//! Bounded foreground-owned operator supervision. No OS startup permission,
//! signer capability, network authority or background installation is created.
use serde::Serialize;
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::watch;

pub type TaskFuture<'a> = Pin<Box<dyn Future<Output = Result<(), TaskFailure>> + Send + 'a>>;
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaskFailure {
    Unavailable,
    PermissionLost,
    RecoveryRequired,
}
/// Implementors own their actual read/transport permissions. They must retain a
/// permission lease through each external effect and support cancellation by
/// dropping this future. External effects require their own durable idempotency
/// journal; cancellation cannot undo a send. Uncertain outcomes must return
/// RecoveryRequired, never Unavailable. This supervisor grants no permissions.
pub trait OperatorTask: Send + Sync {
    fn kind(&self) -> TaskKind;
    fn tick(&self) -> TaskFuture<'_>;
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    ChainObservation,
    TransportDelivery,
    ProofQueue,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Stopped,
    Waiting,
    Running,
    Unavailable,
    PermissionLost,
    RecoveryRequired,
    TimedOut,
}
#[derive(Clone, Debug, Serialize)]
pub struct TaskHealth {
    pub kind: TaskKind,
    pub state: State,
    pub completed_ticks: u64,
    pub heartbeat_sequence: u64,
    /// A successful tick is not evidence of payment, freshness or consensus.
    pub settlement_verified: bool,
}
#[derive(Clone)]
pub struct Health(Arc<Mutex<Vec<TaskHealth>>>);
impl Health {
    pub fn snapshot(&self) -> Result<Vec<TaskHealth>, &'static str> {
        self.0
            .lock()
            .map(|v| v.clone())
            .map_err(|_| "Operator health unavailable")
    }
    fn update(&self, index: usize, state: State, completed: bool, heartbeat: bool) {
        if let Ok(mut rows) = self.0.lock() {
            let row = &mut rows[index];
            row.state = state;
            row.completed_ticks = row.completed_ticks.saturating_add(u64::from(completed));
            row.heartbeat_sequence = row.heartbeat_sequence.saturating_add(u64::from(heartbeat));
        }
    }
}
pub struct Operator {
    tasks: Vec<Arc<dyn OperatorTask>>,
    poll_interval: Duration,
    timeout: Duration,
    health: Health,
}
impl Operator {
    /// Explicit local composition only. There are no defaults that start a task.
    /// Each task is sequential, bounding total concurrent work to one. Adapters
    /// should dequeue a bounded unit; proof adapters may report existing jobs.
    pub fn new(
        tasks: Vec<Arc<dyn OperatorTask>>,
        poll_interval: Duration,
        timeout: Duration,
    ) -> Result<Self, &'static str> {
        if tasks.is_empty()
            || tasks.len() > 16
            || poll_interval < Duration::from_millis(100)
            || poll_interval > Duration::from_secs(3600)
            || timeout < Duration::from_millis(100)
            || timeout > Duration::from_secs(3600)
        {
            return Err("Invalid bounded operator configuration");
        }
        let health = Health(Arc::new(Mutex::new(
            tasks
                .iter()
                .map(|task| TaskHealth {
                    kind: task.kind(),
                    state: State::Stopped,
                    completed_ticks: 0,
                    heartbeat_sequence: 0,
                    settlement_verified: false,
                })
                .collect(),
        )));
        Ok(Self {
            tasks,
            poll_interval,
            timeout,
            health,
        })
    }
    pub fn health(&self) -> Health {
        self.health.clone()
    }
    /// Caller owns task lifetime and signals shutdown. Restart always constructs
    /// fresh stopped health; cached domain observations remain separately stale.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        let _guard = StopGuard(self.health.clone());
        loop {
            if *shutdown.borrow() {
                return;
            }
            for (index, task) in self.tasks.iter().enumerate() {
                if *shutdown.borrow() {
                    return;
                }
                // Permission/recovery failures are latched until explicit runtime
                // reconstruction. A still-running app cannot silently renew them.
                if let Ok(rows) = self.health.snapshot() {
                    if matches!(
                        rows[index].state,
                        State::PermissionLost | State::RecoveryRequired | State::TimedOut
                    ) {
                        continue;
                    }
                } else {
                    return;
                }
                self.health.update(index, State::Running, false, true);
                let work = task.tick();
                tokio::pin!(work);
                let deadline = tokio::time::sleep(self.timeout);
                tokio::pin!(deadline);
                let mut heartbeat = tokio::time::interval(Duration::from_secs(1));
                heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        biased;
                        result = shutdown.changed() => {
                            if result.is_err() || *shutdown.borrow() { return; }
                        }
                        _ = &mut deadline => {
                            self.health.update(index, State::TimedOut, false, false); break;
                        }
                        result = &mut work => {
                            let state = match result {
                                Ok(()) => State::Waiting,
                                Err(TaskFailure::Unavailable) => State::Unavailable,
                                Err(TaskFailure::PermissionLost) => State::PermissionLost,
                                Err(TaskFailure::RecoveryRequired) => State::RecoveryRequired,
                            };
                            self.health.update(index, state, result.is_ok(), false); break;
                        }
                        _ = heartbeat.tick() => self.health.update(index, State::Running, false, true),
                    }
                }
            }
            tokio::select! {
                biased;
                result = shutdown.changed() => { if result.is_err() || *shutdown.borrow() { return; } }
                _ = tokio::time::sleep(self.poll_interval) => {}
            }
        }
    }
}
struct StopGuard(Health);
impl Drop for StopGuard {
    fn drop(&mut self) {
        if let Ok(mut rows) = self.0.0.lock() {
            for row in rows.iter_mut() {
                row.state = State::Stopped;
            }
        }
    }
}
