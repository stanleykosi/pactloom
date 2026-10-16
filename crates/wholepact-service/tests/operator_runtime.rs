use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::watch;
use wholepact_service::operator::{
    Operator, OperatorTask, State, TaskFailure, TaskFuture, TaskKind,
};
struct Task {
    calls: AtomicUsize,
    outcome: Option<TaskFailure>,
    hang: bool,
}
impl OperatorTask for Task {
    fn kind(&self) -> TaskKind {
        TaskKind::ChainObservation
    }
    fn tick(&self) -> TaskFuture<'_> {
        Box::pin(async {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.hang {
                std::future::pending::<()>().await;
            }
            self.outcome.map_or(Ok(()), Err)
        })
    }
}
#[tokio::test]
async fn explicit_lifetime_and_recovery_failures_are_latched() {
    let task = Arc::new(Task {
        calls: AtomicUsize::new(0),
        outcome: Some(TaskFailure::PermissionLost),
        hang: false,
    });
    let runtime = Operator::new(
        vec![task.clone()],
        Duration::from_millis(100),
        Duration::from_millis(100),
    )
    .unwrap();
    let health = runtime.health();
    assert_eq!(health.snapshot().unwrap()[0].state, State::Stopped);
    let (tx, rx) = watch::channel(false);
    let handle = tokio::spawn(runtime.run(rx));
    tokio::time::sleep(Duration::from_millis(350)).await;
    assert_eq!(task.calls.load(Ordering::SeqCst), 1);
    assert_eq!(health.snapshot().unwrap()[0].state, State::PermissionLost);
    tx.send(true).unwrap();
    handle.await.unwrap();
    assert_eq!(health.snapshot().unwrap()[0].state, State::Stopped);
    assert!(!health.snapshot().unwrap()[0].settlement_verified);
}
#[tokio::test]
async fn timed_out_effect_is_not_retried_and_abort_marks_stopped() {
    let task = Arc::new(Task {
        calls: AtomicUsize::new(0),
        outcome: None,
        hang: true,
    });
    let runtime = Operator::new(
        vec![task.clone()],
        Duration::from_millis(100),
        Duration::from_millis(100),
    )
    .unwrap();
    let health = runtime.health();
    let (_tx, rx) = watch::channel(false);
    let handle = tokio::spawn(runtime.run(rx));
    tokio::time::sleep(Duration::from_millis(350)).await;
    assert_eq!(task.calls.load(Ordering::SeqCst), 1);
    assert_eq!(health.snapshot().unwrap()[0].state, State::TimedOut);
    handle.abort();
    let _ = handle.await;
    assert_eq!(health.snapshot().unwrap()[0].state, State::Stopped);
}
#[tokio::test]
async fn long_tick_heartbeats_and_shutdown_cancel_work() {
    let task = Arc::new(Task {
        calls: AtomicUsize::new(0),
        outcome: None,
        hang: true,
    });
    let runtime = Operator::new(
        vec![task],
        Duration::from_millis(100),
        Duration::from_secs(10),
    )
    .unwrap();
    let health = runtime.health();
    let (tx, rx) = watch::channel(false);
    let handle = tokio::spawn(runtime.run(rx));
    tokio::time::sleep(Duration::from_millis(1150)).await;
    let row = &health.snapshot().unwrap()[0];
    assert_eq!(row.state, State::Running);
    assert!(row.heartbeat_sequence >= 2);
    tx.send(true).unwrap();
    handle.await.unwrap();
    assert_eq!(health.snapshot().unwrap()[0].completed_ticks, 0);
    assert_eq!(health.snapshot().unwrap()[0].state, State::Stopped);
}
#[test]
fn resource_limits_reject_unbounded_configuration() {
    assert!(Operator::new(vec![], Duration::from_secs(1), Duration::from_secs(1)).is_err());
    let task: Arc<dyn OperatorTask> = Arc::new(Task {
        calls: AtomicUsize::new(0),
        outcome: None,
        hang: false,
    });
    assert!(
        Operator::new(
            vec![task.clone(); 17],
            Duration::from_secs(1),
            Duration::from_secs(1)
        )
        .is_err()
    );
    assert!(Operator::new(vec![task], Duration::ZERO, Duration::from_secs(1)).is_err());
}
