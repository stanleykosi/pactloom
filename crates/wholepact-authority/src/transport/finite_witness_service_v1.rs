//! Additive finite lifecycle for an already constructed Witness server.
//!
//! This scheduler does not construct or authenticate an original role, native
//! source, grant, or namespace. Its caller-created stop/cutoff can only restrict
//! transport work. Actual effect admission/currentness remains with the same
//! maintained handlers, independently of these scheduling observations.
use super::*;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
        Mutex,
    },
    thread::{self, JoinHandle},
};

const WORKERS: usize = 8;
const QUEUED_CONNECTIONS: usize = 8;
const ACCEPT_POLL: Duration = Duration::from_millis(5);

/// Restriction-only service control, not proof of original-role provenance or
/// permission for an effect. Clones share one irreversible stop flag and the
/// same immutable cutoff; there is deliberately no reset or deadline extension.
#[derive(Clone)]
pub(crate) struct FiniteWitnessServiceStopV1 {
    stopped: Arc<AtomicBool>,
    cutoff: Instant,
}
impl FiniteWitnessServiceStopV1 {
    pub(crate) fn new(service_cutoff: Instant) -> Self {
        Self {
            stopped: Arc::new(AtomicBool::new(false)),
            cutoff: service_cutoff,
        }
    }

    /// Request restriction without acquiring any source/journal/effect lock.
    /// Return does not acknowledge an atomic accept barrier, joined workers,
    /// namespace release, rollback, or recall of an already admitted effect.
    pub(crate) fn request_stop(&self) {
        self.stopped.store(true, Ordering::Release);
    }

    fn may_start_at(&self, now: Instant) -> bool {
        if now >= self.cutoff {
            self.request_stop();
        }
        !self.stopped.load(Ordering::Acquire)
    }
}

type QueuedConnection = (TcpStream, Instant, crate::admission::AdmissionGuard);

/// Also seals on unwind, so a panicking worker cannot leave acceptance running
/// until the cutoff. Sealing never substitutes for joining that worker.
struct SealOnExit(FiniteWitnessServiceStopV1);
impl Drop for SealOnExit {
    fn drop(&mut self) {
        self.0.request_stop();
    }
}

/// Own every successfully spawned handle immediately. No error or panic path
/// may detach the remaining workers by dropping their JoinHandles unjoined.
struct WorkersV1 {
    stop: FiniteWitnessServiceStopV1,
    listener: Option<TcpListener>,
    sender: Option<SyncSender<QueuedConnection>>,
    receiver: Option<Arc<Mutex<Receiver<QueuedConnection>>>>,
    workers: Vec<JoinHandle<Result<()>>>,
}
impl WorkersV1 {
    fn finish(&mut self, first_error: &mut Option<AuthorityError>) {
        self.stop.request_stop();
        // Close acceptance before draining on normal, error, and unwind paths.
        drop(self.listener.take());
        // Wake recv waiters before joining, even after partial spawn failure.
        drop(self.sender.take());
        for worker in self.workers.drain(..) {
            let result = worker.join().unwrap_or(Err(AuthorityError::Storage));
            retain_first_error(first_error, result);
        }
        // A worker can stop without draining the channel. Drop remaining queued
        // sockets and admission guards before this service can return.
        drop(self.receiver.take());
    }
}
impl Drop for WorkersV1 {
    fn drop(&mut self) {
        let mut ignored = None;
        self.finish(&mut ignored);
    }
}

impl AuthorityServer {
    /// Consume this server in a finite service using the maintained eight
    /// workers, eight queued connections, and existing per-IP admission guard.
    /// The accepted socket's ten-second deadline starts at accept; the original
    /// service cutoff may shorten it and is never refreshed.
    ///
    /// Normal stop/cutoff returns Ok only after this runner's listener, queued
    /// sockets, all spawned workers, and its owned server have been dropped.
    /// Setup/accept/worker failures preserve the first observed lifecycle error
    /// while still joining every worker. Ordinary connection rejections retain
    /// the existing nonfatal serve() behavior. Cleanup also runs during unwind.
    ///
    /// A worker check is NOT atomic with later effect admission. Queued work is
    /// discarded after stop, but already started handlers still require their
    /// actual source/A/P contract. No transport flag grants queued effects.
    /// Kernel/storage operations may delay join beyond the cutoff: this is not
    /// a hard execution-time bound, rollback claim, or namespace-handoff receipt.
    /// External server/source clones can still retain namespace custody. The
    /// genuine role owner must release and verify that custody before reopening.
    pub(crate) fn serve_finite_witness_service_v1(
        self,
        listener: TcpListener,
        stop: FiniteWitnessServiceStopV1,
    ) -> Result<()> {
        let _seal_on_exit = SealOnExit(stop.clone());
        let result = self.run_finite_witness_service_v1(listener, stop);
        // All worker clones have joined and their queued resources are gone.
        // This drops only our own server, not hypothetical external custody.
        drop(self);
        result
    }

    fn run_finite_witness_service_v1(
        &self,
        listener: TcpListener,
        stop: FiniteWitnessServiceStopV1,
    ) -> Result<()> {
        if !stop.may_start_at(Instant::now()) {
            return Ok(());
        }
        listener
            .set_nonblocking(true)
            .map_err(|_| AuthorityError::Storage)?;
        let admission = crate::admission::Admission::new();
        let (sender, receiver) = mpsc::sync_channel(QUEUED_CONNECTIONS);
        let receiver = Arc::new(Mutex::new(receiver));
        let mut workers = WorkersV1 {
            stop: stop.clone(),
            listener: Some(listener),
            sender: Some(sender),
            receiver: Some(receiver),
            workers: Vec::with_capacity(WORKERS),
        };
        let mut first_error = None;
        for _ in 0..WORKERS {
            if !stop.may_start_at(Instant::now()) {
                break;
            }
            let receiver = workers.receiver.as_ref().expect("owned receiver").clone();
            let server = self.clone();
            let worker_stop = stop.clone();
            match thread::Builder::new()
                .name("finite-witness-service".into())
                .spawn(move || {
                    let _seal_on_exit = SealOnExit(worker_stop.clone());
                    loop {
                        if !worker_stop.may_start_at(Instant::now()) {
                            return Ok(());
                        }
                        // The queue lock never surrounds TLS/source/effect work.
                        let next = {
                            let receiver = receiver.lock().map_err(|_| AuthorityError::Storage)?;
                            receiver.recv()
                        };
                        let Ok((socket, deadline, _guard)) = next else {
                            return Ok(());
                        };
                        // Independent restrictive check immediately before dispatch.
                        // A stop racing this check is still NOT an effect grant.
                        if !worker_stop.may_start_at(Instant::now()) {
                            return Ok(());
                        }
                        let _ = server.serve_connection_before(socket, deadline);
                    }
                }) {
                Ok(worker) => workers.workers.push(worker),
                Err(_) => {
                    retain_first_error(&mut first_error, Err(AuthorityError::Storage));
                    break;
                }
            }
        }
        if first_error.is_none() {
            while stop.may_start_at(Instant::now()) {
                match workers.listener.as_ref().expect("owned listener").accept() {
                    Ok((socket, peer)) => {
                        let accepted = Instant::now();
                        if !stop.may_start_at(accepted) {
                            break;
                        }
                        let Some(deadline) = accepted_deadline_at(accepted, stop.cutoff) else {
                            break;
                        };
                        // Explicitly restore blocking socket I/O. The maintained
                        // DeadlineSocket sets each remaining read/write timeout.
                        if socket.set_nonblocking(false).is_err() {
                            retain_first_error(&mut first_error, Err(AuthorityError::Storage));
                            break;
                        }
                        if let Ok(guard) = admission.admit(peer.ip()) {
                            match workers
                                .sender
                                .as_ref()
                                .expect("owned sender")
                                .try_send((socket, deadline, guard))
                            {
                                Ok(()) | Err(TrySendError::Full(_)) => (),
                                Err(TrySendError::Disconnected(_)) => {
                                    retain_first_error(
                                        &mut first_error,
                                        Err(AuthorityError::Storage),
                                    );
                                    break;
                                }
                            }
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(
                            ACCEPT_POLL.min(stop.cutoff.saturating_duration_since(Instant::now())),
                        );
                    }
                    Err(_) => {
                        retain_first_error(&mut first_error, Err(AuthorityError::Uncertain));
                        break;
                    }
                }
            }
        }
        stop.request_stop();
        workers.finish(&mut first_error);
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

fn accepted_deadline_at(accepted: Instant, service_cutoff: Instant) -> Option<Instant> {
    if accepted >= service_cutoff {
        return None;
    }
    Some((accepted + IO_TIMEOUT).min(service_cutoff))
}
fn retain_first_error(first: &mut Option<AuthorityError>, result: Result<()>) {
    if let Err(error) = result {
        first.get_or_insert(error);
    }
}

#[cfg(test)]
mod tests {
    // Pure state/deadline/error tests only. No socket, TLS, source, namespace,
    // thread spawn, join, or native owner is constructed or executed here.
    use super::*;

    #[test]
    fn stop_is_monotone_across_clones_and_cutoff_never_renews() {
        let now = Instant::now();
        let stop = FiniteWitnessServiceStopV1::new(now + Duration::from_secs(2));
        let other = stop.clone();
        assert!(stop.may_start_at(now));
        assert!(!other.may_start_at(now + Duration::from_secs(2)));
        assert!(!stop.may_start_at(now));
        assert_eq!(other.cutoff, stop.cutoff);
        let stop = FiniteWitnessServiceStopV1::new(now + Duration::from_secs(2));
        let other = stop.clone();
        stop.request_stop();
        assert!(!other.may_start_at(now));
    }

    #[test]
    fn accept_starts_io_timeout_and_service_cutoff_only_shortens_it() {
        let accepted = Instant::now();
        assert_eq!(accepted_deadline_at(accepted, accepted), None);
        assert_eq!(
            accepted_deadline_at(accepted, accepted + Duration::from_secs(3)),
            Some(accepted + Duration::from_secs(3))
        );
        assert_eq!(
            accepted_deadline_at(accepted, accepted + Duration::from_secs(30)),
            Some(accepted + IO_TIMEOUT)
        );
    }

    #[test]
    fn cleanup_errors_do_not_overwrite_first_lifecycle_failure() {
        let mut first = None;
        retain_first_error(&mut first, Ok(()));
        retain_first_error(&mut first, Err(AuthorityError::Uncertain));
        retain_first_error(&mut first, Err(AuthorityError::Storage));
        retain_first_error(&mut first, Ok(()));
        assert_eq!(first, Some(AuthorityError::Uncertain));
    }
}
