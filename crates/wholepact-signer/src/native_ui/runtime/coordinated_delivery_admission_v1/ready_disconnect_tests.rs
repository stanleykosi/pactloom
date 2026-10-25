//! Real worker/channel regression. No Arm, Final, Attempt, READY or source is
//! constructed. The unchanged successful READY branch is source-reviewed only.
use super::*;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}, mpsc};

// A deterministic destructor barrier, not a timing guess. A timeout merely
// releases test cleanup; it never constructs a successful worker result.
struct HeldDestructor {
    entered: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
    drops: Arc<AtomicUsize>,
}
impl Drop for HeldDestructor {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
        let _ = self.entered.send(());
        let _ = self.release.recv_timeout(Duration::from_secs(5));
    }
}

// Exact pre-correction selection, for the same real receiver and worker.
fn prior_take_ready(worker: &CoordinatedAdmissionWorkerV1) -> Result<Option<(
    wholepact_financial_coordinator_origin::SignerV3AdmitArmV1,
    wholepact_financial_coordinator_origin::SignerV3AdmitReadyV1,
)>> {
    match worker.ready.try_recv() {
        Ok(v) => Ok(Some(v)),
        Err(std::sync::mpsc::TryRecvError::Empty) => Ok(None),
        Err(std::sync::mpsc::TryRecvError::Disconnected) if worker.finished() => Ok(None),
        Err(_) => Err(Error::Unavailable),
    }
}

#[test]
fn ready_disconnect_preserves_pending_worker_error_and_panic_without_fabricating_ready() {
    for panic_worker in [false, true] {
        let (ready_sender, ready) = mpsc::sync_channel(1);
        let (final_sender, _final_receiver) = mpsc::sync_channel(1);
        let (start, started) = mpsc::channel();
        let (entered, at_destructor) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let drops = Arc::new(AtomicUsize::new(0));
        let cleanup_drops = Arc::clone(&drops);
        let handle = std::thread::spawn(move || -> Result<CoordinatedAdmissionAttemptV1> {
            let _held = HeldDestructor { entered, release: released, drops: cleanup_drops };
            started.recv_timeout(Duration::from_secs(5)).expect("test worker start");
            drop(ready_sender);
            if panic_worker { panic!("inert admission worker panic"); }
            Err(Error::Io(std::io::Error::from_raw_os_error(libc::EACCES)))
        });
        let mut worker = CoordinatedAdmissionWorkerV1 {
            worker: Some(handle), ready, final_sender: Some(final_sender),
        };
        assert!(worker.take_ready().expect("empty ready channel").is_none());
        assert!(!worker.finished());
        start.send(()).expect("start real worker");
        at_destructor.recv_timeout(Duration::from_secs(5)).expect("destructor barrier");
        assert!(!worker.finished(), "barrier holds completion publication");
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(matches!(prior_take_ready(&worker), Err(Error::Unavailable)));
        for _ in 0..3 {
            assert!(worker.take_ready().expect("disconnected worker is still pending").is_none());
            assert!(!worker.finished());
        }
        release.send(()).expect("release original cleanup");
        let cutoff = Instant::now() + Duration::from_secs(5);
        while !worker.finished() {
            assert!(Instant::now() < cutoff, "bounded test completion wait");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(worker.take_ready().expect("completed ready channel").is_none());
        // Actual consuming join: this owner cannot join again, and its Drop has
        // no handle left to join. The underlying error/panic mapping is unchanged.
        let result = worker.join();
        if panic_worker {
            assert!(matches!(result, Err(Error::Uncertain)));
        } else {
            match result {
                Err(Error::Io(error)) => assert_eq!(error.raw_os_error(), Some(libc::EACCES)),
                _ => panic!("original worker error not preserved"),
            }
        }
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}
