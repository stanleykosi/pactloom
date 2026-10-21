//! C-owned post-fork driver. The native event loop never blocks on preparation,
//! IPC, source disposal or child reaping; main still joins the terminal driver.
use crate::{bootstrap::InertTreeV1, rejected, review_channel, Result};
use std::{sync::{Arc, atomic::{AtomicBool, Ordering}, mpsc}, thread, time::{Duration, Instant}};
use wholepact_financial_coordinator_origin::CancelReviewResponseV1 as Response;
use wholepact_authority::native_witness_owner::cancel_delivery_review_v1::{CancelOnlyDeliveryInputsV1, CancelOnlyDeliveryPresentationV1};

pub(super) enum Outcome { Prepared(CancelOnlyDeliveryPresentationV1), DisposalStarted, Finished { disposal_confirmed: bool, clean: bool } }
pub(super) struct Driver {
    input: mpsc::SyncSender<CancelOnlyDeliveryInputsV1>,
    pub(super) outcome: mpsc::Receiver<Outcome>,
    revoked: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<Result<()>>>,
    submitted: bool,
}
impl Driver {
    pub(super) fn spawn(tree: InertTreeV1, deadline: Instant) -> Result<Self> {
        let (input, input_rx) = mpsc::sync_channel(1);
        let (output, outcome) = mpsc::channel();
        let revoked = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&revoked);
        let worker = thread::Builder::new().name("coordinator-cancel-review".into()).spawn(move || drive(tree, input_rx, output, flag, deadline))?;
        Ok(Self { input, outcome, revoked, worker: Some(worker), submitted: false })
    }
    pub(super) fn prepare_once(&mut self, input: CancelOnlyDeliveryInputsV1) -> Result<()> {
        if self.submitted || self.revoked.load(Ordering::Acquire) { return Err(rejected("review slot already consumed")); }
        self.submitted = true;
        self.input.try_send(input).map_err(|_| rejected("review driver unavailable"))
    }
    pub(super) fn revoke(&self) { self.revoked.store(true, Ordering::Release); }
    pub(super) fn is_revoked(&self) -> bool { self.revoked.load(Ordering::Acquire) }
    pub(super) fn join(&mut self) -> Result<()> {
        self.revoke();
        self.worker.take().ok_or_else(|| rejected("driver owner missing"))?.join()
            .map_err(|_| rejected("driver panicked; cleanup unconfirmed"))?
    }
}
impl Drop for Driver {
    fn drop(&mut self) {
        self.revoke();
        // Normally main calls join after eframe returns. Error/unwind fallback
        // must not detach the sole actual child owner before process::exit.
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
    }
}

fn drive(mut tree: InertTreeV1, input: mpsc::Receiver<CancelOnlyDeliveryInputsV1>, output: mpsc::Sender<Outcome>, revoked: Arc<AtomicBool>, session_deadline: Instant) -> Result<()> {
    struct RevokeOnExit(Arc<AtomicBool>);
    impl Drop for RevokeOnExit { fn drop(&mut self) { self.0.store(true, Ordering::Release); } }
    // Locals drop before the tree argument during unwinding, so a driver panic
    // revokes C's display even if a subsequent exact-child reap blocks.
    let _revoke_on_exit = RevokeOnExit(Arc::clone(&revoked));
    let mut submitted = false;
    let mut display_received = false;
    let mut failed = false;
    let mut disposed = false;
    let mut cancel_sent = false;
    let mut cleanup_deadline = None;
    let result = (|| -> Result<()> {
        loop {
            tree.check_alive()?;
            if Instant::now() >= session_deadline { revoked.store(true, Ordering::Release); }
            if revoked.load(Ordering::Acquire) && !cancel_sent {
                cleanup_deadline = Some((Instant::now() + Duration::from_secs(5)).min(session_deadline + Duration::from_secs(5)));
                let _ = output.send(Outcome::DisposalStarted);
                tree.send_cancel()?;
                cancel_sent = true;
            }
            if let Ok(data) = input.try_recv() {
                if submitted { return Err(rejected("second driver prepare")); }
                submitted = true;
                if !revoked.load(Ordering::Acquire) { tree.send_prepare_once(review_channel::inputs_to_wire(data))?; }
            }
            if let Some(packet) = tree.try_receive_cancel_response()? {
                match packet {
                    Response::PreparedDisplay(data) if submitted && !display_received && !failed => {
                        let presentation = review_channel::presentation_from_wire(data);
                        display_received = true;
                        review_channel::validate_presentation(&presentation)?;
                        if !revoked.load(Ordering::Acquire) {
                            output.send(Outcome::Prepared(presentation)).map_err(|_| rejected("native display gone"))?;
                        }
                    }
                    Response::PreparationFailed if submitted && !failed && !disposed => {
                        failed = true;
                        revoked.store(true, Ordering::Release);
                    }
                    Response::Disposed if !disposed && (cancel_sent || submitted || Instant::now() >= session_deadline) => {
                        disposed = true;
                        revoked.store(true, Ordering::Release);
                        cleanup_deadline.get_or_insert_with(|| (Instant::now() + Duration::from_secs(5)).min(session_deadline + Duration::from_secs(5)));
                        if !cancel_sent { tree.send_cancel()?; }
                        break;
                    }
                    _ => return Err(rejected("duplicate or out-of-phase source result")),
                }
            }
            if cleanup_deadline.is_some_and(|end| Instant::now() >= end) { return Err(rejected("source disposal not confirmed before cleanup ceiling")); }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    })();
    revoked.store(true, Ordering::Release);
    let _ = output.send(Outcome::DisposalStarted);
    let clean = if result.is_ok() && disposed {
        tree.stop_and_reap(cleanup_deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(5))).is_ok()
    } else {
        // Exact pidfd termination/reaping; deliberately NOT source-disposal
        // evidence. A kernel-blocked final reap can still delay this thread.
        drop(tree);
        false
    };
    let _ = output.send(Outcome::Finished { disposal_confirmed: disposed, clean: clean && !failed });
    if clean && !failed && result.is_ok() { Ok(()) } else { Err(rejected("cancel-only review or cleanup failed")) }
}
