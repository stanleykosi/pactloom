//! One C endpoint owner. It transports sealed native grants, never creates a
//! Review/Ready ticket, invokes Arm/A, or treats a queued click as admission.
use crate::{rejected, Result};
use std::{sync::{Arc, atomic::{AtomicBool, Ordering}, mpsc}, thread, time::{Duration, Instant}};
use wholepact_financial_coordinator_origin::{CoordinatorDeliveryEndpointV1, CoordinatorDeliveryEventV1, DeliveryReviewInputsV1, DeliveryArmOutboundV1, DeliveryFinalOutboundV1, DeliveryReviewTicketV1, DeliveryReadyTicketV1, DeliveryOutcomeV1, DeliveryFailureV1};

enum Input { Prepare(DeliveryReviewInputsV1, Instant), Arm(DeliveryArmOutboundV1), Final(DeliveryFinalOutboundV1) }
pub(super) enum Outcome {
    Prepared(DeliveryReviewTicketV1), Ready(DeliveryReadyTicketV1), Effect(DeliveryOutcomeV1),
    FirstFailure(DeliveryFailureV1), DisposalStarted, Finished { disposal_confirmed: bool, clean: bool, admitted: bool },
}
pub(super) struct Driver {
    input: mpsc::SyncSender<Input>, pub(super) outcome: mpsc::Receiver<Outcome>,
    revoked: Arc<AtomicBool>, worker: Option<thread::JoinHandle<Result<()>>>, submitted: bool,
}
impl Driver {
    pub(super) fn spawn(endpoint: CoordinatorDeliveryEndpointV1) -> Result<Self> {
        let (input, receive) = mpsc::sync_channel(3);
        let (send, outcome) = mpsc::channel();
        let revoked = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&revoked);
        let worker = thread::Builder::new().name("coordinator-delivery-control".into()).spawn(move || drive(endpoint, receive, send, flag))?;
        Ok(Self { input, outcome, revoked, worker: Some(worker), submitted: false })
    }
    pub(super) fn prepare_once(&mut self, data: DeliveryReviewInputsV1, ceiling: Instant) -> Result<()> {
        if self.submitted || self.revoked.load(Ordering::Acquire) { return Err(rejected("delivery preparation slot consumed")); }
        self.submitted = true;
        self.input.try_send(Input::Prepare(data, ceiling)).map_err(|_| rejected("delivery input unavailable"))
    }
    pub(super) fn send_arm(&self, grant: DeliveryArmOutboundV1) -> Result<()> {
        self.input.try_send(Input::Arm(grant)).map_err(|_| rejected("sealed Arm transport unavailable"))
    }
    pub(super) fn send_admitted(&self, grant: DeliveryFinalOutboundV1) -> Result<()> {
        self.input.try_send(Input::Final(grant)).map_err(|_| rejected("admitted grant transport unavailable"))
    }
    pub(super) fn revoke(&self) { self.revoked.store(true, Ordering::Release); }
    pub(super) fn is_revoked(&self) -> bool { self.revoked.load(Ordering::Acquire) }
    pub(super) fn join(&mut self) -> Result<()> {
        self.revoke();
        self.worker.take().ok_or_else(|| rejected("delivery driver missing"))?.join().map_err(|_| rejected("delivery driver panicked"))?
    }
}
impl Drop for Driver {
    fn drop(&mut self) {
        self.revoke();
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
    }
}
fn drive(mut endpoint: CoordinatorDeliveryEndpointV1, input: mpsc::Receiver<Input>, output: mpsc::Sender<Outcome>, revoked: Arc<AtomicBool>) -> Result<()> {
    struct RevokeOnExit(Arc<AtomicBool>);
    impl Drop for RevokeOnExit { fn drop(&mut self) { self.0.store(true, Ordering::Release); } }
    let _revoke = RevokeOnExit(Arc::clone(&revoked));
    let session = endpoint.session_deadline();
    let mut submitted = false;
    let mut armed = false;
    let mut ready_seen = false;
    let mut result_seen = false;
    let mut failed = false;
    let mut disposed = false;
    let mut cancel_sent = false;
    let mut cleanup = None;
    let result = (|| -> Result<()> {
        loop {
            endpoint.check_alive()?;
            if revoked.load(Ordering::Acquire) || Instant::now() >= session { endpoint.revoke(); }
            // Drain the finite queued grants BEFORE cancellation. A has already
            // happened in native code; later R cannot relabel that grant as new
            // work or erase it. An authenticated terminal outcome can make its
            // unsent transport unnecessary, but no retry/admission is possible.
            for _ in 0..3 {
                let message = match input.try_recv() { Ok(value) => value, Err(mpsc::TryRecvError::Empty) => break, Err(mpsc::TryRecvError::Disconnected) => { endpoint.revoke(); break; } };
                match message {
                    Input::Prepare(data, ceiling) if !submitted => {
                        submitted = true;
                        if !endpoint.is_revoked() { endpoint.send_prepare_once(data, ceiling)?; }
                    }
                    Input::Arm(grant) if submitted && !armed => {
                        armed = true;
                        if !endpoint.is_revoked() { endpoint.send_arm(grant)?; }
                    }
                    Input::Final(grant) if armed && !result_seen => { endpoint.send_final_admit(grant)?; }
                    Input::Final(grant) if result_seen => { drop(grant); }
                    _ => return Err(rejected("duplicate delivery driver input")),
                }
            }
            if endpoint.is_revoked() {
                if cleanup.is_none() {
                    cleanup = Some((Instant::now() + Duration::from_secs(5)).min(session + Duration::from_secs(5)));
                    let _ = output.send(Outcome::DisposalStarted);
                }
                // Pending means an exact native A already won. Wait only inside
                // this same cleanup ceiling for that one sealed grant/drop.
                if !cancel_sent && !endpoint.admitted_grant_pending() {
                    endpoint.send_cancel()?;
                    cancel_sent = true;
                }
            }
            if let Some(event) = endpoint.try_receive_delivery_event()? {
                match event {
                    CoordinatorDeliveryEventV1::Prepared(ticket) if submitted && !armed && !result_seen => {
                        output.send(Outcome::Prepared(ticket)).map_err(|_| rejected("native delivery window gone"))?;
                    }
                    CoordinatorDeliveryEventV1::Ready(ticket) if armed && !ready_seen && !result_seen => {
                        ready_seen = true;
                        output.send(Outcome::Ready(ticket)).map_err(|_| rejected("native delivery window gone"))?;
                    }
                    CoordinatorDeliveryEventV1::Outcome(data) if !result_seen => {
                        failed |= matches!(data, DeliveryOutcomeV1::Uncertain { .. });
                        result_seen = true;
                        output.send(Outcome::Effect(data)).map_err(|_| rejected("native delivery result receiver gone"))?;
                    }
                    CoordinatorDeliveryEventV1::FirstFailure(data) => { output.send(Outcome::FirstFailure(data)).map_err(|_| rejected("native diagnostic receiver gone"))?; }
                    CoordinatorDeliveryEventV1::PreparationFailed if !result_seen => { failed = true; result_seen = true; }
                    CoordinatorDeliveryEventV1::Disposed if !disposed => { disposed = true; }
                    _ => return Err(rejected("duplicate delivery driver response")),
                }
            }
            if disposed && cancel_sent { break; }
            if cleanup.is_some_and(|end| Instant::now() >= end) { return Err(rejected("delivery disposal unconfirmed before original cleanup ceiling")); }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    })();
    revoked.store(true, Ordering::Release);
    endpoint.revoke();
    let admitted = endpoint.was_admitted();
    let _ = output.send(Outcome::DisposalStarted);
    let clean = if result.is_ok() && disposed && cancel_sent {
        endpoint.stop_and_reap(cleanup.unwrap_or_else(|| (Instant::now() + Duration::from_secs(5)).min(session + Duration::from_secs(5)))).is_ok()
    } else { drop(endpoint); false };
    let _ = output.send(Outcome::Finished { disposal_confirmed: disposed, clean: clean && !failed, admitted });
    if clean && !failed && result.is_ok() { Ok(()) } else { Err(rejected("exact delivery review or cleanup failed")) }
}
