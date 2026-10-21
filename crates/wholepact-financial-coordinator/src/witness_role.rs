//! One genuine W branch and one prepare/disposal worker. Only ordinary bounded
//! selectors cross C/W; all private key reads and opaque source custody stay W.
use crate::{process::ForkOriginV1, rejected, review_channel::{self, Packet}, Result};
use std::{sync::{Arc, atomic::{AtomicBool, Ordering}, mpsc}, thread, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
use wholepact_authority::native_witness_owner::cancel_delivery_review_v1::{CancelOnlyDeliveryInputsV1, CancelOnlyDeliveryPresentationV1, CancelOnlyDeliveryReviewV1};

pub(super) fn wall_ms() -> Result<u64> {
    SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| rejected("wall clock before epoch"))?
        .as_millis().try_into().map_err(|_| rejected("wall clock overflow"))
}

pub(super) fn run_cancel_only(origin: &ForkOriginV1, session_deadline: Instant) -> Result<()> {
    if origin.role() != review_channel::WITNESS { return Err(rejected("wrong source branch")); }
    origin.check_parent_alive()?;
    let revoked = Arc::new(AtomicBool::new(false));
    let mut slot_used = false;
    let mut cancel_seen = false;
    let mut worker: Option<thread::JoinHandle<Result<()>>> = None;
    let mut display_rx = None;
    let mut display_sent = false;
    let mut disposed = false;
    let hard_cleanup = session_deadline + Duration::from_secs(5);
    loop {
        if let Err(error) = origin.check_parent_alive() {
            revoked.store(true, Ordering::Release);
            // Process exit terminates remaining threads. No fabricated Disposed
            // is sent and no new role or useful work can survive parent loss.
            return Err(error);
        }
        if Instant::now() >= session_deadline { revoked.store(true, Ordering::Release); }
        if Instant::now() >= hard_cleanup { return Err(rejected("source disposal deadline")); }
        if let Some(packet) = origin.review_try_receive()? {
            match packet {
                Packet::PrepareOnce(input) if !slot_used && !cancel_seen && !revoked.load(Ordering::Acquire) => {
                    slot_used = true;
                    let (tx, rx) = mpsc::sync_channel(1);
                    let flag = Arc::clone(&revoked);
                    worker = Some(thread::Builder::new().name("witness-cancel-review".into()).spawn(move || prepare_and_dispose(input, flag, tx, session_deadline))?);
                    display_rx = Some(rx);
                }
                Packet::Cancel if !cancel_seen => {
                    cancel_seen = true;
                    slot_used = true;
                    revoked.store(true, Ordering::Release);
                }
                _ => {
                    revoked.store(true, Ordering::Release);
                    return Err(rejected("duplicate or out-of-phase witness input"));
                }
            }
        }
        if let Some(rx) = &display_rx {
            if let Ok(presentation) = rx.try_recv() {
                if display_sent { return Err(rejected("duplicate source presentation")); }
                display_sent = true;
                // C independently rechecks its terminal epoch. A cancellation
                // racing this check can never resurrect C's discarded display.
                if !revoked.load(Ordering::Acquire) {
                    origin.review_send(&Packet::PreparedDisplay(presentation))?;
                }
            }
        }
        if !disposed && worker.as_ref().is_some_and(|job| job.is_finished()) {
            let result = worker.take().expect("finished worker retained").join()
                .map_err(|_| rejected("source worker panicked; disposal unconfirmed"))?;
            if result.is_err() { origin.review_send(&Packet::PreparationFailed)?; }
            // Actual worker completion follows explicit opaque custody disposal
            // or unwound normal error cleanup, never inferred from process death.
            origin.review_send(&Packet::Disposed)?;
            disposed = true;
        }
        if !disposed && worker.is_none() && revoked.load(Ordering::Acquire) {
            origin.review_send(&Packet::Disposed)?;
            disposed = true;
        }
        // Cancellation acknowledgment closes this grammar before the ordinary
        // STOP frame. Autonomous expiry may produce Disposed first; C must still
        // send exactly one Cancel, preventing an in-flight Cancel becoming STOP.
        if disposed && cancel_seen { return Ok(()); }
        thread::sleep(Duration::from_millis(10));
    }
}

fn prepare_and_dispose(
    input: CancelOnlyDeliveryInputsV1, revoked: Arc<AtomicBool>,
    display: mpsc::SyncSender<CancelOnlyDeliveryPresentationV1>, session_deadline: Instant,
) -> Result<()> {
    if revoked.load(Ordering::Acquire) { return Ok(()); }
    // This API is explicitly non-authorizing. It cannot return a listener,
    // proposal, native decision or arm; only this W worker holds its custody.
    let review = CancelOnlyDeliveryReviewV1::prepare(input).map_err(|_| rejected("source preparation failed"))?;
    review.check_current().map_err(|_| rejected("source review stale"))?;
    let presentation = review.presentation();
    review_channel::validate_presentation(presentation)?;
    let prepared = presentation.prepared_at_ms;
    let expiry = presentation.expires_at_ms;
    let copy = presentation.clone();
    if !revoked.load(Ordering::Acquire) {
        display.send(copy).map_err(|_| rejected("source display receiver gone"))?;
    }
    let mut last_wall = prepared;
    while !revoked.load(Ordering::Acquire) && Instant::now() < session_deadline {
        let now = wall_ms()?;
        if now < last_wall || now >= expiry { break; }
        last_wall = now;
        // Retained original backend clocks/currentness are not refreshed by
        // heartbeats. Any blocking check remains off W's control thread and C.
        if review.check_current().is_err() { break; }
        thread::sleep(Duration::from_millis(25));
    }
    review.dispose();
    Ok(())
}
