//! Genuine positive-profile native review. Only this visible event-loop tail
//! consumes authenticated Ready after the complete immutable interruption batch.
use crate::{delivery_driver::{Driver, Outcome}, rejected, Result};
use eframe::egui;
use std::{cell::RefCell, rc::Rc, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
use wholepact_financial_coordinator_origin::{CoordinatorDeliveryNativeV1, CoordinatorDeliveryEndpointV1, DeliveryReviewInputsV1, DeliveryReviewPresentationV1, DeliveryReviewTicketV1, DeliveryReadyTicketV1, DeliveryOutcomeV1, DeliveryFailureV1};
use wholepact_authority::native_witness_owner::coordinated_delivery_append_v1::{validate_delivery_review_inputs, validate_delivery_review_presentation};
use winit::platform::wayland::EventLoopBuilderExtWayland;
use zeroize::Zeroize;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase { Selecting, Preparing, Reading, Acknowledging, Armed, InFlight, Revoked, Finished }
#[derive(Clone, Copy, PartialEq, Eq)]
enum Effect { NotAdmitted, Pending, KnownNoEffect, Committed, Uncertain }

pub(super) fn run(native: CoordinatorDeliveryNativeV1, endpoint: CoordinatorDeliveryEndpointV1) -> Result<()> {
    let session_deadline = native.session_deadline();
    let driver = Rc::new(RefCell::new(Driver::spawn(endpoint)?));
    let app = Window {
        driver: Rc::clone(&driver), native, input: DeliveryReviewInputsV1::default(), phase: Phase::Selecting,
        presentation: None, review: None, ready: None, effect: Effect::NotAdmitted, first_failure: None,
        focused_last: false, focus_seen: false, close_when_done: false, prepare_intent: false, arm_intent: false, continue_intent: false,
        session_deadline, review_ceiling: None, last_wall: 0, read_to_end: false, acknowledged: false,
        phase_frame: 0, last_tail_frame: None,
        message: "Select existing original Witness inputs. This profile can admit at most one exact delivery append.",
    };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_title("Wholepact · Exact delivery append")
            .with_app_id("org.wholepact.CoordinatorDelivery").with_inner_size([1100.0, 820.0])
            .with_min_inner_size([840.0, 620.0]).with_drag_and_drop(false),
        renderer: eframe::Renderer::Glow, persist_window: false,
        event_loop_builder: Some(Box::new(|builder| { builder.with_wayland(); })), ..Default::default()
    };
    let window = eframe::run_native("Wholepact exact delivery", options, Box::new(move |_cc| Ok(Box::new(app))));
    driver.borrow().revoke();
    // Outside the event loop: retain and join the only tree owner, never detach.
    let cleanup = driver.borrow_mut().join();
    if window.is_err() { return Err(rejected("coordinator Wayland window unavailable")); }
    cleanup
}
struct Window {
    driver: Rc<RefCell<Driver>>, native: CoordinatorDeliveryNativeV1,
    input: DeliveryReviewInputsV1, phase: Phase, presentation: Option<DeliveryReviewPresentationV1>,
    review: Option<DeliveryReviewTicketV1>, ready: Option<DeliveryReadyTicketV1>, effect: Effect,
    first_failure: Option<DeliveryFailureV1>, focused_last: bool, focus_seen: bool, close_when_done: bool,
    prepare_intent: bool, arm_intent: bool, continue_intent: bool, session_deadline: Instant, review_ceiling: Option<Instant>,
    last_wall: u64, read_to_end: bool, acknowledged: bool, phase_frame: u64, last_tail_frame: Option<u64>,
    message: &'static str,
}
impl Window {
    fn clear(&mut self) {
        clear_input(&mut self.input);
        if let Some(mut p) = self.presentation.take() {
            for value in [&mut p.display, &mut p.backend_review_digest, &mut p.presentation_digest,
                &mut p.account_id, &mut p.operation_id, &mut p.request_commitment, &mut p.source_commitment,
                &mut p.owner_certificate_digest, &mut p.expected_head_digest] { value.zeroize(); }
        }
        self.review.take(); self.ready.take();
        self.prepare_intent = false; self.arm_intent = false; self.continue_intent = false;
        self.read_to_end = false; self.acknowledged = false;
    }
    fn revoke(&mut self, message: &'static str) {
        if self.phase == Phase::Finished { return; }
        // R is irreversible. A already won may still complete; never relabel it
        // as canceled, and never discard its already queued sealed outbound grant.
        self.native.revoke();
        if self.native.was_admitted() && self.effect == Effect::NotAdmitted { self.effect = Effect::Pending; }
        self.phase = if self.effect == Effect::Pending { Phase::InFlight } else { Phase::Revoked };
        self.clear(); self.message = message; self.driver.borrow().revoke();
    }
    fn check_local_liveness(&mut self) {
        if self.phase == Phase::Finished { return; }
        let driver_revoked = self.driver.borrow().is_revoked();
        if driver_revoked || self.native.check_current().is_err() {
            self.revoke("The original session is restricted. An already admitted append may still complete; cleanup is pending.");
        }
        if Instant::now() >= self.session_deadline || self.review_ceiling.is_some_and(|d| Instant::now() >= d) {
            self.revoke("An original session or review ceiling expired. No clock or review slot can be renewed.");
        }
        if let Some(p) = &self.presentation {
            match wall_ms() {
                Ok(now) if now >= self.last_wall && now >= p.prepared_at_ms && now < p.expires_at_ms => self.last_wall = now,
                _ => self.revoke("The original review expired or its clock regressed. No new admission is possible."),
            }
        }
    }
    fn poll_driver(&mut self, focused: bool, frame: u64) {
        loop {
            let event = self.driver.borrow().outcome.try_recv();
            match event {
                Ok(Outcome::Prepared(ticket)) => {
                    let p = ticket.presentation();
                    let now = wall_ms();
                    let valid = self.phase == Phase::Preparing && focused && !self.native.is_revoked()
                        && review_time_live(self.review_ceiling, self.session_deadline, Instant::now())
                        && validate_delivery_review_presentation(p).is_ok()
                        && now.as_ref().is_ok_and(|n| *n >= p.prepared_at_ms && *n < p.expires_at_ms);
                    if valid {
                        self.last_wall = now.expect("checked wall time"); self.presentation = Some(p.clone());
                        self.review = Some(ticket); self.phase = Phase::Reading; self.phase_frame = frame;
                        self.message = "Read the entire exact source-backed review. Continue and acknowledge before the one final primary click.";
                    } else { drop(ticket); self.revoke("A stale or interrupted source-backed review was discarded."); }
                }
                Ok(Outcome::Ready(ticket)) => {
                    if self.phase == Phase::Armed && focused && !self.native.is_revoked() && self.ready.is_none()
                        && review_time_live(self.review_ceiling, self.session_deadline, Instant::now()) {
                        self.ready = Some(ticket);
                    } else { drop(ticket); self.revoke("The exact Ready arrived after interruption or outside its one armed slot."); }
                }
                Ok(Outcome::Effect(data)) => {
                    self.effect = match data {
                        DeliveryOutcomeV1::Committed { .. } => Effect::Committed,
                        DeliveryOutcomeV1::KnownNoEffect { .. } => Effect::KnownNoEffect,
                        DeliveryOutcomeV1::Uncertain { .. } => Effect::Uncertain,
                    };
                    self.revoke("An authenticated exact terminal outcome was received. Source and process cleanup are still separate.");
                }
                Ok(Outcome::FirstFailure(data)) => { if self.first_failure.is_none() { self.first_failure = Some(data); } }
                Ok(Outcome::DisposalStarted) => self.revoke("Disposal is pending. Cancellation is not a rollback claim for an admitted append."),
                Ok(Outcome::Finished { disposal_confirmed, clean, admitted }) => {
                    self.clear();
                    if admitted && matches!(self.effect, Effect::NotAdmitted | Effect::Pending) { self.effect = Effect::Uncertain; }
                    self.phase = Phase::Finished;
                    self.message = match (disposal_confirmed, clean) {
                        (true, true) => "Actual Witness disposal was observed and the original fixed children were reaped.",
                        (true, false) => "Actual Witness disposal was observed, but the session or process cleanup failed. The effect outcome below is unchanged.",
                        (false, _) => "Source disposal was not confirmed. Termination alone is not proof of source cleanup. The effect outcome below is unchanged.",
                    };
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    if self.phase != Phase::Finished {
                        if self.native.was_admitted() && matches!(self.effect, Effect::NotAdmitted | Effect::Pending) { self.effect = Effect::Uncertain; }
                        self.revoke("The role driver ended without a complete cleanup observation.");
                    }
                    break;
                }
            }
        }
    }
    fn draw(&mut self, ui: &mut egui::Ui) {
        let frame = ui.ctx().cumulative_frame_nr();
        let (focused, blur, close, escape) = ui.ctx().input(|i| (i.focused && i.viewport().focused == Some(true),
            i.events.iter().any(|e| matches!(e, egui::Event::WindowFocused(false))), i.viewport().close_requested(), i.key_pressed(egui::Key::Escape)));
        self.interrupt(focused, blur, close, escape, ui.ctx());
        self.check_local_liveness(); self.poll_driver(focused, frame);
        ui.ctx().request_repaint_after(Duration::from_millis(20));
        let acknowledged_before_pass = self.acknowledged;
        let mut painted_to_end = false;
        egui::CentralPanel::default().show(ui, |ui| {
            ui.heading("Wholepact coordinator · One exact delivery append");
            ui.label("Only the selected original Witness holds source and key custody. No payment dispatch, signing or reusable approval is exposed here.");
            ui.label(self.message);
            ui.label(effect_text(self.effect));
            if let Some(failure) = self.first_failure { ui.label(format!("First operation termination observation: {:?} / {:?}. This diagnostic does not determine the effect outcome.", failure.stage, failure.class)); }
            ui.separator();
            if !focused { ui.label("Private form and review details are hidden while unfocused."); return; }
            match self.phase {
                Phase::Selecting => self.form(ui),
                Phase::Preparing => { ui.label("The one original Witness preparation is running. Cancel remains available."); }
                Phase::Reading | Phase::Acknowledging => {
                    if let Some(p) = &self.presentation {
                        let shown = egui::ScrollArea::vertical().id_salt("exact-delivery-review").max_height(440.0)
                            .show(ui, |ui| { ui.monospace(&p.display); });
                        if shown.state.offset.y + shown.inner_rect.height() + 1.0 >= shown.content_size.y { painted_to_end = true; }
                        ui.label(format!("Exact presentation digest: {}", p.presentation_digest));
                    }
                    if self.phase == Phase::Reading {
                        if ui.add_enabled(self.read_to_end && frame > self.phase_frame, egui::Button::new("Continue to exact conditional append")).clicked_by(egui::PointerButton::Primary) {
                            self.continue_intent = true;
                        }
                    } else {
                        ui.checkbox(&mut self.acknowledged, "I reviewed the complete exact source, account, head, request and terms. I understand the conditional admission and later-completion notice.");
                        if ui.add_enabled(self.acknowledged && frame > self.phase_frame, egui::Button::new("Arm this exact conditional append")).clicked_by(egui::PointerButton::Primary) { self.arm_intent = true; }
                    }
                }
                Phase::Armed => { ui.label("One exact append is armed, not yet admitted. Its authenticated Ready can be admitted only at a visible, still-current native event-loop tail. There is no second click or renewed timeout."); }
                Phase::InFlight => { ui.label("An exact append was admitted and may be in flight. A later blur or cancel cannot promise rollback."); }
                Phase::Revoked => { ui.label("This one slot is permanently restricted. Refocus cannot rearm or reprepare it."); }
                Phase::Finished => { if ui.button("Close").clicked_by(egui::PointerButton::Primary) { ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close); } }
            }
            if self.phase != Phase::Finished && ui.button("Cancel and dispose").clicked_by(egui::PointerButton::Primary) {
                self.revoke("Cancelled locally. Any admission that already occurred remains potentially in flight until its exact outcome is known.");
            }
        });
        // Every native widget/cancel action has now run. Multipass replay cannot
        // use the same frame again. No hidden callback calls this tail.
        let discarded = ui.ctx().will_discard() || ui.is_sizing_pass() || !ui.is_visible();
        if discarded {
            self.prepare_intent = false; self.arm_intent = false; self.continue_intent = false;
            if !self.native.is_revoked() { self.acknowledged = acknowledged_before_pass; }
        }
        if tail_eligible(frame, self.last_tail_frame, discarded) {
            self.last_tail_frame = Some(frame);
            self.read_to_end |= painted_to_end;
            self.check_local_liveness();
            if focused && !self.native.is_revoked() {
                if self.prepare_intent && self.phase == Phase::Selecting { self.prepare_once(); }
                self.prepare_intent = false;
                if self.continue_intent && self.phase == Phase::Reading && self.read_to_end && frame > self.phase_frame {
                    self.phase = Phase::Acknowledging; self.phase_frame = frame;
                }
                self.continue_intent = false;
                if self.arm_intent && self.phase == Phase::Acknowledging && self.acknowledged && self.read_to_end && frame > self.phase_frame { self.arm_once(); }
                self.arm_intent = false;
                if self.phase == Phase::Armed && review_time_live(self.review_ceiling, self.session_deadline, Instant::now()) {
                    if let Some(ticket) = self.ready.take() {
                        match self.native.admit(ticket) {
                            Ok(grant) => {
                                self.phase = Phase::InFlight; self.effect = Effect::Pending;
                                let sent = self.driver.borrow().send_admitted(grant);
                                if sent.is_err() { self.revoke("Admission occurred, but delivery was not confirmed. The effect may be uncertain."); }
                            }
                            Err(_) => self.revoke("The original Ready could not be admitted. This slot cannot be retried."),
                        }
                    }
                }
            } else { self.prepare_intent = false; self.arm_intent = false; self.continue_intent = false; }
        }
        if self.close_when_done && self.phase == Phase::Finished { ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close); }
    }
    fn interrupt(&mut self, focused: bool, blur: bool, close: bool, escape: bool, ctx: &egui::Context) {
        if must_revoke(self.focus_seen, self.focused_last, focused, blur, escape) { self.revoke("Native interruption permanently restricted this slot before admission processing."); }
        self.focus_seen |= focused; self.focused_last = focused;
        if close && self.phase != Phase::Finished {
            self.close_when_done = true; self.revoke("Close requested. Waiting for the owned cleanup path, without promising rollback.");
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        }
    }
    fn form(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().max_height(520.0).show(ui, |ui| {
            for (label, value, limit) in [
                ("Exact existing endpoint", &mut self.input.endpoint, 256), ("TLS server name", &mut self.input.server_name, 253),
                ("Original Witness ID", &mut self.input.witness_id, 128), ("Pinned server certificate digest", &mut self.input.pinned_server_certificate_digest, 64),
                ("Network profile", &mut self.input.network_profile_id, 128), ("Original expected account ID", &mut self.input.expected_account_id, 64),
                ("Existing namespace storage key file (path only)", &mut self.input.storage_key_file, 4096), ("Existing server certificate DER file", &mut self.input.server_certificate_der, 4096),
                ("Existing server private key PKCS8 DER file (path only)", &mut self.input.server_private_key_pkcs8_der, 4096), ("Existing trusted client root DER file", &mut self.input.trusted_client_root_der, 4096),
            ] { ui.label(label); ui.add(egui::TextEdit::singleline(value).char_limit(limit)); }
            ui.label("Independently selected PUBLIC owner certificate DER, hex");
            ui.add(egui::TextEdit::multiline(&mut self.input.owner_certificate_der_hex).desired_rows(3).char_limit(32768));
            ui.label("Exact original durable-delivery request JSON, no private signer material");
            ui.add(egui::TextEdit::multiline(&mut self.input.request_json).desired_rows(6).char_limit(65536));
            ui.label("Complete packets and complete display must fit 64 KiB. Oversize data is rejected, never truncated.");
        });
        if ui.button("Prepare this exact Witness review once").clicked_by(egui::PointerButton::Primary) { self.prepare_intent = true; }
    }
    fn prepare_once(&mut self) {
        self.phase = Phase::Preparing;
        let ceiling = (Instant::now() + Duration::from_secs(120)).min(self.session_deadline);
        self.review_ceiling = Some(ceiling); // BEFORE queueing; never renewed at driver dequeue/Arm/Ready.
        if validate_delivery_review_inputs(&self.input).is_err() { self.revoke("Input validation rejected this one slot."); return; }
        let data = std::mem::take(&mut self.input);
        let sent = self.driver.borrow_mut().prepare_once(data, ceiling);
        if sent.is_err() { self.revoke("The original preparation request could not be delivered."); }
    }
    fn arm_once(&mut self) {
        let Some(ticket) = self.review.take() else { self.revoke("The exact original review ticket is unavailable."); return; };
        match self.native.arm(ticket) {
            Ok(grant) => {
                self.phase = Phase::Armed;
                let sent = self.driver.borrow().send_arm(grant);
                if sent.is_err() { self.revoke("The one Arm could not be delivered. No replacement is available."); }
            }
            Err(_) => self.revoke("The exact original review could not be armed."),
        }
    }
}
impl eframe::App for Window {
    fn raw_input_hook(&mut self, ctx: &egui::Context, raw: &mut egui::RawInput) {
        let Some(facts) = raw_facts(raw) else { self.revoke("The original native viewport is unavailable."); return; };
        self.interrupt(facts.focused, facts.blur, facts.close, facts.escape, ctx);
        self.check_local_liveness();
        self.poll_driver(facts.focused, ctx.cumulative_frame_nr());
        // Queue only. Neither Arm nor A occurs in this hidden-capable callback.
        ctx.request_repaint_after(Duration::from_millis(20));
    }
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) { self.draw(ui); }
}
impl Drop for Window { fn drop(&mut self) { self.native.revoke(); self.clear(); self.driver.borrow().revoke(); } }
fn clear_input(p: &mut DeliveryReviewInputsV1) {
    for s in [&mut p.endpoint, &mut p.server_name, &mut p.witness_id, &mut p.pinned_server_certificate_digest,
        &mut p.network_profile_id, &mut p.expected_account_id, &mut p.owner_certificate_der_hex, &mut p.storage_key_file,
        &mut p.server_certificate_der, &mut p.server_private_key_pkcs8_der, &mut p.trusted_client_root_der, &mut p.request_json] { s.zeroize(); }
}
fn wall_ms() -> Result<u64> { SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| rejected("wall time before epoch"))?.as_millis().try_into().map_err(|_| rejected("wall time overflow")) }
fn tail_eligible(frame: u64, previous: Option<u64>, discarded: bool) -> bool { !discarded && previous != Some(frame) }
fn review_time_live(ceiling: Option<Instant>, session: Instant, now: Instant) -> bool { now < session && ceiling.is_some_and(|end| now < end) }
fn must_revoke(seen: bool, previous: bool, focused: bool, blur: bool, escape: bool) -> bool { blur || escape || (seen && previous && !focused) }
fn effect_text(effect: Effect) -> &'static str {
    match effect {
        Effect::NotAdmitted => "No native append admission has occurred.", Effect::Pending => "Exact append admitted: effect outcome pending, potentially in flight.",
        Effect::KnownNoEffect => "Authenticated exact outcome: no effect occurred.", Effect::Committed => "Authenticated exact outcome: the one original append committed.",
        Effect::Uncertain => "Effect outcome uncertain. Do not retry or assume cancellation rolled it back.",
    }
}
struct RawFacts { focused: bool, blur: bool, escape: bool, close: bool }
fn raw_facts(raw: &egui::RawInput) -> Option<RawFacts> {
    if raw.viewport_id != egui::ViewportId::ROOT || raw.viewports.len() != 1 { return None; }
    let viewport = raw.viewports.get(&egui::ViewportId::ROOT)?;
    Some(RawFacts { focused: raw.focused && viewport.focused == Some(true),
        blur: raw.events.iter().any(|e| matches!(e, egui::Event::WindowFocused(false))),
        escape: raw.events.iter().any(|e| matches!(e, egui::Event::Key { key: egui::Key::Escape, pressed: true, .. })), close: viewport.close_requested() })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discarded_pass_never_consumes_the_visible_tail_before_cancel() {
        let frame = 9; let mut previous = None;
        assert!(!tail_eligible(frame, previous, true)); assert_eq!(previous, None);
        // A later final pass can still handle Cancel, which removes all intents.
        let canceled = true;
        assert!(tail_eligible(frame, previous, false));
        assert!(!(tail_eligible(frame, previous, false) && !canceled));
        previous = Some(frame); assert!(!tail_eligible(frame, previous, false));
    }
    #[test]
    fn whole_raw_batch_blur_never_rearms_even_with_final_focus() {
        let mut raw = egui::RawInput::default(); raw.focused = true;
        raw.viewports.get_mut(&egui::ViewportId::ROOT).unwrap().focused = Some(true);
        raw.events = vec![egui::Event::WindowFocused(true), egui::Event::WindowFocused(false), egui::Event::WindowFocused(true)];
        let original = raw.events.clone(); let facts = raw_facts(&raw).unwrap();
        assert!(must_revoke(false, false, facts.focused, facts.blur, facts.escape)); assert_eq!(raw.events, original);
        raw.viewports.clear(); assert!(raw_facts(&raw).is_none());
    }
    #[test]
    fn queued_ready_cannot_renew_the_pre_queue_review_ceiling() {
        let start = Instant::now(); let end = start + Duration::from_secs(120); let session = start + Duration::from_secs(300);
        assert!(review_time_live(Some(end), session, end - Duration::from_nanos(1)));
        assert!(!review_time_live(Some(end), session, end)); assert!(!review_time_live(None, session, start));
    }
    #[test]
    fn uncertain_effect_is_not_described_as_cancellation_or_rollback() {
        assert!(effect_text(Effect::Uncertain).contains("Do not retry"));
        assert!(effect_text(Effect::Pending).contains("in flight"));
        assert!(effect_text(Effect::Committed).contains("committed"));
    }
}
