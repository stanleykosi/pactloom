//! Actual C-only Wayland input and source-backed cancel-only review. No positive
//! consent, effect permit, synthetic input hook or role key reaches this module.
use crate::{bootstrap::InertTreeV1, rejected, review_driver::{Driver, Outcome}, Result};
use eframe::egui;
use std::{cell::RefCell, rc::Rc, time::{Duration, Instant}};
use wholepact_authority::native_witness_owner::cancel_delivery_review_v1::{CancelOnlyDeliveryInputsV1, CancelOnlyDeliveryPresentationV1};
use winit::platform::wayland::EventLoopBuilderExtWayland;
use zeroize::Zeroize;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase { Selecting, Preparing, Displaying, Revoked, Finished }

pub(super) fn run(tree: InertTreeV1, session_deadline: Instant) -> Result<()> {
    let driver = Rc::new(RefCell::new(Driver::spawn(tree, session_deadline)?));
    let app = Window {
        driver: Rc::clone(&driver), input: CancelOnlyDeliveryInputsV1::default(),
        phase: Phase::Selecting, presentation: None, focused_last: false,
        focus_seen: false, close_when_done: false, session_deadline,
        prepare_intent: false, review_ceiling: None,
        last_wall: 0, message: "Select only existing original Witness inputs. No setup or approval is available.",
    };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_title("Wholepact · Coordinator review")
            .with_app_id("org.wholepact.Coordinator").with_inner_size([1100.0, 820.0])
            .with_min_inner_size([840.0, 620.0]).with_drag_and_drop(false),
        renderer: eframe::Renderer::Glow,
        persist_window: false,
        event_loop_builder: Some(Box::new(|builder| { builder.with_wayland(); })),
        ..Default::default()
    };
    let window = eframe::run_native("Wholepact coordinator", options, Box::new(move |_cc| Ok(Box::new(app))));
    driver.borrow().revoke();
    // The event loop has returned. Never detach the sole child-owner driver and
    // then process::exit; observe its terminal result, including cleanup failure.
    let cleanup = driver.borrow_mut().join();
    if window.is_err() { return Err(rejected("coordinator Wayland window unavailable")); }
    cleanup
}

struct Window {
    driver: Rc<RefCell<Driver>>,
    input: CancelOnlyDeliveryInputsV1,
    phase: Phase,
    presentation: Option<CancelOnlyDeliveryPresentationV1>,
    focused_last: bool,
    focus_seen: bool,
    close_when_done: bool,
    prepare_intent: bool,
    session_deadline: Instant,
    review_ceiling: Option<Instant>,
    last_wall: u64,
    message: &'static str,
}
impl Window {
    fn clear(&mut self) {
        clear_input(&mut self.input);
        if let Some(mut presentation) = self.presentation.take() { clear_presentation(&mut presentation); }
    }
    fn revoke(&mut self, message: &'static str) {
        // This local cutoff precedes any driver/channel wait. Refocus cannot
        // undo it; a racing queued PreparedDisplay is discarded below.
        if self.phase == Phase::Finished { return; }
        self.phase = Phase::Revoked;
        self.prepare_intent = false;
        self.clear();
        self.message = message;
        self.driver.borrow().revoke();
    }
    fn poll_driver(&mut self, focused: bool) {
        loop {
            let result = self.driver.borrow().outcome.try_recv();
            match result {
                Ok(Outcome::Prepared(mut p)) => {
                    let now = crate::witness_role::wall_ms();
                    let valid = accepts_display(self.phase, focused, self.driver.borrow().is_revoked())
                        && review_time_live(self.review_ceiling, self.session_deadline, Instant::now())
                        && crate::review_channel::validate_presentation(&p).is_ok()
                        && now.as_ref().is_ok_and(|n| *n >= p.prepared_at_ms && *n < p.expires_at_ms);
                    if valid {
                        self.last_wall = now.expect("validated wall time");
                        self.presentation = Some(p);
                        self.phase = Phase::Displaying;
                        self.message = "Original Witness source prepared. Approval remains unavailable; cancellation requests disposal.";
                    } else {
                        clear_presentation(&mut p);
                        self.revoke("A stale, interrupted or invalid review was discarded. Source disposal is pending.");
                    }
                }
                Ok(Outcome::DisposalStarted) => self.revoke("Source disposal is pending. Do not treat cancellation as completed cleanup."),
                Ok(Outcome::Finished { disposal_confirmed, clean }) => {
                    self.clear();
                    self.phase = Phase::Finished;
                    self.message = match (disposal_confirmed, clean) {
                        (true, true) => "The Witness preparation worker disposed its custody and the original fixed children were reaped. No append was admitted.",
                        (true, false) => "Source disposal was observed, but review or process cleanup failed. No retry or approval is available.",
                        (false, _) => "Source disposal was not confirmed. Process termination is not proof of completed source cleanup. No retry or approval is available.",
                    };
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    if self.phase != Phase::Finished { self.revoke("The role driver ended without confirmed cleanup."); }
                    break;
                }
            }
        }
    }
    fn check_local_liveness(&mut self) {
        let driver_revoked = self.driver.borrow().is_revoked();
        if driver_revoked && !matches!(self.phase, Phase::Revoked | Phase::Finished) {
            self.revoke("The original role session ended. Review details were discarded; cleanup is pending.");
        }
        if Instant::now() >= self.session_deadline && self.phase != Phase::Finished {
            self.revoke("The key-free session ceiling expired. This is not a renewed financial or source deadline.");
        }
        if self.review_ceiling.is_some_and(|ceiling| Instant::now() >= ceiling) && self.phase != Phase::Finished {
            self.revoke("The original local review ceiling expired. Disposal is pending; no new review clock is available.");
        }
        if let Some(p) = &self.presentation {
            match crate::witness_role::wall_ms() {
                Ok(now) if now >= self.last_wall && now < p.expires_at_ms => self.last_wall = now,
                _ => self.revoke("The original review expired or its wall clock regressed. Disposal is pending."),
            }
        }
    }
    fn draw(&mut self, ui: &mut egui::Ui) {
        let (focused, blur, close, escape) = ui.ctx().input(|i| (
            i.focused && i.viewport().focused == Some(true),
            i.events.iter().any(|event| matches!(event, egui::Event::WindowFocused(false))),
            i.viewport().close_requested(), i.key_pressed(egui::Key::Escape),
        ));
        // Before the first genuine focus no review can start. ANY explicit blur
        // in any batch revokes, including the first batch with final focus true.
        if must_revoke(self.focus_seen, self.focused_last, focused, blur, escape) {
            self.revoke("The review session was revoked. Returning focus cannot restore it; disposal is pending.");
        }
        self.focus_seen |= focused;
        self.focused_last = focused;
        self.check_local_liveness();
        if close && self.phase != Phase::Finished {
            self.close_when_done = true;
            self.revoke("Window close requested. Waiting for the one owned disposal path.");
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::CancelClose);
        }
        self.poll_driver(focused);
        ui.ctx().request_repaint_after(Duration::from_millis(50));
        if self.close_when_done && self.phase == Phase::Finished { ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close); }
        egui::CentralPanel::default().show(ui, |ui| {
            ui.heading("Wholepact coordinator · Original Witness review");
            ui.label("Cancel-only source slice. No financial approval, append, serving or payment is enabled. Other fixed roles remain inert.");
            ui.label("Existing namespace-key and TLS-key contents are read only inside the selected Witness process. This window receives paths, public selectors and the purpose-limited review, not those keys.");
            ui.separator();
            ui.label(self.message);
            if !focused {
                ui.label("Private form and review details are hidden while this window is unfocused.");
                return;
            }
            match self.phase {
                Phase::Selecting => self.form(ui),
                Phase::Preparing => { ui.label("Preparing the actual original source in Owner1V3DeliveryAdmission. Cancel remains available."); }
                Phase::Displaying => {
                    if let Some(p) = &self.presentation {
                        egui::ScrollArea::vertical().max_height(540.0).show(ui, |ui| { ui.monospace(&p.display); });
                        ui.label(format!("Cancel-only presentation digest: {}", p.presentation_digest));
                    }
                    ui.add_enabled(false, egui::Button::new("Approval unavailable"));
                }
                Phase::Revoked => { ui.label("This single review slot is permanently closed. It cannot be resumed or reprepared."); }
                Phase::Finished => {
                    if ui.button("Close").clicked_by(egui::PointerButton::Primary) { ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close); }
                }
            }
            if self.phase != Phase::Finished && ui.button("Cancel and dispose").clicked_by(egui::PointerButton::Primary) {
                self.revoke("Cancelled locally. Waiting for actual Witness disposal and original-child cleanup.");
            }
        });
        // Dispatch only after every widget in the batch has run, particularly
        // Cancel. A raw/visible interruption can only clear this intent.
        if self.prepare_intent {
            self.prepare_intent = false;
            let driver_revoked = self.driver.borrow().is_revoked();
            if may_dispatch_prepare(self.phase, focused, driver_revoked) {
                self.prepare_once();
            }
        }
    }
    fn form(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().max_height(560.0).show(ui, |ui| {
            for (label, value, limit) in [
                ("Exact existing endpoint", &mut self.input.endpoint, 256),
                ("TLS server name", &mut self.input.server_name, 253),
                ("Original Witness ID", &mut self.input.witness_id, 128),
                ("Pinned server certificate digest", &mut self.input.pinned_server_certificate_digest, 64),
                ("Network profile", &mut self.input.network_profile_id, 128),
                ("Original expected account ID", &mut self.input.expected_account_id, 64),
                ("Existing namespace storage key file (path only)", &mut self.input.storage_key_file, 4096),
                ("Existing server certificate DER file", &mut self.input.server_certificate_der, 4096),
                ("Existing server private key PKCS8 DER file (path only)", &mut self.input.server_private_key_pkcs8_der, 4096),
                ("Existing trusted client root DER file", &mut self.input.trusted_client_root_der, 4096),
            ] {
                ui.label(label);
                ui.add(egui::TextEdit::singleline(value).char_limit(limit));
            }
            ui.label("Independently selected PUBLIC owner certificate DER, hex");
            ui.add(egui::TextEdit::multiline(&mut self.input.owner_certificate_der_hex).desired_rows(3).char_limit(32768));
            ui.label("Exact original durable-delivery request JSON, no private signer material");
            ui.add(egui::TextEdit::multiline(&mut self.input.request_json).desired_rows(6).char_limit(65536));
            ui.label("The complete encoded request and complete review must each fit the 64 KiB closed transport limit. Oversize inputs fail; nothing is truncated.");
        });
        if ui.button("Prepare this original Witness review once").clicked_by(egui::PointerButton::Primary) {
            self.prepare_intent = true;
        }
    }
    fn prepare_once(&mut self) {
        self.phase = Phase::Preparing; // The one slot is consumed even on error.
        // Anchored once before dispatch, not on worker completion/display. This
        // restriction can only shorten W's independent original review bounds.
        self.review_ceiling = Some((Instant::now() + Duration::from_secs(120)).min(self.session_deadline));
        if self.input.validate().is_err() {
            self.revoke("The original input shape was rejected. This review slot is closed.");
            return;
        }
        let data = std::mem::take(&mut self.input);
        let delivered = self.driver.borrow_mut().prepare_once(data);
        if delivered.is_err() {
            self.revoke("The one prepare request could not be delivered. Disposal is pending.");
        }
    }
}
impl eframe::App for Window {
    fn raw_input_hook(&mut self, ctx: &egui::Context, raw: &mut egui::RawInput) {
        // Inspect the complete original input batch before eframe's visible or
        // hidden callbacks. Never mutate/drain it and never trust stale Context
        // input as the only interruption source. This slice has one root window.
        let Some(facts) = raw_facts(raw) else {
            self.revoke("The original native viewport is unavailable. Disposal is pending.");
            return;
        };
        if must_revoke(self.focus_seen, self.focused_last, facts.focused, facts.blur, facts.escape) {
            self.revoke("Native interruption revoked this review before rendering. Disposal is pending.");
        }
        self.focus_seen |= facts.focused;
        self.focused_last = facts.focused;
        if facts.close && self.phase != Phase::Finished {
            self.close_when_done = true;
            self.revoke("Window close requested. Waiting for actual source disposal and cleanup.");
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        }
        self.check_local_liveness();
        self.poll_driver(facts.focused);
        if self.close_when_done && self.phase == Phase::Finished {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        ctx.request_repaint_after(Duration::from_millis(50));
    }
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) { self.draw(ui); }
}
impl Drop for Window { fn drop(&mut self) { self.clear(); self.driver.borrow().revoke(); } }

fn clear_input(input: &mut CancelOnlyDeliveryInputsV1) {
    for value in [&mut input.endpoint, &mut input.server_name, &mut input.witness_id,
        &mut input.pinned_server_certificate_digest, &mut input.network_profile_id,
        &mut input.expected_account_id, &mut input.owner_certificate_der_hex,
        &mut input.storage_key_file, &mut input.server_certificate_der,
        &mut input.server_private_key_pkcs8_der, &mut input.trusted_client_root_der, &mut input.request_json]
    { value.zeroize(); }
}
fn clear_presentation(p: &mut CancelOnlyDeliveryPresentationV1) {
    p.display.zeroize(); p.backend_review_digest.zeroize(); p.presentation_digest.zeroize();
}

fn must_revoke(seen: bool, previous: bool, focused: bool, blur: bool, escape: bool) -> bool {
    blur || escape || (seen && previous && !focused)
}
fn accepts_display(phase: Phase, focused: bool, driver_revoked: bool) -> bool {
    phase == Phase::Preparing && focused && !driver_revoked
}
fn review_time_live(ceiling: Option<Instant>, session: Instant, now: Instant) -> bool {
    now < session && ceiling.is_some_and(|original| now < original)
}
fn may_dispatch_prepare(phase: Phase, focused: bool, driver_revoked: bool) -> bool {
    phase == Phase::Selecting && focused && !driver_revoked
}
struct RawFacts { focused: bool, blur: bool, escape: bool, close: bool }
fn raw_facts(raw: &egui::RawInput) -> Option<RawFacts> {
    if raw.viewport_id != egui::ViewportId::ROOT || raw.viewports.len() != 1 { return None; }
    let viewport = raw.viewports.get(&egui::ViewportId::ROOT)?;
    Some(RawFacts {
        focused: raw.focused && viewport.focused == Some(true),
        blur: raw.events.iter().any(|event| matches!(event, egui::Event::WindowFocused(false))),
        escape: raw.events.iter().any(|event| matches!(event, egui::Event::Key { key: egui::Key::Escape, pressed: true, .. })),
        close: viewport.close_requested(),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn same_batch_blur_refocus_and_escape_revoke_before_render() {
        assert!(must_revoke(true, true, true, true, false));
        assert!(must_revoke(true, true, false, false, false));
        assert!(must_revoke(false, false, false, false, true));
        assert!(must_revoke(false, false, false, true, false));
    }
    #[test]
    fn revoked_or_unsolicited_prepared_data_cannot_reappear() {
        assert!(accepts_display(Phase::Preparing, true, false));
        for phase in [Phase::Selecting, Phase::Displaying, Phase::Revoked, Phase::Finished] {
            assert!(!accepts_display(phase, true, false));
        }
        assert!(!accepts_display(Phase::Preparing, false, false));
        assert!(!accepts_display(Phase::Preparing, true, true));
    }
    #[test]
    fn first_raw_batch_preserves_blur_and_close_without_mutating_input() {
        let mut raw = egui::RawInput::default();
        raw.focused = true;
        let viewport = raw.viewports.get_mut(&egui::ViewportId::ROOT).unwrap();
        viewport.focused = Some(true);
        viewport.events.push(egui::ViewportEvent::Close);
        raw.events = vec![egui::Event::WindowFocused(true), egui::Event::WindowFocused(false), egui::Event::WindowFocused(true)];
        let before = raw.events.clone();
        let facts = raw_facts(&raw).unwrap();
        assert!(facts.focused && facts.blur && facts.close);
        assert!(must_revoke(false, false, facts.focused, facts.blur, facts.escape));
        assert_eq!(raw.events, before);
        raw.viewports.clear();
        assert!(raw_facts(&raw).is_none());
    }
    #[test]
    fn deferred_prepare_is_denied_after_same_batch_cancel_or_slot_use() {
        assert!(may_dispatch_prepare(Phase::Selecting, true, false));
        for phase in [Phase::Preparing, Phase::Displaying, Phase::Revoked, Phase::Finished] {
            assert!(!may_dispatch_prepare(phase, true, false));
        }
        assert!(!may_dispatch_prepare(Phase::Selecting, true, true));
        assert!(!may_dispatch_prepare(Phase::Selecting, false, false));
    }
    #[test]
    fn expired_original_review_ceiling_rejects_queued_display_without_refresh() {
        let start = Instant::now();
        let session = start + Duration::from_secs(300);
        let original = Some(start + Duration::from_secs(120));
        assert!(review_time_live(original, session, start + Duration::from_secs(119)));
        assert!(!review_time_live(original, session, start + Duration::from_secs(120)));
        assert!(!review_time_live(original, session, start + Duration::from_secs(121)));
        assert!(!review_time_live(None, session, start));
        assert!(!review_time_live(original, start + Duration::from_secs(30), start + Duration::from_secs(30)));
        assert_eq!(original, Some(start + Duration::from_secs(120)));
    }
}
