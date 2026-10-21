//! Dormant, private, one-request password input, not a source-entry authority.
//!
//! This leaf has NO runtime callsite. A future exclusive credential modal must
//! forward every original raw batch before any widget, call `show` once, process
//! all remaining cancel controls, then call `finish_frame`. It must cancel/drop
//! this slot before switching roles, requests or UI phases. No sibling text
//! editor may share this input phase. The future authenticated source-entry
//! issuer must independently match the original opaque offer before sealing.
//!
//! Application-owned password storage is zeroized when entry ends (or moved
//! once into the bounded owned result); retained widget undo state is removed.
//! Closed requests cannot be refilled by stale input. Stock egui creates ordinary
//! plaintext undo/input/selection temporaries, which are dropped, NOT guaranteed
//! overwritten. Neither backend/OS/IME copies nor the user's clipboard are
//! guaranteed erased. We never clear the OS clipboard. The stock masked layout
//! and password semantics are retained, including its normal paste handling.
//!
//! Every future actual password profile must depend on this feature's static
//! `log/max_level_off`, not merely runtime logger configuration. Closed typed
//! diagnostics are unaffected. No passwords, dynamic error text or input events
//! are formatted, serialized, logged, persisted, sent or opened here.
#![allow(dead_code)] // Deliberately not wired to an active coordinator profile.

use eframe::egui;
use std::{sync::Arc, time::Instant};
use zeroize::{Zeroize, Zeroizing};

const MIN_PASSWORD_BYTES: usize = 12;
const MAX_PASSWORD_BYTES: usize = 1024;
const MAX_BATCH_EVENTS: usize = 256;
const PASSWORD_ID: &str = "wholepact.coordinator.transient-password.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum InputRole { Signer1, Signer2 }

/// Ordinary UI selection data ONLY. The digest commits to the complete exact
/// source-entry request; it is not a caller-created origin, offer or permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RequestBinding {
    role: InputRole,
    source_entry_request_digest: [u8; 64],
}

impl RequestBinding {
    pub(super) fn new(role: InputRole, digest: &str) -> Option<Self> {
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return None;
        }
        Some(Self { role, source_entry_request_digest: digest.as_bytes().try_into().ok()? })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum InputStatus {
    WaitingForFocus, Editing, Cancelled, Interrupted, InvalidViewport,
    RequestChanged, Expired, InputTooLarge, InvalidLength, Submitted,
}

/// A non-Clone, non-Debug, non-serializable, one-use owned value. Even success is
/// only password INPUT. It cannot authorize opening a source or any effect.
pub(super) struct BoundPassword {
    binding: RequestBinding,
    password: Zeroizing<String>,
}

impl BoundPassword {
    /// Consuming a mismatched result drops/zeroizes it; no retry or retargeting.
    pub(super) fn into_password_for(self, expected: &RequestBinding) -> Option<Zeroizing<String>> {
        (self.binding == *expected).then_some(self.password)
    }
}

#[derive(Clone)]
struct WidgetLease(Arc<()>);

pub(super) struct PasswordInput {
    ctx: egui::Context,
    widget_lease: Arc<()>,
    binding: RequestBinding,
    original_deadline: Instant,
    password: Zeroizing<String>,
    status: InputStatus,
    focus_seen: bool,
    focused_last: bool,
    raw_input_allowed: bool,
    submit_frame: Option<u64>,
}

impl PasswordInput {
    /// One fixed widget ID has one live owner. A terminal slot must be dropped
    /// before another is created, so two roles cannot alias retained edit state.
    pub(super) fn new(ctx: &egui::Context, binding: RequestBinding, original_deadline: Instant) -> Option<Self> {
        if Instant::now() >= original_deadline { return None; }
        let widget_lease = Arc::new(());
        let acquired = ctx.data_mut(|data| {
            if data.get_temp::<WidgetLease>(widget_id()).is_some() { false }
            else { data.insert_temp(widget_id(), WidgetLease(widget_lease.clone())); true }
        });
        if !acquired { return None; }
        clear_widget(ctx);
        Some(Self {
            ctx: ctx.clone(), widget_lease, binding, original_deadline,
            password: Zeroizing::new(String::with_capacity(2 * MAX_PASSWORD_BYTES)),
            status: InputStatus::WaitingForFocus, focus_seen: false, focused_last: false,
            raw_input_allowed: false, submit_frame: None,
        })
    }

    pub(super) fn status(&self) -> InputStatus { self.status }

    fn open(&self) -> bool {
        matches!(self.status, InputStatus::WaitingForFocus | InputStatus::Editing)
    }

    /// Forward from App::raw_input_hook BEFORE any visible or hidden callback.
    /// Inspect the whole immutable interruption history before removing payloads.
    /// Closed/unfocused/expired requests never admit delayed text or IME input.
    pub(super) fn raw_input_hook(&mut self, raw: &mut egui::RawInput) {
        self.raw_input_allowed = false;
        self.submit_frame = None;
        self.observe(raw_facts(raw));
        if self.open() && !bounded_input_events(&raw.events) {
            self.close(InputStatus::InputTooLarge);
        }
        if self.open() && self.focused_last {
            self.raw_input_allowed = true;
        } else {
            scrub_payloads(&mut raw.events);
            scrub_context_payloads(&self.ctx);
            clear_sensitive_output(&self.ctx, true);
        }
    }

    /// The local Cancel widget runs BEFORE TextEdit. This function returns no
    /// secret; even a primary-button submit is only an inert same-frame intent.
    pub(super) fn show(&mut self, ui: &mut egui::Ui, expected: &RequestBinding) {
        if !self.owns_widget(ui.ctx()) || ui.ctx().viewport_id() != egui::ViewportId::ROOT {
            self.close(InputStatus::InvalidViewport);
            return;
        }
        self.check_current(expected);
        if !self.open() { self.scrub_closed_frame(); return; }
        if ui.button("Cancel password entry").clicked_by(egui::PointerButton::Primary) {
            self.cancel();
            return;
        }
        let admitted_batch = std::mem::take(&mut self.raw_input_allowed);
        let eligible = eligible_pass(admitted_batch, self.focused_last, ui.is_enabled(),
            ui.is_visible(), ui.is_sizing_pass(), self.ctx.will_discard());
        if !eligible { scrub_context_payloads(&self.ctx); }
        if !self.focused_last { return; }

        clear_undo(&self.ctx);
        let mut output = egui::TextEdit::singleline(&mut *self.password)
            .id(widget_id()).password(true).interactive(eligible)
            // Batch preflight bounds accepted bytes. This larger defensive
            // character cap never turns an overlength password into success:
            // the authoritative local limit below is BYTES, without normalization.
            .char_limit(2 * MAX_PASSWORD_BYTES).show(ui);
        output.state.clear_undoer();
        output.state.store(&self.ctx, output.response.id);
        // Do not store this old output again after any terminal cleanup.
        scrub_context_payloads(&self.ctx);
        clear_sensitive_output(&self.ctx, false);
        if self.password.len() > MAX_PASSWORD_BYTES {
            self.close(InputStatus::InputTooLarge);
            return;
        }
        let submit = ui.add_enabled(eligible, egui::Button::new("Use password for this request"))
            .clicked_by(egui::PointerButton::Primary);
        if submit { self.submit_frame = Some(self.ctx.cumulative_frame_nr()); }
    }

    /// Call at the visible frame tail, AFTER every remaining Cancel control.
    /// Hidden/discarded/repeated passes cannot submit, and no input caller can
    /// fabricate an intent through this API. The original deadline never renews.
    pub(super) fn finish_frame(&mut self, expected: &RequestBinding) -> Option<BoundPassword> {
        self.check_current(expected);
        let requested = self.submit_frame.take() == Some(self.ctx.cumulative_frame_nr());
        // The exclusive credential modal has now processed all controls. Clear
        // also key/modifier events, which can reveal the input sequence.
        self.ctx.input_mut(|input| {
            scrub_payloads(&mut input.events);
            scrub_payloads(&mut input.raw.events);
            input.events.clear();
            input.raw.events.clear();
        });
        clear_sensitive_output(&self.ctx, !self.open());
        if !self.open() || !self.focused_last || !requested || self.ctx.will_discard() { return None; }
        if !(MIN_PASSWORD_BYTES..=MAX_PASSWORD_BYTES).contains(&self.password.len()) {
            self.close(InputStatus::InvalidLength);
            return None;
        }
        let password = std::mem::take(&mut self.password);
        self.close(InputStatus::Submitted);
        Some(BoundPassword { binding: self.binding, password })
    }

    /// Role/request replacement, upstream cancellation and source failure MUST
    /// reach this before further widgets. A canceled slot cannot be reopened.
    pub(super) fn cancel(&mut self) { self.close(InputStatus::Cancelled); }

    fn check_current(&mut self, expected: &RequestBinding) {
        if self.binding != *expected { self.close(InputStatus::RequestChanged); }
        let facts = self.ctx.input(|input| {
            raw_facts(&input.raw).map(|mut facts| {
                facts.focused &= input.focused;
                facts.blur |= input.events.iter().any(is_blur);
                facts.escape |= input.events.iter().any(is_escape);
                facts
            })
        });
        self.observe(facts);
    }

    fn observe(&mut self, facts: Option<RawFacts>) {
        if !self.open() { return; }
        if Instant::now() >= self.original_deadline { self.close(InputStatus::Expired); return; }
        let Some(facts) = facts else { self.close(InputStatus::InvalidViewport); return; };
        if facts.blur || facts.escape || facts.close || (self.focus_seen && self.focused_last && !facts.focused) {
            self.close(InputStatus::Interrupted);
            return;
        }
        self.focus_seen |= facts.focused;
        self.focused_last = facts.focused;
        self.status = if facts.focused { InputStatus::Editing } else { InputStatus::WaitingForFocus };
    }

    fn close(&mut self, status: InputStatus) {
        if self.open() { self.status = status; }
        self.password.zeroize();
        self.raw_input_allowed = false;
        self.submit_frame = None;
        self.scrub_closed_frame();
    }

    fn scrub_closed_frame(&self) {
        if !self.owns_widget(&self.ctx) { return; }
        clear_widget(&self.ctx);
        scrub_context_payloads(&self.ctx);
        clear_sensitive_output(&self.ctx, true);
    }

    fn owns_widget(&self, ctx: &egui::Context) -> bool {
        ctx.data_mut(|data| data.get_temp::<WidgetLease>(widget_id()))
            .is_some_and(|lease| Arc::ptr_eq(&lease.0, &self.widget_lease))
    }
}

impl Drop for PasswordInput {
    fn drop(&mut self) {
        self.password.zeroize();
        self.scrub_closed_frame();
        if self.owns_widget(&self.ctx) {
            self.ctx.data_mut(|data| data.remove::<WidgetLease>(widget_id()));
        }
    }
}

fn widget_id() -> egui::Id { egui::Id::new(PASSWORD_ID) }

fn eligible_pass(admitted: bool, focused: bool, enabled: bool, visible: bool, sizing: bool, discarded: bool) -> bool {
    admitted && focused && enabled && visible && !sizing && !discarded
}

fn clear_undo(ctx: &egui::Context) {
    if let Some(mut state) = egui::TextEdit::load_state(ctx, widget_id()) {
        // undoer() would clone the plaintext history. Never use it to clear.
        state.clear_undoer();
        state.store(ctx, widget_id());
    }
}

fn clear_widget(ctx: &egui::Context) {
    clear_undo(ctx);
    ctx.data_mut(|data| data.remove::<egui::text_edit::TextEditState>(widget_id()));
    ctx.memory_mut(|memory| {
        memory.surrender_focus(widget_id());
        memory.interrupt_ime();
    });
    ctx.output_mut(|output| output.ime = None);
}

fn clear_sensitive_output(ctx: &egui::Context, terminal: bool) {
    ctx.output_mut(|output| {
        for command in &mut output.commands {
            if let egui::OutputCommand::CopyText(text) = command { text.zeroize(); }
        }
        output.commands.clear();
        output.events.clear();
        output.accesskit_update = None;
        if terminal { output.ime = None; output.mutable_text_under_cursor = false; }
    });
}

fn scrub_payloads(events: &mut Vec<egui::Event>) {
    events.retain_mut(|event| match event {
        egui::Event::Text(text) | egui::Event::Paste(text)
        | egui::Event::Ime(egui::ImeEvent::Preedit { text, .. })
        | egui::Event::Ime(egui::ImeEvent::Commit(text)) => { text.zeroize(); false }
        egui::Event::Ime(_) => false,
        _ => true,
    });
}

fn scrub_context_payloads(ctx: &egui::Context) {
    ctx.input_mut(|input| {
        scrub_payloads(&mut input.events);
        scrub_payloads(&mut input.raw.events);
    });
}

fn bounded_input_events(events: &[egui::Event]) -> bool {
    if events.len() > MAX_BATCH_EVENTS { return false; }
    let mut total = 0usize;
    for event in events {
        let length = match event {
            egui::Event::Text(text) | egui::Event::Paste(text)
            | egui::Event::Ime(egui::ImeEvent::Preedit { text, .. })
            | egui::Event::Ime(egui::ImeEvent::Commit(text)) => text.len(),
            _ => 0,
        };
        total = match total.checked_add(length) { Some(total) => total, None => return false };
        if total > MAX_PASSWORD_BYTES { return false; }
    }
    true
}

struct RawFacts { focused: bool, blur: bool, escape: bool, close: bool }
fn is_blur(event: &egui::Event) -> bool { matches!(event, egui::Event::WindowFocused(false)) }
fn is_escape(event: &egui::Event) -> bool {
    matches!(event, egui::Event::Key { key: egui::Key::Escape, pressed: true, .. })
}
fn raw_facts(raw: &egui::RawInput) -> Option<RawFacts> {
    if raw.viewport_id != egui::ViewportId::ROOT || raw.viewports.len() != 1 { return None; }
    let viewport = raw.viewports.get(&egui::ViewportId::ROOT)?;
    Some(RawFacts {
        focused: raw.focused && viewport.focused == Some(true),
        blur: raw.events.iter().any(is_blur), escape: raw.events.iter().any(is_escape),
        close: viewport.close_requested(),
    })
}
