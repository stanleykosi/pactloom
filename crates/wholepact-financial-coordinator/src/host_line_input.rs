//! Dormant protected input for ONE explicitly entered Host terminal line.
//! No terminal, endpoint, native App callsite, command parser or authority exists
//! here. ALL lines are masked, regardless of prompt contents. Empty/short input
//! is intentional; the sole added newline belongs to the genuine endpoint.
//!
//! The future same-App caller must latch shared/local R before scrub/close,
//! exclusively choose this editor OR the separate Signer credential editor,
//! forward each original raw batch, process all cancel controls before the
//! eligible final tail, and explicitly activate a later fresh line slot only
//! after the prior slot and queued line have ended. Closed slots never reopen.
//! Ordinal and original terminal deadline are only local correlation, never a
//! source token, action grant, replacement terminal or permission to auto-answer.
//!
//! Owned input is zeroized when entry ends or moved once into its bounded result.
//! Retained widget undo is removed. Stock GUI/backend/OS/IME/clipboard copies
//! may be dropped rather than overwritten; full erasure is NOT guaranteed.
//! There is no reveal, history, local echo, prompt inference or clipboard clear.
//! Mandatory feature log-off and its compile assertion protect backend logging.
#![allow(dead_code)] // Deliberately no runtime callsite.

use eframe::egui;
use std::time::Instant;
use zeroize::{Zeroize, Zeroizing};

const MAX_LINE_BYTES: usize = 8192;
const MAX_BATCH_EVENTS: usize = 256;
const HOST_LINE_ID: &str = "wholepact.coordinator.protected-host-line.v1";
// Release-specific log features take precedence over max_level_off. Fail the
// build if future feature unification would make either profile log input.
const _: () = assert!(matches!(log::STATIC_MAX_LEVEL, log::LevelFilter::Off));

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HostLineStatus {
    WaitingForFocus,
    Editing,
    Cancelled,
    Interrupted,
    InvalidViewport,
    RequestChanged,
    Expired,
    InvalidPayload,
    InvalidLine,
    Submitted,
}

/// A non-Clone, non-Debug, non-serializable, one-use owned user line. Even success is
/// only user INPUT. The ordinal/deadline correlate a local slot, not authority.
pub(super) struct SubmittedHostLine {
    ordinal: u64,
    original_deadline: Instant,
    line: Zeroizing<String>,
}

impl SubmittedHostLine {
    /// Consuming a mismatched result drops/zeroizes it; no retry or retargeting.
    pub(super) fn into_line_for(self, expected: u64) -> Option<Zeroizing<String>> {
        if self.ordinal != expected || Instant::now() >= self.original_deadline {
            None
        } else {
            Some(self.line)
        }
    }
}

#[derive(Clone)]
struct WidgetLease;

pub(super) struct HostLineInput {
    ctx: egui::Context,
    ordinal: u64,
    original_deadline: Instant,
    line: Zeroizing<String>,
    status: HostLineStatus,
    focus_seen: bool,
    focused_last: bool,
    raw_input_allowed: bool,
    submit_frame: Option<u64>,
}

impl HostLineInput {
    /// One fixed widget ID has one live owner. A terminal slot must be dropped
    /// before another is created, so two line slots cannot alias retained edit state.
    pub(super) fn new(
        ctx: &egui::Context,
        ordinal: u64,
        original_deadline: Instant,
    ) -> Option<Self> {
        if ordinal == 0 || Instant::now() >= original_deadline {
            return None;
        }
        let acquired = ctx.data_mut(|data| {
            if data.get_temp::<WidgetLease>(widget_id()).is_some() {
                false
            } else {
                data.insert_temp(widget_id(), WidgetLease);
                true
            }
        });
        if !acquired {
            return None;
        }
        clear_widget(ctx);
        Some(Self {
            ctx: ctx.clone(),
            ordinal,
            original_deadline,
            line: Zeroizing::new(String::with_capacity(2 * MAX_LINE_BYTES)),
            status: HostLineStatus::WaitingForFocus,
            focus_seen: false,
            focused_last: false,
            raw_input_allowed: false,
            submit_frame: None,
        })
    }

    pub(super) fn status(&self) -> HostLineStatus {
        self.status
    }

    fn open(&self) -> bool {
        matches!(
            self.status,
            HostLineStatus::WaitingForFocus | HostLineStatus::Editing
        )
    }

    /// Forward from App::raw_input_hook BEFORE any visible or hidden callback.
    /// Inspect the whole immutable interruption history before removing payloads.
    /// Closed/unfocused/expired requests never admit delayed text or IME input.
    pub(super) fn raw_input_hook(&mut self, raw: &mut egui::RawInput) {
        self.raw_input_allowed = false;
        self.submit_frame = None;
        self.observe(raw_facts(raw));
        if self.open() && !bounded_input_events(&raw.events) {
            self.close(HostLineStatus::InvalidPayload);
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
    pub(super) fn show(&mut self, ui: &mut egui::Ui, expected: u64) {
        if ui.ctx() != &self.ctx || ui.ctx().viewport_id() != egui::ViewportId::ROOT {
            self.close(HostLineStatus::InvalidViewport);
            return;
        }
        self.check_current(expected);
        if !self.open() {
            self.scrub_closed_frame();
            return;
        }
        if !self.ctx.input(|input| {
            bounded_input_events(&input.events) && bounded_input_events(&input.raw.events)
        }) {
            self.close(HostLineStatus::InvalidPayload);
            return;
        }
        if ui
            .button("Cancel Host line entry")
            .clicked_by(egui::PointerButton::Primary)
        {
            self.cancel();
            return;
        }
        let admitted_batch = std::mem::take(&mut self.raw_input_allowed);
        let eligible = eligible_pass(
            admitted_batch,
            self.focused_last,
            ui.is_enabled(),
            ui.is_visible(),
            ui.is_sizing_pass(),
            self.ctx.will_discard(),
        );
        if !eligible {
            scrub_context_payloads(&self.ctx);
        }
        if !self.focused_last {
            return;
        }

        clear_undo(&self.ctx);
        let mut output = egui::TextEdit::singleline(&mut *self.line)
            .id(widget_id())
            .password(true)
            .interactive(eligible)
            // Batch preflight bounds accepted bytes. This larger defensive
            // character cap never turns an overlength line into success:
            // the authoritative local limit below is BYTES, without normalization.
            .char_limit(2 * MAX_LINE_BYTES)
            .show(ui);
        output.state.clear_undoer();
        output.state.store(&self.ctx, output.response.id);
        // Do not store this old output again after any terminal cleanup.
        scrub_context_payloads(&self.ctx);
        clear_sensitive_output(&self.ctx, false);
        if !valid_line(&self.line) {
            self.close(HostLineStatus::InvalidPayload);
            return;
        }
        let submit = ui
            .add_enabled(eligible, egui::Button::new("Send this exact Host line"))
            .clicked_by(egui::PointerButton::Primary);
        if submit {
            self.submit_frame = Some(self.ctx.cumulative_frame_nr());
        }
    }

    /// Call at the visible frame tail, AFTER every remaining Cancel control.
    /// Hidden/discarded/repeated passes cannot submit, and no input caller can
    /// fabricate an intent through this API. The original deadline never renews.
    pub(super) fn finish_frame(&mut self, expected: u64) -> Option<SubmittedHostLine> {
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
        if !self.open() || !self.focused_last || !requested || self.ctx.will_discard() {
            return None;
        }
        if !valid_line(&self.line) {
            self.close(HostLineStatus::InvalidLine);
            return None;
        }
        let line = std::mem::take(&mut self.line);
        self.close(HostLineStatus::Submitted);
        Some(SubmittedHostLine {
            ordinal: self.ordinal,
            original_deadline: self.original_deadline,
            line,
        })
    }

    /// Line/phase replacement, upstream cancellation and terminal failure MUST
    /// reach this before further widgets. A canceled slot cannot be reopened.
    pub(super) fn cancel(&mut self) {
        self.close(HostLineStatus::Cancelled);
    }

    fn check_current(&mut self, expected: u64) {
        if self.ordinal != expected {
            self.close(HostLineStatus::RequestChanged);
        }
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
        if !self.open() {
            return;
        }
        if Instant::now() >= self.original_deadline {
            self.close(HostLineStatus::Expired);
            return;
        }
        let Some(facts) = facts else {
            self.close(HostLineStatus::InvalidViewport);
            return;
        };
        if facts.blur
            || facts.escape
            || facts.close
            || (self.focus_seen && self.focused_last && !facts.focused)
        {
            self.close(HostLineStatus::Interrupted);
            return;
        }
        self.focus_seen |= facts.focused;
        self.focused_last = facts.focused;
        self.status = if facts.focused {
            HostLineStatus::Editing
        } else {
            HostLineStatus::WaitingForFocus
        };
    }

    fn close(&mut self, status: HostLineStatus) {
        if self.open() {
            self.status = status;
        }
        self.line.zeroize();
        self.raw_input_allowed = false;
        self.submit_frame = None;
        self.scrub_closed_frame();
    }

    fn scrub_closed_frame(&self) {
        clear_widget(&self.ctx);
        scrub_context_payloads(&self.ctx);
        clear_sensitive_output(&self.ctx, true);
    }
}

impl Drop for HostLineInput {
    fn drop(&mut self) {
        self.line.zeroize();
        self.scrub_closed_frame();
        self.ctx
            .data_mut(|data| data.remove::<WidgetLease>(widget_id()));
    }
}

fn widget_id() -> egui::Id {
    egui::Id::new(HOST_LINE_ID)
}

fn eligible_pass(
    admitted: bool,
    focused: bool,
    enabled: bool,
    visible: bool,
    sizing: bool,
    discarded: bool,
) -> bool {
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
            if let egui::OutputCommand::CopyText(text) = command {
                text.zeroize();
            }
        }
        output.commands.clear();
        output.events.clear();
        output.accesskit_update = None;
        if terminal {
            output.ime = None;
            output.mutable_text_under_cursor = false;
        }
    });
}

fn scrub_payloads(events: &mut Vec<egui::Event>) {
    events.retain_mut(|event| match event {
        egui::Event::Text(text)
        | egui::Event::Paste(text)
        | egui::Event::Ime(egui::ImeEvent::Preedit { text, .. })
        | egui::Event::Ime(egui::ImeEvent::Commit(text)) => {
            text.zeroize();
            false
        }
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

fn valid_line(line: &str) -> bool {
    line.len() <= MAX_LINE_BYTES && !line.bytes().any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
}

fn bounded_input_events(events: &[egui::Event]) -> bool {
    if events.len() > MAX_BATCH_EVENTS {
        return false;
    }
    let mut total = 0usize;
    for event in events {
        let length = match event {
            egui::Event::Text(text)
            | egui::Event::Paste(text)
            | egui::Event::Ime(egui::ImeEvent::Preedit { text, .. })
            | egui::Event::Ime(egui::ImeEvent::Commit(text)) => {
                // Reject BEFORE stock singleline paste could normalize CR/LF
                // into a different accepted command. No trim/normalization.
                if !valid_line(text) {
                    return false;
                }
                text.len()
            }
            _ => 0,
        };
        total = match total.checked_add(length) {
            Some(total) => total,
            None => return false,
        };
        if total > MAX_LINE_BYTES {
            return false;
        }
    }
    true
}

struct RawFacts {
    focused: bool,
    blur: bool,
    escape: bool,
    close: bool,
}
fn is_blur(event: &egui::Event) -> bool {
    matches!(event, egui::Event::WindowFocused(false))
}
fn is_escape(event: &egui::Event) -> bool {
    matches!(
        event,
        egui::Event::Key {
            key: egui::Key::Escape,
            pressed: true,
            ..
        }
    )
}
fn raw_facts(raw: &egui::RawInput) -> Option<RawFacts> {
    if raw.viewport_id != egui::ViewportId::ROOT || raw.viewports.len() != 1 {
        return None;
    }
    let viewport = raw.viewports.get(&egui::ViewportId::ROOT)?;
    Some(RawFacts {
        focused: raw.focused && viewport.focused == Some(true),
        blur: raw.events.iter().any(is_blur),
        escape: raw.events.iter().any(is_escape),
        close: viewport.close_requested(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // Fabricated ordinary test strings only. No native window, Context::run_ui,
    // source opener, line derivation, key generation, IPC or backend runs.
    const MOCK: &str = "fabricated-input-only";

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }
    fn focused_raw() -> egui::RawInput {
        let mut raw = egui::RawInput::default();
        raw.focused = true;
        raw.viewports
            .get_mut(&egui::ViewportId::ROOT)
            .unwrap()
            .focused = Some(true);
        raw
    }
    fn context() -> egui::Context {
        let ctx = egui::Context::default();
        ctx.input_mut(|input| {
            input.raw = focused_raw();
            input.focused = true;
        });
        ctx
    }
    fn payloads() -> Vec<egui::Event> {
        vec![
            egui::Event::Text(MOCK.into()),
            egui::Event::Paste(MOCK.into()),
            egui::Event::Ime(egui::ImeEvent::Preedit {
                text: MOCK.into(),
                active_range_chars: Some(0..1),
            }),
            egui::Event::Ime(egui::ImeEvent::Commit(MOCK.into())),
            egui::Event::Ime(egui::ImeEvent::DeleteSurrounding {
                before_chars: 1,
                after_chars: 0,
            }),
        ]
    }
    fn seed_undo(ctx: &egui::Context) -> egui::text_edit::TextEditState {
        let mut state = egui::text_edit::TextEditState::default();
        let mut history =
            egui::util::undoer::Undoer::<(egui::text::CCursorRange, String)>::default();
        history.feed_state(0.0, &(egui::text::CCursorRange::default(), MOCK.into()));
        state.set_undoer(history);
        state.clone().store(ctx, widget_id());
        state
    }

    #[test]
    fn empty_short_and_utf8_lines_are_exact_not_normalized() {
        for text in ["", "n", " x ", "é"] {
            let ctx = context();
            let mut slot = HostLineInput::new(&ctx, 1, deadline()).unwrap();
            slot.line.push_str(text);
            slot.submit_frame = Some(ctx.cumulative_frame_nr()); // Fabricated intent only.
            let submitted = slot.finish_frame(1).unwrap();
            assert_eq!(&*submitted.into_line_for(1).unwrap(), text);
            assert_eq!(slot.status(), HostLineStatus::Submitted);
            assert!(slot.line.is_empty() && slot.finish_frame(1).is_none());
        }
        assert!(valid_line(&"é".repeat(4096)));
        assert!(!valid_line(&"é".repeat(4097)));
    }
    #[test]
    fn forbidden_control_payloads_are_rejected_before_singleline_normalization() {
        for text in ["line\nbreak", "line\rbreak", "zero\0byte"] {
            for event in [
                egui::Event::Text(text.into()),
                egui::Event::Paste(text.into()),
                egui::Event::Ime(egui::ImeEvent::Preedit {
                    text: text.into(),
                    active_range_chars: None,
                }),
                egui::Event::Ime(egui::ImeEvent::Commit(text.into())),
            ] {
                let ctx = context();
                let mut slot = HostLineInput::new(&ctx, 1, deadline()).unwrap();
                let mut raw = focused_raw();
                raw.events.push(event);
                slot.raw_input_hook(&mut raw);
                assert_eq!(slot.status(), HostLineStatus::InvalidPayload);
                assert!(raw.events.is_empty() && slot.line.is_empty());
            }
        }
    }
    #[test]
    fn host_widget_is_distinct_from_signer_and_zero_ordinal_is_invalid() {
        assert_ne!(
            widget_id(),
            egui::Id::new("wholepact.coordinator.transient-password.v1")
        );
        let ctx = context();
        assert!(HostLineInput::new(&ctx, 0, deadline()).is_none());
        assert!(ctx == ctx.clone());
        assert!(ctx != egui::Context::default());
    }
    #[test]
    fn fixed_widget_has_one_owner_until_terminal_owner_is_dropped() {
        let ctx = context();
        let mut slot = HostLineInput::new(&ctx, 1, deadline()).unwrap();
        assert!(HostLineInput::new(&ctx, 2, deadline()).is_none());
        slot.cancel();
        assert!(HostLineInput::new(&ctx, 2, deadline()).is_none());
        drop(slot);
        assert!(HostLineInput::new(&ctx, 2, deadline()).is_some());
    }

    #[test]
    fn same_batch_blur_refocus_wins_before_payloads_and_cannot_reopen() {
        let ctx = context();
        let mut slot = HostLineInput::new(&ctx, 1, deadline()).unwrap();
        slot.line.push_str(MOCK);
        let mut raw = focused_raw();
        raw.events = payloads();
        raw.events.extend([
            egui::Event::WindowFocused(false),
            egui::Event::WindowFocused(true),
        ]);
        slot.raw_input_hook(&mut raw);
        assert_eq!(slot.status(), HostLineStatus::Interrupted);
        assert!(slot.line.is_empty());
        assert_eq!(
            raw.events,
            vec![
                egui::Event::WindowFocused(false),
                egui::Event::WindowFocused(true)
            ]
        );
        raw.events = payloads();
        slot.raw_input_hook(&mut raw);
        assert!(raw.events.is_empty() && slot.line.is_empty() && !slot.raw_input_allowed);
        assert_eq!(slot.status(), HostLineStatus::Interrupted);
    }

    #[test]
    fn first_unfocused_batch_refuses_input_then_actual_focus_loss_is_terminal() {
        let ctx = context();
        let mut slot = HostLineInput::new(&ctx, 1, deadline()).unwrap();
        let mut raw = focused_raw();
        raw.focused = false;
        raw.events = payloads();
        slot.raw_input_hook(&mut raw);
        assert_eq!(slot.status(), HostLineStatus::WaitingForFocus);
        assert!(raw.events.is_empty() && !slot.raw_input_allowed);
        raw.focused = true;
        slot.raw_input_hook(&mut raw);
        assert!(slot.raw_input_allowed);
        raw.focused = false;
        slot.raw_input_hook(&mut raw);
        assert_eq!(slot.status(), HostLineStatus::Interrupted);
    }

    #[test]
    fn missing_viewport_escape_and_close_are_terminal_before_input() {
        for case in 0..3 {
            let ctx = context();
            let mut slot = HostLineInput::new(&ctx, 1, deadline()).unwrap();
            let mut raw = focused_raw();
            raw.events = payloads();
            match case {
                0 => raw.viewports.clear(),
                1 => raw.events.push(egui::Event::Key {
                    key: egui::Key::Escape,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: egui::Modifiers::NONE,
                }),
                _ => raw
                    .viewports
                    .get_mut(&egui::ViewportId::ROOT)
                    .unwrap()
                    .events
                    .push(egui::ViewportEvent::Close),
            }
            slot.raw_input_hook(&mut raw);
            assert!(!slot.open() && !slot.raw_input_allowed);
            assert!(raw.events.iter().all(|event| matches!(
                event,
                egui::Event::Key {
                    key: egui::Key::Escape,
                    ..
                }
            )));
        }
    }

    #[test]
    fn both_context_input_copies_scrub_text_paste_and_ime_but_preserve_blur() {
        let ctx = context();
        ctx.input_mut(|input| {
            input.events = payloads();
            input.raw.events = payloads();
            input.events.push(egui::Event::WindowFocused(false));
            input.raw.events.push(egui::Event::WindowFocused(false));
        });
        scrub_context_payloads(&ctx);
        ctx.input(|input| {
            assert_eq!(input.events, vec![egui::Event::WindowFocused(false)]);
            assert_eq!(input.raw.events, vec![egui::Event::WindowFocused(false)]);
        });
    }

    #[test]
    fn undo_clear_drops_shared_history_and_terminal_removes_widget_state() {
        let ctx = context();
        let mut slot = HostLineInput::new(&ctx, 1, deadline()).unwrap();
        let retained_state = seed_undo(&ctx);
        clear_undo(&ctx);
        // Inspection only AFTER clearing. Production never calls undoer(),
        // which would clone any remaining plaintext history.
        assert!(!retained_state
            .undoer()
            .has_undo(&(egui::text::CCursorRange::default(), String::new())));
        assert!(!retained_state.undoer().is_in_flux());
        seed_undo(&ctx);
        ctx.memory_mut(|memory| memory.request_focus(widget_id()));
        ctx.output_mut(|output| {
            output
                .commands
                .push(egui::OutputCommand::CopyText(MOCK.into()));
            output.mutable_text_under_cursor = true;
            output.ime = Some(egui::output::IMEOutput {
                purpose: egui::IMEPurpose::Password,
                rect: egui::Rect::ZERO,
                cursor_rect: egui::Rect::ZERO,
                should_interrupt_composition: false,
            });
        });
        slot.line.push_str(MOCK);
        slot.cancel();
        assert!(slot.line.is_empty());
        assert!(egui::TextEdit::load_state(&ctx, widget_id()).is_none());
        assert!(!ctx.memory(|memory| memory.has_focus(widget_id())));
        ctx.output(|output| {
            assert!(
                output.commands.is_empty()
                    && output.ime.is_none()
                    && !output.mutable_text_under_cursor
            )
        });
    }

    #[test]
    fn drop_removes_retained_undo_and_scrubs_both_input_copies() {
        let ctx = context();
        let mut slot = HostLineInput::new(&ctx, 1, deadline()).unwrap();
        slot.line.push_str(MOCK);
        seed_undo(&ctx);
        ctx.input_mut(|input| {
            input.events = payloads();
            input.raw.events = payloads();
        });
        drop(slot);
        assert!(egui::TextEdit::load_state(&ctx, widget_id()).is_none());
        ctx.input(|input| assert!(input.events.is_empty() && input.raw.events.is_empty()));
    }

    #[test]
    fn byte_and_batch_bounds_reject_instead_of_truncating_into_success() {
        assert!(bounded_input_events(&[egui::Event::Paste(
            "a".repeat(8192)
        )]));
        assert!(!bounded_input_events(&[egui::Event::Paste(
            "é".repeat(4097)
        )]));
        assert!(!bounded_input_events(&[
            egui::Event::Text("a".repeat(5000)),
            egui::Event::Paste("b".repeat(5000))
        ]));
        assert!(!bounded_input_events(&vec![
            egui::Event::Copy;
            MAX_BATCH_EVENTS + 1
        ]));
        let ctx = context();
        let mut slot = HostLineInput::new(&ctx, 1, deadline()).unwrap();
        let mut raw = focused_raw();
        raw.events
            .push(egui::Event::Text("a".repeat(MAX_LINE_BYTES + 1)));
        slot.raw_input_hook(&mut raw);
        assert_eq!(slot.status(), HostLineStatus::InvalidPayload);
        assert!(raw.events.is_empty());
    }

    #[test]
    fn hidden_sizing_disabled_discarded_or_repeated_pass_cannot_submit() {
        assert!(eligible_pass(true, true, true, true, false, false));
        for facts in [
            (false, true, true, true, false, false),
            (true, false, true, true, false, false),
            (true, true, false, true, false, false),
            (true, true, true, false, false, false),
            (true, true, true, true, true, false),
            (true, true, true, true, false, true),
        ] {
            assert!(!eligible_pass(
                facts.0, facts.1, facts.2, facts.3, facts.4, facts.5
            ));
        }
    }

    #[test]
    fn wrong_ordinal_and_cancel_after_intent_cannot_submit() {
        for expected in [2, 3] {
            let ctx = context();
            let mut slot = HostLineInput::new(&ctx, 1, deadline()).unwrap();
            slot.line.push_str(MOCK);
            slot.submit_frame = Some(ctx.cumulative_frame_nr());
            assert!(slot.finish_frame(expected).is_none());
            assert_eq!(slot.status(), HostLineStatus::RequestChanged);
            assert!(slot.line.is_empty());
        }
        let ctx = context();
        let expected = 1;
        let mut slot = HostLineInput::new(&ctx, expected, deadline()).unwrap();
        slot.line.push_str(MOCK);
        slot.submit_frame = Some(ctx.cumulative_frame_nr());
        slot.cancel();
        assert!(slot.finish_frame(expected).is_none() && slot.line.is_empty());
    }

    #[test]
    fn intent_moves_once_only_and_wrong_consumer_or_late_consumer_gets_nothing() {
        let ctx = context();
        let expected = 1;
        let mut slot = HostLineInput::new(&ctx, expected, deadline()).unwrap();
        slot.line.push_str(MOCK);
        assert!(slot.finish_frame(expected).is_none()); // no native intent
        slot.submit_frame = Some(ctx.cumulative_frame_nr()); // pure test-state fixture
        let result = slot.finish_frame(expected).unwrap();
        assert_eq!(slot.status(), HostLineStatus::Submitted);
        assert!(slot.line.is_empty() && slot.finish_frame(expected).is_none());
        assert_eq!(&*result.into_line_for(expected).unwrap(), MOCK);
        let wrong = SubmittedHostLine {
            ordinal: expected,
            original_deadline: deadline(),
            line: Zeroizing::new(MOCK.into()),
        };
        assert!(wrong.into_line_for(2).is_none());
        let late = SubmittedHostLine {
            ordinal: expected,
            original_deadline: Instant::now(),
            line: Zeroizing::new(MOCK.into()),
        };
        assert!(late.into_line_for(expected).is_none());
    }

    #[test]
    fn original_deadline_expiry_wipes_and_cannot_be_renewed_by_input() {
        let ctx = context();
        let expected = 1;
        assert!(HostLineInput::new(&ctx, expected, Instant::now()).is_none());
        let mut slot = HostLineInput::new(&ctx, expected, deadline()).unwrap();
        slot.line.push_str(MOCK);
        slot.original_deadline = Instant::now(); // pure expired-state fixture, no production setter
        slot.submit_frame = Some(ctx.cumulative_frame_nr());
        let mut raw = focused_raw();
        raw.events = payloads();
        slot.raw_input_hook(&mut raw);
        assert_eq!(slot.status(), HostLineStatus::Expired);
        assert!(
            raw.events.is_empty() && slot.line.is_empty() && slot.finish_frame(expected).is_none()
        );
    }

    #[test]
    fn invalid_line_is_terminal_and_all_frame_events_are_dropped() {
        for mock in [
            "not\none-line".to_owned(),
            "carriage\rreturn".to_owned(),
            "nul\0byte".to_owned(),
            "é".repeat(4097),
        ] {
            let ctx = context();
            let expected = 1;
            let mut slot = HostLineInput::new(&ctx, expected, deadline()).unwrap();
            slot.line.push_str(&mock);
            slot.submit_frame = Some(ctx.cumulative_frame_nr());
            ctx.input_mut(|input| {
                input.events = payloads();
                input.raw.events = payloads();
            });
            assert!(slot.finish_frame(expected).is_none());
            assert_eq!(slot.status(), HostLineStatus::InvalidLine);
            assert!(slot.line.is_empty());
            ctx.input(|input| assert!(input.events.is_empty() && input.raw.events.is_empty()));
        }
    }
}
