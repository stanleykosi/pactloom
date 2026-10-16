//! Connected, activation-gated evidence-only native entry and review surface.
//! One worker owns both actual vaults, fresh restricted pairing and the exact
//! preparations. Only genuine review machines and consumed decisions cross
//! bounded local channels; ordinary account ownership is never extracted.
#[cfg(test)]
use super::NativeAuthority;
use super::{
    NativeDecision,
    retirement_session::{
        RetirementEvidenceSession, RetirementSessionInputs, ReviewPhase, SessionReview,
    },
};
use crate::{Error, Result};
use eframe::egui;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum ExpectedReview {
    Pairing,
    #[default]
    Source,
    Destination,
    Delivery,
}
struct PendingReview {
    value: SessionReview,
    shown_frame: Option<u64>,
    continued_frame: Option<u64>,
}
#[derive(Default)]
struct ReviewInbox {
    expected: ExpectedReview,
    pending: Option<PendingReview>,
    confirmation: Zeroizing<String>,
}
impl ReviewInbox {
    fn waiting(&self) -> bool {
        self.pending.is_none() && self.expected != ExpectedReview::Delivery
    }
    fn accept(&mut self, value: SessionReview) -> Result<()> {
        let matching = matches!(
            (self.expected, value.phase),
            (ExpectedReview::Pairing, ReviewPhase::Pairing)
                | (ExpectedReview::Source, ReviewPhase::Source)
                | (ExpectedReview::Destination, ReviewPhase::Destination)
        );
        if self.pending.is_some() || !matching {
            return Err(Error::ReviewMismatch);
        }
        self.confirmation.zeroize();
        self.pending = Some(PendingReview {
            value,
            shown_frame: None,
            continued_frame: None,
        });
        Ok(())
    }
    fn presented(&mut self, frame: u64) {
        if let Some(pending) = &mut self.pending {
            pending.shown_frame.get_or_insert(frame);
        }
    }
    fn continue_from_click(&mut self, focused: bool, epoch: u64, frame: u64) -> Result<()> {
        let pending = self.pending.as_mut().ok_or(Error::Locked)?;
        if pending.shown_frame.is_none_or(|shown| frame <= shown)
            || pending.continued_frame.is_some()
        {
            return Err(Error::ReviewMismatch);
        }
        pending
            .value
            .exact
            .continue_from_native_click(focused, epoch)?;
        pending.continued_frame = Some(frame);
        Ok(())
    }
    fn consume_from_click(
        &mut self,
        focused: bool,
        epoch: u64,
        frame: u64,
    ) -> Result<(ReviewPhase, NativeDecision)> {
        let pending = self.pending.take().ok_or(Error::Locked)?;
        if pending
            .continued_frame
            .is_none_or(|continued| frame <= continued)
        {
            self.confirmation.zeroize();
            return Err(Error::ReviewMismatch);
        }
        let decision = pending
            .value
            .exact
            .consume_native_click(focused, epoch, &self.confirmation);
        self.confirmation.zeroize();
        let decision = decision?;
        self.expected = match pending.value.phase {
            ReviewPhase::Pairing => ExpectedReview::Source,
            ReviewPhase::Source => ExpectedReview::Destination,
            ReviewPhase::Destination => ExpectedReview::Delivery,
        };
        Ok((pending.value.phase, decision))
    }
    fn clear(&mut self) {
        *self = Self::default();
    }
}

#[derive(Default)]
pub(super) struct RetirementEvidenceSessionUi {
    active: Option<RetirementEvidenceSession>,
    // Admission permits at most one session, so this collection never grows
    // beyond one. No replacement is admitted until that exact thread is joined.
    draining: Vec<RetirementEvidenceSession>,
    reviews: ReviewInbox,
    message: &'static str,
    destination_path: String,
    destination_password: Zeroizing<String>,
    runtime_directory: String,
}
impl RetirementEvidenceSessionUi {
    /// Caller is the focused native runtime branch after ordinary lock/drain.
    /// The shared public gate precedes copying passwords, native creation,
    /// source opening, provider work, endpoint binding and publication.
    pub(super) fn begin_native(
        &mut self,
        entry: super::runtime::RetirementNativeEntry,
        source: &Path,
        password: &[u8],
    ) -> Result<()> {
        wholepact_signer_origin::retirement_evidence::require_native_transport_activation_v1()
            .map_err(|_| Error::Unavailable)?;
        self.drain_finished();
        if self.is_active() {
            return Err(Error::Locked);
        }
        let inputs = RetirementSessionInputs {
            source_root: source.into(),
            source_password: Zeroizing::new(password.to_vec()),
            destination_root: Path::new(&self.destination_path).into(),
            destination_password: Zeroizing::new(self.destination_password.as_bytes().to_vec()),
            runtime_directory: Path::new(&self.runtime_directory).into(),
        };
        self.destination_password.zeroize();
        let active = RetirementEvidenceSession::start(entry, inputs)?;
        self.reviews.clear();
        self.reviews.expected = ExpectedReview::Pairing;
        self.message = "Fresh restricted pairing and two separate exact evidence reviews are required. The original native deadline includes unlock and pairing.";
        self.active = Some(active);
        Ok(())
    }
    pub(super) fn entry_fields(&mut self, ui: &mut egui::Ui) {
        ui.label("Uses the existing source account directory and password above, after ordinary Lock has fully drained. Old grants and native owners are never transferred.");
        ui.label("Existing independently controlled destination account directory");
        ui.add(egui::TextEdit::singleline(&mut self.destination_path).char_limit(4096));
        ui.label("Destination vault password (native-only; erased after the attempt)");
        ui.add(
            egui::TextEdit::singleline(&mut *self.destination_password)
                .password(true)
                .char_limit(1024),
        );
        ui.label("Existing separate private runtime directory, outside both account trees");
        ui.add(egui::TextEdit::singleline(&mut self.runtime_directory).char_limit(4096));
        ui.label("Activation is unavailable pending attended-native and real transport qualification. No ordinary IPC, financial action, recovery source or retirement readiness is granted.");
    }
    pub(super) fn erase_entry_password(&mut self) {
        self.destination_password.zeroize();
    }
    pub(super) fn is_active(&self) -> bool {
        self.active.is_some() || !self.draining.is_empty()
    }
    pub(super) fn has_content(&self) -> bool {
        self.is_active() || !self.message.is_empty()
    }
    /// Hide and erase review input immediately. Revocation is monotone, but a
    /// syscall already admitted may have disclosed output. Ordinary clear never
    /// joins a running worker or releases its vault ownership early.
    pub(super) fn clear(&mut self) {
        self.destination_path.clear();
        self.destination_password.zeroize();
        self.runtime_directory.clear();
        self.reviews.clear();
        if let Some(active) = self.active.take() {
            active.cancel();
            self.draining.push(active);
            self.message = "Evidence request cancelled. Already-admitted output may have been disclosed; no recall or safe retry is promised.";
        } else if self.draining.is_empty() {
            self.message = "";
        }
        self.drain_finished();
    }
    fn drain_finished(&mut self) {
        let mut index = 0;
        while index < self.draining.len() {
            if self.draining[index].is_finished() {
                let _ = self.draining[index].finish();
                self.draining.remove(index);
            } else {
                index += 1;
            }
        }
    }
    /// Account replacement is an invalidation attempt even if the new account
    /// subsequently fails to open. It cannot overlap a draining old session.
    pub(super) fn before_account_replacement(&mut self) -> Result<()> {
        self.clear();
        self.message = "";
        if self.is_active() {
            return Err(Error::Locked);
        }
        Ok(())
    }
    pub(super) fn poll_lifecycle(&mut self, focused: bool, epoch: u64) {
        self.drain_finished();
        let Some(active) = self.active.as_mut() else {
            return;
        };
        if !focused || active.focus_epoch() != epoch {
            self.clear();
            return;
        }
        if active.is_finished() {
            let result = active.finish();
            self.active = None;
            self.reviews.clear();
            self.message = if result.is_ok() {
                "The bounded evidence attempt completed locally. This does not establish recipient receipt, current ownership after delivery, or retirement readiness."
            } else {
                "The evidence attempt failed or was cancelled. Partial or complete disclosure may already have occurred; no automatic retry is available."
            };
            return;
        }
        if active.check_ui_poll_current().is_err() {
            self.clear();
            return;
        }
        if self.reviews.waiting() {
            match active.try_review() {
                Ok(Some(review)) => {
                    if self.reviews.accept(review).is_err() {
                        self.clear();
                    }
                }
                Ok(None) => {}
                Err(_) => self.clear(),
            }
        }
    }
    pub(super) fn ui(&mut self, ui: &mut egui::Ui, focused: bool, epoch: u64) {
        self.poll_lifecycle(focused, epoch);
        if !focused || !self.has_content() {
            return;
        }
        // egui may invoke this surface more than once in one rendered frame.
        // A local invocation/pass counter must not authorize another click stage.
        let frame = ui.ctx().cumulative_frame_nr();
        ui.label("Evidence-only retirement observation. No funds movement, signing, recovery source or retirement completion is available.");
        if !self.draining.is_empty() {
            ui.label("Cancellation is draining the original request. Its vault owners remain retained; replacement requests are blocked.");
        }
        let mut continue_clicked = false;
        let mut approve_clicked = false;
        if let Some(pending) = &self.reviews.pending {
            ui.label(pending.value.exact.display());
            if pending.value.exact.confirming() {
                ui.label(format!(
                    "Type AUTHORIZE {}",
                    &pending.value.exact.digest()[..12]
                ));
                ui.add(egui::TextEdit::singleline(&mut *self.reviews.confirmation).char_limit(32));
                let separate_frame = pending.continued_frame.is_some_and(|first| frame > first);
                approve_clicked = ui
                    .add_enabled(
                        separate_frame,
                        egui::Button::new("Approve this exact evidence review"),
                    )
                    .clicked_by(egui::PointerButton::Primary);
            } else {
                let separate_frame = pending.shown_frame.is_some_and(|first| frame > first);
                continue_clicked = ui
                    .add_enabled(
                        separate_frame,
                        egui::Button::new("Continue exact evidence review"),
                    )
                    .clicked_by(egui::PointerButton::Primary);
            }
        }
        self.reviews.presented(frame);
        if continue_clicked
            && self
                .reviews
                .continue_from_click(focused, epoch, frame)
                .is_err()
        {
            self.clear();
        }
        if approve_clicked {
            let result = self
                .reviews
                .consume_from_click(focused, epoch, frame)
                .and_then(|(phase, decision)| {
                    self.active
                        .as_mut()
                        .ok_or(Error::Locked)?
                        .submit_decision(phase, decision)
                });
            if result.is_err() {
                self.clear();
            }
        }
        ui.label(self.message);
        if ui
            .button("Clear evidence review and lock its destinations")
            .clicked_by(egui::PointerButton::Primary)
        {
            self.clear();
        }
        if self.is_active() {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(20));
        }
    }
}
impl Drop for RetirementEvidenceSessionUi {
    fn drop(&mut self) {
        self.clear();
        // Normal clear is nonblocking. Final owner destruction invokes each
        // session's cancel-and-join fallback, never silently detaching a worker.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_ui::authority::{ExactNativeReview, recovery_test_authority};

    fn review(native: &NativeAuthority, phase: ReviewPhase, digit: &str) -> SessionReview {
        SessionReview {
            phase,
            exact: ExactNativeReview::stage(
                native,
                &digit.repeat(64),
                "Synthetic review-machine fixture; no attended consent or transport.".into(),
                7,
            )
            .unwrap(),
        }
    }
    fn ready(inbox: &mut ReviewInbox, frame: u64) {
        inbox.presented(frame);
        inbox.continue_from_click(true, 7, frame + 1).unwrap();
        let digest = inbox.pending.as_ref().unwrap().value.exact.digest();
        inbox
            .confirmation
            .push_str(&format!("AUTHORIZE {}", &digest[..12]));
    }

    #[test]
    fn session_review_uses_separate_present_continue_and_consume_frames() {
        let native = recovery_test_authority();
        let mut inbox = ReviewInbox::default();
        inbox
            .accept(review(&native, ReviewPhase::Source, "a"))
            .unwrap();
        assert!(inbox.continue_from_click(true, 7, 1).is_err());
        inbox.presented(1);
        // Repeated layout passes in the same native frame cannot advance.
        for _ in 0..3 {
            inbox.presented(1);
            assert!(inbox.continue_from_click(true, 7, 1).is_err());
        }
        inbox.continue_from_click(true, 7, 2).unwrap();
        inbox.confirmation.push_str("AUTHORIZE aaaaaaaaaaaa");
        let (phase, decision) = inbox.consume_from_click(true, 7, 3).unwrap();
        assert!(matches!(phase, ReviewPhase::Source));
        assert_eq!(decision.reviewed_digest(), "a".repeat(64));
        assert!(decision.binding() == &native.binding());
        assert!(inbox.confirmation.is_empty());
        assert!(inbox.waiting());
    }
    #[test]
    fn session_egui_multipass_cannot_become_another_native_review_frame() {
        // Pure in-memory egui layout only: no window, display, provider, request
        // owner or transport. This verifies the maintained frame/pass distinction.
        let ctx = egui::Context::default();
        ctx.options_mut(|options| options.max_passes = 2.try_into().unwrap());
        let native = recovery_test_authority();
        let mut inbox = ReviewInbox::default();
        inbox
            .accept(review(&native, ReviewPhase::Source, "a"))
            .unwrap();
        let mut passes = 0;
        let output = ctx.run_ui(Default::default(), |ui| {
            let frame = ui.ctx().cumulative_frame_nr();
            assert_eq!(frame, 0);
            inbox.presented(frame);
            assert!(inbox.continue_from_click(true, 7, frame).is_err());
            if passes == 0 {
                ui.request_discard("synthetic same-frame layout pass");
            }
            passes += 1;
        });
        assert_eq!(passes, 2);
        output.drop_without_applying_deltas();
        let mut passes = 0;
        let output = ctx.run_ui(Default::default(), |ui| {
            let frame = ui.ctx().cumulative_frame_nr();
            assert_eq!(frame, 1);
            if passes == 0 {
                inbox.continue_from_click(true, 7, frame).unwrap();
                inbox.confirmation.push_str("AUTHORIZE aaaaaaaaaaaa");
                ui.request_discard("synthetic same-frame approval attempt");
            } else {
                assert!(inbox.consume_from_click(true, 7, frame).is_err());
            }
            passes += 1;
        });
        assert_eq!(passes, 2);
        assert!(inbox.pending.is_none());
        assert!(inbox.confirmation.is_empty());
        output.drop_without_applying_deltas();
    }
    #[test]
    fn session_review_same_frame_consume_is_terminal_and_erases_confirmation() {
        let native = recovery_test_authority();
        let mut inbox = ReviewInbox::default();
        inbox
            .accept(review(&native, ReviewPhase::Source, "a"))
            .unwrap();
        ready(&mut inbox, 1);
        assert!(inbox.consume_from_click(true, 7, 2).is_err());
        assert!(inbox.pending.is_none());
        assert!(inbox.confirmation.is_empty());
    }
    #[test]
    fn session_review_rejects_duplicate_out_of_order_and_post_delivery_review() {
        let native = recovery_test_authority();
        let mut inbox = ReviewInbox::default();
        assert!(
            inbox
                .accept(review(&native, ReviewPhase::Destination, "b"))
                .is_err()
        );
        inbox
            .accept(review(&native, ReviewPhase::Source, "a"))
            .unwrap();
        assert!(
            inbox
                .accept(review(&native, ReviewPhase::Source, "a"))
                .is_err()
        );
        ready(&mut inbox, 1);
        let _ = inbox.consume_from_click(true, 7, 3).unwrap();
        assert!(
            inbox
                .accept(review(&native, ReviewPhase::Source, "a"))
                .is_err()
        );
        inbox.confirmation.push_str("old source confirmation");
        inbox
            .accept(review(&native, ReviewPhase::Destination, "b"))
            .unwrap();
        assert!(inbox.confirmation.is_empty());
        ready(&mut inbox, 4);
        let (_, decision) = inbox.consume_from_click(true, 7, 6).unwrap();
        assert_eq!(decision.reviewed_digest(), "b".repeat(64));
        assert!(!inbox.waiting());
        assert!(
            inbox
                .accept(review(&native, ReviewPhase::Destination, "b"))
                .is_err()
        );
    }
    #[test]
    fn session_review_rejects_blur_epoch_and_revoked_original_native_owner() {
        for case in 0..3 {
            let native = recovery_test_authority();
            let mut inbox = ReviewInbox::default();
            inbox
                .accept(review(&native, ReviewPhase::Source, "a"))
                .unwrap();
            ready(&mut inbox, 1);
            if case == 2 {
                native.revoke_informational_now();
            }
            assert!(
                inbox
                    .consume_from_click(case != 0, if case == 1 { 8 } else { 7 }, 3)
                    .is_err()
            );
            assert!(inbox.pending.is_none());
            assert!(inbox.confirmation.is_empty());
        }
    }
    #[test]
    fn dedicated_pairing_precedes_both_evidence_reviews_with_fresh_confirmation() {
        let source = recovery_test_authority();
        let destination = recovery_test_authority();
        let mut inbox = ReviewInbox {
            expected: ExpectedReview::Pairing,
            ..Default::default()
        };
        assert!(
            inbox
                .accept(review(&source, ReviewPhase::Source, "a"))
                .is_err()
        );
        for (index, phase, native, digit) in [
            (0, ReviewPhase::Pairing, &source, "c"),
            (1, ReviewPhase::Source, &source, "a"),
            (2, ReviewPhase::Destination, &destination, "b"),
        ] {
            inbox.accept(review(native, phase, digit)).unwrap();
            assert!(inbox.confirmation.is_empty());
            let frame = index * 3;
            ready(&mut inbox, frame);
            let (actual, decision) = inbox.consume_from_click(true, 7, frame + 2).unwrap();
            assert_eq!(actual, phase);
            assert!(decision.binding() == &native.binding());
            assert!(inbox.confirmation.is_empty());
        }
        assert!(!inbox.waiting());
        assert!(
            inbox
                .accept(review(&source, ReviewPhase::Pairing, "c"))
                .is_err()
        );
    }
    #[test]
    fn dedicated_entry_clear_erases_destination_password_and_locations() {
        let mut state = RetirementEvidenceSessionUi::default();
        state.destination_path = "synthetic-destination-path".into();
        state
            .destination_password
            .push_str("public-synthetic-password");
        state.runtime_directory = "synthetic-runtime-path".into();
        state.clear();
        assert!(state.destination_path.is_empty());
        assert!(state.destination_password.is_empty());
        assert!(state.runtime_directory.is_empty());
        assert!(!state.is_active());
    }
    #[test]
    fn session_clear_discards_exact_review_and_private_confirmation() {
        let native = recovery_test_authority();
        let mut state = RetirementEvidenceSessionUi::default();
        state
            .reviews
            .accept(review(&native, ReviewPhase::Source, "a"))
            .unwrap();
        ready(&mut state.reviews, 1);
        state.clear();
        assert!(state.reviews.pending.is_none());
        assert!(state.reviews.confirmation.is_empty());
        assert!(!state.is_active());
        assert!(!state.has_content());
        assert!(state.before_account_replacement().is_ok());
    }
}
