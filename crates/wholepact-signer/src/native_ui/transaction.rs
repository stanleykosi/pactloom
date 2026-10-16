//! Signer-verified transaction review, kept separate from manifest-only preview.
//! No app API can synthesize input events or obtain this acknowledgment as authority.
use super::state::Phase;
use crate::{inspection::TransactionInspection, Error, Result};
use sha2::{Digest, Sha256};

pub(super) struct TransactionReview {
    surface: [u8; 32],
    generation: u64,
    focused: bool,
    phase: Phase,
    pending: Option<TransactionInspection>,
    approved: Option<TransactionInspection>,
    binding: Option<String>,
}
impl TransactionReview {
    pub(super) fn new() -> Result<Self> {
        Ok(Self {
            surface: crate::vault::random()?,
            generation: 0,
            focused: false,
            phase: Phase::Idle,
            pending: None,
            approved: None,
            binding: None,
        })
    }
    pub(super) fn phase(&self) -> Phase {
        self.phase
    }
    pub(super) fn display(&self) -> Option<&str> {
        self.pending.as_ref().map(TransactionInspection::display)
    }
    pub(super) fn binding(&self) -> Option<&str> {
        self.binding.as_deref()
    }
    pub(super) fn phrase(&self) -> Option<String> {
        self.binding().map(|b| format!("REVIEW {}", &b[..12]))
    }
    pub(super) fn invalidate(&mut self) {
        self.pending = None;
        self.approved = None;
        self.binding = None;
        self.generation = self.generation.saturating_add(1);
        self.phase = Phase::Idle;
    }
    pub(super) fn observe_focus(&mut self, focused: bool) {
        if !focused {
            self.invalidate();
        }
        self.focused = focused;
    }
    /// Takes independently verified, opaque inspection output, not arbitrary summary
    /// text, a policy JSON report, a preview receipt or a caller's verified flag.
    #[cfg_attr(not(feature = "synthetic-qualification"), allow(dead_code))]
    pub(super) fn stage(&mut self, review: TransactionInspection) -> Result<()> {
        self.invalidate();
        review.recheck()?;
        let mut hash = Sha256::new();
        hash.update(b"wholepact:native-transaction-session:v1\0");
        hash.update(self.surface);
        hash.update(self.generation.to_le_bytes());
        hash.update(review.binding().as_bytes());
        self.binding = Some(hex::encode(hash.finalize()));
        self.pending = Some(review);
        self.phase = Phase::Reading;
        Ok(())
    }
    pub(super) fn expire(&mut self) {
        // The approved review still contains sensitive retained bytes. Discard it
        // on the same original lifetime, not a fresh lifetime after the click.
        let expired = self.pending.as_ref().is_some_and(|r| r.expired())
            || self.approved.as_ref().is_some_and(|r| r.expired());
        if expired {
            self.invalidate();
        }
    }
    pub(super) fn continue_from_local_click(&mut self) -> Result<()> {
        self.expire();
        if !self.focused || self.phase != Phase::Reading || self.pending.is_none() {
            return Err(Error::ReviewMismatch);
        }
        self.pending
            .as_ref()
            .ok_or(Error::ReviewMismatch)?
            .recheck()?;
        self.phase = Phase::Confirming;
        Ok(())
    }
    pub(super) fn confirm_from_local_click(
        &mut self,
        phrase: &str,
        understood: bool,
    ) -> Result<()> {
        self.expire();
        // Consume a failed attempt too. There is no retryable detached approval token.
        let valid = self.focused
            && self.phase == Phase::Confirming
            && understood
            && self.phrase().as_deref() == Some(phrase);
        let pending = self.pending.take();
        self.phase = Phase::Rejected;
        if !valid {
            self.invalidate();
            return Err(Error::ReviewMismatch);
        }
        let pending = pending.ok_or(Error::ReviewMismatch)?;
        pending.recheck()?;
        // Retain an inspection only, never a HumanApprovedReview or release token.
        self.approved = Some(pending);
        self.phase = Phase::Accepted;
        Ok(())
    }
}

#[cfg(all(test, feature = "synthetic-qualification"))]
mod tests {
    use super::*;
    fn ready() -> TransactionReview {
        let mut s = TransactionReview::new().unwrap();
        s.observe_focus(true);
        s.stage(
            crate::review::PreparedReview::synthetic_preview()
                .unwrap()
                .into_inspection(),
        )
        .unwrap();
        s.continue_from_local_click().unwrap();
        s
    }
    #[test]
    fn real_crypto_review_consumes_once_and_never_upgrades_runtime_authority() {
        let mut s = ready();
        assert!(s
            .display()
            .unwrap()
            .contains("Own net debit: 105000 zatoshis"));
        let phrase = s.phrase().unwrap();
        s.confirm_from_local_click(&phrase, true).unwrap();
        assert_eq!(s.phase(), Phase::Accepted);
        let approved = s.approved.take().unwrap();
        assert!(!approved.authorization_allowed());
        assert!(matches!(
            crate::provision_live_account(),
            Err(Error::Unavailable)
        ));
        assert!(s.confirm_from_local_click(&phrase, true).is_err());
    }
    #[test]
    fn original_expiry_erases_pending_and_acknowledged_private_bytes() {
        for acknowledged in [false, true] {
            let mut s = ready();
            let phrase = s.phrase().unwrap();
            if acknowledged {
                s.confirm_from_local_click(&phrase, true).unwrap();
                s.approved.as_mut().unwrap().expire_for_test();
            } else {
                s.pending.as_mut().unwrap().expire_for_test();
            }
            s.expire();
            assert_eq!(s.phase(), Phase::Idle);
            assert!(s.pending.is_none() && s.approved.is_none() && s.binding.is_none());
            assert!(s.confirm_from_local_click(&phrase, true).is_err());
        }
    }
    #[test]
    fn replacement_wrong_phrase_focus_cancel_and_cross_surface_cannot_replay() {
        for reason in 0..5 {
            let mut s = ready();
            let phrase = s.phrase().unwrap();
            match reason {
                0 => {
                    s.stage(
                        crate::review::PreparedReview::synthetic_preview()
                            .unwrap()
                            .into_inspection(),
                    )
                    .unwrap();
                    s.continue_from_local_click().unwrap();
                }
                1 => {
                    s.observe_focus(false);
                    s.observe_focus(true);
                }
                2 => s.invalidate(),
                3 => s = ready(),
                _ => {
                    assert!(s.confirm_from_local_click("wrong", true).is_err());
                }
            }
            assert!(s.confirm_from_local_click(&phrase, true).is_err());
            assert!(s.approved.is_none());
        }
    }
}
