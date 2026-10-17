//! Finite exact profile setup for the genuine consumed born controller only.
//! No authority is constructed here. The supplied context retains the actual
//! source, account, local session and current native owner.
use super::*;

impl NamedRecipientWorkspace {
    pub(in crate::native_ui) fn retain_synthetic_original_born_profile(
        &mut self,
        owner: &NamedRecipientOwnerContext<'_>,
        pins: NamedRecipientPins,
        epoch: u64,
    ) -> Result<()> {
        let (actual, born_owner) = owner.born.ok_or(Error::ReviewMismatch)?;
        actual.check(born_owner)?;
        if self.live.is_some() || self.pending.is_some() || self.final_active() {
            return Err(Error::ReviewMismatch);
        }
        self.verifier_signing = hex::encode(pins.verifier_signing);
        self.verifier_transport = hex::encode(pins.verifier_transport);
        self.witness_transport = hex::encode(pins.witness_transport);
        self.witness_certificate = pins.witness_certificate_digest;
        self.return_transport = hex::encode(pins.return_transport);
        self.prepare(owner, epoch, None)?;
        let p = self.pending.as_mut().ok_or(Error::Locked)?;
        self.frame = self.frame.saturating_add(1);
        if self.frame <= p.shown
            || p.review.confirming()
            || p.review.display().is_empty()
            || p.review.continue_from_native_click(false, epoch).is_ok()
            || p.review.continue_from_native_click(true, epoch + 1).is_ok()
        {
            return Err(Error::ReviewMismatch);
        }
        p.review.continue_from_native_click(true, epoch)?;
        p.continued = Some(self.frame);
        self.frame = self.frame.saturating_add(1);
        if !p.continued.is_some_and(|frame| self.frame > frame) {
            return Err(Error::ReviewMismatch);
        }
        self.phrase = Zeroizing::new(format!("AUTHORIZE {}", &p.review.digest()[..12]));
        // Same production final-click dispatcher, not a duplicate decision
        // constructor. Synthetic event delivery is not attended-human evidence.
        self.retain_reviewed_profile(owner, true, epoch)?;
        let live = self.live.as_ref().ok_or(Error::Locked)?;
        live.check_current(owner.journal, owner.session)?;
        live.check_display_association(owner.journal, owner.authority)?;
        actual.check(born_owner)
    }
}
