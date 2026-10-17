//! Exactly one original payment on the SAME opaque consumed named controller.
//! Caller can neither select a new authorization after uncertainty nor replace
//! an original file. Native decisions are synthetic event delivery only.
use super::*;
use std::os::unix::fs::PermissionsExt;
#[derive(Clone, Copy, PartialEq, Eq)]
enum PaymentPhase {
    Retained,
    Submitting,
    Admitted,
    Signing,
    Returned,
}
pub(super) struct RetainedPayment {
    authorization: String,
    intent: PathBuf,
    returned: PathBuf,
    phase: PaymentPhase,
    references: Option<crate::consent_journal::OriginalNamedReturnReferencesV1>,
    _directory: tempfile::TempDir,
}
impl NamedContinuationFixtureV1 {
    pub(in crate::native_ui) fn retain_original_payment(
        &mut self,
        input: crate::consent_journal::OriginalNamedPaymentArtifactsV1,
    ) -> Result<(String, PathBuf)> {
        self.check_source()?;
        if self.payment.is_some()
            || !matches!(self.phase, Phase::Ready)
            || !self
                .completed_verifier_scopes
                .contains(&input.verifier_scope)
        {
            return Err(Error::ReviewMismatch);
        }
        let directory = tempfile::Builder::new()
            .prefix("pay-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(self.original.temporary.path())?;
        let intent = directory.path().join("original-intent.json");
        let returned = directory.path().join("original-signature-return.wpe");
        // Install the uncertainty guard BEFORE any first-original effect. A failed
        // call is not a permit to allocate another original or signature attempt.
        self.payment = Some(RetainedPayment {
            authorization: input.terms.authorization_id.clone(),
            intent: intent.clone(),
            returned,
            phase: PaymentPhase::Submitting,
            references: None,
            _directory: directory,
        });
        let authorization =
            self.controller
                .ui
                .synthetic_retain_payment(input, &intent, self.controller.epoch)?;
        let retained = self.payment.as_mut().ok_or(Error::Uncertain)?;
        if retained.authorization != authorization {
            return Err(Error::ReviewMismatch);
        }
        retained.phase = PaymentPhase::Retained;
        self.check_source()?;
        Ok((authorization, intent))
    }
    pub(in crate::native_ui) fn submit_original_payment(&mut self) -> Result<()> {
        self.check_source()?;
        let p = self.payment.as_mut().ok_or(Error::Locked)?;
        if p.phase != PaymentPhase::Retained {
            return Err(Error::ReviewMismatch);
        }
        p.phase = PaymentPhase::Submitting;
        self.controller
            .ui
            .synthetic_submit_payment(&p.intent, self.controller.epoch)?;
        p.phase = PaymentPhase::Admitted;
        self.check_source()
    }
    pub(in crate::native_ui) fn sign_and_export_original_return(&mut self) -> Result<PathBuf> {
        self.check_source()?;
        let p = self.payment.as_mut().ok_or(Error::Locked)?;
        if p.phase != PaymentPhase::Admitted {
            return Err(Error::ReviewMismatch);
        }
        p.phase = PaymentPhase::Signing;
        let references = self.controller.ui.synthetic_sign_payment(
            &p.authorization,
            &p.returned,
            self.controller.epoch,
        )?;
        if references.authorization_id != p.authorization {
            return Err(Error::ReviewMismatch);
        }
        p.references = Some(references);
        p.phase = PaymentPhase::Returned;
        let path = p.returned.clone();
        self.check_source()?;
        Ok(path)
    }
    pub(in crate::native_ui) fn poll_original_host_history_or_dispatch(&mut self) -> Result<()> {
        if self
            .payment
            .as_ref()
            .is_none_or(|p| p.phase != PaymentPhase::Returned)
        {
            return Err(Error::ReviewMismatch);
        }
        let epoch = self.controller.epoch;
        self.controller.ui.poll_lifecycle(true, epoch);
        self.controller.ui.owner(epoch)?;
        if self.controller.ui.job.is_some() {
            return Ok(());
        }
        self.check_source()?;
        if let Some(review) = self.controller.ui.review.as_mut() {
            if !matches!(&review.step,Step::Named(step) if matches!(step.as_ref(),NamedStep::Bridge(prepared) if prepared.synthetic_for_authorization(&self.payment.as_ref().ok_or(Error::Locked)?.authorization)))
            {
                return Err(Error::ReviewMismatch);
            }
            if review
                .exact
                .continue_from_native_click(false, epoch)
                .is_ok()
                || review
                    .exact
                    .continue_from_native_click(true, epoch + 1)
                    .is_ok()
            {
                return Err(Error::ReviewMismatch);
            }
            review.displayed_to_end = true;
            review.exact.continue_from_native_click(true, epoch)?;
            self.controller.ui.confirmation =
                Zeroizing::new(format!("AUTHORIZE {}", &review.exact.digest()[..12]));
            // Nonblocking dispatch: real bridge channels remain held while the
            // same Host receives/merges, scans and later requests exact dispatch.
            self.controller.ui.approve(true, epoch)?;
        }
        Ok(())
    }
}

impl NamedContinuationFixtureV1 {
    pub(in crate::native_ui) fn original_return_references(
        &self,
    ) -> Result<crate::consent_journal::OriginalNamedReturnReferencesV1> {
        self.check_source()?;
        let actual = self
            .payment
            .as_ref()
            .filter(|p| p.phase == PaymentPhase::Returned)
            .ok_or(Error::Locked)?;
        actual.references.clone().ok_or(Error::Uncertain)
    }
}
