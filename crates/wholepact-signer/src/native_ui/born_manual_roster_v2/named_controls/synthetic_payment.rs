//! Concrete consumed-owner joins, never a caller-origin or raw owner factory.
use super::*;
impl BornManualRosterUiV2 {
    fn synthetic_payment_idle(&self) -> Result<()> {
        if self.job.is_some()
            || self.review.is_some()
            || self.named_controls.active()
            || self.named_controls.bridge.held()
            || self.named_controls.verifier.engaged()
        {
            return Err(Error::Locked);
        }
        Ok(())
    }
    pub(in crate::native_ui) fn synthetic_retain_payment(
        &mut self,
        input: crate::consent_journal::OriginalNamedPaymentArtifactsV1,
        path: &Path,
        epoch: u64,
    ) -> Result<String> {
        self.synthetic_payment_idle()?;
        let owner = self.owner(epoch)?;
        let actual = self.named_continuation.as_ref().ok_or(Error::Locked)?;
        actual.check(&owner)?;
        let context = actual.context(&owner)?;
        let own = context.born_own_policy(&input.own_context)?;
        let profile = self
            .named_controls
            .workspace
            .live_profile()
            .ok_or(Error::Locked)?;
        let inputs = profile.synthetic_assemble_born_original(
            actual.source(),
            &owner,
            actual.session()?,
            actual.client(),
            own,
            input,
        )?;
        let result = self
            .named_controls
            .workspace
            .synthetic_retain_born_payment(&context, actual.witness(), inputs, path, epoch)?;
        actual.check(&owner)?;
        Ok(result)
    }
    pub(in crate::native_ui) fn synthetic_submit_payment(
        &mut self,
        path: &Path,
        epoch: u64,
    ) -> Result<()> {
        self.synthetic_payment_idle()?;
        let owner = self.owner(epoch)?;
        let actual = self.named_continuation.as_ref().ok_or(Error::Locked)?;
        actual.check(&owner)?;
        self.named_controls
            .workspace
            .synthetic_submit_born_payment(
                &actual.context(&owner)?,
                actual.witness(),
                path,
                epoch,
            )?;
        actual.check(&owner)
    }
    pub(in crate::native_ui) fn synthetic_sign_payment(
        &mut self,
        authorization: &str,
        path: &Path,
        epoch: u64,
    ) -> Result<crate::consent_journal::OriginalNamedReturnReferencesV1> {
        self.synthetic_payment_idle()?;
        let owner = self.owner(epoch)?;
        let actual = self.named_continuation.as_ref().ok_or(Error::Locked)?;
        actual.check(&owner)?;
        let references = self.named_controls.workspace.synthetic_sign_born_payment(
            &actual.context(&owner)?,
            actual.witness(),
            authorization,
            path,
            epoch,
        )?;
        actual.check(&owner)?;
        Ok(references)
    }
}
