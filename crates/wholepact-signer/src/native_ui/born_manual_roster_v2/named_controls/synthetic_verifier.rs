//! Finite synthetic selection of the actual separate verifier lane. This never
//! changes the original Host grant or constructs a peer, decision or FVK lease.
use super::*;
use wholepact_signer_origin::named_verifier_policy::NamedVerifierPolicyScopeV1;

impl BornManualRosterUiV2 {
    pub(in crate::native_ui) fn synthetic_begin_verifier_lane(
        &mut self,
        scope: NamedVerifierPolicyScopeV1,
        epoch: u64,
    ) -> Result<()> {
        if self.job.is_some()
            || self.review.is_some()
            || self.named_controls.active()
            || self.named_controls.bridge.held()
            || self.named_controls.verifier.engaged()
        {
            return Err(Error::Locked);
        }
        let owner = self.owner(epoch)?;
        let actual = self.named_continuation.as_ref().ok_or(Error::Locked)?;
        actual.check(&owner)?;
        let profile = self
            .named_controls
            .workspace
            .live_profile()
            .ok_or(Error::Locked)?;
        profile.check_current(actual.source().journal(), actual.session()?)?;
        scope.validate().map_err(|_| Error::ReviewMismatch)?;
        self.named_controls.verifier.begin()?;
        let actual = self.named_continuation.take().ok_or(Error::Locked)?;
        self.start(
            Work::Named(Box::new(NamedWork::PrepareVerifier(
                actual,
                Box::new(super::super::named_verifier_disclosure::Input::Select(
                    profile, scope,
                )),
            ))),
            epoch,
        )
    }
    pub(in crate::native_ui) fn synthetic_verifier_endpoint(&self) -> Result<PathBuf> {
        self.named_controls
            .verifier
            .endpoint()
            .map(Path::to_path_buf)
            .ok_or(Error::Locked)
    }
    pub(in crate::native_ui) fn synthetic_verifier_engaged(&self) -> bool {
        self.named_controls.verifier.engaged()
    }
    pub(in crate::native_ui) fn synthetic_named_public_context(
        &self,
        epoch: u64,
    ) -> Result<(String, String, [u8; 32])> {
        let owner = self.owner(epoch)?;
        let actual = self.named_continuation.as_ref().ok_or(Error::Locked)?;
        actual.check(&owner)?;
        let profile = self
            .named_controls
            .workspace
            .live_profile()
            .ok_or(Error::Locked)?;
        profile.check_current(actual.source().journal(), actual.session()?)?;
        let (enrollment, manifest) = actual.local_records()?;
        Ok((
            enrollment.reference().into(),
            manifest.reference().into(),
            *profile.transport_public_key(),
        ))
    }
}
