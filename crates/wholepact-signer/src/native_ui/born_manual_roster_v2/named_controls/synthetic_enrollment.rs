//! Finite original-owner enrollment work. Uses the actual retained owner and
//! unchanged production prepare/sign/export workers, with separate reviews.
use super::*;
use wholepact_authority::born_offline_enrollment_v1::BornOfflineEnrollmentV1;
impl BornManualRosterUiV2 {
    pub(in crate::native_ui) fn synthetic_begin_owner_enrollment(
        &mut self,
        source_identity: &str,
        source_policy: &str,
        epoch: u64,
    ) -> Result<BornOfflineEnrollmentV1> {
        if self.job.is_some()
            || self.review.is_some()
            || self.named_controls.active()
            || self.named_controls.bridge.held()
            || self.named_controls.verifier.engaged()
            || self.named_controls.signed.is_some()
        {
            return Err(Error::Locked);
        }
        let owner = self.owner(epoch)?;
        let actual = self.named_continuation.as_ref().ok_or(Error::Locked)?;
        let profile = self
            .named_controls
            .workspace
            .live_profile()
            .ok_or(Error::Locked)?;
        let proposal = profile.synthetic_born_enrollment_draft(
            actual.source(),
            &owner,
            actual.session()?,
            actual.client(),
            source_identity,
            source_policy,
        )?;
        let operation = crate::consent_journal::NamedRecipientOperation::new();
        self.named_controls.operation = Some(operation.clone());
        let actual = self.named_continuation.take().ok_or(Error::Locked)?;
        self.start(
            Work::Named(Box::new(NamedWork::PrepareOwnerEnrollment(
                actual,
                profile,
                proposal.clone(),
                operation,
            ))),
            epoch,
        )?;
        Ok(proposal)
    }
    pub(in crate::native_ui) fn synthetic_begin_owner_enrollment_export(
        &mut self,
        directory: &Path,
        epoch: u64,
    ) -> Result<PathBuf> {
        use sha2::{Digest, Sha256};
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
        let signed = self
            .named_controls
            .signed
            .as_ref()
            .ok_or(Error::Locked)?
            .clone();
        let digest = hex::encode(Sha256::digest(
            serde_json::to_vec_pretty(&signed).map_err(|_| Error::InvalidData)?,
        ));
        let path = directory.join(format!("born-offline-owner-enrollment-v1-{digest}.json"));
        let actual = self.named_continuation.take().ok_or(Error::Locked)?;
        self.start(
            Work::Named(Box::new(NamedWork::PrepareExport(
                actual,
                signed,
                directory.into(),
            ))),
            epoch,
        )?;
        Ok(path)
    }
    pub(in crate::native_ui) fn synthetic_installed_setup_metadata(
        &self,
        epoch: u64,
    ) -> Result<crate::consent_journal::OriginalNamedSetupMetadataV1> {
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
        let profile = self
            .named_controls
            .workspace
            .live_profile()
            .ok_or(Error::Locked)?;
        let signed = &self
            .named_controls
            .signed
            .as_ref()
            .ok_or(Error::Locked)?
            .enrollment;
        profile.synthetic_installed_born_metadata(
            actual.source(),
            &owner,
            actual.session()?,
            actual.client(),
            signed,
        )
    }
}
