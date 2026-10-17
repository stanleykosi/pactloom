//! Same actual consumed native owner signs the original enrollment, then reviews
//! a separate immutable export. Main-thread witness installation remains separate.
use super::*;
impl NamedContinuationFixtureV1 {
    pub(in crate::native_ui) fn export_original_owner_enrollment(
        &mut self,
        source_identity: &str,
        source_policy: &str,
    ) -> Result<(
        PathBuf,
        wholepact_authority::born_offline_enrollment_v1::BornOfflineEnrollmentV1,
    )> {
        self.check_source()?;
        if !matches!(self.phase, Phase::Ready) {
            return Err(Error::ReviewMismatch);
        }
        let epoch = self.controller.epoch;
        let proposal = self.controller.ui.synthetic_begin_owner_enrollment(
            source_identity,
            source_policy,
            epoch,
        )?;
        drain(&mut self.controller.ui, epoch)?;
        if !matches!(self.controller.ui.review.as_ref().map(|r|&r.step),Some(Step::Named(s)) if matches!(s.as_ref(),NamedStep::OwnerEnrollment(_)))
        {
            return Err(Error::ReviewMismatch);
        }
        approve_current(&mut self.controller.ui, epoch)?;
        let directory = self.original.temporary.path().join(format!(
            "born-named-enrollment-{}",
            self.original.account_id
        ));
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new().mode(0o700).create(&directory)?;
        }
        let path = self
            .controller
            .ui
            .synthetic_begin_owner_enrollment_export(&directory, epoch)?;
        drain(&mut self.controller.ui, epoch)?;
        if !matches!(self.controller.ui.review.as_ref().map(|r|&r.step),Some(Step::Named(s)) if matches!(s.as_ref(),NamedStep::Export(_)))
        {
            return Err(Error::ReviewMismatch);
        }
        approve_current(&mut self.controller.ui, epoch)?;
        self.check_source()?;
        self.controller.ui.owner(epoch)?.check_current()?;
        let directory_owner = crate::files::PrivateDirectory::open(&directory)?;
        let bytes = directory_owner.read(
            path.file_name()
                .and_then(|s| s.to_str())
                .ok_or(Error::InvalidData)?,
            256 * 1024,
        )?;
        self.controller.ui.owner(epoch)?.check_current()?;
        let actual:wholepact_authority::born_offline_enrollment_signature_v1::BornOfflineEnrollmentOwnerSignatureV1=
            wholepact_core::parse_typed_json(&bytes).map_err(|_|Error::InvalidData)?;
        if actual.enrollment != proposal {
            return Err(Error::ReviewMismatch);
        }
        wholepact_authority::born_offline_enrollment_signature_v1::verify_born_offline_enrollment_v1_owner_signature(
            &actual,&self.original.credentials.origin().owner_certificate_digest).map_err(|_|Error::Authentication)?;
        Ok((path, proposal))
    }
    pub(in crate::native_ui) fn installed_original_setup_metadata(
        &self,
    ) -> Result<crate::consent_journal::OriginalNamedSetupMetadataV1> {
        self.check_source()?;
        self.controller
            .ui
            .synthetic_installed_setup_metadata(self.controller.epoch)
    }
}
