//! Roster V2 entry points retain their actual V2 history and operation domain.
//! They share private credential/session mechanics, never V1 owner evidence.
use super::*;
use wholepact_authority::{
    manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2,
    manual_roster_witness_v2::ManualRosterSessionContinuationV2,
};
impl PreparedWriterSession {
    pub(in crate::native_ui) fn prepare_born_roster_v2(
        workspace: &NativeWitnessWorkspace,
        extension: &ManualRosterEnrollmentExtensionV2,
    ) -> Result<Self> {
        let prepared = Self::prepare_operation(
            workspace,
            Some(
                extension
                    .acquire_operation_id()
                    .map_err(|_| Error::InvalidData)?,
            ),
        )?;
        require_initial(&prepared, extension)?;
        Ok(prepared)
    }
    pub(in crate::native_ui) fn prepare_born_roster_continued_v2(
        workspace: &NativeWitnessWorkspace,
        extension: &ManualRosterEnrollmentExtensionV2,
        continuation: &ManualRosterSessionContinuationV2,
    ) -> Result<Self> {
        let prepared = Self::prepare_operation(
            workspace,
            Some(
                continuation
                    .acquire_operation_id(extension)
                    .map_err(|_| Error::InvalidData)?,
            ),
        )?;
        require_continued(&prepared, extension, continuation)?;
        Ok(prepared)
    }
}
fn require_initial(
    prepared: &PreparedWriterSession,
    e: &ManualRosterEnrollmentExtensionV2,
) -> Result<()> {
    e.validate().map_err(|_| Error::InvalidData)?;
    let history = &prepared.history;
    let t = &e.account_extension.terms;
    let attempt = history
        .latest_manual_roster_attempt_v2(&e.account_extension.enrollment_ref)
        .map_err(|_| Error::RecoveryRequired)?;
    if history
        .manual_roster_enrollment_extension(&e.account_extension.enrollment_ref)
        .map_err(|_| Error::Authentication)?
        != Some(e)
        || prepared.operation_id != e.acquire_operation_id().map_err(|_| Error::InvalidData)?
        || prepared.client_certificate_digest != t.signer.writer_certificate_digest
        || history.snapshot().writer_epoch != t.signer.writer_epoch
        || history.snapshot().head.sequence != 1
        || attempt.continuation.is_some()
        || attempt.admission.is_some()
        || history.snapshot().pending_writer_session.is_some()
        || history.snapshot().active_writer_session.is_some()
        || history.contains_operation(&e.acquire_operation_id().map_err(|_| Error::InvalidData)?)
        || history.contains_operation(&e.admission_operation_id().map_err(|_| Error::InvalidData)?)
    {
        return Err(Error::RecoveryRequired);
    }
    Ok(())
}
fn require_continued(
    prepared: &PreparedWriterSession,
    e: &ManualRosterEnrollmentExtensionV2,
    c: &ManualRosterSessionContinuationV2,
) -> Result<()> {
    c.validate_for(e).map_err(|_| Error::InvalidData)?;
    let history = &prepared.history;
    let t = &e.account_extension.terms;
    let attempt = history
        .latest_manual_roster_attempt_v2(&e.account_extension.enrollment_ref)
        .map_err(|_| Error::RecoveryRequired)?;
    if history
        .manual_roster_enrollment_extension(&e.account_extension.enrollment_ref)
        .map_err(|_| Error::Authentication)?
        != Some(e)
        || prepared.operation_id != c.acquire_operation_id(e).map_err(|_| Error::InvalidData)?
        || prepared.client_certificate_digest != t.signer.writer_certificate_digest
        || attempt.snapshot.writer_epoch != t.signer.writer_epoch
        || attempt.continuation.as_ref() != Some(c)
        || attempt.admission.is_some()
        || attempt.snapshot.pending_writer_session.is_some()
        || attempt.snapshot.active_writer_session.is_some()
        || history.contains_operation(&c.acquire_operation_id(e).map_err(|_| Error::InvalidData)?)
        || history.contains_operation(
            &c.admission_operation_id(e)
                .map_err(|_| Error::InvalidData)?,
        )
    {
        return Err(Error::RecoveryRequired);
    }
    Ok(())
}
impl ApprovedWriterSession {
    pub(crate) fn born_roster_attempt_review_v2(
        &self,
        e: &ManualRosterEnrollmentExtensionV2,
        source: &NativeAuthorityBinding,
    ) -> Result<String> {
        self.0.source.check_current()?;
        if &self.0.source != source || self.1.elapsed() >= std::time::Duration::from_secs(120) {
            return Err(Error::RecoveryRequired);
        }
        require_initial(&self.0, e)?;
        Ok(self.0.digest.clone())
    }
    pub(crate) fn born_roster_continued_attempt_review_v2(
        &self,
        e: &ManualRosterEnrollmentExtensionV2,
        c: &ManualRosterSessionContinuationV2,
        source: &NativeAuthorityBinding,
    ) -> Result<String> {
        self.0.source.check_current()?;
        if &self.0.source != source || self.1.elapsed() >= std::time::Duration::from_secs(120) {
            return Err(Error::RecoveryRequired);
        }
        require_continued(&self.0, e, c)?;
        Ok(self.0.digest.clone())
    }
}
impl NativeWitnessWorkspace {
    pub(in crate::native_ui) fn from_born_manual_roster_v2(
        approved: crate::native_ui::born_manual_roster_v2::witness::ApprovedManualWitnessSetup,
    ) -> (Self, Self) {
        let (source, account_id, writer, owner, writer_pin, owner_pin) = approved.into_parts();
        (
            Self {
                instance: std::sync::Arc::new(()),
                source: source.clone(),
                account_id: account_id.clone(),
                client: writer,
                writer_certificate_digest: writer_pin,
            },
            Self {
                instance: std::sync::Arc::new(()),
                source,
                account_id,
                client: owner,
                writer_certificate_digest: owner_pin,
            },
        )
    }
}

impl NativeWitnessWorkspace {
    pub(in crate::native_ui) fn check_native_source(
        &self,
        expected: &NativeAuthorityBinding,
    ) -> Result<()> {
        self.check_current()?;
        if &self.source != expected {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
}
