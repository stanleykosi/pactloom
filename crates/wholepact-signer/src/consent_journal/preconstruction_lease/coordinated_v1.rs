//! Exact coordinated Read/export acquisition of the maintained record lease.
use super::*;
use wholepact_financial_coordinator_origin::{
    SignerV3PrepareReadFinalV1, SignerV3RediscloseFinalV1, SignerV3RedisclosureReadFinalV1,
};
pub(crate) enum CoordinatedConstructionActionV1<'a> {
    Read(&'a SignerV3RedisclosureReadFinalV1),
    Prepare(&'a SignerV3PrepareReadFinalV1),
    Export(&'a SignerV3RediscloseFinalV1),
}
impl CoordinatedConstructionActionV1<'_> {
    pub(crate) fn check_current(&self) -> Result<()> {
        match self {
            Self::Read(v) => v.check_current(),
            Self::Prepare(v) => v.check_current(),
            Self::Export(v) => v.check_current(),
        }
        .map_err(|_| JournalError::Permission)
    }
}
impl SignerConsentJournal {
    pub(in crate::consent_journal) fn acquire_coordinated_preconstruction_records<'a>(
        &'a self,
        enrollment_ref: &str,
        manifest_ref: &str,
        session: &'a SignerConsentSession,
        action: &CoordinatedConstructionActionV1<'_>,
    ) -> Result<PreconstructionRecordLease<'a>> {
        hash(enrollment_ref)?;
        hash(manifest_ref)?;
        action.check_current()?;
        // Unlike the legacy helper, the nominal Read is sampled immediately
        // after every lock acquisition, before subsequent private SQL reads.
        let account = {
            let c = self.connection.lock().map_err(|_| JournalError::Database)?;
            action.check_current()?;
            self.database_identity.check_current(&c)?;
            storage::read_account(&c)?
        };
        if account.recovery_required {
            return Err(JournalError::RecoveryRequired);
        }
        let permission = session.read_lease(&self.binding(), &account)?;
        action.check_current()?;
        let fence = self
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        action.check_current()?;
        let c = self.connection.lock().map_err(|_| JournalError::Database)?;
        action.check_current()?;
        self.database_identity.check_current(&c)?;
        storage::check_account(&c, &account)?;
        let enrollment =
            storage::read_enrollment(&c, enrollment_ref)?.ok_or(JournalError::NotFound)?;
        let manifest = storage::read_manifest(&c, manifest_ref)?.ok_or(JournalError::NotFound)?;
        if enrollment.principal_id() != permission.principal
            || manifest.terms.principal_id != permission.principal
            || enrollment.account_id() != account.account_id
            || manifest.terms.account_id != account.account_id
            || manifest.enrollment_ref() != enrollment.reference()
        {
            return Err(JournalError::InvalidBinding);
        }
        let sponsor_policy = sponsor::current_for_manifest(&c, manifest_ref)?;
        let sponsor_required = sponsor::policy_required(&c, &manifest)?;
        let lease = PreconstructionRecordLease {
            journal: self.binding(),
            permission,
            _fence: fence,
            enrollment,
            manifest,
            sponsor_policy,
            sponsor_required,
        };
        lease.require_current_durable_disclosure_receipts_v1()?;
        action.check_current()?;
        Ok(lease)
    }
}
