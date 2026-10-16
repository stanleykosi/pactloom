//! Held, read-only original enrollment and accepted-manifest authority. No
//! authorization result is required and no record can be manufactured by IPC.
use super::*;
use std::sync::RwLockReadGuard;

pub(crate) struct PreconstructionRecordLease<'a> {
    journal: SignerJournalBinding,
    permission: authority::ReadLease<'a>,
    _fence: RwLockReadGuard<'a, ()>,
    enrollment: AccountEnrollmentRecord,
    manifest: AcceptedManifestRecord,
    sponsor_policy: Option<NativeSponsorPolicyRecord>,
    sponsor_required: bool,
}
impl SignerConsentJournal {
    pub(crate) fn acquire_preconstruction_records<'a>(
        &'a self,
        enrollment_ref: &str,
        manifest_ref: &str,
        session: &'a SignerConsentSession,
    ) -> Result<PreconstructionRecordLease<'a>> {
        hash(enrollment_ref)?;
        hash(manifest_ref)?;
        let account = self.account_state()?;
        if account.recovery_required {
            return Err(JournalError::RecoveryRequired);
        }
        let permission = session.read_lease(&self.binding(), &account)?;
        let fence = self
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        let c = self.connection.lock().map_err(|_| JournalError::Database)?;
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
            sponsor_policy,
            sponsor_required,
            permission,
            _fence: fence,
            enrollment,
            manifest,
        };
        lease.check_current()?;
        Ok(lease)
    }
}
impl PreconstructionRecordLease<'_> {
    pub(crate) fn require_journal(&self, journal: &SignerJournalBinding) -> Result<()> {
        if &self.journal != journal {
            return Err(JournalError::Permission);
        }
        Ok(())
    }

    pub(crate) fn sponsor_required(&self) -> bool {
        self.sponsor_required
    }

    pub(crate) fn sponsor_policy(&self) -> Option<&NativeSponsorPolicyRecord> {
        self.sponsor_policy.as_ref()
    }

    pub(crate) fn enrollment(&self) -> &AccountEnrollmentRecord {
        &self.enrollment
    }
    pub(crate) fn manifest(&self) -> &AcceptedManifestRecord {
        &self.manifest
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        self.permission.check_current()?;
        if let Some(policy) = &self.sponsor_policy {
            policy.require_active()?;
        }
        Ok(())
    }
    #[cfg(all(feature = "native-ui", target_os = "linux"))]
    pub(crate) fn require_native_origin(
        &self,
        origin: &crate::native_ui::NativeAuthorityBinding,
    ) -> Result<()> {
        self.permission.require_native_origin(origin)
    }
}
