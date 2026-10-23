//! Purpose-distinct coordinated acquisition; accepted provenance is never permission.
use super::*;
use wholepact_financial_coordinator_origin::{
    SignerV3AdmitFinalV1, SignerV3AdmitReadFinalV1, SignerV3PrepareReadFinalV1,
    SignerV3RediscloseFinalV1, SignerV3RedisclosureReadFinalV1,
};
use crate::account::birth::enrollment::roster_v2::durable_entry_v1::CoordinatedPreparedPurposeBindingV1;
use crate::consent_journal::durable_delivery_admission_intent_v3::coordinated_v1::CoordinatedAdmissionPurposeBindingV1;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CoordinatedPurposeKind { Read, Prepare, AdmitRead, Admit, Export }

// Pure additional restriction only: this returns no lease, action or guard.
// Runtime callers derive the boolean solely from actual Final pointer equality
// and still execute all nominal currentness/provenance checks afterward.
fn require_purpose_identity(held: CoordinatedPurposeKind, requested: CoordinatedPurposeKind, same_final_pointer: bool) -> Result<()> {
    if held != requested || !same_final_pointer { return Err(JournalError::Permission); }
    Ok(())
}

pub(crate) enum CoordinatedConstructionActionV1<'a> {
    Read(&'a SignerV3RedisclosureReadFinalV1),
    Prepare(&'a SignerV3PrepareReadFinalV1),
    AdmitRead(&'a SignerV3AdmitReadFinalV1, CoordinatedPreparedPurposeBindingV1),
    Admit(&'a SignerV3AdmitFinalV1, CoordinatedAdmissionPurposeBindingV1),
    Export(&'a SignerV3RediscloseFinalV1),
}
impl CoordinatedConstructionActionV1<'_> {
    fn kind(&self) -> CoordinatedPurposeKind {
        match self {
            Self::Read(_) => CoordinatedPurposeKind::Read,
            Self::Prepare(_) => CoordinatedPurposeKind::Prepare,
            Self::AdmitRead(_, _) => CoordinatedPurposeKind::AdmitRead,
            Self::Admit(_, _) => CoordinatedPurposeKind::Admit,
            Self::Export(_) => CoordinatedPurposeKind::Export,
        }
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        match self {
            Self::Read(v) => v.check_current(),
            Self::Prepare(v) => v.check_current(),
            Self::AdmitRead(v, _) => v.check_current(),
            Self::Admit(v, _) => v.check_current(),
            Self::Export(v) => v.check_current(),
        }
        .map_err(|_| JournalError::Permission)
    }
}
impl CoordinatedConstructionActionV1<'_> {
    fn require_provenance(&self, accepted: &CoordinatedAcceptedProvenanceV1) -> Result<()> {
        macro_rules! bind {
            ($facts:expr) => {{
                let f = $facts;
                accepted.require_pair_facts(&f.source_identity_digest, &f.pair_grant_id,
                    &f.pair_key_digest, &f.pair_channel_digest, f.pair_generation,
                    &f.coordinated_session_id, &f.current_enrollment_ref, &f.current_manifest_ref)
            }};
        }
        match self {
            Self::Read(v) => bind!(v.facts()),
            Self::Prepare(v) => bind!(v.facts()),
            Self::Export(v) => bind!(v.facts()),
            Self::AdmitRead(v, chain) => {
                chain.require_admit_read(v).map_err(|_| JournalError::Permission)?;
                bind!(&chain.prepare_read().facts)
            }
            Self::Admit(v, chain) => {
                chain.require_admit(v)?;
                bind!(&chain.prepare_read().facts)
            }
        }
    }
}

/// A held specific genuine Final and accepted identity, never a replacement
/// generic receipt. The storage carrier is private and cannot be extracted.
/// No Deref/Clone/serialization or public constructor is provided.
pub(crate) struct CoordinatedPurposeRecordLease<'a> {
    base: PreconstructionRecordLease<'a>,
    accepted: &'a CoordinatedAcceptedProvenanceV1,
    action: CoordinatedConstructionActionV1<'a>,
}
impl CoordinatedPurposeRecordLease<'_> {
    pub(crate) fn check_current(&self) -> Result<()> {
        self.action.check_current()?;
        self.base.check_current()?;
        self.accepted.require_lease(&self.base.permission, &self.base.enrollment, &self.base.manifest)?;
        self.action.require_provenance(self.accepted)?;
        self.action.check_current()
    }
    pub(crate) fn require_journal(&self, journal: &SignerJournalBinding) -> Result<()> {
        self.base.require_journal(journal)
    }
    pub(crate) fn enrollment(&self) -> &AccountEnrollmentRecord { self.base.enrollment() }
    pub(crate) fn manifest(&self) -> &AcceptedManifestRecord { self.base.manifest() }
    pub(crate) fn sponsor_required(&self) -> bool { self.base.sponsor_required() }
    pub(crate) fn sponsor_policy(&self) -> Option<&NativeSponsorPolicyRecord> { self.base.sponsor_policy() }
    pub(crate) fn require_read(&self, action: &SignerV3RedisclosureReadFinalV1) -> Result<()> {
        require_purpose_identity(self.action.kind(), CoordinatedPurposeKind::Read,
            matches!(&self.action, CoordinatedConstructionActionV1::Read(held) if std::ptr::eq(*held, action)))?;
        self.check_current()
    }
    pub(crate) fn require_prepare(&self, action: &SignerV3PrepareReadFinalV1) -> Result<()> {
        require_purpose_identity(self.action.kind(), CoordinatedPurposeKind::Prepare,
            matches!(&self.action, CoordinatedConstructionActionV1::Prepare(held) if std::ptr::eq(*held, action)))?;
        self.check_current()
    }
    pub(crate) fn require_export(&self, action: &SignerV3RediscloseFinalV1) -> Result<()> {
        require_purpose_identity(self.action.kind(), CoordinatedPurposeKind::Export,
            matches!(&self.action, CoordinatedConstructionActionV1::Export(held) if std::ptr::eq(*held, action)))?;
        self.check_current()
    }
    pub(crate) fn require_admit_read(&self, action: &SignerV3AdmitReadFinalV1) -> Result<()> {
        require_purpose_identity(self.action.kind(), CoordinatedPurposeKind::AdmitRead,
            matches!(&self.action, CoordinatedConstructionActionV1::AdmitRead(held, _) if std::ptr::eq(*held, action)))?;
        self.check_current()
    }
    pub(crate) fn require_admit(&self, action: &SignerV3AdmitFinalV1) -> Result<()> {
        require_purpose_identity(self.action.kind(), CoordinatedPurposeKind::Admit,
            matches!(&self.action, CoordinatedConstructionActionV1::Admit(held, _) if std::ptr::eq(*held, action)))?;
        self.check_current()
    }
}

impl SignerConsentJournal {
    pub(in crate::consent_journal) fn acquire_coordinated_preconstruction_records<'a>(
        &'a self,
        enrollment_ref: &str,
        manifest_ref: &str,
        session: &'a SignerConsentSession,
        accepted: &'a CoordinatedAcceptedProvenanceV1,
        action: CoordinatedConstructionActionV1<'a>,
    ) -> Result<CoordinatedPurposeRecordLease<'a>> {
        hash(enrollment_ref)?;
        hash(manifest_ref)?;
        action.check_current()?;
        accepted.require_record_references(enrollment_ref, manifest_ref)?;
        action.require_provenance(accepted)?;
        accepted.require_session_metadata(session)?;
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
        accepted.require_held_session(&permission)?;
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
        let lease = CoordinatedPurposeRecordLease { base: lease, accepted, action };
        lease.check_current()?;
        lease.action.check_current()?;
        Ok(lease)
    }
}

#[cfg(test)]
#[path = "coordinated_v1/handoff_security_tests.rs"]
mod handoff_security_tests;
