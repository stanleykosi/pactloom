//! Actual post-publication Host owner, borrowed by the separately admitted V2
//! viewing import. Saved audit metadata cannot create this process-local owner.
use super::*;
use wholepact_core::manual_roster_inventory_v2::{
    ManualRosterInventoryScopeV2, OriginalHostRosterAuditV3,
};

pub(super) struct CommittedRosterAudit<'host> {
    pub(super) original: PreparedManualEnrollment<'host>,
    pub(super) request: HostManualRosterPublicationRequestV2,
    pub(super) extension: ManualRosterEnrollmentExtensionV2,
    pub(super) original_audit_digest: String,
    pub(super) original_signer_intent_digest: String,
    pub(super) review_digest: String,
    pub(super) deadline: std::time::Instant,
}
impl CommittedRosterAudit<'_> {
    pub(super) fn check_current(&self) -> Result<()> {
        if std::time::Instant::now() >= self.deadline {
            return Err(Error::Permission);
        }
        self.original.source.check_current()?;
        self.original.approval.check()?;
        let source = &self.original.source;
        let current = source
            .host
            .engine
            .manual_roster_request_original(
                source.host.access()?,
                &source.engine,
                &self.request,
                &self.extension.account_extension.enrollment_ref,
                &self
                    .extension
                    .account_extension
                    .digest()
                    .map_err(|_| Error::Invalid)?,
                &self.extension.digest().map_err(|_| Error::Invalid)?,
                &self.extension.signer_roster_record_digest,
            )?
            .ok_or(Error::Authentication)?;
        if current.digest()? != self.original_audit_digest
            || self.original_signer_intent_digest != current.evidence.admission.signer_intent_digest
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
}
pub(in crate::host) struct CommittedRosterImportTarget<'audit, 'host> {
    audit: &'audit CommittedRosterAudit<'host>,
    scope_digest: String,
}
impl<'host> CommittedRosterAudit<'host> {
    pub(super) fn borrow_import_target<'audit>(
        &'audit self,
        host: &Host,
        scope: &ManualRosterInventoryScopeV2,
    ) -> Result<CommittedRosterImportTarget<'audit, 'host>> {
        let target = CommittedRosterImportTarget {
            audit: self,
            scope_digest: scope.pairing_digest().map_err(|_| Error::Invalid)?,
        };
        target.require_current(host, scope)?;
        Ok(target)
    }
}
impl CommittedRosterImportTarget<'_, '_> {
    pub(in crate::host) fn require_current(
        &self,
        host: &Host,
        scope: &ManualRosterInventoryScopeV2,
    ) -> Result<()> {
        self.audit.check_current()?;
        scope.validate().map_err(|_| Error::Invalid)?;
        let a = self.audit;
        let s = &scope.inventory;
        let p = &scope.provenance;
        let ManualRosterPublicationAttemptV2::ContinuationV2 {
            continuation_digest,
            attempt_sequence,
        } = &a.request.attempt
        else {
            return Err(Error::Permission);
        };
        if !std::ptr::eq(host, a.original.source.host)
            || self.scope_digest != scope.pairing_digest().map_err(|_| Error::Invalid)?
            || s.enrollment != a.request.enrollment.terms
            || s.enrollment != *a.original.source.engine.terms()
            || s.enrollment_ref != a.extension.account_extension.enrollment_ref
            || s.witness_extension_digest
                != a.extension
                    .account_extension
                    .digest()
                    .map_err(|_| Error::Invalid)?
            || s.attempt.continuation_digest != *continuation_digest
            || s.attempt.attempt_sequence != *attempt_sequence
            || p.original_host_audit
                != (OriginalHostRosterAuditV3::AdditionalPublicationV3 {
                    audit_digest: a.original_audit_digest.clone(),
                })
            || p.roster != a.extension.roster
            || p.signer_roster_record_digest != a.extension.signer_roster_record_digest
            || p.witness_roster_extension_digest
                != a.extension.digest().map_err(|_| Error::Invalid)?
        {
            return Err(Error::Authentication);
        }
        self.audit.check_current()
    }
}
