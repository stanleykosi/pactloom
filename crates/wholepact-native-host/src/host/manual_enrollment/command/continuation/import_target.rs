//! A short borrow of the actual post-append native owner. This does not create
//! another approval, renew a deadline, or reconstruct an audit from saved rows.
use super::*;
use wholepact_core::manual_inventory::ManualPreliminaryInventoryScope;

pub(in crate::host) struct CommittedImportTarget<'audit, 'host> {
    audit: &'audit CommittedManualAudit<'host>,
    scope_digest: String,
}
impl<'host> CommittedManualAudit<'host> {
    pub(super) fn borrow_import_target<'audit>(
        &'audit self,
        host: &Host,
        scope: &ManualPreliminaryInventoryScope,
    ) -> Result<CommittedImportTarget<'audit, 'host>> {
        let target = CommittedImportTarget {
            audit: self,
            scope_digest: scope.pairing_digest().map_err(|_| Error::Invalid)?,
        };
        target.require_current(host, scope)?;
        Ok(target)
    }
}
impl CommittedImportTarget<'_, '_> {
    pub(in crate::host) fn require_current(
        &self,
        host: &Host,
        scope: &ManualPreliminaryInventoryScope,
    ) -> Result<()> {
        // check_current -> ContinuationOwners::check_after_append -> original
        // ManualEnrollmentOwners::check_current verifies the actual Engine/Store
        // generation, immutable committed target/capsule, history approval,
        // original primary file identities and every exact host-binding field.
        self.audit.check_current()?;
        if !std::ptr::eq(host, self.audit.source.host)
            || self.scope_digest != scope.pairing_digest().map_err(|_| Error::Invalid)?
            || scope.enrollment != self.audit.request.enrollment.terms
            || scope.enrollment != *self.audit.source.engine.terms()
            || scope.attempt.continuation_digest != self.audit.request.continuation_digest
            || scope.enrollment_ref != self.audit.source.enrollment_ref
            || scope.witness_extension_digest != self.audit.source.extension_digest
        {
            return Err(Error::Authentication);
        }
        self.audit.check_current()
    }
}
