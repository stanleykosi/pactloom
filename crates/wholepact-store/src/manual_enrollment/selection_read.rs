//! Actual Store/request-bound local snapshot. No financial authority is issued.
use super::*;
use crate::financial_preflight::RetainedInputExclusions;
use wholepact_core::manual_candidate_selection::ManualCandidateSelectionRequest;
use wholepact_signer_origin::ManualCandidateSelectionLease;

pub struct ManualCandidateLocalExclusions<'store> {
    store: &'store Store,
    target: ManualStoreTarget<'store>,
    expected_agreement: StoredRecord,
    request: ManualCandidateSelectionRequest,
    exclusions: RetainedInputExclusions,
}
impl ManualCandidateLocalExclusions<'_> {
    pub fn current_for(
        &self,
        store: &Store,
        request: &ManualCandidateSelectionRequest,
    ) -> Result<&RetainedInputExclusions> {
        if !std::ptr::eq(store, self.store) || request != &self.request {
            return Err(StoreError::RecoveryRequired);
        }
        let actual = read_local(self.store, &self.target, &self.expected_agreement, request)?;
        if actual != self.exclusions {
            return Err(StoreError::RevisionConflict);
        }
        Ok(&self.exclusions)
    }
}
impl Store {
    pub fn manual_candidate_local_exclusions<'store>(
        &'store self,
        target: &ManualStoreTarget<'_>,
        expected_agreement: &StoredRecord,
        lease: &ManualCandidateSelectionLease<'_>,
    ) -> Result<ManualCandidateLocalExclusions<'store>> {
        lease.check_current().map_err(denied)?;
        let request = lease.binding();
        let exclusions = read_local(self, target, expected_agreement, request)?;
        let target = self.manual_store_target()?;
        lease.check_current().map_err(denied)?;
        Ok(ManualCandidateLocalExclusions {
            store: self,
            target,
            expected_agreement: expected_agreement.clone(),
            request: request.clone(),
            exclusions,
        })
    }
}
fn read_local(
    store: &Store,
    target: &ManualStoreTarget<'_>,
    expected_agreement: &StoredRecord,
    request: &ManualCandidateSelectionRequest,
) -> Result<RetainedInputExclusions> {
    request
        .validate()
        .map_err(|_| StoreError::RecoveryRequired)?;
    let scope = &request.scope.inventory;
    let terms = &scope.enrollment;
    require_target(store, target, terms)?;
    let mut connection = store.connection.try_lock().map_err(|error| match error {
        std::sync::TryLockError::WouldBlock => StoreError::ResourceExhausted,
        std::sync::TryLockError::Poisoned(_) => StoreError::Poisoned,
    })?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    kernel::require_agreement_snapshot(&tx, expected_agreement, terms)?;
    let initial = read_audits::<ManualEnrollmentInitialPublicationV2>(&tx, INITIAL_PUBLICATION_V2)?;
    let additions =
        read_audits::<ManualEnrollmentAdditionalPublicationV3>(&tx, ADDITIONAL_PUBLICATION_V3)?;
    let (aliases, latest_sequence, latest_digest) = if additions
        .iter()
        .any(|(_, a)| a.evidence.enrollment_ref == scope.enrollment_ref)
    {
        let original = kernel::require_continuation_original_v3(
            store,
            &tx,
            terms,
            &scope.enrollment_ref,
            &scope.witness_extension_digest,
            &store_known_inherited(&tx)?,
        )?;
        let original_digest = original.digest()?;
        let mut latest = original.evidence.admission.clone();
        for (_, audit) in read_audits::<ManualEnrollmentContinuationAuditV4>(&tx, CONTINUATION_V4)?
        {
            if audit.original_audit.audit_digest() == original_digest
                && audit.evidence.admission.attempt_sequence > latest.attempt_sequence
            {
                latest = audit.evidence.admission;
            }
        }
        (
            original.aliases,
            latest.attempt_sequence,
            latest.attempt_digest,
        )
    } else if initial
        .iter()
        .any(|(_, a)| a.evidence.enrollment_ref == scope.enrollment_ref)
    {
        let original = kernel::require_continuation_original_v2(
            store,
            &tx,
            terms,
            &scope.enrollment_ref,
            &scope.witness_extension_digest,
            &store_known_inherited(&tx)?,
        )?;
        let original_digest = original.digest()?;
        let mut latest = original.evidence.admission.clone();
        for (_, audit) in read_audits::<ManualEnrollmentContinuationAuditV3>(&tx, CONTINUATION_V3)?
        {
            if audit.original_audit.audit_digest() == original_digest
                && audit.evidence.admission.attempt_sequence > latest.attempt_sequence
            {
                latest = audit.evidence.admission;
            }
        }
        (
            original.aliases,
            latest.attempt_sequence,
            latest.attempt_digest,
        )
    } else {
        let original = kernel::require_continuation_original(
            store,
            &tx,
            terms,
            &scope.enrollment_ref,
            &scope.witness_extension_digest,
        )?;
        let original_digest = original.digest()?;
        let mut latest = None;
        for (_, audit) in read_audits::<ManualEnrollmentContinuationAudit>(&tx, CONTINUATION)? {
            if audit.enrollment_audit_digest == original_digest
                && latest
                    .as_ref()
                    .is_none_or(|old: &ManualContinuationAdmissionV2| {
                        audit.evidence.admission.attempt_sequence > old.attempt_sequence
                    })
            {
                latest = Some(audit.evidence.admission);
            }
        }
        let latest = latest.ok_or(StoreError::RecoveryRequired)?;
        (
            original.aliases,
            latest.attempt_sequence,
            latest.attempt_digest,
        )
    };
    if latest_sequence != scope.attempt.attempt_sequence
        || latest_digest != scope.attempt.continuation_digest
    {
        return Err(StoreError::RecoveryRequired);
    }
    let result = crate::financial_preflight::read_retained_input_exclusions(
        &tx,
        &terms.identity.account_id,
        &aliases,
    )?;

    Ok(result)
}

#[cfg(test)]
#[path = "selection_read_tests.rs"]
mod tests;
