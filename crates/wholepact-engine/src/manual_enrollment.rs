//! Trusted local read-only target projection. No raw Store reference, writable
//! connection, recovered financial exception or request-to-authority factory.
use super::*;
use wholepact_core::manual_enrollment::BornManualEnrollmentTerms;
use wholepact_store::manual_enrollment::ManualStoreTarget;

/// Actual Engine/Store borrow plus exact stored agreement revision. This is
/// correlation only; Host must additionally hold genuine native/profile owners,
/// complete capsule coverage and the concrete installed-signer/witness lease.
/// No Clone, Deserialize or caller-controlled constructor.
pub struct ManualEnrollmentTarget<'engine> {
    engine: &'engine Engine,
    store: ManualStoreTarget<'engine>,
    terms: BornManualEnrollmentTerms,
    owner_client_id: String,
    agreement_revision: u64,
    agreement_record_digest: String,
    agreement_record: wholepact_store::StoredRecord,
}
impl Engine {
    pub fn manual_enrollment_target<'engine>(
        &'engine self,
        access: &Access,
        terms: &BornManualEnrollmentTerms,
    ) -> Result<ManualEnrollmentTarget<'engine>> {
        terms.validate()?;
        let store = self.store.manual_store_target().map_err(store_error)?;
        if access.principal_id != terms.scope.principal_id
            || store.generation_id() != terms.host.generation_id
            || store.inventory_digest() != terms.host.inventory_digest
            || store.store_destination_identity() != terms.host.store_destination_identity
        {
            return Err(manual_denied());
        }
        let record = store
            .current_agreement_record(&terms.scope.agreement_id)
            .map_err(store_error)?;
        let envelope = decode(&record)?;
        // Use the selected-scope worker's exact predicate. Do not hand-roll the
        // old principal==owner fallback or silently widen selected-only access.
        if !access.permits_agreement(&record.id, &envelope.owner_client_id)
            || record.id != terms.scope.agreement_id
            || envelope.view.agreement.agreement_id != terms.scope.agreement_id
            || envelope.view.agreement.obligation_id != terms.scope.obligation_id
            || envelope.view.agreement.network_profile_id != terms.identity.network_profile_id
            || envelope.view.revision != record.revision
        {
            return Err(manual_denied());
        }
        let agreement_record_digest = wholepact_store::request_digest(&serde_json::json!([
            &record.id,
            record.revision,
            &record.payload,
        ]))
        .map_err(store_error)?;
        store.check_current().map_err(store_error)?;
        Ok(ManualEnrollmentTarget {
            engine: self,
            store,
            terms: terms.clone(),
            owner_client_id: envelope.owner_client_id,
            agreement_revision: record.revision,
            agreement_record_digest,
            agreement_record: record,
        })
    }
    pub fn manual_enrollment_target_fail_fast<'engine>(
        &'engine self,
        access: &Access,
        terms: &BornManualEnrollmentTerms,
    ) -> Result<ManualEnrollmentTarget<'engine>> {
        terms.validate()?;
        let store = self
            .store
            .manual_store_target_fail_fast()
            .map_err(store_error)?;
        if access.principal_id != terms.scope.principal_id
            || store.generation_id() != terms.host.generation_id
            || store.inventory_digest() != terms.host.inventory_digest
            || store.store_destination_identity() != terms.host.store_destination_identity
        {
            return Err(manual_denied());
        }
        let record = store
            .current_agreement_record_fail_fast(&terms.scope.agreement_id)
            .map_err(store_error)?;
        let envelope = decode(&record)?;
        // Use the selected-scope worker's exact predicate. Do not hand-roll the
        // old principal==owner fallback or silently widen selected-only access.
        if !access.permits_agreement(&record.id, &envelope.owner_client_id)
            || record.id != terms.scope.agreement_id
            || envelope.view.agreement.agreement_id != terms.scope.agreement_id
            || envelope.view.agreement.obligation_id != terms.scope.obligation_id
            || envelope.view.agreement.network_profile_id != terms.identity.network_profile_id
            || envelope.view.revision != record.revision
        {
            return Err(manual_denied());
        }
        let agreement_record_digest = wholepact_store::request_digest(&serde_json::json!([
            &record.id,
            record.revision,
            &record.payload,
        ]))
        .map_err(store_error)?;
        store.check_current_fail_fast().map_err(store_error)?;
        Ok(ManualEnrollmentTarget {
            engine: self,
            store,
            terms: terms.clone(),
            owner_client_id: envelope.owner_client_id,
            agreement_revision: record.revision,
            agreement_record_digest,
            agreement_record: record,
        })
    }
}
impl ManualEnrollmentTarget<'_> {
    pub fn generation_id(&self) -> &str {
        self.store.generation_id()
    }
    pub fn inventory_digest(&self) -> &str {
        self.store.inventory_digest()
    }
    pub fn store_destination_identity(&self) -> &str {
        self.store.store_destination_identity()
    }
    pub fn owner_client_id(&self) -> &str {
        &self.owner_client_id
    }
    pub fn agreement_revision(&self) -> u64 {
        self.agreement_revision
    }
    pub fn agreement_record_digest(&self) -> &str {
        &self.agreement_record_digest
    }
    pub fn terms(&self) -> &BornManualEnrollmentTerms {
        &self.terms
    }
    /// Require the complete current authenticated agreement draft, rather than
    /// treating its identity or record revision as an economic-content check.
    /// This read-only equality test creates no candidate or financial authority.
    pub fn require_current_agreement(
        &self,
        access: &Access,
        expected: &AgreementDraft,
    ) -> Result<()> {
        expected.validate()?;
        self.check_current(access)?;
        let actual = decode(&self.agreement_record)?;
        if &actual.view.agreement != expected {
            return Err(manual_denied());
        }
        self.store.check_current().map_err(store_error)
    }

    pub fn require_current_agreement_fail_fast(
        &self,
        access: &Access,
        expected: &AgreementDraft,
    ) -> Result<()> {
        expected.validate()?;
        self.check_current_fail_fast(access)?;
        let actual = decode(&self.agreement_record)?;
        if &actual.view.agreement != expected {
            return Err(manual_denied());
        }
        self.store.check_current_fail_fast().map_err(store_error)
    }

    pub fn check_current(&self, access: &Access) -> Result<()> {
        let actual = self.engine.manual_enrollment_target(access, &self.terms)?;
        if actual.owner_client_id != self.owner_client_id
            || actual.agreement_revision != self.agreement_revision
            || actual.agreement_record_digest != self.agreement_record_digest
        {
            return Err(manual_denied());
        }
        self.store.check_current().map_err(store_error)
    }
    pub fn check_current_fail_fast(&self, access: &Access) -> Result<()> {
        let actual = self
            .engine
            .manual_enrollment_target_fail_fast(access, &self.terms)?;
        if actual.owner_client_id != self.owner_client_id
            || actual.agreement_revision != self.agreement_revision
            || actual.agreement_record_digest != self.agreement_record_digest
        {
            return Err(manual_denied());
        }
        self.store.check_current_fail_fast().map_err(store_error)
    }
}
fn manual_denied() -> ApiError {
    ApiError::new(
        "RECOVERY_REQUIRED",
        "Exact current manual enrollment target/scope is unavailable; saved records grant no authority",
    )
}

impl Engine {
    /// Audit retention only. The Host owner must compose genuine local native,
    /// full capsule, exact profile/financial owners and installed-signer lease.
    /// No Store pointer or generic mutation API escapes through this wrapper.
    #[cfg(all(feature = "manual-admission", target_os = "linux"))]
    pub fn append_manual_enrollment_audit(
        &self,
        access: &Access,
        target: &ManualEnrollmentTarget<'_>,
        idempotency_key: &str,
        lease: wholepact_signer_origin::ManualEnrollmentLease<'_>,
    ) -> Result<wholepact_store::manual_enrollment::ManualAuditAppendReceipt> {
        if !std::ptr::eq(self, target.engine) || lease.binding().terms != target.terms {
            return Err(manual_denied());
        }
        target.check_current(access)?;
        let context = wholepact_store::CommandContext::for_request(
            &access.principal_id,
            idempotency_key,
            &serde_json::to_value(lease.binding()).map_err(|_| manual_denied())?,
        )
        .map_err(store_error)?;
        self.store
            .append_manual_enrollment_audit(
                &target.store,
                &context,
                &target.agreement_record,
                lease,
            )
            .map_err(store_error)
    }
}

/// Read-only initial target before the signer derives its private terms. This
/// projects one actual selected current agreement, never a caller's host DTO.
pub struct ManualEnrollmentIntentTarget<'engine> {
    engine: &'engine Engine,
    store: ManualStoreTarget<'engine>,
    principal_id: String,
    owner_client_id: String,
    agreement: wholepact_core::AgreementDraft,
    record: wholepact_store::StoredRecord,
}
impl Engine {
    pub fn manual_enrollment_intent_target<'engine>(
        &'engine self,
        access: &Access,
        agreement_id: &str,
    ) -> Result<ManualEnrollmentIntentTarget<'engine>> {
        let store = self.store.manual_store_target().map_err(store_error)?;
        let record = store
            .current_agreement_record(agreement_id)
            .map_err(store_error)?;
        let envelope = decode(&record)?;
        if !access.permits_agreement(&record.id, &envelope.owner_client_id)
            || record.id != agreement_id
            || envelope.view.agreement.agreement_id != agreement_id
            || envelope.view.revision != record.revision
        {
            return Err(manual_denied());
        }
        envelope.view.agreement.validate()?;
        store.check_current().map_err(store_error)?;
        Ok(ManualEnrollmentIntentTarget {
            engine: self,
            store,
            principal_id: access.principal_id.clone(),
            owner_client_id: envelope.owner_client_id,
            agreement: envelope.view.agreement,
            record,
        })
    }
}
impl ManualEnrollmentIntentTarget<'_> {
    pub fn agreement(&self) -> &wholepact_core::AgreementDraft {
        &self.agreement
    }
    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }
    pub fn owner_client_id(&self) -> &str {
        &self.owner_client_id
    }
    pub fn generation_id(&self) -> &str {
        self.store.generation_id()
    }
    pub fn inventory_digest(&self) -> &str {
        self.store.inventory_digest()
    }
    pub fn store_destination_identity(&self) -> &str {
        self.store.store_destination_identity()
    }
    pub fn check_current(&self, access: &Access) -> Result<()> {
        let actual = self
            .engine
            .manual_enrollment_intent_target(access, &self.record.id)?;
        if actual.principal_id != self.principal_id || actual.record != self.record {
            return Err(manual_denied());
        }
        self.store.check_current().map_err(store_error)
    }
}

#[cfg(all(feature = "manual-admission", target_os = "linux"))]
impl Engine {
    /// Reject a missing original Host audit before any private pairing/send.
    /// This comparison is repeated in the eventual IMMEDIATE audit transaction.
    pub fn require_manual_enrollment_continuation_original(
        &self,
        access: &Access,
        target: &ManualEnrollmentTarget<'_>,
        enrollment_ref: &str,
        witness_extension_digest: &str,
    ) -> Result<()> {
        if !std::ptr::eq(self, target.engine) {
            return Err(manual_denied());
        }
        target.check_current(access)?;
        self.store
            .require_manual_enrollment_continuation_original(
                &target.store,
                &target.agreement_record,
                &target.terms,
                enrollment_ref,
                witness_extension_digest,
            )
            .map_err(store_error)
    }

    /// Audit publication only. Neither this receipt nor its historical replay
    /// can be consumed as construction, financial or key-use authority.
    pub fn append_manual_enrollment_continuation_audit(
        &self,
        access: &Access,
        target: &ManualEnrollmentTarget<'_>,
        idempotency_key: &str,
        lease: wholepact_signer_origin::ManualEnrollmentContinuationLeaseV2<'_>,
    ) -> Result<wholepact_store::manual_enrollment::ManualAuditAppendReceipt> {
        if !std::ptr::eq(self, target.engine) || lease.binding().enrollment.terms != target.terms {
            return Err(manual_denied());
        }
        target.check_current(access)?;
        let context = wholepact_store::CommandContext::for_request(
            &access.principal_id,
            idempotency_key,
            &serde_json::to_value(lease.binding()).map_err(|_| manual_denied())?,
        )
        .map_err(store_error)?;
        self.store
            .append_manual_enrollment_continuation_audit(
                &target.store,
                &context,
                &target.agreement_record,
                lease,
            )
            .map_err(store_error)
    }
}

#[cfg(all(feature = "manual-admission", target_os = "linux"))]
impl Engine {
    /// Explicit first Host publication through a genuine V2 successor attempt.
    /// This comparison is repeated in the eventual IMMEDIATE audit transaction.
    pub fn require_manual_enrollment_initial_publication_v2(
        &self,
        access: &Access,
        target: &ManualEnrollmentTarget<'_>,
        enrollment_ref: &str,
        witness_extension_digest: &str,
    ) -> Result<()> {
        if !std::ptr::eq(self, target.engine) {
            return Err(manual_denied());
        }
        target.check_current(access)?;
        self.store
            .require_manual_enrollment_initial_publication_v2(
                &target.store,
                &target.agreement_record,
                &target.terms,
                enrollment_ref,
                witness_extension_digest,
            )
            .map_err(store_error)
    }

    /// Audit publication only. Neither this receipt nor its historical replay
    /// can be consumed as construction, financial or key-use authority.
    pub fn append_manual_enrollment_initial_publication_v2(
        &self,
        access: &Access,
        target: &ManualEnrollmentTarget<'_>,
        idempotency_key: &str,
        lease: wholepact_signer_origin::ManualEnrollmentContinuationLeaseV2<'_>,
    ) -> Result<wholepact_store::manual_enrollment::ManualAuditAppendReceipt> {
        if !std::ptr::eq(self, target.engine) || lease.binding().enrollment.terms != target.terms {
            return Err(manual_denied());
        }
        target.check_current(access)?;
        let context = wholepact_store::CommandContext::for_request(
            &access.principal_id,
            idempotency_key,
            &serde_json::to_value(lease.binding()).map_err(|_| manual_denied())?,
        )
        .map_err(store_error)?;
        self.store
            .append_manual_enrollment_initial_publication_v2(
                &target.store,
                &context,
                &target.agreement_record,
                lease,
            )
            .map_err(store_error)
    }
    /// Require the exact V2 original for a distinct tagged V3 continuation audit.
    /// This comparison is repeated in the eventual IMMEDIATE audit transaction.
    pub fn require_manual_enrollment_continuation_original_v2(
        &self,
        access: &Access,
        target: &ManualEnrollmentTarget<'_>,
        enrollment_ref: &str,
        witness_extension_digest: &str,
    ) -> Result<()> {
        if !std::ptr::eq(self, target.engine) {
            return Err(manual_denied());
        }
        target.check_current(access)?;
        self.store
            .require_manual_enrollment_continuation_original_v2(
                &target.store,
                &target.agreement_record,
                &target.terms,
                enrollment_ref,
                witness_extension_digest,
            )
            .map_err(store_error)
    }

    /// Audit publication only. Neither this receipt nor its historical replay
    /// can be consumed as construction, financial or key-use authority.
    pub fn append_manual_enrollment_continuation_audit_v3(
        &self,
        access: &Access,
        target: &ManualEnrollmentTarget<'_>,
        idempotency_key: &str,
        lease: wholepact_signer_origin::ManualEnrollmentContinuationLeaseV2<'_>,
    ) -> Result<wholepact_store::manual_enrollment::ManualAuditAppendReceipt> {
        if !std::ptr::eq(self, target.engine) || lease.binding().enrollment.terms != target.terms {
            return Err(manual_denied());
        }
        target.check_current(access)?;
        let context = wholepact_store::CommandContext::for_request(
            &access.principal_id,
            idempotency_key,
            &serde_json::to_value(lease.binding()).map_err(|_| manual_denied())?,
        )
        .map_err(store_error)?;
        self.store
            .append_manual_enrollment_continuation_audit_v3(
                &target.store,
                &context,
                &target.agreement_record,
                lease,
            )
            .map_err(store_error)
    }
}

#[cfg(all(feature = "manual-admission", target_os = "linux"))]
impl Engine {
    /// Explicit historical route selection only. Missing original must stay a
    /// denial for an existing-audit continuation command; only the separately
    /// requested first-publication route may proceed from an eligible None.
    pub fn manual_enrollment_original_audit_link(
        &self,
        access: &Access,
        target: &ManualEnrollmentTarget<'_>,
        enrollment_ref: &str,
        witness_extension_digest: &str,
    ) -> Result<Option<wholepact_store::manual_enrollment::OriginalManualEnrollmentAuditLink>> {
        if !std::ptr::eq(self, target.engine) {
            return Err(manual_denied());
        }
        target.check_current(access)?;
        self.store
            .manual_enrollment_original_audit_link(
                &target.store,
                &target.agreement_record,
                &target.terms,
                enrollment_ref,
                witness_extension_digest,
            )
            .map_err(store_error)
    }
}

#[cfg(all(feature = "manual-admission", target_os = "linux"))]
impl Engine {
    /// Local exclusion metadata under an actual current native preparation
    /// lease. No new candidate or financial authority is created by this read.
    pub fn manual_candidate_local_exclusions(
        &self,
        access: &Access,
        lease: &wholepact_signer_origin::ManualCandidateSelectionLease<'_>,
    ) -> Result<wholepact_store::manual_enrollment::ManualCandidateLocalExclusions<'_>> {
        lease.check_current().map_err(|_| manual_denied())?;
        let request = lease.binding();
        let scope = &request.scope;
        let target = self.manual_enrollment_target(access, &scope.inventory.enrollment)?;
        let envelope = decode(&target.agreement_record)?;
        if scope.economic_intent.agreement != envelope.view.agreement
            || scope.economic_intent.candidate_revision != target.agreement_revision
            || envelope
                .view
                .candidates
                .iter()
                .any(|candidate| candidate.candidate_id == scope.economic_intent.candidate_id)
        {
            return Err(manual_denied());
        }
        let result = self
            .store
            .manual_candidate_local_exclusions(&target.store, &target.agreement_record, lease)
            .map_err(store_error)?;
        target.check_current(access)?;
        lease.check_current().map_err(|_| manual_denied())?;
        Ok(result)
    }
}

#[cfg(all(feature = "manual-admission", target_os = "linux"))]
impl Engine {
    pub fn manual_candidate_current_exclusions<'snapshot>(
        &self,
        access: &Access,
        request: &wholepact_core::manual_candidate_selection::ManualCandidateSelectionRequest,
        snapshot: &'snapshot wholepact_store::manual_enrollment::ManualCandidateLocalExclusions<'_>,
    ) -> Result<&'snapshot wholepact_store::financial_preflight::RetainedInputExclusions> {
        let target = self.manual_enrollment_target(access, &request.scope.inventory.enrollment)?;
        let envelope = decode(&target.agreement_record)?;
        if request.scope.economic_intent.agreement != envelope.view.agreement
            || request.scope.economic_intent.candidate_revision != target.agreement_revision
            || envelope.view.candidates.iter().any(|candidate| {
                candidate.candidate_id == request.scope.economic_intent.candidate_id
            })
        {
            return Err(manual_denied());
        }
        snapshot
            .current_for(&self.store, request)
            .map_err(store_error)
    }
}

#[cfg(all(feature = "manual-admission", target_os = "linux"))]
#[path = "manual_roster_candidate_selection_v2.rs"]
mod roster_candidate_selection_v2;
#[cfg(all(feature = "manual-admission", target_os = "linux"))]
#[path = "manual_roster_v2.rs"]
mod roster_v2;
#[cfg(all(feature = "manual-admission", target_os = "linux"))]
pub use roster_v2::ManualRosterIntentTarget;

#[cfg(all(feature = "manual-admission", target_os = "linux"))]
#[path = "manual_roster_construction_claim_v2.rs"]
mod roster_construction_claim_v2;
#[cfg(all(
    feature = "manual-admission",
    feature = "local-proof-jobs",
    target_os = "linux"
))]
pub use roster_construction_claim_v2::ManualRosterConstructionCheckpointViewV2;
#[cfg(all(feature = "manual-admission", target_os = "linux"))]
pub use roster_construction_claim_v2::{
    ManualRosterConstructionClaimOutcomeV2, ManualRosterConstructionClaimTokenV2,
};

#[cfg(all(feature = "manual-admission", target_os = "linux"))]
#[path = "manual_roster_construction_claim_v3.rs"]
mod roster_construction_claim_v3;
#[cfg(all(
    feature = "manual-admission",
    feature = "local-proof-jobs",
    target_os = "linux"
))]
pub use roster_construction_claim_v3::ManualRosterConstructionCheckpointViewV3;
#[cfg(all(feature = "manual-admission", target_os = "linux"))]
pub use roster_construction_claim_v3::{
    ManualRosterConstructionClaimOutcomeV3, ManualRosterConstructionClaimTokenV3,
};

#[cfg(all(
    feature = "manual-admission",
    feature = "local-proof-jobs",
    target_os = "linux"
))]
#[path = "manual_roster_construction_inspection_v2.rs"]
mod roster_construction_inspection_v2;
#[cfg(all(
    feature = "manual-admission",
    feature = "local-proof-jobs",
    target_os = "linux"
))]
pub use roster_construction_inspection_v2::{
    ManualRosterConstructionInspectionMetadataV2, PreparedManualRosterConstructionInspectionV2,
};

#[cfg(all(
    feature = "manual-admission",
    feature = "local-proof-jobs",
    target_os = "linux"
))]
#[path = "manual_roster_construction_inspection_v3.rs"]
mod roster_construction_inspection_v3;
#[cfg(all(
    feature = "manual-admission",
    feature = "local-proof-jobs",
    target_os = "linux"
))]
pub use roster_construction_inspection_v3::{
    ManualRosterConstructionInspectionMetadataV3, PreparedManualRosterConstructionInspectionV3,
};

#[cfg(all(feature = "manual-admission", target_os = "linux"))]
#[path = "manual_permanent_stop_v1.rs"]
mod permanent_stop_v1;
#[cfg(all(feature = "manual-admission", target_os = "linux"))]
pub use permanent_stop_v1::ManualPermanentStopTargetV1;
