//! Private positive commit marker, issued only after the existing live independent
//! source + authenticated original signer + exact ledger verifier succeeds.
use super::*;
use crate::native_dispatch_requests::DispatchDescriptor;
use crate::participant_records::{
    ParticipantRecordRuntime, reconciliation_selection::SelectedRecordLease,
};
use crate::settlement_fanout::{SettlementSinkAuthority, SettlementSinkScope};
use wholepact_chain::{
    local_node::{LocalNodeSourceDescriptor, LocalResolutionPermit},
    settlement_evidence::RetainedSettlementObservation,
};
use wholepact_signer::authority_bridge::{
    ipc::OriginalHistoryLease,
    settlement_ipc::{SettlementRequest, SignerSettlementReceipt},
};

/// Genuine exact ReadPrivate lease held before signer pairing and through commit.
/// Positive mutation is separately authorized by SettlementSinkAuthority.
pub struct NativeRecordResolutionGuard<'a> {
    saved: StoredNativeReconciliationRequest,
    record: SelectedRecordLease<'a>,
}
impl NativeRecordResolutionGuard<'_> {
    pub fn check_current(&self) -> Result<()> {
        self.record.check_current()
    }
    pub(crate) fn check_commit_permission(&self) -> Result<()> {
        self.record.check_commit_permission()
    }
    /// Bind the genuine retained signer original to this selected private record
    /// before requesting a signer settlement receipt or any other positive effect.
    pub fn validate_signer_history(&self, history: &OriginalHistoryLease<'_>) -> Result<()> {
        self.record.validate_signer_history(history)
    }
}
impl Engine {
    pub fn prepare_native_record_resolution<'a>(
        &self,
        access: &Access,
        attempt: &NativeReconciliationAttempt,
        runtime: &'a ParticipantRecordRuntime<'_>,
    ) -> Result<NativeRecordResolutionGuard<'a>> {
        let e = self.prepare_reconciliation_owner(access, &attempt.saved, true)?;
        let NativeReconciliationRequest::IndependentRecordResolution {
            participant_id,
            record_id,
            ..
        } = &attempt.saved.request
        else {
            return Err(inconsistent());
        };
        let record = crate::participant_records::reconciliation_selection::acquire_selection(
            self,
            access,
            &e,
            &attempt.saved.source,
            participant_id,
            record_id,
            runtime,
        )?;
        record.check_current()?;
        Ok(NativeRecordResolutionGuard {
            saved: attempt.saved.clone(),
            record,
        })
    }
    /// No boolean or serialized result can enter this path. A metadata CAS failure
    /// after apply preserves unknown, even if the separate ledger commit succeeded.
    /// A subsequent explicit request must obtain new live exact source and signer
    /// checks; historical provider reports cannot complete or reset this attempt.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_native_record_resolution(
        &self,
        access: &Access,
        attempt: &NativeReconciliationAttempt,
        guard: &NativeRecordResolutionGuard<'_>,
        scope: &SettlementSinkScope,
        evidence: &RetainedSettlementObservation,
        permit: &LocalResolutionPermit,
        enrolled_source: &LocalNodeSourceDescriptor,
        history: &OriginalHistoryLease<'_>,
        receipt: &SignerSettlementReceipt<'_>,
        request: &SettlementRequest,
        authority: &dyn SettlementSinkAuthority,
    ) -> Result<NativeReconciliationRequestView> {
        let saved = &attempt.saved;
        let e = self.prepare_reconciliation_owner(access, saved, true)?;
        if !same_original(saved, &guard.saved)
            || saved.request.kind() != ReconciliationRequestKind::IndependentRecordResolution
            || evidence.journal_identity() != saved.submission_journal_identity
            || scope.journal_identity != saved.submission_journal_identity
            || scope.transaction != *evidence.descriptor()
        {
            return Err(inconsistent());
        }
        let descriptor: DispatchDescriptor = actual_metadata(evidence.descriptor())?;
        native_dispatch_requests::validate_reconciliation_descriptor(
            &e,
            &access.principal_id,
            saved.request.dispatch_request_id(),
            &descriptor,
        )?;
        guard
            .record
            .check_origin(self, access, &e, &saved.source, history.evidence())?;
        history.check_current().map_err(|_| inconsistent())?;
        guard.check_current()?;
        self.apply_settlement_resolution_checked(
            scope,
            evidence,
            permit,
            enrolled_source,
            history,
            receipt,
            request,
            authority,
            &|| guard.check_commit_permission(),
        )?;
        // Genuine apply is the only producer of this private historical marker.
        // Neither report status nor consumed-looking metadata can substitute for it.
        guard.check_current()?;
        let commit = StoredResolutionCommit {
            evidence_id: evidence.evidence_id().into(),
            signer_settlement_request_digest: request.digest().map_err(|_| inconsistent())?,
            participant_id: saved
                .request
                .participant_id()
                .ok_or_else(inconsistent)?
                .into(),
            record_id: saved.request.record_id().ok_or_else(inconsistent)?.into(),
        };
        self.finish_native_record_resolution(access, saved, commit)
    }
    fn finish_native_record_resolution(
        &self,
        access: &Access,
        saved: &StoredNativeReconciliationRequest,
        commit: StoredResolutionCommit,
    ) -> Result<NativeReconciliationRequestView> {
        let mut e = self.prepare_reconciliation_owner(access, saved, false)?;
        let current = owned(&e, access, &saved.request_id)?;
        if let Some(previous) = &current.resolution_commit {
            if previous != &commit {
                return Err(inconsistent());
            }
            return Ok(view(current));
        }
        // apply_settlement_resolution may have advanced this agreement revision.
        let revision = e.view.revision;
        let command = context(
            access,
            &format!("native-reconciliation-resolution-{}", saved.request_id),
            "native_reconciliation_resolution_recorded",
            &saved.agreement_id,
            Some(revision),
            &json!({"request_id":saved.request_id,"commit":commit}),
        )?;
        e.native_reconciliation_requests
            .get_mut(&saved.request_id)
            .ok_or_else(not_found)?
            .resolution_commit = Some(commit);
        self.commit(
            &command,
            &saved.agreement_id,
            revision,
            e,
            "native_reconciliation_resolution_recorded",
        )?;
        self.native_reconciliation_request(access, &saved.agreement_id, &saved.request_id)
    }
}
