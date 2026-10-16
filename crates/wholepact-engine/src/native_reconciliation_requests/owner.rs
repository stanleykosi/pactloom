//! Native-only actual journal reads and exact independent verifier composition.
//! No caller report, boolean approval, or public result-writing endpoint exists.
use super::*;
use crate::native_dispatch_requests::DispatchObservation;
use wholepact_chain::EncryptedSubmissionJournal;
#[cfg(all(feature = "signer-authority-bridge", target_os = "linux"))]
mod resolution;
#[cfg(all(feature = "signer-authority-bridge", target_os = "linux"))]
pub use resolution::NativeRecordResolutionGuard;

impl Engine {
    /// Must precede provider disclosure or signer contact. An absent actual intent
    /// leaves the durable attempt unknown; cached browser history is never enough.
    pub fn validate_native_reconciliation_attempt(
        &self,
        access: &Access,
        attempt: &NativeReconciliationAttempt,
        journal: &EncryptedSubmissionJournal,
    ) -> Result<()> {
        let e = self.prepare_reconciliation_owner(access, &attempt.saved, true)?;
        let observation = actual_observation(journal, &attempt.saved)?;
        observations::validate_observation(&e, &attempt.saved, &observation)?;
        if observation.submission.descriptor.is_none() || observation.submission.intent.is_none() {
            return Err(unavailable());
        }
        Ok(())
    }
    /// Native caller holds fresh permission for this actual journal disclosure.
    /// `recover_reconciler` explicitly returns stale historical provider evidence;
    /// it can never establish an independent record-resolution commit.
    pub fn inspect_native_reconciliation_status(
        &self,
        access: &Access,
        inspection: NativeReconciliationInspection,
        journal: &EncryptedSubmissionJournal,
    ) -> Result<NativeReconciliationRequestView> {
        let saved = inspection.saved;
        let e = self.prepare_reconciliation_owner(access, &saved, false)?;
        let observation = actual_observation(journal, &saved)?;
        observations::validate_observation(&e, &saved, &observation)?;
        self.finish_reconciliation_observation(access, &saved, e.view.revision, observation)
    }
    fn prepare_reconciliation_owner(
        &self,
        access: &Access,
        saved: &StoredNativeReconciliationRequest,
        initial: bool,
    ) -> Result<Envelope> {
        self.protected_record_store_binding()?;
        self.require_current_agreement(&saved.agreement_id)?;
        let e = self.load(access, &saved.agreement_id)?;
        let current = owned(&e, access, &saved.request_id)?;
        if !same_original(saved, current) || current.state != NativeRequestState::AttemptStarted {
            return Err(inconsistent());
        }
        validate_original(&e, current)?;
        if initial
            && (!current.observations.is_empty()
                || current.resolution_commit.is_some()
                || Some(e.view.revision) != current.attempt_revision)
        {
            return Err(closed());
        }
        Ok(e)
    }
    fn finish_reconciliation_observation(
        &self,
        access: &Access,
        saved: &StoredNativeReconciliationRequest,
        revision: u64,
        observation: ReconciliationJournalObservation,
    ) -> Result<NativeReconciliationRequestView> {
        let mut e = self.prepare_reconciliation_owner(access, saved, false)?;
        let current = owned(&e, access, &saved.request_id)?;
        observations::validate_observation(&e, current, &observation)?;
        // Exact old snapshots are historical replay, never a rollback of latest.
        if current.observations.contains(&observation) {
            return Ok(view(current));
        }
        candidates::check_revision(&e, revision)?;
        if current.observations.len() >= MAX_RECONCILIATION_OBSERVATIONS {
            return Err(exhausted());
        }
        if current
            .observations
            .last()
            .is_some_and(|p| !observations::monotone(p, &observation))
        {
            return Err(inconsistent());
        }
        let snapshot = hash_domain(
            b"wholepact:native-reconciliation-observation:v1\0",
            &json!({"request_id":saved.request_id,"observation":observation}),
        )?;
        let command = context(
            access,
            &format!("native-reconciliation-observe-{snapshot}"),
            "native_reconciliation_observed",
            &saved.agreement_id,
            Some(revision),
            &json!({"request_id":saved.request_id,"observation":observation}),
        )?;
        e.native_reconciliation_requests
            .get_mut(&saved.request_id)
            .ok_or_else(not_found)?
            .observations
            .push(observation);
        self.commit(
            &command,
            &saved.agreement_id,
            revision,
            e,
            "native_reconciliation_result_observed",
        )?;
        self.native_reconciliation_request(access, &saved.agreement_id, &saved.request_id)
    }
}
fn actual_observation(
    journal: &EncryptedSubmissionJournal,
    saved: &StoredNativeReconciliationRequest,
) -> Result<ReconciliationJournalObservation> {
    if journal.identity() != saved.submission_journal_identity {
        return Err(inconsistent());
    }
    let descriptor = journal
        .retained_submission_descriptor(&saved.operation_id)
        .map_err(|_| unavailable())?;
    let attempts = journal
        .submission_attempts(&saved.operation_id)
        .map_err(|_| unavailable())?;
    let intent = journal
        .recover_intent_summary(&saved.operation_id)
        .map_err(|_| unavailable())?;
    let reconciler = journal
        .recover_reconciler(&saved.operation_id)
        .map_err(|_| unavailable())?;
    let report = reconciler
        .as_ref()
        .and_then(|r| r.last_report())
        .map(actual_metadata)
        .transpose()?;
    Ok(ReconciliationJournalObservation {
        submission: DispatchObservation {
            submission_journal_identity: journal.identity().into(),
            descriptor: descriptor.as_ref().map(actual_metadata).transpose()?,
            intent: intent.as_ref().map(actual_metadata).transpose()?,
            attempts: actual_metadata(&attempts)?,
        },
        report,
    })
}
fn actual_metadata<T: Serialize, U: serde::de::DeserializeOwned>(actual: &T) -> Result<U> {
    serde_json::from_value(serde_json::to_value(actual).map_err(|_| inconsistent())?)
        .map_err(|_| inconsistent())
}
fn unavailable() -> ApiError {
    ApiError::new(
        "RECONCILIATION_STATUS_UNAVAILABLE",
        "Exact original journal evidence is unavailable; the attempt remains unknown and no dispatch or resolution retry is granted",
    )
}
