//! Real private journal reads and real verified-predecessor binding only.
//! No injected runtime, caller-supplied result writer, extraction or dispatch API.
use super::*;
use crate::signature_intake::VerifiedCandidateSubmission;
use wholepact_chain::EncryptedSubmissionJournal;

impl Engine {
    /// Check the actual Engine-origin retained predecessor before the native owner
    /// requests provider admission or invokes its protected dispatch composition.
    /// The marker is inert metadata; this check does not issue financial authority.
    pub fn validate_native_dispatch_attempt(
        &self,
        access: &Access,
        attempt: &NativeDispatchAttempt,
        verified: &VerifiedCandidateSubmission,
        journal: &EncryptedSubmissionJournal,
    ) -> Result<()> {
        let e = self.prepare_dispatch_owner(access, &attempt.saved, true)?;
        let saved = &attempt.saved;
        if journal.identity() != attempt.submission_journal_identity() {
            return Err(inconsistent());
        }
        let candidate = candidate_for_source(&e, &saved.source)?;
        candidates::check_current_terms(&e.view, &candidate.proposal.manifest)?;
        let descriptor: DispatchDescriptor = actual_metadata(verified.descriptor())?;
        observations::descriptor_matches(&e, saved, &descriptor)?;
        let actual = verified.context();
        let original = &saved.source.original;
        if verified.agreement_id() != saved.agreement_id
            || verified.signature_retention_key() != original.signature_retention_key
            || verified.signed_result_id() != saved.source.signed.result_id
            || verified.signed_request_digest() != saved.source.signed.request_digest
            || verified.signed_candidate_digest() != saved.source.signed.signed_candidate_digest
            || verified.checkpoint_id() != saved.source.checkpoint_id
            || actual.principal_id != access.principal_id
            || actual.candidate_id != original.candidate_id
            || actual.proof_job_id != original.job_id
            || actual.checkpoint_scope_digest != original.scope_digest
            || actual.proved_artifact_digest != original.proved_artifact_digest
            || actual.manifest_digest != original.manifest_digest
            || !digest(verified.effects_digest())
        {
            return Err(inconsistent());
        }
        // The real verification constructor revalidates original signatures and
        // transaction journals. Browser metadata cannot construct `verified`.
        Ok(())
    }
    /// Caller must hold fresh native permission to disclose this exact journal's
    /// metadata. Reads only public journal metadata APIs; those journal methods
    /// internally authenticate/read private bytes but no bytes leave this API.
    /// A missing intent is unknown historical evidence, never proven non-delivery.
    pub fn inspect_native_dispatch_status(
        &self,
        access: &Access,
        inspection: NativeDispatchInspection,
        journal: &EncryptedSubmissionJournal,
    ) -> Result<NativeDispatchRequestView> {
        let saved = inspection.saved;
        let e = self.prepare_dispatch_owner(access, &saved, false)?;
        if saved.submission_journal_identity.as_deref() != Some(journal.identity()) {
            return Err(inconsistent());
        }
        // Historical status is bound to the immutable original candidate. Later
        // agreement amendments or cancellation do not hide earlier delivery facts.
        // Keep all reads inside the native owner's current journal/authority lock.
        // Never dispatch, recover an exact intent, export bytes or infer a retry.
        let descriptor = journal
            .retained_submission_descriptor(&saved.operation_id)
            .map_err(|_| journal_unavailable())?;
        let attempts = journal
            .submission_attempts(&saved.operation_id)
            .map_err(|_| journal_unavailable())?;
        let intent = journal
            .recover_intent_summary(&saved.operation_id)
            .map_err(|_| journal_unavailable())?;
        let observation = DispatchObservation {
            submission_journal_identity: journal.identity().to_owned(),
            descriptor: descriptor.as_ref().map(actual_metadata).transpose()?,
            intent: intent.as_ref().map(actual_metadata).transpose()?,
            attempts: actual_metadata(&attempts)?,
        };
        observations::validate_observation(&e, &saved, &observation)?;
        self.finish_dispatch_observation(access, &saved, e.view.revision, observation)
    }
    fn prepare_dispatch_owner(
        &self,
        access: &Access,
        saved: &StoredNativeDispatchRequest,
        initial: bool,
    ) -> Result<Envelope> {
        self.protected_record_store_binding()?;
        self.require_current_agreement(&saved.agreement_id)?;
        let e = self.load(access, &saved.agreement_id)?;
        let current = owned(&e, access, &saved.request_id)?;
        if !same_original(saved, current) || current.state != NativeRequestState::AttemptStarted {
            return Err(inconsistent());
        }
        if initial
            && (!current.observations.is_empty()
                || Some(e.view.revision) != current.attempt_revision)
        {
            return Err(closed());
        }
        Ok(e)
    }
    fn finish_dispatch_observation(
        &self,
        access: &Access,
        saved: &StoredNativeDispatchRequest,
        revision: u64,
        observation: DispatchObservation,
    ) -> Result<NativeDispatchRequestView> {
        let mut e = self.load(access, &saved.agreement_id)?;
        let current = owned(&e, access, &saved.request_id)?;
        if !same_original(saved, current) || current.state != NativeRequestState::AttemptStarted {
            return Err(inconsistent());
        }
        observations::validate_observation(&e, current, &observation)?;
        // An exact older snapshot is only historical replay. Do not roll latest back.
        if current.observations.contains(&observation) {
            return Ok(view(current));
        }
        candidates::check_revision(&e, revision)?;
        if current.observations.len() >= MAX_DISPATCH_OBSERVATIONS {
            return Err(exhausted());
        }
        if current
            .observations
            .last()
            .is_some_and(|p| !observations::monotone(p, &observation))
        {
            return Err(inconsistent());
        }
        let snapshot_digest = hash_domain(
            b"wholepact:native-dispatch-observation:v1\0",
            &json!({"request_id":saved.request_id,"observation":observation}),
        )?;
        let command = context(
            access,
            &format!("native-dispatch-observe-{snapshot_digest}"),
            "native_dispatch_observed",
            &saved.agreement_id,
            Some(revision),
            &json!({"request_id":saved.request_id,"observation":observation}),
        )?;
        e.native_dispatch_requests
            .get_mut(&saved.request_id)
            .ok_or_else(not_found)?
            .observations
            .push(observation);
        // Private effects may already be durable. A failed metadata CAS leaves the
        // original attempt fenced; fresh inspection may record existing facts later.
        self.commit(
            &command,
            &saved.agreement_id,
            revision,
            e,
            "native_dispatch_result_observed",
        )?;
        self.native_dispatch_request(access, &saved.agreement_id, &saved.request_id)
    }
}
fn actual_metadata<T: Serialize, U: serde::de::DeserializeOwned>(actual: &T) -> Result<U> {
    serde_json::from_value(serde_json::to_value(actual).map_err(|_| inconsistent())?)
        .map_err(|_| inconsistent())
}
fn journal_unavailable() -> ApiError {
    ApiError::new(
        "SUBMISSION_STATUS_UNAVAILABLE",
        "Exact original journal metadata is unavailable; delivery remains unknown and no dispatch retry is granted",
    )
}
