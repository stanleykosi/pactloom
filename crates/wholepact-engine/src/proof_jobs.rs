//! Embedded local-only bridge to an independent encrypted artifact journal.
//! Public summaries omit PCZT, FVK and private policy bytes. The explicit local
//! review loader returns a sealed sensitive checkpoint under separate read consent.
//! Coordination and artifact commits are separate; recovery never reconstructs
//! saved randomness.
use super::*;
use crate::candidates::{
    check_current_terms, check_revision, private_request_digest, CandidateProofJob,
    LocalConstruction,
};
use wholepact_proof_jobs::{
    CheckpointScope, JobError, JobSummary, LocalAction, LocalProofConsent, ProofJobStore,
};
use wholepact_protocol::proving::ProvingLimits;

/// Neither serializable nor a human approval token. The embedding supplies an
/// authenticated, exact-scope local privacy gate; no default allow exists.
pub struct LocalCheckpoint<'a> {
    pub construction: LocalConstruction<'a>,
    pub jobs: &'a ProofJobStore,
    pub limits: ProvingLimits,
    pub consent: &'a dyn LocalProofConsent,
}
/// Protected scanner selections retained only under both current source provenance
/// and the embedding's existing exact-scope local retention consent.
#[cfg(feature = "wallet-sync")]
pub struct ScannedWalletCheckpoint<'a> {
    pub construction: crate::candidates::ScannedWalletConstruction<'a>,
    pub jobs: &'a ProofJobStore,
    pub limits: ProvingLimits,
    pub consent: &'a dyn LocalProofConsent,
}

#[cfg(feature = "wallet-sync")]
struct WalletCheckpointConsent<'a> {
    inner: &'a dyn LocalProofConsent,
    guards: &'a [wholepact_wallet::wallet::protected_sync::WalletObservationGuard],
}
#[cfg(feature = "wallet-sync")]
impl LocalProofConsent for WalletCheckpointConsent<'_> {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        let current = || {
            action != LocalAction::RetainPrivateWitnesses
                || crate::candidates::check_wallet_guards(self.guards).is_ok()
        };
        // Recheck after the external gate as it can invalidate controller state.
        current() && self.inner.permits(scope, action) && current()
    }
}

pub struct LocalProofJob<'a> {
    pub job_id: &'a str,
    pub jobs: &'a ProofJobStore,
    pub consent: &'a dyn LocalProofConsent,
}

impl Engine {
    fn require_protected_metadata(&self) -> Result<()> {
        if self.store.protection() != wholepact_store::StorageProtection::Encrypted {
            return Err(ApiError::new("STORAGE_PROTECTION_REQUIRED", "The local proof bridge requires verified encrypted coordination and artifact journals"));
        }
        Ok(())
    }

    /// Keep the exact protected-wallet candidate rather than reconstructing it
    /// after a transient economic report. No signing or distribution is enabled.
    /// Existing checkpoints remain inspectable/reconcilable through the separate
    /// status/reconciliation APIs after the source wallet generation expires.
    #[cfg(feature = "wallet-sync")]
    pub fn checkpoint_candidate_from_wallets(
        &self,
        access: &Access,
        key: &str,
        candidate_id: &str,
        revision: u64,
        local: ScannedWalletCheckpoint<'_>,
    ) -> Result<Mutation> {
        self.require_protected_metadata()?;
        let (current_view, _) = self.candidate(access, candidate_id)?;
        self.require_current_agreement(&current_view.agreement.agreement_id)?;
        let (construction, guards) =
            crate::candidates::checked_wallet_construction(local.construction)?;
        let consent = WalletCheckpointConsent {
            inner: local.consent,
            guards: &guards,
        };
        self.checkpoint_candidate_locally(
            access,
            key,
            candidate_id,
            revision,
            LocalCheckpoint {
                construction,
                jobs: local.jobs,
                limits: local.limits,
                consent: &consent,
            },
        )
        .map_err(|mut error| {
            // Preserve durable-receipt recovery details if invalidation occurred
            // after the independent metadata commit but before private retention.
            if error.code == "DISCLOSURE_DENIED" {
                if let Err(source) = crate::candidates::check_wallet_guards(&guards) {
                    error.code = source.code;
                    error.message = source.message;
                }
            }
            error
        })
    }

    /// Construct and retain an exact unsigned candidate, then link its safe
    /// summary. Artifact lookup precedes *all* randomized construction, including
    /// when the artifact commit survived but this engine's operation did not.
    pub fn checkpoint_candidate_locally(
        &self,
        access: &Access,
        key: &str,
        candidate_id: &str,
        revision: u64,
        local: LocalCheckpoint<'_>,
    ) -> Result<Mutation> {
        self.require_protected_metadata()?;
        let LocalCheckpoint {
            construction,
            jobs,
            limits,
            consent,
        } = local;
        if !(1..=wholepact_protocol::proving::MAX_PROVING_ACTIONS).contains(&limits.maximum_actions)
        {
            return Err(ApiError::new(
                "INVALID_REQUEST",
                "Local proof action budget must be between one and eight",
            ));
        }
        let input_digest = private_request_digest(
            construction.context,
            &construction.contributions,
            construction.declarations,
        )?;
        let command = context(
            access,
            key,
            "checkpoint_candidate_locally",
            candidate_id,
            Some(revision),
            &json!({"local_input_digest":input_digest,"maximum_actions":limits.maximum_actions}),
        )?;
        let (view, candidate) = self.candidate(access, candidate_id)?;
        self.require_current_agreement(&view.agreement.agreement_id)?;
        let id = &view.agreement.agreement_id;
        let mut envelope = self.load(access, id)?;
        let receipt_key = hash_domain(
            b"wholepact:checkpoint-receipt:v1\0",
            &json!({"principal":access.principal_id,"key":key}),
        )?;
        // Errors (denied consent, corrupt store, mismatched original request)
        // are never treated as an absent checkpoint.
        let saved = jobs
            .status_for_key(&access.principal_id, key, &command.request_digest, consent)
            .map_err(job_error)?;
        if let Some(replay) = self.replay(access, &command)? {
            let saved = saved.ok_or_else(|| ApiError::new("RECOVERY_REQUIRED", "The coordination journal refers to a missing private checkpoint; restore the original encrypted journal before continuing"))?;
            validate_summary(&candidate, &saved)?;
            validate_provenance(&envelope, access, &saved)?;
            return Ok(replay);
        }
        if let Some(saved) = saved {
            validate_summary(&candidate, &saved)?;
            let prepared_revision =
                validate_provenance(&envelope, access, &saved)?.prepared_revision;
            check_revision(&envelope, prepared_revision)
                .map_err(|error| checkpoint_exists(error, &saved))?;
            // This records an already-durable fact, even if a later local intent
            // was withdrawn. It performs no new retention or proving operation.
            upsert_link(&mut envelope, &saved).map_err(|error| checkpoint_exists(error, &saved))?;
            return self
                .commit(
                    &command,
                    id,
                    prepared_revision,
                    envelope,
                    "candidate_checkpoint_link_recovered",
                )
                .map_err(|error| checkpoint_exists(error, &saved));
        }
        if envelope.checkpoint_receipts.contains_key(&receipt_key) {
            return Err(ApiError::new("RECOVERY_REQUIRED", "An exact constructor receipt exists without its encrypted private artifact. Restore the original artifact journal; do not reconstruct randomized bytes under this request"));
        }
        check_revision(&envelope, revision)?;
        check_current_terms(&envelope.view, &candidate.proposal.manifest)?;
        if candidate.proof_jobs.len() >= 8 {
            return Err(ApiError::new(
                "RESOURCE_EXHAUSTED",
                "At most eight local proof checkpoints can be linked per candidate",
            ));
        }
        let proposal = candidate.verified_snapshot()?;
        let declarations = construction.declarations;
        let first = declarations.first().ok_or_else(|| {
            ApiError::new(
                "DISCLOSURE_DENIED",
                "Every selected account needs the same exact local retention scope",
            )
        })?;
        if declarations
            .iter()
            .any(|d| d.purpose != first.purpose || d.retention_policy != first.retention_policy)
        {
            return Err(ApiError::new("DISCLOSURE_DENIED", "All selected accounts must declare the exact same local purpose and retention policy"));
        }
        let built = wholepact_protocol::construction::construct_proposal(
            &proposal,
            construction.context,
            construction.contributions,
            declarations,
        )
        .map_err(|_| {
            ApiError::new(
                "CANDIDATE_VERIFICATION_FAILED",
                "Exact local candidate construction failed before private retention",
            )
        })?;
        let structure = wholepact_protocol::inspect_candidate(&built.pczt_bytes).map_err(|_| {
            ApiError::new(
                "CANDIDATE_VERIFICATION_FAILED",
                "Constructed local artifact failed bounded inspection",
            )
        })?;
        if structure.actions > limits.maximum_actions {
            return Err(ApiError::new(
                "RESOURCE_EXHAUSTED",
                "The actual padded candidate exceeds the explicitly selected local proving budget",
            ));
        }
        let scope = CheckpointScope {
            principal_id: access.principal_id.clone(),
            candidate_id: candidate_id.into(),
            manifest_digest: candidate.manifest_digest.clone(),
            coordination_request_digest: command.request_digest.clone(),
            artifact_digest: hex::encode(Sha256::digest(&built.pczt_bytes)),
            effects_commitment: built.economic_review.shielded_sighash().into(),
            review_binding: built.economic_review.review_binding().into(),
            account_ids: proposal
                .manifest()
                .participants
                .iter()
                .map(|p| p.account_id.clone())
                .collect(),
            local_operator: proposal
                .manifest()
                .agreement
                .privacy_profile
                .proving_operator
                .clone()
                .ok_or_else(internal)?,
            purpose: first.purpose.clone(),
            retention_policy: first.retention_policy.clone(),
        };
        if !consent.permits(&scope, LocalAction::RetainPrivateWitnesses) {
            return Err(job_error(JobError::ConsentDenied));
        }
        // The constructor's exact artifact receipt is durable before the separate
        // private commit. A caller-supplied manifest digest is not provenance.
        let prepared_revision = revision.checked_add(1).ok_or_else(internal)?;
        let receipt = candidates::CheckpointReceipt {
            job_id: wholepact_proof_jobs::job_id_for_key(&access.principal_id, key)
                .map_err(job_error)?,
            scope_digest: hex::encode(Sha256::digest(
                serde_json::to_vec(&scope).map_err(|_| internal())?,
            )),
            principal_id: access.principal_id.clone(),
            candidate_id: candidate_id.into(),
            manifest_digest: candidate.manifest_digest.clone(),
            coordination_request_digest: command.request_digest.clone(),
            artifact_digest: scope.artifact_digest.clone(),
            review_binding: scope.review_binding.clone(),
            effects_commitment: scope.effects_commitment.clone(),
            prepared_revision,
        };
        if envelope.checkpoint_receipts.len() >= 128 {
            return Err(ApiError::new(
                "RESOURCE_EXHAUSTED",
                "Local constructor receipt limit reached",
            ));
        }
        let prepare_command = context(
            access,
            &format!("prepare-{receipt_key}"),
            "prepare_checkpoint_receipt",
            candidate_id,
            Some(revision),
            &receipt,
        )?;
        envelope.checkpoint_receipts.insert(receipt_key, receipt);
        self.commit(
            &prepare_command,
            id,
            revision,
            envelope.clone(),
            "candidate_checkpoint_constructor_recorded",
        )?;
        envelope.view.revision = prepared_revision;
        let saved = jobs
            .enqueue(
                &scope,
                key,
                &built.pczt_bytes,
                &built.review_policy,
                limits,
                consent,
            )
            .map_err(|error| {
                let mut error = job_error(error);
                error.details = Box::new(json!({"constructor_receipt_created":true,"prepared_revision":prepared_revision,"coordination_request_digest":command.request_digest,"encrypted_checkpoint_status":"not_confirmed","journals_are_atomic_together":false}));
                error.safe_actions = vec!["Inspect the original encrypted checkpoint using the same principal, key and request before retrying".into(), "If no artifact exists, restore the original journal or prepare a separately reviewed new request; do not reconstruct randomized bytes under this key".into()];
                error
            })?;
        validate_summary(&candidate, &saved)?;
        validate_provenance(&envelope, access, &saved)?;
        upsert_link(&mut envelope, &saved).map_err(|error| checkpoint_exists(error, &saved))?;
        self.commit(
            &command,
            id,
            prepared_revision,
            envelope,
            "candidate_private_checkpoint_created",
        )
        .map_err(|error| checkpoint_exists(error, &saved))
    }

    /// Safe status observation; no private bytes are returned and current local
    /// status consent is checked by the artifact journal on every invocation.
    pub fn candidate_proof_status(
        &self,
        access: &Access,
        candidate_id: &str,
        local: LocalProofJob<'_>,
    ) -> Result<CandidateProofJob> {
        self.require_protected_metadata()?;
        let (view, candidate) = self.candidate(access, candidate_id)?;
        self.require_current_agreement(&view.agreement.agreement_id)?;
        let summary = local
            .jobs
            .status(&access.principal_id, local.job_id, local.consent)
            .map_err(job_error)?;
        validate_summary(&candidate, &summary)?;
        validate_provenance(
            &self.load(access, &view.agreement.agreement_id)?,
            access,
            &summary,
        )?;
        Ok(public_summary(&summary))
    }

    /// Sensitive local review handoff, never a service/transport response. Checks
    /// the engine-origin constructor receipt before decrypting a saved proof and
    /// delegates exact-scope, current ReadPrivateArtifact consent to the private
    /// journal. The sealed result conveys no human approval or spending authority.
    pub fn load_candidate_proof_for_local_review(
        &self,
        access: &Access,
        candidate_id: &str,
        local: LocalProofJob<'_>,
    ) -> Result<wholepact_proof_jobs::VerifiedCheckpoint> {
        self.require_protected_metadata()?;
        let (view, candidate) = self.candidate(access, candidate_id)?;
        self.require_current_agreement(&view.agreement.agreement_id)?;
        let envelope = self.load(access, &view.agreement.agreement_id)?;
        let summary = local
            .jobs
            .status(&access.principal_id, local.job_id, local.consent)
            .map_err(job_error)?;
        validate_summary(&candidate, &summary)?;
        validate_provenance(&envelope, access, &summary)?;
        let checkpoint = local
            .jobs
            .load_verified(&access.principal_id, local.job_id, local.consent)
            .map_err(job_error)?;
        validate_summary(&candidate, checkpoint.summary())?;
        validate_provenance(&envelope, access, checkpoint.summary())?;
        Ok(checkpoint)
    }

    /// Reconcile an already-existing encrypted job at an explicitly supplied
    /// current coordination revision. This never constructs or proves anything.
    /// It is the repair route if a separate artifact commit survived a CAS race.
    pub fn reconcile_candidate_proof_job(
        &self,
        access: &Access,
        key: &str,
        candidate_id: &str,
        revision: u64,
        local: LocalProofJob<'_>,
    ) -> Result<Mutation> {
        self.record_proof_job(access, key, candidate_id, revision, local, false)
    }

    /// Bounded synchronous local proof work. The proof store commits running
    /// intent before CPU work, verifies the actual proof and checkpoints exact
    /// bytes before this independent coordination read model is updated.
    pub fn run_candidate_proof_locally(
        &self,
        access: &Access,
        key: &str,
        candidate_id: &str,
        revision: u64,
        local: LocalProofJob<'_>,
    ) -> Result<Mutation> {
        self.record_proof_job(access, key, candidate_id, revision, local, true)
    }

    fn record_proof_job(
        &self,
        access: &Access,
        key: &str,
        candidate_id: &str,
        revision: u64,
        local: LocalProofJob<'_>,
        run: bool,
    ) -> Result<Mutation> {
        self.require_protected_metadata()?;
        let name = if run {
            "run_candidate_proof_locally"
        } else {
            "reconcile_candidate_proof_job"
        };
        let command = context(
            access,
            key,
            name,
            candidate_id,
            Some(revision),
            &json!({"job_id":local.job_id}),
        )?;
        let (view, candidate) = self.candidate(access, candidate_id)?;
        self.require_current_agreement(&view.agreement.agreement_id)?;
        let status = local
            .jobs
            .status(&access.principal_id, local.job_id, local.consent)
            .map_err(job_error)?;
        validate_summary(&candidate, &status)?;
        validate_provenance(
            &self.load(access, &view.agreement.agreement_id)?,
            access,
            &status,
        )?;
        if let Some(replay) = self.replay(access, &command)? {
            return Ok(replay);
        }
        let id = &view.agreement.agreement_id;
        let mut envelope = self.load(access, id)?;
        check_revision(&envelope, revision).map_err(|error| checkpoint_exists(error, &status))?;
        let summary = if run {
            if !candidate
                .proof_jobs
                .iter()
                .any(|job| job.job_id == local.job_id)
            {
                return Err(ApiError::new("INVALID_TRANSITION", "Reconcile the existing encrypted checkpoint into this candidate before starting proof work"));
            }
            check_current_terms(&envelope.view, &candidate.proposal.manifest)?;
            local
                .jobs
                .run(&access.principal_id, local.job_id, local.consent)
                .map_err(|error| {
                    let mut error = job_error(error);
                    error.details = Box::new(
                        json!({"proof_job_id":local.job_id,"inspect_original_encrypted_job":true}),
                    );
                    error
                })?
        } else {
            status
        };
        validate_summary(&candidate, &summary)?;
        upsert_link(&mut envelope, &summary).map_err(|error| checkpoint_exists(error, &summary))?;
        self.commit(
            &command,
            id,
            revision,
            envelope,
            if run {
                "candidate_proof_result_observed"
            } else {
                "candidate_proof_checkpoint_reconciled"
            },
        )
        .map_err(|error| checkpoint_exists(error, &summary))
    }
}

fn validate_provenance<'a>(
    envelope: &'a Envelope,
    access: &Access,
    summary: &JobSummary,
) -> Result<&'a candidates::CheckpointReceipt> {
    envelope.checkpoint_receipts.values().find(|r| r.job_id == summary.job_id && r.scope_digest == summary.scope_digest
                && r.principal_id == access.principal_id
        && r.candidate_id == summary.candidate_id && r.manifest_digest == summary.manifest_digest
        && r.coordination_request_digest == summary.coordination_request_digest
        && r.artifact_digest == summary.input_digest && r.review_binding == summary.review_binding
        && r.effects_commitment == summary.effects_commitment)
        .ok_or_else(|| ApiError::new("MISSING_EVIDENCE", "This job has no matching engine-origin exact constructor receipt; a supplied manifest digest cannot establish provenance"))
}

fn upsert_link(envelope: &mut Envelope, summary: &JobSummary) -> Result<()> {
    let candidate = envelope
        .view
        .candidates
        .iter_mut()
        .find(|c| c.candidate_id == summary.candidate_id)
        .ok_or_else(not_found)?;
    if let Some(previous) = candidate
        .proof_jobs
        .iter_mut()
        .find(|j| j.job_id == summary.job_id)
    {
        if previous.input_digest != summary.input_digest
            || previous.review_binding != summary.review_binding
            || previous.coordination_request_digest != summary.coordination_request_digest
        {
            return Err(ApiError::new(
                "RECOVERY_REQUIRED",
                "Private checkpoint binding changed; preserve both journals",
            ));
        }
        *previous = public_summary(summary);
    } else {
        if candidate.proof_jobs.len() >= 8 {
            return Err(ApiError::new(
                "RESOURCE_EXHAUSTED",
                "At most eight local proof checkpoints can be linked per candidate",
            ));
        }
        candidate.proof_jobs.push(public_summary(summary));
    }
    Ok(())
}
fn validate_summary(candidate: &CandidateView, summary: &JobSummary) -> Result<()> {
    if summary.candidate_id != candidate.candidate_id
        || summary.manifest_digest != candidate.manifest_digest
        || !summary.encrypted_checkpoint_created
        || summary.chain_validated
        || summary.authorization_allowed
        || summary.distribution_allowed
    {
        return Err(ApiError::new(
            "RECOVERY_REQUIRED",
            "Encrypted proof checkpoint scope is incompatible with the immutable candidate",
        ));
    }
    Ok(())
}
fn public_summary(s: &JobSummary) -> CandidateProofJob {
    CandidateProofJob {
        job_id: s.job_id.clone(),
        scope_digest: s.scope_digest.clone(),
        candidate_id: s.candidate_id.clone(),
        manifest_digest: s.manifest_digest.clone(),
        coordination_request_digest: s.coordination_request_digest.clone(),
        state: serde_json::to_value(s.state)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_else(|| "unknown".into()),
        attempt: s.attempt,
        input_digest: s.input_digest.clone(),
        result_digest: s.result_digest.clone(),
        effects_commitment: s.effects_commitment.clone(),
        review_binding: s.review_binding.clone(),
        encrypted_checkpoint_created: s.encrypted_checkpoint_created,
        proof_verified: s.proof_verified,
        chain_validated: false,
        authorization_allowed: false,
        distribution_allowed: false,
        observed_at: now(),
        observation_source: "independent_encrypted_local_proof_journal".into(),
    }
}
fn checkpoint_exists(mut error: ApiError, summary: &JobSummary) -> ApiError {
    error.details = Box::new(
        json!({"proof_job_id":summary.job_id,"encrypted_checkpoint_created":true,"coordination_link_committed":false,"journals_are_atomic_together":false}),
    );
    error.safe_actions = vec!["Inspect the original encrypted checkpoint before retrying".into(), "Retry the exact original command; if its coordination revision changed, reconcile the existing job with the current revision".into()];
    error
}
fn job_error(error: JobError) -> ApiError {
    let (code, message) = match error {
        JobError::ConsentDenied => ("DISCLOSURE_DENIED", "Authenticated local permission for this exact checkpoint action is missing or revoked"),
        JobError::NotFound => ("NOT_FOUND", "The encrypted proof job was not found in this principal's scope"),
        JobError::IdempotencyConflict => ("IDEMPOTENCY_CONFLICT", "The original encrypted checkpoint key is bound to a different exact request"),
        JobError::RecoveryRequired => ("RECOVERY_REQUIRED", "The original proof worker has an uncertain state; explicit verified recovery is required before another attempt"),
        JobError::StateConflict => ("REVISION_CONFLICT", "The proof job state or attempt changed; inspect its current encrypted journal status"),
        JobError::ResourceExhausted => ("RESOURCE_EXHAUSTED", "The bounded local proof queue or artifact limit was reached"),
        JobError::InvalidRequest => ("INVALID_REQUEST", "The local encrypted checkpoint request is invalid or unsupported"),
        JobError::VerificationFailed => ("CANDIDATE_VERIFICATION_FAILED", "The saved candidate or proof failed exact local verification"),
        JobError::Storage | JobError::UnsupportedSchema => ("RECOVERY_REQUIRED", "The original encrypted proof journal cannot be safely read; preserve it and do not reconstruct a replacement artifact"),
    };
    ApiError::new(code, message)
}
