//! Exact reload and union of previously retained signature subsets.
//!
//! References are data, never authenticated intake receipts or spending grants.
//! The engine must resolve them through its immutable original account/intake
//! history before calling this primitive. A generic retained row does not prove
//! that an application authenticated its sender. Every saved subset is reverified
//! against the original complete policy and proof; no saved verification flag,
//! expired IPC permission, new signature, or reconstructed capability is used.

use super::*;
#[cfg(feature = "submission-handoff")]
mod submission_verification_v1;
use serde::Deserialize;
use std::collections::BTreeSet;
use zeroize::Zeroize;

/// Data-only locator for a completed immutable signed result. Deserializing this
/// value establishes no account attribution, authority, freshness, or consent.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedIntakeRefV1 {
    pub result_id: String,
    pub request_digest: String,
    pub signed_candidate_digest: String,
    pub delivery_provenance_digest: String,
}

/// Canonical source-set commitment. Order is immaterial; duplicate result IDs,
/// including differently claimed digests for the same ID, are rejected.
pub fn retained_source_set_digest_v1(sources: &[RetainedIntakeRefV1]) -> Result<String> {
    if sources.is_empty() || sources.len() > MAX_RESULTS as usize {
        return Err(RetentionError::InvalidRequest);
    }
    let mut sorted: Vec<_> = sources.iter().collect();
    sorted.sort_by(|a, b| a.result_id.cmp(&b.result_id));
    for source in &sorted {
        if !source.result_id.strip_prefix("signed-").is_some_and(digest)
            || !digest(&source.request_digest)
            || !digest(&source.signed_candidate_digest)
            || !digest(&source.delivery_provenance_digest)
        {
            return Err(RetentionError::InvalidRequest);
        }
    }
    if sorted.windows(2).any(|pair| pair[0].result_id == pair[1].result_id) {
        return Err(RetentionError::InvalidRequest);
    }
    let bytes = serde_json::to_vec(&sorted).map_err(|_| RetentionError::InvalidRequest)?;
    Ok(framed(&[b"durable-intake-source-set-v1", &bytes]))
}

// Sensitive arrays remain private and are cleared on all ordinary return paths.
// This is memory hygiene, not a claim about copies, swap, crashes, or secure erase.
struct RetainedSignatures(Vec<ExternalSignature>);
impl Drop for RetainedSignatures {
    fn drop(&mut self) {
        for signature in &mut self.0 {
            signature.signature.zeroize();
        }
    }
}

/// Sealed by this journal's exact completed rows and current full verification.
/// No public constructor, serialization, clone, or raw signature/byte accessor.
/// This borrows the original journal and consent, not a restored signing grant.
pub struct VerifiedRetainedUnionV1<'a> {
    journal: &'a SignedResultJournal,
    context: SignedCandidateContext,
    base: &'a [u8],
    policy: &'a ReviewPolicy,
    signatures: RetainedSignatures,
    limits: ProvingLimits,
    consent: &'a dyn SignedRetentionConsent,
    source_scopes: Vec<SignedRetentionScope>,
    inspection: SignatureInspection,
}

struct UnionConsent<'a> {
    original: &'a dyn SignedRetentionConsent,
    sources: &'a [SignedRetentionScope],
}
impl SignedRetentionConsent for UnionConsent<'_> {
    fn permits(&self, scope: &SignedRetentionScope) -> bool {
        self.sources.iter().all(|source| self.original.permits(source))
            && self.original.permits(scope)
            && self.sources.iter().all(|source| self.original.permits(source))
    }
}

impl VerifiedRetainedUnionV1<'_> {
    pub fn context(&self) -> &SignedCandidateContext {
        &self.context
    }

    /// Evidence of this local verification only, never new release authority or
    /// chain inclusion. A partial union remains explicitly incomplete.
    pub fn inspection(&self) -> &SignatureInspection {
        &self.inspection
    }

    fn consent(&self) -> UnionConsent<'_> {
        UnionConsent { original: self.consent, sources: &self.source_scopes }
    }

    /// Retain a separate deterministic union. Original subset rows and exposure
    /// remain untouched. Exact replay reuses the same intent/result.
    pub fn retain(&self, idempotency_key: &str) -> Result<SignedResultSummary> {
        self.journal.retain(
            self.context.clone(), idempotency_key, self.base, self.policy,
            &self.signatures.0, self.limits, &self.consent(),
        )
    }

    /// Read-only verification of an already completed original union. Missing
    /// intent/result is refused; unlike retain/reconcile this performs no repair.
    pub fn verify_completed_existing(&self, idempotency_key: &str) -> Result<SignedResultSummary> {
        self.journal.verify_completed_existing(
            self.context.clone(), idempotency_key, self.base, self.policy,
            &self.signatures.0, self.limits, &self.consent(),
        )
    }

    /// Requires the union to have been retained first. Existing randomized
    /// extraction fencing is unchanged; missing originals are not regenerated.
    #[cfg(feature = "transaction-checkpoint")]
    pub fn checkpoint_transaction(
        &self,
        idempotency_key: &str,
        local: super::transaction::LocalTransactionCheckpoint<'_>,
    ) -> Result<super::transaction::TransactionCheckpointSummary> {
        self.journal.checkpoint_transaction(
            self.context.clone(), idempotency_key, self.base, self.policy,
            &self.signatures.0, self.limits, &self.consent(), local,
        )
    }

    /// Exact completed union only; no missing signed-result repair.
    #[cfg(feature = "transaction-checkpoint")]
    pub fn checkpoint_completed_transaction(
        &self,
        idempotency_key: &str,
        local: super::transaction::LocalTransactionCheckpoint<'_>,
    ) -> Result<super::transaction::TransactionCheckpointSummary> {
        self.journal.checkpoint_completed_transaction(
            self.context.clone(), idempotency_key, self.base, self.policy,
            &self.signatures.0, self.limits, &self.consent(), local,
        )
    }

    #[cfg(feature = "transaction-checkpoint")]
    pub fn recover_transaction_checkpoint(
        &self,
        idempotency_key: &str,
        local: super::transaction::LocalTransactionRecovery<'_>,
    ) -> Result<super::transaction::TransactionRecoverySummary> {
        self.journal.recover_transaction_checkpoint(
            self.context.clone(), idempotency_key, self.base, self.policy,
            &self.signatures.0, self.limits, &self.consent(), local,
        )
    }

    /// Existing dedicated handoff authority is still required. Privacy consent
    /// and possession of the union do not authorize copying or submission.
    #[cfg(feature = "submission-handoff")]
    pub fn retain_transaction_for_submission<
        A: wholepact_chain::SubmissionAuthority,
        C: wholepact_chain::SubmissionClock,
    >(
        &self,
        signature_key: &str,
        obligation_id: &str,
        proposal_id: &str,
        submission_operation_id: &str,
        local: super::transaction::submission_handoff::LocalSubmissionHandoff<'_, A, C>,
    ) -> std::result::Result<
        wholepact_chain::SubmissionDescriptor,
        super::transaction::submission_handoff::SubmissionHandoffError,
    > {
        self.journal.retain_transaction_for_submission(
            self.context.clone(), signature_key, self.base, self.policy,
            &self.signatures.0, self.limits, &self.consent(), obligation_id,
            proposal_id, submission_operation_id, local,
        )
    }

    /// An explicit existing-operation dispatch only. The original dispatcher
    /// retains unknown outcomes and holds its separate authority through await.
    #[cfg(feature = "submission-handoff")]
    pub async fn dispatch_retained_transaction<
        A: wholepact_chain::SubmissionAuthority,
        B: wholepact_chain::SubmissionBackend,
        C: wholepact_chain::SubmissionClock,
    >(
        &self,
        signature_key: &str,
        obligation_id: &str,
        proposal_id: &str,
        submission_operation_id: &str,
        local: super::transaction::submission_handoff::LocalSubmissionDispatch<'_, A, B, C>,
    ) -> std::result::Result<
        wholepact_chain::SubmissionDispatchReport,
        super::transaction::submission_handoff::SubmissionHandoffError,
    > {
        let consent = self.consent();
        self.journal.dispatch_retained_transaction(
            self.context.clone(), signature_key, self.base, self.policy,
            &self.signatures.0, self.limits, &consent, obligation_id,
            proposal_id, submission_operation_id, local,
        ).await
    }
}

impl SignedResultJournal {
    /// Reload only completed original subsets. The trusted engine must first
    /// authenticate each locator against its own durable original intake record
    /// and acquire fresh exact proof-read and signature-retention consent. That
    /// engine gate must remain held while this borrowed handle is used.
    ///
    /// Every saved subset and the union pass the complete maintained verifier.
    /// Original envelope/IPC expiry is intentionally not refreshed or consulted:
    /// these are already released signatures, not permission to produce more.
    #[allow(clippy::too_many_arguments)]
    pub fn load_verified_union<'a>(
        &'a self,
        context: SignedCandidateContext,
        sources: &[RetainedIntakeRefV1],
        base: &'a [u8],
        policy: &'a ReviewPolicy,
        limits: ProvingLimits,
        consent: &'a dyn SignedRetentionConsent,
    ) -> Result<VerifiedRetainedUnionV1<'a>> {
        validate(&context)?;
        if context.delivery_provenance_digest != retained_source_set_digest_v1(sources)?
            || base.len() > MAX_BYTES
            || hash(base) != context.proved_artifact_digest
            || hex::encode(policy.manifest_digest) != context.manifest_digest
            || !(1..=crate::proving::MAX_PROVING_ACTIONS).contains(&limits.maximum_actions)
            || policy.participants.iter().map(|p| p.account_id.as_str()).collect::<BTreeSet<_>>()
                != context.account_ids.iter().map(String::as_str).collect()
        {
            return Err(RetentionError::InvalidRequest);
        }
        let mut signatures = RetainedSignatures(Vec::new());
        let mut source_scopes = Vec::with_capacity(sources.len());
        let mut actions = BTreeSet::new();
        let mut sorted: Vec<_> = sources.iter().collect();
        sorted.sort_by(|a, b| a.result_id.cmp(&b.result_id));
        for source in sorted {
            let (scope, saved) = self.load_verified_subset(
                &context, source, base, policy, limits, consent,
            )?;
            for signature in &saved.0 {
                // Even byte-identical overlapping signatures are refused. A
                // repeated request must reuse its original source set, not add
                // another receipt for the same action and change provenance.
                if !actions.insert(signature.action_index) || signatures.0.len() >= 64 {
                    return Err(RetentionError::InvalidRequest);
                }
                signatures.0.push(ExternalSignature {
                    participant_index: signature.participant_index,
                    action_index: signature.action_index,
                    signature: signature.signature,
                });
            }
            source_scopes.push(scope);
        }
        let scope = SignedRetentionScope {
            context: context.clone(),
            signature_set_digest: hash(&encode_signatures(&signatures.0)?),
        };
        let current = UnionConsent { original: consent, sources: &source_scopes };
        gate(&current, &scope)?;
        let (inspection, bytes) = assemble_external_signatures(
            base, policy, &context.review_binding, &signatures.0, limits,
        ).map_err(|_| RetentionError::VerificationFailed)?;
        let _bytes = Zeroizing::new(bytes);
        gate(&current, &scope)?;
        Ok(VerifiedRetainedUnionV1 {
            journal: self, context, base, policy, signatures, limits, consent,
            source_scopes, inspection,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn load_verified_subset(
        &self,
        target: &SignedCandidateContext,
        reference: &RetainedIntakeRefV1,
        base: &[u8],
        policy: &ReviewPolicy,
        limits: ProvingLimits,
        consent: &dyn SignedRetentionConsent,
    ) -> Result<(SignedRetentionScope, RetainedSignatures)> {
        // Read the small original scope first; consent precedes loading usable
        // signatures or signed bytes. All subsequent row reads share one lock.
        let (scope, encoded, saved, saved_digest) = {
            let c = self.connection.lock().map_err(|_| RetentionError::Storage)?;
            let row: Option<(String, String, String, Vec<u8>)> = c.query_row(
                "SELECT principal_id,idem_key,request_digest,scope FROM signed_intents WHERE result_id=?1 AND length(scope)<=16384",
                [&reference.result_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            ).optional().map_err(db)?;
            let (principal, idem, request, encoded_scope) = row.ok_or(RetentionError::IntentNotFound)?;
            let encoded_scope = Zeroizing::new(encoded_scope);
            let scope = decode_scope(&encoded_scope)?;
            let mut expected = target.clone();
            expected.delivery_provenance_digest = reference.delivery_provenance_digest.clone();
            if serde_json::to_vec(&scope.context).map_err(|_| RetentionError::InvalidRequest)?
                != serde_json::to_vec(&expected).map_err(|_| RetentionError::InvalidRequest)?
                || principal != target.principal_id
                || !(16..=128).contains(&idem.len())
                || !idem.bytes().all(|b| (33..=126).contains(&b))
                || reference.result_id != format!("signed-{}", framed(&[principal.as_bytes(), idem.as_bytes()]))
                || request != reference.request_digest
            {
                return Err(RetentionError::VerificationFailed);
            }
            gate(consent, &scope)?;
            let row: Option<(Vec<u8>, Vec<u8>, String)> = c.query_row(
                "SELECT i.signatures,r.bytes,r.digest FROM signed_intents i JOIN signed_results r ON r.result_id=i.result_id WHERE i.result_id=?1 AND length(i.signatures)<=10240 AND length(r.bytes)<=1048576",
                [&reference.result_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            ).optional().map_err(db)?;
            let (encoded, saved, saved_digest) = row.ok_or(RetentionError::RecoveryRequired)?;
            let encoded = Zeroizing::new(encoded);
            let saved = Zeroizing::new(saved);
            if request != framed(&[&encoded_scope, &encoded, &(limits.maximum_actions as u64).to_le_bytes()])
                || scope.signature_set_digest != hash(&encoded)
                || saved_digest != reference.signed_candidate_digest
                || saved_digest != hash(&saved)
            {
                return Err(RetentionError::VerificationFailed);
            }
            gate(consent, &scope)?;
            (scope, encoded, saved, saved_digest)
        };
        let signatures = decode_signatures(&encoded)?;
        let (_, reassembled) = assemble_external_signatures(
            base, policy, &scope.context.review_binding, &signatures.0, limits,
        ).map_err(|_| RetentionError::VerificationFailed)?;
        let reassembled = Zeroizing::new(reassembled);
        if *reassembled != *saved || hash(&reassembled) != saved_digest {
            return Err(RetentionError::VerificationFailed);
        }
        gate(consent, &scope)?;
        Ok((scope, signatures))
    }
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn decode_signatures(bytes: &[u8]) -> Result<RetainedSignatures> {
    if bytes.is_empty() || bytes.len() % 80 != 0 || bytes.len() / 80 > 64 {
        return Err(RetentionError::VerificationFailed);
    }
    let mut signatures = RetainedSignatures(Vec::with_capacity(bytes.len() / 80));
    for record in bytes.chunks_exact(80) {
        let participant_index = usize::try_from(u64::from_le_bytes(
            record[..8].try_into().map_err(|_| RetentionError::VerificationFailed)?,
        )).map_err(|_| RetentionError::VerificationFailed)?;
        let action_index = usize::try_from(u64::from_le_bytes(
            record[8..16].try_into().map_err(|_| RetentionError::VerificationFailed)?,
        )).map_err(|_| RetentionError::VerificationFailed)?;
        signatures.0.push(ExternalSignature {
            participant_index, action_index,
            signature: record[16..].try_into().map_err(|_| RetentionError::VerificationFailed)?,
        });
    }
    if encode_signatures(&signatures.0)?.as_slice() != bytes {
        return Err(RetentionError::VerificationFailed);
    }
    Ok(signatures)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedScopeV1 {
    context: SavedContextV1,
    signature_set_digest: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedContextV1 {
    principal_id: String,
    candidate_id: String,
    proof_job_id: String,
    checkpoint_scope_digest: String,
    proved_artifact_digest: String,
    manifest_digest: String,
    review_binding: String,
    delivery_provenance_digest: String,
    account_ids: Vec<String>,
    local_operator: String,
    purpose: String,
    retention_policy: String,
}

fn decode_scope(bytes: &[u8]) -> Result<SignedRetentionScope> {
    let saved: SavedScopeV1 = serde_json::from_slice(bytes)
        .map_err(|_| RetentionError::VerificationFailed)?;
    let c = saved.context;
    let scope = SignedRetentionScope {
        context: SignedCandidateContext {
            principal_id: c.principal_id, candidate_id: c.candidate_id,
            proof_job_id: c.proof_job_id, checkpoint_scope_digest: c.checkpoint_scope_digest,
            proved_artifact_digest: c.proved_artifact_digest, manifest_digest: c.manifest_digest,
            review_binding: c.review_binding, delivery_provenance_digest: c.delivery_provenance_digest,
            account_ids: c.account_ids, local_operator: c.local_operator,
            purpose: c.purpose, retention_policy: c.retention_policy,
        },
        signature_set_digest: saved.signature_set_digest,
    };
    validate(&scope.context)?;
    if !digest(&scope.signature_set_digest)
        || serde_json::to_vec(&scope).map_err(|_| RetentionError::VerificationFailed)? != bytes
    {
        return Err(RetentionError::VerificationFailed);
    }
    Ok(scope)
}

#[cfg(all(test, target_os = "linux", feature = "synthetic-qualification"))]
mod tests;
