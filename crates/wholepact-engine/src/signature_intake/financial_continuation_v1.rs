//! Concrete direct original-result adapter. No fabricated relay envelope or
//! caller-owned account association can construct this source.
use super::*;
use wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1;
use wholepact_signer::authority_bridge::financial_continuation_v1::AuthenticatedFinancialResultEvidenceV2;

pub(crate) fn retention_inputs(
    checkpoint: &VerifiedCheckpoint,
    fixed: &FixedProposalIdentityV1,
    actual: &impl AuthenticatedFinancialResultEvidenceV2,
) -> Result<(SignedCandidateContext, Vec<ExternalSignature>)> {
    use sha2::{Digest, Sha256};
    actual.check_current().map_err(|_| association_missing())?;
    if actual.fixed_identity() != fixed {
        return Err(rejected());
    }
    let scope = checkpoint.scope();
    let record = actual.continuation_record();
    let auth = &record.terms.scope.authorization;
    record
        .validate_request(actual.continuation_request(), &record.terms.scope.witness)
        .map_err(|_| rejected())?;
    if actual.account_id() != auth.identity.account_id
        || actual.authorization_id() != auth.authorization_id
        || serde_json::to_value(&auth.fixed).map_err(|_| rejected())?
            != serde_json::to_value(fixed).map_err(|_| rejected())?
    {
        return Err(rejected());
    }
    let bytes = actual.outbox_bytes().map_err(|_| association_missing())?;
    if bytes.len() > 1024 * 1024 || hex::encode(Sha256::digest(bytes)) != actual.outbox_digest() {
        return Err(rejected());
    }
    let payload: SignaturePayload =
        wholepact_core::strict_json::parse_typed_json(bytes).map_err(|_| rejected())?;
    if payload.schema_version != 1
        || payload.candidate_id != scope.candidate_id
        || payload.manifest_digest != scope.manifest_digest
        || Some(payload.proved_artifact_digest.as_str())
            != checkpoint.summary().result_digest.as_deref()
        || payload.review_binding != scope.review_binding
        || payload.account_id != actual.account_id()
        || payload.signatures.is_empty()
        || payload.signatures.len() > 64
    {
        return Err(rejected());
    }
    let participant_index = checkpoint
        .policy()
        .participants
        .iter()
        .position(|p| {
            p.account_id == actual.account_id()
                && hex::encode(Sha256::digest(p.fvk.to_bytes()))
                    == auth.identity.full_viewing_key_digest
        })
        .ok_or_else(rejected)?;
    let mut signatures = Vec::with_capacity(payload.signatures.len());
    for record in payload.signatures {
        if record.signature_hex.len() != 128
            || record
                .signature_hex
                .bytes()
                .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
        {
            return Err(rejected());
        }
        signatures.push(ExternalSignature {
            participant_index,
            action_index: record.action_index,
            signature: hex::decode(record.signature_hex)
                .map_err(|_| rejected())?
                .try_into()
                .map_err(|_| rejected())?,
        });
    }
    let provenance = wholepact_core::proposal::canonical_digest(
        "wholepact:original-financial-result-source:v1",
        &(
            actual.account_id(),
            actual.authorization_id(),
            actual.original_consent_ref(),
            actual.result_digest(),
            actual.outbox_digest(),
            actual.continuation_request(),
            actual.fixed_identity(),
        ),
    )
    .map_err(|_| rejected())?;
    actual.check_current().map_err(|_| association_missing())?;
    Ok((
        SignedCandidateContext {
            principal_id: scope.principal_id.clone(),
            candidate_id: scope.candidate_id.clone(),
            proof_job_id: checkpoint.summary().job_id.clone(),
            checkpoint_scope_digest: checkpoint.summary().scope_digest.clone(),
            proved_artifact_digest: checkpoint
                .summary()
                .result_digest
                .clone()
                .ok_or_else(rejected)?,
            manifest_digest: scope.manifest_digest.clone(),
            review_binding: scope.review_binding.clone(),
            delivery_provenance_digest: provenance,
            account_ids: scope.account_ids.clone(),
            local_operator: scope.local_operator.clone(),
            purpose: scope.purpose.clone(),
            retention_policy: scope.retention_policy.clone(),
        },
        signatures,
    ))
}

/// Exact inert metadata observed from the actual original Signer before its
/// short Return lease. This does not permit reading or retaining signatures.
pub(crate) fn preview_retention_scope(
    checkpoint: &VerifiedCheckpoint,
    fixed: &FixedProposalIdentityV1,
    preview: &wholepact_signer::authority_bridge::financial_continuation_v1::AuthenticatedFinancialResultPreviewV1,
) -> Result<wholepact_protocol::authorization::retention::SignedRetentionScope> {
    use sha2::{Digest, Sha256};
    let record = preview.continuation_record();
    let auth = &record.terms.scope.authorization;
    record
        .validate_request(preview.continuation_request(), &record.terms.scope.witness)
        .map_err(|_| rejected())?;
    let hash = |s: &str| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    if preview.fixed_identity() != fixed
        || preview.account_id() != auth.identity.account_id
        || preview.authorization_id() != auth.authorization_id
        || serde_json::to_value(&auth.fixed).map_err(|_| rejected())?
            != serde_json::to_value(fixed).map_err(|_| rejected())?
        || !hash(preview.signature_set_digest())
        || !hash(preview.result_digest())
        || !hash(preview.outbox_digest())
        || !checkpoint.policy().participants.iter().any(|p| {
            p.account_id == preview.account_id()
                && hex::encode(Sha256::digest(p.fvk.to_bytes()))
                    == auth.identity.full_viewing_key_digest
        })
    {
        return Err(rejected());
    }
    let provenance = wholepact_core::proposal::canonical_digest(
        "wholepact:original-financial-result-source:v1",
        &(
            preview.account_id(),
            preview.authorization_id(),
            preview.original_consent_ref(),
            preview.result_digest(),
            preview.outbox_digest(),
            preview.continuation_request(),
            preview.fixed_identity(),
        ),
    )
    .map_err(|_| rejected())?;
    let scope = checkpoint.scope();
    Ok(
        wholepact_protocol::authorization::retention::SignedRetentionScope {
            context: SignedCandidateContext {
                principal_id: scope.principal_id.clone(),
                candidate_id: scope.candidate_id.clone(),
                proof_job_id: checkpoint.summary().job_id.clone(),
                checkpoint_scope_digest: checkpoint.summary().scope_digest.clone(),
                proved_artifact_digest: checkpoint
                    .summary()
                    .result_digest
                    .clone()
                    .ok_or_else(rejected)?,
                manifest_digest: scope.manifest_digest.clone(),
                review_binding: scope.review_binding.clone(),
                delivery_provenance_digest: provenance,
                account_ids: scope.account_ids.clone(),
                local_operator: scope.local_operator.clone(),
                purpose: scope.purpose.clone(),
                retention_policy: scope.retention_policy.clone(),
            },
            signature_set_digest: preview.signature_set_digest().into(),
        },
    )
}
