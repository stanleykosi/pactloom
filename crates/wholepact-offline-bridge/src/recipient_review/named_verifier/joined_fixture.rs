//! Opt-in synthetic integration support only. Returns untrusted package bytes,
//! never an owner, retained-input wrapper, approval, reservation or permission.
//! Caller keys are ephemeral fixture signing keys, not production credentials.
use super::*;
use ring::signature::{Ed25519KeyPair, KeyPair};

/// Exercise the maintained private assertion producer against a genuinely proved
/// fabricated-note candidate whose full policy uses the fresh fixture vault FVK.
/// All supplied data remains untrusted and the producer reruns exact manifest,
/// economic and cryptographic proof verification before signing any statement.
#[allow(clippy::too_many_arguments)]
pub fn synthetic_joined_named_package(
    proved: &[u8],
    terms: OfflineAuthorizationTerms,
    proposal: Proposal,
    policy: ReviewPolicy,
    input_actions: Vec<InputActionMapping>,
    output_actions: Vec<OutputActionMapping>,
    request_digest: String,
    validity_not_before_ms: u64,
    validity_expires_ms: u64,
    pair: &Ed25519KeyPair,
) -> Result<Vec<u8>> {
    let original_context_digest = named_verifier_original_context_digest(&terms)?;
    let retained = RetainedOfflineReviewInputs {
        terms,
        proposal,
        policy,
        input_actions,
        output_actions,
        maximum_actions: 8,
    };
    let request = OriginalNamedVerifierRequest {
        request_digest,
        original_context_digest,
        validity_not_before_ms,
        validity_expires_ms,
    };
    let key: [u8; 32] = pair
        .public_key()
        .as_ref()
        .try_into()
        .map_err(|_| TransportError::Authentication)?;
    let prepared = prepare_named_verifier_assertion(proved, &retained, &request, &key)?;
    let signature = pair.sign(&prepared.signing_message()?);
    crate::NamedVerifierPackageV1 {
        schema_version: 1,
        statement: prepared.statement().clone(),
        signature: signature.as_ref().to_vec(),
        recipient_artifact: prepared.recipient_artifact().bytes().to_vec(),
    }
    .canonical_bytes()
}
