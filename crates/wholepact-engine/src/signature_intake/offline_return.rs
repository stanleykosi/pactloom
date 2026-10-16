//! Staged private composition for offline-origin returns. It creates neither an
//! ordinary AuthenticatedAccountAssociation nor an online authorization permit.
//! The retained-original producer and qualified offline issuer remain absent.
use super::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use wholepact_transport::{
    EncryptedEnvelope, OfflineReturnData, OfflineReturnInboxReceipt, RetainedOfflineReturnOriginal,
    SqliteReplayLedger, TransportError, TransportPublicKey, TransportSecret,
    accept_offline_return_checked,
};

/// Verified signature evidence plus its exact encrypted transport receipt.
/// No Clone, Deserialize, signed-byte getter or conversion into online origin.
pub(crate) struct InspectedOfflineReturn {
    receipt: OfflineReturnInboxReceipt,
    signatures: SignatureInspection,
}
impl InspectedOfflineReturn {
    pub(crate) fn envelope_digest(&self) -> &str {
        self.receipt.envelope_digest()
    }
    pub(crate) fn inspection(&self) -> &SignatureInspection {
        &self.signatures
    }
}

fn reject() -> ApiError {
    ApiError::new(
        "OFFLINE_RETURN_REJECTED",
        "Offline return does not match its authenticated original, exact admitted effects and owned signature actions",
    )
}

impl Engine {
    /// Read-only financial inspection plus durable ciphertext replay receipt.
    /// Not signed-result retention, extraction or dispatch. No runtime command
    /// calls this, and its retained-original capability has no available factory.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn inspect_offline_return(
        &self,
        access: &Access,
        candidate_id: &str,
        local: LocalProofJob<'_>,
        original: &RetainedOfflineReturnOriginal,
        envelope: &EncryptedEnvelope,
        recipient: &TransportSecret,
        sender: &TransportPublicKey,
        now: &Timestamp,
        inbox: &mut SqliteReplayLedger,
    ) -> Result<InspectedOfflineReturn> {
        let (view, candidate) = self.candidate(access, candidate_id)?;
        self.require_current_agreement(&view.agreement.agreement_id)?;
        let proposal = candidate.verified_snapshot()?;
        let t = original.terms();
        if proposal.proposal_digest() != t.proposal_digest
            || proposal.manifest_digest() != t.manifest_digest
            || proposal.input().proposal_id != t.proposal_id
            || proposal.manifest().agreement.agreement_id != t.agreement_id
            || proposal.manifest().agreement.obligation_id != t.obligation_id
            || u64::from(proposal.manifest().agreement.revision) != t.proposal_revision
            || proposal.manifest().agreement.network_profile_id != t.network_profile_id
        {
            return Err(reject());
        }
        let read_consent = local.consent;
        let checkpoint = self.load_candidate_proof_for_local_review(access, candidate_id, local)?;
        let (receipt, signatures) = accept_offline_return_checked(
            envelope,
            recipient,
            sender,
            original,
            now,
            inbox,
            |data| {
                let read_current = || {
                    read_consent.permits(
                        checkpoint.scope(),
                        wholepact_proof_jobs::LocalAction::ReadPrivateArtifact,
                    )
                };
                if !read_current() {
                    return Err(TransportError::AuthorityUnavailable);
                }
                let checked = inspect_exact(&checkpoint, original, data)
                    .map_err(|_| TransportError::Authentication)?;
                if !read_current() {
                    return Err(TransportError::AuthorityUnavailable);
                }
                Ok(checked)
            },
        )
        .map_err(|_| reject())?;
        Ok(InspectedOfflineReturn {
            receipt,
            signatures,
        })
    }
}

fn inspect_exact(
    checkpoint: &VerifiedCheckpoint,
    original: &RetainedOfflineReturnOriginal,
    data: &OfflineReturnData,
) -> Result<SignatureInspection> {
    let t = original.terms();
    let scope = checkpoint.scope();
    // A reviewed redacted PCZT and its original online proof have different
    // artifact digests. The absent genuine producer must pin their exact mapping;
    // actual review below still checks equality of effects and economic binding.
    if scope.candidate_id != t.proposal_id
        || scope.manifest_digest != t.manifest_digest
        || scope.review_binding != t.review_binding
        || checkpoint.summary().result_digest.as_deref()
            != Some(original.online_proved_artifact_digest())
        || hex::encode(Sha256::digest(checkpoint.pczt_bytes()))
            != original.online_proved_artifact_digest()
        || data.account_id() != t.account_id
        || data.effects_digest() != t.effects_digest
    {
        return Err(reject());
    }
    let policy = checkpoint.policy();
    let owner = policy
        .participants
        .iter()
        .position(|p| {
            p.account_id == t.account_id
                && hex::encode(Sha256::digest(p.fvk.to_bytes())) == original.account_fvk_digest()
        })
        .ok_or_else(reject)?;
    let reviewed = wholepact_protocol::review::verify_review(checkpoint.pczt_bytes(), policy)
        .map_err(|_| reject())?;
    let expected_debit = policy.participants[owner]
        .contribution_zatoshis
        .checked_add(policy.participants[owner].fee_share_zatoshis)
        .ok_or_else(reject)?;
    if reviewed.review_binding() != t.review_binding
        || reviewed.shielded_sighash() != t.effects_digest
        || reviewed.fee_zatoshis() != t.transaction_fee_zatoshis
        || policy.expiry_height != t.transaction_expiry_height
        || policy.participants[owner].fee_share_zatoshis != t.fee_share_zatoshis
        || policy.participants[owner].maximum_net_debit_zatoshis != t.maximum_debit_zatoshis
        || reviewed.net_debits_zatoshis().get(owner) != Some(&expected_debit)
        || expected_debit > t.maximum_debit_zatoshis
        || hex::encode(policy.anchor) != t.snapshot.anchor_root
    {
        return Err(reject());
    }
    let actual_inputs: BTreeSet<_> = policy
        .inputs
        .iter()
        .filter(|i| i.participant_index == owner)
        .map(|i| {
            (
                i.action_index as u64,
                hex::encode(i.nullifier),
                i.value_zatoshis,
            )
        })
        .collect();
    let admitted_inputs: BTreeSet<_> = t
        .inputs
        .iter()
        .map(|i| (i.action_index, i.nullifier.clone(), i.value_zatoshis))
        .collect();
    if actual_inputs != admitted_inputs || actual_inputs.len() != t.inputs.len() {
        return Err(reject());
    }
    let mut signatures = Vec::new();
    for (index, encoded) in data.signatures() {
        let action_index = usize::try_from(index).map_err(|_| reject())?;
        let mut signature = [0_u8; 64];
        hex::decode_to_slice(encoded, &mut signature).map_err(|_| reject())?;
        signatures.push(ExternalSignature {
            participant_index: owner,
            action_index,
            signature,
        });
    }
    if signatures.len() != actual_inputs.len() {
        return Err(reject());
    }
    // Maintained implementation rechecks actual proof and unsigned real inputs,
    // verifies each signature with the exact rk/sighash, and compares the entire
    // normalized candidate with the original after removing only those signatures.
    // A single participant's valid return need not complete all required signatures.
    let result = wholepact_protocol::authorization::inspect_external_signatures(
        checkpoint.pczt_bytes(),
        policy,
        &t.review_binding,
        &signatures,
        wholepact_protocol::proving::ProvingLimits { maximum_actions: 8 },
    )
    .map_err(|_| reject());
    for signature in &mut signatures {
        signature.signature.fill(0);
    }
    result
}

/// A current provider observation can reject stale/expired returns at eventual
/// dispatch, but cannot supply original authority, current input spendability,
/// independent consensus, or revocation evidence. Not called by historical import.
#[cfg(feature = "submission-handoff")]
pub(crate) fn check_current_return_chain_context(
    original: &RetainedOfflineReturnOriginal,
    context: &wholepact_chain::ChainContext,
    backend: &wholepact_chain::BackendIdentity,
    now_unix_seconds: u64,
    minimum_expiry_margin_blocks: u32,
) -> Result<()> {
    let t = original.terms();
    if !(1..=100).contains(&minimum_expiry_margin_blocks)
        || context.source() != backend
        || t.consensus_branch_id != wholepact_chain::NU7_BRANCH_ID
        || t.network_profile_id != crate::candidates::PROFILE_ID
        || context.tip().height < wholepact_chain::NU7_ACTIVATION_HEIGHT
        || context
            .tip()
            .height
            .checked_add(u64::from(minimum_expiry_margin_blocks))
            .is_none_or(|height| height > u64::from(t.transaction_expiry_height))
    {
        return Err(reject());
    }
    context
        .check_fresh_at(now_unix_seconds)
        .map_err(|_| reject())
}

/// Intentional barrier. No online AuthenticatedPermit/OriginalHistoryLease or
/// ordinary DispatchAdmission may be fabricated from offline history/return.
pub(crate) fn offline_return_dispatch_unavailability() -> ApiError {
    ApiError::new(
        "OFFLINE_DISPATCH_AUTHORITY_UNAVAILABLE",
        "Exact offline-origin witness dispatch, current input and source validation, original native result provenance and final-transaction linkage are not composed; preserve the returned authorization and exposure",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn returned_evidence_never_creates_dispatch_authority() {
        assert_eq!(
            offline_return_dispatch_unavailability().code,
            "OFFLINE_DISPATCH_AUTHORITY_UNAVAILABLE"
        );
    }
}
