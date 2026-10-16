//! Opaque transaction inspection shared by the protected checkpoint and native
//! window. It is deliberately not AcceptedManifest or HumanApprovedReview:
//! inspecting a persisted candidate does not authenticate the user or account.
use crate::{Error, Result};
use std::time::{Duration, Instant};
use wholepact_protocol::review::{verify_review, ReviewPolicy};
use zeroize::Zeroizing;

pub struct TransactionInspection {
    bytes: Zeroizing<Vec<u8>>,
    policy: ReviewPolicy,
    binding: String,
    protocol_binding: String,
    display: Zeroizing<String>,
    created: Instant,
}
impl TransactionInspection {
    pub(crate) fn from_prepared(
        bytes: Zeroizing<Vec<u8>>,
        policy: ReviewPolicy,
        binding: String,
        display: String,
        created: Instant,
        protocol_binding: String,
    ) -> Self {
        Self {
            bytes,
            policy,
            binding,
            protocol_binding,
            display: Zeroizing::new(inert_text(&display)),
            created,
        }
    }
    #[cfg(all(test, feature = "native-ui", feature = "synthetic-qualification"))]
    pub(crate) fn expire_for_test(&mut self) {
        self.created = Instant::now() - Duration::from_secs(121);
    }
    pub fn display(&self) -> &str {
        &self.display
    }
    pub fn binding(&self) -> &str {
        &self.binding
    }
    pub fn authorization_allowed(&self) -> bool {
        false
    }
    pub fn expired(&self) -> bool {
        self.created.elapsed() > Duration::from_secs(120)
    }
    pub fn recheck(&self) -> Result<()> {
        if self.expired() {
            return Err(Error::ReviewMismatch);
        }
        let verified = verify_review(&self.bytes, &self.policy).map_err(|_| Error::Verification)?;
        if verified.review_binding() != self.protocol_binding {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    /// Retains the exact independently reverified proof result. Current permission
    /// must cover ReadPrivateArtifact for the full immutable scope, including all
    /// accounts, operator, purpose and retention. No permission to export follows.
    #[cfg(feature = "checkpoint-review")]
    pub fn from_checkpoint(
        checkpoint: wholepact_proof_jobs::VerifiedCheckpoint,
        proposal: &wholepact_core::Proposal,
        account_id: &str,
        principal_id: &str,
        consent: &dyn wholepact_proof_jobs::LocalProofConsent,
    ) -> Result<Self> {
        use sha2::{Digest, Sha256};
        use wholepact_proof_jobs::{JobState, LocalAction};
        use wholepact_protocol::review::OutputPurpose;
        crate::review::validate_label(account_id)?;
        crate::review::validate_label(principal_id)?;
        let scope = checkpoint.scope();
        let summary = checkpoint.summary();
        if !consent.permits(scope, LocalAction::ReadPrivateArtifact)
            || scope.principal_id != principal_id
            || !scope.account_ids.iter().any(|id| id == account_id)
            || scope.manifest_digest != proposal.manifest_digest()
            || summary.manifest_digest != proposal.manifest_digest()
            || summary.state != JobState::Succeeded
            || !summary.proof_verified
            || summary.authorization_allowed
            || summary.distribution_allowed
        {
            return Err(Error::Verification);
        }
        let bytes = checkpoint.pczt_bytes();
        let digest = hex::encode(Sha256::digest(bytes));
        let policy = checkpoint.policy();
        let verified = verify_review(bytes, policy).map_err(|_| Error::Verification)?;
        if summary.result_digest.as_deref() != Some(digest.as_str())
            || summary.review_binding != verified.review_binding()
            || scope.review_binding != verified.review_binding()
            || summary.effects_commitment != verified.shielded_sighash()
            || scope.effects_commitment != verified.shielded_sighash()
            || hex::encode(policy.manifest_digest) != proposal.manifest_digest()
        {
            return Err(Error::ReviewMismatch);
        }
        let owner = policy
            .participants
            .iter()
            .position(|p| p.account_id == account_id)
            .ok_or(Error::Verification)?;
        let mut display = format!("PROTECTED CHECKPOINT INSPECTION; NO SPENDING AUTHORITY\nCandidate: {}\nJob: {}\nAccount scope: {account_id}\nLocal principal: {principal_id}\nNetwork: testnet NU7 / Ironwood\nOriginal artifact digest: {}\nRetained proved artifact digest: {digest}\nManifest digest: {}\nExact review binding: {}\nEffects digest: {}\nOwn net debit: {} zatoshis\nOwn fee share: {} zatoshis\nTransaction fee: {} zatoshis\nExpiry height: {}\n",
            scope.candidate_id, summary.job_id, summary.input_digest, proposal.manifest_digest(),
            verified.review_binding(), verified.shielded_sighash(), verified.net_debits_zatoshis()[owner],
            policy.participants[owner].fee_share_zatoshis, verified.fee_zatoshis(), policy.expiry_height);
        for output in &policy.outputs {
            let purpose = match output.purpose {
                OutputPurpose::Recipient => "Recipient".to_owned(),
                OutputPurpose::Return { participant_index } if participant_index == owner => {
                    "Verified account return".into()
                }
                OutputPurpose::Return { participant_index } => {
                    format!("Other account return {participant_index}")
                }
            };
            display.push_str(&format!(
                "{purpose}: {} zatoshis to receiver {}\nMemo bytes: {}\n",
                output.value_zatoshis,
                hex::encode(output.receiver.to_raw_address_bytes()),
                hex::encode(output.memo)
            ));
        }
        display.push_str(&format!("Local operator: {}\nPurpose: {}\nRetention: {}\nAccount roster: {}\nBroad private fields: FVK, notes, values, witnesses, outputs and memos. Viewing authority can reveal future activity and cannot be revoked.\n", scope.local_operator, scope.purpose, scope.retention_policy, scope.account_ids.join(", ")));
        display.push_str("Bound application manifest (application claims, not authenticated account identities or trusted human consent):\n");
        display.push_str(
            &serde_json::to_string_pretty(proposal.input()).map_err(|_| Error::InvalidData)?,
        );
        display.push_str("\nProof and economic verification do not prove trusted launch, wallet freshness, unspentness, account association or human disclosure approval. This inspection cannot release signatures.\n");
        let mut hash = Sha256::new();
        hash.update(b"wholepact:protected-checkpoint-inspection:v1\0");
        hash.update(crate::vault::random::<32>()?);
        for field in [
            digest.as_str(),
            proposal.proposal_digest(),
            account_id,
            principal_id,
            summary.scope_digest.as_str(),
        ] {
            hash.update((field.len() as u64).to_le_bytes());
            hash.update(field.as_bytes());
        }
        if !consent.permits(scope, LocalAction::ReadPrivateArtifact) {
            return Err(Error::Verification);
        }
        Ok(Self {
            bytes: Zeroizing::new(bytes.to_vec()),
            policy: policy.clone(),
            binding: hex::encode(hash.finalize()),
            protocol_binding: verified.review_binding().into(),
            display: Zeroizing::new(inert_text(&display)),
            created: Instant::now(),
        })
    }
}

// All consumers, including a future terminal adapter, receive inert plain text.
fn inert_text(text: &str) -> String {
    let mut safe = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch == '\n' || ch == ' ' || ch.is_ascii_graphic() {
            safe.push(ch);
        } else {
            safe.extend(ch.escape_default());
        }
    }
    safe
}
