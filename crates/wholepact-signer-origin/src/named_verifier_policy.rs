//! Purpose-specific viewing disclosure claims. Parsing never grants permission.
use crate::{Error, Result, digest, hash, label};
use serde::{Deserialize, Serialize};
use wholepact_core::{Proposal, ProposalInput};
use zeroize::Zeroize;
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedVerifierPolicyScopeV1 {
    pub version: u16,
    pub proposal: ProposalInput,
    pub account_id: String,
    pub participant_id: String,
    pub enrollment_ref: String,
    pub accepted_manifest_ref: String,
    pub original_request_digest: String,
    pub original_nonce: String,
    pub original_artifact_digest: String,
    pub verifier_key_digest: String,
    pub verifier_public_key: [u8; 32],
    pub verifier_destination: String,
    pub original_validity_not_before_ms: u64,
    pub original_validity_expires_ms: u64,
    pub requested_at_ms: u64,
    pub disclosure_expires_at_ms: u64,
}
impl NamedVerifierPolicyScopeV1 {
    pub fn validate(&self) -> Result<Proposal> {
        label(&self.account_id)?;
        label(&self.participant_id)?;
        for value in [
            &self.enrollment_ref,
            &self.accepted_manifest_ref,
            &self.original_request_digest,
            &self.original_nonce,
            &self.original_artifact_digest,
            &self.verifier_key_digest,
        ] {
            hash(value)?;
        }
        if self.version != 1
            || self.original_validity_not_before_ms >= self.original_validity_expires_ms
            || self.original_validity_not_before_ms > self.requested_at_ms
            || self.original_validity_expires_ms < self.disclosure_expires_at_ms
            || self.original_validity_expires_ms > i64::MAX as u64
            || self.requested_at_ms >= self.disclosure_expires_at_ms
            || self.disclosure_expires_at_ms > i64::MAX as u64
            || self.disclosure_expires_at_ms - self.requested_at_ms > 120_000
            || self.verifier_destination.is_empty()
            || self.verifier_destination.len() > 4096
            || self.verifier_destination.chars().any(char::is_control)
        {
            return Err(Error::Binding);
        }
        let proposal = Proposal::validate(self.proposal.clone()).map_err(|_| Error::Binding)?;
        use sha2::{Digest, Sha256};
        if hex::encode(Sha256::digest(self.verifier_public_key)) != self.verifier_key_digest
            || self.original_request_digest
                != digest(
                    "wholepact:named-verifier-original-request:v1",
                    &(
                        &self.original_nonce,
                        proposal.proposal_digest(),
                        &self.original_artifact_digest,
                        &self.verifier_key_digest,
                        self.original_validity_not_before_ms,
                        self.original_validity_expires_ms,
                    ),
                )?
        {
            return Err(Error::Binding);
        }
        if !proposal
            .manifest()
            .participants
            .iter()
            .any(|p| p.account_id == self.account_id && p.participant_id == self.participant_id)
        {
            return Err(Error::Binding);
        }
        if serde_json::to_vec(self).map_err(|_| Error::Binding)?.len() > 128 * 1024 {
            return Err(Error::Limit);
        }
        Ok(proposal)
    }
    pub fn pairing_digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:named-verifier-policy-pair:v1", self)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedVerifierPolicyRequestV1 {
    pub scope: NamedVerifierPolicyScopeV1,
    pub current_caller_binding_digest: String,
    pub verifier_possession_signature: Vec<u8>,
}
impl NamedVerifierPolicyRequestV1 {
    pub fn possession_message(&self) -> Result<Vec<u8>> {
        hash(&self.current_caller_binding_digest)?;
        self.scope.validate()?;
        let mut bytes = b"wholepact:named-verifier-policy-possession:v1\0".to_vec();
        bytes.extend(
            serde_json::to_vec(&(&self.scope, &self.current_caller_binding_digest))
                .map_err(|_| Error::Binding)?,
        );
        Ok(bytes)
    }
    pub fn validate(&self) -> Result<Proposal> {
        let proposal = self.scope.validate()?;
        if self.verifier_possession_signature.len() != 64 {
            return Err(Error::Binding);
        }
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519,
            &self.scope.verifier_public_key,
        )
        .verify(
            &self.possession_message()?,
            &self.verifier_possession_signature,
        )
        .map_err(|_| Error::Authentication)?;
        Ok(proposal)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:named-verifier-policy-disclosure:v1", self)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum NamedVerifierPolicyResponseV1 {
    Disclosed {
        lease_id: String,
        request_digest: String,
        account_fvk_hex: String,
    },
    Denied,
}
impl Drop for NamedVerifierPolicyResponseV1 {
    fn drop(&mut self) {
        if let Self::Disclosed {
            account_fvk_hex, ..
        } = self
        {
            account_fvk_hex.zeroize();
        }
    }
}
