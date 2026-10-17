//! Immutable data describing native installation of the already-pinned born
//! transport keys. A descriptor is never a live namespace or approval capability.
use crate::{born_offline_enrollment_v1::BornOfflineEnrollmentV1, *};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornOfflineArtifactBindingV1 {
    pub version: u16,
    pub enrollment_digest: String,
    pub namespace_binding_digest: String,
    pub witness_public_key_hex: String,
    pub offline_signer_public_key_hex: String,
    pub expected_head: AuthorityHead,
    pub issued_at_ms: u64,
    pub first_commit_deadline_ms: u64,
}
impl BornOfflineArtifactBindingV1 {
    pub fn validate(&self) -> Result<()> {
        for h in [
            &self.enrollment_digest,
            &self.namespace_binding_digest,
            &self.witness_public_key_hex,
            &self.offline_signer_public_key_hex,
            &self.expected_head.digest,
        ] {
            hash(h)?;
        }
        if self.version != 1
            || self.expected_head.sequence >= MAX_EVENTS
            || self.issued_at_ms == 0
            || self.first_commit_deadline_ms > i64::MAX as u64
            || self.first_commit_deadline_ms <= self.issued_at_ms
            || self.first_commit_deadline_ms - self.issued_at_ms > 120_000
            || self.witness_public_key_hex.bytes().all(|v| v == b'0')
            || self
                .offline_signer_public_key_hex
                .bytes()
                .all(|v| v == b'0')
        {
            return Err(AuthorityError::InvalidBinding);
        }
        encode(self)?;
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:born-offline-artifact-binding:v1", self)
    }
    pub fn owner_operation_id(&self) -> Result<String> {
        Ok(format!("born-offline-artifacts-v1-{}", self.digest()?))
    }
    pub fn validate_enrollment(&self, e: &BornOfflineEnrollmentV1) -> Result<()> {
        self.validate()?;
        e.validate()?;
        if self.enrollment_digest != e.digest()?
            || transport_fingerprint(&self.witness_public_key_hex)?
                != e.policy.witness_transport_key_digest
            || transport_fingerprint(&self.offline_signer_public_key_hex)?
                != e.policy.offline_signer_key_digest
            || self.issued_at_ms < e.issued_at_ms
            || self.first_commit_deadline_ms > e.policy.expires_at_ms
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub fn require_first_commit_time(&self, now: u64) -> Result<()> {
        self.validate()?;
        if now < self.issued_at_ms || now >= self.first_commit_deadline_ms {
            return Err(AuthorityError::Expired);
        }
        Ok(())
    }
}

/// The same public-key identifier as the maintained transport format, using
/// standard SHA-256 and its existing domain. This does not perform HPKE or
/// validate possession; the concrete native owner must do both key checks.
fn transport_fingerprint(public_hex: &str) -> Result<String> {
    hash(public_hex)?;
    let bytes = hex::decode(public_hex).map_err(|_| AuthorityError::InvalidBinding)?;
    let mut h = Sha256::new();
    h.update(b"wholepact.transport-key.v1\0");
    h.update(bytes);
    Ok(hex::encode(h.finalize()))
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornOfflineArtifactRecordV1 {
    pub binding: BornOfflineArtifactBindingV1,
    pub native_review_digest: String,
}
impl BornOfflineArtifactRecordV1 {
    pub fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        hash(&self.native_review_digest)
    }
}
