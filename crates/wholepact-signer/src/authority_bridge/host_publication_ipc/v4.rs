//! Separate native admission for one exact restricted host recovery generation.
//! An admitted generation is informational. It grants no financial authority,
//! remote witness lease, global cutoff, or continuing signer freeze.
use super::super::{
    BridgeError, Result,
    host_recovery_ipc::v4::{HostRecoveryContinuityEvidenceV4, HostRecoveryContinuityRequestV4},
};
use serde::{Deserialize, Serialize};
use std::path::{Component, PathBuf};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRecoveryPublicationRequestV4 {
    pub schema_version: u16,
    pub continuity: HostRecoveryContinuityRequestV4,
    pub target_profile: PathBuf,
    pub generation_manifest_digest: String,
    pub continuity_evidence_digest: String,
}
fn hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(BridgeError::Binding);
    }
    Ok(())
}
impl HostRecoveryPublicationRequestV4 {
    pub fn validate(&self) -> Result<()> {
        self.continuity.validate()?;
        hash(&self.generation_manifest_digest)?;
        hash(&self.continuity_evidence_digest)?;
        let target = self.target_profile.to_str().ok_or(BridgeError::Binding)?;
        // The host separately authenticates its canonical directory handles.
        // This boundary rejects ambiguous textual targets and never opens them.
        if self.schema_version != 4
            || !self.target_profile.is_absolute()
            || self.target_profile.file_name().is_none()
            || target.len() > 4096
            || target.chars().any(|c| c.is_control() || matches!(c,
                '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
            ))
            || target.contains("//")
            || target.ends_with('/')
            || target.split('/').any(|part| matches!(part, "." | ".."))
            || self
                .target_profile
                .components()
                .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        wholepact_core::proposal::canonical_digest(
            "wholepact:host-recovery-publication-request:v4",
            self,
        )
        .map_err(|_| BridgeError::Binding)
    }
    pub fn matches_evidence(&self, evidence: &HostRecoveryContinuityEvidenceV4) -> Result<()> {
        self.validate()?;
        if evidence.request != self.continuity
            || evidence.digest()? != self.continuity_evidence_digest
        {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
}

/// Saved audit data only. Deserializing this record cannot recreate admission.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRecoveryPublicationRecordV4 {
    pub request: HostRecoveryPublicationRequestV4,
    pub native_review_digest: String,
    pub admission_id: String,
}
impl HostRecoveryPublicationRecordV4 {
    pub fn validate(&self) -> Result<()> {
        self.request.validate()?;
        hash(&self.native_review_digest)?;
        hash(&self.admission_id)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        wholepact_core::proposal::canonical_digest(
            "wholepact:host-recovery-publication-record:v4",
            self,
        )
        .map_err(|_| BridgeError::Binding)
    }
}
// No constructor: the distinct genuine native V4 publication producer remains
// unavailable. Neither serde nor an archive record can create this owner.
/// Non-cloneable and non-deserializable one-shot permission to publish the exact
/// restricted informational generation. No signer guard or stream is retained.
/// A host-owned native publication lease must protect the final durable marker.
/// Every later financial operation requires fresh independent authorization.
pub struct HostRecoveryPublicationAdmissionV4 {
    record: HostRecoveryPublicationRecordV4,
    evidence: HostRecoveryContinuityEvidenceV4,
    provider_enrollment_reference: String,
}
impl HostRecoveryPublicationAdmissionV4 {
    pub fn binding(&self) -> &HostRecoveryPublicationRequestV4 {
        &self.record.request
    }
    pub fn evidence(&self) -> &HostRecoveryContinuityEvidenceV4 {
        &self.evidence
    }
    pub fn provider_enrollment_reference(&self) -> &str {
        &self.provider_enrollment_reference
    }
    pub fn audit_record(&self) -> &HostRecoveryPublicationRecordV4 {
        &self.record
    }
    pub fn into_audit_record(self) -> HostRecoveryPublicationRecordV4 {
        self.record
    }
}
