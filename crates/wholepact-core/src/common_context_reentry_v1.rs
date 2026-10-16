//! Inert lineage for a genuinely new native construction owner. The original
//! still-active witness attempt/session remains exact; no successor is issued. These values
//! describe old-read/new-construction provenance; parsing never creates a live
//! read, reentry, wallet, signing, witness, or construction capability.
use crate::manual_inventory::MAX_PRELIMINARY_DISCLOSURE_MS;
use crate::manual_roster_construction_v3::RosterCommonContextReadRequestV1;
use crate::{CoreError, ErrorCode, Result, proposal::canonical_digest};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommonContextReentryPurposeV1 {
    ResumeAlreadyAdmittedConstructionOnly,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RosterCommonContextReentryRequestV1 {
    pub version: u16,
    pub operation_id: String,
    pub original_read: RosterCommonContextReadRequestV1,
    pub original_read_admission_digest: String,
    pub pending_grant_digest: String,
    pub original_attempt_digest: String,
    pub original_attempt_sequence: u64,
    pub current_caller_binding_digest: String,
    pub current_attempt_digest: String,
    pub current_attempt_sequence: u64,
    pub purpose: CommonContextReentryPurposeV1,
    pub requested_at_ms: u64,
    pub admission_expires_at_ms: u64,
}
impl RosterCommonContextReentryRequestV1 {
    pub fn validate(&self) -> Result<()> {
        self.original_read.validate()?;
        crate::error::validate_id(&self.operation_id, "common-context reentry")?;
        for h in [
            &self.original_read_admission_digest,
            &self.pending_grant_digest,
            &self.original_attempt_digest,
            &self.current_caller_binding_digest,
            &self.current_attempt_digest,
        ] {
            hash(h)?;
        }
        let original = &self.original_read;
        let retained_attempt = &original
            .plan
            .retained
            .selection
            .scope
            .selection
            .inventory
            .attempt;
        if self.version != 1
            || self.operation_id == original.operation_id
            || self.operation_id == original.plan.retained.operation_id
            || self.operation_id == original.plan.retained.selection.operation_id
            || self.operation_id
                == original
                    .plan
                    .retained
                    .selection
                    .scope
                    .selection
                    .invocation
                    .operation_id
            || self.original_attempt_sequence <= retained_attempt.attempt_sequence
            || self.original_attempt_digest == retained_attempt.continuation_digest
            || self.current_attempt_sequence != self.original_attempt_sequence
            || self.current_attempt_sequence > i64::MAX as u64
            || self.current_attempt_digest != self.original_attempt_digest
            || self.current_caller_binding_digest == original.current_caller_binding_digest
            || self.requested_at_ms < original.requested_at_ms
            || self.requested_at_ms >= self.admission_expires_at_ms
            || self.admission_expires_at_ms > original.completion_expires_at_ms
            || self.admission_expires_at_ms - self.requested_at_ms > MAX_PRELIMINARY_DISCLOSURE_MS
        {
            return Err(invalid());
        }
        bounded(self)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest("wholepact:roster-common-context-reentry-request:v1", self)
    }
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let value: Self = crate::parse_typed_json(bytes)?;
        value.validate()?;
        Ok(value)
    }
    pub fn remaining_admission_ms(&self, now: u64) -> Result<u64> {
        self.validate()?;
        if now < self.requested_at_ms || now >= self.admission_expires_at_ms {
            return Err(invalid());
        }
        Ok(self.admission_expires_at_ms - now)
    }
}

/// Immutable receipt only. The source must independently compare actual native,
/// process, journal and key ownership. Absolute ceilings never reconstruct the
/// original Instant or shared clock/attempt state after process restart.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RosterCommonContextReentryLineageV1 {
    pub version: u16,
    pub request: RosterCommonContextReentryRequestV1,
    pub retained_signer_intent_digest: String,
    pub original_native_binding_digest: String,
    pub current_native_binding_digest: String,
    pub original_host_process_digest: String,
    pub original_record_digest: String,
    pub original_genesis_digest: String,
    pub original_birth_digest: String,
    pub current_witness_history_digest: String,
    pub current_witness_continuation_digest: String,
    pub current_writer_session_digest: String,
    pub construction_transport_credential_digest: String,
    pub construction_transport_credential_id: String,
    pub original_transport_fence_digest: String,
    pub current_writer_session_expires_at_ms: u64,
    pub native_review_digest: String,
    pub admitted_at_ms: u64,
    pub completion_expires_at_ms: u64,
}
impl RosterCommonContextReentryLineageV1 {
    pub fn validate(&self) -> Result<()> {
        self.request.validate()?;
        for h in [
            &self.retained_signer_intent_digest,
            &self.original_native_binding_digest,
            &self.current_native_binding_digest,
            &self.original_host_process_digest,
            &self.original_record_digest,
            &self.original_genesis_digest,
            &self.original_birth_digest,
            &self.current_witness_history_digest,
            &self.current_witness_continuation_digest,
            &self.current_writer_session_digest,
            &self.construction_transport_credential_digest,
            &self.construction_transport_credential_id,
            &self.original_transport_fence_digest,
            &self.native_review_digest,
        ] {
            hash(h)?;
        }
        if self.version != 1
            || self.original_native_binding_digest == self.current_native_binding_digest
            || self.current_witness_continuation_digest != self.request.current_attempt_digest
            || self.admitted_at_ms < self.request.requested_at_ms
            || self.admitted_at_ms >= self.request.admission_expires_at_ms
            || self.admitted_at_ms >= self.completion_expires_at_ms
            || self.completion_expires_at_ms > self.request.original_read.completion_expires_at_ms
            || self.completion_expires_at_ms > self.current_writer_session_expires_at_ms
            || self.current_writer_session_expires_at_ms > i64::MAX as u64
        {
            return Err(invalid());
        }
        bounded(self)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest("wholepact:roster-common-context-reentry-lineage:v1", self)
    }
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let value: Self = crate::parse_typed_json(bytes)?;
        value.validate()?;
        Ok(value)
    }
}
fn invalid() -> CoreError {
    CoreError::new(
        ErrorCode::InvalidTerms,
        "invalid exact old-read/new-construction reentry lineage",
    )
}
fn hash(s: &str) -> Result<()> {
    if s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(invalid())
    }
}
fn bounded<T: Serialize>(value: &T) -> Result<()> {
    if serde_json::to_vec(value).map_err(|_| invalid())?.len() > crate::strict_json::MAX_JSON_BYTES
    {
        Err(invalid())
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "common_context_reentry_v1_tests.rs"]
mod tests;
