//! Inert wire evidence only. Only an authenticated expected installed-peer
//! exchange can create the one-use additional-read owner in the private client.
use crate::{Error, Result, digest, hash};
use serde::{Deserialize, Serialize};
use wholepact_core::manual_roster_construction_v3::RosterCommonContextReadRequestV1;
pub const MAX_COMMON_CONTEXT_READ_FRAME: usize = 768 * 1024;
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RosterCommonContextReadEvidenceV1 {
    pub version: u16,
    pub request: RosterCommonContextReadRequestV1,
    pub retained_signer_intent_digest: String,
    pub current_attempt_digest: String,
    pub current_attempt_sequence: u64,
    pub native_review_digest: String,
    pub admitted_at_ms: u64,
    pub writer_session_expires_at_ms: u64,
}
impl RosterCommonContextReadEvidenceV1 {
    pub fn validate(&self) -> Result<()> {
        self.request.validate().map_err(|_| Error::Binding)?;
        for value in [
            &self.retained_signer_intent_digest,
            &self.current_attempt_digest,
            &self.native_review_digest,
        ] {
            hash(value)?;
        }
        if self.version != 1
            || self.current_attempt_sequence > i64::MAX as u64
            || self.writer_session_expires_at_ms > i64::MAX as u64
            || self.current_attempt_sequence
                <= self
                    .request
                    .plan
                    .retained
                    .selection
                    .scope
                    .selection
                    .inventory
                    .attempt
                    .attempt_sequence
            || self.current_attempt_digest
                == self
                    .request
                    .plan
                    .retained
                    .selection
                    .scope
                    .selection
                    .inventory
                    .attempt
                    .continuation_digest
            || self.admitted_at_ms < self.request.requested_at_ms
            || self.admitted_at_ms >= self.request.admission_expires_at_ms
            || self.admitted_at_ms >= self.writer_session_expires_at_ms
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:roster-common-context-read-evidence:v1", self)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum RosterCommonContextReadResponseV1 {
    CommonContextReadAdmittedV1 {
        evidence: Box<RosterCommonContextReadEvidenceV1>,
    },
    Denied {},
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_and_caller_approval_fields_are_not_new_native_evidence() {
        for value in [
            r#"{"status":"denied","approved":true}"#,
            r#"{"status":"exact_construction_consumed_v2","evidence":{}}"#,
            r#"{"status":"common_context_read_admitted_v1","evidence":{},"renew":true}"#,
        ] {
            assert!(serde_json::from_str::<RosterCommonContextReadResponseV1>(value).is_err());
        }
        assert!(
            serde_json::from_str::<RosterCommonContextReadResponseV1>(r#"{"status":"denied"}"#)
                .is_ok()
        );
    }
}
