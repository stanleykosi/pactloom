//! Inert wire evidence only. Only an authenticated expected installed-peer
//! exchange can create the one-use additional-read owner in the private client.
use crate::{Error, Result, digest, hash};
use serde::{Deserialize, Serialize};
use wholepact_core::manual_roster_exact_input_observation_v1::ManualRosterExactInputObservationRequestV1;
pub const MAX_EXACT_INPUT_OBSERVATION_FRAME: usize = 512 * 1024;
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterExactInputObservationEvidenceV1 {
    pub version: u16,
    pub request: ManualRosterExactInputObservationRequestV1,
    pub retained_signer_intent_digest: String,
    pub current_attempt_digest: String,
    pub current_attempt_sequence: u64,
    pub native_review_digest: String,
    pub admitted_at_ms: u64,
    pub writer_session_expires_at_ms: u64,
}
impl ManualRosterExactInputObservationEvidenceV1 {
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
        digest(
            "wholepact:manual-roster-exact-input-observation-evidence:v1",
            self,
        )
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManualRosterExactInputObservationResponseV1 {
    ExactInputObservationAdmittedV1 {
        evidence: Box<ManualRosterExactInputObservationEvidenceV1>,
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
            r#"{"status":"exact_input_observation_admitted_v1","evidence":{},"renew":true}"#,
        ] {
            assert!(
                serde_json::from_str::<ManualRosterExactInputObservationResponseV1>(value).is_err()
            );
        }
        assert!(
            serde_json::from_str::<ManualRosterExactInputObservationResponseV1>(
                r#"{"status":"denied"}"#
            )
            .is_ok()
        );
    }
}
