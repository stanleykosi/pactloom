//! V3 inert exact-plan consumed evidence. Parsing creates no native owner.
use crate::{Error, Result, digest, hash};
use serde::{Deserialize, Serialize};
use wholepact_core::manual_roster_construction_v3::ManualRosterConstructionRequestV3;
pub const MAX_ROSTER_CONSTRUCTION_FRAME_V3: usize = 768 * 1024;

/// Historical fact produced only after the actual native/witness Reserve and
/// single Consume. These bytes alone have no post-restart construction power.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterConstructionContributionEvidenceV3 {
    pub version: u16,
    pub request: ManualRosterConstructionRequestV3,
    pub retained_signer_intent_digest: String,
    pub current_attempt_digest: String,
    pub current_attempt_sequence: u64,
    pub native_review_digest: String,
    pub common_context_read_admission_digest: String,
    pub witness_plan_approval_digest: String,
    pub witness_reservation_digest: String,
    pub witness_consumed_digest: String,
    pub reviewed_at_ms: u64,
    pub reserved_at_ms: u64,
    pub consumed_at_ms: u64,
    pub reserved_debit_zatoshis: u64,
    pub reserved_input_value_zatoshis: u64,
    pub writer_session_expires_at_ms: u64,
}
impl ManualRosterConstructionContributionEvidenceV3 {
    pub fn validate(&self) -> Result<()> {
        self.request.validate().map_err(|_| Error::Binding)?;
        for h in [
            &self.retained_signer_intent_digest,
            &self.current_attempt_digest,
            &self.native_review_digest,
            &self.common_context_read_admission_digest,
            &self.witness_plan_approval_digest,
            &self.witness_reservation_digest,
            &self.witness_consumed_digest,
        ] {
            hash(h)?;
        }
        let total = self
            .request
            .plan
            .selected_inputs()
            .iter()
            .try_fold(0u64, |n, i| {
                n.checked_add(i.value_zatoshis).ok_or(Error::Binding)
            })?;
        if self.version != 3
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
            || self.reviewed_at_ms < self.request.requested_at_ms
            || self.reserved_at_ms < self.reviewed_at_ms
            || self.consumed_at_ms < self.reserved_at_ms
            || self.consumed_at_ms >= self.request.admission_expires_at_ms
            || self.consumed_at_ms >= self.writer_session_expires_at_ms
            || self.reserved_debit_zatoshis
                != self
                    .request
                    .plan
                    .maximum_net_debit_zatoshis()
                    .map_err(|_| Error::Binding)?
            || self.reserved_input_value_zatoshis != total
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest(
            "wholepact:roster-construction-consumed-native-evidence:v3",
            self,
        )
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManualRosterConstructionResponseV3 {
    ExactConstructionConsumedV3 {
        evidence: Box<ManualRosterConstructionContributionEvidenceV3>,
    },
    Denied {},
}
