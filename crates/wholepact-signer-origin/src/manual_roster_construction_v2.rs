//! Purpose-distinct sequential construction data. Parsing any value in this
//! module creates no current native owner, retained contribution or permission.
use crate::{Error, Result, digest, hash, manual::ManualCurrentState};
use serde::{Deserialize, Serialize};
use wholepact_core::manual_roster_construction_v2::ManualRosterContributionRetentionRequestV2;

/// Full bounded core request plus its strict IPC envelope/evidence overhead.
pub const MAX_ROSTER_CONSTRUCTION_FRAME: usize = 512 * 1024;

/// Only the live candidate-selection stream accepts this transition. The
/// retained response closes that stream; a replay cannot recreate an owner.
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManualRosterSelectionCommandV2 {
    CheckCurrent {
        lease_id: String,
        evidence_digest: String,
        challenge_nonce: String,
    },
    Finish {},
    RetainExactContributionV2 {
        lease_id: String,
        evidence_digest: String,
        request: Box<ManualRosterContributionRetentionRequestV2>,
    },
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterContributionRetentionEvidenceV2 {
    pub version: u16,
    pub request: ManualRosterContributionRetentionRequestV2,
    pub retained_signer_intent_digest: String,
    pub native_review_digest: String,
    pub admitted_at_ms: u64,
    /// Actual historical observation at selection. This is never renewed or
    /// represented as a current native/witness lease after durable admission.
    pub selection_observation: ManualCurrentState,
}
impl ManualRosterContributionRetentionEvidenceV2 {
    pub fn validate(&self) -> Result<()> {
        self.request.validate().map_err(|_| Error::Binding)?;
        self.selection_observation.validate()?;
        hash(&self.retained_signer_intent_digest)?;
        hash(&self.native_review_digest)?;
        let e = &self.request.selection.scope.selection.inventory.enrollment;
        if self.version != 2
            || self.admitted_at_ms < self.request.requested_at_ms
            || self.admitted_at_ms >= self.request.admission_expires_at_ms
            || self.admitted_at_ms >= self.selection_observation.writer_session_expires_at_ms
            || self.selection_observation.writer_certificate_digest
                != e.signer.writer_certificate_digest
            || self.selection_observation.writer_epoch != e.signer.writer_epoch
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:roster-contribution-retention-evidence:v2", self)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManualRosterContributionRetentionResponseV2 {
    ExactContributionRetainedV2 {
        evidence: Box<ManualRosterContributionRetentionEvidenceV2>,
        /// Hash of the actual encrypted immutable source receipt after fsync.
        durable_receipt_digest: String,
    },
    Denied {},
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn serialized_approval_or_legacy_response_never_creates_retention() {
        for value in [
            r#"{"status":"denied","approved":true}"#,
            r#"{"status":"held","lease_id":"x"}"#,
            r#"{"status":"contribution_admitted_v1","evidence":{}}"#,
        ] {
            assert!(
                serde_json::from_str::<ManualRosterContributionRetentionResponseV2>(value).is_err()
            );
        }
        assert!(
            serde_json::from_str::<ManualRosterContributionRetentionResponseV2>(
                r#"{"status":"denied"}"#
            )
            .is_ok()
        );
        assert!(
            serde_json::from_str::<ManualRosterSelectionCommandV2>(
                r#"{"operation":"finish","retained":true}"#
            )
            .is_err()
        );
    }
}

use wholepact_core::manual_roster_construction_v2::ManualRosterConstructionRequestV2;
/// Historical fact produced only after the actual native/witness Reserve and
/// single Consume. These bytes alone have no post-restart construction power.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterConstructionContributionEvidenceV2 {
    pub version: u16,
    pub request: ManualRosterConstructionRequestV2,
    pub retained_signer_intent_digest: String,
    pub current_attempt_digest: String,
    pub current_attempt_sequence: u64,
    pub native_review_digest: String,
    pub witness_reservation_digest: String,
    pub witness_consumed_digest: String,
    pub reviewed_at_ms: u64,
    pub reserved_at_ms: u64,
    pub consumed_at_ms: u64,
    pub reserved_debit_zatoshis: u64,
    pub reserved_input_value_zatoshis: u64,
    pub writer_session_expires_at_ms: u64,
}
impl ManualRosterConstructionContributionEvidenceV2 {
    pub fn validate(&self) -> Result<()> {
        self.request.validate().map_err(|_| Error::Binding)?;
        for h in [
            &self.retained_signer_intent_digest,
            &self.current_attempt_digest,
            &self.native_review_digest,
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
        if self.version != 2
            || self.current_attempt_sequence < 2
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
            "wholepact:roster-construction-consumed-native-evidence:v2",
            self,
        )
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManualRosterConstructionResponseV2 {
    ExactConstructionConsumedV2 {
        evidence: Box<ManualRosterConstructionContributionEvidenceV2>,
    },
    Denied {},
}
