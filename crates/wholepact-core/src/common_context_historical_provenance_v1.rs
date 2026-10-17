//! Immutable historical labels from the original retained wallet observations and
//! their later native-admitted revalidation. These DTOs never grant authority,
//! imply current freshness, restore a native owner, or verify chain consensus.
use crate::{
    CoreError, ErrorCode, Result,
    manual_construction::PreconstructionProvider,
    manual_roster_construction_v3::{
        CommonContextProposalV1, CommonContextReadProfileV1, ManualRosterConstructionPlanV3,
        RosterCommonContextReadRequestV1,
    },
    manual_roster_exact_input_observation_v1::EXACT_OBSERVATION_SOURCE_TTL_MS,
    proposal::canonical_digest,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalChainObservationV1 {
    pub request_started_at_unix_seconds: u64,
    pub observed_at_unix_seconds: u64,
    pub valid_until_unix_seconds: u64,
    pub tip_height: u32,
    /// Protocol byte order, unlike the ChainContext display hash.
    pub tip_hash_protocol: String,
}
impl HistoricalChainObservationV1 {
    pub fn validate(&self) -> Result<()> {
        hash(&self.tip_hash_protocol)?;
        if self.request_started_at_unix_seconds == 0
            || self.request_started_at_unix_seconds > self.observed_at_unix_seconds
            || self.observed_at_unix_seconds > self.valid_until_unix_seconds
            || self
                .valid_until_unix_seconds
                .checked_sub(self.request_started_at_unix_seconds)
                .is_none_or(|seconds| seconds > EXACT_OBSERVATION_SOURCE_TTL_MS / 1000)
            || self.valid_until_unix_seconds > (i64::MAX as u64) / 1000
            || self.tip_height == 0
            || self.tip_height >= 500_000_000
        {
            return Err(invalid());
        }
        Ok(())
    }
    /// Exact source seconds represented in milliseconds, not a fresh timestamp.
    pub fn observed_at_ms(&self) -> Result<u64> {
        self.validate()?;
        self.observed_at_unix_seconds
            .checked_mul(1000)
            .ok_or_else(invalid)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommonContextHistoricalParticipantV1 {
    pub participant_id: String,
    pub account_id: String,
    pub full_viewing_key_digest: String,
    pub plan_digest: String,
    pub retained_request_digest: String,
    pub read_request_digest: String,
    pub read_admission_digest: String,
    pub selected_inputs_digest: String,
    pub original: HistoricalChainObservationV1,
    pub revalidation: HistoricalChainObservationV1,
    pub anchor_height: u32,
    pub anchor_hash_protocol: String,
    pub anchor_root: String,
    pub required_ancestry_digest: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommonContextHistoricalProvenanceV1 {
    pub version: u16,
    pub common_context_digest: String,
    pub reference_participant_id: String,
    pub provider: PreconstructionProvider,
    pub read_profile: CommonContextReadProfileV1,
    /// Complete canonical participant order, never wallet-lock order.
    pub observations: Vec<CommonContextHistoricalParticipantV1>,
}
/// Key-free historical projection only. Consumers must validate the entire
/// provenance against the exact retained claim before using these labels.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommonContextHistoricalReferenceSnapshotV1 {
    pub source_id: String,
    pub source_identity_digest: String,
    pub source_policy_digest: String,
    pub snapshot_digest: String,
    pub observed_at_ms: u64,
    pub tip_height: u32,
    pub tip_hash: String,
    pub anchor_height: u32,
    pub anchor_hash: String,
    pub anchor_root: String,
}
impl CommonContextHistoricalProvenanceV1 {
    /// Structural historical validation, not an owner/plan authentication gate.
    /// The live claim and recovery consumers MUST also call validate_for.
    pub fn validate(&self) -> Result<()> {
        if self.version != 1
            || !(2..=8).contains(&self.observations.len())
            || serde_json::to_vec(self).map_err(|_| invalid())?.len()
                > crate::strict_json::MAX_JSON_BYTES
        {
            return Err(invalid());
        }
        hash(&self.common_context_digest)?;
        text(&self.provider.source_id, 2048)?;
        text(&self.provider.endpoint, 2048)?;
        if !self.provider.endpoint.starts_with("https://")
            || self.provider.endpoint.ends_with('/')
            || self.provider.trust_profile != "single_tls_provider_report_not_consensus"
        {
            return Err(invalid());
        }
        let first = &self.observations[0];
        let mut previous = None;
        let mut accounts = BTreeSet::new();
        let mut keys = BTreeSet::new();
        let mut tips = BTreeMap::new();
        for row in &self.observations {
            crate::error::validate_id(
                &row.participant_id,
                "historical common-context participant",
            )?;
            for h in [
                &row.account_id,
                &row.full_viewing_key_digest,
                &row.plan_digest,
                &row.retained_request_digest,
                &row.read_request_digest,
                &row.read_admission_digest,
                &row.selected_inputs_digest,
                &row.anchor_hash_protocol,
                &row.anchor_root,
                &row.required_ancestry_digest,
            ] {
                hash(h)?;
            }
            row.original.validate()?;
            row.revalidation.validate()?;
            if previous.is_some_and(|id: &str| id >= row.participant_id.as_str())
                || !accounts.insert(&row.account_id)
                || !keys.insert(&row.full_viewing_key_digest)
                || row.anchor_height == 0
                || row.anchor_height > row.original.tip_height
                || row.anchor_height != first.anchor_height
                || row.anchor_hash_protocol != first.anchor_hash_protocol
                || row.anchor_root != first.anchor_root
                || row.required_ancestry_digest != first.required_ancestry_digest
                || row.revalidation.tip_height != first.revalidation.tip_height
                || row.revalidation.tip_hash_protocol != first.revalidation.tip_hash_protocol
                || row.revalidation.tip_height < row.original.tip_height
                || row.revalidation.observed_at_unix_seconds < row.original.observed_at_unix_seconds
                || tips
                    .insert(row.original.tip_height, &row.original.tip_hash_protocol)
                    .is_some_and(|old| old != &row.original.tip_hash_protocol)
            {
                return Err(invalid());
            }
            previous = Some(row.participant_id.as_str());
        }
        let reference = self
            .observations
            .iter()
            .max_by_key(|row| row.original.tip_height)
            .ok_or_else(invalid)?;
        if self.reference_participant_id != reference.participant_id {
            return Err(invalid());
        }
        Ok(())
    }
    /// All rows must agree with the immutable common contract. This does not
    /// authenticate another participant's native read or the Host's chain claims.
    pub fn validate_common_for(&self, common: &CommonContextProposalV1) -> Result<()> {
        self.validate()?;
        common.validate()?;
        if self.common_context_digest != common.digest()?
            || self.provider != common.provider
            || self.read_profile != common.read_profile
            || common.participants.len() != self.observations.len()
        {
            return Err(invalid());
        }
        let ancestry = required_ancestry_digest(common)?;
        let maximum_tip = common
            .expiry_height
            .checked_sub(common.read_profile.minimum_expiry_margin_blocks)
            .and_then(|h| h.checked_sub(1))
            .ok_or_else(invalid)?;
        for (row, expected) in self.observations.iter().zip(&common.participants) {
            if row.participant_id != expected.commitment.participant_id
                || row.account_id != expected.commitment.account_id
                || row.full_viewing_key_digest != expected.commitment.full_viewing_key_digest
                || row.retained_request_digest != expected.commitment.retention_request_digest
                || row.original.tip_height != expected.original_tip_height
                || row.original.tip_hash_protocol != expected.original_tip_hash_protocol
                || row.anchor_height != common.anchor_height
                || row.anchor_hash_protocol != common.anchor_hash_protocol
                || row.anchor_root != common.anchor_root
                || row.required_ancestry_digest != ancestry
                || row.revalidation.tip_height < common.reference_tip_height
                || row.revalidation.tip_height > maximum_tip
                || (row.revalidation.tip_height == common.reference_tip_height
                    && row.revalidation.tip_hash_protocol != common.reference_tip_hash_protocol)
            {
                return Err(invalid());
            }
        }
        let reference = self.reference()?;
        if reference.original.tip_height != common.reference_tip_height
            || reference.original.tip_hash_protocol != common.reference_tip_hash_protocol
        {
            return Err(invalid());
        }
        Ok(())
    }
    /// Independently compare this participant's ACTUAL retained plan and read.
    /// Other rows remain authenticated Host historical provenance, never that
    /// participant's assertion that it independently observed other accounts.
    pub fn validate_participant_for(
        &self,
        plan: &ManualRosterConstructionPlanV3,
        read: &RosterCommonContextReadRequestV1,
        admission_digest: &str,
    ) -> Result<()> {
        self.validate_common_for(&plan.common_context)?;
        let row = self
            .observations
            .iter()
            .find(|r| r.participant_id == plan.enrollment().scope.participant_id)
            .ok_or_else(invalid)?;
        self.validate_participant_row(row, plan, read, admission_digest)
    }
    /// Every exact full read request and its separately retained admission digest
    /// is mandatory. V5 recovery obtains these from its complete reentry lineage.
    pub fn validate_for(
        &self,
        plans: &[ManualRosterConstructionPlanV3],
        reads: &[(&RosterCommonContextReadRequestV1, &str)],
    ) -> Result<()> {
        if plans.len() != self.observations.len() || reads.len() != plans.len() {
            return Err(invalid());
        }
        let common = &plans.first().ok_or_else(invalid)?.common_context;
        self.validate_common_for(common)?;
        for ((row, plan), (read, admission)) in self.observations.iter().zip(plans).zip(reads) {
            if plan.common_context != *common {
                return Err(invalid());
            }
            self.validate_participant_row(row, plan, read, admission)?;
        }
        Ok(())
    }
    fn validate_participant_row(
        &self,
        row: &CommonContextHistoricalParticipantV1,
        plan: &ManualRosterConstructionPlanV3,
        read: &RosterCommonContextReadRequestV1,
        admission: &str,
    ) -> Result<()> {
        plan.validate()?;
        read.validate()?;
        hash(admission)?;
        let identity = &plan.enrollment().identity;
        let retained = &plan.retained.selection_context;
        // Seconds-precision intervals, never invented millisecond precision.
        let request_second_end = row
            .revalidation
            .request_started_at_unix_seconds
            .checked_mul(1000)
            .and_then(|v| v.checked_add(999))
            .ok_or_else(invalid)?;
        let maximum_additional_blocks = read.maximum_additional_blocks()?;
        if read.plan != *plan
            || read.profile != self.read_profile
            || row.participant_id != plan.enrollment().scope.participant_id
            || row.account_id != identity.account_id
            || row.full_viewing_key_digest != identity.full_viewing_key_digest
            || row.plan_digest != plan.digest()?
            || row.retained_request_digest != plan.retained.digest()?
            || row.read_request_digest != read.digest()?
            || row.read_admission_digest != admission
            || row.selected_inputs_digest != selected_inputs_digest(plan)?
            || row.original.tip_height != retained.tip_height
            || row.original.tip_hash_protocol != retained.tip_hash_protocol
            || row.revalidation.tip_height > read.maximum_observed_tip()?
            || row
                .revalidation
                .tip_height
                .checked_sub(row.original.tip_height)
                .is_none_or(|additional| additional > maximum_additional_blocks)
            || request_second_end < read.requested_at_ms
            || row.revalidation.observed_at_ms()? > read.completion_expires_at_ms
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest("wholepact:common-context-historical-provenance:v1", self)
    }
    pub fn source_identity_digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest(
            "wholepact:common-context-historical-source-identity:v1",
            &self.provider,
        )
    }
    /// The declared provider and immutable read policy, not a claim to include
    /// every HTTP/proxy setting or independently verify the provider.
    pub fn source_policy_digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest(
            "wholepact:common-context-historical-source-policy:v1",
            &(&self.provider, &self.read_profile),
        )
    }
    fn reference(&self) -> Result<&CommonContextHistoricalParticipantV1> {
        self.validate()?;
        self.observations
            .iter()
            .find(|r| r.participant_id == self.reference_participant_id)
            .ok_or_else(invalid)
    }
    pub fn reference_snapshot(&self) -> Result<CommonContextHistoricalReferenceSnapshotV1> {
        let reference = self.reference()?;
        Ok(CommonContextHistoricalReferenceSnapshotV1 {
            source_id: self.provider.source_id.clone(),
            source_identity_digest: self.source_identity_digest()?,
            source_policy_digest: self.source_policy_digest()?,
            snapshot_digest: canonical_digest(
                "wholepact:common-context-historical-reference-snapshot:v1",
                &(
                    self.digest()?,
                    &reference.participant_id,
                    &reference.original,
                ),
            )?,
            observed_at_ms: reference.original.observed_at_ms()?,
            tip_height: reference.original.tip_height,
            tip_hash: reference.original.tip_hash_protocol.clone(),
            anchor_height: reference.anchor_height,
            anchor_hash: reference.anchor_hash_protocol.clone(),
            anchor_root: reference.anchor_root.clone(),
        })
    }
}
pub fn selected_inputs_digest(plan: &ManualRosterConstructionPlanV3) -> Result<String> {
    plan.validate()?;
    canonical_digest(
        "wholepact:common-context-historical-selected-inputs:v1",
        &plan.selected_inputs(),
    )
}
pub fn required_ancestry_digest(common: &CommonContextProposalV1) -> Result<String> {
    common.validate()?;
    let mut ancestry = BTreeMap::new();
    for p in &common.participants {
        if ancestry
            .insert(p.original_tip_height, p.original_tip_hash_protocol.clone())
            .is_some_and(|old| old != p.original_tip_hash_protocol)
        {
            return Err(invalid());
        }
    }
    canonical_digest(
        "wholepact:common-context-historical-required-ancestry:v1",
        &ancestry.into_iter().collect::<Vec<_>>(),
    )
}
fn invalid() -> CoreError {
    CoreError::new(
        ErrorCode::InvalidTerms,
        "invalid exact historical common-context provenance",
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
fn text(s: &str, limit: usize) -> Result<()> {
    if s.is_empty() || s.len() > limit || s.chars().any(char::is_control) {
        Err(invalid())
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "common_context_historical_provenance_v1_tests.rs"]
mod tests;
