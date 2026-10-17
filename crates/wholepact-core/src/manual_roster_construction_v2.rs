//! Inert exact claims for sequential roster retention and non-signing construction.
//! Validation cannot create native consent, observed inputs, witness exposure,
//! a one-use contribution, or any authority to sign, prove or dispatch.
use crate::{
    CoreError, ErrorCode, MAX_MONEY, OutputAllocation, Proposal, ProposalInput, Result,
    manual_construction::{ManualConstructionInput, ManualSelectionContext},
    manual_inventory::MAX_PRELIMINARY_DISCLOSURE_MS,
    manual_roster_candidate_selection_v2::ManualRosterCandidateSelectionRequestV2,
    proposal::canonical_digest,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterContributionRetentionRequestV2 {
    pub version: u16,
    pub operation_id: String,
    pub selection: ManualRosterCandidateSelectionRequestV2,
    pub selection_evidence_digest: String,
    pub selected_inputs: Vec<ManualConstructionInput>,
    pub selection_context: ManualSelectionContext,
    pub local_exclusion_digest: String,
    pub change_address: String,
    pub change_value_zatoshis: u64,
    pub requested_at_ms: u64,
    pub admission_expires_at_ms: u64,
}
impl ManualRosterContributionRetentionRequestV2 {
    pub fn validate(&self) -> Result<()> {
        self.selection.validate()?;
        bounded(self)?;
        crate::error::validate_id(&self.operation_id, "roster retention operation")?;
        hash(&self.selection_evidence_digest)?;
        hash(&self.local_exclusion_digest)?;
        crate::agreement::validate_address_text(&self.change_address)?;
        let s = &self.selection;
        let context = &self.selection_context;
        if self.version != 2
            || self.operation_id == s.operation_id
            || self.operation_id == s.scope.selection.invocation.operation_id
            || self.requested_at_ms < s.requested_at_ms
            || self.admission_expires_at_ms > s.disclosure_expires_at_ms
            || self.admission_expires_at_ms <= self.requested_at_ms
            || self.admission_expires_at_ms > self.completion_expires_at_ms()
            || context.anchor_height != s.scope.selection.inventory.anchor_height
            || context.anchor_height == 0
            || context.tip_height < context.anchor_height
            || context
                .tip_height
                .checked_add(1)
                .is_none_or(|n| n > s.scope.selection.economic_intent.expiry_height)
            || self.selected_inputs.is_empty()
            || self.selected_inputs.len() > 256
        {
            return Err(invalid());
        }
        for h in [
            &context.tip_hash_protocol,
            &context.anchor_hash_protocol,
            &context.anchor_root,
        ] {
            hash(h)?;
        }
        let mut previous = None;
        let mut nullifiers = BTreeSet::new();
        let mut sum = 0u64;
        for input in &self.selected_inputs {
            crate::error::validate_id(&input.input_id, "retained input")?;
            hash(&input.nullifier)?;
            if previous.is_some_and(|p: &str| p >= input.input_id.as_str())
                || !nullifiers.insert(&input.nullifier)
                || input.value_zatoshis == 0
            {
                return Err(invalid());
            }
            sum = sum
                .checked_add(input.value_zatoshis)
                .filter(|n| *n <= MAX_MONEY)
                .ok_or_else(invalid)?;
            previous = Some(input.input_id.as_str());
        }
        if sum
            != s.scope
                .requested_debit_zatoshis()?
                .checked_add(self.change_value_zatoshis)
                .filter(|n| *n <= MAX_MONEY)
                .ok_or_else(invalid)?
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest(
            "wholepact:manual-roster-contribution-retention-request:v2",
            self,
        )
    }
    pub fn completion_expires_at_ms(&self) -> u64 {
        self.selection
            .scope
            .selection
            .invocation
            .construction_expires_at_ms
    }
    pub fn remaining_admission_ms(&self, now: u64) -> Result<u64> {
        self.validate()?;
        remaining(self.requested_at_ms, self.admission_expires_at_ms, now)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterRetentionCommitmentV2 {
    pub participant_id: String,
    pub account_id: String,
    pub full_viewing_key_digest: String,
    pub retention_request_digest: String,
    pub retention_evidence_digest: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterConstructionPlanV2 {
    pub version: u16,
    pub retained: ManualRosterContributionRetentionRequestV2,
    pub retained_evidence_digest: String,
    pub proposal: ProposalInput,
    pub participants: Vec<ManualRosterRetentionCommitmentV2>,
}
impl ManualRosterConstructionPlanV2 {
    pub fn enrollment(&self) -> &crate::manual_enrollment::BornManualEnrollmentTerms {
        &self.retained.selection.scope.selection.inventory.enrollment
    }
    pub fn selected_inputs(&self) -> &[ManualConstructionInput] {
        &self.retained.selected_inputs
    }
    pub fn completion_deadline_ms(&self) -> u64 {
        self.completion_expires_at_ms()
    }
    pub fn invocation_digest(&self) -> Result<String> {
        self.retained.selection.scope.selection.invocation.digest()
    }
    pub fn maximum_net_debit_zatoshis(&self) -> Result<u64> {
        let proposal = self.validate()?;
        let owner = self.enrollment();
        proposal
            .manifest()
            .participants
            .iter()
            .find(|p| {
                p.account_id == owner.identity.account_id
                    && p.participant_id == owner.scope.participant_id
            })
            .map(|p| p.maximum_net_debit.as_zatoshis())
            .ok_or_else(invalid)
    }

    pub fn validate(&self) -> Result<Proposal> {
        bounded(self)?;
        self.retained
            .selection
            .scope
            .selection
            .require_legacy_selection()?;
        self.validate_retained_economics()
    }

    /// Pure per-owner economic/input/return checks shared with V3. This does not
    /// validate this value as a public V2 plan, compute its V2 digest or issue an
    /// approval. Keep the original bound, serialized shape and all fact checks.
    pub(crate) fn validate_retained_economics(&self) -> Result<Proposal> {
        bounded(self)?;
        self.retained.validate()?;
        hash(&self.retained_evidence_digest)?;
        let selection = &self.retained.selection.scope.selection;
        let proposal = selection.economic_intent.require_proposal(&self.proposal)?;
        if self.version != 2
            || self.participants.len() != selection.economic_intent.participants.len()
            || !(2..=32).contains(&self.participants.len())
            || self.proposal.artifact_digest.is_some()
            || self.proposal.effects_commitment.is_some()
        {
            return Err(invalid());
        }
        let owner = &selection.inventory.enrollment;
        let mut previous = None;
        let mut keys = BTreeSet::new();
        let mut accounts = BTreeSet::new();
        let mut requests = BTreeSet::new();
        let mut evidence = BTreeSet::new();
        let own_digest = self.retained.digest()?;
        for (actual, expected) in self
            .participants
            .iter()
            .zip(&selection.economic_intent.participants)
        {
            crate::error::validate_id(&actual.participant_id, "retained participant")?;
            for h in [
                &actual.account_id,
                &actual.full_viewing_key_digest,
                &actual.retention_request_digest,
                &actual.retention_evidence_digest,
            ] {
                hash(h)?;
            }
            if previous.is_some_and(|p: &str| p >= actual.participant_id.as_str())
                || actual.participant_id != expected.participant_id
                || actual.account_id != expected.account_id
                || !keys.insert(&actual.full_viewing_key_digest)
                || !accounts.insert(&actual.account_id)
                || !requests.insert(&actual.retention_request_digest)
                || !evidence.insert(&actual.retention_evidence_digest)
            {
                return Err(invalid());
            }
            if actual.account_id == owner.identity.account_id
                && (actual.participant_id != owner.scope.participant_id
                    || actual.full_viewing_key_digest != owner.identity.full_viewing_key_digest
                    || actual.retention_request_digest != own_digest
                    || actual.retention_evidence_digest != self.retained_evidence_digest)
            {
                return Err(invalid());
            }
            previous = Some(actual.participant_id.as_str());
        }
        if !accounts.contains(&owner.identity.account_id) {
            return Err(invalid());
        }
        let actual: BTreeMap<_, _> = proposal
            .manifest()
            .inputs
            .iter()
            .filter(|i| {
                i.account_id == owner.identity.account_id
                    && i.participant_id == owner.scope.participant_id
            })
            .map(|i| (i.input_id.as_str(), i.amount.as_zatoshis()))
            .collect();
        let retained: BTreeMap<_, _> = self
            .retained
            .selected_inputs
            .iter()
            .map(|i| (i.input_id.as_str(), i.value_zatoshis))
            .collect();
        if actual != retained {
            return Err(invalid());
        }
        let returns: Vec<_> = proposal.manifest().outputs.iter().filter(|o| matches!(&o.allocation,
            OutputAllocation::Return{participant_id, account_id, ..} if participant_id == &owner.scope.participant_id && account_id == &owner.identity.account_id)).collect();
        match self.retained.change_value_zatoshis {
            0 if !returns.is_empty() => return Err(invalid()),
            0 => {}
            value
                if returns.len() == 1
                    && returns[0].address == self.retained.change_address
                    && returns[0].amount.as_zatoshis() == value => {}
            _ => return Err(invalid()),
        }
        Ok(proposal)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest("wholepact:manual-roster-construction-plan:v2", self)
    }
    pub fn completion_expires_at_ms(&self) -> u64 {
        self.retained.completion_expires_at_ms()
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterConstructionRequestV2 {
    pub version: u16,
    pub operation_id: String,
    pub plan: ManualRosterConstructionPlanV2,
    pub current_caller_binding_digest: String,
    pub requested_at_ms: u64,
    pub admission_expires_at_ms: u64,
}
impl ManualRosterConstructionRequestV2 {
    pub fn validate(&self) -> Result<Proposal> {
        let proposal = self.plan.validate()?;
        bounded(self)?;
        crate::error::validate_id(&self.operation_id, "roster construction operation")?;
        hash(&self.current_caller_binding_digest)?;
        let r = &self.plan.retained;
        if self.version != 2
            || self.operation_id == r.operation_id
            || self.operation_id == r.selection.operation_id
            || self.operation_id == r.selection.scope.selection.invocation.operation_id
            || self.requested_at_ms < r.requested_at_ms
            || self.admission_expires_at_ms <= self.requested_at_ms
            || self.admission_expires_at_ms > self.plan.completion_expires_at_ms()
            || self.admission_expires_at_ms - self.requested_at_ms > MAX_PRELIMINARY_DISCLOSURE_MS
        {
            return Err(invalid());
        }
        Ok(proposal)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest("wholepact:manual-roster-construction-request:v2", self)
    }
    pub fn remaining_admission_ms(&self, now: u64) -> Result<u64> {
        self.validate()?;
        remaining(self.requested_at_ms, self.admission_expires_at_ms, now)
    }
}
fn remaining(start: u64, end: u64, now: u64) -> Result<u64> {
    if now < start || now >= end {
        Err(invalid())
    } else {
        Ok(end - now)
    }
}
fn invalid() -> CoreError {
    CoreError::new(
        ErrorCode::InvalidTerms,
        "invalid exact sequential roster construction claims",
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
fn bounded<T: Serialize>(v: &T) -> Result<()> {
    if serde_json::to_vec(v).map_err(|_| invalid())?.len() <= 256 * 1024 {
        Ok(())
    } else {
        Err(invalid())
    }
}

#[cfg(test)]
#[path = "manual_roster_construction_v2_tests.rs"]
pub(crate) mod tests;
