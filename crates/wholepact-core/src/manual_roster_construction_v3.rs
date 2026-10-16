//! Inert common-context contracts. Historical retained facts select a fixed
//! target; they do not establish ancestry, freshness, current spendability or
//! approval. Parsing, validation and hashing never mint a live native, wallet,
//! witness, construction, signing, proving or dispatch capability.
use crate::{
    CoreError, ErrorCode, Proposal, ProposalInput, Result,
    manual_construction::{ManualConstructionInput, PreconstructionProvider},
    manual_enrollment::{BornManualEnrollmentTerms, ManualHostGenerationBinding},
    manual_inventory::MAX_PRELIMINARY_DISCLOSURE_MS,
    manual_roster_construction_v2::{
        ManualRosterConstructionPlanV2, ManualRosterContributionRetentionRequestV2,
        ManualRosterRetentionCommitmentV2,
    },
    manual_roster_exact_input_observation_v1::{
        EXACT_OBSERVATION_MAX_ADDITIONAL_BLOCKS, EXACT_OBSERVATION_MAX_ADMISSION_MS,
        EXACT_OBSERVATION_MAX_OWNERS, EXACT_OBSERVATION_MAX_PARALLEL_SCANS,
        EXACT_OBSERVATION_MAX_SCAN_RUNTIME_MS, EXACT_OBSERVATION_MIN_EXPIRY_MARGIN_BLOCKS,
        EXACT_OBSERVATION_POST_SCAN_RUNWAY_MS, EXACT_OBSERVATION_SOURCE_TTL_MS,
        ExactInputObservationCompletionV1, ExactInputObservationModeV1,
    },
    manual_roster_inventory_v2::OriginalHostRosterAuditV3,
    manual_roster_v2::HostRosterAppendBindingV2,
    proposal::canonical_digest,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const COMMON_CONTEXT_PROFILE_ID: &str = "ironwood-testnet-nu7-candidate";
// Inert protocol profile pinned to zcash_protocol 0.11.0-pre.0. The maintained
// wallet/protocol consumers must independently check their actual branch rules.
pub const COMMON_CONTEXT_NU7_BRANCH_ID: u32 = 0x7719_0ad9;
pub const COMMON_CONTEXT_NU7_ACTIVATION_HEIGHT: u32 = 4_465_026;
pub const COMMON_CONTEXT_MAX_NOTES: usize = 64;
pub const COMMON_CONTEXT_MAX_PLAN_BYTES: usize = 768 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommonContextNetworkV1 {
    Testnet,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommonContextSelectionRuleV1 {
    MaximumOriginalTipPlusOne,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommonContextReadPurposeV1 {
    RevalidateExactRetainedNotesAndCommonContext,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterOriginalRetentionV3 {
    pub request: ManualRosterContributionRetentionRequestV2,
    pub evidence_digest: String,
}
impl ManualRosterOriginalRetentionV3 {
    pub fn validate(&self) -> Result<()> {
        self.request.validate()?;
        hash(&self.evidence_digest)
    }
    pub fn commitment(&self) -> Result<ManualRosterRetentionCommitmentV2> {
        self.validate()?;
        let owner = &self.request.selection.scope.selection.inventory.enrollment;
        Ok(ManualRosterRetentionCommitmentV2 {
            participant_id: owner.scope.participant_id.clone(),
            account_id: owner.identity.account_id.clone(),
            full_viewing_key_digest: owner.identity.full_viewing_key_digest.clone(),
            retention_request_digest: self.request.digest()?,
            retention_evidence_digest: self.evidence_digest.clone(),
        })
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest("wholepact:manual-roster-original-retention:v3", self)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommonContextParticipantV1 {
    pub commitment: ManualRosterRetentionCommitmentV2,
    pub original_host_audit: OriginalHostRosterAuditV3,
    pub roster: HostRosterAppendBindingV2,
    pub original_tip_height: u32,
    pub original_tip_hash_protocol: String,
    pub original_completion_expires_at_ms: u64,
    pub provider_configuration_digest: String,
    pub read_scope_digest: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommonContextReadProfileV1 {
    pub mode: ExactInputObservationModeV1,
    pub completion: ExactInputObservationCompletionV1,
    pub maximum_additional_blocks: u32,
    pub maximum_scan_runtime_ms: u64,
    pub post_scan_runway_ms: u64,
    pub minimum_expiry_margin_blocks: u32,
    pub maximum_parallel_scans: u8,
    pub minimum_confirmations: u32,
}
impl CommonContextReadProfileV1 {
    fn validate(&self) -> Result<()> {
        if self.maximum_additional_blocks == 0
            || self.maximum_additional_blocks > EXACT_OBSERVATION_MAX_ADDITIONAL_BLOCKS
            || self.maximum_scan_runtime_ms != EXACT_OBSERVATION_MAX_SCAN_RUNTIME_MS
            || self.post_scan_runway_ms != EXACT_OBSERVATION_POST_SCAN_RUNWAY_MS
            || self.minimum_expiry_margin_blocks != EXACT_OBSERVATION_MIN_EXPIRY_MARGIN_BLOCKS
            || self.maximum_parallel_scans != EXACT_OBSERVATION_MAX_PARALLEL_SCANS
            || !(1..=100).contains(&self.minimum_confirmations)
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn for_plan(plan: &ManualRosterConstructionPlanV3) -> Result<Self> {
        plan.validate()?;
        Ok(plan.common_context.read_profile.clone())
    }
    pub fn validate_for(&self, plan: &ManualRosterConstructionPlanV3) -> Result<()> {
        plan.validate()?;
        self.validate()?;
        if self != &plan.common_context.read_profile {
            return Err(invalid());
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommonContextProposalV1 {
    pub version: u16,
    pub network_profile_id: String,
    pub network: CommonContextNetworkV1,
    pub consensus_branch_id: u32,
    pub selection_rule: CommonContextSelectionRuleV1,
    pub participants: Vec<CommonContextParticipantV1>,
    pub original_invocation_digest: String,
    pub idempotency_key_digest: String,
    pub economic_intent_digest: String,
    pub agreement_id: String,
    pub agreement_revision: u32,
    pub candidate_revision: u64,
    pub host: ManualHostGenerationBinding,
    pub principal_id: String,
    pub anchor_height: u32,
    pub anchor_hash_protocol: String,
    pub anchor_root: String,
    pub reference_tip_height: u32,
    pub reference_tip_hash_protocol: String,
    pub target_height: u32,
    pub expiry_height: u32,
    pub completion_expires_at_ms: u64,
    pub provider: PreconstructionProvider,
    pub operator_name: String,
    pub operator_destination: String,
    pub retention_policy: String,
    pub maximum_owners: u8,
    pub maximum_notes: u16,
    pub read_profile: CommonContextReadProfileV1,
}
impl CommonContextProposalV1 {
    /// Historical deterministic composition only. In particular, a caller
    /// cannot select a newer target from a fresh read or replace original data.
    pub fn from_originals(originals: &[ManualRosterOriginalRetentionV3]) -> Result<Self> {
        if !(2..=EXACT_OBSERVATION_MAX_OWNERS).contains(&originals.len()) {
            return Err(invalid());
        }
        bounded(originals, COMMON_CONTEXT_MAX_PLAN_BYTES)?;
        let first = &originals[0].request;
        let selection = &first.selection.scope.selection;
        let inventory = &selection.inventory;
        let enrollment = &inventory.enrollment;
        let economics = &selection.economic_intent;
        if economics.participants.len() != originals.len() {
            return Err(invalid());
        }
        let mut participants = Vec::with_capacity(originals.len());
        let mut accounts = BTreeSet::new();
        let mut viewing_keys = BTreeSet::new();
        let mut evidence = BTreeSet::new();
        let mut requests = BTreeSet::new();
        let mut input_ids = BTreeSet::new();
        let mut nullifiers = BTreeSet::new();
        let mut wallet_destinations = BTreeSet::new();
        let mut directory_identities = BTreeSet::new();
        let mut maximum_blocks = EXACT_OBSERVATION_MAX_ADDITIONAL_BLOCKS;
        let mut minimum_confirmations = 1;
        for (original, expected) in originals.iter().zip(&economics.participants) {
            original.validate()?;
            let request = &original.request;
            let scope = &request.selection.scope.selection;
            let source = &scope.inventory;
            let owner = &source.enrollment;
            let actual = original.commitment()?;
            if actual.participant_id != expected.participant_id
                || actual.account_id != expected.account_id
                || !accounts.insert(actual.account_id.clone())
                || !viewing_keys.insert(actual.full_viewing_key_digest.clone())
                || !requests.insert(actual.retention_request_digest.clone())
                || !evidence.insert(actual.retention_evidence_digest.clone())
                || !wallet_destinations.insert(&source.wallet_destination)
                || !directory_identities
                    .insert(&source.attachment.selected.directory_identity_digest)
                || scope.invocation != selection.invocation
                || scope.economic_intent != *economics
                || owner.identity.network_profile_id != COMMON_CONTEXT_PROFILE_ID
                || owner.host != enrollment.host
                || owner.scope.principal_id != enrollment.scope.principal_id
                || source.provider != inventory.provider
                || source.operator_name != inventory.operator_name
                || source.operator_destination != inventory.operator_destination
                || source.retention_policy != inventory.retention_policy
                || request.selection_context.anchor_height != first.selection_context.anchor_height
                || request.selection_context.anchor_hash_protocol
                    != first.selection_context.anchor_hash_protocol
                || request.selection_context.anchor_root != first.selection_context.anchor_root
            {
                return Err(invalid());
            }
            for input in &request.selected_inputs {
                if !input_ids.insert(&input.input_id) || !nullifiers.insert(&input.nullifier) {
                    return Err(invalid());
                }
            }
            maximum_blocks = maximum_blocks.min(source.maximum_blocks);
            minimum_confirmations = minimum_confirmations.max(source.minimum_confirmations);
            participants.push(CommonContextParticipantV1 {
                commitment: actual,
                original_host_audit: request
                    .selection
                    .scope
                    .provenance
                    .original_host_audit
                    .clone(),
                roster: request.selection.scope.provenance.roster.clone(),
                original_tip_height: request.selection_context.tip_height,
                original_tip_hash_protocol: request.selection_context.tip_hash_protocol.clone(),
                original_completion_expires_at_ms: request.completion_expires_at_ms(),
                provider_configuration_digest: canonical_digest(
                    "wholepact:common-context-provider-configuration:v1",
                    &source.provider,
                )?,
                // Complete original inventory binds provider, wallet/import,
                // attachment, operator/read destination and retention scope.
                read_scope_digest: canonical_digest(
                    "wholepact:common-context-read-scope:v1",
                    source,
                )?,
            });
        }
        if input_ids.len() > COMMON_CONTEXT_MAX_NOTES {
            return Err(invalid());
        }
        let reference = participants
            .iter()
            .max_by_key(|p| p.original_tip_height)
            .ok_or_else(invalid)?;
        let value = Self {
            version: 1,
            network_profile_id: economics.agreement.network_profile_id.clone(),
            network: CommonContextNetworkV1::Testnet,
            consensus_branch_id: COMMON_CONTEXT_NU7_BRANCH_ID,
            selection_rule: CommonContextSelectionRuleV1::MaximumOriginalTipPlusOne,
            original_invocation_digest: selection.invocation.digest()?,
            idempotency_key_digest: selection.invocation.idempotency_key_digest.clone(),
            economic_intent_digest: economics.digest()?,
            agreement_id: economics.agreement.agreement_id.clone(),
            agreement_revision: economics.agreement.revision,
            candidate_revision: economics.candidate_revision,
            host: enrollment.host.clone(),
            principal_id: enrollment.scope.principal_id.clone(),
            anchor_height: first.selection_context.anchor_height,
            anchor_hash_protocol: first.selection_context.anchor_hash_protocol.clone(),
            anchor_root: first.selection_context.anchor_root.clone(),
            reference_tip_height: reference.original_tip_height,
            reference_tip_hash_protocol: reference.original_tip_hash_protocol.clone(),
            target_height: reference
                .original_tip_height
                .checked_add(1)
                .ok_or_else(invalid)?,
            expiry_height: economics.expiry_height,
            completion_expires_at_ms: participants
                .iter()
                .map(|p| p.original_completion_expires_at_ms)
                .min()
                .ok_or_else(invalid)?,
            participants,
            provider: inventory.provider.clone(),
            operator_name: inventory.operator_name.clone(),
            operator_destination: inventory.operator_destination.clone(),
            retention_policy: inventory.retention_policy.clone(),
            maximum_owners: EXACT_OBSERVATION_MAX_OWNERS as u8,
            maximum_notes: COMMON_CONTEXT_MAX_NOTES as u16,
            read_profile: CommonContextReadProfileV1 {
                mode: ExactInputObservationModeV1::AppendOnlySameOriginalAnchor,
                completion: ExactInputObservationCompletionV1::AdmittedBoundedCompletion,
                maximum_additional_blocks: maximum_blocks,
                maximum_scan_runtime_ms: EXACT_OBSERVATION_MAX_SCAN_RUNTIME_MS,
                post_scan_runway_ms: EXACT_OBSERVATION_POST_SCAN_RUNWAY_MS,
                minimum_expiry_margin_blocks: EXACT_OBSERVATION_MIN_EXPIRY_MARGIN_BLOCKS,
                maximum_parallel_scans: EXACT_OBSERVATION_MAX_PARALLEL_SCANS,
                minimum_confirmations,
            },
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        bounded(self, 128 * 1024)?;
        self.read_profile.validate()?;
        for value in [
            &self.original_invocation_digest,
            &self.idempotency_key_digest,
            &self.economic_intent_digest,
            &self.anchor_hash_protocol,
            &self.anchor_root,
            &self.reference_tip_hash_protocol,
        ] {
            hash(value)?;
        }
        for value in [
            &self.host.inventory_digest,
            &self.host.generation_plan_digest,
            &self.host.financial_journal_origin_digest,
            &self.host.destination_identity_digest,
            &self.host.inherited_identity_digest,
        ] {
            hash(value)?;
        }
        for value in [
            &self.operator_name,
            &self.retention_policy,
            &self.provider.source_id,
            &self.provider.endpoint,
            &self.host.profile_id,
        ] {
            text(value, 2048)?;
        }
        absolute(&self.operator_destination)?;
        absolute(&self.host.canonical_root)?;
        text(&self.host.store_destination_identity, 4096)?;
        if self.provider.trust_profile != "single_tls_provider_report_not_consensus"
            || !self.provider.endpoint.starts_with("https://")
            || self.provider.endpoint.ends_with('/')
        {
            return Err(invalid());
        }
        crate::error::validate_id(&self.agreement_id, "common-context agreement")?;
        crate::error::validate_id(&self.principal_id, "common-context principal")?;
        if self.version != 1
            || self.network_profile_id != COMMON_CONTEXT_PROFILE_ID
            || self.consensus_branch_id != COMMON_CONTEXT_NU7_BRANCH_ID
            || self.maximum_owners != EXACT_OBSERVATION_MAX_OWNERS as u8
            || self.maximum_notes != COMMON_CONTEXT_MAX_NOTES as u16
            || !(2..=EXACT_OBSERVATION_MAX_OWNERS).contains(&self.participants.len())
            || self.agreement_revision == 0
            || self.candidate_revision == 0
            || self.anchor_height < COMMON_CONTEXT_NU7_ACTIVATION_HEIGHT
            || self.anchor_height >= self.target_height
            || self.reference_tip_height.checked_add(1) != Some(self.target_height)
            || self.target_height > self.expiry_height
            || self.expiry_height >= 500_000_000
            || self
                .reference_tip_height
                .checked_add(self.read_profile.minimum_expiry_margin_blocks)
                .is_none_or(|h| h >= self.expiry_height)
            || self.anchor_hash_protocol == "0".repeat(64)
            || self.completion_expires_at_ms == 0
            || self.completion_expires_at_ms > i64::MAX as u64
        {
            return Err(invalid());
        }
        let mut previous: Option<&str> = None;
        let mut tips = BTreeMap::new();
        let mut accounts = BTreeSet::new();
        let mut keys = BTreeSet::new();
        let mut requests = BTreeSet::new();
        let mut evidence = BTreeSet::new();
        for p in &self.participants {
            p.original_host_audit.validate()?;
            p.roster.validate_for_host(&self.host)?;
            let c = &p.commitment;
            crate::error::validate_id(&c.participant_id, "common-context participant")?;
            for h in [
                &c.account_id,
                &c.full_viewing_key_digest,
                &c.retention_request_digest,
                &c.retention_evidence_digest,
                &p.original_tip_hash_protocol,
                &p.provider_configuration_digest,
                &p.read_scope_digest,
            ] {
                hash(h)?;
            }
            if previous.is_some_and(|old| old >= c.participant_id.as_str())
                || !accounts.insert(&c.account_id)
                || !keys.insert(&c.full_viewing_key_digest)
                || !requests.insert(&c.retention_request_digest)
                || !evidence.insert(&c.retention_evidence_digest)
                || p.original_tip_height < self.anchor_height
                || p.original_tip_height > self.reference_tip_height
                || self.reference_tip_height - p.original_tip_height
                    > self.read_profile.maximum_additional_blocks
                || p.original_completion_expires_at_ms < self.completion_expires_at_ms
                || p.original_completion_expires_at_ms > i64::MAX as u64
                || tips
                    .insert(p.original_tip_height, &p.original_tip_hash_protocol)
                    .is_some_and(|old| old != &p.original_tip_hash_protocol)
                || p.provider_configuration_digest
                    != canonical_digest(
                        "wholepact:common-context-provider-configuration:v1",
                        &self.provider,
                    )?
            {
                return Err(invalid());
            }
            previous = Some(&c.participant_id);
        }
        if tips.last_key_value()
            != Some((
                &self.reference_tip_height,
                &&self.reference_tip_hash_protocol,
            ))
            || self
                .participants
                .iter()
                .map(|p| p.original_completion_expires_at_ms)
                .min()
                != Some(self.completion_expires_at_ms)
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn validate_for(&self, originals: &[ManualRosterOriginalRetentionV3]) -> Result<()> {
        self.validate()?;
        if self != &Self::from_originals(originals)? {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest("wholepact:common-construction-context-proposal:v1", self)
    }
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let value: Self = crate::parse_typed_json(bytes)?;
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterConstructionPlanV3 {
    pub version: u16,
    pub retained: ManualRosterContributionRetentionRequestV2,
    pub retained_evidence_digest: String,
    pub proposal: ProposalInput,
    pub participants: Vec<ManualRosterRetentionCommitmentV2>,
    pub originals: Vec<ManualRosterOriginalRetentionV3>,
    pub common_context: CommonContextProposalV1,
    pub common_context_digest: String,
}
impl ManualRosterConstructionPlanV3 {
    pub fn enrollment(&self) -> &BornManualEnrollmentTerms {
        &self.retained.selection.scope.selection.inventory.enrollment
    }
    pub fn selected_inputs(&self) -> &[ManualConstructionInput] {
        &self.retained.selected_inputs
    }
    pub fn invocation_digest(&self) -> Result<String> {
        self.retained.selection.scope.selection.invocation.digest()
    }
    pub fn completion_expires_at_ms(&self) -> u64 {
        self.common_context.completion_expires_at_ms
    }
    pub fn completion_deadline_ms(&self) -> u64 {
        self.completion_expires_at_ms()
    }
    pub fn maximum_net_debit_zatoshis(&self) -> Result<u64> {
        let proposal = self.validate()?;
        proposal
            .manifest()
            .participants
            .iter()
            .find(|p| {
                p.account_id == self.enrollment().identity.account_id
                    && p.participant_id == self.enrollment().scope.participant_id
            })
            .map(|p| p.maximum_net_debit.as_zatoshis())
            .ok_or_else(invalid)
    }
    pub fn validate(&self) -> Result<Proposal> {
        bounded(self, COMMON_CONTEXT_MAX_PLAN_BYTES)?;
        self.retained.validate()?;
        hash(&self.retained_evidence_digest)?;
        self.common_context.validate_for(&self.originals)?;
        if self.version != 3
            || self.common_context_digest != self.common_context.digest()?
            || self.participants
                != self
                    .common_context
                    .participants
                    .iter()
                    .map(|p| p.commitment.clone())
                    .collect::<Vec<_>>()
            || !self.originals.iter().any(|o| {
                o.request == self.retained && o.evidence_digest == self.retained_evidence_digest
            })
        {
            return Err(invalid());
        }
        let manifest = &self.proposal.manifest;
        if manifest.outputs.len() > 64
            || !manifest.agreement.extensions.is_empty()
            || manifest.participants.iter().any(|p| !p.charges.is_empty())
            || manifest.agreement.privacy_profile.mode != crate::PrivacyMode::DeclaredOperator
            || !manifest
                .agreement
                .privacy_profile
                .dedicated_accounts_required
            || manifest.agreement.privacy_profile.proving_operator.as_ref()
                != Some(&self.common_context.operator_name)
        {
            return Err(invalid());
        }
        // Reuse the unchanged, pure per-owner economics/input/return validator.
        // This local temporary value is never a V2 approval, signature or owner.
        let mut checked = None;
        for original in &self.originals {
            let plan = ManualRosterConstructionPlanV2 {
                version: 2,
                retained: original.request.clone(),
                retained_evidence_digest: original.evidence_digest.clone(),
                proposal: self.proposal.clone(),
                participants: self.participants.clone(),
            };
            checked = Some(plan.validate()?);
        }
        checked.ok_or_else(invalid)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest("wholepact:manual-roster-construction-plan:v3", self)
    }
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let value: Self = crate::parse_typed_json(bytes)?;
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterConstructionRequestV3 {
    pub version: u16,
    pub operation_id: String,
    pub plan: ManualRosterConstructionPlanV3,
    pub current_caller_binding_digest: String,
    pub requested_at_ms: u64,
    pub admission_expires_at_ms: u64,
}
impl ManualRosterConstructionRequestV3 {
    pub fn validate(&self) -> Result<Proposal> {
        let proposal = self.plan.validate()?;
        bounded(self, crate::strict_json::MAX_JSON_BYTES)?;
        hash(&self.current_caller_binding_digest)?;
        validate_operation(&self.plan, &self.operation_id, self.requested_at_ms)?;
        if self.version != 3
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
        canonical_digest("wholepact:manual-roster-construction-request:v3", self)
    }
    pub fn remaining_admission_ms(&self, now: u64) -> Result<u64> {
        self.validate()?;
        remaining(self.requested_at_ms, self.admission_expires_at_ms, now)
    }
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let value: Self = crate::parse_typed_json(bytes)?;
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RosterCommonContextReadRequestV1 {
    pub version: u16,
    pub operation_id: String,
    pub plan: ManualRosterConstructionPlanV3,
    pub original_durable_receipt_digest: String,
    pub witness_plan_approval_digest: String,
    pub purpose: CommonContextReadPurposeV1,
    pub profile: CommonContextReadProfileV1,
    pub current_caller_binding_digest: String,
    pub requested_at_ms: u64,
    pub admission_expires_at_ms: u64,
    /// An additional short ceiling, never a replacement for an original Instant.
    pub completion_expires_at_ms: u64,
}
impl RosterCommonContextReadRequestV1 {
    pub fn validate(&self) -> Result<()> {
        self.plan.validate()?;
        self.profile.validate_for(&self.plan)?;
        bounded(self, crate::strict_json::MAX_JSON_BYTES)?;
        validate_operation(&self.plan, &self.operation_id, self.requested_at_ms)?;
        for h in [
            &self.original_durable_receipt_digest,
            &self.witness_plan_approval_digest,
            &self.current_caller_binding_digest,
        ] {
            hash(h)?;
        }
        if self.version != 1
            || self.admission_expires_at_ms <= self.requested_at_ms
            || self.admission_expires_at_ms - self.requested_at_ms
                > EXACT_OBSERVATION_MAX_ADMISSION_MS
            || self.admission_expires_at_ms > self.completion_expires_at_ms
            || self.completion_expires_at_ms > self.plan.completion_expires_at_ms()
            || self.completion_expires_at_ms <= self.requested_at_ms
            || self.completion_expires_at_ms - self.requested_at_ms
                <= self.profile.post_scan_runway_ms
            || self.completion_expires_at_ms - self.requested_at_ms
                > EXACT_OBSERVATION_SOURCE_TTL_MS
        {
            return Err(invalid());
        }
        self.maximum_additional_blocks()?;
        Ok(())
    }
    pub fn maximum_observed_tip(&self) -> Result<u32> {
        self.plan
            .common_context
            .expiry_height
            .checked_sub(self.profile.minimum_expiry_margin_blocks)
            .and_then(|h| h.checked_sub(1))
            .ok_or_else(invalid)
    }
    pub fn maximum_additional_blocks(&self) -> Result<u32> {
        let own_tip = self.plan.retained.selection_context.tip_height;
        let maximum = self
            .maximum_observed_tip()?
            .checked_sub(own_tip)
            .ok_or_else(invalid)?
            .min(self.profile.maximum_additional_blocks)
            .min(
                self.plan
                    .retained
                    .selection
                    .scope
                    .selection
                    .inventory
                    .maximum_blocks,
            )
            .min(EXACT_OBSERVATION_MAX_ADDITIONAL_BLOCKS);
        if self
            .plan
            .common_context
            .reference_tip_height
            .checked_sub(own_tip)
            .is_none_or(|distance| distance > maximum)
        {
            return Err(invalid());
        }
        Ok(maximum)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest("wholepact:roster-common-context-read-request:v1", self)
    }
    pub fn remaining_admission_ms(&self, now: u64) -> Result<u64> {
        self.validate()?;
        remaining(self.requested_at_ms, self.admission_expires_at_ms, now)
    }
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let value: Self = crate::parse_typed_json(bytes)?;
        value.validate()?;
        Ok(value)
    }
}
fn validate_operation(
    plan: &ManualRosterConstructionPlanV3,
    operation: &str,
    requested: u64,
) -> Result<()> {
    crate::error::validate_id(operation, "common-context operation")?;
    if requested == 0
        || requested > i64::MAX as u64
        || plan.originals.iter().any(|o| {
            operation == o.request.operation_id
                || operation == o.request.selection.operation_id
                || operation == o.request.selection.scope.selection.invocation.operation_id
                || requested < o.request.requested_at_ms
        })
    {
        return Err(invalid());
    }
    Ok(())
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
        "invalid immutable common construction context or exact V3 roster",
    )
}
fn hash(value: &str) -> Result<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(invalid())
    }
}
fn text(value: &str, maximum: usize) -> Result<()> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        Err(invalid())
    } else {
        Ok(())
    }
}
fn absolute(value: &str) -> Result<()> {
    text(value, 4096)?;
    if !value.starts_with('/')
        || value == "/"
        || value.ends_with('/')
        || value
            .split('/')
            .skip(1)
            .any(|p| p.is_empty() || p == "." || p == "..")
    {
        Err(invalid())
    } else {
        Ok(())
    }
}
fn bounded<T: Serialize + ?Sized>(value: &T, maximum: usize) -> Result<()> {
    if serde_json::to_vec(value).map_err(|_| invalid())?.len() <= maximum {
        Ok(())
    } else {
        Err(invalid())
    }
}

#[cfg(test)]
#[path = "manual_roster_construction_v3_tests.rs"]
pub(crate) mod tests;
