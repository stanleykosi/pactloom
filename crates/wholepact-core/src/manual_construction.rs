//! Pure claims for one bounded, non-signing manual construction attempt.
//! Validation proves arithmetic and exact commitments only. No data in this
//! module creates a native decision, wallet observation, witness admission or
//! authority to disclose, construct, sign, prove, dispatch or recover work.
use crate::{
    CoreError, ErrorCode, MAX_MONEY, Proposal, ProposalInput, Result,
    manual_enrollment::{BornManualAction, BornManualActionIntent, BornManualEnrollmentTerms},
    proposal::canonical_digest,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Maximum original non-signing completion window. This never extends any
/// current native, disclosure, session or admission window.
pub const MAX_CONSTRUCTION_INVOCATION_MS: u64 = 2 * 60 * 60 * 1000;

fn invalid() -> CoreError {
    CoreError::new(
        ErrorCode::InvalidTerms,
        "invalid exact manual construction claims",
    )
}
fn text(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 2048 || value.chars().any(char::is_control) {
        return Err(invalid());
    }
    Ok(())
}
fn hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    Ok(())
}
fn absolute(value: &str) -> Result<()> {
    text(value)?;
    if !value.starts_with('/')
        || value == "/"
        || value.ends_with('/')
        || value
            .split('/')
            .skip(1)
            .any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err(invalid());
    }
    Ok(())
}
fn bounded<T: Serialize>(value: &T) -> Result<()> {
    if serde_json::to_vec(value).map_err(|_| invalid())?.len() > 128 * 1024 {
        return Err(CoreError::new(
            ErrorCode::ResourceLimit,
            "manual construction claims exceed bound",
        ));
    }
    Ok(())
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreconstructionBirthday {
    pub prior_height: u32,
    pub prior_block_hash: String,
    pub sapling_tree: String,
    pub orchard_tree: String,
    pub ironwood_tree: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreconstructionProvider {
    pub source_id: String,
    pub endpoint: String,
    pub trust_profile: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreconstructionScope {
    pub schema_version: u16,
    pub proposal: ProposalInput,
    pub account_id: String,
    pub participant_id: String,
    pub profile_id: String,
    pub principal_id: String,
    pub operator_name: String,
    pub operator_destination: String,
    pub wallet_destination: String,
    pub reviewer_account_ids: Vec<String>,
    pub privacy_domain: String,
    pub purpose: String,
    pub retention_policy: String,
    pub provider: PreconstructionProvider,
    pub minimum_confirmations: u32,
    pub maximum_blocks: u32,
    pub anchor_height: u32,
    pub maximum_net_debit_zatoshis: u64,
    pub birthday: PreconstructionBirthday,
}

impl PreconstructionScope {
    pub fn validate(&self) -> Result<Proposal> {
        bounded(self)?;
        let s = self;
        let proposal = Proposal::validate(s.proposal.clone()).map_err(|_| invalid())?;
        if s.schema_version != 1
            || s.purpose != "construct_exact_accepted_candidate"
            || s.provider.trust_profile != "single_tls_provider_report_not_consensus"
            || !s.provider.endpoint.starts_with("https://")
            || s.provider.endpoint.ends_with('/')
            || s.minimum_confirmations == 0
            || s.minimum_confirmations > 100
            || !(1..=1000).contains(&s.maximum_blocks)
            || s.anchor_height == 0
            || s.birthday.prior_height >= s.anchor_height
            || s.maximum_net_debit_zatoshis == 0
            || s.reviewer_account_ids.is_empty()
            || s.reviewer_account_ids.len() > 32
        {
            return Err(invalid());
        }
        for text in [
            &s.account_id,
            &s.participant_id,
            &s.profile_id,
            &s.principal_id,
            &s.operator_name,
            &s.operator_destination,
            &s.wallet_destination,
            &s.privacy_domain,
            &s.retention_policy,
            &s.provider.source_id,
            &s.provider.endpoint,
        ] {
            if text.is_empty() || text.len() > 2048 || text.chars().any(char::is_control) {
                return Err(invalid());
            }
        }
        if !std::path::Path::new(&s.wallet_destination).is_absolute()
            || !std::path::Path::new(&s.operator_destination).is_absolute()
        {
            return Err(invalid());
        }
        hash(&s.birthday.prior_block_hash)?;
        for tree in [
            &s.birthday.sapling_tree,
            &s.birthday.orchard_tree,
            &s.birthday.ironwood_tree,
        ] {
            if tree.len() > 32 * 1024
                || tree.len() % 2 != 0
                || !tree.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(invalid());
            }
        }
        let roster: BTreeSet<_> = s.reviewer_account_ids.iter().collect();
        let actual: BTreeSet<_> = proposal
            .manifest()
            .participants
            .iter()
            .map(|p| &p.account_id)
            .collect();
        if roster.len() != s.reviewer_account_ids.len() || roster != actual {
            return Err(invalid());
        }
        let own = proposal
            .manifest()
            .participants
            .iter()
            .find(|p| p.account_id == s.account_id && p.participant_id == s.participant_id)
            .ok_or(invalid())?;
        if own.maximum_net_debit.as_zatoshis() != s.maximum_net_debit_zatoshis
            || proposal
                .manifest()
                .agreement
                .privacy_profile
                .proving_operator
                .as_ref()
                .is_some_and(|p| p != &s.operator_name)
        {
            return Err(invalid());
        }
        Ok(proposal)
    }
}

/// The payment-effect scope is deliberately separate from a transport recipient
/// or disclosure scope. Every output allocation, including returns and charges,
/// and every declared recipient and participant charge effect is committed.
/// Array order is retained: there is no second normalization of approved terms.
pub fn construction_payment_scope_digest(input: &ProposalInput) -> Result<String> {
    let proposal = Proposal::validate(input.clone())?;
    construction_recipient_scope_digest(&proposal)
}
pub fn construction_recipient_scope_digest(proposal: &Proposal) -> Result<String> {
    let m = proposal.manifest();
    let charges: Vec<_> = m
        .participants
        .iter()
        .map(|p| (&p.participant_id, &p.account_id, &p.charges))
        .collect();
    canonical_digest(
        "wholepact:born-manual-construction-recipient-scope:v1",
        &(&m.agreement.recipients, &m.outputs, charges),
    )
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualParticipantAttachment {
    pub account_id: String,
    pub canonical_directory: String,
    pub directory_identity_digest: String,
    pub journal_origin_digest: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualConstructionAttachmentBinding {
    pub version: u16,
    pub original_primary_journal_origin_digest: String,
    pub predecessor_registry_digest: String,
    pub current_registry_digest: String,
    pub latest_extension_digest: String,
    pub selected: ManualParticipantAttachment,
}
impl ManualConstructionAttachmentBinding {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(invalid());
        }
        for value in [
            &self.original_primary_journal_origin_digest,
            &self.predecessor_registry_digest,
            &self.current_registry_digest,
            &self.latest_extension_digest,
            &self.selected.account_id,
            &self.selected.directory_identity_digest,
            &self.selected.journal_origin_digest,
        ] {
            hash(value)?;
        }
        absolute(&self.selected.canonical_directory)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest("wholepact:manual-construction-attachment-binding:v1", self)
    }
}

/// Only the explicitly versioned continued session is supported by this slice.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualConstructionAttempt {
    pub version: u16,
    pub continuation_digest: String,
    pub attempt_sequence: u64,
}
impl ManualConstructionAttempt {
    pub fn validate(&self) -> Result<()> {
        if self.version != 2 || !(2..=i64::MAX as u64).contains(&self.attempt_sequence) {
            return Err(invalid());
        }
        hash(&self.continuation_digest)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualConstructionParticipant {
    pub participant_id: String,
    pub account_id: String,
}
/// Common across ALL participants. Per-account reservations cannot be spliced
/// together across invocations, revisions, checkpoints or original deadlines.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualConstructionInvocation {
    pub version: u16,
    pub operation_id: String,
    pub idempotency_key_digest: String,
    pub invocation_nonce: String,
    pub candidate_id: String,
    pub candidate_revision: u64,
    pub proposal_id: String,
    pub manifest_digest: String,
    /// Strictly increasing participant ID, exact account bijection.
    pub participants: Vec<ManualConstructionParticipant>,
    pub checkpoint_destination: String,
    pub requested_at_ms: u64,
    pub construction_expires_at_ms: u64,
}
impl ManualConstructionInvocation {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 || self.candidate_revision == 0
            || self.participants.len() < 2 || self.participants.len() > 32
            || self.requested_at_ms == 0 || self.construction_expires_at_ms <= self.requested_at_ms
            // Product-specific non-signing consent is always finite, even when
            // the original account's generic permit limit is much larger.
            || self.construction_expires_at_ms - self.requested_at_ms > MAX_CONSTRUCTION_INVOCATION_MS
        {
            return Err(invalid());
        }
        for value in [&self.operation_id, &self.candidate_id, &self.proposal_id] {
            text(value)?;
        }
        for value in [
            &self.idempotency_key_digest,
            &self.invocation_nonce,
            &self.manifest_digest,
        ] {
            hash(value)?;
        }
        absolute(&self.checkpoint_destination)?;
        let mut previous = None;
        let mut accounts = BTreeSet::new();
        for p in &self.participants {
            text(&p.participant_id)?;
            hash(&p.account_id)?;
            if previous.is_some_and(|id: &str| id >= p.participant_id.as_str())
                || !accounts.insert(&p.account_id)
            {
                return Err(invalid());
            }
            previous = Some(p.participant_id.as_str());
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest("wholepact:manual-construction-common-invocation:v1", self)
    }
    fn validate_proposal(&self, proposal: &Proposal) -> Result<()> {
        self.validate()?;
        if self.proposal_id != proposal.input().proposal_id
            || self.manifest_digest != proposal.manifest_digest()
        {
            return Err(invalid());
        }
        let actual: BTreeMap<_, _> = proposal
            .manifest()
            .participants
            .iter()
            .map(|p| (&p.participant_id, &p.account_id))
            .collect();
        let requested: BTreeMap<_, _> = self
            .participants
            .iter()
            .map(|p| (&p.participant_id, &p.account_id))
            .collect();
        if actual != requested {
            return Err(invalid());
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualPreselectionRequest {
    pub version: u16,
    pub enrollment: BornManualEnrollmentTerms,
    pub enrollment_ref: String,
    pub witness_extension_digest: String,
    pub attempt: ManualConstructionAttempt,
    pub operation_id: String,
    pub candidate_id: String,
    pub candidate_revision: u64,
    pub invocation: ManualConstructionInvocation,
    /// Genuine final pair's binding, checked by its native issuer. Original
    /// enrollment transport remains historical and cannot fill this field.
    pub current_caller_binding_digest: String,
    pub scope: PreconstructionScope,
    pub attachment: ManualConstructionAttachmentBinding,
    pub invocation_nonce: String,
}
impl ManualPreselectionRequest {
    pub fn validate(&self) -> Result<Proposal> {
        bounded(self)?;
        self.enrollment.validate()?;
        self.attempt.validate()?;
        self.attachment.validate()?;
        for h in [
            &self.enrollment_ref,
            &self.witness_extension_digest,
            &self.invocation_nonce,
            &self.current_caller_binding_digest,
        ] {
            hash(h)?;
        }
        text(&self.operation_id)?;
        if self.version != 1
            || self.candidate_id != self.invocation.candidate_id
            || self.candidate_revision != self.invocation.candidate_revision
            || self.invocation_nonce != self.invocation.invocation_nonce
            || self.operation_id == self.invocation.operation_id
        {
            return Err(invalid());
        }
        let proposal = validate_manual_construction_scope(
            &self.enrollment,
            &self.scope,
            &self.attachment,
            &self.invocation,
        )?;
        Ok(proposal)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest("wholepact:manual-preselection-request:v1", self)
    }
}
/// Pure stable original-owner review conjunction. No current session/caller is
/// assumed here; each later preselection must add its independently current
/// attempt and authenticated native channel. Original policy membership remains
/// the authority ledger's separate check against its unchanged original policy.
pub fn validate_manual_construction_scope(
    e: &BornManualEnrollmentTerms,
    s: &PreconstructionScope,
    attachment: &ManualConstructionAttachmentBinding,
    invocation: &ManualConstructionInvocation,
) -> Result<Proposal> {
    e.validate()?;
    attachment.validate()?;
    let proposal = s.validate()?;
    invocation.validate_proposal(&proposal)?;
    let m = proposal.manifest();
    let own = m
        .participants
        .iter()
        .find(|p| {
            p.participant_id == e.scope.participant_id && p.account_id == e.identity.account_id
        })
        .ok_or_else(invalid)?;
    let actual_debit = proposal
        .accounting()
        .participant_net_debits
        .get(&own.participant_id)
        .ok_or_else(invalid)?
        .as_zatoshis();
    if s.account_id != e.identity.account_id
        || s.participant_id != e.scope.participant_id
        || s.profile_id != e.host.profile_id
        || s.principal_id != e.scope.principal_id
        || s.privacy_domain != e.scope.privacy_domain
        || m.agreement.agreement_id != e.scope.agreement_id
        || m.agreement.obligation_id != e.scope.obligation_id
        || m.agreement.network_profile_id != e.identity.network_profile_id
        || s.maximum_net_debit_zatoshis > e.scope.per_operation_limit_zatoshis
        || actual_debit > e.scope.per_operation_limit_zatoshis
        || actual_debit > e.scope.aggregate_budget_zatoshis
        || own.fee_share.as_zatoshis() > e.scope.maximum_fee_share_zatoshis
        || m.transaction_fee.as_zatoshis() > e.scope.maximum_transaction_fee_zatoshis
        || attachment.original_primary_journal_origin_digest
            != e.host.financial_journal_origin_digest
        || attachment.selected.account_id != e.identity.account_id
        || std::path::Path::new(&attachment.selected.canonical_directory)
            .join("wallet.sqlite")
            .to_str()
            != Some(s.wallet_destination.as_str())
        || invocation.checkpoint_destination != s.operator_destination
        || invocation.requested_at_ms < e.issued_at_ms
        || invocation.construction_expires_at_ms > e.scope.expires_at_ms
        || invocation.construction_expires_at_ms - invocation.requested_at_ms
            > e.scope.maximum_permit_lifetime_ms
        || !e
            .scope
            .recipient_scope_digests
            .contains(&construction_recipient_scope_digest(&proposal)?)
    {
        return Err(invalid());
    }
    Ok(proposal)
}

/// Exactly the maintained wallet's available preconstruction evidence. Action
/// indices are randomized-builder output and therefore cannot be invented here.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualConstructionInput {
    pub input_id: String,
    pub nullifier: String,
    pub value_zatoshis: u64,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualSelectionContext {
    pub tip_height: u32,
    pub tip_hash_protocol: String,
    pub anchor_height: u32,
    pub anchor_hash_protocol: String,
    pub anchor_root: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualConstructionPlan {
    pub version: u16,
    pub preselection: ManualPreselectionRequest,
    pub preselection_record_digest: String,
    pub operation_id: String,
    pub idempotency_key_digest: String,
    pub invocation_nonce: String,
    /// Strictly increasing input_id, exact own-account manifest input bijection.
    pub selected_inputs: Vec<ManualConstructionInput>,
    pub selection_context: ManualSelectionContext,
    pub local_exclusion_digest: String,
    pub requested_at_ms: u64,
    pub construction_expires_at_ms: u64,
}
impl ManualConstructionPlan {
    pub fn validate(&self) -> Result<Proposal> {
        bounded(self)?;
        let proposal = self.preselection.validate()?;
        text(&self.operation_id)?;
        for h in [
            &self.preselection_record_digest,
            &self.idempotency_key_digest,
            &self.invocation_nonce,
            &self.local_exclusion_digest,
            &self.selection_context.tip_hash_protocol,
            &self.selection_context.anchor_hash_protocol,
            &self.selection_context.anchor_root,
        ] {
            hash(h)?;
        }
        let i = &self.preselection.invocation;
        if self.version != 1
            || self.operation_id == self.preselection.operation_id
            || self.operation_id == i.operation_id
            || self.invocation_nonce != i.invocation_nonce
            || self.requested_at_ms != i.requested_at_ms
            || self.construction_expires_at_ms != i.construction_expires_at_ms
            || self.selection_context.anchor_height != self.preselection.scope.anchor_height
            || self.selection_context.tip_height < self.selection_context.anchor_height
            || self.selected_inputs.is_empty()
            || self.selected_inputs.len() > 256
        {
            return Err(invalid());
        }
        let e = &self.preselection.enrollment;
        let claimed: BTreeMap<_, _> = proposal
            .manifest()
            .inputs
            .iter()
            .filter(|input| {
                input.account_id == e.identity.account_id
                    && input.participant_id == e.scope.participant_id
            })
            .map(|input| (input.input_id.as_str(), input.amount.as_zatoshis()))
            .collect();
        let mut observed = BTreeMap::new();
        let mut nullifiers = BTreeSet::new();
        let mut previous = None;
        let mut total = 0u64;
        for input in &self.selected_inputs {
            text(&input.input_id)?;
            hash(&input.nullifier)?;
            if input.value_zatoshis == 0
                || input.value_zatoshis > MAX_MONEY
                || previous.is_some_and(|id: &str| id >= input.input_id.as_str())
                || !nullifiers.insert(&input.nullifier)
            {
                return Err(invalid());
            }
            total = total
                .checked_add(input.value_zatoshis)
                .filter(|t| *t <= MAX_MONEY)
                .ok_or_else(invalid)?;
            observed.insert(input.input_id.as_str(), input.value_zatoshis);
            previous = Some(input.input_id.as_str());
        }
        if claimed != observed {
            return Err(invalid());
        }
        Ok(proposal)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest("wholepact:manual-construction-plan:v1", self)
    }
    pub fn input_set_digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest(
            "wholepact:manual-construction-input-set:v1",
            &self.selected_inputs,
        )
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualConstructionRequest {
    pub version: u16,
    pub plan: ManualConstructionPlan,
    pub intent: BornManualActionIntent,
}
impl ManualConstructionRequest {
    pub fn validate(&self) -> Result<Proposal> {
        bounded(self)?;
        let proposal = self.plan.validate()?;
        let p = &self.plan.preselection;
        self.intent.validate_for(&p.enrollment, &p.enrollment_ref)?;
        if self.version != 1
            || self.intent.action != BornManualAction::Construct
            || self.intent.candidate_id != p.candidate_id
            || self.intent.proposal_id != proposal.input().proposal_id
            || self.intent.manifest_digest != proposal.manifest_digest()
            || self.intent.operation_id != self.plan.operation_id
            || self.intent.idempotency_key_digest != self.plan.idempotency_key_digest
            || self.intent.invocation_nonce != self.plan.invocation_nonce
            || self.intent.exact_request_digest != self.plan.digest()?
            || self.intent.input_set_digest != self.plan.input_set_digest()?
        {
            return Err(invalid());
        }
        Ok(proposal)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest("wholepact:manual-construction-request:v1", self)
    }
}
