//! Input-free exact economics and a distinct bounded selection request. These
//! are inert claims: no viewing lease can be upgraded by parsing them, and no
//! selected input, return address, candidate or approval is fabricated here.
use crate::{
    AgreementDraft, Amount, CoreError, ErrorCode, FeeWeight, Result,
    agreement::{bounded_text, validate_address_text, validate_timestamp},
    allocate_fees,
    born_policy_origin_v2::BornRecipientPolicyOriginV2,
    born_recipient_policy_v2::{BornConstructionRecipientPolicyV2, BornOwnReturnRuleV2},
    error::validate_id,
    manual_construction::MAX_CONSTRUCTION_INVOCATION_MS,
    manual_enrollment::BornManualEnrollmentTerms,
    manual_inventory::{MAX_PRELIMINARY_DISCLOSURE_MS, ManualPreliminaryInventoryScope},
    proposal::{ParticipantAllocation, canonical_digest},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualCandidateEconomicIntent {
    pub version: u16,
    pub candidate_id: String,
    /// Exact current authenticated agreement RECORD revision for future candidate CAS.
    /// This differs from AgreementDraft.revision; the concrete Engine must check it.
    pub candidate_revision: u64,
    pub proposal_id: String,
    pub previous_proposal_id: Option<String>,
    pub created_at: String,
    pub agreement: AgreementDraft,
    /// Canonical participant-ID order and an exact account bijection.
    pub participants: Vec<ParticipantAllocation>,
    pub transaction_fee: Amount,
    pub expiry_height: u32,
    /// No return address or amount exists yet. The maintained selector must
    /// derive actual same-account change; the full proposal gets a NEW review.
    pub own_return_rule: BornOwnReturnRuleV2,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualCandidateInvocation {
    pub version: u16,
    pub operation_id: String,
    pub idempotency_key_digest: String,
    pub invocation_nonce: String,
    pub economic_intent_digest: String,
    pub checkpoint_destination: String,
    pub requested_at_ms: u64,
    /// Non-signing completion ceiling only. Never renews selection permission.
    pub construction_expires_at_ms: u64,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualCandidateSelectionScope {
    pub version: u16,
    /// Reuse only the strict candidate-free DATA shape for the exact original
    /// enrollment, attachment, provider, full birthday and scan bounds. Neither
    /// this copy nor an existing preliminary viewing lease authorizes selection.
    pub inventory: ManualPreliminaryInventoryScope,
    pub original_policy_origin: BornRecipientPolicyOriginV2,
    pub economic_intent: ManualCandidateEconomicIntent,
    pub invocation: ManualCandidateInvocation,
    pub purpose: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualCandidateSelectionRequest {
    pub version: u16,
    pub operation_id: String,
    pub scope: ManualCandidateSelectionScope,
    pub current_caller_binding_digest: String,
    pub requested_at_ms: u64,
    pub disclosure_expires_at_ms: u64,
}
fn invalid() -> CoreError {
    CoreError::new(
        ErrorCode::InvalidTerms,
        "invalid bounded native candidate selection intent",
    )
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
fn bounded<T: Serialize>(value: &T) -> Result<()> {
    if serde_json::to_vec(value).map_err(|_| invalid())?.len() > 128 * 1024 {
        return Err(invalid());
    }
    Ok(())
}
fn absolute(value: &str) -> Result<()> {
    bounded_text(value, 2048, "candidate destination")?;
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
impl ManualCandidateEconomicIntent {
    /// Exact input-free arithmetic, using the SAME fee allocator as Proposal.
    /// The result is requested economics, never an observation of available funds.
    pub fn validate(&self) -> Result<BTreeMap<String, Amount>> {
        bounded(self)?;
        self.agreement.validate()?;
        validate_id(&self.candidate_id, "candidate ID")?;
        validate_id(&self.proposal_id, "proposal ID")?;
        validate_timestamp(&self.created_at)?;
        if let Some(previous) = &self.previous_proposal_id {
            validate_id(previous, "previous proposal ID")?;
            if previous == &self.proposal_id {
                return Err(invalid());
            }
        }
        if self.version != 1
            || self.candidate_revision == 0
            || self.candidate_revision > i64::MAX as u64
            || self.expiry_height == 0
            || !(2..=32).contains(&self.participants.len())
        {
            return Err(invalid());
        }
        let mut debits = BTreeMap::new();
        let mut accounts = BTreeSet::new();
        let mut previous = None;
        for p in &self.participants {
            validate_id(&p.participant_id, "participant ID")?;
            hash(&p.account_id)?;
            if previous.is_some_and(|id: &str| id >= p.participant_id.as_str())
                || !accounts.insert(&p.account_id)
                || p.fee_share > p.fee_cap
                || p.charges.len() > 16
            {
                return Err(invalid());
            }
            previous = Some(p.participant_id.as_str());
            let mut charges = BTreeSet::new();
            for c in &p.charges {
                validate_id(&c.charge_id, "charge ID")?;
                validate_address_text(&c.address)?;
                bounded_text(&c.purpose, 1024, "charge purpose")?;
                if c.amount == Amount::ZERO || !charges.insert(&c.charge_id) {
                    return Err(invalid());
                }
            }
            let debit = p
                .contribution
                .checked_add(p.fee_share)?
                .checked_add(Amount::checked_sum(p.charges.iter().map(|c| c.amount))?)?;
            if debit == Amount::ZERO || debit > p.maximum_net_debit {
                return Err(invalid());
            }
            debits.insert(p.participant_id.clone(), debit);
        }
        let weights: Vec<_> = self
            .participants
            .iter()
            .map(|p| FeeWeight {
                participant_id: p.participant_id.clone(),
                contribution: p.contribution,
            })
            .collect();
        let fees = allocate_fees(self.transaction_fee, &weights, &self.agreement.fee_policy)?;
        if self
            .participants
            .iter()
            .any(|p| fees[&p.participant_id] != p.fee_share)
            || Amount::checked_sum(self.participants.iter().map(|p| p.contribution))?
                != Amount::checked_sum(self.agreement.recipients.iter().map(|r| r.amount))?
        {
            return Err(invalid());
        }
        Ok(debits)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest("wholepact:manual-candidate-economic-intent:v1", self)
    }
    /// Later actual-input proposal must preserve these exact economics. This
    /// check creates no native decision and proves neither input ownership nor
    /// returned-address ownership; those remain actual maintained owner checks.
    pub fn require_proposal(&self, input: &crate::ProposalInput) -> Result<crate::Proposal> {
        self.validate()?;
        let proposal = crate::Proposal::validate(input.clone())?;
        if input.proposal_id != self.proposal_id
            || input.previous_proposal_id != self.previous_proposal_id
            || input.created_at != self.created_at
            || input.manifest.agreement != self.agreement
            || input.manifest.participants != self.participants
            || input.manifest.transaction_fee != self.transaction_fee
            || input.manifest.expiry_height != self.expiry_height
        {
            return Err(invalid());
        }
        Ok(proposal)
    }
    /// Pure counterpart of V2 full-candidate constraints. No placeholder
    /// ProposalInput is constructed; actual input/return validation stays later.
    pub fn require_policy(
        &self,
        policy: &BornConstructionRecipientPolicyV2,
        enrollment: &BornManualEnrollmentTerms,
    ) -> Result<Amount> {
        let debits = self.validate()?;
        policy.require_enrollment(enrollment)?;
        let a = &self.agreement;
        if a.agreement_id != policy.agreement_id
            || a.obligation_id != policy.obligation_id
            || a.network_profile_id != policy.network_profile_id
            || a.recipients.len() != policy.recipients.len()
            || self.transaction_fee.as_zatoshis()
                > policy.original_limits.maximum_transaction_fee_zatoshis
            || self.transaction_fee.as_zatoshis()
                > enrollment.scope.maximum_transaction_fee_zatoshis
            || self.own_return_rule != policy.own_return_rule
        {
            return Err(invalid());
        }
        let recipients: BTreeMap<_, _> = policy
            .recipients
            .iter()
            .map(|r| (r.recipient_id.as_str(), r))
            .collect();
        for r in &a.recipients {
            let allowed = recipients
                .get(r.recipient_id.as_str())
                .ok_or_else(invalid)?;
            if r.address != allowed.address
                || r.memo != allowed.memo
                || r.instruction_provenance != allowed.instruction_provenance
                || r.amount.as_zatoshis() > allowed.maximum_amount_zatoshis
            {
                return Err(invalid());
            }
        }
        let own = self
            .participants
            .iter()
            .find(|p| {
                p.participant_id == policy.participant_id && p.account_id == policy.account_id
            })
            .ok_or_else(invalid)?;
        let debit = *debits.get(&own.participant_id).ok_or_else(invalid)?;
        if own.maximum_net_debit.as_zatoshis() > policy.original_limits.per_operation_limit_zatoshis
            || own.maximum_net_debit.as_zatoshis() > enrollment.scope.per_operation_limit_zatoshis
            || debit.as_zatoshis() > enrollment.scope.aggregate_budget_zatoshis
            || own.fee_cap.as_zatoshis() > policy.original_limits.maximum_fee_share_zatoshis
            || own.fee_cap.as_zatoshis() > enrollment.scope.maximum_fee_share_zatoshis
        {
            return Err(invalid());
        }
        let charges: BTreeMap<_, _> = policy
            .charges
            .iter()
            .map(|c| ((c.participant_id.as_str(), c.charge_id.as_str()), c))
            .collect();
        for p in &self.participants {
            for c in &p.charges {
                let allowed = charges
                    .get(&(p.participant_id.as_str(), c.charge_id.as_str()))
                    .ok_or_else(invalid)?;
                if p.account_id != allowed.account_id
                    || c.address != allowed.address
                    || c.purpose != allowed.purpose
                    || c.amount.as_zatoshis() > allowed.maximum_amount_zatoshis
                {
                    return Err(invalid());
                }
            }
        }
        Ok(debit)
    }
}
impl ManualCandidateInvocation {
    pub fn validate(&self) -> Result<()> {
        validate_id(&self.operation_id, "candidate invocation")?;
        for h in [
            &self.idempotency_key_digest,
            &self.invocation_nonce,
            &self.economic_intent_digest,
        ] {
            hash(h)?;
        }
        absolute(&self.checkpoint_destination)?;
        if self.version != 1
            || self.requested_at_ms == 0
            || self.construction_expires_at_ms > i64::MAX as u64
            || self.construction_expires_at_ms <= self.requested_at_ms
            || self.construction_expires_at_ms - self.requested_at_ms
                > MAX_CONSTRUCTION_INVOCATION_MS
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest("wholepact:manual-candidate-invocation:v1", self)
    }
}
impl ManualCandidateSelectionScope {
    pub fn validate(&self) -> Result<()> {
        bounded(self)?;
        self.inventory.validate()?;
        self.original_policy_origin.validate()?;
        self.invocation.validate()?;
        let i = &self.inventory;
        let e = &i.enrollment;
        let o = &self.original_policy_origin;
        let identity = &o.intent.identity;
        self.economic_intent
            .require_policy(&o.recipient_policy, e)?;
        if self.version != 1
            || self.purpose != "prepare_one_private_contribution"
            || o.recipient_policy != i.original_recipient_policy
            || o.birth_digest != e.native_birth_digest
            || identity.account_id != e.identity.account_id
            || identity.full_viewing_key_digest != e.identity.full_viewing_key_digest
            || identity.network_profile_id != e.identity.network_profile_id
            || identity.derivation_domain != e.identity.derivation_domain
            || canonical_digest(
                "wholepact:account-use-witness-origin:v1",
                &(
                    &o.intent.witness_origin.endpoint,
                    &o.intent.witness_origin.server_name,
                    &o.intent.witness_origin.witness_id,
                    &o.intent.witness_origin.pinned_server_certificate_digest,
                ),
            )? != e.original_witness_origin_digest
            || o.intent.original_policy_terms.owner_certificate_digest
                != e.signer.owner_certificate_digest
            || self.invocation.economic_intent_digest != self.economic_intent.digest()?
            || self.invocation.checkpoint_destination != i.operator_destination
            || self.invocation.requested_at_ms < e.issued_at_ms
            || self.invocation.construction_expires_at_ms > e.scope.expires_at_ms
            || self.invocation.construction_expires_at_ms - self.invocation.requested_at_ms
                > e.scope.maximum_permit_lifetime_ms
            || self
                .economic_intent
                .agreement
                .privacy_profile
                .proving_operator
                .as_ref()
                .is_some_and(|p| p != &i.operator_name)
            || self.economic_intent.expiry_height <= i.anchor_height
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn pairing_digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest("wholepact:manual-candidate-selection-scope:v1", self)
    }
    pub fn requested_debit_zatoshis(&self) -> Result<u64> {
        self.validate()?;
        Ok(self
            .economic_intent
            .require_policy(
                &self.original_policy_origin.recipient_policy,
                &self.inventory.enrollment,
            )?
            .as_zatoshis())
    }
}
impl ManualCandidateSelectionRequest {
    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        validate_id(&self.operation_id, "candidate selection operation")?;
        hash(&self.current_caller_binding_digest)?;
        if self.version != 1
            || self.operation_id == self.scope.invocation.operation_id
            || self.requested_at_ms < self.scope.invocation.requested_at_ms
            || self.disclosure_expires_at_ms > self.scope.invocation.construction_expires_at_ms
            || self.disclosure_expires_at_ms <= self.requested_at_ms
            || self.disclosure_expires_at_ms - self.requested_at_ms > MAX_PRELIMINARY_DISCLOSURE_MS
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest("wholepact:manual-candidate-selection-request:v1", self)
    }
    pub fn remaining_ms(&self, now: u64) -> Result<u64> {
        self.validate()?;
        if now < self.requested_at_ms || now >= self.disclosure_expires_at_ms {
            return Err(invalid());
        }
        Ok(self.disclosure_expires_at_ms - now)
    }
}

#[cfg(test)]
mod tests;
