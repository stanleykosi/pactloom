//! Stable recipient constraints for a NEW v2 born origin. This is inert policy
//! data, not enrollment, viewing, construction or signing permission. V1 exact
//! output commitments retain their original meaning and never enter this codec.
use crate::{
    CoreError, ErrorCode, MAX_MONEY, Proposal, ProposalInput, Result,
    agreement::validate_address_text,
    error::validate_id,
    manual_enrollment::BornManualEnrollmentTerms,
    proposal::{OutputAllocation, canonical_digest},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornRecipientLimitV2 {
    pub recipient_id: String,
    pub address: String,
    pub memo: Option<String>,
    pub instruction_provenance: String,
    pub maximum_amount_zatoshis: u64,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornChargeLimitV2 {
    pub participant_id: String,
    pub account_id: String,
    pub charge_id: String,
    pub address: String,
    pub purpose: String,
    pub maximum_amount_zatoshis: u64,
}
/// Exact copy of the original account-wide limits, not a separately spendable
/// pool. Runtime admission must still charge the SAME durable witness ledger.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornOriginalLimitsV2 {
    pub aggregate_budget_zatoshis: u64,
    pub per_operation_limit_zatoshis: u64,
    pub maximum_fee_share_zatoshis: u64,
    pub maximum_transaction_fee_zatoshis: u64,
    pub maximum_permit_lifetime_ms: u64,
    pub policy_expires_at_ms: u64,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BornOwnReturnRuleV2 {
    /// The signer must decode every own return through the qualified protocol
    /// adapter and verify membership with its ACTUAL authenticated account FVK.
    AuthenticatedSameAccount,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornConstructionRecipientPolicyV2 {
    pub version: u16,
    pub account_id: String,
    pub network_profile_id: String,
    pub agreement_id: String,
    pub obligation_id: String,
    pub participant_id: String,
    /// Canonical ID ordering; every declared recipient is required, and no
    /// undeclared recipient is allowed. Values may narrow below these caps.
    pub recipients: Vec<BornRecipientLimitV2>,
    /// Canonical (participant,charge) ordering; allowed charges may be omitted.
    /// Any present charge has the exact account/destination/purpose below.
    pub charges: Vec<BornChargeLimitV2>,
    pub original_limits: BornOriginalLimitsV2,
    pub own_return_rule: BornOwnReturnRuleV2,
}
/// Unverified claims to be discharged by the concrete account owner. A caller
/// cannot turn these strings into address-ownership evidence or native consent.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnReturnRequirementV2 {
    pub output_id: String,
    pub address: String,
    pub amount_zatoshis: u64,
}
fn invalid() -> CoreError {
    CoreError::new(
        ErrorCode::InvalidTerms,
        "invalid original v2 born recipient policy",
    )
}
fn hash(s: &str) -> Result<()> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    Ok(())
}
fn text(s: &str, bound: usize) -> Result<()> {
    if s.is_empty() || s.len() > bound || s.chars().any(char::is_control) {
        return Err(invalid());
    }
    Ok(())
}
fn money(v: u64, positive: bool) -> Result<()> {
    if v > MAX_MONEY || positive && v == 0 {
        return Err(invalid());
    }
    Ok(())
}
impl BornOriginalLimitsV2 {
    pub fn validate(&self) -> Result<()> {
        money(self.aggregate_budget_zatoshis, true)?;
        money(self.per_operation_limit_zatoshis, true)?;
        money(self.maximum_fee_share_zatoshis, false)?;
        money(self.maximum_transaction_fee_zatoshis, false)?;
        if self.per_operation_limit_zatoshis > self.aggregate_budget_zatoshis
            || self.maximum_fee_share_zatoshis > self.per_operation_limit_zatoshis
            || self.maximum_permit_lifetime_ms == 0
            || self.maximum_permit_lifetime_ms > 120_000
            || self.policy_expires_at_ms == 0
        {
            return Err(invalid());
        }
        Ok(())
    }
}
impl BornConstructionRecipientPolicyV2 {
    pub fn validate(&self) -> Result<()> {
        if self.version != 2
            || self.recipients.is_empty()
            || self.recipients.len() > 64
            || self.charges.len() > 64
        {
            return Err(invalid());
        }
        hash(&self.account_id)?;
        for s in [
            &self.network_profile_id,
            &self.agreement_id,
            &self.obligation_id,
            &self.participant_id,
        ] {
            validate_id(s, "v2 policy identity")?;
        }
        self.original_limits.validate()?;
        let mut previous = None;
        for r in &self.recipients {
            validate_id(&r.recipient_id, "v2 recipient ID")?;
            validate_address_text(&r.address)?;
            text(&r.instruction_provenance, 2048)?;
            if let Some(memo) = &r.memo {
                if memo.len() > 512 || memo.chars().any(char::is_control) {
                    return Err(invalid());
                }
            }
            money(r.maximum_amount_zatoshis, true)?;
            if previous.is_some_and(|p: &str| p >= r.recipient_id.as_str()) {
                return Err(invalid());
            }
            previous = Some(r.recipient_id.as_str());
        }
        let mut previous = None;
        for c in &self.charges {
            validate_id(&c.participant_id, "v2 charge participant")?;
            validate_id(&c.charge_id, "v2 charge ID")?;
            hash(&c.account_id)?;
            validate_address_text(&c.address)?;
            text(&c.purpose, 2048)?;
            money(c.maximum_amount_zatoshis, true)?;
            let key = (c.participant_id.as_str(), c.charge_id.as_str());
            if previous.is_some_and(|p| p >= key) {
                return Err(invalid());
            }
            if c.participant_id == self.participant_id && c.account_id != self.account_id {
                return Err(invalid());
            }
            previous = Some(key);
        }
        if serde_json::to_vec(self).map_err(|_| invalid())?.len() > 96 * 1024 {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest("wholepact:born-construction-recipient-policy:v2", self)
    }
    /// Only exact independently authenticated original envelope consumers may
    /// use this projection. Matching caller data alone cannot establish origin.
    pub fn require_enrollment(&self, terms: &BornManualEnrollmentTerms) -> Result<()> {
        self.validate()?;
        terms.validate()?;
        let s = &terms.scope;
        let l = &self.original_limits;
        if terms.identity.account_id != self.account_id
            || terms.identity.network_profile_id != self.network_profile_id
            || s.agreement_id != self.agreement_id
            || s.obligation_id != self.obligation_id
            || s.participant_id != self.participant_id
            || !s.recipient_scope_digests.contains(&self.digest()?)
            || s.aggregate_budget_zatoshis > l.aggregate_budget_zatoshis
            || s.per_operation_limit_zatoshis > l.per_operation_limit_zatoshis
            || s.maximum_fee_share_zatoshis > l.maximum_fee_share_zatoshis
            || s.maximum_transaction_fee_zatoshis > l.maximum_transaction_fee_zatoshis
            || s.maximum_permit_lifetime_ms > l.maximum_permit_lifetime_ms
            || s.expires_at_ms > l.policy_expires_at_ms
        {
            return Err(invalid());
        }
        Ok(())
    }
    /// Validates full arithmetic and destination constraints but deliberately
    /// returns ownership REQUIREMENTS rather than claiming input/return truth.
    pub fn validate_candidate(
        &self,
        input: &ProposalInput,
    ) -> Result<(Proposal, Vec<OwnReturnRequirementV2>)> {
        self.validate()?;
        let proposal = Proposal::validate(input.clone())?;
        let m = proposal.manifest();
        if m.agreement.agreement_id != self.agreement_id
            || m.agreement.obligation_id != self.obligation_id
            || m.agreement.network_profile_id != self.network_profile_id
            || m.agreement.recipients.len() != self.recipients.len()
            || m.transaction_fee.as_zatoshis()
                > self.original_limits.maximum_transaction_fee_zatoshis
        {
            return Err(invalid());
        }
        let recipients: BTreeMap<_, _> = self
            .recipients
            .iter()
            .map(|r| (r.recipient_id.as_str(), r))
            .collect();
        for r in &m.agreement.recipients {
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
        let own = m
            .participants
            .iter()
            .find(|p| p.participant_id == self.participant_id && p.account_id == self.account_id)
            .ok_or_else(invalid)?;
        if own.maximum_net_debit.as_zatoshis() > self.original_limits.per_operation_limit_zatoshis
            || own.fee_cap.as_zatoshis() > self.original_limits.maximum_fee_share_zatoshis
            || own.fee_share.as_zatoshis() > self.original_limits.maximum_fee_share_zatoshis
        {
            return Err(invalid());
        }
        let charges: BTreeMap<_, _> = self
            .charges
            .iter()
            .map(|c| ((c.participant_id.as_str(), c.charge_id.as_str()), c))
            .collect();
        let mut present = BTreeSet::new();
        for p in &m.participants {
            for c in &p.charges {
                let key = (p.participant_id.as_str(), c.charge_id.as_str());
                let allowed = charges.get(&key).ok_or_else(invalid)?;
                if !present.insert(key)
                    || p.account_id != allowed.account_id
                    || c.address != allowed.address
                    || c.purpose != allowed.purpose
                    || c.amount.as_zatoshis() > allowed.maximum_amount_zatoshis
                {
                    return Err(invalid());
                }
            }
        }
        let mut ownership = Vec::new();
        for output in &m.outputs {
            match &output.allocation {
                OutputAllocation::Recipient { recipient_id } => {
                    if output.address
                        != recipients
                            .get(recipient_id.as_str())
                            .ok_or_else(invalid)?
                            .address
                    {
                        return Err(invalid());
                    }
                }
                OutputAllocation::Charge {
                    participant_id,
                    charge_id,
                } => {
                    if output.address
                        != charges
                            .get(&(participant_id.as_str(), charge_id.as_str()))
                            .ok_or_else(invalid)?
                            .address
                    {
                        return Err(invalid());
                    }
                }
                OutputAllocation::Return {
                    participant_id,
                    account_id,
                    ..
                } if participant_id == &self.participant_id || account_id == &self.account_id => {
                    if participant_id != &self.participant_id || account_id != &self.account_id {
                        return Err(invalid());
                    }
                    ownership.push(OwnReturnRequirementV2 {
                        output_id: output.output_id.clone(),
                        address: output.address.clone(),
                        amount_zatoshis: output.amount.as_zatoshis(),
                    });
                }
                OutputAllocation::Return { .. } => {}
            }
        }
        Ok((proposal, ownership))
    }
    pub fn validate_candidate_for_enrollment(
        &self,
        terms: &BornManualEnrollmentTerms,
        input: &ProposalInput,
    ) -> Result<(Proposal, Vec<OwnReturnRequirementV2>)> {
        self.require_enrollment(terms)?;
        let (proposal, returns) = self.validate_candidate(input)?;
        let own = proposal
            .manifest()
            .participants
            .iter()
            .find(|p| {
                p.account_id == terms.identity.account_id
                    && p.participant_id == terms.scope.participant_id
            })
            .ok_or_else(invalid)?;
        if own.maximum_net_debit.as_zatoshis() > terms.scope.per_operation_limit_zatoshis
            || own.fee_cap.as_zatoshis() > terms.scope.maximum_fee_share_zatoshis
            || own.fee_share.as_zatoshis() > terms.scope.maximum_fee_share_zatoshis
            || proposal.manifest().transaction_fee.as_zatoshis()
                > terms.scope.maximum_transaction_fee_zatoshis
        {
            return Err(invalid());
        }
        Ok((proposal, returns))
    }
    pub fn native_review_text(&self) -> Result<String> {
        self.validate()?;
        Ok(format!(
            "NEW ORIGINAL RECIPIENT POLICY VERSION 2\n{}\n\nOnly the listed recipient and charge destinations are allowed, within their stated caps. Every candidate still needs a complete exact review after actual inventory selection. Your returned value may use only an address independently decoded and authenticated as belonging to this same account. Host-supplied ownership labels do not establish that fact. The original lifetime budget, debit limits, fees and expiry remain unchanged and charge the same account-wide ledger. This policy never grants automatic signing, proving or dispatch. A viewing disclosure is separately reviewed, and copied viewing information cannot be recalled.\nPolicy commitment: {}",
            serde_json::to_string_pretty(self).map_err(|_| invalid())?,
            self.digest()?
        ))
    }
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::*;

    fn a(n: u64) -> Amount {
        Amount::from_zatoshis(n).unwrap()
    }
    fn agreement() -> AgreementDraft {
        parse_typed_json(include_bytes!("../tests/fixtures/agreement.json")).unwrap()
    }
    fn proposal() -> ProposalInput {
        ProposalInput {
            proposal_id: "proposal-example-01".into(),
            previous_proposal_id: None,
            artifact_digest: None,
            effects_commitment: None,
            created_at: "2026-10-13T14:00:00Z".into(),
            manifest: ProposalManifest {
                agreement: agreement(),
                participants: vec![
                    ParticipantAllocation {
                        participant_id: "alice".into(),
                        account_id: "11".repeat(32),
                        contribution: a(400_000_000),
                        fee_share: a(12_000),
                        fee_cap: a(12_000),
                        maximum_net_debit: a(400_012_000),
                        charges: vec![],
                    },
                    ParticipantAllocation {
                        participant_id: "bob".into(),
                        account_id: "22".repeat(32),
                        contribution: a(600_000_000),
                        fee_share: a(18_000),
                        fee_cap: a(18_000),
                        maximum_net_debit: a(600_018_000),
                        charges: vec![],
                    },
                ],
                inputs: vec![
                    ClaimedInput {
                        input_id: "input-alice".into(),
                        participant_id: "alice".into(),
                        account_id: "11".repeat(32),
                        amount: a(500_000_000),
                        ownership_evidence_ref: None,
                    },
                    ClaimedInput {
                        input_id: "input-bob".into(),
                        participant_id: "bob".into(),
                        account_id: "22".repeat(32),
                        amount: a(700_000_000),
                        ownership_evidence_ref: None,
                    },
                ],
                outputs: vec![
                    ClaimedOutput {
                        output_id: "recipient-output".into(),
                        address: agreement().recipients[0].address.clone(),
                        amount: a(1_000_000_000),
                        allocation: OutputAllocation::Recipient {
                            recipient_id: "recipient-example".into(),
                        },
                    },
                    ClaimedOutput {
                        output_id: "alice-return".into(),
                        address: "usyntheticreturnalice".into(),
                        amount: a(99_988_000),
                        allocation: OutputAllocation::Return {
                            participant_id: "alice".into(),
                            account_id: "11".repeat(32),
                            ownership_evidence_ref: None,
                        },
                    },
                    ClaimedOutput {
                        output_id: "bob-return".into(),
                        address: "usyntheticreturnbob".into(),
                        amount: a(99_982_000),
                        allocation: OutputAllocation::Return {
                            participant_id: "bob".into(),
                            account_id: "22".repeat(32),
                            ownership_evidence_ref: None,
                        },
                    },
                ],
                transaction_fee: a(30_000),
                expiry_height: 3_000_000,
            },
        }
    }

    fn candidate_policy(p: &ProposalInput) -> BornConstructionRecipientPolicyV2 {
        BornConstructionRecipientPolicyV2 {
            version: 2,
            account_id: "11".repeat(32),
            network_profile_id: p.manifest.agreement.network_profile_id.clone(),
            agreement_id: p.manifest.agreement.agreement_id.clone(),
            obligation_id: p.manifest.agreement.obligation_id.clone(),
            participant_id: "alice".into(),
            recipients: p
                .manifest
                .agreement
                .recipients
                .iter()
                .map(|r| BornRecipientLimitV2 {
                    recipient_id: r.recipient_id.clone(),
                    address: r.address.clone(),
                    memo: r.memo.clone(),
                    instruction_provenance: r.instruction_provenance.clone(),
                    maximum_amount_zatoshis: r.amount.as_zatoshis(),
                })
                .collect(),
            charges: vec![],
            original_limits: BornOriginalLimitsV2 {
                aggregate_budget_zatoshis: 2_000_000_000,
                per_operation_limit_zatoshis: 500_000_000,
                maximum_fee_share_zatoshis: 12_000,
                maximum_transaction_fee_zatoshis: 30_000,
                maximum_permit_lifetime_ms: 120_000,
                policy_expires_at_ms: 500_000,
            },
            own_return_rule: BornOwnReturnRuleV2::AuthenticatedSameAccount,
        }
    }
    #[test]
    fn full_arithmetic_remains_exact_while_own_return_amount_can_follow_real_inventory() {
        let p = proposal();
        let policy = candidate_policy(&p);
        let (_, returns) = policy.validate_candidate(&p).unwrap();
        assert_eq!(returns.len(), 1);
        let mut changed = p.clone();
        changed.manifest.inputs[0].amount = a(500_000_001);
        changed.manifest.outputs[1].amount = a(99_988_001);
        assert!(policy.validate_candidate(&changed).is_ok());
        assert_ne!(
            crate::manual_construction::construction_payment_scope_digest(&p).unwrap(),
            crate::manual_construction::construction_payment_scope_digest(&changed).unwrap()
        );
        let mut redirected = p.clone();
        redirected.manifest.agreement.recipients[0].address = "uRedirected".into();
        redirected.manifest.outputs[0].address = "uRedirected".into();
        assert!(Proposal::validate(redirected.clone()).is_ok());
        assert!(policy.validate_candidate(&redirected).is_err());
        let mut wrong = p;
        wrong.manifest.inputs[0].amount = a(500_000_001);
        assert!(policy.validate_candidate(&wrong).is_err());
    }
    #[test]
    fn charges_need_exact_participant_account_destination_purpose_and_cap() {
        let mut p = proposal();
        let mut policy = candidate_policy(&p);
        policy.charges.push(BornChargeLimitV2 {
            participant_id: "alice".into(),
            account_id: "11".repeat(32),
            charge_id: "service".into(),
            address: "uService".into(),
            purpose: "Exact service".into(),
            maximum_amount_zatoshis: 1,
        });
        p.manifest.participants[0].charges.push(ChargeConsent {
            charge_id: "service".into(),
            address: "uService".into(),
            purpose: "Exact service".into(),
            amount: a(1),
        });
        p.manifest.participants[0].maximum_net_debit = a(400_012_001);
        p.manifest.outputs[1].amount = a(99_987_999);
        p.manifest.outputs.push(ClaimedOutput {
            output_id: "charge".into(),
            address: "uService".into(),
            amount: a(1),
            allocation: OutputAllocation::Charge {
                participant_id: "alice".into(),
                charge_id: "service".into(),
            },
        });
        assert!(policy.validate_candidate(&p).is_ok());
        p.manifest.participants[0].charges[0].purpose = "Different service".into();
        assert!(policy.validate_candidate(&p).is_err());
        p.manifest.participants[0].charges[0].purpose = "Exact service".into();
        policy.charges.clear();
        assert!(policy.validate_candidate(&p).is_err());
    }
    use crate::manual_enrollment::{
        BornManualScope, BornManualSignerBinding, ManualAccountIdentity,
        ManualHostGenerationBinding,
    };
    fn h(c: char) -> String {
        c.to_string().repeat(64)
    }
    fn terms() -> BornManualEnrollmentTerms {
        BornManualEnrollmentTerms {
            version: 1,
            operation_id: "synthetic-enrollment".into(),
            identity: ManualAccountIdentity {
                account_id: h('a'),
                full_viewing_key_digest: h('b'),
                network_profile_id: "synthetic-testnet".into(),
                derivation_domain: "dedicated-synthetic".into(),
            },
            birth_request_digest: h('c'),
            birth_commit_digest: h('d'),
            native_birth_digest: h('e'),
            original_policy_digest: h('f'),
            account_use_genesis_digest: h('1'),
            original_witness_origin_digest: h('2'),
            host: ManualHostGenerationBinding {
                generation_id: h('3'),
                inventory_digest: h('4'),
                generation_plan_digest: h('5'),
                financial_journal_origin_digest: h('6'),
                store_destination_identity: "/synthetic/host/coordination.sqlite".into(),
                profile_id: "synthetic-profile".into(),
                canonical_root: "/synthetic/host".into(),
                destination_identity_digest: h('7'),
                inherited_identity_digest: h('8'),
                scope_predecessor_digest: None,
            },
            signer: BornManualSignerBinding {
                enrollment_generation_id: h('9'),
                signer_target_digest: h('a'),
                original_envelope_digest: h('b'),
                owner_certificate_digest: h('c'),
                writer_certificate_digest: h('d'),
                writer_epoch: 1,
                native_signer_measurement: h('e'),
            },
            scope: BornManualScope {
                agreement_id: "synthetic-agreement".into(),
                obligation_id: "synthetic-obligation".into(),
                participant_id: "synthetic-participant".into(),
                principal_id: "synthetic-principal".into(),
                privacy_domain: "synthetic-domain".into(),
                recipient_scope_digests: vec![h('f')],
                aggregate_budget_zatoshis: 100,
                per_operation_limit_zatoshis: 50,
                maximum_fee_share_zatoshis: 2,
                maximum_transaction_fee_zatoshis: 200,
                maximum_permit_lifetime_ms: 500,
                expires_at_ms: 2000,
            },
            transport_binding_digest: h('1'),
            issued_at_ms: 1000,
        }
    }

    pub(crate) fn modeled_terms_and_policy()
    -> (BornManualEnrollmentTerms, BornConstructionRecipientPolicyV2) {
        let p = proposal();
        let policy = candidate_policy(&p);
        let mut t = terms();
        t.identity.account_id = policy.account_id.clone();
        t.identity.network_profile_id = policy.network_profile_id.clone();
        t.scope.agreement_id = policy.agreement_id.clone();
        t.scope.obligation_id = policy.obligation_id.clone();
        t.scope.participant_id = policy.participant_id.clone();
        t.scope.recipient_scope_digests = vec![policy.digest().unwrap()];
        t.scope.aggregate_budget_zatoshis = 1_000_000_000;
        t.scope.per_operation_limit_zatoshis = 400_012_000;
        t.scope.maximum_fee_share_zatoshis = 12_000;
        t.scope.maximum_transaction_fee_zatoshis = 30_000;
        t.scope.expires_at_ms = 200_000;
        (t, policy)
    }
    #[test]
    fn narrowed_enrollment_limits_remain_additional_required_constraints() {
        let p = proposal();
        let policy = candidate_policy(&p);
        let mut t = terms();
        t.identity.account_id = policy.account_id.clone();
        t.identity.network_profile_id = policy.network_profile_id.clone();
        t.scope.agreement_id = policy.agreement_id.clone();
        t.scope.obligation_id = policy.obligation_id.clone();
        t.scope.participant_id = policy.participant_id.clone();
        t.scope.recipient_scope_digests = vec![policy.digest().unwrap()];
        t.scope.aggregate_budget_zatoshis = 1_000_000_000;
        t.scope.per_operation_limit_zatoshis = 400_012_000;
        t.scope.maximum_fee_share_zatoshis = 12_000;
        t.scope.maximum_transaction_fee_zatoshis = 30_000;
        assert!(policy.validate_candidate_for_enrollment(&t, &p).is_ok());
        for narrowed in 0..3 {
            let mut t = t.clone();
            match narrowed {
                0 => t.scope.per_operation_limit_zatoshis -= 1,
                1 => t.scope.maximum_fee_share_zatoshis -= 1,
                _ => t.scope.maximum_transaction_fee_zatoshis -= 1,
            };
            assert!(policy.require_enrollment(&t).is_ok());
            assert!(policy.validate_candidate_for_enrollment(&t, &p).is_err());
        }
    }
    fn policy() -> BornConstructionRecipientPolicyV2 {
        BornConstructionRecipientPolicyV2 {
            version: 2,
            account_id: "11".repeat(32),
            network_profile_id: "synthetic-testnet".into(),
            agreement_id: "agreement".into(),
            obligation_id: "obligation".into(),
            participant_id: "alice".into(),
            recipients: vec![BornRecipientLimitV2 {
                recipient_id: "recipient".into(),
                address: "uSyntheticRecipient".into(),
                memo: None,
                instruction_provenance: "synthetic owner instruction".into(),
                maximum_amount_zatoshis: 50,
            }],
            charges: vec![],
            original_limits: BornOriginalLimitsV2 {
                aggregate_budget_zatoshis: 100,
                per_operation_limit_zatoshis: 60,
                maximum_fee_share_zatoshis: 3,
                maximum_transaction_fee_zatoshis: 5,
                maximum_permit_lifetime_ms: 120_000,
                policy_expires_at_ms: 500_000,
            },
            own_return_rule: BornOwnReturnRuleV2::AuthenticatedSameAccount,
        }
    }
    #[test]
    fn explicit_version_and_every_semantic_field_is_committed() {
        let p = policy();
        let d = p.digest().unwrap();
        let mut q = p.clone();
        q.version = 1;
        assert!(q.digest().is_err());
        for mutate in 0..5 {
            let mut q = p.clone();
            match mutate {
                0 => q.recipients[0].address = "uDifferentRecipient".into(),
                1 => q.recipients[0].maximum_amount_zatoshis = 49,
                2 => q.original_limits.aggregate_budget_zatoshis = 99,
                3 => q.obligation_id = "different".into(),
                _ => q.recipients[0].memo = Some("memo".into()),
            };
            assert_ne!(d, q.digest().unwrap());
        }
        let text = p.native_review_text().unwrap();
        assert!(text.contains("cannot be recalled") && text.contains("same account-wide ledger"));
    }
    #[test]
    fn no_unknown_fields_or_unbounded_duplicate_destinations() {
        let p = policy();
        let mut value = serde_json::to_value(&p).unwrap();
        value["approved"] = true.into();
        assert!(serde_json::from_value::<BornConstructionRecipientPolicyV2>(value).is_err());
        let mut p = policy();
        p.recipients.push(p.recipients[0].clone());
        assert!(p.validate().is_err());
        let mut p = policy();
        p.original_limits.per_operation_limit_zatoshis = 101;
        assert!(p.validate().is_err());
        let mut p = policy();
        p.recipients[0].address = "t1Transparent".into();
        assert!(p.validate().is_err());
    }
}
