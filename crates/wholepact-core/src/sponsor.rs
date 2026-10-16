//! Reusable sponsor constraints and exact candidate arithmetic. Every account,
//! identity and transaction allocation remains a claim until a qualified verifier
//! establishes it. Saving or evaluating these terms never authorizes a payment.
use crate::agreement::{bounded_text, validate_address_text, validate_timestamp};
use crate::error::validate_id;
use crate::{
    evaluate_match, validate_claimed_accounting, Amount, CoreError, ErrorCode, MatchAllocation,
    MatchAssurance, MatchEvaluation, MatchPolicy, OutputAllocation, ParticipantAllocation,
    PrivacyMode, PrivacyProfile, ProposalManifest, Result,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Rates are JSON integers shared with JavaScript clients. No unsafe-integer
/// round trip may silently change a rational policy. Amounts use string JSON.
pub const MAX_SPONSOR_RATE_TERM: u64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SponsorAccountRestriction {
    pub participant_id: String,
    pub account_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SponsorBeneficiaryRestriction {
    pub recipient_id: String,
    /// Exact intended receiving instructions, not proof of recipient ownership.
    pub address: String,
    pub maximum_amount: Amount,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SponsorPolicyTerms {
    pub schema_version: u32,
    pub network_profile_id: String,
    /// Explicit reusable scope. No wildcard agreements or identities.
    pub agreement_scope: Vec<String>,
    pub sponsor: SponsorAccountRestriction,
    pub eligible_contributors: Vec<SponsorAccountRestriction>,
    pub beneficiaries: Vec<SponsorBeneficiaryRestriction>,
    pub rate_numerator: u64,
    pub rate_denominator: u64,
    pub maximum_match: Amount,
    pub minimum_qualifying_total: Amount,
    pub fee_cap: Amount,
    pub maximum_net_debit: Amount,
    pub aggregate_budget: Amount,
    pub assurance: MatchAssurance,
    /// Explicit additional requirements; this build cannot attest to them.
    pub identity_requirements: Vec<String>,
    /// Exact accepted declaration. This is a limit, never disclosure consent.
    pub privacy_profile: PrivacyProfile,
    pub expires_at: Option<String>,
}

impl SponsorPolicyTerms {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            return Err(CoreError::new(
                ErrorCode::UnsupportedVersion,
                "unsupported sponsor policy schema",
            ));
        }
        validate_id(&self.network_profile_id, "policy network profile")?;
        if self.agreement_scope.is_empty() || self.agreement_scope.len() > 32 {
            return Err(CoreError::new(
                ErrorCode::ResourceLimit,
                "sponsor policy requires 1..=32 explicit agreement IDs",
            ));
        }
        let mut agreements = BTreeSet::new();
        for id in &self.agreement_scope {
            validate_id(id, "policy agreement ID")?;
            if !agreements.insert(id) {
                return Err(CoreError::new(
                    ErrorCode::DuplicateIdentifier,
                    "duplicate sponsor agreement scope",
                ));
            }
        }
        if self.rate_numerator == 0
            || self.rate_numerator > MAX_SPONSOR_RATE_TERM
            || self.rate_denominator == 0
            || self.rate_denominator > MAX_SPONSOR_RATE_TERM
            || self.maximum_match == Amount::ZERO
        {
            return Err(CoreError::new(
                ErrorCode::InvalidTerms,
                "matching requires positive safe-integer rate terms and a positive cap",
            ));
        }
        if self.maximum_match.checked_add(self.fee_cap)? > self.maximum_net_debit
            || self.maximum_net_debit > self.aggregate_budget
        {
            return Err(CoreError::new(
                ErrorCode::DebitCapExceeded,
                "match plus fee cap must fit the per-payment debit and aggregate budget",
            ));
        }
        if self.eligible_contributors.is_empty() || self.eligible_contributors.len() > 31 {
            return Err(CoreError::new(
                ErrorCode::ResourceLimit,
                "policy requires 1..=31 explicit eligible contributor accounts",
            ));
        }
        let mut participants = BTreeSet::new();
        let mut accounts = BTreeSet::new();
        for allocation in std::iter::once(&self.sponsor).chain(&self.eligible_contributors) {
            validate_id(&allocation.participant_id, "policy participant ID")?;
            validate_id(&allocation.account_id, "policy account ID")?;
            if !participants.insert(&allocation.participant_id)
                || !accounts.insert(&allocation.account_id)
            {
                return Err(CoreError::new(
                    ErrorCode::InvalidTerms,
                    "sponsor and eligible participant/account restrictions must not overlap",
                ));
            }
        }
        if self.beneficiaries.is_empty() || self.beneficiaries.len() > 64 {
            return Err(CoreError::new(
                ErrorCode::ResourceLimit,
                "policy requires 1..=64 explicit beneficiary restrictions",
            ));
        }
        let mut beneficiaries = BTreeSet::new();
        for beneficiary in &self.beneficiaries {
            validate_id(&beneficiary.recipient_id, "policy beneficiary ID")?;
            validate_address_text(&beneficiary.address)?;
            if !beneficiaries.insert(&beneficiary.recipient_id) {
                return Err(CoreError::new(
                    ErrorCode::DuplicateIdentifier,
                    "duplicate sponsor beneficiary restriction",
                ));
            }
            if beneficiary.maximum_amount == Amount::ZERO {
                return Err(CoreError::new(
                    ErrorCode::InvalidTerms,
                    "beneficiary ceiling must be positive",
                ));
            }
        }
        if let MatchAssurance::Attested { verifier_identity } = &self.assurance {
            validate_id(verifier_identity, "explicitly trusted match verifier")?;
        }
        if self.identity_requirements.len() > 16 {
            return Err(CoreError::new(
                ErrorCode::ResourceLimit,
                "at most 16 explicit identity requirements are supported",
            ));
        }
        for requirement in &self.identity_requirements {
            bounded_text(requirement, 1024, "identity requirement")?;
        }
        match (
            &self.privacy_profile.mode,
            &self.privacy_profile.proving_operator,
        ) {
            (PrivacyMode::LocalOnly, None) => {}
            (PrivacyMode::DeclaredOperator, Some(operator))
                if self.privacy_profile.dedicated_accounts_required =>
            {
                bounded_text(operator, 256, "accepted proving operator")?;
            }
            _ => {
                return Err(CoreError::new(
                    ErrorCode::PrivacyIncompatible,
                    "invalid sponsor privacy restriction",
                ))
            }
        }
        if let Some(expires_at) = &self.expires_at {
            validate_timestamp(expires_at)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExcludedSponsorContribution {
    pub participant_id: String,
    pub contribution: Amount,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SponsorFormulaPreview {
    pub evaluation: MatchEvaluation,
    pub eligible_allocations: Vec<MatchAllocation>,
    pub sponsor_allocation: MatchAllocation,
    pub excluded_contributions: Vec<ExcludedSponsorContribution>,
    pub excluded_transaction_fee: Amount,
    pub excluded_service_charges: Amount,
    pub sponsor_fee_share: Amount,
    pub sponsor_net_debit: Amount,
    pub rounding: String,
    pub allocation_assurance: String,
}

/// Evaluate only a concrete, fully reconciled candidate manifest. Eligible
/// funding is derived from its allocations, never from a separately entered
/// total. Ineligible contributions, sponsor funding, fees and charges are
/// excluded explicitly. No caller-controlled success or evidence flags exist.
pub fn evaluate_sponsor_policy(
    terms: &SponsorPolicyTerms,
    manifest: &ProposalManifest,
) -> Result<SponsorFormulaPreview> {
    terms.validate()?;
    let accounting = validate_claimed_accounting(manifest)?;
    if terms.network_profile_id != manifest.agreement.network_profile_id
        || !terms
            .agreement_scope
            .contains(&manifest.agreement.agreement_id)
    {
        return Err(CoreError::new(
            ErrorCode::InvalidTerms,
            "candidate is outside the sponsor policy network or agreement scope",
        ));
    }
    if terms.privacy_profile != manifest.agreement.privacy_profile {
        return Err(CoreError::new(
            ErrorCode::PrivacyIncompatible,
            "candidate disclosure declaration differs from the sponsor policy limit",
        ));
    }
    for recipient in &manifest.agreement.recipients {
        let allowed = terms
            .beneficiaries
            .iter()
            .find(|b| b.recipient_id == recipient.recipient_id)
            .ok_or_else(|| {
                CoreError::new(
                    ErrorCode::InvalidTerms,
                    "candidate beneficiary is not permitted by sponsor policy",
                )
            })?;
        if recipient.address != allowed.address || recipient.amount > allowed.maximum_amount {
            return Err(CoreError::new(
                ErrorCode::InvalidTerms,
                "candidate beneficiary instructions or amount exceed the sponsor restriction",
            ));
        }
    }
    let sponsor = manifest
        .participants
        .iter()
        .find(|p| p.participant_id == terms.sponsor.participant_id)
        .ok_or_else(|| {
            CoreError::new(
                ErrorCode::MissingEvidence,
                "candidate has no designated sponsor allocation",
            )
        })?;
    if sponsor.account_id != terms.sponsor.account_id {
        return Err(CoreError::new(
            ErrorCode::InvalidTerms,
            "candidate sponsor account differs from policy",
        ));
    }
    if !sponsor.charges.is_empty() {
        return Err(CoreError::new(ErrorCode::UnsupportedCapability, "sponsor service charges require a separately supported explicit policy; they cannot be counted as matching or fees"));
    }
    if sponsor.fee_share > terms.fee_cap {
        return Err(CoreError::new(
            ErrorCode::FeeCapExceeded,
            "candidate sponsor fee exceeds policy cap",
        ));
    }
    let debit = *accounting
        .participant_net_debits
        .get(&sponsor.participant_id)
        .ok_or_else(|| {
            CoreError::new(
                ErrorCode::MissingEvidence,
                "sponsor debit was not reconciled",
            )
        })?;
    if debit > terms.maximum_net_debit || debit > terms.aggregate_budget {
        return Err(CoreError::new(
            ErrorCode::DebitCapExceeded,
            "candidate sponsor debit exceeds policy limit",
        ));
    }
    let mut eligible = Vec::new();
    let mut excluded = Vec::new();
    for participant in &manifest.participants {
        if participant.participant_id == sponsor.participant_id {
            excluded.push(ExcludedSponsorContribution {
                participant_id: participant.participant_id.clone(),
                contribution: participant.contribution,
                reason: "sponsor_funding_is_not_eligible".into(),
            });
            continue;
        }
        match terms
            .eligible_contributors
            .iter()
            .find(|p| p.participant_id == participant.participant_id)
        {
            Some(restriction) if restriction.account_id == participant.account_id => {
                eligible.push(match_allocation(manifest, participant));
            }
            Some(_) => {
                return Err(CoreError::new(
                    ErrorCode::InvalidTerms,
                    "eligible participant uses a different designated account",
                ))
            }
            None => {
                // Re-labeling an explicitly eligible account cannot silently
                // turn it into an unrelated excluded participant.
                if terms
                    .eligible_contributors
                    .iter()
                    .any(|p| p.account_id == participant.account_id)
                {
                    return Err(CoreError::new(
                        ErrorCode::InvalidTerms,
                        "eligible account was assigned to a different participant",
                    ));
                }
                excluded.push(ExcludedSponsorContribution {
                    participant_id: participant.participant_id.clone(),
                    contribution: participant.contribution,
                    reason: "not_in_explicit_eligibility_list".into(),
                });
            }
        }
    }
    let sponsor_allocation = match_allocation(manifest, sponsor);
    let policy = MatchPolicy {
        sponsor_participant_id: terms.sponsor.participant_id.clone(),
        rate_numerator: terms.rate_numerator,
        rate_denominator: terms.rate_denominator,
        maximum_match: terms.maximum_match,
        minimum_qualifying_total: terms.minimum_qualifying_total,
        allowed_recipient_ids: terms
            .beneficiaries
            .iter()
            .map(|b| b.recipient_id.clone())
            .collect(),
        assurance: terms.assurance.clone(),
    };
    let recipients = manifest
        .agreement
        .recipients
        .iter()
        .map(|r| r.recipient_id.clone())
        .collect::<Vec<_>>();
    let mut evaluation = evaluate_match(&policy, &eligible, &sponsor_allocation, &recipients)?;
    for requirement in &terms.identity_requirements {
        evaluation
            .required_evidence
            .push(format!("Unverified identity requirement: {requirement}"));
    }
    evaluation.required_evidence.push("Current account-wide pending and settled budget ledger from an authenticated authoritative account connection".into());
    Ok(SponsorFormulaPreview {
        evaluation,
        eligible_allocations: eligible,
        sponsor_allocation,
        excluded_contributions: excluded,
        excluded_transaction_fee: manifest.transaction_fee,
        excluded_service_charges: accounting.charge_total,
        sponsor_fee_share: sponsor.fee_share,
        sponsor_net_debit: debit,
        rounding: "floor_rational_zatoshis_then_cap".into(),
        allocation_assurance: "candidate_claims_only_ownership_unverified".into(),
    })
}

fn match_allocation(
    manifest: &ProposalManifest,
    participant: &ParticipantAllocation,
) -> MatchAllocation {
    MatchAllocation {
        participant_id: participant.participant_id.clone(),
        account_id: participant.account_id.clone(),
        contribution: participant.contribution,
        input_ids: manifest
            .inputs
            .iter()
            .filter(|i| i.participant_id == participant.participant_id)
            .map(|i| i.input_id.clone())
            .collect(),
        return_output_ids: manifest
            .outputs
            .iter()
            .filter_map(|o| match &o.allocation {
                OutputAllocation::Return {
                    participant_id,
                    account_id,
                    ..
                } if participant_id == &participant.participant_id
                    && account_id == &participant.account_id =>
                {
                    Some(o.output_id.clone())
                }
                _ => None,
            })
            .collect(),
    }
}
