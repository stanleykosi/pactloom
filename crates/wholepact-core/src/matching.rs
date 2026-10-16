//! Match arithmetic and explicit evidence requirements. No ownership or
//! attestation verifier is qualified in this crate; previews never verify a match.
use crate::error::validate_id;
use crate::{Amount, CoreError, ErrorCode, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MatchAssurance {
    IndependentlyVerified,
    Attested { verifier_identity: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchPolicy {
    pub sponsor_participant_id: String,
    pub rate_numerator: u64,
    pub rate_denominator: u64,
    pub maximum_match: Amount,
    pub minimum_qualifying_total: Amount,
    pub allowed_recipient_ids: Vec<String>,
    pub assurance: MatchAssurance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchAllocation {
    pub participant_id: String,
    pub account_id: String,
    /// Funding contribution only. Fees and service charges are never included.
    pub contribution: Amount,
    pub input_ids: Vec<String>,
    pub return_output_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchEvidenceStatus {
    Unverifiable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MatchEvaluation {
    pub eligible_total: Amount,
    pub calculated_match: Amount,
    pub assurance: MatchAssurance,
    pub evidence_status: MatchEvidenceStatus,
    pub authorization_allowed: bool,
    pub required_evidence: Vec<String>,
    pub limitations: Vec<String>,
}

/// Returns a mathematically exact preview. Even a consistent declared sponsor
/// allocation cannot establish that a real account controls or funds inputs.
pub fn evaluate_match(
    policy: &MatchPolicy,
    eligible: &[MatchAllocation],
    sponsor: &MatchAllocation,
    recipient_ids: &[String],
) -> Result<MatchEvaluation> {
    validate_id(&policy.sponsor_participant_id, "sponsor ID")?;
    if policy.rate_denominator == 0 {
        return Err(CoreError::new(
            ErrorCode::InvalidTerms,
            "matching rate denominator must be nonzero",
        ));
    }
    if sponsor.participant_id != policy.sponsor_participant_id {
        return Err(CoreError::new(
            ErrorCode::InvalidTerms,
            "sponsor allocation does not match the policy",
        ));
    }
    if eligible.is_empty()
        || eligible.len() > 31
        || recipient_ids.is_empty()
        || recipient_ids.len() > 64
    {
        return Err(CoreError::new(
            ErrorCode::ResourceLimit,
            "matching requires 1..=31 eligible contributors and 1..=64 recipients",
        ));
    }
    if policy.allowed_recipient_ids.is_empty() || policy.allowed_recipient_ids.len() > 64 {
        return Err(CoreError::new(
            ErrorCode::InvalidTerms,
            "matching policy requires explicit recipient restrictions",
        ));
    }
    let mut allowed = BTreeSet::new();
    for id in &policy.allowed_recipient_ids {
        validate_id(id, "allowed recipient ID")?;
        if !allowed.insert(id) {
            return Err(CoreError::new(
                ErrorCode::DuplicateIdentifier,
                "duplicate allowed recipient",
            ));
        }
    }
    let mut recipients = BTreeSet::new();
    for id in recipient_ids {
        validate_id(id, "recipient ID")?;
        if !recipients.insert(id) {
            return Err(CoreError::new(
                ErrorCode::DuplicateIdentifier,
                "duplicate match recipient",
            ));
        }
        if !allowed.contains(id) {
            return Err(CoreError::new(
                ErrorCode::InvalidTerms,
                "recipient is not allowed by the sponsor policy",
            ));
        }
    }
    if let MatchAssurance::Attested { verifier_identity } = &policy.assurance {
        validate_id(verifier_identity, "trusted verifier identity")?;
    }
    let mut participants = BTreeSet::new();
    let mut accounts = BTreeSet::new();
    let mut inputs = BTreeSet::new();
    let mut returns = BTreeSet::new();
    for allocation in eligible.iter().chain(std::iter::once(sponsor)) {
        validate_id(&allocation.participant_id, "match participant ID")?;
        validate_id(&allocation.account_id, "match account ID")?;
        if !participants.insert(&allocation.participant_id)
            || !accounts.insert(&allocation.account_id)
        {
            return Err(CoreError::new(
                ErrorCode::InvalidTerms,
                "sponsor and contributor participant/account allocations must not overlap",
            ));
        }
        if allocation.input_ids.is_empty()
            || allocation.input_ids.len() > 256
            || allocation.return_output_ids.len() > 256
        {
            return Err(CoreError::new(
                ErrorCode::ResourceLimit,
                "match allocation requires 1..=256 inputs and at most 256 return outputs",
            ));
        }
        for id in &allocation.input_ids {
            validate_id(id, "match input ID")?;
            if !inputs.insert(id) {
                return Err(CoreError::new(
                    ErrorCode::DuplicateIdentifier,
                    "overlapping match input allocation",
                ));
            }
        }
        for id in &allocation.return_output_ids {
            validate_id(id, "match return output ID")?;
            if !returns.insert(id) {
                return Err(CoreError::new(
                    ErrorCode::DuplicateIdentifier,
                    "overlapping match return allocation",
                ));
            }
        }
    }
    let eligible_total = Amount::checked_sum(eligible.iter().map(|a| a.contribution))?;
    eligible_total.checked_add(sponsor.contribution)?;
    if eligible_total < policy.minimum_qualifying_total {
        return Err(CoreError::new(
            ErrorCode::InvalidTerms,
            "eligible contribution total is below the sponsor minimum",
        ));
    }
    let floor = (u128::from(eligible_total.as_zatoshis()) * u128::from(policy.rate_numerator))
        / u128::from(policy.rate_denominator);
    let capped = floor.min(u128::from(policy.maximum_match.as_zatoshis()));
    let calculated_match = Amount::from_zatoshis(capped as u64)?;
    if sponsor.contribution != calculated_match {
        return Err(CoreError::new(
            ErrorCode::ConservationFailure,
            "declared sponsor contribution differs from the floored, capped match",
        ));
    }
    let mut required_evidence = vec![
        "Account inputs and independently verified return-output ownership bound to the exact transaction".into(),
        "Authenticated sponsor identity and account attribution bound to agreement and proposal revision".into(),
        "Disclosed eligibility evidence sufficient for the selected policy".into(),
    ];
    if let MatchAssurance::Attested { verifier_identity } = &policy.assurance {
        required_evidence.push(format!("A validated, transaction-bound attestation from the explicitly trusted verifier {verifier_identity}"));
    }
    Ok(MatchEvaluation {
        eligible_total,
        calculated_match,
        assurance: policy.assurance.clone(),
        evidence_status: MatchEvidenceStatus::Unverifiable,
        authorization_allowed: false,
        required_evidence,
        limitations: vec![
            "Arithmetic consistency is not proof of input ownership, sponsor funding, or a valid transaction".into(),
            "Account attribution does not establish distinct people or independent economic sources".into(),
            "No qualified ownership or attestation verifier is included in this build".into(),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn a(n: u64) -> Amount {
        Amount::from_zatoshis(n).unwrap()
    }
    fn allocation(id: &str, contribution: u64) -> MatchAllocation {
        MatchAllocation {
            participant_id: id.into(),
            account_id: format!("account-{id}"),
            contribution: a(contribution),
            input_ids: vec![format!("input-{id}")],
            return_output_ids: vec![],
        }
    }
    fn policy() -> MatchPolicy {
        MatchPolicy {
            sponsor_participant_id: "sponsor".into(),
            rate_numerator: 2,
            rate_denominator: 3,
            maximum_match: a(10),
            minimum_qualifying_total: a(1),
            allowed_recipient_ids: vec!["recipient".into()],
            assurance: MatchAssurance::IndependentlyVerified,
        }
    }

    #[test]
    fn floor_then_cap_and_evidence_boundary() {
        let result = evaluate_match(
            &policy(),
            &[allocation("alice", 8)],
            &allocation("sponsor", 5),
            &["recipient".into()],
        )
        .unwrap();
        assert_eq!(result.calculated_match, a(5));
        assert!(!result.authorization_allowed);
        assert_eq!(result.evidence_status, MatchEvidenceStatus::Unverifiable);
        let result = evaluate_match(
            &policy(),
            &[allocation("alice", 100)],
            &allocation("sponsor", 10),
            &["recipient".into()],
        )
        .unwrap();
        assert_eq!(result.calculated_match, a(10));
    }

    #[test]
    fn sponsor_overlap_and_wrong_contribution_fail() {
        let sponsor = allocation("sponsor", 5);
        let mut contributor = allocation("alice", 8);
        contributor.input_ids = sponsor.input_ids.clone();
        assert_eq!(
            evaluate_match(&policy(), &[contributor], &sponsor, &["recipient".into()])
                .unwrap_err()
                .code,
            ErrorCode::DuplicateIdentifier
        );
        assert!(evaluate_match(
            &policy(),
            &[allocation("alice", 8)],
            &allocation("sponsor", 6),
            &["recipient".into()]
        )
        .is_err());
    }

    #[test]
    fn enormous_rate_is_safely_capped_and_attestation_does_not_verify_itself() {
        let mut policy = policy();
        policy.rate_numerator = u64::MAX;
        policy.assurance = MatchAssurance::Attested {
            verifier_identity: "named-verifier".into(),
        };
        let result = evaluate_match(
            &policy,
            &[allocation("alice", crate::MAX_MONEY - 10)],
            &allocation("sponsor", 10),
            &["recipient".into()],
        )
        .unwrap();
        assert_eq!(result.calculated_match, a(10));
        assert!(!result.authorization_allowed);
        assert!(matches!(result.assurance, MatchAssurance::Attested { .. }));
        policy.rate_denominator = 0;
        assert!(evaluate_match(
            &policy,
            &[allocation("alice", 1)],
            &allocation("sponsor", 0),
            &["recipient".into()]
        )
        .is_err());
    }
}
