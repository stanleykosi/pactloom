//! Live independently paired owner attribution for an exact fixed proposal.
//! This gate is used immediately before normal cryptographic construction; it
//! cannot replace construction, proof verification, native spending review or
//! atomic witness reservation. No serialized success flag is accepted.
use super::*;
use wholepact_signer::authority_bridge::preconstruction_ipc::SignerPreconstructionLease;

#[derive(Serialize)]
pub struct SponsorOwnerReview {
    pub candidate_id: String,
    pub manifest_digest: String,
    pub policy_digest: String,
    pub formula: SponsorFormulaPreview,
    pub budget: SponsorBudgetPreview,
    pub owner_attestation_digest: String,
    pub witness_id: String,
    pub witness_policy_digest: String,
    pub witness_head_digest: String,
    pub assurance: &'static str,
    pub authorization_allowed: bool,
}
impl Engine {
    /// Source-only path. Every account owner independently approved its exact
    /// participant mapping and viewing material on the installed signer. Those
    /// account-control facts do not imply legal identities or distinct people.
    pub fn review_sponsor_from_live_owners(
        &self,
        access: &Access,
        candidate_id: &str,
        terms: &SponsorPolicyTerms,
        leases: &[SignerPreconstructionLease<'_>],
    ) -> Result<SponsorOwnerReview> {
        let (view, candidate) = self.candidate(access, candidate_id)?;
        let proposal = candidate.verified_snapshot()?;
        candidates::check_current_terms(&view, proposal.manifest())?;
        if view.candidates.last().map(|v| v.candidate_id.as_str()) != Some(candidate_id)
            || !view.roster_selected
            || !terms.identity_requirements.is_empty()
            || !matches!(
                terms.assurance,
                wholepact_core::MatchAssurance::Attested { .. }
            )
            || terms.expires_at.as_deref().is_some_and(expired)
            || leases.len() != proposal.manifest().participants.len()
        {
            return Err(source_error());
        }
        let mut accounts = std::collections::BTreeSet::new();
        let mut keys = std::collections::BTreeSet::new();
        for lease in leases {
            lease.check_current().map_err(|_| source_error())?;
            let scope = lease.scope();
            if scope.principal_id != access.principal_id
                || scope.proposal != candidate.proposal
                || lease.manifest_digest() != candidate.manifest_digest
                || !accounts.insert(lease.account_id())
                || !keys.insert(lease.fvk().to_bytes())
                || !proposal.manifest().participants.iter().any(|p| {
                    p.account_id == scope.account_id && p.participant_id == scope.participant_id
                })
            {
                return Err(source_error());
            }
        }
        let sponsor = leases
            .iter()
            .find(|l| l.account_id() == terms.sponsor.account_id)
            .ok_or_else(source_error)?;
        if sponsor.sponsor_policy() != Some(terms) {
            return Err(source_error());
        }
        let snapshot = sponsor
            .sponsor_budget()
            .map_err(|_| source_error())?
            .ok_or_else(source_error)?;
        // The shared atomic witness cap must itself enforce this lifetime cap.
        // A lower snapshot-derived allowance would race other applications.
        if snapshot.aggregate_budget_zatoshis > terms.aggregate_budget.as_zatoshis() {
            return Err(source_error());
        }
        let formula = evaluate_sponsor_policy(terms, proposal.manifest())?;
        let pending = Amount::from_zatoshis(snapshot.outstanding_debit_zatoshis)
            .map_err(|_| source_error())?;
        let settled =
            Amount::from_zatoshis(snapshot.settled_debit_zatoshis).map_err(|_| source_error())?;
        let remaining = terms
            .aggregate_budget
            .checked_sub(pending.checked_add(settled).map_err(|_| source_error())?)
            .map_err(|_| source_error())?;
        let account_remaining = Amount::from_zatoshis(
            snapshot
                .remaining_budget_zatoshis()
                .map_err(|_| source_error())?,
        )
        .map_err(|_| source_error())?;
        let remaining = remaining.min(account_remaining);
        if formula.sponsor_net_debit > remaining {
            return Err(source_error());
        }
        for lease in leases {
            lease.check_current().map_err(|_| source_error())?;
        }
        let owner_attestation_digest = sponsor
            .attest_sponsor_accounts(leases)
            .map_err(|_| source_error())?;
        Ok(SponsorOwnerReview {
            candidate_id: candidate_id.into(),
            manifest_digest: candidate.manifest_digest,
            policy_digest: hash_domain(b"wholepact:owner-reviewed-sponsor-terms:v1\0", &json!(terms))?,
            formula,
            budget: SponsorBudgetPreview {
                aggregate_budget: Amount::from_zatoshis(snapshot.aggregate_budget_zatoshis)
                    .map_err(|_| source_error())?,
                pending_authorization_exposure: Some(pending),
                settled_debit: Some(settled),
                remaining_budget: Some(remaining),
                status: "live_signer_disclosed_reconciled_witness_head".into(),
                reason: "Complete authenticated witness history; this effective aggregate cap is the shared witness cap, which may be stricter than the sponsor policy. All applications share it. Display reserves nothing. The actual signer must obtain an atomic exact permit; consumed debit stays charged and reorg moves it back to pending.".into(),
            },
            owner_attestation_digest,
            witness_id: snapshot.witness_id.clone(),
            witness_policy_digest: snapshot.policy_digest.clone(),
            witness_head_digest: snapshot.head.digest.clone(),
            assurance: "named_local_verifier_attested_account_control_transaction_verification_required",
            authorization_allowed: false,
        })
    }
}
fn source_error() -> ApiError {
    ApiError::new(
        "SPONSOR_EVIDENCE_UNAVAILABLE",
        "Exact live owner attribution, explicit sponsor disclosure, current full witness budget, or supported account-only eligibility is unavailable; no authorization is issued",
    )
}
