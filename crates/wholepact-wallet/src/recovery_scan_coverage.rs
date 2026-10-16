//! Diagnostic evidence coverage only, produced by the maintained local read.
//! No Deserialize, completion permit, public constructor or balance-clear path.
use super::KnownPoolBalance;
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetirementEvidenceGap {
    EarliestAccountActivityBoundary,
    AuthenticatedFullAccountComponentInventory,
    CompletePendingAndFullTransactionHistory,
    IndependentCanonicalUnspentEvidence,
    CurrentAllAuthorizationAndReservationHistory,
}
#[derive(Debug, Serialize)]
pub struct RetirementCoverageReport {
    schema_version: u32,
    evidence_kind: &'static str,
    inspected_wallet_key_profile: &'static str,
    claimed_import_birthday_height: u32,
    local_fully_scanned_tip_height: u32,
    outstanding_wallet_transaction_data_requests: u32,
    wallet_request_queue_semantics: &'static str,
    known_funds_observed: bool,
    missing_evidence: [RetirementEvidenceGap; 5],
    retirement_completion: &'static str,
}

pub(super) fn report(
    birthday: u32,
    tip: u32,
    requests: u32,
    orchard: KnownPoolBalance,
    ironwood: KnownPoolBalance,
) -> RetirementCoverageReport {
    RetirementCoverageReport {
        schema_version: 1,
        evidence_kind: "incomplete_local_wallet_retirement_coverage",
        inspected_wallet_key_profile: "canonical_r0_orchard_only_with_orchard_and_ironwood_balances",
        claimed_import_birthday_height: birthday,
        local_fully_scanned_tip_height: tip,
        outstanding_wallet_transaction_data_requests: requests,
        wallet_request_queue_semantics: "known_requests_only_zero_does_not_prove_complete_pending_history",
        known_funds_observed: orchard.has_funds() || ironwood.has_funds(),
        missing_evidence: [
            RetirementEvidenceGap::EarliestAccountActivityBoundary,
            RetirementEvidenceGap::AuthenticatedFullAccountComponentInventory,
            RetirementEvidenceGap::CompletePendingAndFullTransactionHistory,
            RetirementEvidenceGap::IndependentCanonicalUnspentEvidence,
            RetirementEvidenceGap::CurrentAllAuthorizationAndReservationHistory,
        ],
        retirement_completion: "unavailable",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn zero() -> KnownPoolBalance {
        KnownPoolBalance {
            total_zatoshis: 0,
            spendable_zatoshis: 0,
            locked_zatoshis: 0,
            pending_change_zatoshis: 0,
            pending_spendability_zatoshis: 0,
            uneconomic_zatoshis: 0,
        }
    }
    #[test]
    fn zero_balance_and_empty_request_queue_never_prove_retirement_completion() {
        let view = report(100, 101, 0, zero(), zero());
        assert!(!view.known_funds_observed);
        assert_eq!(view.retirement_completion, "unavailable");
        assert_eq!(view.missing_evidence.len(), 5);
        assert!(
            view.missing_evidence
                .contains(&RetirementEvidenceGap::CompletePendingAndFullTransactionHistory)
        );
        assert!(
            view.missing_evidence
                .contains(&RetirementEvidenceGap::EarliestAccountActivityBoundary)
        );
    }
    #[test]
    fn every_known_fund_category_blocks_empty_interpretation_independently() {
        for field in 0..6 {
            let mut balance = zero();
            match field {
                0 => balance.total_zatoshis = 1,
                1 => balance.spendable_zatoshis = 1,
                2 => balance.locked_zatoshis = 1,
                3 => balance.pending_change_zatoshis = 1,
                4 => balance.pending_spendability_zatoshis = 1,
                _ => balance.uneconomic_zatoshis = 1,
            }
            for (orchard, ironwood) in [(balance, zero()), (zero(), balance)] {
                assert!(report(100, 101, 0, orchard, ironwood).known_funds_observed);
                assert!(matches!(
                    super::super::completion_gate(orchard, ironwood),
                    Err(super::super::RecoveryScanError::KnownFundsRemain)
                ));
            }
        }
    }
    #[test]
    fn chosen_late_birthday_and_known_pending_requests_are_disclosed_without_promoting_coverage() {
        let view = report(999, 1000, 7, zero(), zero());
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["claimed_import_birthday_height"], 999);
        assert_eq!(json["outstanding_wallet_transaction_data_requests"], 7);
        assert_eq!(json["retirement_completion"], "unavailable");
        assert_eq!(
            view.missing_evidence,
            report(1, 1000, 0, zero(), zero()).missing_evidence
        );
    }
}
