//! Deterministic largest-remainder allocation with ascending ASCII ID tie breaks.
use crate::{
    amount::Amount,
    error::{validate_id, CoreError, ErrorCode, Result},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeeWeight {
    pub participant_id: String,
    pub contribution: Amount,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FeePolicy {
    ProRata,
    /// This explicitly quoted part is paid first. The remainder is pro rata.
    Sponsor {
        participant_id: String,
        amount: Amount,
    },
}

pub fn allocate_fees(
    total_fee: Amount,
    weights: &[FeeWeight],
    policy: &FeePolicy,
) -> Result<BTreeMap<String, Amount>> {
    if weights.is_empty() || weights.len() > 32 {
        return Err(CoreError::new(
            ErrorCode::ResourceLimit,
            "fee allocation requires 1..=32 participants",
        ));
    }
    let mut shares = BTreeMap::new();
    for weight in weights {
        validate_id(&weight.participant_id, "participant ID")?;
        if shares
            .insert(weight.participant_id.clone(), Amount::ZERO)
            .is_some()
        {
            return Err(CoreError::new(
                ErrorCode::DuplicateIdentifier,
                "duplicate fee participant",
            ));
        }
    }
    let remaining = match policy {
        FeePolicy::ProRata => total_fee,
        FeePolicy::Sponsor {
            participant_id,
            amount,
        } => {
            let share = shares.get_mut(participant_id).ok_or_else(|| {
                CoreError::new(
                    ErrorCode::UnknownParticipant,
                    "fee sponsor is not in the roster",
                )
            })?;
            if *amount > total_fee {
                return Err(CoreError::new(
                    ErrorCode::InvalidTerms,
                    "sponsored fee portion exceeds the total fee",
                ));
            }
            *share = *amount;
            total_fee.checked_sub(*amount)?
        }
    };
    let total_weight = Amount::checked_sum(weights.iter().map(|w| w.contribution))?;
    if total_weight == Amount::ZERO && matches!(policy, FeePolicy::ProRata) {
        return Err(CoreError::new(
            ErrorCode::InvalidTerms,
            "pro-rata fees require a positive contribution base",
        ));
    }
    if remaining == Amount::ZERO {
        return Ok(shares);
    }
    if total_weight == Amount::ZERO {
        return Err(CoreError::new(
            ErrorCode::InvalidTerms,
            "positive pro-rata fees require a positive contribution base",
        ));
    }
    let denominator = u128::from(total_weight.as_zatoshis());
    let mut remainders = Vec::with_capacity(weights.len());
    let mut distributed = Amount::ZERO;
    for weight in weights {
        // A product of two bounded u64 values fits u128; no float or rounding.
        let numerator =
            u128::from(remaining.as_zatoshis()) * u128::from(weight.contribution.as_zatoshis());
        let floor = Amount::from_zatoshis((numerator / denominator) as u64)?;
        let existing = shares
            .get_mut(&weight.participant_id)
            .expect("roster was initialized");
        *existing = existing.checked_add(floor)?;
        distributed = distributed.checked_add(floor)?;
        remainders.push((weight.participant_id.as_str(), numerator % denominator));
    }
    remainders.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    let leftover = remaining.checked_sub(distributed)?.as_zatoshis() as usize;
    // The sum of the fractional remainders is strictly below the roster size.
    if leftover >= weights.len() {
        return Err(CoreError::new(
            ErrorCode::ConservationFailure,
            "invalid largest-remainder residue",
        ));
    }
    for (id, _) in remainders.into_iter().take(leftover) {
        let share = shares.get_mut(id).expect("roster was initialized");
        *share = share.checked_add(Amount::from_zatoshis(1)?)?;
    }
    if Amount::checked_sum(shares.values().copied())? != total_fee {
        return Err(CoreError::new(
            ErrorCode::ConservationFailure,
            "fee allocation did not conserve the total",
        ));
    }
    Ok(shares)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amount::MAX_MONEY;

    fn a(n: u64) -> Amount {
        Amount::from_zatoshis(n).unwrap()
    }
    fn weight(id: &str, value: u64) -> FeeWeight {
        FeeWeight {
            participant_id: id.into(),
            contribution: a(value),
        }
    }

    #[test]
    fn published_example_and_tie_break_are_exact() {
        let weights = [
            weight("buyer-a", 200_000_000),
            weight("buyer-b", 300_000_000),
            weight("sponsor", 500_000_000),
        ];
        let shares = allocate_fees(a(30_000), &weights, &FeePolicy::ProRata).unwrap();
        assert_eq!(shares["buyer-a"], a(6_000));
        assert_eq!(shares["buyer-b"], a(9_000));
        assert_eq!(shares["sponsor"], a(15_000));
        let forward = [weight("b", 1), weight("a", 1), weight("c", 1)];
        let reverse = [weight("c", 1), weight("a", 1), weight("b", 1)];
        let shares = allocate_fees(a(2), &forward, &FeePolicy::ProRata).unwrap();
        assert_eq!(
            shares,
            allocate_fees(a(2), &reverse, &FeePolicy::ProRata).unwrap()
        );
        assert_eq!(
            shares.values().copied().collect::<Vec<_>>(),
            vec![a(1), a(1), a(0)]
        );
    }

    #[test]
    fn explicit_partial_sponsor_and_zero_weights() {
        let weights = [weight("a", 1), weight("b", 1), weight("s", 0)];
        let shares = allocate_fees(
            a(9),
            &weights,
            &FeePolicy::Sponsor {
                participant_id: "s".into(),
                amount: a(4),
            },
        )
        .unwrap();
        assert_eq!(shares["a"], a(3));
        assert_eq!(shares["b"], a(2));
        assert_eq!(shares["s"], a(4));
        assert!(allocate_fees(a(1), &[weight("a", 0)], &FeePolicy::ProRata).is_err());
    }

    #[test]
    fn large_products_do_not_overflow_and_duplicate_ids_fail() {
        let shares = allocate_fees(
            a(MAX_MONEY),
            &[weight("a", MAX_MONEY - 1), weight("b", 1)],
            &FeePolicy::ProRata,
        )
        .unwrap();
        assert_eq!(shares["a"], a(MAX_MONEY - 1));
        assert_eq!(shares["b"], a(1));
        assert_eq!(
            allocate_fees(a(1), &[weight("a", 1), weight("a", 1)], &FeePolicy::ProRata)
                .unwrap_err()
                .code,
            ErrorCode::DuplicateIdentifier
        );
    }

    #[test]
    fn small_allocations_conserve_exactly() {
        for first in 0..12 {
            for second in 0..12 {
                if first + second == 0 {
                    continue;
                }
                for fee in 0..12 {
                    let shares = allocate_fees(
                        a(fee),
                        &[weight("a", first), weight("b", second)],
                        &FeePolicy::ProRata,
                    )
                    .unwrap();
                    assert_eq!(
                        Amount::checked_sum(shares.values().copied()).unwrap(),
                        a(fee)
                    );
                }
            }
        }
    }
}
