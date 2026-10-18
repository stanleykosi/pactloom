//! Pure economic planning from historical metadata, never an authenticated
//! intake, current unspentness proof, disclosure permission or spend approval.
//! This leaf is intentionally unregistered until the native discovery route and
//! Engine receipt joins are complete. The actual constructor still independently
//! computes the fee from its real maintained builder and exact selected notes.
use std::collections::{BTreeMap, BTreeSet};
use wholepact_core::{
    allocate_fees, durable_input_projection_v1::DurableInputProjectionV1, Amount, ClaimedInput,
    ClaimedOutput, FeeWeight, OutputAllocation, ParticipantAllocation, Proposal, ProposalInput,
    ProposalManifest,
};
use zcash_primitives::transaction::{
    builder::BundlePadding,
    fees::{zip317, FeeRule as _},
};
use zcash_protocol::consensus::{BlockHeight, BranchId, Network};

type Result<T> = std::result::Result<T, String>;
fn invalid() -> String {
    "Retained projection shape cannot form this bounded exact plain candidate; obtain a distinct explicit discovery rather than reselecting inputs".into()
}

/// The SAME maintained padding and standard-fee implementation used by actual
/// construction. Counts are inert claims here; the later builder verifies them.
fn exact_shape_fee(target: u32, inputs: usize, outputs: usize) -> Result<Amount> {
    if !(2..=8).contains(&inputs)
        || !(1..=3).contains(&outputs)
        || BranchId::for_height(&Network::TestNetwork, BlockHeight::from_u32(target))
            != BranchId::Nu7
    {
        return Err(invalid());
    }
    let actions = BundlePadding::DEFAULT
        .bundle_type()
        .num_actions(
            orchard::bundle::BundleVersion::ironwood_v3().default_flags(),
            inputs,
            outputs,
        )
        .map_err(|_| invalid())?;
    if actions > 8 {
        return Err(invalid());
    }
    let value = zip317::FeeRule::standard()
        .fee_required(
            &Network::TestNetwork,
            target.into(),
            [],
            [],
            0,
            0,
            0,
            actions,
        )
        .map_err(|_| invalid())?;
    Amount::from_zatoshis(u64::from(value)).map_err(|_| invalid())
}

/// Both exact authenticated receipt references must be joined by the Engine
/// BEFORE calling. Passing arbitrary public DTOs here grants no permission.
///
/// The selected note identifiers never change. We evaluate all three possible
/// output counts (one recipient and zero/one/two positive own returns) and keep
/// only a unique fee/return fixed point. We never discard dust, overpay a fee,
/// add an input, or broaden an owner's maximum debit to force construction.
pub fn candidate_from_retained_projections_v1(
    projections: &[DurableInputProjectionV1],
    created_at: &str,
) -> Result<Proposal> {
    if projections.len() != 2 {
        return Err(invalid());
    }
    let mut owners: Vec<_> = projections.iter().collect();
    owners.sort_by(|a, b| a.intent.account_id.cmp(&b.intent.account_id));
    for owner in &owners {
        owner.validate().map_err(|_| invalid())?;
    }
    let first = owners[0];
    let second = owners[1];
    let intent = &first.intent;
    if intent.account_id == second.intent.account_id
        || intent.participant_id == second.intent.participant_id
        || intent.agreement != second.intent.agreement
        || intent.proposal_id != second.intent.proposal_id
        || intent.provider != second.intent.provider
        || intent.transaction_expiry_height != second.intent.transaction_expiry_height
        || intent.constructor_principal_id != second.intent.constructor_principal_id
        || intent.protected_destination != second.intent.protected_destination
        || intent.local_reviewer_account_ids != second.intent.local_reviewer_account_ids
        || intent.local_reviewer_account_ids
            != vec![intent.account_id.clone(), second.intent.account_id.clone()]
        || intent
            .contribution
            .checked_add(second.intent.contribution)
            .map_err(|_| invalid())?
            != intent.agreement.recipients[0].amount
    {
        return Err(invalid());
    }
    // Discovery contexts stay historical and may have different anchors. They
    // are NOT a common proof anchor. Reject contradictions at shared heights,
    // but leave ancestry and the separately approved construction anchor to
    // maintained exact-ID recapture. Never overwrite either saved context.
    let mut observed_blocks = BTreeMap::new();
    for owner in &owners {
        for (height, hash) in [
            (owner.context.tip_height, &owner.context.tip_hash),
            (owner.context.anchor_height, &owner.context.anchor_hash),
        ] {
            if observed_blocks
                .insert(height, hash)
                .is_some_and(|prior| prior != hash)
            {
                return Err(invalid());
            }
        }
    }
    if first.context.anchor_height == second.context.anchor_height
        && first.context.anchor_root != second.context.anchor_root
    {
        return Err(invalid());
    }
    let target = first
        .context
        .tip_height
        .max(second.context.tip_height)
        .checked_add(1)
        .ok_or_else(invalid)?;
    if target >= intent.transaction_expiry_height
        || BranchId::for_height(
            &Network::TestNetwork,
            intent.transaction_expiry_height.into(),
        ) != BranchId::Nu7
    {
        return Err(invalid());
    }
    let count = owners.iter().map(|o| o.inputs.len()).sum::<usize>();
    let mut seen = BTreeSet::new();
    let inputs = owners
        .iter()
        .flat_map(|owner| {
            owner.inputs.iter().map(|input| ClaimedInput {
                input_id: input.input_id.clone(),
                participant_id: owner.intent.participant_id.clone(),
                account_id: owner.intent.account_id.clone(),
                amount: input.value,
                ownership_evidence_ref: None,
            })
        })
        .collect::<Vec<_>>();
    if inputs
        .iter()
        .any(|input| !seen.insert(input.input_id.as_str()))
    {
        return Err(invalid());
    }
    let weights = owners
        .iter()
        .map(|owner| FeeWeight {
            participant_id: owner.intent.participant_id.clone(),
            contribution: owner.intent.contribution,
        })
        .collect::<Vec<_>>();
    let mut solution = None;
    for expected_outputs in 1..=3 {
        let fee = exact_shape_fee(target, count, expected_outputs)?;
        if owners
            .iter()
            .any(|o| fee > o.intent.maximum_transaction_fee)
        {
            continue;
        }
        let shares =
            allocate_fees(fee, &weights, &intent.agreement.fee_policy).map_err(|_| invalid())?;
        let recipient = &intent.agreement.recipients[0];
        let mut outputs = vec![ClaimedOutput {
            output_id: "durable-recipient-v1".into(),
            address: recipient.address.clone(),
            amount: recipient.amount,
            allocation: OutputAllocation::Recipient {
                recipient_id: recipient.recipient_id.clone(),
            },
        }];
        let mut participants = Vec::new();
        let mut feasible = true;
        for (index, owner) in owners.iter().enumerate() {
            let own = &owner.intent;
            let share = shares[&own.participant_id];
            let debit = own.contribution.checked_add(share).map_err(|_| invalid())?;
            if share > own.maximum_fee_share || debit > owner.selected_total {
                feasible = false;
                break;
            }
            let returned = owner
                .selected_total
                .checked_sub(debit)
                .map_err(|_| invalid())?;
            participants.push(ParticipantAllocation {
                participant_id: own.participant_id.clone(),
                account_id: own.account_id.clone(),
                contribution: own.contribution,
                fee_share: share,
                fee_cap: own.maximum_fee_share,
                maximum_net_debit: debit,
                charges: vec![],
            });
            if returned != Amount::ZERO {
                outputs.push(ClaimedOutput {
                    output_id: format!("durable-return-{index}-v1"),
                    address: owner.own_return_receiver.clone(),
                    amount: returned,
                    allocation: OutputAllocation::Return {
                        participant_id: own.participant_id.clone(),
                        account_id: own.account_id.clone(),
                        ownership_evidence_ref: None,
                    },
                });
            }
        }
        if !feasible || outputs.len() != expected_outputs {
            continue;
        }
        let input = ProposalInput {
            proposal_id: intent.proposal_id.clone(),
            previous_proposal_id: None,
            artifact_digest: None,
            effects_commitment: None,
            created_at: created_at.into(),
            manifest: ProposalManifest {
                agreement: intent.agreement.clone(),
                participants,
                inputs: inputs.clone(),
                outputs,
                transaction_fee: fee,
                expiry_height: intent.transaction_expiry_height,
            },
        };
        for owner in &owners {
            owner
                .matches_final_proposal(&input)
                .map_err(|_| invalid())?;
        }
        let candidate = Proposal::validate(input).map_err(|_| invalid())?;
        if solution.is_some() {
            return Err(invalid());
        }
        solution = Some(candidate);
    }
    solution.ok_or_else(invalid)
}

#[cfg(test)]
mod tests;
