//! Selected-own policy derived from retained acceptance and maintained selection.
//! Only the actual dedicated account supplies viewing authority. Peer ownership,
//! chain freshness, proof validity, account-wide completeness and signing consent
//! are not established here; a named verifier's assertion establishes none of
//! those facts merely by being signed. This module issues expectations, not a
//! reservation, journal admission, native decision or key-use authority.

use super::{AcceptedManifest, LocalSelection};
use crate::{Error, Result, account::DedicatedAccount};
use orchard::Anchor;
use std::collections::{BTreeMap, BTreeSet};
use wholepact_core::{Amount, OutputAllocation, PrivacyMode};
use wholepact_protocol::{
    construction::{ConstructionContext, InputActionMapping, OutputActionMapping, PROFILE_ID},
    own_effects::{OwnEffectsPolicy, OwnInputExpectation, OwnOutputExpectation, OwnOutputPurpose},
    review::decode_testnet_receiver,
};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, Network},
    memo::MemoBytes,
};

// Match the pinned protocol preflight's qualified real-action envelope. Actual
// PCZT action coverage and same-byte effects are still checked by own_effects.
const MAX_ACTIONS: usize = 64;

fn check(ok: bool) -> Result<()> {
    if ok { Ok(()) } else { Err(Error::Verification) }
}

/// This private adapter must be called with a genuine retained manifest and
/// maintained local selection by NativeWalletWorkspace. Its caller still needs
/// the original-history lease, live native binding and protected witness path.
/// Neither mappings nor imported peer FVKs can supply the selected nullifiers,
/// values, own account identity, debit limits, receiver ownership or memos.
pub(crate) fn derive_selected_own_policy(
    accepted: &AcceptedManifest,
    selected: &LocalSelection,
    account: &DedicatedAccount,
    context: &ConstructionContext,
    input_actions: &[InputActionMapping],
    output_actions: &[OutputActionMapping],
) -> Result<OwnEffectsPolicy> {
    let manifest = accepted.proposal.manifest();
    check(
        (1..=MAX_ACTIONS).contains(&manifest.inputs.len())
            && (1..=MAX_ACTIONS).contains(&manifest.outputs.len())
            && (1..=MAX_ACTIONS).contains(&selected.inputs.len())
            && input_actions.len() == manifest.inputs.len()
            && output_actions.len() == manifest.outputs.len()
            && manifest.agreement.network_profile_id == PROFILE_ID
            && manifest.agreement.extensions.is_empty()
            && manifest.participants.iter().all(|p| p.charges.is_empty())
            && manifest.agreement.privacy_profile.mode == PrivacyMode::DeclaredOperator
            && manifest
                .agreement
                .privacy_profile
                .dedicated_accounts_required
            && manifest
                .agreement
                .privacy_profile
                .proving_operator
                .as_deref()
                .is_some_and(|operator| !operator.trim().is_empty()),
    )?;
    // Reuse the checked integer accounting rules, including recipient IDs and
    // exact address text, fee allocation, account roster and return allocation.
    let accounting =
        wholepact_core::validate_claimed_accounting(manifest).map_err(|_| Error::Verification)?;
    let account_id = account.account_id()?;
    let own_fvk = account.fvk()?;
    check(selected.account_id == account_id && selected.fvk.to_bytes() == own_fvk.to_bytes())?;
    let owner = manifest
        .participants
        .iter()
        .find(|participant| participant.account_id == account_id)
        .ok_or(Error::Verification)?;

    let target_height = selected
        .context
        .tip_height
        .checked_add(1)
        .ok_or(Error::Verification)?;
    check(
        context.anchor == selected.context.anchor_root
            && context.anchor_height == selected.context.anchor_height
            && context.anchor_block_hash == selected.context.anchor_hash
            && context.target_height == target_height
            && selected.context.anchor_height <= selected.context.tip_height
            && selected.context.tip_hash != [0; 32]
            && selected.context.anchor_hash != [0; 32]
            && (selected.context.anchor_height != selected.context.tip_height
                || selected.context.anchor_hash == selected.context.tip_hash)
            && manifest.expiry_height >= target_height
            && manifest.expiry_height < 500_000_000
            && Option::<Anchor>::from(Anchor::from_bytes(context.anchor)).is_some(),
    )?;
    // ConstructionContext has no separate tip hash. The retained local selection
    // remains the sole tip-hash source; the caller must keep its freshness lease.
    for height in [target_height, manifest.expiry_height] {
        check(
            BranchId::for_height(&Network::TestNetwork, BlockHeight::from_u32(height))
                == BranchId::Nu7,
        )?;
    }

    let mut mapped_inputs = BTreeMap::new();
    let mut input_indices = BTreeSet::new();
    for mapping in input_actions {
        check(
            mapping.action_index < MAX_ACTIONS
                && mapping.input_id.len() <= 128
                && mapping.account_id.len() <= 128
                && mapped_inputs
                    .insert(mapping.input_id.as_str(), mapping)
                    .is_none()
                && input_indices.insert(mapping.action_index),
        )?;
    }
    let mut selected_inputs = BTreeMap::new();
    let mut nullifiers = BTreeSet::new();
    for input in &selected.inputs {
        check(
            input.input_id.len() <= 128
                && input.value > 0
                && selected_inputs
                    .insert(input.input_id.as_str(), input)
                    .is_none()
                && nullifiers.insert(input.nullifier),
        )?;
        Amount::from_zatoshis(input.value).map_err(|_| Error::Verification)?;
    }
    let mut own_inputs = Vec::with_capacity(selected.inputs.len());
    let mut own_input_total = Amount::ZERO;
    // Manifest order is part of the resulting policy commitment. Mapping-vector
    // order and maintained-selection enumeration order have no authority.
    for claimed in &manifest.inputs {
        let mapping = mapped_inputs
            .remove(claimed.input_id.as_str())
            .ok_or(Error::Verification)?;
        check(mapping.account_id == claimed.account_id)?;
        if claimed.account_id == account_id {
            check(claimed.participant_id == owner.participant_id)?;
            let local = selected_inputs
                .remove(claimed.input_id.as_str())
                .ok_or(Error::Verification)?;
            check(local.value == claimed.amount.as_zatoshis())?;
            own_input_total = own_input_total
                .checked_add(claimed.amount)
                .map_err(|_| Error::Verification)?;
            own_inputs.push(OwnInputExpectation {
                action_index: mapping.action_index,
                nullifier: local.nullifier,
                value_zatoshis: local.value,
            });
        }
    }
    check(mapped_inputs.is_empty() && selected_inputs.is_empty() && !own_inputs.is_empty())?;

    let mut mapped_outputs = BTreeMap::new();
    let mut output_indices = BTreeSet::new();
    for mapping in output_actions {
        check(
            mapping.action_index < MAX_ACTIONS
                && mapping.output_id.len() <= 128
                && mapped_outputs
                    .insert(mapping.output_id.as_str(), mapping)
                    .is_none()
                && output_indices.insert(mapping.action_index),
        )?;
    }
    let mut outputs = Vec::with_capacity(manifest.outputs.len());
    let mut own_return_total = Amount::ZERO;
    for claimed in &manifest.outputs {
        let mapping = mapped_outputs
            .remove(claimed.output_id.as_str())
            .ok_or(Error::Verification)?;
        let receiver =
            decode_testnet_receiver(&claimed.address).map_err(|_| Error::Verification)?;
        let owned = own_fvk.scope_for_address(&receiver).is_some();
        let (purpose, memo) = match &claimed.allocation {
            OutputAllocation::Recipient { recipient_id } => {
                let recipient = manifest
                    .agreement
                    .recipients
                    .iter()
                    .find(|recipient| recipient.recipient_id == *recipient_id)
                    .ok_or(Error::Verification)?;
                check(
                    !owned
                        && recipient.address == claimed.address
                        && recipient.amount == claimed.amount,
                )?;
                let memo = recipient
                    .memo
                    .as_ref()
                    .map(|text| MemoBytes::from_bytes(text.as_bytes()))
                    .transpose()
                    .map_err(|_| Error::Verification)?
                    .unwrap_or_else(MemoBytes::empty);
                (OwnOutputPurpose::Recipient, memo)
            }
            OutputAllocation::Return {
                participant_id,
                account_id: return_account,
                ..
            } => {
                let participant = manifest
                    .participants
                    .iter()
                    .find(|participant| participant.participant_id == *participant_id)
                    .ok_or(Error::Verification)?;
                check(participant.account_id == *return_account)?;
                let purpose = if return_account == &account_id {
                    check(owned && participant_id == &owner.participant_id)?;
                    own_return_total = own_return_total
                        .checked_add(claimed.amount)
                        .map_err(|_| Error::Verification)?;
                    OwnOutputPurpose::OwnReturn
                } else {
                    // Peer account/participant names are accepted allocations,
                    // never proof that the peer controls this return receiver.
                    check(!owned)?;
                    OwnOutputPurpose::PeerReturnUnverified
                };
                (purpose, MemoBytes::empty())
            }
            OutputAllocation::Charge { .. } => return Err(Error::Verification),
        };
        outputs.push(OwnOutputExpectation {
            action_index: mapping.action_index,
            receiver,
            value_zatoshis: claimed.amount.as_zatoshis(),
            memo: memo.into_bytes(),
            purpose,
        });
    }
    check(mapped_outputs.is_empty())?;
    let exact_debit = owner
        .contribution
        .checked_add(owner.fee_share)
        .map_err(|_| Error::Verification)?;
    check(
        accounting.participant_net_debits.get(&owner.participant_id) == Some(&exact_debit)
            && own_input_total
                .checked_sub(own_return_total)
                .map_err(|_| Error::Verification)?
                == exact_debit
            && exact_debit <= owner.maximum_net_debit
            && owner.fee_share <= owner.fee_cap
            && owner.fee_share <= manifest.transaction_fee,
    )?;

    Ok(OwnEffectsPolicy {
        account_id,
        own_fvk,
        manifest_digest: hex::decode(accepted.digest())
            .map_err(|_| Error::Verification)?
            .try_into()
            .map_err(|_| Error::Verification)?,
        anchor: context.anchor,
        expiry_height: manifest.expiry_height,
        maximum_selected_net_debit_zatoshis: owner.maximum_net_debit.as_zatoshis(),
        exact_selected_net_debit_zatoshis: exact_debit.as_zatoshis(),
        declared_fee_share_zatoshis: owner.fee_share.as_zatoshis(),
        exact_transaction_fee_zatoshis: manifest.transaction_fee.as_zatoshis(),
        own_inputs,
        outputs,
    })
}

#[cfg(test)]
mod tests;
