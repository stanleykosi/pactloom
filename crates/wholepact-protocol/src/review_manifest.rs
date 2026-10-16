//! Bind independently supplied local review policy to exact immutable terms.
//! Mappings select protocol actions; they do not authenticate account identity,
//! input-ID provenance, disclosure consent, human approval or chain state.
use crate::{
    construction::{InputActionMapping, OutputActionMapping, PROFILE_ID},
    review::{OutputPurpose, ReviewPolicy, decode_testnet_receiver},
};
use std::collections::BTreeSet;
use wholepact_core::{OutputAllocation, PrivacyMode, Proposal};
use zcash_protocol::memo::MemoBytes;

/// A non-secret commitment to the complete private policy, using the existing
/// maintained verifier's canonical binding. Never serialize the policy itself.
pub fn policy_fingerprint(policy: &ReviewPolicy) -> String {
    hex::encode(crate::review::policy_digest(policy))
}

/// Checks exact coverage and economic/address/memo semantics before cryptographic
/// review. The caller must source policies and mappings independently of the
/// incoming envelope. Every real policy input/output must map exactly once.
pub fn verify_manifest_policy(
    proposal: &Proposal,
    policy: &ReviewPolicy,
    inputs: &[InputActionMapping],
    outputs: &[OutputActionMapping],
) -> Result<(), String> {
    let m = proposal.manifest();
    check(
        m.agreement.network_profile_id == PROFILE_ID,
        "Unsupported review profile",
    )?;
    check(
        m.agreement.privacy_profile.mode == PrivacyMode::DeclaredOperator
            && m.agreement.privacy_profile.dedicated_accounts_required
            && m.agreement
                .privacy_profile
                .proving_operator
                .as_deref()
                .is_some_and(|p| !p.trim().is_empty()),
        "Broad-witness review requires an explicit dedicated-account operator profile",
    )?;
    check(
        m.agreement.extensions.is_empty() && m.participants.iter().all(|p| p.charges.is_empty()),
        "Unqualified extension or service charge",
    )?;
    check(
        hex::encode(policy.manifest_digest) == proposal.manifest_digest()
            && policy.expiry_height == m.expiry_height
            && policy.exact_fee_zatoshis == m.transaction_fee.as_zatoshis(),
        "Policy differs from accepted manifest, fee or expiry",
    )?;
    check(
        policy.participants.len() == m.participants.len(),
        "Participant policy coverage differs",
    )?;
    for (actual, expected) in policy.participants.iter().zip(&m.participants) {
        check(
            actual.account_id == expected.account_id
                && actual.contribution_zatoshis == expected.contribution.as_zatoshis()
                && actual.fee_share_zatoshis == expected.fee_share.as_zatoshis()
                && actual.maximum_net_debit_zatoshis == expected.maximum_net_debit.as_zatoshis(),
            "Participant policy differs from accepted allocation",
        )?;
    }
    check(
        inputs.len() == m.inputs.len()
            && policy.inputs.len() == inputs.len()
            && outputs.len() == m.outputs.len()
            && policy.outputs.len() == outputs.len(),
        "Action mapping coverage differs",
    )?;
    let mut input_ids = BTreeSet::new();
    let mut input_actions = BTreeSet::new();
    for mapping in inputs {
        check(
            input_ids.insert(&mapping.input_id) && input_actions.insert(mapping.action_index),
            "Duplicate input mapping",
        )?;
        let expected = m
            .inputs
            .iter()
            .find(|i| i.input_id == mapping.input_id)
            .ok_or("Unknown mapped input")?;
        let actual = policy
            .inputs
            .iter()
            .find(|i| i.action_index == mapping.action_index)
            .ok_or("Missing input policy action")?;
        let participant = m
            .participants
            .get(actual.participant_index)
            .ok_or("Invalid input participant")?;
        check(
            mapping.account_id == expected.account_id
                && participant.account_id == expected.account_id
                && participant.participant_id == expected.participant_id
                && actual.value_zatoshis == expected.amount.as_zatoshis(),
            "Input policy differs from accepted allocation",
        )?;
    }
    check(
        policy
            .inputs
            .iter()
            .map(|i| i.action_index)
            .collect::<BTreeSet<_>>()
            == input_actions,
        "Input policy contains duplicate or unmapped actions",
    )?;
    let mut output_ids = BTreeSet::new();
    let mut output_actions = BTreeSet::new();
    for mapping in outputs {
        check(
            output_ids.insert(&mapping.output_id) && output_actions.insert(mapping.action_index),
            "Duplicate output mapping",
        )?;
        let expected = m
            .outputs
            .iter()
            .find(|o| o.output_id == mapping.output_id)
            .ok_or("Unknown mapped output")?;
        let actual = policy
            .outputs
            .iter()
            .find(|o| o.action_index == mapping.action_index)
            .ok_or("Missing output policy action")?;
        check(
            actual.receiver == decode_testnet_receiver(&expected.address)?
                && actual.value_zatoshis == expected.amount.as_zatoshis(),
            "Output policy differs from accepted receiver or amount",
        )?;
        let memo = match (&expected.allocation, actual.purpose) {
            (OutputAllocation::Recipient { recipient_id }, OutputPurpose::Recipient) => {
                let recipient = m
                    .agreement
                    .recipients
                    .iter()
                    .find(|r| &r.recipient_id == recipient_id)
                    .ok_or("Accepted recipient is missing")?;
                match &recipient.memo {
                    Some(text) => MemoBytes::from_bytes(text.as_bytes())
                        .map_err(|_| "Invalid accepted memo")?,
                    None => MemoBytes::empty(),
                }
            }
            (
                OutputAllocation::Return {
                    participant_id,
                    account_id,
                    ..
                },
                OutputPurpose::Return { participant_index },
            ) => {
                let participant = m
                    .participants
                    .get(participant_index)
                    .ok_or("Invalid return participant")?;
                check(
                    &participant.participant_id == participant_id
                        && &participant.account_id == account_id,
                    "Return policy differs from accepted account",
                )?;
                MemoBytes::empty()
            }
            _ => return Err("Output purpose differs or is unqualified".into()),
        };
        check(
            actual.memo == memo.into_bytes(),
            "Output memo differs from accepted instructions",
        )?;
    }
    check(
        policy
            .outputs
            .iter()
            .map(|o| o.action_index)
            .collect::<BTreeSet<_>>()
            == output_actions,
        "Output policy contains duplicate or unmapped actions",
    )?;
    Ok(())
}
fn check(ok: bool, reason: &str) -> Result<(), String> {
    if ok { Ok(()) } else { Err(reason.into()) }
}
