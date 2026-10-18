//! Discharge the original V2 policy's inert own-return requirements against an
//! independently verified fixed PCZT and the actual local account's FVK. This
//! helper issues no permission and does not replace fresh wallet/key-use checks.
use crate::authority_bridge::{BridgeError, Result};
use orchard::keys::FullViewingKey;
use std::collections::BTreeSet;
use wholepact_core::born_recipient_policy_v2::OwnReturnRequirementV2;
use wholepact_protocol::{
    construction::{InputActionMapping, OutputActionMapping},
    durable_proposal_v1::{canonical_durable_account_id, VerifiedFixedProposal},
    review::{decode_testnet_receiver, OutputPurpose, ReviewPolicy},
};

pub(super) fn verify_stable_returns_v2(
    fixed: &VerifiedFixedProposal,
    input_actions: &[InputActionMapping],
    output_actions: &[OutputActionMapping],
    actual_fvk: &FullViewingKey,
    account_id: &str,
    requirements: &[OwnReturnRequirementV2],
) -> Result<()> {
    // This verifies complete manifest/policy attribution, not merely equality of
    // return amounts. The opaque fixed value already verified actual ciphertext,
    // proofs and all-account economics for these exact bytes and this policy.
    fixed
        .verify_action_mappings(input_actions, output_actions)
        .map_err(|_| BridgeError::Binding)?;
    verify_returns_against_policy(
        fixed.private_review_policy(),
        output_actions,
        actual_fvk,
        account_id,
        requirements,
    )
}

fn verify_returns_against_policy(
    policy: &ReviewPolicy,
    mappings: &[OutputActionMapping],
    actual_fvk: &FullViewingKey,
    account_id: &str,
    requirements: &[OwnReturnRequirementV2],
) -> Result<()> {
    if canonical_durable_account_id(actual_fvk) != account_id {
        return Err(BridgeError::Binding);
    }
    let mut owners = policy
        .participants
        .iter()
        .enumerate()
        .filter(|(_, owner)| owner.account_id == account_id);
    let (owner_index, owner) = owners.next().ok_or(BridgeError::Binding)?;
    if owners.next().is_some() || owner.fvk.to_bytes() != actual_fvk.to_bytes() {
        return Err(BridgeError::Binding);
    }
    let mut mapped_ids = BTreeSet::new();
    let mut mapped_actions = BTreeSet::new();
    if mappings.len() != policy.outputs.len()
        || mappings.iter().any(|m| {
            !mapped_ids.insert(m.output_id.as_str()) || !mapped_actions.insert(m.action_index)
        })
    {
        return Err(BridgeError::Binding);
    }
    let own_returns = policy
        .outputs
        .iter()
        .filter(|output| {
            matches!(output.purpose, OutputPurpose::Return { participant_index } if participant_index == owner_index)
        })
        .count();
    if own_returns != requirements.len() {
        return Err(BridgeError::Binding);
    }
    let mut seen = BTreeSet::new();
    for requirement in requirements {
        if !seen.insert(requirement.output_id.as_str()) {
            return Err(BridgeError::Binding);
        }
        let mapping = mappings
            .iter()
            .find(|m| m.output_id == requirement.output_id)
            .ok_or(BridgeError::Binding)?;
        let output = policy
            .outputs
            .iter()
            .find(|output| output.action_index == mapping.action_index)
            .ok_or(BridgeError::Binding)?;
        let receiver =
            decode_testnet_receiver(&requirement.address).map_err(|_| BridgeError::Binding)?;
        if !matches!(output.purpose, OutputPurpose::Return { participant_index } if participant_index == owner_index)
            || output.receiver != receiver
            || output.value_zatoshis != requirement.amount_zatoshis
            || actual_fvk.scope_for_address(&receiver).is_none()
        {
            return Err(BridgeError::Binding);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    // Pure attribution tests with never-funded keys and real address ownership.
    // They do not manufacture a VerifiedFixedProposal, native consent or spend.
    use super::*;
    use orchard::keys::{Scope, SpendingKey};
    use wholepact_protocol::review::{encode_testnet_receiver, OutputPolicy, ParticipantPolicy};

    fn fixture() -> (
        ReviewPolicy,
        Vec<OutputActionMapping>,
        FullViewingKey,
        Vec<OwnReturnRequirementV2>,
    ) {
        let own = FullViewingKey::from(&SpendingKey::from_bytes([7; 32]).unwrap());
        let other = FullViewingKey::from(&SpendingKey::from_bytes([9; 32]).unwrap());
        let receiver = own.address_at(0u32, Scope::Internal);
        let policy = ReviewPolicy {
            manifest_digest: [1; 32],
            participants: vec![own.clone(), other.clone()]
                .into_iter()
                .map(|fvk| ParticipantPolicy {
                    account_id: canonical_durable_account_id(&fvk),
                    fvk,
                    contribution_zatoshis: 50_000,
                    fee_share_zatoshis: 5_000,
                    maximum_net_debit_zatoshis: 55_000,
                })
                .collect(),
            inputs: vec![],
            outputs: vec![
                OutputPolicy {
                    action_index: 0,
                    receiver: other.address_at(0u32, Scope::External),
                    value_zatoshis: 100_000,
                    memo: [0; 512],
                    purpose: OutputPurpose::Recipient,
                },
                OutputPolicy {
                    action_index: 2,
                    receiver,
                    value_zatoshis: 5_000,
                    memo: [0; 512],
                    purpose: OutputPurpose::Return {
                        participant_index: 0,
                    },
                },
            ],
            exact_fee_zatoshis: 10_000,
            expiry_height: 3_000_000,
            anchor: [2; 32],
        };
        let mappings = vec![
            OutputActionMapping {
                output_id: "payment".into(),
                action_index: 0,
            },
            OutputActionMapping {
                output_id: "own-return".into(),
                action_index: 2,
            },
        ];
        let requirements = vec![OwnReturnRequirementV2 {
            output_id: "own-return".into(),
            address: encode_testnet_receiver(&receiver),
            amount_zatoshis: 5_000,
        }];
        (policy, mappings, own, requirements)
    }

    #[test]
    fn stable_return_requires_exact_mapping_amount_and_actual_own_address() {
        let (policy, mappings, own, requirements) = fixture();
        let id = canonical_durable_account_id(&own);
        verify_returns_against_policy(&policy, &mappings, &own, &id, &requirements).unwrap();
        let changes: &[fn(&mut OwnReturnRequirementV2)] = &[
            |r: &mut OwnReturnRequirementV2| r.output_id = "payment".into(),
            |r: &mut OwnReturnRequirementV2| r.output_id = "missing".into(),
            |r: &mut OwnReturnRequirementV2| r.amount_zatoshis += 1,
            |r: &mut OwnReturnRequirementV2| r.address = "not-an-address".into(),
        ];
        for alter in changes {
            let mut changed = requirements.clone();
            alter(&mut changed[0]);
            assert!(
                verify_returns_against_policy(&policy, &mappings, &own, &id, &changed).is_err()
            );
        }
        let mut changed = requirements.clone();
        changed[0].address = encode_testnet_receiver(&policy.outputs[0].receiver);
        assert!(verify_returns_against_policy(&policy, &mappings, &own, &id, &changed).is_err());
        assert!(verify_returns_against_policy(&policy, &mappings, &own, &id, &[]).is_err());
        assert!(
            verify_returns_against_policy(&policy, &mappings, &own, "alias", &requirements)
                .is_err()
        );
    }

    #[test]
    fn stable_return_rejects_relabelled_owner_fvk_and_duplicate_action() {
        let (mut policy, mut mappings, own, requirements) = fixture();
        let id = canonical_durable_account_id(&own);
        mappings[1].action_index = mappings[0].action_index;
        assert!(
            verify_returns_against_policy(&policy, &mappings, &own, &id, &requirements).is_err()
        );
        mappings[1].action_index = 2;
        policy.outputs[1].purpose = OutputPurpose::Return {
            participant_index: 1,
        };
        assert!(
            verify_returns_against_policy(&policy, &mappings, &own, &id, &requirements).is_err()
        );
        policy.outputs[1].purpose = OutputPurpose::Return {
            participant_index: 0,
        };
        policy.participants[0].fvk = policy.participants[1].fvk.clone();
        assert!(
            verify_returns_against_policy(&policy, &mappings, &own, &id, &requirements).is_err()
        );
    }

    #[test]
    fn stable_return_ownership_is_not_established_by_matching_labels() {
        let (mut policy, mappings, own, mut requirements) = fixture();
        let id = canonical_durable_account_id(&own);
        // Coordinated labels do not make a foreign receiver this account's own.
        policy.outputs[1].receiver = policy.outputs[0].receiver;
        requirements[0].address = encode_testnet_receiver(&policy.outputs[1].receiver);
        assert!(
            verify_returns_against_policy(&policy, &mappings, &own, &id, &requirements).is_err()
        );
        policy.outputs.pop();
        verify_returns_against_policy(&policy, &mappings[..1], &own, &id, &[]).unwrap();
    }
}
