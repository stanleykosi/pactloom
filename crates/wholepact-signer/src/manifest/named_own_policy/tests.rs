//! Pure source qualification. No wallet database, chain service, PCZT proof,
//! native consent, credential issuance or signature is created by these tests.
//! Accounts use OS-random ephemeral BIP39 entropy and are never persisted or funded.

use super::*;
use crate::manifest::{SelectedInput, SelectionContext};
use bip39::{Language, Mnemonic};
use orchard::keys::Scope;
use wholepact_core::{ChargeConsent, ClaimedOutput, Extension, Proposal, ProposalInput};
use wholepact_protocol::review::encode_testnet_receiver;
use zcash_protocol::consensus::{NetworkUpgrade, Parameters};

struct Fixture {
    accepted: AcceptedManifest,
    selected: LocalSelection,
    account: DedicatedAccount,
    context: ConstructionContext,
    inputs: Vec<InputActionMapping>,
    outputs: Vec<OutputActionMapping>,
}

fn amount(value: u64) -> Amount {
    Amount::from_zatoshis(value).unwrap()
}

fn synthetic_account(index: u32) -> DedicatedAccount {
    let mut entropy = zeroize::Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *entropy).unwrap();
    let words = zeroize::Zeroizing::new(
        Mnemonic::from_entropy_in(Language::English, &*entropy)
            .unwrap()
            .to_string(),
    );
    DedicatedAccount::recover(&words, index, "public-synthetic-own-policy".into()).unwrap()
}

impl Fixture {
    fn new() -> Self {
        // Reuse the inherited immutable-economics fixture. Replace only its
        // placeholder receivers/profile and split its own input to test order.
        let mut input: ProposalInput =
            serde_json::from_str(include_str!("../../native_ui/synthetic-proposal.json")).unwrap();
        let account = synthetic_account(0);
        let account_id = account.account_id().unwrap();
        let own_fvk = account.fvk().unwrap();
        let peer = synthetic_account(1).fvk().unwrap();
        let recipient = synthetic_account(2).fvk().unwrap();
        let recipient_address =
            encode_testnet_receiver(&recipient.address_at(0u32, Scope::External));
        let manifest = &mut input.manifest;
        manifest.agreement.network_profile_id = PROFILE_ID.into();
        manifest.agreement.privacy_profile.mode = PrivacyMode::DeclaredOperator;
        manifest.agreement.privacy_profile.proving_operator =
            Some("synthetic-named-verifier".into());
        manifest.agreement.recipients[0].address = recipient_address.clone();
        manifest.agreement.recipients[0].memo = Some("Exact synthetic recipient memo".into());
        manifest.outputs[0].address = recipient_address;
        manifest.outputs[1].address =
            encode_testnet_receiver(&own_fvk.address_at(0u32, Scope::Internal));
        manifest.outputs[2].address =
            encode_testnet_receiver(&peer.address_at(0u32, Scope::Internal));
        manifest.participants[0].account_id = account_id.clone();
        manifest.inputs[0].account_id = account_id.clone();
        manifest.inputs[0].input_id = "input-alice-first".into();
        manifest.inputs[0].amount = amount(300_000_000);
        let mut second = manifest.inputs[0].clone();
        second.input_id = "input-alice-second".into();
        second.amount = amount(200_000_000);
        manifest.inputs.push(second);
        match &mut manifest.outputs[1].allocation {
            OutputAllocation::Return { account_id: id, .. } => *id = account_id.clone(),
            _ => unreachable!(),
        }
        let target_height = u32::from(
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu7)
                .unwrap(),
        ) + 100;
        manifest.expiry_height = target_height + 40;
        let context = ConstructionContext {
            anchor: Anchor::empty_tree().to_bytes(),
            anchor_height: target_height - 2,
            anchor_block_hash: [0x21; 32],
            target_height,
        };
        let inputs = manifest
            .inputs
            .iter()
            .zip([4, 0, 2])
            .map(|(input, action_index)| InputActionMapping {
                input_id: input.input_id.clone(),
                account_id: input.account_id.clone(),
                action_index,
            })
            .rev()
            .collect();
        let outputs = manifest
            .outputs
            .iter()
            .zip([2, 4, 1])
            .map(|(output, action_index)| OutputActionMapping {
                output_id: output.output_id.clone(),
                action_index,
            })
            .rev()
            .collect();
        Self {
            accepted: AcceptedManifest {
                proposal: Proposal::validate(input).unwrap(),
            },
            selected: LocalSelection {
                account_id,
                fvk: own_fvk,
                key_use_policy: None,
                context: SelectionContext {
                    tip_height: target_height - 1,
                    tip_hash: [0x22; 32],
                    anchor_height: context.anchor_height,
                    anchor_hash: context.anchor_block_hash,
                    anchor_root: context.anchor,
                },
                inputs: vec![
                    SelectedInput {
                        input_id: "input-alice-second".into(),
                        nullifier: [0x12; 32],
                        value: 200_000_000,
                    },
                    SelectedInput {
                        input_id: "input-alice-first".into(),
                        nullifier: [0x11; 32],
                        value: 300_000_000,
                    },
                ],
            },
            account,
            context,
            inputs,
            outputs,
        }
    }

    fn derive(&self) -> Result<OwnEffectsPolicy> {
        derive_selected_own_policy(
            &self.accepted,
            &self.selected,
            &self.account,
            &self.context,
            &self.inputs,
            &self.outputs,
        )
    }

    fn revise(&mut self, change: impl FnOnce(&mut wholepact_core::ProposalManifest)) {
        let mut proposal = self.accepted.proposal.input().clone();
        change(&mut proposal.manifest);
        self.accepted = AcceptedManifest {
            proposal: Proposal::validate(proposal).unwrap(),
        };
    }
}

fn purpose(value: OwnOutputPurpose) -> u8 {
    match value {
        OwnOutputPurpose::Recipient => 0,
        OwnOutputPurpose::OwnReturn => 1,
        OwnOutputPurpose::PeerReturnUnverified => 2,
    }
}

fn same_policy(a: &OwnEffectsPolicy, b: &OwnEffectsPolicy) {
    assert!(a.account_id == b.account_id && a.own_fvk.to_bytes() == b.own_fvk.to_bytes());
    assert_eq!(a.manifest_digest, b.manifest_digest);
    assert_eq!(a.anchor, b.anchor);
    assert_eq!(a.expiry_height, b.expiry_height);
    assert_eq!(
        a.maximum_selected_net_debit_zatoshis,
        b.maximum_selected_net_debit_zatoshis
    );
    assert_eq!(
        a.exact_selected_net_debit_zatoshis,
        b.exact_selected_net_debit_zatoshis
    );
    assert_eq!(a.declared_fee_share_zatoshis, b.declared_fee_share_zatoshis);
    assert_eq!(
        a.exact_transaction_fee_zatoshis,
        b.exact_transaction_fee_zatoshis
    );
    assert_eq!(a.own_inputs.len(), b.own_inputs.len());
    for (a, b) in a.own_inputs.iter().zip(&b.own_inputs) {
        assert_eq!(a.action_index, b.action_index);
        assert!(a.nullifier == b.nullifier);
        assert_eq!(a.value_zatoshis, b.value_zatoshis);
    }
    assert_eq!(a.outputs.len(), b.outputs.len());
    for (a, b) in a.outputs.iter().zip(&b.outputs) {
        assert_eq!(a.action_index, b.action_index);
        assert!(a.receiver == b.receiver && a.memo == b.memo);
        assert_eq!(a.value_zatoshis, b.value_zatoshis);
        assert_eq!(purpose(a.purpose), purpose(b.purpose));
    }
}

#[test]
fn accepted_order_and_economics_survive_mapping_and_selection_reordering() {
    let mut f = Fixture::new();
    let policy = f.derive().unwrap();
    assert_eq!(policy.account_id, f.account.account_id().unwrap());
    assert!(policy.own_fvk.to_bytes() == f.account.fvk().unwrap().to_bytes());
    assert_eq!(hex::encode(policy.manifest_digest), f.accepted.digest());
    assert_eq!(policy.exact_selected_net_debit_zatoshis, 400_012_000);
    assert_eq!(policy.maximum_selected_net_debit_zatoshis, 400_012_000);
    assert_eq!(policy.declared_fee_share_zatoshis, 12_000);
    assert_eq!(policy.exact_transaction_fee_zatoshis, 30_000);
    assert_eq!(policy.anchor, f.context.anchor);
    assert_eq!(
        policy.expiry_height,
        f.accepted.proposal.manifest().expiry_height
    );
    assert_eq!(
        policy
            .own_inputs
            .iter()
            .map(|i| i.action_index)
            .collect::<Vec<_>>(),
        vec![4, 2]
    );
    assert!(policy.own_inputs[0].nullifier == [0x11; 32]);
    assert!(policy.own_inputs[1].nullifier == [0x12; 32]);
    assert_eq!(policy.own_inputs[0].value_zatoshis, 300_000_000);
    assert_eq!(policy.own_inputs[1].value_zatoshis, 200_000_000);
    assert_eq!(
        policy
            .outputs
            .iter()
            .map(|o| o.action_index)
            .collect::<Vec<_>>(),
        vec![2, 4, 1]
    );
    assert_eq!(
        policy
            .outputs
            .iter()
            .map(|o| purpose(o.purpose))
            .collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    for (output, accepted) in policy
        .outputs
        .iter()
        .zip(&f.accepted.proposal.manifest().outputs)
    {
        assert!(output.receiver == decode_testnet_receiver(&accepted.address).unwrap());
        assert_eq!(output.value_zatoshis, accepted.amount.as_zatoshis());
    }
    assert!(
        policy.outputs[0].memo
            == MemoBytes::from_bytes(b"Exact synthetic recipient memo")
                .unwrap()
                .into_bytes()
    );
    assert!(policy.outputs[1].memo == MemoBytes::empty().into_bytes());
    assert!(policy.outputs[2].memo == MemoBytes::empty().into_bytes());
    f.inputs.reverse();
    f.outputs.reverse();
    f.selected.inputs.reverse();
    same_policy(&policy, &f.derive().unwrap());
}

#[test]
fn rejects_local_account_key_or_exact_selected_input_coverage_substitution() {
    let mutations: &[fn(&mut Fixture)] = &[
        |f| f.account = synthetic_account(3),
        |f| f.selected.account_id = "borrowed-account-label".into(),
        |f| f.selected.fvk = synthetic_account(3).fvk().unwrap(),
        |f| {
            f.selected.inputs.pop();
        },
        |f| f.selected.inputs.clear(),
        |f| f.selected.inputs[0].input_id = "input-bob".into(),
        |f| f.selected.inputs[0].value += 1,
        |f| f.selected.inputs[0].value = 0,
        |f| f.selected.inputs[0].value = u64::MAX,
        |f| f.selected.inputs[0].input_id = f.selected.inputs[1].input_id.clone(),
        |f| f.selected.inputs[0].nullifier = f.selected.inputs[1].nullifier,
        |f| {
            f.selected.inputs.push(SelectedInput {
                input_id: "omitted-own-note".into(),
                nullifier: [0x13; 32],
                value: 1,
            })
        },
        |f| {
            for i in 0..64 {
                f.selected.inputs.push(SelectedInput {
                    input_id: format!("extra-{i}"),
                    nullifier: [i; 32],
                    value: 1,
                });
            }
        },
    ];
    for (case, mutate) in mutations.iter().enumerate() {
        let mut f = Fixture::new();
        mutate(&mut f);
        assert!(f.derive().is_err(), "selected-account case {case}");
    }
}

#[test]
fn rejects_missing_extra_unknown_duplicate_or_misattributed_action_mappings() {
    let mutations: &[fn(&mut Fixture)] = &[
        |f| {
            f.inputs.pop();
        },
        |f| f.inputs.push(f.inputs[0].clone()),
        |f| f.inputs[0].input_id = "unknown-input".into(),
        |f| f.inputs[0].input_id = f.inputs[1].input_id.clone(),
        |f| f.inputs[0].action_index = f.inputs[1].action_index,
        |f| f.inputs[0].account_id = "account-bob".into(),
        |f| f.inputs[1].account_id = f.selected.account_id.clone(),
        |f| f.inputs[0].action_index = 64,
        |f| {
            f.outputs.pop();
        },
        |f| f.outputs.push(f.outputs[0].clone()),
        |f| f.outputs[0].output_id = "unknown-output".into(),
        |f| f.outputs[0].output_id = f.outputs[1].output_id.clone(),
        |f| f.outputs[0].action_index = f.outputs[1].action_index,
        |f| f.outputs[0].action_index = usize::MAX,
    ];
    for (case, mutate) in mutations.iter().enumerate() {
        let mut f = Fixture::new();
        mutate(&mut f);
        assert!(f.derive().is_err(), "mapping case {case}");
    }
}

#[test]
fn rejects_context_drift_invalid_anchor_expiry_and_pre_activation_height() {
    let mutations: &[fn(&mut Fixture)] = &[
        |f| f.context.anchor[0] ^= 1,
        |f| f.context.anchor_height += 1,
        |f| f.context.anchor_block_hash[0] ^= 1,
        |f| f.context.target_height += 1,
        |f| f.selected.context.tip_height = u32::MAX,
        |f| f.selected.context.tip_hash = [0; 32],
        |f| {
            f.context.anchor_block_hash = [0; 32];
            f.selected.context.anchor_hash = [0; 32];
        },
        |f| {
            f.context.anchor = [0xff; 32];
            f.selected.context.anchor_root = [0xff; 32];
        },
        |f| {
            f.selected.context.anchor_height = f.context.target_height;
            f.context.anchor_height = f.context.target_height;
        },
        |f| {
            f.context.anchor_height = f.selected.context.tip_height;
            f.selected.context.anchor_height = f.selected.context.tip_height;
        },
        |f| f.revise(|m| m.expiry_height = 500_000_000),
        |f| {
            let expired = f.context.target_height - 1;
            f.revise(|m| m.expiry_height = expired);
        },
        |f| {
            f.context.target_height = 100;
            f.context.anchor_height = 98;
            f.selected.context.tip_height = 99;
            f.selected.context.anchor_height = 98;
        },
    ];
    for (case, mutate) in mutations.iter().enumerate() {
        let mut f = Fixture::new();
        mutate(&mut f);
        assert!(f.derive().is_err(), "context case {case}");
    }
    let mut same_height = Fixture::new();
    same_height.context.anchor_height = same_height.selected.context.tip_height;
    same_height.selected.context.anchor_height = same_height.selected.context.tip_height;
    same_height.selected.context.tip_hash = same_height.context.anchor_block_hash;
    assert!(same_height.derive().is_ok());
}

#[test]
fn accepted_return_labels_cannot_override_actual_account_receiver_ownership() {
    let mut wrong_return = Fixture::new();
    wrong_return.revise(|m| m.outputs[1].address = m.outputs[2].address.clone());
    assert!(wrong_return.derive().is_err());

    let mut disguised_peer_return = Fixture::new();
    disguised_peer_return.revise(|m| m.outputs[2].address = m.outputs[1].address.clone());
    assert!(disguised_peer_return.derive().is_err());

    let mut disguised_recipient = Fixture::new();
    disguised_recipient.revise(|m| {
        m.outputs[0].address = m.outputs[1].address.clone();
        m.agreement.recipients[0].address = m.outputs[1].address.clone();
    });
    assert!(disguised_recipient.derive().is_err());

    // Peer attribution remains deliberately unknown even for a syntactically
    // valid receiver that differs from any peer's known fixture key.
    let mut different_peer_receiver = Fixture::new();
    let unverified = encode_testnet_receiver(
        &synthetic_account(4)
            .fvk()
            .unwrap()
            .address_at(0u32, Scope::External),
    );
    different_peer_receiver.revise(|m| m.outputs[2].address = unverified);
    assert!(matches!(
        different_peer_receiver.derive().unwrap().outputs[2].purpose,
        OwnOutputPurpose::PeerReturnUnverified
    ));
}

#[test]
fn rejects_unqualified_network_optional_extension_privacy_and_explicit_charge() {
    let mut unsupported_network = Fixture::new();
    unsupported_network.revise(|m| m.agreement.network_profile_id = "zcash-mainnet".into());
    assert!(unsupported_network.derive().is_err());

    let mut unsupported_extension = Fixture::new();
    unsupported_extension.revise(|m| {
        m.agreement.extensions.push(Extension {
            name: "optional-unqualified-match".into(),
            required: false,
            schema_version: 1,
            value: serde_json::json!({"ratio": "1:1"}),
        })
    });
    assert!(unsupported_extension.derive().is_err());

    let mut unsupported_privacy = Fixture::new();
    unsupported_privacy.revise(|m| {
        m.agreement.privacy_profile.mode = PrivacyMode::LocalOnly;
        m.agreement.privacy_profile.proving_operator = None;
    });
    assert!(unsupported_privacy.derive().is_err());

    let mut charge = Fixture::new();
    charge.revise(|m| {
        let address = m.outputs[0].address.clone();
        m.participants[0].charges.push(ChargeConsent {
            charge_id: "explicit-synthetic-charge".into(),
            address: address.clone(),
            amount: amount(1),
            purpose: "Unsupported charge fixture".into(),
        });
        m.participants[0].maximum_net_debit = amount(400_012_001);
        m.outputs[1].amount = amount(99_987_999);
        m.outputs.push(ClaimedOutput {
            output_id: "charge-output".into(),
            address,
            amount: amount(1),
            allocation: OutputAllocation::Charge {
                participant_id: "alice".into(),
                charge_id: "explicit-synthetic-charge".into(),
            },
        });
    });
    charge.outputs.push(OutputActionMapping {
        output_id: "charge-output".into(),
        action_index: 3,
    });
    assert!(charge.derive().is_err());
}

#[test]
fn exact_recipient_identity_address_amount_and_memo_come_only_from_acceptance() {
    let mut f = Fixture::new();
    let original = f.derive().unwrap();
    f.revise(|m| {
        m.agreement.recipients[0].recipient_id = "accepted-new-recipient-id".into();
        m.agreement.recipients[0].memo = Some("Revised accepted memo".into());
        m.outputs[0].allocation = OutputAllocation::Recipient {
            recipient_id: "accepted-new-recipient-id".into(),
        };
    });
    let revised = f.derive().unwrap();
    assert_ne!(original.manifest_digest, revised.manifest_digest);
    assert!(
        revised.outputs[0].memo
            == MemoBytes::from_bytes(b"Revised accepted memo")
                .unwrap()
                .into_bytes()
    );

    // A consented cap is preserved separately from the exact checked debit.
    f.revise(|m| m.participants[0].maximum_net_debit = amount(450_000_000));
    let wider_cap = f.derive().unwrap();
    assert_eq!(wider_cap.maximum_selected_net_debit_zatoshis, 450_000_000);
    assert_eq!(wider_cap.exact_selected_net_debit_zatoshis, 400_012_000);

    // The genuine AcceptedManifest boundary rejects inconsistent recipient
    // identities/addresses/amounts before this adapter can receive them.
    for mutation in [
        (|m: &mut wholepact_core::ProposalManifest| {
            m.outputs[0].allocation = OutputAllocation::Recipient {
                recipient_id: "unapproved-id".into(),
            }
        }) as fn(&mut wholepact_core::ProposalManifest),
        |m| m.outputs[0].address = m.outputs[2].address.clone(),
        |m| m.outputs[0].amount = amount(999_999_999),
    ] {
        let mut input = f.accepted.proposal.input().clone();
        mutation(&mut input.manifest);
        assert!(Proposal::validate(input).is_err());
    }

    // Core text validation alone is not shielded/network receiver decoding.
    f.revise(|m| {
        let invalid = "uregtestsyntheticaddressnotforfunds".to_owned();
        m.agreement.recipients[0].address = invalid.clone();
        m.outputs[0].address = invalid;
    });
    assert!(f.derive().is_err());
}
