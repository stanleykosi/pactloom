//! Maintained encrypted-wallet/loopback component tests only. No native owner,
//! durable disclosure, construction admission or signing permission is faked.
use super::super::durable_construction_v1::{
    ConstructionRecipientV1, ConstructionReviewerV1, HistoricalConstructionMaterialV1, PURPOSE,
};
use super::*;
use crate::wallet::sync_test_support::*;
use wholepact_core::*;
use wholepact_protocol::review::encode_testnet_receiver;
use zcash_client_backend::data_api::locking::{LockOwner, OutputLockStore};
use zcash_client_backend::wallet::OutputRef;

fn amount(v: u64) -> Amount {
    Amount::from_zatoshis(v).unwrap()
}

fn scope(owners: &[ProtectedContribution]) -> DurableConstructionScopeV1 {
    let first = owners[0].selection();
    let receiver = encode_testnet_receiver(&first.notes()[0].note.recipient());
    let agreement = AgreementDraft {
        schema_version: 1,
        agreement_id: "exact-data-component".into(),
        obligation_id: "never-funded".into(),
        revision: 1,
        purpose: "Exact maintained row recapture component, no native authority".into(),
        organizer_identity: "component".into(),
        network_profile_id: wholepact_protocol::construction::PROFILE_ID.into(),
        recipients: vec![Recipient {
            recipient_id: "recipient".into(),
            address: receiver.clone(),
            amount: amount(300_000),
            memo: None,
            instruction_provenance: "component".into(),
        }],
        funding_policy: FundingPolicy::Exact {
            target: amount(300_000),
        },
        fee_policy: FeePolicy::ProRata,
        privacy_profile: PrivacyProfile {
            mode: PrivacyMode::DeclaredOperator,
            proving_operator: Some("component".into()),
            dedicated_accounts_required: true,
        },
        coordination_deadline: None,
        confirmation_policy: ConfirmationPolicy::default(),
        extensions: vec![],
    };
    let mut participants = Vec::new();
    let mut inputs = Vec::new();
    let mut outputs = vec![ClaimedOutput {
        output_id: "recipient".into(),
        address: receiver,
        amount: amount(300_000),
        allocation: OutputAllocation::Recipient {
            recipient_id: "recipient".into(),
        },
    }];
    for (i, owner) in owners.iter().enumerate() {
        let selected = owner.selection();
        let participant_id = format!("participant-{i}");
        participants.push(ParticipantAllocation {
            participant_id: participant_id.clone(),
            account_id: selected.account_id().into(),
            contribution: amount(if i == 0 { 100_000 } else { 200_000 }),
            fee_share: amount(if i == 0 { 5_000 } else { 10_000 }),
            fee_cap: amount(if i == 0 { 5_000 } else { 10_000 }),
            maximum_net_debit: amount(selected.requested_debit_zatoshis()),
            charges: vec![],
        });
        for n in selected.notes() {
            inputs.push(ClaimedInput {
                input_id: n.input_id.clone(),
                participant_id: participant_id.clone(),
                account_id: selected.account_id().into(),
                amount: amount(n.note.value().inner()),
                ownership_evidence_ref: None,
            });
        }
        outputs.push(ClaimedOutput {
            output_id: format!("return-{i}"),
            address: encode_testnet_receiver(&selected.change_address()),
            amount: amount(selected.selected_zatoshis() - selected.requested_debit_zatoshis()),
            allocation: OutputAllocation::Return {
                participant_id,
                account_id: selected.account_id().into(),
                ownership_evidence_ref: None,
            },
        });
    }
    let clock = now().unwrap();
    DurableConstructionScopeV1 {
        version: 2,
        purpose: PURPOSE.into(),
        proposal: ProposalInput {
            proposal_id: "exact-candidate".into(),
            previous_proposal_id: None,
            manifest: ProposalManifest {
                agreement,
                participants,
                inputs,
                outputs,
                transaction_fee: amount(15_000),
                expiry_height: first.context().tip_height + 30,
            },
            artifact_digest: None,
            effects_commitment: None,
            created_at: "2026-10-18T00:00:00Z".into(),
        },
        account_id: first.account_id().into(),
        participant_id: "participant-0".into(),
        privacy_domain: "component".into(),
        constructor: ConstructionRecipientV1 {
            principal_id: "component".into(),
            authenticated_local_grant_digest: "11".repeat(32),
        },
        prover: ConstructionRecipientV1 {
            principal_id: "component".into(),
            authenticated_local_grant_digest: "11".repeat(32),
        },
        reviewers: owners
            .iter()
            .map(|o| {
                ConstructionReviewerV1::local_installed_signer(o.selection().account_id().into())
            })
            .collect(),
        protected_destination: "/component/private/intake.sqlite".into(),
        retention_policy: "component only".into(),
        valid_from_unix_seconds: clock - 1,
        valid_until_unix_seconds: clock + 600,
        minimum_confirmations: 1,
        maximum_scan_blocks: 100,
    }
}

fn expectation(
    wallet: &ProtectedWalletSync,
    selected: &ProtectedContribution,
) -> DurableExactSelectionExpectationV1 {
    let mut inputs = selected
        .selection()
        .notes()
        .iter()
        .map(|n| DurableExactInputV1 {
            input_id: n.input_id.clone(),
            value_zatoshis: n.note.value().inner(),
            commitment: Some(
                orchard::note::ExtractedNoteCommitment::from(n.note.commitment()).to_bytes(),
            ),
        })
        .collect::<Vec<_>>();
    inputs.sort_by(|a, b| a.input_id.cmp(&b.input_id));
    DurableExactSelectionExpectationV1 {
        provider: wallet.source.identity().clone(),
        original_context: selected.selection().context().clone(),
        construction_anchor: DurableExactConstructionAnchorV1 {
            height: selected.selection().context().anchor_height,
            block_hash_protocol: selected.selection().context().anchor_hash_protocol,
            root: selected.selection().context().anchor_root,
        },
        inputs,
    }
}

#[test]
fn exact_outpoints_refuse_aliases_noncanonical_indices_and_values() {
    let txid = TxId::from_bytes([19; 32]);
    let good = DurableExactInputV1 {
        input_id: format!("ironwood:{txid}:7"),
        value_zatoshis: 1,
        commitment: None,
    };
    assert_eq!(good.outpoint().unwrap(), (txid, 7));
    for id in [
        format!("ironwood:{txid}:07"),
        format!("ironwood:{txid}:+7"),
        format!("ironwood:{txid}:65536"),
        format!("orchard:{txid}:7"),
        "wallet-row-7".into(),
        format!("ironwood:{}:7", "AB".repeat(32)),
    ] {
        let mut wrong = good.clone();
        wrong.input_id = id;
        assert!(wrong.outpoint().is_err());
    }
    for value in [0, crate::wallet::MAX_MONEY + 1] {
        let mut wrong = good.clone();
        wrong.value_zatoshis = value;
        assert!(wrong.outpoint().is_err());
    }
}

#[tokio::test]
async fn exact_recap_uses_actual_rows_and_rejects_substitution_staleness_and_locks() {
    let (fake, endpoint, server, first_fvk) = fake_server(1).await;
    let second_fvk = fake.owner_fvks[1].clone();
    let (_a, path_a, key_a) = database(&first_fvk);
    let (_b, path_b, key_b) = database(&second_fvk);
    let mut a = controller(&path_a, &key_a, &endpoint);
    let mut b = controller(&path_b, &key_b, &endpoint);
    a.synchronize(&FixtureAccess(true), SyncLimits::default())
        .await
        .unwrap();
    b.synchronize(&FixtureAccess(true), SyncLimits::default())
        .await
        .unwrap();
    // Generic selection is confined to generating the initial component
    // projection. The new exact recapture API never invokes that selector.
    let owners = vec![
        a.select_contribution(
            &FixtureAccess(true),
            &first_fvk,
            &canonical_durable_account_id(&first_fvk),
            105_000,
            &[],
        )
        .unwrap(),
        b.select_contribution(
            &FixtureAccess(true),
            &second_fvk,
            &canonical_durable_account_id(&second_fvk),
            210_000,
            &[],
        )
        .unwrap(),
    ];
    let scope = scope(&owners);
    let expected = expectation(&a, &owners[0]);
    let selected = a
        .select_exact_durable_contribution_v1(&FixtureAccess(true), &first_fvk, &scope, &expected)
        .unwrap();
    // This real scanner fixture uses HTTP loopback. Exact maintained recapture
    // succeeds, but it must NOT become a TLS-qualified durable material export.
    assert!(HistoricalConstructionMaterialV1::capture(&selected, &a).is_err());
    assert_eq!(
        selected
            .selection()
            .notes()
            .iter()
            .map(|n| n.input_id.as_str())
            .collect::<Vec<_>>(),
        expected
            .inputs
            .iter()
            .map(|n| n.input_id.as_str())
            .collect::<Vec<_>>()
    );
    assert!(selected.selection().context() == &expected.original_context);
    for (note, exact) in selected.selection().notes().iter().zip(&expected.inputs) {
        assert_eq!(note.note.value().inner(), exact.value_zatoshis);
        assert_eq!(
            Some(orchard::note::ExtractedNoteCommitment::from(note.note.commitment()).to_bytes()),
            exact.commitment
        );
        assert_eq!(
            note.witness.root(note.note.commitment().into()).to_bytes(),
            expected.construction_anchor.root
        );
    }
    let mut no_commitment = expected.clone();
    for n in &mut no_commitment.inputs {
        n.commitment = None;
    }
    assert!(
        a.select_exact_durable_contribution_v1(
            &FixtureAccess(true),
            &first_fvk,
            &scope,
            &no_commitment
        )
        .is_ok()
    );
    assert!(
        a.select_exact_durable_contribution_v1(
            &FixtureAccess(false),
            &first_fvk,
            &scope,
            &expected
        )
        .is_err()
    );
    assert!(
        a.select_exact_durable_contribution_v1(
            &FixtureAccess(true),
            &second_fvk,
            &scope,
            &expected
        )
        .is_err()
    );
    for kind in 0..7 {
        let mut bad = expected.clone();
        match kind {
            0 => bad.inputs[0].value_zatoshis += 1,
            1 => bad.inputs[0].commitment = Some([0; 32]),
            2 => bad.inputs.push(bad.inputs[0].clone()),
            3 => bad.provider.endpoint.push_str("/different"),
            4 => bad.original_context.anchor_root[0] ^= 1,
            5 => bad.original_context.anchor_hash_protocol[0] ^= 1,
            _ => bad.original_context.tip_hash_protocol[0] ^= 1,
        }
        assert!(
            a.select_exact_durable_contribution_v1(&FixtureAccess(true), &first_fvk, &scope, &bad)
                .is_err()
        );
    }
    // Coordinated DTO/manifest relabeling cannot turn a nonexistent exact
    // outpoint into an equal-value replacement or a fresh native approval.
    let mut wrong_scope = scope.clone();
    let mut wrong_inputs = expected.clone();
    let old = wrong_inputs.inputs[0].input_id.clone();
    wrong_inputs.inputs[0].input_id = format!("ironwood:{}:65535", TxId::from_bytes([88; 32]));
    for i in &mut wrong_scope.proposal.manifest.inputs {
        if i.input_id == old {
            i.input_id = wrong_inputs.inputs[0].input_id.clone();
        }
    }
    wrong_inputs
        .inputs
        .sort_by(|a, b| a.input_id.cmp(&b.input_id));
    assert!(wrong_scope.validate().is_ok());
    assert!(
        a.select_exact_durable_contribution_v1(
            &FixtureAccess(true),
            &first_fvk,
            &wrong_scope,
            &wrong_inputs
        )
        .is_err()
    );
    // A changed own return still balances the contract but is not the actual
    // dedicated internal return. Private capture must refuse it.
    let mut wrong_return = scope.clone();
    let other_address = encode_testnet_receiver(&second_fvk.address_at(0u32, Scope::Internal));
    for o in &mut wrong_return.proposal.manifest.outputs {
        if matches!(&o.allocation, OutputAllocation::Return{account_id,..} if account_id == &scope.account_id)
        {
            o.address = other_address.clone();
        }
    }
    assert!(
        a.select_exact_durable_contribution_v1(
            &FixtureAccess(true),
            &first_fvk,
            &wrong_return,
            &expected
        )
        .is_err()
    );
    let (txid, index) = expected.inputs[0].outpoint().unwrap();
    let output = OutputRef::new(
        txid,
        zcash_protocol::PoolType::Shielded(ShieldedPool::Ironwood),
        u32::from(index),
    );
    let owner = LockOwner::new([41; 32]);
    a.wallet
        .db
        .lock_outputs(
            std::slice::from_ref(&output),
            owner,
            (expected.original_context.tip_height + 20).into(),
        )
        .unwrap();
    assert!(
        a.select_exact_durable_contribution_v1(&FixtureAccess(true), &first_fvk, &scope, &expected)
            .is_err()
    );
    a.wallet.db.unlock_output(&output, owner).unwrap();
    assert!(
        a.select_exact_durable_contribution_v1(&FixtureAccess(true), &first_fvk, &scope, &expected)
            .is_ok()
    );
    a.invalidate_observation();
    assert!(
        a.select_exact_durable_contribution_v1(&FixtureAccess(true), &first_fvk, &scope, &expected)
            .is_err()
    );
    server.abort();
}

#[tokio::test]
async fn explicit_new_preproof_anchor_keeps_historical_context_and_exact_inputs() {
    let (fake, endpoint, server, first_fvk) = fake_server(2).await;
    let second_fvk = fake.owner_fvks[1].clone();
    let (_a, path_a, key_a) = database(&first_fvk);
    let (_b, path_b, key_b) = database(&second_fvk);
    let mut a = controller(&path_a, &key_a, &endpoint);
    let mut b = controller(&path_b, &key_b, &endpoint);
    let old_height = u32::try_from(fake.blocks[0].height).unwrap();
    for wallet in [&mut a, &mut b] {
        wallet
            .synchronize(
                &FixtureAccess(true),
                SyncLimits {
                    anchor_height: Some(old_height),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
    }
    let owners = vec![
        a.select_contribution(
            &FixtureAccess(true),
            &first_fvk,
            &canonical_durable_account_id(&first_fvk),
            105_000,
            &[],
        )
        .unwrap(),
        b.select_contribution(
            &FixtureAccess(true),
            &second_fvk,
            &canonical_durable_account_id(&second_fvk),
            210_000,
            &[],
        )
        .unwrap(),
    ];
    let scope = scope(&owners);
    let historical = expectation(&a, &owners[0]);
    let mut expected = historical.clone();
    // A provider tip advancing does not imply the maintained default anchor
    // advances. This test exercises an explicitly agreed NEW pre-proof anchor.
    let new_height = u32::try_from(fake.blocks[1].height).unwrap();
    assert!(new_height > old_height);
    a.synchronize(
        &FixtureAccess(true),
        SyncLimits {
            anchor_height: Some(new_height),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let current = &a.accepted.as_ref().unwrap().selection;
    assert_eq!(current.anchor_height, new_height);
    expected.construction_anchor = DurableExactConstructionAnchorV1 {
        height: current.anchor_height,
        block_hash_protocol: current.anchor_hash_protocol,
        root: current.anchor_root,
    };
    // No silent anchor replacement: retaining the old construction expectation
    // refuses against this newly observed anchor, even though the inputs remain.
    assert!(
        a.select_exact_durable_contribution_v1(
            &FixtureAccess(true),
            &first_fvk,
            &scope,
            &historical
        )
        .is_err()
    );
    let selected = a
        .select_exact_durable_contribution_v1(&FixtureAccess(true), &first_fvk, &scope, &expected)
        .unwrap();
    assert!(expected.original_context == historical.original_context);
    assert!(expected.inputs == historical.inputs);
    assert_eq!(
        selected.selection().context().anchor_height,
        expected.construction_anchor.height
    );
    assert_eq!(
        selected
            .selection()
            .notes()
            .iter()
            .map(|n| n.input_id.as_str())
            .collect::<Vec<_>>(),
        expected
            .inputs
            .iter()
            .map(|n| n.input_id.as_str())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        selected.selection().context().anchor_hash_protocol,
        expected.construction_anchor.block_hash_protocol
    );
    assert_eq!(
        selected.selection().context().anchor_root,
        expected.construction_anchor.root
    );
    for (note, exact) in selected.selection().notes().iter().zip(&expected.inputs) {
        assert_eq!(note.note.value().inner(), exact.value_zatoshis);
        assert_eq!(
            Some(orchard::note::ExtractedNoteCommitment::from(note.note.commitment()).to_bytes()),
            exact.commitment
        );
        assert_eq!(
            note.witness.root(note.note.commitment().into()).to_bytes(),
            expected.construction_anchor.root
        );
    }
    // Preserve the separate production HTTPS boundary; no endpoint rewriting
    // or test-only material-authority constructor is used here.
    assert!(HistoricalConstructionMaterialV1::capture(&selected, &a).is_err());
    for kind in 0..5 {
        let mut bad = expected.clone();
        match kind {
            0 => bad.original_context.tip_hash_protocol[0] ^= 1,
            1 => bad.original_context.anchor_hash_protocol[0] ^= 1,
            2 => bad.construction_anchor.root[0] ^= 1,
            3 => bad.construction_anchor.block_hash_protocol[0] ^= 1,
            _ => bad.construction_anchor.height = old_height - 1,
        }
        assert!(
            a.select_exact_durable_contribution_v1(&FixtureAccess(true), &first_fvk, &scope, &bad)
                .is_err()
        );
    }
    server.abort();
}
