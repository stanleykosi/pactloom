#![cfg(all(feature = "protected-sync", feature = "synthetic-qualification"))]
//! Two encrypted dedicated synthetic wallets -> exact protected selections -> encrypted
//! engine candidate. No real account, proof, signing, disclosure or settlement occurs.
use wholepact_core::*;
use wholepact_engine::{Access, CandidateRequest, Engine, candidates::ScannedWalletConstruction};
use wholepact_protocol::{construction::*, review::encode_testnet_receiver};
use wholepact_store::Store;
use wholepact_wallet::wallet::protected_sync::*;
mod support;
use support::*;

fn amount(n: u64) -> Amount {
    Amount::from_zatoshis(n).unwrap()
}
fn candidate(wallets: &[ProtectedContribution]) -> CandidateRequest {
    let selected: Vec<_> = wallets.iter().map(|w| w.selection()).collect();
    let receiver = encode_testnet_receiver(&selected[0].notes()[0].note.recipient());
    let agreement = AgreementDraft {
        schema_version: 1,
        agreement_id: "protected-wallet-synthetic".into(),
        obligation_id: "never-funded".into(),
        revision: 1,
        purpose: "Two synthetic encrypted wallet snapshots, no network settlement".into(),
        organizer_identity: "synthetic".into(),
        network_profile_id: PROFILE_ID.into(),
        recipients: vec![Recipient {
            recipient_id: "recipient".into(),
            address: receiver.clone(),
            amount: amount(300_000),
            memo: None,
            instruction_provenance: "Synthetic never-funded receiver".into(),
        }],
        funding_policy: FundingPolicy::Exact {
            target: amount(300_000),
        },
        fee_policy: FeePolicy::ProRata,
        privacy_profile: PrivacyProfile {
            mode: PrivacyMode::DeclaredOperator,
            proving_operator: Some("synthetic-local".into()),
            dedicated_accounts_required: true,
        },
        coordination_deadline: None,
        confirmation_policy: ConfirmationPolicy::default(),
        extensions: vec![],
    };
    let mut participants = vec![];
    let mut inputs = vec![];
    let mut outputs = vec![ClaimedOutput {
        output_id: "recipient-output".into(),
        address: receiver,
        amount: amount(300_000),
        allocation: OutputAllocation::Recipient {
            recipient_id: "recipient".into(),
        },
    }];
    for (i, w) in selected.iter().enumerate() {
        let participant_id = format!("participant-{i}");
        participants.push(ParticipantAllocation {
            participant_id: participant_id.clone(),
            account_id: w.account_id().into(),
            contribution: amount(if i == 0 { 100_000 } else { 200_000 }),
            fee_share: amount(if i == 0 { 5_000 } else { 10_000 }),
            fee_cap: amount(if i == 0 { 5_000 } else { 10_000 }),
            maximum_net_debit: amount(w.requested_debit_zatoshis()),
            charges: vec![],
        });
        for n in w.notes() {
            inputs.push(ClaimedInput {
                input_id: n.input_id.clone(),
                participant_id: participant_id.clone(),
                account_id: w.account_id().into(),
                amount: amount(n.note.value().inner()),
                ownership_evidence_ref: None,
            });
        }
        outputs.push(ClaimedOutput {
            output_id: format!("change-{i}"),
            address: encode_testnet_receiver(&w.change_address()),
            amount: amount(w.selected_zatoshis() - w.requested_debit_zatoshis()),
            allocation: OutputAllocation::Return {
                participant_id,
                account_id: w.account_id().into(),
                ownership_evidence_ref: None,
            },
        });
    }
    CandidateRequest {
        manifest: ProposalManifest {
            agreement,
            participants,
            inputs,
            outputs,
            transaction_fee: amount(15_000),
            expiry_height: selected[0].context().tip_height + 30,
        },
        previous_candidate_id: None,
    }
}

#[tokio::test]
async fn protected_public_scan_to_engine_review_and_stale_generation_refusal() {
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
    let selections = vec![
        a.select_contribution(&FixtureAccess(true), &first_fvk, "owner-a", 105_000, &[])
            .unwrap(),
        b.select_contribution(&FixtureAccess(true), &second_fvk, "owner-b", 210_000, &[])
            .unwrap(),
    ];
    let request = candidate(&selections);
    let metadata = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(metadata.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let metadata_path = metadata.path().join("synthetic-engine.db");
    let metadata_key = ephemeral_database_key();
    let engine =
        Engine::from_store(Store::create_encrypted(&metadata_path, &metadata_key).unwrap());
    let access = Access {
        include_owned_agreements: true,
        principal_id: "synthetic-controller".into(),
        ..Default::default()
    };
    let agreement = &request.manifest.agreement;
    engine
        .create(&access, "protected-create-agreement", agreement.clone())
        .unwrap();
    for (i, p) in request.manifest.participants.iter().enumerate() {
        engine
            .add_intent(
                &access,
                &format!("protected-intent-{i}"),
                &agreement.agreement_id,
                i as u64 + 1,
                ParticipationIntent {
                    intent_id: format!("intent-{i}"),
                    agreement_id: agreement.agreement_id.clone(),
                    participant_id: p.participant_id.clone(),
                    desired_contribution: p.contribution,
                    maximum_net_debit: p.maximum_net_debit,
                    fee_cap: p.fee_cap,
                    conditions: vec![],
                    valid_until: None,
                    status: IntentStatus::Active,
                },
            )
            .unwrap();
    }
    let frozen = engine
        .create_candidate(
            &access,
            "protected-freeze-candidate",
            &agreement.agreement_id,
            3,
            request.clone(),
        )
        .unwrap();
    let frozen = &frozen.agreement.candidates[0];
    let declarations: Vec<_> = ["owner-a", "owner-b"]
        .into_iter()
        .map(|id| DisclosureAcknowledgement {
            account_id: id.into(),
            manifest_digest: hex::decode(&frozen.manifest_digest)
                .unwrap()
                .try_into()
                .unwrap(),
            operator: "synthetic-local".into(),
            reviewer_account_ids: vec!["owner-a".into(), "owner-b".into()],
            purpose: "Local synthetic constructor test".into(),
            retention_policy: "Discard private artifacts".into(),
            scope: DisclosureScope::DedicatedAccountFvkAndSelectedNotesAndOutputs,
        })
        .collect();
    let candidate_id = frozen.candidate_id.clone();
    let plaintext = Engine::open(metadata.path().join("synthetic-plaintext-metadata.db")).unwrap();
    assert_eq!(
        plaintext
            .construct_candidate_from_wallets(
                &access,
                "protected-plaintext-refused",
                &candidate_id,
                4,
                ScannedWalletConstruction {
                    contributions: vec![],
                    declarations: &declarations
                }
            )
            .unwrap_err()
            .code,
        "STORAGE_PROTECTION_REQUIRED"
    );
    drop(plaintext);
    // Controller drop invalidates already-issued provenance at the actual engine entry.
    let stale_a = a
        .select_contribution(&FixtureAccess(true), &first_fvk, "owner-a", 105_000, &[])
        .unwrap();
    let stale_b = b
        .select_contribution(&FixtureAccess(true), &second_fvk, "owner-b", 210_000, &[])
        .unwrap();
    let denied = Access {
        include_owned_agreements: true,
        principal_id: "other-controller".into(),
        ..Default::default()
    };
    assert!(
        engine
            .construct_candidate_from_wallets(
                &denied,
                "protected-denied-client",
                &candidate_id,
                4,
                ScannedWalletConstruction {
                    contributions: vec![stale_a, stale_b],
                    declarations: &declarations
                }
            )
            .is_err()
    );
    let report = engine
        .construct_candidate_from_wallets(
            &access,
            "protected-compute-candidate",
            &candidate_id,
            4,
            ScannedWalletConstruction {
                contributions: selections,
                declarations: &declarations,
            },
        )
        .unwrap();
    let review = &report.agreement.candidates[0].reviews[0];
    assert!(review.economic_terms_verified);
    assert!(
        !review.chain_validated
            && !review.authorization_allowed
            && !review.distribution_allowed
            && !review.account_associations_authenticated
            && !review.disclosure_consents_authenticated
    );
    assert_eq!(
        review.participant_net_debits_zatoshis["participant-0"],
        "105000"
    );
    assert_eq!(
        review.participant_net_debits_zatoshis["participant-1"],
        "210000"
    );
    let stale = vec![
        a.select_contribution(&FixtureAccess(true), &first_fvk, "owner-a", 105_000, &[])
            .unwrap(),
        b.select_contribution(&FixtureAccess(true), &second_fvk, "owner-b", 210_000, &[])
            .unwrap(),
    ];
    drop(a);
    assert_eq!(
        engine
            .construct_candidate_from_wallets(
                &access,
                "protected-stale-controller",
                &candidate_id,
                5,
                ScannedWalletConstruction {
                    contributions: stale,
                    declarations: &declarations
                }
            )
            .unwrap_err()
            .code,
        "WALLET_OBSERVATION_UNAVAILABLE"
    );
    let wire = serde_json::to_string(&report).unwrap();
    assert!(
        !wire.contains(&hex::encode(first_fvk.to_bytes()))
            && !wire.contains("nullifier")
            && !wire.contains("witness")
    );
    drop(engine);
    let reopened =
        Engine::from_store(Store::open_encrypted(&metadata_path, &metadata_key).unwrap());
    let (_, candidate) = reopened.candidate(&access, &candidate_id).unwrap();
    assert_eq!(candidate.reviews.len(), 1);
    server.abort();
}
