#![cfg(all(feature = "protected-sync", feature = "synthetic-qualification"))]
//! Never-funded synthetic HTTP/2 scans -> exact encrypted checkpoint. No signer,
//! external disclosure, actual network chain, or settlement is exercised.
use std::cell::{Cell, RefCell};
use wholepact_core::*;
use wholepact_engine::{
    Access, CandidateRequest, Engine,
    candidates::ScannedWalletConstruction,
    proof_jobs::{LocalProofJob, ScannedWalletCheckpoint},
};
use wholepact_proof_jobs::{CheckpointScope, LocalAction, LocalProofConsent, ProofJobStore};
use wholepact_protocol::{
    construction::*, proving::ProvingLimits, review::encode_testnet_receiver,
};
use wholepact_storage_security::{create_encrypted, open_encrypted};
use wholepact_store::Store;
use wholepact_wallet::wallet::protected_sync::*;
mod support;
use support::*;

struct FixtureGate {
    candidate: String,
    manifest: String,
    controller: RefCell<Option<ProtectedWalletSync>>,
    invalidate_at: Option<usize>,
    retention_checks: Cell<usize>,
    allowed: Cell<bool>,
    read_allowed: Cell<bool>,
}
impl LocalProofConsent for FixtureGate {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        if action == LocalAction::RetainPrivateWitnesses {
            let n = self.retention_checks.get();
            self.retention_checks.set(n + 1);
            if self.invalidate_at == Some(n) {
                self.controller.borrow_mut().take();
            }
        }
        self.allowed.get()
            && scope.principal_id == "synthetic-controller"
            && scope.candidate_id == self.candidate
            && scope.manifest_digest == self.manifest
            && scope.account_ids == ["owner-a", "owner-b"]
            && scope.local_operator == "synthetic-local"
            && scope.purpose == "Local synthetic checkpoint test"
            && scope.retention_policy == "Temporary encrypted test directory only; no distribution"
            && (action != LocalAction::ReadPrivateArtifact || self.read_allowed.get())
    }
}
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

async fn run_case(invalidate_at: Option<usize>, prove: bool) {
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
    let capabilities = engine.capabilities();
    assert_eq!(
        capabilities["features"]["protected_wallet_checkpoint"]["status"],
        "experimental"
    );
    assert_eq!(
        capabilities["features"]["cooperative_settlement"]["status"],
        "unavailable"
    );
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
            purpose: "Local synthetic checkpoint test".into(),
            retention_policy: "Temporary encrypted test directory only; no distribution".into(),
            scope: DisclosureScope::DedicatedAccountFvkAndSelectedNotesAndOutputs,
        })
        .collect();
    let candidate_id = frozen.candidate_id.clone();

    let artifact_path = metadata.path().join("synthetic-proof.db");
    let artifact_key = ephemeral_database_key();
    let jobs = ProofJobStore::from_encrypted_connection(
        create_encrypted(&artifact_path, &artifact_key).unwrap(),
    )
    .unwrap();
    let gate = FixtureGate {
        candidate: candidate_id.clone(),
        manifest: frozen.manifest_digest.clone(),
        controller: RefCell::new(Some(a)),
        invalidate_at,
        retention_checks: Cell::new(0),
        allowed: Cell::new(true),
        read_allowed: Cell::new(false),
    };
    if invalidate_at.is_none() {
        let denied = Access {
            include_owned_agreements: true,
            principal_id: "different-controller".into(),
            ..Default::default()
        };
        let empty = || ScannedWalletCheckpoint {
            construction: ScannedWalletConstruction {
                contributions: vec![],
                declarations: &declarations,
            },
            jobs: &jobs,
            limits: ProvingLimits { maximum_actions: 8 },
            consent: &gate,
        };
        assert_eq!(
            engine
                .checkpoint_candidate_from_wallets(
                    &denied,
                    "protected-denied-client",
                    &candidate_id,
                    4,
                    empty()
                )
                .unwrap_err()
                .code,
            "NOT_FOUND"
        );
        let plaintext = Engine::open(metadata.path().join("plaintext.db")).unwrap();
        assert_eq!(
            plaintext
                .checkpoint_candidate_from_wallets(
                    &access,
                    "protected-plaintext-refused",
                    &candidate_id,
                    4,
                    empty()
                )
                .unwrap_err()
                .code,
            "STORAGE_PROTECTION_REQUIRED"
        );
        gate.allowed.set(false);
        let denied_selections = vec![
            gate.controller
                .borrow_mut()
                .as_mut()
                .unwrap()
                .select_contribution(&FixtureAccess(true), &first_fvk, "owner-a", 105_000, &[])
                .unwrap(),
            b.select_contribution(&FixtureAccess(true), &second_fvk, "owner-b", 210_000, &[])
                .unwrap(),
        ];
        assert_eq!(
            engine
                .checkpoint_candidate_from_wallets(
                    &access,
                    "protected-consent-refused",
                    &candidate_id,
                    4,
                    ScannedWalletCheckpoint {
                        construction: ScannedWalletConstruction {
                            contributions: denied_selections,
                            declarations: &declarations
                        },
                        jobs: &jobs,
                        limits: ProvingLimits { maximum_actions: 8 },
                        consent: &gate,
                    }
                )
                .unwrap_err()
                .code,
            "DISCLOSURE_DENIED"
        );
        assert_eq!(
            engine
                .get(&access, &agreement.agreement_id)
                .unwrap()
                .revision,
            4
        );
        gate.allowed.set(true);
        gate.retention_checks.set(0);
    }
    let key = "protected-checkpoint-exact";
    let result = engine.checkpoint_candidate_from_wallets(
        &access,
        key,
        &candidate_id,
        4,
        ScannedWalletCheckpoint {
            construction: ScannedWalletConstruction {
                contributions: selections,
                declarations: &declarations,
            },
            jobs: &jobs,
            limits: ProvingLimits { maximum_actions: 8 },
            consent: &gate,
        },
    );
    if let Some(at) = invalidate_at {
        let error = result.unwrap_err();
        assert_eq!(error.code, "WALLET_OBSERVATION_UNAVAILABLE");
        assert_eq!(
            engine
                .get(&access, &agreement.agreement_id)
                .unwrap()
                .revision,
            if at == 0 { 4 } else { 5 }
        );
        if at != 0 {
            assert_eq!(error.details["constructor_receipt_created"], true);
            // A receipt without a private artifact is explicit recovery state.
            // Retrying the same request with restored source objects must not
            // construct different randomized bytes under that idempotency key.
            let digest = error.details["coordination_request_digest"]
                .as_str()
                .unwrap();
            assert!(
                jobs.status_for_key(&access.principal_id, key, digest, &gate)
                    .unwrap()
                    .is_none()
            );
        }
        assert!(
            jobs.status(
                &access.principal_id,
                &wholepact_proof_jobs::job_id_for_key(&access.principal_id, key).unwrap(),
                &gate
            )
            .is_err()
        );
        if at != 0 {
            let mut restored = controller(&path_a, &key_a, &endpoint);
            restored
                .synchronize(&FixtureAccess(true), SyncLimits::default())
                .await
                .unwrap();
            let retry_selections = vec![
                restored
                    .select_contribution(&FixtureAccess(true), &first_fvk, "owner-a", 105_000, &[])
                    .unwrap(),
                b.select_contribution(&FixtureAccess(true), &second_fvk, "owner-b", 210_000, &[])
                    .unwrap(),
            ];
            *gate.controller.borrow_mut() = Some(restored);
            assert_eq!(
                engine
                    .checkpoint_candidate_from_wallets(
                        &access,
                        key,
                        &candidate_id,
                        4,
                        ScannedWalletCheckpoint {
                            construction: ScannedWalletConstruction {
                                contributions: retry_selections,
                                declarations: &declarations
                            },
                            jobs: &jobs,
                            limits: ProvingLimits { maximum_actions: 8 },
                            consent: &gate,
                        }
                    )
                    .unwrap_err()
                    .code,
                "RECOVERY_REQUIRED"
            );
            assert_eq!(
                engine
                    .get(&access, &agreement.agreement_id)
                    .unwrap()
                    .revision,
                5
            );
        }
    } else {
        let result = result.unwrap();
        let checkpoint = &result.agreement.candidates[0].proof_jobs[0];
        assert!(checkpoint.encrypted_checkpoint_created);
        assert_eq!(checkpoint.state, "queued");
        assert!(
            !checkpoint.proof_verified
                && !checkpoint.chain_validated
                && !checkpoint.authorization_allowed
                && !checkpoint.distribution_allowed
        );
        let job_id = checkpoint.job_id.clone();
        let digest = checkpoint.input_digest.clone();
        // A current source permits exact-key replay without reconstructing.
        let again = vec![
            gate.controller
                .borrow_mut()
                .as_mut()
                .unwrap()
                .select_contribution(&FixtureAccess(true), &first_fvk, "owner-a", 105_000, &[])
                .unwrap(),
            b.select_contribution(&FixtureAccess(true), &second_fvk, "owner-b", 210_000, &[])
                .unwrap(),
        ];
        let replay = engine
            .checkpoint_candidate_from_wallets(
                &access,
                key,
                &candidate_id,
                4,
                ScannedWalletCheckpoint {
                    construction: ScannedWalletConstruction {
                        contributions: again,
                        declarations: &declarations,
                    },
                    jobs: &jobs,
                    limits: ProvingLimits { maximum_actions: 8 },
                    consent: &gate,
                },
            )
            .unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.operation_id, result.operation_id);
        assert_eq!(
            replay.agreement.candidates[0].proof_jobs[0].input_digest,
            digest
        );
        let wire = serde_json::to_string(&result).unwrap();
        assert!(
            !wire.contains(&hex::encode(first_fvk.to_bytes()))
                && !wire.contains("pczt_bytes")
                && !wire.contains("review_policy")
        );
        let stale = vec![
            gate.controller
                .borrow_mut()
                .as_mut()
                .unwrap()
                .select_contribution(&FixtureAccess(true), &first_fvk, "owner-a", 105_000, &[])
                .unwrap(),
            b.select_contribution(&FixtureAccess(true), &second_fvk, "owner-b", 210_000, &[])
                .unwrap(),
        ];
        gate.controller.borrow_mut().take();
        let error = engine
            .checkpoint_candidate_from_wallets(
                &access,
                "protected-stale-checkpoint",
                &candidate_id,
                6,
                ScannedWalletCheckpoint {
                    construction: ScannedWalletConstruction {
                        contributions: stale,
                        declarations: &declarations,
                    },
                    jobs: &jobs,
                    limits: ProvingLimits { maximum_actions: 8 },
                    consent: &gate,
                },
            )
            .unwrap_err();
        assert_eq!(error.code, "WALLET_OBSERVATION_UNAVAILABLE");
        drop(engine);
        drop(jobs);
        let engine =
            Engine::from_store(Store::open_encrypted(&metadata_path, &metadata_key).unwrap());
        let jobs = ProofJobStore::from_encrypted_connection(
            open_encrypted(&artifact_path, &artifact_key).unwrap(),
        )
        .unwrap();
        let local = || LocalProofJob {
            job_id: &job_id,
            jobs: &jobs,
            consent: &gate,
        };
        let status = engine
            .candidate_proof_status(&access, &candidate_id, local())
            .unwrap();
        assert_eq!(status.input_digest, digest);
        // Reconciliation observes existing retention, not fresh wallet authority.
        let linked = engine
            .reconcile_candidate_proof_job(
                &access,
                "protected-reconcile-checkpoint",
                &candidate_id,
                6,
                local(),
            )
            .unwrap();
        assert_eq!(
            linked.agreement.candidates[0].proof_jobs[0].input_digest,
            digest
        );
        gate.allowed.set(false);
        assert_eq!(
            engine
                .candidate_proof_status(&access, &candidate_id, local())
                .unwrap_err()
                .code,
            "DISCLOSURE_DENIED"
        );
        gate.allowed.set(true);
        if prove {
            let proved = engine
                .run_candidate_proof_locally(
                    &access,
                    "protected-prove-checkpoint",
                    &candidate_id,
                    7,
                    local(),
                )
                .unwrap();
            let saved = &proved.agreement.candidates[0].proof_jobs[0];
            assert_eq!(saved.input_digest, digest);
            assert!(saved.proof_verified && saved.result_digest.is_some());
            assert!(
                !saved.authorization_allowed
                    && !saved.chain_validated
                    && !saved.distribution_allowed
            );
            assert_eq!(
                engine
                    .load_candidate_proof_for_local_review(&access, &candidate_id, local())
                    .err()
                    .unwrap()
                    .code,
                "DISCLOSURE_DENIED"
            );
            gate.read_allowed.set(true);
            assert!(
                engine
                    .load_candidate_proof_for_local_review(&access, "different-candidate", local())
                    .is_err()
            );
            let checkpoint = engine
                .load_candidate_proof_for_local_review(&access, &candidate_id, local())
                .unwrap();
            assert_eq!(checkpoint.summary().input_digest, digest);
            assert_eq!(checkpoint.summary().result_digest, saved.result_digest);
            let (_, candidate) = engine.candidate(&access, &candidate_id).unwrap();
            let proposal = Proposal::validate(candidate.proposal).unwrap();
            // Loading private bytes does not confer continuing inspection consent.
            gate.read_allowed.set(false);
            assert!(
                wholepact_signer::inspection::TransactionInspection::from_checkpoint(
                    checkpoint,
                    &proposal,
                    "owner-a",
                    &access.principal_id,
                    &gate
                )
                .is_err()
            );
            gate.read_allowed.set(true);
            let mut substituted = proposal.input().clone();
            substituted.manifest.agreement.purpose = "Substituted application claim".into();
            let substituted = Proposal::validate(substituted).unwrap();
            let checkpoint = engine
                .load_candidate_proof_for_local_review(&access, &candidate_id, local())
                .unwrap();
            assert!(
                wholepact_signer::inspection::TransactionInspection::from_checkpoint(
                    checkpoint,
                    &substituted,
                    "owner-a",
                    &access.principal_id,
                    &gate
                )
                .is_err()
            );
            let checkpoint = engine
                .load_candidate_proof_for_local_review(&access, &candidate_id, local())
                .unwrap();
            assert!(
                wholepact_signer::inspection::TransactionInspection::from_checkpoint(
                    checkpoint,
                    &proposal,
                    "owner-a",
                    "different-controller",
                    &gate
                )
                .is_err()
            );
            let checkpoint = engine
                .load_candidate_proof_for_local_review(&access, &candidate_id, local())
                .unwrap();
            let inspection = wholepact_signer::inspection::TransactionInspection::from_checkpoint(
                checkpoint,
                &proposal,
                "owner-a",
                &access.principal_id,
                &gate,
            )
            .unwrap();
            assert!(!inspection.authorization_allowed());
            inspection.recheck().unwrap();
            assert!(
                inspection
                    .display()
                    .contains(saved.result_digest.as_ref().unwrap())
            );
            assert!(inspection.display().contains(&digest));
            assert!(
                inspection
                    .display()
                    .contains("Own net debit: 105000 zatoshis")
            );
            assert!(inspection.display().contains("NO SPENDING AUTHORITY"));
            let binding = inspection.binding().to_owned();
            #[cfg(target_os = "linux")]
            assert_eq!(
                wholepact_signer::native_ui::qualify_transaction_inspection(inspection).unwrap(),
                binding
            );
            #[cfg(not(target_os = "linux"))]
            let _ = binding;
        }
    }
    server.abort();
}

#[tokio::test]
async fn protected_wallet_checkpoint_replays_and_restores_exact_artifact() {
    run_case(None, false).await;
}

#[tokio::test]
async fn invalidation_during_every_retention_gate_rolls_back_private_checkpoint() {
    for gate in 0..4 {
        run_case(Some(gate), false).await;
    }
}

#[tokio::test]
#[ignore = "Expensive actual Halo2 proof; run explicitly with the qualified release toolchain"]
async fn protected_wallet_checkpoint_proves_exact_saved_artifact() {
    run_case(None, true).await;
}
