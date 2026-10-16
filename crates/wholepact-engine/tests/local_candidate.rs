#![cfg(feature = "synthetic-qualification")]
//! Real maintained-library scanning/construction, exclusively never-funded
//! synthetic notes and a fabricated compact block. This is not chain settlement.
use wholepact_core::*;
use wholepact_engine::candidates::LocalConstruction;
use wholepact_engine::{Access, CandidateRequest, Engine};
use wholepact_protocol::{construction::*, review::encode_testnet_receiver};
use wholepact_wallet::wallet::synthetic_scanned_contributions;

fn amount(n: u64) -> Amount {
    Amount::from_zatoshis(n).unwrap()
}
fn copy_packages(packages: &[OwnedContribution]) -> Vec<OwnedContribution> {
    packages
        .iter()
        .map(|p| OwnedContribution {
            account_id: p.account_id.clone(),
            fvk: p.fvk.clone(),
            change_address: p.change_address,
            notes: p
                .notes
                .iter()
                .map(|n| SpendableNote {
                    input_id: n.input_id.clone(),
                    note: n.note,
                    witness: n.witness.clone(),
                })
                .collect(),
        })
        .collect()
}

struct Fixture {
    agreement: AgreementDraft,
    request: CandidateRequest,
    chain: ConstructionContext,
    packages: Vec<OwnedContribution>,
    account_ids: Vec<String>,
}
fn fixture() -> Fixture {
    let (wallets, selection) = synthetic_scanned_contributions().unwrap();
    let receiver = encode_testnet_receiver(&wallets[0].notes()[0].note.recipient());
    let account_ids: Vec<_> = wallets.iter().map(|w| w.account_id().to_owned()).collect();
    let agreement = AgreementDraft {
        schema_version: 1,
        agreement_id: "scanner-to-engine-synthetic".into(),
        obligation_id: "never-funded-obligation".into(),
        revision: 1,
        purpose: "Synthetic scanner to candidate qualification; no network or funds".into(),
        organizer_identity: "fixture-organizer".into(),
        network_profile_id: PROFILE_ID.into(),
        recipients: vec![Recipient {
            recipient_id: "fixture-recipient".into(),
            address: receiver.clone(),
            amount: amount(300_000),
            memo: None,
            instruction_provenance: "Synthetic owner receiver, not a live payment".into(),
        }],
        funding_policy: FundingPolicy::Exact {
            target: amount(300_000),
        },
        fee_policy: FeePolicy::ProRata,
        privacy_profile: PrivacyProfile {
            mode: PrivacyMode::DeclaredOperator,
            proving_operator: Some("synthetic-local-constructor".into()),
            dedicated_accounts_required: true,
        },
        coordination_deadline: None,
        confirmation_policy: ConfirmationPolicy::default(),
        extensions: vec![],
    };
    let participants: Vec<_> = wallets
        .iter()
        .enumerate()
        .map(|(i, w)| ParticipantAllocation {
            participant_id: format!("participant-{i}"),
            account_id: w.account_id().into(),
            contribution: amount(if i == 0 { 100_000 } else { 200_000 }),
            fee_share: amount(if i == 0 { 5_000 } else { 10_000 }),
            fee_cap: amount(if i == 0 { 5_000 } else { 10_000 }),
            maximum_net_debit: amount(w.requested_debit_zatoshis()),
            charges: vec![],
        })
        .collect();
    let mut inputs = vec![];
    let mut outputs = vec![ClaimedOutput {
        output_id: "recipient-output".into(),
        address: receiver,
        amount: amount(300_000),
        allocation: OutputAllocation::Recipient {
            recipient_id: "fixture-recipient".into(),
        },
    }];
    for (i, w) in wallets.iter().enumerate() {
        for n in w.notes() {
            inputs.push(ClaimedInput {
                input_id: n.input_id.clone(),
                participant_id: participants[i].participant_id.clone(),
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
                participant_id: participants[i].participant_id.clone(),
                account_id: w.account_id().into(),
                ownership_evidence_ref: None,
            },
        });
    }
    let request = CandidateRequest {
        manifest: ProposalManifest {
            agreement: agreement.clone(),
            participants: participants.clone(),
            inputs,
            outputs,
            transaction_fee: amount(15_000),
            expiry_height: selection.tip_height + 30,
        },
        previous_candidate_id: None,
    };
    let chain = ConstructionContext {
        anchor: selection.anchor_root,
        anchor_height: selection.anchor_height,
        anchor_block_hash: selection.anchor_hash_protocol,
        target_height: selection.tip_height + 1,
    };
    let packages: Vec<_> = wallets.into_iter().map(|w| w.into_contribution()).collect();
    Fixture {
        agreement,
        request,
        chain,
        packages,
        account_ids,
    }
}

#[test]
fn scanner_to_durable_candidate_actual_economic_review_and_restart_without_release() {
    let Fixture {
        agreement,
        request,
        chain,
        packages,
        account_ids,
    } = fixture();
    let participants = request.manifest.participants.clone();
    let private_fvk_hex = hex::encode(packages[0].fvk.to_bytes());
    let access = Access {
        include_owned_agreements: true,
        principal_id: "synthetic-controller".into(),
        ..Access::default()
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic-public-summaries.sqlite");
    let engine = Engine::open(&path).unwrap();
    engine
        .create(&access, "synthetic-agreement-create", agreement.clone())
        .unwrap();
    for (i, p) in participants.iter().enumerate() {
        engine
            .add_intent(
                &access,
                &format!("synthetic-intent-{i:04}"),
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
            "synthetic-candidate-create",
            &agreement.agreement_id,
            3,
            request.clone(),
        )
        .unwrap();
    let candidate = &frozen.agreement.candidates[0];
    let candidate_id = candidate.candidate_id.clone();
    let mut declarations: Vec<_> = account_ids
        .iter()
        .map(|id| DisclosureAcknowledgement {
            account_id: id.clone(),
            manifest_digest: hex::decode(&candidate.manifest_digest)
                .unwrap()
                .try_into()
                .unwrap(),
            operator: "synthetic-local-constructor".into(),
            reviewer_account_ids: account_ids.clone(),
            purpose: "Local synthetic computation only, no distribution".into(),
            retention_policy: "Discard private artifacts immediately".into(),
            scope: DisclosureScope::DedicatedAccountFvkAndSelectedNotesAndOutputs,
        })
        .collect();
    declarations[0].reviewer_account_ids.pop();
    assert_eq!(
        engine
            .construct_candidate_locally(
                &access,
                "synthetic-bad-declaration",
                &candidate_id,
                4,
                LocalConstruction {
                    context: chain,
                    contributions: copy_packages(&packages),
                    declarations: &declarations
                },
            )
            .unwrap_err()
            .code,
        "CANDIDATE_VERIFICATION_FAILED"
    );
    declarations[0].reviewer_account_ids = account_ids;
    let computed = engine
        .construct_candidate_locally(
            &access,
            "synthetic-compute-candidate",
            &candidate_id,
            4,
            LocalConstruction {
                context: chain,
                contributions: copy_packages(&packages),
                declarations: &declarations,
            },
        )
        .unwrap();
    let report = &computed.agreement.candidates[0].reviews[0];
    assert!(report.economic_terms_verified);
    assert_eq!(report.exact_fee_zatoshis, "15000");
    assert_eq!(
        report.participant_net_debits_zatoshis["participant-0"],
        "105000"
    );
    assert_eq!(
        report.participant_net_debits_zatoshis["participant-1"],
        "210000"
    );
    assert!(
        report.artifact_digest.is_some()
            && report.effects_commitment.is_some()
            && report.review_binding.is_some()
    );
    assert!(
        !report.disclosure_consents_authenticated
            && !report.account_associations_authenticated
            && !report.authorization_allowed
            && !report.distribution_allowed
            && !report.chain_validated
    );
    assert_eq!(report.human_approval, "not_requested");
    assert!(report.artifact_persistence.starts_with("not_retained"));
    let visible =
        serde_json::to_string(&engine.operation(&access, &computed.operation_id).unwrap()).unwrap();
    assert!(!visible.contains(&private_fvk_hex));
    assert!(!visible.contains("pczt_bytes"));
    assert!(!visible.contains("review_policy"));
    drop(engine);
    let engine = Engine::open(&path).unwrap();
    let replay = engine
        .construct_candidate_locally(
            &access,
            "synthetic-compute-candidate",
            &candidate_id,
            4,
            LocalConstruction {
                context: chain,
                contributions: copy_packages(&packages),
                declarations: &declarations,
            },
        )
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.operation_id, computed.operation_id);
    assert_eq!(
        replay.agreement.candidates[0].reviews[0].artifact_digest,
        report.artifact_digest
    );
    let mut changed_context = chain;
    changed_context.target_height += 1;
    assert_eq!(
        engine
            .construct_candidate_locally(
                &access,
                "synthetic-compute-candidate",
                &candidate_id,
                4,
                LocalConstruction {
                    context: changed_context,
                    contributions: copy_packages(&packages),
                    declarations: &declarations
                },
            )
            .unwrap_err()
            .code,
        "IDEMPOTENCY_CONFLICT"
    );
    // Reconciled claims can still lie about actual input values; real construction rejects them.
    let mut changed = request;
    changed.previous_candidate_id = Some(candidate_id);
    changed.manifest.inputs[0].amount = changed.manifest.inputs[0]
        .amount
        .checked_add(amount(1))
        .unwrap();
    changed.manifest.outputs[1].amount = changed.manifest.outputs[1]
        .amount
        .checked_add(amount(1))
        .unwrap();
    let next = engine
        .create_candidate(
            &access,
            "synthetic-changed-input",
            &agreement.agreement_id,
            5,
            changed,
        )
        .unwrap();
    let new_candidate = next.agreement.candidates.last().unwrap();
    for d in &mut declarations {
        d.manifest_digest = hex::decode(&new_candidate.manifest_digest)
            .unwrap()
            .try_into()
            .unwrap();
    }
    assert_eq!(
        engine
            .construct_candidate_locally(
                &access,
                "synthetic-reject-fake-input",
                &new_candidate.candidate_id,
                6,
                LocalConstruction {
                    context: chain,
                    contributions: packages,
                    declarations: &declarations
                },
            )
            .unwrap_err()
            .code,
        "CANDIDATE_VERIFICATION_FAILED"
    );
    assert_eq!(
        engine
            .get(&access, &agreement.agreement_id)
            .unwrap()
            .revision,
        6
    );
    assert_eq!(
        engine
            .get(&access, &agreement.agreement_id)
            .unwrap()
            .authorization_exposure,
        "unknown"
    );
}

#[cfg(feature = "local-proof-jobs")]
mod encrypted_proof_bridge {
    use super::*;
    use sha2::Digest;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wholepact_engine::proof_jobs::{LocalCheckpoint, LocalProofJob};
    use wholepact_proof_jobs::{CheckpointScope, LocalAction, LocalProofConsent, ProofJobStore};
    use wholepact_protocol::proving::ProvingLimits;
    use wholepact_storage_security::{DatabaseKey, create_encrypted, open_encrypted};

    // This gate approves only this test's fabricated never-funded account data.
    // It is not shipped as a production consent provider or a human approval.
    struct SyntheticGate {
        candidate_id: String,
        manifest_digest: String,
        accounts: Vec<String>,
        allowed: bool,
        race: Option<(Engine, Access, String)>,
        raced: AtomicUsize,
    }
    impl LocalProofConsent for SyntheticGate {
        fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
            let valid = self.allowed
                && scope.principal_id == "synthetic-controller"
                && scope.candidate_id == self.candidate_id
                && scope.manifest_digest == self.manifest_digest
                && scope.account_ids == self.accounts
                && scope.local_operator == "synthetic-local-constructor"
                && scope.purpose == "Temporary synthetic proof qualification only"
                && scope.retention_policy
                    == "Temporary encrypted test directory only; no distribution"
                && scope.artifact_digest.len() == 64
                && scope.coordination_request_digest.len() == 64
                && action != LocalAction::ReadPrivateArtifact;
            if valid
                && action == LocalAction::RetainPrivateWitnesses
                && self.raced.fetch_add(1, Ordering::SeqCst) == 1
            {
                if let Some((engine, access, agreement)) = &self.race {
                    engine
                        .propose(access, "synthetic-concurrent-metadata", agreement, 5)
                        .unwrap();
                }
            }
            valid
        }
    }

    struct AbortAtEnqueue<'a> {
        inner: &'a dyn LocalProofConsent,
        retention_checks: AtomicUsize,
    }
    impl LocalProofConsent for AbortAtEnqueue<'_> {
        fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
            if action == LocalAction::RetainPrivateWitnesses
                && self.retention_checks.fetch_add(1, Ordering::SeqCst) == 1
            {
                return false;
            }
            self.inner.permits(scope, action)
        }
    }

    #[test]
    fn independent_journal_failure_reconciles_exact_checkpoint_then_proves_and_restarts() {
        let Fixture {
            agreement,
            request,
            chain,
            packages,
            account_ids,
        } = fixture();
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let metadata_path = dir.path().join("metadata.encrypted.sqlite");
        let artifact_path = dir.path().join("artifacts.encrypted.sqlite");
        // Public deterministic test-only keys protect never-funded synthetic data.
        let metadata_key = DatabaseKey::from_bytes([81; 32]);
        let artifact_key = DatabaseKey::from_bytes([82; 32]);
        let engine = Engine::from_store(
            wholepact_store::Store::create_encrypted(&metadata_path, &metadata_key).unwrap(),
        );
        let jobs = ProofJobStore::from_encrypted_connection(
            create_encrypted(&artifact_path, &artifact_key).unwrap(),
        )
        .unwrap();
        let access = Access {
            include_owned_agreements: true,
            principal_id: "synthetic-controller".into(),
            ..Access::default()
        };
        engine
            .create(&access, "synthetic-proof-agreement", agreement.clone())
            .unwrap();
        for (i, p) in request.manifest.participants.iter().enumerate() {
            engine
                .add_intent(
                    &access,
                    &format!("synthetic-proof-intent-{i}"),
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
                "synthetic-proof-candidate",
                &agreement.agreement_id,
                3,
                request,
            )
            .unwrap();
        let candidate = &frozen.agreement.candidates[0];
        let declarations: Vec<_> = account_ids
            .iter()
            .map(|id| DisclosureAcknowledgement {
                account_id: id.clone(),
                manifest_digest: hex::decode(&candidate.manifest_digest)
                    .unwrap()
                    .try_into()
                    .unwrap(),
                operator: "synthetic-local-constructor".into(),
                reviewer_account_ids: account_ids.clone(),
                purpose: "Temporary synthetic proof qualification only".into(),
                retention_policy: "Temporary encrypted test directory only; no distribution".into(),
                scope: DisclosureScope::DedicatedAccountFvkAndSelectedNotesAndOutputs,
            })
            .collect();
        let gate = SyntheticGate {
            candidate_id: candidate.candidate_id.clone(),
            manifest_digest: candidate.manifest_digest.clone(),
            accounts: account_ids.clone(),
            allowed: false,
            race: None,
            raced: AtomicUsize::new(0),
        };
        let checkpoint = |gate, maximum_actions| LocalCheckpoint {
            construction: LocalConstruction {
                context: chain,
                contributions: copy_packages(&packages),
                declarations: &declarations,
            },
            jobs: &jobs,
            limits: ProvingLimits { maximum_actions },
            consent: gate,
        };
        for maximum_actions in [0, 9] {
            assert_eq!(
                engine
                    .checkpoint_candidate_locally(
                        &access,
                        "synthetic-invalid-proof-limit",
                        &candidate.candidate_id,
                        4,
                        checkpoint(&gate, maximum_actions)
                    )
                    .unwrap_err()
                    .code,
                "INVALID_REQUEST"
            );
        }
        assert_eq!(
            engine
                .checkpoint_candidate_locally(
                    &access,
                    "synthetic-invalid-action-shape",
                    &candidate.candidate_id,
                    4,
                    checkpoint(&gate, 2)
                )
                .unwrap_err()
                .code,
            "RESOURCE_EXHAUSTED"
        );
        assert_eq!(
            engine
                .get(&access, &agreement.agreement_id)
                .unwrap()
                .revision,
            4
        );
        assert_eq!(
            engine
                .checkpoint_candidate_locally(
                    &access,
                    "synthetic-private-checkpoint",
                    &candidate.candidate_id,
                    4,
                    checkpoint(&gate, 8)
                )
                .unwrap_err()
                .code,
            "DISCLOSURE_DENIED"
        );
        let gate = SyntheticGate {
            allowed: true,
            race: Some((
                engine.clone(),
                access.clone(),
                agreement.agreement_id.clone(),
            )),
            candidate_id: gate.candidate_id.clone(),
            manifest_digest: gate.manifest_digest.clone(),
            accounts: gate.accounts.clone(),
            raced: AtomicUsize::new(0),
        };
        let foreign_gate = SyntheticGate {
            candidate_id: gate.candidate_id.clone(),
            manifest_digest: gate.manifest_digest.clone(),
            accounts: gate.accounts.clone(),
            allowed: true,
            race: None,
            raced: AtomicUsize::new(0),
        };
        let foreign_built = construct_proposal(
            &Proposal::validate(candidate.proposal.clone()).unwrap(),
            chain,
            copy_packages(&packages),
            &declarations,
        )
        .unwrap();
        let foreign_scope = CheckpointScope {
            principal_id: access.principal_id.clone(),
            candidate_id: candidate.candidate_id.clone(),
            manifest_digest: candidate.manifest_digest.clone(),
            coordination_request_digest: "11".repeat(32),
            artifact_digest: hex::encode(sha2::Sha256::digest(&foreign_built.pczt_bytes)),
            effects_commitment: foreign_built.economic_review.shielded_sighash().into(),
            review_binding: foreign_built.economic_review.review_binding().into(),
            account_ids: account_ids.clone(),
            local_operator: "synthetic-local-constructor".into(),
            purpose: "Temporary synthetic proof qualification only".into(),
            retention_policy: "Temporary encrypted test directory only; no distribution".into(),
        };
        let foreign_job = jobs
            .enqueue(
                &foreign_scope,
                "synthetic-direct-population",
                &foreign_built.pczt_bytes,
                &foreign_built.review_policy,
                ProvingLimits { maximum_actions: 8 },
                &foreign_gate,
            )
            .unwrap();
        assert_eq!(
            engine
                .reconcile_candidate_proof_job(
                    &access,
                    "synthetic-reject-foreign-job",
                    &candidate.candidate_id,
                    4,
                    LocalProofJob {
                        job_id: &foreign_job.job_id,
                        jobs: &jobs,
                        consent: &foreign_gate
                    }
                )
                .unwrap_err()
                .code,
            "MISSING_EVIDENCE"
        );
        assert_eq!(
            Engine::in_memory()
                .unwrap()
                .checkpoint_candidate_locally(
                    &access,
                    "synthetic-private-checkpoint",
                    &candidate.candidate_id,
                    4,
                    checkpoint(&gate, 8)
                )
                .unwrap_err()
                .code,
            "STORAGE_PROTECTION_REQUIRED"
        );
        let partial = engine
            .checkpoint_candidate_locally(
                &access,
                "synthetic-private-checkpoint",
                &candidate.candidate_id,
                4,
                checkpoint(&gate, 8),
            )
            .unwrap_err();
        assert_eq!(partial.code, "REVISION_CONFLICT");
        assert_eq!(partial.details["encrypted_checkpoint_created"], true);
        assert_eq!(partial.details["coordination_link_committed"], false);
        let job_id = partial.details["proof_job_id"].as_str().unwrap().to_owned();
        let again = engine
            .checkpoint_candidate_locally(
                &access,
                "synthetic-private-checkpoint",
                &candidate.candidate_id,
                4,
                checkpoint(&gate, 8),
            )
            .unwrap_err();
        assert_eq!(again.details["proof_job_id"], job_id);
        // Different semantic request under the same key is rejected without building.
        assert_eq!(
            engine
                .checkpoint_candidate_locally(
                    &access,
                    "synthetic-private-checkpoint",
                    &candidate.candidate_id,
                    4,
                    checkpoint(&gate, 7)
                )
                .unwrap_err()
                .code,
            "IDEMPOTENCY_CONFLICT"
        );
        assert!(
            engine
                .get(&access, &agreement.agreement_id)
                .unwrap()
                .candidates[0]
                .proof_jobs
                .is_empty()
        );
        let repaired = engine
            .reconcile_candidate_proof_job(
                &access,
                "synthetic-link-reconciliation",
                &candidate.candidate_id,
                6,
                LocalProofJob {
                    job_id: &job_id,
                    jobs: &jobs,
                    consent: &gate,
                },
            )
            .unwrap();
        let saved = repaired.agreement.candidates[0].proof_jobs[0].clone();
        assert_eq!(saved.state, "queued");
        assert_eq!(saved.attempt, 0);
        assert!(saved.encrypted_checkpoint_created);
        assert!(!saved.proof_verified);
        let private_fvk = hex::encode(packages[0].fvk.to_bytes());
        let candidate_id = candidate.candidate_id.clone();
        drop(gate);
        drop(engine);
        drop(jobs);
        let engine = Engine::from_store(
            wholepact_store::Store::open_encrypted(&metadata_path, &metadata_key).unwrap(),
        );
        let jobs = ProofJobStore::from_encrypted_connection(
            open_encrypted(&artifact_path, &artifact_key).unwrap(),
        )
        .unwrap();
        let gate = SyntheticGate {
            candidate_id: candidate_id.clone(),
            manifest_digest: candidate.manifest_digest.clone(),
            accounts: account_ids,
            allowed: true,
            race: None,
            raced: AtomicUsize::new(0),
        };
        let proven = engine
            .run_candidate_proof_locally(
                &access,
                "synthetic-engine-proof-run",
                &candidate_id,
                7,
                LocalProofJob {
                    job_id: &job_id,
                    jobs: &jobs,
                    consent: &gate,
                },
            )
            .unwrap();
        let summary = &proven.agreement.candidates[0].proof_jobs[0];
        assert_eq!(summary.state, "succeeded");
        assert_eq!(summary.attempt, 1);
        assert!(summary.proof_verified);
        assert_eq!(summary.input_digest, saved.input_digest);
        assert_eq!(summary.review_binding, saved.review_binding);
        assert!(summary.result_digest.is_some());
        assert!(
            !summary.chain_validated
                && !summary.authorization_allowed
                && !summary.distribution_allowed
        );
        #[cfg(feature = "signature-intake")]
        {
            // Existing gate deliberately denies private reads; the public entry
            // must preserve that denial before any signature inspection.
            let denied = engine.inspect_candidate_signatures(
                &access,
                &candidate_id,
                LocalProofJob {
                    job_id: &job_id,
                    jobs: &jobs,
                    consent: &gate,
                },
                &[],
                &wholepact_transport::Timestamp::from_unix_seconds(1_800_000_000).unwrap(),
            );
            assert!(denied.is_err());
            struct FixtureReadGate<'a>(&'a SyntheticGate);
            impl LocalProofConsent for FixtureReadGate<'_> {
                fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
                    self.0.permits(
                        scope,
                        if action == LocalAction::ReadPrivateArtifact {
                            LocalAction::InspectStatus
                        } else {
                            action
                        },
                    )
                }
            }
            let inspection = engine
                .inspect_candidate_signatures(
                    &access,
                    &candidate_id,
                    LocalProofJob {
                        job_id: &job_id,
                        jobs: &jobs,
                        consent: &FixtureReadGate(&gate),
                    },
                    &[],
                    &wholepact_transport::Timestamp::from_unix_seconds(1_800_000_000).unwrap(),
                )
                .unwrap();
            assert_eq!(inspection.verified_real_inputs, 0);
            assert!(inspection.proof_verified && inspection.exact_candidate_preserved);
            assert!(
                !inspection.signatures_complete
                    && !inspection.authorization_allowed
                    && !inspection.distribution_allowed
                    && !inspection.chain_validated
            );
        }
        let visible =
            serde_json::to_string(&engine.operation(&access, &proven.operation_id).unwrap())
                .unwrap();
        assert!(!visible.contains(&private_fvk));
        assert!(!visible.contains("pczt_bytes"));
        assert!(!visible.contains("policy_bytes"));
        drop(engine);
        drop(jobs);
        let engine = Engine::from_store(
            wholepact_store::Store::open_encrypted(&metadata_path, &metadata_key).unwrap(),
        );
        let jobs = ProofJobStore::from_encrypted_connection(
            open_encrypted(&artifact_path, &artifact_key).unwrap(),
        )
        .unwrap();
        let replay = engine
            .run_candidate_proof_locally(
                &access,
                "synthetic-engine-proof-run",
                &candidate_id,
                7,
                LocalProofJob {
                    job_id: &job_id,
                    jobs: &jobs,
                    consent: &gate,
                },
            )
            .unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.operation_id, proven.operation_id);
        assert_eq!(
            replay.agreement.candidates[0].proof_jobs[0].result_digest,
            summary.result_digest
        );
        let denied = SyntheticGate {
            allowed: false,
            ..gate
        };
        assert_eq!(
            engine
                .candidate_proof_status(
                    &access,
                    &candidate_id,
                    LocalProofJob {
                        job_id: &job_id,
                        jobs: &jobs,
                        consent: &denied
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
                .chain_observation,
            "unknown"
        );
        assert_eq!(
            engine
                .get(&access, &agreement.agreement_id)
                .unwrap()
                .authorization_exposure,
            "unknown"
        );
        // Constructor receipt committed, then enqueue permission disappears:
        // exact-key retry must not construct a new randomized artifact.
        let allowed_again = SyntheticGate {
            allowed: true,
            ..denied
        };
        let abort = AbortAtEnqueue {
            inner: &allowed_again,
            retention_checks: AtomicUsize::new(0),
        };
        let revision = engine
            .get(&access, &agreement.agreement_id)
            .unwrap()
            .revision;
        let missing = engine
            .checkpoint_candidate_locally(
                &access,
                "synthetic-aborted-enqueue",
                &candidate_id,
                revision,
                LocalCheckpoint {
                    construction: LocalConstruction {
                        context: chain,
                        contributions: copy_packages(&packages),
                        declarations: &declarations,
                    },
                    jobs: &jobs,
                    limits: ProvingLimits { maximum_actions: 8 },
                    consent: &abort,
                },
            )
            .unwrap_err();
        assert_eq!(missing.code, "DISCLOSURE_DENIED");
        assert_eq!(missing.details["constructor_receipt_created"], true);
        assert_eq!(missing.details["prepared_revision"], revision + 1);
        assert!(
            jobs.status_for_key(
                &access.principal_id,
                "synthetic-aborted-enqueue",
                missing.details["coordination_request_digest"]
                    .as_str()
                    .unwrap(),
                &allowed_again
            )
            .unwrap()
            .is_none()
        );
        let retry = engine
            .checkpoint_candidate_locally(
                &access,
                "synthetic-aborted-enqueue",
                &candidate_id,
                revision,
                LocalCheckpoint {
                    construction: LocalConstruction {
                        context: chain,
                        contributions: copy_packages(&packages),
                        declarations: &declarations,
                    },
                    jobs: &jobs,
                    limits: ProvingLimits { maximum_actions: 8 },
                    consent: &allowed_again,
                },
            )
            .unwrap_err();
        assert_eq!(retry.code, "RECOVERY_REQUIRED");
        assert_eq!(
            engine
                .get(&access, &agreement.agreement_id)
                .unwrap()
                .revision,
            revision + 1
        );
        // A separate deliberate request invokes exact local permission anew.
        let fresh = engine
            .checkpoint_candidate_locally(
                &access,
                "synthetic-fresh-reviewed-key",
                &candidate_id,
                revision + 1,
                LocalCheckpoint {
                    construction: LocalConstruction {
                        context: chain,
                        contributions: copy_packages(&packages),
                        declarations: &declarations,
                    },
                    jobs: &jobs,
                    limits: ProvingLimits { maximum_actions: 8 },
                    consent: &allowed_again,
                },
            )
            .unwrap();
        assert_eq!(fresh.agreement.revision, revision + 3);
        assert_eq!(fresh.agreement.candidates[0].proof_jobs.len(), 2);
        assert_eq!(fresh.agreement.candidates[0].proof_jobs[1].state, "queued");
    }

    #[test]
    fn actual_constructor_receipt_domains_survive_complete_recovery_without_rekey() {
        use std::collections::BTreeMap;
        use wholepact_storage_security::bundle::*;
        let Fixture {
            agreement,
            request,
            chain,
            packages,
            account_ids,
        } = fixture();
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let metadata_path = dir.path().join("metadata.encrypted.sqlite");
        let artifact_path = dir.path().join("artifacts.encrypted.sqlite");
        // Public deterministic test-only keys protect never-funded synthetic data.
        let metadata_key = DatabaseKey::from_bytes([81; 32]);
        let artifact_key = DatabaseKey::from_bytes([82; 32]);
        let engine = Engine::from_store(
            wholepact_store::Store::create_encrypted(&metadata_path, &metadata_key).unwrap(),
        );
        let jobs = ProofJobStore::from_encrypted_connection(
            create_encrypted(&artifact_path, &artifact_key).unwrap(),
        )
        .unwrap();
        let access = Access {
            include_owned_agreements: true,
            principal_id: "synthetic-controller".into(),
            ..Access::default()
        };
        engine
            .create(&access, "synthetic-proof-agreement", agreement.clone())
            .unwrap();
        for (i, p) in request.manifest.participants.iter().enumerate() {
            engine
                .add_intent(
                    &access,
                    &format!("synthetic-proof-intent-{i}"),
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
                "synthetic-proof-candidate",
                &agreement.agreement_id,
                3,
                request,
            )
            .unwrap();
        let candidate = &frozen.agreement.candidates[0];
        let declarations: Vec<_> = account_ids
            .iter()
            .map(|id| DisclosureAcknowledgement {
                account_id: id.clone(),
                manifest_digest: hex::decode(&candidate.manifest_digest)
                    .unwrap()
                    .try_into()
                    .unwrap(),
                operator: "synthetic-local-constructor".into(),
                reviewer_account_ids: account_ids.clone(),
                purpose: "Temporary synthetic proof qualification only".into(),
                retention_policy: "Temporary encrypted test directory only; no distribution".into(),
                scope: DisclosureScope::DedicatedAccountFvkAndSelectedNotesAndOutputs,
            })
            .collect();
        let gate = SyntheticGate {
            candidate_id: candidate.candidate_id.clone(),
            manifest_digest: candidate.manifest_digest.clone(),
            accounts: account_ids.clone(),
            allowed: true,
            race: None,
            raced: AtomicUsize::new(0),
        };
        let checkpoint = |gate, maximum_actions| LocalCheckpoint {
            construction: LocalConstruction {
                context: chain,
                contributions: copy_packages(&packages),
                declarations: &declarations,
            },
            jobs: &jobs,
            limits: ProvingLimits { maximum_actions },
            consent: gate,
        };

        let original_key = "synthetic-recovery-construction-key";
        let result = engine
            .checkpoint_candidate_locally(
                &access,
                original_key,
                &candidate.candidate_id,
                4,
                checkpoint(&gate, 8),
            )
            .unwrap();
        let job_id = result.agreement.candidates[0].proof_jobs[0].job_id.clone();
        assert_eq!(
            job_id,
            wholepact_proof_jobs::job_id_for_key(&access.principal_id, original_key).unwrap()
        );
        drop(engine);
        let store = wholepact_store::Store::open_encrypted(&metadata_path, &metadata_key).unwrap();
        let record = store
            .get_agreement(&agreement.agreement_id)
            .unwrap()
            .unwrap();
        let receipts = record.payload["checkpoint_receipts"].as_object().unwrap();
        assert_eq!(receipts.len(), 1);
        let (receipt_key, receipt) = receipts.iter().next().unwrap();
        assert_ne!(receipt_key, &job_id);
        assert_eq!(receipt["job_id"], job_id);
        assert!(wholepact_engine::candidates::valid_checkpoint_receipt_index(receipt_key, &job_id));
        let before = serde_json::to_vec(&record.payload).unwrap();
        struct BackupGate;
        impl BundleLease for BackupGate {
            fn check_current(&self) -> std::result::Result<(), BundleError> {
                Ok(())
            }
            fn checkpoint_id(&self) -> &str {
                "synthetic-constructor-recovery-quiesced"
            }
        }
        impl BundleAuthority for BackupGate {
            fn acquire<'a>(
                &'a self,
                scope: &BundleScope<'_>,
            ) -> std::result::Result<Box<dyn BundleLease + 'a>, BundleError> {
                if scope.principal_id != "synthetic-admin"
                    || scope.profile_id != "synthetic-profile"
                {
                    return Err(BundleError::Permission);
                }
                Ok(Box::new(BackupGate))
            }
        }
        let coordination = wholepact_store::bundle::CoordinationBundleAdapter::new(&store).unwrap();
        let proof = wholepact_proof_jobs::backup::ProofWitnessBackupAdapter::new(&jobs);
        let sources = [
            RegisteredJournal::new("coordination", &coordination).unwrap(),
            RegisteredJournal::new("proof", &proof).unwrap(),
        ];
        let archive = dir.path().join("recovery-archive");
        snapshot(SnapshotRequest {
            principal_id: "synthetic-admin",
            profile_id: "synthetic-profile",
            sources: &sources,
            destination: &archive,
            key: &metadata_key,
            authority: &BackupGate,
            coverage: Coverage {
                present: BTreeMap::from([
                    (
                        JournalKind::CoordinationAuthority,
                        vec!["coordination".into()],
                    ),
                    (JournalKind::ProofWitness, vec!["proof".into()]),
                ]),
                absent: [
                    JournalKind::SignerConsentAuthority,
                    JournalKind::WalletScan,
                    JournalKind::SignedResults,
                    JournalKind::ExactTransactions,
                    JournalKind::Submission,
                    JournalKind::TransportInbox,
                    JournalKind::TransportOutbox,
                ]
                .into(),
            },
        })
        .unwrap();
        let restored_coordination = dir.path().join("restored-coordination");
        let restored_proof = dir.path().join("restored-proof");
        test_restore(RestoreRequest {
            principal_id: "synthetic-admin",
            profile_id: "synthetic-profile",
            archive: &archive,
            key: &metadata_key,
            targets: &[
                RestoreTarget {
                    component_id: "coordination",
                    template: coordination.template(),
                    destination: &restored_coordination,
                    key: &metadata_key,
                },
                RestoreTarget {
                    component_id: "proof",
                    template: proof.template(),
                    destination: &restored_proof,
                    key: &artifact_key,
                },
            ],
            authority: &BackupGate,
        })
        .unwrap();
        let source = recovery::VerifiedRecoveryComponent::open(
            history::HistoryOpenRequest {
                archive: &archive,
                archive_key: &metadata_key,
                component_id: "coordination",
                restored_component: &restored_coordination,
                restored_key: &metadata_key,
            },
            coordination.template(),
        )
        .unwrap();
        let inventory = wholepact_engine::recovery::inspect_coordination_recovery(&source).unwrap();
        assert!(
            inventory
                .attempts()
                .iter()
                .any(|attempt| attempt.job_id.as_deref() == Some(job_id.as_str()))
        );
        let saved = inventory
            .store_inventory()
            .agreements()
            .iter()
            .find(|value| value.id == agreement.agreement_id)
            .unwrap();
        assert_eq!(serde_json::to_vec(&saved.payload).unwrap(), before);
        assert!(
            saved.payload["checkpoint_receipts"]
                .get(receipt_key)
                .is_some()
        );
        assert!(saved.payload["checkpoint_receipts"].get(&job_id).is_none());
        assert_eq!(
            serde_json::to_vec(
                &store
                    .get_agreement(&agreement.agreement_id)
                    .unwrap()
                    .unwrap()
                    .payload
            )
            .unwrap(),
            before
        );
        assert!(
            wholepact_store::Store::open_encrypted(&restored_coordination, &metadata_key).is_err()
        );
    }
}
