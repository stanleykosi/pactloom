//! Source-only synthetic constructor/retention qualification. No proof run or native approval.
use super::*;
use crate::candidates::LocalConstruction;
use crate::{Access, CandidateRequest, Engine};
use wholepact_core::*;
use wholepact_protocol::{construction::*, review::encode_testnet_receiver};
use wholepact_wallet::wallet::synthetic_scanned_contributions;

fn amount(n: u64) -> Amount {
    Amount::from_zatoshis(n).unwrap()
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

use crate::proof_jobs::{LocalCheckpoint, LocalProofJob};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use wholepact_proof_jobs::{CheckpointScope, LocalAction, LocalProofConsent, ProofJobStore};
use wholepact_protocol::proving::ProvingLimits;
use wholepact_storage_security::{DatabaseKey, create_encrypted};

// Test-only permission for never-funded synthetic data. This gate explicitly
// excludes ProveLocally, recovery, and ReadPrivateArtifact; no native UI is invoked.
struct SyntheticInspectGate {
    candidate: String,
    manifest: String,
    accounts: Vec<String>,
    allowed: AtomicBool,
    race: Option<(Engine, Access, String)>,
    checks: AtomicUsize,
}
impl LocalProofConsent for SyntheticInspectGate {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        let valid = self.allowed.load(Ordering::SeqCst)
            && scope.principal_id == "synthetic-controller"
            && scope.candidate_id == self.candidate
            && scope.manifest_digest == self.manifest
            && scope.account_ids == self.accounts
            && scope.local_operator == "synthetic-local-constructor"
            && scope.purpose == "Synthetic request reconciliation qualification"
            && scope.retention_policy == "Encrypted temporary directory only"
            && matches!(
                action,
                LocalAction::RetainPrivateWitnesses | LocalAction::InspectStatus
            );
        if valid
            && action == LocalAction::RetainPrivateWitnesses
            && self.checks.fetch_add(1, Ordering::SeqCst) == 1
        {
            if let Some((engine, access, id)) = &self.race {
                engine
                    .propose(
                        access,
                        "synthetic-constructor-race",
                        id,
                        engine.get(access, id).unwrap().revision,
                    )
                    .unwrap();
            }
        }
        valid
    }
}
struct Constructed {
    dir: tempfile::TempDir,
    engine: Engine,
    jobs: ProofJobStore,
    access: Access,
    gate: SyntheticInspectGate,
    agreement: String,
    candidate: String,
    job: String,
}
impl Constructed {
    fn revision(&self) -> u64 {
        self.engine
            .get(&self.access, &self.agreement)
            .unwrap()
            .revision
    }
    fn queue(&self, key: &str) -> NativeProofExecutionRequestView {
        self.engine
            .queue_native_proof_execution(
                &self.access,
                key,
                &self.agreement,
                self.revision(),
                NativeProofExecutionRequest {
                    candidate_id: self.candidate.clone(),
                    job_id: self.job.clone(),
                },
            )
            .unwrap()
    }
    fn status(&self, request: &str) -> NativeProofExecutionRequestView {
        self.engine
            .native_proof_execution_request(&self.access, &self.agreement, request)
            .unwrap()
    }
    fn mark(&self, request: &str) -> NativeProofExecutionAttempt {
        self.engine
            .mark_native_proof_execution_attempt(&self.access, &self.agreement, request)
            .unwrap()
    }
    fn reconcile(&self, attempt: &NativeProofExecutionAttempt) -> crate::Result<Mutation> {
        self.engine.reconcile_candidate_proof_job(
            &self.access,
            "synthetic-distinct-metadata-reconciliation",
            attempt.candidate_id(),
            attempt.revision(),
            LocalProofJob {
                job_id: attempt.job_id(),
                jobs: &self.jobs,
                consent: &self.gate,
            },
        )
    }
    fn restart(&mut self) {
        self.engine = Engine::in_memory().unwrap();
        self.engine = Engine::from_store(
            Store::open_encrypted(
                self.dir.path().join("metadata.sqlite"),
                &DatabaseKey::from_bytes([81; 32]),
            )
            .unwrap(),
        );
    }
}
fn constructed(missing_link: bool) -> Constructed {
    constructed_named(missing_link, false).0
}
fn constructed_named(missing_link: bool, native: bool) -> (Constructed, Option<String>) {
    use std::os::unix::fs::PermissionsExt;
    let Fixture {
        agreement,
        request,
        chain,
        packages,
        account_ids,
    } = fixture();
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let engine = Engine::from_store(
        Store::create_encrypted(
            dir.path().join("metadata.sqlite"),
            &DatabaseKey::from_bytes([81; 32]),
        )
        .unwrap(),
    );
    let jobs = ProofJobStore::from_encrypted_connection(
        create_encrypted(
            dir.path().join("proof.sqlite"),
            &DatabaseKey::from_bytes([82; 32]),
        )
        .unwrap(),
    )
    .unwrap();
    let access = Access {
        principal_id: "synthetic-controller".into(),
        include_owned_agreements: true,
        ..Access::default()
    };
    engine
        .create(
            &access,
            "synthetic-proof-request-agreement",
            agreement.clone(),
        )
        .unwrap();
    for (i, p) in request.manifest.participants.iter().enumerate() {
        engine
            .add_intent(
                &access,
                &format!("synthetic-proof-request-intent-{i}"),
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
            "synthetic-proof-request-candidate",
            &agreement.agreement_id,
            3,
            request,
        )
        .unwrap();
    let candidate = &frozen.agreement.candidates[0];
    let (construction_key, construction_revision, native_request) = if native {
        let queued = engine
            .queue_native_construction(
                &access,
                "synthetic-original-native-request",
                &agreement.agreement_id,
                frozen.agreement.revision,
                crate::native_requests::NativeConstructionRequest {
                    candidate_id: candidate.candidate_id.clone(),
                },
            )
            .unwrap();
        let attempt = engine
            .mark_native_construction_attempt(&access, &agreement.agreement_id, &queued.request_id)
            .unwrap();
        (
            attempt.construction_key().to_owned(),
            attempt.revision(),
            Some(queued.request_id),
        )
    } else {
        (
            "synthetic-proof-request-original-construction".to_owned(),
            frozen.agreement.revision,
            None,
        )
    };

    let declarations: Vec<_> = account_ids
        .iter()
        .map(|account| DisclosureAcknowledgement {
            account_id: account.clone(),
            manifest_digest: hex::decode(&candidate.manifest_digest)
                .unwrap()
                .try_into()
                .unwrap(),
            operator: "synthetic-local-constructor".into(),
            reviewer_account_ids: account_ids.clone(),
            purpose: "Synthetic request reconciliation qualification".into(),
            retention_policy: "Encrypted temporary directory only".into(),
            scope: DisclosureScope::DedicatedAccountFvkAndSelectedNotesAndOutputs,
        })
        .collect();
    let mut gate = SyntheticInspectGate {
        candidate: candidate.candidate_id.clone(),
        manifest: candidate.manifest_digest.clone(),
        accounts: account_ids,
        allowed: AtomicBool::new(true),
        checks: AtomicUsize::new(0),
        race: missing_link.then(|| {
            (
                engine.clone(),
                access.clone(),
                agreement.agreement_id.clone(),
            )
        }),
    };
    let result = engine.checkpoint_candidate_locally(
        &access,
        &construction_key,
        &candidate.candidate_id,
        construction_revision,
        LocalCheckpoint {
            construction: LocalConstruction {
                context: chain,
                contributions: packages,
                declarations: &declarations,
            },
            jobs: &jobs,
            limits: ProvingLimits { maximum_actions: 8 },
            consent: &gate,
        },
    );
    if missing_link {
        let error = result.unwrap_err();
        assert_eq!(error.code, "REVISION_CONFLICT");
        assert_eq!(error.details["encrypted_checkpoint_created"], true);
        assert!(
            engine
                .get(&access, &agreement.agreement_id)
                .unwrap()
                .candidates[0]
                .proof_jobs
                .is_empty()
        );
    } else {
        assert_eq!(result.unwrap().agreement.candidates[0].proof_jobs.len(), 1);
    }
    gate.race = None;
    let job =
        wholepact_proof_jobs::job_id_for_key(&access.principal_id, &construction_key).unwrap();
    (
        Constructed {
            dir,
            engine,
            jobs,
            access,
            gate,
            agreement: agreement.agreement_id,
            candidate: candidate.candidate_id.clone(),
            job,
        },
        native_request,
    )
}

#[test]
fn actual_checkpoint_execution_fence_survives_restart_and_never_infers_success() {
    let mut f = constructed(false);
    let q = f.queue("execution-original");
    assert_ne!(q.job_id, q.receipt_storage_key);
    let a = f.mark(&q.request_id);
    assert_eq!(a.execution_key(), q.execution_key());
    assert_eq!(a.receipt_digest(), q.receipt_digest);
    f.restart();
    assert_eq!(f.status(&q.request_id).execution_status, "unknown");
    assert!(
        f.engine
            .mark_native_proof_execution_attempt(&f.access, &f.agreement, &q.request_id)
            .is_err()
    );
    assert!(
        f.engine
            .withdraw_native_proof_execution_request(
                &f.access,
                "withdraw-started",
                &f.agreement,
                f.revision(),
                &q.request_id
            )
            .is_err()
    );
    // Metadata reconciliation is a different durable operation and does not prove execution.
    f.reconcile(&a).unwrap();
    assert_eq!(f.status(&q.request_id).execution_status, "unknown");
    assert!(
        f.engine
            .queue_native_proof_execution(
                &f.access,
                "synthetic-replacement-request",
                &f.agreement,
                f.revision(),
                NativeProofExecutionRequest {
                    candidate_id: f.candidate.clone(),
                    job_id: f.job.clone()
                }
            )
            .is_err()
    );
}
#[test]
fn queued_execution_withdrawal_is_durable_and_does_not_touch_private_job() {
    let mut f = constructed(false);
    let before = f
        .jobs
        .status(&f.access.principal_id, &f.job, &f.gate)
        .unwrap();
    let q = f.queue("withdraw-before-start");
    let withdrawn = f
        .engine
        .withdraw_native_proof_execution_request(
            &f.access,
            "synthetic-withdraw-queued",
            &f.agreement,
            f.revision(),
            &q.request_id,
        )
        .unwrap();
    assert_eq!(withdrawn.state, NativeRequestState::Withdrawn);
    f.restart();
    assert_eq!(f.status(&q.request_id).state, NativeRequestState::Withdrawn);
    let after = f
        .jobs
        .status(&f.access.principal_id, &f.job, &f.gate)
        .unwrap();
    assert_eq!(
        serde_json::to_value(before).unwrap(),
        serde_json::to_value(after).unwrap()
    );
    assert!(
        f.engine
            .mark_native_proof_execution_attempt(&f.access, &f.agreement, &q.request_id)
            .is_err()
    );
}

#[test]
fn execution_request_backup_preserves_receipt_and_historical_requests_without_activation() {
    use std::collections::BTreeMap;
    use wholepact_storage_security::bundle::*;
    struct BackupGate;
    impl BundleLease for BackupGate {
        fn check_current(&self) -> std::result::Result<(), BundleError> {
            Ok(())
        }
        fn checkpoint_id(&self) -> &str {
            "synthetic-stopped-request-writer"
        }
    }
    impl BundleAuthority for BackupGate {
        fn acquire<'a>(
            &'a self,
            scope: &BundleScope<'_>,
        ) -> std::result::Result<Box<dyn BundleLease + 'a>, BundleError> {
            if scope.principal_id != "synthetic-admin" || scope.profile_id != "synthetic-profile" {
                return Err(BundleError::Permission);
            }
            Ok(Box::new(BackupGate))
        }
    }
    let f = constructed(false);
    let queued = f.queue("synthetic-backup-proof-request");
    let attempt = f.mark(&queued.request_id);
    f.reconcile(&attempt).unwrap();
    let before = f.engine.store.get_agreement(&f.agreement).unwrap().unwrap();
    let adapter = wholepact_store::bundle::CoordinationBundleAdapter::new(&f.engine.store).unwrap();
    let sources = [RegisteredJournal::new("coordination", &adapter).unwrap()];
    let archive = f.dir.path().join("archive");
    let key = DatabaseKey::from_bytes([81; 32]);
    snapshot(SnapshotRequest {
        principal_id: "synthetic-admin",
        profile_id: "synthetic-profile",
        sources: &sources,
        destination: &archive,
        key: &key,
        authority: &BackupGate,
        coverage: Coverage {
            present: BTreeMap::from([(
                JournalKind::CoordinationAuthority,
                vec!["coordination".into()],
            )]),
            absent: [
                JournalKind::SignerConsentAuthority,
                JournalKind::WalletScan,
                JournalKind::ProofWitness,
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
    let restored = f.dir.path().join("restored");
    test_restore(RestoreRequest {
        principal_id: "synthetic-admin",
        profile_id: "synthetic-profile",
        archive: &archive,
        key: &key,
        targets: &[RestoreTarget {
            component_id: "coordination",
            template: wholepact_store::bundle::coordination_template(),
            destination: &restored,
            key: &key,
        }],
        authority: &BackupGate,
    })
    .unwrap();
    assert!(Store::open_encrypted(&restored, &key).is_err());
    let source = wholepact_storage_security::bundle::recovery::VerifiedRecoveryComponent::open(
        wholepact_storage_security::bundle::history::HistoryOpenRequest {
            archive: &archive,
            archive_key: &key,
            component_id: "coordination",
            restored_component: &restored,
            restored_key: &key,
        },
        wholepact_store::bundle::coordination_template(),
    )
    .unwrap();
    let inventory = crate::recovery::inspect_coordination_recovery(&source).unwrap();
    let latest = inventory
        .store_inventory()
        .agreements()
        .iter()
        .find(|record| record.id == f.agreement)
        .unwrap();
    assert_eq!(
        latest.payload["checkpoint_receipts"],
        before.payload["checkpoint_receipts"]
    );
    assert_eq!(
        latest.payload["native_proof_execution_requests"],
        before.payload["native_proof_execution_requests"]
    );
    assert!(
        inventory
            .store_inventory()
            .historical_agreements()
            .iter()
            .any(
                |record| record.payload["native_proof_execution_requests"][&queued.request_id]["state"]
                    == "queued"
            )
    );
    assert_eq!(f.status(&queued.request_id).execution_status, "unknown");
    assert!(
        f.status(&queued.request_id)
            .execution_operation_id
            .is_none()
    );
    assert!(Store::open_encrypted(&restored, &key).is_err());
}
