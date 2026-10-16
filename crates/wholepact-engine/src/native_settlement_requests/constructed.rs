//! Source-only synthetic constructor/retention qualification. No proof run or native approval.
use super::*;
use crate::candidates::LocalConstruction;
use crate::native_artifact_handoff_requests::*;
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
    fn queue(&self, key: &str) -> NativeArtifactHandoffRequestView {
        self.engine
            .queue_native_artifact_handoff(
                &self.access,
                key,
                &self.agreement,
                self.revision(),
                NativeArtifactHandoffRequest {
                    kind: ArtifactHandoffKind::SignerReview,
                    candidate_id: self.candidate.clone(),
                    job_id: self.job.clone(),
                },
            )
            .unwrap()
    }
    fn mark(&self, request: &str) -> NativeArtifactHandoffAttempt {
        self.engine
            .mark_native_artifact_handoff_attempt(&self.access, &self.agreement, request)
            .unwrap()
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

// Deliberately modeled cache only. No proof is produced; private journal remains
// Prepared. This tests inert request persistence, never native proof authority.
fn model_cache_claim(f: &Constructed) {
    let mut envelope = f.engine.load(&f.access, &f.agreement).unwrap();
    let revision = envelope.view.revision;
    let job = &mut envelope.view.candidates[0].proof_jobs[0];
    job.state = "succeeded".into();
    job.proof_verified = true;
    job.result_digest = Some("ab".repeat(32));
    let command = context(
        &f.access,
        "synthetic-modeled-cache-only",
        "synthetic_modeled_cache_only",
        &f.agreement,
        Some(revision),
        &json!({"modeled":true}),
    )
    .unwrap();
    f.engine
        .commit(
            &command,
            &f.agreement,
            revision,
            envelope,
            "synthetic_modeled_cache_only",
        )
        .unwrap();
}

fn started_intake(f: &Constructed) -> String {
    model_cache_claim(f);
    let view = f
        .engine
        .queue_native_artifact_handoff(
            &f.access,
            "synthetic-settlement-intake",
            &f.agreement,
            f.revision(),
            NativeArtifactHandoffRequest {
                kind: ArtifactHandoffKind::SignatureIntake,
                candidate_id: f.candidate.clone(),
                job_id: f.job.clone(),
            },
        )
        .unwrap();
    f.mark(&view.request_id);
    view.request_id
}
fn queue(
    f: &Constructed,
    intake: &str,
    kind: SettlementRequestKind,
    key: &str,
) -> NativeSettlementRequestView {
    f.engine
        .queue_native_settlement(
            &f.access,
            key,
            &f.agreement,
            f.revision(),
            NativeSettlementRequest {
                intake_request_id: intake.into(),
                kind,
            },
        )
        .unwrap()
}
#[test]
fn reconciliation_preserves_original_intake_identity_and_restart_unknown() {
    let mut f = constructed(false);
    let intake = started_intake(&f);
    let queued = queue(
        &f,
        &intake,
        SettlementRequestKind::SignatureReconcile,
        "synthetic-signature-reconcile",
    );
    assert_eq!(
        queued.source.signature_retention_key,
        format!("native-artifact-handoff-{intake}")
    );
    let attempt = f
        .engine
        .mark_native_settlement_attempt(&f.access, &f.agreement, &queued.request_id)
        .unwrap();
    assert_eq!(attempt.source(), &queued.source);
    f.restart();
    let view = f
        .engine
        .native_settlement_request(&f.access, &f.agreement, &queued.request_id)
        .unwrap();
    assert_eq!(view.outcome_status, "attempted_outcome_unknown");
    assert!(view.observation.is_none());
    assert!(
        f.engine
            .mark_native_settlement_attempt(&f.access, &f.agreement, &queued.request_id)
            .is_err()
    );
    assert!(
        f.engine
            .withdraw_native_settlement_request(
                &f.access,
                "synthetic-settlement-withdraw",
                &f.agreement,
                f.revision(),
                &queued.request_id
            )
            .is_err()
    );
    let inspection = f
        .engine
        .native_settlement_inspection(&f.access, &f.agreement, &queued.request_id)
        .unwrap();
    assert_eq!(inspection.source(), &queued.source);
    assert!(
        f.engine
            .queue_native_settlement(
                &f.access,
                "synthetic-replacement-reconcile",
                &f.agreement,
                f.revision(),
                NativeSettlementRequest {
                    intake_request_id: intake,
                    kind: SettlementRequestKind::SignatureReconcile
                }
            )
            .is_err()
    );
}
#[test]
fn review_request_cannot_supply_intake_and_missing_signed_observation_blocks_checkpoint() {
    let f = constructed(false);
    model_cache_claim(&f);
    let review = f.queue("synthetic-review-source");
    f.mark(&review.request_id);
    assert!(
        f.engine
            .queue_native_settlement(
                &f.access,
                "synthetic-wrong-source",
                &f.agreement,
                f.revision(),
                NativeSettlementRequest {
                    intake_request_id: review.request_id,
                    kind: SettlementRequestKind::SignatureReconcile
                }
            )
            .is_err()
    );
    let intake = f
        .engine
        .queue_native_artifact_handoff(
            &f.access,
            "synthetic-right-intake",
            &f.agreement,
            f.revision(),
            NativeArtifactHandoffRequest {
                kind: ArtifactHandoffKind::SignatureIntake,
                candidate_id: f.candidate.clone(),
                job_id: f.job.clone(),
            },
        )
        .unwrap();
    f.mark(&intake.request_id);
    assert!(
        f.engine
            .queue_native_settlement(
                &f.access,
                "synthetic-no-signed-observation",
                &f.agreement,
                f.revision(),
                NativeSettlementRequest {
                    intake_request_id: intake.request_id,
                    kind: SettlementRequestKind::TransactionCheckpoint
                }
            )
            .is_err()
    );
}
#[test]
fn queued_settlement_withdrawal_and_original_source_tampering_fail_closed() {
    let f = constructed(false);
    let intake = started_intake(&f);
    let queued = queue(
        &f,
        &intake,
        SettlementRequestKind::SignatureReconcile,
        "synthetic-withdrawable-reconcile",
    );
    let mut envelope = f.engine.load(&f.access, &f.agreement).unwrap();
    envelope
        .native_settlement_requests
        .get_mut(&queued.request_id)
        .unwrap()
        .source
        .signature_retention_key = "replacement-key".into();
    assert!(crate::native_settlement_requests::validate_stored(&envelope).is_err());
    let result = f
        .engine
        .withdraw_native_settlement_request(
            &f.access,
            "synthetic-settlement-withdraw",
            &f.agreement,
            f.revision(),
            &queued.request_id,
        )
        .unwrap();
    assert_eq!(result.state, NativeRequestState::Withdrawn);
    assert!(
        f.engine
            .native_settlement_inspection(&f.access, &f.agreement, &queued.request_id)
            .is_err()
    );
}
// Model only coordination metadata; no signatures or native approvals are made.
// Actual private proof/signed journals remain empty/unproved and must refuse use.
fn model_signed_observation(f: &Constructed, request: &str) {
    let mut envelope = f.engine.load(&f.access, &f.agreement).unwrap();
    let revision = envelope.view.revision;
    envelope
        .native_settlement_requests
        .get_mut(request)
        .unwrap()
        .observation = Some(SettlementObservation::Signed {
        evidence: SignedObservation {
            result_id: format!("signed-{}", "31".repeat(32)),
            request_digest: "32".repeat(32),
            signed_candidate_digest: "33".repeat(32),
            signatures_complete: true,
        },
    });
    let command = context(
        &f.access,
        "synthetic-modeled-signed-cache",
        "synthetic_modeled_signed_cache_only",
        &f.agreement,
        Some(revision),
        &json!({"modeled":true}),
    )
    .unwrap();
    f.engine
        .commit(
            &command,
            &f.agreement,
            revision,
            envelope,
            "synthetic_modeled_signed_cache_only",
        )
        .unwrap();
}
#[test]
fn modeled_signed_metadata_cannot_authorize_actual_checkpoint_or_reset_inspection() {
    use wholepact_protocol::authorization::retention::{
        SignedResultJournal, SignedRetentionConsent, SignedRetentionScope,
        transaction::{
            LocalTransactionCheckpoint, TransactionCheckpointJournal, TransactionRetentionConsent,
            TransactionRetentionScope,
        },
    };
    struct Deny;
    impl SignedRetentionConsent for Deny {
        fn permits(&self, _: &SignedRetentionScope) -> bool {
            false
        }
    }
    impl TransactionRetentionConsent for Deny {
        fn permits(&self, _: &TransactionRetentionScope) -> bool {
            false
        }
    }
    let f = constructed(false);
    let intake = started_intake(&f);
    let reconcile = queue(
        &f,
        &intake,
        SettlementRequestKind::SignatureReconcile,
        "synthetic-signed-metadata-reconcile",
    );
    f.engine
        .mark_native_settlement_attempt(&f.access, &f.agreement, &reconcile.request_id)
        .unwrap();
    model_signed_observation(&f, &reconcile.request_id);
    let request = queue(
        &f,
        &intake,
        SettlementRequestKind::TransactionCheckpoint,
        "synthetic-exact-checkpoint-request",
    );
    let attempt = f
        .engine
        .mark_native_settlement_attempt(&f.access, &f.agreement, &request.request_id)
        .unwrap();
    let signed = SignedResultJournal::from_encrypted_connection(
        create_encrypted(
            f.dir.path().join("signed-empty.sqlite"),
            &DatabaseKey::from_bytes([83; 32]),
        )
        .unwrap(),
    )
    .unwrap();
    let transactions = TransactionCheckpointJournal::from_encrypted_connection(
        create_encrypted(
            f.dir.path().join("transaction-empty.sqlite"),
            &DatabaseKey::from_bytes([84; 32]),
        )
        .unwrap(),
    )
    .unwrap();
    let result = f.engine.checkpoint_native_settlement_transaction(
        &f.access,
        attempt,
        LocalProofJob {
            job_id: &f.job,
            jobs: &f.jobs,
            consent: &f.gate,
        },
        crate::signature_intake::LocalSignedRetention {
            journal: &signed,
            consent: &Deny,
        },
        LocalTransactionCheckpoint {
            journal: &transactions,
            consent: &Deny,
        },
        &[],
        &wholepact_transport::Timestamp::from_unix_seconds(1_800_000_000).unwrap(),
    );
    assert!(result.is_err());
    let view = f
        .engine
        .native_settlement_request(&f.access, &f.agreement, &request.request_id)
        .unwrap();
    assert!(view.observation.is_none());
    assert_eq!(view.outcome_status, "attempted_outcome_unknown");
    assert!(
        f.engine
            .mark_native_settlement_attempt(&f.access, &f.agreement, &request.request_id)
            .is_err()
    );
    assert_eq!(
        f.engine
            .native_settlement_inspection(&f.access, &f.agreement, &request.request_id)
            .unwrap()
            .kind(),
        SettlementRequestKind::TransactionCheckpoint
    );
}
#[test]
fn settlement_backup_preserves_original_intake_chain_and_unknown_without_activation() {
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
    let intake = started_intake(&f);
    let queued = queue(
        &f,
        &intake,
        SettlementRequestKind::SignatureReconcile,
        "synthetic-backup-settlement-request",
    );
    let _attempt = f
        .engine
        .mark_native_settlement_attempt(&f.access, &f.agreement, &queued.request_id)
        .unwrap();
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
        latest.payload["native_settlement_requests"],
        before.payload["native_settlement_requests"]
    );
    assert!(
        inventory
            .store_inventory()
            .historical_agreements()
            .iter()
            .any(
                |record| record.payload["native_settlement_requests"][&queued.request_id]["state"]
                    == "queued"
            )
    );
    assert_eq!(
        f.engine
            .native_settlement_request(&f.access, &f.agreement, &queued.request_id)
            .unwrap()
            .outcome_status,
        "attempted_outcome_unknown"
    );
    assert!(Store::open_encrypted(&restored, &key).is_err());
}

#[cfg(feature = "submission-handoff")]
mod dispatch_handoff {
    //! Real scanner/constructor/checkpoint provenance, modeled coordination result
    //! metadata only. No prover, signature, transaction extraction, packet, genuine
    //! native approval or positive VerifiedCandidateSubmission is manufactured.
    use super::*;
    use crate::native_dispatch_requests::{self, NativeDispatchRequest};
    use crate::native_requests::{NativeConstructionRequest, NativeRequestState};
    use wholepact_chain::EncryptedSubmissionJournal;

    fn completed_metadata() -> (Constructed, String) {
        let f = constructed(false);
        let intake = started_intake(&f);
        let reconcile = queue(
            &f,
            &intake,
            SettlementRequestKind::SignatureReconcile,
            "synthetic-dispatch-signature-metadata",
        );
        f.engine
            .mark_native_settlement_attempt(&f.access, &f.agreement, &reconcile.request_id)
            .unwrap();
        model_signed_observation(&f, &reconcile.request_id);
        let tx = queue(
            &f,
            &intake,
            SettlementRequestKind::TransactionCheckpoint,
            "synthetic-dispatch-transaction-metadata",
        );
        f.engine
            .mark_native_settlement_attempt(&f.access, &f.agreement, &tx.request_id)
            .unwrap();
        let mut e = f.engine.load(&f.access, &f.agreement).unwrap();
        let revision = e.view.revision;
        let row = e
            .native_settlement_requests
            .get_mut(&tx.request_id)
            .unwrap();
        row.observation = Some(SettlementObservation::Transaction {
            signed: row.expected_signed.clone().unwrap(),
            checkpoint_id: format!("transaction-{}", "41".repeat(32)),
            transaction_digest: "42".repeat(32),
            txid: "43".repeat(32),
        });
        let command = context(
            &f.access,
            "synthetic-dispatch-modeled-transaction-cache",
            "synthetic_dispatch_modeled_transaction_cache",
            &f.agreement,
            Some(revision),
            &json!({"modeled":true}),
        )
        .unwrap();
        f.engine
            .commit(
                &command,
                &f.agreement,
                revision,
                e,
                "synthetic_dispatch_modeled_transaction_cache",
            )
            .unwrap();
        (f, tx.request_id)
    }
    fn request(
        f: &Constructed,
        tx: &str,
        key: &str,
    ) -> crate::Result<native_dispatch_requests::NativeDispatchRequestView> {
        f.engine.queue_native_dispatch(
            &f.access,
            key,
            &f.agreement,
            f.revision(),
            NativeDispatchRequest {
                transaction_request_id: tx.into(),
            },
        )
    }
    fn journal(f: &Constructed, name: &str, key: u8) -> EncryptedSubmissionJournal {
        EncryptedSubmissionJournal::from_encrypted_connection(
            create_encrypted(f.dir.path().join(name), &DatabaseKey::from_bytes([key; 32])).unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn dispatch_request_reconstructs_originals_and_fences_across_restart() {
        let (mut f, tx) = completed_metadata();
        let original_revision = f.revision();
        let queued = request(&f, &tx, "synthetic-original-dispatch-request").unwrap();
        assert_eq!(
            queued.operation_id,
            format!("native-dispatch-{}", queued.request_id)
        );
        assert_eq!(queued.source.transaction_request_id, tx);
        assert_eq!(queued.source.original.candidate_id, f.candidate);
        assert_eq!(queued.source.original.job_id, f.job);
        assert!(!queued.authorization_allowed);
        assert!(queued.submission_journal_identity.is_none());
        let replay = f
            .engine
            .queue_native_dispatch(
                &f.access,
                "synthetic-original-dispatch-request",
                &f.agreement,
                original_revision,
                NativeDispatchRequest {
                    transaction_request_id: tx.clone(),
                },
            )
            .unwrap();
        assert_eq!(replay.request_id, queued.request_id);
        assert!(request(&f, &tx, "synthetic-replacement-dispatch-request").is_err());
        let actual = journal(&f, "dispatch-empty.sqlite", 91);
        let identity = actual.identity().to_owned();
        let attempt = f
            .engine
            .mark_native_dispatch_attempt(&f.access, &f.agreement, &queued.request_id, &identity)
            .unwrap();
        assert_eq!(attempt.source(), &queued.source);
        assert_eq!(attempt.operation_id(), queued.operation_id);
        assert_eq!(attempt.submission_journal_identity(), identity);
        assert_eq!(attempt.revision(), f.revision());
        let inspection = attempt.into_inspection();
        assert_eq!(inspection.operation_id(), queued.operation_id);
        f.restart();
        let restored = f
            .engine
            .native_dispatch_request(&f.access, &f.agreement, &queued.request_id)
            .unwrap();
        assert_eq!(
            restored.submission_journal_identity.as_deref(),
            Some(identity.as_str())
        );
        assert_eq!(restored.outcome_status, "attempted_outcome_unknown");
        assert!(restored.observations.is_empty());
        assert!(
            f.engine
                .mark_native_dispatch_attempt(
                    &f.access,
                    &f.agreement,
                    &queued.request_id,
                    &identity
                )
                .is_err()
        );
        assert!(
            f.engine
                .withdraw_native_dispatch_request(
                    &f.access,
                    "synthetic-dispatch-withdraw-started",
                    &f.agreement,
                    f.revision(),
                    &queued.request_id
                )
                .is_err()
        );
        assert!(
            f.engine
                .native_dispatch_inspection(&f.access, &f.agreement, &queued.request_id)
                .is_ok()
        );
        let foreign = Access {
            principal_id: "other-controller".into(),
            all_agreements: true,
            ..Access::default()
        };
        assert!(
            f.engine
                .native_dispatch_request(&foreign, &f.agreement, &queued.request_id)
                .is_err()
        );
        assert!(
            f.engine
                .native_dispatch_requests(&foreign, &f.agreement)
                .unwrap()
                .is_empty()
        );
    }
    #[test]
    fn never_started_withdrawal_preserves_history_and_allows_fresh_request() {
        let (f, tx) = completed_metadata();
        let queued = request(&f, &tx, "synthetic-withdrawable-dispatch-request").unwrap();
        let withdrawn = f
            .engine
            .withdraw_native_dispatch_request(
                &f.access,
                "synthetic-withdraw-dispatch-request",
                &f.agreement,
                f.revision(),
                &queued.request_id,
            )
            .unwrap();
        assert_eq!(withdrawn.state, NativeRequestState::Withdrawn);
        let replacement = request(&f, &tx, "synthetic-requeue-withdrawn-dispatch").unwrap();
        assert_ne!(replacement.request_id, queued.request_id);
        assert_ne!(replacement.operation_id, queued.operation_id);
        assert_eq!(replacement.source, queued.source);
        assert_eq!(
            f.engine
                .native_dispatch_requests(&f.access, &f.agreement)
                .unwrap()
                .len(),
            2
        );
        assert!(
            f.engine
                .mark_native_dispatch_attempt(
                    &f.access,
                    &f.agreement,
                    &queued.request_id,
                    &"ab".repeat(32)
                )
                .is_err()
        );
        assert!(
            f.engine
                .native_dispatch_inspection(&f.access, &f.agreement, &queued.request_id)
                .is_err()
        );
    }
    #[test]
    fn changed_revision_cannot_issue_a_dispatch_attempt() {
        let (f, tx) = completed_metadata();
        let queued = request(&f, &tx, "synthetic-stale-dispatch-request").unwrap();
        f.engine
            .propose(
                &f.access,
                "synthetic-dispatch-advance-revision",
                &f.agreement,
                f.revision(),
            )
            .unwrap();
        assert_eq!(
            f.engine
                .mark_native_dispatch_attempt(
                    &f.access,
                    &f.agreement,
                    &queued.request_id,
                    &"ab".repeat(32)
                )
                .err()
                .unwrap()
                .code,
            "REVISION_CONFLICT"
        );
    }
    #[test]
    fn actual_empty_journal_reader_records_unknown_without_reset_and_wrong_journal_is_rejected() {
        let (f, tx) = completed_metadata();
        let queued = request(&f, &tx, "synthetic-empty-journal-dispatch-request").unwrap();
        let actual = journal(&f, "dispatch-status.sqlite", 92);
        let other = journal(&f, "dispatch-wrong.sqlite", 93);
        let attempt = f
            .engine
            .mark_native_dispatch_attempt(
                &f.access,
                &f.agreement,
                &queued.request_id,
                actual.identity(),
            )
            .unwrap();
        let wrong = f
            .engine
            .native_dispatch_inspection(&f.access, &f.agreement, &queued.request_id)
            .unwrap();
        assert!(
            f.engine
                .inspect_native_dispatch_status(&f.access, wrong, &other)
                .is_err()
        );
        let observed = f
            .engine
            .inspect_native_dispatch_status(&f.access, attempt.into_inspection(), &actual)
            .unwrap();
        assert_eq!(observed.observations.len(), 1);
        assert!(observed.observations[0].intent.is_none());
        assert!(observed.observations[0].descriptor.is_none());
        assert!(observed.observations[0].attempts.is_empty());
        assert_eq!(observed.outcome_status, "attempted_outcome_unknown");
        assert!(!observed.authorization_allowed);
        let revision = f.revision();
        let inspection = f
            .engine
            .native_dispatch_inspection(&f.access, &f.agreement, &queued.request_id)
            .unwrap();
        let replay = f
            .engine
            .inspect_native_dispatch_status(&f.access, inspection, &actual)
            .unwrap();
        assert_eq!(f.revision(), revision);
        assert_eq!(replay.observations, observed.observations);
        assert!(
            f.engine
                .mark_native_dispatch_attempt(
                    &f.access,
                    &f.agreement,
                    &queued.request_id,
                    actual.identity()
                )
                .is_err()
        );
    }
    #[test]
    fn original_source_operation_and_journal_tampering_fail_closed() {
        let (f, tx) = completed_metadata();
        let queued = request(&f, &tx, "synthetic-tamper-dispatch-request").unwrap();
        f.engine
            .mark_native_dispatch_attempt(
                &f.access,
                &f.agreement,
                &queued.request_id,
                &"ab".repeat(32),
            )
            .unwrap();
        let e = f.engine.load(&f.access, &f.agreement).unwrap();
        let encoded = serde_json::to_value(e).unwrap();
        for field in [
            "signature_retention_key",
            "candidate_id",
            "receipt_digest",
            "checkpoint_id",
            "transaction_digest",
            "txid",
            "transaction_request_id",
        ] {
            let mut corrupted = encoded.clone();
            corrupted["native_dispatch_requests"][&queued.request_id]["source"][field] =
                json!("forged-original");
            let bad: Envelope = serde_json::from_value(corrupted).unwrap();
            assert!(
                native_dispatch_requests::validate_stored(&bad).is_err(),
                "{field}"
            );
        }
        for (field, value) in [
            ("operation_id", json!("replacement-dispatch-operation")),
            ("submission_journal_identity", json!("00".repeat(32))),
            ("attempt_revision", json!(0)),
        ] {
            let mut corrupted = encoded.clone();
            corrupted["native_dispatch_requests"][&queued.request_id][field] = value;
            let bad: Envelope = serde_json::from_value(corrupted).unwrap();
            assert!(
                native_dispatch_requests::validate_stored(&bad).is_err(),
                "{field}"
            );
        }
    }
    #[test]
    fn combined_quota_counts_dispatch_and_never_evicts_original_history() {
        let (f, tx) = completed_metadata();
        let queued = request(&f, &tx, "synthetic-quota-dispatch-request").unwrap();
        loop {
            let e = f.engine.load(&f.access, &f.agreement).unwrap();
            let count = crate::native_requests::total_requests(&e);
            assert_eq!(
                count,
                e.native_requests.len()
                    + e.native_proof_requests.len()
                    + e.native_proof_execution_requests.len()
                    + e.native_artifact_handoff_requests.len()
                    + e.native_settlement_requests.len()
                    + e.native_dispatch_requests.len()
                    + e.native_reconciliation_requests.len()
            );
            if count == crate::native_requests::MAX_NATIVE_REQUESTS {
                break;
            }
            let req = f
                .engine
                .queue_native_construction(
                    &f.access,
                    &format!("synthetic-quota-construction-{count}"),
                    &f.agreement,
                    f.revision(),
                    NativeConstructionRequest {
                        candidate_id: f.candidate.clone(),
                    },
                )
                .unwrap();
            f.engine
                .withdraw_native_request(
                    &f.access,
                    &format!("synthetic-quota-withdraw-{count}"),
                    &f.agreement,
                    f.revision(),
                    &req.request_id,
                )
                .unwrap();
        }
        let err = request(&f, &tx, "synthetic-quota-overflow-dispatch").unwrap_err();
        assert_eq!(err.code, "RESOURCE_EXHAUSTED");
        assert_eq!(
            f.engine
                .native_dispatch_requests(&f.access, &f.agreement)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            f.engine
                .native_dispatch_request(&f.access, &f.agreement, &queued.request_id)
                .unwrap()
                .state,
            NativeRequestState::Queued
        );
    }
    #[test]
    fn empty_dispatch_field_preserves_legacy_envelope_bytes() {
        let f = constructed(false);
        let original = f
            .engine
            .store
            .get_agreement(&f.agreement)
            .unwrap()
            .unwrap()
            .payload;
        assert!(original.get("native_dispatch_requests").is_none());
        assert!(original.get("native_reconciliation_requests").is_none());
        let decoded: Envelope = serde_json::from_value(original.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), original);
    }

    #[test]
    fn historical_status_remains_available_after_modeled_terms_amendment() {
        let (f, tx) = completed_metadata();
        let queued = request(&f, &tx, "synthetic-amended-dispatch-request").unwrap();
        let actual = journal(&f, "dispatch-amended.sqlite", 94);
        let attempt = f
            .engine
            .mark_native_dispatch_attempt(
                &f.access,
                &f.agreement,
                &queued.request_id,
                actual.identity(),
            )
            .unwrap();
        let mut e = f.engine.load(&f.access, &f.agreement).unwrap();
        let revision = e.view.revision;
        // This archival robustness fixture bypasses the public revision operation,
        // which refuses constructed histories. Preserve prior terms explicitly.
        e.view.terms_history.push(e.view.agreement.clone());
        e.view.agreement.purpose = "Synthetic changed current terms".into();
        e.view.agreement.revision += 1;
        let command = context(
            &f.access,
            "synthetic-dispatch-amend-current-terms",
            "synthetic_dispatch_amend_current_terms",
            &f.agreement,
            Some(revision),
            &json!({"modeled":true}),
        )
        .unwrap();
        f.engine
            .commit(
                &command,
                &f.agreement,
                revision,
                e,
                "synthetic_dispatch_amended_terms",
            )
            .unwrap();
        let observed = f
            .engine
            .inspect_native_dispatch_status(&f.access, attempt.into_inspection(), &actual)
            .unwrap();
        assert_eq!(observed.outcome_status, "attempted_outcome_unknown");
        assert_eq!(observed.observations.len(), 1);
        assert_eq!(observed.source, queued.source);
        assert!(!observed.authorization_allowed);
    }
    #[test]
    fn actual_unbound_unverified_intent_is_not_accepted_as_dispatch_history() {
        use wholepact_chain::{ExactSubmissionIntent, SubmissionJournal};
        let (f, tx) = completed_metadata();
        let queued = request(&f, &tx, "synthetic-unbound-dispatch-request").unwrap();
        let mut actual = journal(&f, "dispatch-unbound.sqlite", 95);
        let attempt = f
            .engine
            .mark_native_dispatch_attempt(
                &f.access,
                &f.agreement,
                &queued.request_id,
                actual.identity(),
            )
            .unwrap();
        // Deliberately invalid synthetic bytes, never a real transaction or authority.
        let invalid =
            ExactSubmissionIntent::new(attempt.operation_id(), b"never-funded-unverified-model")
                .unwrap();
        actual.record_exact_intent(&invalid).unwrap();
        assert!(
            f.engine
                .inspect_native_dispatch_status(&f.access, attempt.into_inspection(), &actual)
                .is_err()
        );
        let unchanged = f
            .engine
            .native_dispatch_request(&f.access, &f.agreement, &queued.request_id)
            .unwrap();
        assert!(unchanged.observations.is_empty());
        assert_eq!(unchanged.outcome_status, "attempted_outcome_unknown");
    }

    #[test]
    fn modeled_snapshot_validation_rejects_substitution_regression_and_exhaustion() {
        let (f, tx) = completed_metadata();
        let queued = request(&f, &tx, "synthetic-snapshot-model-dispatch").unwrap();
        f.engine
            .mark_native_dispatch_attempt(
                &f.access,
                &f.agreement,
                &queued.request_id,
                &"ab".repeat(32),
            )
            .unwrap();
        let e = f.engine.load(&f.access, &f.agreement).unwrap();
        let candidate = &e.view.candidates[0];
        // This is only a serialization/validation model, never supplied to the
        // public journal reader or presented as genuine verified evidence.
        let snapshot = json!({
            "submission_journal_identity":"ab".repeat(32),
            "descriptor":{
                "operation_id":queued.operation_id,
                "obligation_id":candidate.proposal.manifest.agreement.obligation_id,
                "proposal_id":candidate.proposal.proposal_id,
                "transaction_id":queued.source.txid,
                "bytes_sha256":queued.source.transaction_digest,
                "expiry_height":candidate.proposal.manifest.expiry_height,
                "network":"testnet","consensus_branch_id":0x77190ad9u32
            },
            "intent":{"operation_id":queued.operation_id,"bytes_sha256":queued.source.transaction_digest,"historical_provider_state":"submission_unknown"},
            "attempts":[{"number":1,"source_id":"synthetic-history","started_at_unix_seconds":1,"outcome":{"kind":"unknown"}}]
        });
        let mut encoded = serde_json::to_value(e).unwrap();
        encoded["native_dispatch_requests"][&queued.request_id]["observations"] = json!([snapshot]);
        let valid: Envelope = serde_json::from_value(encoded.clone()).unwrap();
        assert!(native_dispatch_requests::validate_stored(&valid).is_ok());
        for field in [
            "operation_id",
            "obligation_id",
            "proposal_id",
            "transaction_id",
            "bytes_sha256",
            "network",
        ] {
            let mut corrupted = encoded.clone();
            corrupted["native_dispatch_requests"][&queued.request_id]["observations"][0]["descriptor"]
                [field] = json!("substituted");
            let bad: Envelope = serde_json::from_value(corrupted).unwrap();
            assert!(
                native_dispatch_requests::validate_stored(&bad).is_err(),
                "{field}"
            );
        }
        let mut duplicate = encoded.clone();
        duplicate["native_dispatch_requests"][&queued.request_id]["observations"] =
            json!([snapshot, snapshot]);
        assert!(
            native_dispatch_requests::validate_stored(
                &serde_json::from_value::<Envelope>(duplicate).unwrap()
            )
            .is_err()
        );
        let absent = json!({"submission_journal_identity":"ab".repeat(32),"descriptor":null,"intent":null,"attempts":[]});
        let mut regressed = encoded.clone();
        regressed["native_dispatch_requests"][&queued.request_id]["observations"] =
            json!([snapshot, absent]);
        assert!(
            native_dispatch_requests::validate_stored(
                &serde_json::from_value::<Envelope>(regressed).unwrap()
            )
            .is_err()
        );
        let mut snapshots = vec![];
        for count in 1..=native_dispatch_requests::MAX_DISPATCH_OBSERVATIONS + 1 {
            let mut next = snapshot.clone();
            next["attempts"] = json!((1..=count).map(|n| json!({"number":n,"source_id":"synthetic-history","started_at_unix_seconds":n,"outcome":{"kind":"unknown"}})).collect::<Vec<_>>());
            snapshots.push(next);
        }
        let mut full = encoded.clone();
        full["native_dispatch_requests"][&queued.request_id]["observations"] =
            json!(&snapshots[..native_dispatch_requests::MAX_DISPATCH_OBSERVATIONS]);
        assert!(
            native_dispatch_requests::validate_stored(
                &serde_json::from_value::<Envelope>(full).unwrap()
            )
            .is_ok()
        );
        encoded["native_dispatch_requests"][&queued.request_id]["observations"] = json!(snapshots);
        assert_eq!(
            native_dispatch_requests::validate_stored(
                &serde_json::from_value::<Envelope>(encoded).unwrap()
            )
            .unwrap_err()
            .code,
            "RESOURCE_EXHAUSTED"
        );
    }

    #[test]
    fn dispatch_backup_history_preserves_unknown_journal_snapshot_without_activation() {
        use std::collections::BTreeMap;
        use wholepact_storage_security::bundle::*;
        struct BackupGate;
        impl BundleLease for BackupGate {
            fn check_current(&self) -> std::result::Result<(), BundleError> {
                Ok(())
            }
            fn checkpoint_id(&self) -> &str {
                "synthetic-stopped-dispatch-writer"
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
        let (f, tx) = completed_metadata();
        let queued = request(&f, &tx, "synthetic-backup-dispatch-request").unwrap();
        let actual = journal(&f, "dispatch-backup-status.sqlite", 96);
        let attempt = f
            .engine
            .mark_native_dispatch_attempt(
                &f.access,
                &f.agreement,
                &queued.request_id,
                actual.identity(),
            )
            .unwrap();
        let observed = f
            .engine
            .inspect_native_dispatch_status(&f.access, attempt.into_inspection(), &actual)
            .unwrap();
        assert_eq!(observed.outcome_status, "attempted_outcome_unknown");
        assert_eq!(observed.observations.len(), 1);
        let reconciliation = f.engine.queue_native_reconciliation(
            &f.access,"synthetic-backup-reconciliation-request",&f.agreement,f.revision(),
            crate::native_reconciliation_requests::NativeReconciliationRequest::ProviderObservation { dispatch_request_id: queued.request_id.clone() },
        ).unwrap();
        let reconciliation_attempt = f
            .engine
            .mark_native_reconciliation_attempt(&f.access, &f.agreement, &reconciliation.request_id)
            .unwrap();
        let reconciled = f
            .engine
            .inspect_native_reconciliation_status(
                &f.access,
                reconciliation_attempt.into_inspection(),
                &actual,
            )
            .unwrap();
        assert_eq!(reconciled.outcome_status, "attempted_outcome_unknown");
        let before = f.engine.store.get_agreement(&f.agreement).unwrap().unwrap();
        let adapter =
            wholepact_store::bundle::CoordinationBundleAdapter::new(&f.engine.store).unwrap();
        let sources = [RegisteredJournal::new("coordination", &adapter).unwrap()];
        let archive = f.dir.path().join("dispatch-archive");
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
        let restored = f.dir.path().join("dispatch-restored");
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
            .find(|r| r.id == f.agreement)
            .unwrap();
        assert_eq!(
            latest.payload["native_dispatch_requests"],
            before.payload["native_dispatch_requests"]
        );
        assert_eq!(
            latest.payload["native_reconciliation_requests"],
            before.payload["native_reconciliation_requests"]
        );
        let reconciliation_row =
            &latest.payload["native_reconciliation_requests"][&reconciliation.request_id];
        assert_eq!(reconciliation_row["state"], "attempt_started");
        assert_eq!(reconciliation_row["operation_id"], observed.operation_id);
        assert!(reconciliation_row["resolution_commit"].is_null());
        assert!(reconciliation_row["observations"][0]["report"].is_null());
        let row = &latest.payload["native_dispatch_requests"][&queued.request_id];
        assert_eq!(row["operation_id"], observed.operation_id);
        assert_eq!(row["submission_journal_identity"], actual.identity());
        assert_eq!(
            row["source"],
            serde_json::to_value(&observed.source).unwrap()
        );
        assert_eq!(
            row["observations"],
            serde_json::to_value(&observed.observations).unwrap()
        );
        assert_eq!(row["state"], "attempt_started");
        assert!(row["observations"][0]["intent"].is_null());
        assert!(
            inventory
                .store_inventory()
                .historical_agreements()
                .iter()
                .any(
                    |r| r.payload["native_dispatch_requests"][&queued.request_id]["state"]
                        == "queued"
                )
        );
        assert!(
            inventory
                .store_inventory()
                .historical_agreements()
                .iter()
                .any(
                    |r| r.payload["native_dispatch_requests"][&queued.request_id]["state"]
                        == "attempt_started"
                        && r.payload["native_dispatch_requests"][&queued.request_id]["observations"]
                            == json!([])
                )
        );
        assert!(Store::open_encrypted(&restored, &key).is_err());
        assert!(
            f.engine
                .mark_native_dispatch_attempt(
                    &f.access,
                    &f.agreement,
                    &queued.request_id,
                    actual.identity()
                )
                .is_err()
        );
    }
    include!("../native_reconciliation_requests/constructed.rs");
}
