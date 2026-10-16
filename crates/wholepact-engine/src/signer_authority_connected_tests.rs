//! Supplementary fixed-account connected qualification of the concrete signer
//! authority path. One real proof is retained for local repair/reuse; no live funds,
//! real enrollment, user-input origin, installed signer or consensus is claimed.
use super::authority_bridge::with_signer_account_association;
use super::record_source::{LocalParticipantRecordSource, OriginalAuthorizationHistory};
use super::*;
use crate::{
    Result,
    candidates::{CandidateRequest, LocalConstruction},
    participant_records::*,
    planning::RosterSelectionRequest,
    proof_jobs::{LocalCheckpoint, LocalProofJob},
};
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use wholepact_core::*;
use wholepact_proof_jobs::{CheckpointScope, LocalAction, LocalProofConsent, ProofJobStore};
use wholepact_protocol::{
    authorization::retention::transaction::{
        LocalTransactionCheckpoint, RecoveryAction, TransactionCheckpointJournal,
        TransactionRecoveryConsent, TransactionRecoveryScope, TransactionRetentionConsent,
        TransactionRetentionScope,
    },
    construction::*,
    proving::ProvingLimits,
};
use wholepact_signer::native_ui::qualification_fixture::{
    AGREEMENT, FixedAuthorityFixture, OPERATOR, PURPOSE, RETENTION,
};
use wholepact_storage_security::{DatabaseKey, create_encrypted, open_encrypted};
use wholepact_store::Store;
use wholepact_transport as transport;

struct Privacy {
    principal: String,
    candidate: String,
    manifest: String,
    account: String,
    allowed: AtomicBool,
}
impl LocalProofConsent for Privacy {
    fn permits(&self, s: &CheckpointScope, _: LocalAction) -> bool {
        self.allowed.load(Ordering::SeqCst)
            && s.principal_id == self.principal
            && s.candidate_id == self.candidate
            && s.manifest_digest == self.manifest
            && s.account_ids == [self.account.clone()]
            && s.local_operator == OPERATOR
            && s.purpose == PURPOSE
            && s.retention_policy == RETENTION
    }
}
impl SignedRetentionConsent for Privacy {
    fn permits(&self, s: &SignedRetentionScope) -> bool {
        self.allowed.load(Ordering::SeqCst)
            && s.context.principal_id == self.principal
            && s.context.candidate_id == self.candidate
            && s.context.manifest_digest == self.manifest
            && s.context.account_ids == [self.account.clone()]
            && s.context.local_operator == OPERATOR
            && s.context.purpose == PURPOSE
            && s.context.retention_policy == RETENTION
    }
}
impl TransactionRetentionConsent for Privacy {
    fn permits(&self, s: &TransactionRetentionScope) -> bool {
        SignedRetentionConsent::permits(self, &s.signed_scope)
    }
}
impl TransactionRecoveryConsent for Privacy {
    fn permits(&self, s: &TransactionRecoveryScope<'_>) -> bool {
        s.action == RecoveryAction::InspectExistingIntent
            && TransactionRetentionConsent::permits(self, s.retention)
    }
}
struct RecordAuthority {
    binding: RecordStoreBinding,
    principal: String,
    account: String,
}
struct RecordLease {
    scope: ParticipantRecordScope,
    expiry: String,
}
impl ParticipantRecordAuthority for RecordAuthority {
    fn acquire<'a>(
        &'a self,
        s: &ParticipantRecordScope,
        w: &records::ObservationWindow,
    ) -> Result<Box<dyn ParticipantRecordLease + 'a>> {
        if s.store != self.binding
            || s.principal_id != self.principal
            || s.account_id != self.account
            || s.agreement_id != AGREEMENT
            || s.record_id != "fixed-native-record"
            || s.profile_id != "fixed-native-record-profile"
            || s.participant_id != "fixed-participant"
        {
            return Err(ApiError::new(
                "PERMISSION_DENIED",
                "Fixed synthetic record scope differs",
            ));
        }
        let t = Timestamp::try_from(w.now.clone()).unwrap();
        Ok(Box::new(RecordLease {
            scope: s.clone(),
            expiry: Timestamp::from_unix_seconds(t.unix_seconds() + 300)
                .unwrap()
                .as_str()
                .into(),
        }))
    }
}
impl ParticipantRecordLease for RecordLease {
    fn scope(&self) -> &ParticipantRecordScope {
        &self.scope
    }
    fn expires_at(&self) -> &str {
        &self.expiry
    }
    fn check_current(&self) -> Result<()> {
        Ok(())
    }
}
fn key(n: u8) -> DatabaseKey {
    DatabaseKey::from_bytes([n; 32])
}
fn now() -> Timestamp {
    Timestamp::from_unix_seconds(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
    )
    .unwrap()
}
fn envelope(
    payload: &[u8],
    candidate: &str,
    principal: &str,
    time: &Timestamp,
) -> transport::ReceivedArtifact {
    let sender = transport::TransportSecret::from_bytes([173; 32]).unwrap();
    let recipient = transport::TransportSecret::from_bytes([174; 32]).unwrap();
    let context = transport::MessageContext {
        network_profile_id: "ironwood-testnet-nu7-candidate".into(),
        agreement_id: AGREEMENT.into(),
        proposal_id: candidate.into(),
        proposal_revision: 1,
        sender_id: "fixed-synthetic-relay".into(),
        recipient_id: principal.into(),
        artifact_kind: transport::ArtifactKind::Authorization,
    };
    let prepared = transport::prepare_export(
        transport::ExportRequest {
            context: context.clone(),
            order: transport::MessageOrder {
                message_id: transport::random_message_id().unwrap(),
                sequence: 1,
                issued_at: time.clone(),
                expires_at: Timestamp::from_unix_seconds(time.unix_seconds() + 120).unwrap(),
            },
            purpose: PURPOSE.into(),
            persistence_warning: RETENTION.into(),
        },
        vec![
            transport::DisclosureField::new("external_spend_signatures_v1", payload.to_vec())
                .unwrap(),
        ],
        &sender.public_key().unwrap(),
        &recipient.public_key().unwrap(),
        time,
    )
    .unwrap();
    let digest = prepared.preview().digest().unwrap();
    let sealed = prepared.seal(&sender, &digest, time).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut ledger = transport::SqliteReplayLedger::from_encrypted_connection(
        create_encrypted(directory.path().join("inbox.db"), &key(175)).unwrap(),
    )
    .unwrap();
    transport::open_envelope(
        &sealed,
        &recipient,
        &sender.public_key().unwrap(),
        &context,
        time,
        &mut ledger,
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixed_native_witness_wallet_signer_to_engine_records_uses_one_proof() {
    let mut fixture = FixedAuthorityFixture::new().await.unwrap();
    let manifest = fixture.manifest().clone();
    let access = Access {
        include_owned_agreements: true,
        principal_id: fixture.principal_id().into(),
        ..Default::default()
    };
    let directory = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let metadata = directory.path().join("coordination.db");
    let proof_path = directory.path().join("proof.db");
    // The cache contains only fixed never-funded pre-signing encrypted artifacts.
    // Generated files are never accepted as authority: every open/proof/candidate
    // is revalidated, and the exact generated manifest must match this fresh scan.
    let cache = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../.runtime/fixed-native-authority-proof");
    let cache_manifest = cache.join("synthetic-proof-manifest.json");
    let mut reused = false;
    let (engine, jobs, candidate_id, job_id, privacy) = if cache_manifest.exists() {
        let saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&cache_manifest).unwrap()).unwrap();
        assert_eq!(saved["synthetic_never_funded"], true);
        assert_eq!(saved["production_qualification"], false);
        std::fs::copy(cache.join("coordination.db"), &metadata).unwrap();
        std::fs::copy(cache.join("proof.db"), &proof_path).unwrap();
        let engine = Engine::from_store(Store::open_encrypted(&metadata, &key(181)).unwrap());
        let jobs = ProofJobStore::from_encrypted_connection(
            open_encrypted(&proof_path, &key(182)).unwrap(),
        )
        .unwrap();
        let candidate_id = saved["candidate_id"].as_str().unwrap().to_owned();
        let job_id = saved["proof_job_id"].as_str().unwrap().to_owned();
        let (_, candidate) = engine.candidate(&access, &candidate_id).unwrap();
        assert_eq!(candidate.proposal.manifest, manifest);
        let privacy = Privacy {
            principal: access.principal_id.clone(),
            candidate: candidate_id.clone(),
            manifest: candidate.manifest_digest,
            account: manifest.participants[0].account_id.clone(),
            allowed: AtomicBool::new(true),
        };
        reused = true;
        (engine, jobs, candidate_id, job_id, privacy)
    } else {
        let engine = Engine::from_store(Store::create_encrypted(&metadata, &key(181)).unwrap());
        engine
            .create(&access, "fixed-create", manifest.agreement.clone())
            .unwrap();
        let owner = &manifest.participants[0];
        engine
            .add_intent(
                &access,
                "fixed-intent",
                AGREEMENT,
                1,
                ParticipationIntent {
                    intent_id: "fixed-intent".into(),
                    agreement_id: AGREEMENT.into(),
                    participant_id: owner.participant_id.clone(),
                    desired_contribution: owner.contribution,
                    maximum_net_debit: owner.maximum_net_debit,
                    fee_cap: owner.fee_cap,
                    conditions: vec![],
                    valid_until: None,
                    status: IntentStatus::Active,
                },
            )
            .unwrap();
        engine
            .select_roster(
                &access,
                "fixed-roster",
                AGREEMENT,
                2,
                RosterSelectionRequest {
                    selected_intent_ids: vec!["fixed-intent".into()],
                },
            )
            .unwrap();
        let candidate = engine
            .create_candidate(
                &access,
                "fixed-candidate",
                AGREEMENT,
                3,
                CandidateRequest {
                    manifest: manifest.clone(),
                    previous_candidate_id: None,
                },
            )
            .unwrap()
            .agreement
            .candidates[0]
            .clone();
        let candidate_id = candidate.candidate_id.clone();
        let privacy = Privacy {
            principal: access.principal_id.clone(),
            candidate: candidate_id.clone(),
            manifest: candidate.manifest_digest.clone(),
            account: owner.account_id.clone(),
            allowed: AtomicBool::new(true),
        };
        let declarations = vec![DisclosureAcknowledgement {
            account_id: owner.account_id.clone(),
            manifest_digest: hex::decode(&candidate.manifest_digest)
                .unwrap()
                .try_into()
                .unwrap(),
            operator: OPERATOR.into(),
            reviewer_account_ids: vec![owner.account_id.clone()],
            purpose: PURPOSE.into(),
            retention_policy: RETENTION.into(),
            scope: DisclosureScope::DedicatedAccountFvkAndSelectedNotesAndOutputs,
        }];
        let jobs = ProofJobStore::from_encrypted_connection(
            create_encrypted(&proof_path, &key(182)).unwrap(),
        )
        .unwrap();
        let checkpointed = engine
            .checkpoint_candidate_locally(
                &access,
                "fixed-checkpoint",
                &candidate_id,
                4,
                LocalCheckpoint {
                    construction: LocalConstruction {
                        context: fixture.construction_context(),
                        contributions: fixture.take_contribution().unwrap(),
                        declarations: &declarations,
                    },
                    jobs: &jobs,
                    limits: ProvingLimits { maximum_actions: 8 },
                    consent: &privacy,
                },
            )
            .unwrap();
        let job_id = checkpointed.agreement.candidates[0].proof_jobs[0]
            .job_id
            .clone();
        let proved = engine
            .run_candidate_proof_locally(
                &access,
                "fixed-prove-once",
                &candidate_id,
                checkpointed.agreement.revision,
                LocalProofJob {
                    job_id: &job_id,
                    jobs: &jobs,
                    consent: &privacy,
                },
            )
            .unwrap();
        assert_eq!(proved.agreement.candidates[0].proof_jobs[0].attempt, 1);
        drop(jobs);
        drop(engine);
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::copy(&metadata, cache.join("coordination.db")).unwrap();
        std::fs::copy(&proof_path, cache.join("proof.db")).unwrap();
        std::fs::write(&cache_manifest,serde_json::to_vec(&serde_json::json!({"schema_version":1,"synthetic_never_funded":true,"production_qualification":false,"candidate_id":candidate_id,"proof_job_id":job_id,"status":"proved_before_signing","database_key_fixture_bytes":{"coordination.db":181,"proof.db":182}})).unwrap()).unwrap();
        std::fs::set_permissions(&cache_manifest, std::fs::Permissions::from_mode(0o600)).unwrap();
        let engine = Engine::from_store(Store::open_encrypted(&metadata, &key(181)).unwrap());
        let jobs = ProofJobStore::from_encrypted_connection(
            open_encrypted(&proof_path, &key(182)).unwrap(),
        )
        .unwrap();
        (engine, jobs, candidate_id, job_id, privacy)
    };
    let local = || LocalProofJob {
        job_id: &job_id,
        jobs: &jobs,
        consent: &privacy,
    };
    let checkpoint = engine
        .load_candidate_proof_for_local_review(&access, &candidate_id, local())
        .unwrap();
    assert!(checkpoint.summary().proof_verified);
    assert!(!checkpoint.summary().authorization_allowed);
    let (_, candidate) = engine.candidate(&access, &candidate_id).unwrap();
    let proposal = candidate.verified_snapshot().unwrap();
    let signed = SignedResultJournal::from_encrypted_connection(
        create_encrypted(directory.path().join("signed.db"), &key(183)).unwrap(),
    )
    .unwrap();
    let transactions = TransactionCheckpointJournal::from_encrypted_connection(
        create_encrypted(directory.path().join("transaction.db"), &key(184)).unwrap(),
    )
    .unwrap();
    let retention = || LocalSignedRetention {
        journal: &signed,
        consent: &privacy,
    };
    let transaction = || LocalTransactionCheckpoint {
        journal: &transactions,
        consent: &privacy,
    };
    fixture
        .with_signed_result(
            &proposal,
            checkpoint.pczt_bytes(),
            checkpoint.policy(),
            |flow| {
                let mut wrong_history = flow.history.clone();
                wrong_history.expected_original_consent_ref = "00".repeat(32);
                assert!(flow.client.acquire(&wrong_history).is_err());
                let payload = flow
                    .client
                    .retrieve_original_authorization(flow.history)
                    .unwrap();
                assert_eq!(
                    payload,
                    flow.client
                        .retrieve_original_authorization(flow.history)
                        .unwrap()
                );
                let held = flow.client.acquire(flow.history).unwrap();
                let original = held.evidence().clone();
                held.check_current().unwrap();
                drop(held);
                assert_eq!(
                    original.consent.reference(),
                    flow.commit.original_consent_ref
                );
                assert!(original.retained_result.is_some());
                let release = original.release_intent.intent();
                // The host has no complete signer-account ledger. Production
                // receipt retention must consume the live original history,
                // rather than manufacturing an apparently reconciled mirror.
                assert!(
                    engine
                        .store
                        .authority_account(&release.account_id)
                        .unwrap()
                        .is_none()
                );
                let time = now();
                let artifact = envelope(&payload, &candidate_id, &access.principal_id, &time);
                let mut altered: serde_json::Value = serde_json::from_slice(&payload).unwrap();
                altered["account_id"] = serde_json::json!("other-synthetic-account");
                let bad = envelope(
                    &serde_json::to_vec(&altered).unwrap(),
                    &candidate_id,
                    &access.principal_id,
                    &time,
                );
                assert!(
                    with_signer_account_association(flow.client, flow.history, &bad, |_| Ok(()))
                        .is_err()
                );
                let wrong_candidate = envelope(
                    &payload,
                    "other-fixed-candidate",
                    &access.principal_id,
                    &time,
                );
                assert!(
                    with_signer_account_association(
                        flow.client,
                        flow.history,
                        &wrong_candidate,
                        |_| Ok(())
                    )
                    .is_err()
                );
                let record_authority = RecordAuthority {
                    binding: engine.protected_record_store_binding().unwrap(),
                    principal: access.principal_id.clone(),
                    account: release.account_id.clone(),
                };
                let window = records::ObservationWindow {
                    now: time.as_str().into(),
                    oldest_acceptable: Timestamp::from_unix_seconds(time.unix_seconds() - 30)
                        .unwrap()
                        .as_str()
                        .into(),
                };
                let runtime = || ParticipantRecordRuntime {
                    profile_id: "fixed-native-record-profile",
                    authority: &record_authority,
                    window: &window,
                };
                let record_request = RetainParticipantRecordRequest {
                    record_id: "fixed-native-record".into(),
                    candidate_id: candidate_id.clone(),
                    participant_id: "fixed-participant".into(),
                    account_id: release.account_id.clone(),
                };
                with_signer_account_association(
                    flow.client,
                    flow.history,
                    &artifact,
                    |association| {
                        assert!(matches!(
                            &association.origin,
                            AccountAssociationOrigin::LocalSignerResult { .. }
                        ));
                        let deliveries = [AuthenticatedSignatureDelivery {
                            artifact: &artifact,
                            association: Some(association),
                        }];
                        let inspected = engine.inspect_candidate_signatures(
                            &access,
                            &candidate_id,
                            local(),
                            &deliveries,
                            &time,
                        )?;
                        assert!(inspected.signatures_complete);
                        engine.retain_candidate_signatures(
                            &access,
                            "fixed-retain-signatures",
                            &candidate_id,
                            local(),
                            retention(),
                            &deliveries,
                            &time,
                        )?;
                        let extracted = engine.checkpoint_retained_candidate_transaction(
                            &access,
                            "fixed-retain-signatures",
                            &candidate_id,
                            local(),
                            retention(),
                            transaction(),
                            &deliveries,
                            &time,
                        )?;
                        assert!(extracted.cryptographic_transaction_verified);
                        let history = flow.client.acquire(flow.history).unwrap();
                        let source = || LocalParticipantRecordSource {
                            proof: local(),
                            signatures: retention(),
                            transaction: transaction(),
                            transaction_read_consent: &privacy,
                            deliveries: &deliveries,
                            signature_idempotency_key: "fixed-retain-signatures",
                            original_authorization:
                                OriginalAuthorizationHistory::AuthenticatedSigner {
                                    history: &history,
                                },
                            now: &time,
                        };
                        let revision = engine.get(&access, AGREEMENT)?.revision;
                        let stored = engine.retain_participant_record_from_protocol(
                            &access,
                            "fixed-retain-record",
                            AGREEMENT,
                            revision,
                            record_request.clone(),
                            runtime(),
                            source(),
                        )?;
                        assert!(
                            engine
                                .retain_participant_record_from_protocol(
                                    &access,
                                    "fixed-retain-record",
                                    AGREEMENT,
                                    revision,
                                    record_request.clone(),
                                    runtime(),
                                    source()
                                )?
                                .replayed
                        );
                        let record = engine.read_participant_record(
                            &access,
                            AGREEMENT,
                            &record_request.record_id,
                            runtime(),
                        )?;
                        assert_eq!(
                            record.own_authorization().consent_record_ref,
                            flow.history.expected_original_consent_ref
                        );
                        assert_eq!(record.transaction().transaction_id, extracted.txid);
                        assert_eq!(
                            record.own_authorization().exposure,
                            AuthorizationExposure::OutstandingUncertain
                        );
                        assert!(stored.record.recovery_required);
                        Ok(())
                    },
                )
                .unwrap();
                flow.revoke_fixture_pairing();
                assert!(flow.client.acquire(flow.history).is_err());
                assert!(
                    flow.client
                        .retrieve_original_authorization(flow.history)
                        .is_err()
                );
                assert!(
                    with_signer_account_association(flow.client, flow.history, &artifact, |_| Ok(
                        ()
                    ))
                    .is_err()
                );
                assert!(
                    engine
                        .store
                        .authority_account(&release.account_id)
                        .unwrap()
                        .is_none()
                );
                let retained = engine
                    .read_participant_record(
                        &access,
                        AGREEMENT,
                        &record_request.record_id,
                        runtime(),
                    )
                    .unwrap();
                assert_eq!(
                    retained.own_authorization().consent_record_ref,
                    flow.history.expected_original_consent_ref
                );
            },
        )
        .await
        .unwrap();
    assert_eq!(
        engine
            .load_candidate_proof_for_local_review(&access, &candidate_id, local())
            .unwrap()
            .summary()
            .attempt,
        1
    );
    eprintln!(
        "Fixed never-funded signer flow passed; maintained proof generated this run: {}; cached proof replay: {}; real GUI/install/consensus qualification: false",
        !reused, reused
    );
}
