//! Never-funded maintained-library cryptography, encrypted checkpoint, and actual
//! HPKE-authenticated transport. Synthetic association issuance is test-only.
use super::*;
use orchard::keys::{SpendAuthorizingKey, SpendingKey};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use sha2::{Digest, Sha256};
use wholepact_proof_jobs::{CheckpointScope, LocalAction, LocalProofConsent, ProofJobStore};
use wholepact_protocol::{
    proving::ProvingLimits, review::verify_review, synthetic::review_fixture,
};
use wholepact_storage_security::{create_encrypted, DatabaseKey};
use wholepact_transport::*;

struct FixtureConsent;
impl LocalProofConsent for FixtureConsent {
    fn permits(&self, scope: &CheckpointScope, _: LocalAction) -> bool {
        scope.principal_id == "synthetic-controller"
            && scope.local_operator == "synthetic-local-prover"
    }
}

#[test]
fn saved_proof_authenticated_signatures_partial_complete_and_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let jobs = ProofJobStore::from_encrypted_connection(
        create_encrypted(
            dir.path().join("private-proof.db"),
            &DatabaseKey::from_bytes([0x64; 32]),
        )
        .unwrap(),
    )
    .unwrap();
    let fixture = review_fixture().unwrap();
    let review = verify_review(&fixture.pczt_bytes, &fixture.policy).unwrap();
    let scope = CheckpointScope {
        principal_id: "synthetic-controller".into(),
        candidate_id: "synthetic-candidate".into(),
        manifest_digest: hex::encode(fixture.policy.manifest_digest),
        artifact_digest: hex::encode(Sha256::digest(&fixture.pczt_bytes)),
        effects_commitment: review.shielded_sighash().into(),
        coordination_request_digest: "12".repeat(32),
        review_binding: review.review_binding().into(),
        account_ids: fixture
            .policy
            .participants
            .iter()
            .map(|p| p.account_id.clone())
            .collect(),
        local_operator: "synthetic-local-prover".into(),
        purpose: "Synthetic signature inspection".into(),
        retention_policy: "Temporary encrypted fixture only".into(),
    };
    let queued = jobs
        .enqueue(
            &scope,
            "synthetic-signature-intake",
            &fixture.pczt_bytes,
            &fixture.policy,
            ProvingLimits { maximum_actions: 8 },
            &FixtureConsent,
        )
        .unwrap();
    jobs.run(&scope.principal_id, &queued.job_id, &FixtureConsent)
        .unwrap();
    let checkpoint = jobs
        .load_verified(&scope.principal_id, &queued.job_id, &FixtureConsent)
        .unwrap();
    let original = checkpoint.pczt_bytes().to_vec();
    let now = Timestamp::from_unix_seconds(1_800_000_000).unwrap();
    let recipient = TransportSecret::from_bytes([93; 32]).unwrap();
    let mut ledger = SqliteReplayLedger::open(dir.path().join("inbox.db")).unwrap();
    let mut artifacts = Vec::new();
    let mut associations = Vec::new();
    let mut signature_records = Vec::new();
    for owner in 0..2 {
        let sender = TransportSecret::from_bytes([71 + owner as u8; 32]).unwrap();
        let participant = &checkpoint.policy().participants[owner];
        let input = checkpoint
            .policy()
            .inputs
            .iter()
            .find(|i| i.participant_index == owner)
            .unwrap();
        let mut signer =
            pczt::roles::signer::Signer::new(pczt::Pczt::parse(&original).unwrap()).unwrap();
        let sk = SpendingKey::from_bytes([owner as u8 + 1; 32]).unwrap();
        signer
            .sign_ironwood(
                UnwrapErr(SysRng),
                input.action_index,
                &SpendAuthorizingKey::from(&sk),
            )
            .unwrap();
        let signed = signer.finish();
        let signature = signed.ironwood().actions()[input.action_index]
            .spend()
            .spend_auth_sig()
            .unwrap();
        signature_records.push((owner, input.action_index, signature));
        let payload = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1, "candidate_id": scope.candidate_id,
            "manifest_digest": scope.manifest_digest, "proved_artifact_digest": checkpoint.summary().result_digest,
            "review_binding": scope.review_binding, "account_id": participant.account_id,
            "signatures": [{"action_index": input.action_index, "signature_hex": hex::encode(signature)}]
        })).unwrap();
        let context = MessageContext {
            network_profile_id: crate::candidates::PROFILE_ID.into(),
            agreement_id: "synthetic-agreement".into(),
            proposal_id: "synthetic-proposal".into(),
            proposal_revision: 1,
            sender_id: format!("synthetic-owner-{owner}"),
            recipient_id: "synthetic-coordinator".into(),
            artifact_kind: ArtifactKind::Authorization,
        };
        let prepared = prepare_export(
            ExportRequest {
                context: context.clone(),
                order: MessageOrder {
                    message_id: random_message_id().unwrap(),
                    sequence: 1,
                    issued_at: now.clone(),
                    expires_at: Timestamp::from_unix_seconds(now.unix_seconds() + 60).unwrap(),
                },
                purpose: "Synthetic external signature fixture".into(),
                persistence_warning: "Temporary fixture ciphertext".into(),
            },
            vec![DisclosureField::new("external_spend_signatures_v1", payload).unwrap()],
            &sender.public_key().unwrap(),
            &recipient.public_key().unwrap(),
            &now,
        )
        .unwrap();
        let preview_digest = prepared.preview().digest().unwrap();
        let sealed = prepared.seal(&sender, &preview_digest, &now).unwrap();
        artifacts.push(
            open_envelope(
                &sealed,
                &recipient,
                &sender.public_key().unwrap(),
                &context,
                &now,
                &mut ledger,
            )
            .unwrap(),
        );
        assert!(open_envelope(
            &sealed,
            &recipient,
            &sender.public_key().unwrap(),
            &context,
            &now,
            &mut ledger
        )
        .is_err());
        // Test-only issuer. No corresponding constructor exists in library builds.
        associations.push(AuthenticatedAccountAssociation {
            origin: AccountAssociationOrigin::RemoteKeys,
            sender_fingerprint: sender.public_key().unwrap().fingerprint(),
            recipient_fingerprint: recipient.public_key().unwrap().fingerprint(),
            sender_id: context.sender_id,
            recipient_id: context.recipient_id,
            account_id: participant.account_id.clone(),
            fvk_digest: hex::encode(Sha256::digest(participant.fvk.to_bytes())),
            manifest_digest: scope.manifest_digest.clone(),
            candidate_id: scope.candidate_id.clone(),
        });
    }
    let inspect = |deliveries: &[AuthenticatedSignatureDelivery<'_>], at: &Timestamp| {
        inspect_deliveries(
            &checkpoint,
            "synthetic-agreement",
            "synthetic-proposal",
            1,
            deliveries,
            at,
        )
    };
    let missing = [AuthenticatedSignatureDelivery {
        artifact: &artifacts[0],
        association: None,
    }];
    assert_eq!(
        inspect(&missing, &now).unwrap_err().code,
        "ACCOUNT_ASSOCIATION_UNAVAILABLE"
    );
    let first = AuthenticatedSignatureDelivery {
        artifact: &artifacts[0],
        association: Some(&associations[0]),
    };
    let partial = inspect(&[first], &now).unwrap();
    assert_eq!(partial.verified_real_inputs, 1);
    assert!(!partial.signatures_complete);
    #[cfg(all(feature = "signer-authority-bridge", target_os = "linux"))]
    {
        // Test-only sealed-origin fixture. The production constructor separately
        // requires the actual installed-provider/native original-history lease.
        let a = &associations[0];
        let mut local = AuthenticatedAccountAssociation {
            origin: AccountAssociationOrigin::LocalSignerResult {
                provider_enrollment_ref: "11".repeat(32),
                original_consent_ref: "22".repeat(32),
                authorization_id: "synthetic-authorization".into(),
                result_digest: "33".repeat(32),
                outbox_digest: hex::encode(Sha256::digest(artifacts[0].fields()[0].bytes())),
            },
            sender_fingerprint: a.sender_fingerprint.clone(),
            recipient_fingerprint: a.recipient_fingerprint.clone(),
            sender_id: a.sender_id.clone(),
            recipient_id: a.recipient_id.clone(),
            account_id: a.account_id.clone(),
            fvk_digest: a.fvk_digest.clone(),
            manifest_digest: a.manifest_digest.clone(),
            candidate_id: a.candidate_id.clone(),
        };
        fn delivery<'a>(
            artifact: &'a ReceivedArtifact,
            association: &'a AuthenticatedAccountAssociation,
        ) -> [AuthenticatedSignatureDelivery<'a>; 1] {
            [AuthenticatedSignatureDelivery {
                artifact,
                association: Some(association),
            }]
        }
        assert!(
            inspect(&delivery(&artifacts[0], &local), &now)
                .unwrap()
                .proof_verified
        );
        if let AccountAssociationOrigin::LocalSignerResult { outbox_digest, .. } = &mut local.origin
        {
            *outbox_digest = "44".repeat(32);
        }
        assert!(inspect(&delivery(&artifacts[0], &local), &now).is_err());
        if let AccountAssociationOrigin::LocalSignerResult { outbox_digest, .. } = &mut local.origin
        {
            *outbox_digest = hex::encode(Sha256::digest(artifacts[0].fields()[0].bytes()));
        }
        local.account_id = "wrong-original-account".into();
        assert!(inspect(&delivery(&artifacts[0], &local), &now).is_err());
        local.account_id = a.account_id.clone();
        local.candidate_id = "wrong-original-candidate".into();
        assert!(inspect(&delivery(&artifacts[0], &local), &now).is_err());
    }
    let deliveries: Vec<_> = artifacts
        .iter()
        .zip(&associations)
        .map(|(artifact, association)| AuthenticatedSignatureDelivery {
            artifact,
            association: Some(association),
        })
        .collect();
    let complete = inspect(&deliveries, &now).unwrap();
    assert!(
        complete.signatures_complete
            && complete.exact_candidate_preserved
            && complete.proof_verified
    );
    assert!(
        !complete.authorization_allowed
            && !complete.distribution_allowed
            && !complete.chain_validated
    );
    assert_eq!(checkpoint.pczt_bytes(), original);
    assert!(inspect(
        &deliveries,
        &Timestamp::from_unix_seconds(now.unix_seconds() + 60).unwrap()
    )
    .is_err());
    let wrong = [AuthenticatedSignatureDelivery {
        artifact: &artifacts[0],
        association: Some(&associations[1]),
    }];
    assert!(inspect(&wrong, &now).is_err());
    assert!(inspect_deliveries(
        &checkpoint,
        "wrong-agreement",
        "synthetic-proposal",
        1,
        &deliveries,
        &now
    )
    .is_err());
    // A distinct encrypted immutable journal, separate from the unsigned store.
    // The trusted fixture gate explicitly consents to signed-candidate retention.
    use wholepact_protocol::authorization::retention::{
        SignedResultJournal, SignedRetentionConsent, SignedRetentionScope,
    };
    struct RetainConsent;
    impl SignedRetentionConsent for RetainConsent {
        fn permits(&self, scope: &SignedRetentionScope) -> bool {
            scope.context.principal_id == "synthetic-controller"
                && scope.context.local_operator == "synthetic-local-prover"
                && scope.context.candidate_id == "synthetic-candidate"
                && scope.context.account_ids.len() == 2
                && scope.signature_set_digest.len() == 64
        }
    }
    struct Deny;
    impl SignedRetentionConsent for Deny {
        fn permits(&self, _: &SignedRetentionScope) -> bool {
            false
        }
    }
    // Fail at the gate just after the intent transaction commits. Restart may
    // resume the deterministic assembly, but cannot substitute a partial set.
    struct Interrupt(std::cell::Cell<usize>);
    impl SignedRetentionConsent for Interrupt {
        fn permits(&self, scope: &SignedRetentionScope) -> bool {
            self.0.set(self.0.get() + 1);
            RetainConsent.permits(scope) && self.0.get() < 3
        }
    }
    let signed_path = dir.path().join("private-signed.db");
    let signed_key = DatabaseKey::from_bytes([0x65; 32]);
    let encrypted = create_encrypted(&signed_path, &signed_key).unwrap();
    encrypted
        .connection()
        .execute_batch("PRAGMA synchronous=OFF;")
        .unwrap();
    let journal = SignedResultJournal::from_encrypted_connection(encrypted).unwrap();
    let retain = |journal: &SignedResultJournal,
                  key: &str,
                  ds: &[AuthenticatedSignatureDelivery<'_>],
                  consent: &dyn SignedRetentionConsent,
                  at: &Timestamp| {
        retain_deliveries(
            &checkpoint,
            "synthetic-agreement",
            "synthetic-proposal",
            1,
            ds,
            at,
            key,
            LocalSignedRetention { journal, consent },
            &FixtureConsent,
            false,
        )
    };
    let historical = |journal: &SignedResultJournal,
                      key: &str,
                      ds: &[AuthenticatedSignatureDelivery<'_>],
                      consent: &dyn SignedRetentionConsent| {
        retain_deliveries(
            &checkpoint,
            "synthetic-agreement",
            "synthetic-proposal",
            1,
            ds,
            &Timestamp::from_unix_seconds(now.unix_seconds() + 600).unwrap(),
            key,
            LocalSignedRetention { journal, consent },
            &FixtureConsent,
            true,
        )
    };
    assert_eq!(
        historical(
            &journal,
            "no-existing-intent-key",
            &deliveries,
            &RetainConsent
        )
        .unwrap_err()
        .code,
        "SIGNED_RETENTION_INTENT_NOT_FOUND"
    );
    assert_eq!(
        retain(
            &journal,
            "synthetic-retention-key",
            &deliveries,
            &Deny,
            &now
        )
        .unwrap_err()
        .code,
        "SIGNED_RETENTION_CONSENT_DENIED"
    );
    assert_eq!(
        retain(
            &journal,
            "synthetic-retention-key",
            &missing,
            &RetainConsent,
            &now
        )
        .unwrap_err()
        .code,
        "ACCOUNT_ASSOCIATION_UNAVAILABLE"
    );
    assert_eq!(
        retain(
            &journal,
            "synthetic-retention-key",
            &deliveries,
            &Interrupt(std::cell::Cell::new(0)),
            &now
        )
        .unwrap_err()
        .code,
        "SIGNED_RETENTION_CONSENT_DENIED"
    );
    drop(journal);
    let journal = SignedResultJournal::from_encrypted_connection(
        wholepact_storage_security::open_encrypted(&signed_path, &signed_key).unwrap(),
    )
    .unwrap();
    assert_eq!(
        retain(
            &journal,
            "synthetic-retention-key",
            &deliveries[..1],
            &RetainConsent,
            &now
        )
        .unwrap_err()
        .code,
        "SIGNED_RETENTION_IDEMPOTENCY_CONFLICT"
    );
    let saved = historical(
        &journal,
        "synthetic-retention-key",
        &deliveries,
        &RetainConsent,
    )
    .unwrap();
    assert!(saved.historical_reconciliation);
    assert!(!saved.exact_replay);
    assert!(saved.inspection.signatures_complete);
    assert!(
        !saved.transaction_extracted && !saved.authorization_allowed && !saved.distribution_allowed
    );
    drop(journal);
    let journal = SignedResultJournal::from_encrypted_connection(
        wholepact_storage_security::open_encrypted(&signed_path, &signed_key).unwrap(),
    )
    .unwrap();
    let replay = historical(
        &journal,
        "synthetic-retention-key",
        &deliveries,
        &RetainConsent,
    )
    .unwrap();
    assert!(replay.historical_reconciliation);
    assert!(replay.exact_replay);
    assert_eq!(saved.result_id, replay.result_id);
    assert_eq!(saved.request_digest, replay.request_digest);
    assert_eq!(
        saved.signed_candidate_digest,
        replay.signed_candidate_digest
    );
    assert_eq!(
        retain(
            &journal,
            "synthetic-retention-key",
            &deliveries,
            &Deny,
            &now
        )
        .unwrap_err()
        .code,
        "SIGNED_RETENTION_CONSENT_DENIED"
    );
    assert!(retain(
        &journal,
        "synthetic-retention-key",
        &deliveries,
        &RetainConsent,
        &Timestamp::from_unix_seconds(now.unix_seconds() + 60).unwrap()
    )
    .is_err());
    assert_eq!(
        historical(&journal, "synthetic-retention-key", &deliveries, &Deny)
            .unwrap_err()
            .code,
        "SIGNED_RETENTION_CONSENT_DENIED"
    );
    assert_eq!(
        historical(
            &journal,
            "synthetic-retention-key",
            &deliveries[..1],
            &RetainConsent
        )
        .unwrap_err()
        .code,
        "SIGNED_RETENTION_IDEMPOTENCY_CONFLICT"
    );
    let unchanged = jobs
        .load_verified(&scope.principal_id, &queued.job_id, &FixtureConsent)
        .unwrap();
    assert_eq!(unchanged.pczt_bytes(), original);
    assert!(!std::fs::read(&signed_path)
        .unwrap()
        .windows(16)
        .any(|w| w == b"SQLite format 3\0"));
    // Check representative private byte canaries in both encrypted main and WAL
    // pages; this is focused fixture evidence, not a complete storage audit.
    for path in [signed_path.clone(), signed_path.with_extension("db-wal")] {
        if let Ok(disk) = std::fs::read(path) {
            assert!(!disk.windows(32).any(|w| w == &signature_records[0].2[..32]));
            assert!(!disk
                .windows(scope.principal_id.len())
                .any(|w| w == scope.principal_id.as_bytes()));
        }
    }
    let audit = wholepact_storage_security::open_encrypted(&signed_path, &signed_key).unwrap();
    assert_eq!(
        audit
            .connection()
            .query_row("SELECT count(*) FROM signed_intents", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        audit
            .connection()
            .query_row("SELECT count(*) FROM signed_results", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert!(audit
        .connection()
        .execute("UPDATE signed_results SET digest='replacement'", [])
        .is_err());
    assert!(audit
        .connection()
        .execute("DELETE FROM signed_intents", [])
        .is_err());
    let retained_bytes: Vec<u8> = audit
        .connection()
        .query_row("SELECT bytes FROM signed_results", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&retained_bytes)),
        replay.signed_candidate_digest
    );
    drop(audit);
    #[cfg(feature = "transaction-checkpoint")]
    {
        use wholepact_protocol::authorization::retention::transaction::{
            LocalTransactionCheckpoint, TransactionCheckpointJournal, TransactionRetentionConsent,
            TransactionRetentionScope,
        };
        struct RetainTransaction;
        impl TransactionRetentionConsent for RetainTransaction {
            fn permits(&self, scope: &TransactionRetentionScope) -> bool {
                RetainConsent.permits(&scope.signed_scope)
                    && scope.signed_candidate_digest.len() == 64
                    && scope.signed_request_digest.len() == 64
            }
        }
        struct DenyTransaction;
        impl TransactionRetentionConsent for DenyTransaction {
            fn permits(&self, _: &TransactionRetentionScope) -> bool {
                false
            }
        }
        struct InterruptTransaction(std::cell::Cell<usize>);
        impl TransactionRetentionConsent for InterruptTransaction {
            fn permits(&self, scope: &TransactionRetentionScope) -> bool {
                self.0.set(self.0.get() + 1);
                RetainTransaction.permits(scope) && self.0.get() < 4
            }
        }
        let tx_path = dir.path().join("private-transaction.db");
        let tx_key = DatabaseKey::from_bytes([0x66; 32]);
        let transactions = TransactionCheckpointJournal::from_encrypted_connection(
            create_encrypted(&tx_path, &tx_key).unwrap(),
        )
        .unwrap();
        let extract = |transactions: &TransactionCheckpointJournal,
                       key: &str,
                       ds: &[AuthenticatedSignatureDelivery<'_>],
                       consent: &dyn TransactionRetentionConsent| {
            checkpoint_transaction_deliveries(
                &checkpoint,
                "synthetic-agreement",
                "synthetic-proposal",
                1,
                ds,
                &Timestamp::from_unix_seconds(now.unix_seconds() + 600).unwrap(),
                key,
                LocalSignedRetention {
                    journal: &journal,
                    consent: &RetainConsent,
                },
                &FixtureConsent,
                LocalTransactionCheckpoint {
                    journal: transactions,
                    consent,
                },
            )
        };
        assert_eq!(
            extract(
                &transactions,
                "synthetic-retention-key",
                &deliveries,
                &DenyTransaction
            )
            .unwrap_err()
            .code,
            "TRANSACTION_RETENTION_CONSENT_DENIED"
        );
        assert_eq!(
            extract(
                &transactions,
                "missing-signed-key",
                &deliveries,
                &RetainTransaction
            )
            .unwrap_err()
            .code,
            "SIGNED_RETENTION_INTENT_NOT_FOUND"
        );
        assert_eq!(
            extract(
                &transactions,
                "synthetic-retention-key",
                &missing,
                &RetainTransaction
            )
            .unwrap_err()
            .code,
            "ACCOUNT_ASSOCIATION_UNAVAILABLE"
        );
        retain(
            &journal,
            "partial-retention-key",
            &deliveries[..1],
            &RetainConsent,
            &now,
        )
        .unwrap();
        assert_eq!(
            extract(
                &transactions,
                "partial-retention-key",
                &deliveries[..1],
                &RetainTransaction
            )
            .unwrap_err()
            .code,
            "TRANSACTION_SIGNATURES_INCOMPLETE"
        );
        let extracted = extract(
            &transactions,
            "synthetic-retention-key",
            &deliveries,
            &RetainTransaction,
        )
        .unwrap();
        assert!(
            !extracted.exact_replay
                && extracted.transaction_extracted
                && extracted.cryptographic_transaction_verified
        );
        assert!(
            !extracted.chain_validated
                && !extracted.authorization_allowed
                && !extracted.distribution_allowed
                && !extracted.release_allowed
        );
        drop(transactions);
        let transactions = TransactionCheckpointJournal::from_encrypted_connection(
            wholepact_storage_security::open_encrypted(&tx_path, &tx_key).unwrap(),
        )
        .unwrap();
        let replayed = extract(
            &transactions,
            "synthetic-retention-key",
            &deliveries,
            &RetainTransaction,
        )
        .unwrap();
        assert!(replayed.exact_replay);
        assert_eq!(extracted.transaction_digest, replayed.transaction_digest);
        assert_eq!(extracted.txid, replayed.txid);
        assert_eq!(
            extract(
                &transactions,
                "synthetic-retention-key",
                &deliveries,
                &DenyTransaction
            )
            .unwrap_err()
            .code,
            "TRANSACTION_RETENTION_CONSENT_DENIED"
        );
        let uncertain_path = dir.path().join("uncertain-transaction.db");
        let uncertain = TransactionCheckpointJournal::from_encrypted_connection(
            create_encrypted(&uncertain_path, &tx_key).unwrap(),
        )
        .unwrap();
        assert_eq!(
            extract(
                &uncertain,
                "synthetic-retention-key",
                &deliveries,
                &InterruptTransaction(std::cell::Cell::new(0))
            )
            .unwrap_err()
            .code,
            "TRANSACTION_RETENTION_CONSENT_DENIED"
        );
        drop(uncertain);
        let uncertain = TransactionCheckpointJournal::from_encrypted_connection(
            wholepact_storage_security::open_encrypted(&uncertain_path, &tx_key).unwrap(),
        )
        .unwrap();
        assert_eq!(
            extract(
                &uncertain,
                "synthetic-retention-key",
                &deliveries,
                &RetainTransaction
            )
            .unwrap_err()
            .code,
            "TRANSACTION_CHECKPOINT_RECOVERY_REQUIRED"
        );
        // Synthetic fault injection bypasses immutable triggers deliberately;
        // replays must independently reject corrupted hash, txid and auth bytes.
        let audit = wholepact_storage_security::open_encrypted(&tx_path, &tx_key).unwrap();
        let tx_bytes: Vec<u8> = audit
            .connection()
            .query_row("SELECT bytes FROM transaction_results", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&tx_bytes)),
            extracted.transaction_digest
        );
        assert!(audit
            .connection()
            .execute("DELETE FROM transaction_intents", [])
            .is_err());
        assert!(audit
            .connection()
            .execute("UPDATE transaction_results SET txid='bad'", [])
            .is_err());
        audit
            .connection()
            .execute_batch("DROP TRIGGER immutable_transaction_result_update;")
            .unwrap();
        audit
            .connection()
            .execute("UPDATE transaction_results SET digest='bad'", [])
            .unwrap();
        assert_eq!(
            extract(
                &transactions,
                "synthetic-retention-key",
                &deliveries,
                &RetainTransaction
            )
            .unwrap_err()
            .code,
            "TRANSACTION_CHECKPOINT_REJECTED"
        );
        audit
            .connection()
            .execute(
                "UPDATE transaction_results SET digest=?1,txid='bad'",
                [&extracted.transaction_digest],
            )
            .unwrap();
        assert_eq!(
            extract(
                &transactions,
                "synthetic-retention-key",
                &deliveries,
                &RetainTransaction
            )
            .unwrap_err()
            .code,
            "TRANSACTION_CHECKPOINT_REJECTED"
        );
        let mut tampered = tx_bytes.clone();
        *tampered.last_mut().unwrap() ^= 1;
        audit
            .connection()
            .execute(
                "UPDATE transaction_results SET bytes=?1,digest=?2,txid=?3",
                (
                    tampered.as_slice(),
                    hex::encode(Sha256::digest(&tampered)),
                    extracted.txid.as_str(),
                ),
            )
            .unwrap();
        assert_eq!(
            extract(
                &transactions,
                "synthetic-retention-key",
                &deliveries,
                &RetainTransaction
            )
            .unwrap_err()
            .code,
            "TRANSACTION_CHECKPOINT_REJECTED"
        );
        // Use only parameter binding, never render raw private bytes into SQL.
        let disk = std::fs::read(&tx_path).unwrap();
        assert!(!disk
            .windows(32)
            .any(|w| w == &tx_bytes[tx_bytes.len() - 32..]));
    }
    let make_signature = |owner: usize, action: usize, signature: [u8; 64]| {
        wholepact_protocol::authorization::ExternalSignature {
            participant_index: owner,
            action_index: action,
            signature,
        }
    };
    let (owner, action, signature) = signature_records[0];
    let validate = |records: &[wholepact_protocol::authorization::ExternalSignature],
                    binding: &str| {
        wholepact_protocol::authorization::inspect_external_signatures(
            &original,
            checkpoint.policy(),
            binding,
            records,
            ProvingLimits { maximum_actions: 8 },
        )
    };
    assert!(validate(
        &[
            make_signature(owner, action, signature),
            make_signature(owner, action, signature)
        ],
        &scope.review_binding
    )
    .is_err());
    assert!(validate(
        &[make_signature(1 - owner, action, signature)],
        &scope.review_binding
    )
    .is_err());
    assert!(validate(
        &[make_signature(owner, usize::MAX, signature)],
        &scope.review_binding
    )
    .is_err());
    assert!(validate(
        &[make_signature(owner, action, signature)],
        &"00".repeat(32)
    )
    .is_err());
    let bad_signature = wholepact_protocol::authorization::ExternalSignature {
        participant_index: 0,
        action_index: checkpoint.policy().inputs[0].action_index,
        signature: [0; 64],
    };
    assert!(
        wholepact_protocol::authorization::inspect_external_signatures(
            &original,
            checkpoint.policy(),
            &scope.review_binding,
            &[bad_signature],
            ProvingLimits { maximum_actions: 8 }
        )
        .is_err()
    );
}
