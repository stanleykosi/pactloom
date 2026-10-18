//! Synthetic encrypted archive/source tests. No production enrollment, keys,
//! offline issuance, proof verification, sockets or financial execution.
use super::*;
use crate::consent_journal::offline_history::tests::{
    connection, full_admission, h, insert_keyuse, insert_local, insert_original, insert_remote,
    minimal, original,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use wholepact_storage_security::bundle::*;

struct SourceFixture {
    dir: tempfile::TempDir,
    journal: SignerConsentJournal,
}
impl SourceFixture {
    fn new() -> Self {
        Self::new_for("synthetic-account")
    }
    fn new_for(account: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let private_directory = crate::files::PrivateDirectory::open(dir.path()).unwrap();
        let journal = SignerConsentJournal::create_encrypted(
            &dir.path().join("synthetic-source.sqlite"),
            &DatabaseKey::from_bytes([0x71; 32]),
            account,
            1,
            false,
            &private_directory
                .signer_journal_source_owner_for_test(&dir.path().join("synthetic-source.sqlite"))
                .unwrap(),
        )
        .unwrap();
        Self { dir, journal }
    }
    fn archive(&self) -> VerifiedSignerRecoverySource {
        let archive = self.dir.path().join("synthetic-archive.sqlite");
        let restored = self.dir.path().join("synthetic-restored.sqlite");
        let archive_key = DatabaseKey::from_bytes([0x72; 32]);
        let restored_key = DatabaseKey::from_bytes([0x73; 32]);
        let adapter = self.journal.backup_adapter();
        let sources = [RegisteredJournal::new("signer-authority", &adapter).unwrap()];
        snapshot(SnapshotRequest {
            principal_id: "synthetic-owner",
            profile_id: "synthetic-signer-profile",
            coverage: Coverage {
                present: BTreeMap::from([(
                    JournalKind::SignerConsentAuthority,
                    vec!["signer-authority".into()],
                )]),
                absent: BTreeSet::from([
                    JournalKind::CoordinationAuthority,
                    JournalKind::WalletScan,
                    JournalKind::ProofWitness,
                    JournalKind::SignedResults,
                    JournalKind::ExactTransactions,
                    JournalKind::Submission,
                    JournalKind::TransportInbox,
                    JournalKind::TransportOutbox,
                ]),
            },
            sources: &sources,
            destination: &archive,
            key: &archive_key,
            authority: &crate::consent_journal::tests::BackupGate,
        })
        .unwrap();
        restore(RestoreRequest {
            principal_id: "synthetic-owner",
            profile_id: "synthetic-signer-profile",
            archive: &archive,
            key: &archive_key,
            targets: &[RestoreTarget {
                component_id: "signer-authority",
                template: SignerConsentBundleAdapter::template(),
                destination: &restored,
                key: &restored_key,
            }],
            authority: &crate::consent_journal::tests::BackupGate,
        })
        .unwrap();
        VerifiedSignerRecoverySource::open(
            history::HistoryOpenRequest {
                archive: &archive,
                archive_key: &archive_key,
                component_id: "signer-authority",
                restored_component: &restored,
                restored_key: &restored_key,
            },
            SignerConsentBundleAdapter::template(),
        )
        .unwrap()
    }
}
fn tree(path: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut result = BTreeMap::new();
    for entry in std::fs::read_dir(path).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            result.extend(tree(&path));
        } else {
            result.insert(path.clone(), std::fs::read(path).unwrap());
        }
    }
    result
}
fn assert_exact_source_rows(c: &Connection, source: &VerifiedSignerRecoverySource) {
    for table in source.tables() {
        let count: u64 = c
            .query_row(&format!("SELECT count(*) FROM {}", table.name()), [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(count, table.rows().len() as u64);
        let sql = format!("SELECT * FROM {} WHERE rowid=?1", table.name());
        for row in table.rows() {
            let actual: Vec<Value> = c
                .query_row(&sql, [row.rowid().unwrap()], |r| {
                    (0..table.columns().len()).map(|i| r.get(i)).collect()
                })
                .unwrap();
            let expected: Vec<Value> = row
                .cells()
                .iter()
                .map(|cell| match cell {
                    RecoveryCell::Null => Value::Null,
                    RecoveryCell::Integer(v) => Value::Integer(*v),
                    RecoveryCell::Text(v) => Value::Text(v.clone()),
                    _ => panic!("unexpected synthetic source cell type"),
                })
                .collect();
            assert_eq!(actual, expected);
        }
    }
}
fn receipt(c: &Connection, authorization: &str, stage: u8) {
    let bytes = b"synthetic retained ciphertext, not an authenticated envelope";
    let mut hasher = Sha256::new();
    hasher.update(b"wholepact.encrypted-envelope.v1\0");
    hasher.update(bytes);
    let envelope = hex::encode(hasher.finalize());
    c.execute(
        "INSERT INTO signer_offline_review_inputs VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            authorization,
            "synthetic-account",
            h(90),
            h(91),
            envelope,
            hex::encode(bytes)
        ],
    )
    .unwrap();
    if stage == 0 {
        return;
    }
    #[derive(Serialize)]
    struct SyntheticReceipt<'a> {
        account_id: &'a str,
        authorization_id: &'a str,
        owner_setup_digest: String,
        terms_digest: String,
        package_digest: String,
        preview_json: &'a str,
        sequence: u64,
        envelope_digest: String,
        content_digest: String,
    }
    let record = SyntheticReceipt {
        account_id: "synthetic-account",
        authorization_id: authorization,
        owner_setup_digest: h(92),
        terms_digest: h(90),
        package_digest: h(91),
        preview_json: "{\"synthetic_history_only\":true}",
        sequence: 1,
        envelope_digest: envelope,
        content_digest: h(93),
    };
    let reference = digest("wholepact:offline-review-receipt:v1", &record).unwrap();
    c.execute(
        "INSERT INTO signer_offline_review_authenticated VALUES(?1,?2,?3)",
        params![authorization, reference, encode(&record).unwrap().as_str()],
    )
    .unwrap();
    if stage == 2 {
        c.execute(
            "INSERT INTO signer_offline_review_accepted VALUES(?1,?2)",
            params![authorization, reference],
        )
        .unwrap();
    }
}

#[test]
fn sealed_minimal_source_preserves_all_rows_and_does_not_gain_private_admission_or_epoch() {
    let fixture = SourceFixture::new();
    let (admission, _, _) = full_admission();
    let local = minimal(&admission);
    {
        let c = fixture.journal.connection.lock().unwrap();
        insert_local(&c, &local);
        let consent = original(&local);
        insert_original(&c, &consent);
        insert_keyuse(&c, &consent);
        receipt(&c, "synthetic-pending-receipt", 0);
    }
    let source = fixture.archive();
    let before = tree(fixture.dir.path());
    with_complete_source(&source, |tx| {
        assert_exact_source_rows(tx, &source);
        let state = storage::read_account(tx)?;
        assert_eq!(state.writer_epoch, 1);
        let local = writer_history::WriterLocalInventory::read(
            tx,
            &state,
            (MAX_BACKUP_ROWS, MAX_BACKUP_ENCODED_BYTES),
        )?;
        let origins = local.offline_history().admitted_origins();
        assert_eq!(origins.len(), 1);
        assert!(origins[0].local_admission().is_some());
        assert!(origins[0].admission().is_none());
        assert!(origins[0].provenance().is_none());
        assert_eq!(
            origins[0].signature_knowledge(),
            OfflineSignatureKnowledge::LocalKeyUseStartedSignatureUnknown
        );
        let joined = offline_reconciliation::join_replayed(local.offline_history(), [])?;
        assert_eq!(joined.offline_origins()[0].replayed_writer_epoch(), None);
        assert!(matches!(
            joined.require_retained_offline_coverage(),
            Err(JournalError::RecoveryRequired)
        ));
        assert_eq!(receipt_inventory(tx, "synthetic-account")?.len(), 1);
        Ok(())
    })
    .unwrap();
    assert_eq!(before, tree(fixture.dir.path()));
    assert!(matches!(
        RecoveryActivationInventory::prepare(
            &source,
            "synthetic-recovery".into(),
            h(94),
            fixture.dir.path().join("target"),
            full_admission().2.witness,
            h(95),
        ),
        Err(JournalError::OfflineHistoryUnsupported)
    ));
    assert!(!fixture.dir.path().join("target").exists());
}

#[test]
fn complete_source_keeps_remote_and_local_origin_result_and_every_receipt_state() {
    let fixture = SourceFixture::new();
    let (admission, policy, provenance) = full_admission();
    {
        let c = fixture.journal.connection.lock().unwrap();
        insert_remote(&c, &admission, &policy, &provenance);
        let local = minimal(&admission);
        insert_local(&c, &local);
        let consent = original(&local);
        insert_original(&c, &consent);
        insert_keyuse(&c, &consent);
        let bytes = b"synthetic unverified result, no signatures";
        let result = OfflineRetainedResultHistory {
            authorization_id: consent.authorization_id.clone(),
            original_consent_ref: consent.reference.clone(),
            admission_request_digest: consent.admission_request_digest.clone(),
            authenticated_package_digest: consent.authenticated_package_digest.clone(),
            signed_artifact_digest: hex::encode(Sha256::digest(bytes)),
            return_recipient_key_digest: consent.return_recipient_key_digest.clone(),
        };
        c.execute(
            "INSERT INTO signer_offline_results VALUES(?1,?2,?3,?4)",
            params![
                result.authorization_id,
                result.signed_artifact_digest,
                hex::encode(bytes),
                encode(&result).unwrap().as_str()
            ],
        )
        .unwrap();
        receipt(&c, "receipt-a", 0);
        receipt(&c, "receipt-b", 1);
        receipt(&c, "receipt-c", 2);
    }
    let source = fixture.archive();
    with_complete_source(&source, |tx| {
        assert_exact_source_rows(tx, &source);
        let local = offline_history::read_inventory(tx, "synthetic-account")?;
        assert_eq!(local.enrollments().len(), 1);
        assert_eq!(local.reservation_intents().len(), 1);
        let origin = &local.admitted_origins()[0];
        assert!(origin.admission() == Some(&admission));
        assert!(origin.provenance() == Some(&provenance));
        assert_eq!(
            origin.signature_knowledge(),
            OfflineSignatureKnowledge::ExactResultRetainedCurrentValidityUnknown
        );
        let receipts = receipt_inventory(tx, "synthetic-account")?;
        assert_eq!(receipts.len(), 3);
        assert!(receipts[0].authenticated_receipt_digest.is_none());
        assert!(receipts[1].authenticated_receipt_digest.is_some());
        assert!(receipts[1].accepted_receipt_digest.is_none());
        assert!(receipts[2].accepted_receipt_digest.is_some());
        Ok(())
    })
    .unwrap();
}

#[test]
fn accepted_receipt_without_original_authentication_is_not_a_recovery_fact() {
    let c = connection();
    receipt(&c, "receipt-a", 0);
    c.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
    c.execute(
        "INSERT INTO signer_offline_review_accepted VALUES('receipt-a',?1)",
        [h(99)],
    )
    .unwrap();
    assert!(receipt_inventory(&c, "synthetic-account").is_err());
}

#[cfg(feature = "synthetic-qualification")]
#[test]
fn receipt_only_complete_plan_blocks_successor_before_schema_or_exposure_writes() {
    use wholepact_authority::{AuthorityJournal, transport::synthetic};
    let fixture = SourceFixture::new();
    receipt(&fixture.journal.connection.lock().unwrap(), "receipt-a", 2);
    let source = fixture.archive();
    let mut policy = full_admission().2.account_policy;
    let now = now_ms().unwrap();
    policy.policy_expires_at_ms = now + 120_000;
    let witness = AuthorityJournal::create_encrypted(
        &fixture.dir.path().join("synthetic-witness.sqlite"),
        &DatabaseKey::from_bytes([0x74; 32]),
        policy.clone(),
    )
    .unwrap();
    synthetic::activate(&witness, &policy.initial_writer_certificate_digest, now).unwrap();
    let (replayed, _) = synthetic::reconciled_session(
        &witness,
        &policy.initial_writer_certificate_digest,
        &policy.account_id,
        &policy.network_profile_id,
    )
    .unwrap();
    let prepared = PreparedRecoveryHistory::read(&source, &replayed).unwrap();
    assert!(prepared.has_offline());
    assert!(matches!(
        prepared.require_enabled(),
        Err(JournalError::OfflineHistoryUnsupported)
    ));
    let retention = account_use_recovery::reconcile_complete(&source, &replayed).unwrap();
    let record = RecoveryActivationRecord {
        account_use_retention_digest: None,
        operation_id: "synthetic-recovery".into(),
        generation_id: h(80),
        inventory_digest: h(81),
        fence_digest: h(82),
        history_digest: h(83),
        account_id: policy.account_id,
        writer_epoch: 2,
        source_bundle_digest: h(84),
        source_component_digest: h(85),
        target_profile: fixture.dir.path().join("never-created"),
        review_digest: h(86),
    };
    let mut target = Connection::open_in_memory().unwrap();
    let tx = target.transaction().unwrap();
    assert!(matches!(
        populate_successor(&tx, &source, &prepared, &record, &retention),
        Err(JournalError::OfflineHistoryUnsupported)
    ));
    assert!(matches!(
        prepared.import_on(&tx, &record.account_id),
        Err(JournalError::OfflineHistoryUnsupported)
    ));
    let count: i64 = tx
        .query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn complete_source_retains_genesis_permanent_exclusion_and_witness_ack_exactly() {
    use wholepact_authority::{
        AuthorityHead,
        account_use::{
            AccountUseGenesis, AccountUseIdentity, ExclusionReason, PermanentAccountExclusion,
        },
        account_use_link::AccountExclusionReceipt,
    };
    let account = h(70);
    let fixture = SourceFixture::new_for(&account);
    let genesis = AccountUseGenesis {
        version: 1,
        identity: AccountUseIdentity {
            account_id: account.clone(),
            full_viewing_key_digest: h(71),
            network_profile_id: "synthetic-testnet".into(),
            derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
        },
        witness_id: "synthetic-witness".into(),
        witness_origin_digest: h(72),
        owner_certificate_digest: h(73),
        native_birth_digest: h(74),
    };
    let exclusion = PermanentAccountExclusion {
        version: 1,
        identity: genesis.identity.clone(),
        genesis_digest: genesis.digest().unwrap(),
        operation_id: "synthetic-permanent-exclusion".into(),
        native_review_digest: h(75),
        reason: ExclusionReason::RetirementRequested,
    };
    let ack = AccountExclusionReceipt {
        genesis_digest: genesis.digest().unwrap(),
        exclusion_digest: exclusion.digest().unwrap(),
        witness_origin_digest: genesis.witness_origin_digest.clone(),
        committed_head: AuthorityHead {
            sequence: 3,
            digest: h(76),
        },
        operation_id: exclusion.operation_id.clone(),
    };
    {
        let c = fixture.journal.connection.lock().unwrap();
        c.execute(
            "INSERT INTO signer_account_use_genesis VALUES(1,?1,?2,?3,?4)",
            params![
                account,
                genesis.identity.full_viewing_key_digest,
                genesis.digest().unwrap(),
                encode(&genesis).unwrap().as_str()
            ],
        )
        .unwrap();
        c.execute(
            "INSERT INTO signer_account_use_exclusion VALUES(1,?1,?2,?3)",
            params![
                exclusion.genesis_digest,
                exclusion.digest().unwrap(),
                encode(&exclusion).unwrap().as_str()
            ],
        )
        .unwrap();
        c.execute(
            "INSERT INTO signer_account_use_witness_ack VALUES(?1,?2,?3,?4,?5)",
            params![
                ack.exclusion_digest,
                ack.witness_origin_digest,
                ack.committed_head.digest,
                ack.digest().unwrap(),
                encode(&ack).unwrap().as_str()
            ],
        )
        .unwrap();
    }
    let source = fixture.archive();
    with_complete_source(&source, |tx| {
        assert_exact_source_rows(tx, &source);
        let retained = account_use_storage::inspect(tx, &account)?;
        assert!(retained.genesis() == Some(&genesis));
        assert!(retained.exclusion() == Some(&exclusion));
        assert!(retained.witness_ack() == Some(&ack));
        assert_eq!(storage::read_account(tx)?.writer_epoch, 1);
        Ok(())
    })
    .unwrap();
}

#[cfg(feature = "synthetic-qualification")]
#[test]
fn pending_birth_metadata_uses_distinct_review_and_cannot_change_during_recheck() {
    use wholepact_authority::{AuthorityJournal, transport::synthetic};
    let fixture = SourceFixture::new();
    let source = fixture.archive();
    let mut policy = full_admission().2.account_policy;
    let now = now_ms().unwrap();
    policy.policy_expires_at_ms = now + 120_000;
    let witness = AuthorityJournal::create_encrypted(
        &fixture.dir.path().join("synthetic-review-witness.sqlite"),
        &DatabaseKey::from_bytes([0x74; 32]),
        policy.clone(),
    )
    .unwrap();
    synthetic::activate(&witness, &policy.initial_writer_certificate_digest, now).unwrap();
    let (replayed, _) = synthetic::reconciled_session(
        &witness,
        &policy.initial_writer_certificate_digest,
        &policy.account_id,
        &policy.network_profile_id,
    )
    .unwrap();
    let mut original = PreparedRecoveryHistory::read(&source, &replayed).unwrap();
    let mut current = PreparedRecoveryHistory::read(&source, &replayed).unwrap();
    assert!(!original.uses_v2_review());
    original.require_identical(&current).unwrap();
    // Test-only value injection exercises review/recheck representation. It
    // does not fabricate authenticated born replay or an activation capability.
    let commit = crate::authority_bridge::host_recovery_ipc::v2::tests::pending_birth_fixture()
        .complete_history
        .pending_birth_commit
        .unwrap();
    original.pending_birth_commit = Some(commit.clone());
    current.pending_birth_commit = Some(commit);
    assert!(original.uses_v2_review());
    assert!(!original.has_offline());
    original.require_enabled().unwrap();
    original.require_identical(&current).unwrap();
    current
        .pending_birth_commit
        .as_mut()
        .unwrap()
        .owner_approval_evidence_digest = h(97);
    assert!(original.require_identical(&current).is_err());
    current.pending_birth_commit = None;
    assert!(original.require_identical(&current).is_err());
}
