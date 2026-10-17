//! Public synthetic keys and temporary encrypted historical records only.
//! Direct test SQL never constructs a native decision or a live namespace owner.
use super::*;
use crate::born_offline_artifacts_v1::*;
use crate::offline_witness_transport_v1 as mail;
use wholepact_storage_security::generation_archive as capsule;

fn append(tx: &Transaction<'_>, ledger: &mut Ledger, event: &Event) {
    let previous = ledger.snapshot.head.digest.clone();
    ledger.apply(event).unwrap();
    tx.execute(
        "INSERT INTO authority_events VALUES(?1,?2,?3,?4,?5)",
        params![
            ledger.snapshot.head.sequence,
            event.mutation.operation_id(),
            previous,
            ledger.snapshot.head.digest,
            &*encode(event).unwrap()
        ],
    )
    .unwrap();
}
fn extension(tx: &Transaction<'_>, record: &BornOfflineArtifactRecordV1) {
    tx.execute_batch(schema_v7().strip_prefix(SCHEMA).unwrap())
        .unwrap();
    tx.execute(
        "INSERT INTO authority_born_offline_artifacts VALUES(1,?1,?2)",
        params![&*encode(record).unwrap(), [0x51u8; 32].as_slice()],
    )
    .unwrap();
    tx.pragma_update(None, "user_version", 7).unwrap();
}
fn fixture(path: &Path, key: &DatabaseKey) -> (EncryptedConnection, BornOfflineArtifactRecordV1) {
    let c = write_fixture(path, key, false);
    let (birth, _, _, _) = bootstrap_events();
    let mut ledger = load(c.connection()).unwrap();
    let mut enrollment = crate::born_offline_enrollment_v1::tests::record(&ledger, &birth);
    let witness = mail::TransportSecret::from_bytes([0x51; 32])
        .unwrap()
        .public_key()
        .unwrap();
    let signer = mail::TransportSecret::from_bytes([0x52; 32])
        .unwrap()
        .public_key()
        .unwrap();
    enrollment.enrollment.policy.witness_transport_key_digest = witness.fingerprint();
    enrollment.enrollment.policy.offline_signer_key_digest = signer.fingerprint();
    let event = crate::born_offline_enrollment_v1::tests::event(&ledger, &enrollment);
    let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate).unwrap();
    append(&tx, &mut ledger, &event);
    tx.commit().unwrap();
    let record = BornOfflineArtifactRecordV1 {
        binding: BornOfflineArtifactBindingV1 {
            version: 1,
            enrollment_digest: enrollment.enrollment.digest().unwrap(),
            namespace_binding_digest: "a".repeat(64),
            witness_public_key_hex: hex::encode(witness.as_bytes()),
            offline_signer_public_key_hex: hex::encode(signer.as_bytes()),
            expected_head: ledger.snapshot.head.clone(),
            issued_at_ms: ledger.snapshot.last_witness_time_ms + 1,
            first_commit_deadline_ms: enrollment.enrollment.policy.expires_at_ms,
        },
        native_review_digest: "b".repeat(64),
    };
    let event = Event {
        mutation: AuthorityMutation::OwnerControl(OwnerControlRequest {
            operation_id: record.binding.owner_operation_id().unwrap(),
            account_id: ledger.policy.account_id.clone(),
            network_profile_id: ledger.policy.network_profile_id.clone(),
            expected_head: ledger.snapshot.head.clone(),
            writer_epoch: ledger.snapshot.writer_epoch,
            control: OwnerControl::InstallBornOfflineArtifactsV1 {
                record: Box::new(record.clone()),
            },
        }),
        authenticated_certificate_digest: ledger.policy.owner_certificate_digest.clone(),
        witness_time_ms: record.binding.issued_at_ms + 1,
        writer_session_id: None,
        original_request_link: None,
    };
    let before = crate::journal::namespace_account_stamp(c.connection(), &ledger.policy)
        .unwrap()
        .0;
    {
        let tx =
            Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate).unwrap();
        extension(&tx, &record);
        assert!(load(&tx).is_err()); // no matching event yet
        // No native decision is constructed; dropping rolls back all new rows.
    }
    verify_schema(c.connection()).unwrap();
    assert!(
        crate::journal::namespace_account_stamp(c.connection(), &ledger.policy)
            .unwrap()
            .0
            == before
    );
    let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate).unwrap();
    extension(&tx, &record);
    append(&tx, &mut ledger, &event);
    verify_born_artifact_schema_v1(&tx).unwrap();
    tx.commit().unwrap();
    assert!(
        load(c.connection())
            .unwrap()
            .born_offline_artifacts_v1()
            .unwrap()
            == Some(&record)
    );
    (c, record)
}

struct SyntheticCapture {
    expected: capsule::ArchiveScope,
    lock: std::fs::File,
}
struct SyntheticLease<'a>(&'a SyntheticCapture);
impl capsule::ArchiveAuthority for SyntheticCapture {
    fn acquire<'a>(
        &'a self,
        scope: &capsule::ArchiveScope,
    ) -> capsule::Result<Box<dyn capsule::ArchiveLease + 'a>> {
        if scope != &self.expected {
            return Err(capsule::ArchiveError::Permission);
        }
        Ok(Box::new(SyntheticLease(self)))
    }
}
impl capsule::ArchiveLease for SyntheticLease<'_> {
    fn check_current(&self) -> capsule::Result<()> {
        self.0
            .lock
            .metadata()
            .map(|_| ())
            .map_err(|_| capsule::ArchiveError::Storage)
    }
}
#[test]
fn encrypted_schema7_rollback_reopen_and_whole_archive_remain_historical() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = temp.path().join("synthetic-born-artifacts.wp");
    let key = DatabaseKey::from_bytes([0x53; 32]);
    let (c, record) = fixture(&path, &key);
    let ledger = load(c.connection()).unwrap();
    let stamp = crate::journal::namespace_account_stamp(c.connection(), &ledger.policy)
        .unwrap()
        .0;
    let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate).unwrap();
    let trigger: String = tx
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name='born_artifacts_no_update'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    tx.execute_batch("DROP TRIGGER born_artifacts_no_update")
        .unwrap();
    tx.execute(
        "UPDATE authority_born_offline_artifacts SET secret=?1",
        [[0x54u8; 32].as_slice()],
    )
    .unwrap();
    tx.execute_batch(&trigger).unwrap();
    verify_schema(&tx).unwrap();
    assert!(load(&tx).is_err());
    drop(tx);
    drop(c);
    let before = tree(temp.path());
    let snapshot = wholepact_storage_security::open_encrypted_read_snapshot(&path, &key).unwrap();
    assert!(
        crate::journal::namespace_account_stamp(snapshot.connection(), &ledger.policy)
            .unwrap()
            .0
            == stamp
    );
    assert!(
        load(snapshot.connection())
            .unwrap()
            .born_offline_artifacts_v1()
            .unwrap()
            == Some(&record)
    );
    drop(snapshot);
    assert_eq!(before, tree(temp.path()));

    let output = tempfile::tempdir().unwrap();
    std::fs::set_permissions(output.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let destination = output.path().join("synthetic-historical-capsule.wp");
    let archive_key = DatabaseKey::from_bytes([0x55; 32]);
    let sources = [capsule::RegisteredSource::new(
        "account",
        "synthetic-born-history",
        capsule::Source::Journal(&path),
    )
    .unwrap()];
    let node = capsule::NodeSpec {
        generation_id: "c".repeat(64),
        profile_id: "synthetic-born-profile".into(),
        original_root: temp.path().into(),
    };
    let expected = capsule::ArchiveScope::for_snapshot(
        &destination,
        &archive_key,
        &"d".repeat(64),
        &node,
        &sources,
        &[],
    )
    .unwrap();
    let lock = std::fs::File::open(temp.path()).unwrap();
    lock.try_lock().unwrap();
    let authority = SyntheticCapture { expected, lock };
    capsule::snapshot(capsule::SnapshotRequest {
        destination: &destination,
        key: &archive_key,
        capsule_id: &"d".repeat(64),
        node: &node,
        sources: &sources,
        parents: &[],
        authority: &authority,
    })
    .unwrap();
    let archive = capsule::inspect(&destination, &archive_key).unwrap();
    let source = archive
        .journal(archive.manifest_digest(), "account")
        .unwrap();
    let historical = crate::journal::open_namespace_archive_account(&source, &key).unwrap();
    assert!(
        crate::journal::namespace_account_stamp(historical.connection(), &ledger.policy)
            .unwrap()
            .0
            == stamp
    );
    assert!(
        load(historical.connection())
            .unwrap()
            .born_offline_artifacts_v1()
            .unwrap()
            == Some(&record)
    );
    assert_eq!(before, tree(temp.path()));

    assert!(matches!(
        AuthorityJournal::open_encrypted(
            &path,
            &key,
            &ledger.policy.account_id,
            &ledger.policy.network_profile_id
        ),
        Err(AuthorityError::UnsupportedVersion)
    ));
    assert!(
        mail::SqliteReplayLedger::from_encrypted_connection(
            wholepact_storage_security::open_encrypted(&path, &key).unwrap()
        )
        .is_err()
    );
    assert!(
        mail::SqliteOutbox::from_encrypted_connection(
            wholepact_storage_security::open_encrypted(&path, &key).unwrap()
        )
        .is_err()
    );
    let unowned = AuthorityJournal {
        connection: Mutex::new(wholepact_storage_security::open_encrypted(&path, &key).unwrap()),
        resolution_node: Mutex::new(None),
        born_owner: None,
        born_manual_scope: None,
    };
    assert!(matches!(
        unowned.born_offline_artifacts_v1(),
        Err(AuthorityError::Permission)
    ));
    assert!(matches!(
        unowned.open_born_artifact_handles_v1(),
        Err(AuthorityError::Permission)
    ));
}
