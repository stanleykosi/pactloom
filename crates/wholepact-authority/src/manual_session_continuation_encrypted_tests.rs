//! Actual encrypted synthetic storage/read qualification. This does not forge a
//! native decision, namespace owner or authenticated client admission.
use super::*;
use crate::manual_session_continuation::tests::continued_fixture;
use std::os::unix::fs::PermissionsExt;

fn tree(path: &Path) -> Vec<(String, Vec<u8>)> {
    let mut entries: Vec<_> = std::fs::read_dir(path)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (
                e.file_name().to_str().unwrap().to_owned(),
                std::fs::read(e.path()).unwrap(),
            )
        })
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries
}
fn write_fixture(path: &Path, key: &DatabaseKey, wrong_birth_time: bool) -> EncryptedConnection {
    let (mut birth, _, events, _) = continued_fixture();
    if wrong_birth_time {
        birth.committed_at_ms += 1;
    }
    let connection = wholepact_storage_security::create_encrypted(path, key).unwrap();
    configure(connection.connection()).unwrap();
    let tx = Transaction::new_unchecked(connection.connection(), TransactionBehavior::Immediate)
        .unwrap();
    tx.execute_batch(SCHEMA).unwrap();
    tx.execute(
        "INSERT INTO authority_genesis VALUES(1,?1)",
        [&*encode(&birth.request.policy).unwrap()],
    )
    .unwrap();
    tx.execute("INSERT INTO authority_quarantine VALUES(1,0)", [])
        .unwrap();
    for peer in [
        &birth.request.policy.owner_certificate_digest,
        &birth.request.policy.initial_writer_certificate_digest,
    ] {
        tx.execute("INSERT INTO authority_principals VALUES(?1)", [peer])
            .unwrap();
    }
    tx.execute(
        "INSERT INTO authority_pending_birth_commit VALUES(1,?1,?2,?3)",
        params![
            birth.request.operation_id,
            birth.request_digest,
            serde_json::to_string(&birth).unwrap()
        ],
    )
    .unwrap();
    let mut ledger = Ledger::new(birth.request.policy.clone()).unwrap();
    for event in events {
        let previous = ledger.snapshot.head.digest.clone();
        ledger.apply(&event).unwrap();
        tx.execute(
            "INSERT INTO authority_events VALUES(?1,?2,?3,?4,?5)",
            params![
                ledger.snapshot.head.sequence,
                event.mutation.operation_id(),
                previous,
                ledger.snapshot.head.digest,
                &*encode(&event).unwrap()
            ],
        )
        .unwrap();
    }
    for (session, key) in [
        (crate::session::session_id(&[0x33; 32]), [0x33u8; 32]),
        (crate::session::session_id(&[0x44; 32]), [0x44u8; 32]),
    ] {
        tx.execute(
            "INSERT INTO authority_session_keys VALUES(?1,?2)",
            params![session, key.as_slice()],
        )
        .unwrap();
    }
    tx.pragma_update(None, "application_id", APPLICATION_ID)
        .unwrap();
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)
        .unwrap();
    tx.commit().unwrap();
    connection
}
#[test]
fn encrypted_complete_continuation_replay_preserves_source_tree_on_read_and_reject() {
    for wrong in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("synthetic-continuation.wp");
        let key = DatabaseKey::from_bytes([0x29; 32]);
        drop(write_fixture(&path, &key, wrong));
        let before = tree(temp.path());
        let snapshot =
            wholepact_storage_security::open_encrypted_read_snapshot(&path, &key).unwrap();
        verify_schema(snapshot.connection()).unwrap();
        let result = load(snapshot.connection());
        if wrong {
            assert!(result.is_err());
        } else {
            let replay = result.unwrap();
            assert_eq!(replay.snapshot.head.sequence, 8);
            assert_eq!(replay.sessions.len(), 2);
            assert_eq!(replay.latest_manual_attempt().unwrap().sequence, 2);
            assert_eq!(replay.snapshot.aggregate_budget_zatoshis, 100);
            assert!(replay.manual_extension().unwrap().is_some());
        }
        drop(snapshot);
        assert_eq!(tree(temp.path()), before);
    }
}

#[test]
fn continuation_fixture_keeps_both_session_keys_and_rollback_is_atomic() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = temp.path().join("synthetic-continuation-rollback.wp");
    let key = DatabaseKey::from_bytes([0x31; 32]);
    let c = write_fixture(&path, &key, false);
    let old = load(c.connection()).unwrap().snapshot;
    assert_eq!(
        c.connection()
            .query_row("SELECT count(*) FROM authority_session_keys", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        2
    );
    {
        let tx =
            Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate).unwrap();
        // Production immutability is expected, including inside a transaction.
        assert!(
            tx.execute("DELETE FROM authority_session_keys", [])
                .is_err()
        );
        // An allowed staged append disappears on rollback without touching
        // either retained original. No native/session capability is constructed.
        tx.execute(
            "INSERT INTO authority_session_keys VALUES(?1,?2)",
            params![crate::session::session_id(&[0x55; 32]), &[0x55u8; 32][..]],
        )
        .unwrap();
        assert_eq!(
            tx.query_row("SELECT count(*) FROM authority_session_keys", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            3
        );
        // Injected uncommitted transaction loss: no staged append escapes rollback.
        tx.rollback().unwrap();
    }
    assert_eq!(
        c.connection()
            .query_row("SELECT count(*) FROM authority_session_keys", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        2
    );
    assert!(load(c.connection()).unwrap().snapshot == old);
}
