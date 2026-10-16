//! Actual encrypted synthetic storage/read qualification. This does not forge a
//! native decision, namespace owner or authenticated client admission.
use super::*;
use crate::manual_roster_construction_v3::tests::construction_fixture_v3;
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
    let (mut birth, _, events, _) = construction_fixture_v3();
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
        (crate::session::session_id(&[0x55; 32]), [0x55u8; 32]),
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
fn encrypted_v3_complete_construction_replay_preserves_source_tree_on_read_and_reject() {
    for wrong in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("synthetic-v3-construction.wp");
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
            assert_eq!(replay.snapshot.head.sequence, 15);
            assert_eq!(replay.sessions.len(), 3);
            assert_eq!(
                replay.latest_manual_roster_attempt_v2().unwrap().sequence,
                3
            );
            assert_eq!(replay.snapshot.aggregate_budget_zatoshis, 1_000_000_000);
            assert_eq!(replay.snapshot.outstanding_debit_zatoshis, 400_012_000);
            assert!(replay.manual_extension().unwrap().is_some());
        }
        drop(snapshot);
        assert_eq!(tree(temp.path()), before);
    }
}

#[test]
fn v3_construction_fixture_keeps_all_session_keys_and_rollback_is_atomic() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = temp.path().join("synthetic-v3-construction-rollback.wp");
    let key = DatabaseKey::from_bytes([0x31; 32]);
    let c = write_fixture(&path, &key, false);
    let old = load(c.connection()).unwrap().snapshot;
    assert_eq!(
        c.connection()
            .query_row("SELECT count(*) FROM authority_session_keys", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        3
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
            params![crate::session::session_id(&[0x66; 32]), &[0x66u8; 32][..]],
        )
        .unwrap();
        assert_eq!(
            tx.query_row("SELECT count(*) FROM authority_session_keys", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            4
        );
        // Injected uncommitted transaction loss: no staged append escapes rollback.
        tx.rollback().unwrap();
    }
    assert_eq!(
        c.connection()
            .query_row("SELECT count(*) FROM authority_session_keys", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        3
    );
    assert!(load(c.connection()).unwrap().snapshot == old);
}

#[test]
fn encrypted_v3_unknown_version_never_becomes_empty_history() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = temp.path().join("synthetic-v3-unknown.wp");
    let key = DatabaseKey::from_bytes([0x53; 32]);
    let c = write_fixture(&path, &key, false);
    // Intentional test corruption of a disposable source, never a production
    // migration: retain bytes under an unsupported typed origin marker.
    c.connection()
        .execute_batch("DROP TRIGGER events_no_update")
        .unwrap();
    let raw: Vec<u8> = c
        .connection()
        .query_row(
            "SELECT payload FROM authority_events WHERE sequence=9",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    value["mutation"]["body"]["control"]["action"] = "approve_manual_roster_construction_v4".into();
    c.connection()
        .execute(
            "UPDATE authority_events SET payload=?1 WHERE sequence=9",
            [serde_json::to_vec(&value).unwrap()],
        )
        .unwrap();
    assert!(load(c.connection()).is_err());
    drop(c);
    let before = tree(temp.path());
    let snapshot = wholepact_storage_security::open_encrypted_read_snapshot(&path, &key).unwrap();
    assert!(verify_schema(snapshot.connection()).is_err());
    assert!(load(snapshot.connection()).is_err());
    drop(snapshot);
    assert_eq!(tree(temp.path()), before);
}
