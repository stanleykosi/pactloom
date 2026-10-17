//! Actual encrypted synthetic storage/read qualification. This does not forge a
//! native decision, namespace owner or authenticated client admission.
use super::*;
use crate::manual_enrollment::tests::bootstrap_events;
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
    let (mut birth, _, events, _) = bootstrap_events();
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
    tx.execute(
        "INSERT INTO authority_session_keys VALUES(?1,?2)",
        params![crate::session::session_id(&[0x33; 32]), &[0x33u8; 32][..]],
    )
    .unwrap();
    tx.pragma_update(None, "application_id", APPLICATION_ID)
        .unwrap();
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)
        .unwrap();
    tx.commit().unwrap();
    connection
}
#[test]
fn encrypted_complete_extension_replay_preserves_source_tree_on_read_and_reject() {
    for wrong in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("synthetic-enrollment.wp");
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
            assert_eq!(replay.snapshot.head.sequence, 4);
            assert_eq!(replay.snapshot.aggregate_budget_zatoshis, 100);
            assert!(replay.manual_extension().unwrap().is_some());
        }
        drop(snapshot);
        assert_eq!(tree(temp.path()), before);
    }
}
#[test]
fn serialized_scope_without_actual_namespace_owner_cannot_enable_bootstrap() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = temp.path().join("synthetic-enrollment.wp");
    let key = DatabaseKey::from_bytes([0x2a; 32]);
    let connection = write_fixture(&path, &key, false);
    let (_, extension, events, ledger) = bootstrap_events();
    let journal = AuthorityJournal {
        connection: Mutex::new(connection),
        resolution_node: Mutex::new(None),
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        born_owner: None,
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        born_manual_scope: Some(
            crate::manual_session_continuation::BornManualBootstrapScope {
                extension_digest: extension.digest().unwrap(),
                attempt_digest: crate::manual_session_continuation::initial_manual_attempt_digest(
                    &extension,
                )
                .unwrap(),
            },
        ),
    };
    let result = journal.mutate_on_channel(
        &ledger.policy.initial_writer_certificate_digest,
        events.last().unwrap().mutation.clone(),
        None,
        &[0x33; 32],
        &"5".repeat(64),
        8000,
    );
    assert!(matches!(result, Err(AuthorityError::Permission)));
    let c = journal.connection.lock().unwrap();
    assert!(load(c.connection()).unwrap().snapshot == ledger.snapshot);
    let _ = extension;
}

#[path = "born_offline_enrollment_encrypted_tests.rs"]
mod born_offline_enrollment_tests;

#[cfg(all(feature = "born-offline-witness-owner", target_os = "linux"))]
#[path = "born_offline_artifacts_encrypted_tests_v1.rs"]
mod born_offline_artifacts_tests;
