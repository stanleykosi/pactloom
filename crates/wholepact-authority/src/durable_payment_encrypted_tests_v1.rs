//! Negative encrypted journal boundaries only. These tests do NOT manufacture a
//! native source, issue a financial admission, or claim native/TLS qualification.
use super::*;
use crate::durable_payment_v1::tests::{admission, fixture};
use std::os::unix::fs::PermissionsExt;

fn raw_journal(path: &Path, born: bool) -> AuthorityJournal {
    let (birth, _, _, _) = fixture();
    let mut policy = birth.request.policy.clone();
    if !born {
        policy.account_use_genesis = None;
    }
    let c =
        wholepact_storage_security::create_encrypted(path, &DatabaseKey::from_bytes([0x71; 32]))
            .unwrap();
    configure(c.connection()).unwrap();
    let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate).unwrap();
    tx.execute_batch(SCHEMA).unwrap();
    tx.execute(
        "INSERT INTO authority_genesis VALUES(1,?1)",
        [&*encode(&policy).unwrap()],
    )
    .unwrap();
    tx.execute("INSERT INTO authority_quarantine VALUES(1,0)", [])
        .unwrap();
    for cert in [
        &policy.owner_certificate_digest,
        &policy.initial_writer_certificate_digest,
    ] {
        tx.execute(
            "INSERT OR IGNORE INTO authority_principals VALUES(?1)",
            [cert],
        )
        .unwrap();
    }
    if born {
        tx.execute(
            "INSERT INTO authority_pending_birth_commit VALUES(1,?1,?2,?3)",
            params![
                birth.request.operation_id,
                birth.request_digest,
                serde_json::to_string(&birth).unwrap()
            ],
        )
        .unwrap();
    }
    tx.pragma_update(None, "application_id", APPLICATION_ID)
        .unwrap();
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)
        .unwrap();
    tx.commit().unwrap();
    AuthorityJournal {
        connection: Mutex::new(c),
        resolution_node: Mutex::new(None),
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        born_owner: None,
        #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
        born_manual_scope: None,
    }
}
#[test]
fn new_admission_denied_by_all_generic_paths_even_nonborn_raw_journal() {
    let (birth, _, events, terms) = fixture();
    let expected = admission(&birth, &events, terms);
    for born in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let journal = raw_journal(&dir.path().join("never-funded.db"), born);
        let mutation = AuthorityMutation::OwnerControl(expected.clone());
        let peer = &birth.request.policy.owner_certificate_digest;
        for outcome in [
            journal.mutate_on_channel(
                peer,
                mutation.clone(),
                None,
                &[0x19; 32],
                &"1".repeat(64),
                128_000,
            ),
            journal.mutate(peer, mutation.clone(), 128_000),
            journal.mutate_inner(
                peer,
                mutation.clone(),
                None,
                &[0x19; 32],
                &"1".repeat(64),
                128_000,
                None,
                false,
            ),
            journal.mutate_inner_timed(
                peer,
                mutation.clone(),
                None,
                &[0x19; 32],
                &"1".repeat(64),
                128_000,
                None,
                false,
                None,
            ),
        ] {
            assert!(matches!(outcome, Err(AuthorityError::Permission)));
        }
        let c = journal.connection.lock().unwrap();
        let count: u64 = c
            .connection()
            .query_row("SELECT count(*) FROM authority_events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
        let count: u64 = c
            .connection()
            .query_row("SELECT count(*) FROM authority_session_keys", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(count, 0);
        let ledger = load(c.connection()).unwrap();
        assert_eq!(ledger.snapshot.outstanding_debit_zatoshis, 0);
        assert_eq!(ledger.snapshot.settled_debit_zatoshis, 0);
    }
}
#[test]
fn serialized_exact_record_is_only_data_and_cannot_open_a_native_source() {
    let (birth, _, events, terms) = fixture();
    let request = admission(&birth, &events, terms);
    let bytes = serde_json::to_vec(&request).unwrap();
    let decoded: OwnerControlRequest = serde_json::from_slice(&bytes).unwrap();
    assert!(decoded == request);
    let mut value = serde_json::to_value(request).unwrap();
    value["native_approved"] = true.into();
    assert!(serde_json::from_value::<OwnerControlRequest>(value).is_err());
}
