//! Source tests. Synthetic database key only; no native/witness issuer,
//! certificate generation, network, signing or positive birth capability.
use super::*;
use rusqlite::{Transaction, TransactionBehavior};

fn legacy_v4(path: &Path, key: &DatabaseKey, p: AccountPolicy) {
    let journal = AuthorityJournal::create_encrypted_legacy_v3_for_test(path, key, p).unwrap();
    let locked = journal.connection.lock().unwrap();
    let tx =
        Transaction::new_unchecked(locked.connection(), TransactionBehavior::Immediate).unwrap();
    tx.execute_batch(crate::offline_retry::OFFLINE_RETRY_SCHEMA)
        .unwrap();
    tx.execute_batch(crate::offline_outcome::OFFLINE_OUTCOME_SCHEMA)
        .unwrap();
    tx.pragma_update(None, "user_version", 4).unwrap();
    tx.commit().unwrap();
}
#[test]
fn v4_empty_provenance_migration_preserves_policy_and_never_synthesizes_birth() {
    let dir = private_dir();
    let path = dir.path().join("authority.sqlite");
    let key = DatabaseKey::from_bytes([0x51; 32]);
    let p = policy();
    legacy_v4(&path, &key, p.clone());
    let journal =
        AuthorityJournal::open_encrypted(&path, &key, &p.account_id, &p.network_profile_id)
            .unwrap();
    let locked = journal.connection.lock().unwrap();
    let c = locked.connection();
    assert_eq!(
        c.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        6
    );
    let raw: Vec<u8> = c
        .query_row("SELECT policy FROM authority_genesis", [], |r| r.get(0))
        .unwrap();
    assert!(decode::<AccountPolicy>(&raw).unwrap() == p);
    assert!(crate::pending_birth_storage::read(c, &p).unwrap().is_none());
    assert_eq!(
        c.query_row(
            "SELECT count(*) FROM authority_pending_birth_commit",
            [],
            |r| r.get::<_, u64>(0)
        )
        .unwrap(),
        0
    );
}
#[test]
fn wrong_identity_cannot_extend_v4_schema() {
    let dir = private_dir();
    let path = dir.path().join("authority.sqlite");
    let key = DatabaseKey::from_bytes([0x52; 32]);
    let p = policy();
    legacy_v4(&path, &key, p.clone());
    assert!(
        AuthorityJournal::open_encrypted(&path, &key, "wrong-account", &p.network_profile_id)
            .is_err()
    );
    let c = wholepact_storage_security::open_encrypted(&path, &key).unwrap();
    assert_eq!(
        c.connection()
            .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        4
    );
    assert_eq!(
        c.connection()
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name='authority_pending_birth_commit'",
                [],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
        0
    );
}
#[test]
fn v5_legacy_backup_preserves_unknown_provenance_and_quarantine() {
    let dir = private_dir();
    let path = dir.path().join("authority.sqlite");
    let key = DatabaseKey::from_bytes([0x53; 32]);
    let p = policy();
    let journal = AuthorityJournal::create_encrypted(&path, &key, p.clone()).unwrap();
    let stage = dir.path().join("backup.pending");
    let backup = dir.path().join("backup.sqlite");
    journal.backup_quarantined(&stage, &backup, &key).unwrap();
    let c = wholepact_storage_security::open_encrypted(&backup, &key).unwrap();
    assert!(crate::pending_birth_storage::read(c.connection(), &p)
        .unwrap()
        .is_none());
    assert_eq!(
        c.connection()
            .query_row("SELECT quarantined FROM authority_quarantine", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        1
    );
}
