//! Synthetic keys and temporary directories only; the owning directory lock is held.
use super::*;
use crate::tests::tree_fingerprint;
use std::{fs, os::unix::fs::PermissionsExt};
struct Fixture {
    _lock: fs::File,
    directory: tempfile::TempDir,
    path: PathBuf,
    key: DatabaseKey,
    plan: PlannedWitnessBirthInitialization,
    connection: EncryptedConnection,
}
fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let lock = fs::File::open(directory.path()).unwrap();
    lock.try_lock().unwrap();
    let path = directory.path().join("synthetic-birth.wp");
    let key = DatabaseKey::from_bytes([0x73; 32]);
    let connection = crate::create_encrypted(&path, &key).unwrap();
    let plan =
        PlannedWitnessBirthInitialization::new(&"1".repeat(64), &"2".repeat(64), &path, &key)
            .unwrap();
    Fixture {
        _lock: lock,
        directory,
        path,
        key,
        plan,
        connection,
    }
}
#[test]
fn exact_empty_initialization_is_classified_without_mutating_source() {
    let f = fixture();
    let before = tree_fingerprint(f.directory.path());
    assert!(matches!(
        f.plan
            .inspect(&f.path, &f.key, &"1".repeat(64), &"2".repeat(64))
            .unwrap(),
        PlannedWitnessBirthInspection::AuthenticatedEmpty
    ));
    assert_eq!(tree_fingerprint(f.directory.path()), before);
    let resumed = f
        .plan
        .resume(&f.path, &f.key, &"1".repeat(64), &"2".repeat(64))
        .unwrap();
    resumed
        .connection()
        .execute_batch(
            "CREATE TABLE synthetic_typed_initialization(v INTEGER); PRAGMA user_version=1;",
        )
        .unwrap();
    assert!(
        f.plan
            .verify_empty(&f.path, &f.key, &"1".repeat(64), &"2".repeat(64))
            .is_err()
    );
}
#[test]
fn mismatched_key_path_namespace_and_intent_preserve_full_tree() {
    let f = fixture();
    let before = tree_fingerprint(f.directory.path());
    let wrong_key = DatabaseKey::from_bytes([0x74; 32]);
    for (path, key, namespace, intent) in [
        (f.path.clone(), &wrong_key, "1".repeat(64), "2".repeat(64)),
        (
            f.directory.path().join("wrong.wp"),
            &f.key,
            "1".repeat(64),
            "2".repeat(64),
        ),
        (f.path.clone(), &f.key, "3".repeat(64), "2".repeat(64)),
        (f.path.clone(), &f.key, "1".repeat(64), "3".repeat(64)),
    ] {
        assert!(f.plan.resume(&path, key, &namespace, &intent).is_err());
        assert_eq!(tree_fingerprint(f.directory.path()), before);
    }
}
#[test]
fn objects_and_protected_markers_never_become_empty_retry() {
    for sql in [
        "CREATE TABLE existing_object(v INTEGER)",
        "CREATE TABLE wholepact_recovered_generation(v INTEGER)",
        "CREATE TABLE archive_root(v INTEGER)",
    ] {
        let f = fixture();
        f.connection.connection().execute_batch(sql).unwrap();
        let before = tree_fingerprint(f.directory.path());
        assert!(
            f.plan
                .resume(&f.path, &f.key, &"1".repeat(64), &"2".repeat(64))
                .is_err()
        );
        if sql.contains("recovered") || sql.contains("archive") {
            assert!(
                f.plan
                    .inspect(&f.path, &f.key, &"1".repeat(64), &"2".repeat(64))
                    .is_err()
            );
        }
        assert_eq!(tree_fingerprint(f.directory.path()), before);
    }
}

#[test]
fn incorrect_expected_key_still_fails_cipher_authentication_without_source_writes() {
    let f = fixture();
    let wrong = DatabaseKey::from_bytes([0x75; 32]);
    let expectation =
        PlannedWitnessBirthInitialization::new(&"1".repeat(64), &"2".repeat(64), &f.path, &wrong)
            .unwrap();
    let before = tree_fingerprint(f.directory.path());
    assert!(
        expectation
            .resume(&f.path, &wrong, &"1".repeat(64), &"2".repeat(64))
            .is_err()
    );
    assert!(
        expectation
            .inspect(&f.path, &wrong, &"1".repeat(64), &"2".repeat(64))
            .is_err()
    );
    assert_eq!(tree_fingerprint(f.directory.path()), before);
}

#[test]
fn quarantine_application_identity_preserves_full_tree_on_both_read_and_retry() {
    let f = fixture();
    f.connection
        .connection()
        .pragma_update(
            None,
            "application_id",
            crate::bundle::QUARANTINE_APPLICATION_ID,
        )
        .unwrap();
    let before = tree_fingerprint(f.directory.path());
    assert!(
        f.plan
            .resume(&f.path, &f.key, &"1".repeat(64), &"2".repeat(64))
            .is_err()
    );
    assert!(matches!(
        f.plan
            .inspect(&f.path, &f.key, &"1".repeat(64), &"2".repeat(64)),
        Err(StorageSecurityError::QuarantinedDatabase)
    ));
    assert_eq!(tree_fingerprint(f.directory.path()), before);
}
