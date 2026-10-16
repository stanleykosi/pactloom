//! Synthetic schema/read-only fixtures only. These do not construct a native
//! decision, born-publication owner, writer session, signer capability or proof.
//! The private source-directory lock excludes writers throughout each snapshot.
use super::*;
use crate::files::PrivateDirectory;
use std::{collections::BTreeMap, fs, os::unix::fs::MetadataExt, path::PathBuf};
use wholepact_authority::account_use::{
    AccountUseIdentity, ExclusionReason, PermanentAccountExclusion,
};

const EPOCH: u64 = 7;
struct Fixture {
    // Keep the lock until the writable fixture handle has closed.
    connection: Connection,
    directory: PrivateDirectory,
    _temporary: tempfile::TempDir,
    key: DatabaseKey,
    genesis: AccountUseGenesis,
}
impl Fixture {
    fn new() -> Self {
        Self::new_schema(SCHEMA, SCHEMA_VERSION)
    }
    fn new_schema(schema: &str, version: i64) -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let directory =
            PrivateDirectory::create(&temporary.path().join("synthetic-source")).unwrap();
        let key = DatabaseKey::from_bytes([0x57; 32]);
        let genesis = AccountUseGenesis {
            version: 1,
            identity: AccountUseIdentity {
                account_id: "11".repeat(32),
                full_viewing_key_digest: "22".repeat(32),
                network_profile_id: "synthetic-schema-only".into(),
                derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
            },
            witness_id: "synthetic-witness-no-service".into(),
            witness_origin_digest: "33".repeat(32),
            owner_certificate_digest: "44".repeat(32),
            native_birth_digest: "55".repeat(32),
        };
        let mut connection = wholepact_storage_security::create_encrypted(
            directory.root().join("authority.sqlite"),
            &key,
        )
        .unwrap()
        .into_connection();
        configure(&connection).unwrap();
        // Match the compiled initial schema/data layout. Deliberately do not
        // call publish_born_enrollment or synthesize its opaque owner.
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        tx.execute_batch(schema).unwrap();
        if version == SCHEMA_VERSION {
            verify_capacity_schema(&tx).unwrap();
        }
        tx.execute(
            "INSERT INTO signer_account VALUES(1,?1,?2,0)",
            params![genesis.identity.account_id, EPOCH],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO signer_account_use_genesis VALUES(1,?1,?2,?3,?4)",
            params![
                genesis.identity.account_id,
                genesis.identity.full_viewing_key_digest,
                genesis.digest().unwrap(),
                encode(&genesis).unwrap().as_str()
            ],
        )
        .unwrap();
        tx.pragma_update(None, "application_id", APPLICATION_ID)
            .unwrap();
        tx.pragma_update(None, "user_version", version).unwrap();
        if version == SCHEMA_VERSION {
            verify_born_initial(&tx, &genesis, EPOCH).unwrap();
        } else {
            recovery_migration::verify_exact_schema(&tx, schema).unwrap();
            verify_born_identity_cells(&tx, &genesis, EPOCH).unwrap();
        }
        tx.commit().unwrap();
        Self {
            connection,
            directory,
            _temporary: temporary,
            key,
            genesis,
        }
    }
    fn path(&self) -> PathBuf {
        self.directory.root().join("authority.sqlite")
    }
    fn inspect(&self) -> Result<()> {
        SignerConsentJournal::verify_initial_born_history(
            &self.path(),
            &self.key,
            &self.genesis,
            EPOCH,
        )
    }
}

#[derive(Debug, PartialEq, Eq)]
struct FileState {
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    device: u64,
    inode: u64,
    len: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    bytes: Option<Vec<u8>>,
}
fn tree(root: &Path) -> BTreeMap<PathBuf, FileState> {
    fn visit(root: &Path, path: &Path, output: &mut BTreeMap<PathBuf, FileState>) {
        let m = fs::symlink_metadata(path).unwrap();
        assert!(
            m.is_dir() || m.is_file(),
            "fixture has no links or special files"
        );
        let bytes = m.is_file().then(|| fs::read(path).unwrap());
        output.insert(
            path.strip_prefix(root).unwrap().to_owned(),
            FileState {
                mode: m.mode(),
                uid: m.uid(),
                gid: m.gid(),
                links: m.nlink(),
                device: m.dev(),
                inode: m.ino(),
                len: m.len(),
                modified: (m.mtime(), m.mtime_nsec()),
                changed: (m.ctime(), m.ctime_nsec()),
                bytes,
            },
        );
        if m.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                visit(root, &entry.unwrap().path(), output);
            }
        }
    }
    let mut output = BTreeMap::new();
    visit(root, root, &mut output);
    // Read access time is intentionally excluded; content, inventory, inode,
    // ownership, permissions and modification/change times must stay exact.
    output
}

#[test]
fn initial_born_schema_snapshot_preserves_complete_encrypted_source_tree() {
    let f = Fixture::new();
    // Keep a live, quiescent fixture connection so the WAL/SHM must be included;
    // closing it first would checkpoint away this important capture case.
    assert!(f.directory.root().join("authority.sqlite-wal").exists());
    assert!(f.directory.root().join("authority.sqlite-shm").exists());
    let before = tree(f.directory.root());
    f.inspect().unwrap();
    assert_eq!(tree(f.directory.root()), before);
    f.inspect().unwrap();
    assert_eq!(tree(f.directory.root()), before);
}

#[test]
fn later_rows_and_recovery_state_deny_initial_backup_without_source_mutation() {
    for mutation in ["later-enrollment", "permanent-exclusion", "recovered"] {
        let f = Fixture::new();
        match mutation {
            "later-enrollment" => {
                // This is only a modeled extra row in the executable-owned
                // table. Its JSON cannot create an original signer enrollment.
                f.connection
                    .execute(
                        "INSERT INTO signer_enrollments VALUES(?1,?2,?3,?4,?5)",
                        params![
                            "synthetic-later-row",
                            f.genesis.identity.account_id,
                            "synthetic-agreement",
                            "synthetic-participant",
                            "{}"
                        ],
                    )
                    .unwrap();
            }
            "permanent-exclusion" => {
                let exclusion = PermanentAccountExclusion {
                    version: 1,
                    identity: f.genesis.identity.clone(),
                    genesis_digest: f.genesis.digest().unwrap(),
                    operation_id: "synthetic-retirement".into(),
                    native_review_digest: "66".repeat(32),
                    reason: ExclusionReason::RetirementRequested,
                };
                f.connection
                    .execute(
                        "INSERT INTO signer_account_use_exclusion VALUES(1,?1,?2,?3)",
                        params![
                            exclusion.genesis_digest,
                            exclusion.digest().unwrap(),
                            encode(&exclusion).unwrap().as_str()
                        ],
                    )
                    .unwrap();
            }
            "recovered" => {
                f.connection
                    .execute(
                        "UPDATE signer_account SET recovery_required=1 WHERE singleton=1",
                        [],
                    )
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let before = tree(f.directory.root());
        assert!(
            matches!(f.inspect(), Err(JournalError::RecoveryRequired)),
            "{mutation}"
        );
        assert_eq!(tree(f.directory.root()), before, "{mutation}");
    }
}

#[test]
fn mismatched_initial_identity_epoch_or_key_preserves_complete_source_tree() {
    let f = Fixture::new();
    let before = tree(f.directory.root());
    let mut other = f.genesis.clone();
    other.identity.full_viewing_key_digest = "77".repeat(32);
    let wrong_key = DatabaseKey::from_bytes([0x58; 32]);
    for (genesis, key, epoch) in [
        (&other, &f.key, EPOCH),
        (&f.genesis, &f.key, EPOCH + 1),
        (&f.genesis, &wrong_key, EPOCH),
    ] {
        assert!(
            SignerConsentJournal::verify_initial_born_history(&f.path(), key, genesis, epoch,)
                .is_err()
        );
        assert_eq!(tree(f.directory.root()), before);
    }
}

#[test]
fn schema15_born_archive_keeps_exact_bytes_without_implicit_migration() {
    let f = Fixture::new_schema(recovery_migration::V15_SCHEMA, 15);
    let before = tree(f.directory.root());
    f.inspect().unwrap();
    assert_eq!(tree(f.directory.root()), before);
    recovery_migration::verify_exact_schema(&f.connection, recovery_migration::V15_SCHEMA).unwrap();
    assert_eq!(
        f.connection
            .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        15
    );
}
