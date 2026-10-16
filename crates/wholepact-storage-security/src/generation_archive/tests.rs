//! Synthetic local storage fixtures only; no live keys, consent or settlement.
use super::*;
use crate::{bundle::JournalKind, tests::tree_fingerprint};
use std::{
    cell::Cell,
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
};

static TEMPLATE: JournalTemplate = JournalTemplate {
    kind: JournalKind::Submission,
    application_id: 0,
    schema_version: 1,
    create_sql: "CREATE TABLE synthetic_history(value TEXT NOT NULL);",
};
const CANARY: &[u8] = b"SYNTHETIC-CAPSULE-PRIVATE-MATERIAL-734f";
fn directory() -> tempfile::TempDir {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}
struct Authority {
    expected: ArchiveScope,
    checks: Cell<usize>,
    fail_at: usize,
}
struct Lease<'a>(&'a Authority);
impl ArchiveAuthority for Authority {
    fn acquire<'a>(&'a self, scope: &ArchiveScope) -> Result<Box<dyn ArchiveLease + 'a>> {
        if *scope != self.expected {
            return Err(ArchiveError::Permission);
        }
        Ok(Box::new(Lease(self)))
    }
}
impl ArchiveLease for Lease<'_> {
    fn check_current(&self) -> Result<()> {
        let count = self.0.checks.get() + 1;
        self.0.checks.set(count);
        if count == self.0.fail_at {
            Err(ArchiveError::Permission)
        } else {
            Ok(())
        }
    }
}
fn make<'a>(
    destination: &Path,
    key: &DatabaseKey,
    node: &NodeSpec,
    sources: &'a [RegisteredSource<'a>],
    parents: &[&VerifiedArchive],
    capsule_id: &str,
) -> Result<ArchiveReport> {
    let authority = Authority {
        expected: ArchiveScope::for_snapshot(destination, key, capsule_id, node, sources, parents)?,
        checks: Cell::new(0),
        fail_at: usize::MAX,
    };
    snapshot(SnapshotRequest {
        destination,
        key,
        capsule_id,
        node,
        sources,
        parents,
        authority: &authority,
    })
}
#[test]
fn capsule_preserves_complete_byte_inventory_and_reads_committed_wal_privately() {
    let source = directory();
    let output = directory();
    let journal = source.path().join("journal.sqlite");
    let vault = source.path().join("profile.vault");
    let journal_key = DatabaseKey::from_bytes([141; 32]);
    let archive_key = DatabaseKey::from_bytes([142; 32]);
    let writer = crate::create_encrypted(&journal, &journal_key).unwrap();
    writer.connection().execute_batch("PRAGMA wal_autocheckpoint=0; PRAGMA user_version=1; CREATE TABLE synthetic_history(value TEXT NOT NULL);").unwrap();
    crate::checkpoint_and_sync(writer.connection(), &journal).unwrap();
    writer
        .connection()
        .execute(
            "INSERT INTO synthetic_history VALUES(?1)",
            [std::str::from_utf8(CANARY).unwrap()],
        )
        .unwrap();
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&vault)
        .unwrap()
        .write_all(&[0xa7; 193])
        .unwrap();
    let secret = Zeroizing::new(CANARY.to_vec());
    let sources = [
        RegisteredSource::new("journal", "current-submission", Source::Journal(&journal)).unwrap(),
        RegisteredSource::new("vault", "root-vault", Source::File(&vault)).unwrap(),
        RegisteredSource::new("secret", "root-secret", Source::Secret(&secret)).unwrap(),
    ];
    let node = NodeSpec {
        generation_id: "11".repeat(32),
        profile_id: "synthetic-profile".into(),
        original_root: source.path().into(),
    };
    let destination = output.path().join("capsule.sqlite");
    let before = tree_fingerprint(source.path());
    let report = make(
        &destination,
        &archive_key,
        &node,
        &sources,
        &[],
        &"22".repeat(32),
    )
    .unwrap();
    assert!(
        before == tree_fingerprint(source.path()),
        "capsule capture changed source tree"
    );
    assert!(
        !fs::read(&destination)
            .unwrap()
            .windows(CANARY.len())
            .any(|bytes| bytes == CANARY)
    );
    let archive_before = tree_fingerprint(output.path());
    let archive = inspect(&destination, &archive_key).unwrap();
    assert!(report == archive.report());
    assert_eq!(
        archive
            .read_private_entry(&report.manifest_digest, "secret", CANARY.len())
            .unwrap()
            .as_slice(),
        CANARY
    );
    assert!(matches!(
        archive.read_private_entry(&report.manifest_digest, "secret", CANARY.len() - 1),
        Err(ArchiveError::Limit)
    ));
    let archived = archive.journal(&report.manifest_digest, "journal").unwrap();
    assert_eq!(archived.origin(), journal.to_str().unwrap());
    let read = archived.open_ordinary(&journal_key, &TEMPLATE).unwrap();
    assert_eq!(
        read.connection()
            .query_row("SELECT value FROM synthetic_history", [], |r| r
                .get::<_, String>(0))
            .unwrap()
            .as_bytes(),
        CANARY
    );
    assert!(
        read.connection()
            .execute("DELETE FROM synthetic_history", [])
            .is_err()
    );
    let typed = archived.inspect_ordinary(&journal_key, &TEMPLATE).unwrap();
    assert_eq!(typed.provenance().rows, 1);
    assert_eq!(typed.provenance().component_id, "journal");
    assert_eq!(typed.tables().len(), 1);
    assert!(
        archived
            .open_ordinary(&DatabaseKey::from_bytes([143; 32]), &TEMPLATE)
            .is_err()
    );
    assert!(inspect(&destination, &DatabaseKey::from_bytes([143; 32])).is_err());
    assert!(crate::open_encrypted_quiescent(&destination, &archive_key).is_err());
    assert!(
        before == tree_fingerprint(source.path()),
        "typed archived readers changed source tree"
    );
    assert!(
        archive_before == tree_fingerprint(output.path()),
        "immutable verification changed capsule files"
    );
    assert!(
        make(
            &destination,
            &archive_key,
            &node,
            &sources,
            &[],
            &"22".repeat(32)
        )
        .is_err()
    );
    assert!(
        archive_before == tree_fingerprint(output.path()),
        "new-only rejection changed existing capsule"
    );
}
#[test]
fn capsule_import_retains_exact_parent_manifest_and_deduplicates_objects() {
    let source = directory();
    let output = directory();
    let secret = Zeroizing::new(CANARY.to_vec());
    let sources =
        [RegisteredSource::new("secret", "synthetic-secret", Source::Secret(&secret)).unwrap()];
    let mut node = NodeSpec {
        generation_id: "31".repeat(32),
        profile_id: "synthetic-profile".into(),
        original_root: source.path().into(),
    };
    let parent_path = output.path().join("parent.sqlite");
    let child_path = output.path().join("child.sqlite");
    let key = DatabaseKey::from_bytes([144; 32]);
    let parent_report = make(&parent_path, &key, &node, &sources, &[], &"32".repeat(32)).unwrap();
    let parent = inspect(&parent_path, &key).unwrap();
    let parent_bytes = format::encode(parent.manifest()).unwrap();
    node.generation_id = "33".repeat(32);
    let report = make(
        &child_path,
        &key,
        &node,
        &sources,
        &[&parent],
        &"34".repeat(32),
    )
    .unwrap();
    let child = inspect(&child_path, &key).unwrap();
    assert_eq!(report.nodes, 2);
    assert_eq!(report.entries, 2);
    assert_eq!(report.distinct_bytes, CANARY.len() as u64);
    assert_ne!(report.manifest_digest, parent_report.manifest_digest);
    assert_eq!(
        child.manifest().parent_manifest_digests.as_slice(),
        std::slice::from_ref(&parent_report.manifest_digest)
    );
    assert_eq!(
        format::encode(
            child
                .manifest_by_digest(&parent_report.manifest_digest)
                .unwrap()
        )
        .unwrap(),
        parent_bytes
    );
    assert_eq!(
        child
            .read_private_entry(&parent_report.manifest_digest, "secret", CANARY.len())
            .unwrap()
            .as_slice(),
        CANARY
    );
    // A capsule ID cannot be rebound to a different node or parent closure.
    let bad = output.path().join("rebound.sqlite");
    assert!(make(&bad, &key, &node, &sources, &[&parent], &"32".repeat(32)).is_err());
    assert!(inspect(&bad, &key).is_err());
}
#[test]
fn capsule_rejects_extra_missing_corrupt_objects_and_missing_publication() {
    let source = directory();
    let output = directory();
    let key = DatabaseKey::from_bytes([145; 32]);
    let node = NodeSpec {
        generation_id: "41".repeat(32),
        profile_id: "synthetic-profile".into(),
        original_root: source.path().into(),
    };
    let sources =
        [RegisteredSource::new("secret", "synthetic-secret", Source::Secret(CANARY)).unwrap()];
    for (index,sql) in ["DELETE FROM archive_root", "UPDATE archive_chunks SET payload=zeroblob(length(payload))", "INSERT INTO archive_objects VALUES('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',0)", "DELETE FROM archive_chunks", "PRAGMA application_id=0"].into_iter().enumerate() {
        let path=output.path().join(format!("tamper-{index}.sqlite"));
        make(&path,&key,&node,&sources,&[],&"42".repeat(32)).unwrap();
        let connection=crate::keyed_connection(&path,&key).unwrap();connection.execute_batch(sql).unwrap();crate::checkpoint_and_sync(&connection,&path).unwrap();drop(connection);
        let before=tree_fingerprint(output.path());
        assert!(inspect(&path,&key).is_err(),"tampered capsule accepted");
        assert!(before==tree_fingerprint(output.path()),"tamper rejection changed capsule");
    }
}
#[test]
fn capsule_scope_identity_and_revocation_fail_without_source_changes() {
    let source = directory();
    let output = directory();
    let key = DatabaseKey::from_bytes([146; 32]);
    let node = NodeSpec {
        generation_id: "51".repeat(32),
        profile_id: "synthetic-profile".into(),
        original_root: source.path().into(),
    };
    let path = output.path().join("capsule.sqlite");
    let capsule = "52".repeat(32);
    let enrolled =
        [RegisteredSource::new("secret", "synthetic-secret", Source::Secret(CANARY)).unwrap()];
    let impostor =
        [RegisteredSource::new("secret", "synthetic-secret", Source::Secret(CANARY)).unwrap()];
    let authority = Authority {
        expected: ArchiveScope::for_snapshot(&path, &key, &capsule, &node, &enrolled, &[]).unwrap(),
        checks: Cell::new(0),
        fail_at: usize::MAX,
    };
    assert!(
        snapshot(SnapshotRequest {
            destination: &path,
            key: &key,
            capsule_id: &capsule,
            node: &node,
            sources: &impostor,
            parents: &[],
            authority: &authority
        })
        .is_err()
    );
    assert!(!path.exists());
    assert!(
        snapshot(SnapshotRequest {
            destination: &path,
            key: &DatabaseKey::from_bytes([247; 32]),
            capsule_id: &capsule,
            node: &node,
            sources: &enrolled,
            parents: &[],
            authority: &authority
        })
        .is_err()
    );
    assert!(!path.exists());
    let authority = Authority {
        fail_at: 4,
        ..authority
    };
    let before = tree_fingerprint(source.path());
    assert!(
        snapshot(SnapshotRequest {
            destination: &path,
            key: &key,
            capsule_id: &capsule,
            node: &node,
            sources: &enrolled,
            parents: &[],
            authority: &authority
        })
        .is_err()
    );
    assert!(before == tree_fingerprint(source.path()));
    assert!(inspect(&path, &key).is_err());
    let inside = source.path().join("not-external.sqlite");
    assert!(make(&inside, &key, &node, &enrolled, &[], &capsule).is_err());
    assert!(!inside.exists());
}

struct CopyGate {
    expected: CopyScope,
}
impl CopyAuthority for CopyGate {
    fn acquire<'a>(&'a self, scope: &CopyScope) -> Result<Box<dyn ArchiveLease + 'a>> {
        if *scope != self.expected {
            return Err(ArchiveError::Permission);
        }
        struct Allowed;
        impl ArchiveLease for Allowed {
            fn check_current(&self) -> Result<()> {
                Ok(())
            }
        }
        Ok(Box::new(Allowed))
    }
}
#[test]
fn capsule_copy_rekeys_exact_graph_new_only_and_binds_key_and_source_instance() {
    let source = directory();
    let output = directory();
    let restore = directory();
    let key = DatabaseKey::from_bytes([147; 32]);
    let next_key = DatabaseKey::from_bytes([148; 32]);
    let node = NodeSpec {
        generation_id: "61".repeat(32),
        profile_id: "synthetic-profile".into(),
        original_root: source.path().into(),
    };
    let sources =
        [RegisteredSource::new("secret", "synthetic-secret", Source::Secret(CANARY)).unwrap()];
    let path = output.path().join("capsule.sqlite");
    let original = make(&path, &key, &node, &sources, &[], &"62".repeat(32)).unwrap();
    let token = inspect(&path, &key).unwrap();
    let equivalent = inspect(&path, &key).unwrap();
    let destination = restore.path().join("inert-capsule.sqlite");
    let gate = CopyGate {
        expected: CopyScope::for_copy(&token, &destination, &next_key).unwrap(),
    };
    assert!(
        copy(CopyRequest {
            source: &equivalent,
            destination: &destination,
            key: &next_key,
            authority: &gate
        })
        .is_err()
    );
    assert!(
        copy(CopyRequest {
            source: &token,
            destination: &destination,
            key: &key,
            authority: &gate
        })
        .is_err()
    );
    assert!(!destination.exists());
    let before = tree_fingerprint(output.path());
    let report = copy(CopyRequest {
        source: &token,
        destination: &destination,
        key: &next_key,
        authority: &gate,
    })
    .unwrap();
    assert!(report == original);
    assert!(
        before == tree_fingerprint(output.path()),
        "copy changed original capsule"
    );
    assert!(inspect(&destination, &key).is_err());
    let restored = inspect(&destination, &next_key).unwrap();
    assert_eq!(
        restored
            .read_private_entry(&report.manifest_digest, "secret", CANARY.len())
            .unwrap()
            .as_slice(),
        CANARY
    );
    let restored_before = tree_fingerprint(restore.path());
    assert!(
        copy(CopyRequest {
            source: &token,
            destination: &destination,
            key: &next_key,
            authority: &gate
        })
        .is_err()
    );
    assert!(
        restored_before == tree_fingerprint(restore.path()),
        "new-only copy retry touched target"
    );
    assert!(crate::open_encrypted_quiescent(&destination, &next_key).is_err());
    assert!(
        restored_before == tree_fingerprint(restore.path()),
        "ordinary rejection touched inert target"
    );
}
#[test]
fn capsule_rejects_valid_but_unreachable_graph_and_physical_limit_before_copy() {
    let source = directory();
    let output = directory();
    let key = DatabaseKey::from_bytes([149; 32]);
    let node = NodeSpec {
        generation_id: "71".repeat(32),
        profile_id: "synthetic-profile".into(),
        original_root: source.path().into(),
    };
    let sources =
        [RegisteredSource::new("secret", "synthetic-secret", Source::Secret(CANARY)).unwrap()];
    let path = output.path().join("capsule.sqlite");
    let report = make(&path, &key, &node, &sources, &[], &"72".repeat(32)).unwrap();
    let token = inspect(&path, &key).unwrap();
    let mut extra_node = token.node(&report.manifest_digest).unwrap().clone();
    extra_node.generation_id = "73".repeat(32);
    let node_bytes = format::encode(&extra_node).unwrap();
    let node_digest = format::digest(format::NODE_DOMAIN, &node_bytes);
    let extra_manifest = SnapshotManifest {
        format: FORMAT,
        capsule_id: "74".repeat(32),
        node_digest: node_digest.clone(),
        parent_manifest_digests: vec![],
    };
    let manifest_bytes = format::encode(&extra_manifest).unwrap();
    let manifest_digest = format::digest(format::MANIFEST_DOMAIN, &manifest_bytes);
    let connection = crate::keyed_connection(&path, &key).unwrap();
    connection
        .execute(
            "INSERT INTO archive_nodes VALUES(?1,?2)",
            rusqlite::params![node_digest, node_bytes],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO archive_manifests VALUES(?1,?2)",
            rusqlite::params![manifest_digest, manifest_bytes],
        )
        .unwrap();
    crate::checkpoint_and_sync(&connection, &path).unwrap();
    drop(connection);
    let before = tree_fingerprint(output.path());
    assert!(inspect(&path, &key).is_err());
    assert!(before == tree_fingerprint(output.path()));
    let oversized = output.path().join("oversized.sqlite");
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&oversized)
        .unwrap();
    file.set_len(MAX_ARCHIVE_FILE_BYTES + 1).unwrap();
    assert!(inspect(&oversized, &key).is_err());
    assert_eq!(file.metadata().unwrap().len(), MAX_ARCHIVE_FILE_BYTES + 1);
}

mod history;

#[test]
fn retained_archive_source_guard_detects_change_without_repairing_original() {
    let source = directory();
    let output = directory();
    let file = source.path().join("synthetic-source");
    fs::write(&file, b"inert synthetic source").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    let destination = output.path().join("history.capsule.sqlite");
    let key = DatabaseKey::from_bytes([31; 32]);
    let node = NodeSpec {
        generation_id: "a".repeat(64),
        profile_id: "synthetic-profile".into(),
        original_root: source.path().into(),
    };
    let entries =
        [RegisteredSource::new("synthetic-file", "synthetic-role", Source::File(&file)).unwrap()];
    make(&destination, &key, &node, &entries, &[], &"b".repeat(64)).unwrap();
    let before = tree_fingerprint(output.path());
    let archive = inspect(&destination, &key).unwrap();
    archive.check_source_unchanged(&destination).unwrap();
    assert!(
        archive
            .check_source_unchanged(&source.path().join("wrong-path"))
            .is_err()
    );
    assert_eq!(before, tree_fingerprint(output.path()));
    fs::OpenOptions::new()
        .append(true)
        .open(&destination)
        .unwrap()
        .write_all(b"synthetic-change")
        .unwrap();
    let changed = tree_fingerprint(output.path());
    assert!(archive.check_source_unchanged(&destination).is_err());
    assert_eq!(changed, tree_fingerprint(output.path()));
}
