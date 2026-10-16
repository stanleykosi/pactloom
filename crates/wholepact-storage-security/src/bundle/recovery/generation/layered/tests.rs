use super::*;
use crate::generation_archive::{
    self as archive, ArchiveAuthority, ArchiveError, ArchiveLease, ArchiveScope, NodeSpec,
    RegisteredSource, Source,
};
use std::os::unix::fs::PermissionsExt;

// Synthetic encrypted fixtures only. No real native authority or funds exist.
macro_rules! owner_schema {()=>{"CREATE TABLE original(id INTEGER PRIMARY KEY AUTOINCREMENT, label TEXT NOT NULL); CREATE TABLE exact_bytes(id TEXT PRIMARY KEY, payload BLOB NOT NULL) WITHOUT ROWID; CREATE TABLE prior_fences(kind TEXT NOT NULL,identity TEXT NOT NULL,detail TEXT NOT NULL,PRIMARY KEY(kind,identity)); CREATE TRIGGER prior_fences_no_update BEFORE UPDATE ON prior_fences BEGIN SELECT RAISE(ABORT,'immutable'); END; CREATE TRIGGER prior_fences_no_delete BEFORE DELETE ON prior_fences BEGIN SELECT RAISE(ABORT,'immutable'); END;"};}
const NEXT: &str = "CREATE TABLE next_layer(singleton INTEGER PRIMARY KEY CHECK(singleton=1),parent TEXT NOT NULL); CREATE TRIGGER next_layer_no_update BEFORE UPDATE ON next_layer BEGIN SELECT RAISE(ABORT,'immutable'); END;";
static OWNER: JournalTemplate = JournalTemplate {
    kind: JournalKind::CoordinationAuthority,
    application_id: RECOVERED_GENERATION_APPLICATION_ID,
    schema_version: 7,
    create_sql: owner_schema!(),
};
static NEXT_OWNER: JournalTemplate = JournalTemplate {
    kind: JournalKind::CoordinationAuthority,
    application_id: RECOVERED_GENERATION_APPLICATION_ID,
    schema_version: 8,
    create_sql: concat!(
        owner_schema!(),
        "CREATE TABLE next_layer(singleton INTEGER PRIMARY KEY CHECK(singleton=1),parent TEXT NOT NULL); CREATE TRIGGER next_layer_no_update BEFORE UPDATE ON next_layer BEGIN SELECT RAISE(ABORT,'immutable'); END;"
    ),
};
static WRONG: JournalTemplate = JournalTemplate {
    kind: JournalKind::CoordinationAuthority,
    application_id: RECOVERED_GENERATION_APPLICATION_ID,
    schema_version: 7,
    create_sql: "CREATE TABLE missing(id INTEGER);",
};
struct Authority(ArchiveScope);
struct Lease;
impl ArchiveAuthority for Authority {
    fn acquire<'a>(
        &'a self,
        scope: &ArchiveScope,
    ) -> std::result::Result<Box<dyn ArchiveLease + 'a>, ArchiveError> {
        if *scope != self.0 {
            return Err(ArchiveError::Permission);
        }
        Ok(Box::new(Lease))
    }
}
impl ArchiveLease for Lease {
    fn check_current(&self) -> std::result::Result<(), ArchiveError> {
        Ok(())
    }
}
fn directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}
fn binding(index: u8) -> GenerationBinding {
    GenerationBinding::new(
        &format!("{index:02x}").repeat(32),
        &format!("{:02x}", index + 20).repeat(32),
    )
    .unwrap()
}
fn provenance() -> RecoveryProvenance {
    RecoveryProvenance {
        profile_id: "synthetic-old-profile".into(),
        checkpoint_id: "synthetic-old-checkpoint".into(),
        bundle_digest: "ab".repeat(32),
        component_id: "coordination".into(),
        kind: JournalKind::CoordinationAuthority,
        component_digest: "cd".repeat(32),
        application_id: 0,
        schema_version: 6,
        rows: 4,
    }
}
fn capsule(
    path: &Path,
    key: &DatabaseKey,
    source: &Path,
    node: &NodeSpec,
    parents: &[&archive::VerifiedArchive],
    index: u8,
) -> archive::VerifiedArchive {
    let sources = [RegisteredSource::new(
        "coordination",
        "current-coordination",
        Source::Journal(source),
    )
    .unwrap()];
    let capsule_id = format!("{index:02x}").repeat(32);
    let authority = Authority(
        ArchiveScope::for_snapshot(path, key, &capsule_id, node, &sources, parents).unwrap(),
    );
    archive::snapshot(archive::SnapshotRequest {
        destination: path,
        key,
        capsule_id: &capsule_id,
        node,
        sources: &sources,
        parents,
        authority: &authority,
    })
    .unwrap();
    archive::inspect(path, key).unwrap()
}
fn initialize(c: &Connection) -> Result<()> {
    c.execute_batch(NEXT)?;
    c.execute(
        "INSERT INTO next_layer VALUES(1,'synthetic-parent-one')",
        [],
    )?;
    Ok(())
}
fn source(directory: &Path, key: &DatabaseKey, binding: &GenerationBinding) -> std::path::PathBuf {
    let path = directory.join("coordination.sqlite");
    let connection = crate::create_encrypted(&path, key).unwrap();
    let c = connection.connection();
    c.execute_batch(OWNER.create_sql).unwrap();
    c.execute("INSERT INTO original(id,label) VALUES(-9,'synthetic-negative-rowid'),(27,'synthetic-history')",[]).unwrap();
    c.execute("INSERT INTO exact_bytes VALUES('exact',x'00ff0102')", [])
        .unwrap();
    c.execute(
        "INSERT INTO prior_fences VALUES('obligation','old-obligation','unknown')",
        [],
    )
    .unwrap();
    c.execute(
        "UPDATE sqlite_sequence SET rowid=17,seq=900 WHERE name='original'",
        [],
    )
    .unwrap();
    let marker = marker(
        binding,
        &provenance(),
        &OWNER,
        &path,
        Purpose::CoordinationRuntime,
        None,
    )
    .unwrap();
    install_marker(c, &marker, &OWNER).unwrap();
    crate::checkpoint_and_sync(c, &path).unwrap();
    drop(connection);
    path
}
#[test]
fn archived_layer_kernel_preserves_rows_lineage_and_exact_retries() {
    let input = directory();
    let capsules = directory();
    let output = directory();
    let parent_key = DatabaseKey::from_bytes([191; 32]);
    let archive_key = DatabaseKey::from_bytes([192; 32]);
    let child_key = DatabaseKey::from_bytes([193; 32]);
    let parent_binding = binding(1);
    let child_binding = binding(2);
    let source = source(input.path(), &parent_key, &parent_binding);
    let before = crate::tests::tree_fingerprint(input.path());
    let node = NodeSpec {
        generation_id: parent_binding.generation_id().into(),
        profile_id: "synthetic-one".into(),
        original_root: input.path().into(),
    };
    let archive = capsule(
        &capsules.path().join("first.sqlite"),
        &archive_key,
        &source,
        &node,
        &[],
        40,
    );
    let archived = archive
        .journal(archive.manifest_digest(), "coordination")
        .unwrap();
    assert!(
        archived
            .open_generation(
                &DatabaseKey::from_bytes([194; 32]),
                &parent_binding,
                &provenance(),
                &OWNER
            )
            .is_err()
    );
    assert!(
        archived
            .open_generation(&parent_key, &child_binding, &provenance(), &OWNER)
            .is_err()
    );
    assert!(
        archived
            .open_generation(&parent_key, &parent_binding, &provenance(), &WRONG)
            .is_err()
    );
    let sealed = archived
        .open_generation(&parent_key, &parent_binding, &provenance(), &OWNER)
        .unwrap();
    let destination = output.path().join("coordination.sqlite");
    initialize_coordination_generation_from_archive(
        &sealed,
        &OWNER,
        &NEXT_OWNER,
        &child_binding,
        &destination,
        &child_key,
        initialize,
    )
    .unwrap();
    let copied = crate::tests::tree_fingerprint(output.path());
    initialize_coordination_generation_from_archive(
        &sealed,
        &OWNER,
        &NEXT_OWNER,
        &child_binding,
        &destination,
        &child_key,
        |_| panic!("exact retry must not replay callback"),
    )
    .unwrap();
    assert!(copied == crate::tests::tree_fingerprint(output.path()));
    let reopened = open_recovered_generation_snapshot(
        &destination,
        &child_key,
        &child_binding,
        sealed.source_provenance(),
        &NEXT_OWNER,
    )
    .unwrap();
    assert_eq!(
        reopened
            .connection()
            .query_row("SELECT label FROM original WHERE rowid=-9", [], |r| r
                .get::<_, String>(0))
            .unwrap(),
        "synthetic-negative-rowid"
    );
    assert_eq!(
        reopened
            .connection()
            .query_row(
                "SELECT payload FROM exact_bytes WHERE id='exact'",
                [],
                |r| r.get::<_, Vec<u8>>(0)
            )
            .unwrap(),
        vec![0, 255, 1, 2]
    );
    assert_eq!(
        reopened
            .connection()
            .query_row(
                "SELECT seq FROM sqlite_sequence WHERE rowid=17 AND name='original'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        900
    );
    assert_eq!(
        reopened
            .connection()
            .query_row(
                "SELECT detail FROM prior_fences WHERE identity='old-obligation'",
                [],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
        "unknown"
    );
    assert!(crate::open_encrypted_quiescent(&destination, &child_key).is_err());
    assert!(
        initialize_coordination_generation_from_archive(
            &sealed,
            &OWNER,
            &NEXT_OWNER,
            &binding(3),
            &destination,
            &child_key,
            initialize
        )
        .is_err()
    );
    let second_node = NodeSpec {
        generation_id: child_binding.generation_id().into(),
        profile_id: "synthetic-two".into(),
        original_root: output.path().into(),
    };
    let second = capsule(
        &capsules.path().join("second.sqlite"),
        &archive_key,
        &destination,
        &second_node,
        &[&archive],
        41,
    );
    assert_eq!(second.report().nodes, 2);
    let second_sealed = second
        .journal(second.manifest_digest(), "coordination")
        .unwrap()
        .open_generation(
            &child_key,
            &child_binding,
            sealed.source_provenance(),
            &NEXT_OWNER,
        )
        .unwrap();
    assert_eq!(second_sealed.snapshot().generation(), &child_binding);
    assert!(
        second
            .journal(archive.manifest_digest(), "coordination")
            .unwrap()
            .open_generation(&parent_key, &parent_binding, &provenance(), &OWNER)
            .is_ok()
    );
    assert!(before == crate::tests::tree_fingerprint(input.path()));
}
#[test]
fn archived_layer_kernel_failure_and_wrong_origin_never_adopt_or_mutate_source() {
    let input = directory();
    let capsules = directory();
    let output = directory();
    let parent_key = DatabaseKey::from_bytes([195; 32]);
    let archive_key = DatabaseKey::from_bytes([196; 32]);
    let child_key = DatabaseKey::from_bytes([197; 32]);
    let parent_binding = binding(4);
    let child_binding = binding(5);
    let source = source(input.path(), &parent_key, &parent_binding);
    let before = crate::tests::tree_fingerprint(input.path());
    let node = NodeSpec {
        generation_id: parent_binding.generation_id().into(),
        profile_id: "synthetic-four".into(),
        original_root: input.path().into(),
    };
    let archive = capsule(
        &capsules.path().join("parent.sqlite"),
        &archive_key,
        &source,
        &node,
        &[],
        42,
    );
    let sealed = archive
        .journal(archive.manifest_digest(), "coordination")
        .unwrap()
        .open_generation(&parent_key, &parent_binding, &provenance(), &OWNER)
        .unwrap();
    let interrupted = output.path().join("interrupted.sqlite");
    assert!(
        initialize_coordination_generation_from_archive(
            &sealed,
            &OWNER,
            &NEXT_OWNER,
            &child_binding,
            &interrupted,
            &child_key,
            |_| Err(BundleError::Permission)
        )
        .is_err()
    );
    assert!(crate::open_encrypted_quiescent(&interrupted, &child_key).is_err());
    initialize_coordination_generation_from_archive(
        &sealed,
        &OWNER,
        &NEXT_OWNER,
        &child_binding,
        &interrupted,
        &child_key,
        initialize,
    )
    .unwrap();
    assert!(
        initialize_coordination_generation_from_archive(
            &sealed,
            &OWNER,
            &NEXT_OWNER,
            &child_binding,
            &source,
            &parent_key,
            initialize
        )
        .is_err()
    );
    let wrong_origin = output.path().join("copied-origin.sqlite");
    std::fs::copy(&source, &wrong_origin).unwrap();
    let wrong_node = NodeSpec {
        generation_id: parent_binding.generation_id().into(),
        profile_id: "synthetic-wrong-origin".into(),
        original_root: output.path().into(),
    };
    let wrong = capsule(
        &capsules.path().join("wrong-origin.sqlite"),
        &archive_key,
        &wrong_origin,
        &wrong_node,
        &[],
        43,
    );
    assert!(
        wrong
            .journal(wrong.manifest_digest(), "coordination")
            .unwrap()
            .open_generation(&parent_key, &parent_binding, &provenance(), &OWNER)
            .is_err()
    );
    assert!(before == crate::tests::tree_fingerprint(input.path()));
}
