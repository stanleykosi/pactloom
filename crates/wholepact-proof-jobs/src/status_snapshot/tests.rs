use super::*;
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
};
struct Inspect(CheckpointScope, bool);
impl LocalProofConsent for Inspect {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        self.1 && &self.0 == scope && action == LocalAction::InspectStatus
    }
}
fn scope() -> CheckpointScope {
    CheckpointScope {
        principal_id: "synthetic-inspector".into(),
        candidate_id: "synthetic-candidate".into(),
        manifest_digest: "a".repeat(64),
        artifact_digest: "b".repeat(64),
        effects_commitment: "c".repeat(64),
        coordination_request_digest: "d".repeat(64),
        review_binding: "e".repeat(64),
        account_ids: vec!["synthetic-account".into()],
        local_operator: "synthetic-host".into(),
        purpose: "metadata-only-fixture".into(),
        retention_policy: "local".into(),
    }
}
struct Fixture {
    store: ProofJobStore,
    path: PathBuf,
    key: DatabaseKey,
    dir: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("proof.sqlite");
        let key = DatabaseKey::from_bytes([91; 32]);
        let store = ProofJobStore::from_encrypted_connection(
            wholepact_storage_security::create_encrypted(&path, &key).unwrap(),
        )
        .unwrap();
        Self {
            store,
            path,
            key,
            dir,
        }
    }
    fn insert(&self) {
        let s = scope();
        let job = job_id_for_key(&s.principal_id, "synthetic-original-key").unwrap();
        // Inert private bytes intentionally cannot be parsed as a candidate.
        self.store.connection.lock().unwrap().execute(
            "INSERT INTO proof_jobs(job_id,principal_id,idem_key,request_digest,scope,input_digest,input,policy,maximum_actions,state,attempt) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,1,'uncertain',7)",
            params![job,&s.principal_id,"synthetic-original-key","f".repeat(64),serde_json::to_vec(&s).unwrap(),"b".repeat(64),b"INERT NON-PCZT".as_slice(),b"INERT POLICY".as_slice()],
        ).unwrap();
    }
}
#[derive(Debug, PartialEq, Eq)]
struct Stamp {
    mode: u32,
    inode: u64,
    len: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
    digest: Option<String>,
}
fn tree(path: &Path) -> BTreeMap<PathBuf, Stamp> {
    let mut result = BTreeMap::new();
    for entry in std::iter::once(path.to_path_buf())
        .chain(fs::read_dir(path).unwrap().map(|e| e.unwrap().path()))
    {
        let m = fs::symlink_metadata(&entry).unwrap();
        let bytes = m.is_file().then(|| digest(&fs::read(&entry).unwrap()));
        result.insert(
            entry.strip_prefix(path).unwrap().to_path_buf(),
            Stamp {
                mode: m.mode(),
                inode: m.ino(),
                len: m.len(),
                mtime: (m.mtime(), m.mtime_nsec()),
                ctime: (m.ctime(), m.ctime_nsec()),
                digest: bytes,
            },
        );
    }
    result
}
#[test]
fn immutable_status_preserves_full_source_tree_and_uncertain_attempt() {
    let f = Fixture::new();
    f.insert();
    let before = tree(f.dir.path());
    let owner = ProofStatusSnapshot::open(&f.path, &f.key).unwrap();
    let s = scope();
    let summary = owner
        .status_for_key(
            &s.principal_id,
            "synthetic-original-key",
            &s.coordination_request_digest,
            &Inspect(s.clone(), true),
        )
        .unwrap()
        .unwrap();
    assert_eq!(summary.state, JobState::Uncertain);
    assert_eq!(summary.attempt, 7);
    assert!(!summary.authorization_allowed && !summary.distribution_allowed);
    assert_eq!(
        owner.status_for_key(
            &s.principal_id,
            "synthetic-original-key",
            &s.coordination_request_digest,
            &Inspect(s.clone(), false)
        ),
        Err(JobError::ConsentDenied)
    );
    assert!(
        owner
            .status_for_key(
                &s.principal_id,
                "synthetic-absent-key",
                &s.coordination_request_digest,
                &Inspect(s.clone(), false)
            )
            .unwrap()
            .is_none()
    );
    owner.source_database_identity().unwrap();
    owner.check_source_unchanged().unwrap();
    drop(owner);
    assert_eq!(before, tree(f.dir.path()));
}
#[test]
fn source_changes_wrong_key_and_wrong_schema_never_create_status_authority() {
    let f = Fixture::new();
    f.insert();
    let before = tree(f.dir.path());
    assert!(ProofStatusSnapshot::open(&f.path, &DatabaseKey::from_bytes([92; 32])).is_err());
    assert_eq!(before, tree(f.dir.path()));
    let owner = ProofStatusSnapshot::open(&f.path, &f.key).unwrap();
    f.store
        .connection
        .lock()
        .unwrap()
        .execute("UPDATE proof_jobs SET attempt=8", [])
        .unwrap();
    let after = tree(f.dir.path());
    assert!(owner.check_source_unchanged().is_err());
    let s = scope();
    assert!(
        owner
            .status_for_key(
                &s.principal_id,
                "synthetic-original-key",
                &s.coordination_request_digest,
                &Inspect(s.clone(), true)
            )
            .is_err()
    );
    assert_eq!(after, tree(f.dir.path()));
    drop(owner);
    f.store
        .connection
        .lock()
        .unwrap()
        .execute_batch("CREATE TABLE sqliteX_untrusted(id TEXT)")
        .unwrap();
    let after = tree(f.dir.path());
    assert!(ProofStatusSnapshot::open(&f.path, &f.key).is_err());
    assert_eq!(after, tree(f.dir.path()));
}
#[test]
fn corrupted_original_key_binding_is_never_absence() {
    for change in [
        "job_id='wrong-job-id'",
        "principal_id='wrong-principal'",
        "idem_key='wrong-original-key'",
    ] {
        let f = Fixture::new();
        f.insert();
        f.store
            .connection
            .lock()
            .unwrap()
            .execute(&format!("UPDATE proof_jobs SET {change}"), [])
            .unwrap();
        let before = tree(f.dir.path());
        let owner = ProofStatusSnapshot::open(&f.path, &f.key).unwrap();
        let s = scope();
        assert!(
            owner
                .status_for_key(
                    &s.principal_id,
                    "synthetic-original-key",
                    &s.coordination_request_digest,
                    &Inspect(s.clone(), true)
                )
                .is_err()
        );
        drop(owner);
        assert_eq!(before, tree(f.dir.path()));
    }
}

#[test]
fn malformed_selected_digest_or_result_shape_is_not_verified_status() {
    for change in [
        "request_digest='not-a-digest'",
        "input_digest='not-a-digest'",
        "state='succeeded',result=X'00',result_digest='not-a-digest'",
        "result=X'00'",
    ] {
        let f = Fixture::new();
        f.insert();
        f.store
            .connection
            .lock()
            .unwrap()
            .execute(&format!("UPDATE proof_jobs SET {change}"), [])
            .unwrap();
        let before = tree(f.dir.path());
        let owner = ProofStatusSnapshot::open(&f.path, &f.key).unwrap();
        let s = scope();
        assert!(
            owner
                .status_for_key(
                    &s.principal_id,
                    "synthetic-original-key",
                    &s.coordination_request_digest,
                    &Inspect(s.clone(), true)
                )
                .is_err()
        );
        drop(owner);
        assert_eq!(before, tree(f.dir.path()));
    }
}
