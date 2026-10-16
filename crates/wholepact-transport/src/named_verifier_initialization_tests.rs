//! Actual SQLCipher first-page retry fixtures with OS-random ephemeral test-only
//! storage/transport material and public messages. No wallet, signing identity, NativeDecision, generation
//! authority or network exists. Plans are test-only correlation expectations;
//! these tests do not authenticate a production durable intent or owner approval.
use crate::{
    ArtifactKind, DisclosureField, ExportRequest, MessageContext, MessageOrder,
    OUTBOX_BACKUP_TEMPLATE, SqliteOutbox, Timestamp, TransportError, TransportSecret,
    prepare_export,
};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use wholepact_storage_security::{
    DatabaseKey, PlannedNamedVerifierOutboxInitialization as Planned,
    PlannedNamedVerifierOutboxInspection as Inspection, StorageSecurityError,
    bundle::{QUARANTINE_APPLICATION_ID, open_journal_read_snapshot},
    create_encrypted, open_encrypted_quiescent,
};

use zeroize::Zeroizing;

// A fresh context per test keeps each original key stable through interruptions
// and replay while making every test-only secret ephemeral and OS-random.
// Only encrypted fixture data reaches disk; keys are never logged or persisted.
struct EphemeralKeys {
    database: DatabaseKey,
    wrong_database: DatabaseKey,
    sender: TransportSecret,
    recipient: TransportSecret,
}
fn ephemeral_bytes() -> Zeroizing<[u8; 32]> {
    let mut bytes = Zeroizing::new([0; 32]);
    loop {
        getrandom::fill(&mut *bytes).expect("OS randomness for isolated fixture");
        if *bytes != [0; 32] {
            return bytes;
        }
    }
}
impl EphemeralKeys {
    fn new() -> Self {
        let database = ephemeral_bytes();
        let wrong_database = loop {
            let candidate = ephemeral_bytes();
            if *candidate != *database {
                break candidate;
            }
        };
        Self {
            database: DatabaseKey::from_bytes(*database),
            wrong_database: DatabaseKey::from_bytes(*wrong_database),
            sender: TransportSecret::from_bytes(*ephemeral_bytes()).unwrap(),
            recipient: TransportSecret::from_bytes(*ephemeral_bytes()).unwrap(),
        }
    }
}
fn verifier() -> String {
    "a1".repeat(32)
}
fn original_review() -> String {
    "b2".repeat(32)
}
/// Mirrors the owned/private fixture-lock boundary without depending on the
/// signer crate or adding a transport->signer/storage dependency cycle.
struct PrivateFixture {
    path: PathBuf,
    lock: Option<File>,
}
impl PrivateFixture {
    fn new() -> Self {
        static SERIAL: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "wholepact-public-named-initialization-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        let path = fs::canonicalize(path).unwrap();
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path.join("synthetic.lock"))
            .unwrap();
        lock.try_lock().unwrap();
        Self {
            path,
            lock: Some(lock),
        }
    }
    fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}
impl Drop for PrivateFixture {
    fn drop(&mut self) {
        drop(self.lock.take());
        let _ = fs::remove_dir_all(&self.path);
    }
}
// Preserve names, content, identity, permissions and modification times. Ordinary
// reading can update access times, which are deliberately outside this promise.
type FileState = (Vec<u8>, u32, u64, u64, i64, i64);
fn fingerprint(directory: &PrivateFixture) -> BTreeMap<PathBuf, FileState> {
    fs::read_dir(&directory.path)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            assert!(metadata.is_file() && !metadata.file_type().is_symlink());
            (
                path.file_name().unwrap().into(),
                (
                    fs::read(&path).unwrap(),
                    metadata.mode(),
                    metadata.dev(),
                    metadata.ino(),
                    metadata.mtime(),
                    metadata.mtime_nsec(),
                ),
            )
        })
        .collect()
}
fn commitment(key: &DatabaseKey) -> [u8; 32] {
    Planned::database_key_commitment(key)
}
fn plan(path: &Path, key: &DatabaseKey) -> Planned {
    Planned::new(&verifier(), &original_review(), path, key, &commitment(key)).unwrap()
}
fn inspect(
    plan: &Planned,
    path: &Path,
    key: &DatabaseKey,
) -> wholepact_storage_security::Result<Inspection> {
    plan.inspect(path, key, &verifier(), &original_review(), &commitment(key))
}
fn resume(
    plan: &Planned,
    path: &Path,
    key: &DatabaseKey,
) -> wholepact_storage_security::Result<wholepact_storage_security::NamedVerifierOutboxInitialization>
{
    plan.resume(path, key, &verifier(), &original_review(), &commitment(key))
}
fn at(seconds: i64) -> Timestamp {
    Timestamp::from_unix_seconds(1_790_000_000 + seconds).unwrap()
}
fn context() -> MessageContext {
    MessageContext {
        network_profile_id: "testnet-public-synthetic-unqualified".into(),
        agreement_id: "public-synthetic-agreement".into(),
        proposal_id: "public-proposal".into(),
        proposal_revision: 1,
        sender_id: "public-sender".into(),
        recipient_id: "public-recipient".into(),
        artifact_kind: ArtifactKind::Invitation,
    }
}
fn enqueue_public_message(outbox: &mut SqliteOutbox, keys: &EphemeralKeys) -> Vec<u8> {
    let sender = &keys.sender;
    let recipient = keys.recipient.public_key().unwrap();
    let prepared = prepare_export(
        ExportRequest {
            context: context(),
            order: MessageOrder {
                message_id: "01".repeat(16),
                sequence: 1,
                issued_at: at(0),
                expires_at: at(600),
            },
            purpose: "Public synthetic first-page qualification".into(),
            persistence_warning: "Public synthetic recipient copies persist".into(),
        },
        vec![
            DisclosureField::new("public-message", b"public synthetic setup refusal".to_vec())
                .unwrap(),
        ],
        &sender.public_key().unwrap(),
        &recipient,
        &at(0),
    )
    .unwrap();
    let preview = prepared.preview().digest().unwrap();
    outbox
        .enqueue(prepared, sender, &preview, &at(0))
        .unwrap()
        .envelope()
        .as_bytes()
        .to_vec()
}

#[test]
fn named_verifier_real_encrypted_first_page_resumes_only_before_outbox_schema_commit() {
    let keys = EphemeralKeys::new();
    let directory = PrivateFixture::new();
    let path = directory.file("planned.sqlite");
    let key = &keys.database;
    let plan = plan(&path, key);
    let absent = fingerprint(&directory);
    assert!(inspect(&plan, &path, key).is_err());
    assert!(resume(&plan, &path, key).is_err());
    assert_eq!(fingerprint(&directory), absent);
    assert!(!path.exists());
    // Simulated crash boundary: the actual encrypted first page exists, but the
    // original typed outbox constructor has never been called.
    drop(create_encrypted(&path, key).unwrap());
    let first_page = fingerprint(&directory);
    assert!(!fs::read(&path).unwrap().starts_with(b"SQLite format 3\0"));
    assert!(matches!(
        open_encrypted_quiescent(&path, key),
        Err(StorageSecurityError::UninitializedDatabase)
    ));
    assert!(matches!(
        inspect(&plan, &path, key).unwrap(),
        Inspection::AuthenticatedPristineEmpty
    ));
    assert_eq!(fingerprint(&directory), first_page);
    // A second interruption after authenticated resume but still before schema
    // commit remains the same pristine planned page, not replacement keys.
    drop(resume(&plan, &path, key).unwrap());
    assert!(matches!(
        inspect(&plan, &path, key).unwrap(),
        Inspection::AuthenticatedPristineEmpty
    ));
    let outbox =
        SqliteOutbox::from_named_verifier_initialization(resume(&plan, &path, key).unwrap())
            .unwrap();
    outbox.require_empty_for_initial_setup().unwrap();
    assert_eq!(outbox.next_sequence(&context()).unwrap(), 1);
    drop(outbox);
    let initialized = fingerprint(&directory);
    match inspect(&plan, &path, key).unwrap() {
        Inspection::Initialized(snapshot) => {
            let count: i64 = snapshot
                .connection()
                .query_row("SELECT count(*) FROM outbox", [], |row| row.get(0))
                .unwrap();
            assert_eq!(count, 0);
        }
        Inspection::AuthenticatedPristineEmpty => {
            panic!("committed outbox was treated as first page")
        }
    }
    // Exact trusted schema authentication is separate from coarse classification.
    let checked = SqliteOutbox::inspect_empty_named_verifier_setup(&path, key).unwrap();
    let count: i64 = checked
        .connection()
        .query_row("SELECT count(*) FROM outbox", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
    drop(checked);
    assert!(resume(&plan, &path, key).is_err());
    assert_eq!(fingerprint(&directory), initialized);
    let reopened =
        SqliteOutbox::from_encrypted_connection(open_encrypted_quiescent(&path, key).unwrap())
            .unwrap();
    reopened.require_empty_for_initial_setup().unwrap();
    assert_eq!(reopened.next_sequence(&context()).unwrap(), 1);
}

#[test]
fn named_verifier_real_initialization_rejects_changed_plan_path_key_and_commitment_without_mutation()
 {
    let keys = EphemeralKeys::new();
    let directory = PrivateFixture::new();
    let path = directory.file("planned.sqlite");
    let other = directory.file("other.sqlite");
    let key = &keys.database;
    let wrong = &keys.wrong_database;
    drop(create_encrypted(&path, key).unwrap());
    drop(create_encrypted(&other, key).unwrap());
    let plan = plan(&path, key);
    let before = fingerprint(&directory);
    let correct = commitment(key);
    let changed_verifier = "c3".repeat(32);
    let changed_review = "d4".repeat(32);
    for (verifier_digest, review) in [
        (changed_verifier, original_review()),
        (verifier(), changed_review),
    ] {
        assert!(
            plan.inspect(&path, key, &verifier_digest, &review, &correct)
                .is_err()
        );
        assert!(
            plan.resume(&path, key, &verifier_digest, &review, &correct)
                .is_err()
        );
    }
    assert!(
        plan.inspect(&other, key, &verifier(), &original_review(), &correct)
            .is_err()
    );
    assert!(
        plan.resume(&other, key, &verifier(), &original_review(), &correct)
            .is_err()
    );
    assert!(
        plan.inspect(&path, wrong, &verifier(), &original_review(), &correct)
            .is_err()
    );
    assert!(
        plan.resume(&path, wrong, &verifier(), &original_review(), &correct)
            .is_err()
    );
    let mut changed = correct;
    changed[0] ^= 1;
    assert!(
        plan.inspect(&path, key, &verifier(), &original_review(), &changed)
            .is_err()
    );
    assert!(
        plan.resume(&path, key, &verifier(), &original_review(), &changed)
            .is_err()
    );
    assert!(Planned::new(&verifier(), &original_review(), &path, key, &changed).is_err());
    // Even self-consistent wrong key metadata cannot authenticate the actual
    // encrypted original. This is distinct from the cheap expectation mismatch.
    let wrong_plan = Planned::new(
        &verifier(),
        &original_review(),
        &path,
        wrong,
        &commitment(wrong),
    )
    .unwrap();
    assert!(inspect(&wrong_plan, &path, wrong).is_err());
    assert!(resume(&wrong_plan, &path, wrong).is_err());
    assert_eq!(fingerprint(&directory), before);
}

#[test]
fn named_verifier_real_nonempty_outbox_is_refused_on_immutable_exact_schema_snapshot() {
    let keys = EphemeralKeys::new();
    let directory = PrivateFixture::new();
    let path = directory.file("nonempty.sqlite");
    let key = &keys.database;
    let mut outbox =
        SqliteOutbox::from_encrypted_connection(create_encrypted(&path, key).unwrap()).unwrap();
    let original = enqueue_public_message(&mut outbox, &keys);
    assert!(matches!(
        outbox.require_empty_for_initial_setup(),
        Err(TransportError::Equivocation)
    ));
    drop(outbox);
    let plan = plan(&path, key);
    let before = fingerprint(&directory);
    assert!(matches!(
        inspect(&plan, &path, key).unwrap(),
        Inspection::Initialized(_)
    ));
    assert!(resume(&plan, &path, key).is_err());
    // Exercise the actual shared owner preflight, not a copied count gate.
    assert!(matches!(
        SqliteOutbox::inspect_empty_named_verifier_setup(&path, key),
        Err(TransportError::AuthorityUnavailable)
    ));
    // Independently inspect why the real helper refused, without opening any
    // writable original or treating retained ciphertext as new export authority.
    let checked = open_journal_read_snapshot(&path, key, &OUTBOX_BACKUP_TEMPLATE).unwrap();
    let count: i64 = checked
        .connection()
        .query_row("SELECT count(*) FROM outbox", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
    assert_ne!(
        count, 0,
        "Prepared setup must refuse before a writable opener"
    );
    let (sequence, envelope): (i64, Vec<u8>) = checked
        .connection()
        .query_row("SELECT sequence,envelope FROM outbox", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap();
    assert_eq!(sequence, 1);
    assert_eq!(envelope, original);
    drop(checked);
    assert_eq!(fingerprint(&directory), before);
}

#[test]
fn named_verifier_real_empty_retry_rejects_zero_corrupt_unknown_quarantine_and_recovered_sources_unchanged()
 {
    let keys = EphemeralKeys::new();
    let directory = PrivateFixture::new();
    let key = &keys.database;
    // Rejections below exercise actual authenticated source pages and source
    // sidecars, not merely a copied enum/tuple predicate.
    let zero = directory.file("zero.sqlite");
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&zero)
        .unwrap()
        .sync_all()
        .unwrap();
    let zero_plan = plan(&zero, key);
    let before = fingerprint(&directory);
    assert!(inspect(&zero_plan, &zero, key).is_err());
    assert!(resume(&zero_plan, &zero, key).is_err());
    assert_eq!(fingerprint(&directory), before);
    let corrupt = directory.file("corrupt.sqlite");
    drop(create_encrypted(&corrupt, key).unwrap());
    let mut bytes = fs::read(&corrupt).unwrap();
    assert!(bytes.len() > 100);
    bytes[100] ^= 0x80;
    fs::write(&corrupt, &bytes).unwrap();
    let corrupt_plan = plan(&corrupt, key);
    let before = fingerprint(&directory);
    assert!(inspect(&corrupt_plan, &corrupt, key).is_err());
    assert!(resume(&corrupt_plan, &corrupt, key).is_err());
    assert_eq!(fingerprint(&directory), before);
    let cases=[
        ("unknown.sqlite","CREATE TABLE foreign_rows(value TEXT);".to_owned(),false),
        ("extra-schema.sqlite",format!("{} CREATE TABLE extra_rows(value TEXT); PRAGMA application_id={}; PRAGMA user_version={};",OUTBOX_BACKUP_TEMPLATE.create_sql,OUTBOX_BACKUP_TEMPLATE.application_id,OUTBOX_BACKUP_TEMPLATE.schema_version),false),
        ("quarantine.sqlite",format!("PRAGMA application_id={QUARANTINE_APPLICATION_ID};"),true),
        ("recovered.sqlite",format!("PRAGMA application_id={};",wholepact_storage_security::bundle::recovery::generation::RECOVERED_GENERATION_APPLICATION_ID),true),
        ("discarded.sqlite","CREATE TABLE discarded(value TEXT); DROP TABLE discarded;".to_owned(),true),
    ];
    for (name, sql, classifier_refuses) in cases {
        let path = directory.file(name);
        let connection = create_encrypted(&path, key).unwrap();
        connection.connection().execute_batch(&sql).unwrap();
        drop(connection);
        let plan = plan(&path, key);
        let before = fingerprint(&directory);
        if classifier_refuses {
            assert!(inspect(&plan, &path, key).is_err());
        } else {
            assert!(matches!(
                inspect(&plan, &path, key).unwrap(),
                Inspection::Initialized(_)
            ));
        }
        assert!(resume(&plan, &path, key).is_err());
        assert!(open_journal_read_snapshot(&path, key, &OUTBOX_BACKUP_TEMPLATE).is_err());
        assert!(matches!(
            SqliteOutbox::inspect_empty_named_verifier_setup(&path, key),
            Err(TransportError::AuthorityUnavailable)
        ));
        assert_eq!(
            fingerprint(&directory),
            before,
            "rejected source changed: {name}"
        );
    }
}
