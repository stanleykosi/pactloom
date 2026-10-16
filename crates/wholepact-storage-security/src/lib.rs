//! Private, authenticated-at-open storage. This protects confidentiality at rest;
//! it provides no monotonic counter, clone detection, or rollback freshness.
//! Keys must be random independent database keys held by a separate encrypted vault.

pub mod bundle;
mod database_identity;
pub mod generation_archive;
mod read_snapshot;
pub use database_identity::DatabaseFileIdentity;
pub mod receipt_file;

use rusqlite::{Connection, OpenFlags};
use std::{fs, path::Path, time::Duration};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const SQLCIPHER_VERSION: &str = "4.19.0";
pub const OPENSSL_VERSION: &str = "OpenSSL 3.5.9";
const HEADER: &[u8] = b"SQLite format 3\0";

// The stable documented SQLCipher extension is absent from SQLite-only generated
// bindings. A missing SQLCipher library must fail at link time, never fall back.
unsafe extern "C" {
    fn sqlite3_key(
        db: *mut rusqlite::ffi::sqlite3,
        key: *const std::ffi::c_void,
        len: std::ffi::c_int,
    ) -> std::ffi::c_int;
}

/// An independently generated 256-bit storage key. This API never generates or
/// persists keys, accepts passphrases, derives a key from wallet seed, or logs it.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DatabaseKey([u8; 32]);
impl DatabaseKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}
impl std::fmt::Debug for DatabaseKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DatabaseKey([REDACTED])")
    }
}

#[derive(Debug, Error)]
pub enum StorageSecurityError {
    #[error("encrypted storage is unavailable on this platform")]
    UnsupportedPlatform,
    #[error("restored journal is quarantined; writer and exposure reconciliation is required")]
    QuarantinedDatabase,
    #[error("recovered generation requires its dedicated authenticated generation opener")]
    RecoveredGeneration,
    #[error("generation capsule is inert historical material and requires its dedicated verifier")]
    GenerationArchive,
    #[error(
        "uninitialized encrypted database requires explicit recovery; normal open will not initialize it"
    )]
    UninitializedDatabase,
    #[error("encrypted storage requires a private regular file in a private directory")]
    UnsafePath,
    #[error("database already exists; creation will not overwrite it")]
    AlreadyExists,
    #[error("an existing nonempty encrypted database is required")]
    MissingDatabase,
    #[error("plaintext databases are not accepted; migration is a separate operation")]
    PlaintextRefused,
    #[error("the qualified SQLCipher/OpenSSL build is unavailable")]
    UnqualifiedRuntime,
    #[error("database authentication or integrity verification failed")]
    AuthenticationFailed,
    #[error("encrypted storage operation failed")]
    Database,
    #[error("encrypted storage file operation failed")]
    Io,
    #[error("encrypted read snapshot exceeds its bounded resource profile")]
    SnapshotLimit,
    #[error("encrypted read source changed while capturing its snapshot")]
    SourceChanged,
}
pub type Result<T> = std::result::Result<T, StorageSecurityError>;

/// Proof that the factory keyed and authenticated a private disk database before
/// making it available. Consumers own trusted SQL and must not disable encryption,
/// attach plaintext databases, enable traces, or use unkeyed backup convenience APIs.
pub struct EncryptedConnection {
    connection: Connection,
}
impl EncryptedConnection {
    /// Read-only identity of the actual authenticated main database, never a
    /// caller-asserted path. The owner must exclude replacement for its lifetime.
    pub fn database_identity(&self) -> Result<DatabaseFileIdentity> {
        database_identity::capture(&self.connection)
    }
    pub fn connection(&self) -> &Connection {
        &self.connection
    }
    pub fn into_connection(self) -> Connection {
        self.connection
    }
}

/// A source-preserving, authenticated encrypted read snapshot for trusted
/// archive decoders. Only a borrowed read-only connection is exposed: this
/// cannot be consumed as an EncryptedConnection or a live journal connection.
/// Consumers still own trusted SQL and must not export plaintext or disable
/// the qualified encryption/temp-store settings.
pub struct EncryptedReadSnapshot {
    snapshot: read_snapshot::ReadOnlySnapshot,
}
impl EncryptedReadSnapshot {
    /// The ORIGINAL authenticated source file, not the temporary SQLite copy.
    /// This read-only correlation cannot be consumed as a writable journal. The
    /// caller must hold the original complete-source quiescence/ownership lock.
    pub fn source_database_identity(&self) -> Result<DatabaseFileIdentity> {
        self.snapshot.source_database_identity()
    }
    /// Recheck every retained original main/WAL/journal/SHM descriptor and path.
    /// Missing or changed sources fail; this does not establish writer freshness.
    pub fn check_source_unchanged(&self) -> Result<()> {
        self.snapshot.check_retained_source_unchanged()
    }
    pub fn connection(&self) -> &Connection {
        &self.snapshot
    }
}

/// Authenticate a private encrypted copy of an existing database, preserving
/// the original base file and every sidecar. Quarantined and uninitialized
/// sources are rejected exactly as by open_encrypted; only dedicated internal
/// recovery readers may inspect those sources.
///
/// The caller must keep the complete source file set quiescent under its owning
/// locks throughout capture. This is not an atomic backup of concurrent writers
/// or a freshness proof. Copies include WAL/journal ciphertext, never SHM, and
/// are bounded to 512 MiB in aggregate. Temporary copies are private and cleaned
/// up on drop where possible; crashes/cleanup failures can leave encrypted
/// remnants. Hot rollback journals requiring recovery writes fail closed.
pub fn open_encrypted_read_snapshot(
    path: impl AsRef<Path>,
    key: &DatabaseKey,
) -> Result<EncryptedReadSnapshot> {
    let snapshot = open_encrypted_read_only(path.as_ref(), key)?;
    reject_quarantined_or_uninitialized(&snapshot)?;
    Ok(EncryptedReadSnapshot { snapshot })
}

/// Create exclusively. Existing files (including empty files) are never adopted.
/// The caller must provision a directory owned by this user with mode 0700.
pub fn create_encrypted(path: impl AsRef<Path>, key: &DatabaseKey) -> Result<EncryptedConnection> {
    let path = path.as_ref();
    validate_parent(path)?;
    validate_sidecars(path, true)?;
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::AlreadyExists => StorageSecurityError::AlreadyExists,
        _ => StorageSecurityError::Io,
    })?;
    file.sync_all().map_err(|_| StorageSecurityError::Io)?;
    let connection = keyed_connection(path, key)?;
    // Force an encrypted first page without inserting application tables or
    // consuming application_id/user_version, which belong to downstream schemas.
    connection
        .execute_batch("BEGIN IMMEDIATE; PRAGMA user_version = 0; COMMIT;")
        .map_err(|_| StorageSecurityError::Database)?;
    checkpoint_and_sync(&connection, path)?;
    validate_file(path, true)?;
    Ok(EncryptedConnection { connection })
}

/// Open only a preexisting, nonempty encrypted file. No automatic create, rekey,
/// plaintext migration, legacy compatibility fallback, or key retry is performed.
/// This ordinary SQLite opener supports separately serialized connections; it
/// does not copy the file set or require global writer quiescence. Opening even
/// a rejected database may update WAL/SHM sidecars. Source-preserving history
/// uses immutable readers, and explicitly quiescent owners may use the separate
/// `open_encrypted_quiescent` preflight boundary below.
pub fn open_encrypted(path: impl AsRef<Path>, key: &DatabaseKey) -> Result<EncryptedConnection> {
    let path = path.as_ref();
    validate_parent(path)?;
    validate_file(path, true)?;
    validate_sidecars(path, false)?;
    let connection = keyed_connection(path, key)?;
    reject_quarantined_or_uninitialized(&connection)?;
    Ok(EncryptedConnection { connection })
}

/// Open under an actual owning writer/replacement exclusion scope. The owner
/// must exclude source writers, checkpointers and path replacement through its
/// exclusive profile/directory lock and in-process writer lifetime for the
/// entire call. This precondition is not enforced by the ordinary opener.
///
/// Protected identities and wrong keys are rejected on private encrypted copies
/// before a writable SQLite handle can change original sidecars. The complete
/// captured file set is bounded to 512 MiB; copying adds temporary encrypted
/// disk use and I/O and is not production-performance qualified. Descriptor and
/// path stamps detect changes around handle allocation; hostile same-user/OS
/// replacement after the final check is outside this qualified locking boundary.
pub fn open_encrypted_quiescent(
    path: impl AsRef<Path>,
    key: &DatabaseKey,
) -> Result<EncryptedConnection> {
    let path = path.as_ref();
    validate_parent(path)?;
    validate_file(path, true)?;
    validate_sidecars(path, false)?;
    let preflight = open_encrypted_read_only(path, key)?;
    reject_quarantined_or_uninitialized(&preflight)?;
    let connection = keyed_connection_checked(path, key, false, Some(&preflight))?;
    reject_quarantined_or_uninitialized(&connection)?;
    Ok(EncryptedConnection { connection })
}

fn reject_quarantined_or_uninitialized(connection: &Connection) -> Result<()> {
    let application: i64 = connection
        .pragma_query_value(None, "application_id", |r| r.get(0))
        .map_err(|_| StorageSecurityError::Database)?;
    let archive_marker: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name IN ('archive_root','archive_manifests','archive_nodes','archive_objects','archive_chunks')", [], |row| row.get(0)
    ).map_err(|_| StorageSecurityError::Database)?;
    if application == generation_archive::APPLICATION_ID
        || application == generation_archive::STAGING_ID
        || archive_marker != 0
    {
        return Err(StorageSecurityError::GenerationArchive);
    }
    if application == bundle::QUARANTINE_APPLICATION_ID {
        return Err(StorageSecurityError::QuarantinedDatabase);
    }
    // The permanent application identity survives marker erasure. Conversely,
    // merely changing application_id cannot turn a marked generation into an
    // ordinary journal. Neither factory is a recovery/activation path.
    let generation_marker: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name='wholepact_recovered_generation'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StorageSecurityError::Database)?;
    if application == bundle::recovery::generation::RECOVERED_GENERATION_APPLICATION_ID
        || generation_marker != 0
    {
        return Err(StorageSecurityError::RecoveredGeneration);
    }
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(|_| StorageSecurityError::Database)?;
    let objects: i64 = connection
        .query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))
        .map_err(|_| StorageSecurityError::Database)?;
    // A crash after exclusive creation but before the application commits its
    // first schema (or restore marker) must never mint a new authority on reopen.
    // Only the original create_encrypted handle or the dedicated, host-plan-bound
    // empty initialization retry can initialize it; normal open never does.
    if application == 0 && version == 0 && objects == 0 {
        return Err(StorageSecurityError::UninitializedDatabase);
    }
    Ok(())
}

// Only bundle verification may inspect these handles. They never escape through
// public APIs to a live journal constructor.
fn open_quarantined(path: &Path, key: &DatabaseKey) -> Result<EncryptedConnection> {
    validate_parent(path)?;
    validate_file(path, true)?;
    validate_sidecars(path, false)?;
    let connection = keyed_connection(path, key)?;
    let application: i64 = connection
        .pragma_query_value(None, "application_id", |r| r.get(0))
        .map_err(|_| StorageSecurityError::Database)?;
    if application != bundle::QUARANTINE_APPLICATION_ID {
        return Err(StorageSecurityError::AuthenticationFailed);
    }
    Ok(EncryptedConnection { connection })
}

// SQLite READ_ONLY may still modify SHM/WAL sidecars. Keep every SQLite handle
// on private encrypted copies; never expose the original path to SQLite here.
fn open_encrypted_read_only(
    path: &Path,
    key: &DatabaseKey,
) -> Result<read_snapshot::ReadOnlySnapshot> {
    read_snapshot::ReadOnlySnapshot::open(path, key)
}
fn keyed_connection(path: &Path, key: &DatabaseKey) -> Result<Connection> {
    keyed_connection_mode(path, key, false)
}
fn keyed_connection_mode(path: &Path, key: &DatabaseKey, read_only: bool) -> Result<Connection> {
    keyed_connection_checked(path, key, read_only, None)
}
fn keyed_connection_checked(
    path: &Path,
    key: &DatabaseKey,
    read_only: bool,
    preflight: Option<&read_snapshot::ReadOnlySnapshot>,
) -> Result<Connection> {
    if let Some(preflight) = preflight {
        preflight.check_source_unchanged(path)?;
    }
    let mode = if read_only {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    } else {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    };
    let flags = mode | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    // No URI flag: key-bearing URI options are never accepted.
    let connection =
        Connection::open_with_flags(path, flags).map_err(|_| StorageSecurityError::Database)?;
    // Check immediately after handle allocation and before any SQL can rebuild
    // source WAL shared memory. The owner lock, not these checks, excludes an
    // adversarial swap between this final check and SQLite's first source read.
    if let Some(preflight) = preflight {
        preflight.check_source_unchanged(path)?;
    }
    // SQLCipher uses the same raw-key syntax through sqlite3_key as PRAGMA key.
    // 32 arbitrary binary bytes would instead be interpreted as a passphrase.
    let mut raw = Zeroizing::new([0u8; 67]);
    raw[0] = b'x';
    raw[1] = b'\'';
    raw[66] = b'\'';
    const HEX: &[u8] = b"0123456789abcdef";
    for (i, value) in key.0.iter().enumerate() {
        raw[2 + i * 2] = HEX[(value >> 4) as usize];
        raw[3 + i * 2] = HEX[(value & 15) as usize];
    }
    // SAFETY: the live connection owns its SQLite handle; SQLCipher consumes/copies
    // exactly 67 bytes synchronously. No SQL, tracing, or logging sees these bytes.
    let rc = unsafe { sqlite3_key(connection.handle(), raw.as_ptr().cast(), 67) };
    drop(raw);
    if rc != rusqlite::ffi::SQLITE_OK {
        return Err(StorageSecurityError::AuthenticationFailed);
    }
    // This is the first SQL. Unknown pragmas return no row, which is an error.
    verify_runtime(&connection)?;
    connection.execute_batch("PRAGMA cipher_memory_security=ON; PRAGMA cipher_plaintext_header_size=0; PRAGMA cipher_use_hmac=ON; PRAGMA temp_store=MEMORY;")
        .map_err(|_| StorageSecurityError::UnqualifiedRuntime)?;
    connection
        .query_row("SELECT count(*) FROM sqlite_schema", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(|_| StorageSecurityError::AuthenticationFailed)?;
    verify_cipher_integrity(&connection)?;
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|_| StorageSecurityError::Database)?;
    if read_only {
        connection
            .execute_batch(
                "PRAGMA query_only=ON; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;",
            )
            .map_err(|_| StorageSecurityError::Database)?;
        return Ok(connection);
    }
    let mode: String = connection
        .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
        .map_err(|_| StorageSecurityError::Database)?;
    if mode != "wal" {
        return Err(StorageSecurityError::Database);
    }
    connection.execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON; PRAGMA trusted_schema=OFF;")
        .map_err(|_| StorageSecurityError::Database)?;
    Ok(connection)
}

fn verify_runtime(connection: &Connection) -> Result<()> {
    let read = |sql| {
        connection
            .query_row(sql, [], |row| row.get::<_, String>(0))
            .map_err(|_| StorageSecurityError::UnqualifiedRuntime)
    };
    let version = read("PRAGMA cipher_version")?;
    let provider = read("PRAGMA cipher_provider")?;
    let provider_version = read("PRAGMA cipher_provider_version")?;
    let status = read("PRAGMA cipher_status")?;
    if version.split_whitespace().next() != Some(SQLCIPHER_VERSION)
        || provider != "openssl"
        || provider_version
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            != ["OpenSSL", "3.5.9"]
        || status != "1"
        || rusqlite::version_number() != 3_053_004
    {
        return Err(StorageSecurityError::UnqualifiedRuntime);
    }
    // Global C metadata avoids a SELECT that might read the database schema
    // before the dedicated authentication read and misclassify a wrong key.
    let memory_temp =
        unsafe { rusqlite::ffi::sqlite3_compileoption_used(c"TEMP_STORE=3".as_ptr()) } == 1;
    if !memory_temp {
        return Err(StorageSecurityError::UnqualifiedRuntime);
    }
    Ok(())
}

/// Authenticate every page, not just the schema. This is deliberately conservative
/// at open time; changing its performance policy requires separate qualification.
fn verify_cipher_integrity(connection: &Connection) -> Result<()> {
    let mut statement = connection
        .prepare("PRAGMA cipher_integrity_check")
        .map_err(|_| StorageSecurityError::AuthenticationFailed)?;
    let mut rows = statement
        .query([])
        .map_err(|_| StorageSecurityError::AuthenticationFailed)?;
    if rows
        .next()
        .map_err(|_| StorageSecurityError::AuthenticationFailed)?
        .is_some()
    {
        return Err(StorageSecurityError::AuthenticationFailed);
    }
    Ok(())
}

fn checkpoint_and_sync(connection: &Connection, path: &Path) -> Result<()> {
    let (busy, _, _): (i64, i64, i64) = connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .map_err(|_| StorageSecurityError::Database)?;
    if busy != 0 {
        return Err(StorageSecurityError::Database);
    }
    fs::File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|_| StorageSecurityError::Io)?;
    fs::File::open(path.parent().ok_or(StorageSecurityError::UnsafePath)?)
        .and_then(|f| f.sync_all())
        .map_err(|_| StorageSecurityError::Io)?;
    Ok(())
}

fn validate_parent(path: &Path) -> Result<()> {
    // Only the Linux filesystem/build boundary has qualification evidence.
    if !cfg!(target_os = "linux") {
        return Err(StorageSecurityError::UnsupportedPlatform);
    }
    if path.file_name().is_none() {
        return Err(StorageSecurityError::UnsafePath);
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or(StorageSecurityError::UnsafePath)?;
    let meta = fs::symlink_metadata(parent).map_err(|_| StorageSecurityError::UnsafePath)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no arguments or memory effects.
        if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return Err(StorageSecurityError::UnsafePath);
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        Err(StorageSecurityError::UnsupportedPlatform)
    }
}
fn validate_file(path: &Path, nonempty: bool) -> Result<()> {
    use std::io::Read;
    let meta = fs::symlink_metadata(path).map_err(|_| StorageSecurityError::MissingDatabase)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !meta.is_file()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.mode() & 0o077 != 0
            || meta.nlink() != 1
        {
            return Err(StorageSecurityError::UnsafePath);
        }
    }
    if nonempty && meta.len() < 4096 {
        return Err(StorageSecurityError::MissingDatabase);
    }
    let mut file = fs::OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| StorageSecurityError::Io)?;
    let mut header = [0u8; 16];
    file.read_exact(&mut header)
        .map_err(|_| StorageSecurityError::AuthenticationFailed)?;
    if header == HEADER {
        return Err(StorageSecurityError::PlaintextRefused);
    }
    Ok(())
}

fn validate_sidecars(path: &Path, exclusive: bool) -> Result<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        let sidecar = std::path::PathBuf::from(name);
        match fs::symlink_metadata(&sidecar) {
            Ok(meta) => {
                if exclusive {
                    return Err(StorageSecurityError::AlreadyExists);
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if !meta.is_file()
                        || meta.uid() != unsafe { libc::geteuid() }
                        || meta.mode() & 0o077 != 0
                        || meta.nlink() != 1
                    {
                        return Err(StorageSecurityError::UnsafePath);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(StorageSecurityError::Io),
        }
    }
    Ok(())
}

/// A consistent SQLite snapshot to a separately keyed, exclusive destination.
/// Never use Connection::backup(path): it opens an unkeyed destination. The backup
/// API is verified here with SQLCipher page codecs on both handles.
pub fn backup_encrypted(
    source: &EncryptedConnection,
    path: impl AsRef<Path>,
    key: &DatabaseKey,
) -> Result<()> {
    verify_runtime(&source.connection)?;
    let path = path.as_ref();
    let mut destination = create_encrypted(path, key)?;
    {
        let backup = rusqlite::backup::Backup::new(&source.connection, &mut destination.connection)
            .map_err(|_| StorageSecurityError::Database)?;
        // Bounded attempt; caller decides when to retry if another writer prevents progress.
        for _ in 0..1000 {
            match backup
                .step(256)
                .map_err(|_| StorageSecurityError::Database)?
            {
                rusqlite::backup::StepResult::Done => break,
                rusqlite::backup::StepResult::More => continue,
                _ => return Err(StorageSecurityError::Database),
            }
        }
        if backup.progress().remaining != 0 {
            return Err(StorageSecurityError::Database);
        }
    }
    verify_cipher_integrity(&destination.connection)?;
    checkpoint_and_sync(&destination.connection, path)?;
    drop(destination);
    // Verify the persisted copy under its destination key, never only its source handle.
    open_encrypted(path, key)?;
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests;

mod planned_witness_initialization;
pub use planned_witness_initialization::{
    PlannedWitnessBirthInitialization, PlannedWitnessBirthInspection,
};
#[cfg(target_os = "linux")]
pub mod witness_namespace_fs;

mod planned_named_verifier_initialization;
pub use planned_named_verifier_initialization::{PlannedNamedVerifierOutboxInitialization, PlannedNamedVerifierOutboxInspection, NamedVerifierOutboxInitialization};
