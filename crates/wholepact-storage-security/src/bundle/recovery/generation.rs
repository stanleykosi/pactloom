//! Integrity boundary for separately reconstructed generations. These types do
//! not establish native consent, live signer continuity, or publication. The
//! native host must authenticate its committed whole-generation manifest and
//! hold its current publication/revocation admission before opening a runtime.
//! In particular, a caller-selected key or a saved marker is not native consent.

use super::{RecoveryProvenance, VerifiedRecoveryComponent, wallet};
use crate::{DatabaseKey, StorageSecurityError};
use rusqlite::{Connection, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

mod empty_initialization;
mod layered;
pub use empty_initialization::PlannedEmptyInitialization;
pub use layered::{
    coordination_owner_rows_commitment, initialize_coordination_generation_from_archive,
};

use super::super::{
    BundleError, JournalKind, JournalTemplate, hex_digest, identifier, integrity,
    validate_component_template, verify_restored_rows,
};

type Result<T> = std::result::Result<T, BundleError>;

/// Permanent identity for recovered runtime and evidence files. Ordinary open
/// rejects this identity even if the marker is removed. No API clears it.
pub const RECOVERED_GENERATION_APPLICATION_ID: i64 = 0x57504752;

pub(super) const MARKER_SCHEMA: &str = "CREATE TABLE wholepact_recovered_generation(
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    binding BLOB NOT NULL CHECK(length(binding)<=1048576));
    CREATE TRIGGER immutable_recovered_generation_update BEFORE UPDATE ON wholepact_recovered_generation BEGIN SELECT RAISE(ABORT,'immutable'); END;
    CREATE TRIGGER immutable_recovered_generation_delete BEFORE DELETE ON wholepact_recovered_generation BEGIN SELECT RAISE(ABORT,'immutable'); END;";

/// Validated correlation metadata, never an authority token. It deliberately has
/// no deserialization constructor. A dedicated opener additionally authenticates
/// the independently keyed persisted marker, exact path, provenance and schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerationBinding {
    generation_id: String,
    inventory_digest: String,
}
impl GenerationBinding {
    pub fn new(generation_id: &str, inventory_digest: &str) -> Result<Self> {
        hash(generation_id)?;
        hash(inventory_digest)?;
        Ok(Self {
            generation_id: generation_id.into(),
            inventory_digest: inventory_digest.into(),
        })
    }
    pub fn generation_id(&self) -> &str {
        &self.generation_id
    }
    pub fn inventory_digest(&self) -> &str {
        &self.inventory_digest
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Purpose {
    CoordinationRuntime,
    ImmutableEvidence,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Marker {
    format: u32,
    generation_id: String,
    inventory_digest: String,
    destination: String,
    provenance: RecoveryProvenance,
    successor_schema_digest: String,
    purpose: Purpose,
    // Only evidence includes the exact original manifest needed to authenticate
    // retained row bytes after the source inventory has been dropped.
    pub(super) component: Option<super::super::ComponentManifest>,
}

/// A sealed integrity proof and dedicated connection, not a published runtime
/// credential. Never accepted by ordinary journal constructors. Owning crates
/// must validate their conservative overlays before admitting any operations.
pub struct RecoveredGenerationConnection {
    connection: Connection,
    generation: GenerationBinding,
    provenance: RecoveryProvenance,
}
impl RecoveredGenerationConnection {
    /// Identity of this already authenticated live generation connection.
    /// Owning journals retain it before ownership transfer; no caller path,
    /// unauthenticated handle, DTO or historical snapshot can supply it.
    pub fn database_identity(&self) -> crate::Result<crate::DatabaseFileIdentity> {
        crate::database_identity::capture(&self.connection)
    }
    pub fn generation(&self) -> &GenerationBinding {
        &self.generation
    }
    pub fn provenance(&self) -> &RecoveryProvenance {
        &self.provenance
    }
    pub fn connection(&self) -> &Connection {
        &self.connection
    }
    pub fn into_connection(self) -> Connection {
        self.connection
    }
}

/// Source-preserving generation integrity evidence. The connection belongs to
/// a private encrypted READ_ONLY copy, including committed WAL frames. No live
/// connection, mutable journal conversion, or publication permission is exposed.
/// Owning crates must additionally check their typed conservative overlays.
pub struct RecoveredGenerationSnapshot {
    snapshot: crate::read_snapshot::ReadOnlySnapshot,
    generation: GenerationBinding,
    provenance: RecoveryProvenance,
}
impl RecoveredGenerationSnapshot {
    /// Recheck the retained original descriptors and path inventory under the
    /// caller's source quiescence. This never opens SQLite on the source and
    /// grants no runtime, native consent, or write permission.
    pub fn check_source_unchanged(&self) -> Result<()> {
        self.snapshot.check_retained_source_unchanged()?;
        Ok(())
    }
    pub fn generation(&self) -> &GenerationBinding {
        &self.generation
    }
    pub fn provenance(&self) -> &RecoveryProvenance {
        &self.provenance
    }
    /// Trusted owner readers only. SQLite cannot write the captured database;
    /// this borrowed connection cannot be consumed as a live journal handle.
    pub fn connection(&self) -> &Connection {
        &self.snapshot
    }
}

/// Read a generation at its original committed location without opening any
/// source file through SQLite. The caller must hold its complete directory
/// locks and exclude writers/checkpointers/replacement throughout capture.
pub fn open_recovered_generation_snapshot(
    path: &Path,
    key: &DatabaseKey,
    binding: &GenerationBinding,
    expected: &RecoveryProvenance,
    template: &'static JournalTemplate,
) -> Result<RecoveredGenerationSnapshot> {
    let destination = bound_path(path)?;
    open_generation_snapshot(path, destination, key, binding, expected, template)
}

/// Read relocated historical bytes using the exact original path recorded in
/// their authenticated archive. The native composition must authenticate the
/// complete origin-to-snapshot mapping before invoking this reader. The origin
/// is an inert marker value: it is never opened or required to still exist.
///
/// This integrity-only entry point cannot produce RecoveredGenerationConnection
/// or a runtime. The ordinary/runtime openers continue to require the actual
/// current path and never accept an archived-origin override.
pub fn open_archived_generation_snapshot(
    path: &Path,
    original_path: &Path,
    key: &DatabaseKey,
    binding: &GenerationBinding,
    expected: &RecoveryProvenance,
    template: &'static JournalTemplate,
) -> Result<RecoveredGenerationSnapshot> {
    let destination = archived_bound_path(original_path)?;
    open_generation_snapshot(path, destination, key, binding, expected, template)
}

fn open_generation_snapshot(
    path: &Path,
    destination: String,
    key: &DatabaseKey,
    binding: &GenerationBinding,
    expected: &RecoveryProvenance,
    template: &'static JournalTemplate,
) -> Result<RecoveredGenerationSnapshot> {
    if expected.kind != JournalKind::CoordinationAuthority
        || template.kind != JournalKind::CoordinationAuthority
        || template.application_id != RECOVERED_GENERATION_APPLICATION_ID
    {
        return Err(BundleError::Unsupported);
    }
    let expected_marker = marker_for_destination(
        binding,
        expected,
        template,
        destination,
        Purpose::CoordinationRuntime,
        None,
    )?;
    let schema = compiled_schema(template, true)?;
    let snapshot = crate::open_encrypted_read_only(path, key)?;
    snapshot.execute_batch("BEGIN DEFERRED;")?;
    verify_marker(&snapshot, &expected_marker, template, &schema)?;
    Ok(RecoveredGenerationSnapshot {
        snapshot,
        generation: binding.clone(),
        provenance: expected.clone(),
    })
}

/// Fixed-kind coordination reconstruction for the owning Store's typed wrapper.
/// The callback runs only on a separate staging destination after exact source
/// rows were authenticated and copied. It must install the executable-owned
/// recovery schema, retain original audit rows, and apply conservative fences.
/// This is not a generic quarantine opener and never mutates the source.
///
/// A completed retry is authenticated and left unchanged; the callback is not
/// replayed. The caller must also validate its semantic fences on every reopen.
pub fn initialize_coordination_generation(
    source: &VerifiedRecoveryComponent,
    source_template: &'static JournalTemplate,
    successor_template: &'static JournalTemplate,
    binding: &GenerationBinding,
    path: &Path,
    key: &DatabaseKey,
    initialize: impl FnOnce(&Connection) -> Result<()>,
) -> Result<()> {
    if source.provenance().kind != JournalKind::CoordinationAuthority
        || source_template.kind != JournalKind::CoordinationAuthority
        || successor_template.kind != JournalKind::CoordinationAuthority
        || successor_template.application_id != RECOVERED_GENERATION_APPLICATION_ID
    {
        return Err(BundleError::Unsupported);
    }
    let component = source_component(source, source_template)?;
    let base_schema = compiled_schema(source_template, false)?;
    let successor_schema = compiled_schema(successor_template, true)?;
    let marker = marker(
        binding,
        source.provenance(),
        successor_template,
        path,
        Purpose::CoordinationRuntime,
        None,
    )?;
    let Some(mut output) =
        prepare_output(path, key, &marker, successor_template, &successor_schema)?
    else {
        return Ok(());
    };
    let transaction = output.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_staging(&transaction)?;
    wallet::populate(&transaction, source, source_template, &base_schema)?;
    verify_restored_rows(&transaction, component)?;
    // Keep the dedicated identity even if an owner callback mistakenly ends the
    // transaction. The autocommit check below still refuses that result.
    transaction.pragma_update(None, "application_id", RECOVERED_GENERATION_APPLICATION_ID)?;
    initialize(&transaction)?;
    if transaction.is_autocommit() {
        return Err(BundleError::Integrity);
    }
    install_marker(&transaction, &marker, successor_template)?;
    verify_marker(&transaction, &marker, successor_template, &successor_schema)?;
    transaction.commit()?;
    crate::checkpoint_and_sync(&output, path)?;
    drop(output);
    let persisted = crate::open_encrypted_read_only(path, key)?;
    persisted.execute_batch("BEGIN DEFERRED;")?;
    verify_marker(&persisted, &marker, successor_template, &successor_schema)
}

/// Authenticate only an already committed coordination component. The caller
/// supplies expected metadata from its authenticated whole-generation plan.
/// This proof establishes component integrity, not host activation or consent.
/// The profile lock must exclude concurrent writers throughout open.
pub fn open_recovered_generation(
    path: &Path,
    key: &DatabaseKey,
    binding: &GenerationBinding,
    expected: &RecoveryProvenance,
    template: &'static JournalTemplate,
) -> Result<RecoveredGenerationConnection> {
    if expected.kind != JournalKind::CoordinationAuthority
        || template.kind != JournalKind::CoordinationAuthority
        || template.application_id != RECOVERED_GENERATION_APPLICATION_ID
    {
        return Err(BundleError::Unsupported);
    }
    let expected_marker = marker(
        binding,
        expected,
        template,
        path,
        Purpose::CoordinationRuntime,
        None,
    )?;
    let schema = compiled_schema(template, true)?;
    // Reject wrong keys, paths, schemas, quarantine and partial destinations on a
    // private encrypted read copy before any writable handle can reach the file.
    let read = crate::open_encrypted_read_only(path, key)?;
    read.execute_batch("BEGIN DEFERRED;")?;
    verify_marker(&read, &expected_marker, template, &schema)?;
    drop(read);
    let connection = crate::keyed_connection(path, key)?;
    verify_marker(&connection, &expected_marker, template, &schema)?;
    Ok(RecoveredGenerationConnection {
        connection,
        generation: binding.clone(),
        provenance: expected.clone(),
    })
}

pub(super) fn source_component<'a>(
    source: &'a VerifiedRecoveryComponent,
    template: &JournalTemplate,
) -> Result<&'a super::super::ComponentManifest> {
    let component = source
        .manifest()
        .components
        .iter()
        .find(|component| component.id == source.provenance().component_id)
        .ok_or(BundleError::Integrity)?;
    validate_component_template(component, template)?;
    Ok(component)
}

pub(super) fn compiled_schema(
    template: &JournalTemplate,
    with_marker: bool,
) -> Result<Vec<wallet::SchemaObject>> {
    if template.schema_version < 0 || template.create_sql.len() > 1024 * 1024 {
        return Err(BundleError::Unsupported);
    }
    let reference = Connection::open_in_memory()?;
    reference.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY;")?;
    reference.execute_batch(template.create_sql)?;
    if !reference.is_autocommit() {
        return Err(BundleError::Unsupported);
    }
    if with_marker {
        reference.execute_batch(MARKER_SCHEMA)?;
    }
    wallet::exact_schema(&reference)
}

pub(super) fn marker(
    binding: &GenerationBinding,
    provenance: &RecoveryProvenance,
    template: &JournalTemplate,
    path: &Path,
    purpose: Purpose,
    component: Option<super::super::ComponentManifest>,
) -> Result<Marker> {
    marker_for_destination(
        binding,
        provenance,
        template,
        bound_path(path)?,
        purpose,
        component,
    )
}

/// Only immutable archived readers use this expected-marker constructor.
pub(super) fn archived_marker(
    binding: &GenerationBinding,
    provenance: &RecoveryProvenance,
    template: &JournalTemplate,
    original_path: &Path,
    purpose: Purpose,
    component: Option<super::super::ComponentManifest>,
) -> Result<Marker> {
    marker_for_destination(
        binding,
        provenance,
        template,
        archived_bound_path(original_path)?,
        purpose,
        component,
    )
}

fn marker_for_destination(
    binding: &GenerationBinding,
    provenance: &RecoveryProvenance,
    template: &JournalTemplate,
    destination: String,
    purpose: Purpose,
    component: Option<super::super::ComponentManifest>,
) -> Result<Marker> {
    identifier(&provenance.profile_id)?;
    identifier(&provenance.checkpoint_id)?;
    identifier(&provenance.component_id)?;
    hash(&provenance.bundle_digest)?;
    hash(&provenance.component_digest)?;
    if provenance.kind != template.kind {
        return Err(BundleError::Unsupported);
    }
    let mut digest = Sha256::new();
    digest.update(b"wholepact:recovered-generation-schema:v1\0");
    digest.update(
        serde_json::to_vec(&compiled_schema(template, true)?).map_err(|_| BundleError::Invalid)?,
    );
    Ok(Marker {
        format: 1,
        generation_id: binding.generation_id.clone(),
        inventory_digest: binding.inventory_digest.clone(),
        destination,
        provenance: provenance.clone(),
        successor_schema_digest: hex_digest(digest),
        purpose,
        component,
    })
}

pub(super) fn prepare_output(
    path: &Path,
    key: &DatabaseKey,
    marker: &Marker,
    template: &JournalTemplate,
    schema: &[wallet::SchemaObject],
) -> Result<Option<Connection>> {
    let output = match crate::create_encrypted(path, key) {
        Ok(connection) => connection.into_connection(),
        Err(StorageSecurityError::AlreadyExists) => {
            let existing = crate::open_encrypted_read_only(path, key)?;
            if require_staging(&existing).is_err() {
                verify_marker(&existing, marker, template, schema)?;
                return Ok(None);
            }
            drop(existing);
            crate::keyed_connection(path, key)?
        }
        Err(error) => return Err(error.into()),
    };
    require_staging(&output)?;
    // This is committed separately before schema import. A crash, an owner
    // callback error, or marker erasure cannot expose an ordinary live journal.
    output.pragma_update(None, "application_id", RECOVERED_GENERATION_APPLICATION_ID)?;
    crate::checkpoint_and_sync(&output, path)?;
    Ok(Some(output))
}

pub(super) fn require_staging(connection: &Connection) -> Result<()> {
    let application = wallet::application_id(connection)?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let count: i64 =
        connection.query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))?;
    if (application == 0 || application == RECOVERED_GENERATION_APPLICATION_ID)
        && version == 0
        && count == 0
    {
        Ok(())
    } else {
        Err(BundleError::Integrity)
    }
}

pub(super) fn install_marker(
    connection: &Connection,
    marker: &Marker,
    template: &JournalTemplate,
) -> Result<()> {
    connection.execute_batch(MARKER_SCHEMA)?;
    let encoded = serde_json::to_vec(marker).map_err(|_| BundleError::Invalid)?;
    connection.execute(
        "INSERT INTO wholepact_recovered_generation VALUES(1,?1)",
        [encoded],
    )?;
    connection.pragma_update(None, "application_id", RECOVERED_GENERATION_APPLICATION_ID)?;
    connection.pragma_update(None, "user_version", template.schema_version)?;
    Ok(())
}

pub(super) fn read_marker(connection: &Connection) -> Result<Marker> {
    let count: i64 = connection.query_row(
        "SELECT count(*) FROM wholepact_recovered_generation",
        [],
        |row| row.get(0),
    )?;
    if count != 1 {
        return Err(BundleError::Integrity);
    }
    let bytes: Vec<u8> = connection.query_row(
        "SELECT binding FROM wholepact_recovered_generation WHERE singleton=1 AND length(binding)<=1048576", [],
        |row| row.get(0),
    )?;
    serde_json::from_slice(&bytes).map_err(|_| BundleError::Integrity)
}

pub(super) fn verify_marker(
    connection: &Connection,
    expected: &Marker,
    template: &JournalTemplate,
    schema: &[wallet::SchemaObject],
) -> Result<()> {
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if wallet::application_id(connection)? != RECOVERED_GENERATION_APPLICATION_ID
        || version != template.schema_version
        || wallet::exact_schema(connection)? != schema
        || read_marker(connection)? != *expected
    {
        return Err(BundleError::Integrity);
    }
    integrity(connection)
}

fn bound_path(path: &Path) -> Result<String> {
    let parent = path.parent().ok_or(BundleError::Invalid)?;
    if !path.is_absolute()
        || path.file_name().is_none()
        || std::fs::canonicalize(parent).map_err(|_| BundleError::Storage)? != parent
    {
        return Err(BundleError::Invalid);
    }
    archived_bound_path(path)
}

fn archived_bound_path(path: &Path) -> Result<String> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path.components().any(|component| {
            !matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(BundleError::Invalid);
    }
    let encoded = path.to_str().ok_or(BundleError::Invalid)?;
    if encoded.len() > 4096 {
        return Err(BundleError::Limit);
    }
    Ok(encoded.into())
}

fn hash(value: &str) -> Result<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(BundleError::Invalid)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
