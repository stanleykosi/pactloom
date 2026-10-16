//! Bounded, encrypted capsules of generation ciphertext and private key material.
//! Verification establishes exact structural inventory and immutable relocation,
//! never complete host coverage, consent, signer freshness, or runtime authority.
//! Native owners must validate their complete role/key/lineage matrix separately.
//! Distinct object payload is capped at 512 MiB, canonical metadata at 16 MiB,
//! and the encrypted SQLite file set at 640 MiB including format overhead.
//! Immutable capture/materialization adds private encrypted temporary I/O, is
//! not production-performance qualified, and may leave encrypted remnants on
//! crash/cleanup failure. Source locks must exclude writers and replacement;
//! descriptor stamps detect races but do not defeat hostile same-user renames.
use crate::{
    DatabaseKey,
    bundle::{
        JournalTemplate,
        recovery::{
            RecoveryProvenance, RecoveryTable,
            evidence::history::{
                HistoricalArchiveOrigin, HistoricalDisclosureIdentity, HistoricalSourceBinding,
            },
            generation::RecoveredGenerationSnapshot,
        },
    },
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroizing;

mod copy;
mod format;
mod readers;
#[cfg(all(test, target_os = "linux"))]
mod tests;
mod write;

pub const APPLICATION_ID: i64 = 0x57504741;
pub(crate) const STAGING_ID: i64 = 0x57504750;
const FORMAT: u32 = 1;
const MAX_NODES: usize = 16;
const MAX_ENTRIES: usize = 4096;
const MAX_BYTES: u64 = 512 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
const CHUNK_BYTES: usize = 1024 * 1024;
// SQLCipher pages, index pages and canonical metadata are additional to payload.
const MAX_ARCHIVE_FILE_BYTES: u64 = 640 * 1024 * 1024;
const SCHEMA: &str = "CREATE TABLE archive_root(singleton INTEGER PRIMARY KEY CHECK(singleton=1), digest TEXT NOT NULL); CREATE TABLE archive_manifests(digest TEXT PRIMARY KEY, payload BLOB NOT NULL); CREATE TABLE archive_nodes(digest TEXT PRIMARY KEY, payload BLOB NOT NULL); CREATE TABLE archive_objects(digest TEXT PRIMARY KEY, length INTEGER NOT NULL CHECK(length>=0)); CREATE TABLE archive_chunks(digest TEXT NOT NULL REFERENCES archive_objects(digest), ordinal INTEGER NOT NULL CHECK(ordinal>=0), payload BLOB NOT NULL, PRIMARY KEY(digest,ordinal));";

pub type Result<T> = std::result::Result<T, ArchiveError>;
#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    #[error("generation capsule scope or inventory is invalid")]
    Invalid,
    #[error("generation capsule exceeds its bounded resource profile")]
    Limit,
    #[error("generation capsule authentication or structural integrity failed")]
    Integrity,
    #[error("generation capsule permission or actual writer exclusion is unavailable")]
    Permission,
    #[error("generation capsule version or component is unsupported")]
    Unsupported,
    #[error("generation capsule source changed during its protected capture")]
    SourceChanged,
    #[error("generation capsule storage failed; partial encrypted output may exist")]
    Storage,
}
impl From<crate::StorageSecurityError> for ArchiveError {
    fn from(error: crate::StorageSecurityError) -> Self {
        match error {
            crate::StorageSecurityError::SnapshotLimit => Self::Limit,
            crate::StorageSecurityError::SourceChanged => Self::SourceChanged,
            crate::StorageSecurityError::AuthenticationFailed => Self::Integrity,
            crate::StorageSecurityError::UnsupportedPlatform => Self::Unsupported,
            _ => Self::Storage,
        }
    }
}
impl From<rusqlite::Error> for ArchiveError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Storage
    }
}
impl From<crate::bundle::BundleError> for ArchiveError {
    fn from(error: crate::bundle::BundleError) -> Self {
        match error {
            crate::bundle::BundleError::Limit => Self::Limit,
            crate::bundle::BundleError::Unsupported => Self::Unsupported,
            crate::bundle::BundleError::Permission
            | crate::bundle::BundleError::PermissionChanged => Self::Permission,
            _ => Self::Integrity,
        }
    }
}

/// This record is the canonical whole-snapshot commitment. Parents refer to
/// exact previous manifest digests, not node hashes. All parent records remain
/// unchanged in the flat graph; ancestor object bytes are deduplicated.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotManifest {
    pub format: u32,
    pub capsule_id: String,
    pub node_digest: String,
    pub parent_manifest_digests: Vec<String>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub generation_id: String,
    pub profile_id: String,
    pub original_root: String,
    pub entries: BTreeMap<String, Entry>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub role: String,
    pub origin: Option<String>,
    pub payload: EntryPayload,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EntryPayload {
    File {
        object: ObjectRef,
    },
    Secret {
        object: ObjectRef,
    },
    /// Exact byte snapshots. The committed logical SQLite state is verified by
    /// typed immutable readers; SHM is evidence only and is never installed.
    Journal {
        files: BTreeMap<String, ObjectRef>,
    },
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectRef {
    pub digest: String,
    pub length: u64,
}
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct NodeSpec {
    pub generation_id: String,
    pub profile_id: String,
    pub original_root: PathBuf,
}

pub enum Source<'a> {
    File(&'a Path),
    Journal(&'a Path),
    /// Caller retains a zeroizing owner for these bytes throughout the call.
    Secret(&'a [u8]),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    File,
    Journal,
    Secret,
}
#[derive(Clone)]
pub struct SourceBinding(Arc<()>);
impl PartialEq for SourceBinding {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for SourceBinding {}
impl std::fmt::Debug for SourceBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SourceBinding([opaque])")
    }
}
/// Exact, borrowed source registration. A binding is identity, not authority.
pub struct RegisteredSource<'a> {
    id: String,
    role: String,
    source: Source<'a>,
    binding: SourceBinding,
}
impl<'a> RegisteredSource<'a> {
    pub fn new(id: &str, role: &str, source: Source<'a>) -> Result<Self> {
        format::identifier(id)?;
        format::identifier(role)?;
        Ok(Self {
            id: id.into(),
            role: role.into(),
            source,
            binding: SourceBinding(Arc::new(())),
        })
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn role(&self) -> &str {
        &self.role
    }
    pub fn binding(&self) -> SourceBinding {
        self.binding.clone()
    }
    pub fn kind(&self) -> SourceKind {
        match self.source {
            Source::File(_) => SourceKind::File,
            Source::Journal(_) => SourceKind::Journal,
            Source::Secret(_) => SourceKind::Secret,
        }
    }
    pub fn path(&self) -> Option<&Path> {
        match self.source {
            Source::File(p) | Source::Journal(p) => Some(p),
            Source::Secret(_) => None,
        }
    }
}
/// Canonical pre-enrollment metadata. Serialization omits process-local binding
/// handles; equality additionally checks every exact borrowed registration.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ArchiveScope {
    pub destination: PathBuf,
    pub capsule_id: String,
    pub node: NodeSpec,
    pub sources: Vec<SourceScope>,
    pub parent_manifest_digests: Vec<String>,
    pub private_key_material_may_be_included: bool,
    pub new_key_commitment: String,
}
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct SourceScope {
    pub id: String,
    pub role: String,
    pub kind: SourceKind,
    pub path: Option<PathBuf>,
    #[serde(skip)]
    pub binding: SourceBinding,
}
impl ArchiveScope {
    pub fn for_snapshot(
        destination: &Path,
        key: &DatabaseKey,
        capsule_id: &str,
        node: &NodeSpec,
        sources: &[RegisteredSource<'_>],
        parents: &[&VerifiedArchive],
    ) -> Result<Self> {
        format::origin(destination)?;
        format::hash(capsule_id)?;
        format::origin(&node.original_root)?;
        format::hash(&node.generation_id)?;
        format::identifier(&node.profile_id)?;
        let mut parents: Vec<_> = parents
            .iter()
            .map(|p| p.manifest_digest().to_owned())
            .collect();
        parents.sort();
        if parents.len() >= MAX_NODES
            || parents.windows(2).any(|p| p[0] == p[1])
            || sources.is_empty()
            || sources.len() > MAX_ENTRIES
        {
            return Err(ArchiveError::Invalid);
        }
        let mut sources: Vec<_> = sources
            .iter()
            .map(|s| SourceScope {
                id: s.id.clone(),
                role: s.role.clone(),
                kind: s.kind(),
                path: s.path().map(Path::to_path_buf),
                binding: s.binding(),
            })
            .collect();
        sources.sort_by(|a, b| a.id.cmp(&b.id));
        if sources.windows(2).any(|s| s[0].id == s[1].id) {
            return Err(ArchiveError::Invalid);
        }
        Ok(Self {
            destination: destination.into(),
            capsule_id: capsule_id.into(),
            node: node.clone(),
            sources,
            parent_manifest_digests: parents,
            private_key_material_may_be_included: true,
            new_key_commitment: key_commitment(key),
        })
    }
}
pub trait ArchiveLease {
    /// Implementations retain actual writer/checkpointer/replacement exclusion,
    /// plus revocation synchronization; rechecks alone do not supply either.
    fn check_current(&self) -> Result<()>;
}
pub trait ArchiveAuthority {
    fn acquire<'a>(&'a self, scope: &ArchiveScope) -> Result<Box<dyn ArchiveLease + 'a>>;
}
pub struct SnapshotRequest<'a> {
    pub destination: &'a Path,
    pub key: &'a DatabaseKey,
    pub capsule_id: &'a str,
    pub node: &'a NodeSpec,
    pub sources: &'a [RegisteredSource<'a>],
    pub parents: &'a [&'a VerifiedArchive],
    pub authority: &'a dyn ArchiveAuthority,
}
impl SnapshotRequest<'_> {
    pub fn scope(&self) -> Result<ArchiveScope> {
        ArchiveScope::for_snapshot(
            self.destination,
            self.key,
            self.capsule_id,
            self.node,
            self.sources,
            self.parents,
        )
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct ArchiveReport {
    pub manifest_digest: String,
    pub capsule_id: String,
    pub nodes: usize,
    pub entries: usize,
    pub distinct_bytes: u64,
}

/// Non-deserializable integrity proof retaining an encrypted private READ_ONLY
/// snapshot. This does not establish native semantic completeness or approval.
pub struct VerifiedArchive {
    snapshot: crate::read_snapshot::ReadOnlySnapshot,
    binding: SourceBinding,
    root: String,
    manifests: BTreeMap<String, SnapshotManifest>,
    nodes: BTreeMap<String, Node>,
    objects: BTreeMap<String, u64>,
}
impl VerifiedArchive {
    /// Restriction-only recheck of the exact original source file inventory and
    /// descriptor identities retained by this verified read snapshot. No path,
    /// key, writable connection or new archive authority is returned.
    pub fn check_source_unchanged(&self, actual_path: &Path) -> Result<()> {
        self.snapshot
            .check_source_unchanged(actual_path)
            .map_err(ArchiveError::from)
    }
    pub fn binding(&self) -> SourceBinding {
        self.binding.clone()
    }
    pub fn manifest_digest(&self) -> &str {
        &self.root
    }
    pub fn manifest(&self) -> &SnapshotManifest {
        &self.manifests[&self.root]
    }
    pub fn manifests(&self) -> &BTreeMap<String, SnapshotManifest> {
        &self.manifests
    }
    pub fn manifest_by_digest(&self, digest: &str) -> Result<&SnapshotManifest> {
        self.manifests.get(digest).ok_or(ArchiveError::Invalid)
    }
    pub fn node(&self, manifest_digest: &str) -> Result<&Node> {
        self.nodes
            .get(&self.manifest_by_digest(manifest_digest)?.node_digest)
            .ok_or(ArchiveError::Integrity)
    }
    pub fn report(&self) -> ArchiveReport {
        ArchiveReport {
            manifest_digest: self.root.clone(),
            capsule_id: self.manifest().capsule_id.clone(),
            nodes: self.nodes.len(),
            entries: self.nodes.values().map(|n| n.entries.len()).sum(),
            distinct_bytes: self.objects.values().sum(),
        }
    }
    /// Explicit maximum checked against the authenticated length BEFORE allocation.
    /// Never logs or implements Debug for returned private material.
    pub fn read_private_entry(
        &self,
        manifest_digest: &str,
        id: &str,
        max_bytes: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let entry = self
            .node(manifest_digest)?
            .entries
            .get(id)
            .ok_or(ArchiveError::Invalid)?;
        let object = match &entry.payload {
            EntryPayload::File { object } | EntryPayload::Secret { object } => object,
            _ => return Err(ArchiveError::Invalid),
        };
        self.read_object(object, max_bytes)
    }
    pub fn journal(&self, manifest_digest: &str, id: &str) -> Result<ArchivedJournal<'_>> {
        let node = self.node(manifest_digest)?;
        let entry = node.entries.get(id).ok_or(ArchiveError::Invalid)?;
        if !matches!(entry.payload, EntryPayload::Journal { .. }) {
            return Err(ArchiveError::Invalid);
        }
        Ok(ArchivedJournal {
            archive: self,
            manifest_digest: manifest_digest.into(),
            id: id.into(),
        })
    }
}

/// The archive authenticates origin→ciphertext mapping. No path to a mutable
/// relocated database is exposed; all materialization is private and temporary.
pub struct ArchivedJournal<'a> {
    archive: &'a VerifiedArchive,
    manifest_digest: String,
    id: String,
}
/// Full current parent generation authenticated from its capsule, separately
/// retaining its original permanent marker provenance and generation binding.
pub struct ArchivedGenerationSource {
    historical_binding: HistoricalSourceBinding,
    archive_origin: HistoricalArchiveOrigin,
    snapshot: RecoveredGenerationSnapshot,
    provenance: RecoveryProvenance,
}
impl ArchivedGenerationSource {
    pub fn disclosure_identity(&self) -> HistoricalDisclosureIdentity<'_> {
        HistoricalDisclosureIdentity::from_generation(self)
    }
    pub fn historical_binding(&self) -> HistoricalSourceBinding {
        self.historical_binding.clone()
    }
    pub fn archive_origin(&self) -> &HistoricalArchiveOrigin {
        &self.archive_origin
    }
    pub fn snapshot(&self) -> &RecoveredGenerationSnapshot {
        &self.snapshot
    }
    pub fn source_provenance(&self) -> &RecoveryProvenance {
        &self.provenance
    }
}

/// Complete typed ordinary journal rows, sealed by archive ciphertext, key and
/// compiled schema verification. It is not a runtime or publication capability.
pub struct ArchivedOrdinarySource {
    historical_binding: HistoricalSourceBinding,
    archive_origin: HistoricalArchiveOrigin,
    provenance: RecoveryProvenance,
    tables: Vec<RecoveryTable>,
}
impl ArchivedOrdinarySource {
    pub fn disclosure_identity(&self) -> HistoricalDisclosureIdentity<'_> {
        HistoricalDisclosureIdentity::from_ordinary(self)
    }
    pub fn historical_binding(&self) -> HistoricalSourceBinding {
        self.historical_binding.clone()
    }
    pub fn archive_origin(&self) -> &HistoricalArchiveOrigin {
        &self.archive_origin
    }
    pub fn provenance(&self) -> &RecoveryProvenance {
        &self.provenance
    }
    pub fn tables(&self) -> &[RecoveryTable] {
        &self.tables
    }
}

/// Exact new-key and source-instance enrollment for inert copy/restore.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct CopyScope {
    pub destination: PathBuf,
    pub manifest_digest: String,
    pub new_key_commitment: String,
    #[serde(skip)]
    pub source_binding: SourceBinding,
}
impl CopyScope {
    pub fn for_copy(
        source: &VerifiedArchive,
        destination: &Path,
        key: &DatabaseKey,
    ) -> Result<Self> {
        format::origin(destination)?;
        Ok(Self {
            destination: destination.into(),
            manifest_digest: source.root.clone(),
            new_key_commitment: key_commitment(key),
            source_binding: source.binding(),
        })
    }
}
pub trait CopyAuthority {
    fn acquire<'a>(&'a self, scope: &CopyScope) -> Result<Box<dyn ArchiveLease + 'a>>;
}
pub struct CopyRequest<'a> {
    pub source: &'a VerifiedArchive,
    pub destination: &'a Path,
    pub key: &'a DatabaseKey,
    pub authority: &'a dyn CopyAuthority,
}
impl CopyRequest<'_> {
    pub fn scope(&self) -> Result<CopyScope> {
        CopyScope::for_copy(self.source, self.destination, self.key)
    }
}
fn key_commitment(key: &DatabaseKey) -> String {
    format::digest(
        b"wholepact:generation-capsule-random-key-intent:v1\0",
        &key.0,
    )
}
pub use copy::copy;
pub use write::snapshot;
/// Independently verify exact schema, bounded graph/object coverage and hashes.
/// Caller excludes source writers/replacement. No original SQLite file is opened.
pub fn inspect(path: &Path, key: &DatabaseKey) -> Result<VerifiedArchive> {
    let snapshot =
        crate::read_snapshot::ReadOnlySnapshot::open_bounded(path, key, MAX_ARCHIVE_FILE_BYTES)?;
    snapshot.execute_batch("BEGIN DEFERRED;")?;
    let (root, manifests, nodes, objects) = format::verify(&snapshot)?;
    Ok(VerifiedArchive {
        snapshot,
        binding: SourceBinding(Arc::new(())),
        root,
        manifests,
        nodes,
        objects,
    })
}
