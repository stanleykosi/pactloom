use super::*;
use rusqlite::{Connection, OptionalExtension};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub(super) fn identifier(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.:".contains(&b))
    {
        return Err(ArchiveError::Invalid);
    }
    Ok(())
}
pub(super) fn hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ArchiveError::Invalid);
    }
    Ok(())
}
pub(super) fn origin(path: &Path) -> Result<String> {
    let value = path.to_str().ok_or(ArchiveError::Invalid)?;
    if value.len() > 4096
        || value.contains('\0')
        || !path.is_absolute()
        || path.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(ArchiveError::Invalid);
    }
    // Require normalized lexical spelling without touching historical paths.
    let normalized: PathBuf = path.components().collect();
    if normalized.as_os_str() != path.as_os_str() {
        return Err(ArchiveError::Invalid);
    }
    Ok(value.into())
}
pub(super) fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| ArchiveError::Invalid)
}
pub(super) fn digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(bytes);
    finish(h)
}
pub(super) fn finish(h: Sha256) -> String {
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}
pub(super) const MANIFEST_DOMAIN: &[u8] = b"wholepact:generation-capsule-manifest:v1\0";
pub(super) const NODE_DOMAIN: &[u8] = b"wholepact:generation-capsule-node:v1\0";
pub(super) const OBJECT_DOMAIN: &[u8] = b"wholepact:generation-capsule-object:v1\0";

type Inventory = (
    String,
    BTreeMap<String, SnapshotManifest>,
    BTreeMap<String, Node>,
    BTreeMap<String, u64>,
);
pub(super) fn verify(connection: &Connection) -> Result<Inventory> {
    let application: i64 = connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if application != APPLICATION_ID || version != i64::from(FORMAT) {
        return Err(ArchiveError::Unsupported);
    }
    let reference = Connection::open_in_memory()?;
    reference.execute_batch(SCHEMA)?;
    if schema(connection)? != schema(&reference)? {
        return Err(ArchiveError::Integrity);
    }
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    if integrity != "ok"
        || connection
            .query_row("SELECT 1 FROM pragma_foreign_key_check LIMIT 1", [], |r| {
                r.get::<_, i64>(0)
            })
            .optional()?
            .is_some()
    {
        return Err(ArchiveError::Integrity);
    }
    let roots: i64 = connection.query_row("SELECT count(*) FROM archive_root", [], |r| r.get(0))?;
    if roots != 1 {
        return Err(ArchiveError::Integrity);
    }
    let mut root_query = connection.prepare("SELECT digest FROM archive_root WHERE singleton=1")?;
    let mut root_rows = root_query.query([])?;
    let root = bounded_text(root_rows.next()?.ok_or(ArchiveError::Integrity)?, 0, 64)?;
    hash(&root)?;
    let mut metadata_bytes = 0usize;
    let manifests = read_records::<SnapshotManifest>(
        connection,
        "SELECT digest,payload FROM archive_manifests ORDER BY digest",
        MANIFEST_DOMAIN,
        &mut metadata_bytes,
    )?;
    let nodes = read_records::<Node>(
        connection,
        "SELECT digest,payload FROM archive_nodes ORDER BY digest",
        NODE_DOMAIN,
        &mut metadata_bytes,
    )?;
    let mut visited = BTreeSet::new();
    let mut active = BTreeSet::new();
    let mut capsule_ids = BTreeSet::new();
    let mut node_ids = BTreeSet::new();
    walk(
        &root,
        &manifests,
        &mut visited,
        &mut active,
        &mut capsule_ids,
        &mut node_ids,
    )?;
    if visited.len() != manifests.len()
        || node_ids.len() != nodes.len()
        || node_ids.iter().any(|id| !nodes.contains_key(id))
    {
        return Err(ArchiveError::Integrity);
    }
    let mut expected_objects = BTreeMap::new();
    let mut count = 0usize;
    for node in nodes.values() {
        hash(&node.generation_id)?;
        identifier(&node.profile_id)?;
        origin(Path::new(&node.original_root))?;
        count = count
            .checked_add(node.entries.len())
            .filter(|count| *count <= MAX_ENTRIES)
            .ok_or(ArchiveError::Limit)?;
        if node.entries.is_empty() {
            return Err(ArchiveError::Invalid);
        }
        let mut paths = BTreeSet::new();
        for (id, entry) in &node.entries {
            identifier(id)?;
            identifier(&entry.role)?;
            match &entry.payload {
                EntryPayload::Secret { object } => {
                    if entry.origin.is_some() || object.length > MAX_MANIFEST_BYTES as u64 {
                        return Err(ArchiveError::Invalid);
                    }
                    register(object, &mut expected_objects)?;
                }
                EntryPayload::File { object } => {
                    let path = entry.origin.as_deref().ok_or(ArchiveError::Invalid)?;
                    origin(Path::new(path))?;
                    if !paths.insert(path.to_owned()) {
                        return Err(ArchiveError::Invalid);
                    }
                    register(object, &mut expected_objects)?;
                }
                EntryPayload::Journal { files } => {
                    let path = entry.origin.as_deref().ok_or(ArchiveError::Invalid)?;
                    origin(Path::new(path))?;
                    if files.is_empty()
                        || files.len() > 4
                        || files.get("").is_none_or(|base| base.length < 4096)
                    {
                        return Err(ArchiveError::Invalid);
                    }
                    let mut bytes = 0u64;
                    for (suffix, object) in files {
                        if !["", "-wal", "-journal", "-shm"].contains(&suffix.as_str())
                            || !paths.insert(format!("{path}{suffix}"))
                        {
                            return Err(ArchiveError::Invalid);
                        }
                        bytes = bytes
                            .checked_add(object.length)
                            .filter(|bytes| *bytes <= MAX_BYTES)
                            .ok_or(ArchiveError::Limit)?;
                        register(object, &mut expected_objects)?;
                    }
                }
            }
        }
    }
    let mut objects = BTreeMap::new();
    let mut total = 0u64;
    let mut query =
        connection.prepare("SELECT digest,length FROM archive_objects ORDER BY digest")?;
    let mut rows = query.query([])?;
    while let Some(row) = rows.next()? {
        if objects.len() >= MAX_ENTRIES * 4 {
            return Err(ArchiveError::Limit);
        }
        let id = bounded_text(row, 0, 64)?;
        hash(&id)?;
        let length: u64 = row.get(1)?;
        total = total
            .checked_add(length)
            .filter(|total| *total <= MAX_BYTES)
            .ok_or(ArchiveError::Limit)?;
        verify_object(connection, &id, length)?;
        if objects.insert(id, length).is_some() {
            return Err(ArchiveError::Integrity);
        }
    }
    if objects != expected_objects {
        return Err(ArchiveError::Integrity);
    }
    Ok((root, manifests, nodes, objects))
}
type SchemaObject = (String, String, String, Option<String>);
fn schema(connection: &Connection) -> Result<Vec<SchemaObject>> {
    let mut query = connection
        .prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name")?;
    let mut rows = query.query([])?;
    let mut result = Vec::new();
    while let Some(row) = rows.next()? {
        if result.len() >= 32 {
            return Err(ArchiveError::Limit);
        }
        let sql = match row.get_ref(3)? {
            rusqlite::types::ValueRef::Null => None,
            _ => Some(bounded_text(row, 3, 65536)?),
        };
        result.push((
            bounded_text(row, 0, 16)?,
            bounded_text(row, 1, 128)?,
            bounded_text(row, 2, 128)?,
            sql,
        ));
    }
    Ok(result)
}
fn bounded_text(row: &rusqlite::Row<'_>, index: usize, max_bytes: usize) -> Result<String> {
    let bytes = row
        .get_ref(index)?
        .as_str()
        .map_err(|_| ArchiveError::Integrity)?;
    if bytes.len() > max_bytes {
        return Err(ArchiveError::Limit);
    }
    Ok(bytes.to_owned())
}
fn read_records<T: DeserializeOwned + Serialize>(
    connection: &Connection,
    sql: &str,
    domain: &[u8],
    total: &mut usize,
) -> Result<BTreeMap<String, T>> {
    let mut query = connection.prepare(sql)?;
    let mut rows = query.query([])?;
    let mut records = BTreeMap::new();
    while let Some(row) = rows.next()? {
        if records.len() >= MAX_NODES {
            return Err(ArchiveError::Limit);
        }
        let id = bounded_text(row, 0, 64)?;
        hash(&id)?;
        let bytes = row
            .get_ref(1)?
            .as_blob()
            .map_err(|_| ArchiveError::Integrity)?;
        *total = total
            .checked_add(bytes.len())
            .filter(|total| *total <= MAX_MANIFEST_BYTES)
            .ok_or(ArchiveError::Limit)?;
        if digest(domain, bytes) != id {
            return Err(ArchiveError::Integrity);
        }
        let value: T = serde_json::from_slice(bytes).map_err(|_| ArchiveError::Integrity)?;
        if encode(&value)?.as_slice() != bytes || records.insert(id, value).is_some() {
            return Err(ArchiveError::Integrity);
        }
    }
    Ok(records)
}
fn walk(
    id: &str,
    manifests: &BTreeMap<String, SnapshotManifest>,
    visited: &mut BTreeSet<String>,
    active: &mut BTreeSet<String>,
    capsule_ids: &mut BTreeSet<String>,
    node_ids: &mut BTreeSet<String>,
) -> Result<()> {
    if active.contains(id) {
        return Err(ArchiveError::Integrity);
    }
    if visited.contains(id) {
        return Ok(());
    }
    if visited.len() >= MAX_NODES || active.len() >= MAX_NODES {
        return Err(ArchiveError::Limit);
    }
    let manifest = manifests.get(id).ok_or(ArchiveError::Integrity)?;
    if manifest.format != FORMAT {
        return Err(ArchiveError::Unsupported);
    }
    hash(&manifest.capsule_id)?;
    hash(&manifest.node_digest)?;
    if !capsule_ids.insert(manifest.capsule_id.clone())
        || !node_ids.insert(manifest.node_digest.clone())
    {
        return Err(ArchiveError::Integrity);
    }
    if manifest.parent_manifest_digests.len() >= MAX_NODES
        || manifest
            .parent_manifest_digests
            .windows(2)
            .any(|w| w[0] >= w[1])
    {
        return Err(ArchiveError::Invalid);
    }
    active.insert(id.into());
    for parent in &manifest.parent_manifest_digests {
        hash(parent)?;
        walk(parent, manifests, visited, active, capsule_ids, node_ids)?;
    }
    active.remove(id);
    visited.insert(id.into());
    Ok(())
}
fn register(object: &ObjectRef, objects: &mut BTreeMap<String, u64>) -> Result<()> {
    hash(&object.digest)?;
    if object.length > MAX_BYTES {
        return Err(ArchiveError::Limit);
    }
    if objects
        .insert(object.digest.clone(), object.length)
        .is_some_and(|old| old != object.length)
    {
        return Err(ArchiveError::Integrity);
    }
    Ok(())
}
pub(super) fn verify_object(connection: &Connection, id: &str, length: u64) -> Result<()> {
    let mut hash = Sha256::new();
    hash.update(OBJECT_DOMAIN);
    let mut total = 0u64;
    let mut ordinal = 0usize;
    let mut statement = connection
        .prepare("SELECT ordinal,payload FROM archive_chunks WHERE digest=?1 ORDER BY ordinal")?;
    let mut rows = statement.query([id])?;
    while let Some(row) = rows.next()? {
        let actual: usize = row.get(0)?;
        let bytes = row
            .get_ref(1)?
            .as_blob()
            .map_err(|_| ArchiveError::Integrity)?;
        let wanted = usize::try_from((length - total).min(CHUNK_BYTES as u64))
            .map_err(|_| ArchiveError::Limit)?;
        if actual != ordinal || wanted == 0 || bytes.len() != wanted {
            return Err(ArchiveError::Integrity);
        }
        total += bytes.len() as u64;
        ordinal += 1;
        hash.update(bytes);
    }
    if total != length || finish(hash) != id {
        return Err(ArchiveError::Integrity);
    }
    Ok(())
}
