use super::*;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Create a new encrypted archive only. Failures may leave an unusable staging
/// file; no existing output is adopted and a retry requires a new destination.
/// A native outer COMPLETE marker must follow independent verification and its
/// own digest-bound recovery envelope. This function never restores live files.
pub fn snapshot(request: SnapshotRequest<'_>) -> Result<ArchiveReport> {
    #[cfg(unix)]
    {
        unix::snapshot(request)
    }
    #[cfg(not(unix))]
    {
        let _ = request;
        Err(ArchiveError::Unsupported)
    }
}
#[cfg(unix)]
mod unix {
    use super::*;
    use crate::read_snapshot::capture::{CapturedFile, SourceSet};
    use std::os::unix::fs::FileExt;

    enum Captured<'a> {
        File(CapturedFile),
        Journal(SourceSet),
        Secret(&'a [u8]),
    }
    impl Captured<'_> {
        fn check(&self) -> Result<()> {
            match self {
                Self::File(file) => file.check_unchanged()?,
                Self::Journal(set) => set.check_unchanged()?,
                Self::Secret(_) => (),
            }
            Ok(())
        }
    }
    pub(super) fn snapshot(request: SnapshotRequest<'_>) -> Result<ArchiveReport> {
        let scope = request.scope()?;
        let lease = request.authority.acquire(&scope)?;
        lease.check_current()?;
        exclude_sources(request.destination, request.node, request.sources)?;
        let mut captured = Vec::new();
        for source in request.sources {
            lease.check_current()?;
            if let Some(path) = source.path() {
                format::origin(path)?;
            }
            captured.push(match source.source {
                Source::File(path) => Captured::File(CapturedFile::open(path)?),
                Source::Journal(path) => Captured::Journal(SourceSet::open(path)?),
                Source::Secret(bytes) => {
                    if bytes.len() > MAX_MANIFEST_BYTES {
                        return Err(ArchiveError::Limit);
                    }
                    Captured::Secret(bytes)
                }
            });
        }
        lease.check_current()?;
        let mut output =
            crate::create_encrypted(request.destination, request.key)?.into_connection();
        output.pragma_update(None, "application_id", STAGING_ID)?;
        output.pragma_update(None, "max_page_count", MAX_ARCHIVE_FILE_BYTES / 4096)?;
        let transaction = output.transaction()?;
        transaction.execute_batch(SCHEMA)?;
        let mut objects = BTreeMap::new();
        let mut manifests = BTreeMap::<String, SnapshotManifest>::new();
        let mut nodes = BTreeMap::<String, Node>::new();
        let mut metadata_bytes = 0usize;
        for parent in request.parents {
            lease.check_current()?;
            for (id, manifest) in &parent.manifests {
                if let Some(old) = manifests.get(id) {
                    if old != manifest {
                        return Err(ArchiveError::Integrity);
                    }
                } else {
                    put_record(
                        &transaction,
                        "archive_manifests",
                        id,
                        manifest,
                        &mut metadata_bytes,
                    )?;
                    manifests.insert(id.clone(), manifest.clone());
                }
            }
            for (id, node) in &parent.nodes {
                if let Some(old) = nodes.get(id) {
                    if old != node {
                        return Err(ArchiveError::Integrity);
                    }
                } else {
                    put_record(&transaction, "archive_nodes", id, node, &mut metadata_bytes)?;
                    nodes.insert(id.clone(), node.clone());
                }
            }
            if manifests.len() >= MAX_NODES || nodes.len() >= MAX_NODES {
                return Err(ArchiveError::Limit);
            }
            for (id, length) in &parent.objects {
                lease.check_current()?;
                if register_object(&transaction, &mut objects, id, *length)? {
                    parent.visit_object(id, |ordinal, bytes| {
                        transaction.execute(
                            "INSERT INTO archive_chunks VALUES(?1,?2,?3)",
                            params![id, ordinal, bytes],
                        )?;
                        Ok(())
                    })?;
                }
            }
        }
        let mut entries = BTreeMap::new();
        for (source, capture) in request.sources.iter().zip(&captured) {
            lease.check_current()?;
            capture.check()?;
            let payload = match capture {
                Captured::File(file) => EntryPayload::File {
                    object: put_file(&transaction, &mut objects, file.file(), file.length())?,
                },
                Captured::Secret(bytes) => EntryPayload::Secret {
                    object: put_bytes(&transaction, &mut objects, bytes)?,
                },
                Captured::Journal(set) => {
                    let mut files = BTreeMap::new();
                    for (suffix, file, length) in set.files() {
                        lease.check_current()?;
                        files.insert(
                            suffix.into(),
                            put_file(&transaction, &mut objects, file, length)?,
                        );
                    }
                    EntryPayload::Journal { files }
                }
            };
            capture.check()?;
            entries.insert(
                source.id.clone(),
                Entry {
                    role: source.role.clone(),
                    origin: source.path().map(format::origin).transpose()?,
                    payload,
                },
            );
        }
        let node = Node {
            generation_id: request.node.generation_id.clone(),
            profile_id: request.node.profile_id.clone(),
            original_root: format::origin(&request.node.original_root)?,
            entries,
        };
        let node_bytes = format::encode(&node)?;
        let node_digest = format::digest(format::NODE_DOMAIN, &node_bytes);
        if nodes.contains_key(&node_digest) {
            return Err(ArchiveError::Invalid);
        }
        put_record(
            &transaction,
            "archive_nodes",
            &node_digest,
            &node,
            &mut metadata_bytes,
        )?;
        let manifest = SnapshotManifest {
            format: FORMAT,
            capsule_id: request.capsule_id.into(),
            node_digest,
            parent_manifest_digests: scope.parent_manifest_digests,
        };
        let manifest_digest = format::digest(format::MANIFEST_DOMAIN, &format::encode(&manifest)?);
        put_record(
            &transaction,
            "archive_manifests",
            &manifest_digest,
            &manifest,
            &mut metadata_bytes,
        )?;
        transaction.execute("INSERT INTO archive_root VALUES(1,?1)", [&manifest_digest])?;
        transaction.pragma_update(None, "user_version", FORMAT)?;
        transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
        // The complete publication record and permanent identity become visible
        // atomically with every object. Verify before making this transaction durable.
        format::verify(&transaction)?;
        for capture in &captured {
            capture.check()?;
        }
        lease.check_current()?;
        transaction.commit()?;
        crate::checkpoint_and_sync(&output, request.destination)?;
        drop(output);
        lease.check_current()?;
        let independently_verified = inspect(request.destination, request.key)?;
        if independently_verified.manifest_digest() != manifest_digest {
            return Err(ArchiveError::Integrity);
        }
        for capture in &captured {
            capture.check()?;
        }
        lease.check_current()?;
        Ok(independently_verified.report())
    }
    fn exclude_sources(
        destination: &Path,
        node: &NodeSpec,
        sources: &[RegisteredSource<'_>],
    ) -> Result<()> {
        let parent = destination.parent().ok_or(ArchiveError::Invalid)?;
        let destination_parent =
            std::fs::canonicalize(parent).map_err(|_| ArchiveError::Storage)?;
        let root = std::fs::canonicalize(&node.original_root).map_err(|_| ArchiveError::Storage)?;
        if destination_parent.starts_with(root) {
            return Err(ArchiveError::Invalid);
        }
        let mut paths = BTreeSet::new();
        for source in sources {
            if let Some(path) = source.path() {
                let parent = std::fs::canonicalize(path.parent().ok_or(ArchiveError::Invalid)?)
                    .map_err(|_| ArchiveError::Storage)?;
                if destination_parent.starts_with(parent) {
                    return Err(ArchiveError::Invalid);
                }
                let path = format::origin(path)?;
                let suffixes: &[&str] = if source.kind() == SourceKind::Journal {
                    &["", "-wal", "-journal", "-shm"]
                } else {
                    &[""]
                };
                for suffix in suffixes {
                    if !paths.insert(format!("{path}{suffix}")) {
                        return Err(ArchiveError::Invalid);
                    }
                }
            }
        }
        Ok(())
    }
    fn put_file(
        connection: &Connection,
        objects: &mut BTreeMap<String, u64>,
        file: &std::fs::File,
        length: u64,
    ) -> Result<ObjectRef> {
        let mut hash = Sha256::new();
        hash.update(format::OBJECT_DOMAIN);
        let mut buffer = Zeroizing::new(vec![0; CHUNK_BYTES]);
        let mut offset = 0u64;
        while offset < length {
            let count = (length - offset).min(CHUNK_BYTES as u64) as usize;
            file.read_exact_at(&mut buffer[..count], offset)
                .map_err(|_| ArchiveError::Storage)?;
            hash.update(&buffer[..count]);
            offset += count as u64;
        }
        let id = format::finish(hash);
        if register_object(connection, objects, &id, length)? {
            let mut offset = 0u64;
            let mut ordinal = 0i64;
            while offset < length {
                let count = (length - offset).min(CHUNK_BYTES as u64) as usize;
                file.read_exact_at(&mut buffer[..count], offset)
                    .map_err(|_| ArchiveError::Storage)?;
                connection.execute(
                    "INSERT INTO archive_chunks VALUES(?1,?2,?3)",
                    params![id, ordinal, &buffer[..count]],
                )?;
                offset += count as u64;
                ordinal += 1;
            }
        }
        Ok(ObjectRef { digest: id, length })
    }
}
pub(super) fn put_record(
    connection: &Connection,
    table: &str,
    id: &str,
    value: &impl Serialize,
    total: &mut usize,
) -> Result<()> {
    let bytes = Zeroizing::new(format::encode(value)?);
    *total = total
        .checked_add(bytes.len())
        .filter(|total| *total <= MAX_MANIFEST_BYTES)
        .ok_or(ArchiveError::Limit)?;
    // Table identifiers are private fixed literals, never archive data.
    connection.execute(
        &format!("INSERT INTO {table} VALUES(?1,?2)"),
        params![id, bytes.as_slice()],
    )?;
    Ok(())
}
pub(super) fn register_object(
    connection: &Connection,
    objects: &mut BTreeMap<String, u64>,
    id: &str,
    length: u64,
) -> Result<bool> {
    if let Some(old) = objects.get(id) {
        if *old != length {
            return Err(ArchiveError::Integrity);
        }
        return Ok(false);
    }
    if objects.len() >= MAX_ENTRIES * 4
        || objects
            .values()
            .try_fold(length, |sum, next| sum.checked_add(*next))
            .is_none_or(|sum| sum > MAX_BYTES)
    {
        return Err(ArchiveError::Limit);
    }
    connection.execute(
        "INSERT INTO archive_objects VALUES(?1,?2)",
        params![id, length],
    )?;
    objects.insert(id.into(), length);
    Ok(true)
}
fn put_bytes(
    connection: &Connection,
    objects: &mut BTreeMap<String, u64>,
    bytes: &[u8],
) -> Result<ObjectRef> {
    let id = format::digest(format::OBJECT_DOMAIN, bytes);
    if register_object(connection, objects, &id, bytes.len() as u64)? {
        for (ordinal, chunk) in bytes.chunks(CHUNK_BYTES).enumerate() {
            connection.execute(
                "INSERT INTO archive_chunks VALUES(?1,?2,?3)",
                params![id, ordinal, chunk],
            )?;
        }
    }
    Ok(ObjectRef {
        digest: id,
        length: bytes.len() as u64,
    })
}
