use super::*;
use rusqlite::params;

/// Re-encrypt exactly the verified capsule graph into a new inert capsule.
/// This does not add a generation node or recreate original live filenames.
/// No existing file is adopted. Native restore writes its independently keyed
/// quarantine envelope and RESTORED finalmarker only after this succeeds.
pub fn copy(request: CopyRequest<'_>) -> Result<ArchiveReport> {
    let scope = request.scope()?;
    let lease = request.authority.acquire(&scope)?;
    lease.check_current()?;
    let mut output = crate::create_encrypted(request.destination, request.key)?.into_connection();
    output.pragma_update(None, "application_id", STAGING_ID)?;
    output.pragma_update(None, "max_page_count", MAX_ARCHIVE_FILE_BYTES / 4096)?;
    let transaction = output.transaction()?;
    transaction.execute_batch(SCHEMA)?;
    let mut metadata_bytes = 0usize;
    for (id, manifest) in &request.source.manifests {
        lease.check_current()?;
        write::put_record(
            &transaction,
            "archive_manifests",
            id,
            manifest,
            &mut metadata_bytes,
        )?;
    }
    for (id, node) in &request.source.nodes {
        lease.check_current()?;
        write::put_record(&transaction, "archive_nodes", id, node, &mut metadata_bytes)?;
    }
    let mut objects = BTreeMap::new();
    for (id, length) in &request.source.objects {
        lease.check_current()?;
        write::register_object(&transaction, &mut objects, id, *length)?;
        request.source.visit_object(id, |ordinal, bytes| {
            lease.check_current()?;
            transaction.execute(
                "INSERT INTO archive_chunks VALUES(?1,?2,?3)",
                params![id, ordinal, bytes],
            )?;
            Ok(())
        })?;
    }
    transaction.execute(
        "INSERT INTO archive_root VALUES(1,?1)",
        [request.source.manifest_digest()],
    )?;
    transaction.pragma_update(None, "user_version", FORMAT)?;
    transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
    format::verify(&transaction)?;
    lease.check_current()?;
    transaction.commit()?;
    crate::checkpoint_and_sync(&output, request.destination)?;
    drop(output);
    lease.check_current()?;
    let verified = inspect(request.destination, request.key)?;
    if verified.report() != request.source.report() {
        return Err(ArchiveError::Integrity);
    }
    lease.check_current()?;
    Ok(verified.report())
}
