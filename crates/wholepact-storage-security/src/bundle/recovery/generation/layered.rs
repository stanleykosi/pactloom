//! Typed recursive coordination reconstruction. Only an authenticated archive
//! source can enter this boundary; no ordinary or quarantined Store is opened.
use super::super::super::{quote, table_manifest, MAX_CELL, MAX_COMPONENT_BYTES, MAX_ROWS};
use super::*;
use crate::generation_archive::ArchivedGenerationSource;
use rusqlite::{
    params_from_iter,
    types::{ToSqlOutput, ValueRef},
};

/// Copy a sealed archived generation to a separately encrypted destination.
/// Every parent owner table, rowid, sequence and recovery overlay is retained.
/// Only the storage-owned marker is replaced in the NEW destination. The source
/// marker remains unchanged in its authenticated archive. The owner callback
/// must install an additive conservative schema and never grant authority.
///
/// This establishes storage integrity only. Native publication and current
/// authorization are separate. Exact completed retries are read-only verified.
pub fn initialize_coordination_generation_from_archive(
    source: &ArchivedGenerationSource,
    parent_template: &'static JournalTemplate,
    successor_template: &'static JournalTemplate,
    binding: &GenerationBinding,
    path: &Path,
    key: &DatabaseKey,
    initialize: impl FnOnce(&Connection) -> Result<()>,
) -> Result<()> {
    let parent = source.snapshot();
    if source.source_provenance().kind != JournalKind::CoordinationAuthority
        || parent_template.kind != JournalKind::CoordinationAuthority
        || successor_template.kind != JournalKind::CoordinationAuthority
        || parent_template.application_id != RECOVERED_GENERATION_APPLICATION_ID
        || successor_template.application_id != RECOVERED_GENERATION_APPLICATION_ID
        || parent.generation().generation_id() == binding.generation_id()
        || source.source_provenance().application_id != RECOVERED_GENERATION_APPLICATION_ID
        || source.source_provenance().schema_version != parent_template.schema_version
    {
        return Err(BundleError::Unsupported);
    }
    let parent_schema = compiled_schema(parent_template, true)?;
    let owner_schema = compiled_schema(parent_template, false)?;
    let parent_marker = read_marker(parent.connection())?;
    if parent_marker.generation_id != parent.generation().generation_id()
        || parent_marker.inventory_digest != parent.generation().inventory_digest()
        || parent_marker.provenance != *parent.provenance()
        || parent_marker.purpose != Purpose::CoordinationRuntime
    {
        return Err(BundleError::Integrity);
    }
    verify_marker(
        parent.connection(),
        &parent_marker,
        parent_template,
        &parent_schema,
    )?;
    let successor_schema = compiled_schema(successor_template, true)?;
    let marker = marker(
        binding,
        source.source_provenance(),
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
    let tx = output.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_staging(&tx)?;
    copy_owner_rows(parent.connection(), &tx, parent_template, &owner_schema)?;
    // The permanent generation identity survives even an erroneous callback
    // transaction boundary; such a callback is still rejected below.
    tx.pragma_update(None, "application_id", RECOVERED_GENERATION_APPLICATION_ID)?;
    initialize(&tx)?;
    if tx.is_autocommit() {
        return Err(BundleError::Integrity);
    }
    install_marker(&tx, &marker, successor_template)?;
    verify_marker(&tx, &marker, successor_template, &successor_schema)?;
    tx.commit()?;
    crate::checkpoint_and_sync(&output, path)?;
    drop(output);
    let persisted = crate::open_encrypted_read_only(path, key)?;
    persisted.execute_batch("BEGIN DEFERRED;")?;
    verify_marker(&persisted, &marker, successor_template, &successor_schema)
}

fn copy_owner_rows(
    source: &Connection,
    output: &Connection,
    template: &JournalTemplate,
    schema: &[wallet::SchemaObject],
) -> Result<()> {
    output.execute_batch("PRAGMA defer_foreign_keys=ON;")?;
    output.execute_batch(template.create_sql)?;
    if output.is_autocommit() || wallet::exact_schema(output)? != schema {
        return Err(BundleError::Integrity);
    }
    // These are executable-owned objects, never SQL supplied by an archive.
    for object in schema.iter().filter(|object| object.0 == "trigger") {
        output.execute_batch(&format!("DROP TRIGGER {}", quote(&object.1)?))?;
    }
    let tables: Vec<_> = schema.iter().filter(|object| object.0 == "table").collect();
    for table in tables.iter().rev() {
        output.execute(&format!("DELETE FROM {}", quote(&table.1)?), [])?;
    }
    let mut rows = 0usize;
    let mut bytes = 0usize;
    for object in tables
        .iter()
        .filter(|object| object.1 != "sqlite_sequence")
        .chain(tables.iter().filter(|object| object.1 == "sqlite_sequence"))
    {
        let table = table_manifest(source, &object.1)?;
        if table.name == "wholepact_recovered_generation" {
            return Err(BundleError::Integrity);
        }
        if table.name == "sqlite_sequence" {
            output.execute("DELETE FROM sqlite_sequence", [])?;
        }
        let columns = table
            .columns
            .iter()
            .map(|column| quote(column))
            .collect::<Result<Vec<_>>>()?
            .join(",");
        let projection = format!("{}{}", if table.rowid { "rowid," } else { "" }, columns);
        let ordering = if table.rowid { "rowid" } else { &columns };
        let select = format!(
            "SELECT {projection} FROM {} ORDER BY {ordering}",
            quote(&table.name)?
        );
        let count = table.columns.len() + usize::from(table.rowid);
        let insert = format!(
            "INSERT INTO {} ({projection}) VALUES ({})",
            quote(&table.name)?,
            vec!["?"; count].join(",")
        );
        let mut query = source.prepare(&select)?;
        let mut query_rows = query.query([])?;
        let mut insert = output.prepare(&insert)?;
        while let Some(row) = query_rows.next()? {
            rows = rows.checked_add(1).ok_or(BundleError::Limit)?;
            if rows > MAX_ROWS {
                return Err(BundleError::Limit);
            }
            let mut values = Vec::with_capacity(count);
            for index in 0..count {
                let value = row.get_ref(index)?;
                let size = match value {
                    ValueRef::Null => 1,
                    ValueRef::Integer(_) => 8,
                    ValueRef::Real(value) if value.is_finite() => 8,
                    ValueRef::Real(_) => return Err(BundleError::Unsupported),
                    ValueRef::Text(value) | ValueRef::Blob(value) => value.len(),
                };
                if size > MAX_CELL {
                    return Err(BundleError::Limit);
                }
                bytes = bytes.checked_add(size).ok_or(BundleError::Limit)?;
                if bytes > MAX_COMPONENT_BYTES {
                    return Err(BundleError::Limit);
                }
                values.push(ToSqlOutput::Borrowed(value));
            }
            insert.execute(params_from_iter(values))?;
        }
        // Confirm all copied cells and hidden rowids before owner overlays.
        let mut left = source.prepare(&select)?;
        let mut right = output.prepare(&select)?;
        let mut left_rows = left.query([])?;
        let mut right_rows = right.query([])?;
        loop {
            match (left_rows.next()?, right_rows.next()?) {
                (None, None) => break,
                (Some(left), Some(right)) => {
                    for index in 0..count {
                        let equal = match (left.get_ref(index)?, right.get_ref(index)?) {
                            (ValueRef::Real(a), ValueRef::Real(b)) => a.to_bits() == b.to_bits(),
                            (a, b) => a == b,
                        };
                        if !equal {
                            return Err(BundleError::Integrity);
                        }
                    }
                }
                _ => return Err(BundleError::Integrity),
            }
        }
    }
    for object in schema.iter().filter(|object| object.0 == "trigger") {
        output.execute_batch(object.3.as_deref().ok_or(BundleError::Unsupported)?)?;
    }
    if wallet::exact_schema(output)? != schema {
        return Err(BundleError::Integrity);
    }
    integrity(output)
}

/// Deterministic checksum of complete coordination OWNER rows, excluding only
/// the storage marker. This returns no source capability, permission or runtime
/// handle. It supports owner validation of a reconstructed in-memory historical
/// layer as well as the sealed archive opener. Caller-selected checksums cannot
/// substitute for ArchivedGenerationSource authentication.
pub fn coordination_owner_rows_commitment(
    connection: &Connection,
    template: &JournalTemplate,
) -> Result<(String, usize)> {
    use super::super::super::{Cell, Row};
    if template.kind != JournalKind::CoordinationAuthority
        || template.application_id != RECOVERED_GENERATION_APPLICATION_ID
    {
        return Err(BundleError::Unsupported);
    }
    let owner = compiled_schema(template, false)?;
    let actual = wallet::exact_schema(connection)?;
    if actual != owner && actual != compiled_schema(template, true)? {
        return Err(BundleError::Integrity);
    }
    let mut hash = Sha256::new();
    hash.update(b"wholepact:archived-generation-owner:v1\0");
    hash.update(serde_json::to_vec(&owner).map_err(|_| BundleError::Invalid)?);
    let mut total_rows = 0usize;
    let mut total_bytes = 0usize;
    for object in owner.iter().filter(|object| object.0 == "table") {
        let mut table = table_manifest(connection, &object.1)?;
        let columns = table
            .columns
            .iter()
            .map(|column| quote(column))
            .collect::<Result<Vec<_>>>()?
            .join(",");
        let sql = format!(
            "SELECT {}{} FROM {}",
            if table.rowid { "rowid," } else { "" },
            columns,
            quote(&table.name)?
        );
        let mut statement = connection.prepare(&sql)?;
        let mut query = statement.query([])?;
        let mut encoded_rows = Vec::new();
        while let Some(row) = query.next()? {
            let offset = usize::from(table.rowid);
            let mut cells = Vec::with_capacity(table.columns.len());
            for index in 0..table.columns.len() {
                cells.push(match row.get_ref(index + offset)? {
                    ValueRef::Null => Cell::Null,
                    ValueRef::Integer(value) => Cell::Integer(value),
                    ValueRef::Real(value) if value.is_finite() => Cell::Real(value.to_bits()),
                    ValueRef::Real(_) => return Err(BundleError::Unsupported),
                    ValueRef::Text(value) => {
                        if value.len() > MAX_CELL {
                            return Err(BundleError::Limit);
                        }
                        Cell::Text(
                            std::str::from_utf8(value)
                                .map_err(|_| BundleError::Integrity)?
                                .to_owned(),
                        )
                    }
                    ValueRef::Blob(value) => {
                        if value.len() > MAX_CELL {
                            return Err(BundleError::Limit);
                        }
                        Cell::Blob(value.to_vec())
                    }
                });
            }
            let bytes = zeroize::Zeroizing::new(
                serde_json::to_vec(&Row {
                    rowid: if table.rowid { Some(row.get(0)?) } else { None },
                    cells,
                })
                .map_err(|_| BundleError::Invalid)?,
            );
            total_rows = total_rows.checked_add(1).ok_or(BundleError::Limit)?;
            total_bytes = total_bytes
                .checked_add(bytes.len())
                .ok_or(BundleError::Limit)?;
            if total_rows > MAX_ROWS || total_bytes > MAX_COMPONENT_BYTES {
                return Err(BundleError::Limit);
            }
            encoded_rows.push(bytes);
        }
        encoded_rows.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
        table.rows = encoded_rows.len();
        hash.update(serde_json::to_vec(&table).map_err(|_| BundleError::Invalid)?);
        for bytes in encoded_rows {
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(&*bytes);
        }
    }
    Ok((hex_digest(hash), total_rows))
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
