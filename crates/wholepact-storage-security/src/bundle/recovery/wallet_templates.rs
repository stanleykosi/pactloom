//! Read-only wallet layout selection. A selected compiled template is not
//! recovery evidence, import provenance, a live journal, or activation authority.
//! Owners supply their bounded executable-owned WalletScan templates. No
//! imported SQL is executed and no failed reader triggers a different decoder.

use super::super::{
    BundleError, ComponentManifest, JournalKind, JournalTemplate, identifier, integrity, schema,
    table_manifest, template_schema, validate_archive, validate_component_template,
};
use super::{VerifiedRecoveryComponent, generation, wallet};
use crate::{DatabaseKey, EncryptedConnection, EncryptedReadSnapshot};
use rusqlite::Connection;
use std::path::Path;

type Result<T> = std::result::Result<T, BundleError>;
type Templates<const N: usize = 2> = [&'static JournalTemplate; N];

fn check_templates<const N: usize>(templates: Templates<N>) -> Result<()> {
    if N == 0 || N > 8 {
        return Err(BundleError::Unsupported);
    }
    let mut schemas = Vec::with_capacity(N);
    for template in templates {
        if template.kind != JournalKind::WalletScan {
            return Err(BundleError::Unsupported);
        }
        // Also rejects reserved identities, invalid versions and marker tables.
        let current = template_schema(template)?;
        if schemas.contains(&current) {
            return Err(BundleError::Unsupported);
        }
        schemas.push(current);
    }
    Ok(())
}

fn exact_choice<T: PartialEq>(actual: &T, candidates: &[T]) -> Result<usize> {
    let mut chosen = None;
    for (index, candidate) in candidates.iter().enumerate() {
        if actual == candidate && chosen.replace(index).is_some() {
            return Err(BundleError::Unsupported);
        }
    }
    chosen.ok_or(BundleError::Unsupported)
}

fn choose_component<const N: usize>(
    component: &ComponentManifest,
    templates: Templates<N>,
) -> Result<&'static JournalTemplate> {
    check_templates(templates)?;
    let candidates = templates
        .iter()
        .map(|t| template_schema(t))
        .collect::<Result<Vec<_>>>()?;
    let index = exact_choice(&component.schema, &candidates)?;
    let selected = templates[index];
    // This checks kind/application/version AND every table name, ordered column
    // list and hidden-rowid rule. A correct schema with omitted descriptors fails.
    validate_component_template(component, selected)?;
    Ok(selected)
}

fn choose_ordinary<const N: usize>(
    connection: &Connection,
    templates: Templates<N>,
) -> Result<&'static JournalTemplate> {
    check_templates(templates)?;
    let actual = wallet::exact_schema(connection)?;
    let candidates = templates
        .iter()
        .map(|t| generation::compiled_schema(t, false))
        .collect::<Result<Vec<_>>>()?;
    let index = exact_choice(&actual, &candidates)?;
    let selected = templates[index];
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if wallet::application_id(connection)? != selected.application_id
        || version != selected.schema_version
    {
        return Err(BundleError::Unsupported);
    }
    // Inspect descriptors only after the entire executable-owned schema matches.
    let reference = Connection::open_in_memory()?;
    reference.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY;")?;
    reference.execute_batch(selected.create_sql)?;
    for object in schema(&reference)?
        .iter()
        .filter(|object| object.kind == "table")
    {
        let mut actual = table_manifest(connection, &object.name)?;
        // Layout comparison never compares live row counts to an empty template.
        // table_manifest currently returns zero here; retain the invariant if
        // its capture behavior changes in a future implementation.
        actual.rows = 0;
        if actual != table_manifest(&reference, &object.name)? {
            return Err(BundleError::Integrity);
        }
    }
    Ok(selected)
}

/// Classify the actual authenticated current backup source, not a caller's
/// version hint. The owning adapter still binds the source and validates its
/// rows under the held whole-profile lease. This does not open or migrate files.
pub fn for_backup_source<const N: usize>(
    source: &EncryptedConnection,
    templates: Templates<N>,
) -> Result<&'static JournalTemplate> {
    choose_ordinary(source.connection(), templates)
}

/// Validate a source-preserving ordinary snapshot's selected complete layout
/// and integrity on the same private immutable connection. The owner must retain
/// source quiescence; this never grants a live connection or key use.
pub fn for_read_snapshot<const N: usize>(
    source: &EncryptedReadSnapshot,
    templates: Templates<N>,
) -> Result<&'static JournalTemplate> {
    let connection = source.connection();
    if connection.is_autocommit() {
        connection.execute_batch("BEGIN DEFERRED;")?;
    }
    let selected = choose_ordinary(connection, templates)?;
    integrity(connection)?;
    source.check_source_unchanged()?;
    Ok(selected)
}

/// Authenticate the bundle before selecting a complete component descriptor.
/// The existing restore/recovery reader must subsequently revalidate the source
/// with the returned template. Selection itself cannot restore or activate it.
pub fn for_bundle_component<const N: usize>(
    archive: &Path,
    key: &DatabaseKey,
    component_id: &str,
    templates: Templates<N>,
) -> Result<&'static JournalTemplate> {
    identifier(component_id)?;
    let snapshot = crate::open_encrypted_read_snapshot(archive, key)?;
    let connection = snapshot.connection();
    connection.execute_batch("BEGIN DEFERRED;")?;
    let manifest = validate_archive(connection)?;
    let component = manifest
        .components
        .iter()
        .find(|component| component.id == component_id)
        .ok_or(BundleError::Invalid)?;
    let selected = choose_component(component, templates)?;
    snapshot.check_source_unchanged()?;
    Ok(selected)
}

/// Reclassify an already sealed historical component. The full manifest schema
/// and every descriptor are checked; its row contents are not decoded or repaired.
pub fn for_recovery_component<const N: usize>(
    source: &VerifiedRecoveryComponent,
    templates: Templates<N>,
) -> Result<&'static JournalTemplate> {
    let component = source
        .manifest()
        .components
        .iter()
        .find(|component| component.id == source.provenance().component_id)
        .ok_or(BundleError::Integrity)?;
    choose_component(component, templates)
}

/// Classify immutable evidence by its complete base-plus-marker schema before
/// reading any marker payload. The embedded component's entire schema and table
/// inventory must match the same selected candidate. Original/archived evidence
/// readers must then revalidate generation, original destination and all rows.
/// This function deliberately returns no evidence or mutable connection.
pub fn for_evidence_file<const N: usize>(
    path: &Path,
    key: &DatabaseKey,
    templates: Templates<N>,
) -> Result<&'static JournalTemplate> {
    check_templates(templates)?;
    // The public ordinary snapshot factory rejects generation identities. This
    // internal snapshot uses exactly its source-preserving ciphertext capture.
    let snapshot = crate::open_encrypted_read_only(path, key)?;
    snapshot.execute_batch("BEGIN DEFERRED;")?;
    if wallet::application_id(&snapshot)? != generation::RECOVERED_GENERATION_APPLICATION_ID {
        return Err(BundleError::Unsupported);
    }
    let actual = wallet::exact_schema(&snapshot)?;
    let candidates = templates
        .iter()
        .map(|t| generation::compiled_schema(t, true))
        .collect::<Result<Vec<_>>>()?;
    let selected = templates[exact_choice(&actual, &candidates)?];
    let version: i64 = snapshot.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version != selected.schema_version {
        return Err(BundleError::Unsupported);
    }
    let marker = generation::read_marker(&snapshot)?;
    let component = marker.component.as_ref().ok_or(BundleError::Integrity)?;
    // Never try another reader if this same-layout validation fails.
    validate_component_template(component, selected)?;
    snapshot.check_retained_source_unchanged()?;
    Ok(selected)
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
