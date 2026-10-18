//! Typed coordination/authority adapter for a complete profile bundle. This is
//! separate from the legacy single-Store archive API; no scoped-reader export.
use crate::{StorageProtection, Store};
use wholepact_storage_security::bundle::{
    BackupReadPermit, BundleError, JournalAdapter, JournalKind, JournalTemplate,
};

static LEGACY_TEMPLATE_V2: JournalTemplate = JournalTemplate {
    kind: JournalKind::CoordinationAuthority,
    application_id: 0,
    schema_version: 2,
    create_sql: concat!(
        include_str!("schema.sql"),
        "\n",
        include_str!("migration-v2.sql")
    ),
};

static LEGACY_TEMPLATE_V1: JournalTemplate = JournalTemplate {
    kind: JournalKind::CoordinationAuthority,
    application_id: 0,
    schema_version: 1,
    create_sql: include_str!("schema.sql"),
};
static LEGACY_TEMPLATE_V3: JournalTemplate = JournalTemplate {
    kind: JournalKind::CoordinationAuthority,
    application_id: 0,
    schema_version: 3,
    create_sql: concat!(
        include_str!("schema.sql"),
        "\n",
        include_str!("migration-v2.sql")
    ),
};

static LEGACY_TEMPLATE_V4: JournalTemplate = JournalTemplate {
    kind: JournalKind::CoordinationAuthority,
    application_id: 0,
    schema_version: 4,
    create_sql: concat!(
        include_str!("schema.sql"),
        "\n",
        include_str!("migration-v2.sql")
    ),
};

static TEMPLATE: JournalTemplate = JournalTemplate {
    kind: JournalKind::CoordinationAuthority,
    application_id: 0,
    schema_version: crate::SCHEMA_VERSION,
    create_sql: concat!(
        include_str!("schema.sql"),
        "\n",
        include_str!("migration-v2.sql")
    ),
};

/// Exact historical encoding template; never reinterpret a legacy component as
/// current merely because its physical SQL layout happens to be identical.
pub fn coordination_template_for_schema(
    version: i64,
) -> Result<&'static JournalTemplate, BundleError> {
    match version {
        1 => Ok(&LEGACY_TEMPLATE_V1),
        2 => Ok(&LEGACY_TEMPLATE_V2),
        3 => Ok(&LEGACY_TEMPLATE_V3),
        4 => Ok(&LEGACY_TEMPLATE_V4),
        5 => Ok(&TEMPLATE),
        _ => Err(BundleError::Unsupported),
    }
}

/// Executable-owned current schema for typed restore/history composition.
/// This template is never populated from configuration or archive SQL.
pub fn coordination_template() -> &'static JournalTemplate {
    &TEMPLATE
}

pub struct CoordinationBundleAdapter<'a> {
    store: &'a Store,
}

// Same-thread test observation only, never a production callback or policy
// control. It distinguishes refusal before the visitor from later failure.
#[cfg(test)]
std::thread_local! {
    static BUNDLE_VISITOR_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_bundle_visitor_calls() {
    BUNDLE_VISITOR_CALLS.with(|calls| calls.set(0));
}

#[cfg(test)]
pub(crate) fn bundle_visitor_calls() -> usize {
    BUNDLE_VISITOR_CALLS.with(std::cell::Cell::get)
}

impl<'a> CoordinationBundleAdapter<'a> {
    pub fn new(store: &'a Store) -> Result<Self, BundleError> {
        if store.protection != StorageProtection::Encrypted {
            return Err(BundleError::Invalid);
        }
        // Preflight before a caller can hand this adapter to bundle staging;
        // read_locked repeats the check on the actual export snapshot.
        {
            let connection = store.connection.lock().map_err(|_| BundleError::Storage)?;
            crate::backup::validate_no_private_input_projections(&connection)
                .map_err(|_| BundleError::Integrity)?;
        }
        Ok(Self { store })
    }
}

impl JournalAdapter for CoordinationBundleAdapter<'_> {
    fn template(&self) -> &'static JournalTemplate {
        &TEMPLATE
    }
    fn read_locked(
        &self,
        permit: &BackupReadPermit<'_>,
        visitor: &mut dyn FnMut(&rusqlite::Connection) -> Result<(), BundleError>,
    ) -> Result<(), BundleError> {
        permit.check(self)?;
        let connection = self
            .store
            .connection
            .lock()
            .map_err(|_| BundleError::Storage)?;
        // Complete bundles retain their broader construction scope, but do not
        // qualify disclosure of private input projections or any private-workspace
        // marker in any saved revision, including an otherwise empty seed.
        crate::backup::validate_no_private_input_projections(&connection)
            .map_err(|_| BundleError::Integrity)?;
        crate::backup::validate_live_schema_and_rows(&connection, crate::SCHEMA_VERSION)
            .map_err(|_| BundleError::Integrity)?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
        let application: i64 =
            connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
        if version != crate::SCHEMA_VERSION || application != 0 {
            return Err(BundleError::Unsupported);
        }
        #[cfg(test)]
        BUNDLE_VISITOR_CALLS.with(|calls| calls.set(calls.get() + 1));
        visitor(&connection)
    }
}

/// Immutable coordination evidence, separate from the successor runtime.
pub fn reconstruct_coordination_successor_evidence(
    source: &wholepact_storage_security::bundle::recovery::VerifiedRecoveryComponent,
    path: impl AsRef<std::path::Path>,
    key: &wholepact_storage_security::DatabaseKey,
    binding: &wholepact_storage_security::bundle::recovery::generation::GenerationBinding,
) -> Result<(), BundleError> {
    crate::recovery::StoreRecoveryInventory::inspect(source).map_err(|_| BundleError::Integrity)?;
    let template = coordination_template_for_schema(source.provenance().schema_version)?;
    wholepact_storage_security::bundle::recovery::evidence::reconstruct_coordination_evidence(
        source, template, path, key, binding,
    )
}
pub fn open_coordination_successor_evidence(
    path: impl AsRef<std::path::Path>,
    key: &wholepact_storage_security::DatabaseKey,
    binding: &wholepact_storage_security::bundle::recovery::generation::GenerationBinding,
    expected: &wholepact_storage_security::bundle::recovery::RecoveryProvenance,
) -> Result<wholepact_storage_security::bundle::recovery::evidence::RecoveredEvidence, BundleError>
{
    let template = coordination_template_for_schema(expected.schema_version)?;
    let evidence =
        wholepact_storage_security::bundle::recovery::evidence::open_coordination_evidence(
            path, key, binding, expected, template,
        )?;
    crate::recovery::StoreRecoveryInventory::inspect_successor(&evidence)
        .map_err(|_| BundleError::Integrity)?;
    Ok(evidence)
}
