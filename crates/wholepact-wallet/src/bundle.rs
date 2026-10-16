//! Dedicated viewing-wallet bundle adapter. Pinned maintained migrations generate
//! the trusted template from a new empty in-memory database, never imported SQL.
//! A separately authenticated snapshot handle must name the actual enrolled open
//! wallet file by device/inode AND retained private path; labels alone do not bind.
pub mod recovery;

use crate::wallet::DedicatedTestnetWallet;
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use rusqlite::Connection;
use std::{
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};
use wholepact_storage_security::{
    DatabaseKey, EncryptedConnection, EncryptedReadSnapshot,
    bundle::{BackupReadPermit, BundleError, JournalAdapter, JournalKind, JournalTemplate},
};
use zcash_client_backend::util::SystemClock;
use zcash_client_sqlite::WalletDb;
use zcash_protocol::consensus::TEST_NETWORK;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct WalletFileIdentity {
    path: PathBuf,
    device: u64,
    inode: u64,
}
impl WalletFileIdentity {
    pub(crate) fn capture(connection: &Connection) -> Result<Self, BundleError> {
        let path = PathBuf::from(connection.path().ok_or(BundleError::Invalid)?);
        if !path.is_absolute()
            || path
                .components()
                .any(|p| matches!(p, std::path::Component::ParentDir))
        {
            return Err(BundleError::Invalid);
        }
        let metadata = std::fs::symlink_metadata(&path).map_err(|_| BundleError::Storage)?;
        let parent = std::fs::symlink_metadata(path.parent().ok_or(BundleError::Invalid)?)
            .map_err(|_| BundleError::Storage)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
            || !parent.is_dir()
            || parent.file_type().is_symlink()
            || parent.mode() & 0o077 != 0
        {
            return Err(BundleError::Invalid);
        }
        Ok(Self {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    pub(crate) fn check(&self) -> Result<(), BundleError> {
        let metadata = std::fs::symlink_metadata(&self.path).map_err(|_| BundleError::Storage)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
        {
            return Err(BundleError::Permission);
        }
        let parent = std::fs::symlink_metadata(self.path.parent().ok_or(BundleError::Invalid)?)
            .map_err(|_| BundleError::Storage)?;
        if !parent.is_dir() || parent.file_type().is_symlink() || parent.mode() & 0o077 != 0 {
            return Err(BundleError::Permission);
        }
        Ok(())
    }
}

pub struct WalletScanBackupAdapter<'a> {
    wallet: &'a DedicatedTestnetWallet,
    source: Mutex<EncryptedConnection>,
    identity: WalletFileIdentity,
    template: &'static JournalTemplate,
}
impl<'a> WalletScanBackupAdapter<'a> {
    /// The host supplies a factory-authenticated handle to this same dedicated
    /// wallet, and must stop its writer and every independent connection under
    /// the whole-profile lease. This method imports no viewing key or account.
    pub fn new(
        wallet: &'a DedicatedTestnetWallet,
        source: EncryptedConnection,
    ) -> Result<Self, BundleError> {
        let identity = WalletFileIdentity::capture(source.connection())?;
        let enrolled = wallet
            .backup_identity
            .as_ref()
            .ok_or(BundleError::Permission)?;
        enrolled.check()?;
        if identity != *enrolled {
            return Err(BundleError::Permission);
        }
        let template = trusted_template_for_backup_source(&source)?;
        Ok(Self {
            wallet,
            source: Mutex::new(source),
            identity,
            template,
        })
    }
}
impl JournalAdapter for WalletScanBackupAdapter<'_> {
    fn template(&self) -> &'static JournalTemplate {
        self.template
    }
    fn read_locked(
        &self,
        permit: &BackupReadPermit<'_>,
        visitor: &mut dyn FnMut(&Connection) -> Result<(), BundleError>,
    ) -> Result<(), BundleError> {
        permit.check(self)?;
        let enrolled = self
            .wallet
            .backup_identity
            .as_ref()
            .ok_or(BundleError::Permission)?;
        if enrolled != &self.identity {
            return Err(BundleError::Permission);
        }
        enrolled.check()?;
        let source = self.source.lock().map_err(|_| BundleError::Storage)?;
        if WalletFileIdentity::capture(source.connection())? != self.identity {
            return Err(BundleError::Permission);
        }
        visitor(source.connection())?;
        enrolled.check()?;
        if WalletFileIdentity::capture(source.connection())? != self.identity {
            return Err(BundleError::Permission);
        }
        Ok(())
    }
}

pub fn trusted_template() -> Result<&'static JournalTemplate, BundleError> {
    static TEMPLATE: OnceLock<Option<&'static JournalTemplate>> = OnceLock::new();
    TEMPLATE
        .get_or_init(|| build_template().ok().map(|t| &*Box::leak(Box::new(t))))
        .as_ref()
        .copied()
        .ok_or(BundleError::Unsupported)
}
fn build_template() -> Result<JournalTemplate, BundleError> {
    let mut connection = Connection::open_in_memory().map_err(|_| BundleError::Storage)?;
    rusqlite::vtab::array::load_module(&connection).map_err(|_| BundleError::Unsupported)?;
    {
        let mut db = WalletDb::from_connection(
            &mut connection,
            TEST_NETWORK,
            SystemClock,
            UnwrapErr(SysRng),
        );
        zcash_client_sqlite::wallet::init::init_wallet_db(&mut db, None)
            .map_err(|_| BundleError::Unsupported)?;
    }
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(|_| BundleError::Unsupported)?;
    // This is freshly constructed TRUSTED maintained-library state. Never collect
    // executable schema from a live wallet or from a backup supplied by a caller.
    let mut stmt=connection.prepare("SELECT sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' AND sql IS NOT NULL ORDER BY CASE type WHEN 'table' THEN 0 WHEN 'index' THEN 1 WHEN 'view' THEN 2 ELSE 3 END,name").map_err(|_|BundleError::Unsupported)?;
    let mut rows = stmt.query([]).map_err(|_| BundleError::Unsupported)?;
    let mut sql = String::new();
    let mut count = 0usize;
    while let Some(row) = rows.next().map_err(|_| BundleError::Unsupported)? {
        let object: String = row.get(0).map_err(|_| BundleError::Unsupported)?;
        count += 1;
        if count > 256 || object.len() > 65536 || sql.len() + object.len() > 1024 * 1024 {
            return Err(BundleError::Limit);
        }
        sql.push_str(&object);
        sql.push_str(";\n");
    }
    if sql.is_empty() {
        return Err(BundleError::Unsupported);
    }
    Ok(JournalTemplate {
        kind: JournalKind::WalletScan,
        application_id: 0x57505754,
        schema_version: version,
        create_sql: Box::leak(sql.into_boxed_str()),
    })
}

/// The legacy maintained-library template plus the fixed append-only import
/// record layout. This does not change the legacy template, user_version, or
/// grant import/reopen/key-use authority. Historical row semantics are separate.
pub fn trusted_recorded_import_template() -> Result<&'static JournalTemplate, BundleError> {
    static TEMPLATE: OnceLock<Option<&'static JournalTemplate>> = OnceLock::new();
    TEMPLATE
        .get_or_init(|| {
            build_recorded_import_template()
                .ok()
                .map(|t| &*Box::leak(Box::new(t)))
        })
        .as_ref()
        .copied()
        .ok_or(BundleError::Unsupported)
}

fn build_recorded_import_template() -> Result<JournalTemplate, BundleError> {
    let maintained = trusted_template()?;
    // Both fragments are executable-owned. Never use source sqlite_schema SQL.
    let sql = format!(
        "{}\n{}",
        maintained.create_sql,
        crate::wallet::recorded_import::SCHEMA
    );
    if sql.len() > 1024 * 1024 {
        return Err(BundleError::Limit);
    }
    Ok(JournalTemplate {
        kind: maintained.kind,
        application_id: maintained.application_id,
        schema_version: maintained.schema_version,
        create_sql: Box::leak(sql.into_boxed_str()),
    })
}

/// Distinct V2 roster-import layout. The maintained and V1 templates remain
/// byte-identical; no existing wallet is migrated or silently upgraded.
pub fn trusted_recorded_roster_import_v2_template() -> Result<&'static JournalTemplate, BundleError>
{
    static TEMPLATE: OnceLock<Option<&'static JournalTemplate>> = OnceLock::new();
    TEMPLATE
        .get_or_init(|| {
            build_recorded_roster_import_v2_template()
                .ok()
                .map(|t| &*Box::leak(Box::new(t)))
        })
        .as_ref()
        .copied()
        .ok_or(BundleError::Unsupported)
}
fn build_recorded_roster_import_v2_template() -> Result<JournalTemplate, BundleError> {
    let maintained = trusted_template()?;
    let sql = format!(
        "{}\n{}",
        maintained.create_sql,
        crate::wallet::recorded_roster_import_v2::SCHEMA
    );
    if sql.len() > 1024 * 1024 {
        return Err(BundleError::Limit);
    }
    Ok(JournalTemplate {
        kind: maintained.kind,
        application_id: maintained.application_id,
        schema_version: maintained.schema_version,
        create_sql: Box::leak(sql.into_boxed_str()),
    })
}

pub(super) fn trusted_wallet_templates() -> Result<[&'static JournalTemplate; 3], BundleError> {
    Ok([
        trusted_template()?,
        trusted_recorded_import_template()?,
        trusted_recorded_roster_import_v2_template()?,
    ])
}

/// Select by the full schema of an authenticated current backup handle. The
/// adapter still requires exact enrolled file identity and the profile lease.
pub fn trusted_template_for_backup_source(
    source: &EncryptedConnection,
) -> Result<&'static JournalTemplate, BundleError> {
    wholepact_storage_security::bundle::recovery::wallet_templates::for_backup_source(
        source,
        trusted_wallet_templates()?,
    )
}

/// Select a restore target template from an authenticated bundle's complete
/// component schema and descriptors. The existing restore reader must revalidate
/// the bundle with this template. No version or kind hint selects the layout.
pub fn trusted_template_for_bundle_component(
    archive: &Path,
    key: &DatabaseKey,
    component_id: &str,
) -> Result<&'static JournalTemplate, BundleError> {
    wholepact_storage_security::bundle::recovery::wallet_templates::for_bundle_component(
        archive,
        key,
        component_id,
        trusted_wallet_templates()?,
    )
}

/// Open a raw frozen ordinary wallet as immutable encrypted history using one
/// private ciphertext capture. Complete layout and existing integrity checks run
/// on that same immutable snapshot; SQLite never opens the original source. The
/// caller must retain its complete source/quiescence lock throughout capture.
/// A validation failure never falls back to another layout or reader.
pub fn open_wallet_scan_read_snapshot(
    path: &Path,
    key: &DatabaseKey,
) -> Result<EncryptedReadSnapshot, BundleError> {
    let snapshot = wholepact_storage_security::open_encrypted_read_snapshot(path, key)?;
    wholepact_storage_security::bundle::recovery::wallet_templates::for_read_snapshot(
        &snapshot,
        trusted_wallet_templates()?,
    )?;
    Ok(snapshot)
}

#[cfg(test)]
mod template_tests;
