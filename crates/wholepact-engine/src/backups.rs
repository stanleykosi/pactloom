//! Trusted local administration for a full coordination/authority journal backup.
//! Never attach these key/path-bearing requests to ordinary HTTP or scoped-read
//! routes. A held embedding-owned consent lease is required; there is no default
//! allow implementation and no grant from Access::all_agreements.
use crate::{Access, ApiError, Engine, Result};
use serde::Serialize;
use std::{
    path::{Component, Path},
    sync::Arc,
};
use wholepact_store::{
    backup::{AgreementBackupSummary, AgreementRestoreReport, DatabaseKey},
    StorageProtection, Store, StoreError,
};

pub const INCLUDED_JOURNALS: &[&str] = &[
    "complete_coordination_metadata",
    "complete_local_authority_journal",
];
pub const EXCLUDED_JOURNALS: &[&str] = &[
    "wallet_secrets_and_signer_vault",
    "wallet_scan_state",
    "private_witness_and_proof_jobs",
    "signed_results",
    "exact_transactions",
    "submission_journal",
    "transport_inbox_and_outbox",
];
/// This bridge schedules no cleanup and therefore accepts no timed-deletion promise.
pub const LOCAL_RETENTION_UNTIL_REMOVAL: &str = "local-only; retain until deliberately removed";

/// Runtime-issued identity, not an authority grant. A clone retains the same
/// actual store binding. Reopening the same file creates a new identity requiring
/// new runtime enrollment; labels alone cannot substitute for this handle.
#[derive(Clone)]
pub struct LocalBackupSource {
    store: Arc<Store>,
    local_profile_id: String,
    source_id: String,
}
impl LocalBackupSource {
    pub fn local_profile_id(&self) -> &str {
        &self.local_profile_id
    }
    pub fn source_id(&self) -> &str {
        &self.source_id
    }
    pub fn matches_binding(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.store, &other.store)
            && self.local_profile_id == other.local_profile_id
            && self.source_id == other.source_id
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FullJournalBackupAction {
    CreateArchive,
    TestRestore,
    RestoreJournal,
}

/// Engine-constructed, non-serializable exact local administration scope. The
/// full journal may contain other principals' agreements and multiple networks;
/// the local profile label is not a filter or a narrower disclosure guarantee.
pub struct FullJournalBackupScope<'a> {
    source: &'a LocalBackupSource,
    principal_id: &'a str,
    action: FullJournalBackupAction,
    archive_path: &'a Path,
    restore_destination: Option<&'a Path>,
    retention_policy: &'a str,
}
impl FullJournalBackupScope<'_> {
    pub fn source(&self) -> &LocalBackupSource {
        self.source
    }
    pub fn principal_id(&self) -> &str {
        self.principal_id
    }
    pub fn action(&self) -> FullJournalBackupAction {
        self.action
    }
    pub fn archive_path(&self) -> &Path {
        self.archive_path
    }
    pub fn restore_destination(&self) -> Option<&Path> {
        self.restore_destination
    }
    pub fn retention_policy(&self) -> &str {
        self.retention_policy
    }
    pub fn included_journals(&self) -> &'static [&'static str] {
        INCLUDED_JOURNALS
    }
    pub fn excluded_journals(&self) -> &'static [&'static str] {
        EXCLUDED_JOURNALS
    }
    pub fn includes_all_principals_and_profiles(&self) -> bool {
        true
    }
    pub fn backup_key_loss_is_unrecoverable(&self) -> bool {
        true
    }
}

/// Implement only in the trusted local administration runtime. Acquire must verify
/// explicit full-store permission, exact principal/source/profile/paths/retention,
/// and hold an authoritative lock/lease against concurrent revocation for the
/// complete operation. A Boolean callback, broad read grant, or UI acknowledgment
/// does not meet that contract. No credentials or persistent grants are created.
pub trait FullJournalBackupConsent {
    fn acquire<'a>(
        &'a self,
        scope: &'a FullJournalBackupScope<'_>,
    ) -> Option<Box<dyn FullJournalBackupLease + 'a>>;
}
/// The trusted provider owns this lease and releases its authority lock on drop.
/// Rechecks catch invalidation but alone do not provide atomic revocation safety.
pub trait FullJournalBackupLease {
    fn still_authorized(&self) -> bool;
}

/// Preprovisioned storage key and private local path, never a wire DTO.
pub struct LocalJournalBackup<'a> {
    pub source: &'a LocalBackupSource,
    pub destination: &'a Path,
    pub backup_key: &'a DatabaseKey,
    pub retention_policy: &'a str,
    pub consent: &'a dyn FullJournalBackupConsent,
}
pub struct LocalJournalRestore<'a> {
    pub source: &'a LocalBackupSource,
    pub archive: &'a Path,
    pub backup_key: &'a DatabaseKey,
    pub destination: &'a Path,
    pub destination_key: &'a DatabaseKey,
    pub retention_policy: &'a str,
    pub consent: &'a dyn FullJournalBackupConsent,
}

/// Safe runtime metadata. No archive path, snapshot digest, account IDs, table
/// counts, keys or other principals' records are exposed to ordinary readers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct JournalRecoveryMetadata {
    pub schema_version: u16,
    pub restored_journal_quarantined: bool,
    pub writer_reconciliation_required: bool,
    pub writer_authority_established: bool,
    pub outstanding_history_completeness_established: bool,
    pub new_authorization_allowed: bool,
    pub wallet_recovered: bool,
    pub separate_private_journals_recovered: bool,
    pub backup_scope: &'static str,
}

impl Engine {
    /// The trusted runtime associates this handle with its configured local
    /// profile before granting backup administration. Issuance confers no grant,
    /// source freshness, signer connection or permission to back up anything.
    pub fn bind_local_backup_source(
        &self,
        local_profile_id: &str,
        source_id: &str,
    ) -> Result<LocalBackupSource> {
        require_encrypted(self)?;
        validate_id(local_profile_id)?;
        validate_id(source_id)?;
        Ok(LocalBackupSource {
            store: self.store.clone(),
            local_profile_id: local_profile_id.into(),
            source_id: source_id.into(),
        })
    }
    pub fn backup_local_journal(
        &self,
        access: &Access,
        local: LocalJournalBackup<'_>,
    ) -> Result<AgreementBackupSummary> {
        validate_request(
            self,
            access,
            local.source,
            local.destination,
            local.retention_policy,
        )?;
        let scope = FullJournalBackupScope {
            source: local.source,
            principal_id: &access.principal_id,
            action: FullJournalBackupAction::CreateArchive,
            archive_path: local.destination,
            restore_destination: None,
            retention_policy: local.retention_policy,
        };
        let lease = local.consent.acquire(&scope).ok_or_else(consent_denied)?;
        if !lease.still_authorized() {
            return Err(consent_denied());
        }
        let result = self
            .store
            .backup_agreement_journal(local.destination, local.backup_key)
            .map_err(backup_error)?;
        if !lease.still_authorized() {
            return Err(permission_changed());
        }
        Ok(result)
    }
    /// Produces a separate quarantined restored Engine, never replaces this
    /// engine, installs a profile, reconnects a signer or clears writer recovery.
    pub fn restore_local_journal(
        &self,
        access: &Access,
        local: LocalJournalRestore<'_>,
    ) -> Result<(Engine, AgreementRestoreReport)> {
        self.restore_journal_with_action(access, local, FullJournalBackupAction::RestoreJournal)
    }
    /// Runs an actual encrypted restore and keyed reopen, then releases the
    /// restored Engine. The private test destination remains on disk, quarantined.
    pub fn test_restore_local_journal(
        &self,
        access: &Access,
        local: LocalJournalRestore<'_>,
    ) -> Result<AgreementRestoreReport> {
        let (restored, report) =
            self.restore_journal_with_action(access, local, FullJournalBackupAction::TestRestore)?;
        // Store restoration already verifies integrity and keyed reopen while
        // the consent lease is held in restore_journal_with_action.
        drop(restored);
        Ok(report)
    }
    fn restore_journal_with_action(
        &self,
        access: &Access,
        local: LocalJournalRestore<'_>,
        action: FullJournalBackupAction,
    ) -> Result<(Engine, AgreementRestoreReport)> {
        validate_request(
            self,
            access,
            local.source,
            local.destination,
            local.retention_policy,
        )?;
        validate_path(local.archive)?;
        if local.archive == local.destination {
            return Err(ApiError::new(
                "INVALID_REQUEST",
                "A restore requires a distinct new private destination",
            ));
        }
        let scope = FullJournalBackupScope {
            source: local.source,
            principal_id: &access.principal_id,
            action,
            archive_path: local.archive,
            restore_destination: Some(local.destination),
            retention_policy: local.retention_policy,
        };
        let lease = local.consent.acquire(&scope).ok_or_else(consent_denied)?;
        if !lease.still_authorized() {
            return Err(consent_denied());
        }
        let (store, report) = wholepact_store::backup::restore_agreement_journal(
            local.archive,
            local.backup_key,
            local.destination,
            local.destination_key,
        )
        .map_err(backup_error)?;
        if !lease.still_authorized() {
            return Err(permission_changed());
        }
        Ok((Engine::from_store(store), report))
    }
    pub fn journal_recovery_metadata(&self) -> Result<JournalRecoveryMetadata> {
        let state = self.store.recovery_state().map_err(backup_error)?;
        Ok(JournalRecoveryMetadata {
            schema_version: 1,
            restored_journal_quarantined: state.recovery_required,
            writer_reconciliation_required: state.recovery_required,
            writer_authority_established: false,
            outstanding_history_completeness_established: false,
            new_authorization_allowed: false,
            wallet_recovered: false,
            separate_private_journals_recovered: false,
            backup_scope: "complete_coordination_and_local_authority_journal_only",
        })
    }
}
fn require_encrypted(engine: &Engine) -> Result<()> {
    if engine.store.protection() != StorageProtection::Encrypted {
        return Err(ApiError::new(
            "ENCRYPTED_STORAGE_REQUIRED",
            "Full-journal backup requires a verified encrypted coordination store",
        ));
    }
    Ok(())
}
fn validate_request(
    engine: &Engine,
    access: &Access,
    source: &LocalBackupSource,
    destination: &Path,
    retention: &str,
) -> Result<()> {
    require_encrypted(engine)?;
    validate_id(&access.principal_id)?;
    if !Arc::ptr_eq(&engine.store, &source.store) {
        return Err(ApiError::new("BACKUP_SOURCE_MISMATCH", "Backup administration is bound to a different local store instance; obtain a new trusted runtime binding"));
    }
    validate_path(destination)?;
    if retention != LOCAL_RETENTION_UNTIL_REMOVAL {
        return Err(ApiError::new(
            "UNSUPPORTED_RETENTION_POLICY",
            "This local archive supports retention until deliberate removal; no automatic timed deletion is implemented",
        ));
    }
    Ok(())
}
fn validate_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
    {
        return Err(ApiError::new(
            "INVALID_REQUEST",
            "A canonical local profile, source and principal identity is required",
        ));
    }
    Ok(())
}
fn validate_path(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return Err(ApiError::new(
            "INVALID_REQUEST",
            "Use an explicit absolute private file path without parent-directory traversal",
        ));
    }
    Ok(())
}
fn consent_denied() -> ApiError {
    ApiError::new("FULL_JOURNAL_BACKUP_CONSENT_REQUIRED", "A current trusted local administration lease for this exact full-journal operation is required; agreement read access is insufficient")
}
fn permission_changed() -> ApiError {
    let mut error = ApiError::new("BACKUP_PERMISSION_CHANGED", "Local backup permission changed before completion could be reported; preserve any encrypted output and inspect it under a new explicit grant");
    error.details =
        Box::new(serde_json::json!({"encrypted_output_may_exist":true,"authority_enabled":false}));
    error.safe_actions = vec![
        "preserve_existing_local_files".into(),
        "request_fresh_local_backup_administration".into(),
    ];
    error
}
fn backup_error(error: StoreError) -> ApiError {
    let code = match error {
        StoreError::UnsupportedSchema(_) => "BACKUP_SCHEMA_UNSUPPORTED",
        StoreError::ResourceExhausted => "RESOURCE_EXHAUSTED",
        StoreError::RecoveryRequired => "RECOVERY_REQUIRED",
        _ => "BACKUP_STORAGE_UNAVAILABLE",
    };
    let mut error = ApiError::new(code, "The encrypted local journal operation could not be verified; preserve existing files and do not overwrite or activate a partial restore");
    error.details =
        Box::new(serde_json::json!({"encrypted_output_may_exist":true,"authority_enabled":false}));
    error.safe_actions = vec![
        "preserve_existing_local_files".into(),
        "inspect_original_journal".into(),
    ];
    error
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
