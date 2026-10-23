//! Foreground, non-signing native composition. No constructor creates a grant.
//! The executable alone owns profile, terminals and all writer lifetimes. It
//! deliberately provides no spending, account-enrollment or submission issuer.
mod authority;
mod backup;
mod files;
#[cfg(all(wholepact_financial_rendered_host_semantic_ci, feature="coordinated-financial-workflow-v1", target_os="linux"))]
mod financial_ci_host_failure;
#[cfg(feature = "financial-runtime")]
mod financial_backup;
#[cfg(feature = "financial-runtime")]
mod financial_inventory;
#[cfg(feature = "financial-runtime")]
mod financial_profile;
#[cfg(feature = "financial-runtime")]
mod financial_runtime;
#[cfg(feature = "financial-runtime")]
mod generation_backup;
#[cfg(feature = "financial-runtime")]
mod generation_restore;
mod history;
mod host;
#[cfg(feature = "financial-runtime")]
mod recovered_capsule_history;
#[cfg(feature = "financial-runtime")]
mod recovered_history;
#[cfg(feature = "financial-runtime")]
mod recovery_generation;
mod recovery_inventory;
#[cfg(feature = "financial-runtime")]
mod recovery_semantics;
mod terminal;
mod vault;

pub use host::run;
#[cfg(all(feature = "coordinated-financial-workflow-v1", target_os = "linux"))]
pub use host::run_coordinated_financial_host_v1;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("This native host is qualified only for the Linux source configuration")]
    Platform,
    #[error(
        "A foreground controlling terminal is required; stdin and redirected input are not accepted"
    )]
    Terminal,
    #[error("The operation was not explicitly approved, or its session permission expired")]
    Permission,
    #[error("Profile already open; another foreground host owns its exclusive lock")]
    Locked,
    #[error("Invalid, unexpected or incomplete profile/artifact; preserve the original files")]
    Invalid,
    #[error("Profile authentication failed")]
    Authentication,
    #[error(
        "Protected storage or cryptographic operation failed; preserve any partial encrypted output"
    )]
    Storage,
    #[error(
        "Restored journals are quarantined; history and recovery-review are read-only. A restricted successor requires the separately gated recovery-activate workflow"
    )]
    Quarantined,
    #[error(
        "Unsupported operation: no signer/account ownership/financial authority is created by this host"
    )]
    Unsupported,
    #[error(
        "Receipt operation could not be verified ({0}); preserve the original intent and any output unchanged"
    )]
    Receipt(String),
    #[error("Recovery semantic inventory is incomplete or inconsistent: {0}")]
    RecoverySemantic(String),
    #[error(
        "Close this successor first, then use the explicit generation-backup command with separate native approval; ordinary backup format cannot represent its complete ancestor history"
    )]
    RecoveryBackupUnsupported,
    #[error(
        "Restricted successors cannot run financial workflows until generation-scoped account and signer continuity admission is implemented; original recovery restrictions remain unchanged"
    )]
    RecoveryFinancialUnsupported,
    #[error(
        "Complete-origin informational recovery v2 remains unavailable pending native lifecycle and exact publication qualification; no source, signer or target was opened"
    )]
    CompleteOriginRecoveryUnavailable,
    #[error(
        "Historical export did not finish cleanly. The destination may contain a complete or partial private transaction; preserve and inspect it. This operation never overwrites an existing file or submits a transaction"
    )]
    HistoricalExportIncomplete,
    #[error(
        "Generation archive operation did not finish cleanly. Complete or partial encrypted output may remain at the requested destination. Preserve every file and authenticate that exact path before use; never overwrite or treat a lost acknowledgment as proof that publication did not occur"
    )]
    GenerationArchiveIncomplete,
}
pub(crate) type Result<T> = std::result::Result<T, Error>;
impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self::Storage
    }
}
impl From<wholepact_engine::ApiError> for Error {
    fn from(_: wholepact_engine::ApiError) -> Self {
        Self::Permission
    }
}
impl From<wholepact_storage_security::StorageSecurityError> for Error {
    fn from(_: wholepact_storage_security::StorageSecurityError) -> Self {
        Self::Storage
    }
}
impl From<wholepact_storage_security::bundle::BundleError> for Error {
    fn from(_: wholepact_storage_security::bundle::BundleError) -> Self {
        Self::Storage
    }
}
impl From<wholepact_transport::TransportError> for Error {
    fn from(_: wholepact_transport::TransportError) -> Self {
        Self::Invalid
    }
}
impl From<wholepact_chain::ChainError> for Error {
    fn from(_: wholepact_chain::ChainError) -> Self {
        Self::Invalid
    }
}
impl From<wholepact_store::StoreError> for Error {
    fn from(_: wholepact_store::StoreError) -> Self {
        Self::Storage
    }
}
impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Self::Invalid
    }
}

pub(crate) fn now() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|_| Error::Invalid)
}
pub(crate) fn random<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0; N];
    getrandom::fill(&mut b).map_err(|_| Error::Storage)?;
    Ok(b)
}
pub(crate) fn id(s: &str) -> Result<()> {
    if s.is_empty()
        || s.len() > 128
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
    {
        Err(Error::Invalid)
    } else {
        Ok(())
    }
}

#[cfg(feature = "financial-runtime")]
impl From<wholepact_storage_security::generation_archive::ArchiveError> for Error {
    fn from(_: wholepact_storage_security::generation_archive::ArchiveError) -> Self {
        Self::Storage
    }
}
