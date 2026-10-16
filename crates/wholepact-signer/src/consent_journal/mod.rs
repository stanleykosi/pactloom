//! Signer-owned original authority, distinct from coordinator metadata and the
//! legacy synthetic Store ledger. The vault retains the independent journal key.
//! No JSON import, generic mutation, connection accessor, terminal-approval
//! conversion, or coordinator authority provider can create original consent.
//!
//! Native launch, transport-key possession, current input/chain/writer freshness
//! still require independently qualified providers. This module implements the
//! durable evidence boundary, not those external trust mechanisms or signing.

mod authority;
mod automation;
pub use automation::*;
mod sponsor;
#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    target_os = "linux"
))]
pub(crate) use sponsor::{ApprovedSponsorManifestBinding, PreparedSponsorPolicyChange};
pub use sponsor::{
    NativeSponsorPolicyRecord, NativeSponsorPolicyStatus, SponsorOwnerAttestation,
    SponsorOwnerBinding, SponsorPolicyBinding, SponsorWitnessBinding,
};
mod bridge_storage;
#[cfg(all(
    target_os = "linux",
    any(
        all(feature = "native-ui", feature = "authority-signing"),
        all(test, feature = "synthetic-qualification")
    )
))]
mod dispatch_storage;
#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    target_os = "linux"
))]
mod preconstruction_lease;
#[cfg(all(
    target_os = "linux",
    any(
        all(feature = "native-ui", feature = "authority-signing"),
        all(test, feature = "synthetic-qualification")
    )
))]
pub(crate) use dispatch_storage::RetainedDispatch;
mod bridge_delivery_storage;
mod redelivery_types;
pub use redelivery_types::*;
#[cfg(feature = "authority-signing")]
mod settlement;
#[cfg(feature = "authority-signing")]
pub use settlement::*;
#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    target_os = "linux"
))]
mod account_use_recovery;
mod account_use_storage;
#[cfg(all(feature = "pending-birth-owner-signing", target_os = "linux"))]
mod permanent_stop;
#[cfg(all(feature = "pending-birth-owner-signing", target_os = "linux"))]
pub(crate) use permanent_stop::PermanentStopSnapshot;
#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    target_os = "linux"
))]
#[allow(dead_code)]
mod retired_history;
#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    target_os = "linux"
))]
pub(crate) use retired_history::RetiredLocalSnapshot;
mod offline_history;
mod offline_reconciliation;
mod writer_history;
pub use offline_reconciliation::{
    OfflineReconciliationInventory, OfflineReconciliationPresence, OfflineReplayCoverage,
    ReconciledOfflineOrigin,
};
mod offline_receipts;
mod recovery_migration;
mod storage;
pub use offline_history::{
    OfflineHistoryInventory, OfflineLocalAdmissionHistory, OfflineLocalKeyUseHistory,
    OfflineMinimalAdmissionHistoryStatement, OfflineNativeConsentHistoryReceipt,
    OfflineOriginHistory, OfflineOriginalConsentHistory, OfflineRemoteHistoryProvenance,
    OfflineRetainedResultHistory, OfflineSignatureKnowledge,
};
#[cfg(all(feature = "pending-birth-owner-signing", target_os = "linux"))]
pub(crate) use storage::CommonContextAuthorizedReentryOwnerInput;
#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    target_os = "linux"
))]
mod host_recovery_continuity;
#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    target_os = "linux"
))]
mod recovery_activation;
#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    target_os = "linux"
))]
pub(crate) use recovery_activation::*;
mod types;
pub use authority::*;
pub use storage::{OriginalAuthorizationLease, SignerConsentBundleAdapter, SignerConsentJournal};
pub use types::*;

use serde::{Serialize, de::DeserializeOwned};
use std::sync::Arc;
use wholepact_core::proposal::canonical_digest;
use zeroize::Zeroizing;

const APPLICATION_ID: i64 = 0x57505343;
const SCHEMA_VERSION: i64 = 15;
const MAX_RECORD_BYTES: usize = 512 * 1024;
const MAX_BACKUP_ROWS: u64 = 100_000;
const MAX_BACKUP_ENCODED_BYTES: u64 = 64 * 1024 * 1024;
const BACKUP_METADATA_RESERVE: u64 = 1024 * 1024;
const MAX_MONEY: u64 = 2_100_000_000_000_000;
const SCHEMA: &str = include_str!("schema.sql");

type Result<T> = std::result::Result<T, JournalError>;
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("protected signer journal storage failed")]
    Storage(#[from] wholepact_storage_security::StorageSecurityError),
    #[error("signer journal database operation failed")]
    Database,
    #[error("signer authority or exact native decision is unavailable or revoked")]
    Permission,
    #[error("signer review or decision expired")]
    Expired,
    #[error("signer journal requires writer and exposure reconciliation")]
    RecoveryRequired,
    #[error(
        "unsupported signer journal schema; only exact v8 through v14 additive schema extensions are supported"
    )]
    UnsupportedSchema,
    #[error("offline reservation history requires a qualified typed signer recovery consumer")]
    OfflineHistoryUnsupported,
    #[error("non-signing construction history requires a qualified financial activation consumer")]
    ConstructionHistoryUnsupported,
    #[error("signer journal record or exact binding is invalid")]
    InvalidBinding,
    #[error("immutable signer authority conflicts with retained original evidence")]
    Conflict,
    #[error("signer authority record not found")]
    NotFound,
    #[error("another potentially executable authorization exists for this obligation")]
    LiveAuthorization,
    #[error("an input is reserved by an outstanding signer authorization")]
    InputReserved,
    #[error("outstanding signer exposure exceeds the original enrolled budget")]
    BudgetExceeded,
    #[error("signer journal resource limit reached")]
    Limit,
}
impl From<rusqlite::Error> for JournalError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Database
    }
}

/// Process-local exact source identity, never a portable capability or key.
#[derive(Clone)]
pub struct SignerJournalBinding(Arc<()>);
impl PartialEq for SignerJournalBinding {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for SignerJournalBinding {}

fn digest<T: Serialize>(domain: &str, value: &T) -> Result<String> {
    canonical_digest(domain, value).map_err(|_| JournalError::InvalidBinding)
}
fn encode<T: Serialize>(value: &T) -> Result<Zeroizing<String>> {
    let raw =
        Zeroizing::new(serde_json::to_string(value).map_err(|_| JournalError::InvalidBinding)?);
    if raw.len() > MAX_RECORD_BYTES {
        return Err(JournalError::Limit);
    }
    Ok(raw)
}
fn decode<T: DeserializeOwned>(raw: String) -> Result<T> {
    let raw = Zeroizing::new(raw);
    if raw.len() > MAX_RECORD_BYTES {
        return Err(JournalError::Limit);
    }
    serde_json::from_str(&raw).map_err(|_| JournalError::InvalidBinding)
}
fn id(value: &str) -> Result<()> {
    crate::review::validate_label(value).map_err(|_| JournalError::InvalidBinding)
}
fn hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(JournalError::InvalidBinding);
    }
    Ok(())
}
fn now_ms() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| JournalError::Expired)?
        .as_millis()
        .try_into()
        .map_err(|_| JournalError::Expired)
}
fn random_id() -> Result<String> {
    crate::vault::random::<32>()
        .map(hex::encode)
        .map_err(|_| JournalError::Permission)
}

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "native-ui", target_os = "linux"))]
pub(crate) use authority::fixture::native_session as native_fixture_session;

mod construction_audit_v3;
pub use construction_audit_v3::{
    CommonContextSignerAuditInventoryV1, CommonContextSignerAuditV1,
    MissingCommonContextNativeAuditV1,
};

#[cfg(test)]
mod common_context_audit_tests;

mod common_context_reentry_audit_v1;
pub use common_context_reentry_audit_v1::{
    CommonContextReentryAuditInventoryV1, CommonContextReentryAuditPhaseV1,
    CommonContextReentrySignerAuditV1, CommonContextSignerAuditInventoryV2,
    MissingCommonContextNativeAuditV2, MissingConstructionTransportNativeAuditV1,
};

#[cfg(test)]
mod common_context_reentry_audit_tests;

#[cfg(test)]
pub(crate) mod common_context_reentry_audit_fixture;

#[cfg(all(feature = "native-ui", feature = "authority-signing", target_os = "linux"))]
mod owner_inspection;
