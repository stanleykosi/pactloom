//! Optional independent account authority, not a signing service or chain oracle.
//!
//! Every exact permit already represents durable conservative exposure. A permit
//! is not canceled by pausing/revoking its writer. Availability loss never permits
//! a fallback to a local budget. Correct signer/OS and a durable independently
//! administered witness are explicit assumptions; no TPM is required. A witness
//! snapshot rollback itself is outside this assumption and restores quarantine.
#![forbid(unsafe_code)]

#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
pub mod native_witness_owner;

pub mod construction_transport_handoff_v1;
mod construction_transport_handoff_policy_v1;
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
pub(crate) mod construction_transport_owner_v1;
mod admission;
mod automation;
pub mod offline;
pub mod offline_clock_v1;
mod offline_admission;
mod offline_export;
mod offline_outcome;
mod offline_retry;
pub use automation::*;
pub use offline_admission::{
    AuthenticatedOfflineIntent, CommittedOfflineAdmission, OfflineEnrollmentStatus,
    OfflineIntentAuthenticationIssuer, OfflineIntentAuthenticationRecord, OfflineReservationRecord,
};
pub use offline_export::{CommittedOfflineAdmissionExport, OfflineAdmissionExportPlan};
pub use offline_outcome::{
    CommittedOfflineControlExport, HistoricalOfflineAdmissionExport,
    HistoricalOfflineControlExport, OfflineAdmissionControl, OfflineAdmissionControlOutcome,
};
pub use offline_retry::{
    OfflineControllerProofInput, OfflineOriginalBridge, OriginalCommitLink,
    OriginalTransportReceipt, RetainedOfflineOriginal,
};
pub mod account_use;
pub mod account_use_link;
#[cfg(feature = "pending-birth-foundation")]
pub mod permanent_exclusion_signature;
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
pub(crate) mod permanent_exclusion_owner;
mod journal;
pub mod manual_enrollment;
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
pub(crate) mod manual_enrollment_owner;
mod manual_enrollment_policy;
#[cfg(feature = "pending-birth-foundation")]
pub mod manual_enrollment_signature;
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
pub(crate) mod manual_roster_construction_owner_v2;
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
pub(crate) mod manual_roster_construction_owner_v3;
mod manual_roster_construction_policy_v2;
mod manual_roster_construction_policy_v3;
#[cfg(feature = "pending-birth-foundation")]
pub mod manual_roster_construction_signature_v2;
#[cfg(feature = "pending-birth-foundation")]
pub mod manual_roster_construction_signature_v3;
pub mod manual_roster_construction_v2;
pub mod manual_roster_construction_v3;
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
pub(crate) mod manual_roster_continuation_owner_v2;
#[cfg(feature = "pending-birth-foundation")]
pub mod manual_roster_continuation_signature_v2;
pub mod manual_roster_extension_v2;
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
pub(crate) mod manual_roster_owner_v2;
mod manual_roster_policy_v2;
#[cfg(feature = "pending-birth-foundation")]
pub mod manual_roster_signature_v2;
pub mod manual_roster_witness_v2;
pub mod manual_session_continuation;
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
pub(crate) mod manual_session_continuation_owner;
mod manual_session_continuation_policy;
#[cfg(feature = "pending-birth-foundation")]
pub mod manual_session_continuation_signature;
pub mod pending_birth;
#[cfg(feature = "pending-birth-foundation")]
pub mod pending_birth_signature;
mod pending_birth_storage;
pub use manual_enrollment::{
    AuthenticatedBornManualEnrollment, BornManualEnrollmentAdmissionRequest,
    ManualEnrollmentExtension,
};
mod exposure_view;
mod policy;
pub mod protocol;
mod recovery;
mod reservation_view;
mod resolution;
pub use recovery::{AuthenticatedRecoveryFence, RecoveryFenceReceipt};
mod session;
pub use resolution::{AuthenticatedResolutionReceipt, resolution_source_digest};
pub mod transport;

pub use journal::AuthorityJournal;
pub use protocol::*;
pub use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
pub use transport::{
    AuthenticatedAutomaticKeyUseAdmission, AuthenticatedDispatchAdmission, AuthenticatedPermit,
    AuthenticatedWriterSession, AuthorityClient, AuthorityServer, ClientTls, ServerTls,
};

use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Source-staged V3 must not be exposed before complete joined/native qualification.
pub const COMMON_CONTEXT_V3_ACTIVATION_QUALIFIED: bool = false;

pub const MAX_FRAME_BYTES: usize = 256 * 1024;
pub(crate) const MAX_EVENTS: u64 = 10_000;
pub(crate) const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_MONEY: u64 = 2_100_000_000_000_000;
pub type Result<T> = std::result::Result<T, AuthorityError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityError {
    #[error("authority request is malformed or does not match its exact binding")]
    InvalidBinding,
    #[error("authority identity is not authorized for this account or action")]
    Permission,
    #[error("authority head or writer epoch is stale")]
    StaleHead,
    #[error("operation identity was previously used for different content")]
    Conflict,
    #[error("writer is paused or revoked")]
    Inactive,
    #[error("restored authority requires independent reconciliation")]
    RecoveryRequired,
    #[error("authorization or owner policy expired")]
    Expired,
    #[error("owner-authorized account policy rejects this request")]
    PolicyDenied,
    #[error("conservative account exposure would exceed the owner-authorized budget")]
    BudgetExceeded,
    #[error("a selected input has an outstanding reservation")]
    InputReserved,
    #[error("this obligation already has an outstanding reservation")]
    ObligationReserved,
    #[error("authority resource limit exceeded")]
    Limit,
    #[error("protected authority storage failed; outcome must be reconciled")]
    Storage,
    #[error("authority history failed verification")]
    CorruptHistory,
    #[error("permanent routine-use exclusion is unavailable pending attended native and kernel qualification")]
    PermanentStopUnavailable,
    #[error("offline reservation history requires a qualified typed consumer")]
    OfflineHistoryUnsupported,
    #[error("non-signing construction history requires a qualified purpose-specific consumer")]
    ConstructionHistoryUnsupported,
    #[error("unsupported authority format or schema")]
    UnsupportedVersion,
    #[error("mutually authenticated TLS failed")]
    Authentication,
    #[error("authority response is uncertain; retry the identical operation")]
    Uncertain,
    #[error("chain-qualified exposure resolution is unavailable")]
    ResolutionUnavailable,
    #[error("fresh reconciled and owner-activated writer session is required")]
    SessionRequired,
    #[error("a pending or active writer session requires an explicit owner pause or replacement")]
    SessionPending,
}
impl From<rusqlite::Error> for AuthorityError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Storage
    }
}
impl From<wholepact_storage_security::StorageSecurityError> for AuthorityError {
    fn from(e: wholepact_storage_security::StorageSecurityError) -> Self {
        use wholepact_storage_security::StorageSecurityError as E;
        if matches!(e, E::QuarantinedDatabase) {
            Self::RecoveryRequired
        } else {
            Self::Storage
        }
    }
}

pub(crate) fn encode<T: Serialize>(v: &T) -> Result<Zeroizing<Vec<u8>>> {
    let b = Zeroizing::new(serde_json::to_vec(v).map_err(|_| AuthorityError::InvalidBinding)?);
    if b.len() > MAX_FRAME_BYTES {
        return Err(AuthorityError::Limit);
    }
    Ok(b)
}
pub(crate) fn decode<T: DeserializeOwned>(b: &[u8]) -> Result<T> {
    if b.len() > MAX_FRAME_BYTES {
        return Err(AuthorityError::Limit);
    }
    serde_json::from_slice(b).map_err(|_| AuthorityError::InvalidBinding)
}
pub(crate) fn digest<T: Serialize>(domain: &str, v: &T) -> Result<String> {
    let b = encode(v)?;
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update([0]);
    h.update(&*b);
    Ok(hex::encode(h.finalize()))
}
pub(crate) fn id(v: &str) -> Result<()> {
    if v.is_empty()
        || v.len() > 128
        || !v
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.:".contains(&c))
    {
        return Err(AuthorityError::InvalidBinding);
    }
    Ok(())
}
pub(crate) fn hash(v: &str) -> Result<()> {
    if v.len() != 64
        || !v
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(AuthorityError::InvalidBinding);
    }
    Ok(())
}
pub(crate) fn now_ms() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| AuthorityError::Expired)?
        .as_millis()
        .try_into()
        .map_err(|_| AuthorityError::Expired)
}

#[cfg(test)]
mod tests;

#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
mod born_history_server;
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
mod pending_birth_owner;
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
mod witness_locator;
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
pub use born_history_server::{
    open_born_history_for_server, open_born_manual_attempt_for_server,
    open_born_manual_enrollment_for_server, open_born_manual_roster_attempt_v2_for_server,
};

mod retirement_history;
pub use retirement_history::RetirementWitnessHistoryFacts;

mod construction_history;
mod construction_history_v2;
pub use construction_history::{ConstructionHistoryV1, ConstructionOriginHistoryV1};
pub use construction_history_v2::{
    ConstructionApprovalHistoryV2, ConstructionHistoryV2, ConstructionOriginHistoryV2,
    ConstructionOriginHistoryV3,
};
