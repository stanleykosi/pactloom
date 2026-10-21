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
#[cfg(target_os = "linux")]
mod born_dispatch_storage;
mod bridge_storage;
pub(crate) mod durable_born_policy_v1;
pub(crate) use durable_born_policy_v1::validate_retained_original as validate_retained_durable_born_original_v1;
pub use durable_born_policy_v1::DurableBornPolicyBindingV1;
#[cfg(all(
    feature = "durable-proposal",
    feature = "native-ui",
    target_os = "linux"
))]
pub(crate) mod durable_construction_v1;
#[cfg(target_os = "linux")]
pub(crate) use born_dispatch_storage::RetainedBornDispatchV1;
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
#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    target_os = "linux"
))]
pub(crate) use preconstruction_lease::PreconstructionRecordLease;
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
pub(crate) mod named_recipient_inventory;
pub(crate) mod named_recipient_records;
mod offline_receipts;
mod recovery_migration;
mod storage;
#[cfg(all(
    feature = "durable-proposal",
    feature = "pending-birth-owner-signing",
    target_os = "linux"
))]
pub(crate) use storage::PreparedDeliveryJournalRevisionV3;
#[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing", target_os = "linux"))]
pub(crate) use storage::financial_profile_v1::{FinancialConsentJournalV1, FinancialAdmissionJournalPinV1, FinancialOperationJournalPinV1, FinancialReturnJournalPinV1, FinancialSourceBindingV1, PreparedFinancialContinuationIntentV1, RetainedFinancialContinuationIntentV1, PendingFinancialContinuationAdmissionV1, ApprovedFinancialSpendConsentV1, PreparedFinancialSpendV1};
#[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing", target_os = "linux"))]
pub(crate) use storage::financial_profile_v1::{CoordinatedContinueReviewDataV1, CoordinatedContinueSignerRoleV1, PreparedCoordinatedFinancialContinuationV1};
#[cfg(all(feature = "coordinated-signer-continue", target_os = "linux"))]
pub(crate) use storage::financial_profile_v1::{PresentedCoordinatedFinancialContinuationV1, CoordinatedContinuationCommitFailureV1};
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
pub(crate) use authority::durable_payment_admission_intent_v1;
pub use authority::*;
pub(crate) use durable_payment_admission_intent_v1::{
    read_durable_payment_admission_intents_v1, RetainedDurablePaymentAdmissionIntentV1,
};
#[cfg(all(
    feature = "durable-proposal",
    feature = "native-ui",
    target_os = "linux"
))]
pub(crate) use durable_payment_admission_intent_v1::{
    ApprovedDurablePaymentAdmissionIntentV1, PreparedDurablePaymentAdmissionIntentV1,
};
pub use storage::{OriginalAuthorizationLease, SignerConsentBundleAdapter, SignerConsentJournal};
pub(crate) use storage::SignerJournalSourceOwner;
pub use types::*;

use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;
use wholepact_core::proposal::canonical_digest;
use zeroize::Zeroizing;

const APPLICATION_ID: i64 = 0x57505343;
const SCHEMA_VERSION: i64 = 19;
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
        "unsupported signer journal schema; only exact proven-nonborn v12 through v18 additive extensions are supported"
    )]
    UnsupportedSchema,
    #[error("offline reservation history requires a qualified typed signer recovery consumer")]
    OfflineHistoryUnsupported,
    #[error("named-recipient history requires a qualified typed financial consumer")]
    NamedRecipientHistoryUnsupported,
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

#[cfg(all(feature = "pending-birth-owner-signing", target_os = "linux"))]
mod born_named_continuation;
#[cfg(all(feature = "pending-birth-owner-signing", target_os = "linux"))]
mod born_named_reentry;
mod common_context_reentry_audit_v1;
#[cfg(all(feature = "pending-birth-owner-signing", target_os = "linux"))]
pub(crate) use born_named_reentry::BornNamedReentryInventoryV1;
pub use common_context_reentry_audit_v1::{
    CommonContextReentryAuditInventoryV1, CommonContextReentryAuditPhaseV1,
    CommonContextReentrySignerAuditV1, CommonContextSignerAuditInventoryV2,
    MissingCommonContextNativeAuditV2, MissingConstructionTransportNativeAuditV1,
};

#[cfg(test)]
mod common_context_reentry_audit_tests;

#[cfg(test)]
pub(crate) mod common_context_reentry_audit_fixture;

#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    target_os = "linux"
))]
mod owner_inspection;

#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    feature = "offline-review-foundation",
    target_os = "linux"
))]
mod named_recipient_setup;
#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    feature = "offline-review-foundation",
    target_os = "linux"
))]
pub(crate) use named_recipient_setup::{
    LiveNamedRecipientProfile, NamedRecipientPins, PreparedNamedRecipientSetup,
};

#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    feature = "offline-review-foundation",
    target_os = "linux"
))]
mod named_intent_transport;

#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    feature = "offline-review-foundation",
    target_os = "linux"
))]
pub(crate) use named_recipient_setup::PreparedNamedRecipientReturnFile;
#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    feature = "offline-review-foundation",
    target_os = "linux"
))]
pub(crate) use named_recipient_setup::{
    NamedIntentExportTemplate, NamedRecipientOriginalInputs, PreparedNamedIntentFileExport,
    PreparedNamedRecipientOriginalImport, RetainedNamedIntentExport,
};
#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    feature = "offline-review-foundation",
    target_os = "linux"
))]
pub(crate) use named_recipient_setup::{
    NamedRecipientOperation, PreparedBornNamedRecipientReturnFile,
    PreparedBornNamedRecipientSigning, PreparedNamedRecipientSigning,
};

#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    feature = "offline-review-foundation",
    target_os = "linux"
))]
pub(crate) use named_recipient_setup::{
    BornCourierActionV1, BornNamedRecipientOriginalInputs, PreparedBornDeliveryFileV1,
    PreparedBornIntentCourierV1, PreparedBornNamedIntentFileExport,
    PreparedBornNamedRecipientOriginalImport, RetainedBornCourierDeliveryV1,
    RetainedBornNamedIntentExport,
};

#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    feature = "offline-review-foundation",
    target_os = "linux"
))]
pub(crate) use named_recipient_setup::PreparedBornAdmissionImportV1;

#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    feature = "offline-review-foundation",
    target_os = "linux"
))]
pub(crate) use named_recipient_setup::HeldBornHostHistoryV1;

#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    feature = "offline-review-foundation",
    feature = "pending-birth-owner-signing",
    target_os = "linux"
))]
pub(crate) use named_recipient_setup::PreparedBornOfflineOwnerEnrollmentV1;

#[cfg(feature = "synthetic-born-joined-qualification")]
pub use named_recipient_setup::OriginalNamedSetupMetadataV1;

#[cfg(feature = "synthetic-born-joined-qualification")]
pub use named_recipient_setup::{OriginalNamedPaymentArtifactsV1, OriginalNamedReturnReferencesV1};

#[cfg(test)]
#[path = "durable_payment_admission_schema19_tests.rs"]
mod durable_payment_admission_schema19_tests;

pub(crate) use authority::durable_delivery_admission_intent_v2;
mod financial_admission_intents;
pub(crate) use durable_delivery_admission_intent_v2::RetainedDurableDeliveryAdmissionIntentV2;
#[cfg(all(
    feature = "durable-proposal",
    feature = "native-ui",
    target_os = "linux"
))]
pub(crate) use durable_delivery_admission_intent_v2::{
    ApprovedDurableDeliveryAdmissionIntentV2, PreparedDurableDeliveryAdmissionIntentV2,
};

/// Preserve the original accepted-manifest receipt/reference validation before
/// the closed delivery controller interprets its retained proposal.
#[cfg(all(feature = "durable-proposal", feature = "pending-birth-owner-signing", target_os = "linux"))]
pub(crate) fn validated_delivery_manifest_proposal_v3(
    manifest: &AcceptedManifestRecord,
) -> Result<wholepact_core::Proposal> {
    manifest.proposal()
}
