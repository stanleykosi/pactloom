//! Lower dependency installed-signer authentication boundary. This contains no
//! Store, wallet, journal, native decision or witness issuer. Public request and
//! audit structures are inert. Opaque manual leases arise only from the existing
//! fixed installed root pin and a live kernel-authenticated signer channel.
//!
//! Staged source only: no workspace membership, dependency or runtime route is
//! enabled by these files. Normal builds expose no synthetic issuer.
#![cfg(target_os = "linux")]

mod client;
pub mod framing;
pub mod manual;
pub mod manual_candidate_selection;
pub mod manual_continuation_v2;
pub mod manual_inventory;
pub mod manual_roster_v2;
pub mod native_launch;
pub mod native_peer;
pub mod provider;
pub mod retirement_evidence;
pub mod permanent_stop_v1;
pub use client::{
    ManualActionLease, ManualCandidateSelectionLease, ManualEnrollmentContinuationLeaseV2,
    ManualEnrollmentLease, ManualPreliminaryInventoryLease, NativeManualClient, PairScope,
    PendingManualCandidateSelection, PendingManualEnrollment,
    PendingManualEnrollmentContinuationV2, PendingManualPreliminaryInventory,
    PendingNativeManualPair, manual_current_caller_binding_digest,
};
pub use client::{ManualRosterEnrollmentLeaseV2, PendingManualRosterEnrollmentV2, PendingPermanentStopV1, PermanentStopLeaseV1};
pub use provider::{InstalledSignerProvider, SignerProviderInstallRequest};

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("permanent routine-use exclusion transport is unavailable pending attended native and kernel qualification")]
    PermanentStopUnavailable,
    #[error("retirement evidence transport is unavailable pending native and kernel qualification")]
    RetirementEvidenceUnavailable,
    #[error("installed signer origin is unavailable")]
    SignerOriginUnavailable,
    #[error("kernel-bound peer lifetime is unavailable")]
    PeerLifetimeUnavailable,
    #[error("protected peer authentication failed")]
    Authentication,
    #[error("exact manual binding does not match")]
    Binding,
    #[error("manual request conflicts with the held original")]
    Conflict,
    #[error("current manual permission is unavailable")]
    Permission,
    #[error("protected data is invalid or unsupported")]
    InvalidData,
    #[error("protected operation is locked")]
    Locked,
    #[error("protected entropy is unavailable")]
    Crypto,
    #[error("authenticated signer IPC failed")]
    Ipc,
    #[error("bounded signer resource limit reached")]
    Limit,
    #[error("protected file or channel operation failed")]
    Io(#[from] std::io::Error),
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut value = [0; N];
    getrandom::fill(&mut value).map_err(|_| Error::Crypto)?;
    Ok(value)
}
fn label(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_:./@".contains(&b))
    {
        return Err(Error::Binding);
    }
    Ok(())
}
fn hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Binding);
    }
    Ok(())
}
fn digest<T: serde::Serialize>(domain: &str, value: &T) -> Result<String> {
    wholepact_core::proposal::canonical_digest(domain, value).map_err(|_| Error::Binding)
}

pub mod manual_roster_candidate_selection_v2;
pub mod manual_roster_inventory_v2;
pub use client::{
    ManualRosterCandidateSelectionLeaseV2, ManualRosterInventoryLeaseV2,
    PendingManualRosterCandidateSelectionV2, PendingManualRosterInventoryV2,
};

pub mod manual_roster_construction_v2;
pub use client::{PendingManualRosterContributionRetentionV2, RetainedManualRosterContributionV2};

pub use client::{
    AdmittedManualRosterConstructionContributionV2, PendingManualRosterConstructionV2,
};

pub mod manual_roster_exact_input_observation_v1;
pub use client::{
    AdmittedRosterExactInputObservationV1, PendingRosterExactInputObservationV1,
    StartedRosterExactInputObservationV1,
};

// Distinct common-context domains; legacy V2 bytes retain their meaning.
pub mod manual_roster_construction_v3;
pub mod roster_common_context_read_v1;
pub use client::{
    AdmittedManualRosterConstructionContributionV3, AdmittedRosterCommonContextReadV1,
    PendingManualRosterConstructionV3, PendingRosterCommonContextReadV1,
    StartedRosterCommonContextReadV1,
};

pub mod common_context_reentry_v1;
pub use client::{
    CommonContextReentryClientV1, CommonContextReentrySourceV1, PendingCommonContextReentryPairV1,
    PendingCommonContextReentryV1, PendingReenteredRosterConstructionV1,
    ReenteredCommonContextConstruction,
};

pub mod common_context_handoff_v1;
pub use client::{
    NativeCommonContextHandoffAuthorizationV1, PendingCommonContextHandoffAuthorizationV1,
};

#[cfg(feature = "retirement-evidence-client")]
pub use client::{
    InstalledRetirementEvidenceClientV1, PendingRetirementDestinationEvidenceV1,
    PendingRetirementEvidencePairV1, RetirementDestinationEvidenceObservationV1,
    RetirementEvidenceCancellationV1,
};

pub mod named_verifier_policy;
pub use client::{NamedVerifierPolicyLease, PendingNamedVerifierPolicy};
