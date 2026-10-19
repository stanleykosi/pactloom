//! Bounded, request-only local application channel. Only the native window can
//! approve a pending kernel-observed peer; requests never unlock, approve or sign.
//! Authentication is a local process/channel claim, not remote key ownership.
#![cfg(target_os = "linux")]
#![cfg_attr(not(feature = "native-ui"), allow(dead_code))]
#[cfg(feature = "authority-signing")]
use crate::authority_bridge::host_recovery_ipc::v5::V5TransferDialect;
use crate::{Error, Result, files::PrivateDirectory, native_peer::PeerProcess, review::validate_label};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    os::{
        fd::AsRawFd,
        unix::{
            fs::PermissionsExt,
            net::{UnixListener, UnixStream},
        },
    },
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};
const MAX_GRANTS: usize = 16;
/// Public location metadata only. Knowledge of this narrow endpoint grants no
/// pairing, source disclosure, native approval or financial authority.
pub const QUARANTINED_INFORMATIONAL_SOCKET_BASENAME: &str = "quarantined-history-v5.sock";
const MAX_EVENTS: usize = 8;
const LEASE: Duration = Duration::from_secs(900);

// Dedicated retirement endpoint; no AppRequest or LocalEvent route reaches
// its private receive/authentication seam. Installed activation remains closed.
#[cfg(feature = "pending-birth-owner-signing")]
pub(crate) mod permanent_stop;
#[cfg(all(feature = "native-ui", feature = "authority-signing"))]
pub(crate) mod retirement_evidence;

// Pure checks are shared, but the ordinary outer product refusal stays closed.
#[cfg(feature = "pending-birth-owner-signing")]
mod common_context_scope_v3;
// No runtime, CLI or environment activation. This nominal owner exists only in
// the dedicated synthetic dependency facade, including cross-crate libtests.
#[cfg(feature = "synthetic-born-joined-qualification")]
mod scoped_born_qualification_v3;

/// Public request data; constructing this does not create any authority.
pub use wholepact_signer_origin::PairScope;
#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum Envelope {
    RequestPairing {
        schema_version: u32,
        application_label: String,
        scope: PairScope,
    },
    Request {
        schema_version: u32,
        grant_id: String,
        token_hex: String,
        request: AppRequest,
    },
}
impl Drop for Envelope {
    fn drop(&mut self) {
        if let Self::Request { token_hex, .. } = self {
            token_hex.zeroize();
        }
    }
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum AppRequest {
    #[cfg(feature = "pending-birth-owner-signing")]
    RequestBornPermanentStopV1 { request: Box<wholepact_signer_origin::permanent_stop_v1::HostPermanentStopRequestV1> },
    #[cfg(feature = "pending-birth-owner-signing")]
    RequestBornManualRosterEnrollmentIntentV2 {
        request: Box<wholepact_signer_origin::manual_roster_v2::HostManualRosterEnrollmentIntentV2>,
    },
    #[cfg(feature = "pending-birth-owner-signing")]
    RequestBornManualRosterEnrollmentV2 {
        request: Box<wholepact_signer_origin::manual_roster_v2::HostManualRosterPublicationRequestV2>,
    },

    #[cfg(feature = "pending-birth-owner-signing")]
    RequestBornCandidateSelectionV1 {request:Box<wholepact_core::manual_candidate_selection::ManualCandidateSelectionRequest>},
    #[cfg(feature = "pending-birth-owner-signing")]
    RequestBornPreliminaryInventoryV1 {request:Box<wholepact_core::manual_inventory::ManualPreliminaryInventoryRequest>},
    #[cfg(feature = "pending-birth-owner-signing")]
    RequestBornRosterExactInputObservationV1 {request:Box<wholepact_core::manual_roster_exact_input_observation_v1::ManualRosterExactInputObservationRequestV1>},
    #[cfg(feature = "pending-birth-owner-signing")]
    RequestBornRosterCommonContextReadV1 {request:Box<wholepact_core::manual_roster_construction_v3::RosterCommonContextReadRequestV1>},
    #[cfg(feature = "pending-birth-owner-signing")]
    RequestBornRosterCommonContextHandoffAuthorizationV1 {request:Box<wholepact_signer_origin::common_context_handoff_v1::RosterCommonContextHandoffAuthorizationRequestV1>},
    #[cfg(feature = "pending-birth-owner-signing")]
    RequestBornRosterCommonContextReentryV1 { request:Box<wholepact_core::common_context_reentry_v1::RosterCommonContextReentryRequestV1>, pending_grant_json:String },
    #[cfg(feature = "pending-birth-owner-signing")]
    RequestBornRosterReenteredConstructionV1 { request:Box<wholepact_core::manual_roster_construction_v3::ManualRosterConstructionRequestV3>, reentry_lineage_digest:String },
    #[cfg(feature = "pending-birth-owner-signing")]
    RequestBornRosterConstructionV2 {request:Box<wholepact_core::manual_roster_construction_v2::ManualRosterConstructionRequestV2>},
    #[cfg(feature = "pending-birth-owner-signing")]
    RequestBornRosterConstructionV3 {request:Box<wholepact_core::manual_roster_construction_v3::ManualRosterConstructionRequestV3>},
    #[cfg(feature = "pending-birth-owner-signing")]
    RequestBornRosterCandidateSelectionV2 {request:Box<wholepact_core::manual_roster_candidate_selection_v2::ManualRosterCandidateSelectionRequestV2>},
    #[cfg(feature = "pending-birth-owner-signing")]
    RequestBornRosterInventoryV2 {request:Box<wholepact_core::manual_roster_inventory_v2::ManualRosterInventoryRequestV2>},
    #[cfg(feature = "pending-birth-owner-signing")]
    RequestBornManualEnrollmentContinuationV2 {
        request: Box<wholepact_signer_origin::manual_continuation_v2::HostManualEnrollmentContinuationRequestV2>,
    },
    #[cfg(feature = "pending-birth-owner-signing")]
    RequestBornManualEnrollment {
        request: Box<wholepact_signer_origin::manual::HostManualEnrollmentRequest>,
    },
    #[cfg(feature = "pending-birth-owner-signing")]
    RequestBornManualEnrollmentIntent {
        request: Box<wholepact_signer_origin::manual::HostManualEnrollmentIntent>,
    },
    #[cfg(feature = "authority-signing")]
    RequestOwnerInspection { request: Box<wholepact_core::owner_inspection::OwnerInspectionRequest> },
    Status {},
    #[cfg(feature = "authority-signing")]
    RequestAutomaticAuthorization {
        request: Box<crate::authority_bridge::automation_ipc::AutomaticRequest>,
    },
    #[cfg(feature = "authority-signing")]
    RequestProvedDisclosure {
        request: Box<crate::authority_bridge::proved_disclosure_ipc::ProvedDisclosureRequest>,
    },
    #[cfg(feature = "authority-signing")]
    RequestNamedVerifierPolicyV1 {
        request: Box<wholepact_signer_origin::named_verifier_policy::NamedVerifierPolicyRequestV1>,
    },
    #[cfg(feature = "authority-signing")]
    RequestPreconstruction {
        request: Box<crate::authority_bridge::preconstruction_ipc::PreconstructionRequest>,
    },
    #[cfg(feature = "durable-proposal")]
    RequestDurableConstructionV1 {
        request: Box<crate::authority_bridge::durable_construction_v1::DurableConstructionRequestV1>,
    },
    #[cfg(feature = "durable-proposal")]
    RequestDurableConstructionHistoryV1 {
        request: Box<crate::authority_bridge::durable_construction_v1::DurableConstructionHistoryRequestV1>,
    },
    #[cfg(feature = "durable-proposal")]
    RequestDurableConstructionRedisclosureV1 {
        request: Box<crate::authority_bridge::durable_construction_v1::DurableConstructionRedisclosureRequestV1>,
    },
    #[cfg(feature = "durable-proposal")]
    RequestDurableDeliveryV2 { request: Box<crate::authority_bridge::durable_delivery_admission_ipc_v2::DurableDeliveryCommandV2> },
    #[cfg(feature = "durable-proposal")]
    RequestDurableProposalReviewV1 {
        request: Box<crate::authority_bridge::durable_review_ipc_v1::DurableReviewDeliveryRequestV1>,
    },
    #[cfg(all(feature="authority-signing",feature="offline-review-foundation"))]
    RequestBornOriginalHistoryV1 {request:Box<crate::authority_bridge::born_history_ipc::BornOriginalHistoryRequestV1>},
    #[cfg(all(feature="authority-signing",feature="offline-review-foundation"))]
    RequestBornDispatchV1 {request:Box<crate::authority_bridge::born_dispatch_ipc::BornDispatchRequestV1>},
    #[cfg(feature = "authority-signing")]
    RequestDispatch {
        request: Box<crate::authority_bridge::dispatch_ipc::DispatchRequest>,
    },
    #[cfg(feature = "authority-signing")]
    RequestSettlement {
        request: Box<crate::authority_bridge::settlement_ipc::SettlementRequest>,
    },
    #[cfg(feature = "authority-signing")]
    RequestHostRecoveryContinuity {
        request: Box<crate::authority_bridge::host_recovery_ipc::HostRecoveryContinuityRequest>,
    },
    #[cfg(feature = "authority-signing")]
    RequestHostRecoveryContinuityV2 {
        request:
            Box<crate::authority_bridge::host_recovery_ipc::v2::HostRecoveryContinuityRequestV2>,
    },
    #[cfg(feature = "authority-signing")]
    RequestHostRecoveryContinuityV3 {
        request:
            Box<crate::authority_bridge::host_recovery_ipc::v3::HostRecoveryContinuityRequestV3>,
    },
    #[cfg(feature = "authority-signing")]
    RequestHostRecoveryContinuityV5 {
        request:
            Box<crate::authority_bridge::host_recovery_ipc::v5::HostRecoveryContinuityRequestV5>,
        // Transport selection is separate from the immutable V5 request DTO.
        // Only an omitted field defaults to the legacy single-frame dialect.
        #[serde(default)]
        transfer_dialect: V5TransferDialect,
    },
    #[cfg(feature = "authority-signing")]
    RequestHostRecoveryPublication {
        request: Box<crate::authority_bridge::host_publication_ipc::HostRecoveryPublicationRequest>,
    },
    #[cfg(feature = "authority-signing")]
    RequestHostRecoveryPublicationV2 {
        request: Box<
            crate::authority_bridge::host_publication_ipc::v2::HostRecoveryPublicationRequestV2,
        >,
    },
    #[cfg(feature = "authority-signing")]
    RequestHostRecoveryPublicationV3 {
        request: Box<
            crate::authority_bridge::host_publication_ipc::v3::HostRecoveryPublicationRequestV3,
        >,
    },
    #[cfg(feature = "authority-signing")]
    RequestHostRecoveryPublicationV5 {
        request: Box<
            crate::authority_bridge::host_publication_ipc::v5::HostRecoveryPublicationRequestV5,
        >,
        // Transport selection is separate from the immutable V5 request DTO.
        // Only an omitted field defaults to the legacy single-frame dialect.
        #[serde(default)]
        transfer_dialect: V5TransferDialect,
    },
    RequestResultRedelivery {
        request: crate::consent_journal::ResultRedeliveryRequest,
    },
    RetrieveRedeliveredAuthorization {
        history: crate::authority_bridge::ipc::HistoryRequest,
        redelivery: crate::consent_journal::ResultRedeliveryReference,
    },
    AcquireRedeliveredAuthorization {
        history: crate::authority_bridge::ipc::HistoryRequest,
        redelivery: crate::consent_journal::ResultRedeliveryReference,
    },
    RetrieveAuthorization {
        history: crate::authority_bridge::ipc::HistoryRequest,
    },
    AcquireOriginalAuthorization {
        history: crate::authority_bridge::ipc::HistoryRequest,
    },
    RequestReview {
        request_id: String,
        accepted_manifest_digest: String,
        pczt_hex: String,
    },
}
impl AppRequest {
    fn validate(&self, scope: &PairScope) -> Result<()> {
        match self {
            #[cfg(feature = "pending-birth-owner-signing")]
            Self::RequestBornCandidateSelectionV1 { request } => {
                request.validate().map_err(|_| Error::InvalidData)?;
                let t = &request.scope.inventory.enrollment;
                if request
                    .scope
                    .pairing_digest()
                    .map_err(|_| Error::InvalidData)?
                    != scope.manifest_digest
                    || t.identity.account_id != scope.account_id
                    || t.scope.agreement_id != scope.agreement_id
                    || t.scope.participant_id != scope.participant_id
                    || scope.history_read
                    || scope.authorization_export
                    || scope.preconstruction_export
                {
                    return Err(Error::Authentication);
                }
            }
            #[cfg(feature = "pending-birth-owner-signing")]
            Self::RequestBornPreliminaryInventoryV1 { request } => {
                request.validate().map_err(|_| Error::InvalidData)?;
                let t = &request.scope.enrollment;
                if request
                    .scope
                    .pairing_digest()
                    .map_err(|_| Error::InvalidData)?
                    != scope.manifest_digest
                    || t.identity.account_id != scope.account_id
                    || t.scope.agreement_id != scope.agreement_id
                    || t.scope.participant_id != scope.participant_id
                    || scope.history_read
                    || scope.authorization_export
                    || scope.preconstruction_export
                {
                    return Err(Error::Authentication);
                }
            }

            #[cfg(feature = "pending-birth-owner-signing")]
            Self::RequestBornRosterExactInputObservationV1 { request } => {
                request.validate().map_err(|_| Error::InvalidData)?;
                let t = request.plan.enrollment();
                if request.plan.digest().map_err(|_| Error::InvalidData)? != scope.manifest_digest
                    || t.identity.account_id != scope.account_id
                    || t.scope.agreement_id != scope.agreement_id
                    || t.scope.participant_id != scope.participant_id
                    || scope.history_read
                    || scope.authorization_export
                    || scope.preconstruction_export
                {
                    return Err(Error::Authentication);
                }
            }
            #[cfg(feature = "pending-birth-owner-signing")]
            Self::RequestBornRosterCommonContextReadV1 { .. } => {
                if !COMMON_CONTEXT_V3_COMPOSITION_QUALIFIED {
                    return Err(Error::Unavailable);
                }
                common_context_scope_v3::validate_fields(self, scope)?;
            }
            #[cfg(feature = "pending-birth-owner-signing")]
            Self::RequestBornRosterCommonContextReentryV1 { .. } => {
                if !COMMON_CONTEXT_V3_COMPOSITION_QUALIFIED {
                    return Err(Error::Unavailable);
                }
                common_context_scope_v3::validate_fields(self, scope)?;
            }
            #[cfg(feature = "pending-birth-owner-signing")]
            Self::RequestBornRosterReenteredConstructionV1 { .. } => {
                if !COMMON_CONTEXT_V3_COMPOSITION_QUALIFIED {
                    return Err(Error::Unavailable);
                }
                common_context_scope_v3::validate_fields(self, scope)?;
            }
            #[cfg(feature = "pending-birth-owner-signing")]
            Self::RequestBornRosterCommonContextHandoffAuthorizationV1 { .. } => {
                if !COMMON_CONTEXT_V3_COMPOSITION_QUALIFIED {
                    return Err(Error::Unavailable);
                }
                common_context_scope_v3::validate_fields(self, scope)?;
            }
            #[cfg(feature = "pending-birth-owner-signing")]
            Self::RequestBornRosterConstructionV2 { request } => {
                request.validate().map_err(|_| Error::InvalidData)?;
                let t = request.plan.enrollment();
                if request.plan.digest().map_err(|_| Error::InvalidData)? != scope.manifest_digest
                    || t.identity.account_id != scope.account_id
                    || t.scope.agreement_id != scope.agreement_id
                    || t.scope.participant_id != scope.participant_id
                    || scope.history_read
                    || scope.authorization_export
                    || scope.preconstruction_export
                {
                    return Err(Error::Authentication);
                }
            }
            #[cfg(feature = "pending-birth-owner-signing")]
            Self::RequestBornRosterConstructionV3 { .. } => {
                if !COMMON_CONTEXT_V3_COMPOSITION_QUALIFIED {
                    return Err(Error::Unavailable);
                }
                common_context_scope_v3::validate_fields(self, scope)?;
            }
            #[cfg(feature = "pending-birth-owner-signing")]
            Self::RequestBornRosterCandidateSelectionV2 { request } => {
                request.validate().map_err(|_| Error::InvalidData)?;
                let t = &request.scope.selection.inventory.enrollment;
                if request
                    .scope
                    .pairing_digest()
                    .map_err(|_| Error::InvalidData)?
                    != scope.manifest_digest
                    || t.identity.account_id != scope.account_id
                    || t.scope.agreement_id != scope.agreement_id
                    || t.scope.participant_id != scope.participant_id
                    || scope.history_read
                    || scope.authorization_export
                    || scope.preconstruction_export
                {
                    return Err(Error::Authentication);
                }
            }
            #[cfg(feature = "pending-birth-owner-signing")]
            Self::RequestBornRosterInventoryV2 { request } => {
                request.validate().map_err(|_| Error::InvalidData)?;
                let t = &request.scope.inventory.enrollment;
                if request
                    .scope
                    .pairing_digest()
                    .map_err(|_| Error::InvalidData)?
                    != scope.manifest_digest
                    || t.identity.account_id != scope.account_id
                    || t.scope.agreement_id != scope.agreement_id
                    || t.scope.participant_id != scope.participant_id
                    || scope.history_read
                    || scope.authorization_export
                    || scope.preconstruction_export
                {
                    return Err(Error::Authentication);
                }
            }

            #[cfg(feature = "pending-birth-owner-signing")]
            Self::RequestBornPermanentStopV1 { .. } => return Err(Error::Unavailable),
            #[cfg(feature = "pending-birth-owner-signing")]
            Self::RequestBornManualRosterEnrollmentIntentV2 { request } => {
                request.validate().map_err(|_| Error::InvalidData)?;
                if request.digest().map_err(|_| Error::InvalidData)? != scope.manifest_digest
                    || request.account_intent.scope.agreement_id != scope.agreement_id
                    || request.account_intent.scope.participant_id != scope.participant_id
                    || scope.history_read
                    || scope.authorization_export
                    || scope.preconstruction_export
                {
                    return Err(Error::Authentication);
                }
            }
            #[cfg(feature = "pending-birth-owner-signing")]
            Self::RequestBornManualRosterEnrollmentV2 { request } => {
                request.validate().map_err(|_| Error::InvalidData)?;
                let t = &request.enrollment.terms;
                if request.digest().map_err(|_| Error::InvalidData)? != scope.manifest_digest
                    || t.identity.account_id != scope.account_id
                    || t.scope.agreement_id != scope.agreement_id
                    || t.scope.participant_id != scope.participant_id
                    || scope.history_read
                    || scope.authorization_export
                    || scope.preconstruction_export
                {
                    return Err(Error::Authentication);
                }
            }
            #[cfg(feature = "pending-birth-owner-signing")]
            Self::RequestBornManualEnrollmentContinuationV2 { request } => {
                request.validate().map_err(|_| Error::InvalidData)?;
                let t = &request.enrollment.terms;
                if request.digest().map_err(|_| Error::InvalidData)? != scope.manifest_digest
                    || t.identity.account_id != scope.account_id
                    || t.scope.agreement_id != scope.agreement_id
                    || t.scope.participant_id != scope.participant_id
                    || scope.history_read
                    || scope.authorization_export
                    || scope.preconstruction_export
                {
                    return Err(Error::Authentication);
                }
            }
            #[cfg(feature = "pending-birth-owner-signing")]
            Self::RequestBornManualEnrollment { request } => {
                request.validate().map_err(|_| Error::InvalidData)?;
                if request.terms.identity.account_id != scope.account_id
                    || request.terms.scope.agreement_id != scope.agreement_id
                    || request.terms.scope.participant_id != scope.participant_id
                {
                    return Err(Error::Authentication);
                }
            }
            #[cfg(feature = "pending-birth-owner-signing")]
            Self::RequestBornManualEnrollmentIntent { request } => {
                request.validate().map_err(|_| Error::InvalidData)?;
                if request.digest().map_err(|_| Error::InvalidData)? != scope.manifest_digest
                    || request.scope.agreement_id != scope.agreement_id
                    || request.scope.participant_id != scope.participant_id
                {
                    return Err(Error::Authentication);
                }
            }
            #[cfg(feature = "authority-signing")]
            Self::RequestAutomaticAuthorization { request } => {
                request.validate().map_err(|_| Error::InvalidData)?;
                if request.accepted_manifest_digest != scope.manifest_digest {
                    return Err(Error::Authentication);
                }
            }
            #[cfg(feature = "authority-signing")]
            Self::RequestProvedDisclosure { request } => {
                request.validate().map_err(|_| Error::InvalidData)?;
                if request.account_id != scope.account_id
                    || request.participant_id != scope.participant_id
                    || request
                        .validate()
                        .map_err(|_| Error::InvalidData)?
                        .manifest_digest()
                        != scope.manifest_digest
                {
                    return Err(Error::Authentication);
                }
            }
            #[cfg(feature = "authority-signing")]
            Self::RequestOwnerInspection { request } => {
                if !scope.history_read
                    || !request.validate()
                    || request.agreement_id != scope.agreement_id
                    || request.participant_id != scope.participant_id
                    || request.manifest_digest != scope.manifest_digest
                {
                    return Err(Error::Authentication);
                }
            }
            #[cfg(feature = "authority-signing")]
            Self::RequestNamedVerifierPolicyV1 { request } => {
                let proposal = request.validate().map_err(|_| Error::InvalidData)?;
                if scope.account_id != request.scope.account_id
                    || scope.participant_id != request.scope.participant_id
                    || scope.agreement_id != proposal.manifest().agreement.agreement_id
                    || scope.manifest_digest
                        != request
                            .scope
                            .pairing_digest()
                            .map_err(|_| Error::InvalidData)?
                    || scope.history_read
                    || scope.authorization_export
                    || scope.preconstruction_export
                {
                    return Err(Error::Authentication);
                }
            }
            #[cfg(feature = "authority-signing")]
            Self::RequestPreconstruction { request } => {
                if !scope.preconstruction_export {
                    return Err(Error::Authentication);
                }
                request.validate().map_err(|_| Error::InvalidData)?;
            }
            #[cfg(feature = "durable-proposal")]
            Self::RequestDurableConstructionV1 { request } => {
                let proposal = request.validate().map_err(|_| Error::InvalidData)?;
                if !scope.preconstruction_export
                    || request.scope.account_id != scope.account_id
                    || request.scope.participant_id != scope.participant_id
                    || proposal.manifest().agreement.agreement_id != scope.agreement_id
                    || proposal.manifest_digest() != scope.manifest_digest
                {
                    return Err(Error::Authentication);
                }
            }
            #[cfg(feature = "durable-proposal")]
            Self::RequestDurableConstructionHistoryV1 { request } => {
                if !scope.history_read || !scope.preconstruction_export {
                    return Err(Error::Authentication);
                }
                request.validate().map_err(|_| Error::InvalidData)?;
            }
            #[cfg(feature = "durable-proposal")]
            Self::RequestDurableConstructionRedisclosureV1 { request } => {
                if !scope.history_read || !scope.preconstruction_export {
                    return Err(Error::Authentication);
                }
                request.validate().map_err(|_| Error::InvalidData)?;
            }
            #[cfg(feature = "durable-proposal")]
            Self::RequestDurableDeliveryV2 { request } => {
                if !scope.history_read || (matches!(request.as_ref(), crate::authority_bridge::durable_delivery_admission_ipc_v2::DurableDeliveryCommandV2::Admit { .. }) && !scope.preconstruction_export) {
                    return Err(Error::Authentication);
                }
                request.validate().map_err(|_| Error::InvalidData)?;
            }
            #[cfg(feature = "durable-proposal")]
            Self::RequestDurableProposalReviewV1 { request } => {
                if !scope.history_read || !scope.preconstruction_export {
                    return Err(Error::Authentication);
                }
                request.validate().map_err(|_| Error::InvalidData)?;
            }
            #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
            Self::RequestBornOriginalHistoryV1 { request } => {
                if !scope.history_read || scope.authorization_export || scope.preconstruction_export
                {
                    return Err(Error::Authentication);
                }
                request.validate().map_err(|_| Error::InvalidData)?;
            }
            #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
            Self::RequestBornDispatchV1 { request } => {
                if !scope.history_read || scope.authorization_export || scope.preconstruction_export
                {
                    return Err(Error::Authentication);
                }
                request.validate().map_err(|_| Error::InvalidData)?;
            }
            #[cfg(feature = "authority-signing")]
            Self::RequestDispatch { request } => {
                if !scope.history_read || !scope.authorization_export {
                    return Err(Error::Authentication);
                }
                request.validate().map_err(|_| Error::InvalidData)?;
            }
            #[cfg(feature = "authority-signing")]
            Self::RequestSettlement { request } => {
                if !scope.history_read || !scope.authorization_export {
                    return Err(Error::Authentication);
                }
                request.validate().map_err(|_| Error::InvalidData)?;
            }
            #[cfg(feature = "authority-signing")]
            Self::RequestHostRecoveryContinuity { request } => {
                request.validate().map_err(|_| Error::InvalidData)?;
                if !scope.history_read
                    || !scope.authorization_export
                    || request.account_id != scope.account_id
                {
                    return Err(Error::Authentication);
                }
            }
            #[cfg(feature = "authority-signing")]
            Self::RequestHostRecoveryContinuityV2 { request } => {
                request.validate().map_err(|_| Error::InvalidData)?;
                if !scope.history_read
                    || !scope.authorization_export
                    || request.account_id != scope.account_id
                    || request.inventory_digest != scope.manifest_digest
                {
                    return Err(Error::Authentication);
                }
                crate::authority_bridge::host_recovery_ipc::v2::require_complete_origin_endpoint()
                    .map_err(|_| Error::Unavailable)?;
            }
            #[cfg(feature = "authority-signing")]
            Self::RequestHostRecoveryContinuityV3 { request } => {
                request.validate().map_err(|_| Error::InvalidData)?;
                if !scope.history_read
                    || !scope.authorization_export
                    || request.account_id != scope.account_id
                    || request.inventory_digest != scope.manifest_digest
                {
                    return Err(Error::Authentication);
                }
                crate::authority_bridge::host_recovery_ipc::v3::require_complete_origin_endpoint()
                    .map_err(|_| Error::Unavailable)?;
            }
            #[cfg(feature = "authority-signing")]
            Self::RequestHostRecoveryContinuityV5 { request, .. } => {
                request.validate().map_err(|_| Error::InvalidData)?;
                if !scope.history_read
                    || !scope.authorization_export
                    || request.account_id != scope.account_id
                    || request.inventory_digest != scope.manifest_digest
                {
                    return Err(Error::Authentication);
                }
                crate::authority_bridge::host_recovery_ipc::v5::require_construction_transport_recovery_endpoint()
                    .map_err(|_| Error::Unavailable)?;
            }
            #[cfg(feature = "authority-signing")]
            Self::RequestHostRecoveryPublication { request } => {
                request.validate().map_err(|_| Error::InvalidData)?;
                if !scope.history_read
                    || !scope.authorization_export
                    || request.continuity.account_id != scope.account_id
                {
                    return Err(Error::Authentication);
                }
            }
            #[cfg(feature = "authority-signing")]
            Self::RequestHostRecoveryPublicationV2 { request } => {
                request.validate().map_err(|_| Error::InvalidData)?;
                if !scope.history_read
                    || !scope.authorization_export
                    || request.continuity.account_id != scope.account_id
                    || request.continuity.inventory_digest != scope.manifest_digest
                {
                    return Err(Error::Authentication);
                }
                crate::authority_bridge::host_recovery_ipc::v2::require_complete_origin_endpoint()
                    .map_err(|_| Error::Unavailable)?;
            }
            #[cfg(feature = "authority-signing")]
            Self::RequestHostRecoveryPublicationV3 { request } => {
                request.validate().map_err(|_| Error::InvalidData)?;
                if !scope.history_read
                    || !scope.authorization_export
                    || request.continuity.account_id != scope.account_id
                    || request.continuity.inventory_digest != scope.manifest_digest
                {
                    return Err(Error::Authentication);
                }
                crate::authority_bridge::host_recovery_ipc::v3::require_complete_origin_endpoint()
                    .map_err(|_| Error::Unavailable)?;
            }
            #[cfg(feature = "authority-signing")]
            Self::RequestHostRecoveryPublicationV5 { request, .. } => {
                request.validate().map_err(|_| Error::InvalidData)?;
                if !scope.history_read
                    || !scope.authorization_export
                    || request.continuity.account_id != scope.account_id
                    || request.continuity.inventory_digest != scope.manifest_digest
                {
                    return Err(Error::Authentication);
                }
                crate::authority_bridge::host_recovery_ipc::v5::require_construction_transport_recovery_endpoint()
                    .map_err(|_| Error::Unavailable)?;
            }
            Self::RequestResultRedelivery { request } => {
                if !scope.history_read || !scope.authorization_export {
                    return Err(Error::Authentication);
                }
                request.validate().map_err(|_| Error::InvalidData)?;
            }
            Self::RetrieveRedeliveredAuthorization {
                history,
                redelivery,
            }
            | Self::AcquireRedeliveredAuthorization {
                history,
                redelivery,
            } => {
                if !scope.history_read || !scope.authorization_export {
                    return Err(Error::Authentication);
                }
                history.validate().map_err(|_| Error::InvalidData)?;
                redelivery.validate().map_err(|_| Error::InvalidData)?;
            }
            _ => {}
        }
        if let Self::RetrieveAuthorization { history } = self {
            if !scope.authorization_export {
                return Err(Error::Authentication);
            }
            history.validate().map_err(|_| Error::InvalidData)?;
        }
        if let Self::AcquireOriginalAuthorization { history } = self {
            if !scope.history_read {
                return Err(Error::Authentication);
            }
            history.validate().map_err(|_| Error::InvalidData)?;
        }
        if let Self::RequestReview {
            request_id,
            accepted_manifest_digest,
            pczt_hex,
        } = self
        {
            validate_label(request_id)?;
            if *accepted_manifest_digest != scope.manifest_digest
                || pczt_hex.len() > 2_097_152
                || pczt_hex.is_empty()
                || pczt_hex.len() % 2 != 0
                || !pczt_hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(Error::InvalidData);
            }
        }
        Ok(())
    }
}
impl Drop for AppRequest {
    fn drop(&mut self) {
        if let Self::RequestReview { pczt_hex, .. } = self {
            pczt_hex.zeroize();
        }
    }
}

struct Grant {
    #[cfg(feature = "native-ui")]
    native_origin: crate::native_ui::NativeAuthorityBinding,
    peer: PeerProcess,
    scope: PairScope,
    label: String,
    token_digest: [u8; 32],
    channel_digest: String,
    generation: u64,
    expires: Instant,
    current: Arc<AtomicBool>,
}
impl Drop for Grant {
    fn drop(&mut self) {
        self.current.store(false, Ordering::Release);
    }
}
#[derive(Clone)]
pub(crate) struct AuthenticatedPeer {
    #[cfg(feature = "native-ui")]
    pub(crate) native_origin: crate::native_ui::NativeAuthorityBinding,
    pub(crate) grant_id: String,
    pub(crate) scope: PairScope,
    pub(crate) label: String,
    pub(crate) peer: PeerProcess,
    pub(crate) key_digest: String,
    pub(crate) channel_digest: String,
    pub(crate) generation: u64,
    expires: Instant,
    current: Arc<AtomicBool>,
}
impl AuthenticatedPeer {
    /// Same concrete grant, not a matching client-provided identity claim.
    #[cfg(all(feature = "native-ui", feature = "authority-signing"))]
    pub(crate) fn require_same_grant(&self, other: &Self) -> Result<()> {
        self.check_current()?;
        other.check_current()?;
        self.peer.same_live_process(&other.peer)?;
        if !Arc::ptr_eq(&self.current, &other.current)
            || self.native_origin != other.native_origin
            || self.grant_id != other.grant_id
            || self.scope != other.scope
            || self.label != other.label
            || self.peer.instance() != other.peer.instance()
            || self.key_digest != other.key_digest
            || self.channel_digest != other.channel_digest
            || self.generation != other.generation
            || self.expires != other.expires
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }

    #[cfg(feature = "authority-signing")]
    pub(crate) fn deadline(&self) -> Instant {
        self.expires
    }
    #[cfg(feature = "pending-birth-owner-signing")]
    pub(crate) fn retire_now(&self) {
        self.current.store(false, Ordering::Release);
    }

    #[cfg(all(test, feature = "native-ui"))]
    pub(crate) fn shorten_expiry_for_test(&mut self, duration: Duration) {
        self.expires = self.expires.min(Instant::now() + duration);
    }

    pub(crate) fn check_current(&self) -> Result<()> {
        #[cfg(feature = "native-ui")]
        self.native_origin.check_current()?;
        if !self.current.load(Ordering::Acquire) || Instant::now() >= self.expires {
            return Err(Error::Authentication);
        }
        self.peer.check_alive().map_err(Into::into)
    }
}
pub(crate) struct PendingPairing {
    peer: PeerProcess,
    pub(crate) label: String,
    pub(crate) scope: PairScope,
    stream: UnixStream,
    created: Instant,
}
impl PendingPairing {
    #[cfg(feature = "pending-birth-owner-signing")]
    pub(crate) fn same_live_peer(&self, peer: &AuthenticatedPeer) -> Result<()> {
        self.check_current()?;
        self.peer.same_live_process(&peer.peer)?;
        Ok(())
    }

    #[cfg(feature = "pending-birth-owner-signing")]
    pub(crate) fn same_live_process(&self, peer: &PeerProcess) -> Result<()> {
        self.check_current()?;
        self.peer.same_live_process(peer)?;
        Ok(())
    }

    pub(crate) fn uid(&self) -> u32 {
        self.peer.uid()
    }
    pub(crate) fn pid(&self) -> u32 {
        self.peer.pid()
    }
    pub(crate) fn instance(&self) -> &str {
        self.peer.instance()
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        if self.created.elapsed() >= Duration::from_secs(120) {
            return Err(Error::ReviewMismatch);
        }
        self.peer.check_alive().map_err(Into::into)
    }
    pub(crate) fn review_digest(&self, generation: u64) -> Result<String> {
        self.check_current()?;
        let bytes = serde_json::to_vec(&self.scope).map_err(|_| Error::InvalidData)?;
        let mut h = Sha256::new();
        h.update(b"wholepact:local-process-pairing:v1\0");
        h.update(self.peer.instance().as_bytes());
        h.update(generation.to_le_bytes());
        h.update(bytes);
        Ok(hex::encode(h.finalize()))
    }
}
pub(crate) enum LocalEvent {
    #[cfg(feature = "pending-birth-owner-signing")]
    BornPermanentStopV1(Box<permanent_stop::AuthenticatedPermanentStopRequestV1>),
    #[cfg(feature = "pending-birth-owner-signing")]
    BornManualRosterEnrollmentV2 {
        peer: AuthenticatedPeer, stream: UnixStream,
        request: Box<wholepact_signer_origin::manual_roster_v2::HostManualRosterPublicationRequestV2>,
    },

    #[cfg(feature = "pending-birth-owner-signing")]
    BornCandidateSelectionV1 {peer:AuthenticatedPeer,stream:UnixStream,request:Box<wholepact_core::manual_candidate_selection::ManualCandidateSelectionRequest>},
    #[cfg(feature = "pending-birth-owner-signing")]
    BornPreliminaryInventoryV1 {peer:AuthenticatedPeer,stream:UnixStream,request:Box<wholepact_core::manual_inventory::ManualPreliminaryInventoryRequest>},

    #[cfg(feature = "pending-birth-owner-signing")]
    BornRosterExactInputObservationV1 {peer:AuthenticatedPeer,stream:UnixStream,request:Box<wholepact_core::manual_roster_exact_input_observation_v1::ManualRosterExactInputObservationRequestV1>},
    #[cfg(feature = "pending-birth-owner-signing")]
    BornRosterCommonContextReadV1 {peer:AuthenticatedPeer,stream:UnixStream,request:Box<wholepact_core::manual_roster_construction_v3::RosterCommonContextReadRequestV1>},
    #[cfg(feature = "pending-birth-owner-signing")]
    BornRosterCommonContextHandoffAuthorizationV1 {peer:AuthenticatedPeer,stream:UnixStream,request:Box<wholepact_signer_origin::common_context_handoff_v1::RosterCommonContextHandoffAuthorizationRequestV1>},
    #[cfg(feature = "pending-birth-owner-signing")]
    BornRosterCommonContextReentryV1 {peer:AuthenticatedPeer,stream:UnixStream,request:Box<wholepact_core::common_context_reentry_v1::RosterCommonContextReentryRequestV1>,pending_grant_json:String},
    #[cfg(feature = "pending-birth-owner-signing")]
    BornRosterReenteredConstructionV1 {peer:AuthenticatedPeer,stream:UnixStream,request:Box<wholepact_core::manual_roster_construction_v3::ManualRosterConstructionRequestV3>,reentry_lineage_digest:String},
    #[cfg(feature = "pending-birth-owner-signing")]
    BornRosterConstructionV2 {peer:AuthenticatedPeer,stream:UnixStream,request:Box<wholepact_core::manual_roster_construction_v2::ManualRosterConstructionRequestV2>},
    #[cfg(feature = "pending-birth-owner-signing")]
    BornRosterConstructionV3 {peer:AuthenticatedPeer,stream:UnixStream,request:Box<wholepact_core::manual_roster_construction_v3::ManualRosterConstructionRequestV3>},
    #[cfg(feature = "pending-birth-owner-signing")]
    BornRosterCandidateSelectionV2 {peer:AuthenticatedPeer,stream:UnixStream,request:Box<wholepact_core::manual_roster_candidate_selection_v2::ManualRosterCandidateSelectionRequestV2>},
    #[cfg(feature = "pending-birth-owner-signing")]
    BornRosterInventoryV2 {peer:AuthenticatedPeer,stream:UnixStream,request:Box<wholepact_core::manual_roster_inventory_v2::ManualRosterInventoryRequestV2>},

    #[cfg(feature = "pending-birth-owner-signing")]
    BornManualEnrollmentContinuationV2 {
        peer:AuthenticatedPeer,
        stream:UnixStream,
        request:Box<wholepact_signer_origin::manual_continuation_v2::HostManualEnrollmentContinuationRequestV2>,
    },
    #[cfg(feature = "pending-birth-owner-signing")]
    BornManualEnrollment {
        peer: AuthenticatedPeer,
        stream: UnixStream,
        request: Box<wholepact_signer_origin::manual::HostManualEnrollmentRequest>,
    },
    #[cfg(feature = "authority-signing")]
    AutomaticAuthorization {
        peer: AuthenticatedPeer,
        stream: UnixStream,
        request: Box<crate::authority_bridge::automation_ipc::AutomaticRequest>,
    },
    #[cfg(feature = "authority-signing")]
    ProvedDisclosure {
        peer: AuthenticatedPeer,
        stream: UnixStream,
        request: Box<crate::authority_bridge::proved_disclosure_ipc::ProvedDisclosureRequest>,
    },
    #[cfg(feature = "authority-signing")]
    OwnerInspection { peer: AuthenticatedPeer, stream: UnixStream, request: Box<wholepact_core::owner_inspection::OwnerInspectionRequest> },
    NamedVerifierPolicy {
        peer: AuthenticatedPeer,
        stream: UnixStream,
        request: Box<wholepact_signer_origin::named_verifier_policy::NamedVerifierPolicyRequestV1>,
    },
    #[cfg(feature = "authority-signing")]
    Preconstruction {
        peer: AuthenticatedPeer,
        stream: UnixStream,
        request: Box<crate::authority_bridge::preconstruction_ipc::PreconstructionRequest>,
    },
    #[cfg(feature = "durable-proposal")]
    DurableConstructionV1 {
        peer: AuthenticatedPeer,
        stream: UnixStream,
        request: Box<crate::authority_bridge::durable_construction_v1::DurableConstructionRequestV1>,
    },
    #[cfg(feature = "durable-proposal")]
    DurableConstructionHistoryV1 {
        peer: AuthenticatedPeer,
        stream: UnixStream,
        request: Box<crate::authority_bridge::durable_construction_v1::DurableConstructionHistoryRequestV1>,
    },
    #[cfg(feature = "durable-proposal")]
    DurableConstructionRedisclosureV1 {
        peer: AuthenticatedPeer,
        stream: UnixStream,
        request: Box<crate::authority_bridge::durable_construction_v1::DurableConstructionRedisclosureRequestV1>,
    },
    #[cfg(feature = "durable-proposal")]
    DurableDeliveryV2 { peer: AuthenticatedPeer, stream: UnixStream, request: Box<crate::authority_bridge::durable_delivery_admission_ipc_v2::DurableDeliveryCommandV2> },
    #[cfg(feature = "durable-proposal")]
    DurableProposalReviewV1 {
        peer: AuthenticatedPeer,
        stream: UnixStream,
        request: Box<crate::authority_bridge::durable_review_ipc_v1::DurableReviewDeliveryRequestV1>,
    },
    #[cfg(all(feature="authority-signing",feature="offline-review-foundation"))]
    BornOriginalHistoryV1{peer:AuthenticatedPeer,stream:UnixStream,request:Box<crate::authority_bridge::born_history_ipc::BornOriginalHistoryRequestV1>},
    #[cfg(all(feature="authority-signing",feature="offline-review-foundation"))]
    BornDispatchV1{peer:AuthenticatedPeer,stream:UnixStream,request:Box<crate::authority_bridge::born_dispatch_ipc::BornDispatchRequestV1>},
    #[cfg(feature = "authority-signing")]
    Dispatch {
        peer: AuthenticatedPeer,
        stream: UnixStream,
        request: Box<crate::authority_bridge::dispatch_ipc::DispatchRequest>,
    },
    #[cfg(feature = "authority-signing")]
    Settlement {
        peer: AuthenticatedPeer,
        stream: UnixStream,
        request: Box<crate::authority_bridge::settlement_ipc::SettlementRequest>,
    },
    #[cfg(feature = "authority-signing")]
    HostRecoveryContinuity {
        peer: AuthenticatedPeer,
        stream: UnixStream,
        request: Box<crate::authority_bridge::host_recovery_ipc::HostRecoveryContinuityRequest>,
    },
    #[cfg(feature = "authority-signing")]
    HostRecoveryContinuityV2 {
        peer: AuthenticatedPeer,
        stream: UnixStream,
        request:
            Box<crate::authority_bridge::host_recovery_ipc::v2::HostRecoveryContinuityRequestV2>,
    },
    #[cfg(feature = "authority-signing")]
    HostRecoveryContinuityV3 {
        peer: AuthenticatedPeer,
        stream: UnixStream,
        request:
            Box<crate::authority_bridge::host_recovery_ipc::v3::HostRecoveryContinuityRequestV3>,
    },
    #[cfg(feature = "authority-signing")]
    HostRecoveryContinuityV5 {
        peer: AuthenticatedPeer,
        stream: UnixStream,
        request:
            Box<crate::authority_bridge::host_recovery_ipc::v5::HostRecoveryContinuityRequestV5>,
        transfer_dialect: V5TransferDialect,
    },
    #[cfg(feature = "authority-signing")]
    HostRecoveryPublication {
        peer: AuthenticatedPeer,
        stream: UnixStream,
        request: Box<crate::authority_bridge::host_publication_ipc::HostRecoveryPublicationRequest>,
    },
    #[cfg(feature = "authority-signing")]
    HostRecoveryPublicationV2 {
        peer: AuthenticatedPeer,
        stream: UnixStream,
        request: Box<
            crate::authority_bridge::host_publication_ipc::v2::HostRecoveryPublicationRequestV2,
        >,
    },
    #[cfg(feature = "authority-signing")]
    HostRecoveryPublicationV3 {
        peer: AuthenticatedPeer,
        stream: UnixStream,
        request: Box<
            crate::authority_bridge::host_publication_ipc::v3::HostRecoveryPublicationRequestV3,
        >,
    },
    #[cfg(feature = "authority-signing")]
    HostRecoveryPublicationV5 {
        peer: AuthenticatedPeer,
        stream: UnixStream,
        request: Box<
            crate::authority_bridge::host_publication_ipc::v5::HostRecoveryPublicationRequestV5,
        >,
        transfer_dialect: V5TransferDialect,
    },
    Redelivery {
        peer: AuthenticatedPeer,
        stream: UnixStream,
        request: crate::consent_journal::ResultRedeliveryRequest,
    },
    Redelivered {
        peer: AuthenticatedPeer,
        stream: UnixStream,
        history: crate::authority_bridge::ipc::HistoryRequest,
        redelivery: crate::consent_journal::ResultRedeliveryReference,
        history_only: bool,
    },
    Export {
        peer: AuthenticatedPeer,
        stream: UnixStream,
        history: crate::authority_bridge::ipc::HistoryRequest,
    },
    Pairing(PendingPairing),
    History {
        peer: AuthenticatedPeer,
        stream: UnixStream,
        history: crate::authority_bridge::ipc::HistoryRequest,
    },
    Request {
        peer: AuthenticatedPeer,
        request: AppRequest,
    },
}

/// No public registration/approval API. The daemon only accepts request data and
/// forwards bounded events to the owning native window. Tokens never use argv,
/// files, URLs, stdout, clipboard, browser storage, or persistent config.
#[derive(Clone)]
pub(crate) struct IpcRevocation {
    grants: Arc<Mutex<BTreeMap<String, Grant>>>,
    admission_closed: Arc<AtomicBool>,
}
impl IpcRevocation {
    /// Restricted informational UI calls this after immediate native revocation.
    /// Actual peer checks also retain that native binding; failed try_lock cannot
    /// leave a usable grant. Cleanup drains outside the GUI thread.
    #[cfg(feature = "authority-signing")]
    pub(crate) fn close_informational_now(&self) {
        self.admission_closed.store(true, Ordering::Release);
        if let Ok(mut grants) = self.grants.try_lock() {
            grants.clear();
        }
    }
    /// Used only after the pending native owner has atomically revoked its
    /// binding. A pairing worker may be draining a bounded socket write while
    /// holding the grant map; the GUI must never wait for that lock.
    #[cfg(feature = "pending-birth-owner-signing")]
    pub(crate) fn close_pending_now(&self) {
        self.admission_closed.store(true, Ordering::Release);
        if let Ok(mut grants) = self.grants.try_lock() {
            grants.clear();
        }
    }
    /// Active named-recipient Lock calls this only after atomically revoking
    /// the actual native owner. Existing peer checks retain that same owner;
    /// a contended grant map is drained by OpenAccount::close off the GUI.
    #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
    pub(crate) fn close_named_recipient_now(&self) {
        self.admission_closed.store(true, Ordering::Release);
        if let Ok(mut grants) = self.grants.try_lock() {
            grants.clear();
        }
    }
    pub(crate) fn close(&self) {
        self.admission_closed.store(true, Ordering::Release);
        if let Ok(mut grants) = self.grants.lock() {
            grants.clear();
        }
    }
}
/// Dispatcher restriction, never account or native authority. The ordinary
/// listener keeps its original behavior; the private informational listener
/// rejects every other operation before authentication or event delivery.
#[derive(Clone)]
enum IpcMode {
    Ordinary,
    #[cfg(all(
        feature = "pending-birth-owner-signing",
        feature = "offline-review-foundation"
    ))]
    BornNamedVerifierV1 {
        exact: PairScope,
    },
    #[cfg(feature = "pending-birth-owner-signing")]
    PermanentStopV1 {
        account_id: String,
    },
    #[cfg(feature = "authority-signing")]
    QuarantinedV5 {
        account_id: String,
    },
}
impl IpcMode {
    /// Actual post-token-authentication validation seam. This private dispatcher
    /// keeps generic validation denied, while validating the exact DTO and grant
    /// scope for the separately selected restricted informational listener.
    /// Passing this check issues neither an authenticated peer nor native consent.
    fn validate_authenticated_request(
        &self,
        request: &AppRequest,
        scope: &PairScope,
    ) -> Result<()> {
        match self {
            Self::Ordinary => request.validate(scope),
            #[cfg(all(
                feature = "pending-birth-owner-signing",
                feature = "offline-review-foundation"
            ))]
            Self::BornNamedVerifierV1 { .. } => {
                if !self.permits_scope(scope) || !self.permits_request(request) {
                    return Err(Error::Authentication);
                }
                request.validate(scope)
            }
            #[cfg(feature = "pending-birth-owner-signing")]
            Self::PermanentStopV1 { .. } => {
                if !self.permits_scope(scope) || !self.permits_request(request) {
                    return Err(Error::Authentication);
                }
                match request {
                    AppRequest::Status {} => Ok(()),
                    AppRequest::RequestBornPermanentStopV1 { request } => request
                        .require_scope(scope)
                        .map_err(|_| Error::Authentication),
                    _ => Err(Error::Authentication),
                }
            }
            #[cfg(feature = "authority-signing")]
            Self::QuarantinedV5 { .. } => {
                if !self.permits_scope(scope) || !self.permits_request(request) {
                    return Err(Error::Authentication);
                }
                scope.validate()?;
                let continuity = match request {
                    AppRequest::RequestHostRecoveryContinuityV5 { request, .. } => {
                        request.validate().map_err(|_| Error::InvalidData)?;
                        request.as_ref()
                    }
                    AppRequest::RequestHostRecoveryPublicationV5 { request, .. } => {
                        request.validate().map_err(|_| Error::InvalidData)?;
                        &request.continuity
                    }
                    _ => return Err(Error::Authentication),
                };
                if continuity.account_id != scope.account_id
                    || continuity.inventory_digest != scope.manifest_digest
                {
                    return Err(Error::Authentication);
                }
                crate::authority_bridge::host_recovery_ipc::v5::require_quarantined_informational_endpoint()
                    .map_err(|_| Error::Unavailable)
            }
        }
    }
    fn permits_scope(&self, scope: &PairScope) -> bool {
        match self {
            Self::Ordinary => true,
            #[cfg(all(
                feature = "pending-birth-owner-signing",
                feature = "offline-review-foundation"
            ))]
            Self::BornNamedVerifierV1 { exact } => scope == exact,
            #[cfg(feature = "pending-birth-owner-signing")]
            Self::PermanentStopV1 { account_id } => {
                scope.account_id == *account_id
                    && !scope.history_read
                    && !scope.authorization_export
                    && !scope.preconstruction_export
            }
            #[cfg(feature = "authority-signing")]
            Self::QuarantinedV5 { account_id } => {
                scope.account_id == *account_id
                    && scope.history_read
                    && scope.authorization_export
                    && !scope.preconstruction_export
            }
        }
    }
    fn permits_request(&self, request: &AppRequest) -> bool {
        match self {
            Self::Ordinary => true,
            #[cfg(all(
                feature = "pending-birth-owner-signing",
                feature = "offline-review-foundation"
            ))]
            Self::BornNamedVerifierV1 { .. } => matches!(
                request,
                AppRequest::Status {} | AppRequest::RequestNamedVerifierPolicyV1 { .. }
            ),
            #[cfg(feature = "pending-birth-owner-signing")]
            Self::PermanentStopV1 { account_id } => match request {
                AppRequest::Status {} => true,
                AppRequest::RequestBornPermanentStopV1 { request } => {
                    request.original.enrollment.terms.identity.account_id == *account_id
                }
                _ => false,
            },
            #[cfg(feature = "authority-signing")]
            Self::QuarantinedV5 { account_id } => match request {
                AppRequest::RequestHostRecoveryContinuityV5 {
                    request,
                    transfer_dialect,
                } => {
                    request.account_id == *account_id
                        && *transfer_dialect == V5TransferDialect::BoundedV1
                }
                AppRequest::RequestHostRecoveryPublicationV5 {
                    request,
                    transfer_dialect,
                } => {
                    request.continuity.account_id == *account_id
                        && *transfer_dialect == V5TransferDialect::BoundedV1
                }
                _ => false,
            },
        }
    }
}
/// Finite exact-path preflight only; this neither binds nor authenticates an
/// endpoint. UnixListener::bind subsequently fails atomically if an entry races
/// into this cooperative private runtime directory. No unlink fallback exists.
#[cfg(all(feature = "native-ui", feature = "authority-signing"))]
fn quarantined_reentry_socket_path(
    root: &std::path::Path,
    exact: &std::path::Path,
) -> Result<PathBuf> {
    if !root.is_absolute() || fs::canonicalize(root)? != root || exact.parent() != Some(root) {
        return Err(Error::InvalidData);
    }
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || exact.file_name().and_then(|name| name.to_str())
            != Some(QUARANTINED_INFORMATIONAL_SOCKET_BASENAME)
    {
        return Err(Error::InvalidData);
    }
    match fs::symlink_metadata(exact) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(exact.into()),
        _ => Err(Error::InvalidData),
    }
}

pub struct LocalIpc {
    _directory: PrivateDirectory,
    path: PathBuf,
    grants: Arc<Mutex<BTreeMap<String, Grant>>>,
    stop: Arc<AtomicBool>,
    events: Receiver<LocalEvent>,
    worker: Option<JoinHandle<()>>,
    generation: u64,
    admission_closed: Arc<AtomicBool>,
    mode: IpcMode,
    #[cfg(feature = "synthetic-born-joined-qualification")]
    scoped_born_qualification_v3: scoped_born_qualification_v3::ScopedBornQualificationV3,
}
impl LocalIpc {
    #[cfg(all(
        feature = "pending-birth-owner-signing",
        feature = "offline-review-foundation"
    ))]
    pub(crate) fn bind_born_named_verifier_v1(
        directory: PrivateDirectory,
        exact: PairScope,
    ) -> Result<Self> {
        exact.validate()?;
        if exact.history_read || exact.authorization_export || exact.preconstruction_export {
            return Err(Error::Authentication);
        }
        // A restriction-only listener, never a native/account/pairing issuer.
        Self::bind_mode(directory, IpcMode::BornNamedVerifierV1 { exact })
    }
    #[cfg(feature = "pending-birth-owner-signing")]
    pub(crate) fn bind_permanent_stop_v1(
        directory: PrivateDirectory,
        account_id: String,
    ) -> Result<Self> {
        wholepact_signer_origin::permanent_stop_v1::require_activation_v1()
            .map_err(|_| Error::Unavailable)?;
        Self::bind_mode(directory, IpcMode::PermanentStopV1 { account_id })
    }
    pub fn bind(directory: PrivateDirectory) -> Result<Self> {
        Self::bind_mode(directory, IpcMode::Ordinary)
    }
    #[cfg(all(feature = "native-ui", feature = "authority-signing"))]
    pub(crate) fn bind_quarantined_v5(
        directory: PrivateDirectory,
        source: &crate::account::informational::QuarantinedInformationalAccount,
    ) -> Result<Self> {
        // Only the separately qualified informational route selects this mode.
        // No generic listener is substituted if its scope is refused.
        crate::authority_bridge::host_recovery_ipc::v5::require_quarantined_informational_endpoint(
        )
        .map_err(|_| Error::Unavailable)?;
        source.check_source_unchanged_until(source.deadline())?;
        let path = directory
            .root()
            .join(QUARANTINED_INFORMATIONAL_SOCKET_BASENAME);
        let path = quarantined_reentry_socket_path(directory.root(), &path)?;
        Self::bind_mode_path(
            directory,
            IpcMode::QuarantinedV5 {
                account_id: source.account_id().into(),
            },
            path,
        )
    }
    /// Reentry only: the prior exact endpoint is inert location metadata. Its
    /// absent path is required; no existing entry is removed or reused. Actual
    /// native pairing and kernel/server authentication are still mandatory.
    #[cfg(all(feature = "native-ui", feature = "authority-signing"))]
    pub(crate) fn bind_quarantined_v5_at(
        directory: PrivateDirectory,
        source: &crate::account::informational::QuarantinedInformationalAccount,
        exact_socket_path: &std::path::Path,
    ) -> Result<Self> {
        crate::authority_bridge::host_recovery_ipc::v5::require_quarantined_informational_endpoint(
        )
        .map_err(|_| Error::Unavailable)?;
        source.check_source_unchanged_until(source.deadline())?;
        let path = quarantined_reentry_socket_path(directory.root(), exact_socket_path)?;
        Self::bind_mode_path(
            directory,
            IpcMode::QuarantinedV5 {
                account_id: source.account_id().into(),
            },
            path,
        )
    }
    fn bind_mode(directory: PrivateDirectory, mode: IpcMode) -> Result<Self> {
        let path = directory.root().join(format!(
            "requests-{}.sock",
            hex::encode(crate::vault::random::<12>()?)
        ));
        Self::bind_mode_path(directory, mode, path)
    }
    fn bind_mode_path(directory: PrivateDirectory, mode: IpcMode, path: PathBuf) -> Result<Self> {
        let listener = UnixListener::bind(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        enable_credentials(listener.as_raw_fd())?;
        let grants = Arc::new(Mutex::new(BTreeMap::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (sender, events) = mpsc::sync_channel(MAX_EVENTS);
        let admission_closed = Arc::new(AtomicBool::new(false));
        let admission = admission_closed.clone();
        let g = grants.clone();
        let s = stop.clone();
        let worker_mode = mode.clone();
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let scoped_born_qualification_v3 =
            scoped_born_qualification_v3::ScopedBornQualificationV3::default();
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let worker_scoped_v3 = scoped_born_qualification_v3.clone();
        let worker = std::thread::spawn(move || {
            serve(
                listener,
                g,
                s,
                sender,
                admission,
                worker_mode,
                #[cfg(feature = "synthetic-born-joined-qualification")]
                worker_scoped_v3,
            )
        });
        Ok(Self {
            _directory: directory,
            path,
            grants,
            stop,
            events,
            worker: Some(worker),
            generation: 1,
            admission_closed,
            mode,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            scoped_born_qualification_v3,
        })
    }
    pub(crate) fn revocation(&self) -> IpcRevocation {
        IpcRevocation {
            grants: self.grants.clone(),
            admission_closed: self.admission_closed.clone(),
        }
    }
    pub fn socket_path(&self) -> &std::path::Path {
        &self.path
    }
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
    pub(crate) fn next_event(&self) -> Option<LocalEvent> {
        self.events.try_recv().ok()
    }
    pub(crate) fn revoke(&self, id: &str) {
        if let Ok(mut grants) = self.grants.lock() {
            grants.remove(id);
        }
    }
    pub(crate) fn revoke_all(&mut self) {
        if let Ok(mut grants) = self.grants.lock() {
            grants.clear();
        }
        self.generation = self.generation.saturating_add(1);
        while self.events.try_recv().is_ok() {}
    }
    #[cfg(feature = "native-ui")]
    pub(crate) fn approve_pairing(
        &self,
        mut pending: PendingPairing,
        decision: crate::native_ui::NativeDecision,
        authority: &crate::native_ui::NativeAuthority,
    ) -> Result<()> {
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let _scoped_admission = self.scoped_born_qualification_v3.begin_admission()?;
        if !self.mode.permits_scope(&pending.scope)
            || decision.binding() != &authority.binding()
            || decision.reviewed_digest() != pending.review_digest(self.generation)?
        {
            return Err(Error::Authentication);
        }
        authority.binding().check_current()?;
        pending.check_current()?;
        #[cfg(feature = "synthetic-born-joined-qualification")]
        self.scoped_born_qualification_v3
            .require_pairing_owner(&pending.scope, &authority.binding())?;
        let mut grants = self.grants.lock().map_err(|_| Error::Locked)?;
        grants.retain(|_, g| g.peer.check_alive().is_ok() && Instant::now() < g.expires);
        if grants.len() >= MAX_GRANTS {
            return Err(Error::InvalidData);
        }
        let (id, secret, grant) = issue_pairing_grant(&pending, authority, self.generation, None)?;
        // Insert before delivery. A failed/uncertain delivery immediately revokes;
        // an app must prove token possession in a separate authenticated request.
        grants.insert(id.clone(), grant);
        let token = Zeroizing::new(hex::encode(secret.as_slice()));
        let response = Zeroizing::new(serde_json::json!({"schema_version":1,"accepted":true,"reason_code":"LOCAL_PROCESS_REQUEST_SCOPE","grant_id":id,"token_hex":token.as_str(),"expires_in_seconds":900}).to_string());
        if pending
            .stream
            .write_all(response.as_bytes())
            .and_then(|_| pending.stream.write_all(b"\n"))
            .and_then(|_| pending.stream.flush())
            .is_err()
        {
            grants.remove(&id);
            return Err(Error::Authentication);
        }
        Ok(())
    }
}
/// Private concrete issuer shared by the existing ordinary pairing and the
/// restricted endpoint. Callers retain their exact native-decision checks and
/// registry policy; this helper cannot accept a caller-selected peer or scope.
#[cfg(feature = "native-ui")]
fn issue_pairing_grant(
    pending: &PendingPairing,
    authority: &crate::native_ui::NativeAuthority,
    generation: u64,
    ceiling: Option<Instant>,
) -> Result<(String, Zeroizing<[u8; 32]>, Grant)> {
    let secret = Zeroizing::new(crate::vault::random::<32>()?);
    let id = hex::encode(crate::vault::random::<32>()?);
    let channel_digest = pending.review_digest(generation)?;
    let grant = Grant {
        native_origin: authority.binding(),
        peer: pending.peer.clone(),
        scope: pending.scope.clone(),
        label: pending.label.clone(),
        token_digest: Sha256::digest(secret.as_slice()).into(),
        channel_digest,
        generation,
        expires: {
            let ordinary_expiry = Instant::now() + LEASE;
            ceiling.map_or(ordinary_expiry, |limit| limit.min(ordinary_expiry))
        },
        current: Arc::new(AtomicBool::new(true)),
    };
    Ok((id, secret, grant))
}

impl Drop for LocalIpc {
    fn drop(&mut self) {
        self.revoke_all();
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        let _ = fs::remove_file(&self.path);
    }
}
fn serve(
    listener: UnixListener,
    grants: Arc<Mutex<BTreeMap<String, Grant>>>,
    stop: Arc<AtomicBool>,
    sender: SyncSender<LocalEvent>,
    admission_closed: Arc<AtomicBool>,
    mode: IpcMode,
    #[cfg(feature = "synthetic-born-joined-qualification")]
    scoped_v3: scoped_born_qualification_v3::ScopedBornQualificationV3,
) {
    while !stop.load(Ordering::Acquire) {
        if let Ok(mut g) = grants.lock() {
            g.retain(|_, g| g.peer.check_alive().is_ok() && Instant::now() < g.expires);
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                let result = (|| -> Result<()> {
                    if admission_closed.load(Ordering::Acquire) {
                        return Err(Error::Locked);
                    }
                    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
                    let peer = PeerProcess::observe(&stream)?;
                    let frame = match &mode {
                        #[cfg(feature = "pending-birth-owner-signing")]
                        IpcMode::PermanentStopV1 { .. } => {
                            wholepact_signer_origin::framing::read_frame_capped_until(
                                &stream,
                                &peer,
                                wholepact_signer_origin::permanent_stop_v1::MAX_FRAME_BYTES,
                                Instant::now() + Duration::from_secs(2),
                            )
                            .map_err(Error::from)?
                        }
                        _ => read_frame(&stream, &peer)?,
                    };
                    let mut envelope: Envelope =
                        serde_json::from_slice(&frame).map_err(|_| Error::InvalidData)?;
                    // Attachment, approval and event admission share one bounded
                    // linearization point. Socket reading never holds this lock.
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    let _scoped_admission = scoped_v3.begin_admission()?;
                    match &mut envelope {
                        Envelope::RequestPairing {
                            schema_version,
                            application_label,
                            scope,
                        } => {
                            if *schema_version != 1 {
                                return Err(Error::InvalidData);
                            }
                            validate_label(application_label)?;
                            scope.validate()?;
                            if !mode.permits_scope(scope) {
                                return Err(Error::Authentication);
                            }
                            #[cfg(feature = "synthetic-born-joined-qualification")]
                            scoped_v3.require_pairing_scope(scope)?;
                            peer.check_alive()?;
                            sender
                                .try_send(LocalEvent::Pairing(PendingPairing {
                                    peer,
                                    label: application_label.clone(),
                                    scope: scope.clone(),
                                    stream: stream.try_clone()?,
                                    created: Instant::now(),
                                }))
                                .map_err(|_| Error::Unavailable)?;
                        }
                        Envelope::Request {
                            schema_version,
                            grant_id,
                            token_hex,
                            request,
                        } => {
                            if *schema_version != 1 {
                                return Err(Error::InvalidData);
                            }
                            if !mode.permits_request(request) {
                                return Err(Error::Authentication);
                            }
                            #[cfg(feature = "synthetic-born-joined-qualification")]
                            let peer = scoped_v3
                                .authenticate(&grants, peer, grant_id, token_hex, request, &mode)?;
                            #[cfg(not(feature = "synthetic-born-joined-qualification"))]
                            let peer =
                                authenticate(&grants, peer, grant_id, token_hex, request, &mode)?;
                            let request = std::mem::replace(request, AppRequest::Status {});
                            match request {
                                #[cfg(feature = "pending-birth-owner-signing")]
                                AppRequest::RequestBornCandidateSelectionV1 { ref request } => {
                                    sender
                                        .try_send(LocalEvent::BornCandidateSelectionV1 {
                                            peer,
                                            stream: stream.try_clone()?,
                                            request: request.clone(),
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }
                                #[cfg(feature = "pending-birth-owner-signing")]
                                AppRequest::RequestBornPreliminaryInventoryV1 { ref request } => {
                                    sender
                                        .try_send(LocalEvent::BornPreliminaryInventoryV1 {
                                            peer,
                                            stream: stream.try_clone()?,
                                            request: request.clone(),
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }

                                #[cfg(feature = "pending-birth-owner-signing")]
                                AppRequest::RequestBornRosterExactInputObservationV1 {
                                    ref request,
                                } => {
                                    sender
                                        .try_send(LocalEvent::BornRosterExactInputObservationV1 {
                                            peer,
                                            stream: stream.try_clone()?,
                                            request: request.clone(),
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }
                                #[cfg(feature = "pending-birth-owner-signing")]
                                AppRequest::RequestBornRosterCommonContextReadV1 {
                                    ref request,
                                } => {
                                    sender
                                        .try_send(LocalEvent::BornRosterCommonContextReadV1 {
                                            peer,
                                            stream: stream.try_clone()?,
                                            request: request.clone(),
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }
                                #[cfg(feature = "pending-birth-owner-signing")]
                                AppRequest::RequestBornRosterCommonContextReentryV1 {ref request,ref pending_grant_json}=>{
                                    sender.try_send(LocalEvent::BornRosterCommonContextReentryV1{peer,stream:stream.try_clone()?,request:request.clone(),pending_grant_json:pending_grant_json.clone()}).map_err(|_|Error::Unavailable)?;
                                }
                                #[cfg(feature = "pending-birth-owner-signing")]
                                AppRequest::RequestBornRosterReenteredConstructionV1 {ref request,ref reentry_lineage_digest}=>{
                                    sender.try_send(LocalEvent::BornRosterReenteredConstructionV1{peer,stream:stream.try_clone()?,request:request.clone(),reentry_lineage_digest:reentry_lineage_digest.clone()}).map_err(|_|Error::Unavailable)?;
                                }
                                #[cfg(feature = "pending-birth-owner-signing")]
                                AppRequest::RequestBornRosterCommonContextHandoffAuthorizationV1 { ref request } => {
                                    sender.try_send(LocalEvent::BornRosterCommonContextHandoffAuthorizationV1 { peer, stream:stream.try_clone()?, request:request.clone() }).map_err(|_|Error::Unavailable)?;
                                }
                                #[cfg(feature = "pending-birth-owner-signing")]
                                AppRequest::RequestBornRosterConstructionV2 { ref request } => {
                                    sender
                                        .try_send(LocalEvent::BornRosterConstructionV2 {
                                            peer,
                                            stream: stream.try_clone()?,
                                            request: request.clone(),
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }
                                #[cfg(feature = "pending-birth-owner-signing")]
                                AppRequest::RequestBornRosterConstructionV3 { ref request } => {
                                    sender
                                        .try_send(LocalEvent::BornRosterConstructionV3 {
                                            peer,
                                            stream: stream.try_clone()?,
                                            request: request.clone(),
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }
                                #[cfg(feature = "pending-birth-owner-signing")]
                                AppRequest::RequestBornRosterCandidateSelectionV2 {
                                    ref request,
                                } => {
                                    sender
                                        .try_send(LocalEvent::BornRosterCandidateSelectionV2 {
                                            peer,
                                            stream: stream.try_clone()?,
                                            request: request.clone(),
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }
                                #[cfg(feature = "pending-birth-owner-signing")]
                                AppRequest::RequestBornRosterInventoryV2 { ref request } => {
                                    sender
                                        .try_send(LocalEvent::BornRosterInventoryV2 {
                                            peer,
                                            stream: stream.try_clone()?,
                                            request: request.clone(),
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }

                                #[cfg(feature = "pending-birth-owner-signing")]
                                AppRequest::RequestBornPermanentStopV1 { ref request } => {
                                    let admitted = permanent_stop::AuthenticatedPermanentStopRequestV1::admitted(stream.try_clone()?, peer, *request.clone())?;
                                    sender.try_send(LocalEvent::BornPermanentStopV1(Box::new(admitted))).map_err(|_| Error::Unavailable)?;
                                }
                                #[cfg(feature = "pending-birth-owner-signing")]
                                AppRequest::RequestBornManualRosterEnrollmentV2 { ref request } => {
                                    sender
                                        .try_send(LocalEvent::BornManualRosterEnrollmentV2 {
                                            peer,
                                            stream: stream.try_clone()?,
                                            request: request.clone(),
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }
                                #[cfg(feature = "pending-birth-owner-signing")]
                                AppRequest::RequestBornManualEnrollmentContinuationV2 {
                                    ref request,
                                } => {
                                    sender
                                        .try_send(LocalEvent::BornManualEnrollmentContinuationV2 {
                                            peer,
                                            stream: stream.try_clone()?,
                                            request: request.clone(),
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }
                                #[cfg(feature = "pending-birth-owner-signing")]
                                AppRequest::RequestBornManualEnrollment { ref request } => {
                                    sender
                                        .try_send(LocalEvent::BornManualEnrollment {
                                            peer,
                                            stream: stream.try_clone()?,
                                            request: request.clone(),
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }
                                #[cfg(feature = "authority-signing")]
                                AppRequest::RequestAutomaticAuthorization { ref request } => {
                                    sender
                                        .try_send(LocalEvent::AutomaticAuthorization {
                                            peer,
                                            stream: stream.try_clone()?,
                                            request: request.clone(),
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }
                                #[cfg(feature = "authority-signing")]
                                AppRequest::RequestProvedDisclosure { ref request } => {
                                    sender
                                        .try_send(LocalEvent::ProvedDisclosure {
                                            peer,
                                            stream: stream.try_clone()?,
                                            request: request.clone(),
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }
                                #[cfg(feature = "authority-signing")]
                                AppRequest::RequestOwnerInspection { ref request } => {
                                    sender.try_send(LocalEvent::OwnerInspection { peer, stream:stream.try_clone()?, request:request.clone() }).map_err(|_| Error::Unavailable)?;
}
                                #[cfg(feature = "authority-signing")]
                                AppRequest::RequestNamedVerifierPolicyV1 { ref request } => {
                                    sender
                                        .try_send(LocalEvent::NamedVerifierPolicy {
                                            peer,
                                            stream: stream.try_clone()?,
                                            request: request.clone(),
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }
                                #[cfg(feature = "authority-signing")]
                                AppRequest::RequestPreconstruction { ref request } => {
                                    sender
                                        .try_send(LocalEvent::Preconstruction {
                                            peer,
                                            stream: stream.try_clone()?,
                                            request: request.clone(),
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }
                                #[cfg(feature = "durable-proposal")]
                                AppRequest::RequestDurableConstructionV1 { ref request } => {
                                    sender
                                        .try_send(LocalEvent::DurableConstructionV1 {
                                            peer,
                                            stream: stream.try_clone()?,
                                            request: request.clone(),
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }
                                #[cfg(feature = "durable-proposal")]
                                AppRequest::RequestDurableConstructionHistoryV1 { ref request } => {
                                    sender
                                        .try_send(LocalEvent::DurableConstructionHistoryV1 {
                                            peer,
                                            stream: stream.try_clone()?,
                                            request: request.clone(),
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }
                                #[cfg(feature = "durable-proposal")]
                                AppRequest::RequestDurableConstructionRedisclosureV1 { ref request } => {
                                    sender
                                        .try_send(LocalEvent::DurableConstructionRedisclosureV1 {
                                            peer,
                                            stream: stream.try_clone()?,
                                            request: request.clone(),
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }
                                #[cfg(feature = "durable-proposal")]
                                AppRequest::RequestDurableDeliveryV2 { ref request } => {
                                    sender.try_send(LocalEvent::DurableDeliveryV2 { peer, stream: stream.try_clone()?, request:request.clone() }).map_err(|_| Error::Unavailable)?;
                                }
                                #[cfg(feature = "durable-proposal")]
                                AppRequest::RequestDurableProposalReviewV1 { ref request } => {
                                    sender.try_send(LocalEvent::DurableProposalReviewV1 {
                                        peer, stream: stream.try_clone()?, request: request.clone(),
                                    }).map_err(|_| Error::Unavailable)?;
                                }
                                #[cfg(all(feature="authority-signing",feature="offline-review-foundation"))]
                                AppRequest::RequestBornOriginalHistoryV1{ref request}=>{sender.try_send(LocalEvent::BornOriginalHistoryV1{peer,stream:stream.try_clone()?,request:request.clone()}).map_err(|_|Error::Unavailable)?;}
                                #[cfg(all(feature="authority-signing",feature="offline-review-foundation"))]
                                AppRequest::RequestBornDispatchV1{ref request}=>{sender.try_send(LocalEvent::BornDispatchV1{peer,stream:stream.try_clone()?,request:request.clone()}).map_err(|_|Error::Unavailable)?;}
                                #[cfg(feature = "authority-signing")]
                                AppRequest::RequestDispatch { ref request } => {
                                    sender
                                        .try_send(LocalEvent::Dispatch {
                                            peer,
                                            stream: stream.try_clone()?,
                                            request: request.clone(),
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }
                                #[cfg(feature = "authority-signing")]
                                AppRequest::RequestSettlement { ref request } => {
                                    sender
                                        .try_send(LocalEvent::Settlement {
                                            peer,
                                            stream: stream.try_clone()?,
                                            request: request.clone(),
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }
                                #[cfg(feature = "authority-signing")]
                                AppRequest::RequestHostRecoveryContinuity { ref request } => {
                                    sender
                                        .try_send(LocalEvent::HostRecoveryContinuity {
                                            peer,
                                            stream: stream.try_clone()?,
                                            request: request.clone(),
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }
                                #[cfg(feature = "authority-signing")]
                                AppRequest::RequestHostRecoveryContinuityV2 { ref request } => {
                                    crate::authority_bridge::host_recovery_ipc::v2::require_complete_origin_endpoint().map_err(|_| Error::Unavailable)?;
                                    sender
                                        .try_send(LocalEvent::HostRecoveryContinuityV2 {
                                            peer,
                                            stream: stream.try_clone()?,
                                            request: request.clone(),
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }
                                #[cfg(feature = "authority-signing")]
                                AppRequest::RequestHostRecoveryContinuityV3 { ref request } => {
                                    crate::authority_bridge::host_recovery_ipc::v3::require_complete_origin_endpoint().map_err(|_| Error::Unavailable)?;
                                    sender
                                        .try_send(LocalEvent::HostRecoveryContinuityV3 {
                                            peer,
                                            stream: stream.try_clone()?,
                                            request: request.clone(),
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }
                                #[cfg(feature = "authority-signing")]
                                AppRequest::RequestHostRecoveryContinuityV5 {
                                    ref request,
                                    transfer_dialect,
                                } => {
                                    match &mode {
                                        #[cfg(feature = "pending-birth-owner-signing")]
                                        IpcMode::PermanentStopV1 { .. } => return Err(Error::Authentication),
                                        #[cfg(all(feature = "pending-birth-owner-signing", feature = "offline-review-foundation"))]
                                        IpcMode::BornNamedVerifierV1 { .. } => return Err(Error::Authentication),
                                        IpcMode::Ordinary => crate::authority_bridge::host_recovery_ipc::v5::require_construction_transport_recovery_endpoint(),
                                        IpcMode::QuarantinedV5 { .. } => crate::authority_bridge::host_recovery_ipc::v5::require_quarantined_informational_endpoint(),
                                    }.map_err(|_| Error::Unavailable)?;
                                    sender
                                        .try_send(LocalEvent::HostRecoveryContinuityV5 {
                                            peer,
                                            stream: stream.try_clone()?,
                                            request: request.clone(),
                                            transfer_dialect,
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }
                                #[cfg(feature = "authority-signing")]
                                AppRequest::RequestHostRecoveryPublication { ref request } => {
                                    sender
                                        .try_send(LocalEvent::HostRecoveryPublication {
                                            peer,
                                            stream: stream.try_clone()?,
                                            request: request.clone(),
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }
                                #[cfg(feature = "authority-signing")]
                                AppRequest::RequestHostRecoveryPublicationV2 { ref request } => {
                                    crate::authority_bridge::host_recovery_ipc::v2::require_complete_origin_endpoint().map_err(|_| Error::Unavailable)?;
                                    sender
                                        .try_send(LocalEvent::HostRecoveryPublicationV2 {
                                            peer,
                                            stream: stream.try_clone()?,
                                            request: request.clone(),
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }
                                #[cfg(feature = "authority-signing")]
                                AppRequest::RequestHostRecoveryPublicationV3 { ref request } => {
                                    crate::authority_bridge::host_recovery_ipc::v3::require_complete_origin_endpoint().map_err(|_| Error::Unavailable)?;
                                    sender
                                        .try_send(LocalEvent::HostRecoveryPublicationV3 {
                                            peer,
                                            stream: stream.try_clone()?,
                                            request: request.clone(),
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }
                                #[cfg(feature = "authority-signing")]
                                AppRequest::RequestHostRecoveryPublicationV5 {
                                    ref request,
                                    transfer_dialect,
                                } => {
                                    match &mode {
                                        #[cfg(feature = "pending-birth-owner-signing")]
                                        IpcMode::PermanentStopV1 { .. } => return Err(Error::Authentication),
                                        #[cfg(all(feature = "pending-birth-owner-signing", feature = "offline-review-foundation"))]
                                        IpcMode::BornNamedVerifierV1 { .. } => return Err(Error::Authentication),
                                        IpcMode::Ordinary => crate::authority_bridge::host_recovery_ipc::v5::require_construction_transport_recovery_endpoint(),
                                        IpcMode::QuarantinedV5 { .. } => crate::authority_bridge::host_recovery_ipc::v5::require_quarantined_informational_endpoint(),
                                    }.map_err(|_| Error::Unavailable)?;
                                    sender
                                        .try_send(LocalEvent::HostRecoveryPublicationV5 {
                                            peer,
                                            stream: stream.try_clone()?,
                                            request: request.clone(),
                                            transfer_dialect,
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }
                                AppRequest::RequestResultRedelivery { ref request } => {
                                    sender
                                        .try_send(LocalEvent::Redelivery {
                                            peer,
                                            stream: stream.try_clone()?,
                                            request: request.clone(),
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }
                                AppRequest::RetrieveRedeliveredAuthorization {
                                    ref history,
                                    ref redelivery,
                                } => {
                                    sender
                                        .try_send(LocalEvent::Redelivered {
                                            peer,
                                            stream: stream.try_clone()?,
                                            history: history.clone(),
                                            redelivery: redelivery.clone(),
                                            history_only: false,
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }
                                AppRequest::AcquireRedeliveredAuthorization {
                                    ref history,
                                    ref redelivery,
                                } => {
                                    sender
                                        .try_send(LocalEvent::Redelivered {
                                            peer,
                                            stream: stream.try_clone()?,
                                            history: history.clone(),
                                            redelivery: redelivery.clone(),
                                            history_only: true,
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }
                                AppRequest::RetrieveAuthorization { ref history } => {
                                    sender
                                        .try_send(LocalEvent::Export {
                                            peer,
                                            stream: stream.try_clone()?,
                                            history: history.clone(),
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }
                                AppRequest::AcquireOriginalAuthorization { ref history } => {
                                    sender
                                        .try_send(LocalEvent::History {
                                            peer,
                                            stream: stream.try_clone()?,
                                            history: history.clone(),
                                        })
                                        .map_err(|_| Error::Unavailable)?;
                                }
                                request => {
                                    sender
                                        .try_send(LocalEvent::Request { peer, request })
                                        .map_err(|_| Error::Unavailable)?;
                                    stream.write_all(
                                        b"{\"accepted\":true,\"reason_code\":\"REQUEST_ONLY\"}\n",
                                    )?;
                                }
                            }
                        }
                    }
                    Ok(())
                })();
                if result.is_err() {
                    let _ = stream
                        .write_all(b"{\"accepted\":false,\"reason_code\":\"REQUEST_DENIED\"}\n");
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20))
            }
            Err(_) => break,
        }
    }
}
fn authenticate(
    grants: &Mutex<BTreeMap<String, Grant>>,
    observed: PeerProcess,
    id: &str,
    token: &str,
    request: &AppRequest,
    mode: &IpcMode,
) -> Result<AuthenticatedPeer> {
    let peer = authenticate_grant(grants, observed, id, token)?;
    // Generic and quarantined dispatch retain their existing exact validators.
    // The shared concrete verifier does not admit any operation by itself.
    mode.validate_authenticated_request(request, &peer.scope)?;
    peer.check_current()?;
    Ok(peer)
}

/// Concrete original-grant verifier shared only by private IPC admission seams.
/// An observed process or matching scope cannot replace the token, original
/// revocation owner, native owner, generation or original grant expiry.
fn authenticate_grant(
    grants: &Mutex<BTreeMap<String, Grant>>,
    observed: PeerProcess,
    id: &str,
    token: &str,
) -> Result<AuthenticatedPeer> {
    valid_hash(id)?;
    valid_hash(token)?;
    let token = Zeroizing::new(hex::decode(token).map_err(|_| Error::Authentication)?);
    let digest: [u8; 32] = Sha256::digest(token.as_slice()).into();
    let grants = grants.lock().map_err(|_| Error::Authentication)?;
    let grant = grants.get(id).ok_or(Error::Authentication)?;
    grant.peer.same_live_process(&observed)?;
    if Instant::now() >= grant.expires || !bool::from(digest.ct_eq(&grant.token_digest)) {
        return Err(Error::Authentication);
    }
    let peer = AuthenticatedPeer {
        #[cfg(feature = "native-ui")]
        native_origin: grant.native_origin.clone(),
        grant_id: id.into(),
        scope: grant.scope.clone(),
        label: grant.label.clone(),
        peer: grant.peer.clone(),
        key_digest: hex::encode(grant.token_digest),
        channel_digest: grant.channel_digest.clone(),
        generation: grant.generation,
        expires: grant.expires,
        current: grant.current.clone(),
    };
    peer.check_current()?;
    Ok(peer)
}
fn valid_hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Authentication);
    }
    Ok(())
}
pub(crate) fn enable_credentials(fd: std::os::fd::RawFd) -> Result<()> {
    wholepact_signer_origin::framing::enable_credentials(fd).map_err(Into::into)
}
pub(crate) fn read_frame(stream: &UnixStream, peer: &PeerProcess) -> Result<Zeroizing<Vec<u8>>> {
    wholepact_signer_origin::framing::read_frame(stream, peer).map_err(Into::into)
}
pub(crate) fn read_frame_with_deadline(
    stream: &UnixStream,
    peer: &PeerProcess,
    timeout: Duration,
) -> Result<Zeroizing<Vec<u8>>> {
    wholepact_signer_origin::framing::read_frame_with_deadline(stream, peer, timeout)
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
    #[test]
    fn named_close_admission_never_waits_for_contended_grant_map() {
        let revocation = super::IpcRevocation {
            grants: std::sync::Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new())),
            admission_closed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let held = revocation.grants.lock().unwrap();
        let closing = revocation.clone();
        let (send, recv) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            closing.close_named_recipient_now();
            send.send(()).unwrap();
        });
        let immediate = recv.recv_timeout(std::time::Duration::from_secs(2)).is_ok();
        drop(held);
        worker.join().unwrap();
        assert!(immediate);
        assert!(
            revocation
                .admission_closed
                .load(std::sync::atomic::Ordering::Acquire)
        );
        revocation.close();
    }
    use super::*;
    #[test]
    fn request_schema_cannot_express_unlock_approval_or_peer_attestation() {
        for value in [
            r#"{"command":"approve","verified":true}"#,
            r#"{"command":"unlock","password":"synthetic"}"#,
            r#"{"command":"request_pairing","schema_version":1,"application_label":"app","scope":{"account_id":"a","agreement_id":"g","participant_id":"p","manifest_digest":"00"},"pid":42}"#,
        ] {
            assert!(serde_json::from_str::<Envelope>(value).is_err());
        }
        assert!(
            serde_json::from_str::<AppRequest>(r#"{"operation":"status","verified":true}"#)
                .is_err()
        );
    }
    #[cfg(feature = "authority-signing")]
    #[test]
    fn settlement_requests_require_both_current_pair_scopes() {
        let request = AppRequest::RequestSettlement {
            request: Box::new(crate::authority_bridge::settlement_ipc::SettlementRequest {
                history: crate::authority_bridge::ipc::HistoryRequest {
                    authorization_id: "synthetic-authorization".into(),
                    expected_original_consent_ref: "12".repeat(32),
                    expected_enrollment_ref: "34".repeat(32),
                    expected_manifest_ref: "56".repeat(32),
                },
                dispatch_operation_id: "synthetic-dispatch".into(),
                conflict: None,
            }),
        };
        for (history_read, authorization_export) in
            [(false, false), (false, true), (true, false), (true, true)]
        {
            let scope = PairScope {
                account_id: "synthetic-account".into(),
                agreement_id: "synthetic-agreement".into(),
                participant_id: "synthetic-participant".into(),
                manifest_digest: "56".repeat(32),
                history_read,
                authorization_export,
                preconstruction_export: false,
            };
            assert_eq!(
                request.validate(&scope).is_ok(),
                history_read && authorization_export
            );
        }
        let wire = serde_json::json!({"operation":"request_settlement", "request":{
            "history":{"authorization_id":"synthetic-authorization", "expected_original_consent_ref":"12".repeat(32), "expected_enrollment_ref":"34".repeat(32), "expected_manifest_ref":"56".repeat(32)},
            "dispatch_operation_id":"synthetic-dispatch", "verified":true
        }});
        assert!(serde_json::from_value::<AppRequest>(wire).is_err());
    }
    #[test]
    fn requested_review_is_exact_scope_and_bounded() {
        let scope = PairScope {
            account_id: "a".into(),
            agreement_id: "g".into(),
            participant_id: "p".into(),
            manifest_digest: "12".repeat(32),
            history_read: false,
            authorization_export: false,
            preconstruction_export: false,
        };
        scope.validate().unwrap();
        let valid = AppRequest::RequestReview {
            request_id: "r".into(),
            accepted_manifest_digest: scope.manifest_digest.clone(),
            pczt_hex: "ab".into(),
        };
        valid.validate(&scope).unwrap();
        let mismatch = AppRequest::RequestReview {
            request_id: "r".into(),
            accepted_manifest_digest: "34".repeat(32),
            pczt_hex: "ab".into(),
        };
        assert!(mismatch.validate(&scope).is_err());
        let too_big = AppRequest::RequestReview {
            request_id: "r".into(),
            accepted_manifest_digest: scope.manifest_digest.clone(),
            pczt_hex: "ab".repeat(1_048_577),
        };
        assert!(too_big.validate(&scope).is_err());
    }
}

#[cfg(all(test, feature = "authority-signing"))]
mod complete_origin_routing_tests {
    use super::*;
    fn request() -> serde_json::Value {
        let evidence: serde_json::Value = serde_json::from_str(include_str!(
            "authority_bridge/host_recovery_ipc/v2/fixtures/minimal_evidence.json"
        ))
        .unwrap();
        evidence["request"].clone()
    }
    fn scope(request: &serde_json::Value) -> PairScope {
        PairScope {
            account_id: request["account_id"].as_str().unwrap().into(),
            agreement_id: "host-recovery".into(),
            participant_id: "host-recovery".into(),
            manifest_digest: request["inventory_digest"].as_str().unwrap().into(),
            history_read: true,
            authorization_export: true,
            preconstruction_export: false,
        }
    }
    #[test]
    fn complete_origin_route_remains_unavailable_after_exact_validation() {
        let r = request();
        let parsed: AppRequest = serde_json::from_value(serde_json::json!({
            "operation": "request_host_recovery_continuity_v2", "request": r
        }))
        .unwrap();
        assert!(matches!(
            parsed.validate(&scope(&r)),
            Err(Error::Unavailable)
        ));
    }
    #[test]
    fn complete_origin_route_never_downgrades_a_mixed_version() {
        for (operation, version) in [
            ("request_host_recovery_continuity_v2", 1),
            ("request_host_recovery_continuity", 2),
        ] {
            let mut r = request();
            r["schema_version"] = version.into();
            let parsed: AppRequest =
                serde_json::from_value(serde_json::json!({"operation": operation,"request": r}))
                    .unwrap();
            assert!(matches!(
                parsed.validate(&scope(&r)),
                Err(Error::InvalidData)
            ));
        }
        let mut value = serde_json::json!({"operation":"request_host_recovery_continuity_v2","request":request()});
        value["approved"] = true.into();
        assert!(serde_json::from_value::<AppRequest>(value).is_err());
    }
    #[test]
    fn complete_origin_scope_requires_both_permissions_and_exact_account() {
        let r = request();
        let parsed: AppRequest = serde_json::from_value(
            serde_json::json!({"operation":"request_host_recovery_continuity_v2","request":r}),
        )
        .unwrap();
        for mismatch in 0..4 {
            let mut s = scope(&r);
            match mismatch {
                0 => s.history_read = false,
                1 => s.authorization_export = false,
                2 => s.account_id = "other-account".into(),
                _ => s.manifest_digest = "ee".repeat(32),
            }
            assert!(matches!(parsed.validate(&s), Err(Error::Authentication)));
        }
    }

    #[test]
    fn complete_origin_publication_has_distinct_exact_scope_and_disabled_route() {
        let r = request();
        let publication = serde_json::json!({"schema_version":2,"continuity":r,"target_profile":"/synthetic/successor","generation_manifest_digest":"77".repeat(32),"continuity_evidence_digest":"88".repeat(32)});
        let parsed:AppRequest=serde_json::from_value(serde_json::json!({"operation":"request_host_recovery_publication_v2","request":publication})).unwrap();
        assert!(matches!(
            parsed.validate(&scope(&r)),
            Err(Error::Unavailable)
        ));
        let mut wrong = scope(&r);
        wrong.manifest_digest = "99".repeat(32);
        assert!(matches!(
            parsed.validate(&wrong),
            Err(Error::Authentication)
        ));
        let mut mixed = publication;
        mixed["continuity"]["schema_version"] = 1.into();
        let parsed: AppRequest = serde_json::from_value(
            serde_json::json!({"operation":"request_host_recovery_publication_v2","request":mixed}),
        )
        .unwrap();
        assert!(matches!(
            parsed.validate(&scope(&r)),
            Err(Error::InvalidData)
        ));
    }
}

#[cfg(all(test, feature = "authority-signing"))]
mod construction_origin_routing_tests {
    use super::*;
    fn request() -> serde_json::Value {
        let evidence: serde_json::Value = serde_json::from_str(include_str!(
            "authority_bridge/host_recovery_ipc/v3/fixtures/minimal_evidence.json"
        ))
        .unwrap();
        evidence["request"].clone()
    }
    fn scope(request: &serde_json::Value) -> PairScope {
        PairScope {
            account_id: request["account_id"].as_str().unwrap().into(),
            agreement_id: "host-recovery".into(),
            participant_id: "host-recovery".into(),
            manifest_digest: request["inventory_digest"].as_str().unwrap().into(),
            history_read: true,
            authorization_export: true,
            preconstruction_export: false,
        }
    }
    #[test]
    fn complete_origin_route_remains_unavailable_after_exact_validation() {
        let r = request();
        let parsed: AppRequest = serde_json::from_value(serde_json::json!({
            "operation": "request_host_recovery_continuity_v3", "request": r
        }))
        .unwrap();
        assert!(matches!(
            parsed.validate(&scope(&r)),
            Err(Error::Unavailable)
        ));
    }
    #[test]
    fn complete_origin_route_never_downgrades_a_mixed_version() {
        for (operation, version) in [
            ("request_host_recovery_continuity_v3", 1),
            ("request_host_recovery_continuity_v3", 2),
            ("request_host_recovery_continuity_v2", 3),
            ("request_host_recovery_continuity", 3),
        ] {
            let mut r = request();
            r["schema_version"] = version.into();
            let parsed: AppRequest =
                serde_json::from_value(serde_json::json!({"operation": operation,"request": r}))
                    .unwrap();
            assert!(matches!(
                parsed.validate(&scope(&r)),
                Err(Error::InvalidData)
            ));
        }
        let mut value = serde_json::json!({"operation":"request_host_recovery_continuity_v3","request":request()});
        value["approved"] = true.into();
        assert!(serde_json::from_value::<AppRequest>(value).is_err());
    }
    #[test]
    fn complete_origin_scope_requires_both_permissions_and_exact_account() {
        let r = request();
        let parsed: AppRequest = serde_json::from_value(
            serde_json::json!({"operation":"request_host_recovery_continuity_v3","request":r}),
        )
        .unwrap();
        for mismatch in 0..4 {
            let mut s = scope(&r);
            match mismatch {
                0 => s.history_read = false,
                1 => s.authorization_export = false,
                2 => s.account_id = "other-account".into(),
                _ => s.manifest_digest = "ee".repeat(32),
            }
            assert!(matches!(parsed.validate(&s), Err(Error::Authentication)));
        }
    }

    #[test]
    fn complete_origin_publication_has_distinct_exact_scope_and_disabled_route() {
        let r = request();
        let publication = serde_json::json!({"schema_version":3,"continuity":r,"target_profile":"/synthetic/successor","generation_manifest_digest":"77".repeat(32),"continuity_evidence_digest":"88".repeat(32)});
        let parsed:AppRequest=serde_json::from_value(serde_json::json!({"operation":"request_host_recovery_publication_v3","request":publication})).unwrap();
        assert!(matches!(
            parsed.validate(&scope(&r)),
            Err(Error::Unavailable)
        ));
        let mut wrong = scope(&r);
        wrong.manifest_digest = "99".repeat(32);
        assert!(matches!(
            parsed.validate(&wrong),
            Err(Error::Authentication)
        ));
        let mut mixed = publication;
        mixed["continuity"]["schema_version"] = 1.into();
        let parsed: AppRequest = serde_json::from_value(
            serde_json::json!({"operation":"request_host_recovery_publication_v3","request":mixed}),
        )
        .unwrap();
        assert!(matches!(
            parsed.validate(&scope(&r)),
            Err(Error::InvalidData)
        ));
    }
}

/// Deliberately independent of Host recovery V3: common-context composition
/// is unavailable until genuine joined/runtime and persistence closure qualifies.
pub(crate) const COMMON_CONTEXT_V3_COMPOSITION_QUALIFIED: bool = false;
#[cfg(all(test, feature = "authority-signing"))]
mod transport_complete_host_routing_v5_tests {
    use super::*;
    fn continuity() -> serde_json::Value {
        serde_json::json!({
            "schema_version": 5,
            "inventory_digest": "a1".repeat(32),
            "generation_id": "a2".repeat(32),
            "account_id": "synthetic-account",
            "network_profile_id": "synthetic-network",
            "expected_writer_epoch": 1,
            "expected_witness": {
                "endpoint": "127.0.0.1:4444",
                "server_name": "localhost",
                "witness_id": "synthetic-witness",
                "account_id": "synthetic-account",
                "network_profile_id": "synthetic-network",
                "policy_digest": "a3".repeat(32),
                "pinned_server_certificate_digest": "a4".repeat(32)
            }
        })
    }
    fn scope() -> PairScope {
        PairScope {
            account_id: "synthetic-account".into(),
            agreement_id: "host-recovery".into(),
            participant_id: "host-recovery".into(),
            manifest_digest: "a1".repeat(32),
            history_read: true,
            authorization_export: true,
            preconstruction_export: false,
        }
    }
    fn request(publication: bool) -> serde_json::Value {
        if publication {
            serde_json::json!({
                "operation": "request_host_recovery_publication_v5",
                "request": {
                    "schema_version": 5,
                    "continuity": continuity(),
                    "target_profile": "/synthetic/recovered-profile",
                    "generation_manifest_digest": "a5".repeat(32),
                    "continuity_evidence_digest": "a6".repeat(32)
                }
            })
        } else {
            serde_json::json!({
                "operation": "request_host_recovery_continuity_v5",
                "request": continuity()
            })
        }
    }
    fn dialect(request: &AppRequest) -> V5TransferDialect {
        match request {
            AppRequest::RequestHostRecoveryContinuityV5 {
                transfer_dialect, ..
            }
            | AppRequest::RequestHostRecoveryPublicationV5 {
                transfer_dialect, ..
            } => *transfer_dialect,
            _ => panic!("expected a V5 informational request"),
        }
    }
    #[test]
    fn v5_transfer_dialect_defaults_only_when_omitted_and_selects_exact_values() {
        for publication in [false, true] {
            let legacy: AppRequest = serde_json::from_value(request(publication)).unwrap();
            assert_eq!(dialect(&legacy), V5TransferDialect::SingleFrame);
            for (wire, expected) in [
                ("single_frame", V5TransferDialect::SingleFrame),
                ("v5_bounded_transfer_v1", V5TransferDialect::BoundedV1),
            ] {
                let mut value = request(publication);
                value["transfer_dialect"] = wire.into();
                let parsed: AppRequest = serde_json::from_value(value).unwrap();
                assert_eq!(dialect(&parsed), expected);
                assert!(matches!(parsed.validate(&scope()), Err(Error::Unavailable)));
            }
        }
    }
    #[test]
    fn v5_transfer_dialect_rejects_unsupported_values_and_types() {
        for publication in [false, true] {
            for unsupported in [
                serde_json::Value::Null,
                serde_json::json!(false),
                serde_json::json!(1),
                serde_json::json!([]),
                serde_json::json!({"dialect": "v5_bounded_transfer_v1"}),
                serde_json::json!({"single_frame": null}),
                serde_json::json!({"v5_bounded_transfer_v1": null}),
                serde_json::json!(""),
                serde_json::json!("bounded_v1"),
                serde_json::json!("v5_bounded_transfer_v0"),
                serde_json::json!("v5_bounded_transfer_v2"),
                serde_json::json!("V5_BOUNDED_TRANSFER_V1"),
                serde_json::json!("v5_bounded_transfer_v1 "),
                serde_json::json!(" single_frame"),
            ] {
                let mut value = request(publication);
                value["transfer_dialect"] = unsupported;
                assert!(serde_json::from_value::<AppRequest>(value).is_err());
            }
        }
    }
    #[test]
    fn v5_transfer_dialect_is_not_an_evidence_request_field_or_ordinary_option() {
        for publication in [false, true] {
            let mut nested = request(publication);
            nested["request"]["transfer_dialect"] = "v5_bounded_transfer_v1".into();
            assert!(serde_json::from_value::<AppRequest>(nested).is_err());
        }
        assert!(
            serde_json::from_value::<AppRequest>(serde_json::json!({
                "operation": "status",
                "transfer_dialect": "v5_bounded_transfer_v1"
            }))
            .is_err()
        );
        for operation in [
            "request_host_recovery_continuity_v3",
            "request_host_recovery_publication_v3",
        ] {
            let mut value = request(operation.contains("publication"));
            value["operation"] = operation.into();
            value["transfer_dialect"] = "v5_bounded_transfer_v1".into();
            assert!(serde_json::from_value::<AppRequest>(value).is_err());
        }
    }
    #[test]
    fn v5_transfer_dialect_rejects_duplicate_selections() {
        for publication in [false, true] {
            let mut value = serde_json::to_string(&request(publication)).unwrap();
            assert_eq!(value.pop(), Some('}'));
            value.push_str(
                r#","transfer_dialect":"single_frame","transfer_dialect":"v5_bounded_transfer_v1"}"#,
            );
            assert!(serde_json::from_str::<AppRequest>(&value).is_err());
        }
    }
    #[test]
    fn v5_read_and_publication_routes_are_distinct_exact_and_still_denied() {
        for publication in [false, true] {
            let value = request(publication);
            let parsed: AppRequest = serde_json::from_value(value.clone()).unwrap();
            assert!(matches!(parsed.validate(&scope()), Err(Error::Unavailable)));
            for field in 0..4 {
                let mut wrong = scope();
                match field {
                    0 => wrong.history_read = false,
                    1 => wrong.authorization_export = false,
                    2 => wrong.account_id = "other-account".into(),
                    _ => wrong.manifest_digest = "ab".repeat(32),
                }
                assert!(matches!(
                    parsed.validate(&wrong),
                    Err(Error::Authentication)
                ));
            }
            let mut flag = value.clone();
            flag["approved"] = true.into();
            assert!(serde_json::from_value::<AppRequest>(flag).is_err());
            for version in [1, 2, 3, 4, 6] {
                let mut mixed = value.clone();
                mixed["request"]["schema_version"] = version.into();
                let parsed: AppRequest = serde_json::from_value(mixed).unwrap();
                assert!(matches!(parsed.validate(&scope()), Err(Error::InvalidData)));
            }
        }
    }

    mod quarantined_mode_tests {
        include!("ipc/quarantined_mode_tests.rs");
    }
}

#[cfg(all(test, feature = "native-ui", feature = "authority-signing"))]
#[path = "ipc/quarantined_endpoint_tests.rs"]
mod quarantined_endpoint_tests;

#[cfg(all(
    test,
    feature = "authority-signing",
    feature = "offline-review-foundation"
))]
mod born_host_scope_tests {
    use super::*;
    #[test]
    fn born_bridge_narrow_pairing_is_request_transport_not_export_authority() {
        let request = crate::authority_bridge::born_dispatch_ipc::born_synthetic_request();
        let history = request.history();
        let mut scope = PairScope {
            account_id: "synthetic-account".into(),
            agreement_id: "synthetic-agreement".into(),
            participant_id: "synthetic-participant".into(),
            manifest_digest: "42".repeat(32),
            history_read: true,
            authorization_export: false,
            preconstruction_export: false,
        };
        let dispatch = AppRequest::RequestBornDispatchV1 {
            request: Box::new(request),
        };
        let history = AppRequest::RequestBornOriginalHistoryV1 {
            request: Box::new(history),
        };
        assert!(dispatch.validate(&scope).is_ok());
        assert!(history.validate(&scope).is_ok());
        for change in 0..3 {
            scope.history_read = change != 0;
            scope.authorization_export = change == 1;
            scope.preconstruction_export = change == 2;
            assert!(dispatch.validate(&scope).is_err());
            assert!(history.validate(&scope).is_err());
        }
        let mode = IpcMode::QuarantinedV5 {
            account_id: "synthetic-account".into(),
        };
        assert!(
            mode.validate_authenticated_request(&dispatch, &scope)
                .is_err()
        );
    }
}

#[cfg(all(
    test,
    feature = "pending-birth-owner-signing",
    feature = "offline-review-foundation"
))]
#[path = "ipc/born_named_verifier_tests.rs"]
mod born_named_verifier_tests;

#[cfg(all(test, feature = "durable-proposal"))]
mod durable_delivery_scope_tests_v2 {
    use super::*;
    use crate::authority_bridge::durable_delivery_admission_ipc_v2::*;
    #[test]
    fn public_delivery_history_needs_only_history_but_admission_needs_preconstruction() {
        let mut scope = PairScope {
            account_id: "11".repeat(32),
            agreement_id: "synthetic-agreement".into(),
            participant_id: "alice".into(),
            manifest_digest: "22".repeat(32),
            history_read: true,
            authorization_export: false,
            preconstruction_export: false,
        };
        let evidence = AppRequest::RequestDurableDeliveryV2 {
            request: Box::new(DurableDeliveryCommandV2::OriginalWitnessEvidence {}),
        };
        let history = AppRequest::RequestDurableDeliveryV2 {
            request: Box::new(DurableDeliveryCommandV2::History {
                request: DurableDeliveryHistoryRequestV2 {
                    authorization_id: "synthetic-authorization".into(),
                },
            }),
        };
        // Inert request shape only. Actual source derivation validates the full
        // delivery plan and never takes these claims as admission authority.
        let admission: AppRequest = serde_json::from_value(serde_json::json!({
            "operation":"request_durable_delivery_v2", "request": {"purpose":"admit", "request": {
                "version":2,
                "import_request":{"operation_id":"synthetic-import", "enrollment_ref":"33".repeat(32), "accepted_manifest_ref":"44".repeat(32), "own_disclosure":{"operation_id":"synthetic-material", "expected_request_digest":"55".repeat(32)}, "proposal_binding":"66".repeat(32)},
                "delivery": {
                    "dispatcher":{"principal_id":"synthetic-host", "public_identity_commitment":"77".repeat(32), "authentication_profile":"original_protected_host_dispatcher_v2", "custody_policy_commitment":"88".repeat(32)},
                    "original_host_generation_binding_digest":"99".repeat(32), "original_host_profile_id":"synthetic-profile", "submission_journal_identity":"aa".repeat(32), "submission_operation_id":"synthetic-submission",
                    "provider":{"source_id":"synthetic-provider", "endpoint":"https://provider.example", "trust_profile":"single_tls_provider_report_not_consensus"}, "route":{"kind":"direct"}, "owners":[], "valid_from_ms":1000, "valid_until_ms":2000,
                    "minimum_expiry_margin_blocks":1, "maximum_fresh_admission_lifetime_ms":1000, "maximum_explicitly_approved_attempts":1,
                    "extraction_rule":"first_durably_retained_verified_extraction", "retry_rule":"same_retained_bytes_with_fresh_admission", "attempt_rule":"explicit_immediate_host_decision"
                }
            }}
        })).unwrap();
        assert!(evidence.validate(&scope).is_ok());
        assert!(history.validate(&scope).is_ok());
        assert!(admission.validate(&scope).is_err());
        scope.preconstruction_export = true;
        assert!(evidence.validate(&scope).is_ok());
        assert!(history.validate(&scope).is_ok());
        assert!(admission.validate(&scope).is_ok());
        scope.history_read = false;
        assert!(evidence.validate(&scope).is_err());
        assert!(history.validate(&scope).is_err());
        assert!(admission.validate(&scope).is_err());
    }
    #[test]
    fn delivery_commands_reject_financial_actions_unknown_fields_and_duplicate_purpose() {
        for bytes in [
            r#"{"purpose":"acquire"}"#,
            r#"{"purpose":"activate"}"#,
            r#"{"purpose":"reserve"}"#,
            r#"{"purpose":"sign"}"#,
            r#"{"purpose":"extract"}"#,
            r#"{"purpose":"dispatch"}"#,
            r#"{"purpose":"original_witness_evidence","replacement_root":"/tmp/untrusted"}"#,
            r#"{"purpose":"original_witness_evidence","purpose":"original_witness_evidence"}"#,
        ] {
            assert!(
                wholepact_core::parse_typed_json::<DurableDeliveryCommandV2>(bytes.as_bytes())
                    .is_err()
            );
        }
    }
}
