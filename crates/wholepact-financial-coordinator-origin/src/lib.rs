//! Exact whole-image, fixed-fork actor/edge provenance. This crate does not
//! proves a human click. Purpose-specific opaque gates bind actual native admission
//! to exact original role custody; source owners still enforce their effect checks. The whole pinned
//! coordinator image, including its private native controller, is trusted.
//! The sole entry belongs at the start of that image's private main, before any
//! thread-capable initialization or role source/key access. It accepts no role,
//! descriptor, claimed identity, callback or caller-provided pin.
#![deny(unsafe_op_in_unsafe_fn)]
#![cfg(target_os = "linux")]
#[cfg(all(feature = "coordinated-financial-workflow-v1", not(target_arch = "x86_64")))]
compile_error!("The full workflow shared-atomic/PTY profile is selected for Linux x86_64 only");
#[cfg(all(wholepact_bootstrap_ci, any(feature = "cancel-only-witness-review", feature = "coordinated-witness-delivery-append", feature = "coordinated-signer-continue")))]
compile_error!("Bootstrap-only CI instrumentation cannot select the source-opening UI profile");
#[cfg(all(feature = "cancel-only-witness-review", feature = "coordinated-witness-delivery-append"))]
compile_error!("Cancel-only and one-exact-append are separate common-image profiles");

#[cfg(all(wholepact_delivery_ci, not(feature = "coordinated-witness-delivery-append")))]
compile_error!("Delivery evidence requires the exact positive profile");
#[cfg(all(wholepact_delivery_ci, wholepact_bootstrap_ci))]
compile_error!("Delivery and bootstrap evidence are separate images");
#[cfg(wholepact_delivery_ci)]
mod delivery_observer;
#[cfg(wholepact_delivery_ci)]
pub use delivery_observer::{record_delivery_observation_for_ci, finish_delivery_observation_for_ci, DeliveryObservationV1, DeliveryUiPhaseV1, DeliveryWidgetIdV1, DeliveryRectV1, DeliveryWidgetRectV1, DeliveryWidgetSnapshotV1};
#[cfg(all(feature = "coordinated-signer-continue", any(feature = "cancel-only-witness-review", feature = "coordinated-witness-delivery-append")))]
compile_error!("Continue is a separate typechecked-only custody profile, not a conversion from a Witness profile");
#[cfg(all(feature = "coordinated-signer-continue", any(wholepact_bootstrap_ci, wholepact_delivery_ci)))]
compile_error!("The Continue profile has a distinct retained-FD inventory and needs its own reviewed CI gate");
#[cfg(feature = "coordinated-signer-continue")]
mod signer_continue_channel;
#[cfg(feature = "coordinated-signer-continue")]
mod signer_continue_state;
#[cfg(feature = "coordinated-signer-continue")]
mod signer_continue_origin;
#[cfg(feature = "coordinated-signer-continue")]
pub use signer_continue_channel::{SignerContinueRoleV1, SignerContinueSourceFactsV1,
    SignerContinueReviewDataV1, SignerContinuePresentationV1, SignerContinueOutcomeV1};
#[cfg(feature = "coordinated-signer-continue")]
pub use signer_continue_origin::{CoordinatorSignerContinueNativeV1, CoordinatorSignerContinueEndpointV1,
    CoordinatorSignerContinueEventV1, SignerContinueReviewTicketV1, SignerContinueReadyTicketV1,
    SignerContinueArmOutboundV1, SignerContinueFinalOutboundV1, HostSignerFinancialRelayV1,
    SignerFinancialOriginV1, SignerContinueRequestV1, SignerContinueArmV1, SignerContinueFinalV1};
#[cfg(feature = "source-entry-envelope")]
mod source_entry_envelope;
#[cfg(feature = "coordinated-financial-workflow-v1")]
mod financial_workflow_clock;
#[cfg(feature = "coordinated-financial-workflow-v1")]
mod financial_workflow_channel;
#[cfg(feature = "coordinated-financial-workflow-v1")]
mod financial_workflow_source;
#[cfg(feature = "coordinated-financial-workflow-v1")]
mod financial_workflow_origin;
#[cfg(feature = "coordinated-financial-workflow-v1")]
mod financial_workflow_continue;
#[cfg(feature = "coordinated-financial-workflow-v1")]
mod financial_witness_channel;
#[cfg(feature = "coordinated-financial-workflow-v1")]
mod financial_witness_origin;
#[cfg(feature = "coordinated-financial-workflow-v1")]
mod signer_admit_data;
#[cfg(feature = "coordinated-financial-workflow-v1")]
pub use signer_admit_data::{SignerAdmitFactsV1,SignerAdmitPresentationV1,SignerAdmitCommittedV1,SignerAdmitOutcomeV1};
#[cfg(feature = "coordinated-financial-workflow-v1")]
pub use financial_witness_channel::{FinancialWitnessInputsV1,FinancialWitnessContinuationV1,FinancialWitnessPresentationV1,
    FinancialWitnessReadyV1,FinancialWitnessOutcomeV1,FINANCIAL_WITNESS_PURPOSE,FINANCIAL_WITNESS_MODE};
#[cfg(feature = "coordinated-financial-workflow-v1")]
pub use financial_witness_origin::{WitnessFinancialContinuationOriginV1,FinancialWitnessRequestV1,
    WitnessFinancialContinuationSetupV1,WitnessFinancialContinuationArmV1,WitnessFinancialContinuationFinalV1};

#[cfg(feature = "coordinated-financial-workflow-v1")]
mod financial_history_data;
#[cfg(feature = "coordinated-financial-workflow-v1")]
mod financial_history_channel;
#[cfg(feature = "coordinated-financial-workflow-v1")]
mod financial_history_origin;
#[cfg(feature = "coordinated-financial-workflow-v1")]
mod financial_signing_data;
#[cfg(feature = "coordinated-financial-workflow-v1")]
mod financial_signing_channel;
#[cfg(feature = "coordinated-financial-workflow-v1")]
mod financial_signing_origin;
#[cfg(feature = "coordinated-financial-workflow-v1")]
mod signer_writer_read_acquire_data;
#[cfg(feature="coordinated-financial-workflow-v1")]
mod signer_activate_wallet_data;
#[cfg(feature="coordinated-financial-workflow-v1")]
mod completed_pair_data;
#[cfg(feature="coordinated-financial-workflow-v1")]
mod completed_pair_channel;
#[cfg(feature="coordinated-financial-workflow-v1")]
mod completed_pair_origin;
#[cfg(feature="coordinated-financial-workflow-v1")]
pub use completed_pair_data::{CompletedPairInputsV1,CompletedPairOriginalV1,CompletedPairAccountV1,CompletedPairPresentationV1,COMPLETED_PAIR_PURPOSE,COMPLETED_PAIR_MODE};
#[cfg(feature="coordinated-financial-workflow-v1")]
pub use completed_pair_origin::{WitnessCompletedPairOriginV1,WitnessCompletedPairSetupV1,WitnessCompletedPairServeV1,CompletedPairRequestV1};
#[cfg(feature="coordinated-financial-workflow-v1")]
pub use bootstrap::FinancialWitnessPurposeV1;
#[cfg(feature = "coordinated-financial-workflow-v1")]
pub use financial_history_data::{FinancialHistoryInputsV1,FinancialHistoryReadBindingV1,FinancialHistoryPresentationV1,FINANCIAL_HISTORY_PURPOSE,FINANCIAL_HISTORY_MODE};
#[cfg(feature = "coordinated-financial-workflow-v1")]
pub use financial_history_origin::{WitnessFinancialHistoryOriginV1,WitnessFinancialHistorySetupV1,WitnessFinancialHistoryServeV1,FinancialHistoryRequestV1};
#[cfg(feature = "coordinated-financial-workflow-v1")]
pub use financial_signing_data::{FinancialSigningInputsV1,FinancialSigningOriginalV1,FinancialSigningPresentationV1,FinancialSigningServiceV1,FINANCIAL_SIGNING_PURPOSE,FINANCIAL_SIGNING_MODE};
#[cfg(feature = "coordinated-financial-workflow-v1")]
pub use financial_signing_origin::{WitnessFinancialSigningOriginV1,WitnessFinancialSigningSetupV1,WitnessFinancialSigningServeV1,FinancialSigningRequestV1};
#[cfg(feature = "coordinated-financial-workflow-v1")]
pub use financial_workflow_origin::{FinancialHistorySetupTicketV1,FinancialHistorySetupOutboundV1,FinancialHistoryReviewTicketV1,FinancialHistoryServeOutboundV1,FinancialHistoryServingV1,CoordinatorFinancialHistoryEventV1,FinancialSigningSetupTicketV1,FinancialSigningSetupOutboundV1,FinancialSigningReviewTicketV1,FinancialSigningServeOutboundV1,FinancialSigningServingV1,CoordinatorFinancialSigningEventV1};

#[cfg(feature = "coordinated-financial-workflow-v1")]
mod host_restriction;
#[cfg(feature="coordinated-financial-workflow-v1")]
mod host_interstage;
#[cfg(feature="coordinated-financial-workflow-v1")]
pub use host_interstage::{HostFinancialForegroundV1,HostFinancialInterstageWaitV1,HostWitnessRetirementGuardV1,HostCompletedPairServiceV1};
#[cfg(feature = "coordinated-financial-workflow-v1")]
mod host_terminal;
#[cfg(feature = "coordinated-financial-workflow-v1")]
pub use host_restriction::HostOriginalRestrictionV1;
#[cfg(feature = "coordinated-financial-workflow-v1")]
pub use host_terminal::{CoordinatorHostTerminalEndpointV1, HostControllingTerminalV1};
#[cfg(feature = "coordinated-financial-workflow-v1")]
pub use financial_workflow_continue::{SignerContinuationSavedV1, FinancialCancelProgressV1, FinancialContinueReviewTicketV1,
    FinancialContinueReadyTicketV1, FinancialContinueArmOutboundV1, FinancialContinueFinalOutboundV1};
#[cfg(feature = "coordinated-financial-workflow-v1")]
pub use financial_workflow_channel::{FinancialActorContextV1, SignerSourceEntryFactsV1,
    SignerSourceEntryPresentationV1, SignerFinancialReadFactsV1, SignerFinancialReadPresentationV1, FinancialWorkflowStageV1};
#[cfg(feature = "coordinated-financial-workflow-v1")]
pub use financial_workflow_source::{SignerSourceEntryOfferV1, SignerSourceEntryOutboundV1,
    SignerSourceEntryFinalV1, SignerSourceEntryInputV1, SignerOriginalCustodyLifetimeV1, SignerOriginalRestrictionV1,
    SignerFinancialReadTicketV1, SignerFinancialReadOutboundV1, SignerFinancialReadFinalV1};
#[cfg(feature = "coordinated-financial-workflow-v1")]
pub use financial_workflow_origin::{CoordinatorFinancialNativeV1, CoordinatorFinancialEndpointV1,
    CoordinatorFinancialEventV1, HostFinancialWorkflowRelayV1, SignerFinancialWorkflowOriginV1,
    SignerFinancialWorkflowRequestV1,SignerAdmitArmV1,SignerAdmitFinalV1,SignerAdmitReviewTicketV1,SignerAdmitReadyTicketV1,
    SignerAdmitArmOutboundV1,SignerAdmitFinalOutboundV1,
    FinancialWitnessSetupTicketV1,FinancialWitnessSetupOutboundV1,FinancialWitnessReviewTicketV1,
    FinancialWitnessArmOutboundV1,FinancialWitnessArmedV1,FinancialWitnessReadyTicketV1,FinancialWitnessFinalOutboundV1,CoordinatorFinancialWitnessEventV1};
mod bootstrap;
mod channel;
mod image;
#[cfg(feature = "common-image-fork-provider")]
mod fork_signer;
#[cfg(feature = "common-image-fork-provider")]
pub use fork_signer::OriginalForkSignerVerifier;
mod process;
mod delivery_failure;
pub use delivery_failure::{DeliveryFailureV1, DeliveryFailureStageV1, DeliveryFailureClassV1};
#[cfg(wholepact_bootstrap_ci)]
mod ci;
#[cfg(any(feature = "cancel-only-witness-review", feature = "coordinated-witness-delivery-append", feature = "coordinated-signer-continue"))]
mod desktop_launch;
#[cfg(feature = "cancel-only-witness-review")]
mod cancel_review;
#[cfg(feature = "coordinated-witness-delivery-append")]
mod delivery_channel;
#[cfg(feature = "coordinated-witness-delivery-append")]
mod delivery_origin;

pub use bootstrap::{bootstrap_common_image_v1, BootstrappedRoleV1, CoordinatorOriginV1,
    HostOriginV1, SignerOriginV1, InertWitnessOriginV1};
#[cfg(feature = "cancel-only-witness-review")]
pub use bootstrap::{CoordinatorCancelOriginV1, CancelOnlyWitnessOriginV1};
#[cfg(feature = "cancel-only-witness-review")]
pub use cancel_review::{CancelReviewInputsV1, CancelReviewPresentationV1,
    CancelReviewRequestV1, CancelReviewResponseV1};
#[cfg(feature = "coordinated-witness-delivery-append")]
pub use delivery_channel::{DeliveryReviewInputsV1, DeliveryReviewPresentationV1, DeliveryReadyV1, DeliveryOutcomeV1};
#[cfg(feature = "coordinated-witness-delivery-append")]
pub use delivery_origin::{CoordinatorDeliveryNativeV1, CoordinatorDeliveryEndpointV1,
    DeliveryReviewTicketV1, DeliveryReadyTicketV1, DeliveryArmOutboundV1, DeliveryFinalOutboundV1,
    CoordinatorDeliveryEventV1, WitnessDeliveryOriginV1, WitnessDeliveryRequestV1,
    WitnessDeliveryArmV1, WitnessDeliveryFinalAdmitV1};

type Result<T> = std::io::Result<T>;
fn rejected(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, message)
}

// Only the separately compiled bootstrap-CI image has this observation hook.
// It is never an origin, financial capability or production API.
#[cfg(wholepact_bootstrap_ci)]
pub fn record_process_exit_for_ci(code: i32) { ci::finished(code); }

#[cfg(feature="coordinated-financial-workflow-v1")]
pub use financial_workflow_origin::{CoordinatorWitnessRetirementTicketV1,CoordinatorWitnessRetirementOutboundV1,CoordinatorWitnessRetiredV1};

#[cfg(feature="coordinated-financial-workflow-v1")]
pub use financial_workflow_channel::FinancialSendProgressV1;

#[cfg(feature="coordinated-financial-workflow-v1")]
pub use signer_writer_read_acquire_data::{SignerFinancialWriterReadFactsV1,SignerFinancialWriterReadPresentationV1,SignerAcquireFactsV1,SignerAcquirePresentationV1,SignerAcquireOutcomeV1,SignerAcquireCommittedV1};
#[cfg(feature="coordinated-financial-workflow-v1")]
pub use financial_workflow_origin::{SignerFinancialWriterReadTicketV1,SignerFinancialWriterReadOutboundV1,SignerFinancialWriterReadFinalV1,
    SignerAcquireReviewTicketV1,SignerAcquireArmOutboundV1,SignerAcquireArmV1,SignerAcquireReadyTicketV1,SignerAcquireFinalV1,SignerAcquireFinalOutboundV1};

#[cfg(feature="coordinated-financial-workflow-v1")]
pub use signer_activate_wallet_data::{SignerActivateOriginalV1,SignerActivateReadFactsV1,SignerActivateReadPresentationV1,SignerActivateFactsV1,SignerActivatePresentationV1,SignerActivateCommittedV1,SignerActivateOutcomeV1};
#[cfg(feature="coordinated-financial-workflow-v1")]
pub use financial_workflow_origin::{SignerActivateReadTicketV1,SignerActivateReadOutboundV1,SignerActivateReadFinalV1,
    SignerActivateReviewTicketV1,SignerActivateArmOutboundV1,SignerActivateArmV1,SignerActivateReadyTicketV1,SignerActivateFinalV1,SignerActivateFinalOutboundV1};

#[cfg(feature="coordinated-financial-workflow-v1")]
pub use financial_workflow_origin::OriginalSignerHostPeerV1;

#[cfg(feature="coordinated-financial-workflow-v1")]mod signer_v3_source_entry_data;
#[cfg(feature="coordinated-financial-workflow-v1")]mod v3_source_entry_envelope;
#[cfg(feature="coordinated-financial-workflow-v1")]
pub use signer_v3_source_entry_data::{SignerV3SourceOpenedV1,SignerV3SourceEntrySelectionV1,SignerV3SourceEntryFactsV1,SignerV3SourceEntryPresentationV1};
#[cfg(feature="coordinated-financial-workflow-v1")]
pub use financial_workflow_origin::{SignerV3SourceEntryOfferV1,SignerV3SourceEntryOutboundV1,SignerV3SourceEntryFinalV1,SignerV3SourceEntryInputV1,SignerV3SourceLifetimeV1};

#[cfg(feature="coordinated-financial-workflow-v1")]
mod signer_v3_pair_data;
#[cfg(feature="coordinated-financial-workflow-v1")]
pub use signer_v3_pair_data::{SignerV3PairedV1,SignerV3PairEndpointV1,SignerV3PairFactsV1,SignerV3PairPresentationV1};
#[cfg(feature="coordinated-financial-workflow-v1")]
pub use financial_workflow_origin::{SignerV3PairTicketV1,SignerV3PairOutboundV1,SignerV3PairFinalV1,SignerV3PairLifetimeV1};

#[cfg(feature="coordinated-financial-workflow-v1")]mod signer_v3_receipt_data;
#[cfg(feature="coordinated-financial-workflow-v1")]pub use signer_v3_receipt_data::{SignerV3CurrentDisclosureV1,SignerV3EnrollmentFactsV1,SignerV3EnrollmentPresentationV1,SignerV3EnrollmentCommittedV1,SignerV3ManifestFactsV1,SignerV3ManifestPresentationV1,SignerV3ManifestCommittedV1};
#[cfg(feature="coordinated-financial-workflow-v1")]pub use financial_workflow_origin::{SignerV3EnrollmentTicketV1,SignerV3EnrollmentOutboundV1,SignerV3EnrollmentFinalV1,SignerV3ManifestTicketV1,SignerV3ManifestOutboundV1,SignerV3ManifestFinalV1};

#[cfg(feature="coordinated-financial-workflow-v1")]mod signer_v3_redisclosure_data;
#[cfg(feature="coordinated-financial-workflow-v1")]pub use signer_v3_redisclosure_data::{SignerV3RedisclosureReadFactsV1,SignerV3RedisclosureReadPresentationV1,SignerV3RedisclosurePreparedV1,SignerV3RediscloseFactsV1,SignerV3RedisclosePresentationV1,SignerV3RedisclosedV1};
#[cfg(feature="coordinated-financial-workflow-v1")]pub use financial_workflow_origin::{SignerV3RedisclosureReadTicketV1,SignerV3RedisclosureReadOutboundV1,SignerV3RedisclosureReadFinalV1,SignerV3RediscloseTicketV1,SignerV3RediscloseOutboundV1,SignerV3RediscloseFinalV1};

#[cfg(feature="coordinated-financial-workflow-v1")]mod signer_v3_delivery_data;
#[cfg(feature="coordinated-financial-workflow-v1")]pub use signer_v3_delivery_data::{SignerV3OwnerSetupSelectionV1,SignerV3PrepareReadFactsV1,SignerV3PrepareReadPresentationV1,SignerV3PreparedV1,SignerV3ReceiveFactsV1,SignerV3ReceivePresentationV1,SignerV3ReceivedV1};
#[cfg(feature="coordinated-financial-workflow-v1")]pub use financial_workflow_origin::{SignerV3PrepareReadTicketV1,SignerV3PrepareReadOutboundV1,SignerV3PrepareReadFinalV1,SignerV3PreparedLifetimeV1,SignerV3ReceiveTicketV1,SignerV3ReceiveOutboundV1,SignerV3ReceiveFinalV1};
