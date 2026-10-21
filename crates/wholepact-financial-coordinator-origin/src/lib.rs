//! Exact whole-image, fixed-fork actor/edge provenance only. This crate neither
//! proves a human click nor issues a financial effect permit. The whole pinned
//! coordinator image, including its private native controller, is trusted.
//! The sole entry belongs at the start of that image's private main, before any
//! thread-capable initialization or role source/key access. It accepts no role,
//! descriptor, claimed identity, callback or caller-provided pin.
#![deny(unsafe_op_in_unsafe_fn)]
#![cfg(target_os = "linux")]
#[cfg(all(wholepact_bootstrap_ci, any(feature = "cancel-only-witness-review", feature = "coordinated-witness-delivery-append")))]
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
mod bootstrap;
mod channel;
mod image;
mod process;
mod delivery_failure;
pub use delivery_failure::{DeliveryFailureV1, DeliveryFailureStageV1, DeliveryFailureClassV1};
#[cfg(wholepact_bootstrap_ci)]
mod ci;
#[cfg(any(feature = "cancel-only-witness-review", feature = "coordinated-witness-delivery-append"))]
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
