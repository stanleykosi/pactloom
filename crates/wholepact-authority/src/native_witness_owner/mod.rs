//! Independent local witness-owner review. Linux Wayland source implementation,
//! under the trusted owner process / OS / compositor assumption. Source review,
//! native consent, existing-key authentication and journal creation are distinct.
//! No signer dependency, no signer-key loader, no socket and no public approval factory.
mod lifecycle;
pub(crate) use lifecycle::{NativePublicationLease, NativeWorkerLease};
#[cfg(feature = "born-offline-witness-owner")]
pub(crate) use window::NativeBornOfflineArtifactsDecisionV1;
pub(crate) use window::{
    NativeBornOfflineEnrollmentDecisionV1, NativeConstructionTransportGrantDecisionV1,
    NativeEnrollmentDecision, NativeManualEnrollmentExtensionDecision,
    NativeManualRosterConstructionDecisionV2, NativeManualRosterConstructionDecisionV3,
    NativeManualRosterContinuationDecisionV2, NativeManualRosterExtensionDecisionV2,
    NativeManualSessionContinuationDecision, NativeNamespaceBackupDecision,
    NativeNamespaceRecoveryDisclosureDecision, NativePermanentExclusionDecisionV1,
    NativeSetupDecision,
};
mod window;
#[cfg(feature = "synthetic-qualification")]
pub(crate) use window::ephemeral_fixture_v1::RetainedConstructionFixtureLivenessV1;
#[cfg(feature = "synthetic-qualification")]
pub use window::ephemeral_fixture_v1::{
    EphemeralConstructionClientScopeV1, EphemeralHistoryServerV1, EphemeralNativeWitnessV1,
    EphemeralRosterAttemptV2, EphemeralWitnessOriginV1,
};

#[cfg(all(
    feature = "synthetic-qualification",
    feature = "born-offline-witness-owner"
))]
pub use window::ephemeral_fixture_v1::{
    EphemeralBornTransportKeyV1, EphemeralBornTransportPublicPinV1,
};

use std::fmt;
use winit::platform::wayland::EventLoopBuilderExtWayland;

#[derive(Debug)]
pub struct WindowError(&'static str);
impl fmt::Display for WindowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for WindowError {}

/// The sole public entry point takes no approval, request, path, owner or callback.
/// All independently selected inputs are entered in the actual native window.
/// Returned success means only that the window closed normally, never a claim
/// that enrollment, archive publication or historical verification completed.
pub fn run() -> Result<(), WindowError> {
    if std::env::args_os().nth(1).is_some() {
        return Err(WindowError(
            "Usage: wholepact-witness-owner-ui. No arguments are accepted.",
        ));
    }
    if [
        "EGUI_INSPECTION",
        "EGUI_INSPECTION_ADDR",
        "EFRAME_SCREENSHOT_TO",
    ]
    .iter()
    .any(|name| std::env::var_os(name).is_some())
    {
        return Err(WindowError(
            "Inspection and injected-input configuration are not accepted.",
        ));
    }
    if std::env::var_os("WAYLAND_DISPLAY").is_none() && std::env::var_os("WAYLAND_SOCKET").is_none()
    {
        return Err(WindowError(
            "This owner window requires Linux Wayland. X11 fallback is disabled.",
        ));
    }
    // Display environment is a connection prerequisite, never proof of human
    // origin, a trustworthy desktop, independent administration or key freshness.
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("Wholepact · Independent witness owner")
            .with_app_id("org.wholepact.WitnessOwner")
            .with_inner_size([1100.0, 820.0])
            .with_min_inner_size([840.0, 620.0])
            .with_drag_and_drop(false),
        renderer: eframe::Renderer::Glow,
        persist_window: false,
        event_loop_builder: Some(Box::new(|builder| {
            builder.with_wayland();
        })),
        ..Default::default()
    };
    eframe::run_native(
        "Wholepact witness owner",
        options,
        Box::new(|cc| {
            window::configure_style(&cc.egui_ctx);
            Ok(Box::new(window::Window::new()))
        }),
    )
    .map_err(|_| WindowError("The native owner window failed. Preserve any output and verify the exact operation before retrying."))
}
