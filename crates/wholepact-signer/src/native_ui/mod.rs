//! Signer-owned native Wayland account, pairing and exact-consent surface.
//! Source is implemented under a trusted signer/OS/compositor assumption.
//! Synthetic preview remains isolated; live signing and release qualification
//! are separate gates. There is no public event-injection interface.
mod authority;
#[cfg(feature = "authority-signing")]
mod automatic_ipc;
#[cfg(feature = "authority-signing")]
mod automation_workspace;
#[cfg(feature = "authority-signing")]
mod birth_workspace;
#[cfg(feature = "authority-signing")]
mod dispatch;
#[cfg(feature = "authority-signing")]
mod host_publication;
#[cfg(feature = "authority-signing")]
mod host_recovery;
#[cfg(feature = "authority-signing")]
mod informational_witness;
#[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
mod offline_review;
#[cfg(feature = "authority-signing")]
mod preconstruction;
mod provider_export;
#[cfg(all(feature = "synthetic-qualification", feature = "authority-signing"))]
pub mod qualification_fixture;
#[cfg(feature = "authority-signing")]
mod quarantined_history;
#[cfg(feature = "authority-signing")]
mod quarantined_v5;
#[cfg(feature = "authority-signing")]
mod resolution_workspace;
#[cfg(feature = "authority-signing")]
pub(crate) mod retirement_delivery;
#[cfg(feature = "authority-signing")]
mod retirement_destination;
#[cfg(feature = "authority-signing")]
mod retirement_recipient;
#[cfg(feature = "authority-signing")]
mod retirement_review;
#[cfg(feature = "authority-signing")]
mod retirement_session;
#[cfg(feature = "authority-signing")]
mod retirement_session_ui;
#[cfg(feature = "authority-signing")]
mod retirement_source;
#[cfg(feature = "authority-signing")]
mod retirement_witness;
mod runtime;
#[cfg(feature = "authority-signing")]
mod wallet_workspace;
#[cfg(feature = "authority-signing")]
mod witness_workspace;
#[cfg(feature = "pending-birth-owner-signing")]
pub(crate) use authority::DormantNativeLifetime;
#[cfg(feature = "authority-signing")]
pub(crate) use authority::PendingAccountNativeAuthority;
pub(crate) use authority::{NativeAuthority, NativeAuthorityBinding, NativeDecision};
pub(crate) use runtime::AuthenticatedPairing;
mod pairing;
mod state;
mod transaction;
mod window;

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

/// Only launcher API. Approval, secrets, account paths and application grants are
/// deliberately absent from arguments, environment configuration and this API.
pub fn run() -> Result<(), WindowError> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut parent_channel = None;
    let mode = match args.as_slice() {
        [flag] if flag == "--private-parent-channel" => {
            parent_channel = Some(
                crate::native_launch::ParentChannel::take_inherited()
                    .map_err(|_| WindowError("Private native launch channel is unavailable."))?,
            );
            state::SurfaceMode::NativePreview
        }
        [] => state::SurfaceMode::NativePreview,
        [flag] if flag == "--demo" => state::SurfaceMode::SyntheticDemo,
        [flag] if flag == "--capabilities" => {
            println!("{}", capabilities());
            return Ok(());
        }
        _ => {
            return Err(WindowError(
                "Usage: wholepact-signer-ui [--demo | --capabilities]. No approval, key, password, path or IPC token arguments are accepted.",
            ));
        }
    };
    if std::env::var_os("EGUI_INSPECTION").is_some()
        || std::env::var_os("EGUI_INSPECTION_ADDR").is_some()
        || std::env::var_os("EFRAME_SCREENSHOT_TO").is_some()
    {
        return Err(WindowError(
            "Inspection, injected input and automated screenshots are not accepted by the signer window.",
        ));
    }
    // A display variable is only a prerequisite. It is never user-origin,
    // sandbox or compositor authentication, including app-owned nested displays.
    if std::env::var_os("WAYLAND_DISPLAY").is_none() && std::env::var_os("WAYLAND_SOCKET").is_none()
    {
        return Err(WindowError(
            "A Linux Wayland desktop is required to open this window. This environment has no Wayland connection; X11 fallback is disabled. --capabilities works without a display.",
        ));
    }
    crate::harden_process()
        .map_err(|_| WindowError("Signer process hardening could not be established."))?;
    let app = window::Window::new(mode, parent_channel)
        .map_err(|_| WindowError("Could not initialize a private window session."))?;
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("Wholepact · Signer review")
            .with_app_id("org.wholepact.Signer")
            .with_inner_size([1100.0, 780.0])
            .with_min_inner_size([840.0, 620.0])
            .with_drag_and_drop(false),
        renderer: eframe::Renderer::Glow,
        persist_window: false,
        event_loop_builder: Some(Box::new(|builder| {
            builder.with_wayland();
        })),
        ..Default::default()
    };
    eframe::run_native("Wholepact signer", options, Box::new(|cc| {
        window::configure_style(&cc.egui_ctx);
        Ok(Box::new(app))
    })).map_err(|_| WindowError("Native Wayland window startup failed. No account was unlocked and no consent was retained."))
}
/// Machine-readable observations, never an authorization flag accepted by IPC.
pub fn capabilities() -> String {
    serde_json::json!({
        "schema_version": 1,
        "surface": "native-wayland-signer",
        "application_manifest_review": true,
        "synthetic_pairing_rehearsal": true,
        "synthetic_transaction_review": cfg!(feature = "synthetic-qualification"),
        "private_transaction_intake_source": cfg!(feature = "authority-signing"),
        "local_wallet_selection_source": cfg!(feature = "authority-signing"),
        "pinned_witness_source": cfg!(feature = "authority-signing"),
        "exact_authorization_source": cfg!(feature = "authority-signing"),
        "original_result_export_source": true,
        "runtime_profile": "linux-wayland-trusted-os-local-peer-v1",
        "runtime_qualification": "pending",
        "account_provisioning_source": true,
        "persistent_consent_source": true,
        "app_pairing_source": true,
        "peer_identity": "SO_PEERCRED+SO_PEERPIDFD+SCM_CREDENTIALS",
        "pairing_kernel_minimum": "Linux 6.5",
        "attended_runtime_qualified": false,
        "foreground_bounded_automation_source": cfg!(feature = "authority-signing"),
        "coordinator_two_phase_automation_source": cfg!(feature = "authority-signing"),
        "foreground_automation_requires_exact_native_privacy_decision": true,
        "automatic_or_unattended_signing": false,
        "reasons": [
            "attended_desktop_qualification_not_performed",
            "selected_wallet_provider_witness_and_installed_profile_require_owner_setup",
            "local_process_identity_does_not_authenticate_remote_participant_keys"
        ]
    })
    .to_string()
}

/// Headless synthetic exercise of the same session used by the native window.
/// This is not attended-input evidence, a receipt, or a permission to release.
/// It accepts an opaque verified inspection, never an arbitrary verified flag.
#[cfg(feature = "synthetic-qualification")]
pub fn qualify_transaction_inspection(
    inspection: crate::inspection::TransactionInspection,
) -> crate::Result<String> {
    let binding = inspection.binding().to_owned();
    let mut session = transaction::TransactionReview::new()?;
    session.observe_focus(true);
    session.stage(inspection)?;
    session.continue_from_local_click()?;
    let phrase = session.phrase().ok_or(crate::Error::ReviewMismatch)?;
    session.confirm_from_local_click(&phrase, true)?;
    if session.phase() != state::Phase::Accepted {
        return Err(crate::Error::ReviewMismatch);
    }
    session.observe_focus(false);
    if session.binding().is_some() || session.confirm_from_local_click(&phrase, true).is_ok() {
        return Err(crate::Error::ReviewMismatch);
    }
    Ok(binding)
}

#[cfg(feature = "authority-signing")]
mod recipient;

#[cfg(feature = "authority-signing")]
mod proved_disclosure;

#[cfg(feature = "authority-signing")]
mod recovery_workspace;
#[cfg(all(
    test,
    feature = "authority-signing",
    feature = "synthetic-qualification"
))]
pub(crate) use authority::{recovery_test_authority, recovery_test_decision};

#[cfg(feature = "authority-signing")]
pub(crate) use authority::NativePublicationLease;

#[cfg(feature = "pending-birth-owner-signing")]
mod pending_owner_signing;

#[cfg(feature = "pending-birth-owner-signing")]
mod pending_enrollment;

#[cfg(feature = "pending-birth-owner-signing")]
mod born_origin_workspace;

#[cfg(feature = "pending-birth-owner-signing")]
mod born_enrolled_backup;
#[cfg(feature = "pending-birth-owner-signing")]
mod born_manual;

#[cfg(feature = "pending-birth-owner-signing")]
pub(crate) use witness_workspace::ApprovedWriterSession as NativeApprovedWriterSession;

#[cfg(feature = "pending-birth-owner-signing")]
mod born_manual_roster_v2;
#[cfg(all(feature = "pending-birth-owner-signing", target_os = "linux"))]
pub(crate) use born_manual_roster_v2::permanent_stop_publication::AuthenticatedPermanentStopHostReceiptV1;

#[cfg(feature = "authority-signing")]
pub(crate) use host_recovery::v5::NativeHostRecoveryObservationV5;

#[cfg(feature = "authority-signing")]
mod account_inspection;
#[cfg(feature = "authority-signing")]
mod named_verifier_policy;

#[cfg(all(feature = "authority-signing", feature = "offline-review-foundation"))]
mod named_verifier_owner;
