//! An isolated, fail-closed signer companion. Feature-gated native signing
//! requires the concrete wallet, peer, consent and witness authority paths.
//! End-to-end platform qualification and recovery activation remain incomplete.
//! The opt-in qualification interface accepts only public synthetic accounts.
//! No network client, browser credential, coordinator credential or generic
//! "verified" JSON can confer signing authority.

#[cfg(all(wholepact_financial_rendered_host_semantic_ci, not(all(
    wholepact_financial_ci, wholepact_financial_external_ci,
    feature = "coordinated-financial-workflow-v1", target_os = "linux"
))))]
compile_error!("semantic financial observation requires the original Linux coordinated workflow profile");
// Each wrapper evaluates the original expression exactly once and returns its
// unchanged Result. No observation API or output exists in other profiles.
macro_rules! actor_driver_result {
    ($stage:ident, $result:expr) => {{
        let result = $result;
        #[cfg(wholepact_financial_rendered_host_semantic_ci)]
        if let Err(error) = &result { crate::financial_ci_actor::driver(
            wholepact_financial_coordinator_origin::financial_ci_actor_diagnostics::DriverStage::$stage, error); }
        result
    }};
}
macro_rules! actor_driver_detail_result {
    ($stage:ident, $result:expr) => {{
        let result = $result;
        #[cfg(wholepact_financial_rendered_host_semantic_ci)]
        if let Err(error) = &result { crate::financial_ci_actor::driver_detail(
            wholepact_financial_coordinator_origin::financial_ci_actor_diagnostics::DriverStage::$stage, error); }
        result
    }};
}
macro_rules! actor_listener_result {
    ($stage:ident, $result:expr) => {{
        let result = $result;
        #[cfg(wholepact_financial_rendered_host_semantic_ci)]
        if let Err(error) = &result { crate::financial_ci_actor::listener(
            wholepact_financial_coordinator_origin::financial_ci_actor_diagnostics::ListenerStage::$stage, error); }
        result
    }};
}
macro_rules! actor_listener_denial {
    ($stage:ident, $class:ident) => {{
        #[cfg(wholepact_financial_rendered_host_semantic_ci)]
        wholepact_financial_coordinator_origin::financial_ci_actor_diagnostics::listener(
            wholepact_financial_coordinator_origin::financial_ci_actor_diagnostics::ListenerStage::$stage,
            wholepact_financial_coordinator_origin::financial_ci_actor_diagnostics::Class::$class);
    }};
}

#[cfg(wholepact_financial_rendered_host_semantic_ci)]
mod financial_ci_actor;

pub mod account;
pub mod authority_bridge;
pub mod consent_journal;
pub mod files;
pub mod inspection;
#[cfg(target_os = "linux")]
pub mod ipc;
pub mod manifest;
#[cfg(target_os = "linux")]
mod native_launch;
#[cfg(target_os = "linux")]
mod native_peer;
#[cfg(all(feature = "native-ui", target_os = "linux"))]
pub mod native_ui;
pub mod review;
#[cfg(feature = "synthetic-qualification")]
pub mod synthetic;
pub mod terminal;
pub mod vault;

use thiserror::Error;
#[derive(Debug, Error)]
pub enum Error {
    #[error(
        "operation unavailable through this entry point or without required platform and authority prerequisites"
    )]
    Unavailable,
    #[error(
        "kernel-bound local peer lifetime is unavailable; Linux SO_PEERPIDFD support is required"
    )]
    PeerLifetimeUnavailable,
    #[error("protected file operation failed")]
    Io(#[from] std::io::Error),
    #[error("protected data authentication failed")]
    Authentication,
    #[error("unsupported or invalid protected data")]
    InvalidData,
    #[error("cryptographic operation failed")]
    Crypto,
    #[error("account is locked")]
    Locked,
    #[error("backup verification is required")]
    BackupRequired,
    #[error("account requires writer and exposure reconciliation; signing is disabled")]
    RecoveryRequired,
    #[error("account already has an active local process")]
    AlreadyOpen,
    #[error("review rejected, expired, already consumed or substituted")]
    ReviewMismatch,
    #[error("transaction verification failed")]
    Verification,
    #[error("authorization result is uncertain; existing exposure is retained")]
    Uncertain,
    #[error("signer consent journal operation failed")]
    ConsentJournal(#[from] consent_journal::JournalError),
    #[error("authority journal operation failed")]
    Store(#[from] wholepact_store::StoreError),
}
pub type Result<T> = std::result::Result<T, Error>;

pub fn provision_live_account() -> Result<()> {
    Err(Error::Unavailable)
}
pub fn automation_supported() -> bool {
    false
}

/// Process-local defense only. This is not secure memory or swap protection.
/// Other operating systems remain unqualified rather than claiming equivalence.
#[cfg(target_os = "linux")]
pub fn harden_process() -> Result<()> {
    // SAFETY: constants and a pointer to a valid stack rlimit are passed to libc.
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let ok = unsafe {
        libc::setrlimit(libc::RLIMIT_CORE, &limit) == 0
            && libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0
    };
    if ok { Ok(()) } else { Err(Error::Unavailable) }
}
#[cfg(not(target_os = "linux"))]
pub fn harden_process() -> Result<()> {
    Err(Error::Unavailable)
}

#[cfg(target_os = "linux")]
impl From<wholepact_signer_origin::Error> for Error {
    fn from(error: wholepact_signer_origin::Error) -> Self {
        use wholepact_signer_origin::Error as Origin;
        match error {
            Origin::Io(error) => Self::Io(error),
            Origin::PeerLifetimeUnavailable => Self::PeerLifetimeUnavailable,
            Origin::Crypto => Self::Crypto,
            Origin::Locked => Self::Locked,
            Origin::InvalidData | Origin::Binding => Self::InvalidData,
            _ => Self::Authentication,
        }
    }
}
