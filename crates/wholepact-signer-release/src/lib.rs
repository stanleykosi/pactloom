//! Installed-signer release adapter; no issuer, signing, offline admission or
//! general-purpose privileged journal API. Native profile ownership must remain
//! held while either database owner is alive.
#![forbid(unsafe_code)]
#[cfg(target_os = "linux")]
mod authorization;
#[cfg(target_os = "linux")]
#[allow(dead_code)]
mod journal;
#[cfg(target_os = "linux")]
mod outbox;
#[cfg(target_os = "linux")]
pub use authorization::*;
#[cfg(target_os = "linux")]
pub use outbox::AuthorizationOutbox;
