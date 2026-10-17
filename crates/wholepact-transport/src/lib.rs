//! Offline, recipient-scoped authenticated encrypted exchange and agreement backups.
//!
//! No networking, automatic export, wallet authorization or signer credentials are
//! created here. Transport authentication is not transaction authorization. Imported
//! backups always require authority and exposure reconciliation.
#![forbid(unsafe_code)]

mod backup;
mod domain;
mod envelope;
mod invitation;
#[cfg(feature = "offline-admission-export")]
mod offline_admission_outbox;
mod outbox;
#[cfg(feature = "offline-admission-export")]
pub use offline_admission_outbox::*;
#[cfg(feature = "offline-admission-export")]
mod offline_control_outbox;
#[cfg(feature = "offline-admission-export")]
pub use offline_control_outbox::*;
#[cfg(feature = "offline-admission-export")]
mod offline_control_inbox;
#[cfg(feature = "offline-admission-export")]
pub use offline_control_inbox::*;
mod named_recipient_receipt_source;
mod replay;
pub use named_recipient_receipt_source::SignerNamedRecipientReceiptSource;
mod replay_schema;
mod types;

pub use backup::*;
pub use bundle::*;
pub use domain::*;
pub use envelope::*;
pub use invitation::*;
pub use outbox::*;
pub use replay::*;
pub use types::*;

pub mod bundle;

#[cfg(feature = "offline-admission-export")]
mod offline_minimal_admission;
#[cfg(feature = "offline-admission-export")]
pub use offline_minimal_admission::*;

#[cfg(feature = "offline-admission-export")]
mod offline_return_inbox;
#[cfg(feature = "offline-admission-export")]
pub use offline_return_inbox::*;

mod named_verifier_initialization;

mod named_review_binding_v1;
pub use named_review_binding_v1::*;

#[cfg(feature = "offline-admission-export")]
mod born_offline_minimal_admission_v1;
#[cfg(feature = "offline-admission-export")]
pub use born_offline_minimal_admission_v1::*;
#[cfg(feature = "offline-admission-export")]
mod offline_intent_handoff_v1;
#[cfg(feature = "offline-admission-export")]
pub use offline_intent_handoff_v1::{MAX_OFFLINE_INTENT_HANDOFF_BYTES_V1, OfflineIntentHandoffV1};

#[cfg(feature = "offline-admission-export")]
mod born_offline_intent_v1;
#[cfg(feature = "offline-admission-export")]
pub use born_offline_intent_v1::*;

#[cfg(feature = "offline-admission-export")]
mod born_offline_checkpoint_v1;
#[cfg(feature = "offline-admission-export")]
pub use born_offline_checkpoint_v1::*;
