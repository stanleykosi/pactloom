//! Maintained-library, testnet-only wallet contribution adapter.
//!
//! Viewing material and note witnesses are privacy-sensitive. This crate never
//! holds spending keys, signs, broadcasts, or claims consensus validation in product
//! operation. The opt-in `synthetic-qualification` fixture owns ephemeral never-funded
//! test keys solely to keep fabricated notes matched to separate synthetic signers.

extern crate self as wholepact_wallet;

#[cfg(feature = "wallet")]
pub mod wallet;

#[cfg(all(feature = "encrypted-storage", target_os = "linux"))]
pub mod bundle;

mod key_use_policy;
pub use key_use_policy::{WalletKeyUseConfidence, WalletKeyUsePolicy};
