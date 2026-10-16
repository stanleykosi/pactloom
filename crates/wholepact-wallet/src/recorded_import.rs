//! Fixed application-owned import provenance. These rows are historical facts,
//! never scan consent, current signer authority, or a wallet-reopen capability.
//! The issuer is deliberately separate from ordinary open/import paths.
pub(crate) const SCHEMA: &str = include_str!("recorded_import/schema.sql");

#[cfg(feature = "protected-sync")]
#[path = "recorded_import/issuer.rs"]
mod issuer;
#[cfg(feature = "protected-sync")]
pub use issuer::{RecordedImportError, RecordedImportEvidence, RecordedPreliminaryImport};
