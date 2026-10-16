//! V2 roster import provenance is immutable history, not scan permission,
//! signer authority, a V1 provenance conversion, or wallet-reopen capability.
pub(crate) const SCHEMA: &str = include_str!("recorded_roster_import_v2/schema.sql");

#[cfg(feature = "protected-sync")]
#[path = "recorded_roster_import_v2/issuer.rs"]
mod issuer;
#[cfg(feature = "protected-sync")]
pub use issuer::{RecordedRosterImportErrorV2, RecordedRosterInventoryImportV2};
