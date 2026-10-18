//! Wholepact's pure accounting and policy layer.
//!
//! This crate does not sign, prove, broadcast, access wallets, or verify Zcash
//! ownership. Arithmetic validation must never be presented as spend approval.
#![forbid(unsafe_code)]
pub mod automation;

pub mod agreement;
pub mod amount;
pub mod disclosure;
pub mod durable_input_projection_v1;
pub mod error;
pub mod fees;
pub mod lifecycle;
pub mod matching;
pub mod proposal;
pub mod recipient;
pub mod records;
pub mod retirement;
pub mod sponsor;
pub mod strict_json;

pub use agreement::*;
pub use amount::{Amount, AmountError, MAX_MONEY, ZATOSHIS_PER_ZEC};
pub use error::{CoreError, ErrorCode, Result};
pub use fees::{allocate_fees, FeePolicy, FeeWeight};
pub use lifecycle::*;
pub use matching::*;
pub use proposal::*;
pub use strict_json::{parse_json_unique, parse_typed_json};

pub mod manual_enrollment;

pub mod manual_construction;

pub mod born_policy_origin_v2;
pub mod born_recipient_policy_v2;
pub mod manual_candidate_selection;
pub mod manual_inventory;

pub mod manual_roster_v2;

pub mod manual_roster_candidate_selection_v2;
pub mod manual_roster_inventory_v2;

pub mod manual_roster_construction_v2;

pub mod manual_roster_exact_input_observation_v1;

pub mod common_context_reentry_v1;
pub mod manual_roster_construction_v3;

pub mod joined_acceptance;

pub mod owner_inspection;

pub mod common_context_historical_provenance_v1;
