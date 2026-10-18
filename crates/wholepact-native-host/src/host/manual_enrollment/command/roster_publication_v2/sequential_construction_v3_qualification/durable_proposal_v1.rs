//! Separate NEW durable profile qualification. Initial birth/roster setup is
//! historical association only; no V3 common-context/construction owner exists.
//! This leaf currently qualifies real native disclosure, encrypted intake, closed
//! native associations, fixed proof and fresh reentry, not final payment release.
#![cfg(all(
    test,
    feature = "synthetic-born-joined-qualification",
    feature = "durable-proposal"
))]
use super::*;
#[path = "durable_proposal_v1/initial.rs"]
mod initial;
#[path = "durable_proposal_v1/preproof.rs"]
mod preproof;
#[path = "durable_proposal_v1/worker.rs"]
mod worker;

pub(super) fn inputs() -> Vec<Input<'static>> {
    initial::inputs()
}
pub(super) fn exercise_stage(terminal: crate::terminal::Terminal) -> Result<()> {
    let initial = initial::prepare(terminal)?;
    preproof::exercise(initial)
}

#[test]
#[ignore = "Explicit approved isolated Linux synthetic runner only; no local native IPC execution"]
fn durable_proposal_native_owner_reopen_retains_exact_fixed_proof() {
    foreground_child("durable-proposal-native-owner-reopen-v1", &inputs())
        .expect("genuine native disclosure, encrypted intake and fixed proof after closed owner associations");
}
