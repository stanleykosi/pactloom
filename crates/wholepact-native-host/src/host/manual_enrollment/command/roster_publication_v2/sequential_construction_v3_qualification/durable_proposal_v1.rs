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
#[path = "durable_proposal_v1/fixed_signing.rs"]
mod fixed_signing;
#[path = "durable_proposal_v1/delivery_admission_v2.rs"]
pub(super) mod delivery_admission_v2;
#[path = "durable_proposal_v1/private_fixed_v2.rs"]
pub(super) mod private_fixed_v2;
#[path = "durable_proposal_v1/initial.rs"]
mod initial;
#[path = "durable_proposal_v1/pristine_coordinator_v1.rs"]
pub(super) mod pristine_coordinator_v1;
#[path = "durable_proposal_v1/pristine_owner_client_v1.rs"]
mod pristine_owner_client_v1;
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

/// Separate fixed-signing stage, selected only by its explicit ignored test.
pub(super) fn exercise_fixed_signing_stage(terminal: crate::terminal::Terminal) -> Result<()> {
    let initial = initial::prepare(terminal)?;
    preproof::exercise_with_fixed_signing(initial)
}

/// Separate pending-session qualification, never a fixed-signing continuation.
pub(super) fn exercise_acquire_reply_loss_stage(terminal: crate::terminal::Terminal) -> Result<()> {
    let initial = initial::prepare(terminal)?;
    preproof::exercise_with_acquire_reply_loss(initial)
}

#[test]
#[ignore = "Explicit approved isolated Linux synthetic runner only; no local native IPC execution"]
fn durable_proposal_native_owner_reopen_retains_exact_fixed_proof() {
    foreground_child("durable-proposal-native-owner-reopen-v1", &inputs())
        .expect("genuine native disclosure, encrypted intake and fixed proof after closed owner associations");
}

#[test]
#[ignore = "Explicit approved isolated Linux synthetic runner only; no local native IPC execution"]
fn durable_proposal_native_fixed_signing_retains_exact_results() {
    foreground_child("durable-proposal-native-fixed-signing-v1", &inputs()).expect(
        "genuine native fixed signing and exact retained results; no chain consensus or submission",
    );
}

#[test]
#[ignore = "Explicit approved isolated Linux synthetic runner only; no local native IPC execution"]
fn durable_proposal_native_acquire_reply_loss_retries_original_session() {
    foreground_child("durable-proposal-native-acquire-reply-loss-v1", &inputs()).expect(
        "original pending-session recovery after one committed Acquire reply loss; no activation or signing",
    );
}
