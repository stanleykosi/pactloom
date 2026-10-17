//! Finite SYNTHETIC controlling-PTY input for the one original full path.
//! Each reply is delivered only after its purpose-specific prompt and actual
//! native challenge by the existing foreground driver. This is not attended
//! consent, a generic auto-approve facility, live-chain settlement or permission
//! to retry blocked IPC. The full parent test remains explicitly ignored.
#![cfg(all(test, feature = "synthetic-born-joined-qualification"))]

use super::{Input, foreground_child};
use crate::{Error, Result, terminal::Terminal};

fn review(detail: &'static str) -> Input<'static> {
    Input::ExactReview {
        detail,
        approve: true,
    }
}

fn checkpoint_private_reads(inputs: &mut Vec<Input<'static>>) {
    inputs.push(review("Read the current authenticated generation's complete sealed parent capsule, inherited identity coverage and complete bounded coordination construction/audit records, then select the actual completed version-5 construction with immutable original scanner provenance below."));
    inputs.push(review("Read and independently verify ONLY the actual completed private checkpoint for this exact saved scope."));
    inputs.push(review("Keep and use ONLY this already independently verified completed private checkpoint in this Host's memory for at most15 minutes, ending sooner on lock/revoke/foreground loss."));
}

/// The actual constructor input plan is reused unchanged. Everything appended
/// here names one finite next purpose; no fallback or unmatched approval exists.
/// Dynamic account/path text is produced by the actual owners, not input data.
pub(super) fn inputs() -> Vec<Input<'static>> {
    let mut inputs = super::constructed_joined_v3::inputs();
    inputs.push(review("Read the actual current-generation sealed parent capsule and complete bounded private coordination claim/audit history to select ONLY this original common-context constructor checkpoint (claim encodings 3–5)."));
    inputs.push(review("NEW purpose-specific local privacy/CPU approval for ONLY this exact actual saved constructor checkpoint."));
    for _ in 0..2 {
        // Fresh original named Pair and profile precede transport selection.
        // Signer/witness exact native events remain owned by their controllers;
        // those events are not replaced by an extra Host-terminal response.
        inputs.push(review("SYNTHETIC JOINED CONTROLLER TEST: read only the actual saved construction claim/proposal metadata to check this same original account's fresh named Pair scope."));
        inputs.push(review("SYNTHETIC JOINED CONTROLLER TEST: pair this exact fresh named request-only scope with the SAME retained original installed signer process and complete its authenticated Status handshake."));
        // Exactly outgoing checkpoint pin, then incoming return pin. Each
        // ordinary pin review still contains its actual distinct full context.
        for _ in 0..2 {
            inputs.push(review("Pin a non-signing transport peer for this exact session scope. This is not human, receiving-address or wallet ownership verification."));
        }
        checkpoint_private_reads(&mut inputs);
        inputs.push(review("Export exactly this completed-checkpoint origin metadata, HPKE-authenticated by the existing Host return key to the independently pinned offline signer."));
        // Export consumed its owner. Reopen with NEW privacy/read decisions,
        // SAME original plan/ciphertext. There is no second export or reseal.
        checkpoint_private_reads(&mut inputs);
    }
    // Metadata/enrollment installation is actual native-controller work, not
    // a Host terminal yes. Each selected recipient has a distinct disclosure.
    for _ in 0..2 {
        inputs.push(review("SYNTHETIC JOINED CONTROLLER TEST: disclose this exact ACTUAL independently verified saved full private transaction to the separately selected local named verifier, plus exact key-free action/context claims to the original offline recipients."));
    }
    for _ in 0..2 {
        inputs.push(review("Authenticate and retain this exact born signature return in the existing encrypted Host inbox, then independently verify its signature-only delta against the ORIGINAL completed proof and full private policy."));
    }
    // These are TWO separately cached exact scopes. Merely approving usable
    // signatures does not approve complete-transaction extraction/retention.
    inputs.push(review(
        "Approve retain exact usable signatures for this EXACT scope?",
    ));
    inputs.push(review(
        "Approve extract/read and retain exact complete transaction for this EXACT scope?",
    ));
    inputs.push(review("Open ONLY these already registered existing participant wallet journals for one fresh born post-return input observation."));
    for _ in 0..2 {
        // Both actual participant wallets were initially created by the reused
        // retained-stage inputs with this public SYNTHETIC password. Their
        // canonical account order/path is displayed by the production owner.
        // Match only this finite purpose twice, never a generic password ask.
        inputs.push(Input::Text {
            prompt: "Existing participant wallet passphrase for account ",
            response: "synthetic-recovery-review-password",
        });
    }
    inputs.push(review("Approve one fresh post-return protected-wallet observation of these EXACT original inputs and final signed transaction."));
    inputs.push(review("Authorize copying ONLY this already retained exact complete signed transaction into the exact submission journal identified below, and ONE exact born post-return transaction dispatch attempt to this provider and actual network route."));
    inputs
}

/// Exactly one genuine temporary scenario and one consuming full continuation.
/// The scenario retains Host, original witnesses, signer worker and recipient
/// until the actual carrier/payment result and its bounded owners have drained.
pub(super) fn exercise_full_payment_stage(terminal: Terminal) -> Result<()> {
    let mut scenario = super::full_joined_v3::prepare(terminal)?;
    let result = scenario.prove_originals()?.finish_original_payment()?;
    if result.public_network_settlement_verified
        || result.attended_native_acceptance_verified
        || result.recipient.public_network_inclusion_verified
        || result.recipient.independent_consensus_verified
        || result.exact_submission.clears_authorization_exposure
        || result.exact_submission.permits_replacement
    {
        return Err(Error::Authentication);
    }
    let public = super::public_outcome_v1::PublicOutcomeV1::from_actual(&result)
        .map_err(|_| Error::Storage)?;
    drop(result);
    drop(scenario);
    // One create-only PUBLIC projection after successful actual receipt and
    // same-scenario teardown. Parent publishes it only after verified cleanup.
    public.write_child_once().map_err(|_| Error::Storage)?;
    Ok(())
}

#[test]
#[ignore = "Explicit approved isolated Linux synthetic runner only; never a local denied-IPC retry"]
fn actual_three_born_full_payment_uses_one_original_synthetic_path() {
    foreground_child("three-born-full-payment-v1", &inputs()).expect(
        "one original temporary synthetic full path only; not public-chain settlement or attended native acceptance",
    );
}

#[test]
fn full_foreground_suffix_has_only_its_finite_exact_purposes() {
    let constructor_len = super::constructed_joined_v3::inputs().len();
    let full = inputs();
    let suffix = &full[constructor_len..];
    assert_eq!(suffix.len(), 35);
    assert_eq!(
        suffix
            .iter()
            .filter(|input| matches!(input, Input::ExactReview { approve: true, .. }))
            .count(),
        33
    );
    assert_eq!(
        suffix
            .iter()
            .filter(|input| matches!(
                input,
                Input::Text {
                    prompt: "Existing participant wallet passphrase for account ",
                    response: "synthetic-recovery-review-password"
                }
            ))
            .count(),
        2
    );
    assert!(!suffix.iter().any(|input| matches!(
        input,
        Input::CapturedPath { .. } | Input::ExactReview { approve: false, .. }
    )));
}
