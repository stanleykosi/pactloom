//! Same-owner continuation of the concrete temporary retained-input scenario.
//! All full-plan reviews and NEW original continuations precede the first
//! bounded common-context observation. No grant, Reserve, Consume, constructor,
//! proof or transaction authorization is invoked by this milestone.
#![cfg(all(test, feature = "synthetic-born-joined-qualification"))]

use super::super::prepared_common_context_read_v3;
use super::continued_joined_v3::{ReviewedJoinedContinuationV3, prepare_original_continuation};
use super::joined_signer_worker_v1::{
    JoinedSignerCommandV1 as Command, JoinedSignerPeerV1, JoinedSignerReplyV1 as Reply,
    JoinedSignerWorkerV1, PublicJoinedBornV1,
};
use super::retained_joined_v3::{CONSTRUCTION_KEY, RetainedJoinedStageV3};
use super::safe_diagnostics_v1::{self as diagnostic, Boundary as B};
use super::*;
use std::{
    collections::BTreeSet,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
};
use wholepact_authority::native_witness_owner::EphemeralNativeWitnessV1;
use wholepact_signer::native_ui::synthetic_born_joined_qualification::ExpectedCommonContextReadV3Input;
use wholepact_signer_origin::manual_roster_v2::{
    HostManualRosterEnrollmentIntentV2, ManualRosterPublicationAttemptV2,
};

/// These operation IDs are inert original correlations. A later completion
/// stage must also receive the concrete witness client scope from its actual
/// native producer exactly once for this same observed original. No scope,
/// pending grant, native decision or completion capability is synthesized here.
pub(super) struct ObservedJoinedOwnerV3 {
    pub(super) signer_index: usize,
    pub(super) operations: CompletionOperationIdsV1,
}

/// Private actual all-observations owner plus the SAME live finite provider.
/// Retaining this object does not renew any observation or original deadline.
/// The enclosing scenario still owns Host, all signer originals and witness.
pub(super) struct ObservedJoinedStageV3<'host> {
    pub(super) roster: AllObservedCommonContextRosterV1<'host>,
    pub(super) owners: Vec<ObservedJoinedOwnerV3>,
    pub(super) provider: super::synthetic_born_provider_v1::SyntheticBornProviderV1,
    pub(super) runtime: tokio::runtime::Runtime,
}

struct PreparedOwnerReadV3 {
    index: usize,
    plan: ReadPlanV3,
    continuation: ReviewedJoinedContinuationV3,
}

fn stage(label: &'static str) -> Error {
    Error::Receipt(format!("synthetic all-observations stage failed: {label}"))
}
fn receive_peer(worker: &JoinedSignerWorkerV1) -> Result<JoinedSignerPeerV1> {
    match worker.receive().map_err(stage)? {
        Reply::Peer(peer) if Instant::now() < peer.deadline => Ok(peer),
        _ => Err(Error::Authentication),
    }
}
fn done(worker: &JoinedSignerWorkerV1, expected: usize) -> Result<()> {
    match worker.receive().map_err(stage)? {
        Reply::Done { index } if index == expected => Ok(()),
        _ => Err(Error::Authentication),
    }
}
fn check_scenario(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        Err(Error::Permission)
    } else {
        Ok(())
    }
}

/// Each input is an actual predecessor retained by this one scenario. The
/// public birth metadata selects only an already-existing worker original; it
/// cannot create one. Both native producers independently recheck that original.
#[allow(clippy::too_many_arguments)]
pub(super) fn observe_two<'host>(
    host: &'host Host,
    witness: &mut EphemeralNativeWitnessV1,
    signers: &JoinedSignerWorkerV1,
    born: &[PublicJoinedBornV1; 3],
    roster_intents: &[HostManualRosterEnrollmentIntentV2; 2],
    roster_signed_extension_files: &[PathBuf; 2],
    temporary_root: &Path,
    original_scenario_deadline: Instant,
    retained: RetainedJoinedStageV3<'host>,
) -> Result<ObservedJoinedStageV3<'host>> {
    observe_two_inner(
        host,
        super::full_joined_v3::JoinedWitnessRouteV1::ConstructorOnly(witness),
        signers,
        born,
        roster_intents,
        roster_signed_extension_files,
        temporary_root,
        original_scenario_deadline,
        retained,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn observe_two_with_original_witnesses<'host>(
    host: &'host Host,
    witnesses: &mut super::full_joined_v3::OriginalJoinedWitnessSetV1,
    signers: &JoinedSignerWorkerV1,
    born: &[PublicJoinedBornV1; 3],
    roster_intents: &[HostManualRosterEnrollmentIntentV2; 2],
    roster_signed_extension_files: &[PathBuf; 2],
    temporary_root: &Path,
    original_scenario_deadline: Instant,
    retained: RetainedJoinedStageV3<'host>,
) -> Result<ObservedJoinedStageV3<'host>> {
    observe_two_inner(
        host,
        super::full_joined_v3::JoinedWitnessRouteV1::Distinct(witnesses),
        signers,
        born,
        roster_intents,
        roster_signed_extension_files,
        temporary_root,
        original_scenario_deadline,
        retained,
    )
}

#[allow(clippy::too_many_arguments)]
fn observe_two_inner<'host>(
    host: &'host Host,
    mut witnesses: super::full_joined_v3::JoinedWitnessRouteV1<'_>,
    signers: &JoinedSignerWorkerV1,
    born: &[PublicJoinedBornV1; 3],
    roster_intents: &[HostManualRosterEnrollmentIntentV2; 2],
    roster_signed_extension_files: &[PathBuf; 2],
    temporary_root: &Path,
    original_scenario_deadline: Instant,
    retained: RetainedJoinedStageV3<'host>,
) -> Result<ObservedJoinedStageV3<'host>> {
    diagnostic::host(B::ObservedInputs, || {
        check_scenario(original_scenario_deadline)?;
        host.require_manual_session()
    })?;
    let RetainedJoinedStageV3 {
        contributions,
        provider,
        runtime,
    } = retained;
    if contributions.len() != 2 {
        return Err(Error::Authentication);
    }
    for original in &contributions {
        original.require_original_retention_scope_v2(host)?;
    }
    // Consume the actual Vec, never reconstruct retained input/source owners.
    let candidate = diagnostic::host(B::ObservedAssemble, || {
        UnreviewedRosterManualCandidateV3::assemble(host, contributions)
    })?;
    let reviewed = diagnostic::host(B::ObservedCandidateReview, || {
        candidate.display_current(host)?;
        candidate.review_full_candidate_before_construction(host, CONSTRUCTION_KEY.into(), 4)
    })?;
    let plans = reviewed.exact_native_plans(host)?.to_vec();
    if plans.len() != 2 {
        return Err(Error::Authentication);
    }

    // A new private destination, not chmod of an existing directory. The
    // ordinary production exporter still checks all source exclusions/mode/uid.
    let exports = temporary_root.join("synthetic-actual-full-plans-v3");
    std::fs::DirBuilder::new().mode(0o700).create(&exports)?;
    let mut prepared_reads = Vec::with_capacity(2);
    let mut distinct_originals = BTreeSet::new();
    for plan in plans {
        check_scenario(original_scenario_deadline)?;
        reviewed.check_current(host)?;
        let owner = born[1..]
            .iter()
            .find(|owner| owner.account_id == plan.enrollment().identity.account_id)
            .ok_or(Error::Authentication)?;
        if !distinct_originals.insert(owner.index)
            || !(1..=2).contains(&owner.index)
            || owner.full_viewing_key_digest != plan.enrollment().identity.full_viewing_key_digest
            || owner.participant_id != plan.enrollment().scope.participant_id
        {
            return Err(Error::Authentication);
        }
        let witness = witnesses.for_original(owner)?;
        roster_intents[owner.index - 1]
            .matches_terms(
                plan.enrollment(),
                &plan.retained.selection.scope.provenance.roster,
            )
            .map_err(|_| Error::Authentication)?;
        let durable_receipt_digest = reviewed
            .exact_retained_owner(host, &plan)?
            .durable_receipt_digest()
            .to_owned();
        let actual_plan_file =
            exports.join(format!("owner-{}-original-full-plan.json", owner.index));
        diagnostic::host(B::ObservedPlanExport, || {
            reviewed.export_native_plan(host, &plan, &actual_plan_file)
        })?;
        let signed_file = diagnostic::host(B::ObservedPlanSign, || {
            signers
                .send(Command::SignAndExportOriginalFullPlan(
                    owner.index,
                    actual_plan_file,
                ))
                .map_err(stage)?;
            match signers.receive().map_err(stage)? {
                Reply::FullPlanExport {
                    index,
                    signed_plan_file,
                } if index == owner.index => Ok(signed_plan_file),
                _ => Err(Error::Authentication),
            }
        })?;
        host.terminal.message(&format!(
            "SYNTHETIC_JOINED_SIGNED_FULL_PLAN_PATH={}\n",
            signed_file.display()
        ))?;
        let signed: ManualRosterConstructionOwnerSignatureV3 = diagnostic::host(
            B::ObservedPlanRead,
            || {
                host.read_manual_private(
            "Exact privately exported V3 full-plan owner-signature JSON: ",
            "authenticating this exact full plan against its already retained owner certificate pin",
        )
            },
        )?;
        let verified_digest = diagnostic::host(B::ObservedPlanAuthenticate, || {
            let verified = verify_manual_roster_construction_owner_signature_v3(
                &signed,
                &plan.enrollment().signer.owner_certificate_digest,
            )
            .map_err(|_| Error::Authentication)?;
            if verified.approval().plan != plan {
                return Err(Error::Authentication);
            }
            verified
                .approval()
                .digest_for(verified.extension())
                .map_err(|_| Error::Authentication)
        })?;
        // The witness separately consumes the actual private signer export,
        // through its existing real Window prepare/review/commit event path.
        let witness_plan_approval_digest = diagnostic::host(B::ObservedPlanWitness, || {
            let actual_bytes =
                zeroize::Zeroizing::new(crate::files::read_private(&signed_file, 2 * 1024 * 1024)?);
            let actual = witness
                .review_original_construction_plan_v3(&owner.account_id, &actual_bytes)
                .map_err(|error| {
                    diagnostic::emit(
                        B::ObservedPlanWitnessOrigin,
                        diagnostic::authority_error(&error),
                    );
                    stage("independent exact original full-plan witness review")
                })?;
            if actual != verified_digest {
                return Err(Error::Authentication);
            }
            reviewed.check_current(host)?;
            Ok(actual)
        })?;
        // NOT the retained-input publication again. This producer waits the
        // genuine prior deadline then signs/reviews a distinct newer attempt.
        let continuation = diagnostic::host(B::ObservedContinuation, || {
            prepare_original_continuation(
                host,
                witness,
                signers,
                owner,
                &roster_intents[owner.index - 1],
                &roster_signed_extension_files[owner.index - 1],
                original_scenario_deadline,
            )
        })?;
        reviewed.check_current(host)?;
        prepared_reads.push(PreparedOwnerReadV3 {
            index: owner.index,
            plan: ReadPlanV3 {
                plan,
                durable_receipt_digest,
                witness_plan_approval_digest,
            },
            continuation,
        });
    }

    let (coordinator, retained) =
        diagnostic::host(B::ObservedOwnerSplit, || reviewed.into_owner_reads(host))?;
    if retained.len() != prepared_reads.len() {
        return Err(Error::Authentication);
    }
    let mut observations = Vec::with_capacity(2);
    let mut owners = Vec::with_capacity(2);
    // Prepare BOTH actual owner ceremonies before starting EITHER short-lived
    // native read. These are the same non-Clone retained owners and exact Host
    // approvals, with their originally captured deadlines, not renewed reviews.
    // Execution below asks no terminal questions, so finite input order is unchanged.
    let read_wave = prepare_read_wave(
        retained.into_iter().zip(prepared_reads),
        |(original, entry)| {
            check_scenario(original_scenario_deadline)?;
            let owner = born
                .get(entry.index)
                .filter(|owner| {
                    owner.index == entry.index
                        && owner.account_id == entry.plan.plan.enrollment().identity.account_id
                })
                .ok_or(Error::Authentication)?;
            coordinator.check_current(host)?;
            host.terminal.message(&format!(
                "SYNTHETIC_JOINED_READ_CONTINUATION_PATH={}\n",
                entry.continuation.signed_continuation_file().display()
            ))?;
            let prepared = diagnostic::host(B::ObservedReadPrepare, || {
                prepared_common_context_read_v3::prepare(host, &coordinator, original, &entry.plan)
            })?;
            if prepared.publication_request() != entry.continuation.request() {
                return Err(Error::Authentication);
            }
            Ok((entry, owner, prepared))
        },
    )?;
    // Only actual prepared owners enter this original-order execution wave.
    // The existing pair/publication/read checks still run at their effect boundaries.
    for (entry, owner, prepared) in read_wave {
        // Preparation can take time. Retain both original restriction checks
        // immediately before the history/server/native-open side effects too.
        check_scenario(original_scenario_deadline)?;
        coordinator.check_current(host)?;
        let witness = witnesses.for_original(owner)?;
        let (actual, read_operation, handoff_operation) = prepared.exact_read_parts();
        let expected = ExpectedCommonContextReadV3Input {
            plan: actual.plan.clone(),
            durable_receipt_digest: actual.durable_receipt_digest.clone(),
            witness_plan_approval_digest: actual.witness_plan_approval_digest.clone(),
            read_operation: read_operation.into(),
            handoff_operation: handoff_operation.into(),
        };
        let attempt_digest = match &prepared.publication_request().attempt {
            ManualRosterPublicationAttemptV2::ContinuationV2 {
                continuation_digest,
                ..
            } => continuation_digest,
            _ => return Err(Error::Authentication),
        };
        let history = diagnostic::host(B::ObservedReadHistory, || {
            witness
                .serve_original_roster_attempt_v2(
                    &entry.plan.plan.enrollment().identity.account_id,
                    &entry
                        .plan
                        .plan
                        .retained
                        .selection
                        .scope
                        .provenance
                        .witness_roster_extension_digest,
                    attempt_digest,
                )
                .map_err(|_| stage("newer original common-context history server"))
        })?;
        let peer = diagnostic::host(B::ObservedReadOpen, || {
            signers
                .send(Command::OpenCommonContextRead(
                    entry.index,
                    prepared.publication_request().clone(),
                    expected,
                ))
                .map_err(stage)?;
            receive_peer(signers)
        })?;
        let pending = diagnostic::host(B::ObservedReadPair, || {
            prepared.begin_pair(peer.provider, &peer.endpoint)
        })?;
        let (observation, operations) = diagnostic::host(B::ObservedReadFinish, || {
            signers
                .send(Command::PollCommonContextReadAndHandoff(entry.index))
                .map_err(stage)?;
            let result = pending.finish(&runtime)?;
            done(signers, entry.index)?;
            Ok(result)
        })?;
        // The same native controller stays alive until the Host's actual read
        // finishes. Only then drain/park its original for later fresh completion.
        diagnostic::host(B::ObservedReadPark, || {
            signers
                .send(Command::ParkCommonContextCompletion(entry.index))
                .map_err(stage)?;
            done(signers, entry.index)
        })?;
        drop(history);
        observations.push(observation);
        owners.push(ObservedJoinedOwnerV3 {
            signer_index: entry.index,
            operations,
        });
    }
    check_scenario(original_scenario_deadline)?;
    let roster = diagnostic::host(B::ObservedBarrier, || {
        let roster = coordinator.finish_all_handoff_observations(host, observations)?;
        roster.check_current(host)?;
        Ok(roster)
    })?;
    if owners.len() != 2
        || provider.served_requests() == 0
        || provider.denied_requests() != 0
        || host.require_financial_generation_admission().is_ok()
    {
        return Err(Error::Authentication);
    }
    // Deliberately no grant_request, completion reentry, Reserve/Consume or
    // construct_checkpoint. The real all-observations owner is the sole output.
    Ok(ObservedJoinedStageV3 {
        roster,
        owners,
        provider,
        runtime,
    })
}

// A private collect barrier, not a permission or owner constructor. On any
// preparation error it drops all already prepared values before returning; no
// execution callback exists here and no original can be cloned or reconstructed.
fn prepare_read_wave<I, P>(
    originals: I,
    prepare: impl FnMut(I::Item) -> Result<P>,
) -> Result<Vec<P>>
where
    I: IntoIterator,
{
    originals.into_iter().map(prepare).collect()
}

/// A separately named executable milestone, not completed construction. All
/// actual original births, audits and retained inputs occur in this same child.
pub(super) fn exercise_all_observations_stage(terminal: crate::terminal::Terminal) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(840);
    let mut scenario = super::initial_joined_v3::prepare(terminal)?;
    let retained = diagnostic::host(B::ObservedRetainedPredecessor, || {
        super::retained_joined_v3::retain_two(
            &scenario.host,
            &mut scenario.witness,
            &scenario.signers,
            &scenario.born,
            &scenario.roster_intents,
            &scenario.roster_requests,
            &scenario.roster_signed_extension_files,
            &scenario.roster_original_policy_files,
            scenario.expiry_ms,
            scenario.temporary.path(),
            deadline,
        )
    })?;
    let observed = observe_two(
        &scenario.host,
        &mut scenario.witness,
        &scenario.signers,
        &scenario.born,
        &scenario.roster_intents,
        &scenario.roster_signed_extension_files,
        scenario.temporary.path(),
        deadline,
        retained,
    )?;
    observed.roster.check_current(&scenario.host)?;
    let ObservedJoinedStageV3 {
        roster,
        owners,
        provider,
        runtime,
    } = observed;
    // Consume no grant or financial authorization simply to show test progress.
    // Actual owners are dropped before stopping their public provider runtime.
    drop(roster);
    drop(owners);
    diagnostic::host(B::ObservedProviderDrain, || {
        runtime
            .block_on(provider.shutdown())
            .map_err(|_| stage("finite provider drain"))
    })?;
    drop(runtime);
    drop(scenario);
    Ok(())
}

pub(super) fn inputs() -> Vec<Input<'static>> {
    let mut result = super::retained_joined_v3::inputs();
    let review = |detail| Input::ExactReview {
        detail,
        approve: true,
    };
    result.push(review("Approve this exact complete candidate for ONE non-signing local construction and encrypted private checkpoint"));
    for _ in 0..2 {
        result.push(review("Create this ONE new private full construction-plan file for the selected owner's separate native approval/signature/export"));
        result.push(Input::CapturedPath {
            marker: "SYNTHETIC_JOINED_SIGNED_FULL_PLAN_PATH=",
            prompt: "Exact privately exported V3 full-plan owner-signature JSON: ",
        });
        result.push(review("Read this exact private local file into the current non-signing host for authenticating this exact full plan"));
        result.push(Input::CapturedPath {
            marker: "SYNTHETIC_JOINED_ORIGINAL_ROSTER_PATH=",
            prompt: "Exact ORIGINAL private roster owner-signature JSON file: ",
        });
        for detail in [
            "Read this exact private local file into the current non-signing host for reviewing unchanged original account",
            "Inspect the complete protected ancestor capsule for exact manual-enrollment distinctness.",
            "Review the immutable original account owner for an exact additional-account roster AUDIT",
            "SYNTHETIC JOINED CONTROLLER TEST, NOT ATTENDED CONSENT.",
            "SYNTHETIC JOINED CONTROLLER TEST: approve only finite original-intent pairing metadata",
        ] {
            result.push(review(detail));
        }
    }
    for operations in [
        [
            "synthetic-read-audit-owner-1-v3",
            "synthetic-common-read-owner-1-v3",
            "synthetic-common-handoff-owner-1-v3",
            "synthetic-common-reentry-owner-1-v3",
            "synthetic-common-construct-owner-1-v3",
        ],
        [
            "synthetic-read-audit-owner-2-v3",
            "synthetic-common-read-owner-2-v3",
            "synthetic-common-handoff-owner-2-v3",
            "synthetic-common-reentry-owner-2-v3",
            "synthetic-common-construct-owner-2-v3",
        ],
    ] {
        for (prompt, response) in [
            "Exact new read-continuation Host audit key: ",
            "Distinct common-context read operation ID: ",
            "Distinct future-handoff preauthorization operation ID: ",
            "Distinct later transport-reentry operation ID: ",
            "Distinct later full-construction operation ID: ",
        ]
        .into_iter()
        .zip(operations)
        {
            result.push(Input::Text { prompt, response });
        }
        result.push(Input::CapturedPath {
            marker: "SYNTHETIC_JOINED_READ_CONTINUATION_PATH=",
            prompt: "Exact NEW private roster-continuation signature JSON for this original owner: ",
        });
        for detail in [
            "Read this exact private local file into the current non-signing host for reviewing the exact fresh continuation",
            "Inspect the complete protected ancestor capsule for exact manual-enrollment distinctness.",
            "Review the immutable original account owner for an exact additional-account roster AUDIT",
            "Retain this exact roster-bound audit under the original account ledger",
            "Pair once for this exact fresh original-account continuation.",
            "Publish this exact fresh V4 continuation against the same original V3/account ledger",
            "After exact publication, pair the SAME actual installed process for this full V3 common-context plan.",
            "After the separate native read admission, send one future construction-only transport preauthorization request",
            "Approve ONE additional exact-input observation separately from full-plan construction.",
        ] {
            result.push(review(detail));
        }
    }
    result
}

#[test]
fn actual_three_born_same_original_all_observations_preserve_refusal() {
    foreground_child("three-born-all-observations-v3", &inputs()).expect(
        "actual temporary same-owner all-observations barrier only; no Reserve, Consume, construction, proof, return, dispatch or attended qualification",
    );
}

#[test]
fn actual_read_wave_prepares_every_item_before_original_order_execution() {
    let events = std::cell::RefCell::new(Vec::new());
    let original = vec![(1, String::from("first")), (2, String::from("second"))];
    let prepared = prepare_read_wave(original, |(index, value)| {
        events.borrow_mut().push(("prepare", index));
        Ok((index, value))
    })
    .unwrap();
    for (index, value) in prepared {
        events.borrow_mut().push(("execute", index));
        assert_eq!(value, if index == 1 { "first" } else { "second" });
    }
    assert_eq!(
        *events.borrow(),
        vec![("prepare", 1), ("prepare", 2), ("execute", 1), ("execute", 2)],
    );
}

#[test]
fn failed_read_wave_drops_prepared_values_without_execution_or_retry() {
    struct InertPrepared<'a>(&'a std::cell::RefCell<Vec<(&'static str, usize)>>, usize);
    impl Drop for InertPrepared<'_> {
        fn drop(&mut self) {
            self.0.borrow_mut().push(("drop", self.1));
        }
    }
    let events = std::cell::RefCell::new(Vec::new());
    let result = prepare_read_wave([1, 2, 3], |index| {
        events.borrow_mut().push(("prepare", index));
        if index == 2 {
            return Err(Error::Permission);
        }
        Ok(InertPrepared(&events, index))
    });
    assert!(matches!(result, Err(Error::Permission)));
    assert_eq!(
        *events.borrow(),
        vec![("prepare", 1), ("prepare", 2), ("drop", 1)],
    );
}
