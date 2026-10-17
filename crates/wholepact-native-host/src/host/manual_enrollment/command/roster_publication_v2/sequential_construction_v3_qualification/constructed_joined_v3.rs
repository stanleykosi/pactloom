//! Actual all-observations owner through native handoff, fresh same-process
//! completion and the unchanged constructor. This synthetic milestone saves an
//! unsigned checkpoint; it does not prove, sign, submit or establish settlement.
#![cfg(all(test, feature = "synthetic-born-joined-qualification"))]

#[path = "constructed_joined_v3/proved_checkpoint_joined_v1.rs"]
pub(super) mod proved_checkpoint_joined_v1;

use super::joined_signer_worker_v1::{
    AGREEMENT_ID, JoinedSignerCommandV1 as Command, JoinedSignerReplyV1 as Reply,
    JoinedSignerWorkerV1, PublicJoinedBornV1,
};
use super::observed_joined_v3::ObservedJoinedStageV3;
use super::retained_joined_v3::CONSTRUCTION_KEY;
use super::safe_diagnostics_v1::{self as diagnostic, Boundary as B};
use super::*;
use crate::terminal::historical::HistoricalApproval;
use std::{collections::BTreeMap, os::unix::fs::DirBuilderExt, path::Path};
use wholepact_authority::native_witness_owner::{
    EphemeralHistoryServerV1, EphemeralNativeWitnessV1,
};
use wholepact_engine::born_offline_checkpoint_original_v1::PreparedBornOfflineCheckpointOriginalV1;
use wholepact_signer::native_ui::synthetic_born_joined_qualification::ExpectedCompletionOperationsV3Input;

/// The actual immutable Store checkpoint, not a receipt DTO or a successful
/// status flag. The same Host and signer worker remain owned by the caller.
/// Each signer worker slot now retains its actual consumed named predecessor.
/// This private read approval is neither ongoing proof consent nor admission.
pub(super) struct ConstructedJoinedStageV3<'host> {
    host: &'host Host,
    original: PreparedBornOfflineCheckpointOriginalV1<'host>,
    historical_read: HistoricalApproval,
    // Keep ALL actual server objects alive through construction and its final
    // checks. Sealing their accept loops does not extend their original clocks.
    history_servers: Vec<EphemeralHistoryServerV1>,
    provider: super::synthetic_born_provider_v1::SyntheticBornProviderV1,
    runtime: tokio::runtime::Runtime,
}

impl<'host> ConstructedJoinedStageV3<'host> {
    /// Borrow only actual historical checkpoint evidence while this exact
    /// native read remains valid. A later proof/carrier must obtain its own
    /// purpose-specific genuine approval and independently load this original.
    pub(super) fn original(
        &self,
        host: &Host,
    ) -> Result<&PreparedBornOfflineCheckpointOriginalV1<'host>> {
        if !std::ptr::eq(host, self.host) {
            return Err(Error::Authentication);
        }
        self.historical_read.check()?;
        host.require_manual_session()?;
        self.original.check_current(host.access()?)?;
        self.historical_read.check()?;
        Ok(&self.original)
    }
}

fn failed(label: &'static str) -> Error {
    Error::Receipt(format!(
        "synthetic actual-constructor stage failed: {label}"
    ))
}

fn check_scenario(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        Err(Error::Permission)
    } else {
        Ok(())
    }
}

/// Consume the SAME actual observed owner. The only public correlations select
/// already-existing original worker slots. No raw grant, claim or completion
/// supplied by a caller can substitute for a producer below.
#[allow(clippy::too_many_arguments)]
pub(super) fn construct_two<'host>(
    host: &'host Host,
    witness: &mut EphemeralNativeWitnessV1,
    signers: &JoinedSignerWorkerV1,
    born: &[PublicJoinedBornV1; 3],
    temporary_root: &Path,
    original_scenario_deadline: Instant,
    observed: ObservedJoinedStageV3<'host>,
) -> Result<ConstructedJoinedStageV3<'host>> {
    construct_two_inner(
        host,
        super::full_joined_v3::JoinedWitnessRouteV1::ConstructorOnly(witness),
        signers,
        born,
        temporary_root,
        original_scenario_deadline,
        observed,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn construct_two_with_original_witnesses<'host>(
    host: &'host Host,
    witnesses: &mut super::full_joined_v3::OriginalJoinedWitnessSetV1,
    signers: &JoinedSignerWorkerV1,
    born: &[PublicJoinedBornV1; 3],
    temporary_root: &Path,
    original_scenario_deadline: Instant,
    observed: ObservedJoinedStageV3<'host>,
) -> Result<ConstructedJoinedStageV3<'host>> {
    construct_two_inner(
        host,
        super::full_joined_v3::JoinedWitnessRouteV1::Distinct(witnesses),
        signers,
        born,
        temporary_root,
        original_scenario_deadline,
        observed,
    )
}

#[allow(clippy::too_many_arguments)]
fn construct_two_inner<'host>(
    host: &'host Host,
    mut witnesses: super::full_joined_v3::JoinedWitnessRouteV1<'_>,
    signers: &JoinedSignerWorkerV1,
    born: &[PublicJoinedBornV1; 3],
    temporary_root: &Path,
    original_scenario_deadline: Instant,
    observed: ObservedJoinedStageV3<'host>,
) -> Result<ConstructedJoinedStageV3<'host>> {
    diagnostic::host(B::ConstructedPredecessor, || {
        check_scenario(original_scenario_deadline)?;
        host.require_manual_session()?;
        observed.roster.check_current(host)?;
        if observed.owners.len() != 2 || host.require_financial_generation_admission().is_ok() {
            return Err(Error::Authentication);
        }
        Ok(())
    })?;
    let ObservedJoinedStageV3 {
        mut roster,
        owners,
        provider,
        runtime,
    } = observed;
    let pending_files = temporary_root.join("synthetic-actual-completion-grants-v3");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&pending_files)?;
    let mut history_servers = Vec::with_capacity(2);
    let mut originals = BTreeMap::new();

    for (participant, owner) in owners.into_iter().enumerate() {
        check_scenario(original_scenario_deadline)?;
        let actual_born = born
            .get(owner.signer_index)
            .filter(|original| {
                original.index == owner.signer_index && (1..=2).contains(&original.index)
            })
            .ok_or(Error::Authentication)?;
        let witness = witnesses.for_original(actual_born)?;
        let expected = ExpectedCompletionOperationsV3Input {
            reentry_operation: owner.operations.reentry.clone(),
            construction_operation: owner.operations.construction.clone(),
        };
        if originals
            .insert(
                actual_born.account_id.clone(),
                expected.construction_operation.clone(),
            )
            .is_some()
        {
            return Err(Error::Authentication);
        }
        // This is the production Host disclosure stage, not a fixture read of
        // grant_request without privacy approval. It rechecks the full barrier.
        let disclosed = diagnostic::host(B::ConstructedDisclosure, || {
            super::super::prepared_common_context_completion_v3::disclose_original(
                host,
                &roster,
                participant,
            )
        })?;
        let authorization = disclosed.authorization(&roster)?;
        if authorization.authorization.account_id != actual_born.account_id {
            return Err(Error::Authentication);
        }
        // Observe the real journal BEFORE publishing the native grant. The
        // immediately following scoped server must still consume that exact
        // completed Window receipt, never a replaced or invented native event.
        let original = diagnostic::host(B::ConstructedWitnessOriginal, || {
            witness
                .observe_original_roster_attempt_v2(&actual_born.account_id)
                .map_err(|_| failed("actual original witness attempt"))
        })?;
        if original
            .extension
            .account_extension
            .terms
            .identity
            .account_id
            != actual_born.account_id
            || original.attempt.attempt_digest != authorization.authorization.attempt_digest
            || original.attempt.sequence != authorization.authorization.attempt_sequence
        {
            return Err(Error::Authentication);
        }
        let authorization_bytes = zeroize::Zeroizing::new(serde_json::to_vec(authorization)?);
        let pending = diagnostic::host(B::ConstructedWitnessGrant, || {
            witness
                .review_original_construction_handoff_v1(
                    &actual_born.account_id,
                    &authorization_bytes,
                )
                .map_err(|_| failed("actual original witness native grant"))
        })?;
        if &pending.grant.authorization != authorization {
            return Err(Error::Authentication);
        }
        let pending_digest = pending.digest().map_err(|_| Error::Authentication)?;
        let (server, scope) = diagnostic::host(B::ConstructedWitnessScope, || {
            witness
                .serve_original_construction_handoff_scoped_v1(
                    &actual_born.account_id,
                    &original
                        .extension
                        .digest()
                        .map_err(|_| Error::Authentication)?,
                    &original.attempt.attempt_digest,
                    &pending_digest,
                )
                .map_err(|_| failed("actual one-use scoped witness server"))
        })?;
        // Immediately retain this actual server. In particular no prior server
        // is dropped just to let another account use the shared listener.
        history_servers.push(server);
        diagnostic::host(B::ConstructedPendingFile, || {
            let path =
                pending_files.join(format!("owner-{}-pending-grant.json", actual_born.index));
            let display = zeroize::Zeroizing::new(serde_json::to_vec(&serde_json::json!({
                "kind": "inert_pending_construction_transport_grant_v1",
                "notice": "Actual temporary witness native review output. Inert evidence only; no native authority or currentness is conveyed by this private file.",
                "pending_grant": pending,
            }))?);
            crate::files::write_new(&path, &display)?;
            host.terminal.message(&format!(
                "SYNTHETIC_JOINED_PENDING_GRANT_PATH={}\n",
                path.display()
            ))
        })?;
        let prepared = diagnostic::host(B::ConstructedPendingReview, || {
            disclosed.review_pending(&roster, owner.operations)
        })?;
        let original_deadline = prepared.original_deadline().min(original_scenario_deadline);
        diagnostic::host(B::ConstructedSignerOpen, || {
            signers
                .send(Command::OpenOriginalCompletion(
                    actual_born.index,
                    expected,
                    scope,
                ))
                .map_err(failed)?;
            // Actual reopen reported its locator to the retained original
            // provider. This reply is correlation only; pair_owner_before still
            // authenticates that same original process and fresh native scope.
            match signers.receive().map_err(failed)? {
                Reply::OriginalCompletionReady { index, deadline }
                    if index == actual_born.index && Instant::now() < deadline => Ok(()),
                _ => Err(Error::Authentication),
            }
        })?;
        diagnostic::host(B::ConstructedConsume, || {
            signers
                .send(Command::PollOriginalCompletionAndPark(actual_born.index))
                .map_err(failed)?;
            prepared.consume(&mut roster)
        })?;
        diagnostic::host(B::ConstructedSignerPark, || {
            match signers.receive().map_err(failed)? {
                Reply::Done { index } if index == actual_born.index => Ok(()),
                _ => Err(Error::Authentication),
            }
        })?;
        // Both actual consume and actual same-controller named park succeeded.
        // Seal NEW accepts before selecting another namespace's server, while
        // retaining the old server/liveness owner through constructor checks.
        diagnostic::host(B::ConstructedServerSeal, || {
            history_servers
                .last()
                .ok_or(Error::Authentication)?
                .seal_new_connections(original_deadline)
                .map_err(|_| failed("original witness accept seal"))?;
            roster.check_current(host)
        })?;
    }

    diagnostic::host(B::ConstructedCheckpoint, || {
        check_scenario(original_scenario_deadline)?;
        if history_servers.len() != 2 || originals.len() != 2 {
            return Err(Error::Authentication);
        }
        // This consuming production method alone admits the actual retained
        // wallet/source/native owners to Engine and its immutable claim/job.
        // Never retry this call after any error or uncertain durable outcome.
        roster.construct_checkpoint(host)
    })?;
    let (original, historical_read) = diagnostic::host(B::ConstructedSavedOriginal, || {
        let approval = host.terminal.approve_historical(
            "SYNTHETIC JOINED CONTROLLER TEST: read the actual encrypted Store's complete bounded private construction claim and saved checkpoint after the unchanged constructor returned. Retain only this original agreement/key association for the next separately approved stage. Other accounts and private input facts can be read but are not displayed or exported. No proof, source renewal, signature, admission or dispatch is approved. This does not assert a verified proof or attended consent.",
        )?;
        let mut actual = None;
        approval.effect(&mut || {
            approval.check()?;
            host.require_manual_session()?;
            let prepared = host.engine.prepare_born_offline_checkpoint_original_v1(
                host.access()?,
                AGREEMENT_ID,
                CONSTRUCTION_KEY,
            )?;
            if prepared.claim().consumed.len() != 2
                || prepared.claim().construction_key != CONSTRUCTION_KEY
                || prepared.proposal().manifest().agreement.agreement_id != AGREEMENT_ID
            {
                return Err(Error::Authentication);
            }
            for consumed in &prepared.claim().consumed {
                let enrollment = consumed.request.plan.enrollment();
                let born = born[1..]
                    .iter()
                    .find(|b| b.account_id == enrollment.identity.account_id)
                    .ok_or(Error::Authentication)?;
                if originals.get(&born.account_id) != Some(&consumed.request.operation_id)
                    || born.full_viewing_key_digest != enrollment.identity.full_viewing_key_digest
                    || born.participant_id != enrollment.scope.participant_id
                {
                    return Err(Error::Authentication);
                }
            }
            prepared.check_current(host.access()?)?;
            approval.check()?;
            actual = Some(prepared);
            Ok(())
        })?;
        Ok((actual.ok_or(Error::Authentication)?, approval))
    })?;
    diagnostic::host(B::ConstructedInvariant, || {
        check_scenario(original_scenario_deadline)?;
        original.check_current(host.access()?)?;
        historical_read.check()?;
        if provider.served_requests() == 0
            || provider.denied_requests() != 0
            || host.require_financial_generation_admission().is_ok()
        {
            return Err(Error::Authentication);
        }
        Ok(())
    })?;
    Ok(ConstructedJoinedStageV3 {
        host,
        original,
        historical_read,
        history_servers,
        provider,
        runtime,
    })
}

/// Bounded same-scenario executable boundary. This deliberately stops before
/// actual saved proof execution and all financial signing/dispatch operations.
pub(super) fn exercise_constructed_checkpoint_stage(
    terminal: crate::terminal::Terminal,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(840);
    let mut scenario = super::initial_joined_v3::prepare(terminal)?;
    let retained = super::retained_joined_v3::retain_two(
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
    )?;
    let observed = super::observed_joined_v3::observe_two(
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
    let constructed = construct_two(
        &scenario.host,
        &mut scenario.witness,
        &scenario.signers,
        &scenario.born,
        scenario.temporary.path(),
        deadline,
        observed,
    )?;
    constructed.original(&scenario.host)?;
    let ConstructedJoinedStageV3 {
        original,
        historical_read,
        history_servers,
        provider,
        runtime,
        ..
    } = constructed;
    drop(original);
    drop(historical_read);
    drop(history_servers);
    diagnostic::host(B::ConstructedProviderDrain, || {
        runtime
            .block_on(provider.shutdown())
            .map_err(|_| failed("finite provider drain"))
    })?;
    drop(runtime);
    drop(scenario);
    Ok(())
}

pub(super) fn inputs() -> Vec<Input<'static>> {
    let mut inputs = super::observed_joined_v3::inputs();
    let review = |detail| Input::ExactReview {
        detail,
        approve: true,
    };
    for _ in 0..2 {
        inputs.push(review("Display this one exact original-owner signed handoff preauthorization for manual relay"));
        inputs.push(Input::CapturedPath {
            marker: "SYNTHETIC_JOINED_PENDING_GRANT_PATH=",
            prompt: "Exact native witness pending-grant DISPLAY JSON file (kind, notice, pending_grant): ",
        });
        for detail in [
            "Read this exact private local file into the current non-signing host for binding the separately issued inert pending grant",
            "Display the exact inert pending-grant digest and original attempt digest",
            "Wait for a genuinely fresh original-account completion unlock in the SAME still-running installed signer",
            "Send one exact completion request using this pending grant and the actual fresh caller",
        ] {
            inputs.push(review(detail));
        }
    }
    inputs.push(review("SYNTHETIC JOINED CONTROLLER TEST: read the actual encrypted Store's complete bounded private construction claim"));
    inputs
}

#[test]
fn actual_three_born_same_original_constructor_retains_checkpoint_and_refusal() {
    foreground_child("three-born-constructed-checkpoint-v3", &inputs()).expect(
        "actual temporary native completion and unsigned checkpoint only; no proof, signature, return, dispatch, settlement or attended qualification",
    );
}
