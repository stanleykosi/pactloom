//! Sequential actual-owner assembly. Native selection windows never overlap:
//! each owner is already explicitly retained under its fixed original invocation.
//! No retained receipt or proposal JSON can create this private owner.
use super::{Host, retained_inputs::RetainedRosterCandidateInputsV2};
use crate::{Error, Result};
use std::collections::{BTreeMap, BTreeSet};
use wholepact_core::{
    Amount, ClaimedInput, ClaimedOutput, OutputAllocation, Proposal, ProposalInput,
    ProposalManifest,
    manual_candidate_selection::{ManualCandidateEconomicIntent, ManualCandidateInvocation},
    manual_construction::{ManualConstructionInput, ManualSelectionContext},
    manual_roster_construction_v2::{
        ManualRosterConstructionPlanV2, ManualRosterRetentionCommitmentV2,
    },
};

/// No Clone/Deserialize, raw contribution or raw builder conversion. Every
/// retained owner owns its original fresh wallet, real native durable receipt,
/// local provenance and fixed completion deadline; no simultaneous focus exists.
pub(in crate::host) struct UnreviewedRosterManualCandidateV2<'host> {
    proposal: Proposal,
    owners: Vec<RetainedRosterCandidateInputsV2<'host>>,
}
impl<'host> UnreviewedRosterManualCandidateV2<'host> {
    pub(in crate::host) fn assemble(
        host: &Host,
        owners: Vec<RetainedRosterCandidateInputsV2<'host>>,
    ) -> Result<Self> {
        if !(2..=32).contains(&owners.len()) {
            return Err(Error::Invalid);
        }
        for owner in &owners {
            owner.check_current(host)?;
        }
        let proposal = assemble_current_claims(host, &owners)?;
        let result = Self { proposal, owners };
        result.check_current(host)?;
        Ok(result)
    }
    pub(in crate::host) fn check_current(&self, host: &Host) -> Result<()> {
        for owner in &self.owners {
            owner.check_current(host)?;
        }
        Ok(())
    }
    pub(in crate::host) fn display_current(&self, host: &Host) -> Result<()> {
        self.check_current(host)?;
        host.terminal.message("UNREVIEWED complete historical actual-input candidate. Current same-input observation is separately required before construction. Exact private contributions have been explicitly retained for sequential review. No construction, witness reservation, proof, signature, release or dispatch has occurred.\n")?;
        host.terminal.json(self.proposal.input())?;
        self.check_current(host)
    }
    /// Build inert exact full-proposal review material only from all actual
    /// retained owners. Native witness approval and one-use Consume remain
    /// separate and cannot be inferred from this plan.
    fn construction_plans(&self, host: &Host) -> Result<Vec<ManualRosterConstructionPlanV2>> {
        self.check_current(host)?;
        let mut commitments = Vec::with_capacity(self.owners.len());
        for owner in &self.owners {
            let request = owner.request(host)?;
            let enrollment = &request.selection.scope.selection.inventory.enrollment;
            commitments.push(ManualRosterRetentionCommitmentV2 {
                participant_id: enrollment.scope.participant_id.clone(),
                account_id: enrollment.identity.account_id.clone(),
                full_viewing_key_digest: enrollment.identity.full_viewing_key_digest.clone(),
                retention_request_digest: request.digest().map_err(|_| Error::Invalid)?,
                retention_evidence_digest: owner.retention_evidence_digest(host)?,
            });
        }
        commitments.sort_by(|a, b| a.participant_id.cmp(&b.participant_id));
        let mut plans = Vec::with_capacity(self.owners.len());
        for owner in &self.owners {
            let plan = ManualRosterConstructionPlanV2 {
                version: 2,
                retained: owner.request(host)?.clone(),
                retained_evidence_digest: owner.retention_evidence_digest(host)?,
                proposal: self.proposal.input().clone(),
                participants: commitments.clone(),
            };
            if plan.validate().map_err(|_| Error::Invalid)? != self.proposal {
                return Err(Error::Authentication);
            }
            plans.push(plan);
        }
        self.check_current(host)?;
        Ok(plans)
    }
    /// Fresh foreground Host approval occurs AFTER sequential native retention,
    /// when there is no live selection GUI lease to keep focused. It reviews all
    /// actual inputs/outputs and complete disclosure facts, not placeholders.
    pub(in crate::host) fn review_full_candidate_before_construction(
        self,
        host: &Host,
        construction_key: String,
        maximum_actions: usize,
    ) -> Result<ReviewedRosterManualCandidateV2<'host>> {
        if !(16..=128).contains(&construction_key.len())
            || !construction_key.bytes().all(|b| (33..=126).contains(&b))
            || !(1..=8).contains(&maximum_actions)
        {
            return Err(Error::Invalid);
        }
        let plans = self.construction_plans(host)?;
        let expected_key = wholepact_store::request_digest(&serde_json::json!([
            &host.access()?.principal_id,
            &construction_key
        ]))?;
        if plans.iter().any(|p| {
            p.retained
                .selection
                .scope
                .selection
                .invocation
                .idempotency_key_digest
                != expected_key
        }) {
            return Err(Error::Authentication);
        }
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:host-roster-full-construction-review:v2",
            &(&plans, &construction_key, maximum_actions),
        )
        .map_err(|_| Error::Invalid)?;
        self.check_current(host)?;
        let approval = host.terminal.approve_publication(&digest, &format!(
            "Approve this exact complete candidate for ONE non-signing local construction and encrypted private checkpoint, only after every owner separately obtains a fresh genuine native continuation and exact witness Reserve/Consume.\n{}\nEach plan names the actual inputs/nullifiers, same-account return, complete reviewer roster, chosen operator, destination, provider and retention policy. Retention lasts only to the original invocation expiry. This does not prove unspentness, sign, release, dispatch, retry randomized construction or approve future work. A durable invocation claim precedes any builder randomness; an ambiguous missing checkpoint is fenced and cannot be rebuilt.",
            serde_json::to_string_pretty(&(&plans, &construction_key, maximum_actions))?,
        ))?;
        // Move the exact owner through the held terminal's two-phase contract.
        // The terminal rechecks its own deadline and foreground after prepare,
        // before admitting the operation that creates the reviewed owner.
        approval.commit(
            &digest,
            || {
                self.check_current(host)?;
                Ok(self)
            },
            |candidate| {
                candidate.check_current(host)?;
                Ok(ReviewedRosterManualCandidateV2 {
                    candidate,
                    plans,
                    review_digest: digest.clone(),
                    construction_key,
                    maximum_actions,
                })
            },
        )
    }
}
/// Opaque full Host decision. Only this private producer creates it; keeping it
/// never renews original lineage, local permission or invocation expiration.
pub(in crate::host) struct ReviewedRosterManualCandidateV2<'host> {
    candidate: UnreviewedRosterManualCandidateV2<'host>,
    plans: Vec<ManualRosterConstructionPlanV2>,
    review_digest: String,
    construction_key: String,
    maximum_actions: usize,
}
impl ReviewedRosterManualCandidateV2<'_> {
    pub(in crate::host) fn check_current(&self, host: &Host) -> Result<()> {
        self.candidate.check_current(host)?;
        if self.review_digest
            != wholepact_core::proposal::canonical_digest(
                "wholepact:host-roster-full-construction-review:v2",
                &(&self.plans, &self.construction_key, self.maximum_actions),
            )
            .map_err(|_| Error::Invalid)?
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    pub(in crate::host) fn exact_retained_owner(
        &self, host: &Host, plan: &ManualRosterConstructionPlanV2,
    ) -> Result<&wholepact_signer::authority_bridge::manual_roster_candidate_selection_v2::SignerRetainedRosterContributionV2>{
        self.check_current(host)?;
        if !self.plans.contains(plan) {
            return Err(Error::Authentication);
        }
        let mut matching = self.candidate.owners.iter().filter(|owner| {
            owner
                .request(host)
                .is_ok_and(|request| request == &plan.retained)
        });
        let owner = matching.next().ok_or(Error::Authentication)?;
        if matching.next().is_some() {
            return Err(Error::Authentication);
        }
        owner.native_retained(host)
    }
    pub(in crate::host) fn original_completion_deadline(
        &self,
        host: &Host,
    ) -> Result<std::time::Instant> {
        self.check_current(host)?;
        self.candidate
            .owners
            .iter()
            .map(|owner| owner.original_completion_deadline())
            .min()
            .ok_or(Error::Invalid)
    }
    /// Create-once private exact-plan export, separately approved for the native
    /// owner-signature ceremony. The file remains inert and cannot recreate any
    /// retained wallet owner or substitute for the eventual current witness.
    pub(in crate::host) fn export_native_plan(
        &self,
        host: &Host,
        plan: &ManualRosterConstructionPlanV2,
        path: &std::path::Path,
    ) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        self.check_current(host)?;
        if !self.plans.contains(plan) {
            return Err(Error::Authentication);
        }
        let check = || -> Result<()> {
            self.check_current(host)?;
            host.directory.external_destination(path)?;
            host.financial
                .as_ref()
                .ok_or(Error::Locked)?
                .directory
                .external_destination(path)?;
            for owner in &self.candidate.owners {
                owner.require_external_destination(host, path)?;
            }
            let parent = path.parent().ok_or(Error::Invalid)?;
            let metadata = std::fs::symlink_metadata(parent)?;
            if !metadata.is_dir()
                || metadata.mode() & 0o077 != 0
                || metadata.uid() != unsafe { libc::geteuid() }
            {
                return Err(Error::Permission);
            }
            Ok(())
        };
        check()?;
        let digest = plan.digest().map_err(|_| Error::Invalid)?;
        let approval = host.terminal.approve_publication(&digest, &format!(
            "Create this ONE new private full construction-plan file for the selected owner's separate native approval/signature/export, then independent witness-owner review.\nDestination: {}\nExact plan: {}\nThis file includes actual private input identifiers, nullifiers, values, return and complete participant terms. It grants no source, native, witness, builder or spending authority. No overwrite or automatic transmission is permitted.", path.display(), digest,
        ))?;
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec_pretty(plan)?);
        approval.commit(&digest, check, |_| crate::files::write_new(path, &bytes))?;
        self.check_current(host)
    }
    /// Inert request bytes for the separate actual installed native ceremony.
    /// This is not a contribution, builder token, native or witness permission.
    pub(in crate::host) fn exact_native_plans(
        &self,
        host: &Host,
    ) -> Result<&[ManualRosterConstructionPlanV2]> {
        self.check_current(host)?;
        Ok(&self.plans)
    }
}

fn assemble_current_claims(
    host: &Host,
    owners: &[RetainedRosterCandidateInputsV2<'_>],
) -> Result<Proposal> {
    let first = owners.first().ok_or(Error::Invalid)?.request(host)?;
    let intent = &first.selection.scope.selection.economic_intent;
    let invocation = &first.selection.scope.selection.invocation;
    let mut facts = Vec::with_capacity(owners.len());
    let mut viewing_authorities = BTreeSet::new();
    for owner in owners {
        let retained = owner.request(host)?;
        let request = &retained.selection;
        retained.validate().map_err(|_| Error::Invalid)?;
        require_common_intent(
            intent,
            invocation,
            &request.scope.selection.economic_intent,
            &request.scope.selection.invocation,
        )?;
        let enrollment = &request.scope.selection.inventory.enrollment;
        require_unique_viewing_authority(&mut viewing_authorities, &enrollment.identity)?;
        let debit = request
            .scope
            .requested_debit_zatoshis()
            .map_err(|_| Error::Invalid)?;
        let total = debit
            .checked_add(retained.change_value_zatoshis)
            .ok_or(Error::Invalid)?;
        wholepact_protocol::review::decode_testnet_receiver(&retained.change_address)
            .map_err(|_| Error::Invalid)?;
        facts.push(CandidateInputFacts {
            participant_id: &enrollment.scope.participant_id,
            account_id: &enrollment.identity.account_id,
            requested_debit_zatoshis: debit,
            selected_zatoshis: total,
            inputs: &retained.selected_inputs,
            context: &retained.selection_context,
            change_address: &retained.change_address,
        });
    }
    let proposal = reconcile_actual_facts(intent, &facts)?;
    for (owner, actual) in owners.iter().zip(&facts) {
        let retained = owner.request(host)?;
        let scope = &retained.selection.scope.selection;
        let (checked, returns) = scope
            .original_policy_origin
            .recipient_policy
            .validate_candidate_for_enrollment(&scope.inventory.enrollment, proposal.input())
            .map_err(|_| Error::Permission)?;
        if checked != proposal
            || returns.len() != usize::from(retained.change_value_zatoshis > 0)
            || returns.iter().any(|r| {
                r.address != actual.change_address
                    || r.amount_zatoshis != retained.change_value_zatoshis
            })
        {
            return Err(Error::Permission);
        }
        owner.check_current(host)?;
    }
    Ok(proposal)
}

/// Pure uniqueness guard. Authentication comes exclusively from the production
/// caller's concrete held native lease; accepting inert identity data here does
/// not create a lease, a maintained selection or a candidate owner.
fn require_unique_viewing_authority<'a>(
    seen: &mut BTreeSet<&'a str>,
    identity: &'a wholepact_core::manual_enrollment::ManualAccountIdentity,
) -> Result<()> {
    if !canonical_hash(&identity.full_viewing_key_digest)
        || !seen.insert(identity.full_viewing_key_digest.as_str())
    {
        return Err(Error::Permission);
    }
    Ok(())
}

fn require_common_intent(
    intent: &ManualCandidateEconomicIntent,
    invocation: &ManualCandidateInvocation,
    actual_intent: &ManualCandidateEconomicIntent,
    actual_invocation: &ManualCandidateInvocation,
) -> Result<()> {
    if intent != actual_intent || invocation != actual_invocation {
        return Err(Error::Permission);
    }
    Ok(())
}

/// Inert borrowed facts used only inside the private projection. Tests may model
/// these facts; neither they nor a Proposal can create SelectedRosterCandidateInputsV2,
/// a native lease or UnreviewedRosterManualCandidateV2.
struct CandidateInputFacts<'a> {
    participant_id: &'a str,
    account_id: &'a str,
    requested_debit_zatoshis: u64,
    selected_zatoshis: u64,
    inputs: &'a [ManualConstructionInput],
    context: &'a ManualSelectionContext,
    change_address: &'a str,
}

fn reconcile_actual_facts(
    intent: &ManualCandidateEconomicIntent,
    facts: &[CandidateInputFacts<'_>],
) -> Result<Proposal> {
    let debits = intent.validate().map_err(|_| Error::Invalid)?;
    if intent.agreement.network_profile_id != wholepact_protocol::construction::PROFILE_ID
        || facts.len() != intent.participants.len()
    {
        return Err(Error::Invalid);
    }
    let common = facts.first().ok_or(Error::Invalid)?.context;
    validate_context(common, intent.expiry_height)?;
    let mut participants = BTreeMap::new();
    let mut accounts = BTreeSet::new();
    let mut all_inputs = BTreeSet::new();
    let mut all_nullifiers = BTreeSet::new();
    for actual in facts {
        if actual.context != common
            || !accounts.insert(actual.account_id)
            || participants.insert(actual.participant_id, actual).is_some()
            || actual.inputs.is_empty()
            || actual.inputs.len() > 256
        {
            return Err(Error::Invalid);
        }
        let mut total = 0u64;
        let mut previous = None;
        for input in actual.inputs {
            if input.input_id.is_empty()
                || previous.is_some_and(|id: &str| id >= input.input_id.as_str())
                || !all_inputs.insert(input.input_id.as_str())
                || !canonical_hash(&input.nullifier)
                || !all_nullifiers.insert(input.nullifier.as_str())
                || input.value_zatoshis == 0
            {
                return Err(Error::Invalid);
            }
            total = total
                .checked_add(input.value_zatoshis)
                .filter(|sum| *sum <= wholepact_core::MAX_MONEY)
                .ok_or(Error::Invalid)?;
            previous = Some(input.input_id.as_str());
        }
        if total != actual.selected_zatoshis {
            return Err(Error::Invalid);
        }
    }
    let mut inputs = Vec::new();
    let mut outputs: Vec<_> = intent
        .agreement
        .recipients
        .iter()
        .enumerate()
        .map(|(n, r)| ClaimedOutput {
            output_id: format!("candidate-recipient-{n}"),
            address: r.address.clone(),
            amount: r.amount,
            allocation: OutputAllocation::Recipient {
                recipient_id: r.recipient_id.clone(),
            },
        })
        .collect();
    for (n, participant) in intent.participants.iter().enumerate() {
        let actual = participants
            .get(participant.participant_id.as_str())
            .ok_or(Error::Invalid)?;
        let debit = debits
            .get(&participant.participant_id)
            .ok_or(Error::Invalid)?
            .as_zatoshis();
        if actual.account_id != participant.account_id || actual.requested_debit_zatoshis != debit {
            return Err(Error::Invalid);
        }
        for input in actual.inputs {
            inputs.push(ClaimedInput {
                input_id: input.input_id.clone(),
                participant_id: participant.participant_id.clone(),
                account_id: participant.account_id.clone(),
                amount: Amount::from_zatoshis(input.value_zatoshis).map_err(|_| Error::Invalid)?,
                // Native/local source authority is held privately, not represented
                // by a portable caller-invented ownership evidence identifier.
                ownership_evidence_ref: None,
            });
        }
        for (charge_index, charge) in participant.charges.iter().enumerate() {
            outputs.push(ClaimedOutput {
                output_id: format!("candidate-charge-{n}-{charge_index}"),
                address: charge.address.clone(),
                amount: charge.amount,
                allocation: OutputAllocation::Charge {
                    participant_id: participant.participant_id.clone(),
                    charge_id: charge.charge_id.clone(),
                },
            });
        }
        let change = actual
            .selected_zatoshis
            .checked_sub(debit)
            .ok_or(Error::Invalid)?;
        if change > 0 {
            outputs.push(ClaimedOutput {
                output_id: format!("candidate-return-{n}"),
                address: actual.change_address.to_owned(),
                amount: Amount::from_zatoshis(change).map_err(|_| Error::Invalid)?,
                allocation: OutputAllocation::Return {
                    participant_id: participant.participant_id.clone(),
                    account_id: participant.account_id.clone(),
                    ownership_evidence_ref: None,
                },
            });
        }
    }
    if inputs.len() > 256 || outputs.len() > 256 {
        return Err(Error::Invalid);
    }
    let proposal = ProposalInput {
        proposal_id: intent.proposal_id.clone(),
        previous_proposal_id: intent.previous_proposal_id.clone(),
        created_at: intent.created_at.clone(),
        manifest: ProposalManifest {
            agreement: intent.agreement.clone(),
            participants: intent.participants.clone(),
            inputs,
            outputs,
            transaction_fee: intent.transaction_fee,
            expiry_height: intent.expiry_height,
        },
        artifact_digest: None,
        effects_commitment: None,
    };
    // require_proposal runs Proposal::validate and exact economic equality. It
    // grants no native review, transaction-effects verification or key authority.
    intent
        .require_proposal(&proposal)
        .map_err(|_| Error::Invalid)
}
fn canonical_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn validate_context(context: &ManualSelectionContext, expiry_height: u32) -> Result<()> {
    if context.anchor_height == 0
        || context.tip_height < context.anchor_height
        || context
            .tip_height
            .checked_add(1)
            .is_none_or(|target| target > expiry_height)
        || !canonical_hash(&context.tip_hash_protocol)
        || !canonical_hash(&context.anchor_hash_protocol)
        || !canonical_hash(&context.anchor_root)
    {
        return Err(Error::Invalid);
    }
    Ok(())
}

#[cfg(test)]
#[path = "manual_roster_candidate_assembly_v2_tests.rs"]
mod tests;

/// Pure resource arithmetic only; actual clocks and opaque native/Host owners
/// supply all four bounds in production. This helper cannot grant a read.
fn exact_wave_budget(
    remaining: std::time::Duration,
    runtime: std::time::Duration,
    ttl: std::time::Duration,
    runway: std::time::Duration,
) -> Result<std::time::Duration> {
    if runtime.is_zero() || runway.is_zero() {
        return Err(Error::Permission);
    }
    let original = remaining
        .checked_sub(runway)
        .filter(|d| !d.is_zero())
        .ok_or(Error::Permission)?;
    let fresh = ttl
        .checked_sub(runway)
        .filter(|d| !d.is_zero())
        .ok_or(Error::Permission)?;
    Ok(runtime.min(original).min(fresh))
}

impl ReviewedRosterManualCandidateV2<'_> {
    pub(in crate::host) fn construct_exact_checkpoint(
        self,
        host: &Host,
        admitted: Vec<wholepact_signer_origin::AdmittedManualRosterConstructionContributionV2>,
        reads: Vec<crate::authority::manual_roster_exact_input_observation_v1::HostAdmittedRosterExactInputObservationV1>,
    ) -> Result<()> {
        use wholepact_core::manual_roster_exact_input_observation_v1::{
            EXACT_OBSERVATION_MAX_SCAN_RUNTIME_MS, EXACT_OBSERVATION_POST_SCAN_RUNWAY_MS,
            EXACT_OBSERVATION_SOURCE_TTL_MS,
        };
        use wholepact_wallet::wallet::protected_sync::exact_input_observation::{
            ExactInputWalletSlot, with_exact_input_roster,
        };
        self.check_current(host)?;
        if !(2..=8).contains(&admitted.len())
            || admitted.len() != self.candidate.owners.len()
            || reads.len() != admitted.len()
        {
            return Err(Error::Authentication);
        }
        let mut completion_deadline = self.original_completion_deadline(host)?;
        for ((plan, native), read) in self.plans.iter().zip(&admitted).zip(&reads) {
            native.check_completion().map_err(|_| Error::Permission)?;
            if native.request().map_err(|_| Error::Permission)?.plan != *plan
                || read.request()?.plan != *plan
            {
                return Err(Error::Authentication);
            }
            completion_deadline = completion_deadline.min(read.completion_deadline()?);
        }
        let wave_start = std::time::Instant::now();
        let remaining = completion_deadline
            .checked_duration_since(wave_start)
            .ok_or(Error::Permission)?;
        let runway = std::time::Duration::from_millis(EXACT_OBSERVATION_POST_SCAN_RUNWAY_MS);
        let scan_budget = exact_wave_budget(
            remaining,
            std::time::Duration::from_millis(EXACT_OBSERVATION_MAX_SCAN_RUNTIME_MS),
            std::time::Duration::from_millis(EXACT_OBSERVATION_SOURCE_TTL_MS),
            runway,
        )?;
        let wave_deadline = wave_start.checked_add(scan_budget).ok_or(Error::Invalid)?;
        let Self {
            candidate,
            plans,
            review_digest: _,
            construction_key,
            maximum_actions,
        } = self;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| Error::Storage)?;
        // One final wave; at most two public scans are polled concurrently.
        // Timer/drop revokes in-flight transitions. No retry/rescan/reselection.
        // A timer cannot preempt a synchronous scan batch, SQLite/fsync or builder.
        let refreshed = runtime.block_on(async {
            tokio::time::timeout_at(tokio::time::Instant::from_std(wave_deadline), async {
                let mut pending = candidate.owners.into_iter().zip(reads);
                let mut values = Vec::with_capacity(admitted.len());
                while let Some((first, first_read)) = pending.next() {
                    if let Some((second, second_read)) = pending.next() {
                        let (a, b) = tokio::join!(
                            first.refresh_exact_inputs(host, first_read),
                            second.refresh_exact_inputs(host, second_read),
                        );
                        values.push(a?); values.push(b?);
                    } else {
                        values.push(first.refresh_exact_inputs(host, first_read).await?);
                    }
                }
                Ok::<_, Error>(values)
            }).await.map_err(|_| Error::Receipt(
                "Exact-input observation timed out; partial scan progress may remain. Original exposure is unchanged. Do not repeat this invocation".into()))?
        })?;
        let mut contributions = Vec::with_capacity(admitted.len());
        let mut sources = Vec::with_capacity(admitted.len());
        let mut observations = Vec::with_capacity(admitted.len());
        let mut snapshots = Vec::with_capacity(admitted.len());
        for ((retained, source, observation, snapshot), native) in
            refreshed.into_iter().zip(admitted)
        {
            contributions.push((retained, native));
            sources.push(source);
            observations.push(observation);
            snapshots.push(snapshot);
        }
        let mut plans = plans;
        plans.sort_by(|a, b| {
            a.enrollment()
                .scope
                .participant_id
                .cmp(&b.enrollment().scope.participant_id)
        });
        let primary = host.financial.as_ref().ok_or(Error::Locked)?;
        primary.inventory()?;
        let mut excluded = primary.exact_input_excluded_origins()?;
        excluded.push(host.engine.manual_roster_store_origin_fail_fast()?);
        let mut wallets = Vec::with_capacity(sources.len());
        let mut checks = Vec::with_capacity(sources.len());
        for source in &mut sources {
            let (wallet, check) = source.split();
            check.check_original_account()?;
            wallets.push(wallet);
            checks.push(check);
        }
        let mut slots = Vec::with_capacity(wallets.len());
        for (((wallet, check), snapshot), observation) in wallets
            .into_iter()
            .zip(&checks)
            .zip(&snapshots)
            .zip(&observations)
        {
            slots.push(ExactInputWalletSlot::new(
                wallet,
                snapshot,
                observation,
                check,
            )?);
        }
        let restriction = HostRosterConstructionRestrictionV2 {
            host,
            sources: &checks,
            observations: &observations,
            plans,
            construction_key: &construction_key,
            maximum_actions,
        };
        restriction.check()?;
        // Diagnostic only. Its lifetime extends past EVERY nested final check
        // and commit, including an error after the leaf already returned success.
        let progress = wholepact_engine::manual_roster_construct_v2::ManualRosterConstructionProgressV2::default();
        let outcome = with_exact_input_roster(slots, &excluded, |held| {
            host.engine.checkpoint_manual_roster_from_retained_v2(
                host.access()?, &construction_key,
                wholepact_engine::manual_roster_construct_v2::ManualRosterPrivateConstructionV2 {
                    contributions, jobs: &primary.proof, maximum_actions,
                    restriction: &restriction, held, progress: &progress,
                },
            ).map_err(Error::from)
        });
        let pending = exact_outer_result(&progress, &construction_key, outcome)?;
        // Wallet final checks and commits have now all unwound. The independent
        // original native construction owners can have an EARLIER deadline than
        // the exact-read owners, so check them and the original restriction again
        // before the opaque pending result releases any safe metadata.
        let result = exact_outer_result(
            &progress,
            &construction_key,
            pending.finish().map_err(Error::from),
        )?;
        // Final source-owner sample before output. It cannot undo a durable
        // claim or promise atomic timing across a subsequent terminal write.
        exact_outer_result(
            &progress,
            &construction_key,
            restriction.check_observations(),
        )?;
        exact_outer_result(&progress, &construction_key, host.terminal.json(&result))?;
        Ok(())
    }
}
fn exact_outer_result<T>(
    progress: &wholepact_engine::manual_roster_construct_v2::ManualRosterConstructionProgressV2,
    construction_key: &str,
    result: Result<T>,
) -> Result<T> {
    use wholepact_engine::manual_roster_construct_v2::ManualRosterConstructionOuterErrorV2;
    progress
        .classify_outer_result(result)
        .map_err(|error| match error {
            ManualRosterConstructionOuterErrorV2::BeforeClaim(error) => error,
            ManualRosterConstructionOuterErrorV2::ClaimMayExist(_) => {
                exact_claim_uncertain_error(construction_key, progress.claim_digest().as_deref())
            }
        })
}
fn exact_claim_uncertain_error(construction_key: &str, claim_digest: Option<&str>) -> Error {
    // Exact safe correlation survives the outer callback/COMMIT/output error.
    // This is not a new invocation or permission to retry randomized work.
    let correlation = serde_json::json!({
        "construction_key": construction_key, "claim_digest": claim_digest,
        "claim_may_be_durable": true, "randomized_retry_allowed": false,
        "journals_are_atomic_together": false,
    });
    Error::Receipt(format!(
        "An exact construction claim MAY already be durable, including after a wallet final-check, commit or output error. Correlation: {correlation}. Preserve the original key and every journal. Only manual-roster-construction-inspect-v2 may inspect the original outcome; never regenerate this invocation"
    ))
}
impl From<wholepact_wallet::wallet::protected_sync::exact_input_observation::ExactObservationError>
    for Error
{
    fn from(
        error: wholepact_wallet::wallet::protected_sync::exact_input_observation::ExactObservationError,
    ) -> Self {
        use wholepact_wallet::wallet::protected_sync::exact_input_observation::ExactObservationError as E;
        #[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
        {
            use crate::host::synthetic_roster_trace_v1::{self as trace, Phase};
            trace::observation_failure(Phase::CompletionObservationDenied, &error);
        }
        let reason = match error {
            E::Permission => "original or new read permission expired",
            E::Lineage => "original wallet lineage invalidated or already attempted",
            E::Binding => "exact immutable material or scope mismatch",
            E::Storage => "original wallet file, held lock or commit unavailable",
            E::RecoveryRequired => "wallet requires explicit recovery",
            E::StateChanged => "exact retained inputs, account or original anchor changed",
            E::ProfileChanged => "provider network, branch or protocol profile changed",
            E::Budget => "remaining scan, source freshness or expiry budget insufficient",
            E::Roster => "wallet alias, duplicate or incompatible original/current context",
            E::Sync(_) => "provider or bounded scan observation unavailable",
        };
        Error::Receipt(format!(
            "RETAINED_INPUT_OBSERVATION_UNAVAILABLE: {reason}. Partial scan progress may remain; original exposure is unchanged. No automatic retry or new selection is authorized"
        ))
    }
}
struct HostRosterConstructionRestrictionV2<'a, 'source, 'host> {
    host: &'a Host,
    sources: &'a [super::retained_inputs::RetainedRosterSourceCheckV2<'source, 'host>],
    observations: &'a [wholepact_wallet::wallet::protected_sync::exact_input_observation::FreshExactInputObservation],
    plans: Vec<ManualRosterConstructionPlanV2>,
    construction_key: &'a str,
    maximum_actions: usize,
}
impl HostRosterConstructionRestrictionV2<'_, '_, '_> {
    fn check_observations(&self) -> Result<()> {
        if self.plans.len() != self.sources.len() || self.observations.len() != self.sources.len() {
            return Err(Error::Authentication);
        }
        for observation in self.observations {
            observation.check_current()?;
        }
        Ok(())
    }
    fn check(&self) -> Result<()> {
        // The wallet's post-commit check precedes these potentially slow local
        // file/Store checks. Retain the ACTUAL fresh owners and bracket that work
        // with their original source/native deadlines; never reread an unlocked
        // wallet or reconstruct/renew an observation from metadata.
        exact_observations_around(|| self.check_observations(), || self.check_local_owners())
    }
    fn check_local_owners(&self) -> Result<()> {
        for source in self.sources {
            source.check_original_account()?;
        }
        let expected_key = wholepact_store::request_digest(&serde_json::json!([
            &self.host.access()?.principal_id,
            self.construction_key,
        ]))?;
        for plan in &self.plans {
            plan.validate().map_err(|_| Error::Invalid)?;
            if plan.enrollment().scope.principal_id != self.host.access()?.principal_id
                || plan
                    .retained
                    .selection
                    .scope
                    .selection
                    .invocation
                    .idempotency_key_digest
                    != expected_key
            {
                return Err(Error::Permission);
            }
        }
        Ok(())
    }
}
// Private ordering component only. The production caller above supplies actual
// FreshExactInputObservation checks, never a public freshness/capability flag.
fn exact_observations_around(
    mut observations: impl FnMut() -> Result<()>,
    local_checks: impl FnOnce() -> Result<()>,
) -> Result<()> {
    observations()?;
    local_checks()?;
    observations()
}
impl wholepact_engine::manual_roster_construct_v2::ManualRosterConstructionRestrictionV2
    for HostRosterConstructionRestrictionV2<'_, '_, '_>
{
    fn check_before_constructor(
        &self,
        plans: &[ManualRosterConstructionPlanV2],
        key: &str,
        maximum_actions: usize,
    ) -> wholepact_engine::Result<()> {
        if plans != self.plans
            || key != self.construction_key
            || maximum_actions != self.maximum_actions
            || self.check().is_err()
        {
            return Err(wholepact_engine::ApiError::new(
                "MANUAL_CONSTRUCTION_DENIED",
                "Exact Host full-candidate decision or current local owners no longer match",
            ));
        }
        Ok(())
    }
}
impl wholepact_proof_jobs::LocalProofConsent for HostRosterConstructionRestrictionV2<'_, '_, '_> {
    fn permits(
        &self,
        scope: &wholepact_proof_jobs::CheckpointScope,
        action: wholepact_proof_jobs::LocalAction,
    ) -> bool {
        if !matches!(
            action,
            wholepact_proof_jobs::LocalAction::RetainPrivateWitnesses
                | wholepact_proof_jobs::LocalAction::InspectStatus
        ) || self.check().is_err()
        {
            return false;
        }
        let Some(first) = self.plans.first() else {
            return false;
        };
        let Ok(proposal) = first.validate() else {
            return false;
        };
        let inventory = &first.retained.selection.scope.selection.inventory;
        scope.principal_id == first.enrollment().scope.principal_id
            && scope.candidate_id == first.retained.selection.scope.selection.economic_intent.candidate_id
            && scope.manifest_digest == proposal.manifest_digest()
            && scope.account_ids == proposal.manifest().participants.iter().map(|p| p.account_id.clone()).collect::<Vec<_>>()
            && scope.local_operator == inventory.operator_name
            && scope.retention_policy == inventory.retention_policy
            && scope.purpose == "construct_one_candidate"
            // Exact actual artifact fields are checked by the independent Engine
            // completion gate and the maintained journal's cryptographic review.
            && self.check().is_ok()
    }
}
