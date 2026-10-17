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
    manual_roster_construction_v2::ManualRosterRetentionCommitmentV2,
    manual_roster_construction_v3::{
        CommonContextProposalV1, ManualRosterConstructionPlanV3, ManualRosterOriginalRetentionV3,
    },
};

/// No Clone/Deserialize, raw contribution or raw builder conversion. Every
/// retained owner owns its original fresh wallet, real native durable receipt,
/// local provenance and fixed completion deadline; no simultaneous focus exists.
pub(in crate::host) struct UnreviewedRosterManualCandidateV3<'host> {
    proposal: Proposal,
    owners: Vec<RetainedRosterCandidateInputsV2<'host>>,
}
impl<'host> UnreviewedRosterManualCandidateV3<'host> {
    pub(in crate::host) fn assemble(
        host: &Host,
        owners: Vec<RetainedRosterCandidateInputsV2<'host>>,
    ) -> Result<Self> {
        if !(2..=8).contains(&owners.len()) {
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
    fn construction_plans(&self, host: &Host) -> Result<Vec<ManualRosterConstructionPlanV3>> {
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
        let mut originals = self
            .owners
            .iter()
            .map(|owner| {
                Ok(ManualRosterOriginalRetentionV3 {
                    request: owner.request(host)?.clone(),
                    evidence_digest: owner.retention_evidence_digest(host)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        originals.sort_by(|a, b| {
            a.request
                .selection
                .scope
                .selection
                .inventory
                .enrollment
                .scope
                .participant_id
                .cmp(
                    &b.request
                        .selection
                        .scope
                        .selection
                        .inventory
                        .enrollment
                        .scope
                        .participant_id,
                )
        });
        let common_context = CommonContextProposalV1::from_originals(&originals)
            .map_err(|_| Error::Authentication)?;
        let common_context_digest = common_context.digest().map_err(|_| Error::Invalid)?;
        let mut plans = Vec::with_capacity(self.owners.len());
        for owner in &self.owners {
            let plan = ManualRosterConstructionPlanV3 {
                version: 3,
                retained: owner.request(host)?.clone(),
                retained_evidence_digest: owner.retention_evidence_digest(host)?,
                proposal: self.proposal.input().clone(),
                participants: commitments.clone(),
                originals: originals.clone(),
                common_context: common_context.clone(),
                common_context_digest: common_context_digest.clone(),
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
    ) -> Result<ReviewedRosterManualCandidateV3<'host>> {
        if !(16..=128).contains(&construction_key.len())
            || !construction_key.bytes().all(|b| (33..=126).contains(&b))
            || !(1..=8).contains(&maximum_actions)
        {
            return Err(Error::Invalid);
        }
        let plans = self.construction_plans(host)?;
        for plan in &plans {
            host.engine.require_unused_common_context_invocation(
                host.access()?,
                &construction_key,
                plan,
            )?;
        }
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
            "wholepact:host-roster-full-construction-review:v3",
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
                Ok(ReviewedRosterManualCandidateV3 {
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
pub(in crate::host) struct ReviewedRosterManualCandidateV3<'host> {
    candidate: UnreviewedRosterManualCandidateV3<'host>,
    plans: Vec<ManualRosterConstructionPlanV3>,
    review_digest: String,
    construction_key: String,
    maximum_actions: usize,
}
impl ReviewedRosterManualCandidateV3<'_> {
    pub(in crate::host) fn check_current(&self, host: &Host) -> Result<()> {
        self.candidate.check_current(host)?;
        if self.review_digest
            != wholepact_core::proposal::canonical_digest(
                "wholepact:host-roster-full-construction-review:v3",
                &(&self.plans, &self.construction_key, self.maximum_actions),
            )
            .map_err(|_| Error::Invalid)?
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    pub(in crate::host) fn exact_retained_owner(
        &self, host: &Host, plan: &ManualRosterConstructionPlanV3,
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
        plan: &ManualRosterConstructionPlanV3,
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
    ) -> Result<&[ManualRosterConstructionPlanV3]> {
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
/// a native lease or UnreviewedRosterManualCandidateV3.
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
        if actual.context.anchor_height != common.anchor_height
            || actual.context.anchor_hash_protocol != common.anchor_hash_protocol
            || actual.context.anchor_root != common.anchor_root
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

/// The actual reviewed Host decision can split into original owner reads once.
/// No constructor, Clone or deserialization exists for this coordinator.
pub(in crate::host) struct CommonContextConstructionCoordinatorV3<'host> {
    host: &'host Host,
    plans: Vec<ManualRosterConstructionPlanV3>,
    construction_key: String,
    maximum_actions: usize,
    original_deadline: std::time::Instant,
}
impl<'host> ReviewedRosterManualCandidateV3<'host> {
    pub(in crate::host) fn into_owner_reads(
        self,
        host: &'host Host,
    ) -> Result<(
        CommonContextConstructionCoordinatorV3<'host>,
        Vec<RetainedRosterCandidateInputsV2<'host>>,
    )> {
        self.check_current(host)?;
        let original_deadline = self.original_completion_deadline(host)?;
        let coordinator = CommonContextConstructionCoordinatorV3 {
            host,
            plans: self.plans,
            construction_key: self.construction_key,
            maximum_actions: self.maximum_actions,
            original_deadline,
        };
        coordinator.check_current(host)?;
        Ok((coordinator, self.candidate.owners))
    }
}
impl CommonContextConstructionCoordinatorV3<'_> {
    pub(in crate::host) fn original_deadline(&self) -> std::time::Instant {
        self.original_deadline
    }

    pub(in crate::host) fn check_current(&self, host: &Host) -> Result<()> {
        if !std::ptr::eq(host, self.host) || std::time::Instant::now() >= self.original_deadline {
            return Err(Error::Permission);
        }
        for plan in &self.plans {
            plan.validate().map_err(|_| Error::Authentication)?;
            let target = host
                .engine
                .manual_enrollment_target(host.access()?, plan.enrollment())?;
            target.check_current_fail_fast(host.access()?)?;
        }
        if std::time::Instant::now() >= self.original_deadline {
            return Err(Error::Permission);
        }
        Ok(())
    }
    pub(in crate::host) fn construct_observed_checkpoint(
        self,
        host: &Host,
        observed: Vec<super::retained_inputs::ObservedHostCommonContextV3<'_>>,
        admitted: Vec<wholepact_signer_origin::AdmittedManualRosterConstructionContributionV3>,
    ) -> Result<()> {
        use wholepact_wallet::wallet::protected_sync::exact_input_observation::{
            CommonContextWalletSlot, with_common_context_roster,
        };
        self.check_current(host)?;
        if !(2..=8).contains(&observed.len())
            || admitted.len() != observed.len()
            || self.plans.len() != observed.len()
        {
            return Err(Error::Authentication);
        }
        for ((plan, native), (_, _, observation, _)) in
            self.plans.iter().zip(&admitted).zip(&observed)
        {
            native.check_completion().map_err(|_| Error::Permission)?;
            observation.check_current().map_err(Error::from)?;
            native
                .check_original_read(observation.native_read())
                .map_err(|_| Error::Authentication)?;
            if native.request().map_err(|_| Error::Permission)?.plan != *plan
                || observation
                    .native_read()
                    .request()
                    .map_err(|_| Error::Permission)?
                    .plan
                    != *plan
            {
                return Err(Error::Authentication);
            }
        }
        let Self {
            plans,
            construction_key,
            maximum_actions,
            ..
        } = self;
        let mut contributions = Vec::with_capacity(admitted.len());
        let mut sources = Vec::with_capacity(admitted.len());
        let mut observations = Vec::with_capacity(admitted.len());
        let mut snapshots = Vec::with_capacity(admitted.len());
        for ((retained, source, observation, snapshot), native) in
            observed.into_iter().zip(admitted)
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
            slots.push(CommonContextWalletSlot::new(
                wallet,
                snapshot,
                observation,
                check,
            )?);
        }
        let restriction = HostRosterConstructionRestrictionV3 {
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
        let progress = wholepact_engine::manual_roster_construct_v3::ManualRosterConstructionProgressV3::default();
        let outcome = roster_trace!(CheckpointWalletUnwind, with_common_context_roster(slots, &excluded, |held| {
            roster_trace!(CheckpointEngine, host.engine.checkpoint_manual_roster_from_retained_v3(
                host.access()?, &construction_key,
                wholepact_engine::manual_roster_construct_v3::ManualRosterPrivateConstructionV3 {
                    contributions, jobs: &primary.proof, maximum_actions,
                    restriction: &restriction, held, progress: &progress,
                },
            ).map_err(Error::from))
        }));
        let pending = exact_outer_result(&progress, &construction_key, outcome)?;
        // Wallet final checks and commits have now all unwound. The independent
        // original native construction owners can have an EARLIER deadline than
        // the exact-read owners, so check them and the original restriction again
        // before the opaque pending result releases any safe metadata.
        let result = exact_outer_result(
            &progress,
            &construction_key,
            roster_trace!(CheckpointFinish, pending.finish().map_err(Error::from)),
        )?;
        // Final source-owner sample before output. It cannot undo a durable
        // claim or promise atomic timing across a subsequent terminal write.
        exact_outer_result(
            &progress,
            &construction_key,
            roster_trace!(CheckpointObservations, restriction.check_observations()),
        )?;
        exact_outer_result(
            &progress,
            &construction_key,
            roster_trace!(CheckpointOutput, host.terminal.json(&result)),
        )?;
        Ok(())
    }
}
fn exact_outer_result<T>(
    progress: &wholepact_engine::manual_roster_construct_v3::ManualRosterConstructionProgressV3,
    construction_key: &str,
    result: Result<T>,
) -> Result<T> {
    use wholepact_engine::manual_roster_construct_v3::ManualRosterConstructionOuterErrorV3;
    progress
        .classify_outer_result(result)
        .map_err(|error| {
            // Observe only the closed original kind before the existing durable
            // uncertainty mapping. No claim state, payload or retry permission.
            #[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
            {
                use crate::host::synthetic_roster_trace_v1::{self as trace, Phase};
                match &error {
                    ManualRosterConstructionOuterErrorV3::BeforeClaim(error) => {
                        trace::host_failure(Phase::CheckpointBeforeClaim, error);
                    }
                    ManualRosterConstructionOuterErrorV3::ClaimMayExist(error) => {
                        trace::host_failure(Phase::CheckpointClaimMayExist, error);
                    }
                }
            }
            match error {
                ManualRosterConstructionOuterErrorV3::BeforeClaim(error) => error,
                ManualRosterConstructionOuterErrorV3::ClaimMayExist(_) => {
                    exact_claim_uncertain_error(construction_key, progress.claim_digest().as_deref())
                }
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
        "An exact construction claim MAY already be durable, including after a wallet final-check, commit or output error. Correlation: {correlation}. Preserve the original key and every journal. Use manual-roster-construction-inspect-v3 only for exact original-key metadata under fresh native approval; never regenerate this invocation"
    ))
}
struct HostRosterConstructionRestrictionV3<'a, 'source, 'host> {
    host: &'a Host,
    sources: &'a [super::retained_inputs::RetainedRosterSourceCheckV2<'source, 'host>],
    observations: &'a [wholepact_wallet::wallet::protected_sync::exact_input_observation::FreshCommonContextObservation],
    plans: Vec<ManualRosterConstructionPlanV3>,
    construction_key: &'a str,
    maximum_actions: usize,
}
impl HostRosterConstructionRestrictionV3<'_, '_, '_> {
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
// FreshCommonContextObservation checks, never a public freshness/capability flag.
fn exact_observations_around(
    mut observations: impl FnMut() -> Result<()>,
    local_checks: impl FnOnce() -> Result<()>,
) -> Result<()> {
    observations()?;
    local_checks()?;
    observations()
}
impl wholepact_engine::manual_roster_construct_v3::ManualRosterConstructionRestrictionV3
    for HostRosterConstructionRestrictionV3<'_, '_, '_>
{
    fn check_before_constructor(
        &self,
        plans: &[ManualRosterConstructionPlanV3],
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
impl wholepact_proof_jobs::LocalProofConsent for HostRosterConstructionRestrictionV3<'_, '_, '_> {
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

/// All actual maintained observations exist before any grant/claim/Reserve.
/// Private fields and consuming construction prevent a prefix from serving as
/// a complete roster; no serialized completion flag is accepted.
pub(in crate::host) struct AllObservedCommonContextRosterV1<'host> {
    coordinator: CommonContextConstructionCoordinatorV3<'host>,
    owners: Vec<super::retained_inputs::ObservedHandoffCommonContextV1<'host>>,
    consumed: Vec<Option<wholepact_signer_origin::AdmittedManualRosterConstructionContributionV3>>,
}
impl<'host> CommonContextConstructionCoordinatorV3<'host> {
    pub(in crate::host) fn finish_all_handoff_observations(
        self,
        host: &Host,
        owners: Vec<super::retained_inputs::ObservedHandoffCommonContextV1<'host>>,
    ) -> Result<AllObservedCommonContextRosterV1<'host>> {
        let consumed = (0..owners.len()).map(|_| None).collect();
        let roster = AllObservedCommonContextRosterV1 {
            coordinator: self,
            owners,
            consumed,
        };
        roster.check_current(host)?;
        Ok(roster)
    }
}
impl AllObservedCommonContextRosterV1<'_> {
    pub(in crate::host) fn check_current(&self, host: &Host) -> Result<()> {
        self.coordinator.check_current(host)?;
        if !(2..=8).contains(&self.owners.len())
            || self.owners.len() != self.coordinator.plans.len()
        {
            return Err(Error::Authentication);
        }
        let first = &self.owners.first().ok_or(Error::Authentication)?.observed.2;
        let mut participants = BTreeSet::new();
        for (plan, owner) in self.coordinator.plans.iter().zip(&self.owners) {
            first.require_same_current_context(&owner.observed.2)?;
            owner
                .authorization
                .check_observed_read(&owner.observed.2)
                .map_err(|_| Error::Permission)?;
            if owner
                .observed
                .2
                .native_read()
                .request()
                .map_err(|_| Error::Permission)?
                .plan
                != *plan
                || !participants.insert(plan.enrollment().scope.participant_id.as_str())
            {
                return Err(Error::Authentication);
            }
            owner
                .observed
                .0
                .common_context_verifier_snapshot(&owner.observed.2)
                .map_err(|_| Error::Authentication)?;
        }
        self.coordinator.check_current(host)
    }
    /// Inert export material only after the full actual read barrier. The
    /// independent local witness owner must still authorize each exact grant.
    pub(in crate::host) fn grant_request(
        &self, host: &Host, participant: usize,
    ) -> Result<&wholepact_authority::construction_transport_handoff_v1::SignedConstructionTransportPreauthorizationV1>{
        self.check_current(host)?;
        let owner = self.owners.get(participant).ok_or(Error::Invalid)?;
        Ok(owner.authorization.authorization())
    }
}

impl AllObservedCommonContextRosterV1<'_> {
    pub(in crate::host) fn pair_owner_before(
        &mut self,
        host: &Host,
        participant: usize,
        label: &str,
    ) -> Result<wholepact_signer_origin::CommonContextReentryClientV1> {
        self.check_current(host)?;
        let owner = self.owners.get_mut(participant).ok_or(Error::Invalid)?;
        let source = owner.reentry.take().ok_or(Error::Permission)?;
        let pending = roster_trace!(
            origin,
            CompletionPairBegin,
            source.begin_pair_before(
                owner.observed.2.native_read(),
                label,
                self.coordinator.original_deadline,
            )
        )
        .map_err(|_| Error::Permission)?;
        let client = roster_trace!(
            origin,
            CompletionPairFinish,
            pending.finish(owner.observed.2.native_read())
        )
        .map_err(|_| Error::Permission)?;
        self.check_current(host)?;
        Ok(client)
    }
    /// Request bytes are derived from the actual completed observation and
    /// fresh same-process pairing. Parsing a grant alone creates no owner.
    pub(in crate::host) fn reentry_request(
        &self,
        host: &Host,
        participant: usize,
        client: &wholepact_signer_origin::CommonContextReentryClientV1,
        pending: &wholepact_authority::construction_transport_handoff_v1::PendingConstructionTransportGrantV1,
        operation_id: String,
    ) -> Result<wholepact_core::common_context_reentry_v1::RosterCommonContextReentryRequestV1>
    {
        self.check_current(host)?;
        let owner = self.owners.get(participant).ok_or(Error::Invalid)?;
        if owner.reentry.is_some()
            || self
                .consumed
                .get(participant)
                .ok_or(Error::Invalid)?
                .is_some()
        {
            return Err(Error::Permission);
        }
        pending.validate().map_err(|_| Error::Authentication)?;
        if &pending.grant.authorization != owner.authorization.authorization() {
            return Err(Error::Authentication);
        }
        let read = owner.observed.2.native_read();
        let evidence = read.evidence();
        let requested_at_ms = super::retained_inputs::now_ms()?;
        let admission_expires_at_ms = bounded_reentry_admission_end(
            requested_at_ms,
            evidence
                .request
                .completion_expires_at_ms
                .min(pending.grant.authorization.authorization.expires_at_ms),
        )?;
        let request = wholepact_core::common_context_reentry_v1::RosterCommonContextReentryRequestV1 {
            version: 1,
            operation_id,
            original_read: read.request().map_err(|_| Error::Permission)?.clone(),
            original_read_admission_digest: evidence.digest().map_err(|_| Error::Authentication)?,
            pending_grant_digest: pending.digest().map_err(|_| Error::Authentication)?,
            original_attempt_digest: evidence.current_attempt_digest.clone(),
            original_attempt_sequence: evidence.current_attempt_sequence,
            current_caller_binding_digest: client.current_caller_binding_digest().map_err(|_| Error::Permission)?,
            current_attempt_digest: evidence.current_attempt_digest.clone(),
            current_attempt_sequence: evidence.current_attempt_sequence,
            purpose: wholepact_core::common_context_reentry_v1::CommonContextReentryPurposeV1::ResumeAlreadyAdmittedConstructionOnly,
            requested_at_ms,
            admission_expires_at_ms,
        };
        request.validate().map_err(|_| Error::Permission)?;
        self.check_current(host)?;
        Ok(request)
    }
    /// All reads precede every call here. Each current native owner and retained
    /// witness channel is independent; no previous owner's focus is retained.
    pub(in crate::host) fn consume_owner_before(
        &mut self,
        host: &Host,
        participant: usize,
        client: &wholepact_signer_origin::CommonContextReentryClientV1,
        pending_grant: &wholepact_authority::construction_transport_handoff_v1::PendingConstructionTransportGrantV1,
        reentry_request: &wholepact_core::common_context_reentry_v1::RosterCommonContextReentryRequestV1,
        construction_operation_id: String,
    ) -> Result<()> {
        self.check_current(host)?;
        let owner = self.owners.get(participant).ok_or(Error::Invalid)?;
        if owner.reentry.is_some()
            || self
                .consumed
                .get(participant)
                .ok_or(Error::Invalid)?
                .is_some()
        {
            return Err(Error::Permission);
        }
        let pending = roster_trace!(
            bridge,
            CompletionReentryBegin,
            owner.observed.0.begin_common_context_reentry_before(
                client,
                reentry_request,
                pending_grant,
                &owner.authorization,
                &owner.observed.2,
                self.coordinator.original_deadline,
            )
        )
        .map_err(|_| Error::Permission)?;
        let reentered = roster_trace!(bridge, CompletionReentryFinish, pending.finish())
            .map_err(|_| Error::Permission)?;
        self.check_current(host)?;
        // The request is produced only after the actual fresh reentry returns.
        // Never predate it, guess a future admission, or renew an original ceiling.
        reentered
            .check_original_read(owner.observed.2.native_read())
            .map_err(|_| Error::Authentication)?;
        let lineage = reentered.lineage();
        let requested_at_ms = super::retained_inputs::now_ms()?;
        require_reentry_construction_send_time(
            requested_at_ms,
            lineage.admitted_at_ms,
            lineage.completion_expires_at_ms,
        )?;
        let construction_request =
            wholepact_core::manual_roster_construction_v3::ManualRosterConstructionRequestV3 {
                version: 3,
                operation_id: construction_operation_id,
                plan: lineage.request.original_read.plan.clone(),
                current_caller_binding_digest: client
                    .current_caller_binding_digest()
                    .map_err(|_| Error::Permission)?,
                requested_at_ms,
                admission_expires_at_ms: bounded_reentry_admission_end(
                    requested_at_ms,
                    lineage.completion_expires_at_ms,
                )?,
            };
        construction_request
            .validate()
            .map_err(|_| Error::Invalid)?;
        let pending = roster_trace!(
            bridge,
            CompletionConstructionBegin,
            owner.observed.0.begin_reentered_construction_before(
                client,
                &construction_request,
                &owner.observed.2,
                reentered,
                self.coordinator.original_deadline,
            )
        )
        .map_err(|_| Error::Permission)?;
        let admitted = roster_trace!(origin, CompletionConstructionFinish, pending.finish())
            .map_err(|_| Error::Permission)?;
        admitted
            .check_original_read(owner.observed.2.native_read())
            .map_err(|_| Error::Authentication)?;
        self.check_current(host)?;
        self.consumed[participant] = Some(admitted);
        Ok(())
    }
    pub(in crate::host) fn construct_checkpoint(self, host: &Host) -> Result<()> {
        self.check_current(host)?;
        let consumed = self
            .consumed
            .into_iter()
            .map(|owner| owner.ok_or(Error::Permission))
            .collect::<Result<Vec<_>>>()?;
        let observed = self
            .owners
            .into_iter()
            .map(|owner| owner.observed)
            .collect();
        self.coordinator
            .construct_observed_checkpoint(host, observed, consumed)
    }
}

/// Pure timing predicate only; it neither reconstructs nor admits a native
/// completion owner. The production caller checks its actual read first.
fn require_reentry_construction_send_time(now: u64, admitted: u64, expiry: u64) -> Result<()> {
    if admitted == 0 || now < admitted || now >= expiry {
        return Err(Error::Permission);
    }
    Ok(())
}

fn bounded_reentry_admission_end(now: u64, original: u64) -> Result<u64> {
    if now >= original {
        return Err(Error::Permission);
    }
    Ok(now
        .checked_add(wholepact_core::manual_inventory::MAX_PRELIMINARY_DISCLOSURE_MS)
        .ok_or(Error::Invalid)?
        .min(original))
}

#[cfg(test)]
mod reentry_request_timing_tests {
    use super::*;

    #[test]
    fn request_is_made_after_actual_reentry_with_original_expiry() {
        assert_eq!(
            bounded_reentry_admission_end(1_000, 60_000).unwrap(),
            31_000
        );
        assert_eq!(
            bounded_reentry_admission_end(1_000, 12_000).unwrap(),
            12_000
        );
        assert!(bounded_reentry_admission_end(12_000, 12_000).is_err());
        assert!(bounded_reentry_admission_end(u64::MAX - 1, u64::MAX).is_err());
        require_reentry_construction_send_time(12, 12, 20).unwrap();
        require_reentry_construction_send_time(19, 12, 20).unwrap();
    }

    #[test]
    fn predated_expired_and_empty_original_windows_refuse() {
        for (now, admitted, expiry) in [
            (11, 12, 20),
            (20, 12, 20),
            (21, 12, 20),
            (12, 12, 12),
            (12, 0, 20),
        ] {
            assert!(require_reentry_construction_send_time(now, admitted, expiry).is_err());
        }
    }
}
