//! Explicit sequential command. The first phase retains each genuine selection
//! before releasing its signer GUI. The second phase reopens fresh genuine
//! continuation ceremonies for the complete candidate, one owner at a time.
use super::*;
use crate::authority::manual_roster_exact_input_observation_v1::{
    HostAdmittedRosterExactInputObservationV1, RosterExactInputObservationAdmissionV1,
};
use crate::host::financial::manual_roster_inventory_setup_v2::{
    ReviewedRosterManualCandidateV2, UnreviewedRosterManualCandidateV2,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use wholepact_core::manual_roster_construction_v2::{
    ManualRosterConstructionPlanV2, ManualRosterConstructionRequestV2,
};
use wholepact_signer_origin::AdmittedManualRosterConstructionContributionV2;

impl Host {
    pub(in crate::host) fn manual_roster_sequential_construct_v2_command(&self) -> Result<()> {
        self.require_manual_session()?;
        let count = self
            .terminal
            .ask("Number of exact owners to retain sequentially (2–8): ")?
            .parse::<usize>()
            .map_err(|_| Error::Invalid)?;
        // The maintained construction/proof profile admits at most eight padded
        // actions. Larger economic rosters are not silently truncated.
        if !(2..=8).contains(&count) {
            return Err(Error::Invalid);
        }
        let construction_key = self
            .terminal
            .ask(
                "Exact construction key (16–128 printable ASCII bytes; preserve even on failure): ",
            )?
            .to_string();
        if !(16..=128).contains(&construction_key.len())
            || !construction_key.bytes().all(|b| (33..=126).contains(&b))
        {
            return Err(Error::Invalid);
        }
        let maximum_actions = self
            .terminal
            .ask("Maximum padded construction actions (1–8): ")?
            .parse::<usize>()
            .map_err(|_| Error::Invalid)?;
        if !(1..=8).contains(&maximum_actions) {
            return Err(Error::Invalid);
        }
        self.terminal.confirm("Start this bounded sequential collection? Every owner must independently complete its exact original continuation, fresh wallet import/scan, selection and separate native durable retention review. Each original deadline continues while other owners are reviewed. No background retry, wallet reopen, proof, signature or dispatch is requested. Preserve every immutable attempt and wallet even if collection fails.")?;
        let mut owners = Vec::with_capacity(count);
        for index in 0..count {
            self.terminal.message(&format!("Collecting owner {} of {}. Prior contributions remain guarded by their original lineage and invocation lifetimes; current observations will be separately obtained after all reviews.\n", index + 1, count))?;
            let owner = self
                .roster_publish_v2_collect(
                    true,
                    RosterAuditPurpose::ExistingOriginalContinuationV4,
                    PreparationMode::InventoryAndRetainedSelection,
                )?
                .ok_or(Error::Authentication)?;
            owners.push(owner);
        }
        let candidate = UnreviewedRosterManualCandidateV2::assemble(self, owners)?;
        candidate.display_current(self)?;
        let reviewed = candidate.review_full_candidate_before_construction(
            self,
            construction_key,
            maximum_actions,
        )?;
        let plans = reviewed.exact_native_plans(self)?.to_vec();
        let mut admitted = Vec::with_capacity(plans.len());
        let mut reads = Vec::with_capacity(plans.len());
        for plan in plans {
            reviewed.check_current(self)?;
            self.prepare_roster_full_plan_owner_approval(&reviewed, &plan)?;
            let (construction, read) =
                self.acquire_roster_construction_owner_v2(&reviewed, &plan)?;
            admitted.push(construction);
            reads.push(read);
        }
        reviewed.construct_exact_checkpoint(self, admitted, reads)?;
        self.terminal.message("One exact unsigned candidate was retained in the encrypted private journal. No proof, spend signature, release, transaction checkpoint or dispatch ran. Preserve the original construction key and every journal. The separate manual-roster-construction-inspect-v2 command can inspect exact current-generation original metadata under fresh native consent. An existing claim never permits regenerating randomized bytes for this invocation.\n")
    }

    fn prepare_roster_full_plan_owner_approval(
        &self,
        reviewed: &ReviewedRosterManualCandidateV2<'_>,
        plan: &ManualRosterConstructionPlanV2,
    ) -> Result<()> {
        reviewed.check_current(self)?;
        let path = self.path("NEW exact full-plan JSON file in an existing private directory: ")?;
        reviewed.export_native_plan(self, plan, &path)?;
        self.terminal.message(&format!("Use the installed signer roster workspace to open this account's existing source, load {}, and select 'Review existing-owner signature of exact full construction plan', then the separate private export action. Next complete the independent native witness-owner exact-plan review. Only after both, this Host will separately pair and send the genuine original intent to prepare a NEW continuation for this same original account and original V3 audit. The Host will independently authenticate the resulting fresh continuation and native Reserve/Consume; Enter below proves none of these steps. Original invocation deadlines continue throughout. Historical observations are not represented as current; a separately approved exact-input observation is required after all reviews.\n", path.display()))?;
        self.terminal.confirm("Launch the installed signer for this separate stable-plan approval/signature/export ceremony? No current Host selection GUI owner remains and no construction request is sent by this launch.")?;
        let provider = InstalledSignerProvider::load().map_err(|_| Error::Permission)?;
        provider.launch_native().map_err(|_| Error::Permission)?;
        // Retain launcher ownership only. The user's terminal acknowledgment
        // closes it; it is never interpreted as native/witness completion.
        let _cleanup = self.terminal.ask("After native plan approval/export and independent witness exact-plan review, press Enter to close this launcher (cleanup only): ")?;
        drop(provider);
        reviewed.check_current(self)?;
        // New continuation production requires its own genuine original-intent
        // pairing. A plain launcher or saved full-plan JSON cannot provide it.
        // This existing command obtains fresh historical/terminal approvals,
        // sends the exact immutable original intent under actual pairing, and
        // requires independent witness-owner continuation review after export.
        self.manual_roster_continue_intent_v2_command()?;
        reviewed.check_current(self)
    }

    fn acquire_roster_construction_owner_v2(
        &self,
        reviewed: &ReviewedRosterManualCandidateV2<'_>,
        plan: &ManualRosterConstructionPlanV2,
    ) -> Result<(
        AdmittedManualRosterConstructionContributionV2,
        HostAdmittedRosterExactInputObservationV1,
    )> {
        reviewed.check_current(self)?;
        plan.validate().map_err(|_| Error::Invalid)?;
        let terms = plan.enrollment();
        let key = self
            .terminal
            .ask("Exact fresh construction-continuation Host audit key: ")?;
        id(&key)?;
        let operation = self
            .terminal
            .ask("Exact distinct native construction operation ID: ")?
            .to_string();
        id(&operation)?;
        let signed: ManualRosterContinuationOwnerSignatureV2 = self.read_manual_private(
            "Exact NEW private roster-continuation signature JSON for this retained owner: ",
            "reviewing a fresh independent continuation for this exact retained contribution and complete candidate",
        )?;
        signed.extension.validate().map_err(|_| Error::Invalid)?;
        signed
            .continuation
            .validate_for(&signed.extension)
            .map_err(|_| Error::Invalid)?;
        let selected = &plan.retained.selection.scope;
        let current_attempt_digest = signed
            .continuation
            .digest_for(&signed.extension)
            .map_err(|_| Error::Invalid)?;
        let current_attempt_sequence = signed.continuation.sequence();
        if signed.extension.account_extension.terms != *terms
            || signed.extension.account_extension.enrollment_ref
                != selected.selection.inventory.enrollment_ref
            || signed
                .extension
                .account_extension
                .digest()
                .map_err(|_| Error::Invalid)?
                != selected.selection.inventory.witness_extension_digest
            || signed.extension.roster != selected.provenance.roster
            || signed.extension.signer_roster_record_digest
                != selected.provenance.signer_roster_record_digest
            || signed.extension.digest().map_err(|_| Error::Invalid)?
                != selected.provenance.witness_roster_extension_digest
            || current_attempt_sequence <= selected.selection.inventory.attempt.attempt_sequence
        {
            return Err(Error::Authentication);
        }
        let request = HostManualRosterPublicationRequestV2 {
            version: 2,
            enrollment: HostManualEnrollmentRequest {
                terms: terms.clone(),
            },
            roster: signed.extension.roster.clone(),
            attempt: ManualRosterPublicationAttemptV2::ContinuationV2 {
                continuation_digest: current_attempt_digest.clone(),
                attempt_sequence: current_attempt_sequence,
            },
        };
        let prepared = self.prepare_roster_publication(
            request,
            signed.extension,
            RosterAuditPurpose::ExistingOriginalContinuationV4,
            &key,
        )?;
        if prepared.prior_digest.as_deref()
            != Some(selected.provenance.original_host_audit.audit_digest())
        {
            return Err(Error::Authentication);
        }
        let exact_digest = prepared.request.digest().map_err(|_| Error::Invalid)?;
        let plan_digest = plan.digest().map_err(|_| Error::Invalid)?;
        let ceremony_digest = wholepact_core::proposal::canonical_digest(
            "wholepact:host-roster-fresh-construction-ceremony:v2",
            &(
                &plan_digest,
                &exact_digest,
                &operation,
                &current_attempt_digest,
                current_attempt_sequence,
            ),
        )
        .map_err(|_| Error::Invalid)?;
        let prior = &prepared.original.source.history_review;
        let pair_approval = self.terminal.approve_publication_reviewed(prior, &exact_digest,
            "Pair once for the exact fresh roster continuation. All terminal prompts finish before signer launch; old selection/historical approvals are not extended.")?;
        let request_approval = self.terminal.approve_publication_reviewed(prior, &exact_digest,
            &format!("Publish this exact new V4 against the SAME original V3 and account ledger.\nRequest: {exact_digest}\nSequence: {current_attempt_sequence}\nNo lifetime budget, inherited exposure, input exclusion or retirement fence is reset."))?;
        let construction_pair = self.terminal.approve_publication_reviewed(prior, &ceremony_digest,
            &format!("After exact V4 publication completes, separately pair the SAME actual installed process for this complete construction plan.\nPlan commitment: {plan_digest}\nThe old retained selection remains historical; this fresh ceremony is independent."))?;
        let construction_request = self.terminal.approve_publication_reviewed(prior, &ceremony_digest,
            &format!("Send one exact non-signing construction request for this full actual plan after new pairing.\n{}\nOperation: {}\nCaller binding and send time come only from that actual pairing. Native review and independent witness-owner approval must separately Reserve and Consume on the original account-wide lifetime ledger. Construction completion remains bounded by the ORIGINAL invocation expiry. No proof, spend signing or dispatch is approved.", serde_json::to_string_pretty(plan)?, operation))?;
        let original_completion_deadline = reviewed.original_completion_deadline(self)?;
        let read_operation = self
            .terminal
            .ask("Distinct ONE exact-input observation operation ID: ")?
            .to_string();
        id(&read_operation)?;
        if read_operation == operation {
            return Err(Error::Invalid);
        }
        let exact_read = RosterExactInputObservationAdmissionV1::review(
            &self.terminal,
            prior,
            plan,
            reviewed
                .exact_retained_owner(self, plan)?
                .durable_receipt_digest(),
            read_operation,
            original_completion_deadline,
        )?;
        let wall = now_ms()?;
        let completion_remaining = plan
            .completion_expires_at_ms()
            .checked_sub(wall)
            .ok_or(Error::Permission)?;
        let invocation_deadline = Instant::now()
            .checked_add(Duration::from_millis(completion_remaining))
            .ok_or(Error::Invalid)?;
        let deadline = original_completion_deadline
            .min(invocation_deadline)
            .min(prior.deadline())
            .min(prepared.original.approval.deadline())
            .min(prepared.approval.deadline())
            .min(pair_approval.deadline())
            .min(request_approval.deadline())
            .min(construction_pair.deadline())
            .min(construction_request.deadline())
            .min(exact_read.deadline());
        reviewed.check_current(self)?;
        prepared.check_before()?;
        let provider = InstalledSignerProvider::load().map_err(|_| Error::Permission)?;
        provider.launch_native().map_err(|_| Error::Permission)?;
        let endpoint = wait_manual_endpoint_before(&provider, deadline)?;
        let pending = pair_approval.commit(
            &exact_digest,
            || {
                reviewed.check_current(self)?;
                prepared.check_before()
            },
            |_| {
                NativeManualClient::begin_pair_before(
                    provider,
                    &endpoint,
                    "wholepact-native-roster-construction-continuation-v2",
                    PairScope {
                        account_id: terms.identity.account_id.clone(),
                        agreement_id: terms.scope.agreement_id.clone(),
                        participant_id: terms.scope.participant_id.clone(),
                        manifest_digest: exact_digest.clone(),
                        history_read: false,
                        authorization_export: false,
                        preconstruction_export: false,
                    },
                    deadline,
                )
                .map_err(|_| Error::Permission)
            },
        )?;
        let client = pending.finish().map_err(|_| Error::Permission)?;
        let pending = request_approval.commit(
            &exact_digest,
            || {
                reviewed.check_current(self)?;
                prepared.check_before()
            },
            |_| {
                client
                    .begin_roster_enrollment_v2_before(&prepared.request, deadline)
                    .map_err(|_| Error::Permission)
            },
        )?;
        let lease = pending.finish().map_err(|_| Error::Permission)?;
        let (_audit_receipt, committed) = prepared.append_owned(lease)?;
        reviewed.check_current(self)?;
        committed.check_current()?;
        let pending = construction_pair.commit(
            &ceremony_digest,
            || {
                reviewed.check_current(self)?;
                committed.check_current()
            },
            |_| {
                client
                    .begin_roster_construction_pair_before(
                        "wholepact-native-roster-construction-v2",
                        plan,
                        deadline,
                    )
                    .map_err(|_| Error::Permission)
            },
        )?;
        let client = pending.finish().map_err(|_| Error::Permission)?;
        // Actual additional-read decision finishes BEFORE any full-construction
        // native Reserve/Consume request, on this same freshly paired source.
        let read_request = exact_read.request(
            client
                .current_caller_binding_digest()
                .map_err(|_| Error::Permission)?,
            now_ms()?,
        )?;
        let pending_read = reviewed
            .exact_retained_owner(self, plan)?
            .begin_exact_input_observation_before(
                &client,
                &read_request,
                &current_attempt_digest,
                current_attempt_sequence,
                deadline,
                original_completion_deadline,
            )
            .map_err(|_| Error::Permission)?;
        let read = exact_read.finish(pending_read.finish().map_err(|_| Error::Permission)?)?;
        reviewed.check_current(self)?;
        committed.check_current()?;
        let pending = construction_request.commit(
            &ceremony_digest,
            || {
                reviewed.check_current(self)?;
                committed.check_current()
            },
            |_| {
                let requested_at_ms = now_ms()?;
                let admission_expires_at_ms = requested_at_ms
                    .checked_add(wholepact_core::manual_inventory::MAX_PRELIMINARY_DISCLOSURE_MS)
                    .ok_or(Error::Invalid)?
                    .min(plan.completion_expires_at_ms());
                let request = ManualRosterConstructionRequestV2 {
                    version: 2,
                    operation_id: operation,
                    plan: plan.clone(),
                    current_caller_binding_digest: client
                        .current_caller_binding_digest()
                        .map_err(|_| Error::Permission)?,
                    requested_at_ms,
                    admission_expires_at_ms,
                };
                request.validate().map_err(|_| Error::Invalid)?;
                client
                    .begin_roster_construction_before(
                        &request,
                        &committed.original_signer_intent_digest,
                        &current_attempt_digest,
                        current_attempt_sequence,
                        deadline,
                        original_completion_deadline,
                    )
                    .map_err(|_| Error::Permission)
            },
        )?;
        let admitted = pending.finish().map_err(|_| Error::Permission)?;
        // This last old-owner check is an admission boundary only. The returned
        // one-use native owner carries its own fixed completion guard afterwards.
        committed.check_current()?;
        reviewed.check_current(self)?;
        admitted.check_completion().map_err(|_| Error::Permission)?;
        if admitted.request().map_err(|_| Error::Permission)?.plan != *plan {
            return Err(Error::Authentication);
        }
        Ok((admitted, read))
    }
}
fn now_ms() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Permission)?
            .as_millis(),
    )
    .map_err(|_| Error::Invalid)
}
