//! Source-connected all-read-first command. Public admission remains denied.
//! Every continuation, read, authorization and construction owner comes from
//! its actual producer. Inert files never substitute for those owners.
use super::*;
use crate::authority::manual_roster_common_context_read_v1::RosterCommonContextReadAdmissionV1;
use crate::host::financial::manual_roster_inventory_setup_v2::{
    AllObservedCommonContextRosterV1, CommonContextConstructionCoordinatorV3,
    ObservedHandoffCommonContextV1, RetainedRosterCandidateInputsV2,
    ReviewedRosterManualCandidateV3, UnreviewedRosterManualCandidateV3,
};
use std::collections::BTreeSet;
use wholepact_authority::construction_transport_handoff_v1::{
    MAX_CONSTRUCTION_TRANSPORT_COMPONENT_BYTES, PendingConstructionTransportGrantV1,
};
use wholepact_authority::manual_roster_construction_signature_v3::{
    ManualRosterConstructionOwnerSignatureV3, verify_manual_roster_construction_owner_signature_v3,
};
use wholepact_core::manual_roster_construction_v3::ManualRosterConstructionPlanV3;

/// Inert exact review material captured while the genuine reviewed owner exists.
struct ReadPlanV3 {
    plan: ManualRosterConstructionPlanV3,
    durable_receipt_digest: String,
    witness_plan_approval_digest: String,
}
struct CompletionOperationIdsV1 {
    reentry: String,
    construction: String,
}

/// Exact wrapper displayed by the independent native witness owner. Parsing it
/// grants no witness, native, transport or read authority.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingGrantDisplayV1 {
    kind: String,
    notice: String,
    pending_grant: PendingConstructionTransportGrantV1,
}
impl PendingGrantDisplayV1 {
    fn into_pending(self) -> Result<PendingConstructionTransportGrantV1> {
        if self.kind != "inert_pending_construction_transport_grant_v1"
            || self.notice.len() > 1024
            || serde_json::to_vec(&self.pending_grant)?.len()
                > MAX_CONSTRUCTION_TRANSPORT_COMPONENT_BYTES
        {
            return Err(Error::Invalid);
        }
        self.pending_grant
            .validate()
            .map_err(|_| Error::Authentication)?;
        Ok(self.pending_grant)
    }
}

impl Host {
    pub(in crate::host) fn manual_roster_sequential_construct_v3_command(&self) -> Result<()> {
        // First and unconditional: no session, prompt, private file, launch,
        // provider observation, grant or Reserve precedes qualification.
        require_common_context_v3_qualification()?;
        self.run_manual_roster_sequential_construct_v3()
    }

    fn run_manual_roster_sequential_construct_v3(&self) -> Result<()> {
        self.require_manual_session()?;
        let count = self
            .terminal
            .ask("Number of exact original owners (2–8): ")?
            .parse::<usize>()
            .map_err(|_| Error::Invalid)?;
        if !(2..=8).contains(&count) {
            return Err(Error::Invalid);
        }
        let construction_key = self
            .terminal
            .ask(
                "Exact construction key (16–128 printable ASCII bytes; preserve on any failure): ",
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
        self.terminal.confirm("Begin one all-read-first construction invocation? Retain each exact original contribution, separately approve the complete candidate and each full plan, then admit one bounded read and separate future-handoff authorization per owner. Every actual observation must exist and agree before any witness grant, transport claim or Reserve. Each original deadline keeps running. Failure is terminal; there is no reread, renewed session, replacement input or randomized retry. This requests no proof, transaction signature, release or dispatch.")?;
        let mut retained = Vec::with_capacity(count);
        for index in 0..count {
            self.terminal.message(&format!(
                "Collecting exact retained owner {} of {} under its original invocation.\n",
                index + 1,
                count
            ))?;
            retained.push(
                self.roster_publish_v2_collect(
                    true,
                    RosterAuditPurpose::ExistingOriginalContinuationV4,
                    PreparationMode::InventoryAndRetainedSelection,
                )?
                .ok_or(Error::Authentication)?,
            );
        }
        let candidate = UnreviewedRosterManualCandidateV3::assemble(self, retained)?;
        candidate.display_current(self)?;
        let reviewed = candidate.review_full_candidate_before_construction(
            self,
            construction_key,
            maximum_actions,
        )?;
        let plans = reviewed.exact_native_plans(self)?.to_vec();
        let mut read_plans = Vec::with_capacity(plans.len());
        for plan in plans {
            reviewed.check_current(self)?;
            let durable_receipt_digest = reviewed
                .exact_retained_owner(self, &plan)?
                .durable_receipt_digest()
                .to_owned();
            let witness_plan_approval_digest =
                self.prepare_roster_full_plan_owner_approval_v3(&reviewed, &plan)?;
            read_plans.push(ReadPlanV3 {
                plan,
                durable_receipt_digest,
                witness_plan_approval_digest,
            });
        }
        let (coordinator, retained) = reviewed.into_owner_reads(self)?;
        if retained.len() != read_plans.len() {
            return Err(Error::Authentication);
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| Error::Storage)?;
        let mut observations = Vec::with_capacity(count);
        let mut completion_operations = Vec::with_capacity(count);
        for (retained, plan) in retained.into_iter().zip(read_plans) {
            coordinator.check_current(self)?;
            let (observation, operations) = self.acquire_roster_common_context_observation_v3(
                &coordinator,
                retained,
                &plan,
                &runtime,
            )?;
            observations.push(observation);
            completion_operations.push(operations);
        }
        // No grant request has been exported and no grant, claim, Reserve or
        // construction request has been issued above this actual-read barrier.
        let mut roster = coordinator.finish_all_handoff_observations(self, observations)?;
        for (index, operations) in completion_operations.into_iter().enumerate() {
            self.complete_roster_common_context_owner_v1(&mut roster, index, operations)?;
        }
        roster.construct_checkpoint(self)?;
        self.terminal.message("One exact unsigned candidate was retained in the encrypted private journal after all actual reads and separate per-owner native construction decisions. Preserve the original construction key and every journal. No proof, transaction signature, release or dispatch ran. An existing or uncertain claim never permits regenerating randomized work.\n")
    }

    fn prepare_roster_full_plan_owner_approval_v3(
        &self,
        reviewed: &ReviewedRosterManualCandidateV3<'_>,
        plan: &ManualRosterConstructionPlanV3,
    ) -> Result<String> {
        reviewed.check_current(self)?;
        let path =
            self.path("NEW exact V3 full-plan JSON file in an existing private directory: ")?;
        reviewed.export_native_plan(self, plan, &path)?;
        self.terminal.message(&format!("In the installed signer original roster workspace, load {} and use the separate V3 full-plan owner-signature and private-export reviews. Then obtain the independent native witness-owner exact V3 plan approval. Keep the original invocation and all inputs unchanged. The exported signature is inert; the eventual native read still requires exact current witness history.\n", path.display()))?;
        self.terminal.confirm("Launch the installed signer for this exact separate V3 full-plan signature/export ceremony? This launch sends no read or construction request.")?;
        let provider = InstalledSignerProvider::load().map_err(|_| Error::Permission)?;
        provider.launch_native().map_err(|_| Error::Permission)?;
        let _cleanup = self.terminal.ask("After native plan signature/export and independent witness review, press Enter to close this launcher (cleanup only; this proves no approval): ")?;
        drop(provider);
        reviewed.check_current(self)?;
        let signed: ManualRosterConstructionOwnerSignatureV3 = self.read_manual_private(
            "Exact privately exported V3 full-plan owner-signature JSON: ",
            "authenticating this exact full plan against its already retained owner certificate pin",
        )?;
        let verified = verify_manual_roster_construction_owner_signature_v3(
            &signed,
            &plan.enrollment().signer.owner_certificate_digest,
        )
        .map_err(|_| Error::Authentication)?;
        if verified.approval().plan != *plan {
            return Err(Error::Authentication);
        }
        let digest = verified
            .approval()
            .digest_for(verified.extension())
            .map_err(|_| Error::Authentication)?;
        reviewed.check_current(self)?;
        // Existing original-intent continuation ceremony, before observation.
        self.manual_roster_continue_intent_v2_command()?;
        reviewed.check_current(self)?;
        Ok(digest)
    }

    fn acquire_roster_common_context_observation_v3<'host>(
        &'host self,
        coordinator: &CommonContextConstructionCoordinatorV3<'host>,
        retained: RetainedRosterCandidateInputsV2<'host>,
        read_plan: &ReadPlanV3,
        runtime: &tokio::runtime::Runtime,
    ) -> Result<(
        ObservedHandoffCommonContextV1<'host>,
        CompletionOperationIdsV1,
    )> {
        coordinator.check_current(self)?;
        let plan = &read_plan.plan;
        plan.validate().map_err(|_| Error::Invalid)?;
        let terms = plan.enrollment();
        let key = self
            .terminal
            .ask("Exact new read-continuation Host audit key: ")?;
        id(&key)?;
        let read_operation = self
            .terminal
            .ask("Distinct common-context read operation ID: ")?
            .to_string();
        let handoff_operation = self
            .terminal
            .ask("Distinct future-handoff preauthorization operation ID: ")?
            .to_string();
        let reentry_operation = self
            .terminal
            .ask("Distinct later transport-reentry operation ID: ")?
            .to_string();
        let construction_operation = self
            .terminal
            .ask("Distinct later full-construction operation ID: ")?
            .to_string();
        require_distinct_operations(
            plan,
            &[
                &read_operation,
                &handoff_operation,
                &reentry_operation,
                &construction_operation,
            ],
        )?;
        let signed: ManualRosterContinuationOwnerSignatureV2 = self.read_manual_private(
            "Exact NEW private roster-continuation signature JSON for this original owner: ",
            "reviewing the exact fresh continuation used by this sole common-context read",
        )?;
        signed.extension.validate().map_err(|_| Error::Invalid)?;
        signed
            .continuation
            .validate_for(&signed.extension)
            .map_err(|_| Error::Invalid)?;
        let selected = &plan.retained.selection.scope;
        let attempt_digest = signed
            .continuation
            .digest_for(&signed.extension)
            .map_err(|_| Error::Invalid)?;
        let attempt_sequence = signed.continuation.sequence();
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
            || attempt_sequence <= selected.selection.inventory.attempt.attempt_sequence
        {
            return Err(Error::Authentication);
        }
        let publication_request = HostManualRosterPublicationRequestV2 {
            version: 2,
            enrollment: HostManualEnrollmentRequest {
                terms: terms.clone(),
            },
            roster: signed.extension.roster.clone(),
            attempt: ManualRosterPublicationAttemptV2::ContinuationV2 {
                continuation_digest: attempt_digest.clone(),
                attempt_sequence,
            },
        };
        let prepared = self.prepare_roster_publication(
            publication_request,
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
        let ceremony_digest = wholepact_core::proposal::canonical_digest(
            "wholepact:host-common-context-read-and-handoff-ceremony:v1",
            &(
                plan,
                &exact_digest,
                &read_plan.durable_receipt_digest,
                &read_plan.witness_plan_approval_digest,
                &attempt_digest,
                attempt_sequence,
                &read_operation,
                &handoff_operation,
            ),
        )
        .map_err(|_| Error::Invalid)?;
        let prior = &prepared.original.source.history_review;
        let pair_approval = self.terminal.approve_publication_reviewed(prior, &exact_digest,
            "Pair once for this exact fresh original-account continuation. All terminal questions finish before signer launch; no old approval or deadline is extended.")?;
        let publication_approval = self.terminal.approve_publication_reviewed(prior, &exact_digest,
            "Publish this exact fresh V4 continuation against the same original V3/account ledger, without resetting retained exposure, input exclusions or lifetime budget.")?;
        let read_pair_approval = self.terminal.approve_publication_reviewed(prior, &ceremony_digest,
            "After exact publication, pair the SAME actual installed process for this full V3 common-context plan. This permits no read or construction without its separate native decision.")?;
        let handoff_approval = self.terminal.approve_publication_reviewed(prior, &ceremony_digest,
            "After the separate native read admission, send one future construction-only transport preauthorization request on that SAME original paired source. The actual read receipt digest and caller come from that admission and pairing. The signer must obtain a NEW purpose-distinct native owner decision. Its signed response remains inert until all actual observations and independent witness grant review. No new key, Reserve, construction or spending authority is requested here.")?;
        let original_deadline = coordinator.original_deadline();
        let read_admission = RosterCommonContextReadAdmissionV1::review(
            &self.terminal,
            prior,
            plan,
            &read_plan.durable_receipt_digest,
            &read_plan.witness_plan_approval_digest,
            read_operation,
            original_deadline,
        )?;
        let deadline = original_deadline
            .min(prior.deadline())
            .min(prepared.original.approval.deadline())
            .min(prepared.approval.deadline())
            .min(pair_approval.deadline())
            .min(publication_approval.deadline())
            .min(read_pair_approval.deadline())
            .min(handoff_approval.deadline())
            .min(read_admission.deadline());
        coordinator.check_current(self)?;
        prepared.check_before()?;
        let provider = InstalledSignerProvider::load().map_err(|_| Error::Permission)?;
        provider.launch_native().map_err(|_| Error::Permission)?;
        let endpoint = wait_manual_endpoint_before(&provider, deadline)?;
        let client = pair_approval
            .commit(
                &exact_digest,
                || {
                    coordinator.check_current(self)?;
                    prepared.check_before()
                },
                |_| {
                    NativeManualClient::begin_pair_before(
                        provider,
                        &endpoint,
                        "wholepact-native-roster-common-context-publication-v3",
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
            )?
            .finish()
            .map_err(|_| Error::Permission)?;
        let pending = publication_approval.commit(
            &exact_digest,
            || {
                coordinator.check_current(self)?;
                prepared.check_before()
            },
            |_| {
                client
                    .begin_roster_enrollment_v2_before(&prepared.request, deadline)
                    .map_err(|_| Error::Permission)
            },
        )?;
        let lease = pending.finish().map_err(|_| Error::Permission)?;
        let (_, committed) = prepared.append_owned(lease)?;
        committed.check_current()?;
        coordinator.check_current(self)?;
        let client = read_pair_approval
            .commit(
                &ceremony_digest,
                || {
                    coordinator.check_current(self)?;
                    committed.check_current()
                },
                |_| {
                    client
                        .begin_roster_construction_v3_pair_before(
                            "wholepact-native-roster-common-context-read-v3",
                            plan,
                            deadline,
                        )
                        .map_err(|_| Error::Permission)
                },
            )?
            .finish()
            .map_err(|_| Error::Permission)?;
        let ready = retained
            .begin_common_context_read(
                self,
                &client,
                read_admission,
                &attempt_digest,
                attempt_sequence,
            )?
            .finish(self)?;
        committed.check_current()?;
        coordinator.check_current(self)?;
        let request = ready.handoff_request(&client, handoff_operation)?;
        let authorized = handoff_approval.commit(
            &ceremony_digest,
            || {
                coordinator.check_current(self)?;
                committed.check_current()
            },
            |_| ready.authorize_handoff_before(&client, &request, deadline),
        )?;
        committed.check_current()?;
        coordinator.check_current(self)?;
        // Both pending stages finished before moving the paired client. A timed
        // out read is dropped, never returned for a repeat observation wave.
        let observed = runtime.block_on(async {
            tokio::time::timeout_at(tokio::time::Instant::from_std(original_deadline),
                authorized.observe(self, client),
            ).await.map_err(|_| Error::Receipt(
                "Common-context read expired; partial scan progress may remain. Preserve the original invocation and journals; no reread or randomized retry is permitted".into(),
            ))?
        })?;
        coordinator.check_current(self)?;
        Ok((
            observed,
            CompletionOperationIdsV1 {
                reentry: reentry_operation,
                construction: construction_operation,
            },
        ))
    }

    fn complete_roster_common_context_owner_v1(
        &self,
        roster: &mut AllObservedCommonContextRosterV1<'_>,
        participant: usize,
        operations: CompletionOperationIdsV1,
    ) -> Result<()> {
        roster.check_current(self)?;
        let authorization = roster.grant_request(self, participant)?.clone();
        let disclosure = self.terminal.approve_historical(
            "Display this one exact original-owner signed handoff preauthorization for manual relay to its independent pinned native witness owner? ALL actual observations have been checked. It includes exact original account/session/read/plan commitments and creates no active credential or grant. Do not reuse it for another account or operation.",
        )?;
        let output = self.terminal.historical_output()?;
        disclosure
            .effect(&mut || output.json_checked(&authorization, || roster.check_current(self)))?;
        self.terminal.message("Paste that exact authorization into the independent witness owner's 'One-use construction transport handoff' review. Save its resulting exact inert pending-grant display as a private JSON file. Select the exact original namespace/attempt and pending-grant digest in the purpose-limited Authority server. Neither a terminal acknowledgment nor the file proves native approval. Keep every original signer process open so its key-free completion remains available.\n")?;
        let shown: PendingGrantDisplayV1 = self.read_manual_private(
            "Exact native witness pending-grant DISPLAY JSON file (kind, notice, pending_grant): ",
            "binding the separately issued inert pending grant to this original actual observed owner",
        )?;
        let pending = shown.into_pending()?;
        if pending.grant.authorization != authorization {
            return Err(Error::Authentication);
        }
        roster.check_current(self)?;
        let pending_digest = pending.digest().map_err(|_| Error::Authentication)?;
        let selector_disclosure = self.terminal.approve_historical_reviewed(&disclosure,
            "Display the exact inert pending-grant digest and original attempt digest for selecting this one purpose-limited Authority server? Use the already retained original namespace, extension and server configuration. This metadata creates no credential or approval and cannot renew the original read or invocation clocks.")?;
        let selector = serde_json::json!({
            "kind": "inert_construction_transport_server_selector_v1",
            "pending_grant_digest": pending_digest,
            "original_attempt_digest": authorization.authorization.attempt_digest,
            "original_attempt_sequence": authorization.authorization.attempt_sequence,
        });
        selector_disclosure.effect(&mut || {
            output.json_checked(&selector, || {
                disclosure.check()?;
                roster.check_current(self)
            })
        })?;
        self.terminal.message("Configure serve-born-construction-transport-v1 with that exact pending_grant_digest and original_attempt.attempt_digest, preserving the original namespace, extension and pinned server configuration. Complete that selection before the fresh signer unlock below. Do not select the ordinary writer server.\n")?;
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:host-common-context-exact-reentry-process:v1",
            &(
                &authorization,
                &pending_digest,
                &operations.reentry,
                &operations.construction,
            ),
        )
        .map_err(|_| Error::Invalid)?;
        let pair_approval = self.terminal.approve_publication_reviewed(&disclosure, &digest,
            "Wait for a genuinely fresh original-account completion unlock in the SAME still-running installed signer, then pair only that newly published endpoint. The original dormant owner and original read clocks remain mandatory; this approves no new account/session, read, input selection or general writer use.")?;
        let request_approval = self.terminal.approve_publication_reviewed(&disclosure, &digest,
            "Send one exact completion request using this pending grant and the actual fresh caller. The signer must separately approve original witness contact, then the exact fresh TLS-bound claim and permanent old-key fence, then the complete original proposal's Reserve/Consume. The construction request will be created only after actual reentry admission. All original observations and deadlines remain mandatory; uncertainty or failure cannot retry. No proof, transaction signature or dispatch is approved.")?;
        self.terminal.message("Now use the SAME original signer window's 'Unlock exact original account for admitted completion' control, complete fresh pairing, and remain there for the separate contact, TLS claim and full-proposal reviews. Do not use ordinary account unlock, explicit Lock or another signer process. The retained claim channel keeps its original ten-second limit, including both later native reviews.\n")?;
        let (roster, client) = pair_approval.commit(
            &digest,
            || {
                roster.check_current(self)?;
                Ok(roster)
            },
            |roster| {
                let client = roster.pair_owner_before(
                    self,
                    participant,
                    "wholepact-native-common-context-reentry-v1",
                )?;
                Ok((roster, client))
            },
        )?;
        let request =
            roster.reentry_request(self, participant, &client, &pending, operations.reentry)?;
        request_approval.commit(
            &digest,
            || {
                roster.check_current(self)?;
                Ok(roster)
            },
            |roster| {
                roster.consume_owner_before(
                    self,
                    participant,
                    &client,
                    &pending,
                    &request,
                    operations.construction,
                )?;
                roster.check_current(self)
            },
        )
    }
}

fn require_distinct_operations(
    plan: &ManualRosterConstructionPlanV3,
    operations: &[&str],
) -> Result<()> {
    let mut used = BTreeSet::from([
        plan.retained.operation_id.as_str(),
        plan.retained.selection.operation_id.as_str(),
        plan.retained
            .selection
            .scope
            .selection
            .invocation
            .operation_id
            .as_str(),
    ]);
    for operation in operations {
        id(operation)?;
        if !used.insert(operation) {
            return Err(Error::Invalid);
        }
    }
    Ok(())
}

/// No feature, environment variable, terminal answer or serialized record can
/// bypass this gate. Source-connected owners do not establish attended timing.
fn require_common_context_v3_qualification() -> Result<()> {
    Err(Error::Receipt("Common-context V3 construction is unavailable: the reviewed all-observations-first handoff/reentry source and interactive command still require joined qualification. No prompt, provider read, reservation or construction was started".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn common_context_v3_public_command_stays_unconditionally_unqualified() {
        assert!(matches!(
            require_common_context_v3_qualification(),
            Err(Error::Receipt(_))
        ));
    }
    #[test]
    fn exact_inert_pending_grant_display_parses_without_native_authority() {
        // Existing canonical inert fixture only. No native owner, key factory,
        // socket, provider read or current transport is constructed here.
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../wholepact-signer/src/consent_journal/fixtures/common-context-handoff-audit.synthetic.json",
        ))).unwrap();
        let pending =
            fixture["complete_history"]["transport"]["credentials"][0]["pending_grant"].clone();
        let wrapper = serde_json::json!({
            "kind": "inert_pending_construction_transport_grant_v1",
            "notice": "Inert synthetic fixture; not native approval",
            "pending_grant": pending,
        });
        let parsed: PendingGrantDisplayV1 = serde_json::from_value(wrapper.clone()).unwrap();
        assert!(parsed.into_pending().is_ok());
        let mut flags = wrapper.clone();
        flags["approved"] = serde_json::json!(true);
        assert!(serde_json::from_value::<PendingGrantDisplayV1>(flags).is_err());
        let mut wrong_kind = wrapper.clone();
        wrong_kind["kind"] = serde_json::json!("construction_transport_claimed");
        let mut oversized_notice = wrapper;
        oversized_notice["notice"] = serde_json::json!("x".repeat(1025));
        assert!(
            serde_json::from_value::<PendingGrantDisplayV1>(oversized_notice)
                .unwrap()
                .into_pending()
                .is_err()
        );
        assert!(
            serde_json::from_value::<PendingGrantDisplayV1>(wrong_kind)
                .unwrap()
                .into_pending()
                .is_err()
        );
    }
    #[test]
    fn exact_operation_intent_is_distinct_without_constructing_an_owner() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../wholepact-signer/src/consent_journal/fixtures/common-context-handoff-audit.synthetic.json",
        ))).unwrap();
        let plan: ManualRosterConstructionPlanV3 =
            serde_json::from_value(fixture["modeled_read_evidence"]["request"]["plan"].clone())
                .unwrap();
        // This is the production inert intent predicate, never a read, native
        // approval or all-observed capability factory.
        assert!(
            require_distinct_operations(
                &plan,
                &[
                    "synthetic-next-read",
                    "synthetic-next-handoff",
                    "synthetic-next-reentry",
                    "synthetic-next-construction",
                ]
            )
            .is_ok()
        );
        assert!(
            require_distinct_operations(&plan, &["synthetic-duplicate", "synthetic-duplicate"])
                .is_err()
        );
        assert!(require_distinct_operations(&plan, &[&plan.retained.operation_id]).is_err());
        assert!(require_distinct_operations(&plan, &[""]).is_err());
    }
}
