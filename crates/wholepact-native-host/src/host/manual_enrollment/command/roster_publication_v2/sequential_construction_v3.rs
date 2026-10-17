//! Source-connected all-read-first command. Public admission remains denied.
//! Every continuation, read, authorization and construction owner comes from
//! its actual producer. Inert files never substitute for those owners.
use super::*;
#[path = "sequential_construction_v3/prepared_common_context_completion_v3.rs"]
mod prepared_common_context_completion_v3;
#[path = "sequential_construction_v3/prepared_common_context_read_v3.rs"]
mod prepared_common_context_read_v3;
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
                    PreparationMode::InventoryAndCommonContextRetainedSelection,
                )?
                .ok_or(Error::Authentication)?,
            );
        }
        self.construct_retained_sequential_roster_v3(retained, construction_key, maximum_actions)
    }

    /// Shared inner composition for the actual retained owners. The public
    /// command is still qualification-gated before any prompt. Synthetic tests
    /// may call this private boundary only with owners from their maintained
    /// producers; there is no DTO, fixture-state or approval-flag conversion.
    fn construct_retained_sequential_roster_v3<'host>(
        &'host self,
        retained: Vec<RetainedRosterCandidateInputsV2<'host>>,
        construction_key: String,
        maximum_actions: usize,
    ) -> Result<()> {
        self.require_manual_session()?;
        let count = retained.len();
        for owner in &retained {
            owner.require_original_retention_scope_v2(self)?;
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
        let prepared =
            prepared_common_context_read_v3::prepare(self, coordinator, retained, read_plan)?;
        let provider = InstalledSignerProvider::load().map_err(|_| Error::Permission)?;
        provider.launch_native().map_err(|_| Error::Permission)?;
        let endpoint = wait_manual_endpoint_before(&provider, prepared.deadline())?;
        prepared.begin_pair(provider, &endpoint)?.finish(runtime)
    }

    fn complete_roster_common_context_owner_v1(
        &self,
        roster: &mut AllObservedCommonContextRosterV1<'_>,
        participant: usize,
        operations: CompletionOperationIdsV1,
    ) -> Result<()> {
        prepared_common_context_completion_v3::disclose_original(self, roster, participant)?
            .review_pending(roster, operations)?
            .consume(roster)
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

#[cfg(test)]
#[path = "sequential_construction_v3_qualification.rs"]
mod qualification;
