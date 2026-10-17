//! Same actual read preparation and consumption for the production command
//! and its concrete synthetic caller. The public gate is unchanged. No parsed
//! record, peer metadata or callback constructs any retained source/approval.
use super::*;
use std::{path::Path, time::Instant};
use wholepact_signer_origin::PendingNativeManualPair;

struct ReadStateV3<'host, 'coordinator> {
    host: &'host Host,
    coordinator: &'coordinator CommonContextConstructionCoordinatorV3<'host>,
    retained: RetainedRosterCandidateInputsV2<'host>,
    read_plan: ReadPlanV3,
    prepared: PreparedRosterPublication<'host>,
    publication_approval: PublicationApproval,
    read_pair_approval: PublicationApproval,
    handoff_approval: PublicationApproval,
    read_admission: RosterCommonContextReadAdmissionV1,
    exact_digest: String,
    ceremony_digest: String,
    attempt_digest: String,
    attempt_sequence: u64,
    read_operation: String,
    handoff_operation: String,
    operations: CompletionOperationIdsV1,
    original_deadline: Instant,
    deadline: Instant,
}
pub(super) struct PreparedCommonContextReadV3<'host, 'coordinator> {
    state: ReadStateV3<'host, 'coordinator>,
    pair_approval: PublicationApproval,
}
pub(super) struct PendingCommonContextReadV3<'host, 'coordinator> {
    state: ReadStateV3<'host, 'coordinator>,
    pairing: PendingNativeManualPair,
}

pub(super) fn prepare<'host, 'coordinator>(
    host: &'host Host,
    coordinator: &'coordinator CommonContextConstructionCoordinatorV3<'host>,
    retained: RetainedRosterCandidateInputsV2<'host>,
    read_plan: &ReadPlanV3,
) -> Result<PreparedCommonContextReadV3<'host, 'coordinator>> {
    coordinator.check_current(host)?;
    let plan = &read_plan.plan;
    plan.validate().map_err(|_| Error::Invalid)?;
    let terms = plan.enrollment();
    let key = host
        .terminal
        .ask("Exact new read-continuation Host audit key: ")?;
    id(&key)?;
    let read_operation = host
        .terminal
        .ask("Distinct common-context read operation ID: ")?
        .to_string();
    let handoff_operation = host
        .terminal
        .ask("Distinct future-handoff preauthorization operation ID: ")?
        .to_string();
    let reentry_operation = host
        .terminal
        .ask("Distinct later transport-reentry operation ID: ")?
        .to_string();
    let construction_operation = host
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
    let signed: ManualRosterContinuationOwnerSignatureV2 = host.read_manual_private(
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
    let prepared = host.prepare_roster_publication(
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
    let pair_approval = host.terminal.approve_publication_reviewed(prior, &exact_digest,
            "Pair once for this exact fresh original-account continuation. All terminal questions finish before signer launch; no old approval or deadline is extended.")?;
    let publication_approval = host.terminal.approve_publication_reviewed(prior, &exact_digest,
            "Publish this exact fresh V4 continuation against the same original V3/account ledger, without resetting retained exposure, input exclusions or lifetime budget.")?;
    let read_pair_approval = host.terminal.approve_publication_reviewed(prior, &ceremony_digest,
            "After exact publication, pair the SAME actual installed process for this full V3 common-context plan. This permits no read or construction without its separate native decision.")?;
    let handoff_approval = host.terminal.approve_publication_reviewed(prior, &ceremony_digest,
            "After the separate native read admission, send one future construction-only transport preauthorization request on that SAME original paired source. The actual read receipt digest and caller come from that admission and pairing. The signer must obtain a NEW purpose-distinct native owner decision. Its signed response remains inert until all actual observations and independent witness grant review. No new key, Reserve, construction or spending authority is requested here.")?;
    let original_deadline = coordinator.original_deadline();
    let read_admission = RosterCommonContextReadAdmissionV1::review(
        &host.terminal,
        prior,
        plan,
        &read_plan.durable_receipt_digest,
        &read_plan.witness_plan_approval_digest,
        read_operation.clone(),
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
    coordinator.check_current(host)?;
    prepared.check_before()?;

    Ok(PreparedCommonContextReadV3 {
        pair_approval,
        state: ReadStateV3 {
            host,
            coordinator,
            retained,
            read_plan: ReadPlanV3 {
                plan: plan.clone(),
                durable_receipt_digest: read_plan.durable_receipt_digest.clone(),
                witness_plan_approval_digest: read_plan.witness_plan_approval_digest.clone(),
            },
            prepared,
            publication_approval,
            read_pair_approval,
            handoff_approval,
            read_admission,
            exact_digest,
            ceremony_digest,
            attempt_digest,
            attempt_sequence,
            read_operation,
            handoff_operation,
            operations: CompletionOperationIdsV1 {
                reentry: reentry_operation,
                construction: construction_operation,
            },
            original_deadline,
            deadline,
        },
    })
}
impl<'host, 'coordinator> PreparedCommonContextReadV3<'host, 'coordinator> {
    pub(super) fn deadline(&self) -> Instant {
        self.state.deadline
    }
    #[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
    pub(super) fn publication_request(&self) -> &HostManualRosterPublicationRequestV2 {
        &self.state.prepared.request
    }
    #[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
    pub(super) fn exact_read_parts(&self) -> (&ReadPlanV3, &str, &str) {
        (
            &self.state.read_plan,
            &self.state.read_operation,
            &self.state.handoff_operation,
        )
    }
    pub(super) fn begin_pair(
        self,
        provider: InstalledSignerProvider,
        endpoint: &Path,
    ) -> Result<PendingCommonContextReadV3<'host, 'coordinator>> {
        let Self {
            state,
            pair_approval,
        } = self;
        let host = state.host;
        let coordinator = state.coordinator;
        let prepared = &state.prepared;
        let terms = state.read_plan.plan.enrollment();
        let exact_digest = &state.exact_digest;
        let deadline = state.deadline;
        let pairing = pair_approval.commit(
            &exact_digest,
            || {
                coordinator.check_current(host)?;
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
        )?;

        Ok(PendingCommonContextReadV3 { state, pairing })
    }
}
impl<'host> PendingCommonContextReadV3<'host, '_> {
    pub(super) fn finish(
        self,
        runtime: &tokio::runtime::Runtime,
    ) -> Result<(
        ObservedHandoffCommonContextV1<'host>,
        CompletionOperationIdsV1,
    )> {
        let Self { state, pairing } = self;
        let ReadStateV3 {
            host,
            coordinator,
            retained,
            read_plan,
            prepared,
            publication_approval,
            read_pair_approval,
            handoff_approval,
            read_admission,
            exact_digest,
            ceremony_digest,
            attempt_digest,
            attempt_sequence,
            read_operation: _,
            handoff_operation,
            operations,
            original_deadline,
            deadline,
        } = state;
        let CompletionOperationIdsV1 {
            reentry: reentry_operation,
            construction: construction_operation,
        } = operations;
        let plan = &read_plan.plan;
        let client = pairing.finish().map_err(|_| Error::Permission)?;
        let pending = publication_approval.commit(
            &exact_digest,
            || {
                coordinator.check_current(host)?;
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
        coordinator.check_current(host)?;
        let client = read_pair_approval
            .commit(
                &ceremony_digest,
                || {
                    coordinator.check_current(host)?;
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
                host,
                &client,
                read_admission,
                &attempt_digest,
                attempt_sequence,
            )?
            .finish(host)?;
        committed.check_current()?;
        coordinator.check_current(host)?;
        let request = ready.handoff_request(&client, handoff_operation)?;
        let authorized = handoff_approval.commit(
            &ceremony_digest,
            || {
                coordinator.check_current(host)?;
                committed.check_current()
            },
            |_| ready.authorize_handoff_before(&client, &request, deadline),
        )?;
        committed.check_current()?;
        coordinator.check_current(host)?;
        // Both pending stages finished before moving the paired client. A timed
        // out read is dropped, never returned for a repeat observation wave.
        let observed = runtime.block_on(async {
            tokio::time::timeout_at(tokio::time::Instant::from_std(original_deadline),
                authorized.observe(host, client),
            ).await.map_err(|_| Error::Receipt(
                "Common-context read expired; partial scan progress may remain. Preserve the original invocation and journals; no reread or randomized retry is permitted".into(),
            ))?
        })?;
        coordinator.check_current(host)?;
        Ok((
            observed,
            CompletionOperationIdsV1 {
                reentry: reentry_operation,
                construction: construction_operation,
            },
        ))
    }
}
