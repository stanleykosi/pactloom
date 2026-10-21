//! Private child of the retained Admit owner. One fresh writer Read may open
//! the selected TLS credential, authenticate history, and freeze one Acquire
//! recipe. The genuine Read stays live through the complete Origin presentation
//! join, then is consumed before cached-only display. No approval or Acquire
//! effect is issued during preparation. The consuming Final path below performs
//! one maintained Acquire and retains its actual authenticated outcome.
use super::*;

#[path = "coordinated_financial_activate_v1.rs"]
pub(in crate::native_ui::runtime) mod coordinated_financial_activate_v1;
use crate::account::birth::enrollment::roster_v2::financial_source_v1::FinancialOperationSourcePinV1;
use crate::native_ui::witness_workspace::financial_continuation_v1::coordinated_writer_read_v1::{
    PreparedCoordinatedWriterReadV1, PresentedCoordinatedWriterReadV1, ReadFinancialAcquireInputsV1,
};
use wholepact_financial_coordinator_origin::{
    SignerAcquireArmV1, SignerAcquireFactsV1, SignerAcquirePresentationV1,
    SignerFinancialWriterReadFactsV1, SignerFinancialWriterReadFinalV1,
    SignerFinancialWriterReadPresentationV1,
};

fn check_retained_context(context: &Context) -> Result<()> {
    if context.next != Next::Acquire
        || context.material.is_none()
        || context.writer.is_some()
        || context.prepared_wallet.is_some()
        || context.wallet.is_some()
        || context.inputs.is_some()
        || context.prepared_spend.is_some()
        || context.active.is_some()
        || context.original_history.is_some()
        || context.history.is_some()
        || context.activation.is_some()
        || context.result_request.is_some()
        || Arc::strong_count(&context.source) != 1
    {
        return Err(Error::Unavailable);
    }
    let host = context
        .original_peer
        .as_ref()
        .ok_or(Error::Authentication)?;
    context.source.check_coordinated_public_custody_v2(host)?;
    let certificate = context
        .owner
        .check_coordinated_continue_owner_v1(&context.source)?;
    context
        .source
        .require_coordinated_owner_metadata_v2(&context.terms.scope.witness, &certificate)?;
    if context.source.original_ceiling_ms() != context.terms.valid_until_ms {
        return Err(Error::ReviewMismatch);
    }
    context
        .terms
        .require_live(wall_now()?)
        .map_err(|_| Error::Locked)?;
    context.source.check_coordinated_public_custody_v2(host)
}

pub(in crate::native_ui::runtime) struct PreparedCoordinatedWriterReadRoleV1 {
    context: Context,
    selected: PreparedCoordinatedWriterReadV1,
    original_session_deadline: Instant,
}
pub(in crate::native_ui::runtime) struct PresentedCoordinatedWriterReadRoleV1 {
    context: Context,
    selected: PresentedCoordinatedWriterReadV1,
    original_session_deadline: Instant,
}

impl PreparedCoordinatedWriterReadRoleV1 {
    /// The sole input is the actual consuming Admit-success owner. Ordinary
    /// configuration, a historical receipt or independently supplied client
    /// cannot reconstruct this transition. The supplied session bound can only
    /// shorten the original source; Origin independently authenticates it.
    pub(in crate::native_ui::runtime) fn prepare(
        retained: AwaitingCoordinatedWriterReadV1,
        original_session_deadline: Instant,
    ) -> Result<Self> {
        let AwaitingCoordinatedWriterReadV1 {
            context,
            authenticated_snapshot,
            admitted_presentation,
        } = retained;
        check_retained_context(&context)?;
        let selected = PreparedCoordinatedWriterReadV1::prepare(
            context.writer_setup.as_str(),
            &context.source,
            &context.owner,
            context
                .original_peer
                .as_ref()
                .ok_or(Error::Authentication)?,
            &context.terms,
            admitted_presentation,
            authenticated_snapshot,
            original_session_deadline,
        )?;
        check_retained_context(&context)?;
        Ok(Self {
            context,
            selected,
            original_session_deadline,
        })
    }
    pub(in crate::native_ui::runtime) fn facts(&self) -> &SignerFinancialWriterReadFactsV1 {
        self.selected.facts()
    }
    pub(in crate::native_ui::runtime) fn original_source_deadline(&self) -> Instant {
        self.selected.original_source_deadline()
    }
    pub(in crate::native_ui::runtime) fn original_read_deadline(&self) -> Instant {
        self.selected.original_read_deadline()
    }

    /// Called with the ordinary presentation returned by the actual original
    /// issuer. Matching data alone neither creates nor substitutes for Final.
    pub(in crate::native_ui::runtime) fn freeze_presentation(
        self,
        presentation: SignerFinancialWriterReadPresentationV1,
    ) -> Result<PresentedCoordinatedWriterReadRoleV1> {
        check_retained_context(&self.context)?;
        let selected = self.selected.freeze_presentation(presentation)?;
        Ok(PresentedCoordinatedWriterReadRoleV1 {
            context: self.context,
            selected,
            original_session_deadline: self.original_session_deadline,
        })
    }
}

/// No public source/client access, Clone, serde or retry. The actual Origin
/// presentation join consumes this state while the same Read remains live.
/// Dropping it drops this one preparation; no Acquire has been attempted.
pub(in crate::native_ui::runtime) struct PreparedCoordinatedAcquireUnderReadV1 {
    context: Context,
    inputs: ReadFinancialAcquireInputsV1,
    recipe: SignerAcquireFactsV1,
    original_acquire_deadline: Instant,
}

impl PresentedCoordinatedWriterReadRoleV1 {
    pub(in crate::native_ui::runtime) fn read_and_prepare(
        self,
        final_read: SignerFinancialWriterReadFinalV1,
    ) -> Result<PreparedCoordinatedAcquireUnderReadV1> {
        final_read.check_current()?;
        check_retained_context(&self.context)?;
        final_read.check_current()?;
        let Self {
            context,
            selected,
            original_session_deadline,
        } = self;
        let host = context
            .original_peer
            .as_ref()
            .ok_or(Error::Authentication)?;
        let inputs = selected.read_once_for_acquire_preparation(
            &context.source,
            &context.owner,
            host,
            final_read,
        )?;
        inputs.check_preparation_current(&context.source, &context.owner, host)?;
        let read = inputs.final_read.presentation();
        let history = &inputs.history;
        let request = history.continuation_request();
        let record = history.continuation_record();
        let request_json = serde_json::to_string(request).map_err(|_| Error::InvalidData)?;
        if request_json != read.facts.continuation_request_json
            || record.terms != context.terms
            || history.snapshot().writer_certificate_digest != read.facts.writer_certificate_digest
            || history.disclosure() != &context.terms.scope.witness
        {
            return Err(Error::ReviewMismatch);
        }
        history
            .financial_continuation_online_permits_v1(&request.operation_id)
            .map_err(|_| Error::ReviewMismatch)?;
        let acquire_operation_id = record
            .acquire_operation_id(request)
            .map_err(|_| Error::ReviewMismatch)?;
        // Capture once while Read is live. This is Acquire's OWN independent
        // review ceiling; it is not a refreshed or inherited Read permission.
        let monotonic_now = Instant::now();
        let now = wall_now()?;
        let original_acquire_deadline = context
            .source
            .original_deadline()
            .min(original_session_deadline)
            .min(
                monotonic_now
                    .checked_add(Duration::from_secs(120))
                    .ok_or(Error::InvalidData)?,
            );
        let review_ms = u64::try_from(
            original_acquire_deadline
                .checked_duration_since(monotonic_now)
                .ok_or(Error::Locked)?
                .as_millis(),
        )
        .map_err(|_| Error::InvalidData)?;
        let expires = now
            .checked_add(review_ms)
            .ok_or(Error::InvalidData)?
            .min(context.source.original_ceiling_ms());
        let display = serde_json::to_string_pretty(&serde_json::json!({
            "purpose": "acquire-one-exact-exporter-bound-writer-session-v1",
            "notice": "This recipe permits only one Acquire attempt using the retained selected writer and this exact authenticated history, source, head and deterministic operation. The actual session ID and nonbackup key are generated only from the one real TLS exporter during that attempt, not before this review. Separate Arm and final approval are required. No Activate, signature, resend, replacement session or refreshed interval is permitted. An uncertain attempt retains the same client only for bounded cleanup and disposal.",
            "source_identity_digest": context.source.identity_digest(),
            "original_host_process_instance": host.instance(),
            "writer_read_presentation_digest": read.presentation_digest,
            "writer_selection_digest": read.facts.writer_selection_digest,
            "writer_certificate_digest": read.facts.writer_certificate_digest,
            "writer_disclosure": history.disclosure(),
            "exact_continuation_request": request,
            "financial_terms": context.terms,
            "authenticated_history_digest": history.history_digest(),
            "authenticated_snapshot": history.snapshot(),
            "deterministic_acquire_operation_id": acquire_operation_id,
            "reviewed_at_ms": now,
            "expires_at_ms": expires,
            "source_expires_at_ms": context.source.original_ceiling_ms(),
        })).map_err(|_| Error::InvalidData)?;
        let recipe = SignerAcquireFactsV1 {
            display,
            source_identity_digest: context.source.identity_digest().to_owned(),
            terms_digest: context
                .terms
                .intent_terms_digest()
                .map_err(|_| Error::InvalidData)?,
            continuation_request_digest: SignerContinuePresentationV1::calculate_request_digest(
                &request_json,
            ),
            continuation_request_json: request_json,
            admit_presentation_digest: read.facts.admit_presentation_digest.clone(),
            writer_read_presentation_digest: read.presentation_digest.clone(),
            original_host_process_instance: host.instance().to_owned(),
            owner_certificate_digest: read.facts.owner_certificate_digest.clone(),
            owner_disclosure_digest: read.facts.owner_disclosure_digest.clone(),
            writer_selection_digest: read.facts.writer_selection_digest.clone(),
            writer_certificate_digest: read.facts.writer_certificate_digest.clone(),
            writer_disclosure_json: read.facts.writer_disclosure_json.clone(),
            writer_disclosure_digest: read.facts.writer_disclosure_digest.clone(),
            authenticated_history_digest: history.history_digest().to_owned(),
            authenticated_snapshot_json: serde_json::to_string(history.snapshot())
                .map_err(|_| Error::InvalidData)?,
            expected_head_sequence: history.snapshot().head.sequence,
            expected_head_digest: history.snapshot().head.digest.clone(),
            acquire_operation_id,
            writer_epoch: history.snapshot().writer_epoch,
            reviewed_at_ms: now,
            expires_at_ms: expires,
            source_expires_at_ms: context.source.original_ceiling_ms(),
        };
        inputs.check_preparation_current(&context.source, &context.owner, host)?;
        inputs.final_read.check_current()?;
        recipe.validate()?;
        // The same live Read and complete local recipe move together into the
        // consuming Origin presentation join below, never a post-Read reread.
        Ok(PreparedCoordinatedAcquireUnderReadV1 {
            context,
            inputs,
            recipe,
            original_acquire_deadline,
        })
    }
}

/// Same actual Context and selected restricted client, authenticated history,
/// immutable presentation and original Acquire bound. No source/client getter,
/// action constructor, session recipe retry or automatic effect is exposed.
pub(in crate::native_ui::runtime) struct PresentedCoordinatedAcquireReviewV1 {
    context: Context,
    writer: FinancialWitnessCustodyV1,
    history: AuthenticatedFinancialContinuationHistoryV1,
    presentation: SignerAcquirePresentationV1,
    original_acquire_deadline: Instant,
}
impl PreparedCoordinatedAcquireUnderReadV1 {
    /// The continuously borrowed actual Origin both freezes and sends this
    /// exact draft. No independently supplied second origin can be substituted
    /// between consuming Read and presenting its already frozen data.
    pub(in crate::native_ui::runtime) fn freeze_and_present(
        self,
        origin: &mut SignerFinancialWorkflowOriginV1,
    ) -> Result<PresentedCoordinatedAcquireReviewV1> {
        let Self {
            context,
            inputs,
            recipe,
            original_acquire_deadline,
        } = self;
        let host = context
            .original_peer
            .as_ref()
            .ok_or(Error::Authentication)?;
        inputs.check_preparation_current(&context.source, &context.owner, host)?;
        recipe.validate()?;
        let presentation = origin.begin_acquire_review(
            &inputs.final_read,
            recipe.clone(),
            context.source.original_deadline(),
            original_acquire_deadline,
        )?;
        presentation.validate()?;
        let read = inputs.final_read.presentation();
        if presentation.facts != recipe
            || presentation.actor != read.actor
            || presentation.source_ceiling_ms != read.source_ceiling_ms
            || presentation.facts.writer_read_presentation_digest != read.presentation_digest
            || presentation.recipe_digest != recipe.calculate_recipe_digest()?
        {
            return Err(Error::ReviewMismatch);
        }
        // Concrete Read checks bracket the final source pin. No full source
        // audit, private read or replacement clock occurs after finish_read.
        inputs.check_preparation_current(&context.source, &context.owner, host)?;
        let (writer, history) = inputs.finish_preparation(&context.source, &context.owner, host)?;
        origin.send_acquire_display()?;
        Ok(PresentedCoordinatedAcquireReviewV1 {
            context,
            writer,
            history,
            presentation,
            original_acquire_deadline,
        })
    }
}

/// Exact actual Ready state only. The existing source, owner/writer clients,
/// authenticated history and pin remain private; there is no Final effect,
/// success/report, retry or disposal assertion in this preparation boundary.
pub(in crate::native_ui::runtime) struct ReadyCoordinatedAcquireV1 {
    retained: PresentedCoordinatedAcquireReviewV1,
    pin: FinancialOperationSourcePinV1,
    acquire_ready_digest: String,
}
impl PresentedCoordinatedAcquireReviewV1 {
    pub(in crate::native_ui::runtime) fn prepare_ready(
        self,
        arm: SignerAcquireArmV1,
    ) -> Result<AcquireReadyToReportV1> {
        arm.check_current()?;
        if arm.presentation() != &self.presentation
            || arm.original_source_deadline() != self.context.source.original_deadline()
            || arm.original_acquire_deadline() != self.original_acquire_deadline
        {
            return Err(Error::ReviewMismatch);
        }
        check_retained_context(&self.context)?;
        arm.check_current()?;
        let host = self
            .context
            .original_peer
            .as_ref()
            .ok_or(Error::Authentication)?;
        let pin = self.writer.prepare_coordinated_acquire_pin_v1(
            &self.context.source,
            &self.context.owner,
            host,
            &self.history,
            &arm,
        )?;
        arm.check_current()?;
        let acquire_ready_digest = pin.coordinated_acquire_ready_digest_v1(&self.presentation)?;
        arm.check_current()?;
        // The concrete source/journal factory has returned and dropped every
        // acquisition guard before the genuine original-channel send below.
        Ok(AcquireReadyToReportV1 { arm, ready: ReadyCoordinatedAcquireV1 {
            retained: self, pin, acquire_ready_digest,
        } })
    }
}

/// Only the actual one-use Acquire and authenticated original-channel report
/// produce this owner. Ordinary receipt data cannot recreate it. The Activate
/// child may consume these fields; no source/client/permission getter exists.
pub(in crate::native_ui::runtime) struct AwaitingCoordinatedActivateReadV1 {
    context: Context,
    receipt: wholepact_authority::WriterSessionReceipt,
    acquired_presentation: SignerAcquirePresentationV1,
    acquired_report: wholepact_financial_coordinator_origin::SignerAcquireCommittedV1,
    original_writer_session_deadline: Instant,
    original_service_deadline: Instant,
}

/// Terminal custody, never a retry or next-stage owner. Keep the same source,
/// clients, pin and authenticated history until the surrounding worker has
/// actually joined. If transport authenticated a receipt before restriction or
/// report loss, retain that evidence too; absence is not proof of no effect.
pub(in crate::native_ui::runtime) struct FailedCoordinatedAcquireV1 {
    retained: ReadyCoordinatedAcquireV1,
    receipt: Option<wholepact_authority::WriterSessionReceipt>,
    error: Error,
    attempted: bool,
}
impl FailedCoordinatedAcquireV1 {
    pub(in crate::native_ui::runtime) fn is_uncertain(&self) -> bool {
        self.attempted
    }
    pub(in crate::native_ui::runtime) fn error(&self) -> &Error {
        &self.error
    }
}

impl ReadyCoordinatedAcquireV1 {
    pub(in crate::native_ui::runtime) fn commit_final(
        self,
        final_action: wholepact_financial_coordinator_origin::SignerAcquireFinalV1,
    ) -> CoordinatedAcquireCommitV1 {
        use crate::native_ui::witness_workspace::financial_continuation_v1::coordinated_acquire_v1::CoordinatedAcquireFailureV1;
        use wholepact_financial_coordinator_origin::SignerAcquireCommittedV1;
        let mut receipt = None;
        let mut attempted = false;
        let original_service_deadline = final_action.original_service_deadline();
        let result = (|| -> Result<(Instant, SignerAcquireCommittedV1)> {
            final_action.check_current()?;
            let retained = &self.retained;
            if final_action.presentation() != &retained.presentation
                || final_action.acquire_ready_digest() != self.acquire_ready_digest
                || final_action.original_source_deadline()
                    != retained.context.source.original_deadline()
                || final_action.original_acquire_deadline() != retained.original_acquire_deadline
            {
                return Err(Error::ReviewMismatch);
            }
            check_retained_context(&retained.context)?;
            let service_digest = final_action.signing_service_digest().to_owned();
            let host = retained
                .context
                .original_peer
                .as_ref()
                .ok_or(Error::Authentication)?;
            let (actual, deadline) = match retained.writer.acquire_coordinated_once_v1(
                &retained.context.source,
                &retained.context.owner,
                host,
                &retained.history,
                &self.pin,
                final_action,
            ) {
                Ok(value) => {
                    attempted = true;
                    value
                }
                Err(CoordinatedAcquireFailureV1::KnownNoEffect(error)) => return Err(error),
                Err(CoordinatedAcquireFailureV1::Uncertain {
                    error,
                    receipt: actual,
                }) => {
                    attempted = true;
                    receipt = actual;
                    return Err(error);
                }
            };
            receipt = Some(actual);
            let actual = receipt.as_ref().ok_or(Error::Uncertain)?;
            let report = SignerAcquireCommittedV1 {
                presentation_digest: retained.presentation.presentation_digest.clone(),
                recipe_digest: retained.presentation.recipe_digest.clone(),
                acquire_ready_digest: self.acquire_ready_digest.clone(),
                signing_service_digest: service_digest,
                session_id: actual.session_id.clone(),
                writer_certificate_digest: actual.writer_certificate_digest.clone(),
                writer_epoch: actual.writer_epoch,
                reconciled_head_sequence: actual.reconciled_head.sequence,
                reconciled_head_digest: actual.reconciled_head.digest.clone(),
                reconciled_history_digest: actual.reconciled_history_digest.clone(),
                acquired_head_sequence: actual.acquired_head.sequence,
                acquired_head_digest: actual.acquired_head.digest.clone(),
                acquired_at_ms: actual.acquired_at_ms,
                expires_at_ms: actual.expires_at_ms,
                disclosure_json: serde_json::to_string(&actual.disclosure)
                    .map_err(|_| Error::InvalidData)?,
                disclosure_digest: wholepact_core::proposal::canonical_digest(
                    "wholepact:coordinated-original-financial-disclosure:v1",
                    &actual.disclosure,
                )
                .map_err(|_| Error::InvalidData)?,
            };
            report.validate()?;
            // This is authenticated-result observation, not renewal of Final.
            // No private audit, wallet preparation, or replacement key occurs.

            Ok((deadline, report))
        })();
        let result = match result {
            Ok((original_writer_session_deadline, acquired_report)) => {
                let ReadyCoordinatedAcquireV1 { retained, .. } = self;
                let PresentedCoordinatedAcquireReviewV1 {
                    mut context,
                    writer,
                    presentation,
                    ..
                } = retained;
                context.writer = Some(writer);
                context.next = Next::Activate;
                Ok(AwaitingCoordinatedActivateReadV1 {
                    context,
                    receipt: receipt.expect("successful actual Acquire retains receipt"),
                    acquired_presentation: presentation,
                    acquired_report,
                    original_writer_session_deadline,
                    original_service_deadline,
                })
            }
            Err(error) => {
                Err(FailedCoordinatedAcquireV1 {
                    retained: self,
                    receipt,
                    error,
                    attempted,
                })
            }
        };
        CoordinatedAcquireCommitV1 { result }
    }
}

pub(in crate::native_ui::runtime) struct AcquireReadyToReportV1 { arm: SignerAcquireArmV1, ready: ReadyCoordinatedAcquireV1 }
impl AcquireReadyToReportV1 {
    pub(in crate::native_ui::runtime) fn send_ready(self, origin: &mut SignerFinancialWorkflowOriginV1) -> Result<ReadyCoordinatedAcquireV1> {
        origin.send_acquire_ready(self.arm, self.ready.acquire_ready_digest.clone())?;
        Ok(self.ready)
    }
}
pub(in crate::native_ui::runtime) struct CoordinatedAcquireCommitV1 { result: std::result::Result<AwaitingCoordinatedActivateReadV1, FailedCoordinatedAcquireV1> }
impl CoordinatedAcquireCommitV1 {
    pub(in crate::native_ui::runtime) fn succeeded(&self) -> bool { self.result.is_ok() }
    pub(in crate::native_ui::runtime) fn report(&self, origin: &mut SignerFinancialWorkflowOriginV1) -> Result<()> {
        use wholepact_financial_coordinator_origin::SignerAcquireOutcomeV1;
        match &self.result {
            Ok(actual) => { origin.report_acquired(actual.acquired_report.clone(),actual.original_writer_session_deadline)?; Ok(()) }
            Err(failed) => {
                let presentation_digest=failed.retained.retained.presentation.presentation_digest.clone();
                let acquire_ready_digest=Some(failed.retained.acquire_ready_digest.clone());
                let outcome=if failed.attempted { SignerAcquireOutcomeV1::Uncertain {presentation_digest,acquire_ready_digest} } else {SignerAcquireOutcomeV1::KnownNoEffect {presentation_digest,acquire_ready_digest}};
                let report=origin.send_acquire_outcome(outcome);
                origin.close_for_failed_worker_v1();
                report.map_err(Into::into)
            }
        }
    }
    pub(in crate::native_ui::runtime) fn into_result(self)->std::result::Result<AwaitingCoordinatedActivateReadV1,FailedCoordinatedAcquireV1> {self.result}
}
