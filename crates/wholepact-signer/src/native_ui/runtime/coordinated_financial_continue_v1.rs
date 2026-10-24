//! One same-role Continue adapter, not a runner or an issuer. Actual Context,
//! source, authenticated history, owner client and Host peer remain in Signer.
//! The original control owner must still observe R and join workers; no new
//! Admit permission is obtained from a successful nonterminal observation.
use super::*;
use crate::consent_journal::{
    CoordinatedContinuationCommitFailureV1 as Failure, CoordinatedContinueReviewDataV1,
    CoordinatedContinueSignerRoleV1, PresentedCoordinatedFinancialContinuationV1,
};
use crate::native_ui::witness_workspace::financial_continuation_v1::coordinated_initial_read_v1::ReadFinancialContinueInputsV2;
use std::time::{SystemTime, UNIX_EPOCH};
use wholepact_financial_coordinator_origin::{
    SignerContinuationSavedV1, SignerContinueArmV1, SignerContinueFinalV1, SignerContinueOutcomeV1,
    SignerContinuePresentationV1, SignerContinueReviewDataV1, SignerContinueRoleV1,
    SignerContinueSourceFactsV1, SignerFinancialReadFinalV1, SignerFinancialReadPresentationV1,
    SignerFinancialWorkflowOriginV1,
};

fn wall_now() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Locked)?
            .as_millis(),
    )
    .map_err(|_| Error::Locked)
}

/// Only ordinary data crosses the provenance type boundary. The existing
/// preparation later compares every field to the genuine Arm and Final.
fn local_review(data: &SignerContinueReviewDataV1) -> CoordinatedContinueReviewDataV1 {
    CoordinatedContinueReviewDataV1 {
        coordinator_process_instance: data.coordinator_process_instance.clone(),
        coordinator_focus_epoch: data.coordinator_focus_epoch,
        signer_role: match data.signer_role {
            SignerContinueRoleV1::Signer1 => CoordinatedContinueSignerRoleV1::Signer1,
            SignerContinueRoleV1::Signer2 => CoordinatedContinueSignerRoleV1::Signer2,
        },
        signer_process_instance: data.signer_process_instance.clone(),
        original_host_process_instance: data.original_host_process_instance.clone(),
        signer_principal_id: data.signer_principal_id.clone(),
        signer_image_measurement: data.signer_image_measurement.clone(),
        source_identity_digest: data.source_identity_digest.clone(),
        terms_digest: data.terms_digest.clone(),
        session_digest: data.session_digest.clone(),
        review_challenge: data.review_challenge.clone(),
        review_digest: data.review_digest.clone(),
        reviewed_at_ms: data.reviewed_at_ms,
        expires_at_ms: data.expires_at_ms,
        session_expires_at_ms: data.session_expires_at_ms,
    }
}

fn check_context(context: &Context, read: Option<&SignerFinancialReadFinalV1>) -> Result<String> {
    macro_rules! check_read {
        () => {
            if let Some(read) = read {
                read.check_current()?;
            }
        };
    }
    check_read!();
    if context.next != Next::Continue
        || context.material.is_none()
        || context.writer.is_some()
        || context.prepared_wallet.is_some()
        || context.wallet.is_some()
        || context.inputs.is_some()
        || context.prepared_spend.is_some()
        || context.active.is_some()
        || context.history.is_some()
        || context.activation.is_some()
        || context.result_request.is_some()
    {
        return Err(Error::Unavailable);
    }
    let source = &context.source;
    let host = context
        .original_peer
        .as_ref()
        .ok_or(Error::Authentication)?;
    check_read!();
    source.check_coordinated_public_custody_v2(host)?;
    check_read!();
    if source.original_ceiling_ms() != context.terms.valid_until_ms
        || Instant::now() >= source.original_deadline()
    {
        return Err(Error::Locked);
    }
    context
        .terms
        .require_live(wall_now()?)
        .map_err(|_| Error::Locked)?;
    check_read!();
    let certificate = context.owner.check_coordinated_continue_owner_v1(source)?;
    check_read!();
    source.require_coordinated_owner_metadata_v2(&context.terms.scope.witness, &certificate)?;
    check_read!();
    source.check_coordinated_public_custody_v2(host)?;
    check_read!();
    Ok(certificate)
}

fn check_completed_read(
    context: &Context,
    read: &SignerFinancialReadPresentationV1,
    certificate: &str,
    journal_digest: &str,
) -> Result<()> {
    read.validate()?;
    let facts = &read.facts;
    let terms = &context.terms;
    let host = context
        .original_peer
        .as_ref()
        .ok_or(Error::Authentication)?;
    if facts.source_identity_digest != context.source.identity_digest()
        || facts.original_journal_digest != journal_digest
        || facts.terms_digest
            != terms
                .intent_terms_digest()
                .map_err(|_| Error::InvalidData)?
        || facts.original_delivery_operation_id != terms.original_delivery_operation_id
        || facts.original_delivery_request_digest != terms.original_delivery_request_digest
        || facts.original_delivery_head_sequence != terms.original_delivery_committed_head.sequence
        || facts.original_delivery_head_digest != terms.original_delivery_committed_head.digest
        || facts.original_host_process_instance != host.instance()
        || facts.account_id != terms.scope.witness.account_id
        || facts.owner_certificate_digest != certificate
        || facts.disclosure_digest
            != digest(
                "wholepact:coordinated-original-financial-disclosure:v1",
                &terms.scope.witness,
            )?
        || facts.source_expires_at_ms != context.source.original_ceiling_ms()
    {
        return Err(Error::ReviewMismatch);
    }
    // A completed Read's short permission may have expired. This comparison is
    // evidence linkage only; current source custody and fresh Continue tokens
    // are separately required. Origin authenticates this exact retained Read.
    Ok(())
}

/// Non-cloneable actual role owner plus an inert frozen ticket. The ticket owns
/// the moved authenticated history; no additional Arc of source is retained.
pub(in crate::native_ui::runtime) struct PreparedCoordinatedContinueRoleV1 {
    context: Context,
    presented: PresentedCoordinatedFinancialContinuationV1,
    display: Option<SignerContinuePresentationV1>,
}

impl PreparedCoordinatedContinueRoleV1 {
    /// Move the actual source and one-use Read owner state into the existing
    /// Context. Unopened writer/wallet strings grant nothing; their later native
    /// purposes remain separate. No substitute source or native owner is built.
    pub(in crate::native_ui::runtime) fn inspect_from_read_v2(
        original_peer: crate::native_peer::PeerProcess,
        terms: FinancialContinuationTermsV1,
        material: VerifiedDurableEconomicsV1,
        writer_setup: Zeroizing<String>,
        wallet_setup: Zeroizing<String>,
        read: ReadFinancialContinueInputsV2,
    ) -> Result<InspectedCoordinatedContinueReadV1> {
        let ReadFinancialContinueInputsV2 {
            source,
            owner,
            history,
            final_read,
        } = read;
        let context = Context {
            source: Arc::new(source),
            original_peer: Some(original_peer),
            owner,
            writer: None,
            writer_setup,
            terms,
            material: Some(Arc::new(material)),
            wallet_setup,
            prepared_wallet: None,
            wallet: None,
            inputs: None,
            prepared_spend: None,
            active: None,
            original_history: Some(history),
            history: None,
            activation: None,
            result_request: None,
            next: Next::Continue,
        };
        Self::inspect_continue_v1(context, final_read)
    }

    fn inspect_continue_v1(
        mut context: Context,
        final_read: SignerFinancialReadFinalV1,
    ) -> Result<InspectedCoordinatedContinueReadV1> {
        final_read.check_current()?;
        let completed_read = final_read.presentation().clone();
        let certificate = check_context(&context, Some(&final_read))?;
        if Arc::strong_count(&context.source) != 1 {
            return Err(Error::Unavailable);
        }
        let host = context
            .original_peer
            .as_ref()
            .ok_or(Error::Authentication)?;
        let principal =
            context
                .source
                .coordinated_continue_principal_v1(&context.terms, host, &final_read)?;
        final_read.check_current()?;
        let journal_digest = context.source.coordinated_public_journal_digest_v2()?;
        final_read.check_current()?;
        check_completed_read(&context, &completed_read, &certificate, &journal_digest)?;
        let history = context
            .original_history
            .as_ref()
            .ok_or(Error::Unavailable)?;
        if history.disclosure() != &context.terms.scope.witness {
            return Err(Error::Authentication);
        }
        let history_digest = history.history_digest().map_err(|_| Error::InvalidData)?;
        let history_snapshot =
            serde_json::to_value(history.snapshot()).map_err(|_| Error::InvalidData)?;
        let review_digest = digest(
            "wholepact:coordinated-retained-financial-continue-review:v1",
            &(
                context.source.identity_digest(),
                &journal_digest,
                &principal,
                &context.terms,
                &history_digest,
                history.snapshot(),
                &certificate,
                host.instance(),
                &completed_read.presentation_digest,
                &completed_read.facts.owner_selection_digest,
            ),
        )?;
        let monotonic_now = Instant::now();
        let now = wall_now()?;
        // Continue has its OWN immutable review clock, captured once while the
        // separate Read Final is still live. No later display/Arm can renew it.
        let original_review_deadline = context.source.original_deadline().min(
            monotonic_now
                .checked_add(Duration::from_secs(120))
                .ok_or(Error::InvalidData)?,
        );
        final_read.check_current()?;
        let review_ms = u64::try_from(
            original_review_deadline
                .checked_duration_since(monotonic_now)
                .ok_or(Error::Locked)?
                .as_millis(),
        )
        .map_err(|_| Error::InvalidData)?;
        let facts = SignerContinueSourceFactsV1 {
            original_host_process_instance: host.instance().to_owned(),
            signer_principal_id: principal,
            source_identity_digest: context.source.identity_digest().to_owned(),
            terms_digest: context
                .terms
                .intent_terms_digest()
                .map_err(|_| Error::InvalidData)?,
            session_digest: completed_read.facts.session_digest.clone(),
            review_digest,
            reviewed_at_ms: now,
            expires_at_ms: now
                .checked_add(review_ms)
                .ok_or(Error::InvalidData)?
                .min(context.source.original_ceiling_ms()),
            // Historical field spelling; the immutable bound is the retained
            // terms/source wall ceiling, not a newly reconstructed session.
            session_expires_at_ms: context.source.original_ceiling_ms(),
        };
        Ok(InspectedCoordinatedContinueReadV1 {
            context,
            final_read,
            completed_read,
            certificate,
            journal_digest,
            history_digest,
            history_snapshot,
            facts,
            original_review_deadline,
        })
    }
}

pub(in crate::native_ui::runtime) struct InspectedCoordinatedContinueReadV1 {
    context: Context,
    final_read: SignerFinancialReadFinalV1,
    completed_read: SignerFinancialReadPresentationV1,
    certificate: String,
    journal_digest: String,
    history_digest: String,
    history_snapshot: serde_json::Value,
    facts: SignerContinueSourceFactsV1,
    original_review_deadline: Instant,
}
pub(in crate::native_ui::runtime) struct BoundCoordinatedContinueReviewV1 {
    inspected: InspectedCoordinatedContinueReadV1,
    review: SignerContinueReviewDataV1,
}
impl InspectedCoordinatedContinueReadV1 {
    /// Main control owner only: binds the already captured actual source facts
    /// to this genuine original Origin. No private I/O occurs here.
    pub(in crate::native_ui::runtime) fn begin_review(
        self,
        origin: &mut SignerFinancialWorkflowOriginV1,
    ) -> Result<BoundCoordinatedContinueReviewV1> {
        self.final_read.check_current()?;
        let review = origin.begin_continue_review(
            &self.final_read,
            self.facts.clone(),
            self.context.source.original_deadline(),
            self.original_review_deadline,
        )?;
        Ok(BoundCoordinatedContinueReviewV1 {
            inspected: self,
            review,
        })
    }
}
impl BoundCoordinatedContinueReviewV1 {
    /// Owned worker phase: genuine Read remains live through exact private
    /// preparation. No Origin reference, proxy issuer or report callback exists.
    pub(in crate::native_ui::runtime) fn prepare(
        self,
    ) -> Result<PreparedCoordinatedContinueRoleV1> {
        let Self { inspected, review } = self;
        let InspectedCoordinatedContinueReadV1 {
            mut context,
            final_read,
            completed_read,
            certificate,
            journal_digest,
            history_digest,
            history_snapshot,
            facts: _,
            original_review_deadline,
        } = inspected;
        final_read.check_current()?;
        let host = context
            .original_peer
            .as_ref()
            .ok_or(Error::Authentication)?;
        let history = context.original_history.take().ok_or(Error::Unavailable)?;
        final_read.check_current()?;
        let prepared = context
            .source
            .prepare_coordinated_continuation_from_read_v2(
                context.terms.clone(),
                history,
                host.clone(),
                local_review(&review),
                original_review_deadline,
                &final_read,
            )?;
        final_read.check_current()?;
        let presentation = project_continue_presentation(
            prepared.request(), prepared.prepared_digest(), review,
            context.source.original_root(), context.source.identity_digest(),
            &journal_digest, &certificate, &completed_read, &history_digest, &history_snapshot,
        )?;
        final_read.check_current()?;
        let presented = prepared.freeze_presentation_v1(&presentation)?;
        check_context(&context, Some(&final_read))?;
        final_read.check_current()?;
        // All private reads and complete immutable preparation are now done.
        // These two observations must precede the later genuine ContinueRequested.
        final_read.finish_read()?;
        Ok(PreparedCoordinatedContinueRoleV1 {
            context,
            presented,
            display: Some(presentation),
        })
    }
}
impl PreparedCoordinatedContinueRoleV1 {
    /// Main retains this actual prepared owner before reporting; report loss
    /// cannot discard or replay the completed private Read/preparation.
    pub(in crate::native_ui::runtime) fn report_read(
        &self,
        origin: &mut SignerFinancialWorkflowOriginV1,
    ) -> Result<()> {
        origin.history_read()?;
        Ok(())
    }

    /// Called only for the genuine same-Core ContinueRequested event. The Read
    /// has ended, so this operation sends cached immutable data and performs NO
    /// private source read or preparation and no review clock renewal.
    pub(in crate::native_ui::runtime) fn send_continue_display_v1(
        mut self,
        origin: &mut SignerFinancialWorkflowOriginV1,
    ) -> Result<Self> {
        let presentation = self.display.take().ok_or(Error::Unavailable)?;
        origin.send_continue_display(presentation)?;
        Ok(self)
    }

    /// A genuine matching Arm is consumed only after the unchanged source Ready
    /// guarded recheck. No source/journal guard remains across the Ready send.
    pub(in crate::native_ui::runtime) fn prepare_ready(
        self,
        arm: SignerContinueArmV1,
    ) -> Result<ContinueReadyToReportV1> {
        arm.check_current()?;
        if self.display.is_some() {
            return Err(Error::Unavailable);
        }
        check_context(&self.context, None)?;
        arm.check_current()?;
        self.context
            .source
            .check_coordinated_continuation_ready_workflow_v2(
                self.context
                    .original_peer
                    .as_ref()
                    .ok_or(Error::Authentication)?,
                &self.presented,
                &arm,
            )?;
        arm.check_current()?;
        Ok(ContinueReadyToReportV1 {
            prepared: self,
            arm,
        })
    }

    /// Consumes both actual role custody and the genuine one-use Final. No error
    /// returns the source, ticket or grant. Successful Context/Pending remain in
    /// this SAME role/session; no terminal disposal or owner network send occurs.
    pub(in crate::native_ui::runtime) fn commit_final(
        self,
        final_admission: SignerContinueFinalV1,
    ) -> CoordinatedContinueCommitV1 {
        let presentation_digest = self.presented.presentation_digest().to_owned();
        let prepared_digest = self.presented.prepared_digest().to_owned();
        let mut retained = None;
        let result: std::result::Result<SignerContinuationSavedV1, Failure> = (|| {
            final_admission
                .check_current()
                .map_err(|e| Failure::before_effect(e.into()))?;
            if self.display.is_some() {
                return Err(Failure::before_effect(Error::Unavailable));
            }
            check_context(&self.context, None).map_err(Failure::before_effect)?;
            final_admission
                .check_current()
                .map_err(|e| Failure::before_effect(e.into()))?;
            let Self {
                mut context,
                presented,
                display: _,
            } = self;
            let source = Arc::try_unwrap(context.source)
                .map_err(|_| Failure::before_effect(Error::Unavailable))?;
            let host = context
                .original_peer
                .as_ref()
                .ok_or_else(|| Failure::before_effect(Error::Authentication))?;
            let (source, pending) = source.commit_coordinated_continuation_workflow_v2(
                host,
                presented,
                final_admission,
            )?;
            context.source = Arc::new(source);
            // Retain committed actual source/Pending before any post-effect
            // check or reporting can fail, including ordinary R.
            retained = Some(Outcome::AwaitingAdmission(context, pending));
            let Some(Outcome::AwaitingAdmission(context, pending)) = retained.as_ref() else {
                return Err(Failure::after_commit_attempt(Error::Unavailable));
            };
            let host = context
                .original_peer
                .as_ref()
                .ok_or_else(|| Failure::after_commit_attempt(Error::Authentication))?;
            // Recipient was retained unchanged through the same transaction.
            // This checks actual same_live_process plus metadata, not new rows.
            context
                .source
                .check_coordinated_public_custody_v2(host)
                .map_err(Failure::after_commit_attempt)?;
            let admission_terms_digest = pending
                .admission_terms_digest(context.source.identity_digest())
                .map_err(|e| Failure::after_commit_attempt(e.into()))?;
            check_context(&context, None).map_err(Failure::after_commit_attempt)?;
            // An admitted Continue may finish after ordinary R. This observation
            // never overrides R or grants a usable next Admit slot. The control
            // owner must join/drop Context/Pending on cancellation.
            Ok(SignerContinuationSavedV1 {
                presentation_digest: presentation_digest.clone(),
                prepared_digest: prepared_digest.clone(),
                source_identity_digest: context.source.identity_digest().to_owned(),
                admission_terms_digest,
            })
        })();
        let failure_report = if let Err(failure) = &result {
            // One best-effort terminal observation, not a retry of the effect.
            // Lost reporting cannot downgrade actual commit/rollback uncertainty.
            let data = if failure.is_uncertain() {
                SignerContinueOutcomeV1::Uncertain {
                    presentation_digest,
                    prepared_digest,
                }
            } else {
                SignerContinueOutcomeV1::KnownNoEffect {
                    presentation_digest,
                    prepared_digest,
                }
            };
            Some(data)
        } else {
            None
        };
        CoordinatedContinueCommitV1 {
            retained,
            result,
            failure_report,
        }
    }
}

pub(in crate::native_ui::runtime) struct ContinueReadyToReportV1 {
    prepared: PreparedCoordinatedContinueRoleV1,
    arm: SignerContinueArmV1,
}
impl ContinueReadyToReportV1 {
    pub(in crate::native_ui::runtime) fn send_ready(
        self,
        origin: &mut SignerFinancialWorkflowOriginV1,
    ) -> Result<PreparedCoordinatedContinueRoleV1> {
        self.arm.check_current()?;
        origin.send_continue_ready(self.arm)?;
        Ok(self.prepared)
    }
}
/// Sealed actual worker result. Keep this owner in main state before reporting;
/// after-effect failure retains its actual Context/Pending until cleanup.
pub(in crate::native_ui::runtime) struct CoordinatedContinueCommitV1 {
    retained: Option<Outcome>,
    result: std::result::Result<SignerContinuationSavedV1, Failure>,
    failure_report: Option<SignerContinueOutcomeV1>,
}
impl CoordinatedContinueCommitV1 {
    pub(in crate::native_ui::runtime) fn report(
        &self,
        origin: &mut SignerFinancialWorkflowOriginV1,
    ) -> Result<()> {
        match &self.result {
            Ok(saved) => origin.continuation_saved(saved.clone())?,
            Err(_) => origin
                .send_continue_outcome(self.failure_report.clone().ok_or(Error::Unavailable)?)?,
        }
        Ok(())
    }
    pub(in crate::native_ui::runtime) fn succeeded(&self) -> bool {
        self.result.is_ok()
    }
    pub(in crate::native_ui::runtime) fn into_result(
        mut self,
    ) -> std::result::Result<Outcome, Failure> {
        self.result?;
        self.retained
            .take()
            .ok_or_else(|| Failure::after_commit_attempt(Error::Unavailable))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coordinated_continue_review_mapping_preserves_all_fifteen_fields() {
        for role in [SignerContinueRoleV1::Signer1, SignerContinueRoleV1::Signer2] {
            let data = SignerContinueReviewDataV1 {
                coordinator_process_instance: "01".repeat(32),
                coordinator_focus_epoch: 1,
                signer_role: role,
                signer_process_instance: "02".repeat(32),
                original_host_process_instance: "03".repeat(32),
                signer_principal_id: "public-synthetic-principal".into(),
                signer_image_measurement: "04".repeat(32),
                source_identity_digest: "05".repeat(32),
                terms_digest: "06".repeat(32),
                session_digest: "07".repeat(32),
                review_challenge: "08".repeat(32),
                review_digest: "09".repeat(32),
                reviewed_at_ms: 1_000,
                expires_at_ms: 121_000,
                session_expires_at_ms: 1_800_000,
            };
            assert_eq!(
                serde_json::to_value(local_review(&data)).unwrap(),
                serde_json::to_value(&data).unwrap()
            );
        }
    }
}

// Pure complete display projection; no permission, source access or effect.
#[allow(clippy::too_many_arguments)]
pub(crate) fn project_continue_presentation(
    request: &wholepact_authority::OwnerControlRequest,
    prepared_digest: &str,
    review: SignerContinueReviewDataV1,
    selected_root: &std::path::Path,
    source_identity: &str,
    journal_digest: &str,
    certificate: &str,
    completed_read: &SignerFinancialReadPresentationV1,
    history_digest: &str,
    history_snapshot: &serde_json::Value,
) -> Result<SignerContinuePresentationV1> {
    let request_json =
        serde_json::to_string(request).map_err(|_| Error::InvalidData)?;
    let display = serde_json::to_string_pretty(&serde_json::json!({
        "purpose": "save_one_exact_local_financial_continuation",
        "notice": "This Continue saves the exact local request only. Witness review and a separate fresh Admit are still required. No owner mutation, wallet access, signature or return is authorized.",
        "selected_root": selected_root,
        "source_identity_digest": source_identity,
        "original_journal_digest": journal_digest,
        "owner_certificate_digest": certificate,
        "completed_read_presentation_digest": completed_read.presentation_digest,
        "owner_selection_digest": completed_read.facts.owner_selection_digest,
        "authenticated_history_digest": history_digest,
        "authenticated_snapshot": history_snapshot,
        "review": review,
        "exact_request": request,
    })).map_err(|_| Error::InvalidData)?;
    let mut presentation = SignerContinuePresentationV1 {
        review,
        display,
        request_digest: SignerContinuePresentationV1::calculate_request_digest(&request_json),
        request_json,
        prepared_digest: prepared_digest.to_owned(),
        presentation_digest: String::new(),
    };
    presentation.presentation_digest = presentation.calculate_presentation_digest()?;
    presentation.validate()?;
    Ok(presentation)
}
