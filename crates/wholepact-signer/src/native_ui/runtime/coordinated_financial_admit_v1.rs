//! Private consuming same-role AwaitingAdmission adapter. Distinct genuine
//! Arm/Final gates preserve the retained Context and exact pending request.
//! No standalone runner, owner/source importer, native conversion, writer key
//! opening or automatic next-purpose approval.
use super::*;
#[cfg(feature = "coordinated-financial-workflow-v1")]
#[path = "coordinated_financial_writer_read_v1.rs"]
pub(in crate::native_ui::runtime) mod coordinated_writer_read;
use crate::account::birth::enrollment::roster_v2::financial_source_v1::FinancialAdmissionSourcePinV1;
use crate::consent_journal::PendingFinancialContinuationAdmissionV1;
use crate::native_ui::witness_workspace::financial_continuation_v1::coordinated_admit_v1::CoordinatedAdmitFailureV1 as Failure;
use std::time::{SystemTime, UNIX_EPOCH};
use wholepact_authority::AccountSnapshot;
use wholepact_financial_coordinator_origin::{
    SignerAdmitArmV1, SignerAdmitCommittedV1, SignerAdmitFactsV1, SignerAdmitFinalV1,
    SignerAdmitOutcomeV1, SignerAdmitPresentationV1, SignerContinuePresentationV1,
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

/// Metadata and already retained ordinary terms only. In particular, do not
/// call check_custody/check_pending or reopen either owner/writer configuration.
fn check_context(
    context: &Context,
    pending: &PendingFinancialContinuationAdmissionV1,
) -> Result<String> {
    if context.next != Next::Continue
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
    let request = pending.request();
    let record = match &request.control {
        OwnerControl::AdmitFinancialContinuationV1 { record } => record,
        _ => return Err(Error::ReviewMismatch),
    };
    if record.terms != context.terms
        || context.source.original_ceiling_ms() != context.terms.valid_until_ms
    {
        return Err(Error::ReviewMismatch);
    }
    record
        .validate_request(request, &context.terms.scope.witness)
        .map_err(|_| Error::ReviewMismatch)?;
    context
        .terms
        .require_live(wall_now()?)
        .map_err(|_| Error::Locked)?;
    context
        .source
        .require_coordinated_owner_metadata_v2(&context.terms.scope.witness, &certificate)?;
    context.source.check_coordinated_public_custody_v2(host)?;
    Ok(certificate)
}

pub(in crate::native_ui::runtime) struct PreparedCoordinatedAdmitRoleV1 {
    context: Context,
    pending: PendingFinancialContinuationAdmissionV1,
    presentation: SignerAdmitPresentationV1,
    original_admit_deadline: Instant,
}
pub(in crate::native_ui::runtime) struct ReadyCoordinatedAdmitRoleV1 {
    prepared: PreparedCoordinatedAdmitRoleV1,
    pin: FinancialAdmissionSourcePinV1,
    admission_ready_digest: String,
}

/// Exact same Context after validated admission. There is deliberately no
/// native ReadReady conversion or public field/constructor. The next explicit
/// writer-Read must consume this owner and authorize its own key/setup work.
pub(in crate::native_ui::runtime) struct AwaitingCoordinatedWriterReadV1 {
    context: Context,
    authenticated_snapshot: AccountSnapshot,
    // Cached exact request/provenance only, never a surviving action grant.
    admitted_presentation: SignerAdmitPresentationV1,
}

impl PreparedCoordinatedAdmitRoleV1 {
    /// Accept only the retained outcome path, never separately supplied owner,
    /// source or Host. Native outcomes fail the concrete source lifetime check.
    pub(in crate::native_ui::runtime) fn inspect(
        outcome: Outcome,
        original_session_deadline: Instant,
    ) -> Result<InspectedCoordinatedAdmitV1> {
        let Outcome::AwaitingAdmission(context, pending) = outcome else {
            return Err(Error::Unavailable);
        };
        let certificate = check_context(&context, &pending)?;
        let source = &context.source;
        let host = context
            .original_peer
            .as_ref()
            .ok_or(Error::Authentication)?;
        let request = pending.request();
        let request_json = serde_json::to_string(request).map_err(|_| Error::InvalidData)?;
        let disclosure = &context.terms.scope.witness;
        let disclosure_json = serde_json::to_string(disclosure).map_err(|_| Error::InvalidData)?;
        // Capture one independent Admit review interval before display. It may
        // only shorten the actual retained source/material/session ceiling.
        let monotonic_now = Instant::now();
        let now = wall_now()?;
        let original_admit_deadline = source
            .original_deadline()
            .min(original_session_deadline)
            .min(
                monotonic_now
                    .checked_add(Duration::from_secs(120))
                    .ok_or(Error::InvalidData)?,
            );
        let review_ms = u64::try_from(
            original_admit_deadline
                .checked_duration_since(monotonic_now)
                .ok_or(Error::Locked)?
                .as_millis(),
        )
        .map_err(|_| Error::InvalidData)?;
        let expires = now
            .checked_add(review_ms)
            .ok_or(Error::InvalidData)?
            .min(source.original_ceiling_ms());
        let admission_terms_digest = pending.admission_terms_digest(source.identity_digest())?;
        let display = serde_json::to_string_pretty(&serde_json::json!({
            "purpose": "admit_only_exact_retained_financial_continuation",
            "notice": "A separate Signer Arm permits one exact local pending/source preflight. A later native Final, only with the independently Armed original Witness, permits one owner-mTLS Mutate attempt. Cancel remains restrictive for every unsent physical I/O attempt. A lost response is uncertain, never permission to resend, replace, re-sign or refresh. No writer credential, wallet, signing or Return permission is included.",
            "selected_original_root": source.original_root(),
            "source_identity_digest": source.identity_digest(),
            "admission_terms_digest": admission_terms_digest,
            "original_host_process_instance": host.instance(),
            "owner_certificate_digest": certificate,
            "original_owner_disclosure": disclosure,
            "original_terms": context.terms,
            "exact_retained_request": request,
            "reviewed_at_ms": now,
            "expires_at_ms": expires,
            "source_expires_at_ms": source.original_ceiling_ms(),
        })).map_err(|_| Error::InvalidData)?;
        let facts = SignerAdmitFactsV1 {
            display,
            source_identity_digest: source.identity_digest().to_owned(),
            admission_terms_digest,
            request_digest: SignerContinuePresentationV1::calculate_request_digest(&request_json),
            request_json,
            original_host_process_instance: host.instance().to_owned(),
            owner_certificate_digest: certificate,
            disclosure_json,
            disclosure_digest: digest(
                "wholepact:coordinated-original-financial-disclosure:v1",
                disclosure,
            )?,
            account_id: request.account_id.clone(),
            network_profile_id: request.network_profile_id.clone(),
            operation_id: request.operation_id.clone(),
            expected_head_sequence: request.expected_head.sequence,
            expected_head_digest: request.expected_head.digest.clone(),
            terms_digest: context
                .terms
                .intent_terms_digest()
                .map_err(|_| Error::InvalidData)?,
            reviewed_at_ms: now,
            expires_at_ms: expires,
            source_expires_at_ms: source.original_ceiling_ms(),
        };
        facts.validate()?;
        check_context(&context, &pending)?;
        Ok(InspectedCoordinatedAdmitV1 {
            context,
            pending,
            facts,
            original_admit_deadline,
        })
    }
}
pub(in crate::native_ui::runtime) struct InspectedCoordinatedAdmitV1 {
    context: Context,
    pending: PendingFinancialContinuationAdmissionV1,
    facts: SignerAdmitFactsV1,
    original_admit_deadline: Instant,
}
impl InspectedCoordinatedAdmitV1 {
    /// Main actual Origin only; no private work or new deadline is introduced.
    pub(in crate::native_ui::runtime) fn offer(
        self,
        origin: &mut SignerFinancialWorkflowOriginV1,
    ) -> Result<PreparedCoordinatedAdmitRoleV1> {
        let Self {
            context,
            pending,
            facts,
            original_admit_deadline,
        } = self;
        let source = &context.source;
        let presentation = origin.offer_admit_review(
            facts.clone(),
            source.original_deadline(),
            original_admit_deadline,
        )?;
        presentation.validate()?;
        if presentation.facts != facts {
            return Err(Error::ReviewMismatch);
        }
        check_context(&context, &pending)?;
        Ok(PreparedCoordinatedAdmitRoleV1 {
            context,
            pending,
            presentation,
            original_admit_deadline,
        })
    }
}
impl PreparedCoordinatedAdmitRoleV1 {
    pub(in crate::native_ui::runtime) fn prepare_ready(
        self,
        arm: SignerAdmitArmV1,
    ) -> Result<AdmitReadyToReportV1> {
        arm.check_current()?;
        if arm.presentation() != &self.presentation
            || arm.original_source_deadline() != self.context.source.original_deadline()
            || arm.original_admit_deadline() != self.original_admit_deadline
        {
            return Err(Error::ReviewMismatch);
        }
        check_context(&self.context, &self.pending)?;
        arm.check_current()?;
        let pin = self.context.owner.prepare_coordinated_admit_pin_v1(
            &self.context.source,
            &self.pending,
            self.context
                .original_peer
                .as_ref()
                .ok_or(Error::Authentication)?,
            &arm,
        )?;
        arm.check_current()?;
        let admission_ready_digest =
            pin.coordinated_admission_ready_digest_v1(&self.presentation.presentation_digest)?;
        arm.check_current()?;
        // Audit locks are gone; Arm is consumed once by the genuine Ready send.
        Ok(AdmitReadyToReportV1 {
            arm,
            ready: ReadyCoordinatedAdmitRoleV1 {
                prepared: self,
                pin,
                admission_ready_digest,
            },
        })
    }
}

impl ReadyCoordinatedAdmitRoleV1 {
    pub(in crate::native_ui::runtime) fn commit_final(
        self,
        final_action: SignerAdmitFinalV1,
    ) -> CoordinatedAdmitCommitV1 {
        let presentation_digest = self.prepared.presentation.presentation_digest.clone();
        let ready_digest = self.admission_ready_digest.clone();
        let mut retained = None;
        let result: std::result::Result<SignerAdmitCommittedV1, Failure> = (|| {
            final_action
                .check_current()
                .map_err(|e| Failure::before_transport(e.into()))?;
            let Self {
                prepared,
                pin,
                admission_ready_digest,
            } = self;
            let PreparedCoordinatedAdmitRoleV1 {
                mut context,
                pending,
                presentation,
                original_admit_deadline,
            } = prepared;
            if final_action.presentation() != &presentation
                || final_action.original_source_deadline() != context.source.original_deadline()
                || final_action.original_admit_deadline() != original_admit_deadline
                || final_action.admission_ready_digest() != admission_ready_digest
                || final_action.witness_presentation_digest().len() != 64
                || !final_action
                    .witness_presentation_digest()
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit())
            {
                return Err(Failure::before_transport(Error::ReviewMismatch));
            }
            check_context(&context, &pending).map_err(Failure::before_transport)?;
            final_action
                .check_current()
                .map_err(|e| Failure::before_transport(e.into()))?;
            let snapshot = context.owner.admit_coordinated_once_v1(
                &context.source,
                pending,
                pin,
                context
                    .original_peer
                    .as_ref()
                    .ok_or_else(|| Failure::before_transport(Error::Authentication))?,
                final_action,
            )?;
            context.next = Next::Acquire;
            let committed = SignerAdmitCommittedV1 {
                presentation_digest: presentation.presentation_digest.clone(),
                admission_ready_digest,
                request_digest: presentation.facts.request_digest.clone(),
                head_sequence: snapshot.head.sequence,
                head_digest: snapshot.head.digest.clone(),
            };
            retained = Some(AwaitingCoordinatedWriterReadV1 {
                context,
                authenticated_snapshot: snapshot,
                admitted_presentation: presentation,
            });
            let context = &retained
                .as_ref()
                .ok_or_else(|| Failure::after_transport(Error::Unavailable))?
                .context;
            // No new private audit or writer key opening after the action ends.
            context
                .source
                .check_coordinated_public_custody_v2(
                    context
                        .original_peer
                        .as_ref()
                        .ok_or_else(|| Failure::after_transport(Error::Authentication))?,
                )
                .map_err(Failure::after_transport)?;
            Ok(committed)
        })();
        let failure_report = if let Err(failure) = &result {
            let data = if failure.is_uncertain() {
                SignerAdmitOutcomeV1::Uncertain {
                    presentation_digest,
                    admission_ready_digest: Some(ready_digest),
                }
            } else {
                SignerAdmitOutcomeV1::KnownNoEffect {
                    presentation_digest,
                    admission_ready_digest: Some(ready_digest),
                }
            };
            // Reporting loss cannot reset the consumed attempt or uncertainty.
            Some(data)
        } else {
            None
        };
        CoordinatedAdmitCommitV1 {
            retained,
            result,
            failure_report,
        }
    }
}
pub(in crate::native_ui::runtime) struct AdmitReadyToReportV1 {
    ready: ReadyCoordinatedAdmitRoleV1,
    arm: SignerAdmitArmV1,
}
impl AdmitReadyToReportV1 {
    pub(in crate::native_ui::runtime) fn send_ready(
        self,
        origin: &mut SignerFinancialWorkflowOriginV1,
    ) -> Result<ReadyCoordinatedAdmitRoleV1> {
        self.arm.check_current()?;
        origin.send_admit_ready(self.arm, self.ready.admission_ready_digest.clone())?;
        Ok(self.ready)
    }
}
/// Retain actual authenticated result custody in main before reporting. Late
/// source/R/report failure cannot become another owner mutation attempt.
pub(in crate::native_ui::runtime) struct CoordinatedAdmitCommitV1 {
    retained: Option<AwaitingCoordinatedWriterReadV1>,
    result: std::result::Result<SignerAdmitCommittedV1, Failure>,
    failure_report: Option<SignerAdmitOutcomeV1>,
}
impl CoordinatedAdmitCommitV1 {
    pub(in crate::native_ui::runtime) fn report(
        &self,
        origin: &mut SignerFinancialWorkflowOriginV1,
    ) -> Result<()> {
        match &self.result {
            Ok(committed) => origin.report_admitted(committed.clone())?,
            Err(_) => {
                origin.send_admit_outcome(self.failure_report.clone().ok_or(Error::Unavailable)?)?
            }
        }
        Ok(())
    }
    pub(in crate::native_ui::runtime) fn succeeded(&self) -> bool {
        self.result.is_ok()
    }
    pub(in crate::native_ui::runtime) fn into_result(
        mut self,
    ) -> std::result::Result<AwaitingCoordinatedWriterReadV1, Failure> {
        self.result?;
        self.retained
            .take()
            .ok_or_else(|| Failure::after_transport(Error::Unavailable))
    }
}
