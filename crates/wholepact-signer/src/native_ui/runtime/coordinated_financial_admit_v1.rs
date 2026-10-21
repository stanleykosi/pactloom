//! Private consuming same-role AwaitingAdmission adapter. Distinct genuine
//! Arm/Final gates preserve the retained Context and exact pending request.
//! No standalone runner, owner/source importer, native conversion, writer key
//! opening or automatic next-purpose approval.
use super::*;
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

pub(super) struct PreparedCoordinatedAdmitRoleV1 {
    context: Context,
    pending: PendingFinancialContinuationAdmissionV1,
    presentation: SignerAdmitPresentationV1,
    original_admit_deadline: Instant,
}
pub(super) struct ReadyCoordinatedAdmitRoleV1 {
    prepared: PreparedCoordinatedAdmitRoleV1,
    pin: FinancialAdmissionSourcePinV1,
    admission_ready_digest: String,
}

/// Exact same Context after validated admission. There is deliberately no
/// native ReadReady conversion or public field/constructor. The next explicit
/// writer-Read must consume this owner and authorize its own key/setup work.
pub(super) struct AwaitingCoordinatedWriterReadV1 {
    context: Context,
    authenticated_snapshot: AccountSnapshot,
    // Cached exact request/provenance only, never a surviving action grant.
    admitted_presentation: SignerAdmitPresentationV1,
}

impl PreparedCoordinatedAdmitRoleV1 {
    /// Accept only the retained outcome path, never separately supplied owner,
    /// source or Host. Native outcomes fail the concrete source lifetime check.
    pub(super) fn prepare(
        outcome: Outcome,
        origin: &mut SignerFinancialWorkflowOriginV1,
    ) -> Result<Self> {
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
            .min(origin.session_deadline())
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
        // Every source/recipient/binding guard has dropped before original IPC.
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
        Ok(Self {
            context,
            pending,
            presentation,
            original_admit_deadline,
        })
    }

    pub(super) fn send_ready(
        self,
        arm: SignerAdmitArmV1,
        origin: &mut SignerFinancialWorkflowOriginV1,
    ) -> Result<ReadyCoordinatedAdmitRoleV1> {
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
        origin.send_admit_ready(arm, admission_ready_digest.clone())?;
        Ok(ReadyCoordinatedAdmitRoleV1 {
            prepared: self,
            pin,
            admission_ready_digest,
        })
    }
}

impl ReadyCoordinatedAdmitRoleV1 {
    pub(super) fn consume_final(
        self,
        final_action: SignerAdmitFinalV1,
        origin: &mut SignerFinancialWorkflowOriginV1,
    ) -> std::result::Result<AwaitingCoordinatedWriterReadV1, Failure> {
        let presentation_digest = self.prepared.presentation.presentation_digest.clone();
        let ready_digest = self.admission_ready_digest.clone();
        let result = (|| {
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
            origin
                .report_admitted(SignerAdmitCommittedV1 {
                    presentation_digest: presentation.presentation_digest.clone(),
                    admission_ready_digest,
                    request_digest: presentation.facts.request_digest.clone(),
                    head_sequence: snapshot.head.sequence,
                    head_digest: snapshot.head.digest.clone(),
                })
                .map_err(|e| Failure::after_transport(e.into()))?;
            context.next = Next::Acquire;
            Ok(AwaitingCoordinatedWriterReadV1 {
                context,
                authenticated_snapshot: snapshot,
                admitted_presentation: presentation,
            })
        })();
        if let Err(failure) = &result {
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
            let _ = origin.send_admit_outcome(data);
        }
        result
    }
}
