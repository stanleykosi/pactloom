//! Consuming post-Acquire owner. Read prepares; distinct Activate effects once.
//! The only successful output stops BEFORE any wallet private preparation.
use super::*;
use crate::native_ui::witness_workspace::financial_continuation_v1::{
    financial_activation_digest, CoordinatedActivateFailureV1,
};
use wholepact_financial_coordinator_origin::{
    SignerActivateArmV1, SignerActivateCommittedV1, SignerActivateFactsV1, SignerActivateFinalV1,
    SignerActivateOriginalV1, SignerActivateOutcomeV1, SignerActivatePresentationV1,
    SignerActivateReadFactsV1, SignerActivateReadFinalV1, SignerActivateReadPresentationV1,
};

fn check_retained(retained: &AwaitingCoordinatedActivateReadV1) -> Result<()> {
    let c = &retained.context;
    if c.next != Next::Activate
        || c.writer.is_none()
        || c.material.is_none()
        || c.prepared_wallet.is_some()
        || c.wallet.is_some()
        || c.inputs.is_some()
        || c.prepared_spend.is_some()
        || c.active.is_some()
        || c.original_history.is_some()
        || c.history.is_some()
        || c.activation.is_some()
        || c.result_request.is_some()
        || Arc::strong_count(&c.source) != 1
        || Instant::now() >= retained.original_writer_session_deadline
        || Instant::now() >= retained.original_service_deadline
    {
        return Err(Error::Unavailable);
    }
    c.source.check_coordinated_public_custody_v2(
        c.original_peer.as_ref().ok_or(Error::Authentication)?,
    )?;
    c.terms
        .require_live(wall_now()?)
        .map_err(|_| Error::Locked)?;
    Ok(())
}
fn action_deadline(
    now: Instant,
    source: Instant,
    writer: Instant,
    service: Instant,
) -> Result<Instant> {
    let deadline = now
        .checked_add(Duration::from_secs(120))
        .ok_or(Error::Locked)?
        .min(source)
        .min(writer)
        .min(service);
    if deadline <= now {
        return Err(Error::Locked);
    }
    Ok(deadline)
}
fn ceiling(retained: &AwaitingCoordinatedActivateReadV1) -> Result<(Instant, u64, u64)> {
    let monotonic = Instant::now();
    let wall = wall_now()?;
    let deadline = action_deadline(
        monotonic,
        retained.context.source.original_deadline(),
        retained.original_writer_session_deadline,
        retained.original_service_deadline,
    )?;
    let ms = u64::try_from(
        deadline
            .checked_duration_since(monotonic)
            .ok_or(Error::Locked)?
            .as_millis(),
    )
    .map_err(|_| Error::Locked)?;
    let expires = wall
        .checked_add(ms)
        .ok_or(Error::Locked)?
        .min(retained.receipt.expires_at_ms)
        .min(retained.context.source.original_ceiling_ms());
    Ok((deadline, wall, expires))
}
pub(super) struct PresentedCoordinatedActivateReadV1 {
    retained: AwaitingCoordinatedActivateReadV1,
    presentation: SignerActivateReadPresentationV1,
    original_read_deadline: Instant,
}
impl AwaitingCoordinatedActivateReadV1 {
    pub(super) fn offer_activate_read(
        self,
        origin: &mut SignerFinancialWorkflowOriginV1,
    ) -> Result<PresentedCoordinatedActivateReadV1> {
        check_retained(&self)?;
        let (original_read_deadline, reviewed_at_ms, expires_at_ms) = ceiling(&self)?;
        let acquired = &self.acquired_presentation.facts;
        let original = SignerActivateOriginalV1 {
            source_identity_digest: acquired.source_identity_digest.clone(),
            terms_digest: acquired.terms_digest.clone(),
            continuation_request_json: acquired.continuation_request_json.clone(),
            continuation_request_digest: acquired.continuation_request_digest.clone(),
            original_host_process_instance: acquired.original_host_process_instance.clone(),
            owner_certificate_digest: acquired.owner_certificate_digest.clone(),
            owner_disclosure_digest: acquired.owner_disclosure_digest.clone(),
            writer_selection_digest: acquired.writer_selection_digest.clone(),
            acquired: self.acquired_report.clone(),
            source_expires_at_ms: acquired.source_expires_at_ms,
        };
        let facts = SignerActivateReadFactsV1 {
            display: serde_json::to_string_pretty(&serde_json::json!({
                "notice": "Read one complete owner history and prepare one immutable ActivateWriter request. No activation or wallet private read is authorized.",
                "original": original, "actual_acquired_receipt": self.receipt,
            })).map_err(|_| Error::InvalidData)?,
            original, reviewed_at_ms, expires_at_ms,
        };
        facts.validate()?;
        let presentation = origin.offer_activate_read(
            facts.clone(),
            self.context.source.original_deadline(),
            original_read_deadline,
        )?;
        if presentation.facts != facts {
            return Err(Error::ReviewMismatch);
        }
        Ok(PresentedCoordinatedActivateReadV1 {
            retained: self,
            presentation,
            original_read_deadline,
        })
    }
}
pub(super) struct PresentedCoordinatedActivateV1 {
    retained: AwaitingCoordinatedActivateReadV1,
    history: AuthenticatedFinancialContinuationHistoryV1,
    request: wholepact_authority::OwnerControlRequest,
    presentation: SignerActivatePresentationV1,
    original_activate_deadline: Instant,
}
impl PresentedCoordinatedActivateReadV1 {
    pub(super) fn read_and_prepare(
        self,
        read: SignerActivateReadFinalV1,
        origin: &mut SignerFinancialWorkflowOriginV1,
    ) -> Result<PresentedCoordinatedActivateV1> {
        read.check_current()?;
        check_retained(&self.retained)?;
        let c = &self.retained.context;
        if read.presentation() != &self.presentation
            || read.original_source_deadline() != c.source.original_deadline()
            || read.original_read_deadline() != self.original_read_deadline
            || read.original_service_deadline() != self.retained.original_service_deadline
            || read.original_writer_session_deadline()
                != self.retained.original_writer_session_deadline
        {
            return Err(Error::ReviewMismatch);
        }
        let (history, request) = c.owner.read_coordinated_activate_v1(
            &c.source,
            c.writer.as_ref().ok_or(Error::Unavailable)?,
            c.original_peer.as_ref().ok_or(Error::Authentication)?,
            &self.retained.receipt,
            &read,
        )?;
        read.check_current()?;
        let (original_activate_deadline, reviewed_at_ms, expires_at_ms) = ceiling(&self.retained)?;
        let activation_request_json =
            serde_json::to_string(&request).map_err(|_| Error::InvalidData)?;
        let facts = SignerActivateFactsV1 {
            display: serde_json::to_string_pretty(&serde_json::json!({
                "notice": "Activate this exact pending receipt once using the same owner. No wallet preparation, signature or Return is authorized.",
                "original": self.presentation.facts.original,
                "actual_receipt": self.retained.receipt,
                "authenticated_snapshot": history.snapshot(), "exact_activation": request,
            })).map_err(|_| Error::InvalidData)?,
            original: self.presentation.facts.original.clone(),
            activate_read_presentation_digest: self.presentation.presentation_digest.clone(),
            authenticated_history_digest: history.history_digest().to_owned(),
            authenticated_snapshot_json: serde_json::to_string(history.snapshot()).map_err(|_| Error::InvalidData)?,
            activation_request_digest: SignerActivateFactsV1::calculate_request_digest(&activation_request_json),
            activation_request_json, activation_terms_digest: financial_activation_digest(&history, &request)?,
            expected_head_sequence: request.expected_head.sequence,
            expected_head_digest: request.expected_head.digest.clone(), writer_epoch: request.writer_epoch,
            reviewed_at_ms, expires_at_ms,
        };
        facts.validate()?;
        read.check_current()?;
        let presentation = origin.begin_activate_review(
            &read,
            facts.clone(),
            c.source.original_deadline(),
            original_activate_deadline,
        )?;
        if presentation.facts != facts {
            return Err(Error::ReviewMismatch);
        }
        read.check_current()?;
        read.finish_read()?;
        // Display uses frozen cached data only, after the Read is consumed.
        origin.send_activate_display()?;
        Ok(PresentedCoordinatedActivateV1 {
            retained: self.retained,
            history,
            request,
            presentation,
            original_activate_deadline,
        })
    }
}
pub(super) struct ReadyCoordinatedActivateV1 {
    retained: PresentedCoordinatedActivateV1,
    pin: FinancialOperationSourcePinV1,
    ready_digest: String,
}
impl PresentedCoordinatedActivateV1 {
    pub(super) fn arm(
        self,
        arm: SignerActivateArmV1,
        origin: &mut SignerFinancialWorkflowOriginV1,
    ) -> Result<ReadyCoordinatedActivateV1> {
        arm.check_current()?;
        check_retained(&self.retained)?;
        if arm.presentation() != &self.presentation
            || arm.original_activate_deadline() != self.original_activate_deadline
            || arm.original_writer_session_deadline()
                != self.retained.original_writer_session_deadline
            || arm.original_service_deadline() != self.retained.original_service_deadline
        {
            return Err(Error::ReviewMismatch);
        }
        let c = &self.retained.context;
        let pin = c.owner.prepare_coordinated_activate_pin_v1(
            &c.source,
            c.writer.as_ref().ok_or(Error::Unavailable)?,
            c.original_peer.as_ref().ok_or(Error::Authentication)?,
            &self.history,
            &self.request,
            &self.retained.receipt,
            &arm,
        )?;
        let ready_digest = pin.coordinated_activate_ready_digest_v1(&self.presentation)?;
        arm.check_current()?;
        origin.send_activate_ready(arm, ready_digest.clone())?;
        Ok(ReadyCoordinatedActivateV1 {
            retained: self,
            pin,
            ready_digest,
        })
    }
}
/// Custody only. There is deliberately no implicit prepare call or Wallet grant.
pub(super) struct AwaitingCoordinatedWalletPrepareV1 {
    context: Context,
    receipt: wholepact_authority::WriterSessionReceipt,
    activated: wholepact_authority::AccountSnapshot,
    activation_presentation: SignerActivatePresentationV1,
    activation_report: SignerActivateCommittedV1,
    original_writer_session_deadline: Instant,
    original_service_deadline: Instant,
}
pub(super) struct FailedCoordinatedActivateV1 {
    retained: ReadyCoordinatedActivateV1,
    authenticated: Option<wholepact_authority::AccountSnapshot>,
    error: Error,
    attempted: bool,
}
impl ReadyCoordinatedActivateV1 {
    pub(super) fn consume_final(
        self,
        final_action: SignerActivateFinalV1,
        origin: &mut SignerFinancialWorkflowOriginV1,
    ) -> std::result::Result<AwaitingCoordinatedWalletPrepareV1, FailedCoordinatedActivateV1> {
        let mut authenticated = None;
        let mut attempted = false;
        let result = (|| -> Result<SignerActivateCommittedV1> {
            final_action.check_current()?;
            let retained = &self.retained;
            check_retained(&retained.retained)?;
            let c = &retained.retained.context;
            if final_action.presentation() != &retained.presentation
                || final_action.activate_ready_digest() != self.ready_digest
                || final_action.original_activate_deadline() != retained.original_activate_deadline
                || final_action.original_source_deadline() != c.source.original_deadline()
                || final_action.original_service_deadline()
                    != retained.retained.original_service_deadline
                || final_action.original_writer_session_deadline()
                    != retained.retained.original_writer_session_deadline
            {
                return Err(Error::ReviewMismatch);
            }
            let signing_service_digest = final_action.signing_service_digest().to_owned();
            let snapshot = match c.owner.activate_coordinated_once_v1(
                &c.source,
                c.writer.as_ref().ok_or(Error::Unavailable)?,
                c.original_peer.as_ref().ok_or(Error::Authentication)?,
                &retained.history,
                &retained.request,
                &retained.retained.receipt,
                &self.pin,
                final_action,
            ) {
                Ok(snapshot) => {
                    attempted = true;
                    snapshot
                }
                Err(CoordinatedActivateFailureV1::KnownNoEffect(error)) => return Err(error),
                Err(CoordinatedActivateFailureV1::Uncertain(error)) => {
                    attempted = true;
                    return Err(error);
                }
                Err(CoordinatedActivateFailureV1::Authenticated(snapshot, error)) => {
                    attempted = true;
                    authenticated = Some(snapshot);
                    return Err(error);
                }
            };
            let report = SignerActivateCommittedV1 {
                presentation_digest: retained.presentation.presentation_digest.clone(),
                activate_ready_digest: self.ready_digest.clone(),
                activation_request_digest: retained
                    .presentation
                    .facts
                    .activation_request_digest
                    .clone(),
                signing_service_digest,
                session_id: retained.retained.receipt.session_id.clone(),
                writer_epoch: snapshot.writer_epoch,
                head_sequence: snapshot.head.sequence,
                head_digest: snapshot.head.digest.clone(),
            };
            authenticated = Some(snapshot);
            report.validate()?;
            origin.report_activated(report.clone())?;
            Ok(report)
        })();
        match result {
            Ok(activation_report) => {
                let PresentedCoordinatedActivateV1 {
                    retained,
                    presentation,
                    ..
                } = self.retained;
                Ok(AwaitingCoordinatedWalletPrepareV1 {
                    context: retained.context,
                    receipt: retained.receipt,
                    activated: authenticated
                        .expect("successful activation retains authenticated snapshot"),
                    activation_presentation: presentation,
                    activation_report,
                    original_writer_session_deadline: retained.original_writer_session_deadline,
                    original_service_deadline: retained.original_service_deadline,
                })
            }
            Err(error) => {
                let presentation_digest = self.retained.presentation.presentation_digest.clone();
                let activate_ready_digest = Some(self.ready_digest.clone());
                let outcome = if attempted {
                    SignerActivateOutcomeV1::Uncertain {
                        presentation_digest,
                        activate_ready_digest,
                    }
                } else {
                    SignerActivateOutcomeV1::KnownNoEffect {
                        presentation_digest,
                        activate_ready_digest,
                    }
                };
                let _ = origin.send_activate_outcome(outcome);
                origin.close_for_failed_worker_v1();
                Err(FailedCoordinatedActivateV1 {
                    retained: self,
                    authenticated,
                    error,
                    attempted,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn activate_ceiling_is_independently_bounded_by_every_original_clock() {
        let now = Instant::now();
        let at = |seconds| now + Duration::from_secs(seconds);
        assert_eq!(
            action_deadline(now, at(400), at(400), at(400)).unwrap(),
            at(120)
        );
        assert_eq!(
            action_deadline(now, at(20), at(400), at(400)).unwrap(),
            at(20)
        );
        assert_eq!(
            action_deadline(now, at(400), at(30), at(400)).unwrap(),
            at(30)
        );
        assert_eq!(
            action_deadline(now, at(400), at(400), at(40)).unwrap(),
            at(40)
        );
        assert!(action_deadline(now, now, at(400), at(400)).is_err());
        assert!(action_deadline(now, at(400), now, at(400)).is_err());
        assert!(action_deadline(now, at(400), at(400), now).is_err());
    }
}
