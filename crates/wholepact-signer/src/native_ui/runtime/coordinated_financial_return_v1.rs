//! Actual successful Sign custody to fresh ReturnRead and exact original stream.
//! Private child of Sign: no constructor accepts a caller-supplied result DTO.
use super::*;
use crate::account::birth::enrollment::roster_v2::durable_entry_v1::CoordinatedFinancialRoleTransportV1;
use crate::authority_bridge::financial_continuation_v1::PreparedCoordinatedFinancialReturnV1;
use wholepact_financial_coordinator_origin::{
    SignerReturnReadFactsV1, SignerReturnReadFinalV1, SignerReturnReadPresentationV1,
};

pub(in crate::native_ui::runtime) struct PresentedCoordinatedReturnReadV1 {
    retained: AwaitingCoordinatedReturnReadV1,
    transport: CoordinatedFinancialRoleTransportV1,
    event: crate::ipc::CoordinatedFinancialResultEventV1,
    presentation: SignerReturnReadPresentationV1,
    deadline: Instant,
}
pub(in crate::native_ui::runtime) struct UnreportedCoordinatedReturnPreparedV1 {
    retained: AwaitingCoordinatedReturnReadV1,
    prepared: PreparedCoordinatedFinancialReturnV1,
}
pub(in crate::native_ui::runtime) struct FailedCoordinatedReturnV1 {
    retained: AwaitingCoordinatedReturnReadV1,
    error: Error,
    prepared: Option<PreparedCoordinatedFinancialReturnV1>,
    failure: wholepact_financial_coordinator_origin::SignerReturnFailureV1,
}
/// A failed first offer retains the actual successful Sign owner and exact
/// original request/transport. It has no retry or fabricated failure-report API.
pub(in crate::native_ui::runtime) struct FailedCoordinatedReturnOfferV1 {
    retained: AwaitingCoordinatedReturnReadV1,
    transport: CoordinatedFinancialRoleTransportV1,
    event: crate::ipc::CoordinatedFinancialResultEventV1,
    presentation: Option<SignerReturnReadPresentationV1>,
    error: Error,
}
impl AwaitingCoordinatedReturnReadV1 {
    pub(in crate::native_ui::runtime) fn offer_return_read(
        self,
        transport: CoordinatedFinancialRoleTransportV1,
        event: crate::ipc::CoordinatedFinancialResultEventV1,
        origin: &mut SignerFinancialWorkflowOriginV1,
    ) -> std::result::Result<PresentedCoordinatedReturnReadV1, FailedCoordinatedReturnOfferV1> {
        let mut issued = None;
        let result = (|| -> Result<(SignerReturnReadPresentationV1, Instant)> {
            transport.require_peer(&event.peer)?;
            let host = self
                .retained
                .context
                .original_peer
                .as_ref()
                .ok_or(Error::Authentication)?;
            self.retained
                .context
                .source
                .check_coordinated_public_custody_v2(host)?;
            host.same_live_process(event.peer.actual_peer())?;
            if event.request != self.result_request
                || self.committed.authorization_id != self.report.authorization_id
                || self.committed.original_consent_ref != self.report.original_consent_ref
                || self.committed.result_digest != self.report.result_digest
                || self.committed.outbox_digest != self.report.outbox_digest
            {
                return Err(Error::ReviewMismatch);
            }
            let now = Instant::now();
            let wall = wall_now()?;
            let deadline = event
                .original_request_deadline
                .min(event.peer.deadline())
                .min(self.retained.context.source.original_deadline())
                .min(self.retained.original_service_deadline)
                .min(self.retained.original_writer_session_deadline);
            let ms = u64::try_from(
                deadline
                    .checked_duration_since(now)
                    .ok_or(Error::Locked)?
                    .as_millis(),
            )
            .map_err(|_| Error::Locked)?;
            if ms == 0 || ms > 120_000 {
                return Err(Error::Locked);
            }
            let expires_at_ms = wall
                .checked_add(ms)
                .ok_or(Error::Locked)?
                .min(self.retained.receipt.expires_at_ms)
                .min(self.retained.context.source.original_ceiling_ms());
            let request_json =
                serde_json::to_string(&event.request).map_err(|_| Error::InvalidData)?;
            let facts = SignerReturnReadFactsV1 {
                original: self.original.clone(),
                observed: self.observed.clone(),
                signed: self.report.clone(),
                request_digest: SignerReturnReadFactsV1::calculate_request_digest(&request_json)?,
                request_json,
                original_host_process_instance: host.instance().into(),
                display: format!(
                    "Read only the actual persisted successful financial result for authorization {} and original Host {}. Prepare its immutable Preview; do not send signature bytes or sign again.",
                    self.report.authorization_id,
                    host.instance()
                ),
                reviewed_at_ms: wall,
                expires_at_ms,
            };
            let presentation = origin.offer_return_read(facts, deadline)?;
            issued = Some(presentation.clone());
            transport.check_current()?;
            Ok((presentation, deadline))
        })();
        match result {
            Ok((presentation, deadline)) => Ok(PresentedCoordinatedReturnReadV1 {
                retained: self,
                transport,
                event,
                presentation,
                deadline,
            }),
            Err(error) => Err(FailedCoordinatedReturnOfferV1 {
                retained: self,
                transport,
                event,
                presentation: issued,
                error,
            }),
        }
    }
}
impl PresentedCoordinatedReturnReadV1 {
    /// Owned worker only; Origin/control thread continues to pump R/Cancel.
    pub(in crate::native_ui::runtime) fn consume_final(
        self,
        read: SignerReturnReadFinalV1,
    ) -> std::result::Result<UnreportedCoordinatedReturnPreparedV1, FailedCoordinatedReturnV1> {
        let result = (|| -> Result<PreparedCoordinatedFinancialReturnV1> {
            read.check_current()?;
            if read.presentation() != &self.presentation
                || read.original_read_deadline() != self.deadline
                || read.original_source_deadline()
                    != self.retained.retained.context.source.original_deadline()
                || read.original_service_deadline()
                    != self.retained.retained.original_service_deadline
                || read.original_writer_session_deadline()
                    != self.retained.retained.original_writer_session_deadline
            {
                return Err(Error::ReviewMismatch);
            }
            let source = Arc::clone(&self.retained.retained.context.source);
            let host = self
                .retained
                .retained
                .context
                .original_peer
                .as_ref()
                .ok_or(Error::Authentication)?
                .clone();
            PreparedCoordinatedFinancialReturnV1::prepare(
                source,
                self.transport,
                host,
                self.event,
                read,
                self.deadline,
            )
            .map_err(|_| Error::Unavailable)
        })();
        match result {
            Ok(prepared) => Ok(UnreportedCoordinatedReturnPreparedV1 {
                retained: self.retained,
                prepared,
            }),
            Err(error) => Err(FailedCoordinatedReturnV1 {
                retained: self.retained,
                error,
                prepared:None,
                failure:wholepact_financial_coordinator_origin::SignerReturnFailureV1 {
                    presentation_digest:self.presentation.presentation_digest,
                    stage:wholepact_financial_coordinator_origin::SignerReturnFailureStageV1::ReadFailed,
                },
            }),
        }
    }
}

pub(in crate::native_ui::runtime) struct PresentedCoordinatedReturnExactV1 {
    retained: AwaitingCoordinatedReturnReadV1,
    prepared: PreparedCoordinatedFinancialReturnV1,
    presentation: wholepact_financial_coordinator_origin::SignerReturnExactPresentationV1,
    deadline: Instant,
}
pub(in crate::native_ui::runtime) struct CompletedCoordinatedReturnV1 {
    retained: AwaitingCoordinatedReturnReadV1,
    report: wholepact_financial_coordinator_origin::SignerReturnCompletedV1,
}
impl UnreportedCoordinatedReturnPreparedV1 {
    /// Main thread consumes the genuine finished-Read token. Origin emits the
    /// immutable prepared observation and then offers a distinct Exact action.
    pub(in crate::native_ui::runtime) fn offer_return_exact(
        mut self,
        origin: &mut SignerFinancialWorkflowOriginV1,
    ) -> std::result::Result<PresentedCoordinatedReturnExactV1, FailedCoordinatedReturnV1> {
        let result = (|| -> Result<(wholepact_financial_coordinator_origin::SignerReturnExactPresentationV1,Instant)> {
            let completed = self.prepared.take_read_completion().map_err(|_| Error::Locked)?;
            let deadline = self.prepared.setup_deadline();
            let now = Instant::now();
            let wall = wall_now()?;
            let ms = u64::try_from(deadline.checked_duration_since(now).ok_or(Error::Locked)?.as_millis()).map_err(|_| Error::Locked)?;
            if ms==0 || ms>120_000 { return Err(Error::Locked); }
            let facts = wholepact_financial_coordinator_origin::SignerReturnExactFactsV1 {
                read:self.prepared.read_presentation().clone(),
                preview_digest:self.prepared.preview_digest().into(),
                reviewed_digest:self.prepared.reviewed_digest().into(),
                signature_set_digest:self.prepared.signature_set_digest().into(),
                display:self.prepared.display(),reviewed_at_ms:wall,
                expires_at_ms:wall.checked_add(ms).ok_or(Error::Locked)?
                    .min(self.retained.retained.receipt.expires_at_ms)
                    .min(self.retained.retained.context.source.original_ceiling_ms()),
            };
            Ok((origin.offer_return_exact(completed,facts,deadline)?,deadline))
        })();
        match result {
            Ok((presentation, deadline)) => Ok(PresentedCoordinatedReturnExactV1 {
                retained: self.retained,
                prepared: self.prepared,
                presentation,
                deadline,
            }),
            Err(error) => {
                let failure = wholepact_financial_coordinator_origin::SignerReturnFailureV1 {
                    presentation_digest:self.prepared.read_presentation().presentation_digest.clone(),
                    stage:wholepact_financial_coordinator_origin::SignerReturnFailureStageV1::ReadFailed,
                };
                Err(FailedCoordinatedReturnV1 {
                    retained: self.retained,
                    prepared: Some(self.prepared),
                    failure,
                    error,
                })
            }
        }
    }
}
impl PresentedCoordinatedReturnExactV1 {
    /// Owned worker only. Any failure after the attempt is conservatively
    /// uncertain and this stream/approval is never returned for another send.
    pub(in crate::native_ui::runtime) fn consume_final(
        self,
        action: wholepact_financial_coordinator_origin::SignerReturnExactFinalV1,
    ) -> std::result::Result<CompletedCoordinatedReturnV1, FailedCoordinatedReturnV1> {
        let report = wholepact_financial_coordinator_origin::SignerReturnCompletedV1 {
            return_presentation_digest: self.presentation.presentation_digest.clone(),
            preview_digest: self.presentation.facts.preview_digest.clone(),
            result_digest: self.retained.committed.result_digest.clone(),
            outbox_digest: self.retained.committed.outbox_digest.clone(),
        };
        let result = (|| -> Result<()> {
            action.check_current()?;
            if action.presentation() != &self.presentation
                || action.original_return_deadline() != self.deadline
            {
                return Err(Error::ReviewMismatch);
            }
            self.prepared
                .approve(action)
                .and_then(|approved| approved.serve())
                .map_err(|_| Error::Unavailable)
        })();
        match result {
            Ok(())=>Ok(CompletedCoordinatedReturnV1 {retained:self.retained,report}),
            Err(error)=>Err(FailedCoordinatedReturnV1 {
                retained:self.retained,prepared:None,error,
                failure:wholepact_financial_coordinator_origin::SignerReturnFailureV1 {
                    presentation_digest:self.presentation.presentation_digest,
                    stage:wholepact_financial_coordinator_origin::SignerReturnFailureStageV1::ReturnUncertain,
                },
            }),
        }
    }
}
impl CompletedCoordinatedReturnV1 {
    pub(in crate::native_ui::runtime) fn report(
        self,
        origin: &mut SignerFinancialWorkflowOriginV1,
    ) -> std::result::Result<Self, FailedCoordinatedReturnV1> {
        if let Err(error) = origin.report_return_completed(self.report.clone()) {
            return Err(FailedCoordinatedReturnV1 {
                retained:self.retained,prepared:None,error:error.into(),
                failure:wholepact_financial_coordinator_origin::SignerReturnFailureV1 {
                    presentation_digest:self.report.return_presentation_digest,
                    stage:wholepact_financial_coordinator_origin::SignerReturnFailureStageV1::ReturnUncertain,
                },
            });
        }
        Ok(self)
    }
}
impl FailedCoordinatedReturnV1 {
    pub(in crate::native_ui::runtime) fn report_failure(
        &self,
        origin: &mut SignerFinancialWorkflowOriginV1,
    ) -> Result<()> {
        origin
            .report_return_failure(self.failure.clone())
            .map_err(Into::into)
    }
}
