//! One attempted coordinated admission with retained original channel custody.
//! Status is checked business data, never imported admission or native authority.
use super::*;
#[path = "admission_result_v1.rs"]
mod admission_result_v1;
use crate::authority_bridge::durable_delivery_admission_ipc_v2::DurableDeliveryAdmissionStatusV2;
use wholepact_authority::{OwnerControl, OwnerControlRequest};

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoordinatedAdmissionStateV1 {
    AwaitingAudit,
    Unknown,
    Verified,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatedDurableDeliveryAdmissionStatusV1 {
    pub version: u16,
    pub intent_digest: String,
    pub request: OwnerControlRequest,
    pub original_local_intent_digest: String,
    pub state: CoordinatedAdmissionStateV1,
    pub audit: Option<DurableDeliveryAdmissionStatusV2>,
}
impl CoordinatedDurableDeliveryAdmissionStatusV1 {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(BridgeError::Binding);
        }
        crate::authority_bridge::durable_delivery_admission_ipc_v3::validate_admission_status_business_data(
            &self.intent_digest,&self.request,&self.original_local_intent_digest,
            self.state==CoordinatedAdmissionStateV1::Verified,self.audit.as_ref(),
        )?;
        Ok(())
    }
    pub fn verified_audit(&self) -> Result<&DurableDeliveryAdmissionStatusV2> {
        self.validate()?;
        if self.state != CoordinatedAdmissionStateV1::Verified {
            return Err(BridgeError::Uncertain);
        }
        self.audit.as_ref().ok_or(BridgeError::Uncertain)
    }
}
/// Local diagnostic metadata only; never serialized or a permission source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoordinatedAdmissionFailureStageV1 {
    RequestDeadline, RequestChannel, RequestIntent, RequestNonce,
    HistoryIntent, HistoryOwner, HistoryDeadline, HistoryNonce, HistoryOpen,
    HistoryCurrent, HistoryStatus, HistoryPrevious, HistoryResponseMatch,
    ResponseCheckBefore, ResponsePeerBefore, ResponseDeadlineBefore, ResponseFrame,
    ResponseCheckAfter, ResponsePeerAfter, ResponseDeadlineAfter, ResponseDecode,
}
/// Keeps the exact original error; no Display, serialization or copied authority.
pub struct CoordinatedAdmissionFailureV1 {
    stage: CoordinatedAdmissionFailureStageV1,
    frame_cause: Option<wholepact_signer_origin::framing::FrameReadCause>,
    error: BridgeError,
}
impl CoordinatedAdmissionFailureV1 {
    pub fn stage(&self) -> CoordinatedAdmissionFailureStageV1 { self.stage }
    pub fn frame_cause(&self) -> Option<wholepact_signer_origin::framing::FrameReadCause> { self.frame_cause }
    pub fn error(&self) -> &BridgeError { &self.error }
    pub fn into_error(self) -> BridgeError { self.error }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CoordinatedAdmissionAttemptV1 {
    PossiblyStarted,
    Acknowledged,
}
pub struct PendingCoordinatedDurableDeliveryAdmissionV1 {
    client: CoordinatedOriginalClientV1,
    intent: CoordinatedRecipientIntentV1,
    deadline: Instant,
    status: Option<CoordinatedDurableDeliveryAdmissionStatusV1>,
    attempt: CoordinatedAdmissionAttemptV1,
    attempt_error: Option<BridgeError>,
}
impl VerifiedImportedCoordinatedDurableReviewSessionV1 {
    /// The owner exists before an Admit byte can be attempted. Lost ACK keeps
    /// it intact and permits only separately approved history reconciliation.
    pub fn request_admission_retained_v1(
        self,
    ) -> Result<PendingCoordinatedDurableDeliveryAdmissionV1> {
        let mut stage = CoordinatedAdmissionFailureStageV1::RequestDeadline;
        self.request_admission_retained_inner_v1(&mut stage)
    }
    #[cfg(wholepact_financial_rendered_host_semantic_ci)]
    pub fn request_admission_retained_observed_v1(self) -> std::result::Result<PendingCoordinatedDurableDeliveryAdmissionV1, CoordinatedAdmissionFailureV1> {
        let mut stage = CoordinatedAdmissionFailureStageV1::RequestDeadline;
        self.request_admission_retained_inner_v1(&mut stage)
            .map_err(|error| CoordinatedAdmissionFailureV1 { stage, frame_cause: None, error })
    }
    fn request_admission_retained_inner_v1(
        self, stage: &mut CoordinatedAdmissionFailureStageV1,
    ) -> Result<PendingCoordinatedDurableDeliveryAdmissionV1> {
        require_before(self.deadline)?;
        *stage = CoordinatedAdmissionFailureStageV1::RequestChannel;
        self.client.check_current()?;
        *stage = CoordinatedAdmissionFailureStageV1::RequestIntent;
        let intent_digest = self.intent.digest()?;
        *stage = CoordinatedAdmissionFailureStageV1::RequestNonce;
        let nonce = fresh_nonce()?;
        let mut pending = PendingCoordinatedDurableDeliveryAdmissionV1 {
            client: self.client,
            intent: self.intent,
            deadline: self.deadline,
            status: None,
            attempt: CoordinatedAdmissionAttemptV1::PossiblyStarted,
            attempt_error: None,
        };
        let exchange = (|| -> Result<()> {
            let stream = pending.client.open_closed(
                CoordinatedClosedCommandV1::Admit {
                    intent_digest,
                    nonce: nonce.clone(),
                },
                pending.deadline,
            )?;
            if !matches!(pending.client.closed_response(&stream,pending.deadline,&||Ok(()))?,
                CoordinatedClosedResponseV1::Admitting{nonce:actual} if actual==nonce)
            {
                return Err(BridgeError::Uncertain);
            }
            Ok(())
        })();
        match exchange {
            Ok(()) => pending.attempt = CoordinatedAdmissionAttemptV1::Acknowledged,
            Err(e) => pending.attempt_error = Some(e),
        }
        Ok(pending)
    }
}
impl PendingCoordinatedDurableDeliveryAdmissionV1 {
    pub fn intent(&self) -> &CoordinatedRecipientIntentV1 {
        &self.intent
    }
    pub fn status(&self) -> Option<&CoordinatedDurableDeliveryAdmissionStatusV1> {
        self.status.as_ref()
    }
    pub fn attempt_state(&self) -> CoordinatedAdmissionAttemptV1 {
        self.attempt
    }
    pub fn attempt_error(&self) -> Option<&BridgeError> {
        self.attempt_error.as_ref()
    }
    pub fn check_original_channel_current(&self) -> Result<()> {
        self.client.check_current()
    }
    pub fn await_status_v1(&mut self) -> Result<CoordinatedDurableDeliveryAdmissionStatusV1> {
        if let Some(status) = &self.status {
            return Ok(status.clone());
        }
        if self.attempt != CoordinatedAdmissionAttemptV1::Acknowledged {
            return Err(BridgeError::Uncertain);
        }
        let intent_digest = self.intent.digest()?;
        loop {
            require_before(self.deadline)?;
            let nonce = fresh_nonce()?;
            let stream = self.client.open_closed(
                CoordinatedClosedCommandV1::AdmissionStatus {
                    intent_digest: intent_digest.clone(),
                    nonce: nonce.clone(),
                },
                self.deadline,
            )?;
            match self
                .client
                .closed_response(&stream, self.deadline, &|| Ok(()))?
            {
                CoordinatedClosedResponseV1::Admitting { nonce: actual } if actual == nonce => {
                    drop(stream);
                    self.client.check_current()?;
                    std::thread::sleep(Duration::from_millis(100));
                }
                CoordinatedClosedResponseV1::Admission {
                    nonce: actual,
                    admission,
                } if actual == nonce => {
                    self.check_status(&admission)?;
                    self.status = Some(admission.clone());
                    return Ok(admission);
                }
                _ => return Err(BridgeError::Uncertain),
            }
        }
    }
    /// New bounded request/UI wait only. The original S must consume a fresh
    /// exact HistoryRead action before returning complete Witness audit data.
    /// No cached Read or original Admit is replayed by this method.
    pub fn read_original_status_retained_v1(
        &mut self,
    ) -> Result<CoordinatedDurableDeliveryAdmissionStatusV1> {
        let mut stage = CoordinatedAdmissionFailureStageV1::HistoryIntent;
        let mut frame_cause = None;
        self.read_original_status_retained_inner_v1(&mut stage, &mut frame_cause)
    }
    #[cfg(wholepact_financial_rendered_host_semantic_ci)]
    pub fn read_original_status_retained_observed_v1(&mut self) -> std::result::Result<CoordinatedDurableDeliveryAdmissionStatusV1, CoordinatedAdmissionFailureV1> {
        let mut stage = CoordinatedAdmissionFailureStageV1::HistoryIntent;
        let mut frame_cause = None;
        self.read_original_status_retained_inner_v1(&mut stage, &mut frame_cause)
            .map_err(|error| CoordinatedAdmissionFailureV1 { stage, frame_cause, error })
    }
    fn read_original_status_retained_inner_v1(
        &mut self, stage: &mut CoordinatedAdmissionFailureStageV1,
        frame_cause: &mut Option<wholepact_signer_origin::framing::FrameReadCause>,
    ) -> Result<CoordinatedDurableDeliveryAdmissionStatusV1> {
        let intent_digest = self.intent.digest()?;
        *stage = CoordinatedAdmissionFailureStageV1::HistoryOwner;
        let authorization_id = self
            .intent
            .delivery
            .owners
            .iter()
            .find(|owner| {
                owner.account_id == self.intent.account_id
                    && owner.participant_id == self.intent.participant_id
            })
            .ok_or(BridgeError::Binding)?
            .original_authorization_id
            .clone();
        let wait = self
            .client
            .deadline
            .min(Instant::now() + Duration::from_secs(120));
        loop {
            *stage = CoordinatedAdmissionFailureStageV1::HistoryDeadline;
            require_before(wait)?;
            *stage = CoordinatedAdmissionFailureStageV1::HistoryNonce;
            let nonce = fresh_nonce()?;
            *stage = CoordinatedAdmissionFailureStageV1::HistoryOpen;
            let stream = self.client.open_closed(
                CoordinatedClosedCommandV1::History {
                    intent_digest: intent_digest.clone(),
                    authorization_id: authorization_id.clone(),
                    nonce: nonce.clone(),
                },
                wait,
            )?;
            match self.client.closed_response_detailed_v1(&stream, wait, &|| Ok(()), stage, frame_cause)? {
                CoordinatedClosedResponseV1::Preparing { nonce: actual } if actual == nonce => {
                    drop(stream);
                    *stage = CoordinatedAdmissionFailureStageV1::HistoryCurrent;
                    self.client.check_current()?;
                    std::thread::sleep(Duration::from_millis(100));
                }
                CoordinatedClosedResponseV1::Admission {
                    nonce: actual,
                    admission,
                } if actual == nonce => {
                    *stage = CoordinatedAdmissionFailureStageV1::HistoryStatus;
                    self.check_status(&admission)?;
                    *stage = CoordinatedAdmissionFailureStageV1::HistoryPrevious;
                    if let Some(previous) = &self.status {
                        if previous.request != admission.request
                            || previous.original_local_intent_digest
                                != admission.original_local_intent_digest
                        {
                            return Err(BridgeError::Binding);
                        }
                    }
                    self.status = Some(admission.clone());
                    return Ok(admission);
                }
                _ => {
                    *stage = CoordinatedAdmissionFailureStageV1::HistoryResponseMatch;
                    return Err(BridgeError::Permission);
                }
            }
        }
    }
    fn check_status(&self, admission: &CoordinatedDurableDeliveryAdmissionStatusV1) -> Result<()> {
        admission.validate()?;
        let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &admission.request.control
        else {
            return Err(BridgeError::Binding);
        };
        if admission.intent_digest != self.intent.digest()?
            || admission.request.account_id != self.intent.account_id
            || record.scope.delivery != self.intent.delivery
            || record.scope.authorization.fixed != fixed_binding_v3(&self.intent.fixed)?
            || record.scope.accepted_manifest_ref != self.intent.request.accepted_manifest_ref
            || record.scope.original_ceilings.material_scopes != self.intent.material_scopes
        {
            return Err(BridgeError::Binding);
        }
        if let Some(audit) = &admission.audit {
            if audit.original_enrollment_ref != self.intent.original_enrollment_ref
                || audit.original_accepted_manifest_ref != self.intent.original_manifest_ref
            {
                return Err(BridgeError::Binding);
            }
        }
        Ok(())
    }
}
