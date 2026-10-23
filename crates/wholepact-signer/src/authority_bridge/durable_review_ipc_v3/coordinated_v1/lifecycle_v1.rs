//! Same-original-channel lifecycle. Ordinary wire records never issue source
//! Read/Receive authority; every positive transition is reported by original S
//! after its independently consumed nominal C action.
pub use super::super::coordinated_recipient_v1::CoordinatedRecipientIntentV1;
use super::*;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatedDeliveryReceiptV1 {
    pub version: u16,
    pub intent_digest: String,
    pub payload_digest: String,
    pub payload_bytes: u64,
    pub state: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatedVerifiedReceiptV1 {
    pub version: u16,
    pub intent_digest: String,
    pub payload_digest: String,
    pub payload_bytes: u64,
    pub verified_fixed_identity_digest: String,
    pub state: String,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "purpose", rename_all = "snake_case", deny_unknown_fields)]
pub enum CoordinatedClosedCommandV1 {
    Admit {
        intent_digest: String,
        nonce: String,
    },
    AdmissionStatus {
        intent_digest: String,
        nonce: String,
    },
    History {
        intent_digest: String,
        authorization_id: String,
        nonce: String,
    },
    PreparationStatus {
        request_digest: String,
        nonce: String,
    },
    Activate {
        intent_digest: String,
        nonce: String,
    },
    VerifyImport {
        intent_digest: String,
        nonce: String,
    },
}
impl CoordinatedClosedCommandV1 {
    pub(crate) fn validate(&self) -> Result<()> {
        let (digest, nonce) = match self {
            Self::PreparationStatus {
                request_digest,
                nonce,
            } => (request_digest, nonce),
            Self::History {
                intent_digest,
                authorization_id,
                nonce,
            } => {
                crate::review::validate_label(authorization_id)
                    .map_err(|_| BridgeError::Binding)?;
                (intent_digest, nonce)
            }
            Self::Admit {
                intent_digest,
                nonce,
            }
            | Self::AdmissionStatus {
                intent_digest,
                nonce,
            } => (intent_digest, nonce),
            Self::Activate {
                intent_digest,
                nonce,
            }
            | Self::VerifyImport {
                intent_digest,
                nonce,
            } => (intent_digest, nonce),
        };
        super::super::super::durable_construction_v1::hash(digest)?;
        super::super::super::durable_construction_v1::hash(nonce)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum CoordinatedClosedResponseV1 {
    Admitting {
        nonce: String,
    },
    Admission {
        nonce: String,
        admission: CoordinatedDurableDeliveryAdmissionStatusV1,
    },
    Staged {
        request_digest: String,
    },
    Preparing {
        nonce: String,
    },
    Prepared {
        nonce: String,
        intent: CoordinatedRecipientIntentV1,
        remaining_read_ms: u64,
        remaining_material_ms: u64,
    },
    Ready {
        intent_digest: String,
        nonce: String,
        remaining_read_ms: u64,
    },
    Current {
        intent_digest: String,
    },
    Receiving {
        received_bytes: u64,
    },
    BytesReceived {
        receipt: CoordinatedDeliveryReceiptV1,
    },
    Verifying {
        nonce: String,
    },
    Verified {
        nonce: String,
        receipt: CoordinatedVerifiedReceiptV1,
    },
    Denied,
}
pub struct PreparedCoordinatedDurableReviewRecipientV1 {
    client: CoordinatedOriginalClientV1,
    intent: CoordinatedRecipientIntentV1,
    deadline: Instant,
    material_deadline: Instant,
}
pub struct FreshCoordinatedDurableReviewDeliveryV1 {
    client: CoordinatedOriginalClientV1,
    intent: CoordinatedRecipientIntentV1,
    stream: std::sync::Mutex<UnixStream>,
    deadline: Instant,
    material_deadline: Instant,
}
pub struct ImportedCoordinatedDurableReviewSessionV1 {
    client: CoordinatedOriginalClientV1,
    intent: CoordinatedRecipientIntentV1,
    receipt: CoordinatedDeliveryReceiptV1,
    deadline: Instant,
}
pub struct VerifiedImportedCoordinatedDurableReviewSessionV1 {
    pub(crate) client: CoordinatedOriginalClientV1,
    pub(crate) intent: CoordinatedRecipientIntentV1,
    pub(crate) receipt: CoordinatedVerifiedReceiptV1,
    pub(crate) deadline: Instant,
}
/// Local first-readiness failure detail only; never a permission or wire value.
pub struct CoordinatedPreparationFailureV1 {
    readiness: Option<(CoordinatedAdmissionFailureStageV1, Option<wholepact_signer_origin::framing::FrameReadCause>)>,
    error: BridgeError,
}
impl CoordinatedPreparationFailureV1 {
    pub fn readiness_stage(&self) -> Option<CoordinatedAdmissionFailureStageV1> { self.readiness.map(|v| v.0) }
    pub fn frame_cause(&self) -> Option<wholepact_signer_origin::framing::FrameReadCause> { self.readiness.and_then(|v| v.1) }
    pub fn error(&self) -> &BridgeError { &self.error }
    pub fn into_error(self) -> BridgeError { self.error }
}
impl CoordinatedOriginalClientV1 {
    /// Uses the actual H verified payload preparation. Exactly one initial
    /// request is sent, never retried after an uncertain stage acknowledgement.
    pub fn prepare_closed_recipient_v1(
        self,
        request: DurableReviewDeliveryRequestV1,
        fixed: FixedProposalIdentityV1,
        payload_digest: String,
        payload_bytes: u64,
        delivery: DurableDeliveryPlanV2,
        material_scopes: Vec<DurableDeliveryMaterialScopeRefV2>,
    ) -> Result<PreparedCoordinatedDurableReviewRecipientV1> {
        self.prepare_closed_recipient_inner_v1(request, fixed, payload_digest, payload_bytes, delivery, material_scopes, &mut None)
    }
    #[cfg(wholepact_financial_rendered_host_semantic_ci)]
    pub fn prepare_closed_recipient_observed_v1(
        self,
        request: DurableReviewDeliveryRequestV1,
        fixed: FixedProposalIdentityV1,
        payload_digest: String,
        payload_bytes: u64,
        delivery: DurableDeliveryPlanV2,
        material_scopes: Vec<DurableDeliveryMaterialScopeRefV2>,
    ) -> std::result::Result<PreparedCoordinatedDurableReviewRecipientV1, CoordinatedPreparationFailureV1> {
        let mut readiness = None;
        self.prepare_closed_recipient_inner_v1(request, fixed, payload_digest, payload_bytes, delivery, material_scopes, &mut readiness)
            .map_err(|error| CoordinatedPreparationFailureV1 { readiness, error })
    }
    fn prepare_closed_recipient_inner_v1(
        self,
        request: DurableReviewDeliveryRequestV1,
        fixed: FixedProposalIdentityV1,
        payload_digest: String,
        payload_bytes: u64,
        delivery: DurableDeliveryPlanV2,
        material_scopes: Vec<DurableDeliveryMaterialScopeRefV2>,
        readiness_failure: &mut Option<(CoordinatedAdmissionFailureStageV1, Option<wholepact_signer_origin::framing::FrameReadCause>)>,
    ) -> Result<PreparedCoordinatedDurableReviewRecipientV1> {
        let preparation = self.build_preparation(
            request,
            fixed,
            payload_digest,
            payload_bytes,
            delivery,
            material_scopes,
        )?;
        let request_digest = preparation.digest()?;
        let deadline = self.deadline.min(Instant::now() + Duration::from_secs(120));
        let stream = self.open_request(
            &CoordinatedAppRequestV1::Prepare {
                request: Box::new(preparation.clone()),
            },
            deadline,
        )?;
        match self.closed_response(&stream, deadline, &|| Ok(()))? {
            CoordinatedClosedResponseV1::Staged {
                request_digest: actual,
            } if actual == request_digest => {}
            _ => return Err(BridgeError::Permission),
        }
        drop(stream);
        // The first status query is readiness only: native owner configuration,
        // PrepareRead and Receive reviews may take place while it is queued.
        // It is bounded by the original Pair channel, never a renewed lease.
        let mut readiness: Option<(CoordinatedRecipientIntentV1, String)> = None;
        loop {
            let nonce = fresh_nonce()?;
            if readiness
                .as_ref()
                .is_some_and(|(_, first_nonce)| first_nonce == &nonce)
            {
                return Err(BridgeError::Binding);
            }
            let started = Instant::now();
            let deadline = preparation_status_deadline(started, self.deadline, readiness.is_some());
            let stream = self.open_closed(
                CoordinatedClosedCommandV1::PreparationStatus {
                    request_digest: request_digest.clone(),
                    nonce: nonce.clone(),
                },
                deadline,
            )?;
            // The first response is inert readiness only. Its original channel
            // may exceed a single transfer's 120-second budget; wait without
            // consuming bytes, then enter the same authenticated frame parser.
            // Initial Prepare and the second, permission-bearing query keep
            // their unchanged ordinary short-response path.
            let response = if readiness.is_none() {
                let mut stage = CoordinatedAdmissionFailureStageV1::ResponseCheckBefore;
                let mut frame_cause = None;
                let result = self.preparation_readiness_response(&stream, deadline, &|| Ok(()), &mut stage, &mut frame_cause);
                if result.is_err() { *readiness_failure = Some((stage, frame_cause)); }
                result
            } else {
                self.closed_response(&stream, deadline, &|| Ok(()))
            }?;
            match response {
                CoordinatedClosedResponseV1::Prepared {
                    nonce: actual,
                    intent,
                    remaining_read_ms,
                    remaining_material_ms,
                } if actual == nonce => {
                    intent.validate()?;
                    if intent.preparation() != preparation
                        || intent.account_id != self.scope.account_id
                        || intent.participant_id != self.scope.participant_id
                        || intent.agreement_id != self.scope.agreement_id
                        || intent.manifest_digest != self.scope.manifest_digest
                        || intent.source_identity_digest != self.endpoint.source_identity_digest
                        || intent.authorized_host_process_instance
                            != self.original_host_process_instance
                        || intent.signer_process_instance != self.endpoint.signer_process_instance
                        || intent.coordinated_provider_reference
                            != self.endpoint.coordinated_provider_reference
                    {
                        return Err(BridgeError::Binding);
                    }
                    if remaining_read_ms == 0
                        || remaining_read_ms > 120_000
                        || remaining_material_ms == 0
                        || remaining_material_ms > 900_000
                    {
                        return Err(BridgeError::Permission);
                    }
                    if let Some((expected, _)) = &readiness {
                        if expected != &intent {
                            return Err(BridgeError::Binding);
                        }
                    } else {
                        // Fully validated binding only; no read/material deadline,
                        // prepared client or other permission is created here.
                        readiness = Some((intent, nonce));
                        drop(stream);
                        continue;
                    }
                    // Only the second, fresh nonce-bound query yields remaining
                    // genuine Receive/material bounds. Its pre-I/O anchor keeps
                    // transit conservative without charging the earlier reviews
                    // against a permission which did not yet exist then.
                    let material_deadline =
                        (started + Duration::from_millis(remaining_material_ms)).min(self.deadline);
                    require_before(material_deadline)?;
                    let deadline =
                        narrowed_deadline(started, remaining_read_ms, material_deadline)?;
                    return Ok(PreparedCoordinatedDurableReviewRecipientV1 {
                        client: self,
                        intent,
                        deadline,
                        material_deadline,
                    });
                }
                CoordinatedClosedResponseV1::Preparing { nonce: actual }
                    if actual == nonce && readiness.is_none() =>
                {
                    drop(stream);
                    require_before(deadline)?;
                    self.check_current()?;
                    std::thread::sleep(Duration::from_millis(100));
                }
                _ => return Err(BridgeError::Permission),
            }
        }
    }
    // Private to the first PreparationStatus readiness fence. This does not
    // create a client permission or renew a clock: the original channel caps
    // setup, and the existing setup reader caps transfer at first-readable+120.
    fn preparation_readiness_response(
        &self,
        stream: &UnixStream,
        deadline: Instant,
        check: &dyn Fn() -> Result<()>,
        stage: &mut CoordinatedAdmissionFailureStageV1,
        frame_cause: &mut Option<wholepact_signer_origin::framing::FrameReadCause>,
    ) -> Result<CoordinatedClosedResponseV1> {
        *frame_cause = None;
        *stage = CoordinatedAdmissionFailureStageV1::ResponseCheckBefore;
        check()?;
        *stage = CoordinatedAdmissionFailureStageV1::ResponsePeerBefore;
        self.check_stream(stream)?;
        *stage = CoordinatedAdmissionFailureStageV1::ResponseDeadlineBefore;
        require_before(deadline)?;
        *stage = CoordinatedAdmissionFailureStageV1::ResponseFrame;
        let bytes = wholepact_signer_origin::framing::read_setup_frame_capped_checked_observed_until(
            stream,
            &self.peer,
            MAX_METADATA_V3,
            deadline.min(self.deadline),
            || {
                check().map_err(|_| wholepact_signer_origin::Error::Permission)?;
                self.check_stream(stream)
                    .map_err(|_| wholepact_signer_origin::Error::Permission)
            },
        )
        .map_err(|failure| { *frame_cause = Some(failure.cause); BridgeError::Ipc })?;
        *stage = CoordinatedAdmissionFailureStageV1::ResponseCheckAfter;
        check()?;
        *stage = CoordinatedAdmissionFailureStageV1::ResponsePeerAfter;
        self.check_stream(stream)?;
        *stage = CoordinatedAdmissionFailureStageV1::ResponseDeadlineAfter;
        require_before(deadline)?;
        *stage = CoordinatedAdmissionFailureStageV1::ResponseDecode;
        wholepact_core::strict_json::parse_typed_json_with_byte_limit(&bytes, MAX_METADATA_V3)
            .map_err(|_| BridgeError::Binding)
    }
    pub(super) fn open_closed(
        &self,
        request: CoordinatedClosedCommandV1,
        deadline: Instant,
    ) -> Result<UnixStream> {
        self.open_request(&CoordinatedAppRequestV1::Closed { request }, deadline)
    }
    pub(super) fn closed_response(
        &self,
        stream: &UnixStream,
        deadline: Instant,
        check: &dyn Fn() -> Result<()>,
    ) -> Result<CoordinatedClosedResponseV1> {
        let mut stage = CoordinatedAdmissionFailureStageV1::ResponseCheckBefore;
        let mut frame_cause = None;
        self.closed_response_detailed_v1(stream, deadline, check, &mut stage, &mut frame_cause)
    }
    pub(super) fn closed_response_detailed_v1(
        &self, stream: &UnixStream, deadline: Instant, check: &dyn Fn() -> Result<()>,
        stage: &mut CoordinatedAdmissionFailureStageV1,
        frame_cause: &mut Option<wholepact_signer_origin::framing::FrameReadCause>,
    ) -> Result<CoordinatedClosedResponseV1> {
        *frame_cause = None;
        *stage = CoordinatedAdmissionFailureStageV1::ResponseCheckBefore;
        check()?;
        *stage = CoordinatedAdmissionFailureStageV1::ResponsePeerBefore;
        self.check_stream(stream)?;
        *stage = CoordinatedAdmissionFailureStageV1::ResponseDeadlineBefore;
        require_before(deadline)?;
        *stage = CoordinatedAdmissionFailureStageV1::ResponseFrame;
        let bytes = wholepact_signer_origin::framing::read_frame_capped_checked_observed_until(
            stream,
            &self.peer,
            MAX_METADATA_V3,
            deadline.min(self.deadline),
            || {
                check().map_err(|_| wholepact_signer_origin::Error::Permission)?;
                self.check_stream(stream)
                    .map_err(|_| wholepact_signer_origin::Error::Permission)
            },
        )
        .map_err(|failure| {
            *frame_cause = Some(failure.cause);
            BridgeError::Ipc
        })?;
        *stage = CoordinatedAdmissionFailureStageV1::ResponseCheckAfter;
        check()?;
        *stage = CoordinatedAdmissionFailureStageV1::ResponsePeerAfter;
        self.check_stream(stream)?;
        *stage = CoordinatedAdmissionFailureStageV1::ResponseDeadlineAfter;
        require_before(deadline)?;
        *stage = CoordinatedAdmissionFailureStageV1::ResponseDecode;
        wholepact_core::strict_json::parse_typed_json_with_byte_limit(&bytes, MAX_METADATA_V3)
            .map_err(|_| BridgeError::Binding)
    }
}
// Readiness carries no permission. The second request retains the original
// short transport bound, and neither phase can extend the original channel.
fn preparation_status_deadline(started: Instant, channel: Instant, ready: bool) -> Instant {
    if ready {
        channel.min(started + Duration::from_secs(120))
    } else {
        channel
    }
}
#[cfg(test)]
mod preparation_status_deadline_tests {
    use super::*;
    #[test]
    fn readiness_wait_uses_original_channel_and_final_query_remains_short() {
        let start = Instant::now();
        let channel = start + Duration::from_secs(900);
        assert_eq!(preparation_status_deadline(start, channel, false), channel);
        let later = start + Duration::from_secs(240);
        assert_eq!(preparation_status_deadline(later, channel, false), channel);
        assert_eq!(preparation_status_deadline(later, channel, true), later + Duration::from_secs(120));
        assert_eq!(preparation_status_deadline(channel, channel, true), channel);
        let short = later + Duration::from_secs(7);
        assert_eq!(preparation_status_deadline(later, short, true), short);
    }
}
impl PreparedCoordinatedDurableReviewRecipientV1 {
    pub fn intent(&self) -> &CoordinatedRecipientIntentV1 {
        &self.intent
    }
    pub fn activate(
        self,
        host_action_deadline: Instant,
    ) -> Result<FreshCoordinatedDurableReviewDeliveryV1> {
        let started = Instant::now();
        let deadline = self
            .deadline
            .min(host_action_deadline)
            .min(self.client.deadline);
        require_before(deadline)?;
        let nonce = fresh_nonce()?;
        let digest = self.intent.digest()?;
        let stream = self.client.open_closed(
            CoordinatedClosedCommandV1::Activate {
                intent_digest: digest.clone(),
                nonce: nonce.clone(),
            },
            deadline,
        )?;
        let CoordinatedClosedResponseV1::Ready {
            intent_digest,
            nonce: actual,
            remaining_read_ms,
        } = self.client.closed_response(&stream, deadline, &|| Ok(()))?
        else {
            return Err(BridgeError::Permission);
        };
        if intent_digest != digest || nonce != actual {
            return Err(BridgeError::Binding);
        }
        let read_deadline = narrowed_deadline(started, remaining_read_ms, self.deadline)?;
        Ok(FreshCoordinatedDurableReviewDeliveryV1 {
            client: self.client,
            intent: self.intent,
            stream: std::sync::Mutex::new(stream),
            deadline: deadline.min(read_deadline),
            material_deadline: self.material_deadline,
        })
    }
}
impl FreshCoordinatedDurableReviewDeliveryV1 {
    pub fn intent(&self) -> &CoordinatedRecipientIntentV1 {
        &self.intent
    }
    pub fn original_delivery_deadline_v3(&self) -> Instant {
        self.deadline
    }
    pub fn check_current(&self) -> Result<()> {
        require_before(self.deadline)?;
        let mut stream = self.stream.lock().map_err(|_| BridgeError::Ipc)?;
        let observer = stream.try_clone().map_err(|_| BridgeError::Ipc)?;
        v1::bounded_write(
            &mut stream,
            &v1::DeliveryCommandV1::CheckCurrent,
            self.deadline,
            || self.client.check_stream(&observer),
        )?;
        match self
            .client
            .closed_response(&stream, self.deadline, &|| Ok(()))?
        {
            CoordinatedClosedResponseV1::Current { intent_digest }
                if intent_digest == self.intent.digest()? =>
            {
                Ok(())
            }
            _ => Err(BridgeError::Permission),
        }
    }
    pub fn deliver_prepared_restricted_v3(
        self,
        payload: PreparedDurableReviewPayloadV2,
        check: &dyn Fn() -> Result<()>,
        final_restriction: &dyn Fn() -> Result<()>,
    ) -> Result<ImportedCoordinatedDurableReviewSessionV1> {
        check()?;
        self.check_current()?;
        if payload.payload_digest() != self.intent.payload_digest
            || payload.payload_bytes() != self.intent.payload_bytes
        {
            return Err(BridgeError::Binding);
        }
        let (raw, digest) = payload.into_exact_parts_v3();
        let mut stream = self.stream.into_inner().map_err(|_| BridgeError::Ipc)?;
        let observer = stream.try_clone().map_err(|_| BridgeError::Ipc)?;
        let current = || {
            check()?;
            require_before(self.deadline)?;
            self.client.check_stream(&observer)
        };
        let expect = |expected| -> Result<()> {
            match self
                .client
                .closed_response(&observer, self.deadline, &current)?
            {
                CoordinatedClosedResponseV1::Receiving { received_bytes }
                    if received_bytes == expected =>
                {
                    Ok(())
                }
                _ => Err(BridgeError::Permission),
            }
        };
        v1::bounded_write_restricted(
            &mut stream,
            &v1::DeliveryCommandV1::Begin {
                payload_digest: digest.clone(),
                payload_bytes: raw.len() as u64,
            },
            self.deadline,
            current,
            final_restriction,
        )?;
        expect(0)?;
        for (index, bytes) in raw.chunks(v1::CHUNK_BYTES).enumerate() {
            let offset = index * v1::CHUNK_BYTES;
            v1::bounded_write_restricted(
                &mut stream,
                &v1::DeliveryCommandV1::Chunk {
                    offset: offset as u64,
                    data_hex: hex::encode(bytes),
                },
                self.deadline,
                current,
                final_restriction,
            )?;
            expect((offset + bytes.len()) as u64)?;
        }
        v1::bounded_write_restricted(
            &mut stream,
            &v1::DeliveryCommandV1::Finish,
            self.deadline,
            current,
            final_restriction,
        )?;
        let CoordinatedClosedResponseV1::BytesReceived { receipt } =
            self.client
                .closed_response(&stream, self.deadline, &current)?
        else {
            return Err(BridgeError::Permission);
        };
        current()?;
        if receipt.version != 1
            || receipt.intent_digest != self.intent.digest()?
            || receipt.payload_digest != digest
            || receipt.payload_bytes != raw.len() as u64
            || receipt.state != "bytes_received_unverified"
        {
            return Err(BridgeError::Binding);
        }
        drop(raw);
        drop(stream);
        drop(observer);
        Ok(ImportedCoordinatedDurableReviewSessionV1 {
            client: self.client,
            intent: self.intent,
            receipt,
            // Completed bytes retain original material custody, not live
            // Receive permission. Verify/Admit require separate actual S actions.
            deadline: self.material_deadline,
        })
    }
}
impl ImportedCoordinatedDurableReviewSessionV1 {
    pub fn intent(&self) -> &CoordinatedRecipientIntentV1 {
        &self.intent
    }
    pub fn receipt(&self) -> &CoordinatedDeliveryReceiptV1 {
        &self.receipt
    }
    pub fn await_verified_v3(self) -> Result<VerifiedImportedCoordinatedDurableReviewSessionV1> {
        loop {
            require_before(self.deadline)?;
            let nonce = fresh_nonce()?;
            let stream = self.client.open_closed(
                CoordinatedClosedCommandV1::VerifyImport {
                    intent_digest: self.intent.digest()?,
                    nonce: nonce.clone(),
                },
                self.deadline,
            )?;
            match self
                .client
                .closed_response(&stream, self.deadline, &|| Ok(()))?
            {
                CoordinatedClosedResponseV1::Verified {
                    nonce: actual,
                    receipt,
                } if nonce == actual => {
                    if receipt.version != 1
                        || receipt.intent_digest != self.intent.digest()?
                        || receipt.payload_digest != self.intent.payload_digest
                        || receipt.payload_bytes != self.intent.payload_bytes
                        || receipt.verified_fixed_identity_digest
                            != verified_fixed_identity_digest_v3(&self.intent.fixed)?
                        || receipt.state != "verified_import_for_review"
                    {
                        return Err(BridgeError::Binding);
                    }
                    drop(stream);
                    return Ok(VerifiedImportedCoordinatedDurableReviewSessionV1 {
                        client: self.client,
                        intent: self.intent,
                        receipt,
                        deadline: self.deadline,
                    });
                }
                CoordinatedClosedResponseV1::Verifying { nonce: actual } if nonce == actual => {
                    drop(stream);
                    self.client.check_current()?;
                    std::thread::sleep(Duration::from_millis(100));
                }
                _ => return Err(BridgeError::Permission),
            }
        }
    }
}
impl VerifiedImportedCoordinatedDurableReviewSessionV1 {
    pub fn intent(&self) -> &CoordinatedRecipientIntentV1 {
        &self.intent
    }
    pub fn receipt(&self) -> &CoordinatedVerifiedReceiptV1 {
        &self.receipt
    }
}
