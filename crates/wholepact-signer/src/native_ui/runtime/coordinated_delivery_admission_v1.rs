//! Actual post-Receive custody. Fresh owner history does not constitute Admit.
use super::*;
use crate::native_ui::witness_workspace::durable_delivery_v3::coordinated_v1::admit_read::ReadCoordinatedDeliveryWitnessV1;
use wholepact_financial_coordinator_origin::SignerV3AdmitReadFinalV1;

/// No public constructor, cloning, deserialization or completed-state flag.
/// The nominal Read is still unspent while exact local preparation is pending.
pub(in crate::native_ui::runtime) struct CoordinatedReadAdmissionV1 {
    source: CoordinatedPreparedDeliverySourceV1,
    witness: ReadCoordinatedDeliveryWitnessV1,
    intent: CoordinatedRecipientIntentV1,
    fixed: VerifiedDurableEconomicsV1,
    receipt: CoordinatedVerifiedReceiptV1,
    received: SignerV3ReceivedV1,
}

impl CoordinatedVerifiedImportV1 {
    pub(in crate::native_ui::runtime) fn read_for_admission(
        self,
        action: SignerV3AdmitReadFinalV1,
    ) -> Result<CoordinatedReadAdmissionV1> {
        self.check_current()?;
        action.check_current()?;
        // A DTO-equivalent report alone cannot enter: this method consumes the
        // sole actual proof-verified source/client/material owner as well.
        if action.facts().received != self.report
            || self.intent.digest().map_err(|_| Error::ReviewMismatch)?
                != self.report.recipient_intent_digest
        {
            return Err(Error::ReviewMismatch);
        }
        self.source.check_admit_read_source(&action)?;
        let Self {
            source,
            witness,
            intent,
            fixed,
            receipt,
            report,
        } = self;
        // The callback below is restriction-only; all actual journal reads are
        // separately guarded by the retained nominal Final before and after.
        let witness = witness.read_for_admission(action, || source.check_current())?;
        source.check_admit_read_source(witness.action())?;
        Ok(CoordinatedReadAdmissionV1 {
            source,
            witness,
            intent,
            fixed,
            receipt,
            received: report,
        })
    }
}

pub(in crate::native_ui::runtime) struct PreparedCoordinatedAdmissionV1 {
    source: CoordinatedPreparedDeliverySourceV1,
    witness: CoordinatedDeliveryWitnessV1,
    intent: CoordinatedRecipientIntentV1,
    fixed: VerifiedDurableEconomicsV1,
    receipt: CoordinatedVerifiedReceiptV1,
    received: SignerV3ReceivedV1,
    history: wholepact_authority::ReconciledAuthorityHistory,
    prepared: crate::consent_journal::durable_delivery_admission_intent_v3::coordinated_v1::PreparedCoordinatedAdmissionIntentV1,
    retained_report: wholepact_financial_coordinator_origin::SignerV3AdmitReadRetainedV1,
    read_deadline: Instant,
    read_expires_at_ms: u64,
}
impl CoordinatedReadAdmissionV1 {
    pub(in crate::native_ui::runtime) fn prepare(self) -> Result<PreparedCoordinatedAdmissionV1> {
        let prepared = self.source.prepare_admission_intent(
            self.witness.action(),
            &self.fixed,
            &self.intent,
            self.witness.history(),
        )?;
        let request = prepared.request();
        let retained_report = wholepact_financial_coordinator_origin::SignerV3AdmitReadRetainedV1 {
            admit_read_presentation_digest: self
                .witness
                .action()
                .presentation()
                .presentation_digest
                .clone(),
            source_identity_digest: self.received.source_identity_digest.clone(),
            owner_service_digest: self.received.owner_service_digest.clone(),
            recipient_intent_digest: self.received.recipient_intent_digest.clone(),
            authenticated_history_digest: self
                .witness
                .history()
                .history_digest()
                .map_err(|_| Error::ReviewMismatch)?,
            admission_request_digest: prepared.request_digest()?,
            admission_review_digest: prepared.review_digest().into(),
            operation_id: request.operation_id.clone(),
            expected_head_sequence: request.expected_head.sequence,
            expected_head_digest: request.expected_head.digest.clone(),
            display: prepared.display()?,
        };
        retained_report.validate()?;
        self.source.check_admit_read_source(self.witness.action())?;
        let read_deadline = self.witness.action().original_read_deadline();
        let read_expires_at_ms = self.witness.action().facts().expires_at_ms;
        let (witness, history) = self.witness.finish()?;
        Ok(PreparedCoordinatedAdmissionV1 {
            source: self.source,
            witness,
            intent: self.intent,
            fixed: self.fixed,
            receipt: self.receipt,
            received: self.received,
            history,
            prepared,
            retained_report,
            read_deadline,
            read_expires_at_ms,
        })
    }
}

impl CoordinatedVerifiedImportV1 {
    pub(in crate::native_ui::runtime) fn admit_read_review(
        &self,
    ) -> Result<(
        wholepact_financial_coordinator_origin::SignerV3AdmitReadFactsV1,
        Instant,
    )> {
        self.check_current()?;
        let read = self.source.cached_prepare_read()?;
        let now = Instant::now();
        let wall = unix_ms()?;
        let deadline = (now + Duration::from_secs(120))
            .min(self.source.original_material_deadline())
            .min(self.witness.original_service_deadline());
        let facts = wholepact_financial_coordinator_origin::SignerV3AdmitReadFactsV1 {
            received: self.report.clone(), owner_selection_digest: read.facts.owner_selection_digest.clone(),
            owner_certificate_digest: read.facts.owner_certificate_digest.clone(),
            disclosure_digest: read.facts.disclosure_digest.clone(),
            display: format!("Read the complete authenticated original owner history and prepare exactly one immutable admission candidate. No INSERT, READY, admission or financial authority.\nRecipient: {}\nOriginal owner: {}", self.report.recipient_intent_digest, self.report.owner_service_digest),
            reviewed_at_ms: wall, expires_at_ms: wall_at(now,wall,deadline,read.facts.material_expires_at_ms)?,
            source_expires_at_ms: read.facts.source_expires_at_ms,
            service_expires_at_ms: read.facts.service_expires_at_ms,
            material_expires_at_ms: read.facts.material_expires_at_ms,
        };
        facts.validate()?;
        Ok((facts, deadline))
    }
}
impl PreparedCoordinatedAdmissionV1 {
    pub(in crate::native_ui::runtime) fn read_report(
        &self,
    ) -> wholepact_financial_coordinator_origin::SignerV3AdmitReadRetainedV1 {
        self.retained_report.clone()
    }
    pub(in crate::native_ui::runtime) fn check_current(&self) -> Result<()> {
        self.source.check_current()?;
        self.witness.check_custody()?;
        if Instant::now() >= self.read_deadline {
            return Err(Error::Locked);
        }
        Ok(())
    }
    pub(in crate::native_ui::runtime) fn review(
        &self,
    ) -> Result<(
        wholepact_financial_coordinator_origin::SignerV3AdmitFactsV1,
        Instant,
    )> {
        self.check_current()?;
        let read = self.source.cached_prepare_read()?;
        let now = Instant::now();
        let wall = unix_ms()?;
        let deadline = (now + Duration::from_secs(120)).min(self.read_deadline);
        let facts = wholepact_financial_coordinator_origin::SignerV3AdmitFactsV1 {
            read: self.retained_report.clone(),
            request_json: serde_json::to_string(self.prepared.request())
                .map_err(|_| Error::InvalidData)?,
            display: self.prepared.display()?,
            reviewed_at_ms: wall,
            expires_at_ms: wall_at(now, wall, deadline, self.read_expires_at_ms)?,
            source_expires_at_ms: read.facts.source_expires_at_ms,
            service_expires_at_ms: read.facts.service_expires_at_ms,
            material_expires_at_ms: read.facts.material_expires_at_ms,
        };
        facts.validate()?;
        Ok((facts, deadline))
    }
}

pub(in crate::native_ui::runtime) struct CoordinatedAdmissionWorkerV1 {
    worker: Option<std::thread::JoinHandle<Result<CoordinatedAdmissionAttemptV1>>>,
    ready: std::sync::mpsc::Receiver<(
        wholepact_financial_coordinator_origin::SignerV3AdmitArmV1,
        wholepact_financial_coordinator_origin::SignerV3AdmitReadyV1,
    )>,
    final_sender: Option<
        std::sync::mpsc::SyncSender<wholepact_financial_coordinator_origin::SignerV3AdmitFinalV1>,
    >,
}
pub(in crate::native_ui::runtime) struct CoordinatedAdmissionAttemptV1 {
    source: CoordinatedPreparedDeliverySourceV1,
    witness: CoordinatedDeliveryWitnessV1,
    intent: CoordinatedRecipientIntentV1,
    fixed: VerifiedDurableEconomicsV1,
    receipt: CoordinatedVerifiedReceiptV1,
    received: SignerV3ReceivedV1,
    request: wholepact_authority::OwnerControlRequest,
    retained: Option<crate::consent_journal::durable_delivery_admission_intent_v3::coordinated_v1::RetainedCoordinatedAdmissionIntentV1>,
    controlled: Option<wholepact_authority::AccountSnapshot>,
    admitted: Option<wholepact_financial_coordinator_origin::SignerV3AdmittedV1>,
    failure: Option<Error>,
}
impl PreparedCoordinatedAdmissionV1 {
    pub(in crate::native_ui::runtime) fn start_admission(
        self,
        arm: wholepact_financial_coordinator_origin::SignerV3AdmitArmV1,
    ) -> Result<CoordinatedAdmissionWorkerV1> {
        self.check_current()?;
        arm.check_current()?;
        if arm.facts().read != self.retained_report {
            return Err(Error::ReviewMismatch);
        }
        let (ready_sender, ready) = std::sync::mpsc::sync_channel(1);
        let (final_sender, final_receiver) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("coordinated-original-admission".into())
            .spawn(move || self.run_admission(arm, ready_sender, final_receiver))?;
        Ok(CoordinatedAdmissionWorkerV1 {
            worker: Some(worker),
            ready,
            final_sender: Some(final_sender),
        })
    }
    fn run_admission(
        mut self,
        arm: wholepact_financial_coordinator_origin::SignerV3AdmitArmV1,
        ready_sender: std::sync::mpsc::SyncSender<(
            wholepact_financial_coordinator_origin::SignerV3AdmitArmV1,
            wholepact_financial_coordinator_origin::SignerV3AdmitReadyV1,
        )>,
        final_receiver: std::sync::mpsc::Receiver<
            wholepact_financial_coordinator_origin::SignerV3AdmitFinalV1,
        >,
    ) -> Result<CoordinatedAdmissionAttemptV1> {
        let request = self.prepared.request().clone();
        let deadline = arm.original_admit_deadline();
        let channel = self
            .witness
            .prepare_admission(&arm, &request, || self.source.check_current())?;
        let ready = wholepact_financial_coordinator_origin::SignerV3AdmitReadyV1 {
            admit_presentation_digest: arm.presentation().presentation_digest.clone(),
            admission_request_digest: self.prepared.request_digest()?,
            admission_review_digest: self.prepared.review_digest().into(),
            owner_service_digest: self.received.owner_service_digest.clone(),
            authenticated_ready_digest: channel
                .authenticated_ready_digest_v1()
                .map_err(|_| Error::Uncertain)?,
            expected_head_sequence: request.expected_head.sequence,
            expected_head_digest: request.expected_head.digest.clone(),
            operation_id: request.operation_id.clone(),
        };
        ready.validate()?;
        ready_sender
            .send((arm, ready.clone()))
            .map_err(|_| Error::Unavailable)?;
        let action = loop {
            self.source.check_current()?;
            self.witness.check_custody()?;
            channel.check_current().map_err(|_| Error::Uncertain)?;
            if Instant::now() >= deadline {
                return Err(Error::Locked);
            }
            match final_receiver.recv_timeout(Duration::from_millis(20)) {
                Ok(action) => break action,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => (),
                Err(_) => return Err(Error::Unavailable),
            }
        };
        action.check_current()?;
        if action.ready() != &ready || action.facts().read != self.retained_report {
            return Err(Error::ReviewMismatch);
        }
        // From this point retain all original custody even on R or a publication
        // failure. Nothing in an attempted outcome permits a second send.
        let retention = self
            .source
            .retain_admission_intent(self.prepared, &action, &channel)
            .and_then(|value| value.retained());
        let mut retained = None;
        let mut controlled = None;
        let mut admitted = None;
        let mut failure = None;
        match retention {
            Err(error) => {
                failure = Some(error);
                drop(channel);
            }
            Ok((record, source_uncertain)) => match record.history_digest() {
                Err(error) => {
                    retained = Some(record);
                    failure = Some(Error::from(error));
                    drop(channel);
                }
                Ok(local_record_digest) => {
                    let send = if source_uncertain {
                        drop(channel);
                        Err(Error::Uncertain)
                    } else {
                        channel
                            .send_retained_exact(&request, action.original_admit_deadline(), || {
                                self.source
                                    .check_current()
                                    .and_then(|_| self.witness.check_custody())
                                    .and_then(|_| action.check_current().map_err(Error::from))
                                    .map_err(|_| wholepact_authority::AuthorityError::Permission)
                            })
                            .map_err(|_| Error::Uncertain)
                    };
                    let observation = match send {
                        Ok(snapshot) => {
                            let result = wholepact_financial_coordinator_origin::SignerV3AdmissionObservationV1::Controlled {
                            head_sequence:snapshot.head.sequence,head_digest:snapshot.head.digest.clone(),
                        };
                            controlled = Some(snapshot);
                            result
                        }
                        Err(error) => {
                            failure = Some(error);
                            wholepact_financial_coordinator_origin::SignerV3AdmissionObservationV1::Unknown
                        }
                    };
                    let report = wholepact_financial_coordinator_origin::SignerV3AdmittedV1 {
                        admit_presentation_digest: action
                            .presentation()
                            .presentation_digest
                            .clone(),
                        admission_request_digest: self
                            .retained_report
                            .admission_request_digest
                            .clone(),
                        admission_review_digest: self
                            .retained_report
                            .admission_review_digest
                            .clone(),
                        owner_service_digest: self.received.owner_service_digest.clone(),
                        local_record_digest,
                        observation,
                    };
                    retained = Some(record);
                    match action.finish_admission() {
                        Ok(()) => admitted = Some(report),
                        Err(error) => failure = Some(Error::from(error)),
                    }
                }
            },
        }
        Ok(CoordinatedAdmissionAttemptV1 {
            source: self.source,
            witness: self.witness,
            intent: self.intent,
            fixed: self.fixed,
            receipt: self.receipt,
            received: self.received,
            request,
            retained,
            controlled,
            admitted,
            failure,
        })
    }
}
impl CoordinatedAdmissionWorkerV1 {
    pub(in crate::native_ui::runtime) fn take_ready(
        &mut self,
    ) -> Result<
        Option<(
            wholepact_financial_coordinator_origin::SignerV3AdmitArmV1,
            wholepact_financial_coordinator_origin::SignerV3AdmitReadyV1,
        )>,
    > {
        match self.ready.try_recv() {
            Ok(v) => Ok(Some(v)),
            Err(std::sync::mpsc::TryRecvError::Empty) => Ok(None),
            Err(std::sync::mpsc::TryRecvError::Disconnected) if self.finished() => Ok(None),
            Err(_) => Err(Error::Unavailable),
        }
    }
    pub(in crate::native_ui::runtime) fn provide_final(
        &mut self,
        action: wholepact_financial_coordinator_origin::SignerV3AdmitFinalV1,
    ) -> Result<()> {
        self.final_sender
            .take()
            .ok_or(Error::ReviewMismatch)?
            .try_send(action)
            .map_err(|_| Error::Unavailable)
    }
    pub(in crate::native_ui::runtime) fn finished(&self) -> bool {
        self.worker.as_ref().is_some_and(|v| v.is_finished())
    }
    pub(in crate::native_ui::runtime) fn join(mut self) -> Result<CoordinatedAdmissionAttemptV1> {
        self.final_sender.take();
        self.worker
            .take()
            .ok_or(Error::Unavailable)?
            .join()
            .map_err(|_| Error::Uncertain)?
    }
}
impl Drop for CoordinatedAdmissionWorkerV1 {
    fn drop(&mut self) {
        self.final_sender.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
impl CoordinatedAdmissionAttemptV1 {
    pub(in crate::native_ui::runtime) fn admitted_report(
        &self,
    ) -> Option<wholepact_financial_coordinator_origin::SignerV3AdmittedV1> {
        self.admitted.clone()
    }
}

pub(in crate::native_ui::runtime) struct AuditedCoordinatedV3V1 {
    custody: CoordinatedAdmissionAttemptV1,
    selection: crate::account::birth::enrollment::roster_v2::durable_entry_v1::OriginalFinancialReentrySelectionV1,
    history: wholepact_authority::ReconciledAuthorityHistory,
    terms: wholepact_authority::durable_financial_continuation_v1::FinancialContinuationTermsV1,
    report: wholepact_financial_coordinator_origin::SignerV3AuditedV1,
    lifetime: wholepact_financial_coordinator_origin::SignerV3CompletedLifetimeV1,
}
/// Only actual authenticated Audit plus the retained original local admission,
/// proof/receipt/source/client and exact financial selection can construct this.
/// It has no Deserialize/Clone/public constructor or metadata completion flag.
pub(in crate::native_ui::runtime) struct CompletedCoordinatedV3V1 {
    audited: AuditedCoordinatedV3V1,
}
impl CoordinatedAdmissionAttemptV1 {
    pub(in crate::native_ui::runtime) fn audit_review(
        &self,
    ) -> Result<(
        wholepact_financial_coordinator_origin::SignerV3AuditFactsV1,
        Instant,
    )> {
        self.source.check_current()?;
        self.witness.check_custody()?;
        let admitted = self.admitted.as_ref().ok_or(Error::Unavailable)?;
        self.retained.as_ref().ok_or(Error::RecoveryRequired)?;
        let read = self.source.cached_prepare_read()?;
        let now = Instant::now();
        let wall = unix_ms()?;
        let deadline = (now + Duration::from_secs(120))
            .min(self.source.original_material_deadline())
            .min(self.witness.original_service_deadline());
        let facts=wholepact_financial_coordinator_origin::SignerV3AuditFactsV1 {
            received:self.received.clone(),admitted:admitted.clone(),operation_id:self.request.operation_id.clone(),
            owner_selection_digest:read.facts.owner_selection_digest.clone(),owner_certificate_digest:read.facts.owner_certificate_digest.clone(),disclosure_digest:read.facts.disclosure_digest.clone(),
            display:format!("Read full authenticated original owner history for this exact retained admission. Never resend. Verify original local record and current material; retain exact financial originals only if this audit joins.\\nOperation: {}\\nRequest: {}",self.request.operation_id,admitted.admission_request_digest),
            reviewed_at_ms:wall,expires_at_ms:wall_at(now,wall,deadline,read.facts.material_expires_at_ms)?,
            source_expires_at_ms:read.facts.source_expires_at_ms,service_expires_at_ms:read.facts.service_expires_at_ms,material_expires_at_ms:read.facts.material_expires_at_ms,
        };
        facts.validate()?;
        Ok((facts, deadline))
    }
    pub(in crate::native_ui::runtime) fn audit(
        self,
        action: wholepact_financial_coordinator_origin::SignerV3AuditFinalV1,
    ) -> Result<AuditedCoordinatedV3V1> {
        use wholepact_authority::durable_financial_continuation_v1::{
            original_delivery_request_digest_v1, FinancialContinuationTermsV1,
        };
        action.check_current()?;
        if action.facts().received != self.received
            || Some(&action.facts().admitted) != self.admitted.as_ref()
            || action.facts().operation_id != self.request.operation_id
        {
            return Err(Error::ReviewMismatch);
        }
        let retained = self.retained.as_ref().ok_or(Error::RecoveryRequired)?;
        if retained.request() != &self.request || retained.recipient_intent() != &self.intent {
            return Err(Error::ReviewMismatch);
        }
        let read = self
            .witness
            .read_for_audit(action, || self.source.check_current())?;
        let history = read.history();
        crate::native_ui::runtime::durable_delivery_v3::require_exact_original_admission(
            history,
            retained.request(),
            retained.disclosure(),
            retained.owner_certificate_digest(),
            self.controlled.as_ref(),
        )?;
        let wholepact_authority::OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } =
            &self.request.control
        else {
            return Err(Error::ReviewMismatch);
        };
        // The maintained first financial continuation needs the original
        // immediate admitted head, not any later unrelated current snapshot.
        if self.request.expected_head.sequence.checked_add(1)
            != Some(history.snapshot().head.sequence)
        {
            return Err(Error::Uncertain);
        }
        let terms = FinancialContinuationTermsV1 {
            scope: record.scope.clone(),
            original_delivery_operation_id: self.request.operation_id.clone(),
            original_delivery_request_digest: original_delivery_request_digest_v1(&self.request)
                .map_err(|_| Error::ReviewMismatch)?,
            original_delivery_committed_head: history.snapshot().head.clone(),
            original_local_intent_digest: retained.history_digest()?,
            original_recipient_intent_digest: self
                .intent
                .digest()
                .map_err(|_| Error::ReviewMismatch)?,
            original_recipient_enrollment_ref: retained.enrollment_ref().into(),
            original_recipient_manifest_ref: retained.manifest_ref().into(),
            valid_from_ms: record.scope.delivery.valid_from_ms,
            valid_until_ms: record.scope.delivery.valid_until_ms,
        };
        terms.validate().map_err(|_| Error::ReviewMismatch)?;
        let selection = self.source.capture_financial_selection_under_audit(
            read.action(),
            &terms,
            &self.intent,
            retained,
        )?;
        let report = wholepact_financial_coordinator_origin::SignerV3AuditedV1 {
            audit_presentation_digest: read.action().presentation().presentation_digest.clone(),
            admit_presentation_digest: read
                .action()
                .facts()
                .admitted
                .admit_presentation_digest
                .clone(),
            source_identity_digest: self.received.source_identity_digest.clone(),
            owner_service_digest: self.received.owner_service_digest.clone(),
            recipient_intent_digest: self.received.recipient_intent_digest.clone(),
            authenticated_history_digest: history
                .history_digest()
                .map_err(|_| Error::ReviewMismatch)?,
            local_record_digest: retained.history_digest()?,
            admission_request_digest: read
                .action()
                .facts()
                .admitted
                .admission_request_digest
                .clone(),
            operation_id: self.request.operation_id.clone(),
        };
        report.validate()?;
        let (witness, history, lifetime) = read.finish()?;
        let custody = CoordinatedAdmissionAttemptV1 {
            source: self.source,
            witness,
            intent: self.intent,
            fixed: self.fixed,
            receipt: self.receipt,
            received: self.received,
            request: self.request,
            retained: self.retained,
            controlled: self.controlled,
            admitted: self.admitted,
            failure: self.failure,
        };
        Ok(AuditedCoordinatedV3V1 {
            custody,
            selection,
            history,
            terms,
            report,
            lifetime,
        })
    }
}
impl AuditedCoordinatedV3V1 {
    pub(in crate::native_ui::runtime) fn report(
        &self,
    ) -> wholepact_financial_coordinator_origin::SignerV3AuditedV1 {
        self.report.clone()
    }
    pub(in crate::native_ui::runtime) fn seal(self) -> Result<CompletedCoordinatedV3V1> {
        self.lifetime.check_current()?;
        self.custody.source.check_current()?;
        self.custody.witness.check_custody()?;
        // No private read here: every retained original was captured above under
        // the actual fresh Audit before its nominal owner was consumed.
        Ok(CompletedCoordinatedV3V1 { audited: self })
    }
}

fn respond_original_host(
    source: &CoordinatedPreparedDeliverySourceV1,
    peer: crate::ipc::CoordinatedPairPeerV1,
    mut stream: UnixStream,
    intent_digest: &str,
    expected: &str,
    response: CoordinatedClosedResponseV1,
    request_deadline: Instant,
) -> Result<()> {
    source.check_current()?;
    source.peer().require_same_grant(&peer)?;
    if intent_digest != expected {
        return Err(Error::ReviewMismatch);
    }
    let observed = crate::native_peer::PeerProcess::observe(&stream)?;
    peer.actual_peer().same_live_process(&observed)?;
    let observer = stream.try_clone()?;
    let current = || {
        source
            .check_current()
            .map_err(|_| crate::authority_bridge::BridgeError::Permission)?;
        peer.check_current()
            .map_err(|_| crate::authority_bridge::BridgeError::Permission)?;
        let actual = crate::native_peer::PeerProcess::observe(&observer)
            .map_err(|_| crate::authority_bridge::BridgeError::Permission)?;
        peer.actual_peer()
            .same_live_process(&actual)
            .map_err(|_| crate::authority_bridge::BridgeError::Permission)
    };
    crate::authority_bridge::durable_review_ipc_v1::bounded_write_restricted(
        &mut stream,
        &response,
        request_deadline
            .min(source.original_material_deadline())
            .min(peer.deadline()),
        &current,
        &current,
    )
    .map_err(|_| Error::Uncertain)
}
impl PreparedCoordinatedAdmissionV1 {
    pub(in crate::native_ui::runtime) fn next_event(
        &self,
    ) -> Result<Option<crate::ipc::CoordinatedLocalEventV1>> {
        self.check_current()?;
        self.source.next_event()
    }
    pub(in crate::native_ui::runtime) fn acknowledge(
        &self,
        peer: crate::ipc::CoordinatedPairPeerV1,
        stream: UnixStream,
        intent_digest: String,
        nonce: String,
        deadline: Instant,
    ) -> Result<()> {
        respond_original_host(
            &self.source,
            peer,
            stream,
            &intent_digest,
            &self.received.recipient_intent_digest,
            CoordinatedClosedResponseV1::Admitting { nonce },
            deadline,
        )
    }
}
impl CoordinatedAdmissionAttemptV1 {
    pub(in crate::native_ui::runtime) fn next_event(
        &self,
    ) -> Result<Option<crate::ipc::CoordinatedLocalEventV1>> {
        self.source.next_event()
    }
    pub(in crate::native_ui::runtime) fn respond(
        &self,
        peer: crate::ipc::CoordinatedPairPeerV1,
        stream: UnixStream,
        intent_digest: String,
        nonce: String,
        deadline: Instant,
        history: Option<&str>,
    ) -> Result<()> {
        let retained = self.retained.as_ref().ok_or(Error::RecoveryRequired)?;
        let wholepact_authority::OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } =
            &self.request.control
        else {
            return Err(Error::ReviewMismatch);
        };
        let response = if let Some(authorization) = history {
            if authorization != record.scope.authorization.authorization_id {
                return Err(Error::ReviewMismatch);
            }
            CoordinatedClosedResponseV1::Preparing { nonce }
        } else {
            use crate::authority_bridge::durable_review_ipc_v3::coordinated_v1::{
                CoordinatedAdmissionStateV1, CoordinatedDurableDeliveryAdmissionStatusV1,
            };
            let status = CoordinatedDurableDeliveryAdmissionStatusV1 {
                version: 1,
                intent_digest: self.received.recipient_intent_digest.clone(),
                request: self.request.clone(),
                original_local_intent_digest: retained.history_digest()?,
                state: if self.controlled.is_some() {
                    CoordinatedAdmissionStateV1::AwaitingAudit
                } else {
                    CoordinatedAdmissionStateV1::Unknown
                },
                audit: None,
            };
            status.validate().map_err(|_| Error::ReviewMismatch)?;
            CoordinatedClosedResponseV1::Admission {
                nonce,
                admission: status,
            }
        };
        respond_original_host(
            &self.source,
            peer,
            stream,
            &intent_digest,
            &self.received.recipient_intent_digest,
            response,
            deadline,
        )
    }
}
impl CompletedCoordinatedV3V1 {
    pub(in crate::native_ui::runtime) fn next_event(
        &self,
    ) -> Result<Option<crate::ipc::CoordinatedLocalEventV1>> {
        self.audited.lifetime.check_current()?;
        self.audited.custody.source.next_event()
    }
    pub(in crate::native_ui::runtime) fn respond_history(
        self,
        peer: crate::ipc::CoordinatedPairPeerV1,
        stream: UnixStream,
        intent_digest: String,
        authorization: String,
        nonce: String,
        deadline: Instant,
    ) -> Result<HistoryReturnedCoordinatedV3V1> {
        use crate::authority_bridge::durable_review_ipc_v3::coordinated_v1::{
            CoordinatedAdmissionStateV1, CoordinatedDurableDeliveryAdmissionStatusV1,
        };
        self.audited.lifetime.check_current()?;
        let custody = &self.audited.custody;
        let retained = custody.retained.as_ref().ok_or(Error::RecoveryRequired)?;
        let wholepact_authority::OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } =
            &custody.request.control
        else {
            return Err(Error::ReviewMismatch);
        };
        if authorization != record.scope.authorization.authorization_id {
            return Err(Error::ReviewMismatch);
        }
        let audit=crate::authority_bridge::durable_delivery_admission_ipc_v2::DurableDeliveryAdmissionStatusV2 {
            version:2,request:custody.request.clone(),scope:record.scope.clone(),original_enrollment_ref:retained.enrollment_ref().into(),original_accepted_manifest_ref:retained.manifest_ref().into(),original_local_intent_digest:retained.history_digest()?,authenticated_witness_history_digest:self.audited.history.history_digest().map_err(|_|Error::ReviewMismatch)?,witness_committed:true,current_fixed_material_source:"unchecked".into(),
        };
        let status = CoordinatedDurableDeliveryAdmissionStatusV1 {
            version: 1,
            intent_digest: custody.received.recipient_intent_digest.clone(),
            request: custody.request.clone(),
            original_local_intent_digest: retained.history_digest()?,
            state: CoordinatedAdmissionStateV1::Verified,
            audit: Some(audit),
        };
        status.validate().map_err(|_| Error::ReviewMismatch)?;
        respond_original_host(
            &custody.source,
            peer,
            stream,
            &intent_digest,
            &custody.received.recipient_intent_digest,
            CoordinatedClosedResponseV1::Admission {
                nonce,
                admission: status,
            },
            deadline,
        )?;
        Ok(HistoryReturnedCoordinatedV3V1 { completed: self })
    }
}

pub(in crate::native_ui::runtime) struct HistoryReturnedCoordinatedV3V1 {
    completed: CompletedCoordinatedV3V1,
}

#[path = "coordinated_delivery_admission_v1/coordinated_financial_handoff_v1.rs"]
mod coordinated_financial_handoff_v1;
pub(in crate::native_ui::runtime) use coordinated_financial_handoff_v1::DetachedCoordinatedFinancialHandoffV1;
pub(in crate::native_ui::runtime) use coordinated_financial_handoff_v1::coordinated_financial_entry_v1::{PresentedFinancialEntryRoleV1,OpenedFinancialEntryRoleV1,PreparedInitialFinancialReadRoleV1,PresentedInitialFinancialReadRoleV1,ReadInitialFinancialRoleV1};
