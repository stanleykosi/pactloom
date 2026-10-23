//! Original-S control owner, separate from every private opening worker.
//! This initial source route uses no Signer native window, legacy decision,
//! credential argv, role replay, or imported completed-V3 custody.
use super::coordinated_v3_delivery::{
    self as delivery, AuditedCoordinatedV3V1, CompletedCoordinatedV3V1,
    CoordinatedAdmissionAttemptV1, CoordinatedAdmissionWorkerV1, CoordinatedReadyToReceiveV1,
    CoordinatedReceiveReviewV1, CoordinatedReceivedBytesV1, CoordinatedVerifiedImportV1,
    HistoryReturnedCoordinatedV3V1, PreparedCoordinatedAdmissionV1,
    PreparedCoordinatedDeliveryReviewV1,
};
use super::*;
#[path="coordinated_financial_driver_v1/financial_tail_v1.rs"]
mod financial_tail_v1;
use financial_tail_v1::FinancialState;
#[path="coordinated_financial_driver_v1/status_worker_v1.rs"]
mod status_worker_v1;
use status_worker_v1::{StatusKind,StatusWorker};
use crate::account::birth::enrollment::roster_v2::durable_entry_v1::CoordinatedFinancialRoleTransportV1;
use wholepact_financial_coordinator_origin::SignerFinancialSetupSelectionV1;
use crate::account::birth::enrollment::roster_v2::durable_entry_v1::{
    CoordinatedEnrollmentReviewV1, CoordinatedManifestReviewV1,
    CoordinatedOriginalDeliverySourceV1, CoordinatedPreconstructionReadyV1,
    CoordinatedPreparingDeliverySourceV1, CoordinatedRediscloseV1, CoordinatedRedisclosedSourceV1,
    CoordinatedRedisclosureReadV1, CoordinatedRestrictedReceiptV1, CoordinatedSourcePairingV1,
    PreparedCoordinatedV3SourceEntryV1, PresentedCoordinatedV3SourceEntryV1,
};
use crate::authority_bridge::durable_review_ipc_v3::coordinated_v1::CoordinatedClosedCommandV1;
use crate::ipc::{
    CoordinatedLocalEventV1, CoordinatedPairPeerV1, CoordinatedRequestV1, PendingPairing,
};
use crate::native_peer::PeerProcess;
use wholepact_financial_coordinator_origin::{
    SignerFinancialWorkflowOriginV1, SignerFinancialWorkflowRequestV1 as Request, SignerOriginV1,
    SignerV3PairEndpointV1, SignerV3PairedV1, SignerNormalCloseV1,
};

struct Opening {
    worker: Option<std::thread::JoinHandle<Result<CoordinatedOriginalDeliverySourceV1>>>,
}
impl Opening {
    fn join(mut self) -> Result<CoordinatedOriginalDeliverySourceV1> {
        self.worker
            .take()
            .ok_or(Error::Unavailable)?
            .join()
            .map_err(|_| Error::Unavailable)?
    }
}
impl Drop for Opening {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
struct PairIssuing {
    worker: Option<std::thread::JoinHandle<Result<CoordinatedSourcePairingV1>>>,
}
impl PairIssuing {
    fn join(mut self) -> Result<CoordinatedSourcePairingV1> {
        self.worker
            .take()
            .ok_or(Error::Unavailable)?
            .join()
            .map_err(|_| Error::Unavailable)?
    }
}
impl Drop for PairIssuing {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
enum ReceiptOutcome {
    Enrolled(CoordinatedManifestReviewV1),
    ManifestAccepted(CoordinatedPreconstructionReadyV1),
    Restricted(CoordinatedRestrictedReceiptV1),
}
struct ReceiptWriting {
    worker: Option<std::thread::JoinHandle<Result<ReceiptOutcome>>>,
}
impl ReceiptWriting {
    fn join(mut self) -> Result<ReceiptOutcome> {
        self.worker
            .take()
            .ok_or(Error::Unavailable)?
            .join()
            .map_err(|_| Error::Uncertain)?
    }
}
impl Drop for ReceiptWriting {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
enum RedisclosureOutcome {
    Prepared(CoordinatedRediscloseV1),
    Exported(CoordinatedRedisclosedSourceV1),
}
struct RedisclosureWorking {
    worker: Option<std::thread::JoinHandle<Result<RedisclosureOutcome>>>,
}
impl RedisclosureWorking {
    fn join(mut self) -> Result<RedisclosureOutcome> {
        self.worker
            .take()
            .ok_or(Error::Unavailable)?
            .join()
            .map_err(|_| Error::Uncertain)?
    }
}
impl Drop for RedisclosureWorking {
    fn drop(&mut self) {
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}
enum DeliveryOutcome {
    Staged(CoordinatedPreparingDeliverySourceV1),
    ReadReview(PreparedCoordinatedDeliveryReviewV1),
    ReceiveReview(CoordinatedReceiveReviewV1),
    Ready(CoordinatedReadyToReceiveV1),
    Received(CoordinatedReceivedBytesV1),
    Verified(CoordinatedVerifiedImportV1),
    AdmissionPrepared(PreparedCoordinatedAdmissionV1),
    Audited(AuditedCoordinatedV3V1),
    HistoryReturned(HistoryReturnedCoordinatedV3V1),
}
struct DeliveryWorking {
    worker: Option<std::thread::JoinHandle<Result<DeliveryOutcome>>>,
}
impl DeliveryWorking {
    fn join(mut self) -> Result<DeliveryOutcome> {
        self.worker
            .take()
            .ok_or(Error::Unavailable)?
            .join()
            .map_err(|_| Error::Uncertain)?
    }
}
impl Drop for DeliveryWorking {
    fn drop(&mut self) {
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}
enum State {
    AwaitingPeer,
    Peer(PeerProcess),
    Offered {
        peer: PeerProcess,
        entry: PresentedCoordinatedV3SourceEntryV1,
    },
    Opening(Opening),
    Opened(CoordinatedOriginalDeliverySourceV1),
    Pairing {
        owner: CoordinatedSourcePairingV1,
        endpoint: SignerV3PairEndpointV1,
        pending: Option<(PendingPairing, String)>,
    },
    PairIssuing {
        job: PairIssuing,
        endpoint: SignerV3PairEndpointV1,
    },
    Paired {
        owner: CoordinatedSourcePairingV1,
        peer: CoordinatedPairPeerV1,
    },
    EnrollmentReview(CoordinatedEnrollmentReviewV1),
    ManifestReview(CoordinatedManifestReviewV1),
    ReceiptWriting(ReceiptWriting),
    ReceiptRestricted(CoordinatedRestrictedReceiptV1),
    PreconstructionReady(CoordinatedPreconstructionReadyV1),
    RedisclosureRead(CoordinatedRedisclosureReadV1),
    Redisclose(CoordinatedRediscloseV1),
    RedisclosureWorking(RedisclosureWorking),
    Redisclosed(CoordinatedRedisclosedSourceV1),
    // Actual committed result retained after R/postcheck/partial-send failure;
    // no polling, report, grant, mutation retry or next-stage join is permitted.
    RedisclosureRestricted(CoordinatedRedisclosedSourceV1),
    AwaitingOwner(CoordinatedPreparingDeliverySourceV1),
    DeliveryReadReview(PreparedCoordinatedDeliveryReviewV1),
    DeliveryReceiveReview(CoordinatedReceiveReviewV1),
    DeliveryReady(CoordinatedReadyToReceiveV1),
    DeliveryBytes(CoordinatedReceivedBytesV1),
    DeliveryVerified(CoordinatedVerifiedImportV1),
    AdmissionPrepared(PreparedCoordinatedAdmissionV1),
    AdmissionReview(PreparedCoordinatedAdmissionV1),
    AdmissionWorking(CoordinatedAdmissionWorkerV1),
    AdmissionAttempt(CoordinatedAdmissionAttemptV1),
    AuditReview(CoordinatedAdmissionAttemptV1),
    Audited(AuditedCoordinatedV3V1),
    Completed(CompletedCoordinatedV3V1),
    HistoryReturned(HistoryReturnedCoordinatedV3V1),
    DeliveryWorking(DeliveryWorking),
    StatusWorking(StatusWorker),
    Financial(FinancialState),
    Taken,
}
impl State {
    fn join_and_drop(self) -> Result<()> {
        if let State::Opening(job) = self {
            // No result is interpreted as completion or turned into a grant.
            let result = job.join();
            drop(result);
        }
        Ok(())
    }
}
// Declaration order is security-relevant: unwind drops Origin (publishes R
// and closes control) before State joins an outstanding private worker.
struct Driver {
    origin: SignerFinancialWorkflowOriginV1,
    normal_close: Option<SignerNormalCloseV1>,
    state: State,
    entry_opened_reported: bool,
    owner_selection: Option<(String, String)>,
    pending_status_control:Option<Request>,
    financial_setup:Option<SignerFinancialSetupSelectionV1>,
    financial_entry_requested:bool,
    financial_transport:Option<CoordinatedFinancialRoleTransportV1>,
}
impl Driver {
    fn poll_opening(&mut self) -> Result<()> {
        if !matches!(&self.state, State::Opening(job) if job.worker.as_ref().is_some_and(|worker| worker.is_finished()))
        {
            return Ok(());
        }
        let State::Opening(job) = std::mem::replace(&mut self.state, State::Taken) else {
            return Err(Error::Unavailable);
        };
        let source = job.join()?;
        // Retain successful private custody before any fallible report. Loss of
        // the observation does not reconstruct the source or permit re-entry.
        self.state = State::Opened(source);
        if let State::Opened(source) = &self.state {
            source.check_retained_restriction()?;
            self.origin
                .v3_source_opened(source.opened_report().clone())?;
            self.entry_opened_reported = true;
        }
        Ok(())
    }
    fn begin_pairing(&mut self) -> Result<()> {
        if !matches!(self.state, State::Opened(_)) {
            return Ok(());
        }
        let State::Opened(source) = std::mem::replace(&mut self.state, State::Taken) else {
            return Err(Error::Unavailable);
        };
        let owner = source.into_pairing_endpoint()?;
        let endpoint = self
            .origin
            .publish_v3_pair_endpoint(owner.endpoint_path()?.to_owned())?;
        self.state = State::Pairing {
            owner,
            endpoint,
            pending: None,
        };
        Ok(())
    }
    fn poll_pairing(&mut self) -> Result<()> {
        if matches!(&self.state, State::PairIssuing { job, .. }
            if job.worker.as_ref().is_some_and(|w| w.is_finished()))
        {
            let State::PairIssuing { job, endpoint } =
                std::mem::replace(&mut self.state, State::Taken)
            else {
                return Err(Error::Unavailable);
            };
            self.state = State::Pairing {
                owner: job.join()?,
                endpoint,
                pending: None,
            };
        }
        let event = match &self.state {
            State::Pairing { owner, .. } => owner.next_event()?,
            State::Paired { owner, peer } => {
                owner.check_current()?;
                peer.check_current()?;
                owner.next_event()?
            }
            _ => None,
        };
        let Some(event) = event else {
            return Ok(());
        };
        match event {
            CoordinatedLocalEventV1::Pairing(request) => {
                let State::Pairing {
                    owner,
                    endpoint,
                    pending,
                } = &mut self.state
                else {
                    return Err(Error::ReviewMismatch);
                };
                if pending.is_some() {
                    return Err(Error::ReviewMismatch);
                }
                let (facts, deadline, channel_deadline) = owner.pair_facts(&request, endpoint)?;
                let presentation = self
                    .origin
                    .offer_v3_pair(facts, deadline, channel_deadline)?;
                *pending = Some((request, presentation.presentation_digest));
            }
            CoordinatedLocalEventV1::StatusProof(peer) => {
                peer.check_current()?;
                let State::Pairing {
                    owner,
                    pending: None,
                    ..
                } = std::mem::replace(&mut self.state, State::Taken)
                else {
                    return Err(Error::ReviewMismatch);
                };
                owner.check_current()?;
                // Actual fresh token possession, not issuance/empty queue, is
                // retained before reporting the paired observation.
                self.state = State::Paired { owner, peer };
                let State::Paired { peer, .. } = &self.state else {
                    return Err(Error::Unavailable);
                };
                self.origin.report_v3_pair_authenticated(SignerV3PairedV1 {
                    presentation_digest: peer.pair_presentation_digest().into(),
                    source_identity_digest: peer.source_identity().into(),
                    original_host_process_instance: peer.original_host_process_instance().into(),
                    grant_id: peer.grant_id().into(),
                    key_digest: peer.key_digest().into(),
                    channel_digest: peer.channel_digest().into(),
                    generation: peer.generation(),
                })?;
            }
            // No ordinary request supplies a private Read or export approval.
            CoordinatedLocalEventV1::Request { .. } => return Err(Error::ReviewMismatch),
        }
        Ok(())
    }
    fn begin_enrollment(&mut self) -> Result<()> {
        if !matches!(self.state, State::Paired { .. }) {
            return Ok(());
        }
        let State::Paired { owner, peer } = std::mem::replace(&mut self.state, State::Taken) else {
            return Err(Error::Unavailable);
        };
        self.state = State::EnrollmentReview(owner.begin_enrollment(peer)?);
        let State::EnrollmentReview(review) = &self.state else {
            return Err(Error::Unavailable);
        };
        self.origin
            .offer_v3_enrollment(review.facts().clone(), review.original_review_deadline())?;
        Ok(())
    }
    fn poll_receipts(&mut self) -> Result<()> {
        if matches!(&self.state, State::ReceiptWriting(job) if job.worker.as_ref().is_some_and(|w|w.is_finished()))
        {
            let State::ReceiptWriting(job) = std::mem::replace(&mut self.state, State::Taken)
            else {
                return Err(Error::Unavailable);
            };
            match job.join()? {
                ReceiptOutcome::Restricted(held) => self.state = State::ReceiptRestricted(held),
                ReceiptOutcome::Enrolled(next) => {
                    self.state = State::ManifestReview(next);
                    self.origin.report_v3_enrolled()?;
                    let State::ManifestReview(review) = &self.state else {
                        return Err(Error::Unavailable);
                    };
                    review.check_current()?;
                    self.origin.offer_v3_manifest(
                        review.facts().clone(),
                        review.original_review_deadline(),
                    )?;
                }
                ReceiptOutcome::ManifestAccepted(next) => {
                    self.state = State::PreconstructionReady(next);
                    self.origin.report_v3_manifest_accepted()?;
                }
            }
        }
        match &self.state {
            State::EnrollmentReview(review) => review.check_current()?,
            State::ManifestReview(review) => review.check_current()?,
            State::PreconstructionReady(ready) => ready.check_current()?,
            _ => (),
        }
        Ok(())
    }
    fn poll_redisclosure(&mut self) -> Result<()> {
        if matches!(&self.state,State::RedisclosureWorking(job) if job.worker.as_ref().is_some_and(|w|w.is_finished()))
        {
            let State::RedisclosureWorking(job) = std::mem::replace(&mut self.state, State::Taken)
            else {
                return Err(Error::Unavailable);
            };
            match job.join()? {
                RedisclosureOutcome::Prepared(next) => {
                    self.state = State::Redisclose(next);
                    let State::Redisclose(next) = &self.state else {
                        return Err(Error::Unavailable);
                    };
                    self.origin
                        .report_v3_redisclosure_prepared(next.prepared_report().clone())?;
                    self.origin.offer_v3_redisclose(
                        next.facts().clone(),
                        next.original_review_deadline(),
                    )?;
                }
                RedisclosureOutcome::Exported(next) => match next.report() {
                    Some(report) => {
                        self.state = State::Redisclosed(next);
                        self.origin.report_v3_redisclosed(report)?;
                    }
                    None => self.state = State::RedisclosureRestricted(next),
                },
            }
        }
        let event = if let State::PreconstructionReady(ready) = &self.state {
            ready.next_event()?
        } else {
            None
        };
        if let Some(event) = event {
            let CoordinatedLocalEventV1::Request {
                peer,
                stream,
                request: CoordinatedRequestV1::Redisclosure(selector),
                original_request_deadline,
            } = event
            else {
                return Err(Error::ReviewMismatch);
            };
            let State::PreconstructionReady(ready) =
                std::mem::replace(&mut self.state, State::Taken)
            else {
                return Err(Error::Unavailable);
            };
            self.state = State::RedisclosureRead(ready.begin_redisclosure(
                peer,
                stream,
                *selector,
                original_request_deadline,
            )?);
            let State::RedisclosureRead(review) = &self.state else {
                return Err(Error::Unavailable);
            };
            self.origin.offer_v3_redisclosure_read(
                review.facts().clone(),
                review.original_review_deadline(),
            )?;
        }
        match &self.state {
            State::RedisclosureRead(v) => v.check_current()?,
            State::Redisclose(v) => v.check_current()?,
            State::Redisclosed(v) => v.check_current()?,
            _ => (),
        }
        Ok(())
    }
    fn spawn_delivery(
        &mut self,
        work: impl FnOnce() -> Result<DeliveryOutcome> + Send + 'static,
    ) -> Result<()> {
        let worker = std::thread::Builder::new()
            .name("original-v3-delivery".into())
            .spawn(work)?;
        self.state = State::DeliveryWorking(DeliveryWorking {
            worker: Some(worker),
        });
        Ok(())
    }
    fn poll_delivery(&mut self) -> Result<()> {
        if let State::AdmissionWorking(worker) = &mut self.state {
            if let Some((arm, ready)) = worker.take_ready()? {
                self.origin.send_v3_admit_ready(arm, ready)?;
            }
        }
        if matches!(&self.state,State::AdmissionWorking(worker) if worker.finished()) {
            let State::AdmissionWorking(worker) = std::mem::replace(&mut self.state, State::Taken)
            else {
                return Err(Error::Unavailable);
            };
            self.state = State::AdmissionAttempt(worker.join()?);
            let State::AdmissionAttempt(attempt) = &self.state else {
                return Err(Error::Unavailable);
            };
            if let Some(report) = attempt.admitted_report() {
                self.origin.report_v3_admitted(report)?;
            }
        }
        if matches!(&self.state,State::DeliveryWorking(job) if job.worker.as_ref().is_some_and(|w|w.is_finished()))
        {
            let State::DeliveryWorking(job) = std::mem::replace(&mut self.state, State::Taken)
            else {
                return Err(Error::Unavailable);
            };
            match job.join()? {
                DeliveryOutcome::Staged(source) => self.state = State::AwaitingOwner(source),
                DeliveryOutcome::HistoryReturned(actual)=>self.state=State::HistoryReturned(actual),
                DeliveryOutcome::ReadReview(review) => {
                    self.state = State::DeliveryReadReview(review);
                    let State::DeliveryReadReview(review) = &self.state else {
                        return Err(Error::Unavailable);
                    };
                    let (read, service, material) = review.deadlines();
                    self.origin.offer_v3_prepare_read(
                        review.facts().clone(),
                        read,
                        service,
                        material,
                    )?;
                }
                DeliveryOutcome::ReceiveReview(review) => {
                    self.state = State::DeliveryReceiveReview(review);
                    let State::DeliveryReceiveReview(review) = &self.state else {
                        return Err(Error::Unavailable);
                    };
                    self.origin
                        .report_v3_prepared(review.prepared_report().clone())?;
                    self.origin
                        .offer_v3_receive(review.facts().clone(), review.deadline())?;
                }
                DeliveryOutcome::Ready(ready) => self.state = State::DeliveryReady(ready),
                DeliveryOutcome::Received(bytes) => self.state = State::DeliveryBytes(bytes),
                DeliveryOutcome::Audited(audited) => {
                    self.state = State::Audited(audited);
                    let State::Audited(audited) = &self.state else {
                        return Err(Error::Unavailable);
                    };
                    self.origin.report_v3_audited(audited.report())?;
                    let State::Audited(audited) = std::mem::replace(&mut self.state, State::Taken)
                    else {
                        return Err(Error::Unavailable);
                    };
                    self.state = State::Completed(audited.seal()?);
                }
                DeliveryOutcome::AdmissionPrepared(prepared) => {
                    self.state = State::AdmissionPrepared(prepared);
                    let State::AdmissionPrepared(prepared) = &self.state else {
                        return Err(Error::Unavailable);
                    };
                    self.origin
                        .report_v3_admit_read_retained(prepared.read_report())?;
                }
                DeliveryOutcome::Verified(verified) => {
                    self.state = State::DeliveryVerified(verified);
                    let State::DeliveryVerified(verified) = &self.state else {
                        return Err(Error::Unavailable);
                    };
                    self.origin.report_v3_received(verified.report())?;
                    let (facts, deadline) = verified.admit_read_review()?;
                    self.origin.offer_v3_admit_read(facts, deadline)?;
                }
            }
        }
        if matches!(self.state, State::AwaitingOwner(_)) && self.owner_selection.is_some() {
            let State::AwaitingOwner(source) = std::mem::replace(&mut self.state, State::Taken)
            else {
                return Err(Error::Unavailable);
            };
            let (json, challenge) = self.owner_selection.take().ok_or(Error::Unavailable)?;
            self.spawn_delivery(move || {
                PreparedCoordinatedDeliveryReviewV1::prepare(source, json, challenge)
                    .map(DeliveryOutcome::ReadReview)
            })?;
        }
        // Waiting status sockets remain queued until an actual Receive Final
        // exists. No placeholder intent or positive owner is sent while reviewing.
        let event = match &self.state {
            State::Redisclosed(v) => v.next_event()?,
            State::DeliveryReady(v) => v.next_event()?,
            State::DeliveryBytes(v) => v.next_event()?,
            State::AdmissionPrepared(v) | State::AdmissionReview(v) => v.next_event()?,
            State::AdmissionAttempt(v) | State::AuditReview(v) => v.next_event()?,
            State::Completed(v) => v.next_event()?,
            _ => None,
        };
        if let Some(event) = event {
            let CoordinatedLocalEventV1::Request {
                peer,
                stream,
                request,
                original_request_deadline,
            } = event
            else {
                return Err(Error::ReviewMismatch);
            };
            match request {
                CoordinatedRequestV1::Prepare(request) => {
                    let State::Redisclosed(source) =
                        std::mem::replace(&mut self.state, State::Taken)
                    else {
                        return Err(Error::ReviewMismatch);
                    };
                    self.spawn_delivery(move || {
                        delivery::stage_preparation(
                            source,
                            peer,
                            stream,
                            *request,
                            original_request_deadline,
                        )
                        .map(DeliveryOutcome::Staged)
                    })?;
                }
                CoordinatedRequestV1::Closed(command) => match command {
                    CoordinatedClosedCommandV1::Admit {intent_digest,nonce}=>{
                        self.spawn_status(peer,stream,intent_digest,nonce,original_request_deadline,StatusKind::Admit)?;
                    },
                    CoordinatedClosedCommandV1::AdmissionStatus {intent_digest,nonce}=>{
                        self.spawn_status(peer,stream,intent_digest,nonce,original_request_deadline,StatusKind::Status)?;
                    },
                    CoordinatedClosedCommandV1::History {intent_digest,authorization_id,nonce}=>{
                        if matches!(&self.state,State::Completed(_)) {
                            let State::Completed(v)=std::mem::replace(&mut self.state,State::Taken) else {return Err(Error::Unavailable)};
                            self.spawn_delivery(move ||v.respond_history(peer,stream,intent_digest,authorization_id,nonce,original_request_deadline).map(DeliveryOutcome::HistoryReturned))?;
                        } else {
                            self.spawn_status(peer,stream,intent_digest,nonce,original_request_deadline,StatusKind::History(authorization_id))?;
                        }
                    },
                    CoordinatedClosedCommandV1::PreparationStatus {
                        request_digest,
                        nonce,
                    } => {
                        let State::DeliveryReady(ready) =
                            std::mem::replace(&mut self.state, State::Taken)
                        else {
                            return Err(Error::ReviewMismatch);
                        };
                        if ready.preparation_digest() != request_digest {
                            return Err(Error::ReviewMismatch);
                        }
                        self.spawn_delivery(move || {
                            ready
                                .respond_prepared(peer, stream, nonce, original_request_deadline)
                                .map(DeliveryOutcome::Ready)
                        })?;
                    }
                    CoordinatedClosedCommandV1::Activate {
                        intent_digest,
                        nonce,
                    } => {
                        let State::DeliveryReady(ready) =
                            std::mem::replace(&mut self.state, State::Taken)
                        else {
                            return Err(Error::ReviewMismatch);
                        };
                        self.spawn_delivery(move || {
                            ready
                                .receive(
                                    peer,
                                    stream,
                                    intent_digest,
                                    nonce,
                                    original_request_deadline,
                                )
                                .map(DeliveryOutcome::Received)
                        })?;
                    }
                    CoordinatedClosedCommandV1::VerifyImport {
                        intent_digest,
                        nonce,
                    } => {
                        let State::DeliveryBytes(bytes) =
                            std::mem::replace(&mut self.state, State::Taken)
                        else {
                            return Err(Error::ReviewMismatch);
                        };
                        self.spawn_delivery(move || {
                            bytes
                                .verify(
                                    peer,
                                    stream,
                                    intent_digest,
                                    nonce,
                                    original_request_deadline,
                                )
                                .map(DeliveryOutcome::Verified)
                        })?;
                    }
                    _ => return Err(Error::ReviewMismatch),
                },
                _ => return Err(Error::ReviewMismatch),
            }
        }
        match &self.state {
            State::AwaitingOwner(v) => v.check_current()?,
            State::DeliveryReadReview(v) => v.check_current()?,
            State::DeliveryReceiveReview(v) => v.check_current()?,
            State::DeliveryReady(v) => v.check_current()?,
            State::DeliveryBytes(v) => v.check_current()?,
            State::DeliveryVerified(v) => v.check_current()?,
            State::AdmissionPrepared(v) | State::AdmissionReview(v) => v.check_current()?,
            _ => (),
        }
        Ok(())
    }
    fn handle(&mut self, request: Request) -> Result<bool> {
        // This is an original typed close action, never a DTO/phase boolean.
        // It cannot queue behind any private worker or skip actual Return.
        let request = match request {
            Request::NormalClose { action } => {
                if !matches!(&self.state, State::Financial(FinancialState::ReturnReported(_)))
                    || self.pending_status_control.is_some() || self.normal_close.is_some() {
                    return Err(Error::ReviewMismatch);
                }
                action.check_current()?;
                self.normal_close = Some(action);
                return Ok(false);
            }
            other => other,
        };
        // A real native action may arrive while a denial-only status send owns
        // custody. Keep its one-use token inert until that exact worker joins.
        // Cancel never queues and always publishes restriction immediately.
        if matches!(&self.state,State::StatusWorking(_)) && !matches!(&request,Request::Cancel) {
            if self.pending_status_control.replace(request).is_some(){return Err(Error::ReviewMismatch)}
            return Ok(true);
        }
        match request {
            Request::Cancel => return Ok(false),
            Request::FinancialSetupSelection {selection}=>{
                if self.financial_setup.is_some() || self.financial_entry_requested || self.financial_transport.is_some(){return Err(Error::ReviewMismatch)}
                self.financial_setup=Some(selection);
            },
            Request::SourceEntryRequested=>{
                if self.financial_entry_requested || self.financial_setup.is_none(){return Err(Error::ReviewMismatch)}
                self.financial_entry_requested=true;
            },
            request @ (Request::SourceEntry{..}|Request::InitialRead(_)|Request::ContinueRequested|Request::ContinueArm(_)|Request::ContinueFinal(_)|Request::AdmitArm(_)|Request::AdmitFinal(_)|Request::WriterRead(_)|Request::AcquireArm(_)|Request::AcquireFinal(_)|Request::ActivateRead(_)|Request::ActivateArm(_)|Request::ActivateFinal(_)|Request::WalletPrepare{..}|Request::WalletObserve{..}|Request::SignRead{..}|Request::SignExact{..}|Request::ReturnRead{..}|Request::ReturnExact{..})=>self.handle_financial(request)?,
            Request::V3OwnerSelection {
                owner_setup_json,
                owner_selection_challenge,
            } => {
                if self.owner_selection.is_some()
                    || !matches!(
                        self.state,
                        State::Redisclosed(_) | State::AwaitingOwner(_) | State::DeliveryWorking(_)
                    )
                {
                    return Err(Error::ReviewMismatch);
                }
                self.owner_selection = Some((owner_setup_json, owner_selection_challenge));
            }
            Request::V3PrepareRead { final_action } => {
                let State::DeliveryReadReview(review) =
                    std::mem::replace(&mut self.state, State::Taken)
                else {
                    return Err(Error::ReviewMismatch);
                };
                self.spawn_delivery(move || {
                    review
                        .consume_read(final_action)
                        .map(DeliveryOutcome::ReceiveReview)
                })?;
            }
            Request::V3Audit { final_action } => {
                let State::AuditReview(attempt) = std::mem::replace(&mut self.state, State::Taken)
                else {
                    return Err(Error::ReviewMismatch);
                };
                self.spawn_delivery(move || {
                    attempt.audit(final_action).map(DeliveryOutcome::Audited)
                })?;
            }
            Request::V3AdmitArm { arm } => {
                let State::AdmissionReview(prepared) =
                    std::mem::replace(&mut self.state, State::Taken)
                else {
                    return Err(Error::ReviewMismatch);
                };
                self.state = State::AdmissionWorking(prepared.start_admission(arm)?);
            }
            Request::V3AdmitFinal { final_action } => {
                let State::AdmissionWorking(worker) = &mut self.state else {
                    return Err(Error::ReviewMismatch);
                };
                worker.provide_final(final_action)?;
            }
            Request::V3AdmitRead { final_action } => {
                let State::DeliveryVerified(verified) =
                    std::mem::replace(&mut self.state, State::Taken)
                else {
                    return Err(Error::ReviewMismatch);
                };
                self.spawn_delivery(move || {
                    verified
                        .read_for_admission(final_action)?
                        .prepare()
                        .map(DeliveryOutcome::AdmissionPrepared)
                })?;
            }
            Request::V3Receive { final_action } => {
                let State::DeliveryReceiveReview(review) =
                    std::mem::replace(&mut self.state, State::Taken)
                else {
                    return Err(Error::ReviewMismatch);
                };
                self.state = State::DeliveryReady(review.consume_final(final_action)?);
            }
            Request::V3RedisclosureRead { final_action } => {
                let State::RedisclosureRead(review) =
                    std::mem::replace(&mut self.state, State::Taken)
                else {
                    return Err(Error::ReviewMismatch);
                };
                let worker = std::thread::Builder::new()
                    .name("original-v3-redisclosure-read".into())
                    .spawn(move || review.read(final_action).map(RedisclosureOutcome::Prepared))?;
                self.state = State::RedisclosureWorking(RedisclosureWorking {
                    worker: Some(worker),
                });
            }
            Request::V3Redisclose { final_action } => {
                let State::Redisclose(review) = std::mem::replace(&mut self.state, State::Taken)
                else {
                    return Err(Error::ReviewMismatch);
                };
                let worker = std::thread::Builder::new()
                    .name("original-v3-redisclosure-export".into())
                    .spawn(move || {
                        review
                            .export(final_action)
                            .map(RedisclosureOutcome::Exported)
                    })?;
                self.state = State::RedisclosureWorking(RedisclosureWorking {
                    worker: Some(worker),
                });
            }
            Request::OriginalHostPeer(original) => {
                if !matches!(self.state, State::AwaitingPeer) {
                    return Err(Error::ReviewMismatch);
                }
                self.state = State::Peer(PeerProcess::from_original_financial_host(original)?);
            }
            Request::V3SourceEntryRequested { selection } => {
                let State::Peer(peer) = &self.state else {
                    return Err(Error::ReviewMismatch);
                };
                peer.check_alive()?;
                let facts = selection.proposed_facts(peer.instance())?;
                let prepared = PreparedCoordinatedV3SourceEntryV1::prepare(
                    std::path::Path::new(&selection.canonical_root),
                    facts,
                    peer,
                    self.origin.session_deadline(),
                )?;
                let presentation = self.origin.offer_v3_source_entry(
                    prepared.facts().clone(),
                    prepared.original_source_deadline(),
                    prepared.original_entry_deadline(),
                )?;
                let entry = prepared.freeze(presentation)?;
                self.state = State::Offered {
                    peer: peer.clone(),
                    entry,
                };
            }
            Request::V3Enrollment { final_action } => {
                if !matches!(self.state, State::EnrollmentReview(_)) {
                    return Err(Error::ReviewMismatch);
                }
                let State::EnrollmentReview(review) =
                    std::mem::replace(&mut self.state, State::Taken)
                else {
                    return Err(Error::Unavailable);
                };
                let worker = std::thread::Builder::new()
                    .name("original-v3-enrollment".into())
                    .spawn(move || {
                        review.commit(final_action).map(|result| match result {
                            Ok(next) => ReceiptOutcome::Enrolled(next),
                            Err(held) => ReceiptOutcome::Restricted(held),
                        })
                    })?;
                self.state = State::ReceiptWriting(ReceiptWriting {
                    worker: Some(worker),
                });
            }
            Request::V3Manifest { final_action } => {
                if !matches!(self.state, State::ManifestReview(_)) {
                    return Err(Error::ReviewMismatch);
                }
                let State::ManifestReview(review) =
                    std::mem::replace(&mut self.state, State::Taken)
                else {
                    return Err(Error::Unavailable);
                };
                let worker = std::thread::Builder::new()
                    .name("original-v3-manifest".into())
                    .spawn(move || {
                        review.commit(final_action).map(|result| match result {
                            Ok(next) => ReceiptOutcome::ManifestAccepted(next),
                            Err(held) => ReceiptOutcome::Restricted(held),
                        })
                    })?;
                self.state = State::ReceiptWriting(ReceiptWriting {
                    worker: Some(worker),
                });
            }
            Request::V3Pair { final_action } => {
                let State::Pairing {
                    pending: Some((_, digest)),
                    ..
                } = &self.state
                else {
                    return Err(Error::ReviewMismatch);
                };
                if digest != &final_action.presentation().presentation_digest {
                    return Err(Error::ReviewMismatch);
                }
                let State::Pairing {
                    owner,
                    endpoint,
                    pending: Some((pending, _)),
                } = std::mem::replace(&mut self.state, State::Taken)
                else {
                    return Err(Error::Unavailable);
                };
                let worker = std::thread::Builder::new()
                    .name("original-v3-pair-issue".into())
                    .spawn(move || {
                        owner.approve_pairing(pending, final_action)?;
                        Ok(owner)
                    })?;
                self.state = State::PairIssuing {
                    job: PairIssuing {
                        worker: Some(worker),
                    },
                    endpoint,
                };
            }
            Request::V3SourceEntry {
                input,
                final_action,
            } => {
                if !matches!(self.state, State::Offered { .. }) {
                    return Err(Error::ReviewMismatch);
                }
                let State::Offered { peer, entry } =
                    std::mem::replace(&mut self.state, State::Taken)
                else {
                    return Err(Error::Unavailable);
                };
                let worker = std::thread::Builder::new()
                    .name("original-v3-entry".into())
                    .spawn(move || entry.open(peer, input, final_action))?;
                self.state = State::Opening(Opening {
                    worker: Some(worker),
                });
            }
            // No phase flag/queued message is a PrepareRead or completed-V3
            // owner. Later nominal consumers extend this exact retained state.
            _ => return Err(Error::ReviewMismatch),
        }
        Ok(true)
    }
    fn run(mut self) -> ! {
        let work = (|| -> Result<()> {
            loop {
                actor_driver_result!(OriginalActors, self.origin.check_original_actors_alive())?;
                // Pump authenticated restriction before interpreting a worker's
                // result or offering another purpose. No Origin moves to worker.
                if let Some(request) = actor_driver_result!(Receive, self.origin.try_receive())? {
                    if !actor_driver_result!(Handle, self.handle(request))? {
                        return Ok(());
                    }
                }
                actor_driver_result!(Opening, self.poll_opening())?;
                actor_driver_result!(PairBegin, self.begin_pairing())?;
                actor_driver_result!(PairPoll, self.poll_pairing())?;
                actor_driver_result!(EnrollmentBegin, self.begin_enrollment())?;
                actor_driver_result!(ReceiptPoll, self.poll_receipts())?;
                actor_driver_result!(RedisclosurePoll, self.poll_redisclosure())?;
                actor_driver_result!(StatusPoll, self.poll_status())?;
                actor_driver_result!(DeliveryPoll, self.poll_delivery())?;
                actor_driver_result!(FinancialPoll, self.poll_financial())?;
                // ReturnReported retains the actual completed private owner.
                // Only the original typed NormalClose may end this wait; a
                // completed result is not a cancellation or disposal proof.
                if let Some(transport)=&self.financial_transport {actor_driver_result!(FinancialTransport, transport.check_current())?;}
                if let State::Opened(source) = &self.state {
                    actor_driver_result!(SourceRetention, source.check_retained_restriction())?;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        })();
        if work.is_err() {
            #[cfg(wholepact_financial_rendered_host_semantic_ci)]
            if let Err(error) = &work { crate::financial_ci_actor::driver(
                wholepact_financial_coordinator_origin::financial_ci_actor_diagnostics::DriverStage::WorkUnclassified, error); }
            if !self.entry_opened_reported {
                let _ = self.origin.v3_source_entry_failed();
            }
            self.origin.close_for_failed_worker_v1();
        }
        // On Cancel, Origin already published R; on error denial above precedes
        // every worker join and source/key drop. Never claim an empty queue is Q.
        // An offered/opening Entry has not reported opened custody. Cancel is
        // restriction, not a terminal observation: first join/drop the actual
        // worker/source, then explicitly report failure over cleanup transport.
        let cancelled_unreported_entry =
            work.is_ok() && matches!(self.state, State::Offered { .. } | State::Opening(_));
        let cleanup = actor_driver_result!(Cleanup, std::mem::replace(&mut self.state, State::Taken).join_and_drop());
        // Disposal includes the actual original return-only listener/tempdir,
        // not merely the private source worker. Complete never returns.
        drop(self.financial_transport.take());
        drop(self.pending_status_control.take());
        let cleanup = cleanup.and_then(|()| {
            if cancelled_unreported_entry {
                self.origin.v3_source_entry_failed()?;
            }
            Ok(())
        });
        if let Some(action) = self.normal_close.take() {
            let result = match (work, cleanup) {
                (Ok(()), Ok(())) => self.origin.send_normal_disposed(action),
                _ => Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied,
                    "original Signer normal close failed; no normal disposal claim")),
            };
            self.origin.complete_normal(result)
        }
        let result = match (work, cleanup) {
            (Ok(()), Ok(())) => self.origin.send_disposed(),
            _ => Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied,
                "original Signer workflow failed; private custody disposed without completion claim")),
        };
        self.origin.complete(result)
    }
}

/// Only genuine fixed-fork Signer origin can enter. It carries no account
/// password, path, authority flag or reconstructed role handle in its arguments.
pub fn run_coordinated_financial_signer_v1(origin: SignerOriginV1) -> ! {
    match actor_driver_result!(Initialization, origin.into_financial_workflow()) {
        Ok(origin) => Driver {
            origin,
            normal_close: None,
            state: State::AwaitingPeer,
            entry_opened_reported: false,
            owner_selection: None,
            pending_status_control:None, financial_setup:None, financial_entry_requested:false, financial_transport:None,
        }
        .run(),
        Err(_) => {
            #[cfg(wholepact_financial_rendered_host_semantic_ci)]
            wholepact_financial_coordinator_origin::financial_ci_flush_actor_diagnostics();
            std::process::exit(1)
        },
    }
}
