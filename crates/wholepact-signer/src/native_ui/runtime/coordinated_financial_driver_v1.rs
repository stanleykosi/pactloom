//! Original-S control owner, separate from every private opening worker.
//! This initial source route uses no Signer native window, legacy decision,
//! credential argv, role replay, or imported completed-V3 custody.
use super::coordinated_v3_delivery::{
    self as delivery, CoordinatedReadyToReceiveV1, CoordinatedReceiveReviewV1,
    CoordinatedReceivedBytesV1, CoordinatedVerifiedImportV1, PreparedCoordinatedDeliveryReviewV1,
};
use super::*;
use crate::account::birth::enrollment::roster_v2::durable_entry_v1::{
    CoordinatedEnrollmentReviewV1, CoordinatedManifestReviewV1,
    CoordinatedOriginalDeliverySourceV1, CoordinatedPreconstructionReadyV1,
    CoordinatedPreparingDeliverySourceV1, CoordinatedRediscloseV1, CoordinatedRedisclosedSourceV1,
    CoordinatedRedisclosureReadV1, CoordinatedSourcePairingV1, PreparedCoordinatedV3SourceEntryV1,
    PresentedCoordinatedV3SourceEntryV1,
};
use crate::authority_bridge::durable_review_ipc_v3::coordinated_v1::CoordinatedClosedCommandV1;
use crate::ipc::{
    CoordinatedLocalEventV1, CoordinatedPairPeerV1, CoordinatedRequestV1, PendingPairing,
};
use crate::native_peer::PeerProcess;
use wholepact_financial_coordinator_origin::{
    SignerFinancialWorkflowOriginV1, SignerFinancialWorkflowRequestV1 as Request, SignerOriginV1,
    SignerV3PairEndpointV1, SignerV3PairedV1,
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
    PreconstructionReady(CoordinatedPreconstructionReadyV1),
    RedisclosureRead(CoordinatedRedisclosureReadV1),
    Redisclose(CoordinatedRediscloseV1),
    RedisclosureWorking(RedisclosureWorking),
    Redisclosed(CoordinatedRedisclosedSourceV1),
    AwaitingOwner(CoordinatedPreparingDeliverySourceV1),
    DeliveryReadReview(PreparedCoordinatedDeliveryReviewV1),
    DeliveryReceiveReview(CoordinatedReceiveReviewV1),
    DeliveryReady(CoordinatedReadyToReceiveV1),
    DeliveryBytes(CoordinatedReceivedBytesV1),
    DeliveryVerified(CoordinatedVerifiedImportV1),
    DeliveryWorking(DeliveryWorking),
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
    state: State,
    entry_opened_reported: bool,
    owner_selection: Option<(String, String)>,
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
                RedisclosureOutcome::Exported(next) => {
                    self.state = State::Redisclosed(next);
                    let State::Redisclosed(next) = &self.state else {
                        return Err(Error::Unavailable);
                    };
                    self.origin.report_v3_redisclosed(next.report())?;
                }
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
        if matches!(&self.state,State::DeliveryWorking(job) if job.worker.as_ref().is_some_and(|w|w.is_finished()))
        {
            let State::DeliveryWorking(job) = std::mem::replace(&mut self.state, State::Taken)
            else {
                return Err(Error::Unavailable);
            };
            match job.join()? {
                DeliveryOutcome::Staged(source) => self.state = State::AwaitingOwner(source),
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
                DeliveryOutcome::Verified(verified) => {
                    self.state = State::DeliveryVerified(verified);
                    let State::DeliveryVerified(verified) = &self.state else {
                        return Err(Error::Unavailable);
                    };
                    self.origin.report_v3_received(verified.report())?;
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
            _ => (),
        }
        Ok(())
    }
    fn handle(&mut self, request: Request) -> Result<bool> {
        match request {
            Request::Cancel => return Ok(false),
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
                    .spawn(move || review.commit(final_action).map(ReceiptOutcome::Enrolled))?;
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
                        review
                            .commit(final_action)
                            .map(ReceiptOutcome::ManifestAccepted)
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
                self.origin.check_original_actors_alive()?;
                // Pump authenticated restriction before interpreting a worker's
                // result or offering another purpose. No Origin moves to worker.
                if let Some(request) = self.origin.try_receive()? {
                    if !self.handle(request)? {
                        return Ok(());
                    }
                }
                self.poll_opening()?;
                self.begin_pairing()?;
                self.poll_pairing()?;
                self.begin_enrollment()?;
                self.poll_receipts()?;
                self.poll_redisclosure()?;
                self.poll_delivery()?;
                if let State::Opened(source) = &self.state {
                    source.check_retained_restriction()?;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        })();
        if work.is_err() {
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
        let cleanup = std::mem::replace(&mut self.state, State::Taken).join_and_drop();
        let cleanup = cleanup.and_then(|()| {
            if cancelled_unreported_entry {
                self.origin.v3_source_entry_failed()?;
            }
            Ok(())
        });
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
    match origin.into_financial_workflow() {
        Ok(origin) => Driver {
            origin,
            state: State::AwaitingPeer,
            entry_opened_reported: false,
            owner_selection: None,
        }
        .run(),
        Err(_) => std::process::exit(1),
    }
}
