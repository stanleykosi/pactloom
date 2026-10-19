//! Version-distinct native intake and immediate manual review. The immutable
//! data may wait, but old permissions/wallet snapshots never do. Received bytes
//! stay memory-only; another process lifetime requires a fresh exact import.
use super::*;
use crate::account::birth::enrollment::roster_v2::durable_entry_v1::FreshDurableBornEntryV1;
use crate::authority_bridge::{
    durable_proposal_v1::{self as bridge, PreparedDurableProposalReview},
    durable_review_ipc_v1::{
        self as wire, DeliveryCommandV1, DeliveryResponseV1, DurableReviewDeliveryReceiptV1,
        DurableReviewDeliveryRequestV1, DurableReviewPayloadV1,
    },
    BridgeError,
};
use crate::native_ui::durable_proposal_v1::VerifiedDurableEconomicsV1;
use sha2::{Digest, Sha256};
use std::{
    os::unix::net::UnixStream,
    sync::mpsc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use wholepact_wallet::wallet::protected_sync::durable_construction_v1::DurableConstructionScopeV1;
fn bridge_error(_: impl std::fmt::Display) -> BridgeError {
    BridgeError::Permission
}
fn now() -> authority_bridge::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|_| BridgeError::Permission)
}

pub(super) struct ImportedDurableReviewV1 {
    pub(super) fixed: Arc<VerifiedDurableEconomicsV1>,
    pub(super) request: DurableReviewDeliveryRequestV1,
    source: Arc<FreshDurableBornEntryV1>,
    peer: AuthenticatedPeer,
    scopes: Vec<DurableConstructionScopeV1>,
}
impl ImportedDurableReviewV1 {
    fn material_time_current(&self) -> bool {
        now().is_ok_and(|time| {
            self.scopes.iter().all(|scope| {
                time >= scope.valid_from_unix_seconds && time < scope.valid_until_unix_seconds
            })
        })
    }
    fn check_data_source(&self) -> authority_bridge::Result<()> {
        self.check_data_source_inner(
            #[cfg(feature = "synthetic-born-joined-qualification")]
            None,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            flow_diag_v1::DurableFlowStageV1::ImportSource,
        )
    }
    fn check_data_source_inner(
        &self,
        #[cfg(feature = "synthetic-born-joined-qualification")] observer: Option<
            &flow_diag_v1::DurableFlowObserverV1,
        >,
        #[cfg(feature = "synthetic-born-joined-qualification")]
        stage: flow_diag_v1::DurableFlowStageV1,
    ) -> authority_bridge::Result<()> {
        // No recursive journal authority lock: financial preflight/held-lease
        // checks are performed separately by the specialized signer adapter.
        durable_flow_observe_v1!(observer, stage, self.source.check_original_source_current())
            .map_err(bridge_error)?;
        durable_flow_observe_v1!(observer, stage, self.peer.check_current())
            .map_err(bridge_error)?;
        for scope in &self.scopes {
            scope.check_valid_at(now()?).map_err(bridge_error)?;
        }
        Ok(())
    }
    fn proposal_source(self: &Arc<Self>) -> bridge::FixedProposalSource {
        self.proposal_source_inner(
            #[cfg(feature = "synthetic-born-joined-qualification")]
            None,
        )
    }
    fn proposal_source_inner(
        self: &Arc<Self>,
        #[cfg(feature = "synthetic-born-joined-qualification")] observer: Option<
            flow_diag_v1::DurableFlowObserverV1,
        >,
    ) -> bridge::FixedProposalSource {
        let retained = self.clone();
        Arc::new(move || {
            retained.check_data_source_inner(
                #[cfg(feature = "synthetic-born-joined-qualification")]
                observer.as_ref(),
                #[cfg(feature = "synthetic-born-joined-qualification")]
                flow_diag_v1::DurableFlowStageV1::AuthorizationSource,
            )?;
            Ok(retained.fixed.verified().clone())
        })
    }
}

/// Custody of the actual imported privacy source, not mathematical evidence or
/// a caller-supplied disclosure claim. Only the live OpenAccount can mint it.
pub(super) struct DurableWitnessImportedSourceV1 {
    imported: Arc<ImportedDurableReviewV1>,
    session: Arc<SignerConsentSession>,
}
impl OpenAccount {
    pub(super) fn durable_witness_source_v1(&self) -> Result<Arc<DurableWitnessImportedSourceV1>> {
        let pairing = self.check_pairing()?;
        let imported = self.durable_review.as_ref().ok_or(Error::ReviewMismatch)?;
        if !Arc::ptr_eq(
            &imported.source,
            self.durable_born_entry.as_ref().ok_or(Error::Unavailable)?,
        ) || self
            .enrollment
            .as_ref()
            .is_none_or(|e| e.reference() != imported.request.enrollment_ref)
            || self
                .manifest
                .as_ref()
                .is_none_or(|m| m.reference() != imported.request.accepted_manifest_ref)
        {
            return Err(Error::ReviewMismatch);
        }
        imported.peer.require_same_grant(&pairing.peer)?;
        let source = Arc::new(DurableWitnessImportedSourceV1 {
            imported: imported.clone(),
            session: self.session.clone().ok_or(Error::Locked)?,
        });
        source.check_current()?;
        Ok(source)
    }
}
impl DurableWitnessImportedSourceV1 {
    pub(super) fn check_current(&self) -> Result<()> {
        self.check_current_inner(
            #[cfg(feature = "synthetic-born-joined-qualification")]
            None,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            flow_diag_v1::DurableFlowStageV1::ImportSource,
        )
    }
    pub(super) fn check_current_inner(
        &self,
        #[cfg(feature = "synthetic-born-joined-qualification")] observer: Option<
            &flow_diag_v1::DurableFlowObserverV1,
        >,
        #[cfg(feature = "synthetic-born-joined-qualification")]
        stage: flow_diag_v1::DurableFlowStageV1,
    ) -> Result<()> {
        self.check_data_current_under_fence_inner(
            #[cfg(feature = "synthetic-born-joined-qualification")]
            observer,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            stage,
        )?;
        // Acquire this callback's actual fence BEFORE the complete snapshot.
        // Record acquisition alone does not check permanent-stop exclusion.
        // The fence is not global snapshot exclusion: other handles and
        // immutable append paths retain their existing semantics.
        let lease = durable_flow_observe_v1!(
            observer,
            stage,
            self.entry().journal().acquire_preconstruction_records(
                &self.imported.request.enrollment_ref,
                &self.imported.request.accepted_manifest_ref,
                &self.session,
            )
        )?;
        lease.require_native_origin(&self.entry().native_binding())?;
        self.entry()
            .check_current_under_preconstruction_lease(&lease)?;
        // Freshness of BOTH original receipts must follow the potentially
        // expensive full scan; a generic lease liveness check is insufficient.
        lease.require_current_durable_disclosure_receipts_v1()?;
        if lease.enrollment().account_id() != self.entry().account().account_id()?
            || lease.enrollment().participant_id() != self.imported.peer.scope.participant_id
            || lease.manifest().manifest_digest()
                != self.fixed().verified().identity().manifest_digest
            || lease.manifest().proposal_input() != self.fixed().proposal().input()
        {
            return Err(Error::ReviewMismatch);
        }
        let result = self.check_data_current_under_fence_inner(
            #[cfg(feature = "synthetic-born-joined-qualification")]
            observer,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            stage,
        );
        // No receipt/fence or prior successful check survives into TLS, native
        // waiting, a write transaction, or the next callback.
        drop(lease);
        result
    }
    /// Deny-only final gate. This method deliberately takes NO journal/session
    /// lock: callers already retain their real approval and journal write fence.
    pub(super) fn check_data_current_under_fence(&self) -> Result<()> {
        self.check_data_current_under_fence_inner(
            #[cfg(feature = "synthetic-born-joined-qualification")]
            None,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            flow_diag_v1::DurableFlowStageV1::ImportSource,
        )
    }
    pub(super) fn check_data_current_under_fence_inner(
        &self,
        #[cfg(feature = "synthetic-born-joined-qualification")] observer: Option<
            &flow_diag_v1::DurableFlowObserverV1,
        >,
        #[cfg(feature = "synthetic-born-joined-qualification")]
        stage: flow_diag_v1::DurableFlowStageV1,
    ) -> Result<()> {
        durable_flow_observe_v1!(
            observer,
            stage,
            self.imported.check_data_source_inner(
                #[cfg(feature = "synthetic-born-joined-qualification")]
                observer,
                #[cfg(feature = "synthetic-born-joined-qualification")]
                stage
            )
        )
        .map_err(|_| Error::ReviewMismatch)?;
        if self.imported.scopes.len() != 2
            || self
                .imported
                .scopes
                .iter()
                .any(|s| s.proposal != *self.fixed().proposal().input())
            || self.imported.peer.native_origin != self.entry().native_binding()
            || Instant::now() >= self.deadline()?
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(super) fn deadline(&self) -> Result<Instant> {
        Ok(self
            .imported
            .peer
            .deadline()
            .min(self.entry().native_binding().bounded_deadline()?))
    }
    pub(super) fn fixed(&self) -> &VerifiedDurableEconomicsV1 {
        &self.imported.fixed
    }
    pub(super) fn entry(&self) -> &FreshDurableBornEntryV1 {
        &self.imported.source
    }
    pub(super) fn session(&self) -> &SignerConsentSession {
        &self.session
    }
    pub(super) fn enrollment_ref(&self) -> &str {
        &self.imported.request.enrollment_ref
    }
    pub(super) fn manifest_ref(&self) -> &str {
        &self.imported.request.accepted_manifest_ref
    }
}
#[cfg(feature = "synthetic-born-joined-qualification")]
fn flow_fingerprint_v1<T: serde::Serialize>(domain: &[u8], value: &T) -> Option<[u8; 32]> {
    // Only fixed hashes survive. The sink is bounded by the existing durable
    // wire payload ceiling and performs no filesystem/network IO or validation.
    struct Sink {
        hash: Sha256,
        bytes: usize,
    }
    impl std::io::Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let count = self
                .bytes
                .checked_add(bytes.len())
                .filter(|count| *count <= wire::MAX_DURABLE_REVIEW_PAYLOAD_BYTES_V1)
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
            self.hash.update(bytes);
            self.bytes = count;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut sink = Sink {
        hash: Sha256::new(),
        bytes: 0,
    };
    sink.hash.update(domain);
    serde_json::to_writer(&mut sink, value).ok()?;
    Some(sink.hash.finalize().into())
}
#[cfg(feature = "synthetic-born-joined-qualification")]
#[derive(Clone)]
pub(super) struct DurableFlowImportExpectationV1 {
    request: [u8; 32],
    identity: [u8; 32],
    epoch: u64,
    observer: flow_diag_v1::DurableFlowObserverV1,
}
#[cfg(feature = "synthetic-born-joined-qualification")]
struct DurableFlowImportBoundV1 {
    identity: [u8; 32],
    observer: flow_diag_v1::DurableFlowObserverV1,
    job: flow_diag_v1::DurableFlowJobObservationV1,
}
#[cfg(feature = "synthetic-born-joined-qualification")]
impl DurableFlowImportExpectationV1 {
    pub(super) fn new(
        request: &DurableReviewDeliveryRequestV1,
        identity: &wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1,
        epoch: u64,
        observer: &flow_diag_v1::DurableFlowObserverV1,
    ) -> Option<Self> {
        let request = flow_fingerprint_v1(b"durable-flow-request-v1\0", request);
        let identity = flow_fingerprint_v1(b"durable-flow-identity-v1\0", identity);
        match (request, identity) {
            (Some(request), Some(identity)) => Some(Self {
                request,
                identity,
                epoch,
                observer: observer.clone(),
            }),
            _ => {
                observer.mark_incomplete();
                None
            }
        }
    }
    pub(super) fn matches_poll(
        &self,
        request: &DurableReviewDeliveryRequestV1,
        identity: &wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1,
        epoch: u64,
    ) -> bool {
        self.epoch == epoch
            && flow_fingerprint_v1(b"durable-flow-request-v1\0", request) == Some(self.request)
            && flow_fingerprint_v1(b"durable-flow-identity-v1\0", identity) == Some(self.identity)
    }
    fn bind(
        self,
        request: &DurableReviewDeliveryRequestV1,
        epoch: u64,
    ) -> Option<DurableFlowImportBoundV1> {
        if self.epoch != epoch
            || flow_fingerprint_v1(b"durable-flow-request-v1\0", request) != Some(self.request)
        {
            self.observer.mark_incomplete();
            return None;
        }
        let job = self
            .observer
            .job_start(flow_diag_v1::DurableFlowJobPurposeV1::Import, epoch);
        Some(DurableFlowImportBoundV1 {
            identity: self.identity,
            observer: self.observer,
            job,
        })
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum DurableImportDispositionV1 {
    Invalidated,
    Rejected,
    Accepted,
}
// This is the actual poller's decision kernel, borrowing the original Result.
// Caller ownership and result/job drop order remain where they originally were.
fn durable_import_disposition_v1<T>(
    result: &authority_bridge::Result<T>,
    received: bool,
    epoch_matches: bool,
    pairing: impl FnOnce() -> Result<()>,
    source: impl FnOnce(&T) -> authority_bridge::Result<()>,
    #[cfg(feature = "synthetic-born-joined-qualification")] observation: Option<
        &flow_diag_v1::DurableFlowJobObservationV1,
    >,
    #[cfg(feature = "synthetic-born-joined-qualification")] observer: Option<
        &flow_diag_v1::DurableFlowObserverV1,
    >,
) -> DurableImportDispositionV1 {
    #[cfg(feature = "synthetic-born-joined-qualification")]
    if received {
        if let Some(job) = observation {
            job.received(flow_diag_v1::DurableFlowStageV1::ImportReceive, result);
        }
    }
    #[cfg(not(feature = "synthetic-born-joined-qualification"))]
    let _ = received;
    if !epoch_matches
        || durable_flow_observe_v1!(
            observer,
            flow_diag_v1::DurableFlowStageV1::ImportPairing,
            pairing()
        )
        .is_err()
    {
        #[cfg(feature = "synthetic-born-joined-qualification")]
        if let Some(job) = observation {
            job.invalidated();
            job.presentation(flow_diag_v1::DurableFlowPresentationV1::Suppressed);
        }
        return DurableImportDispositionV1::Invalidated;
    }
    let accepted = match result {
        Ok(value) => durable_flow_observe_v1!(
            observer,
            flow_diag_v1::DurableFlowStageV1::ImportSource,
            source(value)
        )
        .is_ok(),
        Err(_) => false,
    };
    #[cfg(feature = "synthetic-born-joined-qualification")]
    if received {
        if let Some(job) = observation {
            job.presentation(if accepted {
                flow_diag_v1::DurableFlowPresentationV1::Accepted
            } else {
                flow_diag_v1::DurableFlowPresentationV1::Suppressed
            });
        }
    }
    if accepted {
        DurableImportDispositionV1::Accepted
    } else {
        DurableImportDispositionV1::Rejected
    }
}

pub(super) struct DurableImportJobV1 {
    #[cfg(feature = "synthetic-born-joined-qualification")]
    flow: Option<DurableFlowImportBoundV1>,
    receive: mpsc::Receiver<authority_bridge::Result<ImportedDurableReviewV1>>,
    epoch: u64,
}
pub(super) struct DurableWalletJobV1 {
    #[cfg(feature = "synthetic-born-joined-qualification")]
    flow: Option<(
        flow_diag_v1::DurableFlowJobObservationV1,
        flow_diag_v1::DurableFlowObserverV1,
    )>,
    receive: mpsc::Receiver<(
        NativeWalletWorkspace,
        Result<(
            crate::manifest::ReviewInputs,
            wholepact_authority::AuthorityHead,
        )>,
    )>,
    done: Arc<AtomicBool>,
    revoke: NativeWalletRevocation,
    epoch: u64,
    imported: Arc<ImportedDurableReviewV1>,
}
pub(super) struct DurableSpendFlowV1 {
    #[cfg(feature = "synthetic-born-joined-qualification")]
    flow_epoch: u64,
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) flow_observer: Option<flow_diag_v1::DurableFlowObserverV1>,
    prepared: PreparedDurableProposalReview,
    head: wholepact_authority::AuthorityHead,
    imported: Arc<ImportedDurableReviewV1>,
}

// Qualification observes the exact production-prepared review. It cannot
// extract a decision, continuation, wallet ticket or source capability.
#[cfg(feature = "synthetic-born-joined-qualification")]
impl DurableSpendFlowV1 {
    pub(super) fn qualification_identity(
        &self,
    ) -> &wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1 {
        self.prepared.identity()
    }
    pub(super) fn qualification_history(&self) -> authority_bridge::ipc::HistoryRequest {
        let consent = self.prepared.prepared_spend().record();
        authority_bridge::ipc::HistoryRequest {
            authorization_id: consent.terms().authorization_id.clone(),
            expected_original_consent_ref: consent.reference().into(),
            expected_enrollment_ref: consent.terms().enrollment_ref.clone(),
            expected_manifest_ref: consent.terms().accepted_manifest_ref.clone(),
        }
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
impl NativeRuntime {
    /// Metadata only, through the same actual source and maintained retained
    /// result reader as the production retry path. Missing committed output is
    /// still recovery-required; this never exports or regenerates signatures.
    pub(super) fn qualification_retained_durable_result_v1(
        &self,
        expected: &wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1,
    ) -> Result<
        Option<(
            authority_bridge::ipc::HistoryRequest,
            authority_bridge::AuthorizationCommit,
        )>,
    > {
        let open = self.open.as_ref().ok_or(Error::Locked)?;
        open.check_pairing()?;
        let imported = open.durable_review.as_ref().ok_or(Error::ReviewMismatch)?;
        imported
            .check_data_source()
            .map_err(|_| Error::ReviewMismatch)?;
        if imported.fixed.verified().identity() != expected
            || !Arc::ptr_eq(
                open.durable_born_entry.as_ref().ok_or(Error::Unavailable)?,
                &imported.source,
            )
        {
            return Err(Error::ReviewMismatch);
        }
        let session = open.session.as_ref().ok_or(Error::Locked)?;
        let Some(commit) = bridge::retained_manual_commit_diagnosed(
            &imported.proposal_source(),
            &open.journal,
            session,
            open.vault.account(),
            open.durable_witness.flow_observation.as_ref(),
        )
        .map_err(|_| Error::RecoveryRequired)?
        else {
            return Ok(None);
        };
        // The previous reader has dropped its journal lease before this read.
        let original = open
            .journal
            .original_authorization(&commit.authorization_id, session)?
            .ok_or(Error::RecoveryRequired)?;
        if original.original_consent().reference() != commit.original_consent_ref {
            return Err(Error::ReviewMismatch);
        }
        let history = authority_bridge::ipc::HistoryRequest {
            authorization_id: commit.authorization_id.clone(),
            expected_original_consent_ref: original.original_consent().reference().into(),
            expected_enrollment_ref: original.enrollment().reference().into(),
            expected_manifest_ref: original.accepted_manifest().reference().into(),
        };
        Ok(Some((history, commit)))
    }
}

fn receive_durable(
    mut stream: UnixStream,
    peer: AuthenticatedPeer,
    request: DurableReviewDeliveryRequestV1,
    source: Arc<FreshDurableBornEntryV1>,
    session: Arc<SignerConsentSession>,
    #[cfg(feature = "synthetic-born-joined-qualification")] observer: Option<
        &flow_diag_v1::DurableFlowObserverV1,
    >,
) -> authority_bridge::Result<ImportedDurableReviewV1> {
    let deadline = Instant::now() + Duration::from_secs(120);
    request.validate()?;
    durable_flow_observe_v1!(
        observer,
        flow_diag_v1::DurableFlowStageV1::ImportSource,
        source.check_current()
    )
    .map_err(bridge_error)?;
    let journal = source.journal();
    let original = journal.durable_construction_history_v1(&request.own_disclosure, &session)?;
    if original.redisclosure().is_some() {
        return Err(BridgeError::Binding);
    }
    let current = if let Some(current) = &request.current_disclosure {
        let renewed = journal.durable_construction_history_v1(current, &session)?;
        renewed.validate_redisclosure_of(&original)?;
        renewed
    } else {
        original.clone()
    };
    if !authority_bridge::ipc::exact_local_recipient(current.recipient_transport(), &peer)
        || !peer.scope.history_read
        || !peer.scope.preconstruction_export
        || peer.native_origin != source.native_binding()
    {
        return Err(BridgeError::Permission);
    }
    original
        .request()
        .material
        .verify_owner(&source.account().fvk().map_err(bridge_error)?)
        .map_err(bridge_error)?;
    let lease = journal.acquire_preconstruction_records(
        &request.enrollment_ref,
        &request.accepted_manifest_ref,
        &session,
    )?;
    lease.require_native_origin(&source.native_binding())?;
    let proposal = Proposal::validate(lease.manifest().proposal_input().clone())
        .map_err(|_| BridgeError::Binding)?;
    let account_id = source.account().account_id().map_err(bridge_error)?;
    let original_scope = &original.request().scope;
    let born_scope = &source.record().account_record.terms.scope;
    if lease.enrollment().account_id() != account_id
        || lease.enrollment().participant_id() != peer.scope.participant_id
        || lease.enrollment().agreement_id() != peer.scope.agreement_id
        || lease.manifest().manifest_digest() != peer.scope.manifest_digest
        || original_scope.proposal != *proposal.input()
        || original_scope.account_id != account_id
        || proposal.manifest().agreement.agreement_id != born_scope.agreement_id
        || proposal.manifest().agreement.obligation_id != born_scope.obligation_id
        || !original_scope
            .permits_local_reviewer_account(&account_id)
            .map_err(bridge_error)?
    {
        return Err(BridgeError::Binding);
    }
    let check = || -> authority_bridge::Result<()> {
        if Instant::now() >= deadline {
            return Err(BridgeError::Permission);
        }
        source
            .check_original_source_current()
            .map_err(bridge_error)?;
        durable_flow_observe_v1!(
            observer,
            flow_diag_v1::DurableFlowStageV1::ImportSource,
            peer.check_current()
        )
        .map_err(bridge_error)?;
        lease.require_native_origin(&source.native_binding())?;
        lease.check_current()?;
        original_scope
            .check_valid_at(now()?)
            .map_err(bridge_error)?;
        Ok(())
    };
    let request_digest = request.digest()?;
    wire::bounded_write(
        &mut stream,
        &DeliveryResponseV1::Ready {
            request_digest: request_digest.clone(),
            account_id: account_id.clone(),
            participant_id: peer.scope.participant_id.clone(),
            agreement_id: peer.scope.agreement_id.clone(),
            manifest_digest: peer.scope.manifest_digest.clone(),
            local_grant_id: peer.grant_id.clone(),
            local_channel_digest: peer.channel_digest.clone(),
        },
        deadline,
        &check,
    )?;
    let mut bytes = Zeroizing::new(Vec::new());
    let mut expected: Option<(String, usize)> = None;
    loop {
        check()?;
        // Waiting for the engine's independently verified export intent is not
        // a new permission window. Preserve the original absolute deadline and
        // partial frame while polling actual revocation/scope every 100 ms.
        let frame = wholepact_signer_origin::framing::read_frame_capped_checked_until(
            &stream,
            &peer.peer,
            128 * 1024,
            deadline,
            || check().map_err(|_| wholepact_signer_origin::Error::Permission),
        )
        .map_err(|_| BridgeError::Ipc)?;
        check()?;
        let command: DeliveryCommandV1 =
            wholepact_core::parse_typed_json(&frame).map_err(|_| BridgeError::Binding)?;
        match &command {
            DeliveryCommandV1::CheckCurrent if expected.is_none() => {
                wire::bounded_write(
                    &mut stream,
                    &DeliveryResponseV1::Current {
                        request_digest: request_digest.clone(),
                    },
                    deadline,
                    &check,
                )?;
            }
            DeliveryCommandV1::Begin {
                payload_digest,
                payload_bytes,
            } if expected.is_none() => {
                if payload_digest.len() != 64
                    || !payload_digest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(BridgeError::Binding);
                }
                let size = usize::try_from(*payload_bytes).map_err(|_| BridgeError::Limit)?;
                if size == 0 || size > wire::MAX_PAYLOAD {
                    return Err(BridgeError::Limit);
                }
                bytes.reserve(size);
                expected = Some((payload_digest.clone(), size));
                wire::bounded_write(
                    &mut stream,
                    &DeliveryResponseV1::Receiving { received_bytes: 0 },
                    deadline,
                    &check,
                )?;
            }
            DeliveryCommandV1::Chunk { offset, data_hex } => {
                let (_, size) = expected.as_ref().ok_or(BridgeError::Binding)?;
                if *offset != bytes.len() as u64
                    || data_hex.is_empty()
                    || data_hex.len() > wire::CHUNK_BYTES * 2
                    || data_hex.len() % 2 != 0
                    || !data_hex
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(BridgeError::Binding);
                }
                let chunk =
                    Zeroizing::new(hex::decode(data_hex).map_err(|_| BridgeError::Binding)?);
                if bytes
                    .len()
                    .checked_add(chunk.len())
                    .is_none_or(|n| n > *size)
                {
                    return Err(BridgeError::Limit);
                }
                bytes.extend_from_slice(&chunk);
                wire::bounded_write(
                    &mut stream,
                    &DeliveryResponseV1::Receiving {
                        received_bytes: bytes.len() as u64,
                    },
                    deadline,
                    &check,
                )?;
            }
            DeliveryCommandV1::Finish => break,
            _ => return Err(BridgeError::Binding),
        }
    }
    let (digest, size) = expected.ok_or(BridgeError::Binding)?;
    if bytes.len() != size || hex::encode(Sha256::digest(bytes.as_slice())) != digest {
        return Err(BridgeError::Binding);
    }
    let payload: DurableReviewPayloadV1 =
        wholepact_core::strict_json::parse_typed_json_with_byte_limit(&bytes, wire::MAX_PAYLOAD)
            .map_err(|_| BridgeError::Binding)?;
    if payload.encode()?.as_slice() != bytes.as_slice() {
        return Err(BridgeError::Binding);
    }
    let own = payload
        .contributions
        .iter()
        .find(|c| c.request().scope.account_id == account_id)
        .ok_or(BridgeError::Binding)?;
    if own != &original {
        return Err(BridgeError::Binding);
    }
    for contribution in &payload.contributions {
        contribution
            .request()
            .scope
            .check_valid_at(now()?)
            .map_err(bridge_error)?;
    }
    let unsigned =
        Zeroizing::new(hex::decode(&payload.unsigned_pczt_hex).map_err(|_| BridgeError::Binding)?);
    let proved =
        Zeroizing::new(hex::decode(&payload.proved_pczt_hex).map_err(|_| BridgeError::Binding)?);
    check()?;
    let fixed = VerifiedDurableEconomicsV1::verify(
        &proposal,
        &unsigned,
        &proved,
        &payload.contributions,
        &account_id,
        payload
            .output_actions
            .iter()
            .map(|m| wholepact_protocol::construction::OutputActionMapping {
                output_id: m.output_id.clone(),
                action_index: m.action_index,
            })
            .collect(),
        wholepact_protocol::proving::ProvingLimits { maximum_actions: 8 },
    )
    .map_err(|_| BridgeError::Binding)?;
    if fixed.verified().identity().proposal_binding != request.proposal_binding {
        return Err(BridgeError::Binding);
    }
    check()?;
    let imported = ImportedDurableReviewV1 {
        fixed: Arc::new(fixed),
        request,
        source: source.clone(),
        peer: peer.clone(),
        scopes: payload
            .contributions
            .iter()
            .map(|c| c.request().scope.clone())
            .collect(),
    };
    imported.check_data_source_inner(
        #[cfg(feature = "synthetic-born-joined-qualification")]
        observer,
        #[cfg(feature = "synthetic-born-joined-qualification")]
        flow_diag_v1::DurableFlowStageV1::ImportSource,
    )?;
    wire::bounded_write(
        &mut stream,
        &DeliveryResponseV1::Imported {
            receipt: DurableReviewDeliveryReceiptV1 {
                version: 1,
                recipient_request_digest: request_digest,
                payload_digest: digest,
                payload_bytes: size as u64,
                state: "imported_for_review".into(),
            },
        },
        deadline,
        &check,
    )?;
    drop(lease);
    Ok(imported)
}

impl OpenAccount {
    pub(super) fn clear_durable_review_v1(&mut self) {
        // The retry wrappers retain the same private imported evidence. Drop
        // that custody on EVERY clear path while preserving inert admission
        // correlation and the independent actual writer client's session key.
        self.durable_witness.discard_import_custody();
        self.durable_review = None;
        #[cfg(feature = "synthetic-born-joined-qualification")]
        if let Some(flow) = self
            .durable_import_job
            .as_ref()
            .and_then(|job| job.flow.as_ref())
        {
            flow.job.invalidated();
        }
        self.durable_import_job = None;
        if let Some(job) = self.durable_wallet_job.take() {
            #[cfg(feature = "synthetic-born-joined-qualification")]
            if let Some((flow, _)) = &job.flow {
                flow.invalidated();
            }
            job.revoke.revoke();
            self.revocations.push(job.done);
        }
    }
}
impl NativeRuntime {
    pub(super) fn poll_durable_material_lifetime_v1(&mut self) {
        let material_expired = self.open.as_ref().is_some_and(|open| {
            open.durable_review
                .as_ref()
                .is_some_and(|review| !review.material_time_current())
                || open
                    .durable_wallet_job
                    .as_ref()
                    .is_some_and(|job| !job.imported.material_time_current())
        }) || self.pending.as_ref().is_some_and(|pending| {
            match &pending.operation {
                Operation::DurableDisclosureV1 { flow, .. }
                | Operation::DurableSpendV1 { flow, .. } => !flow.imported.material_time_current(),
                Operation::DurableWitnessV1(prepared) => !prepared.source_current(),
                _ => false,
            }
        });
        if !material_expired {
            return;
        }
        if let Some(open) = self.open.as_mut() {
            open.clear_durable_review_v1();
        }
        if self.pending.as_ref().is_some_and(|pending| {
            matches!(
                pending.operation,
                Operation::DurableDisclosureV1 { .. }
                    | Operation::DurableSpendV1 { .. }
                    | Operation::DurableWitnessV1(_)
            )
        }) {
            self.pending = None;
            self.confirmation.zeroize();
        }
        // Only unusable private memory and derived work are discarded. The
        // original outboxes, release intents, reservations and source remain.
        self.message = "The original material-use window ended. Imported private review data and derived pending review were discarded; retained history and financial exposure were not changed.";
    }
    pub(super) fn start_durable_import_v1(
        &mut self,
        stream: UnixStream,
        peer: AuthenticatedPeer,
        request: DurableReviewDeliveryRequestV1,
        epoch: u64,
    ) -> Result<()> {
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let observer = self
            .open
            .as_ref()
            .and_then(|open| open.durable_witness.flow_import.as_ref())
            .and_then(|expected| {
                if expected.epoch == epoch
                    && flow_fingerprint_v1(b"durable-flow-request-v1\0", &request)
                        == Some(expected.request)
                {
                    Some(expected.observer.clone())
                } else {
                    expected.observer.mark_incomplete();
                    None
                }
            });
        let result = self.start_durable_import_inner_v1(stream, peer, request, epoch);
        durable_flow_observe_v1!(
            observer.as_ref(),
            flow_diag_v1::DurableFlowStageV1::ImportReceive,
            result
        )
    }
    fn start_durable_import_inner_v1(
        &mut self,
        stream: UnixStream,
        peer: AuthenticatedPeer,
        request: DurableReviewDeliveryRequestV1,
        epoch: u64,
    ) -> Result<()> {
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        open.check_pairing()?;
        if self.pending.is_some()
            || open.durable_import_job.is_some()
            || open.durable_wallet_job.is_some()
            || open.wallet_job.is_some()
            || open.witness_job.is_some()
            || open.history_workers.len() >= 8
            || open
                .pairing
                .as_ref()
                .is_none_or(|p| p.peer.grant_id != peer.grant_id)
            || open
                .enrollment
                .as_ref()
                .is_none_or(|e| e.reference() != request.enrollment_ref)
            || open
                .manifest
                .as_ref()
                .is_none_or(|m| m.reference() != request.accepted_manifest_ref)
        {
            return Err(Error::ReviewMismatch);
        }
        let source = open.durable_born_entry.clone().ok_or(Error::Unavailable)?;
        let session = open.session.clone().ok_or(Error::Locked)?;
        let (send, receive) = mpsc::channel();
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let flow = open
            .durable_witness
            .flow_import
            .take()
            .and_then(|expected| expected.bind(&request, epoch));
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let worker_observer = flow.as_ref().map(|flow| flow.observer.clone());
        let worker = std::thread::spawn(move || {
            let result = durable_flow_observe_v1!(
                worker_observer.as_ref(),
                flow_diag_v1::DurableFlowStageV1::ImportReceive,
                receive_durable(
                    stream,
                    peer,
                    request,
                    source,
                    session,
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    worker_observer.as_ref()
                )
            );
            let _ = send.send(result);
        });
        open.history_workers.push(worker);
        open.durable_review = None;
        open.durable_import_job = Some(DurableImportJobV1 {
            receive,
            epoch,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            flow,
        });
        self.message = "Receiving only the exact authorized fixed proposal into private memory. Full all-account verification is required; this request grants no approval or signature.";
        Ok(())
    }
    pub(super) fn poll_durable_import_v1(&mut self, epoch: u64) {
        let Some(open) = self.open.as_mut() else {
            return;
        };
        let Some(job) = open.durable_import_job.as_ref() else {
            return;
        };
        let (result, received) = match durable_flow_try_receive_v1(
            &job.receive,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            job.flow.as_ref().map(|flow| &flow.job),
        ) {
            Ok(v) => (v, true),
            Err(mpsc::TryRecvError::Empty) => {
                return;
            }
            Err(_) => (Err(BridgeError::Ipc), false),
        };
        let job = open.durable_import_job.take().expect("checked import job");
        let disposition = durable_import_disposition_v1(
            &result,
            received,
            job.epoch == epoch,
            || open.check_pairing().map(|_| ()),
            |imported| {
                #[cfg(feature = "synthetic-born-joined-qualification")]
                if let Some(flow) = &job.flow {
                    if flow_fingerprint_v1(
                        b"durable-flow-identity-v1\0",
                        imported.fixed.verified().identity(),
                    ) != Some(flow.identity)
                    {
                        flow.observer.mark_incomplete();
                    }
                }
                imported.check_data_source_inner(
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    job.flow.as_ref().map(|flow| &flow.observer),
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    flow_diag_v1::DurableFlowStageV1::ImportSource,
                )
            },
            #[cfg(feature = "synthetic-born-joined-qualification")]
            job.flow.as_ref().map(|flow| &flow.job),
            #[cfg(feature = "synthetic-born-joined-qualification")]
            job.flow.as_ref().map(|flow| &flow.observer),
        );
        if disposition == DurableImportDispositionV1::Invalidated {
            return;
        }
        match result {
            Ok(imported) if disposition == DurableImportDispositionV1::Accepted => {
                open.durable_review = Some(Arc::new(imported));
                self.message = "Exact fixed proof and full two-account economics verified in private memory. Canonical accounts are not named people or prior peer approvals. Fresh wallet, witness and native spend decisions are still required.";
            }
            _ => {
                self.message = "Fixed proposal intake failed, expired or changed. No arbitrary forwarded data, old approval or signing permission was accepted.";
            }
        }
    }
}

fn durable_wallet_completion_allowed_v1<T>(
    result: &Result<T>,
    epoch_matches: bool,
    pairing: impl FnOnce() -> Result<()>,
    #[cfg(feature = "synthetic-born-joined-qualification")] job: Option<
        &flow_diag_v1::DurableFlowJobObservationV1,
    >,
    #[cfg(feature = "synthetic-born-joined-qualification")] observer: Option<
        &flow_diag_v1::DurableFlowObserverV1,
    >,
) -> bool {
    #[cfg(feature = "synthetic-born-joined-qualification")]
    if let Some(job) = job {
        job.received(flow_diag_v1::DurableFlowStageV1::WalletSync, result);
    }
    #[cfg(not(feature = "synthetic-born-joined-qualification"))]
    let _ = result;
    if !epoch_matches
        || durable_flow_observe_v1!(
            observer,
            flow_diag_v1::DurableFlowStageV1::WalletSource,
            pairing()
        )
        .is_err()
    {
        #[cfg(feature = "synthetic-born-joined-qualification")]
        if let Some(job) = job {
            job.invalidated();
            job.presentation(flow_diag_v1::DurableFlowPresentationV1::Suppressed);
        }
        false
    } else {
        true
    }
}

impl NativeRuntime {
    pub(super) fn start_durable_wallet_review_v1(&mut self, epoch: u64) -> Result<()> {
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let observer = self
            .open
            .as_ref()
            .and_then(|open| open.durable_witness.flow_observation.clone());
        let result = self.start_durable_wallet_review_inner_v1(
            epoch,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            observer.as_ref(),
        );
        durable_flow_observe_v1!(
            observer.as_ref(),
            flow_diag_v1::DurableFlowStageV1::WalletSync,
            result
        )
    }
    fn start_durable_wallet_review_inner_v1(
        &mut self,
        epoch: u64,
        #[cfg(feature = "synthetic-born-joined-qualification")] observer: Option<
            &flow_diag_v1::DurableFlowObserverV1,
        >,
    ) -> Result<()> {
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        open.check_pairing()?;
        if !open.writer_reconciled
            || self.pending.is_some()
            || open.durable_wallet_job.is_some()
            || open.durable_import_job.is_some()
            || open.wallet_job.is_some()
            || open.witness_job.is_some()
        {
            return Err(Error::Locked);
        }
        let imported = open.durable_review.clone().ok_or(Error::ReviewMismatch)?;
        imported
            .check_data_source_inner(
                #[cfg(feature = "synthetic-born-joined-qualification")]
                observer,
                #[cfg(feature = "synthetic-born-joined-qualification")]
                flow_diag_v1::DurableFlowStageV1::WalletSource,
            )
            .map_err(|_| Error::ReviewMismatch)?;
        let session = open.session.as_ref().ok_or(Error::Locked)?;
        if open
            .enrollment
            .as_ref()
            .is_none_or(|e| e.reference() != imported.request.enrollment_ref)
            || open
                .manifest
                .as_ref()
                .is_none_or(|m| m.reference() != imported.request.accepted_manifest_ref)
            || !Arc::ptr_eq(
                open.durable_born_entry.as_ref().ok_or(Error::Unavailable)?,
                &imported.source,
            )
        {
            return Err(Error::ReviewMismatch);
        }
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let retained = bridge::retained_manual_commit_diagnosed(
            &imported.proposal_source_inner(observer.cloned()),
            &open.journal,
            session,
            open.vault.account(),
            observer,
        );
        #[cfg(not(feature = "synthetic-born-joined-qualification"))]
        let retained = bridge::retained_manual_commit(
            &imported.proposal_source(),
            &open.journal,
            session,
            open.vault.account(),
        );
        match retained.map_err(|_| Error::RecoveryRequired)? {
            Some(receipt) => {
                self.last_receipt = Some(receipt.original_consent_ref);
                self.message = "Exact original signature result already retained. Use original authenticated retrieval or a separately approved redelivery; no new wallet selection, reservation or key use was started.";
                return Ok(());
            }
            None => {}
        }
        let witness = open.witness.clone().ok_or(Error::Locked)?;
        witness.check_current()?;
        if witness.client().disclosure_descriptor()
            != imported.source.original_witness_disclosure()?
        {
            return Err(Error::Authentication);
        }
        let mut wallet = open.wallet.take().ok_or(Error::Locked)?;
        let revoke = wallet.revoke_handle();
        let done = Arc::new(AtomicBool::new(false));
        let finished = done.clone();
        let (send, receive) = mpsc::channel();
        let worker_imported = imported.clone();
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let flow = observer.map(|observer| {
            (
                observer.job_start(flow_diag_v1::DurableFlowJobPurposeV1::WalletReview, epoch),
                observer.clone(),
            )
        });
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let worker_observer = observer.cloned();
        std::thread::spawn(move || {
            let _done = WorkerCompletion(finished);
            let result = (|| {
                worker_imported
                    .check_data_source_inner(
                        #[cfg(feature = "synthetic-born-joined-qualification")]
                        worker_observer.as_ref(),
                        #[cfg(feature = "synthetic-born-joined-qualification")]
                        flow_diag_v1::DurableFlowStageV1::WalletSource,
                    )
                    .map_err(|_| Error::ReviewMismatch)?;
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| Error::Unavailable)?;
                let inputs = durable_flow_observe_v1!(
                    worker_observer.as_ref(),
                    flow_diag_v1::DurableFlowStageV1::WalletSync,
                    runtime.block_on(wallet.synchronize_durable_review_v1(
                        &worker_imported.fixed,
                        &worker_imported.source,
                        &worker_imported.peer,
                    ))
                )?;
                durable_flow_observe_v1!(
                    worker_observer.as_ref(),
                    flow_diag_v1::DurableFlowStageV1::WalletSource,
                    wallet.check_current()
                )?;
                worker_imported
                    .check_data_source_inner(
                        #[cfg(feature = "synthetic-born-joined-qualification")]
                        worker_observer.as_ref(),
                        #[cfg(feature = "synthetic-born-joined-qualification")]
                        flow_diag_v1::DurableFlowStageV1::WalletSource,
                    )
                    .map_err(|_| Error::ReviewMismatch)?;
                let head = durable_flow_observe_v1!(
                    worker_observer.as_ref(),
                    flow_diag_v1::DurableFlowStageV1::WitnessHead,
                    witness.snapshot_head()
                )?;
                worker_imported
                    .check_data_source_inner(
                        #[cfg(feature = "synthetic-born-joined-qualification")]
                        worker_observer.as_ref(),
                        #[cfg(feature = "synthetic-born-joined-qualification")]
                        flow_diag_v1::DurableFlowStageV1::WalletSource,
                    )
                    .map_err(|_| Error::ReviewMismatch)?;
                Ok((inputs, head))
            })();
            let result = durable_flow_observe_v1!(
                worker_observer.as_ref(),
                flow_diag_v1::DurableFlowStageV1::WalletSync,
                result
            );
            let _ = send.send((wallet, result));
        });
        open.durable_wallet_job = Some(DurableWalletJobV1 {
            #[cfg(feature = "synthetic-born-joined-qualification")]
            flow,
            receive,
            done,
            revoke,
            epoch,
            imported,
        });
        self.message = "Checking the original fixed inputs at the same anchor with a fresh wallet snapshot and independent witness. No input is reselected and no proof is replaced.";
        Ok(())
    }
    pub(super) fn poll_durable_wallet_review_v1(&mut self, epoch: u64) {
        let Some(open) = self.open.as_mut() else {
            return;
        };
        let Some(job) = open.durable_wallet_job.as_ref() else {
            return;
        };
        let (wallet, result) = match durable_flow_try_receive_v1(
            &job.receive,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            job.flow.as_ref().map(|(flow, _)| flow),
        ) {
            Ok(value) => value,
            Err(mpsc::TryRecvError::Empty) => {
                return;
            }
            Err(_) => {
                open.durable_wallet_job = None;
                self.message = "Exact durable wallet worker stopped; no approval was created.";
                return;
            }
        };
        let job = open.durable_wallet_job.take().expect("checked wallet job");
        open.wallet = Some(wallet);
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let observer = job.flow.as_ref().map(|(_, observer)| observer.clone());
        if !durable_wallet_completion_allowed_v1(
            &result,
            job.epoch == epoch,
            || open.check_pairing().map(|_| ()),
            #[cfg(feature = "synthetic-born-joined-qualification")]
            job.flow.as_ref().map(|(flow, _)| flow),
            #[cfg(feature = "synthetic-born-joined-qualification")]
            observer.as_ref(),
        ) {
            job.revoke.revoke();
            return;
        }
        let result = result.and_then(|(inputs, head)| {
            self.stage_durable_spend_inner_v1(
                job.imported,
                inputs,
                head,
                epoch,
                #[cfg(feature = "synthetic-born-joined-qualification")]
                observer.as_ref(),
            )
        });
        let result = durable_flow_observe_v1!(
            observer.as_ref(),
            flow_diag_v1::DurableFlowStageV1::SpendStage,
            result
        );
        #[cfg(feature = "synthetic-born-joined-qualification")]
        if let Some((flow, _)) = &job.flow {
            flow.presentation(if result.is_ok() {
                flow_diag_v1::DurableFlowPresentationV1::Accepted
            } else {
                flow_diag_v1::DurableFlowPresentationV1::Suppressed
            });
        }
        if result.is_err() {
            self.message = "Fresh fixed-proposal checks failed or expired. Original data and existing exposure are preserved; no substitute transaction or consent was created.";
        }
    }
    fn stage_durable_spend_v1(
        &mut self,
        imported: Arc<ImportedDurableReviewV1>,
        inputs: crate::manifest::ReviewInputs,
        head: wholepact_authority::AuthorityHead,
        epoch: u64,
    ) -> Result<()> {
        self.stage_durable_spend_inner_v1(
            imported,
            inputs,
            head,
            epoch,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            None,
        )
    }
    fn stage_durable_spend_inner_v1(
        &mut self,
        imported: Arc<ImportedDurableReviewV1>,
        inputs: crate::manifest::ReviewInputs,
        head: wholepact_authority::AuthorityHead,
        epoch: u64,
        #[cfg(feature = "synthetic-born-joined-qualification")] observer: Option<
            &flow_diag_v1::DurableFlowObserverV1,
        >,
    ) -> Result<()> {
        let open = self.open.as_ref().ok_or(Error::Locked)?;
        open.check_pairing()?;
        let session = open.session.as_ref().ok_or(Error::Locked)?;
        let prepared = durable_flow_observe_v1!(
            observer,
            flow_diag_v1::DurableFlowStageV1::SpendStage,
            bridge::prepare_manual_review(
                imported.proposal_source_inner(
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    observer.cloned()
                ),
                &open.journal,
                session,
                open.enrollment.as_ref().ok_or(Error::ReviewMismatch)?,
                open.manifest.as_ref().ok_or(Error::ReviewMismatch)?,
                open.vault.account(),
                inputs,
            )
        )
        .map_err(|_| Error::ReviewMismatch)?;
        // The original witnessed account-policy pin is not a fresh native
        // consent reference. Bind both explicitly, under the actual original
        // source, before either disclosure or spending review is displayed.
        let prepared = durable_flow_observe_v1!(
            observer,
            flow_diag_v1::DurableFlowStageV1::SpendStage,
            prepared.with_durable_born_policy_v1(
                open.durable_born_entry
                    .as_deref()
                    .ok_or(Error::Unavailable)?,
                open.enrollment.as_ref().ok_or(Error::ReviewMismatch)?,
                open.manifest.as_ref().ok_or(Error::ReviewMismatch)?,
            )
        )
        .map_err(|_| Error::ReviewMismatch)?;
        let witness = open.witness.as_ref().ok_or(Error::Locked)?;
        witness.check_current()?;
        let disclosure =
            WitnessDisclosureReview::new(witness.client(), prepared.prepared_spend(), head.clone())
                .map_err(|_| Error::Verification)?;
        let review = ExactNativeReview::stage(
            &open.authority,
            disclosure.review_digest(),
            disclosure.display().into(),
            epoch,
        )?;
        self.pending = Some(PendingDecision {
            review,
            operation: Operation::DurableDisclosureV1 {
                flow: Box::new(DurableSpendFlowV1 {
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    flow_epoch: epoch,
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    flow_observer: observer.cloned(),
                    prepared,
                    head,
                    imported,
                }),
                review: Box::new(disclosure),
            },
        });
        Ok(())
    }
    pub(super) fn approve_durable_disclosure_v1(
        &mut self,
        flow: DurableSpendFlowV1,
        review: WitnessDisclosureReview,
        decision: super::super::NativeDecision,
        epoch: u64,
    ) -> Result<()> {
        let open = self.open.as_ref().ok_or(Error::Locked)?;
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let observer = flow.flow_observer.as_ref();
        open.check_pairing()?;
        flow.imported
            .check_data_source_inner(
                #[cfg(feature = "synthetic-born-joined-qualification")]
                observer,
                #[cfg(feature = "synthetic-born-joined-qualification")]
                flow_diag_v1::DurableFlowStageV1::DisclosureDecision,
            )
            .map_err(|_| Error::ReviewMismatch)?;
        let disclosure = durable_flow_observe_v1!(
            observer,
            flow_diag_v1::DurableFlowStageV1::DisclosureDecision,
            review.approve(decision, &open.authority)
        )
        .map_err(|_| Error::Authentication)?;
        let display = format!(
            "AUTHORIZE THIS EXACT FIXED DURABLE PROPOSAL\n{}\n\nCOMPLETE ACCEPTED MANIFEST\n{}\n\nThis full-account profile verifies the exact accepted canonical account/FVK identities, real note/nullifier/action mapping, recipient and change outputs, fees and every account's net debit against the same proved transaction. It does NOT authenticate named people or organisations, distinct humans or funding sources, or prior peer approval. Required final spend signatures establish executable account control only when combined. No sponsor, matching or identity-dependent condition is supported.\n\nThis fresh one-action decision does not restore an old native approval. The current protected wallet and original independent witness are checked again before key use. Previously committed exposure remains reserved. Only this account's assigned detached signatures can be retained; this signer does not broadcast.",
            serde_json::to_string_pretty(flow.prepared.prepared_spend().record())
                .map_err(|_| Error::InvalidData)?,
            serde_json::to_string_pretty(open.manifest.as_ref().ok_or(Error::ReviewMismatch)?)
                .map_err(|_| Error::InvalidData)?
        );
        self.pending = Some(PendingDecision {
            review: ExactNativeReview::stage(
                &open.authority,
                flow.prepared.prepared_spend().review_digest(),
                display,
                epoch,
            )?,
            operation: Operation::DurableSpendV1 {
                flow: Box::new(flow),
                disclosure: Box::new(disclosure),
            },
        });
        self.message = "Exact witness disclosure accepted. Review the separate fresh fixed-proposal spending decision; account attribution does not identify a person or imply prior peer consent.";
        Ok(())
    }
    pub(super) fn begin_durable_signing_v1(
        &mut self,
        flow: DurableSpendFlowV1,
        disclosure: ApprovedWitnessDisclosure,
        decision: super::super::NativeDecision,
    ) -> Result<()> {
        let open = self.open.as_mut().ok_or(Error::Locked)?;
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let observer = flow.flow_observer.clone();
        let peer = open.check_pairing()?.peer.clone();
        let session = open.session.clone().ok_or(Error::Locked)?;
        flow.imported
            .check_data_source_inner(
                #[cfg(feature = "synthetic-born-joined-qualification")]
                observer.as_ref(),
                #[cfg(feature = "synthetic-born-joined-qualification")]
                flow_diag_v1::DurableFlowStageV1::SigningLaunch,
            )
            .map_err(|_| Error::ReviewMismatch)?;
        let approved = durable_flow_observe_v1!(
            observer.as_ref(),
            flow_diag_v1::DurableFlowStageV1::SpendDecision,
            flow.prepared
                .approve(&session, session.native_decision(decision)?)
        )
        .map_err(|_| Error::ReviewMismatch)?;
        let source = open.durable_born_entry.clone().ok_or(Error::Unavailable)?;
        if !Arc::ptr_eq(&source, &flow.imported.source) {
            return Err(Error::Authentication);
        }
        let witness = open.witness.clone().ok_or(Error::Locked)?;
        witness.check_current()?;
        let wallet = open.wallet.as_mut().ok_or(Error::Locked)?;
        let wallet_revoke = wallet.revoke_handle();
        let ticket = wallet.take_ticket()?;
        let admission = open.ipc.revocation();
        let mut open = self.open.take().ok_or(Error::Locked)?;
        let worker_session = session.clone();
        let (send, receive) = mpsc::sync_channel(1);
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let observation = observer.as_ref().map(|observer| {
            (
                observer.job_start(flow_diag_v1::DurableFlowJobPurposeV1::Sign, flow.flow_epoch),
                observer.clone(),
            )
        });
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let worker_observer = observer;
        std::thread::spawn(move || {
            let result = (|| {
                durable_flow_observe_v1!(
                    worker_observer.as_ref(),
                    flow_diag_v1::DurableFlowStageV1::AuthorizationSource,
                    open.check_pairing()
                )
                .map_err(bridge_error)?;
                durable_flow_observe_v1!(
                    worker_observer.as_ref(),
                    flow_diag_v1::DurableFlowStageV1::AuthorizationSource,
                    source.require_account_identity(open.vault.account())
                )
                .map_err(bridge_error)?;
                durable_flow_observe_v1!(
                    worker_observer.as_ref(),
                    flow_diag_v1::DurableFlowStageV1::AuthorizationSource,
                    source.require_journal_identity(&open.journal)
                )
                .map_err(bridge_error)?;
                #[cfg(feature = "synthetic-born-joined-qualification")]
                return approved.authorize_from_durable_born_v1_diagnosed(
                    &source,
                    &worker_session,
                    flow.head,
                    disclosure,
                    witness.client(),
                    open.wallet
                        .as_mut()
                        .ok_or(BridgeError::Permission)?
                        .wallet_mut(),
                    &ticket,
                    worker_observer.as_ref(),
                );
                #[cfg(not(feature = "synthetic-born-joined-qualification"))]
                approved.authorize_from_durable_born_v1(
                    &source,
                    &worker_session,
                    flow.head,
                    disclosure,
                    witness.client(),
                    open.wallet
                        .as_mut()
                        .ok_or(BridgeError::Permission)?
                        .wallet_mut(),
                    &ticket,
                )
            })();
            let result = durable_flow_observe_v1!(
                worker_observer.as_ref(),
                flow_diag_v1::DurableFlowStageV1::Completion,
                result
            );
            if let Err(unsent) = send.send((open, result)) {
                unsent.0 .0.close();
            }
        });
        self.signing_job = Some(SigningJob {
            #[cfg(feature = "synthetic-born-joined-qualification")]
            flow: observation,
            receive,
            session,
            admission,
            wallet_revoke,
            peer,
            lock_requested: false,
        });
        self.message = "Exact durable one-action authorization is in progress. Release intent and exposure commit before key use; uncertain attempts never receive replacement signatures. No payment is broadcast.";
        Ok(())
    }
}

pub(super) fn allowed_event(event: &LocalEvent) -> bool {
    match event {
        LocalEvent::Pairing(_)
        | LocalEvent::History { .. }
        | LocalEvent::Export { .. }
        | LocalEvent::Redelivery { .. }
        | LocalEvent::Redelivered { .. }
        | LocalEvent::Preconstruction { .. }
        | LocalEvent::DurableConstructionV1 { .. }
        | LocalEvent::DurableConstructionHistoryV1 { .. }
        | LocalEvent::DurableConstructionRedisclosureV1 { .. }
        | LocalEvent::DurableProposalReviewV1 { .. } => true,
        LocalEvent::Request { request, .. } => {
            matches!(request, crate::ipc::AppRequest::Status { .. })
        }
        _ => false,
    }
}
pub(super) fn allowed_operation(operation: &Operation) -> bool {
    matches!(
        operation,
        Operation::Pair(_)
            | Operation::Enroll(_)
            | Operation::Manifest(_)
            | Operation::DurableBornWalletV1(_)
            | Operation::Witness(_)
            | Operation::OwnerWitness(_)
            | Operation::DurableWitnessV1(_)
            | Operation::Preconstruction(_)
            | Operation::DurableConstructionV1(_)
            | Operation::Redelivery { .. }
            | Operation::DurableDisclosureV1 { .. }
            | Operation::DurableSpendV1 { .. }
    )
}
pub(super) fn check_plain_proposal(open: &OpenAccount, proposal: &Proposal) -> Result<()> {
    let Some(source) = &open.durable_born_entry else {
        return Ok(());
    };
    source.check_current()?;
    crate::native_ui::durable_proposal_v1::plain_profile(proposal)?;
    let scope = &source.record().account_record.terms.scope;
    let account_id = source.account().account_id()?;
    let own = proposal
        .manifest()
        .participants
        .iter()
        .find(|p| p.account_id == account_id)
        .ok_or(Error::ReviewMismatch)?;
    if proposal.manifest().agreement.agreement_id != scope.agreement_id
        || proposal.manifest().agreement.obligation_id != scope.obligation_id
        || own.participant_id != scope.participant_id
        || own.maximum_net_debit.as_zatoshis() > scope.per_operation_limit_zatoshis
        || own.fee_share.as_zatoshis() > scope.maximum_fee_share_zatoshis
        || own.fee_cap.as_zatoshis() > scope.maximum_fee_share_zatoshis
        || proposal.manifest().transaction_fee.as_zatoshis()
            > scope.maximum_transaction_fee_zatoshis
        || now()
            .map_err(|_| Error::ReviewMismatch)?
            .checked_mul(1000)
            .is_none_or(|v| v >= scope.expires_at_ms)
    {
        return Err(Error::ReviewMismatch);
    }
    Ok(())
}
pub(super) fn check_plain_preconstruction(
    open: &OpenAccount,
    request: &authority_bridge::preconstruction_ipc::PreconstructionRequest,
) -> Result<()> {
    if open.durable_born_entry.is_none() {
        return Ok(());
    }
    if request.sponsor_policy.is_some() {
        return Err(Error::Unavailable);
    }
    let proposal = request.validate().map_err(|_| Error::ReviewMismatch)?;
    check_plain_proposal(open, &proposal)?;
    if open
        .enrollment
        .as_ref()
        .is_none_or(|e| e.reference() != request.enrollment_ref)
        || open
            .manifest
            .as_ref()
            .is_none_or(|m| m.reference() != request.accepted_manifest_ref)
    {
        return Err(Error::ReviewMismatch);
    }
    let session = open.session.as_ref().ok_or(Error::Locked)?;
    let lease = open.journal.acquire_preconstruction_records(
        &request.enrollment_ref,
        &request.accepted_manifest_ref,
        session,
    )?;
    lease.require_native_origin(&open.authority.binding())?;
    if lease.sponsor_required() || lease.sponsor_policy().is_some() {
        return Err(Error::Unavailable);
    }
    lease.check_current()?;
    Ok(())
}

/// Reject a foreign witness before any session contact or journal mutation.
/// This uses historical origin only as an exact destination constraint; the
/// configured workspace and native owner must still be freshly current.
pub(super) fn check_witness_descriptor(
    open: &OpenAccount,
    descriptor: &wholepact_authority::WitnessDisclosureDescriptor,
) -> Result<()> {
    if let Some(source) = &open.durable_born_entry {
        source.check_current()?;
        if source.original_witness_disclosure()? != *descriptor {
            return Err(Error::ReviewMismatch);
        }
    }
    Ok(())
}
pub(super) fn check_selected_witness_setup(open: &OpenAccount, json: &str) -> Result<()> {
    if open.durable_born_entry.is_some() {
        let selected = crate::native_ui::witness_workspace::prepare_selected_witness_configuration(
            json,
            &open.vault.account_id()?,
            None,
        )?;
        check_witness_descriptor(open, &selected.client.disclosure_descriptor())?;
    }
    Ok(())
}
// Closed same-call preparation only. These two slots are the actual selected
// workspaces; neither a descriptor nor this Result carries current authority.
fn check_configured_witnesses_v1<S, W>(
    source: Option<&S>,
    workspaces: [Option<&W>; 2],
    workspace_current: impl Fn(&W) -> Result<()>,
    workspace_disclosure: impl Fn(&W) -> wholepact_authority::WitnessDisclosureDescriptor,
    original_disclosure: impl FnOnce(&S) -> Result<wholepact_authority::WitnessDisclosureDescriptor>,
    late_source_current: impl FnOnce(&S) -> Result<()>,
) -> Result<()> {
    let Some(source) = source else {
        return Ok(());
    };
    if workspaces.iter().all(Option::is_none) {
        return Ok(());
    }
    let mut disclosures = [None, None];
    for (index, workspace) in workspaces.iter().enumerate() {
        if let Some(workspace) = workspace {
            workspace_current(workspace)?;
            disclosures[index] = Some(workspace_disclosure(workspace));
        }
    }
    let original = original_disclosure(source)?;
    if disclosures
        .iter()
        .flatten()
        .any(|actual| actual != &original)
    {
        return Err(Error::ReviewMismatch);
    }
    // The original entry performs its full native/original/journal check here.
    // This is not an imported-source receipt or current-epoch acquisition.
    late_source_current(source)?;
    for workspace in workspaces.into_iter().flatten() {
        workspace_current(workspace)?;
    }
    Ok(())
}
pub(super) fn check_configured_witnesses(open: &OpenAccount) -> Result<()> {
    check_configured_witnesses_v1(
        open.durable_born_entry.as_deref(),
        [open.witness.as_deref(), open.owner_witness.as_deref()],
        |workspace| workspace.check_current(),
        |workspace| workspace.disclosure(),
        |source| source.original_witness_disclosure_data_v1(),
        |source| source.check_current(),
    )
}

#[cfg(test)]
mod configured_witness_preparation_tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use wholepact_authority::WitnessDisclosureDescriptor;

    // Inert descriptor equality fixtures, never native or imported authority.
    fn descriptor() -> WitnessDisclosureDescriptor {
        WitnessDisclosureDescriptor {
            endpoint: "127.0.0.1:7443".into(),
            server_name: "inert.example".into(),
            witness_id: "inert-witness".into(),
            account_id: "inert-account".into(),
            network_profile_id: "inert-network".into(),
            policy_digest: "11".repeat(32),
            pinned_server_certificate_digest: "22".repeat(32),
        }
    }

    #[test]
    fn configured_preparation_actual_kernel_orders_zero_one_and_two_slots() {
        for has_source in [false, true] {
            for occupied in [[false, false], [true, false], [false, true], [true, true]] {
                let slots = [0, 1];
                let source = ();
                let events = RefCell::new(Vec::new());
                let result = check_configured_witnesses_v1(
                    has_source.then_some(&source),
                    [
                        occupied[0].then_some(&slots[0]),
                        occupied[1].then_some(&slots[1]),
                    ],
                    |slot| {
                        events.borrow_mut().push(("current", *slot));
                        Ok(())
                    },
                    |slot| {
                        events.borrow_mut().push(("descriptor", *slot));
                        descriptor()
                    },
                    |_| {
                        events.borrow_mut().push(("original", 0));
                        Ok(descriptor())
                    },
                    |_| {
                        events.borrow_mut().push(("late", 0));
                        Ok(())
                    },
                );
                assert!(result.is_ok());
                let mut expected = Vec::new();
                if has_source && occupied.iter().any(|value| *value) {
                    for slot in 0..2 {
                        if occupied[slot] {
                            expected.extend([("current", slot), ("descriptor", slot)]);
                        }
                    }
                    expected.extend([("original", 0), ("late", 0)]);
                    for slot in 0..2 {
                        if occupied[slot] {
                            expected.push(("current", slot));
                        }
                    }
                }
                assert!(*events.borrow() == expected);
            }
        }
    }

    #[test]
    fn configured_preparation_actual_kernel_preserves_each_owned_error() {
        // Descriptor reads are infallible and must follow their actual lifetime
        // gate. Every fallible phase keeps the original owned error and stops.
        for fail_at in [0, 2, 4, 5, 6, 7] {
            let calls = Cell::new([0; 2]);
            let events = RefCell::new(Vec::new());
            let step = |at| -> Result<()> {
                events.borrow_mut().push(at);
                if at == fail_at {
                    Err(Error::Io(std::io::Error::from_raw_os_error(1400 + at)))
                } else {
                    Ok(())
                }
            };
            let result = check_configured_witnesses_v1(
                Some(&()),
                [Some(&0_usize), Some(&1_usize)],
                |slot| {
                    let mut counts = calls.get();
                    let at = if counts[*slot] == 0 {
                        2 * *slot
                    } else {
                        6 + *slot
                    };
                    counts[*slot] += 1;
                    calls.set(counts);
                    step(at as i32)
                },
                |slot| {
                    events.borrow_mut().push((2 * *slot + 1) as i32);
                    descriptor()
                },
                |_| {
                    step(4)?;
                    Ok(descriptor())
                },
                |_| step(5),
            );
            assert!(
                matches!(result, Err(Error::Io(error)) if error.raw_os_error() == Some(1400 + fail_at))
            );
            assert!(*events.borrow() == (0..=fail_at).collect::<Vec<_>>());
        }
    }

    #[test]
    fn configured_preparation_actual_kernel_rejects_every_descriptor_field() {
        let original = descriptor();
        let encoded = serde_json::to_value(&original).unwrap();
        let fields = encoded.as_object().unwrap();
        assert!(
            fields.keys().map(String::as_str).collect::<Vec<_>>()
                == [
                    "account_id",
                    "endpoint",
                    "network_profile_id",
                    "pinned_server_certificate_digest",
                    "policy_digest",
                    "server_name",
                    "witness_id",
                ]
        );
        for field in fields.keys() {
            let mut changed = encoded.clone();
            changed[field] =
                serde_json::Value::String(format!("{}x", fields[field].as_str().unwrap()));
            let changed: WitnessDisclosureDescriptor = serde_json::from_value(changed).unwrap();
            for wrong_slot in 0..2 {
                let events = RefCell::new(Vec::new());
                let result = check_configured_witnesses_v1(
                    Some(&()),
                    [Some(&0), Some(&1)],
                    |slot| {
                        events.borrow_mut().push(("current", *slot));
                        Ok(())
                    },
                    |slot| {
                        events.borrow_mut().push(("descriptor", *slot));
                        if *slot == wrong_slot {
                            changed.clone()
                        } else {
                            original.clone()
                        }
                    },
                    |_| {
                        events.borrow_mut().push(("original", 0));
                        Ok(original.clone())
                    },
                    |_| panic!("mismatched descriptor must stop before the late source check"),
                );
                assert!(
                    matches!(result, Err(Error::ReviewMismatch)),
                    "{field} in slot {wrong_slot}"
                );
                assert!(
                    *events.borrow()
                        == [
                            ("current", 0),
                            ("descriptor", 0),
                            ("current", 1),
                            ("descriptor", 1),
                            ("original", 0),
                        ]
                );
            }
        }
    }

    #[test]
    fn configured_preparation_actual_kernel_rechecks_invalidated_workspaces() {
        for invalidated in 0..2 {
            let late_completed = Cell::new(false);
            let final_calls = RefCell::new(Vec::new());
            let result = check_configured_witnesses_v1(
                Some(&()),
                [Some(&0), Some(&1)],
                |slot| {
                    if late_completed.get() {
                        final_calls.borrow_mut().push(*slot);
                        if *slot == invalidated {
                            return Err(Error::Locked);
                        }
                    }
                    Ok(())
                },
                |_| descriptor(),
                |_| Ok(descriptor()),
                |_| {
                    late_completed.set(true);
                    Ok(())
                },
            );
            assert!(matches!(result, Err(Error::Locked)));
            assert!(*final_calls.borrow() == (0..=invalidated).collect::<Vec<_>>());
        }
    }
}

#[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
mod durable_flow_import_tests {
    use super::*;
    use flow_diag_v1::{
        DurableFlowCollectorV1 as Collector, DurableFlowErrorCodeV1 as Code,
        DurableFlowJobPurposeV1 as Purpose, DurableFlowOperationV1 as Operation,
        DurableFlowPresentationV1 as Presentation, DurableFlowReceiveV1 as Receive,
        DurableFlowResultV1 as Observed, DurableFlowStageV1 as Stage,
    };
    use std::cell::Cell;

    #[test]
    fn actual_import_poller_distinguishes_disconnected_from_returned_ipc() {
        for returned in [false, true] {
            let collector = Collector::default();
            let observer = collector.arm(Operation::FinancialImport);
            let job = observer.job_start(Purpose::Import, 7);
            let (send, receive) = mpsc::channel::<authority_bridge::Result<()>>();
            if returned {
                send.send(Err(BridgeError::Ipc)).unwrap();
            }
            drop(send);
            let (result, received) = match durable_flow_try_receive_v1(&receive, Some(&job)) {
                Ok(result) => (result, true),
                Err(mpsc::TryRecvError::Disconnected) => (Err(BridgeError::Ipc), false),
                _ => panic!("unexpected pending channel"),
            };
            assert!(
                durable_import_disposition_v1(
                    &result,
                    received,
                    true,
                    || Ok(()),
                    |_| panic!("error has no source"),
                    Some(&job),
                    Some(&observer)
                ) == DurableImportDispositionV1::Rejected
            );
            assert!(matches!(result, Err(BridgeError::Ipc)));
            let report = observer.finish(Observed::ReturnedErr).unwrap();
            if returned {
                assert!(report.first_error().unwrap().code() == Code::BridgeIpc);
                assert!(report.completion().result() == Observed::ReturnedErr);
                assert!(report.completion().receive() == Receive::Received);
            } else {
                assert!(report.first_error().is_none());
                assert!(report.completion().result() == Observed::NotObserved);
                assert!(report.completion().receive() == Receive::Disconnected);
            }
        }
    }
    #[test]
    fn actual_import_poller_invalid_epoch_skips_pairing_and_source() {
        let collector = Collector::default();
        let observer = collector.arm(Operation::FinancialImport);
        let job = observer.job_start(Purpose::Import, 7);
        let result: authority_bridge::Result<()> = Err(BridgeError::Verification);
        assert!(
            durable_import_disposition_v1(
                &result,
                true,
                false,
                || panic!("pairing short circuit"),
                |_| panic!("source short circuit"),
                Some(&job),
                Some(&observer)
            ) == DurableImportDispositionV1::Invalidated
        );
        let report = observer.finish(Observed::ReturnedErr).unwrap();
        assert!(report.first_error().unwrap().code() == Code::BridgeVerification);
        assert!(report.completion().result() == Observed::ReturnedErr);
        assert!(report.completion().receive() == Receive::Invalidated);
        assert!(report.completion().presentation() == Presentation::Suppressed);
    }
    #[test]
    fn actual_import_poller_keeps_success_and_source_failure_separate() {
        for diagnosed in [false, true] {
            let collector = Collector::default();
            let observer = collector.arm(Operation::FinancialImport);
            let job = observer.job_start(Purpose::Import, 7);
            let source_calls = Cell::new(0);
            let original = Box::new(19u8);
            let address = &*original as *const u8;
            let result = Ok(original);
            assert!(
                durable_import_disposition_v1(
                    &result,
                    true,
                    true,
                    || Ok(()),
                    |value| {
                        assert!(std::ptr::eq(&**value, address));
                        source_calls.set(source_calls.get() + 1);
                        Err(BridgeError::Permission)
                    },
                    diagnosed.then_some(&job),
                    diagnosed.then_some(&observer)
                ) == DurableImportDispositionV1::Rejected
            );
            assert_eq!(source_calls.get(), 1);
            assert!(std::ptr::eq(&**result.as_ref().unwrap(), address));
            if diagnosed {
                let report = observer.finish(Observed::ReturnedErr).unwrap();
                assert!(report.first_error().unwrap().stage() == Stage::ImportSource);
                assert!(report.first_error().unwrap().code() == Code::BridgePermission);
                assert!(report.completion().result() == Observed::ReturnedOk);
                assert!(report.completion().presentation() == Presentation::Suppressed);
            }
        }
    }
    #[test]
    fn actual_import_poller_pending_does_not_invent_result_or_cause() {
        let collector = Collector::default();
        let observer = collector.arm(Operation::FinancialImport);
        let job = observer.job_start(Purpose::Import, 7);
        let (_send, receive) = mpsc::channel::<authority_bridge::Result<()>>();
        for _ in 0..3 {
            assert!(matches!(
                durable_flow_try_receive_v1(&receive, Some(&job)),
                Err(mpsc::TryRecvError::Empty)
            ));
        }
        let report = observer.finish(Observed::ReturnedErr).unwrap();
        assert!(report.first_error().is_none());
        assert!(report.completion().receive() == Receive::Pending);
        assert!(report.completion().result() == Observed::NotObserved);
    }
    #[test]
    fn actual_wallet_poller_old_job_pairing_error_cannot_enter_new_attempt() {
        let collector = Collector::default();
        let old = collector.arm(Operation::InitialSign);
        let job = old.job_start(Purpose::WalletReview, 7);
        let current = collector.arm(Operation::InitialSign);
        let current_job = current.job_start(Purpose::WalletReview, 8);
        let calls = Cell::new(0);
        let result: Result<()> = Ok(());
        assert!(!durable_wallet_completion_allowed_v1(
            &result,
            true,
            || {
                calls.set(calls.get() + 1);
                Err(Error::Authentication)
            },
            Some(&job),
            Some(&old)
        ));
        assert_eq!(calls.get(), 1);
        // Stage completion uses this same job-bound observer, never the current arm.
        let staged: Result<()> =
            durable_flow_observe_v1!(Some(&old), Stage::SpendStage, Err(Error::Verification));
        assert!(matches!(staged, Err(Error::Verification)));
        current_job.pending();
        let report = current.finish(Observed::ReturnedErr).unwrap();
        assert!(report.first_error().is_none());
        assert!(report.completion().result() == Observed::NotObserved);
        assert!(report.completion().receive() == Receive::Pending);
        assert!(report.incomplete());
    }
    #[test]
    fn actual_wallet_poller_invalid_epoch_keeps_original_error_without_pairing() {
        let collector = Collector::default();
        let observer = collector.arm(Operation::InitialSign);
        let job = observer.job_start(Purpose::WalletReview, 7);
        let result: Result<()> = Err(Error::Uncertain);
        assert!(!durable_wallet_completion_allowed_v1(
            &result,
            false,
            || panic!("pairing short circuit"),
            Some(&job),
            Some(&observer)
        ));
        assert!(matches!(result, Err(Error::Uncertain)));
        let report = observer.finish(Observed::ReturnedErr).unwrap();
        assert!(report.first_error().unwrap().code() == Code::SignerUncertain);
        assert!(report.completion().receive() == Receive::Invalidated);
    }
    #[test]
    fn actual_import_expectation_binds_once_and_rejects_mismatched_or_stale_attribution() {
        use wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1;
        use crate::authority_bridge::durable_construction_v1::DurableConstructionHistoryRequestV1;
        let hash = |value: char| value.to_string().repeat(64);
        let request = DurableReviewDeliveryRequestV1 {
            operation_id: "inert-import".into(),
            enrollment_ref: hash('a'),
            accepted_manifest_ref: hash('b'),
            own_disclosure: DurableConstructionHistoryRequestV1 {
                operation_id: "inert-disclosure".into(),
                expected_request_digest: hash('c'),
            },
            current_disclosure: None,
            proposal_binding: hash('d'),
        };
        let identity = FixedProposalIdentityV1 {
            schema_version: 1,
            network_profile_id: "inert-network".into(),
            agreement_id: "inert-agreement".into(),
            obligation_id: "inert-obligation".into(),
            proposal_id: "inert-proposal".into(),
            revision: 1,
            expiry_height: 1,
            proposal_digest: hash('1'),
            manifest_digest: hash('2'),
            unsigned_artifact_digest: hash('3'),
            proved_artifact_digest: hash('4'),
            effects_commitment: hash('5'),
            policy_digest: hash('6'),
            review_binding: hash('7'),
            action_mapping_digest: hash('8'),
            anchor: hash('9'),
            proposal_binding: hash('d'),
        };
        let collector = Collector::default();
        let observer = collector.arm(Operation::FinancialImport);
        let expected =
            DurableFlowImportExpectationV1::new(&request, &identity, 7, &observer).unwrap();
        assert!(expected.matches_poll(&request, &identity, 7));
        let mut wrong_request = request.clone();
        wrong_request.operation_id.push('x');
        let mut wrong_identity = identity.clone();
        wrong_identity.proposal_id.push('x');
        assert!(!expected.matches_poll(&wrong_request, &identity, 7));
        assert!(!expected.matches_poll(&request, &wrong_identity, 7));
        assert!(!expected.matches_poll(&request, &identity, 8));
        assert!(expected.clone().bind(&wrong_request, 7).is_none());
        assert!(expected.clone().bind(&request, 8).is_none());
        let bound = expected.clone().bind(&request, 7).unwrap();
        let (send, receive) = mpsc::channel::<authority_bridge::Result<()>>();
        for _ in 0..3 {
            assert!(expected.matches_poll(&request, &identity, 7));
            assert!(matches!(
                durable_flow_try_receive_v1(&receive, Some(&bound.job)),
                Err(mpsc::TryRecvError::Empty)
            ));
        }
        // An actual failed receive needs no fabricated successful imported identity.
        send.send(Err(BridgeError::Ipc)).unwrap();
        let result = durable_flow_try_receive_v1(&receive, Some(&bound.job)).unwrap();
        assert!(
            durable_import_disposition_v1(
                &result,
                true,
                true,
                || Ok(()),
                |_| panic!("error has no imported identity"),
                Some(&bound.job),
                Some(&bound.observer)
            ) == DurableImportDispositionV1::Rejected
        );
        let report = observer.finish(Observed::ReturnedErr).unwrap();
        assert!(report.first_error().unwrap().code() == Code::BridgeIpc);
        assert!(report.completion().purpose() == Some(Purpose::Import));
        assert!(report.completion().result() == Observed::ReturnedErr);
        let old = collector.arm(Operation::FinancialImport);
        let stale = DurableFlowImportExpectationV1::new(&request, &identity, 7, &old).unwrap();
        let current = collector.arm(Operation::FinancialImport);
        let stale_bound = stale.bind(&request, 7).unwrap();
        let actual: authority_bridge::Result<()> = Err(BridgeError::Verification);
        assert!(
            durable_import_disposition_v1(
                &actual,
                true,
                true,
                || Ok(()),
                |_| panic!("error has no source"),
                Some(&stale_bound.job),
                Some(&stale_bound.observer)
            ) == DurableImportDispositionV1::Rejected
        );
        let report = current.finish(Observed::ReturnedErr).unwrap();
        assert!(report.first_error().is_none());
        assert!(report.completion().purpose().is_none());
        assert!(report.incomplete());
    }
    #[test]
    fn bounded_import_fingerprint_is_domain_separated_and_rejects_overflow() {
        let small = "inert correlation only";
        assert!(flow_fingerprint_v1(b"durable-flow-request-v1\0", &small).is_some());
        assert!(
            flow_fingerprint_v1(b"durable-flow-request-v1\0", &small)
                != flow_fingerprint_v1(b"durable-flow-identity-v1\0", &small)
        );
        let oversized = "x".repeat(wire::MAX_DURABLE_REVIEW_PAYLOAD_BYTES_V1 + 1);
        assert!(flow_fingerprint_v1(b"durable-flow-request-v1\0", &oversized).is_none());
    }
}
