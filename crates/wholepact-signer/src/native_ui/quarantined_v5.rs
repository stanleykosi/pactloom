//! Source-only quarantined informational V5 adapter. This does not enable the
//! public endpoint or convert an original restored source into a writer.
//!
//! Both source directory locks remain owned by the retained account Arc through
//! final checks and response. Full source-content rechecks detect ordinary races;
//! synchronous filesystem calls cannot provide a hard realtime bound or protect
//! against hostile same-user swaps. A witness snapshot is an authenticated
//! observation, never a remote lease, atomic cutoff or financial authority.
use super::{
    NativeAuthority, NativeAuthorityBinding, NativeDecision,
    informational_witness::NativeInformationalWitness,
};
use crate::{
    Error, Result,
    account::informational::{QuarantinedInformationalAccount, QuarantinedInformationalBinding},
    authority_bridge::{
        self, BridgeError,
        host_publication_ipc::{
            PublicationWindow,
            v5::{
                HostPublicationCommandV5, HostPublicationResponseV5,
                HostRecoveryPublicationRecordV5, HostRecoveryPublicationRequestV5,
            },
        },
        host_recovery_ipc::v5::{
            HostContinuityCommandV5, HostContinuityResponseV5, HostRecoveryContinuityEvidenceV5,
            HostRecoveryContinuityRequestV5,
            transfer::{
                self, TransferCommandV1, TransferMetadata, TransferPurpose, TransferResponseV1,
                TransferSender, V5TransferDialect,
            },
            transfer_io::{read_frame_until, require_before_deadline, write_frame_until},
        },
    },
    ipc::{AuthenticatedPeer, PairScope},
};
use serde::Serialize;
use std::{
    os::unix::net::UnixStream,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use wholepact_authority::ReconciledAuthorityHistory;

const TRANSFER_WINDOW: Duration = Duration::from_secs(30);
const REVIEW_WINDOW: Duration = Duration::from_secs(120);
const DISPLAY_LIMIT: usize = 1_900_000;

fn review_error(_: impl std::fmt::Display) -> Error {
    Error::ReviewMismatch
}
fn permission(_: impl std::fmt::Display) -> BridgeError {
    BridgeError::Permission
}
fn require_bounded(dialect: V5TransferDialect) -> Result<()> {
    if dialect != V5TransferDialect::BoundedV1 {
        return Err(Error::Unavailable);
    }
    Ok(())
}
fn require_request_scope(
    request: &HostRecoveryContinuityRequestV5,
    scope: &PairScope,
    account_id: &str,
    historical_writer_epoch: u64,
) -> authority_bridge::Result<()> {
    request.validate()?;
    scope.validate().map_err(permission)?;
    if !scope.history_read
        || !scope.authorization_export
        || scope.preconstruction_export
        || scope.account_id != request.account_id
        || scope.manifest_digest != request.inventory_digest
        || request.account_id != account_id
        || request.expected_writer_epoch != historical_writer_epoch
    {
        return Err(BridgeError::Binding);
    }
    Ok(())
}

/// Pure deadline selection only. Issuing it requires the genuine consumed
/// NativeDecision below. Calling serve later cannot refresh this budget.
fn transfer_deadline(approved_at: Instant, original_deadline: Instant) -> Instant {
    (approved_at + TRANSFER_WINDOW).min(original_deadline)
}

/// Inert metadata only. It does not retain source locks, an account owner,
/// native authority, a peer, witness credentials or any financial capability.
struct ContinuityCompletionBinding {
    source_inventory_digest: String,
    checkpoint_id: String,
    account_id: String,
    historical_writer_epoch: u64,
    request: HostRecoveryContinuityRequestV5,
    request_digest: String,
    evidence_digest: String,
    original_source_deadline: Instant,
    deadline: Instant,
}
impl ContinuityCompletionBinding {
    #[allow(clippy::too_many_arguments)]
    fn require_source_metadata(
        &self,
        inventory: &str,
        checkpoint: &str,
        account: &str,
        epoch: u64,
        source_deadline: Instant,
        now: Instant,
    ) -> Result<()> {
        if now >= self.deadline
            || now >= source_deadline
            || source_deadline > self.deadline
            || self.deadline > self.original_source_deadline
            || inventory != self.source_inventory_digest
            || checkpoint != self.checkpoint_id
            || account != self.account_id
            || epoch != self.historical_writer_epoch
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    fn require_publication(&self, request: &HostRecoveryPublicationRequestV5) -> Result<()> {
        require_before_deadline(self.deadline).map_err(review_error)?;
        request.validate().map_err(review_error)?;
        if request.continuity != self.request
            || request.continuity.digest().map_err(review_error)? != self.request_digest
            || request.continuity_evidence_digest != self.evidence_digest
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
}

/// One-shot, key-free completion marker, issued only by the fully accepted
/// continuity branch after explicit Finish/Finished and final checks. No Clone,
/// serde or caller factory exists. This marker cannot recreate an account,
/// witness, native decision or peer, and never itself approves publication.
pub(super) struct CompletedQuarantinedContinuityV5(ContinuityCompletionBinding);
impl CompletedQuarantinedContinuityV5 {
    pub(super) fn deadline(&self) -> Instant {
        self.0.deadline
    }
    /// Metadata binding only; the supplied source must have been freshly
    /// authenticated. Publication preparation still performs full source checks.
    pub(super) fn require_source(&self, source: &QuarantinedInformationalAccount) -> Result<()> {
        self.0.require_source_metadata(
            source.source_inventory_digest(),
            source.checkpoint_id(),
            source.account_id(),
            source.historical_writer_epoch(),
            source.deadline(),
            Instant::now(),
        )
    }
    pub(super) fn require_publication(
        &self,
        request: &HostRecoveryPublicationRequestV5,
    ) -> Result<()> {
        self.0.require_publication(request)
    }
}

/// Inert digest inputs; serializing or retaining this data grants no authority.
#[derive(Serialize)]
struct ReviewCommitment<'a> {
    purpose: TransferPurpose,
    request_digest: &'a str,
    evidence_digest: &'a str,
    native_entry_digest: &'a str,
    source_inventory_digest: &'a str,
    checkpoint_id: &'a str,
    account_id: &'a str,
    historical_writer_epoch: u64,
    grant_id: &'a str,
    channel_digest: &'a str,
    peer_key_digest: &'a str,
    peer_generation: u64,
    peer_instance: &'a str,
    peer_pid: u32,
    peer_uid: u32,
    scope: &'a PairScope,
    review_nonce: &'a str,
}
fn review_digest(commitment: &ReviewCommitment<'_>) -> Result<String> {
    wholepact_core::proposal::canonical_digest(
        "wholepact:native-quarantined-informational-transfer:v5:bounded:v1",
        &(
            commitment,
            V5TransferDialect::BoundedV1,
            transfer::MAX_TRANSFER_EVIDENCE_BYTES,
            transfer::MAX_TRANSFER_FRAME_BYTES,
            transfer::RAW_CHUNK_BYTES,
            transfer::MAX_TRANSFER_CHUNKS,
        ),
    )
    .map_err(review_error)
}

// Neither variant is deserializable or convertible into the other review path.
enum ExactRequest {
    Continuity(HostRecoveryContinuityRequestV5),
    Publication(HostRecoveryPublicationRequestV5),
}
impl ExactRequest {
    fn continuity(&self) -> &HostRecoveryContinuityRequestV5 {
        match self {
            Self::Continuity(request) => request,
            Self::Publication(request) => &request.continuity,
        }
    }
    fn purpose(&self) -> TransferPurpose {
        match self {
            Self::Continuity(_) => TransferPurpose::Continuity,
            Self::Publication(_) => TransferPurpose::Publication,
        }
    }
    fn digest(&self) -> authority_bridge::Result<String> {
        match self {
            Self::Continuity(request) => request.digest(),
            Self::Publication(request) => request.digest(),
        }
    }
    fn matches_evidence(
        &self,
        evidence: &HostRecoveryContinuityEvidenceV5,
    ) -> authority_bridge::Result<()> {
        if self.continuity() != &evidence.request {
            return Err(BridgeError::Binding);
        }
        evidence.validate()?;
        if let Self::Publication(request) = self {
            request.matches_evidence(evidence)?;
        }
        Ok(())
    }
    fn display(&self) -> Result<String> {
        match self {
            Self::Continuity(request) => serde_json::to_string_pretty(request),
            Self::Publication(request) => serde_json::to_string_pretty(request),
        }
        .map_err(review_error)
    }
}

/// Owns every real capability used by this adapter; no journal, vault, session,
/// credential accessor or witness client can be obtained from it.
struct RetainedOwner {
    account: Arc<QuarantinedInformationalAccount>,
    account_binding: QuarantinedInformationalBinding,
    source: NativeAuthorityBinding,
    witness: Arc<NativeInformationalWitness>,
    peer: AuthenticatedPeer,
    cancelled: Arc<AtomicBool>,
    // Actual native-launch lifetime only; never sourced from a request or DTO.
    parent_channel: Option<crate::native_launch::ParentChannel>,
    original_deadline: Instant,
}
impl RetainedOwner {
    /// Cheap lifecycle checks only: immutable native/source/witness bindings
    /// were authenticated during preparation. Content is rechecked at the
    /// replay/final boundaries, not once per bounded chunk or UI click.
    fn check_lifetime_until(&self, deadline: Instant) -> authority_bridge::Result<()> {
        let deadline = deadline.min(self.original_deadline);
        require_before_deadline(deadline)?;
        if self.cancelled.load(Ordering::Acquire)
            || self.account.binding() != self.account_binding
            || self.peer.native_origin != self.source
        {
            return Err(BridgeError::Permission);
        }
        if let Some(parent) = &self.parent_channel {
            parent.check_connected().map_err(permission)?;
        }
        self.source.check_current().map_err(permission)?;
        self.peer.check_current().map_err(permission)?;
        if let Some(parent) = &self.parent_channel {
            parent.check_connected().map_err(permission)?;
        }
        require_before_deadline(deadline)
    }
    fn check_until(&self, deadline: Instant) -> authority_bridge::Result<()> {
        self.check_lifetime_until(deadline)?;
        self.witness
            .require_binding_until(&self.source, &self.account, deadline)
            .map_err(permission)?;
        self.check_lifetime_until(deadline)
    }

    /// Complete authenticated replay and read-only original-source projection.
    /// No page, full replay, projection, snapshot or serialization resets time.
    fn observe_until(
        &self,
        request: &HostRecoveryContinuityRequestV5,
        deadline: Instant,
    ) -> authority_bridge::Result<(ReconciledAuthorityHistory, HostRecoveryContinuityEvidenceV5)>
    {
        self.check_until(deadline)?;
        require_request_scope(
            request,
            &self.peer.scope,
            self.account.account_id(),
            self.account.historical_writer_epoch(),
        )?;
        if self.witness.disclosure() != request.expected_witness {
            return Err(BridgeError::Binding);
        }
        let history = self
            .witness
            .reconcile_history_checked_until(deadline, || {
                self.check_lifetime_until(deadline).map_err(review_error)
            })
            .map_err(permission)?;
        self.check_lifetime_until(deadline)?;
        let snapshot = history.snapshot();
        if snapshot.account_id != request.account_id
            || snapshot.network_profile_id != request.network_profile_id
            || snapshot.writer_epoch != request.expected_writer_epoch
            || snapshot.writer_certificate_digest != self.witness.writer_certificate_digest()
            || history.disclosure() != &request.expected_witness
        {
            return Err(BridgeError::Binding);
        }
        // This reader authenticates all original local records against complete
        // replay. Missing local admissions and inconsistent lineage fail closed.
        let complete_history = self
            .account
            .read_history_v5(&history, deadline)
            .map_err(permission)?;
        let historical_session = snapshot.active_writer_session.as_ref();
        let evidence = HostRecoveryContinuityEvidenceV5 {
            request: request.clone(),
            writer_certificate_digest: snapshot.writer_certificate_digest.clone(),
            writer_session_id: historical_session.map(|session| session.session_id.clone()),
            writer_session_expires_at_ms: historical_session.map(|session| session.expires_at_ms),
            head: snapshot.head.clone(),
            history_digest: history.history_digest()?,
            complete_history,
        };
        evidence.validate()?;
        self.require_final_snapshot(&history, &evidence, deadline)?;
        Ok((history, evidence))
    }

    fn require_final_snapshot(
        &self,
        history: &ReconciledAuthorityHistory,
        evidence: &HostRecoveryContinuityEvidenceV5,
        deadline: Instant,
    ) -> authority_bridge::Result<()> {
        self.check_lifetime_until(deadline)?;
        // This read checks the same source content before and after I/O under
        // the caller deadline. Projection then rechecks around local replay.
        let current = self.witness.snapshot_until(deadline).map_err(permission)?;
        self.check_lifetime_until(deadline)?;
        if &current != history.snapshot() {
            return Err(BridgeError::Binding);
        }
        // Re-project while the very same account and both directory locks are
        // retained. No digest can bridge dropping/reopening the source owner.
        if self
            .account
            .read_history_v5(history, deadline)
            .map_err(permission)?
            != evidence.complete_history
        {
            return Err(BridgeError::Binding);
        }
        self.check_lifetime_until(deadline)
    }
}

struct PreparedTransfer {
    request: ExactRequest,
    evidence: HostRecoveryContinuityEvidenceV5,
    owner: RetainedOwner,
    stream: UnixStream,
    digest: String,
    review_started: Instant,
}
impl PreparedTransfer {
    #[allow(clippy::too_many_arguments)]
    fn prepare(
        request: ExactRequest,
        peer: AuthenticatedPeer,
        stream: UnixStream,
        account: Arc<QuarantinedInformationalAccount>,
        source: NativeAuthorityBinding,
        witness: Arc<NativeInformationalWitness>,
        cancelled: Arc<AtomicBool>,
        dialect: V5TransferDialect,
        parent_channel: Option<crate::native_launch::ParentChannel>,
        completed_continuity: Option<CompletedQuarantinedContinuityV5>,
    ) -> Result<Self> {
        require_bounded(dialect)?;
        crate::authority_bridge::host_recovery_ipc::v5::require_quarantined_informational_endpoint(
        )
        .map_err(review_error)?;
        let review_started = Instant::now();
        let completed_deadline = match (&request, completed_continuity.as_ref()) {
            (ExactRequest::Continuity(_), None) => review_started + REVIEW_WINDOW,
            (ExactRequest::Publication(request), Some(completed)) => {
                completed.require_source(&account)?;
                completed.require_publication(request)?;
                completed.deadline()
            }
            _ => return Err(Error::ReviewMismatch),
        };
        // The original setup, account, native and authenticated-pair lifetimes
        // are upper bounds; approval never renews any one of those owners.
        let original_deadline = account
            .deadline()
            .min(witness.deadline())
            .min(peer.deadline())
            .min(completed_deadline)
            .min(source.deadline().unwrap_or(review_started + REVIEW_WINDOW))
            .min(review_started + REVIEW_WINDOW);
        let request_digest = request.digest().map_err(review_error)?;
        let owner = RetainedOwner {
            account_binding: account.binding(),
            account,
            source,
            witness,
            peer,
            cancelled,
            parent_channel,
            original_deadline,
        };
        // Observe this already-authenticated retained stream again; never open
        // a socket or trust a supplied PID. Its kernel peer must be the same
        // live process as the exact authenticated grant owner before disclosure.
        owner.check_until(original_deadline).map_err(review_error)?;
        let observed = crate::native_peer::PeerProcess::observe(&stream).map_err(review_error)?;
        owner
            .peer
            .peer
            .same_live_process(&observed)
            .map_err(review_error)?;
        let (_, evidence) = owner
            .observe_until(request.continuity(), original_deadline)
            .map_err(review_error)?;
        request.matches_evidence(&evidence).map_err(review_error)?;
        if let Some(completed) = completed_continuity {
            if evidence.digest().map_err(review_error)? != completed.0.evidence_digest {
                return Err(Error::ReviewMismatch);
            }
            // Consumed metadata cannot be reused, even if a later review fails.
            // Fresh source/native/peer/witness owners remain mandatory below.
        }
        let nonce = hex::encode(crate::vault::random::<32>()?);
        let evidence_digest = evidence.digest().map_err(review_error)?;
        let digest = review_digest(&ReviewCommitment {
            purpose: request.purpose(),
            request_digest: &request_digest,
            evidence_digest: &evidence_digest,
            native_entry_digest: owner.source.entry_digest(),
            source_inventory_digest: owner.account.source_inventory_digest(),
            checkpoint_id: owner.account.checkpoint_id(),
            account_id: owner.account.account_id(),
            historical_writer_epoch: owner.account.historical_writer_epoch(),
            grant_id: &owner.peer.grant_id,
            channel_digest: &owner.peer.channel_digest,
            peer_key_digest: &owner.peer.key_digest,
            peer_generation: owner.peer.generation,
            peer_instance: owner.peer.peer.instance(),
            peer_pid: owner.peer.peer.pid(),
            peer_uid: owner.peer.peer.uid(),
            scope: &owner.peer.scope,
            review_nonce: &nonce,
        })?;
        // Enforce bounded serialization before presenting consent, without
        // emitting a frame. These inert IDs are never accepted as live leases.
        drop(
            TransferSender::new(
                TransferMetadata {
                    purpose: request.purpose(),
                    transfer_id: "00".repeat(32),
                    lease_id: "00".repeat(32),
                    request_digest,
                    native_review_digest: digest.clone(),
                    evidence_digest,
                    head_digest: evidence.head.digest.clone(),
                    head_sequence: evidence.head.sequence,
                },
                &evidence,
            )
            .map_err(review_error)?,
        );
        owner.check_until(original_deadline).map_err(review_error)?;
        Ok(Self {
            request,
            evidence,
            owner,
            stream,
            digest,
            review_started,
        })
    }
    fn display(&self) -> Result<String> {
        self.owner
            .check_until(self.owner.original_deadline)
            .map_err(review_error)?;
        let purpose = match &self.request {
            ExactRequest::Continuity(_) => "DISCLOSE QUARANTINED INFORMATIONAL CONTINUITY",
            ExactRequest::Publication(_) => "PUBLISH ONE QUARANTINED INFORMATIONAL HOST GENERATION",
        };
        let request = self.request.display()?;
        let evidence = serde_json::to_string_pretty(&self.evidence).map_err(review_error)?;
        if request
            .len()
            .checked_add(evidence.len())
            .is_none_or(|length| length > DISPLAY_LIMIT)
        {
            return Err(Error::Unavailable);
        }
        let text = format!(
            "{purpose}\n\nRecipient: locally paired application {} (PID {}, UID {}, grant {}).\n\nExact original source checkpoint: {}\nSource inventory commitment: {}\n\nThe retained restored source remains quarantined, historical and read-only. This account-wide disclosure includes agreement, obligation, input/nullifier, amount, fee, authorization, original consent and receipt metadata, even outside the paired agreement. Every admitted origin and permanent account exclusion remains conservative exposure. Construction Reserve and Consume records and transport grants, claimed credentials, reentries, caller/native lineage and retained fences remain unchanged. Consumption, expiry, missing results and historical resolution never prove absence of a signature or refund a permanent charge. Missing local originals or admissions absent from complete witness replay cause refusal.\n\nThe observed session is historical metadata, including paused, revoked or fenced state, never active writer authority. No writer recovery, activation, credential migration, signing, spending, redelivery, submission or financial status is approved. Sequential observations do not establish an atomic global cutoff. External signatures and later activity remain possible.\n\nBounded V5 only: exact evidence up to 1 MiB, at most 32 chunks of 32 KiB, each inside the existing 128 KiB frame ceiling. Fresh complete replay, source-content checks, reconstruction, final authenticated snapshot and admission share one original 30-second window starting at approval, shortened by all original owner deadlines. No chunk or acknowledgement renews it. Already disclosed metadata cannot be recalled after cancellation or failure.\n\nContinuity approval never approves publication. Publication requires this separate exact target/inventory/generation/manifest review and a distinct Admit after complete reconstruction. Its unchanged saved record is audit data, never a reusable admission. Native publication admission uses the actual current native publication lease; the host must separately protect its final durable write. Both source directory locks remain retained throughout. Synchronous source checks are race detectors, with no hard realtime, hostile filesystem-swap or remote-lease guarantee.\n\nExact request:\n{request}\n\nExact complete evidence:\n{evidence}\n\nNative review binding: {}",
            self.owner.peer.label,
            self.owner.peer.peer.pid(),
            self.owner.peer.peer.uid(),
            self.owner.peer.grant_id,
            self.owner.account.checkpoint_id(),
            self.owner.account.source_inventory_digest(),
            self.digest,
        );
        if text.len() > DISPLAY_LIMIT {
            return Err(Error::Unavailable);
        }
        self.owner
            .check_until(self.owner.original_deadline)
            .map_err(review_error)?;
        Ok(text)
    }
    fn approve(
        self,
        decision: NativeDecision,
        authority: &NativeAuthority,
    ) -> Result<ApprovedTransfer> {
        // The actual consuming native click starts the only post-approval
        // window. Queueing this decision for a worker spends that same budget;
        // neither approve nor serve can replace it with worker-start time.
        let approved_at = decision.consumed_at();
        let deadline = transfer_deadline(approved_at, self.owner.original_deadline);
        authority.check_current()?;
        if authority.binding() != self.owner.source
            || decision.binding() != &self.owner.source
            || decision.reviewed_digest() != self.digest
            || approved_at
                .checked_duration_since(self.review_started)
                .is_none_or(|elapsed| elapsed >= REVIEW_WINDOW)
        {
            return Err(Error::ReviewMismatch);
        }
        // No source hash on the native click path. The worker must complete a
        // fresh full replay, projection and source recheck before its first frame.
        self.owner
            .check_lifetime_until(deadline)
            .map_err(review_error)?;
        Ok(ApprovedTransfer {
            prepared: self,
            approved_at,
            deadline,
        })
    }
}

pub(super) struct PreparedQuarantinedContinuityV5(PreparedTransfer);
pub(super) struct PreparedQuarantinedPublicationV5(PreparedTransfer);
pub(super) struct ApprovedQuarantinedContinuityV5(ApprovedTransfer);
pub(super) struct ApprovedQuarantinedPublicationV5(ApprovedTransfer);

macro_rules! prepared_review_api {
    ($prepared:ident, $approved:ident) => {
        impl $prepared {
            pub(super) fn digest(&self) -> &str {
                &self.0.digest
            }
            pub(super) fn display(&self) -> Result<String> {
                self.0.display()
            }
            pub(super) fn approve(
                self,
                decision: NativeDecision,
                authority: &NativeAuthority,
            ) -> Result<$approved> {
                self.0.approve(decision, authority).map($approved)
            }
        }
    };
}
prepared_review_api!(
    PreparedQuarantinedContinuityV5,
    ApprovedQuarantinedContinuityV5
);
prepared_review_api!(
    PreparedQuarantinedPublicationV5,
    ApprovedQuarantinedPublicationV5
);
impl PreparedQuarantinedContinuityV5 {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare(
        request: HostRecoveryContinuityRequestV5,
        peer: AuthenticatedPeer,
        stream: UnixStream,
        account: Arc<QuarantinedInformationalAccount>,
        source: NativeAuthorityBinding,
        witness: Arc<NativeInformationalWitness>,
        cancelled: Arc<AtomicBool>,
        dialect: V5TransferDialect,
        parent_channel: Option<crate::native_launch::ParentChannel>,
    ) -> Result<Self> {
        PreparedTransfer::prepare(
            ExactRequest::Continuity(request),
            peer,
            stream,
            account,
            source,
            witness,
            cancelled,
            dialect,
            parent_channel,
            None,
        )
        .map(Self)
    }
}
impl PreparedQuarantinedPublicationV5 {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare(
        request: HostRecoveryPublicationRequestV5,
        peer: AuthenticatedPeer,
        stream: UnixStream,
        account: Arc<QuarantinedInformationalAccount>,
        source: NativeAuthorityBinding,
        witness: Arc<NativeInformationalWitness>,
        cancelled: Arc<AtomicBool>,
        dialect: V5TransferDialect,
        parent_channel: Option<crate::native_launch::ParentChannel>,
        completed_continuity: CompletedQuarantinedContinuityV5,
    ) -> Result<Self> {
        PreparedTransfer::prepare(
            ExactRequest::Publication(request),
            peer,
            stream,
            account,
            source,
            witness,
            cancelled,
            dialect,
            parent_channel,
            Some(completed_continuity),
        )
        .map(Self)
    }
}
impl ApprovedQuarantinedContinuityV5 {
    pub(super) fn serve(
        self,
    ) -> authority_bridge::Result<Option<CompletedQuarantinedContinuityV5>> {
        match self.0.serve()? {
            TransferOutcome::Continuity(completed) => Ok(Some(*completed)),
            TransferOutcome::Cancelled => Ok(None),
            TransferOutcome::PublicationAdmitted => Err(BridgeError::Binding),
        }
    }
}
impl ApprovedQuarantinedPublicationV5 {
    pub(super) fn serve(self) -> authority_bridge::Result<()> {
        match self.0.serve()? {
            TransferOutcome::PublicationAdmitted | TransferOutcome::Cancelled => Ok(()),
            TransferOutcome::Continuity(_) => Err(BridgeError::Binding),
        }
    }
}
enum TransferOutcome {
    Cancelled,
    Continuity(Box<CompletedQuarantinedContinuityV5>),
    PublicationAdmitted,
}

struct ApprovedTransfer {
    prepared: PreparedTransfer,
    approved_at: Instant,
    deadline: Instant,
}
impl ApprovedTransfer {
    fn serve(mut self) -> authority_bridge::Result<TransferOutcome> {
        let p = &mut self.prepared;
        let deadline = self.deadline;
        p.owner.check_lifetime_until(deadline)?;
        let (history, evidence) = p.owner.observe_until(p.request.continuity(), deadline)?;
        p.request.matches_evidence(&evidence)?;
        evidence.require_unchanged(&p.evidence, self.approved_at.elapsed())?;
        p.owner.check_lifetime_until(deadline)?;
        let lease_id = hex::encode(crate::vault::random::<32>().map_err(permission)?);
        let request_digest = p.request.digest()?;
        let evidence_digest = evidence.digest()?;
        let mut sender = TransferSender::new(
            TransferMetadata {
                purpose: p.request.purpose(),
                transfer_id: hex::encode(crate::vault::random::<32>().map_err(permission)?),
                lease_id: lease_id.clone(),
                request_digest: request_digest.clone(),
                native_review_digest: p.digest.clone(),
                evidence_digest: evidence_digest.clone(),
                head_digest: evidence.head.digest.clone(),
                head_sequence: evidence.head.sequence,
            },
            &evidence,
        )?;
        p.owner.check_lifetime_until(deadline)?;
        let header = sender.begin()?;
        let chunk_count = header.chunk_count;
        write_frame_until(
            &mut p.stream,
            &TransferResponseV1::Begin { header },
            deadline,
        )?;
        p.owner.check_lifetime_until(deadline)?;
        // Only Next is accepted until every bounded chunk has been served. An
        // Admit or cross-purpose frame cannot skip reconstruction or review.
        for _ in 0..chunk_count {
            let frame = read_frame_until(&p.stream, &p.owner.peer.peer, deadline)?;
            p.owner.check_lifetime_until(deadline)?;
            let command: TransferCommandV1 = transfer::decode_frame(&frame)?;
            if matches!(command, TransferCommandV1::Finish {}) {
                sender.finish();
                return Ok(TransferOutcome::Cancelled);
            }
            let chunk = sender.next(&command)?;
            p.owner.check_lifetime_until(deadline)?;
            write_frame_until(
                &mut p.stream,
                &TransferResponseV1::Chunk { chunk },
                deadline,
            )?;
            p.owner.check_lifetime_until(deadline)?;
        }
        let frame = read_frame_until(&p.stream, &p.owner.peer.peer, deadline)?;
        p.owner.check_lifetime_until(deadline)?;
        let command: TransferCommandV1 = transfer::decode_frame(&frame)?;
        if matches!(command, TransferCommandV1::Finish {}) {
            sender.finish();
            return Ok(TransferOutcome::Cancelled);
        }
        sender.accept_complete(&command)?;
        p.owner
            .require_final_snapshot(&history, &evidence, deadline)?;
        let confirmation = sender.confirmation()?;
        p.owner.check_lifetime_until(deadline)?;
        write_frame_until(&mut p.stream, &confirmation, deadline)?;
        p.owner.check_lifetime_until(deadline)?;
        drop(sender);

        match &p.request {
            ExactRequest::Continuity(_) => loop {
                p.owner.check_lifetime_until(deadline)?;
                let frame = read_frame_until(&p.stream, &p.owner.peer.peer, deadline)?;
                p.owner.check_lifetime_until(deadline)?;
                let command: HostContinuityCommandV5 = transfer::decode_frame(&frame)?;
                match command {
                    HostContinuityCommandV5::Finish {} => {
                        // Only this post-reconstruction protocol state may issue
                        // a dormant marker, after fresh complete final checks.
                        p.owner
                            .require_final_snapshot(&history, &evidence, deadline)?;
                        let completed =
                            CompletedQuarantinedContinuityV5(ContinuityCompletionBinding {
                                source_inventory_digest: p
                                    .owner
                                    .account
                                    .source_inventory_digest()
                                    .into(),
                                checkpoint_id: p.owner.account.checkpoint_id().into(),
                                account_id: p.owner.account.account_id().into(),
                                historical_writer_epoch: p.owner.account.historical_writer_epoch(),
                                request: evidence.request.clone(),
                                request_digest: evidence.request.digest()?,
                                evidence_digest: evidence_digest.clone(),
                                original_source_deadline: p.owner.account.deadline(),
                                deadline: p.owner.original_deadline,
                            });
                        p.owner.check_lifetime_until(deadline)?;
                        write_frame_until(
                            &mut p.stream,
                            &HostContinuityResponseV5::Finished {},
                            deadline,
                        )?;
                        p.owner.check_lifetime_until(deadline)?;
                        return Ok(TransferOutcome::Continuity(Box::new(completed)));
                    }
                    HostContinuityCommandV5::CheckCurrent {} => {
                        p.owner
                            .require_final_snapshot(&history, &evidence, deadline)?;
                        write_frame_until(
                            &mut p.stream,
                            &HostContinuityResponseV5::Current {
                                lease_id: lease_id.clone(),
                                evidence_digest: evidence_digest.clone(),
                            },
                            deadline,
                        )?;
                        p.owner.check_lifetime_until(deadline)?;
                    }
                }
            },
            ExactRequest::Publication(request) => {
                let frame = read_frame_until(&p.stream, &p.owner.peer.peer, deadline)?;
                p.owner.check_lifetime_until(deadline)?;
                let command: HostPublicationCommandV5 = transfer::decode_frame(&frame)?;
                match command {
                    HostPublicationCommandV5::Finish {} => {
                        write_frame_until(
                            &mut p.stream,
                            &HostPublicationResponseV5::Finished {},
                            deadline,
                        )?;
                        p.owner.check_lifetime_until(deadline)?;
                        return Ok(TransferOutcome::Cancelled);
                    }
                    HostPublicationCommandV5::Admit {
                        lease_id: supplied,
                        request_digest: supplied_digest,
                    } if supplied == lease_id && supplied_digest == request_digest => {}
                    _ => return Err(BridgeError::Binding),
                }
                request.matches_evidence(&evidence)?;
                // This ends with the exact read-only projection and full source
                // rechecks, immediately before taking the short native fence.
                // Both cooperative directory locks remain retained; hostile
                // same-user swaps are not prevented by this race detector.
                p.owner
                    .require_final_snapshot(&history, &evidence, deadline)?;
                // The actual native instance linearizes this one admission.
                // Only fast lifecycle/deadline checks occur while it is held;
                // no source hashing, SQL replay, witness or socket I/O occurs.
                let native = p.owner.source.publication_lease().map_err(permission)?;
                p.owner.check_lifetime_until(deadline)?;
                let mut window = PublicationWindow::default();
                window.consume(self.approved_at.elapsed())?;
                let record = HostRecoveryPublicationRecordV5 {
                    request: request.clone(),
                    native_review_digest: p.digest.clone(),
                    admission_id: lease_id,
                };
                record.validate()?;
                require_before_deadline(deadline)?;
                // Release the native admission fence before remote I/O. Keep
                // original source locks until this worker/retained owner drops.
                drop(native);
                write_frame_until(
                    &mut p.stream,
                    &HostPublicationResponseV5::Admitted {
                        record: Box::new(record),
                    },
                    deadline,
                )?;
                p.owner.check_lifetime_until(deadline)?;
                Ok(TransferOutcome::PublicationAdmitted)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Inert policy/DTO fixtures only. These tests do not construct an actual
    // native authority/decision, account owner, TLS client, socket or proof.
    fn request() -> HostRecoveryContinuityRequestV5 {
        HostRecoveryContinuityRequestV5 {
            schema_version: 5,
            inventory_digest: "11".repeat(32),
            generation_id: "22".repeat(32),
            account_id: "synthetic-quarantined-account".into(),
            network_profile_id: wholepact_protocol::construction::PROFILE_ID.into(),
            expected_writer_epoch: 7,
            expected_witness: wholepact_authority::WitnessDisclosureDescriptor {
                endpoint: "127.0.0.1:28443".into(),
                server_name: "synthetic.invalid".into(),
                witness_id: "synthetic-witness".into(),
                account_id: "synthetic-quarantined-account".into(),
                network_profile_id: wholepact_protocol::construction::PROFILE_ID.into(),
                policy_digest: "33".repeat(32),
                pinned_server_certificate_digest: "44".repeat(32),
            },
        }
    }
    fn scope(request: &HostRecoveryContinuityRequestV5) -> PairScope {
        PairScope {
            account_id: request.account_id.clone(),
            agreement_id: "synthetic-agreement".into(),
            participant_id: "synthetic-participant".into(),
            manifest_digest: request.inventory_digest.clone(),
            history_read: true,
            authorization_export: true,
            preconstruction_export: false,
        }
    }
    fn completion_metadata(now: Instant) -> ContinuityCompletionBinding {
        let request = request();
        ContinuityCompletionBinding {
            source_inventory_digest: "aa".repeat(32),
            checkpoint_id: "synthetic-checkpoint".into(),
            account_id: request.account_id.clone(),
            historical_writer_epoch: request.expected_writer_epoch,
            request_digest: request.digest().unwrap(),
            request,
            evidence_digest: "bb".repeat(32),
            original_source_deadline: now + REVIEW_WINDOW,
            deadline: now + Duration::from_secs(60),
        }
    }
    #[test]
    fn completed_continuity_metadata_refuses_source_change_expiry_and_deadline_renewal() {
        // Test inert binding policy only, never construct a successful completion
        // marker or a source/native owner from these values.
        let now = Instant::now();
        let metadata = completion_metadata(now);
        metadata
            .require_source_metadata(
                &metadata.source_inventory_digest,
                &metadata.checkpoint_id,
                &metadata.account_id,
                metadata.historical_writer_epoch,
                metadata.deadline,
                now,
            )
            .unwrap();
        for changed in 0..6 {
            let mut inventory = metadata.source_inventory_digest.as_str();
            let mut checkpoint = metadata.checkpoint_id.as_str();
            let mut account = metadata.account_id.as_str();
            let mut epoch = metadata.historical_writer_epoch;
            let mut deadline = metadata.deadline;
            let mut checked_at = now;
            match changed {
                0 => inventory = "changed-source",
                1 => checkpoint = "other-checkpoint",
                2 => account = "other-account",
                3 => epoch += 1,
                4 => deadline += Duration::from_secs(1),
                5 => checked_at = metadata.deadline,
                _ => unreachable!(),
            }
            assert!(
                metadata
                    .require_source_metadata(
                        inventory, checkpoint, account, epoch, deadline, checked_at
                    )
                    .is_err()
            );
        }
    }
    #[test]
    fn completed_continuity_metadata_binds_exact_request_and_evidence_for_separate_publication() {
        let metadata = completion_metadata(Instant::now());
        let request = HostRecoveryPublicationRequestV5 {
            schema_version: 5,
            continuity: metadata.request.clone(),
            target_profile: "/synthetic/host".into(),
            generation_manifest_digest: "cc".repeat(32),
            continuity_evidence_digest: metadata.evidence_digest.clone(),
        };
        metadata.require_publication(&request).unwrap();
        let mut changed = request.clone();
        changed.continuity.generation_id = "dd".repeat(32);
        assert!(metadata.require_publication(&changed).is_err());
        let mut changed = request.clone();
        changed.continuity.inventory_digest = "ee".repeat(32);
        assert!(metadata.require_publication(&changed).is_err());
        let mut changed = request;
        changed.continuity_evidence_digest = "ff".repeat(32);
        assert!(metadata.require_publication(&changed).is_err());
    }

    #[test]
    fn quarantined_transfer_refuses_legacy_dialect_and_scope_substitutions() {
        assert!(require_bounded(V5TransferDialect::SingleFrame).is_err());
        require_bounded(V5TransferDialect::BoundedV1).unwrap();
        let request = request();
        let original = scope(&request);
        require_request_scope(&request, &original, &request.account_id, 7).unwrap();
        for mode in 0..5 {
            let mut changed = original.clone();
            match mode {
                0 => changed.history_read = false,
                1 => changed.authorization_export = false,
                2 => changed.preconstruction_export = true,
                3 => changed.account_id = "other-account".into(),
                4 => changed.manifest_digest = "55".repeat(32),
                _ => unreachable!(),
            }
            assert!(require_request_scope(&request, &changed, &request.account_id, 7).is_err());
        }
        assert!(require_request_scope(&request, &original, "other-account", 7).is_err());
        assert!(require_request_scope(&request, &original, &request.account_id, 8).is_err());
    }
    #[test]
    fn quarantined_approval_deadline_never_renews_original_owner() {
        let now = Instant::now();
        assert_eq!(
            transfer_deadline(now, now + Duration::from_secs(120)),
            now + TRANSFER_WINDOW
        );
        let short = now + Duration::from_secs(4);
        assert_eq!(transfer_deadline(now, short), short);
        assert_eq!(
            transfer_deadline(now + Duration::from_secs(3), short),
            short
        );
        assert_eq!(transfer_deadline(now, now), now);
        assert_eq!(
            transfer_deadline(now, now - Duration::from_secs(1)),
            now - Duration::from_secs(1)
        );
    }
    #[test]
    fn quarantined_native_click_to_worker_queue_delay_spends_original_window() {
        // These are inert clock values only, never a fabricated NativeDecision.
        let worker_start = Instant::now();
        let original_owner_deadline = worker_start + REVIEW_WINDOW;
        let clicked = worker_start - Duration::from_secs(12);
        let deadline = transfer_deadline(clicked, original_owner_deadline);
        assert_eq!(
            deadline.checked_duration_since(worker_start),
            Some(Duration::from_secs(18))
        );
        let expired_click = worker_start - Duration::from_secs(31);
        let expired_deadline = transfer_deadline(expired_click, original_owner_deadline);
        assert!(require_before_deadline(expired_deadline).is_err());
        assert!(expired_deadline < worker_start);
    }
    #[test]
    fn quarantined_review_digest_separates_purpose_and_exact_source_peer_request() {
        let request = request();
        let scope = scope(&request);
        let h = "11".repeat(32);
        let other = "22".repeat(32);
        let make = || ReviewCommitment {
            purpose: TransferPurpose::Continuity,
            request_digest: &h,
            evidence_digest: &h,
            native_entry_digest: &h,
            source_inventory_digest: &h,
            checkpoint_id: "synthetic-checkpoint",
            account_id: &request.account_id,
            historical_writer_epoch: 7,
            grant_id: &h,
            channel_digest: &h,
            peer_key_digest: &h,
            peer_generation: 2,
            peer_instance: "synthetic-peer-instance",
            peer_pid: 123,
            peer_uid: 456,
            scope: &scope,
            review_nonce: &h,
        };
        let original = review_digest(&make()).unwrap();
        for mode in 0..16 {
            let mut changed = make();
            match mode {
                0 => changed.purpose = TransferPurpose::Publication,
                1 => changed.request_digest = &other,
                2 => changed.evidence_digest = &other,
                3 => changed.native_entry_digest = &other,
                4 => changed.source_inventory_digest = &other,
                5 => changed.checkpoint_id = "other-checkpoint",
                6 => changed.account_id = "other-account",
                7 => changed.historical_writer_epoch += 1,
                8 => changed.grant_id = &other,
                9 => changed.channel_digest = &other,
                10 => changed.peer_key_digest = &other,
                11 => changed.peer_generation += 1,
                12 => changed.peer_pid += 1,
                13 => changed.peer_uid += 1,
                14 => changed.review_nonce = &other,
                15 => changed.peer_instance = "other-peer-instance",
                _ => unreachable!(),
            }
            assert_ne!(review_digest(&changed).unwrap(), original);
        }
        let mut other_scope = scope.clone();
        other_scope.participant_id = "another-participant".into();
        let mut changed = make();
        changed.scope = &other_scope;
        assert_ne!(review_digest(&changed).unwrap(), original);
    }
    #[test]
    fn quarantined_publication_cannot_be_parsed_during_bounded_reconstruction_or_continuity() {
        let admit = br#"{"operation":"admit","lease_id":"11","request_digest":"22"}"#;
        assert!(transfer::decode_frame::<TransferCommandV1>(admit).is_err());
        assert!(transfer::decode_frame::<HostContinuityCommandV5>(admit).is_err());
        let current = br#"{"operation":"check_current"}"#;
        assert!(transfer::decode_frame::<HostPublicationCommandV5>(current).is_err());
        let forged_complete = br#"{"operation":"accept_complete","binding":{"transfer_id":"11","begin_digest":"22"},"byte_digest":"33","evidence_digest":"44","admit":true}"#;
        assert!(transfer::decode_frame::<TransferCommandV1>(forged_complete).is_err());
    }
}
