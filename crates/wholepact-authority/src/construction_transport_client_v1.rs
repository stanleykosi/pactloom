//! Exact prepared mTLS construction channel. This module owns the stream and
//! exporter through native review, claim and one Reserve/Consume pair. It never
//! routes through AuthorityClient::call_with: reconnecting would change the
//! reviewed exporter. All work drains inside the ORIGINAL ten-second call budget.
use super::*;
use crate::construction_transport_handoff_v1::*;
use crate::manual_roster_construction_v3::*;
use crate::manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2;
use crate::manual_roster_witness_v2::ManualRosterSessionContinuationV2;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Exact original read clock. The shared high-water is the actual original
/// native read's owner, not a new clock initialized on fresh unlock. This data
/// alone grants nothing; only the private channel issuer can retain it.
struct HandoffClockV1 {
    deadline: Instant,
    expires_at_ms: u64,
    high_water_ms: Arc<AtomicU64>,
    terminal: Arc<AtomicBool>,
}
impl HandoffClockV1 {
    fn check_at(&self, now: u64, monotonic: Instant) -> Result<()> {
        if self.terminal.load(Ordering::Acquire) {
            return Err(AuthorityError::Expired);
        }
        let previous = self.high_water_ms.fetch_max(now, Ordering::AcqRel);
        if now < previous || now >= self.expires_at_ms || monotonic >= self.deadline {
            self.terminal.store(true, Ordering::Release);
            return Err(AuthorityError::Expired);
        }
        Ok(())
    }
    fn check(&self) -> Result<()> {
        self.check_at(now_ms()?, Instant::now())
    }
}

/// Private exact stream owner. No Clone/Serialize/Deserialize, key accessor,
/// generic writer conversion, reconnect, head refresh or replay factory exists.
struct HandoffChannelV1 {
    stream: StreamOwned<ClientConnection, DeadlineSocket>,
    revocation: Arc<HandoffRevocationStateV1>,
    clock: HandoffClockV1,
    certificate_digest: String,
    sent: u8,
}
impl HandoffChannelV1 {
    fn open(
        client: &AuthorityClient,
        original_deadline: Instant,
        expires_at_ms: u64,
        high_water_ms: Arc<AtomicU64>,
        cancellation: ConstructionTransportCancellationV1,
    ) -> Result<Self> {
        let revocation = cancellation.state;
        revocation
            .started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| AuthorityError::Permission)?;
        // Until the owning channel exists, every early return closes this same
        // one-use attempt and any socket already installed for GUI cancellation.
        let opening = OpeningHandoffChannelV1(Some(revocation.clone()));
        let started = Instant::now();
        let deadline = (started + IO_TIMEOUT).min(original_deadline);
        let clock = HandoffClockV1 {
            deadline,
            expires_at_ms,
            high_water_ms,
            terminal: revocation.terminal.clone(),
        };
        clock.check()?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(AuthorityError::Expired)?;
        let socket = TcpStream::connect_timeout(&client.endpoint, remaining)
            .map_err(|_| AuthorityError::Uncertain)?;
        // Publish cancellation of this exact socket BEFORE any TLS I/O. No
        // exporter exists while connect_timeout is pending; cancellation during
        // connect permanently refuses adoption as soon as it returns.
        revocation.install_socket(&socket)?;
        clock.check()?;
        let mut socket = DeadlineSocket { socket, deadline };
        let mut connection =
            ClientConnection::new(client.tls.config.clone(), client.tls.server_name.clone())
                .map_err(|_| AuthorityError::Authentication)?;
        while connection.is_handshaking() {
            clock.check()?;
            connection
                .complete_io(&mut socket)
                .map_err(|_| AuthorityError::Authentication)?;
        }
        let peer = connection
            .peer_certificates()
            .and_then(|c| c.first())
            .ok_or(AuthorityError::Authentication)?;
        if certificate_digest(peer) != client.tls.pinned_certificate
            || connection.alpn_protocol() != Some(ALPN)
        {
            return Err(AuthorityError::Authentication);
        }
        let exporter = Zeroizing::new(
            connection
                .export_keying_material(
                    [0_u8; 32],
                    crate::construction_transport_handoff_v1::EXPORTER_LABEL,
                    None,
                )
                .map_err(|_| AuthorityError::Authentication)?,
        );
        clock.check()?;
        revocation.install_exporter(exporter)?;
        clock.check()?;
        // Disarming this local cleanup transfers exactly the same state into
        // the real channel; the GUI still owns cancellation independently.
        opening.disarm();
        Ok(Self {
            stream: StreamOwned::new(connection, socket),
            revocation,
            clock,
            certificate_digest: client.tls.pinned_certificate.clone(),
            sent: 0,
        })
    }
    fn check_current(&self) -> Result<()> {
        if let Err(error) = self.clock.check() {
            self.revocation.revoke();
            return Err(error);
        }
        Ok(())
    }
    fn with_exporter<T>(&self, operation: impl FnOnce(&[u8; 32]) -> Result<T>) -> Result<T> {
        self.check_current()?;
        let key = self
            .revocation
            .resources
            .lock()
            .map_err(|_| AuthorityError::Permission)?;
        let key = key.exporter.as_ref().ok_or(AuthorityError::Permission)?;
        operation(key)
    }
    fn credential_id(&self) -> Result<String> {
        self.with_exporter(|key| Ok(credential_id(key)))
    }
    fn exporter_commitment(&self) -> Result<String> {
        self.with_exporter(|key| Ok(exporter_commitment(key)))
    }
    fn observe_proof(&self, credential: &str) -> Result<ConstructionTransportProofV1> {
        self.with_exporter(|key| observe_proof(key, key, credential))
    }
    fn mutation_proof(
        &self,
        request: &ConstructionTransportRequestV1,
    ) -> Result<ConstructionTransportProofV1> {
        self.with_exporter(|key| proof(key, key, request))
    }
    fn exchange(&mut self, request: &WireRequest) -> Result<WireResponse> {
        self.check_current()?;
        self.sent = self.sent.checked_add(1).ok_or(AuthorityError::Limit)?;
        if self.sent > 4 {
            return Err(AuthorityError::Limit);
        }
        write_frame(&mut self.stream, request).map_err(|_| AuthorityError::Uncertain)?;
        let response: WireResponse =
            read_frame(&mut self.stream).map_err(|_| AuthorityError::Uncertain)?;
        self.check_current()?;
        match response {
            WireResponse::Rejected(error) => Err(error),
            response => Ok(response),
        }
    }
}
impl Drop for HandoffChannelV1 {
    fn drop(&mut self) {
        // Never block on flushing a lost channel during blur/cancel. Shutdown
        // tears down both directions; Zeroizing destroys the exporter afterward.
        self.stream.conn.send_close_notify();
        self.revocation.revoke();
    }
}

/// Inert GUI-owned cancellation, created and registered BEFORE contact. It has
/// no connection, exporter, credential, native authority or permit constructor.
/// Drop/revoke closes the one subsequently attached exact socket and zeroizes
/// its key, including during handshake or a blocked claim/Reserve worker.
pub struct ConstructionTransportRevocationV1 {
    state: Arc<HandoffRevocationStateV1>,
}
impl ConstructionTransportRevocationV1 {
    pub fn new() -> Self {
        Self {
            state: Arc::new(HandoffRevocationStateV1 {
                resources: std::sync::Mutex::new(HandoffResourcesV1 {
                    socket: None,
                    exporter: None,
                }),
                terminal: Arc::new(AtomicBool::new(false)),
                started: AtomicBool::new(false),
            }),
        }
    }
    pub fn cancellation_token(&self) -> ConstructionTransportCancellationV1 {
        ConstructionTransportCancellationV1 {
            state: self.state.clone(),
        }
    }
    pub fn revoke(&self) {
        self.state.revoke();
    }
}
impl Default for ConstructionTransportRevocationV1 {
    fn default() -> Self {
        Self::new()
    }
}
impl Drop for ConstructionTransportRevocationV1 {
    fn drop(&mut self) {
        self.revoke();
    }
}
/// Cloning this cancellation-only token never creates another attempt. Its
/// shared one-shot opening bit is consumed before connection establishment.
#[derive(Clone)]
pub struct ConstructionTransportCancellationV1 {
    state: Arc<HandoffRevocationStateV1>,
}
struct HandoffResourcesV1 {
    socket: Option<TcpStream>,
    exporter: Option<Zeroizing<[u8; 32]>>,
}
struct HandoffRevocationStateV1 {
    resources: std::sync::Mutex<HandoffResourcesV1>,
    terminal: Arc<AtomicBool>,
    started: AtomicBool,
}
impl HandoffRevocationStateV1 {
    fn install_socket(&self, socket: &TcpStream) -> Result<()> {
        let shutdown = socket.try_clone().map_err(|_| AuthorityError::Uncertain)?;
        let mut resources = self
            .resources
            .lock()
            .map_err(|_| AuthorityError::Permission)?;
        if self.terminal.load(Ordering::Acquire) || resources.socket.is_some() {
            let _ = shutdown.shutdown(std::net::Shutdown::Both);
            return Err(AuthorityError::Permission);
        }
        resources.socket = Some(shutdown);
        Ok(())
    }
    fn install_exporter(&self, exporter: Zeroizing<[u8; 32]>) -> Result<()> {
        let mut resources = self
            .resources
            .lock()
            .map_err(|_| AuthorityError::Permission)?;
        if self.terminal.load(Ordering::Acquire)
            || resources.socket.is_none()
            || resources.exporter.is_some()
        {
            return Err(AuthorityError::Permission);
        }
        resources.exporter = Some(exporter);
        Ok(())
    }
    fn revoke(&self) {
        self.terminal.store(true, Ordering::Release);
        // Held only for bounded HMAC/hash work, never I/O, review, KDF or a
        // publication lease. Even poison cannot retain an orphaned key/socket.
        let mut resources = self.resources.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(socket) = resources.socket.take() {
            let _ = socket.shutdown(std::net::Shutdown::Both);
        }
        resources.exporter.take();
    }
}
struct OpeningHandoffChannelV1(Option<Arc<HandoffRevocationStateV1>>);
impl OpeningHandoffChannelV1 {
    fn disarm(mut self) {
        self.0.take();
    }
}
impl Drop for OpeningHandoffChannelV1 {
    fn drop(&mut self) {
        if let Some(state) = &self.0 {
            state.revoke();
        }
    }
}

/// A genuinely fresh native ceremony owns this value while reviewing the exact
/// exporter binding. The only way forward consumes it once on this same stream.
/// Public DTOs cannot reconstruct it after blur, crash, uncertainty or timeout.
pub struct PreparedConstructionTransportHandoffV1 {
    channel: HandoffChannelV1,
    pending: PendingConstructionTransportGrantV1,
    claim_binding: ConstructionTransportClaimV1,
    owner_certificate_digest: String,
    disclosure: WitnessDisclosureDescriptor,
    history: ReconciledAuthorityHistory,
}
impl AuthorityClient {
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_construction_transport_handoff_v1(
        &self,
        history: ReconciledAuthorityHistory,
        pending: PendingConstructionTransportGrantV1,
        new_caller_binding_digest: String,
        new_native_binding_digest: String,
        original_deadline: Instant,
        original_high_water_ms: Arc<AtomicU64>,
        cancellation: ConstructionTransportCancellationV1,
    ) -> Result<PreparedConstructionTransportHandoffV1> {
        // Source staging does not authorize opening a handoff channel. Keep the
        // public route unavailable until the joined native path is qualified.
        if !crate::COMMON_CONTEXT_V3_ACTIVATION_QUALIFIED {
            return Err(AuthorityError::ConstructionHistoryUnsupported);
        }
        // A fresh unlock must have discarded its original ephemeral writer key.
        // Neither an active nor an acquired original client is a fresh source.
        if self
            .session
            .lock()
            .map_err(|_| AuthorityError::SessionRequired)?
            .is_some()
        {
            return Err(AuthorityError::SessionRequired);
        }
        pending.validate()?;
        hash(&new_caller_binding_digest)?;
        hash(&new_native_binding_digest)?;
        let a = &pending.grant.authorization.authorization;
        history
            .account_use_history
            .require_not_permanently_excluded()?;
        if history.disclosure != self.disclosure_descriptor()
            || history.snapshot.head != pending.committed_head
            || history.snapshot.writer_status != WriterStatus::Active
            || history.snapshot.active_writer_session.as_ref() != Some(&a.original_session)
            || history.snapshot.writer_certificate_digest != self.tls.client_certificate
            || a.original_session.writer_certificate_digest != self.tls.client_certificate
            || history.snapshot.writer_epoch != a.original_session.writer_epoch
            || new_caller_binding_digest == a.original_caller_binding_digest
            || new_native_binding_digest == a.original_native_binding_digest
        {
            return Err(AuthorityError::Authentication);
        }
        history
            .snapshot
            .require_unfenced_transport(&a.original_session.session_id)?;
        let actual = history.construction_transport_history_v1()?;
        if !actual.grants.iter().any(|g| g == &pending)
            || actual
                .credentials
                .iter()
                .any(|c| c.pending_grant == pending)
        {
            return Err(AuthorityError::Conflict);
        }
        let owner_certificate_digest = history.account_policy().owner_certificate_digest.clone();
        pending
            .grant
            .authorization
            .verify(&owner_certificate_digest)?;
        let channel = HandoffChannelV1::open(
            self,
            original_deadline,
            a.expires_at_ms,
            original_high_water_ms,
            cancellation,
        )?;
        let pending_digest = pending.digest()?;
        let claim_binding = ConstructionTransportClaimV1 {
            version: 1,
            operation_id: format!("construct-transport-claim-{pending_digest}"),
            pending_grant_digest: pending_digest.clone(),
            expected_head: pending.committed_head.clone(),
            credential_id: channel.credential_id()?,
            exporter_commitment: channel.exporter_commitment()?,
            new_caller_binding_digest,
            new_native_binding_digest,
            original_host_process_commitment: a.original_host_process_commitment.clone(),
            // Display binding only. The native owner replaces this one field
            // with its actual final decision digest before using its owner key.
            native_review_digest: digest(
                "wholepact:construction-transport-unreviewed:v1",
                &pending_digest,
            )?,
            claimed_at_ms: now_ms()?,
        };
        claim_binding.validate()?;
        channel.clock.check()?;
        Ok(PreparedConstructionTransportHandoffV1 {
            channel,
            pending,
            claim_binding,
            owner_certificate_digest,
            disclosure: self.disclosure_descriptor(),
            history,
        })
    }
}
impl PreparedConstructionTransportHandoffV1 {
    pub fn check_current(&self) -> Result<()> {
        self.channel.check_current()
    }
    /// Inert exact native review material. This does not expose the exporter.
    /// The native decision may replace ONLY native_review_digest before signing.
    pub fn unsigned_claim_binding(&self) -> &ConstructionTransportClaimV1 {
        &self.claim_binding
    }
    pub fn pending_grant(&self) -> &PendingConstructionTransportGrantV1 {
        &self.pending
    }
    pub fn review_digest(&self) -> Result<String> {
        self.check_current()?;
        digest(
            "wholepact:construction-transport-prepared-channel-review:v1",
            &(&self.pending, &self.claim_binding, &self.disclosure),
        )
    }
    pub fn claim(
        mut self,
        signed: SignedConstructionTransportClaimV1,
    ) -> Result<AuthenticatedConstructionTransportV1> {
        self.check_current()?;
        signed.verify(&self.owner_certificate_digest)?;
        let mut exact = self.claim_binding.clone();
        exact.native_review_digest = signed.claim.native_review_digest.clone();
        if signed.claim != exact
            || signed.claim.native_review_digest == self.claim_binding.native_review_digest
        {
            return Err(AuthorityError::InvalidBinding);
        }
        let response = self
            .channel
            .exchange(&WireRequest::ClaimConstructionTransport {
                claim: Box::new(signed.clone()),
            })?;
        let WireResponse::ConstructionTransportClaimed(credential) = response else {
            return Err(AuthorityError::InvalidBinding);
        };
        credential.validate()?;
        if credential.pending_grant != self.pending
            || credential.signed_claim != signed
            || credential.credential_id() != self.channel.credential_id()?
        {
            return Err(AuthorityError::Authentication);
        }
        self.check_current()?;
        Ok(AuthenticatedConstructionTransportV1 {
            channel: self.channel,
            credential: *credential,
            disclosure: self.disclosure,
            history: self.history,
        })
    }
}

/// Purpose-distinct live authority with no conversion into WriterSession. This
/// has no signing, dispatch, ordinary/offline authorization or recovery method.
pub struct AuthenticatedConstructionTransportV1 {
    channel: HandoffChannelV1,
    credential: ConstructionTransportCredentialV1,
    disclosure: WitnessDisclosureDescriptor,
    history: ReconciledAuthorityHistory,
}
impl AuthenticatedConstructionTransportV1 {
    pub fn credential(&self) -> &ConstructionTransportCredentialV1 {
        &self.credential
    }
    pub fn check_current(&self) -> Result<()> {
        self.channel.check_current()
    }
    pub fn authenticated_witness_certificate_digest(&self) -> &str {
        &self.channel.certificate_digest
    }
    /// Consumes the local observation attempt, even if the server result is lost.
    pub fn observe(mut self) -> Result<ObservedConstructionTransportV1> {
        self.check_current()?;
        let observed = Instant::now();
        let observed_at_ms = now_ms()?;
        let credential_id = self.credential.credential_id().to_owned();
        let proof = self.channel.observe_proof(&credential_id)?;
        let response = self
            .channel
            .exchange(&WireRequest::ObserveConstructionTransport {
                credential_id,
                proof,
            })?;
        let WireResponse::ConstructionTransportObserved(observation) = response else {
            return Err(AuthorityError::InvalidBinding);
        };
        if observation.version != 1
            || observation.credential != self.credential
            || observation.snapshot.head != self.credential.claimed_head
        {
            return Err(AuthorityError::Authentication);
        }
        check_construction_snapshot(&observation.snapshot, &self.credential, &self.disclosure)?;
        let mut expected = self.history.snapshot.clone();
        expected.head = observation.snapshot.head.clone();
        expected.last_witness_time_ms = observation.snapshot.last_witness_time_ms;
        expected
            .transport_fences
            .as_mut()
            .ok_or(AuthorityError::Authentication)?
            .fenced_session_ids
            .insert(
                self.credential
                    .authorization()
                    .original_session
                    .session_id
                    .clone(),
            );
        if expected != observation.snapshot {
            return Err(AuthorityError::Authentication);
        }
        check_handoff_committed_head(
            &self.credential.pending_grant.committed_head,
            &self.credential.claimed_head,
            AuthorityMutation::ClaimConstructionTransportV1(Box::new(
                self.credential.signed_claim.clone(),
            )),
            observation.snapshot.last_witness_time_ms,
            &self
                .credential
                .authorization()
                .original_session
                .writer_certificate_digest,
        )?;
        self.history
            .construction_transport_history
            .credentials
            .push(self.credential.clone());
        advance_verified_history(
            &mut self.history,
            &observation.snapshot,
            &self.credential.signed_claim.claim.operation_id,
        )?;
        self.check_current()?;
        Ok(ObservedConstructionTransportV1 {
            transport: self,
            snapshot: observation.snapshot,
            observed,
            observed_at_ms,
        })
    }
}

pub struct ObservedConstructionTransportV1 {
    transport: AuthenticatedConstructionTransportV1,
    snapshot: AccountSnapshot,
    observed: Instant,
    observed_at_ms: u64,
}
impl ObservedConstructionTransportV1 {
    /// Complete retained pre-grant history plus this channel's exact authenticated
    /// immediate claim append. No caller snapshot or archive can populate it.
    pub fn history(&self) -> &ReconciledAuthorityHistory {
        &self.transport.history
    }
    pub fn credential(&self) -> &ConstructionTransportCredentialV1 {
        self.transport.credential()
    }
    pub fn snapshot(&self) -> &AccountSnapshot {
        &self.snapshot
    }
    pub fn observed_at_ms(&self) -> u64 {
        self.observed_at_ms
    }
    pub fn observation_age(&self) -> Duration {
        self.observed.elapsed()
    }
    pub fn check_current(&self) -> Result<()> {
        self.transport.check_current()
    }
    /// A separate genuine full-proposal native decision must own this call.
    /// The exact one-use transport and original economic request both move once.
    pub fn reserve(
        mut self,
        extension: &ManualRosterEnrollmentExtensionV2,
        continuation: &ManualRosterSessionContinuationV2,
        request: &ManualRosterConstructionReservationRequestV3,
    ) -> Result<AuthenticatedConstructionTransportReservationV1> {
        self.check_current()?;
        request.validate_for(extension, continuation)?;
        let authorization = self.credential().authorization().clone();
        if request.expected_head != self.snapshot.head
            || request.session_id != authorization.original_session.session_id
            || request.writer_epoch != authorization.original_session.writer_epoch
            || request.attempt_digest != authorization.attempt_digest
            || request.attempt_sequence != authorization.attempt_sequence
            || request.invocation_digest()? != authorization.invocation_digest
            || request.construction.admission_expires_at_ms > authorization.expires_at_ms
        {
            return Err(AuthorityError::InvalidBinding);
        }
        let wire = ConstructionTransportRequestV1 {
            version: 1,
            credential_id: self.credential().credential_id().into(),
            mutation: ConstructionTransportMutationV1::Reserve(Box::new(request.clone())),
        };
        let proof = self.transport.channel.mutation_proof(&wire)?;
        let response =
            self.transport
                .channel
                .exchange(&WireRequest::MutateConstructionTransport {
                    request: Box::new(wire.clone()),
                    proof,
                })?;
        let WireResponse::Mutation(MutationResult::ConstructionTransportReservedV1(record)) =
            response
        else {
            return Err(AuthorityError::InvalidBinding);
        };
        record.original.validate_for(extension, continuation)?;
        if record.credential_id != self.credential().credential_id()
            || record.original.request != *request
            || record.extension != *extension
            || record.continuation != *continuation
            || record.original.session != authorization.original_session
        {
            return Err(AuthorityError::Authentication);
        }
        check_construction_snapshot(
            &record.original.snapshot,
            self.credential(),
            &self.transport.disclosure,
        )?;
        let mut expected = self.snapshot.clone();
        expected.head = record.original.snapshot.head.clone();
        expected.last_witness_time_ms = record.original.admitted_at_ms;
        expected.outstanding_debit_zatoshis = expected
            .outstanding_debit_zatoshis
            .checked_add(record.original.reserved_debit_zatoshis)
            .ok_or(AuthorityError::Limit)?;
        expected.reserved_input_value_zatoshis = expected
            .reserved_input_value_zatoshis
            .checked_add(record.original.reserved_input_value_zatoshis)
            .ok_or(AuthorityError::Limit)?;
        expected.outstanding_reservations = expected
            .outstanding_reservations
            .checked_add(1)
            .ok_or(AuthorityError::Limit)?;
        if record.original.snapshot != expected {
            return Err(AuthorityError::Authentication);
        }
        check_handoff_committed_head(
            &request.expected_head,
            &record.original.snapshot.head,
            AuthorityMutation::UseConstructionTransportV1(Box::new(wire)),
            record.original.admitted_at_ms,
            &authorization.original_session.writer_certificate_digest,
        )?;
        self.transport
            .history
            .construction_transport_history
            .reservations
            .push((*record).clone());
        advance_verified_history(
            &mut self.transport.history,
            &record.original.snapshot,
            &request.construction.operation_id,
        )?;
        self.check_current()?;
        Ok(AuthenticatedConstructionTransportReservationV1 {
            transport: self.transport,
            record: *record,
            extension: extension.clone(),
            continuation: continuation.clone(),
        })
    }
}

pub struct AuthenticatedConstructionTransportReservationV1 {
    transport: AuthenticatedConstructionTransportV1,
    record: ConstructionTransportReservationRecordV1,
    extension: ManualRosterEnrollmentExtensionV2,
    continuation: ManualRosterSessionContinuationV2,
}
impl AuthenticatedConstructionTransportReservationV1 {
    pub fn history(&self) -> &ReconciledAuthorityHistory {
        &self.transport.history
    }
    pub fn record(&self) -> &ConstructionTransportReservationRecordV1 {
        &self.record
    }
    pub fn credential(&self) -> &ConstructionTransportCredentialV1 {
        self.transport.credential()
    }
    pub fn check_current(&self) -> Result<()> {
        self.transport.check_current()
    }
    /// Consumes the actual local reservation and exact channel. No result, error
    /// or retry can reconstruct this wrapper from historical consumed evidence.
    pub fn consume(
        mut self,
        request: &ManualRosterConstructionConsumeRequestV3,
    ) -> Result<AuthenticatedConstructionTransportContributionV1> {
        self.check_current()?;
        request.validate_for(&self.record.original, &self.extension, &self.continuation)?;
        let wire = ConstructionTransportRequestV1 {
            version: 1,
            credential_id: self.credential().credential_id().into(),
            mutation: ConstructionTransportMutationV1::Consume(Box::new(request.clone())),
        };
        let proof = self.transport.channel.mutation_proof(&wire)?;
        let response =
            self.transport
                .channel
                .exchange(&WireRequest::MutateConstructionTransport {
                    request: Box::new(wire.clone()),
                    proof,
                })?;
        let WireResponse::Mutation(MutationResult::ConstructionTransportConsumedV1(consumed)) =
            response
        else {
            return Err(AuthorityError::InvalidBinding);
        };
        consumed.original.validate_for(
            &self.record.original,
            &self.extension,
            &self.continuation,
        )?;
        if consumed.credential_id != self.credential().credential_id()
            || consumed.original.request != *request
        {
            return Err(AuthorityError::Authentication);
        }
        check_construction_snapshot(
            &consumed.original.snapshot,
            self.credential(),
            &self.transport.disclosure,
        )?;
        check_handoff_committed_head(
            &request.expected_head,
            &consumed.original.snapshot.head,
            AuthorityMutation::UseConstructionTransportV1(Box::new(wire)),
            consumed.original.consumed_at_ms,
            &self
                .credential()
                .authorization()
                .original_session
                .writer_certificate_digest,
        )?;
        self.transport
            .history
            .construction_transport_history
            .consumptions
            .push((*consumed).clone());
        advance_verified_history(
            &mut self.transport.history,
            &consumed.original.snapshot,
            &request.operation_id,
        )?;
        self.check_current()?;
        // The exporter/stream is destroyed when the consumed transport drops.
        // The one-use contribution retains exact original clock and lineage only.
        let clock = HandoffClockV1 {
            deadline: self.transport.channel.clock.deadline,
            expires_at_ms: self.transport.channel.clock.expires_at_ms,
            high_water_ms: self.transport.channel.clock.high_water_ms.clone(),
            // Closing the key-bearing transport cannot undo a committed Consume.
            // This key-free result still retains the unchanged original bounds.
            terminal: Arc::new(AtomicBool::new(false)),
        };
        Ok(AuthenticatedConstructionTransportContributionV1 {
            credential: self.transport.credential.clone(),
            reservation: self.record,
            consumed: *consumed,
            clock,
            history: self.transport.history,
        })
    }
}

pub struct AuthenticatedConstructionTransportContributionV1 {
    credential: ConstructionTransportCredentialV1,
    reservation: ConstructionTransportReservationRecordV1,
    consumed: ConstructionTransportConsumedRecordV1,
    clock: HandoffClockV1,
    history: ReconciledAuthorityHistory,
}
impl AuthenticatedConstructionTransportContributionV1 {
    pub fn history(&self) -> &ReconciledAuthorityHistory {
        &self.history
    }
    pub fn credential(&self) -> &ConstructionTransportCredentialV1 {
        &self.credential
    }
    pub fn reservation(&self) -> &ConstructionTransportReservationRecordV1 {
        &self.reservation
    }
    pub fn consumed(&self) -> &ConstructionTransportConsumedRecordV1 {
        &self.consumed
    }
    pub fn check_current(&self) -> Result<()> {
        self.clock.check()
    }
}
fn check_construction_snapshot(
    snapshot: &AccountSnapshot,
    credential: &ConstructionTransportCredentialV1,
    disclosure: &WitnessDisclosureDescriptor,
) -> Result<()> {
    let a = credential.authorization();
    let fences = snapshot
        .transport_fences
        .as_ref()
        .ok_or(AuthorityError::Authentication)?;
    if fences.version != 1
        || !fences
            .fenced_session_ids
            .contains(&a.original_session.session_id)
        || snapshot.account_id != disclosure.account_id
        || snapshot.network_profile_id != disclosure.network_profile_id
        || snapshot.witness_id != disclosure.witness_id
        || snapshot.policy_digest != disclosure.policy_digest
        || snapshot.active_writer_session.as_ref() != Some(&a.original_session)
        || snapshot.writer_certificate_digest != a.original_session.writer_certificate_digest
        || snapshot.writer_epoch != a.original_session.writer_epoch
        || snapshot.writer_status != WriterStatus::Active
        || snapshot
            .account_use_checkpoint
            .as_ref()
            .is_some_and(|c| c.permanent_exclusion_digest.is_some())
    {
        return Err(AuthorityError::Authentication);
    }
    hash(&snapshot.head.digest)
}

fn check_handoff_committed_head(
    previous: &AuthorityHead,
    committed: &AuthorityHead,
    mutation: AuthorityMutation,
    time: u64,
    writer_certificate: &str,
) -> Result<()> {
    let event = crate::policy::Event {
        original_request_link: None,
        mutation,
        authenticated_certificate_digest: writer_certificate.into(),
        witness_time_ms: time,
        // Deliberately no old writer-HMAC authentication claim on new proof events.
        writer_session_id: None,
    };
    if previous.sequence.checked_add(1) != Some(committed.sequence)
        || committed.digest != digest("wholepact:authority-append:v2", &(previous, event))?
    {
        return Err(AuthorityError::Authentication);
    }
    Ok(())
}

/// Only called after a same-stream response independently checks the exact append
/// hash, prior head and all economic delta fields. It advances retained verified
/// history by ONE event; it never repairs, refreshes or filters a changed head.
fn advance_verified_history(
    history: &mut ReconciledAuthorityHistory,
    snapshot: &AccountSnapshot,
    operation_id: &str,
) -> Result<()> {
    if history.snapshot.head.sequence.checked_add(1) != Some(snapshot.head.sequence)
        || !history.committed_operation_ids.insert(operation_id.into())
        || history
            .history_heads
            .insert(snapshot.head.sequence, snapshot.head.digest.clone())
            .is_some()
    {
        return Err(AuthorityError::Authentication);
    }
    history.snapshot = snapshot.clone();
    if let Some(attempt) = &mut history.manual_roster_attempt {
        attempt.snapshot = snapshot.clone();
    }
    if let Some(attempt) = &mut history.manual_attempt {
        attempt.snapshot = snapshot.clone();
    }
    history
        .construction_transport_history
        .validate_for(&history.account_policy, snapshot)?;
    history
        .construction_history_with_transport_v1()?
        .validate()?;
    Ok(())
}

#[cfg(test)]
mod clock_tests {
    use super::*;
    // Pure synthetic clock qualification only. These helpers create no socket,
    // certificate, native decision, storage key, provider read, proof or funds.
    #[test]
    fn cancellation_exists_before_contact_and_destroys_synthetic_key_slot() {
        let owner = ConstructionTransportRevocationV1::new();
        let token = owner.cancellation_token();
        let clone = token.clone();
        assert!(token.state.resources.lock().unwrap().socket.is_none());
        // Explicit inert synthetic bytes only, no TLS/certificate/live secret.
        token.state.resources.lock().unwrap().exporter = Some(Zeroizing::new([0xa5; 32]));
        drop(owner);
        assert!(clone.state.terminal.load(Ordering::Acquire));
        assert!(token.state.resources.lock().unwrap().exporter.is_none());
        assert!(
            clone
                .state
                .install_exporter(Zeroizing::new([0x5a; 32]))
                .is_err()
        );
    }
    #[test]
    fn cloned_cancellation_tokens_share_one_open_attempt() {
        let owner = ConstructionTransportRevocationV1::new();
        let token = owner.cancellation_token();
        let clone = token.clone();
        assert!(
            token
                .state
                .started
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        );
        assert!(
            clone
                .state
                .started
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        );
    }
    #[test]
    fn retained_handoff_clock_never_renews_deadline_or_wall_high_water() {
        let start = Instant::now();
        let high_water = Arc::new(AtomicU64::new(10));
        let clock = HandoffClockV1 {
            deadline: start + Duration::from_millis(10),
            expires_at_ms: 20,
            high_water_ms: high_water.clone(),
            terminal: Arc::new(AtomicBool::new(false)),
        };
        assert!(clock.check_at(11, start).is_ok());
        assert_eq!(high_water.load(Ordering::Acquire), 11);
        assert_eq!(clock.check_at(10, start), Err(AuthorityError::Expired));
        // Catching wall time back up never revives a failed attempt.
        assert_eq!(clock.check_at(12, start), Err(AuthorityError::Expired));
        assert_eq!(clock.check_at(20, start), Err(AuthorityError::Expired));
        assert_eq!(
            clock.check_at(21, start + Duration::from_millis(10)),
            Err(AuthorityError::Expired)
        );
    }
}
