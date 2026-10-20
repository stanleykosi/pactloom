//! Concrete installed-origin request client. No externally implemented trait,
//! caller-provided response parser, verification boolean or raw socket can mint
//! either opaque lease. Endpoint paths choose availability, never trust.
use crate::manual_continuation_v2::{
    HostManualEnrollmentContinuationRequestV2, ManualEnrollmentContinuationEvidenceV2,
};
use crate::{
    framing, hash, label, manual::*, native_peer::PeerProcess, Error, InstalledSignerProvider,
    Result,
};
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{ffi::OsStrExt, net::UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Mutex,
    },
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

const MAX_LEASE: Duration = Duration::from_secs(30);
const MAX_CURRENT_WAIT: Duration = Duration::from_secs(2);
const MAX_MANUAL_FRAME: usize = 128 * 1024;

/// Exact existing request-only pairing wire scope. The installed signer requires
/// its independent native pairing decision; this structure cannot grant access.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairScope {
    pub account_id: String,
    pub agreement_id: String,
    pub participant_id: String,
    pub manifest_digest: String,
    #[serde(default)]
    pub history_read: bool,
    #[serde(default)]
    pub authorization_export: bool,
    #[serde(default)]
    pub preconstruction_export: bool,
}
impl PairScope {
    pub fn validate(&self) -> Result<()> {
        for value in [&self.account_id, &self.agreement_id, &self.participant_id] {
            label(value)?;
        }
        hash(&self.manifest_digest)
    }
}
/// Inert commitment helper. Only the actual paired client/native peer can
/// establish that these fields came from its current grant and kernel channel.
pub fn manual_current_caller_binding_digest(grant_id: &str, scope: &PairScope) -> Result<String> {
    hash(grant_id)?;
    scope.validate()?;
    crate::digest(
        "wholepact:manual-current-caller-binding:v1",
        &(grant_id, scope),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PairResponse {
    schema_version: u16,
    accepted: bool,
    reason_code: String,
    grant_id: String,
    token_hex: String,
    expires_in_seconds: u64,
}
impl Drop for PairResponse {
    fn drop(&mut self) {
        self.token_hex.zeroize();
    }
}
struct ClientGrant {
    grant_id: String,
    token_hex: Zeroizing<String>,
    expires: Instant,
}

/// Installed signer plus exact native-approved request-only pairing. Every
/// enrollment/action still requires a new concrete signer/witness decision.
pub struct NativeManualClient {
    provider: InstalledSignerProvider,
    socket: PathBuf,
    peer: PeerProcess,
    scope: PairScope,
    grant: ClientGrant,
    active_leases: AtomicUsize,
    /// Irreversible failed/cancelled acknowledged handoff; never reset by re-pairing.
    handoff: HandoffState,
}
impl NativeManualClient {
    /// Binding data from the actual current authenticated grant and scope.
    pub fn current_caller_binding_digest(&self) -> Result<String> {
        self.check_channel()?;
        manual_current_caller_binding_digest(&self.grant.grant_id, &self.scope)
    }

    pub fn launch_and_pair(
        provider: InstalledSignerProvider,
        application_label: &str,
        scope: PairScope,
    ) -> Result<Self> {
        provider.launch_native()?;
        let endpoint = provider.wait_native_endpoint(Duration::from_secs(120))?;
        Self::pair(provider, &endpoint, application_label, scope)
    }
    /// The socket path is a transport locator only; no caller path can replace
    /// the fixed installed provider root or the kernel-observed signer image.
    pub fn pair(
        provider: InstalledSignerProvider,
        socket: &Path,
        application_label: &str,
        scope: PairScope,
    ) -> Result<Self> {
        Self::begin_pair_before(
            provider,
            socket,
            application_label,
            scope,
            Instant::now()
                .checked_add(Duration::from_secs(120))
                .ok_or(Error::Permission)?,
        )?
        .finish()
    }
    /// Restriction-only deadline. This finite phase sends the exact request-only
    /// scope; the caller can guard it with its own concrete native disclosure
    /// decision. No callback or caller approval flag enters this crate.
    pub fn begin_pair_before(
        provider: InstalledSignerProvider,
        socket: &Path,
        application_label: &str,
        scope: PairScope,
        deadline: Instant,
    ) -> Result<PendingNativeManualPair> {
        label(application_label)?;
        scope.validate()?;
        let mut stream =
            connect_local_before(socket, restricted_phase(deadline, MAX_CURRENT_WAIT)?)?;
        framing::enable_credentials(stream.as_raw_fd())?;
        let peer = provider.verify_server(&stream)?;
        let started = Instant::now();
        write_frame_until(
            &mut stream,
            &serde_json::json!({
                "command":"request_pairing", "schema_version":1,
                "application_label":application_label, "scope":scope,
            }),
            restricted_phase(deadline, MAX_CURRENT_WAIT)?,
            None,
        )?;
        remaining_before(deadline)?;
        Ok(PendingNativeManualPair {
            provider,
            socket: socket.into(),
            peer,
            scope,
            stream,
            started,
            deadline,
        })
    }
    /// Submit reviewed host claims to the same actual paired signer process.
    /// The pairing manifest slot commits this request-only enrollment intent,
    /// not a transaction manifest. Only an acknowledgement is returned; exact
    /// private signer-derived terms require a separate native-approved export.
    pub fn submit_enrollment_intent(&self, intent: &HostManualEnrollmentIntent) -> Result<()> {
        self.submit_enrollment_intent_before(intent, self.grant.expires)
    }
    /// Deadline restricts only; current installed channel and exact original
    /// request-only pairing remain independently required.
    pub fn submit_enrollment_intent_before(
        &self,
        intent: &HostManualEnrollmentIntent,
        deadline: Instant,
    ) -> Result<()> {
        require_intent_pair_scope(&self.scope, intent)?;
        let deadline = deadline.min(self.grant.expires);
        let stream = self.open_request_before(
            serde_json::json!({
                "operation":"request_born_manual_enrollment_intent", "request":intent
            }),
            deadline,
        )?;
        let bytes = framing::read_frame_with_deadline(
            &stream,
            &self.peer,
            remaining_before(deadline)?.min(MAX_CURRENT_WAIT),
        )?;
        if bytes.len() > MAX_MANUAL_FRAME {
            return Err(Error::Limit);
        }
        require_request_only_ack(&bytes)?;
        remaining_before(deadline)?;
        self.check_channel()
    }
    pub fn acquire_enrollment(
        &self,
        request: &HostManualEnrollmentRequest,
    ) -> Result<ManualEnrollmentLease<'_>> {
        self.begin_enrollment_before(
            request,
            Instant::now()
                .checked_add(Duration::from_secs(120))
                .ok_or(Error::Permission)?,
        )?
        .finish()
    }
    /// Sends one exact request in a bounded phase, returns an inert pending
    /// channel. Neither this object nor any saved response is authority.
    pub fn begin_enrollment_before(
        &self,
        request: &HostManualEnrollmentRequest,
        deadline: Instant,
    ) -> Result<PendingManualEnrollment<'_>> {
        request.validate()?;
        self.require_scope(&request.terms)?;
        let deadline = deadline.min(self.grant.expires);
        remaining_before(deadline)?;
        let slot = self.acquire_slot()?;
        let stream = self.open_request_before(
            serde_json::json!({
                "operation":"request_born_manual_enrollment", "request":request
            }),
            deadline,
        )?;
        Ok(PendingManualEnrollment {
            client: self,
            request: request.clone(),
            pending: PendingStream(Some(stream)),
            slot,
            deadline,
        })
    }
    /// Sends a distinct V2 request only on its exact fresh native-approved
    /// pairing. The deadline restricts; it cannot create source permission.
    pub fn begin_enrollment_continuation_v2_before(
        &self,
        request: &HostManualEnrollmentContinuationRequestV2,
        deadline: Instant,
    ) -> Result<PendingManualEnrollmentContinuationV2<'_>> {
        request.validate()?;
        self.require_scope(&request.enrollment.terms)?;
        require_continuation_pair_scope(&self.scope, request)?;
        let deadline = deadline.min(self.grant.expires);
        remaining_before(deadline)?;
        let slot = self.acquire_slot()?;
        let stream = self.open_request_before(
            serde_json::json!({
                "operation":"request_born_manual_enrollment_continuation_v2", "request":request,
            }),
            deadline,
        )?;
        Ok(PendingManualEnrollmentContinuationV2 {
            client: self,
            request: request.clone(),
            pending: PendingStream(Some(stream)),
            slot,
            deadline,
        })
    }
    pub fn acquire_action(
        &self,
        request: &HostManualActionRequest,
    ) -> Result<ManualActionLease<'_>> {
        request.validate()?;
        self.require_scope(&request.enrollment)?;
        if request.intent.manifest_digest != self.scope.manifest_digest {
            return Err(Error::Binding);
        }
        let slot = self.acquire_slot()?;
        let stream = self.open_request(serde_json::json!({
            "operation":"request_born_manual_action", "request":request}))?;
        let mut pending = PendingStream(Some(stream));
        let response = read_response(pending.stream()?, &self.peer, Duration::from_secs(120))?;
        let ManualAdmissionResponse::ActionHeld { lease_id, evidence } = response else {
            return Err(Error::Permission);
        };
        hash(&lease_id)?;
        evidence.validate()?;
        if &evidence.request != request {
            return Err(Error::Binding);
        }
        let observed = Instant::now();
        let observed_at_ms = now_ms()?;
        let lifetime = original_deadline_budget(
            evidence.admission.admitted_at_ms,
            evidence.admission.admission_deadline_ms,
            observed_at_ms,
        )?;
        let original_deadline = Some((observed_at_ms, evidence.admission.admission_deadline_ms));
        let lease = ManualActionLease {
            held: HeldLease {
                client: self,
                stream: Mutex::new(pending.take()?),
                lease_id,
                evidence_digest: evidence.digest()?,
                started: observed,
                lifetime,
                original_deadline,
                failed: AtomicBool::new(false),
                completion: CompletionState::Legacy,
                _slot: slot,
            },
            evidence: *evidence,
        };
        lease.check_current()?;
        Ok(lease)
    }
    fn require_scope(&self, terms: &BornManualEnrollmentTerms) -> Result<()> {
        if terms.identity.account_id != self.scope.account_id
            || terms.scope.agreement_id != self.scope.agreement_id
            || terms.scope.participant_id != self.scope.participant_id
        {
            return Err(Error::Binding);
        }
        self.check_channel()
    }
    fn check_channel(&self) -> Result<()> {
        self.handoff.check()?;
        if Instant::now() >= self.grant.expires {
            return Err(Error::Permission);
        }
        self.peer.check_alive()
    }
    fn open_request(&self, request: serde_json::Value) -> Result<UnixStream> {
        self.open_request_before(request, self.grant.expires)
    }
    fn open_request_before(
        &self,
        request: serde_json::Value,
        deadline: Instant,
    ) -> Result<UnixStream> {
        self.open_request_before_bounded(request, deadline, MAX_MANUAL_FRAME)
    }
    fn open_request_before_bounded(
        &self,
        request: serde_json::Value,
        deadline: Instant,
        max_frame: usize,
    ) -> Result<UnixStream> {
        self.check_channel()?;
        let deadline = deadline.min(self.grant.expires);
        let mut stream =
            connect_local_before(&self.socket, restricted_phase(deadline, MAX_CURRENT_WAIT)?)?;
        framing::enable_credentials(stream.as_raw_fd())?;
        let actual = self.provider.verify_server(&stream)?;
        self.peer.same_live_process(&actual)?;
        write_frame_until_bounded(
            &mut stream,
            &serde_json::json!({
                "command":"request", "schema_version":1,
                "grant_id":self.grant.grant_id, "token_hex":self.grant.token_hex.as_str(),
                "request":request,
            }),
            restricted_phase(deadline, MAX_CURRENT_WAIT)?,
            None,
            max_frame,
        )?;
        remaining_before(deadline)?;
        self.check_channel()?;
        Ok(stream)
    }
    fn acquire_slot(&self) -> Result<LeaseSlot<'_>> {
        let mut observed = self.active_leases.load(Ordering::Acquire);
        loop {
            if observed >= 8 {
                return Err(Error::Limit);
            }
            match self.active_leases.compare_exchange_weak(
                observed,
                observed + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(LeaseSlot(&self.active_leases)),
                Err(current) => observed = current,
            }
        }
    }
}

/// Inert outstanding request-only pair exchange. It holds the actual verified
/// channel, never native approval or permission to append a record.
pub struct PendingNativeManualPair {
    provider: InstalledSignerProvider,
    socket: PathBuf,
    peer: PeerProcess,
    scope: PairScope,
    stream: UnixStream,
    started: Instant,
    deadline: Instant,
}
impl PendingNativeManualPair {
    /// Waits outside the Host's native terminal lock. The original caller
    /// deadline cannot be renewed by delay, progress or server-reported TTL.
    pub fn finish(self) -> Result<NativeManualClient> {
        self.finish_checked(|| Ok(()))
    }
    /// Caller cancellation can only narrow mandatory installed-peer/grant checks.
    pub fn finish_checked(
        self,
        mut check_current: impl FnMut() -> Result<()>,
    ) -> Result<NativeManualClient> {
        check_current()?;
        let bytes = framing::read_frame_capped_checked_until(
            &self.stream,
            &self.peer,
            MAX_MANUAL_FRAME,
            self.deadline,
            &mut check_current,
        )?;
        check_current()?;
        let response: PairResponse = serde_json::from_slice(&bytes).map_err(|_| Error::Ipc)?;
        if response.schema_version != 1
            || !response.accepted
            || response.reason_code != "LOCAL_PROCESS_REQUEST_SCOPE"
            || response.expires_in_seconds == 0
            || response.expires_in_seconds > 900
        {
            return Err(Error::Permission);
        }
        hash(&response.grant_id)?;
        hash(&response.token_hex)?;
        self.peer.check_alive()?;
        remaining_before(self.deadline)?;
        let client = NativeManualClient {
            provider: self.provider,
            socket: self.socket,
            peer: self.peer,
            scope: self.scope,
            grant: ClientGrant {
                grant_id: response.grant_id.clone(),
                token_hex: Zeroizing::new(response.token_hex.clone()),
                expires: self
                    .started
                    .checked_add(Duration::from_secs(response.expires_in_seconds))
                    .ok_or(Error::Permission)?
                    .min(self.deadline),
            },
            active_leases: AtomicUsize::new(0),
            handoff: HandoffState::new(),
        };
        // Same token-possession handshake on the exact installed peer. Caller
        // cancellation narrows both response phases and final publication.
        check_current()?;
        let stream =
            client.open_request_before(serde_json::json!({"operation":"status"}), self.deadline)?;
        check_current()?;
        let bytes = framing::read_frame_capped_checked_until(
            &stream,
            &client.peer,
            MAX_MANUAL_FRAME,
            restricted_phase(self.deadline, MAX_CURRENT_WAIT)?,
            &mut check_current,
        )?;
        check_current()?;
        require_request_only_ack(&bytes)?;
        remaining_before(self.deadline)?;
        client.check_channel()?;
        check_current()?;
        Ok(client)
    }
}
/// A queued exact request, not an admission. No Clone/Deserialize or public
/// constructor; only the real client can create it by bounded authenticated send.
pub struct PendingManualEnrollment<'client> {
    client: &'client NativeManualClient,
    request: HostManualEnrollmentRequest,
    pending: PendingStream,
    slot: LeaseSlot<'client>,
    deadline: Instant,
}
impl<'client> PendingManualEnrollment<'client> {
    pub fn finish(mut self) -> Result<ManualEnrollmentLease<'client>> {
        let response = read_response(
            self.pending.stream()?,
            &self.client.peer,
            remaining_before(self.deadline)?.min(Duration::from_secs(120)),
        )?;
        let ManualAdmissionResponse::EnrollmentHeld { lease_id, evidence } = response else {
            return Err(Error::Permission);
        };
        hash(&lease_id)?;
        evidence.validate()?;
        if evidence.request != self.request {
            return Err(Error::Binding);
        }
        let observed = Instant::now();
        let observed_at_ms = now_ms()?;
        let lifetime = original_deadline_budget(
            evidence.admission.admitted_at_ms,
            evidence.admission.admission_deadline_ms,
            observed_at_ms,
        )?
        .min(remaining_before(self.deadline)?);
        let original_deadline = Some((observed_at_ms, evidence.admission.admission_deadline_ms));
        let lease = ManualEnrollmentLease {
            held: HeldLease {
                client: self.client,
                stream: Mutex::new(self.pending.take()?),
                lease_id,
                evidence_digest: evidence.digest()?,
                started: observed,
                lifetime,
                original_deadline,
                failed: AtomicBool::new(false),
                completion: CompletionState::initial_enrollment(),
                _slot: self.slot,
            },
            evidence: *evidence,
        };
        lease.check_current()?;
        remaining_before(self.deadline)?;
        Ok(lease)
    }
}
/// Inert V2 queued request. It cannot be cast to V1 or reconstruct an admission
/// from retained attempt/audit bytes. The real source must issue the exact V2 Held.
pub struct PendingManualEnrollmentContinuationV2<'client> {
    client: &'client NativeManualClient,
    request: HostManualEnrollmentContinuationRequestV2,
    pending: PendingStream,
    slot: LeaseSlot<'client>,
    deadline: Instant,
}
impl<'client> PendingManualEnrollmentContinuationV2<'client> {
    pub fn finish(mut self) -> Result<ManualEnrollmentContinuationLeaseV2<'client>> {
        let response = read_response(
            self.pending.stream()?,
            &self.client.peer,
            remaining_before(self.deadline)?.min(Duration::from_secs(120)),
        )?;
        let ManualAdmissionResponse::EnrollmentContinuationHeldV2 { lease_id, evidence } = response
        else {
            return Err(Error::Permission);
        };
        hash(&lease_id)?;
        evidence.validate()?;
        if evidence.request != self.request {
            return Err(Error::Binding);
        }
        self.client.check_channel()?;
        let observed = Instant::now();
        let observed_at_ms = now_ms()?;
        let lifetime = original_deadline_budget(
            evidence.admission.admitted_at_ms,
            evidence.admission.admission_deadline_ms,
            observed_at_ms,
        )?
        .min(remaining_before(self.deadline)?);
        let original_deadline = Some((observed_at_ms, evidence.admission.admission_deadline_ms));
        let lease = ManualEnrollmentContinuationLeaseV2 {
            held: HeldLease {
                client: self.client,
                stream: Mutex::new(self.pending.take()?),
                lease_id,
                evidence_digest: evidence.digest()?,
                started: observed,
                lifetime,
                original_deadline,
                failed: AtomicBool::new(false),
                completion: CompletionState::Legacy,
                _slot: self.slot,
            },
            evidence: *evidence,
        };
        // This same stream/source must answer a fresh exact evidence challenge.
        // Saved native observations and attempt IDs cannot satisfy this check.
        lease.check_current()?;
        remaining_before(self.deadline)?;
        Ok(lease)
    }
}
fn require_continuation_pair_scope(
    scope: &PairScope,
    request: &HostManualEnrollmentContinuationRequestV2,
) -> Result<()> {
    request.validate()?;
    scope.validate()?;
    let terms = &request.enrollment.terms;
    if scope.account_id != terms.identity.account_id
        || scope.agreement_id != terms.scope.agreement_id
        || scope.participant_id != terms.scope.participant_id
        || scope.manifest_digest != request.digest()?
        || scope.history_read
        || scope.authorization_export
        || scope.preconstruction_export
    {
        return Err(Error::Binding);
    }
    Ok(())
}

fn remaining_before(deadline: Instant) -> Result<Duration> {
    remaining_at(deadline, Instant::now())
}
fn remaining_at(deadline: Instant, now: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(now)
        .filter(|d| !d.is_zero())
        .ok_or(Error::Permission)
}
fn restricted_phase(deadline: Instant, maximum: Duration) -> Result<Instant> {
    remaining_before(deadline)?;
    Ok(deadline.min(
        Instant::now()
            .checked_add(maximum)
            .ok_or(Error::Permission)?,
    ))
}

fn require_request_only_ack(bytes: &[u8]) -> Result<()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RequestOnly {
        accepted: bool,
        reason_code: String,
    }
    let response: RequestOnly = serde_json::from_slice(bytes).map_err(|_| Error::Ipc)?;
    if !response.accepted || response.reason_code != "REQUEST_ONLY" {
        return Err(Error::Permission);
    }
    Ok(())
}
fn require_intent_pair_scope(scope: &PairScope, intent: &HostManualEnrollmentIntent) -> Result<()> {
    intent.validate()?;
    scope.validate()?;
    if scope.agreement_id != intent.scope.agreement_id
        || scope.participant_id != intent.scope.participant_id
        || scope.manifest_digest != intent.digest()?
        || scope.history_read
        || scope.authorization_export
        || scope.preconstruction_export
    {
        return Err(Error::Binding);
    }
    Ok(())
}

/// A bounded live manual-enrollment admission, not a durable approval. Keep it
/// alive across the Store transaction and require check_current immediately
/// before mutation and after the final CAS, before commit. The stable audit
/// record alone cannot be reused to reconstruct this type.
pub struct ManualEnrollmentLease<'a> {
    held: HeldLease<'a>,
    evidence: ManualEnrollmentEvidence,
}
impl ManualEnrollmentLease<'_> {
    /// Complete this exact initial audit channel before releasing its stream.
    /// A failed or late acknowledgment never rolls back the durable audit and
    /// permanently prevents reuse of this client. Drop is cancellation only.
    pub fn finish(self) -> Result<()> {
        self.held.finish()
    }

    pub fn binding(&self) -> &HostManualEnrollmentRequest {
        &self.evidence.request
    }
    pub fn evidence(&self) -> &ManualEnrollmentEvidence {
        &self.evidence
    }
    pub fn provider_enrollment_reference(&self) -> &str {
        self.held.client.provider.native_enrollment_reference()
    }
    pub fn check_current(&self) -> Result<()> {
        self.held.check_current()
    }
}
/// Opaque current successor-session publication, audit retention only. It has
/// no Clone/Deserialize, no public constructor and no conversion from/to V1.
/// Its original witness and Host deadlines survive every current challenge.
pub struct ManualEnrollmentContinuationLeaseV2<'client> {
    held: HeldLease<'client>,
    evidence: ManualEnrollmentContinuationEvidenceV2,
}
impl ManualEnrollmentContinuationLeaseV2<'_> {
    pub fn binding(&self) -> &HostManualEnrollmentContinuationRequestV2 {
        &self.evidence.request
    }
    pub fn evidence(&self) -> &ManualEnrollmentContinuationEvidenceV2 {
        &self.evidence
    }
    pub fn provider_enrollment_reference(&self) -> &str {
        self.held.client.provider.native_enrollment_reference()
    }
    pub fn check_current(&self) -> Result<()> {
        self.held.check_current()
    }
}
/// Fresh single-action admission. It cannot be converted from the stable
/// enrollment lease, a saved record, or another action. The caller recomputes
/// exact_request_digest from the full owning request before every effect.
pub struct ManualActionLease<'a> {
    held: HeldLease<'a>,
    evidence: ManualActionEvidence,
}
impl ManualActionLease<'_> {
    pub fn binding(&self) -> &HostManualActionRequest {
        &self.evidence.request
    }
    pub fn evidence(&self) -> &ManualActionEvidence {
        &self.evidence
    }
    pub fn provider_enrollment_reference(&self) -> &str {
        self.held.client.provider.native_enrollment_reference()
    }
    pub fn check_current(&self) -> Result<()> {
        self.held.check_current()
    }
}
struct HeldLease<'a> {
    client: &'a NativeManualClient,
    stream: Mutex<UnixStream>,
    lease_id: String,
    evidence_digest: String,
    started: Instant,
    lifetime: Duration,
    original_deadline: Option<(u64, u64)>,
    failed: AtomicBool,
    completion: CompletionState,
    _slot: LeaseSlot<'a>,
}
impl HeldLease<'_> {
    /// Explicit completion keeps the authenticated stream open until its
    /// exact Finished acknowledgment. The entire phase is bounded once, by the
    /// original monotonic/wall/grant deadlines and at most two seconds.
    /// It cannot renew a lease or undo any already committed external effect.
    fn finish(mut self) -> Result<()> {
        let result = self.finish_inner();
        if result.is_err() {
            self.failed.store(true, Ordering::Release);
            self.completion.fail();
            self.client.handoff.poison();
        }
        result
    }
    fn finish_inner(&mut self) -> Result<()> {
        self.completion.begin()?;
        if self.failed.load(Ordering::Acquire) {
            return Err(Error::Permission);
        }
        self.client.check_channel()?;
        self.check_original_deadline()?;
        let lease_deadline = self
            .started
            .checked_add(self.lifetime)
            .ok_or(Error::Permission)?;
        let phase_deadline = Instant::now()
            .checked_add(MAX_CURRENT_WAIT)
            .ok_or(Error::Permission)?
            .min(lease_deadline)
            .min(self.client.grant.expires);
        phase_budget(
            phase_deadline,
            Instant::now(),
            self.original_deadline,
            now_ms()?,
        )?;
        let response = {
            let mut stream = self.stream.lock().map_err(|_| Error::Ipc)?;
            write_frame_until(
                &mut stream,
                &ManualAdmissionCommand::Finish {},
                phase_deadline,
                self.original_deadline,
            )?;
            let budget = phase_budget(
                phase_deadline,
                Instant::now(),
                self.original_deadline,
                now_ms()?,
            )?;
            read_response(&stream, &self.client.peer, budget)?
        };
        // An exact but late acknowledgment is still failure. Do not re-open or
        // repeat Finish, and never grant the next purpose after that outcome.
        phase_budget(
            phase_deadline,
            Instant::now(),
            self.original_deadline,
            now_ms()?,
        )?;
        self.check_original_deadline()?;
        self.client.check_channel()?;
        self.completion.acknowledge(response)
    }

    fn check_current(&self) -> Result<()> {
        if self.failed.load(Ordering::Acquire) {
            return Err(Error::Permission);
        }
        let result = self.check_current_inner();
        if result.is_err() {
            self.failed.store(true, Ordering::Release);
            if self.completion.requires_ack() {
                self.client.handoff.poison();
            }
        }
        result
    }
    fn check_current_inner(&self) -> Result<()> {
        self.client.check_channel()?;
        let mut stream = self.stream.lock().map_err(|_| Error::Ipc)?;
        self.check_original_deadline()?;
        let remaining = self
            .lifetime
            .checked_sub(self.started.elapsed())
            .filter(|v| !v.is_zero())
            .ok_or(Error::Permission)?;
        let nonce = hex::encode(crate::random::<32>()?);
        let lease_deadline = self
            .started
            .checked_add(self.lifetime)
            .ok_or(Error::Permission)?;
        let phase_deadline = Instant::now()
            .checked_add(remaining.min(MAX_CURRENT_WAIT))
            .ok_or(Error::Permission)?
            .min(lease_deadline);
        write_frame_until(
            &mut stream,
            &ManualAdmissionCommand::CheckCurrent {
                lease_id: self.lease_id.clone(),
                evidence_digest: self.evidence_digest.clone(),
                challenge_nonce: nonce.clone(),
            },
            phase_deadline,
            self.original_deadline,
        )?;
        // Sending consumed part of the lease. Never restart the old remaining
        // budget for the response phase after partial write progress.
        let read_budget = phase_budget(
            lease_deadline,
            Instant::now(),
            self.original_deadline,
            now_ms()?,
        )?
        .min(MAX_CURRENT_WAIT);
        let response = read_response(&stream, &self.client.peer, read_budget)?;
        require_current_response(response, &self.lease_id, &self.evidence_digest, &nonce)?;
        if self.started.elapsed() >= self.lifetime {
            return Err(Error::Permission);
        }
        self.check_original_deadline()?;
        self.client.check_channel()
    }
    fn check_original_deadline(&self) -> Result<()> {
        if let Some((observed, deadline)) = self.original_deadline {
            let now = now_ms()?;
            if now < observed || now >= deadline {
                return Err(Error::Permission);
            }
        }
        Ok(())
    }
}
impl Drop for HeldLease<'_> {
    fn drop(&mut self) {
        if self.completion.requires_ack() {
            // Dropping an ack-required lease is cancellation, never successful handoff.
            // Closing the owned stream makes the producer fail closed; poison
            // this client even if its process/grant remain otherwise current.
            self.client.handoff.poison();
            return;
        }
        if self.completion == CompletionState::Legacy {
            if let Ok(mut stream) = self.stream.lock() {
                let _ = write_frame(&mut stream, &ManualAdmissionCommand::Finish {});
            }
        }
        // Acknowledged completion sends no second Finish during destruction.
    }
}

/// Irreversible per-client handoff guard, never a native/process owner.
/// It has no reset path; newly paired scopes still consult this same guard.
struct HandoffState(AtomicBool);
impl HandoffState {
    fn new() -> Self {
        Self(AtomicBool::new(false))
    }
    fn check(&self) -> Result<()> {
        if self.0.load(Ordering::Acquire) {
            Err(Error::Permission)
        } else {
            Ok(())
        }
    }
    fn poison(&self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Protocol bookkeeping only, never a native or process owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompletionState {
    Legacy,
    Pending,
    Completing,
    Acknowledged,
    Failed,
}
impl CompletionState {
    fn initial_enrollment() -> Self {
        // V1 initial publication uses the same explicit Finished protocol as
        // V2 roster publication. A best-effort Finish from Drop races the
        // producer's unchanged same-channel connected() checks.
        Self::Pending
    }
    fn requires_ack(self) -> bool {
        matches!(self, Self::Pending | Self::Completing | Self::Failed)
    }
    fn begin(&mut self) -> Result<()> {
        if *self != Self::Pending {
            return Err(Error::Permission);
        }
        *self = Self::Completing;
        Ok(())
    }
    fn acknowledge(&mut self, response: ManualAdmissionResponse) -> Result<()> {
        if *self != Self::Completing || !matches!(response, ManualAdmissionResponse::Finished {}) {
            self.fail();
            return Err(Error::Permission);
        }
        *self = Self::Acknowledged;
        Ok(())
    }
    fn fail(&mut self) {
        *self = Self::Failed;
    }
}

struct LeaseSlot<'a>(&'a AtomicUsize);
impl Drop for LeaseSlot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
/// V2 pending cancellation is a close, never an implicit successful Finish.
/// The separate attempt guard poisons before releasing its occupied slot.
struct PendingRosterV2Stream(Option<UnixStream>);
impl PendingRosterV2Stream {
    fn stream(&self) -> Result<&UnixStream> {
        self.0.as_ref().ok_or(Error::Ipc)
    }
    fn take(&mut self) -> Result<UnixStream> {
        self.0.take().ok_or(Error::Ipc)
    }
}
/// Armed before any request bytes can be sent. This guard owns the occupied
/// slot, so another thread cannot acquire it before cancellation is poisoned.
/// Neither this guard nor a slot is a native authority or disclosure lease.
struct PendingRosterV2Attempt<'a> {
    handoff: &'a HandoffState,
    slot: Option<LeaseSlot<'a>>,
}
impl<'a> PendingRosterV2Attempt<'a> {
    fn new(handoff: &'a HandoffState, slot: LeaseSlot<'a>) -> Self {
        Self {
            handoff,
            slot: Some(slot),
        }
    }
    /// Called only as the last field of an infallible HeldLease initializer,
    /// after stream extraction, evidence validation and all other fallible work.
    /// The new HeldLease immediately owns cancellation/error poisoning.
    fn transfer_to_held(&mut self) -> Result<LeaseSlot<'a>> {
        match self.slot.take() {
            Some(slot) => Ok(slot),
            None => {
                self.handoff.poison();
                Err(Error::Permission)
            }
        }
    }
}
impl Drop for PendingRosterV2Attempt<'_> {
    fn drop(&mut self) {
        if self.slot.is_some() {
            self.handoff.poison();
        }
        // Only after the poisoning above does the owned slot get released.
    }
}

struct PendingStream(Option<UnixStream>);
impl PendingStream {
    fn stream(&self) -> Result<&UnixStream> {
        self.0.as_ref().ok_or(Error::Ipc)
    }
    fn take(&mut self) -> Result<UnixStream> {
        self.0.take().ok_or(Error::Ipc)
    }
}
impl Drop for PendingStream {
    fn drop(&mut self) {
        if let Some(stream) = self.0.as_mut() {
            let _ = write_frame(stream, &ManualAdmissionCommand::Finish {});
        }
    }
}
fn read_response(
    stream: &UnixStream,
    peer: &PeerProcess,
    timeout: Duration,
) -> Result<ManualAdmissionResponse> {
    let bytes = framing::read_frame_with_deadline(stream, peer, timeout)?;
    if bytes.len() > MAX_MANUAL_FRAME {
        return Err(Error::Limit);
    }
    serde_json::from_slice(&bytes).map_err(|_| Error::Ipc)
}
/// Filesystem Unix endpoint encoding only. Endpoint paths select availability;
/// actual installed image and peer process are still checked after connecting.
fn local_address(path: &Path) -> Result<(libc::sockaddr_un, libc::socklen_t)> {
    let bytes = path.as_os_str().as_bytes();
    // SAFETY: sockaddr_un is a plain C address record whose all-zero value is valid.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if !path.is_absolute()
        || bytes.is_empty()
        || bytes.contains(&0)
        || bytes.len() >= address.sun_path.len()
    {
        return Err(Error::Binding);
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (slot, byte) in address.sun_path.iter_mut().zip(bytes) {
        *slot = *byte as libc::c_char;
    }
    let length = std::mem::offset_of!(libc::sockaddr_un, sun_path)
        .checked_add(bytes.len())
        .and_then(|n| n.checked_add(1))
        .ok_or(Error::Limit)?;
    Ok((
        address,
        libc::socklen_t::try_from(length).map_err(|_| Error::Limit)?,
    ))
}
fn poll_timeout_ms(deadline: Instant, now: Instant) -> Result<libc::c_int> {
    let remaining = deadline
        .checked_duration_since(now)
        .filter(|d| !d.is_zero())
        .ok_or(Error::Permission)?;
    // poll takes whole milliseconds. Recheck the absolute Instant after it
    // returns, so rounding/scheduling never turns a late result into permission.
    let milliseconds = remaining
        .as_nanos()
        .div_ceil(1_000_000)
        .min(i32::MAX as u128);
    libc::c_int::try_from(milliseconds).map_err(|_| Error::Limit)
}
/// Restriction-only transport adapter. This returns an UNAUTHENTICATED local
/// socket, never a signer grant. The caller must still verify installed server
/// identity and kernel peer credentials. A local connection receives at most
/// 100ms of the caller's original budget; full backlogs fail without fallback.
pub fn connect_local_checked_until(
    path: &Path,
    original_deadline: Instant,
    check_current: impl Fn() -> Result<()>,
) -> Result<UnixStream> {
    check_current()?;
    poll_timeout_ms(original_deadline, Instant::now())?;
    let deadline = original_deadline.min(Instant::now() + Duration::from_millis(100));
    let stream = connect_local_before(path, deadline)?;
    check_current()?;
    poll_timeout_ms(deadline, Instant::now())?;
    Ok(stream)
}
fn connect_local_before(path: &Path, deadline: Instant) -> Result<UnixStream> {
    let (address, length) = local_address(path)?;
    poll_timeout_ms(deadline, Instant::now())?;
    // SAFETY: socket has no borrowed pointers. Atomic flags prevent a blocking
    // connect and descriptor leakage to concurrently launched processes.
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if raw < 0 {
        return Err(Error::Ipc);
    }
    // SAFETY: successful socket returns one newly owned descriptor.
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: initialized address and the exact bounded address length are valid
    // for this synchronous syscall; the descriptor is owned for the whole call.
    let connected = unsafe {
        libc::connect(
            socket.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            length,
        )
    };
    if connected != 0 {
        let error = std::io::Error::last_os_error();
        // A full AF_UNIX backlog commonly reports EAGAIN, which is not an
        // asynchronous in-progress connection. Deny and close; never retry it
        // as blocking or pretend POLLOUT alone established a connected peer.
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(Error::Ipc);
        }
        loop {
            let timeout = poll_timeout_ms(deadline, Instant::now())?;
            let mut state = libc::pollfd {
                fd: socket.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            // SAFETY: one initialized pollfd stays live throughout poll.
            let result = unsafe { libc::poll(&mut state, 1, timeout) };
            let interrupted = result < 0
                && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted;
            poll_timeout_ms(deadline, Instant::now())?;
            if result < 0 {
                if interrupted {
                    continue;
                }
                return Err(Error::Ipc);
            }
            if result == 0
                || state.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0
                || state.revents & libc::POLLOUT == 0
            {
                return Err(Error::Ipc);
            }
            break;
        }
    }
    let mut error: libc::c_int = 0;
    let mut size = std::mem::size_of_val(&error) as libc::socklen_t;
    // SAFETY: the output buffer and its exact length are initialized and valid.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&mut error as *mut libc::c_int).cast(),
            &mut size,
        )
    };
    if result != 0 || size as usize != std::mem::size_of_val(&error) || error != 0 {
        return Err(Error::Ipc);
    }
    poll_timeout_ms(deadline, Instant::now())?;
    let stream = UnixStream::from(socket);
    // Connection is already complete. Existing credential-authenticated framing
    // uses its own absolute read/write phases; no blocking-connect fallback.
    stream.set_nonblocking(false)?;
    poll_timeout_ms(deadline, Instant::now())?;
    Ok(stream)
}
fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    // Initial requests and terminal Finish have an independent finite phase.
    let deadline = Instant::now()
        .checked_add(MAX_CURRENT_WAIT)
        .ok_or(Error::Permission)?;
    write_frame_until(stream, value, deadline, None)
}
fn phase_budget(
    deadline: Instant,
    now: Instant,
    original: Option<(u64, u64)>,
    wall_now: u64,
) -> Result<Duration> {
    let remaining = deadline
        .checked_duration_since(now)
        .filter(|d| !d.is_zero())
        .ok_or(Error::Permission)?;
    match original {
        Some((observed, expires)) => {
            if wall_now < observed || wall_now >= expires {
                return Err(Error::Permission);
            }
            Ok(remaining.min(Duration::from_millis(expires - wall_now)))
        }
        None => Ok(remaining),
    }
}
fn write_frame_until<T: Serialize>(
    stream: &mut UnixStream,
    value: &T,
    deadline: Instant,
    original: Option<(u64, u64)>,
) -> Result<()> {
    write_frame_until_bounded(stream, value, deadline, original, MAX_MANUAL_FRAME)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FrameWriteCause {
    Unclassified,
    Serialize,
    FrameLimit,
    Clock,
    Budget,
    Io,
    ZeroWrite,
    BrokenPipe,
    Reset,
    Timeout,
}
fn write_frame_until_bounded<T: Serialize>(
    stream: &mut UnixStream,
    value: &T,
    deadline: Instant,
    original: Option<(u64, u64)>,
    max_frame: usize,
) -> Result<()> {
    write_frame_until_bounded_observed(
        stream,
        value,
        deadline,
        original,
        max_frame,
        &mut FrameWriteCause::Unclassified,
    )
}
// The production writer itself records closed causes. No payload or authority
// is copied into diagnostics, and the legacy error/lease poisoning is unchanged.
fn write_frame_until_bounded_observed<T: Serialize>(
    stream: &mut UnixStream,
    value: &T,
    deadline: Instant,
    original: Option<(u64, u64)>,
    max_frame: usize,
    cause: &mut FrameWriteCause,
) -> Result<()> {
    let mut bytes = Zeroizing::new(serde_json::to_vec(value).map_err(|_| {
        *cause = FrameWriteCause::Serialize;
        Error::Ipc
    })?);
    if bytes.len() >= max_frame {
        *cause = FrameWriteCause::FrameLimit;
        return Err(Error::Limit);
    }
    bytes.push(b'\n');
    let mut sent = 0;
    while sent < bytes.len() {
        // SO_SNDTIMEO alone is per syscall. Reset it only to the remaining
        // absolute phase/lease budget, never to a fresh two seconds.
        let remaining = phase_budget(
            deadline,
            Instant::now(),
            original,
            now_ms().map_err(|error| {
                *cause = FrameWriteCause::Clock;
                error
            })?,
        )
        .map_err(|error| {
            *cause = FrameWriteCause::Budget;
            error
        })?;
        stream.set_write_timeout(Some(remaining)).map_err(|error| {
            *cause = FrameWriteCause::Io;
            Error::Io(error)
        })?;
        match stream.write(&bytes[sent..]) {
            Ok(0) => {
                *cause = FrameWriteCause::ZeroWrite;
                return Err(Error::Ipc);
            }
            Ok(count) => sent += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => {
                *cause = match error.kind() {
                    std::io::ErrorKind::BrokenPipe => FrameWriteCause::BrokenPipe,
                    std::io::ErrorKind::ConnectionReset => FrameWriteCause::Reset,
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
                        FrameWriteCause::Timeout
                    }
                    _ => FrameWriteCause::Io,
                };
                return Err(Error::Ipc);
            }
        }
        phase_budget(
            deadline,
            Instant::now(),
            original,
            now_ms().map_err(|error| {
                *cause = FrameWriteCause::Clock;
                error
            })?,
        )
        .map_err(|error| {
            *cause = FrameWriteCause::Budget;
            error
        })?;
    }
    // UnixStream is unbuffered: all payload bytes and the newline were written.
    // A partial/late write is uncertain and the existing HeldLease failure path
    // permanently poisons this object. Nothing refunds durable original state.
    Ok(())
}
fn now_ms() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Permission)?
        .as_millis()
        .try_into()
        .map_err(|_| Error::Permission)
}
fn original_deadline_budget(admitted: u64, deadline: u64, observed: u64) -> Result<Duration> {
    if observed < admitted || observed >= deadline {
        return Err(Error::Permission);
    }
    Ok(Duration::from_millis(deadline - observed).min(MAX_LEASE))
}
fn require_current_response(
    response: ManualAdmissionResponse,
    lease: &str,
    evidence: &str,
    nonce: &str,
) -> Result<()> {
    match response {
        ManualAdmissionResponse::Current {
            lease_id,
            evidence_digest,
            challenge_nonce,
        } if lease_id == lease && evidence_digest == evidence && challenge_nonce == nonce => Ok(()),
        _ => Err(Error::Permission),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn continuation_pair_requires_exact_v2_request_and_no_legacy_disclosure_scope() {
        let request = crate::manual_continuation_v2::tests::request();
        let terms = &request.enrollment.terms;
        let scope = PairScope {
            account_id: terms.identity.account_id.clone(),
            agreement_id: terms.scope.agreement_id.clone(),
            participant_id: terms.scope.participant_id.clone(),
            manifest_digest: request.digest().unwrap(),
            history_read: false,
            authorization_export: false,
            preconstruction_export: false,
        };
        require_continuation_pair_scope(&scope, &request).unwrap();
        for field in 0..7 {
            let mut wrong = scope.clone();
            match field {
                0 => wrong.account_id = "other".into(),
                1 => wrong.agreement_id = "other".into(),
                2 => wrong.participant_id = "other".into(),
                3 => wrong.manifest_digest = request.enrollment.digest().unwrap(),
                4 => wrong.history_read = true,
                5 => wrong.authorization_export = true,
                _ => wrong.preconstruction_export = true,
            }
            assert!(require_continuation_pair_scope(&wrong, &request).is_err());
        }
    }
    #[test]
    fn caller_deadline_only_restricts_endpoint_pair_and_held_budget() {
        let now = Instant::now();
        let host = now + Duration::from_secs(5);
        let server = now + Duration::from_secs(900);
        assert_eq!(server.min(host), host);
        assert_eq!(remaining_at(host, now).unwrap(), Duration::from_secs(5));
        assert_eq!(
            remaining_at(host, now + Duration::from_millis(4999)).unwrap(),
            Duration::from_millis(1)
        );
        assert!(remaining_at(host, host).is_err());
        assert!(remaining_at(host, host + Duration::from_nanos(1)).is_err());
        // Receiving fresh progress/TTL/Held never recreates the original budget.
        assert_eq!(
            original_deadline_budget(10, 120_010, 20)
                .unwrap()
                .min(remaining_at(host, now + Duration::from_millis(4999)).unwrap()),
            Duration::from_millis(1)
        );
    }
    #[test]
    fn initial_intent_requires_exact_pair_commitment_and_no_export_flags() {
        // Pure wire predicates only; this does not create a native client or grant.
        let h = "a".repeat(64);
        let intent = HostManualEnrollmentIntent {
            version: 1,
            operation_id: "operation".into(),
            host: ManualHostGenerationBinding {
                generation_id: h.clone(),
                inventory_digest: h.clone(),
                generation_plan_digest: h.clone(),
                financial_journal_origin_digest: h.clone(),
                store_destination_identity: h.clone(),
                profile_id: "profile".into(),
                canonical_root: "/private/host".into(),
                destination_identity_digest: h.clone(),
                inherited_identity_digest: h.clone(),
                scope_predecessor_digest: None,
            },
            scope: BornManualScope {
                agreement_id: "agreement".into(),
                obligation_id: "obligation".into(),
                participant_id: "participant".into(),
                principal_id: "principal".into(),
                privacy_domain: "domain".into(),
                recipient_scope_digests: vec![h.clone()],
                aggregate_budget_zatoshis: 1,
                per_operation_limit_zatoshis: 1,
                maximum_fee_share_zatoshis: 0,
                maximum_transaction_fee_zatoshis: 0,
                maximum_permit_lifetime_ms: 1,
                expires_at_ms: 2,
            },
        };
        let scope = PairScope {
            account_id: h,
            agreement_id: "agreement".into(),
            participant_id: "participant".into(),
            manifest_digest: intent.digest().unwrap(),
            history_read: false,
            authorization_export: false,
            preconstruction_export: false,
        };
        require_intent_pair_scope(&scope, &intent).unwrap();
        for which in 0..6 {
            let mut changed = scope.clone();
            match which {
                0 => changed.agreement_id = "other".into(),
                1 => changed.participant_id = "other".into(),
                2 => changed.manifest_digest = "b".repeat(64),
                3 => changed.history_read = true,
                4 => changed.authorization_export = true,
                _ => changed.preconstruction_export = true,
            }
            assert!(require_intent_pair_scope(&changed, &intent).is_err());
        }
        let mut changed = intent.clone();
        changed.host.profile_id = "different-owner".into();
        assert!(require_intent_pair_scope(&scope, &changed).is_err());
    }
    #[test]
    fn request_only_ack_cannot_carry_terms_approval_or_held_evidence() {
        assert!(
            require_request_only_ack(br#"{"accepted":true,"reason_code":"REQUEST_ONLY"}"#).is_ok()
        );
        for bytes in [
            br#"{"accepted":true,"reason_code":"HELD"}"#.as_slice(),
            br#"{"accepted":false,"reason_code":"REQUEST_ONLY"}"#.as_slice(),
            br#"{"accepted":true,"reason_code":"REQUEST_ONLY","approved":true}"#.as_slice(),
            br#"{"accepted":true,"reason_code":"REQUEST_ONLY","terms":{}}"#.as_slice(),
            br#"{"accepted":true,"reason_code":"REQUEST_ONLY","lease_id":"anything"}"#.as_slice(),
        ] {
            assert!(require_request_only_ack(bytes).is_err());
        }
    }
    #[test]
    fn local_socket_path_bounds_reject_abstract_nul_relative_and_truncated_names() {
        use std::ffi::OsStr;
        for path in [
            Path::new(""),
            Path::new("relative.sock"),
            Path::new(OsStr::from_bytes(b"/tmp/bad\0suffix")),
            Path::new(OsStr::from_bytes(b"\0abstract")),
        ] {
            assert!(local_address(path).is_err());
        }
        let exact = format!("/{}", "a".repeat(106));
        let (address, length) = local_address(Path::new(&exact)).unwrap();
        assert_eq!(address.sun_path[107], 0);
        assert_eq!(
            length as usize,
            std::mem::offset_of!(libc::sockaddr_un, sun_path) + 108
        );
        let too_long = format!("/{}", "a".repeat(107));
        assert!(local_address(Path::new(&too_long)).is_err());
    }
    #[test]
    fn connect_poll_uses_one_absolute_deadline_across_interrupts() {
        let start = Instant::now();
        let deadline = start + Duration::from_millis(2000);
        assert_eq!(poll_timeout_ms(deadline, start).unwrap(), 2000);
        assert_eq!(
            poll_timeout_ms(deadline, start + Duration::from_millis(1999)).unwrap(),
            1
        );
        assert_eq!(
            poll_timeout_ms(deadline, start + Duration::from_nanos(1_999_999_999)).unwrap(),
            1
        );
        assert!(poll_timeout_ms(deadline, deadline).is_err());
        assert!(poll_timeout_ms(deadline, deadline + Duration::from_nanos(1)).is_err());
    }
    #[test]
    fn partial_write_progress_cannot_restart_phase_or_immutable_lease_deadline() {
        let start = Instant::now();
        let deadline = start + Duration::from_millis(2000);
        let original = Some((10_000, 10_750));
        for (elapsed, wall, want) in [(0, 10_000, 750), (200, 10_200, 550), (700, 10_700, 50)] {
            assert_eq!(
                phase_budget(
                    deadline,
                    start + Duration::from_millis(elapsed),
                    original,
                    wall
                )
                .unwrap(),
                Duration::from_millis(want)
            );
        }
        assert!(phase_budget(
            deadline,
            start + Duration::from_millis(750),
            original,
            10_750
        )
        .is_err());
        assert!(phase_budget(deadline, start + Duration::from_millis(2000), None, 0).is_err());
        assert!(
            phase_budget(deadline, start + Duration::from_millis(10), original, 9_999).is_err()
        );
        // Independently bounded Finish has no renewed enrollment authority.
        assert_eq!(
            phase_budget(deadline, start + Duration::from_millis(1999), None, 0).unwrap(),
            Duration::from_millis(1)
        );
    }
    #[test]
    fn enrollment_held_budget_is_remaining_original_time_not_fresh_thirty_seconds() {
        assert_eq!(
            original_deadline_budget(10, 120_010, 120_009).unwrap(),
            Duration::from_millis(1)
        );
        assert_eq!(
            original_deadline_budget(10, 120_010, 119_000).unwrap(),
            Duration::from_millis(1010)
        );
        assert!(original_deadline_budget(10, 120_010, 120_010).is_err());
        assert!(original_deadline_budget(10, 120_010, 9).is_err());
    }
    #[test]
    fn action_deadline_cannot_restart_at_reacquisition_or_clock_rollback() {
        assert_eq!(
            original_deadline_budget(10, 30, 10).unwrap(),
            Duration::from_millis(20)
        );
        assert_eq!(
            original_deadline_budget(10, 30, 29).unwrap(),
            Duration::from_millis(1)
        );
        assert!(original_deadline_budget(10, 30, 30).is_err());
        assert!(original_deadline_budget(10, 30, 9).is_err());
        assert_eq!(original_deadline_budget(1, 100_000, 1).unwrap(), MAX_LEASE);
    }
    #[test]
    fn current_response_requires_exact_lease_evidence_and_fresh_challenge() {
        for (lease, evidence, nonce) in [
            ("a", "e", "n"),
            ("x", "e", "n"),
            ("a", "x", "n"),
            ("a", "e", "old"),
        ] {
            let result = require_current_response(
                ManualAdmissionResponse::Current {
                    lease_id: lease.into(),
                    evidence_digest: evidence.into(),
                    challenge_nonce: nonce.into(),
                },
                "a",
                "e",
                "n",
            );
            assert_eq!(result.is_ok(), (lease, evidence, nonce) == ("a", "e", "n"));
        }
        assert!(
            require_current_response(ManualAdmissionResponse::Finished {}, "a", "e", "n").is_err()
        );
        assert!(
            require_current_response(ManualAdmissionResponse::Denied {}, "a", "e", "n").is_err()
        );
    }
}

#[path = "manual_candidate_selection_client.rs"]
mod candidate_selection;
pub use candidate_selection::{ManualCandidateSelectionLease, PendingManualCandidateSelection};

#[path = "manual_inventory_client.rs"]
mod inventory;
pub use inventory::{ManualPreliminaryInventoryLease, PendingManualPreliminaryInventory};

#[path = "manual_roster_v2_client.rs"]
mod roster_v2;
pub use roster_v2::{ManualRosterEnrollmentLeaseV2, PendingManualRosterEnrollmentV2};

#[path = "manual_roster_inventory_v2_client.rs"]
mod roster_inventory_v2;
pub use roster_inventory_v2::{ManualRosterInventoryLeaseV2, PendingManualRosterInventoryV2};
#[path = "manual_roster_candidate_selection_v2_client.rs"]
mod roster_candidate_selection_v2;
pub use roster_candidate_selection_v2::{
    ManualRosterCandidateSelectionLeaseV2, PendingManualRosterCandidateSelectionV2,
    PendingManualRosterContributionRetentionV2, RetainedManualRosterContributionV2,
};

#[cfg(test)]
mod completion_tests {
    use super::*;
    #[test]
    fn failed_close_permanently_blocks_the_same_client_guard() {
        // Pure guard only, no socket, native authority or process is fabricated.
        let guard = HandoffState::new();
        assert!(guard.check().is_ok());
        guard.poison();
        assert!(guard.check().is_err());
        guard.poison();
        assert!(guard.check().is_err());
    }
    #[test]
    fn initial_enrollment_never_completes_by_drop_or_unacknowledged_finish() {
        // The selector is the exact one used by PendingManualEnrollment::finish.
        // This is protocol bookkeeping only, without any socket or owner.
        let mut state = CompletionState::initial_enrollment();
        assert_eq!(state, CompletionState::Pending);
        assert!(state.requires_ack());
        state.begin().unwrap();
        assert!(state.requires_ack());
        state
            .acknowledge(ManualAdmissionResponse::Finished {})
            .unwrap();
        assert_eq!(state, CompletionState::Acknowledged);
        assert!(!state.requires_ack());
        assert!(state.begin().is_err());

        for response in [
            ManualAdmissionResponse::Denied {},
            ManualAdmissionResponse::Finished {},
        ] {
            let mut failed = CompletionState::initial_enrollment();
            failed.begin().unwrap();
            failed.fail(); // Includes timeout/disconnect after an already committed audit.
            assert!(failed.acknowledge(response).is_err());
            assert!(failed.requires_ack());
            assert!(failed.begin().is_err());
        }
        let mut wrong = CompletionState::initial_enrollment();
        wrong.begin().unwrap();
        assert!(wrong
            .acknowledge(ManualAdmissionResponse::Denied {})
            .is_err());
        assert_eq!(wrong, CompletionState::Failed);
    }

    #[test]
    fn only_explicit_exact_finish_ack_completes_a_v2_handoff() {
        let mut state = CompletionState::Pending;
        assert!(state.requires_ack());
        state.begin().unwrap();
        assert!(state.requires_ack());
        state
            .acknowledge(ManualAdmissionResponse::Finished {})
            .unwrap();
        assert_eq!(state, CompletionState::Acknowledged);
        assert!(!state.requires_ack());
        assert!(state.begin().is_err());
    }
    #[test]
    fn unexpected_missing_or_duplicate_completion_cannot_enable_repair() {
        for response in [
            ManualAdmissionResponse::Denied {},
            ManualAdmissionResponse::Current {
                lease_id: "a".into(),
                evidence_digest: "b".into(),
                challenge_nonce: "c".into(),
            },
        ] {
            let mut state = CompletionState::Pending;
            state.begin().unwrap();
            assert!(state.acknowledge(response).is_err());
            assert_eq!(state, CompletionState::Failed);
            assert!(state.requires_ack());
            assert!(state.begin().is_err());
        }
        let mut unsolicited = CompletionState::Pending;
        assert!(unsolicited
            .acknowledge(ManualAdmissionResponse::Finished {})
            .is_err());
        let mut disconnected = CompletionState::Completing;
        disconnected.fail();
        assert!(disconnected
            .acknowledge(ManualAdmissionResponse::Finished {})
            .is_err());
        assert!(CompletionState::Legacy.begin().is_err());
    }
    #[test]
    fn finish_phase_uses_remaining_original_budget_across_send_and_ack() {
        let start = Instant::now();
        let phase = start + Duration::from_secs(2);
        let original = Some((1000, 1100));
        assert_eq!(
            phase_budget(phase, start, original, 1099).unwrap(),
            Duration::from_millis(1)
        );
        assert!(phase_budget(phase, start, original, 1100).is_err());
        assert!(phase_budget(phase, start, original, 999).is_err());
        assert!(phase_budget(phase, phase, original, 1099).is_err());
        assert_eq!(
            phase_budget(
                phase,
                start + Duration::from_millis(1999),
                Some((1000, 5000)),
                1001
            )
            .unwrap(),
            Duration::from_millis(1)
        );
    }
}

#[cfg(test)]
mod pending_roster_v2_tests {
    use super::*;
    #[test]
    fn pending_cancel_poison_is_visible_before_slot_release() {
        let handoff = HandoffState::new();
        let slots = AtomicUsize::new(1);
        let attempt = PendingRosterV2Attempt::new(&handoff, LeaseSlot(&slots));
        assert_eq!(slots.load(Ordering::Acquire), 1);
        drop(attempt);
        assert_eq!(slots.load(Ordering::Acquire), 0);
        assert!(handoff.check().is_err());
    }
    #[test]
    fn errors_at_every_preheld_stage_preserve_armed_cancellation() {
        // Synthetic control-flow boundaries only; no stream or native owner.
        // These represent send, response/decode, binding/FVK, and deadline errors.
        for fail_at in 0..4 {
            let handoff = HandoffState::new();
            let slots = AtomicUsize::new(1);
            let result = (|| -> Result<()> {
                let _attempt = PendingRosterV2Attempt::new(&handoff, LeaseSlot(&slots));
                for stage in 0..4 {
                    if stage == fail_at {
                        return Err(Error::Permission);
                    }
                }
                unreachable!()
            })();
            assert!(result.is_err());
            assert!(handoff.check().is_err());
            assert_eq!(slots.load(Ordering::Acquire), 0);
        }
    }
    #[test]
    fn successful_transfer_retains_slot_and_disarms_only_pending_guard() {
        let handoff = HandoffState::new();
        let slots = AtomicUsize::new(1);
        let mut attempt = PendingRosterV2Attempt::new(&handoff, LeaseSlot(&slots));
        let held_slot = attempt.transfer_to_held().unwrap();
        drop(attempt);
        assert!(handoff.check().is_ok());
        assert_eq!(slots.load(Ordering::Acquire), 1);
        // Protocol bookkeeping only. Real HeldLease Drop separately poisons.
        drop(held_slot);
        assert_eq!(slots.load(Ordering::Acquire), 0);
    }
    #[test]
    fn duplicate_transfer_cannot_reset_or_reuse_the_attempt() {
        let handoff = HandoffState::new();
        let slots = AtomicUsize::new(1);
        let mut attempt = PendingRosterV2Attempt::new(&handoff, LeaseSlot(&slots));
        let held_slot = attempt.transfer_to_held().unwrap();
        assert!(attempt.transfer_to_held().is_err());
        assert!(handoff.check().is_err());
        drop(attempt);
        assert_eq!(slots.load(Ordering::Acquire), 1);
        drop(held_slot);
        assert_eq!(slots.load(Ordering::Acquire), 0);
    }
}

#[path = "manual_roster_construction_v2_client.rs"]
mod roster_construction_v2;
pub use roster_construction_v2::{
    AdmittedManualRosterConstructionContributionV2, PendingManualRosterConstructionV2,
};

#[path = "manual_roster_exact_input_observation_v1_client.rs"]
mod roster_exact_input_observation_v1;
pub use roster_exact_input_observation_v1::{
    AdmittedRosterExactInputObservationV1, PendingRosterExactInputObservationV1,
    StartedRosterExactInputObservationV1,
};

#[path = "roster_common_context_read_v1_client.rs"]
mod roster_common_context_read_v1;
pub use roster_common_context_read_v1::{
    AdmittedRosterCommonContextReadV1, PendingRosterCommonContextReadV1,
    StartedRosterCommonContextReadV1,
};
#[path = "manual_roster_construction_v3_client.rs"]
mod roster_construction_v3;
pub use roster_construction_v3::{
    AdmittedManualRosterConstructionContributionV3, PendingManualRosterConstructionV3,
};

#[path = "common_context_reentry_v1_client.rs"]
mod common_context_reentry_v1;
pub use common_context_reentry_v1::{
    CommonContextReentryClientV1, CommonContextReentrySourceV1, PendingCommonContextReentryPairV1,
    PendingCommonContextReentryV1, PendingReenteredRosterConstructionV1,
    ReenteredCommonContextConstruction,
};

#[path = "common_context_handoff_v1_client.rs"]
mod common_context_handoff_v1;
pub use common_context_handoff_v1::{
    NativeCommonContextHandoffAuthorizationV1, PendingCommonContextHandoffAuthorizationV1,
};

#[cfg(feature = "retirement-evidence-client")]
#[path = "retirement_evidence_client.rs"]
mod retirement_evidence_client;
#[cfg(feature = "retirement-evidence-client")]
pub use retirement_evidence_client::{
    InstalledRetirementEvidenceClientV1, PendingRetirementDestinationEvidenceV1,
    PendingRetirementEvidencePairV1, RetirementDestinationEvidenceObservationV1,
    RetirementEvidenceCancellationV1,
};

#[path = "permanent_stop_v1_client.rs"]
mod permanent_stop_v1_client;
pub use permanent_stop_v1_client::{PendingPermanentStopV1, PermanentStopLeaseV1};
#[path = "named_verifier_policy_client.rs"]
mod named_verifier_policy_client;
pub use named_verifier_policy_client::{NamedVerifierPolicyLease, PendingNamedVerifierPolicy};

// Only the non-constructible observation crosses the crate boundary. New
// discovery launch/pair/pending handles remain private until native issuance,
// journal migration and foreground Host privacy are separately qualified.
#[path = "durable_input_projection_v1_client.rs"]
mod durable_input_projection_v1_client;
pub use durable_input_projection_v1_client::AuthenticatedDurableInputProjectionV1;

#[cfg(test)]
mod checked_local_connect_tests {
    use super::*;
    #[test]
    fn born_checked_connect_refuses_expired_or_revoked_before_open() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("synthetic.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        assert!(connect_local_checked_until(&path, Instant::now(), || Ok(())).is_err());
        assert!(connect_local_checked_until(
            &path,
            Instant::now() + Duration::from_secs(1),
            || Err(Error::Permission)
        )
        .is_err());
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    #[test]
    fn born_checked_connect_uses_actual_socket_without_creating_authority() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("synthetic.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let stream =
            connect_local_checked_until(&path, Instant::now() + Duration::from_secs(1), || Ok(()))
                .unwrap();
        let (accepted, _) = listener.accept().unwrap();
        drop((stream, accepted));
    }
}

#[cfg(test)]
#[path = "framing_integration_tests.rs"]
mod framing_integration_tests;
