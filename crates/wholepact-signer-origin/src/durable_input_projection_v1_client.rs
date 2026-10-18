//! Installed-origin, projection-ONLY client. Intended as a gated child of
//! client.rs, but deliberately unregistered until the complete native route is
//! qualified. No ordinary pairing/client/session or manual lease is constructed.
use super::*;
use crate::durable_input_projection_v1::{
    DurableInputProjectionOutboxV1, DurableInputProjectionRequestV1,
    INPUT_PROJECTION_PAIR_REASON_V1, MAX_INPUT_PROJECTION_FRAME_BYTES_V1,
    ProjectionChannelBindingV1, ProjectionPairResponseV1, ProjectionPairScopeV1,
    ProjectionRequestV1, ProjectionResponseV1, decode_projection_response_v1,
};
use sha2::{Digest, Sha256};
use std::net::Shutdown;

const MAX_PROJECTION_OPERATION: Duration = Duration::from_secs(120);
const PAIR_COMMAND: &str = "request_durable_input_projection_pairing_v1";
const REQUEST_COMMAND: &str = "request_durable_input_projection_v1";

/// Holds the real installed signer and one native-approved, purpose-separated
/// request grant. There is no raw-socket/DTO constructor, arbitrary operation,
/// Deref, ordinary client conversion, enrollment issuer or financial operation.
pub struct NativeInputProjectionClientV1 {
    provider: InstalledSignerProvider,
    socket: PathBuf,
    peer: PeerProcess,
    request: DurableInputProjectionRequestV1,
    scope: ProjectionPairScopeV1,
    binding: ProjectionChannelBindingV1,
    grant: ClientGrant,
    deadline: Instant,
    requested: AtomicBool,
}
impl NativeInputProjectionClientV1 {
    pub fn launch_and_pair(
        provider: InstalledSignerProvider,
        application_label: &str,
        request: DurableInputProjectionRequestV1,
    ) -> Result<Self> {
        let deadline = projection_deadline(Instant::now(), None)?;
        request.require_valid_at(now_ms()? / 1000)?;
        provider.launch_native()?;
        let socket = provider.wait_native_endpoint(remaining_before(deadline)?)?;
        Self::begin_pair_before(provider, &socket, application_label, request, deadline)?.finish()
    }

    pub fn pair(
        provider: InstalledSignerProvider,
        socket: &Path,
        application_label: &str,
        request: DurableInputProjectionRequestV1,
    ) -> Result<Self> {
        Self::begin_pair_before(
            provider,
            socket,
            application_label,
            request,
            projection_deadline(Instant::now(), None)?,
        )?
        .finish()
    }

    /// Native pairing receives the full exact nonspending intent. The endpoint
    /// path chooses availability only; installed image and kernel process
    /// authentication are still the maintained concrete provider's checks.
    pub fn begin_pair_before(
        provider: InstalledSignerProvider,
        socket: &Path,
        application_label: &str,
        request: DurableInputProjectionRequestV1,
        deadline: Instant,
    ) -> Result<PendingInputProjectionPairV1> {
        let started = Instant::now();
        let deadline = projection_deadline(started, Some(deadline))?;
        label(application_label)?;
        request.require_valid_at(now_ms()? / 1000)?;
        let scope = request.pair_scope()?;
        let stream = connect_local_before(socket, restricted_phase(deadline, MAX_CURRENT_WAIT)?)?;
        framing::enable_credentials(stream.as_raw_fd())?;
        let peer = provider.verify_server(&stream)?;
        #[derive(Serialize)]
        struct PairEnvelope<'a> {
            command: &'static str,
            schema_version: u16,
            application_label: &'a str,
            request: &'a DurableInputProjectionRequestV1,
        }
        let pending = ProjectionStreamV1(stream);
        write_projection_frame(
            &pending.0,
            &PairEnvelope {
                command: PAIR_COMMAND,
                schema_version: 1,
                application_label,
                request: &request,
            },
            restricted_phase(deadline, MAX_CURRENT_WAIT)?,
            || {
                peer.check_alive()?;
                remaining_before(deadline)?;
                request.require_valid_at(now_ms()? / 1000)
            },
        )?;
        peer.same_live_process(&provider.verify_server(&pending.0)?)?;
        Ok(PendingInputProjectionPairV1 {
            provider,
            socket: socket.into(),
            peer,
            request,
            scope,
            pending,
            started,
            deadline,
        })
    }

    /// One exact scan/export attempt per client. A failed/ambiguous exchange is
    /// not retried or refunded by this object. Any later disclosure must obtain
    /// its own genuine native approval; immutable outboxes remain historical.
    pub fn begin_projection_before(
        &self,
        deadline: Instant,
    ) -> Result<PendingDurableInputProjectionV1<'_>> {
        self.check_current()?;
        self.request.require_scope(&self.scope)?;
        self.requested
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::Conflict)?;
        let deadline = deadline.min(self.deadline).min(self.grant.expires);
        let pending = self.open_request(
            &ProjectionRequestV1::Project {
                request: Box::new(self.request.clone()),
            },
            deadline,
        )?;
        Ok(PendingDurableInputProjectionV1 {
            client: self,
            pending,
            deadline,
        })
    }

    fn check_current(&self) -> Result<()> {
        remaining_before(self.deadline.min(self.grant.expires))?;
        self.request.require_valid_at(now_ms()? / 1000)?;
        self.peer.check_alive()
    }

    fn require_channel(&self, stream: &UnixStream) -> Result<()> {
        self.check_current()?;
        self.peer
            .same_live_process(&self.provider.verify_server(stream)?)?;
        self.check_current()
    }

    fn open_request(
        &self,
        request: &ProjectionRequestV1,
        deadline: Instant,
    ) -> Result<ProjectionStreamV1> {
        self.check_current()?;
        let deadline = deadline.min(self.deadline).min(self.grant.expires);
        let stream =
            connect_local_before(&self.socket, restricted_phase(deadline, MAX_CURRENT_WAIT)?)?;
        framing::enable_credentials(stream.as_raw_fd())?;
        let pending = ProjectionStreamV1(stream);
        self.require_channel(&pending.0)?;
        #[derive(Serialize)]
        struct RequestEnvelope<'a> {
            command: &'static str,
            schema_version: u16,
            grant_id: &'a str,
            token_hex: &'a str,
            request: &'a ProjectionRequestV1,
        }
        write_projection_frame(
            &pending.0,
            &RequestEnvelope {
                command: REQUEST_COMMAND,
                schema_version: 1,
                grant_id: &self.grant.grant_id,
                token_hex: self.grant.token_hex.as_str(),
                request,
            },
            restricted_phase(deadline, MAX_CURRENT_WAIT)?,
            || self.require_channel(&pending.0),
        )?;
        self.require_channel(&pending.0)?;
        Ok(pending)
    }
}

/// Pending real native pairing, not a locally manufactured approval. Caller
/// cancellation only narrows all mandatory installed/kernel/expiry checks.
pub struct PendingInputProjectionPairV1 {
    provider: InstalledSignerProvider,
    socket: PathBuf,
    peer: PeerProcess,
    request: DurableInputProjectionRequestV1,
    scope: ProjectionPairScopeV1,
    pending: ProjectionStreamV1,
    started: Instant,
    deadline: Instant,
}
impl PendingInputProjectionPairV1 {
    pub fn finish(self) -> Result<NativeInputProjectionClientV1> {
        self.finish_checked(|| Ok(()))
    }
    pub fn finish_checked(
        self,
        mut check_current: impl FnMut() -> Result<()>,
    ) -> Result<NativeInputProjectionClientV1> {
        check_current()?;
        self.peer
            .same_live_process(&self.provider.verify_server(&self.pending.0)?)?;
        let bytes = framing::read_frame_capped_checked_until(
            &self.pending.0,
            &self.peer,
            MAX_INPUT_PROJECTION_FRAME_BYTES_V1,
            self.deadline,
            || {
                check_current()?;
                self.peer.check_alive()?;
                self.request.require_valid_at(now_ms()? / 1000)
            },
        )?;
        let response: ProjectionPairResponseV1 =
            wholepact_core::parse_typed_json(&bytes).map_err(|_| Error::InvalidData)?;
        validate_pair_response(&response, &self.scope)?;
        self.peer
            .same_live_process(&self.provider.verify_server(&self.pending.0)?)?;
        check_current()?;
        let expires = self
            .started
            .checked_add(Duration::from_secs(response.expires_in_seconds))
            .ok_or(Error::Permission)?
            .min(self.deadline);
        remaining_before(expires)?;
        let client = NativeInputProjectionClientV1 {
            provider: self.provider,
            socket: self.socket,
            peer: self.peer,
            request: self.request,
            scope: self.scope,
            binding: response.binding.clone(),
            grant: ClientGrant {
                grant_id: response.grant_id.clone(),
                token_hex: Zeroizing::new(response.token_hex.clone()),
                expires,
            },
            deadline: self.deadline,
            requested: AtomicBool::new(false),
        };
        // A separate purpose-specific request must prove actual token
        // possession. It cannot enter the ordinary Status/AppRequest route.
        let pending = client.open_request(&ProjectionRequestV1::Status, expires)?;
        let bytes = framing::read_frame_capped_checked_until(
            &pending.0,
            &client.peer,
            MAX_INPUT_PROJECTION_FRAME_BYTES_V1,
            restricted_phase(expires, MAX_CURRENT_WAIT)?,
            || {
                check_current()?;
                client.check_current()
            },
        )?;
        let ProjectionResponseV1::Current { binding } = decode_projection_response_v1(&bytes)?
        else {
            return Err(Error::Permission);
        };
        binding.validate()?;
        if binding != client.binding {
            return Err(Error::Binding);
        }
        client.require_channel(&pending.0)?;
        check_current()?;
        Ok(client)
    }
}

pub struct PendingDurableInputProjectionV1<'client> {
    client: &'client NativeInputProjectionClientV1,
    pending: ProjectionStreamV1,
    deadline: Instant,
}
impl PendingDurableInputProjectionV1<'_> {
    pub fn finish(self) -> Result<AuthenticatedDurableInputProjectionV1> {
        self.finish_checked(|| Ok(()))
    }
    pub fn finish_checked(
        self,
        mut check_current: impl FnMut() -> Result<()>,
    ) -> Result<AuthenticatedDurableInputProjectionV1> {
        check_current()?;
        self.client.require_channel(&self.pending.0)?;
        let bytes = framing::read_frame_capped_checked_until(
            &self.pending.0,
            &self.client.peer,
            MAX_INPUT_PROJECTION_FRAME_BYTES_V1,
            self.deadline,
            || {
                check_current()?;
                self.client.check_current()
            },
        )?;
        let ProjectionResponseV1::Retained { outbox } = decode_projection_response_v1(&bytes)?
        else {
            return Err(Error::Permission);
        };
        outbox.validate()?;
        if outbox.request != self.client.request || outbox.recipient != self.client.binding {
            return Err(Error::Binding);
        }
        self.client.require_channel(&self.pending.0)?;
        remaining_before(self.deadline)?;
        check_current()?;
        Ok(AuthenticatedDurableInputProjectionV1 {
            outbox: *outbox,
            signer_enrollment_reference: self.client.provider.native_enrollment_reference().into(),
            signer_process_instance: self.client.peer.instance().into(),
        })
    }
}

/// Sealed observation of exact bytes received from the actual installed signer
/// on this process's authenticated channel. It is historical provenance for
/// encrypted intake, NOT live native/scan/spending authority. No Clone,
/// Deserialize, public constructor or conversion from a public outbox exists.
pub struct AuthenticatedDurableInputProjectionV1 {
    outbox: DurableInputProjectionOutboxV1,
    signer_enrollment_reference: String,
    signer_process_instance: String,
}
impl AuthenticatedDurableInputProjectionV1 {
    pub fn outbox(&self) -> &DurableInputProjectionOutboxV1 {
        &self.outbox
    }
    pub fn signer_enrollment_reference(&self) -> &str {
        &self.signer_enrollment_reference
    }
    pub fn signer_process_instance(&self) -> &str {
        &self.signer_process_instance
    }
}

struct ProjectionStreamV1(UnixStream);
impl Drop for ProjectionStreamV1 {
    fn drop(&mut self) {
        let _ = self.0.shutdown(Shutdown::Both);
    }
}

fn projection_deadline(started: Instant, restriction: Option<Instant>) -> Result<Instant> {
    let maximum = started
        .checked_add(MAX_PROJECTION_OPERATION)
        .ok_or(Error::Permission)?;
    let deadline = restriction.map_or(maximum, |value| value.min(maximum));
    if deadline <= started {
        return Err(Error::Permission);
    }
    Ok(deadline)
}

fn validate_pair_response(
    response: &ProjectionPairResponseV1,
    scope: &ProjectionPairScopeV1,
) -> Result<()> {
    scope.validate()?;
    response.binding.validate()?;
    hash(&response.grant_id)?;
    hash(&response.token_hex)?;
    let token =
        Zeroizing::new(hex::decode(&response.token_hex).map_err(|_| Error::Authentication)?);
    let token_digest = hex::encode(Sha256::digest(token.as_slice()));
    if response.schema_version != 1
        || !response.accepted
        || response.reason_code != INPUT_PROJECTION_PAIR_REASON_V1
        || response.expires_in_seconds == 0
        || response.expires_in_seconds > MAX_PROJECTION_OPERATION.as_secs()
        || response.binding.scope != *scope
        || response.binding.grant_id != response.grant_id
        || response.binding.authenticated_local_grant_digest != token_digest
        || response.binding.pid != std::process::id()
        || response.binding.uid != unsafe { libc::geteuid() }
    {
        return Err(Error::Authentication);
    }
    Ok(())
}

fn write_projection_frame(
    stream: &UnixStream,
    value: &impl Serialize,
    deadline: Instant,
    mut check_current: impl FnMut() -> Result<()>,
) -> Result<()> {
    check_current()?;
    let mut bytes = Zeroizing::new(serde_json::to_vec(value).map_err(|_| Error::InvalidData)?);
    if bytes.len() >= MAX_INPUT_PROJECTION_FRAME_BYTES_V1 {
        return Err(Error::Limit);
    }
    bytes.push(b'\n');
    let mut offset = 0;
    let mut stream = stream;
    while offset < bytes.len() {
        check_current()?;
        stream.set_write_timeout(Some(remaining_before(deadline)?.min(MAX_CURRENT_WAIT)))?;
        match stream.write(&bytes[offset..]) {
            Ok(0) => return Err(Error::Ipc),
            Ok(written) => offset += written,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(Error::Ipc),
        }
        remaining_before(deadline)?;
        check_current()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projection_deadline_only_restricts_and_never_renews() {
        let now = Instant::now();
        assert!(projection_deadline(now, Some(now)).is_err());
        assert_eq!(
            projection_deadline(now, None).unwrap(),
            now + MAX_PROJECTION_OPERATION
        );
        assert_eq!(
            projection_deadline(now, Some(now + Duration::from_secs(3))).unwrap(),
            now + Duration::from_secs(3)
        );
        assert_eq!(
            projection_deadline(now, Some(now + Duration::from_secs(900))).unwrap(),
            now + MAX_PROJECTION_OPERATION
        );
    }

    #[test]
    fn ordinary_pair_response_cannot_decode_as_projection_pairing() {
        let ordinary = serde_json::json!({
            "schema_version":1, "accepted":true,
            "reason_code":"LOCAL_PROCESS_REQUEST_SCOPE",
            "grant_id":"a".repeat(64), "token_hex":"b".repeat(64),
            "expires_in_seconds":900,
        });
        assert!(
            wholepact_core::parse_typed_json::<ProjectionPairResponseV1>(
                &serde_json::to_vec(&ordinary).unwrap()
            )
            .is_err()
        );
    }
}
