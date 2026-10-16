//! One fresh pairing and one evidence request. This endpoint is owned and
//! polled by the native session worker; it never creates another worker thread.
//! The installed client gate stays closed before any endpoint side effect.
use super::super::{Grant, PairScope, PendingPairing, enable_credentials, issue_pairing_grant};
use super::{
    AuthenticatedRetirementEvidenceRequestV1, DeliveryIo, RetainedRequestChannel,
    check_exact_request_channel, encode_frame_until,
    receive_authenticated_retirement_evidence_request, remaining_at, write_bytes_until,
};
use crate::{
    Error, Result,
    files::PrivateDirectory,
    native_peer::PeerProcess,
    native_ui::{NativeAuthority, NativeAuthorityBinding, NativeDecision},
    review::validate_label,
};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Write},
    net::Shutdown,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use wholepact_signer_origin::retirement_evidence::{
    FRAME_LIMIT, PAIR_AGREEMENT_ID, PAIR_PARTICIPANT_ID,
};
use zeroize::Zeroizing;

const READ_BUDGET: Duration = Duration::from_secs(2);
const GENERATION: u64 = 1;

/// No generic request tag, empty variant, optional authority field or fallback.
#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum PairingEnvelope {
    RequestPairing {
        schema_version: u16,
        application_label: String,
        scope: PairScope,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Admission {
    Fresh,
    Pairing,
    Paired,
    Sealed,
}
impl Admission {
    fn advance(&mut self, expected: Self, next: Self) -> Result<()> {
        if *self != expected {
            return Err(Error::Authentication);
        }
        *self = next;
        Ok(())
    }
    fn accepts_connection(self) -> bool {
        matches!(self, Self::Fresh | Self::Paired)
    }
}

struct ActiveChannel {
    stream: UnixStream,
    cancelled: Arc<AtomicBool>,
}
impl ActiveChannel {
    fn close(&self) {
        self.cancelled.store(true, Ordering::Release);
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

/// Restriction-only and monotone. The native caller revokes its owner first.
/// Neither mutex is held across IO. A racing registration rechecks cancellation
/// after releasing its lock, so try_lock cancellation cannot miss a new channel.
#[derive(Clone)]
pub(crate) struct RetirementEndpointCancellation {
    cancelled: Arc<AtomicBool>,
    active: Arc<Mutex<Option<ActiveChannel>>>,
    grants: Arc<Mutex<BTreeMap<String, Grant>>>,
}
impl RetirementEndpointCancellation {
    pub(crate) fn cancel(&self) {
        self.cancelled.swap(true, Ordering::SeqCst);
        let active = self
            .active
            .try_lock()
            .ok()
            .and_then(|mut active| active.take());
        if let Some(active) = active {
            active.close();
        }
        // A racing issuer checks the flag after releasing this mutex. Native
        // invalidation already prevents authentication while that lock drains.
        if let Ok(mut grants) = self.grants.try_lock() {
            grants.clear();
        }
    }
}

/// Only removes the exact filesystem entry this bind created. A replacement,
/// symlink or preexisting socket is never removed or adopted.
struct OwnedSocketPath {
    path: PathBuf,
    device: u64,
    inode: u64,
}
impl Drop for OwnedSocketPath {
    fn drop(&mut self) {
        if let Ok(metadata) = fs::symlink_metadata(&self.path) {
            if metadata.dev() == self.device && metadata.ino() == self.inode {
                let _ = fs::remove_file(&self.path);
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct SocketIdentity {
    device: libc::dev_t,
    inode: libc::ino_t,
}
fn socket_identity(stream: &UnixStream) -> Result<SocketIdentity> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: valid descriptor and initialized output storage of the right type.
    if unsafe { libc::fstat(stream.as_raw_fd(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(SocketIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
    })
}
struct OriginalPairing {
    socket: SocketIdentity,
    created: Instant,
    digest: String,
}
impl OriginalPairing {
    fn require(&self, pending: &PendingPairing) -> Result<()> {
        if self.socket != socket_identity(&pending.stream)?
            || self.created != pending.created
            || self.digest != pending.review_digest(GENERATION)?
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
}

pub(crate) enum RetirementEndpointEvent {
    Pairing(PendingPairing),
    Evidence(Box<AuthenticatedRetirementEvidenceRequestV1>),
}

pub(crate) struct RetirementEvidenceEndpoint {
    listener: Option<UnixListener>,
    path: OwnedSocketPath,
    cancellation: RetirementEndpointCancellation,
    native: NativeAuthorityBinding,
    source_account_id: String,
    deadline: Instant,
    admission: Admission,
    pairing: Option<OriginalPairing>,
    // The original private-directory lock survives endpoint delivery and drain.
    _directory: PrivateDirectory,
}
impl RetirementEvidenceEndpoint {
    pub(crate) fn bind(
        directory: PrivateDirectory,
        native: &NativeAuthority,
        source_account_id: String,
        deadline: Instant,
    ) -> Result<Self> {
        wholepact_signer_origin::retirement_evidence::require_native_transport_activation_v1()
            .map_err(|_| Error::Unavailable)?;
        native.check_current()?;
        validate_label(&source_account_id)?;
        let binding = native.binding();
        let deadline = require_native_ceiling(binding.deadline(), deadline, Instant::now())?;
        let path = directory.root().join(format!(
            "retirement-evidence-{}.sock",
            hex::encode(crate::vault::random::<12>()?)
        ));
        // bind refuses existing entries; no cleanup/removal happens before bind.
        let listener = UnixListener::bind(&path)?;
        let metadata = fs::symlink_metadata(&path)?;
        let path = OwnedSocketPath {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        fs::set_permissions(&path.path, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        enable_credentials(listener.as_raw_fd())?;
        let endpoint = Self {
            listener: Some(listener),
            path,
            cancellation: RetirementEndpointCancellation {
                cancelled: Arc::new(AtomicBool::new(false)),
                active: Arc::new(Mutex::new(None)),
                grants: Arc::new(Mutex::new(BTreeMap::new())),
            },
            native: binding,
            source_account_id,
            deadline,
            admission: Admission::Fresh,
            pairing: None,
            _directory: directory,
        };
        endpoint.check_current()?;
        Ok(endpoint)
    }

    pub(crate) fn socket_path(&self) -> &Path {
        &self.path.path
    }
    pub(crate) fn generation(&self) -> u64 {
        GENERATION
    }
    pub(crate) fn cancellation_handle(&self) -> RetirementEndpointCancellation {
        self.cancellation.clone()
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        if self.cancellation.cancelled.load(Ordering::Acquire) {
            return Err(Error::Authentication);
        }
        self.native.check_current()?;
        remaining_at(self.deadline, Instant::now())?;
        Ok(())
    }

    /// Keep the exact pending connection current throughout native review.
    /// A live process cannot substitute for this channel remaining open, nor
    /// append another request while its original pairing review is pending.
    pub(crate) fn check_pairing_current(&self, pending: &PendingPairing) -> Result<()> {
        self.check_current()?;
        if self.admission != Admission::Pairing {
            return Err(Error::Authentication);
        }
        self.pairing
            .as_ref()
            .ok_or(Error::Authentication)?
            .require(pending)?;
        require_reserved_scope(&pending.scope, &self.source_account_id)?;
        pending.check_current()?;
        check_exact_request_channel(&pending.stream, &pending.peer)?;
        pending.check_current()?;
        self.check_current()
    }

    /// Nonblocking accept; at most one credentialed, capped read with a two
    /// second ceiling, always shortened by the original native entry deadline.
    pub(crate) fn next_event(&mut self) -> Result<Option<RetirementEndpointEvent>> {
        let result = self.next_event_inner();
        if result.is_err() {
            self.cancellation.cancel();
        }
        result
    }
    fn next_event_inner(&mut self) -> Result<Option<RetirementEndpointEvent>> {
        self.check_current()?;
        if !self.admission.accepts_connection() {
            return Ok(None);
        }
        let listener = self.listener.as_ref().ok_or(Error::Authentication)?;
        let (stream, _) = match listener.accept() {
            Ok(connection) => connection,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        };
        // Admission predates peer observation, all bytes, parsing and review.
        let admitted_at = Instant::now();
        let cancelled = Arc::new(AtomicBool::new(false));
        self.retain_active(&stream, &cancelled)?;
        self.check_current()?;
        stream.set_nonblocking(false)?;
        enable_credentials(stream.as_raw_fd())?;
        let observed = PeerProcess::observe(&stream)?;
        let read_deadline = phase_deadline(admitted_at, self.deadline)?;
        let frame = wholepact_signer_origin::framing::read_frame_capped_until(
            &stream,
            &observed,
            FRAME_LIMIT,
            read_deadline,
        )?;
        self.check_current()?;
        remaining_at(read_deadline, Instant::now())?;
        match self.admission {
            Admission::Fresh => {
                let PairingEnvelope::RequestPairing {
                    schema_version,
                    application_label,
                    scope,
                } = serde_json::from_slice(&frame).map_err(|_| Error::InvalidData)?;
                if schema_version != 1 {
                    return Err(Error::InvalidData);
                }
                validate_label(&application_label)?;
                require_reserved_scope(&scope, &self.source_account_id)?;
                check_exact_request_channel(&stream, &observed)?;
                let pending = PendingPairing {
                    peer: observed,
                    label: application_label,
                    scope,
                    stream,
                    created: admitted_at,
                };
                self.pairing = Some(OriginalPairing {
                    socket: socket_identity(&pending.stream)?,
                    created: admitted_at,
                    digest: pending.review_digest(GENERATION)?,
                });
                self.admission
                    .advance(Admission::Fresh, Admission::Pairing)?;
                self.check_current()?;
                Ok(Some(RetirementEndpointEvent::Pairing(pending)))
            }
            Admission::Paired => {
                let owner = receive_authenticated_retirement_evidence_request(
                    &self.cancellation.grants,
                    RetainedRequestChannel { stream, cancelled },
                    observed,
                    &frame,
                    admitted_at,
                    self.deadline,
                )?;
                require_reserved_scope(&owner.peer.scope, &self.source_account_id)?;
                if owner.peer.native_origin != self.native
                    || owner.request.source_account_id != self.source_account_id
                {
                    return Err(Error::Authentication);
                }
                owner.check_current()?;
                self.check_current()?;
                self.admission
                    .advance(Admission::Paired, Admission::Sealed)?;
                // Stop accepting without touching the fresh Grant. The endpoint
                // and registry remain owned until final delivery/drain finishes.
                self.listener.take();
                Ok(Some(RetirementEndpointEvent::Evidence(Box::new(owner))))
            }
            _ => Err(Error::Authentication),
        }
    }

    fn retain_active(&self, stream: &UnixStream, cancelled: &Arc<AtomicBool>) -> Result<()> {
        let mut active = self.cancellation.active.lock().map_err(|_| Error::Locked)?;
        if active.is_some() {
            return Err(Error::Authentication);
        }
        *active = Some(ActiveChannel {
            stream: stream.try_clone()?,
            cancelled: Arc::clone(cancelled),
        });
        drop(active);
        // This RMW and cancel's swap have one total order. If cancellation
        // skipped the held lock, this observes it; otherwise cancel can acquire
        // the released lock. Plain release-store/acquire-load is insufficient.
        if self
            .cancellation
            .cancelled
            .fetch_or(false, Ordering::SeqCst)
            || self.check_current().is_err()
        {
            self.cancellation.cancel();
            return Err(Error::Authentication);
        }
        Ok(())
    }

    pub(crate) fn approve_pairing(
        &mut self,
        pending: PendingPairing,
        decision: NativeDecision,
        native: &NativeAuthority,
    ) -> Result<()> {
        let result = self.approve_pairing_inner(&pending, decision, native);
        // A single terminal response, including EOF, satisfies the dedicated
        // client. Failure can follow partial token disclosure; never retry.
        let close = pending.stream.shutdown(Shutdown::Both).map_err(Error::from);
        let result = result.and(close).and_then(|()| self.check_current());
        if result.is_err() {
            self.cancellation.cancel();
        } else {
            // Clearing the restriction clone does not revoke the issued Grant.
            self.cancellation
                .active
                .lock()
                .map_err(|_| Error::Locked)?
                .take();
            self.pairing.take();
            self.admission
                .advance(Admission::Pairing, Admission::Paired)?;
        }
        result
    }
    fn approve_pairing_inner(
        &self,
        pending: &PendingPairing,
        decision: NativeDecision,
        native: &NativeAuthority,
    ) -> Result<()> {
        self.check_pairing_current(pending)?;
        if native.binding() != self.native
            || decision.binding() != &self.native
            || decision.reviewed_digest() != pending.review_digest(GENERATION)?
        {
            return Err(Error::Authentication);
        }
        let (id, secret, grant) =
            issue_pairing_grant(pending, native, GENERATION, Some(self.deadline))?;
        let current = Arc::clone(&grant.current);
        let expires = grant.expires;
        {
            let mut grants = self.cancellation.grants.lock().map_err(|_| Error::Locked)?;
            if !grants.is_empty() {
                return Err(Error::Authentication);
            }
            grants.insert(id.clone(), grant);
        }
        // The publication RMW pairs with cancel's swap just as active-channel
        // registration does. A cancelled insert is revoked by the outer error
        // path, without waiting on a registry lock in the native caller.
        if self
            .cancellation
            .cancelled
            .fetch_or(false, Ordering::SeqCst)
        {
            return Err(Error::Authentication);
        }
        self.check_current()?;
        let token = Zeroizing::new(hex::encode(secret.as_slice()));
        #[derive(serde::Serialize)]
        struct PairResponse<'a> {
            schema_version: u16,
            accepted: bool,
            reason_code: &'static str,
            grant_id: &'a str,
            token_hex: &'a str,
            expires_in_seconds: u64,
        }
        // Relative time is measured from the original pairing admission by the
        // existing client. Round down and never restart a 900 second lease.
        let seconds = expires
            .checked_duration_since(pending.created)
            .filter(|time| !time.is_zero())
            .ok_or(Error::Authentication)?
            .as_secs();
        if seconds == 0 || seconds > 120 {
            return Err(Error::Authentication);
        }
        let response = PairResponse {
            schema_version: 1,
            accepted: true,
            reason_code: "LOCAL_PROCESS_REQUEST_SCOPE",
            grant_id: &id,
            token_hex: &token,
            expires_in_seconds: seconds,
        };
        let mut io = PairingIo {
            endpoint: self,
            pending,
            current,
            deadline: expires,
        };
        let bytes = encode_frame_until(&response, expires, &mut io)?;
        write_bytes_until(&bytes, expires, &mut io)?;
        io.check()
    }
}
impl Drop for RetirementEvidenceEndpoint {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.listener.take();
        // The worker owns the endpoint until delivery/drain. No joins, other
        // registry, inherited ordinary grants, or socket adoption occur here.
    }
}

struct PairingIo<'a> {
    endpoint: &'a RetirementEvidenceEndpoint,
    pending: &'a PendingPairing,
    current: Arc<AtomicBool>,
    deadline: Instant,
}
impl DeliveryIo for PairingIo<'_> {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn check(&mut self) -> Result<()> {
        self.endpoint.check_current()?;
        remaining_at(self.deadline, self.now())?;
        if !self.current.load(Ordering::Acquire) {
            return Err(Error::Authentication);
        }
        self.pending.check_current()?;
        check_exact_request_channel(&self.pending.stream, &self.pending.peer)?;
        self.endpoint.check_current()
    }
    fn write(&mut self, bytes: &[u8], timeout: Duration) -> io::Result<usize> {
        self.pending.stream.set_write_timeout(Some(timeout))?;
        let mut stream = &self.pending.stream;
        stream.write(bytes)
    }
}

fn require_reserved_scope(scope: &PairScope, source: &str) -> Result<()> {
    scope.validate()?;
    if scope.account_id != source
        || scope.agreement_id != PAIR_AGREEMENT_ID
        || scope.participant_id != PAIR_PARTICIPANT_ID
        || scope.history_read
        || scope.authorization_export
        || scope.preconstruction_export
    {
        return Err(Error::Authentication);
    }
    Ok(())
}
fn require_native_ceiling(
    native: Option<Instant>,
    entry: Instant,
    now: Instant,
) -> Result<Instant> {
    let native = native.ok_or(Error::Authentication)?;
    if native > entry || remaining_at(entry, now)? > super::REQUEST_BUDGET {
        return Err(Error::Authentication);
    }
    remaining_at(native, now)?;
    Ok(native)
}
fn phase_deadline(admitted: Instant, entry: Instant) -> Result<Instant> {
    remaining_at(entry, admitted)?;
    Ok((admitted + READ_BUDGET).min(entry))
}

#[cfg(test)]
#[path = "endpoint_tests.rs"]
mod tests;
