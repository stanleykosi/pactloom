//! Authenticated original-history and retained-result IPC. The server holds
//! original permission through the consumer's final retention/CAS commit. A
//! redelivery request can only stage a separate actual native review; the client
//! cannot supply approval, unlock, signing or a generic journal operation.
use super::{
    BridgeError, Result, protocol::OriginalAuthorizationView, provider::InstalledSignerProvider,
};
use crate::{
    consent_journal::{SignerConsentJournal, SignerConsentSession},
    ipc::{AuthenticatedPeer, PairScope},
    native_peer::PeerProcess,
};
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    os::{fd::AsRawFd, unix::net::UnixStream},
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryRequest {
    pub authorization_id: String,
    pub expected_original_consent_ref: String,
    pub expected_enrollment_ref: String,
    pub expected_manifest_ref: String,
}
impl HistoryRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        crate::review::validate_label(&self.authorization_id).map_err(|_| BridgeError::Binding)?;
        for h in [
            &self.expected_original_consent_ref,
            &self.expected_enrollment_ref,
            &self.expected_manifest_ref,
        ] {
            if h.len() != 64
                || !h
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(BridgeError::Binding);
            }
        }
        Ok(())
    }
    pub(crate) fn matches(&self, e: &OriginalAuthorizationView) -> Result<()> {
        self.validate()?;
        if e.consent.terms().authorization_id != self.authorization_id
            || e.consent.reference() != self.expected_original_consent_ref
            || e.enrollment.reference() != self.expected_enrollment_ref
            || e.accepted_manifest.reference() != self.expected_manifest_ref
        {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum LeaseRequest {
    CheckCurrent,
    Finish,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum LeaseResponse {
    Original {
        lease_id: String,
        evidence: Box<OriginalAuthorizationView>,
    },
    Current {
        lease_id: String,
    },
    Finished,
    Denied,
}

/// Native runtime dispatches this only after actual kernel peer credentials and
/// capability proof have authenticated a separately approved history-read grant.
pub(crate) fn serve_original_history(
    stream: UnixStream,
    peer: AuthenticatedPeer,
    request: HistoryRequest,
    journal: &SignerConsentJournal,
    session: &SignerConsentSession,
) -> Result<()> {
    serve_history(stream, peer, request, None, journal, session)
}
pub(crate) fn serve_history(
    mut stream: UnixStream,
    peer: AuthenticatedPeer,
    request: HistoryRequest,
    redelivery: Option<crate::consent_journal::ResultRedeliveryReference>,
    journal: &SignerConsentJournal,
    session: &SignerConsentSession,
) -> Result<()> {
    request.validate()?;
    peer.check_current().map_err(|_| BridgeError::Permission)?;
    if !peer.scope.history_read {
        return Err(BridgeError::Permission);
    }
    let lease = journal.acquire_original_authorization(&request.authorization_id, session)?;
    let mut evidence = OriginalAuthorizationView::from_original(lease.evidence());
    request.matches(&evidence)?;
    if evidence.enrollment.account_id() != peer.scope.account_id
        || evidence.enrollment.agreement_id() != peer.scope.agreement_id
        || evidence.enrollment.participant_id() != peer.scope.participant_id
        || evidence.accepted_manifest.manifest_digest() != peer.scope.manifest_digest
    {
        return Err(BridgeError::Permission);
    }
    let recipient = authorized_recipient(journal, &lease, &peer, redelivery.as_ref())?;
    if peer.scope.authorization_export && recipient.is_some() {
        match journal.bridge_result(&lease) {
            Ok(result) => {
                evidence.retained_result = Some(super::protocol::RetainedResultIdentity {
                    authorization_id: result.authorization_id.clone(),
                    original_consent_ref: result.original_consent_ref.clone(),
                    result_digest: result.result_digest.clone(),
                    outbox_digest: result.outbox_digest.clone(),
                    exact_local_recipient: recipient.clone().ok_or(BridgeError::Permission)?,
                    redelivery: redelivery.clone(),
                })
            }
            Err(BridgeError::Missing | BridgeError::Uncertain) => {}
            Err(error) => return Err(error),
        }
    }
    let lease_id = hex::encode(crate::vault::random::<32>().map_err(|_| BridgeError::Ipc)?);
    let response = LeaseResponse::Original {
        lease_id: lease_id.clone(),
        evidence: Box::new(evidence),
    };
    lease.check_current()?;
    peer.check_current().map_err(|_| BridgeError::Permission)?;
    if write_frame(&mut stream, &response).is_err() {
        retain_uncertain_consumer(&mut stream, &peer);
        return Err(BridgeError::Ipc);
    }
    loop {
        let frame = match crate::ipc::read_frame_with_deadline(
            &stream,
            &peer.peer,
            Duration::from_secs(120),
        ) {
            Ok(frame) => frame,
            Err(_) => {
                retain_uncertain_consumer(&mut stream, &peer);
                return Err(BridgeError::Ipc);
            }
        };
        let command: LeaseRequest = match serde_json::from_slice(&frame) {
            Ok(command) => command,
            Err(_) => {
                retain_uncertain_consumer(&mut stream, &peer);
                return Err(BridgeError::Ipc);
            }
        };
        match command {
            LeaseRequest::Finish => {
                let _ = write_frame(&mut stream, &LeaseResponse::Finished);
                return Ok(());
            }
            LeaseRequest::CheckCurrent => {
                if lease.check_current().is_err() || peer.check_current().is_err() {
                    let _ = write_frame(&mut stream, &LeaseResponse::Denied);
                    retain_uncertain_consumer(&mut stream, &peer);
                    return Err(BridgeError::Permission);
                }
                if write_frame(
                    &mut stream,
                    &LeaseResponse::Current {
                        lease_id: lease_id.clone(),
                    },
                )
                .is_err()
                {
                    retain_uncertain_consumer(&mut stream, &peer);
                    return Err(BridgeError::Ipc);
                }
            }
        }
    }
}
fn retain_uncertain_consumer(stream: &mut UnixStream, peer: &AuthenticatedPeer) {
    // A disconnected consumer could still be inside the final database commit.
    // Dropping permission after a timeout would falsely complete revocation.
    // The same stable peer may explicitly finish while unwinding a failed check;
    // no other request can disclose data or release the in-flight lease.
    while peer.peer.check_alive().is_ok() {
        let finished =
            crate::ipc::read_frame_with_deadline(stream, &peer.peer, Duration::from_secs(2))
                .ok()
                .and_then(|frame| serde_json::from_slice::<LeaseRequest>(&frame).ok())
                .is_some_and(|request| matches!(request, LeaseRequest::Finish));
        if finished {
            let _ = write_frame(stream, &LeaseResponse::Finished);
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    let bytes = Zeroizing::new(serde_json::to_vec(value).map_err(|_| BridgeError::Ipc)?);
    if bytes.len() > 2_100_000 {
        return Err(BridgeError::Limit);
    }
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| BridgeError::Ipc)?;
    stream
        .write_all(&bytes)
        .and_then(|_| stream.write_all(b"\n"))
        .and_then(|_| stream.flush())
        .map_err(|_| BridgeError::Ipc)
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
/// Pairing wire negotiation stays identical. Only the explicit restricted path
/// defers its channel-key possession proof to the first authenticated bounded V5
/// request; the restricted listener must never receive a Status probe.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum PairingMode {
    #[default]
    Ordinary,
    QuarantinedInformational,
}
impl PairingMode {
    fn validate_scope(self, scope: &PairScope) -> Result<()> {
        if self == Self::QuarantinedInformational {
            // Run before opening any connection. The full exact inventory is
            // still checked by the native listener and every V5 request.
            scope.validate().map_err(|_| BridgeError::Binding)?;
            if !scope.history_read || !scope.authorization_export || scope.preconstruction_export {
                return Err(BridgeError::Permission);
            }
        }
        Ok(())
    }
    /// Restriction-only teardown predicate. This neither attests successful
    /// continuity nor creates a native or provider capability.
    fn require_provider_release(self, active_leases: usize) -> Result<()> {
        if self != Self::QuarantinedInformational || active_leases != 0 {
            return Err(BridgeError::Permission);
        }
        Ok(())
    }
    fn possession_probe(self) -> Option<serde_json::Value> {
        match self {
            Self::Ordinary => Some(serde_json::json!({"operation":"status"})),
            Self::QuarantinedInformational => None,
        }
    }
}

/// Authenticated actual installed signer process plus an exact native-approved
/// local history grant. There is no constructor from caller-provided evidence.
pub struct OriginalHistoryClient {
    provider: InstalledSignerProvider,
    socket: PathBuf,
    peer: PeerProcess,
    scope: PairScope,
    grant: ClientGrant,
    active_leases: AtomicUsize,
    mode: PairingMode,
}
impl OriginalHistoryClient {
    /// Consumes a restricted client and destroys its local pairing grant/token,
    /// scope and peer handles, retaining only the already-owned installed-image
    /// and direct-child provenance. The parent report channel stays alive so the
    /// same native window can perform a separately approved fresh source entry.
    ///
    /// This is teardown, not a successful-Finish assertion or permission. The
    /// Host calls explicit continuity Finish first; the signer's independent
    /// one-shot completion marker enforces that ordering before publication.
    /// A fresh pairing, source/witness entry and exact native review remain
    /// mandatory. No prior credential or native/source owner is returned.
    pub fn into_quarantined_unpaired_provider(self) -> Result<InstalledSignerProvider> {
        self.mode
            .require_provider_release(self.active_leases.load(Ordering::Acquire))?;
        // Every lease borrows this client, so safe Rust cannot consume it while
        // such a lease is live. The counter is an additional fail-closed check.
        let Self {
            provider,
            socket,
            peer,
            scope,
            grant,
            active_leases: _,
            mode: _,
        } = self;
        // ClientGrant owns a Zeroizing token. Explicit destruction happens
        // before the provenance owner becomes visible to the caller. This does
        // not send revocation or claim remote credential erasure; native blur
        // independently revokes the original grant and all actual source owners.
        drop(grant);
        drop(scope);
        drop(socket);
        drop(peer);
        Ok(provider)
    }

    /// Supported installed profile, including a nondumpable signer: launch the
    /// exact pinned image, obtain its private endpoint after native unlock, then
    /// ask for the exact history scope on the signer's own native window.
    pub fn launch_and_pair(
        provider: InstalledSignerProvider,
        application_label: &str,
        scope: PairScope,
    ) -> Result<Self> {
        provider.launch_native()?;
        let endpoint = provider.wait_native_endpoint(Duration::from_secs(120))?;
        Self::pair(provider, &endpoint, application_label, scope)
    }

    /// Requests the signer's distinct native pairing decision, then proves this
    /// process possesses its granted channel key with the ordinary Status probe.
    pub fn pair(
        provider: InstalledSignerProvider,
        socket: &Path,
        application_label: &str,
        scope: PairScope,
    ) -> Result<Self> {
        Self::pair_with_mode(
            provider,
            socket,
            application_label,
            scope,
            PairingMode::Ordinary,
        )
    }

    /// Requests only the separately entered quarantined informational mode's
    /// native pairing decision. Scope is checked before connection; no Status
    /// request is sent. The first authenticated bounded V5 request proves this
    /// process's channel-key possession and binds the native owner's first peer.
    /// Pairing itself is never continuity, publication or financial admission.
    pub fn pair_quarantined_informational(
        provider: InstalledSignerProvider,
        socket: &Path,
        application_label: &str,
        scope: PairScope,
    ) -> Result<Self> {
        Self::pair_with_mode(
            provider,
            socket,
            application_label,
            scope,
            PairingMode::QuarantinedInformational,
        )
    }

    fn pair_with_mode(
        provider: InstalledSignerProvider,
        socket: &Path,
        application_label: &str,
        scope: PairScope,
        mode: PairingMode,
    ) -> Result<Self> {
        mode.validate_scope(&scope)?;
        crate::review::validate_label(application_label).map_err(|_| BridgeError::Binding)?;
        let mut stream = UnixStream::connect(socket).map_err(|_| BridgeError::Ipc)?;
        crate::ipc::enable_credentials(stream.as_raw_fd()).map_err(|_| BridgeError::Ipc)?;
        let peer = provider.verify_server(&stream)?;
        let started = Instant::now();
        write_frame(
            &mut stream,
            &serde_json::json!({"command":"request_pairing","schema_version":1,"application_label":application_label,"scope":scope}),
        )?;
        let frame = crate::ipc::read_frame_with_deadline(&stream, &peer, Duration::from_secs(120))
            .map_err(|_| BridgeError::Ipc)?;
        let response: PairResponse =
            serde_json::from_slice(&frame).map_err(|_| BridgeError::Permission)?;
        if response.schema_version != 1
            || !response.accepted
            || response.reason_code != "LOCAL_PROCESS_REQUEST_SCOPE"
            || response.expires_in_seconds == 0
            || response.expires_in_seconds > 900
            || response.grant_id.len() != 64
            || response.token_hex.len() != 64
            || !response
                .grant_id
                .bytes()
                .chain(response.token_hex.bytes())
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(BridgeError::Permission);
        }
        peer.check_alive().map_err(|_| BridgeError::Permission)?;
        let grant = ClientGrant {
            grant_id: response.grant_id.clone(),
            token_hex: Zeroizing::new(response.token_hex.clone()),
            expires: started + Duration::from_secs(response.expires_in_seconds),
        };
        let client = Self {
            provider,
            socket: socket.into(),
            peer,
            scope,
            grant,
            active_leases: AtomicUsize::new(0),
            mode,
        };
        if let Some(probe) = mode.possession_probe() {
            // Ordinary pairing keeps its existing immediate possession proof.
            // Restricted pairing authenticates through its first bounded V5
            // request instead; native approval is still separately required.
            let stream = client.open_scoped_request(probe)?;
            let frame =
                crate::ipc::read_frame_with_deadline(&stream, &client.peer, Duration::from_secs(2))
                    .map_err(|_| BridgeError::Ipc)?;
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Accepted {
                accepted: bool,
                reason_code: String,
            }
            let response: Accepted =
                serde_json::from_slice(&frame).map_err(|_| BridgeError::Ipc)?;
            if !response.accepted || response.reason_code != "REQUEST_ONLY" {
                return Err(BridgeError::Permission);
            }
        }
        Ok(client)
    }
    pub fn acquire(&self, request: &HistoryRequest) -> Result<OriginalHistoryLease<'_>> {
        self.acquire_with_redelivery(request, None)
    }
    pub fn acquire_redelivered(
        &self,
        request: &HistoryRequest,
        redelivery: &crate::consent_journal::ResultRedeliveryReference,
    ) -> Result<OriginalHistoryLease<'_>> {
        redelivery.validate()?;
        self.acquire_with_redelivery(request, Some(redelivery))
    }
    fn acquire_with_redelivery(
        &self,
        request: &HistoryRequest,
        redelivery: Option<&crate::consent_journal::ResultRedeliveryReference>,
    ) -> Result<OriginalHistoryLease<'_>> {
        request.validate()?;
        let mut observed = self.active_leases.load(Ordering::Acquire);
        loop {
            if observed >= 8 {
                return Err(BridgeError::Limit);
            }
            match self.active_leases.compare_exchange_weak(
                observed,
                observed + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => observed = current,
            }
        }
        let admission = ReadAdmission(&self.active_leases);
        if Instant::now() >= self.grant.expires {
            return Err(BridgeError::Permission);
        }
        self.peer
            .check_alive()
            .map_err(|_| BridgeError::Permission)?;
        let mut stream = UnixStream::connect(&self.socket).map_err(|_| BridgeError::Ipc)?;
        crate::ipc::enable_credentials(stream.as_raw_fd()).map_err(|_| BridgeError::Ipc)?;
        let actual = self.provider.verify_server(&stream)?;
        self.peer
            .same_live_process(&actual)
            .map_err(|_| BridgeError::Permission)?;
        write_frame(
            &mut stream,
            &serde_json::json!({"command":"request","schema_version":1,"grant_id":self.grant.grant_id,"token_hex":self.grant.token_hex.as_str(),"request": if let Some(redelivery) = redelivery { serde_json::json!({"operation":"acquire_redelivered_authorization","history":request,"redelivery":redelivery}) } else { serde_json::json!({"operation":"acquire_original_authorization","history":request}) }}),
        )?;
        let frame =
            crate::ipc::read_frame_with_deadline(&stream, &self.peer, Duration::from_secs(2))
                .map_err(|_| BridgeError::Ipc)?;
        let response: LeaseResponse =
            serde_json::from_slice(&frame).map_err(|_| BridgeError::Ipc)?;
        let LeaseResponse::Original { lease_id, evidence } = response else {
            return Err(BridgeError::Permission);
        };
        request.matches(&evidence)?;
        if evidence
            .retained_result
            .as_ref()
            .and_then(|r| r.redelivery.as_ref())
            != redelivery
        {
            return Err(BridgeError::Binding);
        }
        if evidence.enrollment.account_id() != self.scope.account_id
            || evidence.enrollment.agreement_id() != self.scope.agreement_id
            || evidence.enrollment.participant_id() != self.scope.participant_id
            || evidence.accepted_manifest.manifest_digest() != self.scope.manifest_digest
        {
            return Err(BridgeError::Binding);
        }
        let lease = OriginalHistoryLease {
            client: self,
            stream: Mutex::new(stream),
            lease_id,
            evidence: *evidence,
            _admission: admission,
        };
        lease.check_current()?;
        Ok(lease)
    }
}
/// Keep this object alive through the caller's final private effect/record CAS.
/// Dropping it sends Finish on the same authenticated process-bound channel.
pub struct OriginalHistoryLease<'a> {
    client: &'a OriginalHistoryClient,
    stream: Mutex<UnixStream>,
    lease_id: String,
    evidence: OriginalAuthorizationView,
    _admission: ReadAdmission<'a>,
}
impl OriginalHistoryLease<'_> {
    /// Includes a separately native-approved redelivery, when present. The
    /// protected signer validated its immutable redelivery record before export.
    pub fn result_is_for_current_recipient(&self) -> bool {
        self.evidence
            .retained_result
            .as_ref()
            .is_some_and(|result| {
                matches!(&result.exact_local_recipient,
                crate::consent_journal::TransportIdentityBinding::LocalProcess {
                    transport_identity_id, account_id, agreement_id, participant_id,
                    manifest_digest, ..
                } if transport_identity_id == &self.client.grant.grant_id
                    && account_id == &self.client.scope.account_id
                    && agreement_id == &self.client.scope.agreement_id
                    && participant_id == &self.client.scope.participant_id
                    && manifest_digest == &self.client.scope.manifest_digest)
            })
    }
    pub(crate) fn belongs_to(&self, client: &OriginalHistoryClient) -> bool {
        std::ptr::eq(self.client, client)
    }

    pub fn provider_enrollment_reference(&self) -> &str {
        self.client.provider.native_enrollment_reference()
    }

    pub fn evidence(&self) -> &OriginalAuthorizationView {
        &self.evidence
    }
    pub fn check_current(&self) -> Result<()> {
        if Instant::now() >= self.client.grant.expires {
            return Err(BridgeError::Permission);
        }
        self.client
            .peer
            .check_alive()
            .map_err(|_| BridgeError::Permission)?;
        let mut stream = self.stream.lock().map_err(|_| BridgeError::Ipc)?;
        write_frame(&mut stream, &LeaseRequest::CheckCurrent)?;
        let frame = crate::ipc::read_frame_with_deadline(
            &stream,
            &self.client.peer,
            Duration::from_secs(2),
        )
        .map_err(|_| BridgeError::Ipc)?;
        match serde_json::from_slice(&frame).map_err(|_| BridgeError::Ipc)? {
            LeaseResponse::Current { lease_id } if lease_id == self.lease_id => Ok(()),
            _ => Err(BridgeError::Permission),
        }
    }
}
impl Drop for OriginalHistoryLease<'_> {
    fn drop(&mut self) {
        if let Ok(mut stream) = self.stream.lock() {
            let _ = write_frame(&mut stream, &LeaseRequest::Finish);
        }
    }
}

struct ReadAdmission<'a>(&'a AtomicUsize);
impl Drop for ReadAdmission<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Native export is exactbytes only, and restricted to the very same originally
/// approved local process/channel. Re-pairing never silently changes recipient.
pub(crate) fn serve_original_authorization_result(
    stream: UnixStream,
    peer: AuthenticatedPeer,
    history: HistoryRequest,
    journal: &SignerConsentJournal,
    session: &SignerConsentSession,
) -> Result<()> {
    serve_authorization_result(stream, peer, history, None, journal, session)
}
pub(crate) fn serve_authorization_result(
    mut stream: UnixStream,
    peer: AuthenticatedPeer,
    history: HistoryRequest,
    redelivery: Option<crate::consent_journal::ResultRedeliveryReference>,
    journal: &SignerConsentJournal,
    session: &SignerConsentSession,
) -> Result<()> {
    history.validate()?;
    peer.check_current().map_err(|_| BridgeError::Permission)?;
    if !peer.scope.authorization_export {
        return Err(BridgeError::Permission);
    }
    let lease = journal.acquire_original_authorization(&history.authorization_id, session)?;
    let original = OriginalAuthorizationView::from_original(lease.evidence());
    history.matches(&original)?;
    if authorized_recipient(journal, &lease, &peer, redelivery.as_ref())?.is_none() {
        return Err(BridgeError::Permission);
    }
    let result = journal.bridge_result(&lease)?;
    lease.check_current()?;
    peer.check_current().map_err(|_| BridgeError::Permission)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| BridgeError::Ipc)?;
    stream
        .write_all(result.outbox_payload.as_bytes())
        .and_then(|_| stream.write_all(b"\n"))
        .and_then(|_| stream.flush())
        .map_err(|_| BridgeError::Ipc)
}
impl OriginalHistoryClient {
    /// Retrieves the original exact already-retained authorization bytes. Loss
    /// of this response never causes new key use. This is not account provenance
    /// for an engine; that separately requires an authenticated held history lease.
    pub fn retrieve_original_authorization(
        &self,
        history: &HistoryRequest,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.retrieve_with_redelivery(history, None)
    }
    pub fn retrieve_redelivered_authorization(
        &self,
        history: &HistoryRequest,
        redelivery: &crate::consent_journal::ResultRedeliveryReference,
    ) -> Result<Zeroizing<Vec<u8>>> {
        redelivery.validate()?;
        self.retrieve_with_redelivery(history, Some(redelivery))
    }
    fn retrieve_with_redelivery(
        &self,
        history: &HistoryRequest,
        redelivery: Option<&crate::consent_journal::ResultRedeliveryReference>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        history.validate()?;
        if !self.scope.authorization_export || Instant::now() >= self.grant.expires {
            return Err(BridgeError::Permission);
        }
        let mut stream = UnixStream::connect(&self.socket).map_err(|_| BridgeError::Ipc)?;
        crate::ipc::enable_credentials(stream.as_raw_fd()).map_err(|_| BridgeError::Ipc)?;
        let actual = self.provider.verify_server(&stream)?;
        self.peer
            .same_live_process(&actual)
            .map_err(|_| BridgeError::Permission)?;
        write_frame(
            &mut stream,
            &serde_json::json!({"command":"request","schema_version":1,"grant_id":self.grant.grant_id,"token_hex":self.grant.token_hex.as_str(),"request": if let Some(redelivery) = redelivery { serde_json::json!({"operation":"retrieve_redelivered_authorization","history":history,"redelivery":redelivery}) } else { serde_json::json!({"operation":"retrieve_authorization","history":history}) }}),
        )?;
        let result =
            crate::ipc::read_frame_with_deadline(&stream, &self.peer, Duration::from_secs(2))
                .map_err(|_| BridgeError::Ipc)?;
        if result.is_empty() || result.len() > super::protocol::MAX_OUTBOX_BYTES {
            return Err(BridgeError::Limit);
        }
        #[derive(Deserialize)]
        struct ResultScope {
            schema_version: u16,
            candidate_id: String,
            manifest_digest: String,
            account_id: String,
        }
        let scope: ResultScope =
            serde_json::from_slice(&result).map_err(|_| BridgeError::Binding)?;
        if scope.schema_version != 1
            || scope.candidate_id.is_empty()
            || scope.manifest_digest != self.scope.manifest_digest
            || scope.account_id != self.scope.account_id
        {
            return Err(BridgeError::Binding);
        }
        Ok(result)
    }
}

pub(crate) fn exact_local_recipient(
    transport: &crate::consent_journal::TransportIdentityBinding,
    peer: &AuthenticatedPeer,
) -> bool {
    let crate::consent_journal::TransportIdentityBinding::LocalProcess {
        transport_identity_id,
        channel_key_digest,
        channel_binding_digest,
        uid,
        pid,
        process_instance,
        signer_generation,
        account_id,
        agreement_id,
        participant_id,
        manifest_digest,
    } = transport
    else {
        return false;
    };
    transport_identity_id == &peer.grant_id
        && channel_key_digest == &peer.key_digest
        && channel_binding_digest == &peer.channel_digest
        && *uid == peer.peer.uid()
        && *pid == peer.peer.pid()
        && process_instance == peer.peer.instance()
        && *signer_generation == peer.generation
        && account_id == &peer.scope.account_id
        && agreement_id == &peer.scope.agreement_id
        && participant_id == &peer.scope.participant_id
        && manifest_digest == &peer.scope.manifest_digest
}

fn authorized_recipient(
    journal: &SignerConsentJournal,
    lease: &crate::consent_journal::OriginalAuthorizationLease<'_>,
    peer: &AuthenticatedPeer,
    redelivery: Option<&crate::consent_journal::ResultRedeliveryReference>,
) -> Result<Option<crate::consent_journal::TransportIdentityBinding>> {
    if let Some(reference) = redelivery {
        reference.validate()?;
        if !peer.scope.history_read || !peer.scope.authorization_export {
            return Err(BridgeError::Permission);
        }
        let record = journal
            .result_redelivery(lease, &reference.operation_id)?
            .ok_or(BridgeError::Missing)?;
        if record.reference() != reference.reference
            || !exact_local_recipient(&record.terms().recipient, peer)
        {
            return Err(BridgeError::Permission);
        }
        Ok(Some(record.terms().recipient.clone()))
    } else {
        let recipient = lease.evidence().enrollment().transport();
        Ok(exact_local_recipient(recipient, peer).then(|| recipient.clone()))
    }
}

pub(crate) fn send_redelivery_reference(
    stream: &mut UnixStream,
    reference: &crate::consent_journal::ResultRedeliveryReference,
) -> crate::Result<()> {
    write_frame(stream, reference).map_err(|_| crate::Error::Unavailable)
}
impl OriginalHistoryClient {
    /// Requests a separate actual native review. No caller decision or receipt
    /// can approve this operation; the returned reference is evidence only.
    pub fn request_result_redelivery(
        &self,
        request: &crate::consent_journal::ResultRedeliveryRequest,
    ) -> Result<crate::consent_journal::ResultRedeliveryReference> {
        request.validate()?;
        if !self.scope.authorization_export
            || !self.scope.history_read
            || Instant::now() >= self.grant.expires
        {
            return Err(BridgeError::Permission);
        }
        let mut stream = UnixStream::connect(&self.socket).map_err(|_| BridgeError::Ipc)?;
        crate::ipc::enable_credentials(stream.as_raw_fd()).map_err(|_| BridgeError::Ipc)?;
        let actual = self.provider.verify_server(&stream)?;
        self.peer
            .same_live_process(&actual)
            .map_err(|_| BridgeError::Permission)?;
        write_frame(
            &mut stream,
            &serde_json::json!({"command":"request","schema_version":1,"grant_id":self.grant.grant_id,"token_hex":self.grant.token_hex.as_str(),"request":{"operation":"request_result_redelivery","request":request}}),
        )?;
        let frame =
            crate::ipc::read_frame_with_deadline(&stream, &self.peer, Duration::from_secs(120))
                .map_err(|_| BridgeError::Ipc)?;
        let reference: crate::consent_journal::ResultRedeliveryReference =
            serde_json::from_slice(&frame).map_err(|_| BridgeError::Binding)?;
        reference.validate()?;
        if reference.operation_id != request.operation_id {
            return Err(BridgeError::Binding);
        }
        Ok(reference)
    }
}

impl OriginalHistoryClient {
    pub(super) fn open_preconstruction_request(
        &self,
        request: serde_json::Value,
    ) -> Result<UnixStream> {
        if !self.scope.preconstruction_export || Instant::now() >= self.grant.expires {
            return Err(BridgeError::Permission);
        }
        self.open_scoped_request(request)
    }
    /// Dedicated restriction-only sender. Generic request I/O keeps its existing
    /// semantics. The absolute caller/grant deadline is checked around connect,
    /// provider/kernel-peer authentication and every bounded partial write.
    /// Local connect and OS checks are synchronous, not hard realtime; a late
    /// return is denied and an already transmitted request cannot be recalled.
    pub(super) fn open_quarantined_v5_request_until(
        &self,
        request: serde_json::Value,
        original_deadline: Instant,
    ) -> Result<(UnixStream, Instant)> {
        use super::host_recovery_ipc::v5::transfer_io::{
            require_before_deadline, write_frame_until,
        };
        let deadline = original_deadline.min(self.grant.expires);
        require_before_deadline(deadline)?;
        require_quarantined_v5_request(self.mode, &self.scope, &request)?;
        self.peer
            .check_alive()
            .map_err(|_| BridgeError::Permission)?;
        require_before_deadline(deadline)?;
        let mut stream = UnixStream::connect(&self.socket).map_err(|_| BridgeError::Ipc)?;
        require_before_deadline(deadline)?;
        crate::ipc::enable_credentials(stream.as_raw_fd()).map_err(|_| BridgeError::Ipc)?;
        require_before_deadline(deadline)?;
        let actual = self.provider.verify_server(&stream)?;
        require_before_deadline(deadline)?;
        self.peer
            .same_live_process(&actual)
            .map_err(|_| BridgeError::Permission)?;
        require_before_deadline(deadline)?;
        // Borrow the credential directly; bounded serialization owns zeroizing
        // scratch bytes, avoiding an additional token-bearing JSON Value.
        #[derive(Serialize)]
        struct AuthenticatedRequest<'a> {
            command: &'static str,
            schema_version: u16,
            grant_id: &'a str,
            token_hex: &'a str,
            request: &'a serde_json::Value,
        }
        write_frame_until(
            &mut stream,
            &AuthenticatedRequest {
                command: "request",
                schema_version: 1,
                grant_id: &self.grant.grant_id,
                token_hex: self.grant.token_hex.as_str(),
                request: &request,
            },
            deadline,
        )?;
        self.peer
            .check_alive()
            .map_err(|_| BridgeError::Permission)?;
        require_before_deadline(deadline)?;
        Ok((stream, deadline))
    }
    pub(super) fn open_born_request_checked_until(
        &self,
        request: serde_json::Value,
        original_deadline: Instant,
        check_current: &impl Fn() -> Result<()>,
    ) -> Result<(UnixStream, Instant)> {
        use super::born_ipc_io::{require_current, write_checked};
        let deadline = original_deadline.min(self.grant.expires);
        require_born_request_scope(self.mode, &self.scope, &request)?;
        let current = || {
            check_current()?;
            self.peer.check_alive().map_err(|_| BridgeError::Permission)
        };
        require_current(deadline, &current)?;
        let mut stream =
            wholepact_signer_origin::connect_local_checked_until(&self.socket, deadline, || {
                current().map_err(|_| wholepact_signer_origin::Error::Permission)
            })
            .map_err(|_| BridgeError::Ipc)?;
        require_current(deadline, &current)?;
        crate::ipc::enable_credentials(stream.as_raw_fd()).map_err(|_| BridgeError::Ipc)?;
        require_current(deadline, &current)?;
        let actual = self.provider.verify_server(&stream)?;
        require_current(deadline, &current)?;
        self.peer
            .same_live_process(&actual)
            .map_err(|_| BridgeError::Permission)?;
        require_current(deadline, &current)?;
        #[derive(Serialize)]
        struct Request<'a> {
            command: &'static str,
            schema_version: u16,
            grant_id: &'a str,
            token_hex: &'a str,
            request: &'a serde_json::Value,
        }
        write_checked(
            &mut stream,
            &Request {
                command: "request",
                schema_version: 1,
                grant_id: &self.grant.grant_id,
                token_hex: self.grant.token_hex.as_str(),
                request: &request,
            },
            deadline,
            &current,
        )?;
        require_current(deadline, &current)?;
        Ok((stream, deadline))
    }
    pub(super) fn open_authenticated_request(
        &self,
        request: serde_json::Value,
    ) -> Result<UnixStream> {
        if !self.scope.history_read
            || !self.scope.authorization_export
            || Instant::now() >= self.grant.expires
        {
            return Err(BridgeError::Permission);
        }
        self.open_scoped_request(request)
    }
    pub(super) fn check_automatic_scope(
        &self,
        d: &super::automation_ipc::AutomaticDescriptor,
    ) -> Result<()> {
        if d.request.application_id != self.grant.grant_id
            || d.grant.application_id != self.grant.grant_id
            || d.request.account_id != self.scope.account_id
            || d.participant_id != self.scope.participant_id
            || d.request.agreement_id != self.scope.agreement_id
            || d.request.manifest_digest != self.scope.manifest_digest
        {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
    pub(super) fn open_automatic_request(&self, request: serde_json::Value) -> Result<UnixStream> {
        if Instant::now() >= self.grant.expires {
            return Err(BridgeError::Permission);
        }
        self.open_scoped_request(request)
    }
    pub(super) fn open_inspection_request(&self, request: serde_json::Value) -> Result<UnixStream> {
        if self.mode != PairingMode::Ordinary
            || !self.scope.history_read
            || Instant::now() >= self.grant.expires
        {
            return Err(BridgeError::Permission);
        }
        self.open_scoped_request(request)
    }
    fn open_scoped_request(&self, request: serde_json::Value) -> Result<UnixStream> {
        let mut stream = UnixStream::connect(&self.socket).map_err(|_| BridgeError::Ipc)?;
        crate::ipc::enable_credentials(stream.as_raw_fd()).map_err(|_| BridgeError::Ipc)?;
        let actual = self.provider.verify_server(&stream)?;
        self.peer
            .same_live_process(&actual)
            .map_err(|_| BridgeError::Permission)?;
        write_frame(
            &mut stream,
            &serde_json::json!({"command":"request","schema_version":1,"grant_id":self.grant.grant_id,"token_hex":self.grant.token_hex.as_str(),"request":request}),
        )?;
        Ok(stream)
    }
    pub(super) fn peer(&self) -> &PeerProcess {
        &self.peer
    }
}

/// Recover only the already committed exact redelivery for the same live peer.
/// Lost-response retry cannot replace its recipient, originals or operation.
pub(crate) fn existing_redelivery_reference(
    journal: &SignerConsentJournal,
    session: &SignerConsentSession,
    peer: &AuthenticatedPeer,
    request: &crate::consent_journal::ResultRedeliveryRequest,
) -> Result<Option<crate::consent_journal::ResultRedeliveryReference>> {
    request.validate()?;
    peer.check_current().map_err(|_| BridgeError::Permission)?;
    if !peer.scope.history_read || !peer.scope.authorization_export {
        return Err(BridgeError::Permission);
    }
    let lease = journal.acquire_original_authorization(&request.authorization_id, session)?;
    request.matches(lease.evidence())?;
    let Some(record) = journal.result_redelivery(&lease, &request.operation_id)? else {
        return Ok(None);
    };
    if record.terms().request != *request || !exact_local_recipient(&record.terms().recipient, peer)
    {
        return Err(BridgeError::Permission);
    }
    lease.check_current()?;
    peer.check_current().map_err(|_| BridgeError::Permission)?;
    Ok(Some(record.reference_request()))
}

impl OriginalHistoryClient {
    /// Identity observed from the actual installed signer and paired account.
    pub fn proved_disclosure_recipient(
        &self,
    ) -> Result<super::proved_disclosure_ipc::ProvedDisclosureRecipient> {
        if Instant::now() >= self.grant.expires {
            return Err(BridgeError::Permission);
        }
        self.peer
            .check_alive()
            .map_err(|_| BridgeError::Permission)?;
        Ok(super::proved_disclosure_ipc::ProvedDisclosureRecipient {
            account_id: self.scope.account_id.clone(),
            provider_enrollment_reference: self.provider.native_enrollment_reference().into(),
            process_instance: self.peer.instance().into(),
        })
    }
    pub(super) fn open_disclosure_request(&self, request: serde_json::Value) -> Result<UnixStream> {
        if Instant::now() >= self.grant.expires {
            return Err(BridgeError::Permission);
        }
        self.open_scoped_request(request)
    }
    /// Request-only intake. Caller must first hold every owner's exact disclosure
    /// lease; this response never represents inspection, approval or signing.
    pub fn request_review(
        &self,
        request_id: &str,
        accepted_manifest_digest: &str,
        bytes: &[u8],
    ) -> Result<()> {
        crate::review::validate_label(request_id).map_err(|_| BridgeError::Binding)?;
        if accepted_manifest_digest != self.scope.manifest_digest
            || bytes.is_empty()
            || bytes.len() > 1_048_576
        {
            return Err(BridgeError::Binding);
        }
        let stream = self.open_disclosure_request(serde_json::json!({"operation":"request_review", "request_id":request_id, "accepted_manifest_digest":accepted_manifest_digest, "pczt_hex":hex::encode(bytes)}))?;
        let frame =
            crate::ipc::read_frame_with_deadline(&stream, &self.peer, Duration::from_secs(2))
                .map_err(|_| BridgeError::Ipc)?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Reply {
            accepted: bool,
            reason_code: String,
        }
        let reply: Reply = serde_json::from_slice(&frame).map_err(|_| BridgeError::Ipc)?;
        if reply.accepted && reply.reason_code == "REQUEST_ONLY" {
            Ok(())
        } else {
            Err(BridgeError::Permission)
        }
    }
}

impl OriginalHistoryClient {
    pub(super) fn check_host_recovery_scope(
        &self,
        request: &super::host_recovery_ipc::HostRecoveryContinuityRequest,
    ) -> Result<()> {
        self.check_host_recovery_account_scope(&request.account_id)
    }
    pub(super) fn check_host_recovery_account_scope(&self, account_id: &str) -> Result<()> {
        if account_id != self.scope.account_id
            || !self.scope.history_read
            || !self.scope.authorization_export
            || Instant::now() >= self.grant.expires
        {
            return Err(BridgeError::Permission);
        }
        self.peer.check_alive().map_err(|_| BridgeError::Permission)
    }
    pub(super) fn host_recovery_provider_reference(&self) -> &str {
        self.provider.native_enrollment_reference()
    }
}

impl OriginalHistoryClient {
    /// V5 is bound to the exact authenticated inventory as well as account.
    pub(super) fn check_host_recovery_v5_scope(
        &self,
        account_id: &str,
        inventory_digest: &str,
    ) -> Result<()> {
        self.check_host_recovery_account_scope(account_id)?;
        if inventory_digest != self.scope.manifest_digest {
            return Err(BridgeError::Permission);
        }
        Ok(())
    }
}

/// Pure actual restricted-send validation seam; no connection or credential
/// exists here, and passing it creates no native/provider/client capability.
fn require_quarantined_v5_request(
    mode: PairingMode,
    scope: &PairScope,
    request: &serde_json::Value,
) -> Result<()> {
    if mode != PairingMode::QuarantinedInformational {
        return Err(BridgeError::Permission);
    }
    mode.validate_scope(scope)?;
    use super::host_recovery_ipc::v5::V5TransferDialect;
    // A private two-operation parser avoids importing signer-native feature
    // variants into the client-only build. Omitted dialect and every unknown
    // operation/field are refused; these are unchanged existing wire records.
    #[derive(Deserialize)]
    #[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
    enum QuarantinedV5Request {
        RequestHostRecoveryContinuityV5 {
            request: Box<super::host_recovery_ipc::v5::HostRecoveryContinuityRequestV5>,
            transfer_dialect: V5TransferDialect,
        },
        RequestHostRecoveryPublicationV5 {
            request: Box<super::host_publication_ipc::v5::HostRecoveryPublicationRequestV5>,
            transfer_dialect: V5TransferDialect,
        },
    }
    let parsed: QuarantinedV5Request =
        serde_json::from_value(request.clone()).map_err(|_| BridgeError::Binding)?;
    let continuity = match &parsed {
        QuarantinedV5Request::RequestHostRecoveryContinuityV5 {
            request,
            transfer_dialect: V5TransferDialect::BoundedV1,
        } => {
            request.validate()?;
            request.as_ref()
        }
        QuarantinedV5Request::RequestHostRecoveryPublicationV5 {
            request,
            transfer_dialect: V5TransferDialect::BoundedV1,
        } => {
            request.validate()?;
            &request.continuity
        }
        _ => return Err(BridgeError::Permission),
    };
    if continuity.account_id != scope.account_id
        || continuity.inventory_digest != scope.manifest_digest
    {
        return Err(BridgeError::Binding);
    }
    super::host_recovery_ipc::v5::require_quarantined_informational_endpoint()
}

#[cfg(test)]
#[path = "ipc/quarantined_pairing_tests.rs"]
mod quarantined_pairing_tests;

#[cfg(test)]
mod quarantined_v5_until_tests {
    use super::*;
    // These tests invoke the real preconnection validation seam with inert DTOs.
    // They create no provider, client, native/source owner, credential or socket.
    fn request_and_scope() -> (serde_json::Value, PairScope) {
        let account = "synthetic-quarantined-account";
        let network = "synthetic-network";
        let continuity = serde_json::json!({
            "schema_version": 5,
            "inventory_digest": "11".repeat(32),
            "generation_id": "22".repeat(32),
            "account_id": account,
            "network_profile_id": network,
            "expected_writer_epoch": 7,
            "expected_witness": {
                "endpoint": "127.0.0.1:28443",
                "server_name": "synthetic.invalid",
                "witness_id": "synthetic-witness",
                "account_id": account,
                "network_profile_id": network,
                "policy_digest": "33".repeat(32),
                "pinned_server_certificate_digest": "44".repeat(32),
            },
        });
        let scope = PairScope {
            account_id: account.into(),
            agreement_id: "host-recovery".into(),
            participant_id: "host-recovery".into(),
            manifest_digest: "11".repeat(32),
            history_read: true,
            authorization_export: true,
            preconstruction_export: false,
        };
        (continuity, scope)
    }
    fn frames(continuity: &serde_json::Value) -> [serde_json::Value; 2] {
        [
            serde_json::json!({
                "operation": "request_host_recovery_continuity_v5",
                "transfer_dialect": "v5_bounded_transfer_v1",
                "request": continuity,
            }),
            serde_json::json!({
                "operation": "request_host_recovery_publication_v5",
                "transfer_dialect": "v5_bounded_transfer_v1",
                "request": {
                    "schema_version": 5,
                    "continuity": continuity,
                    "target_profile": "/synthetic-unopened/successor",
                    "generation_manifest_digest": "55".repeat(32),
                    "continuity_evidence_digest": "66".repeat(32),
                },
            }),
        ]
    }
    #[test]
    fn restricted_until_sender_dispatch_requires_exact_mode_scope_and_dto() {
        let (continuity, scope) = request_and_scope();
        for frame in frames(&continuity) {
            assert!(
                require_quarantined_v5_request(
                    PairingMode::QuarantinedInformational,
                    &scope,
                    &frame
                )
                .is_ok()
            );
            assert!(require_quarantined_v5_request(PairingMode::Ordinary, &scope, &frame).is_err());
            for field in 0..5 {
                let mut wrong = scope.clone();
                match field {
                    0 => wrong.account_id = "another-account".into(),
                    1 => wrong.manifest_digest = "77".repeat(32),
                    2 => wrong.history_read = false,
                    3 => wrong.authorization_export = false,
                    _ => wrong.preconstruction_export = true,
                }
                assert!(
                    require_quarantined_v5_request(
                        PairingMode::QuarantinedInformational,
                        &wrong,
                        &frame
                    )
                    .is_err()
                );
            }
            for dialect in [
                serde_json::Value::Null,
                serde_json::json!("single_frame"),
                serde_json::json!("unknown"),
            ] {
                let mut wrong = frame.clone();
                wrong["transfer_dialect"] = dialect;
                assert!(
                    require_quarantined_v5_request(
                        PairingMode::QuarantinedInformational,
                        &scope,
                        &wrong
                    )
                    .is_err()
                );
            }
            let mut missing = frame.clone();
            missing.as_object_mut().unwrap().remove("transfer_dialect");
            assert!(
                require_quarantined_v5_request(
                    PairingMode::QuarantinedInformational,
                    &scope,
                    &missing
                )
                .is_err()
            );
            let mut unknown = frame.clone();
            unknown["caller_approval"] = serde_json::json!(true);
            assert!(
                require_quarantined_v5_request(
                    PairingMode::QuarantinedInformational,
                    &scope,
                    &unknown
                )
                .is_err()
            );
        }
        for field in ["schema_version", "expected_writer_epoch"] {
            let mut wrong = continuity.clone();
            wrong[field] = serde_json::json!(0);
            for frame in frames(&wrong) {
                assert!(
                    require_quarantined_v5_request(
                        PairingMode::QuarantinedInformational,
                        &scope,
                        &frame
                    )
                    .is_err()
                );
            }
        }
    }
    #[test]
    fn restricted_until_sender_dispatch_rejects_generic_and_cross_purpose_requests() {
        let (continuity, scope) = request_and_scope();
        let [mut disclosure, mut publication] = frames(&continuity);
        disclosure["operation"] = serde_json::json!("request_host_recovery_publication_v5");
        publication["operation"] = serde_json::json!("request_host_recovery_continuity_v5");
        for frame in [
            disclosure,
            publication,
            serde_json::json!({"operation": "status"}),
            serde_json::json!({"operation": "list_accounts"}),
            serde_json::json!({"operation": "request_host_recovery_continuity_v4", "request": continuity}),
            serde_json::json!({"operation": "request_signature", "approved": true}),
        ] {
            assert!(
                require_quarantined_v5_request(
                    PairingMode::QuarantinedInformational,
                    &scope,
                    &frame
                )
                .is_err()
            );
        }
    }
}

fn require_born_request_scope(
    mode: PairingMode,
    scope: &PairScope,
    request: &serde_json::Value,
) -> Result<()> {
    if mode != PairingMode::Ordinary
        || !scope.history_read
        || scope.authorization_export
        || scope.preconstruction_export
        || !matches!(
            request.get("operation").and_then(|v| v.as_str()),
            Some("request_born_original_history_v1" | "request_born_dispatch_v1")
        )
    {
        return Err(BridgeError::Permission);
    }
    Ok(())
}

#[cfg(all(test, feature = "offline-review-foundation"))]
mod born_opener_tests {
    use super::*;
    #[test]
    fn born_opener_accepts_only_ordinary_exact_narrow_request_scope() {
        let scope = PairScope {
            account_id: "synthetic-account".into(),
            agreement_id: "synthetic-agreement".into(),
            participant_id: "synthetic-participant".into(),
            manifest_digest: "42".repeat(32),
            history_read: true,
            authorization_export: false,
            preconstruction_export: false,
        };
        for operation in [
            "request_born_original_history_v1",
            "request_born_dispatch_v1",
        ] {
            let request = serde_json::json!({"operation":operation});
            assert!(require_born_request_scope(PairingMode::Ordinary, &scope, &request).is_ok());
            assert!(
                require_born_request_scope(PairingMode::QuarantinedInformational, &scope, &request)
                    .is_err()
            );
            for change in 0..3 {
                let mut other = scope.clone();
                match change {
                    0 => other.history_read = false,
                    1 => other.authorization_export = true,
                    _ => other.preconstruction_export = true,
                };
                assert!(
                    require_born_request_scope(PairingMode::Ordinary, &other, &request).is_err()
                );
            }
        }
        for operation in [
            "request_dispatch",
            "request_original_history",
            "request_preconstruction",
        ] {
            assert!(
                require_born_request_scope(
                    PairingMode::Ordinary,
                    &scope,
                    &serde_json::json!({"operation":operation})
                )
                .is_err()
            );
        }
    }
}

mod born_pairing;
pub use born_pairing::PendingBornHistoryPairV1;
