//! Request-only channel of the SAME original coordinated Signer. This registry
//! is deliberately disjoint from native-window grants and AuthenticatedPeer.
//! Actual socket credentials, fresh token possession and a genuine C Pair
//! Final are required; source lifetime never substitutes for an action grant.
use super::*;
use crate::authority_bridge::durable_review_ipc_v3::coordinated_v1::{
    CoordinatedAppRequestV1, CoordinatedClosedCommandV1, CoordinatedPrepareClosedRecipientRequestV1,
};
#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum CoordinatedEnvelopeV1 {
    RequestPairing {
        schema_version: u32,
        application_label: String,
        scope: PairScope,
    },
    CoordinatedV3Request {
        schema_version: u32,
        grant_id: String,
        token_hex: String,
        request: CoordinatedAppRequestV1,
    },
}
impl Drop for CoordinatedEnvelopeV1 {
    fn drop(&mut self) {
        if let Self::CoordinatedV3Request { token_hex, .. } = self {
            token_hex.zeroize();
        }
    }
}
use wholepact_financial_coordinator_origin::{
    SignerV3PairEndpointV1, SignerV3PairFinalV1, SignerV3PairLifetimeV1, SignerV3SourceLifetimeV1,
};

pub(crate) enum CoordinatedRequestV1 {
    FinancialResult(crate::authority_bridge::financial_continuation_v1::FinancialResultRequestV1),
    Closed(CoordinatedClosedCommandV1),
    Redisclosure(Box<crate::authority_bridge::durable_construction_v1::DurableConstructionRedisclosureRequestV1>),
    Prepare(Box<CoordinatedPrepareClosedRecipientRequestV1>),
}
pub(crate) enum CoordinatedLocalEventV1 {
    Pairing(PendingPairing),
    StatusProof(CoordinatedPairPeerV1),
    Request {
        peer: CoordinatedPairPeerV1,
        stream: UnixStream,
        request: CoordinatedRequestV1,
        original_request_deadline: Instant,
    },
}
struct Bounds {
    host: PeerProcess,
    source_identity: String,
    lifetime: Arc<SignerV3SourceLifetimeV1>,
    deadline: Instant,
    stopped: Arc<AtomicBool>,
}
impl Bounds {
    fn check(&self) -> Result<()> {
        self.lifetime.check_current().map_err(|_| Error::Locked)?;
        self.host.check_alive()?;
        if self.stopped.load(Ordering::Acquire) || Instant::now() >= self.deadline {
            return Err(Error::Locked);
        }
        Ok(())
    }
}
/// Clone shares only the exact channel's revocation and source restrictions.
/// It cannot approve a Read, export, receive or financial action.
#[derive(Clone)]
pub(crate) struct CoordinatedPairPeerV1 {
    bounds: Arc<Bounds>,
    observed: PeerProcess,
    pairing: Arc<SignerV3PairLifetimeV1>,
    scope: PairScope,
    grant_id: String,
    key_digest: String,
    channel_digest: String,
    generation: u64,
    common_image_measurement: String,
    pair_presentation_digest: String,
    coordinated_provider_reference: String,
    signer_process_instance: String,
    expires: Instant,
    current: Arc<AtomicBool>,
}
impl CoordinatedPairPeerV1 {
    pub(crate) fn check_current(&self) -> Result<()> {
        self.bounds.check()?;
        self.pairing.check_current().map_err(|_| Error::Locked)?;
        self.observed.check_alive()?;
        if !self.current.load(Ordering::Acquire) || Instant::now() >= self.expires {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    pub(crate) fn scope(&self) -> &PairScope {
        &self.scope
    }
    pub(crate) fn actual_peer(&self) -> &PeerProcess {
        &self.observed
    }
    pub(crate) fn original_host_process_instance(&self) -> &str {
        self.bounds.host.instance()
    }
    pub(crate) fn source_identity(&self) -> &str {
        &self.bounds.source_identity
    }
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
    pub(crate) fn grant_id(&self) -> &str {
        &self.grant_id
    }
    pub(crate) fn key_digest(&self) -> &str {
        &self.key_digest
    }
    pub(crate) fn channel_digest(&self) -> &str {
        &self.channel_digest
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.expires
    }
    pub(crate) fn common_image_measurement(&self) -> &str {
        &self.common_image_measurement
    }
    pub(crate) fn pair_presentation_digest(&self) -> &str {
        &self.pair_presentation_digest
    }
    pub(crate) fn coordinated_provider_reference(&self) -> &str {
        &self.coordinated_provider_reference
    }
    pub(crate) fn signer_process_instance(&self) -> &str {
        &self.signer_process_instance
    }
    pub(crate) fn require_same_grant(&self, other: &Self) -> Result<()> {
        self.check_current()?;
        other.check_current()?;
        if !Arc::ptr_eq(&self.current, &other.current) || !Arc::ptr_eq(&self.bounds, &other.bounds)
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
}
struct Grant {
    peer: CoordinatedPairPeerV1,
    token_digest: [u8; 32],
    possession_proved: bool,
}
impl Drop for Grant {
    fn drop(&mut self) {
        self.peer.current.store(false, Ordering::Release);
    }
}

pub(crate) struct CoordinatedLocalIpcV1 {
    // Join service before releasing the directory or source lifetime.
    worker: Option<JoinHandle<()>>,
    bounds: Arc<Bounds>,
    grants: Arc<Mutex<BTreeMap<String, Grant>>>,
    events: Receiver<CoordinatedLocalEventV1>,
    path: PathBuf,
    _directory: PrivateDirectory,
}
impl CoordinatedLocalIpcV1 {
    pub(crate) fn bind(
        directory: PrivateDirectory,
        host: PeerProcess,
        source_identity: String,
        lifetime: Arc<SignerV3SourceLifetimeV1>,
        deadline: Instant,
    ) -> Result<Self> {
        valid_hash(&source_identity)?;
        let bounds = Arc::new(Bounds {
            host,
            source_identity,
            lifetime,
            deadline,
            stopped: Arc::new(AtomicBool::new(false)),
        });
        bounds.check()?;
        let path = directory.root().join(format!(
            "coordinated-v3-{}.sock",
            hex::encode(crate::vault::random::<12>()?)
        ));
        let listener = UnixListener::bind(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        enable_credentials(listener.as_raw_fd())?;
        let grants = Arc::new(Mutex::new(BTreeMap::new()));
        let (sender, events) = mpsc::sync_channel(MAX_EVENTS);
        let worker_bounds = Arc::clone(&bounds);
        let worker_grants = Arc::clone(&grants);
        let worker = std::thread::Builder::new()
            .name("original-v3-pair".into())
            .spawn(move || {
                serve(listener, &worker_bounds, &worker_grants, &sender);
                worker_bounds.stopped.store(true, Ordering::Release);
                if let Ok(mut held) = worker_grants.lock() {
                    held.clear();
                }
            })?;
        Ok(Self {
            worker: Some(worker),
            bounds,
            grants,
            events,
            path,
            _directory: directory,
        })
    }
    /// Only this nominal C Pair Final can authorize a fresh request token.
    /// Neither source lifetime nor a caller boolean can enter this issuer.
    pub(crate) fn approve_pairing(
        &self,
        mut pending: PendingPairing,
        final_action: SignerV3PairFinalV1,
    ) -> Result<()> {
        self.bounds.check()?;
        pending.check_current()?;
        self.bounds.host.same_live_process(&pending.peer)?;
        allowed_scope(&pending.scope)?;
        final_action.check_current()?;
        let facts = final_action.facts();
        let endpoint = SignerV3PairEndpointV1 {
            entry_presentation_digest: facts.entry_presentation_digest.clone(),
            source_identity_digest: self.bounds.source_identity.clone(),
            endpoint_path: self.path.to_str().ok_or(Error::InvalidData)?.to_owned(),
            endpoint_digest: facts.endpoint_digest.clone(),
            signer_process_instance: facts.signer_process_instance.clone(),
            coordinated_provider_reference: facts.coordinated_provider_reference.clone(),
            source_expires_at_ms: facts.source_expires_at_ms,
        };
        endpoint.validate()?;
        let exact_scope: PairScope = wholepact_core::strict_json::parse_typed_json_with_byte_limit(
            facts.scope_json.as_bytes(),
            16 * 1024,
        )
        .map_err(|_| Error::InvalidData)?;
        if facts.source_identity_digest != self.bounds.source_identity
            || facts.generation != self.generation()
            || facts.pairing_review_digest != pending.review_digest(self.generation())?
            || facts.original_host_uid != self.bounds.host.uid()
            || facts.original_host_pid != self.bounds.host.pid()
            || facts.original_host_process_instance != self.bounds.host.instance()
            || exact_scope != pending.scope
        {
            return Err(Error::Authentication);
        }
        let expires = self
            .bounds
            .deadline
            .min(final_action.original_source_deadline())
            .min(final_action.original_channel_deadline());
        let remaining = expires.saturating_duration_since(Instant::now()).as_secs();
        if remaining == 0 {
            return Err(Error::Locked);
        }
        let (id, secret) = fresh_pairing_secret()?;
        let token_digest: [u8; 32] = Sha256::digest(secret.as_slice()).into();
        let channel_digest = pending.review_digest(self.generation())?;
        // As in the maintained issuer, hold the registry's bounded admission
        // lock across the small token response. Status cannot race promotion.
        let mut held = self.grants.lock().map_err(|_| Error::Locked)?;
        if !held.is_empty() {
            return Err(Error::Authentication);
        }
        final_action.check_current()?;
        self.bounds.check()?;
        pending.check_current()?;
        let token = Zeroizing::new(hex::encode(secret.as_slice()));
        #[derive(serde::Serialize)]
        struct Response<'a> {
            schema_version: u32,
            accepted: bool,
            reason_code: &'static str,
            grant_id: &'a str,
            token_hex: &'a str,
            expires_in_seconds: u64,
            profile: &'static str,
            channel_digest: &'a str,
            observed_host_process_instance: &'a str,
            original_host_process_instance: &'a str,
            source_identity_digest: &'a str,
            pair_presentation_digest: &'a str,
            generation: u64,
        }
        let response = Response {
            schema_version: 1,
            accepted: true,
            reason_code: "LOCAL_PROCESS_REQUEST_SCOPE",
            grant_id: &id,
            token_hex: &token,
            expires_in_seconds: remaining,
            profile: "coordinated_original_fork_v1",
            channel_digest: &channel_digest,
            observed_host_process_instance: pending.peer.instance(),
            original_host_process_instance: self.bounds.host.instance(),
            source_identity_digest: &self.bounds.source_identity,
            pair_presentation_digest: &final_action.presentation().presentation_digest,
            generation: self.generation(),
        };
        let direct = pending.peer.clone();
        let created = pending.created;
        crate::authority_bridge::durable_review_ipc_v1::bounded_write(
            &mut pending.stream,
            &response,
            expires.min(final_action.original_pair_deadline()),
            || {
                final_action
                    .check_current()
                    .map_err(|_| crate::authority_bridge::BridgeError::Permission)?;
                self.bounds
                    .check()
                    .map_err(|_| crate::authority_bridge::BridgeError::Permission)?;
                direct
                    .check_alive()
                    .map_err(|_| crate::authority_bridge::BridgeError::Permission)?;
                if created.elapsed() >= Duration::from_secs(120) {
                    return Err(crate::authority_bridge::BridgeError::Permission);
                }
                Ok(())
            },
        )
        .map_err(|_| Error::Authentication)?;
        final_action.check_current()?;
        self.bounds.check()?;
        pending.check_current()?;
        let common_image_measurement = final_action
            .presentation()
            .actor
            .common_image_measurement
            .clone();
        let pair_presentation_digest = final_action.presentation().presentation_digest.clone();
        let coordinated_provider_reference =
            final_action.facts().coordinated_provider_reference.clone();
        let signer_process_instance = final_action.facts().signer_process_instance.clone();
        let pairing = Arc::new(final_action.into_pair_lifetime()?);
        let peer = CoordinatedPairPeerV1 {
            bounds: Arc::clone(&self.bounds),
            observed: pending.peer,
            pairing,
            scope: pending.scope,
            grant_id: id.clone(),
            key_digest: hex::encode(token_digest),
            channel_digest,
            generation: self.generation(),
            common_image_measurement,
            pair_presentation_digest,
            coordinated_provider_reference,
            signer_process_instance,
            expires,
            current: Arc::new(AtomicBool::new(true)),
        };
        peer.check_current()?;
        held.insert(
            id,
            Grant {
                peer,
                token_digest,
                possession_proved: false,
            },
        );
        Ok(())
    }
    pub(crate) fn socket_path(&self) -> &std::path::Path {
        &self.path
    }
    pub(crate) fn generation(&self) -> u64 {
        1
    }
    pub(crate) fn next_event(&self) -> Option<CoordinatedLocalEventV1> {
        self.events.try_recv().ok()
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        self.bounds.check()
    }
}
impl Drop for CoordinatedLocalIpcV1 {
    fn drop(&mut self) {
        self.bounds.stopped.store(true, Ordering::Release);
        if let Ok(mut held) = self.grants.lock() {
            held.clear();
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        let _ = fs::remove_file(&self.path);
    }
}
fn allowed_scope(scope: &PairScope) -> Result<()> {
    scope.validate()?;
    if !scope.history_read || !scope.preconstruction_export || scope.authorization_export {
        return Err(Error::Authentication);
    }
    Ok(())
}
fn serve(
    listener: UnixListener,
    bounds: &Arc<Bounds>,
    grants: &Mutex<BTreeMap<String, Grant>>,
    sender: &SyncSender<CoordinatedLocalEventV1>,
) {
    let mut pairing_seen = false;
    while bounds.check().is_ok() {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let result = handle(&mut stream, bounds, grants, sender, &mut pairing_seen);
                if result.is_err() {
                    let _ = stream
                        .write_all(b"{\"accepted\":false,\"reason_code\":\"REQUEST_DENIED\"}\n");
                    // An authenticated original request failure is terminal;
                    // never silently replace its original grant or pending work.
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10))
            }
            Err(_) => break,
        }
    }
}
fn handle(
    stream: &mut UnixStream,
    bounds: &Arc<Bounds>,
    grants: &Mutex<BTreeMap<String, Grant>>,
    sender: &SyncSender<CoordinatedLocalEventV1>,
    pairing_seen: &mut bool,
) -> Result<()> {
    bounds.check()?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    enable_credentials(stream.as_raw_fd())?;
    let observed = PeerProcess::observe(stream)?;
    bounds.host.same_live_process(&observed)?;
    let bytes = wholepact_signer_origin::framing::read_frame_capped_checked_until(
        stream,
        &observed,
        144 * 1024,
        bounds.deadline.min(Instant::now() + Duration::from_secs(2)),
        || {
            bounds
                .check()
                .map_err(|_| wholepact_signer_origin::Error::Permission)
        },
    )
    .map_err(|_| Error::Authentication)?;
    // Capture once at physical receive, never when a queued request is reviewed.
    let received_request_deadline = Instant::now() + Duration::from_secs(120);
    let mut envelope: CoordinatedEnvelopeV1 =
        wholepact_core::strict_json::parse_typed_json_with_byte_limit(&bytes, 144 * 1024)
            .map_err(|_| Error::InvalidData)?;
    bounds.check()?;
    match &mut envelope {
        CoordinatedEnvelopeV1::RequestPairing {
            schema_version: 1,
            application_label,
            scope,
        } => {
            if *pairing_seen {
                return Err(Error::Authentication);
            }
            allowed_scope(scope)?;
            validate_label(application_label)?;
            *pairing_seen = true;
            sender
                .try_send(CoordinatedLocalEventV1::Pairing(PendingPairing {
                    peer: observed,
                    label: application_label.clone(),
                    scope: scope.clone(),
                    stream: stream.try_clone()?,
                    created: Instant::now(),
                }))
                .map_err(|_| Error::Unavailable)?;
        }
        CoordinatedEnvelopeV1::CoordinatedV3Request {
            schema_version: 1,
            grant_id,
            token_hex,
            request,
        } => {
            valid_hash(grant_id)?;
            let digest = pairing_token_digest(token_hex)?;
            let is_status = matches!(request, CoordinatedAppRequestV1::Status);
            let peer = {
                let mut held = grants.lock().map_err(|_| Error::Locked)?;
                let grant = held.get_mut(grant_id).ok_or(Error::Authentication)?;
                grant.peer.check_current()?;
                grant.peer.actual_peer().same_live_process(&observed)?;
                if !bool::from(digest.ct_eq(&grant.token_digest)) {
                    return Err(Error::Authentication);
                }
                request
                    .validate(grant.peer.scope())
                    .map_err(|_| Error::Authentication)?;
                if is_status {
                    if grant.possession_proved {
                        return Err(Error::Authentication);
                    }
                    grant.possession_proved = true;
                } else if !grant.possession_proved {
                    return Err(Error::Authentication);
                }
                grant.peer.clone()
            };
            if is_status {
                sender
                    .try_send(CoordinatedLocalEventV1::StatusProof(peer.clone()))
                    .map_err(|_| Error::Unavailable)?;
                crate::authority_bridge::durable_review_ipc_v1::bounded_write(
                    stream,
                    &serde_json::json!({"accepted":true,"reason_code":"REQUEST_ONLY"}),
                    received_request_deadline.min(peer.deadline()),
                    || {
                        peer.check_current()
                            .map_err(|_| crate::authority_bridge::BridgeError::Permission)
                    },
                )
                .map_err(|_| Error::Authentication)?;
            } else {
                let request = match std::mem::replace(request, CoordinatedAppRequestV1::Status) {
                    CoordinatedAppRequestV1::FinancialResult { request } => {
                        CoordinatedRequestV1::FinancialResult(request)
                    }
                    CoordinatedAppRequestV1::Closed { request } => {
                        CoordinatedRequestV1::Closed(request)
                    }
                    CoordinatedAppRequestV1::Redisclosure { request } => {
                        CoordinatedRequestV1::Redisclosure(request)
                    }
                    CoordinatedAppRequestV1::Prepare { request } => {
                        CoordinatedRequestV1::Prepare(request)
                    }
                    _ => return Err(Error::Authentication),
                };
                sender
                    .try_send(CoordinatedLocalEventV1::Request {
                        original_request_deadline: received_request_deadline
                            .min(bounds.deadline)
                            .min(peer.deadline()),
                        peer,
                        stream: stream.try_clone()?,
                        request,
                    })
                    .map_err(|_| Error::Unavailable)?;
            }
        }
        _ => return Err(Error::Authentication),
    }
    bounds.check()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn coordinated_endpoint_rejects_legacy_and_unknown_wire_profiles() {
        for bytes in [
            r#"{"command":"request","schema_version":1,"grant_id":"00","token_hex":"00","request":{"operation":"status"}}"#,
            r#"{"command":"closed_recipient_v3","schema_version":3,"request":{"purpose":"activate","intent_digest":"00","nonce":"00"}}"#,
            r#"{"command":"coordinated_v3_request","schema_version":1,"grant_id":"00","token_hex":"00","request":{"operation":"status"},"approved":true}"#,
        ] {
            assert!(serde_json::from_str::<CoordinatedEnvelopeV1>(bytes).is_err());
        }
    }
    #[test]
    fn coordinated_status_is_request_only_and_does_not_deserialize_a_peer() {
        let bytes = r#"{"command":"coordinated_v3_request","schema_version":1,"grant_id":"00","token_hex":"00","request":{"operation":"status"}}"#;
        assert!(matches!(
            serde_json::from_str::<CoordinatedEnvelopeV1>(bytes).unwrap(),
            CoordinatedEnvelopeV1::CoordinatedV3Request {
                schema_version: 1,
                ..
            }
        ));
        // Parsing is inert. The actual handler separately requires hashes,
        // the private registry, observed same H, token proof and source lifetime.
    }
    #[test]
    fn shared_token_kernel_rejects_wrong_length_case_and_nonhex() {
        for value in ["00".to_owned(), "FF".repeat(32), "zz".repeat(32)] {
            assert!(pairing_token_digest(&value).is_err());
        }
        assert!(pairing_token_digest(&"ab".repeat(32)).is_ok());
    }
}
