//! Inactive purpose-separated discovery admission. Integration replaces the
//! private Grant.scope with GrantScopeV1 and calls authenticate_common_v1 from
//! EVERY ordinary extractor as well as this route. No separate grant registry,
//! ordinary session conversion, or DTO-derived native authority is introduced.
use super::*;
use crate::account::birth::enrollment::roster_v2::durable_entry_v1::FreshDurableBornEntryV1;
use crate::native_ui::{NativeAuthority, NativeAuthorityBinding, NativeDecision};
use wholepact_signer_origin::durable_input_projection_v1::{
    DurableInputProjectionRequestV1, INPUT_PROJECTION_PAIR_REASON_V1,
    MAX_INPUT_PROJECTION_FRAME_BYTES_V1, ProjectionChannelBindingV1, ProjectionPairResponseV1,
    ProjectionPairScopeV1, ProjectionRequestV1, ProjectionResponseV1,
    projection_pairing_review_digest_v1,
    redisclosure::{
        DurableInputProjectionRedisclosureRequestV1, ProjectionRedisclosureChannelBindingV1,
        ProjectionRedisclosurePairResponseV1, ProjectionRedisclosurePairScopeV1,
        ProjectionRedisclosureRequestV1, ProjectionRedisclosureResponseV1,
        REDISCLOSURE_PAIR_REASON_V1, redisclosure_pairing_review_digest_v1,
    },
};

const MAX_OPERATION: Duration = Duration::from_secs(120);
fn now() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| Error::Authentication)
}
fn invalid(_: impl std::fmt::Display) -> Error {
    Error::Authentication
}

/// PRIVATE registry tag. Ordinary pairing's exact scope bytes/domain remain
/// unchanged. No caller can select a kind when authenticating an issued token.
#[derive(Clone)]
pub(super) enum GrantScopeV1 {
    Ordinary(PairScope),
    InputProjection(ProjectionPairScopeV1),
    ProjectionRedisclosure(ProjectionRedisclosurePairScopeV1),
}

/// Shared private authenticated carrier. This cannot issue a consent session,
/// transport binding or any public capability. Kind extraction happens BEFORE
/// either nominal peer is constructed, including ordinary private callers.
#[derive(Clone)]
pub(super) struct AuthenticatedGrantV1 {
    native_origin: NativeAuthorityBinding,
    grant_id: String,
    scope: GrantScopeV1,
    label: String,
    peer: PeerProcess,
    token_digest: String,
    channel_digest: String,
    generation: u64,
    expires: Instant,
    current: Arc<AtomicBool>,
}
impl AuthenticatedGrantV1 {
    fn check_current(&self) -> Result<()> {
        self.native_origin.check_current()?;
        if !self.current.load(Ordering::Acquire) || Instant::now() >= self.expires {
            return Err(Error::Authentication);
        }
        self.peer.check_alive().map_err(Into::into)
    }
    pub(super) fn into_ordinary(self) -> Result<AuthenticatedPeer> {
        self.check_current()?;
        let GrantScopeV1::Ordinary(scope) = self.scope else {
            return Err(Error::Authentication);
        };
        let result = AuthenticatedPeer {
            native_origin: self.native_origin,
            grant_id: self.grant_id,
            scope,
            label: self.label,
            peer: self.peer,
            key_digest: self.token_digest,
            channel_digest: self.channel_digest,
            generation: self.generation,
            expires: self.expires,
            current: self.current,
        };
        result.check_current()?;
        Ok(result)
    }
    fn same_grant(&self, other: &Self) -> Result<()> {
        self.check_current()?;
        other.check_current()?;
        self.peer.same_live_process(&other.peer)?;
        if !Arc::ptr_eq(&self.current, &other.current)
            || self.native_origin != other.native_origin
            || self.grant_id != other.grant_id
            || self.token_digest != other.token_digest
            || self.channel_digest != other.channel_digest
            || self.generation != other.generation
            || self.expires != other.expires
            || self.peer.instance() != other.peer.instance()
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
}

/// Single maintained token/kernel/native/expiry verifier for all tagged kinds.
/// Parent authenticate_grant MUST delegate here and call into_ordinary; retaining
/// an old ordinary extractor that treats a projection scope as PairScope is not
/// supported. No route-specific verifier may omit any of these checks.
pub(super) fn authenticate_common_v1(
    grants: &Mutex<BTreeMap<String, Grant>>,
    observed: PeerProcess,
    id: &str,
    token: &str,
) -> Result<AuthenticatedGrantV1> {
    valid_hash(id)?;
    valid_hash(token)?;
    let token = Zeroizing::new(hex::decode(token).map_err(|_| Error::Authentication)?);
    let digest: [u8; 32] = Sha256::digest(token.as_slice()).into();
    let grants = grants.lock().map_err(|_| Error::Authentication)?;
    let grant = grants.get(id).ok_or(Error::Authentication)?;
    grant.peer.same_live_process(&observed)?;
    if Instant::now() >= grant.expires || !bool::from(digest.ct_eq(&grant.token_digest)) {
        return Err(Error::Authentication);
    }
    let result = AuthenticatedGrantV1 {
        native_origin: grant.native_origin.clone(),
        grant_id: id.into(),
        scope: grant.scope.clone(),
        label: grant.label.clone(),
        peer: grant.peer.clone(),
        token_digest: hex::encode(grant.token_digest),
        channel_digest: grant.channel_digest.clone(),
        generation: grant.generation,
        expires: grant.expires,
        current: grant.current.clone(),
    };
    result.check_current()?;
    Ok(result)
}

#[derive(Clone)]
pub(crate) struct AuthenticatedInputProjectionPeerV1 {
    grant: AuthenticatedGrantV1,
    scope: ProjectionPairScopeV1,
}
impl AuthenticatedInputProjectionPeerV1 {
    fn from_common(grant: AuthenticatedGrantV1) -> Result<Self> {
        grant.check_current()?;
        let GrantScopeV1::InputProjection(scope) = &grant.scope else {
            return Err(Error::Authentication);
        };
        let scope = scope.clone();
        let result = Self { grant, scope };
        result.binding()?;
        Ok(result)
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        self.grant.check_current()
    }
    pub(crate) fn native_origin(&self) -> &NativeAuthorityBinding {
        &self.grant.native_origin
    }
    pub(crate) fn scope(&self) -> &ProjectionPairScopeV1 {
        &self.scope
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.grant.expires
    }
    pub(crate) fn require_stream(&self, stream: &UnixStream) -> Result<()> {
        self.check_current()?;
        self.grant
            .peer
            .same_live_process(&PeerProcess::observe(stream)?)?;
        self.check_current()
    }
    pub(crate) fn require_request(&self, request: &DurableInputProjectionRequestV1) -> Result<()> {
        self.check_current()?;
        request.require_valid_at(now()?).map_err(invalid)?;
        request.require_scope(&self.scope).map_err(invalid)
    }
    pub(crate) fn require_same_grant(&self, other: &Self) -> Result<()> {
        self.grant.same_grant(&other.grant)?;
        if self.scope != other.scope {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    pub(crate) fn binding(&self) -> Result<ProjectionChannelBindingV1> {
        self.check_current()?;
        let binding = ProjectionChannelBindingV1 {
            version: 1,
            scope: self.scope.clone(),
            grant_id: self.grant.grant_id.clone(),
            authenticated_local_grant_digest: self.grant.token_digest.clone(),
            channel_binding_digest: self.grant.channel_digest.clone(),
            uid: self.grant.peer.uid(),
            pid: self.grant.peer.pid(),
            process_instance: self.grant.peer.instance().into(),
            signer_generation: self.grant.generation,
        };
        binding.validate().map_err(invalid)?;
        Ok(binding)
    }
}

#[derive(Clone)]
pub(crate) struct AuthenticatedProjectionRedisclosurePeerV1 {
    grant: AuthenticatedGrantV1,
    scope: ProjectionRedisclosurePairScopeV1,
}
impl AuthenticatedProjectionRedisclosurePeerV1 {
    fn from_common(grant: AuthenticatedGrantV1) -> Result<Self> {
        grant.check_current()?;
        let GrantScopeV1::ProjectionRedisclosure(scope) = &grant.scope else {
            return Err(Error::Authentication);
        };
        let scope = scope.clone();
        let result = Self { grant, scope };
        result.binding()?;
        Ok(result)
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        self.grant.check_current()
    }
    pub(crate) fn native_origin(&self) -> &NativeAuthorityBinding {
        &self.grant.native_origin
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.grant.expires
    }
    pub(crate) fn require_stream(&self, stream: &UnixStream) -> Result<()> {
        self.check_current()?;
        self.grant
            .peer
            .same_live_process(&PeerProcess::observe(stream)?)?;
        self.check_current()
    }
    pub(crate) fn require_request(
        &self,
        request: &DurableInputProjectionRedisclosureRequestV1,
    ) -> Result<()> {
        self.check_current()?;
        request.require_valid_at(now()?).map_err(invalid)?;
        request.require_scope(&self.scope).map_err(invalid)
    }
    pub(crate) fn binding(&self) -> Result<ProjectionRedisclosureChannelBindingV1> {
        self.check_current()?;
        let binding = ProjectionRedisclosureChannelBindingV1 {
            version: 1,
            scope: self.scope.clone(),
            grant_id: self.grant.grant_id.clone(),
            authenticated_local_grant_digest: self.grant.token_digest.clone(),
            channel_binding_digest: self.grant.channel_digest.clone(),
            uid: self.grant.peer.uid(),
            pid: self.grant.peer.pid(),
            process_instance: self.grant.peer.instance().into(),
            signer_generation: self.grant.generation,
        };
        binding.validate().map_err(invalid)?;
        Ok(binding)
    }
}

pub(crate) enum ProjectionLocalEventV1 {
    Pairing(PendingInputProjectionPairingV1),
    RedisclosurePairing(PendingProjectionRedisclosurePairingV1),
    Project {
        peer: AuthenticatedInputProjectionPeerV1,
        stream: UnixStream,
        request: DurableInputProjectionRequestV1,
    },
    Redisclose {
        peer: AuthenticatedProjectionRedisclosurePeerV1,
        stream: UnixStream,
        request: DurableInputProjectionRedisclosureRequestV1,
    },
}

pub(crate) struct PendingInputProjectionPairingV1 {
    observed: PeerProcess,
    stream: UnixStream,
    created: Instant,
    label: String,
    request: DurableInputProjectionRequestV1,
}
impl PendingInputProjectionPairingV1 {
    pub(crate) fn request(&self) -> &DurableInputProjectionRequestV1 {
        &self.request
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        if self.created.elapsed() >= MAX_OPERATION {
            return Err(Error::Authentication);
        }
        self.observed.check_alive()?;
        self.request.require_valid_at(now()?).map_err(invalid)
    }
    pub(crate) fn review_digest(&self, generation: u64) -> Result<String> {
        self.check_current()?;
        projection_pairing_review_digest_v1(
            &self.request.pair_scope().map_err(invalid)?,
            self.observed.instance(),
            generation,
        )
        .map_err(invalid)
    }
    pub(crate) fn display(&self) -> Result<String> {
        self.check_current()?;
        Ok(format!(
            "PAIR FOR NONSPENDING INPUT PROJECTION ONLY\nApplication label (unverified): {}\nActual local PID/UID: {}/{}\nExact request:\n{}\n\nThis purpose can request one bounded signer-local selection and a SEPARATE native metadata disclosure. It cannot create enrollment, accept a manifest, export an FVK/note/witness, reserve funds, sign, or broadcast. Canonical account attribution is not person identity or prior peer approval.",
            self.label,
            self.observed.pid(),
            self.observed.uid(),
            serde_json::to_string_pretty(&self.request).map_err(|_| Error::InvalidData)?
        ))
    }
}
pub(crate) struct PendingProjectionRedisclosurePairingV1 {
    observed: PeerProcess,
    stream: UnixStream,
    created: Instant,
    label: String,
    request: DurableInputProjectionRedisclosureRequestV1,
}
impl PendingProjectionRedisclosurePairingV1 {
    pub(crate) fn request(&self) -> &DurableInputProjectionRedisclosureRequestV1 {
        &self.request
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        if self.created.elapsed() >= MAX_OPERATION {
            return Err(Error::Authentication);
        }
        self.observed.check_alive()?;
        self.request.require_valid_at(now()?).map_err(invalid)
    }
    pub(crate) fn review_digest(&self, generation: u64) -> Result<String> {
        self.check_current()?;
        redisclosure_pairing_review_digest_v1(
            &self.request.pair_scope().map_err(invalid)?,
            self.observed.instance(),
            generation,
        )
        .map_err(invalid)
    }
    pub(crate) fn display(&self) -> Result<String> {
        self.check_current()?;
        Ok(format!(
            "PAIR FOR EXACT HISTORICAL PROJECTION REDISCLOSURE ONLY\nApplication label (unverified): {}\nActual local PID/UID: {}/{}\nExact original locator and new delivery request:\n{}\n\nA separate native disclosure decision is still required. No scan, reselection, renewed validity, replacement original record, financial approval or ordinary signer session is permitted.",
            self.label,
            self.observed.pid(),
            self.observed.uid(),
            serde_json::to_string_pretty(&self.request).map_err(|_| Error::InvalidData)?
        ))
    }
}

/// New commands are parsed independently using the strict bounded visitor.
/// Parent dispatch must call this only for these exact tags, before AppRequest.
#[derive(Deserialize)]
#[serde(tag = "command", deny_unknown_fields)]
pub(super) enum ProjectionEnvelopeV1 {
    #[serde(rename = "request_durable_input_projection_pairing_v1")]
    Pair {
        schema_version: u16,
        application_label: String,
        request: DurableInputProjectionRequestV1,
    },
    #[serde(rename = "request_durable_input_projection_v1")]
    Request {
        schema_version: u16,
        grant_id: String,
        token_hex: String,
        request: ProjectionRequestV1,
    },
    #[serde(rename = "request_durable_input_projection_redisclosure_pairing_v1")]
    RedisclosurePair {
        schema_version: u16,
        application_label: String,
        request: DurableInputProjectionRedisclosureRequestV1,
    },
    #[serde(rename = "request_durable_input_projection_redisclosure_v1")]
    RedisclosureRequest {
        schema_version: u16,
        grant_id: String,
        token_hex: String,
        request: ProjectionRedisclosureRequestV1,
    },
}
impl Drop for ProjectionEnvelopeV1 {
    fn drop(&mut self) {
        match self {
            Self::Request { token_hex, .. } | Self::RedisclosureRequest { token_hex, .. } => {
                token_hex.zeroize()
            }
            _ => {}
        }
    }
}

pub(super) fn admit_v1(
    frame: &[u8],
    stream: &mut UnixStream,
    observed: PeerProcess,
    grants: &Mutex<BTreeMap<String, Grant>>,
    mode: &IpcMode,
) -> Result<Option<ProjectionLocalEventV1>> {
    if !matches!(mode, IpcMode::Ordinary) || frame.len() > MAX_INPUT_PROJECTION_FRAME_BYTES_V1 {
        return Err(Error::Authentication);
    }
    let envelope: ProjectionEnvelopeV1 =
        wholepact_core::parse_typed_json(frame).map_err(|_| Error::InvalidData)?;
    match &envelope {
        ProjectionEnvelopeV1::Pair {
            schema_version,
            application_label,
            request,
        } => {
            if *schema_version != 1 {
                return Err(Error::InvalidData);
            }
            validate_label(application_label)?;
            request.require_valid_at(now()?).map_err(invalid)?;
            observed.check_alive()?;
            Ok(Some(ProjectionLocalEventV1::Pairing(
                PendingInputProjectionPairingV1 {
                    observed,
                    stream: stream.try_clone()?,
                    created: Instant::now(),
                    label: application_label.clone(),
                    request: request.clone(),
                },
            )))
        }
        ProjectionEnvelopeV1::RedisclosurePair {
            schema_version,
            application_label,
            request,
        } => {
            if *schema_version != 1 {
                return Err(Error::InvalidData);
            }
            validate_label(application_label)?;
            request.require_valid_at(now()?).map_err(invalid)?;
            observed.check_alive()?;
            Ok(Some(ProjectionLocalEventV1::RedisclosurePairing(
                PendingProjectionRedisclosurePairingV1 {
                    observed,
                    stream: stream.try_clone()?,
                    created: Instant::now(),
                    label: application_label.clone(),
                    request: request.clone(),
                },
            )))
        }
        ProjectionEnvelopeV1::Request {
            schema_version,
            grant_id,
            token_hex,
            request,
        } => {
            if *schema_version != 1 {
                return Err(Error::InvalidData);
            }
            let peer = AuthenticatedInputProjectionPeerV1::from_common(authenticate_common_v1(
                grants, observed, grant_id, token_hex,
            )?)?;
            match request {
                ProjectionRequestV1::Status => {
                    let raw = Zeroizing::new(
                        serde_json::to_vec(&ProjectionResponseV1::Current {
                            binding: peer.binding()?,
                        })
                        .map_err(|_| Error::InvalidData)?,
                    );
                    write_checked_v1(stream, raw, peer.deadline(), peer.native_origin(), || {
                        peer.check_current()
                    })?;
                    Ok(None)
                }
                ProjectionRequestV1::Project { request } => {
                    peer.require_request(request)?;
                    Ok(Some(ProjectionLocalEventV1::Project {
                        peer,
                        stream: stream.try_clone()?,
                        request: *request.clone(),
                    }))
                }
            }
        }
        ProjectionEnvelopeV1::RedisclosureRequest {
            schema_version,
            grant_id,
            token_hex,
            request,
        } => {
            if *schema_version != 1 {
                return Err(Error::InvalidData);
            }
            let peer = AuthenticatedProjectionRedisclosurePeerV1::from_common(
                authenticate_common_v1(grants, observed, grant_id, token_hex)?,
            )?;
            match request {
                ProjectionRedisclosureRequestV1::Status => {
                    let raw = Zeroizing::new(
                        serde_json::to_vec(&ProjectionRedisclosureResponseV1::Current {
                            binding: peer.binding()?,
                        })
                        .map_err(|_| Error::InvalidData)?,
                    );
                    write_checked_v1(stream, raw, peer.deadline(), peer.native_origin(), || {
                        peer.check_current()
                    })?;
                    Ok(None)
                }
                ProjectionRedisclosureRequestV1::Redisclose { request } => {
                    peer.require_request(request)?;
                    Ok(Some(ProjectionLocalEventV1::Redisclose {
                        peer,
                        stream: stream.try_clone()?,
                        request: *request.clone(),
                    }))
                }
            }
        }
    }
}

/// A publication fence covers only a bounded write syscall, never human wait.
/// Checks include actual native/peer/source permission before and after every
/// chunk. Errors preserve already committed outbox/disclosed-or-unknown state.
pub(crate) fn write_checked_v1(
    stream: &mut UnixStream,
    mut raw: Zeroizing<Vec<u8>>,
    deadline: Instant,
    native: &NativeAuthorityBinding,
    mut check: impl FnMut() -> Result<()>,
) -> Result<()> {
    if raw.len() >= MAX_INPUT_PROJECTION_FRAME_BYTES_V1 {
        return Err(Error::InvalidData);
    }
    raw.push(b'\n');
    let mut offset = 0;
    while offset < raw.len() {
        native.check_current()?;
        check()?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|v| !v.is_zero())
            .ok_or(Error::Locked)?;
        stream.set_write_timeout(Some(remaining.min(Duration::from_secs(2))))?;
        let lease = native.publication_lease()?;
        check()?;
        let written = stream.write(&raw[offset..raw.len().min(offset + 32 * 1024)])?;
        drop(lease);
        native.check_current()?;
        check()?;
        if written == 0 || Instant::now() >= deadline {
            return Err(Error::Unavailable);
        }
        offset += written;
    }
    Ok(())
}

impl LocalIpc {
    pub(crate) fn approve_input_projection_pairing_v1(
        &self,
        pending: PendingInputProjectionPairingV1,
        decision: NativeDecision,
        authority: &NativeAuthority,
        source: &FreshDurableBornEntryV1,
    ) -> Result<()> {
        pending.check_current()?;
        source.check_current()?;
        source.require_input_projection_intent_v1(&pending.request.intent)?;
        let digest = pending.review_digest(self.generation)?;
        self.require_projection_entry_v1(source, authority, &decision, &digest)?;
        let scope = pending.request.pair_scope().map_err(invalid)?;
        let mut pending = pending;
        self.issue_projection_pairing_v1(
            &pending.observed,
            &mut pending.stream,
            pending.created,
            &pending.label,
            GrantScopeV1::InputProjection(scope.clone()),
            digest,
            source,
            authority,
            pending.request.intent.valid_until_unix_seconds,
            |id, token, expires, grant| {
                let binding = ProjectionChannelBindingV1 {
                    version: 1,
                    scope: scope.clone(),
                    grant_id: id.into(),
                    authenticated_local_grant_digest: hex::encode(grant.token_digest),
                    channel_binding_digest: grant.channel_digest.clone(),
                    uid: grant.peer.uid(),
                    pid: grant.peer.pid(),
                    process_instance: grant.peer.instance().into(),
                    signer_generation: grant.generation,
                };
                binding.validate().map_err(invalid)?;
                serde_json::to_vec(&ProjectionPairResponseV1 {
                    schema_version: 1,
                    accepted: true,
                    reason_code: INPUT_PROJECTION_PAIR_REASON_V1.into(),
                    grant_id: id.into(),
                    token_hex: token.into(),
                    expires_in_seconds: expires,
                    binding,
                })
                .map_err(|_| Error::InvalidData)
            },
        )
    }
    pub(crate) fn approve_projection_redisclosure_pairing_v1(
        &self,
        pending: PendingProjectionRedisclosurePairingV1,
        decision: NativeDecision,
        authority: &NativeAuthority,
        source: &FreshDurableBornEntryV1,
    ) -> Result<()> {
        pending.check_current()?;
        source.check_current()?;
        source.require_input_projection_intent_v1(&pending.request.original_request.intent)?;
        let digest = pending.review_digest(self.generation)?;
        self.require_projection_entry_v1(source, authority, &decision, &digest)?;
        let scope = pending.request.pair_scope().map_err(invalid)?;
        let mut pending = pending;
        self.issue_projection_pairing_v1(
            &pending.observed,
            &mut pending.stream,
            pending.created,
            &pending.label,
            GrantScopeV1::ProjectionRedisclosure(scope.clone()),
            digest,
            source,
            authority,
            pending
                .request
                .original_request
                .intent
                .valid_until_unix_seconds,
            |id, token, expires, grant| {
                let binding = ProjectionRedisclosureChannelBindingV1 {
                    version: 1,
                    scope: scope.clone(),
                    grant_id: id.into(),
                    authenticated_local_grant_digest: hex::encode(grant.token_digest),
                    channel_binding_digest: grant.channel_digest.clone(),
                    uid: grant.peer.uid(),
                    pid: grant.peer.pid(),
                    process_instance: grant.peer.instance().into(),
                    signer_generation: grant.generation,
                };
                binding.validate().map_err(invalid)?;
                serde_json::to_vec(&ProjectionRedisclosurePairResponseV1 {
                    schema_version: 1,
                    accepted: true,
                    reason_code: REDISCLOSURE_PAIR_REASON_V1.into(),
                    grant_id: id.into(),
                    token_hex: token.into(),
                    expires_in_seconds: expires,
                    binding,
                })
                .map_err(|_| Error::InvalidData)
            },
        )
    }
    fn require_projection_entry_v1(
        &self,
        source: &FreshDurableBornEntryV1,
        authority: &NativeAuthority,
        decision: &NativeDecision,
        digest: &str,
    ) -> Result<()> {
        if !matches!(self.mode, IpcMode::Ordinary)
            || self.admission_closed.load(Ordering::Acquire)
            || source.native_binding() != authority.binding()
            || decision.binding() != &authority.binding()
            || decision.reviewed_digest() != digest
        {
            return Err(Error::Authentication);
        }
        source.check_original_source_current()?;
        authority.check_current()
    }
    #[allow(clippy::too_many_arguments)]
    fn issue_projection_pairing_v1(
        &self,
        peer: &PeerProcess,
        stream: &mut UnixStream,
        created: Instant,
        label: &str,
        scope: GrantScopeV1,
        channel_digest: String,
        source: &FreshDurableBornEntryV1,
        authority: &NativeAuthority,
        valid_until_unix_seconds: u64,
        response: impl FnOnce(&str, &str, u64, &Grant) -> Result<Vec<u8>>,
    ) -> Result<()> {
        let native = authority.binding();
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::Locked)?;
        let scope_remaining = Duration::from_secs(valid_until_unix_seconds)
            .checked_sub(wall)
            .ok_or(Error::Locked)?;
        let scope_deadline = Instant::now()
            .checked_add(scope_remaining)
            .ok_or(Error::Locked)?;
        let deadline = (created + MAX_OPERATION)
            .min(native.bounded_deadline()?)
            .min(scope_deadline);
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(Error::Locked)?;
        let ttl = remaining.as_secs();
        if ttl == 0 {
            return Err(Error::Locked);
        }
        let secret = Zeroizing::new(crate::vault::random::<32>()?);
        let id = hex::encode(crate::vault::random::<32>()?);
        let grant = Grant {
            native_origin: native.clone(),
            peer: peer.clone(),
            scope,
            label: label.into(),
            token_digest: Sha256::digest(secret.as_slice()).into(),
            channel_digest,
            generation: self.generation,
            expires: deadline,
            current: Arc::new(AtomicBool::new(true)),
        };
        let token = Zeroizing::new(hex::encode(secret.as_slice()));
        let raw = Zeroizing::new(response(&id, token.as_str(), ttl, &grant)?);
        let mut grants = self.grants.lock().map_err(|_| Error::Locked)?;
        grants.retain(|_, g| g.peer.check_alive().is_ok() && Instant::now() < g.expires);
        if grants.len() >= MAX_GRANTS || self.admission_closed.load(Ordering::Acquire) {
            return Err(Error::Locked);
        }
        source.check_original_source_current()?;
        peer.check_alive()?;
        grants.insert(id.clone(), grant);
        // Same registry/cap/revocation. Failure removes this exact grant; it
        // does not mint another or broaden the deadline. Pair response is not
        // projection disclosure and cannot authorize any ordinary request.
        let result = write_checked_v1(stream, raw, deadline, &native, || {
            source.check_original_source_current()?;
            peer.check_alive()?;
            if self.admission_closed.load(Ordering::Acquire) || now()? >= valid_until_unix_seconds {
                return Err(Error::Locked);
            }
            Ok(())
        });
        if result.is_err() {
            grants.remove(&id);
        }
        result
    }
}
