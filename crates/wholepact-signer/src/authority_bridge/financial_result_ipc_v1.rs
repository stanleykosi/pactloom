//! Actual installed-provider/kernel-peer result lease. Wire evidence is inert;
//! only this authenticated receive path can construct the public lease.
use crate::authority_bridge::{BridgeError, Result, financial_continuation_v1::*};
use crate::{
    account::birth::enrollment::roster_v2::financial_source_v1::PreparedOriginalFinancialSourceV1,
    native_peer::PeerProcess,
    native_ui::financial_authority_v1::{FinancialReadLeaseV1, FinancialReturnActionV1},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    os::{fd::AsRawFd, unix::net::UnixStream},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1;
const MAX_FRAME: usize = 512 * 1024;
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FinancialResultRequestV1 {
    pub account_id: String,
    pub authorization_id: String,
    pub original_consent_ref: String,
    pub fixed: FixedProposalIdentityV1,
}
impl FinancialResultRequestV1 {
    pub(crate) fn validate(&self) -> Result<()> {
        crate::authority_bridge::born_history_ipc::hash(&self.account_id)?;
        crate::authority_bridge::born_history_ipc::hash(&self.original_consent_ref)?;
        crate::review::validate_label(&self.authorization_id).map_err(|_| BridgeError::Binding)?;
        crate::authority_bridge::durable_review_ipc_v3::fixed_binding_v3(&self.fixed)?
            .validate()?;
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    request: FinancialResultRequestV1,
    continuation: OwnerControlRequest,
    record: FinancialContinuationRecordV1,
    result_digest: String,
    outbox_digest: String,
    participant_index: usize,
    signature_set_digest: String,
    outbox: String,
}
impl Evidence {
    fn validate(&self) -> Result<()> {
        self.request.validate()?;
        self.record
            .validate_request(&self.continuation, &self.record.terms.scope.witness)?;
        let a = &self.record.terms.scope.authorization;
        if self.request.account_id != a.identity.account_id
            || self.request.authorization_id != a.authorization_id
            || crate::authority_bridge::durable_review_ipc_v3::fixed_binding_v3(
                &self.request.fixed,
            )? != a.fixed
            || self.outbox.len() > crate::authority_bridge::protocol::MAX_OUTBOX_BYTES
            || hex::encode(Sha256::digest(self.outbox.as_bytes())) != self.outbox_digest
        {
            return Err(BridgeError::Binding);
        }
        if signature_digest(&self.outbox, self.participant_index)? != self.signature_set_digest {
            return Err(BridgeError::Binding);
        }
        crate::authority_bridge::born_history_ipc::hash(&self.result_digest)?;
        crate::authority_bridge::born_history_ipc::hash(&self.outbox_digest)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum Response {
    Preview {
        preview: PreviewData,
    },
    Ready {
        lease_id: String,
    },
    Held {
        lease_id: String,
        remaining_ms: u64,
        evidence: Box<Evidence>,
    },
    Current {
        lease_id: String,
        nonce: String,
    },
    Finished,
    Denied,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    HostPrepared { preview_digest: String },
    Fetch { lease_id: String },
    Check { nonce: String },
    Finish,
}
fn read<T: serde::de::DeserializeOwned>(
    stream: &UnixStream,
    peer: &PeerProcess,
    deadline: Instant,
    check: &dyn Fn() -> Result<()>,
) -> Result<T> {
    let bytes = zeroize::Zeroizing::new(
        wholepact_signer_origin::framing::read_frame_capped_checked_until(
            stream,
            peer,
            MAX_FRAME,
            deadline,
            || check().map_err(|_| wholepact_signer_origin::Error::Permission),
        )
        .map_err(|_| BridgeError::Ipc)?,
    );
    wholepact_core::strict_json::parse_typed_json_with_byte_limit(&bytes, MAX_FRAME)
        .map_err(|_| BridgeError::Binding)
}
fn write<T: Serialize>(
    stream: &mut UnixStream,
    data: &T,
    deadline: Instant,
    check: &dyn Fn() -> Result<()>,
) -> Result<()> {
    crate::authority_bridge::durable_review_ipc_v1::bounded_write(stream, data, deadline, check)
}

/// Actual source + exact retained bytes + observed recipient, awaiting a fresh
/// ReturnExact native decision. It is not a public evidence constructor.
pub(crate) struct PreparedFinancialReturnV1 {
    source: Arc<PreparedOriginalFinancialSourceV1>,
    peer: PeerProcess,
    evidence: Evidence,
    digest: String,
}
impl PreparedFinancialReturnV1 {
    pub(crate) fn prepare(
        source: Arc<PreparedOriginalFinancialSourceV1>,
        read_owner: FinancialReadLeaseV1,
        peer: PeerProcess,
        request: &FinancialResultRequestV1,
        stream: &mut UnixStream,
    ) -> Result<Self> {
        request.validate()?;
        source
            .require_original_financial_host_v1(&peer)
            .map_err(|_| BridgeError::Permission)?;
        source
            .check_read(&read_owner)
            .map_err(|_| BridgeError::Permission)?;
        peer.check_alive().map_err(|_| BridgeError::Permission)?;
        let (original, _, _, result) = source
            .financial_journal()
            .map_err(|_| BridgeError::Permission)?
            .financial_retained_result_v1(
                &*source
                    .financial_binding()
                    .map_err(|_| BridgeError::Permission)?,
                &read_owner,
            )?;
        let continuation = source
            .continuation_request()
            .map_err(|_| BridgeError::Binding)?;
        let OwnerControl::AdmitFinancialContinuationV1 { record } = &continuation.control else {
            return Err(BridgeError::Binding);
        };
        if original.original_consent().reference() != request.original_consent_ref
            || result.original_consent_ref != request.original_consent_ref
            || result.authorization_id != request.authorization_id
        {
            return Err(BridgeError::Binding);
        }
        let participant_index = original
            .accepted_manifest()
            .proposal_input()
            .manifest
            .participants
            .iter()
            .position(|p| p.account_id == request.account_id)
            .ok_or(BridgeError::Binding)?;
        let signature_set_digest = signature_digest(&result.outbox_payload, participant_index)?;
        let evidence = Evidence {
            participant_index,
            signature_set_digest,
            request: request.clone(),
            record: record.as_ref().clone(),
            continuation,
            result_digest: result.result_digest.clone(),
            outbox_digest: result.outbox_digest.clone(),
            outbox: result.outbox_payload.clone(),
        };
        evidence.validate()?;
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:financial-exact-result-return:v1",
            &(
                source.identity_digest(),
                peer.instance(),
                PreviewData::from_evidence(&evidence),
            ),
        )
        .map_err(|_| BridgeError::Binding)?;
        let observed = PeerProcess::observe(stream).map_err(|_| BridgeError::Permission)?;
        peer.same_live_process(&observed)
            .map_err(|_| BridgeError::Permission)?;
        let preview = PreviewData::from_evidence(&evidence);
        write(
            stream,
            &Response::Preview { preview },
            source
                .original_deadline()
                .min(Instant::now() + Duration::from_secs(2)),
            &|| {
                source
                    .check_read(&read_owner)
                    .and_then(|_| source.require_original_financial_host_v1(&peer))
                    .map_err(|_| BridgeError::Permission)
            },
        )?;
        source
            .check_read(&read_owner)
            .map_err(|_| BridgeError::Permission)?;
        drop(read_owner);
        Ok(Self {
            source,
            peer,
            evidence,
            digest,
        })
    }
    /// Wait with inert prepared data only. Do not stage the short native review
    /// until the Host has completed its own exact retention preflight.
    pub(crate) fn await_host_prepared(self, stream: &UnixStream) -> Result<Self> {
        let deadline = self
            .source
            .original_deadline()
            .min(Instant::now() + Duration::from_secs(900));
        let current = || {
            self.source
                .require_original_financial_host_v1(&self.peer)
                .map_err(|_| BridgeError::Permission)
        };
        let expected = PreviewData::from_evidence(&self.evidence).digest()?;
        match read(stream, &self.peer, deadline, &current)? {
            Command::HostPrepared { preview_digest } if preview_digest == expected => {
                current()?;
                Ok(self)
            }
            _ => Err(BridgeError::Permission),
        }
    }
    pub(crate) fn reviewed_digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn display(&self) -> String {
        format!(
            "RETURN ONLY THE ALREADY RETAINED EXACT FINANCIAL SIGNATURE RESULT\nAccount: {}\nAuthorization: {}\nOriginal consent: {}\nResult: {}\nOutbox: {}\nRecipient process: {}\nNo new signature, reservation, or transaction will be created.\nExact return: {}",
            self.evidence.request.account_id,
            self.evidence.request.authorization_id,
            self.evidence.request.original_consent_ref,
            self.evidence.result_digest,
            self.evidence.outbox_digest,
            self.peer.instance(),
            self.digest
        )
    }
    pub(crate) fn approve(
        self,
        action: FinancialReturnActionV1,
    ) -> Result<ApprovedFinancialReturnV1> {
        self.source
            .check_custody()
            .map_err(|_| BridgeError::Permission)?;
        self.peer
            .check_alive()
            .map_err(|_| BridgeError::Permission)?;
        action
            .check_source(self.source.identity_digest())
            .map_err(|_| BridgeError::Permission)?;
        if action.terms_digest() != self.digest {
            return Err(BridgeError::Binding);
        }
        Ok(ApprovedFinancialReturnV1 {
            prepared: self,
            action,
        })
    }
}
pub(crate) struct ApprovedFinancialReturnV1 {
    prepared: PreparedFinancialReturnV1,
    action: FinancialReturnActionV1,
}
impl ApprovedFinancialReturnV1 {
    fn check(&self) -> Result<()> {
        self.prepared
            .source
            .require_original_financial_host_v1(&self.prepared.peer)
            .map_err(|_| BridgeError::Permission)?;
        self.action
            .check_source(self.prepared.source.identity_digest())
            .map_err(|_| BridgeError::Permission)?;
        self.prepared
            .peer
            .check_alive()
            .map_err(|_| BridgeError::Permission)
    }
    pub(crate) fn serve(self, mut stream: UnixStream) -> Result<()> {
        self.check()?;
        let observed = PeerProcess::observe(&stream).map_err(|_| BridgeError::Permission)?;
        self.prepared
            .peer
            .same_live_process(&observed)
            .map_err(|_| BridgeError::Permission)?;
        let deadline = self
            .action
            .binding()
            .bounded_deadline()
            .map_err(|_| BridgeError::Permission)?
            .min(self.prepared.source.original_deadline());
        let lease_id = hex::encode(crate::vault::random::<32>().map_err(|_| BridgeError::Ipc)?);
        // Borrow evidence while serializing so no duplicate secret-bearing copy
        // is minted and no later retry can reconstruct a different payload.
        #[derive(Serialize)]
        struct Held<'a> {
            status: &'static str,
            lease_id: &'a str,
            remaining_ms: u64,
            evidence: &'a Evidence,
        }
        write(
            &mut stream,
            &Response::Ready {
                lease_id: lease_id.clone(),
            },
            deadline,
            &|| self.check(),
        )?;
        match read(&stream, &self.prepared.peer, deadline, &|| self.check())? {
            Command::Fetch { lease_id: actual } if actual == lease_id => (),
            _ => return Err(BridgeError::Permission),
        }
        let remaining_ms = u64::try_from(
            deadline
                .saturating_duration_since(Instant::now())
                .as_millis(),
        )
        .map_err(|_| BridgeError::Permission)?;
        if remaining_ms == 0 || remaining_ms > 120_000 {
            return Err(BridgeError::Permission);
        }
        write(
            &mut stream,
            &Held {
                status: "held",
                lease_id: &lease_id,
                remaining_ms,
                evidence: &self.prepared.evidence,
            },
            deadline,
            &|| self.check(),
        )?;
        loop {
            let command: Command = read(&stream, &self.prepared.peer, deadline, &|| self.check())?;
            self.check()?;
            match command {
                Command::Check { nonce } => {
                    crate::authority_bridge::born_history_ipc::hash(&nonce)?;
                    write(
                        &mut stream,
                        &Response::Current {
                            lease_id: lease_id.clone(),
                            nonce,
                        },
                        deadline,
                        &|| self.check(),
                    )?;
                }
                Command::Finish => {
                    write(&mut stream, &Response::Finished, deadline, &|| self.check())?;
                    return Ok(());
                }
                Command::Fetch { .. } | Command::HostPrepared { .. } => {
                    return Err(BridgeError::Permission);
                }
            }
        }
    }
}

/// Owns the actual installed trust anchor and checked kernel peer, not an old
/// signing lease or a caller-asserted delivery record. No Clone/serde constructor.
pub struct AuthenticatedFinancialResultLeaseV1 {
    provider: crate::authority_bridge::provider::InstalledSignerProvider,
    peer: PeerProcess,
    stream: Mutex<UnixStream>,
    failed: AtomicBool,
    lease_id: String,
    evidence: Evidence,
    deadline: Instant,
}
impl AuthenticatedFinancialResultLeaseV1 {
    pub fn receive(
        provider: crate::authority_bridge::provider::InstalledSignerProvider,
        socket: &Path,
        request: &FinancialResultRequestV1,
        original_deadline: Instant,
    ) -> Result<Self> {
        PreparedFinancialResultReceiverV1::prepare(provider, socket, request, original_deadline)?
            .receive()
    }
    pub fn check_current(&self) -> Result<()> {
        let deadline = self.deadline.min(Instant::now() + Duration::from_secs(2));
        let current = || {
            if self.failed.load(Ordering::Acquire) || Instant::now() >= deadline {
                return Err(BridgeError::Permission);
            }
            self.peer.check_alive().map_err(|_| BridgeError::Permission)
        };
        let result = (|| {
            current()?;
            let mut stream =
                crate::authority_bridge::born_ipc_io::lock_until(&self.stream, deadline, &current)?;
            let actual = self.provider.verify_server(&stream)?;
            self.peer
                .same_live_process(&actual)
                .map_err(|_| BridgeError::Permission)?;
            let nonce = hex::encode(crate::vault::random::<32>().map_err(|_| BridgeError::Ipc)?);
            write(
                &mut stream,
                &Command::Check {
                    nonce: nonce.clone(),
                },
                deadline,
                &current,
            )?;
            match read(&stream, &self.peer, deadline, &current)? {
                Response::Current {
                    lease_id,
                    nonce: actual,
                } if lease_id == self.lease_id && nonce == actual => current(),
                _ => Err(BridgeError::Permission),
            }
        })();
        if result.is_err() {
            self.failed.store(true, Ordering::Release);
        }
        result
    }
    /// Call only after the consumer's durable exact-intake commit. A missing
    /// reply is uncertain acknowledgement, never permission to sign again.
    pub fn finish(self) -> Result<()> {
        self.check_current()?;
        let deadline = self.deadline.min(Instant::now() + Duration::from_secs(2));
        let mut stream = self.stream.into_inner().map_err(|_| BridgeError::Ipc)?;
        let current = || {
            if Instant::now() >= deadline {
                return Err(BridgeError::Permission);
            }
            self.peer.check_alive().map_err(|_| BridgeError::Permission)
        };
        write(&mut stream, &Command::Finish, deadline, &current)?;
        match read(&stream, &self.peer, deadline, &current)? {
            Response::Finished => Ok(()),
            _ => Err(BridgeError::Uncertain),
        }
    }
    pub fn account_id(&self) -> &str {
        &self.evidence.request.account_id
    }
    pub fn authorization_id(&self) -> &str {
        &self.evidence.request.authorization_id
    }
    pub fn original_consent_ref(&self) -> &str {
        &self.evidence.request.original_consent_ref
    }
    pub fn fixed_identity(&self) -> &FixedProposalIdentityV1 {
        &self.evidence.request.fixed
    }
    pub fn result_digest(&self) -> &str {
        &self.evidence.result_digest
    }
    pub fn outbox_digest(&self) -> &str {
        &self.evidence.outbox_digest
    }
    pub fn continuation_request(&self) -> &OwnerControlRequest {
        &self.evidence.continuation
    }
    pub fn continuation_record(&self) -> &FinancialContinuationRecordV1 {
        &self.evidence.record
    }
    pub fn outbox_bytes(&self) -> Result<&[u8]> {
        self.check_current()?;
        Ok(self.evidence.outbox.as_bytes())
    }
}

impl Drop for Evidence {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.outbox.zeroize();
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PreviewData {
    request: FinancialResultRequestV1,
    continuation: OwnerControlRequest,
    record: FinancialContinuationRecordV1,
    result_digest: String,
    outbox_digest: String,
    signature_set_digest: String,
}
impl PreviewData {
    fn from_evidence(e: &Evidence) -> Self {
        Self {
            request: e.request.clone(),
            continuation: e.continuation.clone(),
            record: e.record.clone(),
            result_digest: e.result_digest.clone(),
            outbox_digest: e.outbox_digest.clone(),
            signature_set_digest: e.signature_set_digest.clone(),
        }
    }
    fn digest(&self) -> Result<String> {
        wholepact_core::proposal::canonical_digest("wholepact:financial-result-preview:v1", self)
            .map_err(|_| BridgeError::Binding)
    }
    fn validate(&self) -> Result<()> {
        self.request.validate()?;
        self.record
            .validate_request(&self.continuation, &self.record.terms.scope.witness)?;
        let a = &self.record.terms.scope.authorization;
        if self.request.account_id != a.identity.account_id
            || self.request.authorization_id != a.authorization_id
            || crate::authority_bridge::durable_review_ipc_v3::fixed_binding_v3(
                &self.request.fixed,
            )? != a.fixed
        {
            return Err(BridgeError::Binding);
        }
        for h in [
            &self.result_digest,
            &self.outbox_digest,
            &self.signature_set_digest,
        ] {
            crate::authority_bridge::born_history_ipc::hash(h)?;
        }
        Ok(())
    }
}
/// Authenticated, inert metadata only. No signature bytes, live grant, or DTO
/// constructor. It may cross the Host's human review without a Signer action.
pub struct AuthenticatedFinancialResultPreviewV1 {
    data: PreviewData,
}
impl AuthenticatedFinancialResultPreviewV1 {
    pub fn account_id(&self) -> &str {
        &self.data.request.account_id
    }
    pub fn authorization_id(&self) -> &str {
        &self.data.request.authorization_id
    }
    pub fn original_consent_ref(&self) -> &str {
        &self.data.request.original_consent_ref
    }
    pub fn fixed_identity(&self) -> &FixedProposalIdentityV1 {
        &self.data.request.fixed
    }
    pub fn result_digest(&self) -> &str {
        &self.data.result_digest
    }
    pub fn outbox_digest(&self) -> &str {
        &self.data.outbox_digest
    }
    pub fn signature_set_digest(&self) -> &str {
        &self.data.signature_set_digest
    }
    pub fn continuation_request(&self) -> &OwnerControlRequest {
        &self.data.continuation
    }
    pub fn continuation_record(&self) -> &FinancialContinuationRecordV1 {
        &self.data.record
    }
}
pub struct PreparedFinancialResultReceiverV1 {
    provider: crate::authority_bridge::provider::InstalledSignerProvider,
    peer: PeerProcess,
    stream: UnixStream,
    preview: AuthenticatedFinancialResultPreviewV1,
    original_deadline: Instant,
}
impl PreparedFinancialResultReceiverV1 {
    pub fn prepare(
        provider: crate::authority_bridge::provider::InstalledSignerProvider,
        socket: &Path,
        request: &FinancialResultRequestV1,
        original_deadline: Instant,
    ) -> Result<Self> {
        request.validate()?;
        let deadline = original_deadline.min(Instant::now() + Duration::from_secs(900));
        let mut stream =
            wholepact_signer_origin::connect_local_checked_until(socket, deadline, || {
                if Instant::now() < deadline {
                    Ok(())
                } else {
                    Err(wholepact_signer_origin::Error::Permission)
                }
            })?;
        crate::ipc::enable_credentials(stream.as_raw_fd()).map_err(|_| BridgeError::Ipc)?;
        let peer = provider.verify_server(&stream)?;
        let current = || peer.check_alive().map_err(|_| BridgeError::Permission);
        write(
            &mut stream,
            &serde_json::json!({"command":"financial_result_v1","schema_version":1,"request":request}),
            deadline,
            &current,
        )?;
        let Response::Preview { preview } = read(&stream, &peer, deadline, &current)? else {
            return Err(BridgeError::Permission);
        };
        preview.validate()?;
        if preview.request != *request {
            return Err(BridgeError::Binding);
        }
        Ok(Self {
            provider,
            peer,
            stream,
            preview: AuthenticatedFinancialResultPreviewV1 { data: preview },
            original_deadline,
        })
    }
    pub fn preview(&self) -> &AuthenticatedFinancialResultPreviewV1 {
        &self.preview
    }
    /// Host preflight must finish before asking the Signer to make ReturnExact.
    /// No saved preview itself grants receive, key use, or dispatch permission.
    pub fn receive(mut self) -> Result<AuthenticatedFinancialResultLeaseV1> {
        let deadline = self
            .original_deadline
            .min(Instant::now() + Duration::from_secs(900));
        let current = || self.peer.check_alive().map_err(|_| BridgeError::Permission);
        let actual = self.provider.verify_server(&self.stream)?;
        self.peer
            .same_live_process(&actual)
            .map_err(|_| BridgeError::Permission)?;
        write(
            &mut self.stream,
            &Command::HostPrepared {
                preview_digest: self.preview.data.digest()?,
            },
            deadline,
            &current,
        )?;
        let Response::Ready { lease_id: ready } =
            read(&self.stream, &self.peer, deadline, &current)?
        else {
            return Err(BridgeError::Permission);
        };
        crate::authority_bridge::born_history_ipc::hash(&ready)?;
        let started = Instant::now();
        let deadline = self
            .original_deadline
            .min(started + Duration::from_secs(120));
        write(
            &mut self.stream,
            &Command::Fetch {
                lease_id: ready.clone(),
            },
            deadline,
            &current,
        )?;
        let Response::Held {
            lease_id,
            remaining_ms,
            evidence,
        } = read(&self.stream, &self.peer, deadline, &current)?
        else {
            return Err(BridgeError::Permission);
        };
        evidence.validate()?;
        if lease_id != ready
            || remaining_ms == 0
            || remaining_ms > 120_000
            || PreviewData::from_evidence(&evidence) != self.preview.data
        {
            return Err(BridgeError::Binding);
        }
        let deadline = deadline.min(started + Duration::from_millis(remaining_ms));
        let lease = AuthenticatedFinancialResultLeaseV1 {
            provider: self.provider,
            peer: self.peer,
            stream: Mutex::new(self.stream),
            failed: AtomicBool::new(false),
            lease_id,
            evidence: *evidence,
            deadline,
        };
        lease.check_current()?;
        Ok(lease)
    }
}
fn signature_digest(outbox: &str, participant_index: usize) -> Result<String> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Signature {
        action_index: usize,
        signature_hex: String,
    }
    impl Drop for Signature {
        fn drop(&mut self) {
            use zeroize::Zeroize;
            self.signature_hex.zeroize();
        }
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Payload {
        schema_version: u16,
        candidate_id: String,
        manifest_digest: String,
        proved_artifact_digest: String,
        review_binding: String,
        account_id: String,
        signatures: Vec<Signature>,
    }
    let mut payload: Payload = wholepact_core::strict_json::parse_typed_json_with_byte_limit(
        outbox.as_bytes(),
        crate::authority_bridge::protocol::MAX_OUTBOX_BYTES,
    )
    .map_err(|_| BridgeError::Binding)?;
    if payload.schema_version != 1 || payload.signatures.is_empty() || payload.signatures.len() > 8
    {
        return Err(BridgeError::Binding);
    }
    let _ = (
        &payload.candidate_id,
        &payload.manifest_digest,
        &payload.proved_artifact_digest,
        &payload.review_binding,
        &payload.account_id,
    );
    payload.signatures.sort_by_key(|s| s.action_index);
    if payload
        .signatures
        .windows(2)
        .any(|w| w[0].action_index == w[1].action_index)
    {
        return Err(BridgeError::Binding);
    }
    let mut hash = Sha256::new();
    for sig in &payload.signatures {
        let bytes = zeroize::Zeroizing::new(
            hex::decode(&sig.signature_hex).map_err(|_| BridgeError::Binding)?,
        );
        if bytes.len() != 64 {
            return Err(BridgeError::Binding);
        }
        hash.update((participant_index as u64).to_le_bytes());
        hash.update((sig.action_index as u64).to_le_bytes());
        hash.update(bytes.as_slice());
    }
    Ok(hex::encode(hash.finalize()))
}
