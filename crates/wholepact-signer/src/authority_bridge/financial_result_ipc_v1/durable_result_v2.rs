//! Explicit completed-result recovery profile. Selectors are historical data;
//! only the fresh native source/peer decisions can authorize Read or Return.
use super::*;

pub const DURABLE_RESULT_REQUEST_MAX_BYTES_V2: usize = 16 * 1024;
pub(crate) const READ_DOMAIN_V2: &str = "wholepact:durable-financial-result-read:v2";
pub(crate) const RETURN_DOMAIN_V2: &str = "wholepact:durable-financial-result-return:v2";

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DurableFinancialResultRequestV2 {
    pub version: u16,
    pub request: FinancialResultRequestV1,
    pub result_digest: String,
    pub outbox_digest: String,
    pub continuation_request_digest: String,
    pub continuation_history_digest: String,
    pub original_delivery_intent_digest: String,
    /// Historical provenance only. This is NEVER the current recipient grant.
    pub original_host_process_instance: String,
    pub original_terms_digest: String,
}
impl DurableFinancialResultRequestV2 {
    pub fn validate(&self) -> Result<()> {
        if self.version != 2 { return Err(BridgeError::Binding); }
        self.request.validate()?;
        for value in [&self.result_digest, &self.outbox_digest,
            &self.continuation_request_digest, &self.continuation_history_digest,
            &self.original_delivery_intent_digest, &self.original_host_process_instance,
            &self.original_terms_digest] {
            crate::authority_bridge::born_history_ipc::hash(value)?;
        }
        if serde_json::to_vec(self).map_err(|_| BridgeError::Binding)?.len()
            > DURABLE_RESULT_REQUEST_MAX_BYTES_V2 { return Err(BridgeError::Limit); }
        Ok(())
    }
    pub fn parse_exact(bytes: &[u8]) -> Result<Self> {
        let value: Self = wholepact_core::strict_json::parse_typed_json_with_byte_limit(
            bytes, DURABLE_RESULT_REQUEST_MAX_BYTES_V2,
        ).map_err(|_| BridgeError::Binding)?;
        value.validate()?;
        Ok(value)
    }
    fn action_digest(&self, domain: &str, source_identity: &str, peer_instance: &str) -> Result<String> {
        self.validate()?;
        crate::authority_bridge::born_history_ipc::hash(source_identity)?;
        crate::authority_bridge::born_history_ipc::hash(peer_instance)?;
        wholepact_core::proposal::canonical_digest(domain, &(self, source_identity, peer_instance))
            .map_err(|_| BridgeError::Binding)
    }
    pub(crate) fn read_review_digest(&self, source_identity: &str, peer_instance: &str) -> Result<String> {
        self.action_digest(READ_DOMAIN_V2, source_identity, peer_instance)
    }
    pub(crate) fn return_review_digest(&self, source_identity: &str, peer_instance: &str, signature_set_digest: &str) -> Result<String> {
        self.validate()?;
        for value in [source_identity, peer_instance, signature_set_digest] {
            crate::authority_bridge::born_history_ipc::hash(value)?;
        }
        wholepact_core::proposal::canonical_digest(
            RETURN_DOMAIN_V2, &(self, source_identity, peer_instance, signature_set_digest),
        ).map_err(|_| BridgeError::Binding)
    }
}

/// Called only by the closed audited source while its actual fresh Read is held.
/// Reuses the original exact outbox/participant validator; no txid-only shortcut.
pub(crate) fn audited_signature_set_digest_v2(
    original: &crate::consent_journal::OriginalAuthorizationEvidence,
    result: &crate::authority_bridge::protocol::RetainedAuthorizationResult,
    continuation: &OwnerControlRequest,
    request: &FinancialResultRequestV1,
) -> Result<String> {
    Ok(Evidence::from_retained(original, result, continuation.clone(), request)?.signature_set_digest.clone())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurablePreviewV2 {
    version: u16,
    request: DurableFinancialResultRequestV2,
    preview: PreviewData,
}

/// V2 has its own handshake and nominal receiver. Shared framing does not
/// convert this owner into the legacy original-peer route.
pub struct PreparedDurableFinancialResultReceiverV2(PreparedFinancialResultReceiverV1);
impl PreparedDurableFinancialResultReceiverV2 {
    pub fn prepare(
        provider: crate::authority_bridge::provider::InstalledSignerProvider,
        socket: &Path,
        request: &DurableFinancialResultRequestV2,
        original_deadline: Instant,
        original: Box<dyn FinancialResultRestrictionV1>,
        preview_read: &dyn FinancialResultRestrictionV1,
    ) -> Result<Self> {
        request.validate()?;
        if !socket.is_absolute() { return Err(BridgeError::Binding); }
        let provider = ResultPeerOriginV1::Installed(provider);
        let deadline = original_deadline.min(Instant::now() + Duration::from_secs(900));
        let restriction = || {
            if Instant::now() >= deadline { return Err(BridgeError::Permission); }
            provider.check_retained()?;
            original.check_before_io()?;
            preview_read.check_before_io()
        };
        restriction()?;
        let mut stream = wholepact_signer_origin::connect_local_checked_until(socket, deadline, || {
            restriction().map_err(|_| wholepact_signer_origin::Error::Permission)
        })?;
        crate::ipc::enable_credentials(stream.as_raw_fd()).map_err(|_| BridgeError::Ipc)?;
        let peer = provider.verify_server(&stream)?;
        let current = || {
            peer.check_alive().map_err(|_| BridgeError::Permission)?;
            restriction()
        };
        write_restricted(&mut stream,
            &serde_json::json!({"command":"durable_financial_result_v2","schema_version":2,"request":request}),
            deadline.min(Instant::now() + Duration::from_secs(120)), &current, Some(&restriction))?;
        let response: DurablePreviewV2 = read_setup_restricted_observed(
            &stream, &peer, deadline, &current, None, Some(&restriction))?;
        response.request.validate()?;
        response.preview.validate()?;
        if response.version != 2 || response.request != *request
            || response.preview.request != request.request
            || response.preview.result_digest != request.result_digest
            || response.preview.outbox_digest != request.outbox_digest
        { return Err(BridgeError::Binding); }
        restriction()?;
        Ok(Self(PreparedFinancialResultReceiverV1 {
            original_restrictions: Some(OriginalResultRestrictionsV1::awaiting_intake(original)),
            setup_deadline: deadline, provider, peer, stream,
            preview: AuthenticatedFinancialResultPreviewV1 { data: response.preview }, original_deadline,
        }))
    }
    pub fn preview(&self) -> &AuthenticatedFinancialResultPreviewV1 { self.0.preview() }
    pub fn bind_intake_restriction_v2(self, intake: Box<dyn FinancialResultRestrictionV1>) -> Result<Self> {
        Ok(Self(self.0.bind_original_intake_restriction_v1(intake)?))
    }
    pub fn receive(self) -> Result<AuthenticatedDurableFinancialResultLeaseV2> {
        // The private common kernel preserves all physical-I/O current checks;
        // a missing independent intake owner still denies before HostPrepared.
        Ok(AuthenticatedDurableFinancialResultLeaseV2(self.0.receive()?))
    }
}

/// A fresh V2 native Return-backed authenticated result, not a V1 conversion.
pub struct AuthenticatedDurableFinancialResultLeaseV2(AuthenticatedFinancialResultLeaseV1);
impl AuthenticatedDurableFinancialResultLeaseV2 {
    pub fn check_current(&self) -> Result<()> { self.0.check_current() }
    pub fn account_id(&self) -> &str { self.0.account_id() }
    pub fn authorization_id(&self) -> &str { self.0.authorization_id() }
    pub fn original_consent_ref(&self) -> &str { self.0.original_consent_ref() }
    pub fn fixed_identity(&self) -> &FixedProposalIdentityV1 { self.0.fixed_identity() }
    pub fn result_digest(&self) -> &str { self.0.result_digest() }
    pub fn outbox_digest(&self) -> &str { self.0.outbox_digest() }
    pub fn continuation_request(&self) -> &OwnerControlRequest { self.0.continuation_request() }
    pub fn continuation_record(&self) -> &FinancialContinuationRecordV1 { self.0.continuation_record() }
    pub fn outbox_bytes(&self) -> Result<&[u8]> { self.0.outbox_bytes() }
    pub fn finish(self) -> Result<()> { self.0.finish() }
}
mod sealed {
    pub trait ResultEvidence {}
    impl ResultEvidence for super::AuthenticatedFinancialResultLeaseV1 {}
    impl ResultEvidence for super::AuthenticatedDurableFinancialResultLeaseV2 {}
}
/// Public read surface for private Engine kernels. Only the two genuine
/// receiver-owned nominal leases implement it; callers cannot forge evidence.
pub trait AuthenticatedFinancialResultEvidenceV2: sealed::ResultEvidence {
    fn check_current(&self) -> Result<()>;
    fn account_id(&self) -> &str;
    fn authorization_id(&self) -> &str;
    fn original_consent_ref(&self) -> &str;
    fn fixed_identity(&self) -> &FixedProposalIdentityV1;
    fn result_digest(&self) -> &str;
    fn outbox_digest(&self) -> &str;
    fn continuation_request(&self) -> &OwnerControlRequest;
    fn continuation_record(&self) -> &FinancialContinuationRecordV1;
    fn outbox_bytes(&self) -> Result<&[u8]>;
}
macro_rules! result_evidence {
    ($name:ident) => { impl AuthenticatedFinancialResultEvidenceV2 for $name {
        fn check_current(&self) -> Result<()> { $name::check_current(self) }
        fn account_id(&self) -> &str { $name::account_id(self) }
        fn authorization_id(&self) -> &str { $name::authorization_id(self) }
        fn original_consent_ref(&self) -> &str { $name::original_consent_ref(self) }
        fn fixed_identity(&self) -> &FixedProposalIdentityV1 { $name::fixed_identity(self) }
        fn result_digest(&self) -> &str { $name::result_digest(self) }
        fn outbox_digest(&self) -> &str { $name::outbox_digest(self) }
        fn continuation_request(&self) -> &OwnerControlRequest { $name::continuation_request(self) }
        fn continuation_record(&self) -> &FinancialContinuationRecordV1 { $name::continuation_record(self) }
        fn outbox_bytes(&self) -> Result<&[u8]> { $name::outbox_bytes(self) }
    }};
}
result_evidence!(AuthenticatedFinancialResultLeaseV1);
result_evidence!(AuthenticatedDurableFinancialResultLeaseV2);

use crate::account::birth::enrollment::roster_v2::financial_source_v1::{
    RecoveredFinancialResultSourceV2, AuditedFinancialResultSnapshotV2, RecipientBoundFinancialResultV2,
};
use crate::native_ui::durable_result_authority_v2::{DurableFinancialResultReadV2, DurableFinancialResultReturnV2};

pub(crate) struct PreparedDurableFinancialReturnV2 {
    snapshot: AuditedFinancialResultSnapshotV2,
    setup_deadline: Instant,
    evidence: Evidence,
    digest: String,
    review_scope: String,
}
impl PreparedDurableFinancialReturnV2 {
    pub(crate) fn prepare(
        source: Arc<RecoveredFinancialResultSourceV2>, read_owner: DurableFinancialResultReadV2,
        peer: PeerProcess, request: &DurableFinancialResultRequestV2, stream: &mut UnixStream,
    ) -> Result<Self> {
        request.validate()?;
        read_owner.check_scope(source.identity_digest(), request, &peer).map_err(|_| BridgeError::Permission)?;
        let observed = PeerProcess::observe(stream).map_err(|_| BridgeError::Permission)?;
        peer.same_live_process(&observed).map_err(|_| BridgeError::Permission)?;
        let snapshot = source.read_for_return_v2(request, &peer, &read_owner).map_err(|_| BridgeError::Permission)?;
        let (original, result, continuation) = snapshot.evidence_for_preview_v2(&read_owner).map_err(|_| BridgeError::Permission)?;
        let evidence = Evidence::from_retained(original, result, continuation.clone(), &request.request)?;
        if evidence.result_digest != request.result_digest || evidence.outbox_digest != request.outbox_digest
            || evidence.signature_set_digest != snapshot.signature_set_digest()
        { return Err(BridgeError::Binding); }
        let digest = request.return_review_digest(source.identity_digest(), peer.instance(), &evidence.signature_set_digest)?;
        let review_scope = source.review_scope_v2().map_err(|_| BridgeError::Permission)?;
        let setup_deadline = source.original_deadline().min(Instant::now() + Duration::from_secs(900));
        let current = || {
            read_owner.check_scope(source.identity_digest(), request, &peer).map_err(|_| BridgeError::Permission)?;
            snapshot.check_custody_v2().map_err(|_| BridgeError::Permission)?;
            read_owner.check_scope(source.identity_digest(), request, &peer).map_err(|_| BridgeError::Permission)
        };
        current()?;
        write(stream, &DurablePreviewV2 { version: 2, request: request.clone(), preview: PreviewData::from_evidence(&evidence) },
            source.original_deadline().min(Instant::now() + Duration::from_secs(2)), &current)?;
        current()?;
        drop(read_owner);
        Ok(Self { snapshot, setup_deadline, evidence, digest, review_scope })
    }
    pub(crate) fn await_host_prepared(self, stream: &UnixStream) -> Result<Self> {
        let current = || self.snapshot.check_custody_v2().map_err(|_| BridgeError::Permission);
        let expected = PreviewData::from_evidence(&self.evidence).digest()?;
        match read_setup(stream, self.snapshot.peer(), self.setup_deadline.min(self.snapshot.original_deadline()), &current)? {
            Command::HostPrepared { preview_digest } if preview_digest == expected => { current()?; Ok(self) }
            _ => Err(BridgeError::Permission),
        }
    }
    pub(crate) fn reviewed_digest(&self) -> &str { &self.digest }
    pub(crate) fn signature_set_digest(&self) -> &str { &self.evidence.signature_set_digest }
    pub(crate) fn request(&self) -> &DurableFinancialResultRequestV2 { self.snapshot.request() }
    pub(crate) fn source_identity(&self) -> &str { self.snapshot.source_identity_digest() }
    pub(crate) fn peer(&self) -> &PeerProcess { self.snapshot.peer() }
    pub(crate) fn original_deadline(&self) -> Instant { self.snapshot.original_deadline() }
    pub(crate) fn original_ceiling_ms(&self) -> u64 { self.snapshot.original_ceiling_ms() }
    pub(crate) fn display(&self) -> String {
        format!("RETURN COMPLETED EXACT RESULT — DURABLE V2\nAccount: {}\nAuthorization: {}\nOriginal consent: {}\nResult bytes digest: {}\nOutbox bytes digest: {}\nSignature set: {}\nFresh recipient UID: {} PID: {} instance: {} (not a software publisher claim)\nHistorical Host (not current permission): {}\nReturn commitment: {}\nNo signature, reservation, new writer or transaction is created.\nAudited original audience and permission scope:\n{}",
            self.evidence.request.account_id, self.evidence.request.authorization_id, self.evidence.request.original_consent_ref,
            self.evidence.result_digest, self.evidence.outbox_digest, self.evidence.signature_set_digest,
            self.peer().uid(), self.peer().pid(), self.peer().instance(), self.request().original_host_process_instance, self.digest, self.review_scope)
    }
    pub(crate) fn approve(self, action: DurableFinancialResultReturnV2) -> Result<ApprovedDurableFinancialReturnV2> {
        let peer = self.snapshot.peer().clone();
        let bound = self.snapshot.bind_return_v2(action, peer).map_err(|_| BridgeError::Permission)?;
        bound.check_current().map_err(|_| BridgeError::Permission)?;
        Ok(ApprovedDurableFinancialReturnV2 { bound, evidence: self.evidence })
    }
}
pub(crate) struct ApprovedDurableFinancialReturnV2 {
    bound: RecipientBoundFinancialResultV2,
    evidence: Evidence,
}
impl ApprovedDurableFinancialReturnV2 {
    pub(super) fn check(&self) -> Result<()> { self.bound.check_current().map_err(|_| BridgeError::Permission) }
    pub(super) fn peer(&self) -> &PeerProcess { self.bound.peer() }
    pub(super) fn evidence(&self) -> &Evidence { &self.evidence }
    pub(super) fn deadline(&self) -> Result<Instant> { self.bound.original_deadline().map_err(|_| BridgeError::Permission) }
    pub(crate) fn serve(self, stream: UnixStream) -> Result<()> { FinancialReturnSenderV1::Durable(self).serve(stream) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn durable_v2_receiver_constructor_requires_independent_intake() {
        struct OriginalOnly;
        impl FinancialResultRestrictionV1 for OriginalOnly {
            fn check_before_io(&self) -> Result<()> { Ok(()) }
        }
        // A permissive first restriction is NOT enough to receive. This pure
        // predicate fixture creates no provider, peer, grant, stream or lease.
        let pending = OriginalResultRestrictionsV1::awaiting_intake(Box::new(OriginalOnly));
        assert!(matches!(pending.check(), Err(BridgeError::Permission)));
    }
    fn request() -> DurableFinancialResultRequestV2 {
        let mut fixed = FixedProposalIdentityV1 {
            schema_version: 1, network_profile_id: "never-funded-network".into(),
            agreement_id: "never-funded-agreement".into(), obligation_id: "never-funded-obligation".into(),
            proposal_id: "never-funded-proposal".into(), revision: 1, expiry_height: 1,
            proposal_digest: "11".repeat(32), manifest_digest: "22".repeat(32),
            unsigned_artifact_digest: "33".repeat(32), proved_artifact_digest: "44".repeat(32),
            effects_commitment: "55".repeat(32), policy_digest: "66".repeat(32),
            review_binding: "77".repeat(32), action_mapping_digest: "88".repeat(32),
            anchor: "99".repeat(32), proposal_binding: String::new(),
        };
        let mut h = Sha256::new();
        h.update(b"wholepact:durable-fixed-proposal:pczt-0.10.0-pre.1:v1\0");
        for n in [fixed.schema_version, fixed.revision, fixed.expiry_height] { h.update(n.to_le_bytes()); }
        for value in [&fixed.network_profile_id, &fixed.agreement_id, &fixed.obligation_id, &fixed.proposal_id,
            &fixed.proposal_digest, &fixed.manifest_digest, &fixed.unsigned_artifact_digest, &fixed.proved_artifact_digest,
            &fixed.effects_commitment, &fixed.policy_digest, &fixed.review_binding, &fixed.action_mapping_digest, &fixed.anchor]
        { h.update((value.len() as u64).to_le_bytes()); h.update(value.as_bytes()); }
        fixed.proposal_binding = hex::encode(h.finalize());
        DurableFinancialResultRequestV2 {
            version: 2, request: FinancialResultRequestV1 { account_id: "aa".repeat(32), authorization_id: "never-funded-authorization".into(), original_consent_ref: "bb".repeat(32), fixed },
            result_digest: "01".repeat(32), outbox_digest: "02".repeat(32), continuation_request_digest: "03".repeat(32),
            continuation_history_digest: "04".repeat(32), original_delivery_intent_digest: "05".repeat(32),
            original_host_process_instance: "06".repeat(32), original_terms_digest: "07".repeat(32),
        }
    }
    #[test]
    fn durable_v2_selector_is_strict_bounded_and_never_legacy_fallback() {
        let request = request();
        request.validate().unwrap();
        let bytes = serde_json::to_vec(&request).unwrap();
        assert!(DurableFinancialResultRequestV2::parse_exact(&bytes).unwrap() == request);
        for version in [0, 1, 3, u16::MAX] { let mut r = request.clone(); r.version = version; assert!(r.validate().is_err()); }
        let text = String::from_utf8(bytes).unwrap();
        assert!(DurableFinancialResultRequestV2::parse_exact(text.replacen("\"version\":2", "\"version\":2,\"version\":2", 1).as_bytes()).is_err());
        assert!(DurableFinancialResultRequestV2::parse_exact(text.replacen("{", "{\"unexpected\":0,", 1).as_bytes()).is_err());
        assert!(DurableFinancialResultRequestV2::parse_exact(text.replacen("\"account_id\":", "\"account_id\":\"aa\",\"account_id\":", 1).as_bytes()).is_err());
        assert!(DurableFinancialResultRequestV2::parse_exact(&vec![b' '; DURABLE_RESULT_REQUEST_MAX_BYTES_V2 + 1]).is_err());
        assert!(DurableFinancialResultRequestV2::parse_exact(&serde_json::to_vec(&request.request).unwrap()).is_err());
    }
    #[test]
    fn durable_v2_read_and_return_bind_source_peer_and_explicit_signature_set() {
        let r = request(); let source = "a1".repeat(32); let peer = "b1".repeat(32); let sig = "c1".repeat(32);
        let read = r.read_review_digest(&source, &peer).unwrap();
        let ret = r.return_review_digest(&source, &peer, &sig).unwrap();
        assert_ne!(read, ret);
        assert_ne!(read, r.read_review_digest(&"a2".repeat(32), &peer).unwrap());
        assert_ne!(read, r.read_review_digest(&source, &"b2".repeat(32)).unwrap());
        assert_ne!(ret, r.return_review_digest(&"a2".repeat(32), &peer, &sig).unwrap());
        assert_ne!(ret, r.return_review_digest(&source, &"b2".repeat(32), &sig).unwrap());
        assert_ne!(ret, r.return_review_digest(&source, &peer, &"c2".repeat(32)).unwrap());
        for bad in ["", "txid-only", "ZZ"] { assert!(r.return_review_digest(&source, &peer, bad).is_err()); }
    }
    #[test]
    fn durable_v2_all_historical_and_exact_byte_commitments_are_review_bound() {
        let r = request(); let source = "a1".repeat(32); let peer = "b1".repeat(32); let sig = "c1".repeat(32);
        let read = r.read_review_digest(&source, &peer).unwrap(); let ret = r.return_review_digest(&source, &peer, &sig).unwrap();
        for field in ["result_digest", "outbox_digest", "continuation_request_digest", "continuation_history_digest", "original_delivery_intent_digest", "original_host_process_instance", "original_terms_digest"] {
            let mut value = serde_json::to_value(&r).unwrap(); value[field] = serde_json::Value::String("ff".repeat(32));
            let changed: DurableFinancialResultRequestV2 = serde_json::from_value(value).unwrap();
            assert_ne!(read, changed.read_review_digest(&source, &peer).unwrap(), "{field}");
            assert_ne!(ret, changed.return_review_digest(&source, &peer, &sig).unwrap(), "{field}");
        }
    }
}
