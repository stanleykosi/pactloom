//! Inert, purpose-distinct construction transport lineage. No public value in
//! this module is a writer capability, an owner decision, or permission to sign.
use crate::{manual_roster_construction_v3::*, *};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub(crate) const EXPORTER_LABEL: &[u8] = b"EXPORTER-Wholepact-Construction-Transport-v1";
pub const CONSTRUCTION_TRANSPORT_VERSION: u16 = 1;
pub const MAX_CONSTRUCTION_TRANSPORT_COMPONENT_BYTES: usize = 16 * 1024;
pub const MAX_CONSTRUCTION_TRANSPORT_LINEAGE_BYTES: usize = 32 * 1024;
pub const MAX_CONSTRUCTION_TRANSPORT_HISTORY_BYTES: usize = 1024 * 1024;
pub(crate) fn bounded<T: Serialize>(value: &T, limit: usize) -> Result<()> {
    if serde_json::to_vec(value)
        .map_err(|_| AuthorityError::InvalidBinding)?
        .len()
        > limit
    {
        return Err(AuthorityError::Limit);
    }
    Ok(())
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstructionTransportPreauthorizationV1 {
    pub version: u16,
    pub operation_id: String,
    pub account_id: String,
    pub network_profile_id: String,
    pub genesis_digest: String,
    pub policy_digest: String,
    pub original_session: WriterSessionReceipt,
    pub attempt_digest: String,
    pub attempt_sequence: u64,
    pub read_request_digest: String,
    pub read_evidence_digest: String,
    pub plan_approval_digest: String,
    pub invocation_digest: String,
    pub original_caller_binding_digest: String,
    pub original_host_process_commitment: String,
    pub original_native_binding_digest: String,
    pub native_review_digest: String,
    pub nonce: String,
    pub authorized_at_ms: u64,
    pub expires_at_ms: u64,
}
impl ConstructionTransportPreauthorizationV1 {
    pub fn validate(&self) -> Result<()> {
        bounded(self, MAX_CONSTRUCTION_TRANSPORT_COMPONENT_BYTES)?;
        for v in [
            &self.operation_id,
            &self.account_id,
            &self.network_profile_id,
        ] {
            id(v)?;
        }
        for v in [
            &self.genesis_digest,
            &self.policy_digest,
            &self.attempt_digest,
            &self.read_request_digest,
            &self.read_evidence_digest,
            &self.plan_approval_digest,
            &self.invocation_digest,
            &self.original_caller_binding_digest,
            &self.original_host_process_commitment,
            &self.original_native_binding_digest,
            &self.native_review_digest,
            &self.nonce,
            &self.original_session.session_id,
            &self.original_session.writer_certificate_digest,
            &self.original_session.acquired_head.digest,
            &self.original_session.reconciled_head.digest,
            &self.original_session.reconciled_history_digest,
        ] {
            hash(v)?;
        }
        self.original_session.disclosure.validate()?;
        if self.version != 1
            || self.attempt_sequence == 0
            || self.account_id != self.original_session.disclosure.account_id
            || self.network_profile_id != self.original_session.disclosure.network_profile_id
            || self.policy_digest != self.original_session.disclosure.policy_digest
            || self.authorized_at_ms < self.original_session.acquired_at_ms
            || self.expires_at_ms <= self.authorized_at_ms
            || self.expires_at_ms > self.original_session.expires_at_ms
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:construction-transport-preauthorization:v1", self)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedConstructionTransportPreauthorizationV1 {
    pub authorization: ConstructionTransportPreauthorizationV1,
    pub scheme: String,
    pub owner_certificate_der: Vec<u8>,
    pub signature: Vec<u8>,
}
impl SignedConstructionTransportPreauthorizationV1 {
    pub fn verify(&self, owner_pin: &str) -> Result<()> {
        self.authorization.validate()?;
        bounded(self, MAX_CONSTRUCTION_TRANSPORT_COMPONENT_BYTES)?;
        verify_owner_signature(
            owner_pin,
            &self.scheme,
            &self.owner_certificate_der,
            &self.signature,
            &construction_transport_preauthorization_signing_bytes_v1(&self.authorization)?,
        )
    }
    pub fn digest(&self) -> Result<String> {
        self.authorization.validate()?;
        bounded(self, MAX_CONSTRUCTION_TRANSPORT_COMPONENT_BYTES)?;
        digest(
            "wholepact:construction-transport-signed-preauthorization:v1",
            self,
        )
    }
}
pub fn construction_transport_preauthorization_signing_bytes_v1(
    a: &ConstructionTransportPreauthorizationV1,
) -> Result<Vec<u8>> {
    let mut b = b"wholepact:construction-transport-preauthorization-signature:v1\0".to_vec();
    b.extend_from_slice(a.digest()?.as_bytes());
    Ok(b)
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstructionTransportGrantV1 {
    pub version: u16,
    pub operation_id: String,
    pub authorization: SignedConstructionTransportPreauthorizationV1,
    pub expected_head: AuthorityHead,
    pub native_review_digest: String,
    pub granted_at_ms: u64,
}
impl ConstructionTransportGrantV1 {
    pub fn validate(&self) -> Result<()> {
        bounded(self, MAX_CONSTRUCTION_TRANSPORT_COMPONENT_BYTES)?;
        self.authorization.authorization.validate()?;
        id(&self.operation_id)?;
        hash(&self.expected_head.digest)?;
        hash(&self.native_review_digest)?;
        let a = &self.authorization.authorization;
        if self.version != 1
            || self.operation_id
                != format!("construct-transport-grant-{}", self.authorization.digest()?)
            || self.granted_at_ms < a.authorized_at_ms
            || self.granted_at_ms >= a.expires_at_ms
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:construction-transport-grant:v1", self)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingConstructionTransportGrantV1 {
    pub grant: ConstructionTransportGrantV1,
    pub committed_head: AuthorityHead,
}
impl PendingConstructionTransportGrantV1 {
    pub fn validate(&self) -> Result<()> {
        bounded(self, MAX_CONSTRUCTION_TRANSPORT_COMPONENT_BYTES)?;
        self.grant.validate()?;
        hash(&self.committed_head.digest)?;
        if self.grant.expected_head.sequence.checked_add(1) != Some(self.committed_head.sequence) {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:construction-transport-pending-grant:v1", self)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstructionTransportClaimV1 {
    pub version: u16,
    pub operation_id: String,
    pub pending_grant_digest: String,
    /// The committed post-grant head, never the grant's expected pre-append head.
    pub expected_head: AuthorityHead,
    pub credential_id: String,
    pub exporter_commitment: String,
    pub new_caller_binding_digest: String,
    pub new_native_binding_digest: String,
    pub original_host_process_commitment: String,
    pub native_review_digest: String,
    pub claimed_at_ms: u64,
}
impl ConstructionTransportClaimV1 {
    pub fn validate(&self) -> Result<()> {
        bounded(self, MAX_CONSTRUCTION_TRANSPORT_COMPONENT_BYTES)?;
        id(&self.operation_id)?;
        for h in [
            &self.pending_grant_digest,
            &self.expected_head.digest,
            &self.credential_id,
            &self.exporter_commitment,
            &self.new_caller_binding_digest,
            &self.new_native_binding_digest,
            &self.original_host_process_commitment,
            &self.native_review_digest,
        ] {
            hash(h)?;
        }
        if self.version != 1
            || self.operation_id
                != format!("construct-transport-claim-{}", self.pending_grant_digest)
        {
            return Err(AuthorityError::UnsupportedVersion);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:construction-transport-claim:v1", self)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedConstructionTransportClaimV1 {
    pub claim: ConstructionTransportClaimV1,
    pub scheme: String,
    pub owner_certificate_der: Vec<u8>,
    pub signature: Vec<u8>,
}
impl SignedConstructionTransportClaimV1 {
    pub fn verify(&self, owner_pin: &str) -> Result<()> {
        self.claim.validate()?;
        bounded(self, MAX_CONSTRUCTION_TRANSPORT_COMPONENT_BYTES)?;
        verify_owner_signature(
            owner_pin,
            &self.scheme,
            &self.owner_certificate_der,
            &self.signature,
            &construction_transport_claim_signing_bytes_v1(&self.claim)?,
        )
    }
    pub fn digest(&self) -> Result<String> {
        self.claim.validate()?;
        bounded(self, MAX_CONSTRUCTION_TRANSPORT_COMPONENT_BYTES)?;
        digest("wholepact:construction-transport-signed-claim:v1", self)
    }
}
pub fn construction_transport_claim_signing_bytes_v1(
    c: &ConstructionTransportClaimV1,
) -> Result<Vec<u8>> {
    let mut b = b"wholepact:construction-transport-claim-signature:v1\0".to_vec();
    b.extend_from_slice(c.digest()?.as_bytes());
    Ok(b)
}
fn verify_owner_signature(
    pin: &str,
    scheme: &str,
    certificate: &[u8],
    signature: &[u8],
    bytes: &[u8],
) -> Result<()> {
    hash(pin)?;
    if scheme != "ecdsa-p256-sha256-asn1-v1"
        || certificate.is_empty()
        || certificate.len() > 12 * 1024
        || signature.is_empty()
        || signature.len() > 80
    {
        return Err(AuthorityError::InvalidBinding);
    }
    let cert = rustls::pki_types::CertificateDer::from(certificate);
    if crate::transport::certificate_digest(&cert) != pin {
        return Err(AuthorityError::Permission);
    }
    #[cfg(feature = "pending-birth-foundation")]
    {
        webpki::EndEntityCert::try_from(&cert)
            .map_err(|_| AuthorityError::InvalidBinding)?
            .verify_signature(webpki::ring::ECDSA_P256_SHA256, bytes, signature)
            .map_err(|_| AuthorityError::Permission)?;
        Ok(())
    }
    #[cfg(not(feature = "pending-birth-foundation"))]
    {
        let _ = bytes;
        Err(AuthorityError::ConstructionHistoryUnsupported)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstructionTransportCredentialV1 {
    pub pending_grant: PendingConstructionTransportGrantV1,
    pub signed_claim: SignedConstructionTransportClaimV1,
    pub claimed_head: AuthorityHead,
    pub old_key_fence_digest: String,
}
impl ConstructionTransportCredentialV1 {
    pub fn credential_id(&self) -> &str {
        &self.signed_claim.claim.credential_id
    }
    pub fn authorization(&self) -> &ConstructionTransportPreauthorizationV1 {
        &self.pending_grant.grant.authorization.authorization
    }
    pub fn validate(&self) -> Result<()> {
        bounded(self, MAX_CONSTRUCTION_TRANSPORT_LINEAGE_BYTES)?;
        self.pending_grant.validate()?;
        self.signed_claim.claim.validate()?;
        hash(&self.claimed_head.digest)?;
        hash(&self.old_key_fence_digest)?;
        let c = &self.signed_claim.claim;
        let a = self.authorization();
        if c.pending_grant_digest != self.pending_grant.digest()?
            || c.expected_head != self.pending_grant.committed_head
            || c.expected_head.sequence.checked_add(1) != Some(self.claimed_head.sequence)
            || c.new_caller_binding_digest == a.original_caller_binding_digest
            || c.new_native_binding_digest == a.original_native_binding_digest
            || c.original_host_process_commitment != a.original_host_process_commitment
            || c.claimed_at_ms < self.pending_grant.grant.granted_at_ms
            || c.claimed_at_ms >= a.expires_at_ms
            || self.old_key_fence_digest
                != old_key_fence_digest(a, &self.signed_claim, &self.claimed_head)?
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:construction-transport-credential:v1", self)
    }
}
pub(crate) fn old_key_fence_digest(
    a: &ConstructionTransportPreauthorizationV1,
    c: &SignedConstructionTransportClaimV1,
    head: &AuthorityHead,
) -> Result<String> {
    digest(
        "wholepact:construction-transport-old-key-fence:v1",
        &(
            &a.original_session.session_id,
            a.digest()?,
            c.digest()?,
            head,
        ),
    )
}
/// This required extension appears once the protocol has entered account history.
/// Older deny-unknown-fields readers reject it rather than infer an unfenced key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstructionTransportFenceSnapshotV1 {
    pub version: u16,
    pub fenced_session_ids: BTreeSet<String>,
}
impl AccountSnapshot {
    pub fn require_unfenced_transport(&self, session_id: &str) -> Result<()> {
        hash(session_id)?;
        if let Some(s) = &self.transport_fences {
            if s.version != 1 {
                return Err(AuthorityError::UnsupportedVersion);
            }
            for v in &s.fenced_session_ids {
                hash(v)?;
            }
            if s.fenced_session_ids.contains(session_id) {
                return Err(AuthorityError::SessionRequired);
            }
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "operation",
    content = "request",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ConstructionTransportMutationV1 {
    Reserve(Box<ManualRosterConstructionReservationRequestV3>),
    Consume(Box<ManualRosterConstructionConsumeRequestV3>),
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstructionTransportRequestV1 {
    pub version: u16,
    pub credential_id: String,
    pub mutation: ConstructionTransportMutationV1,
}
impl ConstructionTransportRequestV1 {
    pub fn operation_id(&self) -> &str {
        match &self.mutation {
            ConstructionTransportMutationV1::Reserve(r) => &r.construction.operation_id,
            ConstructionTransportMutationV1::Consume(r) => &r.operation_id,
        }
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstructionTransportReservationRecordV1 {
    pub credential_id: String,
    pub original: ManualRosterConstructionReservationRecordV3,
    pub extension: crate::manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2,
    pub continuation: crate::manual_roster_witness_v2::ManualRosterSessionContinuationV2,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstructionTransportConsumedRecordV1 {
    pub credential_id: String,
    pub original: ManualRosterConstructionConsumedRecordV3,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstructionTransportObservationV1 {
    pub version: u16,
    pub credential: ConstructionTransportCredentialV1,
    pub snapshot: AccountSnapshot,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstructionTransportProofV1 {
    pub credential_id: String,
    pub tag: String,
}
pub fn credential_id(exporter: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(b"wholepact:construction-transport-credential-id:v1\0");
    h.update(exporter);
    hex::encode(h.finalize())
}
pub fn exporter_commitment(exporter: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(b"wholepact:construction-transport-exporter:v1\0");
    h.update(exporter);
    hex::encode(h.finalize())
}
fn proof_bytes<T: Serialize>(
    credential: &str,
    exporter: &[u8; 32],
    operation: &T,
) -> Result<Zeroizing<Vec<u8>>> {
    hash(credential)?;
    encode(&(
        "wholepact:construction-transport-channel-proof:v1",
        1u16,
        credential,
        exporter_commitment(exporter),
        operation,
    ))
}
pub(crate) fn proof(
    key: &[u8; 32],
    exporter: &[u8; 32],
    r: &ConstructionTransportRequestV1,
) -> Result<ConstructionTransportProofV1> {
    make_proof(key, exporter, &r.credential_id, &("mutate", r))
}
pub(crate) fn observe_proof(
    key: &[u8; 32],
    exporter: &[u8; 32],
    id: &str,
) -> Result<ConstructionTransportProofV1> {
    make_proof(key, exporter, id, &("observe", id))
}
fn make_proof<T: Serialize>(
    key: &[u8; 32],
    exporter: &[u8; 32],
    id: &str,
    r: &T,
) -> Result<ConstructionTransportProofV1> {
    if credential_id(key) != id {
        return Err(AuthorityError::Authentication);
    }
    let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    let tag = ring::hmac::sign(&k, &proof_bytes(id, exporter, r)?);
    Ok(ConstructionTransportProofV1 {
        credential_id: id.into(),
        tag: hex::encode(tag.as_ref()),
    })
}
pub(crate) fn verify_proof(
    key: &[u8; 32],
    exporter: &[u8; 32],
    r: &ConstructionTransportRequestV1,
    p: &ConstructionTransportProofV1,
) -> Result<()> {
    verify_tag(key, exporter, &r.credential_id, &("mutate", r), p)
}
pub(crate) fn verify_observe_proof(
    key: &[u8; 32],
    exporter: &[u8; 32],
    id: &str,
    p: &ConstructionTransportProofV1,
) -> Result<()> {
    verify_tag(key, exporter, id, &("observe", id), p)
}
fn verify_tag<T: Serialize>(
    key: &[u8; 32],
    exporter: &[u8; 32],
    id: &str,
    r: &T,
    p: &ConstructionTransportProofV1,
) -> Result<()> {
    hash(&p.tag)?;
    if p.credential_id != id || credential_id(key) != id {
        return Err(AuthorityError::Authentication);
    }
    let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    let tag = hex::decode(&p.tag).map_err(|_| AuthorityError::Authentication)?;
    ring::hmac::verify(&k, &proof_bytes(id, exporter, r)?, &tag)
        .map_err(|_| AuthorityError::Authentication)
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ConstructionTransportHistoryV1 {
    pub version: u16,
    pub grants: Vec<PendingConstructionTransportGrantV1>,
    pub credentials: Vec<ConstructionTransportCredentialV1>,
    pub reservations: Vec<ConstructionTransportReservationRecordV1>,
    pub consumptions: Vec<ConstructionTransportConsumedRecordV1>,
}
impl ConstructionTransportHistoryV1 {
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
            && self.credentials.is_empty()
            && self.reservations.is_empty()
            && self.consumptions.is_empty()
    }
    pub fn digest(&self) -> Result<String> {
        bounded(self, MAX_CONSTRUCTION_TRANSPORT_HISTORY_BYTES)?;
        digest("wholepact:construction-transport-history:v1", self)
    }
}

/// Explicit new complete envelope. The legacy subrecord is a partial typed
/// projection only inside this required wrapper; it cannot escape as an old
/// complete-history capability when transport lineage exists.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstructionHistoryWithTransportV1 {
    pub version: u16,
    pub original: crate::construction_history_v2::ConstructionHistoryV2,
    pub transport: ConstructionTransportHistoryV1,
}
impl ConstructionHistoryWithTransportV1 {
    pub fn observed_snapshot(&self) -> &AccountSnapshot {
        self.original.observed_snapshot()
    }
    pub fn retained_debit_zatoshis(&self) -> Result<u64> {
        self.transport.reservations.iter().try_fold(
            self.original.retained_debit_zatoshis()?,
            |n, r| {
                n.checked_add(r.original.reserved_debit_zatoshis)
                    .ok_or(AuthorityError::Limit)
            },
        )
    }
    pub fn retained_input_value_zatoshis(&self) -> Result<u64> {
        self.transport.reservations.iter().try_fold(
            self.original.retained_input_value_zatoshis()?,
            |n, r| {
                n.checked_add(r.original.reserved_input_value_zatoshis)
                    .ok_or(AuthorityError::Limit)
            },
        )
    }
    pub fn conservative_obligations(&self) -> BTreeSet<String> {
        let mut v = self.original.conservative_obligations();
        for r in &self.transport.reservations {
            v.insert(r.original.request.enrollment().scope.obligation_id.clone());
        }
        v
    }
    pub fn validate(&self) -> Result<()> {
        bounded(self, MAX_CONSTRUCTION_TRANSPORT_HISTORY_BYTES)?;
        self.original.validate_projection()?;
        if self.version != 1 {
            return Err(AuthorityError::UnsupportedVersion);
        }
        if self.transport.is_empty() {
            if self.transport.version != 1 || self.observed_snapshot().transport_fences.is_some() {
                return Err(AuthorityError::InvalidBinding);
            }
            return Ok(());
        }
        let birth = self
            .original
            .original_birth()
            .ok_or(AuthorityError::InvalidBinding)?;
        self.transport
            .validate_for(&birth.request.policy, self.observed_snapshot())?;
        let mut operations: BTreeSet<&str> = self
            .original
            .origins()
            .iter()
            .map(|o| o.operation_id())
            .collect();
        let mut keys: BTreeSet<&str> = self
            .original
            .origins()
            .iter()
            .map(|o| o.original_key_digest())
            .collect();
        for r in &self.transport.reservations {
            r.extension.validate_original_birth(birth)?;
            let key = &r
                .original
                .request
                .construction
                .plan
                .retained
                .selection
                .scope
                .selection
                .invocation
                .idempotency_key_digest;
            if !operations.insert(&r.original.request.construction.operation_id)
                || !keys.insert(key)
            {
                return Err(AuthorityError::InvalidBinding);
            }
            let c = self
                .transport
                .credentials
                .iter()
                .find(|c| c.credential_id() == r.credential_id)
                .ok_or(AuthorityError::InvalidBinding)?;
            let mut approvals=self.original.approvals().iter().filter_map(|v|match v{
                crate::construction_history_v2::ConstructionApprovalHistoryV2::CommonContextV3{extension,record} if extension.as_ref()==&r.extension=>Some(record.as_ref()),_=>None
            }).filter(|v|v.approval.plan==r.original.request.construction.plan);
            let approval = approvals.next().ok_or(AuthorityError::InvalidBinding)?;
            if approvals.next().is_some()
                || approval.approval.digest_for(&r.extension)?
                    != c.authorization().plan_approval_digest
            {
                return Err(AuthorityError::InvalidBinding);
            }
        }
        // Grant/claim-only lineages also retain and authenticate the original
        // approved full plan even when no local Reserve was ever recorded.
        for g in &self.transport.grants {
            let a = &g.grant.authorization.authorization;
            let mut matches = 0;
            for v in self.original.approvals() {
                if let crate::construction_history_v2::ConstructionApprovalHistoryV2::CommonContextV3{extension,record}=v{
                if record.approval.digest_for(extension)?==a.plan_approval_digest&&record.approval.plan.invocation_digest().map_err(|_|AuthorityError::InvalidBinding)?==a.invocation_digest{matches+=1;}
            }
            }
            if matches != 1 {
                return Err(AuthorityError::InvalidBinding);
            }
        }
        let s = self.observed_snapshot();
        if self.retained_debit_zatoshis()? > s.outstanding_debit_zatoshis
            || self.retained_input_value_zatoshis()? > s.reserved_input_value_zatoshis
            || self.original.origins().len() + self.transport.reservations.len()
                > s.outstanding_reservations as usize
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:construction-history-with-transport:v1", self)
    }
}
impl ReconciledAuthorityHistory {
    pub fn construction_history_with_transport_v1(
        &self,
    ) -> Result<ConstructionHistoryWithTransportV1> {
        let h = ConstructionHistoryWithTransportV1 {
            version: 1,
            original: self.construction_history_v2_projection()?,
            transport: self.construction_transport_history_v1()?,
        };
        h.validate()?;
        Ok(h)
    }
}

#[cfg(all(test, feature = "pending-birth-foundation", target_os = "linux"))]
#[path = "construction_transport_handoff_tests_v1.rs"]
pub(crate) mod tests;
