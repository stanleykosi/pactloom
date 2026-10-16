//! Wire lookup/request data and authenticated delivery metadata, never an issuer.
use crate::{offline::ReserveOfflineAuthorization, *};
use serde::{Deserialize, Serialize};

// Keep this dedicated route inside the existing bounded authority frame. JSON
// and request metadata consume the remaining half; encode() checks the full frame.
/// Inert size limit for the dedicated configured-witness submission route.
/// A fitting ciphertext is not authenticated and does not imply the complete
/// request fits its separately enforced MAX_FRAME_BYTES wire limit.
pub const MAX_OFFLINE_INTENT_CIPHERTEXT_BYTES_V1: usize = MAX_FRAME_BYTES / 4;
pub(crate) const MAX_ENVELOPE_HEX: usize = MAX_OFFLINE_INTENT_CIPHERTEXT_BYTES_V1 * 2;

/// Pure preflight using the actual dedicated wire encoding and fixed-width proof
/// fields. Success proves only structural size compatibility, never ownership,
/// HPKE authentication, enrollment, availability or permission to submit.
pub fn validate_offline_intent_delivery_size_v1(
    request: &ReserveOfflineAuthorization,
    original_envelope: &[u8],
    export_template: &OfflineAdmissionExportPlan,
) -> Result<()> {
    if original_envelope.is_empty()
        || original_envelope.len() > MAX_OFFLINE_INTENT_CIPHERTEXT_BYTES_V1
    {
        return Err(AuthorityError::Limit);
    }
    let wire = OfflineWitnessRequestV1 {
        request: request.clone(),
        original_envelope_hex: hex::encode(original_envelope),
        export_template: export_template.clone(),
        // Actual session IDs are SHA-256 digests and tags are HMAC-SHA256 hex.
        // These inert placeholders are never returned, sent or verified.
        proof: protocol::WriterSessionProof {
            session_id: "0".repeat(64),
            tag: "0".repeat(64),
        },
    };
    wire.record()?;
    encode(&protocol::WireRequest::SubmitOfflineIntentV1(Box::new(
        wire,
    )))
    .map(|_| ())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OfflineWitnessRequestV1 {
    pub request: ReserveOfflineAuthorization,
    pub original_envelope_hex: String,
    pub export_template: OfflineAdmissionExportPlan,
    pub proof: protocol::WriterSessionProof,
}
impl OfflineWitnessRequestV1 {
    pub(crate) fn envelope(&self) -> Result<Vec<u8>> {
        decode_ciphertext(&self.original_envelope_hex)
    }
    pub(crate) fn record(&self) -> Result<OfflineReservationRecord> {
        self.request.validate()?;
        if self.export_template.sequence != 0 {
            return Err(AuthorityError::InvalidBinding);
        }
        let mut allocated = self.export_template.clone();
        allocated.sequence = 1;
        allocated.validate()?;
        let envelope = self.envelope()?;
        let mut digest = Sha256::new();
        digest.update(b"wholepact.encrypted-envelope.v1\0");
        digest.update(&envelope);
        Ok(OfflineReservationRecord {
            request: self.request.clone(),
            authentication: OfflineIntentAuthenticationRecord {
                intent_digest: self.request.intent.intent_digest()?,
                reservation_request_digest: self.request.request_digest()?,
                policy_digest: self.request.intent.terms.offline_policy_digest.clone(),
                sender_fingerprint: self.request.intent.terms.offline_signer_key_digest.clone(),
                witness_fingerprint: self.export_template.sender_key_fingerprint.clone(),
                envelope_digest: hex::encode(digest.finalize()),
            },
        })
    }
}

/// Original lookup expectations only. Incoming values cannot enroll a policy or
/// replace the server's retained original. This type carries no financial power.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineAdmissionDeliveryLookupV1 {
    pub account_id: String,
    pub network_profile_id: String,
    pub operation_id: String,
    pub original_request_digest: String,
    pub original_intent_digest: String,
    pub offline_policy_digest: String,
}
impl OfflineAdmissionDeliveryLookupV1 {
    pub fn from_request(request: &ReserveOfflineAuthorization) -> Result<Self> {
        request.validate()?;
        Ok(Self {
            account_id: request.intent.terms.account_id.clone(),
            network_profile_id: request.intent.terms.network_profile_id.clone(),
            operation_id: request.operation_id.clone(),
            original_request_digest: request.request_digest()?,
            original_intent_digest: request.intent.intent_digest()?,
            offline_policy_digest: request.intent.terms.offline_policy_digest.clone(),
        })
    }
    pub(crate) fn validate(&self) -> Result<()> {
        for value in [
            &self.account_id,
            &self.network_profile_id,
            &self.operation_id,
        ] {
            id(value)?;
        }
        for value in [
            &self.original_request_digest,
            &self.original_intent_digest,
            &self.offline_policy_digest,
        ] {
            hash(value)?;
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OfflineWitnessDeliveryBodyV1 {
    pub schema_version: u16,
    pub original: OfflineAdmissionDeliveryLookupV1,
    pub authorization_id: String,
    pub witness_id: String,
    pub witness_account_policy_digest: String,
    pub original_admission_digest: String,
    pub export_plan: OfflineAdmissionExportPlan,
    pub committed_head: AuthorityHead,
    pub reserved_at_ms: u64,
    pub admission_expires_at_ms: u64,
    pub ciphertext_hex: String,
    pub recovered_original: bool,
}
impl OfflineWitnessDeliveryBodyV1 {
    pub(crate) fn validate(&self) -> Result<Vec<u8>> {
        if self.schema_version != 1
            || self.reserved_at_ms == 0
            || self.reserved_at_ms >= self.admission_expires_at_ms
            || self.admission_expires_at_ms > i64::MAX as u64
            || self.committed_head.sequence == 0
            || self.committed_head.sequence > MAX_EVENTS
        {
            return Err(AuthorityError::InvalidBinding);
        }
        self.original.validate()?;
        id(&self.authorization_id)?;
        id(&self.witness_id)?;
        for value in [
            &self.witness_account_policy_digest,
            &self.original_admission_digest,
            &self.committed_head.digest,
        ] {
            hash(value)?;
        }
        self.export_plan.validate()?;
        decode_ciphertext(&self.ciphertext_hex)
    }
}

/// Bytes and immutable metadata received from the configured authenticated
/// witness. The recipient must independently decrypt, pin the complete original,
/// check its selected assurance, native consent and current validity. No signing
/// capability, plaintext account totals or reusable writer credential is returned.
/// ```compile_fail
/// use wholepact_authority::OfflineAdmissionDeliveryV1;
/// let _ = serde_json::from_str::<OfflineAdmissionDeliveryV1>("{}");
/// ```
pub struct OfflineAdmissionDeliveryV1 {
    pub(crate) body: OfflineWitnessDeliveryBodyV1,
    pub(crate) ciphertext: Vec<u8>,
}
impl OfflineAdmissionDeliveryV1 {
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
    pub fn original(&self) -> &OfflineAdmissionDeliveryLookupV1 {
        &self.body.original
    }
    pub fn export_plan(&self) -> &OfflineAdmissionExportPlan {
        &self.body.export_plan
    }
    pub fn committed_head(&self) -> &AuthorityHead {
        &self.body.committed_head
    }
    pub fn original_admission_digest(&self) -> &str {
        &self.body.original_admission_digest
    }
    pub fn reserved_at_ms(&self) -> u64 {
        self.body.reserved_at_ms
    }
    pub fn admission_expires_at_ms(&self) -> u64 {
        self.body.admission_expires_at_ms
    }
    pub fn recovered_original(&self) -> bool {
        self.body.recovered_original
    }
    pub fn signing_authority(&self) -> bool {
        false
    }
}

pub(crate) fn decode_ciphertext(value: &str) -> Result<Vec<u8>> {
    if value.is_empty()
        || value.len() > MAX_ENVELOPE_HEX
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(AuthorityError::InvalidBinding);
    }
    hex::decode(value).map_err(|_| AuthorityError::InvalidBinding)
}

/// Concrete process-local current-time bound for the configured owner only.
/// It is never serialized, returned, renewed, or accepted as financial authority.
pub(crate) struct CurrentOfflineWitnessWindowV1 {
    first_wall_ms: u64,
    not_before_ms: u64,
    expires_at_ms: u64,
    ceiling: std::time::Instant,
}
impl CurrentOfflineWitnessWindowV1 {
    #[cfg(all(feature = "offline-witness-owner", target_os = "linux"))]
    pub(crate) fn capture(
        not_before_ms: u64,
        expires_at_ms: u64,
        deadline: std::time::Instant,
    ) -> Result<Self> {
        let started = std::time::Instant::now();
        let wall = now_ms()?;
        if wall < not_before_ms || wall >= expires_at_ms {
            return Err(AuthorityError::Expired);
        }
        let ceiling = started
            .checked_add(std::time::Duration::from_millis(expires_at_ms - wall))
            .ok_or(AuthorityError::Expired)?
            .min(deadline);
        let value = Self {
            first_wall_ms: wall,
            not_before_ms,
            expires_at_ms,
            ceiling,
        };
        value.check()?;
        Ok(value)
    }
    #[cfg(all(feature = "offline-witness-owner", target_os = "linux"))]
    pub(crate) fn ceiling(&self) -> std::time::Instant {
        self.ceiling
    }
    #[cfg(all(feature = "offline-witness-owner", target_os = "linux"))]
    pub(crate) fn first_wall_ms(&self) -> u64 {
        self.first_wall_ms
    }
    pub(crate) fn check_after_replay(
        &self,
        ledger: &crate::policy::Ledger,
        request: &ReserveOfflineAuthorization,
    ) -> Result<()> {
        let policy = ledger
            .offline_policies
            .get(&request.intent.terms.offline_policy_digest)
            .ok_or(AuthorityError::PolicyDenied)?;
        let session = ledger
            .snapshot
            .active_writer_session
            .as_ref()
            .ok_or(AuthorityError::SessionRequired)?;
        // The final sample follows all journal replay and policy traversal. This
        // is a precommit decision bound, not a claim about fsync completion time.
        let now = self.check()?;
        if now >= session.expires_at_ms
            || now >= ledger.policy.policy_expires_at_ms
            || now < policy.valid_from_ms
            || now >= policy.expires_at_ms
        {
            return Err(AuthorityError::Expired);
        }
        Ok(())
    }
    pub(crate) fn check(&self) -> Result<u64> {
        let wall = now_ms()?;
        if std::time::Instant::now() >= self.ceiling
            || wall < self.first_wall_ms
            || wall < self.not_before_ms
            || wall >= self.expires_at_ms
        {
            return Err(AuthorityError::Expired);
        }
        Ok(wall)
    }
}

#[cfg(test)]
#[path = "offline_intent_size_v1_tests.rs"]
mod size_tests;
