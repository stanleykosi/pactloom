//! Purpose-distinct inert born courier format. It carries no approval, writer
//! secret, peer viewing key or signing authority. No legacy conversion exists.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use wholepact_authority::{
    OfflineAdmissionExportPlan, born_offline_admission_v1::BornOfflineReservationRequestV1,
};

pub(crate) const MAX_BORN_INTENT_HANDOFF_BYTES_V1: usize = 2 * 1024 * 1024;
const FORMAT: &str = "wholepact.born-offline-intent-handoff.v1";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BornIntentHandoffV1 {
    format: String,
    version: u16,
    request: BornOfflineReservationRequestV1,
    admission_export_template: OfflineAdmissionExportPlan,
    encrypted_intent_base64: String,
}
impl BornIntentHandoffV1 {
    pub(super) fn from_original(
        original: &NamedRecipientOriginalRecordV1,
        encrypted: &[u8],
    ) -> ImportResult<Self> {
        let origin = original
            .born_origin
            .as_ref()
            .ok_or(TransportError::WrongContext)?;
        if origin.request.reservation != original.reservation_request {
            return Err(TransportError::WrongContext);
        }
        let result = Self {
            format: FORMAT.into(),
            version: 1,
            request: origin.request.clone(),
            admission_export_template: original.admission_export_template.clone(),
            encrypted_intent_base64: STANDARD_NO_PAD.encode(encrypted),
        };
        result.validate()?;
        Ok(result)
    }
    pub(crate) fn parse(bytes: &[u8]) -> ImportResult<Self> {
        if bytes.is_empty() || bytes.len() > MAX_BORN_INTENT_HANDOFF_BYTES_V1 {
            return Err(TransportError::ResourceLimit);
        }
        let result: Self =
            wholepact_core::parse_typed_json(bytes).map_err(|_| TransportError::Malformed)?;
        result.validate()?;
        if result.canonical_bytes()?.as_slice() != bytes {
            return Err(TransportError::Malformed);
        }
        Ok(result)
    }
    fn validate(&self) -> ImportResult<()> {
        if self.format != FORMAT || self.version != 1 {
            return Err(TransportError::UnsupportedVersion);
        }
        self.request
            .validate()
            .map_err(|_| TransportError::WrongContext)?;
        let encrypted = self.encrypted_intent()?;
        wholepact_authority::validate_born_offline_intent_delivery_size_v1(
            &self.request,
            &encrypted,
            &self.admission_export_template,
        )
        .map_err(|_| TransportError::WrongContext)?;
        EncryptedEnvelope::from_bytes(encrypted)?;
        let r = &self.request.reservation;
        let plan = &self.admission_export_template;
        let milliseconds = |v: i64| {
            u64::try_from(v)
                .ok()
                .and_then(|s| s.checked_mul(1000))
                .ok_or(TransportError::InvalidTime)
        };
        if plan.sequence != 0
            || milliseconds(plan.issued_at_unix_seconds)? < r.requested_at_ms
            || milliseconds(plan.expires_at_unix_seconds)? > r.admission_expires_at_ms
            || plan.sender_id
                != format!("offline-admission:{}", r.intent.terms.offline_policy_digest)
            || plan.recipient_id
                != format!(
                    "offline-admission:{}",
                    r.intent.terms.offline_signer_key_digest
                )
            || plan.recipient_key_fingerprint != r.intent.terms.offline_signer_key_digest
        {
            return Err(TransportError::WrongContext);
        }
        Ok(())
    }
    pub(crate) fn canonical_bytes(&self) -> ImportResult<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| TransportError::Malformed)?;
        if bytes.len() > MAX_BORN_INTENT_HANDOFF_BYTES_V1 {
            return Err(TransportError::ResourceLimit);
        }
        Ok(bytes)
    }
    pub(crate) fn commitment(&self) -> ImportResult<String> {
        let mut h = Sha256::new();
        h.update(b"wholepact:born-offline-intent-handoff:v1\0");
        h.update(self.canonical_bytes()?);
        Ok(hex::encode(h.finalize()))
    }
    pub(super) fn require_exact_retained(&self, retained: &Self) -> ImportResult<()> {
        if self.canonical_bytes()? != retained.canonical_bytes()? {
            return Err(TransportError::WrongContext);
        }
        Ok(())
    }
    pub(crate) fn request(&self) -> &BornOfflineReservationRequestV1 {
        &self.request
    }
    pub(crate) fn admission_export_template(&self) -> &OfflineAdmissionExportPlan {
        &self.admission_export_template
    }
    pub(crate) fn encrypted_intent(&self) -> ImportResult<Vec<u8>> {
        let max = wholepact_authority::MAX_OFFLINE_INTENT_CIPHERTEXT_BYTES_V1;
        if self.encrypted_intent_base64.is_empty()
            || self.encrypted_intent_base64.len() > max.div_ceil(3) * 4
        {
            return Err(TransportError::ResourceLimit);
        }
        let bytes = STANDARD_NO_PAD
            .decode(&self.encrypted_intent_base64)
            .map_err(|_| TransportError::Malformed)?;
        if bytes.is_empty()
            || bytes.len() > max
            || STANDARD_NO_PAD.encode(&bytes) != self.encrypted_intent_base64
        {
            return Err(TransportError::Malformed);
        }
        Ok(bytes)
    }
}

/// Private exact-format dispatch, never a born→legacy conversion.
pub(super) enum ExactIntentHandoff {
    Legacy(OfflineIntentHandoffV1),
    Born(BornIntentHandoffV1),
}
impl ExactIntentHandoff {
    pub(super) fn from_original(
        original: &NamedRecipientOriginalRecordV1,
        encrypted: &[u8],
    ) -> ImportResult<Self> {
        match &original.born_origin {
            None => Ok(Self::Legacy(OfflineIntentHandoffV1::from_untrusted_parts(
                original.reservation_request.clone(),
                original.admission_export_template.clone(),
                encrypted,
            )?)),
            Some(_) => Ok(Self::Born(BornIntentHandoffV1::from_original(
                original, encrypted,
            )?)),
        }
    }
    pub(super) fn canonical_bytes(&self) -> ImportResult<Vec<u8>> {
        match self {
            Self::Legacy(h) => h.canonical_bytes(),
            Self::Born(h) => h.canonical_bytes(),
        }
    }
    pub(super) fn commitment(&self) -> ImportResult<String> {
        match self {
            Self::Legacy(h) => h.commitment(),
            Self::Born(h) => h.commitment(),
        }
    }
    pub(super) fn request_display(&self) -> ImportResult<String> {
        match self {
            Self::Legacy(h) => serde_json::to_string_pretty(h.request()),
            Self::Born(h) => serde_json::to_string_pretty(h.request()),
        }
        .map_err(|_| TransportError::Malformed)
    }
    pub(super) fn reply_display(&self) -> ImportResult<String> {
        match self {
            Self::Legacy(h) => serde_json::to_string_pretty(h.admission_export_template()),
            Self::Born(h) => serde_json::to_string_pretty(h.admission_export_template()),
        }
        .map_err(|_| TransportError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn inert_fixture() -> BornIntentHandoffV1 {
        // Public synthetic DTO and deliberately unauthenticated outer bytes.
        // No witness, encryption, native decision, wallet or key use occurs.
        let (admission, policy, _) =
            crate::consent_journal::offline_history::tests::full_admission();
        let request = BornOfflineReservationRequestV1 {
            version: 1,
            enrollment_digest: "a".repeat(64),
            artifact_binding_digest: "b".repeat(64),
            construction_link:
                wholepact_authority::born_offline_construction_v1::BornOfflineConstructionLinkV1 {
                    version: 1,
                    reservation_operation_id: "synthetic-reserve".into(),
                    reservation_digest: "1".repeat(64),
                    consume_operation_id: "synthetic-consume".into(),
                    consume_digest: "2".repeat(64),
                    plan_digest: "3".repeat(64),
                    common_context_digest: "4".repeat(64),
                    invocation_digest: "5".repeat(64),
                    checkpoint_origin_digest: "6".repeat(64),
                },
            reservation: admission.request,
        };
        let t = &request.reservation.intent.terms;
        let plan = OfflineAdmissionExportPlan {
            message_id: "21".repeat(16),
            sequence: 0,
            issued_at_unix_seconds: 2,
            expires_at_unix_seconds: 30,
            purpose: "Synthetic born courier formatter".into(),
            persistence_warning: "Inert untrusted format, not authentication".into(),
            sender_id: format!("offline-admission:{}", t.offline_policy_digest),
            recipient_id: format!("offline-admission:{}", t.offline_signer_key_digest),
            sender_key_fingerprint: policy.witness_transport_key_digest,
            recipient_key_fingerprint: t.offline_signer_key_digest.clone(),
        };
        let bytes=serde_json::to_vec(&serde_json::json!({"schema_version":1,"suite":"HPKE-Auth-X25519-HKDF-SHA256-ChaCha20Poly1305","encapsulated_key":"11".repeat(32),"ciphertext":"AA"})).unwrap();
        BornIntentHandoffV1 {
            format: FORMAT.into(),
            version: 1,
            request,
            admission_export_template: plan,
            encrypted_intent_base64: STANDARD_NO_PAD.encode(bytes),
        }
    }
    #[test]
    fn born_courier_format_is_canonical_purpose_distinct_and_keeps_exact_original() {
        let h = inert_fixture();
        let bytes = h.canonical_bytes().unwrap();
        let parsed = BornIntentHandoffV1::parse(&bytes).unwrap();
        assert!(parsed.request() == h.request());
        assert_eq!(parsed.commitment().unwrap(), h.commitment().unwrap());
        assert!(OfflineIntentHandoffV1::parse(&bytes).is_err());
        let legacy = OfflineIntentHandoffV1::from_untrusted_parts(
            h.request.reservation.clone(),
            h.admission_export_template.clone(),
            &h.encrypted_intent().unwrap(),
        )
        .unwrap();
        assert!(BornIntentHandoffV1::parse(&legacy.canonical_bytes().unwrap()).is_err());
        assert!(BornIntentHandoffV1::parse(&serde_json::to_vec_pretty(&h).unwrap()).is_err());
        let mut json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        json["trusted"] = true.into();
        assert!(BornIntentHandoffV1::parse(&serde_json::to_vec(&json).unwrap()).is_err());
    }
    #[test]
    fn canonical_draft_cannot_replace_the_retained_request_or_ciphertext() {
        let original = inert_fixture();
        let bytes = original.canonical_bytes().unwrap();
        let mut changed = BornIntentHandoffV1::parse(&bytes).unwrap();
        changed.request.reservation.operation_id = "changed-operation".into();
        // Syntax validity and the same HPKE intent are not original provenance.
        assert!(changed.canonical_bytes().is_ok());
        assert!(changed.require_exact_retained(&original).is_err());
        let mut changed = BornIntentHandoffV1::parse(&bytes).unwrap();
        changed.request.reservation.expected_head.digest = "d".repeat(64);
        assert!(changed.canonical_bytes().is_ok());
        assert!(changed.require_exact_retained(&original).is_err());
        let mut changed = BornIntentHandoffV1::parse(&bytes).unwrap();
        changed.admission_export_template.message_id = "cd".repeat(16);
        assert!(changed.canonical_bytes().is_ok());
        assert!(changed.require_exact_retained(&original).is_err());
        assert!(
            BornIntentHandoffV1::parse(&bytes)
                .unwrap()
                .require_exact_retained(&original)
                .is_ok()
        );
    }
    #[test]
    fn born_courier_rejects_allocation_renewal_malformed_and_oversize() {
        let mut h = inert_fixture();
        h.admission_export_template.sequence = 1;
        assert!(h.canonical_bytes().is_err());
        let mut h = inert_fixture();
        h.admission_export_template.expires_at_unix_seconds = 31;
        assert!(h.canonical_bytes().is_err());
        let mut h = inert_fixture();
        h.request.artifact_binding_digest = "not-a-digest".into();
        assert!(h.canonical_bytes().is_err());
        let mut h = inert_fixture();
        h.encrypted_intent_base64.push('=');
        assert!(h.canonical_bytes().is_err());
        assert!(BornIntentHandoffV1::parse(b"{}").is_err());
        assert!(
            BornIntentHandoffV1::parse(&vec![b' '; MAX_BORN_INTENT_HANDOFF_BYTES_V1 + 1]).is_err()
        );
    }
}
