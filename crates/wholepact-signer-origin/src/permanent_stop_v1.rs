//! Strict inert restriction-only wire records. They do not establish ownership,
//! native consent, witness authenticity, or a durable Host write by themselves.
use crate::manual_roster_v2::HostManualRosterEnrollmentRequestV2;
use crate::{digest, hash, Error, PairScope, Result};
use serde::{Deserialize, Serialize};

pub const MAX_FRAME_BYTES: usize = 128 * 1024;
pub fn require_activation_v1() -> Result<()> {
    Err(Error::PermanentStopUnavailable)
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPermanentStopRequestV1 {
    pub version: u16,
    pub original: HostManualRosterEnrollmentRequestV2,
    pub original_host_audit_digest: String,
    pub provider_enrollment_ref: String,
}
impl HostPermanentStopRequestV1 {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(Error::Binding);
        }
        self.original.validate()?;
        hash(&self.original_host_audit_digest)?;
        hash(&self.provider_enrollment_ref)?;
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:host-permanent-stop-request:v1", self)
    }
    pub fn require_scope(&self, scope: &PairScope) -> Result<()> {
        self.validate()?;
        scope.validate()?;
        let t = &self.original.enrollment.terms;
        if scope.account_id != t.identity.account_id
            || scope.agreement_id != t.scope.agreement_id
            || scope.participant_id != t.scope.participant_id
            || scope.manifest_digest != self.digest()?
            || scope.history_read
            || scope.authorization_export
            || scope.preconstruction_export
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
    pub fn pair_scope(&self) -> Result<PairScope> {
        let t = &self.original.enrollment.terms;
        let scope = PairScope {
            account_id: t.identity.account_id.clone(),
            agreement_id: t.scope.agreement_id.clone(),
            participant_id: t.scope.participant_id.clone(),
            manifest_digest: self.digest()?,
            history_read: false,
            authorization_export: false,
            preconstruction_export: false,
        };
        self.require_scope(&scope)?;
        Ok(scope)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermanentStopEvidenceV1 {
    pub version: u16,
    pub request: HostPermanentStopRequestV1,
    pub exclusion_operation_id: String,
    pub exclusion_digest: String,
    pub original_witness_receipt_digest: String,
    pub original_witness_head_sequence: u64,
    pub original_witness_head_digest: String,
    pub complete_witness_history_digest: String,
    pub native_review_digest: String,
}
impl PermanentStopEvidenceV1 {
    pub fn validate(&self) -> Result<()> {
        self.request.validate()?;
        crate::label(&self.exclusion_operation_id)?;
        for h in [
            &self.exclusion_digest,
            &self.original_witness_receipt_digest,
            &self.original_witness_head_digest,
            &self.complete_witness_history_digest,
            &self.native_review_digest,
        ] {
            hash(h)?;
        }
        if self.version != 1
            || self.original_witness_head_sequence == 0
            || self.original_witness_head_sequence > i64::MAX as u64
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:permanent-stop-evidence:v1", self)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPermanentStopAcknowledgmentV1 {
    pub version: u16,
    pub request_digest: String,
    pub exclusion_operation_id: String,
    pub exclusion_digest: String,
    pub original_witness_receipt_digest: String,
    pub original_host_audit_digest: String,
    pub restriction_audit_digest: String,
    pub original_host_witness_history_digest: String,
    pub provider_enrollment_ref: String,
}
impl HostPermanentStopAcknowledgmentV1 {
    pub fn require_evidence(&self, e: &PermanentStopEvidenceV1) -> Result<()> {
        e.validate()?;
        for h in [
            &self.request_digest,
            &self.exclusion_digest,
            &self.original_witness_receipt_digest,
            &self.original_host_audit_digest,
            &self.restriction_audit_digest,
            &self.original_host_witness_history_digest,
            &self.provider_enrollment_ref,
        ] {
            hash(h)?;
        }
        if self.version != 1
            || self.request_digest != e.request.digest()?
            || self.exclusion_operation_id != e.exclusion_operation_id
            || self.exclusion_digest != e.exclusion_digest
            || self.original_witness_receipt_digest != e.original_witness_receipt_digest
            || self.original_host_audit_digest != e.request.original_host_audit_digest
            || self.provider_enrollment_ref != e.request.provider_enrollment_ref
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum PermanentStopCommandV1 {
    CheckCurrent {
        lease_id: String,
        evidence_digest: String,
        challenge_nonce: String,
    },
    Acknowledge {
        lease_id: String,
        evidence_digest: String,
        acknowledgment: Box<HostPermanentStopAcknowledgmentV1>,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum PermanentStopResponseV1 {
    Held {
        lease_id: String,
        evidence: Box<PermanentStopEvidenceV1>,
    },
    Current {
        lease_id: String,
        evidence_digest: String,
        challenge_nonce: String,
    },
    Acknowledged {},
    Denied {},
}
pub fn encode_frame<T: Serialize>(value: &T) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let mut bytes =
        zeroize::Zeroizing::new(serde_json::to_vec(value).map_err(|_| Error::InvalidData)?);
    if bytes.len() >= MAX_FRAME_BYTES {
        return Err(Error::Limit);
    }
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> HostPermanentStopRequestV1 {
        let enrollment = crate::manual_continuation_v2::tests::enrollment_request();
        let roster = wholepact_core::manual_roster_v2::HostRosterAppendBindingV2 {
            version: 2,
            generation_id: enrollment.terms.host.generation_id.clone(),
            store_destination_identity: enrollment.terms.host.store_destination_identity.clone(),
            roster_sequence: 2,
            predecessor:
                wholepact_core::manual_roster_v2::HostRosterPredecessorV2::InitialPublicationV2 {
                    audit_digest: "a".repeat(64),
                },
        };
        HostPermanentStopRequestV1 {
            version: 1,
            original: HostManualRosterEnrollmentRequestV2 {
                version: 2,
                enrollment,
                roster,
            },
            original_host_audit_digest: "b".repeat(64),
            provider_enrollment_ref: "c".repeat(64),
        }
    }
    fn evidence() -> PermanentStopEvidenceV1 {
        PermanentStopEvidenceV1 {
            version: 1,
            request: request(),
            exclusion_operation_id: "synthetic-permanent-stop".into(),
            exclusion_digest: "d".repeat(64),
            original_witness_receipt_digest: "e".repeat(64),
            original_witness_head_sequence: 17,
            original_witness_head_digest: "f".repeat(64),
            complete_witness_history_digest: "1".repeat(64),
            native_review_digest: "2".repeat(64),
        }
    }
    #[test]
    fn strict_request_and_empty_tagged_variants_reject_asserted_authority() {
        let request = request();
        request.validate().unwrap();
        for field in [
            "owner",
            "native_decision",
            "vault_key",
            "recipient",
            "approved",
        ] {
            let mut value = serde_json::to_value(&request).unwrap();
            value[field] = serde_json::json!(true);
            assert!(serde_json::from_value::<HostPermanentStopRequestV1>(value).is_err());
        }
        for status in ["acknowledged", "denied"] {
            assert!(serde_json::from_value::<PermanentStopResponseV1>(
                serde_json::json!({"status":status,"approved":true})
            )
            .is_err());
        }
        assert!(serde_json::from_value::<PermanentStopCommandV1>(
            serde_json::json!({"operation":"finish"})
        )
        .is_err());
        assert!(require_activation_v1().is_err());
    }
    #[test]
    fn wire_limit_counts_actual_utf8_serialization_and_newline_exactly() {
        let exact = "x".repeat(MAX_FRAME_BYTES - 3);
        assert_eq!(encode_frame(&exact).unwrap().len(), MAX_FRAME_BYTES);
        assert!(encode_frame(&(exact + "x")).is_err());
        let multibyte = "é".repeat((MAX_FRAME_BYTES - 4) / 2);
        let frame = encode_frame(&multibyte).unwrap();
        assert_eq!(
            frame.len(),
            serde_json::to_vec(&multibyte).unwrap().len() + 1
        );
        assert!(encode_frame(&"é".repeat(MAX_FRAME_BYTES / 2)).is_err());
    }
    #[test]
    fn scope_rejects_substituted_account_recipient_manifest_and_capabilities() {
        let r = request();
        let scope = r.pair_scope().unwrap();
        r.require_scope(&scope).unwrap();
        for change in 0..7 {
            let mut bad = scope.clone();
            match change {
                0 => bad.account_id = "3".repeat(64),
                1 => bad.agreement_id = "different-agreement".into(),
                2 => bad.participant_id = "different-recipient".into(),
                3 => bad.manifest_digest = "4".repeat(64),
                4 => bad.history_read = true,
                5 => bad.authorization_export = true,
                _ => bad.preconstruction_export = true,
            };
            assert!(r.require_scope(&bad).is_err());
        }
    }
    #[test]
    fn exact_ack_retry_keeps_first_host_history_and_receipt() {
        let e = evidence();
        let ack = HostPermanentStopAcknowledgmentV1 {
            version: 1,
            request_digest: e.request.digest().unwrap(),
            exclusion_operation_id: e.exclusion_operation_id.clone(),
            exclusion_digest: e.exclusion_digest.clone(),
            original_witness_receipt_digest: e.original_witness_receipt_digest.clone(),
            original_host_audit_digest: e.request.original_host_audit_digest.clone(),
            restriction_audit_digest: "5".repeat(64),
            original_host_witness_history_digest: e.complete_witness_history_digest.clone(),
            provider_enrollment_ref: e.request.provider_enrollment_ref.clone(),
        };
        ack.require_evidence(&e).unwrap();
        let mut later = e.clone();
        later.complete_witness_history_digest = "6".repeat(64);
        later.native_review_digest = "7".repeat(64);
        ack.require_evidence(&later).unwrap();
        for change in 0..5 {
            let mut bad = e.clone();
            match change {
                0 => bad.original_witness_receipt_digest = "8".repeat(64),
                1 => bad.exclusion_digest = "8".repeat(64),
                2 => bad.request.original_host_audit_digest = "8".repeat(64),
                3 => bad.request.provider_enrollment_ref = "8".repeat(64),
                _ => bad.exclusion_operation_id = "replacement-operation".into(),
            };
            assert!(ack.require_evidence(&bad).is_err());
        }
    }
}
