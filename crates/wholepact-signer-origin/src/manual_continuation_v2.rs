//! Explicit successor-session publication protocol. V1 enrollment and old local
//! acquisition markers are never reinterpreted as this type. All public values
//! remain inert; only the actual installed same-peer channel can issue its lease.
use crate::manual::{HostManualEnrollmentRequest, ManualCurrentState, validate_admission_window};
use crate::{Error, Result, digest, hash};
use serde::{Deserialize, Serialize};

/// The full immutable first enrollment plus one exact independently reviewed
/// continuation commitment. A digest identifies data; it grants no permission.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostManualEnrollmentContinuationRequestV2 {
    pub version: u16,
    pub enrollment: HostManualEnrollmentRequest,
    pub continuation_digest: String,
}
impl HostManualEnrollmentContinuationRequestV2 {
    pub fn validate(&self) -> Result<()> {
        if self.version != 2 {
            return Err(Error::Binding);
        }
        self.enrollment.validate()?;
        hash(&self.continuation_digest)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest(
            "wholepact:host-manual-enrollment-continuation-request:v2",
            self,
        )
    }
}

/// Original admission for this exact successor attempt. Times are copied only
/// from the genuine witness V2 record. The separate signed continuation's FIRST
/// append cutoff is not this publication deadline and can never renew it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableManualEnrollmentContinuationAdmissionV2 {
    pub version: u16,
    pub exact_request_digest: String,
    pub signer_intent_digest: String,
    /// Actual authority RecordV2.digest_for(extension, continuation), not a
    /// substitute canonical rehash of a caller-supplied projection.
    pub witness_admission_digest: String,
    pub attempt_digest: String,
    pub attempt_sequence: u64,
    pub admitted_at_ms: u64,
    pub admission_deadline_ms: u64,
}
impl DurableManualEnrollmentContinuationAdmissionV2 {
    pub fn validate_for(&self, request: &HostManualEnrollmentContinuationRequestV2) -> Result<()> {
        request.validate()?;
        if self.version != 2
            || self.attempt_sequence < 2
            || self.attempt_sequence > i64::MAX as u64
            || self.exact_request_digest != request.digest()?
            || self.attempt_digest != request.continuation_digest
        {
            return Err(Error::Binding);
        }
        for value in [
            &self.exact_request_digest,
            &self.signer_intent_digest,
            &self.witness_admission_digest,
            &self.attempt_digest,
        ] {
            hash(value)?;
        }
        let terms = &request.enrollment.terms;
        validate_admission_window(
            self.admitted_at_ms,
            self.admission_deadline_ms,
            terms.issued_at_ms,
            terms.scope.expires_at_ms,
            120_000,
        )
    }
    pub fn digest_for(
        &self,
        request: &HostManualEnrollmentContinuationRequestV2,
    ) -> Result<String> {
        self.validate_for(request)?;
        digest(
            "wholepact:durable-manual-enrollment-continuation-admission:v2",
            self,
        )
    }
    pub fn require_exact_retry(
        &self,
        original: &Self,
        request: &HostManualEnrollmentContinuationRequestV2,
    ) -> Result<()> {
        self.validate_for(request)?;
        original.validate_for(request)?;
        if self != original {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualEnrollmentContinuationEvidenceV2 {
    pub version: u16,
    pub request: HostManualEnrollmentContinuationRequestV2,
    pub enrollment_ref: String,
    pub witness_extension_digest: String,
    pub witness_extension_sequence: u64,
    pub witness_extension_predecessor_digest: Option<String>,
    pub admission: DurableManualEnrollmentContinuationAdmissionV2,
    pub current: ManualCurrentState,
}
impl ManualEnrollmentContinuationEvidenceV2 {
    pub fn validate(&self) -> Result<()> {
        self.request.validate()?;
        hash(&self.enrollment_ref)?;
        hash(&self.witness_extension_digest)?;
        self.admission.validate_for(&self.request)?;
        self.current.validate()?;
        let terms = &self.request.enrollment.terms;
        // The original first extension/epoch/certificate remain immutable. Only
        // an actually authorized successor session is different in this protocol.
        if self.version != 2
            || self.witness_extension_sequence != 1
            || self.witness_extension_predecessor_digest.is_some()
            || terms.host.scope_predecessor_digest.is_some()
            || self.current.writer_epoch != terms.signer.writer_epoch
            || self.current.writer_certificate_digest != terms.signer.writer_certificate_digest
            || self.admission.admission_deadline_ms > self.current.writer_session_expires_at_ms
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:manual-enrollment-continuation-evidence:v2", self)
    }
    /// New observations may differ, but the original exact admission/session
    /// cannot be renewed or replaced while retaining this attempt identifier.
    pub fn require_exact_retry(&self, original: &Self) -> Result<()> {
        self.validate()?;
        original.validate()?;
        if self.request != original.request
            || self.enrollment_ref != original.enrollment_ref
            || self.witness_extension_digest != original.witness_extension_digest
            || self.witness_extension_sequence != original.witness_extension_sequence
            || self.witness_extension_predecessor_digest
                != original.witness_extension_predecessor_digest
            || self.current.writer_session_digest != original.current.writer_session_digest
            || self.current.writer_session_expires_at_ms
                != original.current.writer_session_expires_at_ms
        {
            return Err(Error::Conflict);
        }
        self.admission
            .require_exact_retry(&original.admission, &self.request)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    // Pure synthetic wire fixtures only. None creates a provider, peer, native
    // owner, witness session, pending stream or opaque live admission.
    pub(crate) fn enrollment_request() -> HostManualEnrollmentRequest {
        use wholepact_core::manual_enrollment::{
            BornManualEnrollmentTerms, BornManualScope, BornManualSignerBinding,
            ManualAccountIdentity, ManualHostGenerationBinding,
        };
        let h = |c: char| c.to_string().repeat(64);
        HostManualEnrollmentRequest {
            terms: BornManualEnrollmentTerms {
                version: 1,
                operation_id: "synthetic-enrollment".into(),
                identity: ManualAccountIdentity {
                    account_id: h('1'),
                    full_viewing_key_digest: h('2'),
                    network_profile_id: "synthetic-testnet".into(),
                    derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
                },
                birth_request_digest: h('3'),
                birth_commit_digest: h('4'),
                native_birth_digest: h('5'),
                original_policy_digest: h('6'),
                account_use_genesis_digest: h('7'),
                original_witness_origin_digest: h('8'),
                host: ManualHostGenerationBinding {
                    generation_id: h('9'),
                    inventory_digest: h('a'),
                    generation_plan_digest: h('b'),
                    financial_journal_origin_digest: h('c'),
                    store_destination_identity: h('d'),
                    profile_id: "synthetic-profile".into(),
                    canonical_root: "/synthetic/profile".into(),
                    destination_identity_digest: h('e'),
                    inherited_identity_digest: h('f'),
                    scope_predecessor_digest: None,
                },
                signer: BornManualSignerBinding {
                    enrollment_generation_id: h('1'),
                    signer_target_digest: h('2'),
                    original_envelope_digest: h('3'),
                    owner_certificate_digest: h('4'),
                    writer_certificate_digest: h('5'),
                    writer_epoch: 1,
                    native_signer_measurement: h('6'),
                },
                scope: BornManualScope {
                    agreement_id: "synthetic-agreement".into(),
                    obligation_id: "synthetic-obligation".into(),
                    participant_id: "synthetic-participant".into(),
                    principal_id: "synthetic-principal".into(),
                    privacy_domain: "synthetic-domain".into(),
                    recipient_scope_digests: vec![h('7')],
                    aggregate_budget_zatoshis: 100,
                    per_operation_limit_zatoshis: 80,
                    maximum_fee_share_zatoshis: 5,
                    maximum_transaction_fee_zatoshis: 10,
                    maximum_permit_lifetime_ms: 1000,
                    expires_at_ms: 200_000,
                },
                transport_binding_digest: h('8'),
                issued_at_ms: 10,
            },
        }
    }
    pub(crate) fn request() -> HostManualEnrollmentContinuationRequestV2 {
        HostManualEnrollmentContinuationRequestV2 {
            version: 2,
            enrollment: enrollment_request(),
            continuation_digest: "a".repeat(64),
        }
    }
    fn evidence() -> ManualEnrollmentContinuationEvidenceV2 {
        let request = request();
        ManualEnrollmentContinuationEvidenceV2 {
            version: 2,
            enrollment_ref: "b".repeat(64),
            witness_extension_digest: "c".repeat(64),
            witness_extension_sequence: 1,
            witness_extension_predecessor_digest: None,
            admission: DurableManualEnrollmentContinuationAdmissionV2 {
                version: 2,
                exact_request_digest: request.digest().unwrap(),
                signer_intent_digest: "d".repeat(64),
                witness_admission_digest: "e".repeat(64),
                attempt_digest: request.continuation_digest.clone(),
                attempt_sequence: 2,
                admitted_at_ms: 20,
                admission_deadline_ms: 120_020,
            },
            current: ManualCurrentState {
                writer_certificate_digest: request
                    .enrollment
                    .terms
                    .signer
                    .writer_certificate_digest
                    .clone(),
                writer_epoch: request.enrollment.terms.signer.writer_epoch,
                writer_session_digest: "f".repeat(64),
                writer_session_expires_at_ms: 130_000,
                witness_head_sequence: 6,
                witness_head_digest: "1".repeat(64),
                complete_history_digest: "2".repeat(64),
                exclusion_checkpoint_digest: "3".repeat(64),
                native_review_digest: "4".repeat(64),
            },
            request,
        }
    }
    #[test]
    fn continuation_v2_never_reinterprets_first_enrollment_or_old_attempt_bytes() {
        let v2 = request();
        v2.validate().unwrap();
        let first = serde_json::to_vec(&v2.enrollment).unwrap();
        assert!(
            serde_json::from_slice::<HostManualEnrollmentContinuationRequestV2>(&first).is_err()
        );
        let second = serde_json::to_vec(&v2).unwrap();
        assert!(serde_json::from_slice::<HostManualEnrollmentRequest>(&second).is_err());
        for version in [0, 1, 3] {
            let mut wrong = v2.clone();
            wrong.version = version;
            assert!(wrong.validate().is_err());
        }
        let mut wrong = serde_json::to_value(&v2).unwrap();
        wrong["approved"] = serde_json::json!(true);
        assert!(
            serde_json::from_value::<HostManualEnrollmentContinuationRequestV2>(wrong).is_err()
        );
        let mut wrong = serde_json::to_value(evidence().admission).unwrap();
        wrong["first_append_expires_at_ms"] = serde_json::json!(120_020);
        assert!(
            serde_json::from_value::<DurableManualEnrollmentContinuationAdmissionV2>(wrong)
                .is_err()
        );
    }
    #[test]
    fn exact_attempt_admission_is_immutable_and_uses_v2_request_digest() {
        let original = evidence();
        original.validate().unwrap();
        assert_ne!(
            original.request.digest().unwrap(),
            original.request.enrollment.digest().unwrap()
        );
        original.require_exact_retry(&original).unwrap();
        for field in 0..8 {
            let mut changed = original.clone();
            match field {
                0 => changed.admission.version = 1,
                1 => {
                    changed.admission.exact_request_digest =
                        changed.request.enrollment.digest().unwrap()
                }
                2 => changed.admission.signer_intent_digest = "5".repeat(64),
                3 => changed.admission.witness_admission_digest = "5".repeat(64),
                4 => changed.admission.attempt_digest = "5".repeat(64),
                5 => changed.admission.attempt_sequence += 1,
                6 => changed.admission.admitted_at_ms += 1,
                _ => changed.admission.admission_deadline_ms -= 1,
            }
            assert!(changed.require_exact_retry(&original).is_err());
        }
        let mut wrong = original.clone();
        wrong.admission.attempt_sequence = 1;
        assert!(wrong.validate().is_err());
        let mut wrong = original.clone();
        wrong.request.continuation_digest = "6".repeat(64);
        assert!(wrong.validate().is_err());
    }
    #[test]
    fn continuation_preserves_original_writer_and_exact_admitted_session_deadline() {
        let original = evidence();
        original.validate().unwrap();
        for field in 0..4 {
            let mut wrong = original.clone();
            match field {
                0 => wrong.current.writer_epoch += 1,
                1 => wrong.current.writer_certificate_digest = "9".repeat(64),
                2 => wrong.current.writer_session_expires_at_ms = 120_019,
                _ => wrong.admission.admission_deadline_ms = 120_021,
            }
            assert!(wrong != original, "mutation {field} must change evidence");
            assert!(wrong.validate().is_err(), "mutation {field} must reject");
        }
        let mut changed = original.clone();
        changed.current.writer_session_digest = "6".repeat(64);
        assert!(changed.require_exact_retry(&original).is_err());
        let mut changed = original.clone();
        changed.current.native_review_digest = "6".repeat(64);
        changed.require_exact_retry(&original).unwrap();
        // A changed current audit observation still cannot manufacture a lease.
    }
    #[test]
    fn continuation_held_has_distinct_discriminant_and_strict_versioned_evidence() {
        let response = crate::manual::ManualAdmissionResponse::EnrollmentContinuationHeldV2 {
            lease_id: "7".repeat(64),
            evidence: Box::new(evidence()),
        };
        let mut wire = serde_json::to_value(response).unwrap();
        assert_eq!(wire["status"], "enrollment_continuation_held_v2");
        assert!(
            serde_json::from_value::<crate::manual::ManualAdmissionResponse>(wire.clone()).is_ok()
        );
        wire["status"] = serde_json::json!("enrollment_held");
        assert!(serde_json::from_value::<crate::manual::ManualAdmissionResponse>(wire).is_err());
    }
}
