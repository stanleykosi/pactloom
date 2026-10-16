//! Exact inert wire bindings. Serializing/deserializing these records confers no
//! authority. Only the installed-peer client can construct the opaque leases.
use crate::{Error, Result, digest, hash};
use serde::{Deserialize, Serialize};
pub use wholepact_core::manual_enrollment::{
    BornManualAction, BornManualActionIntent, BornManualEnrollmentTerms, BornManualScope,
    ManualHostGenerationBinding,
};

/// Initial host claims only. The signer derives private account/birth/policy,
/// transport and first-enrollment fields during its genuine native preparation.
/// This request cannot produce a live admission or a verified target token.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostManualEnrollmentIntent {
    pub version: u16,
    pub operation_id: String,
    pub host: ManualHostGenerationBinding,
    pub scope: BornManualScope,
}
impl HostManualEnrollmentIntent {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(Error::Binding);
        }
        for value in [
            &self.operation_id,
            &self.host.profile_id,
            &self.scope.agreement_id,
            &self.scope.obligation_id,
            &self.scope.participant_id,
            &self.scope.principal_id,
            &self.scope.privacy_domain,
        ] {
            bounded_text(value, 256)?;
        }
        bounded_text(&self.host.canonical_root, 4096)?;
        bounded_text(&self.host.store_destination_identity, 4096)?;
        let root = &self.host.canonical_root;
        if !root.starts_with('/')
            || root == "/"
            || root.ends_with('/')
            || root
                .split('/')
                .skip(1)
                .any(|p| p.is_empty() || p == "." || p == "..")
            || self.host.scope_predecessor_digest.is_some()
        {
            return Err(Error::Binding);
        }
        for value in [
            &self.host.generation_id,
            &self.host.inventory_digest,
            &self.host.generation_plan_digest,
            &self.host.financial_journal_origin_digest,
            &self.host.destination_identity_digest,
            &self.host.inherited_identity_digest,
        ] {
            hash(value)?;
        }
        let scope = &self.scope;
        if scope.recipient_scope_digests.is_empty()
            || scope.recipient_scope_digests.len() > 32
            || scope.aggregate_budget_zatoshis == 0
            || scope.per_operation_limit_zatoshis == 0
            || scope.per_operation_limit_zatoshis > scope.aggregate_budget_zatoshis
            || scope.aggregate_budget_zatoshis > wholepact_core::MAX_MONEY
            || scope.maximum_fee_share_zatoshis > scope.maximum_transaction_fee_zatoshis
            || scope.maximum_fee_share_zatoshis > scope.per_operation_limit_zatoshis
            || scope.maximum_transaction_fee_zatoshis > wholepact_core::MAX_MONEY
            || scope.maximum_permit_lifetime_ms == 0
            || scope.expires_at_ms == 0
            || scope.maximum_permit_lifetime_ms > scope.expires_at_ms
        {
            return Err(Error::Binding);
        }
        let mut last: Option<&str> = None;
        for recipient in &scope.recipient_scope_digests {
            hash(recipient)?;
            if last.is_some_and(|previous| previous >= recipient.as_str()) {
                return Err(Error::Binding);
            }
            last = Some(recipient);
        }
        if serde_json::to_vec(self).map_err(|_| Error::Binding)?.len() > 32 * 1024 {
            return Err(Error::Limit);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:host-manual-enrollment-intent:v1", self)
    }
    /// Pure comparison to the later actual signer-derived terms. Success does
    /// not authenticate either structure and cannot manufacture an admission.
    pub fn matches_terms(&self, terms: &BornManualEnrollmentTerms) -> Result<()> {
        self.validate()?;
        terms.validate().map_err(|_| Error::Binding)?;
        if self.operation_id != terms.operation_id
            || self.host != terms.host
            || self.scope != terms.scope
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
}
fn bounded_text(value: &str, maximum: usize) -> Result<()> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(Error::Binding);
    }
    Ok(())
}

/// Claims submitted to the signer's independent native review. The signer
/// derives its real key/birth/journal values and rejects substitutions. The host
/// must independently authenticate its actual target at every consumption.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostManualEnrollmentRequest {
    pub terms: BornManualEnrollmentTerms,
}
impl HostManualEnrollmentRequest {
    pub fn validate(&self) -> Result<()> {
        self.terms.validate().map_err(|_| Error::Binding)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:host-manual-enrollment-request:v1", self)
    }
}

/// A fresh invocation. Stable enrollment/witness extension are exact references,
/// never permission; replay/input commitments and full owning request are bound.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostManualActionRequest {
    pub enrollment: BornManualEnrollmentTerms,
    pub enrollment_ref: String,
    pub witness_extension_digest: String,
    pub intent: BornManualActionIntent,
}
impl HostManualActionRequest {
    pub fn validate(&self) -> Result<()> {
        hash(&self.witness_extension_digest)?;
        self.intent
            .validate_for(&self.enrollment, &self.enrollment_ref)
            .map_err(|_| Error::Binding)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:host-manual-action-request:v1", self)
    }
}

/// Dynamic audit projection of the concrete signer/witness issuer. Neither this
/// record, a retained session ID, nor absence of an exclusion mints permission.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualCurrentState {
    pub writer_certificate_digest: String,
    pub writer_epoch: u64,
    pub writer_session_digest: String,
    pub writer_session_expires_at_ms: u64,
    pub witness_head_sequence: u64,
    pub witness_head_digest: String,
    pub complete_history_digest: String,
    pub exclusion_checkpoint_digest: String,
    pub native_review_digest: String,
}
impl ManualCurrentState {
    pub fn validate(&self) -> Result<()> {
        for value in [
            &self.writer_certificate_digest,
            &self.writer_session_digest,
            &self.witness_head_digest,
            &self.complete_history_digest,
            &self.exclusion_checkpoint_digest,
            &self.native_review_digest,
        ] {
            hash(value)?;
        }
        if self.writer_epoch == 0
            || self.writer_epoch > i64::MAX as u64
            || self.writer_session_expires_at_ms == 0
            || self.writer_session_expires_at_ms > i64::MAX as u64
            || self.witness_head_sequence > i64::MAX as u64
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
}

/// Durable enrollment reference plus a transient current observation. Saved data
/// can be audited, but can never be converted back into a live admission.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualEnrollmentEvidence {
    pub request: HostManualEnrollmentRequest,
    /// Canonical digest of the complete signer-owned BornManualEnrollmentRecord.
    pub enrollment_ref: String,
    /// Exact original-witness extension committing that same stable record/scope.
    pub witness_extension_digest: String,
    /// Actual extension ancestry copied only from the authenticated producer.
    /// No serde default and no assumed synthetic first extension.
    pub witness_extension_sequence: u64,
    pub witness_extension_predecessor_digest: Option<String>,
    /// Exact immutable publication original, never refreshed by a Current reply.
    pub admission: DurableManualEnrollmentAdmission,
    pub current: ManualCurrentState,
}
impl ManualEnrollmentEvidence {
    pub fn validate(&self) -> Result<()> {
        self.request.validate()?;
        hash(&self.enrollment_ref)?;
        hash(&self.witness_extension_digest)?;
        // Match the actual bounded first-extension protocol. Future ancestry
        // requires its own qualified monotone protocol, never an assumed value.
        if self.witness_extension_sequence != 1
            || self.witness_extension_predecessor_digest.is_some()
            || self.request.terms.host.scope_predecessor_digest.is_some()
        {
            return Err(Error::Binding);
        }
        self.admission.validate_for(&self.request)?;
        self.current.validate()?;
        if self.current.writer_certificate_digest
            != self.request.terms.signer.writer_certificate_digest
            || self.current.writer_epoch != self.request.terms.signer.writer_epoch
            || self.admission.admission_deadline_ms > self.current.writer_session_expires_at_ms
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
    /// A current observation may change, but none of the durable enrollment
    /// originals, ancestry, request or publication timing can be replaced.
    pub fn require_exact_retry(&self, original: &Self) -> Result<()> {
        self.validate()?;
        original.validate()?;
        if self.request != original.request
            || self.enrollment_ref != original.enrollment_ref
            || self.witness_extension_digest != original.witness_extension_digest
            || self.witness_extension_sequence != original.witness_extension_sequence
            || self.witness_extension_predecessor_digest
                != original.witness_extension_predecessor_digest
        {
            return Err(Error::Conflict);
        }
        self.admission
            .require_exact_retry(&original.admission, &self.request)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:manual-enrollment-evidence:v1", self)
    }
}
/// Original finite enrollment publication commitment. The producer must derive
/// witness_admission_digest from the FULL actual BornManualEnrollmentAdmissionRecord
/// using its digest_for(extension) helper (domain
/// wholepact:born-manual-enrollment-admission:v1), and copy its
/// admitted_at_ms/publication_expires_at_ms unchanged. This is audit data only.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableManualEnrollmentAdmission {
    /// Canonical digest of the complete HostManualEnrollmentRequest.
    pub exact_request_digest: String,
    /// Authenticated original immutable signer enrollment intent envelope.
    pub signer_intent_digest: String,
    pub witness_admission_digest: String,
    pub admitted_at_ms: u64,
    pub admission_deadline_ms: u64,
}
impl DurableManualEnrollmentAdmission {
    pub fn validate_for(&self, request: &HostManualEnrollmentRequest) -> Result<()> {
        request.validate()?;
        for value in [
            &self.exact_request_digest,
            &self.signer_intent_digest,
            &self.witness_admission_digest,
        ] {
            hash(value)?;
        }
        if self.exact_request_digest != request.digest()? {
            return Err(Error::Binding);
        }
        // Enrollment publication has its own finite 120-second protocol bound;
        // the financial per-operation permit lifetime is a different constraint.
        validate_admission_window(
            self.admitted_at_ms,
            self.admission_deadline_ms,
            request.terms.issued_at_ms,
            request.terms.scope.expires_at_ms,
            120_000,
        )
    }
    pub fn digest_for(&self, request: &HostManualEnrollmentRequest) -> Result<String> {
        self.validate_for(request)?;
        digest("wholepact:durable-manual-enrollment-admission:v1", self)
    }
    /// Inert exact-original comparison, not reauthentication or a lease factory.
    pub fn require_exact_retry(
        &self,
        original: &Self,
        request: &HostManualEnrollmentRequest,
    ) -> Result<()> {
        self.validate_for(request)?;
        original.validate_for(request)?;
        if self != original {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}
/// Audit of one durable, exact operation admission. Both referenced producers
/// must commit before Held. This data never recreates a live capability. A timeout
/// retains conservative exposure; it cannot renew either original timestamp.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableManualActionAdmission {
    /// Canonical HostManualActionRequest digest, including the complete owning
    /// request digest, invocation nonce, inputs and every enrollment binding.
    pub exact_request_digest: String,
    pub signer_intent_digest: String,
    pub witness_admission_digest: String,
    pub admitted_at_ms: u64,
    pub admission_deadline_ms: u64,
}
impl DurableManualActionAdmission {
    pub fn validate_for(&self, request: &HostManualActionRequest) -> Result<()> {
        request.validate()?;
        for value in [
            &self.exact_request_digest,
            &self.signer_intent_digest,
            &self.witness_admission_digest,
        ] {
            hash(value)?;
        }
        if self.exact_request_digest != request.digest()? {
            return Err(Error::Binding);
        }
        validate_admission_window(
            self.admitted_at_ms,
            self.admission_deadline_ms,
            request.enrollment.issued_at_ms,
            request.enrollment.scope.expires_at_ms,
            request.enrollment.scope.maximum_permit_lifetime_ms,
        )
    }
    pub fn digest_for(&self, request: &HostManualActionRequest) -> Result<String> {
        self.validate_for(request)?;
        digest("wholepact:durable-manual-action-admission:v1", self)
    }
    /// Caller supplies retained ORIGINAL audit for comparison only. This does
    /// not authenticate it or mint permission. Genuine producers must read their
    /// own durable originals and enforce this same immutable equality on retry.
    pub fn require_exact_retry(
        &self,
        original: &Self,
        request: &HostManualActionRequest,
    ) -> Result<()> {
        self.validate_for(request)?;
        original.validate_for(request)?;
        self.require_unchanged(original)
    }
    fn require_unchanged(&self, original: &Self) -> Result<()> {
        if self != original {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}
pub(crate) fn validate_admission_window(
    admitted: u64,
    deadline: u64,
    issued: u64,
    policy_expiry: u64,
    maximum_lifetime: u64,
) -> Result<()> {
    if admitted == 0
        || admitted < issued
        || deadline <= admitted
        || deadline > i64::MAX as u64
        || deadline > policy_expiry
        || maximum_lifetime == 0
        || deadline - admitted > maximum_lifetime
    {
        return Err(Error::Binding);
    }
    Ok(())
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualActionEvidence {
    pub request: HostManualActionRequest,
    pub admission: DurableManualActionAdmission,
    pub current: ManualCurrentState,
}
impl ManualActionEvidence {
    pub fn validate(&self) -> Result<()> {
        self.request.validate()?;
        self.admission.validate_for(&self.request)?;
        self.current.validate()
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:manual-action-evidence:v1", self)
    }
}

/// Wire responses are public so the actual signer-owned issuer can serve them.
/// A caller can construct response bytes, but no public API accepts those bytes
/// as authority: only an installed-image, same-kernel-peer stream is consumed.
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManualAdmissionResponse {
    RosterEnrollmentHeldV2 {
        lease_id: String,
        evidence: Box<crate::manual_roster_v2::ManualRosterEnrollmentEvidenceV2>,
    },
    EnrollmentHeld {
        lease_id: String,
        evidence: Box<ManualEnrollmentEvidence>,
    },
    #[serde(rename = "enrollment_continuation_held_v2")]
    EnrollmentContinuationHeldV2 {
        lease_id: String,
        evidence: Box<crate::manual_continuation_v2::ManualEnrollmentContinuationEvidenceV2>,
    },
    ActionHeld {
        lease_id: String,
        evidence: Box<ManualActionEvidence>,
    },
    Current {
        lease_id: String,
        evidence_digest: String,
        challenge_nonce: String,
    },
    Finished {},
    Denied {},
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManualAdmissionCommand {
    CheckCurrent {
        lease_id: String,
        evidence_digest: String,
        challenge_nonce: String,
    },
    Finish {},
}

#[cfg(test)]
mod tests {
    use super::*;
    fn enrollment_request() -> HostManualEnrollmentRequest {
        use wholepact_core::manual_enrollment::{BornManualSignerBinding, ManualAccountIdentity};
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
    fn enrollment_original(
        request: &HostManualEnrollmentRequest,
    ) -> DurableManualEnrollmentAdmission {
        DurableManualEnrollmentAdmission {
            exact_request_digest: request.digest().unwrap(),
            signer_intent_digest: "a".repeat(64),
            witness_admission_digest: "b".repeat(64),
            admitted_at_ms: 20,
            admission_deadline_ms: 120_020,
        }
    }
    #[test]
    fn enrollment_original_binds_exact_request_and_its_own_publication_deadline() {
        let request = enrollment_request();
        let original = enrollment_original(&request);
        original.validate_for(&request).unwrap();
        // Financial permit lifetime is 1000ms, but publication is independently
        // bounded at 120000ms, matching the actual witness protocol.
        let mut wrong = original.clone();
        wrong.admission_deadline_ms += 1;
        assert!(wrong.validate_for(&request).is_err());
        let mut changed = request.clone();
        changed.terms.host.generation_id = "f".repeat(64);
        assert!(original.validate_for(&changed).is_err());
        let mut wrong = original.clone();
        wrong.admitted_at_ms = 9;
        assert!(wrong.validate_for(&request).is_err());
        let mut wrong = original.clone();
        wrong.admission_deadline_ms = 20;
        assert!(wrong.validate_for(&request).is_err());
    }
    #[test]
    fn enrollment_retry_never_renews_or_replaces_original_publication() {
        let request = enrollment_request();
        let original = enrollment_original(&request);
        original.require_exact_retry(&original, &request).unwrap();
        for field in 0..5 {
            let mut changed = original.clone();
            match field {
                0 => changed.exact_request_digest = "c".repeat(64),
                1 => changed.signer_intent_digest = "c".repeat(64),
                2 => changed.witness_admission_digest = "c".repeat(64),
                3 => changed.admitted_at_ms += 1,
                _ => changed.admission_deadline_ms -= 1,
            }
            assert!(changed.require_exact_retry(&original, &request).is_err());
        }
    }
    #[test]
    fn enrollment_deadline_cannot_outlive_original_active_session() {
        let request = enrollment_request();
        let admission = enrollment_original(&request);
        let mut evidence = ManualEnrollmentEvidence {
            request: request.clone(),
            enrollment_ref: "c".repeat(64),
            witness_extension_digest: "d".repeat(64),
            witness_extension_sequence: 1,
            witness_extension_predecessor_digest: None,
            admission,
            current: ManualCurrentState {
                writer_certificate_digest: request.terms.signer.writer_certificate_digest.clone(),
                writer_epoch: 1,
                writer_session_digest: "e".repeat(64),
                writer_session_expires_at_ms: 130_000,
                witness_head_sequence: 4,
                witness_head_digest: "f".repeat(64),
                complete_history_digest: "a".repeat(64),
                exclusion_checkpoint_digest: "b".repeat(64),
                native_review_digest: "c".repeat(64),
            },
        };
        evidence.validate().unwrap();
        let original = evidence.clone();
        evidence.current.native_review_digest = "e".repeat(64);
        evidence.require_exact_retry(&original).unwrap();
        evidence.current.writer_session_expires_at_ms = 120_019;
        assert!(evidence.validate().is_err());
    }
    #[test]
    fn empty_terminal_variants_reject_extra_fields_without_changing_valid_json() {
        assert_eq!(
            serde_json::to_string(&ManualAdmissionCommand::Finish {}).unwrap(),
            r#"{"operation":"finish"}"#
        );
        assert!(
            serde_json::from_str::<ManualAdmissionCommand>(r#"{"operation":"finish"}"#).is_ok()
        );
        assert!(
            serde_json::from_str::<ManualAdmissionCommand>(
                r#"{"operation":"finish","approved":true}"#
            )
            .is_err()
        );
        for status in ["finished", "denied"] {
            let valid = format!(r#"{{"status":"{status}"}}"#);
            let invalid = format!(r#"{{"status":"{status}","approved":true}}"#);
            assert!(serde_json::from_str::<ManualAdmissionResponse>(&valid).is_ok());
            assert!(serde_json::from_str::<ManualAdmissionResponse>(&invalid).is_err());
        }
    }
    #[test]
    fn durable_admission_deadline_is_original_and_policy_bounded() {
        assert!(validate_admission_window(10, 30, 1, 40, 20).is_ok());
        for (admitted, deadline, issued, expiry, maximum) in [
            (0, 30, 1, 40, 30),
            (10, 30, 11, 40, 20),
            (10, 10, 1, 40, 20),
            (10, 31, 1, 40, 20),
            (10, 30, 1, 29, 20),
            (10, 30, 1, 40, 0),
            (1, u64::MAX, 1, u64::MAX, u64::MAX),
        ] {
            assert!(
                validate_admission_window(admitted, deadline, issued, expiry, maximum).is_err()
            );
        }
    }
    #[test]
    fn retry_cannot_renew_time_or_replace_any_durable_reference() {
        let original = DurableManualActionAdmission {
            exact_request_digest: "11".repeat(32),
            signer_intent_digest: "22".repeat(32),
            witness_admission_digest: "33".repeat(32),
            admitted_at_ms: 10,
            admission_deadline_ms: 30,
        };
        original.require_unchanged(&original).unwrap();
        for changed in 0..5 {
            let mut retry = original.clone();
            match changed {
                0 => retry.exact_request_digest = "44".repeat(32),
                1 => retry.signer_intent_digest = "44".repeat(32),
                2 => retry.witness_admission_digest = "44".repeat(32),
                3 => retry.admitted_at_ms += 1,
                _ => retry.admission_deadline_ms += 1,
            }
            assert!(retry.require_unchanged(&original).is_err());
        }
    }
    #[test]
    fn initial_host_intent_cannot_supply_private_signer_identity_or_approval() {
        let intent = HostManualEnrollmentIntent {
            version: 1,
            operation_id: "synthetic-intent".into(),
            host: ManualHostGenerationBinding {
                generation_id: "11".repeat(32),
                inventory_digest: "22".repeat(32),
                generation_plan_digest: "33".repeat(32),
                financial_journal_origin_digest: "44".repeat(32),
                store_destination_identity: "synthetic-destination".into(),
                profile_id: "synthetic-profile".into(),
                canonical_root: "/synthetic/profile".into(),
                destination_identity_digest: "55".repeat(32),
                inherited_identity_digest: "66".repeat(32),
                scope_predecessor_digest: None,
            },
            scope: BornManualScope {
                agreement_id: "synthetic-agreement".into(),
                obligation_id: "synthetic-obligation".into(),
                participant_id: "synthetic-participant".into(),
                principal_id: "synthetic-principal".into(),
                privacy_domain: "synthetic-domain".into(),
                recipient_scope_digests: vec!["77".repeat(32)],
                aggregate_budget_zatoshis: 100,
                per_operation_limit_zatoshis: 100,
                maximum_fee_share_zatoshis: 10,
                maximum_transaction_fee_zatoshis: 10,
                maximum_permit_lifetime_ms: 100,
                expires_at_ms: 1000,
            },
        };
        intent.validate().unwrap();
        let value = serde_json::to_value(&intent).unwrap();
        serde_json::from_value::<HostManualEnrollmentIntent>(value.clone()).unwrap();
        for field in [
            "verified",
            "identity",
            "transport_binding_digest",
            "native_review_digest",
        ] {
            let mut extra = value.clone();
            extra
                .as_object_mut()
                .unwrap()
                .insert(field.into(), serde_json::json!(true));
            assert!(serde_json::from_value::<HostManualEnrollmentIntent>(extra).is_err());
        }
    }
    #[test]
    fn malformed_current_state_never_validates() {
        let mut state = ManualCurrentState {
            writer_certificate_digest: "11".repeat(32),
            writer_epoch: 1,
            writer_session_digest: "22".repeat(32),
            writer_session_expires_at_ms: 1,
            witness_head_sequence: 0,
            witness_head_digest: "33".repeat(32),
            complete_history_digest: "44".repeat(32),
            exclusion_checkpoint_digest: "55".repeat(32),
            native_review_digest: "66".repeat(32),
        };
        state.validate().unwrap();
        state.writer_epoch = 0;
        assert!(state.validate().is_err());
        state.writer_epoch = 1;
        state.exclusion_checkpoint_digest = "caller-says-none".into();
        assert!(state.validate().is_err());
    }
    #[test]
    fn wire_schema_has_no_serialized_approve_or_current_boolean() {
        for source in [
            r#"{"operation":"approve","approved":true}"#,
            r#"{"status":"current","verified":true}"#,
            r#"{"operation":"finish","approved":true}"#,
        ] {
            assert!(serde_json::from_str::<ManualAdmissionResponse>(source).is_err());
            assert!(serde_json::from_str::<ManualAdmissionCommand>(source).is_err());
        }
    }
}
