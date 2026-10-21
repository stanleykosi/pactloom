//! Ordinary exact FinancialSigning setup/resource data. A validated DTO is not
//! a configured source, an authenticated prefix, a service-ready capability or
//! an action grant. The real original W retains source/TLS/listener custody;
//! service Instants and actual actors are established independently by Origin.
use crate::{
    financial_history_data::FinancialHistoryInputsV1,
    financial_workflow_channel::FinancialActorContextV1, financial_workflow_clock::SUPERVISION_MS,
    rejected, signer_continue_channel::SignerContinuePresentationV1, signer_continue_state::hash,
    Result,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const FINANCIAL_SIGNING_PURPOSE: &str = "original-financial-signing-service";
pub const FINANCIAL_SIGNING_MODE: &str = "original-bounded-financial-service";
const MAX_ENCODED: usize = 60 * 1024;
const ORIGINAL_DOMAIN: &[u8] = b"wholepact:financial-signing:original:v1\0";
const PRESENTATION_DOMAIN: &[u8] = b"wholepact:financial-signing:presentation:v1\0";

/// Public selection only. Reuses the exact maintained History11 selector
/// schema; neither request replacement nor private credential bytes are inputs.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinancialSigningInputsV1 {
    pub selectors: FinancialHistoryInputsV1,
    pub continuation_operation_id: String,
}
impl FinancialSigningInputsV1 {
    pub fn validate(&self) -> Result<()> {
        self.selectors.validate()?;
        if !identifier(&self.continuation_operation_id) {
            return Err(rejected("financial signing operation selector rejected"));
        }
        encoded_bound(self)
    }
}

/// Once-retained original Continue/Admit correlation. The admitted head below
/// is historical evidence, not the service's current head or an action permit.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinancialSigningOriginalV1 {
    pub actor: FinancialActorContextV1,
    pub continue_presentation_digest: String,
    pub prepared_digest: String,
    pub admit_presentation_digest: String,
    pub admission_ready_digest: String,
    pub signer_source_identity_digest: String,
    pub admission_terms_digest: String,
    pub request_json: String,
    pub request_digest: String,
    pub original_host_process_instance: String,
    pub owner_certificate_digest: String,
    pub owner_disclosure_json: String,
    pub owner_disclosure_digest: String,
    pub owner_selection_digest: String,
    pub terms_digest: String,
    pub account_id: String,
    pub network_profile_id: String,
    pub operation_id: String,
    pub admitted_head_sequence: u64,
    pub admitted_head_digest: String,
    pub source_ceiling_ms: u64,
    pub source_expires_at_ms: u64,
}
impl FinancialSigningOriginalV1 {
    pub fn validate(&self) -> Result<()> {
        self.actor.validate()?;
        if ![
            &self.continue_presentation_digest,
            &self.prepared_digest,
            &self.admit_presentation_digest,
            &self.admission_ready_digest,
            &self.signer_source_identity_digest,
            &self.admission_terms_digest,
            &self.request_digest,
            &self.original_host_process_instance,
            &self.owner_certificate_digest,
            &self.owner_disclosure_digest,
            &self.owner_selection_digest,
            &self.terms_digest,
            &self.account_id,
            &self.admitted_head_digest,
        ]
        .iter()
        .all(|value| hash(value))
            || !identifier(&self.network_profile_id)
            || !identifier(&self.operation_id)
            || !json_object(&self.request_json, 32 * 1024)
            || !json_object(&self.owner_disclosure_json, 16 * 1024)
            || self.request_digest
                != SignerContinuePresentationV1::calculate_request_digest(&self.request_json)
            || self.source_ceiling_ms == 0
            || self.source_ceiling_ms > SUPERVISION_MS
            || self.source_expires_at_ms == 0
        {
            return Err(rejected("financial signing original correlation rejected"));
        }
        // JSON syntax and exact request-byte commitment only. No Authority
        // semantic parser or replacement disclosure hash is invented here.
        // Actual issuers/source compare the retained canonical bytes and digest.
        encoded_bound(self)
    }
    pub fn commitment(&self) -> Result<String> {
        self.validate()?;
        digest(ORIGINAL_DOMAIN, self)
    }
}

/// Actual configured-resource display, still ordinary data. Setup's <=120s
/// window is distinct from the original service/source validity. No caller can
/// provide or renew a service Instant by constructing this presentation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinancialSigningPresentationV1 {
    pub version: u16,
    pub purpose: String,
    pub mode: String,
    pub display: String,
    pub backend_review_digest: String,
    pub presentation_digest: String,
    pub prepared_at_ms: u64,
    pub expires_at_ms: u64,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
    pub account_id: String,
    pub network_profile_id: String,
    pub operation_id: String,
    pub admission_digest: String,
    pub source_commitment: String,
    pub policy_digest: String,
    pub owner_certificate_digest: String,
    pub writer_certificate_digest: String,
    pub endpoint: String,
    pub server_name: String,
    pub witness_id: String,
    pub pinned_server_certificate_digest: String,
    pub current_head_sequence: u64,
    pub current_head_digest: String,
    pub original: FinancialSigningOriginalV1,
}
impl FinancialSigningPresentationV1 {
    pub fn calculate_presentation_digest(&self) -> Result<String> {
        self.validate_shape()?;
        // Fixed-order nested tuples stay within serde's tuple arity limit.
        // Every non-self-digest field, including exact original bytes, is bound.
        digest(
            PRESENTATION_DOMAIN,
            &(
                (
                    self.version,
                    &self.purpose,
                    &self.mode,
                    &self.display,
                    &self.backend_review_digest,
                    self.prepared_at_ms,
                    self.expires_at_ms,
                    self.valid_from_ms,
                    self.valid_until_ms,
                ),
                (
                    &self.account_id,
                    &self.network_profile_id,
                    &self.operation_id,
                    &self.admission_digest,
                    &self.source_commitment,
                    &self.policy_digest,
                    &self.owner_certificate_digest,
                    &self.writer_certificate_digest,
                ),
                (
                    &self.endpoint,
                    &self.server_name,
                    &self.witness_id,
                    &self.pinned_server_certificate_digest,
                    self.current_head_sequence,
                    &self.current_head_digest,
                    &self.original,
                ),
            ),
        )
    }
    pub fn validate(&self) -> Result<()> {
        self.validate_shape()?;
        if !hash(&self.presentation_digest)
            || self.presentation_digest != self.calculate_presentation_digest()?
        {
            return Err(rejected(
                "financial signing presentation commitment rejected",
            ));
        }
        Ok(())
    }
    fn validate_shape(&self) -> Result<()> {
        self.original.validate()?;
        if self.version != 1
            || self.purpose != FINANCIAL_SIGNING_PURPOSE
            || self.mode != FINANCIAL_SIGNING_MODE
            || !text(&self.display, 32 * 1024)
            || ![
                &self.backend_review_digest,
                &self.account_id,
                &self.admission_digest,
                &self.source_commitment,
                &self.policy_digest,
                &self.owner_certificate_digest,
                &self.writer_certificate_digest,
                &self.pinned_server_certificate_digest,
                &self.current_head_digest,
            ]
            .iter()
            .all(|value| hash(value))
            || !identifier(&self.network_profile_id)
            || !identifier(&self.operation_id)
            || ![&self.endpoint, &self.server_name, &self.witness_id]
                .iter()
                .all(|s| text(s, 4096))
            || self.account_id != self.original.account_id
            || self.network_profile_id != self.original.network_profile_id
            || self.operation_id != self.original.operation_id
            || self.owner_certificate_digest != self.original.owner_certificate_digest
            || self.prepared_at_ms == 0
            || self
                .expires_at_ms
                .checked_sub(self.prepared_at_ms)
                .is_none_or(|n| n == 0 || n > 120_000)
            || self.expires_at_ms > self.valid_until_ms
            || self.valid_from_ms >= self.valid_until_ms
            || self.valid_until_ms != self.original.source_expires_at_ms
            || !historical_prefix_shape(
                self.current_head_sequence,
                &self.current_head_digest,
                self.original.admitted_head_sequence,
                &self.original.admitted_head_digest,
            )
            || self.presentation_digest.len() > 64
        {
            return Err(rejected("financial signing presentation shape rejected"));
        }
        // This comparison is necessary shape only. Actual configured W must
        // authenticate that the original admitted head is in its current prefix.
        encoded_bound(self)
    }
}
/// Inert original-service correlation carried by the genuine typed outbounds.
/// This is NOT FinancialSigningServingV1, and constructing or validating it
/// cannot create a serving owner, W liveness, permission or a direct S/W edge.
/// The service's initial head is intentionally absent: later actions may use
/// later authenticated history under the same bounded actual service.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinancialSigningServiceV1 {
    pub original: FinancialSigningOriginalV1,
    pub witness_instance: String,
    pub presentation_digest: String,
    pub service_challenge: String,
    pub service_ceiling_ms: u64,
    pub writer_certificate_digest: String,
    pub admission_digest: String,
}
impl FinancialSigningServiceV1 {
    pub fn validate(&self) -> Result<()> {
        self.original.validate()?;
        if ![
            &self.witness_instance,
            &self.presentation_digest,
            &self.service_challenge,
            &self.writer_certificate_digest,
            &self.admission_digest,
        ]
        .iter()
        .all(|value| hash(value))
            || self.service_ceiling_ms == 0
            || self.service_ceiling_ms > self.original.source_ceiling_ms
        {
            return Err(rejected("financial signing service correlation rejected"));
        }
        encoded_bound(self)
    }
    pub fn commitment(&self) -> Result<String> {
        self.validate()?;
        digest(b"wholepact:financial-signing:serving:v1\0", self)
    }
}

fn historical_prefix_shape(
    current: u64,
    current_digest: &str,
    admitted: u64,
    admitted_digest: &str,
) -> bool {
    current >= admitted && (current != admitted || current_digest == admitted_digest)
}
fn text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte == b'\n' || byte == b'\t' || (0x20..=0x7e).contains(&byte))
}
fn json_object(value: &str, maximum: usize) -> bool {
    text(value, maximum)
        && serde_json::from_str::<serde_json::Value>(value).is_ok_and(|value| value.is_object())
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
}
fn encoded_bound(value: &impl Serialize) -> Result<()> {
    if serde_json::to_vec(value)
        .map_err(|_| rejected("financial signing public encoding rejected"))?
        .len()
        > MAX_ENCODED
    {
        return Err(rejected(
            "financial signing complete data exceeds frame budget",
        ));
    }
    Ok(())
}
fn digest(domain: &[u8], value: &impl Serialize) -> Result<String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| rejected("financial signing digest encoding rejected"))?;
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(bytes);
    Ok(hex::encode(digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn h() -> String {
        "ab".repeat(32)
    }
    fn original() -> FinancialSigningOriginalV1 {
        // Ordinary synthetic actor metadata only. No Core, process, origin,
        // token, key, HPKE/RNG, clock sampling or service constructor is used.
        let actor = serde_json::from_value(serde_json::json!({
            "profile": "coordinated-financial-workflow-v1",
            "coordinator_process_instance": h(), "coordinator_focus_epoch": 1,
            "signer_role": "signer1", "signer_process_instance": h(),
            "common_image_measurement": h(), "session_challenge": h()
        }))
        .unwrap();
        let request_json = "{\"public_fixture\":1}".to_owned();
        FinancialSigningOriginalV1 {
            actor,
            continue_presentation_digest: h(),
            prepared_digest: h(),
            admit_presentation_digest: h(),
            admission_ready_digest: h(),
            signer_source_identity_digest: h(),
            admission_terms_digest: h(),
            request_digest: SignerContinuePresentationV1::calculate_request_digest(&request_json),
            request_json,
            original_host_process_instance: h(),
            owner_certificate_digest: h(),
            owner_disclosure_json: "{\"public_fixture\":2}".into(),
            owner_disclosure_digest: h(),
            owner_selection_digest: h(),
            terms_digest: h(),
            account_id: h(),
            network_profile_id: "public-network".into(),
            operation_id: "public-operation".into(),
            admitted_head_sequence: 20,
            admitted_head_digest: h(),
            source_ceiling_ms: 300000,
            source_expires_at_ms: 300000,
        }
    }
    fn presentation() -> FinancialSigningPresentationV1 {
        let original = original();
        let mut p = FinancialSigningPresentationV1 {
            version: 1,
            purpose: FINANCIAL_SIGNING_PURPOSE.into(),
            mode: FINANCIAL_SIGNING_MODE.into(),
            display: "Public synthetic FinancialSigning resource, no service created".into(),
            backend_review_digest: h(),
            presentation_digest: String::new(),
            prepared_at_ms: 2000,
            expires_at_ms: 122000,
            valid_from_ms: 1000,
            valid_until_ms: original.source_expires_at_ms,
            account_id: original.account_id.clone(),
            network_profile_id: original.network_profile_id.clone(),
            operation_id: original.operation_id.clone(),
            admission_digest: h(),
            source_commitment: h(),
            policy_digest: h(),
            owner_certificate_digest: original.owner_certificate_digest.clone(),
            writer_certificate_digest: h(),
            endpoint: "127.0.0.1:12345".into(),
            server_name: "public.invalid".into(),
            witness_id: "public-witness".into(),
            pinned_server_certificate_digest: h(),
            current_head_sequence: 20,
            current_head_digest: original.admitted_head_digest.clone(),
            original,
        };
        p.presentation_digest = p.calculate_presentation_digest().unwrap();
        p
    }
    fn inputs() -> FinancialSigningInputsV1 {
        FinancialSigningInputsV1 {
            selectors: FinancialHistoryInputsV1 {
                endpoint: "127.0.0.1:12345".into(),
                server_name: "public.invalid".into(),
                witness_id: "public-witness".into(),
                pinned_server_certificate_digest: h(),
                network_profile_id: "public-network".into(),
                expected_account_id: h(),
                owner_certificate_der_hex: "aa".into(),
                storage_key_file: "/public-fixture/storage".into(),
                server_certificate_der: "/public-fixture/certificate".into(),
                server_private_key_pkcs8_der: "/public-fixture/private-key".into(),
                trusted_client_root_der: "/public-fixture/root".into(),
            },
            continuation_operation_id: "public-operation".into(),
        }
    }
    #[test]
    fn signing_data_roundtrips_strictly_without_source_or_service_construction() {
        let p = presentation();
        p.validate().unwrap();
        let json = serde_json::to_string(&p).unwrap();
        assert!(p == serde_json::from_str::<FinancialSigningPresentationV1>(&json).unwrap());
        for prefix in ["\"unknown\":1,", "\"current_head_sequence\":20,"] {
            assert!(
                serde_json::from_str::<FinancialSigningPresentationV1>(&format!(
                    "{{{prefix}{}",
                    &json[1..]
                ))
                .is_err()
            );
        }
        let original = serde_json::to_string(&p.original).unwrap();
        for prefix in ["\"service_deadline\":1,", "\"source_ceiling_ms\":300000,"] {
            assert!(serde_json::from_str::<FinancialSigningOriginalV1>(&format!(
                "{{{prefix}{}",
                &original[1..]
            ))
            .is_err());
        }
        let selected = inputs();
        selected.validate().unwrap();
        let json = serde_json::to_string(&selected).unwrap();
        assert!(selected == serde_json::from_str::<FinancialSigningInputsV1>(&json).unwrap());
        assert!(serde_json::from_str::<FinancialSigningInputsV1>(&format!(
            "{{\"request_json\":\"{{}}\",{}",
            &json[1..]
        ))
        .is_err());
        let mut selected = selected;
        selected.continuation_operation_id = "../replacement".into();
        assert!(selected.validate().is_err());
    }
    #[test]
    fn signing_commitments_bind_exact_original_bytes_and_distinct_domains() {
        let p = presentation();
        let original_digest = p.original.commitment().unwrap();
        assert_ne!(original_digest, p.presentation_digest);
        let mut original = p.original.clone();
        original.owner_disclosure_json.push(' ');
        // No invented disclosure hash: exact bytes alter this commitment while
        // the actual source/issuer still must compare the retained descriptor.
        original.validate().unwrap();
        assert_ne!(original.commitment().unwrap(), original_digest);
        for n in 0..8 {
            let mut changed = p.clone();
            match n {
                0 => changed.mode = "one-exact-append".into(),
                1 => changed.purpose = "original-financial-history-service".into(),
                2 => changed.writer_certificate_digest = "cd".repeat(32),
                3 => changed.endpoint.push('1'),
                4 => changed.original.admission_ready_digest = "cd".repeat(32),
                5 => changed.source_commitment = "cd".repeat(32),
                6 => changed.expires_at_ms -= 1,
                _ => changed.original.owner_disclosure_json.push(' '),
            }
            assert!(changed.validate().is_err());
        }
        let mut changed = p.original;
        changed.request_json.push(' ');
        assert!(changed.validate().is_err());
    }
    #[test]
    fn signing_historical_head_shape_never_claims_prefix_membership() {
        let p = presentation();
        let mut changed = p.clone();
        changed.current_head_sequence -= 1;
        assert!(changed.calculate_presentation_digest().is_err());
        let mut changed = p.clone();
        changed.current_head_digest = "cd".repeat(32);
        assert!(changed.calculate_presentation_digest().is_err());
        let mut later = p;
        later.current_head_sequence += 1;
        later.current_head_digest = "cd".repeat(32);
        later.presentation_digest = later.calculate_presentation_digest().unwrap();
        later.validate().unwrap();
        // Greater head plus valid data is NOT proof that it contains the old
        // admitted head. Only the actual maintained W audit establishes that.
    }
    #[test]
    fn signing_setup_window_is_separate_from_original_service_validity() {
        let p = presentation();
        assert!(p.valid_until_ms > p.expires_at_ms);
        for (start, end) in [(0, 1), (10, 10), (1, 120002), (u64::MAX, 1)] {
            let mut changed = p.clone();
            changed.prepared_at_ms = start;
            changed.expires_at_ms = end;
            assert!(changed.calculate_presentation_digest().is_err());
        }
        let mut changed = p.clone();
        changed.valid_until_ms -= 1;
        assert!(changed.calculate_presentation_digest().is_err());
        let mut changed = p.clone();
        changed.valid_from_ms = changed.valid_until_ms;
        assert!(changed.calculate_presentation_digest().is_err());
        let mut changed = p;
        changed.original.source_ceiling_ms = SUPERVISION_MS + 1;
        assert!(changed.calculate_presentation_digest().is_err());
    }
    #[test]
    fn signing_complete_data_bounds_reject_instead_of_truncating() {
        let p = presentation();
        let mut changed = p.clone();
        changed.display = "\u{202e}hidden".into();
        assert!(changed.calculate_presentation_digest().is_err());
        let mut changed = p;
        changed.display = "x".repeat(32 * 1024);
        changed.original.request_json = format!("{{\"public_fixture\":\"{}\"}}", "x".repeat(30000));
        changed.original.request_digest =
            SignerContinuePresentationV1::calculate_request_digest(&changed.original.request_json);
        changed.original.validate().unwrap();
        assert!(changed.calculate_presentation_digest().is_err());
        let mut selected = inputs();
        selected.selectors.owner_certificate_der_hex = "GG".into();
        assert!(selected.validate().is_err());
    }
    #[test]
    fn signing_service_data_is_bounded_correlation_not_a_serving_owner() {
        let p = presentation();
        let service = FinancialSigningServiceV1 {
            original: p.original.clone(),
            witness_instance: h(),
            presentation_digest: p.presentation_digest.clone(),
            service_challenge: h(),
            service_ceiling_ms: 299000,
            writer_certificate_digest: p.writer_certificate_digest.clone(),
            admission_digest: p.admission_digest.clone(),
        };
        service.validate().unwrap();
        let commitment = service.commitment().unwrap();
        assert_ne!(commitment, p.presentation_digest);
        assert_ne!(commitment, service.original.commitment().unwrap());
        let json = serde_json::to_string(&service).unwrap();
        assert!(service == serde_json::from_str::<FinancialSigningServiceV1>(&json).unwrap());
        for prefix in [
            "\"current_head_sequence\":21,",
            "\"service_ceiling_ms\":299000,",
        ] {
            assert!(serde_json::from_str::<FinancialSigningServiceV1>(&format!(
                "{{{prefix}{}",
                &json[1..]
            ))
            .is_err());
        }
        for cutoff in [0, service.original.source_ceiling_ms + 1, u64::MAX] {
            let mut changed = service.clone();
            changed.service_ceiling_ms = cutoff;
            assert!(changed.validate().is_err());
        }
        let mut changed = service.clone();
        changed.service_ceiling_ms -= 1;
        assert_ne!(changed.commitment().unwrap(), commitment);
        let mut changed = service;
        changed.witness_instance = "cd".repeat(32);
        assert_ne!(changed.commitment().unwrap(), commitment);
    }
}
