//! Ordinary bounded same-session Signer Admit presentation/outcome data only.
//! No DTO, digest or successful validation is a grant, origin, source owner,
//! proof of commit or permission to reuse the prior Read/Continue. Actual issuer
//! checks independently bind retained actors, source, owner, W and clocks.
use crate::{
    financial_workflow_channel::FinancialActorContextV1, financial_workflow_clock::SUPERVISION_MS,
    rejected, signer_continue_channel::SignerContinuePresentationV1, signer_continue_state::hash,
    Result,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(super) const ADMIT_PURPOSE: &str = "original-financial-continuation-admit";
// The actual closed sender must still bound its COMPLETE frame to 64 KiB.
// This lower public-data limit leaves 4 KiB for the original envelope/framing;
// individual maxima cannot combine into a silently oversized/truncated packet.
const MAX_PRESENTATION_BYTES: usize = 60 * 1024;
const MAX_DISPLAY: usize = 32 * 1024;
const MAX_REQUEST: usize = 32 * 1024;
const MAX_DISCLOSURE: usize = 16 * 1024;
const PRESENTATION_DOMAIN: &[u8] =
    b"wholepact:coordinated-financial-continuation-admit:presentation:v1\0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerAdmitFactsV1 {
    pub display: String,
    pub source_identity_digest: String,
    pub admission_terms_digest: String,
    pub request_json: String,
    pub request_digest: String,
    pub original_host_process_instance: String,
    pub owner_certificate_digest: String,
    pub disclosure_json: String,
    pub disclosure_digest: String,
    pub account_id: String,
    pub network_profile_id: String,
    pub operation_id: String,
    pub expected_head_sequence: u64,
    pub expected_head_digest: String,
    pub terms_digest: String,
    pub reviewed_at_ms: u64,
    pub expires_at_ms: u64,
    pub source_expires_at_ms: u64,
}
impl SignerAdmitFactsV1 {
    pub fn validate(&self) -> Result<()> {
        if !ascii_text(&self.display, MAX_DISPLAY)
            || !json_object(&self.request_json, MAX_REQUEST)
            || !json_object(&self.disclosure_json, MAX_DISCLOSURE)
            || ![
                &self.source_identity_digest,
                &self.admission_terms_digest,
                &self.request_digest,
                &self.original_host_process_instance,
                &self.owner_certificate_digest,
                &self.disclosure_digest,
                &self.expected_head_digest,
                &self.terms_digest,
            ]
            .iter()
            .all(|value| hash(value))
            || ![
                &self.account_id,
                &self.network_profile_id,
                &self.operation_id,
            ]
            .iter()
            .all(|value| identifier(value))
            || self.request_digest
                != SignerContinuePresentationV1::calculate_request_digest(&self.request_json)
            || self.reviewed_at_ms == 0
            || self.expires_at_ms <= self.reviewed_at_ms
            || self.expires_at_ms - self.reviewed_at_ms > 120_000
            || self.expires_at_ms > self.source_expires_at_ms
        {
            return Err(rejected("Signer Admit facts rejected"));
        }
        // Do NOT invent a replacement disclosure hash: the actual issuer must
        // compare these exact bytes and the retained original Read commitment.
        // JSON syntax here neither replays an audit nor validates authority data.
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerAdmitPresentationV1 {
    pub version: u16,
    pub purpose: String,
    pub actor: FinancialActorContextV1,
    pub facts: SignerAdmitFactsV1,
    pub owner_selection_digest: String,
    pub continue_presentation_digest: String,
    pub prepared_digest: String,
    pub admit_challenge: String,
    pub source_ceiling_ms: u64,
    pub admit_ceiling_ms: u64,
    pub presentation_digest: String,
}
impl SignerAdmitPresentationV1 {
    pub fn calculate_presentation_digest(&self) -> Result<String> {
        self.validate_shape()?;
        let bytes = serde_json::to_vec(&(
            self.version,
            &self.purpose,
            &self.actor,
            &self.facts,
            &self.owner_selection_digest,
            &self.continue_presentation_digest,
            &self.prepared_digest,
            &self.admit_challenge,
            self.source_ceiling_ms,
            self.admit_ceiling_ms,
        ))
        .map_err(|_| rejected("Signer Admit presentation encoding rejected"))?;
        let mut digest = Sha256::new();
        digest.update(PRESENTATION_DOMAIN);
        digest.update(bytes);
        Ok(hex::encode(digest.finalize()))
    }
    pub fn validate(&self) -> Result<()> {
        self.validate_shape()?;
        if !hash(&self.presentation_digest)
            || self.presentation_digest != self.calculate_presentation_digest()?
        {
            return Err(rejected("Signer Admit presentation commitment rejected"));
        }
        Ok(())
    }
    fn validate_shape(&self) -> Result<()> {
        self.actor.validate()?;
        self.facts.validate()?;
        if self.version != 1
            || self.purpose != ADMIT_PURPOSE
            || ![
                &self.owner_selection_digest,
                &self.continue_presentation_digest,
                &self.prepared_digest,
                &self.admit_challenge,
            ]
            .iter()
            .all(|value| hash(value))
            || !offset(self.source_ceiling_ms)
            || !offset(self.admit_ceiling_ms)
            || self.admit_ceiling_ms > self.source_ceiling_ms
            || self.presentation_digest.len() > 64
        {
            return Err(rejected("Signer Admit presentation shape rejected"));
        }
        if serde_json::to_vec(self)
            .map_err(|_| rejected("Signer Admit complete encoding rejected"))?
            .len()
            > MAX_PRESENTATION_BYTES
        {
            return Err(rejected(
                "Signer Admit complete presentation exceeds frame budget",
            ));
        }
        Ok(())
    }
}

/// Observation ONLY after the actual original receiver authenticates the exact
/// result. Constructing this ordinary data never establishes that an append ran.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerAdmitCommittedV1 {
    pub presentation_digest: String,
    pub admission_ready_digest: String,
    pub request_digest: String,
    pub head_sequence: u64,
    pub head_digest: String,
}
impl SignerAdmitCommittedV1 {
    pub fn validate(&self) -> Result<()> {
        if ![
            &self.presentation_digest,
            &self.admission_ready_digest,
            &self.request_digest,
            &self.head_digest,
        ]
        .iter()
        .all(|value| hash(value))
        {
            return Err(rejected("Signer Admit committed observation rejected"));
        }
        Ok(())
    }
}

/// These are reported observations, not a local inference from cancellation,
/// response loss or cleanup. Missing authenticated completion remains uncertain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", deny_unknown_fields)]
pub enum SignerAdmitOutcomeV1 {
    KnownNoEffect {
        presentation_digest: String,
        admission_ready_digest: Option<String>,
    },
    Uncertain {
        presentation_digest: String,
        admission_ready_digest: Option<String>,
    },
}
impl SignerAdmitOutcomeV1 {
    pub fn validate(&self) -> Result<()> {
        let (presentation, ready) = match self {
            Self::KnownNoEffect {
                presentation_digest,
                admission_ready_digest,
            }
            | Self::Uncertain {
                presentation_digest,
                admission_ready_digest,
            } => (presentation_digest, admission_ready_digest),
        };
        if !hash(presentation) || ready.as_ref().is_some_and(|value| !hash(value)) {
            return Err(rejected("Signer Admit outcome shape rejected"));
        }
        Ok(())
    }
}

fn ascii_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte == b'\n' || byte == b'\t' || (0x20..=0x7e).contains(&byte))
}
fn json_object(value: &str, maximum: usize) -> bool {
    ascii_text(value, maximum)
        && serde_json::from_str::<serde_json::Value>(value).is_ok_and(|value| value.is_object())
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
}
fn offset(value: u64) -> bool {
    value > 0 && value <= SUPERVISION_MS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{financial_workflow_clock::PROFILE, SignerContinueRoleV1};

    // Public synthetic schema fixtures only. No native/token/source/transport,
    // process, key generation, credential, clock sampling or crypto constructor.
    fn hash_value() -> String {
        "ab".repeat(32)
    }
    fn presentation() -> SignerAdmitPresentationV1 {
        let request_json = "{\"public_fixture\":1}".to_owned();
        let mut data = SignerAdmitPresentationV1 {
            version: 1,
            purpose: ADMIT_PURPOSE.into(),
            actor: FinancialActorContextV1 {
                profile: PROFILE.into(),
                coordinator_process_instance: hash_value(),
                coordinator_focus_epoch: 1,
                signer_role: SignerContinueRoleV1::Signer1,
                signer_process_instance: hash_value(),
                common_image_measurement: hash_value(),
                session_challenge: hash_value(),
            },
            facts: SignerAdmitFactsV1 {
                display: "Public synthetic Admit disclosure only".into(),
                source_identity_digest: hash_value(),
                admission_terms_digest: hash_value(),
                request_digest: SignerContinuePresentationV1::calculate_request_digest(
                    &request_json,
                ),
                request_json,
                original_host_process_instance: hash_value(),
                owner_certificate_digest: hash_value(),
                disclosure_json: "{\"public_fixture\":2}".into(),
                disclosure_digest: hash_value(),
                account_id: "public-account".into(),
                network_profile_id: "public-network".into(),
                operation_id: "public-operation".into(),
                expected_head_sequence: 7,
                expected_head_digest: hash_value(),
                terms_digest: hash_value(),
                reviewed_at_ms: 1_000,
                expires_at_ms: 121_000,
                source_expires_at_ms: 200_000,
            },
            owner_selection_digest: hash_value(),
            continue_presentation_digest: hash_value(),
            prepared_digest: hash_value(),
            admit_challenge: hash_value(),
            source_ceiling_ms: 200_000,
            admit_ceiling_ms: 121_000,
            presentation_digest: String::new(),
        };
        data.presentation_digest = data.calculate_presentation_digest().unwrap();
        data
    }

    #[test]
    fn exact_public_admit_schema_roundtrips_without_becoming_authority() {
        let data = presentation();
        data.validate().unwrap();
        let bytes = serde_json::to_vec(&data).unwrap();
        let decoded: SignerAdmitPresentationV1 = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(data, decoded);
        decoded.validate().unwrap();
    }
    #[test]
    fn unknown_and_duplicate_dto_fields_are_rejected() {
        let data = presentation();
        let json = serde_json::to_string(&data).unwrap();
        for extra in ["\"unknown\":1,", "\"version\":1,"] {
            let text = format!("{{{extra}{}", &json[1..]);
            assert!(serde_json::from_str::<SignerAdmitPresentationV1>(&text).is_err());
        }
        let facts = serde_json::to_string(&data.facts).unwrap();
        for extra in ["\"unknown\":1,", "\"expected_head_sequence\":7,"] {
            let text = format!("{{{extra}{}", &facts[1..]);
            assert!(serde_json::from_str::<SignerAdmitFactsV1>(&text).is_err());
        }
    }
    #[test]
    fn purpose_actor_source_request_disclosure_and_clock_changes_break_commitment() {
        let original = presentation();
        let mut changed = original.clone();
        changed.purpose = "original-financial-continuation-append".into();
        assert!(changed.validate().is_err());
        let mut changed = original.clone();
        changed.actor.coordinator_focus_epoch = 2;
        assert!(changed.validate().is_err());
        let mut changed = original.clone();
        changed.facts.source_identity_digest = "cd".repeat(32);
        assert!(changed.validate().is_err());
        let mut changed = original.clone();
        changed.facts.request_json.push(' ');
        assert!(changed.validate().is_err());
        let mut changed = original.clone();
        changed.facts.disclosure_json.push(' ');
        assert!(changed.validate().is_err());
        let mut changed = original.clone();
        changed.facts.expires_at_ms -= 1;
        assert!(changed.validate().is_err());
        let mut changed = original.clone();
        changed.owner_selection_digest = "cd".repeat(32);
        assert!(changed.validate().is_err());
        let mut changed = original;
        changed.admit_ceiling_ms -= 1;
        assert!(changed.validate().is_err());
    }
    #[test]
    fn original_wall_and_epoch_bounds_reject_renewal_or_overflow() {
        let original = presentation();
        for (start, end, source) in [
            (0, 1, 2),
            (10, 10, 20),
            (10, 9, 20),
            (1, 120_002, 200_000),
            (10, 30, 29),
            (u64::MAX, 1, u64::MAX),
        ] {
            let mut changed = original.clone();
            changed.facts.reviewed_at_ms = start;
            changed.facts.expires_at_ms = end;
            changed.facts.source_expires_at_ms = source;
            assert!(changed.facts.validate().is_err());
        }
        for ceiling in [0, SUPERVISION_MS + 1, u64::MAX] {
            let mut changed = original.clone();
            changed.admit_ceiling_ms = ceiling;
            assert!(changed.validate().is_err());
        }
        let mut changed = original;
        changed.admit_ceiling_ms = changed.source_ceiling_ms + 1;
        assert!(changed.validate().is_err());
    }
    #[test]
    fn field_and_complete_encoding_bounds_reject_instead_of_truncating() {
        let mut data = presentation();
        data.facts.display = "x".repeat(MAX_DISPLAY + 1);
        assert!(data.facts.validate().is_err());
        data = presentation();
        data.facts.display = "\u{202e}hidden".into();
        assert!(data.facts.validate().is_err());
        data = presentation();
        data.facts.network_profile_id = "x".repeat(129);
        assert!(data.facts.validate().is_err());
        data = presentation();
        data.facts.disclosure_json = "not-json".into();
        assert!(data.facts.validate().is_err());
        data = presentation();
        data.facts.display = "x".repeat(MAX_DISPLAY);
        data.facts.request_json = format!("{{\"public\":\"{}\"}}", "x".repeat(30_000));
        data.facts.request_digest =
            SignerContinuePresentationV1::calculate_request_digest(&data.facts.request_json);
        data.facts.validate().unwrap();
        assert!(data.calculate_presentation_digest().is_err());
        assert!(data.validate().is_err());
    }
    #[test]
    fn outcome_and_commit_records_are_strict_observations_not_retry_tokens() {
        let committed = SignerAdmitCommittedV1 {
            presentation_digest: hash_value(),
            admission_ready_digest: hash_value(),
            request_digest: hash_value(),
            head_sequence: 8,
            head_digest: hash_value(),
        };
        committed.validate().unwrap();
        let mut invalid = committed.clone();
        invalid.head_digest = "AB".repeat(32);
        assert!(invalid.validate().is_err());
        for outcome in [
            SignerAdmitOutcomeV1::KnownNoEffect {
                presentation_digest: hash_value(),
                admission_ready_digest: None,
            },
            SignerAdmitOutcomeV1::Uncertain {
                presentation_digest: hash_value(),
                admission_ready_digest: Some(hash_value()),
            },
        ] {
            outcome.validate().unwrap();
            let text = serde_json::to_string(&outcome).unwrap();
            let extra = format!("{{\"unexpected\":1,{}", &text[1..]);
            assert!(serde_json::from_str::<SignerAdmitOutcomeV1>(&extra).is_err());
            let duplicate = format!(
                "{{\"presentation_digest\":\"{}\",{}",
                hash_value(),
                &text[1..]
            );
            assert!(serde_json::from_str::<SignerAdmitOutcomeV1>(&duplicate).is_err());
        }
    }
}
