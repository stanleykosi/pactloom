//! Ordinary data for one post-Acquire Read and one exact owner activation.
//! No value here creates a source, writer key, native action or service owner.
//! Wallet preparation is deliberately NOT part of activation or this schema.
use crate::{
    financial_workflow_channel::FinancialActorContextV1, financial_workflow_clock::SUPERVISION_MS,
    rejected, signer_continue_channel::SignerContinuePresentationV1, signer_continue_state::hash,
    signer_writer_read_acquire_data::SignerAcquireCommittedV1, Result,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(super) const ACTIVATE_READ_PURPOSE: &str =
    "original-financial-owner-history-and-one-activation-preparation-v1";
pub(super) const ACTIVATE_READ_NOTICE: &str = "Read one complete original owner history using the same retained owner client, match the entire actual acquired writer receipt, and prepare one immutable ActivateWriter request. No new credential, writer session, Activate effect, wallet preparation, observation, signature or Return is approved.";
pub(super) const ACTIVATE_PURPOSE: &str = "activate-one-exact-original-financial-writer-v1";
pub(super) const ACTIVATE_NOTICE: &str = "Activate only the exact reviewed pending session through the same original owner client and genuine current FinancialSigning service. The writer key remains solely in the same retained writer client. One attempt only; an uncertain response never permits retry, a replacement session, wallet preparation, signing or Return.";
const MAX_PRESENTATION: usize = 60 * 1024;
const READ_DOMAIN: &[u8] = b"wholepact:coordinated-financial-activate-read:presentation:v1\0";
const REQUEST_DOMAIN: &[u8] = b"wholepact:coordinated-financial-activate:request:v1\0";
const RECIPE_DOMAIN: &[u8] = b"wholepact:coordinated-financial-activate:recipe:v1\0";
const ACTIVATE_DOMAIN: &[u8] = b"wholepact:coordinated-financial-activate:presentation:v1\0";

/// Exact retained observations, not an importer. The issuer independently
/// matches ALL fields against its actual Acquire result and service. The
/// original writer-session Instant is retained separately by the real owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerActivateOriginalV1 {
    pub source_identity_digest: String,
    pub terms_digest: String,
    pub continuation_request_json: String,
    pub continuation_request_digest: String,
    pub original_host_process_instance: String,
    pub owner_certificate_digest: String,
    pub owner_disclosure_digest: String,
    pub writer_selection_digest: String,
    pub acquired: SignerAcquireCommittedV1,
    pub source_expires_at_ms: u64,
}
impl SignerActivateOriginalV1 {
    pub fn validate(&self) -> Result<()> {
        self.acquired.validate()?;
        if !object(&self.continuation_request_json, 32 * 1024)
            || ![
                &self.source_identity_digest,
                &self.terms_digest,
                &self.continuation_request_digest,
                &self.original_host_process_instance,
                &self.owner_certificate_digest,
                &self.owner_disclosure_digest,
                &self.writer_selection_digest,
            ]
            .iter()
            .all(|v| hash(v))
            || self.continuation_request_digest
                != SignerContinuePresentationV1::calculate_request_digest(
                    &self.continuation_request_json,
                )
            || self.acquired.disclosure_digest != self.owner_disclosure_digest
            || self.acquired.expires_at_ms > self.source_expires_at_ms
        {
            return Err(rejected("Activate original observations rejected"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerActivateReadFactsV1 {
    pub display: String,
    pub original: SignerActivateOriginalV1,
    pub reviewed_at_ms: u64,
    pub expires_at_ms: u64,
}
impl SignerActivateReadFactsV1 {
    pub fn validate(&self) -> Result<()> {
        self.original.validate()?;
        if !text(&self.display, 32 * 1024)
            || !wall(self.reviewed_at_ms, self.expires_at_ms, &self.original)
        {
            return Err(rejected("Activate Read facts rejected"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerActivateReadPresentationV1 {
    pub version: u16,
    pub purpose: String,
    pub actor: FinancialActorContextV1,
    pub facts: SignerActivateReadFactsV1,
    pub notice: String,
    pub read_challenge: String,
    pub source_ceiling_ms: u64,
    pub read_ceiling_ms: u64,
    pub presentation_digest: String,
}
impl SignerActivateReadPresentationV1 {
    fn shape(&self) -> Result<()> {
        self.actor.validate()?;
        self.facts.validate()?;
        if self.version != 1
            || self.purpose != ACTIVATE_READ_PURPOSE
            || self.notice != ACTIVATE_READ_NOTICE
            || !hash(&self.read_challenge)
            || !bounds(self.source_ceiling_ms, self.read_ceiling_ms)
            || self.presentation_digest.len() > 64
        {
            return Err(rejected("Activate Read presentation shape rejected"));
        }
        complete(self)
    }
    pub fn calculate_presentation_digest(&self) -> Result<String> {
        self.shape()?;
        digest(
            READ_DOMAIN,
            &(
                self.version,
                &self.purpose,
                &self.actor,
                &self.facts,
                &self.notice,
                &self.read_challenge,
                self.source_ceiling_ms,
                self.read_ceiling_ms,
            ),
        )
    }
    pub fn validate(&self) -> Result<()> {
        self.shape()?;
        if !hash(&self.presentation_digest)
            || self.presentation_digest != self.calculate_presentation_digest()?
        {
            return Err(rejected("Activate Read presentation commitment rejected"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerActivateFactsV1 {
    pub display: String,
    pub original: SignerActivateOriginalV1,
    pub activate_read_presentation_digest: String,
    pub authenticated_history_digest: String,
    pub authenticated_snapshot_json: String,
    pub activation_request_json: String,
    pub activation_request_digest: String,
    pub activation_terms_digest: String,
    pub expected_head_sequence: u64,
    pub expected_head_digest: String,
    pub writer_epoch: u64,
    pub reviewed_at_ms: u64,
    pub expires_at_ms: u64,
}
impl SignerActivateFactsV1 {
    pub fn calculate_request_digest(request_json: &str) -> String {
        let mut h = Sha256::new();
        h.update(REQUEST_DOMAIN);
        h.update(request_json.as_bytes());
        hex::encode(h.finalize())
    }
    pub fn validate(&self) -> Result<()> {
        self.original.validate()?;
        if !text(&self.display, 32 * 1024)
            || !object(&self.authenticated_snapshot_json, 32 * 1024)
            || !object(&self.activation_request_json, 32 * 1024)
            || ![
                &self.activate_read_presentation_digest,
                &self.authenticated_history_digest,
                &self.activation_request_digest,
                &self.activation_terms_digest,
                &self.expected_head_digest,
            ]
            .iter()
            .all(|v| hash(v))
            || self.activation_request_digest
                != Self::calculate_request_digest(&self.activation_request_json)
            || self.expected_head_sequence != self.original.acquired.acquired_head_sequence
            || self.expected_head_digest != self.original.acquired.acquired_head_digest
            || self.writer_epoch != self.original.acquired.writer_epoch
            || !wall(self.reviewed_at_ms, self.expires_at_ms, &self.original)
        {
            return Err(rejected("Activate recipe facts rejected"));
        }
        Ok(())
    }
    pub fn calculate_recipe_digest(&self) -> Result<String> {
        self.validate()?;
        digest(RECIPE_DOMAIN, self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerActivatePresentationV1 {
    pub version: u16,
    pub purpose: String,
    pub actor: FinancialActorContextV1,
    pub facts: SignerActivateFactsV1,
    pub notice: String,
    pub recipe_digest: String,
    pub activate_challenge: String,
    pub source_ceiling_ms: u64,
    pub activate_ceiling_ms: u64,
    pub presentation_digest: String,
}
impl SignerActivatePresentationV1 {
    fn shape(&self) -> Result<()> {
        self.actor.validate()?;
        self.facts.validate()?;
        if self.version != 1
            || self.purpose != ACTIVATE_PURPOSE
            || self.notice != ACTIVATE_NOTICE
            || !hash(&self.activate_challenge)
            || self.recipe_digest != self.facts.calculate_recipe_digest()?
            || !bounds(self.source_ceiling_ms, self.activate_ceiling_ms)
            || self.presentation_digest.len() > 64
        {
            return Err(rejected("Activate presentation shape rejected"));
        }
        complete(self)
    }
    pub fn calculate_presentation_digest(&self) -> Result<String> {
        self.shape()?;
        digest(
            ACTIVATE_DOMAIN,
            &(
                self.version,
                &self.purpose,
                &self.actor,
                &self.facts,
                &self.notice,
                &self.recipe_digest,
                &self.activate_challenge,
                self.source_ceiling_ms,
                self.activate_ceiling_ms,
            ),
        )
    }
    pub fn validate(&self) -> Result<()> {
        self.shape()?;
        if !hash(&self.presentation_digest)
            || self.presentation_digest != self.calculate_presentation_digest()?
        {
            return Err(rejected("Activate presentation commitment rejected"));
        }
        Ok(())
    }
}

/// Authenticated result observation only, never a Wallet or subsequent grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerActivateCommittedV1 {
    pub presentation_digest: String,
    pub activate_ready_digest: String,
    pub activation_request_digest: String,
    pub signing_service_digest: String,
    pub session_id: String,
    pub writer_epoch: u64,
    pub head_sequence: u64,
    pub head_digest: String,
}
impl SignerActivateCommittedV1 {
    pub fn validate(&self) -> Result<()> {
        if ![
            &self.presentation_digest,
            &self.activate_ready_digest,
            &self.activation_request_digest,
            &self.signing_service_digest,
            &self.session_id,
            &self.head_digest,
        ]
        .iter()
        .all(|v| hash(v))
        {
            return Err(rejected("Activated observation rejected"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", deny_unknown_fields)]
pub enum SignerActivateOutcomeV1 {
    KnownNoEffect {
        presentation_digest: String,
        activate_ready_digest: Option<String>,
    },
    Uncertain {
        presentation_digest: String,
        activate_ready_digest: Option<String>,
    },
}
impl SignerActivateOutcomeV1 {
    pub(super) fn parts(&self) -> (&str, Option<&str>) {
        match self {
            Self::KnownNoEffect {
                presentation_digest,
                activate_ready_digest,
            }
            | Self::Uncertain {
                presentation_digest,
                activate_ready_digest,
            } => (presentation_digest, activate_ready_digest.as_deref()),
        }
    }
    pub fn validate(&self) -> Result<()> {
        let (presentation, ready) = self.parts();
        if !hash(presentation) || ready.is_some_and(|d| !hash(d)) {
            return Err(rejected("Activate outcome rejected"));
        }
        Ok(())
    }
}

fn digest(domain: &[u8], value: &impl Serialize) -> Result<String> {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(serde_json::to_vec(value).map_err(|_| rejected("Activate encoding rejected"))?);
    Ok(hex::encode(h.finalize()))
}
fn complete(value: &impl Serialize) -> Result<()> {
    if serde_json::to_vec(value)
        .map_err(|_| rejected("Activate presentation encoding rejected"))?
        .len()
        > MAX_PRESENTATION
    {
        return Err(rejected(
            "Activate complete presentation exceeds frame budget",
        ));
    }
    Ok(())
}
fn text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|b| b == b'\n' || b == b'\t' || (0x20..=0x7e).contains(&b))
}
fn object(value: &str, maximum: usize) -> bool {
    text(value, maximum)
        && serde_json::from_str::<serde_json::Value>(value).is_ok_and(|v| v.is_object())
}
fn wall(start: u64, end: u64, original: &SignerActivateOriginalV1) -> bool {
    start >= original.acquired.acquired_at_ms
        && start > 0
        && end > start
        && end - start <= 120_000
        && end <= original.source_expires_at_ms
        && end <= original.acquired.expires_at_ms
}
fn bounds(source: u64, action: u64) -> bool {
    source > 0 && source <= SUPERVISION_MS && action > 0 && action <= source
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    fn h() -> String {
        "ab".repeat(32)
    }
    pub(crate) fn read() -> SignerActivateReadPresentationV1 {
        let request = "{\"public_fixture\":1}".to_owned();
        let mut p = SignerActivateReadPresentationV1 {
            version: 1,
            purpose: ACTIVATE_READ_PURPOSE.into(),
            actor: crate::financial_workflow_channel::sample_entry()
                .presentation
                .actor,
            facts: SignerActivateReadFactsV1 {
                display: "Public fabricated Activate Read".into(),
                original: SignerActivateOriginalV1 {
                    source_identity_digest: h(),
                    terms_digest: h(),
                    continuation_request_digest:
                        SignerContinuePresentationV1::calculate_request_digest(&request),
                    continuation_request_json: request,
                    original_host_process_instance: h(),
                    owner_certificate_digest: h(),
                    owner_disclosure_digest: h(),
                    writer_selection_digest: h(),
                    acquired: SignerAcquireCommittedV1 {
                        presentation_digest: h(),
                        recipe_digest: h(),
                        acquire_ready_digest: h(),
                        signing_service_digest: h(),
                        session_id: h(),
                        writer_certificate_digest: h(),
                        writer_epoch: 4,
                        reconciled_head_sequence: 21,
                        reconciled_head_digest: h(),
                        reconciled_history_digest: h(),
                        acquired_head_sequence: 22,
                        acquired_head_digest: h(),
                        acquired_at_ms: 1000,
                        expires_at_ms: 200000,
                        disclosure_json: "{\"public_fixture\":2}".into(),
                        disclosure_digest: h(),
                    },
                    source_expires_at_ms: 300000,
                },
                reviewed_at_ms: 2000,
                expires_at_ms: 122000,
            },
            notice: ACTIVATE_READ_NOTICE.into(),
            read_challenge: h(),
            source_ceiling_ms: 300000,
            read_ceiling_ms: 122000,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest().unwrap();
        p
    }
    pub(crate) fn activate() -> SignerActivatePresentationV1 {
        let read = read();
        let request = "{\"public_activation_fixture\":3}".to_owned();
        let facts = SignerActivateFactsV1 {
            display: "Public fabricated exact activation".into(),
            original: read.facts.original,
            activate_read_presentation_digest: read.presentation_digest,
            authenticated_history_digest: h(),
            authenticated_snapshot_json: "{\"public_snapshot_fixture\":4}".into(),
            activation_request_digest: SignerActivateFactsV1::calculate_request_digest(&request),
            activation_request_json: request,
            activation_terms_digest: h(),
            expected_head_sequence: 22,
            expected_head_digest: h(),
            writer_epoch: 4,
            reviewed_at_ms: 3000,
            expires_at_ms: 123000,
        };
        let mut p = SignerActivatePresentationV1 {
            version: 1,
            purpose: ACTIVATE_PURPOSE.into(),
            actor: read.actor,
            notice: ACTIVATE_NOTICE.into(),
            recipe_digest: facts.calculate_recipe_digest().unwrap(),
            facts,
            activate_challenge: h(),
            source_ceiling_ms: 300000,
            activate_ceiling_ms: 123000,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest().unwrap();
        p
    }

    #[test]
    fn activate_data_roundtrips_without_any_source_or_token() {
        let r = read();
        r.validate().unwrap();
        assert_eq!(
            serde_json::from_slice::<SignerActivateReadPresentationV1>(
                &serde_json::to_vec(&r).unwrap()
            )
            .unwrap(),
            r
        );
        let a = activate();
        a.validate().unwrap();
        assert_eq!(
            serde_json::from_slice::<SignerActivatePresentationV1>(
                &serde_json::to_vec(&a).unwrap()
            )
            .unwrap(),
            a
        );
    }

    #[test]
    fn activate_data_rejects_unknown_duplicate_and_wrong_purpose() {
        let r = read();
        let encoded = serde_json::to_string(&r).unwrap();
        for prefix in ["\"unexpected\":1,", "\"version\":1,"] {
            let raw = format!("{{{prefix}{}", &encoded[1..]);
            assert!(serde_json::from_str::<SignerActivateReadPresentationV1>(&raw).is_err());
        }
        let mut a = activate();
        a.purpose = ACTIVATE_READ_PURPOSE.into();
        assert!(a.calculate_presentation_digest().is_err());
        let mut r = read();
        r.notice.push_str(" Approve signing too.");
        assert!(r.calculate_presentation_digest().is_err());
    }

    #[test]
    fn activate_data_keeps_exact_request_and_receipt_bound_in_digest() {
        let r = read();
        let mut changed = r.clone();
        changed.facts.original.acquired.session_id = "cd".repeat(32);
        assert_ne!(
            r.presentation_digest,
            changed.calculate_presentation_digest().unwrap()
        );
        assert!(changed.validate().is_err());
        let mut a = activate();
        a.facts.activation_request_json.push(' ');
        assert!(a.facts.validate().is_err());
        let mut original = r.facts.original;
        original.continuation_request_json.push(' ');
        assert!(original.validate().is_err());
    }

    #[test]
    fn activate_data_rejects_rebased_head_epoch_and_receipt_disclosure() {
        for selector in 0..4 {
            let mut a = activate();
            match selector {
                0 => a.facts.expected_head_sequence += 1,
                1 => a.facts.expected_head_digest = "cd".repeat(32),
                2 => a.facts.writer_epoch += 1,
                _ => a.facts.original.acquired.disclosure_digest = "cd".repeat(32),
            }
            assert!(a.facts.validate().is_err());
        }
    }

    #[test]
    fn activate_data_caps_each_own_interval_by_original_receipt_and_source() {
        let r = read();
        let mut a = activate();
        // The actual issuer must capture this independent interval while Read
        // is live. Its ending need not inherit Read's ending, but it cannot
        // extend the original receipt/source or exceed 120 seconds.
        assert!(a.facts.reviewed_at_ms < r.facts.expires_at_ms);
        assert!(a.facts.expires_at_ms > r.facts.expires_at_ms);
        a.facts.validate().unwrap();
        for (start, end) in [(999, 10000), (2000, 122001), (190000, 200001), (2000, 2000)] {
            a.facts.reviewed_at_ms = start;
            a.facts.expires_at_ms = end;
            assert!(a.facts.validate().is_err());
        }
        let mut r = read();
        r.facts.original.source_expires_at_ms = 199999;
        assert!(r.facts.validate().is_err());
    }

    #[test]
    fn activate_data_full_encoded_cap_dominates_individual_fields() {
        let mut a = activate();
        a.facts.display = "x".repeat(32 * 1024);
        a.facts.authenticated_snapshot_json =
            format!("{{\"public\":\"{}\"}}", "x".repeat(31 * 1024));
        a.facts.validate().unwrap();
        a.recipe_digest = a.facts.calculate_recipe_digest().unwrap();
        assert!(a.calculate_presentation_digest().is_err());
        let mut r = read();
        r.facts.display = "\u{202e}".into();
        assert!(r.facts.validate().is_err());
    }

    #[test]
    fn activate_data_terminal_observations_do_not_infer_effect_from_loss() {
        let a = activate();
        let no_effect = SignerActivateOutcomeV1::KnownNoEffect {
            presentation_digest: a.presentation_digest.clone(),
            activate_ready_digest: None,
        };
        let uncertain = SignerActivateOutcomeV1::Uncertain {
            presentation_digest: a.presentation_digest,
            activate_ready_digest: Some(h()),
        };
        no_effect.validate().unwrap();
        uncertain.validate().unwrap();
        assert_ne!(
            serde_json::to_vec(&no_effect).unwrap(),
            serde_json::to_vec(&uncertain).unwrap()
        );
        let invalid = SignerActivateOutcomeV1::Uncertain {
            presentation_digest: h(),
            activate_ready_digest: Some("not-a-digest".into()),
        };
        assert!(invalid.validate().is_err());
    }
}
