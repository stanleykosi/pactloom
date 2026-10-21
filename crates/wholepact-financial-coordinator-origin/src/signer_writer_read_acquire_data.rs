//! Closed ordinary review data for one fresh Writer Read and one exact Acquire
//! recipe. Neither validation nor a digest constructs an action, client, session
//! key, authenticated history or FinancialSigning service-ready capability.
use crate::{
    financial_workflow_channel::FinancialActorContextV1, financial_workflow_clock::SUPERVISION_MS,
    rejected, signer_continue_channel::SignerContinuePresentationV1, signer_continue_state::hash,
    Result,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(super) const WRITER_READ_PURPOSE: &str =
    "original-financial-history-and-selected-writer-setup-v1";
pub(super) const WRITER_READ_NOTICE: &str = "Read the exact selected writer TLS key after this approval, construct that restricted writer client, read original owner history once, and prepare one immutable local Acquire recipe. This does not approve Acquire, Activate, Wallet, Sign or Return.";
pub(super) const ACQUIRE_PURPOSE: &str = "acquire-one-exact-exporter-bound-writer-session-v1";
pub(super) const ACQUIRE_NOTICE: &str = "Acquire authorizes one exact reviewed recipe and one actual TLS-exporter-derived writer session. No session identifier, exporter or session key exists in this pre-action presentation. A genuine matching FinancialSigning service must be ready before final approval. No retry or later action is authorized.";
const MAX_PRESENTATION: usize = 60 * 1024;
const READ_DOMAIN: &[u8] = b"wholepact:coordinated-financial-writer-read:presentation:v1\0";
const RECIPE_DOMAIN: &[u8] = b"wholepact:coordinated-financial-acquire:recipe:v1\0";
const ACQUIRE_DOMAIN: &[u8] = b"wholepact:coordinated-financial-acquire:presentation:v1\0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerFinancialWriterReadFactsV1 {
    pub display: String,
    pub source_identity_digest: String,
    pub terms_digest: String,
    pub continuation_request_json: String,
    pub continuation_request_digest: String,
    pub admit_presentation_digest: String,
    pub admit_request_digest: String,
    pub admitted_head_sequence: u64,
    pub admitted_head_digest: String,
    pub original_host_process_instance: String,
    pub owner_certificate_digest: String,
    pub owner_disclosure_digest: String,
    pub writer_selection_digest: String,
    pub writer_certificate_digest: String,
    pub writer_root_digest: String,
    pub writer_disclosure_json: String,
    pub writer_disclosure_digest: String,
    pub reviewed_at_ms: u64,
    pub expires_at_ms: u64,
    pub source_expires_at_ms: u64,
}
impl SignerFinancialWriterReadFactsV1 {
    pub fn validate(&self) -> Result<()> {
        if !text(&self.display, 32 * 1024)
            || !object(&self.continuation_request_json, 32 * 1024)
            || !object(&self.writer_disclosure_json, 16 * 1024)
            || ![
                &self.source_identity_digest,
                &self.terms_digest,
                &self.continuation_request_digest,
                &self.admit_presentation_digest,
                &self.admit_request_digest,
                &self.admitted_head_digest,
                &self.original_host_process_instance,
                &self.owner_certificate_digest,
                &self.owner_disclosure_digest,
                &self.writer_selection_digest,
                &self.writer_certificate_digest,
                &self.writer_root_digest,
                &self.writer_disclosure_digest,
            ]
            .iter()
            .all(|s| hash(s))
            || self.continuation_request_digest
                != SignerContinuePresentationV1::calculate_request_digest(
                    &self.continuation_request_json,
                )
            || self.admit_request_digest != self.continuation_request_digest
            || !wall(
                self.reviewed_at_ms,
                self.expires_at_ms,
                self.source_expires_at_ms,
            )
        {
            return Err(rejected("Writer Read facts rejected"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerFinancialWriterReadPresentationV1 {
    pub version: u16,
    pub purpose: String,
    pub actor: FinancialActorContextV1,
    pub facts: SignerFinancialWriterReadFactsV1,
    pub notice: String,
    pub read_challenge: String,
    pub source_ceiling_ms: u64,
    pub read_ceiling_ms: u64,
    pub presentation_digest: String,
}
impl SignerFinancialWriterReadPresentationV1 {
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
            return Err(rejected("Writer Read presentation commitment rejected"));
        }
        Ok(())
    }
    fn shape(&self) -> Result<()> {
        self.actor.validate()?;
        self.facts.validate()?;
        if self.version != 1
            || self.purpose != WRITER_READ_PURPOSE
            || self.notice != WRITER_READ_NOTICE
            || !hash(&self.read_challenge)
            || !bounds(self.source_ceiling_ms, self.read_ceiling_ms)
            || self.presentation_digest.len() > 64
        {
            return Err(rejected("Writer Read presentation shape rejected"));
        }
        complete(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerAcquireFactsV1 {
    pub display: String,
    pub source_identity_digest: String,
    pub terms_digest: String,
    pub continuation_request_json: String,
    pub continuation_request_digest: String,
    pub admit_presentation_digest: String,
    pub writer_read_presentation_digest: String,
    pub original_host_process_instance: String,
    pub owner_certificate_digest: String,
    pub owner_disclosure_digest: String,
    pub writer_selection_digest: String,
    pub writer_certificate_digest: String,
    pub writer_disclosure_json: String,
    pub writer_disclosure_digest: String,
    pub authenticated_history_digest: String,
    pub authenticated_snapshot_json: String,
    pub expected_head_sequence: u64,
    pub expected_head_digest: String,
    pub acquire_operation_id: String,
    pub writer_epoch: u64,
    pub reviewed_at_ms: u64,
    pub expires_at_ms: u64,
    pub source_expires_at_ms: u64,
}
impl SignerAcquireFactsV1 {
    pub fn validate(&self) -> Result<()> {
        if !text(&self.display, 32 * 1024)
            || !object(&self.continuation_request_json, 32 * 1024)
            || !object(&self.writer_disclosure_json, 16 * 1024)
            || !object(&self.authenticated_snapshot_json, 32 * 1024)
            || ![
                &self.source_identity_digest,
                &self.terms_digest,
                &self.continuation_request_digest,
                &self.admit_presentation_digest,
                &self.writer_read_presentation_digest,
                &self.original_host_process_instance,
                &self.owner_certificate_digest,
                &self.owner_disclosure_digest,
                &self.writer_selection_digest,
                &self.writer_certificate_digest,
                &self.writer_disclosure_digest,
                &self.authenticated_history_digest,
                &self.expected_head_digest,
            ]
            .iter()
            .all(|s| hash(s))
            || !identifier(&self.acquire_operation_id)
            || self.continuation_request_digest
                != SignerContinuePresentationV1::calculate_request_digest(
                    &self.continuation_request_json,
                )
            || !wall(
                self.reviewed_at_ms,
                self.expires_at_ms,
                self.source_expires_at_ms,
            )
        {
            return Err(rejected("Acquire recipe facts rejected"));
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
pub struct SignerAcquirePresentationV1 {
    pub version: u16,
    pub purpose: String,
    pub actor: FinancialActorContextV1,
    pub facts: SignerAcquireFactsV1,
    pub notice: String,
    pub recipe_digest: String,
    pub acquire_challenge: String,
    pub source_ceiling_ms: u64,
    pub acquire_ceiling_ms: u64,
    pub presentation_digest: String,
}
impl SignerAcquirePresentationV1 {
    pub fn calculate_presentation_digest(&self) -> Result<String> {
        self.shape()?;
        digest(
            ACQUIRE_DOMAIN,
            &(
                self.version,
                &self.purpose,
                &self.actor,
                &self.facts,
                &self.notice,
                &self.recipe_digest,
                &self.acquire_challenge,
                self.source_ceiling_ms,
                self.acquire_ceiling_ms,
            ),
        )
    }
    pub fn validate(&self) -> Result<()> {
        self.shape()?;
        if !hash(&self.presentation_digest)
            || self.presentation_digest != self.calculate_presentation_digest()?
        {
            return Err(rejected("Acquire presentation commitment rejected"));
        }
        Ok(())
    }
    fn shape(&self) -> Result<()> {
        self.actor.validate()?;
        self.facts.validate()?;
        if self.version != 1
            || self.purpose != ACQUIRE_PURPOSE
            || self.notice != ACQUIRE_NOTICE
            || !hash(&self.acquire_challenge)
            || self.recipe_digest != self.facts.calculate_recipe_digest()?
            || !bounds(self.source_ceiling_ms, self.acquire_ceiling_ms)
            || self.presentation_digest.len() > 64
        {
            return Err(rejected("Acquire presentation shape rejected"));
        }
        complete(self)
    }
}
/// Reported terminal observations only. An entered Acquire call that cannot
/// authenticate completion is uncertain, not a reusable action or retry ticket.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", deny_unknown_fields)]
pub enum SignerAcquireOutcomeV1 {
    KnownNoEffect {
        presentation_digest: String,
        acquire_ready_digest: Option<String>,
    },
    Uncertain {
        presentation_digest: String,
        acquire_ready_digest: Option<String>,
    },
}
impl SignerAcquireOutcomeV1 {
    pub fn validate(&self) -> Result<()> {
        let (p, r) = self.parts();
        if !hash(p) || r.is_some_and(|d| !hash(d)) {
            return Err(rejected("Acquire outcome shape rejected"));
        }
        Ok(())
    }
    pub(super) fn parts(&self) -> (&str, Option<&str>) {
        match self {
            Self::KnownNoEffect {
                presentation_digest,
                acquire_ready_digest,
            }
            | Self::Uncertain {
                presentation_digest,
                acquire_ready_digest,
            } => (presentation_digest, acquire_ready_digest.as_deref()),
        }
    }
}
fn digest(domain: &[u8], value: &impl Serialize) -> Result<String> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| rejected("writer review encoding rejected"))?;
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    Ok(hex::encode(hash.finalize()))
}
fn complete(value: &impl Serialize) -> Result<()> {
    if serde_json::to_vec(value)
        .map_err(|_| rejected("writer presentation encoding rejected"))?
        .len()
        > MAX_PRESENTATION
    {
        return Err(rejected(
            "writer presentation exceeds complete frame budget",
        ));
    }
    Ok(())
}
fn text(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b == b'\n' || b == b'\t' || (0x20..=0x7e).contains(&b))
}
fn object(s: &str, max: usize) -> bool {
    text(s, max) && serde_json::from_str::<serde_json::Value>(s).is_ok_and(|v| v.is_object())
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}
fn wall(start: u64, end: u64, source: u64) -> bool {
    start > 0 && end > start && end - start <= 120_000 && end <= source
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
    pub(crate) fn read() -> SignerFinancialWriterReadPresentationV1 {
        let request = "{\"public_fixture\":1}".to_owned();
        let mut p = SignerFinancialWriterReadPresentationV1 {
            version: 1,
            purpose: WRITER_READ_PURPOSE.into(),
            actor: crate::financial_workflow_channel::sample_entry()
                .presentation
                .actor,
            facts: SignerFinancialWriterReadFactsV1 {
                display: "Public synthetic writer Read only".into(),
                source_identity_digest: h(),
                terms_digest: h(),
                continuation_request_digest: SignerContinuePresentationV1::calculate_request_digest(
                    &request,
                ),
                admit_request_digest: SignerContinuePresentationV1::calculate_request_digest(
                    &request,
                ),
                continuation_request_json: request,
                admit_presentation_digest: h(),
                admitted_head_sequence: 20,
                admitted_head_digest: h(),
                original_host_process_instance: h(),
                owner_certificate_digest: h(),
                owner_disclosure_digest: h(),
                writer_selection_digest: h(),
                writer_certificate_digest: h(),
                writer_root_digest: h(),
                writer_disclosure_json: "{\"public_fixture\":2}".into(),
                writer_disclosure_digest: h(),
                reviewed_at_ms: 1000,
                expires_at_ms: 121000,
                source_expires_at_ms: 300000,
            },
            notice: WRITER_READ_NOTICE.into(),
            read_challenge: h(),
            source_ceiling_ms: 300000,
            read_ceiling_ms: 121000,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest().unwrap();
        p
    }
    pub(crate) fn acquire(
        r: &SignerFinancialWriterReadPresentationV1,
    ) -> SignerAcquirePresentationV1 {
        let f = &r.facts;
        let facts = SignerAcquireFactsV1 {
            display: "Public synthetic exporter recipe, not a created session".into(),
            source_identity_digest: f.source_identity_digest.clone(),
            terms_digest: f.terms_digest.clone(),
            continuation_request_json: f.continuation_request_json.clone(),
            continuation_request_digest: f.continuation_request_digest.clone(),
            admit_presentation_digest: f.admit_presentation_digest.clone(),
            writer_read_presentation_digest: r.presentation_digest.clone(),
            original_host_process_instance: f.original_host_process_instance.clone(),
            owner_certificate_digest: f.owner_certificate_digest.clone(),
            owner_disclosure_digest: f.owner_disclosure_digest.clone(),
            writer_selection_digest: f.writer_selection_digest.clone(),
            writer_certificate_digest: f.writer_certificate_digest.clone(),
            writer_disclosure_json: f.writer_disclosure_json.clone(),
            writer_disclosure_digest: f.writer_disclosure_digest.clone(),
            authenticated_history_digest: h(),
            authenticated_snapshot_json: "{\"public_fixture\":3}".into(),
            expected_head_sequence: 20,
            expected_head_digest: f.admitted_head_digest.clone(),
            acquire_operation_id: "public-acquire-operation".into(),
            writer_epoch: 1,
            reviewed_at_ms: 2000,
            expires_at_ms: 122000,
            source_expires_at_ms: f.source_expires_at_ms,
        };
        let mut p = SignerAcquirePresentationV1 {
            version: 1,
            purpose: ACQUIRE_PURPOSE.into(),
            actor: r.actor.clone(),
            recipe_digest: facts.calculate_recipe_digest().unwrap(),
            facts,
            notice: ACQUIRE_NOTICE.into(),
            acquire_challenge: h(),
            source_ceiling_ms: r.source_ceiling_ms,
            acquire_ceiling_ms: 122000,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest().unwrap();
        p
    }
    #[test]
    fn writer_read_and_acquire_data_are_strict_distinct_complete_commitments() {
        let r = read();
        let a = acquire(&r);
        r.validate().unwrap();
        a.validate().unwrap();
        let rjson = serde_json::to_string(&r).unwrap();
        let ajson = serde_json::to_string(&a).unwrap();
        assert_eq!(
            r,
            serde_json::from_str::<SignerFinancialWriterReadPresentationV1>(&rjson).unwrap()
        );
        assert_eq!(
            a,
            serde_json::from_str::<SignerAcquirePresentationV1>(&ajson).unwrap()
        );
        for prefix in ["\"unknown\":1,", "\"version\":1,"] {
            assert!(
                serde_json::from_str::<SignerFinancialWriterReadPresentationV1>(&format!(
                    "{{{prefix}{}",
                    &rjson[1..]
                ))
                .is_err()
            );
            assert!(
                serde_json::from_str::<SignerAcquirePresentationV1>(&format!(
                    "{{{prefix}{}",
                    &ajson[1..]
                ))
                .is_err()
            );
        }
        let facts = serde_json::to_string(&a.facts).unwrap();
        for prefix in ["\"session_id\":\"invented\",", "\"writer_epoch\":1,"] {
            assert!(serde_json::from_str::<SignerAcquireFactsV1>(&format!(
                "{{{prefix}{}",
                &facts[1..]
            ))
            .is_err());
        }
        assert_ne!(a.recipe_digest, a.presentation_digest);
        assert_ne!(r.presentation_digest, a.presentation_digest);
        let mut changed = a.clone();
        changed.facts.authenticated_snapshot_json.push(' ');
        assert!(changed.validate().is_err());
        let mut changed = a.clone();
        changed.facts.acquire_operation_id.push('x');
        assert!(changed.validate().is_err());
        let mut changed = a.clone();
        changed.acquire_ceiling_ms -= 1;
        assert!(changed.validate().is_err());
        let mut changed = a;
        changed.notice.push(' ');
        assert!(changed.validate().is_err());
        let mut changed = r;
        changed.facts.writer_root_digest = "cd".repeat(32);
        assert!(changed.validate().is_err());
    }
    #[test]
    fn writer_review_data_rejects_expansion_and_oversized_complete_frames() {
        let original = read();
        for (start, end, source) in [
            (0, 1, 2),
            (10, 10, 20),
            (1, 120002, 200000),
            (10, 30, 29),
            (u64::MAX, 1, u64::MAX),
        ] {
            let mut p = original.clone();
            p.facts.reviewed_at_ms = start;
            p.facts.expires_at_ms = end;
            p.facts.source_expires_at_ms = source;
            assert!(p.facts.validate().is_err());
        }
        let mut p = original.clone();
        p.read_ceiling_ms = p.source_ceiling_ms + 1;
        assert!(p.validate().is_err());
        let mut p = original.clone();
        p.facts.display = "\u{202e}hidden".into();
        assert!(p.facts.validate().is_err());
        let mut p = original;
        p.facts.display = "x".repeat(32 * 1024);
        p.facts.continuation_request_json = format!("{{\"public\":\"{}\"}}", "x".repeat(30000));
        p.facts.continuation_request_digest =
            SignerContinuePresentationV1::calculate_request_digest(
                &p.facts.continuation_request_json,
            );
        p.facts.admit_request_digest = p.facts.continuation_request_digest.clone();
        p.facts.validate().unwrap();
        assert!(p.calculate_presentation_digest().is_err());
    }
}
