//! Exact fresh enrollment/manifest reviews; historical records never mint receipts.
use crate::signer_v3_pair_data::digest;
use crate::{
    financial_workflow_channel::FinancialActorContextV1, rejected, signer_continue_state::hash,
    Result,
};
use serde::{Deserialize, Serialize};
pub(crate) const ENROLLMENT_NOTICE:&str="Approve only this exact fresh account enrollment record for the current original paired session. Historical enrollment and manifest references are data, not current approval. No manifest, export, redisclosure, delivery or financial action is approved.";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3EnrollmentFactsV1 {
    pub entry_presentation_digest: String,
    pub source_identity_digest: String,
    pub pair_grant_id: String,
    pub pair_key_digest: String,
    pub pair_channel_digest: String,
    pub record_reference: String,
    pub record_json: String,
    pub coordinated_session_id: String,
    pub receipt_nonce: String,
    pub display: String,
    pub historical_enrollment_ref: String,
    pub historical_manifest_ref: String,
    pub pair_generation: u64,
    pub reviewed_at_ms: u64,
    pub expires_at_ms: u64,
    pub source_expires_at_ms: u64,
}
impl SignerV3EnrollmentFactsV1 {
    pub fn validate(&self) -> Result<()> {
        if ![
            &self.entry_presentation_digest,
            &self.source_identity_digest,
            &self.pair_grant_id,
            &self.pair_key_digest,
            &self.pair_channel_digest,
            &self.record_reference,
            &self.coordinated_session_id,
            &self.receipt_nonce,
            &self.historical_enrollment_ref,
            &self.historical_manifest_ref,
        ]
        .iter()
        .all(|s| hash(s))
            || self.pair_generation != 1
            || self.record_json.len() > 32 * 1024
            || !serde_json::from_str::<serde_json::Value>(&self.record_json)
                .is_ok_and(|v| v.is_object())
            || self.display.is_empty()
            || self.display.len() > 8192
            || self.reviewed_at_ms == 0
            || self.expires_at_ms <= self.reviewed_at_ms
            || self.expires_at_ms - self.reviewed_at_ms > 120000
            || self.expires_at_ms > self.source_expires_at_ms
            || serde_json::to_vec(self)
                .map_err(|_| rejected("receipt facts encoding"))?
                .len()
                > 48 * 1024
        {
            return Err(rejected("fresh receipt exact facts"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3EnrollmentPresentationV1 {
    pub actor: FinancialActorContextV1,
    pub facts: SignerV3EnrollmentFactsV1,
    pub notice: String,
    pub challenge: String,
    pub source_ceiling_ms: u64,
    pub review_ceiling_ms: u64,
    pub presentation_digest: String,
}
impl SignerV3EnrollmentPresentationV1 {
    pub fn calculate_presentation_digest(&self) -> Result<String> {
        digest(
            b"wholepact:coordinated-v3-fresh-enrollment:presentation:v1\0",
            &(
                &self.actor,
                &self.facts,
                &self.notice,
                &self.challenge,
                self.source_ceiling_ms,
                self.review_ceiling_ms,
            ),
        )
    }
    pub fn validate(&self) -> Result<()> {
        self.actor.validate()?;
        self.facts.validate()?;
        if self.notice != ENROLLMENT_NOTICE
            || !hash(&self.challenge)
            || self.review_ceiling_ms == 0
            || self.review_ceiling_ms > self.source_ceiling_ms
            || self.source_ceiling_ms > crate::financial_workflow_clock::SUPERVISION_MS
            || self.presentation_digest != self.calculate_presentation_digest()?
            || serde_json::to_vec(self)
                .map_err(|_| rejected("receipt presentation encoding"))?
                .len()
                > 60 * 1024
        {
            return Err(rejected("fresh receipt presentation"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3EnrollmentCommittedV1 {
    pub presentation_digest: String,
    pub record_reference: String,
}
impl SignerV3EnrollmentCommittedV1 {
    pub fn validate(&self) -> Result<()> {
        if !hash(&self.presentation_digest) || !hash(&self.record_reference) {
            return Err(rejected("receipt committed observation"));
        }
        Ok(())
    }
}
pub(crate) const MANIFEST_NOTICE:&str="Approve only this exact fresh accepted-manifest record under the retained freshly approved current enrollment and original paired session. No private Read, export, redisclosure, delivery or financial action is approved.";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3ManifestFactsV1 {
    pub entry_presentation_digest: String,
    pub source_identity_digest: String,
    pub pair_grant_id: String,
    pub pair_key_digest: String,
    pub pair_channel_digest: String,
    pub record_reference: String,
    pub record_json: String,
    pub coordinated_session_id: String,
    pub receipt_nonce: String,
    pub display: String,
    pub current_enrollment_ref: String,
    pub pair_generation: u64,
    pub reviewed_at_ms: u64,
    pub expires_at_ms: u64,
    pub source_expires_at_ms: u64,
}
impl SignerV3ManifestFactsV1 {
    pub fn validate(&self) -> Result<()> {
        if ![
            &self.entry_presentation_digest,
            &self.source_identity_digest,
            &self.pair_grant_id,
            &self.pair_key_digest,
            &self.pair_channel_digest,
            &self.record_reference,
            &self.coordinated_session_id,
            &self.receipt_nonce,
            &self.current_enrollment_ref,
        ]
        .iter()
        .all(|s| hash(s))
            || self.pair_generation != 1
            || self.record_json.len() > 32 * 1024
            || !serde_json::from_str::<serde_json::Value>(&self.record_json)
                .is_ok_and(|v| v.is_object())
            || self.display.is_empty()
            || self.display.len() > 8192
            || self.reviewed_at_ms == 0
            || self.expires_at_ms <= self.reviewed_at_ms
            || self.expires_at_ms - self.reviewed_at_ms > 120000
            || self.expires_at_ms > self.source_expires_at_ms
            || serde_json::to_vec(self)
                .map_err(|_| rejected("receipt facts encoding"))?
                .len()
                > 48 * 1024
        {
            return Err(rejected("fresh receipt exact facts"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3ManifestPresentationV1 {
    pub actor: FinancialActorContextV1,
    pub facts: SignerV3ManifestFactsV1,
    pub notice: String,
    pub challenge: String,
    pub source_ceiling_ms: u64,
    pub review_ceiling_ms: u64,
    pub presentation_digest: String,
}
impl SignerV3ManifestPresentationV1 {
    pub fn calculate_presentation_digest(&self) -> Result<String> {
        digest(
            b"wholepact:coordinated-v3-fresh-manifest:presentation:v1\0",
            &(
                &self.actor,
                &self.facts,
                &self.notice,
                &self.challenge,
                self.source_ceiling_ms,
                self.review_ceiling_ms,
            ),
        )
    }
    pub fn validate(&self) -> Result<()> {
        self.actor.validate()?;
        self.facts.validate()?;
        if self.notice != MANIFEST_NOTICE
            || !hash(&self.challenge)
            || self.review_ceiling_ms == 0
            || self.review_ceiling_ms > self.source_ceiling_ms
            || self.source_ceiling_ms > crate::financial_workflow_clock::SUPERVISION_MS
            || self.presentation_digest != self.calculate_presentation_digest()?
            || serde_json::to_vec(self)
                .map_err(|_| rejected("receipt presentation encoding"))?
                .len()
                > 60 * 1024
        {
            return Err(rejected("fresh receipt presentation"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3ManifestCommittedV1 {
    pub presentation_digest: String,
    pub record_reference: String,
}
impl SignerV3ManifestCommittedV1 {
    pub fn validate(&self) -> Result<()> {
        if !hash(&self.presentation_digest) || !hash(&self.record_reference) {
            return Err(rejected("receipt committed observation"));
        }
        Ok(())
    }
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) fn enrollment() -> SignerV3EnrollmentPresentationV1 {
        let pair = crate::signer_v3_pair_data::tests::presentation();
        let h = "ab".repeat(32);
        let f = SignerV3EnrollmentFactsV1 {
            entry_presentation_digest: pair.facts.entry_presentation_digest,
            source_identity_digest: pair.facts.source_identity_digest,
            pair_grant_id: h.clone(),
            pair_key_digest: h.clone(),
            pair_channel_digest: pair.facts.pairing_review_digest,
            record_reference: h.clone(),
            record_json: "{\"complete_actual_record\":true}".into(),
            coordinated_session_id: h.clone(),
            receipt_nonce: h.clone(),
            display: "Full fresh enrollment".into(),
            historical_enrollment_ref: h.clone(),
            historical_manifest_ref: h,
            pair_generation: 1,
            reviewed_at_ms: 1100,
            expires_at_ms: 2100,
            source_expires_at_ms: pair.facts.source_expires_at_ms,
        };
        let mut p = SignerV3EnrollmentPresentationV1 {
            actor: pair.actor,
            facts: f,
            notice: ENROLLMENT_NOTICE.into(),
            challenge: "cd".repeat(32),
            source_ceiling_ms: 3000,
            review_ceiling_ms: 2100,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest().unwrap();
        p
    }
    pub(crate) fn manifest() -> SignerV3ManifestPresentationV1 {
        let e = enrollment();
        let f = e.facts;
        let mut p = SignerV3ManifestPresentationV1 {
            actor: e.actor,
            facts: SignerV3ManifestFactsV1 {
                entry_presentation_digest: f.entry_presentation_digest,
                source_identity_digest: f.source_identity_digest,
                pair_grant_id: f.pair_grant_id,
                pair_key_digest: f.pair_key_digest,
                pair_channel_digest: f.pair_channel_digest,
                record_reference: "ef".repeat(32),
                record_json: "{\"complete_actual_manifest\":true}".into(),
                coordinated_session_id: f.coordinated_session_id,
                receipt_nonce: "fe".repeat(32),
                display: "Full fresh manifest".into(),
                current_enrollment_ref: f.record_reference,
                pair_generation: 1,
                reviewed_at_ms: 1200,
                expires_at_ms: 2200,
                source_expires_at_ms: f.source_expires_at_ms,
            },
            notice: MANIFEST_NOTICE.into(),
            challenge: e.challenge,
            source_ceiling_ms: e.source_ceiling_ms,
            review_ceiling_ms: 2200,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest().unwrap();
        p
    }
    #[test]
    fn complete_fresh_records_and_nonce_are_committed() {
        let e = enrollment();
        e.validate().unwrap();
        let m = manifest();
        m.validate().unwrap();
        let mut changed = e;
        changed.facts.record_json.push(' ');
        assert!(changed.validate().is_err());
        let mut changed = m;
        changed.facts.receipt_nonce = "11".repeat(32);
        assert!(changed.validate().is_err());
    }
    #[test]
    fn purpose_cross_cast_and_legacy_session_field_rejected() {
        let e = enrollment();
        assert!(serde_json::from_value::<SignerV3ManifestPresentationV1>(
            serde_json::to_value(&e).unwrap()
        )
        .is_err());
        let mut value = serde_json::to_value(e).unwrap();
        value["facts"]["native_session_id"] = serde_json::json!("11".repeat(32));
        assert!(serde_json::from_value::<SignerV3EnrollmentPresentationV1>(value).is_err());
    }
    #[test]
    fn review_window_and_full_record_bounds_are_closed() {
        let mut e = enrollment();
        e.facts.record_json = "x".repeat(32769);
        e.presentation_digest = e.calculate_presentation_digest().unwrap();
        assert!(e.validate().is_err());
        let mut m = manifest();
        m.facts.expires_at_ms = m.facts.reviewed_at_ms + 120001;
        m.presentation_digest = m.calculate_presentation_digest().unwrap();
        assert!(m.validate().is_err());
    }
}
/// Ordinary immutable references from actual fresh records, not consent or a grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3CurrentDisclosureV1 {
    pub source_identity_digest: String,
    pub entry_presentation_digest: String,
    pub pair_presentation_digest: String,
    pub pair_grant_id: String,
    pub coordinated_session_id: String,
    pub current_enrollment_ref: String,
    pub current_manifest_ref: String,
}
impl SignerV3CurrentDisclosureV1 {
    pub fn validate(&self) -> Result<()> {
        if ![
            &self.source_identity_digest,
            &self.entry_presentation_digest,
            &self.pair_presentation_digest,
            &self.pair_grant_id,
            &self.coordinated_session_id,
            &self.current_enrollment_ref,
            &self.current_manifest_ref,
        ]
        .iter()
        .all(|v| hash(v))
        {
            return Err(rejected("current disclosure observation"));
        }
        Ok(())
    }
}
