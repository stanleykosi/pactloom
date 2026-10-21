//! Fresh authenticated owner-history Read and exact local immutable admission preparation.
use crate::signer_v3_pair_data::digest;
use crate::{
    financial_workflow_channel::FinancialActorContextV1, rejected, signer_continue_state::hash,
    Result, SignerV3ReceivedV1,
};
use serde::{Deserialize, Serialize};
pub(crate) const NOTICE:&str="Read the full authenticated history from this original selected owner and prepare one exact local immutable admission request and journal candidate for this verified payload. No local INSERT, remote READY, admission, audit or financial action is approved.";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3AdmitReadFactsV1 {
    pub received: SignerV3ReceivedV1,
    pub owner_selection_digest: String,
    pub owner_certificate_digest: String,
    pub disclosure_digest: String,
    pub display: String,
    pub reviewed_at_ms: u64,
    pub expires_at_ms: u64,
    pub source_expires_at_ms: u64,
    pub service_expires_at_ms: u64,
    pub material_expires_at_ms: u64,
}
impl SignerV3AdmitReadFactsV1 {
    pub fn validate(&self) -> Result<()> {
        self.received.validate()?;
        if ![
            &self.owner_selection_digest,
            &self.owner_certificate_digest,
            &self.disclosure_digest,
        ]
        .iter()
        .all(|v| hash(v))
            || self.display.is_empty()
            || self.display.len() > 16384
            || self.reviewed_at_ms == 0
            || self.expires_at_ms <= self.reviewed_at_ms
            || self.expires_at_ms - self.reviewed_at_ms > 120000
            || self.expires_at_ms > self.service_expires_at_ms
            || self.expires_at_ms > self.material_expires_at_ms
            || self.service_expires_at_ms > self.source_expires_at_ms
            || self.material_expires_at_ms > self.source_expires_at_ms
        {
            return Err(rejected("AdmitRead exact facts"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3AdmitReadPresentationV1 {
    pub actor: FinancialActorContextV1,
    pub facts: SignerV3AdmitReadFactsV1,
    pub notice: String,
    pub challenge: String,
    pub source_ceiling_ms: u64,
    pub review_ceiling_ms: u64,
    pub service_ceiling_ms: u64,
    pub material_ceiling_ms: u64,
    pub presentation_digest: String,
}
impl SignerV3AdmitReadPresentationV1 {
    pub fn calculate_presentation_digest(&self) -> Result<String> {
        digest(
            b"wholepact:coordinated-v3-admit-read:presentation:v1\0",
            &(
                &self.actor,
                &self.facts,
                &self.notice,
                &self.challenge,
                self.source_ceiling_ms,
                self.review_ceiling_ms,
                self.service_ceiling_ms,
                self.material_ceiling_ms,
            ),
        )
    }
    pub fn validate(&self) -> Result<()> {
        self.actor.validate()?;
        self.facts.validate()?;
        if self.notice != NOTICE
            || !hash(&self.challenge)
            || self.review_ceiling_ms == 0
            || self.review_ceiling_ms > self.service_ceiling_ms
            || self.review_ceiling_ms > self.material_ceiling_ms
            || self.service_ceiling_ms > self.source_ceiling_ms
            || self.material_ceiling_ms > self.source_ceiling_ms
            || self.source_ceiling_ms > crate::financial_workflow_clock::SUPERVISION_MS
            || self.presentation_digest != self.calculate_presentation_digest()?
            || serde_json::to_vec(self)
                .map_err(|_| rejected("AdmitRead encoding"))?
                .len()
                > 60 * 1024
        {
            return Err(rejected("AdmitRead exact presentation"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3AdmitReadRetainedV1 {
    pub admit_read_presentation_digest: String,
    pub source_identity_digest: String,
    pub owner_service_digest: String,
    pub recipient_intent_digest: String,
    pub authenticated_history_digest: String,
    pub admission_request_digest: String,
    pub admission_review_digest: String,
    pub operation_id: String,
    pub expected_head_sequence: u64,
    pub expected_head_digest: String,
    pub display: String,
}
impl SignerV3AdmitReadRetainedV1 {
    pub fn validate(&self) -> Result<()> {
        if ![
            &self.admit_read_presentation_digest,
            &self.source_identity_digest,
            &self.owner_service_digest,
            &self.recipient_intent_digest,
            &self.authenticated_history_digest,
            &self.admission_request_digest,
            &self.admission_review_digest,
            &self.expected_head_digest,
        ]
        .iter()
        .all(|v| hash(v))
            || self.operation_id.is_empty()
            || self.operation_id.len() > 256
            || self.operation_id.chars().any(char::is_control)
            || self.display.is_empty()
            || self.display.len() > 16384
        {
            return Err(rejected("AdmitRead retained exact candidate"));
        }
        Ok(())
    }
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) fn presentation() -> SignerV3AdmitReadPresentationV1 {
        let r = crate::signer_v3_delivery_data::tests::receive();
        let f = r.facts;
        let mut p=SignerV3AdmitReadPresentationV1{actor:r.actor,facts:SignerV3AdmitReadFactsV1{received:SignerV3ReceivedV1{receive_presentation_digest:r.presentation_digest,prepare_read_presentation_digest:f.prepare_read_presentation_digest,source_identity_digest:f.source_identity_digest,owner_service_digest:f.owner_service_digest,recipient_intent_digest:"dd".repeat(32),payload_digest:f.payload_digest,payload_bytes:f.payload_bytes,fixed_identity_digest:f.fixed_identity_digest},owner_selection_digest:f.owner_selection_digest,owner_certificate_digest:f.owner_certificate_digest,disclosure_digest:f.disclosure_digest,display:"Full pinned authenticated history and one local immutable preparation, no mutation".into(),reviewed_at_ms:1700,expires_at_ms:2700,source_expires_at_ms:f.source_expires_at_ms,service_expires_at_ms:f.service_expires_at_ms,material_expires_at_ms:f.material_expires_at_ms},notice:NOTICE.into(),challenge:"cc".repeat(32),source_ceiling_ms:r.source_ceiling_ms,review_ceiling_ms:2700,service_ceiling_ms:r.service_ceiling_ms,material_ceiling_ms:r.material_ceiling_ms,presentation_digest:String::new()};
        p.presentation_digest = p.calculate_presentation_digest().unwrap();
        p
    }
    pub(crate) fn retained() -> SignerV3AdmitReadRetainedV1 {
        let p = presentation();
        SignerV3AdmitReadRetainedV1 {
            admit_read_presentation_digest: p.presentation_digest,
            source_identity_digest: p.facts.received.source_identity_digest,
            owner_service_digest: p.facts.received.owner_service_digest,
            recipient_intent_digest: p.facts.received.recipient_intent_digest,
            authenticated_history_digest: "ab".repeat(32),
            admission_request_digest: "ac".repeat(32),
            admission_review_digest: "ad".repeat(32),
            operation_id: "exact-admission".into(),
            expected_head_sequence: 7,
            expected_head_digest: "ae".repeat(32),
            display: "Full exact request and retained journal candidate".into(),
        }
    }
    #[test]
    fn history_read_is_fresh_and_distinct_from_private_setup() {
        let p = presentation();
        p.validate().unwrap();
        let prior = crate::signer_v3_delivery_data::tests::read();
        assert!(serde_json::from_value::<SignerV3AdmitReadPresentationV1>(
            serde_json::to_value(prior).unwrap()
        )
        .is_err());
        let mut v = serde_json::to_value(p).unwrap();
        v["approved"] = true.into();
        assert!(serde_json::from_value::<SignerV3AdmitReadPresentationV1>(v).is_err());
    }
    #[test]
    fn original_service_not_renewed_by_fresh_history_read() {
        let mut p = presentation();
        p.facts.expires_at_ms = p.facts.material_expires_at_ms + 1;
        p.presentation_digest = p.calculate_presentation_digest().unwrap();
        assert!(p.validate().is_err());
    }
}
