//! Exact historical outbox Read and separately approved fresh redisclosure.
use crate::signer_v3_pair_data::digest;
use crate::{
    financial_workflow_channel::FinancialActorContextV1, rejected, signer_continue_state::hash,
    Result,
};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3RedisclosurePreparedV1 {
    pub read_presentation_digest: String,
    pub source_identity_digest: String,
    pub current_enrollment_ref: String,
    pub current_manifest_ref: String,
    pub coordinated_session_id: String,
    pub next_request_digest: String,
    pub material_digest: String,
    pub original_outbox_reference: String,
    pub original_request_digest: String,
    pub scope_digest: String,
    pub display: String,
}
impl SignerV3RedisclosurePreparedV1 {
    pub fn validate(&self) -> Result<()> {
        if ![
            &self.read_presentation_digest,
            &self.source_identity_digest,
            &self.current_enrollment_ref,
            &self.current_manifest_ref,
            &self.coordinated_session_id,
            &self.next_request_digest,
            &self.material_digest,
            &self.original_outbox_reference,
            &self.original_request_digest,
            &self.scope_digest,
        ]
        .iter()
        .all(|v| hash(v))
            || self.next_request_digest == self.original_request_digest
            || self.display.is_empty()
            || self.display.len() > 16384
        {
            return Err(rejected("redisclosure prepared exact data"));
        }
        Ok(())
    }
}
pub(crate) const REDISCLOSURE_READ_NOTICE:&str="Read only the exact selected historical construction outbox and prepare one immutable redisclosure candidate using these freshly approved records and the actual original paired recipient. No export, outbox append, delivery, admission or financial effect is approved.";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3RedisclosureReadFactsV1 {
    pub entry_presentation_digest: String,
    pub source_identity_digest: String,
    pub pair_grant_id: String,
    pub pair_key_digest: String,
    pub pair_channel_digest: String,
    pub coordinated_session_id: String,
    pub current_enrollment_ref: String,
    pub current_manifest_ref: String,
    pub display: String,
    pub selector_json: String,
    pub selector_digest: String,
    pub pair_generation: u64,
    pub reviewed_at_ms: u64,
    pub expires_at_ms: u64,
    pub source_expires_at_ms: u64,
}
impl SignerV3RedisclosureReadFactsV1 {
    pub fn calculate_selector_digest(&self) -> Result<String> {
        digest(
            b"wholepact:coordinated-v3-redisclosure-selector:v1\0",
            &self.selector_json,
        )
    }
    pub fn validate(&self) -> Result<()> {
        if ![
            &self.entry_presentation_digest,
            &self.source_identity_digest,
            &self.pair_grant_id,
            &self.pair_key_digest,
            &self.pair_channel_digest,
            &self.coordinated_session_id,
            &self.current_enrollment_ref,
            &self.current_manifest_ref,
            &self.selector_digest,
        ]
        .iter()
        .all(|v| hash(v))
            || self.pair_generation != 1
            || self.display.is_empty()
            || self.display.len() > 8192
            || self.reviewed_at_ms == 0
            || self.expires_at_ms <= self.reviewed_at_ms
            || self.expires_at_ms - self.reviewed_at_ms > 120000
            || self.expires_at_ms > self.source_expires_at_ms
            || self.selector_json.len() > 8192
            || !serde_json::from_str::<serde_json::Value>(&self.selector_json)
                .is_ok_and(|v| v.is_object())
            || self.selector_digest != self.calculate_selector_digest()?
            || serde_json::to_vec(self)
                .map_err(|_| rejected("redisclosure facts encoding"))?
                .len()
                > 48 * 1024
        {
            return Err(rejected("redisclosure exact facts"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3RedisclosureReadPresentationV1 {
    pub actor: FinancialActorContextV1,
    pub facts: SignerV3RedisclosureReadFactsV1,
    pub notice: String,
    pub challenge: String,
    pub source_ceiling_ms: u64,
    pub review_ceiling_ms: u64,
    pub presentation_digest: String,
}
impl SignerV3RedisclosureReadPresentationV1 {
    pub fn calculate_presentation_digest(&self) -> Result<String> {
        digest(
            b"wholepact:coordinated-v3-redisclosure_read:presentation:v1\0",
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
        if self.notice != REDISCLOSURE_READ_NOTICE
            || !hash(&self.challenge)
            || self.review_ceiling_ms == 0
            || self.review_ceiling_ms > self.source_ceiling_ms
            || self.source_ceiling_ms > crate::financial_workflow_clock::SUPERVISION_MS
            || self.presentation_digest != self.calculate_presentation_digest()?
            || serde_json::to_vec(self)
                .map_err(|_| rejected("redisclosure presentation encoding"))?
                .len()
                > 60 * 1024
        {
            return Err(rejected("redisclosure presentation"));
        }
        Ok(())
    }
}
pub(crate) const REDISCLOSE_NOTICE:&str="Append exactly this newly prepared redisclosure under the freshly approved current enrollment and manifest, then export its exact retained response once to this actual original paired recipient. Historical approval is not reused. No delivery preparation, admission or financial effect is approved.";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3RediscloseFactsV1 {
    pub entry_presentation_digest: String,
    pub source_identity_digest: String,
    pub pair_grant_id: String,
    pub pair_key_digest: String,
    pub pair_channel_digest: String,
    pub coordinated_session_id: String,
    pub current_enrollment_ref: String,
    pub current_manifest_ref: String,
    pub display: String,
    pub prepared: SignerV3RedisclosurePreparedV1,
    pub pair_generation: u64,
    pub reviewed_at_ms: u64,
    pub expires_at_ms: u64,
    pub source_expires_at_ms: u64,
}
impl SignerV3RediscloseFactsV1 {
    pub fn validate(&self) -> Result<()> {
        self.prepared.validate()?;
        if ![
            &self.entry_presentation_digest,
            &self.source_identity_digest,
            &self.pair_grant_id,
            &self.pair_key_digest,
            &self.pair_channel_digest,
            &self.coordinated_session_id,
            &self.current_enrollment_ref,
            &self.current_manifest_ref,
        ]
        .iter()
        .all(|v| hash(v))
            || self.pair_generation != 1
            || self.display.is_empty()
            || self.display.len() > 8192
            || self.reviewed_at_ms == 0
            || self.expires_at_ms <= self.reviewed_at_ms
            || self.expires_at_ms - self.reviewed_at_ms > 120000
            || self.expires_at_ms > self.source_expires_at_ms
            || self.prepared.source_identity_digest != self.source_identity_digest
            || self.prepared.current_enrollment_ref != self.current_enrollment_ref
            || self.prepared.current_manifest_ref != self.current_manifest_ref
            || self.prepared.coordinated_session_id != self.coordinated_session_id
            || serde_json::to_vec(self)
                .map_err(|_| rejected("redisclosure facts encoding"))?
                .len()
                > 48 * 1024
        {
            return Err(rejected("redisclosure exact facts"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3RedisclosePresentationV1 {
    pub actor: FinancialActorContextV1,
    pub facts: SignerV3RediscloseFactsV1,
    pub notice: String,
    pub challenge: String,
    pub source_ceiling_ms: u64,
    pub review_ceiling_ms: u64,
    pub presentation_digest: String,
}
impl SignerV3RedisclosePresentationV1 {
    pub fn calculate_presentation_digest(&self) -> Result<String> {
        digest(
            b"wholepact:coordinated-v3-redisclose:presentation:v1\0",
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
        if self.notice != REDISCLOSE_NOTICE
            || !hash(&self.challenge)
            || self.review_ceiling_ms == 0
            || self.review_ceiling_ms > self.source_ceiling_ms
            || self.source_ceiling_ms > crate::financial_workflow_clock::SUPERVISION_MS
            || self.presentation_digest != self.calculate_presentation_digest()?
            || serde_json::to_vec(self)
                .map_err(|_| rejected("redisclosure presentation encoding"))?
                .len()
                > 60 * 1024
        {
            return Err(rejected("redisclosure presentation"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3RedisclosedV1 {
    pub presentation_digest: String,
    pub outbox_reference: String,
    pub request_digest: String,
}
impl SignerV3RedisclosedV1 {
    pub fn validate(&self) -> Result<()> {
        if ![
            &self.presentation_digest,
            &self.outbox_reference,
            &self.request_digest,
        ]
        .iter()
        .all(|v| hash(v))
        {
            return Err(rejected("redisclosed observation"));
        }
        Ok(())
    }
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) fn read() -> SignerV3RedisclosureReadPresentationV1 {
        let e = crate::signer_v3_receipt_data::tests::enrollment();
        let m = crate::signer_v3_receipt_data::tests::manifest();
        let f = e.facts;
        let mut facts = SignerV3RedisclosureReadFactsV1 {
            entry_presentation_digest: f.entry_presentation_digest,
            source_identity_digest: f.source_identity_digest,
            pair_grant_id: f.pair_grant_id,
            pair_key_digest: f.pair_key_digest,
            pair_channel_digest: f.pair_channel_digest,
            coordinated_session_id: f.coordinated_session_id,
            current_enrollment_ref: f.record_reference,
            current_manifest_ref: m.facts.record_reference,
            display: "Read exact selected historical outbox only".into(),
            selector_json:
                "{\"operation_id\":\"new-op\",\"original\":{\"operation_id\":\"old-op\"}}".into(),
            selector_digest: String::new(),
            pair_generation: 1,
            reviewed_at_ms: 1300,
            expires_at_ms: 2300,
            source_expires_at_ms: f.source_expires_at_ms,
        };
        facts.selector_digest = facts.calculate_selector_digest().unwrap();
        let mut p = SignerV3RedisclosureReadPresentationV1 {
            actor: e.actor,
            facts,
            notice: REDISCLOSURE_READ_NOTICE.into(),
            challenge: e.challenge,
            source_ceiling_ms: e.source_ceiling_ms,
            review_ceiling_ms: 2300,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest().unwrap();
        p
    }
    pub(crate) fn prepared() -> SignerV3RedisclosurePreparedV1 {
        let p = read();
        SignerV3RedisclosurePreparedV1 {
            read_presentation_digest: p.presentation_digest,
            source_identity_digest: p.facts.source_identity_digest,
            current_enrollment_ref: p.facts.current_enrollment_ref,
            current_manifest_ref: p.facts.current_manifest_ref,
            coordinated_session_id: p.facts.coordinated_session_id,
            next_request_digest: "10".repeat(32),
            material_digest: "20".repeat(32),
            original_outbox_reference: "30".repeat(32),
            original_request_digest: "40".repeat(32),
            scope_digest: "50".repeat(32),
            display: "Exact new request, material and original link; no payload bytes".into(),
        }
    }
    pub(crate) fn export() -> SignerV3RedisclosePresentationV1 {
        let r = read();
        let f = r.facts;
        let mut p = SignerV3RedisclosePresentationV1 {
            actor: r.actor,
            facts: SignerV3RediscloseFactsV1 {
                entry_presentation_digest: f.entry_presentation_digest,
                source_identity_digest: f.source_identity_digest,
                pair_grant_id: f.pair_grant_id,
                pair_key_digest: f.pair_key_digest,
                pair_channel_digest: f.pair_channel_digest,
                coordinated_session_id: f.coordinated_session_id,
                current_enrollment_ref: f.current_enrollment_ref,
                current_manifest_ref: f.current_manifest_ref,
                display: "One exact new outbox/export".into(),
                prepared: prepared(),
                pair_generation: 1,
                reviewed_at_ms: 1400,
                expires_at_ms: 2400,
                source_expires_at_ms: f.source_expires_at_ms,
            },
            notice: REDISCLOSE_NOTICE.into(),
            challenge: r.challenge,
            source_ceiling_ms: r.source_ceiling_ms,
            review_ceiling_ms: 2400,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest().unwrap();
        p
    }
    #[test]
    fn read_selector_and_export_preparation_are_exact_and_disjoint() {
        let r = read();
        r.validate().unwrap();
        let e = export();
        e.validate().unwrap();
        let mut bad = r;
        bad.facts.selector_json.push(' ');
        assert!(bad.validate().is_err());
        assert!(
            serde_json::from_value::<SignerV3RedisclosureReadPresentationV1>(
                serde_json::to_value(e).unwrap()
            )
            .is_err()
        );
    }
    #[test]
    fn historical_request_cannot_be_relabelled_new_export() {
        let mut p = prepared();
        p.next_request_digest = p.original_request_digest.clone();
        assert!(p.validate().is_err());
        let mut e = export();
        e.facts.current_manifest_ref = "aa".repeat(32);
        e.presentation_digest = e.calculate_presentation_digest().unwrap();
        assert!(e.validate().is_err());
    }
    #[test]
    fn private_candidate_cannot_enter_closed_control_schema() {
        let mut v = serde_json::to_value(export()).unwrap();
        v["facts"]["prepared"]["full_private_request_json"] = serde_json::json!("{}");
        assert!(serde_json::from_value::<SignerV3RedisclosePresentationV1>(v).is_err());
        let mut r = read();
        r.facts.selector_json = " ".repeat(8193);
        assert!(r.facts.validate().is_err());
    }
}
