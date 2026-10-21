//! Exact conditional admission, authenticated READY, and immutable local outcome.
use crate::signer_v3_pair_data::digest;
use crate::{
    financial_workflow_channel::FinancialActorContextV1, rejected, signer_continue_state::hash,
    Result, SignerV3AdmitReadRetainedV1,
};
use serde::{Deserialize, Serialize};
pub(crate) const NOTICE:&str="Prepare only this exact admission on the retained original owner client. An authenticated READY must be retained on the same live connection and separately approved before local journal publication and the exact remote send. Unknown outcomes remain retained, never permission to retry; fresh Audit is still required.";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3AdmitFactsV1 {
    pub read: SignerV3AdmitReadRetainedV1,
    pub request_json: String,
    pub display: String,
    pub reviewed_at_ms: u64,
    pub expires_at_ms: u64,
    pub source_expires_at_ms: u64,
    pub service_expires_at_ms: u64,
    pub material_expires_at_ms: u64,
}
impl SignerV3AdmitFactsV1 {
    pub fn validate(&self) -> Result<()> {
        self.read.validate()?;
        if self.request_json.len() > 16384
            || !serde_json::from_str::<serde_json::Value>(&self.request_json)
                .is_ok_and(|v| v.is_object())
            || self.display.is_empty()
            || self.display.len() > 16384
            || self.reviewed_at_ms == 0
            || self.expires_at_ms <= self.reviewed_at_ms
            || self.expires_at_ms - self.reviewed_at_ms > 120000
            || self.expires_at_ms > self.service_expires_at_ms
            || self.expires_at_ms > self.material_expires_at_ms
            || self.service_expires_at_ms > self.source_expires_at_ms
            || self.material_expires_at_ms > self.source_expires_at_ms
            || serde_json::to_vec(self)
                .map_err(|_| rejected("admission facts encoding"))?
                .len()
                > 48 * 1024
        {
            return Err(rejected("admission exact facts"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3AdmitPresentationV1 {
    pub actor: FinancialActorContextV1,
    pub facts: SignerV3AdmitFactsV1,
    pub notice: String,
    pub challenge: String,
    pub source_ceiling_ms: u64,
    pub review_ceiling_ms: u64,
    pub service_ceiling_ms: u64,
    pub material_ceiling_ms: u64,
    pub presentation_digest: String,
}
impl SignerV3AdmitPresentationV1 {
    pub fn calculate_presentation_digest(&self) -> Result<String> {
        digest(
            b"wholepact:coordinated-v3-admit:presentation:v1\0",
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
                .map_err(|_| rejected("admission presentation encoding"))?
                .len()
                > 60 * 1024
        {
            return Err(rejected("admission exact presentation"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3AdmitReadyV1 {
    pub admit_presentation_digest: String,
    pub admission_request_digest: String,
    pub admission_review_digest: String,
    pub owner_service_digest: String,
    pub authenticated_ready_digest: String,
    pub expected_head_sequence: u64,
    pub expected_head_digest: String,
    pub operation_id: String,
}
impl SignerV3AdmitReadyV1 {
    pub fn validate(&self) -> Result<()> {
        if ![
            &self.admit_presentation_digest,
            &self.admission_request_digest,
            &self.admission_review_digest,
            &self.owner_service_digest,
            &self.authenticated_ready_digest,
            &self.expected_head_digest,
        ]
        .iter()
        .all(|v| hash(v))
            || self.operation_id.is_empty()
            || self.operation_id.len() > 256
            || self.operation_id.chars().any(char::is_control)
        {
            return Err(rejected("admission actual READY"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", deny_unknown_fields)]
pub enum SignerV3AdmissionObservationV1 {
    Controlled {
        head_sequence: u64,
        head_digest: String,
    },
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3AdmittedV1 {
    pub admit_presentation_digest: String,
    pub admission_request_digest: String,
    pub admission_review_digest: String,
    pub owner_service_digest: String,
    pub local_record_digest: String,
    pub observation: SignerV3AdmissionObservationV1,
}
impl SignerV3AdmittedV1 {
    pub fn validate(&self) -> Result<()> {
        if ![
            &self.admit_presentation_digest,
            &self.admission_request_digest,
            &self.admission_review_digest,
            &self.owner_service_digest,
            &self.local_record_digest,
        ]
        .iter()
        .all(|v| hash(v))
            || matches!(&self.observation,SignerV3AdmissionObservationV1::Controlled{head_digest,..} if !hash(head_digest))
        {
            return Err(rejected("admission retained actual outcome"));
        }
        Ok(())
    }
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) fn presentation() -> SignerV3AdmitPresentationV1 {
        let r = crate::signer_v3_admit_read_data::tests::presentation();
        let mut p = SignerV3AdmitPresentationV1 {
            actor: r.actor,
            facts: SignerV3AdmitFactsV1 {
                read: crate::signer_v3_admit_read_data::tests::retained(),
                request_json:
                    "{\"operation_id\":\"exact-admission\",\"expected_head\":{\"sequence\":7}}"
                        .into(),
                display: "Exact immutable conditional admission".into(),
                reviewed_at_ms: 1800,
                expires_at_ms: 2700,
                source_expires_at_ms: r.facts.source_expires_at_ms,
                service_expires_at_ms: r.facts.service_expires_at_ms,
                material_expires_at_ms: r.facts.material_expires_at_ms,
            },
            notice: NOTICE.into(),
            challenge: "cf".repeat(32),
            source_ceiling_ms: r.source_ceiling_ms,
            review_ceiling_ms: 2700,
            service_ceiling_ms: r.service_ceiling_ms,
            material_ceiling_ms: r.material_ceiling_ms,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest().unwrap();
        p
    }
    pub(crate) fn ready() -> SignerV3AdmitReadyV1 {
        let p = presentation();
        let r = p.facts.read;
        SignerV3AdmitReadyV1 {
            admit_presentation_digest: p.presentation_digest,
            admission_request_digest: r.admission_request_digest,
            admission_review_digest: r.admission_review_digest,
            owner_service_digest: r.owner_service_digest,
            authenticated_ready_digest: "fe".repeat(32),
            expected_head_sequence: r.expected_head_sequence,
            expected_head_digest: r.expected_head_digest,
            operation_id: r.operation_id,
        }
    }
    pub(crate) fn admitted() -> SignerV3AdmittedV1 {
        let p = presentation();
        SignerV3AdmittedV1 {
            admit_presentation_digest: p.presentation_digest,
            admission_request_digest: p.facts.read.admission_request_digest,
            admission_review_digest: p.facts.read.admission_review_digest,
            owner_service_digest: p.facts.read.owner_service_digest,
            local_record_digest: "af".repeat(32),
            observation: SignerV3AdmissionObservationV1::Unknown,
        }
    }
    #[test]
    fn conditional_review_commits_exact_request_bytes_and_full_prior_result() {
        let p = presentation();
        p.validate().unwrap();
        let mut q = p.clone();
        q.facts.request_json.push(' ');
        assert!(q.validate().is_err());
        let mut q = p;
        q.facts.read.expected_head_sequence += 1;
        assert!(q.validate().is_err());
    }
    #[test]
    fn unknown_is_distinct_from_controlled_and_neither_is_audit() {
        let d = admitted();
        d.validate().unwrap();
        let mut v = serde_json::to_value(d).unwrap();
        v["observation"] = serde_json::json!({"status":"Controlled"});
        assert!(serde_json::from_value::<SignerV3AdmittedV1>(v).is_err());
    }
}
