//! Fresh authenticated owner-history Read and exact local immutable admission preparation.
use crate::signer_v3_pair_data::digest;
use crate::{
    financial_workflow_channel::FinancialActorContextV1, rejected, signer_continue_state::hash,
    Result, SignerV3ReceivedV1,
};
use serde::{Deserialize, Serialize};
pub(crate) const NOTICE:&str="Read the full authenticated original owner history and verify this exact locally retained admission and original verified payload against that history. No retry, new admission, private signing, wallet or financial effect is approved. Only actual successful verification may complete V3 custody.";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3AuditFactsV1 {
    pub received: SignerV3ReceivedV1,
    pub admitted: crate::SignerV3AdmittedV1,
    pub operation_id: String,
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
impl SignerV3AuditFactsV1 {
    pub fn validate(&self) -> Result<()> {
        self.received.validate()?;
        self.admitted.validate()?;
        if ![
            &self.owner_selection_digest,
            &self.owner_certificate_digest,
            &self.disclosure_digest,
        ]
        .iter()
        .all(|v| hash(v))
            || self.operation_id.is_empty()
            || self.operation_id.len() > 256
            || self.operation_id.chars().any(char::is_control)
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
            return Err(rejected("Audit exact facts"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3AuditPresentationV1 {
    pub actor: FinancialActorContextV1,
    pub facts: SignerV3AuditFactsV1,
    pub notice: String,
    pub challenge: String,
    pub source_ceiling_ms: u64,
    pub review_ceiling_ms: u64,
    pub service_ceiling_ms: u64,
    pub material_ceiling_ms: u64,
    pub presentation_digest: String,
}
impl SignerV3AuditPresentationV1 {
    pub fn calculate_presentation_digest(&self) -> Result<String> {
        digest(
            b"wholepact:coordinated-v3-audit:presentation:v1\0",
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
                .map_err(|_| rejected("Audit encoding"))?
                .len()
                > 60 * 1024
        {
            return Err(rejected("Audit exact presentation"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3AuditedV1 {
    pub audit_presentation_digest: String,
    pub admit_presentation_digest: String,
    pub source_identity_digest: String,
    pub owner_service_digest: String,
    pub recipient_intent_digest: String,
    pub authenticated_history_digest: String,
    pub local_record_digest: String,
    pub admission_request_digest: String,
    pub operation_id: String,
}
impl SignerV3AuditedV1 {
    pub fn validate(&self) -> Result<()> {
        if ![
            &self.audit_presentation_digest,
            &self.admit_presentation_digest,
            &self.source_identity_digest,
            &self.owner_service_digest,
            &self.recipient_intent_digest,
            &self.authenticated_history_digest,
            &self.local_record_digest,
            &self.admission_request_digest,
        ]
        .iter()
        .all(|v| hash(v))
            || self.operation_id.is_empty()
            || self.operation_id.len() > 256
            || self.operation_id.chars().any(char::is_control)
        {
            return Err(rejected("exact verified V3 Audit result"));
        }
        Ok(())
    }
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) fn presentation() -> SignerV3AuditPresentationV1 {
        let r = crate::signer_v3_admit_read_data::tests::presentation();
        let f = r.facts;
        let a = crate::signer_v3_admission_data::tests::presentation();
        let mut p=SignerV3AuditPresentationV1{actor:r.actor,facts:SignerV3AuditFactsV1{received:f.received,admitted:crate::signer_v3_admission_data::tests::admitted(),operation_id:a.facts.read.operation_id,owner_selection_digest:f.owner_selection_digest,owner_certificate_digest:f.owner_certificate_digest,disclosure_digest:f.disclosure_digest,display:"Full authenticated original history and exact retained local record verification".into(),reviewed_at_ms:1900,expires_at_ms:2800,source_expires_at_ms:f.source_expires_at_ms,service_expires_at_ms:f.service_expires_at_ms,material_expires_at_ms:f.material_expires_at_ms},notice:NOTICE.into(),challenge:"de".repeat(32),source_ceiling_ms:r.source_ceiling_ms,review_ceiling_ms:2800,service_ceiling_ms:r.service_ceiling_ms,material_ceiling_ms:r.material_ceiling_ms,presentation_digest:String::new()};
        p.presentation_digest = p.calculate_presentation_digest().unwrap();
        p
    }
    pub(crate) fn audited() -> SignerV3AuditedV1 {
        let p = presentation();
        SignerV3AuditedV1 {
            audit_presentation_digest: p.presentation_digest,
            admit_presentation_digest: p.facts.admitted.admit_presentation_digest,
            source_identity_digest: p.facts.received.source_identity_digest,
            owner_service_digest: p.facts.received.owner_service_digest,
            recipient_intent_digest: p.facts.received.recipient_intent_digest,
            authenticated_history_digest: "dc".repeat(32),
            local_record_digest: p.facts.admitted.local_record_digest,
            admission_request_digest: p.facts.admitted.admission_request_digest,
            operation_id: p.facts.operation_id,
        }
    }
    #[test]
    fn fresh_audit_is_not_admission_or_prior_read() {
        let p = presentation();
        p.validate().unwrap();
        let a = crate::signer_v3_admission_data::tests::presentation();
        assert!(serde_json::from_value::<SignerV3AuditPresentationV1>(
            serde_json::to_value(a).unwrap()
        )
        .is_err());
        let mut q = p;
        q.facts.operation_id.push('x');
        assert!(q.validate().is_err());
    }
}
