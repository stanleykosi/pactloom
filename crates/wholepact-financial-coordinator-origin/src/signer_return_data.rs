//! Exact same-original-host return after actual retained Sign result.
use crate::signer_v3_pair_data::digest;
use crate::{
    financial_workflow_channel::FinancialActorContextV1, rejected, signer_continue_state::hash,
    Result, SignerSignCommittedV1, SignerWalletObservedV1, SignerWalletOriginalV1,
};
use serde::{Deserialize, Serialize};
/// Closed ordinary projection of the maintained result request. This parser
/// proves no cryptography, source custody, socket or signature ownership.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerReturnRequestDataV1 {
    pub account_id: String,
    pub authorization_id: String,
    pub original_consent_ref: String,
    pub fixed: SignerReturnFixedIdentityDataV1,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerReturnFixedIdentityDataV1 {
    pub schema_version: u32,
    pub network_profile_id: String,
    pub agreement_id: String,
    pub obligation_id: String,
    pub proposal_id: String,
    pub revision: u32,
    pub expiry_height: u32,
    pub proposal_digest: String,
    pub manifest_digest: String,
    pub unsigned_artifact_digest: String,
    pub proved_artifact_digest: String,
    pub effects_commitment: String,
    pub policy_digest: String,
    pub review_binding: String,
    pub action_mapping_digest: String,
    pub anchor: String,
    pub proposal_binding: String,
}
fn label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_:./@".contains(&b))
}
impl SignerReturnRequestDataV1 {
    pub fn parse_json(json: &str) -> Result<Self> {
        if json.is_empty() || json.len() > 8192 {
            return Err(rejected("Return request size"));
        }
        let s: Self =
            serde_json::from_str(json).map_err(|_| rejected("Return closed request schema"))?;
        let f = &s.fixed;
        if !hash(&s.account_id)
            || !hash(&s.original_consent_ref)
            || !label(&s.authorization_id)
            || ![
                &f.network_profile_id,
                &f.agreement_id,
                &f.obligation_id,
                &f.proposal_id,
            ]
            .iter()
            .all(|v| label(v))
            || f.schema_version != 1
            || f.expiry_height == 0
            || ![
                &f.proposal_digest,
                &f.manifest_digest,
                &f.unsigned_artifact_digest,
                &f.proved_artifact_digest,
                &f.effects_commitment,
                &f.policy_digest,
                &f.review_binding,
                &f.action_mapping_digest,
                &f.anchor,
                &f.proposal_binding,
            ]
            .iter()
            .all(|v| hash(v))
        {
            return Err(rejected("Return request metadata"));
        }
        Ok(s)
    }
}
pub(crate) const READ_NOTICE:&str="Read only this actual retained coordinated signature result and exact original request, construct and send one preview to the same original Host on the same retained channel. No signature payload or Return is authorized; waiting for HostPrepared retains custody only.";
pub(crate) const EXACT_NOTICE:&str="Return only the exact reviewed persisted signature set/result/outbox to the same original Host and the same retained prepared stream. One attempt, original deadlines, exact Ready/Held/Current/Finished checks; partial transfer or report loss is uncertain and never permits retry.";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerReturnReadFactsV1 {
    pub original: SignerWalletOriginalV1,
    pub observed: SignerWalletObservedV1,
    pub signed: SignerSignCommittedV1,
    pub request_json: String,
    pub request_digest: String,
    pub original_host_process_instance: String,
    pub display: String,
    pub reviewed_at_ms: u64,
    pub expires_at_ms: u64,
}
impl SignerReturnReadFactsV1 {
    pub fn request_data(&self) -> Result<SignerReturnRequestDataV1> {
        SignerReturnRequestDataV1::parse_json(&self.request_json)
    }
    pub fn calculate_request_digest(json: &str) -> Result<String> {
        digest(
            b"wholepact:coordinated-financial-return-request:v1\0",
            &json,
        )
    }
    pub fn validate(&self) -> Result<()> {
        let request = self.request_data()?;
        if request.authorization_id != self.signed.authorization_id
            || request.original_consent_ref != self.signed.original_consent_ref
        {
            return Err(rejected("Return request changed actual Sign result"));
        }
        self.original.validate()?;
        self.observed.validate()?;
        self.signed.validate()?;
        if self.observed.activation_presentation_digest
            != self.original.activation.presentation_digest
            || self.observed.fixed_identity_digest != self.original.fixed_identity_digest
            || self.observed.configuration_digest != self.original.configuration_digest
            || self.signed.fixed_identity_digest != self.original.fixed_identity_digest
            || self.original_host_process_instance
                != self
                    .original
                    .activation
                    .facts
                    .original
                    .original_host_process_instance
            || !hash(&self.request_digest)
            || self.request_digest != Self::calculate_request_digest(&self.request_json)?
            || self.request_json.len() > 8192
            || !serde_json::from_str::<serde_json::Value>(&self.request_json)
                .is_ok_and(|v| v.is_object())
        {
            return Err(rejected("return exact original request/result"));
        }
        window(
            &self.original,
            &self.display,
            self.reviewed_at_ms,
            self.expires_at_ms,
        )?;
        bound(self)
    }
}
fn bound<T: Serialize>(v: &T) -> Result<()> {
    if serde_json::to_vec(v)
        .map_err(|_| rejected("return facts encoding"))?
        .len()
        > 48 * 1024
    {
        return Err(rejected("return facts bound"));
    }
    Ok(())
}
fn window(o: &SignerWalletOriginalV1, d: &str, a: u64, b: u64) -> Result<()> {
    if d.is_empty()
        || d.len() > 4096
        || a == 0
        || b <= a
        || b - a > 120000
        || b > o.activation.facts.original.source_expires_at_ms
        || b > o.activation.facts.original.acquired.expires_at_ms
    {
        return Err(rejected("return original action window"));
    }
    Ok(())
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerReturnExactFactsV1 {
    pub read: SignerReturnReadPresentationV1,
    pub preview_digest: String,
    pub reviewed_digest: String,
    pub signature_set_digest: String,
    pub display: String,
    pub reviewed_at_ms: u64,
    pub expires_at_ms: u64,
}
impl SignerReturnExactFactsV1 {
    pub fn validate(&self) -> Result<()> {
        self.read.validate()?;
        if ![
            &self.preview_digest,
            &self.reviewed_digest,
            &self.signature_set_digest,
        ]
        .iter()
        .all(|v| hash(v))
        {
            return Err(rejected("return actual prepared commitments"));
        }
        window(
            &self.read.facts.original,
            &self.display,
            self.reviewed_at_ms,
            self.expires_at_ms,
        )?;
        bound(self)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerReturnReadPresentationV1 {
    pub actor: FinancialActorContextV1,
    pub facts: SignerReturnReadFactsV1,
    pub notice: String,
    pub challenge: String,
    pub source_ceiling_ms: u64,
    pub read_ceiling_ms: u64,
    pub service_ceiling_ms: u64,
    pub writer_session_ceiling_ms: u64,
    pub channel_ceiling_ms: u64,
    pub material_ceiling_ms: u64,
    pub channel_expires_at_ms: u64,
    pub material_expires_at_ms: u64,
    pub presentation_digest: String,
}
impl SignerReturnReadPresentationV1 {
    pub fn calculate_presentation_digest(&self) -> Result<String> {
        digest(
            b"wholepact:coordinated-financial-return-read:presentation:v1\0",
            &(
                &self.actor,
                &self.facts,
                &self.notice,
                &self.challenge,
                self.source_ceiling_ms,
                self.read_ceiling_ms,
                self.service_ceiling_ms,
                self.writer_session_ceiling_ms,
                self.channel_ceiling_ms,
                self.material_ceiling_ms,
                self.channel_expires_at_ms,
                self.material_expires_at_ms,
            ),
        )
    }
    pub fn validate(&self) -> Result<()> {
        self.actor.validate()?;
        self.facts.validate()?;
        if self.actor != self.facts.original.activation.actor
            || self.notice != READ_NOTICE
            || !hash(&self.challenge)
            || self.service_ceiling_ms > self.source_ceiling_ms
            || self.writer_session_ceiling_ms > self.source_ceiling_ms
            || self.read_ceiling_ms == 0
            || [
                self.service_ceiling_ms,
                self.writer_session_ceiling_ms,
                self.channel_ceiling_ms,
                self.material_ceiling_ms,
            ]
            .iter()
            .any(|v| self.read_ceiling_ms > *v)
            || self.facts.expires_at_ms > self.channel_expires_at_ms
            || self.facts.expires_at_ms > self.material_expires_at_ms
            || self.source_ceiling_ms != self.facts.original.activation.source_ceiling_ms
            || self.presentation_digest != self.calculate_presentation_digest()?
            || serde_json::to_vec(self)
                .map_err(|_| rejected("return presentation encoding"))?
                .len()
                > 60 * 1024
        {
            return Err(rejected("return exact original presentation"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerReturnExactPresentationV1 {
    pub actor: FinancialActorContextV1,
    pub facts: SignerReturnExactFactsV1,
    pub notice: String,
    pub challenge: String,
    pub source_ceiling_ms: u64,
    pub return_ceiling_ms: u64,
    pub service_ceiling_ms: u64,
    pub writer_session_ceiling_ms: u64,
    pub channel_ceiling_ms: u64,
    pub material_ceiling_ms: u64,
    pub channel_expires_at_ms: u64,
    pub material_expires_at_ms: u64,
    pub presentation_digest: String,
}
impl SignerReturnExactPresentationV1 {
    pub fn calculate_presentation_digest(&self) -> Result<String> {
        digest(
            b"wholepact:coordinated-financial-return-return:presentation:v1\0",
            &(
                &self.actor,
                &self.facts,
                &self.notice,
                &self.challenge,
                self.source_ceiling_ms,
                self.return_ceiling_ms,
                self.service_ceiling_ms,
                self.writer_session_ceiling_ms,
                self.channel_ceiling_ms,
                self.material_ceiling_ms,
                self.channel_expires_at_ms,
                self.material_expires_at_ms,
            ),
        )
    }
    pub fn validate(&self) -> Result<()> {
        self.actor.validate()?;
        self.facts.validate()?;
        if self.actor != self.facts.read.facts.original.activation.actor
            || self.notice != EXACT_NOTICE
            || !hash(&self.challenge)
            || self.service_ceiling_ms > self.source_ceiling_ms
            || self.writer_session_ceiling_ms > self.source_ceiling_ms
            || self.return_ceiling_ms == 0
            || [
                self.service_ceiling_ms,
                self.writer_session_ceiling_ms,
                self.channel_ceiling_ms,
                self.material_ceiling_ms,
            ]
            .iter()
            .any(|v| self.return_ceiling_ms > *v)
            || self.facts.expires_at_ms > self.channel_expires_at_ms
            || self.facts.expires_at_ms > self.material_expires_at_ms
            || self.source_ceiling_ms != self.facts.read.facts.original.activation.source_ceiling_ms
            || self.presentation_digest != self.calculate_presentation_digest()?
            || serde_json::to_vec(self)
                .map_err(|_| rejected("return presentation encoding"))?
                .len()
                > 60 * 1024
        {
            return Err(rejected("return exact original presentation"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerReturnPreparedV1 {
    pub read_presentation_digest: String,
    pub preview_digest: String,
    pub reviewed_digest: String,
    pub signature_set_digest: String,
}
impl SignerReturnPreparedV1 {
    pub fn validate(&self) -> Result<()> {
        if ![
            &self.read_presentation_digest,
            &self.preview_digest,
            &self.reviewed_digest,
            &self.signature_set_digest,
        ]
        .iter()
        .all(|v| hash(v))
        {
            return Err(rejected("return actual result hashes"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerReturnCompletedV1 {
    pub return_presentation_digest: String,
    pub preview_digest: String,
    pub result_digest: String,
    pub outbox_digest: String,
}
impl SignerReturnCompletedV1 {
    pub fn validate(&self) -> Result<()> {
        if ![
            &self.return_presentation_digest,
            &self.preview_digest,
            &self.result_digest,
            &self.outbox_digest,
        ]
        .iter()
        .all(|v| hash(v))
        {
            return Err(rejected("return actual result hashes"));
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum SignerReturnFailureStageV1 {
    ReadFailed,
    ReturnUncertain,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerReturnFailureV1 {
    pub presentation_digest: String,
    pub stage: SignerReturnFailureStageV1,
}
impl SignerReturnFailureV1 {
    pub fn validate(&self) -> Result<()> {
        if !hash(&self.presentation_digest) {
            return Err(rejected("return failure binding"));
        }
        Ok(())
    }
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) fn read() -> SignerReturnReadPresentationV1 {
        let s = crate::signer_sign_data::tests::exact();
        let signed = SignerSignCommittedV1 {
            sign_presentation_digest: s.presentation_digest,
            authorization_id: "exact-original-operation-1".into(),
            original_consent_ref: "ab".repeat(32),
            result_digest: "bc".repeat(32),
            outbox_digest: "cd".repeat(32),
            fixed_identity_digest: s.facts.original.fixed_identity_digest.clone(),
        };
        let request=serde_json::json!({"account_id":"aa".repeat(32),"authorization_id":"exact-original-operation-1","original_consent_ref":signed.original_consent_ref,"fixed":{"schema_version":1,"network_profile_id":"network","agreement_id":"agreement","obligation_id":"obligation","proposal_id":"proposal","revision":1,"expiry_height":200,"proposal_digest":"ab".repeat(32),"manifest_digest":"bc".repeat(32),"unsigned_artifact_digest":"cd".repeat(32),"proved_artifact_digest":"de".repeat(32),"effects_commitment":"ef".repeat(32),"policy_digest":"fa".repeat(32),"review_binding":"aa".repeat(32),"action_mapping_digest":"bb".repeat(32),"anchor":"cc".repeat(32),"proposal_binding":"dd".repeat(32)}}).to_string();
        let mut p = SignerReturnReadPresentationV1 {
            actor: s.actor,
            facts: SignerReturnReadFactsV1 {
                original_host_process_instance: s
                    .facts
                    .original
                    .activation
                    .facts
                    .original
                    .original_host_process_instance
                    .clone(),
                original: s.facts.original,
                observed: s.facts.observed,
                signed,
                request_digest: SignerReturnReadFactsV1::calculate_request_digest(&request)
                    .unwrap(),
                request_json: request,
                display: "One exact retained result Read and same original Host preview".into(),
                reviewed_at_ms: 8000,
                expires_at_ms: 128000,
            },
            notice: READ_NOTICE.into(),
            challenge: s.challenge,
            source_ceiling_ms: s.source_ceiling_ms,
            read_ceiling_ms: 128000,
            service_ceiling_ms: s.service_ceiling_ms,
            writer_session_ceiling_ms: s.writer_session_ceiling_ms,
            channel_ceiling_ms: 290000,
            material_ceiling_ms: 290000,
            channel_expires_at_ms: 290000,
            material_expires_at_ms: 290000,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest().unwrap();
        p
    }
    pub(crate) fn exact() -> SignerReturnExactPresentationV1 {
        let r = read();
        let mut p = SignerReturnExactPresentationV1 {
            actor: r.actor.clone(),
            notice: EXACT_NOTICE.into(),
            challenge: r.challenge.clone(),
            source_ceiling_ms: r.source_ceiling_ms,
            return_ceiling_ms: 129000,
            service_ceiling_ms: r.service_ceiling_ms,
            writer_session_ceiling_ms: r.writer_session_ceiling_ms,
            channel_ceiling_ms: r.channel_ceiling_ms,
            material_ceiling_ms: r.material_ceiling_ms,
            channel_expires_at_ms: r.channel_expires_at_ms,
            material_expires_at_ms: r.material_expires_at_ms,
            facts: SignerReturnExactFactsV1 {
                read: r,
                preview_digest: "de".repeat(32),
                reviewed_digest: "ef".repeat(32),
                signature_set_digest: "fa".repeat(32),
                display: "Only actual prepared same-stream exact result Return".into(),
                reviewed_at_ms: 9000,
                expires_at_ms: 129000,
            },
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest().unwrap();
        p
    }
    #[test]
    fn return_commits_exact_request_original_host_and_result() {
        let p = read();
        p.validate().unwrap();
        let mut q = p.clone();
        q.facts.request_json.push(' ');
        q.presentation_digest = q.calculate_presentation_digest().unwrap();
        assert!(q.validate().is_err());
        let mut q = p;
        q.facts.original_host_process_instance = "ff".repeat(32);
        q.presentation_digest = q.calculate_presentation_digest().unwrap();
        assert!(q.validate().is_err());
    }
    #[test]
    fn return_read_is_not_exact_and_ceilings_cannot_renew() {
        let p = exact();
        p.validate().unwrap();
        assert!(serde_json::from_value::<SignerReturnReadPresentationV1>(
            serde_json::to_value(&p).unwrap()
        )
        .is_err());
        let mut q = p;
        q.return_ceiling_ms = q.channel_ceiling_ms + 1;
        q.presentation_digest = q.calculate_presentation_digest().unwrap();
        assert!(q.validate().is_err());
    }
    #[test]
    fn return_request_is_closed_and_matches_actual_authorization_and_consent() {
        let mut p = read();
        let mut v: serde_json::Value = serde_json::from_str(&p.facts.request_json).unwrap();
        v["authority"] = serde_json::json!(true);
        assert!(SignerReturnRequestDataV1::parse_json(&v.to_string()).is_err());
        v.as_object_mut().unwrap().remove("authority");
        v["authorization_id"] = serde_json::json!("other-original-operation");
        p.facts.request_json = v.to_string();
        p.facts.request_digest =
            SignerReturnReadFactsV1::calculate_request_digest(&p.facts.request_json).unwrap();
        p.presentation_digest = p.calculate_presentation_digest().unwrap();
        assert!(p.validate().is_err());
    }
    #[test]
    fn tighter_financial_source_does_not_relabel_original_pair_clock() {
        let mut p = read();
        p.channel_ceiling_ms = p.source_ceiling_ms + 100000;
        p.channel_expires_at_ms = p
            .facts
            .original
            .activation
            .facts
            .original
            .source_expires_at_ms
            + 100000;
        p.presentation_digest = p.calculate_presentation_digest().unwrap();
        p.validate().unwrap();
        let mut q = p;
        q.service_ceiling_ms = q.source_ceiling_ms + 1;
        q.presentation_digest = q.calculate_presentation_digest().unwrap();
        assert!(q.validate().is_err());
    }
    #[test]
    fn return_partial_failure_never_claims_known_no_effect() {
        let raw =
            serde_json::json!({"presentation_digest":"ab".repeat(32),"stage":"KnownNoEffect"});
        assert!(serde_json::from_value::<SignerReturnFailureV1>(raw).is_err());
    }
}
