//! Distinct same-source writer Read and exact one-use signing, never native grants.
use crate::signer_v3_pair_data::digest;
use crate::{
    financial_workflow_channel::FinancialActorContextV1, rejected, signer_continue_state::hash,
    Result, SignerWalletObservedV1, SignerWalletOriginalV1,
};
use serde::{Deserialize, Serialize};
fn original(o: &SignerWalletOriginalV1, v: &SignerWalletObservedV1) -> Result<()> {
    o.validate()?;
    v.validate()?;
    if v.activation_presentation_digest != o.activation.presentation_digest
        || v.fixed_identity_digest != o.fixed_identity_digest
        || v.configuration_digest != o.configuration_digest
    {
        return Err(rejected("sign actual observed source/config mismatch"));
    }
    Ok(())
}
fn window(o: &SignerWalletOriginalV1, display: &str, a: u64, b: u64) -> Result<()> {
    if display.is_empty()
        || display.len() > 8192
        || a == 0
        || b <= a
        || b - a > 120000
        || b > o.activation.facts.original.source_expires_at_ms
        || b > o.activation.facts.original.acquired.expires_at_ms
    {
        return Err(rejected("sign original bounded action"));
    }
    Ok(())
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerSignReadFactsV1 {
    pub original: SignerWalletOriginalV1,
    pub observed: SignerWalletObservedV1,
    pub display: String,
    pub reviewed_at_ms: u64,
    pub expires_at_ms: u64,
}
impl SignerSignReadFactsV1 {
    pub fn validate(&self) -> Result<()> {
        original(&self.original, &self.observed)?;
        window(
            &self.original,
            &self.display,
            self.reviewed_at_ms,
            self.expires_at_ms,
        )?;
        if serde_json::to_vec(self)
            .map_err(|_| rejected("sign facts encoding"))?
            .len()
            > 48 * 1024
        {
            return Err(rejected("sign facts bound"));
        }
        Ok(())
    }
}
pub(crate) const READ_NOTICE:&str="Authenticate only the same retained writer active session and full history, and read the same guarded original source to prepare one immutable exact spend. No reservation, journal mutation, private spending key, signature or return.";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerSignReadPresentationV1 {
    pub actor: FinancialActorContextV1,
    pub facts: SignerSignReadFactsV1,
    pub notice: String,
    pub challenge: String,
    pub source_ceiling_ms: u64,
    pub read_ceiling_ms: u64,
    pub service_ceiling_ms: u64,
    pub writer_session_ceiling_ms: u64,
    pub presentation_digest: String,
}
impl SignerSignReadPresentationV1 {
    pub fn calculate_presentation_digest(&self) -> Result<String> {
        digest(
            b"wholepact:coordinated-financial-sign-read:presentation:v1\0",
            &(
                &self.actor,
                &self.facts,
                &self.notice,
                &self.challenge,
                self.source_ceiling_ms,
                self.read_ceiling_ms,
                self.service_ceiling_ms,
                self.writer_session_ceiling_ms,
            ),
        )
    }
    pub fn validate(&self) -> Result<()> {
        self.actor.validate()?;
        self.facts.validate()?;
        if self.actor != self.facts.original.activation.actor
            || self.notice != READ_NOTICE
            || !hash(&self.challenge)
            || self.read_ceiling_ms == 0
            || self.read_ceiling_ms > self.service_ceiling_ms
            || self.read_ceiling_ms > self.writer_session_ceiling_ms
            || self.service_ceiling_ms > self.source_ceiling_ms
            || self.writer_session_ceiling_ms > self.source_ceiling_ms
            || self.source_ceiling_ms != self.facts.original.activation.source_ceiling_ms
            || self.presentation_digest != self.calculate_presentation_digest()?
            || serde_json::to_vec(self)
                .map_err(|_| rejected("sign presentation encoding"))?
                .len()
                > 60 * 1024
        {
            return Err(rejected("sign exact presentation"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerSignExactFactsV1 {
    pub original: SignerWalletOriginalV1,
    pub observed: SignerWalletObservedV1,
    pub original_read_presentation_digest: String,
    pub signing_terms_digest: String,
    pub signer_principal_id: String,
    pub spend_terms_json: String,
    pub authenticated_history_digest: String,
    pub authenticated_snapshot_json: String,
    pub active_receipt_json: String,
    pub active_receipt_digest: String,
    pub display: String,
    pub reviewed_at_ms: u64,
    pub expires_at_ms: u64,
}
impl SignerSignExactFactsV1 {
    pub fn expected_authorization_id(&self) -> Result<String> {
        let v: serde_json::Value = serde_json::from_str(&self.spend_terms_json)
            .map_err(|_| rejected("sign exact spend terms JSON"))?;
        let id = v
            .get("authorization_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| rejected("sign exact authorization absent"))?;
        if id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_:./@".contains(&b))
        {
            return Err(rejected("sign exact authorization bound"));
        }
        Ok(id.into())
    }

    pub fn calculate_active_receipt_digest(json: &str) -> Result<String> {
        digest(
            b"wholepact:coordinated-financial-sign-active-receipt:v1\0",
            &json,
        )
    }

    pub fn validate(&self) -> Result<()> {
        self.expected_authorization_id()?;
        original(&self.original, &self.observed)?;
        window(
            &self.original,
            &self.display,
            self.reviewed_at_ms,
            self.expires_at_ms,
        )?;
        if ![
            &self.original_read_presentation_digest,
            &self.signing_terms_digest,
            &self.authenticated_history_digest,
            &self.active_receipt_digest,
        ]
        .iter()
        .all(|v| hash(v))
            || self.active_receipt_digest
                != Self::calculate_active_receipt_digest(&self.active_receipt_json)?
            || self.signer_principal_id.is_empty()
            || self.signer_principal_id.len() > 256

            || [
                &self.spend_terms_json,
                &self.authenticated_snapshot_json,
                &self.active_receipt_json,
            ]
            .iter()
            .any(|v| {
                v.len() > 16384
                    || !serde_json::from_str::<serde_json::Value>(v).is_ok_and(|x| x.is_object())
            })
        {
            return Err(rejected("sign exact prepared commitments"));
        }
        if serde_json::to_vec(self)
            .map_err(|_| rejected("sign facts encoding"))?
            .len()
            > 48 * 1024
        {
            return Err(rejected("sign facts bound"));
        }
        Ok(())
    }
}
pub(crate) const EXACT_NOTICE:&str="Approve only this exact prepared spend: release and request commits, same-writer reservation, authenticated permit commit, Started commit, one entered protected key derivation and exact signing operation, then one result commit. Original source, wallet, writer session and all deadlines remain fixed; errors or uncertain effects are terminal, never retry.";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerSignExactPresentationV1 {
    pub actor: FinancialActorContextV1,
    pub facts: SignerSignExactFactsV1,
    pub notice: String,
    pub challenge: String,
    pub source_ceiling_ms: u64,
    pub sign_ceiling_ms: u64,
    pub service_ceiling_ms: u64,
    pub writer_session_ceiling_ms: u64,
    pub presentation_digest: String,
}
impl SignerSignExactPresentationV1 {
    pub fn calculate_presentation_digest(&self) -> Result<String> {
        digest(
            b"wholepact:coordinated-financial-sign-sign:presentation:v1\0",
            &(
                &self.actor,
                &self.facts,
                &self.notice,
                &self.challenge,
                self.source_ceiling_ms,
                self.sign_ceiling_ms,
                self.service_ceiling_ms,
                self.writer_session_ceiling_ms,
            ),
        )
    }
    pub fn validate(&self) -> Result<()> {
        self.actor.validate()?;
        self.facts.validate()?;
        if self.actor != self.facts.original.activation.actor
            || self.notice != EXACT_NOTICE
            || !hash(&self.challenge)
            || self.sign_ceiling_ms == 0
            || self.sign_ceiling_ms > self.service_ceiling_ms
            || self.sign_ceiling_ms > self.writer_session_ceiling_ms
            || self.service_ceiling_ms > self.source_ceiling_ms
            || self.writer_session_ceiling_ms > self.source_ceiling_ms
            || self.source_ceiling_ms != self.facts.original.activation.source_ceiling_ms
            || self.presentation_digest != self.calculate_presentation_digest()?
            || serde_json::to_vec(self)
                .map_err(|_| rejected("sign presentation encoding"))?
                .len()
                > 60 * 1024
        {
            return Err(rejected("sign exact presentation"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerSignPreparedV1 {
    pub read_presentation_digest: String,
    pub signing_terms_digest: String,
    pub active_receipt_digest: String,
    pub authenticated_history_digest: String,
}
impl SignerSignPreparedV1 {
    pub fn validate(&self) -> Result<()> {
        if ![
            &self.read_presentation_digest,
            &self.signing_terms_digest,
            &self.active_receipt_digest,
            &self.authenticated_history_digest,
        ]
        .iter()
        .all(|v| hash(v))
        {
            return Err(rejected("sign actual result commitments"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerSignCommittedV1 {
    pub sign_presentation_digest: String,
    pub authorization_id: String,
    pub original_consent_ref: String,
    pub result_digest: String,
    pub outbox_digest: String,
    pub fixed_identity_digest: String,
}
impl SignerSignCommittedV1 {
    pub fn validate(&self) -> Result<()> {
        if self.authorization_id.is_empty()
            || self.authorization_id.len() > 128

            || !self
                .authorization_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_:./@".contains(&b))
        {
            return Err(rejected("sign authorization identifier"));
        }

        if ![
            &self.sign_presentation_digest,
            &self.original_consent_ref,
            &self.result_digest,
            &self.outbox_digest,
            &self.fixed_identity_digest,
        ]
        .iter()
        .all(|v| hash(v))
        {
            return Err(rejected("sign actual result commitments"));
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum SignerSignFailureStageV1 {
    ReadFailed,
    SignUncertain,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerSignFailureV1 {
    pub presentation_digest: String,
    pub stage: SignerSignFailureStageV1,
}
impl SignerSignFailureV1 {
    pub fn validate(&self) -> Result<()> {
        if !hash(&self.presentation_digest) {
            return Err(rejected("sign failure binding"));
        }
        Ok(())
    }
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) fn read() -> SignerSignReadPresentationV1 {
        let w = crate::signer_wallet_data::tests::observe();
        let original = w.facts.original;
        let observed = SignerWalletObservedV1 {
            observe_presentation_digest: w.presentation_digest,
            prepare_presentation_digest: w.facts.prepare_presentation_digest,
            activation_presentation_digest: original.activation.presentation_digest.clone(),
            fixed_identity_digest: original.fixed_identity_digest.clone(),
            configuration_digest: original.configuration_digest.clone(),
            wallet_review_digest: w.facts.wallet_review_digest,
            wallet_observation_digest: "ab".repeat(32),
            tip_height: 2,
            tip_hash: "bc".repeat(32),
            anchor_height: 1,
            anchor_hash: "cd".repeat(32),
            anchor_root: "de".repeat(32),
            input_count: 1,
        };
        let mut p = SignerSignReadPresentationV1 {
            actor: w.actor,
            facts: SignerSignReadFactsV1 {
                original,
                observed,
                display: "Same writer active session/history and guarded immutable spend Read"
                    .into(),
                reviewed_at_ms: 6000,
                expires_at_ms: 126000,
            },
            notice: READ_NOTICE.into(),
            challenge: "ef".repeat(32),
            source_ceiling_ms: w.source_ceiling_ms,
            read_ceiling_ms: 126000,
            service_ceiling_ms: w.service_ceiling_ms,
            writer_session_ceiling_ms: w.writer_session_ceiling_ms,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest().unwrap();
        p
    }
    pub(crate) fn exact() -> SignerSignExactPresentationV1 {
        let r = read();
        let receipt = "{\"actual\":\"receipt\"}".to_string();
        let mut p = SignerSignExactPresentationV1 {
            actor: r.actor,
            facts: SignerSignExactFactsV1 {
                original: r.facts.original,
                observed: r.facts.observed,
                original_read_presentation_digest: r.presentation_digest,
                signing_terms_digest: "ab".repeat(32),
                signer_principal_id: "original-principal".into(),
                spend_terms_json: "{\"authorization_id\":\"exact-original-operation-1\"}".into(),
                authenticated_history_digest: "bc".repeat(32),
                authenticated_snapshot_json: "{}".into(),
                active_receipt_digest: SignerSignExactFactsV1::calculate_active_receipt_digest(
                    &receipt,
                )
                .unwrap(),
                active_receipt_json: receipt,
                display: "Exact spend and six ordered actual effect scopes".into(),
                reviewed_at_ms: 7000,
                expires_at_ms: 127000,
            },
            notice: EXACT_NOTICE.into(),
            challenge: r.challenge,
            source_ceiling_ms: r.source_ceiling_ms,
            sign_ceiling_ms: 127000,
            service_ceiling_ms: r.service_ceiling_ms,
            writer_session_ceiling_ms: r.writer_session_ceiling_ms,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest().unwrap();
        p
    }
    #[test]
    fn sign_requires_exact_actual_wallet_and_active_receipt_bytes() {
        let p = exact();
        p.validate().unwrap();
        let mut q = p.clone();
        q.facts.active_receipt_json.push(' ');
        q.presentation_digest = q.calculate_presentation_digest().unwrap();
        assert!(q.validate().is_err());
        let mut q = p;
        q.facts.observed.fixed_identity_digest = "ff".repeat(32);
        q.presentation_digest = q.calculate_presentation_digest().unwrap();
        assert!(q.validate().is_err());
    }
    #[test]
    fn sign_read_and_exact_are_distinct_closed_profiles() {
        read().validate().unwrap();
        exact().validate().unwrap();
        assert!(serde_json::from_value::<SignerSignExactPresentationV1>(
            serde_json::to_value(read()).unwrap()
        )
        .is_err());
        assert!(serde_json::from_value::<SignerSignReadPresentationV1>(
            serde_json::to_value(exact()).unwrap()
        )
        .is_err());
    }
    #[test]
    fn actual_authorization_identifier_not_fabricated_hash() {
        let d = SignerSignCommittedV1 {
            sign_presentation_digest: "ab".repeat(32),
            authorization_id: "exact-original-operation-1".into(),
            original_consent_ref: "bc".repeat(32),
            result_digest: "cd".repeat(32),
            outbox_digest: "de".repeat(32),
            fixed_identity_digest: "ef".repeat(32),
        };
        d.validate().unwrap();
        let raw =
            serde_json::json!({"presentation_digest":"ab".repeat(32),"stage":"KnownNoEffect"});
        assert!(serde_json::from_value::<SignerSignFailureV1>(raw).is_err());
    }
}
