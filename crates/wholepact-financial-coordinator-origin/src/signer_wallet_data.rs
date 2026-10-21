//! Exact private wallet Prepare and separately reviewed same-source Observe.
use crate::signer_v3_pair_data::digest;
use crate::{
    financial_workflow_channel::FinancialActorContextV1, rejected, signer_continue_state::hash,
    Result, SignerActivateCommittedV1, SignerActivatePresentationV1,
};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerWalletOriginalV1 {
    pub activation: SignerActivatePresentationV1,
    pub activated: SignerActivateCommittedV1,
    pub fixed_identity_digest: String,
    pub configuration_json: String,
    pub configuration_digest: String,
}
impl SignerWalletOriginalV1 {
    pub fn calculate_configuration_digest(json: &str) -> Result<String> {
        digest(
            b"wholepact:coordinated-financial-wallet-configuration:v1\0",
            &json,
        )
    }
    pub fn validate(&self) -> Result<()> {
        self.activation.validate()?;
        self.activated.validate()?;
        let f = &self.activation.facts;
        if !hash(&self.fixed_identity_digest)
            || !hash(&self.configuration_digest)
            || self.configuration_json.len() > 32768
            || !serde_json::from_str::<serde_json::Value>(&self.configuration_json)
                .is_ok_and(|v| v.is_object())
            || self.configuration_digest
                != Self::calculate_configuration_digest(&self.configuration_json)?
            || self.activated.presentation_digest != self.activation.presentation_digest
            || self.activated.activation_request_digest != f.activation_request_digest
            || self.activated.session_id != f.original.acquired.session_id
            || self.activated.writer_epoch != f.writer_epoch
            || f.expected_head_sequence.checked_add(1) != Some(self.activated.head_sequence)
            || self.activated.head_digest == f.expected_head_digest
        {
            return Err(rejected("wallet actual original bindings"));
        }
        Ok(())
    }
}
pub(crate) const PREPARE_NOTICE:&str="Read the exact original account, fixed verified material, selected wallet configuration and guarded semantic journal pin to prepare this wallet. No FVK import, provider network request, ticket, key use, signature or return is permitted.";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerWalletPrepareFactsV1 {
    pub original: SignerWalletOriginalV1,
    pub display: String,
    pub reviewed_at_ms: u64,
    pub expires_at_ms: u64,
}
impl SignerWalletPrepareFactsV1 {
    pub fn validate(&self) -> Result<()> {
        self.original.validate()?;
        if self.display.is_empty()
            || self.display.len() > 8192
            || self.reviewed_at_ms == 0
            || self.expires_at_ms <= self.reviewed_at_ms
            || self.expires_at_ms - self.reviewed_at_ms > 120000
            || self.expires_at_ms > self.original.activation.facts.original.source_expires_at_ms
            || self.expires_at_ms
                > self
                    .original
                    .activation
                    .facts
                    .original
                    .acquired
                    .expires_at_ms
            || serde_json::to_vec(self)
                .map_err(|_| rejected("wallet facts encoding"))?
                .len()
                > 48 * 1024
        {
            return Err(rejected("wallet exact facts"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerWalletPreparePresentationV1 {
    pub actor: FinancialActorContextV1,
    pub facts: SignerWalletPrepareFactsV1,
    pub notice: String,
    pub challenge: String,
    pub source_ceiling_ms: u64,
    pub prepare_ceiling_ms: u64,
    pub service_ceiling_ms: u64,
    pub writer_session_ceiling_ms: u64,
    pub presentation_digest: String,
}
impl SignerWalletPreparePresentationV1 {
    pub fn calculate_presentation_digest(&self) -> Result<String> {
        digest(
            b"wholepact:coordinated-financial-wallet-prepare:presentation:v1\0",
            &(
                &self.actor,
                &self.facts,
                &self.notice,
                &self.challenge,
                self.source_ceiling_ms,
                self.prepare_ceiling_ms,
                self.service_ceiling_ms,
                self.writer_session_ceiling_ms,
            ),
        )
    }
    pub fn validate(&self) -> Result<()> {
        self.actor.validate()?;
        self.facts.validate()?;
        if self.actor != self.facts.original.activation.actor
            || self.notice != PREPARE_NOTICE
            || !hash(&self.challenge)
            || self.prepare_ceiling_ms == 0
            || self.prepare_ceiling_ms > self.service_ceiling_ms
            || self.prepare_ceiling_ms > self.writer_session_ceiling_ms
            || self.service_ceiling_ms > self.source_ceiling_ms
            || self.writer_session_ceiling_ms > self.source_ceiling_ms
            || self.source_ceiling_ms != self.facts.original.activation.source_ceiling_ms
            || self.presentation_digest != self.calculate_presentation_digest()?
            || serde_json::to_vec(self)
                .map_err(|_| rejected("wallet presentation encoding"))?
                .len()
                > 60 * 1024
        {
            return Err(rejected("wallet exact presentation"));
        }
        Ok(())
    }
}
pub(crate) const OBSERVE_NOTICE:&str="Revalidate only this exact prepared source and semantic journal pin, reread the same account FVK, enter one guarded FVK import, then sync and reconcile only the fixed inputs and retain one actual ticket under the original absolute ceilings. No new source/configuration, signing, reservation, key use or return is permitted.";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerWalletObserveFactsV1 {
    pub original: SignerWalletOriginalV1,
    pub display: String,
    pub reviewed_at_ms: u64,
    pub expires_at_ms: u64,
    pub prepare_presentation_digest: String,
    pub wallet_review_digest: String,
}
impl SignerWalletObserveFactsV1 {
    pub fn validate(&self) -> Result<()> {
        self.original.validate()?;
        if self.display.is_empty()
            || self.display.len() > 8192
            || self.reviewed_at_ms == 0
            || self.expires_at_ms <= self.reviewed_at_ms
            || self.expires_at_ms - self.reviewed_at_ms > 120000
            || self.expires_at_ms > self.original.activation.facts.original.source_expires_at_ms
            || self.expires_at_ms
                > self
                    .original
                    .activation
                    .facts
                    .original
                    .acquired
                    .expires_at_ms
            || !hash(&self.prepare_presentation_digest)
            || !hash(&self.wallet_review_digest)
            || serde_json::to_vec(self)
                .map_err(|_| rejected("wallet facts encoding"))?
                .len()
                > 48 * 1024
        {
            return Err(rejected("wallet exact facts"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerWalletObservePresentationV1 {
    pub actor: FinancialActorContextV1,
    pub facts: SignerWalletObserveFactsV1,
    pub notice: String,
    pub challenge: String,
    pub source_ceiling_ms: u64,
    pub observe_ceiling_ms: u64,
    pub service_ceiling_ms: u64,
    pub writer_session_ceiling_ms: u64,
    pub presentation_digest: String,
}
impl SignerWalletObservePresentationV1 {
    pub fn calculate_presentation_digest(&self) -> Result<String> {
        digest(
            b"wholepact:coordinated-financial-wallet-observe:presentation:v1\0",
            &(
                &self.actor,
                &self.facts,
                &self.notice,
                &self.challenge,
                self.source_ceiling_ms,
                self.observe_ceiling_ms,
                self.service_ceiling_ms,
                self.writer_session_ceiling_ms,
            ),
        )
    }
    pub fn validate(&self) -> Result<()> {
        self.actor.validate()?;
        self.facts.validate()?;
        if self.actor != self.facts.original.activation.actor
            || self.notice != OBSERVE_NOTICE
            || !hash(&self.challenge)
            || self.observe_ceiling_ms == 0
            || self.observe_ceiling_ms > self.service_ceiling_ms
            || self.observe_ceiling_ms > self.writer_session_ceiling_ms
            || self.service_ceiling_ms > self.source_ceiling_ms
            || self.writer_session_ceiling_ms > self.source_ceiling_ms
            || self.source_ceiling_ms != self.facts.original.activation.source_ceiling_ms
            || self.presentation_digest != self.calculate_presentation_digest()?
            || serde_json::to_vec(self)
                .map_err(|_| rejected("wallet presentation encoding"))?
                .len()
                > 60 * 1024
        {
            return Err(rejected("wallet exact presentation"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerWalletPreparedV1 {
    pub prepare_presentation_digest: String,
    pub activation_presentation_digest: String,
    pub fixed_identity_digest: String,
    pub configuration_digest: String,
    pub wallet_review_digest: String,
}
impl SignerWalletPreparedV1 {
    pub fn validate(&self) -> Result<()> {
        if ![
            &self.prepare_presentation_digest,
            &self.activation_presentation_digest,
            &self.fixed_identity_digest,
            &self.configuration_digest,
            &self.wallet_review_digest,
        ]
        .iter()
        .all(|v| hash(v))
        {
            return Err(rejected("wallet actual result"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerWalletObservedV1 {
    pub observe_presentation_digest: String,
    pub prepare_presentation_digest: String,
    pub activation_presentation_digest: String,
    pub fixed_identity_digest: String,
    pub configuration_digest: String,
    pub wallet_review_digest: String,
    pub wallet_observation_digest: String,
    pub tip_hash: String,
    pub anchor_hash: String,
    pub anchor_root: String,
    pub tip_height: u32,
    pub anchor_height: u32,
    pub input_count: u32,
}
impl SignerWalletObservedV1 {
    pub fn validate(&self) -> Result<()> {
        if ![
            &self.observe_presentation_digest,
            &self.prepare_presentation_digest,
            &self.activation_presentation_digest,
            &self.fixed_identity_digest,
            &self.configuration_digest,
            &self.wallet_review_digest,
            &self.wallet_observation_digest,
            &self.tip_hash,
            &self.anchor_hash,
            &self.anchor_root,
        ]
        .iter()
        .all(|v| hash(v))
            || self.input_count == 0
            || self.anchor_height > self.tip_height
        {
            return Err(rejected("wallet actual result"));
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignerWalletFailureStageV1 {
    PrepareFailed,
    ObserveUncertain,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerWalletFailureV1 {
    pub presentation_digest: String,
    pub stage: SignerWalletFailureStageV1,
}
impl SignerWalletFailureV1 {
    pub fn validate(&self) -> Result<()> {
        if !hash(&self.presentation_digest) {
            return Err(rejected("wallet failure binding"));
        }
        Ok(())
    }
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) fn prepare() -> SignerWalletPreparePresentationV1 {
        let activation = crate::signer_activate_wallet_data::tests::activate();
        let activated = SignerActivateCommittedV1 {
            presentation_digest: activation.presentation_digest.clone(),
            activate_ready_digest: "ef".repeat(32),
            activation_request_digest: activation.facts.activation_request_digest.clone(),
            signing_service_digest: "ab".repeat(32),
            session_id: activation.facts.original.acquired.session_id.clone(),
            writer_epoch: activation.facts.writer_epoch,
            head_sequence: activation.facts.expected_head_sequence + 1,
            head_digest: "ac".repeat(32),
        };
        let json = "{\"exact_wallet_configuration_fixture\":true}";
        let mut p =
            SignerWalletPreparePresentationV1 {
                actor: activation.actor.clone(),
                facts: SignerWalletPrepareFactsV1 {
                    original: SignerWalletOriginalV1 {
                        activation,
                        activated,
                        fixed_identity_digest: "ad".repeat(32),
                        configuration_json: json.into(),
                        configuration_digest:
                            SignerWalletOriginalV1::calculate_configuration_digest(json).unwrap(),
                    },
                    display: "Exact private wallet setup only".into(),
                    reviewed_at_ms: 4000,
                    expires_at_ms: 124000,
                },
                notice: PREPARE_NOTICE.into(),
                challenge: "ae".repeat(32),
                source_ceiling_ms: 300000,
                prepare_ceiling_ms: 124000,
                service_ceiling_ms: 250000,
                writer_session_ceiling_ms: 200000,
                presentation_digest: String::new(),
            };
        p.presentation_digest = p.calculate_presentation_digest().unwrap();
        p
    }
    pub(crate) fn prepared() -> SignerWalletPreparedV1 {
        let p = prepare();
        SignerWalletPreparedV1 {
            prepare_presentation_digest: p.presentation_digest,
            activation_presentation_digest: p.facts.original.activation.presentation_digest,
            fixed_identity_digest: p.facts.original.fixed_identity_digest,
            configuration_digest: p.facts.original.configuration_digest,
            wallet_review_digest: "ba".repeat(32),
        }
    }
    pub(crate) fn observe() -> SignerWalletObservePresentationV1 {
        let p = prepare();
        let d = prepared();
        let mut q=SignerWalletObservePresentationV1{actor:p.actor,facts:SignerWalletObserveFactsV1{original:p.facts.original,display:"Same-source journal/FVK revalidation, one entered import, exact fixed-input observation".into(),reviewed_at_ms:5000,expires_at_ms:125000,prepare_presentation_digest:d.prepare_presentation_digest,wallet_review_digest:d.wallet_review_digest},notice:OBSERVE_NOTICE.into(),challenge:p.challenge,source_ceiling_ms:p.source_ceiling_ms,observe_ceiling_ms:125000,service_ceiling_ms:p.service_ceiling_ms,writer_session_ceiling_ms:p.writer_session_ceiling_ms,presentation_digest:String::new()};
        q.presentation_digest = q.calculate_presentation_digest().unwrap();
        q
    }
    #[test]
    fn full_exact_config_and_actual_activation_are_committed() {
        let p = prepare();
        p.validate().unwrap();
        let mut q = p.clone();
        q.facts.original.configuration_json.push(' ');
        assert!(q.validate().is_err());
        let mut q = p;
        q.facts.original.activated.session_id = "ff".repeat(32);
        q.presentation_digest = q.calculate_presentation_digest().unwrap();
        assert!(q.validate().is_err());
    }
    #[test]
    fn private_prepare_cannot_substitute_for_import_and_observe() {
        let p = prepare();
        let q = observe();
        q.validate().unwrap();
        assert!(serde_json::from_value::<SignerWalletObservePresentationV1>(
            serde_json::to_value(p).unwrap()
        )
        .is_err());
        assert!(serde_json::from_value::<SignerWalletPreparePresentationV1>(
            serde_json::to_value(q).unwrap()
        )
        .is_err());
    }
    #[test]
    fn wallet_failure_never_claims_known_no_effect() {
        let raw =
            serde_json::json!({"presentation_digest":"ab".repeat(32),"stage":"KnownNoEffect"});
        assert!(serde_json::from_value::<SignerWalletFailureV1>(raw).is_err());
    }
}
