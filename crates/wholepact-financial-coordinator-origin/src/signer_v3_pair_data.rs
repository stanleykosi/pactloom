//! Ordinary descriptions for the fresh original-fork pairing purpose only.
use crate::{
    financial_workflow_channel::FinancialActorContextV1, rejected, signer_continue_state::hash,
    Result,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub(crate) const NOTICE:&str="Pair this exact fresh local channel with the original Host process only, until the separately displayed original channel expiry. The action window is not renewed at approval; original-fork provider identity is not native installation enrollment. No private journal Read, enrollment, manifest, export, redisclosure, delivery, admission or financial action is approved.";
pub(crate) fn digest<T: Serialize>(domain: &[u8], v: &T) -> Result<String> {
    let bytes = serde_json::to_vec(v).map_err(|_| rejected("pair encoding"))?;
    let mut h = Sha256::new();
    h.update(domain);
    h.update(bytes);
    Ok(hex::encode(h.finalize()))
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3PairEndpointV1 {
    pub entry_presentation_digest: String,
    pub source_identity_digest: String,
    pub endpoint_path: String,
    pub endpoint_digest: String,
    pub signer_process_instance: String,
    pub coordinated_provider_reference: String,
    pub source_expires_at_ms: u64,
}
impl SignerV3PairEndpointV1 {
    pub fn calculate_endpoint_digest(&self) -> Result<String> {
        digest(
            b"wholepact:coordinated-v3-pair:endpoint:v1\0",
            &(
                &self.entry_presentation_digest,
                &self.source_identity_digest,
                &self.endpoint_path,
                &self.signer_process_instance,
                &self.coordinated_provider_reference,
                self.source_expires_at_ms,
            ),
        )
    }
    pub fn validate(&self) -> Result<()> {
        if ![
            &self.entry_presentation_digest,
            &self.source_identity_digest,
            &self.endpoint_digest,
            &self.signer_process_instance,
            &self.coordinated_provider_reference,
        ]
        .iter()
        .all(|s| hash(s))
            || !self.endpoint_path.starts_with('/')
            || self.endpoint_path.len() > 4096
            || self.endpoint_path.contains('\0')
            || self.source_expires_at_ms == 0
            || self.endpoint_digest != self.calculate_endpoint_digest()?
        {
            return Err(rejected("pair endpoint binding"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3PairFactsV1 {
    pub channel_expires_at_ms: u64,
    pub entry_presentation_digest: String,
    pub source_identity_digest: String,
    pub endpoint_digest: String,
    pub pairing_review_digest: String,
    pub scope_json: String,
    pub generation: u64,
    pub original_host_uid: u32,
    pub original_host_pid: u32,
    pub original_host_process_instance: String,
    pub signer_process_instance: String,
    pub coordinated_provider_reference: String,
    pub reviewed_at_ms: u64,
    pub expires_at_ms: u64,
    pub source_expires_at_ms: u64,
    pub display: String,
}
impl SignerV3PairFactsV1 {
    pub fn validate(&self) -> Result<()> {
        if ![
            &self.entry_presentation_digest,
            &self.source_identity_digest,
            &self.endpoint_digest,
            &self.pairing_review_digest,
            &self.original_host_process_instance,
            &self.signer_process_instance,
            &self.coordinated_provider_reference,
        ]
        .iter()
        .all(|s| hash(s))
            || self.generation != 1
            || self.original_host_pid == 0
            || self.scope_json.len() > 8192
            || serde_json::from_str::<serde_json::Value>(&self.scope_json).is_err()
            || self.display.is_empty()
            || self.display.len() > 16384
            || self.reviewed_at_ms == 0
            || self.expires_at_ms <= self.reviewed_at_ms
            || self.expires_at_ms - self.reviewed_at_ms > 120000
            || self.expires_at_ms > self.channel_expires_at_ms
            || self.channel_expires_at_ms > self.source_expires_at_ms
            || self
                .channel_expires_at_ms
                .saturating_sub(self.reviewed_at_ms)
                > 900000
        {
            return Err(rejected("pair exact facts"));
        }
        Ok(())
    }
    pub(crate) fn matches_endpoint(&self, e: &SignerV3PairEndpointV1) -> bool {
        self.entry_presentation_digest == e.entry_presentation_digest
            && self.source_identity_digest == e.source_identity_digest
            && self.endpoint_digest == e.endpoint_digest
            && self.signer_process_instance == e.signer_process_instance
            && self.coordinated_provider_reference == e.coordinated_provider_reference
            && self.source_expires_at_ms == e.source_expires_at_ms
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3PairPresentationV1 {
    pub actor: FinancialActorContextV1,
    pub facts: SignerV3PairFactsV1,
    pub notice: String,
    pub challenge: String,
    pub source_ceiling_ms: u64,
    pub pair_ceiling_ms: u64,
    pub channel_ceiling_ms: u64,
    pub presentation_digest: String,
}
impl SignerV3PairPresentationV1 {
    pub fn calculate_presentation_digest(&self) -> Result<String> {
        digest(
            b"wholepact:coordinated-v3-pair:presentation:v1\0",
            &(
                &self.actor,
                &self.facts,
                &self.notice,
                &self.challenge,
                self.source_ceiling_ms,
                self.pair_ceiling_ms,
                self.channel_ceiling_ms,
            ),
        )
    }
    pub fn validate(&self) -> Result<()> {
        self.actor.validate()?;
        self.facts.validate()?;
        if self.notice != NOTICE
            || !hash(&self.challenge)
            || self.actor.signer_process_instance != self.facts.signer_process_instance
            || self.pair_ceiling_ms == 0
            || self.pair_ceiling_ms > self.channel_ceiling_ms
            || self.channel_ceiling_ms > self.source_ceiling_ms
            || self.source_ceiling_ms > crate::financial_workflow_clock::SUPERVISION_MS
            || self.presentation_digest != self.calculate_presentation_digest()?
        {
            return Err(rejected("pair presentation"));
        }
        Ok(())
    }
}
/// Immutable result of actual fresh token possession on the authenticated socket.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3PairedV1 {
    pub presentation_digest: String,
    pub source_identity_digest: String,
    pub original_host_process_instance: String,
    pub grant_id: String,
    pub key_digest: String,
    pub channel_digest: String,
    pub generation: u64,
}
impl SignerV3PairedV1 {
    pub fn validate(&self) -> Result<()> {
        if self.generation != 1
            || ![
                &self.presentation_digest,
                &self.source_identity_digest,
                &self.original_host_process_instance,
                &self.grant_id,
                &self.key_digest,
                &self.channel_digest,
            ]
            .iter()
            .all(|s| hash(s))
        {
            return Err(rejected("Pair authenticated result"));
        }
        Ok(())
    }
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) fn endpoint() -> SignerV3PairEndpointV1 {
        let mut e = SignerV3PairEndpointV1 {
            entry_presentation_digest: "11".repeat(32),
            source_identity_digest: "22".repeat(32),
            endpoint_path: "/tmp/original-pair/socket".into(),
            endpoint_digest: String::new(),
            signer_process_instance: "33".repeat(32),
            coordinated_provider_reference: "44".repeat(32),
            source_expires_at_ms: 999999,
        };
        e.endpoint_digest = e.calculate_endpoint_digest().unwrap();
        e
    }
    pub(crate) fn presentation() -> SignerV3PairPresentationV1 {
        let e = endpoint();
        let f = SignerV3PairFactsV1 {
            channel_expires_at_ms: 3000,
            entry_presentation_digest: e.entry_presentation_digest,
            source_identity_digest: e.source_identity_digest,
            endpoint_digest: e.endpoint_digest,
            pairing_review_digest: "55".repeat(32),
            scope_json: "{}".into(),
            generation: 1,
            original_host_uid: 1000,
            original_host_pid: 123,
            original_host_process_instance: "66".repeat(32),
            signer_process_instance: e.signer_process_instance.clone(),
            coordinated_provider_reference: e.coordinated_provider_reference,
            reviewed_at_ms: 1000,
            expires_at_ms: 2000,
            source_expires_at_ms: e.source_expires_at_ms,
            display: "Exact fresh original Host channel".into(),
        };
        let mut p = SignerV3PairPresentationV1 {
            actor: FinancialActorContextV1 {
                profile: crate::financial_workflow_clock::PROFILE.into(),
                coordinator_process_instance: "77".repeat(32),
                coordinator_focus_epoch: 1,
                signer_role: crate::SignerContinueRoleV1::Signer1,
                signer_process_instance: e.signer_process_instance,
                common_image_measurement: "88".repeat(32),
                session_challenge: "99".repeat(32),
            },
            facts: f,
            notice: NOTICE.into(),
            challenge: "aa".repeat(32),
            source_ceiling_ms: 3000,
            pair_ceiling_ms: 2000,
            channel_ceiling_ms: 3000,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest().unwrap();
        p
    }
    #[test]
    fn endpoint_binds_path_and_distinct_provider() {
        let e = endpoint();
        e.validate().unwrap();
        let mut bad = e.clone();
        bad.endpoint_path.push('x');
        assert!(bad.validate().is_err());
        let mut bad = e;
        bad.coordinated_provider_reference = "ff".repeat(32);
        assert!(bad.validate().is_err());
    }
    #[test]
    fn pair_exact_scope_generation_and_notice() {
        let p = presentation();
        p.validate().unwrap();
        let mut bad = p.clone();
        bad.facts.generation = 2;
        bad.presentation_digest = bad.calculate_presentation_digest().unwrap();
        assert!(bad.validate().is_err());
        let mut bad = p;
        bad.notice = "native provider enrollment".into();
        bad.presentation_digest = bad.calculate_presentation_digest().unwrap();
        assert!(bad.validate().is_err());
    }
    #[test]
    fn pair_wire_rejects_legacy_provider_field() {
        let p = presentation();
        let mut v = serde_json::to_value(p).unwrap();
        v["facts"]["provider_enrollment_reference"] = serde_json::json!("ff".repeat(32));
        assert!(serde_json::from_value::<SignerV3PairPresentationV1>(v).is_err());
    }
}
#[cfg(test)]
mod channel_clock_tests {
    use super::*;
    #[test]
    fn channel_window_is_frozen_separately_from_action() {
        let p = tests::presentation();
        assert!(p.facts.channel_expires_at_ms > p.facts.expires_at_ms);
        let mut changed = p.clone();
        changed.channel_ceiling_ms -= 1;
        assert!(changed.validate().is_err());
        let mut widened = p;
        widened.facts.channel_expires_at_ms = widened.facts.reviewed_at_ms + 900001;
        widened.presentation_digest = widened.calculate_presentation_digest().unwrap();
        assert!(widened.validate().is_err());
    }
    #[test]
    fn action_cannot_outlive_original_channel() {
        let mut p = tests::presentation();
        p.facts.channel_expires_at_ms = p.facts.expires_at_ms - 1;
        p.presentation_digest = p.calculate_presentation_digest().unwrap();
        assert!(p.validate().is_err());
        let mut p = tests::presentation();
        p.pair_ceiling_ms = p.channel_ceiling_ms + 1;
        p.presentation_digest = p.calculate_presentation_digest().unwrap();
        assert!(p.validate().is_err());
    }
}
