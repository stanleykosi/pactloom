//! Separate private preparation Read and one exact bounded payload Receive.
use crate::signer_v3_pair_data::digest;
use crate::{
    financial_workflow_channel::FinancialActorContextV1, rejected, signer_continue_state::hash,
    Result,
};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3OwnerSetupSelectionV1 {
    pub schema_version: u16,
    pub endpoint: std::net::SocketAddr,
    pub server_name: String,
    pub witness_id: String,
    pub account_id: String,
    pub network_profile_id: String,
    pub policy_digest: String,
    pub pinned_server_certificate_digest: String,
    pub trusted_server_root_der: std::path::PathBuf,
    pub client_certificate_der: std::path::PathBuf,
    pub client_private_key_pkcs8_der: std::path::PathBuf,
    pub operator_name: String,
    pub retention_statement: String,
}
impl SignerV3OwnerSetupSelectionV1 {
    pub fn parse_json(raw: &str) -> Result<Self> {
        if raw.len() > 16384 {
            return Err(rejected("owner selection oversized"));
        }
        let s: Self = serde_json::from_str(raw).map_err(|_| rejected("owner selection schema"))?;
        if s.schema_version != 1
            || !hash(&s.policy_digest)
            || !hash(&s.pinned_server_certificate_digest)
            || [
                &s.server_name,
                &s.witness_id,
                &s.account_id,
                &s.network_profile_id,
                &s.operator_name,
                &s.retention_statement,
            ]
            .iter()
            .any(|v| v.is_empty() || v.len() > 4096)
            || [
                &s.trusted_server_root_der,
                &s.client_certificate_der,
                &s.client_private_key_pkcs8_der,
            ]
            .iter()
            .any(|v| !v.is_absolute() || v.as_os_str().len() > 4096)
        {
            return Err(rejected("owner selection values"));
        }
        Ok(s)
    }
}
pub(crate) const PREPARE_READ_NOTICE:&str="Read exactly the selected private source and owner client key to prepare this immutable recipient delivery and retain local client custody. This does not authenticate a remote owner or authorize history, Receive, admission, export or financial effects.";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3PrepareReadFactsV1 {
    pub entry_presentation_digest: String,
    pub source_identity_digest: String,
    pub pair_grant_id: String,
    pub pair_key_digest: String,
    pub pair_channel_digest: String,
    pub coordinated_session_id: String,
    pub current_enrollment_ref: String,
    pub current_manifest_ref: String,
    pub current_outbox_reference: String,
    pub current_request_digest: String,
    pub preparation_digest: String,
    pub owner_selection_digest: String,
    pub owner_certificate_digest: String,
    pub disclosure_digest: String,
    pub payload_digest: String,
    pub fixed_identity_digest: String,
    pub material_scopes_digest: String,
    pub coordinated_provider_reference: String,
    pub original_host_process_instance: String,
    pub display: String,
    pub preparation_json: String,
    pub owner_setup_json: String,
    pub owner_selection_challenge: String,
    pub pair_generation: u64,
    pub payload_bytes: u64,
    pub reviewed_at_ms: u64,
    pub expires_at_ms: u64,
    pub source_expires_at_ms: u64,
    pub service_expires_at_ms: u64,
    pub material_expires_at_ms: u64,
}
impl SignerV3PrepareReadFactsV1 {
    pub fn validate(&self) -> Result<()> {
        SignerV3OwnerSetupSelectionV1::parse_json(&self.owner_setup_json)?;
        if ![
            &self.entry_presentation_digest,
            &self.source_identity_digest,
            &self.pair_grant_id,
            &self.pair_key_digest,
            &self.pair_channel_digest,
            &self.coordinated_session_id,
            &self.current_enrollment_ref,
            &self.current_manifest_ref,
            &self.current_outbox_reference,
            &self.current_request_digest,
            &self.preparation_digest,
            &self.owner_selection_digest,
            &self.owner_certificate_digest,
            &self.disclosure_digest,
            &self.payload_digest,
            &self.fixed_identity_digest,
            &self.material_scopes_digest,
            &self.coordinated_provider_reference,
            &self.original_host_process_instance,
            &self.owner_selection_challenge,
        ]
        .iter()
        .all(|v| hash(v))
            || self.pair_generation != 1
            || self.payload_bytes == 0
            || self.payload_bytes > 5 * 1024 * 1024
            || self.display.is_empty()
            || self.display.len() > 8192
            || self.reviewed_at_ms == 0
            || self.expires_at_ms <= self.reviewed_at_ms
            || self.expires_at_ms - self.reviewed_at_ms > 120000
            || self.expires_at_ms > self.source_expires_at_ms
            || self.expires_at_ms > self.service_expires_at_ms
            || self.expires_at_ms > self.material_expires_at_ms
            || self.service_expires_at_ms > self.source_expires_at_ms
            || self.material_expires_at_ms > self.source_expires_at_ms
            || self.preparation_json.len() > 32768
            || !serde_json::from_str::<serde_json::Value>(&self.preparation_json)
                .is_ok_and(|v| v.is_object())
            || serde_json::to_vec(self)
                .map_err(|_| rejected("delivery facts encoding"))?
                .len()
                > 48 * 1024
        {
            return Err(rejected("delivery exact facts"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3PrepareReadPresentationV1 {
    pub actor: FinancialActorContextV1,
    pub facts: SignerV3PrepareReadFactsV1,
    pub notice: String,
    pub challenge: String,
    pub source_ceiling_ms: u64,
    pub review_ceiling_ms: u64,
    pub service_ceiling_ms: u64,
    pub material_ceiling_ms: u64,
    pub presentation_digest: String,
}
impl SignerV3PrepareReadPresentationV1 {
    pub fn calculate_presentation_digest(&self) -> Result<String> {
        digest(
            b"wholepact:coordinated-v3-prepare_read:presentation:v1\0",
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
        if self.notice != PREPARE_READ_NOTICE
            || !hash(&self.challenge)
            || self.review_ceiling_ms == 0
            || self.review_ceiling_ms > self.service_ceiling_ms
            || self.review_ceiling_ms > self.material_ceiling_ms
            || self.service_ceiling_ms > self.source_ceiling_ms
            || self.material_ceiling_ms > self.source_ceiling_ms
            || self.source_ceiling_ms > crate::financial_workflow_clock::SUPERVISION_MS
            || self.presentation_digest != self.calculate_presentation_digest()?
            || serde_json::to_vec(self)
                .map_err(|_| rejected("delivery presentation encoding"))?
                .len()
                > 60 * 1024
        {
            return Err(rejected("delivery presentation"));
        }
        Ok(())
    }
}
pub(crate) const RECEIVE_NOTICE:&str="Receive and verify one exact bounded payload on this original authenticated paired channel for this immutable preparation. The actual recipient intent is issued only after this decision. No owner history, admission or financial effect is approved.";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3ReceiveFactsV1 {
    pub entry_presentation_digest: String,
    pub source_identity_digest: String,
    pub pair_grant_id: String,
    pub pair_key_digest: String,
    pub pair_channel_digest: String,
    pub coordinated_session_id: String,
    pub current_enrollment_ref: String,
    pub current_manifest_ref: String,
    pub current_outbox_reference: String,
    pub current_request_digest: String,
    pub preparation_digest: String,
    pub owner_selection_digest: String,
    pub owner_certificate_digest: String,
    pub disclosure_digest: String,
    pub payload_digest: String,
    pub fixed_identity_digest: String,
    pub material_scopes_digest: String,
    pub coordinated_provider_reference: String,
    pub original_host_process_instance: String,
    pub display: String,
    pub prepare_read_presentation_digest: String,
    pub owner_service_digest: String,
    pub read_session_digest: String,
    pub pair_generation: u64,
    pub payload_bytes: u64,
    pub reviewed_at_ms: u64,
    pub expires_at_ms: u64,
    pub source_expires_at_ms: u64,
    pub service_expires_at_ms: u64,
    pub material_expires_at_ms: u64,
}
impl SignerV3ReceiveFactsV1 {
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
            &self.current_outbox_reference,
            &self.current_request_digest,
            &self.preparation_digest,
            &self.owner_selection_digest,
            &self.owner_certificate_digest,
            &self.disclosure_digest,
            &self.payload_digest,
            &self.fixed_identity_digest,
            &self.material_scopes_digest,
            &self.coordinated_provider_reference,
            &self.original_host_process_instance,
            &self.prepare_read_presentation_digest,
            &self.owner_service_digest,
            &self.read_session_digest,
        ]
        .iter()
        .all(|v| hash(v))
            || self.pair_generation != 1
            || self.payload_bytes == 0
            || self.payload_bytes > 5 * 1024 * 1024
            || self.display.is_empty()
            || self.display.len() > 8192
            || self.reviewed_at_ms == 0
            || self.expires_at_ms <= self.reviewed_at_ms
            || self.expires_at_ms - self.reviewed_at_ms > 120000
            || self.expires_at_ms > self.source_expires_at_ms
            || self.expires_at_ms > self.service_expires_at_ms
            || self.expires_at_ms > self.material_expires_at_ms
            || self.service_expires_at_ms > self.source_expires_at_ms
            || self.material_expires_at_ms > self.source_expires_at_ms
            || self.read_session_digest != self.prepare_read_presentation_digest
            || serde_json::to_vec(self)
                .map_err(|_| rejected("delivery facts encoding"))?
                .len()
                > 48 * 1024
        {
            return Err(rejected("delivery exact facts"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3ReceivePresentationV1 {
    pub actor: FinancialActorContextV1,
    pub facts: SignerV3ReceiveFactsV1,
    pub notice: String,
    pub challenge: String,
    pub source_ceiling_ms: u64,
    pub review_ceiling_ms: u64,
    pub service_ceiling_ms: u64,
    pub material_ceiling_ms: u64,
    pub presentation_digest: String,
}
impl SignerV3ReceivePresentationV1 {
    pub fn calculate_presentation_digest(&self) -> Result<String> {
        digest(
            b"wholepact:coordinated-v3-receive:presentation:v1\0",
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
        if self.notice != RECEIVE_NOTICE
            || !hash(&self.challenge)
            || self.review_ceiling_ms == 0
            || self.review_ceiling_ms > self.service_ceiling_ms
            || self.review_ceiling_ms > self.material_ceiling_ms
            || self.service_ceiling_ms > self.source_ceiling_ms
            || self.material_ceiling_ms > self.source_ceiling_ms
            || self.source_ceiling_ms > crate::financial_workflow_clock::SUPERVISION_MS
            || self.presentation_digest != self.calculate_presentation_digest()?
            || serde_json::to_vec(self)
                .map_err(|_| rejected("delivery presentation encoding"))?
                .len()
                > 60 * 1024
        {
            return Err(rejected("delivery presentation"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3PreparedV1 {
    pub prepare_read_presentation_digest: String,
    pub preparation_digest: String,
    pub source_identity_digest: String,
    pub owner_service_digest: String,
    pub read_session_digest: String,
}
impl SignerV3PreparedV1 {
    pub fn validate(&self) -> Result<()> {
        if ![
            &self.prepare_read_presentation_digest,
            &self.preparation_digest,
            &self.source_identity_digest,
            &self.owner_service_digest,
            &self.read_session_digest,
        ]
        .iter()
        .all(|v| hash(v))
            || self.read_session_digest != self.prepare_read_presentation_digest
        {
            return Err(rejected("delivery actual result"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3ReceivedV1 {
    pub receive_presentation_digest: String,
    pub prepare_read_presentation_digest: String,
    pub source_identity_digest: String,
    pub owner_service_digest: String,
    pub recipient_intent_digest: String,
    pub payload_digest: String,
    pub fixed_identity_digest: String,
    pub payload_bytes: u64,
}
impl SignerV3ReceivedV1 {
    pub fn validate(&self) -> Result<()> {
        if ![
            &self.receive_presentation_digest,
            &self.prepare_read_presentation_digest,
            &self.source_identity_digest,
            &self.owner_service_digest,
            &self.recipient_intent_digest,
            &self.payload_digest,
            &self.fixed_identity_digest,
        ]
        .iter()
        .all(|v| hash(v))
            || self.payload_bytes == 0
            || self.payload_bytes > 5 * 1024 * 1024
        {
            return Err(rejected("delivery actual result"));
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) fn owner_json() -> String {
        serde_json::to_string(&SignerV3OwnerSetupSelectionV1 {
            schema_version: 1,
            endpoint: "127.0.0.1:443".parse().unwrap(),
            server_name: "w.example".into(),
            witness_id: "w".into(),
            account_id: "a".into(),
            network_profile_id: "n".into(),
            policy_digest: "ab".repeat(32),
            pinned_server_certificate_digest: "ac".repeat(32),
            trusted_server_root_der: "/selected/root.der".into(),
            client_certificate_der: "/selected/client.der".into(),
            client_private_key_pkcs8_der: "/selected/key.der".into(),
            operator_name: "operator".into(),
            retention_statement: "selected retention".into(),
        })
        .unwrap()
    }
    pub(crate) fn read() -> SignerV3PrepareReadPresentationV1 {
        let old = crate::signer_v3_redisclosure_data::tests::read();
        let pair = crate::signer_v3_pair_data::tests::presentation();
        let f = old.facts;
        let mut p = SignerV3PrepareReadPresentationV1 {
            actor: old.actor,
            facts: SignerV3PrepareReadFactsV1 {
                entry_presentation_digest: f.entry_presentation_digest,
                source_identity_digest: f.source_identity_digest,
                pair_grant_id: f.pair_grant_id,
                pair_key_digest: f.pair_key_digest,
                pair_channel_digest: f.pair_channel_digest,
                coordinated_session_id: f.coordinated_session_id,
                current_enrollment_ref: f.current_enrollment_ref,
                current_manifest_ref: f.current_manifest_ref,
                current_outbox_reference: "ab".repeat(32),
                current_request_digest: "ab".repeat(32),
                preparation_digest: "ab".repeat(32),
                owner_selection_digest: "ab".repeat(32),
                owner_certificate_digest: "ab".repeat(32),
                disclosure_digest: "ab".repeat(32),
                payload_digest: "ab".repeat(32),
                fixed_identity_digest: "ab".repeat(32),
                material_scopes_digest: "ab".repeat(32),
                owner_selection_challenge: "ab".repeat(32),
                coordinated_provider_reference: pair.facts.coordinated_provider_reference,
                original_host_process_instance: pair.facts.original_host_process_instance,
                display: "Full source and selected local client Read only".into(),
                preparation_json: "{\"version\":1}".into(),
                owner_setup_json: owner_json(),
                pair_generation: 1,
                payload_bytes: 123,
                reviewed_at_ms: 1500,
                expires_at_ms: 2500,
                source_expires_at_ms: f.source_expires_at_ms,
                service_expires_at_ms: 2900,
                material_expires_at_ms: 2800,
            },
            notice: PREPARE_READ_NOTICE.into(),
            challenge: "cd".repeat(32),
            source_ceiling_ms: 3000,
            review_ceiling_ms: 2500,
            service_ceiling_ms: 2900,
            material_ceiling_ms: 2800,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest().unwrap();
        p
    }
    pub(crate) fn prepared() -> SignerV3PreparedV1 {
        let r = read();
        SignerV3PreparedV1 {
            prepare_read_presentation_digest: r.presentation_digest.clone(),
            read_session_digest: r.presentation_digest,
            preparation_digest: r.facts.preparation_digest,
            source_identity_digest: r.facts.source_identity_digest,
            owner_service_digest: "ee".repeat(32),
        }
    }
    pub(crate) fn receive() -> SignerV3ReceivePresentationV1 {
        let r = read();
        let d = prepared();
        let f = r.facts;
        let mut p = SignerV3ReceivePresentationV1 {
            actor: r.actor,
            facts: SignerV3ReceiveFactsV1 {
                entry_presentation_digest: f.entry_presentation_digest,
                source_identity_digest: f.source_identity_digest,
                pair_grant_id: f.pair_grant_id,
                pair_key_digest: f.pair_key_digest,
                pair_channel_digest: f.pair_channel_digest,
                coordinated_session_id: f.coordinated_session_id,
                current_enrollment_ref: f.current_enrollment_ref,
                current_manifest_ref: f.current_manifest_ref,
                current_outbox_reference: f.current_outbox_reference,
                current_request_digest: f.current_request_digest,
                preparation_digest: f.preparation_digest,
                owner_selection_digest: f.owner_selection_digest,
                owner_certificate_digest: f.owner_certificate_digest,
                disclosure_digest: f.disclosure_digest,
                payload_digest: f.payload_digest,
                fixed_identity_digest: f.fixed_identity_digest,
                material_scopes_digest: f.material_scopes_digest,
                coordinated_provider_reference: f.coordinated_provider_reference,
                original_host_process_instance: f.original_host_process_instance,
                display: f.display,
                prepare_read_presentation_digest: r.presentation_digest,
                owner_service_digest: d.owner_service_digest,
                read_session_digest: d.read_session_digest,
                pair_generation: f.pair_generation,
                payload_bytes: f.payload_bytes,
                reviewed_at_ms: 1600,
                expires_at_ms: 2600,
                source_expires_at_ms: f.source_expires_at_ms,
                service_expires_at_ms: f.service_expires_at_ms,
                material_expires_at_ms: f.material_expires_at_ms,
            },
            notice: RECEIVE_NOTICE.into(),
            challenge: r.challenge,
            source_ceiling_ms: r.source_ceiling_ms,
            review_ceiling_ms: 2600,
            service_ceiling_ms: r.service_ceiling_ms,
            material_ceiling_ms: r.material_ceiling_ms,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest().unwrap();
        p
    }
    #[test]
    fn selected_public_owner_schema_is_closed_and_paths_not_defaulted() {
        let raw = owner_json();
        SignerV3OwnerSetupSelectionV1::parse_json(&raw).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        v["approved"] = true.into();
        assert!(SignerV3OwnerSetupSelectionV1::parse_json(&v.to_string()).is_err());
        v.as_object_mut().unwrap().remove("approved");
        v["client_private_key_pkcs8_der"] = "relative.der".into();
        assert!(SignerV3OwnerSetupSelectionV1::parse_json(&v.to_string()).is_err());
    }
    #[test]
    fn read_and_receive_are_distinct_closed_native_purposes() {
        let p = read();
        p.validate().unwrap();
        let q = receive();
        q.validate().unwrap();
        assert!(serde_json::from_value::<SignerV3ReceivePresentationV1>(
            serde_json::to_value(p).unwrap()
        )
        .is_err());
        assert!(serde_json::from_value::<SignerV3PrepareReadPresentationV1>(
            serde_json::to_value(q).unwrap()
        )
        .is_err());
    }
    #[test]
    fn independent_service_and_material_ceilings_are_digest_bound() {
        let p = read();
        let mut q = p.clone();
        q.service_ceiling_ms -= 1;
        assert!(q.validate().is_err());
        let mut q = p.clone();
        q.facts.material_expires_at_ms = q.facts.expires_at_ms - 1;
        q.presentation_digest = q.calculate_presentation_digest().unwrap();
        assert!(q.validate().is_err());
        let mut q = p;
        q.facts.owner_setup_json.push(' ');
        assert!(q.validate().is_err());
    }
    #[test]
    fn receive_is_one_bounded_payload_and_read_result_is_exact() {
        let mut p = receive();
        p.facts.payload_bytes = 5 * 1024 * 1024 + 1;
        p.presentation_digest = p.calculate_presentation_digest().unwrap();
        assert!(p.validate().is_err());
        let mut d = prepared();
        d.read_session_digest = "ff".repeat(32);
        assert!(d.validate().is_err());
    }
}
