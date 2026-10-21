//! Ordinary initial V3 source selection, before any completed V3 custody.
//! Metadata never authorizes KDF, source reads, journal opens or later effects.
use crate::{
    financial_workflow_channel::FinancialActorContextV1, financial_workflow_clock::SUPERVISION_MS,
    rejected, signer_continue_state::hash, Result,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub(super) const NOTICE:&str="Unlock and audit only the exact selected original V3 account and journal with this one encrypted password. No preparation Read, receive, admission, history audit, financial continuation, wallet, signing or Return is approved.";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3SourceEntryFactsV1 {
    pub canonical_root: String,
    pub public_source_files_json: String,
    pub source_selection_digest: String,
    pub account_id: String,
    pub original_enrollment_ref: String,
    pub original_manifest_ref: String,
    pub owner_certificate_digest: String,
    pub witness_disclosure_json: String,
    pub witness_disclosure_digest: String,
    pub original_host_process_instance: String,
    pub session_digest: String,
    pub display: String,
    pub reviewed_at_ms: u64,
    pub expires_at_ms: u64,
    pub source_expires_at_ms: u64,
}
impl SignerV3SourceEntryFactsV1 {
    pub fn calculate_source_selection_digest(&self) -> Result<String> {
        digest(
            b"wholepact:coordinated-v3-source-entry:selection:v1\0",
            &(
                &self.canonical_root,
                &self.public_source_files_json,
                &self.account_id,
                &self.original_enrollment_ref,
                &self.original_manifest_ref,
                &self.owner_certificate_digest,
                &self.witness_disclosure_json,
                &self.witness_disclosure_digest,
                &self.original_host_process_instance,
                &self.session_digest,
            ),
        )
    }
    pub fn validate(&self) -> Result<()> {
        if !text(&self.canonical_root, 4096)
            || !self.canonical_root.starts_with('/')
            || !json(&self.public_source_files_json, 12 * 1024)
            || !json(&self.witness_disclosure_json, 8 * 1024)
            || !text(&self.display, 16 * 1024)
            || ![
                &self.source_selection_digest,
                &self.account_id,
                &self.original_enrollment_ref,
                &self.original_manifest_ref,
                &self.owner_certificate_digest,
                &self.witness_disclosure_digest,
                &self.original_host_process_instance,
                &self.session_digest,
            ]
            .iter()
            .all(|v| hash(v))
            || self.source_selection_digest != self.calculate_source_selection_digest()?
            || self.reviewed_at_ms == 0
            || self.expires_at_ms <= self.reviewed_at_ms
            || self.expires_at_ms - self.reviewed_at_ms > 120_000
            || self.expires_at_ms > self.source_expires_at_ms
        {
            return Err(rejected("V3 source selection facts rejected"));
        }
        limit(self, 48 * 1024)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3SourceEntryPresentationV1 {
    pub actor: FinancialActorContextV1,
    pub facts: SignerV3SourceEntryFactsV1,
    pub notice: String,
    pub sender_key_fingerprint: String,
    pub recipient_key_fingerprint: String,
    pub request_challenge: String,
    pub offer_challenge: String,
    pub native_ceiling_ms: u64,
    pub entry_ceiling_ms: u64,
    pub source_ceiling_ms: u64,
    pub presentation_digest: String,
}
impl SignerV3SourceEntryPresentationV1 {
    pub fn calculate_presentation_digest(&self) -> Result<String> {
        digest(
            b"wholepact:coordinated-v3-source-entry:presentation:v1\0",
            &(
                &self.actor,
                &self.facts,
                &self.notice,
                &self.sender_key_fingerprint,
                &self.recipient_key_fingerprint,
                &self.request_challenge,
                &self.offer_challenge,
                self.native_ceiling_ms,
                self.entry_ceiling_ms,
                self.source_ceiling_ms,
            ),
        )
    }
    pub fn validate(&self) -> Result<()> {
        self.actor.validate()?;
        self.facts.validate()?;
        if self.notice != NOTICE
            || ![
                &self.sender_key_fingerprint,
                &self.recipient_key_fingerprint,
                &self.request_challenge,
                &self.offer_challenge,
                &self.presentation_digest,
            ]
            .iter()
            .all(|v| hash(v))
            || ![
                self.native_ceiling_ms,
                self.entry_ceiling_ms,
                self.source_ceiling_ms,
            ]
            .iter()
            .all(|n| *n > 0 && *n <= SUPERVISION_MS)
            || self.entry_ceiling_ms > self.source_ceiling_ms
            || self.presentation_digest != self.calculate_presentation_digest()?
        {
            return Err(rejected("V3 source presentation rejected"));
        }
        limit(self, 60 * 1024)
    }
}
fn digest(domain: &[u8], value: &impl Serialize) -> Result<String> {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(serde_json::to_vec(value).map_err(|_| rejected("V3 source commitment encoding"))?);
    Ok(hex::encode(h.finalize()))
}
fn text(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b == b'\n' || b == b'\t' || (0x20..=0x7e).contains(&b))
}
fn json(s: &str, max: usize) -> bool {
    text(s, max)
        && serde_json::from_str::<serde_json::Value>(s).is_ok_and(|v| v.is_object() || v.is_array())
}
fn limit(v: &impl Serialize, max: usize) -> Result<()> {
    if serde_json::to_vec(v)
        .map_err(|_| rejected("V3 source encoding"))?
        .len()
        > max
    {
        Err(rejected("V3 source presentation frame budget"))
    } else {
        Ok(())
    }
}

/// Ordinary proposed initial selection sent before S observes public metadata.
/// No private source handle, password, clock authority or completed-V3 proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3SourceEntrySelectionV1 {
    pub canonical_root: String,
    pub account_id: String,
    pub original_enrollment_ref: String,
    pub original_manifest_ref: String,
    pub owner_certificate_digest: String,
    pub witness_disclosure_json: String,
    pub witness_disclosure_digest: String,
    pub session_digest: String,
    pub display: String,
    pub source_expires_at_ms: u64,
}
impl SignerV3SourceEntrySelectionV1 {
    pub fn validate(&self) -> Result<()> {
        if !text(&self.canonical_root, 4096)
            || !self.canonical_root.starts_with('/')
            || !json(&self.witness_disclosure_json, 8 * 1024)
            || !text(&self.display, 16 * 1024)
            || self.source_expires_at_ms == 0
            || ![
                &self.account_id,
                &self.original_enrollment_ref,
                &self.original_manifest_ref,
                &self.owner_certificate_digest,
                &self.witness_disclosure_digest,
                &self.session_digest,
            ]
            .iter()
            .all(|v| hash(v))
        {
            return Err(rejected("V3 proposed source selection rejected"));
        }
        limit(self, 32 * 1024)
    }
    pub fn proposed_facts(
        &self,
        original_host_instance: &str,
    ) -> Result<SignerV3SourceEntryFactsV1> {
        self.validate()?;
        if !hash(original_host_instance) {
            return Err(rejected("V3 proposed Host observation rejected"));
        }
        Ok(SignerV3SourceEntryFactsV1 {
            canonical_root: self.canonical_root.clone(),
            public_source_files_json: String::new(),
            source_selection_digest: String::new(),
            account_id: self.account_id.clone(),
            original_enrollment_ref: self.original_enrollment_ref.clone(),
            original_manifest_ref: self.original_manifest_ref.clone(),
            owner_certificate_digest: self.owner_certificate_digest.clone(),
            witness_disclosure_json: self.witness_disclosure_json.clone(),
            witness_disclosure_digest: self.witness_disclosure_digest.clone(),
            original_host_process_instance: original_host_instance.into(),
            session_digest: self.session_digest.clone(),
            display: self.display.clone(),
            reviewed_at_ms: 0,
            expires_at_ms: 0,
            source_expires_at_ms: self.source_expires_at_ms,
        })
    }
    pub(super) fn matches(&self, f: &SignerV3SourceEntryFactsV1) -> bool {
        self.canonical_root == f.canonical_root
            && self.account_id == f.account_id
            && self.original_enrollment_ref == f.original_enrollment_ref
            && self.original_manifest_ref == f.original_manifest_ref
            && self.owner_certificate_digest == f.owner_certificate_digest
            && self.witness_disclosure_json == f.witness_disclosure_json
            && self.witness_disclosure_digest == f.witness_disclosure_digest
            && self.session_digest == f.session_digest
            && self.display == f.display
            && self.source_expires_at_ms == f.source_expires_at_ms
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    pub(crate) fn selection() -> SignerV3SourceEntrySelectionV1 {
        let h = "ab".repeat(32);
        SignerV3SourceEntrySelectionV1 {
            canonical_root: "/public/synthetic/original19".into(),
            account_id: h.clone(),
            original_enrollment_ref: h.clone(),
            original_manifest_ref: h.clone(),
            owner_certificate_digest: h.clone(),
            witness_disclosure_json: "{}".into(),
            witness_disclosure_digest: h.clone(),
            session_digest: h,
            display: "Synthetic original19 selection, not an opened source".into(),
            source_expires_at_ms: 300000,
        }
    }
    pub(crate) fn facts() -> SignerV3SourceEntryFactsV1 {
        let mut f = selection().proposed_facts(&"cd".repeat(32)).unwrap();
        f.public_source_files_json = "{\"public_fixture\":[1,2]}".into();
        f.reviewed_at_ms = 1000;
        f.expires_at_ms = 121000;
        f.source_selection_digest = f.calculate_source_selection_digest().unwrap();
        f
    }
    #[test]
    fn initial_v3_facts_are_data_only_and_strictly_bounded() {
        let f = facts();
        f.validate().unwrap();
        let encoded = serde_json::to_string(&f).unwrap();
        assert_eq!(
            serde_json::from_str::<SignerV3SourceEntryFactsV1>(&encoded).unwrap(),
            f
        );
        assert!(serde_json::from_str::<SignerV3SourceEntryFactsV1>(&format!(
            "{{\"unexpected\":1,{}",
            &encoded[1..]
        ))
        .is_err());
        let mut large = f.clone();
        large.display = "x".repeat(16 * 1024 + 1);
        assert!(large.validate().is_err());
        let mut long = f;
        long.expires_at_ms = 121001;
        assert!(long.validate().is_err());
    }
    #[test]
    fn selected_original_metadata_and_refs_are_committed() {
        let f = facts();
        for name in [
            "canonical_root",
            "public_source_files_json",
            "account_id",
            "original_enrollment_ref",
            "original_manifest_ref",
            "owner_certificate_digest",
            "witness_disclosure_json",
            "witness_disclosure_digest",
            "original_host_process_instance",
            "session_digest",
        ] {
            let mut v = serde_json::to_value(&f).unwrap();
            v[name] = serde_json::Value::String(format!("{}x", v[name].as_str().unwrap()));
            let changed: SignerV3SourceEntryFactsV1 = serde_json::from_value(v).unwrap();
            assert_ne!(
                f.source_selection_digest,
                changed.calculate_source_selection_digest().unwrap()
            );
            assert!(changed.validate().is_err());
        }
    }
    #[test]
    fn pending_selection_cannot_substitute_offered_source() {
        let s = selection();
        let f = facts();
        assert!(s.matches(&f));
        let mut changed = f.clone();
        changed.original_manifest_ref = "ef".repeat(32);
        assert!(!s.matches(&changed));
        assert!(s.proposed_facts("not-a-host-instance").is_err());
        assert!(s
            .proposed_facts(&"cd".repeat(32))
            .unwrap()
            .validate()
            .is_err());
    }
}

/// Actual successful source opener observation, not a source constructor or
/// preparation permission. Its instance-bound identity is made only by S.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerV3SourceOpenedV1 {
    pub entry_presentation_digest: String,
    pub source_identity_digest: String,
}
impl SignerV3SourceOpenedV1 {
    pub fn validate(&self) -> Result<()> {
        if !hash(&self.entry_presentation_digest) || !hash(&self.source_identity_digest) {
            Err(rejected("V3 opened observation rejected"))
        } else {
            Ok(())
        }
    }
}
