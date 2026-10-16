//! Preliminary viewing disclosure before a payment candidate exists. These are
//! bounded private claims only; no field asserts inventory, input spendability,
//! construction admission, native focus, peer authenticity or signing consent.
use crate::{
    CoreError, ErrorCode, Result,
    born_recipient_policy_v2::BornConstructionRecipientPolicyV2,
    manual_construction::{
        ManualConstructionAttachmentBinding, ManualConstructionAttempt, PreconstructionBirthday,
        PreconstructionProvider,
    },
    manual_enrollment::BornManualEnrollmentTerms,
    proposal::canonical_digest,
};
use serde::{Deserialize, Serialize};

pub const MAX_PRELIMINARY_DISCLOSURE_MS: u64 = 30_000;
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualPreliminaryInventoryScope {
    pub version: u16,
    pub enrollment: BornManualEnrollmentTerms,
    pub enrollment_ref: String,
    pub witness_extension_digest: String,
    pub attempt: ManualConstructionAttempt,
    pub original_recipient_policy: BornConstructionRecipientPolicyV2,
    pub attachment: ManualConstructionAttachmentBinding,
    pub operator_name: String,
    pub operator_destination: String,
    pub wallet_destination: String,
    pub purpose: String,
    pub retention_policy: String,
    pub provider: PreconstructionProvider,
    pub birthday: PreconstructionBirthday,
    pub minimum_confirmations: u32,
    pub maximum_blocks: u32,
    pub anchor_height: u32,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualPreliminaryInventoryRequest {
    pub version: u16,
    pub operation_id: String,
    pub scope: ManualPreliminaryInventoryScope,
    pub current_caller_binding_digest: String,
    pub requested_at_ms: u64,
    pub disclosure_expires_at_ms: u64,
}
fn invalid() -> CoreError {
    CoreError::new(
        ErrorCode::InvalidTerms,
        "invalid preliminary inventory privacy scope",
    )
}
fn text(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 2048 || s.chars().any(char::is_control) {
        return Err(invalid());
    }
    Ok(())
}
fn hash(s: &str) -> Result<()> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    Ok(())
}
fn path(s: &str) -> Result<()> {
    text(s)?;
    if !s.starts_with('/')
        || s == "/"
        || s.ends_with('/')
        || s.split('/')
            .skip(1)
            .any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err(invalid());
    }
    Ok(())
}
impl ManualPreliminaryInventoryScope {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1
            || self.purpose != "preliminary_inventory_only"
            || self.provider.trust_profile != "single_tls_provider_report_not_consensus"
            || !self.provider.endpoint.starts_with("https://")
            || self.provider.endpoint.ends_with('/')
            || !(1..=100).contains(&self.minimum_confirmations)
            || !(1..=1000).contains(&self.maximum_blocks)
            || self.anchor_height == 0
            || self.birthday.prior_height >= self.anchor_height
        {
            return Err(invalid());
        }
        self.enrollment.validate()?;
        self.original_recipient_policy
            .require_enrollment(&self.enrollment)?;
        self.attachment.validate()?;
        if self.attempt.version != 2
            || self.attempt.attempt_sequence < 2
            || self.attempt.attempt_sequence > i64::MAX as u64
        {
            return Err(invalid());
        }
        for h in [
            &self.enrollment_ref,
            &self.witness_extension_digest,
            &self.attempt.continuation_digest,
            &self.birthday.prior_block_hash,
        ] {
            hash(h)?;
        }
        for s in [
            &self.operator_name,
            &self.retention_policy,
            &self.provider.source_id,
            &self.provider.endpoint,
        ] {
            text(s)?;
        }
        path(&self.operator_destination)?;
        path(&self.wallet_destination)?;
        let h = &self.enrollment.host;
        if self.attachment.original_primary_journal_origin_digest
            != h.financial_journal_origin_digest
            || self.attachment.selected.account_id != self.enrollment.identity.account_id
            || format!(
                "{}/wallet.sqlite",
                self.attachment.selected.canonical_directory
            ) != self.wallet_destination
        {
            return Err(invalid());
        }
        for tree in [
            &self.birthday.sapling_tree,
            &self.birthday.orchard_tree,
            &self.birthday.ironwood_tree,
        ] {
            if tree.len() > 32 * 1024
                || tree.len() % 2 != 0
                || !tree.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(invalid());
            }
        }
        if serde_json::to_vec(self).map_err(|_| invalid())?.len() > 128 * 1024 {
            return Err(invalid());
        }
        Ok(())
    }
    /// Pairing commits this exact candidate-free privacy intent. It excludes
    /// the grant-derived caller digest and therefore has no grant/hash cycle.
    pub fn pairing_digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest("wholepact:manual-preliminary-inventory-scope:v1", self)
    }
}
impl ManualPreliminaryInventoryRequest {
    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        text(&self.operation_id)?;
        hash(&self.current_caller_binding_digest)?;
        if self.version != 1
            || self.requested_at_ms == 0
            || self.requested_at_ms < self.scope.enrollment.issued_at_ms
            || self.requested_at_ms > i64::MAX as u64
            || self.disclosure_expires_at_ms > i64::MAX as u64
            || self.disclosure_expires_at_ms <= self.requested_at_ms
            || self.disclosure_expires_at_ms - self.requested_at_ms > MAX_PRELIMINARY_DISCLOSURE_MS
            || self.disclosure_expires_at_ms > self.scope.enrollment.scope.expires_at_ms
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest("wholepact:manual-preliminary-inventory-request:v1", self)
    }
    pub fn remaining_ms(&self, now: u64) -> Result<u64> {
        self.validate()?;
        if now < self.requested_at_ms || now >= self.disclosure_expires_at_ms {
            return Err(invalid());
        }
        Ok(self.disclosure_expires_at_ms - now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manual_construction::ManualParticipantAttachment;
    fn request() -> ManualPreliminaryInventoryRequest {
        let (enrollment, policy) =
            crate::born_recipient_policy_v2::tests::modeled_terms_and_policy();
        let attachment = ManualConstructionAttachmentBinding {
            version: 1,
            original_primary_journal_origin_digest: enrollment
                .host
                .financial_journal_origin_digest
                .clone(),
            predecessor_registry_digest: "aa".repeat(32),
            current_registry_digest: "bb".repeat(32),
            latest_extension_digest: "cc".repeat(32),
            selected: ManualParticipantAttachment {
                account_id: enrollment.identity.account_id.clone(),
                canonical_directory: "/synthetic/wallet".into(),
                directory_identity_digest: "dd".repeat(32),
                journal_origin_digest: "ee".repeat(32),
            },
        };
        ManualPreliminaryInventoryRequest {
            version: 1,
            operation_id: "preliminary-inventory".into(),
            scope: ManualPreliminaryInventoryScope {
                version: 1,
                enrollment,
                enrollment_ref: "11".repeat(32),
                witness_extension_digest: "22".repeat(32),
                attempt: ManualConstructionAttempt {
                    version: 2,
                    continuation_digest: "33".repeat(32),
                    attempt_sequence: 2,
                },
                original_recipient_policy: policy,
                attachment,
                operator_name: "synthetic-local-operator".into(),
                operator_destination: "/synthetic/operator".into(),
                wallet_destination: "/synthetic/wallet/wallet.sqlite".into(),
                purpose: "preliminary_inventory_only".into(),
                retention_policy: "Retain private wallet until explicit local deletion".into(),
                provider: PreconstructionProvider {
                    source_id: "synthetic-provider".into(),
                    endpoint: "https://synthetic.invalid".into(),
                    trust_profile: "single_tls_provider_report_not_consensus".into(),
                },
                birthday: PreconstructionBirthday {
                    prior_height: 1,
                    prior_block_hash: "44".repeat(32),
                    sapling_tree: String::new(),
                    orchard_tree: String::new(),
                    ironwood_tree: String::new(),
                },
                minimum_confirmations: 1,
                maximum_blocks: 10,
                anchor_height: 100,
            },
            current_caller_binding_digest: "55".repeat(32),
            requested_at_ms: 2000,
            disclosure_expires_at_ms: 32_000,
        }
    }
    #[test]
    fn preliminary_scope_contains_no_candidate_and_cannot_accept_placeholder_fields() {
        let request = request();
        request.validate().unwrap();
        let mut json = serde_json::to_value(&request).unwrap();
        json["scope"]["proposal"] = serde_json::json!({"approved":true});
        assert!(serde_json::from_value::<ManualPreliminaryInventoryRequest>(json).is_err());
        let mut other = request.clone();
        other.current_caller_binding_digest = "66".repeat(32);
        assert_eq!(
            request.scope.pairing_digest().unwrap(),
            other.scope.pairing_digest().unwrap()
        );
        assert_ne!(request.digest().unwrap(), other.digest().unwrap());
    }
    #[test]
    fn exact_wallet_filename_and_original_deadline_cannot_be_relaxed() {
        let request = request();
        for path in [
            "/synthetic/wallet",
            "/synthetic/wallet/./wallet.sqlite",
            "/synthetic//wallet/wallet.sqlite",
            "/synthetic/wallet/other.sqlite",
        ] {
            let mut changed = request.clone();
            changed.scope.wallet_destination = path.into();
            assert!(changed.validate().is_err());
        }
        assert_eq!(request.remaining_ms(2000).unwrap(), 30_000);
        assert!(request.remaining_ms(1999).is_err());
        assert!(request.remaining_ms(32_000).is_err());
        let mut changed = request.clone();
        changed.disclosure_expires_at_ms += 1;
        assert!(changed.validate().is_err());
        let mut before = request.clone();
        before.requested_at_ms = before.scope.enrollment.issued_at_ms - 1;
        before.disclosure_expires_at_ms = before.requested_at_ms + 1;
        assert!(before.validate().is_err());
        let mut too_large = request.clone();
        too_large.scope.attempt.attempt_sequence = (i64::MAX as u64) + 1;
        assert!(too_large.validate().is_err());
        let mut changed = request;
        changed.scope.original_recipient_policy.version = 1;
        assert!(changed.validate().is_err());
    }
}
