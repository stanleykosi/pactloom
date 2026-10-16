//! Disabled foundation: immutable preparation metadata is evidence, never authority.
//! Only a private durable selected-outcome conversion exists; no public issuer factory.
use crate::{offline::*, *};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineAdmissionExportPlan {
    pub message_id: String,
    pub sequence: u64,
    pub issued_at_unix_seconds: i64,
    pub expires_at_unix_seconds: i64,
    pub purpose: String,
    pub persistence_warning: String,
    pub sender_id: String,
    pub recipient_id: String,
    pub sender_key_fingerprint: String,
    pub recipient_key_fingerprint: String,
}
impl OfflineAdmissionExportPlan {
    pub fn validate(&self) -> Result<()> {
        if self.message_id.len() != 32
            || !self
                .message_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.sequence == 0
            || self.sequence > i64::MAX as u64
        {
            return Err(AuthorityError::InvalidBinding);
        }
        for value in [&self.purpose, &self.persistence_warning] {
            if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
                return Err(AuthorityError::InvalidBinding);
            }
        }
        for value in [&self.sender_id, &self.recipient_id] {
            id(value)?;
        }
        for value in [
            &self.sender_key_fingerprint,
            &self.recipient_key_fingerprint,
        ] {
            hash(value)?;
        }
        let (start, end) = self.milliseconds()?;
        // Match the existing transport's seven-day limit; transport revalidates.
        if end <= start || end - start > 7 * 24 * 60 * 60 * 1000 {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    fn milliseconds(&self) -> Result<(u64, u64)> {
        let convert = |v: i64| -> Result<u64> {
            u64::try_from(v)
                .ok()
                .and_then(|v| v.checked_mul(1000))
                .ok_or(AuthorityError::InvalidBinding)
        };
        Ok((
            convert(self.issued_at_unix_seconds)?,
            convert(self.expires_at_unix_seconds)?,
        ))
    }
    pub fn plan_digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:offline-admission-export-plan:v1", self)
    }
    /// Structural checks only. Policy must come from independently authenticated
    /// witness enrollment, and sequence must be allocated in durable preparation.
    pub fn matches_preparation(
        &self,
        request: &ReserveOfflineAuthorization,
        policy: &OfflineEnrollmentPolicy,
    ) -> Result<()> {
        self.validate()?;
        request.validate()?;
        policy.validate()?;
        let t = &request.intent.terms;
        let (start, end) = self.milliseconds()?;
        if start < request.requested_at_ms
            || end > request.admission_expires_at_ms
            || self.sender_id != format!("offline-admission:{}", t.offline_policy_digest)
            || self.recipient_id != format!("offline-admission:{}", t.offline_signer_key_digest)
            || self.sender_key_fingerprint != policy.witness_transport_key_digest
            || self.recipient_key_fingerprint != policy.offline_signer_key_digest
            || t.offline_policy_digest != policy.policy_digest()?
            || t.offline_signer_key_digest != policy.offline_signer_key_digest
            || t.account_id != policy.account_id
            || t.network_profile_id != policy.network_profile_id
            || t.enrollment_ref != policy.enrollment_ref
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    /// The transport clock starts before commit, conservatively shortening its
    /// lifetime. A delayed reservation cannot renew this immutable original plan.
    pub fn matches_commit(&self, admission: &OfflineAuthorizationAdmission) -> Result<()> {
        self.validate()?;
        admission.matches_request(&admission.request)?;
        let t = &admission.request.intent.terms;
        let (start, end) = self.milliseconds()?;
        if start < admission.request.requested_at_ms
            || start > admission.reserved_at_ms
            || admission.reserved_at_ms >= end
            || end > admission.request.admission_expires_at_ms
            || self.sender_key_fingerprint != admission.witness_transport_key_digest
            || self.recipient_key_fingerprint != t.offline_signer_key_digest
            || self.sender_id != format!("offline-admission:{}", t.offline_policy_digest)
            || self.recipient_id != format!("offline-admission:{}", t.offline_signer_key_digest)
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
}

/// A distinct sealed capability. Descriptor-only CommittedOfflineAdmission and
/// portable DTOs cannot be converted to this type. Only a private durable selected-
/// outcome conversion exists; no public issuer or configured bridge factory.
/// Fields intentionally remain private even to sibling modules.
pub struct CommittedOfflineAdmissionExport {
    descriptor: OfflineAuthorizationAdmission,
    plan: OfflineAdmissionExportPlan,
}
impl CommittedOfflineAdmissionExport {
    pub(crate) fn from_selected(selected: crate::offline_outcome::SelectedOfflineAdmission) -> Self {
        let (descriptor, plan) = selected.into_parts();
        Self { descriptor, plan }
    }
    pub fn descriptor(&self) -> &OfflineAuthorizationAdmission {
        &self.descriptor
    }
    pub fn export_plan(&self) -> &OfflineAdmissionExportPlan {
        &self.plan
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan() -> OfflineAdmissionExportPlan {
        OfflineAdmissionExportPlan {
            message_id: "11".repeat(16),
            sequence: 1,
            issued_at_unix_seconds: 1,
            expires_at_unix_seconds: 2,
            purpose: "Synthetic admission evidence".into(),
            persistence_warning: "Recipient may retain this evidence".into(),
            sender_id: format!("offline-admission:{}", "22".repeat(32)),
            recipient_id: format!("offline-admission:{}", "33".repeat(32)),
            sender_key_fingerprint: "44".repeat(32),
            recipient_key_fingerprint: "55".repeat(32),
        }
    }
    #[test]
    fn plan_rejects_malformed_and_overflow_windows() {
        for (start, end) in [(-1, 2), (1, 1), (2, 1), (1, 604802), (1, i64::MAX)] {
            let mut p = plan();
            p.issued_at_unix_seconds = start;
            p.expires_at_unix_seconds = end;
            assert!(p.validate().is_err());
        }
        assert!(plan().validate().is_ok());
    }
    #[test]
    fn plan_digest_commits_exact_original_metadata() {
        let p = plan();
        let original = p.plan_digest().unwrap();
        let mut changed = p.clone();
        changed.sequence += 1;
        assert_ne!(original, changed.plan_digest().unwrap());
        changed = p.clone();
        changed.purpose.push('.');
        assert_ne!(original, changed.plan_digest().unwrap());
        changed = p;
        changed.expires_at_unix_seconds += 1;
        assert_ne!(original, changed.plan_digest().unwrap());
    }
    #[test]
    fn plan_rejects_unsafe_text_ids_and_sequence() {
        let mut p = plan();
        p.purpose.push('\n');
        assert!(p.validate().is_err());
        p = plan();
        p.message_id = "AA".repeat(16);
        assert!(p.validate().is_err());
        p = plan();
        p.sequence = 0;
        assert!(p.validate().is_err());
        p = plan();
        p.sequence = u64::MAX;
        assert!(p.validate().is_err());
    }
}
