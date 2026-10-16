//! STAGED, UNCOMPILED. Intended wholepact-core::manual_roster_v2.
//! Host roster ancestry is NOT account witness-extension ancestry. Every value
//! here is inert. No validation result is a native decision or a live admission.
use crate::{
    CoreError, ErrorCode, Result, manual_enrollment::ManualHostGenerationBinding,
    proposal::canonical_digest,
};
use serde::{Deserialize, Serialize};

pub const MAX_MANUAL_ROSTER_ACCOUNTS_V2: u64 = 32;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostRosterPredecessorV2 {
    EnrollmentV1 { audit_digest: String },
    InitialPublicationV2 { audit_digest: String },
    AdditionalPublicationV3 { audit_digest: String },
}
impl HostRosterPredecessorV2 {
    pub fn audit_digest(&self) -> &str {
        match self {
            Self::EnrollmentV1 { audit_digest }
            | Self::InitialPublicationV2 { audit_digest }
            | Self::AdditionalPublicationV3 { audit_digest } => audit_digest,
        }
    }
    pub fn validate(&self) -> Result<()> {
        hash(self.audit_digest())
    }
}

/// Exact proposed successor to an actual Host roster row. The native Host must
/// derive this from its real Store and compare it again under transaction CAS.
/// The signer/witness review the claim; they cannot authenticate remote Store
/// contents. No existing account changes its scope or policy through this type.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRosterAppendBindingV2 {
    pub version: u16,
    pub generation_id: String,
    pub store_destination_identity: String,
    pub roster_sequence: u64,
    pub predecessor: HostRosterPredecessorV2,
}
impl HostRosterAppendBindingV2 {
    pub fn validate(&self) -> Result<()> {
        hash(&self.generation_id)?;
        text(&self.store_destination_identity, 4096)?;
        self.predecessor.validate()?;
        if self.version != 2
            || !(2..=MAX_MANUAL_ROSTER_ACCOUNTS_V2).contains(&self.roster_sequence)
            || (self.roster_sequence == 2)
                != matches!(
                    self.predecessor,
                    HostRosterPredecessorV2::EnrollmentV1 { .. }
                        | HostRosterPredecessorV2::InitialPublicationV2 { .. }
                )
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn validate_for_host(&self, host: &ManualHostGenerationBinding) -> Result<()> {
        self.validate()?;
        if host.scope_predecessor_digest.is_some()
            || self.generation_id != host.generation_id
            || self.store_destination_identity != host.store_destination_identity
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest("wholepact:host-roster-append-binding:v2", self)
    }
}
fn invalid() -> CoreError {
    CoreError::new(
        ErrorCode::InvalidTerms,
        "invalid exact Host roster append binding",
    )
}
fn text(value: &str, maximum: usize) -> Result<()> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(invalid());
    }
    Ok(())
}
fn hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binding() -> HostRosterAppendBindingV2 {
        HostRosterAppendBindingV2 {
            version: 2,
            generation_id: "a".repeat(64),
            store_destination_identity: "synthetic-store".into(),
            roster_sequence: 2,
            predecessor: HostRosterPredecessorV2::InitialPublicationV2 {
                audit_digest: "b".repeat(64),
            },
        }
    }
    #[test]
    fn roster_sequence_requires_exact_typed_predecessor_and_bound() {
        let original = binding();
        original.validate().unwrap();
        for sequence in [0, 1, 3, 32, 33, u64::MAX] {
            let mut wrong = original.clone();
            wrong.roster_sequence = sequence;
            assert!(wrong.validate().is_err());
        }
        let mut later = original.clone();
        later.roster_sequence = 3;
        later.predecessor = HostRosterPredecessorV2::AdditionalPublicationV3 {
            audit_digest: "c".repeat(64),
        };
        later.validate().unwrap();
        later.roster_sequence = 32;
        later.validate().unwrap();
        later.roster_sequence = 33;
        assert!(later.validate().is_err());
        later.roster_sequence = 2;
        assert!(later.validate().is_err());
        let mut bad = original;
        bad.predecessor = HostRosterPredecessorV2::EnrollmentV1 {
            audit_digest: "NOT-A-DIGEST".into(),
        };
        assert!(bad.validate().is_err());
    }
    #[test]
    fn roster_binding_never_reuses_per_account_scope_chain() {
        let binding = binding();
        let mut host = ManualHostGenerationBinding {
            generation_id: binding.generation_id.clone(),
            inventory_digest: "1".repeat(64),
            generation_plan_digest: "2".repeat(64),
            financial_journal_origin_digest: "3".repeat(64),
            store_destination_identity: binding.store_destination_identity.clone(),
            profile_id: "synthetic".into(),
            canonical_root: "/synthetic/host".into(),
            destination_identity_digest: "4".repeat(64),
            inherited_identity_digest: "5".repeat(64),
            scope_predecessor_digest: None,
        };
        binding.validate_for_host(&host).unwrap();
        host.scope_predecessor_digest = Some("6".repeat(64));
        assert!(binding.validate_for_host(&host).is_err());
        host.scope_predecessor_digest = None;
        host.generation_id = "7".repeat(64);
        assert!(binding.validate_for_host(&host).is_err());
        host.generation_id = binding.generation_id.clone();
        host.store_destination_identity.push_str("-other");
        assert!(binding.validate_for_host(&host).is_err());
    }
}
