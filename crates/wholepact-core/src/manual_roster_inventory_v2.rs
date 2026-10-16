//! Roster-native, candidate-free DATA contracts. Parsing never creates consent.
//! The Host audit reference is a correlation claim on the signer. Only the Host's
//! locked authenticated Store can establish that this exact original V3 exists.
use crate::{
    CoreError, ErrorCode, Result,
    manual_inventory::{MAX_PRELIMINARY_DISCLOSURE_MS, ManualPreliminaryInventoryScope},
    manual_roster_v2::HostRosterAppendBindingV2,
    proposal::canonical_digest,
};
use serde::{Deserialize, Serialize};
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OriginalHostRosterAuditV3 {
    AdditionalPublicationV3 { audit_digest: String },
}
impl OriginalHostRosterAuditV3 {
    pub fn audit_digest(&self) -> &str {
        match self {
            Self::AdditionalPublicationV3 { audit_digest } => audit_digest,
        }
    }
    pub fn validate(&self) -> Result<()> {
        hash(self.audit_digest())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterPreparationProvenanceV2 {
    pub version: u16,
    pub original_host_audit: OriginalHostRosterAuditV3,
    pub roster: HostRosterAppendBindingV2,
    pub signer_roster_record_digest: String,
    pub witness_roster_extension_digest: String,
}
impl ManualRosterPreparationProvenanceV2 {
    pub fn validate_for(&self, inventory: &ManualPreliminaryInventoryScope) -> Result<()> {
        inventory.validate()?;
        self.original_host_audit.validate()?;
        self.roster.validate_for_host(&inventory.enrollment.host)?;
        hash(&self.signer_roster_record_digest)?;
        hash(&self.witness_roster_extension_digest)?;
        if self.version != 2 {
            return Err(invalid());
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterInventoryScopeV2 {
    pub version: u16,
    /// Existing inner data retains its true account-extension and attempt digest.
    /// It is never a V1 enrollment owner or V1 disclosure evidence.
    pub inventory: ManualPreliminaryInventoryScope,
    pub provenance: ManualRosterPreparationProvenanceV2,
}
impl ManualRosterInventoryScopeV2 {
    pub fn validate(&self) -> Result<()> {
        self.provenance.validate_for(&self.inventory)?;
        bounded(self)?;
        if self.version != 2 {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn pairing_digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest("wholepact:manual-roster-inventory-scope:v2", self)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterInventoryRequestV2 {
    pub version: u16,
    pub operation_id: String,
    pub scope: ManualRosterInventoryScopeV2,
    pub current_caller_binding_digest: String,
    pub requested_at_ms: u64,
    pub disclosure_expires_at_ms: u64,
}
impl ManualRosterInventoryRequestV2 {
    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        text(&self.operation_id)?;
        hash(&self.current_caller_binding_digest)?;
        if self.version != 2
            || self.requested_at_ms == 0
            || self.requested_at_ms < self.scope.inventory.enrollment.issued_at_ms
            || self.requested_at_ms > i64::MAX as u64
            || self.disclosure_expires_at_ms > i64::MAX as u64
            || self.disclosure_expires_at_ms <= self.requested_at_ms
            || self.disclosure_expires_at_ms - self.requested_at_ms > MAX_PRELIMINARY_DISCLOSURE_MS
            || self.disclosure_expires_at_ms > self.scope.inventory.enrollment.scope.expires_at_ms
        {
            return Err(invalid());
        }
        bounded(self)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest("wholepact:manual-roster-inventory-request:v2", self)
    }
    pub fn remaining_ms(&self, now: u64) -> Result<u64> {
        self.validate()?;
        if now < self.requested_at_ms || now >= self.disclosure_expires_at_ms {
            return Err(invalid());
        }
        Ok(self.disclosure_expires_at_ms - now)
    }
}
fn invalid() -> CoreError {
    CoreError::new(
        ErrorCode::InvalidTerms,
        "invalid exact roster-native preparation provenance",
    )
}
fn text(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 2048 || s.chars().any(char::is_control) {
        Err(invalid())
    } else {
        Ok(())
    }
}
fn hash(s: &str) -> Result<()> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Err(invalid())
    } else {
        Ok(())
    }
}
fn bounded<T: Serialize>(v: &T) -> Result<()> {
    if serde_json::to_vec(v).map_err(|_| invalid())?.len() > 128 * 1024 {
        Err(invalid())
    } else {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn test_provenance(
    inventory: &ManualPreliminaryInventoryScope,
) -> ManualRosterPreparationProvenanceV2 {
    ManualRosterPreparationProvenanceV2 {
        version: 2,
        original_host_audit: OriginalHostRosterAuditV3::AdditionalPublicationV3 {
            audit_digest: "91".repeat(32),
        },
        roster: HostRosterAppendBindingV2 {
            version: 2,
            generation_id: inventory.enrollment.host.generation_id.clone(),
            store_destination_identity: inventory
                .enrollment
                .host
                .store_destination_identity
                .clone(),
            roster_sequence: 2,
            predecessor: crate::manual_roster_v2::HostRosterPredecessorV2::InitialPublicationV2 {
                audit_digest: "92".repeat(32),
            },
        },
        signer_roster_record_digest: "93".repeat(32),
        witness_roster_extension_digest: "94".repeat(32),
    }
}
#[cfg(test)]
mod tests {

    use super::*;
    use crate::manual_construction::ManualParticipantAttachment;
    use crate::manual_construction::*;
    use crate::manual_inventory::ManualPreliminaryInventoryRequest;
    fn inner_request() -> ManualPreliminaryInventoryRequest {
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

    fn request() -> ManualRosterInventoryRequestV2 {
        let r = inner_request();
        let provenance = test_provenance(&r.scope);
        ManualRosterInventoryRequestV2 {
            version: 2,
            operation_id: r.operation_id,
            scope: ManualRosterInventoryScopeV2 {
                version: 2,
                inventory: r.scope,
                provenance,
            },
            current_caller_binding_digest: r.current_caller_binding_digest,
            requested_at_ms: r.requested_at_ms,
            disclosure_expires_at_ms: r.disclosure_expires_at_ms,
        }
    }
    #[test]
    fn full_v2_pairing_and_request_bind_every_original_roster_identity() {
        let r = request();
        r.validate().unwrap();
        let pairing = r.scope.pairing_digest().unwrap();
        for field in 0..6 {
            let mut changed = r.clone();
            let p = &mut changed.scope.provenance;
            match field {
                0 => {
                    p.original_host_audit = OriginalHostRosterAuditV3::AdditionalPublicationV3 {
                        audit_digest: "98".repeat(32),
                    }
                }
                1 => p.signer_roster_record_digest = "98".repeat(32),
                2 => p.witness_roster_extension_digest = "98".repeat(32),
                3 => {
                    p.roster.predecessor =
                        crate::manual_roster_v2::HostRosterPredecessorV2::InitialPublicationV2 {
                            audit_digest: "98".repeat(32),
                        }
                }
                4 => changed.scope.inventory.attempt.continuation_digest = "98".repeat(32),
                _ => changed.scope.inventory.witness_extension_digest = "98".repeat(32),
            }
            changed.validate().unwrap();
            assert_ne!(pairing, changed.scope.pairing_digest().unwrap());
            assert_ne!(r.digest().unwrap(), changed.digest().unwrap());
        }
        let mut grant = r.clone();
        grant.current_caller_binding_digest = "97".repeat(32);
        assert_eq!(pairing, grant.scope.pairing_digest().unwrap());
        assert_ne!(r.digest().unwrap(), grant.digest().unwrap());
    }
    #[test]
    fn roster_contract_denies_cross_generation_legacy_and_extra_authority_claims() {
        let r = request();
        let mut mismatch = r.clone();
        mismatch.scope.provenance.roster.generation_id = "99".repeat(32);
        assert!(mismatch.validate().is_err());
        let mut mismatch = r.clone();
        mismatch
            .scope
            .provenance
            .roster
            .store_destination_identity
            .push_str("-different");
        assert!(mismatch.validate().is_err());
        let mut mismatch = r.clone();
        mismatch.scope.provenance.version = 1;
        assert!(mismatch.validate().is_err());
        let mut mismatch = r.clone();
        mismatch.version = 1;
        assert!(mismatch.validate().is_err());
        assert!(
            serde_json::from_value::<ManualRosterInventoryRequestV2>(
                serde_json::to_value(inner_request()).unwrap()
            )
            .is_err()
        );
        for name in ["approved", "verified", "can_construct", "inputs"] {
            let mut data = serde_json::to_value(&r).unwrap();
            data["scope"][name] = serde_json::json!(true);
            assert!(serde_json::from_value::<ManualRosterInventoryRequestV2>(data).is_err());
        }
        let mut data = serde_json::to_value(&r).unwrap();
        data["scope"]["provenance"]["original_host_audit"]["kind"] =
            serde_json::json!("enrollment_v1");
        assert!(serde_json::from_value::<ManualRosterInventoryRequestV2>(data).is_err());
    }
    #[test]
    fn original_request_cutoff_stays_bounded_despite_full_v2_wrapper() {
        let r = request();
        assert_eq!(r.remaining_ms(31_999).unwrap(), 1);
        assert!(r.remaining_ms(32_000).is_err());
        assert!(r.remaining_ms(1_999).is_err());
        let mut changed = r;
        changed.disclosure_expires_at_ms += 1;
        assert!(changed.validate().is_err());
    }
}
