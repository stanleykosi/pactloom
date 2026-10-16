//! Data-only bounded candidate selection consent wire. Deserializing this module
//! cannot create a native decision, current peer, inventory or financial owner.
use crate::{Error, Result, digest, hash, manual::ManualCurrentState};
use serde::{Deserialize, Serialize};
use wholepact_core::manual_roster_candidate_selection_v2::ManualRosterCandidateSelectionRequestV2;
use zeroize::Zeroize;

pub const MAX_CANDIDATE_SELECTION_FRAME: usize = 128 * 1024;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterCandidateSelectionEvidenceV2 {
    pub version: u16,
    pub request: ManualRosterCandidateSelectionRequestV2,
    pub retained_signer_intent_digest: String,
    pub original_descriptor_digest: String,
    /// Historical observation from the genuine issuer, never a remote financial
    /// freshness lease or a persistent native approval.
    pub current: ManualCurrentState,
}
impl ManualRosterCandidateSelectionEvidenceV2 {
    pub fn validate(&self) -> Result<()> {
        self.request.validate().map_err(|_| Error::Binding)?;
        self.current.validate()?;
        hash(&self.retained_signer_intent_digest)?;
        hash(&self.original_descriptor_digest)?;
        let terms = &self.request.scope.selection.inventory.enrollment;
        if self.version != 2
            || self.original_descriptor_digest
                != self
                    .request
                    .scope
                    .selection
                    .inventory
                    .original_recipient_policy
                    .digest()
                    .map_err(|_| Error::Binding)?
            || self.current.writer_certificate_digest != terms.signer.writer_certificate_digest
            || self.current.writer_epoch != terms.signer.writer_epoch
            || self.request.requested_at_ms < terms.issued_at_ms
            || self.request.requested_at_ms > i64::MAX as u64
            || self.request.disclosure_expires_at_ms > i64::MAX as u64
            || self.request.disclosure_expires_at_ms > self.current.writer_session_expires_at_ms
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:roster-candidate-selection-evidence:v2", self)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManualRosterCandidateSelectionResponseV2 {
    RosterCandidateSelectionDisclosedV2 {
        lease_id: String,
        evidence: Box<ManualRosterCandidateSelectionEvidenceV2>,
        account_fvk_hex: String,
    },
    Denied {},
}
impl Drop for ManualRosterCandidateSelectionResponseV2 {
    fn drop(&mut self) {
        if let Self::RosterCandidateSelectionDisclosedV2 {
            account_fvk_hex, ..
        } = self
        {
            account_fvk_hex.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_wire_and_serialized_approval_cannot_create_v2_permission() {
        assert!(serde_json::from_str::<ManualRosterCandidateSelectionResponseV2>(r#"{"status":"preliminary_inventory_disclosed_v1","lease_id":"x","evidence":{},"account_fvk_hex":"00"}"#).is_err());
        assert!(serde_json::from_str::<ManualRosterCandidateSelectionResponseV2>(r#"{"status":"candidate_selection_disclosed_v1","lease_id":"x","evidence":{},"account_fvk_hex":"00"}"#).is_err());
        assert!(
            serde_json::from_str::<ManualRosterCandidateSelectionResponseV2>(
                r#"{"status":"denied","approved":true}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<ManualRosterCandidateSelectionResponseV2>(
                r#"{"status":"contribution_admitted_v1","evidence":{}}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<ManualRosterCandidateSelectionResponseV2>(
                r#"{"status":"denied"}"#
            )
            .is_ok()
        );
    }
}
