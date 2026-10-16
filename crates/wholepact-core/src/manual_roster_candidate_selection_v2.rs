//! Distinct roster-native bounded selection DATA. Neither prior viewing data
//! nor a parsed economic intent can issue live selection or construction consent.
use crate::{
    CoreError, ErrorCode, Result, manual_candidate_selection::ManualCandidateSelectionScope,
    manual_inventory::MAX_PRELIMINARY_DISCLOSURE_MS,
    manual_roster_inventory_v2::ManualRosterPreparationProvenanceV2, proposal::canonical_digest,
};
use serde::{Deserialize, Serialize};
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterCandidateSelectionScopeV2 {
    pub version: u16,
    pub selection: ManualCandidateSelectionScope,
    pub provenance: ManualRosterPreparationProvenanceV2,
}
impl ManualRosterCandidateSelectionScopeV2 {
    pub fn validate(&self) -> Result<()> {
        self.selection.validate()?;
        self.provenance.validate_for(&self.selection.inventory)?;
        bounded(self)?;
        if self.version != 2 {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn pairing_digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest("wholepact:manual-roster-candidate-selection-scope:v2", self)
    }
    pub fn requested_debit_zatoshis(&self) -> Result<u64> {
        self.validate()?;
        self.selection.requested_debit_zatoshis()
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterCandidateSelectionRequestV2 {
    pub version: u16,
    pub operation_id: String,
    pub scope: ManualRosterCandidateSelectionScopeV2,
    pub current_caller_binding_digest: String,
    pub requested_at_ms: u64,
    pub disclosure_expires_at_ms: u64,
}
impl ManualRosterCandidateSelectionRequestV2 {
    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        crate::error::validate_id(&self.operation_id, "roster candidate selection operation")?;
        hash(&self.current_caller_binding_digest)?;
        let i = &self.scope.selection.invocation;
        if self.version != 2
            || self.operation_id == i.operation_id
            || self.requested_at_ms < i.requested_at_ms
            || self.disclosure_expires_at_ms > i.construction_expires_at_ms
            || self.disclosure_expires_at_ms <= self.requested_at_ms
            || self.disclosure_expires_at_ms - self.requested_at_ms > MAX_PRELIMINARY_DISCLOSURE_MS
        {
            return Err(invalid());
        }
        bounded(self)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest(
            "wholepact:manual-roster-candidate-selection-request:v2",
            self,
        )
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
        "invalid exact roster-native candidate selection",
    )
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
mod tests;
