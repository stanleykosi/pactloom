//! Data-only candidate-free inventory disclosure wire. Deserializing this module
//! cannot create a native decision, current peer, inventory or financial owner.
use crate::{Error, Result, digest, hash, manual::ManualCurrentState};
use serde::{Deserialize, Serialize};
use wholepact_core::manual_inventory::ManualPreliminaryInventoryRequest;
use zeroize::Zeroize;

pub const MAX_PRELIMINARY_INVENTORY_FRAME: usize = 128 * 1024;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualPreliminaryInventoryEvidence {
    pub version: u16,
    pub request: ManualPreliminaryInventoryRequest,
    pub retained_signer_intent_digest: String,
    pub original_descriptor_digest: String,
    /// Historical observation from the genuine issuer, never a remote financial
    /// freshness lease or a persistent native approval.
    pub current: ManualCurrentState,
}
impl ManualPreliminaryInventoryEvidence {
    pub fn validate(&self) -> Result<()> {
        self.request.validate().map_err(|_| Error::Binding)?;
        self.current.validate()?;
        hash(&self.retained_signer_intent_digest)?;
        hash(&self.original_descriptor_digest)?;
        let terms = &self.request.scope.enrollment;
        if self.version != 1
            || self.original_descriptor_digest
                != self
                    .request
                    .scope
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
        digest("wholepact:preliminary-inventory-evidence:v1", self)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManualPreliminaryInventoryResponse {
    PreliminaryInventoryDisclosedV1 {
        lease_id: String,
        evidence: Box<ManualPreliminaryInventoryEvidence>,
        account_fvk_hex: String,
    },
    Denied {},
}
impl Drop for ManualPreliminaryInventoryResponse {
    fn drop(&mut self) {
        if let Self::PreliminaryInventoryDisclosedV1 {
            account_fvk_hex, ..
        } = self
        {
            account_fvk_hex.zeroize();
        }
    }
}

#[cfg(test)]
#[path = "manual_inventory_tests.rs"]
mod tests;
