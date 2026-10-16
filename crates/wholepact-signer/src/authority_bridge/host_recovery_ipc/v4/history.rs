//! Construction-complete audit contract. This module has no transport/issuer.
//! Financial v2 bytes remain nested unchanged; no v2 reader receives a filtered view.
use super::super::v2::HostRecoveryHistoryV2;
use super::{BridgeError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use wholepact_authority::ConstructionHistoryV2;
use wholepact_authority::{AuthorityHead, WitnessDisclosureDescriptor};

/// V4 archive budget only. Older transport/frame and V2/V3 limits stay fixed.
pub const MAX_COMPLETE_HISTORY_V4_BYTES: usize = 1024 * 1024 - 4096;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRecoveryHistoryV4 {
    pub schema_version: u16,
    pub financial_origins_v2: HostRecoveryHistoryV2,
    pub construction: ConstructionHistoryV2,
    pub signer_common_context_audit: crate::consent_journal::CommonContextSignerAuditInventoryV1,
}
impl HostRecoveryHistoryV4 {
    pub fn validate(
        &self,
        account: &str,
        network: &str,
        witness: &WitnessDisclosureDescriptor,
        head: &AuthorityHead,
        epoch: u64,
    ) -> Result<()> {
        self.financial_origins_v2
            .validate(account, network, witness, head, epoch)?;
        self.construction.validate()?;
        self.signer_common_context_audit
            .validate(account)
            .map_err(|_| BridgeError::Binding)?;
        self.signer_common_context_audit
            .validate_against(&self.construction)
            .map_err(|_| BridgeError::Binding)?;
        if self.schema_version != 4
            || self.construction.witness() != witness
            || &self.construction.observed_snapshot().head != head
            || self.construction.observed_snapshot().writer_epoch != epoch
            || self.construction.original_birth()
                != self.financial_origins_v2.pending_birth_commit.as_ref()
            || serde_json::to_vec(self)
                .map_err(|_| BridgeError::Binding)?
                .len()
                > MAX_COMPLETE_HISTORY_V4_BYTES
        {
            return Err(BridgeError::Binding);
        }
        let snapshot = self.construction.observed_snapshot();
        let observed_debit = snapshot
            .outstanding_debit_zatoshis
            .checked_add(snapshot.settled_debit_zatoshis)
            .ok_or(BridgeError::Binding)?;
        if self.conservative_debit_zatoshis()? < observed_debit {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
    pub fn conservative_debit_zatoshis(&self) -> Result<u64> {
        self.financial_origins_v2
            .conservative_debit_zatoshis()?
            .checked_add(self.construction.retained_debit_zatoshis()?)
            .ok_or(BridgeError::Binding)
    }
    pub fn conservative_obligations(&self) -> Result<BTreeSet<String>> {
        let mut obligations = self.financial_origins_v2.conservative_obligations()?;
        obligations.extend(self.construction.conservative_obligations());
        Ok(obligations)
    }
    pub fn unresolved_offline_authorizations(&self) -> Result<BTreeSet<String>> {
        self.financial_origins_v2
            .unresolved_offline_authorizations()
    }
    pub fn missing_local_native_phases(
        &self,
    ) -> Result<Vec<crate::consent_journal::MissingCommonContextNativeAuditV1>> {
        self.signer_common_context_audit
            .missing_local_phases(&self.construction)
            .map_err(|_| BridgeError::Binding)
    }
    /// Even empty construction is not permission to select a different wire or
    /// activate a writer. There is no source-qualified v3 financial issuer.
    pub fn require_financial_activation_supported(&self) -> Result<()> {
        Err(BridgeError::Permission)
    }
}
