//! Explicit complete historical envelope for construction transport handoff.
//! V4 is never reinterpreted. Separate native owners are required; public V5
//! recovery/publication availability remains denied.
use super::super::v2::HostRecoveryHistoryV2;
use super::{BridgeError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use wholepact_authority::construction_transport_handoff_v1::ConstructionHistoryWithTransportV1;
use wholepact_authority::{AuthorityHead, WitnessDisclosureDescriptor};

/// No widened archive budget: complete V5 data must fit the existing ceiling.
pub const MAX_COMPLETE_HISTORY_V5_BYTES: usize = super::super::v4::MAX_COMPLETE_HISTORY_V4_BYTES;

pub(super) fn require_encoded_limit<T: Serialize>(value: &T, limit: usize) -> Result<()> {
    if serde_json::to_vec(value)
        .map_err(|_| BridgeError::Binding)?
        .len()
        > limit
    {
        return Err(BridgeError::Binding);
    }
    Ok(())
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRecoveryHistoryV5 {
    pub schema_version: u16,
    pub financial_origins_v2: HostRecoveryHistoryV2,
    pub construction: ConstructionHistoryWithTransportV1,
    pub signer_common_context_audit: crate::consent_journal::CommonContextSignerAuditInventoryV2,
}
impl HostRecoveryHistoryV5 {
    pub fn validate(
        &self,
        account: &str,
        network: &str,
        witness: &WitnessDisclosureDescriptor,
        head: &AuthorityHead,
        epoch: u64,
    ) -> Result<()> {
        require_encoded_limit(self, MAX_COMPLETE_HISTORY_V5_BYTES)?;
        self.construction.validate()?;
        self.signer_common_context_audit
            .validate_against(&self.construction)
            .map_err(|_| BridgeError::Binding)?;
        self.financial_origins_v2
            .validate(account, network, witness, head, epoch)?;
        let s = self.construction.observed_snapshot();
        if self.schema_version != 5
            || self.construction.original.witness() != witness
            || &s.head != head
            || s.writer_epoch != epoch
            || self.construction.original.original_birth()
                != self.financial_origins_v2.pending_birth_commit.as_ref()
        {
            return Err(BridgeError::Binding);
        }
        let observed = s
            .outstanding_debit_zatoshis
            .checked_add(s.settled_debit_zatoshis)
            .ok_or(BridgeError::Binding)?;
        if self.conservative_debit_zatoshis()? < observed {
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
        let mut values = self.financial_origins_v2.conservative_obligations()?;
        values.extend(self.construction.conservative_obligations());
        Ok(values)
    }
    pub fn unresolved_offline_authorizations(&self) -> Result<BTreeSet<String>> {
        self.financial_origins_v2
            .unresolved_offline_authorizations()
    }
    pub fn missing_local_native_phases(
        &self,
    ) -> Result<crate::consent_journal::MissingCommonContextNativeAuditV2> {
        self.signer_common_context_audit
            .missing_local_phases(&self.construction)
            .map_err(|_| BridgeError::Binding)
    }
    pub fn require_financial_activation_supported(&self) -> Result<()> {
        Err(BridgeError::Permission)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn v5_encoded_boundary_keeps_complete_and_outer_caps_exact() {
        for limit in [
            MAX_COMPLETE_HISTORY_V5_BYTES,
            MAX_COMPLETE_HISTORY_V5_BYTES + 4096,
        ] {
            // JSON quotes add exactly two bytes. This exercises the actual
            // production encoder guard, without malformed semantic metadata.
            let exact = "a".repeat(limit - 2);
            assert_eq!(serde_json::to_vec(&exact).unwrap().len(), limit);
            require_encoded_limit(&exact, limit).unwrap();
            let over = format!("{exact}a");
            assert_eq!(serde_json::to_vec(&over).unwrap().len(), limit + 1);
            assert!(require_encoded_limit(&over, limit).is_err());
        }
    }
}
