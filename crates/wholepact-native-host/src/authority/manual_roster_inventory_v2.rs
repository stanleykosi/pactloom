//! Candidate-free privacy admission. This private owner admits only a bounded
//! public-block scan and local balance read for an exactly reviewed inventory.
//! The genuine installed signer viewing owner remains independently required.
use crate::{
    Error, Result,
    terminal::{Terminal, historical::HistoricalApproval},
};
use std::time::Instant;
use wholepact_core::manual_roster_inventory_v2::ManualRosterInventoryScopeV2;
use wholepact_signer::authority_bridge::manual_roster_inventory_v2::SignerRosterInventoryLeaseV2;
use wholepact_wallet::wallet::{
    AccountUuid,
    protected_sync::{
        BackendIdentity, LocalWalletAccess, ProtectedWalletSync, WalletAccessPurpose,
    },
};

/// Process-local, one-operation authority. No public constructor, Clone or
/// Deserialize. The original review deadline includes launch and pairing time.
pub(crate) struct RosterInventoryAdmissionV2 {
    scope: ManualRosterInventoryScopeV2,
    deadline: Instant,
}
impl RosterInventoryAdmissionV2 {
    pub(crate) fn review(
        terminal: &Terminal,
        prior: &HistoricalApproval,
        scope: &ManualRosterInventoryScopeV2,
    ) -> Result<Self> {
        scope.validate().map_err(|_| Error::Invalid)?;
        let digest = scope.pairing_digest().map_err(|_| Error::Invalid)?;
        let detail = serde_json::to_string_pretty(scope)?;
        let approval = terminal.approve_publication_reviewed(prior, &digest, &format!(
            "Admit one exact roster-native V2 preliminary account inventory operation with the complete original V3 and current V4 provenance.\n{detail}\nThe installed signer must separately approve viewing disclosure. The retained audit alone does not authorize this read. This permits only the named provider's public-block scan and local known-balance read at the exact encrypted wallet destination. It cannot select contribution inputs, construct, sign or dispatch a transaction. Once admitted, this bounded operation may finish after focus changes; disclosed data and admitted writes cannot be recalled. Cancellation stops new admissions. The original deadline includes launch and review delays and cannot be renewed."
        ))?;
        let deadline = approval.deadline();
        approval.commit(
            &digest,
            || prior.check(),
            |_| {
                Ok(Self {
                    scope: scope.clone(),
                    deadline,
                })
            },
        )
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(crate) fn require_scope(&self, scope: &ManualRosterInventoryScopeV2) -> Result<()> {
        if &self.scope != scope || Instant::now() >= self.deadline {
            return Err(Error::Permission);
        }
        Ok(())
    }
    pub(crate) fn bind<'a, 'peer>(
        self,
        wallet: &ProtectedWalletSync,
        lease: &'a SignerRosterInventoryLeaseV2<'peer>,
    ) -> Result<RosterInventoryWalletAccessV2<'a, 'peer>> {
        if self.scope != lease.request().map_err(|_| Error::Permission)?.scope
            || Instant::now() >= self.deadline
        {
            return Err(Error::Permission);
        }
        lease.check_current().map_err(|_| Error::Permission)?;
        let account = lease
            .verify_wallet_account(wallet)
            .map_err(|_| Error::Permission)?;
        if Instant::now() >= self.deadline {
            return Err(Error::Permission);
        }
        Ok(RosterInventoryWalletAccessV2 {
            admission: self,
            account,
            lease,
        })
    }
}

/// Binding verifies the actual maintained wallet FVK before deriving its UUID.
/// Provider identity is rechecked on each
/// maintained-wallet access, including after asynchronous provider responses.
pub(crate) struct RosterInventoryWalletAccessV2<'a, 'peer> {
    admission: RosterInventoryAdmissionV2,
    account: AccountUuid,
    lease: &'a SignerRosterInventoryLeaseV2<'peer>,
}
impl RosterInventoryWalletAccessV2<'_, '_> {
    pub(crate) fn request(
        &self,
    ) -> Result<&wholepact_core::manual_roster_inventory_v2::ManualRosterInventoryRequestV2> {
        self.check_current()?;
        self.lease.request().map_err(|_| Error::Permission)
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        if Instant::now() >= self.admission.deadline {
            return crate::host::roster_denial!(
                denied_host,
                ScanNativeAdmissionDeadline,
                Err(Error::Permission)
            );
        }
        crate::host::roster_denial!(
            denied_host,
            ScanNativeLease,
            self.lease.check_current().map_err(|_| Error::Permission)
        )?;
        self.remaining()?;
        Ok(())
    }
    pub(crate) fn remaining(&self) -> Result<std::time::Duration> {
        crate::host::roster_denial!(
            denied_host,
            ScanNativeRemaining,
            remaining_before(self.admission.deadline, Instant::now())
        )
    }
    fn matches(&self, account: AccountUuid, provider: &BackendIdentity) -> bool {
        let approved = &self.admission.scope.inventory.provider;
        crate::host::roster_denial!(
            denied_predicate,
            ScanNativeAccount,
            account == self.account
        ) && crate::host::roster_denial!(
            denied_predicate,
            ScanNativeProviderSource,
            provider.source_id == approved.source_id
        ) && crate::host::roster_denial!(
            denied_predicate,
            ScanNativeProviderEndpoint,
            provider.endpoint == approved.endpoint
        ) && crate::host::roster_denial!(
            denied_predicate,
            ScanNativeProviderTrust,
            provider.trust_profile == approved.trust_profile
        )
            && self.check_current().is_ok()
    }
}
impl LocalWalletAccess for RosterInventoryWalletAccessV2<'_, '_> {
    fn permits(
        &self,
        account: AccountUuid,
        provider: &BackendIdentity,
        purpose: WalletAccessPurpose,
    ) -> bool {
        crate::host::roster_denial!(
            denied_predicate,
            ScanNativePurpose,
            inventory_purpose(purpose)
        ) && self.matches(account, provider)
    }
}

impl wholepact_wallet::wallet::protected_sync::recovery::LocalRecoveryReadAccess
    for RosterInventoryWalletAccessV2<'_, '_>
{
    fn permits_recovery_read(&self, account: AccountUuid, provider: &BackendIdentity) -> bool {
        self.matches(account, provider)
    }
}

fn remaining_before(deadline: Instant, now: Instant) -> Result<std::time::Duration> {
    deadline
        .checked_duration_since(now)
        .filter(|d| !d.is_zero())
        .ok_or(Error::Permission)
}

fn inventory_purpose(purpose: WalletAccessPurpose) -> bool {
    matches!(purpose, WalletAccessPurpose::SynchronizePublicBlocks)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_monotonic_window_cannot_be_extended_or_reused_at_cutoff() {
        let now = Instant::now();
        let deadline = now + std::time::Duration::from_millis(17);
        assert_eq!(
            remaining_before(deadline, now).unwrap(),
            std::time::Duration::from_millis(17)
        );
        assert!(remaining_before(deadline, deadline).is_err());
        assert!(remaining_before(deadline, deadline + std::time::Duration::from_nanos(1)).is_err());
    }
    #[test]
    fn inventory_purpose_never_authorizes_private_contribution_selection() {
        assert!(inventory_purpose(
            WalletAccessPurpose::SynchronizePublicBlocks
        ));
        assert!(!inventory_purpose(
            WalletAccessPurpose::SelectPrivateContribution
        ));
    }
    #[test]
    fn expired_or_disconnected_native_review_cannot_admit_inventory_effect() {
        for expired in [false, true] {
            let digest = "a".repeat(64);
            let approval = crate::terminal::PublicationApproval::denied_for_test(&digest, expired);
            let mut reached = false;
            assert!(
                approval
                    .commit(
                        &digest,
                        || Ok(()),
                        |_| {
                            reached = true;
                            Ok(())
                        }
                    )
                    .is_err()
            );
            assert!(!reached);
        }
    }
}
