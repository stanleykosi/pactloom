//! Candidate-free privacy admission. This private owner admits only a bounded
//! public-block scan and local balance read for an exactly reviewed inventory.
//! The genuine installed signer viewing owner remains independently required.
use crate::{Error, Result, terminal::Terminal};
use std::time::Instant;
use wholepact_core::manual_inventory::ManualPreliminaryInventoryScope;
use wholepact_signer::authority_bridge::manual_inventory::SignerPreliminaryInventoryLease;
use wholepact_wallet::wallet::{
    AccountUuid,
    protected_sync::{
        BackendIdentity, LocalWalletAccess, ProtectedWalletSync, WalletAccessPurpose,
    },
};

/// Process-local, one-operation authority. No public constructor, Clone or
/// Deserialize. The original review deadline includes launch and pairing time.
pub(crate) struct PreliminaryInventoryAdmission {
    scope: ManualPreliminaryInventoryScope,
    deadline: Instant,
}
impl PreliminaryInventoryAdmission {
    pub(crate) fn review(
        terminal: &Terminal,
        scope: &ManualPreliminaryInventoryScope,
    ) -> Result<Self> {
        scope.validate().map_err(|_| Error::Invalid)?;
        let digest = scope.pairing_digest().map_err(|_| Error::Invalid)?;
        let detail = serde_json::to_string_pretty(scope)?;
        let approval = terminal.approve_publication(&digest, &format!(
            "Admit one exact preliminary account inventory operation.\n{detail}\nThe installed signer must separately approve viewing disclosure. This permits only the named provider's public-block scan and local known-balance read at the exact encrypted wallet destination. It cannot select contribution inputs, construct, sign or dispatch a transaction. Once admitted, this bounded operation may finish after focus changes; disclosed data and admitted writes cannot be recalled. Cancellation stops new admissions. The original deadline includes launch and review delays and cannot be renewed."
        ))?;
        let deadline = approval.deadline();
        approval.commit(
            &digest,
            || Ok(()),
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
    pub(crate) fn require_scope(&self, scope: &ManualPreliminaryInventoryScope) -> Result<()> {
        if &self.scope != scope || Instant::now() >= self.deadline {
            return Err(Error::Permission);
        }
        Ok(())
    }
    pub(crate) fn bind<'a, 'peer>(
        self,
        wallet: &ProtectedWalletSync,
        lease: &'a SignerPreliminaryInventoryLease<'peer>,
    ) -> Result<PreliminaryInventoryWalletAccess<'a, 'peer>> {
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
        Ok(PreliminaryInventoryWalletAccess {
            admission: self,
            account,
            lease,
        })
    }
}

/// Binding verifies the actual maintained wallet FVK before deriving its UUID.
/// Provider identity is rechecked on each
/// maintained-wallet access, including after asynchronous provider responses.
pub(crate) struct PreliminaryInventoryWalletAccess<'a, 'peer> {
    admission: PreliminaryInventoryAdmission,
    account: AccountUuid,
    lease: &'a SignerPreliminaryInventoryLease<'peer>,
}
impl PreliminaryInventoryWalletAccess<'_, '_> {
    pub(crate) fn check_current(&self) -> Result<()> {
        if Instant::now() >= self.admission.deadline {
            return Err(Error::Permission);
        }
        self.lease.check_current().map_err(|_| Error::Permission)?;
        self.remaining()?;
        Ok(())
    }
    pub(crate) fn remaining(&self) -> Result<std::time::Duration> {
        let remaining = self
            .admission
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or(Error::Permission)?;
        if remaining.is_zero() {
            return Err(Error::Permission);
        }
        Ok(remaining)
    }
    fn matches(&self, account: AccountUuid, provider: &BackendIdentity) -> bool {
        let approved = &self.admission.scope.provider;
        account == self.account
            && provider.source_id == approved.source_id
            && provider.endpoint == approved.endpoint
            && provider.trust_profile == approved.trust_profile
            && self.check_current().is_ok()
    }
}
impl LocalWalletAccess for PreliminaryInventoryWalletAccess<'_, '_> {
    fn permits(
        &self,
        account: AccountUuid,
        provider: &BackendIdentity,
        purpose: WalletAccessPurpose,
    ) -> bool {
        inventory_purpose(purpose) && self.matches(account, provider)
    }
}

impl wholepact_wallet::wallet::protected_sync::recovery::LocalRecoveryReadAccess
    for PreliminaryInventoryWalletAccess<'_, '_>
{
    fn permits_recovery_read(&self, account: AccountUuid, provider: &BackendIdentity) -> bool {
        self.matches(account, provider)
    }
}

fn inventory_purpose(purpose: WalletAccessPurpose) -> bool {
    matches!(purpose, WalletAccessPurpose::SynchronizePublicBlocks)
}

#[cfg(test)]
mod tests {
    use super::*;
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
