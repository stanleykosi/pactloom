//! Bounded V2 scan with current Host/target/import checks at maintained-wallet
//! access boundaries. Read results keep all original owners alive through display.
use super::*;
use crate::authority::manual_roster_inventory_v2::{
    RosterInventoryAdmissionV2, RosterInventoryWalletAccessV2,
};
use wholepact_wallet::wallet::{
    AccountUuid,
    protected_sync::{
        BackendIdentity, LocalWalletAccess, SyncLimits, WalletAccessPurpose,
        recovery::{AccountRecoveryScan, LocalRecoveryReadAccess},
    },
};

/// Host-specific conjunction lives under Host privacy, rather than exporting
/// its internals or accepting a caller-provided permission closure.
struct RosterScanAccessV2<'a, 'peer, 'audit, 'host> {
    native: RosterInventoryWalletAccessV2<'a, 'peer>,
    host: &'a Host,
    target: &'a CommittedRosterImportTarget<'audit, 'host>,
    import: &'a RecordedRosterInventoryImportV2,
}
impl RosterScanAccessV2<'_, '_, '_, '_> {
    fn check_current(&self) -> Result<()> {
        self.native.check_current()?;
        let request = self.native.request()?;
        self.target.require_current(self.host, &request.scope)?;
        let access = self.host.access()?;
        self.host
            .authority
            .check_financial_principal(&access.principal_id)?;
        if request.scope.inventory.enrollment.scope.principal_id != access.principal_id {
            return Err(Error::Permission);
        }
        self.import
            .check_request_scope_and_account(
                &request.digest().map_err(|_| Error::Invalid)?,
                &request.scope.pairing_digest().map_err(|_| Error::Invalid)?,
                self.import.account_uuid(),
            )
            .map_err(|_| Error::Permission)?;
        self.native.check_current()
    }
}
impl LocalWalletAccess for RosterScanAccessV2<'_, '_, '_, '_> {
    fn permits(
        &self,
        account: AccountUuid,
        provider: &BackendIdentity,
        purpose: WalletAccessPurpose,
    ) -> bool {
        account == self.import.account_uuid()
            && self.check_current().is_ok()
            && self.native.permits(account, provider, purpose)
    }
}
impl LocalRecoveryReadAccess for RosterScanAccessV2<'_, '_, '_, '_> {
    fn permits_recovery_read(&self, account: AccountUuid, provider: &BackendIdentity) -> bool {
        account == self.import.account_uuid()
            && self.check_current().is_ok()
            && self.native.permits_recovery_read(account, provider)
    }
}
impl Host {
    pub(in crate::host) fn scan_manual_roster_inventory_v2<'a, 'peer, 'audit, 'host>(
        &'a self,
        fresh: &'a mut FreshRosterPreliminaryWalletV2,
        admission: RosterInventoryAdmissionV2,
        lease: &'a SignerRosterInventoryLeaseV2<'peer>,
        target: &'a CommittedRosterImportTarget<'audit, 'host>,
    ) -> Result<RosterInventoryReadV2<'a, 'peer, 'audit, 'host>> {
        let request = lease.request().map_err(|_| Error::Permission)?;
        let scope = &request.scope;
        let inventory_scope = &scope.inventory;
        fresh.check_current(self, scope, target)?;
        let wallet = &mut fresh.wallet;
        let native = admission.bind(&wallet.sync, lease)?;
        let gate = RosterScanAccessV2 {
            native,
            host: self,
            target,
            import: &fresh.import,
        };
        gate.check_current()?;
        let remaining = request
            .remaining_ms(now_ms()?)
            .map_err(|_| Error::Permission)?;
        if wallet
            .sync
            .status()
            .map_err(|_| Error::Invalid)?
            .minimum_confirmations
            != inventory_scope.minimum_confirmations
        {
            return Err(Error::Permission);
        }
        let limits = SyncLimits {
            maximum_blocks: inventory_scope.maximum_blocks,
            anchor_height: Some(inventory_scope.anchor_height),
            deadline: Duration::from_millis(remaining).min(gate.native.remaining()?),
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| Error::Storage)?;
        roster_trace!(
            sync,
            InventorySynchronize,
            runtime.block_on(wallet.sync.synchronize(&gate, limits))
        )
        .map_err(|_| Error::Invalid)?;
        gate.check_current()?;
        let inventory = roster_trace!(
            recovery,
            InventoryInspect,
            wallet
                .sync
                .inspect_account_recovery(&gate, lease.fvk().map_err(|_| Error::Permission)?)
        )
        .map_err(|_| Error::Invalid)?;
        gate.check_current()?;
        inventory.check_current().map_err(|_| Error::Permission)?;
        fresh.check_current(self, scope, target)?;
        let read = RosterInventoryReadV2 {
            gate,
            fresh,
            inventory,
        };
        read.check_current()?;
        Ok(read)
    }
}
fn now_ms() -> Result<u64> {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::Permission)?
            .as_millis(),
    )
    .map_err(|_| Error::Invalid)
}

/// No Clone, serialization, raw balance getter or fresh owner conversion. The
/// source wallet, original V3+current V4, actual import and native approval remain
/// borrowed; dropping or changing any source never renews inventory permission.
pub(in crate::host) struct RosterInventoryReadV2<'a, 'peer, 'audit, 'host> {
    gate: RosterScanAccessV2<'a, 'peer, 'audit, 'host>,
    fresh: &'a FreshRosterPreliminaryWalletV2,
    inventory: AccountRecoveryScan,
}
impl RosterInventoryReadV2<'_, '_, '_, '_> {
    fn check_current(&self) -> Result<()> {
        self.gate.check_current()?;
        let request = self.gate.native.request()?;
        self.fresh
            .check_current(self.gate.host, &request.scope, self.gate.target)?;
        self.inventory
            .check_current()
            .map_err(|_| Error::Permission)?;
        if self.inventory.account_uuid() != self.fresh.wallet.sync.account_uuid() {
            return Err(Error::Permission);
        }
        self.gate.check_current()
    }
    pub(in crate::host) fn display_known_balances(&self) -> Result<()> {
        self.check_current()?;
        let (orchard, ironwood) = self
            .inventory
            .known_pool_balances()
            .map_err(|_| Error::Permission)?;
        let coverage = self
            .inventory
            .retirement_coverage()
            .map_err(|_| Error::Permission)?;
        self.check_current()?;
        self.gate.host.terminal.json(&serde_json::json!({
            "status": "incomplete_local_known_inventory",
            "meaning": "Single-provider local wallet classification only. Not independently consensus verified, not proof of unspentness or complete account history, not an empty-account finding. No contribution selection or spending authority is granted.",
            "orchard": pool(orchard), "ironwood": pool(ironwood),
            "retirement_coverage": coverage,
        }))?;
        self.check_current()
    }
}
fn pool(
    b: wholepact_wallet::wallet::protected_sync::recovery::KnownPoolBalance,
) -> serde_json::Value {
    serde_json::json!({
        "known_total_zatoshis": b.total_zatoshis,
        "wallet_classified_spendable_zatoshis": b.spendable_zatoshis,
        "locked_zatoshis": b.locked_zatoshis,
        "pending_change_zatoshis": b.pending_change_zatoshis,
        "pending_spendability_zatoshis": b.pending_spendability_zatoshis,
        "uneconomic_zatoshis": b.uneconomic_zatoshis,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn known_balance_display_preserves_every_integer_category() {
        use wholepact_wallet::wallet::protected_sync::recovery::KnownPoolBalance;
        let actual = pool(KnownPoolBalance {
            total_zatoshis: 51,
            spendable_zatoshis: 2,
            locked_zatoshis: 3,
            pending_change_zatoshis: 5,
            pending_spendability_zatoshis: 7,
            uneconomic_zatoshis: 11,
        });
        assert_eq!(
            actual,
            serde_json::json!({ "known_total_zatoshis":51,"wallet_classified_spendable_zatoshis":2,"locked_zatoshis":3,"pending_change_zatoshis":5,"pending_spendability_zatoshis":7,"uneconomic_zatoshis":11 })
        );
        // Unknown upstream category overlap never becomes asserted arithmetic,
        // emptiness, input eligibility or retirement completion.
        assert!(actual.get("empty").is_none());
        assert!(actual.get("retirement_complete").is_none());
    }
}
