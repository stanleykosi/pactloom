//! Concrete bounded scanner for an already native-approved attached wallet.
//! No CLI hook is added until original target/admission and attachment setup are
//! composed. This function cannot construct a candidate or select inputs.
use super::*;
use crate::authority::manual_inventory::{
    PreliminaryInventoryAdmission, PreliminaryInventoryWalletAccess,
};
use wholepact_signer::authority_bridge::manual_inventory::SignerPreliminaryInventoryLease;
use wholepact_wallet::wallet::protected_sync::{SyncLimits, recovery::AccountRecoveryScan};

impl Host {
    pub(in crate::host) fn scan_manual_preliminary_inventory<'a, 'peer>(
        &self,
        fresh: &mut super::FreshPreliminaryWallet,
        admission: PreliminaryInventoryAdmission,
        lease: &'a SignerPreliminaryInventoryLease<'peer>,
    ) -> Result<PreliminaryInventoryRead<'a, 'peer>> {
        let request = lease.request().map_err(|_| Error::Permission)?;
        let scope = &request.scope;
        fresh.check_current(self, scope)?;
        let import_provenance = fresh
            .import
            .evidence_for_scope(
                &scope.pairing_digest().map_err(|_| Error::Invalid)?,
                fresh.wallet.sync.account_uuid(),
            )
            .map_err(|_| Error::Permission)?;
        let wallet = fresh.wallet_for_scope(scope)?;
        let access = self.access()?;
        let terms = &scope.enrollment;
        let primary = self.financial.as_ref().ok_or(Error::Locked)?;
        if terms.scope.principal_id != access.principal_id
            || terms.host.profile_id != self.secrets.profile()
        {
            return Err(Error::Permission);
        }
        // Actual held profile/database identities, not paths supplied by JSON.
        let attachment = crate::financial_inventory::manual::binding_for_wallet(
            &self.directory,
            &self.secrets,
            primary,
            wallet,
            &terms.identity.account_id,
        )?;
        if attachment != scope.attachment {
            return Err(Error::Permission);
        }
        // This identity check derives the actual maintained wallet account UUID.
        // The resulting purpose gate refuses SelectPrivateContribution.
        let gate = admission.bind(&wallet.sync, lease)?;
        let remaining = request
            .remaining_ms(
                u64::try_from(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| Error::Permission)?
                        .as_millis(),
                )
                .map_err(|_| Error::Invalid)?,
            )
            .map_err(|_| Error::Permission)?;
        if wallet
            .sync
            .status()
            .map_err(|_| Error::Invalid)?
            .minimum_confirmations
            != scope.minimum_confirmations
        {
            return Err(Error::Permission);
        }
        let limits = SyncLimits {
            maximum_blocks: scope.maximum_blocks,
            anchor_height: Some(scope.anchor_height),
            deadline: Duration::from_millis(remaining).min(gate.remaining()?),
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| Error::Storage)?;
        runtime
            .block_on(wallet.sync.synchronize(&gate, limits))
            .map_err(|_| Error::Invalid)?;
        gate.check_current()?;
        if crate::financial_inventory::manual::binding_for_wallet(
            &self.directory,
            &self.secrets,
            primary,
            wallet,
            &terms.identity.account_id,
        )? != scope.attachment
        {
            return Err(Error::Permission);
        }
        let inventory = wallet
            .sync
            .inspect_account_recovery(&gate, lease.fvk().map_err(|_| Error::Permission)?)
            .map_err(|_| Error::Invalid)?;
        gate.check_current()?;
        inventory.check_current().map_err(|_| Error::Permission)?;
        // This contains known pool balances and incomplete birthday/history
        // evidence only. It is never an empty-account or unspentness assertion.
        Ok(PreliminaryInventoryRead {
            gate,
            inventory,
            import_provenance,
        })
    }
}

/// The inventory does not escape its original viewing lease. In particular,
/// later metadata access cannot bypass native expiry after the scan completes.
pub(in crate::host) struct PreliminaryInventoryRead<'a, 'peer> {
    gate: PreliminaryInventoryWalletAccess<'a, 'peer>,
    inventory: AccountRecoveryScan,
    import_provenance: wholepact_wallet::wallet::recorded_import::RecordedImportEvidence,
}
impl PreliminaryInventoryRead<'_, '_> {
    pub(in crate::host) fn display_known_balances(
        &self,
        terminal: &crate::terminal::Terminal,
    ) -> Result<()> {
        let (orchard, ironwood) = self.known_balances()?;
        let pool = |b: wholepact_wallet::wallet::protected_sync::recovery::KnownPoolBalance| {
            serde_json::json!({
                "known_total_zatoshis": b.total_zatoshis,
                "wallet_classified_spendable_zatoshis": b.spendable_zatoshis,
                "locked_zatoshis": b.locked_zatoshis,
                "pending_change_zatoshis": b.pending_change_zatoshis,
                "pending_spendability_zatoshis": b.pending_spendability_zatoshis,
                "uneconomic_zatoshis": b.uneconomic_zatoshis,
            })
        };
        self.gate.check_current()?;
        self.inventory
            .check_current()
            .map_err(|_| Error::Permission)?;
        let coverage = self
            .inventory
            .retirement_coverage()
            .map_err(|_| Error::Permission)?;
        self.gate.check_current()?;
        terminal.json(&serde_json::json!({
            "status": "incomplete_local_known_inventory",
            "meaning": "Single-provider local wallet classification only. Not independently consensus verified, not proof of unspentness or complete account history, not an empty-account finding. No contribution selection or spending authority is granted.",
            "orchard": pool(orchard), "ironwood": pool(ironwood),
            "retirement_coverage": coverage,
            "committed_import_provenance": &self.import_provenance,
        }))?;
        self.gate.check_current()?;
        self.inventory
            .check_current()
            .map_err(|_| Error::Permission)
    }
    fn known_balances(
        &self,
    ) -> Result<(
        wholepact_wallet::wallet::protected_sync::recovery::KnownPoolBalance,
        wholepact_wallet::wallet::protected_sync::recovery::KnownPoolBalance,
    )> {
        self.gate.check_current()?;
        let result = self
            .inventory
            .known_pool_balances()
            .map_err(|_| Error::Permission)?;
        self.gate.check_current()?;
        Ok(result)
    }
}
