//! Fresh-only exact import provenance. Reopen/retry cannot construct this owner.
#[path = "manual_candidate_assembly.rs"]
mod candidate_assembly;
#[path = "manual_candidate_selection.rs"]
mod candidate_selection;
#[path = "manual_inventory_scan.rs"]
mod scan;
use super::*;
use crate::host::manual_enrollment::CommittedImportTarget;
use crate::{
    authority::manual_inventory::PreliminaryInventoryAdmission,
    financial_inventory::manual::FreshFinancialProfile, financial_profile::ConstructionWallet,
};
use wholepact_signer::authority_bridge::manual_inventory::SignerPreliminaryInventoryLease;
use wholepact_wallet::wallet::recorded_import::RecordedPreliminaryImport;

pub(in crate::host) struct FreshPreliminaryWallet {
    wallet: ConstructionWallet,
    scope_digest: String,
    import: RecordedPreliminaryImport,
}
impl FreshPreliminaryWallet {
    pub(in crate::host) fn check_current(
        &self,
        host: &Host,
        scope: &wholepact_core::manual_inventory::ManualPreliminaryInventoryScope,
    ) -> Result<()> {
        if self.scope_digest != scope.pairing_digest().map_err(|_| Error::Invalid)?
            || scope.enrollment.scope.principal_id != host.access()?.principal_id
            || scope.enrollment.host.profile_id != host.secrets.profile()
            || host
                .secrets
                .generation_plan_digest()
                .map(hex::encode)
                .as_deref()
                != Some(scope.enrollment.host.generation_plan_digest.as_str())
            || host.directory.manual_target_identity_digest()?
                != scope.enrollment.host.destination_identity_digest
        {
            return Err(Error::Permission);
        }
        self.import
            .check_scope_and_account(&self.scope_digest, self.wallet.sync.account_uuid())
            .map_err(|_| Error::Permission)?;
        self.wallet
            .check_manual_attachment(&host.secrets.profile(), &scope.attachment.selected)?;
        self.wallet
            .sync
            .verify_account_birthday_height(
                scope
                    .birthday
                    .prior_height
                    .checked_add(1)
                    .ok_or(Error::Invalid)?,
            )
            .map_err(|_| Error::Permission)?;
        let primary = host.financial.as_ref().ok_or(Error::Locked)?;
        if crate::financial_inventory::manual::binding_for_wallet(
            &host.directory,
            &host.secrets,
            primary,
            &self.wallet,
            &scope.enrollment.identity.account_id,
        )? != scope.attachment
        {
            return Err(Error::Permission);
        }
        Ok(())
    }
    fn wallet_for_scope(
        &mut self,
        scope: &wholepact_core::manual_inventory::ManualPreliminaryInventoryScope,
    ) -> Result<&mut ConstructionWallet> {
        if self.scope_digest != scope.pairing_digest().map_err(|_| Error::Invalid)? {
            return Err(Error::Permission);
        }
        self.wallet
            .sync
            .verify_account_birthday_height(
                scope
                    .birthday
                    .prior_height
                    .checked_add(1)
                    .ok_or(Error::Invalid)?,
            )
            .map_err(|_| Error::Permission)?;
        self.import
            .check_scope_and_account(&self.scope_digest, self.wallet.sync.account_uuid())
            .map_err(|_| Error::Permission)?;
        Ok(&mut self.wallet)
    }
    pub(in crate::host) fn import(
        host: &Host,
        fresh: FreshFinancialProfile,
        admission: &PreliminaryInventoryAdmission,
        lease: &SignerPreliminaryInventoryLease<'_>,
        target: &CommittedImportTarget<'_, '_>,
    ) -> Result<Self> {
        let request = lease.request().map_err(|_| Error::Permission)?;
        let scope = &request.scope;
        admission.require_scope(scope)?;
        target.require_current(host, scope)?;
        let primary = host.financial.as_ref().ok_or(Error::Locked)?;
        if scope.enrollment.scope.principal_id != host.access()?.principal_id
            || scope.enrollment.host.profile_id != host.secrets.profile()
            || crate::financial_inventory::manual::binding_for_profile(
                &host.directory,
                &host.secrets,
                primary,
                fresh.profile(),
                &scope.enrollment.identity.account_id,
            )? != scope.attachment
        {
            return Err(Error::Permission);
        }
        let b = &scope.birthday;
        let mut profile = fresh.into_profile();
        // Fresh profile is created once through the actual native attachment
        // effect. This maintained importer creates Orchard-only key components.
        let fvk = lease.fvk().map_err(|_| Error::Permission)?;
        admission.require_scope(scope)?;
        let evidence_digest = lease
            .evidence()
            .map_err(|_| Error::Permission)?
            .digest()
            .map_err(|_| Error::Permission)?;
        target.require_current(host, scope)?;
        admission.require_scope(scope)?;
        lease.check_current().map_err(|_| Error::Permission)?;
        let import = profile
            .wallet
            .import_recorded_preliminary_fvk(fvk, request, &evidence_digest)
            .map_err(|_| Error::Invalid)?;
        admission.require_scope(scope)?;
        lease.check_current().map_err(|_| Error::Permission)?;
        target.require_current(host, scope)?;
        let source = ChainAdapter::testnet(
            &scope.provider.source_id,
            &scope.provider.endpoint,
            NetworkPolicy::default(),
        )?;
        let wallet = profile.into_construction_wallet(
            source,
            std::num::NonZeroU32::new(scope.minimum_confirmations).ok_or(Error::Invalid)?,
        )?;
        let actual_account = lease
            .verify_wallet_account(&wallet.sync)
            .map_err(|_| Error::Permission)?;
        import
            .check_scope_and_account(
                &scope.pairing_digest().map_err(|_| Error::Invalid)?,
                actual_account,
            )
            .map_err(|_| Error::Permission)?;
        wallet
            .sync
            .verify_account_birthday_height(b.prior_height.checked_add(1).ok_or(Error::Invalid)?)
            .map_err(|_| Error::Permission)?;
        admission.require_scope(scope)?;
        Ok(Self {
            wallet,
            scope_digest: scope.pairing_digest().map_err(|_| Error::Invalid)?,
            import,
        })
    }
}
