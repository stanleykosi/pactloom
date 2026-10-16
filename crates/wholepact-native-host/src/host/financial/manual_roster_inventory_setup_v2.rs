//! Fresh-only roster-native V2 import provenance. No legacy owner conversion,
//! reopen/retry factory, construction wallet escape or caller-supplied receipt.
#[path = "manual_roster_candidate_assembly_v2.rs"]
mod candidate_assembly;
pub(in crate::host) use candidate_assembly::{
    ReviewedRosterManualCandidateV2, UnreviewedRosterManualCandidateV2,
};
#[path = "manual_roster_candidate_selection_v2.rs"]
mod candidate_selection;
#[path = "manual_roster_retained_inputs_v2.rs"]
mod retained_inputs;
pub(in crate::host) use retained_inputs::{
    ObservedHandoffCommonContextV1, RetainedRosterCandidateInputsV2,
    RosterContributionRetentionAdmissionV2,
};
#[path = "manual_roster_inventory_scan_v2.rs"]
mod scan;
use super::*;
use crate::{
    authority::manual_roster_inventory_v2::RosterInventoryAdmissionV2,
    financial_inventory::manual::FreshRosterFinancialProfileV2,
    financial_profile::ConstructionWallet, host::manual_enrollment::CommittedRosterImportTarget,
};
use wholepact_core::manual_roster_inventory_v2::ManualRosterInventoryScopeV2;
use wholepact_signer::authority_bridge::manual_roster_inventory_v2::SignerRosterInventoryLeaseV2;
use wholepact_wallet::wallet::recorded_roster_import_v2::RecordedRosterInventoryImportV2;

pub(in crate::host) struct FreshRosterPreliminaryWalletV2 {
    wallet: ConstructionWallet,
    scope_digest: String,
    request_digest: String,
    import: RecordedRosterInventoryImportV2,
}
impl FreshRosterPreliminaryWalletV2 {
    pub(in crate::host) fn check_current(
        &self,
        host: &Host,
        scope: &ManualRosterInventoryScopeV2,
        target: &CommittedRosterImportTarget<'_, '_>,
    ) -> Result<()> {
        target.require_current(host, scope)?;
        self.check_current_attachment(host, scope, false)?;
        target.require_current(host, scope)
    }

    // Provenance-only check, never an admission factory. Retained-stage callers
    // additionally hold explicit bounded Host retention consent and the actual
    // captured generation/Store/capsule owner. No old approval is extended.
    fn check_current_attachment(
        &self,
        host: &Host,
        scope: &ManualRosterInventoryScopeV2,
        retained: bool,
    ) -> Result<()> {
        scope.validate().map_err(|_| Error::Invalid)?;
        let inventory = &scope.inventory;
        let access = host.access()?;
        host.authority
            .check_financial_principal(&access.principal_id)?;
        if self.scope_digest != scope.pairing_digest().map_err(|_| Error::Invalid)?
            || inventory.enrollment.scope.principal_id != access.principal_id
            || inventory.enrollment.host.profile_id != host.secrets.profile()
            || host
                .secrets
                .generation_plan_digest()
                .map(hex::encode)
                .as_deref()
                != Some(inventory.enrollment.host.generation_plan_digest.as_str())
            || host.directory.manual_target_identity_digest()?
                != inventory.enrollment.host.destination_identity_digest
        {
            return Err(Error::Permission);
        }
        self.import
            .check_request_scope_and_account(
                &self.request_digest,
                &self.scope_digest,
                // The historical path uses the original authenticated import
                // UUID, without pretending it is a new maintained DB read.
                if retained {
                    self.import.account_uuid()
                } else {
                    self.wallet.sync.account_uuid()
                },
            )
            .map_err(|_| Error::Permission)?;
        self.wallet
            .check_manual_attachment(&host.secrets.profile(), &inventory.attachment.selected)?;
        if !retained {
            self.wallet
                .sync
                .verify_account_birthday_height(
                    inventory
                        .birthday
                        .prior_height
                        .checked_add(1)
                        .ok_or(Error::Invalid)?,
                )
                .map_err(|_| Error::Permission)?;
        }
        // Current account/FVK/birthday rows for retained construction are read
        // only under the new exact-read grant and held maintained transaction.
        let primary = host.financial.as_ref().ok_or(Error::Locked)?;
        if retained {
            crate::financial_inventory::manual::require_retained_wallet_binding(
                &host.directory,
                &host.secrets,
                primary,
                &self.wallet,
                &inventory.attachment,
            )?;
        } else if crate::financial_inventory::manual::binding_for_wallet(
            &host.directory,
            &host.secrets,
            primary,
            &self.wallet,
            &inventory.enrollment.identity.account_id,
        )? != inventory.attachment
        {
            return Err(Error::Permission);
        }
        Ok(())
    }

    pub(in crate::host) fn import(
        host: &Host,
        fresh: FreshRosterFinancialProfileV2,
        admission: &RosterInventoryAdmissionV2,
        lease: &SignerRosterInventoryLeaseV2<'_>,
        target: &CommittedRosterImportTarget<'_, '_>,
    ) -> Result<Self> {
        let request = lease.request().map_err(|_| Error::Permission)?;
        let scope = &request.scope;
        let inventory = &scope.inventory;
        admission.require_scope(scope)?;
        target.require_current(host, scope)?;
        let access = host.access()?;
        host.authority
            .check_financial_principal(&access.principal_id)?;
        let primary = host.financial.as_ref().ok_or(Error::Locked)?;
        if inventory.enrollment.scope.principal_id != access.principal_id
            || inventory.enrollment.host.profile_id != host.secrets.profile()
            || crate::financial_inventory::manual::binding_for_profile(
                &host.directory,
                &host.secrets,
                primary,
                fresh.profile(),
                &inventory.enrollment.identity.account_id,
            )? != inventory.attachment
        {
            return Err(Error::Permission);
        }
        let mut profile = fresh.into_profile();
        let fvk = lease.fvk().map_err(|_| Error::Permission)?;
        let evidence_digest = lease
            .evidence()
            .map_err(|_| Error::Permission)?
            .digest()
            .map_err(|_| Error::Permission)?;
        let request_digest = request.digest().map_err(|_| Error::Invalid)?;
        let scope_digest = scope.pairing_digest().map_err(|_| Error::Invalid)?;
        // Both original approvals and actual Store/audit owners remain current
        // immediately around the one durable V2-only import attempt.
        target.require_current(host, scope)?;
        admission.require_scope(scope)?;
        lease.check_current().map_err(|_| Error::Permission)?;
        let import = profile
            .wallet
            .import_recorded_roster_inventory_fvk_v2(fvk, request, &evidence_digest)
            .map_err(|_| Error::Invalid)?;
        admission.require_scope(scope)?;
        lease.check_current().map_err(|_| Error::Permission)?;
        target.require_current(host, scope)?;
        let source = ChainAdapter::testnet(
            &inventory.provider.source_id,
            &inventory.provider.endpoint,
            NetworkPolicy::default(),
        )?;
        let wallet = profile.into_construction_wallet(
            source,
            std::num::NonZeroU32::new(inventory.minimum_confirmations).ok_or(Error::Invalid)?,
        )?;
        let actual_account = lease
            .verify_wallet_account(&wallet.sync)
            .map_err(|_| Error::Permission)?;
        import
            .check_request_scope_and_account(&request_digest, &scope_digest, actual_account)
            .map_err(|_| Error::Permission)?;
        wallet
            .sync
            .verify_account_birthday_height(
                inventory
                    .birthday
                    .prior_height
                    .checked_add(1)
                    .ok_or(Error::Invalid)?,
            )
            .map_err(|_| Error::Permission)?;
        admission.require_scope(scope)?;
        let result = Self {
            wallet,
            scope_digest,
            request_digest,
            import,
        };
        result.check_current(host, scope, target)?;
        lease.check_current().map_err(|_| Error::Permission)?;
        Ok(result)
    }
}

/// Borrowed original import/file/registry facts only. Account/FVK/birthday and
/// complete scan/exact note checks belong to the actual held WalletDb callback.
struct FreshRosterProvenanceV2<'a> {
    wallet: crate::financial_profile::ConstructionWalletProvenance<'a>,
    scope_digest: &'a str,
    request_digest: &'a str,
    import: &'a RecordedRosterInventoryImportV2,
}
impl FreshRosterPreliminaryWalletV2 {
    fn exact_input_parts(
        &mut self,
    ) -> (
        &mut wholepact_wallet::wallet::protected_sync::ProtectedWalletSync,
        FreshRosterProvenanceV2<'_>,
    ) {
        let (sync, wallet) = self.wallet.exact_input_parts();
        (
            sync,
            FreshRosterProvenanceV2 {
                wallet,
                scope_digest: &self.scope_digest,
                request_digest: &self.request_digest,
                import: &self.import,
            },
        )
    }
}
impl FreshRosterProvenanceV2<'_> {
    fn check_current(
        &self,
        host: &Host,
        scope: &ManualRosterInventoryScopeV2,
        actual_held_account: wholepact_wallet::wallet::AccountUuid,
    ) -> Result<()> {
        scope.validate().map_err(|_| Error::Invalid)?;
        let inventory = &scope.inventory;
        let access = host.access()?;
        host.authority
            .check_financial_principal_fail_fast(&access.principal_id)?;
        if self.scope_digest != scope.pairing_digest().map_err(|_| Error::Invalid)?
            || inventory.enrollment.scope.principal_id != access.principal_id
            || inventory.enrollment.host.profile_id != host.secrets.profile()
            || host
                .secrets
                .generation_plan_digest()
                .map(hex::encode)
                .as_deref()
                != Some(inventory.enrollment.host.generation_plan_digest.as_str())
            || host.directory.manual_target_identity_digest()?
                != inventory.enrollment.host.destination_identity_digest
        {
            return Err(Error::Permission);
        }
        self.import
            .check_request_scope_and_account(
                self.request_digest,
                self.scope_digest,
                actual_held_account,
            )
            .map_err(|_| Error::Permission)?;
        crate::financial_inventory::manual::require_retained_wallet_provenance_binding(
            &host.directory,
            &host.secrets,
            host.financial.as_ref().ok_or(Error::Locked)?,
            &self.wallet,
            &inventory.attachment,
        )
    }
}

#[path = "manual_roster_candidate_assembly_v3.rs"]
mod candidate_assembly_v3;

pub(in crate::host) use candidate_assembly_v3::{
    AllObservedCommonContextRosterV1, CommonContextConstructionCoordinatorV3,
    ReviewedRosterManualCandidateV3, UnreviewedRosterManualCandidateV3,
};
