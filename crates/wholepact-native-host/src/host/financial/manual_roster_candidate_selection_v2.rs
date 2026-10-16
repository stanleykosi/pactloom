//! One actual V2 selection attempt, preserving the exact imported V2 scope and
//! actual retained local-exclusion snapshot. There is no contribution escape.
use super::*;
use crate::authority::manual_roster_candidate_selection_v2::{
    RosterCandidateSelectionAdmissionV2, RosterCandidateSelectionWalletAccessV2,
};
use wholepact_signer::authority_bridge::manual_roster_candidate_selection_v2::SignerRosterCandidateSelectionLeaseV2;
use wholepact_store::manual_enrollment::ManualRosterCandidateLocalExclusionsV2;
use wholepact_wallet::wallet::{
    AccountUuid,
    protected_sync::{BackendIdentity, LocalWalletAccess, WalletAccessPurpose},
};
#[path = "manual_roster_candidate_inputs_v2.rs"]
mod inputs;
pub(in crate::host) use inputs::SelectedRosterCandidateInputsV2;

pub(super) struct RosterCandidateSourceV2<'source, 'audit, 'host, 'store> {
    host: &'source Host,
    admission_deadline: std::time::Instant,
    fresh: &'source FreshRosterPreliminaryWalletV2,
    target: &'source CommittedRosterImportTarget<'audit, 'host>,
    inventory_scope: ManualRosterInventoryScopeV2,
    local_exclusions: &'source ManualRosterCandidateLocalExclusionsV2<'store>,
}
struct RosterSelectionAccessV2<'a, 'peer, 'audit, 'host, 'store> {
    host: &'a Host,
    target: &'a CommittedRosterImportTarget<'audit, 'host>,
    inventory_scope: &'a ManualRosterInventoryScopeV2,
    import: &'a RecordedRosterInventoryImportV2,
    local_exclusions: &'a ManualRosterCandidateLocalExclusionsV2<'store>,
    native: RosterCandidateSelectionWalletAccessV2<'a, 'peer>,
    lease: &'a SignerRosterCandidateSelectionLeaseV2<'peer>,
}
impl RosterSelectionAccessV2<'_, '_, '_, '_, '_> {
    fn check_current(&self) -> Result<()> {
        self.native.check_current()?;
        self.target
            .require_current(self.host, self.inventory_scope)?;
        let access = self.host.access()?;
        self.host
            .authority
            .check_financial_principal(&access.principal_id)?;
        let request = self.lease.request().map_err(|_| Error::Permission)?;
        self.host
            .engine
            .manual_roster_candidate_current_exclusions_v2(
                access,
                request,
                self.local_exclusions,
            )?;
        self.import
            .check_request_scope_and_account(
                self.import.request_digest(),
                &self
                    .inventory_scope
                    .pairing_digest()
                    .map_err(|_| Error::Invalid)?,
                self.import.account_uuid(),
            )
            .map_err(|_| Error::Permission)?;
        self.native.check_current()
    }
}
impl LocalWalletAccess for RosterSelectionAccessV2<'_, '_, '_, '_, '_> {
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
impl Host {
    pub(in crate::host) fn select_manual_roster_candidate_inputs_v2<
        'source,
        'audit,
        'host,
        'store,
    >(
        &'source self,
        fresh: &'source mut FreshRosterPreliminaryWalletV2,
        admission: RosterCandidateSelectionAdmissionV2,
        lease: &SignerRosterCandidateSelectionLeaseV2<'_>,
        target: &'source CommittedRosterImportTarget<'audit, 'host>,
        local_exclusions: &'source ManualRosterCandidateLocalExclusionsV2<'store>,
    ) -> Result<SelectedRosterCandidateInputsV2<'source, 'audit, 'host, 'store>> {
        let request = lease.request().map_err(|_| Error::Permission)?;
        // Copy only inert data into the SAME V2 inventory type, preserving every
        // roster field. No V1 owner, request, import or authority is constructed.
        let inventory_scope = ManualRosterInventoryScopeV2 {
            version: 2,
            inventory: request.scope.selection.inventory.clone(),
            provenance: request.scope.provenance.clone(),
        };
        fresh.check_current(self, &inventory_scope, target)?;
        let admission_deadline = admission.deadline();
        let wallet = &mut fresh.wallet;
        let native = admission.bind(&wallet.sync, lease)?;
        let gate = RosterSelectionAccessV2 {
            host: self,
            target,
            inventory_scope: &inventory_scope,
            import: &fresh.import,
            local_exclusions,
            native,
            lease,
        };
        gate.check_current()?;
        // The actual native bridge consumes its sole attempt before maintained
        // selection, including failures. The V2 exclusion snapshot is rechecked
        // before and after, and capture rejects any selected retained conflict.
        let selected = lease
            .select_contribution(&mut wallet.sync, &gate)
            .map_err(|_| Error::Permission)?;
        gate.check_current()?;
        drop(gate);
        fresh.check_current(self, &inventory_scope, target)?;
        SelectedRosterCandidateInputsV2::capture(
            selected,
            lease,
            RosterCandidateSourceV2 {
                host: self,
                admission_deadline,
                fresh,
                target,
                inventory_scope,
                local_exclusions,
            },
        )
    }
}
