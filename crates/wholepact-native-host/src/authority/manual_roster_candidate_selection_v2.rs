//! One bounded local selection review. This owner cannot admit a scan, builder,
//! proof, signature, export or dispatch. Installed signer consent is independent.
use crate::{
    Error, Result,
    terminal::{Terminal, historical::HistoricalApproval},
};
use std::time::Instant;
use wholepact_core::manual_roster_candidate_selection_v2::ManualRosterCandidateSelectionScopeV2;
use wholepact_signer::authority_bridge::manual_roster_candidate_selection_v2::SignerRosterCandidateSelectionLeaseV2;
use wholepact_wallet::wallet::{
    AccountUuid,
    protected_sync::{
        BackendIdentity, LocalWalletAccess, ProtectedWalletSync, WalletAccessPurpose,
    },
};

pub(crate) struct RosterCandidateSelectionAdmissionV2 {
    scope: ManualRosterCandidateSelectionScopeV2,
    deadline: Instant,
}
impl RosterCandidateSelectionAdmissionV2 {
    pub(crate) fn review(
        terminal: &Terminal,
        prior: &HistoricalApproval,
        scope: &ManualRosterCandidateSelectionScopeV2,
    ) -> Result<Self> {
        scope.validate().map_err(|_| Error::Invalid)?;
        let digest = scope.pairing_digest().map_err(|_| Error::Invalid)?;
        let detail = serde_json::to_string_pretty(scope)?;
        let approval = terminal.approve_publication_reviewed(prior, &digest, &format!("Prepare exactly one private contribution for these exact economic terms.\n{detail}\nThe installed signer must separately approve. Only the already scanned, exactly attached fresh wallet may be used. This does not refresh providers, create a full candidate, construct, reserve funds, sign or dispatch. One selection attempt is consumed even on failure; conflicts require fresh review. Actual input identifiers and values will require a later separate exact contribution review before construction. Disclosed data cannot be recalled. The original deadline includes launch and review delays."))?;
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
    pub(crate) fn require_scope(
        &self,
        scope: &ManualRosterCandidateSelectionScopeV2,
    ) -> Result<()> {
        scope.validate().map_err(|_| Error::Invalid)?;
        if &self.scope != scope || Instant::now() >= self.deadline {
            return Err(Error::Permission);
        }
        Ok(())
    }
    pub(crate) fn bind<'a, 'peer>(
        self,
        wallet: &ProtectedWalletSync,
        lease: &'a SignerRosterCandidateSelectionLeaseV2<'peer>,
    ) -> Result<RosterCandidateSelectionWalletAccessV2<'a, 'peer>> {
        if Instant::now() >= self.deadline
            || self.scope != lease.request().map_err(|_| Error::Permission)?.scope
        {
            return Err(Error::Permission);
        }
        let account = lease
            .verify_wallet_account(wallet)
            .map_err(|_| Error::Permission)?;
        let result = RosterCandidateSelectionWalletAccessV2 {
            admission: self,
            account,
            lease,
        };
        result.check_current()?;
        Ok(result)
    }
}
pub(crate) struct RosterCandidateSelectionWalletAccessV2<'a, 'peer> {
    admission: RosterCandidateSelectionAdmissionV2,
    account: AccountUuid,
    lease: &'a SignerRosterCandidateSelectionLeaseV2<'peer>,
}
impl RosterCandidateSelectionWalletAccessV2<'_, '_> {
    pub(crate) fn check_current(&self) -> Result<()> {
        if Instant::now() >= self.admission.deadline {
            return Err(Error::Permission);
        }
        self.lease.check_current().map_err(|_| Error::Permission)
    }
}
impl LocalWalletAccess for RosterCandidateSelectionWalletAccessV2<'_, '_> {
    fn permits(
        &self,
        account: AccountUuid,
        provider: &BackendIdentity,
        purpose: WalletAccessPurpose,
    ) -> bool {
        let approved = &self.admission.scope.selection.inventory.provider;
        selection_only(purpose)
            && account == self.account
            && provider.source_id == approved.source_id
            && provider.endpoint == approved.endpoint
            && provider.trust_profile == approved.trust_profile
            && self.check_current().is_ok()
    }
}
fn selection_only(purpose: WalletAccessPurpose) -> bool {
    matches!(purpose, WalletAccessPurpose::SelectPrivateContribution)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn candidate_preparation_never_implicitly_refreshes_provider() {
        assert!(selection_only(
            WalletAccessPurpose::SelectPrivateContribution
        ));
        assert!(!selection_only(
            WalletAccessPurpose::SynchronizePublicBlocks
        ));
    }
}
