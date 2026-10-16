//! Child of fresh inventory setup, retaining access to its actual private wallet.
//! This selects once and returns only gated evidence; no builder conversion.
use super::*;
use crate::authority::manual_candidate_selection::CandidateSelectionAdmission;
use wholepact_signer::authority_bridge::manual_candidate_selection::SignerCandidateSelectionLease;
#[path = "manual_candidate_inputs.rs"]
mod inputs;
pub(in crate::host) use inputs::SelectedCandidateInputs;
impl Host {
    pub(in crate::host) fn select_manual_candidate_inputs(
        &self,
        fresh: &mut FreshPreliminaryWallet,
        admission: CandidateSelectionAdmission,
        lease: &SignerCandidateSelectionLease<'_>,
        local_exclusions: &wholepact_store::manual_enrollment::ManualCandidateLocalExclusions<'_>,
    ) -> Result<SelectedCandidateInputs> {
        let request = lease.request().map_err(|_| Error::Permission)?;
        let inventory = &request.scope.inventory;
        fresh.check_current(self, inventory)?;
        let target = self
            .engine
            .manual_enrollment_target(self.access()?, &inventory.enrollment)?;
        if target.agreement_revision() != request.scope.economic_intent.candidate_revision {
            return Err(Error::Permission);
        }
        let wallet = fresh.wallet_for_scope(inventory)?;
        let gate = admission.bind(&wallet.sync, lease)?;
        gate.check_current()?;
        self.engine
            .manual_candidate_current_exclusions(self.access()?, request, local_exclusions)
            .map_err(|_| Error::Permission)?;
        // The bridge consumes its one attempt before the maintained call. No
        // guessed note references, retries or empty-exclusion cleanliness claim.
        let selected = lease
            .select_contribution(&mut wallet.sync, &gate)
            .map_err(|_| Error::Permission)?;
        gate.check_current()?;
        target.check_current(self.access()?)?;
        fresh.check_current(self, inventory)?;
        let result = SelectedCandidateInputs::capture(
            selected,
            lease,
            self.engine
                .manual_candidate_current_exclusions(self.access()?, request, local_exclusions)
                .map_err(|_| Error::Permission)?,
        )?;
        gate.check_current()?;
        Ok(result)
    }
}
