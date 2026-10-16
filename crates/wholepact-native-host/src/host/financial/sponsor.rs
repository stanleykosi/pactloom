//! Account-only exact sponsor constraints in the production construction route.
//! Separate native owner disclosure supplies evidence; no request flag enables it.
use super::*;
use wholepact_signer::authority_bridge::preconstruction_ipc::SignerPreconstructionLease;
impl Host {
    pub(super) fn review_construction_sponsors(
        &self,
        access: &wholepact_engine::Access,
        candidate: &str,
        leases: &[SignerPreconstructionLease<'_>],
    ) -> Result<()> {
        for lease in leases {
            let Some(terms) = lease.sponsor_policy() else {
                continue;
            };
            let review = self
                .engine
                .review_sponsor_from_live_owners(access, candidate, terms, leases)?;
            self.terminal.json(&review)?;
            self.terminal.confirm("Apply these exact account-only sponsor constraints to this immutable fixed-contribution proposal? Native owners approved account attribution and sponsor-budget disclosure. Cryptographic construction must still verify all inputs and returns. This does not prove distinct people or organizations, reserve a budget, or authorize signing. Changing allocations requires a new proposal and native review.")?;
            // Human review can take time. Recheck every owner and the exact
            // witness head before the existing constructor consumes selections.
            self.engine
                .review_sponsor_from_live_owners(access, candidate, terms, leases)?;
        }
        Ok(())
    }
}
