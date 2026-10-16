//! Additional early denial, not recovered financial admission. The permanent
//! host guard and the Store's independent recovered-generation refusal both stay
//! in place until actual owner-issued scope/exclusion provenance is integrated.
use super::*;

impl Host {
    pub(super) fn financial_lineage_preflight(
        &self,
        candidate: &wholepact_engine::CandidateView,
        idempotency_key: Option<&str>,
        operation_ids: &[&str],
    ) -> Result<()> {
        self.require_financial_generation_admission()?;
        let access = self.access()?;
        self.authority
            .check_financial_principal(&access.principal_id)?;
        self.engine.require_ordinary_financial_candidate(
            access,
            candidate,
            idempotency_key,
            operation_ids,
        )?;
        Ok(())
    }
}
