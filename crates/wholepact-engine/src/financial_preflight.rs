//! Read-only early lineage checks. These are additional denials, never current
//! native authority, a financial capability or complete signer-history evidence.
use super::*;
pub use wholepact_store::financial_preflight::RetainedInputExclusions;

impl Engine {
    pub fn require_ordinary_financial_candidate(
        &self,
        access: &Access,
        expected: &CandidateView,
        idempotency_key: Option<&str>,
        operation_ids: &[&str],
    ) -> Result<()> {
        let (view, candidate) = self.candidate(access, &expected.candidate_id)?;
        candidate.verified_snapshot()?;
        if serde_json::to_value(&candidate).map_err(|_| internal())?
            != serde_json::to_value(expected).map_err(|_| internal())?
        {
            return Err(ApiError::new(
                "REVISION_CONFLICT",
                "Exact financial candidate changed before private work",
            ));
        }
        self.require_current_agreement(&view.agreement.agreement_id)?;
        self.store
            .require_ordinary_financial_lineage(
                &view.agreement.agreement_id,
                &view.agreement.obligation_id,
                &access.principal_id,
                idempotency_key,
                operation_ids,
            )
            .map_err(store_error)
    }

    pub fn retained_financial_input_exclusions(
        &self,
        access: &Access,
        candidate: &CandidateView,
        account_id: &str,
    ) -> Result<RetainedInputExclusions> {
        self.require_ordinary_financial_candidate(access, candidate, None, &[])?;
        if !candidate
            .proposal
            .manifest
            .participants
            .iter()
            .any(|p| p.account_id == account_id)
        {
            return Err(ApiError::new(
                "PERMISSION_DENIED",
                "Input exclusions must target an exact candidate participant",
            ));
        }
        self.store
            .retained_financial_input_exclusions(account_id)
            .map_err(store_error)
    }
}

/// Called only by the existing encrypted G1 reconstruction/opener test. No raw
/// Store classification is changed and no financial capability is constructed.
#[cfg(test)]
pub(crate) fn assert_g1_financial_denial(store: &Store, principal: &str, original_operation: &str) {
    // Exercise the real encrypted G1 reconstruction and dedicated opener above,
    // not a fabricated Store classification. These are financial DENIAL checks;
    // this synthetic storage fixture grants no native signer/witness admission.
    assert!(
        store
            .account_exposures("never-seen-account")
            .unwrap()
            .is_empty()
    );
    for account in ["synthetic-account", "never-seen-account"] {
        assert!(matches!(
            store.retained_financial_input_exclusions(account),
            Err(wholepact_store::StoreError::RecoveryRequired)
        ));
    }
    for (agreement, obligation, key, operations) in [
        (
            "fresh-label",
            "obligation-historical",
            None,
            Vec::<&str>::new(),
        ),
        (
            "fresh-label",
            "fresh-obligation",
            Some("synthetic-original-key"),
            vec![original_operation],
        ),
        ("fresh-label", "fresh-obligation", None, vec!["old-effect"]),
        ("fresh-label", "fresh-obligation", None, Vec::new()),
    ] {
        assert!(matches!(
            store.require_ordinary_financial_lineage(
                agreement,
                obligation,
                principal,
                key,
                &operations,
            ),
            Err(wholepact_store::StoreError::RecoveryRequired)
        ));
    }
}
