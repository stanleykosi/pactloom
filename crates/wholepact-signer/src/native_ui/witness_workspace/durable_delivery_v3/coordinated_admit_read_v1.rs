//! One fresh nominal AdmitRead over the retained actual original owner client.
use super::*;
use wholepact_financial_coordinator_origin::SignerV3AdmitReadFinalV1;

/// The consumed Read owner is retained until the same source has prepared the
/// exact immutable local candidate. No second history-read method exists.
pub(in crate::native_ui) struct ReadCoordinatedDeliveryWitnessV1 {
    witness: CoordinatedDeliveryWitnessV1,
    history: ReconciledAuthorityHistory,
    action: SignerV3AdmitReadFinalV1,
}

impl ReadCoordinatedDeliveryWitnessV1 {
    pub(in crate::native_ui) fn history(&self) -> &ReconciledAuthorityHistory {
        &self.history
    }
    pub(in crate::native_ui) fn action(&self) -> &SignerV3AdmitReadFinalV1 {
        &self.action
    }
    /// Called only after the same source's guarded read-only preparation. The
    /// nominal Read is spent before the client can be returned to custody.
    pub(in crate::native_ui) fn finish(
        self,
    ) -> Result<(CoordinatedDeliveryWitnessV1, ReconciledAuthorityHistory)> {
        actor_admit_read_result!(AdmitReadFinishCustody, &self.action, self.witness.check_custody())?;
        self.action.finish_read()?;
        Ok((self.witness, self.history))
    }
}

impl CoordinatedDeliveryWitnessV1 {
    pub(in crate::native_ui) fn read_for_admission(
        self,
        action: SignerV3AdmitReadFinalV1,
        mut check_source: impl FnMut() -> Result<()>,
    ) -> Result<ReadCoordinatedDeliveryWitnessV1> {
        #[cfg(wholepact_financial_rendered_host_semantic_ci)]
        let _observation = crate::financial_ci_actor::AdmitReadObservation::enter();
        let check = || -> Result<()> {
            actor_admit_read_detail_result!(AdmitReadWitnessCustody, self.check_custody())?;
            actor_admit_read_detail_result!(AdmitReadWitnessAction, action.check_current())?;
            actor_admit_read_detail_result!(AdmitReadWitnessPresentation, action.presentation().validate())?;
            let facts = action.facts();
            let opened = &self.opened;
            if facts.received.source_identity_digest != opened.source_identity
                || facts.received.owner_service_digest != opened.owner_service_digest
                || facts.received.prepare_read_presentation_digest
                    != opened.prepare_read_presentation_digest
                || facts.owner_selection_digest != opened.selection_digest
                || facts.owner_certificate_digest != opened.certificate_digest
                || facts.disclosure_digest
                    != actor_admit_read_detail_result!(AdmitReadWitnessDigest, wholepact_core::proposal::canonical_digest(
                        "wholepact:coordinated-v3-owner-disclosure:v1",
                        &opened.disclosure,
                    )
                    .map_err(|_| Error::InvalidData))?
                || action.original_source_deadline() != opened.original_source_deadline
                || action.original_channel_deadline() != opened.original_channel_deadline
                || action.original_service_deadline() != opened.original_service_deadline
                || action.original_material_deadline() != opened.original_material_deadline
            {
                return actor_admit_read_detail_result!(AdmitReadWitnessBinding, Err(Error::ReviewMismatch));
            }
            Ok(())
        };
        actor_admit_read_result!(AdmitReadWitnessCheck, &action, check())?;
        actor_admit_read_result!(AdmitReadSourceCallback, &action, check_source())?;
        let mut callback_error = None;
        let current = || {
            check().and_then(|_| actor_admit_read_detail_result!(AdmitReadSourceCallback, check_source())).map_err(|error| {
                if callback_error.is_none() {
                    callback_error = Some(error);
                }
                wholepact_authority::AuthorityError::Permission
            })
        };
        #[cfg(all(wholepact_financial_rendered_host_semantic_ci, feature = "synthetic-qualification"))]
        let mut history_failure = None;
        #[cfg(all(wholepact_financial_rendered_host_semantic_ci, feature = "synthetic-qualification"))]
        let result = self.opened.client.reconcile_history_diagnosed_checked_until(
            action.original_read_deadline(), current,
        ).map_err(|error| {
            history_failure = Some(crate::financial_ci_actor::admit_read_history_detail(&error));
            error.returned_error()
        });
        #[cfg(not(all(wholepact_financial_rendered_host_semantic_ci, feature = "synthetic-qualification")))]
        let result = self.opened.client.reconcile_history_checked_until(
            action.original_read_deadline(), current,
        );
        if let Some(error) = callback_error {
            return actor_admit_read_result!(AdmitReadHistoryCallback, &action, Err(error));
        }
        #[cfg(all(wholepact_financial_rendered_host_semantic_ci, feature = "synthetic-qualification"))]
        if let Some(detail) = history_failure {
            crate::financial_ci_actor::admit_read_detail_value(detail);
        }
        let history = actor_admit_read_result!(AdmitReadHistory, &action, result.map_err(|_| Error::Uncertain))?;
        actor_admit_read_result!(AdmitReadWitnessCheck, &action, check())?;
        actor_admit_read_result!(AdmitReadSourceCallback, &action, check_source())?;
        if history.disclosure() != &self.opened.disclosure {
            return actor_admit_read_result!(AdmitReadHistoryDisclosure, &action, Err(Error::Authentication));
        }
        Ok(ReadCoordinatedDeliveryWitnessV1 {
            witness: self,
            history,
            action,
        })
    }
}
