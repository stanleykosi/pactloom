//! One fresh nominal Audit over the retained actual original owner client.
use super::*;
use wholepact_financial_coordinator_origin::SignerV3AuditFinalV1;

/// The consumed Read owner is retained until the same source has checked the
/// exact original retained local admission. No second history-read method exists.
pub(in crate::native_ui) struct ReadCoordinatedAuditWitnessV1 {
    witness: CoordinatedDeliveryWitnessV1,
    history: ReconciledAuthorityHistory,
    action: SignerV3AuditFinalV1,
}

impl ReadCoordinatedAuditWitnessV1 {
    pub(in crate::native_ui) fn history(&self) -> &ReconciledAuthorityHistory {
        &self.history
    }
    pub(in crate::native_ui) fn action(&self) -> &SignerV3AuditFinalV1 {
        &self.action
    }
    /// Called only after the same source's guarded read-only preparation. The
    /// nominal Audit Read is spent before the client returns. The denial-only
    /// lifetime is not completed custody; exact original report is still required.
    pub(in crate::native_ui) fn finish(
        self,
    ) -> Result<(
        CoordinatedDeliveryWitnessV1,
        ReconciledAuthorityHistory,
        wholepact_financial_coordinator_origin::SignerV3CompletedLifetimeV1,
    )> {
        self.witness.check_custody()?;
        let lifetime = self.action.finish_audit()?;
        Ok((self.witness, self.history, lifetime))
    }
}

impl CoordinatedDeliveryWitnessV1 {
    pub(in crate::native_ui) fn read_for_audit(
        self,
        action: SignerV3AuditFinalV1,
        mut check_source: impl FnMut() -> Result<()>,
    ) -> Result<ReadCoordinatedAuditWitnessV1> {
        let check = || -> Result<()> {
            self.check_custody()?;
            action.check_current()?;
            action.presentation().validate()?;
            let facts = action.facts();
            let opened = &self.opened;
            if facts.received.source_identity_digest != opened.source_identity
                || facts.received.owner_service_digest != opened.owner_service_digest
                || facts.received.prepare_read_presentation_digest
                    != opened.prepare_read_presentation_digest
                || facts.owner_selection_digest != opened.selection_digest
                || facts.owner_certificate_digest != opened.certificate_digest
                || facts.disclosure_digest
                    != wholepact_core::proposal::canonical_digest(
                        "wholepact:coordinated-v3-owner-disclosure:v1",
                        &opened.disclosure,
                    )
                    .map_err(|_| Error::InvalidData)?
                || action.original_source_deadline() != opened.original_source_deadline
                || action.original_channel_deadline() != opened.original_channel_deadline
                || action.original_service_deadline() != opened.original_service_deadline
                || action.original_material_deadline() != opened.original_material_deadline
            {
                return Err(Error::ReviewMismatch);
            }
            Ok(())
        };
        check()?;
        check_source()?;
        let mut callback_error = None;
        let result = self.opened.client.reconcile_history_checked_until(
            action.original_read_deadline(),
            || {
                check().and_then(|_| check_source()).map_err(|error| {
                    if callback_error.is_none() {
                        callback_error = Some(error);
                    }
                    wholepact_authority::AuthorityError::Permission
                })
            },
        );
        if let Some(error) = callback_error {
            return Err(error);
        }
        let history = result.map_err(|_| Error::Uncertain)?;
        check()?;
        check_source()?;
        if history.disclosure() != &self.opened.disclosure {
            return Err(Error::Authentication);
        }
        Ok(ReadCoordinatedAuditWitnessV1 {
            witness: self,
            history,
            action,
        })
    }
}
