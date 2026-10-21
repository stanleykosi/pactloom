//! Nominal fresh AdmitRead checks against the same opened source and nonce map.
use super::*;
use wholepact_financial_coordinator_origin::SignerV3AdmitReadFinalV1;

impl CoordinatedPreparedDeliverySourceV1 {
    /// This is a fresh guarded read, never an INSERT or a replacement receipt.
    /// Retained metadata is checked against the original live session owner.
    pub(crate) fn check_admit_read_source(&self, action: &SignerV3AdmitReadFinalV1) -> Result<()> {
        self.check_current()?;
        action.check_current()?;
        action.presentation().validate()?;
        let received = &action.facts().received;
        if received.source_identity_digest != self.staged.source_identity()
            || received.prepare_read_presentation_digest != self.read.presentation_digest
            || action.original_source_deadline() != self.lifetime.original_source_deadline()
            || action.original_channel_deadline() != self.lifetime.original_channel_deadline()
            || action.original_material_deadline() != self.staged.original_material_deadline
            || action.original_service_deadline() != self.lifetime.original_service_deadline()
        {
            return Err(Error::ReviewMismatch);
        }
        let ready = &self.staged.source.ready;
        let source = &ready.pairing.source;
        source.retained.check()?;
        action.check_current()?;
        let pin = source.revision.as_ref().ok_or(Error::Unavailable)?;
        source
            .journal
            .check_coordinated_v3_admit_read_revision(pin, action)?;
        let lease = ready.session.acquire_construction_records(
            &source.journal,
            ready.enrollment.reference(),
            ready.manifest.reference(),
            &CoordinatedConstructionActionV1::AdmitRead(action),
        )?;
        if lease.enrollment() != &ready.enrollment || lease.manifest() != &ready.manifest {
            return Err(Error::ReviewMismatch);
        }
        lease.require_current_durable_disclosure_receipts_v1()?;
        action.check_current()?;
        drop(lease);
        source
            .journal
            .check_coordinated_v3_admit_read_revision(pin, action)?;
        self.check_current()?;
        action.check_current()?;
        Ok(())
    }
}

impl CoordinatedPreparedDeliverySourceV1 {
    /// Builds only immutable prospective DATA from the actual private source,
    /// verified mathematics and freshly authenticated original history.
    pub(crate) fn admission_scope(
        &self,
        action: &SignerV3AdmitReadFinalV1,
        economics: &crate::native_ui::durable_proposal_v1::VerifiedDurableEconomicsV1,
        intent: &crate::authority_bridge::durable_review_ipc_v3::coordinated_recipient_v1::CoordinatedRecipientIntentV1,
        history: &wholepact_authority::ReconciledAuthorityHistory,
    ) -> Result<wholepact_authority::durable_delivery_scope_v2::DurableDeliveryScopeV2> {
        use crate::native_ui::durable_proposal_v1::admission_scope_data_v1 as data;
        self.check_admit_read_source(action)?;
        if intent.digest().map_err(|_| Error::ReviewMismatch)?
            != action.facts().received.recipient_intent_digest
            || economics.verified().identity() != &intent.fixed
        {
            return Err(Error::ReviewMismatch);
        }
        let ready = &self.staged.source.ready;
        let source = &ready.pairing.source;
        let lease = ready.session.acquire_construction_records(
            &source.journal,
            ready.enrollment.reference(),
            ready.manifest.reference(),
            &CoordinatedConstructionActionV1::AdmitRead(action),
        )?;
        action.check_current()?;
        let record = &source.retained.record;
        let extension = record.extension()?;
        let account = source.retained.account.account();
        let account_id = account.account_id()?;
        let original = original(&source.retained.account)?;
        original.validate_at_rest(account)?;
        action.check_current()?;
        let policy = crate::account::birth::recipient_policy_v2::OriginalRecipientPolicyExportV2::from_retained(original)?;
        policy.validate()?;
        action.check_current()?;
        let recipient_policy_digest =
            crate::authority_bridge::validate_prepared_delivery_policy_v3(
                record,
                &policy,
                account,
                lease.enrollment(),
                lease.manifest(),
                economics.verified(),
                economics.input_actions(),
                economics.output_actions(),
            )
            .map_err(|_| Error::ReviewMismatch)?;
        let (fixed, inputs) = data::fixed_inputs(economics, &account_id)?;
        let terms = data::terms(
            &extension,
            economics,
            &account_id,
            record
                .account_record
                .genesis
                .digest()
                .map_err(|_| Error::ReviewMismatch)?,
            recipient_policy_digest,
            &fixed,
            &inputs,
            &intent.delivery,
        )?;
        if history.disclosure() != &source.witness
            || history
                .account_policy()
                .policy_digest()
                .map_err(|_| Error::ReviewMismatch)?
                != record.account_record.terms.original_policy_digest
        {
            return Err(Error::Authentication);
        }
        let scope = data::scope(
            terms,
            &extension,
            history,
            economics,
            &fixed,
            &inputs,
            lease.manifest().reference(),
            &source.witness,
            &intent.delivery,
            &intent.material_scopes,
        )?;
        lease.require_current_durable_disclosure_receipts_v1()?;
        action.check_current()?;
        drop(lease);
        self.check_admit_read_source(action)?;
        Ok(scope)
    }
}

impl CoordinatedPreparedDeliverySourceV1 {
    pub(crate) fn require_admission_journal(
        &self,
        journal: &SignerConsentJournal,
        action: &SignerV3AdmitReadFinalV1,
    ) -> Result<()> {
        self.check_admit_read_source(action)?;
        if !std::ptr::eq(
            std::sync::Arc::as_ptr(&self.staged.source.ready.pairing.source.journal),
            journal,
        ) {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(crate) fn admission_read_presentation(
        &self,
        action: &SignerV3AdmitReadFinalV1,
    ) -> Result<&SignerV3PrepareReadPresentationV1> {
        self.check_admit_read_source(action)?;
        Ok(&self.read)
    }
}

impl CoordinatedPreparedDeliverySourceV1 {
    pub(crate) fn prepare_admission_intent(
        &self,
        action: &SignerV3AdmitReadFinalV1,
        economics: &crate::native_ui::durable_proposal_v1::VerifiedDurableEconomicsV1,
        recipient: &crate::authority_bridge::durable_review_ipc_v3::coordinated_recipient_v1::CoordinatedRecipientIntentV1,
        history: &wholepact_authority::ReconciledAuthorityHistory,
    ) -> Result<crate::consent_journal::durable_delivery_admission_intent_v3::coordinated_v1::PreparedCoordinatedAdmissionIntentV1>{
        self.staged
            .source
            .ready
            .pairing
            .source
            .journal
            .prepare_coordinated_admission_intent_v1(self, action, economics, recipient, history)
            .map_err(Error::from)
    }
}

pub(crate) enum CoordinatedAdmissionSourceOutcomeV1 {
    EnteredFailed(crate::consent_journal::JournalError),
    Retained {
        record: crate::consent_journal::durable_delivery_admission_intent_v3::coordinated_v1::RetainedCoordinatedAdmissionIntentV1,
        source_uncertain: bool,
    },
}
impl CoordinatedPreparedDeliverySourceV1 {
    pub(crate) fn retain_admission_intent(
        &mut self,
        prepared: crate::consent_journal::durable_delivery_admission_intent_v3::coordinated_v1::PreparedCoordinatedAdmissionIntentV1,
        action: &wholepact_financial_coordinator_origin::SignerV3AdmitFinalV1,
        channel: &wholepact_authority::transport::AuthenticatedDurableAdmissionChannelV3<'_>,
    ) -> Result<CoordinatedAdmissionSourceOutcomeV1> {
        use crate::consent_journal::durable_delivery_admission_intent_v3::coordinated_v1::CoordinatedAdmissionRetentionV1;
        self.check_current()?;
        action.check_current()?;
        if action.facts().read.source_identity_digest != self.staged.source_identity()
            || action.original_source_deadline() != self.lifetime.original_source_deadline()
            || action.original_channel_deadline() != self.lifetime.original_channel_deadline()
            || action.original_material_deadline() != self.staged.original_material_deadline
            || action.original_service_deadline() != self.lifetime.original_service_deadline()
        {
            return Err(Error::ReviewMismatch);
        }
        let ready = &mut self.staged.source.ready;
        let source = &mut ready.pairing.source;
        source.retained.check()?;
        action.check_current()?;
        let lease = ready.session.acquire_construction_records(
            &source.journal,
            ready.enrollment.reference(),
            ready.manifest.reference(),
            &CoordinatedConstructionActionV1::Admit(action),
        )?;
        lease.require_current_durable_disclosure_receipts_v1()?;
        action.check_current()?;
        // Old revision is consumed before the sole possible effect. Never put
        // it back on error, and never auto-retry a publication or network send.
        let pin = source.revision.take().ok_or(Error::Unavailable)?;
        let outcome = source
            .journal
            .retain_coordinated_admission_intent_v1(prepared, pin, &lease, action, channel)?;
        drop(lease);
        match outcome {
            CoordinatedAdmissionRetentionV1::EnteredFailed(error) => {
                Ok(CoordinatedAdmissionSourceOutcomeV1::EnteredFailed(error))
            }
            CoordinatedAdmissionRetentionV1::Retained { record, pin } => {
                let source_uncertain = pin.is_none();
                source.revision = pin;
                // Preserve the actual result even when R became true during
                // the admitted transaction; a fresh Audit is still necessary.
                Ok(CoordinatedAdmissionSourceOutcomeV1::Retained {
                    record,
                    source_uncertain,
                })
            }
        }
    }
}

impl CoordinatedAdmissionSourceOutcomeV1 {
    pub(crate) fn retained(self) -> Result<(crate::consent_journal::durable_delivery_admission_intent_v3::coordinated_v1::RetainedCoordinatedAdmissionIntentV1, bool)>{
        match self {
            Self::EnteredFailed(error) => Err(Error::from(error)),
            Self::Retained {
                record,
                source_uncertain,
            } => Ok((record, source_uncertain)),
        }
    }
}

impl CoordinatedPreparedDeliverySourceV1 {
    /// Cached presentation DATA only, not a fresh source or owner-history read.
    pub(crate) fn cached_prepare_read(&self) -> Result<&SignerV3PrepareReadPresentationV1> {
        self.check_current()?;
        Ok(&self.read)
    }
}
