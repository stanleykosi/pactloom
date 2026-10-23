//! Captures inert financial originals only while actual fresh Audit permits reads.
//! Completion/lifetime/currentness never opens files or private journal rows.
use super::*;
use crate::account::birth::enrollment::roster_v2::durable_entry_v1::OriginalFinancialReentrySelectionV1;
use crate::authority_bridge::durable_review_ipc_v3::coordinated_recipient_v1::CoordinatedRecipientIntentV1;
use crate::consent_journal::durable_delivery_admission_intent_v3::coordinated_v1::RetainedCoordinatedAdmissionIntentV1;
use wholepact_authority::durable_financial_continuation_v1::{FinancialContinuationTermsV1,original_delivery_request_digest_v1};
use wholepact_financial_coordinator_origin::SignerV3AuditFinalV1;

impl CoordinatedPreparedDeliverySourceV1 {
    pub(crate) fn capture_financial_selection_under_audit(
        &self, action: &SignerV3AuditFinalV1, terms: &FinancialContinuationTermsV1,
        intent: &CoordinatedRecipientIntentV1, retained: &RetainedCoordinatedAdmissionIntentV1,
    ) -> Result<OriginalFinancialReentrySelectionV1> {
        self.check_current()?;
        action.check_current()?;
        action.presentation().validate()?;
        terms.require_live(wall_ms()?).map_err(|_|Error::Locked)?;
        let ready=&self.custody.staged.source.ready;
        let source=&ready.pairing.source;
        let wholepact_authority::OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &retained.request().control
            else { return Err(Error::ReviewMismatch); };
        if action.facts().received.source_identity_digest != self.custody.staged.source_identity()
            || action.facts().received.prepare_read_presentation_digest != self.read.presentation_digest
            || action.original_source_deadline() != self.original_source_deadline()
            || action.original_channel_deadline() != self.original_channel_deadline()
            || action.original_material_deadline() != self.original_material_deadline()
            || action.original_service_deadline() != self.custody.lifetime.original_service_deadline()
            || intent != retained.recipient_intent()
            || terms.scope != record.scope
            || terms.original_delivery_operation_id != retained.request().operation_id
            || terms.original_delivery_request_digest != original_delivery_request_digest_v1(retained.request()).map_err(|_|Error::ReviewMismatch)?
            || terms.original_local_intent_digest != retained.history_digest()?
            || terms.original_recipient_intent_digest != retained.recipient_intent_digest()?
            || terms.original_recipient_enrollment_ref != ready.enrollment.reference()
            || terms.original_recipient_manifest_ref != ready.manifest.reference()
            || retained.enrollment_ref() != ready.enrollment.reference()
            || retained.manifest_ref() != ready.manifest.reference()
            || retained.disclosure() != &source.witness
            || retained.owner_certificate_digest() != source.retained.record.account_record.genesis.owner_certificate_digest
        { return Err(Error::ReviewMismatch); }
        source.host.check_alive()?;
        ready.session.require_accepted_provenance(&ready.accepted,&ready.enrollment,&ready.manifest)?;
        action.check_current()?;
        source.retained.check()?;
        if publication::read_commit(&source.retained)? != source.original_commit
            || immutable_files(&source.retained)? != source.immutable
        { return Err(Error::ReviewMismatch); }
        action.check_current()?;
        let binding=source.journal.prepare_coordinated_v3_audit_source_binding_v1(
            &source.retained.record.account_record.genesis,
            self.custody.staged.source_identity(),retained,action,
        )?;
        let selected=OriginalFinancialReentrySelectionV1::capture_coordinated_under_audit_v1(
            &source.retained,&binding,terms,intent,self.custody.staged.source_identity(),&source.host,action,
        )?;
        // This observer reads only the existing identity/revision pin, never
        // replays the private audit after its genuine purpose has ended.
        source.journal.check_coordinated_public_pin_v2(&binding)?;
        self.check_current()?;
        action.check_current()?;
        Ok(selected)
    }
}

impl CoordinatedPreparedDeliverySourceV1 {
    /// Pure cached configuration observation; it carries no credential/client
    /// and the later financial private read still needs its own genuine Final.
    pub(crate) fn original_owner_setup_json(&self)->&str { &self.read.facts.owner_setup_json }

    pub(crate) fn into_financial_role_transport(
        self,completed:wholepact_financial_coordinator_origin::SignerV3CompletedLifetimeV1,
    )->Result<(super::super::coordinated_pairing_v1::CoordinatedFinancialRoleTransportV1,crate::native_peer::PeerProcess)> {
        self.check_current()?;
        completed.check_current()?;
        if completed.source_identity_digest()!=self.source_identity()
            || completed.original_source_deadline()!=self.original_source_deadline()
            || completed.original_channel_deadline()!=self.original_channel_deadline()
            || completed.original_material_deadline()!=self.original_material_deadline()
            || completed.original_service_deadline()!=self.custody.lifetime.original_service_deadline()
        {return Err(Error::ReviewMismatch);}
        let ready=self.custody.staged.source.ready;
        let (transport,host)=ready.pairing.into_financial_role_transport(completed)?;
        transport.require_peer(&ready.peer)?;
        // Dropping this original nonce map cannot revoke the still-retained
        // genuine Pair registry. It only ends old preconstruction permissions.
        drop(ready.session);
        drop(ready.peer);
        host.check_alive()?;
        transport.check_current()?;
        Ok((transport,host))
    }
}
