//! Actual configured mTLS writer client. No caller can supply its session key,
//! TLS peer or exporter, and no returned metadata becomes signing authority.
use super::*;
use crate::offline::ReserveOfflineAuthorization;
use crate::offline_witness_v1::*;

impl AuthorityClient {
    pub fn submit_offline_intent_v1(
        &self,
        request: ReserveOfflineAuthorization,
        original_envelope: &[u8],
        export_template: OfflineAdmissionExportPlan,
        deadline: Instant,
    ) -> Result<OfflineAdmissionDeliveryV1> {
        let lookup = OfflineAdmissionDeliveryLookupV1::from_request(&request)?;
        self.check_offline_delivery_scope_v1(&lookup)?;
        crate::validate_offline_intent_delivery_size_v1(
            &request,
            original_envelope,
            &export_template,
        )?;
        let state = self
            .session
            .lock()
            .map_err(|_| AuthorityError::SessionRequired)?;
        let session = state
            .as_ref()
            .filter(|s| s.receipt.is_some())
            .ok_or(AuthorityError::SessionRequired)?;
        let response = self.call_with_until(deadline, |exporter| {
            let mut wire = OfflineWitnessRequestV1 {
                request: request.clone(),
                original_envelope_hex: hex::encode(original_envelope),
                export_template: export_template.clone(),
                proof: protocol::WriterSessionProof {
                    session_id: String::new(),
                    tag: String::new(),
                },
            };
            let mutation = AuthorityMutation::ReserveOfflineAuthorization(Box::new(wire.record()?));
            wire.proof = crate::session::proof(
                &session.key,
                (
                    &session.request.session_id,
                    &session.request.disclosure,
                    session.request.writer_epoch,
                ),
                exporter,
                &mutation,
            )?;
            Ok(WireRequest::SubmitOfflineIntentV1(Box::new(wire)))
        })?;
        let delivery = self.check_offline_delivery_v1(response, &lookup)?;
        let mut expected_plan = export_template;
        expected_plan.sequence = delivery.body.export_plan.sequence;
        if delivery.body.export_plan != expected_plan
            || delivery.body.authorization_id != request.intent.terms.authorization_id
            || delivery.body.admission_expires_at_ms != request.admission_expires_at_ms
            || delivery.body.reserved_at_ms < request.requested_at_ms
        {
            return Err(AuthorityError::Authentication);
        }
        Ok(delivery)
    }

    /// Read only the original committed encrypted delivery. This cannot insert an
    /// outbox row, reseal, reserve exposure, replace a head or renew any deadline.
    pub fn recover_offline_admission_delivery_v1(
        &self,
        original: OfflineAdmissionDeliveryLookupV1,
        deadline: Instant,
    ) -> Result<OfflineAdmissionDeliveryV1> {
        self.check_offline_delivery_scope_v1(&original)?;
        let response = self.call_until(
            &WireRequest::RecoverOfflineAdmissionDeliveryV1(original.clone()),
            deadline,
        )?;
        let delivery = self.check_offline_delivery_v1(response, &original)?;
        if !delivery.body.recovered_original {
            return Err(AuthorityError::Authentication);
        }
        Ok(delivery)
    }

    fn check_offline_delivery_scope_v1(
        &self,
        original: &OfflineAdmissionDeliveryLookupV1,
    ) -> Result<()> {
        original.validate()?;
        if original.account_id != self.account || original.network_profile_id != self.network {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    fn check_offline_delivery_v1(
        &self,
        response: WireResponse,
        original: &OfflineAdmissionDeliveryLookupV1,
    ) -> Result<OfflineAdmissionDeliveryV1> {
        let WireResponse::OfflineAdmissionDeliveryV1(body) = response else {
            return Err(AuthorityError::Authentication);
        };
        let ciphertext = body.validate()?;
        if body.original != *original
            || body.witness_id != self.witness
            || body.witness_account_policy_digest != self.policy_digest
        {
            return Err(AuthorityError::Authentication);
        }
        Ok(OfflineAdmissionDeliveryV1 {
            body: *body,
            ciphertext,
        })
    }
}

impl AuthorityServer {
    /// Select an explicitly configured independent legacy witness owner. Existing
    /// owner-mTLS enrollment must already pin the keys. Born accounts and the
    /// dedicated construction server remain unavailable through this composition.
    #[cfg(all(feature = "offline-witness-owner", target_os = "linux"))]
    pub fn with_offline_witness_v1(
        mut self,
        configuration: crate::OfflineWitnessConfigurationV1,
    ) -> Result<Self> {
        if self.handoff_scope.is_some()
            || self.offline_witness.is_some()
            || self.is_born_offline_server_v1()
        {
            return Err(AuthorityError::Permission);
        }
        let owner =
            crate::offline_admission::configured_witness::ConfiguredOfflineWitnessV1::configure(
                self.journal.clone(),
                &self.tls.certificate_digest,
                configuration,
            )?;
        self.offline_witness = Some(Arc::new(std::sync::Mutex::new(owner)));
        Ok(self)
    }

    pub(super) fn serve_offline_intent_v1(
        &self,
        peer: &str,
        exporter: &[u8; 32],
        request: &OfflineWitnessRequestV1,
        deadline: Instant,
    ) -> Result<WireResponse> {
        #[cfg(all(feature = "offline-witness-owner", target_os = "linux"))]
        {
            let owner = self
                .offline_witness
                .as_ref()
                .ok_or(AuthorityError::Permission)?;
            let mut owner = owner.lock().map_err(|_| AuthorityError::Storage)?;
            owner
                .submit(
                    peer,
                    exporter,
                    &self.tls.certificate_digest,
                    request,
                    deadline,
                )
                .map(|body| WireResponse::OfflineAdmissionDeliveryV1(Box::new(body)))
        }
        #[cfg(not(all(feature = "offline-witness-owner", target_os = "linux")))]
        {
            let _ = (peer, exporter, request, deadline);
            Err(AuthorityError::Permission)
        }
    }
    pub(super) fn serve_offline_delivery_recovery_v1(
        &self,
        peer: &str,
        original: &OfflineAdmissionDeliveryLookupV1,
        deadline: Instant,
    ) -> Result<WireResponse> {
        #[cfg(all(feature = "offline-witness-owner", target_os = "linux"))]
        {
            let owner = self
                .offline_witness
                .as_ref()
                .ok_or(AuthorityError::Permission)?;
            let owner = owner.lock().map_err(|_| AuthorityError::Storage)?;
            owner
                .recover(peer, original, deadline)
                .map(|body| WireResponse::OfflineAdmissionDeliveryV1(Box::new(body)))
        }
        #[cfg(not(all(feature = "offline-witness-owner", target_os = "linux")))]
        {
            let _ = (peer, original, deadline);
            Err(AuthorityError::Permission)
        }
    }
}

#[cfg(all(test, feature = "offline-witness-owner", target_os = "linux"))]
#[path = "offline_witness_v1_tests.rs"]
mod tests;
