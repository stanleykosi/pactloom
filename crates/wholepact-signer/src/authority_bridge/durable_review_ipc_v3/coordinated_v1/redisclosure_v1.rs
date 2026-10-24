//! New actual coordinated disclosure, carrying the common immutable outbox
//! evidence schema. Historical rows and DTOs cannot construct this receipt.
use super::*;
use crate::authority_bridge::durable_construction_v1::{
    DurableConstructionOutboxV1, DurableConstructionRedisclosureRequestV1,
    DurableConstructionResponseV1,
};
use crate::consent_journal::TransportIdentityBinding;
use sha2::{Digest, Sha256};
pub struct AuthenticatedCoordinatedConstructionDisclosureV1 {
    outbox: DurableConstructionOutboxV1,
    endpoint: SignerV3PairEndpointV1,
}
impl AuthenticatedCoordinatedConstructionDisclosureV1 {
    pub fn outbox(&self) -> &DurableConstructionOutboxV1 {
        &self.outbox
    }
    pub fn coordinated_provider_reference(&self) -> &str {
        &self.endpoint.coordinated_provider_reference
    }
    pub fn signer_process_instance(&self) -> &str {
        &self.endpoint.signer_process_instance
    }
    pub fn source_identity_digest(&self) -> &str {
        &self.endpoint.source_identity_digest
    }
}
impl CoordinatedOriginalClientV1 {
    /// Exactly one new Redisclose request for this retained channel. On any
    /// post-attempt failure, retain the original operation; never retry mutation.
    /// The original S must independently consume fresh C Read and Redisclose.
    pub fn redisclose_durable_construction_v1(
        &mut self,
        request: DurableConstructionRedisclosureRequestV1,
    ) -> Result<AuthenticatedCoordinatedConstructionDisclosureV1> {
        self.check_current()?;
        request.validate()?;
        if self.redisclosure_attempt.is_some() {
            return Err(BridgeError::Permission);
        }
        self.redisclosure_attempt = Some(request.operation_id.clone());
        let wait = self.deadline.min(Instant::now() + Duration::from_secs(120));
        let stream = self.open_request(
            &CoordinatedAppRequestV1::Redisclosure {
                request: Box::new(request.clone()),
            },
            wait,
        )?;
        let bytes = self.read_metadata(&stream, 128 * 1024, wait)?;
        let response: DurableConstructionResponseV1 =
            wholepact_core::strict_json::parse_typed_json_with_byte_limit(&bytes, 128 * 1024)
                .map_err(|_| BridgeError::Binding)?;
        let DurableConstructionResponseV1::Retained { outbox } = response else {
            return Err(BridgeError::Permission);
        };
        outbox.validate()?;
        self.verify_coordinated_recipient(outbox.recipient_transport())?;
        let link = outbox.redisclosure().ok_or(BridgeError::Binding)?;
        if outbox.request().operation_id != request.operation_id
            || link.original_operation_id != request.original.operation_id
            || request
                .original
                .expected_request_digest
                .as_ref()
                .is_some_and(|expected| expected != &link.original_request_digest)
            || outbox.request().enrollment_ref != request.enrollment_ref
            || outbox.request().accepted_manifest_ref != request.accepted_manifest_ref
            || outbox.request().scope.account_id != self.scope.account_id
        {
            return Err(BridgeError::Binding);
        }
        self.check_stream(&stream)?;
        Ok(AuthenticatedCoordinatedConstructionDisclosureV1 {
            outbox: *outbox,
            endpoint: self.endpoint.clone(),
        })
    }
    pub fn redisclosure_attempted_operation(&self) -> Option<&str> {
        self.redisclosure_attempt.as_deref()
    }
    fn verify_coordinated_recipient(&self, binding: &TransportIdentityBinding) -> Result<()> {
        self.check_current()?;
        let TransportIdentityBinding::LocalProcess {
            transport_identity_id,
            channel_key_digest,
            channel_binding_digest,
            uid,
            pid,
            process_instance,
            signer_generation,
            account_id,
            agreement_id,
            participant_id,
            manifest_digest,
        } = binding
        else {
            return Err(BridgeError::Binding);
        };
        let token =
            Zeroizing::new(hex::decode(self.token.as_str()).map_err(|_| BridgeError::Binding)?);
        let key_digest = hex::encode(Sha256::digest(token.as_slice()));
        if transport_identity_id != &self.grant_id
            || channel_key_digest != &key_digest
            || channel_binding_digest != &self.channel_digest
            || process_instance != &self.original_host_process_instance
            || *uid != unsafe { libc::geteuid() }
            || *pid != std::process::id()
            || *signer_generation != 1
            || account_id != &self.scope.account_id
            || agreement_id != &self.scope.agreement_id
            || participant_id != &self.scope.participant_id
            || manifest_digest != &self.scope.manifest_digest
        {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
}
