//! Ordinary exact coordinated recipient description, never channel/Read authority.
//! Distinct provider namespace; no legacy native enrollment relabeling.
use super::coordinated_v1::CoordinatedPrepareClosedRecipientRequestV1;
use super::*;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatedRecipientIntentV1 {
    pub version: u16,
    pub request: DurableReviewDeliveryRequestV1,
    pub fixed: FixedProposalIdentityV1,
    pub payload_digest: String,
    pub payload_bytes: u64,
    pub delivery: DurableDeliveryPlanV2,
    pub material_scopes: Vec<DurableDeliveryMaterialScopeRefV2>,
    pub account_id: String,
    pub participant_id: String,
    pub agreement_id: String,
    pub manifest_digest: String,
    pub coordinated_provider_reference: String,
    pub signer_process_instance: String,
    pub authorized_host_process_instance: String,
    pub source_identity_digest: String,
    pub source_generation: u64,
    pub read_session_digest: String,
    pub receive_decision_digest: String,
    pub original_enrollment_ref: String,
    pub original_manifest_ref: String,
}
impl CoordinatedRecipientIntentV1 {
    pub fn validate(&self) -> Result<()> {
        self.preparation().validate()?;
        for value in [
            &self.manifest_digest,
            &self.authorized_host_process_instance,
            &self.source_identity_digest,
            &self.read_session_digest,
            &self.receive_decision_digest,
            &self.original_enrollment_ref,
            &self.original_manifest_ref,
        ] {
            crate::authority_bridge::durable_construction_v1::hash(value)?;
        }
        for value in [&self.account_id, &self.participant_id, &self.agreement_id] {
            crate::review::validate_label(value).map_err(|_| BridgeError::Binding)?;
        }
        if self.version != 1
            || self.source_generation != 1
            || self.fixed.agreement_id != self.agreement_id
            || self.fixed.manifest_digest != self.manifest_digest
            || self.original_enrollment_ref != self.request.enrollment_ref
            || self.original_manifest_ref != self.request.accepted_manifest_ref
            || !self.delivery.owners.iter().any(|owner| {
                owner.account_id == self.account_id && owner.participant_id == self.participant_id
            })
        {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        wholepact_core::proposal::canonical_digest(
            "wholepact:coordinated-recipient-intent:v1",
            self,
        )
        .map_err(|_| BridgeError::Binding)
    }
    pub fn preparation(&self) -> CoordinatedPrepareClosedRecipientRequestV1 {
        CoordinatedPrepareClosedRecipientRequestV1 {
            version: 1,
            request: self.request.clone(),
            fixed: self.fixed.clone(),
            payload_digest: self.payload_digest.clone(),
            payload_bytes: self.payload_bytes,
            delivery: self.delivery.clone(),
            material_scopes: self.material_scopes.clone(),
            coordinated_provider_reference: self.coordinated_provider_reference.clone(),
            signer_process_instance: self.signer_process_instance.clone(),
        }
    }
}
