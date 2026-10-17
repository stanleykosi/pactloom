//! Pure completed-checkpoint projection. No raw sealing or authority conversion.
use super::*;
use wholepact_authority::born_offline_checkpoint_origin_v1::BornOfflineCheckpointOriginV1;
pub const BORN_OFFLINE_CHECKPOINT_ORIGIN_FIELD_V1: &str = "born-offline-checkpoint-origin-v1";
pub fn born_offline_checkpoint_context_v1(
    origin: &BornOfflineCheckpointOriginV1,
) -> Result<MessageContext> {
    origin
        .validate()
        .map_err(|_| TransportError::WrongContext)?;
    Ok(MessageContext {
        network_profile_id: origin.network_profile_id.clone(),
        agreement_id: origin.agreement_id.clone(),
        proposal_id: origin.proposal_id.clone(),
        proposal_revision: origin.proposal_revision,
        sender_id: format!("born-offline-checkpoint:{}", origin.host_return_key_digest),
        recipient_id: format!("born-offline-checkpoint:{}", origin.signer_key_digest),
        artifact_kind: ArtifactKind::BornOfflineCheckpointOriginV1,
    })
}
pub fn born_offline_checkpoint_fields_v1(
    origin: &BornOfflineCheckpointOriginV1,
) -> Result<Vec<DisclosureField>> {
    origin
        .validate()
        .map_err(|_| TransportError::WrongContext)?;
    Ok(vec![DisclosureField::new(
        BORN_OFFLINE_CHECKPOINT_ORIGIN_FIELD_V1,
        serde_json::to_vec(origin).map_err(|_| TransportError::Malformed)?,
    )?])
}
