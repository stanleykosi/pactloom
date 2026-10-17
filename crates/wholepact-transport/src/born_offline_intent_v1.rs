//! Pure projection of the COMPLETE born request. No sealer or approval factory.
use super::*;
use wholepact_authority::born_offline_admission_v1::BornOfflineReservationRequestV1;
pub const BORN_OFFLINE_INTENT_FIELD_V1: &str = "born-offline-reservation-intent-v1";
pub fn born_offline_intent_context_v1(
    request: &BornOfflineReservationRequestV1,
) -> Result<MessageContext> {
    request
        .validate()
        .map_err(|_| TransportError::WrongContext)?;
    let t = &request.reservation.intent.terms;
    Ok(MessageContext {
        network_profile_id: t.network_profile_id.clone(),
        agreement_id: t.agreement_id.clone(),
        proposal_id: t.proposal_id.clone(),
        proposal_revision: t.proposal_revision,
        sender_id: format!("born-offline-intent:{}", t.offline_signer_key_digest),
        recipient_id: format!("born-offline-intent:{}", t.offline_policy_digest),
        artifact_kind: ArtifactKind::BornOfflineIntentV1,
    })
}
pub fn born_offline_intent_fields_v1(
    request: &BornOfflineReservationRequestV1,
    header: &NamedReviewBindingV1,
) -> Result<Vec<DisclosureField>> {
    request
        .validate()
        .map_err(|_| TransportError::WrongContext)?;
    header.validate()?;
    if header.review_package_digest()? != request.reservation.intent.terms.review_package_digest {
        return Err(TransportError::WrongContext);
    }
    Ok(vec![
        DisclosureField::new(
            BORN_OFFLINE_INTENT_FIELD_V1,
            serde_json::to_vec(request).map_err(|_| TransportError::Malformed)?,
        )?,
        DisclosureField::new(NAMED_REVIEW_BINDING_FIELD_V1, header.canonical_bytes()?)?,
    ])
}
