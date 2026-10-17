//! Actual completed-checkpoint and complete-history validation of a purpose-
//! distinct authenticated born return. This never grants current-chain or
//! dispatch authority. No imported expected policy, indices or completion flag.
use super::born_offline_checkpoint_carrier_v1::{RetainedBornOfflineCheckpointCarrierV1, codec};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use wholepact_authority::born_offline_admission_v1::BornOfflineAuthorizationAdmissionV1;
use wholepact_protocol::{
    authorization::ExternalSignature,
    own_effects::{OwnEffectsPolicy, OwnInputExpectation, OwnOutputExpectation, OwnOutputPurpose},
    review::OutputPurpose,
};
use wholepact_signer::authority_bridge::born_history_ipc::BornOriginalHistoryLeaseV1;
use zeroize::Zeroize;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReturnPayload {
    schema_version: u16,
    account_id: String,
    authorization_id: String,
    original_consent_ref: String,
    native_review_digest: String,
    admission_request_digest: String,
    intent_digest: String,
    terms_digest: String,
    review_package_digest: String,
    reviewed_artifact_digest: String,
    online_proved_artifact_digest: String,
    manifest_digest: String,
    effects_digest: String,
    review_binding: String,
    signed_artifact_digest: String,
    signatures: Vec<Signature>,
    born_origin_digest: String,
    born_enrollment_digest: String,
    born_artifact_binding_digest: String,
    born_admission_digest: String,
    inner_reservation_request_digest: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Signature {
    action_index: u64,
    signature_hex: String,
}
impl Drop for Signature {
    fn drop(&mut self) {
        self.signature_hex.zeroize();
    }
}

/// Private facts from actual HPKE authentication, exact history and maintained
/// signature verification. Native retention and current dispatch remain separate.
pub(super) struct VerifiedBornReturnV1 {
    pub(super) admission: BornOfflineAuthorizationAdmissionV1,
    pub(super) signatures: Vec<ExternalSignature>,
    pub(super) payload_digest: String,
    pub(super) origin_identifier: String,
    pub(super) consent_identifier: String,
    pub(super) signed_canonical_digest: String,
}
impl Drop for VerifiedBornReturnV1 {
    fn drop(&mut self) {
        for s in &mut self.signatures {
            s.signature.zeroize();
        }
    }
}

pub(super) fn inspect(
    retained: &RetainedBornOfflineCheckpointCarrierV1<'_, '_>,
    history: &BornOriginalHistoryLeaseV1<'_>,
    artifact: &codec::ReceivedArtifact,
) -> Result<VerifiedBornReturnV1> {
    retained.check_current()?;
    history.check_current().map_err(|_| Error::Permission)?;
    let evidence = history.evidence();
    let checkpoint = retained.original().checkpoint();
    let origin = retained.origin();
    if artifact.fields().len() != 1
        || artifact.fields()[0].name() != "born-offline-authorization-return-v1"
        || artifact.fields()[0].bytes().len() > 16_384
    {
        return Err(Error::Authentication);
    }
    let raw = artifact.fields()[0].bytes();
    let payload: ReturnPayload =
        wholepact_core::parse_typed_json(raw).map_err(|_| Error::Authentication)?;
    if serde_json::to_vec(&payload)? != raw
        || payload.schema_version != 1
        || payload.signatures.is_empty()
        || payload.signatures.len() > 64
    {
        return Err(Error::Authentication);
    }
    for h in [
        &payload.original_consent_ref,
        &payload.native_review_digest,
        &payload.admission_request_digest,
        &payload.intent_digest,
        &payload.terms_digest,
        &payload.review_package_digest,
        &payload.reviewed_artifact_digest,
        &payload.online_proved_artifact_digest,
        &payload.manifest_digest,
        &payload.effects_digest,
        &payload.review_binding,
        &payload.signed_artifact_digest,
        &payload.born_origin_digest,
        &payload.born_enrollment_digest,
        &payload.born_artifact_binding_digest,
        &payload.born_admission_digest,
        &payload.inner_reservation_request_digest,
    ] {
        hash(h)?;
    }
    // Find by the complete actual history's exact original request, never by an
    // imported descriptor or a detached consent/identifier copied into a file.
    let admission = &evidence.admission;
    let request = &admission.request;
    let terms = &request.reservation.intent.terms;
    // Exact actual historical snapshot remains part of the admitted request.
    // A signed return cannot substitute another source/time or backfill legacy
    // absence. Historical provenance is not fresh spendability authority.
    origin
        .validate_snapshot_terms(terms)
        .map_err(|_| Error::Authentication)?;
    if terms.authorization_id != payload.authorization_id
        || evidence.original_ref != payload.original_consent_ref
        || evidence.born_origin_digest != payload.born_origin_digest
        || evidence.retained_final_native_review_digest != payload.native_review_digest
    {
        return Err(Error::Authentication);
    }
    admission
        .validate_reserved_policy_bounds(
            &evidence.account_policy,
            &evidence.enrollment.enrollment,
            &evidence.artifacts,
            &evidence.manual_extension,
        )
        .map_err(|_| Error::Authentication)?;
    let construction = &evidence.construction;
    origin
        .validate_for_link(&request.construction_link)
        .map_err(|_| Error::Authentication)?;
    origin
        .validate_for_origin(&construction)
        .map_err(|_| Error::Authentication)?;
    request
        .construction_link
        .validate_for(&construction, &request.reservation)
        .map_err(|_| Error::Authentication)?;
    let preview = artifact.preview();
    let start = milliseconds(preview.order.issued_at.unix_seconds())?;
    let end = milliseconds(preview.order.expires_at.unix_seconds())?;
    let expected_context = codec::MessageContext {
        network_profile_id: terms.network_profile_id.clone(),
        agreement_id: terms.agreement_id.clone(),
        proposal_id: terms.proposal_id.clone(),
        proposal_revision: terms.proposal_revision,
        sender_id: format!("born-offline-return:{}", terms.offline_signer_key_digest),
        recipient_id: format!("born-offline-return:{}", terms.return_recipient_key_digest),
        artifact_kind: codec::ArtifactKind::BornOfflineAuthorizationReturnV1,
    };
    if preview.context != expected_context
        || preview.purpose != "Exact own signatures for the original named-mode authorization"
        || preview.persistence_warning
            != "This encrypted return can outlive local revocation; online current validation remains required."
        || start < admission.reserved.reserved_at_ms / 1000 * 1000
        || end > request.reservation.admission_expires_at_ms
        || end <= start
        || payload.account_id != origin.account_id
        || terms.account_id != origin.account_id
        || terms.offline_signer_key_digest != origin.signer_key_digest
        || terms.return_recipient_key_digest != origin.host_return_key_digest
        || payload.admission_request_digest
            != request
                .request_digest()
                .map_err(|_| Error::Authentication)?
        || payload.inner_reservation_request_digest
            != request
                .reservation
                .request_digest()
                .map_err(|_| Error::Authentication)?
        || payload.born_admission_digest
            != admission
                .admission_digest()
                .map_err(|_| Error::Authentication)?
        || payload.born_enrollment_digest != request.enrollment_digest
        || payload.born_artifact_binding_digest != request.artifact_binding_digest
        || payload.intent_digest
            != request
                .reservation
                .intent
                .intent_digest()
                .map_err(|_| Error::Authentication)?
        || payload.terms_digest != terms.terms_digest().map_err(|_| Error::Authentication)?
        || payload.review_package_digest != terms.review_package_digest
        || payload.online_proved_artifact_digest != terms.artifact_digest
        || payload.online_proved_artifact_digest != origin.proved_artifact_digest
        || payload.manifest_digest != origin.manifest_digest
        || payload.manifest_digest != terms.manifest_digest
        || payload.effects_digest != origin.effects_commitment
        || payload.effects_digest != terms.effects_digest
        || payload.review_binding != origin.review_binding
        || payload.review_binding != terms.review_binding
        || checkpoint.summary().result_digest.as_deref()
            != Some(origin.proved_artifact_digest.as_str())
        || hex::encode(Sha256::digest(checkpoint.pczt_bytes())) != origin.proved_artifact_digest
    {
        return Err(Error::Authentication);
    }
    let policy = checkpoint.policy();
    let owner = policy
        .participants
        .iter()
        .position(|p| p.account_id == origin.account_id)
        .ok_or(Error::Authentication)?;
    let participant = &policy.participants[owner];
    if hex::encode(Sha256::digest(participant.fvk.to_bytes())) != origin.full_viewing_key_digest {
        return Err(Error::Authentication);
    }
    let expected: BTreeSet<_> = policy
        .inputs
        .iter()
        .filter(|i| i.participant_index == owner)
        .map(|i| {
            (
                i.action_index as u64,
                hex::encode(i.nullifier),
                i.value_zatoshis,
            )
        })
        .collect();
    let admitted: BTreeSet<_> = terms
        .inputs
        .iter()
        .map(|i| (i.action_index, i.nullifier.clone(), i.value_zatoshis))
        .collect();
    let indices: BTreeSet<_> = payload.signatures.iter().map(|s| s.action_index).collect();
    if expected != admitted
        || expected.len() != terms.inputs.len()
        || indices.len() != payload.signatures.len()
        || indices != expected.iter().map(|(i, _, _)| *i).collect()
    {
        return Err(Error::Authentication);
    }
    let own = OwnEffectsPolicy {
        account_id: participant.account_id.clone(),
        own_fvk: participant.fvk.clone(),
        manifest_digest: policy.manifest_digest,
        anchor: policy.anchor,
        expiry_height: policy.expiry_height,
        maximum_selected_net_debit_zatoshis: participant.maximum_net_debit_zatoshis,
        exact_selected_net_debit_zatoshis: participant
            .contribution_zatoshis
            .checked_add(participant.fee_share_zatoshis)
            .ok_or(Error::Invalid)?,
        declared_fee_share_zatoshis: participant.fee_share_zatoshis,
        exact_transaction_fee_zatoshis: policy.exact_fee_zatoshis,
        own_inputs: policy
            .inputs
            .iter()
            .filter(|i| i.participant_index == owner)
            .map(|i| OwnInputExpectation {
                action_index: i.action_index,
                nullifier: i.nullifier,
                value_zatoshis: i.value_zatoshis,
            })
            .collect(),
        outputs: policy
            .outputs
            .iter()
            .map(|o| OwnOutputExpectation {
                action_index: o.action_index,
                receiver: o.receiver,
                value_zatoshis: o.value_zatoshis,
                memo: o.memo,
                purpose: match o.purpose {
                    OutputPurpose::Recipient => OwnOutputPurpose::Recipient,
                    OutputPurpose::Return { participant_index } if participant_index == owner => {
                        OwnOutputPurpose::OwnReturn
                    }
                    _ => OwnOutputPurpose::PeerReturnUnverified,
                },
            })
            .collect(),
    };
    if own.maximum_selected_net_debit_zatoshis != terms.maximum_debit_zatoshis
        || own.declared_fee_share_zatoshis != terms.fee_share_zatoshis
        || own.exact_transaction_fee_zatoshis != terms.transaction_fee_zatoshis
        || own.expiry_height != terms.transaction_expiry_height
    {
        return Err(Error::Authentication);
    }
    let layout = wholepact_protocol::canonical_role_layout::produce_canonical_layout(
        checkpoint.pczt_bytes(),
        policy,
    )
    .map_err(|_| Error::Authentication)?;
    require_artifact_roles(
        &layout,
        &terms.artifact_digest,
        &payload.online_proved_artifact_digest,
        &origin.proved_artifact_digest,
        &payload.reviewed_artifact_digest,
    )?;
    let own_inspection = wholepact_protocol::own_effects::verify_own_effects(layout.bytes(), &own)
        .map_err(|_| Error::Authentication)?;
    let parsed = pczt::Pczt::parse(layout.bytes()).map_err(|_| Error::Authentication)?;
    let mut signer = pczt::roles::signer::Signer::new(parsed).map_err(|_| Error::Authentication)?;
    let mut signatures = Vec::with_capacity(payload.signatures.len());
    for signature in &payload.signatures {
        if signature.signature_hex.len() != 128
            || !signature
                .signature_hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::Authentication);
        }
        let mut bytes = [0u8; 64];
        hex::decode_to_slice(&signature.signature_hex, &mut bytes)
            .map_err(|_| Error::Authentication)?;
        let action_index = usize::try_from(signature.action_index).map_err(|_| Error::Invalid)?;
        signer
            .apply_ironwood_signature(action_index, bytes.into())
            .map_err(|_| Error::Authentication)?;
        signatures.push(ExternalSignature {
            participant_index: owner,
            action_index,
            signature: bytes,
        });
    }
    let signed = zeroize::Zeroizing::new(
        pczt::v2::Pczt::try_from(signer.finish())
            .map_err(|_| Error::Authentication)?
            .serialize(),
    );
    if hex::encode(Sha256::digest(signed.as_slice())) != payload.signed_artifact_digest {
        return Err(Error::Authentication);
    }
    wholepact_protocol::offline_return::inspect_exact_own_signature_return(
        layout.bytes(),
        &signed,
        &own_inspection,
    )
    .map_err(|_| Error::Authentication)?;
    wholepact_protocol::authorization::inspect_external_signatures(
        checkpoint.pczt_bytes(),
        policy,
        &origin.review_binding,
        &signatures,
        wholepact_protocol::proving::ProvingLimits {
            maximum_actions: retained.original().claim().maximum_actions,
        },
    )
    .map_err(|_| Error::Authentication)?;
    retained.check_current()?;
    history.check_current().map_err(|_| Error::Permission)?;
    Ok(VerifiedBornReturnV1 {
        admission: admission.clone(),
        signatures,
        payload_digest: hex::encode(Sha256::digest(raw)),
        origin_identifier: payload.born_origin_digest,
        consent_identifier: payload.original_consent_ref,
        signed_canonical_digest: payload.signed_artifact_digest,
    })
}
fn hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Err(Error::Authentication)
    } else {
        Ok(())
    }
}
fn milliseconds(value: i64) -> Result<u64> {
    u64::try_from(value)
        .ok()
        .and_then(|v| v.checked_mul(1000))
        .ok_or(Error::Invalid)
}

// Terms preserve the original full-proof artifact contract. The independently
// reproduced signer role layout has its OWN digest; reduction is not equality
// or a permission to substitute one representation for the other.
fn require_artifact_roles(
    layout: &wholepact_protocol::canonical_role_layout::CanonicalLayoutArtifact,
    terms_original: &str,
    payload_original: &str,
    retained_original: &str,
    payload_reviewed: &str,
) -> Result<()> {
    if terms_original != retained_original
        || payload_original != retained_original
        || layout.transformation().original_digest() != retained_original
        || payload_reviewed != layout.evidence().artifact_digest()
    {
        return Err(Error::Authentication);
    }
    Ok(())
}

#[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
mod artifact_role_tests {
    use super::*;

    #[test]
    fn born_return_artifact_roles_bind_actual_unequal_canonical_projection() {
        // Maintained real constructor/redactor, fabricated never-funded inputs.
        // No proof, real-owner signature, vault, IPC or network is invoked.
        let fixture = wholepact_protocol::synthetic::review_fixture().unwrap();
        let layout = wholepact_protocol::canonical_role_layout::produce_canonical_layout(
            &fixture.pczt_bytes,
            &fixture.policy,
        )
        .unwrap();
        let original = hex::encode(Sha256::digest(&fixture.pczt_bytes));
        let canonical = layout.evidence().artifact_digest();
        assert!(original != canonical);
        assert!(
            require_artifact_roles(&layout, &original, &original, &original, canonical).is_ok()
        );
        // Each role swap independently fails. No term semantics are rewritten.
        assert!(
            require_artifact_roles(&layout, canonical, &original, &original, canonical).is_err()
        );
        assert!(
            require_artifact_roles(&layout, &original, canonical, &original, canonical).is_err()
        );
        assert!(
            require_artifact_roles(&layout, &original, &original, &original, &original).is_err()
        );
        assert!(
            require_artifact_roles(&layout, canonical, canonical, canonical, canonical).is_err()
        );
        let other = wholepact_protocol::synthetic::review_fixture().unwrap();
        let unrelated = wholepact_protocol::canonical_role_layout::produce_canonical_layout(
            &other.pczt_bytes,
            &other.policy,
        )
        .unwrap();
        assert!(
            require_artifact_roles(&unrelated, &original, &original, &original, canonical).is_err()
        );
    }
}
