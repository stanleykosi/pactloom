//! Independently verify actual received allocation; a byte receipt is never enough.
use super::*;
use crate::authority_bridge::durable_review_ipc_v1::{self as wire, DurableReviewPayloadV1};
use crate::authority_bridge::durable_review_ipc_v3::coordinated_v1::CoordinatedVerifiedReceiptV1;
use wholepact_authority::durable_delivery_scope_v2::DurableDeliveryMaterialScopeRefV2;

pub(super) fn verify_exact(
    source: &CoordinatedPreparedDeliverySourceV1,
    intent: &CoordinatedRecipientIntentV1,
    action: &SignerV3ReceiveFinalV1,
    bytes: Zeroizing<Vec<u8>>,
) -> Result<(VerifiedDurableEconomicsV1, CoordinatedVerifiedReceiptV1)> {
    source.check_current()?;
    action.check_current()?;
    if action.presentation().presentation_digest != intent.receive_decision_digest
        || intent.read_session_digest != source.read_presentation_digest()
        || intent.source_identity_digest != source.source_identity()
        || bytes.len() as u64 != intent.payload_bytes
        || hex::encode(Sha256::digest(bytes.as_slice())) != intent.payload_digest
    {
        return Err(Error::ReviewMismatch);
    }
    let payload: DurableReviewPayloadV1 =
        wholepact_core::strict_json::parse_typed_json_with_byte_limit(&bytes, wire::MAX_PAYLOAD)
            .map_err(|_| Error::InvalidData)?;
    if payload.encode().map_err(|_| Error::InvalidData)?.as_slice() != bytes.as_slice() {
        return Err(Error::ReviewMismatch);
    }
    let own = payload
        .contributions
        .iter()
        .find(|c| c.request().scope.account_id == intent.account_id)
        .ok_or(Error::ReviewMismatch)?;
    if own != source.original_outbox() {
        return Err(Error::ReviewMismatch);
    }
    let proposal =
        crate::consent_journal::validated_delivery_manifest_proposal_v3(source.manifest())?;
    let mut materials = Vec::new();
    for contribution in &payload.contributions {
        let scope = &contribution.request().scope;
        scope
            .check_valid_at(unix_ms()? / 1000)
            .map_err(|_| Error::Locked)?;
        if scope.proposal != *proposal.input() {
            return Err(Error::ReviewMismatch);
        }
        materials.push(DurableDeliveryMaterialScopeRefV2 {
            account_id: scope.account_id.clone(),
            original_scope_digest: scope.digest().map_err(|_| Error::ReviewMismatch)?,
            valid_from_unix_seconds: scope.valid_from_unix_seconds,
            valid_until_unix_seconds: scope.valid_until_unix_seconds,
        });
    }
    materials.sort_by(|a, b| a.account_id.cmp(&b.account_id));
    if materials != intent.material_scopes {
        return Err(Error::ReviewMismatch);
    }
    let unsigned =
        Zeroizing::new(hex::decode(&payload.unsigned_pczt_hex).map_err(|_| Error::InvalidData)?);
    let proved =
        Zeroizing::new(hex::decode(&payload.proved_pczt_hex).map_err(|_| Error::InvalidData)?);
    source.check_current()?;
    action.check_current()?;
    let fixed = VerifiedDurableEconomicsV1::verify(
        &proposal,
        &unsigned,
        &proved,
        &payload.contributions,
        &intent.account_id,
        payload
            .output_actions
            .iter()
            .map(|m| wholepact_protocol::construction::OutputActionMapping {
                output_id: m.output_id.clone(),
                action_index: m.action_index,
            })
            .collect(),
        wholepact_protocol::proving::ProvingLimits { maximum_actions: 8 },
    )?;
    // Expensive proof verification may outlive R or original action clocks;
    // no subsequent private publication/positive observation follows unchecked.
    source.check_current()?;
    action.check_current()?;
    if fixed.verified().identity() != &intent.fixed {
        return Err(Error::ReviewMismatch);
    }
    let receipt = CoordinatedVerifiedReceiptV1 {
        version: 1,
        intent_digest: intent.digest().map_err(|_| Error::ReviewMismatch)?,
        payload_digest: intent.payload_digest.clone(),
        payload_bytes: intent.payload_bytes,
        verified_fixed_identity_digest:
            crate::authority_bridge::durable_review_ipc_v3::verified_fixed_identity_digest_v3(
                &intent.fixed,
            )
            .map_err(|_| Error::ReviewMismatch)?,
        state: "verified_import_for_review".into(),
    };
    Ok((fixed, receipt))
}
