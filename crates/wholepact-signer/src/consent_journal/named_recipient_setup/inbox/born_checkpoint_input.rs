//! Concrete maintained HPKE checkpoint-origin intake. This opaque preparation
//! never writes independently. Its actual receipt joins first-original retention
//! only after genuine native approval and independent own-effects verification.
use super::super::super::{
    named_intent_transport as wire,
    named_recipient_records::{BornNamedCheckpointReceiptV1, born_checkpoint_projection},
};
use super::*;
pub(super) struct PreparedBornCheckpointInputV1 {
    source: NativeAuthorityBinding,
    binding: BornNamedCheckpointReceiptV1,
    receipt: wire::AuthenticatedReceipt,
    envelope: wire::EncryptedEnvelope,
    deadline: Instant,
}
impl PreparedBornCheckpointInputV1 {
    pub(super) fn commit_into(
        &self,
        tx: &rusqlite::Transaction<'_>,
        profile: &LiveNamedRecipientProfile,
        original: &NamedRecipientOriginalRecordV1,
        records: &PreconstructionRecordLease<'_>,
    ) -> ImportResult<()> {
        if tx.is_autocommit() || self.source != profile.source {
            return Err(TransportError::AuthorityUnavailable);
        }
        check_setup_current(&self.source, self.deadline).map_err(unavailable)?;
        records
            .require_native_origin(&self.source)
            .map_err(unavailable)?;
        records.check_current().map_err(unavailable)?;
        let origin = original
            .born_origin
            .as_ref()
            .ok_or(TransportError::WrongContext)?;
        origin
            .require_actual_signer(tx, &profile.record, records.enrollment())
            .map_err(unavailable)?;
        origin
            .validate_structure(&profile.record, original)
            .map_err(unavailable)?;
        if origin.checkpoint_receipt != self.binding {
            return Err(TransportError::WrongContext);
        }
        self.binding
            .validate_for(&profile.record, &origin.checkpoint_origin)
            .map_err(unavailable)?;
        // First-original only: an earlier matching receipt does not permit a new
        // original. Historical recovery loads the original row, never this owner.
        super::born_admission_input::insert_born_authenticated(
            tx,
            &profile.record.reference,
            &self.receipt,
            self.envelope.as_bytes(),
        )?;
        self.binding.require_retained(tx).map_err(unavailable)?;
        check_setup_current(&self.source, self.deadline).map_err(unavailable)?;
        records.check_current().map_err(unavailable)
    }
}
pub(super) fn prepare_checkpoint_input(
    profile: &LiveNamedRecipientProfile,
    original: &NamedRecipientOriginalRecordV1,
    envelope: EncryptedEnvelope,
    deadline: Instant,
    mut check_current: impl FnMut() -> ImportResult<()>,
) -> ImportResult<PreparedBornCheckpointInputV1> {
    check_current()?;
    check_setup_current(&profile.source, deadline).map_err(unavailable)?;
    let origin = original
        .born_origin
        .as_ref()
        .ok_or(TransportError::WrongContext)?;
    origin
        .checkpoint_origin
        .validate_for_link(&origin.request.construction_link)
        .map_err(unavailable)?;
    origin
        .checkpoint_receipt
        .validate_for(&profile.record, &origin.checkpoint_origin)
        .map_err(unavailable)?;
    let expected = born_checkpoint_projection(
        &profile.record,
        &origin.checkpoint_origin,
        &origin.checkpoint_receipt.export_plan,
    )
    .map_err(unavailable)?;
    let context: wire::MessageContext = serde_json::from_slice(
        &serde_json::to_vec(&expected.preview().context).map_err(unavailable)?,
    )
    .map_err(unavailable)?;
    let envelope =
        wire::EncryptedEnvelope::from_bytes(envelope.as_bytes().to_vec()).map_err(unavailable)?;
    let sender = wire::TransportPublicKey::from_bytes(profile.record.return_transport_public_key)
        .map_err(unavailable)?;
    let recipient =
        wire::TransportSecret::from_bytes(profile.record.transport_secret).map_err(unavailable)?;
    // This authenticates immutable completed origin, not present spendability.
    // Native original admission separately retains its fixed current window.
    let (received, receipt) =
        wire::authenticate(&envelope, &recipient, &sender, &context, None).map_err(unavailable)?;
    if serde_json::to_vec(received.preview()).map_err(unavailable)?
        != serde_json::to_vec(expected.preview()).map_err(unavailable)?
        || received.fields().len() != expected.fields().len()
        || received
            .fields()
            .iter()
            .zip(expected.fields())
            .any(|(a, b)| a.name() != b.name() || a.bytes() != b.bytes())
    {
        return Err(TransportError::WrongContext);
    }
    let binding = BornNamedCheckpointReceiptV1 {
        version: 1,
        profile_ref: profile.record.reference.clone(),
        checkpoint_origin_digest: origin.checkpoint_origin.digest().map_err(unavailable)?,
        export_plan: origin.checkpoint_receipt.export_plan.clone(),
        stream_digest: receipt.stream_digest().into(),
        sequence: receipt.sequence(),
        message_id_digest: receipt.message_id_digest().into(),
        content_digest: receipt.content_digest().into(),
        payload_digest: receipt.payload_digest().into(),
        envelope_digest: receipt.envelope_digest().into(),
        immutable_slot_digest: receipt
            .immutable_slot_digest()
            .ok_or(TransportError::WrongContext)?
            .into(),
    };
    if binding != origin.checkpoint_receipt {
        return Err(TransportError::WrongContext);
    }
    binding
        .validate_for(&profile.record, &origin.checkpoint_origin)
        .map_err(unavailable)?;
    check_current()?;
    check_setup_current(&profile.source, deadline).map_err(unavailable)?;
    Ok(PreparedBornCheckpointInputV1 {
        source: profile.source.clone(),
        binding,
        receipt,
        envelope,
        deadline,
    })
}
