//! Inert checkpoint receipt commitments, backed by the existing actual encrypted
//! inbox rows. No constructor here authenticates bytes or creates a capability.
use super::*;
use rusqlite::{Connection, OptionalExtension, params};
use wholepact_authority::born_offline_checkpoint_origin_v1::{
    BornOfflineCheckpointExportPlanV1, BornOfflineCheckpointOriginV1,
};
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BornNamedCheckpointReceiptV1 {
    pub(crate) version: u16,
    pub(crate) profile_ref: String,
    pub(crate) checkpoint_origin_digest: String,
    pub(crate) export_plan: BornOfflineCheckpointExportPlanV1,
    pub(crate) stream_digest: String,
    pub(crate) sequence: u64,
    pub(crate) message_id_digest: String,
    pub(crate) content_digest: String,
    pub(crate) payload_digest: String,
    pub(crate) envelope_digest: String,
    pub(crate) immutable_slot_digest: String,
}
impl BornNamedCheckpointReceiptV1 {
    pub(crate) fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:born-named-checkpoint-receipt:v1", self)
    }
    fn validate(&self) -> Result<()> {
        for h in [
            &self.profile_ref,
            &self.checkpoint_origin_digest,
            &self.stream_digest,
            &self.message_id_digest,
            &self.content_digest,
            &self.payload_digest,
            &self.envelope_digest,
            &self.immutable_slot_digest,
        ] {
            hash(h)?;
        }
        self.export_plan.validate().map_err(invalid_named_record)?;
        if self.version != 1 || self.sequence == 0 || self.sequence != self.export_plan.sequence {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
    pub(crate) fn validate_for(
        &self,
        profile: &NamedRecipientProfileRecordV1,
        checkpoint: &BornOfflineCheckpointOriginV1,
    ) -> Result<()> {
        self.validate()?;
        self.export_plan
            .validate_for(checkpoint)
            .map_err(invalid_named_record)?;
        if self.profile_ref != profile.reference
            || self.checkpoint_origin_digest != checkpoint.digest().map_err(invalid_named_record)?
            || checkpoint.account_id != profile.account_id
            || checkpoint.full_viewing_key_digest != profile.full_viewing_key_digest
            || checkpoint.signer_key_digest != transport_fingerprint(&profile.transport_public_key)
            || checkpoint.host_return_key_digest
                != transport_fingerprint(&profile.return_transport_public_key)
        {
            return Err(JournalError::InvalidBinding);
        }
        #[cfg(feature = "offline-review-foundation")]
        {
            let projection = expected_projection(profile, checkpoint, &self.export_plan)?;
            let m = projection
                .retained_metadata()
                .map_err(invalid_named_record)?;
            if self.stream_digest != m.stream_digest
                || self.message_id_digest != m.message_id_digest
                || self.content_digest != m.content_digest
                || self.payload_digest != m.payload_digest
                || m.immutable_slot_digest.as_deref() != Some(self.immutable_slot_digest.as_str())
            {
                return Err(JournalError::InvalidBinding);
            }
        }
        Ok(())
    }
    pub(crate) fn require_retained(&self, c: &Connection) -> Result<()> {
        self.validate()?;
        type Row = (String, String, String, String, Option<String>, String);
        let row:Option<Row> = c.query_row("SELECT message_id,content_hash,payload_digest,envelope_digest,immutable_slot,envelope_hex FROM signer_named_recipient_receipts WHERE profile_ref=?1 AND stream=?2 AND sequence=?3 AND length(envelope_hex)<=2097152",params![self.profile_ref,self.stream_digest,self.sequence],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional()?;
        let Some((message, content, payload, envelope, slot, raw)) = row else {
            return Err(JournalError::InvalidBinding);
        };
        let bytes = Zeroizing::new(hex::decode(&raw).map_err(invalid_named_record)?);
        #[cfg(feature = "offline-review-foundation")]
        wholepact_transport::EncryptedEnvelope::from_bytes(bytes.to_vec())
            .map_err(invalid_named_record)?;
        if message != self.message_id_digest
            || content != self.content_digest
            || payload != self.payload_digest
            || envelope != self.envelope_digest
            || slot.as_deref() != Some(self.immutable_slot_digest.as_str())
            || bytes.is_empty()
            || hex::encode(bytes.as_slice()) != raw
            || domain_digest(b"wholepact.encrypted-envelope.v1\0", bytes.as_slice())
                != self.envelope_digest
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
}
#[cfg(feature = "offline-review-foundation")]
pub(crate) fn expected_projection(
    profile: &NamedRecipientProfileRecordV1,
    checkpoint: &BornOfflineCheckpointOriginV1,
    plan: &BornOfflineCheckpointExportPlanV1,
) -> Result<wholepact_transport::PreparedExport> {
    use wholepact_transport::*;
    plan.validate_for(checkpoint)
        .map_err(invalid_named_record)?;
    prepare_export(
        ExportRequest {
            context: born_offline_checkpoint_context_v1(checkpoint)
                .map_err(invalid_named_record)?,
            order: MessageOrder {
                message_id: plan.message_id.clone(),
                sequence: plan.sequence,
                issued_at: Timestamp::from_unix_seconds(plan.issued_at_unix_seconds)
                    .map_err(invalid_named_record)?,
                expires_at: Timestamp::from_unix_seconds(plan.expires_at_unix_seconds)
                    .map_err(invalid_named_record)?,
            },
            purpose: plan.purpose.clone(),
            persistence_warning: plan.persistence_warning.clone(),
        },
        born_offline_checkpoint_fields_v1(checkpoint).map_err(invalid_named_record)?,
        &TransportPublicKey::from_bytes(profile.return_transport_public_key)
            .map_err(invalid_named_record)?,
        &TransportPublicKey::from_bytes(profile.transport_public_key)
            .map_err(invalid_named_record)?,
        &Timestamp::from_unix_seconds(plan.issued_at_unix_seconds).map_err(invalid_named_record)?,
    )
    .map_err(invalid_named_record)
}
