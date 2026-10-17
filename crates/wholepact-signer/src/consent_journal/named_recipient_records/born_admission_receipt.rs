//! Retained evidence only. These fields never manufacture an authenticated
//! transport receipt; the concrete native input owner constructs that separately.
use super::*;
use rusqlite::{Connection, OptionalExtension, params};
use wholepact_authority::born_offline_admission_v1::BornOfflineAuthorizationAdmissionV1;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BornNamedAdmissionReceiptV1 {
    pub(crate) version: u16,
    pub(crate) profile_ref: String,
    pub(crate) original_ref: String,
    pub(crate) original_admission_digest: String,
    pub(crate) export_plan: OfflineAdmissionExportPlan,
    pub(crate) stream_digest: String,
    pub(crate) sequence: u64,
    pub(crate) message_id_digest: String,
    pub(crate) content_digest: String,
    pub(crate) payload_digest: String,
    pub(crate) envelope_digest: String,
    pub(crate) immutable_slot_digest: String,
}
impl BornNamedAdmissionReceiptV1 {
    pub(crate) fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:born-named-admission-receipt:v1", self)
    }
    fn validate(&self) -> Result<()> {
        for h in [
            &self.profile_ref,
            &self.original_ref,
            &self.original_admission_digest,
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
        if self.version != 1
            || self.sequence == 0
            || self.sequence > i64::MAX as u64
            || self.sequence != self.export_plan.sequence
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
    pub(crate) fn validate_for(
        &self,
        profile: &NamedRecipientProfileRecordV1,
        original: &NamedRecipientOriginalRecordV1,
        admission: &BornOfflineAuthorizationAdmissionV1,
    ) -> Result<()> {
        self.validate()?;
        let origin = original
            .born_origin
            .as_ref()
            .ok_or(JournalError::InvalidBinding)?;
        origin.validate_structure(profile, original)?;
        admission
            .matches_request(&origin.request)
            .map_err(invalid_named_record)?;
        admission
            .validate_reserved_policy_bounds(
                &origin.birth.request.policy,
                &origin.enrollment.enrollment,
                &origin.artifacts,
                origin.manual_extension(),
            )
            .map_err(invalid_named_record)?;
        self.export_plan
            .matches_commit(&admission.reserved)
            .map_err(invalid_named_record)?;
        let mut template = original.admission_export_template.clone();
        template.sequence = self.sequence;
        if self.profile_ref != profile.reference
            || self.original_ref != original.reference
            || self.original_admission_digest
                != admission.admission_digest().map_err(invalid_named_record)?
            || self.export_plan != template
        {
            return Err(JournalError::InvalidBinding);
        }
        #[cfg(feature = "offline-review-foundation")]
        {
            let prepared = expected_projection(profile, original, admission, &self.export_plan)?;
            let m = prepared.retained_metadata().map_err(invalid_named_record)?;
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
    /// Same actual encrypted journal transaction, including exact ciphertext.
    /// Absence is never a successful import or permission to re-sign.
    pub(crate) fn require_retained(&self, c: &Connection) -> Result<()> {
        self.validate()?;
        type Row = (String, String, String, String, Option<String>, String);
        let row: Option<Row> = c.query_row(
            "SELECT message_id,content_hash,payload_digest,envelope_digest,immutable_slot,envelope_hex FROM signer_named_recipient_receipts WHERE profile_ref=?1 AND stream=?2 AND sequence=?3 AND length(envelope_hex)<=2097152",
            params![self.profile_ref,self.stream_digest,self.sequence],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional()?;
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
    original: &NamedRecipientOriginalRecordV1,
    admission: &BornOfflineAuthorizationAdmissionV1,
    plan: &OfflineAdmissionExportPlan,
) -> Result<wholepact_transport::PreparedExport> {
    use wholepact_transport::*;
    let terms = &original.terms;
    let statement = BornOfflineMinimalAdmissionV1::from_descriptor(admission, plan)
        .map_err(invalid_named_record)?;
    prepare_export(
        ExportRequest {
            context: MessageContext {
                network_profile_id: terms.network_profile_id.clone(),
                agreement_id: terms.agreement_id.clone(),
                proposal_id: terms.proposal_id.clone(),
                proposal_revision: terms.proposal_revision,
                sender_id: plan.sender_id.clone(),
                recipient_id: plan.recipient_id.clone(),
                artifact_kind: ArtifactKind::BornOfflineMinimalAdmissionV1,
            },
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
        vec![
            DisclosureField::new(
                BORN_OFFLINE_MINIMAL_ADMISSION_FIELD_V1,
                serde_json::to_vec(&statement).map_err(invalid_named_record)?,
            )
            .map_err(invalid_named_record)?,
        ],
        &TransportPublicKey::from_bytes(profile.witness_transport_public_key)
            .map_err(invalid_named_record)?,
        &TransportPublicKey::from_bytes(profile.transport_public_key)
            .map_err(invalid_named_record)?,
        &Timestamp::from_unix_seconds(plan.issued_at_unix_seconds).map_err(invalid_named_record)?,
    )
    .map_err(invalid_named_record)
}
