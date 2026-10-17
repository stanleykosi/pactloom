//! Concrete original-born HPKE intake. Preparation authenticates but does not
//! write. The genuine native evidence owner may retain it without signing; the final
//! signing owner instead commits it with Started after fresh clock validation.
use super::super::super::{
    named_intent_transport as wire,
    named_recipient_records::{BornNamedAdmissionReceiptV1, born_admission_projection},
};
use super::*;
use wholepact_authority::{
    AuthorityClient, BornOfflineDeliveryLookupV1, ReconciledAuthorityHistory,
    born_offline_admission_v1::BornOfflineAuthorizationAdmissionV1,
};

/// No Deserialize, Clone or raw receipt constructor. The retained wire receipt
/// was produced by maintained HPKE sender authentication of the exact original.
pub(super) struct PreparedBornAdmissionInputV1 {
    source: NativeAuthorityBinding,
    binding: BornNamedAdmissionReceiptV1,
    admission: BornOfflineAuthorizationAdmissionV1,
    receipt: wire::AuthenticatedReceipt,
    envelope: wire::EncryptedEnvelope,
    deadline: Instant,
}
impl PreparedBornAdmissionInputV1 {
    pub(super) fn envelope_digest(&self) -> &str {
        &self.binding.envelope_digest
    }
    pub(super) fn binding_digest(&self) -> ImportResult<String> {
        self.binding.digest().map_err(unavailable)
    }
    pub(super) fn receipt(&self) -> &BornNamedAdmissionReceiptV1 {
        &self.binding
    }
    /// Caller is a private genuine native owner. This does not commit independently.
    /// Final signing shares its transaction with Started; evidence-only retention
    /// deliberately creates no signing marker or key-use authority.
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
        original
            .born_origin
            .as_ref()
            .ok_or(TransportError::AuthorityUnavailable)?
            .require_actual_signer(tx, &profile.record, records.enrollment())
            .map_err(unavailable)?;
        self.binding
            .validate_for(&profile.record, original, &self.admission)
            .map_err(unavailable)?;
        let existing: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM signer_named_recipient_receipts WHERE profile_ref=?1 AND stream=?2 AND sequence=?3)",
            params![self.binding.profile_ref,self.binding.stream_digest,self.binding.sequence], |r| r.get(0)).map_err(unavailable)?;
        if existing {
            self.binding.require_retained(tx).map_err(unavailable)?;
            let raw: String = tx.query_row("SELECT envelope_hex FROM signer_named_recipient_receipts WHERE profile_ref=?1 AND stream=?2 AND sequence=?3 AND length(envelope_hex)<=2097152",
                params![self.binding.profile_ref,self.binding.stream_digest,self.binding.sequence], |r| r.get(0)).map_err(unavailable)?;
            if raw != hex::encode(self.envelope.as_bytes()) {
                return Err(TransportError::Equivocation);
            }
        } else {
            insert_born_authenticated(
                tx,
                &profile.record.reference,
                &self.receipt,
                self.envelope.as_bytes(),
            )?;
        }
        self.binding.require_retained(tx).map_err(unavailable)?;
        check_setup_current(&self.source, self.deadline).map_err(unavailable)?;
        records.check_current().map_err(unavailable)
    }
}

pub(super) fn prepare_admission_input(
    profile: &LiveNamedRecipientProfile,
    original: &NamedRecipientOriginalRecordV1,
    history: &ReconciledAuthorityHistory,
    client: &AuthorityClient,
    deadline: Instant,
    mut check_current: impl FnMut() -> ImportResult<()>,
) -> ImportResult<PreparedBornAdmissionInputV1> {
    check_current()?;
    check_setup_current(&profile.source, deadline).map_err(unavailable)?;
    let admission =
        super::born_original_history::authenticate_admission(profile, original, history, client)?;
    let lookup =
        BornOfflineDeliveryLookupV1::from_request(&admission.request).map_err(unavailable)?;
    // The actual TLS client supplies the exact original bytes. This read never
    // allocates a sequence or asks the witness to reseal after lost delivery.
    let delivery = client
        .recover_born_offline_delivery_checked_until_v1(lookup.clone(), deadline, || {
            check_current().map_err(|_| wholepact_authority::AuthorityError::Permission)?;
            check_setup_current(&profile.source, deadline)
                .map_err(|_| wholepact_authority::AuthorityError::Permission)
        })
        .map_err(unavailable)?;
    check_current()?;
    check_setup_current(&profile.source, deadline).map_err(unavailable)?;
    if delivery.original() != &lookup
        || delivery.original_admission_digest()
            != admission.admission_digest().map_err(unavailable)?
        || delivery.committed_head() != &admission.reserved.committed_head
        || !delivery.recovered_original()
    {
        return Err(TransportError::Authentication);
    }
    let plan = delivery.export_plan().clone();
    let mut expected_plan = original.admission_export_template.clone();
    expected_plan.sequence = plan.sequence;
    if plan != expected_plan {
        return Err(TransportError::WrongContext);
    }
    let expected = born_admission_projection(&profile.record, original, &admission, &plan)
        .map_err(unavailable)?;
    let context: wire::MessageContext = serde_json::from_slice(
        &serde_json::to_vec(&expected.preview().context).map_err(unavailable)?,
    )
    .map_err(unavailable)?;
    let envelope =
        wire::EncryptedEnvelope::from_bytes(delivery.ciphertext().to_vec()).map_err(unavailable)?;
    let sender = wire::TransportPublicKey::from_bytes(profile.record.witness_transport_public_key)
        .map_err(unavailable)?;
    let recipient =
        wire::TransportSecret::from_bytes(profile.record.transport_secret).map_err(unavailable)?;
    // Historical decode has no time assertion. Fresh key use separately requires
    // the actual challenge-bound born clock and all original nonrenewing windows.
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
    let binding = BornNamedAdmissionReceiptV1 {
        version: 1,
        profile_ref: profile.record.reference.clone(),
        original_ref: original.reference.clone(),
        original_admission_digest: admission.admission_digest().map_err(unavailable)?,
        export_plan: plan,
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
    binding
        .validate_for(&profile.record, original, &admission)
        .map_err(unavailable)?;
    check_current()?;
    check_setup_current(&profile.source, deadline).map_err(unavailable)?;
    Ok(PreparedBornAdmissionInputV1 {
        source: profile.source.clone(),
        binding,
        admission,
        receipt,
        envelope,
        deadline,
    })
}

// Same bounded compare/insert algorithm as the maintained named inbox; the
// nominal receipt here is produced only by the private maintained HPKE codec.
pub(super) fn insert_born_authenticated(
    tx: &rusqlite::Transaction<'_>,
    profile: &str,
    receipt: &wire::AuthenticatedReceipt,
    envelope: &[u8],
) -> ImportResult<()> {
    // This helper remains private and only accepts an unforgeable authenticated
    // receipt. It is not an import-row adapter or a public privileged writer.
    let sequence = i64::try_from(receipt.sequence()).map_err(|_| TransportError::Malformed)?;
    if sequence < 1 || envelope_commitment(envelope)? != receipt.envelope_digest() {
        return Err(TransportError::Malformed);
    }
    let prior: Option<(String, String, i64)> = tx.query_row(
        "SELECT substr(content_hash,1,65),substr(message_id,1,65),sequence FROM signer_named_recipient_receipts WHERE profile_ref=?1 AND stream=?2 AND (sequence=?3 OR message_id=?4) LIMIT 1",
        params![profile, receipt.stream_digest(), sequence, receipt.message_id_digest()],
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
    ).optional().map_err(|_| TransportError::Storage)?;
    if let Some((content, message, old_sequence)) = prior {
        return Err(
            if content == receipt.content_digest()
                && message == receipt.message_id_digest()
                && old_sequence == sequence
            {
                TransportError::Replay
            } else {
                TransportError::Equivocation
            },
        );
    }
    if let Some(slot) = receipt.immutable_slot_digest() {
        let old: Option<String> = tx.query_row(
            "SELECT substr(payload_digest,1,65) FROM signer_named_recipient_receipts WHERE profile_ref=?1 AND immutable_slot=?2 LIMIT 1",
            params![profile,slot], |r| r.get(0),
        ).optional().map_err(|_| TransportError::Storage)?;
        if let Some(old) = old {
            return Err(if old == receipt.payload_digest() {
                TransportError::Replay
            } else {
                TransportError::Equivocation
            });
        }
    }
    let last: Option<i64> = tx.query_row(
        "SELECT max(sequence) FROM signer_named_recipient_receipts WHERE profile_ref=?1 AND stream=?2",
        params![profile,receipt.stream_digest()], |r| r.get(0),
    ).map_err(|_| TransportError::Storage)?;
    if last.unwrap_or(0).checked_add(1) != Some(sequence) {
        return Err(TransportError::OutOfOrder);
    }
    let (count, bytes): (i64, i64) = tx.query_row(
        "SELECT count(*),coalesce(sum(length(envelope_hex)/2),0) FROM signer_named_recipient_receipts",
        [], |r| Ok((r.get(0)?, r.get(1)?)),
    ).map_err(|_| TransportError::Storage)?;
    let streams: i64 = tx.query_row(
        "SELECT count(*) FROM (SELECT profile_ref,stream FROM signer_named_recipient_receipts GROUP BY profile_ref,stream)",
        [], |r| r.get(0),
    ).map_err(|_| TransportError::Storage)?;
    check_capacity(count, streams, bytes, last.is_none(), envelope.len())?;
    tx.execute(
        "INSERT INTO signer_named_recipient_receipts(profile_ref,stream,sequence,message_id,content_hash,payload_digest,envelope_digest,immutable_slot,envelope_hex) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![profile,receipt.stream_digest(),sequence,receipt.message_id_digest(),
            receipt.content_digest(),receipt.payload_digest(),receipt.envelope_digest(),
            receipt.immutable_slot_digest(),hex::encode(envelope)],
    ).map_err(|_| TransportError::Storage)?;
    Ok(())
}
