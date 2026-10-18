//! Immutable NON-SPENDING input-discovery outbox and separate one-hop delivery.
//! Only genuine native approval objects can enter the mutation methods. Public
//! wire values and restored history are data, never scan, export or key power.
//!
//! Call these entry methods without an existing journal/native publication
//! lease. They establish their own fences after checking the actual FreshEntry
//! journal identity. Inside those fences every source check deliberately avoids
//! FreshEntry::check_current(), which would reacquire authority_fence.
use super::*;
use crate::account::birth::enrollment::roster_v2::{
    durable_entry_v1::FreshDurableBornEntryV1, BornManualRosterEnrollmentRecordV2,
};
use crate::native_ui::durable_input_projection_v1::{
    ApprovedDurableInputProjectionV1, ApprovedDurableProjectionRedeliveryV1,
};
use crate::native_ui::NativeAuthorityBinding;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use wholepact_signer_origin::durable_input_projection_v1::{
    redisclosure::{encode_redisclosure_response_v1, DurableInputProjectionDeliveryV1},
    DurableInputProjectionOutboxV1, DurableInputProjectionRequestV1,
    MAX_INPUT_PROJECTION_FRAME_BYTES_V1,
};

/// Root integration must install these exact tables/triggers additively, add
/// every text column to capacity/backup inventory, and register validate_rows.
/// This constant does not install or migrate a live database by itself.
pub(super) const SCHEMA_V1: &str = include_str!("durable_input_projection_v1.sql");

/// Historical complete original policy preimage. Its creation here is only a
/// strict projection of the ACTUAL FreshEntry export, never an approval factory.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginalPolicyV2 {
    version: u16,
    anchor: wholepact_core::born_policy_origin_v2::BornRecipientPolicyOriginV2,
    original_birth_commit: wholepact_authority::pending_birth::PendingBirthCommitRecord,
}

/// This remains inside the encrypted signer journal. FVK DIGESTS and historical
/// records are permitted here; neither full FVK, notes nor witnesses are stored
/// by this outbox. This evidence is never included in the transport response.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginalProjectionSourceV1 {
    version: u16,
    original: BornManualRosterEnrollmentRecordV2,
    policy: OriginalPolicyV2,
}
impl OriginalProjectionSourceV1 {
    fn from_entry(entry: &FreshDurableBornEntryV1) -> Result<Self> {
        entry.check_original_source_current().map_err(permission)?;
        let actual = entry
            .original_recipient_policy_export_v2()
            .map_err(permission)?;
        let raw = encode(&actual)?;
        let policy = wholepact_core::parse_typed_json(raw.as_bytes()).map_err(binding)?;
        let source = Self {
            version: 1,
            original: entry.record().clone(),
            policy,
        };
        source.validate()?;
        if &source.original.account_record.genesis != entry.genesis() {
            return Err(JournalError::InvalidBinding);
        }
        entry.check_original_source_current().map_err(permission)?;
        Ok(source)
    }

    fn validate(&self) -> Result<()> {
        self.original.validate().map_err(binding)?;
        self.policy.anchor.validate().map_err(binding)?;
        self.policy
            .original_birth_commit
            .validate()
            .map_err(binding)?;
        let extension = self.original.extension().map_err(binding)?;
        extension
            .validate_original_birth(&self.policy.original_birth_commit)
            .map_err(binding)?;
        let original = &self.original.account_record;
        let genesis = &original.genesis;
        let anchor = &self.policy.anchor;
        let commit = &self.policy.original_birth_commit.request;
        if self.version != 1
            || self.policy.version != 2
            || anchor.birth_digest != genesis.native_birth_digest
            || anchor.birth_digest != commit.native_birth_digest
            || anchor.intent.operation_id != commit.operation_id
            || anchor.intent.generation_instance_id != commit.generation_instance_id
            || anchor.intent.original_policy_terms_digest != commit.original_terms_digest
            || commit.policy.account_use_genesis.as_ref() != Some(genesis)
            || anchor.intent.identity.account_id != genesis.identity.account_id
            || anchor.intent.identity.full_viewing_key_digest
                != genesis.identity.full_viewing_key_digest
            || anchor.intent.identity.network_profile_id != genesis.identity.network_profile_id
            || anchor.intent.identity.derivation_domain != genesis.identity.derivation_domain
            || anchor.intent.witness_origin.endpoint != commit.disclosure.endpoint
            || anchor.intent.witness_origin.server_name != commit.disclosure.server_name
            || anchor.intent.witness_origin.witness_id != commit.disclosure.witness_id
            || anchor
                .intent
                .witness_origin
                .pinned_server_certificate_digest
                != commit.disclosure.pinned_server_certificate_digest
        {
            return Err(JournalError::InvalidBinding);
        }
        anchor
            .recipient_policy
            .require_enrollment(&original.terms)
            .map_err(binding)?;
        Ok(())
    }

    fn digest(&self) -> Result<String> {
        self.validate()?;
        digest(
            "wholepact:durable-input-projection-original-source:v1",
            self,
        )
    }

    fn require_request(&self, request: &DurableInputProjectionRequestV1) -> Result<()> {
        self.validate()?;
        request.validate().map_err(binding)?;
        request
            .intent
            .require_original_policy(
                &self.original.account_record.terms,
                &self.policy.anchor.recipient_policy,
            )
            .map_err(binding)
    }
}

struct OriginalRowV1 {
    outbox: DurableInputProjectionOutboxV1,
    source: OriginalProjectionSourceV1,
    // Keep the exact canonical bytes actually committed; a read never rewrites
    // formatting or silently normalizes restored rows.
    payload: Zeroizing<String>,
    source_payload: Zeroizing<String>,
}

impl SignerConsentJournal {
    /// Initial native preparation calls this BEFORE scan/select. An operation
    /// already retained in either namespace is not another discovery request.
    /// This race-safe preflight grants no export and returns no prior metadata.
    pub(crate) fn require_new_durable_input_projection_v1(
        &self,
        source: &FreshDurableBornEntryV1,
        request: &DurableInputProjectionRequestV1,
    ) -> Result<()> {
        request.require_valid_at(now_seconds()?).map_err(binding)?;
        source.require_journal_identity(self).map_err(permission)?;
        let _fence = self
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        source.check_original_source_current().map_err(permission)?;
        let original = OriginalProjectionSourceV1::from_entry(source)?;
        original.require_request(request)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        self.database_identity.check_current(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        require_current_source(&tx, source, &original, self.capacity_limits())?;
        if operation_exists(&tx, &request.operation_id)? {
            return Err(JournalError::Conflict);
        }
        source.check_original_source_current().map_err(permission)?;
        self.database_identity.check_current(&tx)?;
        tx.commit()?;
        Ok(())
    }

    /// Internal exact locator only. The complete Engine-saved request supplies
    /// the mandatory operation AND digest. No list/latest/optional matching,
    /// no transport write, no scan, and no replacement of original provenance.
    pub(crate) fn prepare_durable_input_projection_redisclosure_source_v1(
        &self,
        source: &FreshDurableBornEntryV1,
        request: &DurableInputProjectionRequestV1,
    ) -> Result<DurableInputProjectionOutboxV1> {
        request.require_valid_at(now_seconds()?).map_err(binding)?;
        let expected_digest = request.digest().map_err(binding)?;
        source.require_journal_identity(self).map_err(permission)?;
        let _fence = self
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        source.check_original_source_current().map_err(permission)?;
        let actual = OriginalProjectionSourceV1::from_entry(source)?;
        actual.require_request(request)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        self.database_identity.check_current(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        require_current_source(&tx, source, &actual, self.capacity_limits())?;
        let original = read_original(&tx, &request.operation_id)?.ok_or(JournalError::NotFound)?;
        if original.outbox.request != *request
            || original.outbox.request_digest != expected_digest
            || original.source != actual
        {
            return Err(JournalError::InvalidBinding);
        }
        request.require_valid_at(now_seconds()?).map_err(binding)?;
        source.check_original_source_current().map_err(permission)?;
        self.database_identity.check_current(&tx)?;
        tx.commit()?;
        Ok(original.outbox)
    }

    /// Commit BEFORE the first metadata byte. This consumes no spending budget,
    /// creates no reservation, and never alters financial exposure. If native
    /// revocation or an uncertain send follows commit, the row stays forever.
    pub(crate) fn record_durable_input_projection_v1(
        &self,
        approved: &ApprovedDurableInputProjectionV1,
    ) -> Result<DurableInputProjectionOutboxV1> {
        approved.check_current().map_err(permission)?;
        let source = approved.source();
        source.require_journal_identity(self).map_err(permission)?;
        let _fence = self
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        let outbox = approved.outbox();
        require_native(
            source,
            approved.native_origin(),
            &outbox.native_entry_digest,
        )?;
        approved.check_current().map_err(permission)?;
        outbox.validate().map_err(binding)?;
        outbox
            .request
            .require_valid_at(now_seconds()?)
            .map_err(binding)?;
        let original = OriginalProjectionSourceV1::from_entry(source)?;
        original.require_request(&outbox.request)?;
        let payload = encode_frame(outbox)?;
        let source_payload = encode(&original)?;
        let source_digest = original.digest()?;
        let genesis_digest = source.genesis().digest().map_err(binding)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        self.database_identity.check_current(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_current_source(&tx, source, &original, self.capacity_limits())?;
        if let Some(old) = read_original(&tx, &outbox.request.operation_id)? {
            // Even an identical request cannot move to a new channel, review,
            // source, or fresh native entry without a DISTINCT delivery row.
            if old.outbox != *outbox
                || old.source != original
                || old.payload.as_str() != payload.as_str()
                || old.source_payload.as_str() != source_payload.as_str()
            {
                return Err(JournalError::Conflict);
            }
            approved.check_current().map_err(permission)?;
            require_native(
                source,
                approved.native_origin(),
                &old.outbox.native_entry_digest,
            )?;
            old.outbox
                .request
                .require_valid_at(now_seconds()?)
                .map_err(binding)?;
            self.database_identity.check_current(&tx)?;
            tx.commit()?;
            return Ok(old.outbox);
        }
        if operation_exists(&tx, &outbox.request.operation_id)? {
            return Err(JournalError::Conflict);
        }
        tx.execute(
            "INSERT INTO signer_durable_input_projection_outbox_v1(operation_id,request_digest,reference,account_id,genesis_digest,source_digest,payload,source_payload) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![outbox.request.operation_id, outbox.request_digest, outbox.reference,
                outbox.request.intent.account_id, genesis_digest, source_digest,
                payload.as_str(), source_payload.as_str()],
        )?;
        storage::bounded(&tx, self.capacity_limits())?;
        require_current_source(&tx, source, &original, self.capacity_limits())?;
        // Linearize this short immutable append against native invalidation.
        let publication = approved
            .native_origin()
            .publication_lease()
            .map_err(permission)?;
        approved.check_current().map_err(permission)?;
        require_current_source_locked(&tx, source, &original)?;
        outbox
            .request
            .require_valid_at(now_seconds()?)
            .map_err(binding)?;
        self.database_identity.check_current(&tx)?;
        tx.commit()?;
        drop(publication);
        // A post-commit failure is deliberately not rollback/refund/erase.
        self.database_identity.check_current(&c)?;
        approved.check_current().map_err(permission)?;
        Ok(outbox.clone())
    }

    /// A new native decision can send only the exact retained original bytes.
    /// A delivery is not another original and cannot be the parent of a chain.
    pub(crate) fn record_durable_input_projection_redelivery_v1(
        &self,
        approved: &ApprovedDurableProjectionRedeliveryV1,
    ) -> Result<DurableInputProjectionDeliveryV1> {
        approved.check_current().map_err(permission)?;
        let source = approved.source();
        source.require_journal_identity(self).map_err(permission)?;
        let _fence = self
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        let delivery = approved.delivery();
        require_native(
            source,
            approved.native_origin(),
            &delivery.native_entry_digest,
        )?;
        approved.check_current().map_err(permission)?;
        delivery
            .require_original(approved.original())
            .map_err(binding)?;
        delivery
            .request
            .require_valid_at(now_seconds()?)
            .map_err(binding)?;
        // Full original + delivery response must fit BEFORE we append anything.
        let _frame =
            encode_redisclosure_response_v1(approved.original(), delivery).map_err(binding)?;
        let actual = OriginalProjectionSourceV1::from_entry(source)?;
        actual.require_request(&delivery.request.original_request)?;
        let payload = encode_frame(delivery)?;
        let recipient_digest = delivery_recipient_digest(delivery)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        self.database_identity.check_current(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_current_source(&tx, source, &actual, self.capacity_limits())?;
        let original = read_original(&tx, &delivery.request.original_request.operation_id)?
            .ok_or(JournalError::NotFound)?;
        if original.source != actual || original.outbox != *approved.original() {
            return Err(JournalError::InvalidBinding);
        }
        delivery
            .require_original(&original.outbox)
            .map_err(binding)?;
        if let Some((old, old_payload)) = read_delivery(&tx, &delivery.request.operation_id)? {
            if old != *delivery || old_payload.as_str() != payload.as_str() {
                return Err(JournalError::Conflict);
            }
            approved.check_current().map_err(permission)?;
            require_native(source, approved.native_origin(), &old.native_entry_digest)?;
            old.request
                .require_valid_at(now_seconds()?)
                .map_err(binding)?;
            self.database_identity.check_current(&tx)?;
            tx.commit()?;
            return Ok(old);
        }
        if operation_exists(&tx, &delivery.request.operation_id)? {
            return Err(JournalError::Conflict);
        }
        tx.execute(
            "INSERT INTO signer_durable_input_projection_deliveries_v1(operation_id,request_digest,reference,original_operation_id,original_request_digest,original_outbox_reference,recipient_digest,payload) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![delivery.request.operation_id, delivery.request_digest, delivery.reference,
                original.outbox.request.operation_id, original.outbox.request_digest,
                original.outbox.reference, recipient_digest, payload.as_str()],
        )?;
        storage::bounded(&tx, self.capacity_limits())?;
        require_current_source(&tx, source, &actual, self.capacity_limits())?;
        let publication = approved
            .native_origin()
            .publication_lease()
            .map_err(permission)?;
        approved.check_current().map_err(permission)?;
        require_current_source_locked(&tx, source, &actual)?;
        delivery
            .request
            .require_valid_at(now_seconds()?)
            .map_err(binding)?;
        self.database_identity.check_current(&tx)?;
        tx.commit()?;
        drop(publication);
        self.database_identity.check_current(&c)?;
        approved.check_current().map_err(permission)?;
        Ok(delivery.clone())
    }
}

fn permission(_: impl std::fmt::Display) -> JournalError {
    JournalError::Permission
}
fn binding(_: impl std::fmt::Display) -> JournalError {
    JournalError::InvalidBinding
}
fn now_seconds() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| JournalError::Expired)
}
fn encode_frame(value: &impl Serialize) -> Result<Zeroizing<String>> {
    let raw = encode(value)?;
    if raw.len() >= MAX_INPUT_PROJECTION_FRAME_BYTES_V1 {
        return Err(JournalError::Limit);
    }
    Ok(raw)
}
fn decode_exact<T: DeserializeOwned + Serialize>(raw: &str, maximum: usize) -> Result<T> {
    if raw.is_empty() || raw.len() > maximum {
        return Err(JournalError::Limit);
    }
    let value: T = wholepact_core::parse_typed_json(raw.as_bytes()).map_err(binding)?;
    if encode(&value)?.as_str() != raw {
        return Err(JournalError::InvalidBinding);
    }
    Ok(value)
}
fn delivery_recipient_digest(delivery: &DurableInputProjectionDeliveryV1) -> Result<String> {
    delivery.recipient.validate().map_err(binding)?;
    digest(
        "wholepact:durable-input-projection-delivery-recipient:v1",
        &delivery.recipient,
    )
}
fn require_native(
    entry: &FreshDurableBornEntryV1,
    origin: &NativeAuthorityBinding,
    entry_digest: &str,
) -> Result<()> {
    origin.check_current().map_err(permission)?;
    entry.check_original_source_current().map_err(permission)?;
    if &entry.native_binding() != origin || origin.entry_digest() != entry_digest {
        return Err(JournalError::Permission);
    }
    Ok(())
}
/// Caller already holds authority_fence and a journal transaction. Do not call
/// an entry/journal method here that might acquire that fence a second time.
fn require_current_source(
    c: &Connection,
    entry: &FreshDurableBornEntryV1,
    original: &OriginalProjectionSourceV1,
    limits: (u64, u64),
) -> Result<()> {
    // Parent-owned wrapper reuses the complete existing snapshot validator.
    // It must not acquire any journal or native lock itself.
    storage::validate_durable_input_projection_source_v1(c, entry.genesis(), limits)?;
    require_current_source_locked(c, entry, original)
}
/// Only the same continuously held journal fence and transaction may use this
/// final bounded conjunction. Full history was validated before acquiring the
/// native publication lease; no journal writer can intervene before commit.
fn require_current_source_locked(
    c: &Connection,
    entry: &FreshDurableBornEntryV1,
    original: &OriginalProjectionSourceV1,
) -> Result<()> {
    if c.is_autocommit() {
        return Err(JournalError::InvalidBinding);
    }
    entry.check_original_source_current().map_err(permission)?;
    let account = storage::read_account(c)?;
    let stored = account_use_storage::inspect(c, &account.account_id)?;
    if account.recovery_required {
        return Err(JournalError::RecoveryRequired);
    }
    if account.account_id != entry.genesis().identity.account_id
        || stored.genesis() != Some(entry.genesis())
        || stored.genesis() != Some(&original.original.account_record.genesis)
        || stored.exclusion().is_some()
        || stored.witness_ack().is_some()
    {
        return Err(JournalError::InvalidBinding);
    }
    Ok(())
}
fn operation_exists(c: &Connection, operation: &str) -> Result<bool> {
    id(operation)?;
    c.query_row(
        "SELECT EXISTS(SELECT 1 FROM signer_durable_input_projection_outbox_v1 WHERE operation_id=?1 UNION ALL SELECT 1 FROM signer_durable_input_projection_deliveries_v1 WHERE operation_id=?1)",
        [operation], |r| r.get(0),
    ).map_err(Into::into)
}
fn read_original(c: &Connection, operation: &str) -> Result<Option<OriginalRowV1>> {
    id(operation)?;
    let raw: Option<(String, String, String, String, String, String, String)> = c.query_row(
        "SELECT request_digest,reference,account_id,genesis_digest,source_digest,payload,source_payload FROM signer_durable_input_projection_outbox_v1 WHERE operation_id=?1",
        [operation], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)),
    ).optional()?;
    raw.map(
        |(
            request_digest,
            reference,
            account_id,
            genesis_digest,
            source_digest,
            payload,
            source_payload,
        )| {
            let payload = Zeroizing::new(payload);
            let source_payload = Zeroizing::new(source_payload);
            let outbox: DurableInputProjectionOutboxV1 =
                decode_exact(&payload, MAX_INPUT_PROJECTION_FRAME_BYTES_V1 - 1)?;
            let source: OriginalProjectionSourceV1 =
                decode_exact(&source_payload, MAX_RECORD_BYTES)?;
            outbox.validate().map_err(binding)?;
            source.require_request(&outbox.request)?;
            let account = storage::read_account(c)?;
            let stored = account_use_storage::inspect(c, &account.account_id)?;
            // Historical verification deliberately has no live-native or wall-time
            // requirement. An expired record remains conservative disclosure history.
            if outbox.request.operation_id != operation
                || outbox.request_digest != request_digest
                || outbox.reference != reference
                || outbox.request.intent.account_id != account_id
                || account_id != account.account_id
                || source
                    .original
                    .account_record
                    .genesis
                    .digest()
                    .map_err(binding)?
                    != genesis_digest
                || source.digest()? != source_digest
                || stored.genesis() != Some(&source.original.account_record.genesis)
            {
                return Err(JournalError::InvalidBinding);
            }
            Ok(OriginalRowV1 {
                outbox,
                source,
                payload,
                source_payload,
            })
        },
    )
    .transpose()
}
fn read_delivery(
    c: &Connection,
    operation: &str,
) -> Result<Option<(DurableInputProjectionDeliveryV1, Zeroizing<String>)>> {
    id(operation)?;
    let raw: Option<(String, String, String, String, String, String, String)> = c.query_row(
        "SELECT request_digest,reference,original_operation_id,original_request_digest,original_outbox_reference,recipient_digest,payload FROM signer_durable_input_projection_deliveries_v1 WHERE operation_id=?1",
        [operation], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)),
    ).optional()?;
    raw.map(
        |(
            request_digest,
            reference,
            original_operation,
            original_request_digest,
            original_reference,
            recipient_digest,
            payload,
        )| {
            let payload = Zeroizing::new(payload);
            let delivery: DurableInputProjectionDeliveryV1 =
                decode_exact(&payload, MAX_INPUT_PROJECTION_FRAME_BYTES_V1 - 1)?;
            delivery.validate().map_err(binding)?;
            if delivery.request.operation_id != operation
                || delivery.request_digest != request_digest
                || delivery.reference != reference
                || delivery.request.original_request.operation_id != original_operation
                || delivery
                    .request
                    .original_request
                    .digest()
                    .map_err(binding)?
                    != original_request_digest
                || delivery.original_outbox_reference != original_reference
                || delivery_recipient_digest(&delivery)? != recipient_digest
            {
                return Err(JournalError::InvalidBinding);
            }
            // Only an ORIGINAL table lookup is allowed. Never follow a delivery
            // recursively, including when validating malicious restored history.
            let original = read_original(c, &original_operation)?.ok_or(JournalError::NotFound)?;
            delivery
                .require_original(&original.outbox)
                .map_err(binding)?;
            let _frame =
                encode_redisclosure_response_v1(&original.outbox, &delivery).map_err(binding)?;
            Ok((delivery, payload))
        },
    )
    .transpose()
}

/// Historical verification only, suitable for bounded backup/reopen/inventory.
/// This intentionally remains usable after native expiry or account exclusion.
pub(super) fn validate_rows(c: &Connection) -> Result<()> {
    let rows: u64 = c.query_row(
        "SELECT (SELECT count(*) FROM signer_durable_input_projection_outbox_v1) + (SELECT count(*) FROM signer_durable_input_projection_deliveries_v1)",
        [], |r| r.get(0),
    )?;
    if rows > MAX_BACKUP_ROWS {
        return Err(JournalError::Limit);
    }
    let collisions: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM signer_durable_input_projection_outbox_v1 o JOIN signer_durable_input_projection_deliveries_v1 d ON o.operation_id=d.operation_id)",
        [], |r| r.get(0),
    )?;
    if collisions {
        return Err(JournalError::InvalidBinding);
    }
    let mut originals = c.prepare(
        "SELECT operation_id FROM signer_durable_input_projection_outbox_v1 ORDER BY operation_id",
    )?;
    for operation in originals.query_map([], |r| r.get::<_, String>(0))? {
        read_original(c, &operation?)?.ok_or(JournalError::NotFound)?;
    }
    drop(originals);
    let mut deliveries = c.prepare("SELECT operation_id FROM signer_durable_input_projection_deliveries_v1 ORDER BY operation_id")?;
    for operation in deliveries.query_map([], |r| r.get::<_, String>(0))? {
        read_delivery(c, &operation?)?.ok_or(JournalError::NotFound)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "durable_input_projection_v1_tests.rs"]
mod tests;
