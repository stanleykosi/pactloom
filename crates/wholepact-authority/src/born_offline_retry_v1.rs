//! Exact original born input retention. Parsing these records authenticates no
//! ciphertext and cannot construct the private post-HPKE input capability.
use crate::{born_offline_admission_v1::*, offline_retry::OriginalPreparation, *};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

#[cfg(all(feature = "born-offline-witness-owner", target_os = "linux"))]
#[path = "born_offline_witness_owner_v1.rs"]
pub(crate) mod configured_born_witness;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BornOriginalPreparationV1 {
    pub(crate) version: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) owner_transport_certificate_digest: Option<String>,
    pub(crate) request: BornOfflineReservationRequestV1,
    pub(crate) original: OriginalPreparation,
    pub(crate) export_plan: OfflineAdmissionExportPlan,
}
impl BornOriginalPreparationV1 {
    pub(crate) fn validate(&self, ledger: &policy::Ledger) -> Result<()> {
        if self.version != 1 || self.request.reservation != self.original.request {
            return Err(AuthorityError::InvalidBinding);
        }
        self.original.validate()?;
        let e = &ledger
            .born_offline_enrollment_v1()?
            .ok_or(AuthorityError::CorruptHistory)?
            .enrollment;
        let a = ledger
            .born_offline_artifacts_v1()?
            .ok_or(AuthorityError::CorruptHistory)?;
        let manual = &ledger
            .manual_extension()?
            .ok_or(AuthorityError::CorruptHistory)?
            .extension;
        self.request.validate_policy_bounds(
            &ledger.policy,
            e,
            a,
            manual,
            self.original.prepared_at_ms,
        )?;
        let construction =
            ledger.born_offline_construction_origin_v1(&self.request.construction_link)?;
        self.request
            .construction_link
            .validate_for(&construction, &self.request.reservation)?;
        if construction.reservation.session != e.original_writer_session {
            return Err(AuthorityError::CorruptHistory);
        }
        self.export_plan
            .matches_preparation(&self.request.reservation, &e.policy)?;
        let mut template = self.export_plan.clone();
        template.sequence = 0;
        if self.owner_transport_certificate_digest.as_deref()
            != e.owner_continuation
                .as_ref()
                .map(|_| e.owner_certificate_digest.as_str())
            || template != self.original.export_plan_template
            || self.original.writer_certificate_digest
                != e.original_writer_session.writer_certificate_digest
            || self.original.writer_session_id != e.original_writer_session.session_id
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub(crate) fn export_stream(&self) -> Result<String> {
        let t = &self.request.reservation.intent.terms;
        digest(
            "wholepact.transport-stream.v1",
            &(
                &t.network_profile_id,
                &t.agreement_id,
                &self.export_plan.sender_id,
                &self.export_plan.recipient_id,
            ),
        )
    }
}

pub(crate) struct RetainedBornOfflineOriginalV1 {
    pub(crate) original: BornOriginalPreparationV1,
    pub(crate) envelope: Vec<u8>,
    pub(crate) receipt: Option<OriginalTransportReceipt>,
}

/// Only the private configured native owner creates this AFTER actual pinned
/// HPKE, exact intent/profile equality and durable inbox acceptance. No test,
/// serialized evidence or caller-implemented trait can supply runtime authority.
#[cfg(all(feature = "born-offline-witness-owner", target_os = "linux"))]
pub(crate) struct AuthenticatedBornInputV1 {
    receipt: OriginalTransportReceipt,
}
#[cfg(all(feature = "born-offline-witness-owner", target_os = "linux"))]
impl AuthenticatedBornInputV1 {
    pub(crate) fn receipt(&self) -> &OriginalTransportReceipt {
        &self.receipt
    }
}

pub(crate) fn envelope_digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"wholepact.encrypted-envelope.v1\0");
    h.update(bytes);
    hex::encode(h.finalize())
}

pub(crate) fn read_original(
    c: &Connection,
    operation: &str,
) -> Result<Option<RetainedBornOfflineOriginalV1>> {
    read_original_guarded(c, operation, crate::journal::ReadGuardV1::legacy())
}

pub(crate) fn read_original_guarded(
    c: &Connection,
    operation: &str,
    guard: crate::journal::ReadGuardV1<'_>,
) -> Result<Option<RetainedBornOfflineOriginalV1>> {
    id(operation)?;
    type OriginalRow = (String, String, String, u64, Vec<u8>, Vec<u8>, String);
    let raw: Option<OriginalRow> = crate::journal::guarded_read!(guard, c.query_row(
        "SELECT request_digest,envelope_digest,export_stream,export_sequence,payload,envelope,construction_reservation_id FROM authority_born_offline_originals WHERE operation_id=?1 AND length(payload)<=262144 AND length(envelope)<=1048576", [operation],
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).optional())?;
    let Some((request, envelope, stream, sequence, payload, bytes, construction)) = raw else {
        return Ok(None);
    };
    let original: BornOriginalPreparationV1 = decode(&payload)?;
    if original.request.construction_link.reservation_operation_id != construction
        || original.request.reservation.operation_id != operation
        || original.request.request_digest()? != request
        || original.original.original_envelope_digest != envelope
        || envelope_digest(&bytes) != envelope
        || bytes.is_empty()
        || original.export_stream()? != stream
        || original.export_plan.sequence != sequence
        || encode(&original)?.as_slice() != payload
    {
        return Err(AuthorityError::CorruptHistory);
    }
    let receipt:Option<Vec<u8>>=crate::journal::guarded_read!(guard, c.query_row("SELECT payload FROM authority_born_offline_receipts WHERE operation_id=?1 AND length(payload)<=16384",[operation],|r|r.get(0)).optional())?;
    let receipt = receipt
        .map(|v| {
            let r: OriginalTransportReceipt = decode(&v)?;
            if encode(&r)?.as_slice() != v {
                return Err(AuthorityError::CorruptHistory);
            }
            Ok(r)
        })
        .transpose()?;
    Ok(Some(RetainedBornOfflineOriginalV1 {
        original,
        envelope: bytes,
        receipt,
    }))
}

pub(crate) fn require_actual_inbox(
    c: &Connection,
    original: &RetainedBornOfflineOriginalV1,
    receipt: &OriginalTransportReceipt,
) -> Result<()> {
    require_actual_inbox_guarded(c, original, receipt, crate::journal::ReadGuardV1::legacy())
}

pub(crate) fn require_actual_inbox_guarded(
    c: &Connection,
    original: &RetainedBornOfflineOriginalV1,
    receipt: &OriginalTransportReceipt,
    guard: crate::journal::ReadGuardV1<'_>,
) -> Result<()> {
    type InboxRow = (String, String, String, Vec<u8>, Option<String>);
    let actual: Option<InboxRow> =crate::journal::guarded_read!(guard, c.query_row(
        "SELECT message_id_digest,content_digest,payload_digest,envelope,slot FROM receipts WHERE stream=?1 AND sequence=?2 AND length(envelope)<=1048576",
        params![receipt.stream_digest,receipt.sequence],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional())?;
    let Some((message, content, payload, envelope, slot)) = actual else {
        return Err(AuthorityError::Uncertain);
    };
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"wholepact.transport-message.v1\0");
    h.update(receipt.message_id.as_bytes());
    if message != hex::encode(h.finalize())
        || content != receipt.content_digest
        || payload != receipt.payload_digest
        || slot
            != Some(digest(
                "wholepact.transport-slot.v1",
                &(
                    &receipt.stream_digest,
                    &receipt.proposal_id,
                    receipt.proposal_revision,
                    "born_offline_intent_v1",
                ),
            )?)
        || envelope != original.envelope
        || envelope_digest(&envelope) != receipt.envelope_digest
    {
        return Err(AuthorityError::CorruptHistory);
    }
    Ok(())
}

/// Complete typed links on every schema7 load, including crash-partial records.
/// Historical replay does not invoke live session/current-time policy checks.
pub(crate) fn verify_retained_born_offline_v1(
    c: &Connection,
    ledger: &policy::Ledger,
) -> Result<()> {
    verify_retained_born_offline_v1_guarded(c, ledger, crate::journal::ReadGuardV1::legacy())
}

pub(crate) fn verify_retained_born_offline_v1_guarded(
    c: &Connection,
    ledger: &policy::Ledger,
    guard: crate::journal::ReadGuardV1<'_>,
) -> Result<()> {
    let (count,bytes):(u64,u64)=crate::journal::guarded_read!(guard, c.query_row("SELECT count(*),coalesce(sum(length(payload)+length(envelope)),0) FROM authority_born_offline_originals",[],|r|Ok((r.get(0)?,r.get(1)?))))?;
    if count > 1024 || bytes > 64 * 1024 * 1024 {
        return Err(AuthorityError::Limit);
    }
    let orphans:u64=crate::journal::guarded_read!(guard, c.query_row("SELECT count(*) FROM authority_born_offline_receipts r LEFT JOIN authority_born_offline_originals o USING(operation_id) WHERE o.operation_id IS NULL",[],|r|r.get(0)))?;
    if orphans != 0 {
        return Err(AuthorityError::CorruptHistory);
    }
    let mut q = crate::journal::guarded_read!(
        guard,
        c.prepare(
            "SELECT operation_id FROM authority_born_offline_originals ORDER BY operation_id",
        )
    )?;
    let operations: Vec<_> = crate::journal::collect_guarded(
        crate::journal::guarded_read!(guard, q.query_map([], |r| r.get::<_, String>(0)))?,
        guard,
    )?;
    // This purpose has no import processors, sequence-reset controls, delivery
    // acknowledgments or deletion path. Unknown auxiliary rows are not ignored.
    for table in ["domain_imports", "offline_control_outcomes"] {
        let n: u64 = crate::journal::guarded_read!(
            guard,
            c.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
        )?;
        if n != 0 {
            return Err(AuthorityError::CorruptHistory);
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut inbox_seen = std::collections::BTreeSet::new();
    let mut outbox_seen = std::collections::BTreeSet::new();
    for operation in operations {
        let retained =
            read_original_guarded(c, &operation, guard)?.ok_or(AuthorityError::CorruptHistory)?;
        let original = &retained.original;
        original.validate(ledger)?;
        let e = &ledger
            .born_offline_enrollment_v1()?
            .ok_or(AuthorityError::CorruptHistory)?
            .enrollment;
        if let Some(receipt) = &retained.receipt {
            receipt.matches_born(&original.original, &e.policy)?;
            match require_actual_inbox_guarded(c, &retained, receipt, guard) {
                Ok(()) => {
                    if !inbox_seen.insert((receipt.stream_digest.clone(), receipt.sequence)) {
                        return Err(AuthorityError::CorruptHistory);
                    }
                }
                // Callback receipt may durably precede inbox acceptance; it is
                // not itself an authenticated admission capability.
                Err(AuthorityError::Uncertain) => {}
                Err(error) => return Err(error),
            }
        }
        if let Some((mutation, peer, result)) = ledger.operations.get(&operation) {
            let (
                AuthorityMutation::ReserveBornOfflineV1(record),
                MutationResult::BornOfflineReservedV1(admission),
            ) = (mutation, result)
            else {
                return Err(AuthorityError::CorruptHistory);
            };
            if record.request != original.request
                || peer != e.born_transport_certificate_v1()
                || record.authentication.envelope_digest
                    != original.original.original_envelope_digest
            {
                return Err(AuthorityError::CorruptHistory);
            }
            record
                .authentication
                .matches(&original.request.reservation, &e.policy)?;
            admission.matches_request(&original.request)?;
            original.export_plan.matches_commit(&admission.reserved)?;
            let receipt = retained
                .receipt
                .as_ref()
                .ok_or(AuthorityError::CorruptHistory)?;
            require_actual_inbox_guarded(c, &retained, receipt, guard)?;
            if verify_original_outbox_guarded(c, ledger, original, admission, guard)?
                && !outbox_seen.insert((original.export_stream()?, original.export_plan.sequence))
            {
                return Err(AuthorityError::CorruptHistory);
            }
            seen.insert(operation.clone());
        } else {
            let emitted: bool = crate::journal::guarded_read!(
                guard,
                c.query_row(
                    "SELECT EXISTS(SELECT 1 FROM outbox WHERE stream=?1 AND sequence=?2)",
                    params![original.export_stream()?, original.export_plan.sequence],
                    |r| r.get(0),
                )
            )?;
            if emitted {
                return Err(AuthorityError::CorruptHistory);
            }
        }
    }
    let inbox_count: u64 = crate::journal::guarded_read!(
        guard,
        c.query_row("SELECT count(*) FROM receipts", [], |r| r.get(0))
    )?;
    let outbox_count: u64 = crate::journal::guarded_read!(
        guard,
        c.query_row("SELECT count(*) FROM outbox", [], |r| r.get(0))
    )?;
    if inbox_count != inbox_seen.len() as u64 || outbox_count != outbox_seen.len() as u64 {
        return Err(AuthorityError::CorruptHistory);
    }
    for (operation, (mutation, _, _)) in &ledger.operations {
        if matches!(mutation, AuthorityMutation::ReserveBornOfflineV1(_))
            && !seen.contains(operation)
        {
            return Err(AuthorityError::CorruptHistory);
        }
    }
    Ok(())
}

fn verify_original_outbox(
    c: &Connection,
    ledger: &policy::Ledger,
    original: &BornOriginalPreparationV1,
    admission: &BornOfflineAuthorizationAdmissionV1,
) -> Result<bool> {
    verify_original_outbox_guarded(
        c,
        ledger,
        original,
        admission,
        crate::journal::ReadGuardV1::legacy(),
    )
}

fn verify_original_outbox_guarded(
    c: &Connection,
    ledger: &policy::Ledger,
    original: &BornOriginalPreparationV1,
    admission: &BornOfflineAuthorizationAdmissionV1,
    guard: crate::journal::ReadGuardV1<'_>,
) -> Result<bool> {
    type OutboxRow = (
        String,
        String,
        String,
        String,
        Option<String>,
        i64,
        i64,
        i64,
    );
    let row: Option<OutboxRow> = crate::journal::guarded_read!(guard, c.query_row(
        "SELECT message_digest,preview_digest,context_digest,payload_digest,slot,issued_at,expires_at,acknowledged FROM outbox WHERE stream=?1 AND sequence=?2",
        params![original.export_stream()?, original.export_plan.sequence],
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?))).optional())?;
    let Some((message, preview, context, payload, slot, issued, expires, acknowledged)) = row
    else {
        return Ok(false);
    };
    let plan = &original.export_plan;
    let terms = &original.request.reservation.intent.terms;
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"wholepact.transport-message.v1\0");
    hash.update(plan.message_id.as_bytes());
    if message != hex::encode(hash.finalize())
        || issued != plan.issued_at_unix_seconds
        || expires != plan.expires_at_unix_seconds
        || acknowledged != 0
        || slot
            != Some(digest(
                "wholepact.transport-slot.v1",
                &(
                    &original.export_stream()?,
                    &terms.proposal_id,
                    terms.proposal_revision,
                    "born_offline_minimal_admission_v1",
                ),
            )?)
    {
        return Err(AuthorityError::CorruptHistory);
    }
    #[cfg(all(feature = "born-offline-witness-owner", target_os = "linux"))]
    {
        use crate::offline_witness_transport_v1 as mail;
        let artifacts = ledger
            .born_offline_artifacts_v1()?
            .ok_or(AuthorityError::CorruptHistory)?;
        let at = mail::Timestamp::from_unix_seconds(issued)
            .map_err(|_| AuthorityError::CorruptHistory)?;
        let prepared =
            configured_born_witness::prepare_original_export(admission, plan, artifacts, &at)?;
        let expected = prepared.preview();
        if preview
            != expected
                .digest()
                .map_err(|_| AuthorityError::CorruptHistory)?
            || payload != expected.payload_digest
            || context != digest("wholepact.outbox-context.v1", &expected.context)?
        {
            return Err(AuthorityError::CorruptHistory);
        }
    }
    #[cfg(not(all(feature = "born-offline-witness-owner", target_os = "linux")))]
    {
        let _ = (ledger, admission, preview, context, payload);
    }
    Ok(true)
}

#[cfg(all(test, feature = "pending-birth-foundation", target_os = "linux"))]
#[path = "born_offline_retry_v1_tests.rs"]
mod tests;
