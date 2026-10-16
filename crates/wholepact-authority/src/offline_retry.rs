//! Private authority-owned original request retention.
//!
//! No public bridge constructor or caller-implemented trust trait.
//! Low-level journal methods use AuthorityJournal's concrete encrypted connection.
//! Cross-crate methods require the unconstructible configured bridge handle.
//! Component verification is recorded in docs/offline-connected-foundation.md;
//! the optional configured legacy owner alone constructs the production bridge.
//! Retained bytes and their checksums are evidence, never authentication authority.
use crate::{offline::*, offline_export::OfflineAdmissionExportPlan, *};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

pub(crate) const OFFLINE_RETRY_SCHEMA: &str = include_str!("offline_retry_schema.sql");
const MAX_ORIGINAL_ROWS: u64 = 1024;
const MAX_ORIGINAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ORIGINAL_ENVELOPE_BYTES: usize = 1_048_576;
const MAX_RECEIPT_BYTES: usize = 16_384;
const MAX_WINDOW_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// Serialization record only. This type is never accepted as an authorization.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OriginalPreparation {
    pub(crate) schema_version: u16,
    pub(crate) request: ReserveOfflineAuthorization,
    pub(crate) export_plan_template: OfflineAdmissionExportPlan,
    pub(crate) original_envelope_digest: String,
    pub(crate) writer_certificate_digest: String,
    pub(crate) writer_session_id: String,
    pub(crate) prepared_at_ms: u64,
}
impl OriginalPreparation {
    fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            return Err(AuthorityError::UnsupportedVersion);
        }
        self.request.validate()?;
        validate_template(&self.export_plan_template)?;
        for value in [
            &self.original_envelope_digest,
            &self.writer_certificate_digest,
            &self.writer_session_id,
        ] {
            hash(value)?;
        }
        let (issued, expires) = window(
            self.export_plan_template.issued_at_unix_seconds,
            self.export_plan_template.expires_at_unix_seconds,
        )?;
        if issued < self.request.requested_at_ms
            || issued > self.prepared_at_ms
            || self.prepared_at_ms >= expires
            || expires > self.request.admission_expires_at_ms
        {
            return Err(AuthorityError::InvalidBinding);
        }
        encode(self)?;
        Ok(())
    }
    pub(crate) fn prepared_digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:offline-original-preparation:v1", self)
    }
    pub(crate) fn export_stream(&self) -> Result<String> {
        stream_digest(
            &self.request.intent.terms.network_profile_id,
            &self.request.intent.terms.agreement_id,
            &self.export_plan_template.sender_id,
            &self.export_plan_template.recipient_id,
        )
    }
}

/// Bridge copies these exact values from ReceivedArtifact AFTER authenticated
/// HPKE open and exact domain payload validation. This DTO alone is not proof.
/// Keeping it here avoids a cyclic authority -> transport dependency.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalTransportReceipt {
    pub network_profile_id: String,
    pub agreement_id: String,
    pub proposal_id: String,
    pub proposal_revision: u64,
    pub sender_id: String,
    pub recipient_id: String,
    pub artifact_kind: String,
    pub message_id: String,
    pub sequence: u64,
    pub issued_at_unix_seconds: i64,
    pub expires_at_unix_seconds: i64,
    pub sender_key_fingerprint: String,
    pub recipient_key_fingerprint: String,
    pub stream_digest: String,
    pub preview_digest: String,
    pub content_digest: String,
    pub payload_digest: String,
    pub envelope_digest: String,
}
impl OriginalTransportReceipt {
    fn matches(
        &self,
        original: &OriginalPreparation,
        policy: &OfflineEnrollmentPolicy,
    ) -> Result<()> {
        original.validate()?;
        template_for_validation(&original.export_plan_template)?
            .matches_preparation(&original.request, policy)?;
        for value in [
            &self.network_profile_id,
            &self.agreement_id,
            &self.proposal_id,
            &self.sender_id,
            &self.recipient_id,
        ] {
            id(value)?;
        }
        for value in [
            &self.sender_key_fingerprint,
            &self.recipient_key_fingerprint,
            &self.stream_digest,
            &self.preview_digest,
            &self.content_digest,
            &self.payload_digest,
            &self.envelope_digest,
        ] {
            hash(value)?;
        }
        message_id(&self.message_id)?;
        let (issued, expires) = window(self.issued_at_unix_seconds, self.expires_at_unix_seconds)?;
        let t = &original.request.intent.terms;
        if self.sequence == 0
            || self.sequence > i64::MAX as u64
            || self.network_profile_id != t.network_profile_id
            || self.agreement_id != t.agreement_id
            || self.proposal_id != t.proposal_id
            || self.proposal_revision != t.proposal_revision
            || self.artifact_kind != "offline_reservation_intent"
            || self.sender_id != format!("offline-intent:{}", t.offline_signer_key_digest)
            || self.recipient_id != format!("offline-intent:{}", t.offline_policy_digest)
            || self.sender_key_fingerprint != policy.offline_signer_key_digest
            || self.recipient_key_fingerprint != policy.witness_transport_key_digest
            || self.stream_digest
                != stream_digest(
                    &self.network_profile_id,
                    &self.agreement_id,
                    &self.sender_id,
                    &self.recipient_id,
                )?
            || self.envelope_digest != original.original_envelope_digest
            || issued > original.prepared_at_ms
            || original.prepared_at_ms >= expires
        {
            return Err(AuthorityError::Authentication);
        }
        if encode(self)?.len() > MAX_RECEIPT_BYTES {
            return Err(AuthorityError::Limit);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OriginalReceiptRecord {
    pub(crate) schema_version: u16,
    pub(crate) prepared_record_digest: String,
    pub(crate) authenticated_at_ms: u64,
    pub(crate) export_plan: OfflineAdmissionExportPlan,
    pub(crate) receipt: OriginalTransportReceipt,
}
impl OriginalReceiptRecord {
    pub(crate) fn receipt_digest(&self) -> Result<String> {
        if self.schema_version != 1 {
            return Err(AuthorityError::UnsupportedVersion);
        }
        hash(&self.prepared_record_digest)?;
        if encode(self)?.len() > MAX_RECEIPT_BYTES {
            return Err(AuthorityError::Limit);
        }
        digest("wholepact:offline-original-authenticated-receipt:v1", self)
    }
    fn matches(
        &self,
        original: &OriginalPreparation,
        policy: &OfflineEnrollmentPolicy,
    ) -> Result<()> {
        self.receipt.matches(original, policy)?;
        self.export_plan
            .matches_preparation(&original.request, policy)?;
        let mut expected = original.export_plan_template.clone();
        expected.sequence = self.export_plan.sequence;
        if self.export_plan != expected {
            return Err(AuthorityError::CorruptHistory);
        }
        let (issued, expires) = window(
            self.receipt.issued_at_unix_seconds,
            self.receipt.expires_at_unix_seconds,
        )?;
        let (export_issued, export_expires) = window(
            self.export_plan.issued_at_unix_seconds,
            self.export_plan.expires_at_unix_seconds,
        )?;
        if self.prepared_record_digest != original.prepared_digest()?
            || self.authenticated_at_ms < original.prepared_at_ms
            || self.authenticated_at_ms < export_issued
            || self.authenticated_at_ms >= export_expires
            || self.authenticated_at_ms < issued
            || self.authenticated_at_ms >= expires
        {
            return Err(AuthorityError::CorruptHistory);
        }
        self.receipt_digest()?;
        Ok(())
    }
}

/// Exact persisted retry evidence. No public constructor, Deserialize, Clone,
/// Debug, or conversion to AuthenticatedOfflineIntent / an export capability.
/// The original ciphertext must be reauthenticated by the bridge on recovery.
pub struct RetainedOfflineOriginal {
    pub(crate) original: OriginalPreparation,
    pub(crate) envelope: Zeroizing<Vec<u8>>,
    pub(crate) receipt: Option<OriginalReceiptRecord>,
}
impl RetainedOfflineOriginal {
    pub fn request(&self) -> &ReserveOfflineAuthorization {
        &self.original.request
    }
    pub fn export_plan(&self) -> Option<&OfflineAdmissionExportPlan> {
        self.receipt.as_ref().map(|record| &record.export_plan)
    }
    pub fn original_envelope_bytes(&self) -> &[u8] {
        &self.envelope
    }
    pub fn prepared_record_digest(&self) -> Result<String> {
        self.original.prepared_digest()
    }
    pub fn authenticated_receipt(&self) -> Option<&OriginalTransportReceipt> {
        self.receipt.as_ref().map(|record| &record.receipt)
    }
    pub fn authorization_allowed(&self) -> bool {
        false
    }
}

/// Pure event-link values for the parent's eventual atomic commit adapter.
/// DO NOT accept these caller-supplied values as authority. Recompute in the same
/// transaction that authenticates current state and appends the reservation event.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalCommitLink {
    pub prepared_record_digest: String,
    pub authenticated_receipt_digest: String,
    pub reservation_request_digest: String,
    pub export_plan_digest: String,
    pub original_envelope_digest: String,
    pub inbox_acceptance_digest: String,
}

/// Untrusted controller input transport, NOT a portable approval or authority
/// token. Every field is checked by the existing exporter-bound session MAC over
/// the exact retained mutation; possession/decoding grants no permission.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineControllerProofInput {
    pub schema_version: u16,
    pub session_id: String,
    pub tag: String,
}
impl OfflineControllerProofInput {
    fn into_internal(self) -> Result<protocol::WriterSessionProof> {
        if self.schema_version != 1 {
            return Err(AuthorityError::UnsupportedVersion);
        }
        hash(&self.session_id)?;
        hash(&self.tag)?;
        Ok(protocol::WriterSessionProof {
            session_id: self.session_id,
            tag: self.tag,
        })
    }
}

/// Privileged configured bridge handle. No public constructor, Deserialize,
/// Clone or Debug. A future factory MUST require authenticated channel/session,
/// owner-enrolled pinned bridge keys and the concrete encrypted journal/inbox.
/// Possession is confined to that configured bridge; never pass to a controller.
pub struct OfflineOriginalBridge<'a> {
    pub(crate) journal: &'a AuthorityJournal,
    pub(crate) peer: &'a str,
}
impl OfflineOriginalBridge<'_> {
    pub fn prepare(
        &self,
        request: &ReserveOfflineAuthorization,
        envelope: &[u8],
        template: OfflineAdmissionExportPlan,
        now: u64,
    ) -> Result<RetainedOfflineOriginal> {
        self.journal
            .prepare_offline_original(self.peer, request, envelope, template, now)
    }
    pub fn recover(
        &self,
        operation: &str,
        request_digest: &str,
        now: u64,
    ) -> Result<Option<RetainedOfflineOriginal>> {
        self.journal
            .retained_offline_original(self.peer, operation, request_digest, now)
    }
    /// Only after pinned HPKE and exact payload/context validation, inside the
    /// open_envelope_checked callback. Returns only after durable allocation.
    pub fn record_authenticated_receipt(
        &self,
        prepared: &str,
        operation: &str,
        receipt: OriginalTransportReceipt,
        now: u64,
    ) -> Result<()> {
        self.journal
            .record_offline_original_authentication(self.peer, prepared, operation, receipt, now)
    }
    /// Only AFTER actual concrete encrypted inbox acceptance, or successful
    /// recover_received of that same original receipt/ciphertext. HPKE alone,
    /// Replay error, absent inbox row or caller report do not authorize this call.
    pub fn record_inbox_accepted(
        &self,
        prepared: &str,
        operation: &str,
        receipt: OriginalTransportReceipt,
        now: u64,
    ) -> Result<()> {
        self.journal
            .record_offline_inbox_accepted(self.peer, prepared, operation, receipt, now)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OriginalInboxAcceptance {
    schema_version: u16,
    prepared_record_digest: String,
    authenticated_receipt_digest: String,
    accepted_at_ms: u64,
    receipt: OriginalTransportReceipt,
}
impl OriginalInboxAcceptance {
    pub(crate) fn acceptance_digest(&self) -> Result<String> {
        if self.schema_version != 1 {
            return Err(AuthorityError::UnsupportedVersion);
        }
        hash(&self.prepared_record_digest)?;
        hash(&self.authenticated_receipt_digest)?;
        if encode(self)?.len() > MAX_RECEIPT_BYTES {
            return Err(AuthorityError::Limit);
        }
        digest("wholepact:offline-original-inbox-acceptance:v1", self)
    }
}

impl AuthorityJournal {
    fn record_offline_inbox_accepted(
        &self,
        peer: &str,
        prepared: &str,
        operation: &str,
        receipt: OriginalTransportReceipt,
        now: u64,
    ) -> Result<()> {
        self.require_born_mutation_current()?;
        hash(prepared)?;
        id(operation)?;
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate)?;
        crate::journal::authenticate_admission(&tx, peer)?;
        let original = read_original(&tx, operation)?.ok_or(AuthorityError::InvalidBinding)?;
        let ledger = gate(&tx, peer, original.request(), now)?;
        verify_retained(&original, policy_for(&ledger, original.request())?)?;
        let authenticated = original
            .receipt
            .as_ref()
            .ok_or(AuthorityError::Authentication)?;
        if original.prepared_record_digest()? != prepared
            || authenticated.receipt != receipt
            || original.original.writer_certificate_digest != peer
            || ledger
                .snapshot
                .active_writer_session
                .as_ref()
                .map(|s| s.session_id.as_str())
                != Some(original.original.writer_session_id.as_str())
            || now < authenticated.authenticated_at_ms
        {
            return Err(AuthorityError::Authentication);
        }
        if read_inbox_acceptance(&tx, &original)?.is_some() {
            return Ok(());
        }
        let record = OriginalInboxAcceptance {
            schema_version: 1,
            prepared_record_digest: prepared.into(),
            authenticated_receipt_digest: authenticated.receipt_digest()?,
            accepted_at_ms: now,
            receipt,
        };
        let payload = encode(&record)?;
        ensure_capacity(&tx, payload.len(), 0, false)?;
        tx.execute(
            "INSERT INTO authority_offline_inbox_acceptances VALUES(?1,?2,?3)",
            params![prepared, record.acceptance_digest()?, &*payload],
        )?;
        tx.commit()?;
        Ok(())
    }
}

pub(crate) fn require_inbox_acceptance(
    c: &Connection,
    original: &RetainedOfflineOriginal,
) -> Result<OriginalInboxAcceptance> {
    read_inbox_acceptance(c, original)?.ok_or(AuthorityError::Authentication)
}
fn read_inbox_acceptance(
    c: &Connection,
    original: &RetainedOfflineOriginal,
) -> Result<Option<OriginalInboxAcceptance>> {
    let prepared = original.prepared_record_digest()?;
    let raw: Option<(String,Vec<u8>)> = c.query_row(
        "SELECT acceptance_digest,CASE WHEN length(payload)<=16384 THEN payload ELSE NULL END FROM authority_offline_inbox_acceptances WHERE prepared_digest=?1",
        [&prepared], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
    let Some((expected, payload)) = raw else {
        return Ok(None);
    };
    let payload = Zeroizing::new(payload);
    let record: OriginalInboxAcceptance = decode(&payload)?;
    let receipt = original
        .receipt
        .as_ref()
        .ok_or(AuthorityError::CorruptHistory)?;
    if record.acceptance_digest()? != expected
        || record.prepared_record_digest != prepared
        || record.authenticated_receipt_digest != receipt.receipt_digest()?
        || record.receipt != receipt.receipt
        || record.accepted_at_ms < receipt.authenticated_at_ms
        || encode(&record)?.as_slice() != payload.as_slice()
    {
        return Err(AuthorityError::CorruptHistory);
    }
    Ok(Some(record))
}

impl AuthorityJournal {
    /// Phase 1, before invoking open_envelope_checked at all. The caller supplies
    /// sequence=0 as an unallocated sentinel. No outbound sequence is allocated
    /// until the post-authentication callback. The input template's issuance,
    /// message identity and deadlines are never regenerated or extended on retry.
    /// A caller must retain/recover this result, then open THESE exact bytes.
    /// export_plan() remains None until the authenticated callback commits.
    /// No inbound authentication is claimed by this preparation step.
    #[allow(dead_code, clippy::too_many_arguments)]
    pub(crate) fn prepare_offline_original(
        &self,
        peer: &str,
        request: &ReserveOfflineAuthorization,
        envelope: &[u8],
        unallocated_plan: OfflineAdmissionExportPlan,
        now: u64,
    ) -> Result<RetainedOfflineOriginal> {
        self.require_born_mutation_current()?;
        if unallocated_plan.sequence != 0 {
            return Err(AuthorityError::InvalidBinding);
        }
        request.validate()?;
        check_envelope_len(envelope)?;
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate)?;
        let ledger = gate(&tx, peer, request, now)?;
        let policy = policy_for(&ledger, request)?;
        // Retry identity is looked up before sequence allocation. Full exact
        // request/envelope/plan equality is mandatory; a changed head is conflict.
        if let Some(old) = read_original(&tx, &request.operation_id)? {
            if old.original.request != *request
                || old.original.export_plan_template != unallocated_plan
                || old.envelope.as_slice() != envelope
                || old.original.writer_certificate_digest != peer
                || ledger
                    .snapshot
                    .active_writer_session
                    .as_ref()
                    .map(|s| s.session_id.as_str())
                    != Some(old.original.writer_session_id.as_str())
            {
                return Err(AuthorityError::Conflict);
            }
            verify_retained(&old, policy)?;
            return Ok(old);
        }
        if request.expected_head != ledger.snapshot.head {
            return Err(AuthorityError::StaleHead);
        }
        // No operation ID may already name an authority event lacking this source.
        if ledger.operations.contains_key(&request.operation_id) {
            return Err(AuthorityError::Conflict);
        }
        template_for_validation(&unallocated_plan)?.matches_preparation(request, policy)?;
        let session = ledger
            .snapshot
            .active_writer_session
            .as_ref()
            .ok_or(AuthorityError::SessionRequired)?;
        let original = OriginalPreparation {
            schema_version: 1,
            request: request.clone(),
            export_plan_template: unallocated_plan,
            original_envelope_digest: envelope_digest(envelope),
            writer_certificate_digest: peer.into(),
            writer_session_id: session.session_id.clone(),
            prepared_at_ms: now,
        };
        original.validate()?;
        let prepared = original.prepared_digest()?;
        let payload = encode(&original)?;
        ensure_capacity(&tx, payload.len(), envelope.len(), true)?;
        // Constraint conflicts are examined BEFORE insertion to distinguish
        // rebinding/equivocation from an uncertain durable storage outcome.
        let collision: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM authority_offline_originals WHERE intent_id=?1 OR intent_digest=?2 OR authorization_id=?3 OR envelope_digest=?4)",
            params![request.intent.intent_id, request.intent.intent_digest()?,
                request.intent.terms.authorization_id, original.original_envelope_digest], |row| row.get(0))?;
        if collision {
            return Err(AuthorityError::Conflict);
        }
        tx.execute("INSERT INTO authority_offline_originals(operation_id,intent_id,intent_digest,authorization_id,prepared_digest,request_digest,envelope_digest,payload,envelope) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![request.operation_id, request.intent.intent_id, request.intent.intent_digest()?,
                request.intent.terms.authorization_id, prepared, request.request_digest()?,
                original.original_envelope_digest, &*payload, envelope])?;
        tx.commit()?; // FULL synchronous; original input exists before HPKE is attempted.
        Ok(RetainedOfflineOriginal {
            original,
            envelope: Zeroizing::new(envelope.to_vec()),
            receipt: None,
        })
    }

    /// Phase 2: invoke only inside open_envelope_checked's authenticated validation
    /// callback, after exact intent/keys/context equality but BEFORE inbox insert.
    /// This single transaction allocates and retains the full immutable export
    /// plan alongside its authenticated receipt. Invalid ciphertext never reaches
    /// allocation, and no allocation escapes if receipt persistence fails.
    /// Trusted composition is intentionally not provided. This accepts a DTO only
    /// inside authority code; it is not a public callback or authentication factory.
    pub(crate) fn record_offline_original_authentication(
        &self,
        peer: &str,
        expected_prepared_digest: &str,
        operation_id: &str,
        receipt: OriginalTransportReceipt,
        now: u64,
    ) -> Result<()> {
        self.require_born_mutation_current()?;
        hash(expected_prepared_digest)?;
        id(operation_id)?;
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate)?;
        crate::journal::authenticate_admission(&tx, peer)?;
        let retained = read_original(&tx, operation_id)?.ok_or(AuthorityError::InvalidBinding)?;
        let ledger = gate(&tx, peer, &retained.original.request, now)?;
        let policy = policy_for(&ledger, &retained.original.request)?;
        verify_retained(&retained, policy)?;
        if retained.prepared_record_digest()? != expected_prepared_digest
            || retained.original.writer_certificate_digest != peer
            || ledger
                .snapshot
                .active_writer_session
                .as_ref()
                .map(|s| s.session_id.as_str())
                != Some(retained.original.writer_session_id.as_str())
        {
            return Err(AuthorityError::Conflict);
        }
        receipt.matches(&retained.original, policy)?;
        if let Some(old) = &retained.receipt {
            if old.receipt != receipt {
                return Err(AuthorityError::Conflict);
            }
            // Even an exact idempotent callback cannot renew the original window.
            let (_, expiry) = window(
                old.export_plan.issued_at_unix_seconds,
                old.export_plan.expires_at_unix_seconds,
            )?;
            if now >= expiry {
                return Err(AuthorityError::Expired);
            }
            return Ok(()); // Never replace first authenticated_at_ms or receipt.
        }
        if retained.original.request.expected_head != ledger.snapshot.head {
            return Err(AuthorityError::StaleHead);
        }
        let stream = retained.original.export_stream()?;
        let mut export_plan = retained.original.export_plan_template.clone();
        export_plan.sequence = allocate_sequence(&tx, &stream)?;
        export_plan.matches_preparation(&retained.original.request, policy)?;
        let (_, export_expiry) = window(
            export_plan.issued_at_unix_seconds,
            export_plan.expires_at_unix_seconds,
        )?;
        if now >= export_expiry {
            return Err(AuthorityError::Expired);
        }
        let record = OriginalReceiptRecord {
            schema_version: 1,
            prepared_record_digest: expected_prepared_digest.into(),
            authenticated_at_ms: now,
            export_plan,
            receipt,
        };
        record.matches(&retained.original, policy)?;
        let payload = encode(&record)?;
        ensure_capacity(&tx, payload.len(), 0, false)?;
        let collision: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM authority_offline_original_receipts WHERE (original_stream=?1 AND (original_sequence=?2 OR original_message_id=?3)) OR (export_stream=?4 AND export_message_id=?5))",
            params![record.receipt.stream_digest, record.receipt.sequence, record.receipt.message_id,
                stream, record.export_plan.message_id],
            |row| row.get(0))?;
        if collision {
            return Err(AuthorityError::Conflict);
        }
        tx.execute(
            "INSERT INTO authority_offline_original_receipts VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                record.prepared_record_digest,
                record.receipt_digest()?,
                record.receipt.stream_digest,
                record.receipt.sequence,
                record.receipt.message_id,
                stream,
                record.export_plan.sequence,
                record.export_plan.message_id,
                &*payload
            ],
        )?;
        tx.commit()?; // Returning an error must abort the transport validation closure.
        Ok(())
    }

    /// Current runtime retry lookup, not the separate historical audit reader.
    /// Born provenance-only handles cannot select ciphertext for a resume path.
    /// Evidence-only retry lookup. Deliberately rejects expired/inactive/quarantined
    /// runtime use. Separate owner reconciliation may inspect expired history, but
    /// must not resume this route or turn history into a live capability.
    pub(crate) fn retained_offline_original(
        &self,
        peer: &str,
        operation_id: &str,
        expected_request_digest: &str,
        now: u64,
    ) -> Result<Option<RetainedOfflineOriginal>> {
        self.require_born_mutation_current()?;
        id(operation_id)?;
        hash(expected_request_digest)?;
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Deferred)?;
        crate::journal::authenticate_admission(&tx, peer)?;
        let Some(retained) = read_original(&tx, operation_id)? else {
            return Ok(None);
        };
        let ledger = gate(&tx, peer, &retained.original.request, now)?;
        if retained.original.writer_certificate_digest != peer
            || retained.original.request.request_digest()? != expected_request_digest
            || ledger
                .snapshot
                .active_writer_session
                .as_ref()
                .map(|s| s.session_id.as_str())
                != Some(retained.original.writer_session_id.as_str())
        {
            return Err(AuthorityError::Conflict);
        }
        verify_retained(&retained, policy_for(&ledger, &retained.original.request)?)?;
        Ok(Some(retained))
    }
}

/// MUST be invoked by the future commit transaction, never by a caller furnishing
/// independently read evidence. This does not authorize commit or issue a token.
pub(crate) fn original_event_link(
    tx: &Transaction<'_>,
    peer: &str,
    request: &ReserveOfflineAuthorization,
    authentication: &OfflineIntentAuthenticationRecord,
    session_id: &str,
    now: u64,
) -> Result<OriginalCommitLink> {
    let ledger = gate(tx, peer, request, now)?;
    let retained =
        read_original(tx, &request.operation_id)?.ok_or(AuthorityError::InvalidBinding)?;
    let policy = policy_for(&ledger, request)?;
    verify_retained(&retained, policy)?;
    let receipt = retained
        .receipt
        .as_ref()
        .ok_or(AuthorityError::Authentication)?;
    let acceptance = require_inbox_acceptance(tx, &retained)?;
    authentication.matches(request, policy)?;
    crate::offline_outcome::ensure_admission_allowed(tx, &retained.prepared_record_digest()?)?;
    let (issued, expires) = window(
        receipt.export_plan.issued_at_unix_seconds,
        receipt.export_plan.expires_at_unix_seconds,
    )?;
    if retained.request() != request
        || retained.original.writer_certificate_digest != peer
        || retained.original.writer_session_id != session_id
        || ledger
            .snapshot
            .active_writer_session
            .as_ref()
            .map(|s| s.session_id.as_str())
            != Some(session_id)
        || authentication.envelope_digest != retained.original.original_envelope_digest
        || acceptance.accepted_at_ms > now
        || receipt.authenticated_at_ms > now
        || retained.original.prepared_at_ms > now
        || now < issued
        || now >= expires
    {
        return Err(AuthorityError::Conflict);
    }
    retained_link(&retained, &acceptance)
}

/// Historical validation called while the parent reconstructs its pre-event
/// ledger. Policy is that ledger's exact retained enrollment, never a caller's
/// current policy; this helper does not recursively load the authority journal.
pub(crate) fn verify_original_event_link(
    c: &Connection,
    record: &OfflineReservationRecord,
    link: &OriginalCommitLink,
    policy: &OfflineEnrollmentPolicy,
    session_id: &str,
    reserved_at: u64,
) -> Result<()> {
    let retained =
        read_original(c, &record.request.operation_id)?.ok_or(AuthorityError::CorruptHistory)?;
    verify_retained(&retained, policy)?;
    let receipt = retained
        .receipt
        .as_ref()
        .ok_or(AuthorityError::CorruptHistory)?;
    let acceptance = require_inbox_acceptance(c, &retained)?;
    record.authentication.matches(&record.request, policy)?;
    let (issued, expires) = window(
        receipt.export_plan.issued_at_unix_seconds,
        receipt.export_plan.expires_at_unix_seconds,
    )?;
    if retained.request() != &record.request
        || retained.original.writer_session_id != session_id
        || record.authentication.envelope_digest != retained.original.original_envelope_digest
        || retained.original.prepared_at_ms > reserved_at
        || receipt.authenticated_at_ms > reserved_at
        || acceptance.accepted_at_ms > reserved_at
        || reserved_at < issued
        || reserved_at >= expires
        || &retained_link(&retained, &acceptance)? != link
    {
        return Err(AuthorityError::CorruptHistory);
    }
    crate::offline_outcome::verify_no_admission_not_selected(c, &link.prepared_record_digest)?;
    Ok(())
}
fn retained_link(
    retained: &RetainedOfflineOriginal,
    acceptance: &OriginalInboxAcceptance,
) -> Result<OriginalCommitLink> {
    let record = retained
        .receipt
        .as_ref()
        .ok_or(AuthorityError::Authentication)?;
    Ok(OriginalCommitLink {
        prepared_record_digest: retained.prepared_record_digest()?,
        authenticated_receipt_digest: record.receipt_digest()?,
        reservation_request_digest: retained.request().request_digest()?,
        export_plan_digest: record.export_plan.plan_digest()?,
        original_envelope_digest: retained.original.original_envelope_digest.clone(),
        inbox_acceptance_digest: acceptance.acceptance_digest()?,
    })
}

pub(crate) fn original_commit_link(
    tx: &Transaction<'_>,
    peer: &str,
    request: &ReserveOfflineAuthorization,
    authentication: &OfflineIntentAuthenticationRecord,
    admission: &OfflineAuthorizationAdmission,
    now: u64,
) -> Result<OriginalCommitLink> {
    let ledger = gate(tx, peer, request, now)?;
    let retained =
        read_original(tx, &request.operation_id)?.ok_or(AuthorityError::InvalidBinding)?;
    let policy = policy_for(&ledger, request)?;
    verify_retained(&retained, policy)?;
    let record = retained
        .receipt
        .as_ref()
        .ok_or(AuthorityError::Authentication)?;
    let acceptance = require_inbox_acceptance(tx, &retained)?;
    crate::offline_outcome::ensure_admission_allowed(tx, &retained.prepared_record_digest()?)?;
    authentication.matches(request, policy)?;
    admission.matches_request(request)?;
    record.export_plan.matches_commit(admission)?;
    if retained.original.request != *request
        || retained.original.writer_certificate_digest != peer
        || retained.original.writer_session_id != admission.writer_session_id
        || retained.original.prepared_at_ms > admission.reserved_at_ms
        || record.authenticated_at_ms > admission.reserved_at_ms
        || authentication.envelope_digest != retained.original.original_envelope_digest
        || acceptance.accepted_at_ms > admission.reserved_at_ms
        || now != admission.reserved_at_ms
    {
        return Err(AuthorityError::Conflict);
    }
    Ok(OriginalCommitLink {
        prepared_record_digest: retained.prepared_record_digest()?,
        authenticated_receipt_digest: record.receipt_digest()?,
        reservation_request_digest: request.request_digest()?,
        export_plan_digest: record.export_plan.plan_digest()?,
        original_envelope_digest: retained.original.original_envelope_digest,
        inbox_acceptance_digest: acceptance.acceptance_digest()?,
    })
}

fn policy_for<'a>(
    ledger: &'a policy::Ledger,
    request: &ReserveOfflineAuthorization,
) -> Result<&'a OfflineEnrollmentPolicy> {
    ledger
        .offline_policies
        .get(&request.intent.terms.offline_policy_digest)
        .ok_or(AuthorityError::PolicyDenied)
}

pub(crate) fn gate(
    c: &Connection,
    peer: &str,
    request: &ReserveOfflineAuthorization,
    now: u64,
) -> Result<policy::Ledger> {
    crate::journal::authenticate_admission(c, peer)?;
    let ledger = crate::journal::load(c)?;
    let t = &request.intent.terms;
    ledger.authenticate_read(peer, &t.account_id, &t.network_profile_id)?;
    // Never re-export an old execution package after a permanent exclusion.
    ledger
        .account_use_history
        .require_not_permanently_excluded()?;
    if ledger.snapshot.writer_status == WriterStatus::Quarantined {
        return Err(AuthorityError::RecoveryRequired);
    }
    if ledger.snapshot.writer_status != WriterStatus::Active
        || ledger.snapshot.writer_certificate_digest != peer
        || request.writer_epoch != ledger.snapshot.writer_epoch
        || ledger.offline_policy_states.get(&t.enrollment_ref)
            != Some(&(
                t.offline_policy_digest.clone(),
                OfflineEnrollmentStatus::Active,
            ))
    {
        return Err(AuthorityError::Inactive);
    }
    let session = ledger
        .snapshot
        .active_writer_session
        .as_ref()
        .ok_or(AuthorityError::SessionRequired)?;
    ledger.require_unfenced_transport(&session.session_id)?;
    if session.writer_epoch != request.writer_epoch
        || session.writer_certificate_digest != peer
        || !ledger.activated_sessions.contains(&session.session_id)
        || now >= session.expires_at_ms
    {
        return Err(AuthorityError::SessionRequired);
    }
    if now < ledger.snapshot.last_witness_time_ms {
        return Err(AuthorityError::Expired);
    }
    request.validate_policy_bounds(&ledger.policy, policy_for(&ledger, request)?, now)?;
    Ok(ledger)
}

pub(crate) fn verify_retained(
    retained: &RetainedOfflineOriginal,
    policy: &OfflineEnrollmentPolicy,
) -> Result<()> {
    template_for_validation(&retained.original.export_plan_template)?
        .matches_preparation(&retained.original.request, policy)?;
    retained.original.validate()?;
    check_envelope_len(&retained.envelope)?;
    if envelope_digest(&retained.envelope) != retained.original.original_envelope_digest {
        return Err(AuthorityError::CorruptHistory);
    }
    if let Some(record) = &retained.receipt {
        record.matches(&retained.original, policy)?;
    }
    Ok(())
}

pub(crate) fn read_original(
    c: &Connection,
    operation_id: &str,
) -> Result<Option<RetainedOfflineOriginal>> {
    // Check BLOB lengths before materialization; all duplicated indexes are
    // compared to their canonical payload, never treated as independent truth.
    type Raw = (
        String,
        String,
        String,
        String,
        String,
        String,
        Vec<u8>,
        Vec<u8>,
    );
    let raw: Option<Raw> = c.query_row(
        "SELECT prepared_digest,request_digest,envelope_digest,intent_id,intent_digest,authorization_id,CASE WHEN length(payload)<=262144 THEN payload ELSE NULL END,CASE WHEN length(envelope)<=1048576 THEN envelope ELSE NULL END FROM authority_offline_originals WHERE operation_id=?1",
        [operation_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?)))
        .optional()?;
    let Some((
        prepared,
        request,
        envelope_hash,
        intent_id,
        intent_digest,
        authorization_id,
        payload,
        envelope,
    )) = raw
    else {
        return Ok(None);
    };
    let payload = Zeroizing::new(payload);
    let original: OriginalPreparation = decode(&payload)?;
    original.validate()?;
    if encode(&original)?.as_slice() != payload.as_slice()
        || original.request.operation_id != operation_id
        || original.prepared_digest()? != prepared
        || original.request.request_digest()? != request
        || original.original_envelope_digest != envelope_hash
        || original.request.intent.intent_id != intent_id
        || original.request.intent.intent_digest()? != intent_digest
        || original.request.intent.terms.authorization_id != authorization_id
        || envelope_digest(&envelope) != envelope_hash
    {
        return Err(AuthorityError::CorruptHistory);
    }
    type ReceiptRaw = (String, String, u64, String, String, u64, String, Vec<u8>);
    let raw_receipt: Option<ReceiptRaw> = c.query_row(
        "SELECT receipt_digest,original_stream,original_sequence,original_message_id,export_stream,export_sequence,export_message_id,CASE WHEN length(payload)<=16384 THEN payload ELSE NULL END FROM authority_offline_original_receipts WHERE prepared_digest=?1",
        [&prepared], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?))).optional()?;
    let receipt = match raw_receipt {
        None => None,
        Some((
            digest,
            stream,
            sequence,
            message,
            export_stream,
            export_sequence,
            export_message,
            payload,
        )) => {
            let payload = Zeroizing::new(payload);
            let record: OriginalReceiptRecord = decode(&payload)?;
            if encode(&record)?.as_slice() != payload.as_slice()
                || record.prepared_record_digest != prepared
                || record.receipt_digest()? != digest
                || record.receipt.stream_digest != stream
                || record.receipt.sequence != sequence
                || record.receipt.message_id != message
                || original.export_stream()? != export_stream
                || record.export_plan.sequence != export_sequence
                || record.export_plan.message_id != export_message
            {
                return Err(AuthorityError::CorruptHistory);
            }
            Some(record)
        }
    };
    Ok(Some(RetainedOfflineOriginal {
        original,
        envelope: Zeroizing::new(envelope),
        receipt,
    }))
}

fn allocate_sequence(tx: &Transaction<'_>, stream: &str) -> Result<u64> {
    let (last, count): (u64,u64) = tx.query_row(
        "SELECT coalesce(max(export_sequence),0),count(*) FROM authority_offline_original_receipts WHERE export_stream=?1",
        [stream], |r| Ok((r.get(0)?,r.get(1)?)))?;
    // Immutable contiguous rows, including authenticated but uncommitted plans.
    // Unauthenticated input rows are intentionally absent from this allocation.
    // This never consults the outbox's advisory next_sequence.
    if last != count {
        return Err(AuthorityError::CorruptHistory);
    }
    last.checked_add(1)
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or(AuthorityError::Limit)
}

pub(crate) fn ensure_capacity(
    c: &Connection,
    metadata: usize,
    envelope: usize,
    new_row: bool,
) -> Result<()> {
    let (count, bytes): (u64,u64) = c.query_row(
        "SELECT count(*),coalesce(sum(length(payload)+length(envelope)),0)+(SELECT coalesce(sum(length(payload)),0) FROM authority_offline_original_receipts)+(SELECT coalesce(sum(length(payload)),0) FROM authority_offline_inbox_acceptances)+(SELECT coalesce(sum(length(payload)),0) FROM authority_offline_outcomes) FROM authority_offline_originals",
        [], |r| Ok((r.get(0)?,r.get(1)?)))?;
    check_capacity(count, bytes, metadata, envelope, new_row)
}
fn check_capacity(
    count: u64,
    bytes: u64,
    metadata: usize,
    envelope: usize,
    new_row: bool,
) -> Result<()> {
    if (new_row && count >= MAX_ORIGINAL_ROWS)
        || bytes
            .checked_add(metadata as u64)
            .and_then(|v| v.checked_add(envelope as u64))
            .filter(|n| *n <= MAX_ORIGINAL_BYTES)
            .is_none()
    {
        return Err(AuthorityError::Limit);
    }
    Ok(())
}
fn check_envelope_len(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_ORIGINAL_ENVELOPE_BYTES {
        return Err(AuthorityError::Limit);
    }
    Ok(())
}
fn envelope_digest(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"wholepact.encrypted-envelope.v1\0");
    h.update(bytes);
    hex::encode(h.finalize())
}
fn stream_digest(network: &str, agreement: &str, sender: &str, recipient: &str) -> Result<String> {
    for value in [network, agreement, sender, recipient] {
        id(value)?;
    }
    // Exactly the existing transport stream domain/tuple; excludes proposal/kind.
    let bytes = encode(&(network, agreement, sender, recipient))?;
    let mut h = Sha256::new();
    h.update(b"wholepact.transport-stream.v1\0");
    h.update(&*bytes);
    Ok(hex::encode(h.finalize()))
}
fn template_for_validation(
    template: &OfflineAdmissionExportPlan,
) -> Result<OfflineAdmissionExportPlan> {
    if template.sequence != 0 {
        return Err(AuthorityError::InvalidBinding);
    }
    let mut validated = template.clone();
    validated.sequence = 1; // Validation-only stand-in; never persisted or exported.
    validated.validate()?;
    Ok(validated)
}
fn validate_template(template: &OfflineAdmissionExportPlan) -> Result<()> {
    template_for_validation(template).map(|_| ())
}
fn message_id(value: &str) -> Result<()> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(AuthorityError::InvalidBinding);
    }
    Ok(())
}
pub(crate) fn window(start: i64, end: i64) -> Result<(u64, u64)> {
    let ms = |n| {
        u64::try_from(n)
            .ok()
            .and_then(|n: u64| n.checked_mul(1000))
            .ok_or(AuthorityError::InvalidBinding)
    };
    let (start, end) = (ms(start)?, ms(end)?);
    if end <= start || end - start > MAX_WINDOW_MS {
        return Err(AuthorityError::InvalidBinding);
    }
    Ok((start, end))
}

#[cfg(test)]
#[path = "offline_retry_tests.rs"]
mod tests;

impl OfflineOriginalBridge<'_> {
    /// Source-connected private workflow. The bridge handle itself cannot be
    /// constructed by callers. Controller session proof authenticates the exact
    /// original mutation; the journal separately binds durable inbox evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_admission_export(
        &self,
        request: ReserveOfflineAuthorization,
        authentication: AuthenticatedOfflineIntent,
        proof: Option<OfflineControllerProofInput>,
        exporter: &[u8; 32],
        server_certificate: &str,
        now: u64,
    ) -> Result<crate::offline_export::CommittedOfflineAdmissionExport> {
        self.journal.require_born_mutation_current()?;
        let proof = proof
            .map(OfflineControllerProofInput::into_internal)
            .transpose()?;
        let operation = request.operation_id.clone();
        self.journal.commit_offline_prepared(
            self.peer,
            request,
            authentication,
            proof,
            exporter,
            server_certificate,
            now,
        )?;
        self.select_admission_export(&operation, now)
    }
}

/// Copy only into the parent's already-open encrypted quarantined backup
/// transaction. No paths, keys, ATTACH, plaintext handles, or independent commit.
/// All immutable source tables are copied in foreign-key dependency order.
pub(crate) fn copy_offline_state(source: &Connection, destination: &Connection) -> Result<()> {
    ensure_capacity(source, 0, 0, false)?;
    for table in [
        "authority_offline_originals",
        "authority_offline_original_receipts",
        "authority_offline_inbox_acceptances",
        "authority_offline_outcomes",
    ] {
        let count: u64 =
            source.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))?;
        if count > MAX_ORIGINAL_ROWS {
            return Err(AuthorityError::Limit);
        }
    }
    {
        let mut query = source.prepare("SELECT operation_id,intent_id,intent_digest,authorization_id,prepared_digest,request_digest,envelope_digest,CASE WHEN length(payload)<=262144 THEN payload ELSE NULL END,CASE WHEN length(envelope)<=1048576 THEN envelope ELSE NULL END FROM authority_offline_originals ORDER BY operation_id")?;
        let mut rows = query.query([])?;
        while let Some(row) = rows.next()? {
            let operation: String = row.get(0)?;
            id(&operation)?;
            // Canonical record and duplicate indexes are verified before copying.
            let original =
                read_original(source, &operation)?.ok_or(AuthorityError::CorruptHistory)?;
            let payload = Zeroizing::new(row.get::<_, Vec<u8>>(7)?);
            let envelope = Zeroizing::new(row.get::<_, Vec<u8>>(8)?);
            if original.original_envelope_bytes() != envelope.as_slice() {
                return Err(AuthorityError::CorruptHistory);
            }
            destination.execute(
                "INSERT INTO authority_offline_originals VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    operation,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    &*payload,
                    &*envelope
                ],
            )?;
        }
    }
    {
        let mut query = source.prepare("SELECT prepared_digest,receipt_digest,original_stream,original_sequence,original_message_id,export_stream,export_sequence,export_message_id,CASE WHEN length(payload)<=16384 THEN payload ELSE NULL END FROM authority_offline_original_receipts ORDER BY prepared_digest")?;
        let mut rows = query.query([])?;
        while let Some(row) = rows.next()? {
            let payload = Zeroizing::new(row.get::<_, Vec<u8>>(8)?);
            destination.execute("INSERT INTO authority_offline_original_receipts VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,u64>(3)?,
                    row.get::<_,String>(4)?,row.get::<_,String>(5)?,row.get::<_,u64>(6)?,row.get::<_,String>(7)?,&*payload])?;
        }
    }
    {
        let mut query = source.prepare("SELECT prepared_digest,acceptance_digest,CASE WHEN length(payload)<=16384 THEN payload ELSE NULL END FROM authority_offline_inbox_acceptances ORDER BY prepared_digest")?;
        let mut rows = query.query([])?;
        while let Some(row) = rows.next()? {
            let payload = Zeroizing::new(row.get::<_, Vec<u8>>(2)?);
            destination.execute(
                "INSERT INTO authority_offline_inbox_acceptances VALUES(?1,?2,?3)",
                params![
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    &*payload
                ],
            )?;
        }
    }
    {
        let mut query = source.prepare("SELECT prepared_digest,outcome_kind,decision_digest,emission_may_have_started,CASE WHEN length(payload)<=262144 THEN payload ELSE NULL END FROM authority_offline_outcomes ORDER BY prepared_digest")?;
        let mut rows = query.query([])?;
        while let Some(row) = rows.next()? {
            let payload = Zeroizing::new(row.get::<_, Vec<u8>>(4)?);
            destination.execute(
                "INSERT INTO authority_offline_outcomes VALUES(?1,?2,?3,?4,?5)",
                params![
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    &*payload
                ],
            )?;
        }
    }
    Ok(())
}

/// Full version-4 reopen/backup verification. Parent calls only after ordinary
/// authority history is reconstructed; never recursively invokes journal::load.
pub(crate) fn verify_offline_state(c: &Connection, ledger: &policy::Ledger) -> Result<()> {
    ensure_capacity(c, 0, 0, false)?;
    for table in [
        "authority_offline_originals",
        "authority_offline_original_receipts",
        "authority_offline_inbox_acceptances",
        "authority_offline_outcomes",
    ] {
        let count: u64 = c.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))?;
        if count > MAX_ORIGINAL_ROWS {
            return Err(AuthorityError::Limit);
        }
    }
    let mut foreign = c.prepare("PRAGMA foreign_key_check")?;
    if foreign.query([])?.next()?.is_some() {
        return Err(AuthorityError::CorruptHistory);
    }
    let mut rows =
        c.prepare("SELECT operation_id FROM authority_offline_originals ORDER BY operation_id")?;
    let mut rows = rows.query([])?;
    while let Some(row) = rows.next()? {
        let operation: String = row.get(0)?;
        id(&operation)?;
        let retained = read_original(c, &operation)?.ok_or(AuthorityError::CorruptHistory)?;
        let policy = policy_for(ledger, retained.request())?;
        verify_retained(&retained, policy)?;
        retained.request().validate_policy_bounds(
            &ledger.policy,
            policy,
            retained.original.prepared_at_ms,
        )?;
        if !ledger
            .admitted_certificates()
            .contains(retained.original.writer_certificate_digest.as_str())
        {
            return Err(AuthorityError::CorruptHistory);
        }
        let session = ledger
            .sessions
            .get(&retained.original.writer_session_id)
            .ok_or(AuthorityError::CorruptHistory)?;
        if session.writer_certificate_digest != retained.original.writer_certificate_digest
            || session.writer_epoch != retained.request().writer_epoch
            || session.acquired_head.sequence > retained.request().expected_head.sequence
            || retained.original.prepared_at_ms >= session.expires_at_ms
        {
            return Err(AuthorityError::CorruptHistory);
        }
        read_inbox_acceptance(c, &retained)?;
        crate::offline_outcome::verify_retained_outcome(c, ledger, &retained)?;
    }
    let mut streams = c.prepare("SELECT export_stream,max(export_sequence),count(*) FROM authority_offline_original_receipts GROUP BY export_stream")?;
    let mut rows = streams.query([])?;
    while let Some(row) = rows.next()? {
        hash(&row.get::<_, String>(0)?)?;
        if row.get::<_, u64>(1)? != row.get::<_, u64>(2)? {
            return Err(AuthorityError::CorruptHistory);
        }
    }
    Ok(())
}
