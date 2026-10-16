// Durable ciphertext outbox. Transport delivery never releases signer authority,
// broadcasts a transaction, or establishes settlement. No network I/O occurs here.
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};
use wholepact_storage_security::DatabaseFileIdentity;

pub(crate) const OUTBOX_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS outbox (
                stream TEXT NOT NULL, sequence INTEGER NOT NULL CHECK(sequence > 0),
                message_digest TEXT NOT NULL, preview_digest TEXT NOT NULL, context_digest TEXT NOT NULL,
                sender_fingerprint TEXT NOT NULL, recipient_fingerprint TEXT NOT NULL,
                payload_digest TEXT NOT NULL, slot TEXT, envelope_digest TEXT NOT NULL,
                issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, envelope BLOB NOT NULL,
                acknowledged INTEGER NOT NULL DEFAULT 0 CHECK(acknowledged IN (0,1)),
                PRIMARY KEY(stream,sequence), UNIQUE(stream,message_digest));
             CREATE INDEX IF NOT EXISTS outbox_slot ON outbox(slot);";

const APPLICATION_ID: i64 = 0x57504f42;
const RECEIPT_FIELD: &str = "delivery_receipt_v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryStatus {
    AwaitingRecipientReceipt,
    RecipientReceiptRecorded,
}

/// Exact persisted ciphertext. Retrying these bytes cannot create new transaction
/// authorization. Its status refers only to recipient transport receipt.
pub struct OutboxArtifact {
    envelope: EncryptedEnvelope,
    sequence: u64,
    preview_digest: String,
    issued_at: i64,
    expires_at: i64,
    status: DeliveryStatus,
}
impl OutboxArtifact {
    pub fn envelope(&self) -> &EncryptedEnvelope {
        &self.envelope
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn preview_digest(&self) -> &str {
        &self.preview_digest
    }
    pub fn delivery_status(&self) -> DeliveryStatus {
        self.status
    }
    pub fn is_currently_valid(&self, now: &Timestamp) -> bool {
        now.unix_seconds() >= self.issued_at && now.unix_seconds() < self.expires_at
    }
    pub fn authorization_allowed(&self) -> bool {
        false
    }
}

/// Protected local storage, not an authenticated remote endpoint. An embedding
/// service must authenticate its client and enforce agreement/disclose capabilities
/// before using these methods. Public key possession alone grants no access.
pub struct SqliteOutbox {
    pub(crate) connection: Connection,
    protection: MailboxProtection,
    identity: Option<DatabaseFileIdentity>,
}
impl SqliteOutbox {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(path) {
                Ok(file) => file.sync_all().map_err(|_| TransportError::Storage)?,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(TransportError::Storage),
            }
        }
        let connection = Connection::open(path).map_err(|_| TransportError::Storage)?;
        Self::from_connection(
            connection,
            MailboxProtection::CiphertextOnlyMetadataUnencrypted,
            None,
        )
    }

    /// Accept only a connection keyed and authenticated by the pinned SQLCipher
    /// factory. This neither generates credentials nor migrates a plaintext file.
    pub fn from_encrypted_connection(
        connection: wholepact_storage_security::EncryptedConnection,
    ) -> Result<Self> {
        let identity = connection
            .database_identity()
            .map_err(|_| TransportError::Storage)?;
        Self::from_connection(
            connection.into_connection(),
            MailboxProtection::Encrypted,
            Some(identity),
        )
    }

    pub fn protection(&self) -> MailboxProtection {
        self.protection
    }

    /// Read-only identity derived from this live authenticated database handle.
    /// No caller-supplied path, key digest, authorization or writer is exposed.
    pub fn database_identity(&self) -> Result<DatabaseFileIdentity> {
        if self.protection != MailboxProtection::Encrypted {
            return Err(TransportError::AuthorityUnavailable);
        }
        let identity = self
            .identity
            .as_ref()
            .ok_or(TransportError::AuthorityUnavailable)?;
        identity
            .check_current(&self.connection)
            .map_err(|_| TransportError::Storage)?;
        Ok(identity.clone())
    }

    fn from_connection(
        connection: Connection,
        protection: MailboxProtection,
        identity: Option<DatabaseFileIdentity>,
    ) -> Result<Self> {
        if let Some(identity) = &identity {
            identity
                .check_current(&connection)
                .map_err(|_| TransportError::Storage)?;
        }
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|_| TransportError::Storage)?;
        let application: i64 = connection
            .pragma_query_value(None, "application_id", |r| r.get(0))
            .map_err(|_| TransportError::Storage)?;
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(|_| TransportError::Storage)?;
        let tables: i64 = connection.query_row("SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT GLOB 'sqlite_*'", [], |r| r.get(0)).map_err(|_| TransportError::Storage)?;
        if !((application == 0 && version == 0 && tables == 0)
            || (application == APPLICATION_ID && version == 1))
        {
            return Err(TransportError::UnsupportedVersion);
        }
        connection.execute_batch(
            &format!("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; BEGIN IMMEDIATE; {OUTBOX_SCHEMA} PRAGMA application_id=1464880962; PRAGMA user_version=1; COMMIT;")
        ).map_err(|_| TransportError::Storage)?;
        let journal: String = connection
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .map_err(|_| TransportError::Storage)?;
        let synchronous: i64 = connection
            .pragma_query_value(None, "synchronous", |r| r.get(0))
            .map_err(|_| TransportError::Storage)?;
        if !journal.eq_ignore_ascii_case("wal") || synchronous != 2 {
            return Err(TransportError::Storage);
        }
        Ok(Self {
            connection,
            protection,
            identity,
        })
    }

    /// Advisory sequence for preview preparation; commit rechecks under an immediate
    /// transaction. Concurrent previews may race, but a loser is never exported.
    /// No sequence is reserved until ciphertext and metadata durably commit.
    pub fn next_sequence(&self, context: &MessageContext) -> Result<u64> {
        let stream = stream_digest(context)?;
        let last: i64 = self
            .connection
            .query_row(
                "SELECT coalesce(max(sequence),0) FROM outbox WHERE stream=?1",
                [stream],
                |r| r.get(0),
            )
            .map_err(|_| TransportError::Storage)?;
        next_sequence(last)
    }

    /// Commit encrypted bytes before handing them to any delivery adapter. Consent
    /// must originate in the trusted disclosure UI. Authorization artifacts require
    /// the separate opaque installed-signer release adapter below.
    pub fn enqueue(
        &mut self,
        prepared: PreparedExport,
        sender: &TransportSecret,
        approved_preview_digest: &str,
        now: &Timestamp,
    ) -> Result<OutboxArtifact> {
        let preview = prepared.preview().clone();
        if requires_qualified_export(preview.context.artifact_kind) {
            return Err(TransportError::AuthorityUnavailable);
        }
        self.enqueue_validated(prepared, sender, approved_preview_digest, now)
    }

    // Only guarded in-crate adapters enter this exact-ciphertext journal:
    // generic non-authorization, sealed signer release, or opaque post-commit
    // offline admission/control with its authority-retained original export plan.
    pub(crate) fn enqueue_validated(
        &mut self,
        prepared: PreparedExport,
        sender: &TransportSecret,
        approved_preview_digest: &str,
        now: &Timestamp,
    ) -> Result<OutboxArtifact> {
        if self.identity.is_some() {
            self.database_identity()?;
        }
        let preview = prepared.preview().clone();
        validate_order(&preview.order, now)?;
        let preview_digest = preview.digest()?;
        if approved_preview_digest != preview_digest
            || sender.public_key()?.fingerprint() != preview.sender_key_fingerprint
        {
            return Err(TransportError::DisclosureDenied);
        }
        let stream = stream_digest(&preview.context)?;
        let context_digest = context_digest(&preview.context)?;
        let message_digest = message_digest(&preview.order.message_id);
        let slot = immutable_slot(&preview.context, &stream)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| TransportError::Storage)?;
        let prior: Option<(i64, String, String)> = tx.query_row(
            "SELECT sequence, substr(message_digest,1,65), substr(preview_digest,1,65) FROM outbox
             WHERE stream=?1 AND (sequence=?2 OR message_digest=?3) LIMIT 1",
            params![stream, preview.order.sequence as i64, message_digest], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).optional().map_err(|_| TransportError::Storage)?;
        if let Some((sequence, message, previous)) = prior {
            if sequence != preview.order.sequence as i64
                || message != message_digest
                || previous != preview_digest
            {
                return Err(TransportError::Equivocation);
            }
            return load(
                &tx,
                &stream,
                preview.order.sequence,
                &context_digest,
                &preview.recipient_key_fingerprint,
            )?
            .ok_or(TransportError::Storage);
        }
        if let Some(slot) = &slot {
            let prior: Option<String> = tx
                .query_row(
                    "SELECT substr(payload_digest,1,65) FROM outbox WHERE slot=?1 LIMIT 1",
                    [slot],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|_| TransportError::Storage)?;
            if let Some(prior) = prior {
                return Err(if prior == preview.payload_digest {
                    TransportError::Replay
                } else {
                    TransportError::Equivocation
                });
            }
        }
        let last: i64 = tx
            .query_row(
                "SELECT coalesce(max(sequence),0) FROM outbox WHERE stream=?1",
                [&stream],
                |r| r.get(0),
            )
            .map_err(|_| TransportError::Storage)?;
        if next_sequence(last)? != preview.order.sequence {
            return Err(TransportError::OutOfOrder);
        }
        let (count, streams, bytes): (i64, i64, i64) = tx.query_row(
            "SELECT count(*), count(DISTINCT stream), coalesce(sum(length(envelope)),0) FROM outbox", [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).map_err(|_| TransportError::Storage)?;
        if count >= MAX_REPLAY_RECORDS as i64 || (last == 0 && streams >= MAX_REPLAY_STREAMS as i64)
        {
            return Err(TransportError::ResourceLimit);
        }
        let envelope = seal_for_journal(prepared, sender, approved_preview_digest, now)?;
        if bytes + envelope.as_bytes().len() as i64 > MAX_ENCRYPTED_INBOX_BYTES as i64 {
            return Err(TransportError::ResourceLimit);
        }
        let envelope_digest = digest(b"wholepact.encrypted-envelope.v1\0", envelope.as_bytes());
        tx.execute(
            "INSERT INTO outbox(stream, sequence, message_digest, preview_digest, context_digest,
             sender_fingerprint, recipient_fingerprint, payload_digest, slot, envelope_digest, issued_at, expires_at, envelope)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![stream, preview.order.sequence as i64, message_digest, preview_digest, context_digest,
                preview.sender_key_fingerprint, preview.recipient_key_fingerprint, preview.payload_digest, slot,
                envelope_digest, preview.order.issued_at.unix_seconds(), preview.order.expires_at.unix_seconds(), envelope.as_bytes()],
        ).map_err(|_| TransportError::Storage)?;
        tx.commit().map_err(|_| TransportError::Storage)?;
        Ok(OutboxArtifact {
            envelope,
            sequence: preview.order.sequence,
            preview_digest,
            issued_at: preview.order.issued_at.unix_seconds(),
            expires_at: preview.order.expires_at.unix_seconds(),
            status: DeliveryStatus::AwaitingRecipientReceipt,
        })
    }

    /// Exact recipient/proposal/type-scoped ciphertext recovery. Requires the same
    /// independently pinned recipient key; never broadens an old disclosure. May
    /// return expired history, which cannot be imported as a new current delivery.
    pub fn recover_for_recipient(
        &self,
        context: &MessageContext,
        recipient: &TransportPublicKey,
        sequence: u64,
    ) -> Result<Option<OutboxArtifact>> {
        if sequence == 0 || sequence > i64::MAX as u64 {
            return Err(TransportError::Malformed);
        }
        if self.identity.is_some() {
            self.database_identity()?;
        }
        load(
            &self.connection,
            &stream_digest(context)?,
            sequence,
            &context_digest(context)?,
            &recipient.fingerprint(),
        )
    }

    /// Reports unacknowledged sequences for the stream and exact pinned recipient.
    /// A missing acknowledgment means delivery is unknown, not that no one has it.
    pub fn pending_sequences(
        &self,
        context: &MessageContext,
        recipient: &TransportPublicKey,
    ) -> Result<Vec<u64>> {
        let mut statement = self.connection.prepare(
            "SELECT sequence FROM outbox WHERE stream=?1 AND recipient_fingerprint=?2 AND acknowledged=0 ORDER BY sequence LIMIT ?3",
        ).map_err(|_| TransportError::Storage)?;
        let rows = statement
            .query_map(
                params![
                    stream_digest(context)?,
                    recipient.fingerprint(),
                    MAX_REPLAY_RECORDS as i64 + 1
                ],
                |r| r.get::<_, i64>(0),
            )
            .map_err(|_| TransportError::Storage)?;
        let mut sequences = Vec::new();
        for row in rows {
            let sequence = row.map_err(|_| TransportError::Storage)?;
            if sequence < 1 {
                return Err(TransportError::Storage);
            }
            if sequences.len() >= MAX_REPLAY_RECORDS {
                return Err(TransportError::ResourceLimit);
            }
            sequences.push(sequence as u64);
        }
        Ok(sequences)
    }

    /// Only an HPKE-authenticated message from the original recipient, addressed
    /// back to the original sender, can mark exact ciphertext received. This says
    /// nothing about domain acceptance, disclosure approval or settlement.
    pub fn record_acknowledgment(&mut self, artifact: &ReceivedArtifact) -> Result<DeliveryStatus> {
        let receipt = read_receipt(artifact)?;
        let stream = stream_digest(&receipt.original_context)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| TransportError::Storage)?;
        let row: Option<(String, String, String, String, String, String)> = tx.query_row(
            "SELECT substr(message_digest,1,65), substr(preview_digest,1,65), substr(context_digest,1,65),
             substr(sender_fingerprint,1,65), substr(recipient_fingerprint,1,65), substr(envelope_digest,1,65)
             FROM outbox WHERE stream=?1 AND sequence=?2", params![stream, receipt.sequence as i64],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        ).optional().map_err(|_| TransportError::Storage)?;
        let (message, preview, context, sender, recipient, envelope) =
            row.ok_or(TransportError::WrongContext)?;
        if message != message_digest(&receipt.message_id)
            || preview != receipt.preview_digest
            || context != context_digest(&receipt.original_context)?
            || sender != artifact.preview().recipient_key_fingerprint
            || recipient != artifact.preview().sender_key_fingerprint
            || envelope != receipt.envelope_digest
        {
            return Err(TransportError::Authentication);
        }
        tx.execute(
            "UPDATE outbox SET acknowledged=1 WHERE stream=?1 AND sequence=?2",
            params![stream, receipt.sequence as i64],
        )
        .map_err(|_| TransportError::Storage)?;
        tx.commit().map_err(|_| TransportError::Storage)?;
        Ok(DeliveryStatus::RecipientReceiptRecorded)
    }
}

fn next_sequence(last: i64) -> Result<u64> {
    if last < 0 {
        return Err(TransportError::Storage);
    }
    last.checked_add(1)
        .map(|v| v as u64)
        .ok_or(TransportError::ResourceLimit)
}
fn context_digest(context: &MessageContext) -> Result<String> {
    validate_context(context)?;
    Ok(digest(b"wholepact.outbox-context.v1\0", &encode(context)?))
}
fn message_digest(id: &str) -> String {
    digest(b"wholepact.transport-message.v1\0", id.as_bytes())
}
fn immutable_slot(context: &MessageContext, stream: &str) -> Result<Option<String>> {
    if !immutable_kind(context.artifact_kind) {
        return Ok(None);
    }
    Ok(Some(digest(
        b"wholepact.transport-slot.v1\0",
        &encode(&(
            stream,
            &context.proposal_id,
            context.proposal_revision,
            context.artifact_kind,
        ))?,
    )))
}
fn load(
    connection: &Connection,
    stream: &str,
    sequence: u64,
    context: &str,
    recipient: &str,
) -> Result<Option<OutboxArtifact>> {
    type Row = (Option<Vec<u8>>, String, String, i64, i64, i64);
    let row: Option<Row> = connection.query_row(
        "SELECT CASE WHEN length(envelope)<=?5 THEN envelope ELSE NULL END,
         substr(preview_digest,1,65), substr(envelope_digest,1,65), issued_at, expires_at, acknowledged FROM outbox
         WHERE stream=?1 AND sequence=?2 AND context_digest=?3 AND recipient_fingerprint=?4",
        params![stream, sequence as i64, context, recipient, MAX_FILE_BYTES as i64],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
    ).optional().map_err(|_| TransportError::Storage)?;
    row.map(
        |(bytes, preview_digest, envelope_digest, issued_at, expires_at, acknowledged)| {
            if issued_at < 0
                || expires_at <= issued_at
                || expires_at - issued_at > MAX_MESSAGE_LIFETIME_SECONDS
            {
                return Err(TransportError::Storage);
            }
            let bytes = bytes.ok_or(TransportError::ResourceLimit)?;
            validate_hex(&preview_digest, 32).map_err(|_| TransportError::Storage)?;
            if digest(b"wholepact.encrypted-envelope.v1\0", &bytes) != envelope_digest {
                return Err(TransportError::Authentication);
            }
            let status = match acknowledged {
                0 => DeliveryStatus::AwaitingRecipientReceipt,
                1 => DeliveryStatus::RecipientReceiptRecorded,
                _ => return Err(TransportError::Storage),
            };
            Ok(OutboxArtifact {
                envelope: EncryptedEnvelope::from_bytes(bytes)?,
                sequence,
                preview_digest,
                issued_at,
                expires_at,
                status,
            })
        },
    )
    .transpose()
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryReceipt {
    schema_version: u16,
    original_context: MessageContext,
    sequence: u64,
    message_id: String,
    envelope_digest: String,
    preview_digest: String,
}

/// Prepare a separate, explicitly consented recipient acknowledgment. The source
/// must already have passed authenticated durable inbox acceptance. No automatic
/// reply or network send is performed, and acknowledgments are not acknowledged.
pub fn prepare_delivery_acknowledgment(
    received: &ReceivedArtifact,
    request: ExportRequest,
    sender: &TransportPublicKey,
    recipient: &TransportPublicKey,
    now: &Timestamp,
) -> Result<PreparedExport> {
    let preview = received.preview();
    validate_reverse_context(&preview.context, &request.context)?;
    if sender.fingerprint() != preview.recipient_key_fingerprint
        || recipient.fingerprint() != preview.sender_key_fingerprint
    {
        return Err(TransportError::Authentication);
    }
    let receipt = DeliveryReceipt {
        schema_version: SCHEMA_VERSION,
        original_context: preview.context.clone(),
        sequence: preview.order.sequence,
        message_id: preview.order.message_id.clone(),
        envelope_digest: received.envelope_digest().into(),
        preview_digest: preview.digest()?,
    };
    prepare_export(
        request,
        vec![DisclosureField::new(RECEIPT_FIELD, encode(&receipt)?)?],
        sender,
        recipient,
        now,
    )
}
fn read_receipt(received: &ReceivedArtifact) -> Result<DeliveryReceipt> {
    if received.fields().len() != 1 || received.fields()[0].name() != RECEIPT_FIELD {
        return Err(TransportError::Malformed);
    }
    let receipt: DeliveryReceipt = parse(received.fields()[0].bytes())?;
    if receipt.schema_version != SCHEMA_VERSION {
        return Err(TransportError::UnsupportedVersion);
    }
    if receipt.sequence == 0 || receipt.sequence > i64::MAX as u64 {
        return Err(TransportError::Malformed);
    }
    validate_hex(&receipt.message_id, 16)?;
    validate_hex(&receipt.envelope_digest, 32)?;
    validate_hex(&receipt.preview_digest, 32)?;
    validate_reverse_context(&receipt.original_context, &received.preview().context)?;
    Ok(receipt)
}
fn validate_reverse_context(
    original: &MessageContext,
    acknowledgment: &MessageContext,
) -> Result<()> {
    validate_context(original)?;
    validate_context(acknowledgment)?;
    if original.artifact_kind == ArtifactKind::DeliveryAcknowledgment {
        return Err(TransportError::WrongContext);
    }
    let mut expected = original.clone();
    std::mem::swap(&mut expected.sender_id, &mut expected.recipient_id);
    expected.artifact_kind = ArtifactKind::DeliveryAcknowledgment;
    if acknowledgment.recipient_id != expected.recipient_id {
        return Err(TransportError::WrongRecipient);
    }
    if acknowledgment.network_profile_id != expected.network_profile_id {
        return Err(TransportError::WrongNetwork);
    }
    if acknowledgment != &expected {
        return Err(TransportError::WrongContext);
    }
    Ok(())
}

// Private, shared deterministic contract. These mirror transport's validation
// and digest rules; golden/source parity tests pin every ledger key. They do not
// authenticate a user, mint an authority capability or expose a journal writer.
fn requires_qualified_export(kind: ArtifactKind) -> bool {
    kind.requires_qualified_export()
}
fn immutable_kind(kind: ArtifactKind) -> bool {
    kind.immutable_slot()
}
fn validate_context(context: &MessageContext) -> Result<()> {
    if context.proposal_revision == 0 || context.proposal_revision > i64::MAX as u64 {
        return Err(TransportError::Malformed);
    }
    for value in [
        &context.network_profile_id,
        &context.agreement_id,
        &context.proposal_id,
        &context.sender_id,
        &context.recipient_id,
    ] {
        validate_id(value)?;
    }
    Ok(())
}
fn validate_order(order: &MessageOrder, now: &Timestamp) -> Result<()> {
    validate_hex(&order.message_id, 16)?;
    if order.sequence == 0 || order.sequence > i64::MAX as u64 {
        return Err(TransportError::Malformed);
    }
    let start = order.issued_at.unix_seconds();
    let end = order.expires_at.unix_seconds();
    if end <= start
        || end - start > MAX_MESSAGE_LIFETIME_SECONDS
        || now.unix_seconds() < start
        || now.unix_seconds() >= end
    {
        return Err(TransportError::InvalidTime);
    }
    Ok(())
}
fn validate_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.:".contains(&c))
    {
        return Err(TransportError::Malformed);
    }
    Ok(())
}
fn validate_hex(value: &str, bytes: usize) -> Result<()> {
    if value.len() != bytes * 2
        || !value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(TransportError::Malformed);
    }
    Ok(())
}
fn digest(domain: &[u8], value: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(value);
    hex::encode(hash.finalize())
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| TransportError::Malformed)
}
fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err(TransportError::ResourceLimit);
    }
    wholepact_core::parse_typed_json(bytes).map_err(|error| match error.code {
        wholepact_core::ErrorCode::ResourceLimit => TransportError::ResourceLimit,
        _ => TransportError::Malformed,
    })
}
fn stream_digest(context: &MessageContext) -> Result<String> {
    validate_context(context)?;
    Ok(digest(
        b"wholepact.transport-stream.v1\0",
        &encode(&(
            &context.network_profile_id,
            &context.agreement_id,
            &context.sender_id,
            &context.recipient_id,
        ))?,
    ))
}


// Synthetic protected-storage boundary tests only. No account, network,
// signing, proof execution, enrollment or live credential is created.
#[cfg(all(test, target_os = "linux"))]
mod internal_name_filter_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use wholepact_storage_security::{DatabaseKey, create_encrypted, open_encrypted};
    struct Temp(std::path::PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "wholepact-schema-SqliteOutbox-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn sqlite_prefix_user_table_and_trigger_cannot_admit_initialization() {
        for trigger in [false, true] {
            let dir = Temp::new();
            let path = dir.0.join("synthetic.sqlite");
            let key = DatabaseKey::from_bytes([0x75; 32]);
            let encrypted = create_encrypted(&path, &key).unwrap();
            encrypted.connection().execute_batch("CREATE TABLE sqliteXextra(value TEXT); INSERT INTO sqliteXextra VALUES('synthetic-preserved');").unwrap();
            if trigger {
                encrypted.connection().execute_batch("CREATE TRIGGER sqliteXtrigger AFTER INSERT ON sqliteXextra BEGIN SELECT 1; END;").unwrap();
            }
            assert!(matches!(
                SqliteOutbox::from_encrypted_connection(encrypted),
                Err(TransportError::UnsupportedVersion)
            ));
            let reopened = open_encrypted(&path, &key).unwrap();
            let c = reopened.connection();
            let app: i64 = c
                .pragma_query_value(None, "application_id", |r| r.get(0))
                .unwrap();
            let version: i64 = c
                .pragma_query_value(None, "user_version", |r| r.get(0))
                .unwrap();
            assert_eq!((app, version), (0, 0));
            let preserved: String = c
                .query_row("SELECT value FROM sqliteXextra", [], |r| r.get(0))
                .unwrap();
            assert_eq!(preserved, "synthetic-preserved");
            let initialized: bool = c
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='outbox')",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(!initialized);
        }
    }
    #[test]
    fn legitimate_sqlite_internal_objects_allow_initialization_and_exact_reopen() {
        let dir = Temp::new();
        let path = dir.0.join("synthetic.sqlite");
        let key = DatabaseKey::from_bytes([0x76; 32]);
        let encrypted = create_encrypted(&path, &key).unwrap();
        encrypted.connection().execute_batch("ANALYZE;").unwrap();
        let stats: bool = encrypted
            .connection()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='sqlite_stat1')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(stats);
        let journal = SqliteOutbox::from_encrypted_connection(encrypted).unwrap();
        drop(journal);
        let reopened = open_encrypted(&path, &key).unwrap();
        reopened.connection().execute_batch("ANALYZE;").unwrap();
        let journal = SqliteOutbox::from_encrypted_connection(reopened).unwrap();
        drop(journal);
    }
}
