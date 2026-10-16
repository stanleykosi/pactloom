use super::{EncryptedEnvelope, types::*};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::{path::Path, time::Duration};

pub const MAX_REPLAY_RECORDS: usize = 8192;
pub const MAX_REPLAY_STREAMS: usize = 512;
pub const MAX_ENCRYPTED_INBOX_BYTES: usize = 64 * 1024 * 1024;

/// Constructed only after decrypting and checking the entire envelope. It contains
/// hashed metadata, not payload bytes or transaction authorization evidence.
pub struct AuthenticatedReceipt {
    stream: String,
    slot: Option<String>,
    message_id_digest: String,
    sequence: u64,
    content_digest: String,
    payload_digest: String,
    envelope_digest: String,
}
impl AuthenticatedReceipt {
    pub(crate) fn new(
        preview: &DisclosurePreview,
        plaintext: &[u8],
        envelope: &[u8],
    ) -> Result<Self> {
        let c = &preview.context;
        let stream = stream_digest(c)?;
        let slot = if c.artifact_kind.immutable_slot() {
            Some(digest(
                b"wholepact.transport-slot.v1\0",
                &encode(&(
                    &stream,
                    &c.proposal_id,
                    c.proposal_revision,
                    c.artifact_kind,
                ))?,
            ))
        } else {
            None
        };
        Ok(Self {
            stream,
            slot,
            message_id_digest: digest(
                b"wholepact.transport-message.v1\0",
                preview.order.message_id.as_bytes(),
            ),
            sequence: preview.order.sequence,
            content_digest: digest(b"wholepact.authenticated-message.v1\0", plaintext),
            payload_digest: preview.payload_digest.clone(),
            envelope_digest: digest(b"wholepact.encrypted-envelope.v1\0", envelope),
        })
    }
    pub fn stream_digest(&self) -> &str {
        &self.stream
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }
    pub fn message_id_digest(&self) -> &str {
        &self.message_id_digest
    }
    pub fn immutable_slot_digest(&self) -> Option<&str> {
        self.slot.as_deref()
    }
    pub fn payload_digest(&self) -> &str {
        &self.payload_digest
    }
    pub fn envelope_digest(&self) -> &str {
        &self.envelope_digest
    }
}

/// Integration boundary. Implementations must durably and atomically compare and
/// insert replay/ordering/immutable-slot records AND retain encrypted inbox bytes
/// (or commit the complete domain import) before returning success. A bare in-memory
/// set does not meet this contract. Do not evict live replay history automatically.
pub trait ReplayLedger {
    fn accept_authenticated(
        &mut self,
        receipt: &AuthenticatedReceipt,
        envelope: &[u8],
    ) -> Result<()>;
}

/// Independently usable bounded SQLite inbox. It stores ciphertext and hashed
/// metadata; it is not the signer authority journal. New files are private on Unix.
/// File locking is not multi-device fencing and copied/stale ledgers are unsafe for
/// new authority decisions. Keep the ledger in a protected local directory.
pub use wholepact_storage_security::DatabaseFileIdentity as InboxDatabaseIdentity;

pub struct SqliteReplayLedger {
    pub(crate) connection: Connection,
    protection: MailboxProtection,
    identity: Option<InboxDatabaseIdentity>,
}

/// A receipt-backed encrypted record returned only by the durable inbox. Its
/// recovery API yields previously accepted content, never a fresh delivery.
pub struct RetainedEnvelope {
    pub(crate) envelope: EncryptedEnvelope,
    pub(crate) stream: String,
    pub(crate) sequence: u64,
    pub(crate) content_digest: String,
}
impl RetainedEnvelope {
    pub fn stream_digest(&self) -> &str {
        &self.stream
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub(crate) fn matches(&self, receipt: &AuthenticatedReceipt) -> bool {
        self.stream == receipt.stream
            && self.sequence == receipt.sequence
            && self.content_digest == receipt.content_digest
    }
}
impl SqliteReplayLedger {
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

    /// Exact live authenticated file identity, with fail-closed moved-file check.
    /// Historical receipt data cannot construct this identity or grant a writer.
    pub fn database_identity(&self) -> Result<InboxDatabaseIdentity> {
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
        identity: Option<InboxDatabaseIdentity>,
    ) -> Result<Self> {
        if let Some(identity) = &identity {
            identity
                .check_current(&connection)
                .map_err(|_| TransportError::Storage)?;
        }
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|_| TransportError::Storage)?;
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(|_| TransportError::Storage)?;
        let application_id: i64 = connection
            .pragma_query_value(None, "application_id", |r| r.get(0))
            .map_err(|_| TransportError::Storage)?;
        if application_id != 0 && application_id != 0x57504942 {
            return Err(TransportError::UnsupportedVersion);
        }
        if application_id == 0 {
            let (tables, inbox): (i64, i64) = connection.query_row(
                "SELECT count(*), coalesce(max(name='receipts'),0) FROM sqlite_master WHERE type='table' AND name NOT GLOB 'sqlite_*'",
                [], |r| Ok((r.get(0)?, r.get(1)?)),
            ).map_err(|_| TransportError::Storage)?;
            if (version == 0 && tables != 0) || (version != 0 && inbox == 0) {
                return Err(TransportError::UnsupportedVersion);
            }
        }
        if !(0..=INBOX_SCHEMA_VERSION).contains(&version) {
            return Err(TransportError::UnsupportedVersion);
        }
        // Reject unknown tables/views/triggers before applying any migration.
        // Feature-disabled builds reject v3 outright, never filter control rows.
        if version == 0 {
            verify_inbox_schema(&connection, "")?;
        } else if version == 1 {
            let v1 = LEGACY_INBOX_SCHEMA
                .split("CREATE TABLE IF NOT EXISTS domain_imports")
                .next()
                .ok_or(TransportError::Storage)?;
            verify_inbox_schema(&connection, v1)?;
        } else if version == 2 {
            verify_inbox_schema(&connection, LEGACY_INBOX_SCHEMA)?;
        } else {
            verify_inbox_schema(&connection, INBOX_SCHEMA)?;
        }
        connection
            .execute_batch(&format!(
                "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; BEGIN IMMEDIATE; {INBOX_SCHEMA}"
            ))
            .map_err(|_| TransportError::Storage)?;
        verify_inbox_schema(&connection, INBOX_SCHEMA)?;
        connection.execute_batch(&format!(
            "PRAGMA application_id=1464879426; PRAGMA user_version={INBOX_SCHEMA_VERSION}; COMMIT;"
        )).map_err(|_| TransportError::Storage)?;
        let journal: String = connection
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .map_err(|_| TransportError::Storage)?;
        let synchronous: i64 = connection
            .pragma_query_value(None, "synchronous", |r| r.get(0))
            .map_err(|_| TransportError::Storage)?;
        if !journal.eq_ignore_ascii_case("wal") || synchronous != 2 {
            return Err(TransportError::Storage);
        }
        if let Some(identity) = &identity {
            identity
                .check_current(&connection)
                .map_err(|_| TransportError::Storage)?;
        }
        Ok(Self {
            connection,
            protection,
            identity,
        })
    }
    /// Bounded discovery after a crash before the importer received its result.
    /// These are historical inbox entries, not a queue of unprocessed domain work.
    pub fn retained_sequences(&self, context: &MessageContext) -> Result<Vec<u64>> {
        let stream = stream_digest(context)?;
        let mut statement = self
            .connection
            .prepare("SELECT sequence FROM receipts WHERE stream=?1 ORDER BY sequence LIMIT ?2")
            .map_err(|_| TransportError::Storage)?;
        let rows = statement
            .query_map(params![stream, MAX_REPLAY_RECORDS as i64 + 1], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(|_| TransportError::Storage)?;
        let mut sequences = Vec::new();
        for row in rows {
            let sequence = row.map_err(|_| TransportError::Storage)?;
            if sequence < 1 {
                return Err(TransportError::Storage);
            }
            if sequences.len() == MAX_REPLAY_RECORDS {
                return Err(TransportError::ResourceLimit);
            }
            sequences.push(sequence as u64);
        }
        Ok(sequences)
    }
    pub fn retained_for_context(
        &self,
        context: &MessageContext,
        sequence: u64,
    ) -> Result<Option<RetainedEnvelope>> {
        self.retained_envelope(&stream_digest(context)?, sequence)
    }

    /// Recovers exact already-received ciphertext after a caller crash. This is a
    /// read-only recovery input, never a new delivery, approval or safe writer state.
    pub fn retained_envelope(
        &self,
        stream_digest: &str,
        sequence: u64,
    ) -> Result<Option<RetainedEnvelope>> {
        validate_hex(stream_digest, 32)?;
        if sequence == 0 || sequence > i64::MAX as u64 {
            return Err(TransportError::Malformed);
        }
        let row: Option<(Option<Vec<u8>>, String)> = self
            .connection
            .query_row(
                "SELECT CASE WHEN length(envelope) <= ?3 THEN envelope ELSE NULL END,
                        substr(content_digest,1,65) FROM receipts WHERE stream=?1 AND sequence=?2",
                params![stream_digest, sequence as i64, MAX_FILE_BYTES as i64],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| TransportError::Storage)?;
        row.map(|(bytes, content_digest)| {
            let bytes = bytes.ok_or(TransportError::ResourceLimit)?;
            validate_hex(&content_digest, 32).map_err(|_| TransportError::Storage)?;
            Ok(RetainedEnvelope {
                envelope: EncryptedEnvelope::from_bytes(bytes)?,
                stream: stream_digest.into(),
                sequence,
                content_digest,
            })
        })
        .transpose()
    }
    pub fn record_count(&self) -> Result<u64> {
        self.connection
            .query_row("SELECT count(*) FROM receipts", [], |r| r.get(0))
            .map_err(|_| TransportError::Storage)
    }
}
impl ReplayLedger for SqliteReplayLedger {
    fn accept_authenticated(&mut self, r: &AuthenticatedReceipt, envelope: &[u8]) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| TransportError::Storage)?;
        insert_authenticated_in_transaction(&tx, r, envelope)?;
        tx.commit().map_err(|_| TransportError::Storage)
    }
}

// Concrete in-crate composition only. This helper does not commit and cannot be
// called by an external ReplayLedger implementation or an application callback.
pub(crate) fn insert_authenticated_in_transaction(
    tx: &rusqlite::Transaction<'_>,
    r: &AuthenticatedReceipt,
    envelope: &[u8],
) -> Result<()> {
    if envelope.len() > MAX_FILE_BYTES
        || digest(b"wholepact.encrypted-envelope.v1\0", envelope) != r.envelope_digest
    {
        return Err(TransportError::Malformed);
    }
    let prior: Option<(String, String, i64)> = tx
            .query_row(
                "SELECT substr(content_digest,1,65), substr(message_id_digest,1,65), sequence FROM receipts
             WHERE stream=?1 AND (sequence=?2 OR message_id_digest=?3) LIMIT 1",
                params![r.stream, r.sequence as i64, r.message_id_digest],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| TransportError::Storage)?;
    if let Some((content, message, seq)) = prior {
        return Err(
            if content == r.content_digest
                && message == r.message_id_digest
                && seq == r.sequence as i64
            {
                TransportError::Replay
            } else {
                TransportError::Equivocation
            },
        );
    }
    if let Some(slot) = &r.slot {
        let previous_payload: Option<String> = tx
            .query_row(
                "SELECT substr(payload_digest,1,65) FROM receipts WHERE slot=?1 LIMIT 1",
                [slot],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| TransportError::Storage)?;
        if let Some(previous) = previous_payload {
            return Err(if previous == r.payload_digest {
                TransportError::Replay
            } else {
                TransportError::Equivocation
            });
        }
    }
    let last: Option<i64> = tx
        .query_row(
            "SELECT max(sequence) FROM receipts WHERE stream=?1",
            [&r.stream],
            |row| row.get(0),
        )
        .map_err(|_| TransportError::Storage)?;
    if last.unwrap_or(0).checked_add(1) != Some(r.sequence as i64) {
        return Err(TransportError::OutOfOrder);
    }
    let (count, streams, bytes): (i64, i64, i64) = tx.query_row(
            "SELECT count(*), count(DISTINCT stream), coalesce(sum(length(envelope)),0) FROM receipts", [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).map_err(|_| TransportError::Storage)?;
    if count >= MAX_REPLAY_RECORDS as i64
        || (last.is_none() && streams >= MAX_REPLAY_STREAMS as i64)
        || bytes + envelope.len() as i64 > MAX_ENCRYPTED_INBOX_BYTES as i64
    {
        return Err(TransportError::ResourceLimit);
    }
    tx.execute("INSERT INTO receipts(stream, sequence, message_id_digest, content_digest, slot, payload_digest, envelope)
                    VALUES(?1,?2,?3,?4,?5,?6,?7)", params![r.stream, r.sequence as i64, r.message_id_digest,
                    r.content_digest, r.slot, r.payload_digest, envelope]).map_err(|_| TransportError::Storage)?;
    Ok(())
}

pub(crate) fn stream_digest(context: &MessageContext) -> Result<String> {
    context.validate()?;
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

// Compile the expected schema locally and compare every SQL-bearing object.
// No untrusted schema, trigger or view is accepted as a decoder instruction.
fn verify_inbox_schema(connection: &Connection, expected_sql: &str) -> Result<()> {
    type Object = (String, String, String, String);
    fn objects(c: &Connection) -> Result<Vec<Object>> {
        let mut q = c.prepare("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*' ORDER BY type,name")
            .map_err(|_| TransportError::Storage)?;
        let rows = q
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .map_err(|_| TransportError::Storage)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| TransportError::Storage)
    }
    let expected = Connection::open_in_memory().map_err(|_| TransportError::Storage)?;
    expected
        .execute_batch(expected_sql)
        .map_err(|_| TransportError::Storage)?;
    if objects(connection)? != objects(&expected)? {
        return Err(TransportError::UnsupportedVersion);
    }
    Ok(())
}
