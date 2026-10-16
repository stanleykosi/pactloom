//! Read-only schema16 signer receipt adapter. The live native signer supplies its
//! actual held journal connection and SQLCipher-factory identity. This reader
//! cannot create a profile, consent, receipt, journal writer or financial owner.
//! Archive cells, imported rows and plaintext connections are not constructors.
use crate::{
    EncryptedEnvelope, MAX_ENCRYPTED_INBOX_BYTES, MAX_FILE_BYTES, MAX_REPLAY_RECORDS,
    MAX_REPLAY_STREAMS, MessageContext, RetainedEnvelope, TransportError,
    replay::{RetainedReceiptMetadata, stream_digest},
    types::{Result, digest, validate_hex},
};
use rusqlite::{Connection, OptionalExtension, params};
use wholepact_storage_security::DatabaseFileIdentity;

// Exact compiled schema16 SQL-object commitment, generated from the canonical
// signer schema.sql through SQLite and canonical JSON tuples. No copied mutable
// schema, SQL supplied by a caller, or transport -> signer crate dependency.
const SIGNER_APPLICATION_ID: i64 = 0x57505343;
const SIGNER_SCHEMA_VERSION: i64 = 16;
const SIGNER_SCHEMA_OBJECTS: usize = 151;
const SIGNER_SCHEMA_DIGEST: &str =
    "c8b46e62eb9c405f02ec281dd6ec49a68e37cc00aea85bdb83bd9c48290fd120";
const SCHEMA_DOMAIN: &[u8] = b"wholepact:signer-schema16-receipt-source:v1\0";

/// No Deserialize, raw-row constructor, writer operation or acceptance method.
/// The identity is opaque and is captured only by authenticated storage opens.
/// This is historical evidence access, not a native/session authority token.
pub struct SignerNamedRecipientReceiptSource<'a> {
    connection: &'a Connection,
    identity: &'a DatabaseFileIdentity,
}
impl<'a> SignerNamedRecipientReceiptSource<'a> {
    /// Caller must hold its genuine signer journal mutex and original ownership
    /// lease throughout the reader's lifetime. Database identity alone proves
    /// neither freshness nor native approval; the concrete signer owns those.
    pub fn from_authenticated_journal(
        connection: &'a Connection,
        identity: &'a DatabaseFileIdentity,
    ) -> Result<Self> {
        identity
            .check_current(connection)
            .map_err(|_| TransportError::Storage)?;
        verify_schema16(connection)?;
        Ok(Self {
            connection,
            identity,
        })
    }

    /// Recover only the original exact encrypted file in the expected stream.
    /// A read transaction keeps schema, profile and receipt checks on one snapshot.
    /// This never inserts replay metadata or refreshes validity/sequence identity.
    pub fn retained_for_envelope(
        &self,
        profile_ref: &str,
        expected: &MessageContext,
        envelope_digest: &str,
    ) -> Result<Option<RetainedEnvelope>> {
        validate_hex(profile_ref, 32)?;
        validate_hex(envelope_digest, 32)?;
        if expected.artifact_kind != crate::ArtifactKind::NamedVerifierAssertion {
            return Err(TransportError::WrongContext);
        }
        let stream = stream_digest(expected)?;
        self.identity
            .check_current(self.connection)
            .map_err(|_| TransportError::Storage)?;
        let tx = self
            .connection
            .unchecked_transaction()
            .map_err(|_| TransportError::Storage)?;
        verify_schema16(&tx)?;
        validate_receipt_capacity(&tx)?;
        // No live account/profile is created or inferred here. The caller already
        // owns one; this equality only blocks cross-profile read substitution.
        let owner: Option<String> = tx.query_row(
            "SELECT substr(account_id,1,129) FROM signer_named_recipient_profiles WHERE reference=?1",
            [profile_ref], |r| r.get(0),
        ).optional().map_err(|_| TransportError::Storage)?;
        if owner.as_deref() != Some(expected.recipient_id.as_str()) {
            return Err(TransportError::WrongContext);
        }
        let count: i64 = tx.query_row(
            "SELECT count(*) FROM signer_named_recipient_receipts WHERE profile_ref=?1 AND stream=?2 AND envelope_digest=?3",
            params![profile_ref,stream,envelope_digest], |r| r.get(0),
        ).map_err(|_| TransportError::Storage)?;
        if count == 0 {
            self.identity
                .check_current(&tx)
                .map_err(|_| TransportError::Storage)?;
            tx.rollback().map_err(|_| TransportError::Storage)?;
            return Ok(None);
        }
        if count != 1 {
            return Err(TransportError::Equivocation);
        }
        let row: ReceiptRow = tx.query_row(
            "SELECT sequence,substr(message_id,1,65),substr(content_hash,1,65),substr(payload_digest,1,65),substr(envelope_digest,1,65),CASE WHEN immutable_slot IS NULL THEN NULL ELSE substr(immutable_slot,1,65) END,CASE WHEN length(CAST(envelope_hex AS BLOB))>0 AND length(CAST(envelope_hex AS BLOB))<=?4 THEN envelope_hex ELSE NULL END FROM signer_named_recipient_receipts WHERE profile_ref=?1 AND stream=?2 AND envelope_digest=?3",
            params![profile_ref,stream,envelope_digest,(2 * MAX_FILE_BYTES) as i64],
            |r| Ok(ReceiptRow { sequence: r.get(0)?, message: r.get(1)?, content: r.get(2)?,
                payload: r.get(3)?, envelope: r.get(4)?, slot: r.get(5)?, bytes_hex: r.get(6)? }),
        ).map_err(|_| TransportError::Storage)?;
        let retained = row.into_retained(stream, envelope_digest)?;
        self.identity
            .check_current(&tx)
            .map_err(|_| TransportError::Storage)?;
        tx.rollback().map_err(|_| TransportError::Storage)?;
        self.identity
            .check_current(self.connection)
            .map_err(|_| TransportError::Storage)?;
        Ok(Some(retained))
    }
}

// Only populated by the fixed bounded SQL query above, never exported/parsed.
struct ReceiptRow {
    sequence: i64,
    message: String,
    content: String,
    payload: String,
    envelope: String,
    slot: Option<String>,
    bytes_hex: Option<String>,
}
impl ReceiptRow {
    fn into_retained(self, stream: String, expected_envelope: &str) -> Result<RetainedEnvelope> {
        if self.sequence < 1 || self.envelope != expected_envelope {
            return Err(TransportError::WrongContext);
        }
        for value in [
            &stream,
            &self.message,
            &self.content,
            &self.payload,
            &self.envelope,
        ] {
            validate_hex(value, 32)?;
        }
        if let Some(slot) = &self.slot {
            validate_hex(slot, 32)?;
        }
        // Named-verifier assertion is an immutable-slot artifact.
        if self.slot.is_none() {
            return Err(TransportError::WrongContext);
        }
        let bytes_hex = self.bytes_hex.ok_or(TransportError::ResourceLimit)?;
        let bytes = hex::decode(&bytes_hex).map_err(|_| TransportError::Malformed)?;
        if hex::encode(&bytes) != bytes_hex
            || bytes.is_empty()
            || bytes.len() > MAX_FILE_BYTES
            || digest(b"wholepact.encrypted-envelope.v1\0", &bytes) != self.envelope
        {
            return Err(TransportError::WrongContext);
        }
        Ok(RetainedEnvelope {
            envelope: EncryptedEnvelope::from_bytes(bytes)?,
            stream,
            sequence: self.sequence as u64,
            content_digest: self.content,
            exact_receipt: Some(RetainedReceiptMetadata {
                message_id_digest: self.message,
                payload_digest: self.payload,
                envelope_digest: self.envelope,
                immutable_slot_digest: self.slot,
            }),
        })
    }
}

fn validate_receipt_capacity(c: &Connection) -> Result<()> {
    let (rows,bytes): (i64,i64) = c.query_row(
        "SELECT count(*),coalesce(sum(length(envelope_hex)/2),0) FROM signer_named_recipient_receipts",
        [], |r| Ok((r.get(0)?,r.get(1)?)),
    ).map_err(|_| TransportError::Storage)?;
    let streams: i64 = c.query_row(
        "SELECT count(*) FROM (SELECT profile_ref,stream FROM signer_named_recipient_receipts GROUP BY profile_ref,stream)",
        [], |r| r.get(0),
    ).map_err(|_| TransportError::Storage)?;
    if rows < 0
        || rows > MAX_REPLAY_RECORDS as i64
        || bytes < 0
        || bytes > MAX_ENCRYPTED_INBOX_BYTES as i64
        || streams < 0
        || streams > MAX_REPLAY_STREAMS as i64
    {
        return Err(TransportError::ResourceLimit);
    }
    Ok(())
}

fn verify_schema16(c: &Connection) -> Result<()> {
    let application: i64 = c
        .pragma_query_value(None, "application_id", |r| r.get(0))
        .map_err(|_| TransportError::Storage)?;
    let version: i64 = c
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(|_| TransportError::Storage)?;
    if application != SIGNER_APPLICATION_ID || version != SIGNER_SCHEMA_VERSION {
        return Err(TransportError::UnsupportedVersion);
    }
    type Object = (String, String, String, String);
    let mut q = c.prepare("SELECT substr(type,1,17),substr(name,1,129),substr(tbl_name,1,129),substr(sql,1,65537) FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' ORDER BY type,name LIMIT 152")
        .map_err(|_| TransportError::Storage)?;
    let rows = q
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .map_err(|_| TransportError::Storage)?;
    let objects: Vec<Object> = rows
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| TransportError::Storage)?;
    if objects.len() != SIGNER_SCHEMA_OBJECTS
        || objects
            .iter()
            .any(|o| o.0.len() > 16 || o.1.len() > 128 || o.2.len() > 128 || o.3.len() > 65_536)
    {
        return Err(TransportError::UnsupportedVersion);
    }
    let encoded = serde_json::to_vec(&objects).map_err(|_| TransportError::Malformed)?;
    if encoded.len() > 1024 * 1024 || digest(SCHEMA_DOMAIN, &encoded) != SIGNER_SCHEMA_DIGEST {
        return Err(TransportError::UnsupportedVersion);
    }
    Ok(())
}
