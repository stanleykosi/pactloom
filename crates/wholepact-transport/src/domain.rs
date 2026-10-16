//! Receipt-backed domain processing. The domain adapter commits its own operation
//! using the stable key before recording completion here. A crash in that gap
//! causes an idempotent retry, never an exactly-once claim across two databases.
use crate::{
    replay::stream_digest, types::*, ReceivedArtifact, SqliteReplayLedger, MAX_REPLAY_RECORDS,
};
use rusqlite::{params, OptionalExtension, TransactionBehavior};

const MAX_DOMAIN_PROCESSORS: i64 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainOutcome {
    Applied,
    Rejected,
}
impl DomainOutcome {
    fn code(self) -> i64 {
        match self {
            Self::Applied => 1,
            Self::Rejected => 2,
        }
    }
    fn from_code(value: i64) -> Result<Self> {
        match value {
            1 => Ok(Self::Applied),
            2 => Ok(Self::Rejected),
            _ => Err(TransportError::Storage),
        }
    }
}

/// A durable local processing result, not participant approval or chain evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainImportResult {
    pub outcome: DomainOutcome,
    /// Digest of the domain adapter's durable result; never the result plaintext.
    pub result_digest: String,
}

/// Receipt-backed identity for one versioned domain importer. No spend authority
/// is contained here. Historical recovery uses the same idempotency key.
pub struct DomainImportTicket {
    stream: String,
    sequence: u64,
    content_digest: String,
    processor: String,
    idempotency_key: String,
    completed: Option<DomainImportResult>,
}
impl DomainImportTicket {
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }
    pub fn completed(&self) -> Option<&DomainImportResult> {
        self.completed.as_ref()
    }
}

impl SqliteReplayLedger {
    /// Returns a stable key after checking the authenticated artifact against this
    /// inbox. The caller must separately validate its domain semantics, identity
    /// evidence, authorization, expiry and current authority. A received signature
    /// or read-only invitation does not grant any of these capabilities.
    pub fn domain_import_ticket(
        &self,
        artifact: &ReceivedArtifact,
        processor_id: &str,
    ) -> Result<DomainImportTicket> {
        validate_id(processor_id)?;
        let processor = digest(b"wholepact.domain-processor.v1\0", processor_id.as_bytes());
        let stream = artifact.stream_digest().to_owned();
        let sequence = artifact.preview().order.sequence;
        let content_digest = artifact.content_digest().to_owned();
        let stored: Option<String> = self
            .connection
            .query_row(
                "SELECT substr(content_digest,1,65) FROM receipts WHERE stream=?1 AND sequence=?2",
                params![stream, sequence as i64],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| TransportError::Storage)?;
        if stored.as_deref() != Some(content_digest.as_str()) {
            return Err(TransportError::Authentication);
        }
        let completed = self.domain_result(&stream, sequence, &processor, &content_digest)?;
        let idempotency_key = digest(
            b"wholepact.domain-import.v1\0",
            &encode(&(&stream, sequence, &content_digest, &processor))?,
        );
        Ok(DomainImportTicket {
            stream,
            sequence,
            content_digest,
            processor,
            idempotency_key,
            completed,
        })
    }

    /// Records terminal completion only *after* the domain adapter committed under
    /// ticket.idempotency_key(). Repeating the exact outcome is idempotent; a changed
    /// outcome is rejected. Transient blocked/unavailable imports stay pending.
    /// This transaction cannot atomically commit another crate's database or any
    /// external operation. Never execute a non-idempotent effect before this call.
    pub fn complete_domain_import(
        &mut self,
        ticket: &DomainImportTicket,
        result: DomainImportResult,
    ) -> Result<DomainImportResult> {
        validate_hex(&result.result_digest, 32)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| TransportError::Storage)?;
        let stored: Option<String> = tx
            .query_row(
                "SELECT substr(content_digest,1,65) FROM receipts WHERE stream=?1 AND sequence=?2",
                params![ticket.stream, ticket.sequence as i64],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| TransportError::Storage)?;
        if stored.as_deref() != Some(ticket.content_digest.as_str()) {
            return Err(TransportError::Authentication);
        }
        let prior: Option<(String, i64, String)> = tx
            .query_row(
                "SELECT substr(content_digest,1,65), outcome, substr(result_digest,1,65)
             FROM domain_imports WHERE stream=?1 AND sequence=?2 AND processor=?3",
                params![ticket.stream, ticket.sequence as i64, ticket.processor],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|_| TransportError::Storage)?;
        if let Some((content, outcome, result_digest)) = prior {
            if content != ticket.content_digest
                || outcome != result.outcome.code()
                || result_digest != result.result_digest
            {
                return Err(TransportError::DomainConflict);
            }
            return Ok(result);
        }
        let (processors, known): (i64, i64) = tx.query_row(
            "SELECT count(DISTINCT processor), coalesce(max(processor=?1),0) FROM domain_imports",
            [&ticket.processor], |r| Ok((r.get(0)?, r.get(1)?)),
        ).map_err(|_| TransportError::Storage)?;
        if processors >= MAX_DOMAIN_PROCESSORS && known == 0 {
            return Err(TransportError::ResourceLimit);
        }
        tx.execute(
            "INSERT INTO domain_imports(stream, sequence, processor, content_digest, outcome, result_digest)
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![ticket.stream, ticket.sequence as i64, ticket.processor, ticket.content_digest,
                result.outcome.code(), result.result_digest],
        ).map_err(|_| TransportError::Storage)?;
        tx.commit().map_err(|_| TransportError::Storage)?;
        Ok(result)
    }

    /// Discover unprocessed records for the exact profile/agreement/sender/recipient
    /// stream. Recover each ciphertext against independently trusted proposal/type
    /// context before processing. This does not make old messages current again.
    pub fn pending_domain_sequences(
        &self,
        context: &MessageContext,
        processor_id: &str,
    ) -> Result<Vec<u64>> {
        validate_id(processor_id)?;
        let processor = digest(b"wholepact.domain-processor.v1\0", processor_id.as_bytes());
        let stream = stream_digest(context)?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT r.sequence FROM receipts r LEFT JOIN domain_imports d
             ON r.stream=d.stream AND r.sequence=d.sequence AND d.processor=?2
             WHERE r.stream=?1 AND d.sequence IS NULL ORDER BY r.sequence LIMIT ?3",
            )
            .map_err(|_| TransportError::Storage)?;
        let rows = statement
            .query_map(
                params![stream, processor, MAX_REPLAY_RECORDS as i64 + 1],
                |r| r.get::<_, i64>(0),
            )
            .map_err(|_| TransportError::Storage)?;
        let mut result = Vec::new();
        for row in rows {
            let sequence = row.map_err(|_| TransportError::Storage)?;
            if sequence < 1 {
                return Err(TransportError::Storage);
            }
            if result.len() >= MAX_REPLAY_RECORDS {
                return Err(TransportError::ResourceLimit);
            }
            result.push(sequence as u64);
        }
        Ok(result)
    }

    fn domain_result(
        &self,
        stream: &str,
        sequence: u64,
        processor: &str,
        content: &str,
    ) -> Result<Option<DomainImportResult>> {
        let row: Option<(String, i64, String)> = self
            .connection
            .query_row(
                "SELECT substr(content_digest,1,65), outcome, substr(result_digest,1,65)
             FROM domain_imports WHERE stream=?1 AND sequence=?2 AND processor=?3",
                params![stream, sequence as i64, processor],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|_| TransportError::Storage)?;
        row.map(|(stored, outcome, result_digest)| {
            if stored != content {
                return Err(TransportError::Authentication);
            }
            validate_hex(&result_digest, 32).map_err(|_| TransportError::Storage)?;
            Ok(DomainImportResult {
                outcome: DomainOutcome::from_code(outcome)?,
                result_digest,
            })
        })
        .transpose()
    }
}
