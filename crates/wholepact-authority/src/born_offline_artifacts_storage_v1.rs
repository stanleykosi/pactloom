//! Version seven is installed only by the opaque native artifact decision.
//! General journal/mailbox constructors never migrate into this schema.
use super::*;
use crate::born_offline_artifacts_v1::BornOfflineArtifactRecordV1;
use rusqlite::OptionalExtension;

#[cfg(any(test, all(feature = "born-offline-witness-owner", target_os = "linux")))]
pub(crate) fn verify_born_artifact_schema_v1(c: &Connection) -> Result<()> {
    let application: i64 = c.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if application != APPLICATION_ID || version != BORN_ARTIFACT_SCHEMA_VERSION {
        return Err(AuthorityError::UnsupportedVersion);
    }
    verify_schema_against(c, schema_v7())?;
    load(c)?;
    Ok(())
}

fn retained(c: &Connection) -> Result<Option<(BornOfflineArtifactRecordV1, Zeroizing<[u8; 32]>)>> {
    let raw: Option<(Vec<u8>, Vec<u8>)> = c
        .query_row(
            "SELECT payload,secret FROM authority_born_offline_artifacts WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    raw.map(|(payload, key)| {
        let payload = Zeroizing::new(payload);
        let key = Zeroizing::new(key);
        let secret: [u8; 32] = key
            .as_slice()
            .try_into()
            .map_err(|_| AuthorityError::CorruptHistory)?;
        let record: BornOfflineArtifactRecordV1 = decode(&payload)?;
        record.validate()?;
        Ok((record, Zeroizing::new(secret)))
    })
    .transpose()
}

pub(super) fn verify_artifact_tables(c: &Connection, ledger: &Ledger) -> Result<()> {
    let version: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let event_record = ledger.born_offline_artifacts_v1()?;
    if version != BORN_ARTIFACT_SCHEMA_VERSION {
        return if event_record.is_none() {
            Ok(())
        } else {
            Err(AuthorityError::CorruptHistory)
        };
    }
    let (record, secret) = retained(c)?.ok_or(AuthorityError::CorruptHistory)?;
    if event_record != Some(&record) || ledger.policy.account_use_genesis.is_none() {
        return Err(AuthorityError::CorruptHistory);
    }
    let enrollment = &ledger
        .born_offline_enrollment_v1()?
        .ok_or(AuthorityError::CorruptHistory)?
        .enrollment;
    record.binding.validate_enrollment(enrollment)?;
    let birth = crate::pending_birth_storage::read(c, &ledger.policy)?
        .ok_or(AuthorityError::CorruptHistory)?;
    enrollment.validate_original_birth(&birth)?;
    #[cfg(all(feature = "born-offline-witness-owner", target_os = "linux"))]
    verify_secret(&record, &secret)?;
    #[cfg(not(all(feature = "born-offline-witness-owner", target_os = "linux")))]
    drop(secret);
    // Bounded original ciphertext/replay retention. No schema owner may evict,
    // normalize, reset or silently reconstruct these records during opening.
    let (inbox_count, inbox_bytes, streams): (u64, u64, u64) = c.query_row(
        "SELECT count(*),coalesce(sum(length(envelope)),0),count(DISTINCT stream) FROM receipts",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let (outbox_count, outbox_bytes, outbox_streams): (u64, u64, u64) = c.query_row(
        "SELECT count(*),coalesce(sum(length(envelope)),0),count(DISTINCT stream) FROM outbox",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    if inbox_count > 8192
        || outbox_count > 8192
        || streams > 512
        || outbox_streams > 512
        || inbox_bytes > 64 * 1024 * 1024
        || outbox_bytes > 64 * 1024 * 1024
    {
        return Err(AuthorityError::Limit);
    }
    for (table, columns) in [
        (
            "receipts",
            "stream,sequence,message_id_digest,content_digest,slot,payload_digest,envelope",
        ),
        (
            "outbox",
            "stream,sequence,message_digest,preview_digest,context_digest,sender_fingerprint,recipient_fingerprint,payload_digest,slot,envelope_digest,issued_at,expires_at,envelope,acknowledged",
        ),
    ] {
        let mut q = c.prepare(&format!("SELECT {columns} FROM {table}"))?;
        let mut rows = q.query([])?;
        while let Some(row) = rows.next()? {
            hash(&row.get::<_, String>(0)?)?;
            if row.get::<_, i64>(1)? <= 0 {
                return Err(AuthorityError::CorruptHistory);
            }
            let (hash_columns, slot_column, envelope_column): (&[usize], usize, usize) =
                if table == "receipts" {
                    (&[2, 3, 5], 4, 6)
                } else {
                    (&[2, 3, 4, 5, 6, 7, 9], 8, 12)
                };
            for i in hash_columns {
                hash(&row.get::<_, String>(*i)?)?;
            }
            if let Some(slot) = row.get::<_, Option<String>>(slot_column)? {
                hash(&slot)?;
            }
            let bytes = Zeroizing::new(row.get::<_, Vec<u8>>(envelope_column)?);
            if bytes.is_empty() || bytes.len() > 1024 * 1024 {
                return Err(AuthorityError::Limit);
            }
            if table == "outbox" {
                let issued: i64 = row.get(10)?;
                let expires: i64 = row.get(11)?;
                if issued < 0
                    || expires <= issued
                    || expires - issued > 7 * 24 * 60 * 60
                    || row.get::<_, String>(5)? != enrollment.policy.witness_transport_key_digest
                    || row.get::<_, String>(6)? != enrollment.policy.offline_signer_key_digest
                    || !matches!(row.get::<_, i64>(13)?, 0 | 1)
                {
                    return Err(AuthorityError::CorruptHistory);
                }
                let mut h = Sha256::new();
                h.update(b"wholepact.encrypted-envelope.v1\0");
                h.update(&*bytes);
                if hex::encode(h.finalize()) != row.get::<_, String>(9)? {
                    return Err(AuthorityError::CorruptHistory);
                }
            }
        }
    }
    for table in ["domain_imports", "offline_control_outcomes"] {
        let orphan: u64 = c.query_row(&format!("SELECT count(*) FROM {table} d LEFT JOIN receipts r ON d.stream=r.stream AND d.sequence=r.sequence WHERE r.stream IS NULL OR d.content_digest!=r.content_digest"), [], |r| r.get(0))?;
        let count: u64 = c.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))?;
        if orphan != 0 || count > 8192 {
            return Err(AuthorityError::CorruptHistory);
        }
    }
    let mut q =
        c.prepare("SELECT stream,content_digest,processor,result_digest FROM domain_imports")?;
    let mut rows = q.query([])?;
    while let Some(row) = rows.next()? {
        for i in [0, 1, 3] {
            hash(&row.get::<_, String>(i)?)?;
        }
        let processor: String = row.get(2)?;
        if processor.is_empty() || processor.len() > 128 {
            return Err(AuthorityError::CorruptHistory);
        }
    }
    let mut q=c.prepare("SELECT stream,content_digest,control_digest,admission_digest FROM offline_control_outcomes")?;
    let mut rows = q.query([])?;
    while let Some(row) = rows.next()? {
        for i in [0, 1, 2] {
            hash(&row.get::<_, String>(i)?)?;
        }
        if let Some(admission) = row.get::<_, Option<String>>(3)? {
            hash(&admission)?;
        }
    }
    Ok(())
}

#[cfg(all(feature = "born-offline-witness-owner", target_os = "linux"))]
fn verify_secret(record: &BornOfflineArtifactRecordV1, secret: &[u8; 32]) -> Result<()> {
    let actual = crate::offline_witness_transport_v1::TransportSecret::from_bytes(*secret)
        .and_then(|s| s.public_key())
        .map_err(|_| AuthorityError::Authentication)?;
    if hex::encode(actual.as_bytes()) != record.binding.witness_public_key_hex {
        return Err(AuthorityError::Authentication);
    }
    Ok(())
}

#[cfg(all(feature = "born-offline-witness-owner", target_os = "linux"))]
impl AuthorityJournal {
    // Namespace ownership checks deliberately take no account-journal lock:
    // callers repeat them while holding their own transaction, before commit.
    pub(crate) fn require_born_artifact_owner_current_v1(&self) -> Result<()> {
        self.born_owner
            .as_ref()
            .ok_or(AuthorityError::Permission)?
            .check_mutation_current()
    }
    pub(crate) fn require_born_artifact_owner_read_current_v1(&self) -> Result<()> {
        self.born_owner
            .as_ref()
            .ok_or(AuthorityError::Permission)?
            .check_current()
    }
    pub(crate) fn born_offline_artifacts_v1(
        &self,
    ) -> Result<(BornOfflineArtifactRecordV1, Zeroizing<[u8; 32]>)> {
        let owner = self.born_owner.as_ref().ok_or(AuthorityError::Permission)?;
        owner.check_mutation_current()?;
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Deferred)?;
        verify_born_artifact_schema_v1(&tx)?;
        let ledger = load(&tx)?;
        if ledger.snapshot.writer_status == WriterStatus::Quarantined {
            return Err(AuthorityError::RecoveryRequired);
        }
        // Existing ciphertext recovery may outlive its original session. This
        // is retained key access only; the dedicated submit path rechecks live
        // original-session/time/authority bounds for every new write.
        ledger
            .account_use_history
            .require_not_permanently_excluded()?;
        let retained = retained(&tx)?.ok_or(AuthorityError::CorruptHistory)?;
        if retained.0.binding.namespace_binding_digest != owner.namespace_binding_digest_v1()? {
            return Err(AuthorityError::InvalidBinding);
        }
        owner.check_mutation_current()?;
        Ok(retained)
    }
    pub(crate) fn open_born_artifact_handles_v1(
        &self,
    ) -> Result<(EncryptedConnection, EncryptedConnection)> {
        let owner = self.born_owner.as_ref().ok_or(AuthorityError::Permission)?;
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        verify_born_artifact_schema_v1(c.connection())?;
        owner.open_born_artifact_handles_v1(&c)
    }
}

/// Only the concrete native decision consumer calls this within its retained
/// publication transaction. No standalone caller can make an installed journal:
/// full load rejects it until the matching owner event is appended atomically.
#[cfg(all(feature = "born-offline-witness-owner", target_os = "linux"))]
pub(crate) fn install_born_artifact_rows_v1(
    tx: &Transaction<'_>,
    record: &BornOfflineArtifactRecordV1,
    secret: &[u8; 32],
) -> Result<()> {
    let version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if version != SCHEMA_VERSION {
        return Err(AuthorityError::UnsupportedVersion);
    }
    verify_schema_against(tx, SCHEMA)?;
    let ledger = load(tx)?;
    ledger.validate_new_born_offline_artifacts_v1(record, now_ms()?)?;
    verify_secret(record, secret)?;
    tx.execute_batch(include_str!("born_offline_artifacts_schema_v1.sql"))?;
    tx.execute_batch(crate::born_offline_artifact_schema_v1::INBOX_SCHEMA)?;
    tx.execute_batch(crate::born_offline_artifact_schema_v1::OUTBOX_SCHEMA)?;
    tx.execute_batch(include_str!("born_offline_retry_schema_v1.sql"))?;
    tx.execute(
        "INSERT INTO authority_born_offline_artifacts VALUES(1,?1,?2)",
        params![&*encode(record)?, secret.as_slice()],
    )?;
    tx.pragma_update(None, "user_version", BORN_ARTIFACT_SCHEMA_VERSION)?;
    verify_schema_against(tx, schema_v7())?;
    Ok(())
}

#[cfg(test)]
mod schema_tests {
    use super::*;
    #[test]
    fn native_extension_schema_is_exact_atomic_and_immutable() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(SCHEMA).unwrap();
        c.pragma_update(None, "user_version", 6).unwrap();
        {
            let tx = Transaction::new_unchecked(&c, TransactionBehavior::Immediate).unwrap();
            tx.execute_batch(include_str!("born_offline_artifacts_schema_v1.sql"))
                .unwrap();
            tx.execute_batch(crate::born_offline_artifact_schema_v1::INBOX_SCHEMA)
                .unwrap();
            tx.execute_batch(crate::born_offline_artifact_schema_v1::OUTBOX_SCHEMA)
                .unwrap();
            tx.execute_batch(include_str!("born_offline_retry_schema_v1.sql"))
                .unwrap();
            verify_schema_against(&tx, schema_v7()).unwrap();
            tx.execute(
                "INSERT INTO authority_born_offline_artifacts VALUES(1,?1,?2)",
                params![b"synthetic-inert-record".as_slice(), [7u8; 32].as_slice()],
            )
            .unwrap();
            assert!(
                tx.execute(
                    "UPDATE authority_born_offline_artifacts SET secret=?1",
                    [[8u8; 32].as_slice()]
                )
                .is_err()
            );
            assert!(
                tx.execute("DELETE FROM authority_born_offline_artifacts", [])
                    .is_err()
            );
            assert!(
                tx.execute(
                    "INSERT OR REPLACE INTO authority_born_offline_artifacts VALUES(1,?1,?2)",
                    params![b"replacement".as_slice(), [8u8; 32].as_slice()]
                )
                .is_err()
            );
            // Simulated cancellation rolls back key, mailbox schema and version.
        }
        verify_schema_against(&c, SCHEMA).unwrap();
        assert_eq!(
            c.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            6
        );
        c.execute_batch(schema_v7().strip_prefix(SCHEMA).unwrap())
            .unwrap();
        c.pragma_update(None, "application_id", APPLICATION_ID)
            .unwrap();
        c.pragma_update(None, "user_version", 7).unwrap();
        // Schema alone must never impersonate a completed native installation.
        assert!(verify_born_artifact_schema_v1(&c).is_err());
        c.execute_batch("CREATE TABLE sqliteXforged(value BLOB)")
            .unwrap();
        assert!(verify_schema_against(&c, schema_v7()).is_err());
    }
}
