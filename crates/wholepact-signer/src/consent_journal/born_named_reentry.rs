//! Key-free complete journal commitment for a consumed-born private reentry.
//! No mutation, serialization, permit, MAC, epoch or deadline is produced here.
use super::*;
use rusqlite::{Connection, OptionalExtension, types::ValueRef};
use sha2::{Digest, Sha256};
use wholepact_authority::{
    account_use::AccountUseGenesis, born_offline_construction_v1::BornOfflineConstructionOriginV1,
};
use wholepact_signer_origin::common_context_reentry_v1::RosterReenteredConstructionEvidenceV1;

/// Private constructor; only complete typed validation under the actual journal
/// connection can issue this non-authorizing, non-portable comparison value.
#[derive(PartialEq, Eq)]
pub(crate) struct BornNamedReentryInventoryV1 {
    digest: String,
}

impl SignerConsentJournal {
    /// Cleanup-only preservation may run after native revocation. The caller
    /// consumes the actual source and must uniquely own/drop journal and vault
    /// before this commitment can be retained as a dormant token. This never
    /// authorizes a new read, export, endpoint, signature or witness operation.
    pub(crate) fn consumed_born_named_inventory_v1(
        &self,
        genesis: &AccountUseGenesis,
        epoch: u64,
        evidence: &RosterReenteredConstructionEvidenceV1,
        expected: &BornOfflineConstructionOriginV1,
    ) -> Result<BornNamedReentryInventoryV1> {
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        self.database_identity
            .check_current(&c)
            .map_err(|_| JournalError::Database)?;
        let tx = c.transaction()?;
        validate(
            &tx,
            self.capacity_limits(),
            genesis,
            epoch,
            evidence,
            expected,
        )?;
        let inventory = BornNamedReentryInventoryV1 {
            digest: complete_commitment(&tx)?,
        };
        self.database_identity
            .check_current(&tx)
            .map_err(|_| JournalError::Database)?;
        tx.rollback()?;
        Ok(inventory)
    }

    pub(crate) fn consumed_born_named_local_records_v1(
        &self,
        genesis: &AccountUseGenesis,
        epoch: u64,
        evidence: &RosterReenteredConstructionEvidenceV1,
        expected: &BornOfflineConstructionOriginV1,
    ) -> Result<(
        Option<AccountEnrollmentRecord>,
        Option<AcceptedManifestRecord>,
    )> {
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        self.database_identity
            .check_current(&c)
            .map_err(|_| JournalError::Database)?;
        let tx = c.transaction()?;
        validate(
            &tx,
            self.capacity_limits(),
            genesis,
            epoch,
            evidence,
            expected,
        )?;
        let enrollment = tx
            .query_row("SELECT reference FROM signer_enrollments", [], |r| {
                r.get::<_, String>(0)
            })
            .optional()?
            .map(|reference| {
                storage::read_enrollment(&tx, &reference)
                    .and_then(|v| v.ok_or(JournalError::InvalidBinding))
            })
            .transpose()?;
        let manifest = tx
            .query_row("SELECT reference FROM signer_accepted_manifests", [], |r| {
                r.get::<_, String>(0)
            })
            .optional()?
            .map(|reference| {
                storage::read_manifest(&tx, &reference)
                    .and_then(|v| v.ok_or(JournalError::InvalidBinding))
            })
            .transpose()?;
        if enrollment.is_some() != manifest.is_some() {
            return Err(JournalError::RecoveryRequired);
        }
        self.database_identity
            .check_current(&tx)
            .map_err(|_| JournalError::Database)?;
        tx.rollback()?;
        Ok((enrollment, manifest))
    }
}

fn validate(
    c: &Connection,
    limits: (u64, u64),
    genesis: &AccountUseGenesis,
    epoch: u64,
    evidence: &RosterReenteredConstructionEvidenceV1,
    expected: &BornOfflineConstructionOriginV1,
) -> Result<()> {
    let validated = storage::verify_schema_with_common_audit(c)?;
    storage::bounded(c, limits)?;
    let account = storage::read_account(c)?;
    let history = account_use_storage::inspect(c, &account.account_id)?;
    if account.recovery_required
        || account.writer_epoch != epoch
        || account.account_id != genesis.identity.account_id
        || history.genesis() != Some(genesis)
        || history.exclusion().is_some()
    {
        return Err(JournalError::InvalidBinding);
    }
    let actual = born_named_continuation::origin_from_verified_schema(
        &validated, &account.account_id, evidence,
    )?;
    if &actual != expected {
        return Err(JournalError::Conflict);
    }
    born_named_continuation::verify_local_records(c, genesis, &actual)
}

/// All tables and every typed cell are committed, not only the original V3
/// rows. Schema verification/bounds and complete typed inventory run first.
/// Deterministic ordering prevents row insertion order from changing identity.
fn complete_commitment(c: &Connection) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(b"wholepact:consumed-born-complete-local-reentry-inventory:v1\0");
    let mut q = c.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")?;
    let tables = q
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    hash.update((tables.len() as u64).to_le_bytes());
    for name in tables {
        frame(&mut hash, name.as_bytes());
        let quoted = name.replace('"', "\"\"");
        let mut columns = c.prepare(&format!("PRAGMA table_info(\"{quoted}\")"))?;
        let columns = columns
            .query_map([], |r| Ok((r.get::<_, String>(1)?, r.get::<_, String>(2)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if columns.is_empty() || columns.len() > 16 {
            return Err(JournalError::UnsupportedSchema);
        }
        hash.update((columns.len() as u64).to_le_bytes());
        for (column, kind) in &columns {
            if kind != "TEXT" && kind != "INTEGER" {
                return Err(JournalError::UnsupportedSchema);
            }
            frame(&mut hash, column.as_bytes());
            frame(&mut hash, kind.as_bytes());
        }
        let order = (1..=columns.len())
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let mut q = c.prepare(&format!("SELECT * FROM \"{quoted}\" ORDER BY {order}"))?;
        let mut rows = q.query([])?;
        let mut count = 0u64;
        while let Some(row) = rows.next()? {
            count = count.checked_add(1).ok_or(JournalError::Limit)?;
            hash.update(b"row\0");
            for index in 0..columns.len() {
                match row.get_ref(index)? {
                    ValueRef::Null => hash.update([0]),
                    ValueRef::Integer(v) => {
                        hash.update([1]);
                        hash.update(v.to_le_bytes());
                    }
                    ValueRef::Text(v) => {
                        hash.update([2]);
                        frame(&mut hash, v);
                    }
                    _ => return Err(JournalError::UnsupportedSchema),
                }
            }
        }
        hash.update(b"rows-end\0");
        hash.update(count.to_le_bytes());
    }
    Ok(hex::encode(hash.finalize()))
}
fn frame(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    fn inert() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE signer_named_recipient_started (id TEXT, payload TEXT); CREATE TABLE signer_named_recipient_results (id TEXT, payload TEXT); CREATE TABLE signer_named_recipient_dispatch_requests (id TEXT, payload TEXT);").unwrap();
        c
    }
    #[test]
    fn consumed_reentry_commitment_accepts_complete_actual_schema17() {
        fn actual_schema() -> Connection {
            let c = Connection::open_in_memory().unwrap();
            c.execute_batch(SCHEMA).unwrap();
            c.pragma_update(None, "application_id", APPLICATION_ID)
                .unwrap();
            c.pragma_update(None, "user_version", SCHEMA_VERSION)
                .unwrap();
            // An inert recovery-required row is not a vault, actual genesis,
            // consumed origin, native grant or SignerConsentJournal owner.
            c.execute(
                "INSERT INTO signer_account VALUES(1,'inert-schema17-commitment',1,1)",
                [],
            )
            .unwrap();
            storage::verify_schema(&c).unwrap();
            storage::bounded(&c, (MAX_BACKUP_ROWS, MAX_BACKUP_ENCODED_BYTES)).unwrap();
            c
        }
        assert_eq!(SCHEMA_VERSION, 17);
        let original = actual_schema();
        let changed = actual_schema();
        let tables: u64 = original.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            [], |r| r.get(0),
        ).unwrap();
        assert_eq!(tables, 48);
        for table in [
            "signer_named_recipient_started",
            "signer_named_recipient_results",
            "signer_named_recipient_dispatch_requests",
        ] {
            assert_eq!(
                original
                    .query_row(
                        "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name=?1",
                        [table],
                        |r| r.get::<_, u64>(0)
                    )
                    .unwrap(),
                1
            );
        }
        let complete = complete_commitment(&original).unwrap();
        assert_eq!(complete.len(), 64);
        assert_eq!(complete, complete_commitment(&changed).unwrap());
        changed
            .execute("UPDATE signer_account SET writer_epoch=2", [])
            .unwrap();
        storage::verify_schema(&changed).unwrap();
        assert_ne!(complete, complete_commitment(&changed).unwrap());
        changed
            .execute("UPDATE signer_account SET writer_epoch=1", [])
            .unwrap();
        assert_eq!(complete, complete_commitment(&changed).unwrap());
        // Omitting even an empty immutable dispatch table is detectable; strict
        // production schema validation also refuses it before any commitment.
        changed
            .execute_batch("DROP TABLE signer_named_recipient_dispatch_requests;")
            .unwrap();
        assert!(storage::verify_schema(&changed).is_err());
        assert_ne!(complete, complete_commitment(&changed).unwrap());
    }

    #[test]
    fn consumed_reentry_commitment_includes_started_result_dispatch_and_rollback() {
        let c = inert();
        let empty = complete_commitment(&c).unwrap();
        c.execute(
            "INSERT INTO signer_named_recipient_started VALUES ('a','started')",
            [],
        )
        .unwrap();
        let started = complete_commitment(&c).unwrap();
        assert_ne!(empty, started);
        c.execute(
            "INSERT INTO signer_named_recipient_results VALUES ('a','result')",
            [],
        )
        .unwrap();
        let result = complete_commitment(&c).unwrap();
        assert_ne!(started, result);
        c.execute(
            "INSERT INTO signer_named_recipient_dispatch_requests VALUES ('a','dispatch')",
            [],
        )
        .unwrap();
        let dispatch = complete_commitment(&c).unwrap();
        assert_ne!(result, dispatch);
        c.execute("DELETE FROM signer_named_recipient_dispatch_requests", [])
            .unwrap();
        assert_eq!(complete_commitment(&c).unwrap(), result);
        assert_ne!(complete_commitment(&c).unwrap(), dispatch);
    }
    #[test]
    fn consumed_reentry_commitment_is_order_stable_and_type_exact() {
        let a = inert();
        let b = inert();
        for id in ["a", "b"] {
            a.execute(
                "INSERT INTO signer_named_recipient_started VALUES (?1,'same')",
                [id],
            )
            .unwrap();
        }
        for id in ["b", "a"] {
            b.execute(
                "INSERT INTO signer_named_recipient_started VALUES (?1,'same')",
                [id],
            )
            .unwrap();
        }
        assert_eq!(
            complete_commitment(&a).unwrap(),
            complete_commitment(&b).unwrap()
        );
        b.execute(
            "UPDATE signer_named_recipient_started SET payload=NULL WHERE id='b'",
            [],
        )
        .unwrap();
        assert_ne!(
            complete_commitment(&a).unwrap(),
            complete_commitment(&b).unwrap()
        );
        b.execute_batch("CREATE TABLE unexpected (v REAL);")
            .unwrap();
        assert!(complete_commitment(&b).is_err());
    }
}
