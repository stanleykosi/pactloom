//! Exact transactional schema extension; migration never clears recovery state.
use super::*;
use rusqlite::{Connection, TransactionBehavior};
pub(super) const V18_SCHEMA: &str = include_str!("schema_v18.sql");
pub(super) const DURABLE_PAYMENT_ADMISSION_SCHEMA: &str =
    include_str!("durable_payment_admission_schema_v19.sql");
pub(super) const V17_SCHEMA: &str = include_str!("schema_v17.sql");
pub(super) const DURABLE_CONSTRUCTION_SCHEMA: &str =
    include_str!("durable_construction_schema_v18.sql");
pub(super) const V16_SCHEMA: &str = include_str!("schema_v16.sql");
pub(super) const BORN_DISPATCH_SCHEMA: &str = include_str!("born_dispatch_schema_v17.sql");
pub(super) const V15_SCHEMA: &str = include_str!("schema_v15.sql");
pub(super) const NAMED_RECIPIENT_SCHEMA: &str = include_str!("named_recipient_schema.sql");
pub(super) const V14_SCHEMA: &str = include_str!("schema_v14.sql");
pub(super) const COMMON_CONTEXT_REENTRY_SCHEMA: &str =
    include_str!("common_context_reentry_v1.sql");
pub(super) const V13_SCHEMA: &str = include_str!("schema_v13.sql");
pub(super) const COMMON_CONTEXT_AUDIT_SCHEMA: &str = include_str!("construction_audit_v3.sql");
pub(super) const V12_SCHEMA: &str = include_str!("schema_v12.sql");
pub(super) const OFFLINE_RECEIPTS_SCHEMA: &str = include_str!("offline_receipts.sql");
pub(super) const V11_SCHEMA: &str = include_str!("schema_v11.sql");
pub(super) const ACCOUNT_USE_SCHEMA: &str = include_str!("account_use_schema.sql");
pub(super) const V10_SCHEMA: &str = include_str!("schema_v10.sql");
pub(super) const OFFLINE_SCHEMA: &str = include_str!("offline_schema.sql");
pub(super) const V9_SCHEMA: &str = include_str!("schema_v9.sql");
pub(super) const AUTOMATION_SCHEMA: &str = include_str!("automation_schema.sql");
pub(super) const V8_SCHEMA: &str = include_str!("schema_v8.sql");
pub(super) const RECOVERY_SCHEMA: &str = include_str!("recovery_schema.sql");
pub(super) fn verify_exact_schema(c: &Connection, sql: &str) -> Result<()> {
    type Object = (String, String, String, Option<String>);
    fn objects(c: &Connection) -> Result<Vec<Object>> {
        let mut q =
            c.prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name")?;
        let rows = q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }
    let reference = Connection::open_in_memory()?;
    reference.execute_batch(sql)?;
    if objects(c)? != objects(&reference)? {
        return Err(JournalError::UnsupportedSchema);
    }
    Ok(())
}
/// Authenticated-copy preflight for the ordinary opener. The caller must retain
/// the actual directory/quiescence owner and carry the snapshot's source identity
/// into its eventual writable open. A version is not account-origin proof.
///
/// Frozen8..11 remain UNKNOWN provenance. Frozen12..18 are accepted only when
/// ALL account-use tables are empty. Known-born callers must independently use
/// the current-schema-only opener even if an old file claims a pre-genesis format.
pub(super) fn preflight_open(c: &Connection, account_id: &str) -> Result<i64> {
    let application: i64 = c.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if application != APPLICATION_ID {
        return Err(JournalError::UnsupportedSchema);
    }
    let schema = match version {
        8 => V8_SCHEMA,
        9 => V9_SCHEMA,
        10 => V10_SCHEMA,
        11 => V11_SCHEMA,
        12 => V12_SCHEMA,
        13 => V13_SCHEMA,
        14 => V14_SCHEMA,
        15 => V15_SCHEMA,
        16 => V16_SCHEMA,
        17 => V17_SCHEMA,
        18 => V18_SCHEMA,
        SCHEMA_VERSION => SCHEMA,
        _ => return Err(JournalError::UnsupportedSchema),
    };
    verify_exact_schema(c, schema)?;
    if storage::read_account(c)?.account_id != account_id {
        return Err(JournalError::InvalidBinding);
    }
    if (12..=18).contains(&version) {
        // Inspect every row, not only singleton=1. Even malformed or orphaned
        // account-use evidence forbids this ordinary schema-only migration.
        for table in [
            "signer_account_use_genesis",
            "signer_account_use_exclusion",
            "signer_account_use_witness_ack",
        ] {
            let present: bool =
                c.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {table})"), [], |r| {
                    r.get(0)
                })?;
            if present {
                return Err(JournalError::RecoveryRequired);
            }
        }
        let state = account_use_storage::inspect(c, account_id)?;
        if state.genesis().is_some() || state.exclusion().is_some() || state.witness_ack().is_some()
        {
            return Err(JournalError::RecoveryRequired);
        }
    } else if version == SCHEMA_VERSION {
        // Current journals retain their existing typed/account-use restrictions;
        // do not mistake a permitted current historical genesis for migration.
        storage::verify_schema(c)?;
    }
    Ok(version)
}

/// Exact additive NONBORN migration only. No existing row, rowid, account,
/// writer epoch, recovery flag, exposure or receipt is rewritten.
fn migrate_from(
    c: &mut Connection,
    account_id: &str,
    expected_version: i64,
    inject_failure: bool,
) -> Result<()> {
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    // Repeat the complete pre-writable classification under the same transaction
    // as DDL. Neither a previously observed version nor a caller flag is proof.
    if !(8..=18).contains(&expected_version) || preflight_open(&tx, account_id)? != expected_version
    {
        return Err(JournalError::UnsupportedSchema);
    }
    for (introduced, sql) in [
        (9, RECOVERY_SCHEMA),
        (10, AUTOMATION_SCHEMA),
        (11, OFFLINE_SCHEMA),
        (12, ACCOUNT_USE_SCHEMA),
        (13, OFFLINE_RECEIPTS_SCHEMA),
        (14, COMMON_CONTEXT_AUDIT_SCHEMA),
        (15, COMMON_CONTEXT_REENTRY_SCHEMA),
        (16, NAMED_RECIPIENT_SCHEMA),
        (17, BORN_DISPATCH_SCHEMA),
        (18, DURABLE_CONSTRUCTION_SCHEMA),
        (19, DURABLE_PAYMENT_ADMISSION_SCHEMA),
    ] {
        if expected_version < introduced {
            tx.execute_batch(sql)?;
        }
    }
    if inject_failure {
        return Err(JournalError::Database);
    }
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    verify_exact_schema(&tx, SCHEMA)?;
    let financial_intents: i64 = tx.query_row(
        "SELECT count(*) FROM signer_durable_payment_admission_intents",
        [],
        |r| r.get(0),
    )?;
    if financial_intents != 0 {
        return Err(JournalError::InvalidBinding);
    }
    // No synthetic genesis or financial/native/writer authority is introduced.
    tx.commit()?;
    Ok(())
}

pub(super) fn migrate_v8(c: &mut Connection, account_id: &str) -> Result<()> {
    migrate(c, account_id, false)
}
fn migrate(c: &mut Connection, account_id: &str, inject_failure: bool) -> Result<()> {
    migrate_from(c, account_id, 8, inject_failure)
}

pub(super) fn migrate_v9(c: &mut Connection, account_id: &str) -> Result<()> {
    migrate_from(c, account_id, 9, false)
}

pub(super) fn migrate_v10(c: &mut Connection, account_id: &str) -> Result<()> {
    migrate_v10_inner(c, account_id, false)
}
fn migrate_v10_inner(c: &mut Connection, account_id: &str, inject_failure: bool) -> Result<()> {
    migrate_from(c, account_id, 10, inject_failure)
}

pub(super) fn migrate_v11(c: &mut Connection, account_id: &str) -> Result<()> {
    migrate_v11_inner(c, account_id, false)
}
fn migrate_v11_inner(c: &mut Connection, account_id: &str, inject_failure: bool) -> Result<()> {
    migrate_from(c, account_id, 11, inject_failure)
}

pub(super) fn migrate_v12(c: &mut Connection, account_id: &str) -> Result<()> {
    migrate_v12_inner(c, account_id, false)
}
fn migrate_v12_inner(c: &mut Connection, account_id: &str, inject_failure: bool) -> Result<()> {
    migrate_from(c, account_id, 12, inject_failure)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(V8_SCHEMA).unwrap();
        c.pragma_update(None, "application_id", APPLICATION_ID)
            .unwrap();
        c.pragma_update(None, "user_version", 8).unwrap();
        c.execute(
            "INSERT INTO signer_account VALUES(1,'synthetic-restored-account',7,1)",
            [],
        )
        .unwrap();
        c.execute("INSERT INTO signer_sponsor_policy_events VALUES('synthetic-policy',1,'retained exact policy payload')",[]).unwrap();
        c
    }
    #[test]
    fn v8_extension_preserves_every_original_row_and_recovery_flag() {
        let mut c = fixture();
        let before = snapshot_rows(&c);
        migrate_v8(&mut c, "synthetic-restored-account").unwrap();
        assert_eq!(before, snapshot_rows(&c));
        assert_eq!(
            c.query_row(
                "SELECT count(*) FROM signer_recovery_generations",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(
            c.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            SCHEMA_VERSION
        );
    }
    #[test]
    fn interrupted_v8_extension_rolls_back_schema_and_rows() {
        let mut c = fixture();
        let before = snapshot_rows(&c);
        assert!(migrate(&mut c, "synthetic-restored-account", true).is_err());
        verify_exact_schema(&c, V8_SCHEMA).unwrap();
        assert_eq!(before, snapshot_rows(&c));
        assert_eq!(
            c.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            8
        );
    }
    #[test]
    fn exact_v9_extension_preserves_rows_and_rejects_schema_drift() {
        let mut c = Connection::open_in_memory().unwrap();
        c.execute_batch(V9_SCHEMA).unwrap();
        c.pragma_update(None, "application_id", APPLICATION_ID)
            .unwrap();
        c.pragma_update(None, "user_version", 9).unwrap();
        c.execute(
            "INSERT INTO signer_account VALUES(1,'synthetic-v9-account',3,1)",
            [],
        )
        .unwrap();
        let before = snapshot_rows(&c);
        migrate_v9(&mut c, "synthetic-v9-account").unwrap();
        assert_eq!(before, snapshot_rows(&c));
        verify_exact_schema(&c, SCHEMA).unwrap();
        assert_eq!(
            c.query_row(
                "SELECT count(*) FROM signer_automation_grant_events",
                [],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
            0
        );
        let mut drift = Connection::open_in_memory().unwrap();
        drift.execute_batch(V9_SCHEMA).unwrap();
        drift
            .pragma_update(None, "application_id", APPLICATION_ID)
            .unwrap();
        drift.pragma_update(None, "user_version", 9).unwrap();
        drift
            .execute_batch("CREATE TABLE unexpected_authority(x TEXT)")
            .unwrap();
        assert!(migrate_v9(&mut drift, "synthetic-v9-account").is_err());
        assert_eq!(
            drift
                .pragma_query_value(None, "user_version", |r| r.get::<_, u64>(0))
                .unwrap(),
            9
        );
    }
    fn v10_fixture() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(V10_SCHEMA).unwrap();
        c.pragma_update(None, "application_id", APPLICATION_ID)
            .unwrap();
        c.pragma_update(None, "user_version", 10).unwrap();
        c.execute(
            "INSERT INTO signer_account VALUES(1,'synthetic-v10-account',9,1)",
            [],
        )
        .unwrap();
        c.execute("INSERT INTO signer_sponsor_policy_events VALUES('synthetic-v10-policy',1,'exact legacy payload')", []).unwrap();
        c.execute("INSERT INTO signer_recovery_generations VALUES('generation','prepared','operation','inventory','fence',9,'exact recovery payload')", []).unwrap();
        c.execute("INSERT INTO signer_enrollments VALUES('enrollment','synthetic-v10-account','agreement','participant','exact enrollment payload')", []).unwrap();
        c.execute("INSERT INTO signer_automation_grant_events VALUES('grant',1,'enrollment','exact automation payload')", []).unwrap();
        c
    }
    #[test]
    fn exact_v10_offline_extension_preserves_old_rows_and_quarantine() {
        let mut c = v10_fixture();
        let before = snapshot_rows_for_schema(&c, V10_SCHEMA);
        migrate_v10(&mut c, "synthetic-v10-account").unwrap();
        assert_eq!(before, snapshot_rows_for_schema(&c, V10_SCHEMA));
        verify_exact_schema(&c, SCHEMA).unwrap();
        assert_eq!(
            c.query_row(
                "SELECT count(*) FROM signer_offline_local_admissions",
                [],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
            0
        );
        assert!(storage::read_account(&c).unwrap().recovery_required);
        assert_eq!(storage::read_account(&c).unwrap().writer_epoch, 9);
    }
    #[test]
    fn v10_wrong_account_drift_and_interruption_never_commit_extension() {
        let mut wrong = v10_fixture();
        assert!(migrate_v10(&mut wrong, "wrong-account").is_err());
        verify_exact_schema(&wrong, V10_SCHEMA).unwrap();
        let mut interrupted = v10_fixture();
        let before = snapshot_rows_for_schema(&interrupted, V10_SCHEMA);
        assert!(migrate_v10_inner(&mut interrupted, "synthetic-v10-account", true).is_err());
        assert_eq!(before, snapshot_rows_for_schema(&interrupted, V10_SCHEMA));
        verify_exact_schema(&interrupted, V10_SCHEMA).unwrap();
        assert_eq!(
            interrupted
                .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            10
        );
        let mut drift = v10_fixture();
        drift
            .execute_batch("CREATE TABLE unexpected_offline_authority(x TEXT)")
            .unwrap();
        assert!(migrate_v10(&mut drift, "synthetic-v10-account").is_err());
        assert_eq!(
            drift
                .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            10
        );
    }
    fn v11_fixture() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(V11_SCHEMA).unwrap();
        c.pragma_update(None, "application_id", APPLICATION_ID)
            .unwrap();
        c.pragma_update(None, "user_version", 11).unwrap();
        c.execute(
            "INSERT INTO signer_account VALUES(1,'synthetic-v11-account',9,1)",
            [],
        )
        .unwrap();
        c.execute("INSERT INTO signer_offline_local_admissions VALUES('offline-authorization','synthetic-v11-account','old-obligation','60','exact prior offline payload')", []).unwrap();
        c.execute("INSERT INTO signer_offline_local_inputs VALUES('offline-authorization','synthetic-v11-account','old-input')", []).unwrap();
        c
    }
    #[test]
    fn v11_provenance_extension_preserves_every_prior_row_and_stays_unknown() {
        let mut c = v11_fixture();
        let before = snapshot_rows_for_schema(&c, V11_SCHEMA);
        migrate_v11(&mut c, "synthetic-v11-account").unwrap();
        assert_eq!(before, snapshot_rows_for_schema(&c, V11_SCHEMA));
        verify_exact_schema(&c, SCHEMA).unwrap();
        let state = account_use_storage::inspect(&c, "synthetic-v11-account").unwrap();
        assert!(state.genesis().is_none());
        assert!(state.exclusion().is_none());
        assert!(state.witness_ack().is_none());
        assert!(storage::read_account(&c).unwrap().recovery_required);
        assert_eq!(storage::read_account(&c).unwrap().writer_epoch, 9);
    }
    #[test]
    fn v11_wrong_account_schema_drift_and_interruption_preserve_old_schema() {
        let mut c = v11_fixture();
        let before = snapshot_rows_for_schema(&c, V11_SCHEMA);
        assert!(migrate_v11(&mut c, "wrong-account").is_err());
        assert!(migrate_v11_inner(&mut c, "synthetic-v11-account", true).is_err());
        verify_exact_schema(&c, V11_SCHEMA).unwrap();
        assert_eq!(before, snapshot_rows_for_schema(&c, V11_SCHEMA));
        assert_eq!(
            c.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            11
        );
        c.execute_batch("CREATE TABLE hidden_genesis(payload TEXT)")
            .unwrap();
        assert!(migrate_v11(&mut c, "synthetic-v11-account").is_err());
        assert_eq!(before, snapshot_rows_for_schema(&c, V11_SCHEMA));
    }
    #[test]
    fn v12_receipt_extension_preserves_all_prior_rows_and_original_epoch() {
        let mut c = Connection::open_in_memory().unwrap();
        c.execute_batch(V12_SCHEMA).unwrap();
        c.pragma_update(None, "application_id", APPLICATION_ID)
            .unwrap();
        c.pragma_update(None, "user_version", 12).unwrap();
        c.execute(
            "INSERT INTO signer_account VALUES(1,'synthetic-v12-account',9,1)",
            [],
        )
        .unwrap();
        let before = snapshot_rows_for_schema(&c, V12_SCHEMA);
        assert!(migrate_v12_inner(&mut c, "synthetic-v12-account", true).is_err());
        verify_exact_schema(&c, V12_SCHEMA).unwrap();
        assert!(migrate_v12(&mut c, "wrong-account").is_err());
        assert_eq!(before, snapshot_rows_for_schema(&c, V12_SCHEMA));
        migrate_v12(&mut c, "synthetic-v12-account").unwrap();
        verify_exact_schema(&c, SCHEMA).unwrap();
        assert_eq!(before, snapshot_rows_for_schema(&c, V12_SCHEMA));
        offline_receipts::validate_all(&c, "synthetic-v12-account").unwrap();
        assert!(storage::read_account(&c).unwrap().recovery_required);
        assert_eq!(storage::read_account(&c).unwrap().writer_epoch, 9);
    }
    #[test]
    fn v12_receipt_extension_rejects_unknown_schema_without_writes() {
        let mut c = Connection::open_in_memory().unwrap();
        c.execute_batch(V12_SCHEMA).unwrap();
        c.pragma_update(None, "application_id", APPLICATION_ID)
            .unwrap();
        c.pragma_update(None, "user_version", 12).unwrap();
        c.execute(
            "INSERT INTO signer_account VALUES(1,'synthetic-v12-account',9,1)",
            [],
        )
        .unwrap();
        c.execute_batch("CREATE TABLE unknown_receipt_authority(payload TEXT)")
            .unwrap();
        assert!(migrate_v12(&mut c, "synthetic-v12-account").is_err());
        assert_eq!(
            c.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            12
        );
    }
    fn snapshot_rows(c: &Connection) -> Vec<(String, Vec<Vec<rusqlite::types::Value>>)> {
        snapshot_rows_for_schema(c, V8_SCHEMA)
    }
    fn snapshot_rows_for_schema(
        c: &Connection,
        schema: &str,
    ) -> Vec<(String, Vec<Vec<rusqlite::types::Value>>)> {
        let reference = Connection::open_in_memory().unwrap();
        reference.execute_batch(schema).unwrap();
        let mut q = reference
            .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
            .unwrap();
        let tables = q
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        tables
            .into_iter()
            .map(|t| {
                let mut q = c
                    .prepare(&format!("SELECT * FROM {t} ORDER BY rowid"))
                    .unwrap();
                let n = q.column_count();
                let rows = q
                    .query_map([], |r| (0..n).map(|i| r.get(i)).collect())
                    .unwrap()
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .unwrap();
                (t, rows)
            })
            .collect()
    }
}

/// Exact schema13 NONBORN predecessor is authenticated before any additive write.
/// No original payload, recovered flag, epoch or accounting row is rewritten.
pub(super) fn migrate_v13(c: &mut Connection, account_id: &str) -> Result<()> {
    migrate_v13_inner(c, account_id, false)
}
fn migrate_v13_inner(c: &mut Connection, account_id: &str, fail: bool) -> Result<()> {
    migrate_from(c, account_id, 13, fail)
}
#[cfg(test)]
mod common_context_migration_tests {
    use super::*;
    fn source() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(V13_SCHEMA).unwrap();
        c.pragma_update(None, "application_id", APPLICATION_ID)
            .unwrap();
        c.pragma_update(None, "user_version", 13).unwrap();
        c.execute(
            "INSERT INTO signer_account VALUES(1,'synthetic-original',7,1)",
            [],
        )
        .unwrap();
        c
    }
    #[test]
    fn additive_common_context_schema_preserves_quarantine_and_rollback() {
        let mut c = source();
        assert!(migrate_v13_inner(&mut c, "synthetic-original", true).is_err());
        verify_exact_schema(&c, V13_SCHEMA).unwrap();
        assert!(migrate_v13(&mut c, "wrong-account").is_err());
        verify_exact_schema(&c, V13_SCHEMA).unwrap();
        migrate_v13(&mut c, "synthetic-original").unwrap();
        verify_exact_schema(&c, SCHEMA).unwrap();
        let state = storage::read_account(&c).unwrap();
        assert_eq!(state.writer_epoch, 7);
        assert!(state.recovery_required);
        assert_eq!(
            c.query_row(
                "SELECT count(*) FROM signer_common_context_audit_v3",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        assert!(verify_exact_schema(&c, V13_SCHEMA).is_err());
    }
}

/// Exact additive schema14 NONBORN migration. No retained row is rewritten.
pub(super) fn migrate_v14(c: &mut Connection, account_id: &str) -> Result<()> {
    migrate_v14_inner(c, account_id, false)
}
fn migrate_v14_inner(c: &mut Connection, account_id: &str, fail: bool) -> Result<()> {
    migrate_from(c, account_id, 14, fail)
}

#[cfg(test)]
mod reentry_foundation_migration_tests {
    use super::*;
    fn fixture() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(V14_SCHEMA).unwrap();
        c.pragma_update(None, "application_id", APPLICATION_ID)
            .unwrap();
        c.pragma_update(None, "user_version", 14).unwrap();
        c.execute(
            "INSERT INTO signer_account VALUES(1,'synthetic-v14-account',7,1)",
            [],
        )
        .unwrap();
        // Migration preserves even unvalidated historical bytes; it never
        // converts this sentinel into a valid receipt or live permission.
        c.execute("INSERT INTO signer_common_context_audit_v3 VALUES('synthetic-invocation','read_admitted','synthetic-v14-account','synthetic-digest','unparsed-original-payload')", []).unwrap();
        c
    }
    #[test]
    fn schema15_addition_preserves_schema14_rows_and_quarantine() {
        let mut c = fixture();
        assert!(migrate_v14(&mut c, "wrong-account").is_err());
        verify_exact_schema(&c, V14_SCHEMA).unwrap();
        assert!(migrate_v14_inner(&mut c, "synthetic-v14-account", true).is_err());
        verify_exact_schema(&c, V14_SCHEMA).unwrap();
        migrate_v14(&mut c, "synthetic-v14-account").unwrap();
        verify_exact_schema(&c, SCHEMA).unwrap();
        assert_eq!(
            c.query_row(
                "SELECT payload FROM signer_common_context_audit_v3",
                [],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
            "unparsed-original-payload"
        );
        let state = storage::read_account(&c).unwrap();
        assert_eq!(state.writer_epoch, 7);
        assert!(state.recovery_required);
        assert_eq!(
            c.query_row(
                "SELECT count(*) FROM signer_common_context_reentry_v1",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }
    #[test]
    fn unimplemented_reentry_rows_are_immutable_and_fail_closed() {
        let mut c = fixture();
        migrate_v14(&mut c, "synthetic-v14-account").unwrap();
        storage::require_no_unimplemented_reentry(&c).unwrap();
        c.execute("INSERT INTO signer_common_context_reentry_v1 VALUES('synthetic-invocation','reentered','synthetic-v14-account','synthetic-reentry-digest','inert-unqualified-payload')", []).unwrap();
        assert!(matches!(
            storage::require_no_unimplemented_reentry(&c),
            Err(JournalError::ConstructionHistoryUnsupported)
        ));
        for sql in [
            "DELETE FROM signer_common_context_reentry_v1",
            "UPDATE signer_common_context_reentry_v1 SET phase='reserved'",
            "INSERT OR REPLACE INTO signer_common_context_reentry_v1 VALUES('synthetic-invocation','reentered','synthetic-v14-account','synthetic-reentry-digest','replacement')",
        ] {
            assert!(c.execute(sql, []).is_err());
        }
    }
}

/// Exact additive schema15 NONBORN migration. Original rows and quarantine survive.
pub(super) fn migrate_v15(c: &mut Connection, account_id: &str) -> Result<()> {
    migrate_v15_inner(c, account_id, false)
}
fn migrate_v15_inner(c: &mut Connection, account_id: &str, fail: bool) -> Result<()> {
    migrate_from(c, account_id, 15, fail)
}

#[cfg(test)]
#[path = "named_recipient_migration_tests.rs"]
mod named_recipient_migration_tests;

/// Exact additive migration; retained requests and quarantine never change.
pub(super) fn migrate_v16(c: &mut Connection, account_id: &str) -> Result<()> {
    migrate_v16_inner(c, account_id, false)
}
fn migrate_v16_inner(c: &mut Connection, account_id: &str, fail: bool) -> Result<()> {
    migrate_from(c, account_id, 16, fail)
}

/// Exact additive schema17 NONBORN extension. Retained evidence remains
/// original; new empty outboxes create no native, financial or writer authority.
pub(super) fn migrate_v17(c: &mut Connection, account_id: &str) -> Result<()> {
    migrate_v17_inner(c, account_id, false)
}
fn migrate_v17_inner(c: &mut Connection, account_id: &str, fail: bool) -> Result<()> {
    migrate_from(c, account_id, 17, fail)
}

#[cfg(test)]
#[path = "durable_construction_migration_tests.rs"]
mod durable_construction_migration_tests;

/// Financial-only schema19 extension. Original BORN18 is deliberately unsupported.
pub(super) fn migrate_v18(c: &mut Connection, account_id: &str) -> Result<()> {
    migrate_from(c, account_id, 18, false)
}

#[cfg(test)]
mod financial_only_migration_tests {
    use super::*;
    use rusqlite::{params, types::Value};
    use wholepact_authority::account_use::{AccountUseGenesis, AccountUseIdentity};

    const ACCOUNT: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const FROZEN: [(i64, &str); 11] = [
        (8, V8_SCHEMA),
        (9, V9_SCHEMA),
        (10, V10_SCHEMA),
        (11, V11_SCHEMA),
        (12, V12_SCHEMA),
        (13, V13_SCHEMA),
        (14, V14_SCHEMA),
        (15, V15_SCHEMA),
        (16, V16_SCHEMA),
        (17, V17_SCHEMA),
        (18, V18_SCHEMA),
    ];

    fn source(version: i64, schema: &str) -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(schema).unwrap();
        c.pragma_update(None, "application_id", APPLICATION_ID)
            .unwrap();
        c.pragma_update(None, "user_version", version).unwrap();
        c.execute("INSERT INTO signer_account VALUES(1,?1,7,1)", [ACCOUNT])
            .unwrap();
        c
    }
    fn rows(c: &Connection, schema: &str) -> Vec<(String, Vec<Vec<Value>>)> {
        let reference = Connection::open_in_memory().unwrap();
        reference.execute_batch(schema).unwrap();
        let mut q = reference
            .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
            .unwrap();
        let tables = q
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        tables
            .into_iter()
            .map(|name| {
                let mut q = c
                    .prepare(&format!("SELECT rowid,* FROM {name} ORDER BY rowid"))
                    .unwrap();
                let width = q.column_count();
                let rows = q
                    .query_map([], |r| (0..width).map(|i| r.get(i)).collect())
                    .unwrap()
                    .collect::<std::result::Result<Vec<Vec<Value>>, _>>()
                    .unwrap();
                (name, rows)
            })
            .collect()
    }
    fn genesis() -> AccountUseGenesis {
        AccountUseGenesis {
            version: 1,
            identity: AccountUseIdentity {
                account_id: ACCOUNT.into(),
                full_viewing_key_digest: "22".repeat(32),
                network_profile_id: "synthetic".into(),
                derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
            },
            witness_id: "synthetic-witness".into(),
            witness_origin_digest: "33".repeat(32),
            owner_certificate_digest: "44".repeat(32),
            native_birth_digest: "55".repeat(32),
        }
    }
    fn insert_genesis(c: &Connection) {
        let g = genesis();
        c.execute(
            "INSERT INTO signer_account_use_genesis VALUES(1,?1,?2,?3,?4)",
            params![
                ACCOUNT,
                g.identity.full_viewing_key_digest,
                g.digest().unwrap(),
                serde_json::to_string(&g).unwrap(),
            ],
        )
        .unwrap();
        assert!(account_use_storage::inspect(c, ACCOUNT)
            .unwrap()
            .genesis()
            .is_some());
    }

    #[test]
    fn every_nonborn_frozen_version_extends_atomically_without_rewriting_original_rows() {
        for (version, schema) in FROZEN {
            let mut c = source(version, schema);
            c.execute("INSERT INTO signer_sponsor_policy_events(rowid,policy_key,version,payload) VALUES(41,'synthetic-original-policy',1,'retained exact original payload')", []).unwrap();
            let before = rows(&c, schema);
            assert_eq!(preflight_open(&c, ACCOUNT).unwrap(), version);
            assert!(migrate_from(&mut c, ACCOUNT, version, true).is_err());
            verify_exact_schema(&c, schema).unwrap();
            assert_eq!(before, rows(&c, schema));
            assert_eq!(
                c.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                    .unwrap(),
                version
            );
            migrate_from(&mut c, ACCOUNT, version, false).unwrap();
            verify_exact_schema(&c, SCHEMA).unwrap();
            assert_eq!(before, rows(&c, schema));
            assert_eq!(
                c.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                    .unwrap(),
                19
            );
            assert_eq!(
                c.query_row(
                    "SELECT count(*) FROM signer_durable_payment_admission_intents",
                    [],
                    |r| r.get::<_, u64>(0)
                )
                .unwrap(),
                0
            );
            let state = account_use_storage::inspect(&c, ACCOUNT).unwrap();
            assert!(state.genesis().is_none());
            assert!(state.exclusion().is_none());
            assert!(state.witness_ack().is_none());
            let account = storage::read_account(&c).unwrap();
            assert_eq!(account.writer_epoch, 7);
            assert!(account.recovery_required);
        }
    }

    #[test]
    fn every_old_account_use_row_refuses_preflight_and_transaction_before_ddl() {
        for (version, schema) in FROZEN.into_iter().filter(|(version, _)| *version >= 12) {
            // These malformed/orphaned rows are deliberate inert corruption,
            // not valid authority. The complete empty-table gate must see them.
            for insert in [
                "INSERT INTO signer_account_use_genesis VALUES(1,'foreign','invalid','invalid','not-json')",
                "INSERT INTO signer_account_use_exclusion VALUES(1,'absent-genesis','invalid','not-json')",
                "INSERT INTO signer_account_use_witness_ack VALUES('absent-exclusion','invalid','invalid','invalid','not-json')",
            ] {
                let mut c = source(version, schema);
                c.pragma_update(None, "foreign_keys", false).unwrap();
                c.execute(insert, []).unwrap();
                let before = rows(&c, schema);
                assert!(preflight_open(&c, ACCOUNT).is_err());
                assert!(migrate_from(&mut c, ACCOUNT, version, false).is_err());
                verify_exact_schema(&c, schema).unwrap();
                assert_eq!(before, rows(&c, schema));
                assert_eq!(c.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0)).unwrap(), version);
            }
            let mut born = source(version, schema);
            insert_genesis(&born);
            let before = rows(&born, schema);
            assert!(preflight_open(&born, ACCOUNT).is_err());
            assert!(migrate_from(&mut born, ACCOUNT, version, false).is_err());
            verify_exact_schema(&born, schema).unwrap();
            assert_eq!(before, rows(&born, schema));
        }
    }

    #[test]
    fn preflight_is_read_only_and_rejects_wrong_identity_application_or_extra_schema() {
        for (version, schema) in FROZEN {
            let mut c = source(version, schema);
            let before = rows(&c, schema);
            c.pragma_update(None, "query_only", true).unwrap();
            assert_eq!(preflight_open(&c, ACCOUNT).unwrap(), version);
            assert!(preflight_open(&c, "wrong-account").is_err());
            assert_eq!(before, rows(&c, schema));
            c.pragma_update(None, "query_only", false).unwrap();
            assert!(migrate_from(&mut c, "wrong-account", version, false).is_err());
            verify_exact_schema(&c, schema).unwrap();
            c.pragma_update(None, "application_id", APPLICATION_ID + 1)
                .unwrap();
            assert!(preflight_open(&c, ACCOUNT).is_err());
            assert!(migrate_from(&mut c, ACCOUNT, version, false).is_err());
            c.pragma_update(None, "application_id", APPLICATION_ID)
                .unwrap();
            c.execute_batch("CREATE TABLE unsupported_discovery_authority(payload TEXT)")
                .unwrap();
            assert!(preflight_open(&c, ACCOUNT).is_err());
            assert!(migrate_from(&mut c, ACCOUNT, version, false).is_err());
            assert_eq!(before, rows(&c, schema));
            assert_eq!(
                c.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                    .unwrap(),
                version
            );
        }
    }

    #[test]
    fn account_use_inserted_after_preflight_is_rejected_again_inside_migration() {
        let mut c = source(18, V18_SCHEMA);
        assert_eq!(preflight_open(&c, ACCOUNT).unwrap(), 18);
        insert_genesis(&c);
        let before = rows(&c, V18_SCHEMA);
        assert!(migrate_v18(&mut c, ACCOUNT).is_err());
        verify_exact_schema(&c, V18_SCHEMA).unwrap();
        assert_eq!(before, rows(&c, V18_SCHEMA));
    }

    #[test]
    fn frozen18_is_not_19_and_current19_keeps_existing_valid_genesis_rules() {
        let old = source(19, V18_SCHEMA);
        assert!(preflight_open(&old, ACCOUNT).is_err());
        let current = source(19, SCHEMA);
        assert_eq!(preflight_open(&current, ACCOUNT).unwrap(), 19);
        insert_genesis(&current);
        assert_eq!(preflight_open(&current, ACCOUNT).unwrap(), 19);
        assert!(verify_exact_schema(&current, V18_SCHEMA).is_err());
    }
}
