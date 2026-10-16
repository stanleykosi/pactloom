//! Exact transactional schema extension; migration never clears recovery state.
use super::*;
use rusqlite::{Connection, TransactionBehavior};
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
pub(super) fn migrate_v8(c: &mut Connection) -> Result<()> {
    migrate(c, false)
}
fn migrate(c: &mut Connection, inject_failure: bool) -> Result<()> {
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let application: i64 = tx.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if application != APPLICATION_ID || version != 8 {
        return Err(JournalError::UnsupportedSchema);
    }
    verify_exact_schema(&tx, V8_SCHEMA)?;
    tx.execute_batch(RECOVERY_SCHEMA)?;
    tx.execute_batch(AUTOMATION_SCHEMA)?;
    tx.execute_batch(OFFLINE_SCHEMA)?;
    tx.execute_batch(ACCOUNT_USE_SCHEMA)?;
    tx.execute_batch(OFFLINE_RECEIPTS_SCHEMA)?;
    tx.execute_batch(COMMON_CONTEXT_AUDIT_SCHEMA)?;
    tx.execute_batch(COMMON_CONTEXT_REENTRY_SCHEMA)?;
    if inject_failure {
        return Err(JournalError::Database);
    }
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    // The ONLY writes are new empty schema objects and the schema version.
    // No account, policy, consent, release, witness or budget rows are modified.
    verify_exact_schema(&tx, SCHEMA)?;
    tx.commit()?;
    Ok(())
}

pub(super) fn migrate_v9(c: &mut Connection) -> Result<()> {
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let application: i64 = tx.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if application != APPLICATION_ID || version != 9 {
        return Err(JournalError::UnsupportedSchema);
    }
    verify_exact_schema(&tx, V9_SCHEMA)?;
    tx.execute_batch(AUTOMATION_SCHEMA)?;
    tx.execute_batch(OFFLINE_SCHEMA)?;
    tx.execute_batch(ACCOUNT_USE_SCHEMA)?;
    tx.execute_batch(OFFLINE_RECEIPTS_SCHEMA)?;
    tx.execute_batch(COMMON_CONTEXT_AUDIT_SCHEMA)?;
    tx.execute_batch(COMMON_CONTEXT_REENTRY_SCHEMA)?;
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    verify_exact_schema(&tx, SCHEMA)?;
    tx.commit()?;
    Ok(())
}

/// Exact additive v10 migration. Account identity is checked before writes;
/// no legacy payload/reference, writer epoch, recovery flag or budget changes.
pub(super) fn migrate_v10(c: &mut Connection, account_id: &str) -> Result<()> {
    migrate_v10_inner(c, account_id, false)
}
fn migrate_v10_inner(c: &mut Connection, account_id: &str, inject_failure: bool) -> Result<()> {
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let application: i64 = tx.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if application != APPLICATION_ID || version != 10 {
        return Err(JournalError::UnsupportedSchema);
    }
    verify_exact_schema(&tx, V10_SCHEMA)?;
    if storage::read_account(&tx)?.account_id != account_id {
        return Err(JournalError::InvalidBinding);
    }
    tx.execute_batch(OFFLINE_SCHEMA)?;
    tx.execute_batch(ACCOUNT_USE_SCHEMA)?;
    tx.execute_batch(OFFLINE_RECEIPTS_SCHEMA)?;
    tx.execute_batch(COMMON_CONTEXT_AUDIT_SCHEMA)?;
    tx.execute_batch(COMMON_CONTEXT_REENTRY_SCHEMA)?;
    if inject_failure {
        return Err(JournalError::Database);
    }
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    verify_exact_schema(&tx, SCHEMA)?;
    tx.commit()?;
    Ok(())
}

/// Empty additive migration preserves all old evidence and unknown provenance.
pub(super) fn migrate_v11(c: &mut Connection, account_id: &str) -> Result<()> {
    migrate_v11_inner(c, account_id, false)
}
fn migrate_v11_inner(c: &mut Connection, account_id: &str, inject_failure: bool) -> Result<()> {
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let application: i64 = tx.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if application != APPLICATION_ID || version != 11 {
        return Err(JournalError::UnsupportedSchema);
    }
    verify_exact_schema(&tx, V11_SCHEMA)?;
    if storage::read_account(&tx)?.account_id != account_id {
        return Err(JournalError::InvalidBinding);
    }
    tx.execute_batch(ACCOUNT_USE_SCHEMA)?;
    tx.execute_batch(OFFLINE_RECEIPTS_SCHEMA)?;
    tx.execute_batch(COMMON_CONTEXT_AUDIT_SCHEMA)?;
    tx.execute_batch(COMMON_CONTEXT_REENTRY_SCHEMA)?;
    if inject_failure {
        return Err(JournalError::Database);
    }
    // Never insert genesis, clear quarantine, rewrite offline exposure, or replace
    // any lifetime account/policy row during a schema-only migration.
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    verify_exact_schema(&tx, SCHEMA)?;
    tx.commit()?;
    Ok(())
}

/// Exact additive v12-to-v13 extension. Old genesis/exclusions stay untouched.
pub(super) fn migrate_v12(c: &mut Connection, account_id: &str) -> Result<()> {
    migrate_v12_inner(c, account_id, false)
}
fn migrate_v12_inner(c: &mut Connection, account_id: &str, inject_failure: bool) -> Result<()> {
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let application: i64 = tx.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if application != APPLICATION_ID || version != 12 {
        return Err(JournalError::UnsupportedSchema);
    }
    verify_exact_schema(&tx, V12_SCHEMA)?;
    if storage::read_account(&tx)?.account_id != account_id {
        return Err(JournalError::InvalidBinding);
    }
    tx.execute_batch(OFFLINE_RECEIPTS_SCHEMA)?;
    tx.execute_batch(COMMON_CONTEXT_AUDIT_SCHEMA)?;
    tx.execute_batch(COMMON_CONTEXT_REENTRY_SCHEMA)?;
    if inject_failure {
        return Err(JournalError::Database);
    }
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    verify_exact_schema(&tx, SCHEMA)?;
    tx.commit()?;
    Ok(())
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
        migrate_v8(&mut c).unwrap();
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
        assert!(migrate(&mut c, true).is_err());
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
        migrate_v9(&mut c).unwrap();
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
        assert!(migrate_v9(&mut drift).is_err());
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

/// Exact schema13 predecessor is authenticated before the additive v14 write.
/// No original payload, recovered flag, epoch or accounting row is rewritten.
pub(super) fn migrate_v13(c: &mut Connection, account_id: &str) -> Result<()> {
    migrate_v13_inner(c, account_id, false)
}
fn migrate_v13_inner(c: &mut Connection, account_id: &str, fail: bool) -> Result<()> {
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let application: i64 = tx.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if application != APPLICATION_ID || version != 13 {
        return Err(JournalError::UnsupportedSchema);
    }
    verify_exact_schema(&tx, V13_SCHEMA)?;
    if storage::read_account(&tx)?.account_id != account_id {
        return Err(JournalError::InvalidBinding);
    }
    tx.execute_batch(COMMON_CONTEXT_AUDIT_SCHEMA)?;
    tx.execute_batch(COMMON_CONTEXT_REENTRY_SCHEMA)?;
    if fail {
        return Err(JournalError::Database);
    }
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    verify_exact_schema(&tx, SCHEMA)?;
    tx.commit()?;
    Ok(())
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

/// Exact additive v14-to-v15 migration. No retained row is rewritten.
pub(super) fn migrate_v14(c: &mut Connection, account_id: &str) -> Result<()> {
    migrate_v14_inner(c, account_id, false)
}
fn migrate_v14_inner(c: &mut Connection, account_id: &str, fail: bool) -> Result<()> {
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let application: i64 = tx.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if application != APPLICATION_ID || version != 14 {
        return Err(JournalError::UnsupportedSchema);
    }
    verify_exact_schema(&tx, V14_SCHEMA)?;
    if storage::read_account(&tx)?.account_id != account_id {
        return Err(JournalError::InvalidBinding);
    }
    tx.execute_batch(COMMON_CONTEXT_REENTRY_SCHEMA)?;
    if fail {
        return Err(JournalError::Database);
    }
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    verify_exact_schema(&tx, SCHEMA)?;
    tx.commit()?;
    Ok(())
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
