//! Inert synthetic schema fixtures. These never produce native approval or a key.
use super::*;
use rusqlite::types::Value;

fn source(sql: &str, version: i64) -> Connection {
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch(sql).unwrap();
    c.pragma_update(None, "application_id", APPLICATION_ID)
        .unwrap();
    c.pragma_update(None, "user_version", version).unwrap();
    c.execute(
        "INSERT INTO signer_account VALUES(1,'synthetic-v16-migration',7,1)",
        [],
    )
    .unwrap();
    c.execute("INSERT INTO signer_sponsor_policy_events VALUES('synthetic-inert-policy',1,'retained unparsed original bytes')", []).unwrap();
    c
}
fn rows(c: &Connection, schema: &str) -> Vec<(String, Vec<Vec<Value>>)> {
    let expected = Connection::open_in_memory().unwrap();
    expected.execute_batch(schema).unwrap();
    let mut q = expected
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
        .unwrap();
    let names = q
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();
    names
        .into_iter()
        .map(|name| {
            let mut q = c
                .prepare(&format!("SELECT rowid,* FROM {name} ORDER BY rowid"))
                .unwrap();
            let width = q.column_count();
            let values = q
                .query_map([], |r| (0..width).map(|i| r.get(i)).collect())
                .unwrap()
                .collect::<std::result::Result<Vec<Vec<Value>>, _>>()
                .unwrap();
            (name, values)
        })
        .collect()
}
fn named_tables_empty(c: &Connection) {
    let outbox: u64 = c
        .query_row("SELECT count(*) FROM signer_named_intent_outbox", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(outbox, 0);
    for suffix in ["profiles", "originals", "receipts", "started", "results"] {
        let n: u64 = c
            .query_row(
                &format!("SELECT count(*) FROM signer_named_recipient_{suffix}"),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 0);
    }
}
#[test]
fn named_schema16_preserves_exact_v15_rows_and_rollback() {
    let mut c = source(V15_SCHEMA, 15);
    c.execute("INSERT INTO signer_common_context_reentry_v1 VALUES('synthetic-original','reentered','synthetic-v16-migration','synthetic-digest','exact unparsed reentry payload')", []).unwrap();
    let before = rows(&c, V15_SCHEMA);
    assert!(migrate_v15(&mut c, "wrong-account").is_err());
    assert!(migrate_v15_inner(&mut c, "synthetic-v16-migration", true).is_err());
    verify_exact_schema(&c, V15_SCHEMA).unwrap();
    assert_eq!(before, rows(&c, V15_SCHEMA));
    assert_eq!(
        c.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        15
    );
    migrate_v15(&mut c, "synthetic-v16-migration").unwrap();
    verify_exact_schema(&c, SCHEMA).unwrap();
    assert_eq!(before, rows(&c, V15_SCHEMA));
    let account = storage::read_account(&c).unwrap();
    assert_eq!(account.writer_epoch, 7);
    assert!(account.recovery_required);
    named_tables_empty(&c);
}
#[test]
fn named_schema16_every_exact_legacy_template_gets_empty_extension() {
    for (version, sql) in [
        (8, V8_SCHEMA),
        (9, V9_SCHEMA),
        (10, V10_SCHEMA),
        (11, V11_SCHEMA),
        (12, V12_SCHEMA),
        (13, V13_SCHEMA),
        (14, V14_SCHEMA),
        (15, V15_SCHEMA),
    ] {
        let mut c = source(sql, version);
        let before = rows(&c, sql);
        match version {
            8 => migrate_v8(&mut c),
            9 => migrate_v9(&mut c),
            10 => migrate_v10(&mut c, "synthetic-v16-migration"),
            11 => migrate_v11(&mut c, "synthetic-v16-migration"),
            12 => migrate_v12(&mut c, "synthetic-v16-migration"),
            13 => migrate_v13(&mut c, "synthetic-v16-migration"),
            14 => migrate_v14(&mut c, "synthetic-v16-migration"),
            15 => migrate_v15(&mut c, "synthetic-v16-migration"),
            _ => unreachable!(),
        }
        .unwrap();
        verify_exact_schema(&c, SCHEMA).unwrap();
        assert_eq!(before, rows(&c, sql));
        named_tables_empty(&c);
        assert_eq!(
            c.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            16
        );
    }
}
#[test]
fn named_schema16_refuses_zero_unknown_and_extra_objects_without_mutation() {
    for extra in [
        "CREATE TABLE unaccounted(x TEXT)",
        "CREATE VIEW unaccounted AS SELECT account_id FROM signer_account",
        "CREATE INDEX unaccounted ON signer_account(account_id)",
        "CREATE TRIGGER unaccounted AFTER INSERT ON signer_account BEGIN SELECT 1; END",
    ] {
        let mut c = source(V15_SCHEMA, 15);
        c.execute_batch(extra).unwrap();
        let before = rows(&c, V15_SCHEMA);
        assert!(matches!(
            migrate_v15(&mut c, "synthetic-v16-migration"),
            Err(JournalError::UnsupportedSchema)
        ));
        assert_eq!(before, rows(&c, V15_SCHEMA));
        assert_eq!(
            c.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            15
        );
    }
    for version in [0, 7, 16, 99] {
        let mut c = source(V15_SCHEMA, version);
        assert!(matches!(
            migrate_v15(&mut c, "synthetic-v16-migration"),
            Err(JournalError::UnsupportedSchema)
        ));
        verify_exact_schema(&c, V15_SCHEMA).unwrap();
    }
}
#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    target_os = "linux"
))]
#[test]
fn named_schema16_keeps_legacy_versioned_backup_templates_exact() {
    for (version, sql) in [
        (8, V8_SCHEMA),
        (9, V9_SCHEMA),
        (10, V10_SCHEMA),
        (11, V11_SCHEMA),
        (12, V12_SCHEMA),
        (13, V13_SCHEMA),
        (14, V14_SCHEMA),
        (15, V15_SCHEMA),
        (16, SCHEMA),
    ] {
        let template = recovery_template(version).unwrap();
        assert_eq!(template.schema_version, version);
        assert_eq!(template.create_sql.as_bytes(), sql.as_bytes());
    }
    assert!(SCHEMA.as_bytes().starts_with(V15_SCHEMA.as_bytes()));
}
