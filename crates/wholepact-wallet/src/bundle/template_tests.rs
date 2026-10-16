//! Staged template-only tests. No viewing material, wallet import, provider,
//! runtime reopen, signing, network, or activation is used by these fixtures.
use super::*;

fn schema(connection: &Connection) -> Vec<(String, String, String, Option<String>)> {
    connection
        .prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name")
        .unwrap()
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}
#[test]
fn recorded_template_adds_only_fixed_schema_and_leaves_legacy_identity_and_bytes() {
    let legacy = trusted_template().unwrap();
    let before = legacy.create_sql.to_owned();
    let new = trusted_recorded_import_template().unwrap();
    assert_eq!(legacy.kind, new.kind);
    assert_eq!(legacy.application_id, new.application_id);
    assert_eq!(legacy.schema_version, new.schema_version);
    assert_eq!(legacy.create_sql, before);
    assert_eq!(
        new.create_sql,
        format!("{}\n{}", before, crate::wallet::recorded_import::SCHEMA)
    );
    assert!(!legacy.create_sql.contains("ext_wholepact_import_records"));
    let original = Connection::open_in_memory().unwrap();
    original.execute_batch(legacy.create_sql).unwrap();
    let recorded = Connection::open_in_memory().unwrap();
    recorded.execute_batch(new.create_sql).unwrap();
    let old_schema = schema(&original);
    let new_schema = schema(&recorded);
    assert!(
        new_schema
            .iter()
            .any(|object| object.1 == "ext_wholepact_import_records")
    );
    assert_eq!(
        old_schema,
        new_schema
            .into_iter()
            .filter(|object| object.2 != "ext_wholepact_import_records")
            .collect::<Vec<_>>()
    );
}
#[test]
fn template_memoization_does_not_change_legacy_sql_after_new_layout_is_built() {
    let first = trusted_template().unwrap();
    let new = trusted_recorded_import_template().unwrap();
    let second = trusted_template().unwrap();
    assert!(std::ptr::eq(first, second));
    assert!(!std::ptr::eq(first, new));
}

#[test]
fn roster_v2_layout_is_separate_and_does_not_rewrite_v1_or_legacy_schema() {
    let legacy = trusted_template().unwrap();
    let v1 = trusted_recorded_import_template().unwrap();
    let old = v1.create_sql.to_owned();
    let v2 = trusted_recorded_roster_import_v2_template().unwrap();
    assert_eq!(v1.create_sql, old);
    assert_eq!(
        v2.create_sql,
        format!(
            "{}\n{}",
            legacy.create_sql,
            crate::wallet::recorded_roster_import_v2::SCHEMA
        )
    );
    assert_eq!(legacy.application_id, v2.application_id);
    assert_eq!(legacy.schema_version, v2.schema_version);
    assert!(
        !v2.create_sql
            .contains("CREATE TABLE ext_wholepact_import_records(")
    );
    assert!(
        !v1.create_sql
            .contains("ext_wholepact_roster_import_records_v2")
    );
    let a = Connection::open_in_memory().unwrap();
    a.execute_batch(legacy.create_sql).unwrap();
    let b = Connection::open_in_memory().unwrap();
    b.execute_batch(v2.create_sql).unwrap();
    assert_eq!(
        schema(&a),
        schema(&b)
            .into_iter()
            .filter(|object| object.2 != "ext_wholepact_roster_import_records_v2")
            .collect::<Vec<_>>()
    );
    assert_eq!(trusted_wallet_templates().unwrap().len(), 3);
}
