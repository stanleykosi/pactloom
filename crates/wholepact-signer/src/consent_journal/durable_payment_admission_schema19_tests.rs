//! Pure synthetic schema predicates, not original-born migration or native birth.
use super::*;
use rusqlite::{params, Connection};

#[test]
fn financial19_is_exact_frozen18_plus_only_financial_intent_objects() {
    assert_eq!(SCHEMA_VERSION, 19);
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch(recovery_migration::V18_SCHEMA).unwrap();
    c.execute_batch(include_str!("durable_payment_admission_schema_v19.sql"))
        .unwrap();
    recovery_migration::verify_exact_schema(&c, SCHEMA).unwrap();
    assert_eq!(
        c.query_row(
            "SELECT count(*) FROM signer_durable_payment_admission_intents",
            [],
            |r| r.get::<_, u64>(0)
        )
        .unwrap(),
        0
    );
    assert!(recovery_migration::verify_exact_schema(&c, recovery_migration::V18_SCHEMA).is_err());
    assert_eq!(
        c.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name LIKE '%durable_input_projection%'",
            [],
            |r| r.get::<_, u64>(0)
        )
        .unwrap(),
        0
    );
}

#[test]
fn immutable_financial_intent_disallows_update_delete_replace_and_all_unique_collisions() {
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch(SCHEMA).unwrap();
    c.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
    c.execute("INSERT INTO signer_durable_payment_admission_intents VALUES('op','auth','digest','e','m','payload')",[]).unwrap();
    for sql in [
        "UPDATE signer_durable_payment_admission_intents SET payload='changed'",
        "DELETE FROM signer_durable_payment_admission_intents",
        "INSERT OR REPLACE INTO signer_durable_payment_admission_intents VALUES('op','new-auth','new-digest','e','m','new')",
        "INSERT OR REPLACE INTO signer_durable_payment_admission_intents VALUES('new-op','auth','new-digest','e','m','new')",
        "INSERT OR REPLACE INTO signer_durable_payment_admission_intents VALUES('new-op','new-auth','digest','e','m','new')",
    ] { assert!(c.execute_batch(sql).is_err()); }
    let retained:(String,String,String,String)=c.query_row("SELECT operation_id,authorization_id,request_digest,payload FROM signer_durable_payment_admission_intents",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
    assert_eq!(
        retained,
        (
            "op".into(),
            "auth".into(),
            "digest".into(),
            "payload".into()
        )
    );
}

#[test]
fn malformed_financial_row_is_not_dropped_by_schema_or_backup_validation() {
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch(SCHEMA).unwrap();
    c.execute("INSERT INTO signer_account VALUES(1,'synthetic',1,0)", [])
        .unwrap();
    c.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
    c.execute(
        "INSERT INTO signer_durable_payment_admission_intents VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            "op",
            "auth",
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(32),
            "{}"
        ],
    )
    .unwrap();
    let changes = c.total_changes();
    assert!(storage::verify_schema(&c).is_err());
    assert_eq!(changes, c.total_changes());
    assert_eq!(
        c.query_row(
            "SELECT count(*) FROM signer_durable_payment_admission_intents",
            [],
            |r| r.get::<_, u64>(0)
        )
        .unwrap(),
        1
    );
}
