//! Unrun synthetic contention tests. No native owner, proof, wallet or network.
use super::*;
use rusqlite::Connection;

fn timeout(c: &Connection) -> u32 {
    c.pragma_query_value(None, "busy_timeout", |r| r.get(0))
        .unwrap()
}

#[test]
fn exact_scope_restores_actual_timeout_after_success_and_sql_error() {
    let store = Store::in_memory().unwrap();
    let mut c = store.connection.lock().unwrap();
    for previous in [37, 5000] {
        c.busy_timeout(Duration::from_millis(previous)).unwrap();
        assert_eq!(
            with_zero_busy_timeout(&mut c, |c| {
                assert_eq!(timeout(c), 0);
                Ok(7)
            })
            .unwrap(),
            7
        );
        assert_eq!(timeout(&c), previous as u32);
        assert!(
            with_zero_busy_timeout::<()>(&mut c, |c| {
                assert_eq!(timeout(c), 0);
                c.execute("INSERT INTO absent_synthetic_table VALUES(1)", [])?;
                Ok(())
            })
            .is_err()
        );
        assert_eq!(timeout(&c), previous as u32);
        ManualPersistenceMode::Existing
            .with_connection(&mut c, |c| {
                assert_eq!(timeout(c), previous as u32);
                Ok(())
            })
            .unwrap();
    }
}

#[test]
fn unwind_restores_timeout_before_poisoned_owner_is_released() {
    let store = Store::in_memory().unwrap();
    let caught = catch_unwind(AssertUnwindSafe(|| {
        let mut c = store.connection.lock().unwrap();
        c.busy_timeout(Duration::from_millis(73)).unwrap();
        let _: Result<()> = with_zero_busy_timeout(&mut c, |c| {
            assert_eq!(timeout(c), 0);
            panic!("synthetic callback panic")
        });
    }));
    assert!(caught.is_err());
    let guard = match store.connection.lock() {
        Err(error) => error.into_inner(),
        Ok(_) => panic!("unwound Store mutex must stay poisoned"),
    };
    assert_eq!(timeout(&guard), 73);
    drop(guard);
    assert!(matches!(
        store.manual_store_target_fail_fast(),
        Err(StoreError::Poisoned)
    ));
}

#[test]
fn zero_or_custom_callback_policy_is_refused_without_replacement() {
    let store = Store::in_memory().unwrap();
    let mut c = store.connection.lock().unwrap();
    c.busy_timeout(Duration::ZERO).unwrap();
    let called = std::cell::Cell::new(false);
    assert!(matches!(
        with_zero_busy_timeout(&mut c, |_| {
            called.set(true);
            Ok(())
        }),
        Err(StoreError::RecoveryRequired)
    ));
    assert!(!called.get());
    assert_eq!(timeout(&c), 0);
    c.busy_handler(Some(|_| false)).unwrap();
    assert!(with_zero_busy_timeout(&mut c, |_| Ok(())).is_err());
}

#[test]
fn actual_sqlite_writer_contention_refuses_and_restores_policy() {
    // Plaintext exists only inside this synthetic test. It does not qualify an
    // encrypted factory, generation owner or native admission.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic-contention.sqlite");
    let store = Store::open(&path).unwrap();
    let other = Connection::open(&path).unwrap();
    other.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut c = store.connection.lock().unwrap();
    let started = std::time::Instant::now();
    let result = with_zero_busy_timeout(&mut c, |c| {
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.commit()?;
        Ok(())
    });
    assert!(matches!(result, Err(StoreError::Database(_))));
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "no configured 5-second busy wait"
    );
    assert_eq!(timeout(&c), 5000);
    other.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn target_read_adapters_preserve_checks_and_restore_policy() {
    let store = crate::manual_enrollment::tests::modeled_store();
    let target = store.manual_store_target().unwrap();
    let ctx = crate::CommandContext::for_request(
        "owner",
        "synthetic-fast-read-key",
        &serde_json::json!([1]),
    )
    .unwrap();
    let record = store
        .create_agreement(
            &ctx,
            "synthetic-fast-agreement",
            serde_json::json!({"fixture":true}),
        )
        .unwrap()
        .record;
    let exact = store.manual_store_target_fail_fast().unwrap();
    assert_eq!(exact.generation_id(), target.generation_id());
    assert_eq!(exact.inventory_digest(), target.inventory_digest());
    assert_eq!(
        exact.store_destination_identity(),
        target.store_destination_identity()
    );
    assert_eq!(
        exact
            .current_agreement_record_fail_fast("synthetic-fast-agreement")
            .unwrap(),
        record
    );
    assert_eq!(
        target
            .current_agreement_record("synthetic-fast-agreement")
            .unwrap(),
        record
    );
    assert!(
        exact
            .current_agreement_record_fail_fast("missing-agreement")
            .is_err()
    );
    assert_eq!(timeout(&store.connection.lock().unwrap()), 5000);
    {
        let _held = store.connection.lock().unwrap();
        assert!(matches!(
            store.manual_store_target_fail_fast(),
            Err(StoreError::ResourceExhausted)
        ));
        assert!(matches!(
            exact.check_current_fail_fast(),
            Err(StoreError::ResourceExhausted)
        ));
        assert!(matches!(
            exact.current_agreement_record_fail_fast("synthetic-fast-agreement"),
            Err(StoreError::ResourceExhausted)
        ));
    }
    store
        .connection
        .lock()
        .unwrap()
        .execute("UPDATE store_recovery SET recovery_required=0, restored_at_ms=NULL, source_snapshot_digest=NULL", [])
        .unwrap();
    assert!(target.check_current().is_err());
    assert!(exact.check_current_fail_fast().is_err());
    assert_eq!(timeout(&store.connection.lock().unwrap()), 5000);
}
