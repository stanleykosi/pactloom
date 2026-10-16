use super::*;
use crate::authority::{ExposureState, ReleaseIntent};
use serde_json::json;
use std::sync::{Arc, Barrier};

fn context(key: &str, body: Value) -> CommandContext {
    CommandContext::for_request("test-client", key, &body).unwrap()
}
fn temporary_path() -> std::path::PathBuf {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "wholepact-store-{}-{}-{}.sqlite",
        std::process::id(),
        now_ms(),
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ))
}
fn cleanup(path: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}
fn intent(id: &str, obligation: &str, input: &str, maximum: &str, budget: &str) -> ReleaseIntent {
    ReleaseIntent {
        authorization_id: id.into(),
        account_id: "account-a".into(),
        writer_epoch: 1,
        obligation_id: obligation.into(),
        proposal_id: format!("proposal-{id}"),
        manifest_digest: "a".repeat(64),
        effects_digest: "b".repeat(64),
        artifact_digest: "c".repeat(64),
        maximum_debit: maximum.into(),
        input_ids: vec![input.into()],
        aggregate_budget_limit: budget.into(),
    }
}

#[test]
fn semantic_retry_returns_original_operation_before_revision_check() {
    let store = Store::in_memory().unwrap();
    let ctx = context(
        "create-agreement-0001",
        json!({"command":"create","id":"a"}),
    );
    let first = store
        .create_agreement(&ctx, "a", json!({"purpose":"one"}))
        .unwrap();
    assert_eq!(first.record.revision, 1);
    let replay = store
        .create_agreement(&ctx, "a", json!({"purpose":"one","derived_timestamp":999}))
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.operation_id, first.operation_id);
    assert_eq!(replay.record, first.record);
    let bad = context(
        "create-agreement-0001",
        json!({"command":"create","id":"changed"}),
    );
    assert!(matches!(
        store.create_agreement(&bad, "changed", json!({})),
        Err(StoreError::IdempotencyConflict)
    ));
    assert_eq!(store.events_after(0, 10).unwrap().len(), 1);
}
#[test]
fn concurrent_writers_use_cas_and_atomic_event_commit() {
    let path = temporary_path();
    let initial = Store::open(&path).unwrap();
    initial
        .create_agreement(
            &context("create-race-key-0001", json!({"create":"a"})),
            "a",
            json!({"count":0}),
        )
        .unwrap();
    drop(initial);
    let barrier = Arc::new(Barrier::new(2));
    let workers = (0..2)
        .map(|i| {
            let p = path.clone();
            let b = barrier.clone();
            std::thread::spawn(move || {
                let s = Store::open(p).unwrap();
                b.wait();
                s.update_agreement(
                    &context(
                        &format!("race-update-key-{i:04}"),
                        json!({"write":i,"expected_revision":1}),
                    ),
                    "a",
                    1,
                    json!({"count":i+1}),
                    "agreement.changed",
                )
            })
        })
        .collect::<Vec<_>>();
    let results = workers
        .into_iter()
        .map(|h| h.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(StoreError::RevisionConflict)))
            .count(),
        1
    );
    let final_store = Store::open(&path).unwrap();
    assert_eq!(final_store.get_agreement("a").unwrap().unwrap().revision, 2);
    assert_eq!(final_store.events_after(0, 10).unwrap().len(), 2);
    drop(final_store);
    cleanup(&path);
}
#[test]
fn fault_during_event_write_rolls_back_state_and_idempotency_together() {
    let store = Store::in_memory().unwrap();
    store.connection.lock().unwrap().execute_batch("CREATE TRIGGER injected_failure BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'fault'); END;").unwrap();
    let ctx = context("crash-boundary-key-001", json!({"create":"a"}));
    assert!(store.create_agreement(&ctx, "a", json!({})).is_err());
    assert!(store.get_agreement("a").unwrap().is_none());
    assert!(store.find_replay(&ctx).unwrap().is_none());
    assert!(store.events_after(0, 10).unwrap().is_empty());
    store
        .connection
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER injected_failure;")
        .unwrap();
    assert!(store.create_agreement(&ctx, "a", json!({})).is_ok());
    store.verify_integrity().unwrap();
}
#[test]
fn proposals_are_immutable_even_when_a_caller_supplies_current_revision() {
    let store = Store::in_memory().unwrap();
    store
        .commit_record(
            &context("proposal-create-key1", json!({"create":"p"})),
            "proposal",
            "p",
            None,
            json!({"effects":"a"}),
            "proposal.created",
        )
        .unwrap();
    assert!(matches!(
        store.commit_record(
            &context("proposal-update-key1", json!({"change":"p"})),
            "proposal",
            "p",
            Some(1),
            json!({"effects":"b"}),
            "proposal.updated"
        ),
        Err(StoreError::InvalidInput(_))
    ));
}
#[test]
fn release_intent_survives_restart_and_blocks_duplicate_obligation_or_input() {
    let path = temporary_path();
    let s = Store::open(&path).unwrap();
    s.initialize_authority_account("account-a", 1).unwrap();
    let request = intent("auth-a", "obligation-a", "note-a", "70", "200");
    let first = s.record_authorization_release_intent(&request).unwrap();
    assert_eq!(first.state, ExposureState::OutstandingUncertain);
    drop(s);
    let s = Store::open(&path).unwrap();
    assert_eq!(s.outstanding_debit("account-a").unwrap(), "70");
    assert_eq!(
        s.record_authorization_release_intent(&request).unwrap(),
        first
    );
    assert!(matches!(
        s.record_authorization_release_intent(&intent(
            "auth-b",
            "obligation-a",
            "note-b",
            "20",
            "200"
        )),
        Err(StoreError::LiveAuthorizationExists)
    ));
    assert!(matches!(
        s.record_authorization_release_intent(&intent(
            "auth-c",
            "obligation-c",
            "note-a",
            "20",
            "200"
        )),
        Err(StoreError::InputReserved)
    ));
    s.mark_authorization_released("auth-a").unwrap();
    assert_eq!(
        s.exposure("auth-a").unwrap().unwrap().state,
        ExposureState::Released
    );
    drop(s);
    cleanup(&path);
}
#[test]
fn concurrent_apps_compete_for_one_authoritative_budget() {
    let path = temporary_path();
    let initial = Store::open(&path).unwrap();
    initial
        .initialize_authority_account("account-a", 1)
        .unwrap();
    drop(initial);
    let barrier = Arc::new(Barrier::new(4));
    let handles = (0..4)
        .map(|i| {
            let p = path.clone();
            let b = barrier.clone();
            std::thread::spawn(move || {
                let store = Store::open(p).unwrap();
                b.wait();
                store.record_authorization_release_intent(&intent(
                    &format!("auth-{i}"),
                    &format!("obligation-{i}"),
                    &format!("note-{i}"),
                    "35",
                    "100",
                ))
            })
        })
        .collect::<Vec<_>>();
    let outcomes = handles
        .into_iter()
        .map(|h| h.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(outcomes.iter().filter(|o| o.is_ok()).count(), 2);
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| matches!(o, Err(StoreError::BudgetExceeded)))
            .count(),
        2
    );
    let store = Store::open(&path).unwrap();
    assert_eq!(store.outstanding_debit("account-a").unwrap(), "70");
    drop(store);
    cleanup(&path);
}
#[test]
fn stale_writer_and_restored_ledger_cannot_issue_release_intent() {
    let s = Store::in_memory().unwrap();
    s.import_restored_account("account-a", 1).unwrap();
    assert!(matches!(
        s.record_authorization_release_intent(&intent("a", "o", "n", "1", "10")),
        Err(StoreError::RecoveryRequired)
    ));
    let fresh = Store::in_memory().unwrap();
    fresh.initialize_authority_account("account-a", 2).unwrap();
    assert!(matches!(
        fresh.record_authorization_release_intent(&intent("a", "o", "n", "1", "10")),
        Err(StoreError::WriterEpochMismatch)
    ));
}
// Private historical-data fixture, not an admission capability. Legacy journals
// may contain alternatives created before the conservative gate was fixed.
fn insert_legacy_alternative(store: &Store, release: &ReleaseIntent) {
    let value = serde_json::to_value(release).unwrap();
    let c = store.connection.lock().unwrap();
    c.execute("INSERT INTO authority_exposures(authorization_id,account_id,obligation_id,proposal_id,request_digest,maximum_debit,state,release_intent,payload,created_at_ms,updated_at_ms) VALUES(?1,?2,?3,?4,?5,?6,'outstanding_uncertain',1,?7,1,1)", params![release.authorization_id,release.account_id,release.obligation_id,release.proposal_id,request_digest(&value).unwrap(),release.maximum_debit,encode(&value).unwrap()]).unwrap();
    for input in &release.input_ids {
        c.execute(
            "INSERT OR IGNORE INTO authority_reservations VALUES(?1,?2,?3)",
            params![release.account_id, input, release.authorization_id],
        )
        .unwrap();
    }
}

#[test]
fn reorg_reopens_old_exposure_and_quarantines_even_after_legacy_replacement() {
    let s = Store::in_memory().unwrap();
    s.initialize_authority_account("account-a", 1).unwrap();
    s.record_authorization_release_intent(&intent("old", "obligation", "old-note", "60", "100"))
        .unwrap();
    s.record_observed_resolution("old", ExposureState::ExpiredObserved, "chain-evidence-1")
        .unwrap();
    assert_eq!(s.outstanding_debit("account-a").unwrap(), "60");
    let replacement = intent("new", "obligation", "new-note", "60", "100");
    assert!(matches!(
        s.record_authorization_release_intent(&replacement),
        Err(StoreError::LiveAuthorizationExists)
    ));
    insert_legacy_alternative(&s, &replacement);
    s.reopen_exposure_after_reorg("old", "reorg-evidence-2")
        .unwrap();
    assert_eq!(s.outstanding_debit("account-a").unwrap(), "120");
    assert!(
        s.authority_account("account-a")
            .unwrap()
            .unwrap()
            .recovery_required
    );
    assert!(matches!(
        s.record_authorization_release_intent(&intent("third", "other", "third-note", "1", "500")),
        Err(StoreError::RecoveryRequired)
    ));
    assert_eq!(s.account_exposures("account-a").unwrap().len(), 2);
}
#[test]
fn uncertain_external_effect_retry_cannot_change_exact_payload() {
    let path = temporary_path();
    let s = Store::open(&path).unwrap();
    let first = s
        .record_effect_intent(
            "submit-a",
            "submit_exact",
            "proposal-a",
            &"d".repeat(64),
            "blob-a",
        )
        .unwrap();
    drop(s);
    let s = Store::open(&path).unwrap();
    assert_eq!(s.unresolved_effect_intents().unwrap(), vec![first.clone()]);
    assert_eq!(
        s.record_effect_intent(
            "submit-a",
            "submit_exact",
            "proposal-a",
            &"d".repeat(64),
            "blob-a"
        )
        .unwrap(),
        first
    );
    assert!(matches!(
        s.record_effect_intent(
            "submit-a",
            "submit_exact",
            "proposal-a",
            &"e".repeat(64),
            "blob-b"
        ),
        Err(StoreError::IdempotencyConflict)
    ));
    drop(s);
    cleanup(&path);
}
#[test]
fn consumed_obligation_cannot_be_paid_again_but_new_obligation_can() {
    let s = Store::in_memory().unwrap();
    s.initialize_authority_account("account-a", 1).unwrap();
    s.record_authorization_release_intent(&intent("paid", "invoice-a", "note-paid", "60", "100"))
        .unwrap();
    s.record_observed_resolution(
        "paid",
        ExposureState::Consumed,
        "confirmed-settlement-evidence",
    )
    .unwrap();
    assert_eq!(s.outstanding_debit("account-a").unwrap(), "0");
    assert!(matches!(
        s.record_authorization_release_intent(&intent(
            "duplicate",
            "invoice-a",
            "fresh-note",
            "60",
            "100"
        )),
        Err(StoreError::LiveAuthorizationExists)
    ));
    // Consumed debit remains charged to the reusable aggregate budget.
    assert!(matches!(
        s.record_authorization_release_intent(&intent(
            "too-large-next",
            "invoice-b",
            "new-note",
            "60",
            "100"
        )),
        Err(StoreError::BudgetExceeded)
    ));
    s.record_authorization_release_intent(&intent("next", "invoice-b", "new-note", "40", "100"))
        .unwrap();
    assert_eq!(s.settled_debit("account-a").unwrap(), "60");
    assert_eq!(s.outstanding_debit("account-a").unwrap(), "40");
}
#[test]
fn agreement_quotas_are_authoritative_and_do_not_block_original_replay() {
    let s = Store::in_memory().unwrap();
    for owner in 0..4 {
        for i in 0..64 {
            let id = format!("agreement-{owner}-{i}");
            let ctx = CommandContext::for_request(
                format!("owner-{owner}"),
                format!("create-agreement-{owner}-{i:04}"),
                &json!({"create":id}),
            )
            .unwrap();
            s.create_agreement(
                &ctx,
                &id,
                json!({"owner_client_id":"untrusted-payload-owner"}),
            )
            .unwrap();
        }
        let blocked = CommandContext::for_request(
            format!("owner-{owner}"),
            "new-over-quota-key",
            &json!({"create":"over"}),
        )
        .unwrap();
        assert!(matches!(
            s.create_agreement(&blocked, "over", json!({})),
            Err(StoreError::ResourceExhausted)
        ));
    }
    let fifth = CommandContext::for_request(
        "owner-fifth",
        "global-over-quota-key",
        &json!({"create":"global-over"}),
    )
    .unwrap();
    assert!(matches!(
        s.create_agreement(&fifth, "global-over", json!({})),
        Err(StoreError::ResourceExhausted)
    ));
    let replay = CommandContext::for_request(
        "owner-0",
        "create-agreement-0-0000",
        &json!({"create":"agreement-0-0"}),
    )
    .unwrap();
    assert!(
        s.create_agreement(&replay, "agreement-0-0", json!({}))
            .unwrap()
            .replayed
    );
    assert_eq!(s.list_agreements().unwrap().len(), 256);
}

#[cfg(target_os = "linux")]
fn encrypted_fixture_path() -> std::path::PathBuf {
    use std::os::unix::fs::DirBuilderExt;
    let dir = temporary_path().with_extension("encrypted-private");
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    dir.join("authority.sqlite")
}

#[cfg(target_os = "linux")]
#[test]
fn encrypted_authority_budget_remains_atomic_across_connections_and_restart() {
    use wholepact_storage_security::DatabaseKey;
    let path = encrypted_fixture_path();
    let key = Arc::new(DatabaseKey::from_bytes([71; 32]));
    let initial = Store::create_encrypted(&path, &key).unwrap();
    assert_eq!(initial.protection(), StorageProtection::Encrypted);
    initial
        .initialize_authority_account("account-a", 1)
        .unwrap();
    drop(initial);
    let barrier = Arc::new(Barrier::new(4));
    let workers = (0..4)
        .map(|i| {
            let path = path.clone();
            let key = key.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let store = Store::open_encrypted(path, &key).unwrap();
                barrier.wait();
                store.record_authorization_release_intent(&intent(
                    &format!("private-auth-{i}"),
                    &format!("private-obligation-{i}"),
                    &format!("private-note-{i}"),
                    "35",
                    "100",
                ))
            })
        })
        .collect::<Vec<_>>();
    let outcomes = workers
        .into_iter()
        .map(|w| w.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(outcomes.iter().filter(|r| r.is_ok()).count(), 2);
    assert_eq!(
        outcomes
            .iter()
            .filter(|r| matches!(r, Err(StoreError::BudgetExceeded)))
            .count(),
        2
    );
    let reopened = Store::open_encrypted(&path, &key).unwrap();
    assert_eq!(reopened.outstanding_debit("account-a").unwrap(), "70");
    drop(reopened);
    for entry in std::fs::read_dir(path.parent().unwrap()).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        assert!(
            !bytes
                .windows(b"private-note-".len())
                .any(|s| s == b"private-note-")
        );
    }
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn encrypted_event_failure_rolls_back_state_and_idempotency_on_restart() {
    use wholepact_storage_security::DatabaseKey;
    let path = encrypted_fixture_path();
    let key = DatabaseKey::from_bytes([73; 32]);
    let store = Store::create_encrypted(&path, &key).unwrap();
    store.connection.lock().unwrap().execute_batch("CREATE TRIGGER injected_failure BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'synthetic fault'); END;").unwrap();
    let ctx = context("encrypted-failure-0001", json!({"create":"a"}));
    assert!(
        store
            .create_agreement(&ctx, "a", json!({"synthetic":"private"}))
            .is_err()
    );
    // The fault trigger is deliberately outside the supported schema. Strict
    // ordinary reopen must refuse it; only this fixture owner removes its own
    // instrumentation before testing the clean restart's rollback evidence.
    assert!(Store::open_encrypted(&path, &key).is_err());
    store
        .connection
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER injected_failure;")
        .unwrap();
    drop(store);
    let reopened = Store::open_encrypted(&path, &key).unwrap();
    assert!(reopened.get_agreement("a").unwrap().is_none());
    assert!(reopened.find_replay(&ctx).unwrap().is_none());
    assert!(reopened.events_after(0, 10).unwrap().is_empty());
    drop(reopened);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn settlement_replay_atomically_reopens_every_alternative_and_fences_accounts() {
    let store = Store::in_memory().unwrap();
    store.initialize_authority_account("account-a", 1).unwrap();
    let old = intent("old", "obligation", "same-input", "10", "100");
    store.record_authorization_release_intent(&old).unwrap();
    store
        .record_observed_resolution("old", ExposureState::ExpiredObserved, "prior-evidence")
        .unwrap();
    let replacement = intent("replacement", "obligation", "same-input", "20", "100");
    assert!(matches!(
        store.record_authorization_release_intent(&replacement),
        Err(StoreError::LiveAuthorizationExists)
    ));
    insert_legacy_alternative(&store, &replacement);
    let initial = store
        .create_agreement(
            &context("create-reorg-agreement", json!({"create":"agreement"})),
            "agreement",
            json!({"record_revision":1}),
        )
        .unwrap();
    let snapshot = store.list_agreements().unwrap();
    let updates = vec![(
        "agreement".into(),
        json!({"record_revision":2,"recovery_required":true}),
    )];
    store
        .reopen_settlement_obligation(
            "source-evidence",
            "obligation",
            &snapshot,
            &["account-a".into()],
            &updates,
        )
        .unwrap();
    assert_eq!(store.outstanding_debit("account-a").unwrap(), "30");
    assert!(
        store
            .authority_account("account-a")
            .unwrap()
            .unwrap()
            .recovery_required
    );
    assert_eq!(
        store.exposure("old").unwrap().unwrap().state,
        ExposureState::OutstandingUncertain
    );
    assert_eq!(
        store.exposure("replacement").unwrap().unwrap().state,
        ExposureState::OutstandingUncertain
    );
    assert!(
        store
            .settlement_obligation_requires_recovery("obligation")
            .unwrap()
    );
    store
        .initialize_authority_account("later-account", 1)
        .unwrap();
    let mut later = intent("later-alternative", "obligation", "later-input", "1", "100");
    later.account_id = "later-account".into();
    assert!(matches!(
        store.record_authorization_release_intent(&later),
        Err(StoreError::RecoveryRequired)
    ));
    let after = store.get_agreement("agreement").unwrap().unwrap();
    assert_eq!(after.revision, initial.record.revision + 1);
    // Simulate application committed but source acknowledgment lost.
    store
        .reopen_settlement_obligation(
            "source-evidence",
            "obligation",
            &snapshot,
            &["account-a".into()],
            &updates,
        )
        .unwrap();
    assert_eq!(store.get_agreement("agreement").unwrap().unwrap(), after);
    assert!(matches!(
        store.reopen_settlement_obligation(
            "source-evidence",
            "wrong-obligation",
            &snapshot,
            &["account-a".into()],
            &updates
        ),
        Err(StoreError::IdempotencyConflict)
    ));
    assert!(matches!(
        store.record_authorization_release_intent(&intent(
            "new",
            "new-obligation",
            "fresh-input",
            "1",
            "100"
        )),
        Err(StoreError::RecoveryRequired)
    ));
}

#[test]
fn settlement_snapshot_race_rolls_back_and_destination_cannot_be_overwritten() {
    let store = Store::in_memory().unwrap();
    let destination = store.settlement_destination().unwrap();
    assert_eq!(destination, store.settlement_destination().unwrap());
    assert_ne!(
        destination,
        Store::in_memory()
            .unwrap()
            .settlement_destination()
            .unwrap()
    );
    assert!(
        store
            .commit_record(
                &context("replace-sink-identity", json!({})),
                "settlement_identity",
                "local",
                Some(0),
                json!("forged"),
                "replace"
            )
            .is_err()
    );
    store.initialize_authority_account("account-a", 1).unwrap();
    store
        .record_authorization_release_intent(&intent("old", "obligation", "input", "10", "100"))
        .unwrap();
    let snapshot = store.list_agreements().unwrap();
    store
        .create_agreement(&context("new-agreement-race", json!({})), "new", json!({}))
        .unwrap();
    assert!(matches!(
        store.reopen_settlement_obligation(
            "evidence",
            "obligation",
            &snapshot,
            &["account-a".into()],
            &[]
        ),
        Err(StoreError::RevisionConflict)
    ));
    assert!(
        !store
            .authority_account("account-a")
            .unwrap()
            .unwrap()
            .recovery_required
    );
    store
        .reopen_settlement_obligation(
            "evidence",
            "obligation",
            &store.list_agreements().unwrap(),
            &["account-a".into()],
            &[],
        )
        .unwrap();
    assert!(
        store
            .authority_account("account-a")
            .unwrap()
            .unwrap()
            .recovery_required
    );
}

#[cfg(target_os = "linux")]
#[test]
fn exact_settlement_mirror_is_atomic_quarantined_replayable_and_reopened() {
    let path = encrypted_fixture_path();
    let key = wholepact_storage_security::DatabaseKey::from_bytes([93; 32]);
    let store = Store::create_encrypted(&path, &key).unwrap();
    let release = intent(
        "settlement-original",
        "settlement-obligation",
        "exact-nullifier",
        "40",
        "100",
    );
    let provenance = json!({"synthetic_storage_contract":"not_chain_authority"});
    assert!(matches!(
        store.consume_exact_settlement_release(
            &release,
            "evidence",
            &provenance,
            &[],
            &[],
            &|| Err(StoreError::RecoveryRequired)
        ),
        Err(StoreError::RecoveryRequired)
    ));
    assert!(store.exposure(&release.authorization_id).unwrap().is_none());
    assert!(store.authority_account("account-a").unwrap().is_none());
    store
        .consume_exact_settlement_release(&release, "evidence", &provenance, &[], &[], &|| Ok(()))
        .unwrap();
    assert!(
        store
            .authority_account("account-a")
            .unwrap()
            .unwrap()
            .recovery_required
    );
    assert_eq!(store.outstanding_debit("account-a").unwrap(), "0");
    assert_eq!(store.settled_debit("account-a").unwrap(), "40");
    store
        .consume_exact_settlement_release(&release, "evidence", &provenance, &[], &[], &|| Ok(()))
        .unwrap();
    let mut changed = release.clone();
    changed.maximum_debit = "41".into();
    assert!(matches!(
        store.consume_exact_settlement_release(
            &changed,
            "evidence",
            &provenance,
            &[],
            &[],
            &|| Ok(())
        ),
        Err(StoreError::IdempotencyConflict)
    ));
    assert!(matches!(
        store.consume_exact_settlement_release(
            &release,
            "evidence",
            &json!({"changed":true}),
            &[],
            &[],
            &|| Ok(())
        ),
        Err(StoreError::IdempotencyConflict)
    ));
    drop(store);
    let store = Store::open_encrypted(&path, &key).unwrap();
    store
        .consume_exact_settlement_release(&release, "evidence", &provenance, &[], &[], &|| Ok(()))
        .unwrap();
    store
        .reopen_settlement_obligation(
            "reorg",
            "settlement-obligation",
            &[],
            &["account-a".into()],
            &[],
        )
        .unwrap();
    assert_eq!(store.outstanding_debit("account-a").unwrap(), "40");
    assert_eq!(store.settled_debit("account-a").unwrap(), "0");
    assert!(matches!(
        store.consume_exact_settlement_release(
            &release,
            "evidence",
            &provenance,
            &[],
            &[],
            &|| Ok(())
        ),
        Err(StoreError::RecoveryRequired)
    ));
    drop(store);
    cleanup(&path);
    std::fs::remove_dir(path.parent().unwrap()).unwrap();
}

#[test]
fn consumed_debit_remains_charged_against_reusable_aggregate_budget() {
    let store = Store::in_memory().unwrap();
    store.initialize_authority_account("account-a", 1).unwrap();
    let first = intent(
        "first-consumed",
        "first-obligation",
        "first-input",
        "70",
        "100",
    );
    store.record_authorization_release_intent(&first).unwrap();
    store
        .record_observed_resolution(
            "first-consumed",
            ExposureState::Consumed,
            "synthetic-storage-test",
        )
        .unwrap();
    assert_eq!(store.settled_debit("account-a").unwrap(), "70");
    assert!(matches!(
        store.record_authorization_release_intent(&intent(
            "reused-consumed-input",
            "new-obligation",
            "first-input",
            "1",
            "100"
        )),
        Err(StoreError::InputReserved)
    ));
    assert!(matches!(
        store.record_authorization_release_intent(&intent(
            "too-much",
            "new-obligation",
            "new-input",
            "31",
            "100"
        )),
        Err(StoreError::BudgetExceeded)
    ));
    store
        .record_authorization_release_intent(&intent(
            "remaining",
            "new-obligation",
            "new-input",
            "30",
            "100",
        ))
        .unwrap();
    assert_eq!(store.outstanding_debit("account-a").unwrap(), "30");
    store
        .reopen_exposure_after_reorg("first-consumed", "synthetic-reorg")
        .unwrap();
    assert_eq!(store.outstanding_debit("account-a").unwrap(), "100");
    assert_eq!(store.settled_debit("account-a").unwrap(), "0");
}

#[cfg(target_os = "linux")]
#[test]
fn exact_settlement_records_and_ledger_share_one_cas_transaction() {
    let path = encrypted_fixture_path();
    let key = wholepact_storage_security::DatabaseKey::from_bytes([94; 32]);
    let store = Store::create_encrypted(&path, &key).unwrap();
    store
        .create_agreement(
            &context("settlement-cas-original", json!({})),
            "agreement",
            json!({"state":"pending"}),
        )
        .unwrap();
    let snapshot = store.list_agreements().unwrap();
    let updates = vec![(
        "agreement".into(),
        json!({"state":"synthetic-consumed-record"}),
    )];
    let release = intent(
        "atomic-original",
        "atomic-obligation",
        "atomic-input",
        "40",
        "100",
    );
    let provenance = json!({"synthetic_storage_only":true});
    assert!(matches!(
        store.consume_exact_settlement_release(
            &release,
            "atomic-evidence",
            &provenance,
            &snapshot,
            &updates,
            &|| Err(StoreError::RecoveryRequired)
        ),
        Err(StoreError::RecoveryRequired)
    ));
    assert!(store.exposure("atomic-original").unwrap().is_none());
    assert_eq!(store.list_agreements().unwrap(), snapshot);
    store
        .create_agreement(
            &context("settlement-cas-racer", json!({})),
            "racer",
            json!({}),
        )
        .unwrap();
    assert!(matches!(
        store.consume_exact_settlement_release(
            &release,
            "atomic-evidence",
            &provenance,
            &snapshot,
            &updates,
            &|| Ok(())
        ),
        Err(StoreError::RevisionConflict)
    ));
    assert!(store.exposure("atomic-original").unwrap().is_none());
    let current = store.list_agreements().unwrap();
    store
        .consume_exact_settlement_release(
            &release,
            "atomic-evidence",
            &provenance,
            &current,
            &updates,
            &|| Ok(()),
        )
        .unwrap();
    assert_eq!(
        store
            .get_record("agreement", "agreement")
            .unwrap()
            .unwrap()
            .revision,
        snapshot[0].revision + 1
    );
    assert_eq!(
        store.exposure("atomic-original").unwrap().unwrap().state,
        ExposureState::Consumed
    );
    let current = store.list_agreements().unwrap();
    store
        .consume_exact_settlement_release(
            &release,
            "atomic-evidence",
            &provenance,
            &current,
            &[],
            &|| Ok(()),
        )
        .unwrap();
    assert_eq!(store.list_agreements().unwrap(), current);
    drop(store);
    cleanup(&path);
    std::fs::remove_dir(path.parent().unwrap()).unwrap();
}

/// Synthetic storage contract only; no node permit or payment is fabricated.
#[cfg(target_os = "linux")]
#[test]
fn canonical_conflict_retains_original_exposure_and_link_through_restart_and_reorg() {
    let path = encrypted_fixture_path();
    let key = wholepact_storage_security::DatabaseKey::from_bytes([94; 32]);
    let store = Store::create_encrypted(&path, &key).unwrap();
    let release = intent(
        "conflict-original",
        "conflict-obligation",
        "original-nullifier",
        "40",
        "100",
    );
    let link =
        json!({"synthetic_alternative":"not_chain_authority","original":"conflict-original"});
    assert!(
        store
            .retain_exact_conflict_release(&release, "conflict-evidence", &link, &[], &[], &|| Err(
                StoreError::RecoveryRequired
            ))
            .is_err()
    );
    assert!(store.exposure(&release.authorization_id).unwrap().is_none());
    store
        .retain_exact_conflict_release(&release, "conflict-evidence", &link, &[], &[], &|| Ok(()))
        .unwrap();
    store
        .retain_exact_conflict_release(&release, "conflict-evidence", &link, &[], &[], &|| Ok(()))
        .unwrap();
    assert_eq!(store.outstanding_debit("account-a").unwrap(), "40");
    assert_eq!(store.settled_debit("account-a").unwrap(), "0");
    assert_eq!(
        store
            .exposure(&release.authorization_id)
            .unwrap()
            .unwrap()
            .intent,
        release
    );
    let mut changed = release.clone();
    changed.maximum_debit = "41".into();
    assert!(
        store
            .retain_exact_conflict_release(&changed, "conflict-evidence", &link, &[], &[], &|| Ok(
                ()
            ))
            .is_err()
    );
    {
        let c = store.connection.lock().unwrap();
        assert_eq!(c.query_row("SELECT count(*) FROM authority_reservations WHERE authorization_id='conflict-original'",[],|r|r.get::<_,u64>(0)).unwrap(),1);
        assert_eq!(
            c.query_row(
                "SELECT count(*) FROM records WHERE aggregate_type='settlement_conflict'",
                [],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
            1
        );
    }
    drop(store);
    let store = Store::open_encrypted(&path, &key).unwrap();
    store
        .retain_exact_conflict_release(&release, "conflict-evidence", &link, &[], &[], &|| Ok(()))
        .unwrap();
    store
        .reopen_settlement_obligation(
            "conflict-reorg",
            "conflict-obligation",
            &[],
            &["account-a".into()],
            &[],
        )
        .unwrap();
    assert_eq!(store.outstanding_debit("account-a").unwrap(), "40");
    assert!(
        store
            .authority_account("account-a")
            .unwrap()
            .unwrap()
            .recovery_required
    );
    assert!(
        store
            .retain_exact_conflict_release(&release, "conflict-evidence", &link, &[], &[], &|| Ok(
                ()
            ))
            .is_err()
    );
    assert_eq!(
        store
            .exposure(&release.authorization_id)
            .unwrap()
            .unwrap()
            .intent,
        release
    );
    drop(store);
    cleanup(&path);
    std::fs::remove_dir(path.parent().unwrap()).unwrap();
}

#[test]
fn observed_conflict_and_expiry_preserve_budget_obligation_and_exact_input_claims() {
    for observed in [
        ExposureState::ConflictedObserved,
        ExposureState::ExpiredObserved,
    ] {
        let store = Store::in_memory().unwrap();
        store.initialize_authority_account("account-a", 1).unwrap();
        let original = intent("original", "obligation", "original-input", "70", "100");
        store
            .record_authorization_release_intent(&original)
            .unwrap();
        store
            .record_observed_resolution("original", observed, "synthetic-observation")
            .unwrap();
        let retained = store.exposure("original").unwrap().unwrap();
        assert_eq!(retained.state, observed);
        assert_eq!(store.outstanding_debit("account-a").unwrap(), "70");
        assert_eq!(store.settled_debit("account-a").unwrap(), "0");
        let count: u64 = store
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM authority_reservations WHERE authorization_id='original'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(
            store
                .record_authorization_release_intent(&original)
                .unwrap(),
            retained
        );
        assert!(matches!(
            store.mark_authorization_released("original"),
            Err(StoreError::InvalidTransition)
        ));
        assert!(matches!(
            store.record_authorization_release_intent(&intent(
                "replacement",
                "obligation",
                "fresh-input",
                "1",
                "100"
            )),
            Err(StoreError::LiveAuthorizationExists)
        ));
        assert!(matches!(
            store.record_authorization_release_intent(&intent(
                "over-budget",
                "fresh-obligation",
                "fresh-input",
                "31",
                "100"
            )),
            Err(StoreError::BudgetExceeded)
        ));
        assert!(matches!(
            store.record_authorization_release_intent(&intent(
                "shared-input",
                "fresh-obligation",
                "original-input",
                "1",
                "100"
            )),
            Err(StoreError::InputReserved)
        ));
        // Reproduce the old writer's missing reservation, without touching its
        // retained original. No migration may interpret that absence as free.
        store
            .connection
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM authority_reservations WHERE authorization_id='original'",
                [],
            )
            .unwrap();
        assert!(matches!(
            store.record_authorization_release_intent(&intent(
                "legacy-shared",
                "fresh-obligation",
                "original-input",
                "1",
                "100"
            )),
            Err(StoreError::InputReserved)
        ));
        store
            .record_authorization_release_intent(&intent(
                "remaining",
                "fresh-obligation",
                "fresh-input",
                "30",
                "100",
            ))
            .unwrap();
        assert_eq!(store.outstanding_debit("account-a").unwrap(), "100");
        assert_eq!(store.account_exposures("account-a").unwrap().len(), 2);
        store
            .reopen_exposure_after_reorg("original", "synthetic-reorg")
            .unwrap();
        assert_eq!(store.outstanding_debit("account-a").unwrap(), "100");
        assert!(
            store
                .authority_account("account-a")
                .unwrap()
                .unwrap()
                .recovery_required
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn legacy_resolved_input_claims_survive_actual_encrypted_reopen() {
    let path = encrypted_fixture_path();
    let mut bytes = [0u8; 32];
    std::io::Read::read_exact(
        &mut std::fs::File::open("/dev/urandom").unwrap(),
        &mut bytes,
    )
    .unwrap();
    let key = wholepact_storage_security::DatabaseKey::from_bytes(bytes);
    let store = Store::create_encrypted(&path, &key).unwrap();
    store.initialize_authority_account("account-a", 1).unwrap();
    let original = intent(
        "original",
        "original-obligation",
        "original-input",
        "70",
        "100",
    );
    store
        .record_authorization_release_intent(&original)
        .unwrap();
    store
        .record_observed_resolution(
            "original",
            ExposureState::ConflictedObserved,
            "synthetic-history",
        )
        .unwrap();
    store
        .connection
        .lock()
        .unwrap()
        .execute(
            "DELETE FROM authority_reservations WHERE authorization_id='original'",
            [],
        )
        .unwrap();
    drop(store);
    let reopened = Store::open_encrypted(&path, &key).unwrap();
    assert_eq!(reopened.outstanding_debit("account-a").unwrap(), "70");
    assert!(matches!(
        reopened.record_authorization_release_intent(&intent(
            "fresh",
            "fresh-obligation",
            "original-input",
            "1",
            "100"
        )),
        Err(StoreError::InputReserved)
    ));
    assert!(matches!(
        reopened.record_authorization_release_intent(&intent(
            "new",
            "original-obligation",
            "new-input",
            "1",
            "100"
        )),
        Err(StoreError::LiveAuthorizationExists)
    ));
    assert_eq!(reopened.account_exposures("account-a").unwrap().len(), 1);
    let archive = path.parent().unwrap().join("history-backup.sqlite");
    reopened.backup_agreement_journal(&archive, &key).unwrap();
    let restored_path = path.parent().unwrap().join("restored.sqlite");
    let (restored, report) =
        crate::backup::restore_agreement_journal(&archive, &key, &restored_path, &key).unwrap();
    assert!(report.recovery_required);
    assert_eq!(restored.outstanding_debit("account-a").unwrap(), "70");
    assert_eq!(
        restored.exposure("original").unwrap().unwrap().intent,
        original
    );
    assert!(matches!(
        restored.record_authorization_release_intent(&intent(
            "restored-fresh",
            "fresh-obligation",
            "fresh-input",
            "1",
            "100"
        )),
        Err(StoreError::RecoveryRequired)
    ));
    drop(restored);
    drop(reopened);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}
