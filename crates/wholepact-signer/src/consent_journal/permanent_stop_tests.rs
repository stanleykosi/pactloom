//! Existing recorded nonempty encrypted history, never a live native decision.
//! No sockets, credentials, proof creation or financial execution are invoked.
use super::*;
use wholepact_authority::account_use::{ExclusionReason, PermanentAccountExclusion};
fn restriction(history: &ReconciledAuthorityHistory) -> PermanentAccountExclusion {
    let genesis = history.account_use_history().genesis().unwrap();
    PermanentAccountExclusion {
        version: 1,
        identity: genesis.identity.clone(),
        genesis_digest: genesis.digest().unwrap(),
        operation_id: "synthetic-local-first-stop".into(),
        native_review_digest: "ab".repeat(32),
        reason: ExclusionReason::RetirementRequested,
    }
}
fn retain_fixture(journal: &SignerConsentJournal, exclusion: &PermanentAccountExclusion) {
    let mut c = journal.connection.lock().unwrap();
    let tx = c.transaction().unwrap();
    account_use_storage::append_exclusion(&tx, &exclusion.identity.account_id, exclusion).unwrap();
    tx.commit().unwrap();
}
#[test]
fn local_first_preserves_nonempty_transport_and_unknown_remote_exposure() {
    let (_dir, journal, history) = source(true);
    let genesis = history.account_use_history().genesis().unwrap();
    let (before, display) = journal.permanent_stop_local_review(genesis).unwrap();
    assert!(before.recovery_required);
    assert!(display["remote_exposure"]
        .as_str()
        .unwrap()
        .contains("UNKNOWN"));
    assert!(before.retained_rows["signer_common_context_reentry_v1"] > 0);
    retain_fixture(&journal, &restriction(&history));
    let (after, observed) = journal
        .permanent_stop_synthetic_history(genesis, &history)
        .unwrap();
    assert!(after.exclusion.is_some());
    assert!(after.witness_ack.is_none());
    assert!(after.recovery_required);
    for (table, count) in before.retained_rows {
        if table != "signer_account_use_exclusion" {
            assert_eq!(after.retained_rows[&table], count, "{table}");
        }
    }
    assert!(
        observed["conservative_historical_union_debit_zatoshis"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(journal.check_initial_born_owner(genesis, 1).is_err());
}
#[test]
fn witnessed_retry_and_archive_preserve_original_ack_and_every_history_cell() {
    let (dir, journal, history) = source(false);
    let genesis = history.account_use_history().genesis().unwrap();
    let exclusion = restriction(&history);
    retain_fixture(&journal, &exclusion);
    let changed = history_after_control(
        &history,
        &exclusion.operation_id,
        wholepact_authority::OwnerControl::PermanentlyExcludeAccount {
            exclusion: exclusion.clone(),
        },
    );
    let ack = wholepact_authority::account_use_link::reconcile_account_exclusion_complete(
        &changed,
        genesis,
        changed.disclosure(),
        &exclusion,
    )
    .unwrap();
    {
        let mut c = journal.connection.lock().unwrap();
        let tx = c.transaction().unwrap();
        // Historical encrypted fixture only; never fabricate the production
        // actual-source witness-ack publication owner.
        account_use_storage::append_witness_ack(&tx, &genesis.identity.account_id, &ack).unwrap();
        tx.commit().unwrap();
    }
    let before = journal.permanent_stop_snapshot(genesis).unwrap();
    {
        let mut c = journal.connection.lock().unwrap();
        let tx = c.transaction().unwrap();
        // Historical encrypted fixture only; never fabricate the production
        // actual-source witness-ack publication owner.
        account_use_storage::append_witness_ack(&tx, &genesis.identity.account_id, &ack).unwrap();
        tx.commit().unwrap();
    }
    let after = journal.permanent_stop_snapshot(genesis).unwrap();
    assert!(before == after);
    journal
        .permanent_stop_synthetic_history(genesis, &changed)
        .unwrap();
    assert!(journal
        .permanent_stop_synthetic_history(genesis, &history)
        .is_err());
    let key = wholepact_storage_security::DatabaseKey::from_bytes([0x74; 32]);
    let archive = SignerConsentJournal::verify_permanent_stop_archive(
        &dir.path().join("never-funded-historical.wp"),
        &key,
        genesis,
    )
    .unwrap();
    assert!(archive == after);
    let mut substituted = genesis.clone();
    substituted.identity.full_viewing_key_digest = "ff".repeat(32);
    assert!(SignerConsentJournal::verify_permanent_stop_archive(
        &dir.path().join("never-funded-historical.wp"),
        &key,
        &substituted
    )
    .is_err());
}
#[test]
fn source_exclusion_mismatch_and_tampered_nonempty_audit_fail_closed() {
    let (_dir, journal, history) = source(false);
    let genesis = history.account_use_history().genesis().unwrap();
    let exclusion = restriction(&history);
    retain_fixture(&journal, &exclusion);
    let mut different = exclusion.clone();
    different.native_review_digest = "cd".repeat(32);
    let changed = history_after_control(
        &history,
        &different.operation_id,
        wholepact_authority::OwnerControl::PermanentlyExcludeAccount {
            exclusion: different.clone(),
        },
    );
    assert!(journal
        .permanent_stop_synthetic_history(genesis, &changed)
        .is_err());
    let c = journal.connection.lock().unwrap();
    c.execute_batch("DROP TRIGGER signer_common_context_reentry_no_update")
        .unwrap();
    c.execute(
        "UPDATE signer_common_context_reentry_v1 SET receipt_digest=?1 WHERE receipt_digest=(SELECT receipt_digest FROM signer_common_context_reentry_v1 ORDER BY receipt_digest LIMIT 1)",
        ["ef".repeat(32)],
    )
    .unwrap();
    drop(c);
    assert!(journal.permanent_stop_local_review(genesis).is_err());
}

#[test]
fn historical_bridge_pin_corruption_is_not_hidden_by_nonempty_construction() {
    let (_dir, journal, history) = source(false);
    let genesis = history.account_use_history().genesis().unwrap();
    journal
        .permanent_stop_synthetic_history(genesis, &history)
        .unwrap();
    {
        let c = journal.connection.lock().unwrap();
        c.execute("INSERT INTO signer_writer_reconciliations SELECT ?1,disclosure,head_sequence,?2,writer_epoch,payload FROM signer_writer_reconciliations LIMIT 1", rusqlite::params!["b1".repeat(32), "b2".repeat(32)]).unwrap();
    }
    assert!(journal
        .permanent_stop_synthetic_history(genesis, &history)
        .is_err());
}

#[test]
fn read_only_cell_kernel_does_not_relax_ordinary_witness_pin_requirement() {
    let (_dir, _journal, history) = source(false);
    let c = rusqlite::Connection::open_in_memory().unwrap();
    c.execute_batch(SCHEMA).unwrap();
    // No source owner is synthesized: this directly inspects a pure empty-cell
    // fixture and proves ordinary continuity still refuses it.
    assert!(!validate_online_continuity_cells(&c, &history, &[]).unwrap());
    assert!(validate_online_continuity(&c, &history, &[]).is_err());
}
