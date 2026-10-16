//! Unrun synthetic SQLite source tests of the connected storage kernel. Direct
//! fixture assembly is cfg(test) only; it does not mint a native approval,
//! authenticated replay, installed writer or production offline capability.
use super::*;
use crate::consent_journal::offline_history::tests::{
    connection, full_admission, h, insert_keyuse, insert_local, insert_original, minimal, original,
    reconciliation_tests::online,
};
fn entry() -> PreparedOfflineExposure {
    let (admission, policy, provenance) = full_admission();
    PreparedOfflineExposure {
        admission,
        policy,
        provenance,
    }
}
fn state(c: &Connection) -> SignerAccountState {
    storage::read_account(c).unwrap()
}
fn snapshot(c: &Connection) -> WriterLocalInventory {
    WriterLocalInventory::read(c, &state(c), (MAX_BACKUP_ROWS, MAX_BACKUP_ENCODED_BYTES)).unwrap()
}
fn plan(local: &WriterLocalInventory) -> PreparedWriterHistory {
    PreparedWriterHistory {
        online: vec![],
        offline: vec![],
        local_commitment: local.commitment.clone(),
        retained_offline_review: vec![],
        retained_offline_enrollments: vec![],
        retained_offline_intents: vec![],
        construction: vec![],
        common_context_history: None,
        common_context_audit: None,
    }
}
fn count(c: &Connection, table: &str) -> u64 {
    c.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}
fn insert_prereview(c: &Connection, entry: &PreparedOfflineExposure) {
    let t = &entry.admission.request.intent.terms;
    c.execute(
        "INSERT INTO signer_offline_enrollments VALUES(?1,?2,?3,?4)",
        params![
            t.offline_policy_digest,
            t.enrollment_ref,
            t.account_id,
            encode(&entry.policy).unwrap().as_str()
        ],
    )
    .unwrap();
    c.execute(
        "INSERT INTO signer_offline_intents VALUES(?1,?2,?3,?4)",
        params![
            entry.admission.request.intent.intent_digest().unwrap(),
            t.authorization_id,
            t.offline_policy_digest,
            encode(&entry.admission.request.intent).unwrap().as_str()
        ],
    )
    .unwrap();
}
#[test]
fn connected_reader_requires_one_transaction_and_retains_nonbinding_rows() {
    let mut c = connection();
    assert!(matches!(
        WriterLocalInventory::read(&c, &state(&c), (MAX_BACKUP_ROWS, MAX_BACKUP_ENCODED_BYTES)),
        Err(JournalError::InvalidBinding)
    ));
    let e = entry();
    insert_prereview(&c, &e);
    let tx = c.transaction().unwrap();
    let read = snapshot(&tx);
    assert!(read.originals.is_empty());
    assert!(read.remote_online.is_empty());
    assert_eq!(read.offline.enrollments().len(), 1);
    assert_eq!(read.offline.reservation_intents().len(), 1);
    assert!(read.offline.admitted_origins().is_empty());
}
#[test]
fn changed_prereview_between_prepare_and_commit_invalidates_exact_snapshot() {
    let mut c = connection();
    let tx = c.transaction().unwrap();
    let first = snapshot(&tx);
    let prepared = plan(&first);
    tx.rollback().unwrap();
    insert_prereview(&c, &entry());
    let tx = c.transaction().unwrap();
    let changed = snapshot(&tx);
    assert_ne!(first.commitment, changed.commitment);
    assert!(matches!(
        prepared.require_unchanged_local(&changed),
        Err(JournalError::Conflict)
    ));
}
#[test]
fn offline_bearing_import_guard_runs_before_even_online_exposure_writes() {
    let mut c = connection();
    let tx = c.transaction().unwrap();
    let local = snapshot(&tx);
    let e = entry();
    let mut prepared = plan(&local);
    prepared.online.push(online(&e.admission));
    prepared.offline.push(e);
    assert!(matches!(
        prepared.import_enabled(&tx, "synthetic-account"),
        Err(JournalError::OfflineHistoryUnsupported)
    ));
    assert_eq!(count(&tx, "signer_remote_exposures"), 0);
    assert_eq!(count(&tx, "signer_offline_enrollments"), 0);
    assert_eq!(count(&tx, "signer_offline_admissions"), 0);
    assert_eq!(state(&tx).writer_epoch, 1);
    assert!(state(&tx).recovery_required);
}
#[test]
fn synthetic_offline_import_retains_all_exact_rows_once_and_never_creates_original() {
    let mut c = connection();
    let tx = c.transaction().unwrap();
    let e = entry();
    retain_offline_exposure(&tx, &e, "synthetic-account").unwrap();
    retain_offline_exposure(&tx, &e, "synthetic-account").unwrap();
    for name in [
        "signer_offline_enrollments",
        "signer_offline_intents",
        "signer_offline_admissions",
        "signer_offline_remote_exposures",
        "signer_offline_remote_inputs",
    ] {
        assert_eq!(count(&tx, name), 1);
    }
    for name in [
        "signer_offline_local_admissions",
        "signer_offline_original_consents",
        "signer_offline_keyuse",
        "signer_offline_results",
        "signer_original_consents",
    ] {
        assert_eq!(count(&tx, name), 0);
    }
    assert_eq!(state(&tx).writer_epoch, 1);
    assert!(state(&tx).recovery_required);
    let all = offline_history::read_all(&tx, "synthetic-account").unwrap();
    assert!(all[0].admission() == Some(&e.admission));
    assert!(all[0].provenance() == Some(&e.provenance));
    assert_eq!(
        all[0].signature_knowledge(),
        OfflineSignatureKnowledge::HistoricalAdmissionSignatureUnknown
    );
}
#[test]
fn conflicting_intent_rolls_back_an_earlier_policy_insert() {
    let mut c = connection();
    let old = entry();
    insert_prereview(&c, &old);
    let mut changed = entry();
    changed.policy.return_recipient_key_digest = h(91);
    changed
        .admission
        .request
        .intent
        .terms
        .return_recipient_key_digest = h(91);
    changed.admission.request.intent.terms.offline_policy_digest =
        changed.policy.policy_digest().unwrap();
    changed.admission.request_digest = changed.admission.request.request_digest().unwrap();
    changed.provenance.enrollment_operation.control = OwnerControl::EnrollOfflinePolicy {
        policy: changed.policy.clone(),
        expected_previous_digest: Some(old.policy.policy_digest().unwrap()),
    };
    let tx = c.transaction().unwrap();
    assert!(matches!(
        retain_offline_exposure(&tx, &changed, "synthetic-account"),
        Err(JournalError::Conflict)
    ));
    assert_eq!(count(&tx, "signer_offline_enrollments"), 2); // Proves failure was after a write.
    tx.rollback().unwrap();
    assert_eq!(count(&c, "signer_offline_enrollments"), 1);
    assert_eq!(count(&c, "signer_offline_intents"), 1);
    assert_eq!(count(&c, "signer_offline_admissions"), 0);
}
#[test]
fn mismatched_local_assertion_rejects_without_any_remote_rows() {
    let mut c = connection();
    let e = entry();
    let mut local = minimal(&e.admission);
    local.statement.original_admission_digest = h(92);
    local.statement_digest = local.statement.statement_digest().unwrap();
    insert_local(&c, &local);
    let tx = c.transaction().unwrap();
    assert!(retain_offline_exposure(&tx, &e, "synthetic-account").is_err());
    tx.rollback().unwrap();
    for name in [
        "signer_offline_enrollments",
        "signer_offline_intents",
        "signer_offline_admissions",
        "signer_offline_remote_exposures",
        "signer_offline_remote_inputs",
    ] {
        assert_eq!(count(&c, name), 0);
    }
    assert_eq!(count(&c, "signer_offline_local_admissions"), 1);
}
#[test]
fn later_import_cannot_rewrite_original_provenance_head_or_digest() {
    let mut c = connection();
    let tx = c.transaction().unwrap();
    let e = entry();
    retain_offline_exposure(&tx, &e, "synthetic-account").unwrap();
    let mut changed = entry();
    changed.provenance.history_head.sequence += 1;
    changed.provenance.history_head.digest = h(93);
    changed.provenance.history_digest = h(94);
    assert!(matches!(
        retain_offline_exposure(&tx, &changed, "synthetic-account"),
        Err(JournalError::Conflict)
    ));
    let all = offline_history::read_all(&tx, "synthetic-account").unwrap();
    assert!(all[0].provenance() == Some(&e.provenance));
}
#[test]
fn remote_import_preserves_existing_original_and_keyuse_bytes() {
    let mut c = connection();
    let e = entry();
    let local = minimal(&e.admission);
    insert_local(&c, &local);
    let original = original(&local);
    insert_original(&c, &original);
    insert_keyuse(&c, &original);
    let original_before: String = c
        .query_row(
            "SELECT payload FROM signer_offline_original_consents",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let keyuse_before: String = c
        .query_row("SELECT payload FROM signer_offline_keyuse", [], |r| {
            r.get(0)
        })
        .unwrap();
    let tx = c.transaction().unwrap();
    retain_offline_exposure(&tx, &e, "synthetic-account").unwrap();
    assert_eq!(
        original_before,
        tx.query_row(
            "SELECT payload FROM signer_offline_original_consents",
            [],
            |r| r.get::<_, String>(0)
        )
        .unwrap()
    );
    assert_eq!(
        keyuse_before,
        tx.query_row("SELECT payload FROM signer_offline_keyuse", [], |r| r
            .get::<_, String>(0))
            .unwrap()
    );
    assert_eq!(
        offline_history::read_all(&tx, "synthetic-account").unwrap()[0].signature_knowledge(),
        OfflineSignatureKnowledge::LocalKeyUseStartedSignatureUnknown
    );
}
#[test]
fn complete_reader_rejects_online_remote_input_omission() {
    let mut c = connection();
    let e = entry();
    let online = online(&e.admission);
    let r = &online.request;
    c.execute(
        "INSERT INTO signer_remote_exposures VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            r.authorization_id,
            r.original_consent_ref,
            r.account_id,
            r.obligation_id,
            r.maximum_debit_zatoshis.to_string(),
            encode(&online).unwrap().as_str()
        ],
    )
    .unwrap();
    let tx = c.transaction().unwrap();
    assert!(
        WriterLocalInventory::read(
            &tx,
            &state(&tx),
            (MAX_BACKUP_ROWS, MAX_BACKUP_ENCODED_BYTES)
        )
        .is_err()
    );
}
#[test]
fn enabled_online_kernel_keeps_legacy_payload_bytes_and_exact_identity_set() {
    let mut c = connection();
    let tx = c.transaction().unwrap();
    let e = entry();
    let online = online(&e.admission);
    let before = encode(&online).unwrap();
    let local = snapshot(&tx);
    let mut prepared = plan(&local);
    prepared.online.push(online);
    assert_eq!(
        encode(&prepared.legacy_online_permits().unwrap())
            .unwrap()
            .as_str(),
        format!("[{}]", before.as_str())
    );
    prepared.import_enabled(&tx, "synthetic-account").unwrap();
    let saved: String = tx
        .query_row("SELECT payload FROM signer_remote_exposures", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(saved, before.as_str());
    prepared.import_enabled(&tx, "synthetic-account").unwrap();
    assert_eq!(count(&tx, "signer_remote_exposures"), 1);
    assert_eq!(state(&tx).writer_epoch, 1); // Kernel does not own epoch transition.
}
#[test]
fn retained_remote_missing_from_prepared_identity_set_cannot_be_dropped() {
    let mut c = connection();
    let tx = c.transaction().unwrap();
    let e = entry();
    let online = online(&e.admission);
    authority::retain_remote_exposure(&tx, &online, "synthetic-account").unwrap();
    let local = snapshot(&tx);
    let prepared = plan(&local);
    assert!(matches!(
        prepared.require_unchanged_local(&local),
        Err(JournalError::Conflict)
    ));
}

#[test]
fn construction_history_is_preserved_but_financial_imports_refuse_before_writes() {
    let mut c = connection();
    let tx = c.transaction().unwrap();
    let local = snapshot(&tx);
    let mut prepared = plan(&local);
    prepared.construction =
        crate::consent_journal::offline_history::tests::reconciliation_tests::construction_records(
        )
        .into_iter()
        .collect();
    // This is historical validation only; exact input and obligation records
    // remain present even though both financial import paths are unavailable.
    prepared.validate_origins(&local).unwrap();
    assert_eq!(prepared.len(), 1);
    assert_eq!(prepared.construction.len(), 2);
    let displayed = serde_json::to_value(&prepared).unwrap();
    assert_eq!(displayed["construction"].as_array().unwrap().len(), 2);
    let e = entry();
    prepared.online.push(online(&e.admission));
    prepared.offline.push(e);
    assert_eq!(prepared.len(), 3);
    assert!(matches!(
        prepared.require_enabled(),
        Err(JournalError::ConstructionHistoryUnsupported)
    ));
    assert!(matches!(
        prepared.import_enabled(&tx, "synthetic-account"),
        Err(JournalError::ConstructionHistoryUnsupported)
    ));
    assert!(matches!(
        prepared.import_complete(&tx, "synthetic-account"),
        Err(JournalError::ConstructionHistoryUnsupported)
    ));
    for table in [
        "signer_remote_exposures",
        "signer_remote_inputs",
        "signer_offline_enrollments",
        "signer_offline_admissions",
        "signer_offline_remote_inputs",
    ] {
        assert_eq!(count(&tx, table), 0);
    }
    assert_eq!(state(&tx).writer_epoch, 1);
    assert!(state(&tx).recovery_required);
}

#[test]
fn empty_construction_history_preserves_legacy_review_representation() {
    let mut c = connection();
    let tx = c.transaction().unwrap();
    let local = snapshot(&tx);
    let prepared = plan(&local);
    let displayed = serde_json::to_value(&prepared).unwrap();
    assert!(displayed.get("construction").is_none());
    assert!(prepared.require_enabled().is_ok());
}
