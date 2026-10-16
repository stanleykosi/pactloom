//! Synthetic account/export consent issuers. Actual encrypted persistence and
//! private-file effects, with no production human approval or external delivery.
use super::*;
use wholepact_engine::participant_records::disclosure_exports::*;
use wholepact_storage_security::receipt_file::{PrivateReceiptTarget, ReceiptTargetBinding};

struct ExportAuthority {
    store: RecordStoreBinding,
    target: ReceiptTargetBinding,
    revoked: AtomicBool,
    deny_after_file: AtomicBool,
    path: std::path::PathBuf,
}
impl ExportAuthority {
    fn new(engine: &Engine, target: &PrivateReceiptTarget) -> Self {
        Self {
            store: engine.protected_record_store_binding().unwrap(),
            target: target.binding(),
            revoked: AtomicBool::new(false),
            deny_after_file: AtomicBool::new(false),
            path: target.identity().path().into(),
        }
    }
}
struct ExportLease<'a> {
    scope: DisclosureExportScope,
    issuer: &'a ExportAuthority,
}
impl DisclosureExportLease for ExportLease<'_> {
    fn scope(&self) -> &DisclosureExportScope {
        &self.scope
    }
    fn consent_record_ref(&self) -> &str {
        "SYNTHETIC-SEPARATE-EXPORT-CONSENT-PRIVATE"
    }
    fn expires_at(&self) -> &str {
        "2026-10-15T14:00:00Z"
    }
    fn check_current(&self) -> wholepact_engine::Result<()> {
        if self.issuer.revoked.load(Ordering::SeqCst)
            || (self.issuer.deny_after_file.load(Ordering::SeqCst) && self.issuer.path.exists())
        {
            Err(ApiError::new(
                "DISCLOSURE_CONSENT_DENIED",
                "Synthetic exact export lease is denied",
            ))
        } else {
            Ok(())
        }
    }
}
impl DisclosureExportAuthority for ExportAuthority {
    fn acquire<'a>(
        &'a self,
        scope: &DisclosureExportScope,
        _: &ObservationWindow,
    ) -> wholepact_engine::Result<Box<dyn DisclosureExportLease + 'a>> {
        if scope.record.store != self.store
            || scope.target_binding != self.target
            || scope.record.action != ParticipantRecordAction::ExportReceipt
            || scope.record.account_id != "account-alice"
            || scope.record.principal_id != owner().principal_id
        {
            return Err(ApiError::new(
                "DISCLOSURE_CONSENT_DENIED",
                "Synthetic export target or store mismatch",
            ));
        }
        Ok(Box::new(ExportLease {
            scope: scope.clone(),
            issuer: self,
        }))
    }
}
fn stage_request() -> StageParticipantReceiptExport {
    StageParticipantReceiptExport {
        record_id: "private-record-alice".into(),
        expected_record_revision: 1,
        preview_id: "amount-only-preview".into(),
        export_id: "selected-export-one".into(),
    }
}
fn write_request() -> WriteParticipantReceiptExport {
    WriteParticipantReceiptExport {
        record_id: "private-record-alice".into(),
        export_id: "selected-export-one".into(),
    }
}
fn preview(engine: &Engine, authority: &SyntheticAuthority) -> (String, u64) {
    let (id, candidate, revision) = setup_candidate(engine);
    let retained = retain(engine, authority, &id, &candidate, revision);
    let prepared = engine
        .preview_participant_disclosure(
            &owner(),
            "export-test-preview-original",
            &id,
            retained.agreement_revision,
            disclosure_request(),
            authority.runtime(&window()),
        )
        .unwrap();
    (id, prepared.agreement_revision)
}
fn status(
    engine: &Engine,
    authority: &SyntheticAuthority,
    id: &str,
) -> ParticipantReceiptExportView {
    engine
        .participant_receipt_export_status(
            &owner(),
            id,
            "private-record-alice",
            "selected-export-one",
            authority.runtime(&window()),
        )
        .unwrap()
}

#[test]
fn selected_export_has_separate_consent_durable_intent_exact_file_and_metadata_only_history() {
    let dir = private_directory();
    let engine = Engine::from_store(
        Store::create_encrypted(
            dir.path().join("journal.db"),
            &DatabaseKey::from_bytes([161; 32]),
        )
        .unwrap(),
    );
    let account = SyntheticAuthority::for_engine(&engine);
    let (id, revision) = preview(&engine, &account);
    let file = dir.path().join("selected.json");
    let target = PrivateReceiptTarget::open(&file).unwrap();
    let consent = ExportAuthority::new(&engine, &target);
    consent.revoked.store(true, Ordering::SeqCst);
    assert_eq!(
        engine
            .stage_participant_receipt_export(
                &owner(),
                "receipt-stage-original-key",
                &id,
                revision,
                stage_request(),
                account.runtime(&window()),
                &target,
                &consent
            )
            .unwrap_err()
            .code,
        "DISCLOSURE_CONSENT_DENIED"
    );
    assert!(!file.exists());
    consent.revoked.store(false, Ordering::SeqCst);
    let staged = engine
        .stage_participant_receipt_export(
            &owner(),
            "receipt-stage-original-key",
            &id,
            revision,
            stage_request(),
            account.runtime(&window()),
            &target,
            &consent,
        )
        .unwrap();
    assert_eq!(staged.state, ReceiptExportState::StagedNoFileEffect);
    assert!(!file.exists());
    assert_eq!(
        engine
            .stage_participant_receipt_export(
                &owner(),
                "receipt-stage-original-key",
                &id,
                revision,
                stage_request(),
                account.runtime(&window()),
                &target,
                &consent
            )
            .unwrap()
            .agreement_revision,
        staged.agreement_revision
    );
    consent.revoked.store(true, Ordering::SeqCst);
    assert_eq!(
        engine
            .write_participant_receipt_export(
                &owner(),
                "receipt-write-original-key",
                &id,
                write_request(),
                account.runtime(&window()),
                &target,
                &consent
            )
            .unwrap_err()
            .code,
        "DISCLOSURE_CONSENT_DENIED"
    );
    assert!(!file.exists());
    consent.revoked.store(false, Ordering::SeqCst);
    let completed = engine
        .write_participant_receipt_export(
            &owner(),
            "receipt-write-original-key",
            &id,
            write_request(),
            account.runtime(&window()),
            &target,
            &consent,
        )
        .unwrap();
    assert_eq!(
        completed.state,
        ReceiptExportState::LocalFileWrittenHistorical
    );
    assert_eq!(completed.attempts, 1);
    let bytes = std::fs::read(&file).unwrap();
    let receipt =
        inspect_private_receipt(&bytes, &disclosure_request().selection.destination).unwrap();
    assert_eq!(
        receipt.facts,
        vec![DisclosedFact::RecipientAmount(amount(1000))]
    );
    let text = String::from_utf8(bytes).unwrap();
    for secret in [
        "PRIVATE-SYNTHETIC",
        "SYNTHETIC-SEPARATE-EXPORT-CONSENT",
        "account-alice",
        "private-record-alice",
        &id,
        &hash(3),
    ] {
        assert!(!text.contains(secret), "Unselected private value leaked");
    }
    let replay = engine
        .write_participant_receipt_export(
            &owner(),
            "receipt-write-original-key",
            &id,
            write_request(),
            account.runtime(&window()),
            &target,
            &consent,
        )
        .unwrap();
    assert_eq!(replay.attempts, 1);
    assert_eq!(replay.agreement_revision, completed.agreement_revision);
    let summary = serde_json::to_string(&status(&engine, &account, &id)).unwrap();
    assert!(!summary.contains("selected.json"));
    assert!(!summary.contains("1000"));
    assert!(!summary.contains("CONSENT"));
    std::fs::remove_file(&file).unwrap();
    // Completion is historical, never an automatic permission to recreate copies.
    assert_eq!(
        engine
            .write_participant_receipt_export(
                &owner(),
                "receipt-write-original-key",
                &id,
                write_request(),
                account.runtime(&window()),
                &target,
                &consent
            )
            .unwrap()
            .state,
        ReceiptExportState::LocalFileWrittenHistorical
    );
    assert!(!file.exists());
    consent.revoked.store(true, Ordering::SeqCst);
    assert_eq!(
        engine
            .write_participant_receipt_export(
                &owner(),
                "receipt-write-original-key",
                &id,
                write_request(),
                account.runtime(&window()),
                &target,
                &consent
            )
            .unwrap_err()
            .code,
        "DISCLOSURE_CONSENT_DENIED"
    );
}

#[test]
fn unknown_write_recovers_original_bytes_after_encrypted_restart_and_refuses_old_bindings() {
    let dir = private_directory();
    let database = dir.path().join("journal.db");
    let key = DatabaseKey::from_bytes([162; 32]);
    let engine = Engine::from_store(Store::create_encrypted(&database, &key).unwrap());
    let account = SyntheticAuthority::for_engine(&engine);
    let (id, revision) = preview(&engine, &account);
    let file = dir.path().join("selected.json");
    let target = PrivateReceiptTarget::open(&file).unwrap();
    let consent = ExportAuthority::new(&engine, &target);
    engine
        .stage_participant_receipt_export(
            &owner(),
            "receipt-stage-restart-key",
            &id,
            revision,
            stage_request(),
            account.runtime(&window()),
            &target,
            &consent,
        )
        .unwrap();
    // Deliberately faulty synthetic issuer fails the post-sink check, modelling
    // interruption after effect. No claim this is a compliant production issuer.
    consent.deny_after_file.store(true, Ordering::SeqCst);
    assert_eq!(
        engine
            .write_participant_receipt_export(
                &owner(),
                "receipt-write-restart-key",
                &id,
                write_request(),
                account.runtime(&window()),
                &target,
                &consent
            )
            .unwrap_err()
            .code,
        "DISCLOSURE_CONSENT_DENIED"
    );
    let original = std::fs::read(&file).unwrap();
    assert_eq!(
        status(&engine, &account, &id).state,
        ReceiptExportState::FileOutcomeUnknown
    );
    let restarted = Engine::from_store(Store::open_encrypted(&database, &key).unwrap());
    let current_account = SyntheticAuthority::for_engine(&restarted);
    let reopened = PrivateReceiptTarget::open(&file).unwrap();
    assert_eq!(
        restarted
            .write_participant_receipt_export(
                &owner(),
                "receipt-write-restart-key",
                &id,
                write_request(),
                current_account.runtime(&window()),
                &reopened,
                &consent
            )
            .unwrap_err()
            .code,
        "DISCLOSURE_CONSENT_DENIED"
    );
    let current_consent = ExportAuthority::new(&restarted, &reopened);
    let completed = restarted
        .write_participant_receipt_export(
            &owner(),
            "receipt-write-restart-key",
            &id,
            write_request(),
            current_account.runtime(&window()),
            &reopened,
            &current_consent,
        )
        .unwrap();
    assert_eq!(completed.attempts, 1);
    assert_eq!(
        completed.state,
        ReceiptExportState::LocalFileWrittenHistorical
    );
    assert_eq!(std::fs::read(&file).unwrap(), original);
    let disk = std::fs::read(database).unwrap();
    assert!(
        !disk
            .windows(b"SYNTHETIC-SEPARATE".len())
            .any(|w| w == b"SYNTHETIC-SEPARATE")
    );
}

#[test]
fn partial_existing_file_and_substituted_target_are_preserved_without_repair_or_new_copy() {
    use std::os::unix::fs::PermissionsExt;
    let dir = private_directory();
    let engine = Engine::from_store(
        Store::create_encrypted(
            dir.path().join("journal.db"),
            &DatabaseKey::from_bytes([163; 32]),
        )
        .unwrap(),
    );
    let account = SyntheticAuthority::for_engine(&engine);
    let (id, revision) = preview(&engine, &account);
    let file = dir.path().join("selected.json");
    let target = PrivateReceiptTarget::open(&file).unwrap();
    let consent = ExportAuthority::new(&engine, &target);
    engine
        .stage_participant_receipt_export(
            &owner(),
            "receipt-stage-partial-key",
            &id,
            revision,
            stage_request(),
            account.runtime(&window()),
            &target,
            &consent,
        )
        .unwrap();
    std::fs::write(&file, b"partial").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        engine
            .write_participant_receipt_export(
                &owner(),
                "receipt-write-partial-key",
                &id,
                write_request(),
                account.runtime(&window()),
                &target,
                &consent
            )
            .unwrap_err()
            .code,
        "DISCLOSURE_FILE_CONFLICT"
    );
    assert_eq!(
        status(&engine, &account, &id).state,
        ReceiptExportState::FileOutcomeUnknown
    );
    assert_eq!(std::fs::read(&file).unwrap(), b"partial");
    let alternative_path = dir.path().join("unselected.json");
    let alternative = PrivateReceiptTarget::open(&alternative_path).unwrap();
    let other_consent = ExportAuthority::new(&engine, &alternative);
    assert_eq!(
        engine
            .write_participant_receipt_export(
                &owner(),
                "receipt-write-other-target",
                &id,
                write_request(),
                account.runtime(&window()),
                &alternative,
                &other_consent
            )
            .unwrap_err()
            .code,
        "DISCLOSURE_INTENT_MISMATCH"
    );
    assert!(!alternative_path.exists());
    assert_eq!(std::fs::read(&file).unwrap(), b"partial");
}

#[test]
fn changed_source_and_restored_quarantine_block_new_export_but_preserve_history() {
    let dir = private_directory();
    let database = dir.path().join("journal.db");
    let key = DatabaseKey::from_bytes([164; 32]);
    let engine = Engine::from_store(Store::create_encrypted(&database, &key).unwrap());
    let account = SyntheticAuthority::for_engine(&engine);
    let (id, revision) = preview(&engine, &account);
    let file = dir.path().join("selected.json");
    let target = PrivateReceiptTarget::open(&file).unwrap();
    let consent = ExportAuthority::new(&engine, &target);
    let staged = engine
        .stage_participant_receipt_export(
            &owner(),
            "receipt-stage-quarantine",
            &id,
            revision,
            stage_request(),
            account.runtime(&window()),
            &target,
            &consent,
        )
        .unwrap();
    let backup = dir.path().join("backup.db");
    let backup_key = DatabaseKey::from_bytes([165; 32]);
    Store::open_encrypted(&database, &key)
        .unwrap()
        .backup_agreement_journal(&backup, &backup_key)
        .unwrap();
    let (restored, _) = wholepact_store::backup::restore_agreement_journal(
        &backup,
        &backup_key,
        dir.path().join("restored.db"),
        &DatabaseKey::from_bytes([166; 32]),
    )
    .unwrap();
    let restored = Engine::from_store(restored);
    let restored_account = SyntheticAuthority::for_engine(&restored);
    let restored_consent = ExportAuthority::new(&restored, &target);
    assert_eq!(
        status(&restored, &restored_account, &id).state,
        ReceiptExportState::StagedNoFileEffect
    );
    assert_eq!(
        restored
            .write_participant_receipt_export(
                &owner(),
                "receipt-restored-denied",
                &id,
                write_request(),
                restored_account.runtime(&window()),
                &target,
                &restored_consent
            )
            .unwrap_err()
            .code,
        "RECOVERY_REQUIRED"
    );
    engine
        .observe_participant_record(
            &owner(),
            "receipt-source-change-observe",
            &id,
            staged.agreement_revision,
            observe_request(1),
            account.runtime(&window()),
            &mut SyntheticChain {
                status: ChainStatus::PendingObserved,
                second: 1,
            },
        )
        .unwrap();
    assert_eq!(
        engine
            .write_participant_receipt_export(
                &owner(),
                "receipt-changed-source-key",
                &id,
                write_request(),
                account.runtime(&window()),
                &target,
                &consent
            )
            .unwrap_err()
            .code,
        "REVISION_CONFLICT"
    );
    assert_eq!(
        status(&engine, &account, &id).state,
        ReceiptExportState::StagedNoFileEffect
    );
    assert!(!file.exists());
}
