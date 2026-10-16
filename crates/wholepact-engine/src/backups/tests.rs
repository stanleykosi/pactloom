use super::*;
use std::{cell::Cell, os::unix::fs::PermissionsExt, path::PathBuf};
use wholepact_core::AgreementDraft;
use wholepact_store::authority::ReleaseIntent;

struct FixtureConsent {
    enrolled: LocalBackupSource,
    principal: String,
    action: FullJournalBackupAction,
    archive: PathBuf,
    destination: Option<PathBuf>,
    allowed: bool,
    invalidate_after_write: bool,
    checks: Cell<usize>,
    held: Cell<bool>,
}
struct FixtureLease<'a>(&'a FixtureConsent);
impl FullJournalBackupLease for FixtureLease<'_> {
    fn still_authorized(&self) -> bool {
        assert!(self.0.held.get());
        let count = self.0.checks.get() + 1;
        self.0.checks.set(count);
        self.0.allowed && !(self.0.invalidate_after_write && count > 1)
    }
}
impl Drop for FixtureLease<'_> {
    fn drop(&mut self) {
        self.0.held.set(false);
    }
}
impl FullJournalBackupConsent for FixtureConsent {
    fn acquire<'a>(
        &'a self,
        scope: &'a FullJournalBackupScope<'_>,
    ) -> Option<Box<dyn FullJournalBackupLease + 'a>> {
        if !self.allowed
            || !scope.source().matches_binding(&self.enrolled)
            || scope.principal_id() != self.principal
            || scope.action() != self.action
            || scope.archive_path() != self.archive
            || scope.restore_destination() != self.destination.as_deref()
            || scope.retention_policy() != "local-only; retain until deliberately removed"
            || scope.included_journals() != INCLUDED_JOURNALS
            || scope.excluded_journals() != EXCLUDED_JOURNALS
            || !scope.includes_all_principals_and_profiles()
            || !scope.backup_key_loss_is_unrecoverable()
        {
            return None;
        }
        assert!(!self.held.replace(true));
        Some(Box::new(FixtureLease(self)))
    }
}
fn private_directory() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}
fn key(value: u8) -> DatabaseKey {
    DatabaseKey::from_bytes([value; 32])
}
fn actor(id: &str) -> Access {
    Access {
        include_owned_agreements: true,
        principal_id: id.into(),
        ..Access::default()
    }
}
fn draft(id: &str) -> AgreementDraft {
    let mut draft: AgreementDraft = serde_json::from_str(include_str!(
        "../../../wholepact-core/tests/fixtures/agreement.json"
    ))
    .unwrap();
    draft.agreement_id = id.into();
    draft.obligation_id = format!("obligation-{id}");
    draft
}
fn consent(
    source: &LocalBackupSource,
    action: FullJournalBackupAction,
    archive: &Path,
    destination: Option<&Path>,
) -> FixtureConsent {
    FixtureConsent {
        enrolled: source.clone(),
        principal: "backup-admin".into(),
        action,
        archive: archive.into(),
        destination: destination.map(Path::to_path_buf),
        allowed: true,
        invalidate_after_write: false,
        checks: Cell::new(0),
        held: Cell::new(false),
    }
}
const RETENTION: &str = "local-only; retain until deliberately removed";
fn release(id: &str) -> ReleaseIntent {
    ReleaseIntent {
        authorization_id: id.into(),
        account_id: "account-a".into(),
        writer_epoch: 1,
        obligation_id: format!("obligation-{id}"),
        proposal_id: format!("proposal-{id}"),
        manifest_digest: "a".repeat(64),
        effects_digest: "b".repeat(64),
        artifact_digest: "c".repeat(64),
        maximum_debit: "20".into(),
        input_ids: vec![format!("input-{id}")],
        aggregate_budget_limit: "100".into(),
    }
}

#[test]
fn protected_engine_backup_test_restore_reopen_preserves_all_principals_and_replay() {
    let dir = private_directory();
    let source_path = dir.path().join("source.sqlite");
    let engine = Engine::from_store(Store::create_encrypted(&source_path, &key(71)).unwrap());
    let owner = actor("owner-a");
    let other = actor("owner-b");
    let admin = actor("backup-admin");
    let first = engine
        .create(&owner, "engine-backup-create-001", draft("agreement-a"))
        .unwrap();
    engine
        .create(&other, "engine-backup-create-002", draft("agreement-b"))
        .unwrap();
    assert!(engine.list(&admin).unwrap().is_empty());
    engine
        .store
        .initialize_authority_account("account-a", 1)
        .unwrap();
    engine
        .store
        .record_authorization_release_intent(&release("auth-a"))
        .unwrap();
    let source = engine
        .bind_local_backup_source("local-test-profile", "coordination-store")
        .unwrap();
    let archive = dir.path().join("backup.sqlite");
    let create_consent = consent(
        &source,
        FullJournalBackupAction::CreateArchive,
        &archive,
        None,
    );
    let summary = engine
        .backup_local_journal(
            &admin,
            LocalJournalBackup {
                source: &source,
                destination: &archive,
                backup_key: &key(72),
                retention_policy: RETENTION,
                consent: &create_consent,
            },
        )
        .unwrap();
    assert_eq!(summary.table_rows["records"], 2);
    assert_eq!(create_consent.checks.get(), 2);
    assert!(!create_consent.held.get());
    assert!(!summary.wallet_secrets_included && !summary.separate_artifact_journals_included);
    let destination = dir.path().join("test-restored.sqlite");
    let restore_consent = consent(
        &source,
        FullJournalBackupAction::TestRestore,
        &archive,
        Some(&destination),
    );
    let report = engine
        .test_restore_local_journal(
            &admin,
            LocalJournalRestore {
                source: &source,
                archive: &archive,
                backup_key: &key(72),
                destination: &destination,
                destination_key: &key(73),
                retention_policy: RETENTION,
                consent: &restore_consent,
            },
        )
        .unwrap();
    assert!(report.recovery_required && report.integrity_verified);
    assert!(!report.authorization_allowed && !report.signer_recovered);
    assert_eq!(restore_consent.checks.get(), 2);
    assert!(!restore_consent.held.get());
    let restored = Engine::from_store(Store::open_encrypted(&destination, &key(73)).unwrap());
    let replay = restored
        .create(&owner, "engine-backup-create-001", draft("agreement-a"))
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.operation_id, first.operation_id);
    assert_eq!(
        restored
            .get(&other, "agreement-b")
            .unwrap()
            .agreement
            .agreement_id,
        "agreement-b"
    );
    assert!(restored.get(&owner, "agreement-b").is_err());
    assert!(matches!(
        restored
            .store
            .initialize_authority_account("fresh-account", 1),
        Err(StoreError::RecoveryRequired)
    ));
    assert!(matches!(
        restored
            .store
            .record_authorization_release_intent(&release("auth-b")),
        Err(StoreError::RecoveryRequired)
    ));
    let recovery = restored.journal_recovery_metadata().unwrap();
    assert!(recovery.restored_journal_quarantined && recovery.writer_reconciliation_required);
    assert!(!recovery.writer_authority_established);
    assert!(
        !recovery.outstanding_history_completeness_established
            && !recovery.new_authorization_allowed
    );
    let wire = serde_json::to_string(&recovery).unwrap();
    for private in [
        "account-a",
        "agreement-a",
        "source.sqlite",
        "snapshot_digest",
    ] {
        assert!(!wire.contains(private));
    }
    let scoped = restored.recovery(&owner).unwrap();
    assert_eq!(scoped["status"], "restored_journal_quarantined");
    assert_eq!(scoped["authority_status"], "recovery_required");
    assert_eq!(scoped["agreements_loaded"], 1);
    assert_eq!(restored.recovery(&admin).unwrap()["agreements_loaded"], 0);
    let capability = engine.capabilities();
    assert_eq!(
        capability["features"]["encrypted_backups"]["status"],
        "experimental"
    );
    assert_eq!(
        capability["features"]["encrypted_backups"]["http_available"],
        false
    );
    assert_eq!(
        Engine::in_memory().unwrap().capabilities()["features"]["encrypted_backups"]["status"],
        "unavailable"
    );
    assert!(
        !engine
            .journal_recovery_metadata()
            .unwrap()
            .restored_journal_quarantined
    );
}

#[test]
fn ordinary_read_or_broad_read_never_grants_backup_and_exact_scope_is_required() {
    let dir = private_directory();
    let engine = Engine::from_store(
        Store::create_encrypted(dir.path().join("source.sqlite"), &key(81)).unwrap(),
    );
    let source = engine
        .bind_local_backup_source("profile-a", "source-a")
        .unwrap();
    let archive = dir.path().join("refused.sqlite");
    let mut grant = consent(
        &source,
        FullJournalBackupAction::CreateArchive,
        &archive,
        None,
    );
    grant.allowed = false;
    let mut broad = actor("backup-admin");
    broad.all_agreements = true;
    assert_eq!(
        engine
            .backup_local_journal(
                &broad,
                LocalJournalBackup {
                    source: &source,
                    destination: &archive,
                    backup_key: &key(82),
                    retention_policy: RETENTION,
                    consent: &grant
                }
            )
            .unwrap_err()
            .code,
        "FULL_JOURNAL_BACKUP_CONSENT_REQUIRED"
    );
    grant.allowed = true;
    assert!(
        engine
            .backup_local_journal(
                &actor("reader"),
                LocalJournalBackup {
                    source: &source,
                    destination: &archive,
                    backup_key: &key(82),
                    retention_policy: RETENTION,
                    consent: &grant
                }
            )
            .is_err()
    );
    let wrong_path = dir.path().join("different.sqlite");
    assert!(
        engine
            .backup_local_journal(
                &broad,
                LocalJournalBackup {
                    source: &source,
                    destination: &wrong_path,
                    backup_key: &key(82),
                    retention_policy: RETENTION,
                    consent: &grant
                }
            )
            .is_err()
    );
    assert!(
        engine
            .backup_local_journal(
                &broad,
                LocalJournalBackup {
                    source: &source,
                    destination: &archive,
                    backup_key: &key(82),
                    retention_policy: "changed retention",
                    consent: &grant
                }
            )
            .is_err()
    );
    assert!(!archive.exists() && !wrong_path.exists());
    assert_eq!(grant.checks.get(), 0);
}

#[test]
fn store_instance_profile_and_action_binding_cannot_be_reused() {
    let dir = private_directory();
    let path = dir.path().join("source.sqlite");
    let engine = Engine::from_store(Store::create_encrypted(&path, &key(91)).unwrap());
    let source = engine
        .bind_local_backup_source("profile-a", "source-a")
        .unwrap();
    let same_label_reopen = Engine::from_store(Store::open_encrypted(&path, &key(91)).unwrap());
    let rebound = same_label_reopen
        .bind_local_backup_source("profile-a", "source-a")
        .unwrap();
    assert!(!source.matches_binding(&rebound));
    let other_profile = engine
        .bind_local_backup_source("profile-b", "source-a")
        .unwrap();
    assert!(!source.matches_binding(&other_profile));
    let archive = dir.path().join("backup.sqlite");
    let grant = consent(
        &source,
        FullJournalBackupAction::CreateArchive,
        &archive,
        None,
    );
    assert_eq!(
        same_label_reopen
            .backup_local_journal(
                &actor("backup-admin"),
                LocalJournalBackup {
                    source: &source,
                    destination: &archive,
                    backup_key: &key(92),
                    retention_policy: RETENTION,
                    consent: &grant
                }
            )
            .unwrap_err()
            .code,
        "BACKUP_SOURCE_MISMATCH"
    );
    assert!(
        engine
            .backup_local_journal(
                &actor("backup-admin"),
                LocalJournalBackup {
                    source: &other_profile,
                    destination: &archive,
                    backup_key: &key(92),
                    retention_policy: RETENTION,
                    consent: &grant
                }
            )
            .is_err()
    );
    engine
        .backup_local_journal(
            &actor("backup-admin"),
            LocalJournalBackup {
                source: &source,
                destination: &archive,
                backup_key: &key(92),
                retention_policy: RETENTION,
                consent: &grant,
            },
        )
        .unwrap();
    let destination = dir.path().join("restore.sqlite");
    assert!(
        engine
            .test_restore_local_journal(
                &actor("backup-admin"),
                LocalJournalRestore {
                    source: &source,
                    archive: &archive,
                    backup_key: &key(92),
                    destination: &destination,
                    destination_key: &key(93),
                    retention_policy: RETENTION,
                    consent: &grant
                }
            )
            .is_err()
    );
    assert!(!destination.exists());
    let restore_grant = consent(
        &source,
        FullJournalBackupAction::RestoreJournal,
        &archive,
        Some(&destination),
    );
    let (restored, _) = engine
        .restore_local_journal(
            &actor("backup-admin"),
            LocalJournalRestore {
                source: &source,
                archive: &archive,
                backup_key: &key(92),
                destination: &destination,
                destination_key: &key(93),
                retention_policy: RETENTION,
                consent: &restore_grant,
            },
        )
        .unwrap();
    assert!(
        restored
            .journal_recovery_metadata()
            .unwrap()
            .restored_journal_quarantined
    );
}

#[test]
fn permission_change_reports_possible_output_and_never_enables_authority() {
    let dir = private_directory();
    let engine = Engine::from_store(
        Store::create_encrypted(dir.path().join("source.sqlite"), &key(101)).unwrap(),
    );
    let source = engine
        .bind_local_backup_source("profile-a", "source-a")
        .unwrap();
    let archive = dir.path().join("backup.sqlite");
    let mut grant = consent(
        &source,
        FullJournalBackupAction::CreateArchive,
        &archive,
        None,
    );
    // This deliberately broken synthetic provider fails its own lease contract;
    // the engine must not hide an already committed encrypted output as absent.
    grant.invalidate_after_write = true;
    let error = engine
        .backup_local_journal(
            &actor("backup-admin"),
            LocalJournalBackup {
                source: &source,
                destination: &archive,
                backup_key: &key(102),
                retention_policy: RETENTION,
                consent: &grant,
            },
        )
        .unwrap_err();
    assert_eq!(error.code, "BACKUP_PERMISSION_CHANGED");
    assert_eq!(error.details["encrypted_output_may_exist"], true);
    assert_eq!(error.details["authority_enabled"], false);
    assert!(!grant.held.get());
    assert!(archive.exists());
    assert!(wholepact_store::backup::inspect_agreement_backup(&archive, &key(102)).is_ok());
    assert!(
        Engine::in_memory()
            .unwrap()
            .bind_local_backup_source("profile", "source")
            .is_err()
    );
    assert!(
        engine
            .backup_local_journal(
                &actor("backup-admin"),
                LocalJournalBackup {
                    source: &source,
                    destination: Path::new("relative.sqlite"),
                    backup_key: &key(102),
                    retention_policy: RETENTION,
                    consent: &grant
                }
            )
            .is_err()
    );
}
