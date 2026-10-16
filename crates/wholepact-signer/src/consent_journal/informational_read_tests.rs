//! Sealed signer-source projection only. Reuses the inspected historical V5
//! fixture and ledger replay; no sockets, proof helpers, native/session issuers,
//! wallet creation or spending/signing keys. Database keys are fixed test bytes.
use super::*;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use wholepact_storage_security::{bundle::*, DatabaseKey};

fn seal_original(
    root: &Path,
    journal: &SignerConsentJournal,
) -> recovery::VerifiedSignerRecoverySource {
    let archive = root.join("synthetic-original-archive.sqlite");
    let restored = root.join("synthetic-quarantined-source.sqlite");
    let archive_key = DatabaseKey::from_bytes([0x72; 32]);
    let restored_key = DatabaseKey::from_bytes([0x73; 32]);
    let adapter = journal.backup_adapter();
    let sources = [RegisteredJournal::new("signer-authority", &adapter).unwrap()];
    snapshot(SnapshotRequest {
        principal_id: "synthetic-owner",
        profile_id: "synthetic-signer-profile",
        coverage: crate::account::backup::coverage(false),
        sources: &sources,
        destination: &archive,
        key: &archive_key,
        authority: &crate::consent_journal::tests::BackupGate,
    })
    .unwrap();
    let report = restore(RestoreRequest {
        principal_id: "synthetic-owner",
        profile_id: "synthetic-signer-profile",
        archive: &archive,
        key: &archive_key,
        targets: &[RestoreTarget {
            component_id: "signer-authority",
            template: SignerConsentBundleAdapter::template(),
            destination: &restored,
            key: &restored_key,
        }],
        authority: &crate::consent_journal::tests::BackupGate,
    })
    .unwrap();
    assert!(!report.authorization_allowed);
    recovery::VerifiedSignerRecoverySource::open(
        history::HistoryOpenRequest {
            archive: &archive,
            archive_key: &archive_key,
            component_id: "signer-authority",
            restored_component: &restored,
            restored_key: &restored_key,
        },
        SignerConsentBundleAdapter::template(),
    )
    .unwrap()
}

fn tree(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    use std::os::unix::fs::MetadataExt;
    let mut files = BTreeMap::new();
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        assert!(metadata.is_file());
        let mut bytes = format!(
            "{}:{}:{}:{}:{}:",
            metadata.mode(),
            metadata.uid(),
            metadata.nlink(),
            metadata.dev(),
            metadata.ino(),
        )
        .into_bytes();
        bytes.extend(std::fs::read(&path).unwrap());
        files.insert(path, bytes);
    }
    files
}

#[test]
fn sealed_original_v5_read_preserves_all_source_files_and_complete_history() {
    let (dir, journal, history) = source(false);
    let account = journal.account_state().unwrap();
    assert!(!account.recovery_required);
    let expected = {
        let mut c = journal.connection.lock().unwrap();
        let tx = c.transaction().unwrap();
        let complete =
            read_complete_continuity_v5(&tx, &account, journal.capacity_limits(), &history)
                .unwrap();
        tx.rollback().unwrap();
        complete
    };
    let sealed = seal_original(dir.path(), &journal);
    let source_account = sealed.account().unwrap();
    let flag = source_account
        .columns()
        .iter()
        .position(|column| column == "recovery_required")
        .unwrap();
    // Verified restoration is quarantined, while its sealed original account
    // row remains exactly the active archival row. The read rewrites neither.
    assert!(matches!(
        source_account.rows()[0].cells()[flag],
        recovery::RecoveryCell::Integer(0)
    ));
    drop(journal);
    let before = tree(dir.path());
    let owner = QuarantinedJournalRead::from_verified(sealed, &account.account_id).unwrap();
    assert_eq!(owner.writer_epoch(), account.writer_epoch);
    assert!(!owner.checkpoint_id().is_empty());
    for _ in 0..2 {
        let complete = owner.complete_history_v5(&history).unwrap();
        assert!(complete == expected);
        assert!(!complete.construction.transport.credentials.is_empty());
        assert!(complete.conservative_debit_zatoshis().unwrap() > 0);
        assert!(complete.require_financial_activation_supported().is_err());
        assert_eq!(before, tree(dir.path()));
    }
    drop(owner);
    assert_eq!(before, tree(dir.path()));
}

#[test]
fn sealed_original_v5_read_keeps_paused_revoked_and_retired_history_informational() {
    use wholepact_authority::{
        account_use::{ExclusionReason, PermanentAccountExclusion},
        OwnerControl,
    };
    let (dir, journal, history) = source(false);
    let account = journal.account_state().unwrap();
    let sealed = seal_original(dir.path(), &journal);
    drop(journal);
    let before = tree(dir.path());
    let owner = QuarantinedJournalRead::from_verified(sealed, &account.account_id).unwrap();
    let baseline = owner.complete_history_v5(&history).unwrap();
    let genesis = history.account_use_history().genesis().unwrap();
    let operation = "synthetic-sealed-v5-retire";
    let exclusion = PermanentAccountExclusion {
        version: 1,
        identity: genesis.identity.clone(),
        genesis_digest: genesis.digest().unwrap(),
        operation_id: operation.into(),
        native_review_digest: "af".repeat(32),
        reason: ExclusionReason::RetirementRequested,
    };
    for (operation, control) in [
        ("synthetic-sealed-v5-pause", OwnerControl::Pause),
        ("synthetic-sealed-v5-revoke", OwnerControl::Revoke),
        (
            operation,
            OwnerControl::PermanentlyExcludeAccount {
                exclusion: exclusion.clone(),
            },
        ),
    ] {
        let changed = history_after_control(&history, operation, control);
        assert!(changed.snapshot().active_writer_session.is_none());
        let complete = owner.complete_history_v5(&changed).unwrap();
        assert!(complete.construction == changed.construction_history_with_transport_v1().unwrap());
        assert!(complete.signer_common_context_audit == baseline.signer_common_context_audit);
        assert_eq!(
            serde_json::to_vec(&complete.construction.transport).unwrap(),
            serde_json::to_vec(&baseline.construction.transport).unwrap()
        );
        assert_eq!(
            complete.conservative_debit_zatoshis().unwrap(),
            baseline.conservative_debit_zatoshis().unwrap()
        );
        assert_eq!(
            complete.conservative_obligations().unwrap(),
            baseline.conservative_obligations().unwrap()
        );
        let mut expected_financial = baseline.financial_origins_v2.clone();
        expected_financial.account_use = complete.financial_origins_v2.account_use.clone();
        assert!(complete.financial_origins_v2 == expected_financial);
        assert!(
            complete.financial_origins_v2.account_use.exclusion.as_ref()
                == changed.account_use_history().exclusion()
        );
        if changed.account_use_history().exclusion().is_some() {
            assert!(complete
                .financial_origins_v2
                .account_use
                .witness_ack
                .is_some());
        }
        assert!(complete.require_financial_activation_supported().is_err());
        assert_eq!(before, tree(dir.path()));
    }
    // A newer exclusion was returned only as historical evidence, not imported
    // into the sealed source or the owner's later projection of original replay.
    assert!(owner.complete_history_v5(&history).unwrap() == baseline);
    assert_eq!(before, tree(dir.path()));
}

#[test]
fn sealed_original_v5_read_refuses_account_and_epoch_substitution_without_writes() {
    let (dir, journal, history) = source(false);
    let sealed = seal_original(dir.path(), &journal);
    drop(journal);
    let before = tree(dir.path());
    assert!(matches!(
        QuarantinedJournalRead::from_verified(sealed, &"ff".repeat(32)),
        Err(JournalError::InvalidBinding)
    ));
    assert_eq!(before, tree(dir.path()));

    let (dir, journal, _) = source(false);
    // Synthetic original database preparation only. No historical replay,
    // native decision or source owner is changed to impersonate epoch 2.
    journal
        .connection
        .lock()
        .unwrap()
        .execute(
            "UPDATE signer_account SET writer_epoch=2 WHERE singleton=1",
            [],
        )
        .unwrap();
    let sealed = seal_original(dir.path(), &journal);
    drop(journal);
    let before = tree(dir.path());
    let owner =
        QuarantinedJournalRead::from_verified(sealed, &history.snapshot().account_id).unwrap();
    assert_eq!(owner.writer_epoch(), 2);
    assert!(matches!(
        owner.complete_history_v5(&history),
        Err(JournalError::InvalidBinding)
    ));
    assert_eq!(before, tree(dir.path()));
}
