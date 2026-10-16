#![cfg(all(
    feature = "submission-handoff",
    feature = "transport-workflows",
    feature = "wallet-sync",
    target_os = "linux"
))]
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Mutex,
};
use wholepact_chain::{
    backup::SubmissionBackupAdapter, EncryptedSubmissionJournal, ExactSubmissionIntent,
    SubmissionJournal,
};
use wholepact_proof_jobs::{backup::ProofWitnessBackupAdapter, ProofJobStore};
use wholepact_protocol::authorization::retention::{
    backup::SignedResultsBackupAdapter,
    transaction::{backup::ExactTransactionsBackupAdapter, TransactionCheckpointJournal},
    SignedResultJournal,
};
use wholepact_storage_security::{
    bundle::*, create_encrypted, open_encrypted, DatabaseKey, StorageSecurityError,
};
use wholepact_store::{bundle::CoordinationBundleAdapter, CommandContext, Store};
use wholepact_transport::{SqliteOutbox, SqliteReplayLedger};

struct FixtureGate {
    sources: Vec<JournalBinding>,
}
struct FixtureLease;
impl BundleLease for FixtureLease {
    fn check_current(&self) -> Result<(), BundleError> {
        Ok(())
    }
    fn checkpoint_id(&self) -> &str {
        "synthetic-quiesced-checkpoint"
    }
}
impl BundleAuthority for FixtureGate {
    fn acquire<'a>(
        &'a self,
        scope: &BundleScope<'_>,
    ) -> Result<Box<dyn BundleLease + 'a>, BundleError> {
        if scope.principal_id != "fixture-admin"
            || scope.profile_id != "fixture-profile"
            || scope.wallet_spending_secrets_included
            || scope.action == BundleAction::Snapshot
                && scope
                    .sources
                    .iter()
                    .map(|s| s.1.clone())
                    .collect::<Vec<_>>()
                    != self.sources
        {
            return Err(BundleError::Permission);
        }
        Ok(Box::new(FixtureLease))
    }
}
#[test]
fn real_encrypted_journal_adapters_share_one_consistent_manifest_and_restore_quarantine() {
    // Fixed public keys protect only never-funded synthetic fixtures.
    let dir = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let source_key = DatabaseKey::from_bytes([83; 32]);
    let archive_key = DatabaseKey::from_bytes([84; 32]);
    let restore_key = DatabaseKey::from_bytes([85; 32]);
    let store = Store::create_encrypted(dir.path().join("coord"), &source_key).unwrap();
    let context = CommandContext::for_request(
        "owner",
        "bundle-fixture-operation",
        &serde_json::json!({"fixture":"original"}),
    )
    .unwrap();
    let operation = store
        .create_agreement(
            &context,
            "agreement",
            serde_json::json!({"private":"coordination-canary"}),
        )
        .unwrap();
    let wallet_path = dir.path().join("wallet");
    let wallet = wholepact_wallet::wallet::DedicatedTestnetWallet::from_encrypted_connection(
        create_encrypted(&wallet_path, &source_key).unwrap(),
    )
    .unwrap();
    let wallet_adapter = wholepact_wallet::bundle::WalletScanBackupAdapter::new(
        &wallet,
        open_encrypted(&wallet_path, &source_key).unwrap(),
    )
    .unwrap();
    let clone_path = dir.path().join("wallet-clone");
    wholepact_storage_security::backup_encrypted(
        &open_encrypted(&wallet_path, &source_key).unwrap(),
        &clone_path,
        &archive_key,
    )
    .unwrap();
    assert!(wholepact_wallet::bundle::WalletScanBackupAdapter::new(
        &wallet,
        open_encrypted(&clone_path, &archive_key).unwrap()
    )
    .is_err());
    let proof = ProofJobStore::from_encrypted_connection(
        create_encrypted(dir.path().join("proof"), &source_key).unwrap(),
    )
    .unwrap();
    let signed = SignedResultJournal::from_encrypted_connection(
        create_encrypted(dir.path().join("signed"), &source_key).unwrap(),
    )
    .unwrap();
    let exact = TransactionCheckpointJournal::from_encrypted_connection(
        create_encrypted(dir.path().join("exact"), &source_key).unwrap(),
    )
    .unwrap();
    let mut submission = EncryptedSubmissionJournal::from_encrypted_connection(
        create_encrypted(dir.path().join("submission"), &source_key).unwrap(),
    )
    .unwrap();
    let intent = ExactSubmissionIntent::new(
        "bundle-synthetic-operation",
        b"never-funded-opaque-intent-not-a-valid-transaction",
    )
    .unwrap();
    submission.record_exact_intent(&intent).unwrap();
    let submission = Mutex::new(submission);
    let mut inbox = SqliteReplayLedger::from_encrypted_connection(
        create_encrypted(dir.path().join("inbox"), &source_key).unwrap(),
    )
    .unwrap();
    let mut outbox = SqliteOutbox::from_encrypted_connection(
        create_encrypted(dir.path().join("outbox"), &source_key).unwrap(),
    )
    .unwrap();
    let coord_adapter = CoordinationBundleAdapter::new(&store).unwrap();
    let proof_adapter = ProofWitnessBackupAdapter::new(&proof);
    let signed_adapter = SignedResultsBackupAdapter::new(&signed);
    let exact_adapter = ExactTransactionsBackupAdapter::new(&exact);
    let submission_adapter = SubmissionBackupAdapter::new(&submission);
    let inbox_adapter = inbox.backup_adapter().unwrap();
    let outbox_adapter = outbox.backup_adapter().unwrap();
    let adapters: [(&str, &dyn JournalAdapter); 8] = [
        ("coord", &coord_adapter),
        ("wallet", &wallet_adapter),
        ("proof", &proof_adapter),
        ("signed", &signed_adapter),
        ("exact", &exact_adapter),
        ("submission", &submission_adapter),
        ("inbox", &inbox_adapter),
        ("outbox", &outbox_adapter),
    ];
    let sources = vec![
        RegisteredJournal::new("coord", &coord_adapter).unwrap(),
        RegisteredJournal::new("wallet", &wallet_adapter).unwrap(),
        RegisteredJournal::new("proof", &proof_adapter).unwrap(),
        RegisteredJournal::new("signed", &signed_adapter).unwrap(),
        RegisteredJournal::new("exact", &exact_adapter).unwrap(),
        RegisteredJournal::new("submission", &submission_adapter).unwrap(),
        RegisteredJournal::new("inbox", &inbox_adapter).unwrap(),
        RegisteredJournal::new("outbox", &outbox_adapter).unwrap(),
    ];
    let coverage = Coverage {
        present: adapters
            .iter()
            .map(|(id, adapter)| (adapter.template().kind, vec![id.to_string()]))
            .collect::<BTreeMap<_, _>>(),
        absent: BTreeSet::from([JournalKind::SignerConsentAuthority]),
    };
    let gate = FixtureGate {
        sources: sources.iter().map(|s| s.binding()).collect(),
    };
    let archive = dir.path().join("bundle");
    let manifest = snapshot(SnapshotRequest {
        principal_id: "fixture-admin",
        profile_id: "fixture-profile",
        coverage,
        sources: &sources,
        destination: &archive,
        key: &archive_key,
        authority: &gate,
    })
    .unwrap();
    assert_eq!(manifest.components.len(), 8);
    assert!(!manifest.wallet_spending_secrets_included);
    assert!(!manifest.writer_freshness_established);
    assert!(
        manifest
            .components
            .iter()
            .find(|c| c.id == "coord")
            .unwrap()
            .rows
            > 3
    );
    assert!(
        manifest
            .components
            .iter()
            .find(|c| c.id == "submission")
            .unwrap()
            .rows
            >= 2
    );
    let destinations: Vec<_> = adapters
        .iter()
        .map(|(id, _)| dir.path().join(format!("restored-{id}")))
        .collect();
    let targets: Vec<_> = adapters
        .iter()
        .zip(&destinations)
        .map(|((id, adapter), path)| RestoreTarget {
            component_id: id,
            template: adapter.template(),
            destination: path,
            key: &restore_key,
        })
        .collect();
    let report = test_restore(RestoreRequest {
        principal_id: "fixture-admin",
        profile_id: "fixture-profile",
        archive: &archive,
        key: &archive_key,
        targets: &targets,
        authority: &gate,
    })
    .unwrap();
    assert_eq!(report.restored_components, 8);
    assert!(report.all_components_quarantined);
    assert!(!report.authorization_allowed);
    for destination in &destinations {
        assert!(matches!(
            open_encrypted(destination, &restore_key),
            Err(StorageSecurityError::QuarantinedDatabase)
        ));
    }
    let replay = store
        .create_agreement(
            &context,
            "agreement",
            serde_json::json!({"private":"coordination-canary"}),
        )
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.operation_id, operation.operation_id);
    assert!(submission
        .lock()
        .unwrap()
        .recover_intent_summary(intent.operation_id())
        .unwrap()
        .is_some());
    assert!(Store::open_encrypted(&destinations[0], &restore_key).is_err());
}
