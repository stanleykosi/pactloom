#![cfg(target_os = "linux")]
use std::{collections::BTreeMap, os::unix::fs::PermissionsExt};
use wholepact_core::AgreementDraft;
use wholepact_engine::{Access, Engine};
use wholepact_storage_security::{DatabaseKey, StorageSecurityError, bundle::*};
use wholepact_store::{
    CommandContext, Store, StoreError,
    bundle::{CoordinationBundleAdapter, coordination_template},
    history::*,
};
struct FixtureBackupGate;
struct FixtureBackupLease;
impl BundleLease for FixtureBackupLease {
    fn check_current(&self) -> Result<(), BundleError> {
        Ok(())
    }
    fn checkpoint_id(&self) -> &str {
        "all-synthetic-writers-stopped"
    }
}
impl BundleAuthority for FixtureBackupGate {
    fn acquire<'a>(
        &'a self,
        scope: &BundleScope<'_>,
    ) -> Result<Box<dyn BundleLease + 'a>, BundleError> {
        if scope.principal_id != "fixture-admin" || scope.profile_id != "fixture-profile" {
            return Err(BundleError::Permission);
        }
        Ok(Box::new(FixtureBackupLease))
    }
}
struct FixtureHistoryGate {
    binding: HistoryBinding,
}
struct FixtureHistoryLease;
impl HistoryLease for FixtureHistoryLease {
    fn check_current(&self) -> Result<(), BundleError> {
        Ok(())
    }
}
impl HistoryAuthority for FixtureHistoryGate {
    fn acquire<'a>(
        &'a self,
        scope: &HistoryScope<'_>,
    ) -> Result<Box<dyn HistoryLease + 'a>, BundleError> {
        if *scope.source != self.binding
            || scope.principal_id != "history-reader"
            || scope.profile_id != "fixture-profile"
            || scope.component_id != "coordination"
            || scope.agreement_id != "historical-agreement"
        {
            return Err(BundleError::Permission);
        }
        Ok(Box::new(FixtureHistoryLease))
    }
}
#[test]
fn encrypted_engine_bundle_restore_can_read_only_original_agreement_history() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let key = DatabaseKey::from_bytes([105; 32]); // Public never-funded synthetic fixture.
    let source_path = dir.path().join("source");
    let engine = Engine::from_store(Store::create_encrypted(&source_path, &key).unwrap());
    let owner = Access {
        include_owned_agreements: true,
        principal_id: "owner".into(),
        ..Default::default()
    };
    let mut draft: AgreementDraft = serde_json::from_str(include_str!(
        "../../wholepact-core/tests/fixtures/agreement.json"
    ))
    .unwrap();
    draft.agreement_id = "historical-agreement".into();
    let purpose = draft.purpose.clone();
    let created = engine
        .create(&owner, "historical-create-command", draft)
        .unwrap();
    engine
        .cancel(
            &owner,
            "historical-cancel-command",
            "historical-agreement",
            1,
        )
        .unwrap();
    drop(engine);
    let store = Store::open_encrypted(&source_path, &key).unwrap();
    // Private aggregate deliberately collides with the agreement ID. Its event
    // and payload must never enter the public historical agreement projection.
    let context = CommandContext::for_request(
        "private-owner",
        "private-collision-command",
        &serde_json::json!({"private":"PRIVATE_CANARY"}),
    )
    .unwrap();
    store
        .commit_record(
            &context,
            "participant_record",
            "historical-agreement",
            None,
            serde_json::json!({"private":"PRIVATE_CANARY"}),
            "PRIVATE_KIND",
        )
        .unwrap();
    let adapter = CoordinationBundleAdapter::new(&store).unwrap();
    let sources = [RegisteredJournal::new("coordination", &adapter).unwrap()];
    let archive = dir.path().join("archive");
    snapshot(SnapshotRequest {
        principal_id: "fixture-admin",
        profile_id: "fixture-profile",
        sources: &sources,
        destination: &archive,
        key: &key,
        authority: &FixtureBackupGate,
        coverage: Coverage {
            present: BTreeMap::from([(
                JournalKind::CoordinationAuthority,
                vec!["coordination".into()],
            )]),
            absent: [
                JournalKind::SignerConsentAuthority,
                JournalKind::WalletScan,
                JournalKind::ProofWitness,
                JournalKind::SignedResults,
                JournalKind::ExactTransactions,
                JournalKind::Submission,
                JournalKind::TransportInbox,
                JournalKind::TransportOutbox,
            ]
            .into_iter()
            .collect(),
        },
    })
    .unwrap();
    let restored_path = dir.path().join("restored");
    test_restore(RestoreRequest {
        principal_id: "fixture-admin",
        profile_id: "fixture-profile",
        archive: &archive,
        key: &key,
        targets: &[RestoreTarget {
            component_id: "coordination",
            template: coordination_template(),
            destination: &restored_path,
            key: &key,
        }],
        authority: &FixtureBackupGate,
    })
    .unwrap();
    assert!(matches!(
        Store::open_encrypted(&restored_path, &key),
        Err(StoreError::StorageSecurity(
            StorageSecurityError::QuarantinedDatabase
        ))
    ));
    let history = open_quarantined_history(HistoryOpenRequest {
        archive: &archive,
        archive_key: &key,
        component_id: "coordination",
        restored_component: &restored_path,
        restored_key: &key,
    })
    .unwrap();
    let gate = FixtureHistoryGate {
        binding: history.binding(),
    };
    let agreement = history
        .agreement("history-reader", "historical-agreement", &gate)
        .unwrap()
        .unwrap();
    assert_eq!(agreement.purpose, purpose);
    assert_eq!(agreement.revision, 2);
    assert!(agreement.cancellation_requested && agreement.recovery_required);
    assert_eq!(agreement.chain_observation, HistoricalObservation::Unknown);
    let events = history
        .events("history-reader", "historical-agreement", 0, 1, &gate)
        .unwrap();
    assert_eq!(events.events.len(), 1);
    assert_eq!(events.events[0].change, HistoricalChange::Created);
    let next = history
        .events(
            "history-reader",
            "historical-agreement",
            events.next_after_sequence,
            100,
            &gate,
        )
        .unwrap();
    assert_eq!(next.events.len(), 1);
    assert_eq!(next.events[0].agreement_revision, 2);
    assert!(!serde_json::to_string(&next).unwrap().contains("PRIVATE_"));
    assert!(
        history
            .agreement("owner", "historical-agreement", &gate)
            .is_err()
    );
    drop(history);
    // Original live source retains operation identity and state; historical reads
    // did not mutate it or synthesize replacement events/authority.
    let original = Engine::from_store(Store::open_encrypted(&source_path, &key).unwrap());
    assert_eq!(
        original
            .get(&owner, "historical-agreement")
            .unwrap()
            .revision,
        2
    );
    assert_eq!(
        original.operation(&owner, &created.operation_id).unwrap()["operation_id"],
        created.operation_id
    );
    assert!(Store::open_encrypted(&restored_path, &key).is_err());
}
