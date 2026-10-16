//! Synthetic encrypted generation tests. No native approval, signer, witness,
//! network settlement, external disclosure, or financial qualification.
use super::*;
use std::{collections::BTreeMap, os::unix::fs::PermissionsExt};
use wholepact_storage_security::{
    DatabaseKey,
    bundle::{self, *},
};
use wholepact_store::authority::{ExposureState, ReleaseIntent};

struct Gate;
impl BundleLease for Gate {
    fn check_current(&self) -> std::result::Result<(), BundleError> {
        Ok(())
    }
    fn checkpoint_id(&self) -> &str {
        "synthetic-coordination-generation"
    }
}
impl BundleAuthority for Gate {
    fn acquire<'a>(
        &'a self,
        scope: &BundleScope<'_>,
    ) -> std::result::Result<Box<dyn BundleLease + 'a>, BundleError> {
        if scope.principal_id != "synthetic-admin" || scope.profile_id != "synthetic-profile" {
            return Err(BundleError::Permission);
        }
        Ok(Box::new(Gate))
    }
}
fn key(value: u8) -> DatabaseKey {
    DatabaseKey::from_bytes([value; 32])
}
fn draft(id: &str) -> AgreementDraft {
    let mut value: AgreementDraft = serde_json::from_str(include_str!(
        "../../../wholepact-core/tests/fixtures/agreement.json"
    ))
    .unwrap();
    value.agreement_id = id.into();
    value.obligation_id = format!("obligation-{id}");
    value
}
fn release(id: &str) -> ReleaseIntent {
    ReleaseIntent {
        authorization_id: id.into(),
        account_id: "synthetic-account".into(),
        writer_epoch: 1,
        obligation_id: format!("obligation-{id}"),
        proposal_id: format!("proposal-{id}"),
        manifest_digest: "a".repeat(64),
        effects_digest: "b".repeat(64),
        artifact_digest: "c".repeat(64),
        maximum_debit: "10".into(),
        input_ids: vec![format!("input-{id}")],
        aggregate_budget_limit: "100".into(),
    }
}
fn coverage() -> Coverage {
    Coverage {
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
    }
}
fn source(engine: &Engine, dir: &Path) -> VerifiedRecoveryComponent {
    let adapter = wholepact_store::bundle::CoordinationBundleAdapter::new(&engine.store).unwrap();
    let sources = [RegisteredJournal::new("coordination", &adapter).unwrap()];
    let archive = dir.join("backup.sqlite");
    let restored = dir.join("restored.sqlite");
    bundle::snapshot(SnapshotRequest {
        principal_id: "synthetic-admin",
        profile_id: "synthetic-profile",
        coverage: coverage(),
        sources: &sources,
        destination: &archive,
        key: &key(172),
        authority: &Gate,
    })
    .unwrap();
    bundle::restore(RestoreRequest {
        principal_id: "synthetic-admin",
        profile_id: "synthetic-profile",
        archive: &archive,
        key: &key(172),
        targets: &[RestoreTarget {
            component_id: "coordination",
            template: wholepact_store::bundle::coordination_template(),
            destination: &restored,
            key: &key(173),
        }],
        authority: &Gate,
    })
    .unwrap();
    VerifiedRecoveryComponent::open(
        bundle::history::HistoryOpenRequest {
            archive: &archive,
            archive_key: &key(172),
            restored_component: &restored,
            restored_key: &key(173),
            component_id: "coordination",
        },
        wholepact_store::bundle::coordination_template(),
    )
    .unwrap()
}
#[test]
fn coordination_generation_preserves_history_and_admits_only_fresh_operations() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let owner = Access {
        include_owned_agreements: true,
        principal_id: "synthetic-owner".into(),
        ..Access::default()
    };
    let engine = Engine::from_store(
        Store::create_encrypted(dir.path().join("source.sqlite"), &key(171)).unwrap(),
    );
    let original = engine
        .create(&owner, "synthetic-original-key", draft("historical"))
        .unwrap();
    engine
        .store
        .initialize_authority_account("synthetic-account", 1)
        .unwrap();
    for (id, state) in [
        ("expired", ExposureState::ExpiredObserved),
        ("consumed", ExposureState::Consumed),
    ] {
        engine
            .store
            .record_authorization_release_intent(&release(id))
            .unwrap();
        engine
            .store
            .record_observed_resolution(id, state, "synthetic-old-chain")
            .unwrap();
    }
    engine
        .store
        .record_effect_intent(
            "old-effect",
            "submit",
            "historical",
            &"d".repeat(64),
            "old-exact-bytes",
        )
        .unwrap();
    let old_destination = engine.store.settlement_destination().unwrap();
    let source = source(&engine, dir.path());
    let inventory = inspect_coordination_recovery(&source).unwrap();
    assert!(inventory.accounts().contains("synthetic-account"));
    assert!(inventory.obligations().contains("obligation-historical"));
    assert_eq!(inventory.store_inventory().historical_agreements().len(), 2);
    let binding =
        bundle::recovery::generation::GenerationBinding::new(&"e".repeat(64), inventory.digest())
            .unwrap();
    let destination = dir.path().join("successor.sqlite");
    Store::reconstruct_recovered_generation(&source, &destination, &key(174), &binding).unwrap();
    assert!(Store::open_encrypted(&destination, &key(174)).is_err());
    let store =
        Store::open_recovered_generation(&destination, &key(174), &binding, source.provenance())
            .unwrap();
    assert!(store.recovery_state().unwrap().recovery_required);
    assert!(!store.runtime_recovery_required().unwrap());
    // Existing protected G1 opener above supplies the actual Store; this helper
    // only adds denial assertions and creates no signer/admission capability.
    crate::financial_preflight::assert_g1_financial_denial(
        &store,
        &owner.principal_id,
        &original.operation_id,
    );
    assert_eq!(store.outstanding_debit("synthetic-account").unwrap(), "10");
    assert_eq!(store.settled_debit("synthetic-account").unwrap(), "10");
    assert_eq!(
        store.exposure("consumed").unwrap().unwrap().state,
        ExposureState::Consumed
    );
    assert_ne!(store.settlement_destination().unwrap(), old_destination);
    assert!(
        store
            .record_observed_resolution(
                "expired",
                ExposureState::ExpiredObserved,
                "synthetic-new-chain"
            )
            .is_err()
    );
    assert!(store.get_operation(&original.operation_id).is_err());
    assert!(
        store
            .record_effect_intent(
                "old-effect",
                "submit",
                "historical",
                &"d".repeat(64),
                "old-exact-bytes"
            )
            .is_err()
    );
    let witness_only = BTreeSet::from(["witness-only-obligation".to_owned()]);
    let wrong_binding =
        bundle::recovery::generation::GenerationBinding::new(&"f".repeat(64), inventory.digest())
            .unwrap();
    assert!(
        store
            .add_recovery_obligation_fences(&wrong_binding, &witness_only)
            .is_err()
    );
    store
        .add_recovery_obligation_fences(&binding, &witness_only)
        .unwrap();
    store
        .add_recovery_obligation_fences(&binding, &witness_only)
        .unwrap();
    assert!(
        store
            .settlement_obligation_requires_recovery("witness-only-obligation")
            .unwrap()
    );
    let recovered = Engine::from_store(store);
    assert!(recovered.get(&owner, "historical").is_ok());
    assert!(
        recovered
            .create(&owner, "synthetic-original-key", draft("historical"))
            .is_err()
    );
    assert!(
        recovered
            .cancel(&owner, "synthetic-cancel-key", "historical", 1)
            .is_err()
    );
    let mut same_obligation = draft("different-agreement");
    same_obligation.obligation_id = "obligation-historical".into();
    assert!(
        recovered
            .create(&owner, "synthetic-replacement-key", same_obligation)
            .is_err()
    );
    let mut witness_obligation = draft("new-agreement-for-witness-obligation");
    witness_obligation.obligation_id = "witness-only-obligation".into();
    assert!(
        recovered
            .create(&owner, "synthetic-witness-only-key", witness_obligation)
            .is_err()
    );
    let fresh = recovered
        .create(&owner, "synthetic-fresh-key", draft("fresh"))
        .unwrap();
    assert_eq!(fresh.agreement.agreement.agreement_id, "fresh");
    // Synthetic storage callback alone is not qualified chain authority. This
    // only checks that the fresh destination can atomically consume a new exact
    // signer release while refusing the restored obligation.
    let snapshot = recovered.store.list_agreements().unwrap();
    assert!(
        recovered
            .store
            .consume_exact_settlement_release(
                &release("consumed"),
                "synthetic-evidence",
                &json!({}),
                &snapshot,
                &[],
                &|| Ok(())
            )
            .is_err()
    );
    recovered
        .store
        .consume_exact_settlement_release(
            &release("fresh-release"),
            "synthetic-evidence",
            &json!({}),
            &snapshot,
            &[],
            &|| Ok(()),
        )
        .unwrap();
    assert_eq!(
        recovered.store.settled_debit("synthetic-account").unwrap(),
        "20"
    );
    drop(recovered);
    Store::open_recovered_generation(&destination, &key(174), &binding, source.provenance())
        .unwrap();
    // An exact retry preserves the completed generation rather than reconstructing
    // over its new live operations.
    Store::reconstruct_recovered_generation(&source, &destination, &key(174), &binding).unwrap();
}

#[test]
fn coordination_generation_rejects_unknown_aggregate_schema() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let engine = Engine::from_store(
        Store::create_encrypted(dir.path().join("source.sqlite"), &key(171)).unwrap(),
    );
    let context =
        CommandContext::for_request("synthetic-owner", "synthetic-unknown-key", &json!({}))
            .unwrap();
    engine
        .store
        .commit_record(
            &context,
            "unknown_future_schema",
            "unknown",
            None,
            json!({"account_id":"hidden-account"}),
            "unknown.created",
        )
        .unwrap();
    let source = source(&engine, dir.path());
    assert!(inspect_coordination_recovery(&source).is_err());
}

#[test]
fn coordination_generation_rejects_missing_defaulted_history_fields() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let owner = Access {
        include_owned_agreements: true,
        principal_id: "synthetic-owner".into(),
        ..Access::default()
    };
    let engine = Engine::from_store(
        Store::create_encrypted(dir.path().join("source.sqlite"), &key(171)).unwrap(),
    );
    engine
        .create(&owner, "synthetic-original-key", draft("historical"))
        .unwrap();
    let mut record = engine.store.get_agreement("historical").unwrap().unwrap();
    // Ordinary backward-compatible decoding supplies this default. Recovery
    // cannot treat its absence as proof that private history never existed.
    record
        .payload
        .as_object_mut()
        .unwrap()
        .remove("participant_records");
    let command =
        CommandContext::for_request("synthetic-owner", "synthetic-corruption-key", &json!({}))
            .unwrap();
    engine
        .store
        .update_agreement(
            &command,
            "historical",
            1,
            record.payload,
            "synthetic_corruption",
        )
        .unwrap();
    let source = source(&engine, dir.path());
    assert!(inspect_coordination_recovery(&source).is_err());
}

#[cfg(feature = "manual-admission")]
#[path = "tests/roster_disclosure.rs"]
mod roster_disclosure;

#[cfg(all(feature = "manual-admission", feature = "local-proof-jobs", target_os = "linux"))]
#[path = "tests/original_construction_inspection.rs"]
mod original_construction_inspection;
