//! Immutable metadata/reader/archive qualification, not live publication.
//! Exact never-funded synthetic signed Claim, Reserve and Consume history is
//! backed up through both generation shapes. Native audit rows remain modeled
//! inert historical records; no NativeDecision or live admission is created.
use super::*;
use crate::recovery_generation::{
    layered::PendingLayeredGeneration, transport_capsule_fixtures as fixtures,
};

fn assert_complete(capsule: &VerifiedGenerationCapsule, expected_nodes: usize) {
    let complete = fixtures::evidence();
    let uncertain = fixtures::evidence_without_local_success();
    let expected_charge = complete
        .complete_history
        .conservative_debit_zatoshis()
        .unwrap();
    assert!(expected_charge > 0);
    let expected_obligations = complete
        .complete_history
        .conservative_obligations()
        .unwrap();
    assert!(!expected_obligations.is_empty());
    let exact_authority = serde_json::to_vec(&complete.complete_history.construction).unwrap();
    let exact_original =
        serde_json::to_vec(&complete.complete_history.financial_origins_v2).unwrap();
    let expected_fences = complete
        .complete_history
        .construction
        .observed_snapshot()
        .transport_fences
        .clone();
    assert!(expected_fences.is_some());
    assert!(
        !complete
            .complete_history
            .construction
            .transport
            .credentials
            .is_empty()
    );
    assert!(
        !complete
            .complete_history
            .construction
            .transport
            .reservations
            .is_empty()
    );
    assert!(
        !complete
            .complete_history
            .construction
            .transport
            .consumptions
            .is_empty()
    );
    let rows = fixtures::retained_archive_evidence(capsule).unwrap();
    assert_eq!(rows.len(), expected_nodes);
    let mut full_count = 0;
    let mut uncertain_count = 0;
    for (_, rows) in rows {
        assert_eq!(rows.len(), 1);
        let history = &rows[0].complete_history;
        assert_eq!(
            serde_json::to_vec(&history.construction).unwrap(),
            exact_authority,
            "complete signed transport Claim, old-key fence, Reserve and Consume stay exact"
        );
        assert_eq!(
            serde_json::to_vec(&history.financial_origins_v2).unwrap(),
            exact_original,
            "the entire older financial origin and identity history stays exact"
        );
        assert_eq!(
            history.conservative_debit_zatoshis().unwrap(),
            expected_charge
        );
        assert_eq!(
            history.conservative_obligations().unwrap(),
            expected_obligations
        );
        assert!(history.construction.observed_snapshot().transport_fences == expected_fences);
        if history == &complete.complete_history {
            full_count += 1;
            let missing = history.missing_local_native_phases().unwrap();
            assert!(missing.transport.is_empty());
        } else {
            assert!(history == &uncertain.complete_history);
            uncertain_count += 1;
            let missing = history.missing_local_native_phases().unwrap();
            assert_eq!(missing.transport.len(), 1);
            let transport = &missing.transport[0];
            assert!(!transport.missing_read_admission && !transport.missing_reentered);
            assert!(!transport.missing_reserved && transport.missing_consumed);
            assert!(transport.authority_consumed_digest.is_some());
        }
        assert!(history.require_financial_activation_supported().is_err());
    }
    assert_eq!(full_count, 1);
    assert_eq!(uncertain_count, expected_nodes - 1);
    // The immutable identity reader must inspect every ancestor before refusing
    // financial use, including a charged origin with no local success receipt.
    let inherited = capsule.inherited_manual_identity_coverage().unwrap();
    let genesis = complete
        .complete_history
        .financial_origins_v2
        .account_use
        .genesis
        .as_ref()
        .unwrap();
    let candidate = wholepact_core::manual_enrollment::ManualAccountIdentity {
        account_id: genesis.identity.account_id.clone(),
        full_viewing_key_digest: genesis.identity.full_viewing_key_digest.clone(),
        network_profile_id: genesis.identity.network_profile_id.clone(),
        derivation_domain: genesis.identity.derivation_domain.clone(),
    };
    assert!(matches!(
        inherited.require_distinct(
            &candidate,
            &std::collections::BTreeSet::from([candidate.account_id.clone()])
        ),
        Err(Error::RecoveryFinancialUnsupported)
    ));
    // Even an otherwise distinct identity cannot turn readable V5 ancestry
    // into financial eligibility. A duplicate-identity check alone is weaker.
    let fresh = wholepact_core::manual_enrollment::ManualAccountIdentity {
        account_id: "fa".repeat(32),
        full_viewing_key_digest: "fb".repeat(32),
        network_profile_id: candidate.network_profile_id.clone(),
        derivation_domain: candidate.derivation_domain.clone(),
    };
    assert!(fresh.account_id != candidate.account_id);
    assert!(fresh.full_viewing_key_digest != candidate.full_viewing_key_digest);
    assert!(matches!(
        inherited.require_distinct(
            &fresh,
            &std::collections::BTreeSet::from([fresh.account_id.clone()])
        ),
        Err(Error::RecoveryFinancialUnsupported)
    ));
}
fn assert_financial_reopen_denied(profile: &Path, expected_plan_version: u16) {
    let before = fingerprint(profile);
    let directory = Directory::open(profile).unwrap();
    let secrets = Secrets::open(&directory.read("profile.vault", 1024).unwrap(), PASSWORD).unwrap();
    let plan_version =
        crate::recovery_generation::archive_history::source_plan_version(&directory, &secrets)
            .unwrap();
    assert_eq!(plan_version, expected_plan_version);
    let rejected = crate::recovery_generation::open_committed(&directory, &secrets);
    // Both explicit families refuse before writable Store access. Preserve the
    // established ordinary Unsupported versus layered financial-refusal errors.
    match plan_version {
        1 => assert!(matches!(rejected, Err(Error::Unsupported))),
        2 => assert!(matches!(rejected, Err(Error::RecoveryFinancialUnsupported))),
        _ => panic!("unexpected synthetic plan family"),
    }
    assert!(matches!(
        crate::recovery_generation::manual_target::ManualCommittedTarget::open(
            &directory, &secrets
        ),
        Err(Error::RecoveryFinancialUnsupported)
    ));
    assert!(before == fingerprint(profile));
}

#[test]
fn nonempty_v5_inert_metadata_backup_restore_layered_rebackup_preserves_transport_history() {
    let (temp, original_backup, original_restore, g1) =
        crate::recovery_inventory::tests::transport_archive_fixture();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let original_before = fingerprint(&original_backup);
    let restored_before = fingerprint(&original_restore);
    assert_financial_reopen_denied(&g1, 1);
    let g1_before = fingerprint(&g1);
    let expected = fixtures::evidence();
    let accounts = std::collections::BTreeSet::from([expected.request.account_id]);
    let quarantine1 = root.join("v5-quarantine-1");
    let restored = synthetic_capsule_quarantine_for_accounts(
        &g1,
        &root.join("v5-backup-1"),
        &quarantine1,
        184,
        &accounts,
    );
    assert_complete(restored.capsule(), 1);
    let quarantine_before = fingerprint(&quarantine1);
    let g2 = root.join("v5-generation-2");
    let pending = PendingLayeredGeneration::create(restored, &g2, PASSWORD).unwrap();
    // This is an independent modeled partial-history view, not a chronological
    // signer-journal transition from G1: G1's surviving rows cannot disappear.
    // Its actual signed authority charge stays exact, while absent local success
    // receipts are preserved as uncertainty. No missing receipt is fabricated.
    let mut current = fixtures::evidence_without_local_success();
    current.request.generation_id = pending.generation_id().into();
    current.request.inventory_digest = pending.inventory_digest().into();
    pending
        .construct_synthetic_transport_archive()
        .unwrap()
        .prepare_publication_v5(vec![current])
        .unwrap()
        .materialize_synthetic_archive_fixture()
        .unwrap();
    assert_financial_reopen_denied(&g2, 2);
    let g2_before = fingerprint(&g2);
    let quarantine2 = root.join("v5-quarantine-2");
    let restored2 = synthetic_capsule_quarantine_for_accounts(
        &g2,
        &root.join("v5-backup-2"),
        &quarantine2,
        186,
        &accounts,
    );
    assert_complete(restored2.capsule(), 2);
    drop(restored2);
    let reopened =
        crate::generation_restore::RestoredGenerationCapsule::open(&quarantine2, PASSWORD).unwrap();
    assert_complete(reopened.capsule(), 2);
    drop(reopened);
    assert!(original_before == fingerprint(&original_backup));
    assert!(restored_before == fingerprint(&original_restore));
    assert!(g1_before == fingerprint(&g1));
    assert!(quarantine_before == fingerprint(&quarantine1));
    assert!(g2_before == fingerprint(&g2));
    let copied_capsule = quarantine2.join(CAPSULE);
    let mut damaged = std::fs::read(&copied_capsule).unwrap();
    damaged[0] ^= 1;
    std::fs::write(&copied_capsule, damaged).unwrap();
    assert!(
        crate::generation_restore::RestoredGenerationCapsule::open(&quarantine2, PASSWORD).is_err()
    );
    assert!(g2_before == fingerprint(&g2));
    assert!(wholepact_signer::authority_bridge::host_recovery_ipc::v5::require_construction_transport_recovery_endpoint().is_err());
}
