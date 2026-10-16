//! Actual encrypted capsule storage composition using a genuinely signed
//! synthetic authority archive and explicitly modeled local native-audit rows.
//! Saved records never become native admissions or a publication authority.
use super::*;
use crate::recovery_generation::{
    common_context_capsule_fixtures as fixtures, layered::PendingLayeredGeneration,
};

fn assert_complete(capsule: &VerifiedGenerationCapsule, expected_nodes: usize) {
    let complete = fixtures::evidence();
    let uncertain = fixtures::evidence_without_local_success();
    let expected_charge = complete
        .complete_history
        .conservative_debit_zatoshis()
        .unwrap();
    assert!(expected_charge > 0);
    let exact_authority = serde_json::to_vec(&complete.complete_history.construction).unwrap();
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
            "every signed approval, Reserve, Consume and original stays exact"
        );
        assert_eq!(
            history.conservative_debit_zatoshis().unwrap(),
            expected_charge
        );
        if history == &complete.complete_history {
            full_count += 1;
            assert!(history.missing_local_native_phases().unwrap().is_empty());
        } else {
            assert!(history == &uncertain.complete_history);
            uncertain_count += 1;
            let missing = history.missing_local_native_phases().unwrap();
            assert_eq!(missing.len(), 1);
            assert!(!missing[0].missing_read_admission);
            assert!(missing[0].missing_reserved && missing[0].missing_consumed);
            assert!(missing[0].authority_consumed_digest.is_some());
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
}
fn assert_financial_reopen_denied(profile: &Path) {
    let before = fingerprint(profile);
    let directory = Directory::open(profile).unwrap();
    let secrets = Secrets::open(&directory.read("profile.vault", 1024).unwrap(), PASSWORD).unwrap();
    assert!(matches!(
        crate::recovery_generation::open_committed(&directory, &secrets),
        Err(Error::RecoveryFinancialUnsupported)
    ));
    assert!(before == fingerprint(profile));
}

#[test]
fn nonempty_v4_capsule_capture_restore_and_recursive_rebackup_preserve_exact_uncertainty() {
    let (temp, original_backup, original_restore, g1) =
        crate::recovery_inventory::tests::common_context_archive_fixture();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let original_before = fingerprint(&original_backup);
    let restored_before = fingerprint(&original_restore);
    assert_financial_reopen_denied(&g1);
    let g1_before = fingerprint(&g1);
    let expected = fixtures::evidence();
    let accounts = std::collections::BTreeSet::from([expected.request.account_id]);
    let quarantine1 = root.join("v4-quarantine-1");
    let restored = synthetic_capsule_quarantine_for_accounts(
        &g1,
        &root.join("v4-backup-1"),
        &quarantine1,
        184,
        &accounts,
    );
    assert_complete(restored.capsule(), 1);
    let quarantine_before = fingerprint(&quarantine1);
    let g2 = root.join("v4-generation-2");
    let pending = PendingLayeredGeneration::create(restored, &g2, PASSWORD).unwrap();
    // This is an independent modeled partial-history view, not a chronological
    // signer-journal transition from G1: G1's surviving rows cannot disappear.
    // Its actual signed authority charge stays exact, while absent local success
    // receipts are preserved as uncertainty. No missing receipt is fabricated.
    let mut current = fixtures::evidence_without_local_success();
    current.request.generation_id = pending.generation_id().into();
    current.request.inventory_digest = pending.inventory_digest().into();
    pending
        .construct_synthetic_common_context_archive()
        .unwrap()
        .prepare_publication_v4(vec![current])
        .unwrap()
        .materialize_synthetic_archive_fixture()
        .unwrap();
    assert_financial_reopen_denied(&g2);
    let g2_before = fingerprint(&g2);
    let quarantine2 = root.join("v4-quarantine-2");
    let restored2 = synthetic_capsule_quarantine_for_accounts(
        &g2,
        &root.join("v4-backup-2"),
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
    assert!(wholepact_signer::authority_bridge::host_recovery_ipc::v4::require_common_context_recovery_endpoint().is_err());
}
