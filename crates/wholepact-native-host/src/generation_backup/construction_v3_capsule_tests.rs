//! Ledger-derived construction archive storage tests. Native publication remains
//! unavailable; synthetic saved records never become opaque live admissions.
use super::*;
use crate::recovery_generation::{
    construction_capsule_fixtures as fixtures, layered::PendingLayeredGeneration,
};

fn assert_complete(capsule: &VerifiedGenerationCapsule, expected_nodes: usize) {
    let expected = fixtures::evidence();
    let rows = fixtures::retained_archive_evidence(capsule).unwrap();
    assert_eq!(rows.len(), expected_nodes);
    for (_, rows) in rows {
        assert_eq!(rows.len(), 1);
        assert!(rows[0].complete_history == expected.complete_history);
        assert_eq!(
            rows[0]
                .complete_history
                .conservative_debit_zatoshis()
                .unwrap(),
            400_012_000
        );
        assert!(
            rows[0].complete_history.construction.origins()[0]
                .consumed()
                .is_some()
        );
        assert!(
            rows[0]
                .complete_history
                .require_financial_activation_supported()
                .is_err()
        );
    }
    // This reader must retain every typed ancestor before refusing financial use.
    let inherited = capsule.inherited_manual_identity_coverage().unwrap();
    let genesis = expected
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
fn nonempty_v3_capsule_capture_restore_and_recursive_retention_preserve_exact_history() {
    let (temp, original_backup, original_restore, g1) =
        crate::recovery_inventory::tests::construction_archive_fixture();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let original_before = fingerprint(&original_backup);
    let restored_before = fingerprint(&original_restore);
    assert_financial_reopen_denied(&g1);
    let g1_before = fingerprint(&g1);
    let expected = fixtures::evidence();
    let accounts = std::collections::BTreeSet::from([expected.request.account_id.clone()]);
    let quarantine1 = root.join("v3-quarantine-1");
    let restored = synthetic_capsule_quarantine_for_accounts(
        &g1,
        &root.join("v3-backup-1"),
        &quarantine1,
        180,
        &accounts,
    );
    assert_complete(restored.capsule(), 1);
    let quarantine_before = fingerprint(&quarantine1);
    let g2 = root.join("v3-generation-2");
    let pending = PendingLayeredGeneration::create(restored, &g2, PASSWORD).unwrap();
    let mut current = fixtures::evidence();
    current.request.generation_id = pending.generation_id().into();
    current.request.inventory_digest = pending.inventory_digest().into();
    pending
        .construct_synthetic_construction_archive()
        .unwrap()
        .prepare_publication_v3(vec![current])
        .unwrap()
        .materialize_synthetic_archive_fixture()
        .unwrap();
    assert_financial_reopen_denied(&g2);
    let g2_before = fingerprint(&g2);
    let restored2 = synthetic_capsule_quarantine_for_accounts(
        &g2,
        &root.join("v3-backup-2"),
        &root.join("v3-quarantine-2"),
        182,
        &accounts,
    );
    assert_complete(restored2.capsule(), 2);
    assert!(original_before == fingerprint(&original_backup));
    assert!(restored_before == fingerprint(&original_restore));
    assert!(g1_before == fingerprint(&g1));
    assert!(quarantine_before == fingerprint(&quarantine1));
    assert!(g2_before == fingerprint(&g2));
    drop(restored2);
    let copied_capsule = root.join("v3-quarantine-2").join(CAPSULE);
    let mut damaged = std::fs::read(&copied_capsule).unwrap();
    damaged[0] ^= 1;
    std::fs::write(&copied_capsule, damaged).unwrap();
    assert!(
        crate::generation_restore::RestoredGenerationCapsule::open(
            &root.join("v3-quarantine-2"),
            PASSWORD
        )
        .is_err()
    );
    assert!(g2_before == fingerprint(&g2));
}
