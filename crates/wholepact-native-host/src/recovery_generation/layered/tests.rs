//! Synthetic recursive native storage qualification only. No attended terminal,
//! signer/witness admission, proof, listener, network or financial effect occurs.
use super::*;
use crate::{
    generation_backup::tests::synthetic_capsule_quarantine,
    recovery_inventory::tests::{PASSWORD, published_empty_fixture},
};
use std::{
    collections::BTreeMap,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
use wholepact_core::agreement::AgreementDraft;
use wholepact_engine::{Access, Engine};
use wholepact_storage_security::bundle::recovery::RecoveryCell;

type Fingerprint = BTreeMap<PathBuf, (Vec<u8>, u32, u64, u64, i64, i64)>;
fn fingerprint(root: &Path) -> Fingerprint {
    let mut result = BTreeMap::new();
    let mut pending = vec![root.to_owned()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            assert!(!metadata.file_type().is_symlink());
            let bytes = if metadata.is_dir() {
                pending.push(path.clone());
                Vec::new()
            } else {
                std::fs::read(&path).unwrap()
            };
            result.insert(
                path.strip_prefix(root).unwrap().into(),
                (
                    bytes,
                    metadata.mode(),
                    metadata.dev(),
                    metadata.ino(),
                    metadata.mtime(),
                    metadata.mtime_nsec(),
                ),
            );
        }
    }
    result
}
fn draft(id: &str) -> AgreementDraft {
    let mut draft: AgreementDraft = serde_json::from_str(include_str!(
        "../../../../wholepact-core/tests/fixtures/agreement.json"
    ))
    .unwrap();
    draft.agreement_id = id.into();
    draft.obligation_id = format!("obligation-{id}");
    draft
}
fn access() -> Access {
    Access {
        include_owned_agreements: true,
        principal_id: "synthetic-layer-owner".into(),
        agreement_ids: BTreeSet::new(),
        all_agreements: true,
    }
}
fn staged_store(directory: &Directory, secrets: &Secrets) -> wholepact_store::Store {
    match super::super::archive_history::source_plan_version(directory, secrets).unwrap() {
        1 => super::super::open_committed(directory, secrets).unwrap(),
        2 => super::super::open_committed(directory, secrets).unwrap(),
        _ => panic!("unsupported synthetic plan"),
    }
}

fn add_current_data(profile: &Path, id: &str, tag: u8) -> (String, String) {
    let directory = Directory::open(profile).unwrap();
    let secrets = Secrets::open(&directory.read("profile.vault", 1024).unwrap(), PASSWORD).unwrap();
    let store = staged_store(&directory, &secrets);
    let destination = store.settlement_destination().unwrap();
    let engine = Engine::from_store(store);
    engine
        .create(&access(), &format!("create-{id}"), draft(id))
        .unwrap();
    drop(engine);
    let store = staged_store(&directory, &secrets);
    store
        .record_effect_intent(
            &format!("effect-{id}"),
            "synthetic-local-unknown",
            id,
            &"a".repeat(64),
            &format!("synthetic-retained:{id}"),
        )
        .unwrap();
    drop(store);
    // Opaque synthetic transport history is retained as bytes. It is never
    // decoded as an authenticated message, delivered or promoted to a worker.
    let inbox = wholepact_storage_security::open_encrypted_quiescent(
        directory.path("inbox.sqlite").unwrap(),
        &secrets.key(1).unwrap(),
    )
    .unwrap();
    inbox
        .connection()
        .execute(
            "INSERT INTO receipts VALUES(?1,1,?2,?3,NULL,?4,?5)",
            (
                format!("{tag:02x}").repeat(32),
                "b".repeat(64),
                "c".repeat(64),
                "d".repeat(64),
                format!("synthetic-opaque-{id}").into_bytes(),
            ),
        )
        .unwrap();
    drop(inbox);
    (destination, secrets.profile())
}
fn assert_fresh_queues(profile: &Path) {
    let directory = Directory::open(profile).unwrap();
    let secrets = Secrets::open(&directory.read("profile.vault", 1024).unwrap(), PASSWORD).unwrap();
    super::super::verify_auxiliaries(&directory, &secrets, true).unwrap();
}
fn assert_history(profile: &Path, ids: &[&str]) -> String {
    let directory = Directory::open(profile).unwrap();
    let secrets = Secrets::open(&directory.read("profile.vault", 1024).unwrap(), PASSWORD).unwrap();
    assert!(secrets.generation_plan_digest().is_some());
    assert!(
        wholepact_store::Store::open_encrypted(
            directory.path("coordination.sqlite").unwrap(),
            &secrets.key(0).unwrap()
        )
        .is_err()
    );
    let store = staged_store(&directory, &secrets);
    assert!(store.recovery_state().unwrap().recovery_required);
    let destination = store.settlement_destination().unwrap();
    for id in ids {
        assert!(
            store
                .recovery_record_is_historical("agreement", id)
                .unwrap()
        );
        assert!(
            store
                .settlement_obligation_requires_recovery(&format!("obligation-{id}"))
                .unwrap()
        );
        let effect = store
            .effect_intent(&format!("effect-{id}"))
            .unwrap()
            .unwrap();
        assert_eq!(effect.status, "outcome_unknown");
        assert!(
            store
                .record_effect_intent(
                    &format!("effect-{id}"),
                    "synthetic-local-unknown",
                    id,
                    &"a".repeat(64),
                    &format!("synthetic-retained:{id}")
                )
                .is_err()
        );
    }
    let engine = Engine::from_store(store);
    for id in ids {
        assert_eq!(
            engine
                .create(&access(), &format!("create-{id}"), draft(id))
                .unwrap_err()
                .code,
            "RECOVERY_REQUIRED"
        );
    }
    destination
}
fn assert_retained_inbox(capsule: &VerifiedGenerationCapsule, id: &str) {
    let source = capsule
        .root()
        .current_journals()
        .iter()
        .find(|source| source.provenance().component_id == "root-inbox")
        .unwrap();
    let receipts = source
        .tables()
        .iter()
        .find(|table| table.name() == "receipts")
        .unwrap();
    assert_eq!(receipts.rows().len(), 1);
    assert!(
        matches!(&receipts.rows()[0].cells()[6],RecoveryCell::Blob(bytes) if bytes==format!("synthetic-opaque-{id}").as_bytes())
    );
}
#[test]
fn native_layered_capsule_g1_g2_g3_preserves_ancestors_and_new_root_history() {
    let (_temp, legacy_backup, legacy_quarantine, g1) = published_empty_fixture();
    let (g1_destination, g1_profile) = add_current_data(&g1, "generation-one-agreement", 11);
    let old_backup = fingerprint(&legacy_backup);
    let old_quarantine = fingerprint(&legacy_quarantine);
    let one_before = fingerprint(&g1);
    let backup1 = g1.with_file_name("capsule-one");
    let quarantine1 = g1.with_file_name("quarantine-one");
    let source = synthetic_capsule_quarantine(&g1, &backup1, &quarantine1, 201);
    assert_eq!(source.capsule().histories().len(), 1);
    assert_retained_inbox(source.capsule(), "generation-one-agreement");
    let parent_manifest = source.capsule().manifest_digest().to_owned();
    let old_parent_node = source
        .capsule()
        .archive()
        .node(&parent_manifest)
        .unwrap()
        .clone();
    let quarantine_before = fingerprint(&quarantine1);
    let backup_before = fingerprint(&backup1);
    let g2 = g1.with_file_name("generation-two");
    let pending = PendingLayeredGeneration::create(source, &g2, PASSWORD).unwrap();
    assert_ne!(pending.plan.successor_profile, g1_profile);
    assert_eq!(pending.plan.parent_manifest_digest, parent_manifest);
    assert!(Directory::open(&quarantine1).is_err());
    pending
        .construct_synthetic_storage()
        .unwrap()
        .prepare_publication(vec![])
        .unwrap()
        .publish_synthetic_empty_accounts()
        .unwrap();
    assert_fresh_queues(&g2);
    let g2_destination = assert_history(&g2, &["generation-one-agreement"]);
    assert_ne!(g1_destination, g2_destination);
    let (_, g2_profile) = add_current_data(&g2, "generation-two-agreement", 12);
    let two_before = fingerprint(&g2);
    let backup2 = g1.with_file_name("capsule-two");
    let quarantine2 = g1.with_file_name("quarantine-two");
    let source = synthetic_capsule_quarantine(&g2, &backup2, &quarantine2, 211);
    assert_eq!(source.capsule().histories().len(), 2);
    assert_retained_inbox(source.capsule(), "generation-two-agreement");
    assert!(source.capsule().archive().node(&parent_manifest).unwrap() == &old_parent_node);
    assert!(source.capsule().histories().contains_key(&parent_manifest));
    let g3 = g1.with_file_name("generation-three");
    let pending = PendingLayeredGeneration::create(source, &g3, PASSWORD).unwrap();
    assert_ne!(pending.plan.successor_profile, g2_profile);
    assert_ne!(pending.plan.successor_profile, g1_profile);
    pending
        .construct_synthetic_storage()
        .unwrap()
        .prepare_publication(vec![])
        .unwrap()
        .publish_synthetic_empty_accounts()
        .unwrap();
    assert_fresh_queues(&g3);
    let g3_destination = assert_history(
        &g3,
        &["generation-one-agreement", "generation-two-agreement"],
    );
    assert_ne!(g3_destination, g2_destination);
    assert_ne!(g3_destination, g1_destination);
    assert_eq!(old_backup, fingerprint(&legacy_backup));
    assert_eq!(old_quarantine, fingerprint(&legacy_quarantine));
    assert_eq!(one_before, fingerprint(&g1));
    assert_eq!(two_before, fingerprint(&g2));
    assert_eq!(quarantine_before, fingerprint(&quarantine1));
    assert_eq!(backup_before, fingerprint(&backup1));
}
#[test]
fn native_layered_pending_exact_retry_rejects_changed_target_key_and_partial_capsule() {
    let (_temp, _legacy_backup, _legacy_quarantine, g1) = published_empty_fixture();
    let backup = g1.with_file_name("retry-capsule");
    let quarantine = g1.with_file_name("retry-quarantine");
    let source = synthetic_capsule_quarantine(&g1, &backup, &quarantine, 221);
    let source_before = fingerprint(&quarantine);
    let target = g1.with_file_name("retry-generation");
    let pending = PendingLayeredGeneration::create(source, &target, PASSWORD).unwrap();
    let generation = pending.generation_id().to_owned();
    let plan_digest = pending.plan_digest.clone();
    // Authenticated schema-empty auxiliary interruption is the sole supported
    // initialization fallback; its key/path remain committed in this exact plan.
    drop(
        wholepact_storage_security::create_encrypted(
            pending.directory.path("inbox.sqlite").unwrap(),
            &pending.secrets.key(1).unwrap(),
        )
        .unwrap(),
    );
    drop(pending);
    let saved_key = std::fs::read(target.join("generation.keys")).unwrap();
    let mut wrong_key = saved_key.clone();
    *wrong_key.last_mut().unwrap() ^= 1;
    {
        let directory = Directory::open(&target).unwrap();
        directory
            .replace_private("generation.keys", &wrong_key)
            .unwrap();
    }
    let target_before = fingerprint(&target);
    assert!(
        PendingLayeredGeneration::resume(
            RestoredGenerationCapsule::open(&quarantine, PASSWORD).unwrap(),
            &target,
            PASSWORD
        )
        .is_err()
    );
    assert_eq!(target_before, fingerprint(&target));
    {
        let directory = Directory::open(&target).unwrap();
        directory
            .replace_private("generation.keys", &saved_key)
            .unwrap();
    }
    let moved = g1.with_file_name("moved-pending-generation");
    std::fs::rename(&target, &moved).unwrap();
    let moved_before = fingerprint(&moved);
    assert!(
        PendingLayeredGeneration::resume(
            RestoredGenerationCapsule::open(&quarantine, PASSWORD).unwrap(),
            &moved,
            PASSWORD
        )
        .is_err()
    );
    assert_eq!(moved_before, fingerprint(&moved));
    std::fs::rename(&moved, &target).unwrap();
    let pending = PendingLayeredGeneration::resume(
        RestoredGenerationCapsule::open(&quarantine, PASSWORD).unwrap(),
        &target,
        PASSWORD,
    )
    .unwrap();
    assert_eq!(pending.generation_id(), generation);
    assert_eq!(pending.plan_digest, plan_digest);
    let constructed = pending.construct_synthetic_storage().unwrap();
    let capsule_bytes = constructed
        .pending
        .directory
        .read(PARENT_CAPSULE, 512 * 1024 * 1024)
        .unwrap();
    let destination = {
        let store = wholepact_store::Store::open_recovered_generation(
            &constructed
                .pending
                .directory
                .path("coordination.sqlite")
                .unwrap(),
            &constructed.pending.secrets.key(0).unwrap(),
            &constructed.pending.binding().unwrap(),
            constructed
                .pending
                .source
                .capsule()
                .root()
                .current_coordination()
                .source_provenance(),
        )
        .unwrap();
        store.settlement_destination().unwrap()
    };
    drop(constructed);
    let pending = PendingLayeredGeneration::resume(
        RestoredGenerationCapsule::open(&quarantine, PASSWORD).unwrap(),
        &target,
        PASSWORD,
    )
    .unwrap();
    let constructed = pending.construct_synthetic_storage().unwrap();
    assert_eq!(
        constructed
            .pending
            .directory
            .read(PARENT_CAPSULE, 512 * 1024 * 1024)
            .unwrap(),
        capsule_bytes
    );
    let store = wholepact_store::Store::open_recovered_generation(
        &constructed
            .pending
            .directory
            .path("coordination.sqlite")
            .unwrap(),
        &constructed.pending.secrets.key(0).unwrap(),
        &constructed.pending.binding().unwrap(),
        constructed
            .pending
            .source
            .capsule()
            .root()
            .current_coordination()
            .source_provenance(),
    )
    .unwrap();
    assert_eq!(store.settlement_destination().unwrap(), destination);
    drop(store);
    constructed
        .prepare_publication(vec![])
        .unwrap()
        .publish_synthetic_empty_accounts()
        .unwrap();
    assert!(
        PendingLayeredGeneration::resume(
            RestoredGenerationCapsule::open(&quarantine, PASSWORD).unwrap(),
            &target,
            PASSWORD
        )
        .is_err()
    );
    assert_eq!(source_before, fingerprint(&quarantine));
    // A separate partial target is retained exactly rather than erased/rekeyed.
    let partial = g1.with_file_name("partial-capsule-generation");
    let pending = PendingLayeredGeneration::create(
        RestoredGenerationCapsule::open(&quarantine, PASSWORD).unwrap(),
        &partial,
        PASSWORD,
    )
    .unwrap();
    pending
        .directory
        .write_new(
            PARENT_CAPSULE,
            b"synthetic-invalid-partial-encrypted-capsule",
        )
        .unwrap();
    let partial_before = fingerprint(&partial);
    assert!(pending.construct_synthetic_storage().is_err());
    assert_eq!(partial_before, fingerprint(&partial));
    assert_eq!(source_before, fingerprint(&quarantine));
}

#[test]
fn native_layered_saved_audit_never_replaces_required_live_publication_admission() {
    use wholepact_signer::authority_bridge::host_recovery_ipc::{
        HostRecoveryContinuityEvidence, HostRecoveryContinuityRequest,
    };
    let (_temp, _, _, g1) = published_empty_fixture();
    let source = synthetic_capsule_quarantine(
        &g1,
        &g1.with_file_name("audit-only-backup"),
        &g1.with_file_name("audit-only-quarantine"),
        161,
    );
    let target = g1.with_file_name("audit-only-pending");
    let pending = PendingLayeredGeneration::create(source, &target, PASSWORD).unwrap();
    let constructed = pending.construct_synthetic_storage().unwrap();
    let pending = &constructed.pending;
    let request = HostRecoveryContinuityRequest {
        schema_version: 1,
        inventory_digest: pending.plan.inventory_digest.clone(),
        generation_id: pending.plan.generation_id.clone(),
        account_id: "synthetic-account".into(),
        network_profile_id: "synthetic-network".into(),
        expected_writer_epoch: 1,
        expected_witness: wholepact_authority::WitnessDisclosureDescriptor {
            endpoint: "127.0.0.1:4444".into(),
            server_name: "localhost".into(),
            witness_id: "synthetic-witness".into(),
            account_id: "synthetic-account".into(),
            network_profile_id: "synthetic-network".into(),
            policy_digest: "33".repeat(32),
            pinned_server_certificate_digest: "44".repeat(32),
        },
    };
    // Plain audit data is deliberately fabricable; it is never live evidence.
    let evidence = HostRecoveryContinuityEvidence {
        request,
        writer_certificate_digest: "55".repeat(32),
        writer_session_id: "66".repeat(32),
        writer_session_expires_at_ms: 1000,
        head: wholepact_authority::AuthorityHead {
            sequence: 2,
            digest: "77".repeat(32),
        },
        history_digest: "88".repeat(32),
        conservative_permits: vec![],
    };
    let before = fingerprint(&target);
    assert!(constructed.missing_publication_admission_fixture_for_test(evidence));
    assert_eq!(before, fingerprint(&target));
    assert!(!target.join(COMMIT).exists());
}
