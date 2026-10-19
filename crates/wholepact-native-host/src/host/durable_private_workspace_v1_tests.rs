//! Isolated encrypted-file tests. These exercise integrity only, never a native
//! privacy grant, actual selected source, installed signer or financial authority.
use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

pub(super) fn fixture(
    root: &Path,
    pending_final: bool,
    commit_final: bool,
) -> (Directory, Secrets) {
    let directory = Directory::create(root).unwrap();
    let workspace_root = root.parent().unwrap().join("workspace");
    let workspace = Directory::create(&workspace_root).unwrap();
    let key = [9u8; 32];
    let metadata = wholepact_store::Store::create_encrypted(
        workspace.path(DATABASE).unwrap(),
        &DatabaseKey::from_bytes(key),
    )
    .unwrap();
    let origin = metadata
        .verify_original_encrypted_destination(&workspace.path(DATABASE).unwrap())
        .unwrap();
    let secrets = Secrets::fresh()
        .unwrap()
        .bind_successor_plan([7; 32])
        .unwrap();
    let association = Association {
        version: 1,
        purpose: PURPOSE.into(),
        dependency_id: "a".repeat(64),
        profile_id: secrets.profile(),
        generation_id: "b".repeat(64),
        inventory_digest: "c".repeat(64),
        generation_plan_digest: hex::encode([7; 32]),
        parent_coverage_digest: "e".repeat(64),
        original_financial_origin_digest: "f".repeat(64),
        host_directory_identity: directory.manual_target_identity_digest().unwrap(),
        source_store_destination_identity: "source-store".into(),
        source_digest: "1".repeat(64),
        principal_id: "owner".into(),
        agreement_id: "agreement".into(),
        obligation_id: "obligation".into(),
        reviewer_account_ids: vec!["2".repeat(64), "3".repeat(64)],
        workspace_root: workspace_root.clone(),
        database_path: workspace_root.join(DATABASE),
        retention_policy: "retain exact original".into(),
    };
    let pending = Pending {
        version: 1,
        purpose: PURPOSE.into(),
        proof: OriginalProofDescriptorV1 {
            role: "original_primary_proof_v1".into(),
            profile_owner: secrets.profile(),
            financial_root: root.parent().unwrap().join("financial"),
            financial_directory_identity: "4".repeat(64),
            basename: "proof.sqlite".into(),
            key_slot: 1,
            original_proof_origin: [5; 32],
        },
        initialization_plan: PrivateWorkspaceInitializationPlanV1 {
            version: 1,
            source_digest: association.source_digest.clone(),
            seed_key: "private-workspace-original-seed-v1".into(),
            seed_kind: "private-workspace-original-seed-v1".into(),
            created_at: "2026-10-19T00:00:00Z".into(),
            updated_at: "2026-10-19T00:00:00Z".into(),
            payload_without_marker_digest: "6".repeat(64),
        },
        association,
        database_key: key,
    };
    validate_pending(&pending, &secrets).unwrap();
    let sealed = crate::recovery_generation::seal_private_workspace_dependency_v1(
        &secrets,
        true,
        &serde_json::to_vec(&pending).unwrap(),
    )
    .unwrap();
    let mut p = PrivateWorkspaceFileV1::stage(&directory, PENDING, &sealed, MAX_REGISTRY).unwrap();
    let workspace_identity = workspace.manual_target_identity_digest().unwrap();
    let association_digest = complete_association(&pending, &workspace_identity, origin).unwrap();
    let marker = wholepact_store::private_workspace_origin_v1::PrivateWorkspaceOriginV1 {
        version: 1,
        purpose: PURPOSE.into(),
        native_association_digest: association_digest.clone(),
        source_digest: pending.association.source_digest.clone(),
        principal_id: "owner".into(),
        agreement_id: "agreement".into(),
        obligation_id: "obligation".into(),
        reviewer_account_ids: pending.association.reviewer_account_ids.clone(),
        protected_destination: workspace_root.join(DATABASE).to_str().unwrap().into(),
        retention_policy: pending.association.retention_policy.clone(),
        metadata_origin: hex::encode(origin),
    };
    let seed = PrivateWorkspaceSeedBindingV1 {
        marker_digest: marker.digest().unwrap(),
        marker,
        operation_kind: "agreement.created".into(),
        resource_id: "agreement".into(),
        command: wholepact_store::CommandContext::for_request(
            "owner",
            "private-workspace-original-seed-v1",
            &serde_json::json!({"fixture":"inert"}),
        )
        .unwrap(),
        final_seed_payload_digest: "8".repeat(64),
    };
    let committed = Committed {
        version: 1,
        pending_ciphertext_digest: p.ciphertext_digest().into(),
        pending_original_file_origin: p.origin().unwrap(),
        association_digest,
        workspace_directory_identity: workspace_identity,
        original_database_origin: origin,
        seed,
    };
    let sealed = crate::recovery_generation::seal_private_workspace_dependency_v1(
        &secrets,
        false,
        &serde_json::to_vec(&committed).unwrap(),
    )
    .unwrap();
    let mut c = PrivateWorkspaceFileV1::stage(&directory, COMMIT, &sealed, MAX_REGISTRY).unwrap();
    let anchor = workspace_anchor(&directory, &committed.association_digest, &p, &c).unwrap();
    let secrets = secrets.bind_private_workspace_v3(anchor).unwrap();
    if pending_final {
        p.publish(&directory, MAX_REGISTRY).unwrap();
    }
    if commit_final {
        c.publish(&directory, MAX_REGISTRY).unwrap();
    }
    drop((metadata, workspace, p, c));
    (directory, secrets)
}
pub(super) fn fingerprint(directory: &Directory) -> Vec<(String, u64, u64, Vec<u8>)> {
    let mut files = fs::read_dir(directory.path("profile.lock").unwrap().parent().unwrap())
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let m = entry.metadata().unwrap();
            (
                entry.file_name().to_str().unwrap().to_owned(),
                m.dev(),
                m.ino(),
                fs::read(entry.path()).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    files.sort_by(|a, b| a.0.cmp(&b.0));
    files
}
#[test]
fn exact_publication_state_table_and_no_replace_preserve_original_inodes() {
    for (p, c, accepted) in [
        (false, false, true),
        (true, false, true),
        (true, true, true),
        (false, true, false),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let (directory, secrets) = fixture(&temp.path().join("host"), p, c);
        let before = fingerprint(&directory);
        let inspected = OriginalWorkspacePublicationV1::inspect(&directory, &secrets);
        assert_eq!(inspected.is_ok(), accepted);
        if accepted {
            let mut original = inspected.unwrap();
            let po = original.pending_file.origin().unwrap();
            let co = original.commit_file.origin().unwrap();
            // Exercise only the owned-file kernel, not production publication
            // (which requires real source-derived exclusion owners and consent).
            original
                .pending_file
                .publish(&directory, MAX_REGISTRY)
                .unwrap();
            original
                .commit_file
                .publish(&directory, MAX_REGISTRY)
                .unwrap();
            let final_files = OriginalWorkspaceFilesV1::open_final(&directory, &secrets).unwrap();
            assert_eq!(po, final_files.original.pending_file.origin().unwrap());
            assert_eq!(co, final_files.original.commit_file.origin().unwrap());
            assert!(
                directory
                    .private_workspace_candidates()
                    .unwrap()
                    .iter()
                    .all(|s| s == PENDING || s == COMMIT)
            );
        } else {
            assert_eq!(fingerprint(&directory), before);
        }
    }
}
#[test]
fn mandatory_anchor_missing_sidecar_matrix_never_restores_portability() {
    for remove in [vec![PENDING], vec![COMMIT], vec![PENDING, COMMIT]] {
        let temp = tempfile::tempdir().unwrap();
        let (directory, secrets) = fixture(&temp.path().join("host"), true, true);
        for name in remove {
            fs::remove_file(directory.path(name).unwrap()).unwrap();
        }
        let before = fingerprint(&directory);
        let destination = temp.path().join("forbidden-backup");
        assert!(OriginalWorkspaceFilesV1::open_final(&directory, &secrets).is_err());
        assert!(secrets.require_portable_legacy().is_err());
        assert!(
            secrets
                .recovery(b"component-test-password", &[8; 32])
                .is_err()
        );
        assert!(crate::vault::generation_archive::source_material(&secrets).is_err());
        let terminal = Terminal::disconnected_for_test();
        assert!(
            crate::backup::Quiescent {
                directory: &directory,
                secrets: &secrets,
                terminal: &terminal
            }
            .snapshot(&destination, b"component-test-password")
            .is_err()
        );
        assert!(!destination.exists());
        assert_eq!(fingerprint(&directory), before);
    }
}
#[test]
fn copied_sidecar_identical_bytes_and_extra_or_malformed_names_refuse() {
    for name in [PENDING, COMMIT] {
        let temp = tempfile::tempdir().unwrap();
        let (directory, secrets) = fixture(&temp.path().join("host"), true, true);
        let path = directory.path(name).unwrap();
        let bytes = fs::read(&path).unwrap();
        fs::rename(&path, temp.path().join("retained-original")).unwrap();
        crate::files::write_new(&path, &bytes).unwrap();
        let before = fingerprint(&directory);
        assert!(OriginalWorkspaceFilesV1::open_final(&directory, &secrets).is_err());
        assert_eq!(fingerprint(&directory), before);
    }
    for extra in [
        "staging-durable-private-pending-v1-bad",
        "staging-durable-private-unknown",
        "durable-private.pending-v1.extra",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let (directory, secrets) = fixture(&temp.path().join("host"), true, true);
        directory.write_new(extra, b"foreign").unwrap();
        let before = fingerprint(&directory);
        assert!(OriginalWorkspaceFilesV1::open_final(&directory, &secrets).is_err());
        assert_eq!(fingerprint(&directory), before);
    }
}
#[test]
fn role_domain_tampering_permissions_and_hardlinks_refuse_without_repair() {
    for mutation in 0..4 {
        let temp = tempfile::tempdir().unwrap();
        let (directory, secrets) = fixture(&temp.path().join("host"), true, true);
        let path = directory.path(PENDING).unwrap();
        match mutation {
            0 => {
                let mut bytes = fs::read(&path).unwrap();
                bytes[40] ^= 1;
                fs::write(&path, bytes).unwrap();
            }
            1 => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            2 => fs::hard_link(&path, temp.path().join("second-link")).unwrap(),
            _ => {
                fs::rename(&path, temp.path().join("original")).unwrap();
                std::os::unix::fs::symlink(temp.path().join("original"), &path).unwrap();
            }
        }
        assert!(OriginalWorkspaceFilesV1::open_final(&directory, &secrets).is_err());
    }
    let secrets = Secrets::fresh()
        .unwrap()
        .bind_successor_plan([7; 32])
        .unwrap();
    let bytes = crate::recovery_generation::seal_private_workspace_dependency_v1(
        &secrets, true, b"pending",
    )
    .unwrap();
    assert!(
        crate::recovery_generation::unseal_private_workspace_dependency_v1(&secrets, false, &bytes)
            .is_err()
    );
    assert!(
        crate::recovery_generation::seal_private_workspace_dependency_v1(
            &secrets,
            true,
            &vec![0; 131_073]
        )
        .is_err()
    );
}
#[test]
fn no_replace_conflict_preserves_both_exact_owned_files() {
    let temp = tempfile::tempdir().unwrap();
    let directory = Directory::create(&temp.path().join("host")).unwrap();
    let mut p =
        PrivateWorkspaceFileV1::stage(&directory, PENDING, b"original", MAX_REGISTRY).unwrap();
    directory.write_new(PENDING, b"conflict").unwrap();
    let before = fingerprint(&directory);
    assert!(p.publish(&directory, MAX_REGISTRY).is_err());
    assert_eq!(fingerprint(&directory), before);
}
#[test]
fn ordinary_inventory_refuses_preanchor_and_unrecognized_staging_artifacts() {
    for name in [
        PENDING,
        COMMIT,
        "staging-durable-private-pending-v1-0123456789abcdef0123456789abcdef",
        "staging-durable-private-invalid",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let directory = Directory::create(&temp.path().join("host")).unwrap();
        directory.refuse_private_workspace_files().unwrap();
        directory.write_new(name, b"partial").unwrap();
        let before = fingerprint(&directory);
        assert!(directory.refuse_private_workspace_files().is_err());
        assert!(directory.inventory().is_err());
        assert_eq!(fingerprint(&directory), before);
    }
}
#[test]
fn original_root_identity_and_destination_overlap_are_not_path_labels() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("original");
    let directory = Directory::create(&root).unwrap();
    assert!(require_external_workspace_root(&directory, &root.join("child")).is_err());
    assert!(require_external_workspace_root(&directory, temp.path()).is_err());
    let alias = temp.path().join("alias");
    std::os::unix::fs::symlink(&root, &alias).unwrap();
    assert!(require_external_workspace_root(&directory, &alias.join("child")).is_err());
    let identity = directory.manual_target_identity_digest().unwrap();
    fs::rename(&root, temp.path().join("retained")).unwrap();
    let replacement = Directory::create(&root).unwrap();
    assert!(directory.check().is_err());
    assert_ne!(
        identity,
        replacement.manual_target_identity_digest().unwrap()
    );
    let missing = temp.path().join("missing");
    assert!(Directory::open(&missing).is_err());
    assert!(!missing.exists());
}
#[test]
fn unsupported_discovery_actions_and_denied_native_privacy_never_acquire() {
    for action in [
        PrivateWorkspaceActionV1::RetainDiscovery,
        PrivateWorkspaceActionV1::RetainProjection,
        PrivateWorkspaceActionV1::FreezeCandidate,
    ] {
        assert!(require_exact_action(action).is_err());
    }
    let approval = HistoricalApproval::denied_for_test(false);
    let mut reached = false;
    assert!(
        approval
            .effect(&mut || {
                reached = true;
                Ok(())
            })
            .is_err()
    );
    assert!(!reached);
}
#[test]
fn ownership_cut_precedes_every_vault_replacement_and_reopen_is_explicit() {
    let source = include_str!("durable_private_workspace_v1.rs");
    let create = source
        .split("pub(in crate::host) fn create_private_durable_workspace_v1")
        .nth(1)
        .unwrap()
        .split("pub(in crate::host) fn reopen_private_workspace_registered_v1")
        .next()
        .unwrap();
    let compact = create
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();
    let cut = compact.find("letHost{").unwrap();
    let drop_owners = compact.find("drop((engine,transport").unwrap();
    let replacement = compact.find("directory.replace_private").unwrap();
    assert!(cut < drop_owners && drop_owners < replacement);
    assert!(!create.contains("initialize_once_original"));
    let open = source
        .split("pub(in crate::host) fn reopen_private_durable_workspace_v1")
        .nth(1)
        .unwrap()
        .split("fn private_workspace_owner_v1")
        .next()
        .unwrap();
    assert!(open.contains("retention_policy, false"));
}
