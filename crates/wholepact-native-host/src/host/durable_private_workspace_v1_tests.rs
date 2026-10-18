//! Negative isolated-file and inert-registry tests. No positive native privacy
//! fake, wallet, installed signer, financial activation or qualified backup.
use super::*;

fn association_fixture() -> Association {
    Association {
        version: 1,
        purpose: PURPOSE.into(),
        dependency_id: "a".repeat(64),
        profile_id: "profile".into(),
        generation_id: "b".repeat(64),
        inventory_digest: "c".repeat(64),
        generation_plan_digest: "d".repeat(64),
        parent_coverage_digest: "e".repeat(64),
        original_financial_origin_digest: "f".repeat(64),
        host_directory_identity: "0".repeat(64),
        source_store_destination_identity: "source-store".into(),
        source_digest: "1".repeat(64),
        principal_id: "owner".into(),
        agreement_id: "agreement".into(),
        obligation_id: "obligation".into(),
        reviewer_account_ids: vec!["account-a".into(), "account-b".into()],
        workspace_root: "/original/private".into(),
        database_path: "/original/private/private-coordination.sqlite".into(),
        retention_policy: "retain exact original".into(),
    }
}
fn registry_fixture() -> (Pending, Committed, Association) {
    let association = association_fixture();
    let current = association_fixture();
    let committed = Committed {
        version: 1,
        pending_ciphertext_digest: "2".repeat(64),
        association_digest: digest(&association).unwrap(),
        workspace_directory_identity: "3".repeat(64),
        original_database_origin: [7; 32],
    };
    (
        Pending {
            association,
            database_key: [9; 32],
        },
        committed,
        current,
    )
}
#[test]
fn incomplete_dependency_cannot_enter_legacy_backup_or_reinitialize() {
    let temp = tempfile::tempdir().unwrap();
    let directory = Directory::create(&temp.path().join("original-host")).unwrap();
    refuse_unqualified_private_workspace_backup_v1(&directory).unwrap();
    directory
        .write_new(PENDING, b"interrupted immutable key association")
        .unwrap();
    assert!(refuse_unqualified_private_workspace_backup_v1(&directory).is_err());
    assert!(directory.write_new(PENDING, b"replacement").is_err());
    assert_eq!(
        directory.read(PENDING, 1024).unwrap(),
        b"interrupted immutable key association"
    );
    assert!(directory.read(COMMIT, 1024).is_err());
}
#[test]
fn orphan_commit_also_denies_backup() {
    let temp = tempfile::tempdir().unwrap();
    let directory = Directory::create(&temp.path().join("original-host")).unwrap();
    directory.write_new(COMMIT, b"orphaned marker").unwrap();
    assert!(refuse_unqualified_private_workspace_backup_v1(&directory).is_err());
}
#[test]
fn new_dependency_cannot_activate_without_qualified_parent_guards() {
    assert!(require_qualified_private_dependency_coverage_v1().is_err());
}
#[test]
fn exact_registry_binding_refuses_second_principal_and_retargeting() {
    let (pending, committed, mut current) = registry_fixture();
    require_original_registry(&pending, &committed, &current, &"2".repeat(64)).unwrap();
    current.principal_id = "second-agreement-scoped-principal".into();
    assert!(require_original_registry(&pending, &committed, &current, &"2".repeat(64)).is_err());
    let mut current = association_fixture();
    current.workspace_root = "/replacement/private".into();
    assert!(require_original_registry(&pending, &committed, &current, &"2".repeat(64)).is_err());
    let mut current = association_fixture();
    current.reviewer_account_ids.reverse();
    assert!(require_original_registry(&pending, &committed, &current, &"2".repeat(64)).is_err());
    let mut current = association_fixture();
    current.source_digest = "4".repeat(64);
    assert!(require_original_registry(&pending, &committed, &current, &"2".repeat(64)).is_err());
}
#[test]
fn replaced_wrapped_key_or_commit_never_authenticates() {
    let (pending, mut committed, current) = registry_fixture();
    assert!(require_original_registry(&pending, &committed, &current, &"5".repeat(64)).is_err());
    committed.association_digest = "6".repeat(64);
    assert!(require_original_registry(&pending, &committed, &current, &"2".repeat(64)).is_err());
}
#[test]
fn dropped_original_directory_cannot_be_replaced_at_same_path() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("original-private");
    let original = Directory::create(&root).unwrap();
    let identity = original.manual_target_identity_digest().unwrap();
    fs::rename(&root, temp.path().join("preserved-original")).unwrap();
    let replacement = Directory::create(&root).unwrap();
    assert!(original.check().is_err());
    assert_ne!(
        identity,
        replacement.manual_target_identity_digest().unwrap()
    );
}
#[test]
fn missing_directory_is_not_created_by_resume() {
    let temp = tempfile::tempdir().unwrap();
    let missing = temp.path().join("missing-original");
    assert!(Directory::open(&missing).is_err());
    assert!(!missing.exists());
}
#[test]
fn production_privacy_has_no_positive_test_override() {
    let approval = HistoricalApproval::denied_for_test(false);
    assert!(approval.check().is_err());
    let mut reached = false;
    assert!(approval
        .effect(&mut || {
            reached = true;
            Ok(())
        })
        .is_err());
    assert!(!reached);
    let source = include_str!("durable_private_workspace_v1.rs");
    assert!(!source.contains("permitted: bool"));
    assert!(!source.contains("allowed_for_test"));
}

#[test]
fn financial_attachment_role_cannot_be_relabelled_as_private_dependency() {
    let (mut pending, mut committed, mut current) = registry_fixture();
    pending.association.purpose = "primary_financial".into();
    current.purpose = "primary_financial".into();
    committed.association_digest = digest(&pending.association).unwrap();
    assert!(require_original_registry(&pending, &committed, &current, &"2".repeat(64)).is_err());
}

#[test]
fn workspace_target_cannot_be_inside_or_above_any_actual_held_root() {
    let temp = tempfile::tempdir().unwrap();
    let host = Directory::create(&temp.path().join("original-host")).unwrap();
    let primary = Directory::create(&temp.path().join("original-primary")).unwrap();
    let target = primary.path("forbidden-new-child").unwrap();
    // The original defect: excluding Host alone is insufficient.
    require_external_workspace_root(&host, &target).unwrap();
    assert!(require_external_workspace_root(&primary, &target).is_err());
    assert!(
        require_external_workspace_root(&host, &host.path("forbidden-child").unwrap()).is_err()
    );
    assert!(require_external_workspace_root(&primary, temp.path()).is_err());
    assert!(!target.exists());
    assert!(!host.path(PENDING).unwrap().exists());
    let separate = temp.path().join("separate-new-workspace");
    require_external_workspace_root(&host, &separate).unwrap();
    require_external_workspace_root(&primary, &separate).unwrap();
}
#[test]
fn destination_preflight_rejects_symlink_alias_of_actual_primary() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("original-primary");
    let primary = Directory::create(&root).unwrap();
    let alias = temp.path().join("primary-alias");
    std::os::unix::fs::symlink(&root, &alias).unwrap();
    assert!(require_external_workspace_root(&primary, &alias.join("forbidden-new-child")).is_err());
    assert!(!root.join("forbidden-new-child").exists());
}
#[test]
fn additional_authenticated_dependency_needs_actual_owner_coverage() {
    use crate::financial_inventory::{Attachment, AttachmentRole};
    let primary = Path::new("/actual/primary");
    let mut entries = vec![Attachment {
        directory: primary.into(),
        role: AttachmentRole::PrimaryFinancial,
        account: None,
    }];
    require_primary_only_destination_coverage(&entries, primary).unwrap();
    // read_current includes this restriction for pending as well as committed
    // attachments. Its authenticated path is not a substitute for a held owner.
    entries.push(Attachment {
        directory: "/actual/participant".into(),
        role: AttachmentRole::ParticipantWallet,
        account: Some("account-a".into()),
    });
    assert!(require_primary_only_destination_coverage(&entries, primary).is_err());
    entries.pop();
    assert!(
        require_primary_only_destination_coverage(&entries, Path::new("/substituted/primary"))
            .is_err()
    );
}
#[test]
fn actual_root_checks_precede_pending_and_repeat_before_directory_creation() {
    let source = include_str!("durable_private_workspace_v1.rs");
    let create = source
        .split("pub(in crate::host) fn create_private_durable_workspace_v1")
        .nth(1)
        .unwrap()
        .split("pub(in crate::host) fn reopen_private_durable_workspace_v1")
        .next()
        .unwrap();
    let pending = create.find("self.directory.write_new(PENDING").unwrap();
    let directory = create.find("Directory::create(root)").unwrap();
    let checks = create
        .match_indices("check_workspace_destination(self, root)?")
        .map(|(position, _)| position)
        .collect::<Vec<_>>();
    assert!(checks.iter().any(|position| *position < pending));
    assert!(checks
        .iter()
        .any(|position| pending < *position && *position < directory));
}
