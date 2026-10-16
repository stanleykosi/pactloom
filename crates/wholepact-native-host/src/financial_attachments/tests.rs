//! Synthetic encrypted-storage checks and denied native decisions only. These
//! fixtures cannot obtain a valid foreground approval or a financial capability.
use super::*;
use std::{collections::BTreeMap, fs};
const PASSWORD: &[u8] = b"synthetic-only-attachment-password";
fn id(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}
fn tree(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut result = BTreeMap::new();
    let mut pending = vec![root.to_owned()];
    while let Some(path) = pending.pop() {
        for child in fs::read_dir(path).unwrap() {
            let path = child.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                result.insert(
                    path.strip_prefix(root).unwrap().to_owned(),
                    fs::read(path).unwrap(),
                );
            }
        }
    }
    result
}
fn original(root: &Path) -> (Directory, Secrets, FinancialProfile) {
    let host = Directory::create(&root.join("host")).unwrap();
    let secrets = Secrets::fresh().unwrap();
    let primary_path = root.join("financial-primary");
    register(
        &host,
        &secrets,
        &primary_path,
        AttachmentRole::PrimaryFinancial,
        None,
    )
    .unwrap();
    let primary = FinancialProfile::create(&primary_path, &secrets.profile(), PASSWORD).unwrap();
    (host, secrets, primary)
}
fn inert_pending(
    host: &Directory,
    secrets: &Secrets,
    primary: &FinancialProfile,
    path: &Path,
) -> (InventoryV2, String) {
    let origin = primary.manual_journal_origin_digest(host, secrets).unwrap();
    let mut value = v2_from(load(host, secrets).unwrap(), &origin, secrets).unwrap();
    value
        .append(
            Extension::Pending {
                request: PendingAttachment {
                    operation_digest: id(1),
                    account_id: id(2),
                    directory: path.to_owned(),
                    mode: AttachmentOpenMode::Create,
                },
            },
            &id(3),
            secrets,
        )
        .unwrap();
    let pending = value.latest_digest().unwrap();
    // Inert fixture bytes only; no production publication approval is minted.
    write_v2(host, secrets, &value).unwrap();
    (value, pending)
}
#[test]
fn denied_native_approval_preserves_complete_tree_and_never_creates_pending() {
    let temporary = tempfile::tempdir().unwrap();
    let (host, secrets, primary) = original(temporary.path());
    let path = temporary.path().join("participant");
    for expired in [false, true] {
        let prepared = PreparedAttachment::prepare(
            &host,
            &secrets,
            &primary,
            &id(1),
            &id(2),
            &path,
            AttachmentOpenMode::Create,
        )
        .unwrap();
        let approval = PublicationApproval::denied_for_test(prepared.review_digest(), expired);
        let before = tree(temporary.path());
        assert!(prepared.open(approval, PASSWORD).is_err());
        assert_eq!(tree(temporary.path()), before);
        assert!(!path.exists());
        assert!(matches!(load(&host, &secrets).unwrap(), Registry::V1(_)));
    }
}
#[test]
fn original_primary_digest_survives_pending_extension_while_v1_api_stays_denied() {
    let temporary = tempfile::tempdir().unwrap();
    let (host, secrets, primary) = original(temporary.path());
    let original = primary
        .manual_journal_origin_digest(&host, &secrets)
        .unwrap();
    let path = temporary.path().join("participant-missing");
    inert_pending(&host, &secrets, &primary, &path);
    assert_eq!(
        primary
            .manual_original_primary_origin_digest(&host, &secrets)
            .unwrap(),
        original
    );
    assert!(
        primary
            .manual_journal_origin_digest(&host, &secrets)
            .is_err()
    );
    assert_eq!(read(&host, &secrets).unwrap().len(), 2);
    let before = tree(temporary.path());
    // A failed first create remains a dependency, never a fresh empty retry.
    assert!(
        PreparedAttachment::prepare(
            &host,
            &secrets,
            &primary,
            &id(1),
            &id(2),
            &path,
            AttachmentOpenMode::Create
        )
        .is_err()
    );
    assert!(
        known_entry_before_open(
            &host,
            &secrets,
            &path,
            AttachmentRole::ParticipantWallet,
            Some(&id(2))
        )
        .is_err()
    );
    assert_eq!(tree(temporary.path()), before);
    assert!(!path.exists());
}
#[test]
fn exact_actual_reopen_and_replacement_missing_wrong_key_and_fulltree_rejection() {
    let temporary = tempfile::tempdir().unwrap();
    let (host, secrets, primary) = original(temporary.path());
    let path = temporary.path().join("participant");
    let (mut value, pending) = inert_pending(&host, &secrets, &primary, &path);
    let participant = FinancialProfile::create(&path, &secrets.profile(), PASSWORD).unwrap();
    let actual = participant
        .manual_attachment_descriptor(&secrets.profile(), &id(2))
        .unwrap();
    value
        .append(
            Extension::Committed {
                pending_extension_digest: pending,
                actual: actual.clone(),
            },
            &id(3),
            &secrets,
        )
        .unwrap();
    write_v2(&host, &secrets, &value).unwrap();
    assert!(
        known_entry_before_open(
            &host,
            &secrets,
            &path,
            AttachmentRole::ParticipantWallet,
            Some(&id(2))
        )
        .unwrap()
    );
    reopen_registered(
        &host,
        &secrets,
        &participant,
        AttachmentRole::ParticipantWallet,
        Some(&id(2)),
    )
    .unwrap();
    let binding = binding_for_profile(&host, &secrets, &primary, &participant, &id(2)).unwrap();
    assert!(binding.selected == actual);
    assert_eq!(
        binding.current_registry_digest,
        value.current_digest().unwrap()
    );
    let before = tree(temporary.path());
    assert!(
        reopen_registered(
            &host,
            &secrets,
            &participant,
            AttachmentRole::ParticipantWallet,
            Some(&id(9))
        )
        .is_err()
    );
    assert_eq!(tree(temporary.path()), before);
    participant
        .directory
        .write_new("unexpected-private-history", b"synthetic-extra-file")
        .unwrap();
    let before = tree(temporary.path());
    assert!(binding_for_profile(&host, &secrets, &primary, &participant, &id(2)).is_err());
    assert_eq!(tree(temporary.path()), before);
    fs::remove_file(path.join("unexpected-private-history")).unwrap();
    drop(participant);
    let before = tree(temporary.path());
    assert!(
        FinancialProfile::open(&path, &secrets.profile(), b"synthetic-wrong-passphrase").is_err()
    );
    assert_eq!(tree(temporary.path()), before);
    let participant = FinancialProfile::open(&path, &secrets.profile(), PASSWORD).unwrap();
    assert!(binding_for_profile(&host, &secrets, &primary, &participant, &id(2)).is_ok());
    // Violate the cooperative owner lock deliberately: exact captured identities
    // detect replacement rather than adopting the same filename.
    fs::rename(
        path.join("signed.sqlite"),
        temporary.path().join("original-signed.sqlite"),
    )
    .unwrap();
    crate::files::write_new(&path.join("signed.sqlite"), b"synthetic-replacement").unwrap();
    let before = tree(temporary.path());
    assert!(
        participant
            .manual_attachment_descriptor(&secrets.profile(), &id(2))
            .is_err()
    );
    assert_eq!(tree(temporary.path()), before);
    fs::remove_file(path.join("signed.sqlite")).unwrap();
    let before = tree(temporary.path());
    assert!(
        participant
            .manual_attachment_descriptor(&secrets.profile(), &id(2))
            .is_err()
    );
    assert_eq!(tree(temporary.path()), before);
    assert!(!path.join("signed.sqlite").exists());
}
#[test]
fn current_registry_change_invalidates_prepared_native_review_without_effect() {
    let temporary = tempfile::tempdir().unwrap();
    let (host, secrets, primary) = original(temporary.path());
    let path = temporary.path().join("participant");
    let prepared = PreparedAttachment::prepare(
        &host,
        &secrets,
        &primary,
        &id(1),
        &id(2),
        &path,
        AttachmentOpenMode::Create,
    )
    .unwrap();
    inert_pending(
        &host,
        &secrets,
        &primary,
        &temporary.path().join("different-pending"),
    );
    let before = tree(temporary.path());
    assert!(prepared.check_current().is_err());
    assert_eq!(tree(temporary.path()), before);
    assert!(!path.exists());
}

#[test]
fn complete_valid_replacement_with_same_owner_and_password_cannot_rebind() {
    let temporary = tempfile::tempdir().unwrap();
    let (host, secrets, primary) = original(temporary.path());
    let path = temporary.path().join("participant");
    let (mut value, pending) = inert_pending(&host, &secrets, &primary, &path);
    let participant = FinancialProfile::create(&path, &secrets.profile(), PASSWORD).unwrap();
    let actual = participant
        .manual_attachment_descriptor(&secrets.profile(), &id(2))
        .unwrap();
    value
        .append(
            Extension::Committed {
                pending_extension_digest: pending,
                actual,
            },
            &id(3),
            &secrets,
        )
        .unwrap();
    write_v2(&host, &secrets, &value).unwrap();
    drop(participant);
    fs::rename(
        &path,
        temporary.path().join("retained-original-participant"),
    )
    .unwrap();
    let replacement = FinancialProfile::create(&path, &secrets.profile(), PASSWORD).unwrap();
    let before = tree(temporary.path());
    assert!(
        reopen_registered(
            &host,
            &secrets,
            &replacement,
            AttachmentRole::ParticipantWallet,
            Some(&id(2))
        )
        .is_err()
    );
    assert!(binding_for_profile(&host, &secrets, &primary, &replacement, &id(2)).is_err());
    let entry = Attachment {
        directory: path,
        role: AttachmentRole::ParticipantWallet,
        account: Some(id(2)),
    };
    assert!(check_backup_owner(&host, &secrets, &entry, &replacement).is_err());
    assert_eq!(tree(temporary.path()), before);
}

#[test]
fn fresh_import_owner_is_not_issued_by_denied_approval_or_pending_create_retry() {
    let temporary = tempfile::tempdir().unwrap();
    let (host, secrets, primary) = original(temporary.path());
    let path = temporary.path().join("fresh-participant");
    for expired in [false, true] {
        let prepared = PreparedAttachment::prepare(
            &host,
            &secrets,
            &primary,
            &id(1),
            &id(2),
            &path,
            AttachmentOpenMode::Create,
        )
        .unwrap();
        let approval = PublicationApproval::denied_for_test(prepared.review_digest(), expired);
        let before = tree(temporary.path());
        assert!(prepared.open_fresh(approval, PASSWORD).is_err());
        assert_eq!(tree(temporary.path()), before);
        assert!(!path.exists());
    }
    // Retained interrupted-create fixture, not an actual native approval.
    inert_pending(&host, &secrets, &primary, &path);
    let _existing = FinancialProfile::create(&path, &secrets.profile(), PASSWORD).unwrap();
    let prepared = PreparedAttachment::prepare(
        &host,
        &secrets,
        &primary,
        &id(1),
        &id(2),
        &path,
        AttachmentOpenMode::Create,
    )
    .unwrap();
    let approval = PublicationApproval::denied_for_test(prepared.review_digest(), false);
    let before = tree(temporary.path());
    assert!(prepared.open_fresh(approval, PASSWORD).is_err());
    assert_eq!(tree(temporary.path()), before);
}

#[test]
fn v2_primary_reopen_uses_retained_owner_without_generic_reregistration() {
    let temporary = tempfile::tempdir().unwrap();
    let (host, secrets, primary) = original(temporary.path());
    let primary_path = primary.current_directory().unwrap();
    inert_pending(&host, &secrets, &primary, &temporary.path().join("pending"));
    let before = tree(temporary.path());
    assert!(prepare_primary_open(&host, &secrets, &primary_path, false).unwrap());
    assert!(prepare_primary_open(&host, &secrets, &primary_path, true).is_err());
    assert!(prepare_primary_open(&host, &secrets, &temporary.path().join("other"), false).is_err());
    assert_eq!(tree(temporary.path()), before);
    drop(primary);
    let actual = FinancialProfile::open(&primary_path, &secrets.profile(), PASSWORD).unwrap();
    reopen_registered(
        &host,
        &secrets,
        &actual,
        AttachmentRole::PrimaryFinancial,
        None,
    )
    .unwrap();
    // Opening the original primary never manufactures a fresh participant owner.
    assert!(matches!(load(&host, &secrets).unwrap(), Registry::V2(_)));
}

#[test]
fn retained_attachment_accepts_only_exact_authenticated_historical_prefix() {
    // Synthetic storage facts only. This creates no current native selection,
    // retention receipt or Host completion authority.
    let temporary = tempfile::tempdir().unwrap();
    let (host, secrets, primary) = original(temporary.path());
    let path = temporary.path().join("retained-participant");
    let (mut inventory, pending) = inert_pending(&host, &secrets, &primary, &path);
    let participant = FinancialProfile::create(&path, &secrets.profile(), PASSWORD).unwrap();
    let actual = participant
        .manual_attachment_descriptor(&secrets.profile(), &id(2))
        .unwrap();
    inventory
        .append(
            Extension::Committed {
                pending_extension_digest: pending,
                actual: actual.clone(),
            },
            &id(4),
            &secrets,
        )
        .unwrap();
    write_v2(&host, &secrets, &inventory).unwrap();
    let expected = binding_for_profile(&host, &secrets, &primary, &participant, &id(2)).unwrap();
    inventory
        .append(
            Extension::Pending {
                request: PendingAttachment {
                    operation_digest: id(5),
                    account_id: id(6),
                    directory: temporary.path().join("later-participant"),
                    mode: AttachmentOpenMode::Create,
                },
            },
            &id(7),
            &secrets,
        )
        .unwrap();
    assert_ne!(
        inventory.current_digest().unwrap(),
        expected.current_registry_digest
    );
    require_retained_registry_prefix(&inventory, &secrets, &expected, &actual).unwrap();
    for field in 0..5 {
        let mut changed = expected.clone();
        match field {
            0 => changed.current_registry_digest = id(21),
            1 => changed.latest_extension_digest = id(22),
            2 => changed.predecessor_registry_digest = id(23),
            3 => changed.original_primary_journal_origin_digest = id(24),
            _ => changed.selected.journal_origin_digest = id(25),
        }
        assert!(require_retained_registry_prefix(&inventory, &secrets, &changed, &actual).is_err());
    }
    let mut truncated = inventory.clone();
    truncated.extensions.truncate(1);
    assert!(require_retained_registry_prefix(&truncated, &secrets, &expected, &actual).is_err());
    let mut altered = inventory.clone();
    altered.extensions[0].native_review_digest = id(26);
    assert!(require_retained_registry_prefix(&altered, &secrets, &expected, &actual).is_err());
}
