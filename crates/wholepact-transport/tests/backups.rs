//! Synthetic agreement archives/passwords only. Integrity is not freshness.
use wholepact_transport::*;
fn scope() -> BackupScope {
    BackupScope {
        network_profile_id: "testnet-synthetic-unqualified".into(),
        agreement_id: "synthetic-agreement".into(),
    }
}
fn password() -> BackupPassword {
    BackupPassword::new(b"SYNTHETIC-TEST-ONLY-NOT-A-REAL-PASSWORD".to_vec()).unwrap()
}
fn archive() -> AgreementBackup {
    let metadata = BackupMetadata {
        schema_version: 1,
        backup_id: "00000000000000000000000000000001".into(),
        scope: scope(),
        created_at: Timestamp::from_unix_seconds(100).unwrap(),
        source_revision: 1,
        source_writer_epoch: 1,
    };
    let sections = [
        BackupSectionKind::Agreement,
        BackupSectionKind::Proposals,
        BackupSectionKind::DisclosureConsents,
        BackupSectionKind::AuthorizationJournal,
        BackupSectionKind::Observations,
    ]
    .into_iter()
    .map(|kind| BackupSection::new(kind, b"SYNTHETIC-PRIVATE-BACKUP-CANARY".to_vec()).unwrap())
    .collect();
    AgreementBackup::new(metadata, sections).unwrap()
}
#[test]
fn backup_integrity_roundtrip_preserves_versions_but_never_writer_authority() {
    let original = archive();
    let file = encrypt_backup(&original, &password()).unwrap();
    let text = std::str::from_utf8(file.as_bytes()).unwrap();
    for marker in [
        "PRIVATE-BACKUP-CANARY",
        "synthetic-agreement",
        "source_writer_epoch",
        "authorization_journal",
    ] {
        assert!(!text.contains(marker));
    }
    let restored = restore_backup(&file, &password(), &scope()).unwrap();
    assert_eq!(restored.status(), RestoreStatus::RecoveryRequired);
    assert!(!restored.authorization_allowed());
    assert_eq!(restored.archive().metadata().schema_version, 1);
    assert_eq!(restored.archive().metadata().source_revision, 1);
    assert_eq!(restored.archive().metadata().source_writer_epoch, 1);
    assert_eq!(restored.archive().metadata().created_at.unix_seconds(), 100);
    for (a, b) in restored
        .archive()
        .sections()
        .iter()
        .zip(original.sections())
    {
        assert_eq!(a.kind(), b.kind());
        assert_eq!(a.bytes(), b.bytes());
    }
    let second = encrypt_backup(&original, &password()).unwrap();
    assert_ne!(file.as_bytes(), second.as_bytes());
    let wrong = BackupPassword::new(b"ANOTHER-SYNTHETIC-TEST-PASSWORD".to_vec()).unwrap();
    assert_eq!(
        restore_backup(&file, &wrong, &scope()).err(),
        Some(TransportError::Authentication)
    );
    let mut value: serde_json::Value = serde_json::from_slice(file.as_bytes()).unwrap();
    let ciphertext = value["ciphertext"].as_str().unwrap();
    let first = if ciphertext.starts_with('A') {
        "B"
    } else {
        "A"
    };
    value["ciphertext"] = format!("{}{}", first, &ciphertext[1..]).into();
    let tampered = EncryptedBackup::from_bytes(serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(
        restore_backup(&tampered, &password(), &scope()).err(),
        Some(TransportError::Authentication)
    );
    let mut wrong_scope = scope();
    wrong_scope.network_profile_id = "wrong-network".into();
    assert_eq!(
        restore_backup(&file, &password(), &wrong_scope).err(),
        Some(TransportError::WrongNetwork)
    );
}
#[test]
fn archive_schema_kdf_password_and_inventory_fail_closed() {
    assert_eq!(
        BackupPassword::new(b"short".to_vec()).err(),
        Some(TransportError::WeakPassword)
    );
    let original = archive();
    assert_eq!(
        AgreementBackup::new(original.metadata().clone(), vec![]).err(),
        Some(TransportError::Malformed)
    );
    let mut metadata = original.metadata().clone();
    metadata.schema_version = 2;
    assert_eq!(
        AgreementBackup::new(metadata, vec![]).err(),
        Some(TransportError::UnsupportedVersion)
    );
    assert_eq!(
        EncryptedBackup::from_bytes(vec![b' '; MAX_FILE_BYTES + 1]).err(),
        Some(TransportError::ResourceLimit)
    );
    // Untrusted KDF parameters reject structurally before allocating KDF memory.
    let bad = serde_json::json!({"header":{"format":"wholepact-encrypted-agreement-backup","schema_version":1,
        "suite":"Argon2id-v19-XChaCha20Poly1305","memory_kib":4294967295u64,"iterations":3,"lanes":1,
        "salt":"00000000000000000000000000000000","nonce":"000000000000000000000000000000000000000000000000"},"ciphertext":""});
    assert_eq!(
        EncryptedBackup::from_bytes(serde_json::to_vec(&bad).unwrap()).err(),
        Some(TransportError::UnsupportedVersion)
    );
}
