//! Pure/synthetic encrypted format tests. These directly construct inert fixture
//! records and never create a positive native approval or financial capability.
use super::*;

fn hex_id(index: u8) -> String {
    format!("{index:02x}").repeat(32)
}
fn fixture(secrets: &Secrets) -> InventoryV2 {
    InventoryV2 {
        version: 2,
        owner: secrets.profile(),
        original_primary: OriginalPrimary {
            registry: Inventory {
                version: 1,
                owner: secrets.profile(),
                entries: vec![Attachment {
                    directory: "/synthetic-financial/primary".into(),
                    role: AttachmentRole::PrimaryFinancial,
                    account: None,
                }],
            },
            journal_origin_digest: hex_id(1),
        },
        extensions: Vec::new(),
    }
}
fn request(index: u8) -> PendingAttachment {
    PendingAttachment {
        operation_digest: hex_id(2),
        account_id: hex_id(index),
        directory: format!("/synthetic-financial/participant-{index}").into(),
        mode: AttachmentOpenMode::Create,
    }
}
fn append_pending(value: &mut InventoryV2, index: u8, secrets: &Secrets) -> String {
    value
        .append(
            Extension::Pending {
                request: request(index),
            },
            &hex_id(3),
            secrets,
        )
        .unwrap();
    value.latest_digest().unwrap()
}
fn append_commit(value: &mut InventoryV2, index: u8, pending: &str, secrets: &Secrets) {
    value
        .append(
            Extension::Committed {
                pending_extension_digest: pending.into(),
                actual: ManualParticipantAttachment {
                    account_id: hex_id(index),
                    canonical_directory: format!("/synthetic-financial/participant-{index}"),
                    directory_identity_digest: hex_id(4),
                    journal_origin_digest: hex_id(5),
                },
            },
            &hex_id(6),
            secrets,
        )
        .unwrap();
}
#[test]
fn encrypted_v2_roundtrip_returns_every_pending_and_committed_dependency() {
    let secrets = Secrets::fresh().unwrap();
    let mut value = fixture(&secrets);
    let first = append_pending(&mut value, 10, &secrets);
    append_commit(&mut value, 10, &first, &secrets);
    append_pending(&mut value, 11, &secrets);
    let original = value.original_primary.clone();
    let bytes = seal(&value, V2_HEADER, V2_DOMAIN, &secrets).unwrap();
    assert_eq!(&bytes[..8], V2_HEADER);
    assert!(
        !bytes
            .windows(b"synthetic-financial".len())
            .any(|part| part == b"synthetic-financial")
    );
    assert_eq!(read_bytes(&bytes, &secrets).unwrap(), value.dependencies());
    assert_eq!(read_bytes(&bytes, &secrets).unwrap().len(), 3);
    match decode(&bytes, &secrets).unwrap() {
        Registry::V2(reopened) => {
            assert!(reopened.original_primary == original);
            assert!(reopened == value);
            assert_eq!(
                reopened.current_digest().unwrap(),
                value.current_digest().unwrap()
            );
        }
        Registry::V1(_) => panic!("v2 must not fall back to v1"),
    }
    assert!(read_bytes(&bytes, &Secrets::fresh().unwrap()).is_err());
    let mut corrupt = bytes;
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(read_bytes(&corrupt, &secrets).is_err());
}
#[test]
fn explicit_v2_header_version_domain_unknown_fields_and_predecessor_fail_closed() {
    let secrets = Secrets::fresh().unwrap();
    let mut value = fixture(&secrets);
    append_pending(&mut value, 10, &secrets);
    let bytes = seal(&value, V2_HEADER, V2_DOMAIN, &secrets).unwrap();
    let mut unknown_header = bytes.clone();
    unknown_header[7] = b'9';
    assert!(read_bytes(&unknown_header, &secrets).is_err());
    assert!(read_bytes(&seal(&value, V2_HEADER, MAGIC, &secrets).unwrap(), &secrets).is_err());
    let mut changed = value.clone();
    changed.version = 1;
    assert!(
        read_bytes(
            &seal(&changed, V2_HEADER, V2_DOMAIN, &secrets).unwrap(),
            &secrets
        )
        .is_err()
    );
    let mut json = serde_json::to_value(&value).unwrap();
    json["approved"] = serde_json::json!(true);
    assert!(
        read_bytes(
            &seal(&json, V2_HEADER, V2_DOMAIN, &secrets).unwrap(),
            &secrets
        )
        .is_err()
    );
    changed = value.clone();
    changed.extensions[0].predecessor_registry_digest = hex_id(99);
    assert!(
        read_bytes(
            &seal(&changed, V2_HEADER, V2_DOMAIN, &secrets).unwrap(),
            &secrets
        )
        .is_err()
    );
    // Retagging a legacy ciphertext cannot admit a v2 inventory or vice versa.
    let legacy = seal(&value.original_primary.registry, &[], MAGIC, &secrets).unwrap();
    let mut forged = V2_HEADER.to_vec();
    forged.extend(legacy);
    assert!(read_bytes(&forged, &secrets).is_err());
    assert!(read_bytes(&bytes[V2_HEADER.len()..], &secrets).is_err());
}
#[test]
fn exact_pending_retry_conflicts_and_maximum_capacity_are_monotone() {
    let secrets = Secrets::fresh().unwrap();
    let mut value = fixture(&secrets);
    let first = append_pending(&mut value, 10, &secrets);
    assert_eq!(
        value.pending(&request(10)).unwrap(),
        Some((0, first.clone()))
    );
    let before = serde_json::to_vec(&value).unwrap();
    for field in 0..4 {
        let mut changed = request(10);
        match field {
            0 => changed.account_id = hex_id(42),
            1 => changed.operation_digest = hex_id(43),
            2 => changed.mode = AttachmentOpenMode::Open,
            _ => changed.directory = "/synthetic-financial/other".into(),
        }
        assert!(value.pending(&changed).is_err());
    }
    assert!(
        value
            .append(
                Extension::Pending {
                    request: request(10)
                },
                &hex_id(3),
                &secrets
            )
            .is_err()
    );
    assert_eq!(serde_json::to_vec(&value).unwrap(), before);
    append_commit(&mut value, 10, &first, &secrets);
    for index in 11..21 {
        let id = append_pending(&mut value, index, &secrets);
        append_commit(&mut value, index, &id, &secrets);
    }
    assert_eq!(value.dependencies().len(), MAX_DEPENDENCIES);
    assert_eq!(value.extensions.len(), 22);
    let before = serde_json::to_vec(&value).unwrap();
    assert!(
        value
            .append(
                Extension::Pending {
                    request: request(21)
                },
                &hex_id(3),
                &secrets
            )
            .is_err()
    );
    assert_eq!(serde_json::to_vec(&value).unwrap(), before);
    assert!(seal(&value, V2_HEADER, V2_DOMAIN, &secrets).unwrap().len() <= MAX);
}
#[test]
fn commits_must_match_one_earlier_exact_pending_and_cannot_be_replaced() {
    let secrets = Secrets::fresh().unwrap();
    let mut value = fixture(&secrets);
    let pending = append_pending(&mut value, 10, &secrets);
    let good = Extension::Committed {
        pending_extension_digest: pending,
        actual: ManualParticipantAttachment {
            account_id: hex_id(10),
            canonical_directory: "/synthetic-financial/participant-10".into(),
            directory_identity_digest: hex_id(4),
            journal_origin_digest: hex_id(5),
        },
    };
    let before = serde_json::to_vec(&value).unwrap();
    for field in 0..3 {
        let mut bad = good.clone();
        if let Extension::Committed {
            pending_extension_digest,
            actual,
        } = &mut bad
        {
            match field {
                0 => *pending_extension_digest = hex_id(99),
                1 => actual.account_id = hex_id(99),
                _ => actual.canonical_directory = "/synthetic-financial/wrong".into(),
            }
        }
        assert!(value.append(bad, &hex_id(3), &secrets).is_err());
        assert_eq!(serde_json::to_vec(&value).unwrap(), before);
    }
    value.append(good.clone(), &hex_id(3), &secrets).unwrap();
    assert!(value.append(good, &hex_id(3), &secrets).is_err());
}
#[test]
fn generic_register_refuses_even_exact_v2_paths_without_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let host = Directory::create(&temp.path().join("host")).unwrap();
    let secrets = Secrets::fresh().unwrap();
    let primary = temp.path().join("primary");
    register(
        &host,
        &secrets,
        &primary,
        AttachmentRole::PrimaryFinancial,
        None,
    )
    .unwrap();
    let original = match load(&host, &secrets).unwrap() {
        Registry::V1(value) => value,
        _ => unreachable!(),
    };
    let mut value = fixture(&secrets);
    value.original_primary.registry = original;
    append_pending(&mut value, 10, &secrets);
    write_v2(&host, &secrets, &value).unwrap();
    let before = host.read(FILE, MAX).unwrap();
    assert!(
        register(
            &host,
            &secrets,
            &primary,
            AttachmentRole::PrimaryFinancial,
            None
        )
        .is_err()
    );
    assert!(
        register(
            &host,
            &secrets,
            &temp.path().join("new"),
            AttachmentRole::ParticipantWallet,
            Some(&hex_id(11))
        )
        .is_err()
    );
    assert_eq!(host.read(FILE, MAX).unwrap(), before);
    assert!(!temp.path().join("new").exists());
}
#[test]
fn nested_dependency_and_oversized_ciphertext_are_rejected_before_append() {
    let secrets = Secrets::fresh().unwrap();
    let mut value = fixture(&secrets);
    let mut nested = request(10);
    nested.directory = "/synthetic-financial/primary/child".into();
    assert!(
        value
            .append(Extension::Pending { request: nested }, &hex_id(3), &secrets)
            .is_err()
    );
    assert!(value.extensions.is_empty());
    let mut largest = request(10);
    largest.directory = format!("/{}", "a".repeat(4096)).into();
    assert!(
        value
            .append(
                Extension::Pending { request: largest },
                &hex_id(3),
                &secrets
            )
            .is_err()
    );
    assert!(seal(&vec![0u8; MAX], V2_HEADER, V2_DOMAIN, &secrets).is_err());
}
