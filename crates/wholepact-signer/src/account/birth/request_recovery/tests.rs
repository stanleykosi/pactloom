//! Modeled-data/ordinary-file tests only. No pending owner, NativeDecision,
//! PreparedPendingOwnerRequestRecovery, or transition capability is fabricated.
use super::*;
use crate::account::birth::tests::{data_account, data_anchor, data_policy};

const STAGE: &str = "tmp-0123456789abcdef0123456789abcdef";
const SECOND_STAGE: &str = "tmp-1123456789abcdef0123456789abcdef";
// Public deterministic synthetic key for data-format tests only; never live.
const DATA_ONLY_KEY: [u8; 32] = [0xa7; 32];

fn directory() -> (tempfile::TempDir, PrivateDirectory) {
    let temp = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::create(&temp.path().join("modeled-pending")).unwrap();
    directory
        .write("account.wp", b"modeled inventory only, not an envelope")
        .unwrap();
    (temp, directory)
}
fn request_data() -> (BirthAnchor, PendingBirthRequest, Vec<u8>) {
    let account = data_account();
    let anchor = data_anchor(&account);
    let mut policy = data_policy(&account);
    policy.account_use_genesis = Some(anchor.expected_account_use_genesis().unwrap());
    let (_, disclosure) = anchor.audit_policy_match(&policy).unwrap();
    let request = PendingBirthRequest {
        version: 1,
        operation_id: anchor.operation_id().into(),
        generation_instance_id: anchor.generation_instance_id().into(),
        native_birth_digest: anchor.birth_digest().into(),
        original_terms_digest: anchor.original_policy_terms_digest().into(),
        original_target_digest: canonical(
            "wholepact:pending-birth-target:v1",
            &anchor.intent.original_target,
        )
        .unwrap(),
        disclosure,
        policy,
        issued_at_ms: 1000,
        initial_commit_deadline_ms: 2000,
    };
    anchor.require_exact_pending_request(&request).unwrap();
    let mut domain = b"wholepact:pending-birth-owner-request-envelope:v1\0".to_vec();
    domain.extend_from_slice(anchor.birth_digest().as_bytes());
    (anchor, request, domain)
}

#[test]
fn modeled_stage_name_requires_exact_ascii_lowercase_shape() {
    assert!(is_stage_name(STAGE));
    for invalid in [
        "tmp-",
        "tmp-0123456789abcdef0123456789abcde",
        "tmp-0123456789abcdef0123456789abcdef0",
        "tmp-0123456789ABCDEF0123456789ABCDEF",
        "tmp-0123456789abcdef0123456789abcdeg",
        "xmp-0123456789abcdef0123456789abcdef",
        "tmp-0123456789abcdef0123456789abcdé",
    ] {
        assert!(!is_stage_name(invalid));
    }
}

#[test]
fn modeled_inventory_classifies_one_stage_without_authenticating_it() {
    let (_temp, directory) = directory();
    assert!(
        scan_pending_inventory(&directory)
            .unwrap()
            .staged_name
            .is_none()
    );
    directory
        .write(STAGE, b"modeled stage bytes, unauthenticated")
        .unwrap();
    assert_eq!(
        scan_pending_inventory(&directory)
            .unwrap()
            .staged_name
            .as_deref(),
        Some(STAGE)
    );
    directory
        .write(REQUEST_FILE, b"modeled conflicting final")
        .unwrap();
    let inventory = scan_pending_inventory(&directory).unwrap();
    assert!(inventory.retained_request);
    assert_eq!(inventory.staged_name.as_deref(), Some(STAGE));
    // Structural admission is not authentication. Production must delegate
    // final-request + stage to the active-envelope decoder, never request promotion.
    // Fixture cleanup only. Production recovery has no remove/reprepare path.
    std::fs::remove_file(directory.root().join(REQUEST_FILE)).unwrap();
    directory
        .write(SECOND_STAGE, b"modeled second candidate")
        .unwrap();
    assert!(scan_pending_inventory(&directory).is_err());
}

#[test]
fn modeled_inventory_rejects_unknown_names_and_oversize_stage() {
    let (_temp, directory) = directory();
    directory
        .write("tmp-wrong-shape", b"modeled invalid name")
        .unwrap();
    assert!(scan_pending_inventory(&directory).is_err());
    std::fs::remove_file(directory.root().join("tmp-wrong-shape")).unwrap();
    directory.write(STAGE, &vec![0; MAX_REQUEST + 1]).unwrap();
    assert!(scan_pending_inventory(&directory).is_err());
}

#[test]
fn modeled_inventory_rejects_symlink_hardlink_and_nonprivate_stage() {
    use std::os::unix::fs::PermissionsExt;
    let (_temp, directory) = directory();
    std::os::unix::fs::symlink("account.wp", directory.root().join(STAGE)).unwrap();
    assert!(scan_pending_inventory(&directory).is_err());
    std::fs::remove_file(directory.root().join(STAGE)).unwrap();
    std::fs::hard_link(
        directory.root().join("account.wp"),
        directory.root().join(STAGE),
    )
    .unwrap();
    assert!(scan_pending_inventory(&directory).is_err());
    std::fs::remove_file(directory.root().join(STAGE)).unwrap();
    directory.write(STAGE, b"modeled stage bytes").unwrap();
    std::fs::set_permissions(
        directory.root().join(STAGE),
        std::fs::Permissions::from_mode(0o640),
    )
    .unwrap();
    assert!(scan_pending_inventory(&directory).is_err());
}

#[test]
fn modeled_stage_authentication_preserves_exact_expired_request_without_renewal() {
    let (anchor, request, domain) = request_data();
    let plain = Zeroizing::new(serde_json::to_vec(&request).unwrap());
    let encrypted = vault::encrypt(&DATA_ONLY_KEY, &domain, &plain).unwrap();
    let decoded = decode_stage(&DATA_ONLY_KEY, &domain, &anchor, &encrypted).unwrap();
    assert!(decoded == request);
    assert_eq!(decoded.issued_at_ms, 1000);
    assert_eq!(decoded.initial_commit_deadline_ms, 2000);
    assert!(decoded.require_initial_commit_time(2000).is_err());
    assert!(decoded.require_initial_commit_time(u64::MAX).is_err());
    // Decoding this DTO never creates a pending owner or native decision.
}

#[test]
fn modeled_stage_rejects_partial_corrupt_wrong_key_domain_and_anchor() {
    let (anchor, request, domain) = request_data();
    let plain = Zeroizing::new(serde_json::to_vec(&request).unwrap());
    let encrypted = vault::encrypt(&DATA_ONLY_KEY, &domain, &plain).unwrap();
    for end in [0, 20, encrypted.len() - 1] {
        assert!(decode_stage(&DATA_ONLY_KEY, &domain, &anchor, &encrypted[..end]).is_err());
    }
    let mut corrupt = encrypted.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert!(decode_stage(&DATA_ONLY_KEY, &domain, &anchor, &corrupt).is_err());
    assert!(decode_stage(&[0xb8; 32], &domain, &anchor, &encrypted).is_err());
    assert!(decode_stage(&DATA_ONLY_KEY, b"wrong-domain", &anchor, &encrypted).is_err());
    let mut other_anchor = anchor.clone();
    other_anchor.intent.operation_id = format!("birth-{}", "ab".repeat(16));
    assert!(decode_stage(&DATA_ONLY_KEY, &domain, &other_anchor, &encrypted).is_err());
}

#[test]
fn modeled_authenticated_payload_cannot_add_unknown_approval_or_change_request_identity() {
    let (anchor, request, domain) = request_data();
    let mut unknown = serde_json::to_value(&request).unwrap();
    unknown["approved"] = serde_json::json!(true);
    let encrypted = vault::encrypt(
        &DATA_ONLY_KEY,
        &domain,
        &serde_json::to_vec(&unknown).unwrap(),
    )
    .unwrap();
    assert!(decode_stage(&DATA_ONLY_KEY, &domain, &anchor, &encrypted).is_err());
    let mut changed = request;
    changed.generation_instance_id = "fe".repeat(32);
    let encrypted = vault::encrypt(
        &DATA_ONLY_KEY,
        &domain,
        &serde_json::to_vec(&changed).unwrap(),
    )
    .unwrap();
    assert!(decode_stage(&DATA_ONLY_KEY, &domain, &anchor, &encrypted).is_err());
}
