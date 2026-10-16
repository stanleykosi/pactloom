//! Source-only tests. Data fixtures below are NOT genuine birth/native/witness
//! capability fixtures. No PendingAccountNativeAuthority or NativeDecision is
//! fabricated. Tests have not been run in this staging task.
use super::*;
use crate::account::{PendingAccount, ProvisioningConsent};

fn generate_verified() -> BackupVerifiedAccount {
    let pending = PendingAccount::generate(ProvisioningConsent {
        privacy_domain: "synthetic-unfunded-test".into(),
        account_index: 0,
    })
    .unwrap();
    let words = pending.recovery_words().unwrap();
    pending.verify_backup(&words).unwrap()
}
pub(super) fn data_account() -> DedicatedAccount {
    DedicatedAccount::from_entropy(
        Zeroizing::new([0x39; 32]),
        0,
        "data-only-fixture".into(),
        false,
    )
    .unwrap()
}
pub(super) fn data_policy(account: &DedicatedAccount) -> AccountPolicy {
    // JSON avoids silently inventing a value for a future required policy field.
    serde_json::from_value(serde_json::json!({
        "witness_id": "synthetic-original-witness",
        "account_id": account.account_id().unwrap(),
        "network_profile_id": NETWORK,
        "owner_certificate_digest": "11".repeat(32),
        "initial_writer_certificate_digest": "22".repeat(32),
        "initial_writer_epoch": 1,
        "enrollment_refs": ["33".repeat(32)],
        "agreement_ids": ["synthetic-agreement"],
        "recipient_scope_digests": ["44".repeat(32)],
        "aggregate_budget_zatoshis": 100,
        "per_operation_limit_zatoshis": 90,
        "maximum_fee_share_zatoshis": 5,
        "maximum_transaction_fee_zatoshis": 10,
        "maximum_permit_lifetime_ms": 60_000,
        "policy_expires_at_ms": 1_800_000_000_000u64
    }))
    .unwrap()
}
pub(super) fn data_anchor(account: &DedicatedAccount) -> BirthAnchor {
    // A modeled audit record only. This deliberately confers no approval: it
    // cannot construct either owner token and data_account has no birth instance.
    let terms = OriginalPolicyTerms::from_policy(&data_policy(account)).unwrap();
    let intent = BirthIntent {
        version: 1,
        operation_id: format!("birth-{}", "12".repeat(16)),
        generation_instance_id: "13".repeat(32),
        identity: BirthIdentity::derive(account).unwrap(),
        witness_origin: BirthWitnessOrigin {
            endpoint: "127.0.0.1:443".into(),
            server_name: "synthetic.invalid".into(),
            witness_id: "synthetic-original-witness".into(),
            pinned_server_certificate_digest: "55".repeat(32),
        },
        original_policy_terms_digest: terms.digest().unwrap(),
        original_policy_terms: terms,
        native_principal_id: "synthetic-principal".into(),
        native_measurement: "66".repeat(32),
        original_target: "/synthetic/data-only-pending".into(),
    };
    BirthAnchor {
        recipient_policy_v2: None,
        birth_digest: intent.digest().unwrap(),
        intent,
    }
}

#[test]
fn generation_instance_survives_real_backup_verification_and_rejects_swap() {
    let pending = PendingAccount::generate(ProvisioningConsent {
        privacy_domain: "synthetic-original-generation".into(),
        account_index: 0,
    })
    .unwrap();
    let generated = pending.account.generated_instance.as_ref().unwrap();
    let marker = generated.marker.clone();
    let instance_id = generated.instance_id.clone();
    let words = pending.recovery_words().unwrap();
    let first = pending.verify_backup(&words).unwrap();
    let second = generate_verified();
    let original = genuine_instance(&first).unwrap();
    assert!(Arc::ptr_eq(&marker, &original.marker));
    assert_eq!(instance_id, original.instance_id);
    assert!(require_generation_instance(&first, &original.marker, &original.instance_id).is_ok());
    assert!(matches!(
        require_generation_instance(&second, &original.marker, &original.instance_id),
        Err(Error::ReviewMismatch)
    ));
    assert!(matches!(
        require_generation_instance(&first, &original.marker, &"ff".repeat(32)),
        Err(Error::ReviewMismatch)
    ));
    assert!(matches!(
        require_generation_instance(&first, &Arc::new(()), &original.instance_id),
        Err(Error::ReviewMismatch)
    ));
    assert_ne!(
        first.account.account_id().unwrap(),
        second.account.account_id().unwrap()
    );
}

#[test]
fn import_decode_and_fixed_entropy_backup_never_mint_generation_instance() {
    let generated = generate_verified();
    let words = generated.account.recovery_words().unwrap();
    let imported = DedicatedAccount::recover(&words, 0, "changed-label".into()).unwrap();
    let decoded = DedicatedAccount::decode(&generated.account.encode()).unwrap();
    let fixed = data_account();
    for account in [imported, decoded, fixed] {
        let words = account.recovery_words().unwrap();
        let verified = PendingAccount { account }.verify_backup(&words).unwrap();
        assert!(genuine_instance(&verified).is_err());
    }
}

#[test]
fn privacy_label_change_preserves_both_derived_identifiers_and_import_is_unknown() {
    let generated = generate_verified();
    let words = generated.account.recovery_words().unwrap();
    let relabeled = DedicatedAccount::recover(&words, 0, "unrelated-new-label".into()).unwrap();
    assert!(
        BirthIdentity::derive(&generated.account).unwrap()
            == BirthIdentity::derive(&relabeled).unwrap()
    );
    assert!(relabeled.generated_instance.is_none());
}

#[test]
fn all_original_policy_fields_are_committed_without_genesis_digest_cycle() {
    let account = data_account();
    let terms = OriginalPolicyTerms::from_policy(&data_policy(&account)).unwrap();
    let digest = terms.digest().unwrap();
    let encoded = serde_json::to_value(&terms).unwrap();
    assert!(encoded.get("account_use_genesis").is_none());
    assert!(encoded.get("policy_digest").is_none());
    for (field, replacement) in [
        ("witness_id", serde_json::json!("another-witness")),
        ("account_id", serde_json::json!("77".repeat(32))),
        ("network_profile_id", serde_json::json!("another-network")),
        (
            "owner_certificate_digest",
            serde_json::json!("77".repeat(32)),
        ),
        (
            "initial_writer_certificate_digest",
            serde_json::json!("77".repeat(32)),
        ),
        ("initial_writer_epoch", serde_json::json!(2)),
        ("enrollment_refs", serde_json::json!(["77".repeat(32)])),
        ("agreement_ids", serde_json::json!(["another-agreement"])),
        (
            "recipient_scope_digests",
            serde_json::json!(["77".repeat(32)]),
        ),
        ("aggregate_budget_zatoshis", serde_json::json!(101)),
        ("per_operation_limit_zatoshis", serde_json::json!(91)),
        ("maximum_fee_share_zatoshis", serde_json::json!(6)),
        ("maximum_transaction_fee_zatoshis", serde_json::json!(11)),
        ("maximum_permit_lifetime_ms", serde_json::json!(60_001)),
        (
            "policy_expires_at_ms",
            serde_json::json!(1_800_000_000_001u64),
        ),
    ] {
        let mut changed = encoded.clone();
        changed[field] = replacement;
        let changed: OriginalPolicyTerms = serde_json::from_value(changed).unwrap();
        assert_ne!(changed.digest().unwrap(), digest, "{field}");
    }
}

#[test]
fn unknown_terms_or_inserted_genesis_fail_closed_at_projection() {
    let terms = OriginalPolicyTerms::from_policy(&data_policy(&data_account())).unwrap();
    for field in ["unreviewed_cap", "account_use_genesis", "policy_digest"] {
        let mut changed = serde_json::to_value(&terms).unwrap();
        changed[field] = serde_json::json!("untrusted-data");
        assert!(serde_json::from_value::<OriginalPolicyTerms>(changed).is_err());
    }
}

#[test]
fn modeled_anchor_detects_identity_origin_terms_generation_and_native_substitution() {
    let account = data_account();
    let anchor = data_anchor(&account);
    anchor.validate(&account).unwrap();
    let original = serde_json::to_value(&anchor).unwrap();
    for (pointer, replacement) in [
        (
            "/intent/operation_id",
            serde_json::json!(format!("birth-{}", "98".repeat(16))),
        ),
        (
            "/intent/generation_instance_id",
            serde_json::json!("98".repeat(32)),
        ),
        (
            "/intent/identity/account_id",
            serde_json::json!("98".repeat(32)),
        ),
        (
            "/intent/identity/full_viewing_key_digest",
            serde_json::json!("98".repeat(32)),
        ),
        (
            "/intent/witness_origin/endpoint",
            serde_json::json!("127.0.0.1:444"),
        ),
        (
            "/intent/witness_origin/server_name",
            serde_json::json!("another.invalid"),
        ),
        (
            "/intent/witness_origin/pinned_server_certificate_digest",
            serde_json::json!("98".repeat(32)),
        ),
        (
            "/intent/original_policy_terms/aggregate_budget_zatoshis",
            serde_json::json!(101),
        ),
        (
            "/intent/native_principal_id",
            serde_json::json!("another-principal"),
        ),
        (
            "/intent/native_measurement",
            serde_json::json!("98".repeat(32)),
        ),
        (
            "/intent/original_target",
            serde_json::json!("/another/target"),
        ),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        let changed: BirthAnchor = serde_json::from_value(changed).unwrap();
        assert!(changed.validate(&account).is_err(), "{pointer}");
    }
}

#[test]
fn modeled_pending_plaintext_roundtrip_preserves_exact_audit_but_no_instance() {
    let account = data_account();
    let anchor = data_anchor(&account);
    let plain = encode_pending(&account, &anchor).unwrap();
    assert!(decode_pending(&plain).unwrap() == anchor);
    assert!(account.generated_instance.is_none());
    // An exact retry has no proposed origin/policy arguments and cannot replace
    // either field. Bounds, truncation, unknown versions and trailing bytes deny.
    for end in [0, 4, plain.len() - 1] {
        assert!(decode_pending(&plain[..end]).is_err());
    }
    let mut changed = plain.to_vec();
    changed[0] = 2;
    assert!(decode_pending(&changed).is_err());
    changed = plain.to_vec();
    changed[1..5].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(decode_pending(&changed).is_err());
    changed = plain.to_vec();
    changed.push(0);
    assert!(decode_pending(&changed).is_err());
}

#[test]
fn legacy_vault_route_discards_transient_generation_instance() {
    let verified = generate_verified();
    assert!(genuine_instance(&verified).is_ok());
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("legacy");
    let vault = AccountVault::create(&root, verified, b"synthetic-birth-test-password").unwrap();
    assert!(vault.account.generated_instance.is_none());
    drop(vault);
    let reopened = AccountVault::unlock(&root, b"synthetic-birth-test-password").unwrap();
    assert!(reopened.account.generated_instance.is_none());
}

#[test]
fn distinct_pending_header_cannot_be_opened_as_account_authority() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("modeled-pending");
    let directory = PrivateDirectory::create(&root).unwrap();
    // Header-only negative fixture; never a successful born account or native
    // decision. Rejection happens before KDF or plaintext parsing.
    let mut bytes = vec![0u8; 64];
    bytes[..8].copy_from_slice(PENDING_MAGIC);
    directory.write("account.wp", &bytes).unwrap();
    drop(directory);
    assert!(matches!(
        AccountVault::unlock(&root, b"synthetic-only"),
        Err(Error::InvalidData)
    ));
}

#[test]
fn pending_inventory_rejects_extra_files_symlinks_and_hardlinks() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("inventory-data-only");
    let directory = PrivateDirectory::create(&root).unwrap();
    directory.write("account.wp", b"modeled-data-only").unwrap();
    assert!(require_pending_inventory(&directory).is_ok());
    directory.write("unexpected", b"extra").unwrap();
    assert!(require_pending_inventory(&directory).is_err());
    std::fs::remove_file(root.join("unexpected")).unwrap();
    std::fs::hard_link(root.join("account.wp"), temp.path().join("hardlink")).unwrap();
    assert!(require_pending_inventory(&directory).is_err());
    std::fs::remove_file(temp.path().join("hardlink")).unwrap();
    std::fs::remove_file(root.join("account.wp")).unwrap();
    symlink(temp.path().join("missing"), root.join("account.wp")).unwrap();
    assert!(require_pending_inventory(&directory).is_err());
}
