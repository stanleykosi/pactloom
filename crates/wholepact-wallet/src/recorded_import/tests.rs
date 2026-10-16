//! All cryptographic values below are synthetic, public, never-funded fixtures.
//! These tests exercise storage plumbing, not native permission or chain evidence.
#[cfg(target_os = "linux")]
#[path = "roundtrip_tests.rs"]
mod roundtrip_tests;

use super::*;
use std::os::unix::fs::PermissionsExt;

fn request(fvk_digest: &str) -> ManualPreliminaryInventoryRequest {
    let h = |byte: &str| byte.repeat(32);
    let network = wholepact_protocol::construction::PROFILE_ID;
    let policy = serde_json::json!({
        "version":2,"account_id":h("11"),"network_profile_id":network,
        "agreement_id":"agreement","obligation_id":"obligation","participant_id":"alice",
        "recipients":[{"recipient_id":"recipient","address":"uSyntheticRecipient","memo":null,
            "instruction_provenance":"synthetic owner instruction","maximum_amount_zatoshis":50}],
        "charges":[],"original_limits":{"aggregate_budget_zatoshis":100,"per_operation_limit_zatoshis":60,
            "maximum_fee_share_zatoshis":3,"maximum_transaction_fee_zatoshis":5,
            "maximum_permit_lifetime_ms":120000,"policy_expires_at_ms":500000},
        "own_return_rule":"authenticated_same_account"
    });
    let policy: wholepact_core::born_recipient_policy_v2::BornConstructionRecipientPolicyV2 =
        serde_json::from_value(policy).unwrap();
    let enrollment = serde_json::json!({
        "version":1,"operation_id":"synthetic-enrollment",
        "identity":{"account_id":h("11"),"full_viewing_key_digest":fvk_digest,"network_profile_id":network,"derivation_domain":DERIVATION},
        "birth_request_digest":h("22"),"birth_commit_digest":h("33"),"native_birth_digest":h("44"),
        "original_policy_digest":h("55"),"account_use_genesis_digest":h("66"),"original_witness_origin_digest":h("77"),
        "host":{"generation_id":h("01"),"inventory_digest":h("02"),"generation_plan_digest":h("03"),
            "financial_journal_origin_digest":h("04"),"store_destination_identity":"/synthetic/host/coordination.sqlite",
            "profile_id":"synthetic-host","canonical_root":"/synthetic/host","destination_identity_digest":h("05"),
            "inherited_identity_digest":h("06"),"scope_predecessor_digest":null},
        "signer":{"enrollment_generation_id":h("07"),"signer_target_digest":h("08"),"original_envelope_digest":h("09"),
            "owner_certificate_digest":h("0a"),"writer_certificate_digest":h("0b"),"writer_epoch":1,"native_signer_measurement":h("0c")},
        "scope":{"agreement_id":"agreement","obligation_id":"obligation","participant_id":"alice","principal_id":"synthetic-principal",
            "privacy_domain":"synthetic-domain","recipient_scope_digests":[policy.digest().unwrap()],"aggregate_budget_zatoshis":100,
            "per_operation_limit_zatoshis":50,"maximum_fee_share_zatoshis":2,"maximum_transaction_fee_zatoshis":5,
            "maximum_permit_lifetime_ms":500,"expires_at_ms":200000},
        "transport_binding_digest":h("0d"),"issued_at_ms":1000
    });
    let request = serde_json::json!({
        "version":1,"operation_id":"synthetic-preliminary-import",
        "scope":{"version":1,"enrollment":enrollment,"enrollment_ref":h("0e"),"witness_extension_digest":h("0f"),
            "attempt":{"version":2,"continuation_digest":h("10"),"attempt_sequence":2},"original_recipient_policy":policy,
            "attachment":{"version":1,"original_primary_journal_origin_digest":h("04"),"predecessor_registry_digest":h("12"),
                "current_registry_digest":h("13"),"latest_extension_digest":h("14"),
                "selected":{"account_id":h("11"),"canonical_directory":"/synthetic/wallet","directory_identity_digest":h("15"),"journal_origin_digest":h("16")}},
            "operator_name":"synthetic-operator","operator_destination":"/synthetic/operator",
            "wallet_destination":"/synthetic/wallet/wallet.sqlite","purpose":"preliminary_inventory_only",
            "retention_policy":"local synthetic test only","provider":{"source_id":"synthetic-provider","endpoint":"https://synthetic.invalid",
                "trust_profile":"single_tls_provider_report_not_consensus"},
            "birthday":{"prior_height":4465025,"prior_block_hash":h("17"),"sapling_tree":"000000","orchard_tree":"000000","ironwood_tree":"000000"},
            "minimum_confirmations":1,"maximum_blocks":10,"anchor_height":4465027},
        "current_caller_binding_digest":h("18"),"requested_at_ms":2000,"disclosure_expires_at_ms":32000
    });
    let result: ManualPreliminaryInventoryRequest = serde_json::from_value(request).unwrap();
    result.validate().unwrap();
    result
}
fn intent() -> Intent {
    Intent {
        version: 1,
        importer: IMPORTER.into(),
        request: request(&"19".repeat(32)),
        native_disclosure_evidence_digest: "20".repeat(32),
        wallet_database_origin_digest: "21".repeat(32),
        actual_network: "zcash_testnet".into(),
        actual_key_type: "ufvk_r0_orchard_only".into(),
        actual_account_purpose: "imported_spending_derivation_none".into(),
        recover_until: None,
    }
}
fn public_fvk() -> FullViewingKey {
    let sk = orchard::keys::SpendingKey::from_zip32_seed(&[0x63; 64], 1, 0u32.try_into().unwrap())
        .unwrap();
    FullViewingKey::from(&sk)
}
fn fresh() -> (
    tempfile::TempDir,
    wholepact_storage_security::DatabaseKey,
    DedicatedTestnetWallet,
) {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let key = wholepact_storage_security::DatabaseKey::from_bytes([0x64; 32]);
    let connection =
        wholepact_storage_security::create_encrypted(directory.path().join("wallet.sqlite"), &key)
            .unwrap();
    let wallet =
        DedicatedTestnetWallet::from_encrypted_connection_recordable_import(connection).unwrap();
    (directory, key, wallet)
}

#[test]
fn canonical_codec_rejects_unknown_duplicate_whitespace_version_and_excess_size() {
    let original = intent();
    original.validate().unwrap();
    let bytes = encode(&original).unwrap();
    assert!(decode::<Intent>(&bytes).unwrap() == original);
    let mut unknown = serde_json::to_value(&original).unwrap();
    unknown["native_approved"] = true.into();
    assert!(decode::<Intent>(&serde_json::to_vec(&unknown).unwrap()).is_err());
    let mut whitespace = bytes.to_vec();
    whitespace.push(b' ');
    assert!(decode::<Intent>(&whitespace).is_err());
    let duplicate = String::from_utf8(bytes.to_vec())
        .unwrap()
        .replacen("{", "{\"version\":1,", 1);
    assert!(decode::<Intent>(duplicate.as_bytes()).is_err());
    let mut future = original.clone();
    future.version = 2;
    assert!(future.validate().is_err());
    assert!(decode::<Intent>(&vec![b' '; MAX_RECORD + 1]).is_err());
}
#[test]
fn full_checkpoint_owner_generation_and_native_evidence_are_not_height_only() {
    let original = intent();
    let digest = original.digest().unwrap();
    for which in 0..11 {
        let mut other = original.clone();
        match which {
            0 => other.request.scope.birthday.prior_block_hash = "31".repeat(32),
            1 => other.request.scope.birthday.sapling_tree = "00000100".into(),
            2 => other.request.scope.birthday.orchard_tree = "00000100".into(),
            3 => other.request.scope.birthday.ironwood_tree = "00000100".into(),
            4 => other.request.scope.enrollment.host.generation_id = "32".repeat(32),
            5 => other.request.scope.enrollment.host.profile_id = "other".into(),
            6 => {
                other
                    .request
                    .scope
                    .attachment
                    .selected
                    .journal_origin_digest = "33".repeat(32)
            }
            7 => other.wallet_database_origin_digest = "34".repeat(32),
            8 => other.native_disclosure_evidence_digest = "35".repeat(32),
            9 => {
                other
                    .request
                    .scope
                    .enrollment
                    .identity
                    .full_viewing_key_digest = "36".repeat(32)
            }
            _ => other.request.scope.enrollment.identity.network_profile_id = "other".into(),
        }
        assert_ne!(digest, other.digest().unwrap());
    }
}
#[test]
fn completed_import_is_actual_uuid_and_reopen_cannot_mint_fresh_owner() {
    let (directory, key, mut wallet) = fresh();
    let fvk = public_fvk();
    let request = request(&hex::encode(Sha256::digest(fvk.to_bytes())));
    let receipt = wallet
        .import_recorded_preliminary_fvk(&fvk, &request, &"44".repeat(32))
        .unwrap();
    assert_eq!(
        wallet.db.get_account_ids().unwrap(),
        vec![receipt.account_uuid()]
    );
    receipt
        .check_scope_and_account(
            &request.scope.pairing_digest().unwrap(),
            receipt.account_uuid(),
        )
        .unwrap();
    wallet
        .db
        .transactionally_with_extension(|_, ext| -> Result<()> {
            assert_eq!(count(ext)?, 2);
            let i = load::<Intent>(ext, 0)?;
            let c = load::<Completion>(ext, 1)?;
            c.require_intent(&i)?;
            assert_eq!(
                c.returned_account_uuid,
                *receipt.account_uuid().expose_uuid().as_bytes()
            );
            Ok(())
        })
        .unwrap();
    assert!(matches!(
        wallet.import_recorded_preliminary_fvk(&fvk, &request, &"44".repeat(32)),
        Err(RecordedImportError::FreshOwnerRequired)
    ));
    drop(wallet);
    let connection = wholepact_storage_security::open_encrypted_quiescent(
        directory.path().join("wallet.sqlite"),
        &key,
    )
    .unwrap();
    assert!(
        DedicatedTestnetWallet::from_encrypted_connection_recordable_import(connection).is_err()
    );
    let connection = wholepact_storage_security::open_encrypted_quiescent(
        directory.path().join("wallet.sqlite"),
        &key,
    )
    .unwrap();
    let mut reopened = DedicatedTestnetWallet::from_encrypted_connection(connection).unwrap();
    assert!(matches!(
        reopened.import_recorded_preliminary_fvk(&fvk, &request, &"44".repeat(32)),
        Err(RecordedImportError::FreshOwnerRequired)
    ));
}
#[test]
fn completion_write_failure_rolls_back_account_but_retains_intent_and_consumes_issuer() {
    let (directory, key, mut wallet) = fresh();
    // A deliberate synthetic fault. This unknown trigger is not a supported
    // layout and is never installed by the product or the production issuer.
    let raw =
        wholepact_storage_security::open_encrypted(directory.path().join("wallet.sqlite"), &key)
            .unwrap();
    raw.connection().execute_batch("CREATE TRIGGER ext_synthetic_fail_completion BEFORE INSERT ON ext_wholepact_import_records WHEN NEW.sequence=1 BEGIN SELECT RAISE(ABORT,'synthetic-failure'); END;").unwrap();
    drop(raw);
    let fvk = public_fvk();
    let request = request(&hex::encode(Sha256::digest(fvk.to_bytes())));
    assert!(
        wallet
            .import_recorded_preliminary_fvk(&fvk, &request, &"44".repeat(32))
            .is_err()
    );
    assert!(wallet.db.get_account_ids().unwrap().is_empty());
    wallet
        .db
        .transactionally_with_extension(|_, ext| -> Result<()> {
            assert_eq!(count(ext)?, 1);
            load::<Intent>(ext, 0)?.validate()
        })
        .unwrap();
    assert!(matches!(
        wallet.import_recorded_preliminary_fvk(&fvk, &request, &"44".repeat(32)),
        Err(RecordedImportError::FreshOwnerRequired)
    ));
}
#[test]
fn generic_import_is_not_retrospective_recorded_import_even_for_matching_key_and_height() {
    let (_directory, _key, mut wallet) = fresh();
    let fvk = public_fvk();
    let request = request(&hex::encode(Sha256::digest(fvk.to_bytes())));
    let mut expected = intent();
    expected.request = request.clone();
    wallet
        .import_dedicated_fvk(&fvk, expected.birthday().unwrap())
        .unwrap();
    assert!(
        wallet
            .import_recorded_preliminary_fvk(&fvk, &request, &"44".repeat(32))
            .is_err()
    );
    wallet
        .db
        .transactionally_with_extension(|_, ext| -> Result<()> {
            assert_eq!(count(ext)?, 0);
            Ok(())
        })
        .unwrap();
}

#[test]
fn committed_birthday_diagnostic_comes_from_actual_import_and_keeps_earliest_history_unknown() {
    let (_directory, _key, mut wallet) = fresh();
    let fvk = public_fvk();
    let request = request(&hex::encode(Sha256::digest(fvk.to_bytes())));
    let owner = wallet
        .import_recorded_preliminary_fvk(&fvk, &request, &"44".repeat(32))
        .unwrap();
    let report = owner
        .evidence_for_scope(
            &request.scope.pairing_digest().unwrap(),
            owner.account_uuid(),
        )
        .unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_eq!(
        value["first_scan_height"],
        request.scope.birthday.prior_height + 1
    );
    assert_eq!(
        value["returned_wallet_account_uuid"],
        owner.account_uuid().expose_uuid().to_string()
    );
    assert_eq!(
        value["chosen_prior_block_hash"],
        request.scope.birthday.prior_block_hash
    );
    assert_eq!(
        value["chosen_full_birthday_digest"],
        wholepact_core::proposal::canonical_digest(
            "wholepact:recorded-import-chosen-birthday:v1",
            &request.scope.birthday
        )
        .unwrap()
    );
    assert_eq!(value["intent_digest"], owner.intent_digest());
    assert_eq!(
        value["earliest_account_activity"],
        "unknown_chosen_boundary_is_not_account_birth"
    );
    assert_eq!(
        value["complete_pending_history"],
        "unknown_import_does_not_ingest_full_pending_history"
    );
    assert_eq!(value["retirement_completion"], "unavailable");
    wallet
        .db
        .transactionally_with_extension(|_, ext| -> Result<()> {
            let c = load::<Completion>(ext, 1)?;
            assert_eq!(
                value["completion_digest"],
                wholepact_core::proposal::canonical_digest(
                    "wholepact:recorded-import-completion-evidence:v1",
                    &c
                )
                .unwrap()
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn import_diagnostic_cannot_be_rebound_to_another_birthday_or_scope() {
    let (_directory, _key, mut wallet) = fresh();
    let fvk = public_fvk();
    let request = request(&hex::encode(Sha256::digest(fvk.to_bytes())));
    let owner = wallet
        .import_recorded_preliminary_fvk(&fvk, &request, &"44".repeat(32))
        .unwrap();
    let mut changed = request.scope.clone();
    changed.birthday.prior_block_hash = "55".repeat(32);
    assert!(
        owner
            .evidence_for_scope(&changed.pairing_digest().unwrap(), owner.account_uuid())
            .is_err()
    );
    assert!(
        owner
            .evidence_for_scope(&"66".repeat(32), owner.account_uuid())
            .is_err()
    );
    assert!(
        owner
            .evidence_for_scope(
                &request.scope.pairing_digest().unwrap(),
                owner.account_uuid()
            )
            .is_ok()
    );
}
