//! All cryptographic values below are synthetic, public, never-funded fixtures.
//! These tests exercise storage plumbing, not native permission or chain evidence.
#[cfg(target_os = "linux")]
#[path = "roundtrip_tests.rs"]
mod roundtrip_tests;

use super::*;
use std::os::unix::fs::PermissionsExt;

fn request(fvk_digest: &str) -> ManualRosterInventoryRequestV2 {
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
    let roster_request = serde_json::json!({
        "version":2,"operation_id":request["operation_id"],
        "scope":{"version":2,"inventory":request["scope"],"provenance":{
            "version":2,"original_host_audit":{"kind":"additional_publication_v3","audit_digest":h("a1")},
            "roster":{"version":2,"generation_id":h("01"),
                "store_destination_identity":"/synthetic/host/coordination.sqlite","roster_sequence":2,
                "predecessor":{"kind":"initial_publication_v2","audit_digest":h("a2")}},
            "signer_roster_record_digest":h("a3"),"witness_roster_extension_digest":h("a4")}},
        "current_caller_binding_digest":request["current_caller_binding_digest"],
        "requested_at_ms":request["requested_at_ms"],"disclosure_expires_at_ms":request["disclosure_expires_at_ms"]
    });
    let result: ManualRosterInventoryRequestV2 = serde_json::from_value(roster_request).unwrap();
    result.validate().unwrap();
    result
}
fn request_for_wallet(
    directory: &tempfile::TempDir,
    fvk_digest: &str,
) -> ManualRosterInventoryRequestV2 {
    let mut request = request(fvk_digest);
    let path = std::fs::canonicalize(directory.path()).unwrap();
    request
        .scope
        .inventory
        .attachment
        .selected
        .canonical_directory = path.to_str().unwrap().into();
    request.scope.inventory.wallet_destination =
        path.join("wallet.sqlite").to_str().unwrap().into();
    request.validate().unwrap();
    request
}
fn intent() -> Intent {
    let request = request(&"19".repeat(32));
    Intent {
        version: 2,
        importer: IMPORTER.into(),
        request_digest: request.digest().unwrap(),
        actual_wallet_destination: request.scope.inventory.wallet_destination.clone(),
        request,
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
        DedicatedTestnetWallet::from_encrypted_connection_recordable_roster_import_v2(connection)
            .unwrap();
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
    future.version = 3;
    assert!(future.validate().is_err());
    assert!(decode::<Intent>(&vec![b' '; MAX_RECORD + 1]).is_err());
}
#[test]
fn full_checkpoint_owner_generation_and_native_evidence_are_not_height_only() {
    let original = intent();
    let digest = original.digest().unwrap();
    for which in 0..19 {
        let mut other = original.clone();
        match which {
            0 => other.request.scope.inventory.birthday.prior_block_hash = "31".repeat(32),
            1 => other.request.scope.inventory.birthday.sapling_tree = "00000100".into(),
            2 => other.request.scope.inventory.birthday.orchard_tree = "00000100".into(),
            3 => other.request.scope.inventory.birthday.ironwood_tree = "00000100".into(),
            4 => other.request.scope.inventory.enrollment.host.generation_id = "32".repeat(32),
            5 => other.request.scope.inventory.enrollment.host.profile_id = "other".into(),
            6 => {
                other
                    .request
                    .scope
                    .inventory
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
                    .inventory
                    .enrollment
                    .identity
                    .full_viewing_key_digest = "36".repeat(32)
            }
            10 => other.request.scope.inventory.enrollment.identity.network_profile_id = "other".into(),
            11 => other.request.scope.provenance.original_host_audit = wholepact_core::manual_roster_inventory_v2::OriginalHostRosterAuditV3::AdditionalPublicationV3 { audit_digest: "37".repeat(32) },
            12 => other.request.scope.provenance.roster.roster_sequence += 1,
            13 => other.request.scope.provenance.signer_roster_record_digest = "38".repeat(32),
            14 => other.request.scope.provenance.witness_roster_extension_digest = "39".repeat(32),
            15 => other.request.scope.inventory.wallet_destination = "/synthetic/other/wallet.sqlite".into(),
            16 => other.request.current_caller_binding_digest = "3a".repeat(32),
            17 => other.request.disclosure_expires_at_ms += 1,
            _ => other.request_digest = "3b".repeat(32),
        }
        assert_ne!(digest, other.digest().unwrap());
    }
}
#[test]
fn completed_import_is_actual_uuid_and_reopen_cannot_mint_fresh_owner() {
    let (directory, key, mut wallet) = fresh();
    let fvk = public_fvk();
    let request = request_for_wallet(&directory, &hex::encode(Sha256::digest(fvk.to_bytes())));
    let receipt = wallet
        .import_recorded_roster_inventory_fvk_v2(&fvk, &request, &"44".repeat(32))
        .unwrap();
    assert_eq!(
        wallet.db.get_account_ids().unwrap(),
        vec![receipt.account_uuid()]
    );
    receipt
        .check_request_scope_and_account(
            &request.digest().unwrap(),
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
        wallet.import_recorded_roster_inventory_fvk_v2(&fvk, &request, &"44".repeat(32)),
        Err(RecordedRosterImportErrorV2::FreshOwnerRequired)
    ));
    drop(wallet);
    let connection = wholepact_storage_security::open_encrypted_quiescent(
        directory.path().join("wallet.sqlite"),
        &key,
    )
    .unwrap();
    assert!(
        DedicatedTestnetWallet::from_encrypted_connection_recordable_roster_import_v2(connection)
            .is_err()
    );
    let connection = wholepact_storage_security::open_encrypted_quiescent(
        directory.path().join("wallet.sqlite"),
        &key,
    )
    .unwrap();
    let mut reopened = DedicatedTestnetWallet::from_encrypted_connection(connection).unwrap();
    assert!(matches!(
        reopened.import_recorded_roster_inventory_fvk_v2(&fvk, &request, &"44".repeat(32)),
        Err(RecordedRosterImportErrorV2::FreshOwnerRequired)
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
    raw.connection().execute_batch("CREATE TRIGGER ext_synthetic_fail_completion BEFORE INSERT ON ext_wholepact_roster_import_records_v2 WHEN NEW.sequence=1 BEGIN SELECT RAISE(ABORT,'synthetic-failure'); END;").unwrap();
    drop(raw);
    let fvk = public_fvk();
    let request = request_for_wallet(&directory, &hex::encode(Sha256::digest(fvk.to_bytes())));
    assert!(
        wallet
            .import_recorded_roster_inventory_fvk_v2(&fvk, &request, &"44".repeat(32))
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
        wallet.import_recorded_roster_inventory_fvk_v2(&fvk, &request, &"44".repeat(32)),
        Err(RecordedRosterImportErrorV2::FreshOwnerRequired)
    ));
}
#[test]
fn generic_import_is_not_retrospective_recorded_import_even_for_matching_key_and_height() {
    let (directory, _key, mut wallet) = fresh();
    let fvk = public_fvk();
    let request = request_for_wallet(&directory, &hex::encode(Sha256::digest(fvk.to_bytes())));
    let mut expected = intent();
    expected.request = request.clone();
    wallet
        .import_dedicated_fvk(&fvk, expected.birthday().unwrap())
        .unwrap();
    assert!(
        wallet
            .import_recorded_roster_inventory_fvk_v2(&fvk, &request, &"44".repeat(32))
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
fn v1_factory_and_v2_factory_cannot_issue_each_others_receipts() {
    let (directory, _key, mut v2) = fresh();
    let fvk = public_fvk();
    let request = request_for_wallet(&directory, &hex::encode(Sha256::digest(fvk.to_bytes())));
    // Only synthetic inert data is projected for this negative compatibility test.
    let v1 = wholepact_core::manual_inventory::ManualPreliminaryInventoryRequest {
        version: 1,
        operation_id: request.operation_id.clone(),
        scope: request.scope.inventory.clone(),
        current_caller_binding_digest: request.current_caller_binding_digest.clone(),
        requested_at_ms: request.requested_at_ms,
        disclosure_expires_at_ms: request.disclosure_expires_at_ms,
    };
    assert!(matches!(
        v2.import_recorded_preliminary_fvk(&fvk, &v1, &"44".repeat(32)),
        Err(crate::wallet::recorded_import::RecordedImportError::FreshOwnerRequired)
    ));
    assert!(
        v2.import_recorded_roster_inventory_fvk_v2(&fvk, &request, &"44".repeat(32))
            .is_ok()
    );
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let key = wholepact_storage_security::DatabaseKey::from_bytes([0x65; 32]);
    let connection =
        wholepact_storage_security::create_encrypted(directory.path().join("wallet.sqlite"), &key)
            .unwrap();
    let mut v1 =
        DedicatedTestnetWallet::from_encrypted_connection_recordable_import(connection).unwrap();
    assert!(matches!(
        v1.import_recorded_roster_inventory_fvk_v2(&fvk, &request, &"44".repeat(32)),
        Err(RecordedRosterImportErrorV2::FreshOwnerRequired)
    ));
}

#[test]
fn mismatched_destination_denies_before_durable_intent_and_consumes_fresh_owner() {
    let (_directory, _key, mut wallet) = fresh();
    let fvk = public_fvk();
    let request = request(&hex::encode(Sha256::digest(fvk.to_bytes())));
    assert!(matches!(
        wallet.import_recorded_roster_inventory_fvk_v2(&fvk, &request, &"44".repeat(32)),
        Err(RecordedRosterImportErrorV2::Binding)
    ));
    wallet
        .db
        .transactionally_with_extension(|db, ext| -> Result<()> {
            assert_eq!(count(ext)?, 0);
            assert!(db.get_account_ids().unwrap().is_empty());
            Ok(())
        })
        .unwrap();
    assert!(matches!(
        wallet.import_recorded_roster_inventory_fvk_v2(&fvk, &request, &"44".repeat(32)),
        Err(RecordedRosterImportErrorV2::FreshOwnerRequired)
    ));
}

#[test]
fn request_and_native_evidence_commitments_cannot_be_relabelled() {
    let original = intent();
    for version in [0, 1, 3, u16::MAX] {
        let mut wrong = original.clone();
        wrong.version = version;
        assert!(wrong.validate().is_err());
        let mut wrong = original.clone();
        wrong.request.version = version;
        assert!(wrong.validate().is_err());
        let mut wrong = original.clone();
        wrong.request.scope.version = version;
        assert!(wrong.validate().is_err());
        let mut wrong = original.clone();
        wrong.request.scope.provenance.version = version;
        assert!(wrong.validate().is_err());
    }
    let mut wrong = original.clone();
    wrong.request.scope.provenance.signer_roster_record_digest = "bc".repeat(32);
    assert!(wrong.validate().is_err()); // Old full-request digest cannot describe new provenance.
    let mut unknown = serde_json::to_value(&original).unwrap();
    unknown["request"]["scope"]["provenance"]["original_host_audit"]["kind"] =
        "enrollment_v1".into();
    assert!(decode::<Intent>(&serde_json::to_vec(&unknown).unwrap()).is_err());
    let mut wrong = original.clone();
    wrong.native_disclosure_evidence_digest = "invalid".into();
    assert!(wrong.validate().is_err());
}

#[test]
fn receipt_checks_full_request_and_scope_not_only_key_and_birthday() {
    let (directory, _key, mut wallet) = fresh();
    let fvk = public_fvk();
    let request = request_for_wallet(&directory, &hex::encode(Sha256::digest(fvk.to_bytes())));
    let receipt = wallet
        .import_recorded_roster_inventory_fvk_v2(&fvk, &request, &"44".repeat(32))
        .unwrap();
    assert_eq!(receipt.request_digest(), request.digest().unwrap());
    let scope = request.scope.pairing_digest().unwrap();
    let account = receipt.account_uuid();
    let mut other = request.clone();
    other.current_caller_binding_digest = "45".repeat(32);
    assert_eq!(other.scope.pairing_digest().unwrap(), scope);
    assert!(
        receipt
            .check_request_scope_and_account(&other.digest().unwrap(), &scope, account)
            .is_err()
    );
    other.scope.provenance.witness_roster_extension_digest = "46".repeat(32);
    assert!(
        receipt
            .check_request_scope_and_account(
                receipt.request_digest(),
                &other.scope.pairing_digest().unwrap(),
                account
            )
            .is_err()
    );
}

#[test]
fn mismatched_record_format_and_completion_request_deny_without_repair() {
    let (directory, key, mut wallet) = fresh();
    let fvk = public_fvk();
    let request = request_for_wallet(&directory, &hex::encode(Sha256::digest(fvk.to_bytes())));
    let receipt = wallet
        .import_recorded_roster_inventory_fvk_v2(&fvk, &request, &"44".repeat(32))
        .unwrap();
    wallet
        .db
        .transactionally_with_extension(|_, ext| -> Result<()> {
            let i = load::<Intent>(ext, 0)?;
            let mut c = load::<Completion>(ext, 1)?;
            c.request_digest = "47".repeat(32);
            assert!(c.require_intent(&i).is_err());
            Ok(())
        })
        .unwrap();
    drop(receipt);
    let connection = wholepact_storage_security::open_encrypted_quiescent(
        directory.path().join("wallet.sqlite"),
        &key,
    )
    .unwrap();
    // Deliberate SQL constraint bypass only in this synthetic adversarial fixture.
    connection.connection().execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE ext_wholepact_roster_import_records_v2 SET format_version=1 WHERE sequence=0; PRAGMA ignore_check_constraints=OFF;").unwrap();
    drop(connection);
    wallet.db.transactionally_with_extension(|_,ext| -> Result<()> {
        assert!(load::<Intent>(ext,0).is_err());
        let version: i64 = ext.query_row("SELECT format_version FROM ext_wholepact_roster_import_records_v2 WHERE sequence=0",[],|r|r.get(0))?;
        assert_eq!(version,1); // Reader did not rewrite or adopt historical bytes.
        Ok(())
    }).unwrap();
}
