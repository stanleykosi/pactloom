//! Read-only correlation with an already completed roster import. Historical
//! records never recreate the import receipt, its create-only owner, or consent.
use super::*;
use wholepact_core::manual_roster_inventory_v2::ManualRosterInventoryScopeV2;

/// Check immutable import history and its actual account under the caller's held
/// wallet transaction. `db` and `ext` must be the pair supplied by the same
/// `transactionally_with_extension` call on the authenticated existing wallet.
/// The caller retains native permission, file identity and recovery checks.
///
/// This checks archival request validity, not whether its expired create-time
/// disclosure is current. Only the caller's fresh post-return permission can
/// authorize the present read. Success is deliberately `()`, not an import token.
pub(crate) fn verify_post_return_history_v1<D>(
    db: &D,
    ext: &ExtensionTransaction<'_>,
    expected: &ManualRosterInventoryScopeV2,
    expected_origin: &str,
    account: AccountUuid,
    fvk: &FullViewingKey,
) -> Result<()>
where
    D: WalletRead<AccountId = AccountUuid>,
{
    expected
        .validate()
        .map_err(|_| RecordedRosterImportErrorV2::Binding)?;
    hash(expected_origin)?;

    // Check the complete row set and bounds before copying any blob into memory,
    // even if a damaged/replaced schema no longer enforces the original CHECKs.
    if count(ext)? != 2 {
        return Err(RecordedRosterImportErrorV2::Incomplete);
    }
    let bounded_rows: i64 = ext.query_row(
        "SELECT count(*) FROM ext_wholepact_roster_import_records_v2
         WHERE typeof(sequence)='integer' AND sequence IN (0,1)
         AND typeof(format_version)='integer' AND format_version=2
         AND typeof(record)='blob' AND length(record) BETWEEN 1 AND ?1",
        [MAX_RECORD as i64],
        |row| row.get(0),
    )?;
    if bounded_rows != 2 {
        return Err(RecordedRosterImportErrorV2::Binding);
    }
    let intent = load::<Intent>(ext, 0)?;
    let completion = load::<Completion>(ext, 1)?;
    require_completed(ext, &intent, &completion)?;
    if &intent.request.scope != expected
        || intent.wallet_database_origin_digest != expected_origin
        || completion.returned_account_uuid != *account.expose_uuid().as_bytes()
    {
        return Err(RecordedRosterImportErrorV2::Binding);
    }

    let fvk_bytes = Zeroizing::new(fvk.to_bytes());
    let fvk_digest = hex::encode(Sha256::digest(fvk_bytes.as_slice()));
    if fvk_digest != completion.actual_fvk_digest
        || fvk_digest
            != expected
                .inventory
                .enrollment
                .identity
                .full_viewing_key_digest
    {
        return Err(RecordedRosterImportErrorV2::Binding);
    }
    // Reconstruct the complete importer encoding, not only an Orchard receiver.
    // A broader everyday UFVK with the same Orchard key must never pass.
    let unified = unified::Ufvk::try_from_items(
        zcash_protocol::address::Revision::R0,
        vec![unified::Uitem::Data(unified::Fvk::Orchard(*fvk_bytes))],
    )
    .map_err(|_| RecordedRosterImportErrorV2::Binding)?;
    let expected_encoding = Zeroizing::new(unified.encode(&NetworkType::Test));
    if hex::encode(Sha256::digest(expected_encoding.as_bytes()))
        != completion.actual_ufvk_encoding_digest
        || db
            .get_account_ids()
            .map_err(|_| RecordedRosterImportErrorV2::Storage)?
            != vec![account]
    {
        return Err(RecordedRosterImportErrorV2::Binding);
    }
    let actual = db
        .get_account(account)
        .map_err(|_| RecordedRosterImportErrorV2::Storage)?
        .ok_or(RecordedRosterImportErrorV2::Binding)?;
    let actual_encoding = Zeroizing::new(
        actual
            .ufvk()
            .ok_or(RecordedRosterImportErrorV2::Binding)?
            .encode_revision(&TEST_NETWORK, zcash_protocol::address::Revision::R0)
            .map_err(|_| RecordedRosterImportErrorV2::Binding)?,
    );
    if actual.id() != account
        || actual_encoding.as_str() != expected_encoding.as_str()
        || u32::from(
            db.get_account_birthday(account)
                .map_err(|_| RecordedRosterImportErrorV2::Storage)?,
        ) != completion.first_scan_height
        || db
            .get_wallet_recover_until()
            .map_err(|_| RecordedRosterImportErrorV2::Storage)?
            .is_some()
        || !matches!(actual.source(), AccountSource::Imported {
            purpose: AccountPurpose::Spending { derivation: None }, key_source
        } if key_source.as_deref() == Some(KEY_SOURCE))
    {
        return Err(RecordedRosterImportErrorV2::Binding);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Only public never-funded keys and SQLite :memory: fixtures. No files,
    //! native permissions, historical receipt minting, or chain evidence.
    use super::*;

    pub(super) fn synthetic_request(fvk_digest: &str) -> ManualRosterInventoryRequestV2 {
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
        let result: ManualRosterInventoryRequestV2 =
            serde_json::from_value(roster_request).unwrap();
        result.validate().unwrap();
        result
    }

    fn public_fvk(seed: u8) -> FullViewingKey {
        let sk =
            orchard::keys::SpendingKey::from_zip32_seed(&[seed; 64], 1, 0u32.try_into().unwrap())
                .unwrap();
        FullViewingKey::from(&sk)
    }
    fn encoding(fvk: &FullViewingKey, extra: bool) -> String {
        let mut items = vec![unified::Uitem::Data(unified::Fvk::Orchard(fvk.to_bytes()))];
        if extra {
            items.push(unified::Uitem::Data(unified::Fvk::Unknown {
                typecode: 7,
                data: vec![0x52; 32],
            }));
        }
        unified::Ufvk::try_from_items(zcash_protocol::address::Revision::R0, items)
            .unwrap()
            .encode(&NetworkType::Test)
    }
    struct Fixture {
        connection: rusqlite::Connection,
        intent: Intent,
        completion: Completion,
        account: AccountUuid,
        fvk: FullViewingKey,
    }
    impl Fixture {
        fn new() -> Self {
            let mut connection = rusqlite::Connection::open_in_memory().unwrap();
            connection.set_transaction_behavior(rusqlite::TransactionBehavior::Immediate);
            rusqlite::vtab::array::load_module(&connection).unwrap();
            let fvk = public_fvk(0x73);
            let fvk_digest = hex::encode(Sha256::digest(fvk.to_bytes()));
            let request = synthetic_request(&fvk_digest);
            let intent = Intent {
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
            };
            let encoded = encoding(&fvk, false);
            let ufvk = UnifiedFullViewingKey::decode(&TEST_NETWORK, &encoded).unwrap();
            let account = {
                let mut db = WalletDb::from_connection(
                    &mut connection,
                    TEST_NETWORK,
                    SystemClock,
                    UnwrapErr(SysRng),
                );
                zcash_client_sqlite::wallet::init::init_wallet_db(&mut db, None).unwrap();
                db.import_account_ufvk(
                    "public in-memory fixture",
                    &ufvk,
                    &intent.birthday().unwrap(),
                    AccountPurpose::Spending { derivation: None },
                    Some(KEY_SOURCE),
                )
                .unwrap()
                .id()
            };
            let completion = Completion {
                version: 2,
                intent_digest: intent.digest().unwrap(),
                request_digest: intent.request_digest.clone(),
                wallet_database_origin_digest: intent.wallet_database_origin_digest.clone(),
                returned_account_uuid: *account.expose_uuid().as_bytes(),
                actual_fvk_digest: fvk_digest,
                actual_ufvk_encoding_digest: hex::encode(Sha256::digest(encoded.as_bytes())),
                first_scan_height: intent.request.scope.inventory.birthday.prior_height + 1,
            };
            completion.require_intent(&intent).unwrap();
            connection
                .execute_batch(super::super::super::SCHEMA)
                .unwrap();
            for (sequence, bytes) in [
                (0, encode(&intent).unwrap()),
                (1, encode(&completion).unwrap()),
            ] {
                connection
                    .execute(
                        "INSERT INTO ext_wholepact_roster_import_records_v2 VALUES(?1,2,?2)",
                        rusqlite::params![sequence, bytes.as_slice()],
                    )
                    .unwrap();
            }
            Self {
                connection,
                intent,
                completion,
                account,
                fvk,
            }
        }
        fn verify_with(
            &mut self,
            scope: &ManualRosterInventoryScopeV2,
            origin: &str,
            fvk: &FullViewingKey,
        ) -> Result<()> {
            let account = self.account;
            WalletDb::from_connection(
                &mut self.connection,
                TEST_NETWORK,
                SystemClock,
                UnwrapErr(SysRng),
            )
            .transactionally_with_extension(|db, ext| {
                verify_post_return_history_v1(db, ext, scope, origin, account, fvk)
            })
        }
        fn verify(&mut self) -> Result<()> {
            let scope = self.intent.request.scope.clone();
            let origin = self.intent.wallet_database_origin_digest.clone();
            let fvk = self.fvk.clone();
            self.verify_with(&scope, &origin, &fvk)
        }
        fn rewrite_completion(&self, completion: &Completion) {
            self.connection
                .execute(
                    "UPDATE ext_wholepact_roster_import_records_v2 SET record=?1 WHERE sequence=1",
                    [encode(completion).unwrap().as_slice()],
                )
                .unwrap();
        }
    }

    #[test]
    fn completed_history_is_repeatable_read_only_and_in_memory() {
        let mut fixture = Fixture::new();
        let changes = fixture.connection.total_changes();
        let file: String = fixture
            .connection
            .query_row(
                "SELECT file FROM pragma_database_list WHERE name='main'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(file.is_empty());
        fixture.verify().unwrap();
        fixture.verify().unwrap();
        assert_eq!(fixture.connection.total_changes(), changes);
        let rows: i64 = fixture
            .connection
            .query_row(
                "SELECT count(*) FROM ext_wholepact_roster_import_records_v2",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rows, 2);
    }

    #[test]
    fn scope_origin_and_authenticated_fvk_must_match_exactly() {
        let mut fixture = Fixture::new();
        let scope = fixture.intent.request.scope.clone();
        let origin = fixture.intent.wallet_database_origin_digest.clone();
        let fvk = fixture.fvk.clone();
        let mut wrong_scope = scope.clone();
        wrong_scope.inventory.birthday.prior_block_hash = "31".repeat(32);
        assert!(fixture.verify_with(&wrong_scope, &origin, &fvk).is_err());
        wrong_scope = scope.clone();
        wrong_scope.provenance.witness_roster_extension_digest = "32".repeat(32);
        assert!(fixture.verify_with(&wrong_scope, &origin, &fvk).is_err());
        assert!(fixture.verify_with(&scope, &"33".repeat(32), &fvk).is_err());
        assert!(
            fixture
                .verify_with(&scope, &origin, &public_fvk(0x74))
                .is_err()
        );
        fixture.verify().unwrap();
    }

    #[test]
    fn completion_is_not_an_account_or_key_lookup_claim() {
        let mut fixture = Fixture::new();
        for which in 0..8 {
            let mut completion = fixture.completion.clone();
            match which {
                0 => completion.version = 3,
                1 => completion.intent_digest = "41".repeat(32),
                2 => completion.request_digest = "42".repeat(32),
                3 => completion.wallet_database_origin_digest = "43".repeat(32),
                4 => completion.returned_account_uuid = [0x44; 16],
                5 => completion.actual_fvk_digest = "45".repeat(32),
                6 => completion.actual_ufvk_encoding_digest = "46".repeat(32),
                _ => completion.first_scan_height += 1,
            }
            fixture.rewrite_completion(&completion);
            assert!(
                fixture.verify().is_err(),
                "changed completion field {which}"
            );
        }
        fixture.rewrite_completion(&fixture.completion);
        fixture.verify().unwrap();
    }

    #[test]
    fn canonical_rows_are_bounded_complete_and_not_extensible() {
        let mut fixture = Fixture::new();
        let canonical = encode(&fixture.completion).unwrap();
        let mut whitespace = canonical.to_vec();
        whitespace.push(b' ');
        let mut unknown = serde_json::to_value(&fixture.completion).unwrap();
        unknown["approved"] = true.into();
        let duplicate = String::from_utf8(canonical.to_vec())
            .unwrap()
            .replacen("{", "{\"version\":2,", 1)
            .into_bytes();
        // Deliberately bypass schema CHECKs only in this disposable in-memory
        // corruption fixture, proving the reader does not rely on those bounds.
        fixture
            .connection
            .execute_batch("PRAGMA ignore_check_constraints=ON")
            .unwrap();
        for bytes in [
            whitespace,
            serde_json::to_vec(&unknown).unwrap(),
            duplicate,
            vec![],
            vec![b' '; MAX_RECORD + 1],
        ] {
            fixture
                .connection
                .execute(
                    "UPDATE ext_wholepact_roster_import_records_v2 SET record=?1 WHERE sequence=1",
                    [bytes],
                )
                .unwrap();
            assert!(fixture.verify().is_err());
        }
        fixture.rewrite_completion(&fixture.completion);
        fixture.connection.execute(
            "UPDATE ext_wholepact_roster_import_records_v2 SET format_version=3 WHERE sequence=1", [],
        ).unwrap();
        assert!(fixture.verify().is_err());
        fixture.connection.execute(
            "UPDATE ext_wholepact_roster_import_records_v2 SET format_version=2 WHERE sequence=1", [],
        ).unwrap();
        fixture
            .connection
            .execute(
                "INSERT INTO ext_wholepact_roster_import_records_v2 VALUES(2,2,?1)",
                [canonical.as_slice()],
            )
            .unwrap();
        assert!(fixture.verify().is_err());
        fixture
            .connection
            .execute(
                "DELETE FROM ext_wholepact_roster_import_records_v2 WHERE sequence IN (1,2)",
                [],
            )
            .unwrap();
        assert!(matches!(
            fixture.verify(),
            Err(RecordedRosterImportErrorV2::Incomplete)
        ));
    }

    #[test]
    fn actual_account_purpose_source_birthday_and_full_ufvk_are_checked() {
        let mut fixture = Fixture::new();
        for (corrupt, restore) in [
            (
                "UPDATE accounts SET key_source='other'",
                "UPDATE accounts SET key_source='explicit local signer viewing export'",
            ),
            (
                "UPDATE accounts SET has_spend_key=0",
                "UPDATE accounts SET has_spend_key=1",
            ),
            (
                "UPDATE accounts SET birthday_height=birthday_height+1",
                "UPDATE accounts SET birthday_height=birthday_height-1",
            ),
            (
                "UPDATE accounts SET recover_until_height=birthday_height+1",
                "UPDATE accounts SET recover_until_height=NULL",
            ),
        ] {
            fixture.connection.execute(corrupt, []).unwrap();
            assert!(fixture.verify().is_err());
            fixture.connection.execute(restore, []).unwrap();
            fixture.verify().unwrap();
        }
        let broad_encoding = encoding(&fixture.fvk, true);
        let broad = UnifiedFullViewingKey::decode(&TEST_NETWORK, &broad_encoding).unwrap();
        assert_eq!(broad.orchard().unwrap().to_bytes(), fixture.fvk.to_bytes());
        fixture
            .connection
            .execute("UPDATE accounts SET ufvk=?1", [&broad_encoding])
            .unwrap();
        assert!(fixture.verify().is_err());
        fixture
            .connection
            .execute(
                "UPDATE accounts SET ufvk=?1",
                [encoding(&fixture.fvk, false)],
            )
            .unwrap();
        fixture.verify().unwrap();
        let extra_fvk = public_fvk(0x75);
        let extra =
            UnifiedFullViewingKey::decode(&TEST_NETWORK, &encoding(&extra_fvk, false)).unwrap();
        WalletDb::from_connection(
            &mut fixture.connection,
            TEST_NETWORK,
            SystemClock,
            UnwrapErr(SysRng),
        )
        .import_account_ufvk(
            "second public fixture",
            &extra,
            &fixture.intent.birthday().unwrap(),
            AccountPurpose::Spending { derivation: None },
            Some(KEY_SOURCE),
        )
        .unwrap();
        assert!(fixture.verify().is_err());
    }
}

#[cfg(all(test, target_os = "linux"))]
mod post_return_scope_tests {
    use super::tests::synthetic_request;
    use crate::wallet::protected_sync::born_post_return_inputs_v1::{
        BornPostReturnInputV1, BornPostReturnWalletScopeV1,
    };
    fn scope() -> BornPostReturnWalletScopeV1 {
        let input = BornPostReturnInputV1 {
            input_id: format!("ironwood:{}:0", "42".repeat(32)),
            nullifier: "43".repeat(32),
            value_zatoshis: 50,
            action_index: 0,
        };
        BornPostReturnWalletScopeV1 {
            checkpoint_binding_digest: "44".repeat(32),
            final_transaction_digest: "45".repeat(32),
            final_transaction_id: "46".repeat(32),
            final_effects_digest: "47".repeat(32),
            transaction_expiry_height: 4465100,
            all_inputs: vec![input.clone()],
            own_inputs: vec![input],
            import_scope: synthetic_request(&"48".repeat(32)).scope,
            wallet_origin_digest: "49".repeat(32),
            provider_read_profile: wholepact_chain::public_read_profile_v1::PublicReadProfileV1 {
                backend: wholepact_chain::BackendIdentity {
                    source_id: "synthetic-provider".into(),
                    endpoint: "https://synthetic.invalid".into(),
                    trust_profile: "single_tls_provider_report_not_consensus",
                },
                route: wholepact_chain::public_read_profile_v1::PublicReadRouteV1::Direct,
                destination_tls_native_roots: true,
                request_timeout_ms: 10000,
                retries: 1,
                retry_delay_ms: 250,
                maximum_response_bytes: 4 * 1024 * 1024,
                observation_ttl_ms: 60000,
                maximum_tip_age_ms: 1200000,
                maximum_clock_skew_ms: 30000,
                maximum_reported_height_gap: 2,
            },
            anchor_height: 4465027,
            anchor_hash: [0x50; 32],
            anchor_root: [0x51; 32],
            original_ancestry: vec![(4465028, [0x52; 32])],
            maximum_tip_height: 4465090,
            minimum_confirmations: 1,
            minimum_expiry_margin_blocks: 10,
            maximum_scan_runtime_ms: 30_000,
            native_observation_expires_at_ms: 190000,
        }
    }
    #[test]
    fn fresh_post_return_scope_commits_final_transaction_full_input_set_and_private_origins() {
        let original = scope();
        let digest = original.digest().unwrap();
        for change in 0..10 {
            let mut other = original.clone();
            match change {
                0 => other.final_transaction_id = "61".repeat(32),
                1 => other.final_transaction_digest = "62".repeat(32),
                2 => other.checkpoint_binding_digest = "63".repeat(32),
                3 => other.wallet_origin_digest = "64".repeat(32),
                4 => other.anchor_root = [0x65; 32],
                5 => other.original_ancestry[0].1 = [0x66; 32],
                6 => other.all_inputs.push(BornPostReturnInputV1 {
                    input_id: format!("ironwood:{}:1", "67".repeat(32)),
                    nullifier: "68".repeat(32),
                    value_zatoshis: 25,
                    action_index: 1,
                }),
                7 => other.native_observation_expires_at_ms -= 1,
                8 => other.maximum_scan_runtime_ms -= 1,
                _ => other.final_effects_digest = "69".repeat(32),
            }
            assert_ne!(other.digest().unwrap(), digest);
        }
    }
    #[test]
    fn fresh_post_return_scope_refuses_ambiguous_inputs_and_unbounded_reads() {
        let original = scope();
        original.validate().unwrap();
        for change in 0..12 {
            let mut other = original.clone();
            match change {
                0 => other.all_inputs.push(other.all_inputs[0].clone()),
                1 => other.own_inputs[0].value_zatoshis += 1,
                2 => other.own_inputs.push(other.own_inputs[0].clone()),
                3 => other.maximum_scan_runtime_ms = 30_001,
                4 => other.maximum_tip_height = other.transaction_expiry_height,
                5 => other.all_inputs[0].input_id = format!("ironwood:{}:00", "42".repeat(32)),
                6 => other.original_ancestry.push(other.original_ancestry[0]),
                7 => other.minimum_confirmations = 0,
                8 => other.minimum_expiry_margin_blocks = 0,
                9 => other.all_inputs[0].action_index = 8,
                10 => {
                    other.transaction_expiry_height = 4467028;
                    other.maximum_tip_height = 4466030;
                }
                _ => other.original_ancestry[0].0 = other.anchor_height - 1,
            }
            assert!(other.validate().is_err(), "mutation {change}");
        }
    }

    // Maintained scanner/note/witness COMPONENT qualification only. This never
    // manufactures a Fresh/Held observation or native/provider consent. Wallet
    // storage is SQLite :memory: and all keys/blocks are never-funded synthetic.
    fn scanned_note_scope() -> (
        crate::wallet::DedicatedTestnetWallet,
        crate::wallet::AccountUuid,
        crate::wallet::FullViewingKey,
        crate::wallet::SelectionContext,
        BornPostReturnWalletScopeV1,
        crate::wallet::qualification::Blocks,
    ) {
        let (mut wallet, account, fvk, current, blocks) =
            crate::wallet::qualification::synthetic_wallet();
        let selected = wallet
            .select_contribution(
                account,
                &fvk,
                "synthetic-component",
                100_000,
                std::num::NonZeroU32::MIN,
                &current,
                &[],
            )
            .unwrap();
        let mut scope = scope();
        scope.own_inputs = selected
            .evidence()
            .inputs
            .iter()
            .enumerate()
            .map(|(index, input)| BornPostReturnInputV1 {
                input_id: input.input_id.clone(),
                nullifier: hex::encode(input.nullifier),
                value_zatoshis: input.value_zatoshis,
                action_index: index,
            })
            .collect();
        scope.all_inputs = scope.own_inputs.clone();
        scope.anchor_height = current.anchor_height;
        scope.anchor_hash = current.anchor_hash_protocol;
        scope.anchor_root = current.anchor_root;
        scope.original_ancestry = vec![(current.tip_height, current.tip_hash_protocol)];
        scope.maximum_tip_height = current.tip_height + 10;
        scope.transaction_expiry_height = current.tip_height + 20;
        (wallet, account, fvk, current, scope, blocks)
    }
    #[test]
    fn maintained_post_return_note_and_witness_accept_only_exact_scanned_original() {
        use crate::wallet::protected_sync::born_post_return_inputs_v1::verify_maintained_post_return_notes_for_test as check;
        let (mut wallet, account, fvk, current, scope, _) = scanned_note_scope();
        assert_eq!(
            check(&mut wallet, &scope, &fvk, &current, account).unwrap(),
            1
        );
        for change in 0..8 {
            let mut scope = scope.clone();
            let mut current = current.clone();
            match change {
                0 => scope.own_inputs[0].nullifier = "91".repeat(32),
                1 => scope.own_inputs[0].value_zatoshis += 1,
                2 => scope.own_inputs[0].input_id = format!("ironwood:{}:0", "92".repeat(32)),
                3 => {
                    scope.anchor_root = [0x93; 32];
                    current.anchor_root = scope.anchor_root;
                } // actual tree rejects even matched caller fields
                4 => scope.original_ancestry[0].1 = [0x94; 32],
                5 => current.tip_height += 1,
                6 => scope.minimum_confirmations = 2,
                _ => {
                    scope.anchor_hash = [0x95; 32];
                    current.anchor_hash_protocol = scope.anchor_hash;
                }
            }
            assert!(
                check(&mut wallet, &scope, &fvk, &current, account).is_err(),
                "mutation {change}"
            );
        }
        // Failed reads and cached witness traversal never alter the original
        // spendability decision or create a native observation capability.
        assert_eq!(
            check(&mut wallet, &scope, &fvk, &current, account).unwrap(),
            1
        );
    }
    #[test]
    fn maintained_post_return_note_rejects_wrong_fvk_and_second_account() {
        use crate::wallet::protected_sync::born_post_return_inputs_v1::verify_maintained_post_return_notes_for_test as check;
        use crate::wallet::*;
        let (mut wallet, account, fvk, current, scope, _) = scanned_note_scope();
        let sk =
            orchard::keys::SpendingKey::from_zip32_seed(&[0x77; 64], 1, 0u32.try_into().unwrap())
                .unwrap();
        let other = FullViewingKey::from(&sk);
        assert!(check(&mut wallet, &scope, &other, &current, account).is_err());
        let prior = ChainState::empty(
            (current.tip_height - 1).into(),
            zcash_primitives::block::BlockHash([50; 32]),
        );
        let birthday = AccountBirthday::from_parts(prior, None);
        assert_eq!(
            wallet.import_dedicated_fvk(&other, birthday.clone()),
            Err(WalletError::AccountScope)
        );
        // Deliberately create an invalid multi-account fixture through the
        // maintained DB API. The production dedicated-wallet factory above
        // still refuses it; no production import boundary is weakened.
        let encoded = unified::Ufvk::try_from_items(
            zcash_protocol::address::Revision::R0,
            vec![unified::Uitem::Data(unified::Fvk::Orchard(
                other.to_bytes(),
            ))],
        )
        .unwrap()
        .encode(&NetworkType::Test);
        let ufvk = UnifiedFullViewingKey::decode(&TEST_NETWORK, &encoded).unwrap();
        wallet
            .db
            .import_account_ufvk(
                "second never-funded component fixture",
                &ufvk,
                &birthday,
                AccountPurpose::Spending { derivation: None },
                Some("synthetic component fixture"),
            )
            .unwrap();
        assert!(check(&mut wallet, &scope, &fvk, &current, account).is_err());
    }
    #[test]
    fn maintained_post_return_note_rejects_nullifier_spent_by_later_scanned_block() {
        use crate::wallet::protected_sync::born_post_return_inputs_v1::verify_maintained_post_return_notes_for_test as check;
        use crate::wallet::*;
        use incrementalmerkletree::frontier::Frontier;
        use zcash_client_backend::proto::compact_formats::{
            ChainMetadata, CompactBlock, CompactTx,
        };
        use zcash_primitives::block::BlockHash;
        let (mut wallet, account, fvk, mut current, scope, blocks) = scanned_note_scope();
        assert_eq!(
            check(&mut wallet, &scope, &fvk, &current, account).unwrap(),
            1
        );
        let tree = wallet
            .db
            .with_ironwood_tree_mut::<_, _, WalletError>(|t| Ok(t.frontier()?))
            .unwrap()
            .unwrap();
        let size = tree.tree_size() as u32;
        let prior = ChainState::new(
            current.tip_height.into(),
            BlockHash(current.tip_hash_protocol),
            Frontier::empty(),
            Frontier::empty(),
            tree,
        );
        let mut action = blocks.0[0].vtx[0].ironwood_actions[0].clone();
        action.nullifier = hex::decode(&scope.own_inputs[0].nullifier).unwrap();
        let spent = crate::wallet::qualification::Blocks(vec![CompactBlock {
            height: u64::from(current.tip_height + 1),
            hash: vec![52; 32],
            prev_hash: current.tip_hash_protocol.to_vec(),
            vtx: vec![CompactTx {
                txid: vec![53; 32],
                ironwood_actions: vec![action],
                ..Default::default()
            }],
            chain_metadata: Some(ChainMetadata {
                sapling_commitment_tree_size: 0,
                orchard_commitment_tree_size: 0,
                ironwood_commitment_tree_size: size + 1,
            }),
            ..Default::default()
        }]);
        wallet
            .scan_cached(&spent, &prior, 1, current.tip_height + 1)
            .unwrap();
        current.tip_height += 1;
        current.tip_hash_protocol = [52; 32];
        assert!(check(&mut wallet, &scope, &fvk, &current, account).is_err());
    }
}
