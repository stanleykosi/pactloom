//! Data/negative tests only. No PendingBirthEntry, native owner, NativeDecision,
//! funded account, witness or socket fixture is constructed. These are UNRUN.
use super::*;

fn setup_json() -> serde_json::Value {
    let policy: AccountPolicy = serde_json::from_value(serde_json::json!({
        "witness_id": "synthetic-original-witness",
        "account_id": "11".repeat(32),
        "network_profile_id": "ironwood-testnet-nu7-candidate",
        "owner_certificate_digest": "22".repeat(32),
        "initial_writer_certificate_digest": "33".repeat(32),
        "initial_writer_epoch": 1,
        "enrollment_refs": ["44".repeat(32)],
        "agreement_ids": ["synthetic-agreement"],
        "recipient_scope_digests": ["55".repeat(32)],
        "aggregate_budget_zatoshis": 100,
        "per_operation_limit_zatoshis": 90,
        "maximum_fee_share_zatoshis": 5,
        "maximum_transaction_fee_zatoshis": 10,
        "maximum_permit_lifetime_ms": 60_000,
        "policy_expires_at_ms": 1_800_000_000_000u64
    }))
    .unwrap();
    serde_json::json!({
        "disclosure": {
            "endpoint": "127.0.0.1:443",
            "server_name": "synthetic.invalid",
            "witness_id": "synthetic-original-witness",
            "account_id": "11".repeat(32),
            "network_profile_id": "ironwood-testnet-nu7-candidate",
            "policy_digest": policy.policy_digest().unwrap(),
            "pinned_server_certificate_digest": "66".repeat(32)
        },
        "original_policy": policy
    })
}
fn parse(value: &serde_json::Value) -> Result<PublicBirthSetup> {
    parse_setup(
        &serde_json::to_string(value).unwrap(),
        &"11".repeat(32),
        "ironwood-testnet-nu7-candidate",
    )
}

#[test]
fn public_setup_parser_binds_actual_account_network_witness_and_policy_digest() {
    let original = setup_json();
    assert!(parse(&original).is_ok()); // Data validity only, never native authority.
    for (pointer, replacement) in [
        ("/disclosure/account_id", serde_json::json!("77".repeat(32))),
        (
            "/original_policy/account_id",
            serde_json::json!("77".repeat(32)),
        ),
        (
            "/disclosure/network_profile_id",
            serde_json::json!("other-network"),
        ),
        (
            "/original_policy/network_profile_id",
            serde_json::json!("other-network"),
        ),
        ("/disclosure/witness_id", serde_json::json!("other-witness")),
        (
            "/original_policy/witness_id",
            serde_json::json!("other-witness"),
        ),
        (
            "/disclosure/policy_digest",
            serde_json::json!("77".repeat(32)),
        ),
        (
            "/original_policy/aggregate_budget_zatoshis",
            serde_json::json!(101),
        ),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        assert!(parse(&changed).is_err(), "{pointer}");
    }
}

#[test]
fn public_setup_rejects_unknown_credentials_and_oversized_input() {
    let original = setup_json();
    for pointer in ["", "/disclosure", "/original_policy"] {
        let mut changed = original.clone();
        changed.pointer_mut(pointer).unwrap()["private_key"] =
            serde_json::json!("public-test-marker-not-a-key");
        assert!(parse(&changed).is_err());
    }
    assert!(
        parse_setup(
            &" ".repeat(MAX_SETUP_BYTES + 1),
            &"11".repeat(32),
            "ironwood-testnet-nu7-candidate"
        )
        .is_err()
    );
}

#[test]
fn public_setup_rejects_existing_genesis_before_backup_is_consumed() {
    let mut changed = setup_json();
    changed["original_policy"]["account_use_genesis"] = serde_json::json!({
        "version": 1,
        "identity": {
            "account_id": "11".repeat(32),
            "full_viewing_key_digest": "77".repeat(32),
            "network_profile_id": "ironwood-testnet-nu7-candidate",
            "derivation_domain": "dedicated-testnet-legacy-zip32-v1"
        },
        "witness_id": "synthetic-original-witness",
        "witness_origin_digest": "88".repeat(32),
        "owner_certificate_digest": "22".repeat(32),
        "native_birth_digest": "99".repeat(32)
    });
    let policy: AccountPolicy = serde_json::from_value(changed["original_policy"].clone()).unwrap();
    changed["disclosure"]["policy_digest"] = serde_json::json!(policy.policy_digest().unwrap());
    assert!(parse(&changed).is_err());
}

#[test]
fn public_setup_rejects_invalid_origin_or_cap_even_when_data_is_well_formed_json() {
    let original = setup_json();
    for (pointer, replacement) in [
        ("/disclosure/endpoint", serde_json::json!("0.0.0.0:443")),
        (
            "/disclosure/pinned_server_certificate_digest",
            serde_json::json!("not-a-hash"),
        ),
        (
            "/original_policy/aggregate_budget_zatoshis",
            serde_json::json!(0),
        ),
        (
            "/original_policy/initial_writer_epoch",
            serde_json::json!(0),
        ),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        assert!(parse(&changed).is_err());
    }
}

impl NativeBirthCeremony {
    pub(in crate::native_ui) fn data_only_draft_fixture() -> Self {
        let mut fixture = Self::default();
        fixture.root = PathBuf::from("/synthetic-data-only");
        fixture.password = Zeroizing::new("synthetic-not-a-real-password".into());
        fixture.backup = Zeroizing::new("public data, not a mnemonic".into());
        fixture.setup = Zeroizing::new("public unvalidated setup draft".into());
        fixture.confirmation = Zeroizing::new("not-an-authorization".into());
        fixture
    }
    pub(in crate::native_ui) fn data_only_drafts_empty(&self) -> bool {
        self.root.as_os_str().is_empty()
            && self.password.is_empty()
            && self.backup.is_empty()
            && self.setup.is_empty()
            && self.confirmation.is_empty()
    }
}

#[test]
fn draft_only_clear_erases_every_private_buffer_without_creating_authority() {
    let mut draft = NativeBirthCeremony::data_only_draft_fixture();
    assert!(!draft.is_active());
    assert!(draft.owner.is_none());
    assert!(draft.current_owner(0).is_err());
    draft.clear();
    assert!(draft.data_only_drafts_empty());
    assert!(draft.owner.is_none());
    assert!(draft.phase.is_none());
}

#[test]
fn no_owner_cannot_stage_continue_or_publish_a_birth() {
    let mut draft = NativeBirthCeremony::data_only_draft_fixture();
    assert!(draft.stage_backup_and_review(0).is_err());
    assert!(draft.continue_review(true, 0).is_err());
    assert!(draft.publish_from_native_click(true, 0).is_err());
    assert!(draft.phase.is_none());
    assert!(draft.owner.is_none());
}

fn construction_draft_fixture() -> (String, String, String, String) {
    let (accepted, _, _) = crate::manifest::tests::consent_fixture();
    let proposal = accepted.proposal.input().clone();
    let account = proposal.manifest.participants[0].account_id.clone();
    let network = proposal.manifest.agreement.network_profile_id.clone();
    let mut value = setup_json();
    value["disclosure"]["account_id"] = serde_json::json!(account);
    value["disclosure"]["network_profile_id"] = serde_json::json!(network);
    value["original_policy"]["account_id"] = serde_json::json!(account);
    value["original_policy"]["network_profile_id"] = serde_json::json!(network);
    value["original_policy"]["agreement_ids"] =
        serde_json::json!([proposal.manifest.agreement.agreement_id]);
    let policy: AccountPolicy = serde_json::from_value(value["original_policy"].clone()).unwrap();
    value["disclosure"]["policy_digest"] = serde_json::json!(policy.policy_digest().unwrap());
    (
        serde_json::to_string(&value).unwrap(),
        serde_json::to_string(&proposal).unwrap(),
        account,
        network,
    )
}
#[test]
fn construction_scope_helper_changes_only_unpublished_scope_and_matching_policy_digest() {
    let (setup, proposal, account, network) = construction_draft_fixture();
    let original = parse_setup(&setup, &account, &network).unwrap();
    let (updated, digest) =
        derive_construction_draft(&setup, &proposal, &account, &network).unwrap();
    let derived = parse_setup(&updated, &account, &network).unwrap();
    let mut expected = original.original_policy.clone();
    expected.recipient_scope_digests.push(digest.clone());
    expected.recipient_scope_digests.sort();
    assert!(derived.original_policy == expected);
    assert_eq!(
        derived.disclosure.policy_digest,
        expected.policy_digest().unwrap()
    );
    assert_eq!(derived.disclosure.endpoint, original.disclosure.endpoint);
    assert_eq!(
        derived.disclosure.pinned_server_certificate_digest,
        original.disclosure.pinned_server_certificate_digest
    );
    let (retry, retry_digest) =
        derive_construction_draft(&updated, &proposal, &account, &network).unwrap();
    assert_eq!(retry.as_str(), updated.as_str());
    assert_eq!(retry_digest, digest);
    assert_eq!(
        parse_setup(&setup, &account, &network)
            .unwrap()
            .original_policy
            .recipient_scope_digests
            .len(),
        1
    );
}
#[test]
fn construction_scope_helper_rejects_wrong_actual_account_network_and_malformed_proposal() {
    let (setup, proposal, account, network) = construction_draft_fixture();
    assert!(derive_construction_draft(&setup, &proposal, "different-account", &network).is_err());
    assert!(derive_construction_draft(&setup, &proposal, &account, "different-network").is_err());
    for invalid in ["{}".to_owned(), " ".repeat(MAX_SETUP_BYTES + 1)] {
        assert!(derive_construction_draft(&setup, &invalid, &account, &network).is_err());
    }
    let mut wrong_agreement: serde_json::Value = serde_json::from_str(&setup).unwrap();
    wrong_agreement["original_policy"]["agreement_ids"] =
        serde_json::json!(["different-agreement"]);
    let p: AccountPolicy =
        serde_json::from_value(wrong_agreement["original_policy"].clone()).unwrap();
    wrong_agreement["disclosure"]["policy_digest"] = serde_json::json!(p.policy_digest().unwrap());
    assert!(
        derive_construction_draft(&wrong_agreement.to_string(), &proposal, &account, &network)
            .is_err()
    );
}
#[test]
fn construction_scope_ui_requires_actual_pending_owner_and_clear_erases_draft_inputs() {
    let mut ui = NativeBirthCeremony::default();
    ui.setup = Zeroizing::new("unchanged draft".into());
    ui.construction_proposal = Zeroizing::new("private proposal draft".into());
    ui.construction_scope_preview = Zeroizing::new("private derived scope".into());
    assert!(ui.derive_construction_scope(1).is_err());
    assert_eq!(ui.setup.as_str(), "unchanged draft");
    ui.clear();
    assert!(ui.construction_proposal.is_empty());
    assert!(ui.construction_scope_preview.is_empty());
    assert!(!ui.is_active());
}
