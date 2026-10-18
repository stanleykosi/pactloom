//! Pure restrictions tests. No native lease, journal, authenticated intake or
//! fresh wallet observation is manufactured by these data-only fixtures.
use super::*;
use orchard::keys::SpendingKey;
use wholepact_core::manual_construction::{PreconstructionBirthday, PreconstructionProvider};
use wholepact_core::*;
use wholepact_wallet::wallet::{
    protected_sync::{
        durable_construction_v1::{ConstructionRecipientV1, ConstructionReviewerV1, PURPOSE},
        durable_exact_selection_v1::{DurableExactConstructionAnchorV1, DurableExactInputV1},
    },
    SelectionContext,
};

fn amount(value: u64) -> Amount {
    Amount::from_zatoshis(value).unwrap()
}

fn fixture() -> (
    DurableConstructionScopeV1,
    PreconstructionScope,
    DurableExactCaptureRestrictionsV1,
    FullViewingKey,
) {
    let fvk = FullViewingKey::from(&SpendingKey::from_bytes([7; 32]).unwrap());
    let other = FullViewingKey::from(&SpendingKey::from_bytes([9; 32]).unwrap());
    let accounts = [
        canonical_durable_account_id(&fvk),
        canonical_durable_account_id(&other),
    ];
    let receiver = encode_testnet_receiver(&other.address_at(0u32, Scope::External));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut scope = DurableConstructionScopeV1 {
        version: 2,
        purpose: PURPOSE.into(),
        proposal: ProposalInput {
            proposal_id: "restriction-only".into(),
            previous_proposal_id: None,
            manifest: ProposalManifest {
                agreement: AgreementDraft {
                    schema_version: 1,
                    agreement_id: "restriction-component".into(),
                    obligation_id: "never-funded".into(),
                    revision: 1,
                    purpose: "Inert restriction checks, no native or wallet authority".into(),
                    organizer_identity: "component".into(),
                    network_profile_id: "ironwood-testnet-nu7-candidate".into(),
                    recipients: vec![Recipient {
                        recipient_id: "recipient".into(),
                        address: receiver.clone(),
                        amount: amount(100_000),
                        memo: None,
                        instruction_provenance: "component".into(),
                    }],
                    funding_policy: FundingPolicy::Exact {
                        target: amount(100_000),
                    },
                    fee_policy: FeePolicy::ProRata,
                    privacy_profile: PrivacyProfile {
                        mode: PrivacyMode::DeclaredOperator,
                        proving_operator: Some("component".into()),
                        dedicated_accounts_required: true,
                    },
                    coordination_deadline: None,
                    confirmation_policy: ConfirmationPolicy::default(),
                    extensions: vec![],
                },
                participants: accounts
                    .iter()
                    .enumerate()
                    .map(|(i, account)| ParticipantAllocation {
                        participant_id: format!("participant-{i}"),
                        account_id: account.clone(),
                        contribution: amount(50_000),
                        fee_share: amount(5_000),
                        fee_cap: amount(5_000),
                        maximum_net_debit: amount(55_000),
                        charges: vec![],
                    })
                    .collect(),
                inputs: accounts
                    .iter()
                    .enumerate()
                    .map(|(i, account)| ClaimedInput {
                        input_id: format!("ironwood:{}:0", format!("{:02x}", 10 + i).repeat(32)),
                        participant_id: format!("participant-{i}"),
                        account_id: account.clone(),
                        amount: amount(55_000),
                        ownership_evidence_ref: None,
                    })
                    .collect(),
                outputs: vec![ClaimedOutput {
                    output_id: "recipient".into(),
                    address: receiver,
                    amount: amount(100_000),
                    allocation: OutputAllocation::Recipient {
                        recipient_id: "recipient".into(),
                    },
                }],
                transaction_fee: amount(10_000),
                expiry_height: 1_100,
            },
            artifact_digest: None,
            effects_commitment: None,
            created_at: "2026-10-18T00:00:00Z".into(),
        },
        account_id: accounts[0].clone(),
        participant_id: "participant-0".into(),
        privacy_domain: "component".into(),
        constructor: ConstructionRecipientV1 {
            principal_id: "component".into(),
            authenticated_local_grant_digest: "11".repeat(32),
        },
        prover: ConstructionRecipientV1 {
            principal_id: "component".into(),
            authenticated_local_grant_digest: "11".repeat(32),
        },
        reviewers: accounts
            .iter()
            .cloned()
            .map(ConstructionReviewerV1::local_installed_signer)
            .collect(),
        protected_destination: "/component/intake.sqlite".into(),
        retention_policy: "component only".into(),
        valid_from_unix_seconds: now - 1,
        valid_until_unix_seconds: now + 600,
        minimum_confirmations: 1,
        maximum_scan_blocks: 100,
    };
    // Keep the fixture canonical without pretending those labels authenticate an owner.
    scope
        .reviewers
        .sort_by(|a, b| a.account_id().cmp(b.account_id()));
    scope.validate().unwrap();
    let current = PreconstructionScope {
        schema_version: 1,
        proposal: scope.proposal.clone(),
        account_id: scope.account_id.clone(),
        participant_id: scope.participant_id.clone(),
        profile_id: "component".into(),
        principal_id: "component".into(),
        operator_name: "component".into(),
        operator_destination: scope.protected_destination.clone(),
        wallet_destination: "/component/wallet.sqlite".into(),
        reviewer_account_ids: accounts.to_vec(),
        privacy_domain: scope.privacy_domain.clone(),
        purpose: "construct_exact_accepted_candidate".into(),
        retention_policy: "component only".into(),
        provider: PreconstructionProvider {
            source_id: "component".into(),
            endpoint: "https://component.invalid".into(),
            trust_profile: "single_tls_provider_report_not_consensus".into(),
        },
        minimum_confirmations: 1,
        maximum_blocks: 100,
        anchor_height: 1_000,
        maximum_net_debit_zatoshis: 55_000,
        birthday: PreconstructionBirthday {
            prior_height: 900,
            prior_block_hash: "22".repeat(32),
            sapling_tree: String::new(),
            orchard_tree: String::new(),
            ironwood_tree: String::new(),
        },
    };
    current.validate().unwrap();
    let restrictions = DurableExactCaptureRestrictionsV1 {
        expected: DurableExactSelectionExpectationV1 {
            provider: BackendIdentity {
                source_id: current.provider.source_id.clone(),
                endpoint: current.provider.endpoint.clone(),
                trust_profile: "single_tls_provider_report_not_consensus",
            },
            original_context: SelectionContext {
                tip_height: 1_001,
                tip_hash_protocol: [1; 32],
                anchor_height: 1_000,
                anchor_hash_protocol: [2; 32],
                anchor_root: [3; 32],
            },
            construction_anchor: DurableExactConstructionAnchorV1 {
                height: 1_000,
                block_hash_protocol: [2; 32],
                root: [3; 32],
            },
            inputs: vec![DurableExactInputV1 {
                input_id: scope.proposal.manifest.inputs[0].input_id.clone(),
                value_zatoshis: 55_000,
                commitment: Some([4; 32]),
            }],
        },
        original_own_return_receiver: encode_testnet_receiver(
            &fvk.address_at(0u32, Scope::Internal),
        ),
    };
    (scope, current, restrictions, fvk)
}

#[test]
fn exact_restrictions_bind_all_commitments_and_actual_return_even_without_change() {
    let (scope, current, good, fvk) = fixture();
    let provider = good.expected.provider.clone();
    good.require_matches(&scope, &current, &provider, &fvk)
        .unwrap();
    for kind in 0..9 {
        let mut bad = good.clone();
        match kind {
            0 => bad.expected.inputs[0].commitment = None,
            1 => {
                bad.original_own_return_receiver =
                    encode_testnet_receiver(&fvk.address_at(1u32, Scope::Internal))
            }
            2 => bad.expected.provider.source_id.push('x'),
            3 => bad.expected.construction_anchor.root[0] ^= 1,
            4 => bad.expected.construction_anchor.block_hash_protocol[0] ^= 1,
            5 => bad.expected.inputs[0].input_id.push('0'),
            6 => bad.expected.inputs[0].value_zatoshis += 1,
            7 => bad.expected.inputs.push(bad.expected.inputs[0].clone()),
            _ => bad.expected.original_context.anchor_height = 0,
        }
        assert!(bad
            .require_matches(&scope, &current, &provider, &fvk)
            .is_err());
    }
    let wrong = FullViewingKey::from(&SpendingKey::from_bytes([9; 32]).unwrap());
    assert!(good
        .require_matches(&scope, &current, &provider, &wrong)
        .is_err());
}

#[test]
fn newly_explicit_anchor_preserves_original_context_and_requires_new_scope_height() {
    let (scope, mut current, good, fvk) = fixture();
    let mut newer = good.clone();
    newer.expected.construction_anchor = DurableExactConstructionAnchorV1 {
        height: 1_002,
        block_hash_protocol: [5; 32],
        root: [6; 32],
    };
    assert!(newer
        .require_matches(&scope, &current, &good.expected.provider, &fvk)
        .is_err());
    current.anchor_height = 1_002;
    newer
        .require_matches(&scope, &current, &good.expected.provider, &fvk)
        .unwrap();
    assert!(newer.expected.original_context == good.expected.original_context);
    assert!(newer.expected.inputs == good.expected.inputs);
    newer.expected.construction_anchor.height = 999;
    current.anchor_height = 999;
    assert!(newer
        .require_matches(&scope, &current, &good.expected.provider, &fvk)
        .is_err());
}

#[test]
fn current_source_is_deny_only_and_scope_clock_is_never_refreshed() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (mut scope, _, _, _) = fixture();
    require_use(&scope, &|| true).unwrap();
    assert!(require_use(&scope, &|| false).is_err());
    let calls = AtomicUsize::new(0);
    assert!(require_use(&scope, &|| calls.fetch_add(1, Ordering::SeqCst) == 0).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    scope.valid_from_unix_seconds = now - 2;
    scope.valid_until_unix_seconds = now - 1;
    assert!(require_use(&scope, &|| true).is_err());
}

#[test]
fn exact_return_is_checked_against_real_fvk_and_unchanged_accounting() {
    let (mut scope, mut current, mut restrictions, fvk) = fixture();
    scope.proposal.manifest.inputs[0].amount = amount(65_000);
    restrictions.expected.inputs[0].value_zatoshis = 65_000;
    scope.proposal.manifest.outputs.push(ClaimedOutput {
        output_id: "own-return".into(),
        address: restrictions.original_own_return_receiver.clone(),
        amount: amount(10_000),
        allocation: OutputAllocation::Return {
            participant_id: scope.participant_id.clone(),
            account_id: scope.account_id.clone(),
            ownership_evidence_ref: None,
        },
    });
    current.proposal = scope.proposal.clone();
    current.validate().unwrap();
    let provider = restrictions.expected.provider.clone();
    restrictions
        .require_matches(&scope, &current, &provider, &fvk)
        .unwrap();
    scope.proposal.manifest.outputs[1].address =
        encode_testnet_receiver(&fvk.address_at(1u32, Scope::Internal));
    current.proposal = scope.proposal.clone();
    current.validate().unwrap();
    assert!(restrictions
        .require_matches(&scope, &current, &provider, &fvk)
        .is_err());
}
