//! Pure, never-funded historical claims. No source authentication, native
//! approval, credential creation, history replay, storage, socket or clock use.
use crate::account_use::{AccountUseGenesis, AccountUseIdentity};
use crate::durable_delivery_scope_v2::*;
use crate::durable_payment_v1::{DurableFixedCandidateBindingV1, DurablePaymentAdmissionTermsV1};
use crate::manual_enrollment::ManualEnrollmentExtension;
use crate::manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2;
use crate::{AccountPolicy, InputReservation, WitnessDisclosureDescriptor, MAX_FRAME_BYTES, MAX_MONEY};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use wholepact_core::manual_construction::PreconstructionProvider;
use wholepact_core::manual_enrollment::{
    BornManualEnrollmentTerms, BornManualScope, BornManualSignerBinding, ManualAccountIdentity,
    ManualHostGenerationBinding,
};
use wholepact_core::manual_roster_v2::{HostRosterAppendBindingV2, HostRosterPredecessorV2};
use wholepact_core::{Proposal, ProposalInput};

fn h(c: char) -> String {
    c.to_string().repeat(64)
}

// Independent byte encodings, not a second validation or authority model.
fn expected_digest<T: Serialize>(domain: &str, value: &T) -> String {
    let mut hash = Sha256::new();
    hash.update(domain.as_bytes());
    hash.update([0]);
    hash.update(serde_json::to_vec(value).expect("serializable inert fixture"));
    hex::encode(hash.finalize())
}

fn expected_fixed_binding(fixed: &DurableFixedCandidateBindingV1) -> String {
    let mut hash = Sha256::new();
    hash.update(b"wholepact:durable-fixed-proposal:pczt-0.10.0-pre.1:v1\0");
    hash.update(fixed.schema_version.to_le_bytes());
    hash.update(fixed.revision.to_le_bytes());
    hash.update(fixed.expiry_height.to_le_bytes());
    for value in [
        &fixed.network_profile_id,
        &fixed.agreement_id,
        &fixed.obligation_id,
        &fixed.proposal_id,
        &fixed.proposal_digest,
        &fixed.manifest_digest,
        &fixed.unsigned_artifact_digest,
        &fixed.proved_artifact_digest,
        &fixed.effects_commitment,
        &fixed.policy_digest,
        &fixed.review_binding,
        &fixed.action_mapping_digest,
        &fixed.anchor,
    ] {
        hash.update((value.len() as u64).to_le_bytes());
        hash.update(value.as_bytes());
    }
    hex::encode(hash.finalize())
}

fn expected_authorization_id(fixed_binding: &str, account: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"wholepact:durable-manual-proposal-authorization:v1\0");
    for value in [fixed_binding, account] {
        hash.update((value.len() as u64).to_le_bytes());
        hash.update(value.as_bytes());
    }
    format!("durable-v1-{}", hex::encode(hash.finalize()))
}

#[derive(Clone)]
struct OriginalClaims {
    policy: AccountPolicy,
    extension: ManualRosterEnrollmentExtensionV2,
    proposal: Proposal,
    fixed: DurableFixedCandidateBindingV1,
    accepted_manifest_ref: String,
    original_writer_epoch: u64,
    witness: WitnessDisclosureDescriptor,
    inputs: Vec<InputReservation>,
    materials: Vec<DurableDeliveryMaterialScopeRefV2>,
}

impl OriginalClaims {
    fn matches(&self, scope: &DurableDeliveryScopeV2) -> crate::Result<()> {
        scope.matches_original_claims(
            &self.policy,
            &self.extension,
            &self.proposal,
            &self.fixed,
            &self.accepted_manifest_ref,
            self.original_writer_epoch,
            &self.witness,
            &self.inputs,
            &self.materials,
        )
    }
}

fn proposal() -> Proposal {
    let input: ProposalInput = serde_json::from_value(json!({
        "proposal_id": "delivery-proposal",
        "previous_proposal_id": null,
        "artifact_digest": null,
        "effects_commitment": null,
        "created_at": "2026-10-19T00:00:00Z",
        "manifest": {
            "agreement": {
                "schema_version": 1,
                "agreement_id": "delivery-agreement",
                "obligation_id": "delivery-obligation",
                "revision": 1,
                "purpose": "Never-funded pure durable delivery fixture",
                "organizer_identity": "fixture-organizer",
                "network_profile_id": "synthetic-testnet",
                "recipients": [{
                    "recipient_id": "fixture-recipient",
                    "address": "usyntheticrecipientnotforfunds",
                    "amount": "100",
                    "memo": null,
                    "instruction_provenance": "Unverified synthetic receiving claim"
                }],
                "funding_policy": {"kind": "exact", "target": "100"},
                "fee_policy": {"kind": "pro_rata"},
                "privacy_profile": {
                    "mode": "local_only", "proving_operator": null,
                    "dedicated_accounts_required": true
                },
                "coordination_deadline": null,
                "confirmation_policy": {"required_confirmations": 10},
                "extensions": []
            },
            "participants": [
                {"participant_id": "alice", "account_id": h('1'),
                 "contribution": "40", "fee_share": "2", "fee_cap": "2",
                 "maximum_net_debit": "42", "charges": []},
                {"participant_id": "bob", "account_id": h('2'),
                 "contribution": "60", "fee_share": "3", "fee_cap": "3",
                 "maximum_net_debit": "63", "charges": []}
            ],
            "inputs": [
                {"input_id": "input-alice", "participant_id": "alice",
                 "account_id": h('1'), "amount": "50", "ownership_evidence_ref": null},
                {"input_id": "input-bob", "participant_id": "bob",
                 "account_id": h('2'), "amount": "70", "ownership_evidence_ref": null}
            ],
            "outputs": [
                {"output_id": "recipient-output", "address": "usyntheticrecipientnotforfunds",
                 "amount": "100", "allocation": {"kind": "recipient", "recipient_id": "fixture-recipient"}},
                {"output_id": "alice-return", "address": "usyntheticreturnalice",
                 "amount": "8", "allocation": {"kind": "return", "participant_id": "alice",
                 "account_id": h('1'), "ownership_evidence_ref": null}},
                {"output_id": "bob-return", "address": "usyntheticreturnbob",
                 "amount": "7", "allocation": {"kind": "return", "participant_id": "bob",
                 "account_id": h('2'), "ownership_evidence_ref": null}}
            ],
            "transaction_fee": "5", "expiry_height": 140
        }
    })).expect("typed proposal fixture");
    Proposal::validate(input).expect("numerically consistent untrusted proposal")
}

fn fixture(owner: usize) -> (DurableDeliveryScopeV2, OriginalClaims) {
    assert!(owner < 2);
    let account = h(if owner == 0 { '1' } else { '2' });
    let participant = if owner == 0 { "alice" } else { "bob" };
    let owner_certificate = h(if owner == 0 { '3' } else { '4' });
    let writer_certificate = h(if owner == 0 { '5' } else { '6' });
    let fvk_digest = h(if owner == 0 { '7' } else { '8' });
    let proposal = proposal();
    let recipient_scope =
        wholepact_core::manual_construction::construction_recipient_scope_digest(&proposal)
            .expect("inert recipient commitment");
    let mut witness = WitnessDisclosureDescriptor {
        endpoint: if owner == 0 {
            "127.0.0.1:1911"
        } else {
            "127.0.0.1:1912"
        }
        .into(),
        server_name: "localhost".into(),
        witness_id: format!("fixture-witness-{participant}"),
        account_id: account.clone(),
        network_profile_id: "synthetic-testnet".into(),
        policy_digest: h('0'),
        pinned_server_certificate_digest: h('9'),
    };
    let genesis = AccountUseGenesis {
        version: 1,
        identity: AccountUseIdentity {
            account_id: account.clone(),
            full_viewing_key_digest: fvk_digest.clone(),
            network_profile_id: "synthetic-testnet".into(),
            derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
        },
        witness_id: witness.witness_id.clone(),
        witness_origin_digest: expected_digest(
            "wholepact:account-use-witness-origin:v1",
            &(
                &witness.endpoint,
                &witness.server_name,
                &witness.witness_id,
                &witness.pinned_server_certificate_digest,
            ),
        ),
        owner_certificate_digest: owner_certificate.clone(),
        native_birth_digest: h('a'),
    };
    let policy = AccountPolicy {
        account_use_genesis: Some(genesis.clone()),
        witness_id: witness.witness_id.clone(),
        account_id: account.clone(),
        network_profile_id: "synthetic-testnet".into(),
        owner_certificate_digest: owner_certificate.clone(),
        initial_writer_certificate_digest: writer_certificate.clone(),
        initial_writer_epoch: 1,
        enrollment_refs: vec![h('b')],
        agreement_ids: vec!["delivery-agreement".into()],
        recipient_scope_digests: vec![recipient_scope.clone()],
        aggregate_budget_zatoshis: 200,
        per_operation_limit_zatoshis: 100,
        maximum_fee_share_zatoshis: 5,
        maximum_transaction_fee_zatoshis: 5,
        maximum_permit_lifetime_ms: 1_000,
        policy_expires_at_ms: 1_000_000,
    };
    witness.policy_digest = policy.policy_digest().expect("inert original policy");
    let host = ManualHostGenerationBinding {
        generation_id: h('1'),
        inventory_digest: h('2'),
        generation_plan_digest: h('3'),
        financial_journal_origin_digest: h('4'),
        store_destination_identity: "synthetic-store".into(),
        profile_id: "synthetic-host-profile".into(),
        canonical_root: "/synthetic/host".into(),
        destination_identity_digest: h('5'),
        inherited_identity_digest: h('6'),
        scope_predecessor_digest: None,
    };
    let extension = ManualRosterEnrollmentExtensionV2 {
        version: 2,
        account_extension: ManualEnrollmentExtension {
            version: 1,
            terms: BornManualEnrollmentTerms {
                version: 1,
                operation_id: format!("fixture-enroll-{participant}"),
                identity: ManualAccountIdentity {
                    account_id: account.clone(),
                    full_viewing_key_digest: fvk_digest,
                    network_profile_id: "synthetic-testnet".into(),
                    derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
                },
                birth_request_digest: h('c'),
                birth_commit_digest: h('d'),
                native_birth_digest: genesis.native_birth_digest.clone(),
                original_policy_digest: witness.policy_digest.clone(),
                account_use_genesis_digest: genesis.digest().expect("inert genesis"),
                original_witness_origin_digest: genesis.witness_origin_digest.clone(),
                host: host.clone(),
                signer: BornManualSignerBinding {
                    enrollment_generation_id: h('7'),
                    signer_target_digest: h('8'),
                    original_envelope_digest: h('9'),
                    owner_certificate_digest: owner_certificate,
                    writer_certificate_digest: writer_certificate.clone(),
                    writer_epoch: 1,
                    native_signer_measurement: h('a'),
                },
                scope: BornManualScope {
                    agreement_id: "delivery-agreement".into(),
                    obligation_id: "delivery-obligation".into(),
                    participant_id: participant.into(),
                    principal_id: format!("original-owner-{participant}"),
                    privacy_domain: "synthetic-shared-domain".into(),
                    recipient_scope_digests: vec![recipient_scope.clone()],
                    aggregate_budget_zatoshis: 150,
                    per_operation_limit_zatoshis: 80,
                    maximum_fee_share_zatoshis: 5,
                    maximum_transaction_fee_zatoshis: 5,
                    maximum_permit_lifetime_ms: 1_000,
                    expires_at_ms: 900_000,
                },
                transport_binding_digest: h('b'),
                issued_at_ms: 50_000,
            },
            enrollment_ref: h('c'),
            enrollment_record_digest: h('c'),
            sequence: 1,
            predecessor_digest: None,
        },
        roster: HostRosterAppendBindingV2 {
            version: 2,
            generation_id: host.generation_id.clone(),
            store_destination_identity: host.store_destination_identity.clone(),
            roster_sequence: 2,
            predecessor: HostRosterPredecessorV2::InitialPublicationV2 {
                audit_digest: h('d'),
            },
        },
        signer_roster_record_digest: h('e'),
    };
    let mut fixed = DurableFixedCandidateBindingV1 {
        schema_version: 1,
        network_profile_id: "synthetic-testnet".into(),
        agreement_id: "delivery-agreement".into(),
        obligation_id: "delivery-obligation".into(),
        proposal_id: "delivery-proposal".into(),
        revision: 1,
        expiry_height: 140,
        proposal_digest: proposal.proposal_digest().into(),
        manifest_digest: proposal.manifest_digest().into(),
        unsigned_artifact_digest: h('1'),
        proved_artifact_digest: h('2'),
        effects_commitment: h('3'),
        policy_digest: h('4'),
        review_binding: h('5'),
        action_mapping_digest: h('6'),
        anchor: h('7'),
        proposal_binding: String::new(),
    };
    fixed.proposal_binding = expected_fixed_binding(&fixed);
    let inputs = vec![InputReservation {
        input_id: format!("input-{participant}"),
        nullifier: h(if owner == 0 { 'a' } else { 'b' }),
        action_index: owner as u64,
        value_zatoshis: if owner == 0 { 50 } else { 70 },
    }];
    let materials: Vec<_> = ['1', '2']
        .into_iter()
        .map(|account| DurableDeliveryMaterialScopeRefV2 {
            account_id: h(account),
            original_scope_digest: h(if account == '1' { '8' } else { '9' }),
            valid_from_unix_seconds: 100,
            valid_until_unix_seconds: 850,
        })
        .collect();
    let authorization = DurablePaymentAdmissionTermsV1 {
        version: 1,
        identity: extension.account_extension.terms.identity.clone(),
        original_policy_digest: witness.policy_digest.clone(),
        original_genesis_digest: genesis.digest().expect("inert genesis"),
        original_birth_commit_digest: h('d'),
        original_roster_extension_digest: extension.digest().expect("inert extension"),
        original_enrollment_ref: h('c'),
        writer_certificate_digest: writer_certificate,
        fixed: fixed.clone(),
        authorization_id: expected_authorization_id(&fixed.proposal_binding, &account),
        recipient_policy_scope_digest: recipient_scope.clone(),
        concrete_recipient_scope_digest: recipient_scope,
        inputs: inputs.clone(),
        maximum_debit_zatoshis: if owner == 0 { 42 } else { 63 },
        fee_share_zatoshis: if owner == 0 { 2 } else { 3 },
        transaction_fee_zatoshis: 5,
        valid_from_ms: 100_000,
        valid_until_ms: 800_000,
    };
    let scope = DurableDeliveryScopeV2 {
        version: 2,
        authorization,
        accepted_manifest_ref: h('f'),
        original_writer_epoch: 1,
        delivery: DurableDeliveryPlanV2 {
            dispatcher: DurableDeliveryDispatcherV2 {
                principal_id: "named-future-dispatcher".into(),
                public_identity_commitment: h('a'),
                authentication_profile: DurableDeliveryAuthenticationProfileV2::OriginalProtectedHostDispatcherV2,
                custody_policy_commitment: h('b'),
            },
            original_host_generation_binding_digest: expected_digest("wholepact:durable-delivery-original-host:v2", &host),
            original_host_profile_id: host.profile_id.clone(),
            submission_journal_identity: h('c'),
            submission_operation_id: "original-delivery-operation".into(),
            provider: PreconstructionProvider {
                source_id: "fixed-provider".into(),
                endpoint: "https://provider.example".into(),
                trust_profile: "single_tls_provider_report_not_consensus".into(),
            },
            route: DurableDeliveryRouteV2::Direct {},
            owners: [('1', "alice"), ('2', "bob")].into_iter().map(|(account, participant)| {
                DurableDeliveryOwnerLineageV2 {
                    account_id: h(account),
                    participant_id: participant.into(),
                    original_authorization_id: expected_authorization_id(&fixed.proposal_binding, &h(account)),
                }
            }).collect(),
            valid_from_ms: 150_000,
            valid_until_ms: 750_000,
            minimum_expiry_margin_blocks: 10,
            maximum_fresh_admission_lifetime_ms: 1_000,
            maximum_explicitly_approved_attempts: 3,
            extraction_rule: DurableDeliveryExtractionRuleV2::FirstDurablyRetainedVerifiedExtraction,
            retry_rule: DurableDeliveryRetryRuleV2::SameRetainedBytesWithFreshAdmission,
            attempt_rule: DurableDeliveryAttemptRuleV2::ExplicitImmediateHostDecision,
        },
        witness: witness.clone(),
        original_ceilings: DurableDeliveryOriginalCeilingsV2 {
            payment_valid_from_ms: 100_000,
            payment_valid_until_ms: 800_000,
            enrollment_expires_at_ms: 900_000,
            policy_expires_at_ms: 1_000_000,
            material_scopes: materials.clone(),
        },
        disclosure_rule: DurableDeliveryDisclosureRuleV2::WholeTransactionAndConnectionMetadataToProviderCommitmentsAndLinkageToWitness,
    };
    let originals = OriginalClaims {
        policy,
        extension,
        proposal,
        fixed,
        accepted_manifest_ref: h('f'),
        original_writer_epoch: 1,
        witness,
        inputs,
        materials,
    };
    (scope, originals)
}

fn assert_invalid(scope: &DurableDeliveryScopeV2, label: &str) {
    let validation: crate::Result<()> = scope.validate();
    assert!(validation.is_err(), "accepted invalid {label}");
    assert!(scope.digest().is_err(), "hashed invalid {label}");
    assert!(
        scope.shared_plan_digest().is_err(),
        "shared-hashed invalid {label}"
    );
    let bytes = serde_json::to_vec(scope).expect("serialize malformed fixture");
    assert!(
        parse_durable_delivery_scope_v2(&bytes).is_err(),
        "parsed invalid {label}"
    );
}

fn set_json<T: Serialize + DeserializeOwned>(value: &T, path: &str, replacement: Value) -> T {
    let mut encoded = serde_json::to_value(value).expect("serialize fixture");
    *encoded.pointer_mut(path).expect("existing fixture field") = replacement;
    serde_json::from_value(encoded).expect("type-preserving fixture mutation")
}

#[test]
fn two_owner_round_trip_is_data_only_and_not_a_fresh_permit() {
    for owner in 0..2 {
        let (scope, originals) = fixture(owner);
        let validation: crate::Result<()> = scope.validate();
        validation.expect("bounded inert scope");
        let comparison: crate::Result<()> = originals.matches(&scope);
        comparison.expect("matching independently assembled historical claims");
        assert!(!originals.proposal.accounting().authorization_allowed);
        assert!(originals.proposal.input().artifact_digest.is_none());
        assert!(
            scope.delivery.dispatcher.principal_id
                != originals
                    .extension
                    .account_extension
                    .terms
                    .scope
                    .principal_id
        );
        assert!(
            scope.delivery.valid_until_ms - scope.delivery.valid_from_ms
                > originals.policy.maximum_permit_lifetime_ms
        );
        let bytes = serde_json::to_vec(&scope).expect("scope JSON");
        let parsed = parse_durable_delivery_scope_v2(&bytes).expect("strict v2 round trip");
        assert!(parsed == scope, "round trip changed inert scope");
        assert_eq!(parsed.digest().unwrap(), scope.digest().unwrap());
    }
}

#[test]
fn independent_golden_scope_and_shared_plan_hashes_are_stable() {
    // Golden bytes were independently assembled from literal fixture data,
    // with Core's sorted JSON domains and Authority's declared-field encoding.
    // They were not captured from this module's digest implementation.
    let whole = [
        "18a414b71e6da7ddaa3c056987eb2275546e183ea0a9aa405ee6d3acd49e5f6b",
        "914ec80ed57db58cf8abd7fc6d40b8da3303adf4fdcd1e73cb33e224a2c94a66",
    ];
    let authorizations = [
        "durable-v1-9b73608b127975718f886af9f9e073f133de47b9ac83838535fa0e715623ebf7",
        "durable-v1-7f211c9a09839b57fc926b1c70d4d6b9686fc228d74fb1ec3e918db2d2cfc2d9",
    ];
    for owner in 0..2 {
        let (scope, _) = fixture(owner);
        assert_eq!(
            scope.authorization.fixed.proposal_binding,
            "eed7cb3ea868b856c2196d7a93b474ac17e693a9fe15106003c10558aa0b2b0f"
        );
        assert_eq!(scope.authorization.authorization_id, authorizations[owner]);
        assert_eq!(scope.digest().unwrap(), whole[owner]);
        assert_eq!(
            scope.shared_plan_digest().unwrap(),
            "9766c29c65e1e2b4f6b604afd70c13942e52ce3610556ecd31fbba8b99bf3f46"
        );
    }
}

#[test]
fn canonical_domains_bind_every_scope_field_and_the_complete_fixed_plan() {
    let (scope, _) = fixture(0);
    assert_eq!(
        scope.digest().unwrap(),
        expected_digest("wholepact:durable-delivery-scope:v2", &scope)
    );
    assert_eq!(
        scope.shared_plan_digest().unwrap(),
        expected_digest(
            "wholepact:durable-delivery-shared-plan:v2",
            &(&scope.authorization.fixed, &scope.delivery)
        )
    );
    assert_ne!(scope.digest().unwrap(), scope.shared_plan_digest().unwrap());
    assert_ne!(
        scope.shared_plan_digest().unwrap(),
        expected_digest("wholepact:durable-delivery-shared-plan:v2", &scope.delivery)
    );
    for owner in &scope.delivery.owners {
        assert_eq!(
            owner.original_authorization_id,
            expected_authorization_id(
                &scope.authorization.fixed.proposal_binding,
                &owner.account_id
            )
        );
    }
}

fn scalar_paths(value: &Value, path: String, paths: &mut Vec<String>) {
    match value {
        Value::Object(fields) => {
            for (name, child) in fields {
                scalar_paths(child, format!("{path}/{name}"), paths);
            }
        }
        Value::Array(values) if !values.is_empty() => {
            for (index, child) in values.iter().enumerate() {
                scalar_paths(child, format!("{path}/{index}"), paths);
            }
        }
        _ => paths.push(path),
    }
}

fn altered(value: &Value) -> Value {
    match value {
        Value::String(text) if text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit()) => {
            let mut replacement = text.clone();
            replacement.replace_range(..1, if text.starts_with('f') { "e" } else { "f" });
            json!(replacement)
        }
        Value::String(text) => json!(format!("{text}-changed")),
        Value::Number(number) => json!(number.as_u64().expect("unsigned fixture number") + 1),
        Value::Bool(value) => json!(!value),
        Value::Null => json!("changed"),
        Value::Array(_) => json!(["changed"]),
        Value::Object(_) => unreachable!("objects traversed recursively"),
    }
}

#[test]
fn every_serialized_scalar_is_bound_or_rejected_without_an_unbound_extension() {
    let (scope, _) = fixture(0);
    let encoded = serde_json::to_value(&scope).unwrap();
    let (whole, shared) = (scope.digest().unwrap(), scope.shared_plan_digest().unwrap());
    let mut paths = Vec::new();
    scalar_paths(&encoded, String::new(), &mut paths);
    assert!(paths.len() > 80, "fixture lost meaningful field coverage");
    for path in paths {
        let mut changed = encoded.clone();
        let original = changed.pointer(&path).unwrap().clone();
        *changed.pointer_mut(&path).unwrap() = altered(&original);
        let bytes = serde_json::to_vec(&changed).unwrap();
        let Ok(mutated) = parse_durable_delivery_scope_v2(&bytes) else {
            continue;
        };
        assert_ne!(
            mutated.digest().unwrap(),
            whole,
            "whole scope omitted {path}"
        );
        if path.starts_with("/delivery/") || path.starts_with("/authorization/fixed/") {
            assert_ne!(
                mutated.shared_plan_digest().unwrap(),
                shared,
                "shared plan omitted {path}"
            );
        } else {
            assert_eq!(
                mutated.shared_plan_digest().unwrap(),
                shared,
                "owner-only field leaked into shared plan: {path}"
            );
        }
    }
}

#[test]
fn both_owner_authorizations_are_canonical_and_distinct_from_shared_agreement() {
    let (alice, alice_originals) = fixture(0);
    let (bob, bob_originals) = fixture(1);
    alice_originals.matches(&alice).unwrap();
    bob_originals.matches(&bob).unwrap();
    assert!(alice.delivery == bob.delivery);
    assert!(alice.authorization.fixed == bob.authorization.fixed);
    assert_ne!(
        alice.authorization.authorization_id,
        bob.authorization.authorization_id
    );
    assert_ne!(alice.witness.policy_digest, bob.witness.policy_digest);
    assert_ne!(alice.digest().unwrap(), bob.digest().unwrap());
    assert_eq!(
        alice.shared_plan_digest().unwrap(),
        bob.shared_plan_digest().unwrap()
    );
    assert!(alice_originals.matches(&bob).is_err());
    assert!(bob_originals.matches(&alice).is_err());
    for index in 0..2 {
        let mut changed = alice.clone();
        changed.delivery.owners[index].original_authorization_id =
            "arbitrary-authorization-label".into();
        assert_invalid(&changed, "noncanonical owner authorization ID");
        changed = alice.clone();
        changed.delivery.owners[index].original_authorization_id = alice.delivery.owners[1 - index]
            .original_authorization_id
            .clone();
        assert_invalid(&changed, "other owner's canonical authorization ID");
    }
    let mut different_witness = alice.clone();
    different_witness.witness.pinned_server_certificate_digest = h('e');
    different_witness.validate().unwrap();
    assert_eq!(
        alice.shared_plan_digest().unwrap(),
        different_witness.shared_plan_digest().unwrap()
    );
    assert_ne!(alice.digest().unwrap(), different_witness.digest().unwrap());
    assert!(alice_originals.matches(&different_witness).is_err());
    let mut different_material = alice.clone();
    different_material.original_ceilings.material_scopes[1].original_scope_digest = h('e');
    different_material.validate().unwrap();
    assert_eq!(
        alice.shared_plan_digest().unwrap(),
        different_material.shared_plan_digest().unwrap()
    );
    assert!(alice_originals.matches(&different_material).is_err());
}

fn decodable_mutations<T: Serialize + DeserializeOwned>(value: &T) -> Vec<(String, T)> {
    let encoded = serde_json::to_value(value).unwrap();
    let mut paths = Vec::new();
    scalar_paths(&encoded, String::new(), &mut paths);
    paths
        .into_iter()
        .filter_map(|path| {
            let mut changed = encoded.clone();
            *changed.pointer_mut(&path).unwrap() = altered(encoded.pointer(&path).unwrap());
            serde_json::from_value(changed)
                .ok()
                .map(|value| (path, value))
        })
        .collect()
}

#[test]
fn every_independently_supplied_original_claim_is_compared_exactly() {
    let (scope, originals) = fixture(0);
    originals.matches(&scope).unwrap();
    for (path, policy) in decodable_mutations(&originals.policy) {
        let mut changed = originals.clone();
        changed.policy = policy;
        assert!(
            changed.matches(&scope).is_err(),
            "original policy omitted {path}"
        );
    }
    for (path, extension) in decodable_mutations(&originals.extension) {
        let mut changed = originals.clone();
        changed.extension = extension;
        assert!(
            changed.matches(&scope).is_err(),
            "original enrollment omitted {path}"
        );
    }
    for (path, fixed) in decodable_mutations(&originals.fixed) {
        let mut changed = originals.clone();
        changed.fixed = fixed;
        assert!(
            changed.matches(&scope).is_err(),
            "original fixed projection omitted {path}"
        );
    }
    for (path, input) in decodable_mutations(originals.proposal.input()) {
        if let Ok(proposal) = Proposal::validate(input) {
            let mut changed = originals.clone();
            changed.proposal = proposal;
            assert!(
                changed.matches(&scope).is_err(),
                "original numerical proposal omitted {path}"
            );
        }
    }
    for (path, witness) in decodable_mutations(&originals.witness) {
        let mut changed = originals.clone();
        changed.witness = witness;
        assert!(
            changed.matches(&scope).is_err(),
            "original witness omitted {path}"
        );
    }
    for (path, inputs) in decodable_mutations(&originals.inputs) {
        let mut changed = originals.clone();
        changed.inputs = inputs;
        assert!(
            changed.matches(&scope).is_err(),
            "independent original input omitted {path}"
        );
    }
    for (path, materials) in decodable_mutations(&originals.materials) {
        let mut changed = originals.clone();
        changed.materials = materials;
        assert!(
            changed.matches(&scope).is_err(),
            "independent original material omitted {path}"
        );
    }
    let mut changed = originals.clone();
    changed.accepted_manifest_ref = h('e');
    assert!(
        changed.matches(&scope).is_err(),
        "accepted manifest was ignored"
    );
    changed = originals.clone();
    changed.original_writer_epoch = 2;
    assert!(
        changed.matches(&scope).is_err(),
        "historical writer epoch was ignored"
    );
    changed = originals.clone();
    changed.inputs.clear();
    assert!(
        changed.matches(&scope).is_err(),
        "missing original inputs accepted"
    );
    changed = originals.clone();
    changed.materials.clear();
    assert!(
        changed.matches(&scope).is_err(),
        "missing original material scopes accepted"
    );
}

fn rebind_fixed(scope: &mut DurableDeliveryScopeV2) {
    scope.authorization.fixed.proposal_binding = expected_fixed_binding(&scope.authorization.fixed);
    scope.authorization.authorization_id = expected_authorization_id(
        &scope.authorization.fixed.proposal_binding,
        &scope.authorization.identity.account_id,
    );
    for owner in &mut scope.delivery.owners {
        owner.original_authorization_id = expected_authorization_id(
            &scope.authorization.fixed.proposal_binding,
            &owner.account_id,
        );
    }
}

#[test]
fn coherent_but_substituted_fixed_metadata_does_not_match_the_core_proposal() {
    let (scope, originals) = fixture(0);
    for (path, replacement) in [
        ("/network_profile_id", json!("other-network")),
        ("/agreement_id", json!("other-agreement")),
        ("/obligation_id", json!("other-obligation")),
        ("/proposal_id", json!("other-proposal")),
        ("/revision", json!(2)),
        ("/expiry_height", json!(141)),
        ("/proposal_digest", json!(h('e'))),
        ("/manifest_digest", json!(h('e'))),
    ] {
        let mut changed = scope.clone();
        changed.authorization.fixed = set_json(&changed.authorization.fixed, path, replacement);
        rebind_fixed(&mut changed);
        let mut claims = originals.clone();
        claims.fixed = changed.authorization.fixed.clone();
        assert!(
            claims.matches(&changed).is_err(),
            "unrelated Core proposal accepted {path}"
        );
    }
    let mut changed = scope.clone();
    changed.authorization.fixed.proved_artifact_digest = h('e');
    rebind_fixed(&mut changed);
    changed.validate().unwrap();
    assert_ne!(
        changed.shared_plan_digest().unwrap(),
        scope.shared_plan_digest().unwrap()
    );
    assert!(
        originals.matches(&changed).is_err(),
        "different PCZT identity accepted"
    );
}

#[test]
fn original_input_action_nullifier_and_economics_are_not_inferred_from_proposal() {
    let (scope, originals) = fixture(0);
    for (path, replacement) in [
        ("/authorization/inputs/0/input_id", json!("other-input")),
        ("/authorization/inputs/0/nullifier", json!(h('e'))),
        ("/authorization/inputs/0/action_index", json!(2)),
        ("/authorization/inputs/0/value_zatoshis", json!(51)),
        ("/authorization/maximum_debit_zatoshis", json!(43)),
        ("/authorization/fee_share_zatoshis", json!(3)),
        ("/authorization/transaction_fee_zatoshis", json!(6)),
        (
            "/authorization/concrete_recipient_scope_digest",
            json!(h('e')),
        ),
    ] {
        let changed: DurableDeliveryScopeV2 = set_json(&scope, path, replacement);
        changed.validate().unwrap();
        assert!(
            originals.matches(&changed).is_err(),
            "original comparison omitted {path}"
        );
    }
    // Exact input equality is necessary but insufficient: the independent Core
    // proposal also constrains each claimed ID and value for this account.
    let mut changed = scope.clone();
    changed.authorization.inputs[0].value_zatoshis = 51;
    let mut claims = originals.clone();
    claims.inputs[0].value_zatoshis = 51;
    assert!(
        claims.matches(&changed).is_err(),
        "unrelated numerical input amount accepted"
    );
    changed = scope.clone();
    changed.authorization.inputs[0].input_id = "unrelated-input".into();
    claims = originals.clone();
    claims.inputs[0].input_id = "unrelated-input".into();
    assert!(
        claims.matches(&changed).is_err(),
        "unrelated input identifier accepted"
    );
}

#[test]
fn complete_proposal_owner_set_and_original_participant_are_required() {
    let (scope, originals) = fixture(0);
    let mut changed = scope.clone();
    changed.delivery.owners[1].account_id = h('3');
    changed.delivery.owners[1].participant_id = "charlie".into();
    changed.delivery.owners[1].original_authorization_id =
        expected_authorization_id(&changed.authorization.fixed.proposal_binding, &h('3'));
    changed.original_ceilings.material_scopes[1].account_id = h('3');
    changed.validate().unwrap();
    let mut claims = originals.clone();
    claims.materials[1].account_id = h('3');
    assert!(
        claims.matches(&changed).is_err(),
        "roster append replaced full proposal participants"
    );
    changed = scope.clone();
    changed.delivery.owners[1].participant_id = "charlie".into();
    changed.validate().unwrap();
    assert!(
        originals.matches(&changed).is_err(),
        "other owner's participant substituted"
    );
    let mut claims = originals.clone();
    claims
        .extension
        .account_extension
        .terms
        .scope
        .participant_id = "charlie".into();
    let mut changed = scope.clone();
    changed.authorization.original_roster_extension_digest = claims.extension.digest().unwrap();
    changed.validate().unwrap();
    assert!(
        claims.matches(&changed).is_err(),
        "own enrollment participant substituted"
    );
}

#[test]
fn original_host_writer_policy_ceilings_and_witness_origin_cannot_be_echoed_away() {
    let (scope, originals) = fixture(0);
    for (path, replacement) in [
        (
            "/delivery/original_host_generation_binding_digest",
            json!(h('e')),
        ),
        (
            "/delivery/original_host_profile_id",
            json!("other-host-profile"),
        ),
        (
            "/original_ceilings/enrollment_expires_at_ms",
            json!(900_001),
        ),
        ("/original_ceilings/policy_expires_at_ms", json!(1_000_001)),
    ] {
        let changed: DurableDeliveryScopeV2 = set_json(&scope, path, replacement);
        changed.validate().unwrap();
        assert!(
            originals.matches(&changed).is_err(),
            "original claim omitted {path}"
        );
    }
    let mut changed = scope.clone();
    changed.original_writer_epoch = 2;
    let mut claims = originals.clone();
    claims.original_writer_epoch = 2;
    assert!(
        claims.matches(&changed).is_err(),
        "echoed epoch bypassed original writer"
    );
    for (path, replacement) in [
        ("/endpoint", json!("127.0.0.1:1913")),
        ("/server_name", json!("other.example")),
        ("/pinned_server_certificate_digest", json!(h('e'))),
    ] {
        let mut changed = scope.clone();
        changed.witness = set_json(&changed.witness, path, replacement);
        changed.validate().unwrap();
        let mut claims = originals.clone();
        claims.witness = changed.witness.clone();
        assert!(
            claims.matches(&changed).is_err(),
            "echoed witness bypassed genesis origin {path}"
        );
    }
}

#[test]
fn missing_duplicate_unsorted_and_unrelated_owner_or_material_entries_reject() {
    let (scope, _) = fixture(0);
    let mut changed = scope.clone();
    changed.delivery.owners.pop();
    assert_invalid(&changed, "missing owner");
    changed = scope.clone();
    changed
        .delivery
        .owners
        .push(scope.delivery.owners[0].clone());
    assert_invalid(&changed, "excess owner");
    changed = scope.clone();
    changed.delivery.owners[1] = changed.delivery.owners[0].clone();
    assert_invalid(&changed, "duplicate owner");
    changed = scope.clone();
    changed.delivery.owners.reverse();
    assert_invalid(&changed, "unsorted owners");
    changed = scope.clone();
    changed.delivery.owners[1].participant_id = changed.delivery.owners[0].participant_id.clone();
    assert_invalid(&changed, "duplicate participants");
    changed = scope.clone();
    changed.delivery.owners[0].account_id = h('0');
    changed.delivery.owners[0].original_authorization_id =
        expected_authorization_id(&changed.authorization.fixed.proposal_binding, &h('0'));
    changed.original_ceilings.material_scopes[0].account_id = h('0');
    assert_invalid(&changed, "current owner omitted");
    changed = scope.clone();
    changed.original_ceilings.material_scopes.clear();
    assert_invalid(&changed, "missing material scopes");
    changed = scope.clone();
    changed.original_ceilings.material_scopes.pop();
    assert_invalid(&changed, "missing other owner material");
    changed = scope.clone();
    changed
        .original_ceilings
        .material_scopes
        .push(scope.original_ceilings.material_scopes[0].clone());
    assert_invalid(&changed, "excess material scope");
    changed = scope.clone();
    changed.original_ceilings.material_scopes[1] =
        changed.original_ceilings.material_scopes[0].clone();
    assert_invalid(&changed, "duplicate material scope");
    changed = scope.clone();
    changed.original_ceilings.material_scopes.reverse();
    assert_invalid(&changed, "unsorted material scopes");
    changed = scope.clone();
    changed.original_ceilings.material_scopes[1].account_id = h('3');
    assert_invalid(&changed, "unrelated material account");
}

#[test]
fn original_absolute_ends_allow_equality_but_never_one_more_millisecond() {
    let (scope, _) = fixture(0);
    // Payment <= enrollment <= policy is itself a maintained original-policy
    // constraint, so equality at a later ceiling also requires earlier ceilings.
    for label in [
        "payment",
        "enrollment",
        "policy",
        "alice material",
        "bob material",
    ] {
        let mut changed = scope.clone();
        changed.delivery.valid_until_ms = 800_000;
        match label {
            "payment" => {}
            "enrollment" => changed.original_ceilings.enrollment_expires_at_ms = 800_000,
            "policy" => {
                changed.original_ceilings.enrollment_expires_at_ms = 800_000;
                changed.original_ceilings.policy_expires_at_ms = 800_000;
            }
            "alice material" => {
                changed.original_ceilings.material_scopes[0].valid_until_unix_seconds = 800
            }
            "bob material" => {
                changed.original_ceilings.material_scopes[1].valid_until_unix_seconds = 800
            }
            _ => unreachable!(),
        }
        changed
            .validate()
            .expect("equality at original absolute end");
        changed.delivery.valid_until_ms += 1;
        assert_invalid(&changed, label);
    }
    // Each original bound is independently required, even when another bound
    // would otherwise admit the requested plan.
    for path in [
        "/original_ceilings/payment_valid_until_ms",
        "/original_ceilings/enrollment_expires_at_ms",
        "/original_ceilings/policy_expires_at_ms",
    ] {
        let changed: DurableDeliveryScopeV2 = set_json(&scope, path, json!(749_999));
        assert_invalid(&changed, path);
    }
    for owner in 0..2 {
        let mut changed = scope.clone();
        changed.original_ceilings.material_scopes[owner].valid_until_unix_seconds = 750;
        changed.validate().unwrap();
        changed.delivery.valid_until_ms = 750_001;
        assert_invalid(&changed, "material milliseconds boundary");
    }
}

#[test]
fn original_starts_are_not_reset_to_a_new_delegation_window() {
    let (scope, originals) = fixture(0);
    let mut changed = scope.clone();
    changed.delivery.valid_from_ms = 100_000;
    originals.matches(&changed).unwrap();
    changed.delivery.valid_from_ms = 99_999;
    assert_invalid(&changed, "payment or material start minus one");
    for owner in 0..2 {
        let mut changed = scope.clone();
        changed.original_ceilings.material_scopes[owner].valid_from_unix_seconds = 150;
        changed.validate().unwrap();
        changed.delivery.valid_from_ms = 149_999;
        assert_invalid(&changed, "material start minus one millisecond");
    }
    changed = scope.clone();
    changed.authorization.valid_from_ms = 150_000;
    changed.original_ceilings.payment_valid_from_ms = 150_000;
    changed.validate().unwrap();
    changed.delivery.valid_from_ms -= 1;
    assert_invalid(&changed, "payment start minus one millisecond");
    for path in [
        "/delivery/valid_from_ms",
        "/authorization/valid_from_ms",
        "/original_ceilings/payment_valid_from_ms",
    ] {
        let changed: DurableDeliveryScopeV2 = set_json(&scope, path, json!(0));
        assert_invalid(&changed, path);
    }
    changed = scope.clone();
    changed.delivery.valid_until_ms = changed.delivery.valid_from_ms;
    assert_invalid(&changed, "empty delivery interval");
    changed.delivery.valid_until_ms -= 1;
    assert_invalid(&changed, "reversed delivery interval");
}

#[test]
fn original_material_seconds_require_checked_sql_milliseconds_and_at_most_24_hours() {
    let (scope, _) = fixture(0);
    for owner in 0..2 {
        for field in ["valid_from_unix_seconds", "valid_until_unix_seconds"] {
            for value in [0, i64::MAX as u64 / 1000 + 1, u64::MAX / 1000 + 1, u64::MAX] {
                let changed: DurableDeliveryScopeV2 = set_json(
                    &scope,
                    &format!("/original_ceilings/material_scopes/{owner}/{field}"),
                    json!(value),
                );
                assert_invalid(&changed, "invalid original seconds projection");
            }
        }
        let mut changed = scope.clone();
        changed.original_ceilings.material_scopes[owner].valid_until_unix_seconds = 100;
        assert_invalid(&changed, "empty material interval");
        changed.original_ceilings.material_scopes[owner].valid_until_unix_seconds = 99;
        assert_invalid(&changed, "reversed material interval");
        changed.original_ceilings.material_scopes[owner].valid_until_unix_seconds = 86_500;
        changed
            .validate()
            .expect("exact original 24-hour material interval");
        changed.original_ceilings.material_scopes[owner].valid_until_unix_seconds += 1;
        assert_invalid(&changed, "original material interval over 24 hours");
    }
    let mut longest = scope.clone();
    longest.authorization.valid_until_ms = 86_500_000;
    longest.original_ceilings.payment_valid_until_ms = 86_500_000;
    longest.original_ceilings.enrollment_expires_at_ms = 86_500_000;
    longest.original_ceilings.policy_expires_at_ms = 86_500_000;
    for material in &mut longest.original_ceilings.material_scopes {
        material.valid_until_unix_seconds = 86_500;
    }
    longest.delivery.valid_from_ms = 100_000;
    longest.delivery.valid_until_ms = 86_500_000;
    longest
        .validate()
        .expect("original 24-hour interval is not a fresh admission");
    assert_eq!(longest.delivery.maximum_fresh_admission_lifetime_ms, 1_000);
    longest.delivery.valid_until_ms += 1;
    assert_invalid(&longest, "cannot refresh original material duration");
}

#[test]
fn finite_milliseconds_writer_epochs_and_closed_caps_are_bounded() {
    let (scope, _) = fixture(0);
    for path in [
        "/original_writer_epoch",
        "/delivery/valid_from_ms",
        "/delivery/valid_until_ms",
        "/authorization/valid_from_ms",
        "/authorization/valid_until_ms",
        "/original_ceilings/payment_valid_from_ms",
        "/original_ceilings/payment_valid_until_ms",
        "/original_ceilings/enrollment_expires_at_ms",
        "/original_ceilings/policy_expires_at_ms",
    ] {
        for value in [0, i64::MAX as u64 + 1, u64::MAX] {
            let changed: DurableDeliveryScopeV2 = set_json(&scope, path, json!(value));
            assert_invalid(&changed, path);
        }
    }
    let mut epoch = scope.clone();
    epoch.original_writer_epoch = i64::MAX as u64;
    epoch
        .validate()
        .expect("finite historical SQL epoch boundary");
    for (path, maximum) in [
        ("/delivery/minimum_expiry_margin_blocks", 100_u64),
        ("/delivery/maximum_fresh_admission_lifetime_ms", 120_000),
        ("/delivery/maximum_explicitly_approved_attempts", 128),
    ] {
        for value in [1, maximum] {
            let changed: DurableDeliveryScopeV2 = set_json(&scope, path, json!(value));
            changed.validate().expect("closed cap endpoint");
        }
        for value in [0, maximum + 1] {
            let changed: DurableDeliveryScopeV2 = set_json(&scope, path, json!(value));
            assert_invalid(&changed, path);
        }
    }
    let mut changed = scope.clone();
    changed.original_ceilings.enrollment_expires_at_ms = 799_999;
    assert_invalid(&changed, "payment exceeds enrollment");
    changed = scope.clone();
    changed.original_ceilings.policy_expires_at_ms = 899_999;
    assert_invalid(&changed, "enrollment exceeds policy");
}

#[test]
fn input_count_uniqueness_actions_values_and_money_preserve_existing_v1_bounds() {
    let (scope, _) = fixture(0);
    for path in [
        "/authorization/maximum_debit_zatoshis",
        "/authorization/transaction_fee_zatoshis",
        "/authorization/fee_share_zatoshis",
        "/authorization/inputs/0/value_zatoshis",
    ] {
        for value in [MAX_MONEY + 1, u64::MAX] {
            let changed: DurableDeliveryScopeV2 = set_json(&scope, path, json!(value));
            assert_invalid(&changed, path);
        }
    }
    for (path, value) in [
        ("/authorization/maximum_debit_zatoshis", 0),
        ("/authorization/maximum_debit_zatoshis", 51),
        ("/authorization/inputs/0/value_zatoshis", 0),
        ("/authorization/inputs/0/value_zatoshis", 41),
        ("/authorization/inputs/0/action_index", 256),
        ("/authorization/fee_share_zatoshis", 6),
        ("/authorization/transaction_fee_zatoshis", 1),
    ] {
        let changed: DurableDeliveryScopeV2 = set_json(&scope, path, json!(value));
        assert_invalid(&changed, path);
    }
    let mut boundary = scope.clone();
    boundary.authorization.maximum_debit_zatoshis = MAX_MONEY;
    boundary.authorization.fee_share_zatoshis = 0;
    boundary.authorization.transaction_fee_zatoshis = 0;
    boundary.authorization.inputs[0].value_zatoshis = MAX_MONEY;
    boundary.authorization.inputs[0].action_index = 255;
    boundary
        .validate()
        .expect("historical money and action maxima");
    boundary.authorization.inputs.push(InputReservation {
        input_id: "second-input".into(),
        nullifier: h('b'),
        action_index: 254,
        value_zatoshis: 1,
    });
    assert_invalid(&boundary, "aggregate input money exceeds maximum");
    let mut many = scope.clone();
    many.authorization.maximum_debit_zatoshis = 256;
    many.authorization.fee_share_zatoshis = 0;
    many.authorization.transaction_fee_zatoshis = 0;
    many.authorization.inputs = (0..256)
        .map(|index| InputReservation {
            input_id: format!("bounded-input-{index}"),
            nullifier: format!("{index:064x}"),
            action_index: index,
            value_zatoshis: 1,
        })
        .collect();
    many.validate()
        .expect("256 distinct bounded original inputs");
    let mut changed = many.clone();
    changed.authorization.inputs.push(InputReservation {
        input_id: "excess-input".into(),
        nullifier: h('e'),
        action_index: 256,
        value_zatoshis: 1,
    });
    assert_invalid(&changed, "257 inputs");
    for field in ["input_id", "nullifier", "action_index"] {
        let first = serde_json::to_value(&many.authorization.inputs[0]).unwrap()[field].clone();
        let changed: DurableDeliveryScopeV2 =
            set_json(&many, &format!("/authorization/inputs/1/{field}"), first);
        assert_invalid(&changed, "duplicate input ID, nullifier, or action");
    }
    let mut changed = scope;
    changed.authorization.inputs.clear();
    assert_invalid(&changed, "empty input set");
}

#[test]
fn identifiers_hashes_and_submission_operation_use_exact_bounded_grammar() {
    let (scope, _) = fixture(0);
    for path in [
        "/delivery/dispatcher/principal_id",
        "/delivery/original_host_profile_id",
        "/delivery/provider/source_id",
        "/delivery/owners/0/participant_id",
        "/authorization/inputs/0/input_id",
    ] {
        for invalid in [
            String::new(),
            "x".repeat(129),
            "contains space".into(),
            "slash/name".into(),
            "nonascii-é".into(),
            "line\nbreak".into(),
        ] {
            let changed: DurableDeliveryScopeV2 = set_json(&scope, path, json!(invalid));
            assert_invalid(&changed, path);
        }
        let changed: DurableDeliveryScopeV2 = set_json(&scope, path, json!("x".repeat(128)));
        changed.validate().expect("bounded identifier length 128");
    }
    for path in [
        "/accepted_manifest_ref",
        "/delivery/submission_journal_identity",
        "/delivery/dispatcher/public_identity_commitment",
        "/delivery/dispatcher/custody_policy_commitment",
        "/delivery/original_host_generation_binding_digest",
        "/original_ceilings/material_scopes/0/original_scope_digest",
    ] {
        for invalid in [
            String::new(),
            "a".repeat(63),
            "a".repeat(65),
            "A".repeat(64),
            "g".repeat(64),
        ] {
            let changed: DurableDeliveryScopeV2 = set_json(&scope, path, json!(invalid));
            assert_invalid(&changed, path);
        }
    }
    for length in [16, 128] {
        let mut changed = scope.clone();
        changed.delivery.submission_operation_id = "a".repeat(length);
        changed.validate().unwrap();
    }
    for invalid in [
        "a".repeat(15),
        "a".repeat(129),
        "operation/name-12345".into(),
        "operation@name-12345".into(),
        "operation name-12345".into(),
        "operation\nname-12345".into(),
    ] {
        let mut changed = scope.clone();
        changed.delivery.submission_operation_id = invalid;
        assert_invalid(&changed, "submission operation intersection grammar");
    }
    let mut changed = scope;
    changed.delivery.submission_operation_id = "AZaz09-_.:exact-id".into();
    changed
        .validate()
        .expect("Authority and Chain identifier intersection");
}

#[test]
fn provider_and_existing_connect_origins_accept_only_canonical_claims() {
    let (scope, _) = fixture(0);
    for authority in [
        "provider.example",
        "a",
        "a-b.example",
        "a1.example",
        "127.0.0.1",
        "192.0.2.10",
        "[::1]",
        "[2001:db8::1]",
        "provider.example:1",
        "provider.example:65535",
        "192.0.2.10:8443",
        "[2001:db8::1]:8080",
    ] {
        let mut changed = scope.clone();
        changed.delivery.provider.endpoint = format!("https://{authority}");
        changed.delivery.route = DurableDeliveryRouteV2::ExistingHttpConnect {
            origin: format!("http://{authority}"),
        };
        changed
            .validate()
            .expect("canonical non-default provider and proxy origins");
        let bytes = serde_json::to_vec(&changed).unwrap();
        assert!(parse_durable_delivery_scope_v2(&bytes).is_ok());
    }
    // Per-label and whole-DNS-host bounds are separate, with no normalization.
    let longest_host = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(longest_host.len(), 253);
    let mut changed = scope.clone();
    changed.delivery.provider.endpoint = format!("https://{longest_host}:65535");
    changed
        .validate()
        .expect("253-byte DNS host and valid maximum port");
    changed.delivery.provider.endpoint = format!("https://{longest_host}d");
    assert_invalid(&changed, "DNS host exceeds 253 bytes");
    changed.delivery.provider.endpoint = format!("https://{}.example", "a".repeat(64));
    assert_invalid(&changed, "DNS label exceeds 63 bytes");
    changed = scope.clone();
    changed.delivery.provider.endpoint = "https://provider.example:80".into();
    changed.delivery.route = DurableDeliveryRouteV2::ExistingHttpConnect {
        origin: "http://proxy.example:443".into(),
    };
    changed
        .validate()
        .expect("only the corresponding scheme default is omitted");
}

#[test]
fn origins_reject_credentials_paths_controls_and_numeric_ip_fallback_spellings() {
    let (scope, _) = fixture(0);
    let invalid_authorities = [
        "",
        "user@provider.example",
        "user:password@provider.example",
        "provider.example/",
        "provider.example/path",
        "provider.example?query",
        "provider.example#fragment",
        "provider.example ",
        " provider.example",
        "provider.\nexample",
        "provider.\texample",
        "provider.example\0",
        "Provider.example",
        "provider.EXAMPLE",
        "provider.example.",
        ".provider.example",
        "provider..example",
        "-provider.example",
        "provider-.example",
        "provider_name.example",
        "prövider.example",
        "%70rovider.example",
        "provider%2eexample",
        "provider.example%3a443",
        "0.0.0.0",
        "224.0.0.1",
        "239.255.255.255",
        "256.1.1.1",
        "127.1",
        "127.00.0.1",
        "0177.0.0.1",
        "0x7f000001",
        "2130706433",
        "0x7f.0.0.1",
        "0X7F000001",
        "127.0.0",
        "127.0.0.1.1",
        "example.123",
        "example.0xabc",
        "[::]",
        "[ff02::1]",
        "[2001:DB8::1]",
        "[2001:0db8::1]",
        "[2001:db8:0:0:0:0:0:1]",
        "[::ffff:0.0.0.0]",
        "[::ffff:224.0.0.1]",
        "[::ffff:239.255.255.255]",
        "2001:db8::1",
        "[2001:db8::1",
        "2001:db8::1]",
        "[::1]extra",
        "[::1%25eth0]",
        "provider.example:",
        "provider.example:0",
        "provider.example:00",
        "provider.example:01",
        "provider.example:+1",
        "provider.example:-1",
        "provider.example:1.0",
        "provider.example:65536",
        "provider.example:999999999999999999999999",
        "provider.example:8080:8081",
        "[::1]:00080",
        "[::1]:65536",
    ];
    for authority in invalid_authorities {
        let mut changed = scope.clone();
        changed.delivery.provider.endpoint = format!("https://{authority}");
        assert_invalid(&changed, "noncanonical provider origin");
        changed = scope.clone();
        changed.delivery.route = DurableDeliveryRouteV2::ExistingHttpConnect {
            origin: format!("http://{authority}"),
        };
        assert_invalid(&changed, "noncanonical CONNECT origin");
    }
    for endpoint in [
        "http://provider.example",
        "HTTPS://provider.example",
        "https:provider.example",
        "https:///provider.example",
        "https://provider.example:443",
        "https://[::1]:443",
    ] {
        let mut changed = scope.clone();
        changed.delivery.provider.endpoint = endpoint.into();
        assert_invalid(&changed, "provider scheme or explicit default port");
    }
    for origin in [
        "https://proxy.example",
        "HTTP://proxy.example",
        "socks5://proxy.example",
        "http:proxy.example",
        "http://proxy.example:80",
        "http://[::1]:80",
    ] {
        let mut changed = scope.clone();
        changed.delivery.route = DurableDeliveryRouteV2::ExistingHttpConnect {
            origin: origin.into(),
        };
        assert_invalid(&changed, "proxy scheme or explicit default port");
    }
    let mut changed = scope;
    changed.delivery.provider.trust_profile = "consensus_verified".into();
    assert_invalid(&changed, "unsupported provider trust claim");
}

fn inject_member(raw: &str, object_start: &str, member: &str) -> Vec<u8> {
    assert!(raw.contains(object_start), "raw fixture object exists");
    raw.replacen(object_start, &format!("{object_start}{member},"), 1)
        .into_bytes()
}

#[test]
fn strict_parser_rejects_unknown_and_duplicate_members_at_each_nested_boundary() {
    let (scope, _) = fixture(0);
    let raw = serde_json::to_string(&scope).unwrap();
    assert!(parse_durable_delivery_scope_v2(raw.as_bytes()).is_ok());
    for (start, duplicate) in [
        ("{", "\"version\":2"),
        ("\"authorization\":{", "\"version\":1"),
        ("\"identity\":{", "\"account_id\":\"duplicate\""),
        ("\"fixed\":{", "\"schema_version\":1"),
        ("\"inputs\":[{", "\"action_index\":0"),
        ("\"delivery\":{", "\"valid_from_ms\":150000"),
        ("\"dispatcher\":{", "\"principal_id\":\"duplicate\""),
        ("\"provider\":{", "\"source_id\":\"duplicate\""),
        ("\"owners\":[{", "\"participant_id\":\"alice\""),
        ("\"witness\":{", "\"endpoint\":\"127.0.0.1:1911\""),
        (
            "\"original_ceilings\":{",
            "\"payment_valid_from_ms\":100000",
        ),
        ("\"material_scopes\":[{", "\"valid_from_unix_seconds\":100"),
    ] {
        let duplicate_bytes = inject_member(&raw, start, duplicate);
        assert!(
            parse_durable_delivery_scope_v2(&duplicate_bytes).is_err(),
            "duplicate object member accepted at {start}"
        );
        let unknown_bytes = inject_member(&raw, start, "\"unreviewed_extra\":true");
        assert!(
            parse_durable_delivery_scope_v2(&unknown_bytes).is_err(),
            "unknown object member accepted at {start}"
        );
    }
    // This is deliberately a literal duplicate-key document, never a Value
    // intermediary that could silently erase the first authorization field.
    let duplicate_authorization = inject_member(&raw, "{", "\"authorization\":{}");
    assert!(parse_durable_delivery_scope_v2(&duplicate_authorization).is_err());
    let escaped_duplicate = inject_member(&raw, "{", "\"vers\\u0069on\":2");
    assert!(parse_durable_delivery_scope_v2(&escaped_duplicate).is_err());
}

#[test]
fn strict_route_variants_reject_extra_fields_and_duplicate_kind_or_origin() {
    let (scope, _) = fixture(0);
    let raw = serde_json::to_string(&scope).unwrap();
    for route in [
        r#"{"kind":"direct","origin":"http://proxy.example"}"#,
        r#"{"kind":"direct","extra":true}"#,
        r#"{"kind":"direct","kind":"direct"}"#,
        r#"{"kind":"direct","kind":"existing_http_connect","origin":"http://proxy.example"}"#,
        r#"{"kind":"environment"}"#,
        r#"{"kind":"fallback","origin":"http://proxy.example"}"#,
        r#"{"kind":"redirect","origin":"http://proxy.example"}"#,
        r#"{"kind":"existing_http_connect","origin":"http://proxy.example","kind":"existing_http_connect"}"#,
        r#"{"kind":"existing_http_connect","origin":"http://proxy.example","origin":"http://proxy.example"}"#,
        r#"{"kind":"existing_http_connect","origin":"http://proxy.example","credentials":"not-allowed"}"#,
        r#"{"kind":"existing_http_connect"}"#,
    ] {
        let changed = raw.replacen(
            r#""route":{"kind":"direct"}"#,
            &format!("\"route\":{route}"),
            1,
        );
        assert!(changed != raw, "raw route fixture must be replaced");
        assert!(
            parse_durable_delivery_scope_v2(changed.as_bytes()).is_err(),
            "noncanonical route object accepted"
        );
    }
}

#[test]
fn v1_missing_scope_unsupported_rules_and_future_cycle_fields_never_become_v2() {
    let (scope, _) = fixture(0);
    let old_terms = serde_json::to_vec(&scope.authorization).unwrap();
    assert!(parse_durable_delivery_scope_v2(&old_terms).is_err());
    for old in [
        json!({}),
        json!({"version":1}),
        json!({"version":2}),
        json!({"authorization":scope.authorization.clone()}),
    ] {
        assert!(parse_durable_delivery_scope_v2(&serde_json::to_vec(&old).unwrap()).is_err());
    }
    let mut encoded = serde_json::to_value(&scope).unwrap();
    let names: Vec<_> = encoded.as_object().unwrap().keys().cloned().collect();
    for name in names {
        let mut missing = encoded.clone();
        missing.as_object_mut().unwrap().remove(&name);
        assert!(
            parse_durable_delivery_scope_v2(&serde_json::to_vec(&missing).unwrap()).is_err(),
            "missing required scope field {name}"
        );
    }
    for version in [0, 1, 3, u16::MAX] {
        encoded["version"] = json!(version);
        assert!(parse_durable_delivery_scope_v2(&serde_json::to_vec(&encoded).unwrap()).is_err());
    }
    for path in [
        "/delivery/dispatcher/authentication_profile",
        "/delivery/extraction_rule",
        "/delivery/retry_rule",
        "/delivery/attempt_rule",
        "/disclosure_rule",
    ] {
        let mut changed = serde_json::to_value(&scope).unwrap();
        *changed.pointer_mut(path).unwrap() = json!("unsupported_future_rule");
        assert!(
            parse_durable_delivery_scope_v2(&serde_json::to_vec(&changed).unwrap()).is_err(),
            "unsupported closed rule {path}"
        );
    }
    let raw = serde_json::to_string(&scope).unwrap();
    for name in [
        "consent_hash",
        "original_consent_ref",
        "request_digest",
        "reservation_hash",
        "signed_result_digest",
        "final_transaction_digest",
        "final_transaction_bytes",
        "native_approved",
        "authenticated",
        "permit",
        "fvk",
        "private_notes",
    ] {
        for start in ["{", "\"delivery\":{", "\"authorization\":{"] {
            let changed = inject_member(
                &raw,
                start,
                &format!("\"{name}\":\"unavailable-at-original-review\""),
            );
            assert!(
                parse_durable_delivery_scope_v2(&changed).is_err(),
                "future or authority field accepted: {name}"
            );
        }
    }
}

#[test]
fn parser_frame_limit_trailing_data_and_malformed_json_are_rejected_before_use() {
    let (scope, _) = fixture(0);
    let bytes = serde_json::to_vec(&scope).unwrap();
    assert!(bytes.len() < MAX_FRAME_BYTES);
    let mut exact = bytes.clone();
    exact.resize(MAX_FRAME_BYTES, b' ');
    assert!(
        parse_durable_delivery_scope_v2(&exact).is_ok(),
        "frame boundary with harmless JSON whitespace"
    );
    exact.push(b' ');
    assert!(matches!(
        parse_durable_delivery_scope_v2(&exact),
        Err(crate::AuthorityError::Limit)
    ));
    let mut oversized = scope.clone();
    oversized.delivery.dispatcher.principal_id = "a".repeat(MAX_FRAME_BYTES);
    assert_invalid(&oversized, "scope encoder frame limit");
    for malformed in [
        b"".as_slice(),
        b"null".as_slice(),
        b"[]".as_slice(),
        b"{".as_slice(),
        b"\xff".as_slice(),
    ] {
        assert!(parse_durable_delivery_scope_v2(malformed).is_err());
    }
    let mut trailing = bytes;
    trailing.extend_from_slice(b"{}");
    assert!(
        parse_durable_delivery_scope_v2(&trailing).is_err(),
        "second JSON document accepted"
    );
}
