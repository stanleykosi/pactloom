use super::*;
use crate::{
    Amount, born_recipient_policy_v2::BornOwnReturnRuleV2, manual_candidate_selection::*,
    manual_inventory::ManualPreliminaryInventoryScope, proposal::ParticipantAllocation,
};
use crate::{born_policy_origin_v2::*, manual_construction::*};
fn a(v: u64) -> Amount {
    Amount::from_zatoshis(v).unwrap()
}
fn h(c: char) -> String {
    c.to_string().repeat(64)
}
fn economics() -> ManualCandidateEconomicIntent {
    ManualCandidateEconomicIntent {
        version: 1,
        candidate_id: "synthetic-candidate".into(),
        candidate_revision: 1,
        proposal_id: "synthetic-proposal".into(),
        previous_proposal_id: None,
        created_at: "2026-10-13T14:00:00Z".into(),
        agreement: crate::parse_typed_json(include_bytes!("../../tests/fixtures/agreement.json"))
            .unwrap(),
        participants: vec![
            ParticipantAllocation {
                participant_id: "alice".into(),
                account_id: "11".repeat(32),
                contribution: a(400_000_000),
                fee_share: a(12_000),
                fee_cap: a(12_000),
                maximum_net_debit: a(400_012_000),
                charges: vec![],
            },
            ParticipantAllocation {
                participant_id: "bob".into(),
                account_id: "22".repeat(32),
                contribution: a(600_000_000),
                fee_share: a(18_000),
                fee_cap: a(18_000),
                maximum_net_debit: a(600_018_000),
                charges: vec![],
            },
        ],
        transaction_fee: a(30_000),
        expiry_height: 3_000_000,
        own_return_rule: BornOwnReturnRuleV2::AuthenticatedSameAccount,
    }
}
fn inner_request() -> ManualCandidateSelectionRequest {
    // Inert, never-funded pure fixture. No native/wallet/current lease exists.
    let (mut enrollment, policy) =
        crate::born_recipient_policy_v2::tests::modeled_terms_and_policy();
    enrollment.scope.maximum_permit_lifetime_ms = 120_000;
    let l = &policy.original_limits;
    let terms = BornPolicyOriginalTermsV2 {
        witness_id: "synthetic-witness".into(),
        account_id: policy.account_id.clone(),
        network_profile_id: policy.network_profile_id.clone(),
        owner_certificate_digest: enrollment.signer.owner_certificate_digest.clone(),
        initial_writer_certificate_digest: enrollment.signer.writer_certificate_digest.clone(),
        initial_writer_epoch: 1,
        enrollment_refs: vec![h('a')],
        agreement_ids: vec![policy.agreement_id.clone()],
        recipient_scope_digests: vec![policy.digest().unwrap()],
        aggregate_budget_zatoshis: l.aggregate_budget_zatoshis,
        per_operation_limit_zatoshis: l.per_operation_limit_zatoshis,
        maximum_fee_share_zatoshis: l.maximum_fee_share_zatoshis,
        maximum_transaction_fee_zatoshis: l.maximum_transaction_fee_zatoshis,
        maximum_permit_lifetime_ms: l.maximum_permit_lifetime_ms,
        policy_expires_at_ms: l.policy_expires_at_ms,
    };
    let intent = BornRecipientPolicyBirthIntentV2 {
        version: 2,
        operation_id: format!("birth-{}", "a".repeat(32)),
        generation_instance_id: h('b'),
        identity: BornPolicyIdentityV2 {
            account_id: enrollment.identity.account_id.clone(),
            full_viewing_key_digest: enrollment.identity.full_viewing_key_digest.clone(),
            network_profile_id: enrollment.identity.network_profile_id.clone(),
            derivation_domain: enrollment.identity.derivation_domain.clone(),
            exact_derivation: "synthetic-derivation".into(),
        },
        witness_origin: BornPolicyWitnessOriginV2 {
            endpoint: "https://synthetic.invalid".into(),
            server_name: "synthetic.invalid".into(),
            witness_id: "synthetic-witness".into(),
            pinned_server_certificate_digest: h('c'),
        },
        original_policy_terms_digest: terms.digest().unwrap(),
        original_policy_terms: terms,
        native_principal_id: "synthetic-principal".into(),
        native_measurement: h('d'),
        original_target: "/synthetic/vault".into(),
    };
    let origin = BornRecipientPolicyOriginV2 {
        version: 2,
        birth_digest: canonical_digest(
            "wholepact:native-account-birth-intent:v2",
            &(&intent, &policy),
        )
        .unwrap(),
        intent,
        recipient_policy: policy.clone(),
    };
    enrollment.native_birth_digest = origin.birth_digest.clone();
    let o = &origin.intent.witness_origin;
    enrollment.original_witness_origin_digest = canonical_digest(
        "wholepact:account-use-witness-origin:v1",
        &(
            &o.endpoint,
            &o.server_name,
            &o.witness_id,
            &o.pinned_server_certificate_digest,
        ),
    )
    .unwrap();
    let attachment = ManualConstructionAttachmentBinding {
        version: 1,
        original_primary_journal_origin_digest: enrollment
            .host
            .financial_journal_origin_digest
            .clone(),
        predecessor_registry_digest: h('e'),
        current_registry_digest: h('f'),
        latest_extension_digest: h('1'),
        selected: ManualParticipantAttachment {
            account_id: enrollment.identity.account_id.clone(),
            canonical_directory: "/synthetic/wallet".into(),
            directory_identity_digest: h('2'),
            journal_origin_digest: h('3'),
        },
    };
    let inventory = ManualPreliminaryInventoryScope {
        version: 1,
        enrollment,
        enrollment_ref: h('4'),
        witness_extension_digest: h('5'),
        attempt: ManualConstructionAttempt {
            version: 2,
            continuation_digest: h('6'),
            attempt_sequence: 2,
        },
        original_recipient_policy: policy,
        attachment,
        operator_name: "synthetic-local-host".into(),
        operator_destination: "/synthetic/checkpoint".into(),
        wallet_destination: "/synthetic/wallet/wallet.sqlite".into(),
        purpose: "preliminary_inventory_only".into(),
        retention_policy: "Keep only at exact local destination until explicit deletion".into(),
        provider: PreconstructionProvider {
            source_id: "synthetic-provider".into(),
            endpoint: "https://synthetic.invalid".into(),
            trust_profile: "single_tls_provider_report_not_consensus".into(),
        },
        birthday: PreconstructionBirthday {
            prior_height: 1,
            prior_block_hash: h('7'),
            sapling_tree: String::new(),
            orchard_tree: String::new(),
            ironwood_tree: String::new(),
        },
        minimum_confirmations: 1,
        maximum_blocks: 10,
        anchor_height: 100,
    };
    let economic_intent = economics();
    let invocation = ManualCandidateInvocation {
        version: 1,
        operation_id: "synthetic-invocation".into(),
        idempotency_key_digest: h('8'),
        invocation_nonce: h('9'),
        economic_intent_digest: economic_intent.digest().unwrap(),
        checkpoint_destination: inventory.operator_destination.clone(),
        requested_at_ms: 2000,
        construction_expires_at_ms: 100_000,
    };
    ManualCandidateSelectionRequest {
        version: 1,
        operation_id: "synthetic-select".into(),
        scope: ManualCandidateSelectionScope {
            version: 1,
            inventory,
            original_policy_origin: origin,
            economic_intent,
            invocation,
            purpose: "prepare_one_private_contribution".into(),
        },
        current_caller_binding_digest: h('a'),
        requested_at_ms: 2000,
        disclosure_expires_at_ms: 32_000,
    }
}

fn request() -> ManualRosterCandidateSelectionRequestV2 {
    let r = inner_request();
    let provenance = crate::manual_roster_inventory_v2::test_provenance(&r.scope.inventory);
    ManualRosterCandidateSelectionRequestV2 {
        version: 2,
        operation_id: r.operation_id,
        scope: ManualRosterCandidateSelectionScopeV2 {
            version: 2,
            selection: r.scope,
            provenance,
        },
        current_caller_binding_digest: r.current_caller_binding_digest,
        requested_at_ms: r.requested_at_ms,
        disclosure_expires_at_ms: r.disclosure_expires_at_ms,
    }
}
#[test]
fn selection_is_input_free_exact_economics_under_distinct_v2_provenance() {
    let r = request();
    r.validate().unwrap();
    assert_eq!(r.scope.requested_debit_zatoshis().unwrap(), 400_012_000);
    let mut changed = r.clone();
    changed.scope.provenance.signer_roster_record_digest = h('9');
    assert_ne!(
        r.scope.pairing_digest().unwrap(),
        changed.scope.pairing_digest().unwrap()
    );
    let mut changed = r.clone();
    changed.scope.selection.economic_intent.participants[0].contribution = a(1);
    assert!(changed.validate().is_err());
    let mut data = serde_json::to_value(&r).unwrap();
    data["scope"]["selection"]["economic_intent"]["selected_inputs"] = serde_json::json!([]);
    assert!(serde_json::from_value::<ManualRosterCandidateSelectionRequestV2>(data).is_err());
    assert!(
        serde_json::from_value::<ManualRosterCandidateSelectionRequestV2>(
            serde_json::to_value(inner_request()).unwrap()
        )
        .is_err()
    );
}
#[test]
fn selection_does_not_borrow_completion_deadline_or_preliminary_pairing() {
    let r = request();
    assert_eq!(r.remaining_ms(31_999).unwrap(), 1);
    assert!(r.remaining_ms(32_000).is_err());
    assert!(r.remaining_ms(1_999).is_err());
    let inventory = crate::manual_roster_inventory_v2::ManualRosterInventoryScopeV2 {
        version: 2,
        inventory: r.scope.selection.inventory.clone(),
        provenance: r.scope.provenance.clone(),
    };
    assert_ne!(
        r.scope.pairing_digest().unwrap(),
        inventory.pairing_digest().unwrap()
    );
    let mut changed = r;
    changed.disclosure_expires_at_ms = changed
        .scope
        .selection
        .invocation
        .construction_expires_at_ms;
    assert!(changed.validate().is_err());
}
