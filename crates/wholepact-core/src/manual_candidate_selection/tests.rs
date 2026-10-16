use super::*;
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
fn request() -> ManualCandidateSelectionRequest {
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
#[test]
fn exact_economics_without_inputs_derives_debit_and_rejects_placeholder_fields() {
    let e = economics();
    assert_eq!(e.validate().unwrap()["alice"], a(400_012_000));
    let mut later_record = e.clone();
    later_record.candidate_revision = 12;
    assert_eq!(later_record.agreement.revision, 1);
    assert!(later_record.validate().is_ok());
    assert_ne!(e.digest().unwrap(), later_record.digest().unwrap());
    // Record CAS revision is checked by the real Engine reader, independently
    // of the agreement draft terms revision; neither is fabricated by core.

    for key in [
        "inputs",
        "outputs",
        "selected_inputs",
        "selection_context",
        "proposal",
        "approved",
        "requested_debit_zatoshis",
    ] {
        let mut v = serde_json::to_value(&e).unwrap();
        v[key] = serde_json::json!([]);
        assert!(serde_json::from_value::<ManualCandidateEconomicIntent>(v).is_err());
    }
}
#[test]
fn economics_reuses_deterministic_fees_and_conservation_without_faking_inputs() {
    for n in 0..7 {
        let mut e = economics();
        match n {
            0 => e.participants[0].contribution = a(399_999_999),
            1 => {
                e.participants[0].fee_share = a(11_999);
                e.participants[1].fee_share = a(18_001);
                e.participants[1].fee_cap = a(18_001);
                e.participants[1].maximum_net_debit = a(600_018_001);
            }
            2 => e.participants[0].maximum_net_debit = a(400_011_999),
            3 => e.participants[0].account_id = e.participants[1].account_id.clone(),
            4 => e.participants.swap(0, 1),
            5 => e.expiry_height = 0,
            _ => e.candidate_revision = 0,
        }
        assert!(e.validate().is_err());
    }
}
#[test]
fn policy_and_narrower_enrollment_constraints_both_apply_before_selection() {
    let e = economics();
    let (terms, policy) = crate::born_recipient_policy_v2::tests::modeled_terms_and_policy();
    assert_eq!(e.require_policy(&policy, &terms).unwrap(), a(400_012_000));
    let mut redirect = e.clone();
    redirect.agreement.recipients[0].address = "uRedirected".into();
    assert!(redirect.validate().is_ok());
    assert!(redirect.require_policy(&policy, &terms).is_err());
    let mut narrower = terms.clone();
    narrower.scope.per_operation_limit_zatoshis -= 1;
    assert!(e.require_policy(&policy, &narrower).is_err());
    let mut charges = e;
    charges.participants[0]
        .charges
        .push(crate::proposal::ChargeConsent {
            charge_id: "hidden".into(),
            address: "uHidden".into(),
            amount: a(1),
            purpose: "Unapproved charge".into(),
        });
    charges.participants[0].maximum_net_debit = a(400_012_001);
    assert!(charges.require_policy(&policy, &terms).is_err());
}
#[test]
fn selection_has_distinct_purpose_pairing_and_original_fixed_deadline() {
    let r = request();
    r.validate().unwrap();
    assert_eq!(r.scope.requested_debit_zatoshis().unwrap(), 400_012_000);
    assert_ne!(
        r.scope.pairing_digest().unwrap(),
        r.scope.inventory.pairing_digest().unwrap()
    );
    assert_eq!(r.remaining_ms(31_999).unwrap(), 1);
    assert!(r.remaining_ms(32_000).is_err());
    assert!(r.remaining_ms(1999).is_err());
    let mut later = r.clone();
    later.disclosure_expires_at_ms += 1;
    assert!(later.validate().is_err());
    let mut wrong = r.clone();
    wrong.scope.purpose = "preliminary_inventory_only".into();
    assert!(wrong.validate().is_err());
    let mut grant = r.clone();
    grant.current_caller_binding_digest = h('f');
    assert_eq!(
        r.scope.pairing_digest().unwrap(),
        grant.scope.pairing_digest().unwrap()
    );
    assert_ne!(r.digest().unwrap(), grant.digest().unwrap());
}
#[test]
fn original_birth_candidate_invocation_and_wallet_identity_cannot_be_substituted() {
    let r = request();
    r.validate().unwrap();
    for n in 0..8 {
        let mut wrong = r.clone();
        match n {
            0 => wrong.scope.original_policy_origin.birth_digest = h('0'),
            1 => wrong.scope.inventory.enrollment.native_birth_digest = h('0'),
            2 => wrong.scope.economic_intent.candidate_revision += 1,
            3 => wrong.scope.invocation.checkpoint_destination = "/synthetic/other".into(),
            4 => wrong.scope.inventory.wallet_destination = "/synthetic/wallet/other.sqlite".into(),
            5 => wrong.scope.inventory.attachment.selected.account_id = h('0'),
            6 => {
                wrong
                    .scope
                    .inventory
                    .enrollment
                    .original_witness_origin_digest = h('0')
            }
            _ => wrong.scope.invocation.construction_expires_at_ms = 200_001,
        }
        assert!(wrong.validate().is_err());
    }
    let mut actual_destination = r.clone();
    actual_destination.scope.inventory.provider.endpoint = "https://another.invalid".into();
    assert!(actual_destination.validate().is_ok());
    assert_ne!(
        r.scope.pairing_digest().unwrap(),
        actual_destination.scope.pairing_digest().unwrap()
    );
}
#[test]
fn full_proposal_requires_actual_inputs_and_cannot_enter_selection_codec() {
    let r = request();
    let mut v = serde_json::to_value(&r).unwrap();
    v["scope"]["selected_inputs"] = serde_json::json!([]);
    assert!(serde_json::from_value::<ManualCandidateSelectionRequest>(v).is_err());
    let mut v = serde_json::to_value(&r).unwrap();
    v["scope"]["economic_intent"]["artifact_digest"] = serde_json::json!(h('f'));
    assert!(serde_json::from_value::<ManualCandidateSelectionRequest>(v).is_err());
}
