use super::*;
use crate::manual_roster_candidate_selection_v2::ManualRosterCandidateSelectionScopeV2;
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
        agreement: crate::parse_typed_json(include_bytes!("../tests/fixtures/agreement.json"))
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

fn retention() -> ManualRosterContributionRetentionRequestV2 {
    let selection = request();
    let anchor = selection.scope.selection.inventory.anchor_height;
    let address = selection
        .scope
        .selection
        .economic_intent
        .agreement
        .recipients[0]
        .address
        .clone();
    let requested_at_ms = selection.requested_at_ms + 1;
    let admission_expires_at_ms = selection.disclosure_expires_at_ms;
    ManualRosterContributionRetentionRequestV2 {
        version: 2,
        operation_id: "synthetic-retain".into(),
        selection,
        selection_evidence_digest: h('a'),
        selected_inputs: vec![ManualConstructionInput {
            input_id: "synthetic-alice-input".into(),
            nullifier: h('b'),
            value_zatoshis: 400_112_000,
        }],
        selection_context: ManualSelectionContext {
            tip_height: anchor + 1,
            tip_hash_protocol: h('c'),
            anchor_height: anchor,
            anchor_hash_protocol: h('d'),
            anchor_root: h('e'),
        },
        local_exclusion_digest: h('f'),
        change_address: address,
        change_value_zatoshis: 100_000,
        requested_at_ms,
        admission_expires_at_ms,
    }
}
pub(crate) fn plan() -> ManualRosterConstructionPlanV2 {
    let retained = retention();
    let e = &retained.selection.scope.selection.economic_intent;
    let mut outputs: Vec<_> = e
        .agreement
        .recipients
        .iter()
        .enumerate()
        .map(|(n, r)| crate::ClaimedOutput {
            output_id: format!("recipient-{n}"),
            address: r.address.clone(),
            amount: r.amount,
            allocation: OutputAllocation::Recipient {
                recipient_id: r.recipient_id.clone(),
            },
        })
        .collect();
    outputs.push(crate::ClaimedOutput {
        output_id: "return-alice".into(),
        address: retained.change_address.clone(),
        amount: a(100_000),
        allocation: OutputAllocation::Return {
            participant_id: "alice".into(),
            account_id: e.participants[0].account_id.clone(),
            ownership_evidence_ref: None,
        },
    });
    let proposal = ProposalInput {
        proposal_id: e.proposal_id.clone(),
        previous_proposal_id: e.previous_proposal_id.clone(),
        created_at: e.created_at.clone(),
        artifact_digest: None,
        effects_commitment: None,
        manifest: crate::ProposalManifest {
            agreement: e.agreement.clone(),
            participants: e.participants.clone(),
            transaction_fee: e.transaction_fee,
            expiry_height: e.expiry_height,
            outputs,
            inputs: vec![
                crate::ClaimedInput {
                    input_id: "synthetic-alice-input".into(),
                    participant_id: "alice".into(),
                    account_id: e.participants[0].account_id.clone(),
                    amount: a(400_112_000),
                    ownership_evidence_ref: None,
                },
                crate::ClaimedInput {
                    input_id: "synthetic-bob-input".into(),
                    participant_id: "bob".into(),
                    account_id: e.participants[1].account_id.clone(),
                    amount: a(600_018_000),
                    ownership_evidence_ref: None,
                },
            ],
        },
    };
    let participants = vec![
        ManualRosterRetentionCommitmentV2 {
            participant_id: "alice".into(),
            account_id: e.participants[0].account_id.clone(),
            full_viewing_key_digest: retained
                .selection
                .scope
                .selection
                .inventory
                .enrollment
                .identity
                .full_viewing_key_digest
                .clone(),
            retention_request_digest: retained.digest().unwrap(),
            retention_evidence_digest: h('1'),
        },
        ManualRosterRetentionCommitmentV2 {
            participant_id: "bob".into(),
            account_id: e.participants[1].account_id.clone(),
            full_viewing_key_digest: h('d'),
            retention_request_digest: h('2'),
            retention_evidence_digest: h('3'),
        },
    ];
    ManualRosterConstructionPlanV2 {
        version: 2,
        retained,
        retained_evidence_digest: h('1'),
        proposal,
        participants,
    }
}
#[test]
fn retention_is_exact_and_cannot_extend_original_selection_window() {
    let r = retention();
    r.validate().unwrap();
    assert!(r.remaining_admission_ms(r.requested_at_ms - 1).is_err());
    assert!(r.remaining_admission_ms(r.admission_expires_at_ms).is_err());
    let mut changed = r.clone();
    changed.admission_expires_at_ms += 1;
    assert!(changed.validate().is_err());
    let mut changed = r.clone();
    changed.change_value_zatoshis += 1;
    assert!(changed.validate().is_err());
    let mut changed = r;
    changed
        .selected_inputs
        .push(changed.selected_inputs[0].clone());
    assert!(changed.validate().is_err());
}
#[test]
fn complete_proposal_requires_every_original_account_and_distinct_viewing_identity() {
    let p = plan();
    p.validate().unwrap();
    let mut changed = p.clone();
    changed.participants.pop();
    assert!(changed.validate().is_err());
    let mut changed = p.clone();
    changed.participants[1].full_viewing_key_digest =
        changed.participants[0].full_viewing_key_digest.clone();
    assert!(changed.validate().is_err());
    let mut changed = p;
    changed.participants[0].retention_request_digest = h('8');
    assert!(changed.validate().is_err());
}
#[test]
fn proposal_cannot_replace_observed_input_or_same_account_return() {
    let p = plan();
    p.validate().unwrap();
    let mut changed = p.clone();
    changed.proposal.manifest.inputs[0].input_id = "replacement-input".into();
    assert!(changed.validate().is_err());
    let mut changed = p.clone();
    changed
        .proposal
        .manifest
        .outputs
        .last_mut()
        .unwrap()
        .address = "replacement-return".into();
    assert!(changed.validate().is_err());
    let mut changed = p;
    changed.proposal.artifact_digest = Some(h('a'));
    assert!(changed.validate().is_err());
}
#[test]
fn fresh_construction_admission_never_renews_original_completion() {
    let plan = plan();
    let now = plan.retained.admission_expires_at_ms + 1;
    let r = ManualRosterConstructionRequestV2 {
        version: 2,
        operation_id: "synthetic-reserve".into(),
        plan,
        current_caller_binding_digest: h('a'),
        requested_at_ms: now,
        admission_expires_at_ms: now + 1,
    };
    r.validate().unwrap();
    let mut changed = r.clone();
    changed.admission_expires_at_ms = changed.plan.completion_deadline_ms() + 1;
    assert!(changed.validate().is_err());
    assert!(r.remaining_admission_ms(now - 1).is_err());
    assert!(r.remaining_admission_ms(now + 1).is_err());
}
#[test]
fn retention_and_construction_data_reject_capability_and_version_fields() {
    let p = plan();
    p.validate().unwrap();
    let mut data = serde_json::to_value(&p).unwrap();
    data["approved"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ManualRosterConstructionPlanV2>(data).is_err());
    let mut r = retention();
    r.version = 1;
    assert!(r.validate().is_err());
}
