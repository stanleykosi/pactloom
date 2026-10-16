// Synthetic inert record tests only; no native permit, wallet, proof or live witness.
use super::*;
use wholepact_core::manual_roster_candidate_selection_v2::{
    ManualRosterCandidateSelectionRequestV2, ManualRosterCandidateSelectionScopeV2,
};
use wholepact_core::manual_roster_construction_v2::*;
use wholepact_core::{
    Amount, born_recipient_policy_v2::BornOwnReturnRuleV2, manual_candidate_selection::*,
    manual_inventory::ManualPreliminaryInventoryScope, proposal::ParticipantAllocation,
};
use wholepact_core::{OutputAllocation, ProposalInput};
use wholepact_core::{born_policy_origin_v2::*, manual_construction::*};
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
        agreement: wholepact_core::parse_typed_json(include_bytes!(
            "../../../wholepact-core/tests/fixtures/agreement.json"
        ))
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
    let (mut enrollment, policy) = modeled_terms_and_policy();
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
        birth_digest: wholepact_core::proposal::canonical_digest(
            "wholepact:native-account-birth-intent:v2",
            &(&intent, &policy),
        )
        .unwrap(),
        intent,
        recipient_policy: policy.clone(),
    };
    enrollment.native_birth_digest = origin.birth_digest.clone();
    let o = &origin.intent.witness_origin;
    enrollment.original_witness_origin_digest = wholepact_core::proposal::canonical_digest(
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
    let provenance = test_provenance(&r.scope.inventory);
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
fn plan() -> ManualRosterConstructionPlanV2 {
    let retained = retention();
    let e = &retained.selection.scope.selection.economic_intent;
    let mut outputs: Vec<_> = e
        .agreement
        .recipients
        .iter()
        .enumerate()
        .map(|(n, r)| wholepact_core::ClaimedOutput {
            output_id: format!("recipient-{n}"),
            address: r.address.clone(),
            amount: r.amount,
            allocation: OutputAllocation::Recipient {
                recipient_id: r.recipient_id.clone(),
            },
        })
        .collect();
    outputs.push(wholepact_core::ClaimedOutput {
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
        manifest: wholepact_core::ProposalManifest {
            agreement: e.agreement.clone(),
            participants: e.participants.clone(),
            transaction_fee: e.transaction_fee,
            expiry_height: e.expiry_height,
            outputs,
            inputs: vec![
                wholepact_core::ClaimedInput {
                    input_id: "synthetic-alice-input".into(),
                    participant_id: "alice".into(),
                    account_id: e.participants[0].account_id.clone(),
                    amount: a(400_112_000),
                    ownership_evidence_ref: None,
                },
                wholepact_core::ClaimedInput {
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

use wholepact_core::born_recipient_policy_v2::{
    BornConstructionRecipientPolicyV2, BornOriginalLimitsV2, BornRecipientLimitV2,
};
use wholepact_core::manual_enrollment::{
    BornManualEnrollmentTerms, BornManualScope, BornManualSignerBinding, ManualAccountIdentity,
    ManualHostGenerationBinding,
};
use wholepact_core::manual_roster_inventory_v2::{
    ManualRosterPreparationProvenanceV2, OriginalHostRosterAuditV3,
};
use wholepact_core::manual_roster_v2::HostRosterAppendBindingV2;
fn terms() -> BornManualEnrollmentTerms {
    BornManualEnrollmentTerms {
        version: 1,
        operation_id: "synthetic-enrollment".into(),
        identity: ManualAccountIdentity {
            account_id: h('a'),
            full_viewing_key_digest: h('b'),
            network_profile_id: "synthetic-testnet".into(),
            derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
        },
        birth_request_digest: h('c'),
        birth_commit_digest: h('d'),
        native_birth_digest: h('e'),
        original_policy_digest: h('f'),
        account_use_genesis_digest: h('1'),
        original_witness_origin_digest: h('2'),
        host: ManualHostGenerationBinding {
            generation_id: h('3'),
            inventory_digest: h('4'),
            generation_plan_digest: h('5'),
            financial_journal_origin_digest: h('6'),
            store_destination_identity: "/synthetic/host/coordination.sqlite".into(),
            profile_id: "synthetic-profile".into(),
            canonical_root: "/synthetic/host".into(),
            destination_identity_digest: h('7'),
            inherited_identity_digest: h('8'),
            scope_predecessor_digest: None,
        },
        signer: BornManualSignerBinding {
            enrollment_generation_id: h('9'),
            signer_target_digest: h('a'),
            original_envelope_digest: h('b'),
            owner_certificate_digest: h('c'),
            writer_certificate_digest: h('d'),
            writer_epoch: 1,
            native_signer_measurement: h('e'),
        },
        scope: BornManualScope {
            agreement_id: "synthetic-agreement".into(),
            obligation_id: "synthetic-obligation".into(),
            participant_id: "synthetic-participant".into(),
            principal_id: "synthetic-principal".into(),
            privacy_domain: "synthetic-domain".into(),
            recipient_scope_digests: vec![h('f')],
            aggregate_budget_zatoshis: 100,
            per_operation_limit_zatoshis: 50,
            maximum_fee_share_zatoshis: 2,
            maximum_transaction_fee_zatoshis: 200,
            maximum_permit_lifetime_ms: 500,
            expires_at_ms: 2000,
        },
        transport_binding_digest: h('1'),
        issued_at_ms: 1000,
    }
}
fn test_provenance(
    inventory: &ManualPreliminaryInventoryScope,
) -> ManualRosterPreparationProvenanceV2 {
    ManualRosterPreparationProvenanceV2 {
        version: 2,
        original_host_audit: OriginalHostRosterAuditV3::AdditionalPublicationV3 {
            audit_digest: "91".repeat(32),
        },
        roster: HostRosterAppendBindingV2 {
            version: 2,
            generation_id: inventory.enrollment.host.generation_id.clone(),
            store_destination_identity: inventory
                .enrollment
                .host
                .store_destination_identity
                .clone(),
            roster_sequence: 2,
            predecessor:
                wholepact_core::manual_roster_v2::HostRosterPredecessorV2::InitialPublicationV2 {
                    audit_digest: "92".repeat(32),
                },
        },
        signer_roster_record_digest: "93".repeat(32),
        witness_roster_extension_digest: "94".repeat(32),
    }
}

fn modeled_terms_and_policy() -> (BornManualEnrollmentTerms, BornConstructionRecipientPolicyV2) {
    let e = economics();
    let mut t = terms();
    let policy = BornConstructionRecipientPolicyV2 {
        version: 2,
        account_id: e.participants[0].account_id.clone(),
        network_profile_id: e.agreement.network_profile_id.clone(),
        agreement_id: e.agreement.agreement_id.clone(),
        obligation_id: e.agreement.obligation_id.clone(),
        participant_id: "alice".into(),
        recipients: e
            .agreement
            .recipients
            .iter()
            .map(|r| BornRecipientLimitV2 {
                recipient_id: r.recipient_id.clone(),
                address: r.address.clone(),
                memo: r.memo.clone(),
                instruction_provenance: r.instruction_provenance.clone(),
                maximum_amount_zatoshis: r.amount.as_zatoshis(),
            })
            .collect(),
        charges: vec![],
        original_limits: BornOriginalLimitsV2 {
            aggregate_budget_zatoshis: 2_000_000_000,
            per_operation_limit_zatoshis: 700_000_000,
            maximum_fee_share_zatoshis: 30_000,
            maximum_transaction_fee_zatoshis: 30_000,
            maximum_permit_lifetime_ms: 120_000,
            policy_expires_at_ms: 500_000,
        },
        own_return_rule: BornOwnReturnRuleV2::AuthenticatedSameAccount,
    };
    t.identity.account_id = policy.account_id.clone();
    t.identity.network_profile_id = policy.network_profile_id.clone();
    t.scope.agreement_id = policy.agreement_id.clone();
    t.scope.obligation_id = policy.obligation_id.clone();
    t.scope.participant_id = policy.participant_id.clone();
    t.scope.recipient_scope_digests = vec![policy.digest().unwrap()];
    t.scope.aggregate_budget_zatoshis = 1_000_000_000;
    t.scope.per_operation_limit_zatoshis = 700_000_000;
    t.scope.maximum_fee_share_zatoshis = 30_000;
    t.scope.maximum_transaction_fee_zatoshis = 30_000;
    t.scope.expires_at_ms = 200_000;
    (t, policy)
}
pub(crate) fn claim() -> ManualRosterConstructionClaimV2 {
    let mut alice = plan();
    let key = "synthetic-construction-key";
    alice
        .retained
        .selection
        .scope
        .selection
        .invocation
        .idempotency_key_digest =
        request_digest(&serde_json::json!(["synthetic-principal", key])).unwrap();
    let mut bob = alice.retained.clone();
    bob.operation_id = "synthetic-retain-bob".into();
    bob.selection.operation_id = "synthetic-select-bob".into();
    bob.selected_inputs = vec![ManualConstructionInput {
        input_id: "synthetic-bob-input".into(),
        nullifier: h('9'),
        value_zatoshis: 600_018_000,
    }];
    bob.change_value_zatoshis = 0;
    let s = &mut bob.selection.scope.selection;
    let p = &mut s.inventory.original_recipient_policy;
    p.account_id = "22".repeat(32);
    p.participant_id = "bob".into();
    let t = &mut s.inventory.enrollment;
    t.operation_id = "synthetic-enrollment-bob".into();
    t.identity.account_id = p.account_id.clone();
    t.identity.full_viewing_key_digest = h('d');
    t.scope.participant_id = "bob".into();
    t.scope.recipient_scope_digests = vec![p.digest().unwrap()];
    t.original_policy_digest = p.digest().unwrap();
    s.inventory.attachment.selected.account_id = t.identity.account_id.clone();
    let o = &mut s.original_policy_origin;
    o.recipient_policy = p.clone();
    o.intent.identity.account_id = t.identity.account_id.clone();
    o.intent.identity.full_viewing_key_digest = t.identity.full_viewing_key_digest.clone();
    o.intent.original_policy_terms.account_id = t.identity.account_id.clone();
    o.intent.original_policy_terms.recipient_scope_digests = vec![p.digest().unwrap()];
    o.intent.original_policy_terms_digest = o.intent.original_policy_terms.digest().unwrap();
    o.birth_digest = wholepact_core::proposal::canonical_digest(
        "wholepact:native-account-birth-intent:v2",
        &(&o.intent, &o.recipient_policy),
    )
    .unwrap();
    t.native_birth_digest = o.birth_digest.clone();
    bob.validate().unwrap();
    alice.participants[0].retention_request_digest = alice.retained.digest().unwrap();
    alice.participants[1].retention_request_digest = bob.digest().unwrap();
    let mut bob_plan = alice.clone();
    bob_plan.retained = bob;
    bob_plan.retained_evidence_digest = alice.participants[1].retention_evidence_digest.clone();
    let consumed = [alice, bob_plan]
        .into_iter()
        .enumerate()
        .map(|(i, plan)| ManualRosterConsumedConstructionAuditV2 {
            version: 2,
            request: ManualRosterConstructionRequestV2 {
                version: 2,
                operation_id: format!("synthetic-construct-{i}"),
                plan,
                current_caller_binding_digest: h('1'),
                requested_at_ms: 2002,
                admission_expires_at_ms: 32000,
            },
            retained_signer_intent_digest: h('2'),
            current_attempt_digest: h('3'),
            current_attempt_sequence: 3,
            native_review_digest: if i == 0 { h('4') } else { h('5') },
            witness_reservation_digest: if i == 0 { h('6') } else { h('7') },
            witness_consumed_digest: if i == 0 { h('8') } else { h('9') },
            reviewed_at_ms: 2003,
            reserved_at_ms: 2004,
            consumed_at_ms: 2005,
            reserved_debit_zatoshis: if i == 0 { 400_012_000 } else { 600_018_000 },
            reserved_input_value_zatoshis: if i == 0 { 400_112_000 } else { 600_018_000 },
            writer_session_expires_at_ms: 100_000,
        })
        .collect();
    ManualRosterConstructionClaimV2 {
        version: 2,
        principal_id: "synthetic-principal".into(),
        construction_key: key.into(),
        maximum_actions: 8,
        consumed,
    }
}
fn checkpoint(c: &ManualRosterConstructionClaimV2) -> ManualRosterConstructionCheckpointV2 {
    let p = c.validate().unwrap();
    let inventory = &c.consumed[0]
        .request
        .plan
        .retained
        .selection
        .scope
        .selection
        .inventory;
    ManualRosterConstructionCheckpointV2 {
        version: 2,
        claim_digest: c.digest().unwrap(),
        job_id: expected_job_id(&c.principal_id, &c.construction_key),
        scope: ManualRosterCheckpointScopeV2 {
            principal_id: c.principal_id.clone(),
            candidate_id: c.candidate_id().into(),
            manifest_digest: p.manifest_digest().into(),
            artifact_digest: h('a'),
            effects_commitment: h('b'),
            coordination_request_digest: c.request_digest().unwrap(),
            review_binding: h('c'),
            account_ids: p
                .manifest()
                .participants
                .iter()
                .map(|p| p.account_id.clone())
                .collect(),
            local_operator: inventory.operator_name.clone(),
            purpose: "construct_one_candidate".into(),
            retention_policy: inventory.retention_policy.clone(),
        },
    }
}
#[test]
fn complete_exact_claim_and_receipt_validate_without_creating_permission() {
    let c = claim();
    assert_eq!(
        expected_job_id(&c.principal_id, &c.construction_key),
        "proof-85f28d37bfc9f4c3c309380c4c3571599ad57dc13b2f95c1f0a91cadee020fd1"
    );
    c.validate().unwrap();
    let r = checkpoint(&c);
    r.validate_for(&c).unwrap();
    validate_construction_set(
        &[(c.digest().unwrap(), c.clone())],
        &[(r.claim_digest.clone(), r)],
    )
    .unwrap();
    let raw = serde_json::to_value(&c).unwrap();
    let decoded: ManualRosterConstructionClaimV2 = strict(&raw).unwrap();
    assert!(decoded == c);
    // DTO equality does not issue a token; no deserialize/constructor exists for it.
}
#[test]
fn duplicate_attempt_changed_key_missing_participant_and_reused_consume_fail_closed() {
    let c = claim();
    let id = c.digest().unwrap();
    assert!(validate_construction_set(&[(id.clone(), c.clone()), (id, c.clone())], &[]).is_err());
    let mut changed = c.clone();
    changed.construction_key.push('x');
    assert!(changed.validate().is_err());
    let mut changed = c.clone();
    changed.consumed.pop();
    assert!(changed.validate().is_err());
    let mut changed = c.clone();
    changed.consumed[1].witness_consumed_digest =
        changed.consumed[0].witness_consumed_digest.clone();
    assert!(changed.validate().is_err());
    let mut changed = c.clone();
    changed.consumed[1].request.plan.proposal.created_at = "2026-10-14T14:00:00Z".into();
    assert!(changed.validate().is_err());
    let mut changed = c.clone();
    changed.consumed[0].request.current_caller_binding_digest = h('f');
    changed.validate().unwrap();
    assert_ne!(changed.digest().unwrap(), c.digest().unwrap());
    assert!(
        validate_construction_set(
            &[
                (c.digest().unwrap(), c),
                (changed.digest().unwrap(), changed)
            ],
            &[]
        )
        .is_err()
    );
}
#[test]
fn altered_checkpoint_binding_or_orphan_receipt_never_confirms_private_result() {
    let c = claim();
    let r = checkpoint(&c);
    assert!(validate_construction_set(&[], &[(r.claim_digest.clone(), r.clone())]).is_err());
    for field in 0..8 {
        let mut q = r.clone();
        match field {
            0 => q.claim_digest = h('f'),
            1 => q.job_id = "proof-wrong".into(),
            2 => q.scope.coordination_request_digest = h('e'),
            3 => q.scope.candidate_id = "other".into(),
            4 => q.scope.manifest_digest = h('d'),
            5 => q.scope.account_ids.pop().map(|_| ()).unwrap(),
            6 => q.scope.purpose = "prove_locally".into(),
            _ => q.scope.retention_policy.push('x'),
        };
        assert!(q.validate_for(&c).is_err());
    }
}
#[test]
fn unknown_nested_fields_or_mutable_claim_records_fail_strict_read() {
    let c = claim();
    let mut value = serde_json::to_value(&c).unwrap();
    value["consumed"][0]["approved"] = true.into();
    assert!(strict::<ManualRosterConstructionClaimV2>(&value).is_err());
    let mut record = StoredRecord {
        id: c.digest().unwrap(),
        revision: 0,
        payload: serde_json::to_value(c).unwrap(),
        created_at_ms: 1,
        updated_at_ms: 1,
    };
    validate_construction_record(CONSTRUCTION_CLAIM_V2, &record).unwrap();
    record.revision = 1;
    assert!(validate_construction_record(CONSTRUCTION_CLAIM_V2, &record).is_err());
    record.revision = 0;
    record.updated_at_ms = 2;
    assert!(validate_construction_record(CONSTRUCTION_CLAIM_V2, &record).is_err());
}
#[test]
fn generic_metadata_writes_and_orphan_receipt_reads_cannot_mint_claims() {
    let store = Store::in_memory().unwrap();
    let c = claim();
    let ctx = crate::CommandContext::for_request(
        "synthetic-principal",
        "synthetic-generic-key",
        &serde_json::json!({}),
    )
    .unwrap();
    assert!(
        store
            .commit_record(
                &ctx,
                CONSTRUCTION_CLAIM_V2,
                &c.digest().unwrap(),
                None,
                serde_json::to_value(&c).unwrap(),
                "created"
            )
            .is_err()
    );
    let r = checkpoint(&c);
    store
        .connection
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO records VALUES(?1,?2,0,?3,1,1)",
            rusqlite::params![
                CONSTRUCTION_CHECKPOINT_V2,
                r.claim_digest,
                serde_json::to_string(&r).unwrap()
            ],
        )
        .unwrap();
    assert!(
        store
            .get_record(CONSTRUCTION_CHECKPOINT_V2, &r.claim_digest)
            .is_err()
    );
    assert!(store.list_records(CONSTRUCTION_CHECKPOINT_V2).is_err());
    assert!(
        store
            .manual_roster_construction_evidence_v2(&c.principal_id, &c.construction_key)
            .is_err()
    );
}
#[test]
fn consumed_evidence_exact_mirror_has_same_native_digest_domain() {
    let c = claim();
    let audit = &c.consumed[0];
    assert_eq!(
        audit.digest().unwrap(),
        wholepact_core::proposal::canonical_digest(
            "wholepact:roster-construction-consumed-native-evidence:v2",
            audit
        )
        .unwrap()
    );
}

/// Build the maintained synthetic roster lineage without constructing or
/// validating a V2 claim. Original selection contexts are never rewritten.
/// V3 tests reuse this exact helper with their own independently valid originals.
pub(crate) fn modeled_construction_roster_history(
    root: &ManualEnrollmentInitialPublicationV2,
    retained: &mut [ManualRosterContributionRetentionRequestV2],
    previous: Option<&ManualEnrollmentAdditionalPublicationV3>,
) -> (
    Vec<ManualEnrollmentAdditionalPublicationV3>,
    Vec<ManualEnrollmentContinuationAuditV4>,
    Vec<String>,
) {
    let digest = |index: usize, tag: &str| {
        request_digest(&serde_json::json!([
            "synthetic-construction-history",
            index,
            tag
        ]))
        .unwrap()
    };
    let mut originals = Vec::new();
    let mut continuations = Vec::new();
    let mut current_attempts = Vec::new();
    let offset = previous.map(|a| a.store_sequence as usize - 1).unwrap_or(0);
    for (position, retained) in retained.iter_mut().enumerate() {
        let i = offset + position;
        let selection = &mut retained.selection.scope;
        let inventory = &mut selection.selection.inventory;
        inventory.enrollment.host = root.terms().host.clone();
        inventory.attachment.original_primary_journal_origin_digest =
            root.terms().host.financial_journal_origin_digest.clone();
        inventory.enrollment_ref = digest(i, "enrollment");
        inventory.witness_extension_digest = digest(i, "extension");
        inventory.attempt.continuation_digest = digest(i, "selection-attempt");
        selection.provenance.roster = HostRosterAppendBindingV2 {
            version: 2,
            generation_id: root.terms().host.generation_id.clone(),
            store_destination_identity: root.terms().host.store_destination_identity.clone(),
            roster_sequence: i as u64 + 2,
            predecessor: if position == 0 && previous.is_none() {
                wholepact_core::manual_roster_v2::HostRosterPredecessorV2::InitialPublicationV2 {
                    audit_digest: root.digest().unwrap(),
                }
            } else {
                wholepact_core::manual_roster_v2::HostRosterPredecessorV2::AdditionalPublicationV3 {
                    audit_digest: originals
                        .last()
                        .or(previous)
                        .map(|a: &ManualEnrollmentAdditionalPublicationV3| a.digest().unwrap())
                        .unwrap(),
                }
            },
        };
        selection.provenance.signer_roster_record_digest = digest(i, "signer-roster");
        selection.provenance.witness_roster_extension_digest = digest(i, "witness-roster");
        let request = ManualRosterPublicationRequestV2 {
            version: 2,
            enrollment: ManualContinuationEnrollment {
                terms: inventory.enrollment.clone(),
            },
            roster: selection.provenance.roster.clone(),
            attempt: ManualRosterPublicationAttemptV2::InitialV2 {},
        };
        let mut current = root.evidence.current.clone();
        current.writer_certificate_digest = inventory
            .enrollment
            .signer
            .writer_certificate_digest
            .clone();
        current.writer_epoch = inventory.enrollment.signer.writer_epoch;
        current.writer_session_digest = digest(i, "initial-session");
        current.writer_session_expires_at_ms = 100_000;
        current.witness_head_sequence = 1;
        let original = ManualEnrollmentAdditionalPublicationV3 {
            version: 3,
            operation_id: format!("synthetic-construction-publication-{i}"),
            request_identity_digest: digest(i, "publication-key"),
            provider_enrollment_ref: digest(i, "provider"),
            store_sequence: i as u64 + 2,
            aliases: BTreeSet::from([inventory.enrollment.identity.account_id.clone()]),
            evidence: ManualRosterEnrollmentEvidenceV2 {
                version: 2,
                enrollment_ref: inventory.enrollment_ref.clone(),
                signer_roster_record_digest: selection
                    .provenance
                    .signer_roster_record_digest
                    .clone(),
                witness_roster_extension_digest: selection
                    .provenance
                    .witness_roster_extension_digest
                    .clone(),
                witness_extension_digest: inventory.witness_extension_digest.clone(),
                witness_extension_sequence: 1,
                witness_extension_predecessor_digest: None,
                admission: ManualRosterAdmissionV2 {
                    version: 2,
                    exact_request_digest: request.digest().unwrap(),
                    signer_intent_digest: digest(i, "original-intent"),
                    witness_admission_digest: digest(i, "original-witness"),
                    attempt_digest: wholepact_core::proposal::canonical_digest(
                        "wholepact:manual-roster-enrollment-initial-attempt:v2",
                        &selection.provenance.witness_roster_extension_digest,
                    )
                    .unwrap(),
                    attempt_sequence: 1,
                    admitted_at_ms: 1000,
                    admission_deadline_ms: 1500,
                },
                current,
                request,
            },
        };
        original.validate().unwrap();
        let original_id = original.digest().unwrap();
        selection.provenance.original_host_audit =
            OriginalHostRosterAuditV3::AdditionalPublicationV3 {
                audit_digest: original_id.clone(),
            };
        let mut previous = None;
        for sequence in [2u64, 3] {
            let mut evidence = original.evidence.clone();
            let attempt = if sequence == 2 {
                inventory.attempt.continuation_digest.clone()
            } else {
                digest(i, "construction-attempt")
            };
            evidence.request.attempt = ManualRosterPublicationAttemptV2::ContinuationV2 {
                continuation_digest: attempt.clone(),
                attempt_sequence: sequence,
            };
            evidence.admission.exact_request_digest = evidence.request.digest().unwrap();
            evidence.admission.attempt_sequence = sequence;
            evidence.admission.attempt_digest = attempt.clone();
            evidence.admission.admitted_at_ms = if sequence == 2 { 1501 } else { 2000 };
            evidence.admission.admission_deadline_ms = if sequence == 2 { 1990 } else { 2100 };
            evidence.current.writer_session_digest = digest(i, &format!("session-{sequence}"));
            evidence.current.witness_head_sequence = sequence;
            let continuation = ManualEnrollmentContinuationAuditV4 {
                version: 4,
                original_audit: OriginalManualEnrollmentAuditLink::AdditionalPublicationV3 {
                    audit_digest: original_id.clone(),
                },
                operation_id: format!("synthetic-construction-continuation-{i}-{sequence}"),
                request_identity_digest: digest(i, &format!("continuation-key-{sequence}")),
                provider_enrollment_ref: original.provider_enrollment_ref.clone(),
                store_sequence: sequence - 1,
                predecessor_digest: previous,
                aliases: original.aliases.clone(),
                evidence,
            };
            continuation.validate_for(&original).unwrap();
            previous = Some(continuation.digest().unwrap());
            continuations.push(continuation);
            if sequence == 3 {
                current_attempts.push(attempt);
            }
        }
        originals.push(original);
    }
    (originals, continuations, current_attempts)
}

/// Synthetic journal-only fixture. It fabricates no current native owner and
/// is unavailable in production. Root is an actual retained V2 layer fixture.
pub(crate) fn append_modeled_construction_rows(
    store: &Store,
    root: &ManualEnrollmentInitialPublicationV2,
    with_checkpoint: bool,
) -> (
    ManualRosterConstructionClaimV2,
    Option<ManualRosterConstructionCheckpointV2>,
) {
    let mut value = claim();
    let mut retained: Vec<_> = value
        .consumed
        .iter()
        .map(|a| a.request.plan.retained.clone())
        .collect();
    let (originals, continuations, current_attempts) =
        modeled_construction_roster_history(root, &mut retained, None);
    for ((audit, retained), attempt) in value
        .consumed
        .iter_mut()
        .zip(retained)
        .zip(current_attempts)
    {
        audit.request.plan.retained = retained;
        audit.current_attempt_digest = attempt;
    }
    let commitments: Vec<_> = value
        .consumed
        .iter()
        .map(|audit| {
            let p = &audit.request.plan;
            ManualRosterRetentionCommitmentV2 {
                participant_id: p.enrollment().scope.participant_id.clone(),
                account_id: p.enrollment().identity.account_id.clone(),
                full_viewing_key_digest: p.enrollment().identity.full_viewing_key_digest.clone(),
                retention_request_digest: p.retained.digest().unwrap(),
                retention_evidence_digest: p.retained_evidence_digest.clone(),
            }
        })
        .collect();
    for audit in &mut value.consumed {
        audit.request.plan.participants = commitments.clone();
    }
    value.validate().unwrap();
    let receipt = with_checkpoint.then(|| checkpoint(&value));
    // Preserve the actual original agreement revision too; no Engine or signer
    // owner is fabricated by writing this private synthetic journal fixture.
    let ctx = crate::CommandContext::for_request(
        &value.principal_id,
        "synthetic-claim-agreement",
        &serde_json::json!(["synthetic-claim-agreement"]),
    )
    .unwrap();
    store.create_agreement(&ctx,&value.proposal().manifest.agreement.agreement_id,serde_json::json!({"view":{"agreement":value.proposal().manifest.agreement,"candidates":[]}})).unwrap();
    let c = store.connection.lock().unwrap();
    let put = |kind: &str, id: String, payload: serde_json::Value| {
        c.execute(
            "INSERT INTO records VALUES(?1,?2,0,?3,1,1)",
            rusqlite::params![kind, id, serde_json::to_string(&payload).unwrap()],
        )
        .unwrap();
    };
    for a in originals {
        put(
            ADDITIONAL_PUBLICATION_V3,
            a.digest().unwrap(),
            serde_json::to_value(a).unwrap(),
        );
    }
    for a in continuations {
        put(
            CONTINUATION_V4,
            a.digest().unwrap(),
            serde_json::to_value(a).unwrap(),
        );
    }
    put(
        CONSTRUCTION_CLAIM_V2,
        value.digest().unwrap(),
        serde_json::to_value(&value).unwrap(),
    );
    if let Some(ref receipt) = receipt {
        put(
            CONSTRUCTION_CHECKPOINT_V2,
            receipt.claim_digest.clone(),
            serde_json::to_value(receipt).unwrap(),
        );
    }
    read_construction_rows(&c).unwrap();
    (value, receipt)
}

#[test]
fn encrypted_construction_claim_backup_restore_preserves_complete_history_and_uncertainty() {
    use wholepact_storage_security::DatabaseKey;
    for with_checkpoint in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let source_key = DatabaseKey::from_bytes([0x61; 32]);
        let archive_key = DatabaseKey::from_bytes([0x62; 32]);
        let destination_key = DatabaseKey::from_bytes([0x63; 32]);
        let source_path = directory.path().join("source.sqlite");
        let archive_path = directory.path().join("archive.sqlite");
        let restored_path = directory.path().join("restored.sqlite");
        let source = Store::create_encrypted(&source_path, &source_key).unwrap();
        // Honest historical fixture: no current native admission or token is
        // manufactured. These rows model a former exact construction invocation.
        let root = append_modeled_construction_root(&source);
        let (claim, receipt) = append_modeled_construction_rows(&source, &root, with_checkpoint);
        source
            .record_effect_intent(
                "synthetic-old-unknown",
                "send",
                "old-resource",
                &h('e'),
                "retained:old-unknown",
            )
            .unwrap();
        let old_effect = source
            .effect_intent("synthetic-old-unknown")
            .unwrap()
            .unwrap();
        let raw = |store: &Store| -> Vec<(String, String, u64, String, i64, i64)> {
            store.connection.lock().unwrap().prepare("SELECT aggregate_type,id,revision,payload,created_at_ms,updated_at_ms FROM records ORDER BY aggregate_type,id").unwrap().query_map([], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).unwrap().collect::<rusqlite::Result<_>>().unwrap()
        };
        let original_rows = raw(&source);
        assert_eq!(
            source
                .list_records(ADDITIONAL_PUBLICATION_V3)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(source.list_records(CONTINUATION_V4).unwrap().len(), 4);
        let summary = source
            .backup_agreement_journal(&archive_path, &archive_key)
            .unwrap();
        let archive_before = std::fs::read(&archive_path).unwrap();
        let (restored, report) = crate::backup::restore_agreement_journal(
            &archive_path,
            &archive_key,
            &restored_path,
            &destination_key,
        )
        .unwrap();
        assert!(report.recovery_required);
        assert!(!report.authorization_allowed);
        assert_eq!(report.backup.snapshot_digest, summary.snapshot_digest);
        assert_eq!(raw(&restored), original_rows);
        drop(restored);
        let reopened = Store::open_encrypted(&restored_path, &destination_key).unwrap();
        assert_eq!(raw(&reopened), original_rows);
        assert!(reopened.recovery_state().unwrap().recovery_required);
        assert!(reopened.manual_store_target().is_err());
        assert_eq!(
            reopened
                .effect_intent("synthetic-old-unknown")
                .unwrap()
                .unwrap(),
            old_effect
        );
        let evidence = reopened
            .manual_roster_construction_evidence_v2(&claim.principal_id, &claim.construction_key)
            .unwrap()
            .unwrap();
        assert!(evidence.0 == claim);
        assert!(evidence.1 == receipt);
        let ctx = crate::CommandContext::for_request(
            &claim.principal_id,
            &claim.construction_key,
            &serde_json::json!({}),
        )
        .unwrap();
        assert!(reopened.find_replay(&ctx).is_err());
        assert!(
            reopened
                .require_ordinary_financial_lineage(
                    &claim.proposal().manifest.agreement.agreement_id,
                    &claim.proposal().manifest.agreement.obligation_id,
                    &claim.principal_id,
                    Some(&claim.construction_key),
                    &[]
                )
                .is_err()
        );
        assert_eq!(std::fs::read(&archive_path).unwrap(), archive_before);
        assert_eq!(raw(&source), original_rows);
        assert!(!source.recovery_state().unwrap().recovery_required);
    }
}

pub(crate) fn append_modeled_construction_root(
    store: &Store,
) -> ManualEnrollmentInitialPublicationV2 {
    let mut root = crate::manual_enrollment::tests::initial_publication::initial_fixture();
    root.evidence.request.enrollment.terms.identity.account_id = h('3');
    root.evidence
        .request
        .enrollment
        .terms
        .identity
        .full_viewing_key_digest = h('4');
    root.aliases = BTreeSet::from([h('3')]);
    root.evidence.admission.exact_request_digest = root.evidence.request.digest().unwrap();
    root.validate().unwrap();
    store
        .connection
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO records VALUES(?1,?2,0,?3,1,1)",
            rusqlite::params![
                INITIAL_PUBLICATION_V2,
                root.digest().unwrap(),
                serde_json::to_string(&root).unwrap()
            ],
        )
        .unwrap();
    root
}

#[test]
fn orphan_roster_root_or_predecessor_fails_every_claim_read() {
    for missing in [INITIAL_PUBLICATION_V2, ADDITIONAL_PUBLICATION_V3] {
        let store = Store::in_memory().unwrap();
        let root = append_modeled_construction_root(&store);
        let (claim, _) = append_modeled_construction_rows(&store, &root, true);
        let id = if missing == INITIAL_PUBLICATION_V2 {
            root.digest().unwrap()
        } else {
            claim.consumed[0]
                .request
                .plan
                .retained
                .selection
                .scope
                .provenance
                .original_host_audit
                .audit_digest()
                .into()
        };
        store
            .connection
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM records WHERE aggregate_type=?1 AND id=?2",
                rusqlite::params![missing, id],
            )
            .unwrap();
        assert!(
            store
                .manual_roster_construction_evidence_v2(
                    &claim.principal_id,
                    &claim.construction_key
                )
                .is_err()
        );
        assert!(store.list_records(CONSTRUCTION_CLAIM_V2).is_err());
        assert!(
            store
                .get_record(CONSTRUCTION_CLAIM_V2, &claim.digest().unwrap())
                .is_err()
        );
    }
}

#[test]
fn absent_exact_retained_selection_or_unknown_manual_row_fails_read() {
    for unknown in [false, true] {
        let store = Store::in_memory().unwrap();
        let root = append_modeled_construction_root(&store);
        let (claim, _) = append_modeled_construction_rows(&store, &root, false);
        let c = store.connection.lock().unwrap();
        if unknown {
            c.execute("INSERT INTO records VALUES('generation_manual_unrecognized_v99','unknown',0,'{}',1,1)", []).unwrap();
        } else {
            let additions = read_audits::<ManualEnrollmentAdditionalPublicationV3>(
                &c,
                ADDITIONAL_PUBLICATION_V3,
            )
            .unwrap();
            let continuations =
                read_audits::<ManualEnrollmentContinuationAuditV4>(&c, CONTINUATION_V4).unwrap();
            for (id, audit) in &continuations {
                if audit.evidence.admission.attempt_sequence == 2 {
                    c.execute(
                        "DELETE FROM records WHERE aggregate_type=?1 AND id=?2",
                        rusqlite::params![CONTINUATION_V4, id],
                    )
                    .unwrap();
                }
            }
            let current_only: Vec<_> = continuations
                .into_iter()
                .filter(|(_, a)| a.evidence.admission.attempt_sequence == 3)
                .collect();
            assert!(
                validate_construction_roster_history(
                    &[(claim.digest().unwrap(), claim.clone())],
                    &additions,
                    &current_only
                )
                .is_err()
            );
            // The full read also rejects the missing persisted selection predecessor.
        }
        drop(c);
        assert!(
            store
                .manual_roster_construction_evidence_v2(
                    &claim.principal_id,
                    &claim.construction_key
                )
                .is_err()
        );
    }
}

#[test]
fn current_manual_audit_operation_collision_remains_occupied_before_claim_insert() {
    let store = Store::in_memory().unwrap();
    let root = append_modeled_construction_root(&store);
    let mut prospective = claim();
    // An inert valid contribution request cannot repurpose a current manual
    // publication's operation identity. No native owner or token is fabricated.
    prospective.consumed[0].request.operation_id = root.operation_id.clone();
    prospective.validate().unwrap();
    let c = store.connection.lock().unwrap();
    assert!(
        require_generic_operation_not_manual(&c, &prospective.consumed[0].request.operation_id)
            .is_err()
    );
    assert!(require_generic_operation_not_manual(&c, &root.terms().operation_id).is_err());
    require_generic_operation_not_manual(&c, prospective.invocation().operation_id.as_str())
        .unwrap();
    assert!(read_construction_rows(&c).unwrap().0.is_empty());
}

#[cfg(target_os = "linux")]
#[path = "construction_inspection_preservation_tests.rs"]
mod inspection_preservation;
