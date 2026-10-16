//! Test-only inert historical rows derived from Store construction_claim_v2_tests.
//! They exercise encrypted readers, not native approval, witness calls, tokens,
//! randomized construction, wallet access or financial authority.
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
use wholepact_store::manual_enrollment::*;
use wholepact_store::request_digest;
fn a(v: u64) -> Amount {
    Amount::from_zatoshis(v).unwrap()
}
fn h(c: char) -> String {
    c.to_string().repeat(64)
}
pub(super) fn economics() -> ManualCandidateEconomicIntent {
    ManualCandidateEconomicIntent {
        version: 1,
        candidate_id: "synthetic-candidate".into(),
        candidate_revision: 1,
        proposal_id: "synthetic-proposal".into(),
        previous_proposal_id: None,
        created_at: "2026-10-13T14:00:00Z".into(),
        agreement: wholepact_core::parse_typed_json(include_bytes!(
            "../../../../../wholepact-core/tests/fixtures/agreement.json"
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
fn claim() -> ManualRosterConstructionClaimV2 {
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
pub(super) fn checkpoint(
    c: &ManualRosterConstructionClaimV2,
) -> ManualRosterConstructionCheckpointV2 {
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
        job_id: wholepact_proof_jobs::job_id_for_key(&c.principal_id, &c.construction_key).unwrap(),
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

const INITIAL_PUBLICATION_V2: &str = "generation_manual_enrollment_initial_publication_v2";
const ADDITIONAL_PUBLICATION_V3: &str = "generation_manual_enrollment_additional_publication_v3";
const CONTINUATION_V4: &str = "generation_manual_enrollment_continuation_v4";
const CONSTRUCTION_CLAIM_V2: &str = "generation_manual_construction_claim_v2";
const CONSTRUCTION_CHECKPOINT_V2: &str = "generation_manual_construction_checkpoint_v2";
fn synthetic_terms() -> BornManualEnrollmentTerms {
    let identity = ManualAccountIdentity {
        account_id: h('3'),
        full_viewing_key_digest: h('4'),
        network_profile_id: "synthetic-test-network".into(),
        derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
    };
    BornManualEnrollmentTerms {
        version: 1,
        operation_id: "enroll-new".into(),
        identity,
        birth_request_digest: h('3'),
        birth_commit_digest: h('4'),
        native_birth_digest: h('5'),
        original_policy_digest: h('6'),
        account_use_genesis_digest: h('7'),
        original_witness_origin_digest: h('8'),
        host: ManualHostGenerationBinding {
            generation_id: h('a'),
            inventory_digest: h('b'),
            generation_plan_digest: h('c'),
            financial_journal_origin_digest: h('d'),
            store_destination_identity: h('c'),
            profile_id: "profile".into(),
            canonical_root: "/synthetic/profile".into(),
            destination_identity_digest: h('e'),
            inherited_identity_digest: h('f'),
            scope_predecessor_digest: None,
        },
        signer: BornManualSignerBinding {
            enrollment_generation_id: h('a'),
            signer_target_digest: h('b'),
            original_envelope_digest: h('c'),
            owner_certificate_digest: h('d'),
            writer_certificate_digest: h('e'),
            writer_epoch: 1,
            native_signer_measurement: h('f'),
        },
        scope: BornManualScope {
            agreement_id: "fresh-agreement".into(),
            obligation_id: "fresh-obligation".into(),
            participant_id: "participant".into(),
            principal_id: "owner".into(),
            privacy_domain: "one-agreement".into(),
            recipient_scope_digests: vec![h('1')],
            aggregate_budget_zatoshis: 100,
            per_operation_limit_zatoshis: 100,
            maximum_fee_share_zatoshis: 5,
            maximum_transaction_fee_zatoshis: 5,
            maximum_permit_lifetime_ms: 1000,
            expires_at_ms: 10000,
        },
        transport_binding_digest: h('2'),
        issued_at_ms: 1,
    }
}

fn initial_fixture(host: &ManualHostGenerationBinding) -> ManualEnrollmentInitialPublicationV2 {
    let mut terms = synthetic_terms();
    terms.host = host.clone();
    let request = ManualContinuationRequestV2 {
        version: 2,
        enrollment: ManualContinuationEnrollment {
            terms: terms.clone(),
        },
        continuation_digest: h('9'),
    };
    ManualEnrollmentInitialPublicationV2 {
        version: 2,
        operation_id: "synthetic-initial-v2".into(),
        request_identity_digest: h('b'),
        provider_enrollment_ref: h('a'),
        store_sequence: 1,
        aliases: BTreeSet::from([terms.identity.account_id.clone()]),
        evidence: ManualContinuationEvidenceV2 {
            version: 2,
            enrollment_ref: h('3'),
            witness_extension_digest: h('4'),
            witness_extension_sequence: 1,
            witness_extension_predecessor_digest: None,
            admission: ManualContinuationAdmissionV2 {
                version: 2,
                exact_request_digest: request.digest().unwrap(),
                signer_intent_digest: h('d'),
                witness_admission_digest: h('d'),
                attempt_digest: h('9'),
                attempt_sequence: 2,
                admitted_at_ms: 1001,
                admission_deadline_ms: 2000,
            },
            current: ManualContinuationCurrentAudit {
                writer_certificate_digest: terms.signer.writer_certificate_digest,
                writer_epoch: terms.signer.writer_epoch,
                writer_session_digest: h('e'),
                writer_session_expires_at_ms: 9000,
                witness_head_sequence: 9,
                witness_head_digest: h('f'),
                complete_history_digest: h('a'),
                exclusion_checkpoint_digest: h('b'),
                native_review_digest: h('c'),
            },
            request,
        },
    }
}
pub(super) fn historical_rows(
    host: &ManualHostGenerationBinding,
    with_checkpoint: bool,
) -> (
    ManualRosterConstructionClaimV2,
    Option<ManualRosterConstructionCheckpointV2>,
    Vec<(String, String, String)>,
) {
    let root = initial_fixture(host);
    let mut value = claim();
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
    for (i, audit) in value.consumed.iter_mut().enumerate() {
        let retained = &mut audit.request.plan.retained;
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
            predecessor: if i == 0 {
                wholepact_core::manual_roster_v2::HostRosterPredecessorV2::InitialPublicationV2 {
                    audit_digest: root.digest().unwrap(),
                }
            } else {
                wholepact_core::manual_roster_v2::HostRosterPredecessorV2::AdditionalPublicationV3 {
                    audit_digest: originals
                        .last()
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
                audit.current_attempt_digest = attempt;
            }
        }
        originals.push(original);
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
    let mut rows = Vec::new();
    let mut put = |kind: &str, id: String, payload: serde_json::Value| {
        rows.push((kind.into(), id, serde_json::to_string(&payload).unwrap()));
    };
    put(
        INITIAL_PUBLICATION_V2,
        root.digest().unwrap(),
        serde_json::to_value(&root).unwrap(),
    );
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
    (value, receipt, rows)
}
