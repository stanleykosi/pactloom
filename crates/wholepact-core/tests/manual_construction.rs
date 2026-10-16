use wholepact_core::manual_construction::*;
use wholepact_core::manual_enrollment::*;
use wholepact_core::*;
fn h(c: char) -> String {
    c.to_string().repeat(64)
}
fn a(n: u64) -> Amount {
    Amount::from_zatoshis(n).unwrap()
}
fn agreement() -> AgreementDraft {
    parse_typed_json(include_bytes!("fixtures/agreement.json")).unwrap()
}
fn proposal() -> ProposalInput {
    ProposalInput {
        proposal_id: "proposal-example-01".into(),
        previous_proposal_id: None,
        artifact_digest: None,
        effects_commitment: None,
        created_at: "2026-10-13T14:00:00Z".into(),
        manifest: ProposalManifest {
            agreement: agreement(),
            participants: vec![
                ParticipantAllocation {
                    participant_id: "alice".into(),
                    account_id: h('a'),
                    contribution: a(400_000_000),
                    fee_share: a(12_000),
                    fee_cap: a(12_000),
                    maximum_net_debit: a(400_012_000),
                    charges: vec![],
                },
                ParticipantAllocation {
                    participant_id: "bob".into(),
                    account_id: h('b'),
                    contribution: a(600_000_000),
                    fee_share: a(18_000),
                    fee_cap: a(18_000),
                    maximum_net_debit: a(600_018_000),
                    charges: vec![],
                },
            ],
            inputs: vec![
                ClaimedInput {
                    input_id: "input-alice".into(),
                    participant_id: "alice".into(),
                    account_id: h('a'),
                    amount: a(500_000_000),
                    ownership_evidence_ref: None,
                },
                ClaimedInput {
                    input_id: "input-bob".into(),
                    participant_id: "bob".into(),
                    account_id: h('b'),
                    amount: a(700_000_000),
                    ownership_evidence_ref: None,
                },
            ],
            outputs: vec![
                ClaimedOutput {
                    output_id: "recipient-output".into(),
                    address: agreement().recipients[0].address.clone(),
                    amount: a(1_000_000_000),
                    allocation: OutputAllocation::Recipient {
                        recipient_id: "recipient-example".into(),
                    },
                },
                ClaimedOutput {
                    output_id: "alice-return".into(),
                    address: "usyntheticreturnalice".into(),
                    amount: a(99_988_000),
                    allocation: OutputAllocation::Return {
                        participant_id: "alice".into(),
                        account_id: h('a'),
                        ownership_evidence_ref: None,
                    },
                },
                ClaimedOutput {
                    output_id: "bob-return".into(),
                    address: "usyntheticreturnbob".into(),
                    amount: a(99_982_000),
                    allocation: OutputAllocation::Return {
                        participant_id: "bob".into(),
                        account_id: h('b'),
                        ownership_evidence_ref: None,
                    },
                },
            ],
            transaction_fee: a(30_000),
            expiry_height: 3_000_000,
        },
    }
}

fn terms() -> BornManualEnrollmentTerms {
    BornManualEnrollmentTerms {
        version: 1,
        operation_id: "synthetic-enrollment".into(),
        identity: ManualAccountIdentity {
            account_id: h('a'),
            full_viewing_key_digest: h('b'),
            network_profile_id: "synthetic-testnet".into(),
            derivation_domain: "dedicated-synthetic".into(),
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

fn request() -> ManualConstructionRequest {
    let proposal = proposal();
    let validated = Proposal::validate(proposal.clone()).unwrap();
    let mut e = terms();
    e.identity.account_id = h('a');
    e.identity.network_profile_id = proposal.manifest.agreement.network_profile_id.clone();
    e.scope.agreement_id = proposal.manifest.agreement.agreement_id.clone();
    e.scope.obligation_id = proposal.manifest.agreement.obligation_id.clone();
    e.scope.participant_id = "alice".into();
    e.scope.recipient_scope_digests = vec![construction_payment_scope_digest(&proposal).unwrap()];
    e.scope.aggregate_budget_zatoshis = 1_000_000_000;
    e.scope.per_operation_limit_zatoshis = 400_012_000;
    e.scope.maximum_fee_share_zatoshis = 12_000;
    e.scope.maximum_transaction_fee_zatoshis = 30_000;
    e.issued_at_ms = 1000;
    e.scope.maximum_permit_lifetime_ms = 120_000;
    e.scope.expires_at_ms = 300_000;
    let invocation = ManualConstructionInvocation {
        version: 1,
        operation_id: "common-operation".into(),
        idempotency_key_digest: h('1'),
        invocation_nonce: h('2'),
        candidate_id: "candidate".into(),
        candidate_revision: 1,
        proposal_id: proposal.proposal_id.clone(),
        manifest_digest: validated.manifest_digest().into(),
        participants: vec![
            ManualConstructionParticipant {
                participant_id: "alice".into(),
                account_id: h('a'),
            },
            ManualConstructionParticipant {
                participant_id: "bob".into(),
                account_id: h('b'),
            },
        ],
        checkpoint_destination: "/synthetic/operator/proof.sqlite".into(),
        requested_at_ms: 2000,
        construction_expires_at_ms: 100_000,
    };
    let scope = PreconstructionScope {
        schema_version: 1,
        proposal,
        account_id: h('a'),
        participant_id: "alice".into(),
        profile_id: e.host.profile_id.clone(),
        principal_id: e.scope.principal_id.clone(),
        operator_name: "synthetic-operator".into(),
        operator_destination: "/synthetic/operator/proof.sqlite".into(),
        wallet_destination: "/synthetic/wallet/wallet.sqlite".into(),
        reviewer_account_ids: vec![h('a'), h('b')],
        privacy_domain: e.scope.privacy_domain.clone(),
        purpose: "construct_exact_accepted_candidate".into(),
        retention_policy: "synthetic bounded retention".into(),
        provider: PreconstructionProvider {
            source_id: "synthetic-source".into(),
            endpoint: "https://synthetic.invalid".into(),
            trust_profile: "single_tls_provider_report_not_consensus".into(),
        },
        minimum_confirmations: 10,
        maximum_blocks: 100,
        anchor_height: 200,
        maximum_net_debit_zatoshis: 400_012_000,
        birthday: PreconstructionBirthday {
            prior_height: 100,
            prior_block_hash: h('3'),
            sapling_tree: String::new(),
            orchard_tree: String::new(),
            ironwood_tree: String::new(),
        },
    };
    let attachment = ManualConstructionAttachmentBinding {
        version: 1,
        original_primary_journal_origin_digest: e.host.financial_journal_origin_digest.clone(),
        predecessor_registry_digest: h('4'),
        current_registry_digest: h('5'),
        latest_extension_digest: h('6'),
        selected: ManualParticipantAttachment {
            account_id: h('a'),
            canonical_directory: "/synthetic/wallet".into(),
            directory_identity_digest: h('7'),
            journal_origin_digest: h('8'),
        },
    };
    let preselection = ManualPreselectionRequest {
        version: 1,
        enrollment: e,
        enrollment_ref: h('9'),
        witness_extension_digest: h('a'),
        attempt: ManualConstructionAttempt {
            version: 2,
            continuation_digest: h('b'),
            attempt_sequence: 2,
        },
        operation_id: "alice-selection".into(),
        candidate_id: invocation.candidate_id.clone(),
        candidate_revision: 1,
        current_caller_binding_digest: h('c'),
        scope,
        attachment,
        invocation_nonce: invocation.invocation_nonce.clone(),
        invocation,
    };
    let plan = ManualConstructionPlan {
        version: 1,
        preselection,
        preselection_record_digest: h('d'),
        operation_id: "alice-contribution".into(),
        idempotency_key_digest: h('e'),
        invocation_nonce: h('2'),
        selected_inputs: vec![ManualConstructionInput {
            input_id: "input-alice".into(),
            nullifier: h('f'),
            value_zatoshis: 500_000_000,
        }],
        selection_context: ManualSelectionContext {
            tip_height: 210,
            tip_hash_protocol: h('1'),
            anchor_height: 200,
            anchor_hash_protocol: h('2'),
            anchor_root: h('3'),
        },
        local_exclusion_digest: h('4'),
        requested_at_ms: 2000,
        construction_expires_at_ms: 100_000,
    };
    let intent = BornManualActionIntent {
        version: 1,
        enrollment_ref: plan.preselection.enrollment_ref.clone(),
        candidate_id: plan.preselection.candidate_id.clone(),
        proposal_id: validated.input().proposal_id.clone(),
        manifest_digest: validated.manifest_digest().into(),
        obligation_id: plan.preselection.enrollment.scope.obligation_id.clone(),
        operation_id: plan.operation_id.clone(),
        idempotency_key_digest: plan.idempotency_key_digest.clone(),
        input_set_digest: plan.input_set_digest().unwrap(),
        exact_request_digest: plan.digest().unwrap(),
        action: BornManualAction::Construct,
        invocation_nonce: plan.invocation_nonce.clone(),
    };
    ManualConstructionRequest {
        version: 1,
        plan,
        intent,
    }
}
#[test]
fn complete_synthetic_claims_validate_but_are_only_data() {
    let r = request();
    assert!(r.validate().is_ok());
    let bytes = serde_json::to_vec(&r).unwrap();
    assert!(bytes.len() < 128 * 1024);
    let decoded: ManualConstructionRequest = serde_json::from_slice(&bytes).unwrap();
    assert!(decoded == r);
}
#[test]
fn payment_scope_has_explicit_domain_and_every_output_and_charge() {
    let input = proposal();
    let p = Proposal::validate(input.clone()).unwrap();
    let d = construction_payment_scope_digest(&input).unwrap();
    assert_eq!(d, construction_recipient_scope_digest(&p).unwrap());
    let mut change = input.clone();
    change.manifest.outputs[1].address.push('x');
    assert_ne!(d, construction_payment_scope_digest(&change).unwrap());
    let mut invalid = input;
    invalid.manifest.outputs[0].amount = Amount::from_zatoshis(1).unwrap();
    assert!(construction_payment_scope_digest(&invalid).is_err());
}
#[test]
fn unchanged_scope_without_payment_domain_rejects() {
    let mut r = request();
    r.plan.preselection.enrollment.scope.recipient_scope_digests = vec![h('e')];
    assert!(r.plan.validate().is_err());
}
#[test]
fn selection_requires_actual_exact_input_claims_and_unique_nullifiers() {
    let r = request();
    let mut x = r.plan.clone();
    x.selected_inputs[0].value_zatoshis -= 1;
    assert!(x.validate().is_err());
    let mut x = r.plan.clone();
    x.selected_inputs[0].input_id = "input-bob".into();
    assert!(x.validate().is_err());
    let mut x = r.plan.clone();
    x.selected_inputs.push(x.selected_inputs[0].clone());
    assert!(x.validate().is_err());
    let mut x = r.plan.clone();
    x.selection_context.anchor_height += 1;
    assert!(x.validate().is_err());
    let mut x = r.plan;
    x.selected_inputs[0].nullifier = "F".repeat(64);
    assert!(x.validate().is_err());
}
#[test]
fn common_invocation_prevents_roster_destination_and_revision_splicing() {
    let r = request();
    let mut x = r.plan.clone();
    x.preselection.invocation.participants.reverse();
    assert!(x.validate().is_err());
    let mut x = r.plan.clone();
    x.preselection.invocation.participants[0].account_id = h('b');
    assert!(x.validate().is_err());
    let mut x = r.plan.clone();
    x.preselection.candidate_revision += 1;
    assert!(x.validate().is_err());
    let mut x = r.plan.clone();
    x.preselection.invocation.checkpoint_destination.push('x');
    assert_ne!(
        x.preselection.invocation.digest().unwrap(),
        r.plan.preselection.invocation.digest().unwrap()
    );
    let mut x = r.plan;
    x.preselection.invocation.checkpoint_destination = "/a/../b".into();
    assert!(x.validate().is_err());
}
#[test]
fn fixed_original_times_cannot_renew_and_action_purpose_cannot_expand() {
    let r = request();
    let mut x = r.clone();
    x.plan.construction_expires_at_ms += 1;
    assert!(x.validate().is_err());
    let mut x = r.clone();
    x.plan.preselection.invocation.construction_expires_at_ms = 122001;
    assert!(x.validate().is_err());
    let mut x = r.clone();
    x.intent.action = BornManualAction::Authorize;
    assert!(x.validate().is_err());
    let mut x = r;
    x.intent.exact_request_digest = h('f');
    assert!(x.validate().is_err());
}
#[test]
fn original_attachment_limits_and_caller_attempt_are_exact() {
    let r = request();
    let mut x = r.plan.clone();
    x.preselection
        .attachment
        .selected
        .canonical_directory
        .push('x');
    assert!(x.validate().is_err());
    let mut x = r.plan.clone();
    x.preselection.enrollment.scope.maximum_fee_share_zatoshis -= 1;
    assert!(x.validate().is_err());
    let mut x = r.plan.clone();
    x.preselection.attempt.version = 1;
    assert!(x.validate().is_err());
    let mut x = r.plan.clone();
    x.preselection.current_caller_binding_digest = h('d');
    assert_ne!(
        x.preselection.digest().unwrap(),
        r.plan.preselection.digest().unwrap()
    );
    let mut x = r.plan;
    x.preselection
        .attachment
        .original_primary_journal_origin_digest = h('f');
    assert!(x.validate().is_err());
}
#[test]
fn wire_rejects_old_markers_unknown_authority_flags_and_action_indices() {
    let r = request();
    let mut value = serde_json::to_value(&r).unwrap();
    value["approved"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ManualConstructionRequest>(value).is_err());
    let mut value = serde_json::to_value(&r.plan.selected_inputs[0]).unwrap();
    value["action_index"] = serde_json::json!(0);
    assert!(serde_json::from_value::<ManualConstructionInput>(value).is_err());
}
#[test]
fn exact_wallet_and_checkpoint_file_destinations_cannot_be_replaced_by_directories() {
    let r = request();
    for destination in [
        "/synthetic/wallet",
        "/synthetic/wallet/other.sqlite",
        "/synthetic/wallet/./wallet.sqlite",
        "/synthetic/wallet//wallet.sqlite",
        "/synthetic/wallet/../wallet/wallet.sqlite",
    ] {
        let mut changed = r.plan.preselection.clone();
        changed.scope.wallet_destination = destination.into();
        assert!(changed.validate().is_err());
    }
    let mut changed = r.plan.preselection.clone();
    changed.invocation.checkpoint_destination = "/synthetic/operator/other.sqlite".into();
    assert!(changed.validate().is_err());
    let mut changed = r.plan.preselection;
    changed.attachment.selected.canonical_directory = "/synthetic/wallet/..".into();
    assert!(changed.validate().is_err());
}
