//! Never-funded synthetic pure history. These tests do not construct native
//! decisions or authenticated transport/Host capabilities.
use super::*;
use crate::manual_enrollment::original_birth_commit_digest;
use crate::manual_roster_witness_v2::tests::{
    bootstrap, continuation, continuation_event, extension_event,
};
use crate::policy::{Event, Ledger};
use wholepact_core::{
    AgreementDraft, Amount, ClaimedInput, ClaimedOutput, OutputAllocation, ParticipantAllocation,
    ProposalInput, ProposalManifest,
};
use wholepact_core::{
    born_policy_origin_v2::*, born_recipient_policy_v2::*, manual_candidate_selection::*,
    manual_construction::*, manual_inventory::ManualPreliminaryInventoryScope,
    manual_roster_candidate_selection_v2::*, manual_roster_construction_v2::*,
    manual_roster_inventory_v2::*, manual_roster_v2::*,
};
fn h(c: char) -> String {
    c.to_string().repeat(64)
}
fn a(n: u64) -> Amount {
    Amount::from_zatoshis(n).unwrap()
}
fn agreement() -> AgreementDraft {
    serde_json::from_str(r###"{
  "schema_version": 1,
  "agreement_id": "agreement-example-01",
  "obligation_id": "obligation-example-01",
  "revision": 1,
  "purpose": "Synthetic cooperative procurement example. No real funds.",
  "organizer_identity": "organizer-example",
  "network_profile_id": "zcash-testnet-unqualified",
  "recipients": [
    {
      "recipient_id": "recipient-example",
      "address": "uregtestsyntheticaddressnotforfunds",
      "amount": "1000000000",
      "memo": null,
      "instruction_provenance": "Synthetic fixture. Not address- or ownership-verified."
    }
  ],
  "funding_policy": {"kind": "exact", "target": "1000000000"},
  "fee_policy": {"kind": "pro_rata"},
  "privacy_profile": {"mode": "local_only", "proving_operator": null, "dedicated_accounts_required": true},
  "coordination_deadline": null,
  "confirmation_policy": {"required_confirmations": 10},
  "extensions": []
}
"###).unwrap()
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

pub(crate) fn construction_fixture() -> (
    crate::pending_birth::PendingBirthCommitRecord,
    ManualRosterEnrollmentExtensionV2,
    Vec<Event>,
    Ledger,
) {
    construction_fixture_with_owner(None)
}
/// Synthetic source fixture helper. `Some` selects the separately supported V3
/// profile and a never-funded test-only certificate; original V2 defaults stay exact.
pub(crate) fn construction_fixture_with_owner(
    owner: Option<&str>,
) -> (
    crate::pending_birth::PendingBirthCommitRecord,
    ManualRosterEnrollmentExtensionV2,
    Vec<Event>,
    Ledger,
) {
    let mut input = proposal();
    let anchor = if owner.is_some() {
        input.manifest.agreement.network_profile_id =
            wholepact_core::manual_roster_construction_v3::COMMON_CONTEXT_PROFILE_ID.into();
        input.manifest.agreement.privacy_profile.mode =
            wholepact_core::PrivacyMode::DeclaredOperator;
        input.manifest.agreement.privacy_profile.proving_operator =
            Some("synthetic-operator".into());
        input.manifest.expiry_height =
            wholepact_core::manual_roster_construction_v3::COMMON_CONTEXT_NU7_ACTIVATION_HEIGHT
                + 100;
        wholepact_core::manual_roster_construction_v3::COMMON_CONTEXT_NU7_ACTIVATION_HEIGHT + 10
    } else {
        200
    };
    let manifest = &input.manifest;
    let (mut birth, mut inner) = crate::manual_enrollment::tests::fixture();
    let descriptor = BornConstructionRecipientPolicyV2 {
        version: 2,
        account_id: h('a'),
        network_profile_id: manifest.agreement.network_profile_id.clone(),
        agreement_id: manifest.agreement.agreement_id.clone(),
        obligation_id: manifest.agreement.obligation_id.clone(),
        participant_id: "alice".into(),
        recipients: manifest
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
        own_return_rule: BornOwnReturnRuleV2::AuthenticatedSameAccount,
        original_limits: BornOriginalLimitsV2 {
            aggregate_budget_zatoshis: 1_000_000_000,
            per_operation_limit_zatoshis: 400_012_000,
            maximum_fee_share_zatoshis: 12_000,
            maximum_transaction_fee_zatoshis: 30_000,
            maximum_permit_lifetime_ms: 120_000,
            policy_expires_at_ms: 6_000_000,
        },
    };
    if let Some(owner) = owner {
        birth.request.policy.owner_certificate_digest = owner.into();
        birth
            .request
            .policy
            .account_use_genesis
            .as_mut()
            .unwrap()
            .owner_certificate_digest = owner.into();
        birth.authenticated_owner_certificate_digest = owner.into();
        inner.terms.signer.owner_certificate_digest = owner.into();
    }
    let p = &mut birth.request.policy;
    p.account_id = h('a');
    p.network_profile_id = descriptor.network_profile_id.clone();
    p.aggregate_budget_zatoshis = 1_000_000_000;
    p.per_operation_limit_zatoshis = 400_012_000;
    p.maximum_fee_share_zatoshis = 12_000;
    p.maximum_transaction_fee_zatoshis = 30_000;
    p.maximum_permit_lifetime_ms = 120_000;
    p.policy_expires_at_ms = 6_000_000;
    p.agreement_ids = vec![descriptor.agreement_id.clone()];
    p.recipient_scope_digests = vec![descriptor.digest().unwrap()];
    let mut terms = serde_json::to_value(&*p).unwrap();
    terms.as_object_mut().unwrap().remove("account_use_genesis");
    let terms: BornPolicyOriginalTermsV2 = serde_json::from_value(terms).unwrap();
    let g = p.account_use_genesis.as_mut().unwrap();
    g.identity.account_id = h('a');
    g.identity.network_profile_id = p.network_profile_id.clone();
    birth.request.disclosure.account_id = h('a');
    birth.request.disclosure.network_profile_id = p.network_profile_id.clone();
    let intent = BornRecipientPolicyBirthIntentV2 {
        version: 2,
        operation_id: format!("birth-{}", "a".repeat(32)),
        generation_instance_id: birth.request.generation_instance_id.clone(),
        identity: BornPolicyIdentityV2 {
            account_id: h('a'),
            full_viewing_key_digest: g.identity.full_viewing_key_digest.clone(),
            network_profile_id: p.network_profile_id.clone(),
            derivation_domain: g.identity.derivation_domain.clone(),
            exact_derivation: "synthetic-derivation".into(),
        },
        witness_origin: BornPolicyWitnessOriginV2 {
            endpoint: birth.request.disclosure.endpoint.clone(),
            server_name: birth.request.disclosure.server_name.clone(),
            witness_id: birth.request.disclosure.witness_id.clone(),
            pinned_server_certificate_digest: birth
                .request
                .disclosure
                .pinned_server_certificate_digest
                .clone(),
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
            &(&intent, &descriptor),
        )
        .unwrap(),
        intent,
        recipient_policy: descriptor.clone(),
    };
    origin.validate().unwrap();
    g.native_birth_digest = origin.birth_digest.clone();
    birth.request.native_birth_digest = origin.birth_digest.clone();
    birth.request.original_terms_digest = origin.intent.original_policy_terms_digest.clone();
    birth.request.disclosure.policy_digest = p.policy_digest().unwrap();
    birth.request_digest = birth.request.digest().unwrap();
    inner.terms.identity.account_id = h('a');
    inner.terms.identity.network_profile_id = descriptor.network_profile_id.clone();
    inner.terms.native_birth_digest = origin.birth_digest.clone();
    inner.terms.birth_request_digest = birth.request_digest.clone();
    inner.terms.birth_commit_digest = original_birth_commit_digest(&birth).unwrap();
    inner.terms.original_policy_digest = birth.request.policy.policy_digest().unwrap();
    inner.terms.account_use_genesis_digest = birth
        .request
        .policy
        .account_use_genesis
        .as_ref()
        .unwrap()
        .digest()
        .unwrap();
    inner.terms.scope.agreement_id = descriptor.agreement_id.clone();
    inner.terms.scope.obligation_id = descriptor.obligation_id.clone();
    inner.terms.scope.participant_id = "alice".into();
    inner.terms.scope.aggregate_budget_zatoshis = 1_000_000_000;
    inner.terms.scope.per_operation_limit_zatoshis = 400_012_000;
    inner.terms.scope.maximum_fee_share_zatoshis = 12_000;
    inner.terms.scope.maximum_transaction_fee_zatoshis = 30_000;
    inner.terms.scope.maximum_permit_lifetime_ms = 120_000;
    inner.terms.scope.expires_at_ms = 5_000_000;
    inner.terms.scope.recipient_scope_digests = vec![descriptor.digest().unwrap()];
    inner.validate_original_birth(&birth).unwrap();
    let e = ManualRosterEnrollmentExtensionV2 {
        version: 2,
        roster: HostRosterAppendBindingV2 {
            version: 2,
            generation_id: inner.terms.host.generation_id.clone(),
            store_destination_identity: inner.terms.host.store_destination_identity.clone(),
            roster_sequence: 2,
            predecessor: HostRosterPredecessorV2::InitialPublicationV2 {
                audit_digest: h('d'),
            },
        },
        signer_roster_record_digest: h('e'),
        account_extension: inner,
    };
    let mut l = Ledger::new(birth.request.policy.clone()).unwrap();
    let mut events = vec![extension_event(&l, &e)];
    l.apply(&events[0]).unwrap();
    bootstrap(
        &birth,
        &e,
        &mut l,
        &mut events,
        5000,
        crate::session::session_id(&[0x33; 32]),
    );
    let c = continuation(&l, &e, 128_000, '8');
    let event = continuation_event(&l, &e, c.clone(), 128_000);
    l.apply(&event).unwrap();
    events.push(event);
    bootstrap(
        &birth,
        &e,
        &mut l,
        &mut events,
        129_000,
        crate::session::session_id(&[0x44; 32]),
    );
    let inventory = ManualPreliminaryInventoryScope {
        version: 1,
        enrollment: e.account_extension.terms.clone(),
        enrollment_ref: e.account_extension.enrollment_ref.clone(),
        witness_extension_digest: e.account_extension.digest().unwrap(),
        attempt: ManualConstructionAttempt {
            version: 2,
            continuation_digest: c.digest_for(&e).unwrap(),
            attempt_sequence: 2,
        },
        original_recipient_policy: descriptor,
        attachment: ManualConstructionAttachmentBinding {
            version: 1,
            original_primary_journal_origin_digest: e
                .account_extension
                .terms
                .host
                .financial_journal_origin_digest
                .clone(),
            predecessor_registry_digest: h('4'),
            current_registry_digest: h('5'),
            latest_extension_digest: h('6'),
            selected: ManualParticipantAttachment {
                account_id: h('a'),
                canonical_directory: "/synthetic/wallet".into(),
                directory_identity_digest: h('7'),
                journal_origin_digest: h('8'),
            },
        },
        operator_name: "synthetic-operator".into(),
        operator_destination: "/synthetic/operator".into(),
        wallet_destination: "/synthetic/wallet/wallet.sqlite".into(),
        purpose: "preliminary_inventory_only".into(),
        retention_policy: "Private synthetic retention only".into(),
        provider: PreconstructionProvider {
            source_id: "synthetic-source".into(),
            endpoint: "https://synthetic.invalid".into(),
            trust_profile: "single_tls_provider_report_not_consensus".into(),
        },
        birthday: PreconstructionBirthday {
            prior_height: anchor - 100,
            prior_block_hash: h('3'),
            sapling_tree: String::new(),
            orchard_tree: String::new(),
            ironwood_tree: String::new(),
        },
        minimum_confirmations: 10,
        maximum_blocks: 100,
        anchor_height: anchor,
    };
    let economic_intent = ManualCandidateEconomicIntent {
        version: 1,
        candidate_id: "candidate".into(),
        candidate_revision: 1,
        proposal_id: input.proposal_id.clone(),
        previous_proposal_id: None,
        created_at: input.created_at.clone(),
        agreement: input.manifest.agreement.clone(),
        participants: input.manifest.participants.clone(),
        transaction_fee: input.manifest.transaction_fee,
        expiry_height: input.manifest.expiry_height,
        own_return_rule: BornOwnReturnRuleV2::AuthenticatedSameAccount,
    };
    let invocation = ManualCandidateInvocation {
        version: 1,
        operation_id: "common-construction".into(),
        idempotency_key_digest: h('1'),
        invocation_nonce: h('2'),
        economic_intent_digest: economic_intent.digest().unwrap(),
        checkpoint_destination: inventory.operator_destination.clone(),
        requested_at_ms: 132_000,
        construction_expires_at_ms: 252_000,
    };
    let selection = ManualRosterCandidateSelectionRequestV2 {
        version: 2,
        operation_id: "alice-selection".into(),
        scope: ManualRosterCandidateSelectionScopeV2 {
            version: 2,
            selection: ManualCandidateSelectionScope {
                version: 1,
                inventory,
                original_policy_origin: origin,
                economic_intent,
                invocation,
                purpose: "prepare_one_private_contribution".into(),
            },
            provenance: ManualRosterPreparationProvenanceV2 {
                version: 2,
                original_host_audit: OriginalHostRosterAuditV3::AdditionalPublicationV3 {
                    audit_digest: h('9'),
                },
                roster: e.roster.clone(),
                signer_roster_record_digest: e.signer_roster_record_digest.clone(),
                witness_roster_extension_digest: e.digest().unwrap(),
            },
        },
        current_caller_binding_digest: h('b'),
        requested_at_ms: 132_000,
        disclosure_expires_at_ms: 160_000,
    };
    let retained = ManualRosterContributionRetentionRequestV2 {
        version: 2,
        operation_id: "alice-retention".into(),
        selection,
        selection_evidence_digest: h('a'),
        selected_inputs: vec![ManualConstructionInput {
            input_id: "input-alice".into(),
            nullifier: h('4'),
            value_zatoshis: 500_000_000,
        }],
        selection_context: ManualSelectionContext {
            tip_height: anchor + 1,
            tip_hash_protocol: h('5'),
            anchor_height: anchor,
            anchor_hash_protocol: h('6'),
            anchor_root: h('7'),
        },
        local_exclusion_digest: h('8'),
        change_address: input.manifest.outputs[1].address.clone(),
        change_value_zatoshis: 99_988_000,
        requested_at_ms: 133_000,
        admission_expires_at_ms: 160_000,
    };
    let participants = vec![
        ManualRosterRetentionCommitmentV2 {
            participant_id: "alice".into(),
            account_id: h('a'),
            full_viewing_key_digest: e
                .account_extension
                .terms
                .identity
                .full_viewing_key_digest
                .clone(),
            retention_request_digest: retained.digest().unwrap(),
            retention_evidence_digest: h('1'),
        },
        ManualRosterRetentionCommitmentV2 {
            participant_id: "bob".into(),
            account_id: h('b'),
            full_viewing_key_digest: h('d'),
            retention_request_digest: h('2'),
            retention_evidence_digest: h('3'),
        },
    ];
    let plan = ManualRosterConstructionPlanV2 {
        version: 2,
        retained,
        retained_evidence_digest: h('1'),
        proposal: input,
        participants,
    };
    plan.validate().unwrap();
    let approval = ManualRosterConstructionApprovalV2 {
        version: 2,
        extension_digest: e.digest().unwrap(),
        plan: plan.clone(),
        issued_at_ms: 134_000,
        initial_commit_deadline_ms: 160_000,
    };
    let event = Event {
        mutation: AuthorityMutation::OwnerControl(OwnerControlRequest {
            operation_id: approval.owner_operation_id(&e).unwrap(),
            account_id: l.policy.account_id.clone(),
            network_profile_id: l.policy.network_profile_id.clone(),
            writer_epoch: 1,
            expected_head: l.snapshot.head.clone(),
            control: OwnerControl::ApproveManualRosterConstructionV2 {
                record: Box::new(ManualRosterConstructionApprovalRecordV2 {
                    approval,
                    owner_signature_evidence_digest: h('d'),
                    native_review_digest: h('e'),
                }),
            },
        }),
        authenticated_certificate_digest: l.policy.owner_certificate_digest.clone(),
        witness_time_ms: 134_000,
        writer_session_id: None,
        original_request_link: None,
    };
    l.apply(&event).unwrap();
    events.push(event);
    let request = ManualRosterConstructionReservationRequestV2 {
        version: 2,
        construction: ManualRosterConstructionRequestV2 {
            version: 2,
            operation_id: "alice-reservation".into(),
            plan,
            current_caller_binding_digest: h('c'),
            requested_at_ms: 135_000,
            admission_expires_at_ms: 165_000,
        },
        attempt_digest: c.digest_for(&e).unwrap(),
        attempt_sequence: 2,
        writer_epoch: 1,
        expected_head: l.snapshot.head.clone(),
        session_id: crate::session::session_id(&[0x44; 32]),
        signer_intent_digest: h('9'),
        native_review_digest: h('a'),
        reviewed_at_ms: 136_000,
    };
    let event = writer_event(
        &l,
        AuthorityMutation::ReserveManualRosterConstructionV2(Box::new(request)),
        136_000,
    );
    let MutationResult::ManualRosterConstructionReservedV2(r) = l.apply(&event).unwrap() else {
        panic!("reserve")
    };
    events.push(event);
    let request = ManualRosterConstructionConsumeRequestV2 {
        version: 2,
        operation_id: construction_consume_operation_id_v2(&r, &e, &c).unwrap(),
        reservation_operation_id: r.request.construction.operation_id.clone(),
        reservation_digest: r.digest_for(&e, &c).unwrap(),
        account_id: l.policy.account_id.clone(),
        network_profile_id: l.policy.network_profile_id.clone(),
        writer_epoch: 1,
        expected_head: l.snapshot.head.clone(),
        session_id: r.session.session_id.clone(),
        common_invocation_digest: r.request.invocation_digest().unwrap(),
        current_caller_binding_digest: h('c'),
    };
    let event = writer_event(
        &l,
        AuthorityMutation::ConsumeManualRosterConstructionV2(request),
        137_000,
    );
    l.apply(&event).unwrap();
    events.push(event);
    (birth, e, events, l)
}
fn writer_event(l: &Ledger, mutation: AuthorityMutation, now: u64) -> Event {
    Event {
        mutation,
        authenticated_certificate_digest: l.policy.initial_writer_certificate_digest.clone(),
        witness_time_ms: now,
        writer_session_id: Some(
            l.snapshot
                .active_writer_session
                .as_ref()
                .unwrap()
                .session_id
                .clone(),
        ),
        original_request_link: None,
    }
}
fn prefix(birth: &crate::pending_birth::PendingBirthCommitRecord, events: &[Event]) -> Ledger {
    let mut l = Ledger::new(birth.request.policy.clone()).unwrap();
    for e in events {
        l.apply(e).unwrap();
    }
    l
}
#[test]
fn durable_construction_charges_original_account_and_shared_exclusions() {
    let (birth, e, events, mut l) = construction_fixture();
    assert_eq!(l.snapshot.head.sequence, 11);
    assert!(l.policy == birth.request.policy);
    assert_eq!(l.snapshot.aggregate_budget_zatoshis, 1_000_000_000);
    assert_eq!(l.snapshot.outstanding_debit_zatoshis, 400_012_000);
    assert_eq!(l.snapshot.reserved_input_value_zatoshis, 500_000_000);
    assert_eq!(l.snapshot.outstanding_reservations, 1);
    assert_eq!(l.snapshot.settled_debit_zatoshis, 0);
    let before = l.snapshot.clone();
    l.recompute_exposure().unwrap();
    assert!(l.snapshot == before);
    assert!(matches!(
        l.check_input_obligation_exclusions(
            &e.account_extension.terms.scope.obligation_id,
            std::iter::empty()
        ),
        Err(AuthorityError::ObligationReserved)
    ));
    assert!(matches!(
        l.check_input_obligation_exclusions("other", [("input-alice", "unused")].into_iter()),
        Err(AuthorityError::InputReserved)
    ));
    assert!(matches!(
        l.check_input_obligation_exclusions("other", [("other", h('4').as_str())].into_iter()),
        Err(AuthorityError::InputReserved)
    ));
    assert!(
        crate::reservation_view::ReservationView::from_result(&l.operations["alice-reservation"].2)
            .is_none()
    );
    assert!(prefix(&birth, &events).snapshot == l.snapshot);
}
#[test]
fn bootstrap_or_continuation_cannot_substitute_exact_owner_plan_approval() {
    let (birth, _, events, _) = construction_fixture();
    let mut l = prefix(&birth, &events[..8]);
    let mut r = events[9].clone();
    let AuthorityMutation::ReserveManualRosterConstructionV2(request) = &mut r.mutation else {
        panic!()
    };
    request.expected_head = l.snapshot.head.clone();
    assert!(matches!(l.apply(&r), Err(AuthorityError::Permission)));
    assert_eq!(l.snapshot.head.sequence, 8);
}
#[test]
fn exact_reservation_retry_is_immutable_and_consume_replay_never_remints() {
    let (birth, e, events, l) = construction_fixture();
    let mut before = prefix(&birth, &events[..10]);
    let snapshot = before.snapshot.clone();
    let MutationResult::ManualRosterConstructionReservedV2(r) = before.apply(&events[9]).unwrap()
    else {
        panic!()
    };
    assert!(before.snapshot == snapshot);
    assert_eq!(r.admitted_at_ms, 136_000);
    assert_eq!(r.construction_expires_at_ms, 252_000);
    assert!(l.replay(&events[10]).unwrap().is_some());
    assert!(matches!(
        l.require_unconsumed_roster_construction_v2(&events[10].mutation),
        Err(AuthorityError::Uncertain)
    ));
    assert!(matches!(
        l.require_roster_construction_scope_v2(&events[9].mutation, 138_000),
        Err(AuthorityError::Uncertain)
    ));
    let c = l
        .latest_manual_roster_attempt_v2()
        .unwrap()
        .continuation
        .unwrap();
    r.validate_for(&e, &c).unwrap();
}
#[test]
fn deadline_drain_and_consumption_preserve_exposure_after_cancellation() {
    let (birth, e, events, mut l) = construction_fixture();
    let c = l
        .latest_manual_roster_attempt_v2()
        .unwrap()
        .continuation
        .unwrap();
    assert_eq!(
        l.roster_construction_drain_deadline_v2(&c.digest_for(&e).unwrap()),
        252_000
    );
    let mut before = prefix(&birth, &events[..10]);
    let mut late = events[10].clone();
    late.witness_time_ms = 165_000;
    assert!(before.apply(&late).is_err());
    assert_eq!(before.snapshot.outstanding_debit_zatoshis, 400_012_000);
    let early = continuation(&l, &e, 251_000, '9');
    assert!(
        l.validate_new_manual_roster_continuation_v2(
            &crate::manual_roster_witness_v2::ManualRosterSessionContinuationRecordV2 {
                continuation: early,
                owner_signature_evidence_digest: h('a'),
                native_review_digest: h('b')
            },
            251_000
        )
        .is_err()
    );
    l.snapshot.writer_status = WriterStatus::Paused;
    assert!(
        l.require_roster_construction_scope_v2(&events[9].mutation, 138_000)
            .is_err()
    );
    let charged = l.snapshot.outstanding_debit_zatoshis;
    l.recompute_exposure().unwrap();
    assert_eq!(l.snapshot.outstanding_debit_zatoshis, charged);
}
#[test]
fn current_attempt_caller_or_input_changes_are_rejected_before_append() {
    let (birth, _, events, _) = construction_fixture();
    for which in 0..5 {
        let mut l = prefix(&birth, &events[..10]);
        let mut bad = events[10].clone();
        let AuthorityMutation::ConsumeManualRosterConstructionV2(r) = &mut bad.mutation else {
            panic!()
        };
        match which {
            0 => r.current_caller_binding_digest = h('f'),
            1 => r.common_invocation_digest = h('f'),
            2 => r.reservation_digest = h('f'),
            3 => r.session_id = h('f'),
            _ => r.expected_head.digest = h('f'),
        }
        assert!(l.apply(&bad).is_err());
        assert_eq!(l.snapshot.head.sequence, 10);
    }
    let mut l = prefix(&birth, &events[..9]);
    let mut bad = events[9].clone();
    let AuthorityMutation::ReserveManualRosterConstructionV2(r) = &mut bad.mutation else {
        panic!()
    };
    r.construction.plan.retained.selected_inputs[0].nullifier = h('f');
    assert!(l.apply(&bad).is_err());
    assert_eq!(l.snapshot.outstanding_debit_zatoshis, 0);
}
#[test]
fn retirement_and_lifetime_budget_cannot_be_erased_by_new_construction() {
    let (birth, _, events, _) = construction_fixture();
    let mut l = prefix(&birth, &events[..9]);
    let g = l.policy.account_use_genesis.as_ref().unwrap().clone();
    l.account_use_history
        .exclude(crate::account_use::PermanentAccountExclusion {
            version: 1,
            identity: g.identity.clone(),
            genesis_digest: g.digest().unwrap(),
            operation_id: "synthetic-retired".into(),
            native_review_digest: h('f'),
            reason: crate::account_use::ExclusionReason::RetirementRequested,
        })
        .unwrap();
    assert!(l.apply(&events[9]).is_err());
    assert_eq!(l.snapshot.outstanding_debit_zatoshis, 0);
    let mut l = prefix(&birth, &events[..9]);
    l.snapshot.settled_debit_zatoshis = 700_000_000;
    assert!(matches!(
        l.apply(&events[9]),
        Err(AuthorityError::BudgetExceeded)
    ));
    assert_eq!(l.snapshot.settled_debit_zatoshis, 700_000_000);
    assert_eq!(l.snapshot.outstanding_debit_zatoshis, 0);
}

#[test]
fn historical_records_remain_enumerable_while_legacy_financial_projection_refuses() {
    let (birth, _, events, l) = construction_fixture();
    let history = crate::manual_roster_witness_v2::tests::history(&birth, &l, &events);
    assert_eq!(history.manual_roster_construction_records_v2().count(), 2);
    let facts = serde_json::to_value(history.retirement_history_facts().unwrap()).unwrap();
    assert_eq!(facts["construction_reservation_records"], 1);
    assert_eq!(facts["construction_consumption_records"], 1);
    assert_eq!(
        facts["construction_retained_debit_zatoshis"],
        400_012_000u64
    );
    assert_eq!(
        facts["construction_retained_input_value_zatoshis"],
        500_000_000u64
    );
    assert_eq!(
        facts["outstanding_debit_zatoshis"],
        history.snapshot().outstanding_debit_zatoshis
    );
    assert_eq!(facts["settled_debit_zatoshis"], 0);
    assert_eq!(facts["retirement_completion"], "unavailable");
    assert_eq!(facts["external_clone_absence"], "unknown");

    assert!(history.reservation_evidence().next().is_none());
    assert!(matches!(
        history.require_legacy_online_only(),
        Err(AuthorityError::ConstructionHistoryUnsupported)
    ));
    assert!(history.permits().is_err());
    assert!(
        history
            .manual_roster_construction_record_v2("alice-reservation")
            .unwrap()
            .is_some()
    );
}

#[test]
fn complete_construction_archive_roundtrip_keeps_original_provenance_and_permanent_charge() {
    let (birth, _, events, ledger) = construction_fixture();
    let history = crate::manual_roster_witness_v2::tests::history(&birth, &ledger, &events);
    let archive = history.construction_history_v1().unwrap();
    assert_eq!(archive.origins().len(), 1);
    assert!(archive.origins()[0].consumed().is_some());
    assert_eq!(archive.retained_debit_zatoshis().unwrap(), 400_012_000);
    assert_eq!(
        archive.retained_input_value_zatoshis().unwrap(),
        500_000_000
    );
    let bytes = serde_json::to_vec(&archive).unwrap();
    let restored: crate::ConstructionHistoryV1 = serde_json::from_slice(&bytes).unwrap();
    restored.validate().unwrap();
    assert_eq!(restored.digest().unwrap(), archive.digest().unwrap());
    assert_eq!(
        restored.complete_replay_digest(),
        history.history_digest().unwrap()
    );
    assert!(restored.observed_snapshot() == history.snapshot());
    assert!(restored.origins()[0].reservation() == archive.origins()[0].reservation());
    let retained: serde_json::Value = serde_json::from_str(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../wholepact-signer/src/authority_bridge/host_recovery_ipc/v3/fixtures/nonempty_evidence.json"))).unwrap();
    assert!(
        serde_json::to_value(&archive).unwrap() == retained["complete_history"]["construction"]
    );
}

#[test]
fn construction_archive_rejects_changed_consume_link_charge_birth_and_current_exposure() {
    let (birth, _, events, ledger) = construction_fixture();
    let history = crate::manual_roster_witness_v2::tests::history(&birth, &ledger, &events);
    let archive = serde_json::to_value(history.construction_history_v1().unwrap()).unwrap();
    for change in 0..5 {
        let mut altered = archive.clone();
        match change {
            0 => {
                altered["origins"][0]["consumed"]["request"]["reservation_operation_id"] =
                    "different-original".into()
            }
            1 => altered["origins"][0]["reservation"]["reserved_debit_zatoshis"] = 0.into(),
            2 => altered["original_birth"] = serde_json::Value::Null,
            3 => altered["observed_snapshot"]["outstanding_debit_zatoshis"] = 0.into(),
            _ => altered["origins"][0]["continuation"]["unexpected"] = true.into(),
        }
        let parsed = serde_json::from_value::<crate::ConstructionHistoryV1>(altered);
        assert!(parsed.is_err() || parsed.unwrap().validate().is_err());
    }
}
