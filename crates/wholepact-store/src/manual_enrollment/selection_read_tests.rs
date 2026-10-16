//! Synthetic private read-path tests only. The in-memory Store is explicitly
//! modeled as protected/recovered; this does not qualify an encrypted opener.
//! No fixture creates a native decision, peer, production selection lease,
//! witness reservation, signing owner, or financial admission.
use super::*;
use crate::manual_enrollment::tests::initial_publication::{
    add_continuation, add_initial, continuation_fixture, initial_fixture,
};
use crate::manual_enrollment::tests::{fence, h, modeled_store};
use wholepact_core::{
    AgreementDraft, Amount,
    agreement::FundingPolicy,
    born_policy_origin_v2::*,
    born_recipient_policy_v2::*,
    manual_candidate_selection::*,
    manual_construction::*,
    manual_inventory::ManualPreliminaryInventoryScope,
    proposal::{ParticipantAllocation, canonical_digest},
};

fn money(value: u64) -> Amount {
    Amount::from_zatoshis(value).unwrap()
}

/// Match a pure input-free request to the existing V2 initial-publication audit
/// fixture. Digests below authenticate no real participant or external history.
fn modeled_request() -> (
    ManualEnrollmentInitialPublicationV2,
    ManualCandidateSelectionRequest,
) {
    let mut initial = initial_fixture();
    let mut terms = initial.terms().clone();
    let mut agreement: AgreementDraft = wholepact_core::parse_typed_json(include_bytes!(
        "../../../wholepact-core/tests/fixtures/agreement.json"
    ))
    .unwrap();
    agreement.agreement_id = terms.scope.agreement_id.clone();
    agreement.obligation_id = terms.scope.obligation_id.clone();
    agreement.network_profile_id = terms.identity.network_profile_id.clone();
    agreement.recipients[0].amount = money(100);
    agreement.funding_policy = FundingPolicy::Exact { target: money(100) };
    let recipient = &agreement.recipients[0];
    let policy = BornConstructionRecipientPolicyV2 {
        version: 2,
        account_id: terms.identity.account_id.clone(),
        network_profile_id: terms.identity.network_profile_id.clone(),
        agreement_id: terms.scope.agreement_id.clone(),
        obligation_id: terms.scope.obligation_id.clone(),
        participant_id: terms.scope.participant_id.clone(),
        recipients: vec![BornRecipientLimitV2 {
            recipient_id: recipient.recipient_id.clone(),
            address: recipient.address.clone(),
            memo: recipient.memo.clone(),
            instruction_provenance: recipient.instruction_provenance.clone(),
            maximum_amount_zatoshis: 100,
        }],
        charges: vec![],
        original_limits: BornOriginalLimitsV2 {
            aggregate_budget_zatoshis: terms.scope.aggregate_budget_zatoshis,
            per_operation_limit_zatoshis: terms.scope.per_operation_limit_zatoshis,
            maximum_fee_share_zatoshis: terms.scope.maximum_fee_share_zatoshis,
            maximum_transaction_fee_zatoshis: terms.scope.maximum_transaction_fee_zatoshis,
            maximum_permit_lifetime_ms: terms.scope.maximum_permit_lifetime_ms,
            policy_expires_at_ms: terms.scope.expires_at_ms,
        },
        own_return_rule: BornOwnReturnRuleV2::AuthenticatedSameAccount,
    };
    terms.scope.recipient_scope_digests = vec![policy.digest().unwrap()];
    let original_terms = BornPolicyOriginalTermsV2 {
        witness_id: "synthetic-witness".into(),
        account_id: terms.identity.account_id.clone(),
        network_profile_id: terms.identity.network_profile_id.clone(),
        owner_certificate_digest: terms.signer.owner_certificate_digest.clone(),
        initial_writer_certificate_digest: terms.signer.writer_certificate_digest.clone(),
        initial_writer_epoch: terms.signer.writer_epoch,
        enrollment_refs: vec![initial.evidence.enrollment_ref.clone()],
        agreement_ids: vec![terms.scope.agreement_id.clone()],
        recipient_scope_digests: terms.scope.recipient_scope_digests.clone(),
        aggregate_budget_zatoshis: terms.scope.aggregate_budget_zatoshis,
        per_operation_limit_zatoshis: terms.scope.per_operation_limit_zatoshis,
        maximum_fee_share_zatoshis: terms.scope.maximum_fee_share_zatoshis,
        maximum_transaction_fee_zatoshis: terms.scope.maximum_transaction_fee_zatoshis,
        maximum_permit_lifetime_ms: terms.scope.maximum_permit_lifetime_ms,
        policy_expires_at_ms: terms.scope.expires_at_ms,
    };
    let intent = BornRecipientPolicyBirthIntentV2 {
        version: 2,
        operation_id: format!("birth-{}", "a".repeat(32)),
        generation_instance_id: h('b'),
        identity: BornPolicyIdentityV2 {
            account_id: terms.identity.account_id.clone(),
            full_viewing_key_digest: terms.identity.full_viewing_key_digest.clone(),
            network_profile_id: terms.identity.network_profile_id.clone(),
            derivation_domain: terms.identity.derivation_domain.clone(),
            exact_derivation: "synthetic-only".into(),
        },
        witness_origin: BornPolicyWitnessOriginV2 {
            endpoint: "https://synthetic.invalid".into(),
            server_name: "synthetic.invalid".into(),
            witness_id: "synthetic-witness".into(),
            pinned_server_certificate_digest: h('c'),
        },
        original_policy_terms_digest: original_terms.digest().unwrap(),
        original_policy_terms: original_terms,
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
    terms.native_birth_digest = origin.birth_digest.clone();
    terms.original_policy_digest = origin.intent.original_policy_terms_digest.clone();
    let witness = &origin.intent.witness_origin;
    terms.original_witness_origin_digest = canonical_digest(
        "wholepact:account-use-witness-origin:v1",
        &(
            &witness.endpoint,
            &witness.server_name,
            &witness.witness_id,
            &witness.pinned_server_certificate_digest,
        ),
    )
    .unwrap();
    initial.evidence.request.enrollment.terms = terms.clone();
    initial.evidence.admission.exact_request_digest = initial.evidence.request.digest().unwrap();
    initial.validate().unwrap();
    let economic_intent = ManualCandidateEconomicIntent {
        version: 1,
        candidate_id: "synthetic-candidate".into(),
        candidate_revision: 1,
        proposal_id: "synthetic-proposal".into(),
        previous_proposal_id: None,
        created_at: "2026-10-13T14:00:00Z".into(),
        agreement,
        participants: vec![
            ParticipantAllocation {
                participant_id: terms.scope.participant_id.clone(),
                account_id: terms.identity.account_id.clone(),
                contribution: money(40),
                fee_share: money(0),
                fee_cap: money(0),
                maximum_net_debit: money(40),
                charges: vec![],
            },
            ParticipantAllocation {
                participant_id: "zz-peer".into(),
                account_id: h('3'),
                contribution: money(60),
                fee_share: money(0),
                fee_cap: money(0),
                maximum_net_debit: money(60),
                charges: vec![],
            },
        ],
        transaction_fee: money(0),
        expiry_height: 200,
        own_return_rule: BornOwnReturnRuleV2::AuthenticatedSameAccount,
    };
    let invocation = ManualCandidateInvocation {
        version: 1,
        operation_id: "synthetic-invocation".into(),
        idempotency_key_digest: h('6'),
        invocation_nonce: h('7'),
        economic_intent_digest: economic_intent.digest().unwrap(),
        checkpoint_destination: "/synthetic/checkpoint".into(),
        requested_at_ms: 3001,
        construction_expires_at_ms: 4000,
    };
    let inventory = ManualPreliminaryInventoryScope {
        version: 1,
        enrollment_ref: initial.evidence.enrollment_ref.clone(),
        witness_extension_digest: initial.evidence.witness_extension_digest.clone(),
        attempt: ManualConstructionAttempt {
            version: 2,
            continuation_digest: initial.evidence.admission.attempt_digest.clone(),
            attempt_sequence: initial.evidence.admission.attempt_sequence,
        },
        original_recipient_policy: policy,
        attachment: ManualConstructionAttachmentBinding {
            version: 1,
            original_primary_journal_origin_digest: terms
                .host
                .financial_journal_origin_digest
                .clone(),
            predecessor_registry_digest: h('a'),
            current_registry_digest: h('b'),
            latest_extension_digest: h('c'),
            selected: ManualParticipantAttachment {
                account_id: terms.identity.account_id.clone(),
                canonical_directory: "/synthetic/wallet".into(),
                directory_identity_digest: h('d'),
                journal_origin_digest: h('e'),
            },
        },
        enrollment: terms,
        operator_name: "synthetic-local-host".into(),
        operator_destination: "/synthetic/checkpoint".into(),
        wallet_destination: "/synthetic/wallet/wallet.sqlite".into(),
        purpose: "preliminary_inventory_only".into(),
        retention_policy: "Synthetic private predicate data only".into(),
        provider: PreconstructionProvider {
            source_id: "synthetic-provider".into(),
            endpoint: "https://synthetic.invalid".into(),
            trust_profile: "single_tls_provider_report_not_consensus".into(),
        },
        birthday: PreconstructionBirthday {
            prior_height: 1,
            prior_block_hash: h('f'),
            sapling_tree: String::new(),
            orchard_tree: String::new(),
            ironwood_tree: String::new(),
        },
        minimum_confirmations: 1,
        maximum_blocks: 10,
        anchor_height: 100,
    };
    let request = ManualCandidateSelectionRequest {
        version: 1,
        operation_id: "synthetic-selection".into(),
        scope: ManualCandidateSelectionScope {
            version: 1,
            inventory,
            original_policy_origin: origin,
            economic_intent,
            invocation,
            purpose: "prepare_one_private_contribution".into(),
        },
        current_caller_binding_digest: h('a'),
        requested_at_ms: 3001,
        disclosure_expires_at_ms: 3900,
    };
    request.validate().unwrap();
    (initial, request)
}

fn install(
    store: &Store,
    initial: &ManualEnrollmentInitialPublicationV2,
    request: &ManualCandidateSelectionRequest,
) -> StoredRecord {
    let context =
        CommandContext::for_request("owner", "synthetic-read-agreement", &serde_json::json!({}))
            .unwrap();
    let record = store
        .create_agreement(
            &context,
            &initial.terms().scope.agreement_id,
            serde_json::json!({"view":{"agreement": request.scope.economic_intent.agreement}}),
        )
        .unwrap()
        .record;
    add_initial(store, initial, &[]).unwrap();
    record
}

/// Deliberately creates only the private data snapshot used to unit-test its
/// read predicates. The production constructor still requires a real native
/// lease, and this test helper is not compiled or exported in production.
fn modeled_snapshot<'a>(
    store: &'a Store,
    record: &StoredRecord,
    request: &ManualCandidateSelectionRequest,
) -> ManualCandidateLocalExclusions<'a> {
    let target = store.manual_store_target().unwrap();
    let exclusions = read_local(store, &target, record, request).unwrap();
    ManualCandidateLocalExclusions {
        store,
        target,
        expected_agreement: record.clone(),
        request: request.clone(),
        exclusions,
    }
}

fn add_exclusion(store: &Store, audit: &ManualExclusionAudit) {
    let mut c = store.connection.lock().unwrap();
    let tx = c
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    kernel::append_exclusion(&tx, audit).unwrap();
    tx.commit().unwrap();
}

#[test]
fn selection_local_read_requires_latest_exact_attempt_and_rejects_stale_snapshot() {
    let store = modeled_store();
    let (initial, request) = modeled_request();
    let record = install(&store, &initial, &request);
    let snapshot = modeled_snapshot(&store, &record, &request);
    assert!(snapshot.current_for(&store, &request).is_ok());
    let mut unknown = request.clone();
    unknown.scope.inventory.attempt.continuation_digest = h('0');
    let target = store.manual_store_target().unwrap();
    assert!(read_local(&store, &target, &record, &unknown).is_err());
    let next = continuation_fixture(&initial);
    add_continuation(&store, &next, &[]).unwrap();
    assert!(read_local(&store, &target, &record, &request).is_err());
    assert!(snapshot.current_for(&store, &request).is_err());
    let mut current = request.clone();
    current.scope.inventory.attempt.attempt_sequence = next.evidence.admission.attempt_sequence;
    current.scope.inventory.attempt.continuation_digest =
        next.evidence.admission.attempt_digest.clone();
    current.validate().unwrap();
    assert!(read_local(&store, &target, &record, &current).is_ok());
    assert!(snapshot.current_for(&store, &current).is_err());
}

#[test]
fn selection_local_read_denies_retirement_after_snapshot_creation() {
    let store = modeled_store();
    let (initial, request) = modeled_request();
    let record = install(&store, &initial, &request);
    let snapshot = modeled_snapshot(&store, &record, &request);
    let retired = ManualExclusionAudit {
        version: 1,
        operation_id: "synthetic-retire-original".into(),
        identity: initial.terms().identity.clone(),
        aliases: initial.aliases.clone(),
        account_use_genesis_digest: initial.terms().account_use_genesis_digest.clone(),
        exclusion_digest: h('6'),
        witness_history_digest: h('7'),
    };
    add_exclusion(&store, &retired);
    assert!(snapshot.current_for(&store, &request).is_err());
    assert!(
        read_local(
            &store,
            &store.manual_store_target().unwrap(),
            &record,
            &request
        )
        .is_err()
    );
}

#[test]
fn selection_local_read_requires_complete_inherited_identity_coverage() {
    let store = modeled_store();
    let (initial, request) = modeled_request();
    let record = install(&store, &initial, &request);
    let target = store.manual_store_target().unwrap();
    assert!(read_local(&store, &target, &record, &request).is_ok());
    fence(&store, "account", "legacy-alias");
    assert!(read_local(&store, &target, &record, &request).is_err());
    let mut identity = initial.terms().identity.clone();
    identity.account_id = h('3');
    identity.full_viewing_key_digest = h('4');
    let old = ManualExclusionAudit {
        version: 1,
        operation_id: "synthetic-old-retirement".into(),
        aliases: BTreeSet::from([identity.account_id.clone(), "legacy-alias".into()]),
        identity,
        account_use_genesis_digest: h('5'),
        exclusion_digest: h('6'),
        witness_history_digest: h('7'),
    };
    add_exclusion(&store, &old);
    assert!(read_local(&store, &target, &record, &request).is_ok());
}

#[test]
fn selection_local_snapshot_is_bound_to_actual_store_and_ordinary_denial_stays() {
    let store = modeled_store();
    let other = modeled_store();
    let (initial, request) = modeled_request();
    let record = install(&store, &initial, &request);
    let other_record = install(&other, &initial, &request);
    let snapshot = modeled_snapshot(&store, &record, &request);
    // Both modeled Stores contain the same original audit, request, destination
    // metadata and economics. Only the actual Store borrow distinguishes them.
    assert!(record.payload == other_record.payload);
    assert_eq!(
        store
            .manual_store_target()
            .unwrap()
            .store_destination_identity(),
        other
            .manual_store_target()
            .unwrap()
            .store_destination_identity()
    );
    assert!(snapshot.current_for(&store, &request).is_ok());
    assert!(matches!(
        snapshot.current_for(&other, &request),
        Err(StoreError::RecoveryRequired)
    ));
    for current in [&store, &other] {
        assert!(matches!(
            current.retained_financial_input_exclusions(&initial.terms().identity.account_id),
            Err(StoreError::RecoveryRequired)
        ));
        assert!(matches!(
            current.require_ordinary_financial_lineage(
                &initial.terms().scope.agreement_id,
                &initial.terms().scope.obligation_id,
                &initial.terms().scope.principal_id,
                None,
                &[],
            ),
            Err(StoreError::RecoveryRequired)
        ));
        assert!(
            current
                .authority_account(&initial.terms().identity.account_id)
                .unwrap()
                .is_none()
        );
        assert!(current.recovery_state().unwrap().recovery_required);
    }
}

#[test]
fn selection_local_read_denies_changed_original_generation_and_full_agreement_record() {
    let store = modeled_store();
    let (initial, request) = modeled_request();
    let record = install(&store, &initial, &request);
    let target = store.manual_store_target().unwrap();
    let mut wrong_generation = request.clone();
    wrong_generation
        .scope
        .inventory
        .enrollment
        .host
        .generation_id = h('0');
    wrong_generation.validate().unwrap();
    assert!(read_local(&store, &target, &record, &wrong_generation).is_err());
    let snapshot = modeled_snapshot(&store, &record, &request);
    // Model an unrelated committed agreement update after the captured read.
    store
        .connection
        .lock()
        .unwrap()
        .execute(
            "UPDATE records SET revision=revision+1 WHERE aggregate_type='agreement' AND id=?1",
            [&record.id],
        )
        .unwrap();
    assert!(matches!(
        snapshot.current_for(&store, &request),
        Err(StoreError::RevisionConflict)
    ));
}
