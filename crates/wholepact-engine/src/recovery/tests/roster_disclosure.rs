//! Synthetic encrypted read-scope regression. The row below is fixture metadata
//! inserted into an isolated encrypted journal, never a native approval, signer
//! lease, witness admission or demonstration of actual publication authority.
use super::*;
use wholepact_core::manual_enrollment::{
    BornManualEnrollmentTerms, BornManualScope, BornManualSignerBinding, ManualAccountIdentity,
    ManualHostGenerationBinding,
};
use wholepact_store::manual_enrollment::{ManualDurableEnrollmentAudit, ManualEnrollmentAudit};

fn h(value: char) -> String {
    value.to_string().repeat(64)
}
fn synthetic_hidden_member(
    generation: &str,
    inventory: &str,
    destination: &str,
) -> ManualEnrollmentAudit {
    let identity = ManualAccountIdentity {
        account_id: h('1'),
        full_viewing_key_digest: h('2'),
        network_profile_id: draft("hidden-b").network_profile_id,
        derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
    };
    let terms = BornManualEnrollmentTerms {
        version: 1,
        operation_id: "synthetic-hidden-member-original".into(),
        identity: identity.clone(),
        birth_request_digest: h('3'),
        birth_commit_digest: h('4'),
        native_birth_digest: h('5'),
        original_policy_digest: h('6'),
        account_use_genesis_digest: h('7'),
        original_witness_origin_digest: h('8'),
        host: ManualHostGenerationBinding {
            generation_id: generation.into(),
            inventory_digest: inventory.into(),
            generation_plan_digest: h('c'),
            financial_journal_origin_digest: h('d'),
            store_destination_identity: destination.into(),
            profile_id: "synthetic-profile".into(),
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
            agreement_id: "hidden-b".into(),
            obligation_id: "obligation-hidden-b".into(),
            participant_id: "private-participant-b".into(),
            principal_id: "hidden-owner".into(),
            privacy_domain: "private-domain-b".into(),
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
    };
    let exact_request_digest = wholepact_core::proposal::canonical_digest(
        "wholepact:host-manual-enrollment-request:v1",
        &json!({"terms": &terms}),
    )
    .unwrap();
    ManualEnrollmentAudit {
        version: 1,
        terms,
        admission: ManualDurableEnrollmentAudit {
            exact_request_digest,
            signer_intent_digest: h('d'),
            witness_admission_digest: h('e'),
            admitted_at_ms: 2,
            admission_deadline_ms: 1000,
        },
        enrollment_ref: h('3'),
        witness_extension_digest: h('4'),
        witness_extension_sequence: 1,
        witness_extension_predecessor_digest: None,
        aliases: BTreeSet::from([identity.account_id]),
        store_sequence: 1,
        request_identity_digest: h('5'),
        original_provider_enrollment_ref: h('a'),
        original_complete_history_digest: h('6'),
        original_exclusion_checkpoint_digest: h('7'),
        original_native_review_digest: h('8'),
    }
}

#[test]
fn actual_roster_target_does_not_disclose_an_unselected_member_agreement() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let source_engine = Engine::from_store(
        Store::create_encrypted(dir.path().join("source.sqlite"), &key(171)).unwrap(),
    );
    let owner_a = Access {
        principal_id: "owner-a".into(),
        include_owned_agreements: true,
        ..Access::default()
    };
    source_engine
        .create(&owner_a, "synthetic-source-key", draft("historical"))
        .unwrap();
    let source = source(&source_engine, dir.path());
    let inventory = inspect_coordination_recovery(&source).unwrap();
    let binding =
        bundle::recovery::generation::GenerationBinding::new(&h('e'), inventory.digest()).unwrap();
    let destination = dir.path().join("successor.sqlite");
    Store::reconstruct_recovered_generation(&source, &destination, &key(174), &binding).unwrap();
    let recovered = Engine::from_store(
        Store::open_recovered_generation(&destination, &key(174), &binding, source.provenance())
            .unwrap(),
    );
    recovered
        .create(&owner_a, "synthetic-selected-key", draft("selected-a"))
        .unwrap();
    let owner_b = Access {
        principal_id: "hidden-owner".into(),
        include_owned_agreements: true,
        ..Access::default()
    };
    recovered
        .create(&owner_b, "synthetic-hidden-key", draft("hidden-b"))
        .unwrap();
    let store_target = recovered.store.manual_store_target().unwrap();
    let member = synthetic_hidden_member(
        store_target.generation_id(),
        store_target.inventory_digest(),
        store_target.store_destination_identity(),
    );
    member.validate().unwrap();
    drop(store_target);
    drop(recovered);

    // A deliberately synthetic retained fixture row, using the genuine encrypted
    // generation opener. No production lease consumer or permission is bypassed
    // by a public test constructor; this helper exists only in this test module.
    let connection = bundle::recovery::generation::open_recovered_generation(
        &destination,
        &key(174),
        &binding,
        source.provenance(),
        wholepact_store::recovery::coordination_successor_template(),
    )
    .unwrap();
    connection.connection().execute(
        "INSERT INTO records(aggregate_type,id,revision,payload,created_at_ms,updated_at_ms) VALUES('generation_manual_enrollment_v1',?1,0,?2,1,1)",
        [member.digest().unwrap(), serde_json::to_string(&member).unwrap()],
    ).unwrap();
    drop(connection);
    let engine = Engine::from_store(
        Store::open_recovered_generation(&destination, &key(174), &binding, source.provenance())
            .unwrap(),
    );
    let selected_a = Access {
        principal_id: "owner-a".into(),
        agreement_ids: BTreeSet::from(["selected-a".into()]),
        all_agreements: false,
        include_owned_agreements: false,
    };
    let target = engine
        .manual_roster_intent_target(&selected_a, "selected-a")
        .unwrap();
    assert_eq!(target.binding().roster_sequence, 2);
    assert!(target.members(&selected_a).is_err());
    assert!(target.members(&owner_a).is_err()); // OWNED does not include hidden-owner's B.
    let selected_both = Access {
        agreement_ids: BTreeSet::from(["selected-a".into(), "hidden-b".into()]),
        ..selected_a.clone()
    };
    let rows = target.members(&selected_both).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].scope.agreement_id, "hidden-b");
    assert_eq!(rows[0].scope.participant_id, "private-participant-b");
    let all = Access {
        all_agreements: true,
        ..selected_a.clone()
    };
    assert_eq!(target.members(&all).unwrap().len(), 1);
    // Permissions are evaluated on each read; an earlier authorized read cannot
    // turn the retained target into a capability for a narrower current scope.
    assert!(target.members(&selected_a).is_err());
    assert!(
        engine
            .store
            .authority_account(&member.terms.identity.account_id)
            .unwrap()
            .is_none()
    );
    assert!(engine.store.recovery_state().unwrap().recovery_required);
}
