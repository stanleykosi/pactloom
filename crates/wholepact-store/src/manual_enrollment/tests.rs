use super::{kernel::*, *};
use crate::{CommandContext, authority::ReleaseIntent};
use rusqlite::{TransactionBehavior, params};
use wholepact_core::manual_enrollment::{
    BornManualAction, BornManualScope, BornManualSignerBinding, ManualHostGenerationBinding,
};
pub(in crate::manual_enrollment) fn h(c: char) -> String {
    c.to_string().repeat(64)
}
fn ident(c: char, f: char) -> ManualAccountIdentity {
    ManualAccountIdentity {
        account_id: h(c),
        full_viewing_key_digest: h(f),
        network_profile_id: "synthetic-test-network".into(),
        derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
    }
}
fn aliases(i: &ManualAccountIdentity) -> BTreeSet<String> {
    BTreeSet::from([i.account_id.clone()])
}
fn enrollment() -> ManualEnrollmentAudit {
    let identity = ident('1', '2');
    let mut audit = ManualEnrollmentAudit {
        version: 1,
        aliases: aliases(&identity),
        terms: BornManualEnrollmentTerms {
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
        },
        admission: ManualDurableEnrollmentAudit {
            exact_request_digest: h('f'),
            signer_intent_digest: h('d'),
            witness_admission_digest: h('e'),
            admitted_at_ms: 2,
            admission_deadline_ms: 1000,
        },
        enrollment_ref: h('3'),
        witness_extension_digest: h('4'),
        witness_extension_sequence: 1,
        witness_extension_predecessor_digest: None,
        store_sequence: 1,
        request_identity_digest: h('5'),
        original_provider_enrollment_ref: h('a'),
        original_complete_history_digest: h('6'),
        original_exclusion_checkpoint_digest: h('7'),
        original_native_review_digest: h('8'),
    };
    rebind(&mut audit);
    audit
}
fn rebind(a: &mut ManualEnrollmentAudit) {
    a.admission.exact_request_digest = enrollment_request_digest(&a.terms).unwrap();
}
fn action(a: &ManualEnrollmentAudit) -> ManualActionAudit {
    let mut audit = ManualActionAudit {
        version: 1,
        enrollment_audit_digest: a.digest().unwrap(),
        witness_extension_digest: a.witness_extension_digest.clone(),
        intent: BornManualActionIntent {
            version: 1,
            enrollment_ref: a.enrollment_ref.clone(),
            candidate_id: "candidate-new".into(),
            proposal_id: "proposal-new".into(),
            manifest_digest: h('1'),
            obligation_id: a.terms.scope.obligation_id.clone(),
            operation_id: "action-new".into(),
            idempotency_key_digest: h('2'),
            input_set_digest: h('3'),
            exact_request_digest: h('4'),
            action: BornManualAction::Construct,
            invocation_nonce: h('5'),
        },
        admission: ManualDurableActionAudit {
            exact_request_digest: h('f'),
            signer_intent_digest: h('d'),
            witness_admission_digest: h('e'),
            admitted_at_ms: 2,
            admission_deadline_ms: 1000,
        },
        provider_enrollment_ref: a.original_provider_enrollment_ref.clone(),
        complete_history_digest: h('6'),
        exclusion_checkpoint_digest: h('7'),
        native_review_digest: h('8'),
    };
    audit.admission.exact_request_digest = action_request_digest(
        &a.terms,
        &a.enrollment_ref,
        &a.witness_extension_digest,
        &audit.intent,
    )
    .unwrap();
    audit
}
// Modeled private predicate fixture, not an encrypted opener or native admission.
pub(in crate::manual_enrollment) fn modeled_store() -> Store {
    let mut s = Store::in_memory().unwrap();
    s.protection = StorageProtection::Encrypted;
    s.recovered_generation = true;
    s.recovered_binding = Some(GenerationBinding::new(&h('a'), &h('b')).unwrap());
    {
        let c = s.connection.lock().unwrap();
        c.execute_batch(include_str!("../recovery-schema.sql"))
            .unwrap();
        c.execute("UPDATE store_recovery SET recovery_required=1,restored_at_ms=1,source_snapshot_digest=?1",[h('f')]).unwrap();
        c.execute(
            "INSERT INTO records VALUES('settlement_generation_identity','local',0,?1,1,1)",
            [serde_json::to_string(&h('c')).unwrap()],
        )
        .unwrap();
    }
    s
}
fn append(
    s: &Store,
    a: &ManualEnrollmentAudit,
    prior: &[(ManualAccountIdentity, BTreeSet<String>)],
) -> Result<bool> {
    let mut c = s.connection.lock().unwrap();
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let result = append_enrollment(s, &tx, a, prior)?;
    tx.commit()?;
    Ok(result)
}
fn add_action(s: &Store, a: &ManualActionAudit) -> Result<bool> {
    let mut c = s.connection.lock().unwrap();
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let result = append_action(s, &tx, a)?;
    tx.commit()?;
    Ok(result)
}
pub(in crate::manual_enrollment) fn fence(s: &Store, kind: &str, id: &str) {
    s.connection
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO store_generation_fences VALUES(?1,?2,'synthetic')",
            params![kind, id],
        )
        .unwrap();
}
#[test]
fn modeled_audit_append_never_grants_financial_permission_or_bootstraps_account() {
    let s = modeled_store();
    let a = enrollment();
    let effect = action(&a);
    assert!(append(&s, &a, &[]).unwrap());
    assert!(!append(&s, &a, &[]).unwrap());
    assert!(add_action(&s, &effect).unwrap());
    assert!(!add_action(&s, &effect).unwrap());
    assert!(
        s.authority_account(&a.terms.identity.account_id)
            .unwrap()
            .is_none()
    );
    assert!(s.recovery_state().unwrap().recovery_required);
    assert!(matches!(
        s.require_ordinary_financial_lineage(
            "fresh-agreement",
            "fresh-obligation",
            "owner",
            None,
            &[]
        ),
        Err(StoreError::RecoveryRequired)
    ));
    assert!(matches!(
        s.retained_financial_input_exclusions(&a.terms.identity.account_id),
        Err(StoreError::RecoveryRequired)
    ));
    assert!(matches!(
        s.initialize_authority_account(&a.terms.identity.account_id, 1),
        Err(StoreError::RecoveryRequired)
    ));
}
#[test]
fn same_fvk_network_alias_or_missing_inherited_identity_rejects() {
    for mutation in 0..4 {
        let s = modeled_store();
        let mut a = enrollment();
        let old = ident('3', '4');
        fence(&s, "account", &old.account_id);
        let mut prior = vec![(old.clone(), aliases(&old))];
        match mutation {
            0 => {
                a.terms.identity.full_viewing_key_digest = old.full_viewing_key_digest.clone();
                a.terms.identity.network_profile_id = "renamed-network".into();
            }
            1 => {
                a.aliases.insert(old.account_id.clone());
            }
            2 => prior.clear(),
            _ => {
                a.terms.identity.account_id = old.account_id.clone();
                a.aliases = aliases(&old);
            }
        }
        rebind(&mut a);
        assert!(append(&s, &a, &prior).is_err());
        assert!(s.list_records(ENROLLMENT).unwrap().is_empty());
    }
    let s = modeled_store();
    let a = enrollment();
    let old = ident('3', '4');
    fence(&s, "account", &old.account_id);
    assert!(append(&s, &a, &[(old.clone(), aliases(&old))]).unwrap());
}
#[test]
fn immutable_generation_scope_chain_rejects_rebinding_and_keeps_prior_obligations() {
    let s = modeled_store();
    let a = enrollment();
    append(&s, &a, &[]).unwrap();
    let mut next = enrollment();
    next.terms.identity = ident('6', '7');
    next.aliases = aliases(&next.terms.identity);
    next.terms.operation_id = "next-enrollment".into();
    next.terms.scope.obligation_id = "next-obligation".into();
    next.terms.scope.agreement_id = "next-agreement".into();
    next.enrollment_ref = h('9');
    next.request_identity_digest = h('9');
    next.store_sequence = 2;
    next.terms.host.scope_predecessor_digest = Some(a.digest().unwrap());
    rebind(&mut next);
    let mut wrong = next.clone();
    wrong.terms.host.scope_predecessor_digest = Some(h('f'));
    rebind(&mut wrong);
    assert!(append(&s, &wrong, &[]).is_err());
    assert!(append(&s, &next, &[]).unwrap());
    let mut changed = a;
    changed.terms.scope.aggregate_budget_zatoshis = 101;
    rebind(&mut changed);
    assert!(append(&s, &changed, &[]).is_err());
    assert_eq!(s.list_records(ENROLLMENT).unwrap().len(), 2);
}
#[test]
fn historical_obligation_operation_idempotency_and_restored_scope_stay_denied() {
    for (kind, value) in [
        ("obligation", "fresh-obligation".into()),
        ("operation", "enroll-new".into()),
        ("effect", "enroll-new".into()),
        ("idempotency", h('5')),
    ] {
        let s = modeled_store();
        fence(&s, kind, &value);
        assert!(append(&s, &enrollment(), &[]).is_err());
        assert!(s.list_records(ENROLLMENT).unwrap().is_empty());
    }
    let s = modeled_store();
    let a = enrollment();
    append(&s, &a, &[]).unwrap();
    fence(
        &s,
        "record",
        &format!("{ENROLLMENT}:{}", a.digest().unwrap()),
    );
    assert!(add_action(&s, &action(&a)).is_err());
    assert!(append(&s, &a, &[]).is_err());
}
#[test]
fn retirement_mirror_union_blocks_same_key_and_preserves_audits() {
    let s = modeled_store();
    let a = enrollment();
    append(&s, &a, &[]).unwrap();
    let exclusion = ManualExclusionAudit {
        version: 1,
        operation_id: "retirement".into(),
        identity: a.terms.identity.clone(),
        aliases: a.aliases.clone(),
        account_use_genesis_digest: a.terms.account_use_genesis_digest.clone(),
        exclusion_digest: h('4'),
        witness_history_digest: h('5'),
    };
    {
        let mut c = s.connection.lock().unwrap();
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert!(append_exclusion(&tx, &exclusion).unwrap());
        tx.commit().unwrap();
    }
    assert!(add_action(&s, &action(&a)).is_err());
    let mut alias = a;
    alias.terms.operation_id = "alias-enrollment".into();
    alias.terms.identity.account_id = h('6');
    alias.aliases = aliases(&alias.terms.identity);
    rebind(&mut alias);
    assert!(append(&s, &alias, &[]).is_err());
    assert_eq!(s.list_records(EXCLUSION).unwrap().len(), 1);
    assert_eq!(s.list_records(ENROLLMENT).unwrap().len(), 1);
}
#[test]
fn generic_mutation_cannot_write_even_well_shaped_audit_namespace() {
    let s = Store::in_memory().unwrap();
    let a = enrollment();
    let context = CommandContext::for_request(
        "owner",
        "long-enough-idempotency-key",
        &serde_json::json!({}),
    )
    .unwrap();
    assert!(
        s.commit_record(
            &context,
            ENROLLMENT,
            &a.digest().unwrap(),
            None,
            serde_json::to_value(&a).unwrap(),
            "enrollment.created"
        )
        .is_err()
    );
    assert!(s.list_records(ENROLLMENT).unwrap().is_empty());
}
#[test]
fn snapshot_projection_retains_aliases_exclusions_and_exact_action() {
    let s = modeled_store();
    let mut a = enrollment();
    a.aliases.insert("disclosed-alias".into());
    append(&s, &a, &[]).unwrap();
    add_action(&s, &action(&a)).unwrap();
    let c = s.connection.lock().unwrap();
    let p = project_snapshot(&c, s.recovered_binding.as_ref().unwrap(), &h('c')).unwrap();
    assert_eq!(p.enrollments().len(), 1);
    assert!(p.enrollments()[0].aliases().contains("disclosed-alias"));
    assert_eq!(p.scope_audits().len(), 1);
    assert_eq!(p.generation_id(), h('a'));
    assert_eq!(p.inventory_digest(), h('b'));
    assert_eq!(p.store_destination_identity(), h('c'));
    assert_eq!(p.digest().len(), 64);
    assert!(p.exclusions().is_empty());
}
#[test]
fn audit_parser_rejects_unknown_fields_mutable_metadata_and_orphan_action() {
    let a = enrollment();
    let mut record = StoredRecord {
        id: a.digest().unwrap(),
        revision: 0,
        payload: serde_json::to_value(&a).unwrap(),
        created_at_ms: 1,
        updated_at_ms: 1,
    };
    validate_recovery_record(ENROLLMENT, &record).unwrap();
    record.revision = 1;
    assert!(validate_recovery_record(ENROLLMENT, &record).is_err());
    record.revision = 0;
    record.payload["verified"] = serde_json::json!(true);
    assert!(validate_recovery_record(ENROLLMENT, &record).is_err());
    let s = modeled_store();
    let effect = action(&a);
    {
        let c = s.connection.lock().unwrap();
        c.execute(
            "INSERT INTO records VALUES(?1,?2,0,?3,1,1)",
            params![
                SCOPE,
                effect.digest().unwrap(),
                serde_json::to_string(&effect).unwrap()
            ],
        )
        .unwrap();
        assert!(project_snapshot(&c, s.recovered_binding.as_ref().unwrap(), &h('c')).is_err());
    }
}
#[test]
fn target_projection_requires_recovered_classification_and_exact_destination() {
    assert!(Store::in_memory().unwrap().manual_store_target().is_err());
    let s = modeled_store();
    let target = s.manual_store_target().unwrap();
    target.check_current().unwrap();
    assert_eq!(target.generation_id(), h('a'));
    assert_eq!(target.inventory_digest(), h('b'));
    assert_eq!(target.store_destination_identity(), h('c'));
    let mut wrong = enrollment();
    wrong.terms.host.store_destination_identity = h('f');
    rebind(&mut wrong);
    assert!(append(&s, &wrong, &[]).is_err());
    assert!(s.list_records(ENROLLMENT).unwrap().is_empty());
}
#[test]
fn inherited_consumed_exposure_is_unchanged_by_new_audit() {
    let mut s = Store::in_memory().unwrap();
    s.protection = StorageProtection::Encrypted;
    let old = ident('3', '4');
    s.initialize_authority_account(&old.account_id, 1).unwrap();
    let intent = ReleaseIntent {
        authorization_id: "old-release".into(),
        account_id: old.account_id.clone(),
        writer_epoch: 1,
        obligation_id: "old-obligation".into(),
        proposal_id: "old-proposal".into(),
        manifest_digest: h('a'),
        effects_digest: h('b'),
        artifact_digest: h('c'),
        maximum_debit: "60".into(),
        input_ids: vec![h('d')],
        aggregate_budget_limit: "100".into(),
    };
    s.record_authorization_release_intent(&intent).unwrap();
    s.record_observed_resolution(
        "old-release",
        crate::authority::ExposureState::Consumed,
        "old-resolution",
    )
    .unwrap();
    s.recovered_generation = true;
    s.recovered_binding = Some(GenerationBinding::new(&h('a'), &h('b')).unwrap());
    {
        let c = s.connection.lock().unwrap();
        c.execute_batch(include_str!("../recovery-schema.sql"))
            .unwrap();
        c.execute("UPDATE store_recovery SET recovery_required=1,restored_at_ms=1,source_snapshot_digest=?1",[h('f')]).unwrap();
        c.execute("UPDATE authority_accounts SET recovery_required=1", [])
            .unwrap();
        c.execute(
            "INSERT INTO records VALUES('settlement_generation_identity','local',0,?1,1,1)",
            [serde_json::to_string(&h('c')).unwrap()],
        )
        .unwrap();
    }
    fence(&s, "account", &old.account_id);
    fence(&s, "obligation", "old-obligation");
    let before = s.account_exposures(&old.account_id).unwrap();
    append(&s, &enrollment(), &[(old.clone(), aliases(&old))]).unwrap();
    assert_eq!(s.account_exposures(&old.account_id).unwrap(), before);
    assert_eq!(s.settled_debit(&old.account_id).unwrap(), "60");
    assert!(
        s.authority_account(&old.account_id)
            .unwrap()
            .unwrap()
            .recovery_required
    );
}

#[test]
fn durable_action_audit_cannot_renew_deadline_or_replace_producer_commitment() {
    let store = modeled_store();
    let enrollment = enrollment();
    append(&store, &enrollment, &[]).unwrap();
    let original = action(&enrollment);
    add_action(&store, &original).unwrap();
    for mutation in 0..5 {
        let mut changed = original.clone();
        match mutation {
            0 => changed.admission.exact_request_digest = h('9'),
            1 => changed.admission.signer_intent_digest = h('9'),
            2 => changed.admission.witness_admission_digest = h('9'),
            3 => changed.admission.admitted_at_ms += 1,
            _ => changed.admission.admission_deadline_ms += 1,
        }
        assert!(add_action(&store, &changed).is_err());
    }
    assert_eq!(store.list_records(SCOPE).unwrap().len(), 1);
    assert!(!add_action(&store, &original).unwrap());
}
#[test]
fn generic_commands_and_effects_cannot_reuse_a_manual_audit_identity() {
    let store = modeled_store();
    let mut enrollment = enrollment();
    let context = CommandContext::for_request(
        "owner",
        "synthetic-stable-idempotency-key",
        &serde_json::json!({}),
    )
    .unwrap();
    enrollment.request_identity_digest = request_digest(&serde_json::json!([
        &context.principal_id,
        &context.idempotency_key
    ]))
    .unwrap();
    append(&store, &enrollment, &[]).unwrap();
    assert!(
        store
            .create_agreement(&context, "other-agreement", serde_json::json!({}))
            .is_err()
    );
    assert!(store.find_replay(&context).is_err());
    assert!(
        store
            .record_effect_intent(
                &enrollment.terms.operation_id,
                "synthetic-effect",
                "resource",
                &h('1'),
                "private-ref"
            )
            .is_err()
    );
    assert!(
        store
            .effect_intent(&enrollment.terms.operation_id)
            .unwrap()
            .is_none()
    );
}
#[test]
fn durable_enrollment_admission_preserves_original_times_and_commitments_on_retry() {
    let store = modeled_store();
    let original = enrollment();
    append(&store, &original, &[]).unwrap();
    for mutation in 0..5 {
        let mut changed = original.clone();
        match mutation {
            0 => changed.admission.exact_request_digest = h('9'),
            1 => changed.admission.signer_intent_digest = h('9'),
            2 => changed.admission.witness_admission_digest = h('9'),
            3 => changed.admission.admitted_at_ms += 1,
            _ => changed.admission.admission_deadline_ms += 1,
        }
        assert!(append(&store, &changed, &[]).is_err());
    }
    assert!(!append(&store, &original, &[]).unwrap());
    assert_eq!(store.list_records(ENROLLMENT).unwrap().len(), 1);
}
#[test]
fn exact_agreement_compare_rejects_revision_payload_and_obligation_drift() {
    let store = modeled_store();
    let audit = enrollment();
    let payload = serde_json::json!({"view":{"agreement":{"agreement_id":"fresh-agreement","obligation_id":"fresh-obligation"}}});
    let create = CommandContext::for_request("owner", "agreement-create-key", &payload).unwrap();
    let expected = store
        .create_agreement(&create, "fresh-agreement", payload.clone())
        .unwrap()
        .record;
    {
        let mut c = store.connection.lock().unwrap();
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        require_agreement_snapshot(&tx, &expected, &audit.terms).unwrap();
    }
    let target = store.manual_store_target().unwrap();
    assert_eq!(
        target.current_agreement_record("fresh-agreement").unwrap(),
        expected
    );
    let changed = serde_json::json!({"view":{"agreement":{"agreement_id":"fresh-agreement","obligation_id":"different-obligation"}}});
    let update = CommandContext::for_request("owner", "agreement-update-key", &changed).unwrap();
    store
        .update_agreement(
            &update,
            "fresh-agreement",
            expected.revision,
            changed,
            "agreement.updated",
        )
        .unwrap();
    let latest = store.get_agreement("fresh-agreement").unwrap().unwrap();
    {
        let mut c = store.connection.lock().unwrap();
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert!(matches!(
            require_agreement_snapshot(&tx, &expected, &audit.terms),
            Err(StoreError::RevisionConflict)
        ));
        assert!(matches!(
            require_agreement_snapshot(&tx, &latest, &audit.terms),
            Err(StoreError::RecoveryRequired)
        ));
    }
    assert!(store.list_records(ENROLLMENT).unwrap().is_empty());
    fence(&store, "record", "agreement:fresh-agreement");
    assert!(matches!(
        target.current_agreement_record("fresh-agreement"),
        Err(StoreError::RecoveryRequired)
    ));
}
#[test]
fn manual_target_recheck_denies_busy_store_instead_of_waiting_on_same_process() {
    let store = modeled_store();
    let target = store.manual_store_target().unwrap();
    let _busy = store.connection.lock().unwrap();
    assert!(matches!(
        target.check_current(),
        Err(StoreError::ResourceExhausted)
    ));
    assert!(matches!(
        target.current_agreement_record("fresh-agreement"),
        Err(StoreError::ResourceExhausted)
    ));
    assert!(matches!(
        store.manual_store_target(),
        Err(StoreError::ResourceExhausted)
    ));
}

#[path = "tests/layer_fixture.rs"]
mod layer_fixture;
pub(crate) use layer_fixture::append_modeled_layer_audits;

#[path = "tests/continuation.rs"]
mod continuation;

#[path = "tests/initial_publication.rs"]
pub(in crate::manual_enrollment) mod initial_publication;
pub(crate) use initial_publication::append_modeled_initial_layer_audits;
