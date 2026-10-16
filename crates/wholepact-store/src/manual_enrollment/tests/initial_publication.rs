//! Honest private synthetic transaction data. These fixtures never construct a
//! native owner, signer peer, witness admission owner, lease, key or authority.
use super::*;

fn synthetic_terms() -> BornManualEnrollmentTerms {
    let identity = ident('1', '2');
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

pub(in crate::manual_enrollment) fn initial_fixture() -> ManualEnrollmentInitialPublicationV2 {
    let terms = synthetic_terms();
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
        aliases: aliases(&terms.identity),
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
fn rebind_initial(a: &mut ManualEnrollmentInitialPublicationV2) {
    a.evidence.admission.exact_request_digest = a.evidence.request.digest().unwrap();
}
pub(in crate::manual_enrollment) fn continuation_fixture(
    original: &ManualEnrollmentInitialPublicationV2,
) -> ManualEnrollmentContinuationAuditV3 {
    let mut evidence = original.evidence.clone();
    evidence.request.continuation_digest = h('8');
    evidence.admission.attempt_digest = h('8');
    evidence.admission.attempt_sequence = 4; // No invented observation for remote attempt 3.
    evidence.admission.exact_request_digest = evidence.request.digest().unwrap();
    evidence.admission.admitted_at_ms = 2001;
    evidence.admission.admission_deadline_ms = 3000;
    evidence.current.writer_session_digest = h('7');
    evidence.current.witness_head_sequence = 15;
    ManualEnrollmentContinuationAuditV3 {
        version: 3,
        original_audit: OriginalManualEnrollmentAuditLink::InitialPublicationV2 {
            audit_digest: original.digest().unwrap(),
        },
        operation_id: "synthetic-continuation-v3".into(),
        request_identity_digest: h('d'),
        provider_enrollment_ref: original.provider_enrollment_ref.clone(),
        store_sequence: 1,
        predecessor_digest: None,
        aliases: original.aliases.clone(),
        evidence,
    }
}
pub(in crate::manual_enrollment) fn add_initial(
    store: &Store,
    audit: &ManualEnrollmentInitialPublicationV2,
    known: &[(ManualAccountIdentity, BTreeSet<String>)],
) -> Result<bool> {
    let mut c = store.connection.lock().unwrap();
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let inserted = append_initial_publication_v2(store, &tx, audit, known)?;
    tx.commit()?;
    Ok(inserted)
}
pub(in crate::manual_enrollment) fn add_continuation(
    store: &Store,
    audit: &ManualEnrollmentContinuationAuditV3,
    known: &[(ManualAccountIdentity, BTreeSet<String>)],
) -> Result<bool> {
    let mut c = store.connection.lock().unwrap();
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let inserted = append_continuation_v3(store, &tx, audit, known)?;
    tx.commit()?;
    Ok(inserted)
}

#[test]
fn initial_v2_without_v1_publishes_once_and_v3_retains_explicit_original_link() {
    let store = modeled_store();
    let initial = initial_fixture();
    let next = continuation_fixture(&initial);
    assert!(add_continuation(&store, &next, &[]).is_err());
    assert!(add_initial(&store, &initial, &[]).unwrap());
    assert!(!add_initial(&store, &initial, &[]).unwrap());
    assert!(store.list_records(ENROLLMENT).unwrap().is_empty());
    assert!(store.list_records(CONTINUATION).unwrap().is_empty());
    assert!(add_continuation(&store, &next, &[]).unwrap());
    assert!(!add_continuation(&store, &next, &[]).unwrap());
    assert!(
        store
            .authority_account(&initial.terms().identity.account_id)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .require_ordinary_financial_lineage(
                &initial.terms().scope.agreement_id,
                &initial.terms().scope.obligation_id,
                &initial.terms().scope.principal_id,
                None,
                &[]
            )
            .is_err()
    );
    assert!(
        store
            .retained_financial_input_exclusions(&initial.terms().identity.account_id)
            .is_err()
    );
    assert!(store.recovery_state().unwrap().recovery_required);
    for table in [
        "authority_accounts",
        "authority_exposures",
        "authority_reservations",
        "authority_events",
        "operations",
        "idempotency",
        "effect_intents",
    ] {
        let count: u64 = store
            .connection
            .lock()
            .unwrap()
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0, "audit retention must not create {table}");
    }
    let c = store.connection.lock().unwrap();
    let projection =
        project_snapshot(&c, store.recovered_binding.as_ref().unwrap(), &h('c')).unwrap();
    assert!(projection.v1_enrollments().is_empty());
    assert_eq!(projection.enrollments().len(), 1);
    assert!(matches!(
        projection.enrollments()[0].initial_admission(),
        ManualInitialAdmissionProvenance::ContinuationV2(_)
    ));
    assert!(projection.enrollments()[0].terms() == initial.terms());
    assert!(projection.enrollments()[0].aliases() == &initial.aliases);
    assert!(projection.enrollments()[0].original_audit_link().unwrap() == next.original_audit);
    assert!(projection.initial_publications_v2() == std::slice::from_ref(&initial));
    assert!(projection.continuations_v3() == std::slice::from_ref(&next));
}

#[test]
fn initial_v2_retry_cannot_change_attempt_deadline_provider_generation_or_original_terms() {
    let store = modeled_store();
    let initial = initial_fixture();
    add_initial(&store, &initial, &[]).unwrap();
    let before = store.list_records(INITIAL_PUBLICATION_V2).unwrap();
    for field in 0..19 {
        let mut a = initial.clone();
        match field {
            0 => a.evidence.current.writer_session_digest = h('6'),
            1 => a.evidence.current.writer_session_expires_at_ms += 1,
            2 => a.evidence.admission.admitted_at_ms += 1,
            3 => a.evidence.admission.admission_deadline_ms += 1,
            4 => a.evidence.admission.witness_admission_digest = h('6'),
            5 => a.evidence.admission.signer_intent_digest = h('6'),
            6 => a.evidence.admission.attempt_sequence += 1,
            7 => a.evidence.admission.attempt_digest = h('6'),
            8 => a.provider_enrollment_ref = h('6'),
            9 => {
                a.aliases.insert("unknown-alias".into());
            }
            10 => {
                a.evidence
                    .request
                    .enrollment
                    .terms
                    .scope
                    .aggregate_budget_zatoshis += 1
            }
            11 => a.evidence.current.writer_epoch += 1,
            12 => a.evidence.current.writer_certificate_digest = h('6'),
            13 => a.request_identity_digest = h('6'),
            14 => a.operation_id = "changed-operation".into(),
            15 => a.evidence.request.enrollment.terms.host.generation_id = h('6'),
            16 => {
                a.evidence
                    .request
                    .enrollment
                    .terms
                    .host
                    .financial_journal_origin_digest = h('6')
            }
            17 => a.evidence.request.enrollment.terms.birth_commit_digest = h('6'),
            _ => a.evidence.enrollment_ref = h('6'),
        }
        assert!(
            a.require_exact_retry(&initial).is_err(),
            "altered immutable field {field}"
        );
        assert!(
            add_initial(&store, &a, &[]).is_err(),
            "altered immutable field {field}"
        );
    }
    let mut observed = initial.clone();
    observed.evidence.current.native_review_digest = h('6');
    observed.evidence.current.complete_history_digest = h('5');
    observed.require_exact_retry(&initial).unwrap();
    assert!(add_initial(&store, &observed, &[]).is_err()); // Production retains original instead.
    assert_eq!(store.list_records(INITIAL_PUBLICATION_V2).unwrap(), before);
}

#[test]
fn initial_v2_and_v3_strict_formats_reject_downgrade_unknown_fields_and_wrong_tags() {
    let a = initial_fixture();
    let b = continuation_fixture(&a);
    let initial = serde_json::to_value(&a).unwrap();
    assert!(strict::<ManualEnrollmentAudit>(&initial).is_err());
    assert!(strict::<ManualEnrollmentContinuationAudit>(&initial).is_err());
    assert!(
        strict::<ManualEnrollmentInitialPublicationV2>(
            &serde_json::to_value(enrollment()).unwrap()
        )
        .is_err()
    );
    assert!(
        strict::<ManualEnrollmentContinuationAudit>(&serde_json::to_value(&b).unwrap()).is_err()
    );
    for path in [
        "",
        "/evidence",
        "/evidence/current",
        "/evidence/admission",
        "/evidence/request",
        "/evidence/request/enrollment",
    ] {
        let mut changed = initial.clone();
        changed
            .pointer_mut(path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("approved".into(), true.into());
        assert!(strict::<ManualEnrollmentInitialPublicationV2>(&changed).is_err());
    }
    let mut wrong = b.clone();
    wrong.original_audit = OriginalManualEnrollmentAuditLink::EnrollmentV1 {
        audit_digest: a.digest().unwrap(),
    };
    assert!(wrong.validate().is_err());
    let mut changed = serde_json::to_value(&b).unwrap();
    changed["original_audit"]["approved"] = true.into();
    assert!(strict::<ManualEnrollmentContinuationAuditV3>(&changed).is_err());
    let mut wrong = a.clone();
    wrong.version = 1;
    assert!(wrong.validate().is_err());
    wrong = a.clone();
    wrong.store_sequence = 2;
    assert!(wrong.validate().is_err());
    wrong = a.clone();
    wrong.evidence.admission.admission_deadline_ms = 9001;
    assert!(wrong.validate().is_err());
    wrong = a.clone();
    wrong
        .evidence
        .request
        .enrollment
        .terms
        .host
        .scope_predecessor_digest = Some(h('6'));
    assert!(wrong.validate().is_err());
    for kind in [ENROLLMENT, CONTINUATION, CONTINUATION_V3] {
        let record = StoredRecord {
            id: a.digest().unwrap(),
            revision: 0,
            payload: initial.clone(),
            created_at_ms: 1,
            updated_at_ms: 1,
        };
        assert!(validate_recovery_record(kind, &record).is_err());
    }
}

#[test]
fn initial_v2_existing_v1_and_changed_generation_scope_deny_in_both_orders() {
    let store = modeled_store();
    let initial = initial_fixture();
    append(&store, &enrollment(), &[]).unwrap();
    assert!(add_initial(&store, &initial, &[]).is_err());
    let other = modeled_store();
    add_initial(&other, &initial, &[]).unwrap();
    assert!(append(&other, &enrollment(), &[]).is_err());
    let mut distinct = initial.clone();
    distinct.evidence.request.enrollment.terms.identity = ident('3', '4');
    distinct.evidence.request.enrollment.terms.operation_id = "other-enrollment".into();
    distinct.evidence.enrollment_ref = h('6');
    distinct.operation_id = "other-initial-v2".into();
    distinct.request_identity_digest = h('6');
    distinct.aliases = aliases(&distinct.terms().identity);
    rebind_initial(&mut distinct);
    assert!(add_initial(&other, &distinct, &[]).is_err());
    assert_eq!(other.list_records(INITIAL_PUBLICATION_V2).unwrap().len(), 1);
}

#[test]
fn initial_v2_unknown_inherited_identity_alias_retirement_and_fences_deny() {
    let initial = initial_fixture();
    let old = ident('3', '4');
    let store = modeled_store();
    fence(&store, "account", "legacy-alias");
    assert!(add_initial(&store, &initial, &[]).is_err());
    let mut old_aliases = aliases(&old);
    old_aliases.insert("legacy-alias".into());
    assert!(add_initial(&store, &initial, &[(old.clone(), old_aliases.clone())]).unwrap());
    let next = continuation_fixture(&initial);
    assert!(add_continuation(&store, &next, &[]).is_err());
    assert!(add_continuation(&store, &next, &[(old, old_aliases)]).unwrap());
    for kind in [
        "operation",
        "effect",
        "idempotency",
        "agreement",
        "obligation",
        "record",
    ] {
        let store = modeled_store();
        let id = match kind {
            "operation" | "effect" => initial.operation_id.clone(),
            "idempotency" => initial.request_identity_digest.clone(),
            "agreement" => initial.terms().scope.agreement_id.clone(),
            "obligation" => initial.terms().scope.obligation_id.clone(),
            _ => format!("{INITIAL_PUBLICATION_V2}:{}", initial.digest().unwrap()),
        };
        fence(&store, kind, &id);
        assert!(add_initial(&store, &initial, &[]).is_err());
    }
    let store = modeled_store();
    let exclusion = ManualExclusionAudit {
        version: 1,
        operation_id: "retire-original".into(),
        identity: initial.terms().identity.clone(),
        aliases: initial.aliases.clone(),
        account_use_genesis_digest: initial.terms().account_use_genesis_digest.clone(),
        exclusion_digest: h('6'),
        witness_history_digest: h('7'),
    };
    {
        let mut c = store.connection.lock().unwrap();
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        append_exclusion(&tx, &exclusion).unwrap();
        tx.commit().unwrap();
    }
    assert!(add_initial(&store, &initial, &[]).is_err());
}

#[test]
fn initial_v2_conflicting_first_publication_race_has_one_immutable_winner() {
    use std::sync::{Arc, Barrier};
    let store = Arc::new(modeled_store());
    let first = initial_fixture();
    let mut second = first.clone();
    second.operation_id = "racing-second-publication".into();
    second.request_identity_digest = h('6');
    second.evidence.request.continuation_digest = h('5');
    second.evidence.admission.attempt_digest = h('5');
    second.evidence.admission.attempt_sequence = 3;
    rebind_initial(&mut second);
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = [first.clone(), second.clone()]
        .into_iter()
        .map(|a| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                add_initial(&store, &a, &[])
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|x| matches!(x, Ok(true))).count(), 1);
    assert_eq!(results.iter().filter(|x| x.is_err()).count(), 1);
    let rows = store.list_records(INITIAL_PUBLICATION_V2).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0].payload == serde_json::to_value(&first).unwrap()
            || rows[0].payload == serde_json::to_value(&second).unwrap()
    );
}

#[test]
fn initial_v2_and_v3_reserve_generic_operations_keys_and_original_operation() {
    let store = modeled_store();
    let mut initial = initial_fixture();
    let context =
        CommandContext::for_request("owner", "initial-v2-key", &serde_json::json!({})).unwrap();
    initial.operation_id = crate::operation_id(&context);
    initial.request_identity_digest = request_digest(&serde_json::json!([
        &context.principal_id,
        &context.idempotency_key
    ]))
    .unwrap();
    add_initial(&store, &initial, &[]).unwrap();
    assert!(store.find_replay(&context).is_err());
    assert!(
        store
            .create_agreement(&context, "unrelated", serde_json::json!({}))
            .is_err()
    );
    for op in [&initial.operation_id, &initial.terms().operation_id] {
        assert!(
            store
                .record_effect_intent(op, "none", "resource", &h('f'), "synthetic")
                .is_err()
        );
    }
    let mut next = continuation_fixture(&initial);
    next.request_identity_digest = initial.request_identity_digest.clone();
    assert!(add_continuation(&store, &next, &[]).is_err());
    next = continuation_fixture(&initial);
    next.operation_id = initial.terms().operation_id.clone();
    assert!(add_continuation(&store, &next, &[]).is_err());
    let context =
        CommandContext::for_request("owner", "continuation-v3-key", &serde_json::json!({}))
            .unwrap();
    next = continuation_fixture(&initial);
    next.operation_id = crate::operation_id(&context);
    next.request_identity_digest = request_digest(&serde_json::json!([
        &context.principal_id,
        &context.idempotency_key
    ]))
    .unwrap();
    add_continuation(&store, &next, &[]).unwrap();
    assert!(store.find_replay(&context).is_err());
    assert!(
        store
            .record_effect_intent(&next.operation_id, "none", "resource", &h('f'), "synthetic")
            .is_err()
    );
}

#[test]
fn v3_link_chain_original_session_and_admission_do_not_renew_or_regress() {
    let store = modeled_store();
    let initial = initial_fixture();
    add_initial(&store, &initial, &[]).unwrap();
    let next = continuation_fixture(&initial);
    for field in 0..9 {
        let mut a = next.clone();
        match field {
            0 => {
                a.evidence.admission.attempt_sequence = initial.evidence.admission.attempt_sequence
            }
            1 => a.evidence.admission.admitted_at_ms = 1999,
            2 => {
                a.evidence.current.writer_session_digest =
                    initial.evidence.current.writer_session_digest.clone()
            }
            3 => {
                a.evidence.current.witness_head_sequence =
                    initial.evidence.current.witness_head_sequence
            }
            4 => a.evidence.admission.signer_intent_digest = h('6'),
            5 => a.provider_enrollment_ref = h('6'),
            6 => {
                a.original_audit = OriginalManualEnrollmentAuditLink::InitialPublicationV2 {
                    audit_digest: h('6'),
                }
            }
            7 => a.predecessor_digest = Some(h('6')),
            _ => a.store_sequence = 2,
        }
        assert!(
            add_continuation(&store, &a, &[]).is_err(),
            "changed V3 field {field}"
        );
    }
    add_continuation(&store, &next, &[]).unwrap();
    let mut later = next.clone();
    later.operation_id = "later-v3".into();
    later.request_identity_digest = h('6');
    later.store_sequence = 2;
    later.predecessor_digest = Some(next.digest().unwrap());
    later.evidence.request.continuation_digest = h('5');
    later.evidence.admission.attempt_digest = h('5');
    later.evidence.admission.exact_request_digest = later.evidence.request.digest().unwrap();
    later.evidence.admission.attempt_sequence = 5;
    later.evidence.admission.admitted_at_ms = 3001;
    later.evidence.admission.admission_deadline_ms = 4000;
    later.evidence.current.witness_head_sequence = 18;
    assert!(add_continuation(&store, &later, &[]).is_err()); // Same session cannot become a new attempt.
    later.evidence.current.writer_session_digest = h('4');
    assert!(add_continuation(&store, &later, &[]).unwrap());
    let mut c = store.connection.lock().unwrap();
    let tx = c
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    tx.execute(
        "DELETE FROM records WHERE aggregate_type=?1",
        [INITIAL_PUBLICATION_V2],
    )
    .unwrap();
    assert!(project_snapshot(&tx, store.recovered_binding.as_ref().unwrap(), &h('c')).is_err());
    tx.rollback().unwrap();
}

/// Encrypted layer fixture uses only private modeled predicates. The root
/// synthetic-account identity is explicitly known in this fixture, never an
/// assertion accepted by the production lease consumer.
pub(crate) fn append_modeled_initial_layer_audits(
    store: &Store,
    index: u8,
) -> (
    ManualEnrollmentInitialPublicationV2,
    ManualEnrollmentContinuationAuditV3,
    ManualExclusionAudit,
) {
    assert!((1..=2).contains(&index));
    assert_eq!(store.protection, StorageProtection::Encrypted);
    let binding = store.recovered_binding.as_ref().unwrap();
    let hash = |kind: &str| {
        request_digest(&serde_json::json!(["synthetic-initial-layer", kind, index])).unwrap()
    };
    let mut a = initial_fixture();
    {
        let terms = &mut a.evidence.request.enrollment.terms;
        terms.identity = if index == 1 {
            ident('1', '2')
        } else {
            ident('3', '4')
        };
        terms.operation_id = format!("synthetic-original-enrollment-v2-{index}");
        terms.scope.agreement_id = format!("synthetic-initial-agreement-{index}");
        terms.scope.obligation_id = format!("synthetic-initial-obligation-{index}");
        terms.host.generation_id = binding.generation_id().into();
        terms.host.inventory_digest = binding.inventory_digest().into();
        terms.host.store_destination_identity = store
            .manual_store_target()
            .unwrap()
            .store_destination_identity()
            .into();
        terms.account_use_genesis_digest = hash("genesis");
    }
    a.aliases = aliases(&a.terms().identity);
    a.operation_id = format!("synthetic-initial-publication-{index}");
    a.request_identity_digest = hash("initial-key");
    a.evidence.enrollment_ref = hash("enrollment-reference");
    a.evidence.witness_extension_digest = hash("extension");
    a.evidence.request.continuation_digest = hash("initial-attempt");
    a.evidence.admission.attempt_digest = a.evidence.request.continuation_digest.clone();
    rebind_initial(&mut a);
    let create = CommandContext::for_request(
        "owner",
        format!("synthetic-initial-create-{index}"),
        &serde_json::json!(["synthetic-initial-create", index]),
    )
    .unwrap();
    store.create_agreement(&create, &a.terms().scope.agreement_id, serde_json::json!({"view":{"agreement":{
        "agreement_id": a.terms().scope.agreement_id, "obligation_id": a.terms().scope.obligation_id,
    }}})).unwrap();
    let old_identity = ident('8', '9');
    let mut old_aliases = aliases(&old_identity);
    old_aliases.insert("synthetic-account".into());
    let mut inherited = vec![(old_identity, old_aliases)];
    {
        let c = store.connection.lock().unwrap();
        inherited.extend(
            read_audits::<ManualEnrollmentAudit>(&c, ENROLLMENT)
                .unwrap()
                .into_iter()
                .map(|(_, old)| (old.terms.identity, old.aliases)),
        );
        inherited.extend(
            read_audits::<ManualEnrollmentInitialPublicationV2>(&c, INITIAL_PUBLICATION_V2)
                .unwrap()
                .into_iter()
                .map(|(_, old)| (old.terms().identity.clone(), old.aliases)),
        );
    }
    assert!(add_initial(store, &a, &inherited).unwrap());
    let mut next = continuation_fixture(&a);
    next.operation_id = format!("synthetic-following-continuation-{index}");
    next.request_identity_digest = hash("continuation-key");
    next.evidence.request.continuation_digest = hash("continuation-attempt");
    next.evidence.admission.attempt_digest = next.evidence.request.continuation_digest.clone();
    next.evidence.admission.exact_request_digest = next.evidence.request.digest().unwrap();
    assert!(add_continuation(store, &next, &inherited).unwrap());
    let exclusion = ManualExclusionAudit {
        version: 1,
        operation_id: format!("synthetic-initial-exclusion-{index}"),
        identity: a.terms().identity.clone(),
        aliases: a.aliases.clone(),
        account_use_genesis_digest: a.terms().account_use_genesis_digest.clone(),
        exclusion_digest: hash("exclusion"),
        witness_history_digest: hash("exclusion-history"),
    };
    let mut c = store.connection.lock().unwrap();
    let tx = c
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    assert!(append_exclusion(&tx, &exclusion).unwrap());
    tx.commit().unwrap();
    (a, next, exclusion)
}

#[test]
fn v2_initial_absence_preserves_existing_continuation_projection_digest_exactly() {
    let store = modeled_store();
    let old = enrollment();
    append(&store, &old, &[]).unwrap();
    let continuation = super::continuation::fixture(&old);
    super::continuation::add(&store, &continuation).unwrap();
    let c = store.connection.lock().unwrap();
    let binding = store.recovered_binding.as_ref().unwrap();
    let expected = domain_digest(
        "wholepact:store-manual-audit-projection:v2",
        &(
            binding.generation_id(),
            binding.inventory_digest(),
            h('c'),
            read_audits::<ManualEnrollmentAudit>(&c, ENROLLMENT).unwrap(),
            Vec::<(String, ManualActionAudit)>::new(),
            Vec::<(String, ManualExclusionAudit)>::new(),
            read_audits::<ManualEnrollmentContinuationAudit>(&c, CONTINUATION).unwrap(),
        ),
    )
    .unwrap();
    let projection = project_snapshot(&c, binding, &h('c')).unwrap();
    assert_eq!(projection.digest(), expected);
    assert!(matches!(
        projection.enrollments()[0].initial_admission(),
        ManualInitialAdmissionProvenance::EnrollmentV1(_)
    ));
    assert!(projection.initial_publications_v2().is_empty());
    assert!(projection.continuations_v3().is_empty());
}

#[test]
fn initial_v2_exact_target_binding_and_full_agreement_cas_are_required() {
    let original = initial_fixture();
    for field in 0..3 {
        let store = modeled_store();
        let mut changed = original.clone();
        let host = &mut changed.evidence.request.enrollment.terms.host;
        match field {
            0 => host.generation_id = h('6'),
            1 => host.inventory_digest = h('6'),
            _ => host.store_destination_identity = h('6'),
        }
        rebind_initial(&mut changed);
        changed.validate().unwrap();
        assert!(add_initial(&store, &changed, &[]).is_err());
    }
    let store = modeled_store();
    let payload = serde_json::json!({"owner_client_id":"owner", "view":{"agreement":{
        "agreement_id":original.terms().scope.agreement_id,
        "obligation_id":original.terms().scope.obligation_id,
        "reviewed_field":"original",
    }}});
    let context =
        CommandContext::for_request("owner", "initial-agreement-create", &payload).unwrap();
    let expected = store
        .create_agreement(
            &context,
            &original.terms().scope.agreement_id,
            payload.clone(),
        )
        .unwrap()
        .record;
    {
        let c = store.connection.lock().unwrap();
        require_agreement_snapshot(&c, &expected, original.terms()).unwrap();
    }
    let mut changed = expected.clone();
    changed.payload["owner_client_id"] = "different".into();
    {
        let c = store.connection.lock().unwrap();
        assert!(matches!(
            require_agreement_snapshot(&c, &changed, original.terms()),
            Err(StoreError::RevisionConflict)
        ));
        let mut changed = expected.clone();
        changed.payload["view"]["agreement"]["reviewed_field"] = "changed".into();
        assert!(matches!(
            require_agreement_snapshot(&c, &changed, original.terms()),
            Err(StoreError::RevisionConflict)
        ));
    }
    assert!(
        store
            .list_records(INITIAL_PUBLICATION_V2)
            .unwrap()
            .is_empty()
    );
}

#[cfg(all(feature = "manual-admission", target_os = "linux"))]
#[test]
fn original_audit_selector_is_explicit_and_missing_original_never_enters_continuation() {
    let initial = initial_fixture();
    let store = modeled_store();
    let create =
        CommandContext::for_request("owner", "selector-agreement-create", &serde_json::json!({}))
            .unwrap();
    let agreement = store.create_agreement(&create, &initial.terms().scope.agreement_id, serde_json::json!({"view":{"agreement":{
        "agreement_id":initial.terms().scope.agreement_id,"obligation_id":initial.terms().scope.obligation_id,
    }}})).unwrap().record;
    let target = store.manual_store_target().unwrap();
    let e = &initial.evidence;
    assert!(
        store
            .manual_enrollment_original_audit_link(
                &target,
                &agreement,
                initial.terms(),
                &e.enrollment_ref,
                &e.witness_extension_digest
            )
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .require_manual_enrollment_continuation_original(
                &target,
                &agreement,
                initial.terms(),
                &e.enrollment_ref,
                &e.witness_extension_digest
            )
            .is_err()
    );
    assert!(
        store
            .require_manual_enrollment_continuation_original_v2(
                &target,
                &agreement,
                initial.terms(),
                &e.enrollment_ref,
                &e.witness_extension_digest
            )
            .is_err()
    );
    add_initial(&store, &initial, &[]).unwrap();
    assert!(
        store
            .manual_enrollment_original_audit_link(
                &target,
                &agreement,
                initial.terms(),
                &e.enrollment_ref,
                &e.witness_extension_digest
            )
            .unwrap()
            == Some(OriginalManualEnrollmentAuditLink::InitialPublicationV2 {
                audit_digest: initial.digest().unwrap()
            })
    );
    assert!(
        store
            .require_manual_enrollment_continuation_original(
                &target,
                &agreement,
                initial.terms(),
                &e.enrollment_ref,
                &e.witness_extension_digest
            )
            .is_err()
    );
    store
        .require_manual_enrollment_continuation_original_v2(
            &target,
            &agreement,
            initial.terms(),
            &e.enrollment_ref,
            &e.witness_extension_digest,
        )
        .unwrap();
    let legacy = modeled_store();
    let agreement = legacy
        .create_agreement(
            &create,
            &initial.terms().scope.agreement_id,
            agreement.payload,
        )
        .unwrap()
        .record;
    let target = legacy.manual_store_target().unwrap();
    let original = enrollment();
    append(&legacy, &original, &[]).unwrap();
    assert!(
        legacy
            .manual_enrollment_original_audit_link(
                &target,
                &agreement,
                &original.terms,
                &original.enrollment_ref,
                &original.witness_extension_digest
            )
            .unwrap()
            == Some(OriginalManualEnrollmentAuditLink::EnrollmentV1 {
                audit_digest: original.digest().unwrap()
            })
    );
    assert!(
        legacy
            .require_manual_enrollment_initial_publication_v2(
                &target,
                &agreement,
                &original.terms,
                &original.enrollment_ref,
                &original.witness_extension_digest
            )
            .is_err()
    );
}
