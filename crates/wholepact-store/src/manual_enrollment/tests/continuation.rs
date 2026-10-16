//! Synthetic audit predicates only. No fixture mints a native decision, peer,
//! witness admission, lower lease, account authority or spending permission.
use super::*;

pub(super) fn fixture(original: &ManualEnrollmentAudit) -> ManualEnrollmentContinuationAudit {
    let request = ManualContinuationRequestV2 {
        version: 2,
        enrollment: ManualContinuationEnrollment {
            terms: original.terms.clone(),
        },
        continuation_digest: h('9'),
    };
    ManualEnrollmentContinuationAudit {
        version: 2,
        enrollment_audit_digest: original.digest().unwrap(),
        operation_id: "synthetic-continuation".into(),
        request_identity_digest: h('b'),
        provider_enrollment_ref: original.original_provider_enrollment_ref.clone(),
        store_sequence: 1,
        predecessor_digest: None,
        aliases: original.aliases.clone(),
        evidence: ManualContinuationEvidenceV2 {
            version: 2,
            enrollment_ref: original.enrollment_ref.clone(),
            witness_extension_digest: original.witness_extension_digest.clone(),
            witness_extension_sequence: original.witness_extension_sequence,
            witness_extension_predecessor_digest: original
                .witness_extension_predecessor_digest
                .clone(),
            admission: ManualContinuationAdmissionV2 {
                version: 2,
                exact_request_digest: request.digest().unwrap(),
                signer_intent_digest: original.admission.signer_intent_digest.clone(),
                witness_admission_digest: h('d'),
                attempt_digest: request.continuation_digest.clone(),
                attempt_sequence: 2,
                admitted_at_ms: 1001,
                admission_deadline_ms: 2000,
            },
            current: ManualContinuationCurrentAudit {
                writer_certificate_digest: original.terms.signer.writer_certificate_digest.clone(),
                writer_epoch: original.terms.signer.writer_epoch,
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
pub(super) fn add(store: &Store, audit: &ManualEnrollmentContinuationAudit) -> Result<bool> {
    let mut c = store.connection.lock().unwrap();
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let inserted = append_continuation(store, &tx, audit)?;
    tx.commit()?;
    Ok(inserted)
}
fn financial_rows(store: &Store) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
    let c = store.connection.lock().unwrap();
    [
        "authority_accounts",
        "authority_exposures",
        "authority_reservations",
        "authority_events",
        "operations",
        "idempotency",
        "effect_intents",
    ]
    .iter()
    .map(|table| {
        let mut q = c
            .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
            .unwrap();
        let count = q.column_count();
        q.query_map([], |row| (0..count).map(|i| row.get(i)).collect())
            .unwrap()
            .collect::<rusqlite::Result<Vec<Vec<_>>>>()
            .unwrap()
    })
    .collect()
}
fn next(old: &ManualEnrollmentContinuationAudit) -> ManualEnrollmentContinuationAudit {
    let mut a = old.clone();
    a.operation_id = "synthetic-continuation-next".into();
    a.request_identity_digest = h('d');
    a.store_sequence += 1;
    a.predecessor_digest = Some(old.digest().unwrap());
    a.evidence.request.continuation_digest = h('8');
    a.evidence.admission.attempt_digest = h('8');
    a.evidence.admission.exact_request_digest = a.evidence.request.digest().unwrap();
    a.evidence.admission.attempt_sequence = 4; // One unobserved remote attempt is not invented.
    a.evidence.admission.admitted_at_ms = 2001;
    a.evidence.admission.admission_deadline_ms = 3000;
    a.evidence.current.writer_session_digest = h('7');
    a.evidence.current.witness_head_sequence = 15;
    a
}

#[test]
fn continuation_requires_exact_original_and_never_creates_account_or_budget() {
    let store = modeled_store();
    let original = enrollment();
    let audit = fixture(&original);
    let before = financial_rows(&store);
    assert!(add(&store, &audit).is_err());
    assert!(store.list_records(ENROLLMENT).unwrap().is_empty());
    assert!(store.list_records(CONTINUATION).unwrap().is_empty());
    append(&store, &original, &[]).unwrap();
    assert!(add(&store, &audit).unwrap());
    assert!(!add(&store, &audit).unwrap());
    assert_eq!(before, financial_rows(&store));
    assert!(
        store
            .authority_account(&original.terms.identity.account_id)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .require_ordinary_financial_lineage(
                &original.terms.scope.agreement_id,
                &original.terms.scope.obligation_id,
                &original.terms.scope.principal_id,
                None,
                &[]
            )
            .is_err()
    );
    assert!(
        store
            .retained_financial_input_exclusions(&original.terms.identity.account_id)
            .is_err()
    );
    assert!(store.recovery_state().unwrap().recovery_required);
}
#[test]
fn continuation_original_admission_session_provider_and_attempt_are_immutable() {
    let store = modeled_store();
    let original = enrollment();
    append(&store, &original, &[]).unwrap();
    let audit = fixture(&original);
    add(&store, &audit).unwrap();
    let before = store.list_records(CONTINUATION).unwrap();
    for field in 0..15 {
        let mut a = audit.clone();
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
                a.aliases.insert("unreviewed-alias".into());
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
            _ => a.operation_id = "changed-operation".into(),
        }
        assert!(add(&store, &a).is_err(), "altered immutable field {field}");
    }
    assert_eq!(before, store.list_records(CONTINUATION).unwrap());
    let mut current = audit.evidence.clone();
    current.current.native_review_digest = h('6');
    current.current.complete_history_digest = h('5');
    current.require_exact_retry(&audit.evidence).unwrap();
    assert!(!add(&store, &audit).unwrap());
    assert_eq!(before, store.list_records(CONTINUATION).unwrap());
}
#[test]
fn continuation_chain_preserves_unobserved_attempts_and_denies_regression_or_renewal() {
    let store = modeled_store();
    let original = enrollment();
    append(&store, &original, &[]).unwrap();
    let first = fixture(&original);
    add(&store, &first).unwrap();
    let next = next(&first);
    for field in 0..6 {
        let mut wrong = next.clone();
        match field {
            0 => wrong.evidence.admission.attempt_sequence = 2,
            1 => wrong.evidence.admission.admitted_at_ms = 1999,
            2 => wrong.predecessor_digest = Some(h('6')),
            3 => wrong.store_sequence = 3,
            4 => {
                wrong.evidence.current.writer_session_digest =
                    first.evidence.current.writer_session_digest.clone()
            }
            _ => {
                wrong.evidence.current.witness_head_sequence =
                    first.evidence.current.witness_head_sequence
            }
        }
        assert!(add(&store, &wrong).is_err());
    }
    assert!(add(&store, &next).unwrap());
    assert!(!add(&store, &first).unwrap()); // Historical exact audit retry is inert.
    assert!(!add(&store, &next).unwrap());
    assert_eq!(store.list_records(CONTINUATION).unwrap().len(), 2);
}
#[test]
fn continuation_cross_purpose_keys_and_operations_cannot_be_reused() {
    let store = modeled_store();
    let original = enrollment();
    append(&store, &original, &[]).unwrap();
    let mut audit = fixture(&original);
    let context =
        CommandContext::for_request("owner", "continuation-key", &serde_json::json!({})).unwrap();
    audit.request_identity_digest = request_digest(&serde_json::json!([
        &context.principal_id,
        &context.idempotency_key
    ]))
    .unwrap();
    audit.operation_id = crate::operation_id(&context);
    add(&store, &audit).unwrap();
    assert!(
        store
            .create_agreement(&context, "unrelated", serde_json::json!({}))
            .is_err()
    );
    assert!(store.find_replay(&context).is_err());
    assert!(
        store
            .record_effect_intent(
                &audit.operation_id,
                "no-effect",
                "resource",
                &h('f'),
                "synthetic"
            )
            .is_err()
    );
    let mut action = action(&original);
    action.intent.idempotency_key_digest = audit.request_identity_digest.clone();
    action.admission.exact_request_digest = action_request_digest(
        &original.terms,
        &original.enrollment_ref,
        &original.witness_extension_digest,
        &action.intent,
    )
    .unwrap();
    assert!(add_action(&store, &action).is_err());
    let mut changed = next(&audit);
    changed.request_identity_digest = original.request_identity_digest.clone();
    assert!(add(&store, &changed).is_err());
    changed.request_identity_digest = h('1');
    changed.operation_id = original.terms.operation_id.clone();
    assert!(add(&store, &changed).is_err());
}
#[test]
fn continuation_projection_preserves_empty_v1_digest_and_rejects_orphans() {
    let store = modeled_store();
    let original = enrollment();
    append(&store, &original, &[]).unwrap();
    let binding = store.recovered_binding.as_ref().unwrap();
    {
        let c = store.connection.lock().unwrap();
        let e = read_audits::<ManualEnrollmentAudit>(&c, ENROLLMENT).unwrap();
        let expected = domain_digest(
            "wholepact:store-manual-audit-projection:v1",
            &(
                binding.generation_id(),
                binding.inventory_digest(),
                h('c'),
                e,
                Vec::<(String, ManualActionAudit)>::new(),
                Vec::<(String, ManualExclusionAudit)>::new(),
            ),
        )
        .unwrap();
        assert_eq!(
            project_snapshot(&c, binding, &h('c')).unwrap().digest(),
            expected
        );
    }
    let audit = fixture(&original);
    add(&store, &audit).unwrap();
    let mut c = store.connection.lock().unwrap();
    let projection = project_snapshot(&c, binding, &h('c')).unwrap();
    assert!(projection.continuations() == std::slice::from_ref(&audit));
    let before = projection.digest().to_owned();
    let tx = c
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    tx.execute("DELETE FROM records WHERE aggregate_type=?1", [ENROLLMENT])
        .unwrap();
    assert!(project_snapshot(&tx, binding, &h('c')).is_err());
    tx.rollback().unwrap();
    assert_eq!(
        project_snapshot(&c, binding, &h('c')).unwrap().digest(),
        before
    );
}
#[test]
fn continuation_strict_mirror_rejects_unknown_fields_original_window_and_exclusions() {
    let store = modeled_store();
    let original = enrollment();
    append(&store, &original, &[]).unwrap();
    let audit = fixture(&original);
    for path in [
        "",
        "/evidence",
        "/evidence/current",
        "/evidence/admission",
        "/evidence/request",
        "/evidence/request/enrollment",
    ] {
        let mut json = serde_json::to_value(&audit).unwrap();
        json.pointer_mut(path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("approved".into(), true.into());
        assert!(strict::<ManualEnrollmentContinuationAudit>(&json).is_err());
    }
    let mut wrong = audit.clone();
    wrong.evidence.admission.admitted_at_ms = 999;
    assert!(wrong.validate_for(&original).is_err());
    wrong = audit.clone();
    wrong.evidence.admission.admission_deadline_ms = 9001;
    assert!(wrong.validate().is_err());
    fence(&store, "account", &original.terms.identity.account_id);
    assert!(add(&store, &audit).is_err());
    assert!(store.list_records(CONTINUATION).unwrap().is_empty());
}
#[cfg(all(feature = "manual-admission", target_os = "linux"))]
#[test]
fn continuation_platform_independent_mirror_matches_real_wire_validation_and_digest() {
    let audit = fixture(&enrollment());
    let wire: wholepact_signer_origin::manual_continuation_v2::ManualEnrollmentContinuationEvidenceV2 =
        serde_json::from_value(serde_json::to_value(&audit.evidence).unwrap()).unwrap();
    wire.validate().unwrap();
    assert_eq!(
        wire.request.digest().unwrap(),
        audit.evidence.request.digest().unwrap()
    );
    assert!(serde_json::to_value(&wire).unwrap() == serde_json::to_value(&audit.evidence).unwrap());
}

#[test]
fn continuation_first_publication_requires_original_retained_signer_intent() {
    let store = modeled_store();
    let original = enrollment();
    append(&store, &original, &[]).unwrap();
    let exact = fixture(&original);
    let mut wrong = exact.clone();
    wrong.evidence.admission.signer_intent_digest = h('6');
    // Syntactically valid producer commitment is still the wrong original.
    wrong.validate().unwrap();
    assert!(wrong.validate_for(&original).is_err());
    let before = financial_rows(&store);
    assert!(add(&store, &wrong).is_err());
    assert!(store.list_records(CONTINUATION).unwrap().is_empty());
    assert_eq!(before, financial_rows(&store));
    assert!(add(&store, &exact).unwrap());
    assert!(!add(&store, &exact).unwrap());
}
