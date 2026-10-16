//! Synthetic encrypted retention of a genuine V2 initial Host publication.
//! These tests use only the private modeled kernel from the adjacent fixture;
//! retained metadata never constructs a native owner, live lease or settlement.
use super::*;
use crate::manual_enrollment::{
    CONTINUATION_V3, INITIAL_PUBLICATION_V2, ManualEnrollmentContinuationAuditV3,
    ManualEnrollmentInitialPublicationV2, ManualInitialAdmissionProvenance,
    OriginalManualEnrollmentAuditLink, append_modeled_initial_layer_audits,
};

type InitialLayerAudits = (
    ManualEnrollmentInitialPublicationV2,
    ManualEnrollmentContinuationAuditV3,
    ManualExclusionAudit,
);

fn assert_initial_retained(store: &Store, expected: &[InitialLayerAudits]) {
    let c = store.connection.lock().unwrap();
    let generation = store.recovered_binding.as_ref().unwrap();
    let projection = crate::recovery::project_manual_snapshot(&c, generation).unwrap();
    assert_eq!(projection.enrollments().len(), expected.len());
    assert_eq!(projection.initial_publications_v2().len(), expected.len());
    assert_eq!(projection.continuations_v3().len(), expected.len());
    assert_eq!(projection.exclusions().len(), expected.len());
    // The common projection must not manufacture a legacy original or action.
    assert!(projection.v1_enrollments().is_empty());
    assert!(projection.continuations().is_empty());
    assert!(projection.scope_audits().is_empty());
    for (initial, continuation, exclusion) in expected {
        assert!(projection.initial_publications_v2().contains(initial));
        assert!(projection.continuations_v3().contains(continuation));
        assert!(projection.exclusions().contains(exclusion));
        initial.validate().unwrap();
        continuation.validate_for(initial).unwrap();
        assert_eq!(initial.version, 2);
        assert_eq!(initial.evidence.admission.version, 2);
        assert!(initial.evidence.admission.attempt_sequence >= 2);
        assert_eq!(continuation.version, 3);
        assert!(
            continuation.evidence.admission.attempt_sequence
                > initial.evidence.admission.attempt_sequence
        );
        assert!(
            continuation.evidence.admission.admitted_at_ms
                >= initial.evidence.admission.admission_deadline_ms
        );
        assert!(
            continuation.original_audit
                == OriginalManualEnrollmentAuditLink::InitialPublicationV2 {
                    audit_digest: initial.digest().unwrap(),
                }
        );

        let common = projection.enrollments();
        let retained = common
            .iter()
            .find(|audit| audit.digest().unwrap() == initial.digest().unwrap())
            .unwrap();
        retained.validate().unwrap();
        assert!(retained.terms() == initial.terms());
        assert!(retained.aliases() == &initial.aliases);
        match retained.initial_admission() {
            ManualInitialAdmissionProvenance::ContinuationV2(evidence) => {
                assert!(evidence == &initial.evidence);
            }
            ManualInitialAdmissionProvenance::EnrollmentV1(_)
            | ManualInitialAdmissionProvenance::RosterV2(_) => {
                panic!("a retained V2 initial publication must not synthesize a V1 admission");
            }
        }
        for (kind, digest) in [
            (INITIAL_PUBLICATION_V2, initial.digest().unwrap()),
            (CONTINUATION_V3, continuation.digest().unwrap()),
            (
                crate::manual_enrollment::EXCLUSION,
                exclusion.digest().unwrap(),
            ),
        ] {
            require_fence(&c, "record", &format!("{kind}:{digest}")).unwrap();
        }
        for operation in [
            &initial.terms().operation_id,
            &initial.operation_id,
            &continuation.operation_id,
        ] {
            require_fence(&c, "operation", operation).unwrap();
        }
        for request in [
            &initial.request_identity_digest,
            &continuation.request_identity_digest,
        ] {
            require_fence(&c, "idempotency", request).unwrap();
        }
        for alias in &initial.aliases {
            require_fence(&c, "account", alias).unwrap();
        }
        require_fence(&c, "account", &initial.terms().identity.account_id).unwrap();
        require_fence(&c, "agreement", &initial.terms().scope.agreement_id).unwrap();
        require_fence(&c, "obligation", &initial.terms().scope.obligation_id).unwrap();
    }
}

#[test]
fn encrypted_v2_initial_and_v3_follow_on_survive_two_modeled_successor_layers() {
    let temporary = tempfile::tempdir().unwrap();
    let one = root_encrypted(&temporary.path().join("g1"));
    let first = append_modeled_initial_layer_audits(&one.store, 1);
    assert_eq!(first.0.evidence.admission.attempt_sequence, 2);
    assert_eq!(first.0.evidence.admission.admitted_at_ms, 1001);
    assert_eq!(first.0.evidence.admission.admission_deadline_ms, 2000);
    assert_eq!(first.1.evidence.admission.attempt_sequence, 4);
    assert_eq!(first.1.evidence.admission.admitted_at_ms, 2001);
    assert_eq!(first.1.evidence.admission.admission_deadline_ms, 3000);
    let one_before = tree(&one.directory);
    let two = advance_encrypted(&one, &temporary.path().join("g2"), 2);
    assert_initial_retained(&two.store, std::slice::from_ref(&first));
    let second = append_modeled_initial_layer_audits(&two.store, 2);
    let two_before = tree(&two.directory);
    let three = advance_encrypted(&two, &temporary.path().join("g3"), 3);
    assert_initial_retained(&three.store, &[first.clone(), second.clone()]);
    assert_eq!(
        three.store.settled_debit("synthetic-account").unwrap(),
        "111"
    );
    assert_eq!(
        three.store.outstanding_debit("synthetic-account").unwrap(),
        "222"
    );
    assert!(three.store.recovery_state().unwrap().recovery_required);
    for (initial, continuation, _) in [first, second] {
        let terms = initial.terms();
        assert!(
            three
                .store
                .authority_account(&terms.identity.account_id)
                .unwrap()
                .is_none()
        );
        assert!(
            three
                .store
                .recovery_record_is_historical("agreement", &terms.scope.agreement_id)
                .unwrap()
        );
        assert!(
            three
                .store
                .settlement_obligation_requires_recovery(&terms.scope.obligation_id)
                .unwrap()
        );
        assert!(matches!(
            three.store.require_ordinary_financial_lineage(
                &terms.scope.agreement_id,
                &terms.scope.obligation_id,
                &terms.scope.principal_id,
                None,
                &[],
            ),
            Err(StoreError::RecoveryRequired)
        ));
        for operation in [
            &terms.operation_id,
            &initial.operation_id,
            &continuation.operation_id,
        ] {
            assert!(
                three
                    .store
                    .record_effect_intent(
                        operation,
                        "send",
                        &terms.scope.agreement_id,
                        &"a".repeat(64),
                        "synthetic:no-effect",
                    )
                    .is_err()
            );
        }
    }
    let c = three.store.connection.lock().unwrap();
    assert_eq!(generation_depth(&c).unwrap(), 3);
    validate_generation(&c, &three.source, &binding(3)).unwrap();
    assert_eq!(
        tree(&one.directory),
        one_before,
        "the first encrypted source tree stays unchanged"
    );
    assert_eq!(
        tree(&two.directory),
        two_before,
        "the second encrypted source tree stays unchanged"
    );
}

fn inert_rows(c: &rusqlite::Connection) -> Vec<(String, Vec<RecoveryCell>)> {
    BASE.iter()
        .flat_map(|table| {
            read_rows(c, table, "")
                .unwrap()
                .into_iter()
                .map(move |row| {
                    let cells = row
                        .cells
                        .into_iter()
                        .map(|cell| match cell {
                            Value::Null => RecoveryCell::Null,
                            Value::String(value) => RecoveryCell::Text(value),
                            Value::Number(value) => RecoveryCell::Integer(value.as_i64().unwrap()),
                            _ => panic!("unexpected synthetic SQL cell"),
                        })
                        .collect();
                    (table.name.into(), cells)
                })
        })
        .collect()
}

fn copy_inert_rows(rows: &[(String, Vec<RecoveryCell>)]) -> Vec<(String, Vec<RecoveryCell>)> {
    rows.iter()
        .map(|(table, cells)| {
            (
                table.clone(),
                cells
                    .iter()
                    .map(|cell| match cell {
                        RecoveryCell::Null => RecoveryCell::Null,
                        RecoveryCell::Integer(value) => RecoveryCell::Integer(*value),
                        RecoveryCell::Text(value) => RecoveryCell::Text(value.clone()),
                        _ => panic!("unexpected synthetic SQL cell"),
                    })
                    .collect(),
            )
        })
        .collect()
}

#[test]
fn encrypted_v2_initial_inventory_rejects_omission_and_tampering_without_source_writes() {
    let temporary = tempfile::tempdir().unwrap();
    let original = root_encrypted(&temporary.path().join("original"));
    let (initial, continuation, _) = append_modeled_initial_layer_audits(&original.store, 1);
    let _quiescence = original.store.connection.lock().unwrap();
    let before = tree(&original.directory);
    // Dedicated sealed snapshot under the held fixture writer exclusion.
    let snapshot = original.snapshot();
    let c = snapshot.snapshot.connection();
    let projection = crate::recovery::project_manual_snapshot(c, &binding(1)).unwrap();
    assert!(projection.initial_publications_v2() == [initial]);
    assert!(projection.continuations_v3() == [continuation]);
    assert!(projection.v1_enrollments().is_empty());
    assert!(projection.continuations().is_empty());
    assert!(crate::recovery::project_manual_snapshot(c, &binding(2)).is_err());
    inventory(c, &original.source).unwrap();
    let rows = inert_rows(c);
    StoreRecoveryInventory::inspect_rows(
        &original.source,
        rows.iter()
            .map(|(table, cells)| (table.as_str(), cells.as_slice())),
        true,
    )
    .unwrap();
    // Only detached cell vectors are changed. No mutation reaches a connection,
    // no raw-row path creates a native owner, and V3 still requires its V2 root.
    let omitted: Vec<_> = rows
        .iter()
        .filter(|(table, cells)| {
            !(table == "records"
                && matches!(&cells[0], RecoveryCell::Text(kind) if kind == INITIAL_PUBLICATION_V2))
        })
        .collect();
    assert!(
        StoreRecoveryInventory::inspect_rows(
            &original.source,
            omitted
                .iter()
                .map(|(table, cells)| (table.as_str(), cells.as_slice())),
            true,
        )
        .is_err()
    );
    for kind in [INITIAL_PUBLICATION_V2, CONTINUATION_V3] {
        for path in [
            "/provider_enrollment_ref",
            "/evidence/admission/attempt_digest",
            "/evidence/admission/attempt_sequence",
            "/evidence/admission/admission_deadline_ms",
            "/evidence/current/writer_session_digest",
            "/evidence/request/enrollment/terms/host/generation_id",
            "/evidence/request/enrollment/terms/host/inventory_digest",
            "/evidence/request/enrollment/terms/host/store_destination_identity",
        ] {
            let mut changed = copy_inert_rows(&rows);
            let (_, cells) = changed
                .iter_mut()
                .find(|(table, cells)| {
                    table == "records"
                        && matches!(&cells[0], RecoveryCell::Text(value) if value == kind)
                })
                .unwrap();
            let RecoveryCell::Text(encoded) = &cells[3] else {
                panic!("synthetic payload");
            };
            let mut payload: Value = serde_json::from_str(encoded).unwrap();
            let field = payload.pointer_mut(path).unwrap();
            let replacement = "6".repeat(64);
            *field = if let Some(value) = field.as_u64() {
                (value + 1).into()
            } else if field.as_str() == Some(replacement.as_str()) {
                "7".repeat(64).into()
            } else {
                replacement.into()
            };
            cells[3] = RecoveryCell::Text(serde_json::to_string(&payload).unwrap());
            assert!(
                StoreRecoveryInventory::inspect_rows(
                    &original.source,
                    changed
                        .iter()
                        .map(|(table, cells)| (table.as_str(), cells.as_slice())),
                    true,
                )
                .is_err(),
                "altered {kind} {path} must be rejected"
            );
        }
    }
    let charges: Vec<(String, String)> = c
        .prepare("SELECT maximum_debit,state FROM authority_exposures ORDER BY authorization_id")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        charges,
        vec![
            ("111".into(), "consumed".into()),
            ("222".into(), "outstanding_uncertain".into()),
        ]
    );
    assert_eq!(
        tree(&original.directory),
        before,
        "the complete encrypted source tree stays unchanged"
    );
}
