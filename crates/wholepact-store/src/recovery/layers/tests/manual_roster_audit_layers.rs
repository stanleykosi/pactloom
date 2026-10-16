//! Modeled coordination retention over actual encrypted synthetic SQLite files.
//! Uses supported sealed storage fixtures and the private audit layer kernel.
//! This does not qualify native account backup,
//! witness service, live signer authority, or independent-key publication.
use super::*;
use crate::manual_enrollment::{
    ADDITIONAL_PUBLICATION_V3, CONTINUATION_V4, ManualEnrollmentAdditionalPublicationV3,
    ManualEnrollmentContinuationAuditV4, ManualInitialAdmissionProvenance,
    OriginalManualEnrollmentAuditLink, append_modeled_initial_layer_audits,
    append_modeled_roster_layer_audits,
};

type RosterRows = (
    ManualEnrollmentAdditionalPublicationV3,
    ManualEnrollmentAdditionalPublicationV3,
    ManualEnrollmentContinuationAuditV4,
    ManualExclusionAudit,
);

fn exact_roster_payloads(c: &Connection) -> Vec<(String, String, String)> {
    c.prepare("SELECT aggregate_type,id,payload FROM records WHERE aggregate_type IN (?1,?2) ORDER BY aggregate_type,id")
        .unwrap()
        .query_map(params![ADDITIONAL_PUBLICATION_V3, CONTINUATION_V4], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

fn assert_roster_retained(
    store: &Store,
    expected: &RosterRows,
    exact: &[(String, String, String)],
) {
    let (second, third, continuation, exclusion) = expected;
    let c = store.connection.lock().unwrap();
    let generation = store.recovered_binding.as_ref().unwrap();
    let projection = crate::recovery::project_manual_snapshot(&c, generation).unwrap();
    assert_eq!(exact_roster_payloads(&c), exact);
    assert_eq!(projection.additional_publications_v3().len(), 2);
    assert!(projection.additional_publications_v3().contains(second));
    assert!(projection.additional_publications_v3().contains(third));
    assert!(projection.continuations_v4() == std::slice::from_ref(continuation));
    assert!(projection.exclusions().contains(exclusion));
    assert!(projection.v1_enrollments().is_empty());
    assert!(projection.continuations().is_empty());
    assert!(projection.scope_audits().is_empty());
    continuation.validate_for(second).unwrap();
    assert!(
        continuation.original_audit
            == OriginalManualEnrollmentAuditLink::AdditionalPublicationV3 {
                audit_digest: second.digest().unwrap(),
            }
    );
    assert_eq!(continuation.evidence.admission.attempt_sequence, 4);
    assert_eq!(continuation.evidence.admission.admitted_at_ms, 2001);
    assert_eq!(continuation.evidence.admission.admission_deadline_ms, 3000);
    assert_eq!(
        continuation.evidence.current.writer_session_digest,
        "7".repeat(64)
    );
    for original in [second, third] {
        original.validate().unwrap();
        assert_ne!(
            original.terms().host.generation_id,
            generation.generation_id()
        );
        assert_eq!(
            original.terms().host.generation_id,
            binding(1).generation_id()
        );
        assert_eq!(
            original.terms().host.inventory_digest,
            binding(1).inventory_digest()
        );
        assert!(original.terms().host.scope_predecessor_digest.is_none());
        assert_eq!(original.evidence.witness_extension_sequence, 1);
        let common = projection.enrollments();
        let retained = common
            .iter()
            .find(|row| row.digest().unwrap() == original.digest().unwrap())
            .unwrap();
        assert!(retained.terms() == original.terms());
        assert!(retained.aliases() == &original.aliases);
        assert!(
            matches!(retained.initial_admission(), ManualInitialAdmissionProvenance::RosterV2(evidence) if evidence == &original.evidence)
        );
        for (kind, id) in [
            (
                "record",
                format!("{ADDITIONAL_PUBLICATION_V3}:{}", original.digest().unwrap()),
            ),
            ("operation", original.terms().operation_id.clone()),
            ("operation", original.operation_id.clone()),
            ("idempotency", original.request_identity_digest.clone()),
            ("agreement", original.terms().scope.agreement_id.clone()),
            ("obligation", original.terms().scope.obligation_id.clone()),
        ] {
            require_fence(&c, kind, &id).unwrap();
        }
        for alias in &original.aliases {
            require_fence(&c, "account", alias).unwrap();
        }
    }
    for alias in &exclusion.aliases {
        require_fence(&c, "account", alias).unwrap();
    }
    for (kind, id) in [
        (
            "record",
            format!("{CONTINUATION_V4}:{}", continuation.digest().unwrap()),
        ),
        ("operation", continuation.operation_id.clone()),
        ("idempotency", continuation.request_identity_digest.clone()),
        (
            "record",
            format!(
                "{}:{}",
                crate::manual_enrollment::EXCLUSION,
                exclusion.digest().unwrap()
            ),
        ),
    ] {
        require_fence(&c, kind, &id).unwrap();
    }
}

#[test]
fn encrypted_roster_v3_v4_bytes_and_fences_survive_recursive_modeled_recovery() {
    let temporary = tempfile::tempdir().unwrap();
    let one = root_encrypted(&temporary.path().join("g1"));
    let root = append_modeled_initial_layer_audits(&one.store, 1);
    let expected = append_modeled_roster_layer_audits(&one.store, &root.0);
    let exact = exact_roster_payloads(&one.store.connection.lock().unwrap());
    assert_eq!(exact.len(), 3);
    let one_before = tree(&one.directory);
    let two = advance_encrypted(&one, &temporary.path().join("g2"), 2);
    assert_roster_retained(&two.store, &expected, &exact);
    let two_before = tree(&two.directory);
    let three = advance_encrypted(&two, &temporary.path().join("g3"), 3);
    assert_roster_retained(&three.store, &expected, &exact);

    // Read the actual dedicated immutable snapshot under fixture exclusion.
    let _quiescence = three.store.connection.lock().unwrap();
    let snapshot = three.snapshot();
    let c = snapshot.snapshot.connection();
    validate_generation(c, &three.source, &binding(3)).unwrap();
    assert_eq!(generation_depth(c).unwrap(), 3);
    assert_eq!(exact_roster_payloads(c), exact);
    let projected = crate::recovery::project_manual_snapshot(c, &binding(3)).unwrap();
    assert!(projected.additional_publications_v3().contains(&expected.0));
    assert!(projected.additional_publications_v3().contains(&expected.1));
    assert!(projected.continuations_v4() == std::slice::from_ref(&expected.2));
    drop(projected);
    drop(snapshot);
    drop(_quiescence);

    assert_eq!(
        three.store.settled_debit("synthetic-account").unwrap(),
        "111"
    );
    assert_eq!(
        three.store.outstanding_debit("synthetic-account").unwrap(),
        "222"
    );
    assert!(three.store.recovery_state().unwrap().recovery_required);
    for original in [&expected.0, &expected.1] {
        let terms = original.terms();
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
        for operation in [&terms.operation_id, &original.operation_id] {
            assert!(
                three
                    .store
                    .record_effect_intent(
                        operation,
                        "send",
                        &terms.scope.agreement_id,
                        &"a".repeat(64),
                        "synthetic:no-effect"
                    )
                    .is_err()
            );
        }
    }
    assert!(
        three
            .store
            .record_effect_intent(
                &expected.2.operation_id,
                "send",
                &expected.0.terms().scope.agreement_id,
                &"a".repeat(64),
                "synthetic:no-effect"
            )
            .is_err()
    );
    assert_eq!(
        tree(&one.directory),
        one_before,
        "first encrypted source bytes and metadata stay unchanged"
    );
    assert_eq!(
        tree(&two.directory),
        two_before,
        "second encrypted source bytes and metadata stay unchanged"
    );
}
