//! Real full validator/row branches observed through the production lexical
//! detail scope. Inert historical DTOs only: no Final, live grant or publication.
//! This private semantic-only child reads finite detail; it cannot set it.
use super::*;
use crate::financial_ci_actor::{AdmitReadObservation, admit_read_detail_for_test};
use wholepact_financial_coordinator_origin::financial_ci_actor_diagnostics::{Class, DriverStage};

#[track_caller]
fn fails_at(stage: DriverStage, class: Class, f: impl FnOnce() -> Result<()>) {
    assert_eq!(admit_read_detail_for_test(), None, "no leaked lexical detail before observation");
    {
        let _observation = AdmitReadObservation::enter();
        let result = f();
        match class {
            Class::JournalInvalidBinding => assert!(matches!(result, Err(JournalError::InvalidBinding))),
            Class::JournalNotFound => assert!(matches!(result, Err(JournalError::NotFound))),
            _ => panic!("unexpected test class"),
        }
        assert_eq!(admit_read_detail_for_test(), Some((stage, class)));
    }
    assert_eq!(admit_read_detail_for_test(), None, "observation restored prior lexical state");
}

#[test]
fn actual_complete_review_and_original_rows_success_leave_no_detail() {
    let f = MaterialFixture::coordinated(); let i = complete(&f);
    let c = checked(f.journal().connection.lock()); let before = c.total_changes();
    assert_eq!(admit_read_detail_for_test(), None);
    {
        let _observation = AdmitReadObservation::enter();
        checked(i.validate_review()); checked(i.validate());
        checked(validate_original_rows(&c, &i));
        assert_eq!(admit_read_detail_for_test(), None);
    }
    assert_eq!(admit_read_detail_for_test(), None);
    assert!(before == c.total_changes());
}

#[test]
fn actual_complete_review_nested_and_shape_failures_select_finite_detail() {
    let f = MaterialFixture::coordinated(); let baseline = complete(&f);
    for mutation in 0..6 {
        let mut i = baseline.clone();
        let stage = match mutation {
            0 => { i.disclosure.pinned_server_certificate_digest.clear(); DriverStage::AdmitReadIntentReviewNested },
            1 => { i.request.operation_id = "different-inert-operation".into(); DriverStage::AdmitReadIntentReviewNested },
            2 => { i.recipient_intent.payload_bytes = 0; DriverStage::AdmitReadIntentReviewNested },
            3 => { i.read.measurement = "not-a-hash".into(); DriverStage::AdmitReadIntentReviewShape },
            4 => { i.read.principal_id.clear(); DriverStage::AdmitReadIntentReviewShape },
            _ => { i.admit_read.authenticated_history_digest.clear(); DriverStage::AdmitReadIntentReviewShape },
        };
        fails_at(stage, Class::JournalInvalidBinding, || i.validate_review());
    }
}

#[test]
fn actual_complete_review_or_groups_select_ceiling_binding_and_material_detail() {
    let f = MaterialFixture::coordinated(); let baseline = complete(&f);
    for mutation in 0..7 {
        let mut i = baseline.clone();
        let stage = match mutation {
            0 => { i.ceilings.original_owner_service_expires_at_ms = 0; DriverStage::AdmitReadIntentReviewCeilings },
            1 => { i.admit_read.source_identity_digest = h(0xfe); DriverStage::AdmitReadIntentReviewCeilings },
            2 => { i.admit_read.expires_at_ms += 1; DriverStage::AdmitReadIntentReviewCeilings },
            3 => { i.version = 3; DriverStage::AdmitReadIntentReviewBinding },
            4 => { i.read.prepare_read_presentation_digest = h(0xfe); DriverStage::AdmitReadIntentReviewBinding },
            5 => { i.read.read_session_digest = h(0xfe); DriverStage::AdmitReadIntentReviewBinding },
            _ => {
                let from = i.read.approved_at_ms - 100_000;
                i.read.approved_at_ms = from - 1; i.read.expires_at_ms = from + 1;
                DriverStage::AdmitReadIntentReviewMaterial
            },
        };
        fails_at(stage, Class::JournalInvalidBinding, || i.validate_review());
    }
}

#[test]
fn actual_original_row_failures_select_exact_lineage_stage_and_original_class() {
    let f = MaterialFixture::coordinated(); let baseline = complete(&f);
    let c = checked(f.journal().connection.lock()); let before = c.total_changes();
    checked(validate_original_rows(&c, &baseline));
    for mutation in 0..7 {
        let mut i = baseline.clone();
        let (stage, class) = match mutation {
            0 => { i.read.principal_id = "different-owner".into(); (DriverStage::AdmitReadIntentRowsOriginalLinks, Class::JournalInvalidBinding) },
            1 => { i.recipient_intent.request.own_disclosure.expected_request_digest = h(0xfe); (DriverStage::AdmitReadIntentRowsOriginalDisclosure, Class::JournalInvalidBinding) },
            2 => { i.recipient_intent.request.current_disclosure = None; (DriverStage::AdmitReadIntentRowsCurrentDisclosure, Class::JournalInvalidBinding) },
            3 => { i.read.measurement = h(0xfe); (DriverStage::AdmitReadIntentRowsSession, Class::JournalInvalidBinding) },
            4 => { i.recipient_intent.authorized_host_process_instance = h(0xfe); (DriverStage::AdmitReadIntentRowsTransport, Class::JournalInvalidBinding) },
            5 => {
                let own = i.recipient_intent.account_id.clone();
                i.recipient_intent.material_scopes.iter_mut().find(|m| m.account_id == own).unwrap().original_scope_digest = h(0xfe);
                scope_mut(&mut i).original_ceilings.material_scopes = i.recipient_intent.material_scopes.clone();
                (DriverStage::AdmitReadIntentRowsMaterial, Class::JournalInvalidBinding)
            },
            _ => { i.recipient_intent.request.own_disclosure.operation_id = "missing-inert-history".into(); (DriverStage::AdmitReadIntentRowsOriginalDisclosure, Class::JournalNotFound) },
        };
        rebind_request(&mut i); rebind_recipient(&mut i); retain(&mut i);
        checked(i.validate()); // A malformed envelope cannot satisfy this test.
        fails_at(stage, class, || validate_original_rows(&c, &i));
    }
    assert!(before == c.total_changes());
}

#[test]
fn actual_validator_first_detail_survives_outer_fallback_and_restores_scope() {
    let f = MaterialFixture::coordinated(); let baseline = complete(&f);
    let c = checked(f.journal().connection.lock()); let before = c.total_changes();
    let mut nested = baseline.clone(); nested.request.operation_id = "wrong-inert-operation".into();
    let mut shape = baseline.clone(); shape.read.measurement.clear();
    // Borrowed failure outside any owner observation is locally silent.
    assert!(matches!(nested.validate_review(), Err(JournalError::InvalidBinding)));
    assert_eq!(admit_read_detail_for_test(), None);
    {
        let _parent = AdmitReadObservation::enter();
        // The real outer Rows wrapper must not overwrite the deeper Nested.
        assert!(matches!(validate_original_rows(&c, &nested), Err(JournalError::InvalidBinding)));
        let first = Some((DriverStage::AdmitReadIntentReviewNested, Class::JournalInvalidBinding));
        assert_eq!(admit_read_detail_for_test(), first);
        assert!(matches!(shape.validate_review(), Err(JournalError::InvalidBinding)));
        assert_eq!(admit_read_detail_for_test(), first);
        {
            let _child = AdmitReadObservation::enter();
            assert_eq!(admit_read_detail_for_test(), None);
            checked(baseline.validate_review());
            assert_eq!(admit_read_detail_for_test(), None);
            assert!(matches!(shape.validate_review(), Err(JournalError::InvalidBinding)));
            assert_eq!(admit_read_detail_for_test(), Some((DriverStage::AdmitReadIntentReviewShape, Class::JournalInvalidBinding)));
        }
        assert_eq!(admit_read_detail_for_test(), first);
    }
    assert_eq!(admit_read_detail_for_test(), None);
    assert!(before == c.total_changes());
}

// The original caller's `?` already performed this exact conversion. The
// diagnostic must classify the Journal wrapper, not require a new blanket
// classifier for raw storage-security errors.
fn implicit_identity_check(
    identity: &wholepact_storage_security::DatabaseFileIdentity,
    connection: &Connection,
) -> Result<()> {
    identity.check_current(connection)?;
    Ok(())
}
#[track_caller]
fn identity_conversion_matches_original(
    identity: &wholepact_storage_security::DatabaseFileIdentity,
    connection: &Connection,
    changed: bool,
) {
    let original = implicit_identity_check(identity, connection);
    assert_eq!(admit_read_detail_for_test(), None);
    {
        let _observation = AdmitReadObservation::enter();
        let mut calls = 0;
        let observed: Result<()> = actor_admit_read_detail_result!(AdmitReadIntentJournalIdentity, {
            calls += 1;
            identity.check_current(connection).map_err(JournalError::from)
        });
        assert_eq!(calls, 1);
        if changed {
            assert!(matches!(original, Err(JournalError::Storage(
                wholepact_storage_security::StorageSecurityError::SourceChanged))));
            assert!(matches!(observed, Err(JournalError::Storage(
                wholepact_storage_security::StorageSecurityError::SourceChanged))));
            assert_eq!(admit_read_detail_for_test(), Some((
                DriverStage::AdmitReadIntentJournalIdentity, Class::JournalStorage)));
        } else {
            assert!(matches!(original, Ok(())));
            assert!(matches!(observed, Ok(())));
            assert_eq!(admit_read_detail_for_test(), None);
        }
    }
    assert_eq!(admit_read_detail_for_test(), None);
}

#[test]
fn actual_connection_identity_error_keeps_original_journal_conversion() {
    let original = MaterialFixture::coordinated();
    let other = MaterialFixture::coordinated();
    let connection = checked(original.journal().connection.lock());
    let before = connection.total_changes();
    identity_conversion_matches_original(&original.journal().database_identity, &connection, false);
    identity_conversion_matches_original(&other.journal().database_identity, &connection, true);
    assert!(before == connection.total_changes());
}

#[test]
fn actual_transaction_identity_error_keeps_original_journal_conversion() {
    let original = MaterialFixture::coordinated();
    let other = MaterialFixture::coordinated();
    let mut connection = checked(original.journal().connection.lock());
    let before = connection.total_changes();
    {
        let transaction = checked(connection.transaction_with_behavior(TransactionBehavior::Deferred));
        identity_conversion_matches_original(&original.journal().database_identity, &transaction, false);
        identity_conversion_matches_original(&other.journal().database_identity, &transaction, true);
    }
    assert!(before == connection.total_changes());
}
