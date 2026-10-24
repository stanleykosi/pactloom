//! Historical DATA regression for the two intentionally distinct process-label
//! namespaces. No genuine Pair, peer credentials, Final, or grant is constructed.
//! The separate source-extracted regression binds the actual producer/consumer
//! field choice; this test exercises the unchanged encrypted row validator.
use super::*;
#[cfg(wholepact_financial_rendered_host_semantic_ci)]
use crate::financial_ci_actor::{AdmitReadObservation, admit_read_detail_for_test};
#[cfg(wholepact_financial_rendered_host_semantic_ci)]
use wholepact_financial_coordinator_origin::financial_ci_actor_diagnostics::{Class, DriverStage};

fn process_label(transport: &TransportIdentityBinding) -> &str {
    let TransportIdentityBinding::LocalProcess { process_instance, .. } = transport else { panic!("expected inert local transport") };
    process_instance
}

#[track_caller]
fn actual_row_gate(f: &MaterialFixture, i: &CoordinatedAdmissionIntentV1, denied: bool) {
    // Every denial below must reach the real row join with a valid full DTO.
    assert!(i.validate().is_ok(), "transport regression full envelope");
    let c = checked(f.journal().connection.lock()); let before = c.total_changes();
    {
        #[cfg(wholepact_financial_rendered_host_semantic_ci)]
        let _observation = AdmitReadObservation::enter();
        let result = validate_original_rows(&c, i);
        if denied {
            assert!(matches!(result, Err(JournalError::InvalidBinding)), "distinct label must fail unchanged transport equality");
        } else {
            assert!(result.is_ok(), "canonical original process label must pass actual rows");
        }
        #[cfg(wholepact_financial_rendered_host_semantic_ci)]
        assert_eq!(admit_read_detail_for_test(), if denied {
            Some((DriverStage::AdmitReadIntentRowsTransport, Class::JournalInvalidBinding))
        } else { None });
    }
    #[cfg(wholepact_financial_rendered_host_semantic_ci)]
    assert_eq!(admit_read_detail_for_test(), None);
    assert!(before == c.total_changes(), "read-only transport validation changed rows");
}

#[test]
fn distinct_observed_and_original_process_labels_require_canonical_current_rows() {
    let original_process_label = h(0xe1);
    let (observed, canonical) = MaterialFixture::coordinated_process_label_pair(&original_process_label);
    let observed_process_label = process_label(observed.rows()[1].recipient_transport()).to_owned();
    assert!(observed_process_label != original_process_label);
    assert!(process_label(canonical.rows()[1].recipient_transport()) == original_process_label);
    // Same scanned owners, exact original disclosure and unrelated row2. No
    // different random wallet/material can explain the old/new result.
    assert!(observed.rows()[0] == canonical.rows()[0]);
    assert!(observed.rows()[2] == canonical.rows()[2]);
    assert!(observed.rows()[1].request().scope == canonical.rows()[1].request().scope);
    assert!(observed.rows()[1].request().material == canonical.rows()[1].request().material);
    let mut expected_transport = observed.rows()[1].recipient_transport().clone();
    let TransportIdentityBinding::LocalProcess { process_instance, .. } = &mut expected_transport else { panic!() };
    *process_instance = original_process_label.clone();
    // UID/PID, generation, account, agreement, participant, manifest and channel
    // fields are unchanged. Only the persistent process-label domain differs.
    assert!(&expected_transport == canonical.rows()[1].recipient_transport());
    for f in [&observed, &canonical] {
        let c = checked(f.journal().connection.lock()); let before = c.total_changes();
        assert!(storage::verify_schema(&c).is_ok(), "transport regression encrypted schema baseline");
        assert!(before == c.total_changes());
    }

    let mut old_mapping = complete(&observed);
    // Positive control: strict equality itself is satisfiable on the old rows.
    actual_row_gate(&observed, &old_mapping, false);
    old_mapping.recipient_intent.authorized_host_process_instance = original_process_label.clone();
    rebind_recipient(&mut old_mapping); retain(&mut old_mapping);
    actual_row_gate(&observed, &old_mapping, true);

    let corrected_mapping = complete(&canonical);
    assert!(corrected_mapping.recipient_intent.authorized_host_process_instance == original_process_label);
    actual_row_gate(&canonical, &corrected_mapping, false);
    // Neither the old observed label nor another purported original label is
    // accepted after canonicalization. No equality relaxation/fallback exists.
    for wrong in [observed_process_label, h(0xfe)] {
        assert!(wrong != original_process_label);
        let mut changed = corrected_mapping.clone();
        changed.recipient_intent.authorized_host_process_instance = wrong;
        rebind_recipient(&mut changed); retain(&mut changed);
        actual_row_gate(&canonical, &changed, true);
    }
    // Other existing scope/generation/account restrictions remain mandatory.
    let mut wrong_generation = corrected_mapping.clone();
    wrong_generation.recipient_intent.source_generation = 2;
    assert!(wrong_generation.validate_review().is_err());
    let mut wrong_account = corrected_mapping.clone();
    wrong_account.recipient_intent.account_id = h(0xfe);
    assert!(wrong_account.validate_review().is_err());
    let mut wrong_scope = corrected_mapping.clone();
    wrong_scope.recipient_intent.material_scopes[0].original_scope_digest = h(0xfe);
    assert!(wrong_scope.validate_review().is_err());
}
