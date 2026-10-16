//! Source-only synthetic union tests. Not authentication, encryption, signing,
//! current dispatch, restore activation or production offline qualification.
use super::super::super::offline_reconciliation::join_replayed;
use super::*;
use wholepact_authority::{ReservationEvidenceRef, ReservationPermit, ReserveAuthorization};

fn empty_inventory() -> OfflineHistoryInventory {
    OfflineHistoryInventory {
        enrollments: vec![],
        reservation_intents: vec![],
        admitted_origins: vec![],
    }
}
fn inventory(c: &Connection) -> OfflineHistoryInventory {
    OfflineHistoryInventory {
        enrollments: vec![],
        reservation_intents: vec![],
        admitted_origins: read_all(c, "synthetic-account").unwrap(),
    }
}
pub(in crate::consent_journal) fn online(
    admission: &OfflineAuthorizationAdmission,
) -> ReservationPermit {
    let t = &admission.request.intent.terms;
    let request = ReserveAuthorization {
        automation: None,
        operation_id: "synthetic-online-operation".into(),
        account_id: t.account_id.clone(),
        network_profile_id: t.network_profile_id.clone(),
        writer_epoch: 1,
        expected_head: AuthorityHead {
            sequence: 3,
            digest: h(60),
        },
        authorization_id: "synthetic-online-authorization".into(),
        original_consent_ref: h(61),
        enrollment_ref: t.enrollment_ref.clone(),
        accepted_manifest_ref: t.accepted_manifest_ref.clone(),
        agreement_id: t.agreement_id.clone(),
        obligation_id: "synthetic-online-obligation".into(),
        proposal_id: "synthetic-online-proposal".into(),
        proposal_digest: t.proposal_digest.clone(),
        manifest_digest: t.manifest_digest.clone(),
        effects_digest: t.effects_digest.clone(),
        artifact_digest: t.artifact_digest.clone(),
        review_binding: t.review_binding.clone(),
        recipient_scope_digest: t.recipient_scope_digest.clone(),
        inputs: vec![InputReservation {
            input_id: "synthetic-online-input".into(),
            nullifier: h(62),
            action_index: 0,
            value_zatoshis: 100,
        }],
        maximum_debit_zatoshis: 20,
        fee_share_zatoshis: 2,
        transaction_fee_zatoshis: 4,
        transaction_expiry_height: 200,
        reviewed_at_ms: 2000,
        permit_expires_at_ms: 30_000,
    };
    ReservationPermit {
        protocol_version: 2,
        witness_id: admission.witness_id.clone(),
        policy_digest: admission.witness_policy_digest.clone(),
        request_digest: request.request_digest().unwrap(),
        request,
        committed_head: AuthorityHead {
            sequence: 4,
            digest: h(63),
        },
        reserved_at_ms: 3000,
        account_outstanding_debit_zatoshis: 90,
        account_reserved_input_value_zatoshis: 200,
        writer_session_id: h(64),
    }
}
#[test]
fn remote_only_admission_is_unknown_and_keeps_exact_historical_epoch() {
    let (admission, _, _) = full_admission();
    let retained = empty_inventory();
    let joined = join_replayed(&retained, [ReservationEvidenceRef::OfflineV1(&admission)]).unwrap();
    assert_eq!(joined.offline_origins().len(), 1);
    let origin = &joined.offline_origins()[0];
    assert_eq!(
        origin.presence(),
        OfflineReconciliationPresence::ReplayedWitnessOnly
    );
    assert!(origin.retained_history().is_none());
    assert_eq!(
        origin.signature_knowledge(),
        OfflineSignatureKnowledge::HistoricalAdmissionSignatureUnknown
    );
    assert_eq!(
        origin.replayed_writer_epoch(),
        Some(admission.request.writer_epoch)
    );
    assert_eq!(joined.conservative_union_debit_zatoshis().unwrap(), 70);
}
#[test]
fn minimal_local_only_admission_remains_visible_and_blocks_coverage() {
    let (admission, _, _) = full_admission();
    let c = connection();
    insert_local(&c, &minimal(&admission));
    let retained = inventory(&c);
    let joined = join_replayed(&retained, []).unwrap();
    assert_eq!(joined.offline_origins().len(), 1);
    let origin = &joined.offline_origins()[0];
    assert_eq!(
        origin.presence(),
        OfflineReconciliationPresence::RetainedSignerOnly
    );
    assert!(origin.replayed_admission().is_none());
    assert_eq!(origin.replayed_writer_epoch(), None);
    assert_eq!(
        origin.signature_knowledge(),
        OfflineSignatureKnowledge::HistoricalAdmissionSignatureUnknown
    );
    assert_eq!(
        joined.replay_coverage(),
        OfflineReplayCoverage::RetainedAdmissionsMissing
    );
    assert!(matches!(
        joined.require_retained_offline_coverage(),
        Err(JournalError::RecoveryRequired)
    ));
    assert_eq!(joined.conservative_union_debit_zatoshis().unwrap(), 70);
    assert!(matches!(
        require_legacy_journal(&c),
        Err(JournalError::OfflineHistoryUnsupported)
    ));
}
#[test]
fn exact_minimal_and_replayed_copies_join_without_enriching_local_storage() {
    let (admission, _, _) = full_admission();
    let c = connection();
    insert_local(&c, &minimal(&admission));
    let retained = inventory(&c);
    let joined = join_replayed(&retained, [ReservationEvidenceRef::OfflineV1(&admission)]).unwrap();
    assert_eq!(joined.offline_origins().len(), 1);
    assert_eq!(
        joined.offline_origins()[0].presence(),
        OfflineReconciliationPresence::ReplayedAndRetained
    );
    assert_eq!(
        joined.replay_coverage(),
        OfflineReplayCoverage::AllRetainedAdmissionsPresent
    );
    assert_eq!(joined.conservative_union_debit_zatoshis().unwrap(), 70);
    assert!(
        joined.offline_origins()[0]
            .retained_history()
            .unwrap()
            .admission()
            .is_none()
    );
    let rows: u64 = c
        .query_row(
            "SELECT count(*) FROM signer_offline_remote_exposures",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(rows, 0);
    assert!(matches!(
        require_accountwide_online_admission(&c),
        Err(JournalError::OfflineHistoryUnsupported)
    ));
}
#[test]
fn full_retained_remote_without_replay_is_preserved_as_a_gap() {
    let (admission, policy, provenance) = full_admission();
    let c = connection();
    insert_remote(&c, &admission, &policy, &provenance);
    let retained = inventory(&c);
    let joined = join_replayed(&retained, []).unwrap();
    assert_eq!(joined.offline_origins().len(), 1);
    assert!(
        joined.offline_origins()[0]
            .retained_history()
            .unwrap()
            .admission()
            .is_some()
    );
    assert!(joined.require_retained_offline_coverage().is_err());
    assert_eq!(joined.conservative_union_debit_zatoshis().unwrap(), 70);
}
#[test]
fn equal_authorization_id_does_not_hide_changed_minimal_or_full_evidence() {
    let (admission, policy, provenance) = full_admission();
    let c = connection();
    insert_local(&c, &minimal(&admission));
    let retained = inventory(&c);
    let mut changed = admission.clone();
    changed.writer_session_id = h(90); // Still shape-valid; assertion commitment changes.
    assert!(join_replayed(&retained, [ReservationEvidenceRef::OfflineV1(&changed)]).is_err());
    let c = connection();
    insert_remote(&c, &admission, &policy, &provenance);
    let retained = inventory(&c);
    assert!(matches!(
        join_replayed(&retained, [ReservationEvidenceRef::OfflineV1(&changed)]),
        Err(JournalError::Conflict)
    ));
}
#[test]
fn duplicate_replay_and_online_offline_authorization_collisions_fail_closed() {
    let (admission, _, _) = full_admission();
    let retained = empty_inventory();
    assert!(matches!(
        join_replayed(
            &retained,
            [
                ReservationEvidenceRef::OfflineV1(&admission),
                ReservationEvidenceRef::OfflineV1(&admission)
            ]
        ),
        Err(JournalError::Conflict)
    ));
    let mut online = online(&admission);
    online.request.authorization_id = admission.request.intent.terms.authorization_id.clone();
    online.request_digest = online.request.request_digest().unwrap();
    assert!(matches!(
        join_replayed(
            &retained,
            [
                ReservationEvidenceRef::OnlineV2(&online),
                ReservationEvidenceRef::OfflineV1(&admission)
            ]
        ),
        Err(JournalError::Conflict)
    ));
    let c = connection();
    insert_local(&c, &minimal(&admission));
    let retained = inventory(&c);
    assert!(matches!(
        join_replayed(&retained, [ReservationEvidenceRef::OnlineV2(&online)]),
        Err(JournalError::Conflict)
    ));
}
#[test]
fn mixed_union_preserves_online_bytes_and_all_nonbinding_history() {
    let (admission, policy, _) = full_admission();
    let online = online(&admission);
    let before = serde_json::to_vec(&online).unwrap();
    let retained = OfflineHistoryInventory {
        enrollments: vec![policy],
        reservation_intents: vec![admission.request.intent.clone()],
        admitted_origins: vec![],
    };
    let joined = join_replayed(
        &retained,
        [
            ReservationEvidenceRef::OfflineV1(&admission),
            ReservationEvidenceRef::OnlineV2(&online),
        ],
    )
    .unwrap();
    assert_eq!(joined.witness_online_reservations().len(), 1);
    assert_eq!(joined.offline_origins().len(), 1);
    assert_eq!(joined.retained_enrollments().len(), 1);
    assert_eq!(joined.retained_reservation_intents().len(), 1);
    assert_eq!(joined.conservative_union_debit_zatoshis().unwrap(), 90);
    assert_eq!(
        before,
        serde_json::to_vec(joined.witness_online_reservations()[0]).unwrap()
    );
    let raw = String::from_utf8(before).unwrap();
    assert!(!raw.contains("\"automation\""));
    assert!(!raw.contains("\"origin\""));
}
#[test]
fn retained_original_and_keyuse_uncertainty_survive_replay_join() {
    let (admission, _, _) = full_admission();
    let c = connection();
    let local = minimal(&admission);
    insert_local(&c, &local);
    let original = original(&local);
    insert_original(&c, &original);
    let retained = inventory(&c);
    let joined = join_replayed(&retained, [ReservationEvidenceRef::OfflineV1(&admission)]).unwrap();
    assert_eq!(
        joined.offline_origins()[0].signature_knowledge(),
        OfflineSignatureKnowledge::OriginalConsentRetainedSignatureUnknown
    );
    insert_keyuse(&c, &original);
    let retained = inventory(&c);
    let joined = join_replayed(&retained, [ReservationEvidenceRef::OfflineV1(&admission)]).unwrap();
    assert_eq!(
        joined.offline_origins()[0].signature_knowledge(),
        OfflineSignatureKnowledge::LocalKeyUseStartedSignatureUnknown
    );
    assert_eq!(joined.conservative_union_debit_zatoshis().unwrap(), 70);
}

#[test]
fn exact_retained_result_still_has_unknown_current_validity_after_join() {
    use sha2::{Digest, Sha256};
    let (admission, _, _) = full_admission();
    let c = connection();
    let local = minimal(&admission);
    insert_local(&c, &local);
    let original = original(&local);
    insert_original(&c, &original);
    insert_keyuse(&c, &original);
    let bytes = b"synthetic unverified history result, not real signatures";
    let result = OfflineRetainedResultHistory {
        authorization_id: original.authorization_id.clone(),
        original_consent_ref: original.reference.clone(),
        admission_request_digest: original.admission_request_digest.clone(),
        authenticated_package_digest: original.authenticated_package_digest.clone(),
        signed_artifact_digest: hex::encode(Sha256::digest(bytes)),
        return_recipient_key_digest: original.return_recipient_key_digest.clone(),
    };
    c.execute(
        "INSERT INTO signer_offline_results VALUES(?1,?2,?3,?4)",
        params![
            result.authorization_id,
            result.signed_artifact_digest,
            hex::encode(bytes),
            encode(&result).unwrap().as_str()
        ],
    )
    .unwrap();
    let retained = inventory(&c);
    let joined = join_replayed(&retained, [ReservationEvidenceRef::OfflineV1(&admission)]).unwrap();
    let origin = &joined.offline_origins()[0];
    assert_eq!(
        origin.signature_knowledge(),
        OfflineSignatureKnowledge::ExactResultRetainedCurrentValidityUnknown
    );
    assert_eq!(
        origin
            .retained_history()
            .unwrap()
            .retained_result()
            .unwrap()
            .signed_artifact_digest,
        result.signed_artifact_digest
    );
    assert_eq!(joined.conservative_union_debit_zatoshis().unwrap(), 70);
    assert!(matches!(
        require_legacy_journal(&c),
        Err(JournalError::OfflineHistoryUnsupported)
    ));
}

// Exported only from the authority's never-funded pure complete-history fixture.
// Parsing these records creates data, never authenticated replay or a live owner.
pub(in crate::consent_journal) fn construction_records() -> std::collections::BTreeMap<
    String,
    wholepact_authority::manual_roster_construction_v2::ManualRosterConstructionHistoryRecordV2,
> {
    serde_json::from_str(include_str!("construction_history.synthetic.json")).unwrap()
}

#[test]
fn construction_history_is_retained_and_consumption_never_doubles_or_refunds_debit() {
    use wholepact_authority::manual_roster_construction_v2::ManualRosterConstructionHistoryRecordV2;
    let retained = empty_inventory();
    let records = construction_records();
    let joined = join_replayed(&retained, [])
        .unwrap()
        .with_construction_records(records.iter().map(|(id, r)| (id.as_str(), r)))
        .unwrap();
    assert_eq!(joined.construction_records().len(), 2);
    assert!(joined.witness_online_reservations().is_empty());
    assert!(joined.offline_origins().is_empty());
    assert_eq!(
        joined.conservative_union_debit_zatoshis().unwrap(),
        400_012_000
    );
    assert!(joined.require_retained_offline_coverage().is_ok());
    assert!(matches!(
        joined.require_financial_activation_supported(),
        Err(JournalError::ConstructionHistoryUnsupported)
    ));
    let original = joined
        .construction_records()
        .iter()
        .find_map(|(_, r)| match r {
            ManualRosterConstructionHistoryRecordV2::Reservation { record } => Some(record),
            ManualRosterConstructionHistoryRecordV2::Consumed { .. } => None,
        })
        .unwrap();
    assert_eq!(original.reserved_input_value_zatoshis, 500_000_000);
    assert_eq!(
        original.request.selected_inputs()[0].input_id,
        "input-alice"
    );
    assert_eq!(
        original.request.selected_inputs()[0].nullifier,
        "4".repeat(64)
    );
    assert_eq!(
        original.request.enrollment().scope.obligation_id,
        "obligation-example-01"
    );
    let reserve_only = join_replayed(&retained, [])
        .unwrap()
        .with_construction_records(
            records
                .iter()
                .filter(|(_, r)| {
                    matches!(
                        r,
                        ManualRosterConstructionHistoryRecordV2::Reservation { .. }
                    )
                })
                .map(|(id, r)| (id.as_str(), r)),
        )
        .unwrap();
    assert_eq!(
        reserve_only.conservative_union_debit_zatoshis().unwrap(),
        joined.conservative_union_debit_zatoshis().unwrap()
    );
}

#[test]
fn construction_history_rejects_omitted_reservation_and_duplicate_rows() {
    use wholepact_authority::manual_roster_construction_v2::ManualRosterConstructionHistoryRecordV2;
    let retained = empty_inventory();
    let records = construction_records();
    let consume_only = records
        .iter()
        .filter(|(_, r)| matches!(r, ManualRosterConstructionHistoryRecordV2::Consumed { .. }))
        .map(|(id, r)| (id.as_str(), r));
    assert!(matches!(
        join_replayed(&retained, [])
            .unwrap()
            .with_construction_records(consume_only),
        Err(JournalError::InvalidBinding)
    ));
    let duplicate = records
        .iter()
        .chain(records.iter())
        .map(|(id, r)| (id.as_str(), r));
    assert!(matches!(
        join_replayed(&retained, [])
            .unwrap()
            .with_construction_records(duplicate),
        Err(JournalError::Conflict)
    ));
}
