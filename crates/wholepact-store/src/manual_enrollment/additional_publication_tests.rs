//! Staged synthetic pure-record tests. Not run and not live admission evidence.
use super::*;
use crate::manual_enrollment::tests::initial_publication::initial_fixture;
use wholepact_core::manual_roster_v2::{HostRosterAppendBindingV2, HostRosterPredecessorV2};
fn h(c: char) -> String {
    c.to_string().repeat(64)
}
fn addition(
    root: &ManualEnrollmentInitialPublicationV2,
) -> ManualEnrollmentAdditionalPublicationV3 {
    let mut terms = root.terms().clone();
    terms.operation_id = "synthetic-distinct-account-intent".into();
    terms.identity.account_id = h('c');
    terms.identity.full_viewing_key_digest = h('d');
    terms.scope.participant_id = "synthetic-second-participant".into();
    let request = ManualRosterPublicationRequestV2 {
        version: 2,
        enrollment: ManualContinuationEnrollment {
            terms: terms.clone(),
        },
        roster: HostRosterAppendBindingV2 {
            version: 2,
            generation_id: terms.host.generation_id.clone(),
            store_destination_identity: terms.host.store_destination_identity.clone(),
            roster_sequence: 2,
            predecessor: HostRosterPredecessorV2::InitialPublicationV2 {
                audit_digest: root.digest().unwrap(),
            },
        },
        attempt: ManualRosterPublicationAttemptV2::InitialV2 {},
    };
    let roster_extension = h('e');
    let attempt_digest = wholepact_core::proposal::canonical_digest(
        "wholepact:manual-roster-enrollment-initial-attempt:v2",
        &roster_extension,
    )
    .unwrap();
    ManualEnrollmentAdditionalPublicationV3 {
        version: 3,
        operation_id: "synthetic-second-publication".into(),
        request_identity_digest: h('a'),
        provider_enrollment_ref: h('b'),
        store_sequence: 2,
        aliases: BTreeSet::from([terms.identity.account_id.clone()]),
        evidence: ManualRosterEnrollmentEvidenceV2 {
            version: 2,
            enrollment_ref: h('f'),
            signer_roster_record_digest: h('9'),
            witness_roster_extension_digest: roster_extension,
            witness_extension_digest: h('8'),
            witness_extension_sequence: 1,
            witness_extension_predecessor_digest: None,
            admission: ManualRosterAdmissionV2 {
                version: 2,
                exact_request_digest: request.digest().unwrap(),
                signer_intent_digest: h('7'),
                witness_admission_digest: h('6'),
                attempt_digest,
                attempt_sequence: 1,
                admitted_at_ms: root.evidence.admission.admitted_at_ms,
                admission_deadline_ms: root.evidence.admission.admission_deadline_ms,
            },
            current: root.evidence.current.clone(),
            request,
        },
    }
}
fn validate(
    root: &ManualEnrollmentInitialPublicationV2,
    rows: &[ManualEnrollmentAdditionalPublicationV3],
) -> Result<()> {
    validate_audit_set(
        &[],
        &[],
        &[],
        &[],
        &[(root.digest()?, root.clone())],
        &[],
        crate::manual_enrollment::RosterAuditRows {
            additions: &rows
                .iter()
                .map(|a| Ok((a.digest()?, a.clone())))
                .collect::<Result<Vec<_>>>()?,
            continuations: &[],
        },
    )
}
#[test]
fn distinct_original_is_a_new_roster_event_not_an_account_scope_extension() {
    let root = initial_fixture();
    let added = addition(&root);
    validate(&root, std::slice::from_ref(&added)).unwrap();
    assert!(added.terms().host.scope_predecessor_digest.is_none());
    assert_eq!(added.evidence.witness_extension_sequence, 1);
    assert_eq!(added.store_sequence, 2);
}
#[test]
fn missing_root_wrong_predecessor_and_fork_are_rejected() {
    let root = initial_fixture();
    let added = addition(&root);
    assert!(
        validate_audit_set(
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            crate::manual_enrollment::RosterAuditRows {
                additions: &[(added.digest().unwrap(), added.clone())],
                continuations: &[]
            },
        )
        .is_err()
    );
    let mut changed = added.clone();
    changed.evidence.request.roster.predecessor = HostRosterPredecessorV2::EnrollmentV1 {
        audit_digest: root.digest().unwrap(),
    };
    changed.evidence.admission.exact_request_digest = changed.evidence.request.digest().unwrap();
    assert!(validate(&root, &[changed]).is_err());
    assert!(validate(&root, &[added.clone(), added]).is_err());
}
#[test]
fn existing_account_or_fvk_cannot_be_enrolled_as_an_addition() {
    let root = initial_fixture();
    let mut added = addition(&root);
    added
        .evidence
        .request
        .enrollment
        .terms
        .identity
        .full_viewing_key_digest = root.terms().identity.full_viewing_key_digest.clone();
    added.evidence.admission.exact_request_digest = added.evidence.request.digest().unwrap();
    assert!(validate(&root, &[added]).is_err());
}
#[test]
fn roster_substitution_cannot_keep_the_same_admission() {
    let root = initial_fixture();
    let mut added = addition(&root);
    added.evidence.request.roster.predecessor = HostRosterPredecessorV2::InitialPublicationV2 {
        audit_digest: h('1'),
    };
    assert!(added.validate().is_err());
}
#[test]
fn historical_exact_retry_cannot_replace_a_retained_session_or_deadline() {
    let root = initial_fixture();
    let added = addition(&root);
    added.require_exact_retry(&added).unwrap();
    let mut changed = added.clone();
    changed.evidence.current.writer_session_digest = h('0');
    assert!(changed.require_exact_retry(&added).is_err());
}
#[test]
fn additional_bytes_are_strict_and_do_not_decode_as_first_publication() {
    let added = addition(&initial_fixture());
    let encoded = serde_json::to_value(&added).unwrap();
    assert!(strict::<ManualEnrollmentAdditionalPublicationV3>(&encoded).is_ok());
    assert!(strict::<ManualEnrollmentInitialPublicationV2>(&encoded).is_err());
    let mut unknown = encoded;
    unknown
        .as_object_mut()
        .unwrap()
        .insert("creates_new_budget".into(), true.into());
    assert!(strict::<ManualEnrollmentAdditionalPublicationV3>(&unknown).is_err());
}

fn rebind(a: &mut ManualEnrollmentAdditionalPublicationV3) {
    a.evidence.admission.exact_request_digest = a.evidence.request.digest().unwrap();
}
fn third(
    second: &ManualEnrollmentAdditionalPublicationV3,
) -> ManualEnrollmentAdditionalPublicationV3 {
    let mut a = second.clone();
    a.evidence.request.enrollment.terms.operation_id = "synthetic-third-account-intent".into();
    a.evidence.request.enrollment.terms.identity.account_id = h('4');
    a.evidence
        .request
        .enrollment
        .terms
        .identity
        .full_viewing_key_digest = h('5');
    a.evidence.request.enrollment.terms.scope.participant_id = "synthetic-third-participant".into();
    a.evidence.request.roster.roster_sequence = 3;
    a.evidence.request.roster.predecessor = HostRosterPredecessorV2::AdditionalPublicationV3 {
        audit_digest: second.digest().unwrap(),
    };
    a.aliases = BTreeSet::from([a.terms().identity.account_id.clone()]);
    a.operation_id = "synthetic-third-publication".into();
    a.request_identity_digest = h('0');
    a.store_sequence = 3;
    a.evidence.enrollment_ref = h('6');
    a.evidence.witness_extension_digest = h('7');
    a.evidence.witness_roster_extension_digest = h('8');
    a.evidence.signer_roster_record_digest = h('a');
    a.evidence.admission.attempt_digest = wholepact_core::proposal::canonical_digest(
        "wholepact:manual-roster-enrollment-initial-attempt:v2",
        &a.evidence.witness_roster_extension_digest,
    )
    .unwrap();
    rebind(&mut a);
    a
}
fn successor(
    original: &ManualEnrollmentAdditionalPublicationV3,
) -> ManualEnrollmentContinuationAuditV4 {
    let mut evidence = original.evidence.clone();
    evidence.request.attempt = ManualRosterPublicationAttemptV2::ContinuationV2 {
        continuation_digest: h('0'),
        attempt_sequence: 4,
    };
    evidence.admission.attempt_sequence = 4;
    evidence.admission.attempt_digest = h('0');
    evidence.admission.exact_request_digest = evidence.request.digest().unwrap();
    evidence.admission.admitted_at_ms = 2001;
    evidence.admission.admission_deadline_ms = 3000;
    evidence.current.writer_session_digest = h('7');
    evidence.current.witness_head_sequence = 15;
    ManualEnrollmentContinuationAuditV4 {
        version: 4,
        original_audit: OriginalManualEnrollmentAuditLink::AdditionalPublicationV3 {
            audit_digest: original.digest().unwrap(),
        },
        operation_id: "synthetic-roster-continuation-v4".into(),
        request_identity_digest: h('2'),
        provider_enrollment_ref: original.provider_enrollment_ref.clone(),
        store_sequence: 1,
        predecessor_digest: None,
        aliases: original.aliases.clone(),
        evidence,
    }
}
fn add(
    store: &Store,
    audit: &ManualEnrollmentAdditionalPublicationV3,
    inherited: &[(ManualAccountIdentity, BTreeSet<String>)],
) -> Result<bool> {
    let mut c = store.connection.lock().unwrap();
    let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let inserted = kernel::append_additional_publication_v3(store, &tx, audit, inherited)?;
    tx.commit()?;
    Ok(inserted)
}
fn continue_audit(
    store: &Store,
    audit: &ManualEnrollmentContinuationAuditV4,
    inherited: &[(ManualAccountIdentity, BTreeSet<String>)],
) -> Result<bool> {
    let mut c = store.connection.lock().unwrap();
    let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let inserted = kernel::append_continuation_v4(store, &tx, audit, inherited)?;
    tx.commit()?;
    Ok(inserted)
}
fn root_store() -> (Store, ManualEnrollmentInitialPublicationV2) {
    let store = crate::manual_enrollment::tests::modeled_store();
    let root = initial_fixture();
    crate::manual_enrollment::tests::initial_publication::add_initial(&store, &root, &[]).unwrap();
    (store, root)
}

#[test]
fn immutable_original_comparison_accepts_new_attempt_but_no_wrapper_substitution() {
    let original = addition(&initial_fixture());
    let next = successor(&original);
    let e = &original.evidence;
    original
        .require_immutable_publication_identity(
            &next.evidence.request,
            &e.enrollment_ref,
            &e.witness_extension_digest,
            &e.witness_roster_extension_digest,
            &e.signer_roster_record_digest,
        )
        .unwrap();
    assert!(
        original
            .require_exact_publication_request(
                &serde_json::to_value(&next.evidence.request).unwrap(),
            )
            .is_err()
    );
    original
        .require_exact_publication_request(&serde_json::to_value(&e.request).unwrap())
        .unwrap();
    for field in 0..6 {
        let mut request = next.evidence.request.clone();
        let mut refs = [
            e.enrollment_ref.clone(),
            e.witness_extension_digest.clone(),
            e.witness_roster_extension_digest.clone(),
            e.signer_roster_record_digest.clone(),
        ];
        match field {
            0 => request.enrollment.terms.scope.participant_id = "substituted".into(),
            1 => {
                request.roster.predecessor = HostRosterPredecessorV2::InitialPublicationV2 {
                    audit_digest: h('0'),
                }
            }
            _ => refs[field - 2] = h('1'),
        }
        assert!(
            original
                .require_immutable_publication_identity(
                    &request, &refs[0], &refs[1], &refs[2], &refs[3],
                )
                .is_err(),
            "immutable identity field {field}"
        );
    }
}

#[test]
fn continuation_can_be_first_retained_v3_without_fabricating_initial_admission() {
    let (store, root) = root_store();
    let mut original = addition(&root);
    original.evidence = successor(&original).evidence;
    // The durable Host original records the actual admitted attempt 4, not 1.
    original.validate().unwrap();
    assert!(add(&store, &original, &[]).unwrap());
    assert!(!add(&store, &original, &[]).unwrap());
    let c = store.connection.lock().unwrap();
    let projection =
        project_snapshot(&c, store.recovered_binding.as_ref().unwrap(), &h('c')).unwrap();
    let retained = &projection.additional_publications_v3()[0];
    assert_eq!(retained.evidence.admission.attempt_sequence, 4);
    assert!(matches!(
        retained.evidence.request.attempt,
        ManualRosterPublicationAttemptV2::ContinuationV2 {
            attempt_sequence: 4,
            ..
        }
    ));
    assert!(projection.continuations_v4().is_empty());
    assert!(matches!(
        projection.enrollments()[1].initial_admission(),
        ManualInitialAdmissionProvenance::RosterV2(_)
    ));
}

#[test]
fn current_roster_tip_does_not_replace_original_lookup_or_exact_retry() {
    let (store, root) = root_store();
    let second = addition(&root);
    let third = third(&second);
    assert!(add(&store, &second, &[]).unwrap());
    assert!(add(&store, &third, &[]).unwrap());
    assert!(!add(&store, &second, &[]).unwrap());
    let c = store.connection.lock().unwrap();
    let first = kernel::require_continuation_original_v2(
        &store,
        &c,
        root.terms(),
        &root.evidence.enrollment_ref,
        &root.evidence.witness_extension_digest,
        &[],
    )
    .unwrap();
    assert!(first == root);
    let original = kernel::require_continuation_original_v3(
        &store,
        &c,
        second.terms(),
        &second.evidence.enrollment_ref,
        &second.evidence.witness_extension_digest,
        &[],
    )
    .unwrap();
    assert!(original == second);
    assert!(
        kernel::require_additional_publication_target(
            &store,
            &c,
            second.terms(),
            &second.evidence.request.roster,
            &second.evidence.enrollment_ref,
            &second.evidence.witness_extension_digest,
            &[]
        )
        .unwrap()
            == Some(second.clone())
    );
    // Preserved first-scope API cannot be reused to append into a nonempty roster.
    assert!(
        kernel::require_initial_publication_target(
            &store,
            &c,
            root.terms(),
            &root.evidence.enrollment_ref,
            &root.evidence.witness_extension_digest,
            &[]
        )
        .is_err()
    );
    let mut competing = addition(&root);
    competing.evidence.request.enrollment.terms.operation_id = "competing-intent".into();
    competing
        .evidence
        .request
        .enrollment
        .terms
        .identity
        .account_id = h('a');
    competing
        .evidence
        .request
        .enrollment
        .terms
        .identity
        .full_viewing_key_digest = h('b');
    competing.evidence.enrollment_ref = h('e');
    rebind(&mut competing);
    assert!(matches!(
        kernel::require_additional_publication_target(
            &store,
            &c,
            competing.terms(),
            &competing.evidence.request.roster,
            &competing.evidence.enrollment_ref,
            &competing.evidence.witness_extension_digest,
            &[]
        ),
        Err(StoreError::RevisionConflict)
    ));
    drop(c);
    assert!(
        store
            .authority_account(&second.terms().identity.account_id)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .require_ordinary_financial_lineage(
                &second.terms().scope.agreement_id,
                &second.terms().scope.obligation_id,
                &second.terms().scope.principal_id,
                None,
                &[]
            )
            .is_err()
    );
    assert!(store.recovery_state().unwrap().recovery_required);
}

#[test]
fn continued_original_preserves_all_outer_identities_and_prior_session_fences() {
    let (store, root) = root_store();
    let original = addition(&root);
    let next = successor(&original);
    assert!(continue_audit(&store, &next, &[]).is_err());
    add(&store, &original, &[]).unwrap();
    for field in 0..10 {
        let mut changed = next.clone();
        match field {
            0 => changed.evidence.signer_roster_record_digest = h('1'),
            1 => changed.evidence.witness_roster_extension_digest = h('1'),
            2 => changed.evidence.witness_extension_digest = h('1'),
            3 => changed.provider_enrollment_ref = h('1'),
            4 => changed.evidence.admission.signer_intent_digest = h('1'),
            5 => {
                changed.evidence.current.writer_session_digest =
                    original.evidence.current.writer_session_digest.clone()
            }
            6 => {
                changed.evidence.current.witness_head_sequence =
                    original.evidence.current.witness_head_sequence
            }
            7 => {
                changed.evidence.admission.admitted_at_ms =
                    original.evidence.admission.admission_deadline_ms - 1
            }
            8 => {
                changed.original_audit = OriginalManualEnrollmentAuditLink::InitialPublicationV2 {
                    audit_digest: original.digest().unwrap(),
                }
            }
            _ => changed.predecessor_digest = Some(h('1')),
        }
        assert!(
            continue_audit(&store, &changed, &[]).is_err(),
            "continuation field {field}"
        );
    }
    assert!(continue_audit(&store, &next, &[]).unwrap());
    add(&store, &third(&original), &[]).unwrap();
    assert!(!continue_audit(&store, &next, &[]).unwrap());
    let mut later = next.clone();
    later.store_sequence = 2;
    later.predecessor_digest = Some(next.digest().unwrap());
    later.operation_id = "synthetic-later-continuation-v4".into();
    later.request_identity_digest = h('3');
    later.evidence.request.attempt = ManualRosterPublicationAttemptV2::ContinuationV2 {
        continuation_digest: h('4'),
        attempt_sequence: 7,
    };
    later.evidence.admission.attempt_sequence = 7;
    later.evidence.admission.attempt_digest = h('4');
    later.evidence.admission.exact_request_digest = later.evidence.request.digest().unwrap();
    later.evidence.admission.admitted_at_ms = 3001;
    later.evidence.admission.admission_deadline_ms = 4000;
    later.evidence.current.witness_head_sequence = 18;
    assert!(continue_audit(&store, &later, &[]).is_err()); // Cannot recycle a current session.
    later.evidence.current.writer_session_digest = h('5');
    assert!(continue_audit(&store, &later, &[]).unwrap());
}

#[test]
fn append_and_historical_retry_still_require_generation_inherited_and_retirement_checks() {
    use crate::manual_enrollment::tests::fence;
    let mut kinds = vec![
        "operation",
        "effect",
        "idempotency",
        "agreement",
        "obligation",
        "record",
        "account",
    ];
    for kind in kinds.drain(..) {
        let (store, root) = root_store();
        let original = addition(&root);
        add(&store, &original, &[]).unwrap();
        let key = match kind {
            "operation" | "effect" => original.operation_id.clone(),
            "idempotency" => original.request_identity_digest.clone(),
            "agreement" => original.terms().scope.agreement_id.clone(),
            "obligation" => original.terms().scope.obligation_id.clone(),
            "account" => original.terms().identity.account_id.clone(),
            _ => format!("{ADDITIONAL_PUBLICATION_V3}:{}", original.digest().unwrap()),
        };
        fence(&store, kind, &key);
        assert!(add(&store, &original, &[]).is_err(), "retry fence {kind}");
        assert!(
            continue_audit(&store, &successor(&original), &[]).is_err(),
            "continue fence {kind}"
        );
    }
    let (store, root) = root_store();
    let original = addition(&root);
    fence(&store, "account", "synthetic-inherited-alias");
    assert!(add(&store, &original, &[]).is_err());
    let inherited_identity = ManualAccountIdentity {
        account_id: h('0'),
        full_viewing_key_digest: h('1'),
        network_profile_id: original.terms().identity.network_profile_id.clone(),
        derivation_domain: original.terms().identity.derivation_domain.clone(),
    };
    let known = vec![(
        inherited_identity.clone(),
        BTreeSet::from([
            inherited_identity.account_id.clone(),
            "synthetic-inherited-alias".into(),
        ]),
    )];
    add(&store, &original, &known).unwrap();
    assert!(add(&store, &original, &[]).is_err());
    assert!(!add(&store, &original, &known).unwrap());
    let mut c = store.connection.lock().unwrap();
    let tx = c
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    let excluded = ManualExclusionAudit {
        version: 1,
        operation_id: "synthetic-retirement".into(),
        identity: original.terms().identity.clone(),
        aliases: original.aliases.clone(),
        account_use_genesis_digest: original.terms().account_use_genesis_digest.clone(),
        exclusion_digest: h('1'),
        witness_history_digest: h('2'),
    };
    kernel::append_exclusion(&tx, &excluded).unwrap();
    tx.commit().unwrap();
    drop(c);
    assert!(add(&store, &original, &known).is_err());
    assert!(continue_audit(&store, &successor(&original), &known).is_err());
}

#[test]
fn missing_earlier_roster_row_blocks_exact_retry_and_continuation() {
    let (store, root) = root_store();
    let original = addition(&root);
    let third = third(&original);
    add(&store, &original, &[]).unwrap();
    add(&store, &third, &[]).unwrap();
    {
        let c = store.connection.lock().unwrap();
        c.execute(
            "DELETE FROM records WHERE aggregate_type=?1 AND id=?2",
            rusqlite::params![ADDITIONAL_PUBLICATION_V3, original.digest().unwrap()],
        )
        .unwrap();
    }
    assert!(add(&store, &third, &[]).is_err());
    assert!(continue_audit(&store, &successor(&third), &[]).is_err());
}

#[test]
fn roster_publication_and_continuation_reserve_generic_operation_and_request_namespaces() {
    let (store, root) = root_store();
    let mut original = addition(&root);
    let context = crate::CommandContext::for_request(
        "owner",
        "synthetic-roster-initial-key",
        &serde_json::json!({}),
    )
    .unwrap();
    original.operation_id = crate::operation_id(&context);
    original.request_identity_digest = request_digest(&serde_json::json!([
        &context.principal_id,
        &context.idempotency_key,
    ]))
    .unwrap();
    add(&store, &original, &[]).unwrap();
    assert!(store.find_replay(&context).is_err());
    for operation in [&original.operation_id, &original.terms().operation_id] {
        assert!(
            store
                .record_effect_intent(operation, "none", "resource", &h('f'), "synthetic")
                .is_err()
        );
    }
    let mut next = successor(&original);
    next.request_identity_digest = original.request_identity_digest.clone();
    assert!(continue_audit(&store, &next, &[]).is_err());
    let context = crate::CommandContext::for_request(
        "owner",
        "synthetic-roster-continuation-key",
        &serde_json::json!({}),
    )
    .unwrap();
    next = successor(&original);
    next.operation_id = crate::operation_id(&context);
    next.request_identity_digest = request_digest(&serde_json::json!([
        &context.principal_id,
        &context.idempotency_key,
    ]))
    .unwrap();
    continue_audit(&store, &next, &[]).unwrap();
    assert!(store.find_replay(&context).is_err());
    assert!(
        store
            .record_effect_intent(&next.operation_id, "none", "resource", &h('f'), "synthetic")
            .is_err()
    );
}

#[cfg(all(feature = "manual-admission", target_os = "linux"))]
#[test]
fn early_roster_original_read_checks_all_wrappers_agreement_cas_and_retained_old_head() {
    let (store, root) = root_store();
    let original = addition(&root);
    let create = crate::CommandContext::for_request(
        "owner",
        "synthetic-roster-agreement",
        &serde_json::json!({}),
    )
    .unwrap();
    let agreement = store
        .create_agreement(
            &create,
            &original.terms().scope.agreement_id,
            serde_json::json!({"view":{"agreement":{
                "agreement_id":original.terms().scope.agreement_id,
                "obligation_id":original.terms().scope.obligation_id,
            }}}),
        )
        .unwrap()
        .record;
    let target = store.manual_store_target().unwrap();
    let request: wholepact_signer_origin::manual_roster_v2::HostManualRosterPublicationRequestV2 =
        serde_json::from_value(serde_json::to_value(&original.evidence.request).unwrap()).unwrap();
    let e = &original.evidence;
    assert!(
        store
            .manual_enrollment_roster_request_original(
                &target,
                &agreement,
                &request,
                &e.enrollment_ref,
                &e.witness_extension_digest,
                &e.witness_roster_extension_digest,
                &e.signer_roster_record_digest
            )
            .unwrap()
            .is_none()
    );
    let head = store
        .manual_enrollment_roster_head(&target, &agreement)
        .unwrap();
    assert!(head.binding() == &request.roster);
    add(&store, &original, &[]).unwrap();
    assert!(matches!(
        head.check_current(),
        Err(StoreError::RevisionConflict)
    ));
    add(&store, &third(&original), &[]).unwrap();
    assert!(
        store
            .manual_enrollment_roster_request_original(
                &target,
                &agreement,
                &request,
                &e.enrollment_ref,
                &e.witness_extension_digest,
                &e.witness_roster_extension_digest,
                &e.signer_roster_record_digest
            )
            .unwrap()
            == Some(original.clone())
    );
    for field in 0..4 {
        let mut refs = [
            e.enrollment_ref.clone(),
            e.witness_extension_digest.clone(),
            e.witness_roster_extension_digest.clone(),
            e.signer_roster_record_digest.clone(),
        ];
        refs[field] = h('1');
        assert!(
            store
                .manual_enrollment_roster_request_original(
                    &target, &agreement, &request, &refs[0], &refs[1], &refs[2], &refs[3]
                )
                .is_err(),
            "wrapper {field}"
        );
    }
    let mut changed = agreement.clone();
    changed.payload["owner_client_id"] = "substituted-owner".into();
    assert!(matches!(
        store.manual_enrollment_roster_request_original(
            &target,
            &changed,
            &request,
            &e.enrollment_ref,
            &e.witness_extension_digest,
            &e.witness_roster_extension_digest,
            &e.signer_roster_record_digest
        ),
        Err(StoreError::RevisionConflict)
    ));
    let next = successor(&original);
    let request: wholepact_signer_origin::manual_roster_v2::HostManualRosterPublicationRequestV2 =
        serde_json::from_value(serde_json::to_value(&next.evidence.request).unwrap()).unwrap();
    assert!(
        store
            .manual_enrollment_roster_request_original(
                &target,
                &agreement,
                &request,
                &e.enrollment_ref,
                &e.witness_extension_digest,
                &e.witness_roster_extension_digest,
                &e.signer_roster_record_digest
            )
            .unwrap()
            == Some(original.clone())
    );
    let lower: wholepact_signer_origin::manual_roster_v2::ManualRosterEnrollmentEvidenceV2 =
        serde_json::from_value(serde_json::to_value(e).unwrap()).unwrap();
    lower.validate().unwrap();
    assert!(serde_json::to_value(&lower).unwrap() == serde_json::to_value(e).unwrap());
}

#[test]
fn v1_original_remains_exact_and_readable_after_roster_addition() {
    let store = crate::manual_enrollment::tests::modeled_store();
    let root = initial_fixture();
    let evidence = &root.evidence;
    let legacy = ManualEnrollmentAudit {
        version: 1,
        terms: root.terms().clone(),
        admission: ManualDurableEnrollmentAudit {
            exact_request_digest: enrollment_request_digest(root.terms()).unwrap(),
            signer_intent_digest: evidence.admission.signer_intent_digest.clone(),
            witness_admission_digest: evidence.admission.witness_admission_digest.clone(),
            admitted_at_ms: evidence.admission.admitted_at_ms,
            admission_deadline_ms: evidence.admission.admission_deadline_ms,
        },
        enrollment_ref: evidence.enrollment_ref.clone(),
        witness_extension_digest: evidence.witness_extension_digest.clone(),
        witness_extension_sequence: 1,
        witness_extension_predecessor_digest: None,
        aliases: root.aliases.clone(),
        store_sequence: 1,
        request_identity_digest: root.request_identity_digest.clone(),
        original_provider_enrollment_ref: root.provider_enrollment_ref.clone(),
        original_complete_history_digest: evidence.current.complete_history_digest.clone(),
        original_exclusion_checkpoint_digest: evidence.current.exclusion_checkpoint_digest.clone(),
        original_native_review_digest: evidence.current.native_review_digest.clone(),
    };
    let encoded = serde_json::to_value(&legacy).unwrap();
    {
        let mut c = store.connection.lock().unwrap();
        let tx = c
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        kernel::append_enrollment(&store, &tx, &legacy, &[]).unwrap();
        tx.commit().unwrap();
    }
    let mut additional = addition(&root);
    additional.evidence.request.roster.predecessor = HostRosterPredecessorV2::EnrollmentV1 {
        audit_digest: legacy.digest().unwrap(),
    };
    rebind(&mut additional);
    add(&store, &additional, &[]).unwrap();
    let c = store.connection.lock().unwrap();
    let retained = kernel::require_continuation_original(
        &store,
        &c,
        &legacy.terms,
        &legacy.enrollment_ref,
        &legacy.witness_extension_digest,
    )
    .unwrap();
    assert!(serde_json::to_value(&retained).unwrap() == encoded);
    assert!(retained == legacy);
}

#[test]
fn no_roster_rows_preserves_the_established_initial_projection_digest() {
    let (store, _) = root_store();
    let c = store.connection.lock().unwrap();
    let binding = store.recovered_binding.as_ref().unwrap();
    let expected = domain_digest(
        "wholepact:store-manual-audit-projection:v3",
        &(
            binding.generation_id(),
            binding.inventory_digest(),
            h('c'),
            Vec::<(String, ManualEnrollmentAudit)>::new(),
            Vec::<(String, ManualActionAudit)>::new(),
            Vec::<(String, ManualExclusionAudit)>::new(),
            Vec::<(String, ManualEnrollmentContinuationAudit)>::new(),
            read_audits::<ManualEnrollmentInitialPublicationV2>(&c, INITIAL_PUBLICATION_V2)
                .unwrap(),
            Vec::<(String, ManualEnrollmentContinuationAuditV3)>::new(),
        ),
    )
    .unwrap();
    let projection = project_snapshot(&c, binding, &h('c')).unwrap();
    assert_eq!(projection.digest(), expected);
    assert!(projection.additional_publications_v3().is_empty());
    assert!(projection.continuations_v4().is_empty());
}

/// Synthetic local rows only, appended through the same private transaction
/// kernel as the pure-record tests. This cannot issue a signer/native lease.
pub(crate) fn append_modeled_roster_layer_audits(
    store: &Store,
    root: &ManualEnrollmentInitialPublicationV2,
) -> (
    ManualEnrollmentAdditionalPublicationV3,
    ManualEnrollmentAdditionalPublicationV3,
    ManualEnrollmentContinuationAuditV4,
    ManualExclusionAudit,
) {
    assert_eq!(store.protection, StorageProtection::Encrypted);
    let second = addition(root);
    let third = third(&second);
    let next = successor(&second);
    // Same deliberately modeled inherited owner as the encrypted root fixture.
    // This declaration is never accepted by a production opaque-lease consumer.
    let mut old_identity = root.terms().identity.clone();
    old_identity.account_id = h('8');
    old_identity.full_viewing_key_digest = h('9');
    let inherited = vec![(
        old_identity.clone(),
        BTreeSet::from([old_identity.account_id, "synthetic-account".into()]),
    )];
    assert!(add(store, &second, &inherited).unwrap());
    assert!(add(store, &third, &inherited).unwrap());
    assert!(continue_audit(store, &next, &inherited).unwrap());
    let exclusion = ManualExclusionAudit {
        version: 1,
        operation_id: "synthetic-roster-retirement".into(),
        identity: second.terms().identity.clone(),
        aliases: BTreeSet::from([
            second.terms().identity.account_id.clone(),
            "synthetic-retired-roster-alias".into(),
        ]),
        account_use_genesis_digest: second.terms().account_use_genesis_digest.clone(),
        exclusion_digest: h('3'),
        witness_history_digest: h('4'),
    };
    let mut c = store.connection.lock().unwrap();
    let tx = c
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    assert!(kernel::append_exclusion(&tx, &exclusion).unwrap());
    tx.commit().unwrap();
    (second, third, next, exclusion)
}

mod permanent_stop_record_tests {
    use super::*;
    use crate::manual_enrollment::permanent_stop_record::*;
    fn fixture() -> (ManualEnrollmentAdditionalPublicationV3, ManualPermanentStopPublicationV1) {
        let original = super::addition(&initial_fixture());
        let row = ManualPermanentStopPublicationV1 {
            version: 1, original_host_audit_digest: original.digest().unwrap(), provider_enrollment_ref: original.provider_enrollment_ref.clone(), request_digest: request_digest_for_original(&original).unwrap(),
            exclusion: ManualExclusionAudit { version: 1, operation_id: "synthetic-permanent-stop".into(), identity: original.terms().identity.clone(), aliases: original.aliases.clone(), account_use_genesis_digest: original.terms().account_use_genesis_digest.clone(), exclusion_digest: "1".repeat(64), witness_history_digest: "2".repeat(64) },
            original_witness_receipt_digest: "3".repeat(64), original_witness_head_sequence: 7, original_witness_head_digest: "4".repeat(64), original_native_review_digest: "5".repeat(64),
        }; (original, row)
    }
    #[test]
    fn restriction_publication_requires_both_exact_original_and_exclusion() {
        let (original, row) = fixture(); let rows = vec![(row.digest().unwrap(), row.clone())]; let originals = vec![(original.digest().unwrap(), original)]; let exclusions = vec![(row.exclusion.digest().unwrap(), row.exclusion.clone())];
        validate_permanent_stop_set(&rows, &originals, &exclusions).unwrap();
        assert!(validate_permanent_stop_set(&rows, &[], &exclusions).is_err()); assert!(validate_permanent_stop_set(&rows, &originals, &[]).is_err()); assert!(validate_permanent_stop_set(&[rows[0].clone(), rows[0].clone()], &originals, &exclusions).is_err());
        let mut changed = row.clone(); changed.exclusion.account_use_genesis_digest = "6".repeat(64); assert!(changed.require_original(&originals[0].1).is_err());
        changed = row; changed.provider_enrollment_ref = "6".repeat(64); assert!(changed.require_original(&originals[0].1).is_err());
    }
    #[test]
    fn exact_retry_preserves_first_history_but_never_changes_original_receipt() {
        let (_, first) = fixture(); let mut later = first.clone(); later.exclusion.witness_history_digest = "6".repeat(64); later.original_native_review_digest = "7".repeat(64);
        first.require_same_publication(&later).unwrap(); assert_ne!(first.digest().unwrap(), later.digest().unwrap());
        later.original_witness_receipt_digest = "8".repeat(64); assert!(first.require_same_publication(&later).is_err());
    }
    #[test]
    fn restriction_records_reject_unknown_fields_and_invalid_head() {
        let (_, row) = fixture(); let mut value = serde_json::to_value(&row).unwrap(); value["financial_permission"] = true.into(); assert!(strict::<ManualPermanentStopPublicationV1>(&value).is_err());
        let mut bad = row; bad.original_witness_head_sequence = 0; assert!(bad.validate().is_err());
    }
    #[test]
    fn restriction_history_survives_complete_snapshot_validation_and_rejects_orphans() {
        // Synthetic inert rows only. No live native owner or signer lease is made.
        let store = Store::in_memory().unwrap();
        let c = store.connection.lock().unwrap();
        let root = initial_fixture();
        let (original, publication) = fixture();
        let insert = |kind: &str, digest: String, value: serde_json::Value| {
            c.execute("INSERT INTO records VALUES(?1,?2,0,?3,1,1)",
                rusqlite::params![kind, digest, crate::encode(&value).unwrap()]).unwrap();
        };
        insert(INITIAL_PUBLICATION_V2, root.digest().unwrap(), serde_json::to_value(&root).unwrap());
        insert(ADDITIONAL_PUBLICATION_V3, original.digest().unwrap(), serde_json::to_value(&original).unwrap());
        let binding = GenerationBinding::new(&root.terms().host.generation_id, &root.terms().host.inventory_digest).unwrap();
        let destination = &root.terms().host.store_destination_identity;
        let before = project_snapshot(&c, &binding, destination).unwrap().digest().to_owned();
        insert(EXCLUSION, publication.exclusion.digest().unwrap(), serde_json::to_value(&publication.exclusion).unwrap());
        insert(PERMANENT_STOP_V1, publication.digest().unwrap(), serde_json::to_value(&publication).unwrap());
        construction_claim_union::validate_current(&c).unwrap();
        let after = project_snapshot(&c, &binding, destination).unwrap();
        assert_ne!(before, after.digest());
        assert_eq!(after.exclusions().len(), 1);
        let retained = read_audits::<ManualPermanentStopPublicationV1>(&c, PERMANENT_STOP_V1).unwrap();
        assert!(retained[0].1 == publication);
        c.execute("DELETE FROM records WHERE aggregate_type=?1", [EXCLUSION]).unwrap();
        assert!(construction_claim_union::validate_current(&c).is_err());
        assert!(project_snapshot(&c, &binding, destination).is_err());
    }

}
