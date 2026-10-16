//! Synthetic data/replay and encrypted fixtures only. No native approval, live
//! fixed namespace, credentials, sockets, production key or financial execution.
use super::*;
use crate::account_use::{
    AccountUseGenesis, AccountUseIdentity, ExclusionReason, PermanentAccountExclusion,
};
use crate::account_use_link::account_use_witness_origin_digest;
use crate::pending_birth::PendingBirthRequest;
use crate::policy::{Event, Ledger};
use wholepact_core::manual_enrollment::*;
fn h(c: char) -> String {
    c.to_string().repeat(64)
}
fn request() -> PendingBirthRequest {
    let mut policy = AccountPolicy {
        account_use_genesis: None,
        witness_id: "test-witness".into(),
        account_id: h('1'),
        network_profile_id: "test-network".into(),
        owner_certificate_digest: h('2'),
        initial_writer_certificate_digest: h('3'),
        initial_writer_epoch: 1,
        enrollment_refs: vec![h('c')],
        agreement_ids: vec!["manual-only".into()],
        recipient_scope_digests: vec![h('4')],
        aggregate_budget_zatoshis: 100,
        per_operation_limit_zatoshis: 100,
        maximum_fee_share_zatoshis: 5,
        maximum_transaction_fee_zatoshis: 5,
        maximum_permit_lifetime_ms: 1000,
        policy_expires_at_ms: 100_000,
    };
    let terms = wholepact_core::proposal::canonical_digest(
        "wholepact:account-birth-original-policy-terms:v1",
        &policy,
    )
    .unwrap();
    let mut disclosure = WitnessDisclosureDescriptor {
        endpoint: "127.0.0.1:1911".into(),
        server_name: "localhost".into(),
        witness_id: policy.witness_id.clone(),
        account_id: policy.account_id.clone(),
        network_profile_id: policy.network_profile_id.clone(),
        policy_digest: h('0'),
        pinned_server_certificate_digest: h('5'),
    };
    policy.account_use_genesis = Some(AccountUseGenesis {
        version: 1,
        identity: AccountUseIdentity {
            account_id: policy.account_id.clone(),
            full_viewing_key_digest: h('6'),
            network_profile_id: policy.network_profile_id.clone(),
            derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
        },
        witness_id: policy.witness_id.clone(),
        witness_origin_digest: account_use_witness_origin_digest(&disclosure).unwrap(),
        owner_certificate_digest: policy.owner_certificate_digest.clone(),
        native_birth_digest: h('7'),
    });
    disclosure.policy_digest = policy.policy_digest().unwrap();
    PendingBirthRequest {
        version: 1,
        operation_id: "birth-test-operation".into(),
        generation_instance_id: h('8'),
        native_birth_digest: h('7'),
        original_terms_digest: terms,
        original_target_digest: h('9'),
        disclosure,
        policy,
        issued_at_ms: 1000,
        initial_commit_deadline_ms: 2000,
    }
}

pub(crate) fn fixture() -> (PendingBirthCommitRecord, ManualEnrollmentExtension) {
    let request = request();
    let birth = PendingBirthCommitRecord {
        version: 1,
        request_digest: request.digest().unwrap(),
        authenticated_owner_certificate_digest: request.policy.owner_certificate_digest.clone(),
        request,
        owner_approval_evidence_digest: h('a'),
        local_target_digest: h('d'),
        local_owner_review_digest: h('e'),
        committed_at_ms: 1500,
    };
    let g = birth.request.policy.account_use_genesis.as_ref().unwrap();
    let extension = ManualEnrollmentExtension {
        version: 1,
        enrollment_ref: h('b'),
        enrollment_record_digest: h('b'),
        sequence: 1,
        predecessor_digest: None,
        terms: BornManualEnrollmentTerms {
            version: 1,
            operation_id: "manual-enroll-fixture".into(),
            identity: ManualAccountIdentity {
                account_id: g.identity.account_id.clone(),
                full_viewing_key_digest: g.identity.full_viewing_key_digest.clone(),
                network_profile_id: g.identity.network_profile_id.clone(),
                derivation_domain: g.identity.derivation_domain.clone(),
            },
            birth_request_digest: birth.request_digest.clone(),
            birth_commit_digest: original_birth_commit_digest(&birth).unwrap(),
            native_birth_digest: g.native_birth_digest.clone(),
            original_policy_digest: birth.request.policy.policy_digest().unwrap(),
            account_use_genesis_digest: g.digest().unwrap(),
            original_witness_origin_digest: g.witness_origin_digest.clone(),
            host: ManualHostGenerationBinding {
                generation_id: h('1'),
                inventory_digest: h('2'),
                generation_plan_digest: h('3'),
                financial_journal_origin_digest: h('4'),
                store_destination_identity: h('5'),
                profile_id: "synthetic-profile".into(),
                canonical_root: "/synthetic/host".into(),
                destination_identity_digest: h('6'),
                inherited_identity_digest: h('7'),
                scope_predecessor_digest: None,
            },
            signer: BornManualSignerBinding {
                enrollment_generation_id: h('8'),
                signer_target_digest: h('9'),
                original_envelope_digest: h('a'),
                owner_certificate_digest: birth.request.policy.owner_certificate_digest.clone(),
                writer_certificate_digest: birth
                    .request
                    .policy
                    .initial_writer_certificate_digest
                    .clone(),
                writer_epoch: 1,
                native_signer_measurement: h('b'),
            },
            scope: BornManualScope {
                agreement_id: "manual-only".into(),
                obligation_id: "synthetic-new-obligation".into(),
                participant_id: "synthetic-participant".into(),
                principal_id: "synthetic-principal".into(),
                privacy_domain: "synthetic-shared-domain".into(),
                recipient_scope_digests: vec![h('4')],
                aggregate_budget_zatoshis: 80,
                per_operation_limit_zatoshis: 50,
                maximum_fee_share_zatoshis: 3,
                maximum_transaction_fee_zatoshis: 3,
                maximum_permit_lifetime_ms: 1000,
                expires_at_ms: 90_000,
            },
            transport_binding_digest: h('c'),
            issued_at_ms: 3000,
        },
    };
    extension.validate_original_birth(&birth).unwrap();
    (birth, extension)
}
pub(crate) fn extension_event(ledger: &Ledger, extension: &ManualEnrollmentExtension) -> Event {
    Event {
        mutation: AuthorityMutation::OwnerControl(OwnerControlRequest {
            operation_id: extension.owner_operation_id().unwrap(),
            account_id: ledger.policy.account_id.clone(),
            network_profile_id: ledger.policy.network_profile_id.clone(),
            writer_epoch: 1,
            expected_head: ledger.snapshot.head.clone(),
            control: OwnerControl::ExtendManualEnrollment {
                record: Box::new(ManualEnrollmentExtensionRecord {
                    extension: extension.clone(),
                    owner_signature_evidence_digest: h('d'),
                    native_review_digest: h('e'),
                }),
            },
        }),
        authenticated_certificate_digest: ledger.policy.owner_certificate_digest.clone(),
        witness_time_ms: 4000,
        writer_session_id: None,
        original_request_link: None,
    }
}
pub(crate) fn bootstrap_events() -> (
    PendingBirthCommitRecord,
    ManualEnrollmentExtension,
    Vec<Event>,
    Ledger,
) {
    let (birth, extension) = fixture();
    let mut ledger = Ledger::new(birth.request.policy.clone()).unwrap();
    let mut events = vec![extension_event(&ledger, &extension)];
    ledger.apply(events.last().unwrap()).unwrap();
    let session_id = crate::session::session_id(&[0x33; 32]);
    let acquire = Event {
        mutation: AuthorityMutation::AcquireWriter(AcquireWriterRequest {
            operation_id: extension.acquire_operation_id().unwrap(),
            account_id: ledger.policy.account_id.clone(),
            network_profile_id: ledger.policy.network_profile_id.clone(),
            writer_epoch: 1,
            expected_head: ledger.snapshot.head.clone(),
            reconciled_history_digest: crate::session::history_digest(&ledger.snapshot).unwrap(),
            session_id: session_id.clone(),
            disclosure: birth.request.disclosure.clone(),
        }),
        authenticated_certificate_digest: ledger.policy.initial_writer_certificate_digest.clone(),
        witness_time_ms: 5000,
        writer_session_id: None,
        original_request_link: None,
    };
    ledger
        .require_manual_bootstrap_scope(&extension.digest().unwrap(), &acquire.mutation, 5000)
        .unwrap();
    ledger.apply(&acquire).unwrap();
    events.push(acquire);
    let activate = Event {
        mutation: AuthorityMutation::OwnerControl(OwnerControlRequest {
            operation_id: "synthetic-native-activate".into(),
            account_id: ledger.policy.account_id.clone(),
            network_profile_id: ledger.policy.network_profile_id.clone(),
            writer_epoch: 1,
            expected_head: ledger.snapshot.head.clone(),
            control: OwnerControl::ActivateWriter {
                session_id: session_id.clone(),
            },
        }),
        authenticated_certificate_digest: ledger.policy.owner_certificate_digest.clone(),
        witness_time_ms: 6000,
        writer_session_id: None,
        original_request_link: None,
    };
    ledger
        .require_manual_bootstrap_scope(&extension.digest().unwrap(), &activate.mutation, 6000)
        .unwrap();
    ledger.apply(&activate).unwrap();
    events.push(activate);
    let admit = Event {
        mutation: AuthorityMutation::AdmitBornManualEnrollment(
            BornManualEnrollmentAdmissionRequest {
                version: 1,
                operation_id: extension.admission_operation_id().unwrap(),
                account_id: ledger.policy.account_id.clone(),
                network_profile_id: ledger.policy.network_profile_id.clone(),
                extension_digest: extension.digest().unwrap(),
                enrollment_ref: extension.enrollment_ref.clone(),
                writer_epoch: 1,
                expected_head: ledger.snapshot.head.clone(),
                session_id: session_id.clone(),
            },
        ),
        authenticated_certificate_digest: ledger.policy.initial_writer_certificate_digest.clone(),
        witness_time_ms: 7000,
        writer_session_id: Some(session_id),
        original_request_link: None,
    };
    ledger.apply(&admit).unwrap();
    events.push(admit);
    (birth, extension, events, ledger)
}
#[test]
fn exact_first_extension_and_bootstrap_preserve_original_refs_policy_and_budget() {
    let (birth, extension, events, ledger) = bootstrap_events();
    assert!(ledger.policy == birth.request.policy);
    assert!(
        !ledger
            .policy
            .enrollment_refs
            .contains(&extension.enrollment_ref)
    );
    assert_eq!(ledger.snapshot.aggregate_budget_zatoshis, 100);
    assert_eq!(ledger.snapshot.outstanding_debit_zatoshis, 0);
    assert_eq!(ledger.snapshot.settled_debit_zatoshis, 0);
    assert_eq!(ledger.snapshot.writer_epoch, 1);
    assert!(ledger.snapshot.active_writer_session.is_some());
    assert_eq!(ledger.snapshot.head.sequence, 4);
    let mut replay = Ledger::new(birth.request.policy.clone()).unwrap();
    for event in events {
        replay.apply(&event).unwrap();
    }
    replay.validate_manual_birth(Some(&birth)).unwrap();
    assert!(replay.snapshot == ledger.snapshot);
}
#[test]
fn changed_birth_identity_scope_policy_or_owner_never_reinterprets_original() {
    let (birth, exact) = fixture();
    let changes: [fn(&mut ManualEnrollmentExtension); 13] = [
        (|e| e.terms.identity.full_viewing_key_digest = h('f')),
        (|e| e.terms.birth_request_digest = h('f')),
        (|e| e.terms.original_policy_digest = h('f')),
        (|e| e.terms.signer.owner_certificate_digest = h('f')),
        (|e| e.terms.signer.writer_epoch = 2),
        (|e| e.terms.scope.aggregate_budget_zatoshis = 101),
        (|e| e.terms.scope.maximum_fee_share_zatoshis = 6),
        (|e| e.terms.scope.maximum_permit_lifetime_ms = 1001),
        (|e| e.terms.scope.expires_at_ms = 100_001),
        (|e| e.terms.scope.agreement_id = "other".into()),
        (|e| e.terms.scope.recipient_scope_digests = vec![h('f')]),
        (|e| e.terms.issued_at_ms = 1499),
        (|e| e.enrollment_ref = h('c')),
    ];
    for change in changes {
        let mut e = exact.clone();
        change(&mut e);
        assert!(e.validate_original_birth(&birth).is_err());
    }
    let mut changed = birth.clone();
    changed.committed_at_ms = 1600;
    assert!(exact.validate_original_birth(&changed).is_err());
}
#[test]
fn successor_or_replacement_extension_is_not_an_implicit_budget_reset() {
    let (birth, mut e) = fixture();
    e.sequence = 2;
    e.predecessor_digest = Some(h('e'));
    assert!(e.validate().is_err());
    let (_, e) = fixture();
    let mut ledger = Ledger::new(birth.request.policy).unwrap();
    let first = extension_event(&ledger, &e);
    ledger.apply(&first).unwrap();
    let mut other = e.clone();
    other.enrollment_ref = h('f');
    other.enrollment_record_digest = h('f');
    let second = extension_event(&ledger, &other);
    assert!(ledger.apply(&second).is_err());
    assert_eq!(ledger.snapshot.head.sequence, 1);
}
#[test]
fn live_retry_cannot_extend_fixed_publication_deadline_or_change_operation() {
    let (_, e, events, mut ledger) = bootstrap_events();
    let exact = events.last().unwrap();
    let before = ledger.snapshot.clone();
    ledger
        .require_manual_bootstrap_scope(&e.digest().unwrap(), &exact.mutation, 8000)
        .unwrap();
    let result = ledger.apply(exact).unwrap();
    let MutationResult::ManualEnrollmentAdmitted(record) = result else {
        panic!("wrong synthetic result");
    };
    assert_eq!(record.admitted_at_ms, 7000);
    assert_eq!(record.publication_expires_at_ms, 90_000);
    assert!(ledger.snapshot == before);
    assert!(
        ledger
            .require_manual_bootstrap_scope(&e.digest().unwrap(), &exact.mutation, 90_000)
            .is_err()
    );
    let mut changed = exact.clone();
    let AuthorityMutation::AdmitBornManualEnrollment(r) = &mut changed.mutation else {
        panic!("request");
    };
    r.session_id = h('d');
    assert!(ledger.apply(&changed).is_err());
}
#[test]
fn bootstrap_route_denies_non_enrollment_controls_and_wrong_session_or_scope() {
    let (_, e, events, ledger) = bootstrap_events();
    for control in [
        OwnerControl::Pause,
        OwnerControl::Revoke,
        OwnerControl::RequireRecovery,
        OwnerControl::ReplaceWriter {
            writer_certificate_digest: h('f'),
        },
    ] {
        let m = AuthorityMutation::OwnerControl(OwnerControlRequest {
            operation_id: "forbidden".into(),
            account_id: ledger.policy.account_id.clone(),
            network_profile_id: ledger.policy.network_profile_id.clone(),
            writer_epoch: 1,
            expected_head: ledger.snapshot.head.clone(),
            control,
        });
        assert!(
            ledger
                .require_manual_bootstrap_scope(&e.digest().unwrap(), &m, 8000)
                .is_err()
        );
    }
    assert!(
        ledger
            .require_manual_bootstrap_scope(&h('f'), &events.last().unwrap().mutation, 8000)
            .is_err()
    );
    let mut acquire = events[1].mutation.clone();
    let AuthorityMutation::AcquireWriter(r) = &mut acquire else {
        panic!("acquire");
    };
    r.operation_id = "new-session-after-loss".into();
    assert!(
        ledger
            .require_manual_bootstrap_scope(&e.digest().unwrap(), &acquire, 8000)
            .is_err()
    );
}
#[test]
fn permanent_exclusion_and_unknown_legacy_are_denied() {
    let (birth, e, _, mut ledger) = bootstrap_events();
    let genesis = birth.request.policy.account_use_genesis.as_ref().unwrap();
    ledger
        .account_use_history
        .exclude(PermanentAccountExclusion {
            version: 1,
            identity: genesis.identity.clone(),
            genesis_digest: genesis.digest().unwrap(),
            operation_id: "retire".into(),
            native_review_digest: h('a'),
            reason: ExclusionReason::RetirementRequested,
        })
        .unwrap();
    assert!(ledger.require_supported_manual_history().is_err());
    let mut legacy = birth.request.policy;
    legacy.account_use_genesis = None;
    assert!(e.validate_original_policy(&legacy).is_err());
    assert!(
        Ledger::new(legacy)
            .unwrap()
            .require_supported_manual_history()
            .is_err()
    );
}
#[test]
fn unsupported_mutation_history_is_not_projected_to_empty_manual_history() {
    let (_, _, _, mut ledger) = bootstrap_events();
    let mutation = AuthorityMutation::OwnerControl(OwnerControlRequest {
        operation_id: "unknown-prior-use".into(),
        account_id: ledger.policy.account_id.clone(),
        network_profile_id: ledger.policy.network_profile_id.clone(),
        writer_epoch: 1,
        expected_head: ledger.snapshot.head.clone(),
        control: OwnerControl::Pause,
    });
    ledger.operations.insert(
        "unknown-prior-use".into(),
        (
            mutation,
            ledger.policy.owner_certificate_digest.clone(),
            MutationResult::Controlled(ledger.snapshot.clone()),
        ),
    );
    assert!(matches!(
        ledger.require_supported_manual_history(),
        Err(AuthorityError::OfflineHistoryUnsupported)
    ));
}
