//! Never-funded pure routing and synthetic in-memory journal fixtures. These do
//! not open sockets, create native owners, prove, sign payments, or read secrets.
use super::*;
use crate::policy::Ledger;

fn ledger_at(f: &crate::construction_transport_handoff_v1::tests::Fixture, count: usize) -> Ledger {
    let mut ledger = Ledger::new(f.birth.request.policy.clone()).unwrap();
    for event in &f.events[..count] {
        ledger.apply(event).unwrap();
    }
    ledger
}

fn scope(
    f: &crate::construction_transport_handoff_v1::tests::Fixture,
) -> ConstructionTransportServingScopeV1 {
    let pending = f.granted.transport.grants[0].clone();
    ConstructionTransportServingScopeV1 {
        pending_digest: pending.digest().unwrap(),
        pending,
    }
}

fn snapshot_request(scope: &ConstructionTransportServingScopeV1) -> WireRequest {
    let a = &scope.pending.grant.authorization.authorization;
    WireRequest::Snapshot {
        account_id: a.account_id.clone(),
        network_profile_id: a.network_profile_id.clone(),
    }
}

fn history_request(scope: &ConstructionTransportServingScopeV1) -> WireRequest {
    let a = &scope.pending.grant.authorization.authorization;
    WireRequest::ReadHistory {
        account_id: a.account_id.clone(),
        network_profile_id: a.network_profile_id.clone(),
        expected_head: scope.pending.committed_head.clone(),
        after_sequence: 0,
        maximum_entries: 16,
    }
}

fn validate(
    scope: &ConstructionTransportServingScopeV1,
    ledger: &Ledger,
    request: &WireRequest,
    now: u64,
) -> Result<()> {
    let a = &scope.pending.grant.authorization.authorization;
    scope.validate_read_request(
        ledger,
        &a.original_session.writer_certificate_digest,
        &a.original_session
            .disclosure
            .pinned_server_certificate_digest,
        request,
        now,
    )
}

#[test]
fn exact_pending_snapshot_and_history_are_read_only_first_frames() {
    let f = crate::construction_transport_handoff_v1::tests::fixture();
    let scope = scope(&f);
    let ledger = ledger_at(&f, 14);
    let before = serde_json::to_vec(&ledger.snapshot).unwrap();
    let operation_count = ledger.operations.len();
    let expires = scope
        .pending
        .grant
        .authorization
        .authorization
        .expires_at_ms;
    for request in [snapshot_request(&scope), history_request(&scope)] {
        assert!(pending_history_request(0, &request));
        for stage in 1..=4 {
            assert!(!pending_history_request(stage, &request));
        }
        validate(&scope, &ledger, &request, 253_010).unwrap();
        validate(&scope, &ledger, &request, expires - 1).unwrap();
    }
    assert_eq!(serde_json::to_vec(&ledger.snapshot).unwrap(), before);
    assert_eq!(ledger.operations.len(), operation_count);
    assert!(
        ledger
            .construction_transport_history_v1()
            .credentials
            .is_empty()
    );
    assert_eq!(
        scope
            .pending
            .grant
            .authorization
            .authorization
            .expires_at_ms,
        expires
    );
}

#[test]
fn pending_read_routing_never_accepts_claim_observe_mutation_or_resolution() {
    let f = crate::construction_transport_handoff_v1::tests::fixture();
    let scope = scope(&f);
    let ledger = ledger_at(&f, 14);
    let AuthorityMutation::ClaimConstructionTransportV1(claim) = &f.events[14].mutation else {
        panic!("synthetic claim")
    };
    let AuthorityMutation::UseConstructionTransportV1(reserve) = &f.events[15].mutation else {
        panic!("synthetic reserve")
    };
    let AuthorityMutation::UseConstructionTransportV1(consume) = &f.events[16].mutation else {
        panic!("synthetic consume")
    };
    let proof = ConstructionTransportProofV1 {
        credential_id: claim.claim.credential_id.clone(),
        tag: "00".repeat(32),
    };
    let a = &scope.pending.grant.authorization.authorization;
    for request in [
        WireRequest::ClaimConstructionTransport {
            claim: claim.clone(),
        },
        WireRequest::ObserveConstructionTransport {
            credential_id: proof.credential_id.clone(),
            proof: proof.clone(),
        },
        WireRequest::MutateConstructionTransport {
            request: reserve.clone(),
            proof: proof.clone(),
        },
        WireRequest::MutateConstructionTransport {
            request: consume.clone(),
            proof,
        },
        WireRequest::Mutate {
            mutation: Box::new(f.old_reservation.mutation.clone()),
            session_proof: None,
        },
        WireRequest::ResolveReservation {
            account_id: a.account_id.clone(),
            network_profile_id: a.network_profile_id.clone(),
            reservation_operation_id: "synthetic-reservation".into(),
            conflict: None,
        },
    ] {
        for stage in 0..=4 {
            assert!(!pending_history_request(stage, &request));
        }
        assert!(matches!(
            validate(&scope, &ledger, &request, 253_010),
            Err(AuthorityError::Permission)
        ));
    }
}

#[test]
fn pending_reads_reject_account_network_peer_server_and_selected_grant_substitutions() {
    let f = crate::construction_transport_handoff_v1::tests::fixture();
    let scope = scope(&f);
    let ledger = ledger_at(&f, 14);
    for mut request in [snapshot_request(&scope), history_request(&scope)] {
        match &mut request {
            WireRequest::Snapshot { account_id, .. }
            | WireRequest::ReadHistory { account_id, .. } => {
                *account_id = "substituted-account".into()
            }
            _ => unreachable!(),
        }
        assert!(matches!(
            validate(&scope, &ledger, &request, 253_010),
            Err(AuthorityError::Permission)
        ));
    }
    for mut request in [snapshot_request(&scope), history_request(&scope)] {
        match &mut request {
            WireRequest::Snapshot {
                network_profile_id, ..
            }
            | WireRequest::ReadHistory {
                network_profile_id, ..
            } => *network_profile_id = "substituted-network".into(),
            _ => unreachable!(),
        }
        assert!(matches!(
            validate(&scope, &ledger, &request, 253_010),
            Err(AuthorityError::Permission)
        ));
    }
    let a = &scope.pending.grant.authorization.authorization;
    let request = snapshot_request(&scope);
    for peer in [&ledger.policy.owner_certificate_digest, &"fe".repeat(32)] {
        assert!(matches!(
            scope.validate_read_request(
                &ledger,
                peer,
                &a.original_session
                    .disclosure
                    .pinned_server_certificate_digest,
                &request,
                253_010
            ),
            Err(AuthorityError::Authentication)
        ));
    }
    assert!(matches!(
        scope.validate_read_request(
            &ledger,
            &a.original_session.writer_certificate_digest,
            &"fe".repeat(32),
            &request,
            253_010
        ),
        Err(AuthorityError::Authentication)
    ));
    let mut substituted = scope.clone();
    substituted.pending_digest = "fe".repeat(32);
    assert!(validate(&substituted, &ledger, &request, 253_010).is_err());
    let mut substituted = scope.clone();
    substituted.pending.committed_head.digest = "fe".repeat(32);
    assert!(matches!(
        validate(&substituted, &ledger, &request, 253_010),
        Err(AuthorityError::InvalidBinding)
    ));
}

#[test]
fn pending_reads_reject_stale_heads_and_out_of_bounds_pages() {
    let f = crate::construction_transport_handoff_v1::tests::fixture();
    let scope = scope(&f);
    let ledger = ledger_at(&f, 14);
    for change_sequence in [false, true] {
        let mut request = history_request(&scope);
        let WireRequest::ReadHistory { expected_head, .. } = &mut request else {
            unreachable!()
        };
        if change_sequence {
            expected_head.sequence -= 1;
        } else {
            expected_head.digest = "fe".repeat(32);
        }
        assert!(matches!(
            validate(&scope, &ledger, &request, 253_010),
            Err(AuthorityError::StaleHead)
        ));
    }
    for (after, maximum) in [
        (0, 0),
        (0, 17),
        (scope.pending.committed_head.sequence + 1, 16),
    ] {
        let mut request = history_request(&scope);
        let WireRequest::ReadHistory {
            after_sequence,
            maximum_entries,
            ..
        } = &mut request
        else {
            unreachable!()
        };
        *after_sequence = after;
        *maximum_entries = maximum;
        assert!(matches!(
            validate(&scope, &ledger, &request, 253_010),
            Err(AuthorityError::Limit)
        ));
    }
    let before_grant = ledger_at(&f, 13);
    assert!(validate(&scope, &before_grant, &snapshot_request(&scope), 253_010).is_err());
}

#[test]
fn pending_reads_require_exact_active_original_session_and_retained_identity() {
    let f = crate::construction_transport_handoff_v1::tests::fixture();
    let scope = scope(&f);
    let request = snapshot_request(&scope);
    for substitution in 0..7 {
        let mut ledger = ledger_at(&f, 14);
        let session_id = ledger
            .snapshot
            .active_writer_session
            .as_ref()
            .unwrap()
            .session_id
            .clone();
        match substitution {
            0 => {
                ledger
                    .snapshot
                    .active_writer_session
                    .as_mut()
                    .unwrap()
                    .session_id = "fe".repeat(32)
            }
            1 => {
                ledger
                    .snapshot
                    .active_writer_session
                    .as_mut()
                    .unwrap()
                    .expires_at_ms += 1
            }
            2 => ledger.snapshot.writer_epoch += 1,
            3 => ledger.snapshot.writer_certificate_digest = "fe".repeat(32),
            4 => {
                ledger.sessions.remove(&session_id);
            }
            5 => {
                ledger.activated_sessions.remove(&session_id);
            }
            6 => ledger.snapshot.active_writer_session = None,
            _ => unreachable!(),
        }
        assert!(validate(&scope, &ledger, &request, 253_010).is_err());
    }
}

#[test]
fn expired_or_claimed_grants_cannot_read_or_revive_the_old_session() {
    let f = crate::construction_transport_handoff_v1::tests::fixture();
    let scope = scope(&f);
    let ledger = ledger_at(&f, 14);
    let a = &scope.pending.grant.authorization.authorization;
    for request in [snapshot_request(&scope), history_request(&scope)] {
        for now in [
            a.authorized_at_ms - 1,
            scope.pending.grant.granted_at_ms - 1,
            a.expires_at_ms,
            a.expires_at_ms + 1,
        ] {
            assert!(matches!(
                validate(&scope, &ledger, &request, now),
                Err(AuthorityError::Expired)
            ));
        }
        let mut claimed = ledger_at(&f, 15);
        assert!(matches!(
            validate(&scope, &claimed, &request, 253_020),
            Err(AuthorityError::StaleHead)
        ));
        // Even a substituted cached head cannot hide the retained old-key fence.
        claimed.snapshot.head = scope.pending.committed_head.clone();
        assert!(matches!(
            validate(&scope, &claimed, &request, 253_020),
            Err(AuthorityError::SessionRequired)
        ));
        assert!(
            claimed
                .require_unfenced_transport(&a.original_session.session_id)
                .is_err()
        );
        assert_eq!(
            claimed
                .construction_transport_history_v1()
                .credentials
                .len(),
            1
        );
    }
}

#[test]
fn maintained_page_builder_reads_exact_synthetic_pending_history_without_changes() {
    let f = crate::construction_transport_handoff_v1::tests::fixture();
    let scope = scope(&f);
    let connection = rusqlite::Connection::open_in_memory().unwrap();
    connection
        .execute_batch(include_str!("schema.sql"))
        .unwrap();
    connection
        .execute_batch(include_str!("pending_birth_schema.sql"))
        .unwrap();
    connection
        .execute(
            "INSERT INTO authority_pending_birth_commit VALUES(1,?1,?2,?3)",
            rusqlite::params![
                f.birth.request.operation_id,
                f.birth.request_digest,
                serde_json::to_string(&f.birth).unwrap()
            ],
        )
        .unwrap();
    let mut ledger = Ledger::new(f.birth.request.policy.clone()).unwrap();
    for event in &f.events[..14] {
        let previous = ledger.snapshot.head.digest.clone();
        ledger.apply(event).unwrap();
        connection
            .execute(
                "INSERT INTO authority_events VALUES(?1,?2,?3,?4,?5)",
                rusqlite::params![
                    ledger.snapshot.head.sequence,
                    event.mutation.operation_id(),
                    previous,
                    ledger.snapshot.head.digest,
                    &*crate::encode(event).unwrap()
                ],
            )
            .unwrap();
    }
    let changes = connection.total_changes();
    let tx =
        rusqlite::Transaction::new_unchecked(&connection, rusqlite::TransactionBehavior::Deferred)
            .unwrap();
    let mut after = 0;
    let mut seen = Vec::new();
    loop {
        let ledger = ledger_at(&f, 14);
        let mut request = history_request(&scope);
        let WireRequest::ReadHistory {
            after_sequence,
            maximum_entries,
            ..
        } = &mut request
        else {
            unreachable!()
        };
        *after_sequence = after;
        *maximum_entries = 3;
        validate(&scope, &ledger, &request, 253_010).unwrap();
        let page =
            crate::journal::history_page_at(&tx, ledger, &scope.pending.committed_head, after, 3)
                .unwrap();
        assert!(page.snapshot.head == scope.pending.committed_head);
        assert!(page.pending_birth_commit.as_ref() == Some(&f.birth));
        assert!(page.entries.len() <= 3);
        crate::encode(&WireResponse::History(Box::new(page.clone()))).unwrap();
        seen.extend(page.entries.into_iter().map(|entry| entry.sequence));
        match page.next_after_sequence {
            Some(next) => {
                assert!(next > after);
                after = next;
            }
            None => break,
        }
    }
    assert_eq!(
        seen,
        (1..=scope.pending.committed_head.sequence).collect::<Vec<_>>()
    );
    assert_eq!(tx.total_changes(), changes);
    assert!(matches!(
        crate::journal::history_page_at(
            &tx,
            ledger_at(&f, 15),
            &scope.pending.committed_head,
            0,
            16
        ),
        Err(AuthorityError::StaleHead)
    ));
    assert!(matches!(
        crate::journal::history_page_at(
            &tx,
            ledger_at(&f, 14),
            &scope.pending.committed_head,
            0,
            17
        ),
        Err(AuthorityError::Limit)
    ));
}

#[test]
fn pending_read_completion_rejects_clock_rollback_and_original_expiry() {
    require_pending_read_finish(10, 10, 20).unwrap();
    require_pending_read_finish(10, 19, 20).unwrap();
    for (start, finish, expiry) in [(10, 9, 20), (10, 20, 20), (10, 21, 20)] {
        assert!(matches!(
            require_pending_read_finish(start, finish, expiry),
            Err(AuthorityError::Expired)
        ));
    }
}

#[test]
fn offline_clock_v1_is_never_admitted_by_the_dedicated_handoff_read_route() {
    use crate::offline_clock_v1::{OfflineClockRequestV1, OfflineClockScopeV1};
    let f = crate::construction_transport_handoff_v1::tests::fixture();
    let scope = scope(&f);
    let ledger = ledger_at(&f, 14);
    let a = &scope.pending.grant.authorization.authorization;
    let request = WireRequest::ObserveOfflineAdmissionTimeV1(Box::new(OfflineClockRequestV1 {
        scope: OfflineClockScopeV1 {
            witness_id: ledger.policy.witness_id.clone(),
            account_id: a.account_id.clone(),
            network_profile_id: a.network_profile_id.clone(),
            witness_policy_digest: ledger.policy.policy_digest().unwrap(),
            operation_id: "synthetic-clock-operation".into(),
            authorization_id: "synthetic-clock-authorization".into(),
            original_request_digest: "11".repeat(32),
            original_admission_digest: "22".repeat(32),
            original_not_before_ms: 253_000,
            original_expires_at_ms: 300_000,
        },
        challenge: "33".repeat(32),
        channel_binding: "44".repeat(32),
    }));
    for stage in 0..=4 {
        assert!(!pending_history_request(stage, &request));
    }
    assert!(matches!(
        validate(&scope, &ledger, &request, 253_010),
        Err(AuthorityError::Permission)
    ));
}
