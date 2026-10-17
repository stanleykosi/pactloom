//! Pure response/continuity arithmetic only; no authenticated clock instance,
//! native owner, live TLS, persistent credential or spending authority.
use super::*;

fn response(scope: &BornOfflineClockScopeV1) -> BornOfflineClockResponseV1 {
    BornOfflineClockResponseV1 {
        scope: scope.clone(),
        challenge: "33".repeat(32),
        channel_binding: "44".repeat(32),
        witness_time_ms: 5000,
    }
}
fn scope() -> BornOfflineClockScopeV1 {
    BornOfflineClockScopeV1 {
        enrollment_digest: "66".repeat(32),
        artifact_binding_digest: "77".repeat(32),
        witness_id: "synthetic-witness".into(),
        account_id: "synthetic-account".into(),
        network_profile_id: "synthetic-testnet".into(),
        witness_policy_digest: "11".repeat(32),
        operation_id: "synthetic-operation".into(),
        authorization_id: "synthetic-authorization".into(),
        original_request_digest: "22".repeat(32),
        original_admission_digest: "55".repeat(32),
        original_not_before_ms: 3000,
        original_expires_at_ms: 30_000,
    }
}
#[test]
fn fixed_ceiling_charges_full_rtt_and_margin_without_renewal() {
    let scope = scope();
    let reply = response(&scope);
    let start = Instant::now();
    let receive = start + Duration::from_millis(123);
    let ceiling = validate_response(
        &scope,
        &reply.challenge,
        &reply.channel_binding,
        &reply,
        start,
        receive,
        start + Duration::from_secs(120),
    )
    .unwrap();
    assert_eq!(ceiling, receive + Duration::from_millis(23_877));
    let wall = std::time::UNIX_EPOCH + Duration::from_secs(1_000_000);
    for advance in [0, 1, 100, 23_876] {
        let elapsed = Duration::from_millis(advance);
        check_continuity(receive, wall, ceiling, receive + elapsed, wall + elapsed).unwrap();
        assert_eq!(ceiling, receive + Duration::from_millis(23_877));
    }
    assert!(
        check_continuity(
            receive,
            wall,
            ceiling,
            ceiling,
            wall + Duration::from_millis(23_877)
        )
        .is_err()
    );
    let owner_end = receive + Duration::from_secs(2);
    assert_eq!(
        validate_response(
            &scope,
            &reply.challenge,
            &reply.channel_binding,
            &reply,
            start,
            receive,
            owner_end
        )
        .unwrap(),
        owner_end
    );
    let mut long = scope.clone();
    long.original_expires_at_ms = 1_000_000;
    let long_reply = response(&long);
    assert_eq!(
        validate_response(
            &long,
            &long_reply.challenge,
            &long_reply.channel_binding,
            &long_reply,
            start,
            receive,
            start + Duration::from_secs(999)
        )
        .unwrap(),
        receive + MAX_OBSERVATION
    );
}
#[test]
fn response_replay_scope_substitution_slow_roundtrip_and_expiry_are_rejected() {
    let s = scope();
    let start = Instant::now();
    let receive = start + Duration::from_millis(1);
    let end = start + Duration::from_secs(120);
    let validate = |r: &BornOfflineClockResponseV1| {
        validate_response(
            &s,
            &"33".repeat(32),
            &"44".repeat(32),
            r,
            start,
            receive,
            end,
        )
    };
    for change in [0, 1, 2, 3, 4, 5, 6] {
        let mut r = response(&s);
        match change {
            0 => r.challenge = "aa".repeat(32),
            1 => r.channel_binding = "bb".repeat(32),
            2 => r.scope.original_expires_at_ms += 1,
            3 => r.scope.original_request_digest = "cc".repeat(32),
            4 => r.scope.enrollment_digest = "dd".repeat(32),
            5 => r.scope.artifact_binding_digest = "ee".repeat(32),
            _ => r.scope.account_id.push('x'),
        };
        assert!(validate(&r).is_err());
    }
    let mut r = response(&s);
    assert!(
        validate_response(
            &s,
            &r.challenge,
            &r.channel_binding,
            &r,
            start,
            start + MAX_RTT + Duration::from_nanos(1),
            end
        )
        .is_err()
    );
    assert!(
        validate_response(
            &s,
            &r.challenge,
            &r.channel_binding,
            &r,
            receive,
            start,
            end
        )
        .is_err()
    );
    assert!(
        validate_response(
            &s,
            &r.challenge,
            &r.channel_binding,
            &r,
            start,
            receive,
            receive
        )
        .is_err()
    );
    for time in [0, 2999, 28_999, 30_000, u64::MAX] {
        r.witness_time_ms = time;
        assert!(validate(&r).is_err());
    }
}
#[test]
fn suspend_and_wall_clock_discontinuity_cannot_extend_monotonic_evidence() {
    let receive = Instant::now();
    let wall = std::time::UNIX_EPOCH + Duration::from_secs(12345);
    let end = receive + Duration::from_secs(120);
    assert!(
        check_continuity(
            receive,
            wall,
            end,
            receive + Duration::from_secs(1),
            wall + Duration::from_secs(3)
        )
        .is_err()
    );
    assert!(
        check_continuity(
            receive,
            wall,
            end,
            receive + Duration::from_secs(3),
            wall + Duration::from_secs(1)
        )
        .is_err()
    );
    assert!(check_continuity(receive, wall, end, receive, wall - Duration::from_secs(1)).is_err());
}

#[test]
fn born_channel_binding_commits_exact_origin_challenge_and_exporter() {
    let original = scope();
    let challenge = "aa".repeat(32);
    let bound = channel_binding(&[1; 32], &original, &challenge).unwrap();
    assert_ne!(
        bound,
        channel_binding(&[2; 32], &original, &challenge).unwrap()
    );
    assert_ne!(
        bound,
        channel_binding(&[1; 32], &original, &"bb".repeat(32)).unwrap()
    );
    let mut changed = original.clone();
    changed.enrollment_digest = "88".repeat(32);
    assert_ne!(
        bound,
        channel_binding(&[1; 32], &changed, &challenge).unwrap()
    );
    let mut changed = original.clone();
    changed.artifact_binding_digest = "99".repeat(32);
    assert_ne!(
        bound,
        channel_binding(&[1; 32], &changed, &challenge).unwrap()
    );
    assert!(
        serde_json::from_slice::<crate::offline_clock_v1::OfflineClockScopeV1>(
            &serde_json::to_vec(&original).unwrap()
        )
        .is_err()
    );
}
