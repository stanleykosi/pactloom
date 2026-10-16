//! Synthetic historical-admission setup uses the existing test-only issuer. No
//! claim of genuine HPKE enrollment/native consent follows. The tested clock read
//! replays the actual encrypted journal and never creates or changes a permit.
use super::*;
use ring::rand::{SecureRandom, SystemRandom};
use std::os::unix::fs::PermissionsExt;
use wholepact_storage_security::DatabaseKey;

pub(crate) struct Fixture {
    pub(crate) journal: AuthorityJournal,
    pub(crate) scope: OfflineClockScopeV1,
    pub(crate) writer: String,
    owner: String,
    _directory: tempfile::TempDir,
}
pub(crate) fn fixture(owner: String, writer: String) -> Fixture {
    let (mut request, mut account, policy) = crate::offline::tests::fixture();
    account.owner_certificate_digest = owner.clone();
    account.initial_writer_certificate_digest = writer.clone();
    let directory = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let mut key = [0; 32];
    SystemRandom::new().fill(&mut key).unwrap();
    let journal = AuthorityJournal::create_encrypted(
        &directory.path().join("synthetic.sqlite"),
        &DatabaseKey::from_bytes(key),
        account,
    )
    .unwrap();
    journal.synthetic_activate(&writer, 998).unwrap();
    let snapshot = journal
        .snapshot(&writer, &policy.account_id, &policy.network_profile_id)
        .unwrap();
    journal
        .mutate(
            &owner,
            AuthorityMutation::OwnerControl(OwnerControlRequest {
                operation_id: "synthetic-clock-enroll".into(),
                account_id: policy.account_id.clone(),
                network_profile_id: policy.network_profile_id.clone(),
                expected_head: snapshot.head,
                writer_epoch: 1,
                control: OwnerControl::EnrollOfflinePolicy {
                    policy: policy.clone(),
                    expected_previous_digest: None,
                },
            }),
            1000,
        )
        .unwrap();
    request.expected_head = journal
        .snapshot(&writer, &policy.account_id, &policy.network_profile_id)
        .unwrap()
        .head;
    let issuer = OfflineIntentAuthenticationIssuer::for_test(policy.clone()).unwrap();
    let authenticated = issuer
        .bind_verified_intent(
            &request,
            &request.intent,
            &policy.offline_signer_key_digest,
            &policy.witness_transport_key_digest,
            &"09".repeat(32),
        )
        .unwrap();
    let admission = journal
        .commit_offline_for_test(&writer, request, authenticated, 3000)
        .unwrap();
    let scope = OfflineClockScopeV1::from_descriptor(admission.descriptor()).unwrap();
    Fixture {
        journal,
        scope,
        writer,
        owner,
        _directory: directory,
    }
}
fn fixture_default() -> Fixture {
    fixture("11".repeat(32), "22".repeat(32))
}
fn request(scope: &OfflineClockScopeV1) -> OfflineClockRequestV1 {
    OfflineClockRequestV1 {
        scope: scope.clone(),
        challenge: "33".repeat(32),
        channel_binding: "44".repeat(32),
    }
}
#[test]
fn exact_clock_read_samples_after_authentication_and_never_changes_ledger() {
    let f = fixture_default();
    let r = request(&f.scope);
    let before = f
        .journal
        .snapshot(&f.writer, &r.scope.account_id, &r.scope.network_profile_id)
        .unwrap();
    let response = f
        .journal
        .observe_offline_clock_v1(&f.writer, &r, &r.channel_binding, || Ok(9000))
        .unwrap();
    assert!(response.scope == f.scope);
    assert_eq!(response.witness_time_ms, 9000);
    assert_eq!(response.challenge, r.challenge);
    assert_eq!(response.channel_binding, r.channel_binding);
    assert_eq!(response.scope.original_not_before_ms, 3000);
    assert_eq!(response.scope.original_expires_at_ms, 30_000);
    assert!(
        f.journal
            .snapshot(&f.writer, &r.scope.account_id, &r.scope.network_profile_id)
            .unwrap()
            == before
    );
}
#[test]
fn wrong_scope_unknown_operation_and_unauthorized_peer_fail_before_sampling() {
    let f = fixture_default();
    let original = request(&f.scope);
    let mutate: [fn(&mut OfflineClockScopeV1); 10] = [
        |s| s.witness_id.push('x'),
        |s| s.account_id.push('x'),
        |s| s.network_profile_id.push('x'),
        |s| s.witness_policy_digest = "aa".repeat(32),
        |s| s.operation_id.push('x'),
        |s| s.authorization_id.push('x'),
        |s| s.original_request_digest = "bb".repeat(32),
        |s| s.original_admission_digest = "cc".repeat(32),
        |s| s.original_not_before_ms += 1,
        |s| s.original_expires_at_ms += 1,
    ];
    for change in mutate {
        let mut r = original.clone();
        change(&mut r.scope);
        assert!(
            f.journal
                .observe_offline_clock_v1(&f.writer, &r, &r.channel_binding, || panic!(
                    "unvalidated lookup reached clock"
                ))
                .is_err()
        );
    }
    assert!(
        f.journal
            .observe_offline_clock_v1(
                &"ff".repeat(32),
                &original,
                &original.channel_binding,
                || panic!("unauthorized clock")
            )
            .is_err()
    );
    assert!(
        f.journal
            .observe_offline_clock_v1(&f.writer, &original, &"ee".repeat(32), || panic!(
                "wrong channel"
            ))
            .is_err()
    );
}
#[test]
fn backward_or_expired_clock_cannot_renew_original_and_pause_revoke_do_not_erase_history() {
    let f = fixture_default();
    let r = request(&f.scope);
    for time in [0, 2999, 30_000, u64::MAX] {
        assert!(
            f.journal
                .observe_offline_clock_v1(&f.writer, &r, &r.channel_binding, || Ok(time))
                .is_err()
        );
    }
    for (index, control) in [OwnerControl::Pause, OwnerControl::Revoke]
        .into_iter()
        .enumerate()
    {
        let snapshot = f
            .journal
            .snapshot(&f.owner, &r.scope.account_id, &r.scope.network_profile_id)
            .unwrap();
        f.journal
            .mutate(
                &f.owner,
                AuthorityMutation::OwnerControl(OwnerControlRequest {
                    operation_id: format!("synthetic-clock-control-{index}"),
                    account_id: r.scope.account_id.clone(),
                    network_profile_id: r.scope.network_profile_id.clone(),
                    expected_head: snapshot.head,
                    writer_epoch: snapshot.writer_epoch,
                    control,
                }),
                4000 + index as u64,
            )
            .unwrap();
        let response = f
            .journal
            .observe_offline_clock_v1(&f.owner, &r, &r.channel_binding, || Ok(5000))
            .unwrap();
        assert!(response.scope == f.scope);
        assert!(
            f.journal
                .observe_offline_clock_v1(&f.owner, &r, &r.channel_binding, || Ok(3500))
                .is_err()
        );
        let after = f
            .journal
            .snapshot(&f.owner, &r.scope.account_id, &r.scope.network_profile_id)
            .unwrap();
        assert_eq!(after.outstanding_debit_zatoshis, 70);
        assert_eq!(after.reserved_input_value_zatoshis, 100);
    }
}
#[test]
fn wire_scope_is_strict_and_is_not_an_authenticated_clock_factory() {
    let f = fixture_default();
    let mut value = serde_json::to_value(&f.scope).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("approved".into(), true.into());
    assert!(serde_json::from_value::<OfflineClockScopeV1>(value).is_err());
    let r = request(&f.scope);
    let mut value = serde_json::to_value(r).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("witness_time_ms".into(), 9000.into());
    assert!(serde_json::from_value::<OfflineClockRequestV1>(value).is_err());
}
