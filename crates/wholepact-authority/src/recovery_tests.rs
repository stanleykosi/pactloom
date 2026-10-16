//! Synthetic in-process fixtures; no live credentials or financial execution.
use super::*;

#[test]
fn recovery_replacement_preserves_all_exposure_and_fences_old_writer() {
    let dir = private_dir();
    let j = create(dir.path());
    let original_request = request(&snapshot(&j).head, 1, 60);
    let original = mutate(&j, original_request.clone()).unwrap();
    let before = snapshot(&j);
    let after = control(
        &j,
        "recovery-operation",
        OwnerControl::RecoverWriter {
            writer_certificate_digest: h('f'),
            inventory_digest: h('9'),
        },
    );
    let exact = OwnerControlRequest {
        operation_id: "recovery-operation".into(),
        account_id: before.account_id.clone(),
        network_profile_id: before.network_profile_id.clone(),
        expected_head: before.head.clone(),
        writer_epoch: before.writer_epoch,
        control: OwnerControl::RecoverWriter {
            writer_certificate_digest: h('f'),
            inventory_digest: h('9'),
        },
    };
    assert!(
        matches!(j.mutate(&h('a'),AuthorityMutation::OwnerControl(exact),after.last_witness_time_ms+1),Ok(MutationResult::Controlled(s)) if s==after)
    );
    assert_eq!(snapshot(&j).head, after.head);
    assert_eq!(after.writer_epoch, before.writer_epoch + 1);
    assert_eq!(
        after.outstanding_debit_zatoshis,
        before.outstanding_debit_zatoshis
    );
    assert_eq!(
        after.reserved_input_value_zatoshis,
        before.reserved_input_value_zatoshis
    );
    assert_eq!(
        after.outstanding_reservations,
        before.outstanding_reservations
    );
    assert_eq!(after.settled_debit_zatoshis, before.settled_debit_zatoshis);
    assert!(after.pending_writer_session.is_none() && after.active_writer_session.is_none());
    assert!(mutate(&j, original_request).unwrap() == original);
    assert!(matches!(
        mutate(&j, request(&after.head, 2, 20)),
        Err(AuthorityError::Permission)
    ));
    let changed = OwnerControlRequest {
        operation_id: "recovery-operation".into(),
        account_id: before.account_id,
        network_profile_id: before.network_profile_id,
        expected_head: before.head,
        writer_epoch: before.writer_epoch,
        control: OwnerControl::RecoverWriter {
            writer_certificate_digest: h('f'),
            inventory_digest: h('8'),
        },
    };
    assert!(matches!(
        j.mutate(
            &h('a'),
            AuthorityMutation::OwnerControl(changed),
            after.last_witness_time_ms + 1
        ),
        Err(AuthorityError::Conflict)
    ));
}

#[test]
fn recovery_replacement_cannot_revive_quarantined_witness_or_use_owner_as_writer() {
    let dir = private_dir();
    let j = create(dir.path());
    let before = snapshot(&j);
    let invalid = OwnerControlRequest {
        operation_id: "invalid-recovery".into(),
        account_id: before.account_id.clone(),
        network_profile_id: before.network_profile_id.clone(),
        expected_head: before.head,
        writer_epoch: before.writer_epoch,
        control: OwnerControl::RecoverWriter {
            writer_certificate_digest: h('a'),
            inventory_digest: h('9'),
        },
    };
    assert!(matches!(
        j.mutate(&h('a'), AuthorityMutation::OwnerControl(invalid), 1010),
        Err(AuthorityError::PolicyDenied)
    ));
    let replacement = control(
        &j,
        "ordinary-replacement",
        OwnerControl::ReplaceWriter {
            writer_certificate_digest: h('f'),
        },
    );
    let recycled = OwnerControlRequest {
        operation_id: "recycled-recovery-identity".into(),
        account_id: replacement.account_id,
        network_profile_id: replacement.network_profile_id,
        expected_head: replacement.head,
        writer_epoch: replacement.writer_epoch,
        control: OwnerControl::RecoverWriter {
            writer_certificate_digest: h('b'),
            inventory_digest: h('9'),
        },
    };
    assert!(matches!(
        j.mutate(&h('a'), AuthorityMutation::OwnerControl(recycled), 1012),
        Err(AuthorityError::PolicyDenied)
    ));
    let before = control(&j, "quarantine-recovery", OwnerControl::RequireRecovery);
    let recovery = OwnerControlRequest {
        operation_id: "cannot-unquarantine".into(),
        account_id: before.account_id,
        network_profile_id: before.network_profile_id,
        expected_head: before.head,
        writer_epoch: before.writer_epoch,
        control: OwnerControl::RecoverWriter {
            writer_certificate_digest: h('f'),
            inventory_digest: h('9'),
        },
    };
    assert!(matches!(
        j.mutate(&h('a'), AuthorityMutation::OwnerControl(recovery), 1020),
        Err(AuthorityError::RecoveryRequired)
    ));
}
