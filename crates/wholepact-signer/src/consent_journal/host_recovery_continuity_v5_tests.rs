//! Encrypted historical read-kernel tests only. The modeled old audit records
//! below are inert fixtures, never a fresh NativeDecision or live read owner.
use super::*;
use crate::consent_journal::common_context_reentry_audit_fixture as fixture;

fn source(
    recovery_required: bool,
) -> (
    tempfile::TempDir,
    SignerConsentJournal,
    ReconciledAuthorityHistory,
) {
    let value = fixture::fixture();
    let raw: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/common-context-handoff-audit.synthetic.json"
    ))
    .unwrap();
    let birth = serde_json::from_value(raw["original_birth"].clone()).unwrap();
    let history = wholepact_authority::transport::synthetic::recorded_fixture_history(
        &birth,
        &serde_json::to_vec(&raw["authority_events"]).unwrap(),
    )
    .unwrap();
    assert!(
        history.construction_history_with_transport_v1().unwrap()
            == value.complete_history.construction
    );
    let account = &value.request.account_id;
    let dir = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let key = wholepact_storage_security::DatabaseKey::from_bytes([0x74; 32]);
    let journal = SignerConsentJournal::create_encrypted(
        &dir.path().join("never-funded-historical.wp"),
        &key,
        account,
        1,
        recovery_required,
    )
    .unwrap();
    {
        let mut c = journal.connection.lock().unwrap();
        let tx = c.transaction().unwrap();
        let genesis = value
            .complete_history
            .financial_origins_v2
            .account_use
            .genesis
            .as_ref()
            .unwrap();
        tx.execute(
            "INSERT INTO signer_account_use_genesis VALUES(1,?1,?2,?3,?4)",
            rusqlite::params![
                account,
                genesis.identity.full_viewing_key_digest,
                genesis.digest().unwrap(),
                serde_json::to_string(genesis).unwrap()
            ],
        )
        .unwrap();
        for row in &value
            .complete_history
            .signer_common_context_audit
            .original
            .rows
        {
            tx.execute(
                "INSERT INTO signer_common_context_audit_v3 VALUES(?1,?2,?3,?4,?5)",
                rusqlite::params![
                    row.invocation_digest().unwrap(),
                    row.phase(),
                    row.account_id(),
                    row.digest().unwrap(),
                    serde_json::to_string(row).unwrap()
                ],
            )
            .unwrap();
        }
        for row in &value
            .complete_history
            .signer_common_context_audit
            .reentry
            .rows
        {
            tx.execute(
                "INSERT INTO signer_common_context_reentry_v1 VALUES(?1,?2,?3,?4,?5)",
                rusqlite::params![
                    row.invocation_digest,
                    row.phase(),
                    row.account_id,
                    row.digest().unwrap(),
                    serde_json::to_string(row).unwrap()
                ],
            )
            .unwrap();
        }
        // Historical pin only. It is decoded by the existing validator but is
        // not offered to any admission, native owner or session constructor.
        let receipt = value
            .complete_history
            .construction
            .observed_snapshot()
            .active_writer_session
            .as_ref()
            .unwrap();
        let native = NativeConsentReceipt {
            native_session_id: "a1".repeat(32),
            trusted_launch_measurement: "a2".repeat(32),
            permission_generation: 1,
            writer_epoch: 1,
            nonce: "a3".repeat(32),
            reviewed_at_ms: 1,
            expires_at_ms: 2,
        };
        tx.execute(
            "INSERT INTO signer_writer_reconciliations VALUES(?1,?2,?3,?4,?5,?6)",
            rusqlite::params![
                "a4".repeat(32),
                serde_json::to_string(history.disclosure()).unwrap(),
                history.snapshot().head.sequence,
                history.snapshot().head.digest,
                1,
                serde_json::to_string(&(receipt, native, "a5".repeat(32))).unwrap()
            ],
        )
        .unwrap();
        tx.commit().unwrap();
    }
    (dir, journal, history)
}

#[test]
fn restored_complete_v5_kernel_preserves_transport_and_refuses_old_writer_inventory() {
    let (_dir, journal, history) = source(true);
    let account = journal.account_state().unwrap();
    assert!(account.recovery_required);
    let mut c = journal.connection.lock().unwrap();
    let tx = c.transaction().unwrap();
    assert!(
        writer_history::WriterLocalInventory::read(&tx, &account, journal.capacity_limits())
            .is_err()
    );
    let complete =
        read_complete_continuity_v5(&tx, &account, journal.capacity_limits(), &history).unwrap();
    assert!(complete.construction == history.construction_history_with_transport_v1().unwrap());
    assert!(!complete.construction.transport.credentials.is_empty());
    assert!(complete.conservative_debit_zatoshis().unwrap() > 0);
    assert!(complete.require_financial_activation_supported().is_err());
    let again =
        read_complete_continuity_v5(&tx, &account, journal.capacity_limits(), &history).unwrap();
    assert_eq!(
        complete.financial_origins_v2.complete_journal_digest,
        again.financial_origins_v2.complete_journal_digest
    );
    assert!(storage::read_account(&tx).unwrap() == account);
    tx.rollback().unwrap();
}

#[test]
fn complete_v5_kernel_requires_actual_transaction_and_account_identity() {
    let (_dir, journal, history) = source(false);
    let account = journal.account_state().unwrap();
    let mut c = journal.connection.lock().unwrap();
    assert!(
        read_complete_continuity_v5(&c, &account, journal.capacity_limits(), &history).is_err()
    );
    let tx = c.transaction().unwrap();
    let mut changed = account.clone();
    changed.account_id = "ff".repeat(32);
    assert!(
        read_complete_continuity_v5(&tx, &changed, journal.capacity_limits(), &history).is_err()
    );
    tx.rollback().unwrap();
}

// Append an ordinary owner-control event to the existing never-funded signed
// transcript, then replay every event through the maintained authority ledger.
// This creates historical evidence only: no native decision, writer session,
// socket, signing key or direct snapshot/status mutation is involved.
fn history_after_control(
    before: &ReconciledAuthorityHistory,
    operation: &str,
    control: wholepact_authority::OwnerControl,
) -> ReconciledAuthorityHistory {
    let mut raw: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/common-context-handoff-audit.synthetic.json"
    ))
    .unwrap();
    let birth: wholepact_authority::pending_birth::PendingBirthCommitRecord =
        serde_json::from_value(raw["original_birth"].clone()).unwrap();
    let request = wholepact_authority::OwnerControlRequest {
        operation_id: operation.into(),
        account_id: before.snapshot().account_id.clone(),
        network_profile_id: before.snapshot().network_profile_id.clone(),
        writer_epoch: before.snapshot().writer_epoch,
        expected_head: before.snapshot().head.clone(),
        control,
    };
    raw["authority_events"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "mutation": wholepact_authority::AuthorityMutation::OwnerControl(request),
            "authenticated_certificate_digest": birth.request.policy.owner_certificate_digest,
            "witness_time_ms": before.snapshot().last_witness_time_ms + 1,
            "writer_session_id": null,
            "original_request_link": null,
        }));
    wholepact_authority::transport::synthetic::recorded_fixture_history(
        &birth,
        &serde_json::to_vec(&raw["authority_events"]).unwrap(),
    )
    .unwrap()
}

fn assert_controlled_history_readable(
    journal: &SignerConsentJournal,
    before: &ReconciledAuthorityHistory,
    after: &ReconciledAuthorityHistory,
) {
    let account = journal.account_state().unwrap();
    assert!(account.recovery_required);
    assert!(after.snapshot().active_writer_session.is_none());
    assert!(after.snapshot().pending_writer_session.is_none());
    assert_eq!(
        after.snapshot().head.sequence,
        before.snapshot().head.sequence + 1
    );
    assert_ne!(after.snapshot().head.digest, before.snapshot().head.digest);
    assert!(after.contains_head(&before.snapshot().head));
    assert_eq!(
        after.snapshot().writer_epoch,
        before.snapshot().writer_epoch
    );
    assert_eq!(
        after.snapshot().writer_certificate_digest,
        before.snapshot().writer_certificate_digest
    );
    assert_eq!(
        after.snapshot().outstanding_debit_zatoshis,
        before.snapshot().outstanding_debit_zatoshis
    );
    assert_eq!(
        after.snapshot().settled_debit_zatoshis,
        before.snapshot().settled_debit_zatoshis
    );
    assert_eq!(
        after.snapshot().reserved_input_value_zatoshis,
        before.snapshot().reserved_input_value_zatoshis
    );
    assert_eq!(
        after.snapshot().outstanding_reservations,
        before.snapshot().outstanding_reservations
    );
    assert!(after.snapshot().transport_fences == before.snapshot().transport_fences);
    let old_session = before.snapshot().active_writer_session.as_ref().unwrap();
    assert!(
        before
            .snapshot()
            .require_unfenced_transport(&old_session.session_id)
            .is_err()
    );
    assert!(
        after
            .snapshot()
            .require_unfenced_transport(&old_session.session_id)
            .is_err()
    );

    let mut c = journal.connection.lock().unwrap();
    let tx = c.transaction().unwrap();
    let baseline =
        read_complete_continuity_v5(&tx, &account, journal.capacity_limits(), before).unwrap();
    let complete =
        read_complete_continuity_v5(&tx, &account, journal.capacity_limits(), after).unwrap();
    assert_eq!(
        serde_json::to_vec(&complete.construction.transport).unwrap(),
        serde_json::to_vec(&baseline.construction.transport).unwrap()
    );
    assert!(complete.construction.original.origins() == baseline.construction.original.origins());
    assert!(
        complete.construction.original.approvals() == baseline.construction.original.approvals()
    );
    assert!(complete.signer_common_context_audit == baseline.signer_common_context_audit);
    assert_eq!(
        complete.conservative_debit_zatoshis().unwrap(),
        baseline.conservative_debit_zatoshis().unwrap()
    );
    assert_eq!(
        complete
            .construction
            .retained_input_value_zatoshis()
            .unwrap(),
        baseline
            .construction
            .retained_input_value_zatoshis()
            .unwrap()
    );
    assert_eq!(
        complete.conservative_obligations().unwrap(),
        baseline.conservative_obligations().unwrap()
    );
    // Only the authenticated historical account-use projection may advance.
    // Every financial origin, local phase, receipt and journal digest is exact.
    let mut unchanged_financial = baseline.financial_origins_v2.clone();
    unchanged_financial.account_use = complete.financial_origins_v2.account_use.clone();
    assert!(complete.financial_origins_v2 == unchanged_financial);
    assert!(complete.require_financial_activation_supported().is_err());
    assert!(
        writer_history::WriterLocalInventory::read(&tx, &account, journal.capacity_limits())
            .is_err()
    );

    let evidence =
        crate::authority_bridge::host_recovery_ipc::v5::HostRecoveryContinuityEvidenceV5 {
            request: fixture::fixture().request,
            writer_certificate_digest: after.snapshot().writer_certificate_digest.clone(),
            writer_session_id: None,
            writer_session_expires_at_ms: None,
            head: after.snapshot().head.clone(),
            history_digest: after.history_digest().unwrap(),
            complete_history: complete,
        };
    evidence.validate().unwrap();
    let mut stale_session = evidence.clone();
    stale_session.writer_session_id = Some(old_session.session_id.clone());
    stale_session.writer_session_expires_at_ms = Some(old_session.expires_at_ms);
    assert!(stale_session.validate().is_err());
    assert!(storage::read_account(&tx).unwrap() == account);
    // An authenticated later exclusion is disclosed, never imported by read.
    assert!(
        account_use_storage::inspect(&tx, &account.account_id)
            .unwrap()
            .exclusion()
            .is_none()
    );
    tx.rollback().unwrap();
}

#[test]
fn paused_and_revoked_complete_v5_replay_remains_readable_without_writer_session() {
    use wholepact_authority::{OwnerControl, WriterStatus};
    let (_dir, journal, history) = source(true);
    for (operation, control, status) in [
        (
            "synthetic-v5-pause",
            OwnerControl::Pause,
            WriterStatus::Paused,
        ),
        (
            "synthetic-v5-revoke",
            OwnerControl::Revoke,
            WriterStatus::Revoked,
        ),
    ] {
        let changed = history_after_control(&history, operation, control);
        assert!(changed.snapshot().writer_status == status);
        assert!(changed.account_use_history().exclusion().is_none());
        assert_controlled_history_readable(&journal, &history, &changed);
    }
}

#[test]
fn retired_complete_v5_replay_retains_exclusion_and_charges_without_import() {
    use wholepact_authority::account_use::{ExclusionReason, PermanentAccountExclusion};
    let (_dir, journal, history) = source(true);
    let genesis = history.account_use_history().genesis().unwrap();
    let operation = "synthetic-v5-retirement";
    let exclusion = PermanentAccountExclusion {
        version: 1,
        identity: genesis.identity.clone(),
        genesis_digest: genesis.digest().unwrap(),
        operation_id: operation.into(),
        native_review_digest: "af".repeat(32),
        reason: ExclusionReason::RetirementRequested,
    };
    let changed = history_after_control(
        &history,
        operation,
        wholepact_authority::OwnerControl::PermanentlyExcludeAccount {
            exclusion: exclusion.clone(),
        },
    );
    assert!(changed.account_use_history().exclusion() == Some(&exclusion));
    assert_eq!(
        changed
            .snapshot()
            .account_use_checkpoint
            .as_ref()
            .unwrap()
            .permanent_exclusion_digest,
        Some(exclusion.digest().unwrap())
    );
    assert_controlled_history_readable(&journal, &history, &changed);
    let account = journal.account_state().unwrap();
    let mut c = journal.connection.lock().unwrap();
    let tx = c.transaction().unwrap();
    let complete =
        read_complete_continuity_v5(&tx, &account, journal.capacity_limits(), &changed).unwrap();
    assert!(complete.financial_origins_v2.account_use.exclusion.as_ref() == Some(&exclusion));
    assert!(
        complete
            .financial_origins_v2
            .account_use
            .witness_ack
            .is_some()
    );
    assert!(
        account_use_storage::inspect(&tx, &account.account_id)
            .unwrap()
            .witness_ack()
            .is_none()
    );
    tx.rollback().unwrap();
}

#[path = "informational_read_tests.rs"]
mod informational_read_tests;

#[cfg(feature = "pending-birth-owner-signing")]
#[path = "permanent_stop_tests.rs"]
mod permanent_stop_tests;
