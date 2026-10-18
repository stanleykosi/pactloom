//! Never-funded, no-socket continuity tests. They do not qualify live native UX.
use super::*;
fn history(
    f: &Fixture,
) -> (
    wholepact_authority::ReconciledAuthorityHistory,
    wholepact_authority::AuthenticatedWriterSession,
) {
    synthetic::reconciled_session(
        &f.witness,
        &"b2".repeat(32),
        "account-alice",
        &f.request.reservation.network_profile_id,
    )
    .unwrap()
}
fn pin(f: &Fixture, journal: &SignerConsentJournal, session: &SignerConsentSession) {
    let (history, active) = history(f);
    let prepared = session
        .prepare_writer_reconciliation(journal, history, active)
        .unwrap();
    let decision = fixture::decision(session, prepared.review_digest());
    journal
        .reconcile_writer(
            session
                .approve_writer_reconciliation(prepared, decision)
                .unwrap(),
        )
        .unwrap();
}
#[test]
fn host_continuity_requires_local_pins_and_exact_original_reservation() {
    let f = Fixture::new();
    // A complete empty witness history cannot erase a local release intent.
    pin(&f, &f.journal, &f.session);
    let (h, a) = history(&f);
    assert!(matches!(
        f.journal
            .acquire_host_recovery_continuity(&f.session, &h, &a),
        Err(JournalError::RecoveryRequired)
    ));
    let _permit = f.permit();
    let (h, a) = history(&f);
    let lease = f
        .journal
        .acquire_host_recovery_continuity(&f.session, &h, &a)
        .unwrap();
    lease.check_current().unwrap();
    assert!(f.journal.authority_fence.try_read().is_err());
    drop(lease);
    assert_eq!(f.journal.account_state().unwrap().writer_epoch, 1);
    assert!(!f.journal.account_state().unwrap().recovery_required);
    let unpinned = Fixture::new();
    let _ = unpinned.permit();
    let (h, a) = history(&unpinned);
    assert!(matches!(
        unpinned
            .journal
            .acquire_host_recovery_continuity(&unpinned.session, &h, &a),
        Err(JournalError::RecoveryRequired)
    ));
}
#[test]
fn host_continuity_rejects_changed_head_other_witness_revoked_session_and_quarantine() {
    let f = Fixture::new();
    pin(&f, &f.journal, &f.session);
    let (old_history, _) = history(&f);
    let _ = f.permit();
    let (_, fresh) = history(&f);
    assert!(matches!(
        f.journal
            .acquire_host_recovery_continuity(&f.session, &old_history, &fresh),
        Err(JournalError::InvalidBinding)
    ));
    let other = Fixture::new();
    let _ = other.permit();
    let (h, a) = history(&other);
    assert!(
        f.journal
            .acquire_host_recovery_continuity(&f.session, &h, &a)
            .is_err()
    );
    let (h, a) = history(&f);
    f.session.invalidate().unwrap();
    assert!(matches!(
        f.journal
            .acquire_host_recovery_continuity(&f.session, &h, &a),
        Err(JournalError::Permission)
    ));
    let session = fixture::session(&f.journal, "synthetic-replacement-native-session");
    f.journal.require_recovery().unwrap();
    assert!(matches!(
        f.journal.acquire_host_recovery_continuity(&session, &h, &a),
        Err(JournalError::RecoveryRequired)
    ));
}
#[test]
fn host_continuity_preserves_witness_only_exposure_without_fabricating_originals() {
    let f = Fixture::new();
    let permit = f.permit();
    let other = SignerConsentJournal::create_encrypted(
        &f._directory.path().join("empty-surviving-signer.sqlite"),
        &DatabaseKey::from_bytes([0x19; 32]),
        "account-alice",
        1,
        false,
        &f.private_directory
            .signer_journal_source_owner_for_test(
                &f._directory.path().join("empty-surviving-signer.sqlite"),
            )
            .unwrap(),
    )
    .unwrap();
    let session = fixture::session(&other, "synthetic-empty-owner");
    pin(&f, &other, &session);
    let (h, a) = history(&f);
    let lease = other
        .acquire_host_recovery_continuity(&session, &h, &a)
        .unwrap();
    assert_eq!(h.permits().unwrap().len(), 1);
    assert!(h.permits().unwrap()[0] == *permit.descriptor());
    let c = other.connection.lock().unwrap();
    let originals: u64 = c
        .query_row("SELECT count(*) FROM signer_original_consents", [], |r| {
            r.get(0)
        })
        .unwrap();
    let remote: u64 = c
        .query_row("SELECT count(*) FROM signer_remote_exposures", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(originals, 0);
    assert_eq!(remote, 1);
    lease.check_current().unwrap();
}

#[test]
fn informational_publication_releases_fence_on_admission_and_deadline() {
    use crate::authority_bridge::host_publication_ipc::PublicationWindow;
    use std::time::Duration;
    let f = Fixture::new();
    pin(&f, &f.journal, &f.session);
    let _ = f.permit();
    let (h, a) = history(&f);
    // Exercise the production admission-and-release operation without a socket,
    // native UI, remote credentials or elapsed wall-clock sleeps.
    for (elapsed, admitted) in [(Duration::ZERO, true), (Duration::from_secs(30), false)] {
        let held = f
            .journal
            .acquire_host_recovery_continuity(&f.session, &h, &a)
            .unwrap();
        assert!(f.journal.authority_fence.try_read().is_err());
        let mut window = PublicationWindow::default();
        assert_eq!(window.consume_and_release(held, elapsed).is_ok(), admitted);
        assert!(f.journal.authority_fence.try_read().is_ok());
        assert!(window.remaining(Duration::ZERO).is_err());
    }
    // Transport failure occurs before admission: ordinary scope unwinding is
    // sufficient, and no remote-consumer drain or witness callback is retained.
    let disconnected: crate::authority_bridge::Result<()> = (|| {
        let _held = f
            .journal
            .acquire_host_recovery_continuity(&f.session, &h, &a)?;
        Err(crate::authority_bridge::BridgeError::Ipc)
    })();
    assert!(disconnected.is_err());
    assert!(f.journal.authority_fence.try_read().is_ok());
    // Session invalidation is possible immediately; publication has not retained
    // the read guard until an external host says it finished writing.
    f.session.invalidate().unwrap();
    assert!(
        f.journal
            .acquire_host_recovery_continuity(&f.session, &h, &a)
            .is_err()
    );
}

#[test]
fn complete_continuity_hold_keeps_online_origin_and_detects_exact_journal_change() {
    use crate::authority_bridge::host_recovery_ipc::v2::HostRecoveryReservationOriginV2;
    use sha2::{Digest, Sha256};
    let f = Fixture::new();
    pin(&f, &f.journal, &f.session);
    let permit = f.permit();
    let (h, a) = history(&f);
    let held = f
        .journal
        .acquire_host_recovery_continuity_v2(&f.session, &h, &a)
        .unwrap();
    held.check_current().unwrap();
    assert!(f.journal.authority_fence.try_read().is_err());
    let audit = held.history_v2();
    assert_eq!(audit.schema_version, 2);
    assert_eq!(audit.origins.len(), 1);
    assert!(
        matches!(&audit.origins[0], HostRecoveryReservationOriginV2::Online { permit: p } if p == permit.descriptor())
    );
    assert!(audit.account_use.genesis.is_none());
    assert!(audit.review_receipts.is_empty());
    // Fault injection bypasses the held Rust fence solely inside this test.
    // A genuine production writer cannot acquire this fence while it is held.
    let mut hasher = Sha256::new();
    hasher.update(b"wholepact.encrypted-envelope.v1\0");
    hasher.update(b"synthetic receipt input");
    {
        let c = f.journal.connection.lock().unwrap();
        c.execute(
            "INSERT INTO signer_offline_review_inputs VALUES(?1,?2,?3,?4,?5,?6)",
            rusqlite::params![
                "receipt-after-hold",
                "account-alice",
                "a".repeat(64),
                "b".repeat(64),
                hex::encode(hasher.finalize()),
                hex::encode(b"synthetic receipt input")
            ],
        )
        .unwrap();
    }
    assert!(held.check_current().is_err());
    drop(held);
    assert!(f.journal.authority_fence.try_read().is_ok());
    let fresh = f
        .journal
        .acquire_host_recovery_continuity_v2(&f.session, &h, &a)
        .unwrap();
    assert_eq!(fresh.history_v2().review_receipts.len(), 1);
    assert!(
        fresh.history_v2().review_receipts[0]
            .authenticated
            .is_none()
    );
}
#[test]
fn complete_continuity_never_hides_missing_online_original_or_revoked_read_session() {
    let f = Fixture::new();
    pin(&f, &f.journal, &f.session);
    let (h, a) = history(&f);
    assert!(
        f.journal
            .acquire_host_recovery_continuity_v2(&f.session, &h, &a)
            .is_err()
    );
    let _permit = f.permit();
    let (h, a) = history(&f);
    f.session.invalidate().unwrap();
    assert!(
        f.journal
            .acquire_host_recovery_continuity_v2(&f.session, &h, &a)
            .is_err()
    );
}

#[test]
fn complete_continuity_rejects_offline_receipt_colliding_with_online_original() {
    use sha2::{Digest, Sha256};
    let f = Fixture::new();
    pin(&f, &f.journal, &f.session);
    let permit = f.permit();
    let (h, a) = history(&f);
    let mut hasher = Sha256::new();
    hasher.update(b"wholepact.encrypted-envelope.v1\0");
    hasher.update(b"synthetic receipt input");
    {
        let c = f.journal.connection.lock().unwrap();
        c.execute(
            "INSERT INTO signer_offline_review_inputs VALUES(?1,?2,?3,?4,?5,?6)",
            rusqlite::params![
                permit.descriptor().request.authorization_id,
                "account-alice",
                "a".repeat(64),
                "b".repeat(64),
                hex::encode(hasher.finalize()),
                hex::encode(b"synthetic receipt input")
            ],
        )
        .unwrap();
    }
    assert!(
        f.journal
            .acquire_host_recovery_continuity_v2(&f.session, &h, &a)
            .is_err()
    );
}
