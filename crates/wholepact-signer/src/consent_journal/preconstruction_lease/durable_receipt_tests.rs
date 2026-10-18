//! Synthetic encrypted journal predicate tests, NOT native approval qualification.
//! No production native owner, stream, witness or spending operation is issued.
use super::*;
use crate::consent_journal::{authority::fixture, tests};
use std::os::unix::fs::PermissionsExt;

struct Fixture {
    journal: SignerConsentJournal,
    session: SignerConsentSession,
    enrollment: AccountEnrollmentRecord,
    manifest: AcceptedManifestRecord,
    _directory: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let key = wholepact_storage_security::DatabaseKey::from_bytes([117; 32]);
        let journal = SignerConsentJournal::create_encrypted(
            &directory.path().join("synthetic-receipts.sqlite"),
            &key,
            "account-alice",
            1,
            false,
        )
        .unwrap();
        let session = fixture::session(&journal, "synthetic-owner");
        let (enrollment, manifest) = tests::enroll(
            &journal,
            &session,
            &tests::proposal("agreement-a", "obligation-a", "proposal-a"),
            1_000_000_000,
        );
        Self {
            journal,
            session,
            enrollment,
            manifest,
            _directory: directory,
        }
    }
    fn lease(&self) -> PreconstructionRecordLease<'_> {
        self.journal
            .acquire_preconstruction_records(
                self.enrollment.reference(),
                self.manifest.reference(),
                &self.session,
            )
            .unwrap()
    }
}

#[test]
fn current_receipts_pass_but_stale_history_does_not_approve_new_disclosure() {
    let f = Fixture::new();
    f.lease()
        .require_current_durable_disclosure_receipts_v1()
        .unwrap();
    f.session.invalidate().unwrap();
    let current = fixture::session(&f.journal, "synthetic-owner");
    // Same principal/account and exact immutable rows remain readable. A new
    // session does not revive the original session's decision/nonce authority.
    let historical = f
        .journal
        .acquire_preconstruction_records(f.enrollment.reference(), f.manifest.reference(), &current)
        .unwrap();
    historical.check_current().unwrap();
    assert!(matches!(
        historical.require_current_durable_disclosure_receipts_v1(),
        Err(JournalError::Permission)
    ));
    drop(historical);
    let (enrollment, manifest) = tests::enroll(
        &f.journal,
        &current,
        &tests::proposal("agreement-a", "obligation-a", "proposal-a"),
        1_000_000_000,
    );
    let fresh = f
        .journal
        .acquire_preconstruction_records(enrollment.reference(), manifest.reference(), &current)
        .unwrap();
    fresh
        .require_current_durable_disclosure_receipts_v1()
        .unwrap();
    drop(fresh);
    for (e, m) in [
        (f.enrollment.reference(), manifest.reference()),
        (enrollment.reference(), f.manifest.reference()),
    ] {
        assert!(matches!(
            f.journal.acquire_preconstruction_records(e, m, &current),
            Err(JournalError::InvalidBinding)
        ));
    }
    let historical = f
        .journal
        .acquire_preconstruction_records(f.enrollment.reference(), f.manifest.reference(), &current)
        .unwrap();
    assert!(historical.enrollment() == &f.enrollment);
    assert!(historical.manifest() == &f.manifest);
    historical.check_current().unwrap();
}

fn receipt_mut<'a>(
    lease: &'a mut PreconstructionRecordLease<'_>,
    manifest: bool,
) -> &'a mut NativeConsentReceipt {
    if manifest {
        &mut lease.manifest.terms.receipt
    } else {
        &mut lease.enrollment.terms.receipt
    }
}

#[test]
fn both_receipts_require_exact_current_session_generation_epoch_and_measurement() {
    let f = Fixture::new();
    for manifest in [false, true] {
        for field in 0..4 {
            let mut lease = f.lease();
            let receipt = receipt_mut(&mut lease, manifest);
            // Negative-only mutation of a local lease snapshot; no forged row
            // is written and no receipt/session factory is added to production.
            match field {
                0 => receipt.native_session_id.push_str("-other"),
                1 => receipt.permission_generation += 1,
                2 => receipt.writer_epoch += 1,
                _ => receipt.trusted_launch_measurement.push_str("-other"),
            }
            assert!(matches!(
                lease.require_current_durable_disclosure_receipts_v1(),
                Err(JournalError::Permission)
            ));
        }
    }
}

#[test]
fn both_receipts_require_an_issued_nonce_not_just_matching_origin_metadata() {
    let f = Fixture::new();
    for manifest in [false, true] {
        let mut lease = f.lease();
        receipt_mut(&mut lease, manifest).nonce.clear();
        assert!(matches!(
            lease.require_current_durable_disclosure_receipts_v1(),
            Err(JournalError::Permission)
        ));
    }
}

#[test]
fn both_receipts_require_the_original_monotonic_review_window() {
    for manifest in [false, true] {
        let f = Fixture::new();
        let nonce = if manifest {
            f.manifest.receipt().nonce()
        } else {
            f.enrollment.receipt().nonce()
        };
        fixture::expire_receipt_monotonically(&f.session, nonce);
        let lease = f.lease();
        // Historical access stays current even when a review nonce is old.
        lease.check_current().unwrap();
        assert!(matches!(
            lease.require_current_durable_disclosure_receipts_v1(),
            Err(JournalError::Expired)
        ));
    }
}

#[test]
fn both_receipts_require_current_wall_clock_window() {
    let f = Fixture::new();
    for manifest in [false, true] {
        for future in [false, true] {
            let mut lease = f.lease();
            let receipt = receipt_mut(&mut lease, manifest);
            if future {
                receipt.reviewed_at_ms = u64::MAX;
            } else {
                receipt.expires_at_ms = 0;
            }
            assert!(matches!(
                lease.require_current_durable_disclosure_receipts_v1(),
                Err(JournalError::Expired)
            ));
        }
    }
}
