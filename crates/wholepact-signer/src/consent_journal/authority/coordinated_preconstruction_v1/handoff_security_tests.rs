//! Maintained negative tests of the production handoff restriction kernels.
//!
//! The encrypted rows and native sessions below are explicitly synthetic. These
//! tests do not construct a PairPeer, genuine Final or accepted-provenance token,
//! and do not qualify the successful coordinated publication/acquisition path.
//! The private kernels called here are the ones called by the real mint and
//! retained-token checks, not copies or extracted source. Genuine actor/peer,
//! purpose-Final and journal-effect integration remains a separate obligation.
use super::*;
use crate::consent_journal::{authority::fixture, tests as journal_tests};
use std::os::unix::fs::PermissionsExt;

struct Fixture {
    journal: SignerConsentJournal,
    session: SignerConsentSession,
    enrollment: AccountEnrollmentRecord,
    manifest: AcceptedManifestRecord,
    source_expires_at_ms: u64,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let path = directory.path().join("synthetic-handoff.sqlite");
        let private_directory = crate::files::PrivateDirectory::open(directory.path()).unwrap();
        let source = private_directory.signer_journal_source_owner_for_test(&path).unwrap();
        let key = wholepact_storage_security::DatabaseKey::from_bytes([118; 32]);
        let journal = SignerConsentJournal::create_encrypted(
            &path, &key, "account-alice", 1, false, &source,
        ).unwrap();
        let session = fixture::session(&journal, "synthetic-owner");
        let (enrollment, manifest) = journal_tests::enroll(
            &journal,
            &session,
            &journal_tests::proposal("agreement-a", "obligation-a", "proposal-a"),
            1_000_000_000,
        );
        Self {
            journal,
            session,
            enrollment,
            manifest,
            source_expires_at_ms: now_ms().unwrap() + 600_000,
            _directory: directory,
        }
    }

    fn lease(&self) -> ReadLease<'_> {
        ReadLease {
            _guard: self.session.inner.read().unwrap(),
            principal: &self.session.inner.principal_id,
            session: &self.session.inner,
        }
    }

    fn identity(&self, lease: &ReadLease<'_>) -> Result<()> {
        require_accepted_identity(
            &self.session.inner, 1, lease,
            &self.enrollment, &self.manifest,
            &self.enrollment, &self.manifest,
            self.source_expires_at_ms,
        )
    }

    fn commitment(&self) -> String {
        writer_history::complete_journal_commitment(&self.journal.connection.lock().unwrap())
            .unwrap()
    }

    fn nonce(&self, manifest: bool) -> &str {
        if manifest { self.manifest.receipt().nonce() } else { self.enrollment.receipt().nonce() }
    }

    fn assert_rows_unchanged(&self, before: &str) {
        let c = self.journal.connection.lock().unwrap();
        assert!(storage::read_enrollment(&c, self.enrollment.reference()).unwrap()
            .as_ref() == Some(&self.enrollment));
        assert!(storage::read_manifest(&c, self.manifest.reference()).unwrap()
            .as_ref() == Some(&self.manifest));
        assert_eq!(writer_history::complete_journal_commitment(&c).unwrap(), before);
    }
}

fn receipt_mut<'a>(
    enrollment: &'a mut AccountEnrollmentRecord,
    manifest: &'a mut AcceptedManifestRecord,
    select_manifest: bool,
) -> &'a mut NativeConsentReceipt {
    if select_manifest { &mut manifest.terms.receipt } else { &mut enrollment.terms.receipt }
}

#[test]
fn handoff_mint_rejects_either_missing_original_nonce() {
    for manifest in [false, true] {
        let f = Fixture::new();
        let before = f.commitment();
        let lease = f.lease();
        require_live_receipt_pair(&lease, &f.enrollment, &f.manifest).unwrap();
        f.session.inner.issued_receipts.lock().unwrap().remove(f.nonce(manifest)).unwrap();
        assert!(matches!(require_live_receipt_pair(&lease, &f.enrollment, &f.manifest),
            Err(JournalError::Permission)));
        f.assert_rows_unchanged(&before);
    }
}

#[test]
fn handoff_mint_rejects_either_expired_original_nonce() {
    for manifest in [false, true] {
        let f = Fixture::new();
        let before = f.commitment();
        let lease = f.lease();
        require_live_receipt_pair(&lease, &f.enrollment, &f.manifest).unwrap();
        fixture::expire_receipt_monotonically(&f.session, f.nonce(manifest));
        let issued = f.session.inner.issued_receipts.lock().unwrap().clone();
        for _ in 0..2 {
            assert!(matches!(require_live_receipt_pair(&lease, &f.enrollment, &f.manifest),
                Err(JournalError::Expired)));
        }
        assert_eq!(*f.session.inner.issued_receipts.lock().unwrap(), issued);
        f.assert_rows_unchanged(&before);
    }
}

#[test]
fn handoff_mint_rejects_either_receipt_wall_expiry_or_rollback() {
    let f = Fixture::new();
    let before = f.commitment();
    let lease = f.lease();
    for manifest in [false, true] {
        for rollback in [false, true] {
            let mut e = f.enrollment.clone();
            let mut m = f.manifest.clone();
            let r = receipt_mut(&mut e, &mut m, manifest);
            if rollback { r.reviewed_at_ms = u64::MAX; } else { r.expires_at_ms = 0; }
            assert!(matches!(require_live_receipt_pair(&lease, &e, &m),
                Err(JournalError::Expired)));
        }
    }
    f.assert_rows_unchanged(&before);
}

#[test]
fn handoff_mint_rejects_crossed_record_references() {
    let f = Fixture::new();
    let before = f.commitment();
    let mut manifest = f.manifest.clone();
    manifest.terms.enrollment_ref = "ff".repeat(32);
    assert!(matches!(require_live_receipt_pair(&f.lease(), &f.enrollment, &manifest),
        Err(JournalError::InvalidBinding)));
    f.assert_rows_unchanged(&before);
}

#[test]
fn handoff_identity_requires_original_session_arc_not_visible_labels() {
    let f = Fixture::new();
    let mut other = fixture::session(&f.journal, "synthetic-owner");
    {
        let other_inner = Arc::get_mut(&mut other.inner).unwrap();
        other_inner.session_id = f.session.inner.session_id.clone();
        other_inner.created = f.session.inner.created;
        *other_inner.issued_receipts.lock().unwrap() =
            f.session.inner.issued_receipts.lock().unwrap().clone();
    }
    let other_lease = ReadLease {
        _guard: other.inner.read().unwrap(),
        principal: &other.inner.principal_id,
        session: &other.inner,
    };
    // The generic receipt predicate sees equal visible metadata and nonces.
    // The new retained-identity predicate additionally requires the SAME Arc.
    require_live_receipt_pair(&other_lease, &f.enrollment, &f.manifest).unwrap();
    assert!(matches!(f.identity(&other_lease), Err(JournalError::Permission)));
}

#[test]
fn handoff_identity_rejects_generation_change() {
    let f = Fixture::new();
    f.identity(&f.lease()).unwrap();
    f.session.inner.state.write().unwrap().generation += 1;
    let lease = f.lease();
    lease.check_current().unwrap();
    assert!(matches!(f.identity(&lease), Err(JournalError::Permission)));
    assert!(matches!(require_live_receipt_pair(&lease, &f.enrollment, &f.manifest),
        Err(JournalError::Permission)));
}

#[test]
fn handoff_identity_rejects_revoked_or_expired_session() {
    for expired in [false, true] {
        let mut f = Fixture::new();
        if expired {
            Arc::get_mut(&mut f.session.inner).unwrap().created =
                Instant::now() - Duration::from_secs(15 * 60 + 1);
        } else {
            f.session.invalidate().unwrap();
        }
        assert!(matches!(f.session.inner.read(), Err(JournalError::Permission)));
        // Negative-only raw guard bypasses acquisition to prove the retained
        // kernel itself rechecks a stale carrier; no authority is constructed.
        let lease = ReadLease {
            _guard: f.session.inner.state.read().unwrap(),
            principal: &f.session.inner.principal_id,
            session: &f.session.inner,
        };
        assert!(matches!(f.identity(&lease), Err(JournalError::Permission)));
    }
}

#[test]
fn handoff_identity_requires_exact_records_including_nonce_and_transport() {
    let f = Fixture::new();
    let before = f.commitment();
    let lease = f.lease();
    for field in 0..9 {
        let mut e = f.enrollment.clone();
        let mut m = f.manifest.clone();
        match field {
            0 => e.reference = "a0".repeat(32),
            1 => m.reference = "a1".repeat(32),
            2 => e.terms.receipt.nonce = "a2".repeat(32),
            3 => m.terms.receipt.nonce = "a3".repeat(32),
            4 => e.terms.participant_id.push_str("-other"),
            5 => e.terms.transport = TransportIdentityBinding::RemoteAuthenticatedKeys {
                transport_identity_id: "other-source".into(),
                sender_key_digest: "d1".repeat(32),
                recipient_key_digest: "d2".repeat(32),
                channel_binding_digest: "d3".repeat(32),
            },
            6 => m.terms.manifest_digest = "a6".repeat(32),
            7 => e.terms.account_fvk_digest = "a7".repeat(32),
            _ => m.terms.proposal_digest = "a8".repeat(32),
        }
        assert!(matches!(require_accepted_identity(
            &f.session.inner, 1, &lease, &e, &m,
            &f.enrollment, &f.manifest, f.source_expires_at_ms,
        ), Err(JournalError::Permission)));
    }
    f.assert_rows_unchanged(&before);
}

#[test]
fn handoff_identity_rechecks_both_receipt_origin_fields() {
    let f = Fixture::new();
    let lease = f.lease();
    for manifest in [false, true] {
        for field in 0..4 {
            let mut e = f.enrollment.clone();
            let mut m = f.manifest.clone();
            let r = receipt_mut(&mut e, &mut m, manifest);
            match field {
                0 => r.native_session_id = "fa".repeat(32),
                1 => r.permission_generation += 1,
                2 => r.writer_epoch += 1,
                _ => r.trusted_launch_measurement = "fb".repeat(32),
            }
            // Equal supplied/retained snapshots deliberately avoid relying on
            // the full-record mismatch to test each origin comparison itself.
            assert!(matches!(require_accepted_identity(
                &f.session.inner, 1, &lease, &e, &m, &e, &m, f.source_expires_at_ms,
            ), Err(JournalError::Permission)));
            assert!(matches!(require_live_receipt_pair(&lease, &e, &m),
                Err(JournalError::Permission)));
        }
    }
}

#[test]
fn handoff_identity_rechecks_account_principal_and_enrollment_link() {
    let f = Fixture::new();
    let lease = f.lease();
    for field in 0..5 {
        let mut e = f.enrollment.clone();
        let mut m = f.manifest.clone();
        match field {
            0 => e.terms.account_id.push_str("-other"),
            1 => e.terms.principal_id.push_str("-other"),
            2 => m.terms.account_id.push_str("-other"),
            3 => m.terms.principal_id.push_str("-other"),
            _ => m.terms.enrollment_ref = "fc".repeat(32),
        }
        assert!(matches!(require_accepted_identity(
            &f.session.inner, 1, &lease, &e, &m, &e, &m, f.source_expires_at_ms,
        ), Err(JournalError::Permission)));
    }
}

#[test]
fn handoff_identity_retains_original_source_absolute_ceiling() {
    let f = Fixture::new();
    let lease = f.lease();
    f.identity(&lease).unwrap();
    for ceiling in [0, now_ms().unwrap()] {
        assert!(matches!(require_accepted_identity(
            &f.session.inner, 1, &lease,
            &f.enrollment, &f.manifest, &f.enrollment, &f.manifest, ceiling,
        ), Err(JournalError::Expired)));
    }
}

#[test]
fn handoff_identity_retains_both_accepted_review_lower_wall_bounds() {
    let f = Fixture::new();
    let lease = f.lease();
    for manifest in [false, true] {
        let mut e = f.enrollment.clone();
        let mut m = f.manifest.clone();
        receipt_mut(&mut e, &mut m, manifest).reviewed_at_ms = u64::MAX;
        assert!(matches!(require_accepted_identity(
            &f.session.inner, 1, &lease, &e, &m, &e, &m, f.source_expires_at_ms,
        ), Err(JournalError::Expired)));
    }
}

#[test]
fn handoff_pair_identity_rejects_each_source_peer_generation_session_and_ref_mismatch() {
    // This is the exact equality kernel called by token.require_pair_facts;
    // these ordinary strings neither construct nor authenticate a PairPeer.
    let expected = ("source", "grant", "key", "channel", 1, "session", "enrollment", "manifest");
    require_accepted_pair_identity(expected, expected).unwrap();
    for field in 0..8 {
        let mut actual = expected;
        match field {
            0 => actual.0 = "other-source",
            1 => actual.1 = "other-grant",
            2 => actual.2 = "other-key",
            3 => actual.3 = "other-channel",
            4 => actual.4 += 1,
            5 => actual.5 = "other-session",
            6 => actual.6 = "other-enrollment",
            _ => actual.7 = "other-manifest",
        }
        assert!(matches!(require_accepted_pair_identity(expected, actual),
            Err(JournalError::Permission)));
    }
}

#[test]
fn handoff_identity_observation_never_renews_legacy_receipt120() {
    for manifest in [false, true] {
        let f = Fixture::new();
        let before = f.commitment();
        fixture::expire_receipt_monotonically(&f.session, f.nonce(manifest));
        let issued = f.session.inner.issued_receipts.lock().unwrap().clone();
        {
            let lease = f.lease();
            for _ in 0..2 { f.identity(&lease).unwrap(); }
            assert!(matches!(require_live_receipt_pair(&lease, &f.enrollment, &f.manifest),
                Err(JournalError::Expired)));
        }
        let legacy = f.journal.acquire_preconstruction_records(
            f.enrollment.reference(), f.manifest.reference(), &f.session,
        ).unwrap();
        legacy.check_current().unwrap();
        assert!(matches!(legacy.require_current_durable_disclosure_receipts_v1(),
            Err(JournalError::Expired)));
        drop(legacy);
        assert_eq!(*f.session.inner.issued_receipts.lock().unwrap(), issued);
        f.assert_rows_unchanged(&before);
    }
}

#[test]
fn handoff_marker_consumes_enrollment_before_attempt_and_rejects_replay() {
    let mut progress = CoordinatedReceiptProgressV1::Fresh;
    progress.begin_enrollment().unwrap();
    assert!(matches!(&progress, CoordinatedReceiptProgressV1::Consumed));
    // No simulated successful commit/finish occurs. Failed/uncertain work may
    // not restore Fresh, even if another approval is later presented.
    assert!(matches!(progress.begin_enrollment(), Err(JournalError::Permission)));
    assert!(matches!(&progress, CoordinatedReceiptProgressV1::Consumed));
}

#[test]
fn handoff_marker_rejects_out_of_order_manifest_and_later_enrollment() {
    let f = Fixture::new();
    let mut progress = CoordinatedReceiptProgressV1::Fresh;
    assert!(matches!(progress.begin_manifest(&f.enrollment), Err(JournalError::Permission)));
    assert!(matches!(progress.begin_enrollment(), Err(JournalError::Permission)));
    assert!(matches!(&progress, CoordinatedReceiptProgressV1::Consumed));
}

#[test]
fn handoff_marker_requires_exact_committed_enrollment_and_consumes_mismatch() {
    let f = Fixture::new();
    let mut progress = CoordinatedReceiptProgressV1::Enrollment(f.enrollment.clone());
    let mut other = f.enrollment.clone();
    other.terms.receipt.nonce = "fe".repeat(32);
    assert!(matches!(progress.begin_manifest(&other), Err(JournalError::Permission)));
    assert!(matches!(progress.begin_manifest(&f.enrollment), Err(JournalError::Permission)));
    assert!(matches!(&progress, CoordinatedReceiptProgressV1::Consumed));
}

#[test]
fn handoff_marker_allows_only_one_manifest_attempt_and_no_second_mint() {
    let f = Fixture::new();
    let mut progress = CoordinatedReceiptProgressV1::Enrollment(f.enrollment.clone());
    assert!(progress.begin_manifest(&f.enrollment).unwrap() == f.enrollment);
    assert!(matches!(&progress, CoordinatedReceiptProgressV1::Consumed));
    assert!(matches!(progress.begin_manifest(&f.enrollment), Err(JournalError::Permission)));
    assert!(matches!(progress.begin_enrollment(), Err(JournalError::Permission)));
}

#[test]
fn handoff_failed_mint_eligibility_does_not_erase_committed_rows() {
    let f = Fixture::new();
    let before = f.commitment();
    let mut progress = CoordinatedReceiptProgressV1::Enrollment(f.enrollment.clone());
    let committed = progress.begin_manifest(&f.enrollment).unwrap();
    fixture::expire_receipt_monotonically(&f.session, f.manifest.receipt().nonce());
    assert!(matches!(require_live_receipt_pair(&f.lease(), &committed, &f.manifest),
        Err(JournalError::Expired)));
    assert!(matches!(progress.begin_manifest(&committed), Err(JournalError::Permission)));
    f.assert_rows_unchanged(&before);
    // This is a committed-row preservation/kernel test, not a simulation of
    // actual Final.execute_* or the publication result's nested-error shape.
}

#[test]
fn handoff_capabilities_do_not_clone_deref_deserialize_or_escape_to_generic_lease() {
    // These are compile-time negative trait assertions against the actual
    // production types. Adding a forbidden impl makes inference ambiguous and
    // fails the lib-test build; no dummy capability value is needed or minted.
    trait AmbiguousIfClone<A> { fn check() {} }
    impl<T: ?Sized> AmbiguousIfClone<()> for T {}
    impl<T: ?Sized + Clone> AmbiguousIfClone<u8> for T {}
    trait AmbiguousIfDeref<A> { fn check() {} }
    impl<T: ?Sized> AmbiguousIfDeref<()> for T {}
    impl<T: ?Sized + std::ops::Deref> AmbiguousIfDeref<u8> for T {}
    trait AmbiguousIfDeserialize<A> { fn check() {} }
    impl<T: ?Sized> AmbiguousIfDeserialize<()> for T {}
    impl<T: serde::de::DeserializeOwned> AmbiguousIfDeserialize<u8> for T {}
    trait AmbiguousIfGenericLease<A> { fn check() {} }
    impl<T: ?Sized> AmbiguousIfGenericLease<()> for T {}
    impl<T: Into<PreconstructionRecordLease<'static>>> AmbiguousIfGenericLease<u8> for T {}

    let _ = <CoordinatedAcceptedProvenanceV1 as AmbiguousIfClone<_>>::check;
    let _ = <CoordinatedAcceptedProvenanceV1 as AmbiguousIfDeref<_>>::check;
    let _ = <CoordinatedAcceptedProvenanceV1 as AmbiguousIfDeserialize<_>>::check;
    let _ = <CoordinatedAcceptedProvenanceV1 as AmbiguousIfGenericLease<_>>::check;
    let _ = <CoordinatedPurposeRecordLease<'static> as AmbiguousIfClone<_>>::check;
    let _ = <CoordinatedPurposeRecordLease<'static> as AmbiguousIfDeref<_>>::check;
    let _ = <CoordinatedPurposeRecordLease<'static> as AmbiguousIfDeserialize<_>>::check;
    let _ = <CoordinatedPurposeRecordLease<'static> as AmbiguousIfGenericLease<_>>::check;
}
