//! Synthetic, never-funded transaction/lifecycle qualification. These tests use
//! the real encrypted AccountVault and journal plus existing cfg(test) native
//! issuer/session fixtures. No compositor, socket/listener, node, wallet scan,
//! proof, transaction signing or user credential is invoked. Fixture approvals
//! do not establish genuine human approval or production native qualification.
use super::*;
use crate::{
    account::{PendingAccount, ProvisioningConsent},
    consent_journal::authority::fixture,
    native_ui::{recovery_test_authority, recovery_test_decision},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use wholepact_storage_security::{DatabaseKey, bundle::*};

fn random32() -> [u8; 32] {
    let mut value = [0; 32];
    getrandom::fill(&mut value).unwrap();
    value
}
fn public_transport_key() -> [u8; 32] {
    let secret = TransportSecret::from_bytes(random32()).unwrap();
    *secret.public_key().unwrap().as_bytes()
}
#[derive(Clone)]
struct SelectedPins {
    verifier_signing: [u8; 32],
    verifier_transport: [u8; 32],
    witness_transport: [u8; 32],
    witness_certificate_digest: String,
    return_transport: [u8; 32],
}
impl SelectedPins {
    fn new() -> Self {
        Self {
            // Only an explicitly selected nonzero pin is needed for setup. No
            // verifier assertion, signing operation or identity proof is made.
            verifier_signing: random32(),
            verifier_transport: public_transport_key(),
            witness_transport: public_transport_key(),
            witness_certificate_digest: hex::encode(random32()),
            return_transport: public_transport_key(),
        }
    }
    fn input(&self) -> NamedRecipientPins {
        NamedRecipientPins {
            verifier_signing: self.verifier_signing,
            verifier_transport: self.verifier_transport,
            witness_transport: self.witness_transport,
            witness_certificate_digest: self.witness_certificate_digest.clone(),
            return_transport: self.return_transport,
        }
    }
}
struct Fixture {
    // Drop database/vault handles before their temporary directory is removed.
    journal: SignerConsentJournal,
    session: SignerConsentSession,
    vault: AccountVault,
    native: Option<NativeAuthority>,
    enrollment: AccountEnrollmentRecord,
    manifest: AcceptedManifestRecord,
    selected: SelectedPins,
    dir: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        // Fresh local entropy, encrypted only under this automatically removed
        // temporary directory. Neither words nor key material are logged.
        let pending = PendingAccount::generate(ProvisioningConsent {
            privacy_domain: "synthetic-named-recipient-setup".into(),
            account_index: 0,
        })
        .unwrap();
        let words = pending.recovery_words().unwrap();
        let verified = pending.verify_backup(&words).unwrap();
        drop(words);
        let password = Zeroizing::new(random32());
        let mut vault = AccountVault::create(
            &dir.path().join("temporary-never-funded-vault"),
            verified,
            password.as_ref(),
        )
        .unwrap();
        drop(password);
        let journal = vault.create_authority_journal().unwrap();
        let native = recovery_test_authority();
        let session = fixture::native_session(
            &journal,
            native.binding(),
            native.principal_id(),
            native.measurement(),
        );
        let (enrollment, manifest) = enroll(&journal, &session, &vault, &native);
        Self {
            journal,
            session,
            vault,
            native: Some(native),
            enrollment,
            manifest,
            selected: SelectedPins::new(),
            dir,
        }
    }
    fn native(&self) -> &NativeAuthority {
        self.native.as_ref().unwrap()
    }
    fn prepare(&self, selected: &SelectedPins) -> PreparedNamedRecipientSetup {
        PreparedNamedRecipientSetup::prepare(
            &self.journal,
            &self.session,
            &self.vault,
            self.native(),
            self.enrollment.reference(),
            self.manifest.reference(),
            selected.input(),
        )
        .unwrap()
    }
    fn approve(&self, prepared: PreparedNamedRecipientSetup) -> LiveNamedRecipientProfile {
        let decision = recovery_test_decision(self.native(), prepared.digest());
        prepared
            .approve(decision, &self.journal, &self.session, &self.vault)
            .unwrap()
    }
    fn profile_count(&self) -> usize {
        self.journal
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM signer_named_recipient_profiles",
                [],
                |r| r.get(0),
            )
            .unwrap()
    }
    fn retained_payload(&self, reference: &str) -> Zeroizing<String> {
        Zeroizing::new(
            self.journal
                .connection
                .lock()
                .unwrap()
                .query_row(
                    "SELECT payload FROM signer_named_recipient_profiles WHERE reference=?1",
                    [reference],
                    |r| r.get(0),
                )
                .unwrap(),
        )
    }
    fn assert_no_financial_effects(&self) {
        let c = self.journal.connection.lock().unwrap();
        for table in [
            "signer_original_consents",
            "signer_release_intents",
            "signer_input_reservations",
            "signer_offline_local_admissions",
            "signer_named_recipient_originals",
            "signer_named_recipient_receipts",
            "signer_named_recipient_started",
            "signer_named_recipient_results",
            "signer_bridge_keyuse",
            "signer_bridge_results",
        ] {
            let count: usize = c
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                .unwrap();
            assert_eq!(count, 0, "setup must not create {table}");
        }
    }
    fn new_native_session(&mut self) {
        self.session.invalidate().unwrap();
        self.native = None;
        let native = recovery_test_authority();
        self.session = fixture::native_session(
            &self.journal,
            native.binding(),
            native.principal_id(),
            native.measurement(),
        );
        self.native = Some(native);
    }
}
fn enroll(
    journal: &SignerConsentJournal,
    session: &SignerConsentSession,
    vault: &AccountVault,
    native: &NativeAuthority,
) -> (AccountEnrollmentRecord, AcceptedManifestRecord) {
    let account_id = vault.account_id().unwrap();
    let mut input = crate::consent_journal::tests::proposal(
        "synthetic-setup-agreement",
        "synthetic-setup-obligation",
        "synthetic-setup-proposal",
    )
    .input()
    .clone();
    input.manifest.agreement.privacy_profile.mode = wholepact_core::PrivacyMode::DeclaredOperator;
    input.manifest.agreement.privacy_profile.proving_operator =
        Some("synthetic-explicitly-selected-prover".into());
    input
        .manifest
        .agreement
        .privacy_profile
        .dedicated_accounts_required = true;
    for participant in &mut input.manifest.participants {
        if participant.account_id == "account-alice" {
            participant.account_id = account_id.clone();
        }
    }
    for claimed in &mut input.manifest.inputs {
        if claimed.account_id == "account-alice" {
            claimed.account_id = account_id.clone();
        }
    }
    for output in &mut input.manifest.outputs {
        if let wholepact_core::OutputAllocation::Return {
            account_id: owner, ..
        } = &mut output.allocation
        {
            if owner == "account-alice" {
                *owner = account_id.clone();
            }
        }
    }
    let proposal = wholepact_core::Proposal::validate(input).unwrap();
    let enrollment = journal
        .record_enrollment(fixture::approve_enrollment(
            session,
            EnrollmentTerms {
                account_id,
                agreement_id: proposal.manifest().agreement.agreement_id.clone(),
                participant_id: "alice".into(),
                principal_id: native.principal_id().into(),
                network_profile_id: proposal.manifest().agreement.network_profile_id.clone(),
                privacy_domain: vault.account().privacy_domain().into(),
                account_fvk_digest: hex::encode(Sha256::digest(
                    vault.account().fvk().unwrap().to_bytes(),
                )),
                transport: TransportIdentityBinding::RemoteAuthenticatedKeys {
                    transport_identity_id: "synthetic-enrollment-transport".into(),
                    sender_key_digest: hex::encode(random32()),
                    recipient_key_digest: hex::encode(random32()),
                    channel_binding_digest: hex::encode(random32()),
                },
                aggregate_budget_limit_zatoshis: 1_000_000_000,
                receipt: fixture::receipt(session),
            },
        ))
        .unwrap();
    let prepared = session.prepare_manifest(&enrollment, &proposal).unwrap();
    let decision = fixture::decision(session, prepared.review_digest());
    let manifest = journal
        .record_accepted_manifest(session.approve_manifest(prepared, decision).unwrap())
        .unwrap();
    (enrollment, manifest)
}

#[test]
fn setup_exact_retry_and_reopen_retain_original_key_reference_and_payload() {
    let mut f = Fixture::new();
    let first = f.approve(f.prepare(&f.selected));
    first.check_current(&f.journal, &f.session).unwrap();
    let original = f.retained_payload(first.reference());
    assert!(first.record.transport_secret != [0; 32]);
    let repeated = f.approve(f.prepare(&f.selected));
    assert_eq!(first.reference(), repeated.reference());
    assert_eq!(
        first.transport_public_key(),
        repeated.transport_public_key()
    );
    // Do not use assert_eq! on secret-bearing records/payloads: failures must not
    // print a temporary transport secret into logs.
    assert!(first.record.transport_secret == repeated.record.transport_secret);
    assert!(f.retained_payload(first.reference()).as_str() == original.as_str());
    assert_eq!(f.profile_count(), 1);

    // Keep only private expected bytes and the original public lookup reference;
    // no original Prepared/live wrapper is retained for the restart entry.
    let original_ref = first.reference().to_owned();
    let original_public = *first.transport_public_key();
    let original_secret = Zeroizing::new(first.record.transport_secret);
    let enrollment_ref = first.record.enrollment_ref.clone();
    let manifest_ref = first.record.manifest_ref.clone();
    drop(first);
    drop(repeated);

    // Reopen the actual original vault-backed encrypted DB and use a different
    // native source instance/session. Historical provenance must remain exact.
    f.session.invalidate().unwrap();
    f.native = None;
    f.journal = f.vault.open_authority_journal().unwrap();
    f.new_native_session();
    let reopened = PreparedNamedRecipientSetup::reopen(
        &f.journal,
        &f.session,
        &f.vault,
        f.native(),
        &original_ref,
    )
    .unwrap();
    assert_eq!(reopened.record.enrollment_ref, enrollment_ref);
    assert_eq!(reopened.record.manifest_ref, manifest_ref);
    let resumed = f.approve(reopened);
    resumed.check_current(&f.journal, &f.session).unwrap();
    assert_eq!(resumed.reference(), original_ref);
    assert_eq!(resumed.transport_public_key(), &original_public);
    assert!(resumed.record.transport_secret == *original_secret);
    assert!(f.retained_payload(&original_ref).as_str() == original.as_str());
    assert_eq!(f.profile_count(), 1);
    {
        let c = f.journal.connection.lock().unwrap();
        let references: (usize, usize) = c
            .query_row(
                "SELECT (SELECT count(*) FROM signer_enrollments), \
                 (SELECT count(*) FROM signer_accepted_manifests)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(references, (1, 1));
    }
    f.assert_no_financial_effects();
    assert_ciphertext_only(
        &f.dir
            .path()
            .join("temporary-never-funded-vault/authority.sqlite"),
    );
}

#[test]
fn setup_every_selected_pin_has_a_separate_original_binding() {
    let f = Fixture::new();
    let original = f.approve(f.prepare(&f.selected));
    let original_payload = f.retained_payload(original.reference());
    let mut setup_digests = BTreeSet::from([original.record.original_setup_digest.clone()]);
    let mut references = BTreeSet::from([original.reference().to_owned()]);
    for changed_pin in 0..5 {
        let mut selected = f.selected.clone();
        match changed_pin {
            0 => selected.verifier_signing = random32(),
            1 => selected.verifier_transport = public_transport_key(),
            2 => selected.witness_transport = public_transport_key(),
            3 => selected.witness_certificate_digest = hex::encode(random32()),
            4 => selected.return_transport = public_transport_key(),
            _ => unreachable!(),
        }
        let changed = f.approve(f.prepare(&selected));
        assert!(setup_digests.insert(changed.record.original_setup_digest.clone()));
        assert!(references.insert(changed.reference().into()));
        assert_ne!(
            original.transport_public_key(),
            changed.transport_public_key()
        );
        let retry = f.approve(f.prepare(&selected));
        assert_eq!(retry.reference(), changed.reference());
        assert!(retry.record.transport_secret == changed.record.transport_secret);
    }
    assert_eq!(f.profile_count(), 6);
    assert!(f.retained_payload(original.reference()).as_str() == original_payload.as_str());
    f.assert_no_financial_effects();
}

#[test]
fn setup_wrong_native_source_digest_and_session_origin_do_not_write() {
    let f = Fixture::new();
    let other_native = recovery_test_authority();
    // The fixed test issuers intentionally share display identity; only actual
    // source-instance equality is authority. Matching labels must not suffice.
    assert_eq!(
        f.native().binding().entry_digest(),
        other_native.binding().entry_digest()
    );
    assert!(f.native().binding() != other_native.binding());
    let prepared = f.prepare(&f.selected);
    let decision = recovery_test_decision(&other_native, prepared.digest());
    assert!(matches!(
        prepared.approve(decision, &f.journal, &f.session, &f.vault),
        Err(crate::Error::ReviewMismatch)
    ));
    let prepared = f.prepare(&f.selected);
    let wrong_digest = if prepared.digest() == "ff".repeat(32) {
        "ee".repeat(32)
    } else {
        "ff".repeat(32)
    };
    let decision = recovery_test_decision(f.native(), &wrong_digest);
    assert!(matches!(
        prepared.approve(decision, &f.journal, &f.session, &f.vault),
        Err(crate::Error::ReviewMismatch)
    ));
    for session in [
        fixture::session(&f.journal, f.native().principal_id()),
        fixture::native_session(
            &f.journal,
            other_native.binding(),
            f.native().principal_id(),
            f.native().measurement(),
        ),
    ] {
        assert!(matches!(
            PreparedNamedRecipientSetup::prepare(
                &f.journal,
                &session,
                &f.vault,
                f.native(),
                f.enrollment.reference(),
                f.manifest.reference(),
                f.selected.input(),
            ),
            Err(crate::Error::Locked)
        ));
    }
    assert_eq!(f.profile_count(), 0);
    f.assert_no_financial_effects();
}

#[test]
fn setup_fresh_decision_cannot_renew_an_expired_original_preparation() {
    let f = Fixture::new();
    let mut prepared = f.prepare(&f.selected);
    prepared.created = Instant::now() - Duration::from_secs(121);
    let decision = recovery_test_decision(f.native(), prepared.digest());
    assert!(matches!(
        prepared.approve(decision, &f.journal, &f.session, &f.vault),
        Err(crate::Error::Locked)
    ));
    assert_eq!(f.profile_count(), 0);
    f.assert_no_financial_effects();
}

#[test]
fn setup_original_deadline_expiring_after_insert_rolls_back_before_commit() {
    let f = Fixture::new();
    let mut prepared = f.prepare(&f.selected);
    // Shorten the real original preparation clock, then let real monotonic time
    // pass it after INSERT. The production expiry predicate is not substituted.
    prepared.created = Instant::now() - Duration::from_secs(118);
    let original_deadline = prepared.created + Duration::from_secs(120);
    let reached_transaction = Arc::new(AtomicBool::new(false));
    let reached = reached_transaction.clone();
    prepared.before_commit = Some(Box::new(move || {
        reached.store(true, Ordering::Release);
        if let Some(remaining) = original_deadline.checked_duration_since(Instant::now()) {
            std::thread::sleep(remaining);
        }
        assert!(Instant::now() >= original_deadline);
    }));
    let decision = recovery_test_decision(f.native(), prepared.digest());
    assert!(matches!(
        prepared.approve(decision, &f.journal, &f.session, &f.vault),
        Err(crate::Error::Locked)
    ));
    assert!(reached_transaction.load(Ordering::Acquire));
    assert_eq!(f.profile_count(), 0);
    f.assert_no_financial_effects();
    // A distinct, fresh review can now create its first original, proving that
    // the expired uncommitted generated key did not leave a poisoned setup row.
    let live = f.approve(f.prepare(&f.selected));
    live.check_current(&f.journal, &f.session).unwrap();
    assert_eq!(f.profile_count(), 1);
}

#[test]
fn setup_native_cancel_after_insert_rolls_back_before_commit() {
    let mut f = Fixture::new();
    let mut prepared = f.prepare(&f.selected);
    let decision = recovery_test_decision(f.native(), prepared.digest());
    let native = f.native.take().unwrap();
    let reached_transaction = Arc::new(AtomicBool::new(false));
    let reached = reached_transaction.clone();
    prepared.before_commit = Some(Box::new(move || {
        reached.store(true, Ordering::Release);
        drop(native); // Actual native Drop invalidates the original shared source.
    }));
    assert!(matches!(
        prepared.approve(decision, &f.journal, &f.session, &f.vault),
        Err(crate::Error::Locked)
    ));
    assert!(reached_transaction.load(Ordering::Acquire));
    assert_eq!(f.profile_count(), 0);
    f.assert_no_financial_effects();
}

#[test]
fn setup_capacity_failure_rolls_back_and_exact_retry_can_then_create_one_profile() {
    let mut f = Fixture::new();
    let original_limits = f.journal.capacity_limits;
    f.journal.capacity_limits =
        storage::capacity_estimate(&f.journal.connection.lock().unwrap()).unwrap();
    let prepared = f.prepare(&f.selected);
    let decision = recovery_test_decision(f.native(), prepared.digest());
    assert!(matches!(
        prepared.approve(decision, &f.journal, &f.session, &f.vault),
        Err(crate::Error::ConsentJournal(JournalError::Database))
    ));
    assert_eq!(f.profile_count(), 0);
    f.journal.capacity_limits = original_limits;
    let live = f.approve(f.prepare(&f.selected));
    live.check_current(&f.journal, &f.session).unwrap();
    assert_eq!(f.profile_count(), 1);
    f.assert_no_financial_effects();
}

#[test]
fn setup_session_invalidation_and_native_close_end_live_association_only() {
    let mut f = Fixture::new();
    let live = f.approve(f.prepare(&f.selected));
    let original = f.retained_payload(live.reference());
    let prepared = f.prepare(&f.selected);
    let decision = recovery_test_decision(f.native(), prepared.digest());
    f.session.invalidate().unwrap();
    assert!(matches!(
        prepared.approve(decision, &f.journal, &f.session, &f.vault),
        Err(crate::Error::Locked)
    ));
    assert!(live.check_current(&f.journal, &f.session).is_err());
    f.new_native_session();
    let renewed = f.approve(f.prepare(&f.selected));
    renewed.check_current(&f.journal, &f.session).unwrap();
    assert_eq!(live.reference(), renewed.reference());
    f.native = None;
    assert!(renewed.check_current(&f.journal, &f.session).is_err());
    assert!(f.retained_payload(live.reference()).as_str() == original.as_str());
    assert_eq!(f.profile_count(), 1);
    f.assert_no_financial_effects();
}

#[test]
fn setup_quarantine_blocks_new_preparation_pending_commit_and_retained_live_profile() {
    let f = Fixture::new();
    let live = f.approve(f.prepare(&f.selected));
    let original = f.retained_payload(live.reference());
    let prepared = f.prepare(&f.selected);
    let decision = recovery_test_decision(f.native(), prepared.digest());
    f.journal.require_recovery().unwrap();
    assert!(f.journal.account_state().unwrap().recovery_required);
    assert!(matches!(
        prepared.approve(decision, &f.journal, &f.session, &f.vault),
        Err(crate::Error::Locked)
    ));
    assert!(matches!(
        PreparedNamedRecipientSetup::prepare(
            &f.journal,
            &f.session,
            &f.vault,
            f.native(),
            f.enrollment.reference(),
            f.manifest.reference(),
            f.selected.input(),
        ),
        Err(crate::Error::Locked)
    ));
    assert!(live.check_current(&f.journal, &f.session).is_err());
    assert!(
        PreparedNamedRecipientSetup::reopen(
            &f.journal,
            &f.session,
            &f.vault,
            f.native(),
            live.reference(),
        )
        .is_err()
    );
    assert!(f.retained_payload(live.reference()).as_str() == original.as_str());
    assert_eq!(f.profile_count(), 1);
    f.assert_no_financial_effects();
}

fn coverage() -> Coverage {
    Coverage {
        present: BTreeMap::from([(
            JournalKind::SignerConsentAuthority,
            vec!["signer-authority".into()],
        )]),
        absent: BTreeSet::from([
            JournalKind::CoordinationAuthority,
            JournalKind::WalletScan,
            JournalKind::ProofWitness,
            JournalKind::SignedResults,
            JournalKind::ExactTransactions,
            JournalKind::Submission,
            JournalKind::TransportInbox,
            JournalKind::TransportOutbox,
        ]),
    }
}
fn assert_ciphertext_only(path: &Path) {
    let bytes = std::fs::read(path).unwrap();
    assert!(!bytes.starts_with(b"SQLite format 3\0"));
    for needle in [
        b"transport_secret".as_slice(),
        b"synthetic-named-recipient-setup".as_slice(),
        b"synthetic-setup-agreement".as_slice(),
    ] {
        assert!(!bytes.windows(needle.len()).any(|part| part == needle));
    }
}

#[test]
fn setup_real_profile_backup_restores_as_history_without_live_profile_conversion() {
    let f = Fixture::new();
    let private_directory = crate::files::PrivateDirectory::open(f.dir.path()).unwrap();
    let live = f.approve(f.prepare(&f.selected));
    let original = f.retained_payload(live.reference());
    let account_id = f.vault.account_id().unwrap();
    let archive = f.dir.path().join("synthetic-profile-archive.sqlite");
    let restored = f.dir.path().join("synthetic-quarantined-profile.sqlite");
    let archive_key = DatabaseKey::from_bytes(random32());
    let restored_key = DatabaseKey::from_bytes(random32());
    let adapter = f.journal.backup_adapter();
    let sources = [RegisteredJournal::new("signer-authority", &adapter).unwrap()];
    snapshot(SnapshotRequest {
        // The existing test BackupGate authorizes only this synthetic archive.
        principal_id: "synthetic-owner",
        profile_id: "synthetic-signer-profile",
        coverage: coverage(),
        sources: &sources,
        destination: &archive,
        key: &archive_key,
        authority: &crate::consent_journal::tests::BackupGate,
    })
    .unwrap();
    let report = restore(RestoreRequest {
        principal_id: "synthetic-owner",
        profile_id: "synthetic-signer-profile",
        archive: &archive,
        key: &archive_key,
        targets: &[RestoreTarget {
            component_id: "signer-authority",
            template: SignerConsentBundleAdapter::template(),
            destination: &restored,
            key: &restored_key,
        }],
        authority: &crate::consent_journal::tests::BackupGate,
    })
    .unwrap();
    assert!(!report.authorization_allowed);
    // The restored DB cannot supply the SignerConsentJournal required by
    // prepare/approve. No test-only promotion/reset constructor is introduced.
    assert!(SignerConsentJournal::open_encrypted(
        &restored,
        &restored_key,
        &account_id,
        &private_directory
            .signer_journal_source_owner_for_test(&restored)
            .unwrap()
    )
    .is_err());
    let source = recovery::VerifiedSignerRecoverySource::open(
        history::HistoryOpenRequest {
            archive: &archive,
            archive_key: &archive_key,
            component_id: "signer-authority",
            restored_component: &restored,
            restored_key: &restored_key,
        },
        SignerConsentBundleAdapter::template(),
    )
    .unwrap();
    assert_eq!(source.provenance().schema_version, SCHEMA_VERSION);
    let retained = source
        .tables()
        .iter()
        .find(|table| table.name() == "signer_named_recipient_profiles")
        .unwrap();
    assert_eq!(retained.rows().len(), 1);
    assert!(retained.rows()[0].cells().iter().any(|cell| {
        matches!(cell, recovery::RecoveryCell::Text(value) if value == original.as_str())
    }));
    assert!(matches!(
        offline_history::require_legacy_recovery_source(&source),
        Err(JournalError::NamedRecipientHistoryUnsupported)
    ));
    let history = QuarantinedJournalRead::from_verified(source, &account_id).unwrap();
    let inventory = history.named_recipient_history_inventory().unwrap();
    assert_eq!(inventory.profiles.len(), 1);
    assert_eq!(inventory.profiles[0].reference, live.reference());
    assert!(inventory.originals.is_empty());
    assert!(inventory.started.is_empty());
    assert!(inventory.results.is_empty());
    let history_json = serde_json::to_string(&inventory).unwrap();
    assert!(!history_json.contains("transport_secret"));
    assert_ciphertext_only(&archive);
    assert_ciphertext_only(&restored);
    live.check_current(&f.journal, &f.session).unwrap();
    assert!(f.retained_payload(live.reference()).as_str() == original.as_str());
    f.assert_no_financial_effects();
}

#[test]
fn setup_postcommit_uncertainty_reopens_by_preapproval_commitment_without_new_key() {
    let mut f = Fixture::new();
    let mut prepared = f.prepare(&f.selected);
    let commitment = prepared.record.original_setup_digest.clone();
    prepared.created = Instant::now() - Duration::from_secs(118);
    let deadline = prepared.created + Duration::from_secs(120);
    prepared.after_commit = Some(Box::new(move || {
        if let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
            std::thread::sleep(remaining);
        }
    }));
    let decision = recovery_test_decision(f.native(), prepared.digest());
    assert!(matches!(
        prepared.approve(decision, &f.journal, &f.session, &f.vault),
        Err(crate::Error::Uncertain)
    ));
    assert_eq!(f.profile_count(), 1);
    // Private test oracle only: caller has no delivered profile reference/key.
    let original: Zeroizing<String> = Zeroizing::new(f.journal.connection.lock().unwrap().query_row(
        "SELECT payload FROM signer_named_recipient_profiles WHERE original_setup_digest=?1", [&commitment], |r| r.get(0)).unwrap());
    f.session.invalidate().unwrap();
    f.native = None;
    f.journal = f.vault.open_authority_journal().unwrap();
    f.new_native_session();
    let prepared = PreparedNamedRecipientSetup::reopen_by_setup_commitment(
        &f.journal,
        &f.session,
        &f.vault,
        f.native(),
        &commitment,
    )
    .unwrap();
    let recovered = f.approve(prepared);
    assert!(f.retained_payload(recovered.reference()).as_str() == original.as_str());
    assert_eq!(f.profile_count(), 1);
    f.assert_no_financial_effects();
}

mod original_import_tests;

#[test]
fn named_display_association_never_waits_for_held_journal_lock() {
    let f = Fixture::new();
    let live = f.approve(f.prepare(&f.selected));
    std::thread::scope(|scope| {
        let (ready_send, ready) = std::sync::mpsc::sync_channel(1);
        let (release, release_wait) = std::sync::mpsc::sync_channel(1);
        let journal = &f.journal;
        scope.spawn(move || {
            let _connection = journal.connection.lock().unwrap();
            ready_send.send(()).unwrap();
            // A future blocking regression fails instead of hanging this test.
            let _ = release_wait.recv_timeout(Duration::from_secs(2));
        });
        ready.recv().unwrap();
        let before = Instant::now();
        live.check_display_association(&f.journal, f.native())
            .unwrap();
        let elapsed = before.elapsed();
        let _ = release.send(());
        assert!(elapsed < Duration::from_millis(250));
    });
    let other = recovery_test_authority();
    assert!(live.check_display_association(&f.journal, &other).is_err());
}
