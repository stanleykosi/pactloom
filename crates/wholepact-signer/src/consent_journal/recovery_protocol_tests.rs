//! Never-funded sealed-history fixtures. Native decisions here are explicit
//! cfg(test) issuers, not attended UI or live TLS qualification.
use super::*;
use crate::consent_journal::recovery_activation::*;
use crate::native_ui::{recovery_test_authority, recovery_test_decision};
use std::collections::{BTreeMap, BTreeSet};
use wholepact_authority::{OwnerControl, OwnerControlRequest};
use wholepact_storage_security::bundle::*;

struct Archived {
    archive: std::path::PathBuf,
    restored: std::path::PathBuf,
    archive_key: DatabaseKey,
    restored_key: DatabaseKey,
}
impl Archived {
    fn new(f: &Fixture, source: &SignerConsentJournal) -> Self {
        let archive = f._directory.path().join("recovery-bundle.sqlite");
        let restored = f._directory.path().join("quarantined.sqlite");
        let archive_key = DatabaseKey::from_bytes([0x91; 32]);
        let restored_key = DatabaseKey::from_bytes([0x92; 32]);
        let adapter = source.backup_adapter();
        let sources = [RegisteredJournal::new("signer-authority", &adapter).unwrap()];
        let coverage = Coverage {
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
        };
        snapshot(SnapshotRequest {
            principal_id: "synthetic-owner",
            profile_id: "synthetic-signer-profile",
            coverage,
            sources: &sources,
            destination: &archive,
            key: &archive_key,
            authority: &crate::consent_journal::tests::BackupGate,
        })
        .unwrap();
        restore(RestoreRequest {
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
        Self {
            archive,
            restored,
            archive_key,
            restored_key,
        }
    }
    fn open(&self) -> recovery::VerifiedSignerRecoverySource {
        recovery::VerifiedSignerRecoverySource::open(
            history::HistoryOpenRequest {
                archive: &self.archive,
                archive_key: &self.archive_key,
                component_id: "signer-authority",
                restored_component: &self.restored,
                restored_key: &self.restored_key,
            },
            SignerConsentBundleAdapter::template(),
        )
        .unwrap()
    }
}
fn pin_source(f: &Fixture, journal: &SignerConsentJournal) {
    let session = fixture::session(journal, "synthetic-recovery-pin-owner");
    let (history, active) = synthetic::reconciled_session(
        &f.witness,
        &"b2".repeat(32),
        "account-alice",
        &f.request.reservation.network_profile_id,
    )
    .unwrap();
    let prepared = session
        .prepare_writer_reconciliation(journal, history, active)
        .unwrap();
    let decision = fixture::decision(&session, prepared.review_digest());
    journal
        .reconcile_writer(
            session
                .approve_writer_reconciliation(prepared, decision)
                .unwrap(),
        )
        .unwrap();
}
fn inventory(
    f: &Fixture,
    source: &recovery::VerifiedSignerRecoverySource,
) -> RecoveryActivationInventory {
    let (history, _) = synthetic::reconciled_session(
        &f.witness,
        &"b2".repeat(32),
        "account-alice",
        &f.request.reservation.network_profile_id,
    )
    .unwrap();
    RecoveryActivationInventory::prepare(
        source,
        "synthetic-recovery-operation".into(),
        "d4".repeat(32),
        f._directory.path().join("successor"),
        history.disclosure().clone(),
        "c3".repeat(32),
    )
    .unwrap()
}
fn replace(f: &Fixture, inventory: &RecoveryActivationInventory) {
    let s = synthetic::snapshot(
        &f.witness,
        &"a1".repeat(32),
        "account-alice",
        &f.request.reservation.network_profile_id,
    )
    .unwrap();
    let now = now_ms().unwrap().max(s.last_witness_time_ms + 1);
    synthetic::control(
        &f.witness,
        &"a1".repeat(32),
        OwnerControlRequest {
            operation_id: inventory.operation_id().into(),
            account_id: s.account_id,
            network_profile_id: s.network_profile_id,
            expected_head: s.head,
            writer_epoch: s.writer_epoch,
            control: OwnerControl::RecoverWriter {
                writer_certificate_digest: "c3".repeat(32),
                inventory_digest: inventory.digest().unwrap(),
            },
        },
        now,
    )
    .unwrap();
    synthetic::activate(&f.witness, &"c3".repeat(32), now + 1).unwrap();
}
fn fence(
    f: &Fixture,
    inventory: &RecoveryActivationInventory,
) -> wholepact_authority::AuthenticatedRecoveryFence {
    synthetic::recovery_fence(
        &f.witness,
        &"c3".repeat(32),
        "account-alice",
        &f.request.reservation.network_profile_id,
        inventory.operation_id(),
        &inventory.digest().unwrap(),
    )
    .unwrap()
}
fn approve(
    f: &Fixture,
    archive: &Archived,
    inventory: RecoveryActivationInventory,
    native: &crate::native_ui::NativeAuthority,
) -> ApprovedRecoveryActivation {
    let prepared = PreparedRecoveryActivation::prepare(
        archive.open(),
        inventory.clone(),
        fence(f, &inventory),
        native,
    )
    .unwrap();
    let decision = recovery_test_decision(native, prepared.digest());
    prepared.approve(decision, native).unwrap()
}
#[test]
fn recovery_preserves_originals_source_and_exact_successor_replay() {
    let f = Fixture::new();
    pin_source(&f, &f.journal);
    let _permit = f.permit();
    // Synthetic historical positive evidence must not survive as a discount.
    {
        let c = f.journal.connection.lock().unwrap();
        c.execute("INSERT INTO signer_settlement_sources VALUES('synthetic-source','account-alice','historical source only')",[]).unwrap();
        c.execute("INSERT INTO signer_settlement_events VALUES(1,'synthetic-old-positive','authorization-a','synthetic-source','canonical_consumed','historical evidence only')",[]).unwrap();
    }
    let archive = Archived::new(&f, &f.journal);
    let source = archive.open();
    let before = std::fs::read(&archive.restored).unwrap();
    let inventory = inventory(&f, &source);
    replace(&f, &inventory);
    drop(source);
    let native = recovery_test_authority();
    std::fs::create_dir(inventory.target_profile()).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        inventory.target_profile(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let private_directory =
        crate::files::PrivateDirectory::open(inventory.target_profile()).unwrap();
    let path = inventory.target_profile().join("authority.sqlite");
    let successor_source = private_directory
        .signer_journal_source_owner_for_test(&path)
        .unwrap();
    let key = DatabaseKey::from_bytes([0x93; 32]);
    let receipt = approve(&f, &archive, inventory.clone(), &native)
        .commit(fence(&f, &inventory), &path, &key, &successor_source)
        .unwrap();
    receipt.check_current().unwrap();
    let first = receipt.record().clone();
    // Deterministic denial-only test clock: expiry after admission does not
    // pretend to undo an already admitted durable write. Next admission fails.
    let trigger = receipt.synthetic_deadline_trigger();
    let admitted = receipt.admit_publication().unwrap();
    trigger.store(true, std::sync::atomic::Ordering::Release);
    let marker = f._directory.path().join("synthetic-admitted-marker");
    std::fs::write(&marker, b"synthetic admitted exact durable write").unwrap();
    std::fs::File::open(&marker).unwrap().sync_all().unwrap();
    drop(admitted);
    assert!(receipt.admit_publication().is_err());
    assert!(matches!(
        receipt.check_current(),
        Err(JournalError::Expired)
    ));

    assert!(matches!(
        SignerConsentJournal::open_encrypted(&path, &key, "account-alice", &successor_source),
        Err(JournalError::RecoveryRequired)
    ));
    let c = wholepact_storage_security::open_encrypted(&path, &key)
        .unwrap()
        .into_connection();
    assert_eq!(
        c.query_row("SELECT count(*) FROM signer_original_consents", [], |r| r
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        1
    );
    assert_eq!(
        c.query_row("SELECT count(*) FROM signer_remote_exposures", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        c.query_row("SELECT writer_epoch FROM signer_account", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        c.query_row(
            "SELECT kind FROM signer_settlement_events ORDER BY sequence DESC LIMIT 1",
            [],
            |r| r.get::<_, String>(0)
        )
        .unwrap(),
        "reopened"
    );
    assert_eq!(
        c.query_row("SELECT count(*) FROM signer_settlement_events", [], |r| r
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        2
    );
    drop(c);
    let replay = approve(&f, &archive, inventory.clone(), &native)
        .commit(fence(&f, &inventory), &path, &key, &successor_source)
        .unwrap();
    assert!(replay.record() == &first);
    assert_eq!(before, std::fs::read(&archive.restored).unwrap());
    // Private synthetic tampering fixture: a different immutable original in
    // the staged copy must not be normalized, ignored or overwritten on retry.
    let c = wholepact_storage_security::open_encrypted(&path, &key)
        .unwrap()
        .into_connection();
    c.execute("UPDATE signer_account SET writer_epoch=3", [])
        .unwrap();
    drop(c);
    assert!(matches!(
        approve(&f, &archive, inventory.clone(), &native).commit(
            fence(&f, &inventory),
            &path,
            &key,
            &successor_source
        ),
        Err(JournalError::Conflict)
    ));
}
#[test]
fn recovery_blocks_local_only_original_and_wrong_native_decision() {
    let f = Fixture::new();
    pin_source(&f, &f.journal);
    let archive = Archived::new(&f, &f.journal);
    let source = archive.open();
    let inventory = inventory(&f, &source);
    replace(&f, &inventory);
    let native = recovery_test_authority();
    assert!(matches!(
        PreparedRecoveryActivation::prepare(
            source,
            inventory.clone(),
            fence(&f, &inventory),
            &native
        ),
        Err(JournalError::RecoveryRequired)
    ));
    // No waiver is accepted; the original remains only in quarantined history.
    assert!(!inventory.target_profile().exists());
}
#[test]
fn recovery_imports_witness_only_reservations_without_creating_original_consent() {
    let f = Fixture::new();
    let empty = SignerConsentJournal::create_encrypted(
        &f._directory.path().join("older-empty.sqlite"),
        &DatabaseKey::from_bytes([0x95; 32]),
        "account-alice",
        1,
        false,
        &f.private_directory
            .signer_journal_source_owner_for_test(&f._directory.path().join("older-empty.sqlite"))
            .unwrap(),
    )
    .unwrap();
    pin_source(&f, &empty);
    let archive = Archived::new(&f, &empty);
    let _permit = f.permit();
    let source = archive.open();
    let inventory = inventory(&f, &source);
    replace(&f, &inventory);
    let native = recovery_test_authority();
    let prepared = PreparedRecoveryActivation::prepare(
        source,
        inventory.clone(),
        fence(&f, &inventory),
        &native,
    )
    .unwrap();
    assert!(matches!(
        prepared.approve(recovery_test_decision(&native, &"ff".repeat(32)), &native),
        Err(JournalError::Permission)
    ));
    std::fs::create_dir(inventory.target_profile()).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        inventory.target_profile(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let private_directory =
        crate::files::PrivateDirectory::open(inventory.target_profile()).unwrap();
    let path = inventory.target_profile().join("authority.sqlite");
    let successor_source = private_directory
        .signer_journal_source_owner_for_test(&path)
        .unwrap();
    let key = DatabaseKey::from_bytes([0x96; 32]);
    approve(&f, &archive, inventory.clone(), &native)
        .commit(fence(&f, &inventory), &path, &key, &successor_source)
        .unwrap();
    let c = wholepact_storage_security::open_encrypted(&path, &key)
        .unwrap()
        .into_connection();
    assert_eq!(
        c.query_row("SELECT count(*) FROM signer_original_consents", [], |r| r
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        0
    );
    assert_eq!(
        c.query_row("SELECT count(*) FROM signer_remote_exposures", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn recovery_rejects_unpinned_history_and_foreign_reconciliation_head() {
    for pinned in [false, true] {
        let f = Fixture::new();
        if pinned {
            pin_source(&f, &f.journal);
            let c = f.journal.connection.lock().unwrap();
            c.execute("INSERT INTO signer_writer_reconciliations SELECT ?1,disclosure,head_sequence,?2,writer_epoch,payload FROM signer_writer_reconciliations LIMIT 1",rusqlite::params!["aa".repeat(32),"ff".repeat(32)]).unwrap();
        }
        let _permit = f.permit();
        let archive = Archived::new(&f, &f.journal);
        let source = archive.open();
        let inventory = inventory(&f, &source);
        replace(&f, &inventory);
        let native = recovery_test_authority();
        let result = PreparedRecoveryActivation::prepare(
            source,
            inventory.clone(),
            fence(&f, &inventory),
            &native,
        );
        if pinned {
            assert!(matches!(result, Err(JournalError::Conflict)));
        } else {
            assert!(matches!(result, Err(JournalError::RecoveryRequired)));
        }
    }
}

#[test]
fn recovery_profile_publishes_reopens_and_rebases_only_absent_owner_operation() {
    use crate::account::AccountVault;
    let witness_dir = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(witness_dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut witness_slot = None;
    let now = now_ms().unwrap();
    let (temp, original, source) =
        crate::account::recovery_profile_fixture_with(|vault, journal| {
            let mut wallet =
                wholepact_wallet::wallet::DedicatedTestnetWallet::from_encrypted_connection(
                    vault.create_viewing_wallet_storage().unwrap(),
                )
                .unwrap();
            wallet
                .import_dedicated_fvk(
                    &vault.account().fvk().unwrap(),
                    wholepact_wallet::wallet::AccountBirthday::from_parts(
                        zcash_client_backend::data_api::chain::ChainState::empty(
                            4_465_039u32.into(),
                            zcash_primitives::block::BlockHash([50; 32]),
                        ),
                        None,
                    ),
                )
                .unwrap();
            drop(wallet);
            let account = vault.account_id().unwrap();
            let policy = AccountPolicy {
                account_use_genesis: None,
                witness_id: "synthetic-surviving-witness".into(),
                account_id: account.clone(),
                network_profile_id: "synthetic-testnet".into(),
                owner_certificate_digest: "a1".repeat(32),
                initial_writer_certificate_digest: "b2".repeat(32),
                initial_writer_epoch: 1,
                enrollment_refs: vec!["c1".repeat(32)],
                agreement_ids: vec!["synthetic-agreement".into()],
                recipient_scope_digests: vec!["c2".repeat(32)],
                aggregate_budget_zatoshis: 100,
                per_operation_limit_zatoshis: 80,
                maximum_fee_share_zatoshis: 5,
                maximum_transaction_fee_zatoshis: 10,
                maximum_permit_lifetime_ms: 120_000,
                policy_expires_at_ms: now + 600_000,
            };
            let witness = AuthorityJournal::create_encrypted(
                &witness_dir.path().join("witness.sqlite"),
                &DatabaseKey::from_bytes([0xa9; 32]),
                policy,
            )
            .unwrap();
            synthetic::activate(&witness, &"b2".repeat(32), now).unwrap();
            let (history, active) = synthetic::reconciled_session(
                &witness,
                &"b2".repeat(32),
                &account,
                "synthetic-testnet",
            )
            .unwrap();
            let session = fixture::session(journal, "synthetic-native-owner");
            let prepared = session
                .prepare_writer_reconciliation(journal, history, active)
                .unwrap();
            let decision = fixture::decision(&session, prepared.review_digest());
            journal
                .reconcile_writer(
                    session
                        .approve_writer_reconciliation(prepared, decision)
                        .unwrap(),
                )
                .unwrap();
            witness_slot = Some(witness);
        });
    assert!(source.wallet().is_some());
    let original_wallet =
        std::fs::read(temp.path().join("quarantine/viewing-wallet.sqlite")).unwrap();
    let witness = witness_slot.unwrap();
    let account = original.account_id().unwrap();
    let (history, _) =
        synthetic::reconciled_session(&witness, &"b2".repeat(32), &account, "synthetic-testnet")
            .unwrap();
    let inventory = RecoveryActivationInventory::prepare(
        &source,
        "synthetic-profile-recovery".into(),
        "d7".repeat(32),
        temp.path().join("activated"),
        history.disclosure().clone(),
        "c3".repeat(32),
    )
    .unwrap();
    verify_recovery_continuity(&source, &history).unwrap();
    let password = b"synthetic-successor-password";
    original
        .stage_recovery_plan(&inventory, &source, password)
        .unwrap();
    let pending =
        AccountVault::unlock_pending_recovery(inventory.target_profile(), password).unwrap();
    assert!(pending.open_viewing_wallet_storage().is_err());
    let wallet_key_path = inventory.target_profile().join("viewing-wallet-key.wp");
    let wrapped_key = std::fs::read(&wallet_key_path).unwrap();
    let mut altered_key = wrapped_key.clone();
    altered_key[0] ^= 1;
    std::fs::write(&wallet_key_path, altered_key).unwrap();
    assert!(pending.verify_recovery_plan().is_err());
    std::fs::write(&wallet_key_path, &wrapped_key).unwrap();
    pending.verify_recovery_plan().unwrap();
    let mut request = OwnerControlRequest {
        operation_id: inventory.operation_id().into(),
        account_id: account.clone(),
        network_profile_id: "synthetic-testnet".into(),
        expected_head: history.snapshot().head.clone(),
        writer_epoch: 1,
        control: OwnerControl::RecoverWriter {
            writer_certificate_digest: "c3".repeat(32),
            inventory_digest: inventory.digest().unwrap(),
        },
    };
    pending.save_recovery_owner_request(&request).unwrap();
    // A different owner control advances the head before this operation commits.
    let mut pause = request.clone();
    pause.operation_id = "synthetic-intervening-pause".into();
    pause.control = OwnerControl::Pause;
    synthetic::control(&witness, &"a1".repeat(32), pause, now + 10).unwrap();
    synthetic::activate(&witness, &"b2".repeat(32), now + 11).unwrap();
    let (new_history, _) =
        synthetic::reconciled_session(&witness, &"b2".repeat(32), &account, "synthetic-testnet")
            .unwrap();
    assert!(!new_history.contains_operation(&request.operation_id));
    request.expected_head = new_history.snapshot().head.clone();
    pending
        .reconcile_recovery_owner_request(&request, &new_history)
        .unwrap();
    assert!(pending.read_recovery_owner_request().unwrap().as_ref() == Some(&request));
    synthetic::control(&witness, &"a1".repeat(32), request.clone(), now + 20).unwrap();
    synthetic::activate(&witness, &"c3".repeat(32), now + 21).unwrap();
    let make_fence = || {
        synthetic::recovery_fence(
            &witness,
            &"c3".repeat(32),
            &account,
            "synthetic-testnet",
            inventory.operation_id(),
            &inventory.digest().unwrap(),
        )
        .unwrap()
    };
    let committed = make_fence();
    assert!(
        committed
            .history()
            .owner_control_request(&request.operation_id)
            == Some(&request)
    );
    let mut forbidden = request.clone();
    forbidden.expected_head = committed.history().snapshot().head.clone();
    assert!(
        pending
            .reconcile_recovery_owner_request(&forbidden, committed.history())
            .is_err()
    );
    drop(pending);
    let native = recovery_test_authority();
    let prepared =
        PreparedRecoveryActivation::prepare(source, inventory.clone(), committed, &native).unwrap();
    let decision = recovery_test_decision(&native, prepared.digest());
    let approved = prepared.approve(decision, &native).unwrap();
    let mut activated = original
        .publish_recovery_successor(approved, make_fence(), password)
        .unwrap();
    let journal = activated.open_authority_journal().unwrap();
    assert_eq!(journal.account_state().unwrap().writer_epoch, 2);
    assert!(!activated.account().recovery_required());
    assert_eq!(
        &*activated.read_recipient_records().unwrap(),
        b"[{\"synthetic\":\"historical-recipient\"}]"
    );
    let controller =
        wholepact_wallet::wallet::protected_sync::ProtectedWalletSync::from_encrypted_connection(
            activated.open_viewing_wallet_storage().unwrap(),
            wholepact_chain::ChainAdapter::synthetic_loopback_for_qualification(
                "http://127.0.0.1:19191",
                wholepact_chain::NetworkPolicy::default(),
            )
            .unwrap(),
            std::num::NonZeroU32::MIN,
        )
        .unwrap();
    assert_eq!(
        controller.status().unwrap().phase,
        wholepact_wallet::wallet::protected_sync::SyncPhase::Unobserved
    );
    assert!(
        !controller
            .status()
            .unwrap()
            .local_selection_context_available
    );
    drop(controller);
    assert_eq!(
        original_wallet,
        std::fs::read(temp.path().join("quarantine/viewing-wallet.sqlite")).unwrap()
    );
    drop(journal);
    drop(activated);
    let mut reopened = AccountVault::unlock(inventory.target_profile(), password).unwrap();
    let journal = reopened.open_authority_journal().unwrap();
    assert!(!reopened.account().recovery_required());
    drop(journal);
    drop(reopened);
    std::fs::remove_file(inventory.target_profile().join("activation-commit.wp")).unwrap();
    assert!(AccountVault::unlock(inventory.target_profile(), password).is_err());
    assert!(original.account().recovery_required());
}

#[test]
fn recovery_rejects_same_account_substitute_witness_before_owner_mutation() {
    let f = Fixture::new();
    pin_source(&f, &f.journal);
    let _permit = f.permit();
    let archive = Archived::new(&f, &f.journal);
    let source = archive.open();
    let request = &f.request.reservation;
    let policy = AccountPolicy {
        account_use_genesis: None,
        witness_id: "synthetic-substitute-witness".into(),
        account_id: request.account_id.clone(),
        network_profile_id: request.network_profile_id.clone(),
        owner_certificate_digest: "a1".repeat(32),
        initial_writer_certificate_digest: "b2".repeat(32),
        initial_writer_epoch: 1,
        enrollment_refs: vec![request.enrollment_ref.clone()],
        agreement_ids: vec![request.agreement_id.clone()],
        recipient_scope_digests: vec![request.recipient_scope_digest.clone()],
        aggregate_budget_zatoshis: 1_000_000_000,
        per_operation_limit_zatoshis: 500_000_000,
        maximum_fee_share_zatoshis: 12_000,
        maximum_transaction_fee_zatoshis: 30_000,
        maximum_permit_lifetime_ms: 120_000,
        policy_expires_at_ms: request.permit_expires_at_ms + 120_000,
    };
    let alternate = AuthorityJournal::create_encrypted(
        &f._directory.path().join("substitute-witness.sqlite"),
        &DatabaseKey::from_bytes([0xee; 32]),
        policy,
    )
    .unwrap();
    synthetic::activate(
        &alternate,
        &"b2".repeat(32),
        request.reviewed_at_ms.saturating_sub(2),
    )
    .unwrap();
    let mut altered = request.clone();
    altered.expected_head = synthetic::snapshot(
        &alternate,
        &"b2".repeat(32),
        &request.account_id,
        &request.network_profile_id,
    )
    .unwrap()
    .head;
    synthetic::reserve(
        &alternate,
        &"b2".repeat(32),
        altered,
        request.reviewed_at_ms + 1,
    )
    .unwrap();
    let (history, _) = synthetic::reconciled_session(
        &alternate,
        &"b2".repeat(32),
        &request.account_id,
        &request.network_profile_id,
    )
    .unwrap();
    assert!(matches!(
        verify_recovery_continuity(&source, &history),
        Err(JournalError::Conflict)
    ));
}

#[test]
fn recovery_rejects_modified_retained_bridge_permit_with_same_original_terms() {
    use crate::authority_bridge::protocol::RetainedWitnessPermit;
    let f = Fixture::new();
    pin_source(&f, &f.journal);
    let permit = f.permit();
    let lease = f.lease();
    f.journal.bridge_retain_request(&lease, &f.request).unwrap();
    drop(lease);
    let mut saved =
        RetainedWitnessPermit::from_authenticated(&permit, &f.request.reservation).unwrap();
    saved.descriptor.committed_head.digest = "ff".repeat(32);
    // Test-only inconsistent retained evidence, authenticated in the backup.
    f.journal
        .connection
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO signer_bridge_permits VALUES(?1,?2)",
            rusqlite::params![
                saved.descriptor.request.authorization_id,
                serde_json::to_string(&saved).unwrap()
            ],
        )
        .unwrap();
    let archive = Archived::new(&f, &f.journal);
    let source = archive.open();
    let (history, _) = synthetic::reconciled_session(
        &f.witness,
        &"b2".repeat(32),
        "account-alice",
        &f.request.reservation.network_profile_id,
    )
    .unwrap();
    assert!(matches!(
        verify_recovery_continuity(&source, &history),
        Err(JournalError::Conflict)
    ));
}
