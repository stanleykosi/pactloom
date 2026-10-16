//! Retained original restored-account historical owner. Never a writer/session.
use super::*;
use crate::consent_journal::QuarantinedJournalRead;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

#[path = "informational/source_guard.rs"]
mod source_guard;
use source_guard::{RetainedSources, before_deadline, inventory};

const MAX_INFORMATIONAL_LIFETIME: Duration = Duration::from_secs(120);

/// Process-local identity only. A clone cannot read sources, renew a deadline,
/// release locks, authorize an action, or recreate this owner after it drops.
#[derive(Clone)]
pub(crate) struct QuarantinedInformationalBinding(Arc<()>);
impl PartialEq for QuarantinedInformationalBinding {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for QuarantinedInformationalBinding {}
impl std::fmt::Debug for QuarantinedInformationalBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("QuarantinedInformationalBinding([opaque])")
    }
}

/// No vault, seed, viewing/spending key, session, connection or mutable journal.
/// Keeps both cooperative locks and every original source descriptor until drop.
/// All rechecks are read-only and bounded by the opening's original deadline.
/// An unchanged source is historical evidence, never a live freshness assertion.
pub(crate) struct QuarantinedInformationalAccount {
    journal: QuarantinedJournalRead,
    sources: RetainedSources,
    binding: QuarantinedInformationalBinding,
    // Last fields: retain exclusion until all historical material is dropped.
    _directory: PrivateDirectory,
    _archive: PrivateDirectory,
}
impl QuarantinedInformationalAccount {
    /// Compatibility entry with one bounded opening/session budget. Native owners
    /// should supply their existing absolute deadline to open_existing_until.
    pub(crate) fn open_existing(
        root: &Path,
        password: &[u8],
        backup: &Path,
        recovery_password: &[u8],
    ) -> Result<Self> {
        Self::open_existing_until(
            root,
            password,
            backup,
            recovery_password,
            Instant::now() + MAX_INFORMATIONAL_LIFETIME,
        )
    }
    /// Captures every allowed source/archive file BEFORE envelope decoding and
    /// authenticates through maintained source-preserving SQLite readers. Both
    /// complete trees are rechecked after authentication before any owner escapes.
    /// Synchronous filesystem/KDF/SQLite calls cannot be interrupted here: expiry
    /// prevents subsequent work/acceptance, not a hard wall-clock syscall bound.
    pub(crate) fn open_existing_until(
        root: &Path,
        password: &[u8],
        backup: &Path,
        recovery_password: &[u8],
        deadline: Instant,
    ) -> Result<Self> {
        let deadline = deadline.min(Instant::now() + MAX_INFORMATIONAL_LIFETIME);
        before_deadline(deadline)?;
        if !root.is_absolute()
            || std::fs::canonicalize(root)? != root
            || !backup.is_absolute()
            || std::fs::canonicalize(backup)? != backup
            || root == backup
        {
            return Err(Error::InvalidData);
        }
        // Preflight precedes all opens, including the already-existing locks.
        // These are cooperative exclusions, not hostile replacement protection.
        inventory(root, false, deadline)?;
        inventory(backup, true, deadline)?;
        let directory = PrivateDirectory::open_existing(root)?;
        before_deadline(deadline)?;
        let archive = PrivateDirectory::open_existing(backup)?;
        let sources = RetainedSources::capture(root, backup, deadline)?;
        let encoded = directory.read("account.wp", MAX_ACCOUNT + 1024)?;
        before_deadline(deadline)?;
        if !encoded.starts_with(MAGIC) {
            return Err(Error::RecoveryRequired);
        }
        // No born-format decoding, activation or recovery-plan flow is admitted.
        let vault = AccountVault::decode_locked(directory, password, true)?;
        before_deadline(deadline)?;
        if !vault.account.restored
            || vault.generation.is_some()
            || vault.born_origin.is_some()
            || !vault.authority_initialized
        {
            return Err(Error::RecoveryRequired);
        }
        let source =
            backup::verified_recovery_source_locked(&vault, backup, recovery_password, &archive)?;
        before_deadline(deadline)?;
        let journal = QuarantinedJournalRead::from_verified(source, &vault.account_id()?)?;
        sources.check_until(deadline)?;
        // Move only exclusion; all remaining secret fields are immediately
        // dropped through their maintained Zeroizing implementations.
        let directory = vault.directory;
        Ok(Self {
            journal,
            sources,
            binding: QuarantinedInformationalBinding(Arc::new(())),
            _directory: directory,
            _archive: archive,
        })
    }
    pub(crate) fn account_id(&self) -> &str {
        self.journal.account_id()
    }
    pub(crate) fn historical_writer_epoch(&self) -> u64 {
        self.journal.writer_epoch()
    }
    pub(crate) fn checkpoint_id(&self) -> &str {
        self.journal.checkpoint_id()
    }
    pub(crate) fn binding(&self) -> QuarantinedInformationalBinding {
        self.binding.clone()
    }
    /// Immutable opening identity, including exact paths, directory/file identity,
    /// metadata, names, optional absence and bounded full ciphertext hashes. This
    /// digest is a native-review binding, not serializable authority or freshness.
    pub(crate) fn source_inventory_digest(&self) -> &str {
        self.sources.digest()
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.sources.deadline()
    }
    /// No source reopen/reacquire or lock-release path exists. Hold this owner
    /// through the last protected publication check. If it is dropped, a fresh
    /// opening, authentication and native binding are required; an old digest or
    /// approval cannot bridge the release/reacquire gap. No atomic final-write or
    /// hostile same-user filesystem guarantee is implied by this race detector.
    pub(crate) fn check_source_unchanged_until(&self, deadline: Instant) -> Result<()> {
        self.sources.check_until(deadline)
    }
    pub(crate) fn read_history_v5(
        &self,
        history: &wholepact_authority::ReconciledAuthorityHistory,
        deadline: Instant,
    ) -> Result<crate::authority_bridge::host_recovery_ipc::v5::HostRecoveryHistoryV5> {
        self.check_source_unchanged_until(deadline)?;
        let history = self.journal.complete_history_v5(history)?;
        self.check_source_unchanged_until(deadline)?;
        Ok(history)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    const PASSWORD: &[u8] = b"synthetic-informational-vault-only";
    const RECOVERY: &[u8] = b"synthetic-informational-backup-only";
    #[test]
    fn retained_historical_owner_is_send_sync_without_retained_connections() {
        // This is a compile-time structural assertion, never a synthetic native
        // owner/approval issuer. No unsafe Send or Sync implementation is used.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<QuarantinedInformationalAccount>();
        assert_send_sync::<QuarantinedInformationalBinding>();
        assert_send_sync::<Arc<QuarantinedInformationalAccount>>();
    }
    fn tree(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut out = BTreeMap::new();
        for entry in std::fs::read_dir(root).unwrap() {
            let entry = entry.unwrap();
            use std::os::unix::fs::MetadataExt;
            let metadata = std::fs::symlink_metadata(entry.path()).unwrap();
            let mut bytes = format!(
                "{}:{}:{}:",
                metadata.mode(),
                metadata.uid(),
                metadata.nlink()
            )
            .into_bytes();
            if metadata.is_file() {
                bytes.extend(std::fs::read(entry.path()).unwrap());
            }
            out.insert(entry.file_name().into(), bytes);
        }
        out
    }
    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        fixture_with_wallet(false)
    }
    fn fixture_with_wallet(wallet: bool) -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        fixture_with_options(wallet, wallet)
    }
    fn fixture_with_options(
        wallet: bool,
        recipient: bool,
    ) -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let original = temp.path().join("original");
        let archive = temp.path().join("archive");
        let restored = temp.path().join("restored");
        let pending = PendingAccount::generate(ProvisioningConsent {
            privacy_domain: "synthetic-informational-only".into(),
            account_index: 0,
        })
        .unwrap();
        let words = pending.recovery_words().unwrap();
        let mut vault =
            AccountVault::create(&original, pending.verify_backup(&words).unwrap(), PASSWORD)
                .unwrap();
        drop(vault.create_authority_journal().unwrap());
        if wallet {
            let wallet =
                wholepact_wallet::wallet::DedicatedTestnetWallet::from_encrypted_connection(
                    vault.create_viewing_wallet_storage().unwrap(),
                )
                .unwrap();
            drop(wallet);
        }
        if recipient {
            vault.write_recipient_records(b"[]").unwrap();
        }
        drop(vault);
        backup::snapshot(&original, &archive, PASSWORD, RECOVERY).unwrap();
        backup::restore(&archive, &restored, RECOVERY, PASSWORD).unwrap();
        (temp, original, archive, restored)
    }
    #[test]
    fn restored_information_consumes_vault_and_preserves_complete_source_trees() {
        let (_temp, _original, archive, restored) = fixture();
        let before = (tree(&archive), tree(&restored));
        let owner =
            QuarantinedInformationalAccount::open_existing(&restored, PASSWORD, &archive, RECOVERY)
                .unwrap();
        assert!(!owner.account_id().is_empty());
        assert!(owner.historical_writer_epoch() > 0);
        assert!(!owner.checkpoint_id().is_empty());
        assert_eq!(owner.source_inventory_digest().len(), 64);
        assert_eq!(owner.binding(), owner.binding());
        owner
            .check_source_unchanged_until(owner.deadline())
            .unwrap();
        assert!(PrivateDirectory::open_existing(&restored).is_err());
        assert!(PrivateDirectory::open_existing(&archive).is_err());
        assert_eq!(before, (tree(&archive), tree(&restored)));
        drop(owner);
        let ordinary = AccountVault::unlock(&restored, PASSWORD).unwrap();
        assert!(ordinary.account().recovery_required());
        drop(ordinary);
        assert_eq!(before, (tree(&archive), tree(&restored)));
    }
    #[test]
    fn wrong_archive_password_and_missing_existing_archive_lock_preserve_trees() {
        let (_temp, _original, archive, restored) = fixture();
        let before = (tree(&archive), tree(&restored));
        assert!(
            QuarantinedInformationalAccount::open_existing(
                &restored,
                PASSWORD,
                &archive,
                b"synthetic-wrong"
            )
            .is_err()
        );
        assert_eq!(before, (tree(&archive), tree(&restored)));
        std::fs::remove_file(archive.join("signer.lock")).unwrap();
        let before = (tree(&archive), tree(&restored));
        assert!(
            QuarantinedInformationalAccount::open_existing(&restored, PASSWORD, &archive, RECOVERY)
                .is_err()
        );
        assert_eq!(before, (tree(&archive), tree(&restored)));
    }
    #[test]
    fn active_vault_and_missing_original_lineage_cannot_issue_information_owner() {
        let (_temp, original, archive, restored) = fixture();
        let before = (tree(&original), tree(&archive), tree(&restored));
        assert!(
            QuarantinedInformationalAccount::open_existing(&original, PASSWORD, &archive, RECOVERY)
                .is_err()
        );
        assert_eq!(before, (tree(&original), tree(&archive), tree(&restored)));
        std::fs::remove_file(archive.join("COMPLETE")).unwrap();
        let before = (tree(&archive), tree(&restored));
        assert!(
            QuarantinedInformationalAccount::open_existing(&restored, PASSWORD, &archive, RECOVERY)
                .is_err()
        );
        assert_eq!(before, (tree(&archive), tree(&restored)));
    }
    #[test]
    fn incomplete_recovery_sidecar_refuses_without_repair() {
        let (_temp, _original, archive, restored) = fixture();
        std::fs::write(restored.join("recovery-plan.wp"), b"synthetic-incomplete").unwrap();
        let before = (tree(&archive), tree(&restored));
        assert!(
            QuarantinedInformationalAccount::open_existing(&restored, PASSWORD, &archive, RECOVERY)
                .is_err()
        );
        assert_eq!(before, (tree(&archive), tree(&restored)));
    }
    #[test]
    fn absent_source_lock_refuses_without_creating_any_file() {
        let (_temp, _original, archive, restored) = fixture();
        std::fs::remove_file(restored.join("signer.lock")).unwrap();
        let before = (tree(&archive), tree(&restored));
        assert!(QuarantinedInformationalAccount::open_existing(
            &restored, PASSWORD, &archive, RECOVERY,
        ).is_err());
        assert_eq!(before, (tree(&archive), tree(&restored)));
    }
    #[test]
    fn malformed_envelope_and_wrong_password_preserve_source_trees() {
        let (_temp, _original, archive, restored) = fixture();
        let before = (tree(&archive), tree(&restored));
        assert!(
            QuarantinedInformationalAccount::open_existing(
                &restored,
                b"synthetic-wrong",
                &archive,
                RECOVERY,
            )
            .is_err()
        );
        assert_eq!(before, (tree(&archive), tree(&restored)));
        std::fs::write(restored.join("account.wp"), b"WPACC002malformed").unwrap();
        let before = (tree(&archive), tree(&restored));
        assert!(QuarantinedInformationalAccount::open_existing(
            &restored, PASSWORD, &archive, RECOVERY,
        ).is_err());
        assert_eq!(before, (tree(&archive), tree(&restored)));
    }
    #[test]
    fn wallet_bearing_restore_is_refused_without_retaining_viewing_material() {
        let (_temp, _original, archive, restored) = fixture_with_wallet(true);
        let before = (tree(&archive), tree(&restored));
        assert!(QuarantinedInformationalAccount::open_existing(
            &restored, PASSWORD, &archive, RECOVERY,
        ).is_err());
        assert_eq!(before, (tree(&archive), tree(&restored)));
    }
    #[test]
    fn foreign_archive_and_missing_journal_refuse_without_source_repair() {
        let (_temp, _original, archive, restored) = fixture();
        let (_other, _other_original, foreign_archive, _other_restored) = fixture();
        let before = (tree(&archive), tree(&restored), tree(&foreign_archive));
        assert!(
            QuarantinedInformationalAccount::open_existing(
                &restored,
                PASSWORD,
                &foreign_archive,
                RECOVERY,
            )
            .is_err()
        );
        assert_eq!(
            before,
            (tree(&archive), tree(&restored), tree(&foreign_archive))
        );
        std::fs::remove_file(restored.join("authority.sqlite")).unwrap();
        let before = (tree(&archive), tree(&restored));
        assert!(QuarantinedInformationalAccount::open_existing(
            &restored, PASSWORD, &archive, RECOVERY,
        ).is_err());
        assert_eq!(before, (tree(&archive), tree(&restored)));
    }
    #[test]
    fn special_account_file_and_hardlinked_lock_refuse_before_any_read() {
        let (_temp, _original, archive, restored) = fixture();
        let encoded = std::fs::read(restored.join("account.wp")).unwrap();
        std::fs::remove_file(restored.join("account.wp")).unwrap();
        std::fs::create_dir(restored.join("account.wp")).unwrap();
        let before = (tree(&archive), tree(&restored));
        assert!(
            QuarantinedInformationalAccount::open_existing(&restored, PASSWORD, &archive, RECOVERY)
                .is_err()
        );
        assert_eq!(before, (tree(&archive), tree(&restored)));
        std::fs::remove_dir(restored.join("account.wp")).unwrap();
        std::fs::write(restored.join("account.wp"), encoded).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            restored.join("account.wp"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        std::fs::hard_link(
            restored.join("signer.lock"),
            _temp.path().join("synthetic-lock-alias"),
        )
        .unwrap();
        let before = (tree(&archive), tree(&restored));
        assert!(
            QuarantinedInformationalAccount::open_existing(&restored, PASSWORD, &archive, RECOVERY)
                .is_err()
        );
        assert_eq!(before, (tree(&archive), tree(&restored)));
    }
    #[test]
    fn orphan_wallet_sidecars_refuse_without_authentication_or_cleanup() {
        use std::os::unix::fs::PermissionsExt;
        let (_temp, _original, archive, restored) = fixture();
        for name in ["viewing-wallet.sqlite-wal", "viewing-wallet.sqlite-shm"] {
            let path = restored.join(name);
            std::fs::write(&path, b"synthetic-orphan").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let before = (tree(&archive), tree(&restored));
            assert!(
                QuarantinedInformationalAccount::open_existing(
                    &restored, PASSWORD, &archive, RECOVERY
                )
                .is_err()
            );
            assert_eq!(before, (tree(&archive), tree(&restored)));
            std::fs::remove_file(path).unwrap();
        }
    }
    #[test]
    fn recipient_presence_and_complete_vault_identity_must_match_original() {
        let (_temp, _original, archive, restored) = fixture_with_options(false, true);
        std::fs::remove_file(restored.join("recipient-record-key.wp")).unwrap();
        std::fs::remove_file(restored.join("recipient-records.wp")).unwrap();
        let before = (tree(&archive), tree(&restored));
        assert!(
            QuarantinedInformationalAccount::open_existing(&restored, PASSWORD, &archive, RECOVERY)
                .is_err()
        );
        assert_eq!(before, (tree(&archive), tree(&restored)));
        let (_other, _original, archive, restored) = fixture();
        let mut vault = AccountVault::unlock(&restored, PASSWORD).unwrap();
        vault.account.privacy_domain = "synthetic-substituted-domain".into();
        vault.persist().unwrap();
        drop(vault);
        let before = (tree(&archive), tree(&restored));
        assert!(
            QuarantinedInformationalAccount::open_existing(&restored, PASSWORD, &archive, RECOVERY)
                .is_err()
        );
        assert_eq!(before, (tree(&archive), tree(&restored)));
    }
    #[test]
    fn signer_only_restore_with_exact_recipient_records_preserves_source_trees() {
        let (_temp, _original, archive, restored) = fixture_with_options(false, true);
        let before = (tree(&archive), tree(&restored));
        let owner =
            QuarantinedInformationalAccount::open_existing(&restored, PASSWORD, &archive, RECOVERY)
                .unwrap();
        assert!(!owner.account_id().is_empty());
        owner
            .check_source_unchanged_until(owner.deadline())
            .unwrap();
        drop(owner);
        assert_eq!(before, (tree(&archive), tree(&restored)));
    }
    #[test]
    fn expiry_refuses_without_opening_and_reopen_changes_opaque_source_identity() {
        let (_temp, _original, archive, restored) = fixture();
        let before = (tree(&archive), tree(&restored));
        assert!(matches!(
            QuarantinedInformationalAccount::open_existing_until(
                &restored,
                PASSWORD,
                &archive,
                RECOVERY,
                Instant::now() - Duration::from_secs(1)
            ),
            Err(Error::ReviewMismatch)
        ));
        assert_eq!(before, (tree(&archive), tree(&restored)));
        let deadline = Instant::now() + Duration::from_secs(90);
        let owner = QuarantinedInformationalAccount::open_existing_until(
            &restored, PASSWORD, &archive, RECOVERY, deadline,
        )
        .unwrap();
        assert_eq!(owner.deadline(), deadline);
        let binding = owner.binding();
        let digest = owner.source_inventory_digest().to_owned();
        assert!(matches!(
            owner.check_source_unchanged_until(Instant::now() - Duration::from_secs(1)),
            Err(Error::ReviewMismatch)
        ));
        drop(owner);
        let reopened =
            QuarantinedInformationalAccount::open_existing(&restored, PASSWORD, &archive, RECOVERY)
                .unwrap();
        assert_ne!(binding, reopened.binding());
        assert_eq!(digest, reopened.source_inventory_digest());
        assert!(PrivateDirectory::open_existing(&restored).is_err());
        assert!(PrivateDirectory::open_existing(&archive).is_err());
        assert_eq!(before, (tree(&archive), tree(&restored)));
    }
    /// Existing-layout integration boundary, using the ACTUAL derived account ID
    /// throughout. No NativeDecision, writer/session activation, socket or TLS
    /// credential is created. Fixed certificate digests are inert identifiers.
    #[cfg(feature = "synthetic-qualification")]
    #[test]
    fn full_original_layout_with_empty_witness_refuses_missing_historical_pin() {
        use std::os::unix::fs::PermissionsExt;
        use wholepact_authority::{AccountPolicy, AuthorityJournal, WitnessDisclosureDescriptor};
        use wholepact_storage_security::DatabaseKey;

        let (temporary, _original, archive, restored) = fixture();
        let before = (tree(&archive), tree(&restored));
        let owner =
            QuarantinedInformationalAccount::open_existing(&restored, PASSWORD, &archive, RECOVERY)
                .unwrap();
        let source_digest = owner.source_inventory_digest().to_owned();
        assert!(PrivateDirectory::open_existing(&restored).is_err());
        assert!(PrivateDirectory::open_existing(&archive).is_err());

        let witness_root = temporary.path().join("synthetic-empty-witness");
        std::fs::create_dir(&witness_root).unwrap();
        std::fs::set_permissions(&witness_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let writer = "82".repeat(32);
        let policy = AccountPolicy {
            // Absence stays unknown. This is not an empty-genesis assertion.
            account_use_genesis: None,
            witness_id: "synthetic-original-layout-witness".into(),
            account_id: owner.account_id().into(),
            network_profile_id: wholepact_protocol::construction::PROFILE_ID.into(),
            owner_certificate_digest: "81".repeat(32),
            initial_writer_certificate_digest: writer.clone(),
            initial_writer_epoch: owner.historical_writer_epoch(),
            enrollment_refs: vec!["83".repeat(32)],
            agreement_ids: vec!["synthetic-unfunded-agreement".into()],
            recipient_scope_digests: vec!["84".repeat(32)],
            aggregate_budget_zatoshis: 100,
            per_operation_limit_zatoshis: 50,
            maximum_fee_share_zatoshis: 1,
            maximum_transaction_fee_zatoshis: 2,
            maximum_permit_lifetime_ms: 30_000,
            policy_expires_at_ms: 1_000_000,
        };
        let descriptor = WitnessDisclosureDescriptor {
            endpoint: "127.0.0.1:1".into(),
            server_name: "synthetic-original-layout.invalid".into(),
            witness_id: policy.witness_id.clone(),
            account_id: policy.account_id.clone(),
            network_profile_id: policy.network_profile_id.clone(),
            policy_digest: policy.policy_digest().unwrap(),
            pinned_server_certificate_digest: "85".repeat(32),
        };
        let witness = AuthorityJournal::create_encrypted(
            &witness_root.join("never-funded-empty.sqlite"),
            &DatabaseKey::from_bytes([0x86; 32]),
            policy,
        )
        .unwrap();
        // Inspected helper reads real journal snapshot/history and folds every
        // historical page with the maintained ledger. It issues no live owner.
        let history = wholepact_authority::transport::synthetic::reconciled_history(
            &witness,
            &writer,
            &descriptor,
        )
        .unwrap();
        assert_eq!(history.snapshot().account_id, owner.account_id());
        assert_eq!(
            history.snapshot().writer_epoch,
            owner.historical_writer_epoch()
        );
        assert_eq!(history.snapshot().head.sequence, 0);
        assert!(history.snapshot().active_writer_session.is_none());
        assert!(history.snapshot().pending_writer_session.is_none());
        assert!(history.pending_birth_commit().is_none());
        assert!(history.account_use_history().genesis().is_none());
        assert!(history.reservation_evidence().next().is_none());
        let construction = history.construction_history_with_transport_v1().unwrap();
        assert!(construction.original.original_birth().is_none());
        assert!(construction.original.origins().is_empty());
        assert!(construction.original.approvals().is_empty());
        assert!(construction.transport.is_empty());

        // Complete V5 requires an ORIGINAL retained witness pin. A fresh empty
        // signer journal and a matching empty witness do not manufacture one.
        // No historical reconciliation/native receipt is inserted to bypass it.
        assert!(matches!(
            owner.read_history_v5(&history, owner.deadline()),
            Err(Error::ConsentJournal(
                crate::consent_journal::JournalError::RecoveryRequired
            ))
        ));
        owner
            .check_source_unchanged_until(owner.deadline())
            .unwrap();
        assert_eq!(source_digest, owner.source_inventory_digest());
        assert_eq!(before, (tree(&archive), tree(&restored)));
        drop(owner);
        assert!(PrivateDirectory::open_existing(&restored).is_ok());
        assert!(PrivateDirectory::open_existing(&archive).is_ok());
        assert_eq!(before, (tree(&archive), tree(&restored)));
    }
    /// Modeled, already-recorded legacy events only. The public session ID is an
    /// inert identifier; no session key, proof, native decision or active owner
    /// is issued. The helper independently replays both production transitions.
    #[cfg(feature = "synthetic-qualification")]
    fn recorded_legacy_history(
        account_id: &str,
    ) -> wholepact_authority::ReconciledAuthorityHistory {
        recorded_legacy_history_with_pin(account_id, &"85".repeat(32))
    }
    #[cfg(feature = "synthetic-qualification")]
    fn recorded_legacy_history_with_pin(
        account_id: &str,
        server_certificate_digest: &str,
    ) -> wholepact_authority::ReconciledAuthorityHistory {
        use wholepact_authority::{
            AccountPolicy, AcquireWriterRequest, AuthorityMutation, OwnerControl,
            OwnerControlRequest, WitnessDisclosureDescriptor,
            transport::synthetic::recorded_legacy_reconciliation_history as replay,
        };
        let policy = AccountPolicy {
            account_use_genesis: None,
            witness_id: "synthetic-recorded-legacy-witness".into(),
            account_id: account_id.into(),
            network_profile_id: wholepact_protocol::construction::PROFILE_ID.into(),
            owner_certificate_digest: "81".repeat(32),
            initial_writer_certificate_digest: "82".repeat(32),
            initial_writer_epoch: 1,
            enrollment_refs: vec!["83".repeat(32)],
            agreement_ids: vec!["synthetic-unfunded-agreement".into()],
            recipient_scope_digests: vec!["84".repeat(32)],
            aggregate_budget_zatoshis: 100,
            per_operation_limit_zatoshis: 50,
            maximum_fee_share_zatoshis: 1,
            maximum_transaction_fee_zatoshis: 2,
            maximum_permit_lifetime_ms: 30_000,
            policy_expires_at_ms: 1_000_000,
        };
        let descriptor = WitnessDisclosureDescriptor {
            endpoint: "127.0.0.1:1".into(),
            server_name: "synthetic-recorded-legacy.invalid".into(),
            witness_id: policy.witness_id.clone(),
            account_id: policy.account_id.clone(),
            network_profile_id: policy.network_profile_id.clone(),
            policy_digest: policy.policy_digest().unwrap(),
            pinned_server_certificate_digest: server_certificate_digest.into(),
        };
        let empty = replay(&policy, &descriptor, b"[]").unwrap();
        let acquire = AuthorityMutation::AcquireWriter(AcquireWriterRequest {
            operation_id: "recorded-legacy-acquire".into(),
            account_id: account_id.into(),
            network_profile_id: policy.network_profile_id.clone(),
            writer_epoch: 1,
            expected_head: empty.snapshot().head.clone(),
            reconciled_history_digest: empty.history_digest().unwrap(),
            session_id: "86".repeat(32),
            disclosure: descriptor.clone(),
        });
        let acquire_event = serde_json::json!({
            "mutation": acquire,
            "authenticated_certificate_digest": policy.initial_writer_certificate_digest,
            "witness_time_ms": 100,
            "writer_session_id": null
        });
        let pending = replay(
            &policy,
            &descriptor,
            &serde_json::to_vec(&vec![acquire_event.clone()]).unwrap(),
        )
        .unwrap();
        let pending_receipt = pending.snapshot().pending_writer_session.as_ref().unwrap();
        assert_eq!(pending_receipt.acquired_head.sequence, 1);
        assert!(pending.snapshot().active_writer_session.is_none());
        let activate = AuthorityMutation::OwnerControl(OwnerControlRequest {
            operation_id: "recorded-legacy-owner-activation".into(),
            account_id: account_id.into(),
            network_profile_id: policy.network_profile_id.clone(),
            expected_head: pending.snapshot().head.clone(),
            writer_epoch: 1,
            control: OwnerControl::ActivateWriter {
                session_id: pending_receipt.session_id.clone(),
            },
        });
        let activation_event = serde_json::json!({
            "mutation": activate,
            "authenticated_certificate_digest": policy.owner_certificate_digest,
            "witness_time_ms": 101,
            "writer_session_id": null
        });
        let events = vec![acquire_event, activation_event];
        // Recorded peer provenance and exact chain/identity remain checked by
        // Ledger::apply, rather than setting snapshot fields or a verified flag.
        let mut wrong_peer = events.clone();
        wrong_peer[1]["authenticated_certificate_digest"] =
            serde_json::json!(policy.initial_writer_certificate_digest);
        assert!(
            replay(
                &policy,
                &descriptor,
                &serde_json::to_vec(&wrong_peer).unwrap()
            )
            .is_err()
        );
        let mut wrong_disclosure = descriptor.clone();
        wrong_disclosure.account_id = "foreign-account".into();
        assert!(
            replay(
                &policy,
                &wrong_disclosure,
                &serde_json::to_vec(&events).unwrap()
            )
            .is_err()
        );
        let history = replay(&policy, &descriptor, &serde_json::to_vec(&events).unwrap()).unwrap();
        assert_eq!(history.snapshot().head.sequence, 2);
        assert!(history.pending_birth_commit().is_none());
        assert!(history.account_use_history().genesis().is_none());
        assert!(history.reservation_evidence().next().is_none());
        let receipt = history.snapshot().active_writer_session.as_ref().unwrap();
        assert!(receipt == pending_receipt);
        assert!(history.contains_head(&receipt.reconciled_head));
        assert!(history.contains_head(&receipt.acquired_head));
        history
    }

    /// Reproduce the inert persisted row shape of legacy reconcile_writer using
    /// its exact v1 review-digest tuple and a ledger-produced historical receipt.
    /// The row is written only into this never-funded test source BEFORE archive
    /// creation. No journal/native capability constructor consumes the receipt.
    #[cfg(feature = "synthetic-qualification")]
    fn fixture_with_recorded_legacy_pin(
        wrong_pin_head: bool,
    ) -> (
        tempfile::TempDir,
        PathBuf,
        PathBuf,
        PathBuf,
        wholepact_authority::ReconciledAuthorityHistory,
    ) {
        use crate::consent_journal::NativeConsentReceipt;
        use wholepact_storage_security::DatabaseKey;
        let temporary = tempfile::tempdir().unwrap();
        let original = temporary.path().join("original");
        let archive = temporary.path().join("archive");
        let restored = temporary.path().join("restored");
        let pending = PendingAccount::generate(ProvisioningConsent {
            privacy_domain: "synthetic-recorded-legacy-only".into(),
            account_index: 0,
        })
        .unwrap();
        let words = pending.recovery_words().unwrap();
        let mut vault =
            AccountVault::create(&original, pending.verify_backup(&words).unwrap(), PASSWORD)
                .unwrap();
        drop(vault.create_authority_journal().unwrap());
        let account_id = vault.account_id().unwrap();
        let history = recorded_legacy_history(&account_id);
        let receipt = history.snapshot().active_writer_session.as_ref().unwrap();
        let native = NativeConsentReceipt {
            native_session_id: "a1".repeat(32),
            trusted_launch_measurement: "a2".repeat(32),
            permission_generation: 1,
            writer_epoch: 1,
            nonce: "a3".repeat(32),
            reviewed_at_ms: 110,
            expires_at_ms: 210,
        };
        assert!(receipt.acquired_at_ms < native.reviewed_at_ms);
        assert!(native.expires_at_ms < receipt.expires_at_ms);
        let history_digest = history.history_digest().unwrap();
        let permits: Vec<wholepact_authority::ReservationPermit> = vec![];
        let review_digest = wholepact_core::proposal::canonical_digest(
            "wholepact:signer-writer-reconciliation:v1",
            &(
                &account_id,
                1u64,
                &native,
                history.disclosure(),
                history.snapshot(),
                receipt,
                &history_digest,
                permits.as_slice(),
            ),
        )
        .unwrap();
        {
            let connection = wholepact_storage_security::open_encrypted(
                original.join("authority.sqlite"),
                &DatabaseKey::from_bytes(*vault.authority_key),
            )
            .unwrap();
            let head_digest = if wrong_pin_head {
                "ff".repeat(32)
            } else {
                history.snapshot().head.digest.clone()
            };
            connection
                .connection()
                .execute(
                    "INSERT INTO signer_writer_reconciliations VALUES(?1,?2,?3,?4,?5,?6)",
                    rusqlite::params![
                        review_digest,
                        serde_json::to_string(history.disclosure()).unwrap(),
                        history.snapshot().head.sequence,
                        head_digest,
                        1u64,
                        serde_json::to_string(&(receipt, native, history_digest)).unwrap(),
                    ],
                )
                .unwrap();
        }
        drop(vault);
        backup::snapshot(&original, &archive, PASSWORD, RECOVERY).unwrap();
        backup::restore(&archive, &restored, RECOVERY, PASSWORD).unwrap();
        (temporary, original, archive, restored, history)
    }

    #[cfg(feature = "synthetic-qualification")]
    #[test]
    fn full_original_layout_with_recorded_legacy_pin_projects_complete_v5() {
        let (_temporary, original, archive, restored, history) =
            fixture_with_recorded_legacy_pin(false);
        let before = (tree(&original), tree(&archive), tree(&restored));
        let owner =
            QuarantinedInformationalAccount::open_existing(&restored, PASSWORD, &archive, RECOVERY)
                .unwrap();
        assert_eq!(owner.account_id(), history.snapshot().account_id);
        assert_eq!(
            owner.historical_writer_epoch(),
            history.snapshot().writer_epoch
        );
        assert!(PrivateDirectory::open_existing(&restored).is_err());
        assert!(PrivateDirectory::open_existing(&archive).is_err());
        let digest = owner.source_inventory_digest().to_owned();
        let complete = owner.read_history_v5(&history, owner.deadline()).unwrap();
        complete
            .validate(
                owner.account_id(),
                &history.disclosure().network_profile_id,
                history.disclosure(),
                &history.snapshot().head,
                owner.historical_writer_epoch(),
            )
            .unwrap();
        assert_eq!(complete.schema_version, 5);
        assert!(complete.require_financial_activation_supported().is_err());
        assert!(complete.financial_origins_v2.pending_birth_commit.is_none());
        assert!(complete.financial_origins_v2.account_use.genesis.is_none());
        assert!(
            complete
                .financial_origins_v2
                .account_use
                .exclusion
                .is_none()
        );
        assert!(
            complete
                .financial_origins_v2
                .account_use
                .witness_ack
                .is_none()
        );
        assert!(complete.financial_origins_v2.origins.is_empty());
        assert_eq!(complete.conservative_debit_zatoshis().unwrap(), 0);
        assert!(complete.construction == history.construction_history_with_transport_v1().unwrap());
        let again = owner.read_history_v5(&history, owner.deadline()).unwrap();
        assert_eq!(
            complete.financial_origins_v2.complete_journal_digest,
            again.financial_origins_v2.complete_journal_digest
        );
        // A separately replay-valid history with another server pin cannot
        // replace the original stored witness association for this same account.
        let other_pin = recorded_legacy_history_with_pin(owner.account_id(), &"87".repeat(32));
        assert!(matches!(
            owner.read_history_v5(&other_pin, owner.deadline()),
            Err(Error::ConsentJournal(
                crate::consent_journal::JournalError::Conflict
            ))
        ));
        let foreign = recorded_legacy_history("synthetic-foreign-account");
        assert!(matches!(
            owner.read_history_v5(&foreign, owner.deadline()),
            Err(Error::ConsentJournal(
                crate::consent_journal::JournalError::InvalidBinding
            ))
        ));
        owner
            .check_source_unchanged_until(owner.deadline())
            .unwrap();
        assert_eq!(digest, owner.source_inventory_digest());
        assert_eq!(before, (tree(&original), tree(&archive), tree(&restored)));
        drop(owner);
        let ordinary = AccountVault::unlock(&restored, PASSWORD).unwrap();
        assert!(ordinary.account().recovery_required());
        drop(ordinary);
        assert!(PrivateDirectory::open_existing(&archive).is_ok());
        assert_eq!(before, (tree(&original), tree(&archive), tree(&restored)));
    }

    #[cfg(feature = "synthetic-qualification")]
    #[test]
    fn full_original_layout_rejects_recorded_pin_outside_replayed_chain() {
        let (_temporary, original, archive, restored, history) =
            fixture_with_recorded_legacy_pin(true);
        let before = (tree(&original), tree(&archive), tree(&restored));
        let owner =
            QuarantinedInformationalAccount::open_existing(&restored, PASSWORD, &archive, RECOVERY)
                .unwrap();
        assert!(matches!(
            owner.read_history_v5(&history, owner.deadline()),
            Err(Error::ConsentJournal(
                crate::consent_journal::JournalError::Conflict
            ))
        ));
        owner
            .check_source_unchanged_until(owner.deadline())
            .unwrap();
        assert_eq!(before, (tree(&original), tree(&archive), tree(&restored)));
        drop(owner);
        assert_eq!(before, (tree(&original), tree(&archive), tree(&restored)));
    }
}
