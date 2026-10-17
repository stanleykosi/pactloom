//! Non-authorizing consumed-origin identity surviving only in this same process.
//! A new explicit native entry/KDF is needed to regain private read access;
//! original V3/financial/session/enrollment clocks and charges never change.
use super::*;
use crate::consent_journal::{BornNamedReentryInventoryV1, SignerJournalBinding};

/// Contains no vault, FVK, secret, journal connection, witness client, owner
/// signer, native binding, pairing, consent session, or transaction permit.
/// Not Clone/Serialize/Deserialize; a failed unlock consumes it permanently.
pub(crate) struct DormantConsumedBornNamedSourceV1 {
    files: OriginalSourceIdentity,
    complete_files: ConsumedFileSnapshotV1,
    record: BornManualRosterEnrollmentRecordV2,
    intent_digest: String,
    journal_binding: SignerJournalBinding,
    previous_native_entry: String,
    host: crate::native_peer::PeerProcess,
    lifetime: crate::native_ui::DormantNativeLifetime,
    construction: BornOfflineConstructionOriginV1,
    evidence: RosterReenteredConstructionEvidenceV1,
    inventory: BornNamedReentryInventoryV1,
}
impl ConsumedBornNamedSourceV1 {
    /// Cleanup-only operation AFTER immediate revocation and worker draining.
    /// Read-only preservation of all existing outcomes, never a new disclosure,
    /// native approval or financial operation. Unique owners are dropped before
    /// a key-free token can return; no old foreground secret can survive in it.
    pub(crate) fn into_dormant(self) -> Result<DormantConsumedBornNamedSourceV1> {
        if self.native.check_current().is_ok() {
            return Err(Error::ReviewMismatch);
        }
        self.host.check_alive().map_err(|_| Error::Authentication)?;
        self.lifetime.check_connected()?;
        self.retained.check()?;
        self.files.check_opened(&self.retained)?;
        check_original_retention(&self.retained, &self.evidence)?;
        let complete_files = ConsumedFileSnapshotV1::capture(&self.retained)?;
        let inventory = self.journal.consumed_born_named_inventory_v1(
            &self.retained.record.account_record.genesis,
            self.retained
                .record
                .account_record
                .terms
                .signer
                .writer_epoch,
            &self.evidence,
            &self.construction,
        )?;
        self.files.check_opened(&self.retained)?;
        complete_files.check_opened(&self.retained)?;
        self.host.check_alive().map_err(|_| Error::Authentication)?;
        self.lifetime.check_connected()?;
        let binding = self.journal.binding();
        let previous_native_entry = self.native.entry_digest().to_owned();
        // Atomically reject any outstanding worker or session-owned resource.
        // Checking a refcount alone is insufficient; successful unwrap proves
        // no other strong owner can append an effect after the snapshot.
        let journal = Arc::try_unwrap(self.journal).map_err(|_| Error::Locked)?;
        let retained = self.retained;
        let account = Arc::try_unwrap(retained.account).map_err(|_| Error::Locked)?;
        drop(journal);
        drop(account);
        drop(retained.journal_key);
        let dormant = DormantConsumedBornNamedSourceV1 {
            files: self.files,
            complete_files,
            record: retained.record,
            intent_digest: retained.intent_digest,
            journal_binding: binding,
            previous_native_entry,
            host: self.host,
            lifetime: self.lifetime,
            construction: self.construction,
            evidence: self.evidence,
            inventory,
        };
        dormant.check_current()?;
        Ok(dormant)
    }
}
impl DormantConsumedBornNamedSourceV1 {
    /// Only inert exact origin/liveness checks. This grants no private access.
    pub(crate) fn check_current(&self) -> Result<()> {
        if !is_hash(&self.previous_native_entry) {
            return Err(Error::Authentication);
        }
        self.host.check_alive().map_err(|_| Error::Authentication)?;
        self.lifetime.check_connected()?;
        self.files.check_path()?;
        self.complete_files.check_path(&self.files.root)
    }
    pub(crate) fn path(&self) -> &Path {
        &self.files.root
    }
    pub(crate) fn unlock(
        self,
        path: &Path,
        password: &[u8],
        owner: &PendingAccountNativeAuthority,
    ) -> Result<ConsumedBornNamedSourceV1> {
        self.check_current()?;
        owner.check_current()?;
        if path != self.files.root
            || owner.native().binding().entry_digest() == self.previous_native_entry
        {
            return Err(Error::ReviewMismatch);
        }
        let account = Arc::new(AccountVault::unlock_born_for_manual_roster_enrollment_v2(
            path, password, owner,
        )?);
        self.check_current()?;
        let retained = read_roster_retained(account)?;
        let proof = FreshConsumedBornNamedJournalReopenV1 {
            dormant: &self,
            retained: &retained,
            owner,
        };
        proof.check_current()?;
        let journal = Arc::new(SignerConsentJournal::reopen_consumed_born_named_v1(&proof)?);
        proof.check_current()?;
        let source = ConsumedBornNamedSourceV1 {
            retained,
            journal,
            files: self.files,
            native: owner.native().binding(),
            host: self.host,
            lifetime: self.lifetime,
            construction: self.construction,
            evidence: self.evidence,
        };
        source.check(owner)?;
        Ok(source)
    }
}

/// Constructor is private to this consumed one-use token's genuine unlock.
/// The journal opener cannot be called with an imported DTO or a bare binding.
pub(crate) struct FreshConsumedBornNamedJournalReopenV1<'a> {
    dormant: &'a DormantConsumedBornNamedSourceV1,
    retained: &'a RetainedBornManualRosterEnrollmentV2,
    owner: &'a PendingAccountNativeAuthority,
}
impl FreshConsumedBornNamedJournalReopenV1<'_> {
    pub(crate) fn check_current(&self) -> Result<()> {
        self.dormant.check_current()?;
        self.owner.check_current()?;
        self.retained.check_current_source(self.owner)?;
        if self.owner.native().binding().entry_digest() == self.dormant.previous_native_entry
            || self.retained.record != self.dormant.record
            || self.retained.intent_digest != self.dormant.intent_digest
        {
            return Err(Error::ReviewMismatch);
        }
        self.dormant.files.check_opened(self.retained)?;
        check_original_retention(self.retained, &self.dormant.evidence)?;
        self.dormant.complete_files.check_opened(self.retained)?;
        self.dormant
            .construction
            .validate()
            .map_err(|_| Error::ReviewMismatch)?;
        self.dormant
            .evidence
            .validate()
            .map_err(|_| Error::ReviewMismatch)?;
        if self.dormant.construction.extension != self.retained.record.extension()? {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(crate) fn journal_path(&self) -> PathBuf {
        self.retained.account.directory.root().join(JOURNAL)
    }
    pub(crate) fn journal_key(&self) -> DatabaseKey {
        DatabaseKey::from_bytes(*self.retained.journal_key)
    }
    pub(crate) fn genesis(&self) -> &AccountUseGenesis {
        &self.retained.record.account_record.genesis
    }
    pub(crate) fn writer_epoch(&self) -> u64 {
        self.retained
            .record
            .account_record
            .terms
            .signer
            .writer_epoch
    }
    pub(crate) fn evidence(&self) -> &RosterReenteredConstructionEvidenceV1 {
        &self.dormant.evidence
    }
    pub(crate) fn construction(&self) -> &BornOfflineConstructionOriginV1 {
        &self.dormant.construction
    }
    pub(crate) fn inventory(&self) -> &BornNamedReentryInventoryV1 {
        &self.dormant.inventory
    }
    pub(crate) fn original_binding(&self) -> &SignerJournalBinding {
        &self.dormant.journal_binding
    }
}

/// Every retained immutable V3/receipt file is bound by inode and ciphertext
/// digest, not only the seven original birth files. SQLite sidecars may be
/// created/removed by the maintained database and are checked by its owner;
/// the actual database inode and complete typed rows are bound separately.
struct ConsumedFileSnapshotV1 {
    identities: std::collections::BTreeMap<String, (u64, u64)>,
    ciphertexts: std::collections::BTreeMap<String, String>,
}
impl ConsumedFileSnapshotV1 {
    fn capture(retained: &RetainedBornManualRosterEnrollmentV2) -> Result<Self> {
        retained.check()?;
        let directory = &retained.account.directory;
        // Existing roster_inventory/continuation/retention bounds run above.
        let identities = Self::identities(directory.root(), 1024)?;
        let mut ciphertexts = std::collections::BTreeMap::new();
        for name in identities.keys() {
            if name != "signer.lock" && name != JOURNAL {
                ciphertexts.insert(
                    name.clone(),
                    hex::encode(Sha256::digest(directory.read(name, 512 * 1024)?)),
                );
            }
        }
        let snapshot = Self {
            identities,
            ciphertexts,
        };
        snapshot.check_path(directory.root())?;
        Ok(snapshot)
    }
    fn identities(
        root: &Path,
        maximum: usize,
    ) -> Result<std::collections::BTreeMap<String, (u64, u64)>> {
        let mut files = std::collections::BTreeMap::new();
        let mut entries = 0usize;
        for entry in std::fs::read_dir(root)? {
            entries = entries.checked_add(1).ok_or(Error::InvalidData)?;
            if entries > maximum.saturating_add(3) {
                return Err(Error::ReviewMismatch);
            }
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| Error::InvalidData)?;
            let metadata = std::fs::symlink_metadata(entry.path())?;
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.nlink() != 1
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0
            {
                return Err(Error::ReviewMismatch);
            }
            if matches!(
                name.as_str(),
                "authority.sqlite-wal" | "authority.sqlite-shm" | "authority.sqlite-journal"
            ) {
                continue;
            }
            if files.len() >= maximum {
                return Err(Error::ReviewMismatch);
            }
            files.insert(name, (metadata.dev(), metadata.ino()));
        }
        Ok(files)
    }
    fn check_path(&self, root: &Path) -> Result<()> {
        if Self::identities(root, self.identities.len())? != self.identities {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    fn check_opened(&self, retained: &RetainedBornManualRosterEnrollmentV2) -> Result<()> {
        self.check_path(retained.account.directory.root())?;
        for (name, expected) in &self.ciphertexts {
            if &hex::encode(Sha256::digest(
                retained.account.directory.read(name, 512 * 1024)?,
            )) != expected
            {
                return Err(Error::ReviewMismatch);
            }
        }
        self.check_path(retained.account.directory.root())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};

    fn root() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("consumed-born-file-identity-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }
    fn file(root: &Path, name: &str) {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join(name))
            .unwrap();
        file.write_all(b"synthetic inert ciphertext").unwrap();
    }
    fn snapshot(root: &Path) -> ConsumedFileSnapshotV1 {
        ConsumedFileSnapshotV1 {
            identities: ConsumedFileSnapshotV1::identities(root, 4).unwrap(),
            ciphertexts: Default::default(),
        }
    }
    #[test]
    fn consumed_reentry_file_identity_rejects_replacement_added_and_removed_files() {
        let root = root();
        file(root.path(), "retained-receipt");
        let original = snapshot(root.path());
        original.check_path(root.path()).unwrap();
        file(root.path(), "extra");
        assert!(original.check_path(root.path()).is_err());
        std::fs::remove_file(root.path().join("extra")).unwrap();
        // Hold the old inode by renaming, so the new identical bytes cannot be
        // mistaken for it even on filesystems that aggressively reuse inodes.
        std::fs::rename(
            root.path().join("retained-receipt"),
            root.path().join("old"),
        )
        .unwrap();
        file(root.path(), "retained-receipt");
        std::fs::remove_file(root.path().join("old")).unwrap();
        assert!(original.check_path(root.path()).is_err());
        std::fs::remove_file(root.path().join("retained-receipt")).unwrap();
        assert!(original.check_path(root.path()).is_err());
    }
    #[test]
    fn consumed_reentry_file_identity_rejects_links_and_public_modes() {
        let root = root();
        file(root.path(), "receipt");
        let original = snapshot(root.path());
        std::fs::hard_link(root.path().join("receipt"), root.path().join("link")).unwrap();
        assert!(original.check_path(root.path()).is_err());
        std::fs::remove_file(root.path().join("link")).unwrap();
        symlink(root.path().join("receipt"), root.path().join("link")).unwrap();
        assert!(original.check_path(root.path()).is_err());
        std::fs::remove_file(root.path().join("link")).unwrap();
        std::fs::set_permissions(
            root.path().join("receipt"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(original.check_path(root.path()).is_err());
    }
    #[test]
    fn consumed_reentry_file_identity_allows_only_valid_ephemeral_sqlite_sidecars() {
        let root = root();
        file(root.path(), JOURNAL);
        let original = snapshot(root.path());
        file(root.path(), "authority.sqlite-wal");
        original.check_path(root.path()).unwrap();
        std::fs::remove_file(root.path().join("authority.sqlite-wal")).unwrap();
        symlink(
            root.path().join(JOURNAL),
            root.path().join("authority.sqlite-wal"),
        )
        .unwrap();
        assert!(original.check_path(root.path()).is_err());
    }
}
