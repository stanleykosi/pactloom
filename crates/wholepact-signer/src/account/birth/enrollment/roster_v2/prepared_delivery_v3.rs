//! Actual original file/journal custody after setup drains. Neither this source
//! nor its immutable commitments grants read, receive, disclosure or key use.
use super::*;
use crate::consent_journal::PreparedDeliveryJournalRevisionV3;
use crate::native_ui::PreparedReceiveAndViewAuthorityV3;
use std::{collections::BTreeMap, os::unix::fs::MetadataExt, sync::Mutex};
#[cfg(feature = "coordinated-signer-continue")]
#[path = "coordinated_financial_selection_v1.rs"]
mod coordinated_financial_selection_v1;
#[cfg(feature = "coordinated-signer-continue")]
pub(crate) use coordinated_financial_selection_v1::OriginalFinancialReentrySelectionV1;

#[derive(PartialEq, Eq)]
struct FileRevisionV3 {
    device: u64, inode: u64, length: u64, uid: u32, gid: u32, mode: u32,
    modified: (i64, i64), changed: (i64, i64),
}
fn immutable_files(retained: &RetainedBornManualRosterEnrollmentV2) -> Result<BTreeMap<String, FileRevisionV3>> {
    let directory = &retained.account.directory;
    // Retains/checks the actual directory+lock descriptors, not pathname belief.
    let _actual = directory.signer_journal_source_owner()?;
    super::super::roster_inventory(directory)?;
    let mut files = BTreeMap::new();
    for entry in std::fs::read_dir(directory.root())? {
        let entry = entry?;
        let name = entry.file_name().into_string().map_err(|_| Error::InvalidData)?;
        if matches!(name.as_str(), "signer.lock" | "authority.sqlite" | "authority.sqlite-wal" | "authority.sqlite-shm" | "authority.sqlite-journal") { continue; }
        let m = std::fs::symlink_metadata(entry.path())?;
        if !m.is_file() || m.file_type().is_symlink() || m.nlink() != 1 || m.mode() & 0o077 != 0 {
            return Err(Error::InvalidData);
        }
        files.insert(name, FileRevisionV3 { device:m.dev(), inode:m.ino(), length:m.len(), uid:m.uid(), gid:m.gid(), mode:m.mode(), modified:(m.mtime(),m.mtime_nsec()), changed:(m.ctime(),m.ctime_nsec()) });
    }
    Ok(files)
}

pub(crate) struct PreparedOriginalDeliverySourceV3 {
    retained: RetainedBornManualRosterEnrollmentV2,
    journal: Arc<SignerConsentJournal>,
    revision: Mutex<Option<PreparedDeliveryJournalRevisionV3>>,
    immutable: BTreeMap<String, FileRevisionV3>,
    original_policy: crate::account::birth::recipient_policy_v2::OriginalRecipientPolicyExportV2,
    witness: wholepact_authority::WitnessDisclosureDescriptor,
    lifetime: crate::native_ui::DormantNativeLifetime,
    identity: String,
}
impl FreshDurableDeliveryEntryV2 {
    /// Must be called only after all old workers and borrowed sessions drain.
    /// Consumption destroys the old short owner; it is never an ancestor of
    /// new read permission. The caller's record references select actual rows,
    /// and cannot supply source or approval authority.
    pub(crate) fn into_prepared_v3(self, enrollment_ref: &str, manifest_ref: &str, revision: PreparedDeliveryJournalRevisionV3) -> Result<PreparedOriginalDeliverySourceV3> {
        self.check_original_source_current()?;
        self.journal.check_delivery_journal_revision_v3(&revision)?;
        let before = immutable_files(&self.retained)?;
        let original_policy = self.original_recipient_policy_export_v2()?;
        let witness = self.original_witness_disclosure_data_v1()?;
        let lifetime = self.owner.dormant_lifetime()?;
        let _ = (enrollment_ref, manifest_ref);
        self.journal.check_delivery_journal_revision_v3(&revision)?;
        self.check_original_source_current()?;
        if immutable_files(&self.retained)? != before { return Err(Error::ReviewMismatch); }
        self.journal.check_delivery_journal_revision_v3(&revision)?;
        let identity = wholepact_core::proposal::canonical_digest(
            "wholepact:prepared-original-delivery-source:v3",
            &(self.record(), &self.original_commit, self.genesis(), hex::encode(crate::vault::random::<32>()?)),
        ).map_err(|_| Error::InvalidData)?;
        let Self { retained, journal, owner, original_commit: _ } = self;
        // Other native owners are not inherited. Their already-revoked tokens
        // cannot use this source, and this custody value has no private getter.
        owner.revoke_prepared_delivery_transition();
        drop(owner);
        Ok(PreparedOriginalDeliverySourceV3 { retained, journal, revision: Mutex::new(Some(revision)), immutable: before, original_policy, witness, lifetime, identity })
    }
}
impl PreparedOriginalDeliverySourceV3 {
    pub(crate) fn open_history(
        root: &Path, password: &[u8], owner: Arc<PendingAccountNativeAuthority>,
        intent: &crate::authority_bridge::durable_review_ipc_v3::RecipientIntentV3,
    ) -> Result<Self> {
        owner.check_current()?;
        intent.validate().map_err(|_| Error::InvalidData)?;
        let account = Arc::new(AccountVault::unlock_born_for_manual_roster_enrollment_v2(root, password, &owner)?);
        let retained = account.retained_born_manual_roster_enrollment_v2(&owner)?.ok_or(Error::RecoveryRequired)?;
        retained.check_current_source(&owner)?;
        let original_commit = publication::read_commit(&retained)?;
        let genesis = &retained.record.account_record.genesis;
        if genesis.identity.account_id != intent.account_id { return Err(Error::ReviewMismatch); }
        let key = DatabaseKey::from_bytes(*retained.journal_key);
        let journal = Arc::new(SignerConsentJournal::open_durable_delivery_entry_v3(
            &account.directory.root().join(JOURNAL), &key, genesis,
            &account.directory.signer_journal_source_owner()?,
        )?);
        let revision = journal.prepare_delivery_journal_revision_v3(genesis, &intent.original_enrollment_ref, &intent.original_manifest_ref)?;
        // Private transient reuse of immutable original-file checks only. This
        // value never calls a V2 journal checker or escapes this consuming path.
        let original = FreshDurableDeliveryEntryV2 { retained, original_commit, journal, owner };
        original.into_prepared_v3(&intent.original_enrollment_ref, &intent.original_manifest_ref, revision)
    }
    pub(crate) fn history_setup_metadata(&self) -> Result<(crate::consent_journal::AccountEnrollmentRecord, crate::consent_journal::AcceptedManifestRecord, wholepact_authority::WitnessDisclosureDescriptor, String)> {
        self.check_custody()?;
        let revision = self.revision.lock().map_err(|_| Error::Locked)?;
        let (enrollment, manifest) = self.journal.prepared_delivery_original_records_v3(revision.as_ref().ok_or(Error::Uncertain)?)?;
        Ok((enrollment, manifest, self.witness.clone(), self.retained.record.account_record.terms.signer.owner_certificate_digest.clone()))
    }
    pub(crate) fn identity(&self) -> &str { &self.identity }
    pub(crate) fn root(&self) -> &Path { self.retained.account.directory.root() }
    pub(crate) fn check_custody(&self) -> Result<()> {
        self.lifetime.check_connected()?;
        if immutable_files(&self.retained)? != self.immutable { return Err(Error::ReviewMismatch); }
        let pin = self.revision.lock().map_err(|_| Error::Locked)?;
        self.journal.check_delivery_journal_revision_v3(pin.as_ref().ok_or(Error::Uncertain)?)?;
        self.lifetime.check_connected()
    }
    pub(crate) fn activate(self, read: Arc<PreparedReceiveAndViewAuthorityV3>) -> Result<ActivePreparedDeliverySourceV3> {
        self.check_custody()?;
        read.check_source(&self.identity)?;
        Ok(ActivePreparedDeliverySourceV3 { source: self, read })
    }
}

/// Every private view is obtained through this real read owner. There is no
/// conversion back to FreshDurableDeliveryEntryV2, a wallet or a spending owner.
pub(crate) struct ActivePreparedDeliverySourceV3 {
    source: PreparedOriginalDeliverySourceV3,
    read: Arc<PreparedReceiveAndViewAuthorityV3>,
}
impl ActivePreparedDeliverySourceV3 {
    pub(crate) fn check_retained_custody(&self) -> Result<()> { self.source.check_custody() }
    pub(crate) fn check_current(&self) -> Result<()> { self.read.check_source(&self.source.identity)?; self.source.check_custody()?; self.read.check_source(&self.source.identity) }
    pub(crate) fn check_data_current(&self) -> Result<()> {
        self.read.check_source(&self.source.identity)?;
        self.source.lifetime.check_connected()?;
        if immutable_files(&self.source.retained)? != self.source.immutable { return Err(Error::ReviewMismatch); }
        self.read.check_source(&self.source.identity)
    }
    pub(crate) fn into_history_preparation(self) -> Result<PreparedOriginalDeliverySourceV3> {
        self.read.invalidate();
        self.source.check_custody()?;
        let previous = self.source.revision.lock().map_err(|_| Error::Locked)?.take().ok_or(Error::Uncertain)?;
        let fresh = self.source.journal.refresh_delivery_journal_revision_v3(previous)?;
        *self.source.revision.lock().map_err(|_| Error::Locked)? = Some(fresh);
        self.source.check_custody()?;
        Ok(self.source)
    }
    pub(crate) fn identity(&self) -> &str { self.source.identity() }
    pub(crate) fn root(&self) -> &Path { self.source.root() }
    pub(crate) fn read(&self) -> &Arc<PreparedReceiveAndViewAuthorityV3> { &self.read }
    pub(crate) fn record(&self) -> Result<&BornManualRosterEnrollmentRecordV2> { self.check_current()?; Ok(&self.source.retained.record) }
    pub(crate) fn account(&self) -> Result<&crate::account::DedicatedAccount> { self.check_current()?; Ok(self.source.retained.account.account()) }
    pub(crate) fn journal(&self) -> Result<&Arc<SignerConsentJournal>> { self.check_current()?; Ok(&self.source.journal) }
    pub(crate) fn original_policy(&self) -> Result<&crate::account::birth::recipient_policy_v2::OriginalRecipientPolicyExportV2> { self.check_current()?; Ok(&self.source.original_policy) }
    pub(crate) fn witness(&self) -> Result<&wholepact_authority::WitnessDisclosureDescriptor> { self.check_current()?; Ok(&self.source.witness) }
    pub(crate) fn with_revision<T>(&self, use_pin: impl FnOnce(&PreparedDeliveryJournalRevisionV3) -> Result<T>) -> Result<T> {
        self.check_current()?;
        let pin = self.source.revision.lock().map_err(|_| Error::Locked)?;
        use_pin(pin.as_ref().ok_or(Error::Uncertain)?)
    }
    pub(crate) fn take_revision(&self) -> Result<PreparedDeliveryJournalRevisionV3> {
        self.check_current()?;
        self.source.revision.lock().map_err(|_| Error::Locked)?.take().ok_or(Error::Uncertain)
    }
    pub(crate) fn install_committed_revision(&self, pin: PreparedDeliveryJournalRevisionV3) -> Result<()> {
        self.check_data_current()?;
        self.source.journal.check_delivery_journal_revision_v3(&pin)?;
        let mut slot = self.source.revision.lock().map_err(|_| Error::Locked)?;
        if slot.is_some() { return Err(Error::ReviewMismatch); }
        *slot = Some(pin);
        Ok(())
    }
}
