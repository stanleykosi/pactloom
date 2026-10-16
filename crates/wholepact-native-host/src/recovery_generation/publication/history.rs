//! Immutable inherited-generation inspection only. Current financial registry
//! metadata is authenticated for scope/exclusion, but its live journal files are
//! not opened here. This is not whole-profile backup or current financial state.
use super::*;
use std::path::Path;
use wholepact_storage_security::{
    EncryptedReadSnapshot,
    bundle::{open_journal_read_snapshot, recovery::evidence::RecoveredEvidence},
};
use wholepact_store::recovery::RecoveredStoreSnapshot;

/// Non-deserializable historical integrity capability. The borrowed directory
/// keeps the exclusive profile lock alive; the private snapshots never become
/// mutable journals, signer permissions, saved admissions, or a host runtime.
pub(crate) struct CommittedHistory<'a> {
    directory: &'a Directory,
    plan: Plan,
    manifest_digest: String,
    components: Vec<RecoveredEvidence>,
    _store: RecoveredStoreSnapshot,
    _auxiliaries: Vec<EncryptedReadSnapshot>,
    financial: Vec<crate::financial_inventory::Attachment>,
}
impl CommittedHistory<'_> {
    pub(crate) fn generation_id(&self) -> &str {
        &self.plan.generation_id
    }
    pub(crate) fn inventory_digest(&self) -> &str {
        &self.plan.inventory_digest
    }
    pub(crate) fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }
    pub(crate) fn profile_id(&self) -> &str {
        &self.plan.successor_profile
    }
    pub(crate) fn known_account_ids(&self) -> &BTreeSet<String> {
        &self.plan.affected_accounts
    }
    pub(crate) fn components(&self) -> &[RecoveredEvidence] {
        &self.components
    }
    pub(crate) fn component(&self, id: &str) -> Result<&RecoveredEvidence> {
        self.components
            .iter()
            .find(|c| c.provenance().component_id == id)
            .ok_or(Error::Invalid)
    }
    /// Authenticated registry metadata only. No current financial journal
    /// closure, account completeness, backup, or live observation is established.
    pub(crate) fn registered_financial_directories(&self) -> usize {
        self.financial.len()
    }
    pub(crate) fn check(&self) -> Result<()> {
        self.directory.check()
    }

    /// Exclude the root and every currently registered financial directory from
    /// private artifact exports. Inspect paths/inodes only; no financial journal
    /// or financial vault is opened, migrated, or unlocked by this check.
    pub(crate) fn external_destination(&self, destination: &Path) -> Result<()> {
        self.directory.external_destination(destination)?;
        for attachment in &self.financial {
            if destination.starts_with(&attachment.directory) {
                return Err(Error::Invalid);
            }
            let canonical = match std::fs::canonicalize(&attachment.directory) {
                Ok(path) => path,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err(Error::Storage),
            };
            if destination.starts_with(&canonical) {
                return Err(Error::Invalid);
            }
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::fs::MetadataExt;
                let protected = std::fs::symlink_metadata(&canonical)?;
                if !protected.is_dir() {
                    return Err(Error::Invalid);
                }
                let parent = destination.parent().ok_or(Error::Invalid)?;
                for ancestor in parent.ancestors() {
                    let candidate = std::fs::symlink_metadata(ancestor)?;
                    if candidate.dev() == protected.dev() && candidate.ino() == protected.ino() {
                        return Err(Error::Invalid);
                    }
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn open_committed_history<'a>(
    directory: &'a Directory,
    secrets: &Secrets,
) -> Result<CommittedHistory<'a>> {
    directory.check()?;
    let commit = unseal(secrets, b"commit", &directory.read(COMMIT, MAX_DOCUMENT)?)?;
    let metadata = complete_origins::checked_metadata_dispatch(directory, secrets, &commit)?;
    check_directory_inventory(directory, &metadata.plan)?;
    let components = read_evidence(directory, &metadata)?;
    // Recompute the complete typed original proof/signature/transaction and
    // submission dependency graph. Individually valid orphan artifacts cannot
    // become selectively exportable by merely surviving in an evidence file.
    let semantic = crate::recovery_semantics::inspect_successor(
        &components,
        &metadata.plan.affected_accounts,
    )?;
    if semantic.digest() != metadata.plan.semantic_inventory_digest
        || semantic.accounts() != &metadata.plan.affected_accounts
    {
        return Err(Error::Authentication);
    }
    let coordination = metadata
        .plan
        .components
        .iter()
        .find(|c| c.component_id == "coordination")
        .ok_or(Error::Authentication)?;
    let store = RecoveredStoreSnapshot::open(
        &directory.path(crate::vault::JOURNALS[0])?,
        &secrets.key(0)?,
        &metadata.binding,
        coordination,
    )?;
    store.verify_recovery_obligation_fences(&metadata.restrictions)?;
    let original_coordination = components
        .iter()
        .find(|c| c.provenance().component_id == "coordination")
        .ok_or(Error::Authentication)?;
    let original_semantic =
        wholepact_engine::recovery::inspect_successor_coordination_recovery(original_coordination)?;
    super::complete_origins::validate_store_manifest_dispatch(
        &unseal(
            secrets,
            b"manifest",
            &directory.read(MANIFEST, MAX_DOCUMENT)?,
        )?,
        original_semantic.store_inventory(),
    )?;
    let templates = [
        &wholepact_transport::bundle::INBOX_BACKUP_TEMPLATE,
        &wholepact_transport::bundle::OUTBOX_BACKUP_TEMPLATE,
        &wholepact_chain::backup::TEMPLATE,
    ];
    let mut auxiliaries = Vec::with_capacity(3);
    for (index, template) in templates.into_iter().enumerate() {
        auxiliaries.push(open_journal_read_snapshot(
            &directory.path(crate::vault::JOURNALS[index + 1])?,
            &secrets.key(index + 1)?,
            template,
        )?);
    }
    let attached = directory.path("financial.attached")?.try_exists()?;
    let registry = directory
        .path(crate::financial_inventory::FILE)?
        .try_exists()?;
    if attached != registry {
        return Err(Error::Authentication);
    }
    let financial = if attached {
        if directory.read("financial.attached", 1024)?
            != b"wholepact-financial-profile-attached-v1\n"
        {
            return Err(Error::Authentication);
        }
        crate::financial_inventory::read(directory, secrets)?
    } else {
        Vec::new()
    };
    check_directory_inventory(directory, &metadata.plan)?;
    directory.check()?;
    Ok(CommittedHistory {
        directory,
        plan: metadata.plan,
        manifest_digest: metadata.manifest_digest,
        components,
        _store: store,
        _auxiliaries: auxiliaries,
        financial,
    })
}
