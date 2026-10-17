//! Native-approved encrypted namespace backup and revocable historical evidence.
//! No archive bytes become NamespaceCore, BornJournalOwner, a live installation,
//! AuthorityJournal, signing authority, or evidence of freshness/antirollback.
use super::*;
#[cfg(test)]
use crate::journal::NAMESPACE_ACCOUNT_TEMPLATE;
use crate::journal::{
    HistoricalNamespaceAccount, HistoricalNamespaceHistoryPage, NamespaceJournalStamp,
    namespace_account_history_page, namespace_account_stamp, namespace_account_summary,
    open_namespace_archive_account,
};
use crate::native_witness_owner::{
    NativeNamespaceBackupDecision, NativeNamespaceRecoveryDisclosureDecision, NativeWorkerLease,
};
use wholepact_storage_security::{
    PlannedWitnessBirthInitialization, PlannedWitnessBirthInspection,
    bundle::{JournalKind, JournalTemplate},
    generation_archive as capsule,
};

#[path = "namespace_archive_package.rs"]
mod package;
use package::{NewPackage, PackageFiles, Publication};

const MAX_DESCRIPTOR_BYTES: usize = 2 * 1024 * 1024;
const MAX_DISCLOSURE_PAGE_BYTES: usize = 1024 * 1024;
const DESCRIPTOR: &str = "namespace-descriptor";
const MASTER: &str = "namespace-storage-key";
const MARKER: &str = "installation-marker";
const LOCATOR: &str = "namespace-locator";
const DESCRIPTOR_ROLE: &str = "witness-namespace-descriptor-v1";
const MASTER_ROLE: &str = "witness-namespace-storage-key-v1";
const MARKER_ROLE: &str = "witness-installation-marker-v1";
const LOCATOR_ROLE: &str = "witness-locator-history-v1";
const ACCOUNT_ROLE: &str = "witness-account-history-v1";
static LOCATOR_TEMPLATE: JournalTemplate = JournalTemplate {
    kind: JournalKind::CoordinationAuthority,
    application_id: storage::LOCATOR_APPLICATION_ID,
    schema_version: storage::LOCATOR_SCHEMA_VERSION,
    create_sql: storage::SCHEMA,
};

#[derive(Clone)]
pub(crate) struct NamespaceBackupInput {
    pub(crate) namespace: NamespaceSetupInput,
    pub(crate) destination_directory: String,
    pub(crate) destination_key_file: String,
}
#[derive(Clone)]
pub(crate) struct NamespaceRecoveryInput {
    pub(crate) package_directory: String,
    pub(crate) archive_key_file: String,
    pub(crate) expected_namespace_digest: Option<String>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum AccountState {
    Absent,
    AuthenticatedEmpty,
    Committed { stamp: Box<NamespaceJournalStamp> },
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    version: u16,
    namespace: WitnessNamespaceBinding,
    captured_at_ms: u64,
    locator_history_digest: String,
    accounts: BTreeMap<String, AccountState>,
}
impl Descriptor {
    fn validate(&self) -> Result<()> {
        self.namespace.validate()?;
        hash(&self.locator_history_digest)?;
        if self.version != 1
            || self.captured_at_ms == 0
            || self.captured_at_ms > i64::MAX as u64
            || self.accounts.len() > MAX_INTENTS
        {
            return Err(AuthorityError::InvalidBinding);
        }
        for key in self.accounts.keys() {
            hash(key)?;
        }
        Ok(())
    }
    fn bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.validate()?;
        let bytes =
            Zeroizing::new(serde_json::to_vec(self).map_err(|_| AuthorityError::InvalidBinding)?);
        if bytes.len() > MAX_DESCRIPTOR_BYTES {
            return Err(AuthorityError::Limit);
        }
        Ok(bytes)
    }
    fn commitment(&self) -> Result<String> {
        self.validate()?;
        let accounts: BTreeMap<_, _> = self
            .accounts
            .iter()
            .map(|(id, state)| {
                Ok((
                    id,
                    digest("wholepact:namespace-archive-account-state:v1", state)?,
                ))
            })
            .collect::<Result<_>>()?;
        digest(
            "wholepact:namespace-archive-source-plan:v1",
            &(
                self.version,
                &self.namespace,
                self.captured_at_ms,
                &self.locator_history_digest,
                accounts,
            ),
        )
    }
}
fn history_digest(history: &LocatorHistory) -> Result<String> {
    let prepared: BTreeMap<_, _> = history
        .prepared
        .iter()
        .map(|(id, record)| {
            Ok((
                id,
                digest("wholepact:namespace-archive-prepared:v1", record)?,
            ))
        })
        .collect::<Result<_>>()?;
    let completed: BTreeMap<_, _> = history
        .completed
        .iter()
        .map(|(id, record)| {
            Ok((
                id,
                digest("wholepact:namespace-archive-completed:v1", record)?,
            ))
        })
        .collect::<Result<_>>()?;
    let exclusions: Vec<_> = history
        .exclusions
        .iter()
        .map(|record| digest("wholepact:namespace-archive-exclusion:v1", record))
        .collect::<Result<_>>()?;
    digest(
        "wholepact:namespace-archive-locator-history:v1",
        &(
            history.namespace.digest()?,
            digest("wholepact:namespace-archive-prepared-set:v1", &prepared)?,
            digest("wholepact:namespace-archive-completed-set:v1", &completed)?,
            digest("wholepact:namespace-archive-exclusion-list:v1", &exclusions)?,
        ),
    )
}
fn require_birth(
    history: &LocatorHistory,
    prepared: &PreparedIntent,
    record: &PendingBirthCommitRecord,
) -> Result<()> {
    prepared.validate(&history.namespace)?;
    record.validate()?;
    let intent = &prepared.intent;
    if record.request != intent.request
        || record.request_digest != intent.request_digest
        || record.local_target_digest != intent.local_target_digest
        || record.local_owner_review_digest != intent.local_owner_review_digest
        || record.owner_approval_evidence_digest != intent.owner_approval_evidence_digest
        || record.committed_at_ms < prepared.prepared_at_ms
    {
        return Err(AuthorityError::CorruptHistory);
    }
    if let Some(completed) = history.completed.get(&intent.digest(&history.namespace)?) {
        if completed.evidence.birth_commit != *record {
            return Err(AuthorityError::CorruptHistory);
        }
    }
    Ok(())
}
fn account_id(intent_digest: &str) -> Result<String> {
    hash(intent_digest)?;
    Ok(format!("account-{intent_digest}"))
}
fn key_for(
    master: &[u8; 32],
    namespace: &WitnessNamespaceBinding,
    intent: &CreationIntent,
) -> Result<DatabaseKey> {
    derive_key(
        master,
        &intent.digest(namespace)?,
        "wholepact:witness-original-account-journal-key:v1",
    )
}
fn absent_file_set(path: &Path) -> Result<bool> {
    let mut absent = true;
    for suffix in ["", "-wal", "-shm", "-journal"] {
        match fs::symlink_metadata(format!("{}{suffix}", path.display())) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) if suffix.is_empty() => absent = false,
            Ok(_) if absent => return Err(AuthorityError::CorruptHistory),
            Ok(_) => {}
            Err(_) => return Err(AuthorityError::Storage),
        }
    }
    Ok(absent)
}
fn capture_descriptor(core: &NamespaceCore, captured_at_ms: u64) -> Result<Descriptor> {
    core.check_current()?;
    let c = core.registry.lock().map_err(|_| AuthorityError::Storage)?;
    let history = storage::load_exact(c.connection(), &core.namespace)?;
    let mut accounts = BTreeMap::new();
    for (id, prepared) in &history.prepared {
        let path = core.path_for(&prepared.intent)?;
        let state = if absent_file_set(&path)? {
            AccountState::Absent
        } else {
            let key = core.key_for(&prepared.intent)?;
            let plan =
                PlannedWitnessBirthInitialization::new(&core.namespace.digest()?, id, &path, &key)?;
            match plan.inspect(&path, &key, &core.namespace.digest()?, id)? {
                PlannedWitnessBirthInspection::AuthenticatedEmpty => {
                    AccountState::AuthenticatedEmpty
                }
                PlannedWitnessBirthInspection::Initialized(snapshot) => {
                    let (stamp, birth) = namespace_account_stamp(
                        snapshot.connection(),
                        &prepared.intent.request.policy,
                    )?;
                    require_birth(&history, prepared, &birth)?;
                    AccountState::Committed {
                        stamp: Box::new(stamp),
                    }
                }
            }
        };
        if history.completed.contains_key(id) && !matches!(state, AccountState::Committed { .. }) {
            return Err(AuthorityError::CorruptHistory);
        }
        accounts.insert(id.clone(), state);
    }
    let descriptor = Descriptor {
        version: 1,
        namespace: core.namespace.clone(),
        captured_at_ms,
        locator_history_digest: history_digest(&history)?,
        accounts,
    };
    descriptor.bytes()?;
    drop(c);
    core.check_current()?;
    Ok(descriptor)
}

pub(crate) struct NamespaceBackupProposal {
    core: Arc<NamespaceCore>,
    target: NewPackage,
    key: DatabaseKey,
    key_file: String,
    key_commitment: String,
    capsule_id: String,
    descriptor: Descriptor,
    reviewed: String,
    display: String,
}
impl NamespaceBackupProposal {
    pub(crate) fn display(&self) -> Result<String> {
        self.check_current()?;
        Ok(self.display.clone())
    }
    pub(crate) fn review_digest(&self) -> Result<String> {
        self.check_current()?;
        Ok(self.reviewed.clone())
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        self.target.check_current()?;
        self.core.check_current()?;
        if capture_descriptor(&self.core, self.descriptor.captured_at_ms)? != self.descriptor {
            return Err(AuthorityError::Conflict);
        }
        let current = read_existing_storage_key(Path::new(&self.key_file))?;
        if digest("wholepact:namespace-archive-key-binding:v1", &*current)? != self.key_commitment {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
}
pub(crate) fn prepare_namespace_backup(
    input: NamespaceBackupInput,
) -> Result<NamespaceBackupProposal> {
    // This opens a NEW exclusive canonical owner, never a clone of a served owner.
    // Another supported writer/owner holding home/root locks makes this fail.
    let core = open_namespace_identity(&input.namespace)?;
    let target = NewPackage::prepare(
        Path::new(&input.destination_directory),
        core.files.root_path(),
    )?;
    let key_bytes = read_existing_storage_key(Path::new(&input.destination_key_file))?;
    if *key_bytes == *core.master {
        return Err(AuthorityError::InvalidBinding);
    }
    let key_commitment = digest("wholepact:namespace-archive-key-binding:v1", &*key_bytes)?;
    let key = DatabaseKey::from_bytes(*key_bytes);
    let mut nonce = [0u8; 32];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| AuthorityError::Storage)?;
    let capsule_id = hex::encode(nonce);
    let descriptor = capture_descriptor(&core, crate::now_ms()?)?;
    let reviewed = digest(
        "wholepact:native-namespace-backup-review:v1",
        &(
            target.binding_digest()?,
            &input.destination_key_file,
            &key_commitment,
            &capsule_id,
            descriptor.commitment()?,
            "complete-encrypted-namespace-storage-key-and-private-history",
        ),
    )?;
    // No decrypted account/history metadata is disclosed before native approval.
    let display = format!(
        "ENCRYPTED WITNESS NAMESPACE BACKUP\n\nSelected installed witness: {}\nNew private package: {}\nExisting independent archive key file: {}\nCapsule ID: {}\nExact review digest: {}\n\nThis copies the COMPLETE private namespace history and its STORAGE MASTER KEY into an encrypted capsule. It includes account and viewing-key DIGEST indexes, immutable requests and evidence, budgets, exclusions, journal history and retained session secrets. It does not include wallet spending/signing keys. The archive key is not stored in the package. Anyone with the package and that key can decrypt its private contents.\n\nOnly a new output directory is supported. Failure remnants cannot be reset or adopted. The package is historical disaster-recovery evidence only. It cannot restore a live namespace, replenish budget, erase exclusions, establish freshness or defeat rollback.",
        input.namespace.witness_id,
        input.destination_directory,
        input.destination_key_file,
        capsule_id,
        reviewed
    );
    let proposal = NamespaceBackupProposal {
        core,
        target,
        key,
        key_file: input.destination_key_file,
        key_commitment,
        capsule_id,
        descriptor,
        reviewed,
        display,
    };
    proposal.check_current()?;
    Ok(proposal)
}

// Private concrete adapter: exact registered sources + native publication + the
// independently acquired live namespace locks. No public callback grants consent.
struct BackupAuthority<'a> {
    expected: capsule::ArchiveScope,
    native: &'a NativePublicationLease,
    core: &'a NamespaceCore,
    package: &'a PackageFiles,
}
struct BackupLease<'a>(&'a BackupAuthority<'a>);
impl capsule::ArchiveAuthority for BackupAuthority<'_> {
    fn acquire<'a>(
        &'a self,
        scope: &capsule::ArchiveScope,
    ) -> capsule::Result<Box<dyn capsule::ArchiveLease + 'a>> {
        if scope != &self.expected {
            return Err(capsule::ArchiveError::Permission);
        }
        let lease = BackupLease(self);
        capsule::ArchiveLease::check_current(&lease)?;
        Ok(Box::new(lease))
    }
}
impl capsule::ArchiveLease for BackupLease<'_> {
    fn check_current(&self) -> capsule::Result<()> {
        self.0
            .native
            .check_current()
            .map_err(|_| capsule::ArchiveError::Permission)?;
        self.0
            .core
            .files
            .check_current()
            .map_err(|_| capsule::ArchiveError::SourceChanged)?;
        let c = self
            .0
            .core
            .registry
            .lock()
            .map_err(|_| capsule::ArchiveError::Permission)?;
        self.0
            .core
            .registry_identity
            .check_current(c.connection())
            .map_err(|_| capsule::ArchiveError::SourceChanged)?;
        self.0
            .package
            .check(false)
            .map_err(|_| capsule::ArchiveError::SourceChanged)
    }
}
#[derive(Serialize)]
pub(crate) struct NamespaceArchiveReceipt {
    pub(crate) package_directory: String,
    pub(crate) capsule_id: String,
    pub(crate) manifest_digest: String,
    pub(crate) namespace_digest: String,
    pub(crate) historical_only: bool,
}
pub(crate) fn write_namespace_backup(
    decision: NativeNamespaceBackupDecision,
) -> Result<NamespaceArchiveReceipt> {
    let (proposal, native) = decision.into_parts();
    native.check_current()?;
    if native.reviewed_digest() != proposal.reviewed {
        return Err(AuthorityError::InvalidBinding);
    }
    proposal.check_current()?;
    let native = native.publication_lease()?;
    native.check_current()?;
    if native.reviewed_digest() != proposal.reviewed || native.admitted_at_ms() > crate::now_ms()? {
        return Err(AuthorityError::InvalidBinding);
    }
    let NamespaceBackupProposal {
        core,
        target,
        key,
        capsule_id,
        descriptor,
        reviewed,
        ..
    } = proposal;
    let files = target.create()?;
    let destination = files.capsule();
    let marker = core.files.root_path().join("installation.id");
    let locator = core.files.registry_path();
    let descriptor_bytes = descriptor.bytes()?;
    let account_paths: Vec<_> = {
        let c = core.registry.lock().map_err(|_| AuthorityError::Storage)?;
        let history = storage::load_exact(c.connection(), &core.namespace)?;
        descriptor
            .accounts
            .iter()
            .filter_map(|(id, state)| (!matches!(state, AccountState::Absent)).then_some(id))
            .map(|id| {
                let prepared = history
                    .prepared
                    .get(id)
                    .ok_or(AuthorityError::CorruptHistory)?;
                Ok((account_id(id)?, core.path_for(&prepared.intent)?))
            })
            .collect::<Result<_>>()?
    };
    let mut sources = vec![
        capsule::RegisteredSource::new(
            DESCRIPTOR,
            DESCRIPTOR_ROLE,
            capsule::Source::Secret(&descriptor_bytes),
        )
        .map_err(archive_error)?,
        capsule::RegisteredSource::new(MASTER, MASTER_ROLE, capsule::Source::Secret(&*core.master))
            .map_err(archive_error)?,
        capsule::RegisteredSource::new(MARKER, MARKER_ROLE, capsule::Source::File(&marker))
            .map_err(archive_error)?,
        capsule::RegisteredSource::new(LOCATOR, LOCATOR_ROLE, capsule::Source::Journal(&locator))
            .map_err(archive_error)?,
    ];
    for (id, path) in &account_paths {
        sources.push(
            capsule::RegisteredSource::new(id, ACCOUNT_ROLE, capsule::Source::Journal(path))
                .map_err(archive_error)?,
        );
    }
    let node = capsule::NodeSpec {
        generation_id: core.namespace.namespace_instance_id.clone(),
        profile_id: core.namespace.witness_id.clone(),
        original_root: core.files.root_path().into(),
    };
    let expected =
        capsule::ArchiveScope::for_snapshot(&destination, &key, &capsule_id, &node, &sources, &[])
            .map_err(archive_error)?;
    let authority = BackupAuthority {
        expected,
        native: &native,
        core: &core,
        package: &files,
    };
    capsule::snapshot(capsule::SnapshotRequest {
        destination: &destination,
        key: &key,
        capsule_id: &capsule_id,
        node: &node,
        sources: &sources,
        parents: &[],
        authority: &authority,
    })
    .map_err(archive_error)?;
    native.check_current()?;
    let archive = capsule::inspect(&destination, &key).map_err(archive_error)?;
    let verified = verify_namespace_archive(archive)?;
    if verified.descriptor != descriptor {
        return Err(AuthorityError::CorruptHistory);
    }
    if capture_descriptor(&core, descriptor.captured_at_ms)? != descriptor {
        return Err(AuthorityError::Conflict);
    }
    native.check_current()?;
    let publication = Publication {
        version: 1,
        capsule_id: capsule_id.clone(),
        manifest_digest: verified.archive.manifest_digest().into(),
        namespace_digest: core.namespace.digest()?,
        source_plan_digest: descriptor.commitment()?,
        native_review_digest: reviewed,
        published_at_ms: crate::now_ms()?,
        permanently_historical: true,
    };
    package::publish(&files, &key, &publication, &native)?;
    core.check_current()?;
    native.check_current()?;
    Ok(NamespaceArchiveReceipt {
        package_directory: files.root().display().to_string(),
        capsule_id,
        manifest_digest: publication.manifest_digest,
        namespace_digest: publication.namespace_digest,
        historical_only: true,
    })
}
fn archive_error(error: capsule::ArchiveError) -> AuthorityError {
    match error {
        capsule::ArchiveError::Limit => AuthorityError::Limit,
        capsule::ArchiveError::Permission => AuthorityError::Permission,
        capsule::ArchiveError::Storage => AuthorityError::Storage,
        _ => AuthorityError::CorruptHistory,
    }
}

// Internal authenticated historical data. This type has NO exported getters and
// never escapes except behind the revocable native disclosure owner below.
struct VerifiedContents {
    archive: capsule::VerifiedArchive,
    descriptor: Descriptor,
    history: LocatorHistory,
    master: Zeroizing<[u8; 32]>,
}
fn require_entry(
    node: &capsule::Node,
    id: &str,
    role: &str,
    origin: Option<&Path>,
    kind: u8,
) -> Result<()> {
    let entry = node.entries.get(id).ok_or(AuthorityError::CorruptHistory)?;
    let expected_origin = origin
        .map(|p| p.to_str().ok_or(AuthorityError::InvalidBinding))
        .transpose()?;
    let actual_kind = match entry.payload {
        capsule::EntryPayload::File { .. } => 0,
        capsule::EntryPayload::Secret { .. } => 1,
        capsule::EntryPayload::Journal { .. } => 2,
    };
    if entry.role != role || entry.origin.as_deref() != expected_origin || actual_kind != kind {
        return Err(AuthorityError::CorruptHistory);
    }
    Ok(())
}
fn require_inventory_matrix(
    node: &capsule::Node,
    descriptor: &Descriptor,
    history: &LocatorHistory,
) -> Result<()> {
    descriptor.validate()?;
    if node.generation_id != descriptor.namespace.namespace_instance_id
        || node.profile_id != descriptor.namespace.witness_id
        || node.original_root != descriptor.namespace.canonical_private_root
        || history.namespace != descriptor.namespace
        || history_digest(history)? != descriptor.locator_history_digest
        || history.prepared.keys().ne(descriptor.accounts.keys())
    {
        return Err(AuthorityError::CorruptHistory);
    }
    let root = Path::new(&descriptor.namespace.canonical_private_root);
    let mut entries = BTreeSet::from([
        DESCRIPTOR.to_owned(),
        MASTER.to_owned(),
        MARKER.to_owned(),
        LOCATOR.to_owned(),
    ]);
    require_entry(node, DESCRIPTOR, DESCRIPTOR_ROLE, None, 1)?;
    require_entry(node, MASTER, MASTER_ROLE, None, 1)?;
    require_entry(
        node,
        MARKER,
        MARKER_ROLE,
        Some(&root.join("installation.id")),
        0,
    )?;
    require_entry(
        node,
        LOCATOR,
        LOCATOR_ROLE,
        Some(&root.join("registry.wp")),
        2,
    )?;
    for (id, prepared) in &history.prepared {
        let state = &descriptor.accounts[id];
        if history.completed.contains_key(id) && !matches!(state, AccountState::Committed { .. }) {
            return Err(AuthorityError::CorruptHistory);
        }
        if !matches!(state, AccountState::Absent) {
            let entry_id = account_id(id)?;
            require_entry(
                node,
                &entry_id,
                ACCOUNT_ROLE,
                Some(&root.join(&prepared.intent.derived_child)),
                2,
            )?;
            entries.insert(entry_id);
        }
    }
    if node.entries.keys().ne(entries.iter()) {
        return Err(AuthorityError::CorruptHistory);
    }
    Ok(())
}
fn verify_namespace_archive(archive: capsule::VerifiedArchive) -> Result<VerifiedContents> {
    if archive.manifests().len() != 1 || !archive.manifest().parent_manifest_digests.is_empty() {
        return Err(AuthorityError::CorruptHistory);
    }
    let manifest = archive.manifest_digest();
    let node = archive.node(manifest).map_err(archive_error)?;
    require_entry(node, DESCRIPTOR, DESCRIPTOR_ROLE, None, 1)?;
    require_entry(node, MASTER, MASTER_ROLE, None, 1)?;
    let bytes = archive
        .read_private_entry(manifest, DESCRIPTOR, MAX_DESCRIPTOR_BYTES)
        .map_err(archive_error)?;
    let descriptor: Descriptor =
        serde_json::from_slice(&bytes).map_err(|_| AuthorityError::CorruptHistory)?;
    descriptor.validate()?;
    // Reject noncanonical/duplicate-key descriptor encodings as well as unknown fields.
    if descriptor.bytes()?.as_slice() != bytes.as_slice() {
        return Err(AuthorityError::CorruptHistory);
    }
    let namespace = &descriptor.namespace;
    let root = Path::new(&namespace.canonical_private_root);
    if node.generation_id != namespace.namespace_instance_id
        || node.profile_id != namespace.witness_id
        || node.original_root != namespace.canonical_private_root
    {
        return Err(AuthorityError::CorruptHistory);
    }
    require_entry(
        node,
        MARKER,
        MARKER_ROLE,
        Some(&root.join("installation.id")),
        0,
    )?;
    require_entry(
        node,
        LOCATOR,
        LOCATOR_ROLE,
        Some(&root.join("registry.wp")),
        2,
    )?;
    let marker = archive
        .read_private_entry(manifest, MARKER, 64)
        .map_err(archive_error)?;
    if marker.as_slice() != namespace.namespace_instance_id.as_bytes() {
        return Err(AuthorityError::CorruptHistory);
    }
    let secret = archive
        .read_private_entry(manifest, MASTER, 32)
        .map_err(archive_error)?;
    let mut master = Zeroizing::new([0u8; 32]);
    if secret.len() != 32 || secret.iter().all(|b| *b == 0) {
        return Err(AuthorityError::CorruptHistory);
    }
    master.copy_from_slice(&secret);
    let locator_key = derive_key(
        &master,
        &namespace.namespace_instance_id,
        "wholepact:witness-locator-storage-key:v1",
    )?;
    let locator = archive
        .journal(manifest, LOCATOR)
        .map_err(archive_error)?
        .open_ordinary(&locator_key, &LOCATOR_TEMPLATE)
        .map_err(archive_error)?;
    let history = storage::load_exact(locator.connection(), namespace)?;
    require_inventory_matrix(node, &descriptor, &history)?;
    let mut expected_entries = BTreeSet::from([
        DESCRIPTOR.to_owned(),
        MASTER.to_owned(),
        MARKER.to_owned(),
        LOCATOR.to_owned(),
    ]);
    for (id, prepared) in &history.prepared {
        let state = descriptor
            .accounts
            .get(id)
            .ok_or(AuthorityError::CorruptHistory)?;
        let entry_id = account_id(id)?;
        let path = root.join(&prepared.intent.derived_child);
        match state {
            AccountState::Absent => {
                if history.completed.contains_key(id) || node.entries.contains_key(&entry_id) {
                    return Err(AuthorityError::CorruptHistory);
                }
            }
            AccountState::AuthenticatedEmpty => {
                if history.completed.contains_key(id) {
                    return Err(AuthorityError::CorruptHistory);
                }
                require_entry(node, &entry_id, ACCOUNT_ROLE, Some(&path), 2)?;
                let key = key_for(&master, namespace, &prepared.intent)?;
                archive
                    .journal(manifest, &entry_id)
                    .map_err(archive_error)?
                    .verify_archived_planned_witness_empty(&key, &namespace.digest()?, id, &path)
                    .map_err(archive_error)?;
                expected_entries.insert(entry_id);
            }
            AccountState::Committed { stamp } => {
                require_entry(node, &entry_id, ACCOUNT_ROLE, Some(&path), 2)?;
                let key = key_for(&master, namespace, &prepared.intent)?;
                let account_source = archive
                    .journal(manifest, &entry_id)
                    .map_err(archive_error)?;
                let account =
                    open_namespace_archive_account(&account_source, &key).map_err(archive_error)?;
                let (actual, birth) =
                    namespace_account_stamp(account.connection(), &prepared.intent.request.policy)?;
                require_birth(&history, prepared, &birth)?;
                if &actual != stamp.as_ref() {
                    return Err(AuthorityError::CorruptHistory);
                }
                expected_entries.insert(entry_id);
            }
        }
    }
    if node.entries.keys().ne(expected_entries.iter()) {
        return Err(AuthorityError::CorruptHistory);
    }
    drop(locator);
    Ok(VerifiedContents {
        archive,
        descriptor,
        history,
        master,
    })
}
fn require_publication(contents: &VerifiedContents, publication: &Publication) -> Result<()> {
    if publication.capsule_id != contents.archive.manifest().capsule_id
        || publication.manifest_digest != contents.archive.manifest_digest()
        || publication.namespace_digest != contents.descriptor.namespace.digest()?
        || publication.source_plan_digest != contents.descriptor.commitment()?
        || publication.published_at_ms < contents.descriptor.captured_at_ms
        || !publication.permanently_historical
    {
        return Err(AuthorityError::CorruptHistory);
    }
    Ok(())
}

/// An inert, bounded private preflight. No metadata/history getter is available.
/// Paths/keys do not construct the approved historical disclosure owner.
pub(crate) struct NamespaceRecoveryProposal {
    files: PackageFiles,
    publication: Publication,
    contents: VerifiedContents,
    package_binding: String,
    key_file: String,
    key_commitment: String,
    reviewed: String,
    display: String,
}
impl NamespaceRecoveryProposal {
    pub(crate) fn display(&self) -> Result<String> {
        self.check_current()?;
        Ok(self.display.clone())
    }
    pub(crate) fn review_digest(&self) -> Result<String> {
        self.check_current()?;
        Ok(self.reviewed.clone())
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        self.files.check(true)?;
        if self.files.binding_digest()? != self.package_binding {
            return Err(AuthorityError::InvalidBinding);
        }
        let key = read_existing_storage_key(Path::new(&self.key_file))?;
        if digest("wholepact:namespace-archive-key-binding:v1", &*key)? != self.key_commitment {
            return Err(AuthorityError::InvalidBinding);
        }
        require_publication(&self.contents, &self.publication)
    }
}
pub(crate) fn prepare_namespace_recovery_disclosure(
    input: NamespaceRecoveryInput,
) -> Result<NamespaceRecoveryProposal> {
    if let Some(expected) = &input.expected_namespace_digest {
        hash(expected)?;
    }
    let files = PackageFiles::open(Path::new(&input.package_directory))?;
    let package_binding = files.binding_digest()?;
    let key_bytes = read_existing_storage_key(Path::new(&input.archive_key_file))?;
    let key_commitment = digest("wholepact:namespace-archive-key-binding:v1", &*key_bytes)?;
    let key = DatabaseKey::from_bytes(*key_bytes);
    let publication = package::read_publication(&files, &key)?;
    let archive = capsule::inspect(&files.capsule(), &key).map_err(archive_error)?;
    let contents = verify_namespace_archive(archive)?;
    require_publication(&contents, &publication)?;
    if input
        .expected_namespace_digest
        .as_ref()
        .is_some_and(|expected| expected != &publication.namespace_digest)
    {
        return Err(AuthorityError::InvalidBinding);
    }
    if files.binding_digest()? != package_binding {
        return Err(AuthorityError::InvalidBinding);
    }
    let reviewed = digest(
        "wholepact:native-namespace-recovery-disclosure:v1",
        &(
            &package_binding,
            &key_commitment,
            &input.archive_key_file,
            &publication,
            &input.expected_namespace_digest,
            "private-historical-inventory-and-account-history-only",
        ),
    )?;
    // Deliberately no decrypted namespace IDs, source roots, accounts, balances,
    // timestamps, exclusions or policy in the preapproval display.
    let display = format!(
        "PRIVATE HISTORICAL NAMESPACE DISCLOSURE\n\nSelected encrypted package: {}\nSelected existing archive key file: {}\nExact private source/key review commitment: {}\n\nApproval permits local review of the authenticated historical namespace identity, exact inventory, immutable creation intents, completion records, exclusions, account policies, budgets, and bounded journal history pages. Private metadata is not shown until this approval. Stored namespace/session keys remain internal and are not exportable through this reader.\n\nDisclosure ends on focus loss, cancellation, window close or the 120-second review deadline. Another review needs fresh approval. The capsule does not establish currentness, latest history, antirollback, live namespace continuity, or authority to spend/sign/mutate. No live installation is recreated or replaced.",
        input.package_directory, input.archive_key_file, reviewed
    );
    let proposal = NamespaceRecoveryProposal {
        files,
        publication,
        contents,
        package_binding,
        key_file: input.archive_key_file,
        key_commitment,
        reviewed,
        display,
    };
    proposal.check_current()?;
    Ok(proposal)
}

/// A native-owned, non-clone, non-deserializable private disclosure session.
/// Only inert bounded values escape; no raw archive, master, key, connection,
/// mutable journal or live namespace owner accessor exists.
pub(crate) struct VerifiedHistoricalNamespace {
    proposal: NamespaceRecoveryProposal,
    native: NativeWorkerLease,
}
pub(crate) fn open_namespace_recovery_evidence(
    decision: NativeNamespaceRecoveryDisclosureDecision,
) -> Result<VerifiedHistoricalNamespace> {
    let (proposal, native) = decision.into_parts();
    native.check_current()?;
    if native.reviewed_digest() != proposal.reviewed {
        return Err(AuthorityError::InvalidBinding);
    }
    proposal.check_current()?;
    // IMPORTANT: never transition this lease to PUBLISHING. OPEN is immediately
    // revocable by the still-responsive GUI; every read checks before AND after.
    native.check_current()?;
    Ok(VerifiedHistoricalNamespace { proposal, native })
}
#[derive(Serialize)]
pub(crate) struct HistoricalNamespaceSummary {
    pub(crate) namespace: WitnessNamespaceBinding,
    pub(crate) namespace_digest: String,
    pub(crate) capsule_id: String,
    pub(crate) manifest_digest: String,
    pub(crate) captured_at_ms: u64,
    pub(crate) published_at_ms: u64,
    pub(crate) prepared_intents: usize,
    pub(crate) completed_intents: usize,
    pub(crate) retained_exclusions: usize,
    pub(crate) historical_only: bool,
    pub(crate) freshness_established: bool,
    pub(crate) mutation_permitted: bool,
}
#[derive(Serialize)]
pub(crate) struct HistoricalNamespaceInventoryRecord {
    pub(crate) kind: String,
    pub(crate) intent_digest: Option<String>,
    // Exact retained canonical JSON is inert review text, never an import API.
    pub(crate) record_json: String,
}
#[derive(Serialize)]
pub(crate) struct HistoricalNamespaceInventoryPage {
    pub(crate) first_record: u32,
    pub(crate) next_record: Option<u32>,
    pub(crate) total_records: usize,
    pub(crate) records: Vec<HistoricalNamespaceInventoryRecord>,
    pub(crate) historical_only: bool,
}
impl VerifiedHistoricalNamespace {
    fn check_disclosure(&self) -> Result<()> {
        self.native.check_current()?;
        if self.native.reviewed_digest() != self.proposal.reviewed {
            return Err(AuthorityError::InvalidBinding);
        }
        self.proposal.check_current()?;
        self.native.check_current()
    }
    pub(crate) fn summary(&self) -> Result<HistoricalNamespaceSummary> {
        self.check_disclosure()?;
        let contents = &self.proposal.contents;
        let summary = HistoricalNamespaceSummary {
            namespace: contents.descriptor.namespace.clone(),
            namespace_digest: contents.descriptor.namespace.digest()?,
            capsule_id: self.proposal.publication.capsule_id.clone(),
            manifest_digest: self.proposal.publication.manifest_digest.clone(),
            captured_at_ms: contents.descriptor.captured_at_ms,
            published_at_ms: self.proposal.publication.published_at_ms,
            prepared_intents: contents.history.prepared.len(),
            completed_intents: contents.history.completed.len(),
            retained_exclusions: contents.history.exclusions.len(),
            historical_only: true,
            freshness_established: false,
            mutation_permitted: false,
        };
        self.check_disclosure()?;
        Ok(summary)
    }
    pub(crate) fn inventory(
        &self,
        first: u32,
        limit: u32,
    ) -> Result<HistoricalNamespaceInventoryPage> {
        self.check_disclosure()?;
        if limit == 0 || limit > 16 {
            return Err(AuthorityError::InvalidBinding);
        }
        let contents = &self.proposal.contents;
        let history = &contents.history;
        let total = history.prepared.len() + history.exclusions.len();
        if first as usize > total {
            return Err(AuthorityError::InvalidBinding);
        }
        let mut records = Vec::new();
        let mut bytes = 0usize;
        for index in first as usize..total {
            if records.len() >= limit as usize {
                break;
            }
            let item = if index < history.prepared.len() {
                let (id, prepared) = history
                    .prepared
                    .iter()
                    .nth(index)
                    .ok_or(AuthorityError::CorruptHistory)?;
                let json = serde_json::to_string(&(
                    prepared,
                    history.completed.get(id),
                    contents.descriptor.accounts.get(id),
                ))
                .map_err(|_| AuthorityError::CorruptHistory)?;
                HistoricalNamespaceInventoryRecord {
                    kind: "retained_intent_and_completion".into(),
                    intent_digest: Some(id.clone()),
                    record_json: json,
                }
            } else {
                let record = &history.exclusions[index - history.prepared.len()];
                HistoricalNamespaceInventoryRecord {
                    kind: "retained_permanent_exclusion".into(),
                    intent_digest: None,
                    record_json: serde_json::to_string(record)
                        .map_err(|_| AuthorityError::CorruptHistory)?,
                }
            };
            let encoded = serde_json::to_vec(&item).map_err(|_| AuthorityError::CorruptHistory)?;
            if encoded.len() > MAX_DISCLOSURE_PAGE_BYTES - 1024 {
                return Err(AuthorityError::Limit);
            }
            if bytes + encoded.len() > MAX_DISCLOSURE_PAGE_BYTES - 1024 {
                break;
            }
            bytes += encoded.len();
            records.push(item);
        }
        let next = first as usize + records.len();
        let page = HistoricalNamespaceInventoryPage {
            first_record: first,
            next_record: (next < total).then_some(next as u32),
            total_records: total,
            records,
            historical_only: true,
        };
        if serde_json::to_vec(&page)
            .map_err(|_| AuthorityError::CorruptHistory)?
            .len()
            > MAX_DISCLOSURE_PAGE_BYTES
        {
            return Err(AuthorityError::Limit);
        }
        self.check_disclosure()?;
        Ok(page)
    }
    fn account_snapshot(
        &self,
        id: &str,
    ) -> Result<(
        wholepact_storage_security::EncryptedReadSnapshot,
        &CreationIntent,
    )> {
        hash(id)?;
        let contents = &self.proposal.contents;
        if !matches!(
            contents.descriptor.accounts.get(id),
            Some(AccountState::Committed { .. })
        ) {
            return Err(AuthorityError::RecoveryRequired);
        }
        let intent = &contents
            .history
            .prepared
            .get(id)
            .ok_or(AuthorityError::CorruptHistory)?
            .intent;
        let key = key_for(&contents.master, &contents.descriptor.namespace, intent)?;
        let account_source = contents
            .archive
            .journal(contents.archive.manifest_digest(), &account_id(id)?)
            .map_err(archive_error)?;
        let snapshot =
            open_namespace_archive_account(&account_source, &key).map_err(archive_error)?;
        Ok((snapshot, intent))
    }
    pub(crate) fn account_summary(&self, id: &str) -> Result<HistoricalNamespaceAccount> {
        self.check_disclosure()?;
        let (snapshot, intent) = self.account_snapshot(id)?;
        let summary = namespace_account_summary(snapshot.connection(), &intent.request.policy)?;
        if serde_json::to_vec(&summary)
            .map_err(|_| AuthorityError::CorruptHistory)?
            .len()
            > MAX_DISCLOSURE_PAGE_BYTES
        {
            return Err(AuthorityError::Limit);
        }
        self.check_disclosure()?;
        Ok(summary)
    }
    pub(crate) fn account_history(
        &self,
        id: &str,
        first_sequence: u64,
        limit: u32,
    ) -> Result<HistoricalNamespaceHistoryPage> {
        self.check_disclosure()?;
        if first_sequence == 0 || limit == 0 || limit > 32 {
            return Err(AuthorityError::InvalidBinding);
        }
        let (snapshot, intent) = self.account_snapshot(id)?;
        let page = namespace_account_history_page(
            snapshot.connection(),
            &intent.request.policy,
            first_sequence,
            limit,
        )?;
        self.check_disclosure()?;
        Ok(page)
    }
}

#[cfg(test)]
#[path = "namespace_archive_tests.rs"]
mod tests;
