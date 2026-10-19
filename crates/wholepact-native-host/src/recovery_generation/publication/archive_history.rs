//! Complete native interpretation of a structurally authenticated generation
//! capsule. Original paths are authenticated identities only and are never read.
//! Saved admissions remain audit records, not publication or financial authority.
use super::*;
use crate::financial_inventory::Attachment;
use std::{collections::BTreeMap, path::Path};
use wholepact_storage_security::{
    bundle::{JournalKind, JournalTemplate, recovery::evidence::RecoveredEvidence},
    generation_archive::{
        ArchivedGenerationSource, ArchivedJournal, ArchivedOrdinarySource, EntryPayload, Node,
        VerifiedArchive,
    },
};

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceDescriptor {
    pub(crate) version: u16,
    pub(crate) profile_id: String,
    pub(crate) generation_id: String,
    pub(crate) plan_digest: String,
    pub(crate) plan_version: u16,
    pub(crate) attachments: Vec<Attachment>,
}

/// Private capture metadata after the existing committed reader has checked the
/// original generation. Capturing must still hold every source directory lock;
/// the resulting capsule must pass complete native verification before success.
pub(crate) struct CaptureMetadata {
    descriptor: SourceDescriptor,
    components: Vec<RecoveryProvenance>,
}
impl CaptureMetadata {
    pub(crate) fn descriptor(&self) -> &SourceDescriptor {
        &self.descriptor
    }
    pub(crate) fn components(&self) -> &[RecoveryProvenance] {
        &self.components
    }
}
pub(crate) fn capture_metadata(
    directory: &Directory,
    secrets: &Secrets,
) -> Result<CaptureMetadata> {
    let history = open_committed_history(directory, secrets)?;
    let mut attachments = if directory
        .path(crate::financial_inventory::FILE)?
        .try_exists()?
    {
        crate::financial_inventory::read(directory, secrets)?
    } else {
        Vec::new()
    };
    attachments.sort_by(|a, b| a.directory.cmp(&b.directory));
    Ok(CaptureMetadata {
        descriptor: SourceDescriptor {
            version: 1,
            profile_id: history.profile_id().into(),
            generation_id: history.generation_id().into(),
            plan_digest: hex::encode(secrets.generation_plan_digest().ok_or(Error::Quarantined)?),
            plan_version: 1,
            attachments,
        },
        components: history
            .components()
            .iter()
            .map(|source| source.provenance().clone())
            .collect(),
    })
}

/// Read only an anchored version discriminator. A recognized number is not
/// validation; callers must invoke that version's complete committed reader.
pub(crate) fn source_plan_version(directory: &Directory, secrets: &Secrets) -> Result<u16> {
    secrets.require_portable_legacy()?;
    directory.refuse_private_workspace_files()?;
    let plain = unseal(secrets, b"plan", &directory.read(PLAN, MAX_DOCUMENT)?)?;
    if secrets.generation_plan_digest() != Some(Sha256::digest(&plain).as_slice()) {
        return Err(Error::Authentication);
    }
    let value: serde_json::Value = serde_json::from_slice(&plain)?;
    let version = value
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .ok_or(Error::Invalid)?;
    match version {
        1 => Ok(1),
        2 => Ok(2),
        _ => Err(Error::Unsupported),
    }
}

fn checked_layered_directory(
    directory: &Directory,
    secrets: &Secrets,
) -> Result<super::layered_metadata::CheckedLayeredMetadata> {
    directory.check()?;
    secrets.require_portable_legacy()?;
    check_layered_directory_inventory(directory)?;
    super::layered_metadata::checked_layered_metadata_bytes(
        directory
            .path("profile.vault")?
            .parent()
            .ok_or(Error::Invalid)?,
        secrets,
        &directory.read(PLAN, MAX_DOCUMENT)?,
        &directory.read(MANIFEST, MAX_DOCUMENT)?,
        &directory.read(COMMIT, MAX_DOCUMENT)?,
        &directory.read("generation.keys", MAX_DOCUMENT)?,
    )
}
fn check_layered_directory_inventory(directory: &Directory) -> Result<()> {
    directory.inventory_of(
        &[
            "coordination.sqlite",
            "inbox.sqlite",
            "outbox.sqlite",
            "submission.sqlite",
            "history.capsule.sqlite",
        ],
        &[
            "profile.lock",
            "profile.vault",
            PLAN,
            MANIFEST,
            COMMIT,
            "generation.keys",
            "financial.attached",
            "financial.inventory",
        ],
    )
}

/// Open the exact saved parent capsule under the source's sealed archive key.
/// This reads encrypted private snapshots only; it never reopens old paths or
/// produces a mutable Store. The caller retains the source Directory lock.
pub(crate) fn open_layered_parent(
    directory: &Directory,
    secrets: &Secrets,
) -> Result<(
    super::layered_metadata::CheckedLayeredMetadata,
    VerifiedGenerationCapsule,
)> {
    let metadata = checked_layered_directory(directory, secrets)?;
    open_layered_parent_checked_metadata(directory, metadata)
}
fn open_layered_parent_checked_metadata(
    directory: &Directory,
    metadata: super::layered_metadata::CheckedLayeredMetadata,
) -> Result<(
    super::layered_metadata::CheckedLayeredMetadata,
    VerifiedGenerationCapsule,
)> {
    let key = wholepact_storage_security::DatabaseKey::from_bytes(
        metadata
            .parent_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::Invalid)?,
    );
    let archive = archive_result(wholepact_storage_security::generation_archive::inspect(
        &directory.path("history.capsule.sqlite")?,
        &key,
    ))?;
    let parent = VerifiedGenerationCapsule::open(archive)?;
    metadata.plan.verify_parent(&parent)?;
    directory.check()?;
    Ok((metadata, parent))
}

#[cfg(all(
    feature = "durable-proposal",
    feature = "manual-admission",
    target_os = "linux"
))]
fn workspace_metadata(
    directory: &Directory,
    secrets: &Secrets,
) -> Result<super::layered_metadata::CheckedLayeredMetadata> {
    super::layered_metadata::checked_layered_metadata_bytes(
        directory
            .path("profile.vault")?
            .parent()
            .ok_or(Error::Invalid)?,
        secrets,
        &directory.read(PLAN, MAX_DOCUMENT)?,
        &directory.read(MANIFEST, MAX_DOCUMENT)?,
        &directory.read(COMMIT, MAX_DOCUMENT)?,
        &directory.read("generation.keys", MAX_DOCUMENT)?,
    )
}
#[cfg(all(
    feature = "durable-proposal",
    feature = "manual-admission",
    target_os = "linux"
))]
pub(crate) fn open_layered_parent_for_private_workspace_v1(
    directory: &Directory,
    secrets: &Secrets,
    files: &crate::host::durable_private_workspace_v1::OriginalWorkspaceFilesV1,
) -> Result<(
    super::layered_metadata::CheckedLayeredMetadata,
    VerifiedGenerationCapsule,
)> {
    files.check_inventory(directory, secrets)?;
    let result =
        open_layered_parent_checked_metadata(directory, workspace_metadata(directory, secrets)?)?;
    files.check_inventory(directory, secrets)?;
    Ok(result)
}
#[cfg(all(
    feature = "durable-proposal",
    feature = "manual-admission",
    target_os = "linux"
))]
pub(crate) fn open_layered_parent_for_workspace_publication_v1(
    directory: &Directory,
    secrets: &Secrets,
    files: &crate::host::durable_private_workspace_v1::OriginalWorkspacePublicationV1,
) -> Result<(
    super::layered_metadata::CheckedLayeredMetadata,
    VerifiedGenerationCapsule,
)> {
    files.check_inventory(directory, secrets)?;
    let result =
        open_layered_parent_checked_metadata(directory, workspace_metadata(directory, secrets)?)?;
    files.check_inventory(directory, secrets)?;
    Ok(result)
}

#[cfg(all(feature = "durable-proposal", feature = "manual-admission", target_os = "linux"))]
pub(crate) fn open_layered_parent_for_workspace_dispatcher_v4(directory: &Directory, secrets: &Secrets, files: &crate::host::durable_dispatcher_v2::OriginalWorkspaceDispatcherFilesV4) -> Result<(super::layered_metadata::CheckedLayeredMetadata, VerifiedGenerationCapsule)> {
    files.check_inventory(directory, secrets)?;
    let submission = files.submission_preflight(directory, secrets)?;
    let result = open_layered_parent_checked_metadata(directory, workspace_metadata(directory, secrets)?)?;
    submission.check()?;
    files.check_inventory(directory, secrets)?;
    Ok(result)
}
#[cfg(all(feature = "durable-proposal", feature = "manual-admission", target_os = "linux"))]
pub(crate) fn open_layered_parent_for_dispatcher_publication_v4(directory: &Directory, secrets: &Secrets, files: &crate::host::durable_dispatcher_v2::OriginalWorkspaceDispatcherPublicationV4) -> Result<(super::layered_metadata::CheckedLayeredMetadata, VerifiedGenerationCapsule)> {
    files.check_inventory(directory, secrets)?;
    let submission = files.submission_preflight(directory, secrets)?;
    let result = open_layered_parent_checked_metadata(directory, workspace_metadata(directory, secrets)?)?;
    submission.check()?;
    files.check_inventory(directory, secrets)?;
    Ok(result)
}
pub(crate) fn capture_layered_metadata(
    directory: &Directory,
    secrets: &Secrets,
    parent: &VerifiedGenerationCapsule,
) -> Result<CaptureMetadata> {
    let metadata = checked_layered_directory(directory, secrets)?;
    metadata.plan.verify_parent(parent)?;
    let expected = metadata
        .plan
        .components
        .iter()
        .find(|component| component.component_id == "root-coordination")
        .ok_or(Error::Authentication)?;
    let store = wholepact_store::recovery::RecoveredStoreSnapshot::open(
        &directory.path(crate::vault::JOURNALS[0])?,
        &secrets.key(0)?,
        &metadata.binding,
        expected,
    )?;
    store.verify_recovery_obligation_fences(&metadata.restrictions)?;
    if store.layer_depth()? != parent.histories().len() + 1 {
        return Err(Error::Authentication);
    }
    for (index, kind) in [
        (1, JournalKind::TransportInbox),
        (2, JournalKind::TransportOutbox),
        (3, JournalKind::Submission),
    ] {
        drop(
            wholepact_storage_security::bundle::open_journal_read_snapshot(
                &directory.path(crate::vault::JOURNALS[index])?,
                &secrets.key(index)?,
                template(kind)?,
            )?,
        );
    }
    let attached = directory.path("financial.attached")?.try_exists()?;
    if attached
        != directory
            .path(crate::financial_inventory::FILE)?
            .try_exists()?
    {
        return Err(Error::Authentication);
    }
    let mut attachments = if attached {
        if directory.read("financial.attached", 1024)?
            != b"wholepact-financial-profile-attached-v1\n"
        {
            return Err(Error::Authentication);
        }
        crate::financial_inventory::read(directory, secrets)?
    } else {
        Vec::new()
    };
    attachments.sort_by(|a, b| a.directory.cmp(&b.directory));
    check_layered_directory_inventory(directory)?;
    Ok(CaptureMetadata {
        descriptor: SourceDescriptor {
            version: 1,
            profile_id: metadata.plan.successor_profile,
            generation_id: metadata.plan.generation_id,
            plan_digest: hex::encode(secrets.generation_plan_digest().ok_or(Error::Quarantined)?),
            plan_version: 2,
            attachments,
        },
        components: Vec::new(),
    })
}

/// No public constructor, cloning, deserialization, mutable Store or source key
/// getters. Every original node must pass this owner boundary independently.
pub(crate) struct ArchivedCommittedHistory {
    descriptor: SourceDescriptor,
    generation_id: String,
    profile_id: String,
    manifest_digest: String,
    components: Vec<RecoveredEvidence>,
    current_coordination: ArchivedGenerationSource,
    current_journals: Vec<ArchivedOrdinarySource>,
    current_semantics: crate::recovery_semantics::SemanticInventory,
}
impl ArchivedCommittedHistory {
    pub(crate) fn descriptor(&self) -> &SourceDescriptor {
        &self.descriptor
    }
    pub(crate) fn generation_id(&self) -> &str {
        &self.generation_id
    }
    pub(crate) fn profile_id(&self) -> &str {
        &self.profile_id
    }
    pub(crate) fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }
    pub(crate) fn components(&self) -> &[RecoveredEvidence] {
        &self.components
    }
    pub(crate) fn current_coordination(&self) -> &ArchivedGenerationSource {
        &self.current_coordination
    }
    pub(crate) fn current_journals(&self) -> &[ArchivedOrdinarySource] {
        &self.current_journals
    }
    pub(crate) fn current_semantics(&self) -> &crate::recovery_semantics::SemanticInventory {
        &self.current_semantics
    }
    pub(crate) fn current_provenance(&self) -> Vec<RecoveryProvenance> {
        let mut result = vec![self.current_coordination.source_provenance().clone()];
        result.extend(
            self.current_journals
                .iter()
                .map(|source| source.provenance().clone()),
        );
        result.sort_by(|a, b| a.component_id.cmp(&b.component_id));
        result
    }
}

/// Integrity/semantic capability only. It does not turn any archived key,
/// admission, queue, observation or original consent into current authority.
pub(crate) struct VerifiedGenerationCapsule {
    archive: VerifiedArchive,
    histories: BTreeMap<String, ArchivedCommittedHistory>,
}
impl VerifiedGenerationCapsule {
    pub(crate) fn open(archive: VerifiedArchive) -> Result<Self> {
        let nodes = archive
            .manifests()
            .keys()
            .map(|digest| archive_result(archive.node(digest)))
            .collect::<Result<Vec<_>>>()?;
        check_native_identities(nodes)?;
        let mut histories = BTreeMap::new();
        let mut visiting = BTreeSet::new();
        open_graph_node(
            &archive,
            archive.manifest_digest(),
            &mut histories,
            &mut visiting,
        )?;
        if histories.len() != archive.manifests().len() {
            return Err(Error::Authentication);
        }
        Ok(Self { archive, histories })
    }
    pub(crate) fn archive(&self) -> &VerifiedArchive {
        &self.archive
    }
    pub(crate) fn manifest_digest(&self) -> &str {
        self.archive.manifest_digest()
    }
    pub(crate) fn capsule_id(&self) -> &str {
        &self.archive.manifest().capsule_id
    }
    pub(crate) fn root(&self) -> &ArchivedCommittedHistory {
        &self.histories[self.archive.manifest_digest()]
    }
    pub(crate) fn histories(&self) -> &BTreeMap<String, ArchivedCommittedHistory> {
        &self.histories
    }

    /// Complete historical union only. Missing older identity provenance stays
    /// unknown; the result never supplies a current native or financial permit.
    pub(crate) fn inherited_manual_identity_coverage(
        &self,
    ) -> Result<super::inherited_manual_identity::InheritedManualIdentityCoverage> {
        let mut coverage = super::inherited_manual_identity::InheritedManualIdentityCoverage::empty_for_verified_capsule(self.manifest_digest())?;
        for (digest, history) in &self.histories {
            let secrets = crate::vault::generation_archive::source_from_material(
                read(&self.archive, digest, "host-source-material", 1024)?,
                &history.descriptor.profile_id,
                &history.descriptor.plan_digest,
            )?;
            let plain = unseal(
                &secrets,
                b"manifest",
                &read(&self.archive, digest, "host-manifest", MAX_DOCUMENT)?,
            )?;
            let rows = super::complete_origins::checked_manual_identity_rows(&plain)?;
            let current = wholepact_store::recovery::RecoveredStoreSnapshot::archived_manual_audit_projection(&history.current_coordination)?;
            coverage.include_checked_node(
                &history.generation_id,
                &history.manifest_digest,
                history.current_semantics.accounts(),
                rows.as_ref(),
                &current,
            )?;
        }
        Ok(coverage)
    }
}

fn check_native_identities<'a>(nodes: impl IntoIterator<Item = &'a Node>) -> Result<()> {
    let mut generations = BTreeSet::new();
    let mut profiles = BTreeSet::new();
    for node in nodes {
        if !generations.insert(&node.generation_id) || !profiles.insert(&node.profile_id) {
            return Err(Error::Authentication);
        }
    }
    Ok(())
}

fn archive_result<T>(
    result: std::result::Result<T, wholepact_storage_security::generation_archive::ArchiveError>,
) -> Result<T> {
    result.map_err(|_| Error::Authentication)
}
fn read(
    archive: &VerifiedArchive,
    digest: &str,
    id: &str,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    archive_result(archive.read_private_entry(digest, id, limit))
}
#[derive(Clone, Copy)]
enum EntryKind {
    File,
    Secret,
    Journal,
}
fn expected_entry(
    node: &Node,
    expected: &mut BTreeSet<String>,
    id: &str,
    role: &str,
    kind: EntryKind,
    origin: Option<&Path>,
) -> Result<()> {
    let entry = node.entries.get(id).ok_or(Error::Authentication)?;
    let origin = origin
        .map(|path| path.to_str().ok_or(Error::Invalid))
        .transpose()?;
    if !expected.insert(id.into())
        || entry.role != role
        || entry.origin.as_deref() != origin
        || !matches!(
            (kind, &entry.payload),
            (EntryKind::File, EntryPayload::File { .. })
                | (EntryKind::Secret, EntryPayload::Secret { .. })
                | (EntryKind::Journal, EntryPayload::Journal { .. })
        )
    {
        return Err(Error::Authentication);
    }
    Ok(())
}
fn inherited_role(kind: JournalKind) -> Result<&'static str> {
    Ok(match kind {
        JournalKind::CoordinationAuthority => "inherited-coordination",
        JournalKind::TransportInbox => "inherited-inbox",
        JournalKind::TransportOutbox => "inherited-outbox",
        JournalKind::Submission => "inherited-submission",
        JournalKind::WalletScan => "inherited-wallet",
        JournalKind::ProofWitness => "inherited-proof",
        JournalKind::SignedResults => "inherited-signed",
        JournalKind::ExactTransactions => "inherited-transactions",
        _ => return Err(Error::Unsupported),
    })
}
pub(super) fn template(kind: JournalKind) -> Result<&'static JournalTemplate> {
    Ok(match kind {
        // Coordination has multiple supported historical encodings. Callers
        // must supply authenticated provenance to template_for_provenance.
        JournalKind::CoordinationAuthority => return Err(Error::Unsupported),
        JournalKind::TransportInbox => &wholepact_transport::bundle::INBOX_BACKUP_TEMPLATE,
        JournalKind::TransportOutbox => &wholepact_transport::bundle::OUTBOX_BACKUP_TEMPLATE,
        JournalKind::Submission => &wholepact_chain::backup::TEMPLATE,
        // Kind/version labels cannot choose between legacy and recorded-import
        // layouts. Every actual wallet reader uses its exact-source wrapper.
        JournalKind::WalletScan => return Err(Error::Unsupported),
        JournalKind::ProofWitness => &wholepact_proof_jobs::backup::TEMPLATE,
        JournalKind::SignedResults => {
            &wholepact_protocol::authorization::retention::backup::TEMPLATE
        }
        JournalKind::ExactTransactions => {
            &wholepact_protocol::authorization::retention::transaction::backup::TEMPLATE
        }
        _ => return Err(Error::Unsupported),
    })
}
pub(super) fn template_for_provenance(
    provenance: &RecoveryProvenance,
) -> Result<&'static JournalTemplate> {
    let selected = if provenance.kind == JournalKind::CoordinationAuthority {
        wholepact_store::bundle::coordination_template_for_schema(provenance.schema_version)?
    } else {
        template(provenance.kind)?
    };
    if selected.application_id != provenance.application_id
        || selected.schema_version != provenance.schema_version
    {
        return Err(Error::Authentication);
    }
    Ok(selected)
}

/// The destination marker carries its own schema independently of its original
/// source provenance. Authenticate that exact marker against the bounded legacy
/// and current template set; never infer or upgrade it from a source version.
pub(super) fn open_archived_coordination_generation(
    source: &ArchivedJournal<'_>,
    key: &wholepact_storage_security::DatabaseKey,
    binding: &wholepact_storage_security::bundle::recovery::generation::GenerationBinding,
    expected: &RecoveryProvenance,
    layered: bool,
) -> Result<ArchivedGenerationSource> {
    for version in coordination_generation_versions(layered) {
        let template = if layered {
            wholepact_store::recovery::coordination_layered_successor_template_for_schema(version)?
        } else {
            wholepact_store::recovery::coordination_successor_template_for_schema(version)?
        };
        if let Ok(history) = source.open_generation(key, binding, expected, template) {
            wholepact_store::recovery::RecoveredStoreSnapshot::validate_archived_source(&history)?;
            return Ok(history);
        }
    }
    Err(Error::Authentication)
}

fn check_role_matrix(
    node: &Node,
    descriptor: &SourceDescriptor,
    inherited: &[RecoveryProvenance],
) -> Result<()> {
    let root = Path::new(&node.original_root);
    crate::files::validate_absolute(root)?;
    let mut expected = BTreeSet::new();
    for id in ["host-source-descriptor", "host-source-material"] {
        expected_entry(node, &mut expected, id, id, EntryKind::Secret, None)?;
    }
    for (id, name) in [
        ("host-vault", "profile.vault"),
        ("host-plan", PLAN),
        ("host-manifest", MANIFEST),
        ("host-commit", COMMIT),
        ("host-evidence-keys", "generation.keys"),
    ] {
        expected_entry(
            node,
            &mut expected,
            id,
            id,
            EntryKind::File,
            Some(&root.join(name)),
        )?;
    }
    for (id, role, name) in [
        (
            "root-coordination",
            "current-coordination",
            "coordination.sqlite",
        ),
        ("root-inbox", "current-inbox", "inbox.sqlite"),
        ("root-outbox", "current-outbox", "outbox.sqlite"),
        ("root-submission", "current-submission", "submission.sqlite"),
    ] {
        expected_entry(
            node,
            &mut expected,
            id,
            role,
            EntryKind::Journal,
            Some(&root.join(name)),
        )?;
    }
    for component in inherited {
        expected_entry(
            node,
            &mut expected,
            &format!("history-{}", component.component_id),
            inherited_role(component.kind)?,
            EntryKind::Journal,
            Some(&root.join(format!("history-{}.sqlite", component.component_id))),
        )?;
    }
    if !descriptor.attachments.is_empty() {
        for (id, name) in [
            ("host-financial-marker", "financial.attached"),
            ("host-financial-registry", crate::financial_inventory::FILE),
        ] {
            expected_entry(
                node,
                &mut expected,
                id,
                id,
                EntryKind::File,
                Some(&root.join(name)),
            )?;
        }
    }
    let mut previous = None;
    for (index, attachment) in descriptor.attachments.iter().enumerate() {
        crate::files::validate_absolute(&attachment.directory)?;
        if attachment.directory.starts_with(root)
            || previous.is_some_and(|path| path >= &attachment.directory)
        {
            return Err(Error::Authentication);
        }
        previous = Some(&attachment.directory);
        expected_entry(
            node,
            &mut expected,
            &format!("financial-{index}-vault"),
            "financial-vault",
            EntryKind::File,
            Some(&attachment.directory.join("financial.vault")),
        )?;
        expected_entry(
            node,
            &mut expected,
            &format!("financial-{index}-source-material"),
            "financial-source-material",
            EntryKind::Secret,
            None,
        )?;
        for suffix in ["wallet", "proof", "signed", "transactions"] {
            expected_entry(
                node,
                &mut expected,
                &format!("financial-{index}-{suffix}"),
                &format!("financial-{suffix}"),
                EntryKind::Journal,
                Some(&attachment.directory.join(format!("{suffix}.sqlite"))),
            )?;
        }
    }
    if node.entries.keys().cloned().collect::<BTreeSet<_>>() != expected {
        return Err(Error::Authentication);
    }
    Ok(())
}

fn read_descriptor(archive: &VerifiedArchive, digest: &str) -> Result<SourceDescriptor> {
    let node = archive_result(archive.node(digest))?;
    let encoded = read(archive, digest, "host-source-descriptor", 65536)?;
    let descriptor: SourceDescriptor = serde_json::from_slice(&encoded)?;
    if descriptor.version != 1 || ![1, 2].contains(&descriptor.plan_version) {
        return Err(Error::RecoverySemantic(
            "Unsupported archived native generation plan version".into(),
        ));
    }
    if descriptor.profile_id != node.profile_id
        || descriptor.generation_id != node.generation_id
        || descriptor.attachments.len() > 12
        || serde_json::to_vec(&descriptor)? != *encoded
    {
        return Err(Error::Authentication);
    }
    canonical_hash(&descriptor.generation_id)?;
    canonical_hash(&descriptor.plan_digest)?;
    crate::id(&descriptor.profile_id)?;
    Ok(descriptor)
}

fn open_current_journals(
    archive: &VerifiedArchive,
    digest: &str,
    descriptor: &SourceDescriptor,
    secrets: &Secrets,
) -> Result<Vec<ArchivedOrdinarySource>> {
    // Preserved ciphertext is audit data; all useful source keys are separately
    // authenticated by material, permanent plan anchor and exact journal opens.
    if read(archive, digest, "host-vault", 1024)?.is_empty() {
        return Err(Error::Authentication);
    }
    let attachments = if descriptor.attachments.is_empty() {
        Vec::new()
    } else {
        if read(archive, digest, "host-financial-marker", 1024)?.as_slice()
            != b"wholepact-financial-profile-attached-v1\n"
        {
            return Err(Error::Authentication);
        }
        let mut entries = crate::financial_inventory::read_bytes(
            &read(archive, digest, "host-financial-registry", 65536)?,
            secrets,
        )?;
        entries.sort_by(|a, b| a.directory.cmp(&b.directory));
        entries
    };
    if attachments != descriptor.attachments {
        return Err(Error::Authentication);
    }
    let mut current_journals = Vec::new();
    for (index, id, kind) in [
        (1, "root-inbox", JournalKind::TransportInbox),
        (2, "root-outbox", JournalKind::TransportOutbox),
        (3, "root-submission", JournalKind::Submission),
    ] {
        current_journals.push(archive_result(
            archive_result(archive.journal(digest, id))?
                .inspect_ordinary(&secrets.key(index)?, template(kind)?),
        )?);
    }
    for (index, _) in attachments.iter().enumerate() {
        if read(archive, digest, &format!("financial-{index}-vault"), 1024)?.is_empty() {
            return Err(Error::Authentication);
        }
        let financial = crate::vault::generation_archive::financial_from_material(
            read(
                archive,
                digest,
                &format!("financial-{index}-source-material"),
                1024,
            )?,
            &descriptor.profile_id,
        )?;
        for (number, suffix, kind) in [
            (0, "wallet", JournalKind::WalletScan),
            (1, "proof", JournalKind::ProofWitness),
            (2, "signed", JournalKind::SignedResults),
            (3, "transactions", JournalKind::ExactTransactions),
        ] {
            let source =
                archive_result(archive.journal(digest, &format!("financial-{index}-{suffix}")))?;
            let key = financial.key(number)?;
            current_journals.push(archive_result(if kind == JournalKind::WalletScan {
                wholepact_wallet::bundle::recovery::inspect_archived_wallet_scan_history(
                    &source, &key,
                )
            } else {
                source.inspect_ordinary(&key, template(kind)?)
            })?);
        }
    }
    Ok(current_journals)
}

fn open_v1_node(archive: &VerifiedArchive, digest: &str) -> Result<ArchivedCommittedHistory> {
    let node = archive_result(archive.node(digest))?;
    let descriptor = read_descriptor(archive, digest)?;
    if descriptor.plan_version != 1
        || !archive_result(archive.manifest_by_digest(digest))?
            .parent_manifest_digests
            .is_empty()
    {
        return Err(Error::Authentication);
    }
    let secrets = crate::vault::generation_archive::source_from_material(
        read(archive, digest, "host-source-material", 1024)?,
        &descriptor.profile_id,
        &descriptor.plan_digest,
    )?;
    let commit = unseal(
        &secrets,
        b"commit",
        &read(archive, digest, "host-commit", MAX_DOCUMENT)?,
    )?;
    let metadata = complete_origins::checked_metadata_bytes_dispatch(
        Path::new(&node.original_root),
        &secrets,
        &commit,
        &read(archive, digest, "host-plan", MAX_DOCUMENT)?,
        &read(archive, digest, "host-manifest", MAX_DOCUMENT)?,
        &read(archive, digest, "host-evidence-keys", MAX_DOCUMENT)?,
    )?;
    if metadata.plan.generation_id != descriptor.generation_id
        || metadata.plan.version != descriptor.plan_version
    {
        return Err(Error::Authentication);
    }
    check_role_matrix(node, &descriptor, &metadata.plan.components)?;
    let mut components = Vec::with_capacity(metadata.plan.components.len());
    for (index, component) in metadata.plan.components.iter().enumerate() {
        let key = wholepact_storage_security::DatabaseKey::from_bytes(
            metadata.evidence_keys[index * 32..(index + 1) * 32]
                .try_into()
                .map_err(|_| Error::Invalid)?,
        );
        let source = archive_result(
            archive.journal(digest, &format!("history-{}", component.component_id)),
        )?;
        components.push(archive_result(
            if component.kind == JournalKind::WalletScan {
                wholepact_wallet::bundle::recovery::open_archived_wallet_scan_successor_evidence(
                    &source,
                    &key,
                    &metadata.binding,
                    component,
                )
            } else {
                source.open_evidence(
                    &key,
                    &metadata.binding,
                    component,
                    template_for_provenance(component)?,
                )
            },
        )?);
    }
    let inherited = crate::recovery_semantics::inspect_successor(
        &components,
        &metadata.plan.affected_accounts,
    )?;
    if inherited.digest() != metadata.plan.semantic_inventory_digest
        || inherited.accounts() != &metadata.plan.affected_accounts
    {
        return Err(Error::Authentication);
    }
    let coordination = metadata
        .plan
        .components
        .iter()
        .find(|component| component.component_id == "coordination")
        .ok_or(Error::Authentication)?;
    let current_coordination = open_archived_coordination_generation(
        &archive_result(archive.journal(digest, "root-coordination"))?,
        &secrets.key(0)?,
        &metadata.binding,
        coordination,
        false,
    )?;
    wholepact_store::recovery::verify_archived_generation_obligation_fences(
        &current_coordination,
        &metadata.restrictions,
    )?;
    let construction_inventory =
        wholepact_engine::recovery::inspect_archived_coordination_recovery(&current_coordination)?;
    super::complete_origins::validate_store_manifest_dispatch(
        &unseal(
            &secrets,
            b"manifest",
            &read(archive, digest, "host-manifest", MAX_DOCUMENT)?,
        )?,
        construction_inventory.store_inventory(),
    )?;
    let current_journals = open_current_journals(archive, digest, &descriptor, &secrets)?;
    let mut known = metadata.plan.affected_accounts.clone();
    known.extend(
        descriptor
            .attachments
            .iter()
            .filter_map(|attachment| attachment.account.clone()),
    );
    let current_semantics = crate::recovery_semantics::inspect_archived_current(
        &current_coordination,
        &current_journals,
        &components.iter().collect::<Vec<_>>(),
        &[],
        &known,
    )?;
    Ok(ArchivedCommittedHistory {
        descriptor,
        generation_id: metadata.plan.generation_id,
        profile_id: metadata.plan.successor_profile,
        manifest_digest: metadata.manifest_digest,
        components,
        current_coordination,
        current_journals,
        current_semantics,
    })
}

fn open_graph_node(
    archive: &VerifiedArchive,
    digest: &str,
    histories: &mut BTreeMap<String, ArchivedCommittedHistory>,
    visiting: &mut BTreeSet<String>,
) -> Result<()> {
    if histories.contains_key(digest) {
        return Ok(());
    }
    if visiting.len() >= 16 || !visiting.insert(digest.into()) {
        return Err(Error::Authentication);
    }
    let manifest = archive_result(archive.manifest_by_digest(digest))?;
    if manifest.parent_manifest_digests.len() > 1 {
        return Err(Error::Authentication);
    }
    for parent in &manifest.parent_manifest_digests {
        open_graph_node(archive, parent, histories, visiting)?;
    }
    let descriptor = read_descriptor(archive, digest)?;
    let history = match descriptor.plan_version {
        1 => open_v1_node(archive, digest)?,
        2 => open_v2_node(archive, digest, histories)?,
        _ => return Err(Error::Unsupported),
    };
    visiting.remove(digest);
    histories.insert(digest.into(), history);
    Ok(())
}

fn open_v2_node(
    archive: &VerifiedArchive,
    digest: &str,
    ancestors: &BTreeMap<String, ArchivedCommittedHistory>,
) -> Result<ArchivedCommittedHistory> {
    let node = archive_result(archive.node(digest))?;
    let descriptor = read_descriptor(archive, digest)?;
    if descriptor.plan_version != 2 {
        return Err(Error::Authentication);
    }
    let secrets = crate::vault::generation_archive::source_from_material(
        read(archive, digest, "host-source-material", 1024)?,
        &descriptor.profile_id,
        &descriptor.plan_digest,
    )?;
    let metadata = super::layered_metadata::checked_layered_metadata_bytes(
        Path::new(&node.original_root),
        &secrets,
        &read(archive, digest, "host-plan", MAX_DOCUMENT)?,
        &read(archive, digest, "host-manifest", MAX_DOCUMENT)?,
        &read(archive, digest, "host-commit", MAX_DOCUMENT)?,
        &read(archive, digest, "host-evidence-keys", MAX_DOCUMENT)?,
    )?;
    let plan = &metadata.plan;
    let manifest = archive_result(archive.manifest_by_digest(digest))?;
    if plan.generation_id != descriptor.generation_id
        || plan.successor_profile != descriptor.profile_id
        || manifest.parent_manifest_digests != [plan.parent_manifest_digest.clone()]
    {
        return Err(Error::Authentication);
    }
    let parent = ancestors
        .get(&plan.parent_manifest_digest)
        .ok_or(Error::Authentication)?;
    let parent_manifest = archive_result(archive.manifest_by_digest(&plan.parent_manifest_digest))?;
    plan.verify_parent_history(parent_manifest, parent)?;
    check_role_matrix(node, &descriptor, &[])?;
    let expected = plan
        .components
        .iter()
        .find(|source| source.component_id == "root-coordination")
        .ok_or(Error::Authentication)?;
    let current_coordination = open_archived_coordination_generation(
        &archive_result(archive.journal(digest, "root-coordination"))?,
        &secrets.key(0)?,
        &metadata.binding,
        expected,
        true,
    )?;
    wholepact_store::recovery::verify_archived_generation_obligation_fences(
        &current_coordination,
        &metadata.restrictions,
    )?;
    let construction_inventory =
        wholepact_engine::recovery::inspect_archived_coordination_recovery(&current_coordination)?;
    super::complete_origins::validate_store_manifest_dispatch(
        &unseal(
            &secrets,
            b"manifest",
            &read(archive, digest, "host-manifest", MAX_DOCUMENT)?,
        )?,
        construction_inventory.store_inventory(),
    )?;
    let current_journals = open_current_journals(archive, digest, &descriptor, &secrets)?;
    let mut known = plan.affected_accounts.clone();
    known.extend(
        descriptor
            .attachments
            .iter()
            .filter_map(|attachment| attachment.account.clone()),
    );
    let inherited = ancestors
        .values()
        .flat_map(|history| history.components.iter())
        .collect::<Vec<_>>();
    let previous = ancestors
        .values()
        .flat_map(|history| history.current_journals.iter())
        .collect::<Vec<_>>();
    let current_semantics = crate::recovery_semantics::inspect_archived_current(
        &current_coordination,
        &current_journals,
        &inherited,
        &previous,
        &known,
    )?;
    Ok(ArchivedCommittedHistory {
        descriptor,
        generation_id: metadata.plan.generation_id,
        profile_id: metadata.plan.successor_profile,
        manifest_digest: metadata.manifest_digest,
        components: Vec::new(),
        current_coordination,
        current_journals,
        current_semantics,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wholepact_storage_security::generation_archive::{Entry, ObjectRef};

    fn fixture() -> (Node, SourceDescriptor, Plan) {
        let root = Path::new("/synthetic-absent-archive-source/profile");
        let components = [
            ("coordination", JournalKind::CoordinationAuthority),
            ("inbox", JournalKind::TransportInbox),
            ("outbox", JournalKind::TransportOutbox),
            ("submission", JournalKind::Submission),
        ]
        .into_iter()
        .map(|(id, kind)| RecoveryProvenance {
            profile_id: "synthetic-original".into(),
            checkpoint_id: "synthetic-checkpoint".into(),
            bundle_digest: "a".repeat(64),
            component_id: id.into(),
            kind,
            component_digest: "b".repeat(64),
            application_id: 0,
            schema_version: 1,
            rows: 0,
        })
        .collect::<Vec<_>>();
        let plan = Plan {
            version: 1,
            generation_id: "c".repeat(64),
            inventory_digest: "d".repeat(64),
            target: root.into(),
            source_profile: "synthetic-original".into(),
            successor_profile: "synthetic-successor".into(),
            components,
            affected_accounts: BTreeSet::new(),
            semantic_inventory_digest: "e".repeat(64),
            unknown_external_signatures: true,
            recovered_obligations_fenced: true,
        };
        let descriptor = SourceDescriptor {
            version: 1,
            profile_id: plan.successor_profile.clone(),
            generation_id: plan.generation_id.clone(),
            plan_digest: "f".repeat(64),
            plan_version: 1,
            attachments: vec![],
        };
        let mut node = Node {
            generation_id: descriptor.generation_id.clone(),
            profile_id: descriptor.profile_id.clone(),
            original_root: root.to_str().unwrap().into(),
            entries: BTreeMap::new(),
        };
        let object = ObjectRef {
            digest: "1".repeat(64),
            length: 1,
        };
        for id in ["host-source-descriptor", "host-source-material"] {
            node.entries.insert(
                id.into(),
                Entry {
                    role: id.into(),
                    origin: None,
                    payload: EntryPayload::Secret {
                        object: object.clone(),
                    },
                },
            );
        }
        for (id, name) in [
            ("host-vault", "profile.vault"),
            ("host-plan", PLAN),
            ("host-manifest", MANIFEST),
            ("host-commit", COMMIT),
            ("host-evidence-keys", "generation.keys"),
        ] {
            node.entries.insert(
                id.into(),
                Entry {
                    role: id.into(),
                    origin: Some(root.join(name).to_str().unwrap().into()),
                    payload: EntryPayload::File {
                        object: object.clone(),
                    },
                },
            );
        }
        for component in &plan.components {
            for (id, role, name) in [
                (
                    format!("root-{}", component.component_id),
                    format!("current-{}", component.component_id),
                    format!("{}.sqlite", component.component_id),
                ),
                (
                    format!("history-{}", component.component_id),
                    inherited_role(component.kind).unwrap().into(),
                    format!("history-{}.sqlite", component.component_id),
                ),
            ] {
                node.entries.insert(
                    id,
                    Entry {
                        role,
                        origin: Some(root.join(name).to_str().unwrap().into()),
                        payload: EntryPayload::Journal {
                            files: BTreeMap::from([("".into(), object.clone())]),
                        },
                    },
                );
            }
        }
        (node, descriptor, plan)
    }

    #[test]
    fn native_chain_rejects_nonadjacent_repeated_generation_or_profile() {
        let (first, _, _) = fixture();
        let mut second = first.clone();
        second.generation_id = "d".repeat(64);
        second.profile_id = "synthetic-second-profile".into();
        let mut third = first.clone();
        third.generation_id = "e".repeat(64);
        third.profile_id = "synthetic-third-profile".into();
        check_native_identities([&first, &second, &third]).unwrap();
        third.generation_id = first.generation_id.clone();
        assert!(check_native_identities([&first, &second, &third]).is_err());
        third.generation_id = "e".repeat(64);
        third.profile_id = first.profile_id.clone();
        assert!(check_native_identities([&first, &second, &third]).is_err());
    }

    #[test]
    fn complete_native_matrix_rejects_missing_extra_role_origin_and_payload_rebinding() {
        let (node, descriptor, plan) = fixture();
        // This checks only typed metadata. No original path is opened or needed.
        check_role_matrix(&node, &descriptor, &plan.components).unwrap();
        let mut changed = node.clone();
        changed.entries.remove("root-submission");
        assert!(check_role_matrix(&changed, &descriptor, &plan.components).is_err());
        let mut changed = node.clone();
        changed.entries.insert(
            "unclaimed-private-history".into(),
            node.entries["host-plan"].clone(),
        );
        assert!(check_role_matrix(&changed, &descriptor, &plan.components).is_err());
        let mut changed = node.clone();
        changed.entries.get_mut("history-inbox").unwrap().role = "inherited-outbox".into();
        assert!(check_role_matrix(&changed, &descriptor, &plan.components).is_err());
        let mut changed = node.clone();
        changed.entries.get_mut("root-coordination").unwrap().origin =
            Some("/different-profile/coordination.sqlite".into());
        assert!(check_role_matrix(&changed, &descriptor, &plan.components).is_err());
        let mut changed = node.clone();
        changed
            .entries
            .get_mut("host-source-material")
            .unwrap()
            .payload = node.entries["host-vault"].payload.clone();
        assert!(check_role_matrix(&changed, &descriptor, &plan.components).is_err());
    }
}

// Explicit destination marker encodings, not an inclusive version range.
// Opening each candidate still authenticates the complete source/template and
// typed Store inventory. No legacy source is rewritten or relabeled.
fn coordination_generation_versions(layered: bool) -> [i64; 4] {
    if layered { [3, 5, 7, 9] } else { [2, 4, 6, 8] }
}

#[cfg(test)]
mod historical_provenance_versions {
    #[test]
    fn historical_provenance_archive_encodings_are_explicit_and_family_distinct() {
        assert_eq!(super::coordination_generation_versions(false), [2, 4, 6, 8]);
        assert_eq!(super::coordination_generation_versions(true), [3, 5, 7, 9]);
        for v in super::coordination_generation_versions(false) {
            assert!(!super::coordination_generation_versions(true).contains(&v));
        }
    }
}
