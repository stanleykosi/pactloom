//! Exclusive original workspace storage. Mandatory v3 anchor and retained
//! own-file proofs are separate from current native permission and financial authority.
use super::Host;
// Data-only bridge for the existing original-reader paths. No source owner or
// permission is exposed through this diagnostic surface.
#[allow(unused_imports)]
pub(crate) use super::financial::private_durable_fixed_v2::{
    PrivateDiagnosticOperationV1, PrivateDiagnosticSiteV1, PrivateFixedDiagnosticV1,
    PrivateFixedDiagnosticScopeV1, begin_private_fixed_diagnostic_scope_v1,
    observe_private_fixed_host_v1, observe_private_fixed_job_v1, observe_private_fixed_storage_v1,
    observe_private_fixed_store_v1, observe_private_fixed_engine_v1,
    private_fixed_diagnostic_snapshot_v1, observe_private_fixed_boundary_v1,
    first_private_fixed_boundary_v1,
};
use super::financial::private_durable_fixed_v2::{
    PrivateStageObservationV1, begin_private_stage_cost_v1,
};

// Evaluate the original expression once, borrow only its returned error, and
// return the same owned Result before the original conversion or propagation.
macro_rules! reader_result {
    ($site:ident, $observe:ident, $result:expr) => {{
        let result = $result;
        if let Err(error) = &result {
            $observe(
                PrivateDiagnosticOperationV1::OpenOriginal,
                PrivateDiagnosticSiteV1::$site,
                error,
            );
        }
        result
    }};
}
use crate::{
    Error, Result,
    files::{Directory, PrivateWorkspaceFileV1},
    recovery_generation::manual_target::ManualCommittedTarget,
    terminal::{Terminal, historical::HistoricalApproval},
    vault::Secrets,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};
use wholepact_engine::{
    Access, Engine, LocalPrivateWorkspaceConsentV1, PreparedPrivateDurableCoordinatorV1,
    PrivateDurableCoordinatorV1, PrivateDurableWorkspaceSourceV1, PrivateWorkspaceActionV1,
    PrivateWorkspaceInitializationPlanV1, PrivateWorkspaceScopeV1, PrivateWorkspaceSeedBindingV1,
    PrivateWorkspaceStatusV1,
};
use wholepact_storage_security::DatabaseKey;
use zeroize::{Zeroize, Zeroizing};
const PENDING: &str = crate::files::PRIVATE_PENDING;
const COMMIT: &str = crate::files::PRIVATE_COMMIT;
const DATABASE: &str = "private-coordination.sqlite";
const PURPOSE: &str = "durable-private-coordination-v1";
const MAX_REGISTRY: usize = 131_112;
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Association {
    version: u16,
    purpose: String,
    dependency_id: String,
    profile_id: String,
    generation_id: String,
    inventory_digest: String,
    generation_plan_digest: String,
    parent_coverage_digest: String,
    original_financial_origin_digest: String,
    host_directory_identity: String,
    source_store_destination_identity: String,
    source_digest: String,
    principal_id: String,
    agreement_id: String,
    obligation_id: String,
    reviewer_account_ids: Vec<String>,
    workspace_root: PathBuf,
    database_path: PathBuf,
    retention_policy: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct OriginalProofDescriptorV1 {
    role: String,
    profile_owner: String,
    financial_root: PathBuf,
    financial_directory_identity: String,
    basename: String,
    key_slot: u8,
    original_proof_origin: [u8; 32],
}
impl OriginalProofDescriptorV1 {
    fn from_host(host: &Host) -> Result<Self> {
        let financial = host.financial.as_ref().ok_or(Error::Locked)?;
        Ok(Self {
            role: "original_primary_proof_v1".into(),
            profile_owner: host.secrets.profile(),
            financial_root: financial.current_directory()?,
            financial_directory_identity: financial.directory.manual_target_identity_digest()?,
            basename: "proof.sqlite".into(),
            key_slot: 1,
            original_proof_origin: financial.original_workspace_proof_origin_v1()?,
        })
    }
    fn validate(&self, secrets: &Secrets) -> Result<()> {
        if self.role != "original_primary_proof_v1"
            || self.profile_owner != secrets.profile()
            || self.basename != "proof.sqlite"
            || self.key_slot != 1
        {
            return Err(Error::Authentication);
        }
        bounded_path(&self.financial_root)?;
        canonical_hash(&self.financial_directory_identity)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    version: u16,
    purpose: String,
    association: Association,
    proof: OriginalProofDescriptorV1,
    initialization_plan: PrivateWorkspaceInitializationPlanV1,
    database_key: [u8; 32],
}
impl Drop for Pending {
    fn drop(&mut self) {
        self.database_key.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Committed {
    version: u16,
    pending_ciphertext_digest: String,
    pending_original_file_origin: String,
    association_digest: String,
    workspace_directory_identity: String,
    original_database_origin: [u8; 32],
    seed: PrivateWorkspaceSeedBindingV1,
}
fn digest<T: Serialize>(value: &T) -> Result<String> {
    wholepact_core::proposal::canonical_digest(
        "wholepact:native-private-workspace-association:v1",
        value,
    )
    .map_err(|_| Error::Authentication)
}
fn complete_association(
    pending: &Pending,
    workspace_identity: &str,
    origin: [u8; 32],
) -> Result<String> {
    wholepact_core::proposal::canonical_digest(
        "wholepact:native-private-workspace-complete-association:v1",
        &(
            &pending.association,
            &pending.proof,
            &pending.initialization_plan,
            workspace_identity,
            origin,
        ),
    )
    .map_err(|_| Error::Authentication)
}
fn canonical_hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Authentication);
    }
    Ok(())
}
fn bounded_path(path: &Path) -> Result<()> {
    crate::files::validate_absolute(path)?;
    if path.to_str().ok_or(Error::Invalid)?.len() > 4096 {
        return Err(Error::Invalid);
    }
    Ok(())
}
fn present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
pub(crate) fn refuse_unqualified_private_workspace_backup_v1(directory: &Directory) -> Result<()> {
    directory.refuse_private_workspace_files()
}
fn validate_pending(p: &Pending, secrets: &Secrets) -> Result<()> {
    let a = &p.association;
    if p.version != 1
        || p.purpose != PURPOSE
        || a.version != 1
        || a.purpose != PURPOSE
        || a.profile_id != secrets.profile()
        || a.reviewer_account_ids.len() != 2
        || a.reviewer_account_ids[0] >= a.reviewer_account_ids[1]
        || a.database_path != a.workspace_root.join(DATABASE)
        || a.retention_policy.is_empty()
        || a.retention_policy.len() > 1024
        || a.retention_policy.chars().any(char::is_control)
    {
        return Err(Error::Authentication);
    }
    bounded_path(&a.workspace_root)?;
    bounded_path(&a.database_path)?;
    for id in [&a.principal_id, &a.agreement_id, &a.obligation_id] {
        crate::id(id)?;
    }
    for account in &a.reviewer_account_ids {
        crate::id(account)?;
    }
    for hash in [
        &a.dependency_id,
        &a.inventory_digest,
        &a.generation_plan_digest,
        &a.parent_coverage_digest,
        &a.original_financial_origin_digest,
        &a.host_directory_identity,
        &a.source_digest,
    ] {
        canonical_hash(hash)?;
    }
    p.proof.validate(secrets)
}
/// Only this private constructor authenticates the exact original handles and
/// mandatory anchor. A staged proof cannot enter any Host/facade constructor.
pub(crate) struct OriginalWorkspacePublicationV1 {
    pending_file: PrivateWorkspaceFileV1,
    commit_file: PrivateWorkspaceFileV1,
    pending: Pending,
    committed: Committed,
}
pub(crate) struct OriginalWorkspaceFilesV1 {
    original: OriginalWorkspacePublicationV1,
}
fn require_publication_order(pending_final: bool, commit_final: bool) -> Result<()> {
    if !pending_final && commit_final {
        return Err(Error::Authentication);
    }
    Ok(())
}
impl OriginalWorkspacePublicationV1 {
    pub(crate) fn inspect(directory: &Directory, secrets: &Secrets) -> Result<Self> {
        if secrets.private_workspace_anchor().is_none() {
            return Err(Error::Authentication);
        }
        let candidates = directory.private_workspace_candidates()?;
        if candidates.len() != 2 {
            return Err(Error::Authentication);
        }
        let pending_name = candidates
            .iter()
            .filter(|s| {
                s.as_str() == PENDING || s.starts_with("staging-durable-private-pending-v1-")
            })
            .collect::<Vec<_>>();
        let commit_name = candidates
            .iter()
            .filter(|s| s.as_str() == COMMIT || s.starts_with("staging-durable-private-commit-v1-"))
            .collect::<Vec<_>>();
        if pending_name.len() != 1 || commit_name.len() != 1 {
            return Err(Error::Authentication);
        }
        let pending_file =
            PrivateWorkspaceFileV1::open(directory, pending_name[0], PENDING, MAX_REGISTRY)?;
        let commit_file =
            PrivateWorkspaceFileV1::open(directory, commit_name[0], COMMIT, MAX_REGISTRY)?;
        require_publication_order(pending_file.is_final(), commit_file.is_final())?;
        let pending: Pending = wholepact_core::parse_typed_json(
            &crate::recovery_generation::unseal_private_workspace_dependency_v1(
                secrets,
                true,
                &pending_file.bytes(directory, MAX_REGISTRY)?,
            )?,
        )
        .map_err(|_| Error::Authentication)?;
        let committed: Committed = wholepact_core::parse_typed_json(
            &crate::recovery_generation::unseal_private_workspace_dependency_v1(
                secrets,
                false,
                &commit_file.bytes(directory, MAX_REGISTRY)?,
            )?,
        )
        .map_err(|_| Error::Authentication)?;
        let result = Self {
            pending_file,
            commit_file,
            pending,
            committed,
        };
        result.check_inventory(directory, secrets)?;
        Ok(result)
    }
    fn anchor(&self, directory: &Directory) -> Result<[u8; 32]> {
        workspace_anchor(
            directory,
            &self.committed.association_digest,
            &self.pending_file,
            &self.commit_file,
        )
    }
    fn check(&self, directory: &Directory, secrets: &Secrets) -> Result<()> {
        validate_pending(&self.pending, secrets)?;
        self.pending_file.check(directory, MAX_REGISTRY)?;
        self.commit_file.check(directory, MAX_REGISTRY)?;
        require_publication_order(self.pending_file.is_final(), self.commit_file.is_final())?;
        if self.committed.version != 1
            || self.pending.association.host_directory_identity
                != directory.manual_target_identity_digest()?
            || self.committed.pending_original_file_origin != self.pending_file.origin()?
            || self.committed.pending_ciphertext_digest != self.pending_file.ciphertext_digest()
            || self.committed.association_digest
                != complete_association(
                    &self.pending,
                    &self.committed.workspace_directory_identity,
                    self.committed.original_database_origin,
                )?
            || secrets.private_workspace_anchor() != Some(self.anchor(directory)?.as_slice())
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    pub(crate) fn check_inventory(&self, directory: &Directory, secrets: &Secrets) -> Result<()> {
        self.check(directory, secrets)?;
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
                "recovery.plan",
                "generation.manifest",
                "generation.commit",
                "generation.keys",
                "financial.attached",
                "financial.inventory",
                self.pending_file.name(),
                self.commit_file.name(),
            ],
        )?;
        self.check(directory, secrets)
    }
    fn publish(
        mut self,
        directory: &Directory,
        secrets: &Secrets,
        exclusions: &PrivateWorkspacePublicationExclusionsV1,
        approval: &HistoricalApproval,
    ) -> Result<()> {
        approval.check()?;
        exclusions.check(directory, secrets, &self)?;
        self.check_inventory(directory, secrets)?;
        self.pending_file.publish(directory, MAX_REGISTRY)?;
        approval.check()?;
        exclusions.check(directory, secrets, &self)?;
        self.check_inventory(directory, secrets)?;
        self.commit_file.publish(directory, MAX_REGISTRY)?;
        approval.check()?;
        exclusions.check(directory, secrets, &self)?;
        self.check_inventory(directory, secrets)?;
        if !self.pending_file.is_final() || !self.commit_file.is_final() {
            return Err(Error::Authentication);
        }
        Ok(())
    }
}
impl OriginalWorkspaceFilesV1 {
    pub(crate) fn open_final(directory: &Directory, secrets: &Secrets) -> Result<Self> {
        reader_result!(
            ReaderFinalRegistry,
            observe_private_fixed_host_v1,
            (|| {
                let original = OriginalWorkspacePublicationV1::inspect(directory, secrets)?;
                if !original.pending_file.is_final() || !original.commit_file.is_final() {
                    return Err(Error::Authentication);
                }
                Ok(Self { original })
            })()
        )
    }
    pub(crate) fn check_inventory(&self, directory: &Directory, secrets: &Secrets) -> Result<()> {
        if !self.original.pending_file.is_final() || !self.original.commit_file.is_final() {
            return Err(Error::Authentication);
        }
        self.original.check_inventory(directory, secrets)
    }
}
fn workspace_anchor(
    directory: &Directory,
    association: &str,
    pending: &PrivateWorkspaceFileV1,
    commit: &PrivateWorkspaceFileV1,
) -> Result<[u8; 32]> {
    pending.check(directory, MAX_REGISTRY)?;
    commit.check(directory, MAX_REGISTRY)?;
    let digest = wholepact_core::proposal::canonical_digest(
        "wholepact:native-private-workspace-mandatory-anchor:v1",
        &(
            1u16,
            PURPOSE,
            association,
            directory.manual_target_identity_digest()?,
            pending.origin()?,
            pending.ciphertext_digest(),
            commit.origin()?,
            commit.ciphertext_digest(),
        ),
    )
    .map_err(|_| Error::Authentication)?;
    hex::decode(digest)
        .map_err(|_| Error::Authentication)?
        .try_into()
        .map_err(|_| Error::Authentication)
}
struct CurrentNativePrivacy<'a, 'host> {
    host: &'host Host,
    committed: &'a ManualCommittedTarget<'host>,
    association: &'a Association,
    approval: &'a HistoricalApproval,
    action: PrivateWorkspaceActionV1,
    observation: PrivateCurrentObservationV1<'a>,
}
enum PrivateCurrentObservationV1<'a> {
    None,
    Inspection,
    Stage(&'a PrivateStageObservationV1),
}
impl CurrentNativePrivacy<'_, '_> {
    fn observed<T>(&self, site: PrivateDiagnosticSiteV1, result: Result<T>) -> Result<T> {
        match &self.observation {
            PrivateCurrentObservationV1::None => result,
            PrivateCurrentObservationV1::Stage(stage) => stage.observe(site, result),
            PrivateCurrentObservationV1::Inspection => {
                if let Err(error) = &result {
                    observe_private_fixed_host_v1(
                        PrivateDiagnosticOperationV1::OpenOriginal,
                        site,
                        error,
                    );
                }
                result
            }
        }
    }
    fn check(&self) -> Result<()> {
        self.observed(
            PrivateDiagnosticSiteV1::HostWorkspaceNativeCheck,
            self.approval.check(),
        )?;
        if matches!(
            self.action,
            PrivateWorkspaceActionV1::Reopen
                | PrivateWorkspaceActionV1::ReadStatus
                | PrivateWorkspaceActionV1::ReadVerifiedFixed
                | PrivateWorkspaceActionV1::InspectFixedStageMetadataV3
        ) {
            self.observed(
                PrivateDiagnosticSiteV1::HostWorkspaceSessionCheck,
                self.host.require_private_workspace_read_session_v1(),
            )?;
        } else {
            self.observed(
                PrivateDiagnosticSiteV1::HostWorkspaceSessionCheck,
                self.host.require_manual_session(),
            )?;
        }
        let source = (|| {
            self.committed.check_current()?;
            self.committed.coverage().require_complete()?;
            if self.host.access()?.principal_id != self.association.principal_id
                || self.committed.profile_id() != self.association.profile_id
                || self.committed.generation_id() != self.association.generation_id
                || self.committed.inventory_digest() != self.association.inventory_digest
                || self.committed.plan_digest() != self.association.generation_plan_digest
                || self.committed.destination_identity_digest()
                    != self.association.host_directory_identity
                || self.committed.coverage().digest()? != self.association.parent_coverage_digest
                || self
                    .host
                    .financial
                    .as_ref()
                    .ok_or(Error::Locked)?
                    .manual_original_primary_origin_digest(
                        &self.host.directory,
                        &self.host.secrets,
                    )?
                    != self.association.original_financial_origin_digest
            {
                return Err(Error::Authentication);
            }
            Ok(())
        })();
        self.observed(PrivateDiagnosticSiteV1::HostWorkspaceSourceCheck, source)?;
        self.observed(
            PrivateDiagnosticSiteV1::HostWorkspaceNativeCheck,
            self.approval.check(),
        )
    }
}
impl LocalPrivateWorkspaceConsentV1 for CurrentNativePrivacy<'_, '_> {
    fn permits_workspace(
        &self,
        scope: &PrivateWorkspaceScopeV1,
        action: PrivateWorkspaceActionV1,
    ) -> bool {
        if !(self.action == action
            && scope.source_digest() == self.association.source_digest
            && scope.principal_id() == self.association.principal_id
            && scope.agreement_id() == self.association.agreement_id
            && scope.obligation_id() == self.association.obligation_id
            && scope.reviewer_account_ids() == self.association.reviewer_account_ids
            && scope.protected_destination() == self.association.database_path
            && scope.retention_policy() == self.association.retention_policy)
        {
            return false;
        }
        match self.check() {
            Ok(()) => true,
            Err(error) => {
                let operation = match action {
                    PrivateWorkspaceActionV1::CheckpointExactOriginal => {
                        PrivateDiagnosticOperationV1::Checkpoint
                    }
                    PrivateWorkspaceActionV1::ProveOriginalOnce => {
                        PrivateDiagnosticOperationV1::Proof
                    }
                    PrivateWorkspaceActionV1::FreezeVerifiedFixed => {
                        PrivateDiagnosticOperationV1::Freeze
                    }
                    PrivateWorkspaceActionV1::ReadVerifiedFixed
                    | PrivateWorkspaceActionV1::ReadStatus => {
                        PrivateDiagnosticOperationV1::ReadFixed
                    }
                    _ => PrivateDiagnosticOperationV1::OpenOriginal,
                };
                observe_private_fixed_host_v1(
                    operation,
                    PrivateDiagnosticSiteV1::HostWorkspaceCurrent,
                    &error,
                );
                storage_host_error(&error);
                false
            }
        }
    }
}
/// Mirror financial_attachments::target_check using the actual held roots,
/// not caller directory labels. Both descendants and ancestors are forbidden.
fn require_external_workspace_root(directory: &Directory, root: &Path) -> Result<()> {
    directory.external_destination(root)?;
    let actual = directory.path("profile.lock")?;
    if actual.parent().ok_or(Error::Invalid)?.starts_with(root) {
        return Err(Error::Invalid);
    }
    Ok(())
}
/// Bounded destination-coverage check only, not a history or financial gate.
/// Authenticated pending/committed extra dependencies cannot be ignored, but
/// this first slice has no nominal actual-owner hook for their Directory locks.
/// Do not substitute registry path labels for such owners or old V3 liveness.
fn require_primary_only_destination_coverage(
    entries: &[crate::financial_inventory::Attachment],
    actual_primary_root: &Path,
) -> Result<()> {
    if entries.len() != 1
        || entries[0].role != crate::financial_inventory::AttachmentRole::PrimaryFinancial
        || entries[0].account.is_some()
        || entries[0].directory != actual_primary_root
    {
        return Err(Error::RecoveryFinancialUnsupported);
    }
    Ok(())
}
fn check_workspace_destination(host: &Host, root: &Path) -> Result<()> {
    host.require_private_workspace_read_session_v1()?;
    let primary = host.financial.as_ref().ok_or(Error::Locked)?;
    // This authenticates the actual original primary and its registry anchor,
    // without promoting that historical association to spending authority.
    primary.manual_original_primary_origin_digest(&host.directory, &host.secrets)?;
    let entries = crate::financial_inventory::read_current(&host.directory, &host.secrets)?;
    require_primary_only_destination_coverage(&entries, &primary.current_directory()?)?;
    require_external_workspace_root(&host.directory, root)?;
    require_external_workspace_root(&primary.directory, root)
}

fn association(
    host: &Host,
    committed: &ManualCommittedTarget<'_>,
    source: &PrivateDurableWorkspaceSourceV1<'_>,
    dependency_id: String,
    root: &Path,
    retention_policy: &str,
) -> Result<Association> {
    host.require_private_workspace_read_session_v1()?;
    reader_result!(
        ReaderSourceFinalCheck,
        observe_private_fixed_engine_v1,
        source.check_current(host.access()?)
    )
    .map_err(storage_engine_error)?;
    committed.check_current()?;
    committed.coverage().require_complete()?;
    crate::files::validate_absolute(root)?;
    check_workspace_destination(host, root)?;
    if source.generation_id() != committed.generation_id()
        || source.inventory_digest() != committed.inventory_digest()
        || source.principal_id() != host.access()?.principal_id
        || retention_policy.is_empty()
        || retention_policy.len() > 1024
        || retention_policy.chars().any(char::is_control)
    {
        return Err(Error::Authentication);
    }
    Ok(Association {
        version: 1,
        purpose: PURPOSE.into(),
        dependency_id,
        profile_id: committed.profile_id().into(),
        generation_id: committed.generation_id().into(),
        inventory_digest: committed.inventory_digest().into(),
        generation_plan_digest: committed.plan_digest().into(),
        parent_coverage_digest: committed.coverage().digest()?,
        original_financial_origin_digest: host
            .financial
            .as_ref()
            .ok_or(Error::Locked)?
            .manual_original_primary_origin_digest(&host.directory, &host.secrets)?,
        host_directory_identity: committed.destination_identity_digest().into(),
        source_store_destination_identity: source.source_destination_identity().into(),
        source_digest: source.source_digest().into(),
        principal_id: source.principal_id().into(),
        agreement_id: source.agreement_id().into(),
        obligation_id: source.obligation_id().into(),
        reviewer_account_ids: source.reviewer_account_ids(),
        workspace_root: root.into(),
        database_path: root.join(DATABASE),
        retention_policy: retention_policy.into(),
    })
}

/// Source-only publication owner. It cannot return its Engine, source target,
/// financial evidence or metadata snapshot, and it cannot authorize an effect.
struct PrivateWorkspacePublicationSourceV1<'a> {
    engine: Engine,
    financial: crate::financial_profile::FinancialReadProfile,
    metadata: wholepact_storage_security::EncryptedReadSnapshot,
    access: Access,
    directory: &'a Directory,
    secrets: &'a Secrets,
    files: &'a OriginalWorkspacePublicationV1,
    approval: &'a HistoricalApproval,
    workspace: Directory,
}
impl<'a> PrivateWorkspacePublicationSourceV1<'a> {
    fn open(
        directory: &'a Directory,
        secrets: &'a Secrets,
        files: &'a OriginalWorkspacePublicationV1,
        financial_password: &[u8],
        approval: &'a HistoricalApproval,
    ) -> Result<Self> {
        reader_result!(
            ReaderSourceOpen,
            observe_private_fixed_host_v1,
            approval.check()
        )?;
        reader_result!(
            ReaderFinalRegistry,
            observe_private_fixed_host_v1,
            files.check_inventory(directory, secrets)
        )?;
        let pending = &files.pending;
        let financial = reader_result!(
            ReaderFinancialSnapshot,
            observe_private_fixed_host_v1,
            crate::financial_profile::FinancialReadProfile::open(
                &pending.proof.financial_root,
                &secrets.profile(),
                financial_password,
            )
        )?;
        reader_result!(
            ReaderFinancialOriginal,
            observe_private_fixed_host_v1,
            financial.require_private_workspace_original_v1(
                directory,
                secrets,
                &pending.association.original_financial_origin_digest,
                &pending.proof.financial_directory_identity,
                pending.proof.original_proof_origin,
            )
        )?;
        require_external_workspace_root(directory, &pending.association.workspace_root)?;
        require_external_workspace_root(&financial.directory, &pending.association.workspace_root)?;
        require_primary_only_destination_coverage(
            &crate::financial_inventory::read_current(directory, secrets)?,
            &financial.current_directory()?,
        )?;
        let workspace = reader_result!(
            ReaderWorkspaceDirectory,
            observe_private_fixed_host_v1,
            Directory::open(&pending.association.workspace_root)
        )?;
        reader_result!(
            ReaderWorkspaceDirectory,
            observe_private_fixed_host_v1,
            workspace.inventory_of(&[DATABASE], &["profile.lock"])
        )?;
        if reader_result!(
            ReaderWorkspaceDirectory,
            observe_private_fixed_host_v1,
            workspace.manual_target_identity_digest()
        )? != files.committed.workspace_directory_identity
        {
            return reader_result!(
                ReaderWorkspaceDirectory,
                observe_private_fixed_host_v1,
                Err(Error::Authentication)
            );
        }
        let metadata = reader_result!(
            ReaderMetadataSnapshot,
            observe_private_fixed_storage_v1,
            wholepact_storage_security::open_encrypted_read_snapshot(
                &pending.association.database_path,
                &DatabaseKey::from_bytes(pending.database_key),
            )
        )?;
        if reader_result!(
            ReaderMetadataOrigin,
            observe_private_fixed_storage_v1,
            metadata.source_database_identity()
        )?
        .origin_commitment()
            != files.committed.original_database_origin
        {
            return reader_result!(
                ReaderMetadataOrigin,
                observe_private_fixed_host_v1,
                Err(Error::Authentication)
            );
        }
        reader_result!(
            ReaderMetadataInitializedSchema,
            observe_private_fixed_engine_v1,
            PreparedPrivateDurableCoordinatorV1::check_initialized_original_v1(
                &pending.association.database_path,
                &DatabaseKey::from_bytes(pending.database_key),
                files.committed.original_database_origin,
            )
        )
        .map_err(storage_engine_error)?;
        let target = reader_result!(
            ReaderSourceStore,
            observe_private_fixed_host_v1,
            ManualCommittedTarget::open_workspace_publication_source_v1(directory, secrets, files)
        )?;
        reader_result!(
            ReaderSourceStore,
            observe_private_fixed_host_v1,
            target.coverage().require_complete()
        )?;
        drop(target);
        let engine = Engine::from_store(reader_result!(
            ReaderSourceStore,
            observe_private_fixed_host_v1,
            crate::recovery_generation::open_workspace_publication_source_store_v1(
                directory, secrets, files,
            )
        )?);
        // This bounded access projection is used only for the separately approved
        // source read. It is never enrolled into a Host or issued as authority.
        let access = Access {
            principal_id: pending.association.principal_id.clone(),
            include_owned_agreements: false,
            all_agreements: false,
            agreement_ids: std::collections::BTreeSet::from([pending
                .association
                .agreement_id
                .clone()]),
        };
        let result = Self {
            engine,
            financial,
            metadata,
            access,
            directory,
            secrets,
            files,
            approval,
            workspace,
        };
        reader_result!(
            ReaderSourceAssociation,
            observe_private_fixed_host_v1,
            result.require_exact_association()
        )?;
        Ok(result)
    }
    fn into_exclusions(self) -> Result<PrivateWorkspacePublicationExclusionsV1> {
        self.require_exact_association()?;
        let Self {
            engine,
            financial,
            metadata,
            access,
            directory: _,
            secrets: _,
            files: _,
            approval: _,
            workspace,
        } = self;
        drop((engine, access));
        Ok(PrivateWorkspacePublicationExclusionsV1 {
            financial,
            metadata,
            workspace,
        })
    }
    fn require_exact_association(&self) -> Result<()> {
        reader_result!(
            ReaderSourceAssociation,
            observe_private_fixed_host_v1,
            self.approval.check()
        )?;
        reader_result!(
            ReaderFinalRegistry,
            observe_private_fixed_host_v1,
            self.files.check_inventory(self.directory, self.secrets)
        )?;
        let p = &self.files.pending;
        let a = &p.association;
        let target = reader_result!(
            ReaderSourceStore,
            observe_private_fixed_host_v1,
            ManualCommittedTarget::open_workspace_publication_source_v1(
                self.directory,
                self.secrets,
                self.files,
            )
        )?;
        reader_result!(
            ReaderSourceStore,
            observe_private_fixed_host_v1,
            target.coverage().require_complete()
        )?;
        let source = reader_result!(
            ReaderSourceSelection,
            observe_private_fixed_engine_v1,
            self.engine
                .original_private_workspace_source_v1(&self.access, &a.agreement_id)
        )
        .map_err(storage_engine_error)?;
        reader_result!(
            ReaderSourceSeedPlan,
            observe_private_fixed_engine_v1,
            source.check_initialization_plan_v1(&self.access, &p.initialization_plan)
        )
        .map_err(storage_engine_error)?;
        let seed = reader_result!(
            ReaderSourceSeedBinding,
            observe_private_fixed_engine_v1,
            source.seed_binding_original_v1(
                &self.access,
                &a.database_path,
                &a.retention_policy,
                &self.files.committed.association_digest,
                self.files.committed.original_database_origin,
                &p.initialization_plan,
            )
        )
        .map_err(storage_engine_error)?;
        if reader_result!(
            ReaderSourceSeedCompare,
            observe_private_fixed_host_v1,
            serde_json::to_value(&seed).map_err(Error::from)
        )? != reader_result!(
            ReaderSourceSeedCompare,
            observe_private_fixed_host_v1,
            serde_json::to_value(&self.files.committed.seed).map_err(Error::from)
        )? {
            return reader_result!(
                ReaderSourceSeedCompare,
                observe_private_fixed_host_v1,
                Err(Error::Authentication)
            );
        }
        if source.source_digest() != a.source_digest
            || source.principal_id() != a.principal_id
            || source.agreement_id() != a.agreement_id
            || source.obligation_id() != a.obligation_id
            || source.reviewer_account_ids() != a.reviewer_account_ids
            || source.source_destination_identity() != a.source_store_destination_identity
            || source.generation_id() != a.generation_id
            || source.inventory_digest() != a.inventory_digest
            || target.profile_id() != a.profile_id
            || target.plan_digest() != a.generation_plan_digest
            || target.generation_id() != a.generation_id
            || target.inventory_digest() != a.inventory_digest
            || target.destination_identity_digest() != a.host_directory_identity
            || reader_result!(
                ReaderSourceCompare,
                observe_private_fixed_host_v1,
                target.coverage().digest()
            )? != a.parent_coverage_digest
            || reader_result!(
                ReaderSourceCompare,
                observe_private_fixed_host_v1,
                self.workspace.manual_target_identity_digest()
            )? != self.files.committed.workspace_directory_identity
            || reader_result!(
                ReaderMetadataOrigin,
                observe_private_fixed_storage_v1,
                self.metadata.source_database_identity()
            )?
            .origin_commitment()
                != self.files.committed.original_database_origin
        {
            return reader_result!(
                ReaderSourceCompare,
                observe_private_fixed_host_v1,
                Err(Error::Authentication)
            );
        }
        reader_result!(
            ReaderFinancialOriginal,
            observe_private_fixed_host_v1,
            self.financial.require_private_workspace_original_v1(
                self.directory,
                self.secrets,
                &a.original_financial_origin_digest,
                &p.proof.financial_directory_identity,
                p.proof.original_proof_origin,
            )
        )?;
        reader_result!(
            ReaderSourceFinalCheck,
            observe_private_fixed_storage_v1,
            self.metadata.check_source_unchanged()
        )?;
        reader_result!(
            ReaderSourceFinalCheck,
            observe_private_fixed_host_v1,
            self.workspace.inventory_of(&[DATABASE], &["profile.lock"])
        )?;
        reader_result!(
            ReaderSourceFinalCheck,
            observe_private_fixed_engine_v1,
            source.check_current(&self.access)
        )
        .map_err(storage_engine_error)?;
        reader_result!(
            ReaderSourceFinalCheck,
            observe_private_fixed_host_v1,
            target.check_current()
        )?;
        reader_result!(
            ReaderSourceFinalCheck,
            observe_private_fixed_host_v1,
            self.approval.check()
        )
    }
}

/// Exclusion-only remainder: no source Engine, runtime, operation or native
/// authority getter. Original financial/metadata read handles and both locks
/// remain held across every no-replace rename and directory fsync.
struct PrivateWorkspacePublicationExclusionsV1 {
    financial: crate::financial_profile::FinancialReadProfile,
    metadata: wholepact_storage_security::EncryptedReadSnapshot,
    workspace: Directory,
}
impl PrivateWorkspacePublicationExclusionsV1 {
    fn check(
        &self,
        directory: &Directory,
        secrets: &Secrets,
        files: &OriginalWorkspacePublicationV1,
    ) -> Result<()> {
        let p = &files.pending;
        let c = &files.committed;
        self.financial.require_private_workspace_original_v1(
            directory,
            secrets,
            &p.association.original_financial_origin_digest,
            &p.proof.financial_directory_identity,
            p.proof.original_proof_origin,
        )?;
        self.metadata.check_source_unchanged()?;
        self.workspace
            .inventory_of(&[DATABASE], &["profile.lock"])?;
        if self
            .metadata
            .source_database_identity()?
            .origin_commitment()
            != c.original_database_origin
            || self.workspace.manual_target_identity_digest()? != c.workspace_directory_identity
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
}

/// Real Directory is last; every borrowed source/proof and coordinator closes
/// before its metadata exclusion lock. Nothing can extract its raw Engine/Store.
pub(in crate::host) struct PrivateWorkspaceOwnerV1<'host> {
    coordinator: PrivateDurableCoordinatorV1<'host>,
    committed_target: ManualCommittedTarget<'host>,
    host: &'host Host,
    files: &'host OriginalWorkspaceFilesV1,
    directory: Directory,
}

impl Host {
    fn private_workspace_source_owners_v1<'host>(
        &'host self,
        agreement_id: &str,
    ) -> Result<(
        ManualCommittedTarget<'host>,
        PrivateDurableWorkspaceSourceV1<'host>,
        HistoricalApproval,
    )> {
        self.require_private_workspace_read_session_v1()?;
        let review = self.terminal.approve_historical(&format!(
            "Read exact current selected original source and complete historical terms for NONSPENDING private coordination. Agreement: {agreement_id}. This reads actual roster/FVK/policy associations; it grants no financial permission."))?;
        review.check()?;
        let committed = match &self.workspace_files {
            Some(files) => ManualCommittedTarget::open_private_workspace_original(
                &self.directory,
                &self.secrets,
                files,
            )?,
            None => ManualCommittedTarget::open(&self.directory, &self.secrets)?,
        };
        committed.coverage().require_complete()?;
        let source = reader_result!(
            ReaderSourceSelection,
            observe_private_fixed_engine_v1,
            self.engine
                .original_private_workspace_source_v1(self.access()?, agreement_id)
        )
        .map_err(storage_engine_error)?;
        reader_result!(
            ReaderSourceFinalCheck,
            observe_private_fixed_engine_v1,
            source.check_current(self.access()?)
        )
        .map_err(storage_engine_error)?;
        committed.check_current()?;
        review.check()?;
        Ok((committed, source, review))
    }
    /// Consumption is irrevocable. No branch, including an uncertain rename,
    /// can give an old unmarked Host back to a caller or ordinary shell.
    pub(in crate::host) fn create_private_durable_workspace_v1(
        self,
        agreement_id: &str,
        root: &Path,
        retention_policy: &str,
        password: &[u8],
    ) -> Result<()> {
        storage_begin("PrivateWorkspaceReserve");
        let result = (|| {
            self.require_manual_session()?;
            self.secrets.require_portable_legacy()?;
            self.directory.refuse_private_workspace_files()?;
            if self.workspace_files.is_some() || self.observation.is_some() || present(root)? {
                return Err(Error::Authentication);
            }
            bounded_path(root)?;
            let (pending_file, commit_file, anchor, workspace_exclusion) = {
                let (committed, source, review) =
                    self.private_workspace_source_owners_v1(agreement_id)?;
                let binding = association(
                    &self,
                    &committed,
                    &source,
                    hex::encode(crate::random::<32>()?),
                    root,
                    retention_policy,
                )?;
                let pending = Pending {
                    version: 1,
                    purpose: PURPOSE.into(),
                    association: binding,
                    proof: OriginalProofDescriptorV1::from_host(&self)?,
                    initialization_plan: source
                        .initialization_plan_v1(self.access()?)
                        .map_err(storage_engine_error)?,
                    database_key: crate::random::<32>()?,
                };
                validate_pending(&pending, &self.secrets)?;
                let approval = self.terminal.approve_historical_reviewed(&review, &format!(
                "Register exact immutable private dependency. Destination: {}. Retention: {}. Association: {}. The original selected and historical terms are retained privately. This is NOT cryptographic confidentiality from this Host's OS user. Portable backup/export/history/successor paths will refuse. No signer disclosure, proof, spend, signing or dispatch is approved. Registration closes this Host before its mandatory vault anchor changes; explicit initialize is required afterward.", root.display(), retention_policy, digest(&pending.association)?))?;
                let privacy = CurrentNativePrivacy {
                    host: &self,
                    committed: &committed,
                    association: &pending.association,
                    approval: &approval,
                    action: PrivateWorkspaceActionV1::Create,
                    observation: PrivateCurrentObservationV1::None,
                };
                privacy.check()?;
                check_workspace_destination(&self, root)?;
                source
                    .check_initialization_plan_v1(self.access()?, &pending.initialization_plan)
                    .map_err(storage_engine_error)?;
                let plain = Zeroizing::new(serde_json::to_vec(&pending)?);
                let sealed = crate::recovery_generation::seal_private_workspace_dependency_v1(
                    &self.secrets,
                    true,
                    &plain,
                )?;
                let pending_file =
                    PrivateWorkspaceFileV1::stage(&self.directory, PENDING, &sealed, MAX_REGISTRY)?;
                privacy.check()?;
                check_workspace_destination(&self, root)?;
                if present(root)? {
                    return Err(Error::Authentication);
                }
                let workspace = Directory::create(root)?;
                let prepared = PreparedPrivateDurableCoordinatorV1::prepare_empty_new(
                    &source,
                    self.access()?,
                    &workspace.path(DATABASE)?,
                    &DatabaseKey::from_bytes(pending.database_key),
                    retention_policy,
                    &privacy,
                )
                .map_err(storage_engine_error)?;
                let workspace_identity = workspace.manual_target_identity_digest()?;
                let origin = prepared.original_origin();
                let association_digest =
                    complete_association(&pending, &workspace_identity, origin)?;
                let seed = prepared
                    .seed_binding_v1(
                        &source,
                        self.access()?,
                        retention_policy,
                        &association_digest,
                        &pending.initialization_plan,
                    )
                    .map_err(storage_engine_error)?;
                let commit = Committed {
                    version: 1,
                    pending_ciphertext_digest: pending_file.ciphertext_digest().into(),
                    pending_original_file_origin: pending_file.origin()?,
                    association_digest,
                    workspace_directory_identity: workspace_identity,
                    original_database_origin: origin,
                    seed,
                };
                let commit_plain = Zeroizing::new(serde_json::to_vec(&commit)?);
                let sealed_commit =
                    crate::recovery_generation::seal_private_workspace_dependency_v1(
                        &self.secrets,
                        false,
                        &commit_plain,
                    )?;
                privacy.check()?;
                source
                    .check_current(self.access()?)
                    .map_err(storage_engine_error)?;
                let commit_file = PrivateWorkspaceFileV1::stage(
                    &self.directory,
                    COMMIT,
                    &sealed_commit,
                    MAX_REGISTRY,
                )?;
                let anchor = workspace_anchor(
                    &self.directory,
                    &commit.association_digest,
                    &pending_file,
                    &commit_file,
                )?;
                privacy.check()?;
                source
                    .check_initialization_plan_v1(self.access()?, &pending.initialization_plan)
                    .map_err(storage_engine_error)?;
                drop(prepared);
                (pending_file, commit_file, anchor, workspace)
            }; // Every source, ManualTarget, native lease and unseeded owner is gone.
            storage_complete("PrivateWorkspaceReserve");
            storage_begin("PrivateWorkspaceAnchor");
            self.authority.fence.revoke()?; // drains any permission effect before ownership cut
            let Host {
                secrets,
                terminal,
                engine,
                authority,
                transport,
                submission,
                access,
                config,
                observation,
                financial,
                signer_review_clients,
                resolution_source,
                workspace_files,
                directory,
            } = self;
            drop((
                engine,
                transport,
                submission,
                observation,
                financial,
                signer_review_clients,
                resolution_source,
            ));
            drop((authority, access, config, workspace_files));
            // Only non-runtime publication state survives. Even seal/replace/fsync
            // failure drops this state; no stale v2 runtime capability exists.
            let secrets = secrets.bind_private_workspace_v3(anchor)?;
            let envelope = Zeroizing::new(secrets.seal(password)?);
            pending_file.check(&directory, MAX_REGISTRY)?;
            commit_file.check(&directory, MAX_REGISTRY)?;
            directory.replace_private("profile.vault", &envelope)?;
            let verified = Secrets::open_private_workspace_v3(
                &directory.read("profile.vault", 1024)?,
                password,
            )?;
            if !verified.same_recovery_material(&secrets) {
                return Err(Error::Authentication);
            }
            drop((
                pending_file,
                commit_file,
                verified,
                secrets,
                workspace_exclusion,
                directory,
            ));
            terminal.message("Mandatory workspace anchor staged. The old Host is closed. Preserve all originals and use durable-private-initialize-v1 to freshly validate, publish and initialize the exact saved seed. No private seed, material or proof has run.\n")?;
            storage_complete("PrivateWorkspaceAnchor");
            Ok(())
        })();
        if let Err(error) = &result {
            storage_host_error(error);
        }
        result
    }
    pub(in crate::host) fn reopen_private_workspace_registered_v1(
        &self,
        root: &Path,
    ) -> Result<PrivateWorkspaceOwnerV1<'_>> {
        let files = self.workspace_files.as_ref().ok_or(Error::Authentication)?;
        let a = &files.original.pending.association;
        self.reopen_private_durable_workspace_v1(&a.agreement_id, root, &a.retention_policy)
    }
    pub(in crate::host) fn reopen_private_durable_workspace_v1<'host>(
        &'host self,
        agreement_id: &str,
        root: &Path,
        retention_policy: &str,
    ) -> Result<PrivateWorkspaceOwnerV1<'host>> {
        self.private_workspace_owner_v1(agreement_id, root, retention_policy, false)
    }
    fn private_workspace_owner_v1<'host>(
        &'host self,
        agreement_id: &str,
        root: &Path,
        retention_policy: &str,
        initialize: bool,
    ) -> Result<PrivateWorkspaceOwnerV1<'host>> {
        let files = reader_result!(
            ReaderFinalRegistry,
            observe_private_fixed_host_v1,
            self.workspace_files.as_ref().ok_or(Error::Authentication)
        )?;
        reader_result!(
            ReaderFinalRegistry,
            observe_private_fixed_host_v1,
            files.check_inventory(&self.directory, &self.secrets)
        )?;
        let p = &files.original.pending;
        let c = &files.original.committed;
        let (committed_target, source, review) = reader_result!(
            ReaderSourceSelection,
            observe_private_fixed_host_v1,
            self.private_workspace_source_owners_v1(agreement_id)
        )?;
        let current = reader_result!(
            ReaderSourceAssociation,
            observe_private_fixed_host_v1,
            association(
                self,
                &committed_target,
                &source,
                p.association.dependency_id.clone(),
                root,
                retention_policy,
            )
        )?;
        if current != p.association
            || reader_result!(
                ReaderSourceAssociation,
                observe_private_fixed_host_v1,
                OriginalProofDescriptorV1::from_host(self)
            )? != p.proof
        {
            return reader_result!(
                ReaderSourceAssociation,
                observe_private_fixed_host_v1,
                Err(Error::Authentication)
            );
        }
        reader_result!(
            ReaderSourceSeedPlan,
            observe_private_fixed_engine_v1,
            source.check_initialization_plan_v1(self.access()?, &p.initialization_plan)
        )
        .map_err(storage_engine_error)?;
        let directory = reader_result!(
            ReaderWorkspaceDirectory,
            observe_private_fixed_host_v1,
            Directory::open(root)
        )?;
        reader_result!(
            ReaderWorkspaceDirectory,
            observe_private_fixed_host_v1,
            directory.inventory_of(&[DATABASE], &["profile.lock"])
        )?;
        if reader_result!(
            ReaderWorkspaceDirectory,
            observe_private_fixed_host_v1,
            directory.manual_target_identity_digest()
        )? != c.workspace_directory_identity
        {
            return reader_result!(
                ReaderWorkspaceDirectory,
                observe_private_fixed_host_v1,
                Err(Error::Authentication)
            );
        }
        let approval = self.terminal.approve_historical_reviewed(&review, if initialize {
            "Initialize ONCE the exact previously anchored private seed, original operation/idempotency/timestamps and marker. Exact committed replay returns the original result only; no material, constructor, proof or authority is resumed."
        } else { "Open ONLY the exact initialized original private workspace. No missing database is created; no material, proof or authority is resumed." })?;
        let action = if initialize {
            PrivateWorkspaceActionV1::Create
        } else {
            PrivateWorkspaceActionV1::Reopen
        };
        let privacy = CurrentNativePrivacy {
            host: self,
            committed: &committed_target,
            association: &p.association,
            approval: &approval,
            action,
            observation: PrivateCurrentObservationV1::None,
        };
        reader_result!(
            ReaderSourceFinalCheck,
            observe_private_fixed_host_v1,
            privacy.check()
        )?;
        let proof = self
            .financial
            .as_ref()
            .ok_or(Error::Locked)?
            .original_workspace_proof_v1()?;
        let key = DatabaseKey::from_bytes(p.database_key);
        let coordinator = if initialize {
            let prepared = PreparedPrivateDurableCoordinatorV1::open_uninitialized_original(
                &p.association.database_path,
                &key,
                c.original_database_origin,
            )
            .map_err(storage_engine_error)?;
            let binding = prepared
                .seed_binding_v1(
                    &source,
                    self.access()?,
                    retention_policy,
                    &c.association_digest,
                    &p.initialization_plan,
                )
                .map_err(storage_engine_error)?;
            if serde_json::to_vec(&binding)? != serde_json::to_vec(&c.seed)? {
                return Err(Error::Authentication);
            }
            prepared
                .initialize_once_original(
                    source,
                    self.access()?,
                    retention_policy,
                    &c.association_digest,
                    &p.initialization_plan,
                    proof,
                    p.proof.original_proof_origin,
                    &privacy,
                )
                .map_err(storage_engine_error)?
        } else {
            reader_result!(
                ReaderSourceOpen,
                observe_private_fixed_engine_v1,
                PrivateDurableCoordinatorV1::open_original(
                    source,
                    self.access()?,
                    &p.association.database_path,
                    &key,
                    c.original_database_origin,
                    retention_policy,
                    &c.association_digest,
                    proof,
                    p.proof.original_proof_origin,
                    &p.initialization_plan,
                    &c.seed,
                    &privacy,
                )
            )
            .map_err(storage_engine_error)?
        };
        if reader_result!(
            ReaderSourceSeedCompare,
            observe_private_fixed_engine_v1,
            coordinator.origin_marker_digest()
        )
        .map_err(storage_engine_error)?
            != c.seed.marker_digest
        {
            return reader_result!(
                ReaderSourceSeedCompare,
                observe_private_fixed_host_v1,
                Err(Error::Authentication)
            );
        }
        reader_result!(
            ReaderSourceFinalCheck,
            observe_private_fixed_host_v1,
            privacy.check()
        )?;
        reader_result!(
            ReaderFinalRegistry,
            observe_private_fixed_host_v1,
            files.check_inventory(&self.directory, &self.secrets)
        )?;
        Ok(PrivateWorkspaceOwnerV1 {
            coordinator,
            committed_target,
            host: self,
            files,
            directory,
        })
    }
    pub(in crate::host) fn initialize_private_workspace_saved_v1(&self, root: &Path) -> Result<()> {
        storage_begin("PrivateWorkspaceInitialize");
        let result = (|| {
            let p = &self
                .workspace_files
                .as_ref()
                .ok_or(Error::Authentication)?
                .original
                .pending;
            let owner = self.private_workspace_owner_v1(
                &p.association.agreement_id,
                root,
                &p.association.retention_policy,
                true,
            )?;
            owner.check_originals()
        })();
        if let Err(error) = &result {
            storage_host_error(error);
        } else {
            storage_complete("PrivateWorkspaceInitialize");
        }
        result
    }
}

impl PrivateWorkspaceOwnerV1<'_> {
    fn check_originals(&self) -> Result<()> {
        self.check_current_without_proof_lock_v2()?;
        reader_result!(
            ReaderOriginalProofCurrent,
            observe_private_fixed_job_v1,
            self.host
                .financial
                .as_ref()
                .ok_or(Error::Locked)?
                .original_workspace_proof_v1()?
                .check_current()
        )
        .map_err(|_| Error::Authentication)
    }
    pub(in crate::host) fn check_current_without_proof_lock_v2(&self) -> Result<()> {
        reader_result!(
            ReaderReadSession,
            observe_private_fixed_host_v1,
            self.host.require_private_workspace_read_session_v1()
        )?;
        reader_result!(
            ReaderFinalRegistry,
            observe_private_fixed_host_v1,
            self.files
                .check_inventory(&self.host.directory, &self.host.secrets)
        )?;
        reader_result!(
            ReaderSourceFinalCheck,
            observe_private_fixed_host_v1,
            self.committed_target.check_current()
        )?;
        let p = &self.files.original.pending;
        let c = &self.files.original.committed;
        reader_result!(
            ReaderWorkspaceDirectory,
            observe_private_fixed_host_v1,
            self.directory.inventory_of(&[DATABASE], &["profile.lock"])
        )?;
        if reader_result!(
            ReaderWorkspaceDirectory,
            observe_private_fixed_host_v1,
            self.directory.manual_target_identity_digest()
        )? != c.workspace_directory_identity
            || self
                .host
                .financial
                .as_ref()
                .ok_or(Error::Locked)?
                .manual_original_primary_origin_digest(&self.host.directory, &self.host.secrets)?
                != p.association.original_financial_origin_digest
        {
            return reader_result!(
                ReaderSourceCompare,
                observe_private_fixed_host_v1,
                Err(Error::Authentication)
            );
        }
        let source = reader_result!(
            ReaderSourceSelection,
            observe_private_fixed_engine_v1,
            self.host.engine.original_private_workspace_source_v1(
                self.host.access()?,
                &p.association.agreement_id
            )
        )
        .map_err(storage_engine_error)?;
        reader_result!(
            ReaderSourceSeedPlan,
            observe_private_fixed_engine_v1,
            source.check_initialization_plan_v1(self.host.access()?, &p.initialization_plan)
        )
        .map_err(storage_engine_error)?;
        if source.source_digest() != p.association.source_digest {
            return reader_result!(
                ReaderSourceCompare,
                observe_private_fixed_host_v1,
                Err(Error::Authentication)
            );
        }
        reader_result!(
            ReaderSourceFinalCheck,
            observe_private_fixed_engine_v1,
            source.check_current(self.host.access()?)
        )
        .map_err(storage_engine_error)?;
        Ok(())
    }
    /// Closure-scoped access to the purpose-limited facade, never its Engine,
    /// Store or proof owner. A consuming proof continuation cannot escape this
    /// lexical borrow. Native consent checks avoid recursively taking proof lock.
    pub(in crate::host) fn with_exact_fixed_v2<R>(
        &self,
        action: PrivateWorkspaceActionV1,
        effect: impl FnOnce(
            &PrivateDurableCoordinatorV1<'_>,
            &dyn LocalPrivateWorkspaceConsentV1,
        ) -> Result<R>,
    ) -> Result<R> {
        require_exact_action(action)?;
        storage_action_boundary(action);
        self.check_originals()?;
        let a = &self.files.original.pending.association;
        let approval = self.host.terminal.approve_historical(&format!(
            "Permit this one exact nonspending private workspace effect for original agreement {} and source {}. Destination: {}. Audience: {:?}. Retention: {}. No financial admission, signature, export or submission is authorized. Operation: {}.",
            a.agreement_id, a.source_digest, a.database_path.display(), a.reviewer_account_ids, a.retention_policy, workspace_action_name(action)))?;
        let privacy = CurrentNativePrivacy {
            host: self.host,
            committed: &self.committed_target,
            association: a,
            approval: &approval,
            action,
            observation: PrivateCurrentObservationV1::None,
        };
        privacy.check()?;
        let result = effect(&self.coordinator, &privacy)?;
        privacy.check()?;
        self.check_originals()?;
        Ok(result)
    }
    pub(in crate::host) fn agreement_id(&self) -> &str {
        &self.files.original.pending.association.agreement_id
    }
    pub(in crate::host) fn principal_id(&self) -> &str {
        &self.files.original.pending.association.principal_id
    }
    pub(in crate::host) fn reviewer_account_ids(&self) -> &[String] {
        &self.files.original.pending.association.reviewer_account_ids
    }
    pub(in crate::host) fn source_digest(&self) -> &str {
        &self.files.original.pending.association.source_digest
    }
    pub(in crate::host) fn native_association_digest(&self) -> &str {
        &self.files.original.committed.association_digest
    }
    pub(in crate::host) fn retention_policy(&self) -> &str {
        &self.files.original.pending.association.retention_policy
    }
    pub(in crate::host) fn metadata_destination(&self) -> &Path {
        &self.files.original.pending.association.database_path
    }
    pub(in crate::host) fn workspace_root(&self) -> &Path {
        &self.files.original.pending.association.workspace_root
    }
    pub(in crate::host) fn metadata_origin(&self) -> [u8; 32] {
        self.files.original.committed.original_database_origin
    }
    pub(in crate::host) fn proof_origin(&self) -> [u8; 32] {
        self.files.original.pending.proof.original_proof_origin
    }
    pub(in crate::host) fn status(&self) -> Result<PrivateWorkspaceStatusV1> {
        self.with_exact_fixed_v2(
            PrivateWorkspaceActionV1::ReadStatus,
            |coordinator, privacy| Ok(coordinator.status(self.host.access()?, privacy)?),
        )
    }
}
fn workspace_action_name(action: PrivateWorkspaceActionV1) -> &'static str {
    match action {
        PrivateWorkspaceActionV1::Create => "initialize exact original seed",
        PrivateWorkspaceActionV1::Reopen => "reopen initialized original",
        PrivateWorkspaceActionV1::ReadStatus => "read sanitized progress",
        PrivateWorkspaceActionV1::PrepareExactCandidate => "prepare exact candidate",
        PrivateWorkspaceActionV1::RetainExactMaterial => "retain exact sealed material",
        PrivateWorkspaceActionV1::ObserveExactMaterial => "observe current exact material",
        PrivateWorkspaceActionV1::CheckpointExactOriginal => "checkpoint one original constructor",
        PrivateWorkspaceActionV1::ProveOriginalOnce => "run one newly committed original proof",
        PrivateWorkspaceActionV1::FreezeVerifiedFixed => "freeze verified fixed identity",
        PrivateWorkspaceActionV1::ReadVerifiedFixed => "read retained verified fixed identity",
        _ => "unsupported operation",
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::host) struct OriginalWorkspaceComparisonV1 {
    pub profile_id: String,
    pub generation_id: String,
    pub generation_plan_digest: String,
    pub source_digest: String,
    pub host_directory_identity: String,
    pub workspace_directory_identity: String,
    pub financial_origin_digest: String,
    pub metadata_origin: [u8; 32],
    pub proof_origin: [u8; 32],
    pub native_association_digest: String,
    pub workspace_anchor: String,
}
impl Host {
    pub(in crate::host) fn private_workspace_comparison_v1(
        &self,
    ) -> Result<OriginalWorkspaceComparisonV1> {
        self.require_private_workspace_read_session_v1()?;
        let files = self.workspace_files.as_ref().ok_or(Error::Authentication)?;
        files.check_inventory(&self.directory, &self.secrets)?;
        let p = &files.original.pending;
        let c = &files.original.committed;
        self.financial
            .as_ref()
            .ok_or(Error::Locked)?
            .original_workspace_proof_v1()?
            .check_current()
            .map_err(|_| Error::Authentication)?;
        if self
            .financial
            .as_ref()
            .ok_or(Error::Locked)?
            .manual_original_primary_origin_digest(&self.directory, &self.secrets)?
            != p.association.original_financial_origin_digest
        {
            return Err(Error::Authentication);
        }
        Ok(OriginalWorkspaceComparisonV1 {
            profile_id: p.association.profile_id.clone(),
            generation_id: p.association.generation_id.clone(),
            generation_plan_digest: p.association.generation_plan_digest.clone(),
            source_digest: p.association.source_digest.clone(),
            host_directory_identity: p.association.host_directory_identity.clone(),
            workspace_directory_identity: c.workspace_directory_identity.clone(),
            financial_origin_digest: p.association.original_financial_origin_digest.clone(),
            metadata_origin: c.original_database_origin,
            proof_origin: p.proof.original_proof_origin,
            native_association_digest: c.association_digest.clone(),
            workspace_anchor: hex::encode(
                self.secrets
                    .private_workspace_anchor()
                    .ok_or(Error::Authentication)?,
            ),
        })
    }
    /// This is the only attended resume path. A fresh source-only publication
    /// inspection closes before a SECOND fresh final-v3 original reopening.
    pub(in crate::host) fn open_private_workspace_registered_v1(
        terminal: Terminal,
        profile: &Path,
        root: &Path,
        initialize: bool,
    ) -> Result<Self> {
        storage_begin(if initialize {
            "PrivateWorkspacePublish"
        } else {
            "PrivateWorkspaceReaderOpen"
        });
        let result = (|| {
            bounded_path(profile)?;
            bounded_path(root)?;
            let password = terminal.secret("Storage passphrase: ")?;
            let financial_password = terminal.secret("Original primary financial passphrase: ")?;
            if initialize {
                let directory = Directory::open(profile)?;
                let secrets = Secrets::open_private_workspace_v3(
                    &directory.read("profile.vault", 1024)?,
                    password.as_bytes(),
                )?;
                let files = OriginalWorkspacePublicationV1::inspect(&directory, &secrets)?;
                if files.pending.association.workspace_root != root {
                    return Err(Error::Authentication);
                }
                let approval = terminal.approve_historical(&format!(
                "Inspect exact anchored ORIGINAL files/source/financial/proof and saved seed plan, then complete only missing no-replace publication renames. Workspace: {}. No reconstruction, key replacement or proof is permitted.", root.display()))?;
                let exclusions = {
                    let source = PrivateWorkspacePublicationSourceV1::open(
                        &directory,
                        &secrets,
                        &files,
                        financial_password.as_bytes(),
                        &approval,
                    )?;
                    source.into_exclusions()?
                };
                approval.check()?;
                files.publish(&directory, &secrets, &exclusions, &approval)?;
                drop(exclusions);
                drop((secrets, directory));
                storage_complete("PrivateWorkspacePublish");
                storage_begin("PrivateWorkspaceInitialize");
            }
            // No publication evidence is accepted as final runtime evidence.
            let directory = reader_result!(
                ReaderProfileDirectory,
                observe_private_fixed_host_v1,
                Directory::open(profile)
            )?;
            let secrets = reader_result!(
                ReaderVaultV3Open,
                observe_private_fixed_host_v1,
                Secrets::open_private_workspace_v3(
                    &reader_result!(
                        ReaderVaultRead,
                        observe_private_fixed_host_v1,
                        directory.read("profile.vault", 1024)
                    )?,
                    password.as_bytes(),
                )
            )?;
            let files = reader_result!(
                ReaderFinalRegistry,
                observe_private_fixed_host_v1,
                OriginalWorkspaceFilesV1::open_final(&directory, &secrets)
            )?;
            if files.original.pending.association.workspace_root != root {
                return reader_result!(
                    ReaderSourceAssociation,
                    observe_private_fixed_host_v1,
                    Err(Error::Authentication)
                );
            }
            let approval = terminal.approve_historical(&format!(
            "Authenticate and read the exact final original workspace, complete original source and all four original primary journals before opening any runtime. Workspace: {}. This grants no financial authority.", root.display()))?;
            {
                let source = reader_result!(
                    ReaderSourceOpen,
                    observe_private_fixed_host_v1,
                    PrivateWorkspacePublicationSourceV1::open(
                        &directory,
                        &secrets,
                        &files.original,
                        financial_password.as_bytes(),
                        &approval,
                    )
                )?;
                reader_result!(
                    ReaderSourceAssociation,
                    observe_private_fixed_host_v1,
                    source.require_exact_association()
                )?;
            }
            reader_result!(
                ReaderSourceFinalCheck,
                observe_private_fixed_host_v1,
                approval.check()
            )?;
            let p = &files.original.pending;
            let financial = reader_result!(
                ReaderFinancialOpen,
                observe_private_fixed_host_v1,
                crate::financial_profile::FinancialProfile::open_private_workspace_original_v1(
                    &p.proof.financial_root,
                    &directory,
                    &secrets,
                    financial_password.as_bytes(),
                    &p.association.original_financial_origin_digest,
                    &p.proof.financial_directory_identity,
                    p.proof.original_proof_origin,
                )
            )?;
            let mut host = reader_result!(
                ReaderHostRuntime,
                observe_private_fixed_host_v1,
                Self::open_private_workspace_original(
                    directory, secrets, terminal, files, financial,
                )
            )?;
            reader_result!(ReaderEnroll, observe_private_fixed_host_v1, host.enroll())?;
            let saved_principal = &reader_result!(
                ReaderSavedPrincipal,
                observe_private_fixed_host_v1,
                host.workspace_files.as_ref().ok_or(Error::Authentication)
            )?
            .original
            .pending
            .association
            .principal_id;
            if reader_result!(
                ReaderSavedPrincipal,
                observe_private_fixed_host_v1,
                host.access()
            )?
            .principal_id
                != *saved_principal
            {
                return reader_result!(
                    ReaderSavedPrincipal,
                    observe_private_fixed_host_v1,
                    Err(Error::Permission)
                );
            }
            reader_result!(
                ReaderReadSession,
                observe_private_fixed_host_v1,
                host.require_private_workspace_read_session_v1()
            )?;
            if initialize {
                host.initialize_private_workspace_saved_v1(root)?;
            } else {
                storage_complete("PrivateWorkspaceReaderOpen");
            }
            Ok(host)
        })();
        if let Err(error) = &result {
            if !initialize {
                observe_private_fixed_host_v1(
                    PrivateDiagnosticOperationV1::OpenOriginal,
                    PrivateDiagnosticSiteV1::ReaderHostReturn,
                    error,
                );
            }
            storage_host_error(error);
        }
        result
    }
}

pub(super) fn create_command_v1(terminal: Terminal, profile: &Path, root: &Path) -> Result<()> {
    let directory = Directory::open(profile)?;
    directory.refuse_private_workspace_files()?;
    let password = terminal.secret("Storage passphrase: ")?;
    let secrets = Secrets::open(&directory.read("profile.vault", 1024)?, password.as_bytes())?;
    if directory.path("restored.quarantine")?.try_exists()? {
        return Err(Error::Quarantined);
    }
    let mut host = Host::open(directory, secrets, terminal.clone())?;
    host.enroll()?;
    host.financial_open(false)?;
    let agreement = terminal.ask("Exact original selected agreement ID: ")?;
    let retention = terminal.ask("Exact private workspace retention policy: ")?;
    host.create_private_durable_workspace_v1(&agreement, root, &retention, password.as_bytes())?;
    // Positive top-level creation requires both fresh publication and final-v3
    // reopen, followed by separately confirmed exact initialization.
    let host = Host::open_private_workspace_registered_v1(terminal.clone(), profile, root, true)?;
    host.private_workspace_comparison_v1()?;
    drop(host);
    terminal.message(
        "Original private workspace initialized. No candidate, material or proof was created.\n",
    )
}

#[cfg(test)]
#[path = "durable_private_workspace_v1_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "durable_private_workspace_v1_process_tests.rs"]
mod process_tests;

/// Foreground lifetime-bearing current native lease for awaited effects. This
/// exposes only the purpose-limited coordinator, never a shared Engine/Store.
pub(in crate::host) struct OwnedPrivateWorkspaceActionV2<'a, 'host> {
    owner: &'a PrivateWorkspaceOwnerV1<'host>,
    approval: HistoricalApproval,
    action: PrivateWorkspaceActionV1,
}
impl<'host> PrivateWorkspaceOwnerV1<'host> {
    pub(in crate::host) fn exact_fixed_action_v2<'a>(
        &'a self,
        action: PrivateWorkspaceActionV1,
    ) -> Result<OwnedPrivateWorkspaceActionV2<'a, 'host>> {
        require_exact_action(action)?;
        storage_action_boundary(action);
        self.check_originals()?;
        let approval = self.host.terminal.approve_historical(&format!(
            "Permit one exact current nonspending workspace effect: {}. Agreement: {}. Source: {}. Protected destination: {}. Audience: {:?}. Retention: {}. No financial admission, signature, export or submission is authorized.",
            workspace_action_name(action), self.agreement_id(), self.source_digest(), self.metadata_destination().display(), self.reviewer_account_ids(), self.retention_policy()))?;
        let result = OwnedPrivateWorkspaceActionV2 {
            owner: self,
            approval,
            action,
        };
        result.check()?;
        Ok(result)
    }
}
impl<'host> OwnedPrivateWorkspaceActionV2<'_, 'host> {
    pub(in crate::host) fn coordinator(&self) -> &PrivateDurableCoordinatorV1<'host> {
        &self.owner.coordinator
    }
    pub(in crate::host) fn deadline(&self) -> std::time::Instant {
        self.approval.deadline()
    }
    pub(in crate::host) fn check(&self) -> Result<()> {
        self.approval.check()?;
        self.owner.check_originals()
    }
}
impl LocalPrivateWorkspaceConsentV1 for OwnedPrivateWorkspaceActionV2<'_, '_> {
    fn permits_workspace(
        &self,
        scope: &PrivateWorkspaceScopeV1,
        action: PrivateWorkspaceActionV1,
    ) -> bool {
        let privacy = CurrentNativePrivacy {
            host: self.owner.host,
            committed: &self.owner.committed_target,
            association: &self.owner.files.original.pending.association,
            approval: &self.approval,
            action: self.action,
            observation: PrivateCurrentObservationV1::None,
        };
        if !privacy.permits_workspace(scope, action) {
            return false;
        }
        match self.owner.check_current_without_proof_lock_v2() {
            Ok(()) => true,
            Err(error) => {
                storage_host_error(&error);
                false
            }
        }
    }
}
fn require_exact_action(action: PrivateWorkspaceActionV1) -> Result<()> {
    if matches!(
        action,
        PrivateWorkspaceActionV1::ReadStatus
            | PrivateWorkspaceActionV1::PrepareExactCandidate
            | PrivateWorkspaceActionV1::RetainExactMaterial
            | PrivateWorkspaceActionV1::ObserveExactMaterial
            | PrivateWorkspaceActionV1::CheckpointExactOriginal
            | PrivateWorkspaceActionV1::ProveOriginalOnce
            | PrivateWorkspaceActionV1::FreezeVerifiedFixed
            | PrivateWorkspaceActionV1::ReadVerifiedFixed
    ) {
        Ok(())
    } else {
        Err(Error::Unsupported)
    }
}

impl Host {
    pub(in crate::host) fn require_private_workspace_read_session_v1(&self) -> Result<()> {
        self.directory.check()?;
        let principal = &self.access()?.principal_id;
        if !self.config.as_ref().is_some_and(|config| {
            config.clients.iter().any(|client| {
                &client.client_id == principal
                    && client
                        .permissions
                        .contains(&wholepact_service::security::Permission::Read)
            })
        }) {
            return Err(Error::Permission);
        }
        self.authority.check_financial_principal(principal)
    }
}

#[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
thread_local! {
    static STORAGE_BOUNDARY_V1: std::cell::Cell<&'static str> = const { std::cell::Cell::new("PrivateWorkspaceReserve") };
    static STORAGE_FIRST_FAILURE_V1: std::cell::RefCell<Option<(&'static str,&'static str)>> = const { std::cell::RefCell::new(None) };
}
#[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
pub(in crate::host) fn first_storage_failure_v1() -> Option<(&'static str, &'static str)> {
    STORAGE_FIRST_FAILURE_V1
        .try_with(|failure| failure.try_borrow().ok().and_then(|value| *value))
        .ok()
        .flatten()
}
pub(in crate::host) fn storage_action_boundary(action: PrivateWorkspaceActionV1) {
    let boundary = match action {
        PrivateWorkspaceActionV1::PrepareExactCandidate => "PrivateWorkspaceCandidate",
        PrivateWorkspaceActionV1::RetainExactMaterial => "PrivateWorkspaceIntake",
        PrivateWorkspaceActionV1::ObserveExactMaterial => "PrivateWorkspaceObserve",
        PrivateWorkspaceActionV1::CheckpointExactOriginal => "PrivateWorkspaceCheckpoint",
        PrivateWorkspaceActionV1::ProveOriginalOnce => "PrivateWorkspaceProof",
        PrivateWorkspaceActionV1::FreezeVerifiedFixed => "PrivateWorkspaceFreeze",
        PrivateWorkspaceActionV1::ReadVerifiedFixed | PrivateWorkspaceActionV1::ReadStatus => {
            "PrivateWorkspaceReadFixed"
        }
        _ => return,
    };
    #[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
    let _ = STORAGE_BOUNDARY_V1.try_with(|current| current.set(boundary));
    #[cfg(not(all(test, feature = "synthetic-born-joined-qualification")))]
    let _ = boundary;
}
fn storage_begin(boundary: &'static str) {
    #[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
    {
        use std::io::Write;
        let _ = STORAGE_BOUNDARY_V1.try_with(|current| current.set(boundary));
        let _ = writeln!(
            std::io::stderr().lock(),
            "\n[JOINED_DIAGNOSTIC {boundary} Begin]"
        );
    }
    #[cfg(not(all(test, feature = "synthetic-born-joined-qualification")))]
    let _ = boundary;
}
fn storage_complete(boundary: &'static str) {
    #[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
    {
        use std::io::Write;
        let _ = writeln!(
            std::io::stderr().lock(),
            "\n[JOINED_DIAGNOSTIC {boundary} Complete]"
        );
    }
    #[cfg(not(all(test, feature = "synthetic-born-joined-qualification")))]
    let _ = boundary;
}
fn storage_failure(outcome: &'static str) {
    #[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
    {
        use std::io::Write;
        let _ = STORAGE_FIRST_FAILURE_V1.try_with(|failure| {
            if let Ok(mut failure) = failure.try_borrow_mut() {
                if failure.is_none() {
                    if let Ok(boundary) = STORAGE_BOUNDARY_V1.try_with(|current| current.get()) {
                        *failure = Some((boundary, outcome));
                        observe_private_fixed_boundary_v1(boundary, outcome);
                        let _ = writeln!(
                            std::io::stderr().lock(),
                            "\n[JOINED_DIAGNOSTIC {boundary} {outcome}]"
                        );
                    }
                }
            }
        });
    }
    #[cfg(not(all(test, feature = "synthetic-born-joined-qualification")))]
    let _ = outcome;
}
fn storage_engine_error(error: wholepact_engine::ApiError) -> Error {
    let outcome = match error.code.as_str() {
        "DISCLOSURE_DENIED" => "EngineDisclosureDenied",
        "DURABLE_CONSTRUCTION_UNAVAILABLE" => "EngineDurableConstructionUnavailable",
        "DURABLE_PROPOSAL_RECOVERY_REQUIRED" => "EngineDurableProposalRecoveryRequired",
        "MISSING_EVIDENCE" => "EngineMissingEvidence",
        "INVALID_TERMS" => "EngineInvalidTerms",
        "UNSUPPORTED_CAPABILITY" => "EngineUnsupportedCapability",
        "DEBIT_CAP_EXCEEDED" => "EngineDebitCapExceeded",
        "PERMISSION_DENIED" => "EnginePermissionDenied",
        "INTERNAL_ERROR" => "EngineInternalError",
        "MANUAL_CONSTRUCTION_DENIED" => "EngineManualConstructionDenied",
        "RETAINED_INPUT_OBSERVATION_UNAVAILABLE" => "EngineRetainedObservationUnavailable",
        "CANDIDATE_VERIFICATION_FAILED" => "EngineCandidateVerificationFailed",
        "IDEMPOTENCY_CONFLICT" => "EngineIdempotencyConflict",
        "REVISION_CONFLICT" => "EngineRevisionConflict",
        "NOT_FOUND" => "EngineNotFound",
        "INVALID_REQUEST" => "EngineInvalidRequest",
        "RECOVERY_REQUIRED" => "EngineRecoveryRequired",
        "LIVE_AUTHORIZATION_EXISTS" => "EngineLiveAuthorizationExists",
        "RESOURCE_EXHAUSTED" => "EngineResourceExhausted",
        "INVALID_TRANSITION" => "EngineInvalidTransition",
        "STORAGE_PROTECTION_REQUIRED" => "EngineStorageProtectionRequired",
        "STORAGE_UNAVAILABLE" => "EngineStorageUnavailable",
        "ACCESS_DENIED" => "EngineAccessDenied",
        _ => "EngineUnclassified",
    };
    storage_failure(outcome);
    Error::from(error)
}
fn storage_host_error(error: &Error) {
    let outcome = match error {
        Error::Platform => "HostPlatform",
        Error::Terminal => "HostTerminal",
        Error::Permission => "HostPermission",
        Error::Locked => "HostLocked",
        Error::Invalid => "HostInvalid",
        Error::Authentication => "HostAuthentication",
        Error::Storage => "HostStorage",
        Error::Quarantined => "HostQuarantined",
        Error::Unsupported => "HostUnsupported",
        Error::Receipt(_) => "HostReceipt",
        Error::RecoverySemantic(_) => "HostRecoverySemantic",
        Error::RecoveryBackupUnsupported => "HostRecoveryBackupUnsupported",
        Error::RecoveryFinancialUnsupported => "HostRecoveryFinancialUnsupported",
        Error::CompleteOriginRecoveryUnavailable => "HostCompleteOriginRecoveryUnavailable",
        Error::HistoricalExportIncomplete => "HostHistoricalExportIncomplete",
        Error::GenerationArchiveIncomplete => "HostGenerationArchiveIncomplete",
    };
    storage_failure(outcome);
}

/// Inspection is current source-reading permission only, never an effect grant.
pub(in crate::host) struct OwnedPrivateWorkspaceInspectionV3<'a, 'host> {
    owner: &'a PrivateWorkspaceOwnerV1<'host>,
    approval: HistoricalApproval,
}
/// One genuine closed-stage decision. The nominal descriptor is consumed into
/// this owner; neither an old permission nor a caller-built scope can issue it.
pub(in crate::host) struct OwnedPrivateWorkspaceStageV3<'a, 'host> {
    owner: &'a PrivateWorkspaceOwnerV1<'host>,
    approval: HistoricalApproval,
    review: wholepact_engine::PrivateFixedStageReviewV3,
    scans: Option<super::financial::private_durable_fixed_v2::StageScanBindingsV3>,
    observation: PrivateStageObservationV1,
}
fn stage_workspace_action_v3(
    stage: wholepact_engine::PrivateFixedStageV3,
    action: PrivateWorkspaceActionV1,
) -> bool {
    use wholepact_engine::PrivateFixedStageV3 as S;
    use PrivateWorkspaceActionV1 as A;
    matches!(
        (stage, action),
        (S::Prepare, A::ObserveExactMaterial | A::PrepareFixedStageV3)
            | (
                S::AdmitOriginal,
                A::ObserveExactMaterial | A::CheckpointExactOriginal
            )
            | (S::ProveOriginal, A::ProveOriginalOnce)
            | (S::FreezeFixed, A::FreezeVerifiedFixed)
            | (S::ReadFixed, A::ReadVerifiedFixed)
    )
}
fn stage_proof_action_v3(
    stage: wholepact_engine::PrivateFixedStageV3,
    action: wholepact_proof_jobs::LocalAction,
) -> bool {
    use wholepact_engine::PrivateFixedStageV3 as S;
    use wholepact_proof_jobs::LocalAction as A;
    matches!(
        (stage, action),
        (S::AdmitOriginal, A::RetainPrivateWitnesses)
            | (
                S::ProveOriginal,
                A::InspectStatus | A::ProveLocally | A::RetainPrivateWitnesses
            )
            | (
                S::FreezeFixed | S::ReadFixed,
                A::InspectStatus | A::ReadPrivateArtifact
            )
    )
}
fn stage_actions_description_v3(stage: wholepact_engine::PrivateFixedStageV3) -> &'static str {
    use wholepact_engine::PrivateFixedStageV3 as S;
    match stage {
        S::Prepare => {
            "Workspace: ObserveExactMaterial, PrepareFixedStageV3. Materials: ReadForExactConstruction for exactly both original materials. Wallet: SynchronizePublicBlocks and SelectPrivateContribution only for the two listed original process-only owners/providers. One unpersisted randomized construction; no CheckpointExactOriginal, witness retention, receipt, enqueue, link, proof or freeze."
        }
        S::AdmitOriginal => {
            "Workspace: ObserveExactMaterial, CheckpointExactOriginal. Materials: ReadForExactConstruction for exactly both originals. Wallet: SynchronizePublicBlocks and SelectPrivateContribution only for the two listed original owners/providers. Proof: RetainPrivateWitnesses for exactly the prepared checkpoint. After genuine fresh observations, consume the same prepared bytes once for receipt, enqueue and original link. No InspectStatus permission for raced-in jobs, no reconstruction or retry."
        }
        S::ProveOriginal => {
            "Workspace: ProveOriginalOnce. Materials: ReadForExactConstruction for exactly both originals. Proof: InspectStatus, ProveLocally and RetainPrivateWitnesses for exactly this checkpoint. Consume the original queued attempt once; before/after computation and result commits require this same current decision. Expiry/cancellation never renews permission or retries the attempt; a post-compute or uncertain commit refusal can leave retained facts requiring recovery. No wallet scan."
        }
        S::FreezeFixed => {
            "Workspace: FreezeVerifiedFixed. Materials: ReadForExactConstruction for exactly both originals. Proof: InspectStatus and ReadPrivateArtifact for exactly this checkpoint. Verify the successful original lineage and persist only its fixed identity. No wallet scan, proof attempt or new checkpoint."
        }
        S::ReadFixed => {
            "Workspace: ReadVerifiedFixed. Materials: ReadForExactConstruction for exactly both originals. Proof: InspectStatus and ReadPrivateArtifact for exactly this checkpoint. Independently verify and read the retained original fixed identity only. No scan, construction, proof attempt, freeze, repair or write."
        }
    }
}
/// Shared exact-join/currentness gate. A denial has no review fallback.
fn stage_permission_v3(exact: bool, current: impl FnOnce() -> Result<()>) -> Result<()> {
    if !exact {
        return Err(Error::Permission);
    }
    current()
}
impl<'host> PrivateWorkspaceOwnerV1<'host> {
    /// Borrows the actual source owner, not the incidental preceding permission.
    pub(in crate::host) fn stage_coordinator_v3(&self) -> &PrivateDurableCoordinatorV1<'host> {
        &self.coordinator
    }
    pub(in crate::host) fn inspect_fixed_stage_v3(
        &self,
    ) -> Result<OwnedPrivateWorkspaceInspectionV3<'_, 'host>> {
        self.check_originals()?;
        let approval = self.host.terminal.approve_historical(&format!(
            "Inspect exact original private V3 stage metadata. Source: {}. Agreement: {}. Destination: {}. Audience: {:?}. Retention: {}. This read-only inspection may validate the original encrypted envelope and retained material consistency only to collect bounded review metadata; no construction/proof use, raw witness/artifact output, scan or effects.",
            self.source_digest(), self.agreement_id(), self.metadata_destination().display(), self.reviewer_account_ids(), self.retention_policy()))?;
        let inspection = OwnedPrivateWorkspaceInspectionV3 {
            owner: self,
            approval,
        };
        inspection.check()?;
        Ok(inspection)
    }
    fn check_stage_descriptor_v3(
        &self,
        review: &wholepact_engine::PrivateFixedStageReviewV3,
    ) -> Result<()> {
        self.check_current_without_proof_lock_v2()?;
        if review.stage() == wholepact_engine::PrivateFixedStageV3::ReadFixed {
            reader_result!(
                HostWorkspaceSessionCheck,
                observe_private_fixed_host_v1,
                self.host.require_private_workspace_read_session_v1()
            )?;
        } else {
            reader_result!(
                HostWorkspaceSessionCheck,
                observe_private_fixed_host_v1,
                self.host.require_manual_session()
            )?;
        }
        let scope = review.workspace_scope();
        let a = &self.files.original.pending.association;
        if scope.source_digest() != a.source_digest
            || scope.principal_id() != a.principal_id
            || scope.agreement_id() != a.agreement_id
            || scope.obligation_id() != a.obligation_id
            || scope.reviewer_account_ids() != a.reviewer_account_ids
            || scope.protected_destination() != a.database_path
            || scope.retention_policy() != a.retention_policy
            || review.marker_digest() != self.files.original.committed.seed.marker_digest
            || review.native_association_digest() != self.native_association_digest()
            || review.metadata_origin() != hex::encode(self.metadata_origin())
            || review.proof_origin() != hex::encode(self.proof_origin())
            || (review.stage() == wholepact_engine::PrivateFixedStageV3::Prepare)
                != review.checkpoint_scope().is_none()
        {
            return Err(Error::Authentication);
        }
        super::financial::private_durable_fixed_v2::check_stage_material_review_v3(
            self.host, self, review,
        )
    }
    pub(in crate::host) fn approve_fixed_stage_v3<'a>(
        &'a self,
        inspection: OwnedPrivateWorkspaceInspectionV3<'a, 'host>,
        review: wholepact_engine::PrivateFixedStageReviewV3,
        scans: Option<super::financial::private_durable_fixed_v2::StageScanBindingsV3>,
        check_scans: impl Fn() -> Result<()>,
    ) -> Result<OwnedPrivateWorkspaceStageV3<'a, 'host>> {
        if !std::ptr::eq(self, inspection.owner) {
            return Err(Error::Authentication);
        }
        inspection.check()?;
        self.check_stage_descriptor_v3(&review)?;
        let needs_scans = matches!(
            review.stage(),
            wholepact_engine::PrivateFixedStageV3::Prepare
                | wholepact_engine::PrivateFixedStageV3::AdmitOriginal
        );
        if needs_scans != scans.is_some() {
            return Err(Error::Authentication);
        }
        if let Some(scans) = &scans {
            scans.check_review(&review)?;
        }
        check_scans()?;
        let detail = format!(
            "Approve V3 private fixed stage {:?}.\n{}\nOriginal process-only scan owners: {}\nClosed actions: {}\nThis permits only the closed actions listed for this stage, under one new 120-second native decision. Both original material absolute ceilings remain unchanged. No financial admission, signing, export, submission, regeneration, retry or permission renewal is authorized.",
            review.stage(),
            serde_json::to_string_pretty(&review).map_err(|_| Error::Invalid)?,
            serde_json::to_string_pretty(&scans).map_err(|_| Error::Invalid)?,
            stage_actions_description_v3(review.stage())
        );
        let check_source = || {
            self.check_originals()?;
            check_scans()?;
            self.check_stage_descriptor_v3(&review)
        };
        let approval = self.host.terminal.approve_private_fixed_stage_v3(
            &inspection.approval,
            &detail,
            &check_source,
            &check_source,
        )?;
        // The completed inspection is deliberately not checked after the wait.
        drop(inspection);
        let observation = begin_private_stage_cost_v1(review.stage(), approval.deadline());
        let stage = OwnedPrivateWorkspaceStageV3 {
            owner: self,
            approval,
            review,
            scans,
            observation,
        };
        check_scans()?;
        stage.check()?;
        Ok(stage)
    }
}
impl OwnedPrivateWorkspaceInspectionV3<'_, '_> {
    fn check(&self) -> Result<()> {
        self.approval.check()?;
        self.owner
            .host
            .require_private_workspace_read_session_v1()?;
        self.owner.check_originals()?;
        self.approval.check()
    }
}
impl LocalPrivateWorkspaceConsentV1 for OwnedPrivateWorkspaceInspectionV3<'_, '_> {
    fn permits_workspace(
        &self,
        scope: &PrivateWorkspaceScopeV1,
        action: PrivateWorkspaceActionV1,
    ) -> bool {
        action == PrivateWorkspaceActionV1::InspectFixedStageMetadataV3
            && CurrentNativePrivacy {
                host: self.owner.host,
                committed: &self.owner.committed_target,
                association: &self.owner.files.original.pending.association,
                approval: &self.approval,
                action,
                observation: PrivateCurrentObservationV1::Inspection,
            }
            .permits_workspace(scope, action)
            && match self
                .owner
                .check_current_without_proof_lock_v2()
                .and_then(|()| self.approval.check())
            {
                Ok(()) => true,
                Err(error) => {
                    observe_private_fixed_host_v1(
                        PrivateDiagnosticOperationV1::OpenOriginal,
                        PrivateDiagnosticSiteV1::HostWorkspaceCurrent,
                        &error,
                    );
                    storage_host_error(&error);
                    false
                }
            }
    }
}
impl OwnedPrivateWorkspaceStageV3<'_, '_> {
    pub(in crate::host) fn deadline(&self) -> std::time::Instant {
        self.approval.deadline()
    }
    pub(in crate::host) fn check(&self) -> Result<()> {
        self.observation.observe(
            PrivateDiagnosticSiteV1::HostWorkspaceNativeCheck,
            self.approval.check(),
        )?;
        self.observation.observe(
            PrivateDiagnosticSiteV1::HostWorkspaceSourceCheck,
            self.owner.check_originals(),
        )?;
        self.check_callback()
    }
    pub(in crate::host) fn check_callback(&self) -> Result<()> {
        self.observation.callback(|| {
            self.observation.observe(
                PrivateDiagnosticSiteV1::HostWorkspaceNativeCheck,
                self.approval.check(),
            )?;
            self.observation.observe(
                PrivateDiagnosticSiteV1::HostWorkspaceSourceCheck,
                self.owner.check_stage_descriptor_v3(&self.review),
            )?;
            self.observation.observe(
                PrivateDiagnosticSiteV1::HostWorkspaceNativeCheck,
                self.approval.check(),
            )
        })
    }
    fn storage_boundary(&self) {
        use wholepact_engine::PrivateFixedStageV3 as S;
        storage_action_boundary(match self.review.stage() {
            S::Prepare => PrivateWorkspaceActionV1::ObserveExactMaterial,
            S::AdmitOriginal => PrivateWorkspaceActionV1::CheckpointExactOriginal,
            S::ProveOriginal => PrivateWorkspaceActionV1::ProveOriginalOnce,
            S::FreezeFixed => PrivateWorkspaceActionV1::FreezeVerifiedFixed,
            S::ReadFixed => PrivateWorkspaceActionV1::ReadVerifiedFixed,
        });
    }
    fn permission_at(&self, exact: bool, site: PrivateDiagnosticSiteV1) -> bool {
        self.storage_boundary();
        match stage_permission_v3(exact, || self.check_callback()) {
            Ok(()) => true,
            Err(error) => {
                use wholepact_engine::PrivateFixedStageV3 as S;
                let operation = match self.review.stage() {
                    S::Prepare | S::AdmitOriginal => PrivateDiagnosticOperationV1::Checkpoint,
                    S::ProveOriginal => PrivateDiagnosticOperationV1::Proof,
                    S::FreezeFixed => PrivateDiagnosticOperationV1::Freeze,
                    S::ReadFixed => PrivateDiagnosticOperationV1::ReadFixed,
                };
                observe_private_fixed_host_v1(operation, site, &error);
                storage_host_error(&error);
                false
            }
        }
    }
    pub(in crate::host) fn scan_bindings(
        &self,
    ) -> Option<&super::financial::private_durable_fixed_v2::StageScanBindingsV3> {
        self.scans.as_ref()
    }
}
impl LocalPrivateWorkspaceConsentV1 for OwnedPrivateWorkspaceStageV3<'_, '_> {
    fn permits_workspace(
        &self,
        scope: &PrivateWorkspaceScopeV1,
        action: PrivateWorkspaceActionV1,
    ) -> bool {
        storage_action_boundary(action);
        stage_workspace_action_v3(self.review.stage(), action)
            && CurrentNativePrivacy {
                host: self.owner.host,
                committed: &self.owner.committed_target,
                association: &self.owner.files.original.pending.association,
                approval: &self.approval,
                action,
                observation: PrivateCurrentObservationV1::Stage(&self.observation),
            }
            .permits_workspace(scope, action)
            && self.permission_at(true, PrivateDiagnosticSiteV1::HostWorkspaceCurrent)
    }
}
impl wholepact_engine::durable_construction_v1::LocalDurableMaterialConsentV1
    for OwnedPrivateWorkspaceStageV3<'_, '_>
{
    fn permits(
        &self,
        scope: &wholepact_signer::authority_bridge::durable_construction_v1::DurableConstructionScopeV1,
        digest: &str,
        action: wholepact_engine::durable_construction_v1::DurableMaterialActionV1,
    ) -> bool {
        self.permission_at(
            matches!(action, wholepact_engine::durable_construction_v1::DurableMaterialActionV1::ReadForExactConstruction)
                && self.review.materials().iter().any(|material| material.scope() == scope && material.material_digest() == digest),
            PrivateDiagnosticSiteV1::HostMaterialScope)
    }
}
impl wholepact_proof_jobs::LocalProofConsent for OwnedPrivateWorkspaceStageV3<'_, '_> {
    fn permits(
        &self,
        scope: &wholepact_proof_jobs::CheckpointScope,
        action: wholepact_proof_jobs::LocalAction,
    ) -> bool {
        self.permission_at(
            stage_proof_action_v3(self.review.stage(), action)
                && self.review.checkpoint_scope() == Some(scope),
            PrivateDiagnosticSiteV1::HostProofScope,
        )
    }
}

#[cfg(test)]
mod closed_stage_v3_tests {
    use super::*;
    use wholepact_engine::PrivateFixedStageV3 as S;
    use wholepact_proof_jobs::LocalAction as P;
    #[test]
    fn stage_workspace_matrix_and_legacy_issuers_remain_closed() {
        use PrivateWorkspaceActionV1 as A;
        let actions = [
            A::Create,
            A::Reopen,
            A::ReadStatus,
            A::RetainDiscovery,
            A::RetainProjection,
            A::FreezeCandidate,
            A::PrepareExactCandidate,
            A::RetainExactMaterial,
            A::ObserveExactMaterial,
            A::CheckpointExactOriginal,
            A::ProveOriginalOnce,
            A::FreezeVerifiedFixed,
            A::ReadVerifiedFixed,
            A::InspectFixedStageMetadataV3,
            A::PrepareFixedStageV3,
        ];
        for (stage, expected) in [
            (
                S::Prepare,
                vec![A::ObserveExactMaterial, A::PrepareFixedStageV3],
            ),
            (
                S::AdmitOriginal,
                vec![A::ObserveExactMaterial, A::CheckpointExactOriginal],
            ),
            (S::ProveOriginal, vec![A::ProveOriginalOnce]),
            (S::FreezeFixed, vec![A::FreezeVerifiedFixed]),
            (S::ReadFixed, vec![A::ReadVerifiedFixed]),
        ] {
            for action in actions {
                assert_eq!(
                    stage_workspace_action_v3(stage, action),
                    expected.contains(&action)
                );
            }
        }
        assert!(require_exact_action(A::InspectFixedStageMetadataV3).is_err());
        assert!(require_exact_action(A::PrepareFixedStageV3).is_err());
    }
    #[test]
    fn stage_proof_matrix_has_no_prepare_or_recovery_authority() {
        for (stage, expected) in [
            (S::Prepare, vec![]),
            (S::AdmitOriginal, vec![P::RetainPrivateWitnesses]),
            (
                S::ProveOriginal,
                vec![P::InspectStatus, P::ProveLocally, P::RetainPrivateWitnesses],
            ),
            (
                S::FreezeFixed,
                vec![P::InspectStatus, P::ReadPrivateArtifact],
            ),
            (S::ReadFixed, vec![P::InspectStatus, P::ReadPrivateArtifact]),
        ] {
            for action in [
                P::InspectStatus,
                P::ProveLocally,
                P::RetainPrivateWitnesses,
                P::ReadPrivateArtifact,
                P::RecoverInterrupted,
            ] {
                assert_eq!(
                    stage_proof_action_v3(stage, action),
                    expected.contains(&action)
                );
            }
        }
    }
    #[test]
    fn exact_stage_permission_rechecks_currentness_and_never_retries_refusal() {
        let calls = std::cell::Cell::new(0);
        for _ in 0..2 {
            assert!(
                stage_permission_v3(true, || {
                    calls.set(calls.get() + 1);
                    Ok(())
                })
                .is_ok()
            );
        }
        assert_eq!(calls.get(), 2);
        assert!(
            stage_permission_v3(false, || {
                calls.set(99);
                Ok(())
            })
            .is_err()
        );
        assert_eq!(calls.get(), 2);
        assert!(matches!(
            stage_permission_v3(true, || {
                calls.set(calls.get() + 1);
                Err(Error::Permission)
            }),
            Err(Error::Permission)
        ));
        assert_eq!(calls.get(), 3);
    }
    #[test]
    fn full_stage_disclosure_names_closed_actions_and_uncertain_proof_semantics() {
        let prepare = stage_actions_description_v3(S::Prepare);
        assert!(prepare.contains("PrepareFixedStageV3"));
        assert!(prepare.contains("no CheckpointExactOriginal"));
        assert!(stage_actions_description_v3(S::AdmitOriginal).contains("No InspectStatus"));
        assert!(
            stage_actions_description_v3(S::ProveOriginal).contains("uncertain commit refusal")
        );
        assert!(
            stage_actions_description_v3(S::ReadFixed)
                .contains("No scan, construction, proof attempt, freeze, repair or write")
        );
    }
}
