//! INACTIVE, nonspending workspace owner. No command/IPC registration exists.
//! Activation needs qualified all-entrypoint dependency guards and the narrow
//! audited recovery_generation wrapping hooks named below. Until then create
//! and reopen fail closed before inspecting or writing private data.
use super::Host;
use crate::{
    files::Directory, recovery_generation::manual_target::ManualCommittedTarget,
    terminal::historical::HistoricalApproval, Error, Result,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};
use wholepact_engine::durable_private_workspace_v1::{
    LocalPrivateWorkspaceConsentV1, PrivateDurableCoordinatorV1, PrivateDurableWorkspaceSourceV1,
    PrivateWorkspaceActionV1, PrivateWorkspaceScopeV1, PrivateWorkspaceStatusV1,
};
use wholepact_storage_security::DatabaseKey;
use zeroize::{Zeroize, Zeroizing};

const PENDING: &str = "durable-private.pending-v1";
const COMMIT: &str = "durable-private.commit-v1";
const DATABASE: &str = "private-coordination.sqlite";
const PURPOSE: &str = "durable-private-coordination-v1";
const MAX_REGISTRY: usize = 131_072;
const PENDING_WRAP: &[u8] = b"durable-private:pending:v1";
const COMMIT_WRAP: &[u8] = b"durable-private:commit:v1";

/// No existing financial/wallet attachment role is reused. This exact private
/// association is encrypted metadata, NOT a current permission or financial
/// origin. It binds original selected FVK/policy/roster/terms via source_digest.
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
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    association: Association,
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
    association_digest: String,
    workspace_directory_identity: String,
    original_database_origin: [u8; 32],
}
fn digest<T: Serialize>(value: &T) -> Result<String> {
    wholepact_core::proposal::canonical_digest(
        "wholepact:native-private-workspace-association:v1",
        value,
    )
    .map_err(|_| Error::Authentication)
}
fn bytes_digest(value: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(value))
}
fn present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Mandatory parent hook for ALL old backup/export/restore/generation paths.
/// Presence, including partial pending or malformed ciphertext, refuses. No
/// old metadata-only archive is complete qualified dependency coverage.
pub(crate) fn refuse_unqualified_private_workspace_backup_v1(directory: &Directory) -> Result<()> {
    directory.check()?;
    if present(&directory.path(PENDING)?)? || present(&directory.path(COMMIT)?)? {
        return Err(Error::RecoveryFinancialUnsupported);
    }
    Ok(())
}
/// Deliberately unimplemented activation fence, not a permission boolean. Root
/// must replace this ONLY after wiring+testing the preceding guard throughout
/// backup/recovery and original-dependency qualification. Check every existing
/// Host/manual-target inventory too: adding PENDING/COMMIT must not invalidate
/// the same held original source immediately after reservation. No test bypass exists.
fn require_qualified_private_dependency_coverage_v1() -> Result<()> {
    Err(Error::RecoveryFinancialUnsupported)
}

/// Real Directory owner is LAST: the sole coordinator and its original source
/// and committed parent owners are dropped before the workspace exclusion lock.
/// No raw Engine/Store/Directory or key getters and no Clone/serde/Deref.
pub(in crate::host) struct PrivateWorkspaceOwnerV1<'host> {
    coordinator: PrivateDurableCoordinatorV1<'host>,
    committed_target: ManualCommittedTarget<'host>,
    host: &'host Host,
    pending: Pending,
    committed: Committed,
    pending_ciphertext_digest: String,
    commit_ciphertext_digest: String,
    directory: Directory,
}

struct CurrentNativePrivacy<'a, 'host> {
    host: &'host Host,
    committed: &'a ManualCommittedTarget<'host>,
    association: &'a Association,
    approval: &'a HistoricalApproval,
    action: PrivateWorkspaceActionV1,
}
impl CurrentNativePrivacy<'_, '_> {
    fn check(&self) -> Result<()> {
        self.approval.check()?;
        self.host.require_manual_session()?;
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
                .manual_original_primary_origin_digest(&self.host.directory, &self.host.secrets)?
                != self.association.original_financial_origin_digest
        {
            return Err(Error::Authentication);
        }
        self.approval.check()
    }
}
impl LocalPrivateWorkspaceConsentV1 for CurrentNativePrivacy<'_, '_> {
    fn permits_workspace(
        &self,
        scope: &PrivateWorkspaceScopeV1,
        action: PrivateWorkspaceActionV1,
    ) -> bool {
        self.action == action
            && scope.source_digest() == self.association.source_digest
            && scope.principal_id() == self.association.principal_id
            && scope.agreement_id() == self.association.agreement_id
            && scope.obligation_id() == self.association.obligation_id
            && scope.reviewer_account_ids() == self.association.reviewer_account_ids
            && scope.protected_destination() == self.association.database_path
            && scope.retention_policy() == self.association.retention_policy
            && self.check().is_ok()
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
    host.require_manual_session()?;
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
    host.require_manual_session()?;
    source.check_current(host.access()?)?;
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

impl Host {
    /// No arbitrary selected-source DTO is accepted. All actual lineage and
    /// original account/roster/terms commitments come from these held owners.
    fn private_workspace_source_owners_v1<'host>(
        &'host self,
        agreement_id: &str,
    ) -> Result<(
        ManualCommittedTarget<'host>,
        PrivateDurableWorkspaceSourceV1<'host>,
        HistoricalApproval,
    )> {
        self.require_manual_session()?;
        let review = self.terminal.approve_historical(&format!(
            "Inspect the exact current selected agreement, complete original historical terms, selected intents and original account/FVK/policy roster associations for a separately keyed NONSPENDING private coordination workspace.\nAgreement: {agreement_id}\nThis reads supported original parent coverage, not financial clearance. Original candidates, proof journals, grants, witness exposure and reservations are neither copied nor cleared."
        ))?;
        let mut owners = None;
        review.effect(&mut || {
            self.require_manual_session()?;
            let committed = ManualCommittedTarget::open(&self.directory, &self.secrets)?;
            committed.coverage().require_complete()?;
            let source = self
                .engine
                .private_durable_workspace_source_v1(self.access()?, agreement_id)?;
            source.check_current(self.access()?)?;
            committed.check_current()?;
            owners = Some((committed, source));
            Ok(())
        })?;
        let (committed, source) = owners.ok_or(Error::Authentication)?;
        Ok((committed, source, review))
    }
    pub(in crate::host) fn create_private_durable_workspace_v1<'host>(
        &'host self,
        agreement_id: &str,
        root: &Path,
        retention_policy: &str,
    ) -> Result<PrivateWorkspaceOwnerV1<'host>> {
        require_qualified_private_dependency_coverage_v1()?;
        refuse_unqualified_private_workspace_backup_v1(&self.directory)?;
        if present(root)? {
            return Err(Error::Authentication);
        }
        let (committed_target, source, review) =
            self.private_workspace_source_owners_v1(agreement_id)?;
        let binding = association(
            self,
            &committed_target,
            &source,
            hex::encode(crate::random::<32>()?),
            root,
            retention_policy,
        )?;
        let review_digest = digest(&binding)?;
        let approval = self.terminal.approve_historical_reviewed(&review, &format!(
            "Create this exact purpose-distinct private coordinator dependency and fresh wrapped database key.\nAssociation digest: {review_digest}\nDestination: {}\nPrincipal: {}\nLocal reviewer account audience: {:?}\nRetention: {}\nThe original selected terms AND complete original historical terms committed by {} are included solely for validation provenance. Host constructor OS access is NOT cryptographic confidentiality from that constructor. The encrypted dependency is durably committed before any workspace metadata; all old metadata-only backup/recovery must refuse until complete qualified coverage exists. No signer pairing, scan, proof, spend, exposure reset or reservation refund is approved.",
            binding.database_path.display(), binding.principal_id, binding.reviewer_account_ids, binding.retention_policy, binding.source_digest
        ))?;
        let pending = Pending {
            association: binding,
            database_key: crate::random::<32>()?,
        };
        let mut source = Some(source);
        let mut created = None;
        approval.effect(&mut || {
            let privacy = CurrentNativePrivacy {
                host: self,
                committed: &committed_target,
                association: &pending.association,
                approval: &approval,
                action: PrivateWorkspaceActionV1::Create,
            };
            privacy.check()?;
            source
                .as_ref()
                .ok_or(Error::Authentication)?
                .check_current(self.access()?)?;
            refuse_unqualified_private_workspace_backup_v1(&self.directory)?;
            check_workspace_destination(self, root)?;
            if present(root)? {
                return Err(Error::Authentication);
            }
            let plain = Zeroizing::new(serde_json::to_vec(&pending)?);
            // Missing trusted parent hook: this narrowly delegates the existing
            // audited seal(), using only PENDING_WRAP or COMMIT_WRAP. No new crypto.
            let sealed = crate::recovery_generation::seal_private_workspace_dependency_v1(
                &self.secrets,
                PENDING_WRAP,
                &plain,
            )?;
            self.directory.write_new(PENDING, &sealed)?;
            let pending_ciphertext_digest = bytes_digest(&sealed);
            // A crash after PENDING is preserved and refuses reopen without the
            // original completed file; NEVER continue by initializing an empty DB.
            // Recheck the same actual roots after pending durability and directly
            // before create. Any new/unknown dependency preserves PENDING and denies.
            check_workspace_destination(self, root)?;
            let directory = Directory::create(root)?;
            privacy.check()?;
            let coordinator = PrivateDurableCoordinatorV1::create_new(
                source.take().ok_or(Error::Authentication)?,
                self.access()?,
                &directory.path(DATABASE)?,
                &DatabaseKey::from_bytes(pending.database_key),
                retention_policy,
                &privacy,
            )?;
            directory.check()?;
            let committed = Committed {
                version: 1,
                pending_ciphertext_digest: pending_ciphertext_digest.clone(),
                association_digest: digest(&pending.association)?,
                workspace_directory_identity: directory.manual_target_identity_digest()?,
                original_database_origin: coordinator.original_origin(),
            };
            privacy.check()?;
            let commit_plain = Zeroizing::new(serde_json::to_vec(&committed)?);
            let commit = crate::recovery_generation::seal_private_workspace_dependency_v1(
                &self.secrets,
                COMMIT_WRAP,
                &commit_plain,
            )?;
            self.directory.write_new(COMMIT, &commit)?;
            created = Some((
                coordinator,
                directory,
                committed,
                pending_ciphertext_digest,
                bytes_digest(&commit),
            ));
            Ok(())
        })?;
        let (
            coordinator,
            directory,
            committed,
            pending_ciphertext_digest,
            commit_ciphertext_digest,
        ) = created.ok_or(Error::Authentication)?;
        Ok(PrivateWorkspaceOwnerV1 {
            coordinator,
            committed_target,
            host: self,
            pending,
            committed,
            pending_ciphertext_digest,
            commit_ciphertext_digest,
            directory,
        })
    }
    pub(in crate::host) fn reopen_private_durable_workspace_v1<'host>(
        &'host self,
        agreement_id: &str,
        root: &Path,
        retention_policy: &str,
    ) -> Result<PrivateWorkspaceOwnerV1<'host>> {
        require_qualified_private_dependency_coverage_v1()?;
        let (committed_target, source, review) =
            self.private_workspace_source_owners_v1(agreement_id)?;
        let approval = self.terminal.approve_historical_reviewed(&review, &format!(
            "Authenticate and reopen ONLY the original complete private coordinator dependency, original wrapped key and original directory/database.\nAgreement: {agreement_id}\nDestination: {}\nRetention: {retention_policy}\nCurrent original selected and historical terms are compared privately. No missing file is recreated; no copied, partial, substituted or recovered backup is adopted. This is not renewed signer permission and does not clear exposure.", root.display()
        ))?;
        let mut source = Some(source);
        let mut opened = None;
        approval.effect(&mut || {
            self.require_manual_session()?;
            let sealed = self.directory.read(PENDING, MAX_REGISTRY)?;
            let commit_sealed = self.directory.read(COMMIT, MAX_REGISTRY)?;
            let plain = crate::recovery_generation::unseal_private_workspace_dependency_v1(
                &self.secrets,
                PENDING_WRAP,
                &sealed,
            )?;
            let commit_plain = crate::recovery_generation::unseal_private_workspace_dependency_v1(
                &self.secrets,
                COMMIT_WRAP,
                &commit_sealed,
            )?;
            let pending: Pending =
                wholepact_core::parse_typed_json(&plain).map_err(|_| Error::Authentication)?;
            let committed: Committed = wholepact_core::parse_typed_json(&commit_plain)
                .map_err(|_| Error::Authentication)?;
            let current = association(
                self,
                &committed_target,
                source.as_ref().ok_or(Error::Authentication)?,
                pending.association.dependency_id.clone(),
                root,
                retention_policy,
            )?;
            let pending_ciphertext_digest = bytes_digest(&sealed);
            require_original_registry(&pending, &committed, &current, &pending_ciphertext_digest)?;
            let directory = Directory::open(root)?;
            directory.inventory_of(&[DATABASE], &["profile.lock"])?;
            if directory.manual_target_identity_digest()? != committed.workspace_directory_identity
            {
                return Err(Error::Authentication);
            }
            let privacy = CurrentNativePrivacy {
                host: self,
                committed: &committed_target,
                association: &pending.association,
                approval: &approval,
                action: PrivateWorkspaceActionV1::Reopen,
            };
            privacy.check()?;
            let coordinator = PrivateDurableCoordinatorV1::open_original(
                source.take().ok_or(Error::Authentication)?,
                self.access()?,
                &directory.path(DATABASE)?,
                &DatabaseKey::from_bytes(pending.database_key),
                committed.original_database_origin,
                retention_policy,
                &privacy,
            )?;
            privacy.check()?;
            opened = Some((
                coordinator,
                directory,
                pending,
                committed,
                pending_ciphertext_digest,
                bytes_digest(&commit_sealed),
            ));
            Ok(())
        })?;
        let (
            coordinator,
            directory,
            pending,
            committed,
            pending_ciphertext_digest,
            commit_ciphertext_digest,
        ) = opened.ok_or(Error::Authentication)?;
        Ok(PrivateWorkspaceOwnerV1 {
            coordinator,
            committed_target,
            host: self,
            pending,
            committed,
            pending_ciphertext_digest,
            commit_ciphertext_digest,
            directory,
        })
    }
}
fn require_original_registry(
    pending: &Pending,
    committed: &Committed,
    current: &Association,
    pending_digest: &str,
) -> Result<()> {
    if pending.association != *current
        || pending.association.version != 1
        || pending.association.purpose != PURPOSE
        || pending.association.dependency_id.len() != 64
        || committed.version != 1
        || committed.association_digest != digest(&pending.association)?
        || committed.pending_ciphertext_digest != pending_digest
    {
        return Err(Error::Authentication);
    }
    Ok(())
}
impl PrivateWorkspaceOwnerV1<'_> {
    fn check_originals(&self) -> Result<()> {
        self.host.require_manual_session()?;
        self.committed_target.check_current()?;
        self.directory.check()?;
        if self.directory.manual_target_identity_digest()?
            != self.committed.workspace_directory_identity
            || bytes_digest(&self.host.directory.read(PENDING, MAX_REGISTRY)?)
                != self.pending_ciphertext_digest
            || bytes_digest(&self.host.directory.read(COMMIT, MAX_REGISTRY)?)
                != self.commit_ciphertext_digest
        {
            return Err(Error::Authentication);
        }
        self.directory.inventory_of(&[DATABASE], &["profile.lock"])
    }
    pub(in crate::host) fn status(&self) -> Result<PrivateWorkspaceStatusV1> {
        self.check_originals()?;
        let approval = self.host.terminal.approve_historical(&format!(
            "Read sanitized progress only for the original private coordinator.\nAgreement: {}\nNo selected IDs, input values, recipients, raw operations or generic agreement views are returned.", self.pending.association.agreement_id
        ))?;
        let mut result = None;
        approval.effect(&mut || {
            self.check_originals()?;
            let privacy = CurrentNativePrivacy {
                host: self.host,
                committed: &self.committed_target,
                association: &self.pending.association,
                approval: &approval,
                action: PrivateWorkspaceActionV1::ReadStatus,
            };
            result = Some(self.coordinator.status(self.host.access()?, &privacy)?);
            self.check_originals()
        })?;
        result.ok_or(Error::Authentication)
    }
}

#[cfg(test)]
#[path = "durable_private_workspace_v1_tests.rs"]
mod tests;
