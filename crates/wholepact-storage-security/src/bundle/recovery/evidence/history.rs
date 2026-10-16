//! Current, exact disclosure gates for immutable recovered artifacts. These
//! capabilities never become runtime grants, signatures, observations or replay.
use super::RecoveredEvidence;
use crate::{
    bundle::{
        BundleError,
        recovery::{RecoveryProvenance, generation::GenerationBinding},
    },
    generation_archive::{ArchivedGenerationSource, ArchivedOrdinarySource},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{path::PathBuf, sync::Arc};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, BundleError>;
pub const MAX_HISTORICAL_METADATA_BYTES: usize = 128 * 1024;
pub const MAX_HISTORICAL_TRANSACTION_BYTES: usize = 1024 * 1024;

/// One actual authenticated in-memory evidence snapshot, not a serializable ID.
#[derive(Clone)]
pub struct HistoricalSourceBinding(Arc<()>);
impl HistoricalSourceBinding {
    pub(crate) fn fresh() -> Self {
        Self(Arc::new(()))
    }
}
impl PartialEq for HistoricalSourceBinding {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for HistoricalSourceBinding {}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalAction {
    ParticipantRecord,
    ProofMetadata,
    SignedResultMetadata,
    TransactionMetadata,
    ExportExactTransaction,
}
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalDestination {
    NativeTerminal,
    NewPrivateLocalFile(PathBuf),
}
/// Authenticated archive location, minted only when a verified archive journal
/// is successfully opened. These labels describe integrity, never permission.
/// There is intentionally no public constructor or deserialization boundary.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct HistoricalArchiveOrigin {
    pub(crate) root_manifest_digest: String,
    pub(crate) root_capsule_id: String,
    pub(crate) selected_manifest_digest: String,
    pub(crate) selected_node_digest: String,
    pub(crate) selected_capsule_id: String,
    pub(crate) selected_generation_id: String,
    pub(crate) selected_profile_id: String,
    pub(crate) selected_original_root: String,
    pub(crate) entry_id: String,
    pub(crate) role: String,
    pub(crate) original_path: String,
    // Current journal row commitment. For generation sources this is distinct
    // from the immutable original marker provenance retained on HistoricalOrigin.
    pub(crate) source_provenance: RecoveryProvenance,
}
impl HistoricalArchiveOrigin {
    pub fn root_manifest_digest(&self) -> &str {
        &self.root_manifest_digest
    }
    pub fn root_capsule_id(&self) -> &str {
        &self.root_capsule_id
    }
    pub fn selected_manifest_digest(&self) -> &str {
        &self.selected_manifest_digest
    }
    pub fn selected_node_digest(&self) -> &str {
        &self.selected_node_digest
    }
    pub fn selected_capsule_id(&self) -> &str {
        &self.selected_capsule_id
    }
    pub fn selected_generation_id(&self) -> &str {
        &self.selected_generation_id
    }
    pub fn selected_profile_id(&self) -> &str {
        &self.selected_profile_id
    }
    pub fn selected_original_root(&self) -> &str {
        &self.selected_original_root
    }
    pub fn entry_id(&self) -> &str {
        &self.entry_id
    }
    pub fn role(&self) -> &str {
        &self.role
    }
    pub fn original_path(&self) -> &str {
        &self.original_path
    }
    pub fn source_provenance(&self) -> &RecoveryProvenance {
        &self.source_provenance
    }
}

/// A borrowed, sealed identity for one actually authenticated source instance.
/// No public label constructor, generic row accessor, mutable journal conversion,
/// Deserialize, or fabricated recovered component is provided. Copying this
/// borrow keeps the same binding; reopening any source mints a different binding.
///
/// A caller cannot manufacture one from labels or keep it beyond its source:
/// ```compile_fail
/// use wholepact_storage_security::bundle::recovery::evidence::history::HistoricalDisclosureIdentity;
/// let identity = HistoricalDisclosureIdentity { source: () };
/// ```
/// ```compile_fail
/// use wholepact_storage_security::bundle::recovery::evidence::{RecoveredEvidence, history::HistoricalDisclosureIdentity};
/// fn escape(source: &RecoveredEvidence) -> HistoricalDisclosureIdentity<'static> {
///     source.disclosure_identity()
/// }
/// ```
#[derive(Clone, Copy)]
pub struct HistoricalDisclosureIdentity<'s> {
    source: HistoricalSource<'s>,
}
#[derive(Clone, Copy)]
enum HistoricalSource<'s> {
    Evidence(&'s RecoveredEvidence),
    Ordinary(&'s ArchivedOrdinarySource),
    Generation(&'s ArchivedGenerationSource),
}
impl<'s> HistoricalDisclosureIdentity<'s> {
    pub(crate) fn from_evidence(source: &'s RecoveredEvidence) -> Self {
        Self {
            source: HistoricalSource::Evidence(source),
        }
    }
    pub(crate) fn from_ordinary(source: &'s ArchivedOrdinarySource) -> Self {
        Self {
            source: HistoricalSource::Ordinary(source),
        }
    }
    pub(crate) fn from_generation(source: &'s ArchivedGenerationSource) -> Self {
        Self {
            source: HistoricalSource::Generation(source),
        }
    }
    pub fn binding(self) -> HistoricalSourceBinding {
        match self.source {
            HistoricalSource::Evidence(source) => source.historical_binding(),
            HistoricalSource::Ordinary(source) => source.historical_binding(),
            HistoricalSource::Generation(source) => source.historical_binding(),
        }
    }
    /// The original recovered generation binding, if one exists. Ordinary
    /// archived journals have no recovered marker and never fabricate a binding.
    pub fn generation(self) -> Option<&'s GenerationBinding> {
        match self.source {
            HistoricalSource::Evidence(source) => Some(source.generation()),
            HistoricalSource::Ordinary(_) => None,
            HistoricalSource::Generation(source) => Some(source.snapshot().generation()),
        }
    }
    /// Original component provenance for recovered evidence/generation. The
    /// archive's current-row provenance is retained separately in archive().
    pub fn provenance(self) -> &'s RecoveryProvenance {
        match self.source {
            HistoricalSource::Evidence(source) => source.provenance(),
            HistoricalSource::Ordinary(source) => source.provenance(),
            HistoricalSource::Generation(source) => source.snapshot().provenance(),
        }
    }
    pub fn archive(self) -> Option<&'s HistoricalArchiveOrigin> {
        match self.source {
            HistoricalSource::Evidence(source) => source.archive_origin(),
            HistoricalSource::Ordinary(source) => Some(source.archive_origin()),
            HistoricalSource::Generation(source) => Some(source.archive_origin()),
        }
    }
    pub fn origin(self) -> HistoricalOrigin {
        let (generation_id, inventory_digest) = match self.source {
            HistoricalSource::Evidence(source) => (
                source.generation().generation_id(),
                source.generation().inventory_digest(),
            ),
            HistoricalSource::Generation(source) => (
                source.snapshot().generation().generation_id(),
                source.snapshot().generation().inventory_digest(),
            ),
            // For ordinary archive rows this is the selected manifest's exact
            // inventory commitment, not an invented recovered GenerationBinding.
            HistoricalSource::Ordinary(source) => (
                source.archive_origin().selected_generation_id(),
                source.archive_origin().selected_manifest_digest(),
            ),
        };
        HistoricalOrigin {
            generation_id: generation_id.into(),
            inventory_digest: inventory_digest.into(),
            provenance: self.provenance().clone(),
            archive: self.archive().cloned(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct HistoricalOrigin {
    pub generation_id: String,
    /// Original GenerationBinding inventory for recovered sources; selected
    /// manifest inventory for ordinary archived sources (generation() is None).
    pub inventory_digest: String,
    pub provenance: RecoveryProvenance,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive: Option<HistoricalArchiveOrigin>,
}
impl HistoricalOrigin {
    pub fn from_evidence(source: &RecoveredEvidence) -> Self {
        Self::from_source(source.disclosure_identity())
    }
    pub fn from_source(source: HistoricalDisclosureIdentity<'_>) -> Self {
        source.origin()
    }
}
/// Exact typed references, never arbitrary JSON or archived permission payloads.
#[derive(Clone, Default, PartialEq, Eq, Serialize)]
pub struct HistoricalReferences {
    pub artifact_id: String,
    pub historical_principal_id: String,
    pub historical_profile_id: Option<String>,
    pub agreement_id: Option<String>,
    pub candidate_id: Option<String>,
    pub record_id: Option<String>,
    pub participant_id: Option<String>,
    pub proof_job_id: Option<String>,
    pub signed_result_id: Option<String>,
    pub transaction_checkpoint_id: Option<String>,
    pub account_ids: Vec<String>,
    pub manifest_digest: Option<String>,
    pub proof_scope_digest: Option<String>,
    pub proved_artifact_digest: Option<String>,
    pub signed_request_digest: Option<String>,
    pub signed_candidate_digest: Option<String>,
    pub transaction_id: Option<String>,
    pub transaction_bytes_digest: Option<String>,
}
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct HistoricalDisclosureScope {
    #[serde(skip)]
    pub source: HistoricalSourceBinding,
    pub origin: HistoricalOrigin,
    pub principal_id: String,
    pub action: HistoricalAction,
    pub references: HistoricalReferences,
    pub destination: HistoricalDestination,
    pub payload_digest: String,
    pub payload_bytes: usize,
    pub maximum_output_bytes: usize,
}
impl HistoricalDisclosureScope {
    /// Trusted journal composition supplies validated exact references. This
    /// creates no permission; the native authority enrolls the opaque snapshot.
    pub fn new(
        source: &RecoveredEvidence,
        principal: &str,
        action: HistoricalAction,
        references: HistoricalReferences,
        destination: HistoricalDestination,
        payload: &[u8],
    ) -> Result<Self> {
        Self::from_source(
            source.disclosure_identity(),
            principal,
            action,
            references,
            destination,
            payload,
        )
    }
    /// Build exact scope from a sealed borrowed source. The owner must derive
    /// this identity from the same typed journal that supplied its projection.
    /// This does not acquire permission or enroll a substituted/reopened source.
    pub fn from_source(
        source: HistoricalDisclosureIdentity<'_>,
        principal: &str,
        action: HistoricalAction,
        references: HistoricalReferences,
        destination: HistoricalDestination,
        payload: &[u8],
    ) -> Result<Self> {
        let maximum = if action == HistoricalAction::ExportExactTransaction {
            if !matches!(destination, HistoricalDestination::NewPrivateLocalFile(_)) {
                return Err(BundleError::Permission);
            }
            MAX_HISTORICAL_TRANSACTION_BYTES
        } else {
            if destination != HistoricalDestination::NativeTerminal {
                return Err(BundleError::Permission);
            }
            MAX_HISTORICAL_METADATA_BYTES
        };
        if principal.is_empty()
            || principal.len() > 128
            || payload.is_empty()
            || payload.len() > maximum
            || references.artifact_id.is_empty()
            || references.account_ids.len() > 256
        {
            return Err(BundleError::Limit);
        }
        let mut accounts = references.account_ids.clone();
        accounts.sort();
        accounts.dedup();
        if accounts.len() != references.account_ids.len() {
            return Err(BundleError::Integrity);
        }
        Ok(Self {
            source: source.binding(),
            origin: source.origin(),
            principal_id: principal.into(),
            action,
            references,
            destination,
            payload_digest: hex_digest(payload),
            payload_bytes: payload.len(),
            maximum_output_bytes: maximum,
        })
    }
}
fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub trait HistoricalDisclosureLease {
    fn scope(&self) -> &HistoricalDisclosureScope;
    fn check_current(&self) -> Result<()>;
    /// Hold the native foreground/revocation fence and monotonic deadline over
    /// this one final handoff/write. Merely checking before a callback is not a
    /// conforming implementation. Never execute the callback more than once.
    fn run_effect(&self, effect: &mut dyn FnMut() -> Result<()>) -> Result<()>;
}
pub trait HistoricalDisclosureAuthority {
    /// Authenticate current principal, enrolled opaque source, exact references,
    /// account set, payload size/digest, action and recipient/destination. Backup,
    /// ordinary agreement and old saved disclosure grants never suffice.
    fn acquire<'a>(
        &'a self,
        scope: &HistoricalDisclosureScope,
    ) -> Result<Box<dyn HistoricalDisclosureLease + 'a>>;
}

/// No Clone, Deserialize, raw JSON accessor or unleased projection getter.
pub struct HistoricalDisclosure<'a, T> {
    projection: T,
    scope: HistoricalDisclosureScope,
    lease: Box<dyn HistoricalDisclosureLease + 'a>,
}
impl<'a, T: Serialize> HistoricalDisclosure<'a, T> {
    pub fn authorize(
        source: &RecoveredEvidence,
        principal: &str,
        action: HistoricalAction,
        references: HistoricalReferences,
        projection: T,
        authority: &'a dyn HistoricalDisclosureAuthority,
    ) -> Result<Self> {
        Self::authorize_from_source(
            source.disclosure_identity(),
            principal,
            action,
            references,
            projection,
            authority,
        )
    }
    /// Owner-specific adapters pass the identity of their authenticated typed
    /// source. This uses the same exact, current, one-use final-effect lease as
    /// the v1 evidence API; archive integrity never supplies disclosure approval.
    pub fn authorize_from_source(
        source: HistoricalDisclosureIdentity<'_>,
        principal: &str,
        action: HistoricalAction,
        references: HistoricalReferences,
        projection: T,
        authority: &'a dyn HistoricalDisclosureAuthority,
    ) -> Result<Self> {
        if action == HistoricalAction::ExportExactTransaction {
            return Err(BundleError::Permission);
        }
        let bytes =
            Zeroizing::new(serde_json::to_vec(&projection).map_err(|_| BundleError::Integrity)?);
        let scope = HistoricalDisclosureScope::from_source(
            source,
            principal,
            action,
            references,
            HistoricalDestination::NativeTerminal,
            &bytes,
        )?;
        let lease = acquire_checked(authority, &scope)?;
        Ok(Self {
            projection,
            scope,
            lease,
        })
    }
    /// The native output callback must write only to the scope's protected TTY.
    /// No result is returned after the held permission is released.
    pub fn deliver(self, output: impl FnOnce(&T) -> Result<()>) -> Result<()> {
        check_lease(&*self.lease, &self.scope)?;
        let mut output = Some(output);
        let mut called = false;
        self.lease.run_effect(&mut || {
            check_lease(&*self.lease, &self.scope)?;
            let callback = output.take().ok_or(BundleError::Permission)?;
            called = true;
            callback(&self.projection)
        })?;
        if !called {
            return Err(BundleError::Permission);
        }
        // A failed postcheck cannot revoke data already disclosed.
        check_lease(&*self.lease, &self.scope).map_err(|_| BundleError::PermissionChanged)
    }
}
pub fn acquire_checked<'a>(
    authority: &'a dyn HistoricalDisclosureAuthority,
    scope: &HistoricalDisclosureScope,
) -> Result<Box<dyn HistoricalDisclosureLease + 'a>> {
    let lease = authority.acquire(scope)?;
    check_lease(&*lease, scope)?;
    Ok(lease)
}
pub fn check_lease(
    lease: &dyn HistoricalDisclosureLease,
    scope: &HistoricalDisclosureScope,
) -> Result<()> {
    if lease.scope() != scope {
        return Err(BundleError::Permission);
    }
    lease.check_current()
}

/// Typed, fixed conservative facts on every historical projection. No saved
/// success/consumption/inclusion label can replace these current unknowns.
#[derive(Serialize)]
pub struct HistoricalRestrictions {
    pub recovery_required: bool,
    pub authorization_exposure: &'static str,
    pub chain_observation: &'static str,
    pub external_signatures: &'static str,
    pub current_authority: bool,
    pub replay_allowed: bool,
    pub replacement_allowed: bool,
}
impl Default for HistoricalRestrictions {
    fn default() -> Self {
        Self {
            recovery_required: true,
            authorization_exposure: "unknown",
            chain_observation: "unknown_historical_observations_only",
            external_signatures: "unknown_possible",
            current_authority: false,
            replay_allowed: false,
            replacement_allowed: false,
        }
    }
}

/// Trusted exact-transaction output primitive. The owning protocol decoder has
/// already authenticated the retained transaction and its references. Unlike a
/// generic byte/file writer, this requires the exact current disclosure lease,
/// transaction action/component, bound bytes and new-private-file destination.
/// The native lease supplies the one-shot foreground/revocation admission.
pub fn export_exact_transaction_bytes(
    scope: &HistoricalDisclosureScope,
    lease: &dyn HistoricalDisclosureLease,
    bytes: &[u8],
) -> Result<()> {
    if scope.action != HistoricalAction::ExportExactTransaction
        || scope.origin.provenance.kind != crate::bundle::JournalKind::ExactTransactions
        || scope.references.transaction_checkpoint_id.as_deref()
            != Some(scope.references.artifact_id.as_str())
        || scope
            .references
            .proof_job_id
            .as_deref()
            .is_none_or(str::is_empty)
        || scope
            .references
            .signed_result_id
            .as_deref()
            .is_none_or(str::is_empty)
        || scope
            .references
            .transaction_id
            .as_deref()
            .is_none_or(str::is_empty)
        || scope.references.transaction_bytes_digest.as_deref()
            != Some(scope.payload_digest.as_str())
        || scope.payload_bytes != bytes.len()
        || scope.maximum_output_bytes != MAX_HISTORICAL_TRANSACTION_BYTES
        || bytes.is_empty()
        || bytes.len() > MAX_HISTORICAL_TRANSACTION_BYTES
        || scope.payload_digest != hex_digest(bytes)
    {
        return Err(BundleError::Permission);
    }
    let HistoricalDestination::NewPrivateLocalFile(path) = &scope.destination else {
        return Err(BundleError::Permission);
    };
    check_lease(lease, scope)?;
    let mut called = false;
    lease.run_effect(&mut || {
        if called {
            return Err(BundleError::Permission);
        }
        check_lease(lease, scope)?;
        called = true;
        write_new_private_file(path, bytes)
    })?;
    if !called {
        return Err(BundleError::Permission);
    }
    check_lease(lease, scope).map_err(|_| BundleError::PermissionChanged)
}

/// Linux-only exclusive private output. Canonical parent and no-follow creation
/// reject aliases; a partial write remains in place for explicit inspection.
/// The owning native authority must additionally exclude protected source trees.
fn write_new_private_file(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, bytes);
        Err(BundleError::Unsupported)
    }
    #[cfg(target_os = "linux")]
    {
        use std::{
            fs::{self, File, OpenOptions},
            io::Write,
            os::{
                fd::{AsRawFd, FromRawFd},
                unix::{
                    ffi::OsStrExt,
                    fs::{MetadataExt, OpenOptionsExt},
                },
            },
        };
        if bytes.is_empty()
            || bytes.len() > MAX_HISTORICAL_TRANSACTION_BYTES
            || !path.is_absolute()
            || path.file_name().is_none()
            || path.components().any(|c| {
                !matches!(
                    c,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
        {
            return Err(BundleError::Invalid);
        }
        let parent = path.parent().ok_or(BundleError::Invalid)?;
        if fs::canonicalize(parent).map_err(|_| BundleError::Storage)? != parent {
            return Err(BundleError::Invalid);
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY)
            .open(parent)
            .map_err(|_| BundleError::Storage)?;
        let metadata = directory.metadata().map_err(|_| BundleError::Storage)?;
        let current = fs::symlink_metadata(parent).map_err(|_| BundleError::Storage)?;
        if metadata.dev() != current.dev() || metadata.ino() != current.ino() {
            return Err(BundleError::Integrity);
        }
        let name = std::ffi::CString::new(path.file_name().ok_or(BundleError::Invalid)?.as_bytes())
            .map_err(|_| BundleError::Invalid)?;
        // SAFETY: directory and C string are live; exclusive no-follow creation
        // returns a new owned fd, never opens/truncates an existing artifact.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(BundleError::Storage);
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .and_then(|_| directory.sync_all())
            .map_err(|_| BundleError::Storage)
    }
}

#[cfg(test)]
mod tests;
