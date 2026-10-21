//! SOURCE-ONLY connected native namespace owner. A single fixed OS-user witness
//! installation is supported; no arbitrary root, implicit install, reset, legacy
//! adoption or restored activation exists. All setup/enrollment mutation consumes
//! the real native module's private one-shot decision and retained publication.
use super::*;
use crate::journal::PendingBirthTargetInspection;
use crate::native_witness_owner::financial_setup_guard_v1::FinancialSetupGuardV1;
use crate::native_witness_owner::{
    NativeEnrollmentDecision, NativePublicationLease, NativeSetupDecision,
};
use crate::pending_birth_signature::VerifiedPendingBirthOwnerSignature;
use crate::AuthorityJournal;
use ring::{
    hkdf,
    rand::{SecureRandom, SystemRandom},
};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use wholepact_storage_security::witness_namespace_fs::{
    read_existing_storage_key, DirectoryStamp, InstallationFiles, InstallationProbe,
};
use wholepact_storage_security::{DatabaseFileIdentity, DatabaseKey, EncryptedConnection};
use zeroize::Zeroizing;

#[path = "namespace_archive.rs"]
mod namespace_archive;
pub(crate) use namespace_archive::*;

#[derive(Clone, Serialize)]
pub(crate) struct NamespaceSetupInput {
    // Concrete temporary owner only; never a serialized root/permission input.
    #[cfg(feature = "synthetic-qualification")]
    #[serde(skip)]
    pub(crate) synthetic_installation:
        Option<Arc<wholepact_storage_security::witness_namespace_fs::EphemeralWitnessInstallation>>,
    pub(crate) endpoint: String,
    pub(crate) server_name: String,
    pub(crate) witness_id: String,
    pub(crate) pinned_server_certificate_digest: String,
    pub(crate) owner_certificate_digest: String,
    pub(crate) network_profile_id: String,
    pub(crate) storage_key_file: String,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NamespaceOpenInput {
    // Concrete temporary owner only; never a serialized root/permission input.
    #[cfg(feature = "synthetic-qualification")]
    #[serde(skip)]
    pub(crate) synthetic_installation:
        Option<Arc<wholepact_storage_security::witness_namespace_fs::EphemeralWitnessInstallation>>,
    pub(crate) endpoint: String,
    pub(crate) server_name: String,
    pub(crate) witness_id: String,
    pub(crate) pinned_server_certificate_digest: String,
    pub(crate) owner_certificate_digest: String,
    pub(crate) network_profile_id: String,
    pub(crate) storage_key_file: String,
    pub(crate) expected_account_id: String,
}
#[derive(Serialize)]
struct OriginBinding<'a> {
    endpoint: &'a str,
    server_name: &'a str,
    witness_id: &'a str,
    pinned_server_certificate_digest: &'a str,
    owner_certificate_digest: &'a str,
    network_profile_id: &'a str,
}
impl NamespaceSetupInput {
    fn installation_probe(&self) -> Result<InstallationProbe> {
        #[cfg(feature = "synthetic-qualification")]
        if let Some(owner) = &self.synthetic_installation {
            return owner.probe().map_err(Into::into);
        }
        InstallationProbe::fixed_user_installation().map_err(Into::into)
    }
    fn validate(&self) -> Result<()> {
        id(&self.witness_id)?;
        id(&self.network_profile_id)?;
        hash(&self.pinned_server_certificate_digest)?;
        hash(&self.owner_certificate_digest)?;
        // Delegate exact endpoint/name parsing to the existing disclosure validator.
        self.disclosure()?.validate()?;
        if self.storage_key_file.len() > 4096 || !Path::new(&self.storage_key_file).is_absolute() {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    fn disclosure(&self) -> Result<crate::WitnessDisclosureDescriptor> {
        Ok(crate::WitnessDisclosureDescriptor {
            endpoint: self.endpoint.clone(),
            server_name: self.server_name.clone(),
            witness_id: self.witness_id.clone(),
            account_id: "0".repeat(64),
            network_profile_id: self.network_profile_id.clone(),
            policy_digest: "0".repeat(64),
            pinned_server_certificate_digest: self.pinned_server_certificate_digest.clone(),
        })
    }
    fn origin(&self) -> OriginBinding<'_> {
        OriginBinding {
            endpoint: &self.endpoint,
            server_name: &self.server_name,
            witness_id: &self.witness_id,
            pinned_server_certificate_digest: &self.pinned_server_certificate_digest,
            owner_certificate_digest: &self.owner_certificate_digest,
            network_profile_id: &self.network_profile_id,
        }
    }
}
impl NamespaceOpenInput {
    fn setup(&self) -> NamespaceSetupInput {
        NamespaceSetupInput {
            #[cfg(feature = "synthetic-qualification")]
            synthetic_installation: self.synthetic_installation.clone(),
            endpoint: self.endpoint.clone(),
            server_name: self.server_name.clone(),
            witness_id: self.witness_id.clone(),
            pinned_server_certificate_digest: self.pinned_server_certificate_digest.clone(),
            owner_certificate_digest: self.owner_certificate_digest.clone(),
            network_profile_id: self.network_profile_id.clone(),
            storage_key_file: self.storage_key_file.clone(),
        }
    }
}

pub(crate) struct NamespaceSetupProposal {
    input: NamespaceSetupInput,
    probe: InstallationProbe,
    master: Zeroizing<[u8; 32]>,
    instance_id: String,
    reviewed: String,
    display: String,
}
impl NamespaceSetupProposal {
    pub(crate) fn display(&self) -> Result<String> {
        self.check_current()?;
        Ok(self.display.clone())
    }
    pub(crate) fn review_digest(&self) -> Result<String> {
        self.check_current()?;
        Ok(self.reviewed.clone())
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        self.input.validate()?;
        self.probe.require_absent()?;
        Ok(())
    }
}
pub(crate) fn prepare_namespace_setup(
    mut input: NamespaceSetupInput,
) -> Result<NamespaceSetupProposal> {
    if !input.witness_id.is_empty() {
        return Err(AuthorityError::RecoveryRequired);
    }
    let mut random = [0u8; 32];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| AuthorityError::Storage)?;
    let instance_id = hex::encode(random);
    input.witness_id = format!("witness-{instance_id}");
    input.validate()?;
    let probe = input.installation_probe()?;
    probe.require_absent()?;
    let master = read_existing_storage_key(Path::new(&input.storage_key_file))?;
    let root = probe.root_path();
    let reviewed = digest(
        "wholepact:native-witness-namespace-setup:v1",
        &(input.origin(), &input.storage_key_file, &root, &instance_id),
    )?;
    let display = format!(
        "FIRST WITNESS NAMESPACE INSTALLATION\n\nCanonical OS-user root: {}\nInstallation identity: {}\nOrigin: {}\nExisting independent storage-key file: {}\n\nThis creates an immutable origin/root registry, encrypted locator and permanent account/FVK collision index. No journal/account is enrolled. Existing or interrupted installation is never replaced. This installation is continuity-critical: keep registry, installation marker and every journal together. Backups/restores remain quarantined; copying or rolling back the whole independent witness violates its no-rollback assumption. This is not a reset route.\n\nReview digest: {}",
        root.display(),
        instance_id,
        serde_json::to_string_pretty(&input.origin())
            .map_err(|_| AuthorityError::InvalidBinding)?,
        input.storage_key_file,
        reviewed
    );
    Ok(NamespaceSetupProposal {
        input,
        probe,
        master,
        instance_id,
        reviewed,
        display,
    })
}
#[derive(Serialize)]
pub(crate) struct NamespaceInstallationAudit {
    pub(crate) witness_id: String,
    pub(crate) namespace_digest: String,
    pub(crate) canonical_root: String,
}
pub(crate) fn install_namespace(
    decision: NativeSetupDecision,
) -> Result<NamespaceInstallationAudit> {
    let (proposal, lease) = decision.into_parts();
    proposal.check_current()?;
    if lease.reviewed_digest() != proposal.reviewed {
        return Err(AuthorityError::InvalidBinding);
    }
    let publication = lease.publication_lease()?;
    publication.check_current()?;
    if publication.reviewed_digest() != proposal.reviewed
        || publication.admitted_at_ms() > crate::now_ms()?
    {
        return Err(AuthorityError::InvalidBinding);
    }
    let files = proposal.probe.create_once(&proposal.instance_id)?;
    // From this point any failure leaves a permanent uncertain installation,
    // never cleanup followed by a second namespace. No origin may be swapped.
    publication.check_current()?;
    let namespace = WitnessNamespaceBinding {
        version: 1,
        namespace_instance_id: proposal.instance_id.clone(),
        initial_inventory_digest: digest(
            "wholepact:witness-native-empty-installation:v1",
            &(&proposal.reviewed, &proposal.instance_id),
        )?,
        witness_id: proposal.input.witness_id.clone(),
        witness_origin_digest: account_use_witness_origin_digest(&proposal.input.disclosure()?)?,
        pinned_server_certificate_digest: proposal.input.pinned_server_certificate_digest.clone(),
        owner_certificate_digest: proposal.input.owner_certificate_digest.clone(),
        network_profile_id: proposal.input.network_profile_id.clone(),
        canonical_private_root: files
            .root_path()
            .to_str()
            .ok_or(AuthorityError::InvalidBinding)?
            .into(),
        root_identity: directory_identity(files.root_stamp()),
        journals_identity: directory_identity(files.journals_stamp()),
    };
    namespace.validate()?;
    let key = derive_key(
        &proposal.master,
        &proposal.instance_id,
        "wholepact:witness-locator-storage-key:v1",
    )?;
    let c = wholepact_storage_security::create_encrypted(files.registry_path(), &key)?;
    let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate)?;
    tx.execute_batch(storage::SCHEMA)?;
    tx.execute(
        "INSERT INTO witness_locator_namespace VALUES(1,?1,?2)",
        params![namespace.digest()?, &*encode(&namespace)?],
    )?;
    tx.execute("INSERT INTO witness_locator_quarantine VALUES(1,0)", [])?;
    tx.pragma_update(None, "application_id", storage::LOCATOR_APPLICATION_ID)?;
    tx.pragma_update(None, "user_version", storage::LOCATOR_SCHEMA_VERSION)?;
    publication.check_current()?;
    files.check_current()?;
    tx.commit()?;
    files.sync_directories()?;
    storage::load_exact(c.connection(), &namespace)?;
    Ok(NamespaceInstallationAudit {
        witness_id: namespace.witness_id.clone(),
        namespace_digest: namespace.digest()?,
        canonical_root: namespace.canonical_private_root,
    })
}
fn directory_identity(s: &DirectoryStamp) -> DirectoryIdentity {
    DirectoryIdentity {
        platform: "linux-unix-v1".into(),
        device: s.device,
        inode: s.inode,
        owner_uid: s.owner_uid,
    }
}
struct KeyLength;
impl hkdf::KeyType for KeyLength {
    fn len(&self) -> usize {
        32
    }
}
fn derive_key(master: &[u8; 32], salt: &str, domain: &str) -> Result<DatabaseKey> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt.as_bytes());
    let prk = salt.extract(master);
    let info = [domain.as_bytes()];
    let okm = prk
        .expand(&info, KeyLength)
        .map_err(|_| AuthorityError::Storage)?;
    let mut bytes = Zeroizing::new([0u8; 32]);
    okm.fill(&mut *bytes).map_err(|_| AuthorityError::Storage)?;
    Ok(DatabaseKey::from_bytes(*bytes))
}
struct NamespaceCore {
    files: InstallationFiles,
    namespace: WitnessNamespaceBinding,
    master: Zeroizing<[u8; 32]>,
    registry: Mutex<EncryptedConnection>,
    registry_identity: DatabaseFileIdentity,
}
impl NamespaceCore {
    fn check_current_guarded(&self, guard: FinancialSetupGuardV1<'_>) -> Result<()> {
        self.check_current_read_guarded(crate::journal::ReadGuardV1::coordinated(guard))
    }
    fn check_current_read_guarded(
        &self,
        read_guard: crate::journal::ReadGuardV1<'_>,
    ) -> Result<()> {
        read_guard.check()?;
        self.files.check_current()?;
        read_guard.check()?;
        let c = self.registry.lock().map_err(|_| AuthorityError::Storage)?;
        read_guard.check()?;
        self.registry_identity.check_current(c.connection())?;
        require_runtime_guarded(c.connection(), read_guard)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Deferred)?;
        read_guard.check()?;
        let history = storage::load_exact_guarded(&tx, &self.namespace, read_guard)?;
        read_guard.check()?;
        check_inventory_guarded(&self.files, &history, read_guard)?;
        read_guard.check()
    }
    fn check_current(&self) -> Result<()> {
        self.files.check_current()?;
        let c = self.registry.lock().map_err(|_| AuthorityError::Storage)?;
        self.check_registry_locked(&c)
    }
    // The coordinated final-effect path never waits for a Rust registry mutex.
    // SQLite/filesystem work below may still block; its original clock must be
    // checked again afterwards. This is source continuity, not consent.
    fn check_current_without_mutex_wait(&self) -> Result<()> {
        self.files.check_current()?;
        let c = self
            .registry
            .try_lock()
            .map_err(|_| AuthorityError::Permission)?;
        self.check_registry_locked(&c)
    }
    fn check_registry_locked(&self, c: &EncryptedConnection) -> Result<()> {
        self.registry_identity.check_current(c.connection())?;
        require_runtime(c.connection())?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Deferred)?;
        let history = storage::load_exact(&tx, &self.namespace)?;
        check_inventory(&self.files, &history)?;
        Ok(())
    }
    fn key_for(&self, intent: &CreationIntent) -> Result<DatabaseKey> {
        derive_key(
            &self.master,
            &intent.digest(&self.namespace)?,
            "wholepact:witness-original-account-journal-key:v1",
        )
    }
    fn path_for(&self, intent: &CreationIntent) -> Result<PathBuf> {
        intent.validate(&self.namespace)?;
        Ok(self.files.root_path().join(&intent.derived_child))
    }
}
fn open_namespace(input: &NamespaceOpenInput) -> Result<Arc<NamespaceCore>> {
    hash(&input.expected_account_id)?;
    open_namespace_identity(&input.setup())
}
// Shared concrete opener: identity-only backup needs no invented account ID.
// Still the same fixed installation, held locks, immutable preflight, exact
// original owner/origin/root binding and missing-history denial.
fn open_namespace_identity(input: &NamespaceSetupInput) -> Result<Arc<NamespaceCore>> {
    open_namespace_identity_guarded(input, FinancialSetupGuardV1::legacy())
}
fn open_namespace_identity_guarded(
    input: &NamespaceSetupInput,
    guard: FinancialSetupGuardV1<'_>,
) -> Result<Arc<NamespaceCore>> {
    let read_guard = crate::journal::ReadGuardV1::coordinated(guard);
    let setup = input;
    setup.validate()?;
    guard.check()?;
    let files = input.installation_probe()?.open_existing()?;
    guard.check()?;
    let master = match guard {
        FinancialSetupGuardV1::Legacy(_) => {
            read_existing_storage_key(Path::new(&input.storage_key_file))?
        }
        #[cfg(feature = "coordinated-witness-financial-signing")]
        FinancialSetupGuardV1::SigningServe(_) => return Err(AuthorityError::Permission),
        #[cfg(feature = "coordinated-witness-financial-signing")]
        FinancialSetupGuardV1::SigningSetup(_) => {
            let bytes = guard.read(Path::new(&input.storage_key_file), 32)?;
            if bytes.len() != 32 || bytes.iter().all(|b| *b == 0) {
                return Err(AuthorityError::Authentication);
            }
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&bytes);
            key
        }
        #[cfg(feature = "coordinated-witness-financial-history")]
        FinancialSetupGuardV1::HistoryServe(_) => return Err(AuthorityError::Permission),
        #[cfg(feature = "coordinated-witness-financial-history")]
        FinancialSetupGuardV1::HistorySetup(_) => {
            let bytes = guard.read(Path::new(&input.storage_key_file), 32)?;
            if bytes.len() != 32 || bytes.iter().all(|b| *b == 0) {
                return Err(AuthorityError::Authentication);
            }
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&bytes);
            key
        }
        #[cfg(feature = "coordinated-witness-financial-continuation")]
        FinancialSetupGuardV1::Final(_) => return Err(AuthorityError::Permission),
        #[cfg(feature = "coordinated-witness-financial-continuation")]
        FinancialSetupGuardV1::Coordinated(_) | FinancialSetupGuardV1::Arm(_) => {
            let bytes = guard.read(Path::new(&input.storage_key_file), 32)?;
            if bytes.len() != 32 || bytes.iter().all(|b| *b == 0) {
                return Err(AuthorityError::Authentication);
            }
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&bytes);
            key
        }
    };
    let key = derive_key(
        &master,
        files.instance_id(),
        "wholepact:witness-locator-storage-key:v1",
    )?;
    // No writable registry handle exists until the complete immutable preflight
    // and actual canonical namespace/inventory comparisons below have succeeded.
    guard.check()?;
    let (namespace, prior) = read_registry_preflight_guarded(&files.registry_path(), &key, guard)?;
    if namespace.namespace_instance_id != files.instance_id()
        || Path::new(&namespace.canonical_private_root) != files.root_path()
        || namespace.root_identity != directory_identity(files.root_stamp())
        || namespace.journals_identity != directory_identity(files.journals_stamp())
        || namespace.witness_id != input.witness_id
        || namespace.network_profile_id != input.network_profile_id
        || namespace.pinned_server_certificate_digest != input.pinned_server_certificate_digest
        || namespace.owner_certificate_digest != input.owner_certificate_digest
        || namespace.witness_origin_digest
            != account_use_witness_origin_digest(&setup.disclosure()?)?
    {
        return Err(AuthorityError::InvalidBinding);
    }
    check_inventory_guarded(&files, &prior, read_guard)?;
    files.check_current()?;
    guard.check()?;
    let registry =
        wholepact_storage_security::open_encrypted_quiescent(files.registry_path(), &key)?;
    guard.check()?;
    require_runtime_guarded(registry.connection(), read_guard)?;
    guard.check()?;
    let current = storage::load_exact_guarded(registry.connection(), &namespace, read_guard)?;
    if prior.prepared != current.prepared
        || prior.completed != current.completed
        || prior.exclusions != current.exclusions
    {
        return Err(AuthorityError::CorruptHistory);
    }
    check_inventory_guarded(&files, &current, read_guard)?;
    let registry_identity = registry.database_identity()?;
    let core = Arc::new(NamespaceCore {
        files,
        namespace,
        master,
        registry: Mutex::new(registry),
        registry_identity,
    });
    core.check_current_guarded(guard)?;
    guard.check()?;
    Ok(core)
}
/// Audit data only. The caller holds the canonical namespace locks. All source
/// authentication/schema/record failures occur on immutable encrypted snapshots;
/// this helper never allocates a writable handle to the original file set.
fn read_registry_preflight(
    path: &Path,
    key: &DatabaseKey,
) -> Result<(WitnessNamespaceBinding, LocatorHistory)> {
    read_registry_preflight_guarded(path, key, FinancialSetupGuardV1::legacy())
}
fn read_registry_preflight_guarded(
    path: &Path,
    key: &DatabaseKey,
    guard: FinancialSetupGuardV1<'_>,
) -> Result<(WitnessNamespaceBinding, LocatorHistory)> {
    let read_guard = crate::journal::ReadGuardV1::coordinated(guard);
    guard.check()?;
    let preflight = wholepact_storage_security::open_encrypted_read_snapshot(path, key)?;
    guard.check()?;
    storage::verify_schema_guarded(preflight.connection(), read_guard)?;
    guard.check()?;
    let payload: Option<Vec<u8>> = preflight
        .connection()
        .query_row(
            "SELECT payload FROM witness_locator_namespace WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    guard.check()?;
    let namespace: WitnessNamespaceBinding =
        crate::decode(&payload.ok_or(AuthorityError::RecoveryRequired)?)?;
    namespace.validate()?;
    guard.check()?;
    let history = storage::load_exact_guarded(preflight.connection(), &namespace, read_guard)?;
    guard.check()?;
    Ok((namespace, history))
}

fn require_runtime(c: &rusqlite::Connection) -> Result<()> {
    require_runtime_guarded(c, crate::journal::ReadGuardV1::legacy())
}

fn require_runtime_guarded(
    c: &rusqlite::Connection,
    guard: crate::journal::ReadGuardV1<'_>,
) -> Result<()> {
    let mode: String = crate::journal::guarded_read!(
        guard,
        c.pragma_query_value(None, "journal_mode", |r| r.get(0))
    )?;
    let sync: i64 = crate::journal::guarded_read!(
        guard,
        c.pragma_query_value(None, "synchronous", |r| r.get(0))
    )?;
    let foreign: i64 = crate::journal::guarded_read!(
        guard,
        c.pragma_query_value(None, "foreign_keys", |r| r.get(0))
    )?;
    if mode != "wal" || sync != 2 || foreign != 1 {
        return Err(AuthorityError::Storage);
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum BirthDisposition {
    FirstCommitAllowed,
    ExistingCommittedAuditOnly,
}
pub(crate) struct NamespaceEnrollmentProposal {
    core: Arc<NamespaceCore>,
    intent: CreationIntent,
    authenticated: VerifiedPendingBirthOwnerSignature,
    disposition: BirthDisposition,
    existing: Option<PendingBirthCommitRecord>,
    reviewed: String,
    display: String,
}
impl NamespaceEnrollmentProposal {
    pub(crate) fn display(&self) -> Result<String> {
        self.check_current()?;
        Ok(self.display.clone())
    }
    pub(crate) fn review_digest(&self) -> Result<String> {
        self.check_current()?;
        Ok(self.reviewed.clone())
    }
    pub(crate) fn first_commit_deadline_ms(&self) -> Option<u64> {
        match self.disposition {
            BirthDisposition::FirstCommitAllowed => {
                Some(self.intent.request.initial_commit_deadline_ms)
            }
            BirthDisposition::ExistingCommittedAuditOnly => None,
        }
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        self.core.check_current()?;
        self.intent.validate(&self.core.namespace)?;
        if self.authenticated.request() != &self.intent.request
            || self.authenticated.certificate_digest()
                != self.core.namespace.owner_certificate_digest
        {
            return Err(AuthorityError::InvalidBinding);
        }
        if matches!(self.disposition, BirthDisposition::FirstCommitAllowed) {
            self.intent
                .request
                .require_initial_commit_time(crate::now_ms()?)?;
        }
        Ok(())
    }
}
pub(crate) fn prepare_namespace_enrollment(
    input: NamespaceOpenInput,
    authenticated: VerifiedPendingBirthOwnerSignature,
) -> Result<NamespaceEnrollmentProposal> {
    let request = authenticated.request();
    request.validate()?;
    if input.expected_account_id != request.policy.account_id
        || input.owner_certificate_digest != authenticated.certificate_digest()
    {
        return Err(AuthorityError::InvalidBinding);
    }
    let core = open_namespace(&input)?;
    core.namespace.require_request(request)?;
    let namespace_digest = core.namespace.digest()?;
    let local_target_digest = target_digest(&core.namespace, &request.policy.account_id)?;
    let mut intent = CreationIntent {
        version: 1,
        namespace_digest,
        request: request.clone(),
        request_digest: request.digest()?,
        derived_child: derived_child(&request.policy.account_id)?,
        local_target_digest,
        local_owner_review_digest: "0".repeat(64),
        owner_approval_evidence_digest: authenticated.evidence_digest().into(),
    };
    let existing_intent = {
        let c = core.registry.lock().map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Deferred)?;
        let history = storage::load_exact(&tx, &core.namespace)?;
        let mut found = None;
        for p in history.prepared.values() {
            let old = &p.intent;
            if old.identity().overlaps(intent.identity())
                || old.request.operation_id == request.operation_id
                || old.request.generation_instance_id == request.generation_instance_id
                || old.derived_child == intent.derived_child
            {
                // Fresh approval may have new signature/review evidence. It may
                // continue only the full original request/namespace/target.
                if old.request != intent.request
                    || old.namespace_digest != intent.namespace_digest
                    || old.derived_child != intent.derived_child
                    || old.local_target_digest != intent.local_target_digest
                {
                    return Err(AuthorityError::Conflict);
                }
                found = Some(old.clone());
            }
        }
        if history
            .exclusions
            .iter()
            .any(|e| e.exclusion.identity.overlaps(intent.identity()))
            && found.is_none()
        {
            return Err(AuthorityError::PolicyDenied);
        }
        found
    };
    // An unreserved request must not inspect/adopt any extant target. A genuinely
    // committed target can only belong to the original durable preparation.
    let existing_intent_digest = existing_intent
        .as_ref()
        .map(|old| old.digest(&core.namespace))
        .transpose()?;
    if let Some(old) = existing_intent {
        intent = old;
    }
    let preliminary_review = digest(
        "wholepact:native-witness-enrollment-review:v1",
        &(
            &core.namespace,
            &intent.request,
            &intent.local_target_digest,
            authenticated.evidence_digest(),
            &existing_intent_digest,
        ),
    )?;
    intent.validate(&core.namespace)?;
    let path = core.path_for(&intent)?;
    let (disposition, existing) = if existing_intent_digest.is_none() {
        // A fresh request cannot derive a final key from a provisional review or
        // adopt any existing file. Final review fixes the original intent/key.
        require_new_target_absent(&path)?;
        intent
            .request
            .require_initial_commit_time(crate::now_ms()?)?;
        (BirthDisposition::FirstCommitAllowed, None)
    } else {
        let key = core.key_for(&intent)?;
        match AuthorityJournal::inspect_pending_birth_for_locator(
            &path,
            &key,
            &intent.request.policy,
            &intent.namespace_digest,
            &intent.digest(&core.namespace)?,
        )? {
            PendingBirthTargetInspection::Absent
            | PendingBirthTargetInspection::AuthenticatedEmpty => {
                intent
                    .request
                    .require_initial_commit_time(crate::now_ms()?)?;
                (BirthDisposition::FirstCommitAllowed, None)
            }
            PendingBirthTargetInspection::Committed {
                record,
                identity: _,
            } => {
                validate_record_against_intent(&core, &intent, &record)?;
                (BirthDisposition::ExistingCommittedAuditOnly, Some(*record))
            }
        }
    };
    let reviewed = digest(
        "wholepact:native-witness-enrollment-publication:v1",
        &(&preliminary_review, &disposition, &existing),
    )?;
    if existing_intent_digest.is_none() {
        // This is the ACTUAL first native review digest, not a precursor. Every
        // later key derivation/retry uses these exact persisted original bytes.
        intent.local_owner_review_digest = reviewed.clone();
    }
    intent.validate(&core.namespace)?;
    let display = format!(
        "EXACT CANONICAL WITNESS ENROLLMENT\n\nNamespace: {}\nCanonical child: {}\nFull immutable request: {}\nAuthenticated owner certificate: {}\nCurrent signature evidence: {}\nOriginal retained evidence: {}\nOriginal local review: {}\nDisposition: {}\n\nThe account-ID and raw-FVK DIGEST are permanently reserved before journal creation. No raw viewing key is disclosed. Failure never frees the key/path/operation or refunds budget. Exact retry retains original request, deadline, limits, evidence and genesis. Existing completed state is audit only; no writer, signing or active-vault authority follows.\n\nNative publication review digest: {}",
        serde_json::to_string_pretty(&core.namespace)
            .map_err(|_| AuthorityError::InvalidBinding)?,
        path.display(),
        serde_json::to_string_pretty(&intent.request)
            .map_err(|_| AuthorityError::InvalidBinding)?,
        authenticated.certificate_digest(),
        authenticated.evidence_digest(),
        intent.owner_approval_evidence_digest,
        intent.local_owner_review_digest,
        match disposition {
            BirthDisposition::FirstCommitAllowed => "first commit only before original deadline",
            BirthDisposition::ExistingCommittedAuditOnly =>
                "exact existing committed audit; no new genesis",
        },
        reviewed
    );
    if display.len() > 512 * 1024 {
        return Err(AuthorityError::Limit);
    }
    let proposal = NamespaceEnrollmentProposal {
        core,
        intent,
        authenticated,
        disposition,
        existing,
        reviewed,
        display,
    };
    proposal.check_current()?;
    Ok(proposal)
}

pub(crate) struct BornJournalOwner {
    core: Arc<NamespaceCore>,
    intent: CreationIntent,
    path: PathBuf,
    key: DatabaseKey,
    intent_digest: String,
}
impl BornJournalOwner {
    /// Audit continuity only. Does not clear retirement or create a writer.
    pub(crate) fn check_current(&self) -> Result<()> {
        self.check(false)
    }
    pub(crate) fn check_mutation_current(&self) -> Result<()> {
        self.check(true)
    }
    fn check(&self, mutation: bool) -> Result<()> {
        self.core.check_current()?;
        let c = self
            .core
            .registry
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        self.check_registry_locked(mutation, &c)
    }
    /// Same original namespace/completed-birth/exclusion checks, with no waiting
    /// for either Rust registry guard. No guard or transaction escapes this call.
    /// This does NOT bound SQL/filesystem latency or grant publication authority.
    pub(crate) fn check_mutation_current_without_mutex_wait(&self) -> Result<()> {
        self.core.check_current_without_mutex_wait()?;
        let c = self
            .core
            .registry
            .try_lock()
            .map_err(|_| AuthorityError::Permission)?;
        self.check_registry_locked(true, &c)
    }
    /// Retained same-owner account identity, not a caller-selected path/open.
    /// The caller separately compares the actual held DatabaseFileIdentity.
    pub(crate) fn require_original_account_connection(
        &self,
        connection: &EncryptedConnection,
        birth: &PendingBirthCommitRecord,
    ) -> Result<()> {
        if connection.connection().path() != self.path.to_str()
            || self.core.path_for(&self.intent)? != self.path
        {
            return Err(AuthorityError::InvalidBinding);
        }
        validate_record_against_intent(&self.core, &self.intent, birth)
    }
    pub(crate) fn check_setup_current(
        &self,
        guard: FinancialSetupGuardV1<'_>,
        mutation: bool,
    ) -> Result<()> {
        self.check_setup_current_read_guarded(
            crate::journal::ReadGuardV1::coordinated(guard),
            mutation,
        )
    }
    /// Restricts the same owner audit to the actual accepted connection ceiling.
    /// This cannot replace an action guard or mint a renewed deadline.
    pub(crate) fn check_setup_current_until(
        &self,
        guard: FinancialSetupGuardV1<'_>,
        mutation: bool,
        original_deadline: std::time::Instant,
    ) -> Result<()> {
        self.check_setup_current_read_guarded(
            crate::journal::ReadGuardV1::coordinated_until(guard, original_deadline),
            mutation,
        )
    }
    fn check_setup_current_read_guarded(
        &self,
        read_guard: crate::journal::ReadGuardV1<'_>,
        mutation: bool,
    ) -> Result<()> {
        self.core.check_current_read_guarded(read_guard)?;
        let c = self
            .core
            .registry
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        read_guard.check()?;
        self.check_registry_locked_read_guarded(mutation, &c, read_guard)
    }
    fn check_registry_locked(&self, mutation: bool, c: &EncryptedConnection) -> Result<()> {
        self.check_registry_locked_guarded(mutation, c, FinancialSetupGuardV1::legacy())
    }
    fn check_registry_locked_guarded(
        &self,
        mutation: bool,
        c: &EncryptedConnection,
        guard: FinancialSetupGuardV1<'_>,
    ) -> Result<()> {
        self.check_registry_locked_read_guarded(
            mutation,
            c,
            crate::journal::ReadGuardV1::coordinated(guard),
        )
    }
    fn check_registry_locked_read_guarded(
        &self,
        mutation: bool,
        c: &EncryptedConnection,
        read_guard: crate::journal::ReadGuardV1<'_>,
    ) -> Result<()> {
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Deferred)?;
        read_guard.check()?;
        let history = storage::load_exact_guarded(&tx, &self.core.namespace, read_guard)?;
        let prepared = history
            .prepared
            .get(&self.intent_digest)
            .ok_or(AuthorityError::RecoveryRequired)?;
        if prepared.intent != self.intent || !history.completed.contains_key(&self.intent_digest) {
            return Err(AuthorityError::RecoveryRequired);
        }
        if mutation
            && history
                .exclusions
                .iter()
                .any(|e| e.exclusion.identity.overlaps(self.intent.identity()))
        {
            return Err(AuthorityError::PolicyDenied);
        }
        read_guard.check()?;
        Ok(())
    }
}
pub(crate) struct ReservedWitnessBirth {
    owner: Arc<BornJournalOwner>,
    publication: NativePublicationLease,
    disposition: BirthDisposition,
    existing: Option<PendingBirthCommitRecord>,
    prepared_at_ms: u64,
}
pub(crate) fn reserve_birth(decision: NativeEnrollmentDecision) -> Result<ReservedWitnessBirth> {
    let (proposal, lease) = decision.into_parts();
    proposal.check_current()?;
    if lease.reviewed_digest() != proposal.reviewed {
        return Err(AuthorityError::InvalidBinding);
    }
    let publication = lease.publication_lease()?;
    publication.check_current()?;
    if publication.reviewed_digest() != proposal.reviewed
        || publication.admitted_at_ms() > crate::now_ms()?
    {
        return Err(AuthorityError::InvalidBinding);
    }
    let core = &proposal.core;
    let prepared_at_ms = {
        let c = core.registry.lock().map_err(|_| AuthorityError::Storage)?;
        core.registry_identity.check_current(c.connection())?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate)?;
        let history = storage::load_exact(&tx, &core.namespace)?;
        let key = proposal.intent.digest(&core.namespace)?;
        let prepared_at_ms = if let Some(original) = history.prepared.get(&key) {
            if original.intent != proposal.intent {
                return Err(AuthorityError::Conflict);
            }
            // Deadline-free recovery is only for a preflight authenticated valid
            // journal, not an expired reserved/absent/empty target.
            if matches!(proposal.disposition, BirthDisposition::FirstCommitAllowed) {
                storage::prepare_in_transaction(&tx, &history, &proposal.intent, crate::now_ms()?)?;
            }
            original.prepared_at_ms
        } else {
            if !matches!(proposal.disposition, BirthDisposition::FirstCommitAllowed) {
                return Err(AuthorityError::RecoveryRequired);
            }
            let now = crate::now_ms()?;
            storage::prepare_in_transaction(&tx, &history, &proposal.intent, now)?;
            now
        };
        publication.check_current()?;
        core.files.check_current()?;
        tx.commit()?;
        core.files.sync_directories()?;
        prepared_at_ms
    };
    let path = core.path_for(&proposal.intent)?;
    let key = core.key_for(&proposal.intent)?;
    let intent_digest = proposal.intent.digest(&core.namespace)?;
    let owner = Arc::new(BornJournalOwner {
        core: proposal.core,
        intent: proposal.intent,
        path,
        key,
        intent_digest,
    });
    let out = ReservedWitnessBirth {
        owner,
        publication,
        disposition: proposal.disposition,
        existing: proposal.existing,
        prepared_at_ms,
    };
    out.check_current()?;
    Ok(out)
}
impl ReservedWitnessBirth {
    pub(crate) fn path(&self) -> &Path {
        &self.owner.path
    }
    pub(crate) fn database_key(&self) -> &DatabaseKey {
        &self.owner.key
    }
    pub(crate) fn namespace_digest(&self) -> &str {
        &self.owner.intent.namespace_digest
    }
    pub(crate) fn intent_digest(&self) -> &str {
        &self.owner.intent_digest
    }
    pub(crate) fn request(&self) -> &PendingBirthRequest {
        &self.owner.intent.request
    }
    pub(crate) fn disposition(&self) -> BirthDisposition {
        self.disposition
    }
    #[allow(dead_code)] // Optional strengthening for callers; original intent remains mandatory.
    pub(crate) fn existing_commit(&self) -> Option<&PendingBirthCommitRecord> {
        self.existing.as_ref()
    }
    pub(crate) fn owner(&self) -> Arc<BornJournalOwner> {
        self.owner.clone()
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        self.publication.check_current()?;
        self.owner.core.check_current()?;
        let c = self
            .owner
            .core
            .registry
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Deferred)?;
        let history = storage::load_exact(&tx, &self.owner.core.namespace)?;
        let original = history
            .prepared
            .get(&self.owner.intent_digest)
            .ok_or(AuthorityError::RecoveryRequired)?;
        if original.intent != self.owner.intent || original.prepared_at_ms != self.prepared_at_ms {
            return Err(AuthorityError::Conflict);
        }
        if matches!(self.disposition, BirthDisposition::FirstCommitAllowed) {
            self.request()
                .require_initial_commit_time(crate::now_ms()?)?;
            if history
                .exclusions
                .iter()
                .any(|e| e.exclusion.identity.overlaps(self.owner.intent.identity()))
            {
                return Err(AuthorityError::PolicyDenied);
            }
        }
        Ok(())
    }
    pub(crate) fn initial_commit_record(&self, now: u64) -> Result<PendingBirthCommitRecord> {
        self.check_current()?;
        if !matches!(self.disposition, BirthDisposition::FirstCommitAllowed) {
            return Err(AuthorityError::Permission);
        }
        self.request().require_initial_commit_time(now)?;
        if now < self.prepared_at_ms {
            return Err(AuthorityError::InvalidBinding);
        }
        let i = &self.owner.intent;
        Ok(PendingBirthCommitRecord {
            version: 1,
            request: i.request.clone(),
            request_digest: i.request_digest.clone(),
            authenticated_owner_certificate_digest: i
                .request
                .policy
                .owner_certificate_digest
                .clone(),
            owner_approval_evidence_digest: i.owner_approval_evidence_digest.clone(),
            local_target_digest: i.local_target_digest.clone(),
            local_owner_review_digest: i.local_owner_review_digest.clone(),
            committed_at_ms: now,
        })
    }
    pub(crate) fn validate_authenticated_record(
        &self,
        record: &PendingBirthCommitRecord,
    ) -> Result<()> {
        validate_record_against_intent(&self.owner.core, &self.owner.intent, record)?;
        if record.committed_at_ms < self.prepared_at_ms {
            return Err(AuthorityError::CorruptHistory);
        }
        if self
            .existing
            .as_ref()
            .is_some_and(|original| original != record)
        {
            return Err(AuthorityError::Conflict);
        }
        Ok(())
    }
    pub(crate) fn complete_authenticated(
        &mut self,
        policy: &crate::AccountPolicy,
        record: &PendingBirthCommitRecord,
        actual: &EncryptedConnection,
    ) -> Result<()> {
        self.check_current()?;
        self.validate_authenticated_record(record)?;
        if policy != &self.request().policy || actual.connection().path() != self.path().to_str() {
            return Err(AuthorityError::InvalidBinding);
        }
        let identity = actual.database_identity()?;
        identity.check_current(actual.connection())?;
        let journal_identity = actual_journal_identity(self.path())?;
        let evidence = CompletionEvidence {
            version: 1,
            intent_digest: self.intent_digest().into(),
            journal_identity,
            journal_genesis_commitment: digest(
                "wholepact:witness-locator-journal-genesis:v1",
                &(policy, record),
            )?,
            birth_commit: record.clone(),
        };
        let c = self
            .owner
            .core
            .registry
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate)?;
        let history = storage::load_exact(&tx, &self.owner.core.namespace)?;
        storage::complete_in_transaction(
            &tx,
            &history,
            &self.owner.intent,
            &evidence,
            crate::now_ms()?,
        )?;
        self.publication.check_current()?;
        self.owner.core.files.check_current()?;
        identity.check_current(actual.connection())?;
        tx.commit()?;
        self.owner.core.files.sync_directories()?;
        self.existing = Some(record.clone());
        Ok(())
    }
}
fn validate_record_against_intent(
    core: &NamespaceCore,
    intent: &CreationIntent,
    record: &PendingBirthCommitRecord,
) -> Result<()> {
    record.validate()?;
    intent.validate(&core.namespace)?;
    if record.request != intent.request
        || record.request_digest != intent.request_digest
        || record.local_target_digest != intent.local_target_digest
        || record.local_owner_review_digest != intent.local_owner_review_digest
        || record.owner_approval_evidence_digest != intent.owner_approval_evidence_digest
    {
        return Err(AuthorityError::CorruptHistory);
    }
    Ok(())
}
fn actual_journal_identity(path: &Path) -> Result<JournalIdentity> {
    actual_journal_identity_guarded(path, crate::journal::ReadGuardV1::legacy())
}

fn actual_journal_identity_guarded(
    path: &Path,
    guard: crate::journal::ReadGuardV1<'_>,
) -> Result<JournalIdentity> {
    let m = crate::journal::guarded_read!(
        guard,
        fs::symlink_metadata(path).map_err(|_| AuthorityError::Storage)
    )?;
    if !m.is_file() || m.nlink() != 1 || m.mode() & 0o7777 != 0o600 {
        return Err(AuthorityError::Storage);
    }
    Ok(JournalIdentity {
        device: m.dev(),
        inode: m.ino(),
        owner_uid: m.uid(),
    })
}

fn check_inventory(files: &InstallationFiles, history: &LocatorHistory) -> Result<()> {
    check_inventory_guarded(files, history, crate::journal::ReadGuardV1::legacy())
}

fn check_inventory_guarded(
    files: &InstallationFiles,
    history: &LocatorHistory,
    guard: crate::journal::ReadGuardV1<'_>,
) -> Result<()> {
    let mut bytes = 0u64;
    let mut count = 0usize;
    let mut directory = crate::journal::guarded_read!(
        guard,
        fs::read_dir(files.root_path()).map_err(|_| AuthorityError::Storage)
    )?;
    while let Some(e) = next_inventory_entry(&mut directory, guard)? {
        let name = e.file_name();
        let name = name.to_str().ok_or(AuthorityError::CorruptHistory)?;
        if name == "journals" {
            continue;
        }
        if ![
            "installation.id",
            "registry.wp",
            "registry.wp-wal",
            "registry.wp-shm",
            "registry.wp-journal",
        ]
        .contains(&name)
        {
            return Err(AuthorityError::RecoveryRequired);
        }
        inventory_file_guarded(&e.path(), &mut bytes, &mut count, guard)?;
    }
    let names: BTreeSet<String> = history
        .prepared
        .values()
        .map(|p| {
            p.intent
                .derived_child
                .trim_start_matches("journals/")
                .to_owned()
        })
        .collect();
    let mut directory = crate::journal::guarded_read!(
        guard,
        fs::read_dir(files.root_path().join("journals")).map_err(|_| AuthorityError::Storage)
    )?;
    while let Some(e) = next_inventory_entry(&mut directory, guard)? {
        let name = e.file_name();
        let name = name.to_str().ok_or(AuthorityError::CorruptHistory)?;
        let main = name
            .strip_suffix("-wal")
            .or_else(|| name.strip_suffix("-shm"))
            .or_else(|| name.strip_suffix("-journal"))
            .unwrap_or(name);
        if !names.contains(main) {
            return Err(AuthorityError::RecoveryRequired);
        }
        if main != name
            && !inventory_is_file(&files.root_path().join("journals").join(main), guard)?
        {
            return Err(AuthorityError::CorruptHistory);
        }
        inventory_file_guarded(&e.path(), &mut bytes, &mut count, guard)?;
    }
    for (key, completed) in &history.completed {
        let prepared = history
            .prepared
            .get(key)
            .ok_or(AuthorityError::CorruptHistory)?;
        let identity = actual_journal_identity_guarded(
            &files.root_path().join(&prepared.intent.derived_child),
            guard,
        )?;
        if identity != completed.evidence.journal_identity {
            return Err(AuthorityError::RecoveryRequired);
        }
    }
    Ok(())
}
fn inventory_file(path: &Path, bytes: &mut u64, count: &mut usize) -> Result<()> {
    inventory_file_guarded(path, bytes, count, crate::journal::ReadGuardV1::legacy())
}

fn inventory_file_guarded(
    path: &Path,
    bytes: &mut u64,
    count: &mut usize,
    guard: crate::journal::ReadGuardV1<'_>,
) -> Result<()> {
    let m = crate::journal::guarded_read!(
        guard,
        fs::symlink_metadata(path).map_err(|_| AuthorityError::Storage)
    )?;
    if !m.is_file() || m.nlink() != 1 || m.mode() & 0o7777 != 0o600 {
        return Err(AuthorityError::Storage);
    }
    *bytes = bytes.checked_add(m.len()).ok_or(AuthorityError::Limit)?;
    *count += 1;
    if *bytes > 512 * 1024 * 1024 || *count > 4 * MAX_INTENTS + 5 {
        return Err(AuthorityError::Limit);
    }
    Ok(())
}

/// Inert exact inventory for a future encrypted backup consumer. This does not
/// activate a restored registry or supply credentials. Destination/export still
/// needs its separately scoped native consent and full checkpoint protocol.
#[derive(Serialize)]
#[allow(dead_code)] // Audit inventory only; no backup/restore activation API yet.
pub(crate) struct NamespaceBackupInventory {
    namespace: WitnessNamespaceBinding,
    files: Vec<String>,
    requires_independent_storage_key: bool,
    restored_must_remain_quarantined: bool,
}
impl BornJournalOwner {
    #[allow(dead_code)] // Future consented encrypted-backup consumer.
    pub(crate) fn backup_inventory(&self) -> Result<NamespaceBackupInventory> {
        self.check_current()?;
        let c = self
            .core
            .registry
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Deferred)?;
        let history = storage::load_exact(&tx, &self.core.namespace)?;
        check_inventory(&self.core.files, &history)?;
        let mut files = Vec::new();
        for directory in [
            self.core.files.root_path().to_path_buf(),
            self.core.files.root_path().join("journals"),
        ] {
            for e in fs::read_dir(directory).map_err(|_| AuthorityError::Storage)? {
                let e = e.map_err(|_| AuthorityError::Storage)?;
                if e.file_type()
                    .map_err(|_| AuthorityError::Storage)?
                    .is_file()
                {
                    files.push(
                        e.path()
                            .to_str()
                            .ok_or(AuthorityError::InvalidBinding)?
                            .into(),
                    );
                }
            }
        }
        files.sort();
        Ok(NamespaceBackupInventory {
            namespace: self.core.namespace.clone(),
            files,
            requires_independent_storage_key: true,
            restored_must_remain_quarantined: true,
        })
    }
}

fn require_new_target_absent(path: &Path) -> Result<()> {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut candidate = path.as_os_str().to_os_string();
        candidate.push(suffix);
        match fs::symlink_metadata(PathBuf::from(candidate)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => return Err(AuthorityError::RecoveryRequired),
            Err(_) => return Err(AuthorityError::Storage),
        }
    }
    Ok(())
}

#[cfg(test)]
mod owner_model_tests {
    use super::*;
    #[test]
    fn explicit_setup_cannot_reimport_an_existing_witness_identity() {
        let input = NamespaceSetupInput {
            #[cfg(feature = "synthetic-qualification")]
            synthetic_installation: None,
            endpoint: "127.0.0.1:1911".into(),
            server_name: "localhost".into(),
            witness_id: "previously-used-witness".into(),
            pinned_server_certificate_digest: "1".repeat(64),
            owner_certificate_digest: "2".repeat(64),
            network_profile_id: "synthetic-network".into(),
            storage_key_file: "/synthetic/never-read.key".into(),
        };
        // Reject occurs before OS-home probing, locks, key reads or randomness.
        assert!(matches!(
            prepare_namespace_setup(input),
            Err(AuthorityError::RecoveryRequired)
        ));
    }
    #[test]
    fn fresh_target_preflight_preserves_unknown_files_and_sidecars() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("synthetic.wp");
        require_new_target_absent(&target).unwrap();
        fs::write(&target, b"preserve unknown state").unwrap();
        assert!(require_new_target_absent(&target).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"preserve unknown state");
        let other = directory.path().join("other.wp");
        fs::write(directory.path().join("other.wp-wal"), b"preserve sidecar").unwrap();
        assert!(require_new_target_absent(&other).is_err());
    }
    // There is intentionally no fake NativeSetupDecision/NativeEnrollmentDecision
    // constructor or positive native acceptance fixture in this module.
}

/// Historical server opener for a fully completed canonical birth. No native
/// enrollment or first-write fallback is possible through this read-only route.
pub(crate) fn open_born_history(input: NamespaceOpenInput) -> Result<AuthorityJournal> {
    open_born_history_guarded(input, FinancialSetupGuardV1::legacy())
}
pub(crate) fn open_born_history_guarded(
    input: NamespaceOpenInput,
    guard: FinancialSetupGuardV1<'_>,
) -> Result<AuthorityJournal> {
    let read_guard = crate::journal::ReadGuardV1::coordinated(guard);
    hash(&input.expected_account_id)?;
    let core = open_namespace_identity_guarded(&input.setup(), guard)?;
    let (intent, expected_record) = {
        let c = core.registry.lock().map_err(|_| AuthorityError::Storage)?;
        guard.check()?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Deferred)?;
        guard.check()?;
        let history = storage::load_exact_guarded(&tx, &core.namespace, read_guard)?;
        let mut selected = history
            .prepared
            .values()
            .filter(|p| p.intent.identity().account_id == input.expected_account_id);
        let prepared = selected.next().ok_or(AuthorityError::RecoveryRequired)?;
        if selected.next().is_some() {
            return Err(AuthorityError::CorruptHistory);
        }
        let digest = prepared.intent.digest(&core.namespace)?;
        let completed = history
            .completed
            .get(&digest)
            .ok_or(AuthorityError::RecoveryRequired)?;
        (
            prepared.intent.clone(),
            completed.evidence.birth_commit.clone(),
        )
    };
    guard.check()?;
    let path = core.path_for(&intent)?;
    let key = core.key_for(&intent)?;
    guard.check()?;
    let intent_digest = intent.digest(&core.namespace)?;
    let owner = Arc::new(BornJournalOwner {
        core,
        intent,
        path,
        key,
        intent_digest,
    });
    owner.check_setup_current(guard, false)?;
    AuthorityJournal::open_born_history_only_guarded(
        owner.clone(),
        &owner.path,
        &owner.key,
        &owner.intent.request.policy,
        &expected_record,
        guard,
    )
}

/// Original completed account with the financial profile and a live setup gate.
#[cfg(feature = "coordinated-witness-financial-signing")]
pub(crate) fn open_born_financial_history_guarded_v1(
    input: NamespaceOpenInput,
    guard: FinancialSetupGuardV1<'_>,
) -> Result<AuthorityJournal> {
    let read_guard = crate::journal::ReadGuardV1::coordinated(guard);
    hash(&input.expected_account_id)?;
    let core = open_namespace_identity_guarded(&input.setup(), guard)?;
    let (intent, expected_record) = {
        let c = core.registry.lock().map_err(|_| AuthorityError::Storage)?;
        guard.check()?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Deferred)?;
        guard.check()?;
        let history = storage::load_exact_guarded(&tx, &core.namespace, read_guard)?;
        let mut selected = history
            .prepared
            .values()
            .filter(|p| p.intent.identity().account_id == input.expected_account_id);
        let prepared = selected.next().ok_or(AuthorityError::RecoveryRequired)?;
        if selected.next().is_some() {
            return Err(AuthorityError::CorruptHistory);
        }
        let digest = prepared.intent.digest(&core.namespace)?;
        let completed = history
            .completed
            .get(&digest)
            .ok_or(AuthorityError::RecoveryRequired)?;
        (
            prepared.intent.clone(),
            completed.evidence.birth_commit.clone(),
        )
    };
    guard.check()?;
    let path = core.path_for(&intent)?;
    let key = core.key_for(&intent)?;
    guard.check()?;
    let intent_digest = intent.digest(&core.namespace)?;
    let owner = Arc::new(BornJournalOwner {
        core,
        intent,
        path,
        key,
        intent_digest,
    });
    owner.check_setup_current(guard, false)?;
    AuthorityJournal::open_born_financial_history_only_guarded_v1(
        owner.clone(),
        &owner.path,
        &owner.key,
        &owner.intent.request.policy,
        &expected_record,
        guard,
    )
}

pub(crate) fn open_born_financial_history_v1(
    input: NamespaceOpenInput,
) -> Result<AuthorityJournal> {
    let core = open_namespace(&input)?;
    open_financial_account_under_namespace_v1(core, &input.expected_account_id)
}

/// Open a bounded set of exact original accounts under ONE held installation
/// owner. Reopening the same exclusive namespace for each route is forbidden:
/// it conflicts with the first route's live directory/registry locks.
pub(crate) fn open_born_financial_histories_v1(
    inputs: &[NamespaceOpenInput],
) -> Result<Vec<AuthorityJournal>> {
    let first = inputs.first().ok_or(AuthorityError::Limit)?;
    if inputs.len() > 2 {
        return Err(AuthorityError::Limit);
    }
    let mut accounts = BTreeSet::new();
    for input in inputs {
        input.setup().validate()?;
        hash(&input.expected_account_id)?;
        if !accounts.insert(input.expected_account_id.as_str()) {
            return Err(AuthorityError::Conflict);
        }
        if !same_financial_namespace_v1(first, input) {
            return Err(AuthorityError::InvalidBinding);
        }
    }
    let core = open_namespace(first)?;
    let mut journals = Vec::with_capacity(inputs.len());
    for input in inputs {
        journals.push(open_financial_account_under_namespace_v1(
            Arc::clone(&core),
            &input.expected_account_id,
        )?);
    }
    core.check_current()?;
    Ok(journals)
}
fn same_financial_namespace_v1(a: &NamespaceOpenInput, b: &NamespaceOpenInput) -> bool {
    #[cfg(feature = "synthetic-qualification")]
    if !match (&a.synthetic_installation, &b.synthetic_installation) {
        (None, None) => true,
        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
        _ => false,
    } {
        return false;
    }
    a.endpoint == b.endpoint
        && a.server_name == b.server_name
        && a.witness_id == b.witness_id
        && a.pinned_server_certificate_digest == b.pinned_server_certificate_digest
        && a.owner_certificate_digest == b.owner_certificate_digest
        && a.network_profile_id == b.network_profile_id
        && a.storage_key_file == b.storage_key_file
}
fn open_financial_account_under_namespace_v1(
    core: Arc<NamespaceCore>,
    expected_account_id: &str,
) -> Result<AuthorityJournal> {
    hash(expected_account_id)?;
    core.check_current()?;
    let (intent, expected_record) = {
        let c = core.registry.lock().map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Deferred)?;
        let history = storage::load_exact(&tx, &core.namespace)?;
        let mut selected = history
            .prepared
            .values()
            .filter(|p| p.intent.identity().account_id == expected_account_id);
        let prepared = selected.next().ok_or(AuthorityError::RecoveryRequired)?;
        if selected.next().is_some() {
            return Err(AuthorityError::CorruptHistory);
        }
        let digest = prepared.intent.digest(&core.namespace)?;
        let completed = history
            .completed
            .get(&digest)
            .ok_or(AuthorityError::RecoveryRequired)?;
        (
            prepared.intent.clone(),
            completed.evidence.birth_commit.clone(),
        )
    };
    let path = core.path_for(&intent)?;
    let key = core.key_for(&intent)?;
    let intent_digest = intent.digest(&core.namespace)?;
    let owner = Arc::new(BornJournalOwner {
        core,
        intent,
        path,
        key,
        intent_digest,
    });
    owner.check_current()?;
    AuthorityJournal::open_born_financial_history_only_v1(
        owner.clone(),
        &owner.path,
        &owner.key,
        &owner.intent.request.policy,
        &expected_record,
    )
}

#[cfg(test)]
mod registry_preflight_tests {
    //! Synthetic encrypted-storage negatives. They operate only in a fresh
    //! tempfile, never the fixed OS-user installation, and mint no native owner.
    use super::*;
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;
    use wholepact_storage_security::create_encrypted;

    enum Damage {
        WrongApplication,
        UnknownVersion,
        WrongSchema,
        MissingNamespace,
    }
    struct Fixture {
        _directory_lock: fs::File,
        directory: tempfile::TempDir,
        _quiescent_connection: EncryptedConnection,
        key: DatabaseKey,
        path: PathBuf,
    }
    fn fixture(damage: Damage) -> Fixture {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let lock = fs::File::open(directory.path()).unwrap();
        lock.try_lock().unwrap();
        let path = directory.path().join("synthetic-registry.wp");
        let key = DatabaseKey::from_bytes([0x41; 32]); // SYNTHETIC, never a real credential.
        let connection = create_encrypted(&path, &key).unwrap();
        let c = connection.connection();
        c.execute_batch(match damage {
            Damage::WrongSchema => "CREATE TABLE wrong_application_table(v INTEGER)",
            _ => storage::SCHEMA,
        })
        .unwrap();
        c.pragma_update(
            None,
            "application_id",
            match damage {
                Damage::WrongApplication => 0x57504157,
                _ => storage::LOCATOR_APPLICATION_ID,
            },
        )
        .unwrap();
        c.pragma_update(
            None,
            "user_version",
            match damage {
                Damage::UnknownVersion => 99,
                _ => storage::LOCATOR_SCHEMA_VERSION,
            },
        )
        .unwrap();
        if !matches!(damage, Damage::WrongSchema) {
            c.execute("INSERT INTO witness_locator_quarantine VALUES(1,0)", [])
                .unwrap();
        }
        // Intentionally no namespace row. Wrong app/version/schema must be
        // rejected earlier; the matching-schema case must report unknown state.
        Fixture {
            _directory_lock: lock,
            directory,
            _quiescent_connection: connection,
            key,
            path,
        }
    }
    fn source_bytes(directory: &Path) -> BTreeMap<String, Vec<u8>> {
        let mut result = BTreeMap::new();
        let mut total = 0usize;
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let metadata = fs::symlink_metadata(entry.path()).unwrap();
            assert!(metadata.is_file());
            assert!(metadata.len() <= 4 * 1024 * 1024);
            let bytes = fs::read(entry.path()).unwrap();
            total += bytes.len();
            assert!(total <= 16 * 1024 * 1024);
            result.insert(entry.file_name().into_string().unwrap(), bytes);
        }
        assert!(!result.is_empty());
        result
    }
    #[test]
    fn wrong_application_version_or_schema_cannot_touch_original_file_set() {
        for damage in [
            Damage::WrongApplication,
            Damage::UnknownVersion,
            Damage::WrongSchema,
        ] {
            let fixture = fixture(damage);
            let before = source_bytes(fixture.directory.path());
            assert!(read_registry_preflight(&fixture.path, &fixture.key).is_err());
            assert_eq!(source_bytes(fixture.directory.path()), before);
        }
    }
    #[test]
    fn missing_namespace_is_unknown_and_does_not_initialize_or_repair_source() {
        let fixture = fixture(Damage::MissingNamespace);
        let before = source_bytes(fixture.directory.path());
        assert!(matches!(
            read_registry_preflight(&fixture.path, &fixture.key),
            Err(AuthorityError::RecoveryRequired)
        ));
        assert_eq!(source_bytes(fixture.directory.path()), before);
        let count: u64 = fixture
            ._quiescent_connection
            .connection()
            .query_row("SELECT count(*) FROM witness_locator_namespace", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(count, 0);
    }
    #[test]
    fn wrong_key_never_falls_back_to_writable_or_empty_namespace() {
        let fixture = fixture(Damage::MissingNamespace);
        let before = source_bytes(fixture.directory.path());
        let wrong = DatabaseKey::from_bytes([0x42; 32]); // SYNTHETIC negative key only.
        assert!(read_registry_preflight(&fixture.path, &wrong).is_err());
        assert_eq!(source_bytes(fixture.directory.path()), before);
    }
}

#[cfg(feature = "born-offline-witness-owner")]
impl BornJournalOwner {
    pub(crate) fn namespace_binding_digest_v1(&self) -> Result<String> {
        self.check_current()?;
        self.core.namespace.digest()
    }
    /// Additional authenticated handles to the SAME completed original database.
    /// No caller path, namespace adoption, table initialization or new file exists.
    pub(crate) fn open_born_artifact_handles_v1(
        &self,
        original: &EncryptedConnection,
    ) -> Result<(EncryptedConnection, EncryptedConnection)> {
        self.check_mutation_current()?;
        let identity = original.database_identity()?;
        identity.check_current(original.connection())?;
        if original.connection().path() != self.path.to_str() {
            return Err(AuthorityError::InvalidBinding);
        }
        let tx = Transaction::new_unchecked(original.connection(), TransactionBehavior::Deferred)?;
        crate::journal::verify_born_artifact_schema_v1(&tx)?;
        let (expected, birth) =
            crate::journal::namespace_account_stamp(&tx, &self.intent.request.policy)?;
        validate_record_against_intent(&self.core, &self.intent, &birth)?;
        // Authenticated immutable preflight precedes additional mutable handles.
        let snapshot =
            wholepact_storage_security::open_encrypted_read_snapshot(&self.path, &self.key)?;
        if crate::journal::namespace_account_stamp(
            snapshot.connection(),
            &self.intent.request.policy,
        )?
        .0 != expected
        {
            return Err(AuthorityError::Conflict);
        }
        drop(snapshot);
        let inbox = wholepact_storage_security::open_encrypted(&self.path, &self.key)?;
        let outbox = wholepact_storage_security::open_encrypted(&self.path, &self.key)?;
        for c in [&inbox, &outbox] {
            identity.check_current(c.connection())?;
            require_runtime(c.connection())?;
            let read = Transaction::new_unchecked(c.connection(), TransactionBehavior::Deferred)?;
            crate::journal::verify_born_artifact_schema_v1(&read)?;
            if crate::journal::namespace_account_stamp(&read, &self.intent.request.policy)?.0
                != expected
            {
                return Err(AuthorityError::Conflict);
            }
        }
        self.check_mutation_current()?;
        identity.check_current(original.connection())?;
        Ok((inbox, outbox))
    }
}

#[cfg(all(test, feature = "synthetic-qualification"))]
mod shared_financial_namespace_lock_tests {
    use super::*;

    /// Storage-component regression only, not native permission or a completed
    /// financial source. Real installation locks and encrypted files reproduce
    /// the router's old second-open failure without opening a socket or GUI.
    #[test]
    fn one_installation_owner_holds_two_encrypted_account_handles() {
        use wholepact_storage_security::witness_namespace_fs::EphemeralWitnessInstallation;
        let installation = EphemeralWitnessInstallation::new().unwrap();
        let files = installation
            .probe()
            .unwrap()
            .create_once(&"a".repeat(64))
            .unwrap();
        let key_a = DatabaseKey::from_bytes([0x31; 32]);
        let key_b = DatabaseKey::from_bytes([0x32; 32]);
        let path_a = files.root_path().join("journals/account-a.wp");
        let path_b = files.root_path().join("journals/account-b.wp");
        for (path, key) in [(&path_a, &key_a), (&path_b, &key_b)] {
            let c = wholepact_storage_security::create_encrypted(path, key).unwrap();
            c.connection().execute_batch("CREATE TABLE retained_head(singleton INTEGER PRIMARY KEY, sequence INTEGER NOT NULL); INSERT INTO retained_head VALUES(1,0);").unwrap();
        }
        // Exactly the second independent namespace open used by the old router.
        assert!(matches!(
            installation.probe(),
            Err(wholepact_storage_security::StorageSecurityError::UnsafePath)
        ));
        let owner = Arc::new(files);
        let retained_a = Arc::clone(&owner);
        let retained_b = Arc::clone(&owner);
        let a = wholepact_storage_security::open_encrypted_quiescent(&path_a, &key_a).unwrap();
        let b = wholepact_storage_security::open_encrypted_quiescent(&path_b, &key_b).unwrap();
        assert!(wholepact_storage_security::open_encrypted_read_snapshot(&path_a, &key_b).is_err());
        for c in [&a, &b] {
            assert_eq!(
                c.connection()
                    .execute(
                        "UPDATE retained_head SET sequence=1 WHERE singleton=1 AND sequence=0",
                        []
                    )
                    .unwrap(),
                1
            );
            assert_eq!(
                c.connection()
                    .execute(
                        "UPDATE retained_head SET sequence=2 WHERE singleton=1 AND sequence=0",
                        []
                    )
                    .unwrap(),
                0
            );
        }
        retained_a.check_current().unwrap();
        retained_b.check_current().unwrap();
        drop(owner);
        drop(a);
        drop(retained_a);
        assert!(
            installation.probe().is_err(),
            "second account still retains original exclusion"
        );
        drop(b);
        drop(retained_b);
        let reopened = installation.probe().unwrap().open_existing().unwrap();
        reopened.check_current().unwrap();
        for (path, key) in [(&path_a, &key_a), (&path_b, &key_b)] {
            let c = wholepact_storage_security::open_encrypted_read_snapshot(path, key).unwrap();
            let sequence: u64 = c
                .connection()
                .query_row(
                    "SELECT sequence FROM retained_head WHERE singleton=1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(sequence, 1);
        }
    }
}

// Filesystem iteration is separately sampled. This does not interrupt an
// in-flight metadata operation or turn metadata into original authority.
fn next_inventory_entry(
    directory: &mut fs::ReadDir,
    guard: crate::journal::ReadGuardV1<'_>,
) -> Result<Option<fs::DirEntry>> {
    guard.check()?;
    let next = directory
        .next()
        .transpose()
        .map_err(|_| AuthorityError::Storage)?;
    guard.check()?;
    Ok(next)
}
fn inventory_is_file(path: &Path, guard: crate::journal::ReadGuardV1<'_>) -> Result<bool> {
    guard.check()?;
    let value = path.is_file();
    guard.check()?;
    Ok(value)
}
