//! Whole-host immutable recovery preflight. No mutable journal constructors,
//! activation credential, transport key reuse, or quarantine-clearing operation.
use crate::{
    Error, Result,
    files::Directory,
    terminal::Terminal,
    vault::{JOURNALS, Secrets},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use wholepact_storage_security::{
    DatabaseKey,
    bundle::{
        self, Coverage, JournalKind, JournalTemplate,
        history::HistoryOpenRequest,
        recovery::{RecoveryCell, RecoveryProvenance, VerifiedRecoveryComponent},
    },
};

/// Public review data is evidence, never a deserializable permission. Private
/// rows remain inside the sealed source and are not printed by the native UI.
#[derive(Serialize)]
struct Review {
    version: u32,
    generation_id: String,
    successor: PathBuf,
    restored_profile: PathBuf,
    profile_id: String,
    bundle_digest: String,
    checkpoint_id: String,
    coverage: Coverage,
    components: Vec<RecoveryProvenance>,
    registered_financial_directories: usize,
    known_account_ids: BTreeSet<String>,
    account_continuity_complete: bool,
    external_or_post_backup_signatures: &'static str,
    saved_observations: &'static str,
    activation_available: bool,
    required_before_activation: [&'static str; 5],
}

/// Non-cloneable, non-deserializable inventory. Exact complete immutable rows and
/// all directory locks survive for the entire review. This is NOT live authority.
pub(crate) struct Inventory {
    review: Review,
    components: Vec<VerifiedRecoveryComponent>,
    directories: Vec<Directory>,
}
impl Inventory {
    #[cfg(feature = "financial-runtime")]
    pub(crate) fn generation_id(&self) -> &str {
        &self.review.generation_id
    }
    #[cfg(feature = "financial-runtime")]
    pub(crate) fn successor(&self) -> &Path {
        &self.review.successor
    }
    #[cfg(feature = "financial-runtime")]
    pub(crate) fn profile_id(&self) -> &str {
        &self.review.profile_id
    }
    #[cfg(feature = "financial-runtime")]
    pub(crate) fn components(&self) -> &[VerifiedRecoveryComponent] {
        &self.components
    }
    #[cfg(feature = "financial-runtime")]
    pub(crate) fn known_account_ids(&self) -> &BTreeSet<String> {
        &self.review.known_account_ids
    }
    pub(crate) fn check(&self) -> Result<()> {
        for directory in &self.directories {
            directory.check()?;
        }
        if self.components.len() != self.review.components.len() {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    pub(crate) fn digest(&self) -> Result<String> {
        self.check()?;
        let mut digest = Sha256::new();
        digest.update(b"wholepact:host-recovery-inventory:v1");
        digest.update(serde_json::to_vec(&self.review)?);
        Ok(hex::encode(digest.finalize()))
    }
}

fn target(source: &Directory, destination: &Path) -> Result<()> {
    source.external_destination(destination)?;
    match std::fs::symlink_metadata(destination) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(Error::Invalid),
        Err(_) => Err(Error::Storage),
    }
}
fn complete_coverage(manifest: &bundle::BundleManifest) -> Result<usize> {
    let count = manifest
        .coverage
        .present
        .get(&JournalKind::WalletScan)
        .map_or(0, Vec::len);
    if count > 12 {
        return Err(Error::Invalid);
    }
    #[cfg(feature = "financial-runtime")]
    let expected = crate::financial_backup::coverage(count);
    #[cfg(not(feature = "financial-runtime"))]
    let expected = crate::backup::coverage();
    if manifest.coverage != expected || manifest.components.len() != 4 + 4 * count {
        return Err(Error::Unsupported);
    }
    // Coverage plus exact ID/kind bijection, not just counts or journal labels.
    let expected: BTreeSet<_> = expected
        .present
        .iter()
        .flat_map(|(kind, ids)| ids.iter().map(move |id| (id.as_str(), *kind)))
        .collect();
    let actual: BTreeSet<_> = manifest
        .components
        .iter()
        .map(|c| (c.id.as_str(), c.kind))
        .collect();
    if expected != actual || actual.len() != manifest.components.len() {
        return Err(Error::Invalid);
    }
    Ok(count)
}
fn component(
    archive: &Path,
    archive_key: &DatabaseKey,
    directory: &Directory,
    filename: &str,
    key: &DatabaseKey,
    id: &str,
    template: &'static JournalTemplate,
) -> Result<VerifiedRecoveryComponent> {
    // The shared storage reader isolates SQLite onto bounded private encrypted
    // snapshots, including WAL, so even sidecar writes cannot touch the source.
    Ok(VerifiedRecoveryComponent::open(
        HistoryOpenRequest {
            archive,
            archive_key,
            component_id: id,
            restored_component: &directory.path(filename)?,
            restored_key: key,
        },
        template,
    )?)
}
fn accounts(component: &VerifiedRecoveryComponent) -> Result<BTreeSet<String>> {
    let table = component
        .tables()
        .iter()
        .find(|table| table.name() == "authority_accounts")
        .ok_or(Error::Unsupported)?;
    let column = table
        .columns()
        .iter()
        .position(|column| column == "account_id")
        .ok_or(Error::Unsupported)?;
    let mut accounts = BTreeSet::new();
    for row in table.rows() {
        let Some(RecoveryCell::Text(account)) = row.cells().get(column) else {
            return Err(Error::Invalid);
        };
        crate::id(account)?;
        if !accounts.insert(account.clone()) {
            return Err(Error::Invalid);
        }
    }
    Ok(accounts)
}

/// Called only after a separate native approval to read historical private data.
/// Passwords are transient, zeroizing caller buffers; none enter the inventory.
pub(crate) fn prepare(
    profile: &Path,
    backup: &Path,
    successor: &Path,
    generation_id: String,
    restored_password: &[u8],
    backup_password: &[u8],
    expires: Instant,
) -> Result<Inventory> {
    prepare_target(
        profile,
        backup,
        successor,
        generation_id,
        restored_password,
        backup_password,
        TargetReview {
            expires,
            existing_target: false,
        },
    )
}

#[cfg(feature = "financial-runtime")]
pub(crate) fn prepare_for_resume(
    profile: &Path,
    backup: &Path,
    successor: &Path,
    generation_id: String,
    restored_password: &[u8],
    backup_password: &[u8],
    expires: Instant,
) -> Result<Inventory> {
    prepare_target(
        profile,
        backup,
        successor,
        generation_id,
        restored_password,
        backup_password,
        TargetReview {
            expires,
            existing_target: true,
        },
    )
}

struct TargetReview {
    expires: Instant,
    existing_target: bool,
}

fn prepare_target(
    profile: &Path,
    backup: &Path,
    successor: &Path,
    generation_id: String,
    restored_password: &[u8],
    backup_password: &[u8],
    review: TargetReview,
) -> Result<Inventory> {
    let TargetReview {
        expires,
        existing_target,
    } = review;
    let target = |source: &Directory, destination: &Path| {
        source.external_destination(destination)?;
        if existing_target {
            if std::fs::canonicalize(destination)? != destination || !destination.is_dir() {
                return Err(Error::Invalid);
            }
            Ok(())
        } else {
            target(source, destination)
        }
    };
    let check = || {
        if Instant::now() < expires {
            Ok(())
        } else {
            Err(Error::Permission)
        }
    };
    check()?;
    if generation_id.len() != 64 || !generation_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Invalid);
    }
    let restored = Directory::open(profile)?;
    restored.inventory()?;
    target(&restored, successor)?;
    if restored.read("restored.quarantine", 1024)?.is_empty() {
        return Err(Error::Invalid);
    }
    check()?;
    let secrets = Secrets::open(&restored.read("profile.vault", 1024)?, restored_password)?;
    let original = Directory::open(backup)?;
    target(&original, successor)?;
    if original.read("COMPLETE", 1024)? != crate::backup::COMPLETE {
        return Err(Error::Invalid);
    }
    check()?;
    let (original_secrets, archive_key) =
        Secrets::open_recovery(&original.read("recovery.wp", 1024)?, backup_password)?;
    if !secrets.same_recovery_material(&original_secrets) {
        return Err(Error::Authentication);
    }
    let archive = original.path("bundle.sqlite")?;
    // Authenticate via the immutable component reader: the legacy bundle
    // inspector alone would not authenticate the restored coordination rows.
    check()?;
    let selected_manifest = bundle::inspect(&archive, &archive_key)?;
    let selected = selected_manifest
        .components
        .iter()
        .find(|component| component.id == "coordination")
        .ok_or(Error::Authentication)?;
    if selected.kind != JournalKind::CoordinationAuthority || selected.application_id != 0 {
        return Err(Error::Authentication);
    }
    let coordination_template =
        wholepact_store::bundle::coordination_template_for_schema(selected.schema_version)?;
    let coordination = component(
        &archive,
        &archive_key,
        &restored,
        JOURNALS[0],
        &secrets.key(0)?,
        "coordination",
        coordination_template,
    )?;
    let manifest = coordination.manifest().clone();
    if manifest != selected_manifest {
        return Err(Error::Authentication);
    }
    if manifest.profile_id != secrets.profile() {
        return Err(Error::Authentication);
    }
    let count = complete_coverage(&manifest)?;
    let mut auxiliaries = vec![
        "profile.lock".to_owned(),
        "COMPLETE".into(),
        "recovery.wp".into(),
    ];
    if count > 0 {
        auxiliaries.push("financial.inventory".into());
        auxiliaries.extend((0..count).map(|index| format!("financial-{index}.vault")));
    } else if restored.path("financial.inventory")?.try_exists()?
        || restored.path("financial.attached")?.try_exists()?
    {
        return Err(Error::Invalid);
    }
    original.inventory_of(
        &["bundle.sqlite"],
        &auxiliaries.iter().map(String::as_str).collect::<Vec<_>>(),
    )?;
    let templates = [
        coordination_template,
        &wholepact_transport::bundle::INBOX_BACKUP_TEMPLATE,
        &wholepact_transport::bundle::OUTBOX_BACKUP_TEMPLATE,
        &wholepact_chain::backup::TEMPLATE,
    ];
    let mut components = vec![coordination];
    for (index, id) in ["coordination", "inbox", "outbox", "submission"]
        .iter()
        .enumerate()
        .skip(1)
    {
        check()?;
        components.push(component(
            &archive,
            &archive_key,
            &restored,
            JOURNALS[index],
            &secrets.key(index)?,
            id,
            templates[index],
        )?);
    }
    #[cfg_attr(not(feature = "financial-runtime"), allow(unused_mut))]
    let mut known_account_ids = accounts(&components[0])?;
    let mut directories = Vec::new();
    #[cfg(feature = "financial-runtime")]
    if count > 0 {
        use crate::{financial_inventory, financial_profile, vault::FinancialSecrets};
        if crate::financial_backup::metadata_digest(&original, count)? != manifest.checkpoint_id
            || restored.read("financial.attached", 1024)?.is_empty()
        {
            return Err(Error::Authentication);
        }
        check()?;
        let entries = financial_inventory::read(&original, &original_secrets)?;
        check()?;
        let current = financial_inventory::read(&restored, &secrets)?;
        if entries.len() != count || current.len() != count {
            return Err(Error::Invalid);
        }
        let name = profile
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(Error::Invalid)?;
        // Keep archive indexes, even though path lexical order differs for 10+.
        let mut ordered = Vec::new();
        for (index, entry) in entries.iter().enumerate() {
            if index > 0 && entries[index - 1].directory >= entry.directory {
                return Err(Error::Invalid);
            }
            let expected_path = profile.with_file_name(format!("{name}-financial-{index}"));
            let actual = current
                .iter()
                .find(|candidate| candidate.directory == expected_path)
                .ok_or(Error::Invalid)?;
            if actual.role != entry.role || actual.account != entry.account {
                return Err(Error::Invalid);
            }
            if let Some(account) = &entry.account {
                known_account_ids.insert(account.clone());
            }
            ordered.push((expected_path, index));
        }
        ordered.sort_by(|a, b| a.0.cmp(&b.0));
        let templates = [
            &wholepact_proof_jobs::backup::TEMPLATE,
            &wholepact_protocol::authorization::retention::backup::TEMPLATE,
            &wholepact_protocol::authorization::retention::transaction::backup::TEMPLATE,
        ];
        for (path, index) in ordered {
            check()?;
            let directory = Directory::open(&path)?;
            target(&directory, successor)?;
            directory.inventory_of(
                &financial_profile::JOURNALS,
                &["profile.lock", "financial.vault", "restored.quarantine"],
            )?;
            if directory.read("restored.quarantine", 1024)?.is_empty() {
                return Err(Error::Invalid);
            }
            let old = FinancialSecrets::open(
                &original.read(&format!("financial-{index}.vault"), 1024)?,
                &secrets.profile(),
                backup_password,
            )?;
            check()?;
            let fresh = FinancialSecrets::open(
                &directory.read("financial.vault", 1024)?,
                &secrets.profile(),
                restored_password,
            )?;
            if !old.same_recovery_material(&fresh) {
                return Err(Error::Authentication);
            }
            for (number, suffix) in ["wallet", "proof", "signed", "transactions"]
                .iter()
                .enumerate()
            {
                check()?;
                let component_id = format!("financial-{index}-{suffix}");
                let selected = if number == 0 {
                    wholepact_wallet::bundle::trusted_template_for_bundle_component(
                        &archive,
                        &archive_key,
                        &component_id,
                    )?
                } else {
                    templates[number - 1]
                };
                components.push(component(
                    &archive,
                    &archive_key,
                    &directory,
                    financial_profile::JOURNALS[number],
                    &fresh.key(number)?,
                    &component_id,
                    selected,
                )?);
            }
            directories.push(directory);
        }
    }
    // Each sealed component must come from exactly the same authenticated bundle.
    if components.len() != manifest.components.len()
        || components
            .iter()
            .any(|component| component.manifest() != &manifest)
    {
        return Err(Error::Authentication);
    }
    components.sort_by(|a, b| {
        a.provenance()
            .component_id
            .cmp(&b.provenance().component_id)
    });
    let review = Review {
        version: 1,
        generation_id,
        successor: successor.to_owned(),
        restored_profile: profile.to_owned(),
        profile_id: secrets.profile(),
        bundle_digest: manifest.digest,
        checkpoint_id: manifest.checkpoint_id,
        coverage: manifest.coverage,
        components: components.iter().map(|c| c.provenance().clone()).collect(),
        registered_financial_directories: count,
        known_account_ids,
        account_continuity_complete: false,
        external_or_post_backup_signatures: "unknown; may still settle; never inferred absent from this inventory",
        saved_observations: "historical only; current chain confidence and discounts are not established",
        activation_available: false,
        required_before_activation: [
            "signer-owned live continuity for every affected account, bound to this exact successor inventory and generation",
            "conservative typed successor journal transitions preserving every exact artifact and unknown exposure",
            "fresh host credentials, native client and peer enrollment, disclosure and account permissions",
            "fresh independently verified wallet and chain observations; no saved positive-status promotion",
            "durable generation plan, exact retry verification and sealed publication/opening gates",
        ],
    };
    directories.push(restored);
    directories.push(original);
    let inventory = Inventory {
        review,
        components,
        directories,
    };
    check()?;
    inventory.check()?;
    Ok(inventory)
}

pub(crate) fn review(
    terminal: Terminal,
    profile: &Path,
    backup: &Path,
    successor: &Path,
) -> Result<()> {
    terminal.confirm(&format!("READ HISTORICAL PRIVATE DATA for recovery preflight. Read every encrypted host-owned component, including wallet viewing history, proof witnesses, signatures, exact transactions, transport and observer history. Private encrypted temporary copies isolate SQLite sidecar writes; interrupted cleanup can leave encrypted copies. Data stays local; only inventory metadata and account identifiers will be displayed on this terminal.\nRestored profile: {}\nOriginal backup: {}\nProposed successor: {}\nThis is a separate private-data approval, not writer activation, disclosure to peers, signing or spending approval.", profile.display(), backup.display(), successor.display()))?;
    let expires = Instant::now() + Duration::from_secs(300);
    let password = terminal.secret("Restored profile passphrase: ")?;
    let backup_password = terminal.secret("Original backup passphrase: ")?;
    let inventory = prepare(
        profile,
        backup,
        successor,
        hex::encode(crate::random::<32>()?),
        password.as_bytes(),
        backup_password.as_bytes(),
        expires,
    )?;
    drop(password);
    drop(backup_password);
    if Instant::now() >= expires {
        return Err(Error::Permission);
    }
    let digest = inventory.digest()?;
    terminal.json(&inventory.review)?;
    terminal.confirm(&format!("Review this exact immutable inventory: {digest}. This approval records no permission and writes no successor. Unknown signatures remain possible; original permits, transport credentials and saved positive observations cannot be reactivated. This review alone cannot activate anything. The separate recovery-activate workflow, when built with financial-runtime, permits restricted coordination only after its additional semantic, native continuity and publication gates."))?;
    if Instant::now() >= expires {
        return Err(Error::Permission);
    }
    inventory.check()?;
    terminal.message("Complete host-owned inventory authenticated and reviewed. Source quarantine is unchanged. No successor, credentials, enrollment, current settlement evidence or activation permission was created. Signer-owned records and independent witness state remain separate.\n")
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;
    use wholepact_storage_security::{bundle::*, create_encrypted};
    pub(crate) const PASSWORD: &[u8] = b"synthetic-recovery-review-password";
    struct Gate;
    impl BundleAuthority for Gate {
        fn acquire<'a>(
            &'a self,
            _: &BundleScope<'_>,
        ) -> std::result::Result<Box<dyn BundleLease + 'a>, BundleError> {
            Ok(Box::new(Gate))
        }
    }
    impl BundleLease for Gate {
        fn check_current(&self) -> std::result::Result<(), BundleError> {
            Ok(())
        }
        fn checkpoint_id(&self) -> &str {
            "synthetic-host-recovery-checkpoint"
        }
    }
    struct Checkpoint(String);
    impl BundleAuthority for Checkpoint {
        fn acquire<'a>(
            &'a self,
            _: &BundleScope<'_>,
        ) -> std::result::Result<Box<dyn BundleLease + 'a>, BundleError> {
            Ok(Box::new(self))
        }
    }
    impl BundleLease for &Checkpoint {
        fn check_current(&self) -> std::result::Result<(), BundleError> {
            Ok(())
        }
        fn checkpoint_id(&self) -> &str {
            &self.0
        }
    }
    struct Fixture {
        _temp: tempfile::TempDir,
        backup: PathBuf,
        restored: PathBuf,
        successor: PathBuf,
    }
    /// A genuinely empty initialized source and pending first generation. This
    /// test helper does not publish, forge admissions or install any account.
    /// The joined native harness must drive the real Terminal publication path.
    #[cfg(all(feature = "financial-runtime", feature = "manual-admission"))]
    pub(crate) fn native_empty_pending_fixture() -> (tempfile::TempDir, crate::recovery_generation::PendingGeneration, PathBuf) {
        let f = fixture_with_accounts(0, false);
        let pending = crate::recovery_generation::PendingGeneration::create(inspect(&f).unwrap(), PASSWORD).unwrap();
        (f._temp, pending, f.successor)
    }
    #[cfg(feature = "financial-runtime")]
    pub(crate) fn published_empty_fixture() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        let f = fixture_with_accounts(0, false);
        crate::recovery_generation::PendingGeneration::create(inspect(&f).unwrap(), PASSWORD)
            .unwrap()
            .construct()
            .unwrap()
            .prepare_publication(vec![])
            .unwrap()
            .publish_synthetic_empty_accounts()
            .unwrap();
        (f._temp, f.backup, f.restored, f.successor)
    }
    // Historical storage fixture only. It never constructs a live native admission.
    #[cfg(feature = "financial-runtime")]
    pub(crate) fn construction_archive_fixture() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        let mut evidence = crate::recovery_generation::construction_capsule_fixtures::evidence();
        let f = fixture_with_identity(
            0,
            Some((
                &evidence.request.account_id,
                evidence.request.expected_writer_epoch,
            )),
        );
        let source = inspect(&f).unwrap();
        evidence.request.inventory_digest = source.digest().unwrap();
        evidence.request.generation_id = source.generation_id().into();
        crate::recovery_generation::PendingGeneration::create(source, PASSWORD)
            .unwrap()
            .construct()
            .unwrap()
            .prepare_publication_v3(vec![evidence])
            .unwrap()
            .materialize_synthetic_archive_fixture()
            .unwrap();
        (f._temp, f.backup, f.restored, f.successor)
    }
    // Historical storage fixture only. It never constructs a live native admission.
    #[cfg(all(feature = "financial-runtime", feature = "manual-admission"))]
    pub(crate) fn common_context_archive_fixture() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf)
    {
        let mut evidence = crate::recovery_generation::common_context_capsule_fixtures::evidence();
        let f = fixture_with_identity(
            0,
            Some((
                &evidence.request.account_id,
                evidence.request.expected_writer_epoch,
            )),
        );
        let source = inspect(&f).unwrap();
        evidence.request.inventory_digest = source.digest().unwrap();
        evidence.request.generation_id = source.generation_id().into();
        crate::recovery_generation::PendingGeneration::create(source, PASSWORD)
            .unwrap()
            .construct()
            .unwrap()
            .prepare_publication_v4(vec![evidence])
            .unwrap()
            .materialize_synthetic_archive_fixture()
            .unwrap();
        (f._temp, f.backup, f.restored, f.successor)
    }
    // Historical storage fixture only. It never constructs a live native admission.
    #[cfg(all(
        feature = "financial-runtime",
        feature = "manual-admission",
        target_os = "linux"
    ))]
    pub(crate) fn transport_archive_fixture() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        let mut evidence = crate::recovery_generation::transport_capsule_fixtures::evidence();
        let f = fixture_with_identity(
            0,
            Some((
                &evidence.request.account_id,
                evidence.request.expected_writer_epoch,
            )),
        );
        let source = inspect(&f).unwrap();
        evidence.request.inventory_digest = source.digest().unwrap();
        evidence.request.generation_id = source.generation_id().into();
        crate::recovery_generation::PendingGeneration::create(source, PASSWORD)
            .unwrap()
            .construct()
            .unwrap()
            .prepare_publication_v5(vec![evidence])
            .unwrap()
            .materialize_synthetic_archive_fixture()
            .unwrap();
        (f._temp, f.backup, f.restored, f.successor)
    }
    fn fixture(financial: usize) -> Fixture {
        fixture_with_accounts(financial, true)
    }
    fn fixture_with_accounts(financial: usize, include_account: bool) -> Fixture {
        fixture_with_identity(
            financial,
            include_account.then_some(("synthetic-account", 7)),
        )
    }
    fn fixture_with_identity(financial: usize, account: Option<(&str, u64)>) -> Fixture {
        let temp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let backup = root.join("backup");
        let restored = root.join("restored");
        let successor = root.join("successor");
        let live = Directory::create(&root.join("live")).unwrap();
        let original = Directory::create(&backup).unwrap();
        let output = Directory::create(&restored).unwrap();
        let secrets = Secrets::fresh().unwrap();
        let archive_key = DatabaseKey::from_bytes([0xa5; 32]);
        let store = wholepact_store::Store::create_encrypted(
            live.path(JOURNALS[0]).unwrap(),
            &secrets.key(0).unwrap(),
        )
        .unwrap();
        if let Some((account_id, epoch)) = account {
            store
                .initialize_authority_account(account_id, epoch)
                .unwrap();
        }
        let coordination = wholepact_store::bundle::CoordinationBundleAdapter::new(&store).unwrap();
        let mut inbox = wholepact_transport::SqliteReplayLedger::from_encrypted_connection(
            create_encrypted(live.path(JOURNALS[1]).unwrap(), &secrets.key(1).unwrap()).unwrap(),
        )
        .unwrap();
        let mut outbox = wholepact_transport::SqliteOutbox::from_encrypted_connection(
            create_encrypted(live.path(JOURNALS[2]).unwrap(), &secrets.key(2).unwrap()).unwrap(),
        )
        .unwrap();
        let submission = Mutex::new(
            wholepact_chain::EncryptedSubmissionJournal::from_encrypted_connection(
                create_encrypted(live.path(JOURNALS[3]).unwrap(), &secrets.key(3).unwrap())
                    .unwrap(),
            )
            .unwrap(),
        );
        let inbox = inbox.backup_adapter().unwrap();
        let outbox = outbox.backup_adapter().unwrap();
        let submission = wholepact_chain::backup::SubmissionBackupAdapter::new(&submission);
        #[cfg_attr(not(feature = "financial-runtime"), allow(unused_mut))]
        let mut sources = vec![
            RegisteredJournal::new("coordination", &coordination).unwrap(),
            RegisteredJournal::new("inbox", &inbox).unwrap(),
            RegisteredJournal::new("outbox", &outbox).unwrap(),
            RegisteredJournal::new("submission", &submission).unwrap(),
        ];
        #[cfg_attr(not(feature = "financial-runtime"), allow(unused_mut))]
        let mut coverage = crate::backup::coverage();
        #[cfg_attr(not(feature = "financial-runtime"), allow(unused_mut))]
        let mut checkpoint = Checkpoint("synthetic-host-recovery-checkpoint".into());
        #[cfg(feature = "financial-runtime")]
        let profiles = (0..financial)
            .map(|index| {
                let path = root.join(format!("live-financial-{index}"));
                crate::financial_inventory::register(
                    &live,
                    &secrets,
                    &path,
                    if index == 0 {
                        crate::financial_inventory::AttachmentRole::PrimaryFinancial
                    } else {
                        crate::financial_inventory::AttachmentRole::ParticipantWallet
                    },
                    if index == 0 {
                        None
                    } else {
                        Some("synthetic-participant")
                    },
                )
                .unwrap();
                let profile = crate::financial_profile::FinancialProfile::create(
                    &path,
                    &secrets.profile(),
                    PASSWORD,
                )
                .unwrap();
                original
                    .write_new(
                        &format!("financial-{index}.vault"),
                        &profile.secrets.seal(PASSWORD).unwrap(),
                    )
                    .unwrap();
                profile
            })
            .collect::<Vec<_>>();
        #[cfg(feature = "financial-runtime")]
        if financial > 0 {
            original
                .write_new(
                    "financial.inventory",
                    &live.read("financial.inventory", 65536).unwrap(),
                )
                .unwrap();
            checkpoint.0 = crate::financial_backup::metadata_digest(&original, financial).unwrap();
            coverage = crate::financial_backup::coverage(financial);
        }
        #[cfg(not(feature = "financial-runtime"))]
        assert_eq!(financial, 0);
        #[cfg(feature = "financial-runtime")]
        let adapters = profiles
            .iter()
            .map(|profile| crate::financial_backup::Adapters::new(profile).unwrap())
            .collect::<Vec<_>>();
        #[cfg(feature = "financial-runtime")]
        for (index, adapters) in adapters.iter().enumerate() {
            sources.extend(adapters.registered(index).unwrap());
        }
        let archive = original.path("bundle.sqlite").unwrap();
        snapshot(SnapshotRequest {
            principal_id: "synthetic-admin",
            profile_id: &secrets.profile(),
            coverage,
            sources: &sources,
            destination: &archive,
            key: &archive_key,
            authority: &checkpoint,
        })
        .unwrap();
        original
            .write_new(
                "recovery.wp",
                &secrets.recovery(PASSWORD, &[0xa5; 32]).unwrap(),
            )
            .unwrap();
        original
            .write_new("COMPLETE", crate::backup::COMPLETE)
            .unwrap();
        output
            .write_new("restored.quarantine", b"synthetic-quarantine")
            .unwrap();
        #[cfg(feature = "financial-runtime")]
        let dependencies = crate::financial_backup::RestoreFinancial::prepare(
            &original, &output, &restored, &secrets, PASSWORD, financial,
        )
        .unwrap();
        let paths = JOURNALS.map(|name| output.path(name).unwrap());
        let keys = (0..4).map(|i| secrets.key(i).unwrap()).collect::<Vec<_>>();
        let templates = [
            wholepact_store::bundle::coordination_template(),
            &wholepact_transport::bundle::INBOX_BACKUP_TEMPLATE,
            &wholepact_transport::bundle::OUTBOX_BACKUP_TEMPLATE,
            &wholepact_chain::backup::TEMPLATE,
        ];
        let ids = ["coordination", "inbox", "outbox", "submission"];
        #[cfg_attr(not(feature = "financial-runtime"), allow(unused_mut))]
        let mut targets = (0..4)
            .map(|i| RestoreTarget {
                component_id: ids[i],
                template: templates[i],
                destination: &paths[i],
                key: &keys[i],
            })
            .collect::<Vec<_>>();
        #[cfg(feature = "financial-runtime")]
        targets.extend(dependencies.targets(&archive, &archive_key).unwrap());
        bundle::restore(RestoreRequest {
            principal_id: "synthetic-admin",
            profile_id: &secrets.profile(),
            archive: &archive,
            key: &archive_key,
            targets: &targets,
            authority: &Gate,
        })
        .unwrap();
        output
            .write_new("profile.vault", &secrets.seal(PASSWORD).unwrap())
            .unwrap();
        #[cfg(feature = "financial-runtime")]
        dependencies.finish(PASSWORD).unwrap();
        Fixture {
            _temp: temp,
            backup,
            restored,
            successor,
        }
    }
    fn inspect(f: &Fixture) -> Result<Inventory> {
        prepare(
            &f.restored,
            &f.backup,
            &f.successor,
            "ab".repeat(32),
            PASSWORD,
            PASSWORD,
            Instant::now() + Duration::from_secs(300),
        )
    }
    fn fingerprint(path: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
        std::fs::read_dir(path)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (
                    entry.file_name().into_string().unwrap(),
                    std::fs::read(entry.path()).unwrap(),
                )
            })
            .collect()
    }
    #[cfg(feature = "financial-runtime")]
    #[test]
    fn restricted_successor_publishes_reopens_and_keeps_original_trees_immutable() {
        // Empty-account synthetic fixture needs no signer admission. It exercises
        // storage publication, not native UI, IPC, financial freshness or signing.
        let f = fixture_with_accounts(0, false);
        let before_backup = fingerprint(&f.backup);
        let before_restored = fingerprint(&f.restored);
        let inventory = inspect(&f).unwrap();
        let generation =
            crate::recovery_generation::PendingGeneration::create(inventory, PASSWORD).unwrap();
        let prepared = generation
            .construct()
            .unwrap()
            .prepare_publication(vec![])
            .unwrap();
        prepared.publish_synthetic_empty_accounts().unwrap();
        assert_eq!(before_backup, fingerprint(&f.backup));
        assert_eq!(before_restored, fingerprint(&f.restored));
        let directory = Directory::open(&f.successor).unwrap();
        let secrets =
            Secrets::open(&directory.read("profile.vault", 1024).unwrap(), PASSWORD).unwrap();
        assert!(secrets.generation_plan_digest().is_some());
        assert!(
            wholepact_store::Store::open_encrypted(
                directory.path(JOURNALS[0]).unwrap(),
                &secrets.key(0).unwrap()
            )
            .is_err()
        );
        let store = crate::recovery_generation::open_committed(&directory, &secrets).unwrap();
        assert!(store.recovery_state().unwrap().recovery_required);
        assert!(!store.runtime_recovery_required().unwrap());
        drop(store);
        let marker = directory.read("generation.commit", 1024 * 1024).unwrap();
        std::fs::remove_file(directory.path("generation.commit").unwrap()).unwrap();
        assert!(crate::recovery_generation::open_committed(&directory, &secrets).is_err());
        directory.write_new("generation.commit", &marker).unwrap();
        let history = directory.path("history-inbox.sqlite").unwrap();
        std::fs::rename(
            &history,
            f.successor.with_file_name("missing-history.sqlite"),
        )
        .unwrap();
        assert!(crate::recovery_generation::open_committed(&directory, &secrets).is_err());
    }

    #[cfg(feature = "financial-runtime")]
    type FullFingerprint = std::collections::BTreeMap<String, (Vec<u8>, u32, u64, u64, i64, i64)>;

    #[cfg(feature = "financial-runtime")]
    fn full_fingerprint(path: &Path) -> FullFingerprint {
        use std::os::unix::fs::MetadataExt;
        std::fs::read_dir(path)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                let metadata = std::fs::symlink_metadata(entry.path()).unwrap();
                assert!(metadata.is_file());
                (
                    entry.file_name().into_string().unwrap(),
                    (
                        std::fs::read(entry.path()).unwrap(),
                        metadata.mode(),
                        metadata.dev(),
                        metadata.ino(),
                        metadata.mtime(),
                        metadata.mtime_nsec(),
                    ),
                )
            })
            .collect()
    }

    #[cfg(feature = "financial-runtime")]
    #[test]
    fn restricted_history_requires_complete_generation_and_preserves_all_source_files() {
        // Synthetic zero-account storage publication only. This does not stand
        // in for signer/native approval or claim attended disclosure coverage.
        let f = fixture_with_accounts(0, false);
        crate::recovery_generation::PendingGeneration::create(inspect(&f).unwrap(), PASSWORD)
            .unwrap()
            .construct()
            .unwrap()
            .prepare_publication(vec![])
            .unwrap()
            .publish_synthetic_empty_accounts()
            .unwrap();
        let directory = Directory::open(&f.successor).unwrap();
        let secrets =
            Secrets::open(&directory.read("profile.vault", 1024).unwrap(), PASSWORD).unwrap();
        // Metadata-only attachment deliberately lacks live financial journals.
        // Historical inspection must neither initialize it nor claim its closure.
        let financial_path = f.successor.with_file_name("current-financial");
        let financial = Directory::create(&financial_path).unwrap();
        crate::financial_inventory::register(
            &directory,
            &secrets,
            &financial_path,
            crate::financial_inventory::AttachmentRole::PrimaryFinancial,
            None,
        )
        .unwrap();
        let financial_before = full_fingerprint(&financial_path);
        let source = wholepact_storage_security::open_encrypted(
            directory.path(JOURNALS[3]).unwrap(),
            &secrets.key(3).unwrap(),
        )
        .unwrap();
        source
            .connection()
            .execute_batch("PRAGMA wal_autocheckpoint=0;")
            .unwrap();
        source
            .connection()
            .execute(
                "UPDATE submission_journal_identity SET identity=?1",
                ["ab".repeat(32)],
            )
            .unwrap();
        let before = full_fingerprint(&f.successor);
        let history =
            crate::recovery_generation::open_committed_history(&directory, &secrets).unwrap();
        assert_eq!(history.components().len(), 4);
        assert!(history.known_account_ids().is_empty());
        assert_eq!(history.registered_financial_directories(), 1);
        assert_eq!(history.manifest_digest().len(), 64);
        assert!(
            history
                .external_destination(&directory.path("new-output").unwrap())
                .is_err()
        );
        assert!(
            history
                .external_destination(&financial.path("new-output").unwrap())
                .is_err()
        );
        history
            .external_destination(&f.successor.with_file_name("new-private-output"))
            .unwrap();
        let binding = history
            .component("coordination")
            .unwrap()
            .generation()
            .clone();
        let provenance = history
            .component("coordination")
            .unwrap()
            .provenance()
            .clone();
        drop(history);
        assert!(
            before == full_fingerprint(&f.successor),
            "immutable native history read changed source files"
        );
        assert!(
            financial_before == full_fingerprint(&financial_path),
            "historical read opened or changed current attachment"
        );
        drop(source);
        for name in [
            "recovery.plan",
            "generation.manifest",
            "generation.commit",
            "generation.keys",
        ] {
            let bytes = directory.read(name, 16 * 1024 * 1024).unwrap();
            let mut changed = bytes.clone();
            *changed.last_mut().unwrap() ^= 1;
            std::fs::write(directory.path(name).unwrap(), changed).unwrap();
            let before = full_fingerprint(&f.successor);
            assert!(
                crate::recovery_generation::open_committed_history(&directory, &secrets).is_err()
            );
            assert!(
                before == full_fingerprint(&f.successor),
                "rejected generation metadata changed source files"
            );
            std::fs::write(directory.path(name).unwrap(), bytes).unwrap();
        }
        let commit = directory
            .read("generation.commit", 16 * 1024 * 1024)
            .unwrap();
        std::fs::remove_file(directory.path("generation.commit").unwrap()).unwrap();
        let before = full_fingerprint(&f.successor);
        assert!(crate::recovery_generation::open_committed_history(&directory, &secrets).is_err());
        assert!(
            before == full_fingerprint(&f.successor),
            "missing commit rejection changed source files"
        );
        directory.write_new("generation.commit", &commit).unwrap();
        directory.write_new("unknown-file", b"synthetic").unwrap();
        let before = full_fingerprint(&f.successor);
        assert!(crate::recovery_generation::open_committed_history(&directory, &secrets).is_err());
        assert!(
            before == full_fingerprint(&f.successor),
            "unknown file rejection changed source files"
        );
        std::fs::remove_file(directory.path("unknown-file").unwrap()).unwrap();
        // Deliberate fixture corruption of the Store flag must be rejected by
        // its immutable owner validator, even with an otherwise valid manifest.
        let store =
            wholepact_storage_security::bundle::recovery::generation::open_recovered_generation(
                &directory.path(JOURNALS[0]).unwrap(),
                &secrets.key(0).unwrap(),
                &binding,
                &provenance,
                wholepact_store::recovery::coordination_successor_template(),
            )
            .unwrap();
        store
            .connection()
            .execute("UPDATE store_recovery SET recovery_required=0,restored_at_ms=NULL,source_snapshot_digest=NULL", [])
            .unwrap();
        drop(store);
        let before = full_fingerprint(&f.successor);
        assert!(crate::recovery_generation::open_committed_history(&directory, &secrets).is_err());
        assert!(
            before == full_fingerprint(&f.successor),
            "rejected recovery-flag corruption changed source files"
        );
    }

    #[cfg(feature = "financial-runtime")]
    #[test]
    fn restricted_successor_retry_authenticates_exact_pending_generation_and_missing_admission() {
        let f = fixture_with_accounts(0, false);
        let pending =
            crate::recovery_generation::PendingGeneration::create(inspect(&f).unwrap(), PASSWORD)
                .unwrap();
        drop(pending.construct().unwrap());
        let generation = crate::recovery_generation::PendingGeneration::pending_identifier(
            &f.successor,
            PASSWORD,
        )
        .unwrap();
        let source = prepare_for_resume(
            &f.restored,
            &f.backup,
            &f.successor,
            generation,
            PASSWORD,
            PASSWORD,
            Instant::now() + Duration::from_secs(300),
        )
        .unwrap();
        let resumed =
            crate::recovery_generation::PendingGeneration::resume(source, PASSWORD).unwrap();
        let prepared = resumed
            .construct()
            .unwrap()
            .prepare_publication(vec![])
            .unwrap();
        // A published generation never re-enters the pending retry path.
        prepared.publish_synthetic_empty_accounts().unwrap();
        assert!(
            crate::recovery_generation::PendingGeneration::pending_identifier(
                &f.successor,
                PASSWORD
            )
            .is_err()
        );

        let f = fixture(0);
        let pending =
            crate::recovery_generation::PendingGeneration::create(inspect(&f).unwrap(), PASSWORD)
                .unwrap();
        assert!(
            pending
                .construct()
                .unwrap()
                .prepare_publication(vec![])
                .is_err()
        );
        assert!(!f.successor.join("generation.commit").exists());
    }

    #[cfg(feature = "financial-runtime")]
    #[test]
    fn restricted_successor_resumes_empty_auxiliary_but_rejects_lost_component_before_commit() {
        let f = fixture_with_accounts(0, false);
        let pending =
            crate::recovery_generation::PendingGeneration::create(inspect(&f).unwrap(), PASSWORD)
                .unwrap();
        let secrets = Secrets::open(
            &crate::files::read_private(&f.successor.join("profile.vault"), 1024).unwrap(),
            PASSWORD,
        )
        .unwrap();
        // Model interruption after keyed database creation, before typed schema.
        drop(create_encrypted(f.successor.join(JOURNALS[1]), &secrets.key(1).unwrap()).unwrap());
        let prepared = pending
            .construct()
            .unwrap()
            .prepare_publication(vec![])
            .unwrap();
        std::fs::rename(
            f.successor.join(JOURNALS[2]),
            f.successor.with_file_name("lost-outbox.sqlite"),
        )
        .unwrap();
        assert!(prepared.publish_synthetic_empty_accounts().is_err());
        assert!(!f.successor.join("generation.commit").exists());
    }

    #[test]
    fn absent_successor_rejects_dangling_symlinks_and_expired_read_approval() {
        let temp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let directory = Directory::create(&root.join("source")).unwrap();
        let successor = root.join("successor");
        assert!(target(&directory, &successor).is_ok());
        std::os::unix::fs::symlink(root.join("nonexistent"), &successor).unwrap();
        assert!(target(&directory, &successor).is_err());
        // Expired consent rejects before even attempting to open these paths.
        assert!(matches!(
            prepare(
                Path::new("/absent-source"),
                Path::new("/absent-backup"),
                &successor,
                "ab".repeat(32),
                PASSWORD,
                PASSWORD,
                Instant::now()
            ),
            Err(Error::Permission)
        ));
    }
    #[test]
    fn complete_immutable_host_review_never_creates_authority_or_successor() {
        let f = fixture(0);
        let path = f.restored.join(JOURNALS[0]);
        let before = std::fs::read(&path).unwrap();
        let archive_before = std::fs::read(f.backup.join("bundle.sqlite")).unwrap();
        let backup_tree = fingerprint(&f.backup);
        let restored_tree = fingerprint(&f.restored);
        let inventory = inspect(&f).unwrap();
        assert_eq!(inventory.components.len(), 4);
        assert!(
            inventory
                .review
                .known_account_ids
                .contains("synthetic-account")
        );
        assert!(!inventory.review.activation_available);
        assert_eq!(inventory.digest().unwrap(), inventory.digest().unwrap());
        assert!(Directory::open(&f.restored).is_err());
        assert!(!f.successor.exists());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(
            std::fs::read(f.backup.join("bundle.sqlite")).unwrap(),
            archive_before
        );
        drop(inventory);
        assert!(fingerprint(&f.backup) == backup_tree);
        assert!(fingerprint(&f.restored) == restored_tree);
        assert!(f.restored.join("restored.quarantine").exists());
        assert!(Directory::open(&f.restored).is_ok());
        let first = inspect(&f).unwrap().digest().unwrap();
        let second = prepare(
            &f.restored,
            &f.backup,
            &f.successor,
            "cd".repeat(32),
            PASSWORD,
            PASSWORD,
            Instant::now() + Duration::from_secs(300),
        )
        .unwrap()
        .digest()
        .unwrap();
        assert_ne!(first, second);
    }
    #[test]
    fn incomplete_unknown_and_substituted_host_inventory_fail_closed() {
        let f = fixture(0);
        crate::files::write_new(&f.restored.join("unknown-journal.sqlite"), b"unknown").unwrap();
        assert!(inspect(&f).is_err());
        std::fs::remove_file(f.restored.join("unknown-journal.sqlite")).unwrap();
        let directory = Directory::open(&f.restored).unwrap();
        directory
            .replace_private(
                "profile.vault",
                &Secrets::fresh().unwrap().seal(PASSWORD).unwrap(),
            )
            .unwrap();
        drop(directory);
        assert!(inspect(&f).is_err());
        assert!(!f.successor.exists());
    }
    #[test]
    fn coverage_rejects_extra_missing_and_wrong_kind_components() {
        let f = fixture(0);
        let source = Directory::open(&f.backup).unwrap();
        let (_, key) =
            Secrets::open_recovery(&source.read("recovery.wp", 1024).unwrap(), PASSWORD).unwrap();
        let mut manifest = bundle::inspect(&source.path("bundle.sqlite").unwrap(), &key).unwrap();
        assert_eq!(complete_coverage(&manifest).unwrap(), 0);
        let original = manifest.clone();
        manifest.components[0].kind = JournalKind::SignerConsentAuthority;
        assert!(complete_coverage(&manifest).is_err());
        manifest = original.clone();
        manifest.components.push(original.components[0].clone());
        assert!(complete_coverage(&manifest).is_err());
        manifest = original;
        manifest.components.pop();
        assert!(complete_coverage(&manifest).is_err());
    }
    #[cfg(feature = "financial-runtime")]
    #[test]
    fn complete_financial_inventory_is_authenticated_and_dependency_loss_blocks() {
        let f = fixture(2);
        let inventory = inspect(&f).unwrap();
        assert_eq!(inventory.components.len(), 12);
        assert_eq!(inventory.review.registered_financial_directories, 2);
        assert!(
            inventory
                .review
                .known_account_ids
                .contains("synthetic-participant")
        );
        assert!(!inventory.review.activation_available);
        drop(inventory);
        // Even a valid owner-authenticated replacement registry cannot change
        // the backup's original account-to-component association.
        let restored = Directory::open(&f.restored).unwrap();
        let secrets =
            Secrets::open(&restored.read("profile.vault", 1024).unwrap(), PASSWORD).unwrap();
        let saved = restored.read("financial.inventory", 65536).unwrap();
        let replacement =
            Directory::create(&f.restored.with_file_name("replacement-registry")).unwrap();
        crate::financial_inventory::register(
            &replacement,
            &secrets,
            &f.restored.with_file_name("restored-financial-0"),
            crate::financial_inventory::AttachmentRole::PrimaryFinancial,
            None,
        )
        .unwrap();
        crate::financial_inventory::register(
            &replacement,
            &secrets,
            &f.restored.with_file_name("restored-financial-1"),
            crate::financial_inventory::AttachmentRole::ParticipantWallet,
            Some("synthetic-other-account"),
        )
        .unwrap();
        restored
            .replace_private(
                "financial.inventory",
                &replacement.read("financial.inventory", 65536).unwrap(),
            )
            .unwrap();
        drop(restored);
        assert!(inspect(&f).is_err());
        let restored = Directory::open(&f.restored).unwrap();
        restored
            .replace_private("financial.inventory", &saved)
            .unwrap();
        drop(restored);
        let path = f.restored.with_file_name("restored-financial-0");
        assert!(path.join("restored.quarantine").exists());
        std::fs::remove_file(path.join("proof.sqlite")).unwrap();
        assert!(inspect(&f).is_err());
        assert!(!f.successor.exists());
    }
}
