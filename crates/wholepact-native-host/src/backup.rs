//! Whole-profile archive after every service/observer runtime has been drained
//! and dropped. The host exposes no engine references outside its owned runtime.
//! Fixed inventory is authenticated by the profile vault and checked on disk.
use crate::{
    Error, Result,
    files::Directory,
    random,
    terminal::Terminal,
    vault::{JOURNALS, Secrets},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Mutex,
};
use wholepact_chain::{EncryptedSubmissionJournal, backup::SubmissionBackupAdapter};
use wholepact_storage_security::{
    DatabaseKey, bundle::*, open_encrypted_quiescent as open_encrypted,
};
use wholepact_store::{Store, bundle::CoordinationBundleAdapter};
use wholepact_transport::{SqliteOutbox, SqliteReplayLedger};
use zeroize::Zeroizing;

pub(crate) const COMPLETE: &[u8] = b"wholepact-native-profile-backup-v1\nAll files in this directory are required, including every financial vault and inventory when present. Signer recovery is separate. No restored authority.\n";

/// Constructed only after Host::serve has returned and its owned Tokio runtime
/// has dropped, or before any runtime has been started. Borrowing the entire
/// host mutably prevents concurrent native actions during this scope.
pub(crate) struct Quiescent<'a> {
    pub(crate) directory: &'a Directory,
    pub(crate) secrets: &'a Secrets,
    pub(crate) terminal: &'a Terminal,
}
pub(crate) fn coverage() -> Coverage {
    Coverage {
        present: BTreeMap::from([
            (
                JournalKind::CoordinationAuthority,
                vec!["coordination".into()],
            ),
            (JournalKind::TransportInbox, vec!["inbox".into()]),
            (JournalKind::TransportOutbox, vec!["outbox".into()]),
            (JournalKind::Submission, vec!["submission".into()]),
        ]),
        absent: BTreeSet::from([
            JournalKind::WalletScan,
            JournalKind::ProofWitness,
            JournalKind::SignedResults,
            JournalKind::ExactTransactions,
            JournalKind::SignerConsentAuthority,
        ]),
    }
}
struct Consent<'a> {
    terminal: &'a Terminal,
    profile: String,
    archive: PathBuf,
    action: BundleAction,
    destinations: Vec<PathBuf>,
    sources: Vec<(String, JournalBinding)>,
    coverage: Coverage,
    checkpoint: String,
    expires: u64,
}
struct Lease<'a> {
    consent: &'a Consent<'a>,
}
impl BundleLease for Lease<'_> {
    fn check_current(&self) -> std::result::Result<(), BundleError> {
        if crate::now().map_err(|_| BundleError::Permission)? >= self.consent.expires {
            Err(BundleError::Permission)
        } else {
            Ok(())
        }
    }
    fn checkpoint_id(&self) -> &str {
        &self.consent.checkpoint
    }
}
impl BundleAuthority for Consent<'_> {
    fn acquire<'a>(
        &'a self,
        s: &BundleScope<'_>,
    ) -> std::result::Result<Box<dyn BundleLease + 'a>, BundleError> {
        if s.profile_id != self.profile
            || s.principal_id != "native-administrator"
            || s.action != self.action
            || s.archive != self.archive
            || s.destinations != self.destinations
            || s.sources != self.sources
            || s.coverage != &self.coverage
            || s.wallet_spending_secrets_included
            || !s.private_viewing_witness_and_correlation_data_may_be_included
            || s.retention != "local-only; retain until deliberately removed"
        {
            return Err(BundleError::Permission);
        }
        self.terminal.confirm(&format!("Host-owned encrypted journal backup administration. Signer authority, signer recovery and recipient-local records are excluded. All native service and observer writers are stopped and drained; the exclusive profile lock remains held.\nProfile: {}\nAction: {:?}\nArchive: {}\nDestinations: {:?}\nCoverage: {:?}\nRetention: {}\nNo wallet spending secrets exist in this host. Private viewing/witness/correlation history may be included. Separate recovery.wp contains NON-signing journal and transport key recovery material. Session grants, pinned peers and consents are NOT restored and require re-enrollment. No clone/writer freshness is established.",self.profile,self.action,self.archive.display(),self.destinations,self.coverage,s.retention)).map_err(|_|BundleError::Permission)?;
        Ok(Box::new(Lease { consent: self }))
    }
}
impl Quiescent<'_> {
    pub(crate) fn snapshot(&self, destination: &Path, password: &[u8]) -> Result<BundleManifest> {
        self.secrets.require_portable_legacy()?;
        self.directory.refuse_private_workspace_files()?;
        self.directory.inventory()?;
        // Never advertise a partial archive as whole-profile after financial attachment,
        // including subsequent sessions where those journals are not yet unlocked.
        #[cfg(not(feature = "financial-runtime"))]
        if self.directory.path("financial.attached")?.try_exists()?
            || self.directory.path("financial.inventory")?.try_exists()?
        {
            return Err(Error::Unsupported);
        }
        #[cfg(feature = "financial-runtime")]
        let financial =
            crate::financial_backup::open_all(self.directory, self.secrets, self.terminal)?;
        #[cfg(feature = "financial-runtime")]
        let adapters = financial
            .iter()
            .map(crate::financial_backup::Adapters::new)
            .collect::<Result<Vec<_>>>()?;
        #[cfg(feature = "financial-runtime")]
        let actual_coverage = crate::financial_backup::coverage(financial.len());
        #[cfg(not(feature = "financial-runtime"))]
        let actual_coverage = coverage();
        // New output directory avoids overwrites, ambiguous pairing and leftovers.
        let output = Directory::create(destination)?;
        let archive = output.path("bundle.sqlite")?;
        let random_key = Zeroizing::new(random::<32>()?);
        let key = DatabaseKey::from_bytes(*random_key);
        let store = Store::from_encrypted_connection(open_encrypted(
            self.directory.path(JOURNALS[0])?,
            &self.secrets.key(0)?,
        )?)?;
        let coordination = CoordinationBundleAdapter::new(&store)?;
        let mut inbox = SqliteReplayLedger::from_encrypted_connection(open_encrypted(
            self.directory.path(JOURNALS[1])?,
            &self.secrets.key(1)?,
        )?)?;
        let mut outbox = SqliteOutbox::from_encrypted_connection(open_encrypted(
            self.directory.path(JOURNALS[2])?,
            &self.secrets.key(2)?,
        )?)?;
        let submission = Mutex::new(EncryptedSubmissionJournal::from_encrypted_connection(
            open_encrypted(self.directory.path(JOURNALS[3])?, &self.secrets.key(3)?)?,
        )?);
        let inbox = inbox.backup_adapter()?;
        let outbox = outbox.backup_adapter()?;
        let submission = SubmissionBackupAdapter::new(&submission);
        let mut sources = vec![
            RegisteredJournal::new("coordination", &coordination)?,
            RegisteredJournal::new("inbox", &inbox)?,
            RegisteredJournal::new("outbox", &outbox)?,
            RegisteredJournal::new("submission", &submission)?,
        ];
        #[cfg(feature = "financial-runtime")]
        for (index, adapter) in adapters.iter().enumerate() {
            sources.extend(adapter.registered(index)?);
        }
        let profile = self.secrets.profile();
        #[cfg(feature = "financial-runtime")]
        for (index, profile) in financial.iter().enumerate() {
            output.write_new(
                &format!("financial-{index}.vault"),
                &profile.secrets.seal(password)?,
            )?;
        }
        #[cfg(feature = "financial-runtime")]
        if !financial.is_empty() {
            output.write_new(
                crate::financial_inventory::FILE,
                &self
                    .directory
                    .read(crate::financial_inventory::FILE, 65536)?,
            )?;
        }
        #[cfg(feature = "financial-runtime")]
        let checkpoint = if financial.is_empty() {
            hex::encode(random::<16>()?)
        } else {
            crate::financial_backup::metadata_digest(&output, financial.len())?
        };
        #[cfg(not(feature = "financial-runtime"))]
        let checkpoint = hex::encode(random::<16>()?);
        let consent = Consent {
            terminal: self.terminal,
            profile: profile.clone(),
            archive: archive.clone(),
            action: BundleAction::Snapshot,
            destinations: vec![],
            sources: sources
                .iter()
                .map(|s| (s.id().to_owned(), s.binding()))
                .collect(),
            coverage: actual_coverage.clone(),
            checkpoint,
            expires: crate::now()?.saturating_add(300),
        };
        let report = snapshot(SnapshotRequest {
            principal_id: "native-administrator",
            profile_id: &profile,
            coverage: actual_coverage.clone(),
            sources: &sources,
            destination: &archive,
            key: &key,
            authority: &consent,
        })?;
        let recovery = self.secrets.recovery(password, &random_key)?;
        output.write_new("recovery.wp", &recovery)?;
        // Independent decryption/keyed inspection before reporting success.
        let (verified, backup_key) =
            Secrets::open_recovery(&output.read("recovery.wp", 1024)?, password)?;
        if verified.profile() != profile || inspect(&archive, &backup_key)?.digest != report.digest
        {
            return Err(Error::Authentication);
        }
        #[cfg(feature = "financial-runtime")]
        for index in 0..financial.len() {
            crate::vault::FinancialSecrets::open(
                &output.read(&format!("financial-{index}.vault"), 1024)?,
                &profile,
                password,
            )?;
        }
        output.write_new("COMPLETE", COMPLETE)?;
        Ok(report)
    }
}
pub(crate) fn restore(
    terminal: &Terminal,
    backup: &Path,
    destination: &Path,
    password: &[u8],
    new_password: &[u8],
    test_only: bool,
) -> Result<BundleRestoreReport> {
    let source = Directory::open(backup)?;
    if source.read("COMPLETE", 256)?.is_empty() {
        return Err(Error::Invalid);
    }
    let (secrets, key) = Secrets::open_recovery(&source.read("recovery.wp", 1024)?, password)?;
    let archive = source.path("bundle.sqlite")?;
    let manifest = inspect(&archive, &key)?;
    #[cfg(feature = "financial-runtime")]
    let financial_count = manifest
        .coverage
        .present
        .get(&JournalKind::WalletScan)
        .map_or(0, Vec::len);
    #[cfg(feature = "financial-runtime")]
    let expected_coverage = crate::financial_backup::coverage(financial_count);
    #[cfg(not(feature = "financial-runtime"))]
    let expected_coverage = coverage();
    if manifest.profile_id != secrets.profile() || manifest.coverage != expected_coverage {
        return Err(Error::Invalid);
    }
    // Authenticate the exact original encoding before creating a destination.
    // Restore preserves the original quarantine template, not the current live
    // schema; any later ordinary migration belongs to the Store owner.
    let coordination = manifest
        .components
        .iter()
        .find(|component| component.id == "coordination")
        .ok_or(Error::Authentication)?;
    if coordination.kind != JournalKind::CoordinationAuthority || coordination.application_id != 0 {
        return Err(Error::Authentication);
    }
    let coordination_template =
        wholepact_store::bundle::coordination_template_for_schema(coordination.schema_version)?;
    #[cfg(feature = "financial-runtime")]
    if financial_count > 0
        && crate::financial_backup::metadata_digest(&source, financial_count)?
            != manifest.checkpoint_id
    {
        return Err(Error::Authentication);
    }
    let mut auxiliary = vec![
        "profile.lock".to_owned(),
        "COMPLETE".to_owned(),
        "recovery.wp".to_owned(),
    ];
    #[cfg(feature = "financial-runtime")]
    if financial_count > 0 {
        auxiliary.push(crate::financial_inventory::FILE.to_owned());
        auxiliary.extend((0..financial_count).map(|i| format!("financial-{i}.vault")));
    }
    let auxiliary: Vec<&str> = auxiliary.iter().map(String::as_str).collect();
    source.inventory_of(&["bundle.sqlite"], &auxiliary)?;
    let output = Directory::create(destination)?;
    output.write_new(
        "restored.quarantine",
        b"History only; no writer or signing authority is restored.\n",
    )?;
    #[cfg(feature = "financial-runtime")]
    let financial = crate::financial_backup::RestoreFinancial::prepare(
        &source,
        &output,
        destination,
        &secrets,
        password,
        financial_count,
    )?;
    let paths = JOURNALS
        .iter()
        .map(|name| output.path(name))
        .collect::<Result<Vec<_>>>()?;
    let keys = (0..4).map(|i| secrets.key(i)).collect::<Result<Vec<_>>>()?;
    let mut targets = vec![
        RestoreTarget {
            component_id: "coordination",
            template: coordination_template,
            destination: &paths[0],
            key: &keys[0],
        },
        RestoreTarget {
            component_id: "inbox",
            template: &wholepact_transport::bundle::INBOX_BACKUP_TEMPLATE,
            destination: &paths[1],
            key: &keys[1],
        },
        RestoreTarget {
            component_id: "outbox",
            template: &wholepact_transport::bundle::OUTBOX_BACKUP_TEMPLATE,
            destination: &paths[2],
            key: &keys[2],
        },
        RestoreTarget {
            component_id: "submission",
            template: &wholepact_chain::backup::TEMPLATE,
            destination: &paths[3],
            key: &keys[3],
        },
    ];
    #[cfg(feature = "financial-runtime")]
    targets.extend(financial.targets(&archive, &key)?);
    let consent = Consent {
        terminal,
        profile: secrets.profile(),
        archive: archive.clone(),
        action: if test_only {
            BundleAction::TestRestore
        } else {
            BundleAction::Restore
        },
        destinations: targets
            .iter()
            .map(|t| t.destination.to_path_buf())
            .collect(),
        sources: vec![],
        coverage: expected_coverage,
        checkpoint: hex::encode(random::<16>()?),
        expires: crate::now()?.saturating_add(300),
    };
    let request = RestoreRequest {
        principal_id: "native-administrator",
        profile_id: &manifest.profile_id,
        archive: &archive,
        key: &key,
        targets: &targets,
        authority: &consent,
    };
    let report = if test_only {
        test_restore(request)?
    } else {
        wholepact_storage_security::bundle::restore(request)?
    };
    output.write_new("profile.vault", &secrets.seal(new_password)?)?;
    #[cfg(feature = "financial-runtime")]
    financial.finish(new_password)?;
    Ok(report)
}
