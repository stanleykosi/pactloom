//! Explicit lineage-qualified archived disclosure; never a live Host or grant.
use crate::{
    Error, Result,
    files::Directory,
    financial_inventory::Attachment,
    generation_restore::RestoredGenerationCapsule,
    recovery_generation::archive_history::{
        VerifiedGenerationCapsule, capture_layered_metadata, open_layered_parent,
    },
    terminal::{
        Terminal,
        historical::{HistoricalApproval, HistoricalOutput},
    },
    vault::Secrets,
};
use std::path::{Path, PathBuf};
use wholepact_storage_security::{
    bundle::{
        BundleError,
        recovery::evidence::{RecoveredEvidence, history::*},
    },
    generation_archive::{ArchivedGenerationSource, ArchivedOrdinarySource},
};

const PRINCIPAL: &str = "native-archived-artifact-reader";
pub(crate) struct Session<'d> {
    inner: SessionKind<'d>,
}
enum SessionKind<'d> {
    Published {
        capsule: VerifiedGenerationCapsule,
        financial: Vec<Attachment>,
        directory: &'d Directory,
    },
    Quarantined(RestoredGenerationCapsule),
}
impl<'d> Session<'d> {
    pub(crate) fn open_layered(directory: &'d Directory, secrets: &Secrets) -> Result<Self> {
        let (_, capsule) = open_layered_parent(directory, secrets)?;
        let metadata = capture_layered_metadata(directory, secrets, &capsule)?;
        Ok(Self {
            inner: SessionKind::Published {
                capsule,
                financial: metadata.descriptor().attachments.clone(),
                directory,
            },
        })
    }
    pub(crate) fn display_inventory(&self, output: &HistoricalOutput) -> Result<()> {
        self.check()?;
        let nodes = self.capsule().histories().iter().map(|(digest, node)| serde_json::json!({
        "node_manifest": digest, "native_publication_manifest": node.manifest_digest(), "generation": node.generation_id(), "profile": node.profile_id(),
        "inherited_components": node.components().iter().map(|source| &source.provenance().component_id).collect::<Vec<_>>(),
        "current_components": node.current_provenance().iter().map(|source| source.component_id.clone()).collect::<Vec<_>>(),
    })).collect::<Vec<_>>();
        output.json(&serde_json::json!({"root_capsule_manifest":self.capsule().manifest_digest(),"nodes":nodes}))
    }
    fn capsule(&self) -> &VerifiedGenerationCapsule {
        match &self.inner {
            SessionKind::Published { capsule, .. } => capsule,
            SessionKind::Quarantined(source) => source.capsule(),
        }
    }
    fn check(&self) -> Result<()> {
        match &self.inner {
            SessionKind::Published { directory, .. } => directory.check(),
            SessionKind::Quarantined(source) => source.check(),
        }
    }
    fn external_destination(&self, destination: &Path) -> Result<()> {
        match &self.inner {
            SessionKind::Quarantined(source) => source.external_destination(destination),
            SessionKind::Published {
                capsule,
                directory,
                financial,
            } => {
                directory.external_destination(destination)?;
                crate::generation_restore::exclude_original_sources(capsule, destination)?;
                for attachment in financial {
                    exclude_directory(&attachment.directory, destination)?;
                }
                Ok(())
            }
        }
    }
}
fn exclude_directory(root: &Path, destination: &Path) -> Result<()> {
    if destination.starts_with(root) {
        return Err(Error::Invalid);
    }
    let canonical = match std::fs::canonicalize(root) {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
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
        for ancestor in destination.parent().ok_or(Error::Invalid)?.ancestors() {
            let candidate = std::fs::symlink_metadata(ancestor)?;
            if candidate.dev() == protected.dev() && candidate.ino() == protected.ino() {
                return Err(Error::Invalid);
            }
        }
    }
    Ok(())
}
#[derive(Clone, Copy)]
enum Selected<'a> {
    Inherited(&'a RecoveredEvidence),
    Ordinary(&'a ArchivedOrdinarySource),
    Coordination(&'a ArchivedGenerationSource),
}
impl Selected<'_> {
    fn identity(&self) -> HistoricalDisclosureIdentity<'_> {
        match self {
            Self::Inherited(source) => source.disclosure_identity(),
            Self::Ordinary(source) => source.disclosure_identity(),
            Self::Coordination(source) => source.disclosure_identity(),
        }
    }
}
struct Consent<'a, 'd> {
    history: &'a Session<'d>,
    source: Selected<'a>,
    node_manifest: &'a str,
    terminal: &'a Terminal,
    output: HistoricalOutput,
    review_approval: &'a HistoricalApproval,
    action: HistoricalAction,
    artifact_id: String,
}
struct Lease<'a, 'd> {
    owner: &'a Consent<'a, 'd>,
    scope: HistoricalDisclosureScope,
    approval: HistoricalApproval,
}
impl HistoricalDisclosureLease for Lease<'_, '_> {
    fn scope(&self) -> &HistoricalDisclosureScope {
        &self.scope
    }
    fn check_current(&self) -> std::result::Result<(), BundleError> {
        self.owner
            .history
            .check()
            .map_err(|_| BundleError::Permission)?;
        if let HistoricalDestination::NewPrivateLocalFile(path) = &self.scope.destination {
            self.owner
                .history
                .external_destination(path)
                .map_err(|_| BundleError::Permission)?;
        }
        self.approval.check().map_err(|_| BundleError::Permission)
    }
    fn run_effect(
        &self,
        effect: &mut dyn FnMut() -> std::result::Result<(), BundleError>,
    ) -> std::result::Result<(), BundleError> {
        self.check_current()?;
        self.approval
            .effect(&mut || effect().map_err(Error::from))
            .map_err(|_| BundleError::Permission)
    }
}
fn validate_scope(
    history: &Session<'_>,
    source: Selected<'_>,
    node_manifest: &str,
    action: HistoricalAction,
    artifact_id: &str,
    scope: &HistoricalDisclosureScope,
) -> std::result::Result<(), BundleError> {
    history.check().map_err(|_| BundleError::Permission)?;
    let node = history
        .capsule()
        .histories()
        .get(node_manifest)
        .ok_or(BundleError::Permission)?;
    let belongs = match source {
        Selected::Inherited(source) => node
            .components()
            .iter()
            .any(|candidate| std::ptr::eq(candidate, source)),
        Selected::Ordinary(source) => node
            .current_journals()
            .iter()
            .any(|candidate| std::ptr::eq(candidate, source)),
        Selected::Coordination(source) => std::ptr::eq(node.current_coordination(), source),
    };
    let identity = source.identity();
    if !belongs
        || identity
            .archive()
            .is_none_or(|archive| archive.selected_manifest_digest() != node_manifest)
        || scope.source != identity.binding()
        || scope.origin != HistoricalOrigin::from_source(identity)
        || scope.principal_id != PRINCIPAL
        || scope.action != action
        || scope.references.artifact_id != artifact_id
        || scope
            .references
            .account_ids
            .iter()
            .any(|account| !node.current_semantics().accounts().contains(account))
    {
        return Err(BundleError::Permission);
    }
    if let HistoricalDestination::NewPrivateLocalFile(path) = &scope.destination {
        history
            .external_destination(path)
            .map_err(|_| BundleError::Permission)?;
    }
    Ok(())
}
impl HistoricalDisclosureAuthority for Consent<'_, '_> {
    fn acquire<'a>(
        &'a self,
        scope: &HistoricalDisclosureScope,
    ) -> std::result::Result<Box<dyn HistoricalDisclosureLease + 'a>, BundleError> {
        validate_scope(
            self.history,
            self.source,
            self.node_manifest,
            self.action,
            &self.artifact_id,
            scope,
        )?;
        self.review_approval
            .check()
            .map_err(|_| BundleError::Permission)?;
        let detail = zeroize::Zeroizing::new(
            serde_json::to_string(scope).map_err(|_| BundleError::Integrity)?,
        );
        if detail.len() > MAX_HISTORICAL_METADATA_BYTES {
            return Err(BundleError::Limit);
        }
        let warning = if scope.action == HistoricalAction::ExportExactTransaction {
            "Exact transaction bytes may contain still-usable spend signatures. Anyone with a copy may be able to submit them; exported copies cannot be revoked."
        } else {
            ""
        };
        let approval = self.terminal.approve_historical_reviewed(self.review_approval, &format!(
            "Disclose this exact lineage-qualified historical artifact under a NEW native decision. Account exposure and external signatures remain unknown. No replay, replacement, signing or submission is authorized. {} Root capsule: {}. Selected original node: {}. Exact scope: {}",
            warning, self.history.capsule().manifest_digest(), self.node_manifest, detail.as_str()
        )).map_err(|_| BundleError::Permission)?;
        Ok(Box::new(Lease {
            owner: self,
            scope: scope.clone(),
            approval,
        }))
    }
}
fn ask_id(terminal: &Terminal, prompt: &str) -> Result<String> {
    let value = terminal.ask(prompt)?;
    crate::id(&value)?;
    Ok(value.to_string())
}
fn select<'a>(
    history: &'a Session<'_>,
    manifest: &str,
    category: &str,
    id: &str,
) -> Result<Selected<'a>> {
    let node = history
        .capsule()
        .histories()
        .get(manifest)
        .ok_or(Error::Invalid)?;
    match category {
        "inherited" => node
            .components()
            .iter()
            .find(|s| s.provenance().component_id == id)
            .map(Selected::Inherited),
        "current" if id == "root-coordination" => {
            Some(Selected::Coordination(node.current_coordination()))
        }
        "current" => node
            .current_journals()
            .iter()
            .find(|s| s.provenance().component_id == id)
            .map(Selected::Ordinary),
        _ => None,
    }
    .ok_or(Error::Invalid)
}

pub(crate) fn read_authenticated(
    terminal: Terminal,
    history: Session<'_>,
    read_approval: HistoricalApproval,
) -> Result<()> {
    history.check()?;
    read_approval.check()?;
    let manifest = terminal.ask("Exact original node manifest digest: ")?;
    if manifest.len() != 64
        || !manifest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Invalid);
    }
    let category = terminal.ask("Node component category (inherited/current): ")?;
    let component = ask_id(&terminal, "Exact component ID within that node/category: ")?;
    let source = select(&history, &manifest, &category, &component)?;
    let operation = terminal.ask("Historical operation (proof, signed-result, transaction, transaction-export, participant-record): ")?;
    let action = match operation.as_str() {
        "proof" => HistoricalAction::ProofMetadata,
        "signed-result" => HistoricalAction::SignedResultMetadata,
        "transaction" => HistoricalAction::TransactionMetadata,
        "transaction-export" => HistoricalAction::ExportExactTransaction,
        "participant-record" => HistoricalAction::ParticipantRecord,
        _ => return Err(Error::Invalid),
    };
    let artifact_id = ask_id(&terminal, "Exact historical artifact/record ID: ")?;
    let gate = Consent {
        history: &history,
        source,
        node_manifest: &manifest,
        terminal: &terminal,
        output: terminal.historical_output()?,
        review_approval: &read_approval,
        action,
        artifact_id: artifact_id.clone(),
    };
    disclose(source, action, &artifact_id, &terminal, &gate)?;
    history.check().map_err(|error| {
        if action == HistoricalAction::ExportExactTransaction {
            Error::HistoricalExportIncomplete
        } else {
            error
        }
    })?;
    terminal.message("Historical disclosure finished. No financial freshness, replay permission or active authority was created.\n").map_err(|error| if action == HistoricalAction::ExportExactTransaction { Error::HistoricalExportIncomplete } else { error })
}
fn disclose(
    source: Selected<'_>,
    action: HistoricalAction,
    artifact: &str,
    terminal: &Terminal,
    gate: &Consent<'_, '_>,
) -> Result<()> {
    macro_rules! deliver {
        ($call:expr) => {
            $call?.deliver(|value| gate.output.json(value).map_err(|_| BundleError::Permission))?
        };
    }
    use wholepact_protocol::authorization::retention::backup as signed;
    use wholepact_protocol::authorization::retention::transaction::backup as transaction;
    match action {
        HistoricalAction::ProofMetadata => match source {
            Selected::Inherited(s) => deliver!(wholepact_proof_jobs::backup::historical_proof(
                s, PRINCIPAL, artifact, gate
            )),
            Selected::Ordinary(s) => {
                deliver!(wholepact_proof_jobs::backup::archived_historical_proof(
                    s, PRINCIPAL, artifact, gate
                ))
            }
            _ => return Err(Error::Invalid),
        },
        HistoricalAction::SignedResultMetadata => match source {
            Selected::Inherited(s) => deliver!(signed::historical_signed_result(
                s, PRINCIPAL, artifact, gate
            )),
            Selected::Ordinary(s) => deliver!(signed::archived_historical_signed_result(
                s, PRINCIPAL, artifact, gate
            )),
            _ => return Err(Error::Invalid),
        },
        HistoricalAction::TransactionMetadata => match source {
            Selected::Inherited(s) => deliver!(transaction::historical_transaction(
                s, PRINCIPAL, artifact, gate
            )),
            Selected::Ordinary(s) => deliver!(transaction::archived_historical_transaction(
                s, PRINCIPAL, artifact, gate
            )),
            _ => return Err(Error::Invalid),
        },
        HistoricalAction::ExportExactTransaction => {
            let destination = PathBuf::from(
                terminal
                    .ask("NEW private local transaction file (absolute path): ")?
                    .as_str(),
            );
            gate.history.external_destination(&destination)?;
            match source {
                Selected::Inherited(s) => transaction::historical_transaction_export(
                    s,
                    PRINCIPAL,
                    artifact,
                    &destination,
                    gate,
                )?
                .export(),
                Selected::Ordinary(s) => transaction::archived_historical_transaction_export(
                    s,
                    PRINCIPAL,
                    artifact,
                    &destination,
                    gate,
                )?
                .export(),
                _ => return Err(Error::Invalid),
            }
            .map_err(|_| Error::HistoricalExportIncomplete)?;
        }
        HistoricalAction::ParticipantRecord => {
            let selection = wholepact_engine::recovery::HistoricalParticipantSelection {
                agreement_id: ask_id(terminal, "Exact historical agreement ID: ")?,
                record_id: artifact.into(),
                historical_owner_principal_id: ask_id(
                    terminal,
                    "Exact original record owner principal ID: ",
                )?,
                historical_profile_id: ask_id(terminal, "Exact original profile ID: ")?,
                participant_id: ask_id(terminal, "Exact participant ID: ")?,
                account_id: ask_id(terminal, "Exact account ID: ")?,
            };
            match source {
                Selected::Inherited(s) => {
                    deliver!(wholepact_engine::recovery::historical_participant_record(
                        s, PRINCIPAL, &selection, gate
                    ))
                }
                Selected::Coordination(s) => deliver!(
                    wholepact_engine::recovery::archived_historical_participant_record(
                        s, PRINCIPAL, &selection, gate
                    )
                ),
                _ => return Err(Error::Invalid),
            }
        }
    }
    Ok(())
}

pub(crate) fn read_quarantined(terminal: Terminal, profile: &Path) -> Result<()> {
    let approval = terminal.approve_historical(&format!(
        "Authenticate all private inherited capsule history at {} for read-only lineage-qualified disclosure. This includes participant records, viewing/scan data, proof witnesses, signatures, exact transactions, transport and observations across every retained generation. Initial approval permits bounded native node/component/account/digest scope metadata; each selected artifact or new-file export requires a SECOND exact decision. No live Host, old grant, saved admission, network, signer or financial authority is opened.", profile.display()
    ))?;
    let password = terminal.secret("Quarantined generation capsule passphrase: ")?;
    let output = terminal.historical_output()?;
    let mut source = None;
    approval.effect(&mut || {
        let session = Session {
            inner: SessionKind::Quarantined(RestoredGenerationCapsule::open(
                profile,
                password.as_bytes(),
            )?),
        };
        approval.check()?;
        session.display_inventory(&output)?;
        source = Some(session);
        Ok(())
    })?;
    drop(password);
    approval.check()?;
    read_authenticated(terminal, source.ok_or(Error::Permission)?, approval)
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
