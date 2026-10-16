//! Separate private-history disclosure route. It never opens a mutable Host,
//! enrolls a signer, grants financial permission or submits retained bytes.
use crate::{
    Error, Result,
    files::Directory,
    recovery_generation::CommittedHistory,
    terminal::{
        Terminal,
        historical::{HistoricalApproval, HistoricalOutput},
    },
    vault::Secrets,
};
use std::path::Path;
use wholepact_storage_security::bundle::{
    BundleError,
    recovery::evidence::{RecoveredEvidence, history::*},
};

const PRINCIPAL: &str = "native-recovered-artifact-reader";
struct Consent<'a, 'd> {
    history: &'a CommittedHistory<'d>,
    source: &'a RecoveredEvidence,
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
impl HistoricalDisclosureAuthority for Consent<'_, '_> {
    fn acquire<'a>(
        &'a self,
        scope: &HistoricalDisclosureScope,
    ) -> std::result::Result<Box<dyn HistoricalDisclosureLease + 'a>, BundleError> {
        self.history.check().map_err(|_| BundleError::Permission)?;
        if scope.source != self.source.historical_binding()
            || scope.origin != HistoricalOrigin::from_evidence(self.source)
            || scope.principal_id != PRINCIPAL
            || scope.action != self.action
            || scope.references.artifact_id != self.artifact_id
            || scope
                .references
                .account_ids
                .iter()
                .any(|account| !self.history.known_account_ids().contains(account))
        {
            return Err(BundleError::Permission);
        }
        if let HistoricalDestination::NewPrivateLocalFile(path) = &scope.destination {
            self.history
                .external_destination(path)
                .map_err(|_| BundleError::Permission)?;
        }
        let detail = zeroize::Zeroizing::new(
            serde_json::to_string(scope).map_err(|_| BundleError::Integrity)?,
        );
        self.review_approval
            .check()
            .map_err(|_| BundleError::Permission)?;
        if detail.len() > MAX_HISTORICAL_METADATA_BYTES {
            return Err(BundleError::Limit);
        }
        let export_warning = if scope.action == HistoricalAction::ExportExactTransaction {
            "These exact bytes may contain a still-usable transaction and spend signatures. Anyone with a copy may be able to submit it; exported copies cannot be revoked."
        } else {
            ""
        };
        let approval = self.terminal.approve_historical_reviewed(self.review_approval, &format!(
            "Disclose exactly this recovered artifact under a new native approval. Historical observations, unknown signatures and exposure remain uncertain. This grants no replay, replacement, signing or submission authority. Exact transaction export creates one new private file; its bytes may already have escaped historically.\n{}\nGeneration manifest: {}\nExact scope: {}",
            export_warning, self.history.manifest_digest(), detail.as_str()
        )).map_err(|_| BundleError::Permission)?;
        Ok(Box::new(Lease {
            owner: self,
            scope: scope.clone(),
            approval,
        }))
    }
}
fn ask_id(terminal: &Terminal, prompt: &str) -> Result<String> {
    let value = terminal.ask(prompt)?.to_string();
    crate::id(&value)?;
    Ok(value)
}
enum OpenedHistory<'a> {
    Original(Box<CommittedHistory<'a>>),
    Layered(Box<crate::recovered_capsule_history::Session<'a>>),
}
pub(crate) fn read(terminal: Terminal, profile: &Path) -> Result<()> {
    let directory = Directory::open(profile)?;
    let read_approval = terminal.approve_historical(&format!(
        "Unlock and authenticate private inherited recovery evidence in {} for a separate historical read. This reads all inherited host-owned participant records, wallet viewing/scan history, proof witnesses, signatures, transactions, transport, submission and observation rows to validate their exact relationships. It also reads current successor coordination and queue snapshots for integrity. Current separately attached financial journals are outside this historical scope. No raw rows are displayed. This initial review permits bounded native scope metadata, including selected identifiers, account IDs and digests, needed to request the second decision. Selected record/proof/result projections and exact transaction bytes require that second exact approval. No live Host, signer, proof worker or network is started.", profile.display()
    ))?;
    let password = terminal.secret("Restricted successor storage passphrase: ")?;
    let output = terminal.historical_output()?;
    let mut history = None;
    read_approval.effect(&mut || {
        let secrets = Secrets::open(&directory.read("profile.vault", 1024)?, password.as_bytes())?;
        history = Some(
            match crate::recovery_generation::archive_history::source_plan_version(
                &directory, &secrets,
            )? {
                1 => OpenedHistory::Original(Box::new(crate::recovery_generation::open_committed_history(
                    &directory, &secrets,
                )?)),
                2 => OpenedHistory::Layered(
                    Box::new(crate::recovered_capsule_history::Session::open_layered(&directory, &secrets)?),
                ),
                _ => return Err(Error::Unsupported),
            },
        );
        read_approval.check()?;
        match history.as_ref().ok_or(Error::Permission)? {
            OpenedHistory::Original(history) => output.json(&serde_json::json!({
                "generation": history.generation_id(), "profile": history.profile_id(),
                "inventory": history.inventory_digest(), "retained_components": history.components().len(),
                "registered_financial_attachments_outside_scope": history.registered_financial_directories(),
            }))?,
            OpenedHistory::Layered(history) => history.display_inventory(&output)?,
        }
        Ok(())
    })?;
    drop(password);
    let history = match history.ok_or(Error::Permission)? {
        OpenedHistory::Original(history) => history,
        OpenedHistory::Layered(history) => {
            return crate::recovered_capsule_history::read_authenticated(
                terminal,
                *history,
                read_approval,
            );
        }
    };
    read_approval.check()?;
    let component = ask_id(&terminal, "Exact retained component ID: ")?;
    let source = history.component(&component)?;
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
        terminal: &terminal,
        output: terminal.historical_output()?,
        review_approval: &read_approval,
        action,
        artifact_id: artifact_id.clone(),
    };
    match action {
        HistoricalAction::ProofMetadata => wholepact_proof_jobs::backup::historical_proof(source, PRINCIPAL, &artifact_id, &gate)?.deliver(|value| gate.output.json(value).map_err(|_| BundleError::Permission))?,
        HistoricalAction::SignedResultMetadata => wholepact_protocol::authorization::retention::backup::historical_signed_result(source, PRINCIPAL, &artifact_id, &gate)?.deliver(|value| gate.output.json(value).map_err(|_| BundleError::Permission))?,
        HistoricalAction::TransactionMetadata => wholepact_protocol::authorization::retention::transaction::backup::historical_transaction(source, PRINCIPAL, &artifact_id, &gate)?.deliver(|value| gate.output.json(value).map_err(|_| BundleError::Permission))?,
        HistoricalAction::ExportExactTransaction => {
            let destination = std::path::PathBuf::from(terminal.ask("NEW private local transaction file (absolute path): ")?.as_str());
            history.external_destination(&destination)?;
            wholepact_protocol::authorization::retention::transaction::backup::historical_transaction_export(source, PRINCIPAL, &artifact_id, &destination, &gate)?.export().map_err(|_| Error::HistoricalExportIncomplete)?;
        }
        HistoricalAction::ParticipantRecord => {
            let selection = wholepact_engine::recovery::HistoricalParticipantSelection {
                agreement_id: ask_id(&terminal, "Exact historical agreement ID: ")?,
                record_id: artifact_id,
                historical_owner_principal_id: ask_id(&terminal, "Exact original record owner principal ID: ")?,
                historical_profile_id: ask_id(&terminal, "Exact original profile ID: ")?,
                participant_id: ask_id(&terminal, "Exact participant ID: ")?,
                account_id: ask_id(&terminal, "Exact account ID: ")?,
            };
            wholepact_engine::recovery::historical_participant_record(source, PRINCIPAL, &selection, &gate)?.deliver(|value| gate.output.json(value).map_err(|_| BundleError::Permission))?;
        }
    }
    history.check().map_err(|error| {
        if action == HistoricalAction::ExportExactTransaction {
            Error::HistoricalExportIncomplete
        } else {
            error
        }
    })?;
    terminal.message("Historical disclosure finished. Exposure and external signatures remain uncertain; no live authority or replay permission was created.\n").map_err(|error| if action == HistoricalAction::ExportExactTransaction { Error::HistoricalExportIncomplete } else { error })
}
