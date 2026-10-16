//! Explicit retained-signature, extraction and one-shot dispatch commands. Every
//! account association comes from the installed live signer, never transport alone.
use super::*;
use wholepact_engine::{
    proof_jobs::LocalProofJob,
    signature_intake::{
        AuthenticatedSignatureDelivery, LocalSignedRetention,
        authority_bridge::{
            with_redelivered_signer_account_association_checked,
            with_signer_account_association_checked,
        },
    },
};
use wholepact_protocol::authorization::retention::transaction::LocalTransactionCheckpoint;
use wholepact_service::protected_transport::signature_intake::AuthorizationArtifactSource;
use wholepact_signer::{
    authority_bridge::{
        dispatch_ipc::DispatchRequest,
        ipc::{HistoryRequest, OriginalHistoryClient},
        provider::InstalledSignerProvider,
    },
    consent_journal::{ResultRedeliveryReference, ResultRedeliveryRequest},
    ipc::PairScope,
};
use wholepact_transport::ReceivedArtifact;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureSource {
    signer_socket: PathBuf,
    history: HistoryRequest,
    /// A fresh native review binds the existing result to this new host process.
    redelivery_operation_id: String,
    context: MessageContext,
    envelope_path: Option<PathBuf>,
    retained_sequence: Option<u64>,
}

struct SettlementOperationContext<'a> {
    expected_artifact: Option<&'a str>,
    native_request: Option<super::settlement_request::NativeSettlementDispatch>,
    dispatch_request: Option<wholepact_engine::native_dispatch_requests::NativeDispatchAttempt>,
}

// Pure full-roster syntax/binding check. This invokes the following operation
// only after EVERY source is valid. It creates no signer or financial capability.
fn after_signature_roster_preflight<R>(
    candidate: &wholepact_engine::CandidateView,
    sources: &[SignatureSource],
    after_preflight: impl FnOnce(BTreeSet<String>) -> Result<R>,
) -> Result<R> {
    if sources.is_empty()
        || sources.len() > 8
        || sources.len() != candidate.proposal.manifest.participants.len()
    {
        return Err(Error::Invalid);
    }
    let mut accounts = BTreeSet::new();
    for source in sources {
        let participant = candidate
            .proposal
            .manifest
            .participants
            .iter()
            .find(|p| p.participant_id == source.context.sender_id)
            .ok_or(Error::Invalid)?;
        if !accounts.insert(participant.account_id.clone())
            || source.context.artifact_kind != wholepact_transport::ArtifactKind::Authorization
            || source.context.proposal_id != candidate.candidate_id.as_str()
            || source.context.agreement_id != candidate.proposal.manifest.agreement.agreement_id
            || source.context.network_profile_id
                != candidate.proposal.manifest.agreement.network_profile_id
            || source.context.proposal_revision
                != u64::from(candidate.proposal.manifest.agreement.revision)
            || source.envelope_path.is_some() == source.retained_sequence.is_some()
            || source
                .retained_sequence
                .is_some_and(|sequence| sequence == 0 || sequence > i64::MAX as u64)
            || source
                .envelope_path
                .as_ref()
                .is_some_and(|path| !path.is_absolute())
            || !source.signer_socket.is_absolute()
        {
            return Err(Error::Invalid);
        }
        id(&source.redelivery_operation_id)?;
        id(&source.history.authorization_id)?;
        id(&source.context.recipient_id)?;
        for reference in [
            &source.history.expected_original_consent_ref,
            &source.history.expected_enrollment_ref,
            &source.history.expected_manifest_ref,
        ] {
            if reference.len() != 64
                || !reference
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(Error::Invalid);
            }
        }
    }
    after_preflight(accounts)
}

// Associations may only exist inside their authenticated history closure. The
// recursive stack keeps all owners' real leases held through the final effect.
fn with_associations<R>(
    clients: &[OriginalHistoryClient],
    sources: &[SignatureSource],
    redeliveries: &[Option<ResultRedeliveryReference>],
    artifacts: &[&ReceivedArtifact],
    accumulated: &[AuthenticatedSignatureDelivery<'_>],
    checks: &[&dyn Fn() -> std::result::Result<(), wholepact_engine::ApiError>],
    operation: &impl Fn(
        &[AuthenticatedSignatureDelivery<'_>],
        &[&dyn Fn() -> std::result::Result<(), wholepact_engine::ApiError>],
    ) -> std::result::Result<R, wholepact_engine::ApiError>,
) -> std::result::Result<R, wholepact_engine::ApiError> {
    let index = accumulated.len();
    if index == sources.len() {
        return operation(accumulated, checks);
    }
    let next =
        |association: &wholepact_engine::signature_intake::AuthenticatedAccountAssociation,
         check: &dyn Fn() -> std::result::Result<(), wholepact_engine::ApiError>| {
            let mut next_checks = checks.to_vec();
            next_checks.push(check);
            let mut deliveries = accumulated
                .iter()
                .map(|d| AuthenticatedSignatureDelivery {
                    artifact: d.artifact,
                    association: d.association,
                })
                .collect::<Vec<_>>();
            deliveries.push(AuthenticatedSignatureDelivery {
                artifact: artifacts[index],
                association: Some(association),
            });
            with_associations(
                clients,
                sources,
                redeliveries,
                artifacts,
                &deliveries,
                &next_checks,
                operation,
            )
        };
    if let Some(reference) = &redeliveries[index] {
        with_redelivered_signer_account_association_checked(
            &clients[index],
            &sources[index].history,
            reference,
            artifacts[index],
            next,
        )
    } else {
        with_signer_account_association_checked(
            &clients[index],
            &sources[index].history,
            artifacts[index],
            next,
        )
    }
}
fn native_failure(_: Error) -> wholepact_engine::ApiError {
    wholepact_engine::ApiError::new(
        "NATIVE_FINANCIAL_OPERATION_BLOCKED",
        "The exact native financial operation did not complete. Preserve original encrypted journals and operation identifiers; a retained or dispatched effect may remain. No replacement is authorized.",
    )
}
fn settlement_observation_value<T: serde::Serialize>(
    observed: std::result::Result<T, wholepact_engine::ApiError>,
) -> Result<serde_json::Value> {
    Ok(serde_json::to_value(observed?)?)
}

impl Host {
    pub(in crate::host) fn financial_settle(&self, operation: &str) -> Result<()> {
        if !matches!(
            operation,
            "signature-retain"
                | "signature-reconcile"
                | "transaction-export"
                | "transaction-checkpoint"
                | "transaction-dispatch"
                | "record-retain"
        ) {
            return Err(Error::Invalid);
        }
        self.financial_permission(if operation == "record-retain" {
            Permission::Read
        } else {
            Permission::Coordinate
        })?;
        self.financial_permission(Permission::Disclose)?;
        let _profile = self.financial.as_ref().ok_or(Error::Locked)?;
        let candidate_id = self.terminal.ask("Exact candidate ID: ")?;
        let job_id = self.terminal.ask("Original proved checkpoint job ID: ")?;
        let signature_key = self
            .terminal
            .ask("Original stable signature-set retention key (reuse unchanged): ")?;
        self.financial_settle_exact(operation, &candidate_id, &job_id, &signature_key, None)
    }
    pub(super) fn financial_settle_exact(
        &self,
        operation: &str,
        candidate_id: &str,
        job_id: &str,
        signature_key: &str,
        expected_artifact: Option<&str>,
    ) -> Result<()> {
        self.financial_settle_owned(
            operation,
            candidate_id,
            job_id,
            signature_key,
            SettlementOperationContext {
                expected_artifact,
                native_request: None,
                dispatch_request: None,
            },
        )
    }
    pub(super) fn financial_settle_request(
        &self,
        request: super::settlement_request::NativeSettlementDispatch,
    ) -> Result<()> {
        let source = request.source().clone();
        let operation = request.operation();
        self.financial_settle_owned(
            operation,
            &source.candidate_id,
            &source.job_id,
            &source.signature_retention_key,
            SettlementOperationContext {
                expected_artifact: Some(&source.proved_artifact_digest),
                native_request: Some(request),
                dispatch_request: None,
            },
        )
    }
    pub(super) fn financial_dispatch_request(
        &self,
        request: wholepact_engine::native_dispatch_requests::NativeDispatchAttempt,
    ) -> Result<()> {
        let source = request.source().original.clone();
        self.financial_settle_owned(
            "transaction-dispatch",
            &source.candidate_id,
            &source.job_id,
            &source.signature_retention_key,
            SettlementOperationContext {
                expected_artifact: Some(&source.proved_artifact_digest),
                native_request: None,
                dispatch_request: Some(request),
            },
        )
    }
    fn financial_settle_owned(
        &self,
        operation: &str,
        candidate_id: &str,
        job_id: &str,
        signature_key: &str,
        context: SettlementOperationContext<'_>,
    ) -> Result<()> {
        let SettlementOperationContext {
            expected_artifact,
            native_request,
            dispatch_request,
        } = context;
        if !matches!(
            operation,
            "transaction-inspect"
                | "signature-retain"
                | "signature-reconcile"
                | "transaction-export"
                | "transaction-checkpoint"
                | "transaction-dispatch"
                | "record-retain"
        ) {
            return Err(Error::Invalid);
        }
        if operation == "transaction-inspect" && native_request.is_none() {
            return Err(Error::Invalid);
        }
        self.financial_permission(if operation == "record-retain" {
            Permission::Read
        } else {
            Permission::Coordinate
        })?;
        self.financial_permission(Permission::Disclose)?;
        let access = self.access()?;
        let profile = self.financial.as_ref().ok_or(Error::Locked)?;
        let (_, candidate) = self.engine.candidate(access, candidate_id)?;
        // A queued handoff pins the proved digest; inspect genuine encrypted bytes
        // before the first pairing, redelivery or transport effect.
        if let Some(expected) = expected_artifact {
            profile.inventory()?;
            let consent = self.authority.proof_consent(
                &access.principal_id,
                candidate_id,
                &candidate.manifest_digest,
                vec![
                    wholepact_proof_jobs::LocalAction::InspectStatus,
                    wholepact_proof_jobs::LocalAction::ReadPrivateArtifact,
                ],
            )?;
            let checkpoint = self.engine.load_candidate_proof_for_local_review(
                access,
                candidate_id,
                LocalProofJob {
                    job_id,
                    jobs: &profile.proof,
                    consent: &consent,
                },
            )?;
            use sha2::Digest;
            let digest = hex::encode(sha2::Sha256::digest(checkpoint.pczt_bytes()));
            if digest != expected || checkpoint.summary().result_digest.as_deref() != Some(expected)
            {
                return Err(Error::Invalid);
            }
        }
        let sources: Vec<SignatureSource> = self.read_json(
            "Exact signer histories and authenticated encrypted authorization sources JSON: ",
        )?;
        self.financial_lineage_preflight(&candidate, Some(signature_key), &[job_id])?;
        let (accounts, clients) = after_signature_roster_preflight(
            &candidate,
            &sources,
            |accounts| {
                for source in &sources {
                    self.financial_lineage_preflight(
                        &candidate,
                        Some(signature_key),
                        &[
                            job_id,
                            &source.history.authorization_id,
                            &source.redelivery_operation_id,
                        ],
                    )?;
                }
                // Validate every source and exact lineage before the first pairing or
                // redelivery. A later bad participant must not cause an earlier effect.
                profile.inventory()?;
                let mut clients = Vec::new();
                for source in &sources {
                    let participant = candidate
                        .proposal
                        .manifest
                        .participants
                        .iter()
                        .find(|p| p.participant_id == source.context.sender_id)
                        .ok_or(Error::Invalid)?;
                    self.financial_lineage_preflight(
                        &candidate,
                        Some(signature_key),
                        &[
                            job_id,
                            &source.history.authorization_id,
                            &source.redelivery_operation_id,
                        ],
                    )?;
                    self.terminal.confirm(&format!("Pair with the installed signer at {} for original authorization {} of account {}. The signer will separately review exact result redelivery to this host process. This does not generate new signatures.", source.signer_socket.display(), source.history.authorization_id, participant.account_id))?;
                    clients.push(
                        OriginalHistoryClient::pair(
                            InstalledSignerProvider::load().map_err(|_| Error::Permission)?,
                            &source.signer_socket,
                            "wholepact-native-settlement",
                            PairScope {
                                account_id: participant.account_id.clone(),
                                agreement_id: source.context.agreement_id.clone(),
                                participant_id: participant.participant_id.clone(),
                                manifest_digest: candidate.manifest_digest.clone(),
                                history_read: true,
                                authorization_export: true,
                                preconstruction_export: false,
                            },
                        )
                        .map_err(|_| Error::Permission)?,
                    );
                }
                Ok((accounts, clients))
            },
        )?;
        let mut redeliveries = Vec::new();
        for (client, source) in clients.iter().zip(&sources) {
            self.financial_lineage_preflight(
                &candidate,
                Some(signature_key),
                &[
                    job_id,
                    &source.history.authorization_id,
                    &source.redelivery_operation_id,
                ],
            )?;
            let history = &source.history;
            let reference = client
                .request_result_redelivery(&ResultRedeliveryRequest {
                    operation_id: source.redelivery_operation_id.clone(),
                    authorization_id: history.authorization_id.clone(),
                    expected_original_consent_ref: history.expected_original_consent_ref.clone(),
                    expected_enrollment_ref: history.expected_enrollment_ref.clone(),
                    expected_manifest_ref: history.expected_manifest_ref.clone(),
                })
                .map_err(|_| Error::Permission)?;
            self.terminal.json(&reference)?;
            redeliveries.push(Some(reference));
        }
        let proof_consent = self.authority.proof_consent(
            &access.principal_id,
            candidate_id,
            &candidate.manifest_digest,
            vec![
                wholepact_proof_jobs::LocalAction::InspectStatus,
                wholepact_proof_jobs::LocalAction::ReadPrivateArtifact,
            ],
        )?;
        let retention = self.authority.retention_consent(
            &access.principal_id,
            candidate_id,
            &candidate.manifest_digest,
            job_id,
            accounts,
        )?;
        let mut envelopes = Vec::new();
        for source in &sources {
            self.financial_lineage_preflight(
                &candidate,
                Some(signature_key),
                &[
                    job_id,
                    &source.history.authorization_id,
                    &source.redelivery_operation_id,
                ],
            )?;
            envelopes.push(
                source
                    .envelope_path
                    .as_ref()
                    .map(|path| {
                        files::read_artifact(path, wholepact_transport::MAX_FILE_BYTES).and_then(
                            |bytes| EncryptedEnvelope::from_bytes(bytes).map_err(Error::from),
                        )
                    })
                    .transpose()?,
            );
        }
        for (source, envelope) in sources.iter().zip(&envelopes) {
            if let Some(envelope) = envelope {
                use sha2::Digest;
                self.terminal.confirm(&format!("Authenticate and retain this exact encrypted authorization file locally. The ciphertext can remain retained if any later consent fails. No signature attribution, extraction or submission is implied by transport authentication.\nContext: {}\nCiphertext SHA256: {}", serde_json::to_string_pretty(&source.context)?, hex::encode(sha2::Sha256::digest(envelope.as_bytes()))))?;
            }
        }
        let inputs = sources
            .iter()
            .zip(&envelopes)
            .map(|(source, envelope)| match envelope {
                Some(envelope) => AuthorizationArtifactSource::Incoming {
                    context: source.context.clone(),
                    envelope,
                },
                None => AuthorizationArtifactSource::Retained {
                    context: source.context.clone(),
                    sequence: source
                        .retained_sequence
                        .expect("validated mutually exclusive source"),
                },
            })
            .collect::<Vec<_>>();
        // All independently selected transport keys and privacy leases remain
        // held while account associations, retention and any dispatch execute.
        let portable: Option<super::participant_delivery::PortableExportInput> = if operation
            == "transaction-export"
        {
            let input: super::participant_delivery::PortableExportInput = self
                .read_json("Exact finalized transaction participant export configuration JSON: ")?;
            let agreement = &candidate.proposal.manifest.agreement;
            if input.context.artifact_kind != wholepact_transport::ArtifactKind::FinalTransaction
                || input.context.agreement_id != agreement.agreement_id
                || input.context.proposal_id != candidate.proposal.proposal_id
                || input.context.proposal_revision != u64::from(agreement.revision)
                || input.context.network_profile_id != agreement.network_profile_id
                || !(candidate
                    .proposal
                    .manifest
                    .participants
                    .iter()
                    .any(|p| p.participant_id == input.context.recipient_id)
                    || agreement
                        .recipients
                        .iter()
                        .any(|r| r.recipient_id == input.context.recipient_id))
            {
                return Err(Error::Permission);
            }
            self.directory.external_destination(&input.destination)?;
            Some(input)
        } else {
            None
        };
        let portable_consent = self.authority.portable_consent(&access.principal_id)?;
        let mut transport = self.transport.lock().map_err(|_| Error::Invalid)?;
        self.financial_lineage_preflight(&candidate, Some(signature_key), &[job_id])?;
        if native_request.is_some() && dispatch_request.is_some() {
            return Err(Error::Invalid);
        }
        let has_dispatch_request = dispatch_request.is_some();
        let dispatch_request = std::cell::RefCell::new(dispatch_request);
        let has_native_request = native_request.is_some();
        let native_request = std::cell::RefCell::new(native_request);
        let result = transport.with_authorization_artifacts_and_transport(access, &inputs, |artifacts, transport, transport_current| {
            let transport = std::cell::RefCell::new(transport);
            with_associations(&clients, &sources, &redeliveries, artifacts, &[], &[], &|deliveries, signer_checks| {
                let run = || -> Result<serde_json::Value> {
                    self.financial_lineage_preflight(&candidate, Some(signature_key), &[job_id])?;
                    let local = || LocalProofJob { job_id, jobs: &profile.proof, consent: &proof_consent };
                    let signed = || LocalSignedRetention { journal: &profile.signed, consent: &retention };
                    let transactions = || LocalTransactionCheckpoint { journal: &profile.transactions, consent: &retention };
                    let timestamp = || Timestamp::from_unix_seconds(i64::try_from(now()?).map_err(|_| Error::Invalid)?).map_err(Error::from);
                    if has_native_request {
                        use super::settlement_request::NativeSettlementDispatch;
                        use super::settlement_request_consent::CheckedSettlementConsent;
                        let current = || transport_current().is_ok() && signer_checks.iter().all(|check| check().is_ok());
                        let checked = CheckedSettlementConsent { proof: &proof_consent, signed: &retention, transaction: &retention, recovery: &retention, submission: &retention, current: &current };
                        let local = || LocalProofJob { job_id, jobs: &profile.proof, consent: &checked };
                        let signed = || LocalSignedRetention { journal: &profile.signed, consent: &checked };
                        let transactions = || LocalTransactionCheckpoint { journal: &profile.transactions, consent: &checked };
                        let request = native_request.borrow_mut().take().ok_or(Error::Invalid)?;
                        let observed = match request {
                            NativeSettlementDispatch::Initial(attempt) => match attempt.kind() {
                                wholepact_engine::native_settlement_requests::SettlementRequestKind::SignatureReconcile => self.engine.reconcile_native_signature_result(access, attempt.into_inspection(), local(), signed(), deliveries, &timestamp()?),
                                wholepact_engine::native_settlement_requests::SettlementRequestKind::TransactionCheckpoint => self.engine.checkpoint_native_settlement_transaction(access, attempt, local(), signed(), transactions(), deliveries, &timestamp()?),
                            },
                            NativeSettlementDispatch::Inspection(inspection) => match inspection.kind() {
                                wholepact_engine::native_settlement_requests::SettlementRequestKind::SignatureReconcile => self.engine.reconcile_native_signature_result(access, inspection, local(), signed(), deliveries, &timestamp()?),
                                wholepact_engine::native_settlement_requests::SettlementRequestKind::TransactionCheckpoint => self.engine.inspect_native_settlement_transaction(access, inspection, local(), signed(), transactions(), &checked, deliveries, &timestamp()?),
                            },
                        };
                        return settlement_observation_value(observed);
                    }
                    if has_dispatch_request {
                        use super::settlement_request_consent::CheckedSettlementConsent;
                        let attempt = dispatch_request.borrow_mut().take().ok_or(Error::Invalid)?;
                        let current = || transport_current().is_ok() && signer_checks.iter().all(|check| check().is_ok());
                        let checked = CheckedSettlementConsent { proof: &proof_consent, signed: &retention, transaction: &retention, recovery: &retention, submission: &retention, current: &current };
                        let local = || LocalProofJob { job_id, jobs: &profile.proof, consent: &checked };
                        let signed = || LocalSignedRetention { journal: &profile.signed, consent: &checked };
                        let transactions = || LocalTransactionCheckpoint { journal: &profile.transactions, consent: &checked };

                            let operation_id = attempt.operation_id().to_owned();
                            id(&operation_id)?;
                            self.financial_lineage_preflight(
                                &candidate, Some(signature_key), &[job_id, &operation_id],
                            )?;
                            let verified = self.engine.verify_candidate_submission(access, signature_key, candidate_id, &operation_id, local(), signed(), transactions(), deliveries, &timestamp()?)?;
                            let originals = clients.iter().zip(&sources).zip(&redeliveries).map(|((client, source), reference)| {
                                client.acquire_redelivered(&source.history, reference.as_ref().ok_or(Error::Invalid)?).map_err(|_| Error::Permission)
                            }).collect::<Result<Vec<_>>>()?;
                            let source_id = self.terminal.ask("Exact submission provider source ID: ")?;
                            let endpoint = self.terminal.ask("Exact submission provider HTTPS origin: ")?;
                            let adapter = ChainAdapter::testnet(&source_id, &endpoint, NetworkPolicy::default())?;
                            let policy = wholepact_chain::SubmissionPolicy::default();
                            let mut journal = self.submission.lock().map_err(|_| Error::Storage)?;
                            self.engine.validate_native_dispatch_attempt(access, &attempt, &verified, &journal)?;
                            if !current() { return Err(Error::Permission); }
                            let native = self.authority.approve_exact_submission(&verified, journal.identity(), adapter.identity(), policy.minimum_expiry_margin_blocks)?;
                            if !current() { return Err(Error::Permission); }
                            let disclosure = native.signer_disclosure()?;
                            if disclosure.digest().map_err(|_| Error::Invalid)? != native.disclosure_digest() { return Err(Error::Invalid); }
                            let requests = sources.iter().map(|source| {
                                let request_id = wholepact_engine::settlement_fanout::native_account_dispatch_operation(operation_id.as_str(), &source.history.authorization_id)?;
                                Ok(DispatchRequest { history: source.history.clone(), operation_id: request_id, backend: disclosure.clone() })
                            }).collect::<Result<Vec<_>>>()?;
                            let admissions = clients.iter().zip(&requests).map(|(client, request)| client.request_dispatch(request).map_err(|_| Error::Permission)).collect::<Result<Vec<_>>>()?;
                            if !current() { return Err(Error::Permission); }
                            let mut backend = wholepact_chain::LightwalletSubmissionBackend::new(adapter);
                            let mut runtime = crate::financial_runtime::ProtectedFinancialRuntime { engine: &self.engine, access, submission_journal: &mut journal, backend: &mut backend };
                            let executor = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_| Error::Storage)?;
                            let retained = executor.block_on(runtime.retain_original_intent(&verified, signature_key, local(), signed(), transactions(), deliveries, &originals, &admissions, &native, &checked, policy, &timestamp()?))?;
                            if &retained != verified.descriptor() || !current() { return Err(Error::Permission); }
                            let report = executor.block_on(runtime.dispatch(&verified, signature_key, local(), signed(), transactions(), deliveries, &originals, &admissions, &native, &checked, policy, &timestamp()?))?;
                            self.terminal.message("One exact dispatch attempt returned a durable report. This is not confirmation or finality; keep exposure and use observe for the same operation.\n")?;
                            self.terminal.json(&report)?;
                            if !current() { return Err(Error::Permission); }
                            self.authority.check_financial_principal(&access.principal_id)?;
                            // Re-read the real journal, never publish a caller report as authority.
                            return settlement_observation_value(self.engine.inspect_native_dispatch_status(access, attempt.into_inspection(), &journal));
                    }
                    match operation {
                        "signature-retain" => Ok(serde_json::to_value(self.engine.retain_candidate_signatures(access, signature_key, candidate_id, local(), signed(), deliveries, &timestamp()?)?)?),
                        "signature-reconcile" => Ok(serde_json::to_value(self.engine.reconcile_retained_candidate_signatures(access, signature_key, candidate_id, local(), signed(), deliveries, &timestamp()?)?)?),
                        "transaction-export" => {
                            let input = portable.as_ref().ok_or(Error::Invalid)?;
                            self.engine.disclose_candidate_transaction(access, signature_key, candidate_id, local(), signed(), transactions(), deliveries, &timestamp()?,
                                &input.context.recipient_id, &input.purpose, &portable_consent, |bytes, retained_current| -> Result<()> {
                                    let field = wholepact_transport::DisclosureField::new("finalized_transaction_v1", bytes.to_vec())?;
                                    let current = || {
                                        transport_current()?;
                                        for check in signer_checks { check()?; }
                                        retained_current().map_err(|_| wholepact_engine::ApiError::new("PORTABLE_SOURCE_EXPIRED", "Original transaction disclosure permission expired"))?;
                                        Ok(())
                                    };
                                    self.deliver_participant_field_with_transport(input, field, &mut transport.borrow_mut(), &current)
                                })??;
                            Ok(serde_json::json!({"exact_transaction_prepared":true,"payment_verified":false}))
                        }
                        "transaction-checkpoint" => Ok(serde_json::to_value(self.engine.checkpoint_retained_candidate_transaction(access, signature_key, candidate_id, local(), signed(), transactions(), deliveries, &timestamp()?)?)?),
                        "record-retain" => {
                            use wholepact_engine::participant_records::{ParticipantRecordAction, ParticipantRecordRuntime, ParticipantRecordScope, RetainParticipantRecordRequest};
                            use wholepact_engine::signature_intake::record_source::{LocalParticipantRecordSource, OriginalAuthorizationHistory};
                            let participant_id = self.terminal.ask("Original participant ID whose private record is retained: ")?;
                            let index = sources.iter().position(|source| source.context.sender_id == participant_id.as_str()).ok_or(Error::Invalid)?;
                            let original = clients[index].acquire_redelivered(&sources[index].history, redeliveries[index].as_ref().ok_or(Error::Invalid)?).map_err(|_| Error::Permission)?;
                            let account_id = original.evidence().consent.terms().account_id.clone();
                            let agreement_id = &candidate.proposal.manifest.agreement.agreement_id;
                            let record_id = self.terminal.ask("Stable private record ID (reuse unchanged): ")?;
                            let key = self.terminal.ask("Stable original record-retention idempotency key: ")?;
                            let revision = self.terminal.ask("Coordination revision at original record request (reuse unchanged on replay): ")?.parse::<u64>().map_err(|_| Error::Invalid)?;
                            let scope = ParticipantRecordScope {
                                store: self.engine.protected_record_store_binding()?, profile_id: self.secrets.profile(),
                                principal_id: access.principal_id.clone(), agreement_id: agreement_id.clone(),
                                record_id: record_id.to_string(), participant_id: participant_id.to_string(), account_id: account_id.clone(), action: ParticipantRecordAction::Retain,
                            };
                            let authority = self.authority.approve_record_retention(scope, &original)?;
                            let current = timestamp()?;
                            let window = wholepact_core::records::ObservationWindow { now: current.as_str().into(), oldest_acceptable: current.as_str().into() };
                            let profile_id = self.secrets.profile();
                            let result = self.engine.retain_participant_record_from_protocol(access, &key, agreement_id, revision,
                                RetainParticipantRecordRequest { record_id: record_id.to_string(), candidate_id: candidate_id.to_string(), participant_id: participant_id.to_string(), account_id },
                                ParticipantRecordRuntime { profile_id: &profile_id, authority: &authority, window: &window },
                                LocalParticipantRecordSource { proof: local(), signatures: signed(), transaction: transactions(), transaction_read_consent: &retention,
                                    deliveries, signature_idempotency_key: signature_key,
                                    original_authorization: OriginalAuthorizationHistory::AuthenticatedSigner { history: &original }, now: &current })?;
                            original.check_current().map_err(|_| Error::Permission)?;
                            self.terminal.message("Private participant record retained from the exact original signer and protected transaction. Use receipt-preview, receipt-stage and receipt-write for separately approved selected-field export. No settlement or complete account exposure was inferred.\n")?;
                            Ok(serde_json::to_value(result)?)
                        }
                        "transaction-dispatch" => {
                            let operation_id = self.terminal.ask("Stable ORIGINAL exact submission operation ID (reuse unchanged): ")?;
                            id(&operation_id)?;
                            self.financial_lineage_preflight(
                                &candidate, Some(signature_key), &[job_id, &operation_id],
                            )?;
                            let verified = self.engine.verify_candidate_submission(access, signature_key, candidate_id, &operation_id, local(), signed(), transactions(), deliveries, &timestamp()?)?;
                            let originals = clients.iter().zip(&sources).zip(&redeliveries).map(|((client, source), reference)| {
                                client.acquire_redelivered(&source.history, reference.as_ref().ok_or(Error::Invalid)?).map_err(|_| Error::Permission)
                            }).collect::<Result<Vec<_>>>()?;
                            let source_id = self.terminal.ask("Exact submission provider source ID: ")?;
                            let endpoint = self.terminal.ask("Exact submission provider HTTPS origin: ")?;
                            let adapter = ChainAdapter::testnet(&source_id, &endpoint, NetworkPolicy::default())?;
                            let policy = wholepact_chain::SubmissionPolicy::default();
                            let mut journal = self.submission.lock().map_err(|_| Error::Storage)?;
                            let native = self.authority.approve_exact_submission(&verified, journal.identity(), adapter.identity(), policy.minimum_expiry_margin_blocks)?;
                            let disclosure = native.signer_disclosure()?;
                            if disclosure.digest().map_err(|_| Error::Invalid)? != native.disclosure_digest() { return Err(Error::Invalid); }
                            let requests = sources.iter().map(|source| {
                                let request_id = wholepact_engine::settlement_fanout::native_account_dispatch_operation(operation_id.as_str(), &source.history.authorization_id)?;
                                Ok(DispatchRequest { history: source.history.clone(), operation_id: request_id, backend: disclosure.clone() })
                            }).collect::<Result<Vec<_>>>()?;
                            let admissions = clients.iter().zip(&requests).map(|(client, request)| client.request_dispatch(request).map_err(|_| Error::Permission)).collect::<Result<Vec<_>>>()?;
                            let mut backend = wholepact_chain::LightwalletSubmissionBackend::new(adapter);
                            let mut runtime = crate::financial_runtime::ProtectedFinancialRuntime { engine: &self.engine, access, submission_journal: &mut journal, backend: &mut backend };
                            let executor = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_| Error::Storage)?;
                            let report = executor.block_on(runtime.dispatch(&verified, signature_key, local(), signed(), transactions(), deliveries, &originals, &admissions, &native, &retention, policy, &timestamp()?))?;
                            self.terminal.message("One exact dispatch attempt returned a durable report. This is not confirmation or finality; keep exposure and use observe for the same operation.\n")?;
                            Ok(serde_json::to_value(report)?)
                        }
                        _ => Err(Error::Invalid),
                    }
                };
                run().map_err(native_failure)
            })
        })?;
        self.terminal.json(&result)
    }
}

#[cfg(test)]
mod early_roster_tests {
    use super::*;
    use std::cell::Cell;

    // Public synthetic terms only, using the existing engine fixture. No key,
    // signer peer, native permission or financial admission is constructed.
    fn fixture() -> (wholepact_engine::CandidateView, Vec<SignatureSource>) {
        let request: wholepact_engine::CandidateRequest = serde_json::from_str(include_str!(
            "../../../../wholepact-engine/tests/fixtures/candidate-request.json"
        ))
        .unwrap();
        let proposal = wholepact_core::Proposal::validate(wholepact_core::ProposalInput {
            proposal_id: "synthetic-early-roster".into(),
            previous_proposal_id: None,
            manifest: request.manifest,
            artifact_digest: None,
            effects_commitment: None,
            created_at: "2026-10-14T00:00:00Z".into(),
        })
        .unwrap();
        let candidate = wholepact_engine::CandidateView {
            candidate_id: proposal.input().proposal_id.clone(),
            proposal: proposal.input().clone(),
            manifest_digest: proposal.manifest_digest().into(),
            proposal_digest: proposal.proposal_digest().into(),
            accounting: serde_json::to_value(proposal.accounting()).unwrap(),
            reviews: vec![],
            proof_jobs: vec![],
        };
        let sources = candidate
            .proposal
            .manifest
            .participants
            .iter()
            .enumerate()
            .map(|(index, p)| SignatureSource {
                signer_socket: PathBuf::from(format!("/synthetic-unused/signer-{index}.sock")),
                history: HistoryRequest {
                    authorization_id: format!("synthetic-original-{index}"),
                    expected_original_consent_ref: "a".repeat(64),
                    expected_enrollment_ref: "b".repeat(64),
                    expected_manifest_ref: "c".repeat(64),
                },
                redelivery_operation_id: format!("synthetic-redelivery-{index}"),
                context: MessageContext {
                    network_profile_id: candidate
                        .proposal
                        .manifest
                        .agreement
                        .network_profile_id
                        .clone(),
                    agreement_id: candidate.proposal.manifest.agreement.agreement_id.clone(),
                    proposal_id: candidate.candidate_id.clone(),
                    proposal_revision: u64::from(candidate.proposal.manifest.agreement.revision),
                    sender_id: p.participant_id.clone(),
                    recipient_id: "synthetic-organizer".into(),
                    artifact_kind: wholepact_transport::ArtifactKind::Authorization,
                },
                envelope_path: None,
                retained_sequence: Some(1),
            })
            .collect();
        (candidate, sources)
    }

    #[test]
    fn malformed_later_participant_never_reaches_pairing_callback() {
        // Each case leaves the first participant syntactically valid. A loop
        // that paired while validating would invoke its callback too early.
        for change in 0..9 {
            let (candidate, mut sources) = fixture();
            assert!(sources.len() >= 2);
            let second = &mut sources[1];
            match change {
                0 => second.context.network_profile_id = "wrong-network".into(),
                1 => second.context.proposal_revision += 1,
                2 => second.history.expected_original_consent_ref = "unmapped".into(),
                3 => second.signer_socket = PathBuf::from("relative.sock"),
                4 => second.envelope_path = Some(PathBuf::from("/synthetic-unused/envelope")),
                5 => second.history.authorization_id = "invalid label".into(),
                6 => second.retained_sequence = Some(0),
                7 => {
                    second.retained_sequence = None;
                    second.envelope_path = Some(PathBuf::from("relative-envelope"));
                }
                _ => second.context.sender_id = "unknown-participant".into(),
            }
            let callbacks = Cell::new(0);
            let result: Result<()> = after_signature_roster_preflight(&candidate, &sources, |_| {
                callbacks.set(callbacks.get() + 1);
                // Even if invoked, this fixture never pretends to pair a signer.
                Err(Error::Permission)
            });
            assert!(matches!(result, Err(Error::Invalid)));
            assert_eq!(callbacks.get(), 0);
        }
    }

    #[test]
    fn duplicate_later_owner_rejects_before_pairing_callback() {
        let (candidate, mut sources) = fixture();
        sources[1].context.sender_id = sources[0].context.sender_id.clone();
        let callbacks = Cell::new(0);
        let result: Result<()> = after_signature_roster_preflight(&candidate, &sources, |_| {
            callbacks.set(callbacks.get() + 1);
            Err(Error::Permission)
        });
        assert!(matches!(result, Err(Error::Invalid)));
        assert_eq!(callbacks.get(), 0);
    }

    #[test]
    fn valid_metadata_only_reaches_next_boundary_without_granting_authority() {
        let (candidate, sources) = fixture();
        let callbacks = Cell::new(0);
        let result: Result<()> =
            after_signature_roster_preflight(&candidate, &sources, |accounts| {
                callbacks.set(callbacks.get() + 1);
                assert_eq!(accounts.len(), sources.len());
                Err(Error::Permission)
            });
        assert!(matches!(result, Err(Error::Permission)));
        assert_eq!(callbacks.get(), 1);
    }
}

#[cfg(test)]
mod settlement_result_tests {
    use super::*;
    #[test]
    fn settlement_owner_failure_is_not_a_successful_serialized_result() {
        let failure =
            wholepact_engine::ApiError::new("ORIGINAL_RESULT_UNKNOWN", "Synthetic absent original");
        assert!(settlement_observation_value::<serde_json::Value>(Err(failure)).is_err());
        let metadata = serde_json::json!({"outcome_status":"historical_result_recorded"});
        assert_eq!(
            settlement_observation_value(Ok(metadata.clone())).unwrap(),
            metadata
        );
    }
}
