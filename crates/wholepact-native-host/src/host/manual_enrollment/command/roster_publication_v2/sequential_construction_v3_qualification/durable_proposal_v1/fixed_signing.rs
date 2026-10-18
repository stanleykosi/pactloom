//! Ignored Linux synthetic qualification follow-on; never run locally.
//!
//! Every command drives the existing runtime, never a manufactured decision,
//! permit, wallet ticket, account association or signing source. Original history
//! serving prepares only the current native imported source. Only the separate
//! genuine focused witness admission and original-owner mTLS may commit this
//! NEW financial record; its narrow committed server is reopened afterward.
//! No copied scope, generic journal or widened old bootstrap allowlist is used.
//! The caller lends the exact retained preproof originals after all prior owners
//! close, while its actual witness/provider/temp custody remains alive. No proof
//! is constructed here. Host privacy gates and the chain remain synthetic; this
//! is not OS-process restart, consensus, submission or attended-GUI evidence.

use super::safe_diagnostics_v1::{self as diagnostic, Boundary as B, Outcome};
use super::worker::{JoinedSignerCommandV1 as Command, JoinedSignerReplyV1 as Reply};
use super::*;
use sha2::{Digest, Sha256};
use std::{
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use wholepact_core::{Proposal, ProposalInput};
use wholepact_engine::durable_construction_v1::{
    LocalDurableMaterialConsentV1,
    review_export_v1::{
        DurableReviewExportScopeV1, DurableReviewSourceV1, LocalDurableReviewExportConsentV1,
    },
};
use wholepact_engine::signature_intake::{
    AuthenticatedSignatureDelivery, LocalSignedRetention,
    authority_bridge::with_signer_account_association_checked,
};
use wholepact_engine::{Access, Engine, proof_jobs::LocalProofJob};
use wholepact_proof_jobs::{LocalProofConsent, ProofJobStore, VerifiedCheckpoint};
use wholepact_protocol::{
    authorization::retention::{
        SignedResultJournal, SignedRetentionConsent, SignedRetentionScope,
        transaction::{
            LocalTransactionCheckpoint, TransactionCheckpointJournal, TransactionRetentionConsent,
            TransactionRetentionScope,
        },
    },
    durable_proposal_v1::FixedProposalIdentityV1,
};
use wholepact_signer::authority_bridge::{
    AuthorizationCommit,
    durable_construction_v1::{
        DurableConstructionHistoryRequestV1, DurableConstructionRedisclosureRequestV1,
        DurableConstructionRedisclosureSourceV1,
    },
    durable_review_ipc_v1::{DurableReviewDeliveryRequestV1, DurableReviewRecipientV1},
    ipc::{HistoryRequest, OriginalHistoryClient},
};
use wholepact_storage_security::{DatabaseKey, create_encrypted};
use wholepact_transport as transport;
use wholepact_wallet::wallet::protected_sync::{BackendIdentity, TreeState};

/// Borrowed custody, not a serialized continuation or an authority factory.
/// The eventual separate preproof wrapper supplies these actual originals at
/// its final pre-provider-shutdown boundary. The baseline wrapper stays unchanged.
pub(super) struct FixedSigningInputsV1<'a> {
    pub original: &'a mut initial::DurableInitialV1,
    pub engine: &'a Engine,
    pub jobs: &'a ProofJobStore,
    pub access: &'a Access,
    pub candidate_id: &'a str,
    pub proposal: &'a ProposalInput,
    pub identity: &'a FixedProposalIdentityV1,
    pub job_id: &'a str,
    pub proof_consent: &'a dyn LocalProofConsent,
    pub material_consent: &'a dyn LocalDurableMaterialConsentV1,
    pub original_disclosures: &'a [DurableConstructionHistoryRequestV1],
    pub export_sources: &'a [DurableReviewSourceV1],
    pub birthday: &'a TreeState,
    pub source: &'a BackendIdentity,
    pub protected_root: &'a Path,
    pub revision: u64,
}

// Synthetic relay/serialization errors stay coarse, but never masquerade as
// native authentication evidence. The active finite boundary reports them.
fn invalid<T>(_: T) -> Error {
    Error::Invalid
}
/// Local diagnostic state only: it never polls, contacts a peer or changes a
/// lifetime. A pending phase is reported at the failing call, before result-service
/// cleanup, so cancellation cannot conceal the first Host-side failure.
struct HostTrace {
    active: Option<B>,
}
impl HostTrace {
    fn new() -> Self {
        Self { active: None }
    }
    fn begin(&mut self, boundary: B) {
        self.complete();
        diagnostic::emit(boundary, Outcome::Begin);
        self.active = Some(boundary);
    }
    fn complete(&mut self) {
        if let Some(boundary) = self.active.take() {
            diagnostic::emit(boundary, Outcome::Complete);
        }
    }
    fn refused(&mut self, outcome: Outcome) -> Error {
        if let Some(boundary) = self.active.take() {
            diagnostic::emit(boundary, outcome);
        }
        Error::Invalid
    }
    fn check(&mut self, condition: bool) -> Result<()> {
        if condition {
            Ok(())
        } else {
            Err(self.refused(Outcome::HostInvalid))
        }
    }
    fn worker(&mut self, _: &'static str) -> Error {
        self.refused(Outcome::WorkerFailure)
    }
    fn storage<T>(&mut self, _: T) -> Error {
        self.refused(Outcome::HostStorage);
        Error::Storage
    }
    fn host(&mut self, error: Error) -> Error {
        let outcome = match &error {
            Error::Platform => Outcome::HostPlatform,
            Error::Terminal => Outcome::HostTerminal,
            Error::Permission => Outcome::HostPermission,
            Error::Locked => Outcome::HostLocked,
            Error::Invalid => Outcome::HostInvalid,
            Error::Authentication => Outcome::HostAuthentication,
            Error::Storage => Outcome::HostStorage,
            Error::Quarantined => Outcome::HostQuarantined,
            Error::Unsupported => Outcome::HostUnsupported,
            Error::Receipt(_) => Outcome::HostReceipt,
            Error::RecoverySemantic(_) => Outcome::HostRecoverySemantic,
            Error::RecoveryBackupUnsupported => Outcome::HostRecoveryBackupUnsupported,
            Error::RecoveryFinancialUnsupported => Outcome::HostRecoveryFinancialUnsupported,
            Error::CompleteOriginRecoveryUnavailable => {
                Outcome::HostCompleteOriginRecoveryUnavailable
            }
            Error::HistoricalExportIncomplete => Outcome::HostHistoricalExportIncomplete,
            Error::GenerationArchiveIncomplete => Outcome::HostGenerationArchiveIncomplete,
        };
        self.refused(outcome);
        error
    }
    fn job(&mut self, error: wholepact_proof_jobs::JobError) -> Error {
        use wholepact_proof_jobs::JobError as E;
        let outcome = match error {
            E::ConsentDenied => Outcome::JobConsentDenied,
            E::NotFound => Outcome::JobNotFound,
            E::InvalidRequest => Outcome::JobInvalidRequest,
            E::VerificationFailed => Outcome::JobVerificationFailed,
            E::IdempotencyConflict => Outcome::JobIdempotencyConflict,
            E::RecoveryRequired => Outcome::JobRecoveryRequired,
            E::StateConflict => Outcome::JobStateConflict,
            E::Storage => Outcome::JobStorage,
            E::UnsupportedSchema => Outcome::JobUnsupportedSchema,
            E::ResourceExhausted => Outcome::JobResourceExhausted,
        };
        self.refused(outcome)
    }
    fn bridge(&mut self, error: wholepact_signer::authority_bridge::BridgeError) -> Error {
        use wholepact_signer::authority_bridge::BridgeError as E;
        let outcome = match error {
            E::Binding => Outcome::BridgeBinding,
            E::Conflict => Outcome::BridgeConflict,
            E::Missing => Outcome::BridgeMissing,
            E::Uncertain => Outcome::BridgeUncertain,
            E::Limit => Outcome::BridgeLimit,
            E::Permission => Outcome::BridgePermission,
            E::RecoveryRequired => Outcome::BridgeRecoveryRequired,
            E::CompleteOriginRecoveryUnavailable => {
                Outcome::BridgeCompleteOriginRecoveryUnavailable
            }
            E::Verification => Outcome::BridgeVerification,
            E::SignerOriginUnavailable => Outcome::BridgeSignerOriginUnavailable,
            E::Journal(_) => Outcome::BridgeJournal,
            E::Authority(_) => Outcome::BridgeAuthority,
            E::Wallet(_) => Outcome::BridgeWallet,
            E::Ipc => Outcome::BridgeIpc,
        };
        self.refused(outcome)
    }
    fn authority(&mut self, error: wholepact_authority::AuthorityError) -> Error {
        self.refused(diagnostic::authority_error(&error))
    }
    fn engine(&mut self, error: wholepact_engine::ApiError) -> Error {
        // Only exact maintained codes select output; private explanatory text,
        // operation IDs and structured details are deliberately never formatted.
        let outcome = match error.code.as_str() {
            "MANUAL_CONSTRUCTION_DENIED" => Outcome::EngineManualConstructionDenied,
            "RETAINED_INPUT_OBSERVATION_UNAVAILABLE" => {
                Outcome::EngineRetainedObservationUnavailable
            }
            "CANDIDATE_VERIFICATION_FAILED" => Outcome::EngineCandidateVerificationFailed,
            "IDEMPOTENCY_CONFLICT" => Outcome::EngineIdempotencyConflict,
            "REVISION_CONFLICT" => Outcome::EngineRevisionConflict,
            "NOT_FOUND" => Outcome::EngineNotFound,
            "INVALID_REQUEST" => Outcome::EngineInvalidRequest,
            "RECOVERY_REQUIRED" => Outcome::EngineRecoveryRequired,
            "LIVE_AUTHORIZATION_EXISTS" => Outcome::EngineLiveAuthorizationExists,
            "RESOURCE_EXHAUSTED" => Outcome::EngineResourceExhausted,
            "INVALID_TRANSITION" => Outcome::EngineInvalidTransition,
            "STORAGE_PROTECTION_REQUIRED" => Outcome::EngineStorageProtectionRequired,
            "STORAGE_UNAVAILABLE" => Outcome::EngineStorageUnavailable,
            "ACCESS_DENIED" => Outcome::EngineAccessDenied,
            _ => Outcome::EngineUnclassified,
        };
        self.refused(outcome)
    }
}
impl Drop for HostTrace {
    fn drop(&mut self) {
        // Panic/unclassified fallback only, never authentication-root-cause
        // evidence. Every ordinary fallible call reports before cleanup, and
        // taking active prevents overwriting an already emitted first failure.
        if let Some(boundary) = self.active.take() {
            diagnostic::emit(boundary, Outcome::WorkerFailure);
        }
    }
}
fn now() -> Result<transport::Timestamp> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(invalid)?
        .as_secs();
    transport::Timestamp::from_unix_seconds(seconds.try_into().map_err(invalid)?).map_err(invalid)
}
fn done(worker: &worker::JoinedSignerWorkerV1, index: usize, trace: &mut HostTrace) -> Result<()> {
    match worker.receive().map_err(|error| trace.worker(error))? {
        Reply::Done { index: actual } if actual == index => Ok(()),
        _ => Err(trace.refused(Outcome::HostInvalid)),
    }
}

/// Exact local private-retention gates only. These cannot mint native consent,
/// signer provenance, account control or an independent witness permit.
struct ExactRetention<'a> {
    fixed: &'a FixedProposalIdentityV1,
    checkpoint: &'a VerifiedCheckpoint,
}
impl SignedRetentionConsent for ExactRetention<'_> {
    fn permits(&self, value: &SignedRetentionScope) -> bool {
        let scope = self.checkpoint.scope();
        let context = &value.context;
        context.principal_id == scope.principal_id
            && context.candidate_id == self.fixed.proposal_id
            && context.proof_job_id == self.checkpoint.summary().job_id
            && context.checkpoint_scope_digest == self.checkpoint.summary().scope_digest
            && context.proved_artifact_digest == self.fixed.proved_artifact_digest
            && context.manifest_digest == self.fixed.manifest_digest
            && context.review_binding == self.fixed.review_binding
            && context.account_ids == scope.account_ids
            && context.local_operator == scope.local_operator
            && context.purpose == scope.purpose
            && context.retention_policy == scope.retention_policy
            && canonical_hash(&context.delivery_provenance_digest)
            && canonical_hash(&value.signature_set_digest)
    }
}
impl TransactionRetentionConsent for ExactRetention<'_> {
    fn permits(&self, scope: &TransactionRetentionScope) -> bool {
        SignedRetentionConsent::permits(self, &scope.signed_scope)
            && scope
                .signed_result_id
                .strip_prefix("signed-")
                .is_some_and(canonical_hash)
            && canonical_hash(&scope.signed_request_digest)
            && canonical_hash(&scope.signed_candidate_digest)
    }
}
fn canonical_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

struct ExactExport<'a> {
    principal: &'a str,
    fixed: &'a FixedProposalIdentityV1,
    recipient: DurableReviewRecipientV1,
    sources: &'a [DurableReviewSourceV1],
}
impl LocalDurableReviewExportConsentV1 for ExactExport<'_> {
    fn permits(&self, scope: &DurableReviewExportScopeV1) -> bool {
        scope.schema_version == 1 && scope.principal_id == self.principal
            && &scope.proposal == self.fixed && scope.recipient == self.recipient
            && scope.sources == self.sources && canonical_hash(&scope.payload_digest)
            && scope.payload_length > 0
            && scope.payload_length <= wholepact_signer::authority_bridge::durable_review_ipc_v1::MAX_DURABLE_REVIEW_PAYLOAD_BYTES_V1 as u64
    }
}

/// The flag ends nonapproving fixture polling only. It neither grants access,
/// revokes an admitted result nor extends the actual native owner's deadline.
struct ResultService<'a> {
    worker: &'a worker::JoinedSignerWorkerV1,
    index: usize,
    stop: Arc<AtomicBool>,
}
impl<'a> ResultService<'a> {
    fn start(
        worker: &'a worker::JoinedSignerWorkerV1,
        index: usize,
        trace: &mut HostTrace,
    ) -> Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        worker
            .send(Command::ServeDurableResult(index, stop.clone()))
            .map_err(|error| trace.worker(error))?;
        Ok(Self {
            worker,
            index,
            stop,
        })
    }
    fn finish(self, trace: &mut HostTrace) -> Result<()> {
        self.stop.store(true, Ordering::Release);
        done(self.worker, self.index, trace)
    }
}
impl Drop for ResultService<'_> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

fn signature_metadata(
    worker: &worker::JoinedSignerWorkerV1,
    index: usize,
    trace: &mut HostTrace,
) -> Result<(HistoryRequest, AuthorizationCommit)> {
    match worker.receive().map_err(|error| trace.worker(error))? {
        Reply::DurableAuthorization {
            index: actual,
            history,
            commit,
        } if actual == index => {
            trace.check(
                history.authorization_id == commit.authorization_id
                    && history.expected_original_consent_ref == commit.original_consent_ref
                    && commit.exposure_remains_uncertain
                    && canonical_hash(&commit.result_digest)
                    && canonical_hash(&commit.outbox_digest),
            )?;
            Ok((history, commit))
        }
        _ => Err(trace.refused(Outcome::HostInvalid)),
    }
}

fn viewing_setup(input: &FixedSigningInputsV1<'_>) -> Result<String> {
    serde_json::to_string(&serde_json::json!({
        "schema_version": 1,
        "purpose": "fresh_born_ephemeral_viewing_wallet_v1",
        "retention": "current_native_owner_only",
        "maximum_blocks": 16,
        "policy": {
            "confidence": "trusted_single_provider_snapshot",
            "source_id": input.source.source_id,
            "endpoint": input.source.endpoint,
            "maximum_observation_age_seconds": 300,
            "minimum_confirmations": 1,
            "minimum_expiry_margin_blocks": 1
        },
        "birthday": {
            "prior_height": u32::try_from(input.birthday.height).map_err(invalid)?,
            "prior_block_hash": input.birthday.hash,
            "sapling_tree": input.birthday.sapling_tree,
            "orchard_tree": input.birthday.orchard_tree,
            "ironwood_tree": input.birthday.ironwood_tree
        }
    }))
    .map_err(invalid)
}

fn accept_records(
    worker: &worker::JoinedSignerWorkerV1,
    index: usize,
    trace: &mut HostTrace,
) -> Result<wholepact_signer::native_ui::synthetic_born_joined_qualification::DurableNativeRecordsV1>
{
    trace.begin(B::DurableHostAccept);
    worker
        .send(Command::AcceptDurable(index))
        .map_err(|error| trace.worker(error))?;
    match worker.receive().map_err(|error| trace.worker(error))? {
        Reply::Records {
            index: actual,
            records,
        } if actual == index => Ok(records),
        _ => Err(trace.refused(Outcome::HostInvalid)),
    }
}

/// Reuse exact original proof bytes, but never reuse old local permission. The
/// two distinct purposes keep pre-admission and post-reconciliation imports and
/// linked disclosures immutable and separately identified.
fn redisclose_and_import(
    input: &FixedSigningInputsV1<'_>,
    client: &OriginalHistoryClient,
    index: usize,
    records: &wholepact_signer::native_ui::synthetic_born_joined_qualification::DurableNativeRecordsV1,
    financial: bool,
    revision: u64,
    trace: &mut HostTrace,
) -> Result<u64> {
    let worker = &input.original.signers;
    let purpose = if financial { "signing" } else { "admission" };
    trace.begin(B::DurableHostRedisclosure);
    let original = &input.original_disclosures[index - 1];
    let renewed = DurableConstructionRedisclosureRequestV1 {
        operation_id: format!("durable-fixed-{purpose}-disclosure-{index}"),
        original: DurableConstructionRedisclosureSourceV1 {
            operation_id: original.operation_id.clone(),
            expected_request_digest: Some(original.expected_request_digest.clone()),
        },
        enrollment_ref: records.enrollment_ref.clone(),
        accepted_manifest_ref: records.accepted_manifest_ref.clone(),
    };
    worker
        .send(Command::ArmRedisclosure(index, renewed.clone()))
        .map_err(|error| trace.worker(error))?;
    done(worker, index, trace)?;
    worker
        .send(Command::PollDisclosure(index))
        .map_err(|error| trace.worker(error))?;
    let current = client
        .redisclose_durable_construction_v1(&renewed)
        .map_err(|error| trace.bridge(error))?;
    done(worker, index, trace)?;
    let link = current
        .outbox()
        .redisclosure()
        .ok_or_else(|| trace.refused(Outcome::HostInvalid))?;
    trace.check(
        link.original_operation_id == original.operation_id
            && link.original_request_digest == original.expected_request_digest,
    )?;
    let current_disclosure = DurableConstructionHistoryRequestV1 {
        operation_id: current.outbox().request().operation_id.clone(),
        expected_request_digest: current.outbox().request_digest().into(),
    };
    drop(current);
    let request = DurableReviewDeliveryRequestV1 {
        operation_id: format!("durable-fixed-{purpose}-import-{index}"),
        enrollment_ref: records.enrollment_ref.clone(),
        accepted_manifest_ref: records.accepted_manifest_ref.clone(),
        own_disclosure: original.clone(),
        current_disclosure: Some(current_disclosure),
        proposal_binding: input.identity.proposal_binding.clone(),
    };
    trace.begin(B::DurableHostReviewReady);
    let command = if financial {
        Command::PollFinancialImport(index, request.clone(), input.identity.clone())
    } else {
        // This remains the unchanged import-only assertion: no writer receipt,
        // reconciliation, wallet/signing job or approval is created by import.
        Command::PollImport(index, request.clone(), input.identity.clone())
    };
    worker.send(command).map_err(|error| trace.worker(error))?;
    let recipient = client
        .prepare_durable_review_delivery_v1(&request)
        .map_err(|error| trace.bridge(error))?;
    let export_gate = ExactExport {
        principal: &input.access.principal_id,
        fixed: input.identity,
        recipient: recipient.descriptor().clone(),
        sources: input.export_sources,
    };
    trace.begin(B::DurableHostReviewExport);
    let delivered = input
        .engine
        .deliver_durable_proposal_for_native_review_v1(
            input.access,
            &format!("durable-fixed-{purpose}-export-{index}"),
            input.candidate_id,
            revision,
            LocalProofJob {
                job_id: input.job_id,
                jobs: input.jobs,
                consent: input.proof_consent,
            },
            recipient,
            input.material_consent,
            &export_gate,
        )
        .map_err(|error| trace.engine(error))?;
    trace.begin(B::DurableHostReviewImported);
    done(worker, index, trace)?;
    Ok(delivered.agreement.revision)
}

fn wall_clock_ms() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(invalid)?
        .as_millis()
        .try_into()
        .map_err(invalid)
}

/// Only wait for the actual original publication fence before opening a fresh
/// native owner. No clock is changed, no human gap or expired-owner continuation
/// is claimed, and the enclosing unchanged child timeout remains authoritative.
fn wait_original_publication(deadline_ms: u64, trace: &mut HostTrace) -> Result<()> {
    let at = wall_clock_ms().map_err(|error| trace.host(error))?;
    if at < deadline_ms {
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(deadline_ms - at))
            .ok_or_else(|| trace.refused(Outcome::HostInvalid))?;
        while Instant::now() < deadline {
            std::thread::sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(20)),
            );
        }
    }
    let after = wall_clock_ms().map_err(|error| trace.host(error))?;
    trace.check(after >= deadline_ms)
}

/// The envelope is only an explicitly synthetic local relay of exact bytes
/// retrieved from the original native outbox. It NEVER creates the account
/// association: that comes exclusively from the real held native history lease.
fn receive_exact_result(
    input: &FixedSigningInputsV1<'_>,
    payload: &[u8],
    owner: usize,
    ledger: &mut transport::SqliteReplayLedger,
    at: &transport::Timestamp,
) -> Result<transport::ReceivedArtifact> {
    let sender = transport::TransportSecret::from_bytes([234; 32]).map_err(invalid)?;
    let recipient = transport::TransportSecret::from_bytes([235; 32]).map_err(invalid)?;
    let context = transport::MessageContext {
        network_profile_id: input.identity.network_profile_id.clone(),
        agreement_id: input.identity.agreement_id.clone(),
        proposal_id: input.identity.proposal_id.clone(),
        proposal_revision: input.identity.revision.into(),
        sender_id: format!("synthetic-native-fixed-result-relay-{owner}"),
        recipient_id: input.access.principal_id.clone(),
        artifact_kind: transport::ArtifactKind::Authorization,
    };
    let prepared = transport::prepare_export(
        transport::ExportRequest {
            context: context.clone(),
            order: transport::MessageOrder {
                message_id: transport::random_message_id().map_err(invalid)?, sequence: 1,
                issued_at: at.clone(),
                expires_at: transport::Timestamp::from_unix_seconds(at.unix_seconds().checked_add(60).ok_or(Error::Invalid)?).map_err(invalid)?,
            },
            purpose: "Exact original native signature intake for the immutable synthetic proposal".into(),
            persistence_warning: "Usable signatures remain private in the original encrypted journals; exposure is not cleared".into(),
        },
        vec![transport::DisclosureField::new("external_spend_signatures_v1", payload.to_vec()).map_err(invalid)?],
        &sender.public_key().map_err(invalid)?, &recipient.public_key().map_err(invalid)?, at,
    ).map_err(invalid)?;
    let digest = prepared.preview().digest().map_err(invalid)?;
    let sealed = prepared.seal(&sender, &digest, at).map_err(invalid)?;
    transport::open_envelope(
        &sealed,
        &recipient,
        &sender.public_key().map_err(invalid)?,
        &context,
        at,
        ledger,
    )
    .map_err(invalid)
}

pub(super) fn exercise(input: FixedSigningInputsV1<'_>) -> Result<()> {
    let mut trace = HostTrace::new();
    trace.begin(B::MetadataCheck);
    trace.check(
        input.original_disclosures.len() == 2
            && input.export_sources.len() == 2
            && input.proposal.manifest.participants.len() == 2
            && input.identity.proposal_id == input.candidate_id,
    )?;
    let proposal = Proposal::validate(input.proposal.clone())
        .map_err(|_| trace.refused(Outcome::HostInvalid))?;
    let manifest = proposal.manifest();
    trace.check(
        input.identity.schema_version == 1
            && proposal.input().proposal_id == input.identity.proposal_id
            && proposal.proposal_digest() == input.identity.proposal_digest
            && proposal.manifest_digest() == input.identity.manifest_digest
            && manifest.agreement.network_profile_id == input.identity.network_profile_id
            && manifest.agreement.agreement_id == input.identity.agreement_id
            && manifest.agreement.obligation_id == input.identity.obligation_id
            && manifest.agreement.revision == input.identity.revision
            && manifest.expiry_height == input.identity.expiry_height
            && manifest
                .participants
                .iter()
                .zip(&input.original.born[1..])
                .all(|(participant, born)| {
                    participant.account_id == born.account_id
                        && participant.participant_id == born.participant_id
                })
            && input.original.born[1..]
                .iter()
                .enumerate()
                .all(|(i, born)| {
                    input.export_sources.iter().any(|source| {
                        born.account_id == source.account_id
                            && source.request_digest
                                == input.original_disclosures[i].expected_request_digest
                    })
                })
            && input.export_sources[0].account_id != input.export_sources[1].account_id,
    )?;
    // Exact original temporary custody, not a caller-selected existing directory
    // or symlink alias. All new private journals remain under the real parent's
    // retained fixture root; no vault or funded-wallet path is accepted.
    let expected_root = input
        .original
        .temporary
        .path()
        .join("durable-original-engine");
    trace.check(input.protected_root == expected_root)?;
    let original_root = std::fs::canonicalize(input.original.temporary.path())
        .map_err(|error| trace.storage(error))?;
    let protected_metadata =
        std::fs::symlink_metadata(input.protected_root).map_err(|error| trace.storage(error))?;
    trace.check(
        protected_metadata.file_type().is_dir()
            && protected_metadata.permissions().mode() & 0o077 == 0,
    )?;
    let protected_root =
        std::fs::canonicalize(input.protected_root).map_err(|error| trace.storage(error))?;
    trace.check(protected_root == original_root.join("durable-original-engine"))?;
    trace.begin(B::DurableHostReload);
    let local = || LocalProofJob {
        job_id: input.job_id,
        jobs: input.jobs,
        consent: input.proof_consent,
    };
    let checkpoint = input
        .jobs
        .load_verified(
            &input.access.principal_id,
            input.job_id,
            input.proof_consent,
        )
        .map_err(|error| trace.job(error))?;
    let fixed = input
        .engine
        .load_durable_proposal_for_local_review_v1(input.access, input.candidate_id, local())
        .map_err(|error| trace.engine(error))?;
    trace.check(fixed.identity() == input.identity)?;
    let retention_gate = ExactRetention {
        fixed: input.identity,
        checkpoint: &checkpoint,
    };
    trace.begin(B::DurableHostCheckpoint);
    let directory = protected_root.join("native-fixed-signing");
    std::fs::create_dir(&directory).map_err(|error| trace.storage(error))?;
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| trace.storage(error))?;
    let signed = SignedResultJournal::from_encrypted_connection(
        create_encrypted(
            directory.join("signed.sqlite3"),
            &DatabaseKey::from_bytes([231; 32]),
        )
        .map_err(|error| trace.storage(error))?,
    )
    .map_err(|error| trace.storage(error))?;
    let transactions = TransactionCheckpointJournal::from_encrypted_connection(
        create_encrypted(
            directory.join("transactions.sqlite3"),
            &DatabaseKey::from_bytes([232; 32]),
        )
        .map_err(|error| trace.storage(error))?,
    )
    .map_err(|error| trace.storage(error))?;
    let mut ledger = transport::SqliteReplayLedger::from_encrypted_connection(
        create_encrypted(
            directory.join("inbox.sqlite3"),
            &DatabaseKey::from_bytes([233; 32]),
        )
        .map_err(|error| trace.storage(error))?,
    )
    .map_err(|error| trace.storage(error))?;
    let retention = || LocalSignedRetention {
        journal: &signed,
        consent: &retention_gate,
    };
    let transaction = || LocalTransactionCheckpoint {
        journal: &transactions,
        consent: &retention_gate,
    };
    let worker = &input.original.signers;
    let mut revision = input.revision;
    for index in 1..=2 {
        trace.begin(B::DurableHostWitnessSetup);
        let account_id = &input.original.born[index].account_id;
        let bootstrap = input
            .original
            .witness
            .observe_original_roster_attempt_v2(account_id)
            .map_err(|error| trace.authority(error))?;
        trace.check(
            bootstrap.attempt.sequence == 1
                && bootstrap.attempt.continuation.is_none()
                && bootstrap.attempt.snapshot.head.sequence == 4
                && bootstrap
                    .extension
                    .account_extension
                    .terms
                    .identity
                    .account_id
                    == *account_id,
        )?;
        let publication_deadline = bootstrap
            .attempt
            .last_publication_deadline_ms()
            .ok_or_else(|| trace.refused(Outcome::HostInvalid))?;
        trace.check(publication_deadline <= input.original.expiry_ms)?;
        wait_original_publication(publication_deadline, &mut trace)?;
        // Informational serving cannot admit this financial record. It exists
        // only while the signer derives its exact request from complete history.
        let history_server = input
            .original
            .witness
            .serve_original_history()
            .map_err(|error| trace.authority(error))?;
        trace.begin(B::DurableHostOpen);
        worker
            .send(Command::OpenDurable(index, input.proposal.clone()))
            .map_err(|error| trace.worker(error))?;
        let (peer, scope) = match worker.receive().map_err(|error| trace.worker(error))? {
            Reply::DurablePeer {
                index: actual,
                peer,
                scope,
                ..
            } if actual == index => (peer, scope),
            _ => return Err(trace.refused(Outcome::HostInvalid)),
        };
        trace.begin(B::DurableHostPairStatus);
        worker
            .send(Command::PollDurablePair(index))
            .map_err(|error| trace.worker(error))?;
        let client = OriginalHistoryClient::pair(
            peer.provider,
            &peer.endpoint,
            "Synthetic-fixed-proposal-signer",
            scope,
        )
        .map_err(|error| trace.bridge(error))?;
        trace.begin(B::DurableHostPairObserved);
        done(worker, index, &mut trace)?;
        trace.begin(B::DurableHostWitnessSetup);
        worker
            .send(Command::ConfigureDurableWitness(index))
            .map_err(|error| trace.worker(error))?;
        done(worker, index, &mut trace)?;
        let admission_records = accept_records(worker, index, &mut trace)?;
        revision = redisclose_and_import(
            &input,
            &client,
            index,
            &admission_records,
            false,
            revision,
            &mut trace,
        )?;
        trace.begin(B::DurableHostWitnessSetup);
        worker
            .send(Command::PrepareDurableAdmission(index))
            .map_err(|error| trace.worker(error))?;
        let admission = match worker.receive().map_err(|error| trace.worker(error))? {
            Reply::DurableAdmissionRequest {
                index: actual,
                request,
            } if actual == index => request,
            _ => return Err(trace.refused(Outcome::HostInvalid)),
        };
        let wholepact_authority::OwnerControl::AdmitDurablePaymentV1 { record } =
            &admission.control
        else {
            return Err(trace.refused(Outcome::HostInvalid));
        };
        let actual_fixed = serde_json::to_value(&record.terms.fixed)
            .map_err(|_| trace.refused(Outcome::HostInvalid))?;
        let expected_fixed = serde_json::to_value(input.identity)
            .map_err(|_| trace.refused(Outcome::HostInvalid))?;
        let extension_digest = bootstrap
            .extension
            .digest()
            .map_err(|error| trace.authority(error))?;
        trace.check(
            admission.account_id == *account_id
                && admission.network_profile_id == input.identity.network_profile_id
                && admission.expected_head == bootstrap.attempt.snapshot.head
                && admission.writer_epoch == bootstrap.attempt.snapshot.writer_epoch
                && record.terms.original_roster_extension_digest == extension_digest
                && record.terms.original_enrollment_ref
                    == bootstrap.extension.account_extension.enrollment_ref
                && actual_fixed == expected_fixed,
        )?;
        // The SAME original endpoint must be unbound before production witness
        // preparation. Starting the focused final click does not drain yet:
        // its real admission worker waits for this signer's original-owner mTLS.
        drop(history_server);
        input
            .original
            .witness
            .start_exact_durable_payment_admission(account_id, &admission)
            .map_err(|error| trace.authority(error))?;
        worker
            .send(Command::ApproveDurableAdmission(index))
            .map_err(|error| trace.worker(error))?;
        input
            .original
            .witness
            .finish_exact_durable_payment_admission()
            .map_err(|error| trace.authority(error))?;
        // The helper observes the real immutable local intent and committed
        // correlation. Its production approval retains intent BEFORE mTLS.
        done(worker, index, &mut trace)?;
        let financial_server = input
            .original
            .witness
            .serve_committed_durable_payment(&admission.operation_id)
            .map_err(|error| trace.authority(error))?;
        trace.begin(B::DurableHostWriterReconcile);
        worker
            .send(Command::ReconcileDurableWriter(index))
            .map_err(|error| trace.worker(error))?;
        done(worker, index, &mut trace)?;
        // Actual reconciliation invalidates the old local permission/import.
        // Keep the same writer key/session, but require new native receipts.
        let records = accept_records(worker, index, &mut trace)?;
        trace.check(
            records.enrollment_ref != admission_records.enrollment_ref
                && records.accepted_manifest_ref != admission_records.accepted_manifest_ref,
        )?;
        trace.begin(B::DurableHostViewingSetup);
        worker
            .send(Command::ConfigureDurableWallet(
                index,
                viewing_setup(&input).map_err(|error| trace.host(error))?,
            ))
            .map_err(|error| trace.worker(error))?;
        done(worker, index, &mut trace)?;
        revision =
            redisclose_and_import(&input, &client, index, &records, true, revision, &mut trace)?;
        trace.begin(B::DurableHostSign);
        worker
            .send(Command::SignDurableFixed(index, input.identity.clone()))
            .map_err(|error| trace.worker(error))?;
        let (history, commit) = signature_metadata(worker, index, &mut trace)?;
        trace.check(
            history.expected_enrollment_ref == records.enrollment_ref
                && history.expected_manifest_ref == records.accepted_manifest_ref,
        )?;
        trace.begin(B::DurableHostSignRetry);
        // Exact retry must resolve the same retained original, not reserve a
        // replacement authorization ID or execute another wallet/key operation.
        // The genuine helper additionally asserts the production retained fast
        // path has no new review, wallet/signing job, reservation, intent or
        // other authority-ledger change. Metadata equality alone is insufficient.
        worker
            .send(Command::SignDurableFixed(index, input.identity.clone()))
            .map_err(|error| trace.worker(error))?;
        let (again_history, again) = signature_metadata(worker, index, &mut trace)?;
        trace.check(
            again_history == history
                && again.authorization_id == commit.authorization_id
                && again.original_consent_ref == commit.original_consent_ref
                && again.result_digest == commit.result_digest
                && again.outbox_digest == commit.outbox_digest,
        )?;
        trace.begin(B::DurableHostResultHistory);
        let service = ResultService::start(worker, index, &mut trace)?;
        let original_lease = client
            .acquire(&history)
            .map_err(|error| trace.bridge(error))?;
        trace.check(original_lease.result_is_for_current_recipient())?;
        original_lease
            .check_current()
            .map_err(|error| trace.bridge(error))?;
        let retained = original_lease
            .evidence()
            .retained_result
            .as_ref()
            .ok_or_else(|| trace.refused(Outcome::HostInvalid))?;
        trace.check(
            retained.authorization_id == commit.authorization_id
                && retained.original_consent_ref == commit.original_consent_ref
                && retained.result_digest == commit.result_digest
                && retained.outbox_digest == commit.outbox_digest,
        )?;
        trace.begin(B::DurableHostResultRetrieve);
        let payload = client
            .retrieve_original_authorization(&history)
            .map_err(|error| trace.bridge(error))?;
        trace.check(hex::encode(Sha256::digest(payload.as_slice())) == commit.outbox_digest)?;
        let retry_payload = client
            .retrieve_original_authorization(&history)
            .map_err(|error| trace.bridge(error))?;
        trace.check(payload.as_slice() == retry_payload.as_slice())?;
        original_lease
            .check_current()
            .map_err(|error| trace.bridge(error))?;
        trace.begin(B::DurableHostResultRelay);
        let at = now().map_err(|error| trace.host(error))?;
        let artifact = receive_exact_result(&input, &payload, index, &mut ledger, &at)
            .map_err(|error| trace.host(error))?;
        trace.begin(B::DurableHostSignatureIntake);
        let before = revision;
        let intake_key = format!("durable-native-fixed-signature-{index}");
        let admitted = with_signer_account_association_checked(
            &client,
            &history,
            &artifact,
            |association, check| {
                check()?;
                let result = input.engine.intake_durable_signature_v1(
                    input.access,
                    &intake_key,
                    input.candidate_id,
                    before,
                    local(),
                    retention(),
                    AuthenticatedSignatureDelivery {
                        artifact: &artifact,
                        association: Some(association),
                    },
                    &at,
                )?;
                check()?;
                let replay = input.engine.intake_durable_signature_v1(
                    input.access,
                    &intake_key,
                    input.candidate_id,
                    before,
                    local(),
                    retention(),
                    AuthenticatedSignatureDelivery {
                        artifact: &artifact,
                        association: Some(association),
                    },
                    &at,
                )?;
                if !replay.replayed || replay.agreement.revision != result.agreement.revision {
                    return Err(wholepact_engine::ApiError::new(
                        "INVALID_REQUEST",
                        "Exact original signature intake replay differs",
                    ));
                }
                check()?;
                Ok(result)
            },
        )
        .map_err(|error| trace.engine(error))?;
        revision = admitted.agreement.revision;
        original_lease
            .check_current()
            .map_err(|error| trace.bridge(error))?;
        drop(original_lease);
        drop(artifact);
        drop(retry_payload);
        drop(payload);
        trace.begin(B::DurableHostResultServiceStop);
        service.finish(&mut trace)?;
        drop(client);
        trace.begin(B::DurableHostClose);
        worker
            .send(Command::CloseDurable(index))
            .map_err(|error| trace.worker(error))?;
        done(worker, index, &mut trace)?;
        // Join this account's exact original witness service before selecting
        // the next owner in the retained namespace. No exposure is cleared.
        drop(financial_server);
        trace.begin(B::DurableHostSignatureStatus);
        let status = input
            .engine
            .durable_proposal_status_v1(input.access, input.candidate_id, local(), retention())
            .map_err(|error| trace.engine(error))?;
        trace.check(
            status.retained_owner_count == index
                && status.signatures_complete == (index == 2)
                && !status.authorization_allowed
                && !status.distribution_allowed
                && !status.chain_validated,
        )?;
        trace.begin(B::DurableHostReload);
        let unchanged = input
            .engine
            .load_durable_proposal_for_local_review_v1(input.access, input.candidate_id, local())
            .map_err(|error| trace.engine(error))?;
        trace.check(unchanged.identity() == input.identity)?;
    }
    trace.begin(B::DurableHostSignatureUnion);
    let union_key = "durable-native-fixed-exact-union";
    let union = input
        .engine
        .assemble_durable_proposal_v1(
            input.access,
            union_key,
            input.candidate_id,
            revision,
            local(),
            retention(),
        )
        .map_err(|error| trace.engine(error))?;
    // These replays use the same open journals; no restart is claimed.
    let replay = input
        .engine
        .assemble_durable_proposal_v1(
            input.access,
            union_key,
            input.candidate_id,
            revision,
            local(),
            retention(),
        )
        .map_err(|error| trace.engine(error))?;
    trace.check(replay.replayed && replay.agreement.revision == union.agreement.revision)?;
    trace.begin(B::DurableHostTransactionCheckpoint);
    let extracted = input
        .engine
        .checkpoint_durable_transaction_v1(
            input.access,
            input.candidate_id,
            local(),
            retention(),
            transaction(),
        )
        .map_err(|error| trace.engine(error))?;
    let repeated = input
        .engine
        .checkpoint_durable_transaction_v1(
            input.access,
            input.candidate_id,
            local(),
            retention(),
            transaction(),
        )
        .map_err(|error| trace.engine(error))?;
    trace.check(
        repeated.exact_replay
            && repeated.txid == extracted.txid
            && repeated.transaction_digest == extracted.transaction_digest
            && extracted.cryptographic_transaction_verified
            && extracted.transaction_extracted
            && !extracted.chain_validated
            && !extracted.authorization_allowed
            && !extracted.distribution_allowed
            && !extracted.release_allowed,
    )?;
    // No submission/broadcast call, witness exposure clearing, source deletion,
    // replacement proof, old-owner renewal or serialization is performed here.
    trace.complete();
    Ok(())
}
