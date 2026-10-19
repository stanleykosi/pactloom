//! All private source material enters through the genuine per-owner native
//! disclosure and maintained protected scanner, never a fixture key getter.
use super::safe_diagnostics_v1::{self as diagnostic, Boundary as B, Outcome};
use super::worker::{JoinedSignerCommandV1 as Command, JoinedSignerReplyV1 as Reply};
use super::*;
use wholepact_core::{
    ClaimedInput, ClaimedOutput, IntentStatus, OutputAllocation, ParticipantAllocation,
    ParticipationIntent, ProposalManifest,
};
use wholepact_engine::durable_construction_v1::review_export_v1::{
    DurableReviewExportScopeV1, DurableReviewSourceV1, LocalDurableReviewExportConsentV1,
};
use wholepact_engine::durable_construction_v1::{
    DurableMaterialActionV1, LocalDurableMaterialConsentV1,
};
use wholepact_engine::planning::RosterSelectionRequest;
use wholepact_engine::proof_jobs::LocalProofJob;
use wholepact_engine::{Access, CandidateRequest, Engine};
use wholepact_proof_jobs::{CheckpointScope, LocalAction, LocalProofConsent, ProofJobStore};
use wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1;
use wholepact_protocol::proving::ProvingLimits;
use wholepact_signer::authority_bridge::{
    durable_construction_v1::{
        DurableConstructionCaptureRequestV1, DurableConstructionHistoryRequestV1,
        DurableConstructionRedisclosureRequestV1, DurableConstructionRedisclosureSourceV1,
        DurableConstructionScopeV1,
    },
    durable_review_ipc_v1::{DurableReviewDeliveryRequestV1, DurableReviewRecipientV1},
    ipc::OriginalHistoryClient,
    preconstruction_ipc::{
        PreconstructionBirthday, PreconstructionProvider, PreconstructionRequest,
        PreconstructionScope,
    },
};
use wholepact_storage_security::{DatabaseKey, create_encrypted};
use wholepact_store::Store;
use wholepact_wallet::wallet::{
    AccountUuid,
    protected_sync::{
        BackendIdentity, LocalWalletAccess, ProtectedWalletSync, WalletAccessPurpose,
        durable_construction_v1::{ConstructionReviewerV1, DurableConstructionWalletSlotV1},
    },
};

const PRINCIPAL: &str = "synthetic-local-host";
const RETENTION: &str =
    "Private temporary fixed-proposal fixture only; irreversible viewing disclosure";
fn fail(_: impl std::fmt::Display) -> Error {
    Error::Authentication
}
fn stage(_: &'static str) -> Error {
    Error::Authentication
}

/// Local diagnostic state only: it never polls, contacts a peer or changes a
/// lifetime. A pending phase is reported before the original worker is dropped,
/// so cleanup cancellation cannot conceal the first Host-side failure.
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
        Error::Authentication
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
        // Covers correlation/shape and remaining generically mapped setup,
        // reload or provider errors. HostAuthentication is only this fixture's
        // collapsed fallback category, not evidence of an authentication cause.
        // It cannot overwrite an already recorded typed first failure.
        if let Some(boundary) = self.active.take() {
            diagnostic::emit(boundary, Outcome::HostAuthentication);
        }
    }
}
fn amount(v: u64) -> wholepact_core::Amount {
    v.to_string().parse().expect("bounded constant amount")
}
fn now() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(fail)
}
fn done(worker: &worker::JoinedSignerWorkerV1, index: usize) -> Result<()> {
    match worker.receive().map_err(stage)? {
        Reply::Done { index: actual } if actual == index => Ok(()),
        _ => Err(Error::Authentication),
    }
}

/// Trusted embedding test-local privacy gate only. This does NOT manufacture
/// native provenance: intake still consumes the sealed actual IPC observation.
struct ExactPrivacy {
    proposal: wholepact_core::ProposalInput,
    candidate: String,
    manifest: String,
    accounts: Vec<String>,
    destination: String,
    source: BackendIdentity,
    wallets: Vec<AccountUuid>,
}
impl LocalDurableMaterialConsentV1 for ExactPrivacy {
    fn permits(
        &self,
        scope: &DurableConstructionScopeV1,
        material: &str,
        _: DurableMaterialActionV1,
    ) -> bool {
        scope.proposal == self.proposal
            && scope.version == 2
            && self.accounts.contains(&scope.account_id)
            && scope.protected_destination == self.destination
            && scope.constructor.principal_id == PRINCIPAL
            && scope.prover.principal_id == PRINCIPAL
            && scope.retention_policy == RETENTION
            && material.len() == 64
    }
}
impl LocalProofConsent for ExactPrivacy {
    fn permits(&self, scope: &CheckpointScope, _: LocalAction) -> bool {
        let mut actual = scope.account_ids.clone();
        actual.sort();
        let mut expected = self.accounts.clone();
        expected.sort();
        scope.principal_id == PRINCIPAL
            && scope.candidate_id == self.candidate
            && scope.manifest_digest == self.manifest
            && actual == expected
            && scope.local_operator == PRINCIPAL
            && scope.retention_policy == RETENTION
            && scope.purpose
                == wholepact_wallet::wallet::protected_sync::durable_construction_v1::PURPOSE
    }
}
impl LocalWalletAccess for ExactPrivacy {
    fn permits(
        &self,
        account: AccountUuid,
        source: &BackendIdentity,
        _: WalletAccessPurpose,
    ) -> bool {
        self.wallets.contains(&account) && source == &self.source
    }
}

/// Exact fresh export consent for one actual metadata-only Ready recipient.
/// Public descriptors alone cannot satisfy Engine's sealed recipient argument.
struct ExactExport {
    identity: FixedProposalIdentityV1,
    recipient: DurableReviewRecipientV1,
    sources: Vec<DurableReviewSourceV1>,
}
impl LocalDurableReviewExportConsentV1 for ExactExport {
    fn permits(&self, scope: &DurableReviewExportScopeV1) -> bool {
        scope.schema_version == 1 && scope.principal_id == PRINCIPAL
            && scope.proposal == self.identity && scope.recipient == self.recipient
            && scope.sources == self.sources && scope.payload_digest.len() == 64
            && scope.payload_length > 0
            && scope.payload_length <= wholepact_signer::authority_bridge::durable_review_ipc_v1::MAX_DURABLE_REVIEW_PAYLOAD_BYTES_V1 as u64
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FollowOnV1 {
    Baseline,
    FixedSigning,
    AcquireReplyLoss,
}

type FollowOnExerciseV1 = for<'a> fn(super::fixed_signing::FixedSigningInputsV1<'a>) -> Result<()>;

impl FollowOnV1 {
    fn exercise(self) -> Option<FollowOnExerciseV1> {
        match self {
            Self::Baseline => None,
            Self::FixedSigning => Some(super::fixed_signing::exercise),
            Self::AcquireReplyLoss => Some(super::fixed_signing::exercise_acquire_reply_loss),
        }
    }
}

pub(super) fn exercise(original: initial::DurableInitialV1) -> Result<()> {
    exercise_inner(original, FollowOnV1::Baseline)
}

/// Separate compiled path; the ordinary baseline never enters financial work.
pub(super) fn exercise_with_fixed_signing(original: initial::DurableInitialV1) -> Result<()> {
    exercise_inner(original, FollowOnV1::FixedSigning)
}

/// Distinct original-session reply-loss path after the same genuine prefix.
pub(super) fn exercise_with_acquire_reply_loss(original: initial::DurableInitialV1) -> Result<()> {
    exercise_inner(original, FollowOnV1::AcquireReplyLoss)
}

fn exercise_inner(original: initial::DurableInitialV1, follow_on: FollowOnV1) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(fail)?;
    runtime.block_on(exercise_async(original, follow_on))
}
async fn exercise_async(
    mut original: initial::DurableInitialV1,
    follow_on: FollowOnV1,
) -> Result<()> {
    use wholepact_wallet::wallet::synthetic_born_receiver_blocks_v1::{
        SyntheticBornChainSpecV1, SyntheticBornReceiverBlocksV1,
    };
    let mut trace = HostTrace::new();
    let block_time: u32 = now()?.try_into().map_err(fail)?;
    // Maintained constructor rechecks actual ZIP317: two spends/one recipient
    // pad to two Ironwood actions, fee10,000. Each exact input155,000 has no change.
    let blocks = SyntheticBornReceiverBlocksV1::build(
        [
            &original.born[1].public_receive_address,
            &original.born[2].public_receive_address,
        ],
        [155_000, 155_000],
        SyntheticBornChainSpecV1 {
            prior_height: 4_465_050,
            prior_hash_protocol: [73; 32],
            block_count: 1,
            timestamp: block_time,
        },
    )
    .map_err(fail)?;
    let outpoints = blocks.public_funding_input_ids().clone();
    let birthday = blocks.trees()[0].clone();
    let anchor_height = blocks.fabricated_context().anchor_height;
    let expiry_height = anchor_height.checked_add(40).ok_or(Error::Invalid)?;
    let provider = synthetic_born_provider_v1::SyntheticBornProviderV1::start(
        blocks,
        synthetic_provider_tls_v1::child_server_config().map_err(fail)?,
        Instant::now() + Duration::from_secs(900),
    )
    .await
    .map_err(fail)?;
    let source = wholepact_chain::ChainAdapter::testnet(
        "synthetic-durable-public-blocks",
        provider.endpoint(),
        wholepact_chain::NetworkPolicy::default(),
    )
    .map_err(fail)?;
    let source_identity = source.identity().clone();
    let root = original.temporary.path().join("durable-original-engine");
    std::fs::create_dir(&root)?;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    let metadata_path = root.join("metadata.sqlite3");
    let jobs_path = root.join("proof.sqlite3");
    let metadata_key = DatabaseKey::from_bytes([201; 32]);
    let proof_key = DatabaseKey::from_bytes([202; 32]);
    let access = Access {
        principal_id: PRINCIPAL.into(),
        include_owned_agreements: true,
        ..Access::default()
    };
    let engine =
        Engine::from_store(Store::create_encrypted(&metadata_path, &metadata_key).map_err(fail)?);
    let mut agreement = original
        .host
        .engine
        .get(original.host.access()?, worker::AGREEMENT_ID)?
        .agreement;
    agreement.organizer_identity = PRINCIPAL.into();
    engine
        .create(&access, "durable-new-original", agreement.clone())
        .map_err(fail)?;
    let participants = original.born[1..]
        .iter()
        .map(|owner| ParticipantAllocation {
            participant_id: owner.participant_id.clone(),
            account_id: owner.account_id.clone(),
            contribution: amount(150_000),
            fee_share: amount(5_000),
            fee_cap: amount(5_000),
            maximum_net_debit: amount(155_000),
            charges: vec![],
        })
        .collect::<Vec<_>>();
    for (i, p) in participants.iter().enumerate() {
        engine
            .add_intent(
                &access,
                &format!("durable-intent-{i}"),
                worker::AGREEMENT_ID,
                i as u64 + 1,
                ParticipationIntent {
                    intent_id: format!("durable-intent-{i}"),
                    agreement_id: worker::AGREEMENT_ID.into(),
                    participant_id: p.participant_id.clone(),
                    desired_contribution: p.contribution,
                    maximum_net_debit: p.maximum_net_debit,
                    fee_cap: p.fee_cap,
                    conditions: vec![],
                    valid_until: None,
                    status: IntentStatus::Active,
                },
            )
            .map_err(fail)?;
    }
    engine
        .select_roster(
            &access,
            "durable-select-roster",
            worker::AGREEMENT_ID,
            3,
            RosterSelectionRequest {
                selected_intent_ids: vec!["durable-intent-0".into(), "durable-intent-1".into()],
            },
        )
        .map_err(fail)?;
    let manifest = ProposalManifest {
        agreement,
        participants: participants.clone(),
        inputs: participants
            .iter()
            .zip(outpoints)
            .map(|(p, input_id)| ClaimedInput {
                input_id,
                participant_id: p.participant_id.clone(),
                account_id: p.account_id.clone(),
                amount: amount(155_000),
                ownership_evidence_ref: None,
            })
            .collect(),
        outputs: vec![ClaimedOutput {
            output_id: "durable-exact-recipient".into(),
            address: original.payment_receiver.clone(),
            amount: amount(300_000),
            allocation: OutputAllocation::Recipient {
                recipient_id: worker::RECIPIENT_ID.into(),
            },
        }],
        transaction_fee: amount(10_000),
        expiry_height,
    };
    let created = engine
        .create_candidate(
            &access,
            "durable-candidate-create",
            worker::AGREEMENT_ID,
            4,
            CandidateRequest {
                manifest,
                previous_candidate_id: None,
            },
        )
        .map_err(fail)?;
    let candidate = created.agreement.candidates[0].clone();
    let mut privacy = ExactPrivacy {
        proposal: candidate.proposal.clone(),
        candidate: candidate.candidate_id.clone(),
        manifest: candidate.manifest_digest.clone(),
        accounts: participants.iter().map(|p| p.account_id.clone()).collect(),
        destination: metadata_path.to_str().ok_or(Error::Invalid)?.into(),
        source: source_identity.clone(),
        wallets: vec![],
    };
    let mut revision = created.agreement.revision;
    let mut wallets = Vec::new();
    let mut old_entries = Vec::new();
    let mut old_deadlines = Vec::new();
    let mut original_disclosures = Vec::new();
    let mut original_records = Vec::new();
    let mut export_sources = Vec::new();
    // No overlapping owner native lifetime is needed: each outbox is durably
    // admitted, old lease/client/runtime destroyed, then the second owner opens.
    for index in 1..=2 {
        let account = &original.born[index];
        trace.begin(B::DurableHostOpen);
        original
            .signers
            .send(Command::OpenDurable(index, candidate.proposal.clone()))
            .map_err(stage)?;
        let (peer, scope, entry) = match original.signers.receive().map_err(stage)? {
            Reply::DurablePeer {
                index: actual,
                peer,
                scope,
                entry_digest,
            } if actual == index => (peer, scope, entry_digest),
            _ => return Err(Error::Authentication),
        };
        old_entries.push(entry);
        old_deadlines.push(peer.deadline);
        trace.begin(B::DurableHostPairStatus);
        original
            .signers
            .send(Command::PollDurablePair(index))
            .map_err(stage)?;
        let client = OriginalHistoryClient::pair(
            peer.provider,
            &peer.endpoint,
            "Synthetic-durable-constructor",
            scope,
        )
        .map_err(|error| trace.bridge(error))?;
        trace.begin(B::DurableHostPairObserved);
        done(&original.signers, index)?;
        trace.begin(B::DurableHostAccept);
        original
            .signers
            .send(Command::AcceptDurable(index))
            .map_err(stage)?;
        let records = match original.signers.receive().map_err(stage)? {
            Reply::Records {
                index: actual,
                records,
            } if actual == index => records,
            _ => return Err(Error::Authentication),
        };
        original_records.push(records.clone());
        let wallet_path = root.join(format!("construction-owner-{index}.sqlite3"));
        let initial = PreconstructionRequest {
            enrollment_ref: records.enrollment_ref.clone(),
            accepted_manifest_ref: records.accepted_manifest_ref.clone(),
            sponsor_policy: None,
            scope: PreconstructionScope {
                schema_version: 1,
                proposal: candidate.proposal.clone(),
                account_id: account.account_id.clone(),
                participant_id: account.participant_id.clone(),
                profile_id: wholepact_protocol::construction::PROFILE_ID.into(),
                principal_id: PRINCIPAL.into(),
                operator_name: PRINCIPAL.into(),
                operator_destination: privacy.destination.clone(),
                wallet_destination: wallet_path.to_str().ok_or(Error::Invalid)?.into(),
                reviewer_account_ids: privacy.accounts.clone(),
                privacy_domain: account.privacy_domain.clone(),
                purpose: "construct_exact_accepted_candidate".into(),
                retention_policy: RETENTION.into(),
                provider: PreconstructionProvider {
                    source_id: source_identity.source_id.clone(),
                    endpoint: source_identity.endpoint.clone(),
                    trust_profile: source_identity.trust_profile.into(),
                },
                minimum_confirmations: 1,
                maximum_blocks: 16,
                anchor_height,
                maximum_net_debit_zatoshis: 155_000,
                birthday: PreconstructionBirthday {
                    prior_height: birthday.height.try_into().map_err(fail)?,
                    prior_block_hash: birthday.hash.clone(),
                    sapling_tree: birthday.sapling_tree.clone(),
                    orchard_tree: birthday.orchard_tree.clone(),
                    ironwood_tree: birthday.ironwood_tree.clone(),
                },
            },
        };
        trace.begin(B::DurableHostInitialDisclosure);
        original
            .signers
            .send(Command::ArmInitial(index, initial.clone()))
            .map_err(stage)?;
        done(&original.signers, index)?;
        original
            .signers
            .send(Command::PollDisclosure(index))
            .map_err(stage)?;
        let initial_lease = client
            .request_preconstruction(&initial)
            .map_err(|error| trace.bridge(error))?;
        trace.begin(B::DurableHostInitialObserved);
        done(&original.signers, index)?;
        trace.begin(B::DurableHostRecipient);
        let recipient = client
            .durable_construction_recipient_v1(PRINCIPAL)
            .map_err(|error| trace.bridge(error))?;
        trace.begin(B::DurableHostCaptureSetup);
        let from = now()?;
        let capture = DurableConstructionCaptureRequestV1 {
            operation_id: format!("durable-native-original-{index}"),
            enrollment_ref: records.enrollment_ref,
            accepted_manifest_ref: records.accepted_manifest_ref,
            scope: DurableConstructionScopeV1 {
                version: 2,
                purpose: wholepact_wallet::wallet::protected_sync::durable_construction_v1::PURPOSE
                    .into(),
                proposal: candidate.proposal.clone(),
                account_id: account.account_id.clone(),
                participant_id: account.participant_id.clone(),
                privacy_domain: account.privacy_domain.clone(),
                constructor: recipient.clone(),
                prover: recipient,
                reviewers: privacy
                    .accounts
                    .iter()
                    .cloned()
                    .map(ConstructionReviewerV1::local_installed_signer)
                    .collect(),
                protected_destination: privacy.destination.clone(),
                retention_policy: RETENTION.into(),
                valid_from_unix_seconds: from,
                valid_until_unix_seconds: from + 1800,
                minimum_confirmations: 1,
                maximum_scan_blocks: 16,
            },
        };
        original
            .signers
            .send(Command::ArmCapture(index, capture.clone()))
            .map_err(stage)?;
        done(&original.signers, index)?;
        original
            .signers
            .send(Command::PollDisclosure(index))
            .map_err(stage)?;
        let wallet_key = DatabaseKey::from_bytes([210 + index as u8; 32]);
        let destination = create_encrypted(&wallet_path, &wallet_key)
            .map_err(|_| trace.refused(Outcome::StoreStorageSecurity))?;
        let adapter = wholepact_chain::ChainAdapter::testnet(
            &source_identity.source_id,
            &source_identity.endpoint,
            wholepact_chain::NetworkPolicy::default(),
        )
        .map_err(fail)?;
        trace.begin(B::DurableHostCapture);
        let (wallet, disclosure) = client
            .capture_and_request_durable_construction_v1(
                initial_lease,
                destination,
                adapter,
                capture,
            )
            .await
            .map_err(|error| trace.bridge(error))?;
        trace.begin(B::DurableHostCaptureObserved);
        done(&original.signers, index)?;
        trace.begin(B::DurableHostCaptureCommitted);
        original
            .signers
            .send(Command::CaptureCommitted(index))
            .map_err(stage)?;
        match original.signers.receive().map_err(stage)? {
            Reply::CaptureCommitted {
                index: actual,
                reference,
            } if actual == index && reference == disclosure.outbox().reference() => {}
            _ => return Err(Error::Authentication),
        };
        let outbox = disclosure.outbox();
        original_disclosures.push(DurableConstructionHistoryRequestV1 {
            operation_id: outbox.request().operation_id.clone(),
            expected_request_digest: outbox.request_digest().into(),
        });
        export_sources.push(DurableReviewSourceV1 {
            account_id: account.account_id.clone(),
            outbox_reference: outbox.reference().into(),
            request_digest: outbox.request_digest().into(),
            material_digest: outbox.material_digest().into(),
            scope_digest: outbox.request().scope.digest().map_err(fail)?,
        });
        trace.begin(B::DurableHostIntake);
        let admitted = engine
            .intake_durable_construction_v1(
                &access,
                &format!("durable-native-intake-{index}"),
                &candidate.candidate_id,
                revision,
                disclosure,
                &privacy,
            )
            .map_err(|error| trace.engine(error))?;
        revision = admitted.agreement.revision;
        trace.begin(B::DurableHostClose);
        // Keep no native disclosure lease or authenticated caller association.
        drop(client);
        original
            .signers
            .send(Command::CloseDurable(index))
            .map_err(stage)?;
        done(&original.signers, index)?;
        privacy.wallets.push(wallet.account_uuid());
        wallets.push(wallet);
        trace.complete();
    }
    trace.begin(B::DurableHostReload);
    drop(engine);
    let engine =
        Engine::from_store(Store::open_encrypted(&metadata_path, &metadata_key).map_err(fail)?);
    let [mut left, mut right]: [ProtectedWalletSync; 2] =
        wallets.try_into().map_err(|_| Error::Invalid)?;
    trace.begin(B::DurableHostObserve);
    let left_observed = engine
        .observe_durable_construction_v1(
            &access,
            &candidate.candidate_id,
            &privacy.accounts[0],
            &mut left,
            &privacy,
            &privacy,
        )
        .await
        .map_err(|error| trace.engine(error))?;
    trace.begin(B::DurableHostObserve);
    let right_observed = engine
        .observe_durable_construction_v1(
            &access,
            &candidate.candidate_id,
            &privacy.accounts[1],
            &mut right,
            &privacy,
            &privacy,
        )
        .await
        .map_err(|error| trace.engine(error))?;
    trace.begin(B::DurableHostCheckpoint);
    let jobs = ProofJobStore::from_encrypted_connection(
        create_encrypted(&jobs_path, &proof_key).map_err(fail)?,
    )
    .map_err(fail)?;
    let checkpointed = engine
        .checkpoint_durable_construction_v1(
            &access,
            "durable-checkpoint-original",
            &candidate.candidate_id,
            revision,
            vec![
                DurableConstructionWalletSlotV1::new(&mut left, &left_observed).map_err(fail)?,
                DurableConstructionWalletSlotV1::new(&mut right, &right_observed).map_err(fail)?,
            ],
            &jobs,
            ProvingLimits { maximum_actions: 8 },
            &privacy,
            &privacy,
        )
        .map_err(|error| trace.engine(error))?;
    let job = checkpointed.agreement.candidates[0].proof_jobs[0]
        .job_id
        .clone();
    trace.begin(B::DurableHostProof);
    let proved = engine
        .run_candidate_proof_locally(
            &access,
            "durable-prove-original-once",
            &candidate.candidate_id,
            checkpointed.agreement.revision,
            LocalProofJob {
                job_id: &job,
                jobs: &jobs,
                consent: &privacy,
            },
        )
        .map_err(|error| trace.engine(error))?;
    trace.begin(B::DurableHostFreeze);
    let frozen = engine
        .freeze_durable_proposal_v1(
            &access,
            "durable-freeze-original",
            &candidate.candidate_id,
            proved.agreement.revision,
            LocalProofJob {
                job_id: &job,
                jobs: &jobs,
                consent: &privacy,
            },
        )
        .map_err(|error| trace.engine(error))?;
    let mut revision = frozen.agreement.revision;
    let fixed = engine
        .load_durable_proposal_for_local_review_v1(
            &access,
            &candidate.candidate_id,
            LocalProofJob {
                job_id: &job,
                jobs: &jobs,
                consent: &privacy,
            },
        )
        .map_err(|error| trace.engine(error))?;
    let identity = fixed.identity().clone();
    drop(fixed);
    drop(jobs);
    drop(engine);
    trace.begin(B::DurableHostReload);
    // Reopen both ORIGINAL encrypted journals: never rebuild proof/randomness.
    let engine =
        Engine::from_store(Store::open_encrypted(&metadata_path, &metadata_key).map_err(fail)?);
    let jobs = ProofJobStore::from_encrypted_connection(
        wholepact_storage_security::open_encrypted(&jobs_path, &proof_key).map_err(fail)?,
    )
    .map_err(fail)?;
    let reloaded = engine
        .load_durable_proposal_for_local_review_v1(
            &access,
            &candidate.candidate_id,
            LocalProofJob {
                job_id: &job,
                jobs: &jobs,
                consent: &privacy,
            },
        )
        .map_err(|error| trace.engine(error))?;
    if reloaded.identity() != &identity {
        return Err(Error::Authentication);
    }
    export_sources.sort_by(|a, b| a.account_id.cmp(&b.account_id));
    for index in 1..=2 {
        trace.begin(B::DurableHostOpen);
        original
            .signers
            .send(Command::OpenDurable(index, candidate.proposal.clone()))
            .map_err(stage)?;
        let (peer, scope) = match original.signers.receive().map_err(stage)? {
            Reply::DurablePeer {
                index: actual,
                entry_digest,
                peer,
                scope,
            } if actual == index && entry_digest != old_entries[index - 1] => (peer, scope),
            _ => return Err(Error::Authentication),
        };
        // Deadline is inert timing data only. No old owner/grant survives close.
        // This run does not claim a long human gap: elapsed may be false, and no
        // arbitrary sleep or fake clock is introduced to manufacture expiry.
        let _original_native_deadline_elapsed = Instant::now() >= old_deadlines[index - 1];
        trace.begin(B::DurableHostPairStatus);
        original
            .signers
            .send(Command::PollDurablePair(index))
            .map_err(stage)?;
        let client = OriginalHistoryClient::pair(
            peer.provider,
            &peer.endpoint,
            "Synthetic-fresh-durable-reviewer",
            scope,
        )
        .map_err(|error| trace.bridge(error))?;
        trace.begin(B::DurableHostPairObserved);
        done(&original.signers, index)?;
        trace.begin(B::DurableHostAccept);
        original
            .signers
            .send(Command::AcceptDurable(index))
            .map_err(stage)?;
        let records = match original.signers.receive().map_err(stage)? {
            Reply::Records {
                index: actual,
                records,
            } if actual == index => records,
            _ => return Err(Error::Authentication),
        };
        if records.enrollment_ref == original_records[index - 1].enrollment_ref
            || records.accepted_manifest_ref == original_records[index - 1].accepted_manifest_ref
        {
            return Err(Error::Authentication);
        }
        let renewed = DurableConstructionRedisclosureRequestV1 {
            operation_id: format!("durable-fresh-review-disclosure-{index}"),
            original: DurableConstructionRedisclosureSourceV1 {
                operation_id: original_disclosures[index - 1].operation_id.clone(),
                // One owner deliberately omits its optional staging digest.
                // This is exact-operation native resolution, not a crash/loss claim.
                expected_request_digest: (index == 2).then(|| {
                    original_disclosures[index - 1]
                        .expected_request_digest
                        .clone()
                }),
            },
            enrollment_ref: records.enrollment_ref.clone(),
            accepted_manifest_ref: records.accepted_manifest_ref.clone(),
        };
        trace.begin(B::DurableHostRedisclosure);
        original
            .signers
            .send(Command::ArmRedisclosure(index, renewed.clone()))
            .map_err(stage)?;
        done(&original.signers, index)?;
        original
            .signers
            .send(Command::PollDisclosure(index))
            .map_err(stage)?;
        let current = client
            .redisclose_durable_construction_v1(&renewed)
            .map_err(|error| trace.bridge(error))?;
        done(&original.signers, index)?;
        let current_ref = DurableConstructionHistoryRequestV1 {
            operation_id: current.outbox().request().operation_id.clone(),
            expected_request_digest: current.outbox().request_digest().into(),
        };
        let link = current
            .outbox()
            .redisclosure()
            .ok_or(Error::Authentication)?;
        if link.original_operation_id != renewed.original.operation_id
            || link.original_request_digest
                != original_disclosures[index - 1].expected_request_digest
        {
            return Err(Error::Authentication);
        }
        // Do not replace Engine's original authenticated intake with a renewed
        // recipient's outbox. Both references remain explicitly distinct.
        drop(current);
        let request = DurableReviewDeliveryRequestV1 {
            operation_id: format!("durable-fresh-fixed-review-{index}"),
            enrollment_ref: records.enrollment_ref,
            accepted_manifest_ref: records.accepted_manifest_ref,
            own_disclosure: original_disclosures[index - 1].clone(),
            current_disclosure: Some(current_ref),
            proposal_binding: identity.proposal_binding.clone(),
        };
        trace.begin(B::DurableHostReviewReady);
        original
            .signers
            .send(Command::PollImport(
                index,
                request.clone(),
                identity.clone(),
            ))
            .map_err(stage)?;
        let recipient = client
            .prepare_durable_review_delivery_v1(&request)
            .map_err(|error| trace.bridge(error))?;
        let export = ExactExport {
            identity: identity.clone(),
            recipient: recipient.descriptor().clone(),
            sources: export_sources.clone(),
        };
        // Ready is metadata only. Human delay must not trip the former two-second
        // read timeout; the unchanged absolute native lease still limits the wait.
        trace.begin(B::DurableHostReviewExport);
        std::thread::sleep(Duration::from_millis(2250));
        let delivered = engine
            .deliver_durable_proposal_for_native_review_v1(
                &access,
                &format!("durable-fixed-native-export-{index}"),
                &candidate.candidate_id,
                revision,
                LocalProofJob {
                    job_id: &job,
                    jobs: &jobs,
                    consent: &privacy,
                },
                recipient,
                &privacy,
                &export,
            )
            .map_err(|error| trace.engine(error))?;
        revision = delivered.agreement.revision;
        trace.begin(B::DurableHostReviewImported);
        done(&original.signers, index)?;
        let unchanged = engine
            .load_durable_proposal_for_local_review_v1(
                &access,
                &candidate.candidate_id,
                LocalProofJob {
                    job_id: &job,
                    jobs: &jobs,
                    consent: &privacy,
                },
            )
            .map_err(|error| trace.engine(error))?;
        if unchanged.identity() != &identity {
            return Err(Error::Authentication);
        }
        drop(unchanged);
        trace.begin(B::DurableHostClose);
        // Imported is memory-only verified data, not approval, signed retention,
        // a writer permit or a session that can survive closing this owner.
        drop(client);
        original
            .signers
            .send(Command::CloseDurable(index))
            .map_err(stage)?;
        done(&original.signers, index)?;
        trace.complete();
    }
    drop(reloaded);
    if let Some(exercise) = follow_on.exercise() {
        // The same real provider, witness, original account custodians and
        // protected Engine/proof journals remain alive. No serialized receipt
        // reconstructs authority, and the immutable proof is never rebuilt.
        exercise(super::fixed_signing::FixedSigningInputsV1 {
            original: &mut original,
            engine: &engine,
            jobs: &jobs,
            access: &access,
            candidate_id: &candidate.candidate_id,
            proposal: &candidate.proposal,
            identity: &identity,
            job_id: &job,
            proof_consent: &privacy,
            material_consent: &privacy,
            original_disclosures: &original_disclosures,
            export_sources: &export_sources,
            birthday: &birthday,
            source: &source_identity,
            protected_root: &root,
            revision,
        })?;
    }
    drop(jobs);
    drop(engine);
    drop(left);
    drop(right);
    trace.begin(B::DurableHostProviderStop);
    provider.shutdown().await.map_err(fail)?;
    trace.complete();
    drop(original); // Revokes/joins worker and original witness before TempDir.
    Ok(())
}

#[cfg(test)]
mod follow_on_tests {
    use super::*;

    #[test]
    fn pure_follow_on_selects_exactly_one_distinct_continuation() {
        assert!(FollowOnV1::Baseline.exercise().is_none());
        let fixed: FollowOnExerciseV1 = super::super::fixed_signing::exercise;
        let loss: FollowOnExerciseV1 = super::super::fixed_signing::exercise_acquire_reply_loss;
        assert!(std::ptr::fn_addr_eq(
            FollowOnV1::FixedSigning.exercise().unwrap(),
            fixed
        ));
        assert!(std::ptr::fn_addr_eq(
            FollowOnV1::AcquireReplyLoss.exercise().unwrap(),
            loss
        ));
        assert!(!std::ptr::fn_addr_eq(fixed, loss));
    }
}
