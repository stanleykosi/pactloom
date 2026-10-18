//! Separate finite never-funded native worker for durable qualification.
//! Historical setup uses real birth/roster controllers only. There are no V3
//! common-context, construction, consumed-owner or named payment variants.
use super::safe_diagnostics_v1::{self as diagnostic, Boundary as B, Outcome};
use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use wholepact_authority::{
    AccountPolicy, OwnerControlRequest, native_witness_owner::EphemeralWitnessOriginV1,
};
use wholepact_core::born_recipient_policy_v2::{
    BornConstructionRecipientPolicyV2, BornOriginalLimitsV2, BornOwnReturnRuleV2,
    BornRecipientLimitV2,
};
use wholepact_signer::authority_bridge::{
    AuthorizationCommit,
    durable_construction_v1::{
        DurableConstructionCaptureRequestV1, DurableConstructionRedisclosureRequestV1,
    },
    durable_review_ipc_v1::DurableReviewDeliveryRequestV1,
    ipc::HistoryRequest,
    preconstruction_ipc::PreconstructionRequest,
};
use wholepact_signer::native_ui::synthetic_born_joined_qualification::{
    DurableNativeEntryFailureV1, DurableNativeEntryStageV1, DurableNativeRecordsV1,
    EphemeralAcknowledgedBornV1, EphemeralDurableNativeV1, EphemeralExportedBirthV1,
    EphemeralFirstAnchorIntentV1, EphemeralFirstAnchorPublicationV1,
    EphemeralOriginalRosterIntentV1, EphemeralPendingBornV1, EphemeralRosterPublicationV1,
    OriginalBirthSetupV1,
};
use wholepact_signer_origin::{
    InstalledSignerProvider, PairScope,
    manual::{HostManualEnrollmentIntent, HostManualEnrollmentRequest},
    manual_roster_v2::{
        HostManualRosterEnrollmentIntentV2, HostManualRosterEnrollmentRequestV2,
        HostManualRosterPublicationRequestV2,
    },
};
type Result<T> = std::result::Result<T, &'static str>;
fn signer_error(error: wholepact_signer::Error, label: &'static str) -> &'static str {
    diagnostic::emit(B::SignerPollTerminal, diagnostic::signer_error(&error));
    label
}
fn durable_entry_error(failure: DurableNativeEntryFailureV1) -> &'static str {
    use DurableNativeEntryStageV1 as S;
    let boundary = match failure.stage() {
        S::NativeOwnerCheck => B::DurableEntryNativeOwnerCheck,
        S::VaultOpen => B::DurableEntryVaultOpen,
        S::RetainedEnrollment => B::DurableEntryRetainedEnrollment,
        S::OriginalCommit => B::DurableEntryOriginalCommit,
        S::JournalOpen => B::DurableEntryJournalOpen,
        S::SourceCheck => B::DurableEntrySourceCheck,
        S::RuntimeActivation => B::DurableEntryRuntimeActivation,
        S::WorkerResult => B::DurableEntryWorkerResult,
        S::EndpointCreate => B::DurableEntryEndpointCreate,
        S::EndpointBind => B::DurableEntryEndpointBind,
        S::EndpointPublish => B::DurableEntryEndpointPublish,
        S::PostEndpointSourceCheck => B::DurableEntryPostEndpointSourceCheck,
        S::FixturePreflight => B::DurableEntryFixturePreflight,
        S::FixturePostActivation => B::DurableEntryFixturePostActivation,
    };
    let error = failure.into_error();
    diagnostic::emit(boundary, diagnostic::signer_error(&error));
    signer_error(error, "fresh durable original entry")
}
pub(super) const AGREEMENT_ID: &str = "synthetic-born-joined-agreement-v3";
pub(super) const OBLIGATION_ID: &str = "synthetic-born-joined-obligation-v3";
pub(super) const PARTICIPANT_IDS: [&str; 3] = [
    "synthetic-anchor",
    "synthetic-owner-one",
    "synthetic-owner-two",
];
pub(super) const RECIPIENT_ID: &str = "synthetic-payment-recipient-v3";
pub(super) const RECIPIENT_PROVENANCE: &str =
    "Synthetic temporary public receiver; no ownership or receipt claim.";
#[derive(Clone)]
pub(super) struct PublicJoinedBornV1 {
    pub index: usize,
    pub account_id: String,
    pub birth_digest: String,
    pub full_viewing_key_digest: String,
    pub network_profile_id: String,
    pub participant_id: String,
    pub privacy_domain: String,
    pub public_receive_address: String,
    pub recipient_scope_digest: String,
}
pub(super) struct JoinedSignerPeerV1 {
    pub endpoint: PathBuf,
    pub provider: InstalledSignerProvider,
    pub deadline: Instant,
}
pub(super) enum JoinedSignerCommandV1 {
    ExportBirth(usize),
    Acknowledge(usize),
    OpenSingleIntent(usize, HostManualEnrollmentIntent),
    PollAndExportSingle(usize),
    OpenSinglePublication(usize, HostManualEnrollmentRequest),
    PollSinglePublication(usize),
    CloseSinglePublication(usize),
    OpenRosterIntent(usize, HostManualRosterEnrollmentIntentV2),
    PollAndExportRoster(usize),
    OpenRosterPublication(usize, HostManualRosterPublicationRequestV2),
    PollRosterPublication(usize),
    CloseRosterPublication(usize),
    OpenDurable(usize, wholepact_core::ProposalInput),
    PollDurablePair(usize),
    ConfigureDurableWitness(usize),
    PrepareDurableAdmission(usize),
    ApproveDurableAdmission(usize),
    ReconcileDurableWriter(usize),
    ConfigureDurableWallet(usize, String),
    AcceptDurable(usize),
    ArmInitial(usize, PreconstructionRequest),
    ArmCapture(usize, DurableConstructionCaptureRequestV1),
    ArmRedisclosure(usize, DurableConstructionRedisclosureRequestV1),
    PollImport(
        usize,
        DurableReviewDeliveryRequestV1,
        wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1,
    ),
    PollFinancialImport(
        usize,
        DurableReviewDeliveryRequestV1,
        wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1,
    ),
    SignDurableFixed(
        usize,
        wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1,
    ),
    ServeDurableResult(usize, Arc<AtomicBool>),
    PollDisclosure(usize),
    CaptureCommitted(usize),
    CloseDurable(usize),
}
pub(super) enum JoinedSignerReplyV1 {
    BirthExport {
        index: usize,
        account_id: String,
        birth_digest: String,
        exported_file: PathBuf,
    },
    Acknowledged(PublicJoinedBornV1),
    Peer(JoinedSignerPeerV1),
    SingleExport {
        index: usize,
        signed_extension_file: PathBuf,
        enrollment_request: HostManualEnrollmentRequest,
    },
    RosterExport {
        index: usize,
        signed_extension_file: PathBuf,
        original_policy_file: PathBuf,
        enrollment_request: HostManualRosterEnrollmentRequestV2,
    },
    DurablePeer {
        index: usize,
        peer: JoinedSignerPeerV1,
        scope: PairScope,
        entry_digest: String,
    },
    Records {
        index: usize,
        records: DurableNativeRecordsV1,
    },
    CaptureCommitted {
        index: usize,
        reference: String,
    },
    DurableAuthorization {
        index: usize,
        history: HistoryRequest,
        commit: AuthorizationCommit,
    },
    DurableAdmissionRequest {
        index: usize,
        request: OwnerControlRequest,
    },
    Done {
        index: usize,
    },
}
struct OriginalPublic {
    account_id: String,
    full_viewing_key_digest: String,
    network_profile_id: String,
    recipient_scope_digest: String,
}
enum State {
    Pending(EphemeralPendingBornV1),
    ExportedBirth(EphemeralExportedBirthV1),
    Acknowledged(EphemeralAcknowledgedBornV1),
    SingleIntent(EphemeralFirstAnchorIntentV1),
    SinglePublication(EphemeralFirstAnchorPublicationV1, bool),
    RosterIntent(EphemeralOriginalRosterIntentV1),
    RosterPublication(EphemeralRosterPublicationV1, bool),
    Durable(Box<EphemeralDurableNativeV1>),
}
enum OriginalWitnessOriginsV1 {
    ConstructorOnly(EphemeralWitnessOriginV1),
    Distinct([EphemeralWitnessOriginV1; 3]),
}
pub(super) struct JoinedSignerWorkerV1 {
    commands: Option<Sender<JoinedSignerCommandV1>>,
    replies: Receiver<Result<JoinedSignerReplyV1>>,
    cancelled: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}
impl JoinedSignerWorkerV1 {
    pub fn spawn(
        origin: EphemeralWitnessOriginV1,
        payment_receiver: String,
        expiry_ms: u64,
    ) -> Result<Self> {
        let (commands, incoming) = mpsc::channel();
        let (outgoing, replies) = mpsc::channel();
        let (started, startup) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = cancelled.clone();
        let join = thread::Builder::new()
            .name("synthetic-durable-native".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(move || {
                let (mut states, public) = match create_originals(
                    OriginalWitnessOriginsV1::ConstructorOnly(origin),
                    &payment_receiver,
                    expiry_ms,
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = started.send(Err(e));
                        return;
                    }
                };
                if started.send(Ok(())).is_err() {
                    return;
                }
                while !flag.load(Ordering::Acquire) {
                    let command = match incoming.recv_timeout(Duration::from_millis(20)) {
                        Ok(v) => v,
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(_) => break,
                    };
                    let reply = execute(command, &mut states, &public, &flag);
                    let failed = reply.is_err();
                    if outgoing.send(reply).is_err() || failed {
                        break;
                    }
                }
                drop(states);
            })
            .map_err(|_| "durable worker thread")?;
        let mut worker = Self {
            commands: Some(commands),
            replies,
            cancelled,
            join: Some(join),
        };
        match startup.recv() {
            Ok(Ok(())) => Ok(worker),
            Ok(Err(e)) => {
                worker.stop_and_join()?;
                Err(e)
            }
            Err(_) => {
                worker.stop_and_join()?;
                Err("durable startup disconnected")
            }
        }
    }
    pub fn send(&self, command: JoinedSignerCommandV1) -> Result<()> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err("durable worker cancelled");
        }
        self.commands
            .as_ref()
            .ok_or("durable worker closed")?
            .send(command)
            .map_err(|_| "durable command disconnected")
    }
    pub fn receive(&self) -> Result<JoinedSignerReplyV1> {
        self.replies
            .recv()
            .map_err(|_| "durable reply disconnected")?
    }
    pub fn shutdown(mut self) -> Result<()> {
        self.stop_and_join()
    }
    fn stop_and_join(&mut self) -> Result<()> {
        self.cancelled.store(true, Ordering::Release);
        self.commands.take();
        if let Some(join) = self.join.take() {
            join.join().map_err(|_| "durable worker panicked")?;
        }
        Ok(())
    }
}
impl Drop for JoinedSignerWorkerV1 {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}

fn create_originals(
    origins: OriginalWitnessOriginsV1,
    payment_receiver: &str,
    expiry_ms: u64,
) -> Result<([Option<State>; 3], [OriginalPublic; 3])> {
    let mut public: [Option<OriginalPublic>; 3] = std::array::from_fn(|_| None);
    let pins = match &origins {
        OriginalWitnessOriginsV1::ConstructorOnly(origin) => {
            std::array::from_fn(|_| origin.clone())
        }
        OriginalWitnessOriginsV1::Distinct(origins) => (*origins).clone(),
    };
    diagnostic::emit(B::SignerCreate, Outcome::Begin);
    let mut setup = |index: usize, identity: &wholepact_signer::native_ui::synthetic_born_joined_qualification::PublicBornIdentityV1| {
        let pins = pins.get(index).ok_or(wholepact_signer::Error::InvalidData)?;
        let participant = PARTICIPANT_IDS
            .get(index)
            .ok_or(wholepact_signer::Error::InvalidData)?;
        let stable = BornConstructionRecipientPolicyV2 {
            version: 2,
            account_id: identity.account_id.clone(),
            network_profile_id: identity.network_profile_id.clone(),
            agreement_id: AGREEMENT_ID.into(),
            obligation_id: OBLIGATION_ID.into(),
            participant_id: (*participant).into(),
            recipients: vec![BornRecipientLimitV2 {
                recipient_id: RECIPIENT_ID.into(),
                address: payment_receiver.into(),
                memo: None,
                instruction_provenance: RECIPIENT_PROVENANCE.into(),
                maximum_amount_zatoshis: 300_000,
            }],
            charges: vec![],
            original_limits: BornOriginalLimitsV2 {
                aggregate_budget_zatoshis: 1_000_000,
                per_operation_limit_zatoshis: 400_000,
                maximum_fee_share_zatoshis: 10_000,
                maximum_transaction_fee_zatoshis: 20_000,
                maximum_permit_lifetime_ms: 120_000,
                policy_expires_at_ms: expiry_ms,
            },
            own_return_rule: BornOwnReturnRuleV2::AuthenticatedSameAccount,
        };
        let recipient_scope_digest = stable
            .digest()
            .map_err(|_| wholepact_signer::Error::InvalidData)?;
        // Original policy requires a nonempty inert requested-enrollment
        // allowlist. This public test label is NOT an enrollment record or a
        // predecessor: the actual manual extension derives its distinct ref.
        let mut requested = Sha256::new();
        requested.update(b"wholepact:synthetic-joined-requested-enrollment:v1\0");
        requested.update(identity.account_id.as_bytes());
        let policy = AccountPolicy {
            account_use_genesis: None,
            witness_id: pins.witness_id.clone(),
            account_id: identity.account_id.clone(),
            network_profile_id: identity.network_profile_id.clone(),
            owner_certificate_digest: pins.owner_certificate_digest.clone(),
            initial_writer_certificate_digest: pins.writer_certificate_digest.clone(),
            initial_writer_epoch: 1,
            enrollment_refs: vec![hex::encode(requested.finalize())],
            agreement_ids: vec![AGREEMENT_ID.into()],
            recipient_scope_digests: vec![recipient_scope_digest.clone()],
            aggregate_budget_zatoshis: stable.original_limits.aggregate_budget_zatoshis,
            per_operation_limit_zatoshis: stable.original_limits.per_operation_limit_zatoshis,
            maximum_fee_share_zatoshis: stable.original_limits.maximum_fee_share_zatoshis,
            maximum_transaction_fee_zatoshis: stable
                .original_limits
                .maximum_transaction_fee_zatoshis,
            maximum_permit_lifetime_ms: stable.original_limits.maximum_permit_lifetime_ms,
            policy_expires_at_ms: expiry_ms,
        };
        policy
            .validate()
            .map_err(|_| wholepact_signer::Error::InvalidData)?;
        public[index] = Some(OriginalPublic {
            account_id: identity.account_id.clone(),
            full_viewing_key_digest: identity.full_viewing_key_digest.clone(),
            network_profile_id: identity.network_profile_id.clone(),
            recipient_scope_digest,
        });
        Ok(OriginalBirthSetupV1 {
            policy,
            stable_recipient_policy_json: serde_json::to_string(&stable)
                .map_err(|_| wholepact_signer::Error::InvalidData)?,
        })
    };
    let accounts = match origins {
        OriginalWitnessOriginsV1::ConstructorOnly(origin) => {
            EphemeralPendingBornV1::create_three(origin, &mut setup)
        }
        OriginalWitnessOriginsV1::Distinct(origins) => {
            EphemeralPendingBornV1::create_three_with_original_witnesses(origins, &mut setup)
        }
    }
    .map_err(|error| {
        diagnostic::emit(B::SignerCreate, diagnostic::signer_error(&error));
        "actual three pending birth controllers"
    })?;
    diagnostic::emit(B::SignerCreate, Outcome::Complete);
    let [anchor, one, two] = public;
    let public = [
        anchor.ok_or("anchor public policy metadata")?,
        one.ok_or("first participant public policy metadata")?,
        two.ok_or("second participant public policy metadata")?,
    ];
    for (account, metadata) in accounts.iter().zip(&public) {
        if account.account_id() != metadata.account_id {
            return Err("actual pending identity differs from reviewed policy");
        }
    }
    Ok((
        accounts.map(|account| Some(State::Pending(account))),
        public,
    ))
}

fn poll_until(
    deadline: Instant,
    cancelled: &AtomicBool,
    mut poll: impl FnMut() -> wholepact_signer::Result<bool>,
    stage: &'static str,
) -> Result<()> {
    loop {
        if cancelled.load(Ordering::Acquire) {
            diagnostic::emit(B::SignerPollCancelled, Outcome::Begin);
            return Err("signer worker cancelled while polling");
        }
        if Instant::now() >= deadline {
            diagnostic::emit(B::SignerPollDeadline, Outcome::Begin);
            return Err("actual signer entry deadline elapsed");
        }
        let result = poll();
        if let Err(error) = &result {
            diagnostic::emit(B::SignerPollTerminal, diagnostic::signer_error(error));
        }
        if result.map_err(|error| signer_error(error, stage))? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(2));
    }
}

fn execute(
    command: JoinedSignerCommandV1,
    states: &mut [Option<State>; 3],
    public: &[OriginalPublic; 3],
    cancelled: &AtomicBool,
) -> Result<JoinedSignerReplyV1> {
    use JoinedSignerCommandV1 as C;
    use JoinedSignerReplyV1 as R;
    let index = match &command {
        C::ExportBirth(i)
        | C::Acknowledge(i)
        | C::OpenSingleIntent(i, _)
        | C::PollAndExportSingle(i)
        | C::OpenSinglePublication(i, _)
        | C::PollSinglePublication(i)
        | C::CloseSinglePublication(i)
        | C::OpenRosterIntent(i, _)
        | C::PollAndExportRoster(i)
        | C::OpenRosterPublication(i, _)
        | C::PollRosterPublication(i)
        | C::CloseRosterPublication(i)
        | C::OpenDurable(i, _)
        | C::PollDurablePair(i)
        | C::ConfigureDurableWitness(i)
        | C::PrepareDurableAdmission(i)
        | C::ApproveDurableAdmission(i)
        | C::ReconcileDurableWriter(i)
        | C::ConfigureDurableWallet(i, _)
        | C::AcceptDurable(i)
        | C::ArmInitial(i, _)
        | C::ArmCapture(i, _)
        | C::ArmRedisclosure(i, _)
        | C::PollImport(i, _, _)
        | C::PollFinancialImport(i, _, _)
        | C::SignDurableFixed(i, _)
        | C::ServeDurableResult(i, _)
        | C::PollDisclosure(i)
        | C::CaptureCommitted(i)
        | C::CloseDurable(i) => *i,
    };
    let slot = states.get_mut(index).ok_or("durable account index")?;
    let state = slot.take().ok_or("durable retained state missing")?;
    let (next, reply) = match (command, state) {
        (C::ExportBirth(_), State::Pending(account)) => {
            let exported = account
                .export_owner_request()
                .map_err(|error| signer_error(error, "native birth request sign and export"))?;
            let reply = R::BirthExport {
                index,
                account_id: exported.account_id().into(),
                birth_digest: exported.birth_digest().into(),
                exported_file: exported.exported_file().into(),
            };
            (State::ExportedBirth(exported), reply)
        }
        (C::Acknowledge(_), State::ExportedBirth(exported)) => {
            let account = exported.acknowledge_original().map_err(|error| {
                signer_error(error, "native original birth history and acknowledgement")
            })?;
            let metadata = &public[index];
            if account.account_id() != metadata.account_id {
                return Err("acknowledged identity differs from original policy");
            }
            let reply = R::Acknowledged(PublicJoinedBornV1 {
                index,
                account_id: account.account_id().into(),
                birth_digest: account.birth_digest().into(),
                full_viewing_key_digest: metadata.full_viewing_key_digest.clone(),
                network_profile_id: metadata.network_profile_id.clone(),
                participant_id: PARTICIPANT_IDS[index].into(),
                privacy_domain: account.privacy_domain().into(),
                public_receive_address: account.public_receive_address().into(),
                recipient_scope_digest: metadata.recipient_scope_digest.clone(),
            });
            (State::Acknowledged(account), reply)
        }
        (C::OpenSingleIntent(_, intent), State::Acknowledged(account)) if index == 0 => {
            let entry = account
                .open_first_anchor_intent(intent)
                .map_err(|error| signer_error(error, "native first anchor intent entry"))?;
            let reply = R::Peer(JoinedSignerPeerV1 {
                endpoint: entry
                    .endpoint()
                    .map_err(|error| signer_error(error, "single intent endpoint"))?,
                provider: entry
                    .provider()
                    .map_err(|error| signer_error(error, "single intent provider"))?,
                deadline: entry
                    .deadline()
                    .map_err(|error| signer_error(error, "single intent deadline"))?,
            });
            (State::SingleIntent(entry), reply)
        }
        (C::PollAndExportSingle(_), State::SingleIntent(mut entry)) if index == 0 => {
            poll_until(
                entry
                    .deadline()
                    .map_err(|error| signer_error(error, "single intent deadline"))?,
                cancelled,
                || entry.poll_initial_intent(),
                "native single pairing and exact intent retention",
            )?;
            diagnostic::emit(B::SignerExportSingle, Outcome::Begin);
            let exported = entry
                .export_original_single()
                .map_err(|error| signer_error(error, "native single owner signature and export"))?;
            let reply = R::SingleExport {
                index,
                signed_extension_file: exported.signed_extension_file().into(),
                enrollment_request: exported.enrollment_request().clone(),
            };
            (
                State::Acknowledged(exported.close_for_witness_review()),
                reply,
            )
        }
        (C::OpenSinglePublication(_, request), State::Acknowledged(account)) if index == 0 => {
            let entry = account
                .open_first_anchor_publication(request)
                .map_err(|error| signer_error(error, "native first anchor publication entry"))?;
            let reply = R::Peer(JoinedSignerPeerV1 {
                endpoint: entry
                    .endpoint()
                    .map_err(|error| signer_error(error, "single publication endpoint"))?,
                provider: entry
                    .provider()
                    .map_err(|error| signer_error(error, "single publication provider"))?,
                deadline: entry
                    .deadline()
                    .map_err(|error| signer_error(error, "single publication deadline"))?,
            });
            (State::SinglePublication(entry, false), reply)
        }
        (C::PollSinglePublication(_), State::SinglePublication(mut entry, false)) if index == 0 => {
            poll_until(
                entry
                    .deadline()
                    .map_err(|error| signer_error(error, "single publication deadline"))?,
                cancelled,
                || entry.poll_manual_publication(),
                "native single witness admission publication and serve",
            )?;
            // Hold the source until foreground Host publication really finishes.
            (State::SinglePublication(entry, true), R::Done { index })
        }
        (C::CloseSinglePublication(_), State::SinglePublication(entry, true)) if index == 0 => (
            State::Acknowledged(entry.close_for_continuation()),
            R::Done { index },
        ),
        (C::OpenRosterIntent(_, intent), State::Acknowledged(account)) if index > 0 => {
            let entry = account
                .open_initial_intent(intent)
                .map_err(|error| signer_error(error, "native roster intent entry"))?;
            let reply = R::Peer(JoinedSignerPeerV1 {
                endpoint: entry
                    .endpoint()
                    .map_err(|error| signer_error(error, "roster intent endpoint"))?,
                provider: entry
                    .provider()
                    .map_err(|error| signer_error(error, "roster intent provider"))?,
                deadline: entry
                    .deadline()
                    .map_err(|error| signer_error(error, "roster intent deadline"))?,
            });
            (State::RosterIntent(entry), reply)
        }
        (C::PollAndExportRoster(_), State::RosterIntent(mut entry)) if index > 0 => {
            poll_until(
                entry
                    .deadline()
                    .map_err(|error| signer_error(error, "roster intent deadline"))?,
                cancelled,
                || entry.poll_initial_intent(),
                "native roster pairing and exact intent retention",
            )?;
            diagnostic::emit(B::SignerExportRoster, Outcome::Begin);
            let exported = entry.export_original_roster().map_err(|error| {
                signer_error(error, "native roster owner signature and exact exports")
            })?;
            let reply = R::RosterExport {
                index,
                signed_extension_file: exported.signed_extension_file().into(),
                original_policy_file: exported.original_policy_file().into(),
                enrollment_request: exported.enrollment_request().clone(),
            };
            (
                State::Acknowledged(exported.close_for_witness_review()),
                reply,
            )
        }
        (C::OpenRosterPublication(_, request), State::Acknowledged(account)) if index > 0 => {
            let entry = account
                .open_initial_publication(request)
                .map_err(|error| signer_error(error, "native initial roster publication entry"))?;
            let reply = R::Peer(JoinedSignerPeerV1 {
                endpoint: entry
                    .endpoint()
                    .map_err(|error| signer_error(error, "roster publication endpoint"))?,
                provider: entry
                    .provider()
                    .map_err(|error| signer_error(error, "roster publication provider"))?,
                deadline: entry
                    .deadline()
                    .map_err(|error| signer_error(error, "roster publication deadline"))?,
            });
            (State::RosterPublication(entry, false), reply)
        }
        (C::PollRosterPublication(_), State::RosterPublication(mut entry, false)) if index > 0 => {
            poll_until(
                entry
                    .deadline()
                    .map_err(|error| signer_error(error, "roster publication deadline"))?,
                cancelled,
                || entry.poll_manual_publication(),
                "native roster witness admission publication and serve",
            )?;
            (State::RosterPublication(entry, true), R::Done { index })
        }
        (C::CloseRosterPublication(_), State::RosterPublication(entry, true)) if index > 0 => (
            State::Acknowledged(entry.close_for_continuation()),
            R::Done { index },
        ),

        (C::OpenDurable(_, proposal), State::Acknowledged(account)) if index > 0 => {
            let entry = account
                .open_fresh_durable(proposal, 1_000_000)
                .map_err(durable_entry_error)?;
            let reply = R::DurablePeer {
                index,
                peer: JoinedSignerPeerV1 {
                    endpoint: entry
                        .endpoint()
                        .map_err(|e| signer_error(e, "durable endpoint"))?,
                    provider: entry
                        .provider()
                        .map_err(|e| signer_error(e, "durable provider"))?,
                    deadline: entry
                        .deadline()
                        .map_err(|e| signer_error(e, "durable deadline"))?,
                },
                scope: entry.scope().clone(),
                entry_digest: entry.native_entry_digest().into(),
            };
            (State::Durable(Box::new(entry)), reply)
        }
        (C::PollDurablePair(_), State::Durable(mut entry)) => {
            poll_until(
                entry
                    .deadline()
                    .map_err(|e| signer_error(e, "durable pair deadline"))?,
                cancelled,
                || entry.poll_exact_pairing(),
                "exact durable pairing",
            )?;
            (State::Durable(entry), R::Done { index })
        }
        (C::AcceptDurable(_), State::Durable(mut entry)) => {
            let records = entry
                .accept_exact_manifest()
                .map_err(|e| signer_error(e, "fresh exact enrollment and manifest"))?;
            (State::Durable(entry), R::Records { index, records })
        }
        (C::ConfigureDurableWitness(_), State::Durable(mut entry)) if index > 0 => {
            entry
                .configure_original_witness()
                .map_err(|e| signer_error(e, "exact original witness native selection"))?;
            (State::Durable(entry), R::Done { index })
        }
        (C::PrepareDurableAdmission(_), State::Durable(mut entry)) if index > 0 => {
            // Only the actual current imported source prepares this inert
            // request. Returning it is not a native approval or witness issuer.
            let request = entry
                .prepare_durable_admission()
                .map_err(|e| signer_error(e, "source-bound exact durable admission preparation"))?;
            (
                State::Durable(entry),
                R::DurableAdmissionRequest { index, request },
            )
        }
        (C::ApproveDurableAdmission(_), State::Durable(mut entry)) if index > 0 => {
            // The production native approval retains its immutable intent
            // before the original owner mTLS submission. Uncertainty is final
            // for this positive fixture, never a reason to invent replacement.
            entry
                .approve_durable_admission()
                .map_err(|e| signer_error(e, "native retained-intent durable admission"))?;
            (State::Durable(entry), R::Done { index })
        }
        (C::ReconcileDurableWriter(_), State::Durable(mut entry)) if index > 0 => {
            entry
                .reconcile_original_writer()
                .map_err(|e| signer_error(e, "exact current writer native reconciliation"))?;
            (State::Durable(entry), R::Done { index })
        }
        (C::ConfigureDurableWallet(_, setup), State::Durable(mut entry)) if index > 0 => {
            entry
                .configure_durable_wallet(&setup)
                .map_err(|e| signer_error(e, "fresh exact durable viewing wallet native setup"))?;
            (State::Durable(entry), R::Done { index })
        }
        (C::ArmInitial(_, request), State::Durable(mut entry)) => {
            entry
                .expect_initial_disclosure(request)
                .map_err(|e| signer_error(e, "exact initial disclosure expectation"))?;
            (State::Durable(entry), R::Done { index })
        }
        (C::ArmCapture(_, request), State::Durable(mut entry)) => {
            entry
                .expect_durable_capture(request)
                .map_err(|e| signer_error(e, "exact durable capture expectation"))?;
            (State::Durable(entry), R::Done { index })
        }
        (C::ArmRedisclosure(_, request), State::Durable(mut entry)) => {
            entry
                .expect_redisclosure(request)
                .map_err(|e| signer_error(e, "fresh exact redisclosure expectation"))?;
            (State::Durable(entry), R::Done { index })
        }
        (C::PollImport(_, request, identity), State::Durable(mut entry)) => {
            poll_until(
                entry
                    .deadline()
                    .map_err(|e| signer_error(e, "import deadline"))?,
                cancelled,
                || entry.poll_exact_import(&request, &identity),
                "exact memory-only fixed import",
            )?;
            (State::Durable(entry), R::Done { index })
        }
        (C::PollFinancialImport(_, request, identity), State::Durable(mut entry)) if index > 0 => {
            // This distinct command cannot weaken the baseline import-only
            // helper's requirement that no current writer was reconciled.
            poll_until(
                entry
                    .deadline()
                    .map_err(|e| signer_error(e, "financial import deadline"))?,
                cancelled,
                || entry.poll_financial_import(&request, &identity),
                "exact fixed import with separately reconciled current writer",
            )?;
            (State::Durable(entry), R::Done { index })
        }
        (C::SignDurableFixed(_, identity), State::Durable(mut entry)) if index > 0 => {
            // The real helper checks its original result/ledger on retry and
            // refuses any new native review, wallet job or reservation there.
            let (history, commit) = entry
                .sign_durable_fixed(&identity)
                .map_err(|e| signer_error(e, "exact fixed native sign or retained-result retry"))?;
            (
                State::Durable(entry),
                R::DurableAuthorization {
                    index,
                    history,
                    commit,
                },
            )
        }
        (C::ServeDurableResult(_, stop), State::Durable(mut entry)) if index > 0 => {
            // Only poll the retained genuine native owner. The caller's stop
            // flag cannot approve a prompt or extend the original deadline.
            poll_until(
                entry
                    .deadline()
                    .map_err(|e| signer_error(e, "retained result service deadline"))?,
                cancelled,
                || {
                    if stop.load(Ordering::Acquire) {
                        return Ok(true);
                    }
                    entry.poll_data_only()?;
                    Ok(false)
                },
                "nonapproving exact retained native result service",
            )?;
            (State::Durable(entry), R::Done { index })
        }
        (C::PollDisclosure(_), State::Durable(mut entry)) => {
            poll_until(
                entry
                    .deadline()
                    .map_err(|e| signer_error(e, "disclosure deadline"))?,
                cancelled,
                || entry.poll_exact_disclosure(),
                "exact privacy disclosure",
            )?;
            (State::Durable(entry), R::Done { index })
        }
        (C::CaptureCommitted(_), State::Durable(entry)) => {
            let reference = entry
                .exact_durable_disclosure_committed()
                .map_err(|e| signer_error(e, "native immutable outbox commit"))?;
            (
                State::Durable(entry),
                R::CaptureCommitted { index, reference },
            )
        }
        (C::CloseDurable(_), State::Durable(entry)) => {
            let account = entry
                .close_original_entry()
                .map_err(|e| signer_error(e, "native revoke and drain"))?;
            (State::Acknowledged(account), R::Done { index })
        }
        _ => return Err("durable finite native transition mismatch"),
    };
    *slot = Some(next);
    Ok(reply)
}
