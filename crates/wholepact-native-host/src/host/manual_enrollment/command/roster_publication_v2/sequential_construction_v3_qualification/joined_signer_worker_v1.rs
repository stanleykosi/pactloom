//! Finite, synthetic-only same-image signer worker for the joined Host fixture.
//!
//! All real signer controllers are constructed and remain on this thread. Only
//! ordinary public metadata, exact production-exported file paths and actual
//! installed-provider/endpoint metadata cross the channel. The foreground Host
//! retains its own native prompt owners and obtains leases through ordinary IPC.
//! This is not attended native evidence or a network-funded wallet fixture.

#![cfg(all(test, feature = "synthetic-born-joined-qualification"))]

#[path = "joined_signer_worker_v1/named_payment_v1.rs"]
mod named_payment_v1;
pub(super) use named_payment_v1::{Command as JoinedNamedCommandV1, Reply as JoinedNamedReplyV1};

use super::safe_diagnostics_v1::{self as diagnostic, Boundary as B, Outcome};
use sha2::{Digest, Sha256};
fn signer_error(error: wholepact_signer::Error, label: &'static str) -> &'static str {
    let boundary = match label {
        "native first anchor intent entry"
        | "native first anchor publication entry"
        | "native roster intent entry"
        | "native initial roster publication entry" => B::SignerNativeEntry,
        "single intent endpoint"
        | "single publication endpoint"
        | "roster intent endpoint"
        | "roster publication endpoint" => B::SignerEndpoint,
        "single intent provider"
        | "single publication provider"
        | "roster intent provider"
        | "roster publication provider" => B::SignerProvider,
        "single intent deadline"
        | "single publication deadline"
        | "roster intent deadline"
        | "roster publication deadline" => B::SignerDeadline,
        _ => B::SignerPeerMetadata,
    };
    diagnostic::emit(boundary, diagnostic::signer_error(&error));
    label
}
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, Sender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use wholepact_authority::{
    AccountPolicy,
    native_witness_owner::{
        EphemeralBornTransportPublicPinV1, EphemeralConstructionClientScopeV1,
        EphemeralWitnessOriginV1,
    },
};
use wholepact_core::born_recipient_policy_v2::{
    BornConstructionRecipientPolicyV2, BornOriginalLimitsV2, BornOwnReturnRuleV2,
    BornRecipientLimitV2,
};
use wholepact_signer::native_ui::synthetic_born_joined_qualification::{
    EphemeralAcknowledgedBornV1, EphemeralCommonContextCompletionV3, EphemeralCommonContextReadV3,
    EphemeralConsumedNamedV3, EphemeralContinuationIntentV1, EphemeralContinuedPublicationV1,
    EphemeralDormantCommonContextV3, EphemeralExportedBirthV1, EphemeralFirstAnchorIntentV1,
    EphemeralFirstAnchorPublicationV1, EphemeralNamedPaymentV1, EphemeralNamedVerifierV1,
    EphemeralOriginalRosterIntentV1, EphemeralPendingBornV1, EphemeralRosterPublicationV1,
    ExpectedCommonContextReadV3Input, ExpectedCompletionOperationsV3Input,
    ExpectedRosterDisclosuresV1, OriginalBirthSetupV1,
};
use wholepact_signer_origin::{
    InstalledSignerProvider,
    manual::{HostManualEnrollmentIntent, HostManualEnrollmentRequest},
    manual_roster_v2::{
        HostManualRosterEnrollmentIntentV2, HostManualRosterEnrollmentRequestV2,
        HostManualRosterPublicationRequestV2,
    },
};

type Result<T> = std::result::Result<T, &'static str>;
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

/// Ordinary public values copied from the actual generated account and the
/// exact stable policy that passed its native birth review. No FVK or seed.
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
    Named(JoinedNamedCommandV1),
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
    OpenContinuationIntent(usize, HostManualRosterEnrollmentIntentV2),
    PollAndExportContinuation(usize),
    OpenContinuedPublication(
        usize,
        HostManualRosterPublicationRequestV2,
        Option<ExpectedRosterDisclosuresV1>,
    ),
    PollContinuedPublicationAndDisclosures(usize),
    CloseContinuedPublication(usize),
    SignAndExportOriginalFullPlan(usize, PathBuf),
    OpenCommonContextRead(
        usize,
        HostManualRosterPublicationRequestV2,
        ExpectedCommonContextReadV3Input,
    ),
    PollCommonContextReadAndHandoff(usize),
    ParkCommonContextCompletion(usize),
    OpenOriginalCompletion(
        usize,
        ExpectedCompletionOperationsV3Input,
        EphemeralConstructionClientScopeV1,
    ),
    PollOriginalCompletionAndPark(usize),
    OpenOriginalNamedPayment(usize),
    PollOriginalNamedPayment(usize),
    RetainOriginalNamedProfile(
        usize,
        EphemeralBornTransportPublicPinV1,
        wholepact_transport::TransportPublicKey,
    ),
}
/// Historical public provenance of the actual original profile setup. Only the
/// finite same-controller worker branch below constructs this private value.
/// No native authority, profile secret, raw decision or replacement pin escapes.
pub(super) struct JoinedOriginalProfilePublicV1 {
    index: usize,
    account_id: String,
    profile_ref: String,
    setup_commitment: String,
    signer_public: wholepact_transport::TransportPublicKey,
    verifier_signing_public: [u8; 32],
    verifier_transport_public: [u8; 32],
}
impl JoinedOriginalProfilePublicV1 {
    pub(super) fn index(&self) -> usize {
        self.index
    }
    pub(super) fn account_id(&self) -> &str {
        &self.account_id
    }
    pub(super) fn profile_ref(&self) -> &str {
        &self.profile_ref
    }
    pub(super) fn setup_commitment(&self) -> &str {
        &self.setup_commitment
    }
    pub(super) fn signer_public_key(&self) -> &wholepact_transport::TransportPublicKey {
        &self.signer_public
    }
    pub(super) fn verifier_public_keys(&self) -> ([u8; 32], [u8; 32]) {
        (self.verifier_signing_public, self.verifier_transport_public)
    }
}
pub(super) enum JoinedSignerReplyV1 {
    Named(JoinedNamedReplyV1),
    NamedPeer {
        index: usize,
        peer: JoinedSignerPeerV1,
        scope: wholepact_signer_origin::PairScope,
    },
    OriginalProfile(JoinedOriginalProfilePublicV1),
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
    FullPlanExport {
        index: usize,
        signed_plan_file: PathBuf,
    },
    ContinuationExport {
        index: usize,
        signed_continuation_file: PathBuf,
    },
    Done {
        index: usize,
    },
}

/// Dropping this handle cancels polling, then joins the worker. The signer
/// facades in the worker revoke their actual owners and drain admitted work
/// before their concrete temporary roots and witness installation can drop.
/// Callers must not retain/use the reported endpoints or files after shutdown.
pub(super) struct JoinedSignerWorkerV1 {
    commands: Option<Sender<JoinedSignerCommandV1>>,
    replies: Receiver<Result<JoinedSignerReplyV1>>,
    cancelled: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}
enum OriginalWitnessOriginsV1 {
    ConstructorOnly(EphemeralWitnessOriginV1),
    Distinct([EphemeralWitnessOriginV1; 3]),
}
impl JoinedSignerWorkerV1 {
    pub fn spawn(
        origin: EphemeralWitnessOriginV1,
        payment_receiver: String,
        expiry_ms: u64,
    ) -> Result<Self> {
        Self::spawn_originals(
            OriginalWitnessOriginsV1::ConstructorOnly(origin),
            payment_receiver,
            expiry_ms,
        )
    }
    /// All original witness owners/pins already exist before this actual worker
    /// enters any birth. This never replaces a retained account's endpoint.
    pub(super) fn spawn_with_original_witnesses(
        origins: [EphemeralWitnessOriginV1; 3],
        payment_receiver: String,
        expiry_ms: u64,
    ) -> Result<Self> {
        Self::spawn_originals(
            OriginalWitnessOriginsV1::Distinct(origins),
            payment_receiver,
            expiry_ms,
        )
    }
    fn spawn_originals(
        origins: OriginalWitnessOriginsV1,
        payment_receiver: String,
        expiry_ms: u64,
    ) -> Result<Self> {
        let (commands, incoming) = mpsc::channel();
        let (outgoing, replies) = mpsc::channel();
        let (started, startup) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = cancelled.clone();
        let join = thread::Builder::new()
            .name("synthetic-born-joined-signer".into())
            // This finite worker retains three genuine native controller states.
            // The measured release entry frame is 2.74MiB before startup, above
            // Rust's default2MiB. Keep headroom local to this test-only worker;
            // do not change process/OS limits or production authority clocks.
            .stack_size(8 * 1024 * 1024)
            .spawn(move || {
                // No native owner is captured by the thread closure. Actual
                // runtime entry and every subsequent controller occur here.
                let initial = create_originals(origins, &payment_receiver, expiry_ms);
                let (mut states, public) = match initial {
                    Ok(value) => value,
                    Err(stage) => {
                        let _ = started.send(Err(stage));
                        return;
                    }
                };
                if started.send(Ok(())).is_err() {
                    return;
                }
                // One genuine verifier for BOTH original named profiles. It is
                // created once before the first profile review and remains on
                // this same worker for the later joint assertion ceremonies.
                let mut verifier: Option<Box<EphemeralNamedVerifierV1>> = None;
                let mut named_progress = named_payment_v1::Progress::default();
                while !worker_cancelled.load(Ordering::Acquire) {
                    let command = match incoming.recv_timeout(Duration::from_millis(20)) {
                        Ok(command) => command,
                        Err(RecvTimeoutError::Timeout) => {
                            if let Err(error) = named_payment_v1::poll_idle(
                                &mut states,
                                &named_progress,
                                &worker_cancelled,
                            ) {
                                let _ = outgoing.send(Err(error));
                                break;
                            }
                            continue;
                        }
                        Err(RecvTimeoutError::Disconnected) => break,
                    };
                    let reply = execute(
                        command,
                        &mut states,
                        &public,
                        &mut verifier,
                        &mut named_progress,
                        &worker_cancelled,
                    );
                    let failed = reply.is_err();
                    if outgoing.send(reply).is_err() || failed {
                        break;
                    }
                }
                // This is the last owner of every signer controller. Their Drop
                // implementations drain effects before their temporary owners.
                // Cancel/drain verifier FVK work while signer controllers and
                // their original temporary installations are still alive.
                drop(verifier);
                drop(states);
            })
            .map_err(|_| "signer worker thread creation")?;
        let mut worker = Self {
            commands: Some(commands),
            replies,
            cancelled,
            join: Some(join),
        };
        match startup.recv() {
            Ok(Ok(())) => Ok(worker),
            Ok(Err(stage)) => {
                worker.stop_and_join()?;
                Err(stage)
            }
            Err(_) => {
                worker.stop_and_join()?;
                Err("signer worker startup disconnected")
            }
        }
    }
    /// Send a polling operation before entering the Host's blocking submit or
    /// finish call. Keep the returned actual NativeManualClient alive through
    /// export completion; dropping it earlier correctly revokes signer review.
    pub fn send(&self, command: JoinedSignerCommandV1) -> Result<()> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err("signer worker cancelled");
        }
        self.commands
            .as_ref()
            .ok_or("signer worker closed")?
            .send(command)
            .map_err(|_| "signer worker command disconnected")
    }
    pub fn recv(&self) -> Result<JoinedSignerReplyV1> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err("signer worker cancelled");
        }
        let reply = self
            .replies
            .recv()
            .map_err(|_| "signer worker reply disconnected")?;
        if self.cancelled.load(Ordering::Acquire) {
            return Err("signer worker cancelled");
        }
        reply
    }
    /// Restricts only the current receive. A timeout is uncertain: permanently
    /// cancel this finite worker and never consume a late reply as a new phase.
    /// Existing worker Drop still drains actual already-started native work.
    pub fn receive_until(&self, original_deadline: Instant) -> Result<JoinedSignerReplyV1> {
        let reply =
            receive_original_reply_until(&self.replies, &self.cancelled, original_deadline)?;
        if reply.is_err() {
            self.cancelled.store(true, Ordering::Release);
        }
        reply
    }
    pub fn receive(&self) -> Result<JoinedSignerReplyV1> {
        self.recv()
    }
    pub fn shutdown(mut self) -> Result<()> {
        self.stop_and_join()
    }
    fn stop_and_join(&mut self) -> Result<()> {
        self.cancelled.store(true, Ordering::Release);
        self.commands.take();
        if let Some(join) = self.join.take() {
            join.join().map_err(|_| "signer worker panicked")?;
        }
        Ok(())
    }
}
impl Drop for JoinedSignerWorkerV1 {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
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
    ContinuationIntent(Box<EphemeralContinuationIntentV1>),
    ContinuedPublication(Box<EphemeralContinuedPublicationV1>, bool),
    CommonContextRead(Box<EphemeralCommonContextReadV3>, bool),
    DormantCommonContext(Box<EphemeralDormantCommonContextV3>),
    OriginalCompletion(Box<EphemeralCommonContextCompletionV3>),
    // Retained for the consuming named facade, never exported across threads.
    ConsumedNamed {
        _original: Box<EphemeralConsumedNamedV3>,
    },
    NamedPayment(Box<EphemeralNamedPaymentV1>, bool),
    NamedProfile {
        _original: Box<EphemeralNamedPaymentV1>,
    },
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
            return Err("signer worker cancelled while polling");
        }
        if Instant::now() >= deadline {
            return Err("actual signer entry deadline elapsed");
        }
        if poll().map_err(|error| signer_error(error, stage))? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(2));
    }
}

fn execute(
    command: JoinedSignerCommandV1,
    states: &mut [Option<State>; 3],
    public: &[OriginalPublic; 3],
    verifier: &mut Option<Box<EphemeralNamedVerifierV1>>,
    named_progress: &mut named_payment_v1::Progress,
    cancelled: &AtomicBool,
) -> Result<JoinedSignerReplyV1> {
    use JoinedSignerCommandV1 as C;
    let boundary = match &command {
        C::Named(command) => command.boundary(),
        C::ExportBirth(_) => B::SignerExportBirth,
        C::Acknowledge(_) => B::SignerAcknowledge,
        C::OpenSingleIntent(..) => B::SignerOpenSingleIntent,
        C::PollAndExportSingle(_) => B::SignerPollSingleIntent,
        C::OpenSinglePublication(..) => B::SignerOpenSinglePublication,
        C::PollSinglePublication(_) => B::SignerPollSinglePublication,
        C::CloseSinglePublication(_) => B::SignerCloseSinglePublication,
        C::OpenRosterIntent(..) => B::SignerOpenRosterIntent,
        C::PollAndExportRoster(_) => B::SignerPollRosterIntent,
        C::OpenRosterPublication(..) => B::SignerOpenRosterPublication,
        C::PollRosterPublication(_) => B::SignerPollRosterPublication,
        C::CloseRosterPublication(_) => B::SignerCloseRosterPublication,
        C::OpenContinuationIntent(..) => B::SignerOpenContinuationIntent,
        C::PollAndExportContinuation(_) => B::SignerPollContinuationIntent,
        C::OpenContinuedPublication(..) => B::SignerOpenContinuedPublication,
        C::PollContinuedPublicationAndDisclosures(_) => B::SignerPollContinuedPublication,
        C::CloseContinuedPublication(_) => B::SignerCloseContinuedPublication,
        C::SignAndExportOriginalFullPlan(..) => B::SignerExportOriginalFullPlan,
        C::OpenCommonContextRead(..) => B::SignerOpenCommonContextRead,
        C::PollCommonContextReadAndHandoff(_) => B::SignerPollCommonContextRead,
        C::ParkCommonContextCompletion(_) => B::SignerParkCommonContextCompletion,
        C::OpenOriginalCompletion(..) => B::SignerOpenOriginalCompletion,
        C::PollOriginalCompletionAndPark(_) => B::SignerPollOriginalCompletion,
        C::OpenOriginalNamedPayment(_) => B::SignerOpenOriginalNamed,
        C::PollOriginalNamedPayment(_) => B::SignerPollOriginalNamed,
        C::RetainOriginalNamedProfile(..) => B::SignerRetainOriginalProfile,
    };
    diagnostic::emit(boundary, Outcome::Begin);
    let result = execute_inner(command, states, public, verifier, named_progress, cancelled);
    diagnostic::emit(
        boundary,
        if result.is_ok() {
            Outcome::Complete
        } else {
            Outcome::WorkerFailure
        },
    );
    result
}

fn execute_inner(
    command: JoinedSignerCommandV1,
    states: &mut [Option<State>; 3],
    public: &[OriginalPublic; 3],
    verifier: &mut Option<Box<EphemeralNamedVerifierV1>>,
    named_progress: &mut named_payment_v1::Progress,
    cancelled: &AtomicBool,
) -> Result<JoinedSignerReplyV1> {
    use JoinedSignerCommandV1 as C;
    use JoinedSignerReplyV1 as R;
    let command = match command {
        C::Named(command) => {
            return named_payment_v1::execute(command, states, verifier, named_progress, cancelled)
                .map(R::Named);
        }
        original => original,
    };
    let index = match &command {
        C::Named(_) => return Err("named command dispatch mismatch"),
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
        | C::OpenContinuationIntent(i, _)
        | C::PollAndExportContinuation(i)
        | C::OpenContinuedPublication(i, _, _)
        | C::PollContinuedPublicationAndDisclosures(i)
        | C::CloseContinuedPublication(i)
        | C::SignAndExportOriginalFullPlan(i, _)
        | C::OpenCommonContextRead(i, _, _)
        | C::PollCommonContextReadAndHandoff(i)
        | C::ParkCommonContextCompletion(i)
        | C::OpenOriginalCompletion(i, _, _)
        | C::PollOriginalCompletionAndPark(i)
        | C::OpenOriginalNamedPayment(i)
        | C::PollOriginalNamedPayment(i)
        | C::RetainOriginalNamedProfile(i, _, _) => *i,
    };
    let slot = states.get_mut(index).ok_or("signer account index")?;
    let state = slot.take().ok_or("signer account has no retained state")?;
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
        (C::OpenContinuationIntent(_, intent), State::Acknowledged(account)) if index > 0 => {
            let entry = account.open_continuation_intent(intent).map_err(|error| {
                signer_error(error, "native original continuation intent entry")
            })?;
            let reply = R::Peer(JoinedSignerPeerV1 {
                endpoint: entry
                    .endpoint()
                    .map_err(|error| signer_error(error, "continuation intent endpoint"))?,
                provider: entry
                    .provider()
                    .map_err(|error| signer_error(error, "continuation intent provider"))?,
                deadline: entry
                    .deadline()
                    .map_err(|error| signer_error(error, "continuation intent deadline"))?,
            });
            (State::ContinuationIntent(Box::new(entry)), reply)
        }
        (C::PollAndExportContinuation(_), State::ContinuationIntent(mut entry)) if index > 0 => {
            poll_until(
                entry
                    .deadline()
                    .map_err(|error| signer_error(error, "continuation intent deadline"))?,
                cancelled,
                || entry.poll_continuation_proposal(),
                "native original continuation pairing and proposal",
            )?;
            let exported = (*entry).export_continuation().map_err(|error| {
                signer_error(error, "native continuation owner signature and export")
            })?;
            let reply = R::ContinuationExport {
                index,
                signed_continuation_file: exported.exported_file().into(),
            };
            (
                State::Acknowledged(exported.close_for_witness_review()),
                reply,
            )
        }
        (C::OpenContinuedPublication(_, request, disclosures), State::Acknowledged(account))
            if index > 0 =>
        {
            let entry = account
                .open_continued_publication(request, disclosures)
                .map_err(|error| signer_error(error, "native continued publication entry"))?;
            let reply = R::Peer(JoinedSignerPeerV1 {
                endpoint: entry
                    .endpoint()
                    .map_err(|error| signer_error(error, "continued publication endpoint"))?,
                provider: entry
                    .provider()
                    .map_err(|error| signer_error(error, "continued publication provider"))?,
                deadline: entry
                    .deadline()
                    .map_err(|error| signer_error(error, "continued publication deadline"))?,
            });
            (State::ContinuedPublication(Box::new(entry), false), reply)
        }
        (
            C::PollContinuedPublicationAndDisclosures(_),
            State::ContinuedPublication(mut entry, false),
        ) if index > 0 => {
            poll_until(
                entry
                    .deadline()
                    .map_err(|error| signer_error(error, "continued publication deadline"))?,
                cancelled,
                || entry.poll_manual_publication_and_disclosures(),
                "native continued publication and exact disclosures",
            )?;
            // Host must still finish actual append/inventory/selection/retention.
            // Keep this genuine native controller owned until its explicit close.
            (State::ContinuedPublication(entry, true), R::Done { index })
        }
        (C::CloseContinuedPublication(_), State::ContinuedPublication(entry, true))
            if index > 0 =>
        {
            (
                State::Acknowledged((*entry).close_for_next_continuation()),
                R::Done { index },
            )
        }

        (C::SignAndExportOriginalFullPlan(_, actual_plan_file), State::Acknowledged(account))
            if index > 0 =>
        {
            let exported = account
                .sign_and_export_original_full_plan_v3(&actual_plan_file)
                .map_err(|error| {
                    signer_error(
                        error,
                        "native exact original full-plan signature and export",
                    )
                })?;
            let reply = R::FullPlanExport {
                index,
                signed_plan_file: exported.exported_file().into(),
            };
            (
                State::Acknowledged(exported.close_for_witness_review()),
                reply,
            )
        }
        (C::OpenCommonContextRead(_, publication, expected), State::Acknowledged(account))
            if index > 0 =>
        {
            let entry = account
                .open_common_context_read_v3(publication, expected)
                .map_err(|error| {
                    signer_error(
                        error,
                        "native newer publication and exact common-context read entry",
                    )
                })?;
            let reply = R::Peer(JoinedSignerPeerV1 {
                endpoint: entry
                    .endpoint()
                    .map_err(|error| signer_error(error, "common-context read endpoint"))?,
                provider: entry
                    .provider()
                    .map_err(|error| signer_error(error, "common-context read provider"))?,
                deadline: entry
                    .deadline()
                    .map_err(|error| signer_error(error, "common-context read deadline"))?,
            });
            (State::CommonContextRead(Box::new(entry), false), reply)
        }
        (C::PollCommonContextReadAndHandoff(_), State::CommonContextRead(mut entry, false))
            if index > 0 =>
        {
            poll_until(
                entry
                    .deadline()
                    .map_err(|error| signer_error(error, "common-context read deadline"))?,
                cancelled,
                || entry.poll_publication_read_and_handoff(),
                "native exact publication read and handoff",
            )?;
            // The Host must complete its one actual observation before this
            // controller is parked. The pending handoff is still not Reserve.
            (State::CommonContextRead(entry, true), R::Done { index })
        }
        (C::ParkCommonContextCompletion(_), State::CommonContextRead(entry, true)) if index > 0 => {
            let dormant = (*entry).park_original_completion().map_err(|error| {
                signer_error(error, "native original completion park and drain")
            })?;
            (
                State::DormantCommonContext(Box::new(dormant)),
                R::Done { index },
            )
        }

        (C::OpenOriginalCompletion(_, expected, scope), State::DormantCommonContext(original))
            if index > 0 =>
        {
            // Consuming the actual dormant predecessor and exact native-issued
            // scope once is mandatory. No boolean, pending DTO or factory can
            // select this branch from an acknowledged/bare account state.
            let entry = (*original)
                .open_original_completion(expected, scope)
                .map_err(|error| signer_error(error, "native exact original completion reopen"))?;
            let reply = R::Peer(JoinedSignerPeerV1 {
                endpoint: entry
                    .endpoint()
                    .map_err(|error| signer_error(error, "original completion endpoint"))?,
                provider: entry
                    .provider()
                    .map_err(|error| signer_error(error, "original completion provider"))?,
                deadline: entry
                    .deadline()
                    .map_err(|error| signer_error(error, "original completion deadline"))?,
            });
            (State::OriginalCompletion(Box::new(entry)), reply)
        }
        (C::PollOriginalCompletionAndPark(_), State::OriginalCompletion(mut entry))
            if index > 0 =>
        {
            poll_until(
                entry
                    .deadline()
                    .map_err(|error| signer_error(error, "original completion deadline"))?,
                cancelled,
                || entry.poll_exact_completion_and_park(),
                "native exact original completion and named park",
            )?;
            // This extracts only the actual consumed + revoked/drained named
            // predecessor. The controller remains on this same worker thread.
            let original = (*entry).take_consumed_named_original().map_err(|error| {
                signer_error(error, "native consumed named predecessor retention")
            })?;
            (
                State::ConsumedNamed {
                    _original: Box::new(original),
                },
                R::Done { index },
            )
        }

        (
            C::OpenOriginalNamedPayment(_),
            State::ConsumedNamed {
                _original: original,
            },
        ) if index > 0 => {
            let entry = (*original)
                .reopen_original_named_payment()
                .map_err(|error| signer_error(error, "actual consumed original named entry"))?;
            let scope = entry
                .pairing_scope()
                .map_err(|error| signer_error(error, "actual original named pairing scope"))?;
            if scope.account_id != public[index].account_id {
                return Err("named scope differs from original account");
            }
            let peer = JoinedSignerPeerV1 {
                endpoint: entry
                    .endpoint()
                    .map_err(|error| signer_error(error, "named payment endpoint"))?,
                provider: entry
                    .provider()
                    .map_err(|error| signer_error(error, "named payment provider"))?,
                deadline: entry
                    .deadline()
                    .map_err(|error| signer_error(error, "named payment deadline"))?,
            };
            (
                State::NamedPayment(Box::new(entry), false),
                R::NamedPeer { index, peer, scope },
            )
        }
        (C::PollOriginalNamedPayment(_), State::NamedPayment(mut entry, false)) if index > 0 => {
            poll_until(
                entry
                    .deadline()
                    .map_err(|error| signer_error(error, "named payment deadline"))?,
                cancelled,
                || entry.poll_exact_pairing_and_local_records(),
                "actual named Pair Status enrollment and manifest",
            )?;
            (State::NamedPayment(entry, true), R::Done { index })
        }
        (
            C::RetainOriginalNamedProfile(_, witness_pin, host_public),
            State::NamedPayment(mut entry, true),
        ) if index > 0 => {
            if witness_pin.account_id() != public[index].account_id {
                return Err("profile witness snapshot differs from actual account");
            }
            // BOTH actual profiles must pin the SAME real verifier owner,
            // otherwise its later exact joint-FVK request cannot be admitted.
            if verifier.is_none() {
                *verifier = Some(Box::new(EphemeralNamedVerifierV1::create().map_err(
                    |error| signer_error(error, "actual ephemeral named verifier creation"),
                )?));
            }
            let verifier = verifier
                .as_deref()
                .ok_or("actual shared verifier unavailable")?;
            let (profile_ref, setup_commitment, signer_key) = entry
                .retain_original_profile(verifier, &witness_pin, &host_public)
                .map_err(|error| signer_error(error, "actual original named profile setup"))?;
            let (verifier_signing_public, verifier_transport_public) = verifier
                .public_keys()
                .map_err(|error| signer_error(error, "actual named verifier public keys"))?;
            let signer_public = wholepact_transport::TransportPublicKey::from_bytes(signer_key)
                .map_err(|_| "actual named signer public key encoding")?;
            let projection = JoinedOriginalProfilePublicV1 {
                index,
                account_id: public[index].account_id.clone(),
                profile_ref,
                setup_commitment,
                signer_public,
                verifier_signing_public,
                verifier_transport_public,
            };
            (
                State::NamedProfile { _original: entry },
                R::OriginalProfile(projection),
            )
        }
        _ => return Err("signer command does not match retained native lifecycle"),
    };
    *slot = Some(next);
    Ok(reply)
}

/// Pure channel bound, not an owner or controller constructor.
fn receive_original_reply_until<T>(
    receiver: &Receiver<T>,
    cancelled: &AtomicBool,
    deadline: Instant,
) -> Result<T> {
    let receive = || {
        if cancelled.load(Ordering::Acquire) {
            return Err("signer worker cancelled");
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or("signer worker original receive deadline")?;
        let value = receiver
            .recv_timeout(remaining)
            .map_err(|_| "signer worker reply timeout or disconnect; original outcome uncertain")?;
        if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
            return Err("signer worker original receive expired; original outcome uncertain");
        }
        Ok(value)
    };
    let result = receive();
    if result.is_err() {
        cancelled.store(true, Ordering::Release);
    }
    result
}
#[cfg(test)]
mod bounded_reply_tests {
    use super::*;
    #[test]
    fn original_reply_expired_or_cancelled_never_consumes_queued_late_reply() {
        for cancelled_before in [false, true] {
            let (send, receive) = mpsc::channel();
            send.send(7u8).unwrap();
            let cancelled = AtomicBool::new(cancelled_before);
            let deadline = if cancelled_before {
                Instant::now() + Duration::from_secs(1)
            } else {
                Instant::now()
            };
            assert!(receive_original_reply_until(&receive, &cancelled, deadline).is_err());
            assert!(cancelled.load(Ordering::Acquire));
            assert_eq!(receive.try_recv().unwrap(), 7);
            assert!(
                receive_original_reply_until(
                    &receive,
                    &cancelled,
                    Instant::now() + Duration::from_secs(1)
                )
                .is_err()
            );
        }
    }
    #[test]
    fn original_reply_timeout_poison_is_permanent_and_no_deadline_reset_occurs() {
        let (send, receive) = mpsc::channel();
        let cancelled = AtomicBool::new(false);
        assert!(
            receive_original_reply_until(
                &receive,
                &cancelled,
                Instant::now() + Duration::from_millis(2)
            )
            .is_err()
        );
        send.send(7u8).unwrap();
        assert!(
            receive_original_reply_until(
                &receive,
                &cancelled,
                Instant::now() + Duration::from_secs(1)
            )
            .is_err()
        );
        assert_eq!(receive.try_recv().unwrap(), 7);
    }
    #[test]
    fn original_reply_current_value_only_returns_once() {
        let (send, receive) = mpsc::channel();
        send.send(7u8).unwrap();
        let cancelled = AtomicBool::new(false);
        assert_eq!(
            receive_original_reply_until(
                &receive,
                &cancelled,
                Instant::now() + Duration::from_secs(1)
            )
            .unwrap(),
            7
        );
        assert!(!cancelled.load(Ordering::Acquire));
        drop(send);
        assert!(
            receive_original_reply_until(
                &receive,
                &cancelled,
                Instant::now() + Duration::from_secs(1)
            )
            .is_err()
        );
        assert!(cancelled.load(Ordering::Acquire));
    }
}
