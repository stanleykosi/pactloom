//! A separate bounded native owner for born manual enrollment. It never calls
//! ordinary runtime activation. All keys, I/O and durable writes stay on workers.
#[cfg(feature = "synthetic-born-joined-qualification")]
#[path = "../qualification/born_manual_roster.rs"]
pub(in crate::native_ui) mod born_manual_roster;

// Closed synthetic diagnostics preserve exact predicate evaluation and results.
#[cfg(feature = "synthetic-born-joined-qualification")]
mod synthetic_diagnostics;
macro_rules! roster_clear_if {
    ($condition:expr, $reason:ident) => {{
        let condition = $condition;
        #[cfg(feature = "synthetic-born-joined-qualification")]
        if condition {
            synthetic_diagnostics::report_begin(synthetic_diagnostics::Operation::$reason);
        }
        condition
    }};
}

mod admission;
mod permanent_stop;
mod permanent_stop_export;
mod permanent_stop_flow;
pub(crate) mod permanent_stop_publication;
mod common_context_handoff;
mod common_context_reentry;
pub(in crate::native_ui) mod named_continuation;
mod named_controls;
mod named_reentry;
mod named_reentry_witness;
#[cfg(feature = "offline-review-foundation")]
mod named_verifier_disclosure;
#[cfg(feature = "offline-review-foundation")]
mod named_bridge;
#[cfg(feature="offline-review-foundation")]
mod named_enrollment_export;
mod construction_export;
mod construction_export_v3;
mod construction_signing;
mod construction_signing_v3;
mod continuation_controller;
mod continuation_export;
mod continuation_signing;
mod continuation_witness;
mod controller;
mod export;
mod policy_export_v2;
mod signing;
pub(in crate::native_ui) mod witness;
use super::{
    authority::{ExactNativeReview, PendingAccountNativeAuthority},
    runtime::{AuthenticatedPairing, PendingBirthEntry},
    state::inert_text,
    witness_workspace::{
        ApprovedWriterActivation, ApprovedWriterSession, NativeWitnessWorkspace,
        PreparedWriterActivation, PreparedWriterSession,
    },
    NativeDecision,
};
use crate::account::birth::enrollment::roster_v2::continuation::{
    self as attempts, ApprovedContinuedReentry, PreparedContinuationProposal,
    PreparedContinuedReentry, RetainedContinuation,
};
use crate::account::birth::enrollment::roster_v2::inventory::candidate::{
    CandidateSelectionOutcomeV2, PreparedRosterCandidateSelectionV2,
};
use crate::account::birth::enrollment::roster_v2::inventory::common_context_read_v1::PreparedRosterCommonContextReadV1;
use crate::account::birth::enrollment::roster_v2::inventory::common_context_reentry_v1::{
    DormantCommonContextReadAdmission, FreshCommonContextReentrySource,
};
use crate::account::birth::enrollment::roster_v2::inventory::construction::PreparedRosterConstructionV2;
use crate::account::birth::enrollment::roster_v2::inventory::construction_v3::PreparedRosterConstructionV3;
use crate::account::birth::enrollment::roster_v2::inventory::exact_input_observation::PreparedRosterExactInputObservationV1;
use crate::account::birth::enrollment::roster_v2::inventory::retention::PreparedRosterContributionRetentionV2;
use crate::account::birth::enrollment::roster_v2::inventory::{
    BornRosterInventorySourceV2, PreparedRosterInventoryV2,
};
use crate::{
    account::{
        birth::enrollment::roster_v2::{
            acquisition::{ApprovedBornManualRosterReentryV2, PreparedBornManualRosterReentryV2},
            publication::{
                BornManualRosterEnrolledSignerV2, PreparedBornManualRosterPublicationV2,
            },
            PreparedBornManualRosterEnrollmentV2,
        },
        AccountVault,
    },
    ipc::{AuthenticatedPeer, IpcRevocation, LocalEvent, LocalIpc, PendingPairing},
    Error, Result,
};
use eframe::egui;
use std::os::unix::fs::PermissionsExt;
use std::{
    path::{Path, PathBuf},
    sync::{mpsc, Arc, Mutex},
    thread::JoinHandle,
    time::{Duration, Instant},
};
use wholepact_authority::{
    manual_roster_signature_v2::ManualRosterEnrollmentOwnerSignatureV2, WriterSessionReceipt,
};
use wholepact_signer_origin::manual_roster_v2::{
    HostManualRosterEnrollmentIntentV2 as HostIntent,
    HostManualRosterPublicationRequestV2 as HostPublication, ManualRosterPublicationAttemptV2,
};
use zeroize::{Zeroize, Zeroizing};

struct Opened {
    account: Arc<AccountVault>,
    account_id: String,
    retained_reference: Option<String>,
    attempted: bool,
    continuation: Option<Arc<RetainedContinuation>>,
    revocation: IpcRevocation,
    ipc: Arc<Mutex<LocalIpc>>,
    _temporary: Arc<tempfile::TempDir>,
    display: Zeroizing<String>,
}
impl Opened {
    fn revoke(&self) {
        self.revocation.close_pending_now();
    }
}
struct CompletionOpened {
    source: Option<FreshCommonContextReentrySource>,
    ipc: Arc<Mutex<LocalIpc>>,
    revocation: IpcRevocation,
    _temporary: tempfile::TempDir,
    queued: Option<CompletionRequest>,
}
struct CompletionRequest {
    peer: AuthenticatedPeer,
    stream: std::os::unix::net::UnixStream,
    request: Box<wholepact_core::common_context_reentry_v1::RosterCommonContextReentryRequestV1>,
    pending_grant_json: Zeroizing<String>,
}
struct CompletionWork {
    source: FreshCommonContextReentrySource,
    request: CompletionRequest,
    setup: Zeroizing<String>,
}
struct ReenteredWork {
    source: common_context_reentry::ReenteredCommonContextOwnerV1,
    peer: AuthenticatedPeer,
    stream: std::os::unix::net::UnixStream,
    request: Box<wholepact_core::manual_roster_construction_v3::ManualRosterConstructionRequestV3>,
    lineage_digest: String,
}
enum Step {
    NamedReentryWitness(Box<named_reentry_witness::PreparedNamedWitnessV1>),
    Named(Box<named_controls::NamedStep>),
    Stop(Box<permanent_stop_flow::StopPreparation>),
    CompletionWitness(Box<common_context_reentry::PreparedCommonContextWitnessV1>),
    CompletionClaim(Box<common_context_reentry::PreparedCommonContextClaimV1>),
    ReenteredConstruction(Box<common_context_reentry::PreparedReenteredConstructionV1>),
    ConstructionSign(Box<construction_signing::PreparedRosterConstructionOwnerSignatureV2>),
    ConstructionV3Sign(Box<construction_signing_v3::PreparedRosterConstructionOwnerSignatureV3>),
    ConstructionExport(Box<construction_export::PreparedRosterConstructionExportV2>),
    ConstructionV3Export(Box<construction_export_v3::PreparedRosterConstructionExportV3>),
    ExactInputObservation(Box<PreparedRosterExactInputObservationV1>),
    CommonContextRead(Box<PreparedRosterCommonContextReadV1>),
    CommonContextHandoffAuthorization(
        Box<common_context_handoff::PreparedCommonContextHandoffAuthorizationV1>,
    ),
    Construction(Box<PreparedRosterConstructionV2>),
    ConstructionV3(Box<PreparedRosterConstructionV3>),
    ContributionRetention(Box<PreparedRosterContributionRetentionV2>),
    CandidateSelection(Box<PreparedRosterCandidateSelectionV2>),
    Inventory(Box<PreparedRosterInventoryV2>),
    PolicyExport(Box<policy_export_v2::PreparedOriginalPolicyExportV2>),

    ContinuationProposal(Box<PreparedContinuationProposal>),
    ContinuationSign(Box<continuation_signing::PreparedRosterContinuationOwnerSignatureV2>),
    ContinuationExport(Box<continuation_export::PreparedContinuationExport>),
    ContinuedReentry(Box<PreparedContinuedReentry>),
    ContinuedAdmit(Box<continuation_witness::PreparedContinuedAdmission>),
    ContinuedServe(Box<admission::PreparedNativeManualRosterAdmissionV2>),
    Pair(Box<PendingPairing>),
    Retain(Box<PreparedBornManualRosterEnrollmentV2>),
    Reentry(Box<PreparedBornManualRosterReentryV2>),
    Sign(Box<signing::PreparedRosterOwnerSignatureV2>),
    Export(Box<export::PreparedManualExport>),
    Witness(Box<witness::PreparedManualWitnessSetup>),
    Acquire(Box<PreparedWriterSession>),
    Activate(Box<PreparedWriterActivation>),
    Admit(Box<witness::PreparedManualAdmission>),
    Publish(Box<PreparedBornManualRosterPublicationV2>),
    Serve(Box<admission::PreparedNativeManualRosterAdmissionV2>),
}
struct Prepared {
    step: Step,
    digest: String,
    display: String,
}
impl Prepared {
    fn new(step: Step) -> Result<Self> {
        let (digest, display) = match &step {
            Step::Named(p) => p.display()?,
            Step::NamedReentryWitness(p) => (p.digest().into(), p.display()?),
            Step::Stop(p) => p.display()?,
            Step::CompletionWitness(p) => (p.reviewed_digest().into(), p.review_json()?),
            Step::CompletionClaim(p) => (p.reviewed_digest().into(), p.review_json()?),
            Step::ReenteredConstruction(p) => (p.reviewed_digest().into(), p.review_json()?),
            Step::ConstructionSign(p) => (p.reviewed_digest().into(), p.display().into()),
            Step::ConstructionV3Sign(p) => (p.reviewed_digest().into(), p.display().into()),
            Step::ConstructionExport(p) => (p.digest().into(), p.display().into()),
            Step::ConstructionV3Export(p) => (p.digest().into(), p.display().into()),
            Step::ExactInputObservation(p) => (p.reviewed_digest().into(), p.review_json()?),
            Step::CommonContextRead(p) => (p.reviewed_digest().into(), p.review_json()?),
            Step::CommonContextHandoffAuthorization(p) => {
                (p.reviewed_digest().into(), p.review_json()?)
            }
            Step::Construction(p) => (p.reviewed_digest().into(), p.review_json()?),
            Step::ConstructionV3(p) => (p.reviewed_digest().into(), p.review_json()?),
            Step::ContributionRetention(p) => (p.reviewed_digest().into(), p.review_json()?),
            Step::CandidateSelection(p) => (p.reviewed_digest().into(), p.review_json()?),
            Step::Inventory(p) => (p.reviewed_digest().into(), p.review_json()?),
            Step::PolicyExport(p) => (p.digest().into(), p.display().into()),
            Step::ContinuationProposal(p) => (p.reviewed_digest().into(), p.review_json()?),
            Step::ContinuationSign(p) => (p.reviewed_digest().into(), p.display().into()),
            Step::ContinuationExport(p) => (p.digest().into(), p.display().into()),
            Step::ContinuedReentry(p) => (p.reviewed_digest().into(), p.review_json()?),
            Step::ContinuedAdmit(p) => (p.digest().into(), p.display()?),
            Step::ContinuedServe(p) => (p.reviewed_digest().into(), p.review_json()?),
            Step::Pair(_) => return Err(Error::Unavailable),
            Step::Retain(p) => (p.reviewed_digest().into(), p.review_json()?),
            Step::Reentry(p) => (p.reviewed_digest().into(), p.review_json()?),
            Step::Sign(p) => (p.reviewed_digest().into(), p.display().into()),
            Step::Export(p) => (p.digest().into(), p.display().into()),
            Step::Witness(p) => (p.digest().into(), p.display()?),
            Step::Acquire(p) => (p.digest().into(), p.display()?),
            Step::Activate(p) => (p.digest().into(), p.display()?),
            Step::Admit(p) => (p.digest().into(), p.display()?),
            Step::Publish(p) => (p.reviewed_digest().into(), p.review_json()?),
            Step::Serve(p) => (p.reviewed_digest().into(), p.review_json()?),
        };
        Ok(Self {
            step,
            digest,
            display,
        })
    }
}
struct Review {
    step: Step,
    exact: ExactNativeReview,
    displayed_to_end: bool,
}
struct Context {
    publication_request: Option<Box<HostPublication>>,
    account: Arc<AccountVault>,
    ipc: Arc<Mutex<LocalIpc>>,
    _temporary: Arc<tempfile::TempDir>,
    peer: Option<AuthenticatedPeer>,
    writer: Option<Arc<NativeWitnessWorkspace>>,
    owner_client: Option<Arc<NativeWitnessWorkspace>>,
    reentry: Option<Arc<ApprovedBornManualRosterReentryV2>>,
    retained_reference: Option<String>,
    attempted: bool,
    continuation: Option<Arc<RetainedContinuation>>,
    continued_reentry: Option<Arc<ApprovedContinuedReentry>>,
}
impl Context {
    fn pairing(&self) -> Result<AuthenticatedPairing> {
        AuthenticatedPairing::from_authenticated_request(
            self.peer.clone().ok_or(Error::Authentication)?,
        )
    }
    fn writer(&self) -> Result<&NativeWitnessWorkspace> {
        self.writer.as_deref().ok_or(Error::Locked)
    }
    fn owner_client(&self) -> Result<&NativeWitnessWorkspace> {
        self.owner_client.as_deref().ok_or(Error::Locked)
    }
}
struct ExactInputObservationWork {
    context: Context,
    source: BornRosterInventorySourceV2,
    peer: AuthenticatedPeer,
    stream: std::os::unix::net::UnixStream,
    request: Box<wholepact_core::manual_roster_exact_input_observation_v1::ManualRosterExactInputObservationRequestV1>,
}
struct CommonContextHandoffWork {
    source: BornRosterInventorySourceV2,
    peer: AuthenticatedPeer,
    stream: std::os::unix::net::UnixStream,
    request: Box<wholepact_signer_origin::common_context_handoff_v1::RosterCommonContextHandoffAuthorizationRequestV1>,
    certificate_path: PathBuf,
    key_path: PathBuf,
}
struct CommonContextReadWork {
    context: Context,
    source: BornRosterInventorySourceV2,
    peer: AuthenticatedPeer,
    stream: std::os::unix::net::UnixStream,
    request: Box<wholepact_core::manual_roster_construction_v3::RosterCommonContextReadRequestV1>,
}
struct ConstructionWork {
    context: Context,
    source: BornRosterInventorySourceV2,
    peer: AuthenticatedPeer,
    stream: std::os::unix::net::UnixStream,
    request: Box<wholepact_core::manual_roster_construction_v2::ManualRosterConstructionRequestV2>,
}
struct ConstructionV3Work {
    context: Context,
    source: BornRosterInventorySourceV2,
    peer: AuthenticatedPeer,
    stream: std::os::unix::net::UnixStream,
    request: Box<wholepact_core::manual_roster_construction_v3::ManualRosterConstructionRequestV3>,
}
struct CandidateSelectionWork {
    context: Context,
    source: BornRosterInventorySourceV2,
    peer: AuthenticatedPeer,
    stream: std::os::unix::net::UnixStream,
    request: Box<wholepact_core::manual_roster_candidate_selection_v2::ManualRosterCandidateSelectionRequestV2>,
}
struct InventoryWork {
    context: Context,
    source: BornRosterInventorySourceV2,
    peer: AuthenticatedPeer,
    stream: std::os::unix::net::UnixStream,
    request: Box<wholepact_core::manual_roster_inventory_v2::ManualRosterInventoryRequestV2>,
}
enum Work {
    OpenNamed(Box<crate::account::birth::enrollment::roster_v2::inventory::common_context_reentry_v1::named_recipient::DormantConsumedBornNamedSourceV1>, PathBuf, Zeroizing<String>),
    PrepareNamedWitness(Box<crate::account::birth::enrollment::roster_v2::inventory::common_context_reentry_v1::named_recipient::ConsumedBornNamedSourceV1>, Zeroizing<String>),
    ApproveNamedWitness(Box<named_reentry_witness::PreparedNamedWitnessV1>, NativeDecision),
    Named(Box<named_controls::NamedWork>),
    Stop(permanent_stop_flow::StopWork),
    OpenCommonContext(Box<DormantCommonContextReadAdmission>, PathBuf, Zeroizing<String>),
    PrepareCompletionWitness(Box<CompletionWork>),
    PrepareReenteredConstruction(Box<ReenteredWork>),
    CommitCompletion(Arc<Mutex<LocalIpc>>, Step, NativeDecision),
    PrepareConstructionSign(Context,PathBuf,PathBuf,PathBuf),
    PrepareConstructionV3Sign(Context,PathBuf,PathBuf,PathBuf),
    PrepareConstructionExport(Context,Box<wholepact_authority::manual_roster_construction_signature_v2::ManualRosterConstructionOwnerSignatureV2>,PathBuf),
    PrepareConstructionV3Export(Context,Box<wholepact_authority::manual_roster_construction_signature_v3::ManualRosterConstructionOwnerSignatureV3>,PathBuf),
    PrepareExactInputObservation(Box<ExactInputObservationWork>),
    PrepareCommonContextRead(Box<CommonContextReadWork>),
    PrepareCommonContextHandoffAuthorization(Box<CommonContextHandoffWork>),
    PrepareConstruction(Box<ConstructionWork>),
    PrepareConstructionV3(Box<ConstructionV3Work>),
    PrepareCandidateSelection(Box<CandidateSelectionWork>),
    PrepareInventory(Box<InventoryWork>),
    PreparePolicyExport(Context, PathBuf),

    PrepareContinuationProposal(Context),
    PrepareContinuationSign(Context, PathBuf, PathBuf),
    PrepareContinuationExport(Context, PathBuf),
    PrepareContinuedReentry(Context, Box<HostPublication>),
    PrepareContinuedServe(
        Arc<BornManualRosterEnrolledSignerV2>,
        AuthenticatedPeer,
        std::os::unix::net::UnixStream,
        Box<HostPublication>,
    ),
    RetryContinuedAdmission(Box<continuation_witness::ApprovedContinuedAdmission>),
    Open(PathBuf, Zeroizing<String>),
    PrepareServe(
        Arc<BornManualRosterEnrolledSignerV2>,
        AuthenticatedPeer,
        std::os::unix::net::UnixStream,
        Box<HostPublication>,
    ),
    PrepareIntent(Context, Box<HostIntent>),
    PrepareReentry(Context, Box<HostPublication>),
    PrepareSignature(Context, PathBuf, PathBuf),
    PrepareExport(
        Context,
        Box<ManualRosterEnrollmentOwnerSignatureV2>,
        PathBuf,
    ),
    PrepareWitness(Context, Zeroizing<String>),
    PrepareAcquire(Context),
    PrepareActivate(Context, Box<WriterSessionReceipt>),
    PreparePublication(Context),
    Commit(Context, Step, NativeDecision),
    RetryAdmission(Box<witness::ApprovedManualAdmission>),
    RetryAcquire(Context, Box<ApprovedWriterSession>),
    RetryActivate(Context, Box<ApprovedWriterActivation>),
}
enum Output {
    NamedReentryOpened(Box<named_reentry::OpenedNamed>),
    NamedOwnerReady(Box<named_continuation::ConsumedBornNamedOwnerV1>),
    Named(Box<named_controls::NamedOutput>),
    Stop(permanent_stop_flow::StopOutput),
    CompletionOpened(Box<CompletionOpened>),
    CompletionReentered(Box<common_context_reentry::ReenteredCommonContextOwnerV1>),
    CompletionConsumed(Box<named_continuation::ConsumedBornNamedOwnerV1>),
    ConstructionSigned(Box<wholepact_authority::manual_roster_construction_signature_v2::ManualRosterConstructionOwnerSignatureV2>),
    ConstructionV3Signed(Box<wholepact_authority::manual_roster_construction_signature_v3::ManualRosterConstructionOwnerSignatureV3>),
    ConstructionExported,
    ConstructionV3Exported,
    ExactInputObservationServed(BornRosterInventorySourceV2),
    CommonContextReadServed(BornRosterInventorySourceV2),
    CommonContextHandoffAuthorized(BornRosterInventorySourceV2),
    ConstructionServed(BornRosterInventorySourceV2),
    ConstructionV3Served(BornRosterInventorySourceV2),
    CandidateSelectionServed(BornRosterInventorySourceV2),
    InventoryServed(BornRosterInventorySourceV2),
    PolicyExported,

    ContinuationRetained(Arc<RetainedContinuation>),
    ContinuationSigned,
    ContinuedReentered(Arc<ApprovedContinuedReentry>),
    ContinuedAdmitted(
        Box<continuation_witness::ApprovedContinuedAdmission>,
        Result<Box<Prepared>>,
    ),
    Opened(Box<Opened>),
    Prepared(Box<Prepared>),
    Paired,
    Retained,
    Reentered(Arc<ApprovedBornManualRosterReentryV2>),
    Signed(Box<ManualRosterEnrollmentOwnerSignatureV2>),
    Exported,
    Witness(Arc<NativeWitnessWorkspace>, Arc<NativeWitnessWorkspace>),
    Acquired(
        Box<ApprovedWriterSession>,
        Result<Box<WriterSessionReceipt>>,
    ),
    Activated(Box<ApprovedWriterActivation>, Result<()>),
    Admitted(Box<witness::ApprovedManualAdmission>, Result<Box<Prepared>>),
    Enrolled(Arc<BornManualRosterEnrolledSignerV2>),
    Served,
}
fn run(work: Work, owner: &PendingAccountNativeAuthority) -> Result<Output> {
    owner.check_current()?;
    owner.native().binding().bounded_deadline()?;
    named_reentry::require_work_purpose(&work, owner)?;
    let result = match work {
        Work::OpenNamed(dormant, path, password) => Output::NamedReentryOpened(Box::new(
            named_reentry::open(*dormant, &path, password.as_bytes(), owner)?,
        )),
        Work::PrepareNamedWitness(source, setup) => Output::Prepared(Box::new(Prepared::new(
            Step::NamedReentryWitness(Box::new(named_reentry_witness::PreparedNamedWitnessV1::prepare(*source, &setup, owner)?)),
        )?)),
        Work::ApproveNamedWitness(prepared, decision) => Output::NamedOwnerReady(Box::new(prepared.approve(decision, owner)?)),
        Work::Named(work) => Output::Named(Box::new(named_controls::run(*work, owner)?)),
        Work::Stop(work) => permanent_stop_flow::run(work, owner)?,
        Work::OpenCommonContext(dormant, path, password) => {
            let source = (*dormant).unlock(&path, password.as_bytes(), owner)?;
            let temporary = tempfile::Builder::new()
                .permissions(std::fs::Permissions::from_mode(0o700))
                .tempdir()?;
            let ipc = LocalIpc::bind(crate::files::PrivateDirectory::open(temporary.path())?)?;
            owner.publish_pending_endpoint(ipc.socket_path())?;
            Output::CompletionOpened(Box::new(CompletionOpened {
                source: Some(source),
                revocation: ipc.revocation(),
                ipc: Arc::new(Mutex::new(ipc)),
                _temporary: temporary,
                queued: None,
            }))
        }
        Work::PrepareCompletionWitness(work) => {
            let CompletionWork {
                source,
                request,
                setup,
            } = *work;
            Output::Prepared(Box::new(Prepared::new(Step::CompletionWitness(Box::new(
                common_context_reentry::PreparedCommonContextWitnessV1::prepare(
                    source,
                    request.peer,
                    request.stream,
                    *request.request,
                    &request.pending_grant_json,
                    &setup,
                    owner,
                )?,
            )))?))
        }
        Work::PrepareReenteredConstruction(work) => {
            let ReenteredWork {
                source,
                peer,
                stream,
                request,
                lineage_digest,
            } = *work;
            Output::Prepared(Box::new(Prepared::new(Step::ReenteredConstruction(
                Box::new(source.prepare(peer, stream, *request, &lineage_digest, owner)?),
            ))?))
        }
        Work::CommitCompletion(ipc, step, decision) => match step {
            Step::Pair(pair) => {
                ipc.lock().map_err(|_| Error::Locked)?.approve_pairing(
                    *pair,
                    decision,
                    owner.native(),
                )?;
                Output::Paired
            }
            Step::CompletionWitness(p) => Output::Prepared(Box::new(Prepared::new(
                Step::CompletionClaim(Box::new(p.approve(decision, owner)?)),
            )?)),
            Step::CompletionClaim(p) => {
                Output::CompletionReentered(Box::new(p.approve_and_serve(decision, owner)?))
            }
            Step::ReenteredConstruction(p) => {
                Output::CompletionConsumed(Box::new(p.approve_and_serve(decision, owner)?))
            }
            _ => return Err(Error::Unavailable),
        },
        Work::PrepareConstructionSign(c, cert, key, plan) => {
            let retained = c
                .account
                .retained_born_manual_roster_enrollment_v2(owner)?
                .ok_or(Error::RecoveryRequired)?;
            Output::Prepared(Box::new(Prepared::new(Step::ConstructionSign(Box::new(
                construction_signing::PreparedRosterConstructionOwnerSignatureV2::prepare(
                    retained, owner, &cert, &key, &plan,
                )?,
            )))?))
        }
        Work::PrepareConstructionV3Sign(c, cert, key, plan) => {
            let retained = c
                .account
                .retained_born_manual_roster_enrollment_v2(owner)?
                .ok_or(Error::RecoveryRequired)?;
            Output::Prepared(Box::new(Prepared::new(Step::ConstructionV3Sign(
                Box::new(
                    construction_signing_v3::PreparedRosterConstructionOwnerSignatureV3::prepare(
                        retained, owner, &cert, &key, &plan,
                    )?,
                ),
            ))?))
        }
        Work::PrepareConstructionExport(c, envelope, path) => {
            let retained = c
                .account
                .retained_born_manual_roster_enrollment_v2(owner)?
                .ok_or(Error::RecoveryRequired)?;
            Output::Prepared(Box::new(Prepared::new(Step::ConstructionExport(
                Box::new(
                    construction_export::PreparedRosterConstructionExportV2::prepare(
                        retained, *envelope, &path, owner,
                    )?,
                ),
            ))?))
        }

        Work::PrepareConstructionV3Export(c, envelope, path) => {
            let retained = c
                .account
                .retained_born_manual_roster_enrollment_v2(owner)?
                .ok_or(Error::RecoveryRequired)?;
            Output::Prepared(Box::new(Prepared::new(Step::ConstructionV3Export(
                Box::new(
                    construction_export_v3::PreparedRosterConstructionExportV3::prepare(
                        retained, *envelope, &path, owner,
                    )?,
                ),
            ))?))
        }

        Work::PrepareExactInputObservation(work) => {
            let ExactInputObservationWork {
                context: c,
                source,
                peer,
                stream,
                request,
            } = *work;
            let history = c
                .writer()?
                .client()
                .reconcile_history_checked(|| {
                    owner
                        .check_current()
                        .map_err(|_| wholepact_authority::AuthorityError::Permission)
                })
                .map_err(|_| Error::Uncertain)?;
            owner.check_current()?;
            let observation = c
                .writer()?
                .client()
                .verify_active_session(&history)
                .map_err(|_| Error::ReviewMismatch)?;
            Output::Prepared(Box::new(Prepared::new(Step::ExactInputObservation(
                Box::new(PreparedRosterExactInputObservationV1::prepare(
                    source,
                    peer,
                    stream,
                    *request,
                    history,
                    observation,
                    owner,
                )?),
            ))?))
        }

        Work::PrepareCommonContextHandoffAuthorization(work) => {
            let CommonContextHandoffWork {
                source,
                peer,
                stream,
                request,
                certificate_path,
                key_path,
            } = *work;
            Output::Prepared(Box::new(Prepared::new(
                Step::CommonContextHandoffAuthorization(Box::new(
                    common_context_handoff::PreparedCommonContextHandoffAuthorizationV1::prepare(
                        source,
                        peer,
                        stream,
                        *request,
                        &certificate_path,
                        &key_path,
                        owner,
                    )?,
                )),
            )?))
        }
        Work::PrepareCommonContextRead(work) => {
            let CommonContextReadWork {
                context: c,
                source,
                peer,
                stream,
                request,
            } = *work;
            let history = c
                .writer()?
                .client()
                .reconcile_history_checked(|| {
                    owner
                        .check_current()
                        .map_err(|_| wholepact_authority::AuthorityError::Permission)
                })
                .map_err(|_| Error::Uncertain)?;
            owner.check_current()?;
            let observation = c
                .writer()?
                .client()
                .verify_active_session(&history)
                .map_err(|_| Error::ReviewMismatch)?;
            Output::Prepared(Box::new(Prepared::new(Step::CommonContextRead(Box::new(
                PreparedRosterCommonContextReadV1::prepare(
                    source,
                    peer,
                    stream,
                    *request,
                    history,
                    observation,
                    owner,
                )?,
            )))?))
        }

        Work::PrepareConstruction(work) => {
            let ConstructionWork {
                context: c,
                source,
                peer,
                stream,
                request,
            } = *work;
            let history = c
                .writer()?
                .client()
                .reconcile_history_checked(|| {
                    owner
                        .check_current()
                        .map_err(|_| wholepact_authority::AuthorityError::Permission)
                })
                .map_err(|_| Error::Uncertain)?;
            owner.check_current()?;
            let observation = c
                .writer()?
                .client()
                .verify_active_session(&history)
                .map_err(|_| Error::ReviewMismatch)?;
            Output::Prepared(Box::new(Prepared::new(Step::Construction(Box::new(
                PreparedRosterConstructionV2::prepare(
                    source,
                    peer,
                    stream,
                    *request,
                    history,
                    observation,
                    owner,
                )?,
            )))?))
        }

        Work::PrepareConstructionV3(work) => {
            let ConstructionV3Work {
                context: c,
                source,
                peer,
                stream,
                request,
            } = *work;
            let history = c
                .writer()?
                .client()
                .reconcile_history_checked(|| {
                    owner
                        .check_current()
                        .map_err(|_| wholepact_authority::AuthorityError::Permission)
                })
                .map_err(|_| Error::Uncertain)?;
            owner.check_current()?;
            let observation = c
                .writer()?
                .client()
                .verify_active_session(&history)
                .map_err(|_| Error::ReviewMismatch)?;
            Output::Prepared(Box::new(Prepared::new(Step::ConstructionV3(Box::new(
                PreparedRosterConstructionV3::prepare(
                    source,
                    peer,
                    stream,
                    *request,
                    history,
                    observation,
                    owner,
                )?,
            )))?))
        }

        Work::PrepareCandidateSelection(work) => {
            let CandidateSelectionWork {
                context: c,
                source,
                peer,
                stream,
                request,
            } = *work;
            let history = c
                .writer()?
                .client()
                .reconcile_history_checked(|| {
                    owner
                        .check_current()
                        .map_err(|_| wholepact_authority::AuthorityError::Permission)
                })
                .map_err(|_| Error::Uncertain)?;
            owner.check_current()?;
            let observation = c
                .writer()?
                .client()
                .verify_active_session(&history)
                .map_err(|_| Error::ReviewMismatch)?;
            owner.check_current()?;
            Output::Prepared(Box::new(Prepared::new(Step::CandidateSelection(
                Box::new(PreparedRosterCandidateSelectionV2::prepare(
                    source,
                    peer,
                    stream,
                    *request,
                    history,
                    observation,
                    owner,
                )?),
            ))?))
        }
        Work::PrepareInventory(work) => {
            let InventoryWork {
                context: c,
                source,
                peer,
                stream,
                request,
            } = *work;
            let history = c
                .writer()?
                .client()
                .reconcile_history_checked(|| {
                    owner
                        .check_current()
                        .map_err(|_| wholepact_authority::AuthorityError::Permission)
                })
                .map_err(|_| Error::Uncertain)?;
            owner.check_current()?;
            let observation = c
                .writer()?
                .client()
                .verify_active_session(&history)
                .map_err(|_| Error::ReviewMismatch)?;
            owner.check_current()?;
            Output::Prepared(Box::new(Prepared::new(Step::Inventory(Box::new(
                PreparedRosterInventoryV2::prepare(
                    source,
                    peer,
                    stream,
                    *request,
                    history,
                    observation,
                    owner,
                )?,
            )))?))
        }
        Work::PreparePolicyExport(c, path) => {
            let retained = c
                .account
                .retained_born_manual_roster_enrollment_v2(owner)?
                .ok_or(Error::RecoveryRequired)?;
            Output::Prepared(Box::new(Prepared::new(Step::PolicyExport(Box::new(
                policy_export_v2::PreparedOriginalPolicyExportV2::prepare(retained, &path, owner)?,
            )))?))
        }
        Work::PrepareContinuationProposal(c) => {
            use crate::account::birth::enrollment::roster_v2::continuation::diagnostics::{
                self as diag, Phase as P,
            };
            if !c.attempted {
                return Err(Error::RecoveryRequired);
            }
            let retained = diag::signer(
                P::ContinuationRetainedSource,
                c.account.retained_born_manual_roster_enrollment_v2(owner),
            )?
            .ok_or(Error::RecoveryRequired)?;
            diag::signer(
                P::ContinuationAttemptedSource,
                attempts::require_attempted_source(&retained, owner),
            )?;
            diag::signer(
                P::ContinuationWriterSource,
                c.writer()?.check_native_source(&owner.native().binding()),
            )?;
            let history = diag::authority(
                P::ContinuationHistoryReplay,
                c.writer()?.client().reconcile_history_checked(|| {
                    owner
                        .check_current()
                        .map_err(|_| wholepact_authority::AuthorityError::Permission)
                }),
            )
            .map_err(|_| Error::Uncertain)?;
            Output::Prepared(Box::new(diag::signer(
                P::ContinuationPreparedReview,
                Prepared::new(Step::ContinuationProposal(Box::new(
                    PreparedContinuationProposal::prepare(
                        retained,
                        &history,
                        &diag::signer(P::ContinuationPairing, c.pairing())?,
                        owner,
                    )?,
                ))),
            )?))
        }
        Work::PrepareContinuationSign(c, cert, key) => {
            Output::Prepared(Box::new(Prepared::new(Step::ContinuationSign(Box::new(
                continuation_signing::PreparedRosterContinuationOwnerSignatureV2::prepare(
                    c.continuation
                        .as_ref()
                        .ok_or(Error::RecoveryRequired)?
                        .reopen(owner)?,
                    owner,
                    &cert,
                    &key,
                )?,
            )))?))
        }
        Work::PrepareContinuationExport(c, path) => {
            let retained = c
                .continuation
                .as_ref()
                .ok_or(Error::RecoveryRequired)?
                .reopen(owner)?;
            let signature = retained.signature(owner)?.ok_or(Error::RecoveryRequired)?;
            Output::Prepared(Box::new(Prepared::new(Step::ContinuationExport(
                Box::new(continuation_export::PreparedContinuationExport::prepare(
                    retained, signature, &path, owner,
                )?),
            ))?))
        }
        Work::PrepareContinuedReentry(c, request) => {
            if !c.attempted {
                return Err(Error::RecoveryRequired);
            }
            let retained = c
                .account
                .retained_born_manual_roster_enrollment_v2(owner)?
                .ok_or(Error::RecoveryRequired)?;
            let ManualRosterPublicationAttemptV2::ContinuationV2 {
                ref continuation_digest,
                ..
            } = request.attempt
            else {
                return Err(Error::ReviewMismatch);
            };
            let selected = attempts::select(retained, continuation_digest, owner)?;
            c.writer()?.check_native_source(&owner.native().binding())?;
            let history = c
                .writer()?
                .client()
                .reconcile_history_checked(|| {
                    owner
                        .check_current()
                        .map_err(|_| wholepact_authority::AuthorityError::Permission)
                })
                .map_err(|_| Error::Uncertain)?;
            Output::Prepared(Box::new(Prepared::new(Step::ContinuedReentry(Box::new(
                PreparedContinuedReentry::prepare(
                    selected,
                    &request,
                    &history,
                    &c.pairing()?,
                    owner,
                )?,
            )))?))
        }
        Work::PrepareContinuedServe(enrolled, peer, stream, request) => {
            Output::Prepared(Box::new(Prepared::new(Step::ContinuedServe(Box::new(
                admission::PreparedNativeManualRosterAdmissionV2::prepare(
                    enrolled, peer, stream, *request, owner,
                )?,
            )))?))
        }
        Work::RetryContinuedAdmission(approved) => {
            let result = approved
                .attempt(owner)
                .and_then(|p| Prepared::new(Step::Publish(Box::new(p))))
                .map(Box::new);
            Output::ContinuedAdmitted(approved, result)
        }
        Work::PrepareServe(enrolled, peer, stream, request) => {
            Output::Prepared(Box::new(Prepared::new(Step::Serve(Box::new(
                admission::PreparedNativeManualRosterAdmissionV2::prepare(
                    enrolled, peer, stream, *request, owner,
                )?,
            )))?))
        }
        Work::PrepareReentry(c, request) => {
            let retained = c
                .account
                .retained_born_manual_roster_enrollment_v2(owner)?
                .ok_or(Error::RecoveryRequired)?;
            if c.retained_reference.as_deref() != Some(retained.record().reference()?.as_str()) {
                return Err(Error::ReviewMismatch);
            }
            Output::Prepared(Box::new(Prepared::new(Step::Reentry(Box::new(
                PreparedBornManualRosterReentryV2::prepare(
                    retained,
                    &request,
                    &c.pairing()?,
                    owner,
                )?,
            )))?))
        }
        Work::Open(path, password) => {
            let account = Arc::new(AccountVault::unlock_born_for_manual_roster_enrollment_v2(
                &path,
                password.as_bytes(),
                owner,
            )?);
            let retained = account.retained_born_manual_roster_enrollment_v2(owner)?;
            let mut attempted = false;
            let mut continuation = None;
            let retained_reference = if let Some(retained) = retained {
                if retained.first_acquire_attempted()? {
                    attempts::require_attempted_source(&retained, owner)?;
                    attempted = true;
                    if let Some(last) = attempts::load(&retained)?.pop() {
                        continuation = Some(Arc::new(RetainedContinuation {
                            retained: retained.reopen_exact(owner)?,
                            proposal: last.proposal,
                        }));
                    }
                } else {
                    retained.require_preacquire_reentry(owner)?;
                }
                Some(retained.record().reference()?)
            } else {
                None
            };
            let account_id = account.account_id()?;
            let display = Zeroizing::new(account.born_origin_audit_json(owner)?);
            let temporary = Arc::new(tempfile::Builder::new()
                .permissions(std::fs::Permissions::from_mode(0o700))
                .tempdir()?);
            let ipc = LocalIpc::bind(crate::files::PrivateDirectory::open(temporary.path())?)?;
            owner.publish_pending_endpoint(ipc.socket_path())?;
            Output::Opened(Box::new(Opened {
                account,
                account_id,
                retained_reference,
                attempted,
                continuation,
                revocation: ipc.revocation(),
                ipc: Arc::new(Mutex::new(ipc)),
                _temporary: temporary,
                display,
            }))
        }
        Work::PrepareIntent(c, input) => {
            input.validate().map_err(|_| Error::InvalidData)?;
            Output::Prepared(Box::new(Prepared::new(Step::Retain(Box::new(
                PreparedBornManualRosterEnrollmentV2::prepare(
                    c.account.clone(),
                    &input,
                    &c.pairing()?,
                    owner,
                )?,
            )))?))
        }
        Work::PrepareSignature(c, cert, key) => {
            let retained = c
                .account
                .retained_born_manual_roster_enrollment_v2(owner)?
                .ok_or(Error::RecoveryRequired)?;
            Output::Prepared(Box::new(Prepared::new(Step::Sign(Box::new(
                signing::PreparedRosterOwnerSignatureV2::prepare(retained, owner, &cert, &key)?,
            )))?))
        }
        Work::PrepareExport(c, envelope, path) => {
            let retained = c
                .account
                .retained_born_manual_roster_enrollment_v2(owner)?
                .ok_or(Error::RecoveryRequired)?;
            Output::Prepared(Box::new(Prepared::new(Step::Export(Box::new(
                export::PreparedManualExport::prepare(retained, *envelope, &path, owner)?,
            )))?))
        }
        Work::PrepareWitness(c, json) => {
            let retained = c
                .account
                .retained_born_manual_roster_enrollment_v2(owner)?
                .ok_or(Error::RecoveryRequired)?;
            Output::Prepared(Box::new(Prepared::new(Step::Witness(Box::new(
                witness::PreparedManualWitnessSetup::prepare(retained, &json, owner)?,
            )))?))
        }
        Work::PrepareAcquire(c) => {
            if c.attempted {
                c.continued_reentry
                    .as_ref()
                    .ok_or(Error::RecoveryRequired)?
                    .check(&c.peer.clone().ok_or(Error::Authentication)?, owner)?;
            } else {
                c.reentry
                    .as_ref()
                    .ok_or(Error::RecoveryRequired)?
                    .matches_peer(&c.peer.clone().ok_or(Error::Authentication)?, owner)?;
            }
            let retained = c
                .account
                .retained_born_manual_roster_enrollment_v2(owner)?
                .ok_or(Error::RecoveryRequired)?;
            Output::Prepared(Box::new(Prepared::new(Step::Acquire(Box::new(
                if c.attempted {
                    PreparedWriterSession::prepare_born_roster_continued_v2(
                        c.writer()?,
                        &retained.record().extension()?,
                        &c.continued_reentry
                            .as_ref()
                            .ok_or(Error::RecoveryRequired)?
                            .proposal()
                            .continuation,
                    )?
                } else {
                    PreparedWriterSession::prepare_born_roster_v2(
                        c.writer()?,
                        &retained.record().extension()?,
                    )?
                },
            )))?))
        }
        Work::PrepareActivate(c, receipt) => {
            Output::Prepared(Box::new(Prepared::new(Step::Activate(Box::new(
                PreparedWriterActivation::prepare(c.owner_client()?, *receipt)?,
            )))?))
        }
        Work::PreparePublication(c) => {
            if c.attempted {
                let retained = c
                    .account
                    .retained_born_manual_roster_enrollment_v2(owner)?
                    .ok_or(Error::RecoveryRequired)?;
                let continuation = c
                    .continued_reentry
                    .as_ref()
                    .ok_or(Error::RecoveryRequired)?
                    .proposal()
                    .continuation
                    .clone();
                let digest = continuation
                    .digest_for(&retained.record().extension()?)
                    .map_err(|_| Error::InvalidData)?;
                return Ok(Output::Prepared(Box::new(Prepared::new(
                    Step::ContinuedAdmit(Box::new(
                        continuation_witness::PreparedContinuedAdmission::prepare(
                            attempts::select(retained, &digest, owner)?,
                            c.writer.clone().ok_or(Error::Locked)?,
                            *c.publication_request.clone().ok_or(Error::ReviewMismatch)?,
                            &c.pairing()?,
                            owner,
                        )?,
                    )),
                )?)));
            }
            let retained = c
                .account
                .retained_born_manual_roster_enrollment_v2(owner)?
                .ok_or(Error::RecoveryRequired)?;
            Output::Prepared(Box::new(Prepared::new(Step::Admit(Box::new(
                witness::PreparedManualAdmission::prepare(
                    retained,
                    c.writer.clone().ok_or(Error::Locked)?,
                    *c.publication_request.clone().ok_or(Error::ReviewMismatch)?,
                    &c.pairing()?,
                    owner,
                )?,
            )))?))
        }
        Work::Commit(c, step, decision) => match step {
            Step::Stop(_) | Step::Named(_) | Step::NamedReentryWitness(_) => return Err(Error::Unavailable),
            Step::CompletionWitness(_)
            | Step::CompletionClaim(_)
            | Step::ReenteredConstruction(_) => return Err(Error::Unavailable),
            Step::ConstructionSign(p) => {
                Output::ConstructionSigned(Box::new(p.approve_and_sign(decision, owner)?))
            }
            Step::ConstructionV3Sign(p) => {
                Output::ConstructionV3Signed(Box::new(p.approve_and_sign(decision, owner)?))
            }
            Step::ConstructionExport(p) => {
                p.publish(decision, owner)?;
                Output::ConstructionExported
            }
            Step::ConstructionV3Export(p) => {
                p.publish(decision, owner)?;
                Output::ConstructionV3Exported
            }
            Step::ExactInputObservation(p) => {
                Output::ExactInputObservationServed(p.approve_and_serve(decision, owner)?)
            }
            Step::CommonContextRead(p) => {
                Output::CommonContextReadServed(p.approve_and_serve(decision, owner)?)
            }
            Step::CommonContextHandoffAuthorization(p) => {
                Output::CommonContextHandoffAuthorized(p.approve_and_serve(decision, owner)?)
            }
            Step::Construction(p) => Output::ConstructionServed(p.approve_and_serve(
                decision,
                owner,
                c.writer()?.client(),
            )?),
            Step::ConstructionV3(p) => Output::ConstructionV3Served(p.approve_and_serve(
                decision,
                owner,
                c.writer()?.client(),
            )?),
            Step::CandidateSelection(p) => match p.approve_and_serve(decision, owner)? {
                CandidateSelectionOutcomeV2::Finished(source) => {
                    Output::CandidateSelectionServed(*source)
                }
                CandidateSelectionOutcomeV2::Retention(p) => {
                    Output::Prepared(Box::new(Prepared::new(Step::ContributionRetention(p))?))
                }
            },
            Step::ContributionRetention(p) => {
                Output::CandidateSelectionServed(p.approve_and_retain(decision, owner)?)
            }
            Step::Inventory(p) => Output::InventoryServed(p.approve_and_serve(decision, owner)?),
            Step::PolicyExport(p) => {
                p.publish(decision, owner)?;
                Output::PolicyExported
            }
            Step::ContinuationProposal(p) => {
                Output::ContinuationRetained(Arc::new(p.approve_and_retain(decision, owner)?))
            }
            Step::ContinuationSign(p) => {
                p.approve_and_sign(decision, owner)?;
                Output::ContinuationSigned
            }
            Step::ContinuationExport(p) => {
                p.publish(decision, owner)?;
                Output::Exported
            }
            Step::ContinuedReentry(p) => {
                Output::ContinuedReentered(Arc::new(p.approve(decision, owner)?))
            }
            Step::ContinuedAdmit(p) => {
                let approved = Box::new(p.approve(decision, owner)?);
                let result = approved
                    .attempt(owner)
                    .and_then(|p| Prepared::new(Step::Publish(Box::new(p))))
                    .map(Box::new);
                Output::ContinuedAdmitted(approved, result)
            }
            Step::ContinuedServe(p) => {
                p.approve_and_serve(decision, owner)?;
                Output::Served
            }
            Step::Pair(pair) => {
                c.ipc.lock().map_err(|_| Error::Locked)?.approve_pairing(
                    *pair,
                    decision,
                    owner.native(),
                )?;
                Output::Paired
            }
            Step::Retain(p) => {
                p.approve_and_retain(decision, owner)?;
                Output::Retained
            }
            Step::Reentry(p) => Output::Reentered(Arc::new(p.approve(decision, owner)?)),
            Step::Sign(p) => Output::Signed(Box::new(p.approve_and_sign(decision, owner)?)),
            Step::Export(p) => {
                p.publish(decision, owner)?;
                Output::Exported
            }
            Step::Witness(p) => {
                let (w, o) = p.approve(decision, owner)?;
                Output::Witness(w, o)
            }
            Step::Acquire(p) => {
                let approved = Box::new(p.approve(decision, owner.native(), c.writer()?)?);
                if c.attempted {
                    c.continued_reentry
                        .as_ref()
                        .ok_or(Error::RecoveryRequired)?
                        .persist_before_acquire(&approved, owner)?;
                } else {
                    c.reentry
                        .as_ref()
                        .ok_or(Error::RecoveryRequired)?
                        .persist_before_first_acquire(&approved, owner)?;
                }
                let result = approved.acquire(c.writer()?).map(Box::new);
                Output::Acquired(approved, result)
            }
            Step::Activate(p) => {
                let approved = Box::new(p.approve(decision, owner.native(), c.owner_client()?)?);
                let result = approved.activate(c.owner_client()?).map(|_| ());
                Output::Activated(approved, result)
            }
            Step::Admit(p) => {
                let approved = Box::new(p.approve(decision, owner)?);
                let result = approved
                    .attempt(owner)
                    .and_then(|p| Prepared::new(Step::Publish(Box::new(p))))
                    .map(Box::new);
                Output::Admitted(approved, result)
            }
            Step::Publish(p) => Output::Enrolled(Arc::new(p.approve_and_publish(decision, owner)?)),
            Step::Serve(p) => {
                p.approve_and_serve(decision, owner)?;
                Output::Served
            }
        },
        Work::RetryAdmission(approved) => {
            let result = approved
                .attempt(owner)
                .and_then(|p| Prepared::new(Step::Publish(Box::new(p))))
                .map(Box::new);
            Output::Admitted(approved, result)
        }
        Work::RetryAcquire(c, approved) => {
            if c.attempted {
                c.continued_reentry
                    .as_ref()
                    .ok_or(Error::RecoveryRequired)?
                    .persist_before_acquire(&approved, owner)?;
            } else {
                c.reentry
                    .as_ref()
                    .ok_or(Error::RecoveryRequired)?
                    .persist_before_first_acquire(&approved, owner)?;
            }
            let result = approved.acquire(c.writer()?).map(Box::new);
            Output::Acquired(approved, result)
        }
        Work::RetryActivate(c, approved) => {
            let result = approved.activate(c.owner_client()?).map(|_| ());
            Output::Activated(approved, result)
        }
    };
    // A fully admitted exact read response may finish after focus revocation.
    // Its sole continuation is key-free dormancy; the UI cannot reinstall its
    // old account/source when that foreground owner is gone.
    if !matches!(
        &result,
        Output::CommonContextReadServed(_) | Output::CommonContextHandoffAuthorized(_)
    ) {
        owner.check_current()?;
    }
    Ok(result)
}
struct Job {
    may_finish_common_context_read: bool,
    thread: JoinHandle<()>,
    receive: mpsc::Receiver<Result<Output>>,
}
impl Job {
    fn start(work: Work, owner: Arc<PendingAccountNativeAuthority>) -> Result<Self> {
        let may_finish_common_context_read = matches!(
            &work,
            Work::Commit(
                _,
                Step::CommonContextRead(_) | Step::CommonContextHandoffAuthorization(_),
                _
            )
        );
        let (send, receive) = mpsc::sync_channel(1);
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let diagnostic_operation = synthetic_diagnostics::Operation::from_work(&work);
        let thread = std::thread::Builder::new()
            .name("wholepact-born-roster-v2-owner".into())
            .spawn(move || {
                #[cfg(feature = "synthetic-born-joined-qualification")]
                synthetic_diagnostics::report_begin(diagnostic_operation);
                let result = run(work, &owner);
                #[cfg(feature = "synthetic-born-joined-qualification")]
                synthetic_diagnostics::report_output(diagnostic_operation, &result);
                let _ = send.send(result);
            })?;
        Ok(Self {
            thread,
            receive,
            may_finish_common_context_read,
        })
    }
    fn finish(self) -> Result<Output> {
        self.thread.join().map_err(|_| Error::Uncertain)?;
        self.receive.try_recv().map_err(|_| Error::Uncertain)?
    }
}
struct QueuedContinuation {
    peer: AuthenticatedPeer,
    stream: std::os::unix::net::UnixStream,
    request: Box<HostPublication>,
}
struct QueuedEnrollment {
    peer: AuthenticatedPeer,
    stream: std::os::unix::net::UnixStream,
    request: Box<HostPublication>,
}
#[derive(Default)]
pub(super) struct BornManualRosterUiV2 {
    stop_opened: Option<permanent_stop_flow::StopOpened>,
    owner: Option<Arc<PendingAccountNativeAuthority>>,
    bootstrap: controller::BootstrapController,
    continuation_controller: continuation_controller::ContinuationController,
    continuation: Option<Arc<RetainedContinuation>>,
    continued_reentry: Option<Arc<ApprovedContinuedReentry>>,
    queued_continuation: Option<QueuedContinuation>,
    continued_admission_retry: Option<Box<continuation_witness::ApprovedContinuedAdmission>>,
    queued: Option<QueuedEnrollment>,
    reentry: Option<Arc<ApprovedBornManualRosterReentryV2>>,
    opened: Option<Opened>,
    peer: Option<AuthenticatedPeer>,
    review: Option<Review>,
    job: Option<Job>,
    cleanup: Vec<JoinHandle<()>>,
    writer: Option<Arc<NativeWitnessWorkspace>>,
    owner_client: Option<Arc<NativeWitnessWorkspace>>,
    receipt: Option<WriterSessionReceipt>,
    acquire_retry: Option<Box<ApprovedWriterSession>>,
    activation_retry: Option<Box<ApprovedWriterActivation>>,
    admission_retry: Option<Box<witness::ApprovedManualAdmission>>,
    activated: bool,
    enrolled: Option<Arc<BornManualRosterEnrolledSignerV2>>,
    inventory_source: Option<BornRosterInventorySourceV2>,
    dormant_common_context: Option<DormantCommonContextReadAdmission>,
    completion_opened: Option<CompletionOpened>,
    completion_reentered: Option<common_context_reentry::ReenteredCommonContextOwnerV1>,
    named_continuation: Option<Box<named_continuation::ConsumedBornNamedOwnerV1>>,
    named_controls: named_controls::NamedControls,
    named_reentry: named_reentry::State,
    accept_blurred_read_completion: bool,
    signed: Option<Box<ManualRosterEnrollmentOwnerSignatureV2>>,

    construction_plan_path:Zeroizing<String>,
    construction_signed:Option<Box<wholepact_authority::manual_roster_construction_signature_v2::ManualRosterConstructionOwnerSignatureV2>>,
    construction_v3_signed:Option<Box<wholepact_authority::manual_roster_construction_signature_v3::ManualRosterConstructionOwnerSignatureV3>>,
    certificate: Zeroizing<String>,
    key: Zeroizing<String>,
    destination: Zeroizing<String>,
    witness_setup: Zeroizing<String>,
    confirmation: Zeroizing<String>,
    message: &'static str,
}
impl BornManualRosterUiV2 {
    pub(super) fn is_active(&self) -> bool {
        self.owner.is_some() || self.job.is_some() || !self.cleanup.is_empty() || self.named_reentry.draining() || self.named_controls.active()
    }
    pub(super) fn begin(
        &mut self,
        entry: PendingBirthEntry,
        path: &Path,
        password: &str,
    ) -> Result<()> {
        if self.is_active() || !path.is_absolute() || !(12..=1024).contains(&password.len()) {
            return Err(Error::ReviewMismatch);
        }
        if let Some(drain) = self.named_reentry.clear() { self.cleanup.push(drain); }
        // Any ordinary entry is a source replacement, never a reentry.
        self.dormant_common_context = None;
        self.accept_blurred_read_completion = false;
        let deadline = Instant::now() + Duration::from_secs(120);
        let owner = Arc::new(PendingAccountNativeAuthority::enter_bounded(
            entry, deadline,
        )?);
        self.job = Some(Job::start(
            Work::Open(path.to_path_buf(), Zeroizing::new(password.into())),
            owner.clone(),
        )?);
        self.owner = Some(owner);
        self.message = "Opening exact original acknowledged vault. Pairing and enrollment need separate exact native reviews; no writer or journal is active.";
        Ok(())
    }
    pub(super) fn has_dormant_common_context(&self) -> bool {
        self.dormant_common_context.is_some()
    }
    pub(super) fn begin_common_context(
        &mut self,
        entry: PendingBirthEntry,
        path: &Path,
        password: &str,
    ) -> Result<()> {
        if self.is_active() {
            return Err(Error::Locked);
        }
        // The actual dormant slot is irreversibly consumed before validation,
        // native entry, KDF, endpoint publication or external contact.
        let dormant = self
            .dormant_common_context
            .take()
            .ok_or(Error::ReviewMismatch)?;
        self.accept_blurred_read_completion = false;
        if !path.is_absolute() || !(12..=1024).contains(&password.len()) {
            return Err(Error::ReviewMismatch);
        }
        dormant.check_current()?;
        let deadline = dormant
            .completion_deadline()
            .min(Instant::now() + Duration::from_secs(120));
        let owner = Arc::new(PendingAccountNativeAuthority::enter_bounded(
            entry, deadline,
        )?);
        self.job = Some(Job::start(
            Work::OpenCommonContext(Box::new(dormant), path.to_path_buf(), Zeroizing::new(password.into())),
            owner.clone(),
        )?);
        self.owner = Some(owner);
        self.message="Opening exact original source for one already-admitted completion. Fresh pairing, witness contact and exact channel claim each require new native approval.";
        Ok(())
    }
    fn owner(&self, epoch: u64) -> Result<Arc<PendingAccountNativeAuthority>> {
        let owner = self.owner.as_ref().ok_or(Error::Locked)?;
        owner.check_current()?;
        if owner.focus_epoch() != epoch {
            return Err(Error::ReviewMismatch);
        }
        Ok(owner.clone())
    }
    fn context(&self) -> Result<Context> {
        if self.completion_opened.is_some() {
            return Err(Error::Unavailable);
        }
        let o = self.opened.as_ref().ok_or(Error::Locked)?;
        Ok(Context {
            publication_request: self
                .queued_continuation
                .as_ref()
                .map(|q| q.request.clone())
                .or_else(|| self.queued.as_ref().map(|q| q.request.clone())),
            account: o.account.clone(),
            ipc: o.ipc.clone(),
            _temporary: o._temporary.clone(),
            peer: self.peer.clone(),
            writer: self.writer.clone(),
            owner_client: self.owner_client.clone(),
            reentry: self.reentry.clone(),
            retained_reference: o.retained_reference.clone(),
            attempted: o.attempted,
            continuation: self.continuation.clone(),
            continued_reentry: self.continued_reentry.clone(),
        })
    }
    fn start(&mut self, work: Work, epoch: u64) -> Result<()> {
        if self.job.is_some() {
            return Err(Error::Locked);
        }
        self.job = Some(Job::start(work, self.owner(epoch)?)?);
        Ok(())
    }
    pub(super) fn clear(&mut self) {
        if let Some(drain) = self.named_reentry.clear() { self.cleanup.push(drain); }
        self.dormant_common_context = None;
        self.accept_blurred_read_completion = false;
        self.retire_foreground();
    }
    pub(super) fn blur(&mut self) {
        // Close foreground admission and any registered live construction
        // channel before checking the dormant source's filesystem identity.
        // Those checks can do I/O; they must never delay focus revocation.
        self.revoke_foreground_now();
        if self.named_continuation.is_some() && self.job.is_none()
            && self.review.is_none() && !self.named_controls.active()
        {
            if self.park_named().is_ok() { return; }
        }
        if self.owner.is_some() {
            self.accept_blurred_read_completion = self
                .job
                .as_ref()
                .is_some_and(|job| job.may_finish_common_context_read);
            if let Some(mut source) = self.inventory_source.take() {
                self.dormant_common_context = source.detach_dormant_common_context().ok();
                self.cleanup.push(std::thread::spawn(move || drop(source)));
            }
        }
        self.retire_foreground();
        if self
            .dormant_common_context
            .as_ref()
            .is_some_and(|d| d.check_current().is_err())
        {
            self.dormant_common_context = None;
        }
    }
    fn revoke_foreground_now(&self) {
        if let Some(open) = &self.stop_opened { open.revoke(); }
        if let Some(owner) = self.owner.as_ref() {
            owner.revoke_pending_now();
        }
        if let Some(open) = self.opened.as_ref() {
            open.revoke();
        }
        if let Some(open) = self.completion_opened.as_ref() {
            open.revocation.close_pending_now();
        }
    }
    fn retire_foreground(&mut self) {
        self.revoke_foreground_now();
        self.cleanup.extend(self.named_controls.clear());
        // Closing admission above is immediate. The last genuine native owner
        // may still need to drain a publication lease, so never drop it on GUI.
        let retired_owner = self.owner.take();
        self.bootstrap.clear();
        self.continuation_controller.clear();
        self.queued_continuation = None;
        self.queued = None;
        // Immediately revoke above; move potentially blocking connection/database
        // destructors off the GUI thread. At most the opened context and one
        // in-flight worker result can await cleanup; a new entry stays denied.
        if retired_owner.is_some()
            || self.stop_opened.is_some()
            || self.opened.is_some()
            || self.enrolled.is_some()
            || self.review.is_some()
            || self.writer.is_some()
            || self.owner_client.is_some()
            || self.reentry.is_some()
            || self.continuation.is_some()
            || self.continued_reentry.is_some()
            || self.continued_admission_retry.is_some()
            || self.inventory_source.is_some()
            || self.completion_opened.is_some()
            || self.completion_reentered.is_some()
            || self.named_continuation.is_some()
            || self.named_reentry.source.is_some()
        {
            let retired = (
                retired_owner,
                self.stop_opened.take(),
                self.opened.take(),
                self.enrolled.take(),
                self.review.take(),
                self.writer.take(),
                self.owner_client.take(),
                self.peer.take(),
                self.acquire_retry.take(),
                self.activation_retry.take(),
                self.admission_retry.take(),
                self.reentry.take(),
                self.continuation.take(),
                self.continued_reentry.take(),
                self.continued_admission_retry.take(),
                self.inventory_source.take(),
                self.completion_opened.take(),
                self.completion_reentered.take(),
                self.named_continuation.take(),
                self.named_reentry.source.take(),
            );
            self.cleanup.push(std::thread::spawn(move || drop(retired)));
        }
        self.peer = None;
        self.receipt = None;
        self.activated = false;
        self.signed = None;

        self.construction_plan_path.zeroize();
        self.construction_signed = None;
        self.construction_v3_signed = None;
        self.certificate.zeroize();
        self.key.zeroize();
        self.destination.zeroize();
        self.witness_setup.zeroize();
        self.confirmation.zeroize();
        self.message = "Manual enrollment closed. An already admitted durable operation may have finished. Preserve intent, journal and witness history; do not regenerate or replace the original operation.";
    }
    pub(super) fn poll_lifecycle(&mut self, focused: bool, epoch: u64) {
        self.named_controls.reap_cancelled();
        if self.named_reentry.poll().is_err() {
            self.clear();
            self.message = "Exact named source retirement failed. No reentry token or financial authority was created; original retained outcomes remain unchanged.";
        }
        if !focused {
            self.blur();
        }
        if self
            .dormant_common_context
            .as_ref()
            .is_some_and(|d| d.check_current().is_err())
        {
            self.dormant_common_context = None;
        }
        if self.owner.is_some()
            && (roster_clear_if!(!focused, ClearFocus)
                || roster_clear_if!(self.owner(epoch).is_err(), ClearOwner)
                || roster_clear_if!(self.peer.as_ref().is_some_and(|p| p.check_current().is_err()), ClearPeer)
                || roster_clear_if!(self.queued.as_ref().is_some_and(|q| admission::connected(&q.stream, &q.peer).is_err()), ClearInitialStream)
                || roster_clear_if!(self.queued_continuation.as_ref().is_some_and(|q| admission::connected(&q.stream, &q.peer).is_err()), ClearContinuedStream)
                || roster_clear_if!(self.review.as_ref().is_some_and(|r| r.exact.expired()), ClearReviewExpired))
        {
            self.clear();
        }
        self.cleanup.retain(|thread| !thread.is_finished());
        if self.job.as_ref().is_some_and(|j| j.thread.is_finished()) {
            let result = self.job.take().unwrap().finish();
            #[cfg(feature = "synthetic-born-joined-qualification")]
            synthetic_diagnostics::report_error(synthetic_diagnostics::Operation::ReceiveResult, &result);
            if roster_clear_if!(self.owner(epoch).is_err(), DropLateOutput) {
                if let Ok(output) = result {
                    match output {
                        Output::CommonContextReadServed(mut source)
                        | Output::CommonContextHandoffAuthorized(mut source)
                            if self.accept_blurred_read_completion =>
                        {
                            self.dormant_common_context =
                                source.detach_dormant_common_context().ok();
                            self.cleanup.push(std::thread::spawn(move || drop(source)));
                        }
                        output => self.cleanup.push(std::thread::spawn(move || drop(output))),
                    }
                }
                self.accept_blurred_read_completion = false;
                return;
            }
            #[cfg(feature = "synthetic-born-joined-qualification")]
            synthetic_diagnostics::report_begin(synthetic_diagnostics::Operation::AdoptOutput);
            let result=result.and_then(|out|{match out{
                Output::Stop(out)=>self.accept_stop_output(out)?,
                Output::Named(out)=>self.accept_named_output(*out,epoch)?,
                Output::CompletionOpened(open)=>{self.completion_opened=Some(*open);self.message="Exact original key-free source authenticated by fresh unlock. Only same original Host pairing and one completion handoff are permitted.";},
                Output::CompletionReentered(source)=>{self.completion_reentered=Some(*source);self.message="Exact new channel claimed and original transport fenced. A separate full-proposal native decision is required within the original channel deadline.";},
                Output::CompletionConsumed(source)=>{self.peer=None;self.named_continuation=Some(source);self.park_named()?;},
                Output::NamedReentryOpened(opened)=>self.accept_named_reentry_open(*opened)?,
                Output::NamedOwnerReady(actual)=>{self.named_continuation=Some(actual);self.message="Existing original owner credentials selected for this exact consumed source. Fresh same-Host pairing and every later exact decision remain required.";},
                Output::ConstructionSigned(s)=>{self.construction_signed=Some(s);self.message="Exact stable full-proposal owner approval signed privately. Separate destination export and independent witness-owner review remain required.";},
                Output::ConstructionV3Signed(s)=>{self.construction_v3_signed=Some(s);self.message="Exact stable full-proposal owner approval signed privately. Separate destination export and independent witness-owner review remain required.";},
                Output::ExactInputObservationServed(source)=>{self.inventory_source=Some(source);self.message="One additional exact-input privacy read admitted within its fixed bounds and original completion ceiling. Separate full-construction review and financial Reserve/Consume remain required. No deadline or financial authority was renewed.";},
                Output::CommonContextHandoffAuthorized(source)=>{self.inventory_source=Some(source);self.message="Exact future handoff authorization sent to this same Host. It remains inert until all actual reads, independent witness grant, fresh unlock and new native TLS-bound claim. Original expiry is unchanged.";},
                Output::CommonContextReadServed(source)=>{self.inventory_source=Some(source);self.message="One additional exact-input privacy read admitted within its fixed bounds and original completion ceiling. Separate full-construction review and financial Reserve/Consume remain required. No deadline or financial authority was renewed.";},
                Output::ConstructionServed(source)=>{self.inventory_source=Some(source);self.message="Exact full-proposal reservation consumed once for bounded non-signing construction. Its original completion deadline is unchanged. Conservative exposure remains retained; saved evidence grants no signing or dispatch authority.";},
                Output::ConstructionV3Served(source)=>{self.inventory_source=Some(source);self.message="Exact full-proposal reservation consumed once for bounded non-signing construction. Its original completion deadline is unchanged. Conservative exposure remains retained; saved evidence grants no signing or dispatch authority.";},
                Output::ConstructionExported=>{self.message="Exact full-proposal owner approval exported to the reviewed private destination. Saved approval is not financial authority. Complete separate witness-owner review before fresh continuation and full native contribution admission.";},
                Output::ConstructionV3Exported=>{self.message="Exact full-proposal owner approval exported to the reviewed private destination. Saved approval is not financial authority. Complete separate witness-owner review before fresh continuation and full native contribution admission.";},
                Output::CandidateSelectionServed(source)=>{self.inventory_source=Some(source);self.message="One private selection channel closed. Any selected contribution and full proposal still require fresh exact native review. No construction or financial permission was issued.";},
                Output::InventoryServed(source)=>{self.inventory_source=Some(source);self.message="Preliminary viewing channel closed. Copied viewing information cannot be recalled. No construction or financial permission was issued.";},
                Output::PolicyExported=>self.message="Complete original V2 policy preimage exported to the exact private destination. The file remains historical data and requires independent original witness comparison.",
                Output::Opened(o)=>{if o.attempted {self.continuation_controller.opened(o.retained_reference.clone().ok_or(Error::RecoveryRequired)?)?;self.continuation=o.continuation.clone();}else{self.bootstrap.opened(o.retained_reference.clone())?;}self.opened=Some(*o);self.message="Original born account authenticated. The separate local process must request pairing and then prove the delivered channel token.";},
                Output::ContinuationRetained(p)=>{self.continuation_controller.retained_proposal()?;self.continuation=Some(p);self.message="Immutable continuation retained. Sign and export it, then close this entry for independent witness review. No acquisition in this export entry.";},
                Output::ContinuationSigned=>self.message="Exact existing-owner signature retained in the immutable local attempt history. Export needs separate private destination review.",
                Output::ContinuedReentered(p)=>{self.continuation_controller.reviewed()?;self.continued_reentry=Some(p);self.message="Fresh current peer/native review accepted for the exact committed successor. The original continuation and first marker remain unchanged.";},
                Output::ContinuedAdmitted(approved,result)=>match result{Ok(p)=>{self.continued_admission_retry=None;let Prepared{step,digest,display}=*p;self.review=Some(Review{step,exact:ExactNativeReview::stage(self.owner(epoch)?.native(),&digest,display,epoch)?,displayed_to_end:false});},Err(_)=>{self.continued_admission_retry=Some(approved);self.message="Successor admission uncertain. Only the exact original in-process request may retry.";}},
                Output::Prepared(p)=>{let Prepared{step,digest,display}=*p;self.confirmation.zeroize();self.review=Some(Review{step,exact:ExactNativeReview::stage(self.owner(epoch)?.native(),&digest,display,epoch)?,displayed_to_end:false});},
                Output::Paired=>self.message="Pair request approved. A subsequent kernel-authenticated token-proving status request is still required.",
                Output::Reentered(r)=>{self.bootstrap.reviewed()?;self.reentry=Some(r);self.message="Fresh native reentry reviewed against unchanged original intent. Select the pinned witness and review the FIRST acquisition; any uncertain send permanently closes fresh reentry.";},
                Output::Retained=>self.message="Exact immutable manual intent retained. Separately review existing-owner signature, then private export for the independent witness owner.",
                Output::Signed(e)=>{self.signed=Some(e);self.message="Existing-owner signature retained in memory only. Private destination export needs another exact review.";},
                Output::Exported=>self.message="Exact signed terms exported privately. The independent witness owner must separately approve the extension; this file is no current authority.",
                Output::Witness(w,o)=>{self.writer=Some(w);self.owner_client=Some(o);self.message="Original pinned witness clients selected. Review fresh writer acquisition, then separate owner activation.";},
                Output::Acquired(approved,result)=>match result{Ok(r)=>{self.receipt=Some(*r);self.acquire_retry=None;self.message="Exact writer session acquired pending independent owner activation.";},Err(_)=>{self.acquire_retry=Some(approved);self.message="Writer acquisition uncertain. Only this exact in-process request can retry; process loss or expiry requires recovery.";}},
                Output::Activated(approved,result)=>match result{Ok(())=>{self.activated=true;self.activation_retry=None;self.message="Exact writer owner activation observed. Refresh complete history and review separate local journal publication.";},Err(_)=>{self.activation_retry=Some(approved);self.message="Owner activation uncertain. Preserve exact operation and retry only within this same native process/deadline.";}},
                Output::Admitted(approved,result)=>match result{Ok(p)=>{self.admission_retry=None;let Prepared { step, digest, display } = *p;self.review=Some(Review{step,exact:ExactNativeReview::stage(self.owner(epoch)?.native(),&digest,display,epoch)?,displayed_to_end:false});},Err(_)=>{self.admission_retry=Some(approved);self.message="Witness publication admission uncertain. Only this exact frozen in-process request may retry; no regenerated head/session is permitted.";}},
                Output::Served=>self.message="Finite exact enrollment publication channel closed. Durable original intent/admission/completion remain unchanged. No financial authority was issued.",
                Output::Enrolled(e)=>{if self.opened.as_ref().is_some_and(|o|o.attempted) {self.continuation_controller.published()?;}else{self.bootstrap.published()?;}self.enrolled=Some(e);self.message="Exact first signer journal and immutable born manual record preserved. Roster balance inventory, candidate selection, financial/key-release/action gates remain denied pending their coherent V2 per-action issuer.";},
            }Ok(())});
            #[cfg(feature = "synthetic-born-joined-qualification")]
            synthetic_diagnostics::report_result(synthetic_diagnostics::Operation::AdoptOutput, &result);
            if result.is_err() {
                self.clear();
                self.message = "Enrollment step failed or became uncertain. Preserve all source and output state. No replacement or synthetic approval was made.";
            }
        }
        // A Finished ack can reach the Host before this worker has returned.
        // Keep a newly queued pairing behind the job. The finished-result arm
        // above installs the source first, or clears the owner on any failure.
        if !queued_event_ready(
            self.job.is_some(),
            self.review.is_some(),
            self.owner.is_some(),
        ) {
            return;
        }
        if self.stop_opened.is_some() {
            if self.poll_stop_event(epoch).is_err() { self.clear(); self.message="Restriction propagation ended or became uncertain. Durable originals remain; reopen for exact retry."; }
            return;
        }
        if self.named_continuation.is_some() {
            if self.poll_named_event(epoch).is_err() { self.clear(); self.message="Exact born payment continuation closed. Original exposure and retained results remain unchanged."; }
            return;
        }
        if self.named_reentry.source.is_some() { return; }
        if self.completion_opened.is_some() {
            if self.poll_completion_event(epoch).is_err() {
                self.clear();
                self.message="Original completion ended or became uncertain. No replacement or retry owner was created.";
            }
            return;
        }
        if let Some(enrolled) = self.enrolled.clone() {
            if let Some(queued) = self.queued_continuation.take() {
                if self
                    .start(
                        Work::PrepareContinuedServe(
                            enrolled,
                            queued.peer,
                            queued.stream,
                            queued.request,
                        ),
                        epoch,
                    )
                    .is_err()
                {
                    self.clear();
                }
                return;
            }
            if let Some(queued) = self.queued.take() {
                if self
                    .start(
                        Work::PrepareServe(enrolled, queued.peer, queued.stream, queued.request),
                        epoch,
                    )
                    .is_err()
                {
                    self.clear();
                }
                return;
            }
        }

        let event = self
            .opened
            .as_ref()
            .and_then(|o| o.ipc.try_lock().ok().and_then(|ipc| ipc.next_event()));
        match event {
            Some(LocalEvent::BornRosterExactInputObservationV1 {
                peer,
                stream,
                request,
            }) => {
                let Some(source) = self.inventory_source.take() else {
                    return;
                };
                if self
                    .peer
                    .as_ref()
                    .is_none_or(|p| p.grant_id != peer.grant_id)
                {
                    self.clear();
                    return;
                }
                if self
                    .context()
                    .and_then(|c| {
                        self.start(
                            Work::PrepareExactInputObservation(Box::new(
                                ExactInputObservationWork {
                                    context: c,
                                    source,
                                    peer,
                                    stream,
                                    request,
                                },
                            )),
                            epoch,
                        )
                    })
                    .is_err()
                {
                    self.clear();
                }
            }
            Some(LocalEvent::BornRosterCommonContextReadV1 {
                peer,
                stream,
                request,
            }) => {
                let Some(source) = self.inventory_source.take() else {
                    return;
                };
                if self
                    .peer
                    .as_ref()
                    .is_none_or(|p| p.grant_id != peer.grant_id)
                {
                    self.clear();
                    return;
                }
                if self
                    .context()
                    .and_then(|c| {
                        self.start(
                            Work::PrepareCommonContextRead(Box::new(CommonContextReadWork {
                                context: c,
                                source,
                                peer,
                                stream,
                                request,
                            })),
                            epoch,
                        )
                    })
                    .is_err()
                {
                    self.clear();
                }
            }
            Some(LocalEvent::BornRosterCommonContextHandoffAuthorizationV1 {
                peer,
                stream,
                request,
            }) => {
                let Some(source) = self.inventory_source.take() else {
                    return;
                };
                if self
                    .peer
                    .as_ref()
                    .is_none_or(|p| p.grant_id != peer.grant_id)
                {
                    self.clear();
                    return;
                }
                let work = CommonContextHandoffWork {
                    source,
                    peer,
                    stream,
                    request,
                    certificate_path: PathBuf::from(self.certificate.as_str()),
                    key_path: PathBuf::from(self.key.as_str()),
                };
                if self
                    .start(
                        Work::PrepareCommonContextHandoffAuthorization(Box::new(work)),
                        epoch,
                    )
                    .is_err()
                {
                    self.clear();
                }
            }
            Some(LocalEvent::BornRosterConstructionV2 {
                peer,
                stream,
                request,
            }) => {
                let Some(source) = self.inventory_source.take() else {
                    return;
                };
                if self
                    .peer
                    .as_ref()
                    .is_none_or(|p| p.grant_id != peer.grant_id)
                {
                    self.clear();
                    return;
                }
                if self
                    .context()
                    .and_then(|c| {
                        self.start(
                            Work::PrepareConstruction(Box::new(ConstructionWork {
                                context: c,
                                source,
                                peer,
                                stream,
                                request,
                            })),
                            epoch,
                        )
                    })
                    .is_err()
                {
                    self.clear();
                }
            }
            Some(LocalEvent::BornRosterConstructionV3 {
                peer,
                stream,
                request,
            }) => {
                let Some(source) = self.inventory_source.take() else {
                    return;
                };
                if self
                    .peer
                    .as_ref()
                    .is_none_or(|p| p.grant_id != peer.grant_id)
                {
                    self.clear();
                    return;
                }
                if self
                    .context()
                    .and_then(|c| {
                        self.start(
                            Work::PrepareConstructionV3(Box::new(ConstructionV3Work {
                                context: c,
                                source,
                                peer,
                                stream,
                                request,
                            })),
                            epoch,
                        )
                    })
                    .is_err()
                {
                    self.clear();
                }
            }
            Some(LocalEvent::BornRosterCandidateSelectionV2 {
                peer,
                stream,
                request,
            }) => {
                let Some(source) = self.inventory_source.take() else {
                    return;
                };
                if self
                    .peer
                    .as_ref()
                    .is_none_or(|p| p.grant_id != peer.grant_id)
                {
                    self.clear();
                    return;
                }
                match self.context().and_then(|c| {
                    self.start(
                        Work::PrepareCandidateSelection(Box::new(CandidateSelectionWork {
                            context: c,
                            source,
                            peer,
                            stream,
                            request,
                        })),
                        epoch,
                    )
                }) {
                    Ok(()) => {}
                    Err(_) => self.clear(),
                }
            }
            Some(LocalEvent::BornRosterInventoryV2 {
                peer,
                stream,
                request,
            }) => {
                let Some(source) = self.inventory_source.take() else {
                    return;
                };
                if self
                    .peer
                    .as_ref()
                    .is_none_or(|p| p.grant_id != peer.grant_id)
                {
                    self.clear();
                    return;
                }
                match self.context().and_then(|c| {
                    self.start(
                        Work::PrepareInventory(Box::new(InventoryWork {
                            context: c,
                            source,
                            peer,
                            stream,
                            request,
                        })),
                        epoch,
                    )
                }) {
                    Ok(()) => {}
                    Err(_) => self.clear(),
                }
            }
            Some(LocalEvent::BornManualRosterEnrollmentV2 {
                peer,
                stream,
                request,
            }) if matches!(
                request.attempt,
                ManualRosterPublicationAttemptV2::ContinuationV2 { .. }
            ) =>
            {
                if let Some(enrolled) = self.enrolled.clone() {
                    if self
                        .start(
                            Work::PrepareContinuedServe(enrolled, peer, stream, request),
                            epoch,
                        )
                        .is_err()
                    {
                        self.clear();
                    }
                    return;
                }
                let valid = self.opened.as_ref().is_some_and(|o| o.attempted)
                    && self.queued_continuation.is_none()
                    && self
                        .peer
                        .as_ref()
                        .is_some_and(|p| p.grant_id == peer.grant_id)
                    && admission::connected(&stream, &peer).is_ok();
                if !valid
                    || request
                        .digest()
                        .ok()
                        .is_none_or(|d| self.continuation_controller.queue(d).is_err())
                {
                    drop(stream);
                    return;
                }
                self.queued_continuation = Some(QueuedContinuation {
                    peer,
                    stream,
                    request,
                });
                self.message = "Exact V2 continuation request queued as inert data. Select original witness clients and review fresh continuation reentry before any acquisition.";
            }
            Some(LocalEvent::BornManualRosterEnrollmentV2 {
                peer,
                stream,
                request,
            }) => {
                if let Some(enrolled) = self.enrolled.clone() {
                    if self
                        .start(Work::PrepareServe(enrolled, peer, stream, request), epoch)
                        .is_err()
                    {
                        self.clear();
                    }
                } else {
                    let valid = self.queued.is_none()
                        && self
                            .peer
                            .as_ref()
                            .is_some_and(|old| old.grant_id == peer.grant_id)
                        && peer.check_current().is_ok()
                        && admission::connected(&stream, &peer).is_ok()
                        && self.bootstrap.queue().is_ok();
                    if !valid {
                        drop(stream);
                        return;
                    }
                    let review_request = request.clone();
                    self.queued = Some(QueuedEnrollment {
                        peer,
                        stream,
                        request,
                    });
                    let result = self
                        .context()
                        .and_then(|c| self.start(Work::PrepareReentry(c, review_request), epoch));
                    if result.is_err() {
                        self.clear();
                    }
                }
            }
            Some(LocalEvent::Pairing(pair)) => {
                if self.peer.is_some() {
                    let result = (|| -> Result<BornRosterInventorySourceV2> {
                        let old = self.peer.as_ref().ok_or(Error::Authentication)?;
                        let enrolled = self.enrolled.clone().ok_or(Error::Unavailable)?;
                        pair.same_live_peer(old)?;
                        if pair.scope.account_id != old.scope.account_id
                            || pair.scope.agreement_id != old.scope.agreement_id
                            || pair.scope.participant_id != old.scope.participant_id
                            || pair.scope.history_read
                            || pair.scope.authorization_export
                            || pair.scope.preconstruction_export
                        {
                            return Err(Error::Authentication);
                        }
                        let owner = self.owner(epoch)?;
                        let source = match self.inventory_source.take() {
                            Some(source) => source.prepare_next_pair(old, owner.as_ref())?,
                            None => BornRosterInventorySourceV2::prepare_repair(
                                enrolled,
                                owner.as_ref(),
                            )?,
                        };
                        old.retire_now();
                        Ok(source)
                    })();
                    match result {
                        Ok(source) => {
                            self.inventory_source = Some(source);
                            self.peer = None;
                        }
                        Err(_) => return,
                    }
                }
                if let Some(open) = &self.opened {
                    if pair.scope.account_id != open.account_id
                        || self.peer.is_some()
                        || pair.scope.history_read
                        || pair.scope.authorization_export
                        || pair.scope.preconstruction_export
                    {
                        return;
                    }
                    let generation = match open.ipc.try_lock() {
                        Ok(ipc) => ipc.generation(),
                        Err(_) => return,
                    };
                    let result: Result<Review> = (|| {
                        let owner = self.owner(epoch)?;
                        let digest = pair.review_digest(generation)?;
                        let purpose = if self.inventory_source.is_some() {
                            "DISTINCT NON-SIGNING PURPOSE: manifest_digest commits the exact preliminary-viewing scope, candidate-selection scope, or full-proposal construction plan. Pairing alone releases no viewing data and grants no selection, retention, construction or signing permission; the specific operation requires a separate exact native review. The old publication grant is retired; original native/session deadlines are unchanged."
                        } else {
                            "MANUAL ENROLLMENT: manifest_digest is the exact request-only enrollment intent or full V2 continuation commitment. No transaction is authorized."
                        };
                        let display = format!(
                            "{purpose}\nPAIR ONE EXACT LOCAL PROCESS FOR MANUAL ENROLLMENT\nThe scope manifest_digest field is the exact request-only enrollment intent digest, not a transaction manifest. Legacy history/export flags must all be false.\nUnverified application label: {}\nActual UID/PID: {} / {}\nActual process instance: {}\n{}\n\nThe native owner reviews this association. It does not authenticate a publisher or the host's encrypted target. All financial requests are denied here. The grant is bounded by this original native entry deadline, focus, process lifetime and parent channel; displayed general grant TTL cannot extend it.",
                            pair.label,
                            pair.uid(),
                            pair.pid(),
                            pair.instance(),
                            serde_json::to_string_pretty(&pair.scope)
                                .map_err(|_| Error::InvalidData)?
                        );
                        Ok(Review {
                            step: Step::Pair(Box::new(pair)),
                            exact: ExactNativeReview::stage(
                                owner.native(),
                                &digest,
                                display,
                                epoch,
                            )?,
                            displayed_to_end: false,
                        })
                    })();
                    if let Ok(review) = result {
                        self.review = Some(review);
                    }
                }
            }
            Some(LocalEvent::Request {
                peer,
                request: crate::ipc::AppRequest::Status {},
            }) => {
                if let Some(open) = &self.opened {
                    if peer.scope.account_id == open.account_id
                        && self
                            .peer
                            .as_ref()
                            .is_none_or(|old| old.grant_id == peer.grant_id)
                        && peer.check_current().is_ok()
                    {
                        self.peer = Some(peer);
                        self.message = "Actual paired process proved current channel possession. Exact host intent may now be reviewed; its encrypted Store is still verified only by the host.";
                    }
                }
            }
            Some(LocalEvent::Request {
                peer,
                request:
                    crate::ipc::AppRequest::RequestBornManualRosterEnrollmentIntentV2 { ref request },
            }) => {
                let valid = self
                    .opened
                    .as_ref()
                    .is_some_and(|o| peer.scope.account_id == o.account_id)
                    && self
                        .peer
                        .as_ref()
                        .is_none_or(|old| old.grant_id == peer.grant_id)
                    && peer.check_current().is_ok()
                    && request
                        .digest()
                        .is_ok_and(|digest| digest == peer.scope.manifest_digest)
                    && request.account_intent.scope.agreement_id == peer.scope.agreement_id
                    && request.account_intent.scope.participant_id == peer.scope.participant_id;
                if valid {
                    self.peer = Some(peer);
                    if self.opened.as_ref().is_some_and(|o| o.attempted) {
                        self.message = "Original host intent paired for continuation proposal review. Select the original witness; no new enrollment is created.";
                        return;
                    }
                    let result = self
                        .context()
                        .and_then(|c| self.start(Work::PrepareIntent(c, request.clone()), epoch));
                    if result.is_err() {
                        self.message = "Exact paired host intent could not be prepared. No terms or approval were fabricated.";
                    }
                }
            }
            // All other legacy financial/history/result request streams close.
            // This workspace never forwards them to generic runtime activation.
            _ => {}
        }
    }
    fn poll_completion_event(&mut self, epoch: u64) -> Result<()> {
        let owner = self.owner(epoch)?;
        if let Some(source) = self
            .completion_opened
            .as_ref()
            .and_then(|o| o.source.as_ref())
        {
            source.check(&owner)?;
        }
        if let Some(source) = self.completion_reentered.as_ref() {
            source.check(&owner)?;
        }
        let event = self
            .completion_opened
            .as_ref()
            .and_then(|o| o.ipc.try_lock().ok().and_then(|ipc| ipc.next_event()));
        match event {
            Some(LocalEvent::Pairing(pair)) => {
                if self.peer.is_some() {
                    return Err(Error::ReviewMismatch);
                }
                let open = self.completion_opened.as_ref().ok_or(Error::Locked)?;
                open.source
                    .as_ref()
                    .ok_or(Error::ReviewMismatch)?
                    .check_pairing(&pair, &owner)?;
                let generation = open.ipc.lock().map_err(|_| Error::Locked)?.generation();
                let digest = pair.review_digest(generation)?;
                let display=format!("PAIR SAME ORIGINAL HOST FOR ONE ALREADY-ADMITTED COMPLETION\n{}\nActual UID/PID: {} / {}; process instance {}. This new grant permits no additional read, enrollment, ordinary writer use, signing or dispatch. A new exact witness selection and channel claim decision remain mandatory.",serde_json::to_string_pretty(&pair.scope).map_err(|_|Error::InvalidData)?,pair.uid(),pair.pid(),pair.instance());
                self.review = Some(Review {
                    step: Step::Pair(Box::new(pair)),
                    exact: ExactNativeReview::stage(owner.native(), &digest, display, epoch)?,
                    displayed_to_end: false,
                });
            }
            Some(LocalEvent::Request {
                peer,
                request: crate::ipc::AppRequest::Status {},
            }) => {
                self.completion_opened
                    .as_ref()
                    .and_then(|o| o.source.as_ref())
                    .ok_or(Error::ReviewMismatch)?
                    .check_peer(&peer, &owner)?;
                if self
                    .peer
                    .as_ref()
                    .is_some_and(|p| p.grant_id != peer.grant_id)
                {
                    return Err(Error::ReviewMismatch);
                }
                self.peer = Some(peer);
            }
            Some(LocalEvent::BornRosterCommonContextReentryV1 {
                peer,
                stream,
                request,
                pending_grant_json,
            }) => {
                let open = self.completion_opened.as_mut().ok_or(Error::Locked)?;
                if open.queued.is_some()
                    || self
                        .peer
                        .as_ref()
                        .is_none_or(|p| p.grant_id != peer.grant_id)
                {
                    return Err(Error::ReviewMismatch);
                }
                open.source
                    .as_ref()
                    .ok_or(Error::ReviewMismatch)?
                    .check_peer(&peer, &owner)?;
                open.queued = Some(CompletionRequest {
                    peer,
                    stream,
                    request,
                    pending_grant_json: Zeroizing::new(pending_grant_json),
                });
                self.message="Exact handoff request queued. Select existing original pinned witness credentials and review contact before any network work.";
            }
            Some(LocalEvent::BornRosterReenteredConstructionV1 {
                peer,
                stream,
                request,
                reentry_lineage_digest,
            }) => {
                let source = self
                    .completion_reentered
                    .take()
                    .ok_or(Error::ReviewMismatch)?;
                self.start(
                    Work::PrepareReenteredConstruction(Box::new(ReenteredWork {
                        source,
                        peer,
                        stream,
                        request,
                        lineage_digest: reentry_lineage_digest,
                    })),
                    epoch,
                )?;
            }
            None => {}
            _ => return Err(Error::Unavailable),
        }
        Ok(())
    }
    fn approve(&mut self, focused: bool, epoch: u64) -> Result<()> {
        let review = self.review.take().ok_or(Error::ReviewMismatch)?;
        if !review.displayed_to_end {
            return Err(Error::ReviewMismatch);
        }
        let decision = review
            .exact
            .consume_native_click(focused, epoch, &self.confirmation)?;
        self.confirmation.zeroize();
        if let Step::NamedReentryWitness(prepared) = review.step {
            return self.start(Work::ApproveNamedWitness(prepared, decision), epoch);
        }
        if let Step::Named(step) = review.step {
            let actual = self.named_continuation.take().ok_or(Error::Locked)?;
            return self.start(Work::Named(Box::new(named_controls::NamedWork::Commit(actual,*step,decision))),epoch);
        }
        if let Some(open) = self.stop_opened.as_ref() {
            self.start(Work::Stop(permanent_stop_flow::StopWork::Commit(open.ipc.clone(), review.step, decision)), epoch)
        } else if let Some(open) = self.completion_opened.as_ref() {
            self.start(
                Work::CommitCompletion(open.ipc.clone(), review.step, decision),
                epoch,
            )
        } else {
            self.start(Work::Commit(self.context()?, review.step, decision), epoch)
        }
    }
    pub(super) fn ui(
        &mut self,
        ui: &mut egui::Ui,
        focused: bool,
        epoch: u64,
    ) -> Option<&'static str> {
        self.poll_lifecycle(focused, epoch);
        ui.heading("Original born account: immutable Host roster enrollment V2");
        ui.label(self.message);
        ui.label("This bounded native entry does not renew after network, pairing or review. Expiry hides private data and invalidates further admission. Already admitted commits may drain.");
        if !focused {
            return Some(self.message);
        }
        if self.job.is_some() || !self.cleanup.is_empty() || self.named_reentry.draining()
            || (self.owner.is_none() && self.named_controls.active()) {
            ui.ctx().request_repaint_after(Duration::from_millis(50));
            if ui
                .button("Cancel and close admission")
                .clicked_by(egui::PointerButton::Primary)
            {
                self.clear();
            }
            return Some(self.message);
        }
        if self.owner.is_none() {
            return Some(self.message);
        }
        if self.stop_opened.is_some() && self.review.is_none() {
            if self.stop_controls(ui, epoch).is_err() { self.clear(); }
            return Some(self.message);
        }
        if self.enrolled.is_some() && self.review.is_none() && ui.button("Permanently stop routine reuse of this original born account").clicked_by(egui::PointerButton::Primary) {
            if self.transition_permanent_stop(epoch).is_err() { self.message="Permanent-stop entry remains unavailable pending native/kernel qualification; original ownership is unchanged."; }
            return Some(self.message);
        }
        if self.named_continuation.is_some() && self.review.is_none() {
            if self.named_ui(ui,focused,epoch).is_err() { self.clear(); }
            return Some(self.message);
        }
        if self.named_reentry.source.is_some() && self.review.is_none() {
            if self.named_reentry_ui(ui, epoch).is_err() { self.clear(); }
            return Some(self.message);
        }
        if self.completion_opened.is_some() && self.review.is_none() {
            ui.label("Purpose-limited original completion only. All ordinary account and enrollment controls remain closed.");
            ui.label("Existing pinned witness credential-selection JSON");
            ui.add(egui::TextEdit::multiline(&mut *self.witness_setup).char_limit(16 * 1024));
            if ui
                .add_enabled(
                    self.completion_opened
                        .as_ref()
                        .is_some_and(|o| o.queued.is_some() && o.source.is_some())
                        && !self.witness_setup.is_empty(),
                    egui::Button::new("Review exact original witness contact"),
                )
                .clicked_by(egui::PointerButton::Primary)
            {
                let result = (|| -> Result<()> {
                    let open = self.completion_opened.as_mut().ok_or(Error::Locked)?;
                    let source = open.source.take().ok_or(Error::ReviewMismatch)?;
                    let request = open.queued.take().ok_or(Error::ReviewMismatch)?;
                    let setup = Zeroizing::new(self.witness_setup.to_string());
                    self.witness_setup.zeroize();
                    self.start(
                        Work::PrepareCompletionWitness(Box::new(CompletionWork {
                            source,
                            request,
                            setup,
                        })),
                        epoch,
                    )
                })();
                if result.is_err() {
                    self.clear();
                }
            }
            if ui
                .button("Cancel original completion")
                .clicked_by(egui::PointerButton::Primary)
            {
                self.clear();
            }
            return Some(self.message);
        }
        enum Action {
            ConstructionSign,
            ConstructionV3Sign,
            ConstructionExport,
            ConstructionV3Export,
            None,
            Continue,
            Approve,
            Close,
            Sign,
            Export,
            PolicyExport,
            Witness,
            Acquire,
            Activate,
            Publish,
            RetryAdmission,
            RetryAcquire,
            RetryActivate,
            ProposeContinuation,
            ReviewContinuedReentry,
            RetryContinuedAdmission,
        }
        let mut action = Action::None;
        if let Some(review) = &mut self.review {
            let scroll = egui::ScrollArea::vertical()
                .id_salt("born-manual-roster-v2-review")
                .max_height(440.0)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new(inert_text(review.exact.display())).monospace())
                });
            if scroll.state.offset.y + scroll.inner_rect.height() + 1.0 >= scroll.content_size.y {
                review.displayed_to_end = true;
            }
            if review.exact.confirming() {
                let phrase = format!("AUTHORIZE {}", &review.exact.digest()[..12]);
                ui.label(format!("Type {phrase}"));
                ui.add(egui::TextEdit::singleline(&mut *self.confirmation).char_limit(64));
                if ui
                    .add_enabled(
                        *self.confirmation == phrase,
                        egui::Button::new(if self.stop_opened.is_some() { "Approve exact permanent-stop step" } else { "Approve exact manual-enrollment step" }),
                    )
                    .clicked_by(egui::PointerButton::Primary)
                {
                    action = Action::Approve;
                }
            } else if ui
                .add_enabled(
                    review.displayed_to_end,
                    egui::Button::new("Continue after reviewing every term"),
                )
                .clicked_by(egui::PointerButton::Primary)
            {
                action = Action::Continue;
            }
        } else if let Some(open) = &self.opened {
            egui::ScrollArea::vertical()
                .id_salt("born-manual-roster-v2-origin")
                .max_height(160.0)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new(inert_text(&open.display)).monospace())
                });
            ui.label("The actually paired process must send its bounded host-generation/manual-scope intent. Only request data crosses IPC; signer-derived terms require the native review and separate exact signed export. No caller-supplied approval, signer hash or placeholder is accepted.");
            ui.label("Exact full construction-plan file in an existing private directory");
            ui.add(egui::TextEdit::singleline(&mut *self.construction_plan_path).char_limit(4096));
            if ui
                .add_enabled(
                    !self.construction_plan_path.is_empty(),
                    egui::Button::new(
                        "Review existing-owner signature of exact full construction plan",
                    ),
                )
                .clicked_by(egui::PointerButton::Primary)
            {
                action = Action::ConstructionSign;
            }
            if ui
                .add_enabled(
                    self.construction_signed.is_some(),
                    egui::Button::new("Review private export of exact full construction approval"),
                )
                .clicked_by(egui::PointerButton::Primary)
            {
                action = Action::ConstructionExport;
            }
            ui.label("V3 common-context construction is unavailable pending complete composition qualification. Original deadlines and all V2 history remain unchanged.");
            if ui
                .add_enabled(
                    crate::ipc::COMMON_CONTEXT_V3_COMPOSITION_QUALIFIED
                        && !self.construction_plan_path.is_empty(),
                    egui::Button::new("Review exact V3 common-context owner signature"),
                )
                .clicked_by(egui::PointerButton::Primary)
            {
                action = Action::ConstructionV3Sign;
            }
            if ui
                .add_enabled(
                    crate::ipc::COMMON_CONTEXT_V3_COMPOSITION_QUALIFIED
                        && self.construction_v3_signed.is_some(),
                    egui::Button::new("Review private V3 common-context approval export"),
                )
                .clicked_by(egui::PointerButton::Primary)
            {
                action = Action::ConstructionV3Export;
            }
            ui.label("Existing original owner certificate DER and PKCS8 key file paths");
            ui.add(egui::TextEdit::singleline(&mut *self.certificate).char_limit(4096));
            ui.add(egui::TextEdit::singleline(&mut *self.key).char_limit(4096));
            if ui
                .add_enabled(
                    !open.attempted || self.continuation.is_some(),
                    egui::Button::new(if open.attempted {
                        "Review signing exact retained continuation"
                    } else {
                        "Review signing retained extension with existing owner credential"
                    }),
                )
                .clicked_by(egui::PointerButton::Primary)
            {
                action = Action::Sign;
            }
            ui.label("Existing private export directory; exported extension includes exact signer-derived terms for the host and independent witness owner");
            ui.add(egui::TextEdit::singleline(&mut *self.destination).char_limit(4096));
            if ui
                .add_enabled(
                    self.signed.is_some() || open.attempted && self.continuation.is_some(),
                    egui::Button::new(if open.attempted {
                        "Review exact private signed-continuation export"
                    } else {
                        "Review exact private signed-extension export"
                    }),
                )
                .clicked_by(egui::PointerButton::Primary)
            {
                action = Action::Export;
            }
            if ui
                .button("Review private export of full ORIGINAL V2 recipient policy")
                .clicked_by(egui::PointerButton::Primary)
            {
                action = Action::PolicyExport;
            }
            if self.bootstrap.initial_export() {
                ui.label("This entry is export-only. Return to the host to close it, commit the independent witness extension, then use the separate publish command to launch a fresh native reentry. First acquisition is unavailable in this entry.");
            }
            ui.label("After independent native witness approval, select existing original owner/writer credentials (paths and operator labels only)");
            ui.add(
                egui::TextEdit::multiline(&mut *self.witness_setup)
                    .desired_rows(4)
                    .char_limit(16 * 1024),
            );
            if ui
                .add_enabled(
                    self.writer.is_none(),
                    egui::Button::new("Review contacting original pinned witness"),
                )
                .clicked_by(egui::PointerButton::Primary)
            {
                action = Action::Witness;
            }
            if open.attempted
                && self.continuation_controller.can_propose()
                && self.writer.is_some()
                && self.peer.is_some()
                && ui
                    .button(
                        "Review new exact continuation against complete original witness history",
                    )
                    .clicked_by(egui::PointerButton::Primary)
            {
                action = Action::ProposeContinuation;
            }
            if open.attempted
                && self.continuation_controller.queued()
                && self.writer.is_some()
                && ui
                    .button("Review fresh current entry for the exact committed continuation")
                    .clicked_by(egui::PointerButton::Primary)
            {
                action = Action::ReviewContinuedReentry;
            }
            if self.continued_admission_retry.is_some()
                && ui
                    .button("Retry exact retained successor admission")
                    .clicked_by(egui::PointerButton::Primary)
            {
                action = Action::RetryContinuedAdmission;
            }
            if ((self.bootstrap.can_acquire() && self.reentry.is_some() && self.queued.is_some())
                || (self.continuation_controller.can_acquire()
                    && self.continued_reentry.is_some()
                    && self.queued_continuation.is_some()))
                && self.writer.is_some()
                && self.receipt.is_none()
                && self.acquire_retry.is_none()
                && ui
                    .button("Review exact fresh writer acquisition")
                    .clicked_by(egui::PointerButton::Primary)
            {
                action = Action::Acquire;
            }
            if self.acquire_retry.is_some()
                && ui
                    .button("Retry only retained in-process writer acquisition")
                    .clicked_by(egui::PointerButton::Primary)
            {
                action = Action::RetryAcquire;
            }
            if self.receipt.is_some()
                && !self.activated
                && self.activation_retry.is_none()
                && ui
                    .button("Review separate original-owner writer activation")
                    .clicked_by(egui::PointerButton::Primary)
            {
                action = Action::Activate;
            }
            if self.activation_retry.is_some()
                && ui
                    .button("Retry only retained owner activation")
                    .clicked_by(egui::PointerButton::Primary)
            {
                action = Action::RetryActivate;
            }
            if self.admission_retry.is_some()
                && ui
                    .button("Retry exact frozen publication admission")
                    .clicked_by(egui::PointerButton::Primary)
            {
                action = Action::RetryAdmission;
            }
            if self.activated
                && self.admission_retry.is_none()
                && self.continued_admission_retry.is_none()
                && self.enrolled.is_none()
                && ui
                    .button("Refresh history and review one exact signer journal publication")
                    .clicked_by(egui::PointerButton::Primary)
            {
                action = Action::Publish;
            }
            ui.label("Losing the ephemeral writer session cannot be repaired by regenerating an enrollment or by a saved certificate/receipt. Preserve exact evidence and use the separately qualified recovery path when available.");
        }
        if ui
            .button("Close manual enrollment")
            .clicked_by(egui::PointerButton::Primary)
        {
            action = Action::Close;
        }
        let result = (|| -> Result<()> {
            match action {
                Action::ConstructionSign => self.start(
                    Work::PrepareConstructionSign(
                        self.context()?,
                        PathBuf::from(self.certificate.as_str()),
                        PathBuf::from(self.key.as_str()),
                        PathBuf::from(self.construction_plan_path.as_str()),
                    ),
                    epoch,
                )?,
                Action::ConstructionV3Sign => self.start(
                    Work::PrepareConstructionV3Sign(
                        self.context()?,
                        PathBuf::from(self.certificate.as_str()),
                        PathBuf::from(self.key.as_str()),
                        PathBuf::from(self.construction_plan_path.as_str()),
                    ),
                    epoch,
                )?,
                Action::ConstructionExport => {
                    let context = self.context()?;
                    let envelope = self
                        .construction_signed
                        .take()
                        .ok_or(Error::ReviewMismatch)?;
                    self.start(
                        Work::PrepareConstructionExport(
                            context,
                            envelope,
                            PathBuf::from(self.destination.as_str()),
                        ),
                        epoch,
                    )?;
                }
                Action::ConstructionV3Export => {
                    let context = self.context()?;
                    let envelope = self
                        .construction_v3_signed
                        .take()
                        .ok_or(Error::ReviewMismatch)?;
                    self.start(
                        Work::PrepareConstructionV3Export(
                            context,
                            envelope,
                            PathBuf::from(self.destination.as_str()),
                        ),
                        epoch,
                    )?;
                }
                Action::None => {}
                Action::Continue => self
                    .review
                    .as_mut()
                    .ok_or(Error::ReviewMismatch)?
                    .exact
                    .continue_from_native_click(focused, epoch)?,
                Action::Approve => self.approve(focused, epoch)?,
                Action::Close => self.clear(),
                Action::Sign => {
                    let c = self.context()?;
                    let cert = PathBuf::from(self.certificate.as_str());
                    let key = PathBuf::from(self.key.as_str());
                    let work = if c.attempted {
                        Work::PrepareContinuationSign(c, cert, key)
                    } else {
                        Work::PrepareSignature(c, cert, key)
                    };
                    self.start(work, epoch)?;
                }
                Action::Export => {
                    let context = self.context()?;
                    let path = PathBuf::from(self.destination.as_str());
                    let work = if context.attempted {
                        Work::PrepareContinuationExport(context, path)
                    } else {
                        Work::PrepareExport(
                            context,
                            self.signed.take().ok_or(Error::ReviewMismatch)?,
                            path,
                        )
                    };
                    self.start(work, epoch)?
                }
                Action::PolicyExport => self.start(
                    Work::PreparePolicyExport(
                        self.context()?,
                        PathBuf::from(self.destination.as_str()),
                    ),
                    epoch,
                )?,
                Action::Witness => self.start(
                    Work::PrepareWitness(
                        self.context()?,
                        Zeroizing::new(self.witness_setup.to_string()),
                    ),
                    epoch,
                )?,
                Action::Acquire => {
                    if self.opened.as_ref().is_some_and(|o| o.attempted) {
                        self.continuation_controller.begin_acquire()?;
                    } else {
                        self.bootstrap.begin_acquire()?;
                    }
                    self.start(Work::PrepareAcquire(self.context()?), epoch)?;
                }
                Action::Activate => self.start(
                    Work::PrepareActivate(
                        self.context()?,
                        Box::new(self.receipt.clone().ok_or(Error::Locked)?),
                    ),
                    epoch,
                )?,
                Action::Publish => self.start(Work::PreparePublication(self.context()?), epoch)?,
                Action::RetryAdmission => {
                    let a = self.admission_retry.take().ok_or(Error::Locked)?;
                    self.start(Work::RetryAdmission(a), epoch)?
                }
                Action::RetryAcquire => {
                    let c = self.context()?;
                    let a = self.acquire_retry.take().ok_or(Error::Locked)?;
                    self.start(Work::RetryAcquire(c, a), epoch)?
                }
                Action::ProposeContinuation => {
                    self.start(Work::PrepareContinuationProposal(self.context()?), epoch)?
                }
                Action::ReviewContinuedReentry => {
                    let request = self
                        .queued_continuation
                        .as_ref()
                        .ok_or(Error::RecoveryRequired)?
                        .request
                        .clone();
                    self.start(
                        Work::PrepareContinuedReentry(self.context()?, request),
                        epoch,
                    )?;
                }
                Action::RetryContinuedAdmission => {
                    let approved = self.continued_admission_retry.take().ok_or(Error::Locked)?;
                    self.start(Work::RetryContinuedAdmission(approved), epoch)?;
                }
                Action::RetryActivate => {
                    let c = self.context()?;
                    let a = self.activation_retry.take().ok_or(Error::Locked)?;
                    self.start(Work::RetryActivate(c, a), epoch)?
                }
            }
            Ok(())
        })();
        if result.is_err() {
            self.message = "Exact step was rejected. No substitute approval, deadline, operation or account was created.";
        }
        Some(self.message)
    }
}
impl Drop for BornManualRosterUiV2 {
    fn drop(&mut self) {
        self.clear();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_lock_cancels_late_read_completion_adoption() {
        let mut ui = BornManualRosterUiV2::default();
        // This flag can be set only for an already executing real read commit.
        // No source, native entry, key, socket or provider is fabricated here.
        ui.accept_blurred_read_completion = true;
        ui.clear();
        assert!(!ui.accept_blurred_read_completion);
        assert!(ui.dormant_common_context.is_none());
        ui.poll_lifecycle(false, 2);
        assert!(!ui.accept_blurred_read_completion);
        assert!(ui.owner.is_none());
        assert!(ui.inventory_source.is_none());
    }
    #[test]
    fn repeat_blur_cannot_mint_dormant_receipt_or_native_owner() {
        let mut ui = BornManualRosterUiV2::default();
        ui.blur();
        ui.blur();
        ui.poll_lifecycle(true, 7);
        assert!(ui.owner.is_none());
        assert!(ui.inventory_source.is_none());
        assert!(ui.dormant_common_context.is_none());
        assert!(!ui.accept_blurred_read_completion);
    }
    #[test]
    fn actual_ui_blur_clears_preacquire_controller_without_minting_native_authority() {
        let mut ui = BornManualRosterUiV2::default();
        ui.bootstrap
            .opened(Some("unchanged-original-ref".into()))
            .unwrap();
        ui.bootstrap.queue().unwrap();
        ui.bootstrap.reviewed().unwrap();
        assert!(ui.bootstrap.can_acquire());
        ui.poll_lifecycle(false, 7);
        assert!(!ui.bootstrap.can_acquire());
        assert!(ui.reentry.is_none() && ui.queued.is_none());
        assert!(ui.owner(7).is_err());
        assert!(ui.approve(true, 7).is_err());
        ui.bootstrap
            .opened(Some("unchanged-original-ref".into()))
            .unwrap();
        assert!(!ui.bootstrap.can_acquire());
        assert!(ui.bootstrap.begin_acquire().is_err());
        assert!(ui.job.is_none());
    }
    #[test]
    fn actual_ui_blur_revokes_continuation_controller_without_approval_factory() {
        let mut ui = BornManualRosterUiV2::default();
        ui.continuation_controller
            .opened("unchanged-original".into())
            .unwrap();
        ui.continuation_controller
            .queue("exact-v2-request".into())
            .unwrap();
        ui.continuation_controller.reviewed().unwrap();
        assert!(ui.continuation_controller.can_acquire());
        ui.poll_lifecycle(false, 11);
        assert!(!ui.continuation_controller.can_acquire());
        assert!(ui.continued_reentry.is_none() && ui.queued_continuation.is_none());
        assert!(ui.owner(11).is_err());
        assert!(ui.approve(true, 11).is_err());
        ui.continuation_controller
            .opened("unchanged-original".into())
            .unwrap();
        assert!(ui.continuation_controller.begin_acquire().is_err());
    }
    #[test]
    fn empty_workspace_cannot_approve_or_publish() {
        let mut ui = BornManualRosterUiV2::default();
        assert!(ui.approve(true, 1).is_err());
        assert!(ui.context().is_err());
        assert!(!ui.is_active());
    }
    #[test]
    fn host_intent_cannot_supply_approval_or_signer_fields() {
        assert!(serde_json::from_str::<HostIntent>(r#"{"version":1,"approved":true}"#).is_err());
    }
}

fn queued_event_ready(has_job: bool, has_review: bool, has_owner: bool) -> bool {
    !has_job && !has_review && has_owner
}
#[cfg(test)]
mod completion_order_tests {
    use super::queued_event_ready;
    #[test]
    fn queued_pairing_cannot_overtake_worker_result_installation() {
        // Sending Finished is not permission to bypass the still-running job.
        assert!(!queued_event_ready(true, false, true));
        // Worker error clears the owner before the event queue can be read.
        assert!(!queued_event_ready(false, false, false));
        // Another pending native review remains a separate admission boundary.
        assert!(!queued_event_ready(false, true, true));
        // Only after successful result installation can queued data be reviewed.
        assert!(queued_event_ready(false, false, true));
    }
}
