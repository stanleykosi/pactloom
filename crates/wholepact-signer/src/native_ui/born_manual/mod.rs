//! A separate bounded native owner for born manual enrollment. It never calls
//! ordinary runtime activation. All keys, I/O and durable writes stay on workers.
mod admission;
mod continuation_admission;
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
    NativeDecision,
    authority::{ExactNativeReview, PendingAccountNativeAuthority},
    runtime::{AuthenticatedPairing, PendingBirthEntry},
    state::inert_text,
    witness_workspace::{
        ApprovedWriterActivation, ApprovedWriterSession, NativeWitnessWorkspace,
        PreparedWriterActivation, PreparedWriterSession,
    },
};
use crate::account::birth::enrollment::attempts::{
    self, ApprovedContinuedReentry, PreparedContinuationProposal, PreparedContinuedReentry,
    RetainedContinuation,
};
use crate::account::birth::enrollment::inventory::candidate::PreparedCandidateSelection;
use crate::account::birth::enrollment::inventory::{
    BornInventorySource, PreparedPreliminaryInventory,
};
use crate::{
    Error, Result,
    account::{
        AccountVault,
        birth::enrollment::{
            ApprovedBornManualReentry, BornManualEnrolledSigner, PreparedBornManualEnrollment,
            PreparedBornManualPublication, PreparedBornManualReentry,
        },
    },
    ipc::{AuthenticatedPeer, IpcRevocation, LocalEvent, LocalIpc, PendingPairing},
};
use eframe::egui;
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex, mpsc},
    thread::JoinHandle,
    time::{Duration, Instant},
};
use wholepact_authority::{
    WriterSessionReceipt, manual_enrollment_signature::ManualEnrollmentExtensionOwnerSignature,
};
use wholepact_signer_origin::manual::HostManualEnrollmentIntent as HostIntent;
use wholepact_signer_origin::manual_continuation_v2::HostManualEnrollmentContinuationRequestV2;
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
enum Step {
    CandidateSelection(Box<PreparedCandidateSelection>),
    Inventory(Box<PreparedPreliminaryInventory>),
    PolicyExport(Box<policy_export_v2::PreparedOriginalPolicyExportV2>),

    ContinuationProposal(Box<PreparedContinuationProposal>),
    ContinuationSign(Box<continuation_signing::PreparedContinuationOwnerSignature>),
    ContinuationExport(Box<continuation_export::PreparedContinuationExport>),
    ContinuedReentry(Box<PreparedContinuedReentry>),
    ContinuedAdmit(Box<continuation_witness::PreparedContinuedAdmission>),
    ContinuedServe(Box<continuation_admission::PreparedNativeManualContinuation>),
    Pair(Box<PendingPairing>),
    Retain(Box<PreparedBornManualEnrollment>),
    Reentry(Box<PreparedBornManualReentry>),
    Sign(Box<signing::PreparedManualOwnerSignature>),
    Export(Box<export::PreparedManualExport>),
    Witness(Box<witness::PreparedManualWitnessSetup>),
    Acquire(Box<PreparedWriterSession>),
    Activate(Box<PreparedWriterActivation>),
    Admit(Box<witness::PreparedManualAdmission>),
    Publish(Box<PreparedBornManualPublication>),
    Serve(Box<admission::PreparedNativeManualEnrollment>),
}
struct Prepared {
    step: Step,
    digest: String,
    display: String,
}
impl Prepared {
    fn new(step: Step) -> Result<Self> {
        let (digest, display) = match &step {
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
    account: Arc<AccountVault>,
    ipc: Arc<Mutex<LocalIpc>>,
    _temporary: Arc<tempfile::TempDir>,
    peer: Option<AuthenticatedPeer>,
    writer: Option<Arc<NativeWitnessWorkspace>>,
    owner_client: Option<Arc<NativeWitnessWorkspace>>,
    reentry: Option<Arc<ApprovedBornManualReentry>>,
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
struct CandidateSelectionWork {
    context: Context,
    source: BornInventorySource,
    peer: AuthenticatedPeer,
    stream: std::os::unix::net::UnixStream,
    request: Box<wholepact_core::manual_candidate_selection::ManualCandidateSelectionRequest>,
}
struct InventoryWork {
    context: Context,
    source: BornInventorySource,
    peer: AuthenticatedPeer,
    stream: std::os::unix::net::UnixStream,
    request: Box<wholepact_core::manual_inventory::ManualPreliminaryInventoryRequest>,
}
enum Work {
    PrepareCandidateSelection(Box<CandidateSelectionWork>),
    PrepareInventory(Box<InventoryWork>),
    PreparePolicyExport(Context, PathBuf),

    PrepareContinuationProposal(Context),
    PrepareContinuationSign(Context, PathBuf, PathBuf),
    PrepareContinuationExport(Context, PathBuf),
    PrepareContinuedReentry(Context, Box<HostManualEnrollmentContinuationRequestV2>),
    PrepareContinuedServe(
        Arc<BornManualEnrolledSigner>,
        AuthenticatedPeer,
        std::os::unix::net::UnixStream,
        Box<HostManualEnrollmentContinuationRequestV2>,
    ),
    RetryContinuedAdmission(Box<continuation_witness::ApprovedContinuedAdmission>),
    Open(PathBuf, Zeroizing<String>),
    PrepareServe(
        Arc<BornManualEnrolledSigner>,
        AuthenticatedPeer,
        std::os::unix::net::UnixStream,
        Box<wholepact_signer_origin::manual::HostManualEnrollmentRequest>,
    ),
    PrepareIntent(Context, Box<HostIntent>),
    PrepareReentry(
        Context,
        Box<wholepact_signer_origin::manual::HostManualEnrollmentRequest>,
    ),
    PrepareSignature(Context, PathBuf, PathBuf),
    PrepareExport(
        Context,
        Box<ManualEnrollmentExtensionOwnerSignature>,
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
    CandidateSelectionServed(BornInventorySource),
    InventoryServed(BornInventorySource),
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
    Reentered(Arc<ApprovedBornManualReentry>),
    Signed(Box<ManualEnrollmentExtensionOwnerSignature>),
    Exported,
    Witness(Arc<NativeWitnessWorkspace>, Arc<NativeWitnessWorkspace>),
    Acquired(
        Box<ApprovedWriterSession>,
        Result<Box<WriterSessionReceipt>>,
    ),
    Activated(Box<ApprovedWriterActivation>, Result<()>),
    Admitted(Box<witness::ApprovedManualAdmission>, Result<Box<Prepared>>),
    Enrolled(Arc<BornManualEnrolledSigner>),
    Served,
}
fn run(work: Work, owner: &PendingAccountNativeAuthority) -> Result<Output> {
    owner.check_current()?;
    owner.native().binding().bounded_deadline()?;
    let result = match work {
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
                Box::new(PreparedCandidateSelection::prepare(
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
                PreparedPreliminaryInventory::prepare(
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
                .retained_born_manual_enrollment(owner)?
                .ok_or(Error::RecoveryRequired)?;
            Output::Prepared(Box::new(Prepared::new(Step::PolicyExport(Box::new(
                policy_export_v2::PreparedOriginalPolicyExportV2::prepare(retained, &path, owner)?,
            )))?))
        }
        Work::PrepareContinuationProposal(c) => {
            if !c.attempted {
                return Err(Error::RecoveryRequired);
            }
            let retained = c
                .account
                .retained_born_manual_enrollment(owner)?
                .ok_or(Error::RecoveryRequired)?;
            attempts::require_attempted_source(&retained, owner)?;
            let history = c
                .writer()?
                .client()
                .reconcile_history_checked(|| {
                    owner
                        .check_current()
                        .map_err(|_| wholepact_authority::AuthorityError::Permission)
                })
                .map_err(|_| Error::Uncertain)?;
            Output::Prepared(Box::new(Prepared::new(Step::ContinuationProposal(
                Box::new(PreparedContinuationProposal::prepare(
                    retained,
                    &history,
                    &c.pairing()?,
                    owner,
                )?),
            ))?))
        }
        Work::PrepareContinuationSign(c, cert, key) => {
            Output::Prepared(Box::new(Prepared::new(Step::ContinuationSign(Box::new(
                continuation_signing::PreparedContinuationOwnerSignature::prepare(
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
                .retained_born_manual_enrollment(owner)?
                .ok_or(Error::RecoveryRequired)?;
            let selected = attempts::select(retained, &request.continuation_digest, owner)?;
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
                continuation_admission::PreparedNativeManualContinuation::prepare(
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
                admission::PreparedNativeManualEnrollment::prepare(
                    enrolled, peer, stream, *request, owner,
                )?,
            )))?))
        }
        Work::PrepareReentry(c, request) => {
            let retained = c
                .account
                .retained_born_manual_enrollment(owner)?
                .ok_or(Error::RecoveryRequired)?;
            if c.retained_reference.as_deref() != Some(retained.record().reference()?.as_str()) {
                return Err(Error::ReviewMismatch);
            }
            Output::Prepared(Box::new(Prepared::new(Step::Reentry(Box::new(
                PreparedBornManualReentry::prepare(retained, &request, &c.pairing()?, owner)?,
            )))?))
        }
        Work::Open(path, password) => {
            let account = Arc::new(AccountVault::unlock_born_for_manual_enrollment(
                &path,
                password.as_bytes(),
                owner,
            )?);
            let retained = account.retained_born_manual_enrollment(owner)?;
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
            let temporary = Arc::new(tempfile::tempdir()?);
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
                PreparedBornManualEnrollment::prepare(
                    c.account.clone(),
                    input.host,
                    input.scope,
                    input.operation_id,
                    &c.pairing()?,
                    owner,
                )?,
            )))?))
        }
        Work::PrepareSignature(c, cert, key) => {
            let retained = c
                .account
                .retained_born_manual_enrollment(owner)?
                .ok_or(Error::RecoveryRequired)?;
            Output::Prepared(Box::new(Prepared::new(Step::Sign(Box::new(
                signing::PreparedManualOwnerSignature::prepare(retained, owner, &cert, &key)?,
            )))?))
        }
        Work::PrepareExport(c, envelope, path) => {
            let retained = c
                .account
                .retained_born_manual_enrollment(owner)?
                .ok_or(Error::RecoveryRequired)?;
            Output::Prepared(Box::new(Prepared::new(Step::Export(Box::new(
                export::PreparedManualExport::prepare(retained, *envelope, &path, owner)?,
            )))?))
        }
        Work::PrepareWitness(c, json) => {
            let retained = c
                .account
                .retained_born_manual_enrollment(owner)?
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
                .retained_born_manual_enrollment(owner)?
                .ok_or(Error::RecoveryRequired)?;
            Output::Prepared(Box::new(Prepared::new(Step::Acquire(Box::new(
                if c.attempted {
                    PreparedWriterSession::prepare_born_continued(
                        c.writer()?,
                        &retained.record().extension()?,
                        &c.continued_reentry
                            .as_ref()
                            .ok_or(Error::RecoveryRequired)?
                            .proposal()
                            .continuation,
                    )?
                } else {
                    PreparedWriterSession::prepare_born(
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
                    .retained_born_manual_enrollment(owner)?
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
                            &c.pairing()?,
                            owner,
                        )?,
                    )),
                )?)));
            }
            let retained = c
                .account
                .retained_born_manual_enrollment(owner)?
                .ok_or(Error::RecoveryRequired)?;
            Output::Prepared(Box::new(Prepared::new(Step::Admit(Box::new(
                witness::PreparedManualAdmission::prepare(
                    retained,
                    c.writer.clone().ok_or(Error::Locked)?,
                    &c.pairing()?,
                    owner,
                )?,
            )))?))
        }
        Work::Commit(c, step, decision) => match step {
            Step::CandidateSelection(p) => {
                Output::CandidateSelectionServed(p.approve_and_serve(decision, owner)?)
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
    owner.check_current()?;
    Ok(result)
}
struct Job {
    thread: JoinHandle<()>,
    receive: mpsc::Receiver<Result<Output>>,
}
impl Job {
    fn start(work: Work, owner: Arc<PendingAccountNativeAuthority>) -> Result<Self> {
        let (send, receive) = mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("wholepact-born-manual-owner".into())
            .spawn(move || {
                let _ = send.send(run(work, &owner));
            })?;
        Ok(Self { thread, receive })
    }
    fn finish(self) -> Result<Output> {
        self.thread.join().map_err(|_| Error::Uncertain)?;
        self.receive.try_recv().map_err(|_| Error::Uncertain)?
    }
}
struct QueuedContinuation {
    peer: AuthenticatedPeer,
    stream: std::os::unix::net::UnixStream,
    request: Box<HostManualEnrollmentContinuationRequestV2>,
}
struct QueuedEnrollment {
    peer: AuthenticatedPeer,
    stream: std::os::unix::net::UnixStream,
    request: Box<wholepact_signer_origin::manual::HostManualEnrollmentRequest>,
}
#[derive(Default)]
pub(super) struct BornManualUi {
    owner: Option<Arc<PendingAccountNativeAuthority>>,
    bootstrap: controller::BootstrapController,
    continuation_controller: continuation_controller::ContinuationController,
    continuation: Option<Arc<RetainedContinuation>>,
    continued_reentry: Option<Arc<ApprovedContinuedReentry>>,
    queued_continuation: Option<QueuedContinuation>,
    continued_admission_retry: Option<Box<continuation_witness::ApprovedContinuedAdmission>>,
    queued: Option<QueuedEnrollment>,
    reentry: Option<Arc<ApprovedBornManualReentry>>,
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
    enrolled: Option<Arc<BornManualEnrolledSigner>>,
    inventory_source: Option<BornInventorySource>,
    signed: Option<Box<ManualEnrollmentExtensionOwnerSignature>>,

    certificate: Zeroizing<String>,
    key: Zeroizing<String>,
    destination: Zeroizing<String>,
    witness_setup: Zeroizing<String>,
    confirmation: Zeroizing<String>,
    message: &'static str,
}
impl BornManualUi {
    pub(super) fn is_active(&self) -> bool {
        self.owner.is_some() || self.job.is_some() || !self.cleanup.is_empty()
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
    fn owner(&self, epoch: u64) -> Result<Arc<PendingAccountNativeAuthority>> {
        let owner = self.owner.as_ref().ok_or(Error::Locked)?;
        owner.check_current()?;
        if owner.focus_epoch() != epoch {
            return Err(Error::ReviewMismatch);
        }
        Ok(owner.clone())
    }
    fn context(&self) -> Result<Context> {
        let o = self.opened.as_ref().ok_or(Error::Locked)?;
        Ok(Context {
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
        if let Some(owner) = self.owner.take() {
            owner.revoke_pending_now();
        }
        self.bootstrap.clear();
        self.continuation_controller.clear();
        self.queued_continuation = None;
        self.queued = None;
        if let Some(open) = self.opened.as_ref() {
            open.revoke();
        }
        // Immediately revoke above; move potentially blocking connection/database
        // destructors off the GUI thread. At most the opened context and one
        // in-flight worker result can await cleanup; a new entry stays denied.
        if self.opened.is_some()
            || self.enrolled.is_some()
            || self.review.is_some()
            || self.writer.is_some()
            || self.owner_client.is_some()
            || self.reentry.is_some()
            || self.continuation.is_some()
            || self.continued_reentry.is_some()
            || self.continued_admission_retry.is_some()
            || self.inventory_source.is_some()
        {
            let retired = (
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
            );
            self.cleanup.push(std::thread::spawn(move || drop(retired)));
        }
        self.peer = None;
        self.receipt = None;
        self.activated = false;
        self.signed = None;

        self.certificate.zeroize();
        self.key.zeroize();
        self.destination.zeroize();
        self.witness_setup.zeroize();
        self.confirmation.zeroize();
        self.message = "Manual enrollment closed. An already admitted durable operation may have finished. Preserve intent, journal and witness history; do not regenerate or replace the original operation.";
    }
    pub(super) fn poll_lifecycle(&mut self, focused: bool, epoch: u64) {
        if !focused {
            self.clear();
        }
        if self.owner.is_some()
            && (!focused
                || self.owner(epoch).is_err()
                || self
                    .peer
                    .as_ref()
                    .is_some_and(|p| p.check_current().is_err())
                || self
                    .queued
                    .as_ref()
                    .is_some_and(|q| admission::connected(&q.stream, &q.peer).is_err())
                || self
                    .queued_continuation
                    .as_ref()
                    .is_some_and(|q| admission::connected(&q.stream, &q.peer).is_err())
                || self.review.as_ref().is_some_and(|r| r.exact.expired()))
        {
            self.clear();
        }
        self.cleanup.retain(|thread| !thread.is_finished());
        if self.job.as_ref().is_some_and(|j| j.thread.is_finished()) {
            let result = self.job.take().unwrap().finish();
            if self.owner(epoch).is_err() {
                if let Ok(output) = result {
                    self.cleanup.push(std::thread::spawn(move || drop(output)));
                }
                return;
            }
            let result=result.and_then(|out|{match out{
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
                Output::Enrolled(e)=>{if self.opened.as_ref().is_some_and(|o|o.attempted) {self.continuation_controller.published()?;}else{self.bootstrap.published()?;}self.enrolled=Some(e);self.message="Exact first signer journal and immutable born manual record preserved. Financial/key-release/action gates remain denied pending their coherent per-action issuer.";},
            }Ok(())});
            if result.is_err() {
                self.clear();
                self.message = "Enrollment step failed or became uncertain. Preserve all source and output state. No replacement or synthetic approval was made.";
            }
        }
        if self.job.is_some() || self.review.is_some() || self.owner.is_none() {
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
            Some(LocalEvent::BornCandidateSelectionV1 {
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
            Some(LocalEvent::BornPreliminaryInventoryV1 {
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
            Some(LocalEvent::BornManualEnrollmentContinuationV2 {
                peer,
                stream,
                request,
            }) => {
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
            Some(LocalEvent::BornManualEnrollment {
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
                    let result = (|| -> Result<BornInventorySource> {
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
                            None => BornInventorySource::prepare_repair(enrolled, owner.as_ref())?,
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
                            "DISTINCT NON-SIGNING PURPOSE: manifest_digest commits the exact preliminary-viewing or candidate-selection scope. Pairing alone releases no viewing data and grants no selection, construction or signing permission; the specific operation requires a separate exact native review. The old publication grant is retired; original native/session deadlines are unchanged."
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
                request: crate::ipc::AppRequest::RequestBornManualEnrollmentIntent { ref request },
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
                    && request.scope.agreement_id == peer.scope.agreement_id
                    && request.scope.participant_id == peer.scope.participant_id;
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
    fn approve(&mut self, focused: bool, epoch: u64) -> Result<()> {
        let review = self.review.take().ok_or(Error::ReviewMismatch)?;
        if !review.displayed_to_end {
            return Err(Error::ReviewMismatch);
        }
        let decision = review
            .exact
            .consume_native_click(focused, epoch, &self.confirmation)?;
        self.confirmation.zeroize();
        self.start(Work::Commit(self.context()?, review.step, decision), epoch)
    }
    pub(super) fn ui(
        &mut self,
        ui: &mut egui::Ui,
        focused: bool,
        epoch: u64,
    ) -> Option<&'static str> {
        self.poll_lifecycle(focused, epoch);
        ui.heading("Original born account: manual enrollment");
        ui.label(self.message);
        ui.label("This bounded native entry does not renew after network, pairing or review. Expiry hides private data and invalidates further admission. Already admitted commits may drain.");
        if !focused {
            return Some(self.message);
        }
        if self.job.is_some() || !self.cleanup.is_empty() {
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
        enum Action {
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
                .id_salt("born-manual-review")
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
                        egui::Button::new("Approve exact manual-enrollment step"),
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
                .id_salt("born-manual-origin")
                .max_height(160.0)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new(inert_text(&open.display)).monospace())
                });
            ui.label("The actually paired process must send its bounded host-generation/manual-scope intent. Only request data crosses IPC; signer-derived terms require the native review and separate exact signed export. No caller-supplied approval, signer hash or placeholder is accepted.");
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
impl Drop for BornManualUi {
    fn drop(&mut self) {
        self.clear();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_ui_blur_clears_preacquire_controller_without_minting_native_authority() {
        let mut ui = BornManualUi::default();
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
        let mut ui = BornManualUi::default();
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
        let mut ui = BornManualUi::default();
        assert!(ui.approve(true, 1).is_err());
        assert!(ui.context().is_err());
        assert!(!ui.is_active());
    }
    #[test]
    fn host_intent_cannot_supply_approval_or_signer_fields() {
        assert!(serde_json::from_str::<HostIntent>(r#"{"version":1,"approved":true}"#).is_err());
    }
}
