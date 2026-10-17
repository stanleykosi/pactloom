//! Finite same-worker continuation, borrowing BOTH actual named controllers and
//! their ONE retained verifier. Input DTOs remain untrusted protocol material.
//! No owner is copied, deserialized or reconstructed from an expected digest.
use super::*;
use wholepact_signer::native_ui::synthetic_born_joined_qualification::{
    OriginalNamedPaymentArtifactsV1, OriginalNamedReturnReferencesV1, OriginalNamedSetupMetadataV1,
};
use wholepact_signer_origin::named_verifier_policy::NamedVerifierPolicyScopeV1;
use zeroize::Zeroizing;

pub(in super::super) enum Command {
    ExportEnrollment {
        index: usize,
        source_identity: String,
        source_policy: String,
    },
    InstalledMetadata {
        index: usize,
    },
    ArmVerifier {
        selected_index: usize,
        scopes: Box<[NamedVerifierPolicyScopeV1; 2]>,
        original_deadline: Instant,
    },
    StartVerifier {
        request: Zeroizing<Vec<u8>>,
    },
    PollVerifier,
    ExportAssertion {
        index: usize,
        row: String,
    },
    RetainPayment {
        index: usize,
        artifacts: Box<OriginalNamedPaymentArtifactsV1>,
    },
    SubmitPayment {
        index: usize,
    },
    SignReturn {
        index: usize,
    },
    BeginHostServing {
        index: usize,
    },
}
impl Command {
    pub(super) fn boundary(&self) -> B {
        match self {
            Self::ExportEnrollment { .. } => B::SignerNamedEnrollmentExport,
            Self::InstalledMetadata { .. } => B::SignerNamedInstalledMetadata,
            Self::ArmVerifier { .. } => B::SignerNamedVerifierArm,
            Self::StartVerifier { .. } => B::SignerNamedVerifierStart,
            Self::PollVerifier => B::SignerNamedVerifierPoll,
            Self::ExportAssertion { .. } => B::SignerNamedAssertionExport,
            Self::RetainPayment { .. } => B::SignerNamedOriginalImport,
            Self::SubmitPayment { .. } => B::SignerNamedOriginalSubmit,
            Self::SignReturn { .. } => B::SignerNamedOriginalSign,
            Self::BeginHostServing { .. } => B::SignerNamedHostServing,
        }
    }
}
pub(in super::super) enum Reply {
    Enrollment {
        index: usize,
        path: PathBuf,
        enrollment: Box<wholepact_authority::born_offline_enrollment_v1::BornOfflineEnrollmentV1>,
    },
    Metadata {
        index: usize,
        metadata: Box<OriginalNamedSetupMetadataV1>,
    },
    VerifierEndpoints([PathBuf; 2]),
    AssertionProgress(Option<String>),
    AssertionCiphertext {
        index: usize,
        bytes: Zeroizing<Vec<u8>>,
    },
    OriginalRetained {
        index: usize,
        authorization: String,
        intent: PathBuf,
    },
    OriginalReturn {
        index: usize,
        path: PathBuf,
        references: OriginalNamedReturnReferencesV1,
    },
    Done {
        index: usize,
    },
}
struct RequestFlow {
    selected_index: usize,
    deadline: Instant,
    started: bool,
    completed_row: Option<String>,
    disclosures_complete: [bool; 2],
}
#[derive(Default)]
pub(super) struct Progress {
    request: Option<RequestFlow>,
    exports: u8,
    exported_indices: [bool; 3],
    returned: [bool; 3],
    serve_host: [bool; 3],
}

fn named(states: &[Option<State>; 3], index: usize) -> Result<&EphemeralNamedPaymentV1> {
    if !(1..=2).contains(&index) {
        return Err("named participant index");
    }
    match states[index].as_ref() {
        Some(State::NamedProfile { _original }) => Ok(_original.as_ref()),
        _ => Err("actual named profile predecessor unavailable"),
    }
}
fn named_mut(
    states: &mut [Option<State>; 3],
    index: usize,
) -> Result<&mut EphemeralNamedPaymentV1> {
    if !(1..=2).contains(&index) {
        return Err("named participant index");
    }
    match states[index].as_mut() {
        Some(State::NamedProfile { _original }) => Ok(_original.as_mut()),
        _ => Err("actual named profile predecessor unavailable"),
    }
}
fn current_request(progress: &Progress) -> Result<&RequestFlow> {
    progress
        .request
        .as_ref()
        .filter(|p| Instant::now() < p.deadline)
        .ok_or("original verifier request expired or absent")
}

pub(super) fn execute(
    command: Command,
    states: &mut [Option<State>; 3],
    verifier: &mut Option<Box<EphemeralNamedVerifierV1>>,
    progress: &mut Progress,
    cancelled: &AtomicBool,
) -> Result<Reply> {
    if cancelled.load(Ordering::Acquire) {
        return Err("named worker cancelled");
    }
    match command {
        Command::ExportEnrollment {
            index,
            source_identity,
            source_policy,
        } => {
            let (path, enrollment) = named_mut(states, index)?
                .export_original_owner_enrollment(&source_identity, &source_policy)
                .map_err(|e| signer_error(e, "actual original owner enrollment export"))?;
            Ok(Reply::Enrollment {
                index,
                path,
                enrollment: Box::new(enrollment),
            })
        }
        Command::InstalledMetadata { index } => {
            let metadata = named(states, index)?
                .installed_original_setup_metadata()
                .map_err(|e| signer_error(e, "actual installed original metadata"))?;
            Ok(Reply::Metadata {
                index,
                metadata: Box::new(metadata),
            })
        }
        Command::ArmVerifier {
            selected_index,
            scopes,
            original_deadline,
        } => {
            if progress.request.is_some()
                || !(1..=2).contains(&selected_index)
                || progress.exported_indices[selected_index]
                || progress.exports >= 2
                || Instant::now() >= original_deadline
            {
                return Err("verifier original phase unavailable");
            }
            // This merely tightens the caller's ORIGINAL fixed request bound.
            // Exact scope times and actual original profile are independently
            // validated by each unchanged native lane and verifier parser.
            let now = Instant::now();
            let mut deadline = original_deadline.min(now + Duration::from_secs(120));
            for index in 1..=2 {
                deadline = deadline.min(
                    named(states, index)?
                        .deadline()
                        .map_err(|e| signer_error(e, "actual named deadline"))?,
                );
            }
            progress.request = Some(RequestFlow {
                selected_index,
                deadline,
                started: false,
                completed_row: None,
                disclosures_complete: [false; 2],
            });
            let [first, second] = *scopes;
            let a = named_mut(states, 1)?
                .arm_original_verifier_scope(first)
                .map_err(|e| signer_error(e, "actual first verifier scope review"))?;
            current_request(progress)?;
            let b = named_mut(states, 2)?
                .arm_original_verifier_scope(second)
                .map_err(|e| signer_error(e, "actual second verifier scope review"))?;
            current_request(progress)?;
            Ok(Reply::VerifierEndpoints([a, b]))
        }
        Command::StartVerifier { request } => {
            if current_request(progress)?.started || request.len() > 2 * 1024 * 1024 {
                return Err("verifier original request cannot restart");
            }
            // Restrict the two finite packages to distinct actual recipients.
            // The full actual verifier parser still independently validates the
            // complete request, exact scopes, pins, proof and economics below.
            #[derive(serde::Deserialize)]
            struct SelectedTerms {
                terms: wholepact_authority::offline::OfflineAuthorizationTerms,
            }
            let selected: SelectedTerms = serde_json::from_slice(&request)
                .map_err(|_| "verifier selected terms malformed")?;
            let index = current_request(progress)?.selected_index;
            let actual_account = named(states, index)?
                .pairing_scope()
                .map_err(|e| signer_error(e, "actual verifier selected account"))?
                .account_id;
            if selected.terms.account_id != actual_account {
                return Err("verifier selected recipient differs from actual owner");
            }
            // Set before potentially effectful work; errors stop the worker and
            // cannot become another original or uncertain signing retry.
            progress
                .request
                .as_mut()
                .ok_or("verifier original missing")?
                .started = true;
            let owners = [named(states, 1)?, named(states, 2)?];
            verifier
                .as_deref_mut()
                .ok_or("actual shared verifier missing")?
                .start_original_assertion(&request, owners)
                .map_err(|e| signer_error(e, "actual original verifier request"))?;
            current_request(progress)?;
            Ok(Reply::AssertionProgress(None))
        }
        Command::PollVerifier => {
            if !current_request(progress)?.started {
                return Err("verifier original not started");
            }
            // One nonblocking tick of EACH real contributor before the verifier
            // tick. A held FVK worker is never synchronously drained here.
            for index in 1..=2 {
                if !current_request(progress)?.disclosures_complete[index - 1] {
                    let done = named_mut(states, index)?
                        .poll_original_verifier_disclosure()
                        .map_err(|e| signer_error(e, "actual verifier disclosure poll"))?;
                    progress
                        .request
                        .as_mut()
                        .ok_or("verifier original missing")?
                        .disclosures_complete[index - 1] = done;
                }
            }
            if current_request(progress)?.completed_row.is_none() {
                let row = verifier
                    .as_deref_mut()
                    .ok_or("actual shared verifier missing")?
                    .poll_original_assertion()
                    .map_err(|e| signer_error(e, "actual verifier assertion poll"))?;
                progress
                    .request
                    .as_mut()
                    .ok_or("verifier original missing")?
                    .completed_row = row;
            }
            let flow = current_request(progress)?;
            Ok(Reply::AssertionProgress(
                if flow.disclosures_complete == [true; 2] {
                    flow.completed_row.clone()
                } else {
                    None
                },
            ))
        }
        Command::ExportAssertion { index, row } => {
            let flow = current_request(progress)?;
            if flow.selected_index != index
                || flow.completed_row.as_deref() != Some(row.as_str())
                || flow.disclosures_complete != [true; 2]
            {
                return Err("verifier actual completion mismatch");
            }
            let bytes = verifier
                .as_deref_mut()
                .ok_or("actual shared verifier missing")?
                .export_original_assertion(&row, named(states, index)?)
                .map_err(|e| signer_error(e, "actual original assertion export"))?;
            current_request(progress)?;
            progress.exports = progress
                .exports
                .checked_add(1)
                .ok_or("verifier export count")?;
            progress.exported_indices[index] = true;
            progress.request = None;
            Ok(Reply::AssertionCiphertext {
                index,
                bytes: Zeroizing::new(bytes),
            })
        }
        Command::RetainPayment { index, artifacts } => {
            let (authorization, intent) = named_mut(states, index)?
                .retain_original_payment(*artifacts)
                .map_err(|e| signer_error(e, "actual original payment import"))?;
            Ok(Reply::OriginalRetained {
                index,
                authorization,
                intent,
            })
        }
        Command::SubmitPayment { index } => {
            named_mut(states, index)?
                .submit_original_payment()
                .map_err(|e| signer_error(e, "actual original intent submit"))?;
            Ok(Reply::Done { index })
        }
        Command::SignReturn { index } => {
            if progress.returned.get(index) != Some(&false) {
                return Err("actual original return cannot repeat");
            }
            let path = named_mut(states, index)?
                .sign_and_export_original_return()
                .map_err(|e| signer_error(e, "actual original final signing and return"))?;
            let references = named(states, index)?
                .original_return_references()
                .map_err(|e| signer_error(e, "actual completed return references"))?;
            progress.returned[index] = true;
            Ok(Reply::OriginalReturn {
                index,
                path,
                references,
            })
        }
        Command::BeginHostServing { index } => {
            if progress.returned.get(index) != Some(&true)
                || progress.serve_host.get(index) != Some(&false)
            {
                return Err("actual returned original required for Host serving");
            }
            named_mut(states, index)?
                .poll_original_host_history_or_dispatch()
                .map_err(|e| signer_error(e, "actual returned original Host review"))?;
            progress.serve_host[index] = true;
            Ok(Reply::Done { index })
        }
    }
}

/// Runs only for two finite originals AFTER their actual final return, while
/// receiving ordinary authenticated Host IPC. No arbitrary event is injected.
pub(super) fn poll_idle(
    states: &mut [Option<State>; 3],
    progress: &Progress,
    cancelled: &AtomicBool,
) -> Result<()> {
    if cancelled.load(Ordering::Acquire) {
        return Err("named worker cancelled");
    }
    for index in 1..=2 {
        if progress.serve_host[index] {
            named_mut(states, index)?
                .poll_original_host_history_or_dispatch()
                .map_err(|e| signer_error(e, "actual returned original Host poll"))?;
        }
    }
    Ok(())
}
