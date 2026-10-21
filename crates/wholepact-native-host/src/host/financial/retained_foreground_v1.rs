//! Concrete original H staging and two retained V3 admission boundaries.
//! No binary caller, automatic workflow progression or successful close is
//! enabled here. Each Resume concerns only its exact original W; selected
//! metadata never substitutes for fresh history/preview/intake decisions.
use super::{
    durable_delivery_admission_v2::{
        begin_original_coordinated_admission_v1, RetainedOriginalCoordinatedAdmissionV1,
        RetainedCoordinatedOwnerWorkflowWaitV1,
    },
    durable_financial_commands_v1::{
        continuation_record, read_histories, read_selection,
        require_pair, require_result_selection, ContinuationSelectionV1, ResultSelectionV1,
        SessionCommandsV1,
    },
    owned_relay_monitor_v1::{HostRelayFailureV1, OwnedHostRelayMonitorV1},
    private_financial_v1::CompletedPrivateFinancialSummaryV1,
    Host,
};
use crate::{terminal::Terminal, Error, Result};
use std::{path::{Path, PathBuf}, sync::Arc};
use wholepact_financial_coordinator_origin::{
    HostFinancialForegroundV1, HostFinancialInterstageWaitV1, HostCompletedPairServiceV1,
    HostOriginV1, OriginalForkSignerVerifier, SignerContinueRoleV1,
};

pub(super) enum OriginalForegroundOpenFailureV1 {
    BeforeMonitor(Error),
    Joined(HostRelayFailureV1),
}

fn before_monitor_failure(error: Error) -> OriginalForegroundOpenFailureV1 {
    crate::terminal::fail_original_coordinator_restriction();
    OriginalForegroundOpenFailureV1::BeforeMonitor(error)
}

pub(super) struct OpenedOriginalFinancialHostV1 {
    // Declaration order is deliberate: synchronous FAILED + owned join before
    // dropping the one actual Host authority. No child reaper is detached.
    monitor: OwnedHostRelayMonitorV1,
    host: Host,
    workspace: PathBuf,
    commands: SessionCommandsV1,
}

pub(super) struct FirstOriginalAdmissionSetupV1 {
    foreground: HostFinancialForegroundV1,
    first: OriginalForkSignerVerifier,
    second: OriginalForkSignerVerifier,
}

pub(super) fn open_original_financial_foreground_v1(
    origin: HostOriginV1,
    profile: &Path,
    workspace: &Path,
) -> std::result::Result<
    (OpenedOriginalFinancialHostV1, FirstOriginalAdmissionSetupV1),
    OriginalForegroundOpenFailureV1,
> {
    open_original_financial_foreground_selected_v1(origin, Some((profile.to_owned(), workspace.to_owned())))
}

fn open_original_financial_foreground_selected_v1(
    mut origin: HostOriginV1,
    selected: Option<(PathBuf, PathBuf)>,
) -> std::result::Result<
    (OpenedOriginalFinancialHostV1, FirstOriginalAdmissionSetupV1),
    OriginalForegroundOpenFailureV1,
> {
    use OriginalForegroundOpenFailureV1::Joined;
    // Irreversible obligation precedes EVERY fallible custody extraction.
    Terminal::require_coordinated_restriction().map_err(before_monitor_failure)?;
    let (tty, restriction) = origin.take_host_terminal_custody()
        .map_err(|error| before_monitor_failure(Error::from(error)))?;
    let terminal = Terminal::open_coordinated(tty, restriction).map_err(before_monitor_failure)?;
    let foreground = origin.take_financial_foreground()
        .map_err(|error| before_monitor_failure(Error::from(error)))?;
    let [first, second] = origin.take_original_signer_verifiers()
        .map_err(|error| before_monitor_failure(Error::from(error)))?;
    let relay = origin.into_financial_workflow_relay()
        .map_err(|error| before_monitor_failure(Error::from(error)))?;
    let monitor = OwnedHostRelayMonitorV1::start(relay).map_err(before_monitor_failure)?;
    let (profile, workspace) = match selected.map(Ok).unwrap_or_else(|| {
        let profile = PathBuf::from(terminal.ask("Existing original Host profile directory (absolute): ")?.as_str());
        let workspace = PathBuf::from(terminal.ask("Existing original dispatcher workspace directory (absolute): ")?.as_str());
        if !profile.is_absolute() || !workspace.is_absolute() { return Err(Error::Invalid); }
        Ok((profile, workspace))
    }) {
        Ok(paths) => paths,
        Err(error) => return Err(Joined(monitor.abort_and_join(error))),
    };
    // The sole relay already progresses while the original foreground opens
    // its real encrypted Host and waits for actual human TTY responses.
    let host = match Host::open_workspace_dispatcher_registered_v4(
        terminal, &profile, &workspace, false,
    ) {
        Ok(host) => host,
        Err(error) => return Err(Joined(monitor.abort_and_join(error))),
    };
    let commands = read_selection::<SessionCommandsV1>(&host,
        "Exact immutable command keys JSON file {version:1,bind_key,intake_keys:[first,second],completion_key} (absolute): ")
        .and_then(|commands| { commands.check()?; Ok(commands) });
    let commands = match commands {
        Ok(commands) => commands,
        Err(error) => {
            let failure = monitor.abort_and_join(error);
            drop(host);
            return Err(Joined(failure));
        }
    };
    Ok((
        OpenedOriginalFinancialHostV1 {
            monitor, host, workspace: workspace.to_owned(), commands,
        },
        FirstOriginalAdmissionSetupV1 { foreground, first, second },
    ))
}

impl OpenedOriginalFinancialHostV1 {
    /// The actual foreground error remains distinct from owned relay cleanup.
    /// Call only after all borrowing admission/wait owners have been dropped.
    pub(super) fn abort_and_join(self, error: Error) -> HostRelayFailureV1 {
        let Self { monitor, host, workspace: _, commands: _ } = self;
        let result = monitor.abort_and_join(error);
        drop(host);
        result
    }
}

pub(super) struct FirstOriginalAdmissionAttemptV1<'host> {
    foreground: Option<HostFinancialForegroundV1>,
    admission: RetainedOriginalCoordinatedAdmissionV1<'host>,
    owner: &'host OpenedOriginalFinancialHostV1,
    second: OriginalForkSignerVerifier,
}
impl FirstOriginalAdmissionSetupV1 {
    pub(super) fn begin<'host>(
        self, owner: &'host OpenedOriginalFinancialHostV1,
    ) -> Result<FirstOriginalAdmissionAttemptV1<'host>> {
        owner.host.terminal.message("Select original reviewer 1 of 2 for its separate closed V3 admission.\n")?;
        let endpoint = wait_original_coordinated_pair_endpoint_v1(&self.foreground, SignerContinueRoleV1::Signer1)?;
        let admission = begin_original_coordinated_admission_v1(
            &owner.host, &owner.workspace, None, self.first, endpoint,
            || wait_original_coordinated_current_disclosure_v1(&self.foreground, SignerContinueRoleV1::Signer1),
        )?;
        Ok(FirstOriginalAdmissionAttemptV1 {
            foreground: Some(self.foreground), admission, owner, second: self.second,
        })
    }
}
impl<'host> FirstOriginalAdmissionAttemptV1<'host> {
    pub(super) fn verify(&mut self) -> Result<()> {
        // Keep the actual Pending/provider/Peer on every status/read failure.
        // The maintained verifier itself refuses every repeated verification.
        let result = self.admission.verify_admission();
        if result.is_err() {
            crate::terminal::fail_original_coordinator_restriction();
            drop(self.foreground.take());
        }
        result
    }
    pub(super) fn park_after_verified(mut self) -> Result<FirstParkedOriginalOwnerV1<'host>> {
        let foreground = self.foreground.take().ok_or(Error::Permission)?;
        let parked = self.admission.into_owner_workflow_wait(foreground)?;
        Ok(FirstParkedOriginalOwnerV1 { parked, owner: self.owner, second: self.second })
    }
}

pub(super) struct FirstParkedOriginalOwnerV1<'host> {
    parked: RetainedCoordinatedOwnerWorkflowWaitV1<'host>,
    owner: &'host OpenedOriginalFinancialHostV1,
    second: OriginalForkSignerVerifier,
}
impl<'host> FirstParkedOriginalOwnerV1<'host> {
    pub(super) fn wait_one_retirement(self) -> Result<Self> {
        Ok(Self { parked: self.parked.wait_for_initial_history_retirement(SignerContinueRoleV1::Signer1)?, ..self })
    }
    pub(super) fn leave_after_resume(self) -> Result<FirstResumedOriginalOwnerV1<'host>> {
        let (admission, foreground) = self.parked.leave_after_resume()?;
        Ok(FirstResumedOriginalOwnerV1 { foreground, admission, owner: self.owner, second: self.second })
    }
}

/// Only the actual resumed V3 owner. This does NOT mean that initial-Read W,
/// continuation W, signing or protected ReturnExact has completed.
pub(super) struct FirstResumedOriginalOwnerV1<'host> {
    foreground: HostFinancialForegroundV1,
    admission: RetainedOriginalCoordinatedAdmissionV1<'host>,
    owner: &'host OpenedOriginalFinancialHostV1,
    second: OriginalForkSignerVerifier,
}
struct SelectedRetainedOriginalOwnerV1<'host> {
    admission: RetainedOriginalCoordinatedAdmissionV1<'host>,
    continuation: ContinuationSelectionV1,
    result: ResultSelectionV1,
}
pub(super) struct FirstSelectedOriginalOwnerV1<'host> {
    foreground: HostFinancialForegroundV1,
    first: SelectedRetainedOriginalOwnerV1<'host>,
    owner: &'host OpenedOriginalFinancialHostV1,
    second: OriginalForkSignerVerifier,
}
impl<'host> FirstResumedOriginalOwnerV1<'host> {
    pub(super) fn select_original_handoffs(self) -> Result<FirstSelectedOriginalOwnerV1<'host>> {
        let host = &self.owner.host;
        host.terminal.message("In this same original Signer, review the fresh original financial continuation. Save its explicit continuation selector before Witness approval. Complete the exact Witness continuation and separate Signer decisions without changing native focus or original deadlines. The Host will not send an owner control request from this file.\n")?;
        let continuation: ContinuationSelectionV1 = read_selection(host,
            "Exact copied native continuation selector JSON file (absolute): ")?;
        require_coordinated_admitted_selection_v1(&continuation, self.admission.checked_admission_status()?)?;
        let foreground = wait_selected_continuation_retirement(
            self.foreground, &[&self.admission], SignerContinueRoleV1::Signer1,
        )?;
        host.terminal.message("After this owner's genuine SignExact finishes, save its native result selector while keeping that original Signer alive and focused for ReturnExact. These selected fields are metadata only; the Host still requires the original peer and a separately approved protected return.\n")?;
        let result: ResultSelectionV1 = read_selection(host,
            "Exact copied native AwaitingReturn result selector JSON file (absolute): ")?;
        require_result_selection(&result, continuation_record(&continuation)?)?;
        // Release this exact original Signing installation before reviewer 2
        // can open it. Selection metadata cannot stand in for the actual
        // drained/reaped Signing purpose and acknowledged same-H Resume.
        let foreground = wait_selected_signing_retirement(
            foreground, &[&self.admission], SignerContinueRoleV1::Signer1, &result,
        )?;
        Ok(FirstSelectedOriginalOwnerV1 {
            foreground,
            first: SelectedRetainedOriginalOwnerV1 { admission: self.admission, continuation, result },
            owner: self.owner, second: self.second,
        })
    }
}

pub(super) struct SecondOriginalAdmissionAttemptV1<'host> {
    foreground: Option<HostFinancialForegroundV1>,
    admission: RetainedOriginalCoordinatedAdmissionV1<'host>,
    first: SelectedRetainedOriginalOwnerV1<'host>,
    owner: &'host OpenedOriginalFinancialHostV1,
}
impl<'host> FirstSelectedOriginalOwnerV1<'host> {
    pub(super) fn begin_second(self) -> Result<SecondOriginalAdmissionAttemptV1<'host>> {
        self.owner.host.terminal.message("Select original reviewer 2 of 2 for its separate closed V3 admission.\n")?;
        let endpoint = wait_original_coordinated_pair_endpoint_v1(&self.foreground, SignerContinueRoleV1::Signer2)?;
        let admission = begin_original_coordinated_admission_v1(
            &self.owner.host, &self.owner.workspace, Some(&self.first.admission), self.second, endpoint,
            || wait_original_coordinated_current_disclosure_v1(&self.foreground, SignerContinueRoleV1::Signer2),
        )?;
        Ok(SecondOriginalAdmissionAttemptV1 {
            foreground: Some(self.foreground), admission, first: self.first, owner: self.owner,
        })
    }
}
impl<'host> SecondOriginalAdmissionAttemptV1<'host> {
    pub(super) fn verify(&mut self) -> Result<()> {
        let result = self.admission.verify_admission();
        if result.is_err() {
            crate::terminal::fail_original_coordinator_restriction();
            drop(self.foreground.take());
        }
        result
    }
    pub(super) fn park_after_verified(mut self) -> Result<SecondParkedOriginalOwnerV1<'host>> {
        let foreground = self.foreground.take().ok_or(Error::Permission)?;
        let parked = self.admission.into_owner_workflow_wait(foreground)?;
        Ok(SecondParkedOriginalOwnerV1 { parked, first: self.first, owner: self.owner })
    }
}
pub(super) struct SecondParkedOriginalOwnerV1<'host> {
    parked: RetainedCoordinatedOwnerWorkflowWaitV1<'host>,
    first: SelectedRetainedOriginalOwnerV1<'host>,
    owner: &'host OpenedOriginalFinancialHostV1,
}
impl SecondParkedOriginalOwnerV1<'_> {
    pub(super) fn wait_one_retirement(self) -> Result<Self> {
        Ok(Self { parked: self.parked.wait_for_initial_history_retirement(SignerContinueRoleV1::Signer2)?, ..self })
    }
}

impl<'host> SecondParkedOriginalOwnerV1<'host> {
    pub(super) fn leave_after_resume(self) -> Result<SecondResumedOriginalOwnerV1<'host>> {
        let (admission, foreground) = self.parked.leave_after_resume()?;
        Ok(SecondResumedOriginalOwnerV1 {
            foreground, admission, first: self.first, owner: self.owner,
        })
    }
}

/// This is only a genuine resumed interstage owner. Neither one Resume nor
/// this type attests initial-Read/Signing namespace disposal or readiness.
pub(super) struct SecondResumedOriginalOwnerV1<'host> {
    foreground: HostFinancialForegroundV1,
    admission: RetainedOriginalCoordinatedAdmissionV1<'host>,
    first: SelectedRetainedOriginalOwnerV1<'host>,
    owner: &'host OpenedOriginalFinancialHostV1,
}
pub(super) struct SelectedOriginalFinancialPairV1<'host> {
    foreground: HostFinancialForegroundV1,
    owners: [SelectedRetainedOriginalOwnerV1<'host>; 2],
    owner: &'host OpenedOriginalFinancialHostV1,
}
impl<'host> SecondResumedOriginalOwnerV1<'host> {
    pub(super) fn select_original_handoffs(self) -> Result<SelectedOriginalFinancialPairV1<'host>> {
        let host = &self.owner.host;
        host.terminal.message("In this same original Signer, review the fresh original financial continuation. Save its explicit continuation selector before Witness approval. Complete the exact Witness continuation and separate Signer decisions without changing native focus or original deadlines. The Host will not send an owner control request from this file.\n")?;
        let continuation: ContinuationSelectionV1 = read_selection(host,
            "Exact copied native continuation selector JSON file (absolute): ")?;
        require_coordinated_admitted_selection_v1(&continuation, self.admission.checked_admission_status()?)?;
        let foreground = wait_selected_continuation_retirement(
            self.foreground, &[&self.first.admission, &self.admission], SignerContinueRoleV1::Signer2,
        )?;
        host.terminal.message("After this owner's genuine SignExact finishes, save its native result selector while keeping that original Signer alive and focused for ReturnExact. These selected fields are metadata only; the Host still requires the original peer and a separately approved protected return.\n")?;
        let result: ResultSelectionV1 = read_selection(host,
            "Exact copied native AwaitingReturn result selector JSON file (absolute): ")?;
        require_result_selection(&result, continuation_record(&continuation)?)?;
        let foreground = wait_selected_signing_retirement(
            foreground, &[&self.first.admission, &self.admission],
            SignerContinueRoleV1::Signer2, &result,
        )?;
        // Preserve immediate owner checks before the pair can be constructed.
        // No caller can mint a pair from detached DTOs or imported peers.
        let selections = [self.first.continuation, continuation];
        require_pair(&selections)?;
        let [first_continuation, continuation] = selections;
        let owners = [SelectedRetainedOriginalOwnerV1 {
            admission: self.first.admission, continuation: first_continuation,
            result: self.first.result,
        }, SelectedRetainedOriginalOwnerV1 {
            admission: self.admission, continuation, result,
        }];
        Ok(SelectedOriginalFinancialPairV1 { foreground, owners, owner: self.owner })
    }
}

fn wait_selected_continuation_retirement(
    foreground: HostFinancialForegroundV1,
    admissions: &[&RetainedOriginalCoordinatedAdmissionV1<'_>],
    target: SignerContinueRoleV1,
) -> Result<HostFinancialForegroundV1> {
    for admission in admissions { admission.check_pair_parked_bounds().map_err(restrict_failed_foreground)?; }
    let mut parked = foreground.enter_owner_workflow_wait().map_err(|e| restrict_failed_foreground(e.into()))?;
    loop {
        for admission in admissions { admission.check_pair_parked_bounds().map_err(restrict_failed_foreground)?; }
        if let Some(guard) = parked.try_next_retirement().map_err(|e| restrict_failed_foreground(e.into()))? {
            guard.wait_financial_continuation_resume(target).map_err(|e| restrict_failed_foreground(e.into()))?;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    for admission in admissions { admission.check_pair_parked_bounds().map_err(restrict_failed_foreground)?; }
    parked.leave_after_resume().map_err(|e| restrict_failed_foreground(e.into()))
}

/// Normal retirement is role-specific and follows the actual successful
/// Sign's selected request. The original peer/providers remain retained while
/// parked; this wait never reads a journal, renews a clock, or mints permission.
fn wait_selected_signing_retirement(
    foreground: HostFinancialForegroundV1,
    admissions: &[&RetainedOriginalCoordinatedAdmissionV1<'_>],
    target: SignerContinueRoleV1,
    result: &ResultSelectionV1,
) -> Result<HostFinancialForegroundV1> {
    for admission in admissions {
        admission.check_pair_parked_bounds().map_err(restrict_failed_foreground)?;
    }
    let mut parked = foreground.enter_owner_workflow_wait()
        .map_err(|e| restrict_failed_foreground(e.into()))?;
    loop {
        for admission in admissions {
            admission.check_pair_parked_bounds().map_err(restrict_failed_foreground)?;
        }
        if let Some(guard) = parked.try_next_retirement()
            .map_err(|e| restrict_failed_foreground(e.into()))? {
            guard.wait_financial_signing_resume(
                target, &result.request.authorization_id, &result.request.original_consent_ref,
            ).map_err(|e| restrict_failed_foreground(e.into()))?;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    for admission in admissions {
        admission.check_pair_parked_bounds().map_err(restrict_failed_foreground)?;
    }
    parked.leave_after_resume().map_err(|e| restrict_failed_foreground(e.into()))
}

fn restrict_failed_foreground(error: Error) -> Error {
    // Denial only. An earlier bind/intake/extraction may already have happened;
    // preserve its exact journal/operation, never retry or infer no effect.
    crate::terminal::fail_original_coordinator_restriction();
    error
}

/// The genuine parked owner is dropped before either retained provider/Peer.
pub(super) struct ParkedSelectedOriginalFinancialPairV1<'host> {
    parked: HostFinancialInterstageWaitV1,
    owners: [SelectedRetainedOriginalOwnerV1<'host>; 2],
    owner: &'host OpenedOriginalFinancialHostV1,
}
pub(super) struct ServingOriginalFinancialPairV1<'host> {
    foreground: HostFinancialForegroundV1,
    service: Arc<HostCompletedPairServiceV1>,
    owners: [SelectedRetainedOriginalOwnerV1<'host>; 2],
    owner: &'host OpenedOriginalFinancialHostV1,
}
impl<'host> SelectedOriginalFinancialPairV1<'host> {
    pub(super) fn park_for_completed_pair_service(self) -> Result<ParkedSelectedOriginalFinancialPairV1<'host>> {
        for selected in &self.owners {
            selected.admission.check_pair_parked_bounds().map_err(restrict_failed_foreground)?;
            require_coordinated_admitted_selection_v1(&selected.continuation,
                selected.admission.checked_admission_status().map_err(restrict_failed_foreground)?)
                .map_err(restrict_failed_foreground)?;
        }
        let parked = self.foreground.enter_owner_workflow_wait()
            .map_err(|e| restrict_failed_foreground(e.into()))?;
        Ok(ParkedSelectedOriginalFinancialPairV1 { parked, owners: self.owners, owner: self.owner })
    }
}
impl<'host> ParkedSelectedOriginalFinancialPairV1<'host> {
    pub(super) fn wait_completed_pair_service(self) -> Result<ServingOriginalFinancialPairV1<'host>> {
        for selected in &self.owners {
            selected.admission.check_pair_parked_bounds().map_err(restrict_failed_foreground)?;
        }
        // Origin handles each exact retirement guard and matching Resume, and
        // returns STILL PARKED. No source/TTY operation runs in this interval.
        let (parked, service) = self.parked.wait_completed_pair_service()
            .map_err(|e| restrict_failed_foreground(e.into()))?;
        for selected in &self.owners {
            selected.admission.check_pair_parked_bounds().map_err(restrict_failed_foreground)?;
        }
        require_selected_pair_service(&self.owners, &service).map_err(restrict_failed_foreground)?;
        let service = Terminal::install_completed_pair_service(service).map_err(restrict_failed_foreground)?;
        let foreground = parked.leave_after_completed_pair_service(&service)
            .map_err(|e| restrict_failed_foreground(e.into()))?;
        Ok(ServingOriginalFinancialPairV1 { foreground, service, owners: self.owners, owner: self.owner })
    }
}
fn pair_digest(domain: &str, value: &impl serde::Serialize) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(domain.as_bytes()); digest.update([0]);
    digest.update(serde_json::to_vec(value)?);
    Ok(hex::encode(digest.finalize()))
}
fn require_selected_pair_service(
    owners: &[SelectedRetainedOriginalOwnerV1<'_>; 2], service: &HostCompletedPairServiceV1,
) -> Result<()> {
    service.check_current()?;
    let presentation = service.presentation();
    presentation.validate()?;
    for (index, selected) in owners.iter().enumerate() {
        let original = &service.original_binding().owners[index];
        let account = &presentation.accounts[index];
        let request: wholepact_authority::OwnerControlRequest =
            wholepact_core::parse_typed_json(original.request_json.as_bytes()).map_err(|_| Error::Authentication)?;
        let disclosure: wholepact_authority::WitnessDisclosureDescriptor =
            wholepact_core::parse_typed_json(original.owner_disclosure_json.as_bytes()).map_err(|_| Error::Authentication)?;
        let record = continuation_record(&selected.continuation)?;
        let terms = &record.terms;
        let scope = &terms.scope;
        let witness = &scope.witness;
        if &request != selected.continuation.original_request()
            || request.account_id != original.account_id || request.operation_id != original.operation_id
            || request.network_profile_id != original.network_profile_id
            || &disclosure != witness
            || wholepact_core::proposal::canonical_digest("wholepact:coordinated-original-financial-disclosure:v1", witness)
                .map_err(|_| Error::Authentication)? != original.owner_disclosure_digest
            || terms.intent_terms_digest().map_err(|_| Error::Authentication)? != original.terms_digest
            || terms.valid_until_ms != original.source_expires_at_ms
            || record.request_digest(&request).map_err(|_| Error::Authentication)? != account.admission_digest
            || account.policy_digest != witness.policy_digest
            || account.dispatcher_certificate_digest != scope.delivery.dispatcher.public_identity_commitment
            || presentation.endpoint != witness.endpoint || presentation.server_name != witness.server_name
            || presentation.witness_id != witness.witness_id
            || presentation.pinned_server_certificate_digest != witness.pinned_server_certificate_digest
            || presentation.fixed_digest != pair_digest("wholepact:coordinated-completed-pair:fixed:v1", &scope.authorization.fixed)?
            || presentation.delivery_digest != pair_digest("wholepact:coordinated-completed-pair:delivery:v1", &scope.delivery)?
        { return Err(Error::Authentication); }
        // Independent original wall intersection. No deadline or authority is minted.
        let ceilings = &scope.original_ceilings;
        let mut from = terms.valid_from_ms.max(scope.authorization.valid_from_ms)
            .max(scope.delivery.valid_from_ms).max(ceilings.payment_valid_from_ms);
        let mut until = terms.valid_until_ms.min(scope.authorization.valid_until_ms)
            .min(scope.delivery.valid_until_ms).min(ceilings.payment_valid_until_ms)
            .min(ceilings.enrollment_expires_at_ms).min(ceilings.policy_expires_at_ms);
        for material in &ceilings.material_scopes {
            from = from.max(material.valid_from_unix_seconds.checked_mul(1000).ok_or(Error::Authentication)?);
            until = until.min(material.valid_until_unix_seconds.checked_mul(1000).ok_or(Error::Authentication)?);
        }
        if from >= until || presentation.valid_from_ms < from || presentation.valid_until_ms > until {
            return Err(Error::Authentication);
        }
        require_coordinated_admitted_selection_v1(&selected.continuation, selected.admission.checked_admission_status()?)?;
        require_result_selection(&selected.result, record)?;
    }
    service.check_current()?;
    Ok(())
}

pub(super) struct RetainedCompletedOriginalFinancialV1<'host> {
    service: Arc<HostCompletedPairServiceV1>,
    foreground: HostFinancialForegroundV1,
    owner: &'host OpenedOriginalFinancialHostV1,
    operation: String,
    // Inert output of actual completed-only verification, not Read permission.
    summary: CompletedPrivateFinancialSummaryV1,
    // Preserve the two already-checked originals for later exact fresh history.
    // These DTOs cannot establish CompletedPair service or dispatch permission.
    selections: [ContinuationSelectionV1; 2],
}
pub(super) enum CompletedSummaryDisclosureV1 {
    Displayed,
    Refused(Error),
}

impl<'host> ServingOriginalFinancialPairV1<'host> {
    pub(super) fn complete(self) -> Result<RetainedCompletedOriginalFinancialV1<'host>> {
        let host = &self.owner.host;
        let workspace = &self.owner.workspace;
        let commands = &self.owner.commands;
        let [first, second] = self.owners;
        let selections = [first.continuation, second.continuation];
        let results = [first.result, second.result];
        let admissions = [first.admission, second.admission];
        require_pair(&selections).map_err(restrict_failed_foreground)?;
        self.service.check_current().map_err(|e| restrict_failed_foreground(e.into()))?;
        // Each maintained helper opens its genuine original source and issues
        // its distinct Read. The ENTIRE authenticated request must still match.
        let histories = read_histories(host, workspace, &selections)
            .map_err(restrict_failed_foreground)?;
        self.service.check_current().map_err(|e| restrict_failed_foreground(e.into()))?;
        host.bind_original_financial_continuations_v1(
            workspace, &commands.bind_key, [&histories[0], &histories[1]],
        ).map_err(restrict_failed_foreground)?;
        for (index, admission) in admissions.into_iter().enumerate() {
            require_result_selection(&results[index], histories[index].continuation_record())
                .map_err(restrict_failed_foreground)?;
            // Move the SAME actual provider/Peer from V3. This method obtains
            // a NEW preview Read; it cannot reuse expired V3 Read authority.
            self.service.check_current().map_err(|e| restrict_failed_foreground(e.into()))?;
            let receiver = admission.prepare_original_result(
                host, workspace, &results[index].signer_socket,
                &results[index].request, &histories[index],
            ).map_err(restrict_failed_foreground)?;
            // No unrelated prompt or operation intervenes. Intake itself owns
            // its separate real Read/action/native retention/setup and binds
            // the second one-shot observer before actual ReturnExact receive.
            self.service.check_current().map_err(|e| restrict_failed_foreground(e.into()))?;
            host.intake_original_coordinated_financial_result_v1(
                workspace, &commands.intake_keys[index], receiver, &histories[index],
            ).map_err(restrict_failed_foreground)?;
        }
        self.service.check_current().map_err(|e| restrict_failed_foreground(e.into()))?;
        let completed = host.complete_original_financial_transaction_v1(
            workspace, &commands.completion_key,
        ).map_err(restrict_failed_foreground)?;
        let operation = histories[0].continuation_record().terms.scope.delivery
            .submission_operation_id.clone();
        self.service.check_current().map_err(|e| restrict_failed_foreground(e.into()))?;
        let summary = host.verify_completed_private_financial_summary_v1(workspace, &operation)
            .map_err(restrict_failed_foreground)?;
        if summary.checkpoint_id != completed.checkpoint_id
            || summary.transaction_digest != completed.transaction_digest
            || summary.transaction_id != completed.txid
        {
            return Err(restrict_failed_foreground(Error::Authentication));
        }
        Ok(RetainedCompletedOriginalFinancialV1 {
            service: self.service, foreground: self.foreground, owner: self.owner, operation, summary, selections,
        })
    }
}
impl RetainedCompletedOriginalFinancialV1<'_> {
    pub(super) fn display_summary(&self) -> CompletedSummaryDisclosureV1 {
        if let Err(error) = self.service.check_current() {
            return CompletedSummaryDisclosureV1::Refused(restrict_failed_foreground(error.into()));
        }
        // Never display the cached summary as if it carried Read permission.
        // A refusal is disclosure-only; this completed owner remains retained.
        match self.owner.host.display_completed_private_financial_summary_v1(
            &self.owner.workspace, &self.operation,
        ) {
            Ok(()) => CompletedSummaryDisclosureV1::Displayed,
            Err(error) => CompletedSummaryDisclosureV1::Refused(error),
        }
    }
    // No dispatch, successful-close or authority-release shortcut exists here.
}

/// Concrete original-H runner for the explicitly enabled common image. It
/// never falls back to legacy and never interprets cleanup as successful close.
pub fn run_coordinated_financial_host_v1(origin: HostOriginV1) -> std::io::Result<()> {
    let (owner, first) = open_original_financial_foreground_selected_v1(origin, None)
        .map_err(|failure| match failure {
            OriginalForegroundOpenFailureV1::BeforeMonitor(error) => std::io::Error::other(format!("Original Host open failed: {error}")),
            OriginalForegroundOpenFailureV1::Joined(failure) => joined_runner_failure(failure, None),
        })?;
    let outcome = (|| -> Result<RetainedCompletedOriginalFinancialV1<'_>> {
        let mut first = first.begin(&owner)?;
        first.verify()?;
        let first = first.park_after_verified()?.wait_one_retirement()?.leave_after_resume()?;
        // Each selection itself parks at the exact continuation retirement,
        // before requesting its SignExact/AwaitingReturn result selector.
        let mut second = first.select_original_handoffs()?.begin_second()?;
        second.verify()?;
        let second = second.park_after_verified()?.wait_one_retirement()?.leave_after_resume()?;
        second.select_original_handoffs()?.park_for_completed_pair_service()?
            .wait_completed_pair_service()?.complete()
    })();
    let (error, completed_operation) = match outcome {
        Err(error) => (restrict_failed_foreground(error), None),
        Ok(completed) => {
            // Disclosure remains a separate real Read; refusal cannot undo a
            // committed completion or authorize replacement work.
            let _disclosure = completed.display_summary();
            let operation = completed.operation.clone();
            let error = loop {
                if let Err(error) = completed.service.check_current() { break Error::from(error); }
                if let Err(error) = crate::terminal::check_original_coordinator_restriction() { break error; }
                std::thread::sleep(std::time::Duration::from_millis(10));
            };
            let error = restrict_failed_foreground(error);
            drop(completed);
            (error, Some(operation))
        }
    };
    // All borrowing admissions/foreground holders have ended before joining
    // the original relay. Neither cleanup nor its failure rewrites effects.
    Err(joined_runner_failure(owner.abort_and_join(error), completed_operation.as_deref()))
}
fn joined_runner_failure(failure: HostRelayFailureV1, completed: Option<&str>) -> std::io::Error {
    let effect = match completed {
        Some(operation) => format!("Original operation {operation} completed before restriction; no dispatch or successful shutdown is claimed"),
        None => "Original Host stopped; effects may be partial or uncertain and must not be retried as a replacement".to_owned(),
    };
    std::io::Error::other(format!("{effect}; foreground: {}; owned relay cleanup: {:?}", failure.foreground, failure.relay))
}

/// One-use original relay mailbox only. Waiting does not create a deadline,
/// select a socket, recover a process, or authorize any source/private read.
fn wait_original_coordinated_pair_endpoint_v1(
    foreground: &HostFinancialForegroundV1, target: SignerContinueRoleV1,
) -> Result<wholepact_financial_coordinator_origin::SignerV3PairEndpointV1> {
    loop {
        let endpoint = match target {
            SignerContinueRoleV1::Signer1 => foreground.take_v3_pair_endpoint_signer1(),
            SignerContinueRoleV1::Signer2 => foreground.take_v3_pair_endpoint_signer2(),
        }.map_err(|error| restrict_failed_foreground(error.into()))?;
        if let Some(endpoint) = endpoint { return Ok(endpoint); }
        // Original actors/session/shared restrictions are checked by each
        // mailbox observation; no new authority is accumulated by this wait.
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
fn require_coordinated_admitted_selection_v1(
    selection: &ContinuationSelectionV1,
    admitted: &wholepact_signer::authority_bridge::durable_review_ipc_v3::coordinated_v1::CoordinatedDurableDeliveryAdmissionStatusV1,
) -> Result<()> {
    let record = continuation_record(selection)?;
    let audit = admitted.verified_audit().map_err(|_| Error::Authentication)?;
    let terms = &record.terms;
    if terms.scope != audit.scope
        || terms.original_delivery_operation_id != admitted.request.operation_id
        || terms.original_delivery_request_digest != wholepact_authority::durable_financial_continuation_v1::original_delivery_request_digest_v1(&admitted.request).map_err(|_| Error::Authentication)?
        || terms.original_local_intent_digest != admitted.original_local_intent_digest
        || terms.original_recipient_intent_digest != admitted.intent_digest
        || terms.original_recipient_enrollment_ref != audit.original_enrollment_ref
        || terms.original_recipient_manifest_ref != audit.original_accepted_manifest_ref
    { return Err(Error::Authentication); }
    Ok(())
}

fn wait_original_coordinated_current_disclosure_v1(
    foreground: &HostFinancialForegroundV1, target: SignerContinueRoleV1,
) -> Result<wholepact_financial_coordinator_origin::SignerV3CurrentDisclosureV1> {
    loop {
        let data = match target {
            SignerContinueRoleV1::Signer1 => foreground.take_v3_current_disclosure_signer1(),
            SignerContinueRoleV1::Signer2 => foreground.take_v3_current_disclosure_signer2(),
        }.map_err(|error| restrict_failed_foreground(error.into()))?;
        if let Some(data) = data { return Ok(data); }
        // No new lifetime or permission: same original mailbox checks each
        // actual actor/session/shared restriction before any observation.
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
