//! Explicit two-phase quarantined source sequencing. Endpoint metadata is only
//! a readiness signal; every single pairing attempt still authenticates the
//! installed image and kernel peer. No endpoint scan, retry or fallback exists.
use super::{SignerRequest, V5SignerSource};
use crate::{
    Error, Result,
    terminal::{PublicationApproval, Terminal},
};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use wholepact_signer::{
    authority_bridge::{
        host_publication_ipc::v5::{
            HostRecoveryPublicationAdmissionV5, HostRecoveryPublicationRequestV5,
        },
        host_recovery_ipc::v5::HostRecoveryContinuityEvidenceV5,
        provider::InstalledSignerProvider,
    },
    ipc::PairScope,
};

const ENDPOINT_WAIT: Duration = Duration::from_secs(120);
const ENDPOINT_POLL: Duration = Duration::from_millis(100);

/// File identity is not signer authentication or a native admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EndpointIdentity {
    directory_dev: u64,
    directory_ino: u64,
    dev: u64,
    ino: u64,
}

/// The selected private runtime directory is mandatory even before its socket
/// exists. Absence must never erase the original directory identity binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EndpointObservation {
    directory_dev: u64,
    directory_ino: u64,
    endpoint: Option<EndpointIdentity>,
}
impl EndpointObservation {
    fn occupied(endpoint: EndpointIdentity) -> Self {
        Self {
            directory_dev: endpoint.directory_dev,
            directory_ino: endpoint.directory_ino,
            endpoint: Some(endpoint),
        }
    }
}

fn observe_endpoint(path: &Path) -> Result<EndpointObservation> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    crate::files::validate_absolute(path)?;
    let parent = path.parent().ok_or(Error::Invalid)?;
    // No implicit runtime-directory creation or adoption during a wait. The
    // exact existing private directory was selected before terminal approval.
    let directory = std::fs::symlink_metadata(parent)?;
    // SAFETY: geteuid only reads this process's effective uid.
    let uid = unsafe { libc::geteuid() };
    if !directory.is_dir()
        || directory.uid() != uid
        || directory.mode() & 0o077 != 0
        || std::fs::canonicalize(parent)? != parent
    {
        return Err(Error::Authentication);
    }
    let socket = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(EndpointObservation {
                directory_dev: directory.dev(),
                directory_ino: directory.ino(),
                endpoint: None,
            });
        }
        Err(error) => return Err(error.into()),
    };
    if !socket.file_type().is_socket()
        || socket.uid() != uid
        || socket.mode() & 0o077 != 0
        || socket.nlink() != 1
    {
        return Err(Error::Authentication);
    }
    Ok(EndpointObservation::occupied(EndpointIdentity {
        directory_dev: directory.dev(),
        directory_ino: directory.ino(),
        dev: socket.dev(),
        ino: socket.ino(),
    }))
}

/// The only polling loop occurs before any pairing/request effect. Injectable
/// clocks and observations test refusal without creating a socket or native owner.
fn await_changed_endpoint(
    previous: EndpointObservation,
    deadline: Instant,
    mut now: impl FnMut() -> Instant,
    mut observe: impl FnMut() -> Result<EndpointObservation>,
    mut check: impl FnMut() -> Result<()>,
    mut pause: impl FnMut(),
) -> Result<EndpointIdentity> {
    loop {
        check()?;
        if now() >= deadline {
            return Err(Error::Permission);
        }
        let observed = observe()?;
        check()?;
        if now() >= deadline {
            return Err(Error::Permission);
        }
        // Check the original directory even while BOTH sockets are absent.
        if observed.directory_dev != previous.directory_dev
            || observed.directory_ino != previous.directory_ino
        {
            return Err(Error::Authentication);
        }
        if let Some(current) = observed.endpoint {
            if Some(current) != previous.endpoint {
                return Ok(current);
            }
        }
        pause();
    }
}

fn wait_endpoint(
    path: &Path,
    previous: EndpointObservation,
    deadline: Instant,
    check: impl FnMut() -> Result<()>,
) -> Result<EndpointIdentity> {
    await_changed_endpoint(
        previous,
        deadline,
        Instant::now,
        || observe_endpoint(path),
        check,
        || std::thread::sleep(ENDPOINT_POLL),
    )
}
fn require_directory(path: &Path, expected: EndpointObservation) -> Result<()> {
    let observed = observe_endpoint(path)?;
    if observed.directory_dev != expected.directory_dev
        || observed.directory_ino != expected.directory_ino
    {
        return Err(Error::Authentication);
    }
    Ok(())
}

/// Restriction only: the original terminal approval and existing 120-second cap
/// share one absolute deadline across launch, report, readiness and pairing.
fn phase_deadline(approval_deadline: Instant, now: Instant) -> Instant {
    approval_deadline.min(now + ENDPOINT_WAIT)
}

fn require_phase_current(deadline: Instant, now: Instant) -> Result<()> {
    if now >= deadline {
        return Err(Error::Permission);
    }
    Ok(())
}

/// Restrict every effect and its acceptance to the same original phase budget.
/// A late successful response is refused; its outcome is not retried or undone.
fn phase_attempt_once<T>(
    deadline: Instant,
    mut now: impl FnMut() -> Instant,
    mut check: impl FnMut() -> Result<()>,
    attempt: impl FnOnce() -> Result<T>,
) -> Result<T> {
    attempt_once(
        || {
            require_phase_current(deadline, now())?;
            check()?;
            require_phase_current(deadline, now())
        },
        attempt,
    )
}

/// Consume ONE actual inherited child report using only the remaining original
/// budget. This report is endpoint data, never native approval or authentication.
/// Error-only test callbacks model child/refusal failures without a provider.
fn receive_endpoint_once(
    expected: &Path,
    deadline: Instant,
    mut now: impl FnMut() -> Instant,
    mut check: impl FnMut() -> Result<()>,
    receive: impl FnOnce(Duration) -> Result<PathBuf>,
) -> Result<()> {
    check()?;
    let remaining = deadline
        .checked_duration_since(now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(Error::Permission)?;
    let reported = receive(remaining)?;
    check()?;
    require_phase_current(deadline, now())?;
    if reported.as_path() != expected {
        return Err(Error::Authentication);
    }
    Ok(())
}

fn require_endpoint(path: &Path, expected: EndpointIdentity) -> Result<()> {
    if observe_endpoint(path)? != EndpointObservation::occupied(expected) {
        return Err(Error::Authentication);
    }
    Ok(())
}

/// A failed effect is terminal. FnOnce rules out automatic retry at this seam;
/// the same original restrictions are checked immediately before and after it.
fn attempt_once<T>(
    mut check: impl FnMut() -> Result<()>,
    attempt: impl FnOnce() -> Result<T>,
) -> Result<T> {
    check()?;
    let result = attempt();
    // Even an error can represent an uncertain effect. Recheck restrictions
    // without accepting any result or attempting the effect again.
    check()?;
    result
}

fn require_distinct_endpoints(requests: &[SignerRequest]) -> Result<()> {
    let mut paths = BTreeSet::new();
    let mut accounts = BTreeSet::new();
    for request in requests {
        request.continuity.validate().map_err(|_| Error::Invalid)?;
        crate::files::validate_absolute(&request.socket)?;
        // The native owner retains only one exact completed source across blur.
        // Different accounts therefore need distinct exact native endpoints.
        if request.socket.file_name()
            != Some(std::ffi::OsStr::new(
                wholepact_signer::ipc::QUARANTINED_INFORMATIONAL_SOCKET_BASENAME,
            ))
            || !paths.insert(&request.socket)
            || !accounts.insert(&request.continuity.account_id)
        {
            return Err(Error::Invalid);
        }
    }
    Ok(())
}
fn scope(request: &SignerRequest) -> PairScope {
    PairScope {
        account_id: request.continuity.account_id.clone(),
        agreement_id: "host-recovery".into(),
        participant_id: "host-recovery".into(),
        manifest_digest: request.continuity.inventory_digest.clone(),
        history_read: true,
        authorization_export: true,
        preconstruction_export: false,
    }
}

/// Key-free in-process routing data only. These exact endpoints and observations
/// cannot be deserialized into a grant or substituted for a fresh native review.
struct PublicationMetadata(Vec<(SignerRequest, EndpointIdentity, String)>);
impl PublicationMetadata {
    fn review_scope(
        &self,
        requests: &[HostRecoveryPublicationRequestV5],
    ) -> Result<serde_json::Value> {
        self.validate_requests(requests)?;
        Ok(serde_json::Value::Array(
            requests
                .iter()
                .map(|request| {
                    let target = self
                        .0
                        .iter()
                        .find(|(target, _, _)| target.continuity == request.continuity)
                        .ok_or(Error::Authentication)?;
                    Ok(serde_json::json!({"socket": target.0.socket, "publication": request}))
                })
                .collect::<Result<Vec<_>>>()?,
        ))
    }
    fn validate_requests(&self, requests: &[HostRecoveryPublicationRequestV5]) -> Result<()> {
        if requests.len() != self.0.len() {
            return Err(Error::Authentication);
        }
        let mut accounts = BTreeSet::new();
        for request in requests {
            request.validate().map_err(|_| Error::Authentication)?;
            if !accounts.insert(&request.continuity.account_id)
                || !self.0.iter().any(|(target, _, evidence_digest)| {
                    target.continuity == request.continuity
                        && evidence_digest == &request.continuity_evidence_digest
                })
            {
                return Err(Error::Authentication);
            }
        }
        Ok(())
    }
}

/// Actual nonclone installed-child provenance is retained separately from
/// inert metadata. After Finish and consuming client release, no old grant,
/// token, scope or peer admission is retained.
/// Keeping this owner also keeps the original inherited report channel alive.
pub(in crate::recovery_generation) struct PublicationTargets {
    metadata: PublicationMetadata,
    providers: Vec<RetainedSigner>,
}
struct RetainedSigner {
    provider: InstalledSignerProvider,
    deadline: Instant,
}
impl PublicationTargets {
    pub(in crate::recovery_generation) fn review_scope(
        &self,
        requests: &[HostRecoveryPublicationRequestV5],
    ) -> Result<serde_json::Value> {
        self.metadata.review_scope(requests)
    }
}

pub(in crate::recovery_generation) fn continuity(
    terminal: &Terminal,
    requests: Vec<SignerRequest>,
    mut source_check: impl FnMut() -> Result<()>,
) -> Result<(Vec<HostRecoveryContinuityEvidenceV5>, PublicationTargets)> {
    require_distinct_endpoints(&requests)?;
    let mut approved = Vec::with_capacity(requests.len());
    // ALL terminal input precedes native focus. Each one-use approval keeps its
    // original 120-second deadline; no wait, retry or later prompt renews it.
    for request in requests {
        source_check()?;
        let previous = observe_endpoint(&request.socket)?;
        let pairing = terminal.approve_historical(&super::super::layered_activate_v5::review(
            "After ALL Host reviews, launch the already installed pinned signer image ONCE for this exact account/endpoint, then enter the exact source and witness in that new native window. Retain this same child process and inherited endpoint-report channel through later fresh publication reentry. After explicit Finish, Host destroys all old pairing credentials and retains only installed-child provenance. Host consumes one exact path report, waits for the expected endpoint identity and makes ONE fresh authenticated pairing attempt. No new child on publication, relaunch, retry or alternate path is permitted. Launch/pairing alone does not approve disclosure, publication or financial activity.", &request)?)?;
        let disclosure = terminal.approve_historical(&super::super::layered_activate_v5::review(
            "Request separate signer-native complete historical continuity for this exact account/writer/witness/inventory. Pairing, disclosure, explicit Finish and client release run sequentially per account with no more Host prompts until the entire continuity phase ends. Each account requires a distinct native endpoint. Keep the original source available for later exact publication reentry within its original deadline. Every exposure, charge and fence stays conservative; no writer, signing, submission or financial authority is requested.", &request)?)?;
        approved.push((request, previous, pairing, disclosure));
    }
    let mut evidence = Vec::with_capacity(approved.len());
    let mut targets = Vec::with_capacity(approved.len());
    let mut providers = Vec::with_capacity(approved.len());
    for (request, previous, pairing, disclosure) in approved {
        let deadline = phase_deadline(
            pairing.deadline().min(disclosure.deadline()),
            Instant::now(),
        );
        let mut paired = None;
        pairing.effect(&mut || {
            source_check()?;
            pairing.check()?;
            disclosure.check()?;
            require_directory(&request.socket, previous)?;
            let provider = InstalledSignerProvider::load().map_err(|_| Error::Permission)?;
            // Recheck after the installed image/configuration read and before
            // admitting the one already reviewed process-launch effect.
            source_check()?;
            pairing.check()?;
            disclosure.check()?;
            require_directory(&request.socket, previous)?;
            require_phase_current(deadline, Instant::now())?;
            // Only this initial continuity phase creates the exact pinned child.
            provider.launch_native().map_err(|_| Error::Permission)?;
            receive_endpoint_once(
                &request.socket,
                deadline,
                Instant::now,
                || {
                    source_check()?;
                    pairing.check()?;
                    disclosure.check()?;
                    require_directory(&request.socket, previous)
                },
                |remaining| {
                    provider
                        .wait_native_endpoint(remaining)
                        .map_err(|_| Error::Permission)
                },
            )?;
            let endpoint = wait_endpoint(&request.socket, previous, deadline, || {
                source_check()?;
                pairing.check()?;
                disclosure.check()
            })?;
            // Exactly one effectful attempt after readiness. Errors propagate;
            // no loop encloses pairing, disclosure, Finish or publication.
            let client = phase_attempt_once(
                deadline,
                Instant::now,
                || {
                    source_check()?;
                    pairing.check()?;
                    disclosure.check()?;
                    require_endpoint(&request.socket, endpoint)
                },
                || {
                    V5SignerSource::QuarantinedInformational.pair(
                        provider,
                        &request.socket,
                        "wholepact-native-host-recovery",
                        scope(&request),
                    )
                },
            )?;
            paired = Some((client, endpoint));
            Ok(())
        })?;
        let (client, endpoint) = paired.ok_or(Error::Permission)?;
        require_phase_current(deadline, Instant::now())?;
        disclosure.effect(&mut || {
            let lease = phase_attempt_once(
                deadline,
                Instant::now,
                || {
                    source_check()?;
                    disclosure.check()?;
                    require_endpoint(&request.socket, endpoint)
                },
                || {
                    client
                        .acquire_quarantined_informational_continuity_v5_until(
                            &request.continuity,
                            deadline,
                        )
                        .map_err(|_| Error::Permission)
                },
            )?;
            phase_attempt_once(
                deadline,
                Instant::now,
                || {
                    source_check()?;
                    disclosure.check()
                },
                || lease.check_current().map_err(|_| Error::Permission),
            )?;
            let exact = lease.evidence().clone();
            phase_attempt_once(
                deadline,
                Instant::now,
                || {
                    source_check()?;
                    disclosure.check()
                },
                || lease.finish().map_err(|_| Error::Permission),
            )?;
            // The authenticated Finish acknowledgment completes this channel.
            // Later blur may remove its endpoint; no live signer hold is reused.
            evidence.push(exact);
            Ok(())
        })?;
        let provider = phase_attempt_once(
            deadline,
            Instant::now,
            || {
                source_check()?;
                disclosure.check()
            },
            || {
                client
                    .into_quarantined_unpaired_provider()
                    .map_err(|_| Error::Permission)
            },
        )?;
        let evidence_digest = evidence
            .last()
            .ok_or(Error::Permission)?
            .digest()
            .map_err(|_| Error::Authentication)?;
        targets.push((request, endpoint, evidence_digest));
        providers.push(RetainedSigner { provider, deadline });
    }
    Ok((
        evidence,
        PublicationTargets {
            metadata: PublicationMetadata(targets),
            providers,
        },
    ))
}

pub(in crate::recovery_generation) fn publication(
    targets: PublicationTargets,
    requests: Vec<HostRecoveryPublicationRequestV5>,
    approval: &PublicationApproval,
    mut source_check: impl FnMut() -> Result<()>,
) -> Result<Vec<HostRecoveryPublicationAdmissionV5>> {
    targets.metadata.validate_requests(&requests)?;
    if targets.providers.len() != targets.metadata.0.len() {
        return Err(Error::Authentication);
    }
    let mut admissions = Vec::with_capacity(requests.len());
    for ((target, previous, _), retained) in targets.metadata.0.into_iter().zip(targets.providers) {
        let request = requests
            .iter()
            .find(|request| request.continuity == target.continuity)
            .ok_or(Error::Authentication)?;
        let previous = EndpointObservation::occupied(previous);
        let deadline = retained.deadline.min(approval.deadline());
        let provider = retained.provider;
        // Consume a new report from the SAME retained child. No provider load,
        // clone, process lookup fallback, new launch or old grant reuse occurs.
        receive_endpoint_once(
            &target.socket,
            deadline,
            Instant::now,
            || {
                approval.check()?;
                source_check()?;
                require_directory(&target.socket, previous)
            },
            |remaining| {
                provider
                    .wait_native_endpoint(remaining)
                    .map_err(|_| Error::Permission)
            },
        )?;
        // The completed continuity client is already gone. A fresh native source
        // and witness entry must create a new endpoint at the SAME exact path.
        let endpoint = wait_endpoint(&target.socket, previous, deadline, || {
            approval.check()?;
            source_check()
        })?;
        let client = phase_attempt_once(
            deadline,
            Instant::now,
            || {
                approval.check()?;
                source_check()?;
                require_endpoint(&target.socket, endpoint)
            },
            || {
                V5SignerSource::QuarantinedInformational.pair(
                    provider,
                    &target.socket,
                    "wholepact-native-host-recovery",
                    scope(&target),
                )
            },
        )?;
        let lease = phase_attempt_once(
            deadline,
            Instant::now,
            || {
                approval.check()?;
                source_check()
            },
            || {
                client
                    .acquire_quarantined_informational_publication_v5_until(request, deadline)
                    .map_err(|_| Error::Permission)
            },
        )?;
        let admission = phase_attempt_once(
            deadline,
            Instant::now,
            || {
                approval.check()?;
                source_check()
            },
            || lease.admit().map_err(|_| Error::Permission),
        )?;
        drop(client);
        approval.check()?;
        source_check()?;
        require_phase_current(deadline, Instant::now())?;
        admissions.push(admission);
    }
    Ok(admissions)
}

#[cfg(test)]
#[path = "quarantined_sequence_tests.rs"]
mod tests;
