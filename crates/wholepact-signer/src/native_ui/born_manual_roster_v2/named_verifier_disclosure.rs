//! Separate exact verifier viewing lane for the actual consumed born owner.
//! The original Host endpoint, pairing and financial scopes are never reused.
use super::{named_continuation::ConsumedBornNamedOwnerV1, *};
use crate::consent_journal::LiveNamedRecipientProfile;
use crate::native_ui::NativeAuthorityBinding;
use crate::native_ui::named_verifier_policy::PreparedNamedVerifierPolicy;
use std::os::unix::net::UnixStream;
use wholepact_signer_origin::{PairScope, named_verifier_policy::NamedVerifierPolicyScopeV1};

fn wall() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Locked)?
        .as_millis()
        .try_into()
        .map_err(|_| Error::Locked)
}
fn expected_pair(scope: &NamedVerifierPolicyScopeV1) -> Result<PairScope> {
    let proposal = scope.validate().map_err(|_| Error::ReviewMismatch)?;
    Ok(PairScope {
        account_id: scope.account_id.clone(),
        agreement_id: proposal.manifest().agreement.agreement_id.clone(),
        participant_id: scope.participant_id.clone(),
        manifest_digest: scope.pairing_digest().map_err(|_| Error::ReviewMismatch)?,
        history_read: false,
        authorization_export: false,
        preconstruction_export: false,
    })
}
fn require_exact(
    actual: &ConsumedBornNamedOwnerV1,
    profile: &LiveNamedRecipientProfile,
    scope: &NamedVerifierPolicyScopeV1,
    owner: &PendingAccountNativeAuthority,
) -> Result<()> {
    actual.check(owner)?;
    profile.check_current(actual.source().journal(), actual.session()?)?;
    profile.check_display_association(actual.source().journal(), owner.native())?;
    let proposal = scope.validate().map_err(|_| Error::ReviewMismatch)?;
    let (enrollment, manifest) = actual.local_records()?;
    if scope.account_id != actual.source().genesis().identity.account_id
        || scope.account_id != enrollment.account_id()
        || scope.participant_id != enrollment.participant_id()
        || scope.enrollment_ref != enrollment.reference()
        || scope.accepted_manifest_ref != manifest.reference()
        || profile.enrollment_ref() != enrollment.reference()
        || profile.manifest_ref() != manifest.reference()
        || scope.verifier_public_key != *profile.verifier_signing_public_key()
        || &scope.proposal != manifest.proposal_input()
        || proposal.manifest_digest() != manifest.manifest_digest()
        || scope.proposal
            != *actual
                .source()
                .construction()
                .reservation
                .request
                .construction
                .plan
                .validate()
                .map_err(|_| Error::ReviewMismatch)?
                .input()
    {
        return Err(Error::ReviewMismatch);
    }
    Ok(())
}
pub(super) struct SelectedScope {
    profile: LiveNamedRecipientProfile,
    scope: NamedVerifierPolicyScopeV1,
    native: NativeAuthorityBinding,
    deadline: Instant,
    wall_floor: u64,
    digest: String,
    display: String,
}
impl SelectedScope {
    fn check(&self) -> Result<()> {
        self.native.check_current()?;
        let now = wall()?;
        if Instant::now() >= self.deadline
            || now < self.wall_floor
            || now >= self.scope.disclosure_expires_at_ms
        {
            return Err(Error::Locked);
        }
        Ok(())
    }
}
struct EndpointInner {
    selected: SelectedScope,
    expected: PairScope,
    ipc: Mutex<LocalIpc>,
    revocation: IpcRevocation,
    path: PathBuf,
    _directory: tempfile::TempDir,
}
#[derive(Clone)]
pub(super) struct Endpoint(Arc<EndpointInner>);
impl Endpoint {
    fn check(&self) -> Result<()> {
        self.0.selected.check()
    }
    fn require_peer(&self, peer: &AuthenticatedPeer) -> Result<()> {
        self.check()?;
        peer.check_current()?;
        if peer.native_origin != self.0.selected.native || peer.scope != self.0.expected {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    fn close_now(&self) {
        self.0.revocation.close_pending_now();
    }
}
pub(super) enum Input {
    Select(LiveNamedRecipientProfile, NamedVerifierPolicyScopeV1),
    Pair(Endpoint, Box<PendingPairing>),
    Disclose(
        Endpoint,
        AuthenticatedPeer,
        UnixStream,
        Box<wholepact_signer_origin::named_verifier_policy::NamedVerifierPolicyRequestV1>,
    ),
}
pub(super) enum Prepared {
    Select(SelectedScope),
    Pair {
        endpoint: Endpoint,
        pending: Box<PendingPairing>,
        digest: String,
        display: String,
    },
    Disclose {
        endpoint: Endpoint,
        prepared: Box<PreparedNamedVerifierPolicy>,
    },
}
pub(super) enum Outcome {
    Armed(Endpoint),
    Paired(Endpoint),
    Served(Endpoint),
}
impl Input {
    pub(super) fn prepare(
        self,
        actual: &ConsumedBornNamedOwnerV1,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Prepared> {
        match self {
            Self::Select(profile, scope) => {
                require_exact(actual, &profile, &scope, owner)?;
                let floor = wall()?;
                if floor < scope.requested_at_ms || floor >= scope.disclosure_expires_at_ms {
                    return Err(Error::Locked);
                }
                let native = owner.native().binding();
                let deadline = (Instant::now()
                    + Duration::from_millis(scope.disclosure_expires_at_ms - floor))
                .min(native.bounded_deadline()?);
                let digest = wholepact_core::proposal::canonical_digest(
                    "wholepact:native-born-exact-verifier-lane:v1",
                    &(
                        profile.reference(),
                        &scope,
                        actual.source().genesis(),
                        actual
                            .source()
                            .construction()
                            .digest()
                            .map_err(|_| Error::InvalidData)?,
                        native.entry_digest(),
                    ),
                )
                .map_err(|_| Error::InvalidData)?;
                let display = format!(
                    "SELECT ONE EXACT NAMED VERIFIER DISCLOSURE LANE\n{}\n\nThis opens a separate temporary endpoint only for this exact policy request and the verifier signing key already pinned in the retained profile. It does not change the original Host pairing or authorize a new Host, wallet read, writer, signature or dispatch. Pairing and FULL VIEWING KEY disclosure require separate native decisions and verifier proof of signing-key possession. A disclosed viewing key reveals past and future account activity and cannot be recalled. The claimed original artifact hash is displayed, not independently authenticated at this stage; exact original import and final signing remain separate. The original request/disclosure deadlines cannot be renewed.\nExact review: {}",
                    serde_json::to_string_pretty(&scope).map_err(|_| Error::InvalidData)?,
                    digest
                );
                Ok(Prepared::Select(SelectedScope {
                    profile,
                    scope,
                    native,
                    deadline,
                    wall_floor: floor,
                    digest,
                    display,
                }))
            }
            Self::Pair(endpoint, pending) => {
                endpoint.check()?;
                require_exact(
                    actual,
                    &endpoint.0.selected.profile,
                    &endpoint.0.selected.scope,
                    owner,
                )?;
                if pending.scope != endpoint.0.expected {
                    return Err(Error::ReviewMismatch);
                }
                let generation = endpoint
                    .0
                    .ipc
                    .lock()
                    .map_err(|_| Error::Locked)?
                    .generation();
                let digest = pending.review_digest(generation)?;
                let display = format!(
                    "PAIR ONLY THE SEPARATELY SELECTED NAMED VERIFIER\n{}\nActual local UID/PID: {}/{}; process instance {}.\nThis is NOT the original Host channel. It grants neither history nor authorization export. A separate exact full-viewing-key disclosure and maintained verifier possession signature remain mandatory.\nExact review: {}",
                    serde_json::to_string_pretty(&pending.scope).map_err(|_| Error::InvalidData)?,
                    pending.uid(),
                    pending.pid(),
                    pending.instance(),
                    digest
                );
                Ok(Prepared::Pair {
                    endpoint,
                    pending,
                    digest,
                    display,
                })
            }
            Self::Disclose(endpoint, peer, stream, request) => {
                endpoint.require_peer(&peer)?;
                require_exact(
                    actual,
                    &endpoint.0.selected.profile,
                    &endpoint.0.selected.scope,
                    owner,
                )?;
                if request.scope != endpoint.0.selected.scope {
                    return Err(Error::ReviewMismatch);
                }
                let prepared = PreparedNamedVerifierPolicy::prepare(
                    *request,
                    peer,
                    stream,
                    actual.source().journal(),
                    actual.session()?,
                    owner.native(),
                    actual.source().vault(),
                )?;
                Ok(Prepared::Disclose {
                    endpoint,
                    prepared: Box::new(prepared),
                })
            }
        }
    }
}
impl Prepared {
    pub(super) fn display(&self) -> Result<(String, String)> {
        match self {
            Self::Select(s) => {
                s.check()?;
                Ok((s.digest.clone(), s.display.clone()))
            }
            Self::Pair {
                endpoint,
                digest,
                display,
                ..
            } => {
                endpoint.check()?;
                Ok((digest.clone(), display.clone()))
            }
            Self::Disclose { endpoint, prepared } => {
                endpoint.check()?;
                Ok((prepared.digest().into(), prepared.display()?))
            }
        }
    }
    pub(super) fn approve(
        self,
        decision: NativeDecision,
        actual: &ConsumedBornNamedOwnerV1,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Outcome> {
        actual.check(owner)?;
        match self {
            Self::Select(selected) => {
                selected.check()?;
                require_exact(actual, &selected.profile, &selected.scope, owner)?;
                if decision.binding() != &selected.native
                    || decision.reviewed_digest() != selected.digest
                    || owner.native().binding() != selected.native
                {
                    return Err(Error::ReviewMismatch);
                }
                let directory = tempfile::Builder::new()
                    .permissions(std::fs::Permissions::from_mode(0o700))
                    .tempdir()?;
                // No replacement Host publication: display this distinct endpoint
                // only after the native result is adopted by the foreground.
                let expected = expected_pair(&selected.scope)?;
                let ipc = LocalIpc::bind_born_named_verifier_v1(
                    crate::files::PrivateDirectory::open(directory.path())?,
                    expected.clone(),
                )?;
                let path = ipc.socket_path().to_path_buf();
                let revocation = ipc.revocation();
                selected.check()?;
                Ok(Outcome::Armed(Endpoint(Arc::new(EndpointInner {
                    selected,
                    expected,
                    ipc: Mutex::new(ipc),
                    revocation,
                    path,
                    _directory: directory,
                }))))
            }
            Self::Pair {
                endpoint, pending, ..
            } => {
                endpoint.check()?;
                require_exact(
                    actual,
                    &endpoint.0.selected.profile,
                    &endpoint.0.selected.scope,
                    owner,
                )?;
                if pending.scope != endpoint.0.expected {
                    return Err(Error::ReviewMismatch);
                }
                endpoint
                    .0
                    .ipc
                    .lock()
                    .map_err(|_| Error::Locked)?
                    .approve_pairing(*pending, decision, owner.native())?;
                endpoint.check()?;
                Ok(Outcome::Paired(endpoint))
            }
            Self::Disclose { endpoint, prepared } => {
                endpoint.check()?;
                require_exact(
                    actual,
                    &endpoint.0.selected.profile,
                    &endpoint.0.selected.scope,
                    owner,
                )?;
                let approved =
                    prepared.approve(decision, owner.native(), actual.source().vault())?;
                // Maintained source-bound record lease remains held through all
                // output bytes. The callback must NOT reacquire its journal.
                approved.serve_with_current(
                    actual.source().journal(),
                    actual.session()?,
                    |lease| {
                        endpoint.check()?;
                        actual.source().check_disclosure_liveness(owner, lease)
                    },
                    || {
                        endpoint.check()?;
                        actual.check(owner)
                    },
                )?;
                actual.check(owner)?;
                Ok(Outcome::Served(endpoint))
            }
        }
    }
}
#[derive(Default)]
pub(super) struct State {
    endpoint: Option<Endpoint>,
    // Adopt even rejected/late outcomes into tracked cleanup before returning.
    retired: Vec<Endpoint>,
    pending: bool,
    paired: bool,
    peer: Option<AuthenticatedPeer>,
}
impl State {
    pub(super) fn engaged(&self) -> bool {
        self.endpoint.is_some() || self.pending
    }
    pub(super) fn begin(&mut self) -> Result<()> {
        if self.engaged() {
            return Err(Error::Locked);
        }
        self.pending = true;
        Ok(())
    }
    pub(super) fn endpoint(&self) -> Option<&Path> {
        self.endpoint.as_ref().map(|e| e.0.path.as_path())
    }
    pub(super) fn adopt(
        &mut self,
        outcome: Outcome,
        owner: Option<&PendingAccountNativeAuthority>,
    ) -> Result<Option<JoinHandle<()>>> {
        let (kind, endpoint) = match outcome {
            Outcome::Armed(e) => (0, e),
            Outcome::Paired(e) => (1, e),
            Outcome::Served(e) => (2, e),
        };
        // No late endpoint may become the last LocalIpc destructor on the GUI.
        self.retired.push(endpoint);
        let endpoint = self.retired.last().ok_or(Error::Locked)?;
        let owner = owner.ok_or(Error::Locked)?;
        owner.check_current()?;
        if !self.pending {
            return Err(Error::ReviewMismatch);
        }
        endpoint.check()?;
        if endpoint.0.selected.native != owner.native().binding() {
            return Err(Error::ReviewMismatch);
        }
        match kind {
            0 => {
                if self.endpoint.is_some() {
                    return Err(Error::ReviewMismatch);
                }
                self.endpoint = self.retired.pop();
                self.pending = false;
                Ok(None)
            }
            1 => {
                self.require_same(endpoint)?;
                if self.paired {
                    return Err(Error::ReviewMismatch);
                }
                self.paired = true;
                self.pending = false;
                // Original endpoint remains held in self.endpoint.
                self.retired.pop();
                Ok(None)
            }
            2 => {
                self.require_same(endpoint)?;
                self.pending = false;
                Ok(self.clear())
            }
            _ => Err(Error::ReviewMismatch),
        }
    }
    fn require_same(&self, e: &Endpoint) -> Result<()> {
        if self
            .endpoint
            .as_ref()
            .is_none_or(|own| !Arc::ptr_eq(&own.0, &e.0))
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(super) fn poll(&mut self) -> Result<Option<Input>> {
        let Some(endpoint) = self.endpoint.as_ref() else {
            return Ok(None);
        };
        endpoint.check()?;
        if let Some(peer) = &self.peer {
            endpoint.require_peer(peer)?;
        }
        if self.pending {
            return Ok(None);
        }
        let event = endpoint
            .0
            .ipc
            .try_lock()
            .map_err(|_| Error::Locked)?
            .next_event();
        let input = match event {
            Some(LocalEvent::Pairing(pair)) if !self.paired && self.peer.is_none() => {
                if pair.scope != endpoint.0.expected {
                    return Err(Error::ReviewMismatch);
                }
                Some(Input::Pair(endpoint.clone(), Box::new(pair)))
            }
            Some(LocalEvent::Request {
                peer,
                request: crate::ipc::AppRequest::Status {},
            }) if self.paired => {
                endpoint.require_peer(&peer)?;
                if let Some(previous) = &self.peer {
                    previous.require_same_grant(&peer)?;
                }
                self.peer = Some(peer);
                None
            }
            Some(LocalEvent::NamedVerifierPolicy {
                peer,
                stream,
                request,
            }) if self.paired => {
                endpoint.require_peer(&peer)?;
                self.peer
                    .as_ref()
                    .ok_or(Error::Authentication)?
                    .require_same_grant(&peer)?;
                if request.scope != endpoint.0.selected.scope {
                    return Err(Error::ReviewMismatch);
                }
                Some(Input::Disclose(endpoint.clone(), peer, stream, request))
            }
            None => None,
            _ => return Err(Error::Unavailable),
        };
        self.pending = input.is_some();
        Ok(input)
    }
    pub(super) fn clear(&mut self) -> Option<JoinHandle<()>> {
        self.pending = false;
        self.paired = false;
        self.peer = None;
        if let Some(endpoint) = self.endpoint.take() {
            self.retired.push(endpoint);
        }
        let retired = std::mem::take(&mut self.retired);
        for endpoint in &retired {
            endpoint.close_now();
        }
        if retired.is_empty() {
            None
        } else {
            Some(std::thread::spawn(move || drop(retired)))
        }
    }
}
impl Drop for State {
    fn drop(&mut self) {
        if let Some(e) = &self.endpoint {
            e.close_now();
        }
        for e in &self.retired {
            e.close_now();
        }
    }
}
