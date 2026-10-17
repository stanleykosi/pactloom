//! Narrow length-delimited JSON over maintained TLS 1.3 with mutual certificate
//! validation. No plaintext remote mode, certificate-verification bypass, custom
//! verifier, redirects, proxy credentials, or caller-controlled URL exists.
mod born_offline_clock_v1;
mod born_offline_dispatch_v1;
mod born_offline_owner_continuation_v1;
pub use born_offline_dispatch_v1::AuthenticatedBornOfflineDispatchV1;
mod born_offline_witness_v1;
#[path = "construction_transport_client_v1.rs"]
mod construction_transport_client_v1;
#[path = "construction_transport_server_v1.rs"]
mod construction_transport_server_v1;
#[path = "manual_roster_construction_transport_v2.rs"]
mod manual_roster_construction_transport_v2;
#[path = "manual_roster_construction_transport_v3.rs"]
mod manual_roster_construction_transport_v3;
mod offline_clock_v1;
mod offline_witness_v1;
use crate::{
    protocol::{WireRequest, WireResponse},
    *,
};
pub use born_offline_clock_v1::AuthenticatedBornOfflineClockV1;
pub use construction_transport_client_v1::{
    AuthenticatedConstructionTransportContributionV1,
    AuthenticatedConstructionTransportReservationV1, AuthenticatedConstructionTransportV1,
    ConstructionTransportCancellationV1, ConstructionTransportRevocationV1,
    ObservedConstructionTransportV1, PreparedConstructionTransportHandoffV1,
};
pub use offline_clock_v1::AuthenticatedOfflineClockV1;
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::Arc,
    time::{Duration, Instant},
};

const IO_TIMEOUT: Duration = Duration::from_secs(10);
const ALPN: &[u8] = b"wholepact-authority/2";

pub fn certificate_digest(certificate: &CertificateDer<'_>) -> String {
    hex::encode(Sha256::digest(certificate.as_ref()))
}

pub struct ClientTls {
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    pinned_certificate: String,
    client_certificate: String,
}
impl ClientTls {
    pub fn new(
        server_name: String,
        pinned_server_certificate_digest: String,
        trusted_server_roots: Vec<CertificateDer<'static>>,
        client_chain: Vec<CertificateDer<'static>>,
        client_key: PrivateKeyDer<'static>,
    ) -> Result<Self> {
        hash(&pinned_server_certificate_digest)?;
        let roots = roots(trusted_server_roots)?;
        validate_chain(&client_chain)?;
        let client_certificate = certificate_digest(&client_chain[0]);
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|_| AuthorityError::Authentication)?
                .with_root_certificates(roots)
                .with_client_auth_cert(client_chain, client_key)
                .map_err(|_| AuthorityError::Authentication)?;
        config.alpn_protocols = vec![ALPN.to_vec()];
        config.enable_early_data = false;
        config.resumption = rustls::client::Resumption::disabled();
        let server_name =
            ServerName::try_from(server_name).map_err(|_| AuthorityError::InvalidBinding)?;
        Ok(Self {
            config: Arc::new(config),
            server_name,
            pinned_certificate: pinned_server_certificate_digest,
            client_certificate,
        })
    }
}
#[derive(Clone)]
pub struct ServerTls {
    config: Arc<ServerConfig>,
    certificate_digest: String,
}
impl ServerTls {
    pub fn new(
        trusted_client_roots: Vec<CertificateDer<'static>>,
        server_chain: Vec<CertificateDer<'static>>,
        server_key: PrivateKeyDer<'static>,
    ) -> Result<Self> {
        let roots = Arc::new(roots(trusted_client_roots)?);
        validate_chain(&server_chain)?;
        let certificate_digest = certificate_digest(&server_chain[0]);
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier =
            rustls::server::WebPkiClientVerifier::builder_with_provider(roots, provider.clone())
                .build()
                .map_err(|_| AuthorityError::Authentication)?;
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| AuthorityError::Authentication)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(server_chain, server_key)
            .map_err(|_| AuthorityError::Authentication)?;
        config.alpn_protocols = vec![ALPN.to_vec()];
        config.max_early_data_size = 0;
        config.send_tls13_tickets = 0;
        Ok(Self {
            config: Arc::new(config),
            certificate_digest,
        })
    }
}
fn validate_chain(certs: &[CertificateDer<'_>]) -> Result<()> {
    if certs.is_empty()
        || certs.len() > 8
        || certs.iter().any(|c| c.is_empty() || c.len() > 16 * 1024)
    {
        return Err(AuthorityError::Authentication);
    }
    Ok(())
}
fn roots(certs: Vec<CertificateDer<'static>>) -> Result<RootCertStore> {
    validate_chain(&certs)?;
    let mut store = RootCertStore::empty();
    for cert in certs {
        store
            .add(cert)
            .map_err(|_| AuthorityError::Authentication)?;
    }
    Ok(store)
}

/// A process-local proof of authenticated exact witness response, not a portable
/// bearer token. It has no Deserialize, Clone, Debug or public constructor.
/// Offline portable descriptors require a separately pinned authenticated
/// envelope adapter; raw ReservationPermit JSON is never sufficient.
pub struct AuthenticatedPermit {
    descriptor: ReservationPermit,
    certificate_digest: String,
}
impl AuthenticatedPermit {
    pub fn descriptor(&self) -> &ReservationPermit {
        &self.descriptor
    }
    pub fn matches_request(&self, request: &ReserveAuthorization) -> Result<()> {
        self.descriptor.matches_request(request)
    }
    pub fn authenticated_witness_certificate_digest(&self) -> &str {
        &self.certificate_digest
    }
}

/// Non-cloneable, non-deserializable admission for exactly one automatic key-use
/// intent. A lost response is unknown, not permission to obtain a fresh lease.
pub struct AuthenticatedAutomaticKeyUseAdmission {
    descriptor: AutomaticKeyUseAdmission,
    certificate_digest: String,
}
impl AuthenticatedAutomaticKeyUseAdmission {
    pub fn descriptor(&self) -> &AutomaticKeyUseAdmission {
        &self.descriptor
    }
    pub fn matches_request(&self, request: &AuthorizeAutomaticKeyUse) -> Result<()> {
        self.descriptor.matches_request(request)
    }
    pub fn authenticated_witness_certificate_digest(&self) -> &str {
        &self.certificate_digest
    }
}

/// Exact durable dispatch admission received through pinned, validated mTLS.
/// A later pause cannot recall an already admitted send; callers must still hold
/// their genuine native-use/chain guards and enforce the admission deadline.
pub struct AuthenticatedDispatchAdmission {
    descriptor: DispatchAdmission,
    certificate_digest: String,
}
impl AuthenticatedDispatchAdmission {
    pub fn descriptor(&self) -> &DispatchAdmission {
        &self.descriptor
    }
    pub fn matches_request(&self, request: &AuthorizeDispatch) -> Result<()> {
        self.descriptor.matches_request(request)
    }
    pub fn authenticated_witness_certificate_digest(&self) -> &str {
        &self.certificate_digest
    }
}

/// A fresh authenticated observation that this live client's ephemeral session
/// is owner-activated at the exact fully reconciled head. This is not a lease:
/// later mutations still require current channel MAC, epoch and head checks.
/// It cannot be deserialized, cloned or constructed by callers.
pub struct AuthenticatedWriterSession {
    observed_at_ms: u64,
    observed: std::time::Instant,
    snapshot: AccountSnapshot,
    receipt: WriterSessionReceipt,
    disclosure: WitnessDisclosureDescriptor,
    history_digest: String,
}
impl AuthenticatedWriterSession {
    /// Local observation time preceding the authenticated current-snapshot read.
    /// Retaining this opaque session never refreshes evidence freshness.
    pub fn observed_at_ms(&self) -> u64 {
        self.observed_at_ms
    }
    pub fn observation_age(&self) -> std::time::Duration {
        self.observed.elapsed()
    }
    pub fn snapshot(&self) -> &AccountSnapshot {
        &self.snapshot
    }
    pub fn receipt(&self) -> &WriterSessionReceipt {
        &self.receipt
    }
    pub fn disclosure(&self) -> &WitnessDisclosureDescriptor {
        &self.disclosure
    }
    pub fn history_digest(&self) -> &str {
        &self.history_digest
    }
}

pub struct AuthorityClient {
    endpoint: SocketAddr,
    tls: ClientTls,
    witness: String,
    account: String,
    network: String,
    policy_digest: String,
    session: std::sync::Mutex<Option<ClientWriterSession>>,
}
struct ClientWriterSession {
    request: AcquireWriterRequest,
    key: Zeroizing<[u8; 32]>,
    receipt: Option<WriterSessionReceipt>,
}
impl AuthorityClient {
    pub fn disclosure_descriptor(&self) -> WitnessDisclosureDescriptor {
        WitnessDisclosureDescriptor {
            endpoint: self.endpoint.to_string(),
            server_name: self.tls.server_name.to_str().into_owned(),
            witness_id: self.witness.clone(),
            account_id: self.account.clone(),
            network_profile_id: self.network.clone(),
            policy_digest: self.policy_digest.clone(),
            pinned_server_certificate_digest: self.tls.pinned_certificate.clone(),
        }
    }
    pub fn new(
        endpoint: SocketAddr,
        tls: ClientTls,
        expected_witness_id: String,
        expected_account_id: String,
        expected_network_profile_id: String,
        expected_policy_digest: String,
    ) -> Result<Self> {
        for value in [
            &expected_witness_id,
            &expected_account_id,
            &expected_network_profile_id,
        ] {
            id(value)?;
        }
        hash(&expected_policy_digest)?;
        if endpoint.port() == 0 || endpoint.ip().is_unspecified() || endpoint.ip().is_multicast() {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(Self {
            endpoint,
            tls,
            witness: expected_witness_id,
            account: expected_account_id,
            network: expected_network_profile_id,
            policy_digest: expected_policy_digest,
            session: std::sync::Mutex::new(None),
        })
    }
    /// Requests an independent live witness node check. No observation, approval
    /// Boolean or signer-supplied canonical evidence is accepted on the wire.
    pub fn resolve_reservation(
        &self,
        reservation_operation_id: &str,
    ) -> Result<AuthenticatedResolutionReceipt> {
        self.resolve_reservation_selected(reservation_operation_id, None)
    }
    /// The candidate is an untrusted lookup selector. The witness checks its
    /// immutable original dispatch and independently reads its enrolled node.
    pub fn resolve_reservation_conflict(
        &self,
        reservation_operation_id: &str,
        conflict: &wholepact_chain::local_node::CanonicalConflictCandidate,
    ) -> Result<AuthenticatedResolutionReceipt> {
        conflict
            .validate_shape()
            .map_err(|_| AuthorityError::InvalidBinding)?;
        self.resolve_reservation_selected(reservation_operation_id, Some(conflict))
    }
    fn resolve_reservation_selected(
        &self,
        reservation_operation_id: &str,
        conflict: Option<&wholepact_chain::local_node::CanonicalConflictCandidate>,
    ) -> Result<AuthenticatedResolutionReceipt> {
        id(reservation_operation_id)?;
        let started = Instant::now();
        let response = self.call(&WireRequest::ResolveReservation {
            account_id: self.account.clone(),
            network_profile_id: self.network.clone(),
            reservation_operation_id: reservation_operation_id.into(),
            conflict: conflict.cloned(),
        })?;
        let WireResponse::Resolution(receipt) = response else {
            return Err(AuthorityError::InvalidBinding);
        };
        if receipt.record.account_id != self.account
            || receipt.record.network_profile_id != self.network
            || receipt.record.reservation_operation_id != reservation_operation_id
            || receipt.record.conflict.as_ref() != conflict
        {
            return Err(AuthorityError::InvalidBinding);
        }
        let result = AuthenticatedResolutionReceipt {
            receipt: *receipt,
            certificate: self.tls.pinned_certificate.clone(),
            deadline: started + Duration::from_secs(30),
        };
        result.check_current()?;
        Ok(result)
    }
    pub fn snapshot(&self) -> Result<AccountSnapshot> {
        match self.call(&WireRequest::Snapshot {
            account_id: self.account.clone(),
            network_profile_id: self.network.clone(),
        })? {
            WireResponse::Snapshot(s) => {
                self.check_snapshot(&s)?;
                Ok(s)
            }
            _ => Err(AuthorityError::InvalidBinding),
        }
    }
    /// Read-only snapshot under the caller's original absolute deadline. The
    /// existing per-call ten-second ceiling can only shorten that budget. Late
    /// transport or synchronous validation work cannot return a usable snapshot.
    pub fn snapshot_until(&self, deadline: Instant) -> Result<AccountSnapshot> {
        let deadline = bounded_transport_deadline_at(Instant::now(), deadline)?;
        let response = self.call_until(
            &WireRequest::Snapshot {
                account_id: self.account.clone(),
                network_profile_id: self.network.clone(),
            },
            deadline,
        )?;
        let WireResponse::Snapshot(snapshot) = response else {
            return Err(AuthorityError::InvalidBinding);
        };
        self.check_snapshot(&snapshot)?;
        require_before_caller_deadline(deadline)?;
        Ok(snapshot)
    }
    /// Reads every bounded page at one immutable head, verifies the complete
    /// append chain and accounting, and returns retained exact original permits.
    /// A changing head aborts; a summary or saved local cursor cannot substitute.
    pub fn reconcile_history(&self) -> Result<ReconciledAuthorityHistory> {
        self.reconcile_history_inner(&mut || Ok(()), false, None)
    }
    /// Complete authenticated history with caller-owned cancellation checks.
    /// This is a read-only admission hook, never an authority/verified factory.
    /// Bounds reject oversized histories rather than returning a partial fold.
    pub fn reconcile_history_checked(
        &self,
        mut check_current: impl FnMut() -> Result<()>,
    ) -> Result<ReconciledAuthorityHistory> {
        self.reconcile_history_inner(&mut check_current, true, None)
    }
    /// Complete bounded read-only replay, with all pages and validation sharing
    /// one caller-owned absolute deadline. No page renews the caller's budget.
    pub fn reconcile_history_checked_until(
        &self,
        deadline: Instant,
        mut check_current: impl FnMut() -> Result<()>,
    ) -> Result<ReconciledAuthorityHistory> {
        require_before_caller_deadline(deadline)?;
        self.reconcile_history_inner(&mut check_current, true, Some(deadline))
    }
    fn reconcile_history_inner(
        &self,
        check_current: &mut dyn FnMut() -> Result<()>,
        bounded: bool,
        caller_deadline: Option<Instant>,
    ) -> Result<ReconciledAuthorityHistory> {
        let started = std::time::Instant::now();
        let check = |check_current: &mut dyn FnMut() -> Result<()>| -> Result<()> {
            if let Some(deadline) = caller_deadline {
                require_before_caller_deadline(deadline)?;
            }
            check_current()?;
            if let Some(deadline) = caller_deadline {
                require_before_caller_deadline(deadline)?;
            }
            if bounded && started.elapsed() >= std::time::Duration::from_secs(120) {
                return Err(AuthorityError::Permission);
            }
            Ok(())
        };
        check(check_current)?;
        let snapshot = match caller_deadline {
            Some(deadline) => self.snapshot_until(deadline)?,
            None => self.snapshot()?,
        };
        check(check_current)?;
        if bounded && snapshot.head.sequence > 65_536 {
            return Err(AuthorityError::Permission);
        }
        let mut pages = 0usize;
        let mut entries = 0usize;
        let mut bytes = 0usize;
        let mut ledger: Option<crate::policy::Ledger> = None;
        let mut pending_birth_commit = None;
        let mut permits = Vec::new();
        let mut offline_permits = Vec::new();
        let mut born_offline_permits = Vec::new();
        let mut born_offline_dispatches = Vec::new();
        let mut automatic_key_use_admissions = Vec::new();
        let mut recovery_fences = Vec::new();
        let mut committed_operation_ids = std::collections::BTreeSet::new();
        let mut owner_controls = std::collections::BTreeMap::new();
        let mut history_heads =
            std::collections::BTreeMap::from([(0, snapshot.policy_digest.clone())]);
        let mut after = 0;
        loop {
            check(check_current)?;
            if bounded && pages >= 4_096 {
                return Err(AuthorityError::Permission);
            }
            let request = WireRequest::ReadHistory {
                account_id: self.account.clone(),
                network_profile_id: self.network.clone(),
                expected_head: snapshot.head.clone(),
                after_sequence: after,
                maximum_entries: 16,
            };
            let response = match caller_deadline {
                Some(deadline) => self.call_until(&request, deadline)?,
                None => self.call(&request)?,
            };
            let WireResponse::History(page) = response else {
                return Err(AuthorityError::InvalidBinding);
            };
            let page = *page;
            check(check_current)?;
            if bounded {
                pages = pages.checked_add(1).ok_or(AuthorityError::Permission)?;
                entries = entries
                    .checked_add(page.entries.len())
                    .ok_or(AuthorityError::Permission)?;
                bytes = bytes
                    .checked_add(
                        serde_json::to_vec(&page)
                            .map_err(|_| AuthorityError::InvalidBinding)?
                            .len(),
                    )
                    .ok_or(AuthorityError::Permission)?;
                if entries > 65_536 || bytes > 32 * 1024 * 1024 {
                    return Err(AuthorityError::Permission);
                }
            }
            if page.snapshot != snapshot || page.policy.policy_digest()? != self.policy_digest {
                return Err(AuthorityError::Authentication);
            }
            if ledger.is_none() {
                if let Some(record) = &page.pending_birth_commit {
                    record.validate()?;
                    if record.request.policy != page.policy
                        || record.request.disclosure != self.disclosure_descriptor()
                    {
                        return Err(AuthorityError::Authentication);
                    }
                }
                // Positive genesis without original authenticated metadata is
                // not a complete birth provenance history.
                if page.policy.account_use_genesis.is_some() != page.pending_birth_commit.is_some()
                {
                    return Err(AuthorityError::CorruptHistory);
                }
                pending_birth_commit = page.pending_birth_commit.clone();
                ledger = Some(crate::policy::Ledger::new(page.policy.clone())?);
            }
            let state = ledger.as_mut().ok_or(AuthorityError::CorruptHistory)?;
            if page.policy != state.policy || page.pending_birth_commit != pending_birth_commit {
                return Err(AuthorityError::Authentication);
            }
            let before = after;
            for entry in page.entries {
                if entry.sequence != state.snapshot.head.sequence + 1
                    || entry.previous_head != state.snapshot.head.digest
                {
                    return Err(AuthorityError::CorruptHistory);
                }
                let event = crate::policy::Event {
                    original_request_link: entry.original_request_link,
                    mutation: entry.mutation,
                    authenticated_certificate_digest: entry.authenticated_certificate_digest,
                    witness_time_ms: entry.witness_time_ms,
                    writer_session_id: entry.writer_session_id,
                };
                let previous = state.snapshot.clone();
                match state.apply(&event)? {
                    MutationResult::Reserved(permit) => permits.push(*permit),
                    MutationResult::OfflineReserved(permit) => offline_permits.push(*permit),
                    MutationResult::BornOfflineDispatchAdmittedV1(admission) => {
                        born_offline_dispatches.push(*admission)
                    }
                    MutationResult::BornOfflineReservedV1(permit) => {
                        born_offline_permits.push(*permit)
                    }
                    MutationResult::AutomaticKeyUseAdmitted(admission) => {
                        automatic_key_use_admissions.push(*admission)
                    }
                    _ => {}
                }
                committed_operation_ids.insert(event.mutation.operation_id().to_owned());
                if let AuthorityMutation::OwnerControl(request) = &event.mutation {
                    owner_controls.insert(request.operation_id.clone(), request.clone());
                }
                if let Some(receipt) =
                    crate::recovery::recovery_receipt(&previous, &event.mutation, &state.snapshot)
                {
                    recovery_fences.push(receipt);
                }
                if state.snapshot.head.digest != entry.head {
                    return Err(AuthorityError::CorruptHistory);
                }
                history_heads.insert(entry.sequence, entry.head.clone());
                after = entry.sequence;
            }
            if after == before && after < snapshot.head.sequence {
                return Err(AuthorityError::CorruptHistory);
            }
            match page.next_after_sequence {
                Some(next) if next == after && next < snapshot.head.sequence => continue,
                None if after == snapshot.head.sequence => break,
                _ => return Err(AuthorityError::CorruptHistory),
            }
        }
        let ledger = ledger.ok_or(AuthorityError::CorruptHistory)?;
        ledger.validate_manual_birth(pending_birth_commit.as_ref())?;
        ledger.validate_born_offline_birth_v1(pending_birth_commit.as_ref())?;
        let manual_roster_attempt = if ledger.manual_roster_extension()?.is_some() {
            Some(ledger.latest_manual_roster_attempt_v2()?)
        } else {
            None
        };
        let manual_attempt =
            if manual_roster_attempt.is_none() && ledger.manual_extension()?.is_some() {
                Some(ledger.latest_manual_attempt()?)
            } else {
                None
            };
        let manual_roster_construction_records = ledger.roster_construction_history_v2();
        let manual_roster_construction_records_v3 = ledger.roster_construction_history_v3();
        let construction_transport_history = ledger.construction_transport_history_v1();
        let account_use_history = ledger.account_use_history;
        let account_policy = ledger.policy;
        let mut computed = ledger.snapshot;
        // A restored database's independent one-way quarantine is not an event
        // that rewrites its historical hash chain. It never enables acquisition.
        if snapshot.writer_status == WriterStatus::Quarantined {
            computed.writer_status = WriterStatus::Quarantined;
        }
        if computed != snapshot {
            return Err(AuthorityError::CorruptHistory);
        }
        check(check_current)?;
        Ok(ReconciledAuthorityHistory {
            construction_transport_history,
            manual_roster_construction_records,
            manual_roster_construction_records_v3,
            manual_roster_attempt,
            manual_attempt,
            pending_birth_commit,
            account_use_history,
            account_policy,
            snapshot,
            permits,
            offline_permits,
            born_offline_permits,
            born_offline_dispatches,
            automatic_key_use_admissions,
            recovery_fences,
            committed_operation_ids,
            owner_controls,
            history_heads,
            disclosure: self.disclosure_descriptor(),
        })
    }
    /// Starts a pending session using complete verified history. The owner must
    /// separately activate its exact ID. A lost response retains the ephemeral
    /// key in this client so the same operation can be retried without takeover.
    pub fn acquire_writer(
        &self,
        history: &ReconciledAuthorityHistory,
        operation_id: &str,
    ) -> Result<WriterSessionReceipt> {
        id(operation_id)?;
        if history.disclosure != self.disclosure_descriptor()
            || history.snapshot.writer_certificate_digest != self.tls.client_certificate
        {
            return Err(AuthorityError::Permission);
        }
        if history.snapshot.writer_status == WriterStatus::Quarantined {
            return Err(AuthorityError::RecoveryRequired);
        }
        let mut state = self
            .session
            .lock()
            .map_err(|_| AuthorityError::SessionRequired)?;
        if let Some(session) = state.as_ref() {
            if session.request.operation_id != operation_id
                || session.request.expected_head != history.snapshot.head
            {
                return Err(AuthorityError::Conflict);
            }
        }
        let response = self.call_with(|exporter| {
            let retry = state.is_some();
            if state.is_none() {
                *state = Some(ClientWriterSession {
                    request: AcquireWriterRequest {
                        operation_id: operation_id.into(),
                        account_id: self.account.clone(),
                        network_profile_id: self.network.clone(),
                        writer_epoch: history.snapshot.writer_epoch,
                        expected_head: history.snapshot.head.clone(),
                        reconciled_history_digest: history.history_digest()?,
                        session_id: crate::session::session_id(exporter),
                        disclosure: self.disclosure_descriptor(),
                    },
                    key: Zeroizing::new(*exporter),
                    receipt: None,
                });
            }
            let session = state.as_ref().ok_or(AuthorityError::SessionRequired)?;
            let mutation = AuthorityMutation::AcquireWriter(session.request.clone());
            let proof = if retry {
                Some(crate::session::proof(
                    &session.key,
                    (
                        &session.request.session_id,
                        &session.request.disclosure,
                        session.request.writer_epoch,
                    ),
                    exporter,
                    &mutation,
                )?)
            } else {
                None
            };
            Ok(WireRequest::Mutate {
                mutation: Box::new(mutation),
                session_proof: proof,
            })
        })?;
        let WireResponse::Mutation(MutationResult::WriterPending(receipt)) = response else {
            return Err(AuthorityError::InvalidBinding);
        };
        let session = state.as_mut().ok_or(AuthorityError::SessionRequired)?;
        if receipt.session_id != session.request.session_id
            || receipt.writer_certificate_digest != self.tls.client_certificate
            || receipt.writer_epoch != session.request.writer_epoch
            || receipt.reconciled_head != session.request.expected_head
            || receipt.reconciled_history_digest != session.request.reconciled_history_digest
            || receipt.disclosure != session.request.disclosure
            || receipt.expires_at_ms <= receipt.acquired_at_ms
        {
            return Err(AuthorityError::Authentication);
        }
        self.check_committed_head(
            &session.request.expected_head,
            &receipt.acquired_head,
            AuthorityMutation::AcquireWriter(session.request.clone()),
            receipt.acquired_at_ms,
            None,
        )?;
        session.receipt = Some(receipt.clone());
        Ok(receipt)
    }
    /// Verifies a current owner-activated session against complete authenticated
    /// history. Calling this does not authorize future reservations or release.
    pub fn verify_active_session(
        &self,
        history: &ReconciledAuthorityHistory,
    ) -> Result<AuthenticatedWriterSession> {
        if history.disclosure != self.disclosure_descriptor() {
            return Err(AuthorityError::Authentication);
        }
        let state = self
            .session
            .lock()
            .map_err(|_| AuthorityError::SessionRequired)?;
        let session = state.as_ref().ok_or(AuthorityError::SessionRequired)?;
        let receipt = session
            .receipt
            .as_ref()
            .ok_or(AuthorityError::SessionRequired)?;
        if crate::session::session_id(&session.key) != receipt.session_id {
            return Err(AuthorityError::Authentication);
        }
        let observed = std::time::Instant::now();
        let observed_at_ms = now_ms()?;
        let snapshot = self.snapshot()?;
        snapshot.require_unfenced_transport(&receipt.session_id)?;
        if snapshot != history.snapshot {
            return Err(AuthorityError::StaleHead);
        }
        if snapshot
            .account_use_checkpoint
            .as_ref()
            .is_some_and(|c| c.permanent_exclusion_digest.is_some())
        {
            return Err(AuthorityError::PolicyDenied);
        }
        if snapshot.writer_status != WriterStatus::Active
            || snapshot.active_writer_session.as_ref() != Some(receipt)
            || receipt.writer_certificate_digest != self.tls.client_certificate
            || receipt.writer_epoch != snapshot.writer_epoch
            || now_ms()? >= receipt.expires_at_ms
        {
            return Err(AuthorityError::SessionRequired);
        }
        Ok(AuthenticatedWriterSession {
            observed,
            observed_at_ms,
            snapshot,
            receipt: receipt.clone(),
            disclosure: self.disclosure_descriptor(),
            history_digest: history.history_digest()?,
        })
    }
    /// One exact finite local enrollment publication. This requires the scoped
    /// namespace server; an audit-only server and raw snapshots cannot issue it.
    /// Retain the identical request across uncertainty. No head/ID auto-retry.
    pub fn admit_born_manual_enrollment(
        &self,
        history: &ReconciledAuthorityHistory,
        extension: &crate::manual_enrollment::ManualEnrollmentExtension,
        request: &crate::manual_enrollment::BornManualEnrollmentAdmissionRequest,
    ) -> Result<crate::manual_enrollment::AuthenticatedBornManualEnrollment> {
        history.require_legacy_online_only()?;
        history
            .account_use_history
            .require_not_permanently_excluded()?;
        extension.validate_original_birth(
            history
                .pending_birth_commit()
                .ok_or(AuthorityError::PolicyDenied)?,
        )?;
        request.validate_for(extension)?;
        if history
            .manual_roster_enrollment_extension(&extension.enrollment_ref)?
            .is_some()
        {
            return Err(AuthorityError::Permission);
        }
        if history.disclosure != self.disclosure_descriptor()
            || history.manual_enrollment_extension(&extension.enrollment_ref)? != Some(extension)
            || !history.contains_head(&request.expected_head)
            || history.snapshot.writer_status != WriterStatus::Active
            || history.snapshot.writer_epoch != request.writer_epoch
            || history.snapshot.writer_certificate_digest != self.tls.client_certificate
        {
            return Err(AuthorityError::Authentication);
        }
        let state = self
            .session
            .lock()
            .map_err(|_| AuthorityError::SessionRequired)?;
        let session = state.as_ref().ok_or(AuthorityError::SessionRequired)?;
        let receipt = session
            .receipt
            .as_ref()
            .ok_or(AuthorityError::SessionRequired)?;
        if receipt.session_id != request.session_id
            || history.snapshot.active_writer_session.as_ref() != Some(receipt)
            || crate::session::session_id(&session.key) != request.session_id
            || now_ms()? >= receipt.expires_at_ms
        {
            return Err(AuthorityError::SessionRequired);
        }
        let observed = std::time::Instant::now();
        let observed_at_ms = now_ms()?;
        let mutation = AuthorityMutation::AdmitBornManualEnrollment(request.clone());
        let response = self.call_with(|exporter| {
            Ok(WireRequest::Mutate {
                session_proof: Some(crate::session::proof(
                    &session.key,
                    (
                        &session.request.session_id,
                        &session.request.disclosure,
                        session.request.writer_epoch,
                    ),
                    exporter,
                    &mutation,
                )?),
                mutation: Box::new(mutation),
            })
        })?;
        let WireResponse::Mutation(MutationResult::ManualEnrollmentAdmitted(record)) = response
        else {
            return Err(AuthorityError::InvalidBinding);
        };
        record.validate_for(extension)?;
        if record.request != *request || record.session != *receipt {
            return Err(AuthorityError::Authentication);
        }
        self.check_snapshot(&record.snapshot)?;
        let mut unchanged_account = history.snapshot.clone();
        unchanged_account.head = record.snapshot.head.clone();
        unchanged_account.last_witness_time_ms = record.admitted_at_ms;
        if record.snapshot != unchanged_account {
            return Err(AuthorityError::Authentication);
        }
        self.check_committed_head(
            &request.expected_head,
            &record.snapshot.head,
            AuthorityMutation::AdmitBornManualEnrollment(request.clone()),
            record.admitted_at_ms,
            Some(request.session_id.clone()),
        )?;
        // Current TLS response plus original session MAC, exact committed event,
        // immutable first deadline and monotonic local elapsed time. Never a
        // claim that a remote GUI remains focused after the operation completed.
        let admitted = crate::manual_enrollment::AuthenticatedBornManualEnrollment {
            extension: extension.clone(),
            record: *record,
            observed_at_ms,
            observed,
        };
        admitted.check_current()?;
        Ok(admitted)
    }
    pub fn admit_born_manual_enrollment_v2(
        &self,
        history: &ReconciledAuthorityHistory,
        extension: &crate::manual_enrollment::ManualEnrollmentExtension,
        continuation: &crate::manual_session_continuation::ManualEnrollmentSessionContinuation,
        request: &crate::manual_session_continuation::BornManualEnrollmentAdmissionRequestV2,
    ) -> Result<crate::manual_session_continuation::AuthenticatedBornManualEnrollmentV2> {
        history.require_legacy_online_only()?;
        history
            .account_use_history
            .require_not_permanently_excluded()?;
        extension.validate_original_birth(
            history
                .pending_birth_commit()
                .ok_or(AuthorityError::PolicyDenied)?,
        )?;
        request.validate_for(extension, continuation)?;
        if history
            .manual_roster_enrollment_extension(&extension.enrollment_ref)?
            .is_some()
        {
            return Err(AuthorityError::Permission);
        }
        let attempt = history.latest_manual_attempt(&extension.enrollment_ref)?;
        if attempt.continuation.as_ref() != Some(continuation)
            || attempt.attempt_digest != request.attempt_digest
        {
            return Err(AuthorityError::StaleHead);
        }
        if history.disclosure != self.disclosure_descriptor()
            || history.manual_enrollment_extension(&extension.enrollment_ref)? != Some(extension)
            || !history.contains_head(&request.expected_head)
            || history.snapshot.writer_status != WriterStatus::Active
            || history.snapshot.writer_epoch != request.writer_epoch
            || history.snapshot.writer_certificate_digest != self.tls.client_certificate
        {
            return Err(AuthorityError::Authentication);
        }
        let state = self
            .session
            .lock()
            .map_err(|_| AuthorityError::SessionRequired)?;
        let session = state.as_ref().ok_or(AuthorityError::SessionRequired)?;
        let receipt = session
            .receipt
            .as_ref()
            .ok_or(AuthorityError::SessionRequired)?;
        if receipt.session_id != request.session_id
            || history.snapshot.active_writer_session.as_ref() != Some(receipt)
            || crate::session::session_id(&session.key) != request.session_id
            || now_ms()? >= receipt.expires_at_ms
        {
            return Err(AuthorityError::SessionRequired);
        }
        let observed = std::time::Instant::now();
        let observed_at_ms = now_ms()?;
        let mutation = AuthorityMutation::AdmitBornManualEnrollmentV2(request.clone());
        let response = self.call_with(|exporter| {
            Ok(WireRequest::Mutate {
                session_proof: Some(crate::session::proof(
                    &session.key,
                    (
                        &session.request.session_id,
                        &session.request.disclosure,
                        session.request.writer_epoch,
                    ),
                    exporter,
                    &mutation,
                )?),
                mutation: Box::new(mutation),
            })
        })?;
        let WireResponse::Mutation(MutationResult::ManualEnrollmentAdmittedV2(record)) = response
        else {
            return Err(AuthorityError::InvalidBinding);
        };
        record.validate_for(extension, continuation)?;
        if record.request != *request || record.session != *receipt {
            return Err(AuthorityError::Authentication);
        }
        self.check_snapshot(&record.snapshot)?;
        let mut unchanged_account = history.snapshot.clone();
        unchanged_account.head = record.snapshot.head.clone();
        unchanged_account.last_witness_time_ms = record.admitted_at_ms;
        if record.snapshot != unchanged_account {
            return Err(AuthorityError::Authentication);
        }
        self.check_committed_head(
            &request.expected_head,
            &record.snapshot.head,
            AuthorityMutation::AdmitBornManualEnrollmentV2(request.clone()),
            record.admitted_at_ms,
            Some(request.session_id.clone()),
        )?;
        // Current TLS response plus original session MAC, exact committed event,
        // immutable first deadline and monotonic local elapsed time. Never a
        // claim that a remote GUI remains focused after the operation completed.
        let admitted = crate::manual_session_continuation::AuthenticatedBornManualEnrollmentV2 {
            extension: extension.clone(),
            continuation: continuation.clone(),
            record: *record,
            observed_at_ms,
            observed,
        };
        admitted.check_current()?;
        Ok(admitted)
    }
    pub fn admit_born_manual_roster_enrollment_v2(
        &self,
        history: &ReconciledAuthorityHistory,
        extension: &crate::manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2,
        continuation: Option<&crate::manual_roster_witness_v2::ManualRosterSessionContinuationV2>,
        request: &crate::manual_roster_witness_v2::BornManualRosterAdmissionRequestV2,
    ) -> Result<crate::manual_roster_witness_v2::AuthenticatedBornManualRosterEnrollmentV2> {
        history.require_original_roster_preconstruction_history()?;
        history
            .account_use_history
            .require_not_permanently_excluded()?;
        extension.validate_original_birth(
            history
                .pending_birth_commit()
                .ok_or(AuthorityError::PolicyDenied)?,
        )?;
        request.validate_for(extension, continuation)?;
        let attempt =
            history.latest_manual_roster_attempt_v2(&extension.account_extension.enrollment_ref)?;
        if attempt.continuation.as_ref() != continuation
            || attempt.attempt_digest != request.attempt_digest
        {
            return Err(AuthorityError::StaleHead);
        }
        if history.disclosure != self.disclosure_descriptor()
            || history
                .manual_roster_enrollment_extension(&extension.account_extension.enrollment_ref)?
                != Some(extension)
            || !history.contains_head(&request.expected_head)
            || history.snapshot.writer_status != WriterStatus::Active
            || history.snapshot.writer_epoch != request.writer_epoch
            || history.snapshot.writer_certificate_digest != self.tls.client_certificate
        {
            return Err(AuthorityError::Authentication);
        }
        let state = self
            .session
            .lock()
            .map_err(|_| AuthorityError::SessionRequired)?;
        let session = state.as_ref().ok_or(AuthorityError::SessionRequired)?;
        let receipt = session
            .receipt
            .as_ref()
            .ok_or(AuthorityError::SessionRequired)?;
        if receipt.session_id != request.session_id
            || history.snapshot.active_writer_session.as_ref() != Some(receipt)
            || crate::session::session_id(&session.key) != request.session_id
            || now_ms()? >= receipt.expires_at_ms
        {
            return Err(AuthorityError::SessionRequired);
        }
        let observed = std::time::Instant::now();
        let observed_at_ms = now_ms()?;
        let mutation = AuthorityMutation::AdmitBornManualRosterEnrollmentV2(request.clone());
        let response = self.call_with(|exporter| {
            Ok(WireRequest::Mutate {
                session_proof: Some(crate::session::proof(
                    &session.key,
                    (
                        &session.request.session_id,
                        &session.request.disclosure,
                        session.request.writer_epoch,
                    ),
                    exporter,
                    &mutation,
                )?),
                mutation: Box::new(mutation),
            })
        })?;
        let WireResponse::Mutation(MutationResult::ManualRosterEnrollmentAdmittedV2(record)) =
            response
        else {
            return Err(AuthorityError::InvalidBinding);
        };
        record.validate_for(extension, continuation)?;
        if record.request != *request || record.session != *receipt {
            return Err(AuthorityError::Authentication);
        }
        self.check_snapshot(&record.snapshot)?;
        let mut unchanged_account = history.snapshot.clone();
        unchanged_account.head = record.snapshot.head.clone();
        unchanged_account.last_witness_time_ms = record.admitted_at_ms;
        if record.snapshot != unchanged_account {
            return Err(AuthorityError::Authentication);
        }
        self.check_committed_head(
            &request.expected_head,
            &record.snapshot.head,
            AuthorityMutation::AdmitBornManualRosterEnrollmentV2(request.clone()),
            record.admitted_at_ms,
            Some(request.session_id.clone()),
        )?;
        // Current TLS response plus original session MAC, exact committed event,
        // immutable first deadline and monotonic local elapsed time. Never a
        // claim that a remote GUI remains focused after the operation completed.
        let admitted = crate::manual_roster_witness_v2::AuthenticatedBornManualRosterEnrollmentV2 {
            extension: extension.clone(),
            continuation: continuation.cloned(),
            record: *record,
            observed_at_ms,
            observed,
        };
        admitted.check_current()?;
        Ok(admitted)
    }
    /// Discards only this process's ephemeral access. Does not revoke exposure or
    /// authorize replacement; the witness still requires an explicit owner action.
    pub fn forget_writer_session(&self) -> Result<()> {
        *self
            .session
            .lock()
            .map_err(|_| AuthorityError::SessionRequired)? = None;
        Ok(())
    }
    pub fn report_progress(&self, request: ReportProgress) -> Result<AccountSnapshot> {
        if request.account_id != self.account || request.network_profile_id != self.network {
            return Err(AuthorityError::InvalidBinding);
        }
        let state = self
            .session
            .lock()
            .map_err(|_| AuthorityError::SessionRequired)?;
        let session = state
            .as_ref()
            .filter(|s| s.receipt.is_some())
            .ok_or(AuthorityError::SessionRequired)?;
        let mutation = AuthorityMutation::ReportProgress(request.clone());
        let response = self.call_with(|exporter| {
            Ok(WireRequest::Mutate {
                session_proof: Some(crate::session::proof(
                    &session.key,
                    (
                        &session.request.session_id,
                        &session.request.disclosure,
                        session.request.writer_epoch,
                    ),
                    exporter,
                    &mutation,
                )?),
                mutation: Box::new(mutation),
            })
        })?;
        let WireResponse::Mutation(MutationResult::ProgressRecorded(snapshot)) = response else {
            return Err(AuthorityError::InvalidBinding);
        };
        self.check_snapshot(&snapshot)?;
        self.check_committed_head(
            &request.expected_head,
            &snapshot.head,
            AuthorityMutation::ReportProgress(request.clone()),
            snapshot.last_witness_time_ms,
            Some(session.request.session_id.clone()),
        )?;
        Ok(snapshot)
    }
    /// No automatic new operation or new-head retry. On Uncertain retry this
    /// identical request, preserving the operation ID and every binding.
    pub fn reserve(&self, request: ReserveAuthorization) -> Result<AuthenticatedPermit> {
        request.validate()?;
        if request.account_id != self.account || request.network_profile_id != self.network {
            return Err(AuthorityError::InvalidBinding);
        }
        let session = self
            .session
            .lock()
            .map_err(|_| AuthorityError::SessionRequired)?;
        let session = session
            .as_ref()
            .filter(|s| s.receipt.is_some())
            .ok_or(AuthorityError::SessionRequired)?;
        let mutation = AuthorityMutation::ReserveAuthorization(Box::new(request.clone()));
        let response = self.call_with(|exporter| {
            Ok(WireRequest::Mutate {
                session_proof: Some(crate::session::proof(
                    &session.key,
                    (
                        &session.request.session_id,
                        &session.request.disclosure,
                        session.request.writer_epoch,
                    ),
                    exporter,
                    &mutation,
                )?),
                mutation: Box::new(mutation),
            })
        })?;
        match response {
            WireResponse::Mutation(MutationResult::Reserved(p)) => {
                p.matches_request(&request)?;
                if p.witness_id != self.witness || p.policy_digest != self.policy_digest {
                    return Err(AuthorityError::Authentication);
                }
                self.check_committed_head(
                    &request.expected_head,
                    &p.committed_head,
                    AuthorityMutation::ReserveAuthorization(Box::new(request.clone())),
                    p.reserved_at_ms,
                    Some(p.writer_session_id.clone()),
                )?;
                Ok(AuthenticatedPermit {
                    descriptor: *p,
                    certificate_digest: self.tls.pinned_certificate.clone(),
                })
            }
            _ => Err(AuthorityError::InvalidBinding),
        }
    }
    /// Commits an exact dispatch intent for already-signed retained bytes. This
    /// never clears exposure or treats a provider report as chain qualification.
    /// Uncertain responses must retry this identical operation and payload.
    pub fn authorize_dispatch(
        &self,
        request: AuthorizeDispatch,
    ) -> Result<AuthenticatedDispatchAdmission> {
        request.validate()?;
        if request.account_id != self.account || request.network_profile_id != self.network {
            return Err(AuthorityError::InvalidBinding);
        }
        let state = self
            .session
            .lock()
            .map_err(|_| AuthorityError::SessionRequired)?;
        let session = state
            .as_ref()
            .filter(|s| s.receipt.is_some())
            .ok_or(AuthorityError::SessionRequired)?;
        let mutation = AuthorityMutation::AuthorizeDispatch(request.clone());
        let response = self.call_with(|exporter| {
            Ok(WireRequest::Mutate {
                session_proof: Some(crate::session::proof(
                    &session.key,
                    (
                        &session.request.session_id,
                        &session.request.disclosure,
                        session.request.writer_epoch,
                    ),
                    exporter,
                    &mutation,
                )?),
                mutation: Box::new(mutation),
            })
        })?;
        let WireResponse::Mutation(MutationResult::DispatchAdmitted(admission)) = response else {
            return Err(AuthorityError::InvalidBinding);
        };
        admission.matches_request(&request)?;
        if admission.witness_id != self.witness || admission.policy_digest != self.policy_digest {
            return Err(AuthorityError::Authentication);
        }
        self.check_committed_head(
            &request.expected_head,
            &admission.committed_head,
            AuthorityMutation::AuthorizeDispatch(request.clone()),
            admission.admitted_at_ms,
            Some(admission.writer_session_id.clone()),
        )?;
        Ok(AuthenticatedDispatchAdmission {
            descriptor: *admission,
            certificate_digest: self.tls.pinned_certificate.clone(),
        })
    }
    /// Commits a single exact automatic key-use intent against the current grant.
    /// Retry after any committed response returns Uncertain, never a new capability.
    pub fn authorize_automatic_key_use(
        &self,
        request: AuthorizeAutomaticKeyUse,
    ) -> Result<AuthenticatedAutomaticKeyUseAdmission> {
        request.validate()?;
        if request.account_id != self.account || request.network_profile_id != self.network {
            return Err(AuthorityError::InvalidBinding);
        }
        let state = self
            .session
            .lock()
            .map_err(|_| AuthorityError::SessionRequired)?;
        let session = state
            .as_ref()
            .filter(|s| s.receipt.is_some())
            .ok_or(AuthorityError::SessionRequired)?;
        let mutation = AuthorityMutation::AuthorizeAutomaticKeyUse(request.clone());
        let response = self.call_with(|exporter| {
            Ok(WireRequest::Mutate {
                session_proof: Some(crate::session::proof(
                    &session.key,
                    (
                        &session.request.session_id,
                        &session.request.disclosure,
                        session.request.writer_epoch,
                    ),
                    exporter,
                    &mutation,
                )?),
                mutation: Box::new(mutation),
            })
        })?;
        let WireResponse::Mutation(MutationResult::AutomaticKeyUseAdmitted(admission)) = response
        else {
            return Err(AuthorityError::InvalidBinding);
        };
        admission.matches_request(&request)?;
        if admission.witness_id != self.witness || admission.policy_digest != self.policy_digest {
            return Err(AuthorityError::Authentication);
        }
        self.check_committed_head(
            &request.expected_head,
            &admission.committed_head,
            AuthorityMutation::AuthorizeAutomaticKeyUse(request.clone()),
            admission.admitted_at_ms,
            Some(admission.writer_session_id.clone()),
        )?;
        Ok(AuthenticatedAutomaticKeyUseAdmission {
            descriptor: *admission,
            certificate_digest: self.tls.pinned_certificate.clone(),
        })
    }
    pub fn control(&self, request: OwnerControlRequest) -> Result<AccountSnapshot> {
        if request.account_id != self.account || request.network_profile_id != self.network {
            return Err(AuthorityError::InvalidBinding);
        }
        match self.call(&WireRequest::Mutate {
            mutation: Box::new(AuthorityMutation::OwnerControl(request.clone())),
            session_proof: None,
        })? {
            WireResponse::Mutation(MutationResult::Controlled(s)) => {
                self.check_snapshot(&s)?;
                self.check_committed_head(
                    &request.expected_head,
                    &s.head,
                    AuthorityMutation::OwnerControl(request.clone()),
                    s.last_witness_time_ms,
                    None,
                )?;
                Ok(s)
            }
            _ => Err(AuthorityError::InvalidBinding),
        }
    }
    fn check_committed_head(
        &self,
        previous: &AuthorityHead,
        committed: &AuthorityHead,
        mutation: AuthorityMutation,
        time: u64,
        writer_session_id: Option<String>,
    ) -> Result<()> {
        let event = crate::policy::Event {
            original_request_link: None,
            mutation,
            authenticated_certificate_digest: self.tls.client_certificate.clone(),
            witness_time_ms: time,
            writer_session_id,
        };
        if previous.sequence.checked_add(1) != Some(committed.sequence)
            || committed.digest != digest("wholepact:authority-append:v2", &(previous, event))?
        {
            return Err(AuthorityError::Authentication);
        }
        Ok(())
    }
    fn check_snapshot(&self, s: &AccountSnapshot) -> Result<()> {
        if s.witness_id != self.witness
            || s.account_id != self.account
            || s.network_profile_id != self.network
            || s.policy_digest != self.policy_digest
        {
            return Err(AuthorityError::Authentication);
        }
        hash(&s.head.digest)?;
        Ok(())
    }
    fn call(&self, request: &WireRequest) -> Result<WireResponse> {
        self.call_with(|_| Ok(request.clone()))
    }
    fn call_until(&self, request: &WireRequest, deadline: Instant) -> Result<WireResponse> {
        self.call_with_until(deadline, |_| Ok(request.clone()))
    }
    fn call_with(
        &self,
        build: impl FnOnce(&[u8; 32]) -> Result<WireRequest>,
    ) -> Result<WireResponse> {
        self.call_with_inner(build, None)
    }
    fn call_with_until(
        &self,
        deadline: Instant,
        build: impl FnOnce(&[u8; 32]) -> Result<WireRequest>,
    ) -> Result<WireResponse> {
        self.call_with_inner(build, Some(deadline))
    }
    fn call_with_inner(
        &self,
        build: impl FnOnce(&[u8; 32]) -> Result<WireRequest>,
        caller_deadline: Option<Instant>,
    ) -> Result<WireResponse> {
        self.call_with_inner_checked(build, caller_deadline, || Ok(()))
    }
    // A cancellation check is not a permission factory. Native callers retain
    // their actual owner and original absolute deadline through this exchange.
    fn call_with_inner_checked(
        &self,
        build: impl FnOnce(&[u8; 32]) -> Result<WireRequest>,
        caller_deadline: Option<Instant>,
        mut current: impl FnMut() -> Result<()>,
    ) -> Result<WireResponse> {
        current()?;
        let started = Instant::now();
        let deadline = match caller_deadline {
            Some(deadline) => bounded_transport_deadline_at(started, deadline)?,
            None => started + IO_TIMEOUT,
        };
        let mut check = || -> Result<()> {
            if caller_deadline.is_some() {
                require_before_caller_deadline(deadline)?;
            }
            current()?;
            if caller_deadline.is_some() {
                require_before_caller_deadline(deadline)?;
            }
            Ok(())
        };
        let connect_timeout = if caller_deadline.is_some() {
            caller_remaining_at(deadline, Instant::now())?
        } else {
            IO_TIMEOUT
        };
        check()?;
        let socket = TcpStream::connect_timeout(&self.endpoint, connect_timeout)
            .map_err(|_| AuthorityError::Uncertain)?;
        check()?;
        let mut socket = CallerDeadlineSocket {
            inner: DeadlineSocket { socket, deadline },
            check_after_io: caller_deadline.is_some(),
        };
        let mut connection =
            ClientConnection::new(self.tls.config.clone(), self.tls.server_name.clone())
                .map_err(|_| AuthorityError::Authentication)?;
        while connection.is_handshaking() {
            check()?;
            connection
                .complete_io(&mut socket)
                .map_err(|_| AuthorityError::Authentication)?;
        }
        check()?;
        let peer = connection
            .peer_certificates()
            .and_then(|c| c.first())
            .ok_or(AuthorityError::Authentication)?;
        if certificate_digest(peer) != self.tls.pinned_certificate
            || connection.alpn_protocol() != Some(ALPN)
        {
            return Err(AuthorityError::Authentication);
        }
        let exporter = Zeroizing::new(
            connection
                .export_keying_material([0_u8; 32], crate::session::EXPORTER_LABEL, None)
                .map_err(|_| AuthorityError::Authentication)?,
        );
        check()?;
        let request = build(&exporter)?;
        check()?;
        let mut stream = StreamOwned::new(connection, socket);
        check()?;
        // From this write onward cancellation cannot promise remote rollback.
        write_frame(&mut stream, &request).map_err(|_| AuthorityError::Uncertain)?;
        check()?;
        let response = read_frame(&mut stream).map_err(|_| AuthorityError::Uncertain)?;
        check()?;
        match response {
            WireResponse::Rejected(e) => Err(e),
            response => Ok(response),
        }
    }
}

#[derive(Clone)]
pub struct AuthorityServer {
    journal: Arc<AuthorityJournal>,
    tls: ServerTls,
    handoff_scope: Option<construction_transport_server_v1::ConstructionTransportServingScopeV1>,
    #[cfg(all(feature="born-offline-witness-owner",target_os="linux"))]
    born_offline_witness: Option<Arc<std::sync::Mutex<crate::born_offline_retry_v1::configured_born_witness::ConfiguredBornOfflineWitnessV1>>>,
    #[cfg(all(feature = "offline-witness-owner", target_os = "linux"))]
    offline_witness: Option<
        Arc<
            std::sync::Mutex<
                crate::offline_admission::configured_witness::ConfiguredOfflineWitnessV1,
            >,
        >,
    >,
}
impl AuthorityServer {
    pub fn new(journal: Arc<AuthorityJournal>, tls: ServerTls) -> Self {
        Self {
            journal,
            tls,
            handoff_scope: None,
            #[cfg(all(feature = "born-offline-witness-owner", target_os = "linux"))]
            born_offline_witness: None,
            #[cfg(all(feature = "offline-witness-owner", target_os = "linux"))]
            offline_witness: None,
        }
    }
    /// One bounded request per connection. Invalid clients never get a response
    /// containing metadata. Requests are logged only in the encrypted journal.
    pub fn serve_connection(&self, socket: TcpStream) -> Result<()> {
        self.serve_connection_before(socket, Instant::now() + IO_TIMEOUT)
    }
    fn serve_connection_before(&self, socket: TcpStream, deadline: Instant) -> Result<()> {
        let mut socket = DeadlineSocket { socket, deadline };
        let mut connection = ServerConnection::new(self.tls.config.clone())
            .map_err(|_| AuthorityError::Authentication)?;
        while connection.is_handshaking() {
            connection
                .complete_io(&mut socket)
                .map_err(|_| AuthorityError::Authentication)?;
        }
        if connection.alpn_protocol() != Some(ALPN) {
            return Err(AuthorityError::Authentication);
        }
        let peer = certificate_digest(
            connection
                .peer_certificates()
                .and_then(|c| c.first())
                .ok_or(AuthorityError::Authentication)?,
        );
        if let Some(scope) = &self.handoff_scope {
            // Explicitly selected handoff servers have their own narrow protocol.
            // They cannot also act as generic writer/control/financial servers.
            let handoff_exporter = Zeroizing::new(
                connection
                    .export_keying_material(
                        [0_u8; 32],
                        crate::construction_transport_handoff_v1::EXPORTER_LABEL,
                        None,
                    )
                    .map_err(|_| AuthorityError::Authentication)?,
            );
            return self.serve_construction_handoff_stream_v1(
                StreamOwned::new(connection, socket),
                &peer,
                &handoff_exporter,
                scope,
            );
        }
        let exporter = Zeroizing::new(
            connection
                .export_keying_material([0_u8; 32], crate::session::EXPORTER_LABEL, None)
                .map_err(|_| AuthorityError::Authentication)?,
        );
        let mut stream = StreamOwned::new(connection, socket);
        let request: WireRequest = read_frame(&mut stream)?;
        if self.is_born_offline_server_v1()
            && !matches!(
                &request,
                WireRequest::SubmitBornOfflineIntentV1(_)
                    | WireRequest::AuthorizeBornOfflineDispatchV1 { .. }
                    | WireRequest::ObserveBornOfflineAdmissionTimeV1(_)
                    | WireRequest::RecoverBornOfflineDeliveryV1(_)
                    | WireRequest::Snapshot { .. }
                    | WireRequest::ReadHistory { .. }
            )
        {
            return write_frame(
                &mut stream,
                &WireResponse::Rejected(AuthorityError::Permission),
            );
        }
        let result = match request {
            WireRequest::ObserveBornOfflineAdmissionTimeV1(request) => {
                if !self.is_born_offline_server_v1() {
                    Err(AuthorityError::Permission)
                } else {
                    let binding = born_offline_clock_v1::channel_binding(
                        &exporter,
                        &request.scope,
                        &request.challenge,
                    )?;
                    self.journal
                        .observe_born_offline_clock_v1(&peer, &request, &binding, now_ms)
                        .map(|response| {
                            WireResponse::BornOfflineAdmissionTimeV1(Box::new(response))
                        })
                }
            }
            WireRequest::AuthorizeBornOfflineDispatchV1 {
                request,
                authentication,
            } => self.serve_born_dispatch_v1(&peer, &exporter, &request, &authentication, deadline),
            WireRequest::SubmitBornOfflineIntentV1(request) => {
                self.serve_born_offline_intent_v1(&peer, &exporter, &request, deadline)
            }
            WireRequest::RecoverBornOfflineDeliveryV1(lookup) => {
                self.serve_born_offline_recovery_v1(&peer, &lookup, deadline)
            }
            WireRequest::SubmitOfflineIntentV1(request) => {
                self.serve_offline_intent_v1(&peer, &exporter, &request, deadline)
            }
            WireRequest::RecoverOfflineAdmissionDeliveryV1(original) => {
                self.serve_offline_delivery_recovery_v1(&peer, &original, deadline)
            }
            WireRequest::ObserveOfflineAdmissionTimeV1(request) => {
                let binding = offline_clock_v1::channel_binding(
                    &exporter,
                    &request.scope,
                    &request.challenge,
                )?;
                self.journal
                    .observe_offline_clock_v1(&peer, &request, &binding, now_ms)
                    .map(|response| WireResponse::OfflineAdmissionTimeV1(Box::new(response)))
            }
            WireRequest::ClaimConstructionTransport { .. }
            | WireRequest::ObserveConstructionTransport { .. }
            | WireRequest::MutateConstructionTransport { .. } => Err(AuthorityError::Permission),
            WireRequest::ResolveReservation {
                account_id,
                network_profile_id,
                reservation_operation_id,
                conflict,
            } => self
                .journal
                .resolve_reservation_selected(
                    &peer,
                    &account_id,
                    &network_profile_id,
                    &reservation_operation_id,
                    conflict.as_ref(),
                )
                .map(|r| WireResponse::Resolution(Box::new(r))),
            WireRequest::Snapshot {
                account_id,
                network_profile_id,
            } => self
                .journal
                .snapshot(&peer, &account_id, &network_profile_id)
                .map(WireResponse::Snapshot),
            WireRequest::Mutate {
                mutation,
                session_proof,
            } => self
                .journal
                .mutate_on_channel(
                    &peer,
                    *mutation,
                    session_proof,
                    &exporter,
                    &self.tls.certificate_digest,
                    now_ms()?,
                )
                .map(WireResponse::Mutation),
            WireRequest::ReadHistory {
                account_id,
                network_profile_id,
                expected_head,
                after_sequence,
                maximum_entries,
            } => self
                .journal
                .history(
                    &peer,
                    &account_id,
                    &network_profile_id,
                    &expected_head,
                    after_sequence,
                    maximum_entries,
                )
                .map(|page| WireResponse::History(Box::new(page))),
        };
        let response = result.unwrap_or_else(WireResponse::Rejected);
        write_frame(&mut stream, &response)?;
        stream.conn.send_close_notify();
        stream.flush().map_err(|_| AuthorityError::Uncertain)?;
        Ok(())
    }
    /// Eight fixed workers, eight queued connections, two in-flight connections
    /// per IP and a bounded 32-request burst/refill-one-per-second peer allowance.
    /// Deadline starts at accept, including queue time. Distributed denial of
    /// service and shared-NAT fairness remain operator/deployment limitations.
    pub fn serve(&self, listener: TcpListener) -> Result<()> {
        self.serve_admitted(listener, None)
    }
    fn serve_admitted(&self, listener: TcpListener, maximum_accepts: Option<usize>) -> Result<()> {
        use std::sync::{Mutex, mpsc};
        let admission = crate::admission::Admission::new();
        let (send, receive) =
            mpsc::sync_channel::<(TcpStream, Instant, crate::admission::AdmissionGuard)>(8);
        let receive = Arc::new(Mutex::new(receive));
        let mut workers = Vec::new();
        for _ in 0..8 {
            let receiver = receive.clone();
            let server = self.clone();
            workers.push(std::thread::spawn(move || {
                loop {
                    let next = match receiver.lock() {
                        Ok(receiver) => receiver.recv(),
                        Err(_) => return,
                    };
                    let Ok((socket, deadline, _guard)) = next else {
                        return;
                    };
                    let _ = server.serve_connection_before(socket, deadline);
                }
            }));
        }
        let mut accepted = 0;
        loop {
            let (socket, peer) = listener.accept().map_err(|_| AuthorityError::Uncertain)?;
            let deadline = Instant::now() + IO_TIMEOUT;
            if let Ok(guard) = admission.admit(peer.ip()) {
                let _ = send.try_send((socket, deadline, guard));
            }
            accepted += 1;
            if maximum_accepts == Some(accepted) {
                break;
            }
        }
        drop(send);
        for worker in workers {
            worker.join().map_err(|_| AuthorityError::Storage)?;
        }
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn serve_test_connections(&self, listener: TcpListener, count: usize) -> Result<()> {
        self.serve_admitted(listener, Some(count))
    }
}

// Pure deadline seams exercise strict behavior without opening a socket or
// invoking TLS/key operations. Only additive caller-deadline APIs use them.
fn caller_remaining_at(deadline: Instant, now: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(now)
        .filter(|duration| !duration.is_zero())
        .ok_or(AuthorityError::Permission)
}
fn require_before_caller_deadline(deadline: Instant) -> Result<()> {
    caller_remaining_at(deadline, Instant::now()).map(|_| ())
}
fn bounded_transport_deadline_at(started: Instant, caller_deadline: Instant) -> Result<Instant> {
    caller_remaining_at(caller_deadline, started)?;
    Ok(caller_deadline.min(started + IO_TIMEOUT))
}

struct DeadlineSocket {
    socket: TcpStream,
    deadline: Instant,
}
impl DeadlineSocket {
    fn remaining(&self) -> std::io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "authority deadline"))
    }
}
impl Read for DeadlineSocket {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        self.socket.set_read_timeout(Some(self.remaining()?))?;
        self.socket.read(b)
    }
}
impl Write for DeadlineSocket {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.socket.set_write_timeout(Some(self.remaining()?))?;
        self.socket.write(b)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.socket.set_write_timeout(Some(self.remaining()?))?;
        self.socket.flush()
    }
}
// Keep the generic DeadlineSocket contract unchanged for all other clients
// and servers. Only explicit caller-deadline adapters enable post-I/O checks.
struct CallerDeadlineSocket {
    inner: DeadlineSocket,
    check_after_io: bool,
}
impl Read for CallerDeadlineSocket {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let result = self.inner.read(bytes);
        if self.check_after_io {
            self.inner.remaining()?;
        }
        result
    }
}
impl Write for CallerDeadlineSocket {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let result = self.inner.write(bytes);
        if self.check_after_io {
            self.inner.remaining()?;
        }
        result
    }
    fn flush(&mut self) -> std::io::Result<()> {
        let result = self.inner.flush();
        if self.check_after_io {
            self.inner.remaining()?;
        }
        result
    }
}

fn read_frame<T: serde::de::DeserializeOwned>(reader: &mut impl Read) -> Result<T> {
    let mut size = [0_u8; 4];
    reader
        .read_exact(&mut size)
        .map_err(|_| AuthorityError::Uncertain)?;
    let len = u32::from_be_bytes(size) as usize;
    if len == 0 || len > MAX_FRAME_BYTES {
        return Err(AuthorityError::Limit);
    }
    let mut body = Zeroizing::new(vec![0_u8; len]);
    reader
        .read_exact(&mut body)
        .map_err(|_| AuthorityError::Uncertain)?;
    decode(&body)
}
fn write_frame<T: Serialize>(writer: &mut impl Write, message: &T) -> Result<()> {
    let body = encode(message)?;
    writer
        .write_all(&(body.len() as u32).to_be_bytes())
        .and_then(|_| writer.write_all(&body))
        .and_then(|_| writer.flush())
        .map_err(|_| AuthorityError::Uncertain)
}

/// Synthetic issuer only for local qualification. Cannot exist in default builds.
#[cfg(any(test, feature = "synthetic-qualification"))]
pub mod synthetic {
    use super::*;
    /// Explicit synthetic fixture only; absent from production builds.
    pub fn recovery_fence(
        journal: &AuthorityJournal,
        writer: &str,
        account: &str,
        network: &str,
        operation: &str,
        inventory: &str,
    ) -> Result<AuthenticatedRecoveryFence> {
        let (history, active) = reconciled_session(journal, writer, account, network)?;
        crate::recovery::bind_fence(
            history,
            active,
            operation,
            inventory,
            std::time::Instant::now(),
        )
    }

    pub fn activate(
        journal: &AuthorityJournal,
        writer_certificate_digest: &str,
        now: u64,
    ) -> Result<AccountSnapshot> {
        journal.synthetic_activate(writer_certificate_digest, now)
    }

    /// Test-only opaque fixture. This never exists in default builds and is not
    /// an authenticated network adapter. Real callers must use the mTLS client.
    pub fn reconciled_session(
        journal: &AuthorityJournal,
        writer: &str,
        account: &str,
        network: &str,
    ) -> Result<(ReconciledAuthorityHistory, AuthenticatedWriterSession)> {
        let snapshot = journal.snapshot(writer, account, network)?;
        let receipt = snapshot
            .active_writer_session
            .clone()
            .ok_or(AuthorityError::SessionRequired)?;
        snapshot.require_unfenced_transport(&receipt.session_id)?;
        if snapshot
            .account_use_checkpoint
            .as_ref()
            .is_some_and(|c| c.permanent_exclusion_digest.is_some())
        {
            return Err(AuthorityError::PolicyDenied);
        }
        if snapshot.writer_status != WriterStatus::Active
            || receipt.writer_certificate_digest != writer
        {
            return Err(AuthorityError::Permission);
        }
        let mut after = 0;
        let mut ledger: Option<crate::policy::Ledger> = None;
        let mut permits = Vec::new();
        let mut offline_permits = Vec::new();
        let mut born_offline_permits = Vec::new();
        let mut born_offline_dispatches = Vec::new();
        let mut automatic_key_use_admissions = Vec::new();
        let mut recovery_fences = Vec::new();
        let mut committed_operation_ids = std::collections::BTreeSet::new();
        let mut owner_controls = std::collections::BTreeMap::new();
        let mut history_heads =
            std::collections::BTreeMap::from([(0, snapshot.policy_digest.clone())]);
        loop {
            let page = journal.history(writer, account, network, &snapshot.head, after, 16)?;
            if ledger.is_none() {
                ledger = Some(crate::policy::Ledger::new(page.policy)?);
            }
            let state = ledger.as_mut().ok_or(AuthorityError::CorruptHistory)?;
            for entry in page.entries {
                if entry.sequence != state.snapshot.head.sequence + 1
                    || entry.previous_head != state.snapshot.head.digest
                {
                    return Err(AuthorityError::CorruptHistory);
                }
                let event = crate::policy::Event {
                    original_request_link: entry.original_request_link,
                    mutation: entry.mutation,
                    authenticated_certificate_digest: entry.authenticated_certificate_digest,
                    witness_time_ms: entry.witness_time_ms,
                    writer_session_id: entry.writer_session_id,
                };
                let previous = state.snapshot.clone();
                match state.apply(&event)? {
                    MutationResult::Reserved(permit) => permits.push(*permit),
                    MutationResult::OfflineReserved(permit) => offline_permits.push(*permit),
                    MutationResult::BornOfflineDispatchAdmittedV1(admission) => {
                        born_offline_dispatches.push(*admission)
                    }
                    MutationResult::BornOfflineReservedV1(permit) => {
                        born_offline_permits.push(*permit)
                    }
                    MutationResult::AutomaticKeyUseAdmitted(admission) => {
                        automatic_key_use_admissions.push(*admission)
                    }
                    _ => {}
                }
                committed_operation_ids.insert(event.mutation.operation_id().to_owned());
                if let AuthorityMutation::OwnerControl(request) = &event.mutation {
                    owner_controls.insert(request.operation_id.clone(), request.clone());
                }
                if let Some(receipt) =
                    crate::recovery::recovery_receipt(&previous, &event.mutation, &state.snapshot)
                {
                    recovery_fences.push(receipt);
                }
                if state.snapshot.head.digest != entry.head {
                    return Err(AuthorityError::CorruptHistory);
                }
                history_heads.insert(entry.sequence, entry.head.clone());
                after = entry.sequence;
            }
            match page.next_after_sequence {
                Some(next) if next == after && next < snapshot.head.sequence => continue,
                None if after == snapshot.head.sequence => break,
                _ => return Err(AuthorityError::CorruptHistory),
            }
        }
        let ledger = ledger.ok_or(AuthorityError::CorruptHistory)?;
        if ledger.snapshot != snapshot {
            return Err(AuthorityError::CorruptHistory);
        }
        let manual_roster_attempt = if ledger.manual_roster_extension()?.is_some() {
            Some(ledger.latest_manual_roster_attempt_v2()?)
        } else {
            None
        };
        let manual_attempt =
            if manual_roster_attempt.is_none() && ledger.manual_extension()?.is_some() {
                Some(ledger.latest_manual_attempt()?)
            } else {
                None
            };
        let history = ReconciledAuthorityHistory {
            construction_transport_history: ledger.construction_transport_history_v1(),
            manual_roster_construction_records_v3: ledger.roster_construction_history_v3(),
            manual_roster_construction_records: ledger.roster_construction_history_v2(),
            manual_roster_attempt,
            manual_attempt,
            pending_birth_commit: None,
            account_use_history: ledger.account_use_history,
            account_policy: ledger.policy,
            snapshot: snapshot.clone(),
            permits,
            offline_permits,
            born_offline_permits,
            born_offline_dispatches,
            automatic_key_use_admissions,
            recovery_fences,
            committed_operation_ids,
            owner_controls,
            history_heads,
            disclosure: receipt.disclosure.clone(),
        };
        let active = AuthenticatedWriterSession {
            observed: std::time::Instant::now(),
            observed_at_ms: snapshot.last_witness_time_ms,
            snapshot,
            disclosure: receipt.disclosure.clone(),
            receipt,
            history_digest: history.history_digest()?,
        };
        Ok((history, active))
    }

    /// Test-only complete historical journal replay. Unlike reconciled_session,
    /// this returns no active session/native owner and deliberately supports
    /// fenced, paused and retired historical accounts. No network is used.
    pub fn reconciled_history(
        journal: &AuthorityJournal,
        writer: &str,
        descriptor: &WitnessDisclosureDescriptor,
    ) -> Result<ReconciledAuthorityHistory> {
        let snapshot = journal.snapshot(
            writer,
            &descriptor.account_id,
            &descriptor.network_profile_id,
        )?;
        replay_historical_pages(snapshot, descriptor, |after, head| {
            journal.history(
                writer,
                &descriptor.account_id,
                &descriptor.network_profile_id,
                head,
                after,
                16,
            )
        })
    }

    /// Test-only modeled legacy reconciliation transcript. This checks historical
    /// reachability with the maintained ledger and complete paging replay; it is
    /// not an authenticated transport, native decision or active-session issuer.
    /// Only an empty prefix, AcquireWriter, or AcquireWriter + owner activation
    /// is accepted. Unknown legacy genesis must remain unknown.
    pub fn recorded_legacy_reconciliation_history(
        policy: &AccountPolicy,
        descriptor: &WitnessDisclosureDescriptor,
        events_json: &[u8],
    ) -> Result<ReconciledAuthorityHistory> {
        policy.validate()?;
        descriptor.validate()?;
        if policy.account_use_genesis.is_some()
            || descriptor.account_id != policy.account_id
            || descriptor.network_profile_id != policy.network_profile_id
            || descriptor.witness_id != policy.witness_id
            || descriptor.policy_digest != policy.policy_digest()?
            || events_json.len() > 64 * 1024
        {
            return Err(AuthorityError::InvalidBinding);
        }
        let events: Vec<crate::policy::Event> =
            serde_json::from_slice(events_json).map_err(|_| AuthorityError::CorruptHistory)?;
        if events.len() > 2 {
            return Err(AuthorityError::Permission);
        }
        let mut ledger = crate::policy::Ledger::new(policy.clone())?;
        let mut entries = Vec::new();
        for (index, event) in events.into_iter().enumerate() {
            let permitted = matches!(
                (index, &event.mutation),
                (0, AuthorityMutation::AcquireWriter(_))
                    | (
                        1,
                        AuthorityMutation::OwnerControl(OwnerControlRequest {
                            control: OwnerControl::ActivateWriter { .. },
                            ..
                        })
                    )
            );
            if !permitted
                || event.writer_session_id.is_some()
                || event.original_request_link.is_some()
            {
                return Err(AuthorityError::Permission);
            }
            let previous = ledger.snapshot.head.clone();
            ledger.apply(&event)?;
            if ledger.snapshot.head.sequence != previous.sequence + 1 {
                return Err(AuthorityError::CorruptHistory);
            }
            entries.push(crate::protocol::HistoryEntry {
                original_request_link: event.original_request_link,
                sequence: ledger.snapshot.head.sequence,
                previous_head: previous.digest,
                head: ledger.snapshot.head.digest.clone(),
                mutation: event.mutation,
                authenticated_certificate_digest: event.authenticated_certificate_digest,
                witness_time_ms: event.witness_time_ms,
                writer_session_id: event.writer_session_id,
            });
        }
        ledger.validate_manual_birth(None)?;
        let snapshot = ledger.snapshot;
        replay_historical_pages(snapshot.clone(), descriptor, |after, _| {
            if after != 0 {
                return Err(AuthorityError::CorruptHistory);
            }
            Ok(crate::protocol::HistoryPage {
                pending_birth_commit: None,
                policy: policy.clone(),
                snapshot: snapshot.clone(),
                entries: entries.clone(),
                next_after_sequence: None,
            })
        })
    }

    /// Existing never-funded signed fixture transcript only. Every event is
    /// replayed by the maintained ledger; this is no native/session issuer.
    pub fn recorded_fixture_history(
        birth: &crate::pending_birth::PendingBirthCommitRecord,
        events_json: &[u8],
    ) -> Result<ReconciledAuthorityHistory> {
        birth.validate()?;
        if events_json.len() > 32 * 1024 * 1024 {
            return Err(AuthorityError::Permission);
        }
        let events: Vec<crate::policy::Event> =
            serde_json::from_slice(events_json).map_err(|_| AuthorityError::CorruptHistory)?;
        if events.len() > 65_536 {
            return Err(AuthorityError::Permission);
        }
        let mut ledger = crate::policy::Ledger::new(birth.request.policy.clone())?;
        let mut entries = Vec::new();
        for event in events {
            let previous_head = ledger.snapshot.head.digest.clone();
            ledger.apply(&event)?;
            entries.push(crate::protocol::HistoryEntry {
                original_request_link: event.original_request_link,
                sequence: ledger.snapshot.head.sequence,
                previous_head,
                head: ledger.snapshot.head.digest.clone(),
                mutation: event.mutation,
                authenticated_certificate_digest: event.authenticated_certificate_digest,
                witness_time_ms: event.witness_time_ms,
                writer_session_id: event.writer_session_id,
            });
        }
        ledger.validate_manual_birth(Some(birth))?;
        let snapshot = ledger.snapshot;
        replay_historical_pages(snapshot.clone(), &birth.request.disclosure, |after, _| {
            let start = usize::try_from(after).map_err(|_| AuthorityError::Permission)?;
            if start > entries.len() {
                return Err(AuthorityError::CorruptHistory);
            }
            let end = (start + 16).min(entries.len());
            Ok(crate::protocol::HistoryPage {
                pending_birth_commit: Some(birth.clone()),
                policy: birth.request.policy.clone(),
                snapshot: snapshot.clone(),
                entries: entries[start..end].to_vec(),
                next_after_sequence: (end < entries.len()).then_some(end as u64),
            })
        })
    }

    fn replay_historical_pages(
        snapshot: AccountSnapshot,
        descriptor: &WitnessDisclosureDescriptor,
        mut page: impl FnMut(u64, &AuthorityHead) -> Result<crate::protocol::HistoryPage>,
    ) -> Result<ReconciledAuthorityHistory> {
        descriptor.validate()?;
        let bounded = true;
        let check_current: &mut dyn FnMut() -> Result<()> = &mut || Ok(());
        let started = std::time::Instant::now();
        let check = |check_current: &mut dyn FnMut() -> Result<()>| -> Result<()> {
            check_current()?;
            if bounded && started.elapsed() >= std::time::Duration::from_secs(120) {
                return Err(AuthorityError::Permission);
            }
            Ok(())
        };
        check(check_current)?;

        check(check_current)?;
        if bounded && snapshot.head.sequence > 65_536 {
            return Err(AuthorityError::Permission);
        }
        let mut pages = 0usize;
        let mut entries = 0usize;
        let mut bytes = 0usize;
        let mut ledger: Option<crate::policy::Ledger> = None;
        let mut pending_birth_commit = None;
        let mut permits = Vec::new();
        let mut offline_permits = Vec::new();
        let mut born_offline_permits = Vec::new();
        let mut born_offline_dispatches = Vec::new();
        let mut automatic_key_use_admissions = Vec::new();
        let mut recovery_fences = Vec::new();
        let mut committed_operation_ids = std::collections::BTreeSet::new();
        let mut owner_controls = std::collections::BTreeMap::new();
        let mut history_heads =
            std::collections::BTreeMap::from([(0, snapshot.policy_digest.clone())]);
        let mut after = 0;
        loop {
            check(check_current)?;
            if bounded && pages >= 4_096 {
                return Err(AuthorityError::Permission);
            }
            let page = page(after, &snapshot.head)?;
            check(check_current)?;
            if bounded {
                pages = pages.checked_add(1).ok_or(AuthorityError::Permission)?;
                entries = entries
                    .checked_add(page.entries.len())
                    .ok_or(AuthorityError::Permission)?;
                bytes = bytes
                    .checked_add(
                        serde_json::to_vec(&page)
                            .map_err(|_| AuthorityError::InvalidBinding)?
                            .len(),
                    )
                    .ok_or(AuthorityError::Permission)?;
                if entries > 65_536 || bytes > 32 * 1024 * 1024 {
                    return Err(AuthorityError::Permission);
                }
            }
            if page.snapshot != snapshot || page.policy.policy_digest()? != descriptor.policy_digest
            {
                return Err(AuthorityError::Authentication);
            }
            if ledger.is_none() {
                if let Some(record) = &page.pending_birth_commit {
                    record.validate()?;
                    if record.request.policy != page.policy
                        || record.request.disclosure != descriptor.clone()
                    {
                        return Err(AuthorityError::Authentication);
                    }
                }
                // Positive genesis without original authenticated metadata is
                // not a complete birth provenance history.
                if page.policy.account_use_genesis.is_some() != page.pending_birth_commit.is_some()
                {
                    return Err(AuthorityError::CorruptHistory);
                }
                pending_birth_commit = page.pending_birth_commit.clone();
                ledger = Some(crate::policy::Ledger::new(page.policy.clone())?);
            }
            let state = ledger.as_mut().ok_or(AuthorityError::CorruptHistory)?;
            if page.policy != state.policy || page.pending_birth_commit != pending_birth_commit {
                return Err(AuthorityError::Authentication);
            }
            let before = after;
            for entry in page.entries {
                if entry.sequence != state.snapshot.head.sequence + 1
                    || entry.previous_head != state.snapshot.head.digest
                {
                    return Err(AuthorityError::CorruptHistory);
                }
                let event = crate::policy::Event {
                    original_request_link: entry.original_request_link,
                    mutation: entry.mutation,
                    authenticated_certificate_digest: entry.authenticated_certificate_digest,
                    witness_time_ms: entry.witness_time_ms,
                    writer_session_id: entry.writer_session_id,
                };
                let previous = state.snapshot.clone();
                match state.apply(&event)? {
                    MutationResult::Reserved(permit) => permits.push(*permit),
                    MutationResult::OfflineReserved(permit) => offline_permits.push(*permit),
                    MutationResult::BornOfflineDispatchAdmittedV1(admission) => {
                        born_offline_dispatches.push(*admission)
                    }
                    MutationResult::BornOfflineReservedV1(permit) => {
                        born_offline_permits.push(*permit)
                    }
                    MutationResult::AutomaticKeyUseAdmitted(admission) => {
                        automatic_key_use_admissions.push(*admission)
                    }
                    _ => {}
                }
                committed_operation_ids.insert(event.mutation.operation_id().to_owned());
                if let AuthorityMutation::OwnerControl(request) = &event.mutation {
                    owner_controls.insert(request.operation_id.clone(), request.clone());
                }
                if let Some(receipt) =
                    crate::recovery::recovery_receipt(&previous, &event.mutation, &state.snapshot)
                {
                    recovery_fences.push(receipt);
                }
                if state.snapshot.head.digest != entry.head {
                    return Err(AuthorityError::CorruptHistory);
                }
                history_heads.insert(entry.sequence, entry.head.clone());
                after = entry.sequence;
            }
            if after == before && after < snapshot.head.sequence {
                return Err(AuthorityError::CorruptHistory);
            }
            match page.next_after_sequence {
                Some(next) if next == after && next < snapshot.head.sequence => continue,
                None if after == snapshot.head.sequence => break,
                _ => return Err(AuthorityError::CorruptHistory),
            }
        }
        let ledger = ledger.ok_or(AuthorityError::CorruptHistory)?;
        ledger.validate_manual_birth(pending_birth_commit.as_ref())?;
        ledger.validate_born_offline_birth_v1(pending_birth_commit.as_ref())?;
        let manual_roster_attempt = if ledger.manual_roster_extension()?.is_some() {
            Some(ledger.latest_manual_roster_attempt_v2()?)
        } else {
            None
        };
        let manual_attempt =
            if manual_roster_attempt.is_none() && ledger.manual_extension()?.is_some() {
                Some(ledger.latest_manual_attempt()?)
            } else {
                None
            };
        let manual_roster_construction_records = ledger.roster_construction_history_v2();
        let manual_roster_construction_records_v3 = ledger.roster_construction_history_v3();
        let construction_transport_history = ledger.construction_transport_history_v1();
        let account_use_history = ledger.account_use_history;
        let account_policy = ledger.policy;
        let mut computed = ledger.snapshot;
        // A restored database's independent one-way quarantine is not an event
        // that rewrites its historical hash chain. It never enables acquisition.
        if snapshot.writer_status == WriterStatus::Quarantined {
            computed.writer_status = WriterStatus::Quarantined;
        }
        if computed != snapshot {
            return Err(AuthorityError::CorruptHistory);
        }
        check(check_current)?;
        Ok(ReconciledAuthorityHistory {
            construction_transport_history,
            manual_roster_construction_records,
            manual_roster_construction_records_v3,
            manual_roster_attempt,
            manual_attempt,
            pending_birth_commit,
            account_use_history,
            account_policy,
            snapshot,
            permits,
            offline_permits,
            born_offline_permits,
            born_offline_dispatches,
            automatic_key_use_admissions,
            recovery_fences,
            committed_operation_ids,
            owner_controls,
            history_heads,
            disclosure: descriptor.clone(),
        })
    }

    pub fn reserve(
        journal: &AuthorityJournal,
        peer_certificate_digest: &str,
        request: ReserveAuthorization,
        now: u64,
    ) -> Result<AuthenticatedPermit> {
        let result = journal.mutate(
            peer_certificate_digest,
            AuthorityMutation::ReserveAuthorization(Box::new(request.clone())),
            now,
        )?;
        match result {
            MutationResult::Reserved(p) => {
                p.matches_request(&request)?;
                Ok(AuthenticatedPermit {
                    descriptor: *p,
                    certificate_digest: "0".repeat(64),
                })
            }
            _ => Err(AuthorityError::InvalidBinding),
        }
    }
    pub fn authorize_dispatch(
        journal: &AuthorityJournal,
        peer: &str,
        request: AuthorizeDispatch,
        now: u64,
    ) -> Result<AuthenticatedDispatchAdmission> {
        match journal.mutate(
            peer,
            AuthorityMutation::AuthorizeDispatch(request.clone()),
            now,
        )? {
            MutationResult::DispatchAdmitted(admission) => {
                admission.matches_request(&request)?;
                Ok(AuthenticatedDispatchAdmission {
                    descriptor: *admission,
                    certificate_digest: "0".repeat(64),
                })
            }
            _ => Err(AuthorityError::InvalidBinding),
        }
    }
    pub fn authorize_automatic_key_use(
        journal: &AuthorityJournal,
        peer: &str,
        request: AuthorizeAutomaticKeyUse,
        now: u64,
    ) -> Result<AuthenticatedAutomaticKeyUseAdmission> {
        match journal.mutate(
            peer,
            AuthorityMutation::AuthorizeAutomaticKeyUse(request.clone()),
            now,
        )? {
            MutationResult::AutomaticKeyUseAdmitted(admission) => {
                admission.matches_request(&request)?;
                Ok(AuthenticatedAutomaticKeyUseAdmission {
                    descriptor: *admission,
                    certificate_digest: "0".repeat(64),
                })
            }
            _ => Err(AuthorityError::InvalidBinding),
        }
    }
    pub fn snapshot(
        journal: &AuthorityJournal,
        peer: &str,
        account: &str,
        network: &str,
    ) -> Result<AccountSnapshot> {
        journal.snapshot(peer, account, network)
    }
    pub fn control(
        journal: &AuthorityJournal,
        peer: &str,
        request: OwnerControlRequest,
        now: u64,
    ) -> Result<AccountSnapshot> {
        match journal.mutate(peer, AuthorityMutation::OwnerControl(request), now)? {
            MutationResult::Controlled(s) => Ok(s),
            _ => Err(AuthorityError::InvalidBinding),
        }
    }
}

#[cfg(test)]
mod caller_deadline_tests {
    use super::*;

    #[test]
    fn caller_budget_caps_original_transport_budget_without_renewal() {
        let started = Instant::now();
        let caller = started + Duration::from_secs(3);
        assert_eq!(
            bounded_transport_deadline_at(started, caller).unwrap(),
            caller
        );
        let next_page_started = started + Duration::from_secs(2);
        assert_eq!(
            bounded_transport_deadline_at(next_page_started, caller).unwrap(),
            caller
        );
        assert_eq!(
            caller_remaining_at(caller, next_page_started).unwrap(),
            Duration::from_secs(1)
        );
        let long_caller = started + Duration::from_secs(30);
        assert_eq!(
            bounded_transport_deadline_at(started, long_caller).unwrap(),
            started + IO_TIMEOUT
        );
    }

    #[test]
    fn expired_caller_budget_never_starts_a_new_transport() {
        let deadline = Instant::now();
        assert!(bounded_transport_deadline_at(deadline, deadline).is_err());
        assert!(
            bounded_transport_deadline_at(deadline + Duration::from_nanos(1), deadline).is_err()
        );
        assert!(caller_remaining_at(deadline, deadline).is_err());
        assert!(caller_remaining_at(deadline, deadline + Duration::from_nanos(1)).is_err());
    }
}
