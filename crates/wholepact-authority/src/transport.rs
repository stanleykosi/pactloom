//! Narrow length-delimited JSON over maintained TLS 1.3 with mutual certificate
//! validation. No plaintext remote mode, certificate-verification bypass, custom
//! verifier, redirects, proxy credentials, or caller-controlled URL exists.
mod born_offline_clock_v1;
mod born_offline_dispatch_v1;
mod born_offline_owner_continuation_v1;
pub use born_offline_dispatch_v1::AuthenticatedBornOfflineDispatchV1;
#[cfg(feature = "synthetic-qualification")]
pub mod admission_diagnostics_v1;
mod born_offline_witness_v1;
#[cfg(all(
    feature = "synthetic-qualification",
    feature = "native-witness-owner",
    target_os = "linux"
))]
mod durable_acquire_reply_loss_v1;
mod durable_payment_client_v1;
mod durable_delivery_admission_v2;
mod financial_continuation_v1;
mod financial_signing_server_v1;
mod financial_signing_client_v1;
#[cfg(all(any(feature = "coordinated-witness-financial-history", feature = "coordinated-witness-financial-signing", feature = "coordinated-witness-completed-pair"), target_os = "linux"))]
mod coordinated_service_worker_v1;
mod completed_dispatch_v1;
#[cfg(all(feature = "coordinated-witness-financial-continuation", target_os = "linux"))]
pub(crate) mod coordinated_financial_continuation_v1;
#[cfg(all(feature = "coordinated-witness-financial-history", target_os = "linux"))]
mod coordinated_initial_history_v1;
#[cfg(all(feature = "coordinated-witness-financial-history", target_os = "linux"))]
pub use coordinated_initial_history_v1::run_coordinated_initial_history_v1;
#[cfg(all(feature = "coordinated-witness-financial-signing", target_os = "linux"))]
mod coordinated_financial_signing_v1;
#[cfg(all(feature = "coordinated-witness-financial-signing", target_os = "linux"))]
pub use coordinated_financial_signing_v1::run_coordinated_financial_signing_v1;
#[cfg(all(feature = "coordinated-witness-completed-pair", target_os = "linux"))]
mod coordinated_completed_pair_v1;
#[cfg(all(feature = "coordinated-witness-completed-pair", target_os = "linux"))]
pub use coordinated_completed_pair_v1::run_coordinated_completed_pair_v1;
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
mod finite_witness_service_v1;
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
pub(crate) use finite_witness_service_v1::FiniteWitnessServiceStopV1;
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
pub use completed_dispatch_v1::{open_born_completed_dispatch_v1_for_server, open_born_completed_dispatch_pair_v1_for_server};
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
pub use financial_signing_server_v1::open_born_financial_signing_v1_for_server;
pub mod durable_delivery_admission_v3;
#[cfg(all(feature = "coordinated-witness-delivery-append", target_os = "linux"))]
pub(crate) mod coordinated_delivery_append_v1;
pub use durable_delivery_admission_v3::AuthenticatedDurableAdmissionChannelV3;
mod durable_payment_server_v1;
#[cfg(all(
    feature = "synthetic-qualification",
    feature = "native-witness-owner",
    target_os = "linux"
))]
pub(crate) use durable_acquire_reply_loss_v1::DurableAcquireReplyLossObservationV1;
#[cfg(feature = "synthetic-qualification")]
pub mod history_diagnostics_v1;
#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
pub use durable_payment_server_v1::open_born_durable_payment_v1_for_server;
#[cfg(feature = "synthetic-qualification")]
use history_diagnostics_v1::{
    CheckedHistoryCheckSiteV1 as HistoryCheckSiteV1,
    CheckedHistoryCheckpointV1 as HistoryCheckpointV1, CheckedHistoryStageV1, HistoryCallStepV1,
    HistoryObserverV1, HistoryOperationV1, HistoryPhaseV1,
};
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
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::Arc,
    time::{Duration, Instant},
};

const IO_TIMEOUT: Duration = Duration::from_secs(10);
const ALPN: &[u8] = b"wholepact-authority/2";

// The original expression is evaluated exactly once. With no synthetic
// observer this is just its result, with no added observational clock sample.
macro_rules! observed_history_result {
    ($observer:expr, $result:expr) => {{
        let result = $result;
        #[cfg(feature = "synthetic-qualification")]
        let result = match $observer {
            Some(observer) => observer.observe_authority(result),
            None => result,
        };
        result
    }};
}

// Observations evaluate the original expression once. None and production
// expansions take no new clock samples and own no operational resources.
macro_rules! admission_stage {
    ($observer:expr, $stage:ident) => {
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = $observer {
            observer
                .enter(crate::transport::admission_diagnostics_v1::AdmissionWitnessStageV1::$stage);
        }
    };
}
macro_rules! admission_measure {
    ($observer:expr, $span:ident, $value:expr) => {{
        #[cfg(feature = "synthetic-qualification")]
        let span = crate::transport::admission_diagnostics_v1::start_span_observed(
            $observer,
            crate::transport::admission_diagnostics_v1::AdmissionWitnessSpanV1::$span,
        );
        let value = $value;
        #[cfg(feature = "synthetic-qualification")]
        drop(span);
        value
    }};
}
macro_rules! admission_result {
    ($observer:expr, $method:ident, $value:expr) => {{
        let value = $value;
        #[cfg(feature = "synthetic-qualification")]
        let value = match $observer {
            Some(observer) => observer.$method(value),
            None => value,
        };
        value
    }};
}
// Flow adapters share the original expressions; None adds no clock or check.
macro_rules! observed_flow_result {
    ($observer:expr, $stage:ident, $result:expr) => {{
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = $observer {
            observer.enter(CheckedHistoryStageV1::$stage);
        }
        let result = $result;
        // Nested callbacks can leave a successful Callback checkpoint behind.
        // A later error returned by this enclosing expression belongs here;
        // any actual earlier callback failure is already preserved unchanged.
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = $observer {
            observer.enter(CheckedHistoryStageV1::$stage);
        }
        observed_history_result!($observer, result)
    }};
}
macro_rules! observed_flow_current {
    ($observer:expr, $current:expr) => {{
        #[cfg(feature = "synthetic-qualification")]
        let result = history_diagnostics_v1::callback_observed($observer, || $current());
        #[cfg(not(feature = "synthetic-qualification"))]
        let result = $current();
        result
    }};
}
pub(super) use {observed_flow_current, observed_flow_result, observed_history_result};
pub(crate) use {admission_measure, admission_result, admission_stage};

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

/// Purpose-independent, denial-only observation for an original client role.
/// It may sample original actors/session and monotone restriction only. It must
/// not retain an action grant, refresh a deadline, read private sources, wait,
/// or issue authority. Individual checked calls still own their action/deadline.
pub trait AuthorityTransportRestrictionV1: Send + Sync {
    fn check_before_io(&self) -> Result<()>;
}

pub struct AuthorityClient {
    endpoint: SocketAddr,
    tls: ClientTls,
    witness: String,
    account: String,
    network: String,
    policy_digest: String,
    session: std::sync::Mutex<Option<ClientWriterSession>>,
    restriction: Option<std::sync::Arc<dyn AuthorityTransportRestrictionV1>>,
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
            restriction: None,
        })
    }
    /// Construct an original restricted client. There is no detach/reset API.
    /// Cloning the observer retains only a denial mechanism, never an approval.
    pub fn new_restricted_v1(
        endpoint: SocketAddr,
        tls: ClientTls,
        expected_witness_id: String,
        expected_account_id: String,
        expected_network_profile_id: String,
        expected_policy_digest: String,
        restriction: std::sync::Arc<dyn AuthorityTransportRestrictionV1>,
    ) -> Result<Self> {
        let mut client = Self::new(endpoint, tls, expected_witness_id,
            expected_account_id, expected_network_profile_id, expected_policy_digest)?;
        restriction.check_before_io()?;
        client.restriction = Some(restriction);
        Ok(client)
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
        self.reconcile_history_inner(
            &mut || Ok(()),
            false,
            None,
            #[cfg(feature = "synthetic-qualification")]
            None,
        )
    }
    /// Complete authenticated history with caller-owned cancellation checks.
    /// This is a read-only admission hook, never an authority/verified factory.
    /// Bounds reject oversized histories rather than returning a partial fold.
    pub fn reconcile_history_checked(
        &self,
        mut check_current: impl FnMut() -> Result<()>,
    ) -> Result<ReconciledAuthorityHistory> {
        self.reconcile_history_inner(
            &mut check_current,
            true,
            None,
            #[cfg(feature = "synthetic-qualification")]
            None,
        )
    }
    /// Complete bounded read-only replay, with all pages and validation sharing
    /// one caller-owned absolute deadline. No page renews the caller's budget.
    pub fn reconcile_history_checked_until(
        &self,
        deadline: Instant,
        mut check_current: impl FnMut() -> Result<()>,
    ) -> Result<ReconciledAuthorityHistory> {
        require_before_caller_deadline(deadline)?;
        self.reconcile_history_inner(
            &mut check_current,
            true,
            Some(deadline),
            #[cfg(feature = "synthetic-qualification")]
            None,
        )
    }
    /// Synthetic observation of the same checked replay. Added clock samples
    /// only measure existing work; no check, retry, deadline or authority changes.
    #[cfg(feature = "synthetic-qualification")]
    pub fn reconcile_history_diagnosed_checked_until(
        &self,
        deadline: Instant,
        mut check_current: impl FnMut() -> Result<()>,
    ) -> std::result::Result<
        ReconciledAuthorityHistory,
        history_diagnostics_v1::CheckedHistoryFailureV1,
    > {
        let observer = HistoryObserverV1::with_caller_deadline(deadline);
        let result = (|| {
            observed_history_result!(Some(&observer), require_before_caller_deadline(deadline))?;
            self.reconcile_history_inner(&mut check_current, true, Some(deadline), Some(&observer))
        })();
        result.map_err(|error| observer.into_failure(error))
    }
    fn reconcile_history_inner(
        &self,
        check_current: &mut dyn FnMut() -> Result<()>,
        bounded: bool,
        caller_deadline: Option<Instant>,
        #[cfg(feature = "synthetic-qualification")] observer: Option<&HistoryObserverV1>,
    ) -> Result<ReconciledAuthorityHistory> {
        self.reconcile_history_profile_v1(check_current, bounded, caller_deadline,
            #[cfg(feature = "synthetic-qualification")] observer,
            crate::journal::OriginalHistoryProfileV1::Legacy)
    }
    fn reconcile_history_profile_v1(
        &self,
        check_current: &mut dyn FnMut() -> Result<()>,
        bounded: bool,
        caller_deadline: Option<Instant>,
        #[cfg(feature = "synthetic-qualification")] observer: Option<&HistoryObserverV1>,
        profile: crate::journal::OriginalHistoryProfileV1,
    ) -> Result<ReconciledAuthorityHistory> {
        self.reconcile_history_profile_restricted_v1(check_current, bounded, caller_deadline,
            #[cfg(feature = "synthetic-qualification")] observer, profile, None)
    }
    fn reconcile_history_profile_restricted_v1(
        &self,
        check_current: &mut dyn FnMut() -> Result<()>,
        bounded: bool,
        caller_deadline: Option<Instant>,
        #[cfg(feature = "synthetic-qualification")] observer: Option<&HistoryObserverV1>,
        profile: crate::journal::OriginalHistoryProfileV1,
        call_restriction: Option<&dyn Fn() -> Result<()>>,
    ) -> Result<ReconciledAuthorityHistory> {
        let started = std::time::Instant::now();
        let check = |check_current: &mut dyn FnMut() -> Result<()>| -> Result<()> {
            if let Some(deadline) = caller_deadline {
                require_before_caller_deadline(deadline).map_err(|error| {
                    #[cfg(feature = "synthetic-qualification")]
                    if let Some(observer) = observer {
                        observer.record(CheckedHistoryStageV1::CallerDeadline, None, error);
                    }
                    error
                })?;
            }
            #[cfg(feature = "synthetic-qualification")]
            let checked = history_diagnostics_v1::callback_observed(observer, || check_current());
            #[cfg(not(feature = "synthetic-qualification"))]
            let checked = check_current();
            checked.map_err(|error| {
                #[cfg(feature = "synthetic-qualification")]
                if let Some(observer) = observer {
                    observer.record(CheckedHistoryStageV1::SourceCallback, None, error);
                }
                error
            })?;
            #[cfg(feature = "synthetic-qualification")]
            if let Some(observer) = observer {
                observer.checkpoint(HistoryCheckpointV1::AfterCallback);
            }
            if let Some(deadline) = caller_deadline {
                require_before_caller_deadline(deadline).map_err(|error| {
                    #[cfg(feature = "synthetic-qualification")]
                    if let Some(observer) = observer {
                        observer.record(CheckedHistoryStageV1::CallerDeadline, None, error);
                    }
                    error
                })?;
            }
            if bounded && started.elapsed() >= std::time::Duration::from_secs(120) {
                #[cfg(feature = "synthetic-qualification")]
                if let Some(observer) = observer {
                    observer.enter(CheckedHistoryStageV1::Bounds);
                }
                return observed_history_result!(observer, Err(AuthorityError::Permission));
            }
            Ok(())
        };
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.replay_check(HistoryCheckSiteV1::ReplayInitial);
        }
        check(check_current)?;
        let snapshot_response = self.call_with_inner_checked_restricted_observed(
            |_| {
                Ok(WireRequest::Snapshot {
                    account_id: self.account.clone(),
                    network_profile_id: self.network.clone(),
                })
            },
            caller_deadline,
            &mut *check_current,
            call_restriction,
            #[cfg(feature = "synthetic-qualification")]
            observer.map(|observer| (observer, HistoryPhaseV1::Snapshot)),
        )?;
        let WireResponse::Snapshot(snapshot) = snapshot_response else {
            return observed_history_result!(observer, Err(AuthorityError::InvalidBinding));
        };
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.enter(CheckedHistoryStageV1::SnapshotValidation);
        }
        observed_history_result!(observer, self.check_snapshot(&snapshot))?;
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.replay_check(HistoryCheckSiteV1::ReplayAfterSnapshot);
        }
        check(check_current)?;
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.enter(CheckedHistoryStageV1::Bounds);
        }
        if bounded && snapshot.head.sequence > 65_536 {
            return observed_history_result!(observer, Err(AuthorityError::Permission));
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
        let mut completed_dispatches_v1 = Vec::new();
        let mut automatic_key_use_admissions = Vec::new();
        let mut recovery_fences = Vec::new();
        let mut committed_operation_ids = std::collections::BTreeSet::new();
        let mut owner_controls = std::collections::BTreeMap::new();
        let mut history_heads =
            std::collections::BTreeMap::from([(0, snapshot.policy_digest.clone())]);
        let mut after = 0;
        loop {
            #[cfg(feature = "synthetic-qualification")]
            if let Some(observer) = observer {
                observer.replay_check(HistoryCheckSiteV1::ReplayBeforePage);
            }
            check(check_current)?;
            #[cfg(feature = "synthetic-qualification")]
            if let Some(observer) = observer {
                observer.enter(CheckedHistoryStageV1::Bounds);
            }
            if bounded && pages >= 4_096 {
                return observed_history_result!(observer, Err(AuthorityError::Permission));
            }
            let request = WireRequest::ReadHistory {
                account_id: self.account.clone(),
                network_profile_id: self.network.clone(),
                expected_head: snapshot.head.clone(),
                after_sequence: after,
                maximum_entries: 16,
            };
            let response = self.call_with_inner_checked_restricted_observed(
                |_| Ok(request),
                caller_deadline,
                &mut *check_current,
                call_restriction,
                #[cfg(feature = "synthetic-qualification")]
                observer.map(|observer| (observer, HistoryPhaseV1::Page)),
            )?;
            let WireResponse::History(page) = response else {
                return observed_history_result!(observer, Err(AuthorityError::InvalidBinding));
            };
            let page = *page;
            #[cfg(feature = "synthetic-qualification")]
            if let Some(observer) = observer {
                observer.replay_check(HistoryCheckSiteV1::ReplayAfterPage);
            }
            check(check_current)?;
            #[cfg(feature = "synthetic-qualification")]
            if let Some(observer) = observer {
                observer.enter(CheckedHistoryStageV1::Bounds);
            }
            if bounded {
                pages = observed_history_result!(
                    observer,
                    pages.checked_add(1).ok_or(AuthorityError::Permission)
                )?;
                entries = observed_history_result!(
                    observer,
                    entries
                        .checked_add(page.entries.len())
                        .ok_or(AuthorityError::Permission)
                )?;
                bytes = observed_history_result!(
                    observer,
                    bytes
                        .checked_add(
                            observed_history_result!(
                                observer,
                                serde_json::to_vec(&page)
                                    .map_err(|_| AuthorityError::InvalidBinding)
                            )?
                            .len(),
                        )
                        .ok_or(AuthorityError::Permission)
                )?;
                if entries > 65_536 || bytes > 32 * 1024 * 1024 {
                    return observed_history_result!(observer, Err(AuthorityError::Permission));
                }
            }
            #[cfg(feature = "synthetic-qualification")]
            if let Some(observer) = observer {
                observer.enter(CheckedHistoryStageV1::PageValidation);
            }
            if page.snapshot != snapshot
                || observed_history_result!(observer, page.policy.policy_digest())?
                    != self.policy_digest
            {
                return observed_history_result!(observer, Err(AuthorityError::Authentication));
            }
            if ledger.is_none() {
                if let Some(record) = &page.pending_birth_commit {
                    observed_history_result!(observer, record.validate())?;
                    if record.request.policy != page.policy
                        || record.request.disclosure != self.disclosure_descriptor()
                    {
                        return observed_history_result!(
                            observer,
                            Err(AuthorityError::Authentication)
                        );
                    }
                }
                // Positive genesis without original authenticated metadata is
                // not a complete birth provenance history.
                if page.policy.account_use_genesis.is_some() != page.pending_birth_commit.is_some()
                {
                    return observed_history_result!(observer, Err(AuthorityError::CorruptHistory));
                }
                pending_birth_commit = page.pending_birth_commit.clone();
                ledger = Some(observed_history_result!(
                    observer,
                    crate::policy::Ledger::new(page.policy.clone())
                )?);
            }
            let state = observed_history_result!(
                observer,
                ledger.as_mut().ok_or(AuthorityError::CorruptHistory)
            )?;
            if page.policy != state.policy || page.pending_birth_commit != pending_birth_commit {
                return observed_history_result!(observer, Err(AuthorityError::Authentication));
            }
            let before = after;
            #[cfg(feature = "synthetic-qualification")]
            if let Some(observer) = observer {
                observer.enter(CheckedHistoryStageV1::EventReplay);
            }
            for entry in page.entries {
                if entry.sequence != state.snapshot.head.sequence + 1
                    || entry.previous_head != state.snapshot.head.digest
                {
                    return observed_history_result!(observer, Err(AuthorityError::CorruptHistory));
                }
                let event = crate::policy::Event {
                    original_request_link: entry.original_request_link,
                    mutation: entry.mutation,
                    authenticated_certificate_digest: entry.authenticated_certificate_digest,
                    witness_time_ms: entry.witness_time_ms,
                    writer_session_id: entry.writer_session_id,
                };
                let previous = state.snapshot.clone();
                match observed_history_result!(observer, match profile {
                    crate::journal::OriginalHistoryProfileV1::Legacy => state.apply(&event),
                    crate::journal::OriginalHistoryProfileV1::FinancialContinuation => state.apply_financial_continuation_v1(&event),
                })? {
                    MutationResult::Reserved(permit) => permits.push(*permit),
                    MutationResult::CompletedDispatchAdmittedV1(admission) => completed_dispatches_v1.push(*admission),
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
                    return observed_history_result!(observer, Err(AuthorityError::CorruptHistory));
                }
                history_heads.insert(entry.sequence, entry.head.clone());
                after = entry.sequence;
            }
            #[cfg(feature = "synthetic-qualification")]
            if let Some(observer) = observer {
                observer.enter(CheckedHistoryStageV1::PageValidation);
            }
            if after == before && after < snapshot.head.sequence {
                return observed_history_result!(observer, Err(AuthorityError::CorruptHistory));
            }
            match page.next_after_sequence {
                Some(next) if next == after && next < snapshot.head.sequence => continue,
                None if after == snapshot.head.sequence => break,
                _ => {
                    return observed_history_result!(observer, Err(AuthorityError::CorruptHistory));
                }
            }
        }
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.enter(CheckedHistoryStageV1::FinalValidation);
        }
        let ledger =
            observed_history_result!(observer, ledger.ok_or(AuthorityError::CorruptHistory))?;
        observed_history_result!(
            observer,
            ledger.validate_manual_birth(pending_birth_commit.as_ref())
        )?;
        observed_history_result!(
            observer,
            ledger.validate_durable_payment_birth_v1(pending_birth_commit.as_ref())
        )?;
        observed_history_result!(
            observer,
            match profile {
                crate::journal::OriginalHistoryProfileV1::Legacy => ledger.validate_durable_delivery_birth_v2(pending_birth_commit.as_ref()),
                crate::journal::OriginalHistoryProfileV1::FinancialContinuation => ledger.validate_financial_continuation_birth_v1(pending_birth_commit.as_ref()),
            }
        )?;
        observed_history_result!(
            observer,
            ledger.validate_born_offline_birth_v1(pending_birth_commit.as_ref())
        )?;
        let manual_roster_attempt =
            if observed_history_result!(observer, ledger.manual_roster_extension())?.is_some() {
                Some(observed_history_result!(
                    observer,
                    ledger.latest_manual_roster_attempt_v2()
                )?)
            } else {
                None
            };
        let manual_attempt = if manual_roster_attempt.is_none()
            && observed_history_result!(observer, ledger.manual_extension())?.is_some()
        {
            Some(observed_history_result!(
                observer,
                ledger.latest_manual_attempt()
            )?)
        } else {
            None
        };
        let manual_roster_construction_records = ledger.roster_construction_history_v2();
        let manual_roster_construction_records_v3 = ledger.roster_construction_history_v3();
        let construction_transport_history = ledger.construction_transport_history_v1();
        let durable_payment_history_supported_v1 = ledger
            .require_supported_durable_payment_history_v1()
            .is_ok();
        let account_use_history = ledger.account_use_history;
        let account_policy = ledger.policy;
        let mut computed = ledger.snapshot;
        // A restored database's independent one-way quarantine is not an event
        // that rewrites its historical hash chain. It never enables acquisition.
        if snapshot.writer_status == WriterStatus::Quarantined {
            computed.writer_status = WriterStatus::Quarantined;
        }
        if computed != snapshot {
            return observed_history_result!(observer, Err(AuthorityError::CorruptHistory));
        }
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.replay_check(HistoryCheckSiteV1::ReplayFinal);
        }
        check(check_current)?;
        Ok(ReconciledAuthorityHistory {
            durable_payment_history_supported_v1,
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
            completed_dispatches_v1,
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
        history.require_no_durable_payment_v1()?;
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
        history.require_no_durable_payment_v1()?;
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
        self.reserve_observed(
            request,
            #[cfg(feature = "synthetic-qualification")]
            None,
        )
    }
    /// Data-only evidence from the ordinary no-caller-deadline reserve kernel.
    #[cfg(feature = "synthetic-qualification")]
    pub fn reserve_diagnosed(
        &self,
        request: ReserveAuthorization,
    ) -> std::result::Result<AuthenticatedPermit, history_diagnostics_v1::CheckedHistoryFailureV1>
    {
        let observer = HistoryObserverV1::with_flow_deadline(None);
        self.reserve_observed(request, Some(&observer))
            .map_err(|error| observer.into_failure(error))
    }
    fn reserve_observed(
        &self,
        request: ReserveAuthorization,
        #[cfg(feature = "synthetic-qualification")] observer: Option<&HistoryObserverV1>,
    ) -> Result<AuthenticatedPermit> {
        observed_flow_result!(observer, FlowRequestValidation, request.validate())?;
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.enter(CheckedHistoryStageV1::FlowBinding);
        }
        if request.account_id != self.account || request.network_profile_id != self.network {
            return observed_history_result!(observer, Err(AuthorityError::InvalidBinding));
        }
        let session = observed_flow_result!(
            observer,
            FlowSession,
            self.session
                .lock()
                .map_err(|_| AuthorityError::SessionRequired)
        )?;
        let session = observed_history_result!(
            observer,
            session
                .as_ref()
                .filter(|s| s.receipt.is_some())
                .ok_or(AuthorityError::SessionRequired)
        )?;
        let mutation = AuthorityMutation::ReserveAuthorization(Box::new(request.clone()));
        let build = |exporter: &[u8; 32]| {
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
        };
        #[cfg(feature = "synthetic-qualification")]
        let response = match observer {
            Some(observer) => {
                self.call_with_inner(build, None, Some((observer, HistoryPhaseV1::Reserve)))
            }
            None => self.call_with(build),
        }?;
        #[cfg(not(feature = "synthetic-qualification"))]
        let response = self.call_with(build)?;
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.enter(CheckedHistoryStageV1::FlowResponse);
        }
        match response {
            WireResponse::Mutation(MutationResult::Reserved(p)) => {
                observed_flow_result!(
                    observer,
                    FlowReceiptValidation,
                    p.matches_request(&request)
                )?;
                if p.witness_id != self.witness || p.policy_digest != self.policy_digest {
                    return observed_history_result!(observer, Err(AuthorityError::Authentication));
                }
                observed_flow_result!(
                    observer,
                    FlowCommittedHeadValidation,
                    self.check_committed_head(
                        &request.expected_head,
                        &p.committed_head,
                        AuthorityMutation::ReserveAuthorization(Box::new(request.clone())),
                        p.reserved_at_ms,
                        Some(p.writer_session_id.clone()),
                    )
                )?;
                Ok(AuthenticatedPermit {
                    descriptor: *p,
                    certificate_digest: self.tls.pinned_certificate.clone(),
                })
            }
            _ => observed_history_result!(observer, Err(AuthorityError::InvalidBinding)),
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
        self.call_with_inner(
            build,
            None,
            #[cfg(feature = "synthetic-qualification")]
            None,
        )
    }
    fn call_with_until(
        &self,
        deadline: Instant,
        build: impl FnOnce(&[u8; 32]) -> Result<WireRequest>,
    ) -> Result<WireResponse> {
        self.call_with_inner(
            build,
            Some(deadline),
            #[cfg(feature = "synthetic-qualification")]
            None,
        )
    }
    fn call_with_inner(
        &self,
        build: impl FnOnce(&[u8; 32]) -> Result<WireRequest>,
        caller_deadline: Option<Instant>,
        #[cfg(feature = "synthetic-qualification")] observation: Option<(
            &HistoryObserverV1,
            HistoryPhaseV1,
        )>,
    ) -> Result<WireResponse> {
        self.call_with_inner_checked_observed(
            build,
            caller_deadline,
            || Ok(()),
            #[cfg(feature = "synthetic-qualification")]
            observation,
        )
    }
    // A cancellation check is not a permission factory. Native callers retain
    // their actual owner and original absolute deadline through this exchange.
    fn call_with_inner_checked(
        &self,
        build: impl FnOnce(&[u8; 32]) -> Result<WireRequest>,
        caller_deadline: Option<Instant>,
        current: impl FnMut() -> Result<()>,
    ) -> Result<WireResponse> {
        self.call_with_inner_checked_observed(
            build,
            caller_deadline,
            current,
            #[cfg(feature = "synthetic-qualification")]
            None,
        )
    }
    fn open_authenticated_stream_checked(
        &self,
        deadline: Instant,
        caller_deadline: Option<Instant>,
        check: &mut impl FnMut() -> Result<()>,
        connect_failure: Option<&mut Option<std::io::ErrorKind>>,
        #[cfg(feature = "synthetic-qualification")] observation: Option<(&HistoryObserverV1, HistoryPhaseV1)>,
    ) -> Result<(ClientConnection, CallerDeadlineSocket, Zeroizing<[u8; 32]>)> {
        self.open_authenticated_stream_checked_with_socket(deadline, caller_deadline, check,
            connect_failure, None, |socket| socket, #[cfg(feature = "synthetic-qualification")] observation)
    }
    // The per-call restriction borrows the actual action owner. It never enters
    // client/session storage and cannot outlive or renew the original approval.
    fn open_authenticated_stream_checked_restricted<'call>(
        &self,
        deadline: Instant,
        caller_deadline: Option<Instant>,
        check: &mut impl FnMut() -> Result<()>,
        connect_failure: Option<&mut Option<std::io::ErrorKind>>,
        call_restriction: Option<&'call dyn Fn() -> Result<()>>,
        #[cfg(feature = "synthetic-qualification")] observation: Option<(&HistoryObserverV1, HistoryPhaseV1)>,
    ) -> Result<(ClientConnection, BorrowedCallerDeadlineSocket<'call>, Zeroizing<[u8; 32]>)> {
        self.open_authenticated_stream_checked_with_socket(deadline, caller_deadline, check,
            connect_failure, call_restriction,
            |inner| BorrowedCallerDeadlineSocket { inner, call_restriction },
            #[cfg(feature = "synthetic-qualification")] observation)
    }
    fn open_authenticated_stream_checked_with_socket<Socket: Read + Write>(
        &self,
        deadline: Instant,
        caller_deadline: Option<Instant>,
        check: &mut impl FnMut() -> Result<()>,
        connect_failure: Option<&mut Option<std::io::ErrorKind>>,
        call_restriction: Option<&dyn Fn() -> Result<()>>,
        wrap: impl FnOnce(CallerDeadlineSocket) -> Socket,
        #[cfg(feature = "synthetic-qualification")] observation: Option<(&HistoryObserverV1, HistoryPhaseV1)>,
    ) -> Result<(ClientConnection, Socket, Zeroizing<[u8; 32]>)> {
        #[cfg(feature = "synthetic-qualification")]
        let observer = observation.map(|(observer, _)| observer);
        #[cfg(feature = "synthetic-qualification")]
        let deadline_stage = history_diagnostics_v1::selected_deadline_stage(deadline, caller_deadline);
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.checkpoint(HistoryCheckpointV1::ConnectRemaining);
        }
        let connect_timeout = if caller_deadline.is_some() {
            caller_remaining_at(deadline, Instant::now()).map_err(|error| {
                #[cfg(feature = "synthetic-qualification")]
                if let Some(observer) = observer {
                    observer.record(deadline_stage, None, error);
                }
                error
            })?
        } else {
            IO_TIMEOUT
        };
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.exchange_check(HistoryCheckSiteV1::BeforeConnect);
        }
        check()?;
        #[cfg(feature = "synthetic-qualification")]
        if let Some((observer, phase)) = observation {
            observer.enter(phase.stage(HistoryCallStepV1::Connect));
        }
        #[cfg(feature = "synthetic-qualification")]
        let connect_token =
            observer.map(|observer| observer.start_operation(HistoryOperationV1::Connect));
        let restricted = self.restriction.is_some() || call_restriction.is_some();
        // Heavy source checks above may consume time. A restricted call uses
        // the SAME absolute deadline, resampled immediately before connect.
        let connect_timeout = if restricted {
            caller_remaining_at(deadline, Instant::now())?
        } else { connect_timeout };
        check_transport_restrictions_v2(self.restriction.as_deref(), call_restriction)?;
        let connected = TcpStream::connect_timeout(&self.endpoint, connect_timeout);
        let post_connect = if restricted {
            check_transport_restrictions_v2(self.restriction.as_deref(), call_restriction)
                .and_then(|()| require_before_caller_deadline(deadline))
        } else { Ok(()) };
        // V3 discovery may distinguish only an actual failure of this original
        // preconnection operation. No TLS, framing or later failure updates it.
        // Legacy callers pass None and retain their original result mapping.
        if let (Some(failure), Err(error)) = (connect_failure, &connected) {
            *failure = Some(error.kind());
        }
        #[cfg(feature = "synthetic-qualification")]
        let connected = match observer {
            Some(observer) => observer.observe_io(connected),
            None => connected,
        };
        let connected = connected.map_err(|_| AuthorityError::Uncertain);
        #[cfg(feature = "synthetic-qualification")]
        let connected =
            history_diagnostics_v1::finish_operation_observed(observer, connect_token, connected);
        let socket = connected?;
        // Preserve an actual failed connect above (and its V3 classification).
        // Only a successful socket can be refused by the later restriction.
        observed_history_result!(observer, post_connect)?;
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.exchange_check(HistoryCheckSiteV1::AfterConnect);
        }
        check()?;
        let mut socket = wrap(CallerDeadlineSocket {
            inner: DeadlineSocket { socket, deadline },
            check_after_io: caller_deadline.is_some(),
            restriction: self.restriction.clone(),
        });
        #[cfg(feature = "synthetic-qualification")]
        if let Some((observer, phase)) = observation {
            observer.enter(phase.stage(HistoryCallStepV1::Handshake));
        }
        let mut connection = observed_history_result!(
            observer,
            ClientConnection::new(self.tls.config.clone(), self.tls.server_name.clone())
                .map_err(|_| AuthorityError::Authentication)
        )?;
        while connection.is_handshaking() {
            #[cfg(feature = "synthetic-qualification")]
            if let Some(observer) = observer {
                observer.exchange_check(HistoryCheckSiteV1::BeforeHandshakeIo);
            }
            check()?;
            #[cfg(feature = "synthetic-qualification")]
            if let Some((observer, phase)) = observation {
                observer.enter(phase.stage(HistoryCallStepV1::Handshake));
            }
            #[cfg(feature = "synthetic-qualification")]
            let handshake_token =
                observer.map(|observer| observer.start_operation(HistoryOperationV1::Handshake));
            let completed = connection.complete_io(&mut socket);
            #[cfg(feature = "synthetic-qualification")]
            let completed = match observer {
                Some(observer) => observer.observe_io(completed),
                None => completed,
            };
            let completed = completed.map_err(|_| AuthorityError::Authentication);
            #[cfg(feature = "synthetic-qualification")]
            let completed = history_diagnostics_v1::finish_operation_observed(
                observer,
                handshake_token,
                completed,
            );
            completed?;
        }
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.exchange_check(HistoryCheckSiteV1::AfterHandshake);
        }
        check()?;
        #[cfg(feature = "synthetic-qualification")]
        if let Some((observer, phase)) = observation {
            observer.enter(phase.stage(HistoryCallStepV1::PeerBinding));
        }
        let peer = observed_history_result!(
            observer,
            connection
                .peer_certificates()
                .and_then(|c| c.first())
                .ok_or(AuthorityError::Authentication)
        )?;
        if certificate_digest(peer) != self.tls.pinned_certificate
            || connection.alpn_protocol() != Some(ALPN)
        {
            return observed_history_result!(observer, Err(AuthorityError::Authentication));
        }
        let exporter = Zeroizing::new(observed_history_result!(
            observer,
            connection
                .export_keying_material([0_u8; 32], crate::session::EXPORTER_LABEL, None)
                .map_err(|_| AuthorityError::Authentication)
        )?);
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.exchange_check(HistoryCheckSiteV1::AfterPeerBinding);
        }
        check()?;
        Ok((connection, socket, exporter))
    }
    // One shared kernel: existing callers pass no diagnostic observer.
    fn call_with_inner_checked_observed(
        &self,
        build: impl FnOnce(&[u8; 32]) -> Result<WireRequest>,
        caller_deadline: Option<Instant>,
        current: impl FnMut() -> Result<()>,
        #[cfg(feature = "synthetic-qualification")] observation: Option<(&HistoryObserverV1, HistoryPhaseV1)>,
    ) -> Result<WireResponse> {
        self.call_with_inner_checked_restricted_observed(build, caller_deadline, current, None,
            #[cfg(feature = "synthetic-qualification")] observation)
    }
    fn call_with_inner_checked_restricted_observed(
        &self,
        build: impl FnOnce(&[u8; 32]) -> Result<WireRequest>,
        caller_deadline: Option<Instant>,
        mut current: impl FnMut() -> Result<()>,
        call_restriction: Option<&dyn Fn() -> Result<()>>,
        #[cfg(feature = "synthetic-qualification")] observation: Option<(&HistoryObserverV1, HistoryPhaseV1)>,
    ) -> Result<WireResponse> {
        #[cfg(feature = "synthetic-qualification")]
        let observer = observation.map(|(observer, _)| observer);
        #[cfg(feature = "synthetic-qualification")]
        if let Some((observer, phase)) = observation {
            observer.begin_exchange(phase);
        }
        #[cfg(feature = "synthetic-qualification")]
        let checked = history_diagnostics_v1::callback_observed(observer, || current());
        #[cfg(not(feature = "synthetic-qualification"))]
        let checked = current();
        checked.map_err(|error| {
            #[cfg(feature = "synthetic-qualification")]
            if let Some(observer) = observer {
                observer.record(CheckedHistoryStageV1::SourceCallback, None, error);
            }
            error
        })?;
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.checkpoint(HistoryCheckpointV1::DeadlineSelection);
        }
        let started = Instant::now();
        let deadline = match caller_deadline {
            Some(deadline) => {
                bounded_transport_deadline_at(started, deadline).map_err(|error| {
                    #[cfg(feature = "synthetic-qualification")]
                    if let Some(observer) = observer {
                        observer.record(CheckedHistoryStageV1::CallerDeadline, None, error);
                    }
                    error
                })?
            }
            None => started + IO_TIMEOUT,
        };
        #[cfg(feature = "synthetic-qualification")]
        let deadline_stage =
            history_diagnostics_v1::selected_deadline_stage(deadline, caller_deadline);
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.select_deadline(started, deadline);
        }
        let mut check = || -> Result<()> {
            if caller_deadline.is_some() {
                require_before_caller_deadline(deadline).map_err(|error| {
                    #[cfg(feature = "synthetic-qualification")]
                    if let Some(observer) = observer {
                        observer.record(deadline_stage, None, error);
                    }
                    error
                })?;
            }
            #[cfg(feature = "synthetic-qualification")]
            let checked = history_diagnostics_v1::callback_observed(observer, || current());
            #[cfg(not(feature = "synthetic-qualification"))]
            let checked = current();
            checked.map_err(|error| {
                #[cfg(feature = "synthetic-qualification")]
                if let Some(observer) = observer {
                    observer.record(CheckedHistoryStageV1::SourceCallback, None, error);
                }
                error
            })?;
            #[cfg(feature = "synthetic-qualification")]
            if let Some(observer) = observer {
                observer.checkpoint(HistoryCheckpointV1::AfterCallback);
            }
            if caller_deadline.is_some() {
                require_before_caller_deadline(deadline).map_err(|error| {
                    #[cfg(feature = "synthetic-qualification")]
                    if let Some(observer) = observer {
                        observer.record(deadline_stage, None, error);
                    }
                    error
                })?;
            }
            Ok(())
        };
        let (connection, socket, exporter) = self.open_authenticated_stream_checked_restricted(
            deadline, caller_deadline, &mut check, None, call_restriction,
            #[cfg(feature = "synthetic-qualification")]
            observation,
        )?;
        #[cfg(feature = "synthetic-qualification")]
        if let Some((observer, phase)) = observation {
            observer.enter(phase.stage(HistoryCallStepV1::RequestBuild));
        }
        let request = observed_history_result!(observer, build(&exporter))?;
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.exchange_check(HistoryCheckSiteV1::AfterRequestBuild);
        }
        check()?;
        let mut stream = StreamOwned::new(connection, socket);
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.exchange_check(HistoryCheckSiteV1::BeforeRequestWrite);
        }
        check()?;
        #[cfg(feature = "synthetic-qualification")]
        if let Some((observer, phase)) = observation {
            observer.enter(phase.stage(HistoryCallStepV1::RequestWrite));
        }
        // From this write onward cancellation cannot promise remote rollback.
        #[cfg(feature = "synthetic-qualification")]
        let written = history_diagnostics_v1::write_frame_observed(&mut stream, &request, observer);
        #[cfg(not(feature = "synthetic-qualification"))]
        let written = write_frame(&mut stream, &request);
        written.map_err(|_| AuthorityError::Uncertain)?;
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.exchange_check(HistoryCheckSiteV1::AfterRequestWrite);
        }
        check()?;
        #[cfg(feature = "synthetic-qualification")]
        if let Some((observer, phase)) = observation {
            observer.enter(phase.stage(HistoryCallStepV1::ResponseRead));
        }
        #[cfg(feature = "synthetic-qualification")]
        let read = history_diagnostics_v1::read_frame_observed(&mut stream, observer);
        #[cfg(not(feature = "synthetic-qualification"))]
        let read = read_frame(&mut stream);
        let response = read.map_err(|_| AuthorityError::Uncertain)?;
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.exchange_check(HistoryCheckSiteV1::AfterResponseRead);
        }
        check()?;
        #[cfg(feature = "synthetic-qualification")]
        if let Some((observer, phase)) = observation {
            observer.enter(phase.stage(HistoryCallStepV1::Response));
        }
        let response = observed_history_result!(
            observer,
            match response {
                WireResponse::Rejected(e) => Err(e),
                response => Ok(response),
            }
        );
        finish_checked_exchange_observed(
            response,
            #[cfg(feature = "synthetic-qualification")]
            observer,
        )
    }
}

// The original success-only reset runs before caller postresponse validation.
// This helper moves the unchanged Result and owns no transport resource.
fn finish_checked_exchange_observed<T>(
    response: Result<T>,
    #[cfg(feature = "synthetic-qualification")] observer: Option<&HistoryObserverV1>,
) -> Result<T> {
    #[cfg(feature = "synthetic-qualification")]
    if response.is_ok() {
        if let Some(observer) = observer {
            observer.end_exchange();
        }
    }
    response
}

#[derive(Clone)]
pub struct AuthorityServer {
    journal: Arc<AuthorityJournal>,
    tls: ServerTls,
    handoff_scope: Option<construction_transport_server_v1::ConstructionTransportServingScopeV1>,
    #[cfg(feature = "synthetic-qualification")]
    admission_observer: Option<admission_diagnostics_v1::AdmissionWitnessObserverV1>,
    #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
    durable_payment: Option<Arc<durable_payment_server_v1::DurablePaymentServingV1>>,
    #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
    financial_signing: Option<Arc<financial_signing_server_v1::FinancialSigningServingV1>>,
    #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
    completed_dispatch_v1: Option<Arc<std::collections::BTreeMap<String, Arc<crate::durable_financial_continuation_owner_v1::ConfiguredFinancialWitnessV1>>>>,
    #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
    durable_delivery_admission_v2: Option<Arc<std::sync::Mutex<crate::durable_delivery_admission_owner_v2::NativeDurableDeliveryAdmissionSourceV2>>>,
    #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
    financial_continuation_v1: Option<Arc<std::sync::Mutex<crate::durable_financial_continuation_owner_v1::NativeFinancialContinuationSourceV1>>>,
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
            #[cfg(feature = "synthetic-qualification")]
            admission_observer: None,
            #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
            durable_payment: None,
            #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
            financial_signing: None,
            #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
            completed_dispatch_v1: None,
            #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
            durable_delivery_admission_v2: None,
            #[cfg(all(feature = "native-witness-owner", target_os = "linux"))]
            financial_continuation_v1: None,
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
        #[cfg(feature = "synthetic-qualification")]
        let observer = self.admission_observer.as_ref();
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.begin_connection();
        }
        let result = admission_measure!(
            observer,
            Connection,
            self.serve_connection_before_observed(socket, deadline)
        );
        let result = admission_result!(observer, observe_connection, result);
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = observer {
            observer.end_connection();
        }
        result
    }
    fn serve_connection_before_observed(&self, socket: TcpStream, deadline: Instant) -> Result<()> {
        #[cfg(feature = "synthetic-qualification")]
        let observer = self.admission_observer.as_ref();
        admission_stage!(observer, SocketBinding);
        self.require_durable_payment_socket_v1(&socket)?;
        self.require_financial_signing_socket_v1(&socket)?;
        self.require_durable_delivery_socket_v2(&socket)?;
        self.require_financial_continuation_socket_v1(&socket)?;
        self.completed_dispatch_wait_v1(Some(&socket))?;
        admission_stage!(observer, WaitCurrent);
        self.check_durable_payment_wait_v1()?;
        self.check_financial_signing_wait_v1()?;
        self.check_durable_delivery_wait_v2()?;
        self.check_financial_continuation_wait_v1()?;
        self.completed_dispatch_wait_v1(None)?;
        let mut socket = DeadlineSocket { socket, deadline };
        admission_stage!(observer, TlsSetup);
        let mut connection = ServerConnection::new(self.tls.config.clone())
            .map_err(|_| AuthorityError::Authentication)?;
        while connection.is_handshaking() {
            admission_stage!(observer, WaitCurrent);
            self.check_durable_payment_wait_v1()?;
        self.check_financial_signing_wait_v1()?;
            self.check_durable_delivery_wait_v2()?;
        self.check_financial_continuation_wait_v1()?;
        self.completed_dispatch_wait_v1(None)?;
            admission_stage!(observer, TlsHandshake);
            let completed =
                admission_measure!(observer, Handshake, connection.complete_io(&mut socket));
            #[cfg(feature = "synthetic-qualification")]
            let completed = match observer {
                Some(observer) => observer.observe_io(completed),
                None => completed,
            };
            completed.map_err(|_| AuthorityError::Authentication)?;
        }
        admission_stage!(observer, WaitCurrent);
        self.check_durable_payment_wait_v1()?;
        self.check_financial_signing_wait_v1()?;
        self.check_durable_delivery_wait_v2()?;
        self.check_financial_continuation_wait_v1()?;
        self.completed_dispatch_wait_v1(None)?;
        admission_stage!(observer, PeerBinding);
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
        admission_stage!(observer, WaitCurrent);
        self.check_durable_payment_wait_v1()?;
        self.check_financial_signing_wait_v1()?;
        self.check_durable_delivery_wait_v2()?;
        self.check_financial_continuation_wait_v1()?;
        self.completed_dispatch_wait_v1(None)?;
        admission_stage!(observer, FrameRead);
        #[cfg(feature = "synthetic-qualification")]
        let request: WireRequest = admission_diagnostics_v1::read_frame(&mut stream, observer)?;
        #[cfg(not(feature = "synthetic-qualification"))]
        let request: WireRequest = read_frame(&mut stream)?;
        admission_stage!(observer, WaitCurrent);
        self.check_durable_payment_wait_v1()?;
        self.check_financial_signing_wait_v1()?;
        self.check_durable_delivery_wait_v2()?;
        self.check_financial_continuation_wait_v1()?;
        self.completed_dispatch_wait_v1(None)?;
        if let WireRequest::PrepareDurableDeliveryAdmissionV3(preparation) = &request {
            return self.serve_durable_delivery_admission_v3(stream, &peer, preparation.clone());
        }
        if self.is_durable_delivery_admission_v2() {
            admission_stage!(observer, SemanticDispatch);
            let response = admission_measure!(
                observer,
                Dispatch,
                self.serve_durable_delivery_admission_v2(&peer, request)
            );
            let response = admission_result!(observer, observe_semantic, response)
                .unwrap_or_else(WireResponse::Rejected);
            admission_stage!(observer, OutputCheck);
            self.check_durable_delivery_output_v2(&response)?;
            admission_stage!(observer, FrameWrite);
            #[cfg(feature = "synthetic-qualification")]
            admission_diagnostics_v1::write_frame(&mut stream, &response, observer)?;
            #[cfg(not(feature = "synthetic-qualification"))]
            write_frame(&mut stream, &response)?;
            admission_stage!(observer, CloseFlush);
            stream.conn.send_close_notify();
            let flushed = stream.flush();
            #[cfg(feature = "synthetic-qualification")]
            let flushed = match observer {
                Some(observer) => observer.observe_io(flushed),
                None => flushed,
            };
            flushed.map_err(|_| AuthorityError::Uncertain)?;
            return Ok(());
        }
        if self.is_financial_continuation_v1() {
            admission_stage!(observer, SemanticDispatch);
            let response = admission_measure!(
                observer,
                Dispatch,
                self.serve_financial_continuation_v1(&peer, request)
            );
            let response = admission_result!(observer, observe_semantic, response)
                .unwrap_or_else(WireResponse::Rejected);
            admission_stage!(observer, OutputCheck);
            self.check_financial_continuation_output_v1(&response)?;
            admission_stage!(observer, FrameWrite);
            #[cfg(feature = "synthetic-qualification")]
            admission_diagnostics_v1::write_frame(&mut stream, &response, observer)?;
            #[cfg(not(feature = "synthetic-qualification"))]
            write_frame(&mut stream, &response)?;
            admission_stage!(observer, CloseFlush);
            stream.conn.send_close_notify();
            let flushed = stream.flush();
            #[cfg(feature = "synthetic-qualification")]
            let flushed = match observer {
                Some(observer) => observer.observe_io(flushed),
                None => flushed,
            };
            flushed.map_err(|_| AuthorityError::Uncertain)?;
            return Ok(());
        }
        if self.is_completed_dispatch_v1() {
            let response = self.serve_completed_dispatch_v1(&peer, request).unwrap_or_else(WireResponse::Rejected);
            self.completed_dispatch_wait_v1(None)?;
            write_frame(&mut stream, &response)?;
            stream.conn.send_close_notify();
            stream.flush().map_err(|_| AuthorityError::Uncertain)?;
            return Ok(());
        }
        if self.is_financial_signing_server_v1() {
            let response = self.serve_financial_signing_request_v1(&peer, &exporter, request).unwrap_or_else(WireResponse::Rejected);
            self.check_financial_signing_output_v1(&response)?;
            write_frame(&mut stream, &response)?;
            stream.conn.send_close_notify();
            stream.flush().map_err(|_| AuthorityError::Uncertain)?;
            return Ok(());
        }
        if self.is_durable_payment_server_v1() {
            #[cfg(all(
                feature = "synthetic-qualification",
                feature = "native-witness-owner",
                target_os = "linux"
            ))]
            let reply_loss_candidate =
                self.durable_acquire_reply_loss_candidate_v1(&peer, &exporter, &request);
            admission_stage!(observer, SemanticDispatch);
            let response = admission_measure!(
                observer,
                Dispatch,
                self.serve_durable_payment_request_v1(&peer, &exporter, request)
            );
            let response = admission_result!(observer, observe_semantic, response);
            // Only this connection's successful real dispatch can yield the
            // fresh-commit observation. It cannot consume the one-shot yet.
            #[cfg(all(
                feature = "synthetic-qualification",
                feature = "native-witness-owner",
                target_os = "linux"
            ))]
            let committed_reply = reply_loss_candidate.and_then(|c| c.after_dispatch(&response));
            let response = response.unwrap_or_else(WireResponse::Rejected);
            admission_stage!(observer, OutputCheck);
            self.check_durable_payment_output_v1(&response)?;
            #[cfg(all(
                feature = "synthetic-qualification",
                feature = "native-witness-owner",
                target_os = "linux"
            ))]
            let selected_reply = committed_reply.and_then(|c| c.after_output_check());
            #[cfg(all(
                feature = "synthetic-qualification",
                feature = "native-witness-owner",
                target_os = "linux"
            ))]
            if let Some(selected) = &selected_reply {
                // Do not return this syscall's result or skip the normal write.
                // The selected receipt has already committed, and every state
                // lock was released before touching this exact socket.
                let shutdown = stream.sock.socket.shutdown(std::net::Shutdown::Both);
                selected.observe_shutdown(&shutdown);
            }
            admission_stage!(observer, FrameWrite);
            #[cfg(all(
                feature = "synthetic-qualification",
                feature = "native-witness-owner",
                target_os = "linux"
            ))]
            durable_acquire_reply_loss_v1::write_frame(
                &mut stream,
                &response,
                observer,
                selected_reply,
            )?;
            #[cfg(all(
                feature = "synthetic-qualification",
                not(all(feature = "native-witness-owner", target_os = "linux"))
            ))]
            admission_diagnostics_v1::write_frame(&mut stream, &response, observer)?;
            #[cfg(not(feature = "synthetic-qualification"))]
            write_frame(&mut stream, &response)?;
            admission_stage!(observer, CloseFlush);
            stream.conn.send_close_notify();
            let flushed = stream.flush();
            #[cfg(feature = "synthetic-qualification")]
            let flushed = match observer {
                Some(observer) => observer.observe_io(flushed),
                None => flushed,
            };
            flushed.map_err(|_| AuthorityError::Uncertain)?;
            return Ok(());
        }
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
            WireRequest::PrepareDurableDeliveryAdmissionV3(_) => Err(AuthorityError::Permission),
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
        use std::sync::{mpsc, Mutex};
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
    restriction: Option<std::sync::Arc<dyn AuthorityTransportRestrictionV1>>,
}
struct BorrowedCallerDeadlineSocket<'call> {
    inner: CallerDeadlineSocket,
    call_restriction: Option<&'call dyn Fn() -> Result<()>>,
}
// The timeout is installed by the caller before this zero-wait final sample.
// This orders the one attempt against restriction; it does not make a syscall
// atomic with cancellation or retract bytes from an already-admitted attempt.
#[cfg(test)]
fn restricted_transport_io_v1<T>(
    restriction: &dyn AuthorityTransportRestrictionV1,
    attempt: impl FnOnce() -> std::io::Result<T>,
) -> std::io::Result<T> {
    restriction.check_before_io().map_err(|_| std::io::Error::new(
        std::io::ErrorKind::PermissionDenied, "original transport restriction"))?;
    attempt()
}
fn check_transport_restrictions_v2(
    original: Option<&dyn AuthorityTransportRestrictionV1>,
    call: Option<&dyn Fn() -> Result<()>>,
) -> Result<()> {
    if let Some(call) = call { call()?; }
    if let Some(original) = original { original.check_before_io()?; }
    Ok(())
}
fn borrowed_restricted_transport_io_v2<T>(
    original: Option<&dyn AuthorityTransportRestrictionV1>,
    call: Option<&dyn Fn() -> Result<()>>,
    attempt: impl FnOnce() -> std::io::Result<T>,
) -> std::io::Result<T> {
    let check = || check_transport_restrictions_v2(original, call).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::PermissionDenied, "original transport restriction")
    });
    check()?;
    let result = attempt();
    let after = check();
    // An admitted syscall may already have sent bytes. A later denial cannot
    // roll that back; callers retain their existing uncertain-outcome contract.
    match result { Err(error) => Err(error), Ok(value) => { after?; Ok(value) } }
}
fn finish_caller_io_v2<T>(
    result: std::io::Result<T>,
    remaining: std::io::Result<Duration>,
    restricted: bool,
) -> std::io::Result<T> {
    // Original unrestricted callers retain their exact deadline/error order.
    if !restricted { remaining?; return result; }
    match result { Err(error) => Err(error), Ok(value) => { remaining?; Ok(value) } }
}
impl CallerDeadlineSocket {
    fn read_restricted(&mut self, bytes: &mut [u8], call: Option<&dyn Fn() -> Result<()>>) -> std::io::Result<usize> {
        let restricted = self.restriction.is_some() || call.is_some();
        let result = if restricted {
            self.inner.socket.set_read_timeout(Some(self.inner.remaining()?))?;
            borrowed_restricted_transport_io_v2(self.restriction.as_deref(), call,
                || self.inner.socket.read(bytes))
        } else { self.inner.read(bytes) };
        if self.check_after_io {
            finish_caller_io_v2(result, self.inner.remaining(), restricted)
        } else { result }
    }
    fn write_restricted(&mut self, bytes: &[u8], call: Option<&dyn Fn() -> Result<()>>) -> std::io::Result<usize> {
        let restricted = self.restriction.is_some() || call.is_some();
        let result = if restricted {
            self.inner.socket.set_write_timeout(Some(self.inner.remaining()?))?;
            borrowed_restricted_transport_io_v2(self.restriction.as_deref(), call,
                || self.inner.socket.write(bytes))
        } else { self.inner.write(bytes) };
        if self.check_after_io {
            finish_caller_io_v2(result, self.inner.remaining(), restricted)
        } else { result }
    }
    fn flush_restricted(&mut self, call: Option<&dyn Fn() -> Result<()>>) -> std::io::Result<()> {
        let restricted = self.restriction.is_some() || call.is_some();
        let result = if restricted {
            self.inner.socket.set_write_timeout(Some(self.inner.remaining()?))?;
            borrowed_restricted_transport_io_v2(self.restriction.as_deref(), call,
                || self.inner.socket.flush())
        } else { self.inner.flush() };
        if self.check_after_io {
            finish_caller_io_v2(result, self.inner.remaining(), restricted)
        } else { result }
    }
}
impl Read for CallerDeadlineSocket {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> { self.read_restricted(bytes, None) }
}
impl Write for CallerDeadlineSocket {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> { self.write_restricted(bytes, None) }
    fn flush(&mut self) -> std::io::Result<()> { self.flush_restricted(None) }
}
impl Read for BorrowedCallerDeadlineSocket<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read_restricted(bytes, self.call_restriction)
    }
}
impl Write for BorrowedCallerDeadlineSocket<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.inner.write_restricted(bytes, self.call_restriction)
    }
    fn flush(&mut self) -> std::io::Result<()> { self.inner.flush_restricted(self.call_restriction) }
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
        let mut completed_dispatches_v1 = Vec::new();
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
                    MutationResult::CompletedDispatchAdmittedV1(admission) => completed_dispatches_v1.push(*admission),
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
            durable_payment_history_supported_v1: false,
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
            completed_dispatches_v1,
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
        let mut completed_dispatches_v1 = Vec::new();
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
                    MutationResult::CompletedDispatchAdmittedV1(admission) => completed_dispatches_v1.push(*admission),
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
        ledger.validate_durable_payment_birth_v1(pending_birth_commit.as_ref())?;
        ledger.validate_durable_delivery_birth_v2(pending_birth_commit.as_ref())?;
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
        let durable_payment_history_supported_v1 = ledger
            .require_supported_durable_payment_history_v1()
            .is_ok();
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
            durable_payment_history_supported_v1,
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
            completed_dispatches_v1,
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

#[cfg(test)]
mod transport_restriction_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    struct Restriction { revoked: AtomicBool, samples: AtomicUsize }
    impl AuthorityTransportRestrictionV1 for Restriction {
        fn check_before_io(&self) -> Result<()> {
            self.samples.fetch_add(1, Ordering::SeqCst);
            if self.revoked.load(Ordering::SeqCst) { Err(AuthorityError::Permission) }
            else { Ok(()) }
        }
    }
    #[test]
    fn final_transport_sample_refuses_unsent_attempt_and_preserves_io_error() {
        let r = Restriction { revoked:AtomicBool::new(true), samples:AtomicUsize::new(0) };
        let calls = AtomicUsize::new(0);
        let err = restricted_transport_io_v1(&r, || { calls.fetch_add(1,Ordering::SeqCst); Ok(1) }).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let fresh = Restriction { revoked:AtomicBool::new(false), samples:AtomicUsize::new(0) };
        let err = restricted_transport_io_v1::<()>(&fresh, || Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
        assert_eq!(fresh.samples.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn each_transport_attempt_resamples_without_renewing_or_retracting_prior_effect() {
        let r = Restriction { revoked:AtomicBool::new(false), samples:AtomicUsize::new(0) };
        let calls = AtomicUsize::new(0);
        assert_eq!(restricted_transport_io_v1(&r, || {
            calls.fetch_add(1,Ordering::SeqCst);
            r.revoked.store(true,Ordering::SeqCst);
            Ok(3)
        }).unwrap(), 3);
        assert!(restricted_transport_io_v1(&r, || { calls.fetch_add(1,Ordering::SeqCst); Ok(4) }).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(r.samples.load(Ordering::SeqCst), 2);
    }
}

#[cfg(test)]
mod borrowed_transport_restriction_tests_v2 {
    use super::*;
    use std::cell::Cell;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    struct Original { denied: AtomicBool, samples: AtomicUsize }
    impl AuthorityTransportRestrictionV1 for Original {
        fn check_before_io(&self) -> Result<()> {
            self.samples.fetch_add(1, Ordering::SeqCst);
            if self.denied.load(Ordering::SeqCst) { Err(AuthorityError::Permission) }
            else { Ok(()) }
        }
    }
    #[test]
    fn borrowed_denial_prevents_attempt_without_storing_or_copying_grant() {
        let calls = Cell::new(0);
        let denied = || Err(AuthorityError::Permission);
        let result = borrowed_restricted_transport_io_v2(None, Some(&denied), || {
            calls.set(calls.get() + 1); Ok(())
        });
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(calls.get(), 0);
    }
    #[test]
    fn original_denial_cannot_be_overridden_by_call_check() {
        let original = Original { denied: AtomicBool::new(true), samples: AtomicUsize::new(0) };
        let calls = Cell::new(0);
        let current = || Ok(());
        assert!(borrowed_restricted_transport_io_v2(Some(&original), Some(&current), || {
            calls.set(calls.get() + 1); Ok(())
        }).is_err());
        assert_eq!(calls.get(), 0);
        assert_eq!(original.samples.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn revoke_during_admitted_attempt_denies_result_not_claimed_rollback() {
        let expired = Cell::new(false);
        let calls = Cell::new(0);
        let current = || if expired.get() { Err(AuthorityError::Expired) } else { Ok(()) };
        assert!(borrowed_restricted_transport_io_v2(None, Some(&current), || {
            calls.set(calls.get() + 1); expired.set(true); Ok(4)
        }).is_err());
        assert_eq!(calls.get(), 1); // already-admitted effect really occurred
        assert!(borrowed_restricted_transport_io_v2(None, Some(&current), || {
            calls.set(calls.get() + 1); Ok(4)
        }).is_err());
        assert_eq!(calls.get(), 1);
    }
    #[test]
    fn original_observer_is_last_before_attempt_and_repeated_after() {
        let original = Original { denied: AtomicBool::new(false), samples: AtomicUsize::new(0) };
        let samples = Cell::new(0);
        let current = || { samples.set(samples.get() + 1); Ok(()) };
        assert_eq!(borrowed_restricted_transport_io_v2(Some(&original), Some(&current), || {
            assert_eq!(samples.get(), 1);
            assert_eq!(original.samples.load(Ordering::SeqCst), 1);
            Ok(9)
        }).unwrap(), 9);
        assert_eq!(samples.get(), 2);
        assert_eq!(original.samples.load(Ordering::SeqCst), 2);
    }
    #[test]
    fn actual_io_error_survives_later_restriction_failure() {
        let expired = Cell::new(false);
        let current = || if expired.get() { Err(AuthorityError::Expired) } else { Ok(()) };
        let result = borrowed_restricted_transport_io_v2::<()>(None, Some(&current), || {
            expired.set(true); Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        });
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
    }
    #[test]
    fn restricted_io_error_survives_deadline_but_legacy_order_is_unchanged() {
        let expired = || Err(std::io::Error::from(std::io::ErrorKind::TimedOut));
        let broken = || Err::<(), _>(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        assert_eq!(finish_caller_io_v2(broken(), expired(), true).unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
        assert_eq!(finish_caller_io_v2(broken(), expired(), false).unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(finish_caller_io_v2(Ok(()), expired(), true).unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    }
    #[test]
    fn original_owned_socket_remains_send_without_action_reference() {
        fn assert_send<T: Send>() {}
        assert_send::<CallerDeadlineSocket>();
    }
}
