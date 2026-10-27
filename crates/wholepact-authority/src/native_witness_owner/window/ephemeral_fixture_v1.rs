//! Explicit temporary synthetic native-controller qualification only.
//! No /etc, passwd-home namespace, installed pin or production account is used.
//! Ordinary form data is supplied by the fixture, while every approval is made
//! by the SAME Window::draw/review_ui primary-pointer event path as production.
//! No FinalPrimaryClick, NativeDecision, lease or completed birth row is built.
use super::*;
use crate::transport::{AuthorityServer, ServerTls};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{
    fs::{self, OpenOptions},
    net::TcpListener,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex, TryLockError,
    },
    time::Instant,
};
use wholepact_storage_security::witness_namespace_fs::EphemeralWitnessInstallation;

const SETUP: &str = "Prepare exact permanent namespace setup review";
const ENROLL: &str = "Open installed namespace and prepare exact enrollment / retry review";
const CONTINUE: &str = "Continue to exact native confirmation";
const UNDERSTOOD: &str = "I reviewed this complete exact operation and its permanent consequences. I understand the existing owner signature does not attest fresh signer keys or native signer focus.";
const AUTHORIZE: &str = "Authorize this exact one-time owner operation";
const PROFILE: &str = "ironwood-testnet-nu7-candidate";

#[derive(Clone, Copy)]
enum TlsFixtureProfileV1 {
    FullExisting,
    PristineDeliveryReview,
}
impl TlsFixtureProfileV1 {
    fn leaves(self) -> &'static [&'static str] {
        match self {
            Self::FullExisting => &["owner", "writer", "server", "dispatcher"],
            Self::PristineDeliveryReview => &["owner", "writer", "server"],
        }
    }
}

#[path = "ephemeral_fixture_v1/durable_delivery_admission_v2.rs"]
mod durable_delivery_admission_v2;
pub use durable_delivery_admission_v2::EphemeralPartialFinancialWitnessV2;
#[path = "ephemeral_fixture_v1/durable_payment_v1.rs"]
mod durable_payment_v1;
#[path = "ephemeral_fixture_v1/financial_continuation_v1.rs"]
mod financial_continuation_v1;
pub(crate) use durable_payment_v1::DurableAcquireReplyLossArmV1;
pub use durable_payment_v1::{
    EphemeralDurableAcquireReplyLossObservationV1, EphemeralDurableAcquireReplyLossReportV1,
};
#[path = "ephemeral_fixture_v1/public_control_navigation_v1.rs"]
mod public_control_navigation_v1;
#[path = "ephemeral_fixture_v1/roster_v3.rs"]
mod roster_v3;
pub use roster_v3::EphemeralRosterAttemptV2;
#[path = "ephemeral_fixture_v1/coordinated_history_lifetime_v1.rs"]
mod coordinated_history_lifetime_v1;
pub use coordinated_history_lifetime_v1::EphemeralCoordinatedHistoryLifetimeV1;
use coordinated_history_lifetime_v1::ScopedHistoryClockV1;
#[cfg(feature = "born-offline-witness-owner")]
#[path = "ephemeral_fixture_v1/born_offline_v1.rs"]
mod born_offline_v1;
#[cfg(feature = "born-offline-witness-owner")]
pub use born_offline_v1::{EphemeralBornTransportKeyV1, EphemeralBornTransportPublicPinV1};
#[path = "ephemeral_fixture_v1/construction_client_scope_v1.rs"]
mod construction_client_scope_v1;
#[path = "ephemeral_fixture_v1/single_anchor_v1.rs"]
mod single_anchor_v1;
#[path = "ephemeral_fixture_v1/tls_child_v1.rs"]
mod tls_child_v1;
pub use construction_client_scope_v1::EphemeralConstructionClientScopeV1;
pub(crate) use construction_client_scope_v1::RetainedConstructionFixtureLivenessV1;

#[derive(Clone, Copy)]
enum QualifiedEntry {
    ConstructionPlan,
    ConstructionTransport,
}
impl QualifiedEntry {
    fn area(self) -> egui::Area {
        egui::Area::new(egui::Id::new("synthetic-original-v3-entry"))
            .fixed_pos(egui::pos2(20.0, 19000.0))
    }
    fn label(self) -> &'static str {
        match self {
            Self::ConstructionPlan => "SYNTHETIC ONLY: enter original V3 plan controller",
            Self::ConstructionTransport => "SYNTHETIC ONLY: enter original handoff controller",
        }
    }
}

/// Public test input/output metadata, not an approval or portable capability.
#[derive(Clone)]
pub struct EphemeralWitnessOriginV1 {
    pub endpoint: String,
    pub server_name: String,
    pub witness_id: String,
    pub server_certificate_digest: String,
    pub owner_certificate_digest: String,
    pub owner_certificate_file: PathBuf,
    pub owner_key_file: PathBuf,
    pub trusted_server_root_file: PathBuf,
    pub writer_certificate_digest: String,
    pub writer_certificate_file: PathBuf,
    pub writer_key_file: PathBuf,
    // A nominal retained owner, never a caller-supplied root or wire selector.
    credential_root: PathBuf,
    _installation: Arc<EphemeralWitnessInstallation>,
}
impl EphemeralWitnessOriginV1 {
    pub fn credential_root(&self) -> &Path {
        &self.credential_root
    }
}

/// Fresh fixtures generate all files below their concrete owner before signer
/// birth deadlines begin. The separate bounded v2 historical route reopens only
/// exact preserved originals, with a fresh native audit and no new authority.
pub struct EphemeralNativeWitnessV1 {
    window: Window,
    context: egui::Context,
    qualification_entry: Option<QualifiedEntry>,
    construction_client_grants: std::collections::BTreeSet<String>,
    construction_client_scope_revoked: Arc<AtomicBool>,
    installation: Arc<EphemeralWitnessInstallation>,
    listener: OriginalListenerV1,
    durable_payment: durable_payment_v1::FixturePhaseV1,
    durable_delivery: durable_delivery_admission_v2::FixturePhaseV2,
    financial_continuation: financial_continuation_v1::FixtureFinancialPhaseV1,
    tls: ServerTls,
    server_certificate_digest: String,
    owner_certificate: Vec<u8>,
    root: PathBuf,
}
// The original socket can be handed off only to the real native admission
// listener, then rebound at the same address after that worker fully drains.
// All existing fixture phases keep their original bound-listener behavior.
struct OriginalListenerV1 {
    bound: Option<TcpListener>,
    address: std::net::SocketAddr,
    server_handles: Arc<AtomicUsize>,
    server_join_failed: Arc<AtomicBool>,
}
impl OriginalListenerV1 {
    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.bound
            .as_ref()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::PermissionDenied))?
            .local_addr()
    }
    fn try_clone(&self) -> std::io::Result<TcpListener> {
        self.bound
            .as_ref()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::PermissionDenied))?
            .try_clone()
    }
}
impl EphemeralNativeWitnessV1 {
    pub fn new() -> Result<Self> {
        Self::new_with_tls_profile(TlsFixtureProfileV1::FullExisting)
    }

    /// The same genuine synthetic setup controller, with no unused dispatcher
    /// credential. This does not create accounts or approve a delivery review.
    /// The caller still needs separately approved disposable fixture execution.
    pub fn new_for_pristine_delivery_review_v1() -> Result<Self> {
        Self::new_with_tls_profile(TlsFixtureProfileV1::PristineDeliveryReview)
    }

    fn new_with_tls_profile(profile: TlsFixtureProfileV1) -> Result<Self> {
        let installation = EphemeralWitnessInstallation::new()?;
        let root = installation
            .probe()?
            .root_path()
            .parent()
            .ok_or(AuthorityError::Storage)?
            .to_path_buf();
        create_tls_material(&root, &installation, profile)?;
        let ca = CertificateDer::from(
            fs::read(root.join("ca.der")).map_err(|_| AuthorityError::Storage)?,
        );
        let certificate = CertificateDer::from(
            fs::read(root.join("server.der")).map_err(|_| AuthorityError::Storage)?,
        );
        let owner_certificate =
            fs::read(root.join("owner.der")).map_err(|_| AuthorityError::Storage)?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            fs::read(root.join("server.pk8")).map_err(|_| AuthorityError::Storage)?,
        ));
        let tls = ServerTls::new(vec![ca], vec![certificate.clone()], key)?;
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|_| AuthorityError::Storage)?;
        let endpoint = listener
            .local_addr()
            .map_err(|_| AuthorityError::Storage)?
            .to_string();
        let key_path = root.join("synthetic-namespace.key");
        let mut key_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key_path)
            .map_err(|_| AuthorityError::Storage)?;
        // Public fixed never-production fixture key, not a secret supplied by a
        // caller or silently provisioned in the user's namespace.
        key_file
            .write_all(&[0x6d; 32])
            .map_err(|_| AuthorityError::Storage)?;
        key_file.sync_all().map_err(|_| AuthorityError::Storage)?;
        drop(key_file);
        let mut window = Window::new();
        window.input.endpoint = endpoint;
        window.input.server_name = "localhost".into();
        window.input.pinned_server_certificate_digest =
            crate::transport::certificate_digest(&certificate);
        window.input.network_profile_id = PROFILE.into();
        window.input.storage_key_file = key_path
            .to_str()
            .ok_or(AuthorityError::InvalidBinding)?
            .into();
        window.input.owner_certificate_hex = Zeroizing::new(hex::encode(&owner_certificate));
        window.input.synthetic_installation = Some(installation.clone());
        let context = egui::Context::default();
        configure_style(&context);
        let mut result = Self {
            window,
            context,
            qualification_entry: None,
            construction_client_grants: std::collections::BTreeSet::new(),
            construction_client_scope_revoked: Arc::new(AtomicBool::new(false)),
            installation,
            listener: OriginalListenerV1 {
                address: listener.local_addr().map_err(|_| AuthorityError::Storage)?,
                bound: Some(listener),
                server_handles: Arc::new(AtomicUsize::new(0)),
                server_join_failed: Arc::new(AtomicBool::new(false)),
            },
            durable_payment: durable_payment_v1::FixturePhaseV1::Idle,
            financial_continuation: financial_continuation_v1::FixtureFinancialPhaseV1::default(),
            durable_delivery: durable_delivery_admission_v2::FixturePhaseV2::default(),
            server_certificate_digest: crate::transport::certificate_digest(&certificate),
            tls,
            owner_certificate,
            root,
        };
        result.click(SETUP).inspect_err(|error| {
            eprintln!("synthetic witness fixture stage setup-pointer: {error:?}");
        })?;
        result.drain().inspect_err(|error| {
            eprintln!("synthetic witness fixture stage setup-prepare-drain: {error:?}");
        })?;
        if !matches!(
            result.window.pending.as_ref().map(|p| &p.prepared.proposal),
            Some(Proposal::Setup(_))
        ) {
            // Window messages are static source literals, never form data.
            eprintln!(
                "synthetic witness fixture stage setup-prepared: {}",
                result.window.message
            );
            return Err(AuthorityError::Permission);
        }
        result.approve_exact().inspect_err(|error| {
            eprintln!("synthetic witness fixture stage setup-exact-review: {error:?}");
        })?;
        if result.window.last_installation_audit.is_none()
            || result.window.input.witness_id.is_empty()
        {
            return Err(AuthorityError::Uncertain);
        }
        // This is the real completed immutable registry, not a synthetic row.
        result
            .installation
            .probe()?
            .open_existing()?
            .check_current()?;
        Ok(result)
    }

    pub fn origin(&self) -> Result<EphemeralWitnessOriginV1> {
        if self.window.input.witness_id.is_empty()
            || self.window.job.is_some()
            || self.window.pending.is_some()
        {
            return Err(AuthorityError::Permission);
        }
        Ok(EphemeralWitnessOriginV1 {
            endpoint: self.window.input.endpoint.clone(),
            server_name: self.window.input.server_name.clone(),
            witness_id: self.window.input.witness_id.clone(),
            server_certificate_digest: self.window.input.pinned_server_certificate_digest.clone(),
            owner_certificate_digest: crate::transport::certificate_digest(&CertificateDer::from(
                self.owner_certificate.as_slice(),
            )),
            owner_certificate_file: self.root.join("owner.der"),
            owner_key_file: self.root.join("owner.pk8"),
            trusted_server_root_file: self.root.join("ca.der"),
            writer_certificate_digest: crate::transport::certificate_digest(&CertificateDer::from(
                fs::read(self.root.join("writer.der")).map_err(|_| AuthorityError::Storage)?,
            )),
            writer_certificate_file: self.root.join("writer.der"),
            writer_key_file: self.root.join("writer.pk8"),
            credential_root: self.root.clone(),
            _installation: self.installation.clone(),
        })
    }

    /// Exact initial synthetic dispatcher leaf/key only. The CA signing key is
    /// never exported. This is credential custody, not enrollment or authority;
    /// the financial continuation still commits its distinct leaf pin.
    pub fn dedicated_dispatcher_credentials_v1(&self) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
        let certificate =
            wholepact_storage_security::witness_namespace_fs::read_existing_private_file(
                &self.root.join("dispatcher.der"),
                16 * 1024,
            )?;
        let key = wholepact_storage_security::witness_namespace_fs::read_existing_private_file(
            &self.root.join("dispatcher.pk8"),
            16 * 1024,
        )?;
        let pin =
            crate::transport::certificate_digest(&CertificateDer::from(certificate.as_slice()));
        let origin = self.origin()?;
        if [
            &origin.owner_certificate_digest,
            &origin.writer_certificate_digest,
            &origin.server_certificate_digest,
        ]
        .contains(&&pin)
        {
            return Err(AuthorityError::Authentication);
        }
        let ca = wholepact_storage_security::witness_namespace_fs::read_existing_private_file(
            &self.root.join("ca.der"),
            16 * 1024,
        )?;
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca.to_vec()))
            .map_err(|_| AuthorityError::Authentication)?;
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .map_err(|_| AuthorityError::Authentication)?;
        verifier
            .verify_client_cert(
                &CertificateDer::from(certificate.as_slice()),
                &[],
                rustls::pki_types::UnixTime::now(),
            )
            .map_err(|_| AuthorityError::Authentication)?;
        rustls::sign::CertifiedKey::from_der(
            vec![CertificateDer::from(certificate.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
            &rustls::crypto::ring::default_provider(),
        )
        .and_then(|certified| certified.keys_match())
        .map_err(|_| AuthorityError::Authentication)?;
        // Maintained rustls configuration uses the exact retained leaf/key.
        let _client = crate::transport::ClientTls::new(
            origin.server_name,
            origin.server_certificate_digest,
            vec![CertificateDer::from(ca.to_vec())],
            vec![CertificateDer::from(certificate.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
        )?;
        Ok((certificate.to_vec(), key))
    }

    /// The caller supplies ONLY the actual signer-private exported public JSON.
    /// The existing native parser verifies it against the independently chosen
    /// DER owner certificate before proposing, reviewing or committing birth.
    pub fn enroll_signed_birth(&mut self, account_id: &str, signed_envelope: &[u8]) -> Result<()> {
        crate::hash(account_id)?;
        if self.durable_delivery.historical_only
            || signed_envelope.is_empty()
            || signed_envelope.len() > crate::MAX_FRAME_BYTES
            || !self.window.can_select()
        {
            return Err(AuthorityError::Limit);
        }
        self.window.input.expected_account_id = account_id.into();
        self.window.input.owner_certificate_hex =
            Zeroizing::new(hex::encode(&self.owner_certificate));
        self.window.input.signed_request_json = Zeroizing::new(
            std::str::from_utf8(signed_envelope)
                .map_err(|_| AuthorityError::InvalidBinding)?
                .into(),
        );
        self.click(ENROLL)?;
        self.drain()?;
        if !matches!(
            self.window.pending.as_ref().map(|p| &p.prepared.proposal),
            Some(Proposal::Enrollment(_))
        ) {
            return Err(AuthorityError::Permission);
        }
        self.approve_exact()?;
        // Read-only actual factory authenticates immutable locator completion,
        // actual born journal and matching request. Never create/open generic
        // AuthorityJournal from a policy with a caller-supplied genesis.
        let journal =
            crate::witness_locator::open_born_history(self.original_namespace_input(account_id)?)?;
        drop(journal);
        // Retain only the actual original public signed envelope. A later
        // synthetic existing-original audit re-verifies it against this same
        // namespace; it never re-signs a birth or renews its original deadline.
        self.durable_delivery
            .original_signed_births
            .entry(account_id.into())
            .or_insert_with(|| signed_envelope.to_vec());
        Ok(())
    }

    /// Actual TLS history server for this original completed namespace. The
    /// caller must drop it before a later native namespace mutation needs locks.
    pub fn serve_original_history(&mut self) -> Result<EphemeralHistoryServerV1> {
        let account_id = self.window.input.expected_account_id.clone();
        let input = self.original_namespace_input(&account_id)?;
        let actual_listen = self
            .listener
            .local_addr()
            .map_err(|_| AuthorityError::Storage)?
            .to_string();
        let journal = Arc::new(
            crate::born_history_server::open_born_history_from_namespace(
                input,
                &self.server_certificate_digest,
                &actual_listen,
            )?,
        );
        self.serve_exact_server(AuthorityServer::new(journal, self.tls.clone()))
    }

    fn original_namespace_input(&mut self, account_id: &str) -> Result<NamespaceOpenInput> {
        crate::hash(account_id)?;
        if !self.window.can_select() {
            return Err(AuthorityError::Permission);
        }
        self.window.input.expected_account_id = account_id.into();
        self.window.input.owner_certificate_hex =
            Zeroizing::new(hex::encode(&self.owner_certificate));
        self.window.input.enrollment_input()
    }

    /// Passive synthetic service restriction, not an action or journal grant.
    /// The caller passes the original child cutoff and original source expiry,
    /// once before READY; each served ledger independently narrows this bound.
    pub fn coordinated_history_lifetime_v1(&self, original_cutoff: Instant,
        original_source_expires_at_ms: u64) -> Result<EphemeralCoordinatedHistoryLifetimeV1> {
        if !self.window.can_select() || self.durable_delivery.historical_only {
            return Err(AuthorityError::Permission);
        }
        EphemeralCoordinatedHistoryLifetimeV1::capture_at(
            self.construction_client_scope_revoked.clone(), original_cutoff,
            original_source_expires_at_ms, Instant::now(), crate::now_ms()?)
    }

    fn serve_exact_server(&self, server: AuthorityServer) -> Result<EphemeralHistoryServerV1> {
        self.serve_exact_server_inner(server, None)
    }
    fn serve_exact_server_until(&self, server: AuthorityServer,
        lifetime: &EphemeralCoordinatedHistoryLifetimeV1, policy_expires_at_ms: u64,
    ) -> Result<EphemeralHistoryServerV1> {
        let scope = lifetime.for_policy_at(&self.construction_client_scope_revoked,
            policy_expires_at_ms, Instant::now(), crate::now_ms()?)?;
        self.serve_exact_server_inner(server, Some(scope))
    }
    fn serve_exact_server_inner(&self, server: AuthorityServer,
        mut scope: Option<ScopedHistoryClockV1>,
    ) -> Result<EphemeralHistoryServerV1> {
        // Keep the original bound endpoint for later independently reviewed
        // phases. Dropping a finite server closes its journal, not this owner.
        let listener = self
            .listener
            .try_clone()
            .map_err(|_| AuthorityError::Storage)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| AuthorityError::Storage)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let accept_gate = Arc::new(Mutex::new(false));
        let serving_accept_gate = accept_gate.clone();
        // Capture once before spawn; neither sealing nor a later caller can
        // restart this original finite serving lifetime.
        let started = Instant::now();
        let deadline = scope.as_ref().map_or(started + Duration::from_secs(120), |v| v.deadline());
        let installation = self.installation.clone();
        let thread = std::thread::Builder::new()
            .name("synthetic-original-witness-history".into())
            .spawn(move || {
                let _server_stopped = SyntheticServerStopped(stopped.clone());
                let _retained_installation = installation;
                while !stopped.load(Ordering::Acquire) && Instant::now() < deadline {
                    if scope.as_mut().is_some_and(|v| v.check_current().is_err()) { break; }
                    // The gate covers only nonblocking accept. It is released
                    // before the maintained bounded TLS/authority handler runs.
                    match accept_while_unsealed(&serving_accept_gate, || listener.accept()) {
                        Ok(Some(Ok((socket, _)))) => {
                            if scope.as_mut().is_some_and(|v| v.check_current().is_err()) { break; }
                            let _ = server.serve_connection(socket);
                        }
                        Ok(None) => std::thread::sleep(Duration::from_millis(2)),
                        Ok(Some(Err(error))) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(2))
                        }
                        Ok(Some(Err(_))) | Err(_) => break,
                    }
                }
                drop(server);
            })
            .map_err(|_| AuthorityError::Storage)?;
        // Count live handles, not just accepting threads. An admission handoff
        // requires Drop to join every original server before releasing its socket.
        self.listener.server_handles.fetch_add(1, Ordering::AcqRel);
        Ok(EphemeralHistoryServerV1 {
            stop,
            accept_gate,
            started,
            deadline,
            thread: Some(thread),
            listener_owner: self.listener.server_handles.clone(),
            join_failed: self.listener.server_join_failed.clone(),
        })
    }

    fn frame(&mut self, events: Vec<egui::Event>, focused: bool) -> egui::FullOutput {
        let input = fixture_input(events, focused);
        let entry = self.qualification_entry;
        self.context.run_ui(input, |ui| {
            self.window.draw(ui);
            if let Some(entry) = entry {
                // A finite synthetic control exercises the SAME private inner
                // prepare branch, not the disabled production entry or a raw
                // owner constructor. Exact review and final commit stay in the
                // unchanged real Window controller.
                entry.area().show(ui.ctx(), |ui| {
                    let focused = ui
                        .ctx()
                        .input(|i| i.focused && i.viewport().focused == Some(true));
                    if ui
                        .add_enabled(self.window.can_select(), egui::Button::new(entry.label()))
                        .clicked_by(egui::PointerButton::Primary)
                        && focused
                    {
                        match entry {
                            QualifiedEntry::ConstructionPlan => self
                                .window
                                .prepare_manual_roster_construction_v3_from_primary(ui.ctx()),
                            QualifiedEntry::ConstructionTransport => self
                                .window
                                .prepare_construction_transport_grant_v1_from_primary(ui.ctx()),
                        }
                    }
                });
            }
        })
    }
    fn click_qualified_entry(&mut self, entry: QualifiedEntry) -> Result<()> {
        self.qualification_entry = Some(entry);
        // A new egui Area first performs an invisible, non-interactable sizing
        // pass. Render that actual no-event frame before locating its label.
        // The next frame and real primary click still use the unchanged path.
        self.frame(vec![], true);
        let result = self.click(entry.label());
        self.qualification_entry = None;
        result
    }
    fn click(&mut self, label: &str) -> Result<()> {
        if self.durable_delivery.historical_only
            && (!self.durable_delivery.native_historical_audit
                || ![ENROLL, CONTINUE, UNDERSTOOD, AUTHORIZE].contains(&label))
        {
            return Err(AuthorityError::Permission);
        }
        let output = self.frame(vec![], true);
        let position = output
            .shapes
            .iter()
            .find_map(|shape| text_position(&shape.shape, label))
            .ok_or(AuthorityError::Permission)
            .inspect_err(|_| eprintln!("synthetic witness fixture missing control: {label}"))?;
        let event = |pressed| egui::Event::PointerButton {
            pos: position,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        self.frame(vec![egui::Event::PointerMoved(position), event(true)], true);
        self.frame(vec![event(false)], true);
        Ok(())
    }
    fn drain(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(120);
        while self.window.job.is_some() {
            self.frame(vec![], true);
            if Instant::now() >= deadline {
                self.window.discard();
                // Revocation is immediate, but already admitted publication
                // still drains. Never drop its temporary owner before joining.
                while self.window.job.is_some() {
                    self.window.poll_job(&self.context, false);
                    std::thread::sleep(Duration::from_millis(2));
                }
                return Err(AuthorityError::Uncertain);
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        if self.window.disposal_failed {
            return Err(AuthorityError::Uncertain);
        }
        Ok(())
    }
    fn approve_exact(&mut self) -> Result<()> {
        self.start_approve_exact()?;
        self.drain()?;
        if self.window.pending.is_some() || !self.window.can_select() {
            return Err(AuthorityError::Uncertain);
        }
        Ok(())
    }
    // Same focused UI path as approve_exact, without waiting for its worker.
    // The exact admission worker must await the independent signer owner-mTLS.
    fn start_approve_exact(&mut self) -> Result<()> {
        if self
            .window
            .pending
            .as_ref()
            .is_none_or(|p| p.phase != Phase::Reading)
        {
            return Err(AuthorityError::Permission);
        }
        self.click(CONTINUE)?;
        let pending = self
            .window
            .pending
            .as_ref()
            .ok_or(AuthorityError::Permission)?;
        if pending.phase != Phase::Confirming {
            return Err(AuthorityError::Permission);
        }
        // Ordinary exact confirmation text is synthetic input data only. The
        // final pointer event below, not this assignment, creates the decision.
        self.window.confirmation = Zeroizing::new(pending.phrase());
        self.click(UNDERSTOOD)?;
        self.click(AUTHORIZE)?;
        Ok(())
    }
}
impl Drop for EphemeralNativeWitnessV1 {
    fn drop(&mut self) {
        self.construction_client_scope_revoked
            .store(true, Ordering::Release);
        self.window.discard();
        while self.window.job.is_some() {
            self.window.poll_job(&self.context, false);
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}
struct SyntheticServerStopped(Arc<AtomicBool>);
impl Drop for SyntheticServerStopped {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
pub struct EphemeralHistoryServerV1 {
    stop: Arc<AtomicBool>,
    accept_gate: Arc<Mutex<bool>>,
    started: Instant,
    deadline: Instant,
    thread: Option<std::thread::JoinHandle<()>>,
    listener_owner: Arc<AtomicUsize>,
    join_failed: Arc<AtomicBool>,
}
impl EphemeralHistoryServerV1 {
    /// Independent synthetic handle observations, not a coherent readiness or
    /// accepting proof. Returns capped age/remaining microseconds, the existing
    /// stop flag, optional thread completion, and a clamped/unavailable marker.
    /// Uses the actual constructor start for either serving horizon; no server
    /// lifetime, socket, source check or gate is touched.
    pub fn measurement_snapshot(&self) -> (Option<u64>, u64, bool, Option<bool>, bool) {
        const MAX_US: u128 = 600_000_000;
        let observed = Instant::now();
        let age_us = Some(observed.saturating_duration_since(self.started).as_micros());
        let remaining_us = self
            .deadline
            .saturating_duration_since(observed)
            .as_micros();
        let clamped = age_us.map_or(true, |age| age > MAX_US) || remaining_us > MAX_US;
        (
            age_us.map(|age| age.min(MAX_US) as u64),
            remaining_us.min(MAX_US) as u64,
            self.stop.load(Ordering::Acquire),
            self.thread
                .as_ref()
                .map(std::thread::JoinHandle::is_finished),
            clamped,
        )
    }

    /// Irreversibly stop accepting NEW sockets on this particular finite
    /// synthetic server. The shared lock acknowledges quiescence before return:
    /// an accept already holding the lock must finish first, and no later
    /// accept can pass it. An already accepted stream is not replaced or reset;
    /// it continues under its unchanged original ten-second handler deadline.
    /// The actual server/namespace and original finite lifetime remain retained.
    /// No resume, rebind, additional authority, or deadline renewal exists.
    pub fn seal_new_connections(&self, original_deadline: Instant) -> Result<()> {
        let deadline = original_deadline
            .min(self.deadline)
            .min(Instant::now() + Duration::from_secs(1));
        seal_acceptance_gate_until(&self.accept_gate, &self.stop, deadline)
    }
}
fn accept_while_unsealed<T>(gate: &Mutex<bool>, accept: impl FnOnce() -> T) -> Result<Option<T>> {
    let sealed = gate.lock().map_err(|_| AuthorityError::Permission)?;
    if *sealed {
        return Ok(None);
    }
    Ok(Some(accept()))
}
fn seal_acceptance_gate_until(
    gate: &Mutex<bool>,
    stopped: &AtomicBool,
    deadline: Instant,
) -> Result<()> {
    loop {
        if stopped.load(Ordering::Acquire) || Instant::now() >= deadline {
            return Err(AuthorityError::Expired);
        }
        match gate.try_lock() {
            Ok(mut sealed) => {
                // This is the only write; it is deliberately one-way.
                *sealed = true;
                drop(sealed);
                return if stopped.load(Ordering::Acquire) || Instant::now() >= deadline {
                    Err(AuthorityError::Expired)
                } else {
                    Ok(())
                };
            }
            Err(TryLockError::WouldBlock) => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(TryLockError::Poisoned(_)) => return Err(AuthorityError::Permission),
        }
    }
}
#[cfg(test)]
mod acceptance_gate_tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn sealed_synthetic_server_gate_never_calls_accept_or_resumes() {
        let gate = Mutex::new(false);
        let stopped = AtomicBool::new(false);
        let calls = Cell::new(0);
        let accept = || calls.set(calls.get() + 1);
        assert!(accept_while_unsealed(&gate, accept).unwrap().is_some());
        assert_eq!(calls.get(), 1);
        let deadline = Instant::now() + Duration::from_secs(1);
        seal_acceptance_gate_until(&gate, &stopped, deadline).unwrap();
        assert!(accept_while_unsealed(&gate, accept).unwrap().is_none());
        seal_acceptance_gate_until(&gate, &stopped, deadline).unwrap();
        assert!(accept_while_unsealed(&gate, accept).unwrap().is_none());
        assert_eq!(calls.get(), 1);
        assert!(!stopped.load(Ordering::Acquire));
    }

    #[test]
    fn sealing_synthetic_server_gate_never_renews_expired_or_stopped_owner() {
        let gate = Mutex::new(false);
        let stopped = AtomicBool::new(false);
        let held = gate.lock().unwrap();
        assert!(matches!(
            seal_acceptance_gate_until(&gate, &stopped, Instant::now()),
            Err(AuthorityError::Expired)
        ));
        assert!(!*held);
        drop(held);
        stopped.store(true, Ordering::Release);
        assert!(matches!(
            seal_acceptance_gate_until(&gate, &stopped, Instant::now() + Duration::from_secs(1)),
            Err(AuthorityError::Expired)
        ));
        assert!(!*gate.lock().unwrap());
    }
}
impl Drop for EphemeralHistoryServerV1 {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            if thread.join().is_err() {
                // Monotone synthetic evidence only: zero live handles alone
                // cannot turn a panicked worker into a successful drain.
                self.join_failed.store(true, Ordering::Release);
            }
        }
        self.listener_owner.fetch_sub(1, Ordering::AcqRel);
    }
}
fn fixture_input(events: Vec<egui::Event>, focused: bool) -> egui::RawInput {
    let mut input = egui::RawInput {
        screen_rect: Some(egui::Rect::from_min_size(
            egui::Pos2::ZERO,
            egui::vec2(1800.0, 20000.0),
        )),
        focused,
        events,
        ..Default::default()
    };
    input
        .viewports
        .get_mut(&egui::ViewportId::ROOT)
        .expect("default root viewport")
        .focused = Some(focused);
    input
}
fn text_position(shape: &egui::epaint::Shape, label: &str) -> Option<egui::Pos2> {
    match shape {
        egui::epaint::Shape::Text(text) if text.galley.text() == label => {
            Some(text.pos + text.galley.rect.center().to_vec2())
        }
        egui::epaint::Shape::Vec(shapes) => {
            shapes.iter().find_map(|shape| text_position(shape, label))
        }
        _ => None,
    }
}
fn create_tls_material(
    root: &Path,
    installation: &Arc<EphemeralWitnessInstallation>,
    profile: TlsFixtureProfileV1,
) -> Result<()> {
    // Fixed once before any birth/native financial approval, never per command.
    let deadline = Instant::now()
        .checked_add(std::time::Duration::from_secs(30))
        .ok_or(AuthorityError::Expired)?;
    let run = |arguments: &[&str]| -> Result<()> {
        tls_child_v1::run_openssl(root, installation, arguments, deadline)
    };
    run(&[
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-sha256",
        "-days",
        "1",
        "-nodes",
        "-subj",
        "/CN=wholepact-ephemeral-qualification-root",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-keyout",
        "ca.key",
        "-out",
        "ca.pem",
    ])?;
    run(&["x509", "-in", "ca.pem", "-outform", "DER", "-out", "ca.der"])?;
    fs::write(root.join("leaf.ext"), b"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:localhost\n").map_err(|_| AuthorityError::Storage)?;
    if matches!(profile, TlsFixtureProfileV1::FullExisting) {
        fs::write(root.join("dispatcher.ext"), b"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n").map_err(|_| AuthorityError::Storage)?;
    }
    for &name in profile.leaves() {
        let key = format!("{name}.key");
        let csr = format!("{name}.csr");
        let der = format!("{name}.der");
        let pk8 = format!("{name}.pk8");
        run(&[
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-sha256",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-keyout",
            &key,
            "-out",
            &csr,
        ])?;
        run(&[
            "x509",
            "-req",
            "-in",
            &csr,
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-days",
            "1",
            "-sha256",
            "-extfile",
            if name == "dispatcher" {
                "dispatcher.ext"
            } else {
                "leaf.ext"
            },
            "-outform",
            "DER",
            "-out",
            &der,
        ])?;
        run(&[
            "pkcs8", "-topk8", "-nocrypt", "-in", &key, "-outform", "DER", "-out", &pk8,
        ])?;
    }
    for entry in fs::read_dir(root).map_err(|_| AuthorityError::Storage)? {
        let entry = entry.map_err(|_| AuthorityError::Storage)?;
        if entry
            .file_type()
            .map_err(|_| AuthorityError::Storage)?
            .is_file()
        {
            fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o600))
                .map_err(|_| AuthorityError::Storage)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::ToSocketAddrs;

    #[test]
    fn pristine_tls_profile_omits_dispatcher_without_changing_existing_order() {
        assert_eq!(TlsFixtureProfileV1::FullExisting.leaves(),
            &["owner", "writer", "server", "dispatcher"]);
        assert_eq!(TlsFixtureProfileV1::PristineDeliveryReview.leaves(),
            &["owner", "writer", "server"]);
    }

    /// No listener, GUI, owner decision or enrollment. The maintained bounded
    /// fixture subprocess creates only ephemeral filesystem TLS material.
    #[test]
    fn dedicated_dispatcher_leaf_chains_to_original_ca_and_key() {
        let installation = EphemeralWitnessInstallation::new().unwrap();
        let root = installation
            .probe()
            .unwrap()
            .root_path()
            .parent()
            .unwrap()
            .to_path_buf();
        create_tls_material(&root, &installation, TlsFixtureProfileV1::FullExisting).unwrap();
        let ca = CertificateDer::from(fs::read(root.join("ca.der")).unwrap());
        let dispatcher = CertificateDer::from(fs::read(root.join("dispatcher.der")).unwrap());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap();
        verifier
            .verify_client_cert(&dispatcher, &[], rustls::pki_types::UnixTime::now())
            .unwrap();
        let key = fs::read(root.join("dispatcher.pk8")).unwrap();
        rustls::sign::CertifiedKey::from_der(
            vec![dispatcher.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
            &rustls::crypto::ring::default_provider(),
        )
        .unwrap()
        .keys_match()
        .unwrap();
        let wrong_key = fs::read(root.join("owner.pk8")).unwrap();
        assert!(rustls::sign::CertifiedKey::from_der(
            vec![dispatcher.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(wrong_key)),
            &rustls::crypto::ring::default_provider()
        )
        .is_err());
        // Reproduce the old self-signed form, with the same dispatcher key.
        tls_child_v1::run_openssl(
            &root,
            &installation,
            &[
                "req",
                "-new",
                "-x509",
                "-key",
                "dispatcher.key",
                "-sha256",
                "-days",
                "1",
                "-subj",
                "/CN=old-self-signed-dispatcher",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-addext",
                "keyUsage=critical,digitalSignature",
                "-addext",
                "extendedKeyUsage=clientAuth",
                "-outform",
                "DER",
                "-out",
                "old-dispatcher.der",
            ],
            Instant::now() + std::time::Duration::from_secs(30),
        )
        .unwrap();
        let old = CertificateDer::from(fs::read(root.join("old-dispatcher.der")).unwrap());
        assert!(verifier
            .verify_client_cert(&old, &[], rustls::pki_types::UnixTime::now())
            .is_err());
        for name in ["owner.der", "writer.der", "server.der"] {
            assert_ne!(
                dispatcher.as_ref(),
                fs::read(root.join(name)).unwrap().as_slice()
            );
        }
    }

    #[test]
    fn actual_ephemeral_native_namespace_setup_preserves_original_registry() {
        let fixture = EphemeralNativeWitnessV1::new().unwrap();
        let original = fixture.origin().unwrap();
        assert!(!original.witness_id.is_empty());
        assert!(original
            .endpoint
            .to_socket_addrs()
            .unwrap()
            .all(|a| a.ip().is_loopback()));
        assert!(fixture
            .installation
            .probe()
            .unwrap()
            .require_absent()
            .is_err());
        let files = fixture
            .installation
            .probe()
            .unwrap()
            .open_existing()
            .unwrap();
        files.check_current().unwrap();
        // No account has been created or enrolled. Namespace setup is distinct
        // from genesis, writer admission, construction and proof qualification.
        assert!(fixture.window.input.expected_account_id.is_empty());
    }
}
