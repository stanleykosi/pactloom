//! Genuine two-original completed-pair resource service. Setup/Serve are not
//! Host dispatch consent. Both accounts retain one actual namespace core and
//! independently authenticated dispatcher pins. The unchanged exact mutation
//! kernel may settle after its request-admission sample; a lost reply is uncertain.
//! Unregistered source leaf: fixed role, C/H observation and binary joins remain
//! separate. No legacy constructor, launcher or caller-input custody conversion.
use super::*;
use crate::native_witness_owner::financial_setup_guard_v1::FinancialSetupGuardV1 as Guard;
use std::sync::atomic::{AtomicBool, Ordering};
use wholepact_financial_coordinator_origin::WitnessCompletedPairServeV1 as Serve;

const POLL: Duration = Duration::from_millis(5);
const MAX_CONNECTIONS: usize = 4096;

use std::{
    sync::mpsc::{self, Receiver, SyncSender, TryRecvError},
    thread::{self, JoinHandle},
};
use wholepact_financial_coordinator_origin::{
    CompletedPairPresentationV1 as Presentation, CompletedPairRequestV1 as Request,
    WitnessCompletedPairOriginV1 as Origin, WitnessCompletedPairSetupV1 as Setup,
};
impl super::coordinated_service_worker_v1::ServiceOriginV1 for Origin {
    fn close_failed_worker(&mut self) { self.close_for_failed_worker_v1(); }
    fn close_failed_worker_error(&mut self) { self.close_for_failed_worker_error_v1(); }
    fn complete_owned(self, result: Result<()>) -> ! {
        self.complete(result.map_err(|_| std::io::Error::other("original completed-pair role stopped")))
    }
}
struct Prepared {
    server: AuthorityServer,
    listener: TcpListener,
    presentation: Presentation,
    original_service_deadline: Instant,
}
enum WorkerEvent {
    Prepared(Presentation, Instant),
    Serving,
}

/// Source-only actual role entry. The binary route remains separately gated.
pub fn run_coordinated_completed_pair_v1(origin: Origin) -> ! {
    let mut owned = super::coordinated_service_worker_v1::ServiceWorkerOwnerV1::new(origin);
    let result = monitor(&mut owned);
    owned.complete(result)
}
fn monitor(owned: &mut super::coordinated_service_worker_v1::ServiceWorkerOwnerV1<Origin, Serve, WorkerEvent>) -> Result<()> {
    let super::coordinated_service_worker_v1::ServiceWorkerOwnerV1 {
        origin, stopped, worker, serve_tx, event_tx, event_rx,
    } = owned;
    let origin = origin.as_mut().ok_or(AuthorityError::Storage)?;
    let mut started = false;
    let mut prepared = false;
    let mut terminal = false;
    let mut disposed = false;
    let mut failure_reported = false;
    let mut ordered_terminal = false;
    loop {
        origin
            .check_original_coordinator_alive()
            .map_err(|_| AuthorityError::Permission)?;
        if terminal {
            if Instant::now()
                >= origin
                    .original_cleanup_deadline()
                    .map_err(|_| AuthorityError::Permission)?
            {
                // The owner closes the actual control edge before its mandatory
                // worker join. No disposal receipt or hard join bound is claimed.
                return Err(AuthorityError::Expired);
            }
        } else if origin.check_current().is_err() {
            origin.restrict();
            stopped.store(true, Ordering::Release);
            terminal = true;
            origin
                .retain_cleanup_deadline(origin.session_deadline())
                .map_err(|_| AuthorityError::Permission)?;
        }
        match origin
            .try_receive()
            .map_err(|_| AuthorityError::Permission)?
        {
            Some(Request::PrepareOnce(setup)) => {
                if started || terminal {
                    return Err(AuthorityError::Permission);
                }
                started = true;
                let (tx, rx) = mpsc::sync_channel(1);
                *serve_tx = Some(tx);
                let events = event_tx.clone();
                let stop = Arc::clone(&stopped);
                *worker = Some(
                    thread::Builder::new()
                        .name("original-completed-pair".into())
                        .spawn(move || worker_main(setup, rx, events, stop))
                        .map_err(|_| AuthorityError::Storage)?,
                );
            }
            Some(Request::Serve(grant)) => {
                if terminal || !prepared {
                    return Err(AuthorityError::Permission);
                }
                serve_tx
                    .take()
                    .ok_or(AuthorityError::Permission)?
                    .try_send(grant)
                    .map_err(|_| AuthorityError::Permission)?;
            }
            Some(Request::FinishService | Request::Cancel) => {
                // Origin already latched its genuine local restriction before
                // returning this request. Stop before dropping queues/custody.
                stopped.store(true, Ordering::Release);
                terminal = true;
                ordered_terminal = true;
                drop(serve_tx.take());
            }
            Some(Request::ClosePurpose) => {
                if !disposed {
                    return Err(AuthorityError::Permission);
                }
                origin
                    .send_purpose_closed()
                    .map_err(|_| AuthorityError::Permission)?;
                return Ok(());
            }
            None => {}
        }
        match event_rx.try_recv() {
            Ok(WorkerEvent::Prepared(data, deadline)) => {
                if prepared {
                    return Err(AuthorityError::Permission);
                }
                if !terminal {
                    origin
                        .send_display(data, deadline)
                        .map_err(|_| AuthorityError::Permission)?;
                    prepared = true;
                }
            }
            Ok(WorkerEvent::Serving) => {
                if !terminal {
                    origin
                        .acknowledge_serving()
                        .map_err(|_| AuthorityError::Permission)?;
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => return Err(AuthorityError::Permission),
        }
        if worker.as_ref().is_some_and(JoinHandle::is_finished) {
            // Join consumes the only handle. All worker locals are already
            // dropped, including accepted socket and protected source custody.
            let result = worker
                .take()
                .ok_or(AuthorityError::Storage)?
                .join()
                .map_err(|_| AuthorityError::Storage)?;
            if result.is_err() && !terminal {
                origin.restrict();
                stopped.store(true, Ordering::Release);
                terminal = true;
                if prepared {
                    origin.send_service_failed()
                } else {
                    origin.send_preparation_failed()
                }
                .map_err(|_| AuthorityError::Permission)?;
                failure_reported = true;
            }
            if !terminal {
                return Err(AuthorityError::Permission);
            }
        }
        if terminal && !disposed && worker.is_none() {
            // A local expiry without an ordered Cancel must still produce a
            // bounded authenticated failure before disposal. Never imply success.
            if !ordered_terminal && !failure_reported {
                if !started {
                    thread::sleep(POLL);
                    continue;
                }
                if prepared {
                    origin.send_service_failed()
                } else {
                    origin.send_preparation_failed()
                }
                .map_err(|_| AuthorityError::Permission)?;
                failure_reported = true;
            }
            origin
                .send_disposed()
                .map_err(|_| AuthorityError::Permission)?;
            disposed = true;
        }
        thread::sleep(POLL);
    }
}
fn worker_main(
    setup: Setup,
    serve_rx: Receiver<Serve>,
    events: SyncSender<WorkerEvent>,
    stopped: Arc<AtomicBool>,
) -> Result<()> {
    let prepared = prepare(&setup)?;
    events
        .try_send(WorkerEvent::Prepared(
            prepared.presentation.clone(),
            prepared.original_service_deadline,
        ))
        .map_err(|_| AuthorityError::Permission)?;
    let original_read = setup.original_setup_deadline();
    let grant = loop {
        if stopped.load(Ordering::Acquire) {
            return Ok(());
        }
        if Instant::now() >= original_read {
            return Err(AuthorityError::Expired);
        }
        setup
            .check_original_coordinator_alive()
            .map_err(|_| AuthorityError::Permission)?;
        match serve_rx.recv_timeout(POLL) {
            Ok(grant) => break grant,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(AuthorityError::Permission),
        }
    };
    drop(setup);
    grant
        .check_current()
        .map_err(|_| AuthorityError::Permission)?;
    if grant.presentation() != &prepared.presentation
        || grant.original_service_deadline() != prepared.original_service_deadline
    {
        return Err(AuthorityError::InvalidBinding);
    }
    events
        .try_send(WorkerEvent::Serving)
        .map_err(|_| AuthorityError::Permission)?;
    serve_original(prepared.server, prepared.listener, grant, &stopped)
}

/// One serial worker owns both journals, listener, accepted socket and TLS.
/// The original-channel monitor retains and joins that same worker before Disposed.
fn serve_original(
    server: AuthorityServer,
    listener: TcpListener,
    grant: Serve,
    stopped: &AtomicBool,
) -> Result<()> {
    require_pair_sources(&server)?;
    listener.set_nonblocking(true).map_err(|_| AuthorityError::Storage)?;
    let admission = crate::admission::Admission::new();
    let mut accepted = 0usize;
    loop {
        if stopped.load(Ordering::Acquire) { return Ok(()); }
        grant.check_current().map_err(|_| AuthorityError::Permission)?;
        match listener.accept() {
            Ok((socket, address)) => {
                accepted = accepted.checked_add(1).ok_or(AuthorityError::Limit)?;
                if accepted > MAX_CONNECTIONS { return Err(AuthorityError::Limit); }
                let deadline = (Instant::now() + IO_TIMEOUT).min(grant.effective_io_deadline());
                grant.check_current().map_err(|_| AuthorityError::Permission)?;
                let _accepted = admission.admit(address.ip())?;
                socket.set_nonblocking(false).map_err(|_| AuthorityError::Storage)?;
                connection(&server, socket, &grant, deadline)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(POLL),
            Err(_) => return Err(AuthorityError::Permission),
        }
    }
}
use crate::durable_financial_continuation_owner_v1::ConfiguredFinancialWitnessV1;
use wholepact_financial_coordinator_origin::{
    CompletedPairAccountV1, COMPLETED_PAIR_MODE, COMPLETED_PAIR_PURPOSE,
};
type PairSources = std::collections::BTreeMap<String, Arc<ConfiguredFinancialWitnessV1>>;
fn require_pair_sources(server: &AuthorityServer) -> Result<&PairSources> {
    let sources = server.completed_dispatch_v1.as_deref().ok_or(AuthorityError::Permission)?;
    if sources.len() != 2 { return Err(AuthorityError::Permission); }
    Ok(sources)
}
fn check_service_source(server: &AuthorityServer, grant: &Serve, deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline { return Err(AuthorityError::Expired); }
    let guard = Guard::CompletedPairServe(grant);
    guard.check()?;
    for source in require_pair_sources(server)?.values() {
        source.journal().born_owner.as_ref().ok_or(AuthorityError::Permission)?
            .check_setup_current_until(guard, false, deadline)?;
    }
    if Instant::now() >= deadline { return Err(AuthorityError::Expired); }
    guard.check()
}
struct ServiceSocket<'a> {
    socket: TcpStream,
    deadline: Instant,
    grant: &'a Serve,
}
impl ServiceSocket<'_> {
    fn check(&self) -> std::io::Result<()> {
        if Instant::now() >= self.deadline {
            return Err(std::io::Error::from(std::io::ErrorKind::TimedOut));
        }
        self.grant.check_current()
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::PermissionDenied))
    }
    fn before(&self) -> std::io::Result<()> {
        self.check()?;
        let remaining = self.deadline.checked_duration_since(Instant::now())
            .filter(|v| !v.is_zero())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::TimedOut))?;
        self.socket.set_read_timeout(Some(remaining))?;
        self.socket.set_write_timeout(Some(remaining))?;
        // Final attempt sample after setup, never a cached reusable permit.
        self.check()
    }
}
impl Read for ServiceSocket<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.before()?;
        let n = self.socket.read(bytes)?;
        self.check()?;
        Ok(n)
    }
}
impl Write for ServiceSocket<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.before()?;
        let n = self.socket.write(bytes)?;
        self.check()?;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.before()?;
        self.socket.flush()?;
        self.check()
    }
}
fn connection(server: &AuthorityServer, socket: TcpStream, grant: &Serve, deadline: Instant) -> Result<()> {
    check_service_source(server, grant, deadline)?;
    let actual_listen = socket.local_addr().map_err(|_| AuthorityError::Authentication)?.to_string();
    for source in require_pair_sources(server)?.values() {
        source.require_endpoint(&server.tls.certificate_digest, &actual_listen)?;
    }
    let mut socket = ServiceSocket { socket, deadline, grant };
    let mut tls = ServerConnection::new(Arc::clone(&server.tls.config))
        .map_err(|_| AuthorityError::Authentication)?;
    while tls.is_handshaking() {
        tls.complete_io(&mut socket).map_err(|_| AuthorityError::Authentication)?;
        grant.check_current().map_err(|_| AuthorityError::Permission)?;
    }
    if tls.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
        || tls.alpn_protocol() != Some(ALPN)
    { return Err(AuthorityError::Authentication); }
    let peer = certificate_digest(tls.peer_certificates().and_then(|v| v.first())
        .ok_or(AuthorityError::Authentication)?);
    let mut stream = StreamOwned::new(tls, socket);
    let request: WireRequest = read_frame(&mut stream)?;
    check_service_source(server, grant, deadline)?;
    let response = match request {
        WireRequest::Snapshot { account_id, network_profile_id } => {
            let source = require_pair_sources(server)?.get(&account_id).ok_or(AuthorityError::Permission)?;
            source.journal().completed_pair_snapshot_guarded_v1(
                source, &peer, &account_id, &network_profile_id, grant, deadline,
            ).map(WireResponse::Snapshot)
        }
        WireRequest::ReadHistory { account_id, network_profile_id, expected_head, after_sequence, maximum_entries } => {
            let source = require_pair_sources(server)?.get(&account_id).ok_or(AuthorityError::Permission)?;
            source.journal().completed_pair_history_guarded_v1(
                source, &peer, &account_id, &network_profile_id, &expected_head,
                after_sequence, maximum_entries, grant, deadline,
            ).map(|page| WireResponse::History(Box::new(page)))
        }
        request @ WireRequest::Mutate { .. } => {
            // Actual pair source/service/clock/R sample immediately before the
            // unchanged exact request kernel. No new in-transaction R hook.
            check_service_source(server, grant, deadline)?;
            stream.sock.check().map_err(|_| AuthorityError::Permission)?;
            server.serve_completed_dispatch_v1(&peer, request)
        }
        _ => Err(AuthorityError::Permission),
    }.unwrap_or_else(WireResponse::Rejected);
    // A request already admitted can settle after R. A response suppressed here
    // is uncertain at H, never proof of no commit or a new permission to retry.
    check_service_source(server, grant, deadline)?;
    write_frame(&mut stream, &response)?;
    stream.conn.send_close_notify();
    stream.flush().map_err(|_| AuthorityError::Uncertain)
}
impl AuthorityJournal {
    fn completed_pair_snapshot_guarded_v1(
        &self, source: &ConfiguredFinancialWitnessV1, peer: &str, account: &str,
        network: &str, grant: &Serve, deadline: Instant,
    ) -> Result<AccountSnapshot> {
        let guard = Guard::CompletedPairServe(grant);
        let read = crate::journal::ReadGuardV1::coordinated_until(guard, deadline);
        read.check()?;
        self.born_owner.as_ref().ok_or(AuthorityError::Permission)?
            .check_setup_current_until(guard, false, deadline)?;
        let c = self.connection.lock().map_err(|_| AuthorityError::Storage)?;
        read.check()?;
        let tx = rusqlite::Transaction::new_unchecked(c.connection(), rusqlite::TransactionBehavior::Deferred)?;
        let ledger = crate::journal::load_financial_continuation_guarded_v1(&tx, read)?;
        // Dispatcher is NOT an ordinary principal; its independent exact pin
        // comes only from this actual account's committed original delegation.
        source.require_dispatcher_locked(self, &ledger, peer)?;
        if ledger.policy.account_id != account || ledger.policy.network_profile_id != network {
            return Err(AuthorityError::Authentication);
        }
        read.check()?;
        Ok(ledger.snapshot)
    }
    fn completed_pair_history_guarded_v1(
        &self, source: &ConfiguredFinancialWitnessV1, peer: &str, account: &str,
        network: &str, expected: &AuthorityHead, after: u64, maximum: u16,
        grant: &Serve, deadline: Instant,
    ) -> Result<HistoryPage> {
        let guard = Guard::CompletedPairServe(grant);
        let read = crate::journal::ReadGuardV1::coordinated_until(guard, deadline);
        read.check()?;
        self.born_owner.as_ref().ok_or(AuthorityError::Permission)?
            .check_setup_current_until(guard, false, deadline)?;
        if maximum == 0 || maximum > 16 || after > expected.sequence { return Err(AuthorityError::Limit); }
        let c = self.connection.lock().map_err(|_| AuthorityError::Storage)?;
        read.check()?;
        let tx = rusqlite::Transaction::new_unchecked(c.connection(), rusqlite::TransactionBehavior::Deferred)?;
        let ledger = crate::journal::load_financial_continuation_guarded_v1(&tx, read)?;
        source.require_dispatcher_locked(self, &ledger, peer)?;
        if ledger.policy.account_id != account || ledger.policy.network_profile_id != network {
            return Err(AuthorityError::Authentication);
        }
        let page = crate::journal::history_page_at_guarded(&tx, ledger, expected, after, maximum, read)?;
        read.check()?;
        Ok(page)
    }
}

fn prepare(setup: &Setup) -> Result<Prepared> {
    let guard = Guard::CompletedPairSetup(setup);
    guard.check()?;
    let inputs = setup.inputs();
    let original = setup.original_binding();
    inputs.require_original(original).map_err(|_| AuthorityError::InvalidBinding)?;
    let fields = &inputs.owners[0].selectors;
    let owner_der = Zeroizing::new(hex::decode(&fields.owner_certificate_der_hex)
        .map_err(|_| AuthorityError::InvalidBinding)?);
    let owner_certificate = CertificateDer::from(owner_der.as_slice());
    webpki::EndEntityCert::try_from(&owner_certificate).map_err(|_| AuthorityError::Authentication)?;
    let owner_digest = certificate_digest(&owner_certificate);
    if original.owners.iter().any(|o| o.owner_certificate_digest != owner_digest) {
        return Err(AuthorityError::Authentication);
    }
    let address: std::net::SocketAddr = fields.endpoint.parse().map_err(|_| AuthorityError::InvalidBinding)?;
    if address.to_string() != fields.endpoint || address.port() == 0
        || address.ip().is_unspecified() || address.ip().is_multicast()
    { return Err(AuthorityError::InvalidBinding); }
    let certificate = CertificateDer::from(guard.read(
        std::path::Path::new(&fields.server_certificate_der), 65536,
    )?.to_vec());
    let name = ServerName::try_from(fields.server_name.clone()).map_err(|_| AuthorityError::InvalidBinding)?;
    webpki::EndEntityCert::try_from(&certificate).map_err(|_| AuthorityError::Authentication)?
        .verify_is_valid_for_subject_name(&name).map_err(|_| AuthorityError::Authentication)?;
    let pin = certificate_digest(&certificate);
    if pin != fields.pinned_server_certificate_digest { return Err(AuthorityError::Authentication); }
    let namespaces = inputs.owners.each_ref().map(|input| {
        let selected = &input.selectors;
        crate::witness_locator::NamespaceOpenInput {
            #[cfg(feature = "synthetic-qualification")]
            synthetic_installation: None,
            endpoint: selected.endpoint.clone(),
            server_name: selected.server_name.clone(),
            witness_id: selected.witness_id.clone(),
            pinned_server_certificate_digest: pin.clone(),
            owner_certificate_digest: owner_digest.clone(),
            network_profile_id: selected.network_profile_id.clone(),
            storage_key_file: selected.storage_key_file.clone(),
            expected_account_id: selected.expected_account_id.clone(),
        }
    });
    // One exclusive namespace core, not two independent legacy opens. The
    // opener itself checks exact namespace equality and independently audits
    // both original account journals under this genuine Pair Setup.
    let [journal1, journal2] = crate::witness_locator::open_born_financial_histories_guarded_v1(&namespaces, guard)?;
    let (source1, account1, terms1) = prepare_account(setup, 0, journal1, &owner_digest, &pin)?;
    let (source2, account2, terms2) = prepare_account(setup, 1, journal2, &owner_digest, &pin)?;
    if terms1.scope.delivery != terms2.scope.delivery
        || terms1.scope.authorization.fixed != terms2.scope.authorization.fixed
    { return Err(AuthorityError::InvalidBinding); }
    let fixed_digest = crate::digest("wholepact:coordinated-completed-pair:fixed:v1", &terms1.scope.authorization.fixed)?;
    let delivery_digest = crate::digest("wholepact:coordinated-completed-pair:delivery:v1", &terms1.scope.delivery)?;
    let accounts = [account1, account2];
    let root = CertificateDer::from(guard.read(std::path::Path::new(&fields.trusted_client_root_der), 65536)?.to_vec());
    let key = guard.read(std::path::Path::new(&fields.server_private_key_pkcs8_der), 65536)?;
    let tls = ServerTls::new(vec![root], vec![certificate],
        PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(key.to_vec())))?;
    guard.check()?;
    let listener = TcpListener::bind(address).map_err(|_| AuthorityError::Permission)?;
    guard.check()?;
    if listener.local_addr().map_err(|_| AuthorityError::Storage)? != address {
        return Err(AuthorityError::Authentication);
    }
    listener.set_nonblocking(true).map_err(|_| AuthorityError::Storage)?;

    // Sample monotonic BEFORE wall conversion. These immutable original
    // material/payment/enrollment/policy/terms/delivery ceilings may only
    // shorten the actual nominal source Instant, never recreate its ancestry.
    let observed = Instant::now();
    let prepared_at_ms = now_ms()?;
    terms1.require_live(prepared_at_ms)?;
    terms2.require_live(prepared_at_ms)?;
    let (from1, until1) = service_wall_bounds(&terms1)?;
    let (from2, until2) = service_wall_bounds(&terms2)?;
    let valid_from_ms = from1.max(from2);
    let valid_until_ms = until1.min(until2)
        .min(original.owners[0].source_expires_at_ms)
        .min(original.owners[1].source_expires_at_ms);
    if prepared_at_ms < valid_from_ms { return Err(AuthorityError::Expired); }
    let remaining = valid_until_ms.checked_sub(prepared_at_ms).filter(|v| *v > 0).ok_or(AuthorityError::Expired)?;
    let wall_deadline = observed.checked_add(Duration::from_millis(remaining)).ok_or(AuthorityError::Limit)?;
    let original_service_deadline = setup.original_source_deadline().min(wall_deadline);
    let setup_remaining = setup.original_setup_deadline().checked_duration_since(observed)
        .filter(|v| !v.is_zero()).ok_or(AuthorityError::Expired)?;
    let expires_at_ms = prepared_at_ms.checked_add(u64::try_from(setup_remaining.as_millis())
        .map_err(|_| AuthorityError::Limit)?).ok_or(AuthorityError::Limit)?.min(valid_until_ms);
    let display = format!(
        "ORIGINAL COMPLETED-PAIR RESOURCE SERVICE\nServe only these two exact committed original accounts to each independently committed dispatcher certificate over mutual TLS. This resource review is NOT Host dispatch approval. The Host still needs its separate fresh exact TTY approval for every attempt. Cancellation stops new requests; an already admitted exact request may settle and a lost reply remains uncertain.\nEndpoint: {}\nServer certificate: {}\nOwner certificate: {}\nNetwork: {}\nS1 account: {}\nS1 operation: {}\nS1 dispatcher certificate: {}\nS1 source: {}\nS1 current head: {}:{}\nS2 account: {}\nS2 operation: {}\nS2 dispatcher certificate: {}\nS2 source: {}\nS2 current head: {}:{}\nFixed: {}\nDelivery: {}\nOriginal valid-from ms: {}\nOriginal valid-until ms: {}\n",
        fields.endpoint, pin, owner_digest, fields.network_profile_id,
        accounts[0].account_id, accounts[0].operation_id, accounts[0].dispatcher_certificate_digest,
        accounts[0].source_commitment, accounts[0].current_head_sequence, accounts[0].current_head_digest,
        accounts[1].account_id, accounts[1].operation_id, accounts[1].dispatcher_certificate_digest,
        accounts[1].source_commitment, accounts[1].current_head_sequence, accounts[1].current_head_digest,
        fixed_digest, delivery_digest, valid_from_ms, valid_until_ms,
    );
    let backend_review_digest = crate::digest("wholepact:coordinated-completed-pair:review:v1",
        &(&display, &accounts, &fixed_digest, &delivery_digest,
            original.commitment().map_err(|_| AuthorityError::InvalidBinding)?))?;
    let mut presentation = Presentation {
        version: 1, purpose: COMPLETED_PAIR_PURPOSE.into(), mode: COMPLETED_PAIR_MODE.into(),
        display, backend_review_digest, presentation_digest: String::new(), prepared_at_ms,
        expires_at_ms, valid_from_ms, valid_until_ms,
        endpoint: fields.endpoint.clone(), server_name: fields.server_name.clone(),
        witness_id: fields.witness_id.clone(), pinned_server_certificate_digest: pin,
        owner_certificate_digest: owner_digest, fixed_digest, delivery_digest, accounts,
        original: original.clone(),
    };
    presentation.presentation_digest = presentation.calculate_presentation_digest()
        .map_err(|_| AuthorityError::InvalidBinding)?;
    presentation.validate().map_err(|_| AuthorityError::InvalidBinding)?;
    guard.check()?;
    if Instant::now() >= original_service_deadline { return Err(AuthorityError::Expired); }
    let mut server = AuthorityServer::new(source1.journal(), tls);
    let sources = std::collections::BTreeMap::from([
        (presentation.accounts[0].account_id.clone(), Arc::new(source1)),
        (presentation.accounts[1].account_id.clone(), Arc::new(source2)),
    ]);
    if sources.len() != 2 { return Err(AuthorityError::Conflict); }
    server.completed_dispatch_v1 = Some(Arc::new(sources));
    Ok(Prepared { server, listener, presentation, original_service_deadline })
}

fn prepare_account(
    setup: &Setup, index: usize, journal: AuthorityJournal, owner_digest: &str, pin: &str,
) -> Result<(ConfiguredFinancialWitnessV1, CompletedPairAccountV1, crate::durable_financial_continuation_v1::FinancialContinuationTermsV1)> {
    let guard = Guard::CompletedPairSetup(setup);
    guard.check()?;
    let input = setup.inputs().owners.get(index).ok_or(AuthorityError::InvalidBinding)?;
    let original = setup.original_binding().owners.get(index).ok_or(AuthorityError::InvalidBinding)?;
    let fields = &input.selectors;
    let expected: OwnerControlRequest = wholepact_core::parse_typed_json(original.request_json.as_bytes())
        .map_err(|_| AuthorityError::InvalidBinding)?;
    if expected.operation_id != input.continuation_operation_id
        || expected.operation_id != original.operation_id
        || expected.account_id != fields.expected_account_id || expected.account_id != original.account_id
        || expected.network_profile_id != fields.network_profile_id || expected.network_profile_id != original.network_profile_id
    { return Err(AuthorityError::InvalidBinding); }
    let source = ConfiguredFinancialWitnessV1::from_original_completed_pair_v1(journal, &expected, setup)?;
    source.require_endpoint(pin, &fields.endpoint)?;
    let disclosure = source.coordinated_original_disclosure_v1();
    let selected: WitnessDisclosureDescriptor = wholepact_core::parse_typed_json(original.owner_disclosure_json.as_bytes())
        .map_err(|_| AuthorityError::InvalidBinding)?;
    if disclosure != &selected || disclosure.witness_id != fields.witness_id
        || wholepact_core::proposal::canonical_digest("wholepact:coordinated-original-financial-disclosure:v1", disclosure)
            .map_err(|_| AuthorityError::InvalidBinding)? != original.owner_disclosure_digest
    { return Err(AuthorityError::InvalidBinding); }
    let admission = source.coordinated_original_admission_v1();
    if admission != &expected { return Err(AuthorityError::InvalidBinding); }
    let OwnerControl::AdmitFinancialContinuationV1 { record } = &admission.control else {
        return Err(AuthorityError::Permission);
    };
    record.validate_request(admission, disclosure)?;
    let admission_digest = record.request_digest(admission)?;
    let terms = record.terms.clone();
    if terms.intent_terms_digest()? != original.terms_digest
        || terms.valid_until_ms != original.source_expires_at_ms
    { return Err(AuthorityError::InvalidBinding); }
    let actual = source.journal();
    let (snapshot, source_commitment) = {
        let c = actual.connection.lock().map_err(|_| AuthorityError::Storage)?;
        guard.check()?;
        let tx = rusqlite::Transaction::new_unchecked(c.connection(), rusqlite::TransactionBehavior::Deferred)?;
        let read = crate::journal::ReadGuardV1::coordinated(guard);
        crate::journal::authenticate_admission_guarded(&tx, owner_digest, read)?;
        let ledger = crate::journal::load_financial_continuation_guarded_v1(&tx, read)?;
        ledger.authenticate_read(owner_digest, &fields.expected_account_id, &fields.network_profile_id)?;
        source.require_locked(&actual, &ledger)?;
        if ledger.policy.owner_certificate_digest != owner_digest { return Err(AuthorityError::Authentication); }
        // Independently verify this actual account's committed dispatcher pin,
        // including its required separation from owner and original writer.
        source.require_dispatcher_locked(&actual, &ledger, &terms.scope.delivery.dispatcher.public_identity_commitment)?;
        let (stamp, birth) = crate::journal::namespace_financial_account_stamp_guarded_v1(&tx, &ledger.policy, read)?;
        actual.born_owner.as_ref().ok_or(AuthorityError::Permission)?
            .require_original_account_connection(&c, &birth)?;
        read.check()?;
        let (head, payload): (String, Zeroizing<Vec<u8>>) = tx.query_row(
            "SELECT head,payload FROM authority_events WHERE sequence=?1",
            [original.admitted_head_sequence],
            |r| Ok((r.get(0)?, Zeroizing::new(r.get(1)?))),
        )?;
        read.check()?;
        let event: crate::policy::Event = decode(&payload)?;
        if head != original.admitted_head_digest || event.authenticated_certificate_digest != owner_digest
            || !matches!(event.mutation, AuthorityMutation::OwnerControl(ref request) if request == admission)
        { return Err(AuthorityError::InvalidBinding); }
        let commitment = crate::digest("wholepact:coordinated-completed-pair:original-source:v1",
            &(&stamp, &ledger.policy, admission, disclosure,
                original.commitment().map_err(|_| AuthorityError::InvalidBinding)?))?;
        read.check()?;
        (ledger.snapshot, commitment)
    };
    let account = CompletedPairAccountV1 {
        account_id: snapshot.account_id, network_profile_id: snapshot.network_profile_id,
        operation_id: admission.operation_id.clone(), admission_digest, source_commitment,
        policy_digest: snapshot.policy_digest,
        dispatcher_certificate_digest: terms.scope.delivery.dispatcher.public_identity_commitment.clone(),
        current_head_sequence: snapshot.head.sequence, current_head_digest: snapshot.head.digest,
    };
    guard.check()?;
    Ok((source, account, terms))
}

/// Pure intersection of actual audited immutable original terms. No clock is
/// created here, and no bound can extend the nominal source service ceiling.
fn service_wall_bounds(terms: &crate::durable_financial_continuation_v1::FinancialContinuationTermsV1) -> Result<(u64, u64)> {
    terms.validate()?;
    let scope = &terms.scope;
    let ceilings = &scope.original_ceilings;
    let mut from = terms.valid_from_ms.max(scope.authorization.valid_from_ms)
        .max(scope.delivery.valid_from_ms).max(ceilings.payment_valid_from_ms);
    let mut until = terms.valid_until_ms.min(scope.authorization.valid_until_ms)
        .min(scope.delivery.valid_until_ms).min(ceilings.payment_valid_until_ms)
        .min(ceilings.enrollment_expires_at_ms).min(ceilings.policy_expires_at_ms);
    for material in &ceilings.material_scopes {
        from = from.max(material.valid_from_unix_seconds.checked_mul(1000).ok_or(AuthorityError::Limit)?);
        until = until.min(material.valid_until_unix_seconds.checked_mul(1000).ok_or(AuthorityError::Limit)?);
    }
    if from >= until { return Err(AuthorityError::Expired); }
    Ok((from, until))
}
