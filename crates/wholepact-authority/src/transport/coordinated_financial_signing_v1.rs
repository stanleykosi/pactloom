//! Original committed financial service under a separate common-image resource
//! owner. Serving is not a new financial approval. Existing authenticated
//! delegation/session kernels retain every mutation policy and commit rule.
//! This leaf is intentionally unregistered until its actual setup/serving join
//! and shared guarded read kernels have independent source review.
use super::*;
use crate::native_witness_owner::financial_setup_guard_v1::FinancialSetupGuardV1 as Guard;
use std::sync::atomic::{AtomicBool, Ordering};
use wholepact_financial_coordinator_origin::WitnessFinancialSigningServeV1 as Serve;

const POLL: Duration = Duration::from_millis(5);
const MAX_CONNECTIONS: usize = 4096;

use std::{
    sync::mpsc::{self, Receiver, SyncSender, TryRecvError},
    thread::{self, JoinHandle},
};
use wholepact_financial_coordinator_origin::{
    FinancialSigningPresentationV1 as Presentation, FinancialSigningRequestV1 as Request,
    WitnessFinancialSigningOriginV1 as Origin, WitnessFinancialSigningSetupV1 as Setup,
};
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
pub fn run_coordinated_financial_signing_v1(origin: Origin) -> ! {
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
    let mut normal_finish = false;
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
                // A blocked worker cannot be joined honestly. The actual role
                // exits unsuccessfully; it MUST NOT send a disposal receipt.
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
                        .name("original-financial-signing".into())
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
            Some(Request::FinishService) => {
                normal_finish = true;
                stopped.store(true, Ordering::Release);
                terminal = true;
                ordered_terminal = true;
                drop(serve_tx.take());
            }
            Some(Request::Cancel) => {
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
            // A genuine normal FinishService requires a successfully joined
            // worker, not merely a joined handle. Cancellation can dispose
            // failed work, but must never turn its result into normal success.
            if normal_finish {
                if let Err(error) = result {
                    origin.restrict();
                    stopped.store(true, Ordering::Release);
                    origin.send_service_failed().map_err(|_| AuthorityError::Permission)?;
                    return Err(error);
                }
            } else if result.is_err() && !terminal {
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
    if grant.presentation() != &prepared.presentation {
        return Err(AuthorityError::InvalidBinding);
    }
    events
        .try_send(WorkerEvent::Serving)
        .map_err(|_| AuthorityError::Permission)?;
    serve_original(prepared.server, prepared.listener, grant, &stopped)
}

/// One serial worker owns all actual listener, TLS and journal custody. The
/// independent original-channel monitor must join/drop it before Disposed.
fn serve_original(
    server: AuthorityServer,
    listener: TcpListener,
    grant: Serve,
    stopped: &AtomicBool,
) -> Result<()> {
    if !matches!(
        server.financial_signing.as_deref(),
        Some(financial_signing_server_v1::FinancialSigningServingV1::Committed { .. })
    ) {
        return Err(AuthorityError::Permission);
    }
    listener
        .set_nonblocking(true)
        .map_err(|_| AuthorityError::Storage)?;
    let admission = crate::admission::Admission::new();
    let mut accepted = 0usize;
    loop {
        if stopped.load(Ordering::Acquire) {
            return Ok(());
        }
        grant
            .check_current()
            .map_err(|_| AuthorityError::Permission)?;
        match listener.accept() {
            Ok((socket, address)) => {
                accepted = accepted.checked_add(1).ok_or(AuthorityError::Limit)?;
                if accepted > MAX_CONNECTIONS {
                    return Err(AuthorityError::Limit);
                }
                let deadline = (Instant::now() + IO_TIMEOUT).min(grant.effective_io_deadline());
                grant
                    .check_current()
                    .map_err(|_| AuthorityError::Permission)?;
                let _accepted = admission.admit(address.ip())?;
                connection(&server, socket, &grant, deadline)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(POLL),
            Err(_) => return Err(AuthorityError::Permission),
        }
    }
}
fn check_service_source(server: &AuthorityServer, grant: &Serve, deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        return Err(AuthorityError::Expired);
    }
    let guard = Guard::SigningServe(grant);
    guard.check()?;
    server
        .journal
        .born_owner
        .as_ref()
        .ok_or(AuthorityError::Permission)?
        .check_setup_current_until(guard, false, deadline)?;
    if Instant::now() >= deadline {
        return Err(AuthorityError::Expired);
    }
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
        self.grant
            .check_current()
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::PermissionDenied))
    }
    fn before(&self) -> std::io::Result<()> {
        self.check()?;
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|v| !v.is_zero())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::TimedOut))?;
        self.socket.set_read_timeout(Some(remaining))?;
        self.socket.set_write_timeout(Some(remaining))?;
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
fn connection(
    server: &AuthorityServer,
    socket: TcpStream,
    grant: &Serve,
    deadline: Instant,
) -> Result<()> {
    check_service_source(server, grant, deadline)?;
    server.require_financial_signing_socket_v1(&socket)?;
    let mut socket = ServiceSocket {
        socket,
        deadline,
        grant,
    };
    let mut tls = ServerConnection::new(Arc::clone(&server.tls.config))
        .map_err(|_| AuthorityError::Authentication)?;
    while tls.is_handshaking() {
        tls.complete_io(&mut socket)
            .map_err(|_| AuthorityError::Authentication)?;
        grant
            .check_current()
            .map_err(|_| AuthorityError::Permission)?;
    }
    if tls.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
        || tls.alpn_protocol() != Some(ALPN)
    {
        return Err(AuthorityError::Authentication);
    }
    let peer = certificate_digest(
        tls.peer_certificates()
            .and_then(|v| v.first())
            .ok_or(AuthorityError::Authentication)?,
    );
    let exporter = Zeroizing::new(
        tls.export_keying_material([0u8; 32], crate::session::EXPORTER_LABEL, None)
            .map_err(|_| AuthorityError::Authentication)?,
    );
    let mut stream = StreamOwned::new(tls, socket);
    let request: WireRequest = read_frame(&mut stream)?;
    check_service_source(server, grant, deadline)?;
    let response = match request {
        WireRequest::Snapshot {
            account_id,
            network_profile_id,
        } => server
            .journal
            .financial_snapshot_guarded_v1(
                &peer,
                &account_id,
                &network_profile_id,
                Guard::SigningServe(grant),
                deadline,
            )
            .map(WireResponse::Snapshot),
        WireRequest::ReadHistory {
            account_id,
            network_profile_id,
            expected_head,
            after_sequence,
            maximum_entries,
        } => server
            .journal
            .financial_history_page_guarded_v1(
                &peer,
                &account_id,
                &network_profile_id,
                &expected_head,
                after_sequence,
                maximum_entries,
                Guard::SigningServe(grant),
                deadline,
            )
            .map(|v| WireResponse::History(Box::new(v))),
        request @ WireRequest::Mutate { .. } => {
            // THE request-admission sample. R after this point does not roll
            // back an admitted existing transaction or manufacture no-effect.
            // No coordinator callback is inserted into the maintained kernel.
            stream
                .sock
                .check()
                .map_err(|_| AuthorityError::Permission)?;
            server.serve_financial_signing_request_v1(&peer, &exporter, request)
        }
        _ => Err(AuthorityError::Permission),
    }
    .unwrap_or_else(WireResponse::Rejected);
    // A committed response lost to R/death/expiry remains uncertain at S.
    // Never convert that outcome into permission to retry or a no-effect claim.
    check_service_source(server, grant, deadline)?;
    write_frame(&mut stream, &response)?;
    stream.conn.send_close_notify();
    stream.flush().map_err(|_| AuthorityError::Uncertain)
}

impl AuthorityJournal {
    fn financial_snapshot_guarded_v1(
        &self,
        peer: &str,
        account: &str,
        network: &str,
        guard: Guard<'_>,
        deadline: Instant,
    ) -> Result<AccountSnapshot> {
        let read_guard = crate::journal::ReadGuardV1::coordinated_until(guard, deadline);
        read_guard.check()?;
        self.born_owner
            .as_ref()
            .ok_or(AuthorityError::Permission)?
            .check_setup_current_until(guard, false, deadline)?;
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        read_guard.check()?;
        let tx = rusqlite::Transaction::new_unchecked(
            c.connection(),
            rusqlite::TransactionBehavior::Deferred,
        )?;
        crate::journal::authenticate_admission_guarded(&tx, peer, read_guard)?;
        let ledger = crate::journal::load_financial_continuation_guarded_v1(&tx, read_guard)?;
        ledger.authenticate_read(peer, account, network)?;
        read_guard.check()?;
        Ok(ledger.snapshot)
    }
    fn financial_history_page_guarded_v1(
        &self,
        peer: &str,
        account: &str,
        network: &str,
        expected: &AuthorityHead,
        after: u64,
        maximum: u16,
        guard: Guard<'_>,
        deadline: Instant,
    ) -> Result<HistoryPage> {
        let read_guard = crate::journal::ReadGuardV1::coordinated_until(guard, deadline);
        read_guard.check()?;
        self.born_owner
            .as_ref()
            .ok_or(AuthorityError::Permission)?
            .check_setup_current_until(guard, false, deadline)?;
        if maximum == 0 || maximum > 16 || after > expected.sequence {
            return Err(AuthorityError::Limit);
        }
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        read_guard.check()?;
        let tx = rusqlite::Transaction::new_unchecked(
            c.connection(),
            rusqlite::TransactionBehavior::Deferred,
        )?;
        crate::journal::authenticate_admission_guarded(&tx, peer, read_guard)?;
        let ledger = crate::journal::load_financial_continuation_guarded_v1(&tx, read_guard)?;
        ledger.authenticate_read(peer, account, network)?;
        let page = crate::journal::history_page_at_guarded(
            &tx, ledger, expected, after, maximum, read_guard,
        )?;
        read_guard.check()?;
        Ok(page)
    }
}

fn prepare(setup: &Setup) -> Result<Prepared> {
    use crate::durable_financial_continuation_owner_v1::ConfiguredFinancialWitnessV1;
    use wholepact_financial_coordinator_origin::{
        FINANCIAL_SIGNING_MODE, FINANCIAL_SIGNING_PURPOSE,
    };
    let guard = Guard::SigningSetup(setup);
    guard.check()?;
    setup
        .inputs()
        .validate()
        .map_err(|_| AuthorityError::InvalidBinding)?;
    let fields = &setup.inputs().selectors;
    let original = setup.original_binding();
    original
        .validate()
        .map_err(|_| AuthorityError::InvalidBinding)?;
    let expected: OwnerControlRequest =
        wholepact_core::parse_typed_json(original.request_json.as_bytes())
            .map_err(|_| AuthorityError::InvalidBinding)?;
    if expected.operation_id != setup.inputs().continuation_operation_id
        || expected.operation_id != original.operation_id
        || expected.account_id != fields.expected_account_id
        || expected.account_id != original.account_id
        || expected.network_profile_id != fields.network_profile_id
        || expected.network_profile_id != original.network_profile_id
    {
        return Err(AuthorityError::InvalidBinding);
    }
    let owner_der = Zeroizing::new(
        hex::decode(&fields.owner_certificate_der_hex)
            .map_err(|_| AuthorityError::InvalidBinding)?,
    );
    let owner_certificate = CertificateDer::from(owner_der.as_slice());
    webpki::EndEntityCert::try_from(&owner_certificate)
        .map_err(|_| AuthorityError::Authentication)?;
    let owner_digest = certificate_digest(&owner_certificate);
    if owner_digest != original.owner_certificate_digest {
        return Err(AuthorityError::Authentication);
    }
    let address: std::net::SocketAddr = fields
        .endpoint
        .parse()
        .map_err(|_| AuthorityError::InvalidBinding)?;
    if address.to_string() != fields.endpoint
        || address.port() == 0
        || address.ip().is_unspecified()
        || address.ip().is_multicast()
    {
        return Err(AuthorityError::InvalidBinding);
    }
    let certificate = CertificateDer::from(
        guard
            .read(std::path::Path::new(&fields.server_certificate_der), 65536)?
            .to_vec(),
    );
    let name = ServerName::try_from(fields.server_name.clone())
        .map_err(|_| AuthorityError::InvalidBinding)?;
    webpki::EndEntityCert::try_from(&certificate)
        .map_err(|_| AuthorityError::Authentication)?
        .verify_is_valid_for_subject_name(&name)
        .map_err(|_| AuthorityError::Authentication)?;
    let pin = certificate_digest(&certificate);
    if pin != fields.pinned_server_certificate_digest {
        return Err(AuthorityError::Authentication);
    }
    let input = crate::witness_locator::NamespaceOpenInput {
        #[cfg(feature = "synthetic-qualification")]
        synthetic_installation: None,
        endpoint: fields.endpoint.clone(),
        server_name: fields.server_name.clone(),
        witness_id: fields.witness_id.clone(),
        pinned_server_certificate_digest: pin.clone(),
        owner_certificate_digest: owner_digest.clone(),
        network_profile_id: fields.network_profile_id.clone(),
        storage_key_file: fields.storage_key_file.clone(),
        expected_account_id: fields.expected_account_id.clone(),
    };
    let journal = crate::witness_locator::open_born_financial_history_guarded_v1(input, guard)?;
    let owner =
        ConfiguredFinancialWitnessV1::from_original_coordinated_v1(journal, &expected, setup)?;
    owner.require_endpoint(&pin, &fields.endpoint)?;
    let disclosure = owner.coordinated_original_disclosure_v1();
    let selected_disclosure: WitnessDisclosureDescriptor =
        wholepact_core::parse_typed_json(original.owner_disclosure_json.as_bytes())
            .map_err(|_| AuthorityError::InvalidBinding)?;
    if disclosure != &selected_disclosure
        || disclosure.witness_id != fields.witness_id
        || wholepact_core::proposal::canonical_digest(
            "wholepact:coordinated-original-financial-disclosure:v1",
            disclosure,
        )
        .map_err(|_| AuthorityError::InvalidBinding)?
            != original.owner_disclosure_digest
    {
        return Err(AuthorityError::InvalidBinding);
    }
    let admission = owner.coordinated_original_admission_v1();
    let OwnerControl::AdmitFinancialContinuationV1 { record } = &admission.control else {
        return Err(AuthorityError::Permission);
    };
    record.validate_request(admission, disclosure)?;
    let admission_digest = record.request_digest(admission)?;
    let terms = record.terms.clone();
    if terms.intent_terms_digest()? != original.terms_digest
        || terms.valid_until_ms != original.source_expires_at_ms
    {
        return Err(AuthorityError::InvalidBinding);
    }
    let actual = owner.journal();
    let (snapshot, source_commitment) = {
        let c = actual
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        guard.check()?;
        let tx = rusqlite::Transaction::new_unchecked(
            c.connection(),
            rusqlite::TransactionBehavior::Deferred,
        )?;
        let read_guard = crate::journal::ReadGuardV1::coordinated(guard);
        crate::journal::authenticate_admission_guarded(&tx, &owner_digest, read_guard)?;
        let ledger = crate::journal::load_financial_continuation_guarded_v1(&tx, read_guard)?;
        ledger.authenticate_read(
            &owner_digest,
            &fields.expected_account_id,
            &fields.network_profile_id,
        )?;
        owner.require_locked(&actual, &ledger)?;
        if ledger.policy.owner_certificate_digest != owner_digest {
            return Err(AuthorityError::Authentication);
        }
        let (stamp, birth) = crate::journal::namespace_financial_account_stamp_guarded_v1(
            &tx,
            &ledger.policy,
            read_guard,
        )?;
        actual
            .born_owner
            .as_ref()
            .ok_or(AuthorityError::Permission)?
            .require_original_account_connection(&c, &birth)?;
        guard.check()?;
        let (head, payload): (String, Zeroizing<Vec<u8>>) = tx.query_row(
            "SELECT head,payload FROM authority_events WHERE sequence=?1",
            [original.admitted_head_sequence],
            |r| Ok((r.get(0)?, Zeroizing::new(r.get(1)?))),
        )?;
        guard.check()?;
        let event: crate::policy::Event = decode(&payload)?;
        if head != original.admitted_head_digest
            || event.authenticated_certificate_digest != owner_digest
            || !matches!(event.mutation,AuthorityMutation::OwnerControl(ref request) if request==admission)
        {
            return Err(AuthorityError::InvalidBinding);
        }
        let commitment = crate::digest(
            "wholepact:coordinated-financial-signing:original-source:v1",
            &(
                &stamp,
                &ledger.policy,
                admission,
                disclosure,
                original
                    .commitment()
                    .map_err(|_| AuthorityError::InvalidBinding)?,
            ),
        )?;
        guard.check()?;
        (ledger.snapshot, commitment)
    };
    let root = CertificateDer::from(
        guard
            .read(std::path::Path::new(&fields.trusted_client_root_der), 65536)?
            .to_vec(),
    );
    let key = guard.read(
        std::path::Path::new(&fields.server_private_key_pkcs8_der),
        65536,
    )?;
    let tls = ServerTls::new(
        vec![root],
        vec![certificate],
        PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(key.to_vec())),
    )?;
    guard.check()?;
    let listener = TcpListener::bind(address).map_err(|_| AuthorityError::Permission)?;
    guard.check()?;
    if listener.local_addr().map_err(|_| AuthorityError::Storage)? != address {
        return Err(AuthorityError::Authentication);
    }
    listener
        .set_nonblocking(true)
        .map_err(|_| AuthorityError::Storage)?;
    let observed = Instant::now();
    let prepared_at_ms = now_ms()?;
    terms.require_live(prepared_at_ms)?;
    let valid_until_ms = terms.valid_until_ms.min(original.source_expires_at_ms);
    let remaining = valid_until_ms
        .checked_sub(prepared_at_ms)
        .filter(|v| *v > 0)
        .ok_or(AuthorityError::Expired)?;
    let wall_deadline = observed
        .checked_add(Duration::from_millis(remaining))
        .ok_or(AuthorityError::Limit)?;
    let original_service_deadline = setup
        .original_source_deadline()
        .min(wall_deadline);
    let setup_remaining = setup
        .original_setup_deadline()
        .checked_duration_since(observed)
        .filter(|v| !v.is_zero())
        .ok_or(AuthorityError::Expired)?;
    let expires_at_ms = prepared_at_ms
        .checked_add(u64::try_from(setup_remaining.as_millis()).map_err(|_| AuthorityError::Limit)?)
        .ok_or(AuthorityError::Limit)?
        .min(valid_until_ms);
    let display = format!(
        "ORIGINAL FINANCIAL SIGNING SERVICE\nServe only the already committed exact financial delegation and authenticated original owner/writer over mutual TLS. This is resource setup, not a new signing or mutation approval. Each Signer action still requires its own fresh review. Cancellation stops new requests; an already admitted request may commit and a lost reply remains uncertain.\nAccount: {}\nNetwork: {}\nOperation: {}\nOwner certificate: {}\nWriter certificate: {}\nSource: {}\nOriginal valid-until ms: {}\n",
        snapshot.account_id,
        snapshot.network_profile_id,
        admission.operation_id,
        owner_digest,
        terms.scope.authorization.writer_certificate_digest,
        source_commitment,
        valid_until_ms
    );
    let backend_review_digest = crate::digest(
        "wholepact:coordinated-financial-signing:review:v1",
        &(&display, &admission_digest, &source_commitment),
    )?;
    let mut presentation = Presentation {
        version: 1,
        purpose: FINANCIAL_SIGNING_PURPOSE.into(),
        mode: FINANCIAL_SIGNING_MODE.into(),
        display,
        backend_review_digest,
        presentation_digest: String::new(),
        prepared_at_ms,
        expires_at_ms,
        valid_from_ms: terms.valid_from_ms,
        valid_until_ms,
        account_id: snapshot.account_id.clone(),
        network_profile_id: snapshot.network_profile_id.clone(),
        operation_id: admission.operation_id.clone(),
        admission_digest,
        source_commitment,
        policy_digest: snapshot.policy_digest.clone(),
        owner_certificate_digest: owner_digest,
        writer_certificate_digest: terms.scope.authorization.writer_certificate_digest.clone(),
        endpoint: fields.endpoint.clone(),
        server_name: fields.server_name.clone(),
        witness_id: fields.witness_id.clone(),
        pinned_server_certificate_digest: pin,
        current_head_sequence: snapshot.head.sequence,
        current_head_digest: snapshot.head.digest.clone(),
        original: original.clone(),
    };
    presentation.presentation_digest = presentation
        .calculate_presentation_digest()
        .map_err(|_| AuthorityError::InvalidBinding)?;
    presentation
        .validate()
        .map_err(|_| AuthorityError::InvalidBinding)?;
    guard.check()?;
    let mut server = AuthorityServer::new(actual, tls);
    server.financial_signing = Some(Arc::new(
        financial_signing_server_v1::FinancialSigningServingV1::Committed {
            owner,
            #[cfg(feature = "synthetic-qualification")]
            acquire_reply_loss: None,
        },
    ));
    Ok(Prepared {
        server,
        listener,
        presentation,
        original_service_deadline,
    })
}
