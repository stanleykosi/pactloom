//! Fixed original owner-history service only. No generic AuthorityServer, writer,
//! mutation dispatcher, raw client factory, source reopen or fabricated Serving.
//! The independent monitor owns the actual worker until join. Only joined and
//! dropped listener/TLS/journal/namespace custody can be reported Disposed.
use super::*;
use crate::native_witness_owner::financial_setup_guard_v1::FinancialSetupGuardV1 as Guard;
use rusqlite::{Transaction, TransactionBehavior};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender, TryRecvError},
    },
    thread::{self, JoinHandle},
};
use wholepact_financial_coordinator_origin::{
    FinancialHistoryPresentationV1 as Presentation, FinancialHistoryRequestV1 as Request,
    WitnessFinancialHistoryOriginV1 as Origin, WitnessFinancialHistoryServeV1 as Serve,
    WitnessFinancialHistorySetupV1 as Setup, HistoryFailureStageV1, HistoryFailureClassV1,
    FINANCIAL_HISTORY_MODE, FINANCIAL_HISTORY_PURPOSE,
};
// This bridge is deliberately always compiled with the history role: only the
// receiving Origin crate owns the semantic cfg. No diagnostic result is used.
macro_rules! history_io {
    ($origin:expr, $stage:ident, $operation:expr) => {{
        let result = $operation;
        if let Err(error) = &result {
            $origin.observe_history_io_failure_detail_v1(HistoryFailureStageV1::$stage, error.kind());
        }
        result
    }};
}
fn history_authority_error(origin: &Origin, stage: HistoryFailureStageV1, error: AuthorityError) -> AuthorityError {
    origin.observe_history_failure_detail_v1(stage, history_authority_class(&error));
    error
}
fn history_authority_class(error: &AuthorityError) -> HistoryFailureClassV1 {
    match error {
        AuthorityError::InvalidBinding => HistoryFailureClassV1::InvalidBinding,
        AuthorityError::Permission => HistoryFailureClassV1::Permission,
        AuthorityError::StaleHead => HistoryFailureClassV1::StaleHead,
        AuthorityError::Conflict => HistoryFailureClassV1::Conflict,
        AuthorityError::Inactive => HistoryFailureClassV1::Inactive,
        AuthorityError::RecoveryRequired => HistoryFailureClassV1::RecoveryRequired,
        AuthorityError::Expired => HistoryFailureClassV1::Expired,
        AuthorityError::PolicyDenied => HistoryFailureClassV1::PolicyDenied,
        AuthorityError::BudgetExceeded => HistoryFailureClassV1::BudgetExceeded,
        AuthorityError::InputReserved => HistoryFailureClassV1::InputReserved,
        AuthorityError::ObligationReserved => HistoryFailureClassV1::ObligationReserved,
        AuthorityError::Limit => HistoryFailureClassV1::Limit,
        AuthorityError::Storage => HistoryFailureClassV1::Storage,
        AuthorityError::CorruptHistory => HistoryFailureClassV1::CorruptHistory,
        AuthorityError::PermanentStopUnavailable => HistoryFailureClassV1::PermanentStopUnavailable,
        AuthorityError::OfflineHistoryUnsupported => HistoryFailureClassV1::OfflineHistoryUnsupported,
        AuthorityError::ConstructionHistoryUnsupported => HistoryFailureClassV1::ConstructionHistoryUnsupported,
        AuthorityError::UnsupportedVersion => HistoryFailureClassV1::UnsupportedVersion,
        AuthorityError::Authentication => HistoryFailureClassV1::Authentication,
        AuthorityError::Uncertain => HistoryFailureClassV1::Uncertain,
        AuthorityError::ResolutionUnavailable => HistoryFailureClassV1::ResolutionUnavailable,
        AuthorityError::SessionRequired => HistoryFailureClassV1::SessionRequired,
        AuthorityError::SessionPending => HistoryFailureClassV1::SessionPending,
    }
}

const POLL: Duration = Duration::from_millis(5);
const MAX_PAGES: usize = 4096;
const MAX_ENTRIES: usize = 65536;
const MAX_HISTORY_BYTES: usize = 32 * 1024 * 1024;

struct Prepared {
    journal: AuthorityJournal,
    tls: ServerTls,
    listener: TcpListener,
    snapshot: AccountSnapshot,
    policy: AccountPolicy,
    source_commitment: String,
    endpoint: String,
    pin: String,
    presentation: Presentation,
}
enum WorkerEvent {
    Prepared(Presentation),
    Serving,
}

/// Source-only actual role entry. The binary route remains separately gated.
pub fn run_coordinated_initial_history_v1(origin: Origin) -> ! {
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
    let mut pending_currentness = None;
    loop {
        history_io!(origin, HistoryMonitorCheck, origin.check_original_coordinator_alive())
            .map_err(|_| AuthorityError::Permission)?;
        if terminal {
            if Instant::now()
                >= history_io!(origin, HistoryCleanupDeadline, origin.original_cleanup_deadline())
                    .map_err(|_| AuthorityError::Permission)?
            {
                // A blocked worker cannot be joined honestly. The actual role
                // exits unsuccessfully; it MUST NOT send a disposal receipt.
                return Err(history_authority_error(origin, HistoryFailureStageV1::HistoryCleanupDeadline, AuthorityError::Expired));
            }
        } else if let Err(error) = origin.check_current() {
            // A later ordered stop can legitimately consume this handled error.
            // Retain only a finite kind until the existing failure-send branch.
            pending_currentness = Some(error.kind());
            origin.restrict();
            stopped.store(true, Ordering::Release);
            terminal = true;
            history_io!(origin, HistoryCleanupRetain, origin.retain_cleanup_deadline(origin.session_deadline()))
                .map_err(|_| AuthorityError::Permission)?;
        }
        match history_io!(origin, HistoryRequestReceive, origin.try_receive())
            .map_err(|_| AuthorityError::Permission)?
        {
            Some(Request::PrepareOnce(setup)) => {
                if started || terminal {
                    return Err(history_authority_error(origin, HistoryFailureStageV1::HistoryRequestOrder, AuthorityError::Permission));
                }
                started = true;
                let (tx, rx) = mpsc::sync_channel(1);
                *serve_tx = Some(tx);
                let events = event_tx.clone();
                let stop = Arc::clone(&stopped);
                *worker = Some(
                    thread::Builder::new()
                        .name("original-owner-history".into())
                        .spawn(move || worker_main(setup, rx, events, stop))
                        .map_err(|_| history_authority_error(origin, HistoryFailureStageV1::HistoryWorkerStart, AuthorityError::Storage))?,
                );
            }
            Some(Request::Serve(grant)) => {
                if terminal || !prepared {
                    return Err(history_authority_error(origin, HistoryFailureStageV1::HistoryRequestOrder, AuthorityError::Permission));
                }
                serve_tx
                    .take()
                    .ok_or_else(|| history_authority_error(origin, HistoryFailureStageV1::HistoryServeHandoff, AuthorityError::Permission))?
                    .try_send(grant)
                    .map_err(|_| history_authority_error(origin, HistoryFailureStageV1::HistoryServeHandoff, AuthorityError::Permission))?;
            }
            Some(Request::FinishRead | Request::Cancel) => {
                // Origin already latched its genuine local restriction before
                // returning this request. Stop before dropping queues/custody.
                stopped.store(true, Ordering::Release);
                terminal = true;
                ordered_terminal = true;
                pending_currentness = None;
                drop(serve_tx.take());
            }
            Some(Request::ClosePurpose) => {
                if !disposed {
                    return Err(history_authority_error(origin, HistoryFailureStageV1::HistoryRequestOrder, AuthorityError::Permission));
                }
                history_io!(origin, HistoryPurposeClosedSend, origin.send_purpose_closed())
                    .map_err(|_| AuthorityError::Permission)?;
                return Ok(());
            }
            None => {}
        }
        match event_rx.try_recv() {
            Ok(WorkerEvent::Prepared(data)) => {
                if prepared {
                    return Err(history_authority_error(origin, HistoryFailureStageV1::HistoryEventOrder, AuthorityError::Permission));
                }
                if !terminal {
                    history_io!(origin, HistoryDisplaySend, origin.send_display(data))
                        .map_err(|_| AuthorityError::Permission)?;
                    prepared = true;
                }
            }
            Ok(WorkerEvent::Serving) => {
                if !terminal {
                    history_io!(origin, HistoryServingSend, origin.acknowledge_serving())
                        .map_err(|_| AuthorityError::Permission)?;
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => return Err(history_authority_error(origin, HistoryFailureStageV1::HistoryEventOrder, AuthorityError::Permission)),
        }
        if worker.as_ref().is_some_and(JoinHandle::is_finished) {
            // Join consumes the only handle. All worker locals are already
            // dropped, including accepted socket and protected source custody.
            let result = worker
                .take()
                .ok_or_else(|| history_authority_error(origin, HistoryFailureStageV1::HistoryWorkerJoin, AuthorityError::Storage))?
                .join()
                .map_err(|_| history_authority_error(origin, HistoryFailureStageV1::HistoryWorkerJoin, AuthorityError::Storage))?;
            if result.is_err() && !terminal {
                // Only this existing failure branch may enable the worker detail.
                // Ordered FinishRead/Cancel deliberately suppress worker errors.
                origin.observe_history_failure_detail_v1(HistoryFailureStageV1::HistoryWorkerFailure,
                    history_authority_class(result.as_ref().unwrap_err()));
                origin.restrict();
                stopped.store(true, Ordering::Release);
                terminal = true;
                history_io!(origin, HistoryFailureSend, if prepared {
                    origin.send_service_failed()
                } else {
                    origin.send_preparation_failed()
                })
                .map_err(|_| AuthorityError::Permission)?;
                failure_reported = true;
            }
            if !terminal {
                return Err(history_authority_error(origin, HistoryFailureStageV1::HistoryWorkerUnexpectedReturn, AuthorityError::Permission));
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
                if let Some(kind) = pending_currentness.take() {
                    origin.observe_history_io_failure_detail_v1(HistoryFailureStageV1::HistoryMonitorCheck, kind);
                }
                history_io!(origin, HistoryFailureSend, if prepared {
                    origin.send_service_failed()
                } else {
                    origin.send_preparation_failed()
                })
                .map_err(|_| AuthorityError::Permission)?;
                failure_reported = true;
            }
            history_io!(origin, HistoryDisposedSend, origin.send_disposed())
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
        .try_send(WorkerEvent::Prepared(prepared.presentation.clone()))
        .map_err(|_| AuthorityError::Permission)?;
    let original_read = setup.original_read_deadline();
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
    serve(prepared, grant, &stopped)
}

fn prepare(setup: &Setup) -> Result<Prepared> {
    let guard = Guard::HistorySetup(setup);
    guard.check()?;
    let fields = setup.inputs();
    fields
        .validate()
        .map_err(|_| AuthorityError::InvalidBinding)?;
    let r = &setup.read_binding().read;
    let owner_der = Zeroizing::new(
        hex::decode(&fields.owner_certificate_der_hex)
            .map_err(|_| AuthorityError::InvalidBinding)?,
    );
    let owner_cert = CertificateDer::from(owner_der.as_slice());
    webpki::EndEntityCert::try_from(&owner_cert).map_err(|_| AuthorityError::Authentication)?;
    let owner = certificate_digest(&owner_cert);
    if owner != r.facts.owner_certificate_digest {
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
    // Preserve the maintained serve-born-history order: server certificate,
    // canonical existing namespace, trusted-root/private-key TLS, then listener.
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
    let input = crate::witness_locator::NamespaceOpenInput {
        #[cfg(feature = "synthetic-qualification")]
        synthetic_installation: None,
        endpoint: fields.endpoint.clone(),
        server_name: fields.server_name.clone(),
        witness_id: fields.witness_id.clone(),
        pinned_server_certificate_digest: fields.pinned_server_certificate_digest.clone(),
        owner_certificate_digest: owner.clone(),
        network_profile_id: fields.network_profile_id.clone(),
        storage_key_file: fields.storage_key_file.clone(),
        expected_account_id: fields.expected_account_id.clone(),
    };
    guard.check()?;
    let journal = crate::born_history_server::open_born_history_from_namespace_guarded(
        input,
        &pin,
        &address.to_string(),
        setup,
    )?;
    guard.check()?;
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
    guard.check()?;
    let (snapshot, policy, source_commitment) = freeze_source(&journal, setup, guard)?;
    let prepared_at_ms = wall_ms()?;
    let expires_at_ms = r.facts.expires_at_ms.min(r.facts.source_expires_at_ms);
    let display=format!("INITIAL ORIGINAL OWNER HISTORY SERVICE\nAction: disclose one Snapshot and complete original history to the exact original owner over mutual TLS.\nNo writer session, mutation, append, replacement source or automatic Continue approval.\nThe Signer's separate Read also covers exactly one local immutable Continue preparation.\nEndpoint: {}\nServer name: {}\nWitness: {}\nAccount: {}\nNetwork: {}\nOwner certificate: {}\nActual current head: {}:{}\nHistorical delivery head: {}:{}\nPolicy: {}\nSource commitment: {}\nServer certificate pin: {}\nOriginal Signer Read: {}\nPrepared at ms: {}\nOriginal expiry ms: {}\n",ascii(&fields.endpoint),ascii(&fields.server_name),ascii(&fields.witness_id),snapshot.account_id,ascii(&snapshot.network_profile_id),owner,snapshot.head.sequence,snapshot.head.digest,r.facts.original_delivery_head_sequence,r.facts.original_delivery_head_digest,snapshot.policy_digest,source_commitment,pin,r.presentation_digest,prepared_at_ms,expires_at_ms);
    let backend_review_digest = crate::digest(
        "wholepact:initial-financial-history:backend-review:v1",
        &(
            &display,
            &source_commitment,
            &snapshot,
            &r.presentation_digest,
        ),
    )?;
    let mut presentation = Presentation {
        version: 1,
        purpose: FINANCIAL_HISTORY_PURPOSE.into(),
        mode: FINANCIAL_HISTORY_MODE.into(),
        display,
        backend_review_digest,
        presentation_digest: String::new(),
        prepared_at_ms,
        expires_at_ms,
        account_id: snapshot.account_id.clone(),
        network_profile_id: snapshot.network_profile_id.clone(),
        source_commitment: source_commitment.clone(),
        policy_digest: snapshot.policy_digest.clone(),
        owner_certificate_digest: owner,
        expected_head_sequence: snapshot.head.sequence,
        expected_head_digest: snapshot.head.digest.clone(),
        read_binding: setup.read_binding().clone(),
    };
    presentation.presentation_digest = presentation
        .calculate_presentation_digest()
        .map_err(|_| AuthorityError::InvalidBinding)?;
    presentation
        .validate()
        .map_err(|_| AuthorityError::InvalidBinding)?;
    guard.check()?;
    Ok(Prepared {
        journal,
        tls,
        listener,
        snapshot,
        policy,
        source_commitment,
        endpoint: fields.endpoint.clone(),
        pin,
        presentation,
    })
}
fn ascii(value: &str) -> String {
    value.chars().flat_map(char::escape_default).collect()
}
fn wall_ms() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| AuthorityError::Expired)?
        .as_millis()
        .try_into()
        .map_err(|_| AuthorityError::Expired)
}

fn freeze_source(
    journal: &AuthorityJournal,
    setup: &Setup,
    guard: Guard<'_>,
) -> Result<(AccountSnapshot, AccountPolicy, String)> {
    let owner = journal
        .born_owner
        .as_ref()
        .ok_or(AuthorityError::Permission)?;
    guard.check()?;
    owner.check_setup_current(guard, false)?;
    guard.check()?;
    let c = journal
        .connection
        .lock()
        .map_err(|_| AuthorityError::Storage)?;
    guard.check()?;
    let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Deferred)?;
    guard.check()?;
    let f = &setup.read_binding().read.facts;
    crate::journal::authenticate_admission_guarded(
        &tx,
        &f.owner_certificate_digest,
        crate::journal::ReadGuardV1::coordinated(guard),
    )?;
    guard.check()?;
    let ledger =
        crate::journal::load_guarded(&tx, crate::journal::ReadGuardV1::coordinated(guard))?;
    guard.check()?;
    ledger.authenticate_read(
        &f.owner_certificate_digest,
        &f.account_id,
        &setup.inputs().network_profile_id,
    )?;
    if ledger.policy.owner_certificate_digest != f.owner_certificate_digest
        || ledger.snapshot.witness_id != setup.inputs().witness_id
        || ledger.snapshot.head.sequence > MAX_ENTRIES as u64
    {
        return Err(AuthorityError::InvalidBinding);
    }
    guard.check()?;
    let (stamp, birth) = crate::journal::namespace_account_stamp_guarded(
        &tx,
        &ledger.policy,
        crate::journal::ReadGuardV1::coordinated(guard),
    )?;
    guard.check()?;
    owner.require_original_account_connection(&c, &birth)?;
    guard.check()?;
    // The old delivery is a prefix, NOT the current remote head. Full maintained
    // replay above authenticates the chain; then compare its exact original row.
    let (head, payload): (String, Zeroizing<Vec<u8>>) = tx.query_row(
        "SELECT head,payload FROM authority_events WHERE sequence=?1",
        [f.original_delivery_head_sequence],
        |row| Ok((row.get(0)?, Zeroizing::new(row.get::<_, Vec<u8>>(1)?))),
    )?;
    guard.check()?;
    let event: crate::policy::Event = decode(&payload)?;
    let AuthorityMutation::OwnerControl(request) = event.mutation else {
        return Err(AuthorityError::InvalidBinding);
    };
    if head != f.original_delivery_head_digest
        || request.operation_id != f.original_delivery_operation_id
        || crate::durable_financial_continuation_v1::original_delivery_request_digest_v1(&request)?
            != f.original_delivery_request_digest
        || event.authenticated_certificate_digest != f.owner_certificate_digest
        || ledger.snapshot.head.sequence < f.original_delivery_head_sequence
    {
        return Err(AuthorityError::InvalidBinding);
    }
    let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &request.control else {
        return Err(AuthorityError::Permission);
    };
    let disclosure = WitnessDisclosureDescriptor {
        endpoint: setup.inputs().endpoint.clone(),
        server_name: setup.inputs().server_name.clone(),
        witness_id: ledger.snapshot.witness_id.clone(),
        account_id: ledger.snapshot.account_id.clone(),
        network_profile_id: ledger.snapshot.network_profile_id.clone(),
        policy_digest: ledger.snapshot.policy_digest.clone(),
        pinned_server_certificate_digest: setup.inputs().pinned_server_certificate_digest.clone(),
    };
    disclosure.validate()?;
    if record.scope.witness != disclosure
        || wholepact_core::proposal::canonical_digest(
            "wholepact:coordinated-original-financial-disclosure:v1",
            &disclosure,
        )
        .map_err(|_| AuthorityError::InvalidBinding)?
            != f.disclosure_digest
    {
        return Err(AuthorityError::InvalidBinding);
    }
    let commitment = crate::digest(
        "wholepact:initial-financial-history:source:v1",
        &(
            &stamp,
            &ledger.policy,
            &setup.inputs().endpoint,
            &setup.inputs().pinned_server_certificate_digest,
            &setup.read_binding().read.presentation_digest,
        ),
    )?;
    guard.check()?;
    Ok((ledger.snapshot, ledger.policy, commitment))
}

#[derive(Default)]
struct Progress {
    snapshot: bool,
    pages: usize,
    entries: usize,
    bytes: usize,
    after: u64,
    complete: bool,
}
impl Progress {
    fn request(&self, request: &WireRequest, prepared: &Prepared) -> Result<()> {
        request_shape(
            request,
            &prepared.snapshot.account_id,
            &prepared.snapshot.network_profile_id,
            &prepared.snapshot.head,
        )?;
        self.order(request)
    }
    fn order(&self, request: &WireRequest) -> Result<()> {
        match request {
            WireRequest::Snapshot { .. } if !self.snapshot && !self.complete => Ok(()),
            WireRequest::ReadHistory { after_sequence, .. }
                if self.snapshot
                    && !self.complete
                    && self.pages < MAX_PAGES
                    && *after_sequence == self.after =>
            {
                Ok(())
            }
            _ => Err(AuthorityError::Permission),
        }
    }
    fn response(&mut self, response: &WireResponse) -> Result<()> {
        match response {
            WireResponse::Snapshot(_) => {
                if self.snapshot {
                    return Err(AuthorityError::Permission);
                }
                self.snapshot = true;
            }
            WireResponse::History(page) => {
                self.pages = self.pages.checked_add(1).ok_or(AuthorityError::Limit)?;
                self.entries = self
                    .entries
                    .checked_add(page.entries.len())
                    .ok_or(AuthorityError::Limit)?;
                self.bytes = self
                    .bytes
                    .checked_add(
                        serde_json::to_vec(page)
                            .map_err(|_| AuthorityError::InvalidBinding)?
                            .len(),
                    )
                    .ok_or(AuthorityError::Limit)?;
                if self.pages > MAX_PAGES
                    || self.entries > MAX_ENTRIES
                    || self.bytes > MAX_HISTORY_BYTES
                {
                    return Err(AuthorityError::Limit);
                }
                if let Some(next) = page.next_after_sequence {
                    if next <= self.after {
                        return Err(AuthorityError::InvalidBinding);
                    }
                    self.after = next;
                } else {
                    self.complete = true;
                }
            }
            _ => return Err(AuthorityError::Permission),
        }
        Ok(())
    }
}
fn request_shape(
    request: &WireRequest,
    account: &str,
    network: &str,
    head: &AuthorityHead,
) -> Result<()> {
    match request {
        WireRequest::Snapshot {
            account_id,
            network_profile_id,
        } if account_id == account && network_profile_id == network => Ok(()),
        WireRequest::ReadHistory {
            account_id,
            network_profile_id,
            expected_head,
            after_sequence,
            maximum_entries,
        } if account_id == account
            && network_profile_id == network
            && expected_head == head
            && *after_sequence <= expected_head.sequence
            && (1..=16).contains(maximum_entries) =>
        {
            Ok(())
        }
        _ => Err(AuthorityError::Permission),
    }
}
fn serve(prepared: Prepared, grant: Serve, stopped: &AtomicBool) -> Result<()> {
    let admission = crate::admission::Admission::new();
    let mut progress = Progress::default();
    loop {
        if stopped.load(Ordering::Acquire) {
            return Ok(());
        }
        grant
            .check_current()
            .map_err(|_| AuthorityError::Permission)?;
        match prepared.listener.accept() {
            Ok((socket, address)) => {
                let accepted = Instant::now();
                let deadline =
                    (accepted + Duration::from_secs(10)).min(grant.effective_io_deadline());
                grant
                    .check_current()
                    .map_err(|_| AuthorityError::Permission)?;
                let _admission = admission.admit(address.ip())?;
                grant
                    .check_current()
                    .map_err(|_| AuthorityError::Permission)?;
                connection(socket, deadline, &prepared, &grant, &mut progress)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(POLL),
            Err(_) => return Err(AuthorityError::Permission),
        }
    }
}
struct HistorySocket<'a> {
    socket: TcpStream,
    deadline: Instant,
    grant: &'a Serve,
}
impl HistorySocket<'_> {
    fn before(&self) -> std::io::Result<()> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|n| !n.is_zero())
            .ok_or_else(|| std::io::Error::other("initial history deadline"))?;
        self.socket.set_read_timeout(Some(remaining))?;
        self.socket.set_write_timeout(Some(remaining))?;
        if Instant::now() >= self.deadline {
            return Err(std::io::Error::other("initial history deadline"));
        }
        // Fresh nominal restriction after timeout installation and immediately
        // before EACH physical I/O attempt, including rustls handshake traffic.
        self.grant
            .check_current()
            .map_err(|_| std::io::Error::other("initial history restricted"))
    }
    fn after(&self) -> std::io::Result<()> {
        if Instant::now() >= self.deadline {
            return Err(std::io::Error::other("initial history deadline"));
        }
        self.grant
            .check_current()
            .map_err(|_| std::io::Error::other("initial history restricted"))
    }
}
impl Read for HistorySocket<'_> {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        self.before()?;
        let n = self.socket.read(b)?;
        self.after()?;
        Ok(n)
    }
}
impl Write for HistorySocket<'_> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.before()?;
        let n = self.socket.write(b)?;
        self.after()?;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.before()?;
        self.socket.flush()?;
        self.after()
    }
}
fn connection(
    socket: TcpStream,
    deadline: Instant,
    prepared: &Prepared,
    grant: &Serve,
    progress: &mut Progress,
) -> Result<()> {
    grant
        .check_current()
        .map_err(|_| AuthorityError::Permission)?;
    let mut connection = ServerConnection::new(Arc::clone(&prepared.tls.config))
        .map_err(|_| AuthorityError::Authentication)?;
    let mut socket = HistorySocket {
        socket,
        deadline,
        grant,
    };
    while connection.is_handshaking() {
        connection
            .complete_io(&mut socket)
            .map_err(|_| AuthorityError::Authentication)?;
        grant
            .check_current()
            .map_err(|_| AuthorityError::Permission)?;
    }
    if connection.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
        || connection.alpn_protocol() != Some(ALPN)
    {
        return Err(AuthorityError::Authentication);
    }
    let peer = connection
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(certificate_digest)
        .ok_or(AuthorityError::Authentication)?;
    if peer != prepared.presentation.owner_certificate_digest {
        return Err(AuthorityError::Permission);
    }
    grant
        .check_current()
        .map_err(|_| AuthorityError::Permission)?;
    let mut stream = StreamOwned::new(connection, socket);
    let request: WireRequest = read_frame(&mut stream)?;
    grant
        .check_current()
        .map_err(|_| AuthorityError::Permission)?;
    progress.request(&request, prepared)?;
    let response = handle(prepared, grant, deadline, &peer, request)?;
    progress.response(&response)?;
    grant
        .check_current()
        .map_err(|_| AuthorityError::Permission)?;
    write_frame(&mut stream, &response)?;
    grant
        .check_current()
        .map_err(|_| AuthorityError::Permission)
}
fn handle(
    prepared: &Prepared,
    grant: &Serve,
    original_deadline: Instant,
    peer: &str,
    request: WireRequest,
) -> Result<WireResponse> {
    let guard = Guard::HistoryServe(grant);
    let read_guard = crate::journal::ReadGuardV1::coordinated_until(guard, original_deadline);
    read_guard.check()?;
    if peer != prepared.presentation.owner_certificate_digest {
        return Err(AuthorityError::Permission);
    }
    request_shape(
        &request,
        &prepared.snapshot.account_id,
        &prepared.snapshot.network_profile_id,
        &prepared.snapshot.head,
    )?;
    // Preserve maintained owner -> connection -> Deferred -> admission -> load ->
    // authenticate -> page order, with checks AFTER all blocking acquisitions.
    let owner = prepared
        .journal
        .born_owner
        .as_ref()
        .ok_or(AuthorityError::Permission)?;
    owner.check_setup_current_until(guard, false, original_deadline)?;
    read_guard.check()?;
    let c = prepared
        .journal
        .connection
        .lock()
        .map_err(|_| AuthorityError::Storage)?;
    read_guard.check()?;
    let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Deferred)?;
    read_guard.check()?;
    crate::journal::authenticate_admission_guarded(&tx, peer, read_guard)?;
    read_guard.check()?;
    let ledger = crate::journal::load_guarded(&tx, read_guard)?;
    read_guard.check()?;
    ledger.authenticate_read(
        peer,
        &prepared.snapshot.account_id,
        &prepared.snapshot.network_profile_id,
    )?;
    if ledger.policy != prepared.policy
        || ledger.policy.owner_certificate_digest != peer
        || ledger.snapshot != prepared.snapshot
    {
        return Err(AuthorityError::StaleHead);
    }
    read_guard.check()?;
    let (stamp, birth) =
        crate::journal::namespace_account_stamp_guarded(&tx, &ledger.policy, read_guard)?;
    read_guard.check()?;
    owner.require_original_account_connection(&c, &birth)?;
    read_guard.check()?;
    let commitment = crate::digest(
        "wholepact:initial-financial-history:source:v1",
        &(
            &stamp,
            &ledger.policy,
            &prepared.endpoint,
            &prepared.pin,
            &prepared.presentation.read_binding.read.presentation_digest,
        ),
    )?;
    if commitment != prepared.source_commitment {
        return Err(AuthorityError::InvalidBinding);
    }
    let response = match request {
        WireRequest::Snapshot { .. } => WireResponse::Snapshot(ledger.snapshot),
        WireRequest::ReadHistory {
            expected_head,
            after_sequence,
            maximum_entries,
            ..
        } => {
            read_guard.check()?;
            let page = crate::journal::history_page_at_guarded(
                &tx,
                ledger,
                &expected_head,
                after_sequence,
                maximum_entries,
                read_guard,
            )?;
            read_guard.check()?;
            WireResponse::History(Box::new(page))
        }
        _ => return Err(AuthorityError::Permission),
    };
    read_guard.check()?;
    encode(&response)?;
    read_guard.check()?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn head() -> AuthorityHead {
        AuthorityHead {
            sequence: 4,
            digest: "a".repeat(64),
        }
    }
    fn page(after: u64, maximum: u16) -> WireRequest {
        WireRequest::ReadHistory {
            account_id: "public-account".into(),
            network_profile_id: "public-network".into(),
            expected_head: head(),
            after_sequence: after,
            maximum_entries: maximum,
        }
    }
    #[test]
    fn initial_history_allowlist_rejects_mutation_related_and_wrong_selection() {
        let snapshot = WireRequest::Snapshot {
            account_id: "public-account".into(),
            network_profile_id: "public-network".into(),
        };
        assert!(request_shape(&snapshot, "public-account", "public-network", &head()).is_ok());
        assert!(request_shape(&snapshot, "other-account", "public-network", &head()).is_err());
        assert!(request_shape(&snapshot, "public-account", "other-network", &head()).is_err());
        let mutation_related = WireRequest::ResolveReservation {
            account_id: "public-account".into(),
            network_profile_id: "public-network".into(),
            reservation_operation_id: "public-operation".into(),
            conflict: None,
        };
        assert!(request_shape(
            &mutation_related,
            "public-account",
            "public-network",
            &head()
        )
        .is_err());
    }
    #[test]
    fn initial_history_pages_require_exact_current_head_and_small_page() {
        assert!(request_shape(&page(0, 16), "public-account", "public-network", &head()).is_ok());
        for request in [page(0, 0), page(0, 17), page(5, 1)] {
            assert!(request_shape(&request, "public-account", "public-network", &head()).is_err());
        }
        let mut stale = head();
        stale.sequence = 3;
        assert!(request_shape(&page(0, 16), "public-account", "public-network", &stale).is_err());
    }
    #[test]
    fn initial_history_progress_is_single_snapshot_and_monotone_original_cursor() {
        let snapshot = WireRequest::Snapshot {
            account_id: String::new(),
            network_profile_id: String::new(),
        };
        let mut progress = Progress::default();
        assert!(progress.order(&snapshot).is_ok());
        assert!(progress.order(&page(0, 16)).is_err());
        progress.snapshot = true;
        assert!(progress.order(&snapshot).is_err());
        assert!(progress.order(&page(0, 16)).is_ok());
        progress.after = 2;
        assert!(progress.order(&page(0, 16)).is_err());
        assert!(progress.order(&page(2, 16)).is_ok());
        progress.pages = MAX_PAGES;
        assert!(progress.order(&page(2, 16)).is_err());
        progress.pages = 0;
        progress.complete = true;
        assert!(progress.order(&page(2, 16)).is_err());
        assert!(progress.order(&snapshot).is_err());
    }
    #[test]
    fn initial_history_display_escapes_all_untrusted_formatting() {
        assert_eq!(
            ascii("public\n\r\t\\\u{202e}é"),
            "public\\n\\r\\t\\\\\\u{202e}\\u{e9}"
        );
        assert!(ascii("public path").is_ascii());
    }
}
