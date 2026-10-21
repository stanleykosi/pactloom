//! Finite coordinated financial-continuation owner-mTLS path, no generic server or reconnect loop.
//! Reachable only from the private genuine common-image role worker.
use super::*;
use crate::native_witness_owner::coordinated_financial_continuation_v1::{
    CoordinatedFinancialContinuationSourceV1, FinancialContinuationCoordinatorBridgeV1,
    observation::Stage,
};
use durable_delivery_admission_v3::{read_frame_checked_v3, write_frame_checked_v3};
use sha2::{Digest, Sha256};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

/// Constructed only below from an ACTUAL completed server TLS connection. No
/// caller peer string/FD/bool constructor, Clone, serde or public fields.
pub(crate) struct AuthenticatedOriginalOwnerPeerV1 {
    certificate: String,
    deadline: Instant,
    stream_commitment: String,
    accepted_at_ms: u64,
    accepted_tls_expires_at_ms: u64,
    local_tls_released: Arc<AtomicBool>,
}
impl AuthenticatedOriginalOwnerPeerV1 {
    pub(crate) fn certificate_digest(&self) -> &str {
        &self.certificate
    }
    pub(crate) fn original_stream_commitment(&self) -> &str {
        &self.stream_commitment
    }
    pub(crate) fn original_deadline(&self) -> Instant {
        self.deadline
    }
    pub(crate) fn original_accept_bounds(&self) -> (u64, u64) {
        (self.accepted_at_ms, self.accepted_tls_expires_at_ms)
    }
    /// Retained authenticated local stream identity + its original deadline.
    /// This is NOT a remote-online assertion: a close while waiting on C may
    /// remain undetected until I/O. Every observed I/O failure is terminal;
    /// this mirrors the maintained V3 server rather than inventing a new oracle.
    pub(crate) fn check_original_bounds(&self) -> Result<()> {
        let now = now_ms()?;
        if Instant::now() >= self.deadline
            || now < self.accepted_at_ms
            || now >= self.accepted_tls_expires_at_ms
        {
            return Err(AuthorityError::Expired);
        }
        if self.local_tls_released.load(Ordering::Acquire) {
            return Err(AuthorityError::Authentication);
        }
        Ok(())
    }
}
/// Private per-physical-attempt restriction. No semantic source audit or
/// permission constructor runs in this I/O path. Original timeout never renews.
struct FinancialIoSocket<'a> {
    socket: TcpStream,
    deadline: Instant,
    source: &'a Mutex<CoordinatedFinancialContinuationSourceV1>,
    terminal_exact: bool,
}
impl FinancialIoSocket<'_> {
    fn remaining(&self) -> std::io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "original financial deadline")
            })
    }
    fn current(&self) -> std::io::Result<()> {
        let source = self
            .source
            .try_lock()
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::PermissionDenied))?;
        let result = if self.terminal_exact {
            source.check_terminal_io()
        } else {
            source.check_before_publication()
        };
        result.map_err(|_| std::io::Error::from(std::io::ErrorKind::PermissionDenied))?;
        self.remaining()?;
        Ok(())
    }
    fn select_exact_terminal(&mut self, response: &WireResponse) -> Result<()> {
        self.source
            .try_lock()
            .map_err(|_| AuthorityError::Permission)?
            .check_exact_terminal_response(response)?;
        self.terminal_exact = true;
        Ok(())
    }
}
impl Read for FinancialIoSocket<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.socket.set_read_timeout(Some(self.remaining()?))?;
        self.current()?;
        let result = self.socket.read(bytes);
        if result.is_ok() {
            self.current()?;
        }
        result
    }
}
impl Write for FinancialIoSocket<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.socket.set_write_timeout(Some(self.remaining()?))?;
        self.current()?;
        let result = self.socket.write(bytes);
        if result.is_ok() {
            self.current()?;
        }
        result
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.socket.set_write_timeout(Some(self.remaining()?))?;
        self.current()?;
        let result = self.socket.flush();
        if result.is_ok() {
            self.current()?;
        }
        result
    }
}

struct OriginalTlsLifetimeV1(Arc<AtomicBool>);
impl Drop for OriginalTlsLifetimeV1 {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
fn authenticated_original_peer(
    stream: &StreamOwned<ServerConnection, FinancialIoSocket<'_>>,
    accepted_at_ms: u64,
    accepted_tls_expires_at_ms: u64,
) -> Result<(AuthenticatedOriginalOwnerPeerV1, OriginalTlsLifetimeV1)> {
    if stream.conn.is_handshaking()
        || stream.conn.alpn_protocol() != Some(ALPN)
        || Instant::now() >= stream.sock.deadline
    {
        return Err(AuthorityError::Authentication);
    }
    let certificate = certificate_digest(
        stream
            .conn
            .peer_certificates()
            .and_then(|certificates| certificates.first())
            .ok_or(AuthorityError::Authentication)?,
    );
    let binding = Zeroizing::new(
        stream
            .conn
            .export_keying_material(
                [0u8; 32],
                b"wholepact:coordinated-financial-continuation-original-tls:v1",
                None,
            )
            .map_err(|_| AuthorityError::Authentication)?,
    );
    // Public correlation is a hash, never the TLS exporter/key material itself.
    let stream_commitment = hex::encode(Sha256::digest(&binding[..]));
    let local_tls_released = Arc::new(AtomicBool::new(false));
    Ok((
        AuthenticatedOriginalOwnerPeerV1 {
            certificate,
            deadline: stream.sock.deadline,
            stream_commitment,
            accepted_at_ms,
            accepted_tls_expires_at_ms,
            local_tls_released: local_tls_released.clone(),
        },
        OriginalTlsLifetimeV1(local_tls_released),
    ))
}

/// Actual private positive role worker only. The listener comes from the SAME
/// reviewed preparation and is consumed after its first accepted connection.
/// Invalid peer/handshake/metadata/request consumes the attempt, never retries.
pub(crate) fn serve_coordinated_financial_continuation_once_v1(
    listener: TcpListener,
    tls: ServerTls,
    source: &Mutex<CoordinatedFinancialContinuationSourceV1>,
    bridge: FinancialContinuationCoordinatorBridgeV1,
) -> Result<()> {
    let mut observed_stage = Stage::TlsAccept;
    let result = (|| {
        let endpoint = listener
            .local_addr()
            .map_err(|_| AuthorityError::Storage)?
            .to_string();
        {
            let source = source.try_lock().map_err(|_| AuthorityError::Permission)?;
            source.check_before_publication()?;
            source.require_endpoint(&tls.certificate_digest, &endpoint)?;
        }
        let (socket, accepted_deadline, accepted_at_ms, accepted_tls_expires_at_ms) = loop {
            source
                .try_lock()
                .map_err(|_| AuthorityError::Permission)?
                .check_before_publication()?;
            match listener.accept() {
                Ok((socket, _)) => {
                    let accepted = Instant::now();
                    let wall = now_ms()?;
                    let until = wall
                        .checked_add(
                            u64::try_from(IO_TIMEOUT.as_millis())
                                .map_err(|_| AuthorityError::Limit)?,
                        )
                        .ok_or(AuthorityError::Limit)?;
                    break (socket, accepted + IO_TIMEOUT, wall, until);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return Err(AuthorityError::Authentication),
            }
        };
        drop(listener);
        socket
            .set_nonblocking(false)
            .map_err(|_| AuthorityError::Authentication)?;
        if socket
            .local_addr()
            .map_err(|_| AuthorityError::Authentication)?
            .to_string()
            != endpoint
        {
            return Err(AuthorityError::Authentication);
        }
        // This is the ONLY call deadline. Never refresh it after TLS, READY,
        // source preflight, C admission, lock reacquisition or local publication.
        let effective = source
            .try_lock()
            .map_err(|_| AuthorityError::Permission)?
            .physical_io_deadline(accepted_deadline);
        let mut socket = FinancialIoSocket {
            socket,
            deadline: effective,
            source,
            terminal_exact: false,
        };
        observed_stage = Stage::TlsHandshake;
        let mut connection = ServerConnection::new(tls.config.clone())
            .map_err(|_| AuthorityError::Authentication)?;
        while connection.is_handshaking() {
            source
                .try_lock()
                .map_err(|_| AuthorityError::Permission)?
                .check_before_publication()?;
            connection
                .complete_io(&mut socket)
                .map_err(|_| AuthorityError::Authentication)?;
            source
                .try_lock()
                .map_err(|_| AuthorityError::Permission)?
                .check_before_publication()?;
        }
        let mut stream = StreamOwned::new(connection, socket);
        observed_stage = Stage::TlsPeerIdentity;
        let (peer, _retained_tls_lifetime) =
            authenticated_original_peer(&stream, accepted_at_ms, accepted_tls_expires_at_ms)?;
        let mut current = || {
            source
                .try_lock()
                .map_err(|_| AuthorityError::Permission)?
                .check_before_publication()
        };
        observed_stage = Stage::TlsRequest;
        let request: WireRequest = read_frame_checked_v3(&mut stream, &mut current)?;
        let WireRequest::Mutate {
            mutation,
            session_proof: None,
        } = request
        else {
            return Err(AuthorityError::Permission);
        };
        let AuthorityMutation::OwnerControl(request) = *mutation else {
            return Err(AuthorityError::Permission);
        };
        let response = dispatch_exact(source, peer, request, &bridge)
            .map(WireResponse::Mutation)
            .unwrap_or_else(WireResponse::Rejected);
        observed_stage = Stage::TlsResponse;
        let mut terminal = || {
            source
                .try_lock()
                .map_err(|_| AuthorityError::Permission)?
                .check_exact_terminal_response(&response)
        };
        terminal()?;
        stream.sock.select_exact_terminal(&response)?;
        write_frame_checked_v3(&mut stream, &response, &mut terminal)?;
        stream.conn.send_close_notify();
        stream.flush().map_err(|_| AuthorityError::Uncertain)
    })();
    if let Err(error) = result.as_ref() {
        if let Ok(mut source) = source.try_lock() {
            source.observe_failure(observed_stage, *error);
            source.record_no_effect(*error);
        }
    }
    result
}

fn dispatch_exact(
    source: &Mutex<CoordinatedFinancialContinuationSourceV1>,
    peer: AuthenticatedOriginalOwnerPeerV1,
    request: OwnerControlRequest,
    bridge: &FinancialContinuationCoordinatorBridgeV1,
) -> Result<MutationResult> {
    let mut observed_stage = Stage::FirstPreflight;
    let result = (|| {
        // FIRST lexical source guard. The journal leaf explicitly rolls back
        // and drops every nested journal/registry guard before returning ticket.
        let (journal, ticket) = {
            let mut source = source.try_lock().map_err(|_| AuthorityError::Permission)?;
            let journal = source.journal();
            let ticket = journal.prepare_coordinated_financial_continuation_v1(
                &mut source,
                peer,
                request,
            )?;
            (journal, ticket)
        };
        // Absolutely no source/journal/registry guard exists during this IPC.
        // The independent role control monitor remains responsive to C loss.
        observed_stage = Stage::FinalAdmitWait;
        let grant = bridge.await_final_admit(&ticket)?;
        observed_stage = Stage::SecondPreflight;
        // SECOND fresh lexical guard. The full exact preflight is repeated;
        // C's already ordered A does not mean a journal commit has occurred.
        {
            let mut source = source.try_lock().map_err(|_| AuthorityError::Permission)?;
            journal.commit_coordinated_financial_continuation_v1(&mut source, ticket, grant)
        }
    })();
    if let Err(error) = result.as_ref() {
        if let Ok(mut source) = source.try_lock() {
            source.observe_failure(observed_stage, *error);
            source.record_no_effect(*error);
        }
    }
    result
}
