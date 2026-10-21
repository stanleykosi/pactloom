//! Metadata-only readiness over the same authenticated TLS stream later used
//! once for unchanged V2 OwnerControl. No complete mutation is sent by prepare.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DurableAdmissionPrepareV3 {
    pub(crate) request_digest: String,
    pub(crate) operation_id: String,
    pub(crate) nonce: String,
    pub(crate) expected_head: AuthorityHead,
}
impl DurableAdmissionPrepareV3 {
    pub(crate) fn validate(&self) -> Result<()> {
        hash(&self.request_digest)?;
        id(&self.operation_id)?;
        hash(&self.nonce)?;
        hash(&self.expected_head.digest)
    }
    pub(crate) fn matches(&self, request: &OwnerControlRequest) -> Result<()> {
        self.validate()?;
        if self.request_digest != request_commitment_v3(request)? || self.operation_id != request.operation_id || self.expected_head != request.expected_head { return Err(AuthorityError::InvalidBinding); }
        Ok(())
    }
}
pub(crate) fn request_commitment_v3(request: &OwnerControlRequest) -> Result<String> {
    digest("wholepact:durable-delivery-admission-preparation:v3",request)
}
/// Only a refused connect before any connection exists permits discovery to
/// continue. Every other error permanently aborts the conditional consent.
#[derive(Debug)]
pub enum PrepareDurableAdmissionErrorV3 {
    NotListening,
    Aborted(AuthorityError),
}
impl From<AuthorityError> for PrepareDurableAdmissionErrorV3 {
    fn from(error: AuthorityError) -> Self { Self::Aborted(error) }
}
/// The only constructor completes mutual TLS and receives exact READY from the
/// already armed original Witness source. No Clone/serde/raw stream accessor.
pub struct AuthenticatedDurableAdmissionChannelV3<'a> {
    client: &'a AuthorityClient,
    stream: StreamOwned<ClientConnection, CallerDeadlineSocket>,
    request: OwnerControlRequest,
    deadline: Instant,
}
/// Finite observation sites. These do not change admission or authorize retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionFailureStageV3 {
    RetainedBinding,
    BeforeSendChannel,
    BeforeSendSource,
    BeforeWriteChannel,
    WriteFrame,
    WritePrecheck,
    WriteIo,
    WritePostcheck,
    FlushPrecheck,
    FlushIo,
    FlushPostcheck,
    AfterWriteSource,
    AfterWriteChannel,
    ReadFrame,
    ReadPrecheck,
    ReadIo,
    ReadPostcheck,
    AfterReadSource,
    AfterReadChannel,
    ResponseRejected,
    ResponseVariant,
    Snapshot,
    CommittedHead,
}
/// A bounded classification, never an OS message, peer value, or raw error.
/// `Other` deliberately remains a first cause rather than being replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionIoKindV3 {
    TimedOut,
    WouldBlock,
    Interrupted,
    UnexpectedEof,
    WriteZero,
    ConnectionAborted,
    ConnectionRefused,
    ConnectionReset,
    BrokenPipe,
    NotConnected,
    PermissionDenied,
    InvalidData,
    InvalidInput,
    Other,
}
impl From<std::io::ErrorKind> for AdmissionIoKindV3 {
    fn from(kind: std::io::ErrorKind) -> Self {
        use std::io::ErrorKind;
        match kind {
            ErrorKind::TimedOut => Self::TimedOut,
            ErrorKind::WouldBlock => Self::WouldBlock,
            ErrorKind::Interrupted => Self::Interrupted,
            ErrorKind::UnexpectedEof => Self::UnexpectedEof,
            ErrorKind::WriteZero => Self::WriteZero,
            ErrorKind::ConnectionAborted => Self::ConnectionAborted,
            ErrorKind::ConnectionRefused => Self::ConnectionRefused,
            ErrorKind::ConnectionReset => Self::ConnectionReset,
            ErrorKind::BrokenPipe => Self::BrokenPipe,
            ErrorKind::NotConnected => Self::NotConnected,
            ErrorKind::PermissionDenied => Self::PermissionDenied,
            ErrorKind::InvalidData => Self::InvalidData,
            ErrorKind::InvalidInput => Self::InvalidInput,
            _ => Self::Other,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionFailureCauseV3 {
    Authority(AuthorityError),
    Source(AuthorityError),
    Io(AdmissionIoKindV3),
    PredicateDenied,
}
/// Inert, operation-local diagnostic data. It conveys no request, stream,
/// credentials, private values, admission authority, or permission to retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionFailureObservationV3 {
    pub stage: AdmissionFailureStageV3,
    pub cause: AdmissionFailureCauseV3,
}
#[derive(Default)]
struct AdmissionFailureCollectorV3 {
    first: Option<AdmissionFailureObservationV3>,
}
impl AdmissionFailureCollectorV3 {
    fn finish(self, failed: bool) -> Option<AdmissionFailureObservationV3> {
        if failed { self.first } else { None }
    }
}
fn retain_admission_failure_v3(
    collector: &mut Option<&mut AdmissionFailureCollectorV3>,
    stage: AdmissionFailureStageV3,
    cause: AdmissionFailureCauseV3,
) {
    if let Some(collector) = collector.as_deref_mut() {
        if collector.first.is_none() {
            collector.first = Some(AdmissionFailureObservationV3 { stage, cause });
        }
    }
}
fn observe_admission_authority_result_v3<T>(
    result: Result<T>,
    stage: AdmissionFailureStageV3,
    collector: &mut Option<&mut AdmissionFailureCollectorV3>,
) -> Result<T> {
    if let Err(error) = &result {
        retain_admission_failure_v3(collector, stage, AdmissionFailureCauseV3::Authority(*error));
    }
    result
}
fn observe_admission_source_result_v3<T>(
    result: Result<T>,
    stage: AdmissionFailureStageV3,
    collector: &mut Option<&mut AdmissionFailureCollectorV3>,
) -> Result<T> {
    if let Err(error) = &result {
        retain_admission_failure_v3(collector, stage, AdmissionFailureCauseV3::Source(*error));
    }
    result
}
impl AuthorityClient {
    pub fn prepare_durable_delivery_admission_v3(
        &self,
        request: &OwnerControlRequest,
        caller_deadline: Instant,
        mut check_current: impl FnMut() -> Result<()>,
    ) -> std::result::Result<AuthenticatedDurableAdmissionChannelV3<'_>, PrepareDurableAdmissionErrorV3> {
        check_current()?;
        let OwnerControl::AdmitDurablePaymentWithDeliveryV2 {record} = &request.control else { return Err(AuthorityError::Permission.into()); };
        record.validate_request(request,&self.disclosure_descriptor())?;
        record.require_live(now_ms()?)?;
        if request.account_id != self.account || request.network_profile_id != self.network { return Err(AuthorityError::InvalidBinding.into()); }
        let deadline = bounded_transport_deadline_at(Instant::now(),caller_deadline)?;
        let mut current = || { require_before_caller_deadline(deadline)?; check_current()?; require_before_caller_deadline(deadline) };
        // Shared maintained TLS kernel, including exact certificate and ALPN pin.
        let mut connect_failure = None;
        let connected = self.open_authenticated_stream_checked(deadline,Some(caller_deadline),&mut current,Some(&mut connect_failure),#[cfg(feature="synthetic-qualification")] None);
        let (connection,socket,_) = match connected {
            Ok(connected) => connected,
            Err(_) if connect_failure == Some(std::io::ErrorKind::ConnectionRefused) => {
                // Revocation/expiry still wins over the otherwise retryable
                // refusal; discovery never acquires a replacement deadline.
                current()?;
                return Err(PrepareDurableAdmissionErrorV3::NotListening);
            }
            Err(error) => return Err(error.into()),
        };
        let mut nonce = [0u8;32];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(),&mut nonce).map_err(|_| AuthorityError::Authentication)?;
        let preparation = DurableAdmissionPrepareV3 {request_digest:request_commitment_v3(request)?,operation_id:request.operation_id.clone(),nonce:hex::encode(nonce),expected_head:request.expected_head.clone()};
        preparation.validate()?;
        let mut stream = StreamOwned::new(connection,socket);
        current()?;
        write_frame_checked_v3(&mut stream,&WireRequest::PrepareDurableDeliveryAdmissionV3(preparation.clone()),&mut current)?;
        current()?;
        let response: WireResponse = read_frame_checked_v3(&mut stream,&mut current)?;
        current()?;
        match response {
            WireResponse::DurableDeliveryAdmissionReadyV3(ready) if ready == preparation => {},
            WireResponse::Rejected(error) => return Err(error.into()),
            _ => return Err(AuthorityError::Authentication.into()),
        }
        Ok(AuthenticatedDurableAdmissionChannelV3 {client:self,stream,request:request.clone(),deadline})
    }
}
impl AuthenticatedDurableAdmissionChannelV3<'_> {
    pub fn request(&self) -> &OwnerControlRequest { &self.request }
    pub fn deadline(&self) -> Instant { self.deadline }
    pub fn check_current(&self) -> Result<()> {
        require_before_caller_deadline(self.deadline)?;
        let cert = self.stream.conn.peer_certificates().and_then(|c| c.first()).ok_or(AuthorityError::Authentication)?;
        if certificate_digest(cert) != self.client.tls.pinned_certificate || self.stream.conn.alpn_protocol() != Some(ALPN) { return Err(AuthorityError::Authentication); }
        Ok(())
    }
    /// The caller's original journal must have committed this exact retained
    /// intent before entering. The request cannot be rebased/replaced. Consuming
    /// this owner prevents a second send or reconnection after uncertainty.
    pub fn send_retained_exact(
        self,
        retained: &OwnerControlRequest,
        action_deadline: Instant,
        check_current: impl FnMut() -> Result<()>,
    ) -> Result<AccountSnapshot> {
        self.send_retained_exact_kernel(retained, action_deadline, check_current, None)
    }
    /// The same consuming send and the same result, with an optional first
    /// failure observation. In particular, post-send failures remain Uncertain.
    /// Successful operations never expose observations of recovered I/O errors.
    pub fn send_retained_exact_observed(
        self,
        retained: &OwnerControlRequest,
        action_deadline: Instant,
        check_current: impl FnMut() -> Result<()>,
    ) -> (Result<AccountSnapshot>, Option<AdmissionFailureObservationV3>) {
        let mut collector = AdmissionFailureCollectorV3::default();
        let result = self.send_retained_exact_kernel(retained, action_deadline, check_current, Some(&mut collector));
        let observation = collector.finish(result.is_err());
        (result, observation)
    }
    fn send_retained_exact_kernel(
        mut self,
        retained: &OwnerControlRequest,
        action_deadline: Instant,
        mut check_current: impl FnMut() -> Result<()>,
        mut collector: Option<&mut AdmissionFailureCollectorV3>,
    ) -> Result<AccountSnapshot> {
        use AdmissionFailureStageV3 as Stage;
        if retained != &self.request {
            retain_admission_failure_v3(&mut collector, Stage::RetainedBinding, AdmissionFailureCauseV3::PredicateDenied);
            return Err(AuthorityError::InvalidBinding);
        }
        self.deadline = self.deadline.min(action_deadline);
        self.stream.sock.inner.deadline = self.deadline;
        observe_admission_authority_result_v3(self.check_current(), Stage::BeforeSendChannel, &mut collector)?;
        observe_admission_source_result_v3(check_current(), Stage::BeforeSendSource, &mut collector)?;
        let request = WireRequest::Mutate {mutation:Box::new(AuthorityMutation::OwnerControl(self.request.clone())),session_proof:None};
        observe_admission_authority_result_v3(self.check_current(), Stage::BeforeWriteChannel, &mut collector)?;
        // All failures from this first complete admission byte onward are unknown.
        write_frame_checked_observed_v3(&mut self.stream,&request,&mut check_current,collector.as_deref_mut()).map_err(|_| AuthorityError::Uncertain)?;
        observe_admission_source_result_v3(check_current(), Stage::AfterWriteSource, &mut collector).map_err(|_| AuthorityError::Uncertain)?;
        observe_admission_authority_result_v3(self.check_current(), Stage::AfterWriteChannel, &mut collector).map_err(|_| AuthorityError::Uncertain)?;
        let response: WireResponse = read_frame_checked_observed_v3(&mut self.stream,&mut check_current,collector.as_deref_mut()).map_err(|_| AuthorityError::Uncertain)?;
        observe_admission_source_result_v3(check_current(), Stage::AfterReadSource, &mut collector).map_err(|_| AuthorityError::Uncertain)?;
        observe_admission_authority_result_v3(self.check_current(), Stage::AfterReadChannel, &mut collector).map_err(|_| AuthorityError::Uncertain)?;
        let snapshot = match response {
            WireResponse::Mutation(MutationResult::Controlled(snapshot)) => snapshot,
            WireResponse::Rejected(error) => {
                retain_admission_failure_v3(&mut collector, Stage::ResponseRejected, AdmissionFailureCauseV3::Authority(error));
                return Err(AuthorityError::Uncertain);
            }
            _ => {
                retain_admission_failure_v3(&mut collector, Stage::ResponseVariant, AdmissionFailureCauseV3::PredicateDenied);
                return Err(AuthorityError::Uncertain);
            }
        };
        observe_admission_authority_result_v3(self.client.check_snapshot(&snapshot), Stage::Snapshot, &mut collector).map_err(|_| AuthorityError::Uncertain)?;
        observe_admission_authority_result_v3(self.client.check_committed_head(&self.request.expected_head,&snapshot.head,AuthorityMutation::OwnerControl(self.request.clone()),snapshot.last_witness_time_ms,None), Stage::CommittedHead, &mut collector).map_err(|_| AuthorityError::Uncertain)?;
        // Controlled remains intermediate. Caller releases this owner and audits
        // complete authenticated history, never resubmits to learn the result.
        Ok(snapshot)
    }
}
impl AuthorityServer {
    pub(super) fn serve_durable_delivery_admission_v3(
        &self,
        mut stream: StreamOwned<ServerConnection,DeadlineSocket>,
        peer: &str,
        preparation: DurableAdmissionPrepareV3,
    ) -> Result<()> {
        self.require_durable_delivery_preparation_v3(peer,&preparation)?;
        let mut current = || self.check_durable_delivery_wait_v2();
        write_frame_checked_v3(&mut stream,&WireResponse::DurableDeliveryAdmissionReadyV3(preparation.clone()),&mut current)?;
        self.check_durable_delivery_wait_v2()?;
        // SAME stream and SAME native source. No human/native prompt occurs here.
        let request: WireRequest = read_frame_checked_v3(&mut stream,&mut current)?;
        self.require_durable_delivery_preparation_v3(peer,&preparation)?;
        match &request {
            WireRequest::Mutate {mutation,session_proof:None} => match mutation.as_ref() {
                AuthorityMutation::OwnerControl(request) => preparation.matches(request)?,
                _ => return Err(AuthorityError::Permission),
            },
            _ => return Err(AuthorityError::Permission),
        }
        let response = self.serve_durable_delivery_admission_v2(peer,request).unwrap_or_else(WireResponse::Rejected);
        self.check_durable_delivery_output_v2(&response)?;
        write_frame_checked_v3(&mut stream,&response,&mut || self.check_durable_delivery_output_v2(&response))?;
        stream.conn.send_close_notify();
        stream.flush().map_err(|_| AuthorityError::Uncertain)
    }
    fn require_durable_delivery_preparation_v3(&self,peer:&str,preparation:&DurableAdmissionPrepareV3)->Result<()> {
        #[cfg(all(feature="native-witness-owner",target_os="linux"))]
        {
            let source = self.durable_delivery_admission_v2.as_ref().ok_or(AuthorityError::Permission)?.try_lock().map_err(|_| AuthorityError::Permission)?;
            source.require_preparation_v3(peer,preparation)
        }
        #[cfg(not(all(feature="native-witness-owner",target_os="linux")))]
        { let _=(peer,preparation); Err(AuthorityError::Permission) }
    }
}

// Restriction-only adapter around the SAME TLS stream and its unchanged
// absolute socket deadline. Each partial framing operation rechecks the actual
// retained source; no retry, replacement stream or new deadline is introduced.
struct CurrentTransportV3<'a, T, C> {
    io: &'a mut T,
    check: &'a mut C,
    collector: Option<&'a mut AdmissionFailureCollectorV3>,
}
impl<T, C: FnMut() -> Result<()>> CurrentTransportV3<'_, T, C> {
    fn current(&mut self, stage: AdmissionFailureStageV3, retain_failure: bool) -> std::io::Result<()> {
        let result = (self.check)();
        let result = if retain_failure {
            observe_admission_source_result_v3(result, stage, &mut self.collector)
        } else {
            result
        };
        result
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::PermissionDenied,"closed source no longer current"))
    }
    fn observe_io_error<U>(&mut self, result: &std::io::Result<U>, stage: AdmissionFailureStageV3) {
        if let Err(error) = result {
            retain_admission_failure_v3(&mut self.collector, stage, AdmissionFailureCauseV3::Io(error.kind().into()));
        }
    }
    fn observe_zero(&mut self, stage: AdmissionFailureStageV3, kind: AdmissionIoKindV3) {
        retain_admission_failure_v3(&mut self.collector, stage, AdmissionFailureCauseV3::Io(kind));
    }
}
impl<T: Read, C: FnMut() -> Result<()>> Read for CurrentTransportV3<'_, T, C> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.current(AdmissionFailureStageV3::ReadPrecheck, true)?;
        let result = self.io.read(bytes);
        // read_exact retries Interrupted and discards its postcheck result.
        // Still execute that check, but retain neither transient observation.
        let interrupted = matches!(&result, Err(error) if error.kind() == std::io::ErrorKind::Interrupted);
        if !interrupted {
            self.observe_io_error(&result, AdmissionFailureStageV3::ReadIo);
        }
        let after = self.current(AdmissionFailureStageV3::ReadPostcheck, !interrupted);
        match result {
            Err(error) => Err(error),
            Ok(value) => {
                // read_exact will turn this into EOF only if the same
                // postcheck succeeded. Empty reads are never EOF evidence.
                if value == 0 && !bytes.is_empty() && after.is_ok() {
                    self.observe_zero(AdmissionFailureStageV3::ReadIo, AdmissionIoKindV3::UnexpectedEof);
                }
                after.map(|_| value)
            }
        }
    }
}
impl<T: Write, C: FnMut() -> Result<()>> Write for CurrentTransportV3<'_, T, C> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.current(AdmissionFailureStageV3::WritePrecheck, true)?;
        let result = self.io.write(bytes);
        // write_all has the same existing Interrupted retry semantics.
        let interrupted = matches!(&result, Err(error) if error.kind() == std::io::ErrorKind::Interrupted);
        if !interrupted {
            self.observe_io_error(&result, AdmissionFailureStageV3::WriteIo);
        }
        let after = self.current(AdmissionFailureStageV3::WritePostcheck, !interrupted);
        match result {
            Err(error) => Err(error),
            Ok(value) => {
                // write_all, not the adapter, still produces WriteZero.
                if value == 0 && !bytes.is_empty() && after.is_ok() {
                    self.observe_zero(AdmissionFailureStageV3::WriteIo, AdmissionIoKindV3::WriteZero);
                }
                after.map(|_| value)
            }
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.current(AdmissionFailureStageV3::FlushPrecheck, true)?;
        let result = self.io.flush();
        // Unlike read_exact/write_all, the maintained flush does not retry
        // Interrupted, so every flush error is an actual terminal cause.
        self.observe_io_error(&result, AdmissionFailureStageV3::FlushIo);
        let after = self.current(AdmissionFailureStageV3::FlushPostcheck, true);
        match result {Err(error)=>Err(error),Ok(())=>after}
    }
}
pub(super) fn write_frame_checked_v3<T: Serialize>(writer: &mut impl Write, value: &T, check: &mut impl FnMut() -> Result<()>) -> Result<()> {
    write_frame_checked_observed_v3(writer, value, check, None)
}
pub(super) fn read_frame_checked_v3<T: serde::de::DeserializeOwned>(reader: &mut impl Read, check: &mut impl FnMut() -> Result<()>) -> Result<T> {
    read_frame_checked_observed_v3(reader, check, None)
}
fn write_frame_checked_observed_v3<T: Serialize>(
    writer: &mut impl Write,
    value: &T,
    check: &mut impl FnMut() -> Result<()>,
    mut collector: Option<&mut AdmissionFailureCollectorV3>,
) -> Result<()> {
    let result = write_frame(&mut CurrentTransportV3 {io:writer,check,collector:collector.as_deref_mut()},value);
    observe_admission_authority_result_v3(result, AdmissionFailureStageV3::WriteFrame, &mut collector)
}
fn read_frame_checked_observed_v3<T: serde::de::DeserializeOwned>(
    reader: &mut impl Read,
    check: &mut impl FnMut() -> Result<()>,
    mut collector: Option<&mut AdmissionFailureCollectorV3>,
) -> Result<T> {
    let result = read_frame(&mut CurrentTransportV3 {io:reader,check,collector:collector.as_deref_mut()});
    observe_admission_authority_result_v3(result, AdmissionFailureStageV3::ReadFrame, &mut collector)
}

#[cfg(test)]
mod observation_tests {
    use super::*;
    use std::{cell::RefCell, io::{Cursor, Error, ErrorKind}, rc::Rc};

    #[derive(Clone, Copy)]
    enum FirstIo {
        Error(ErrorKind),
        Zero,
    }
    /// Only in-memory I/O. The tests below execute the production checked
    /// adapter and the maintained read_frame/write_frame implementations.
    struct MemoryIo {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
        read_first: Option<FirstIo>,
        write_first: Option<FirstIo>,
        write_next: Option<FirstIo>,
        flush_error: Option<ErrorKind>,
        events: Rc<RefCell<Vec<&'static str>>>,
    }
    impl MemoryIo {
        fn new(input: Vec<u8>) -> Self {
            Self {
                input: Cursor::new(input),
                output: Vec::new(),
                read_first: None,
                write_first: None,
                write_next: None,
                flush_error: None,
                events: Rc::new(RefCell::new(Vec::new())),
            }
        }
    }
    impl Read for MemoryIo {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            self.events.borrow_mut().push("read");
            match self.read_first.take() {
                Some(FirstIo::Error(kind)) => Err(Error::from(kind)),
                Some(FirstIo::Zero) => Ok(0),
                None => self.input.read(bytes),
            }
        }
    }
    impl Write for MemoryIo {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.events.borrow_mut().push("write");
            let first = self.write_first.take();
            self.write_first = self.write_next.take();
            match first {
                Some(FirstIo::Error(kind)) => Err(Error::from(kind)),
                Some(FirstIo::Zero) => Ok(0),
                None => self.output.write(bytes),
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.events.borrow_mut().push("flush");
            match self.flush_error.take() {
                Some(kind) => Err(Error::from(kind)),
                None => Ok(()),
            }
        }
    }
    fn check_at(
        events: Rc<RefCell<Vec<&'static str>>>,
        failure: Option<(usize, AuthorityError)>,
    ) -> impl FnMut() -> Result<()> {
        check_with_failures(events, failure.into_iter().collect())
    }
    fn check_with_failures(
        events: Rc<RefCell<Vec<&'static str>>>,
        failures: Vec<(usize, AuthorityError)>,
    ) -> impl FnMut() -> Result<()> {
        let mut calls = 0;
        move || {
            calls += 1;
            events.borrow_mut().push("check");
            match failures.iter().find(|(at, _)| *at == calls) {
                Some((_, error)) => Err(*error),
                None => Ok(()),
            }
        }
    }
    fn encoded_frame(value: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &value).expect("in-memory framing");
        bytes
    }
    fn observation(stage: AdmissionFailureStageV3, cause: AdmissionFailureCauseV3) -> Option<AdmissionFailureObservationV3> {
        Some(AdmissionFailureObservationV3 { stage, cause })
    }
    type WriteTrial = (Result<()>, Option<AdmissionFailureObservationV3>, Vec<&'static str>, Vec<u8>);
    fn write_trial(
        observed: bool,
        first: Option<FirstIo>,
        flush_error: Option<ErrorKind>,
        failure: Option<(usize, AuthorityError)>,
    ) -> WriteTrial {
        let mut io = MemoryIo::new(Vec::new());
        io.write_first = first;
        io.flush_error = flush_error;
        let mut check = check_at(io.events.clone(), failure);
        let mut collector = AdmissionFailureCollectorV3::default();
        let result = if observed {
            write_frame_checked_observed_v3(&mut io, &"retained", &mut check, Some(&mut collector))
        } else {
            write_frame_checked_v3(&mut io, &"retained", &mut check)
        };
        let observation = collector.finish(result.is_err());
        let events = io.events.borrow().clone();
        (result, observation, events, io.output)
    }
    type ReadTrial = (Result<String>, Option<AdmissionFailureObservationV3>, Vec<&'static str>, u64);
    fn read_trial(
        observed: bool,
        input: Vec<u8>,
        first: Option<FirstIo>,
        failure: Option<(usize, AuthorityError)>,
    ) -> ReadTrial {
        let mut io = MemoryIo::new(input);
        io.read_first = first;
        let mut check = check_at(io.events.clone(), failure);
        let mut collector = AdmissionFailureCollectorV3::default();
        let result = if observed {
            read_frame_checked_observed_v3(&mut io, &mut check, Some(&mut collector))
        } else {
            read_frame_checked_v3(&mut io, &mut check)
        };
        let observation = collector.finish(result.is_err());
        let events = io.events.borrow().clone();
        (result, observation, events, io.input.position())
    }
    fn assert_same_write(
        first: Option<FirstIo>,
        flush_error: Option<ErrorKind>,
        failure: Option<(usize, AuthorityError)>,
    ) -> WriteTrial {
        let plain = write_trial(false, first, flush_error, failure);
        let observed = write_trial(true, first, flush_error, failure);
        assert_eq!(plain.0, observed.0);
        assert_eq!(plain.1, None);
        assert_eq!(plain.2, observed.2, "observation must not change check/I/O order");
        assert_eq!(plain.3, observed.3, "observation must not change wire bytes");
        observed
    }
    fn assert_same_read(
        input: Vec<u8>,
        first: Option<FirstIo>,
        failure: Option<(usize, AuthorityError)>,
    ) -> ReadTrial {
        let plain = read_trial(false, input.clone(), first, failure);
        let observed = read_trial(true, input, first, failure);
        assert_eq!(plain.0, observed.0);
        assert_eq!(plain.1, None);
        assert_eq!(plain.2, observed.2, "observation must not change check/I/O order");
        assert_eq!(plain.3, observed.3, "observation must not consume different bytes");
        observed
    }

    #[test]
    fn framed_io_error_wins_over_still_executed_failed_postcheck_including_other() {
        for (kind, expected) in [
            (ErrorKind::TimedOut, AdmissionIoKindV3::TimedOut),
            (ErrorKind::ConnectionReset, AdmissionIoKindV3::ConnectionReset),
            (ErrorKind::Other, AdmissionIoKindV3::Other),
        ] {
            let written = assert_same_write(Some(FirstIo::Error(kind)), None, Some((2, AuthorityError::Expired)));
            assert_eq!(written.0, Err(AuthorityError::Uncertain));
            assert_eq!(written.1, observation(AdmissionFailureStageV3::WriteIo, AdmissionFailureCauseV3::Io(expected)));
            assert_eq!(written.2, ["check", "write", "check"]);
            assert!(written.3.is_empty());

            let read = assert_same_read(encoded_frame("retained"), Some(FirstIo::Error(kind)), Some((2, AuthorityError::Inactive)));
            assert_eq!(read.0, Err(AuthorityError::Uncertain));
            assert_eq!(read.1, observation(AdmissionFailureStageV3::ReadIo, AdmissionFailureCauseV3::Io(expected)));
            assert_eq!(read.2, ["check", "read", "check"]);
            assert_eq!(read.3, 0);
        }
    }

    #[test]
    fn framed_flush_error_wins_over_still_executed_failed_postcheck() {
        for (kind, expected) in [
            (ErrorKind::BrokenPipe, AdmissionIoKindV3::BrokenPipe),
            (ErrorKind::Interrupted, AdmissionIoKindV3::Interrupted),
        ] {
            let written = assert_same_write(None, Some(kind), Some((6, AuthorityError::PolicyDenied)));
            assert_eq!(written.0, Err(AuthorityError::Uncertain));
            assert_eq!(written.1, observation(AdmissionFailureStageV3::FlushIo, AdmissionFailureCauseV3::Io(expected)));
            assert_eq!(written.2, ["check", "write", "check", "check", "write", "check", "check", "flush", "check"]);
            assert_eq!(written.3, encoded_frame("retained"));
        }
    }

    #[test]
    fn framed_zero_with_failed_postcheck_keeps_source_not_eof_or_writezero() {
        let written = assert_same_write(Some(FirstIo::Zero), None, Some((2, AuthorityError::Expired)));
        assert_eq!(written.0, Err(AuthorityError::Uncertain));
        assert_eq!(written.1, observation(AdmissionFailureStageV3::WritePostcheck, AdmissionFailureCauseV3::Source(AuthorityError::Expired)));
        assert_eq!(written.2, ["check", "write", "check"]);

        let read = assert_same_read(encoded_frame("retained"), Some(FirstIo::Zero), Some((2, AuthorityError::PolicyDenied)));
        assert_eq!(read.0, Err(AuthorityError::Uncertain));
        assert_eq!(read.1, observation(AdmissionFailureStageV3::ReadPostcheck, AdmissionFailureCauseV3::Source(AuthorityError::PolicyDenied)));
        assert_eq!(read.2, ["check", "read", "check"]);
    }

    #[test]
    fn framed_nonempty_zero_observes_eventual_eof_and_writezero() {
        let written = assert_same_write(Some(FirstIo::Zero), None, None);
        assert_eq!(written.0, Err(AuthorityError::Uncertain));
        assert_eq!(written.1, observation(AdmissionFailureStageV3::WriteIo, AdmissionFailureCauseV3::Io(AdmissionIoKindV3::WriteZero)));
        assert_eq!(written.2, ["check", "write", "check"]);

        let read = assert_same_read(Vec::new(), None, None);
        assert_eq!(read.0, Err(AuthorityError::Uncertain));
        assert_eq!(read.1, observation(AdmissionFailureStageV3::ReadIo, AdmissionFailureCauseV3::Io(AdmissionIoKindV3::UnexpectedEof)));
        assert_eq!(read.2, ["check", "read", "check"]);
    }

    #[test]
    fn framed_prechecks_keep_actual_source_and_do_not_attempt_io() {
        let written = assert_same_write(None, None, Some((1, AuthorityError::Inactive)));
        assert_eq!(written.0, Err(AuthorityError::Uncertain));
        assert_eq!(written.1, observation(AdmissionFailureStageV3::WritePrecheck, AdmissionFailureCauseV3::Source(AuthorityError::Inactive)));
        assert_eq!(written.2, ["check"]);

        let read = assert_same_read(encoded_frame("retained"), None, Some((1, AuthorityError::RecoveryRequired)));
        assert_eq!(read.0, Err(AuthorityError::Uncertain));
        assert_eq!(read.1, observation(AdmissionFailureStageV3::ReadPrecheck, AdmissionFailureCauseV3::Source(AuthorityError::RecoveryRequired)));
        assert_eq!(read.2, ["check"]);
    }

    #[test]
    fn framed_successful_io_keeps_failed_postcheck_source() {
        let written = assert_same_write(None, None, Some((2, AuthorityError::Expired)));
        assert_eq!(written.0, Err(AuthorityError::Uncertain));
        assert_eq!(written.1, observation(AdmissionFailureStageV3::WritePostcheck, AdmissionFailureCauseV3::Source(AuthorityError::Expired)));
        assert_eq!(written.3.len(), 4, "the original prefix write still happened");

        let read = assert_same_read(encoded_frame("retained"), None, Some((2, AuthorityError::Inactive)));
        assert_eq!(read.0, Err(AuthorityError::Uncertain));
        assert_eq!(read.1, observation(AdmissionFailureStageV3::ReadPostcheck, AdmissionFailureCauseV3::Source(AuthorityError::Inactive)));
        assert_eq!(read.3, 4, "the original prefix read still happened");

        let flushed = assert_same_write(None, None, Some((6, AuthorityError::PolicyDenied)));
        assert_eq!(flushed.0, Err(AuthorityError::Uncertain));
        assert_eq!(flushed.1, observation(AdmissionFailureStageV3::FlushPostcheck, AdmissionFailureCauseV3::Source(AuthorityError::PolicyDenied)));
        assert_eq!(flushed.3, encoded_frame("retained"));
    }

    #[test]
    fn framed_interrupted_io_preserves_maintained_retry_and_terminal_cause() {
        // Only std's existing read_exact/write_all Interrupted handling retries.
        // The observer adds no I/O, check, deadline, or application retry.
        let written = assert_same_write(Some(FirstIo::Error(ErrorKind::Interrupted)), None, Some((3, AuthorityError::Expired)));
        assert_eq!(written.0, Err(AuthorityError::Uncertain));
        assert_eq!(written.1, observation(AdmissionFailureStageV3::WritePrecheck, AdmissionFailureCauseV3::Source(AuthorityError::Expired)));
        assert_eq!(written.2, ["check", "write", "check", "check"]);
        let read = assert_same_read(encoded_frame("retained"), Some(FirstIo::Error(ErrorKind::Interrupted)), Some((3, AuthorityError::Inactive)));
        assert_eq!(read.0, Err(AuthorityError::Uncertain));
        assert_eq!(read.1, observation(AdmissionFailureStageV3::ReadPrecheck, AdmissionFailureCauseV3::Source(AuthorityError::Inactive)));
        assert_eq!(read.2, ["check", "read", "check", "check"]);

        let ended_read = assert_same_read(Vec::new(), Some(FirstIo::Error(ErrorKind::Interrupted)), None);
        assert_eq!(ended_read.0, Err(AuthorityError::Uncertain));
        assert_eq!(ended_read.1, observation(AdmissionFailureStageV3::ReadIo, AdmissionFailureCauseV3::Io(AdmissionIoKindV3::UnexpectedEof)));
        assert_eq!(ended_read.2, ["check", "read", "check", "check", "read", "check"]);

        let mut io = MemoryIo::new(Vec::new());
        io.write_first = Some(FirstIo::Error(ErrorKind::Interrupted));
        io.write_next = Some(FirstIo::Zero);
        let mut check = check_at(io.events.clone(), None);
        let mut collector = AdmissionFailureCollectorV3::default();
        let zero_result = write_frame_checked_observed_v3(&mut io, &"retained", &mut check, Some(&mut collector));
        assert_eq!(zero_result, Err(AuthorityError::Uncertain));
        assert_eq!(collector.finish(zero_result.is_err()), observation(AdmissionFailureStageV3::WriteIo, AdmissionFailureCauseV3::Io(AdmissionIoKindV3::WriteZero)));
        assert_eq!(*io.events.borrow(), ["check", "write", "check", "check", "write", "check"]);

        let recovered_write = assert_same_write(Some(FirstIo::Error(ErrorKind::Interrupted)), None, None);
        assert_eq!(recovered_write.0, Ok(()));
        assert_eq!(recovered_write.1, None);
        assert_eq!(recovered_write.3, encoded_frame("retained"));
        let recovered_read = assert_same_read(encoded_frame("retained"), Some(FirstIo::Error(ErrorKind::Interrupted)), None);
        assert_eq!(recovered_read.0, Ok("retained".to_string()));
        assert_eq!(recovered_read.1, None);
    }

    #[test]
    fn framed_interrupted_io_discards_failed_postcheck_before_terminal_retry_failure() {
        fn trial(reading: bool, observed: bool, terminal_source: bool) -> (Result<()>, Option<AdmissionFailureObservationV3>, Vec<&'static str>) {
            let mut io = MemoryIo::new(Vec::new());
            if reading {
                io.read_first = Some(FirstIo::Error(ErrorKind::Interrupted));
            } else {
                io.write_first = Some(FirstIo::Error(ErrorKind::Interrupted));
                io.write_next = Some(FirstIo::Zero);
            }
            let mut failures = vec![(2, AuthorityError::Expired)];
            if terminal_source {
                failures.push((3, AuthorityError::Inactive));
            }
            let mut check = check_with_failures(io.events.clone(), failures);
            let mut collector = AdmissionFailureCollectorV3::default();
            let result = if reading {
                let result: Result<String> = if observed {
                    read_frame_checked_observed_v3(&mut io, &mut check, Some(&mut collector))
                } else {
                    read_frame_checked_v3(&mut io, &mut check)
                };
                result.map(|_| ())
            } else if observed {
                write_frame_checked_observed_v3(&mut io, &"retained", &mut check, Some(&mut collector))
            } else {
                write_frame_checked_v3(&mut io, &"retained", &mut check)
            };
            let observation = collector.finish(result.is_err());
            let events = io.events.borrow().clone();
            (result, observation, events)
        }
        for reading in [true, false] {
            for terminal_source in [true, false] {
                let plain = trial(reading, false, terminal_source);
                let observed = trial(reading, true, terminal_source);
                assert_eq!(plain.0, Err(AuthorityError::Uncertain));
                assert_eq!(plain.0, observed.0);
                assert_eq!(plain.1, None);
                assert_eq!(plain.2, observed.2);
                let (stage, cause) = if terminal_source {
                    (
                        if reading { AdmissionFailureStageV3::ReadPrecheck } else { AdmissionFailureStageV3::WritePrecheck },
                        AdmissionFailureCauseV3::Source(AuthorityError::Inactive),
                    )
                } else {
                    (
                        if reading { AdmissionFailureStageV3::ReadIo } else { AdmissionFailureStageV3::WriteIo },
                        AdmissionFailureCauseV3::Io(if reading { AdmissionIoKindV3::UnexpectedEof } else { AdmissionIoKindV3::WriteZero }),
                    )
                };
                assert_eq!(observed.1, observation(stage, cause), "neither Interrupted nor its discarded Expired postcheck may mask the terminal retry failure");
                let operation = if reading { "read" } else { "write" };
                let expected_events = if terminal_source {
                    vec!["check", operation, "check", "check"]
                } else {
                    vec!["check", operation, "check", "check", operation, "check"]
                };
                assert_eq!(observed.2, expected_events);
            }
        }
    }

    #[test]
    fn maintained_frame_validation_and_success_results_are_unchanged() {
        let written = assert_same_write(None, None, None);
        assert_eq!(written.0, Ok(()));
        assert_eq!(written.1, None);
        assert_eq!(written.3, encoded_frame("retained"));
        let read = assert_same_read(encoded_frame("retained"), None, None);
        assert_eq!(read.0, Ok("retained".to_string()));
        assert_eq!(read.1, None);

        for bytes in [0_u32.to_be_bytes().to_vec(), ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes().to_vec()] {
            let read = assert_same_read(bytes, None, None);
            assert_eq!(read.0, Err(AuthorityError::Limit));
            assert_eq!(read.1, observation(AdmissionFailureStageV3::ReadFrame, AdmissionFailureCauseV3::Authority(AuthorityError::Limit)));
        }
        let mut malformed = 1_u32.to_be_bytes().to_vec();
        malformed.push(b'!');
        let read = assert_same_read(malformed, None, None);
        assert_eq!(read.0, Err(AuthorityError::InvalidBinding));
        assert_eq!(read.1, observation(AdmissionFailureStageV3::ReadFrame, AdmissionFailureCauseV3::Authority(AuthorityError::InvalidBinding)));
    }

    #[test]
    fn maintained_encode_failure_returns_same_error_without_io_or_source_checks() {
        struct InvalidSerialization;
        impl Serialize for InvalidSerialization {
            fn serialize<S: serde::Serializer>(&self, _: S) -> std::result::Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("synthetic serialization failure"))
            }
        }
        fn check_failure<T: Serialize>(value: &T, error: AuthorityError) {
            let mut plain = MemoryIo::new(Vec::new());
            let mut plain_check = check_at(plain.events.clone(), None);
            let plain_result = write_frame_checked_v3(&mut plain, value, &mut plain_check);
            let mut observed = MemoryIo::new(Vec::new());
            let mut observed_check = check_at(observed.events.clone(), None);
            let mut collector = AdmissionFailureCollectorV3::default();
            let observed_result = write_frame_checked_observed_v3(&mut observed, value, &mut observed_check, Some(&mut collector));
            assert_eq!(plain_result, Err(error));
            assert_eq!(plain_result, observed_result);
            assert_eq!(collector.finish(observed_result.is_err()), observation(AdmissionFailureStageV3::WriteFrame, AdmissionFailureCauseV3::Authority(error)));
            assert!(plain.events.borrow().is_empty());
            assert!(observed.events.borrow().is_empty());
            assert!(plain.output.is_empty());
            assert!(observed.output.is_empty());
        }
        check_failure(&InvalidSerialization, AuthorityError::InvalidBinding);
        check_failure(&"x".repeat(MAX_FRAME_BYTES + 1), AuthorityError::Limit);
    }

    #[test]
    fn empty_raw_reads_and_writes_do_not_create_zero_failure_observations() {
        let mut io = MemoryIo::new(Vec::new());
        let mut check = check_at(io.events.clone(), None);
        let mut collector = AdmissionFailureCollectorV3::default();
        {
            let mut transport = CurrentTransportV3 { io: &mut io, check: &mut check, collector: Some(&mut collector) };
            assert_eq!(transport.read(&mut []).unwrap(), 0);
            assert_eq!(transport.write(&[]).unwrap(), 0);
        }
        assert_eq!(collector.first, None);
        assert_eq!(*io.events.borrow(), ["check", "read", "check", "check", "write", "check"]);
    }

    #[test]
    fn raw_adapter_returns_original_io_error_even_when_postcheck_fails() {
        let mut io = MemoryIo::new(Vec::new());
        io.read_first = Some(FirstIo::Error(ErrorKind::TimedOut));
        let mut check = check_at(io.events.clone(), Some((2, AuthorityError::Expired)));
        let mut collector = AdmissionFailureCollectorV3::default();
        let error = CurrentTransportV3 { io: &mut io, check: &mut check, collector: Some(&mut collector) }
            .read(&mut [0; 4]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::TimedOut);
        assert_eq!(collector.first, observation(AdmissionFailureStageV3::ReadIo, AdmissionFailureCauseV3::Io(AdmissionIoKindV3::TimedOut)));

        let mut io = MemoryIo::new(Vec::new());
        io.write_first = Some(FirstIo::Error(ErrorKind::BrokenPipe));
        let mut check = check_at(io.events.clone(), Some((2, AuthorityError::Inactive)));
        let mut collector = AdmissionFailureCollectorV3::default();
        let error = CurrentTransportV3 { io: &mut io, check: &mut check, collector: Some(&mut collector) }
            .write(&[0; 4]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::BrokenPipe);
        assert_eq!(collector.first, observation(AdmissionFailureStageV3::WriteIo, AdmissionFailureCauseV3::Io(AdmissionIoKindV3::BrokenPipe)));

        let mut io = MemoryIo::new(Vec::new());
        io.flush_error = Some(ErrorKind::Other);
        let mut check = check_at(io.events.clone(), Some((2, AuthorityError::PolicyDenied)));
        let mut collector = AdmissionFailureCollectorV3::default();
        let error = CurrentTransportV3 { io: &mut io, check: &mut check, collector: Some(&mut collector) }
            .flush().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Other);
        assert_eq!(collector.first, observation(AdmissionFailureStageV3::FlushIo, AdmissionFailureCauseV3::Io(AdmissionIoKindV3::Other)));
    }
}
