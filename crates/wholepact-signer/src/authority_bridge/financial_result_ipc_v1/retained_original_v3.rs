//! Retained actual V3 peer/provider transfer. Selection paths and observers grant
//! no authority; the Host supplies separate genuine preview/intake decisions.
use super::*;

/// Denial-only original clock/revocation observation, never a read permission.
/// Implementations must be bounded, zero-wait and must not re-enter source/DB.
pub trait FinancialResultRestrictionV1: Send + Sync {
    fn check_before_io(&self) -> Result<()>;
}
pub(super) struct OriginalResultRestrictionsV1 {
    original: Box<dyn FinancialResultRestrictionV1>,
    intake: Option<Box<dyn FinancialResultRestrictionV1>>,
}
impl OriginalResultRestrictionsV1 {
    pub(super) fn check(&self) -> Result<()> {
        self.original.check_before_io()?;
        self.intake.as_ref().ok_or(BridgeError::Permission)?.check_before_io()
    }
}
impl PreparedFinancialResultReceiverV1 {
    // Only the consuming actual Pending V3 owner calls this. The candidate
    // result socket may differ from V3, but its authenticated process may not.
    pub(crate) fn prepare_retained_original_v3(
        provider: crate::authority_bridge::provider::InstalledSignerProvider,
        peer: PeerProcess,
        socket: &Path,
        request: &FinancialResultRequestV1,
        original_deadline: Instant,
        original: Box<dyn FinancialResultRestrictionV1>,
        preview_read: &dyn FinancialResultRestrictionV1,
    ) -> Result<Self> {
        request.validate()?;
        if !socket.is_absolute() { return Err(BridgeError::Binding); }
        let deadline = original_deadline.min(Instant::now() + Duration::from_secs(900));
        let restriction = || {
            if Instant::now() >= deadline { return Err(BridgeError::Permission); }
            original.check_before_io()?;
            preview_read.check_before_io()
        };
        restriction()?;
        let mut stream = wholepact_signer_origin::connect_local_checked_until(socket, deadline, || {
            restriction().map_err(|_| wholepact_signer_origin::Error::Permission)
        })?;
        crate::ipc::enable_credentials(stream.as_raw_fd()).map_err(|_| BridgeError::Ipc)?;
        let candidate = provider.verify_server(&stream)?;
        peer.same_live_process(&candidate).map_err(|_| BridgeError::Permission)?;
        drop(candidate);
        let current = || {
            peer.check_alive().map_err(|_| BridgeError::Permission)?;
            restriction()
        };
        // Both the original process match and genuine fresh preview Read are
        // checked before the first metadata byte, and again per physical I/O.
        write_restricted(
            &mut stream,
            &serde_json::json!({"command":"financial_result_v1","schema_version":1,"request":request}),
            deadline.min(Instant::now() + Duration::from_secs(120)),
            &current, Some(&restriction),
        )?;
        let Response::Preview { preview } = read_setup_restricted_observed(
            &stream, &peer, deadline, &current, None, Some(&restriction),
        )? else { return Err(BridgeError::Permission); };
        preview.validate()?;
        if preview.request != *request { return Err(BridgeError::Binding); }
        restriction()?;
        Ok(Self {
            setup_deadline: deadline, provider, peer, stream,
            preview: AuthenticatedFinancialResultPreviewV1 { data: preview },
            original_deadline,
            original_restrictions: Some(OriginalResultRestrictionsV1 { original, intake: None }),
        })
    }
    /// Consuming one-shot additional restriction from the actual later intake
    /// decision. Cannot create a common-image receiver from the legacy route or
    /// remove/replace its first observer. Missing second observer denies receive.
    pub fn bind_original_intake_restriction_v1(
        mut self, intake: Box<dyn FinancialResultRestrictionV1>,
    ) -> Result<Self> {
        let restrictions = self.original_restrictions.as_mut().ok_or(BridgeError::Permission)?;
        if restrictions.intake.is_some() { return Err(BridgeError::Permission); }
        restrictions.original.check_before_io()?;
        intake.check_before_io()?;
        restrictions.intake = Some(intake);
        Ok(self)
    }
}
pub(super) fn write_restricted<T: Serialize>(
    stream: &mut UnixStream, data: &T, deadline: Instant, check: &dyn Fn() -> Result<()>,
    restriction: Option<&dyn Fn() -> Result<()>>,
) -> Result<()> {
    match restriction {
        None => write(stream, data, deadline, check),
        Some(restriction) => crate::authority_bridge::durable_review_ipc_v1::bounded_write_restricted(
            stream, data, deadline, || check().and_then(|()| restriction()), restriction,
        ),
    }
}
pub(super) fn read_restricted_observed<T: serde::de::DeserializeOwned>(
    stream: &UnixStream, peer: &PeerProcess, deadline: Instant,
    check: &dyn Fn() -> Result<()>, observer: Option<&FinancialResultObserverV1>,
    restriction: Option<&dyn Fn() -> Result<()>>,
) -> Result<T> {
    let bytes = match restriction {
        None => wholepact_signer_origin::framing::read_frame_capped_checked_observed_until(
            stream, peer, MAX_FRAME, deadline,
            || check().map_err(|_| wholepact_signer_origin::Error::Permission),
        ),
        Some(restriction) => wholepact_signer_origin::framing::read_frame_capped_restricted_observed_until(
            stream, peer, MAX_FRAME, deadline,
            || check().and_then(|()| restriction()).map_err(|_| wholepact_signer_origin::Error::Permission),
            || restriction().map_err(|_| wholepact_signer_origin::Error::Permission),
        ),
    }.map_err(|failure| {
        if let Some(observer) = observer { observer.frame.set(Some(failure.cause)); }
        BridgeError::Ipc
    })?;
    wholepact_core::strict_json::parse_typed_json_with_byte_limit(&bytes, MAX_FRAME)
        .map_err(|_| BridgeError::Binding)
}
pub(super) fn read_setup_restricted_observed<T: serde::de::DeserializeOwned>(
    stream: &UnixStream, peer: &PeerProcess, deadline: Instant,
    check: &dyn Fn() -> Result<()>, observer: Option<&FinancialResultObserverV1>,
    restriction: Option<&dyn Fn() -> Result<()>>,
) -> Result<T> {
    let bytes = match restriction {
        None => wholepact_signer_origin::framing::read_setup_frame_capped_checked_observed_until(
            stream, peer, MAX_FRAME, deadline,
            || check().map_err(|_| wholepact_signer_origin::Error::Permission),
        ),
        Some(restriction) => wholepact_signer_origin::framing::read_setup_frame_capped_restricted_observed_until(
            stream, peer, MAX_FRAME, deadline,
            || check().and_then(|()| restriction()).map_err(|_| wholepact_signer_origin::Error::Permission),
            || restriction().map_err(|_| wholepact_signer_origin::Error::Permission),
        ),
    }.map_err(|failure| {
        if let Some(observer) = observer { observer.frame.set(Some(failure.cause)); }
        BridgeError::Ipc
    })?;
    wholepact_core::strict_json::parse_typed_json_with_byte_limit(&bytes, MAX_FRAME)
        .map_err(|_| BridgeError::Binding)
}
