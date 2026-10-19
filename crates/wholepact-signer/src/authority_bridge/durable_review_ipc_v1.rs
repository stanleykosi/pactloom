//! Bounded memory-only delivery to one actual installed signer on one held
//! authenticated stream. Public descriptors/payloads are inert data. Only the
//! metadata handshake below creates a recipient; it creates no spend authority.
use super::durable_construction_v1::{
    DurableConstructionHistoryRequestV1, DurableConstructionOutboxV1,
};
use super::{ipc::OriginalHistoryClient, BridgeError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    cell::Cell,
    io::Write,
    os::unix::net::UnixStream,
    sync::Mutex,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub const MAX_DURABLE_REVIEW_PAYLOAD_BYTES_V1: usize = 5 * 1024 * 1024;
pub(crate) const MAX_PAYLOAD: usize = MAX_DURABLE_REVIEW_PAYLOAD_BYTES_V1;
pub(crate) const CHUNK_BYTES: usize = 32 * 1024;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableReviewDeliveryRequestV1 {
    pub operation_id: String,
    pub enrollment_ref: String,
    pub accepted_manifest_ref: String,
    pub own_disclosure: DurableConstructionHistoryRequestV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_disclosure: Option<DurableConstructionHistoryRequestV1>,
    pub proposal_binding: String,
}
impl DurableReviewDeliveryRequestV1 {
    pub fn validate(&self) -> Result<()> {
        crate::review::validate_label(&self.operation_id).map_err(|_| BridgeError::Binding)?;
        self.own_disclosure.validate()?;
        if let Some(current) = &self.current_disclosure {
            current.validate()?;
            if current == &self.own_disclosure {
                return Err(BridgeError::Binding);
            }
        }
        for value in [
            &self.enrollment_ref,
            &self.accepted_manifest_ref,
            &self.proposal_binding,
        ] {
            super::durable_construction_v1::hash(value)?;
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        wholepact_core::proposal::canonical_digest(
            "wholepact:durable-review-delivery-request:v1",
            self,
        )
        .map_err(|_| BridgeError::Binding)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableReviewRecipientV1 {
    pub version: u16,
    pub request: DurableReviewDeliveryRequestV1,
    pub account_id: String,
    pub participant_id: String,
    pub agreement_id: String,
    pub manifest_digest: String,
    pub provider_enrollment_reference: String,
    pub signer_process_instance: String,
    pub local_grant_id: String,
    pub local_channel_digest: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableReviewOutputActionV1 {
    pub output_id: String,
    pub action_index: usize,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableReviewPayloadV1 {
    pub version: u16,
    pub unsigned_pczt_hex: String,
    pub proved_pczt_hex: String,
    pub contributions: Vec<DurableConstructionOutboxV1>,
    pub output_actions: Vec<DurableReviewOutputActionV1>,
}
impl Drop for DurableReviewPayloadV1 {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.unsigned_pczt_hex.zeroize();
        self.proved_pczt_hex.zeroize();
    }
}
impl DurableReviewPayloadV1 {
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        if self.version != 1
            || self.contributions.len() != 2
            || self.output_actions.is_empty()
            || self.output_actions.len() > 64
            || [&self.unsigned_pczt_hex, &self.proved_pczt_hex]
                .iter()
                .any(|v| {
                    v.is_empty()
                        || v.len() > 2 * 1024 * 1024
                        || v.len() % 2 != 0
                        || !v
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
        {
            return Err(BridgeError::Binding);
        }
        for contribution in &self.contributions {
            contribution.validate()?;
        }
        let raw = Zeroizing::new(serde_json::to_vec(self).map_err(|_| BridgeError::Binding)?);
        if raw.len() > MAX_PAYLOAD {
            return Err(BridgeError::Limit);
        }
        Ok(raw)
    }
    pub fn digest(&self) -> Result<String> {
        Ok(hex::encode(Sha256::digest(self.encode()?.as_slice())))
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableReviewDeliveryReceiptV1 {
    pub version: u16,
    pub recipient_request_digest: String,
    pub payload_digest: String,
    pub payload_bytes: u64,
    /// Exactly "imported_for_review". This is neither durable storage nor a
    /// native decision, signature, prior peer approval or payment status.
    pub state: String,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DeliveryCommandV1 {
    CheckCurrent,
    Begin {
        payload_digest: String,
        payload_bytes: u64,
    },
    Chunk {
        offset: u64,
        data_hex: String,
    },
    Finish,
}
impl Drop for DeliveryCommandV1 {
    fn drop(&mut self) {
        if let Self::Chunk { data_hex, .. } = self {
            use zeroize::Zeroize;
            data_hex.zeroize();
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DeliveryResponseV1 {
    Ready {
        request_digest: String,
        account_id: String,
        participant_id: String,
        agreement_id: String,
        manifest_digest: String,
        local_grant_id: String,
        local_channel_digest: String,
    },
    Current {
        request_digest: String,
    },
    Receiving {
        received_bytes: u64,
    },
    Imported {
        receipt: DurableReviewDeliveryReceiptV1,
    },
    Denied,
}
// Closed, data-only diagnostics. None of these values can construct or expose
// an authenticated recipient, stream, deadline, or authority capability.
macro_rules! current_diagnostic_labels_v2 {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum $name { $($variant),+ }
        impl $name {
            fn label(self) -> &'static str {
                match self { $(Self::$variant => stringify!($variant)),+ }
            }
        }
    };
}
current_diagnostic_labels_v2! { CurrentSiteV2 {
    RecipientMutex, RecipientDeadline, RecipientOrigin, RecipientObserverClone,
    RecipientWriteSerialize, RecipientWriteLimit, RecipientWriteDeadline,
    RecipientWriteTimeout, RecipientWriteIo, RecipientWriteEmpty, RecipientFrame,
    RecipientResponseDecode, RecipientResponseDigest, RecipientResponse,
} }
current_diagnostic_labels_v2! { CurrentOutcomeV2 {
    BridgeBinding, BridgeConflict, BridgeMissing, BridgeUncertain, BridgeLimit,
    BridgePermission, BridgeRecoveryRequired, BridgeCompleteOriginRecoveryUnavailable,
    BridgeVerification, BridgeSignerOriginUnavailable, BridgeJournal, BridgeAuthority,
    BridgeWallet, BridgeIpc,
    OriginPermanentStopUnavailable, OriginRetirementEvidenceUnavailable,
    OriginSignerOriginUnavailable, OriginPeerLifetimeUnavailable, OriginAuthentication,
    OriginBinding, OriginConflict, OriginPermission, OriginInvalidData, OriginLocked,
    OriginCrypto, OriginIpc, OriginLimit, OriginIoTimedOut, OriginIoWouldBlock,
    OriginIoUnexpectedEof, OriginIoBrokenPipe, OriginIoConnectionReset,
    OriginIoConnectionAborted, OriginIoNotConnected, OriginIoInterrupted,
    OriginIoPermissionDenied, OriginIoOther,
} }

/// Inert first-failure evidence from one actual currentness call. Private closed
/// fields and static-label getters expose neither raw errors nor recipient data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurableReviewCurrentDiagnosticV2 {
    site: CurrentSiteV2,
    outcome: CurrentOutcomeV2,
}
impl DurableReviewCurrentDiagnosticV2 {
    pub fn site_label(&self) -> &'static str {
        self.site.label()
    }
    pub fn outcome_label(&self) -> &'static str {
        self.outcome.label()
    }
}

// Private and stack-local to the observed invocation. Cell avoids locks,
// allocation, borrow failures and callbacks; the first nested cause is sticky.
#[derive(Default)]
struct CurrentCollectorV2(Cell<Option<DurableReviewCurrentDiagnosticV2>>);
impl CurrentCollectorV2 {
    fn record(&self, site: CurrentSiteV2, outcome: CurrentOutcomeV2) {
        if self.0.get().is_none() {
            self.0
                .set(Some(DurableReviewCurrentDiagnosticV2 { site, outcome }));
        }
    }
}
fn observe_current_result_v2<T, E>(
    collector: Option<&CurrentCollectorV2>,
    site: CurrentSiteV2,
    result: std::result::Result<T, E>,
    classify: fn(&E) -> CurrentOutcomeV2,
) -> std::result::Result<T, E> {
    if let (Some(collector), Err(error)) = (collector, &result) {
        collector.record(site, classify(error));
    }
    result
}
fn observe_current_denial_v2(
    collector: Option<&CurrentCollectorV2>,
    site: CurrentSiteV2,
    denied: bool,
    outcome: CurrentOutcomeV2,
) -> bool {
    if denied {
        if let Some(collector) = collector {
            collector.record(site, outcome);
        }
    }
    denied
}
fn current_bridge_outcome_v2(error: &BridgeError) -> CurrentOutcomeV2 {
    use CurrentOutcomeV2 as O;
    match error {
        BridgeError::Binding => O::BridgeBinding,
        BridgeError::Conflict => O::BridgeConflict,
        BridgeError::Missing => O::BridgeMissing,
        BridgeError::Uncertain => O::BridgeUncertain,
        BridgeError::Limit => O::BridgeLimit,
        BridgeError::Permission => O::BridgePermission,
        BridgeError::RecoveryRequired => O::BridgeRecoveryRequired,
        BridgeError::CompleteOriginRecoveryUnavailable => {
            O::BridgeCompleteOriginRecoveryUnavailable
        }
        BridgeError::Verification => O::BridgeVerification,
        BridgeError::SignerOriginUnavailable => O::BridgeSignerOriginUnavailable,
        BridgeError::Journal(_) => O::BridgeJournal,
        BridgeError::Authority(_) => O::BridgeAuthority,
        #[cfg(feature = "authority-signing")]
        BridgeError::Wallet(_) => O::BridgeWallet,
        BridgeError::Ipc => O::BridgeIpc,
    }
}
fn current_io_outcome_v2(error: &std::io::Error) -> CurrentOutcomeV2 {
    use std::io::ErrorKind as E;
    use CurrentOutcomeV2 as O;
    match error.kind() {
        E::TimedOut => O::OriginIoTimedOut,
        E::WouldBlock => O::OriginIoWouldBlock,
        E::UnexpectedEof => O::OriginIoUnexpectedEof,
        E::BrokenPipe => O::OriginIoBrokenPipe,
        E::ConnectionReset => O::OriginIoConnectionReset,
        E::ConnectionAborted => O::OriginIoConnectionAborted,
        E::NotConnected => O::OriginIoNotConnected,
        E::Interrupted => O::OriginIoInterrupted,
        E::PermissionDenied => O::OriginIoPermissionDenied,
        _ => O::OriginIoOther,
    }
}
fn current_origin_outcome_v2(error: &wholepact_signer_origin::Error) -> CurrentOutcomeV2 {
    use wholepact_signer_origin::Error as E;
    use CurrentOutcomeV2 as O;
    match error {
        E::PermanentStopUnavailable => O::OriginPermanentStopUnavailable,
        E::RetirementEvidenceUnavailable => O::OriginRetirementEvidenceUnavailable,
        E::SignerOriginUnavailable => O::OriginSignerOriginUnavailable,
        E::PeerLifetimeUnavailable => O::OriginPeerLifetimeUnavailable,
        E::Authentication => O::OriginAuthentication,
        E::Binding => O::OriginBinding,
        E::Conflict => O::OriginConflict,
        E::Permission => O::OriginPermission,
        E::InvalidData => O::OriginInvalidData,
        E::Locked => O::OriginLocked,
        E::Crypto => O::OriginCrypto,
        E::Ipc => O::OriginIpc,
        E::Limit => O::OriginLimit,
        E::Io(error) => current_io_outcome_v2(error),
    }
}

/// No Clone, Deserialize or from-descriptor constructor. The actual client,
/// installed image, original process and exact held socket remain mandatory.
pub struct PreparedDurableReviewDeliveryV1<'a> {
    client: &'a OriginalHistoryClient,
    stream: Mutex<UnixStream>,
    recipient: DurableReviewRecipientV1,
    deadline: Instant,
}
impl OriginalHistoryClient {
    pub fn prepare_durable_review_delivery_v1<'a>(
        &'a self,
        request: &DurableReviewDeliveryRequestV1,
    ) -> Result<PreparedDurableReviewDeliveryV1<'a>> {
        request.validate()?;
        let deadline = Instant::now() + Duration::from_secs(120);
        let stream = self.open_preconstruction_request(serde_json::json!({
            "operation":"request_durable_proposal_review_v1", "request":request
        }))?;
        let raw = wholepact_signer_origin::framing::read_frame_capped_checked_until(
            &stream,
            self.peer(),
            128 * 1024,
            deadline,
            || {
                self.check_durable_review_origin_v1(&stream)
                    .map_err(|_| wholepact_signer_origin::Error::Permission)
            },
        )
        .map_err(|_| BridgeError::Ipc)?;
        let response: DeliveryResponseV1 =
            serde_json::from_slice(&raw).map_err(|_| BridgeError::Binding)?;
        let DeliveryResponseV1::Ready {
            request_digest,
            account_id,
            participant_id,
            agreement_id,
            manifest_digest,
            local_grant_id,
            local_channel_digest,
        } = response
        else {
            return Err(BridgeError::Permission);
        };
        if request_digest != request.digest()? {
            return Err(BridgeError::Binding);
        }
        let actual = self.proved_disclosure_recipient()?;
        let recipient = DurableReviewRecipientV1 {
            version: 1,
            request: request.clone(),
            account_id,
            participant_id,
            agreement_id,
            manifest_digest,
            provider_enrollment_reference: actual.provider_enrollment_reference,
            signer_process_instance: actual.process_instance,
            local_grant_id,
            local_channel_digest,
        };
        self.check_durable_review_stream_v1(&stream, &recipient)?;
        let prepared = PreparedDurableReviewDeliveryV1 {
            client: self,
            stream: Mutex::new(stream),
            recipient,
            deadline,
        };
        prepared.check_current()?;
        Ok(prepared)
    }
}
impl PreparedDurableReviewDeliveryV1<'_> {
    pub fn descriptor(&self) -> &DurableReviewRecipientV1 {
        &self.recipient
    }
    pub fn recipient(&self) -> &DurableReviewRecipientV1 {
        &self.recipient
    }
    fn check_stream(&self, stream: &UnixStream) -> Result<()> {
        self.check_stream_kernel_v2(stream, None)
    }
    fn check_stream_kernel_v2(
        &self,
        stream: &UnixStream,
        collector: Option<&CurrentCollectorV2>,
    ) -> Result<()> {
        check_stream_expressions_v2(
            || Instant::now() >= self.deadline,
            || {
                self.client
                    .check_durable_review_stream_v1(stream, &self.recipient)
            },
            collector,
        )
    }
    pub fn check_current(&self) -> Result<()> {
        self.check_current_kernel_v2(None)
    }
    /// Runs the same currentness kernel once, returning its original owned
    /// result and optional closed evidence. No observer callback is accepted.
    pub fn check_current_observed_v2(
        &self,
    ) -> (Result<()>, Option<DurableReviewCurrentDiagnosticV2>) {
        let collector = CurrentCollectorV2::default();
        let result = self.check_current_kernel_v2(Some(&collector));
        let diagnostic = if result.is_err() {
            collector.0.get()
        } else {
            None
        };
        (result, diagnostic)
    }
    fn check_current_kernel_v2(&self, collector: Option<&CurrentCollectorV2>) -> Result<()> {
        let mut stream = observe_current_result_v2(
            collector,
            CurrentSiteV2::RecipientMutex,
            self.stream.lock(),
            |_| CurrentOutcomeV2::BridgeIpc,
        )
        .map_err(|_| BridgeError::Ipc)?;
        self.check_stream_kernel_v2(&stream, collector)?;
        let observer = observe_current_result_v2(
            collector,
            CurrentSiteV2::RecipientObserverClone,
            stream.try_clone(),
            current_io_outcome_v2,
        )
        .map_err(|_| BridgeError::Ipc)?;
        bounded_write_kernel_v2(
            &mut stream,
            &DeliveryCommandV1::CheckCurrent,
            self.deadline,
            || self.check_stream_kernel_v2(&observer, collector),
            collector,
        )?;
        let frame = observe_current_result_v2(
            collector,
            CurrentSiteV2::RecipientFrame,
            wholepact_signer_origin::framing::read_frame_capped_checked_until(
                &stream,
                self.client.peer(),
                128 * 1024,
                self.deadline,
                || {
                    self.check_stream_kernel_v2(&observer, collector)
                        .map_err(|_| wholepact_signer_origin::Error::Permission)
                },
            ),
            current_origin_outcome_v2,
        )
        .map_err(|_| BridgeError::Ipc)?;
        self.check_stream_kernel_v2(&stream, collector)?;
        check_current_response_v2(&frame, || self.recipient.request.digest(), collector)
    }
    /// Consumes this one stream/attempt. The trusted engine must have committed
    /// exact payload digest+length+recipient+source-set intent before calling.
    /// Partial failures remain disclosed-or-unknown, never permission rollback.
    pub fn deliver(
        self,
        payload: &DurableReviewPayloadV1,
        check: &dyn Fn() -> Result<()>,
    ) -> Result<DurableReviewDeliveryReceiptV1> {
        let raw = payload.encode()?;
        let digest = hex::encode(Sha256::digest(raw.as_slice()));
        check()?;
        self.check_current()?;
        let mut stream = self.stream.lock().map_err(|_| BridgeError::Ipc)?;
        let observer = stream.try_clone().map_err(|_| BridgeError::Ipc)?;
        let current = || {
            check()?;
            self.check_stream(&observer)
        };
        bounded_write(
            &mut stream,
            &DeliveryCommandV1::Begin {
                payload_digest: digest.clone(),
                payload_bytes: raw.len() as u64,
            },
            self.deadline,
            &current,
        )?;
        expect_received(&stream, self.client, 0, self.deadline, &current)?;
        for (index, bytes) in raw.chunks(CHUNK_BYTES).enumerate() {
            let offset = index * CHUNK_BYTES;
            bounded_write(
                &mut stream,
                &DeliveryCommandV1::Chunk {
                    offset: offset as u64,
                    data_hex: hex::encode(bytes),
                },
                self.deadline,
                &current,
            )?;
            current()?;
            expect_received(
                &stream,
                self.client,
                (offset + bytes.len()) as u64,
                self.deadline,
                &current,
            )?;
        }
        bounded_write(
            &mut stream,
            &DeliveryCommandV1::Finish,
            self.deadline,
            &current,
        )?;
        let frame = wholepact_signer_origin::framing::read_frame_capped_checked_until(
            &stream,
            self.client.peer(),
            128 * 1024,
            self.deadline,
            || current().map_err(|_| wholepact_signer_origin::Error::Permission),
        )
        .map_err(|_| BridgeError::Ipc)?;
        current()?;
        let DeliveryResponseV1::Imported { receipt } =
            serde_json::from_slice(&frame).map_err(|_| BridgeError::Binding)?
        else {
            return Err(BridgeError::Permission);
        };
        if receipt.version != 1
            || receipt.recipient_request_digest != self.recipient.request.digest()?
            || receipt.payload_digest != digest
            || receipt.payload_bytes != raw.len() as u64
            || receipt.state != "imported_for_review"
        {
            return Err(BridgeError::Binding);
        }
        Ok(receipt)
    }
}
// Deferred expressions make the actual short-circuit kernel testable without
// constructing a recipient or opening a socket. Only private callers can supply
// these expressions; production supplies the original checks above exactly once.
fn check_stream_expressions_v2(
    deadline_expired: impl FnOnce() -> bool,
    origin: impl FnOnce() -> Result<()>,
    collector: Option<&CurrentCollectorV2>,
) -> Result<()> {
    if observe_current_denial_v2(
        collector,
        CurrentSiteV2::RecipientDeadline,
        deadline_expired(),
        CurrentOutcomeV2::BridgePermission,
    ) {
        return Err(BridgeError::Permission);
    }
    observe_current_result_v2(
        collector,
        CurrentSiteV2::RecipientOrigin,
        origin(),
        current_bridge_outcome_v2,
    )
}
fn check_current_response_v2(
    frame: &[u8],
    digest: impl FnOnce() -> Result<String>,
    collector: Option<&CurrentCollectorV2>,
) -> Result<()> {
    match observe_current_result_v2(
        collector,
        CurrentSiteV2::RecipientResponseDecode,
        serde_json::from_slice(frame),
        |_| CurrentOutcomeV2::BridgeBinding,
    )
    .map_err(|_| BridgeError::Binding)?
    {
        DeliveryResponseV1::Current { request_digest }
            if request_digest
                == observe_current_result_v2(
                    collector,
                    CurrentSiteV2::RecipientResponseDigest,
                    digest(),
                    current_bridge_outcome_v2,
                )? =>
        {
            Ok(())
        }
        _ => observe_current_result_v2(
            collector,
            CurrentSiteV2::RecipientResponse,
            Err(BridgeError::Permission),
            current_bridge_outcome_v2,
        ),
    }
}

fn expect_received(
    stream: &UnixStream,
    client: &OriginalHistoryClient,
    length: u64,
    deadline: Instant,
    check: &dyn Fn() -> Result<()>,
) -> Result<()> {
    let frame = wholepact_signer_origin::framing::read_frame_capped_checked_until(
        stream,
        client.peer(),
        128 * 1024,
        deadline,
        || check().map_err(|_| wholepact_signer_origin::Error::Permission),
    )
    .map_err(|_| BridgeError::Ipc)?;
    check()?;
    match serde_json::from_slice(&frame).map_err(|_| BridgeError::Binding)? {
        DeliveryResponseV1::Receiving { received_bytes } if received_bytes == length => Ok(()),
        _ => Err(BridgeError::Permission),
    }
}
pub(crate) fn bounded_write<T: Serialize>(
    stream: &mut UnixStream,
    value: &T,
    deadline: Instant,
    check: impl Fn() -> Result<()>,
) -> Result<()> {
    bounded_write_kernel_v2(stream, value, deadline, check, None)
}
fn bounded_write_kernel_v2<T: Serialize>(
    stream: &mut UnixStream,
    value: &T,
    deadline: Instant,
    check: impl Fn() -> Result<()>,
    collector: Option<&CurrentCollectorV2>,
) -> Result<()> {
    bounded_write_expressions_v2(
        stream,
        value,
        || {
            deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or(BridgeError::Permission)
        },
        check,
        collector,
    )
}
// Private IO adapter for the shared write loop. The actual implementation only
// delegates to the same UnixStream timeout operation; no new IO is introduced.
trait CurrentWriterV2: Write {
    fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()>;
}
impl CurrentWriterV2 for UnixStream {
    fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        UnixStream::set_write_timeout(self, timeout)
    }
}
fn bounded_write_expressions_v2<T: Serialize>(
    stream: &mut impl CurrentWriterV2,
    value: &T,
    remaining: impl Fn() -> Result<Duration>,
    check: impl Fn() -> Result<()>,
    collector: Option<&CurrentCollectorV2>,
) -> Result<()> {
    let mut raw = Zeroizing::new(
        observe_current_result_v2(
            collector,
            CurrentSiteV2::RecipientWriteSerialize,
            serde_json::to_vec(value),
            |_| CurrentOutcomeV2::BridgeBinding,
        )
        .map_err(|_| BridgeError::Binding)?,
    );
    if observe_current_denial_v2(
        collector,
        CurrentSiteV2::RecipientWriteLimit,
        raw.len() >= 128 * 1024,
        CurrentOutcomeV2::BridgeLimit,
    ) {
        return Err(BridgeError::Limit);
    }
    raw.push(b'\n');
    let mut offset = 0;
    while offset < raw.len() {
        check()?;
        let remaining = observe_current_result_v2(
            collector,
            CurrentSiteV2::RecipientWriteDeadline,
            remaining(),
            current_bridge_outcome_v2,
        )?;
        observe_current_result_v2(
            collector,
            CurrentSiteV2::RecipientWriteTimeout,
            stream.set_write_timeout(Some(remaining.min(Duration::from_secs(2)))),
            current_io_outcome_v2,
        )
        .map_err(|_| BridgeError::Ipc)?;
        let written = observe_current_result_v2(
            collector,
            CurrentSiteV2::RecipientWriteIo,
            stream.write(&raw[offset..]),
            current_io_outcome_v2,
        )
        .map_err(|_| BridgeError::Ipc)?;
        if observe_current_denial_v2(
            collector,
            CurrentSiteV2::RecipientWriteEmpty,
            written == 0,
            CurrentOutcomeV2::BridgeIpc,
        ) {
            return Err(BridgeError::Ipc);
        }
        offset += written;
        check()?;
    }
    Ok(())
}

#[cfg(test)]
mod current_diagnostics_v2_tests {
    use super::*;
    use std::{cell::RefCell, io::ErrorKind, rc::Rc};

    // Inert expression/byte adapters only. These tests do not create an actual
    // recipient, socket, native authorization, or timing/deadline-fit evidence.
    type Trace = Rc<RefCell<Vec<&'static str>>>;
    struct FakeWriter {
        trace: Trace,
        bytes: Vec<u8>,
        max_write: usize,
        timeout_error: Option<ErrorKind>,
        write_error: Option<ErrorKind>,
        timeouts: RefCell<Vec<Option<Duration>>>,
    }
    impl FakeWriter {
        fn new(trace: Trace) -> Self {
            Self {
                trace,
                bytes: Vec::new(),
                max_write: usize::MAX,
                timeout_error: None,
                write_error: None,
                timeouts: RefCell::new(Vec::new()),
            }
        }
    }
    impl Write for FakeWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.trace.borrow_mut().push("write");
            if let Some(kind) = self.write_error {
                return Err(std::io::Error::from(kind));
            }
            let written = bytes.len().min(self.max_write);
            self.bytes.extend_from_slice(&bytes[..written]);
            Ok(written)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            panic!("the original write loop does not flush")
        }
    }
    impl CurrentWriterV2 for FakeWriter {
        fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
            self.trace.borrow_mut().push("timeout");
            self.timeouts.borrow_mut().push(timeout);
            self.timeout_error
                .map_or(Ok(()), |kind| Err(std::io::Error::from(kind)))
        }
    }
    fn labels(collector: &CurrentCollectorV2) -> Option<(&'static str, &'static str)> {
        collector
            .0
            .get()
            .map(|value| (value.site_label(), value.outcome_label()))
    }
    fn bridge_label<T>(result: &Result<T>) -> Option<CurrentOutcomeV2> {
        result.as_ref().err().map(current_bridge_outcome_v2)
    }

    #[test]
    fn owned_result_adapter_preserves_non_clone_values_errors_and_success_silence() {
        struct NonClone(Box<u8>);
        for observed in [false, true] {
            let collector = CurrentCollectorV2::default();
            let optional = observed.then_some(&collector);
            let value = NonClone(Box::new(7));
            let pointer = value.0.as_ref() as *const u8;
            let result: std::result::Result<NonClone, NonClone> = observe_current_result_v2(
                optional,
                CurrentSiteV2::RecipientMutex,
                Ok(value),
                |_| panic!("success must never classify"),
            );
            let value = match result {
                Ok(value) => value,
                Err(_) => panic!("changed result"),
            };
            assert_eq!(value.0.as_ref() as *const u8, pointer);
            assert!(labels(&collector).is_none());
            let error = NonClone(Box::new(9));
            let pointer = error.0.as_ref() as *const u8;
            let result: std::result::Result<NonClone, NonClone> = observe_current_result_v2(
                optional,
                CurrentSiteV2::RecipientMutex,
                Err(error),
                |_| CurrentOutcomeV2::BridgeIpc,
            );
            let error = match result {
                Err(error) => error,
                Ok(_) => panic!("changed result"),
            };
            assert_eq!(error.0.as_ref() as *const u8, pointer);
            assert_eq!(
                labels(&collector),
                observed.then_some(("RecipientMutex", "BridgeIpc"))
            );
        }
        let result: std::result::Result<(), ()> =
            observe_current_result_v2(None, CurrentSiteV2::RecipientMutex, Err(()), |_| {
                panic!("legacy None must not classify even failure")
            });
        assert!(result.is_err());
    }

    #[test]
    fn stream_kernel_preserves_deadline_origin_order_and_never_rechecks() {
        for observed in [false, true] {
            for (expired, origin_fails) in [(true, false), (false, true), (false, false)] {
                let collector = CurrentCollectorV2::default();
                let trace = RefCell::new(Vec::new());
                let result = check_stream_expressions_v2(
                    || {
                        trace.borrow_mut().push("deadline");
                        expired
                    },
                    || {
                        trace.borrow_mut().push("origin");
                        if origin_fails {
                            Err(BridgeError::Permission)
                        } else {
                            Ok(())
                        }
                    },
                    observed.then_some(&collector),
                );
                assert_eq!(
                    trace.into_inner(),
                    if expired {
                        vec!["deadline"]
                    } else {
                        vec!["deadline", "origin"]
                    }
                );
                assert_eq!(
                    bridge_label(&result),
                    (expired || origin_fails).then_some(CurrentOutcomeV2::BridgePermission)
                );
                let expected = if expired {
                    Some(("RecipientDeadline", "BridgePermission"))
                } else if origin_fails {
                    Some(("RecipientOrigin", "BridgePermission"))
                } else {
                    None
                };
                assert_eq!(labels(&collector), if observed { expected } else { None });
            }
        }
    }

    #[test]
    fn write_kernel_legacy_and_observed_keep_identical_bytes_and_order() {
        for observed in [false, true] {
            for remaining in [Duration::from_millis(7), Duration::from_secs(9)] {
                let collector = CurrentCollectorV2::default();
                let trace = Trace::default();
                let mut writer = FakeWriter::new(trace.clone());
                writer.max_write = 5;
                let result = bounded_write_expressions_v2(
                    &mut writer,
                    &DeliveryCommandV1::CheckCurrent,
                    || {
                        trace.borrow_mut().push("remaining");
                        Ok(remaining)
                    },
                    || {
                        trace.borrow_mut().push("check");
                        Ok(())
                    },
                    observed.then_some(&collector),
                );
                assert!(result.is_ok());
                let mut expected = serde_json::to_vec(&DeliveryCommandV1::CheckCurrent).unwrap();
                expected.push(b'\n');
                assert_eq!(writer.bytes, expected);
                let rounds = expected.len().div_ceil(5);
                let expected_trace =
                    ["check", "remaining", "timeout", "write", "check"].repeat(rounds);
                assert_eq!(*trace.borrow(), expected_trace);
                assert_eq!(
                    *writer.timeouts.borrow(),
                    vec![Some(remaining.min(Duration::from_secs(2))); rounds]
                );
                assert!(labels(&collector).is_none());
            }
        }
    }

    #[test]
    fn write_kernel_pre_io_serialization_and_limit_failures_are_exact() {
        struct InvalidSerialization;
        impl Serialize for InvalidSerialization {
            fn serialize<S: serde::Serializer>(
                &self,
                _: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("inert serialization failure"))
            }
        }
        for observed in [false, true] {
            let collector = CurrentCollectorV2::default();
            let trace = Trace::default();
            let mut writer = FakeWriter::new(trace.clone());
            let result = bounded_write_expressions_v2(
                &mut writer,
                &InvalidSerialization,
                || panic!("remaining must be short-circuited"),
                || panic!("check must be short-circuited"),
                observed.then_some(&collector),
            );
            assert_eq!(bridge_label(&result), Some(CurrentOutcomeV2::BridgeBinding));
            assert_eq!(
                labels(&collector),
                observed.then_some(("RecipientWriteSerialize", "BridgeBinding"))
            );
            assert!(trace.borrow().is_empty());

            let collector = CurrentCollectorV2::default();
            // JSON string quotes make this exactly the original rejected cap.
            let value = "x".repeat(128 * 1024 - 2);
            let result = bounded_write_expressions_v2(
                &mut writer,
                &value,
                || panic!("remaining must be short-circuited"),
                || panic!("check must be short-circuited"),
                observed.then_some(&collector),
            );
            assert_eq!(bridge_label(&result), Some(CurrentOutcomeV2::BridgeLimit));
            assert_eq!(
                labels(&collector),
                observed.then_some(("RecipientWriteLimit", "BridgeLimit"))
            );
            assert!(trace.borrow().is_empty());
            assert!(writer.bytes.is_empty());
        }
    }

    #[test]
    fn write_kernel_failure_sites_keep_original_result_and_short_circuit() {
        for observed in [false, true] {
            for (failure, site, outcome, expected_trace) in [
                (
                    "deadline",
                    "RecipientWriteDeadline",
                    "BridgePermission",
                    vec!["check", "remaining"],
                ),
                (
                    "timeout",
                    "RecipientWriteTimeout",
                    "OriginIoPermissionDenied",
                    vec!["check", "remaining", "timeout"],
                ),
                (
                    "io",
                    "RecipientWriteIo",
                    "OriginIoTimedOut",
                    vec!["check", "remaining", "timeout", "write"],
                ),
                (
                    "empty",
                    "RecipientWriteEmpty",
                    "BridgeIpc",
                    vec!["check", "remaining", "timeout", "write"],
                ),
            ] {
                let collector = CurrentCollectorV2::default();
                let trace = Trace::default();
                let mut writer = FakeWriter::new(trace.clone());
                if failure == "timeout" {
                    writer.timeout_error = Some(ErrorKind::PermissionDenied);
                }
                if failure == "io" {
                    writer.write_error = Some(ErrorKind::TimedOut);
                }
                if failure == "empty" {
                    writer.max_write = 0;
                }
                let result = bounded_write_expressions_v2(
                    &mut writer,
                    &DeliveryCommandV1::CheckCurrent,
                    || {
                        trace.borrow_mut().push("remaining");
                        if failure == "deadline" {
                            Err(BridgeError::Permission)
                        } else {
                            Ok(Duration::from_secs(1))
                        }
                    },
                    || {
                        trace.borrow_mut().push("check");
                        Ok(())
                    },
                    observed.then_some(&collector),
                );
                let terminal = if failure == "deadline" {
                    CurrentOutcomeV2::BridgePermission
                } else {
                    CurrentOutcomeV2::BridgeIpc
                };
                assert_eq!(bridge_label(&result), Some(terminal));
                assert_eq!(labels(&collector), observed.then_some((site, outcome)));
                assert_eq!(*trace.borrow(), expected_trace);
                assert!(writer.bytes.is_empty());
            }
        }
    }

    #[test]
    fn write_kernel_nested_checks_keep_first_cause_before_and_after_io() {
        for observed in [false, true] {
            for fail_at in [1, 2] {
                let collector = CurrentCollectorV2::default();
                let trace = Trace::default();
                let mut writer = FakeWriter::new(trace.clone());
                let calls = Cell::new(0);
                let result = bounded_write_expressions_v2(
                    &mut writer,
                    &DeliveryCommandV1::CheckCurrent,
                    || {
                        trace.borrow_mut().push("remaining");
                        Ok(Duration::from_secs(1))
                    },
                    || {
                        trace.borrow_mut().push("check");
                        calls.set(calls.get() + 1);
                        check_stream_expressions_v2(
                            || false,
                            || {
                                if calls.get() == fail_at {
                                    Err(BridgeError::Conflict)
                                } else {
                                    Ok(())
                                }
                            },
                            observed.then_some(&collector),
                        )
                    },
                    observed.then_some(&collector),
                );
                assert_eq!(
                    bridge_label(&result),
                    Some(CurrentOutcomeV2::BridgeConflict)
                );
                assert_eq!(calls.get(), fail_at);
                assert_eq!(
                    labels(&collector),
                    observed.then_some(("RecipientOrigin", "BridgeConflict"))
                );
                assert_eq!(
                    *trace.borrow(),
                    if fail_at == 1 {
                        vec!["check"]
                    } else {
                        vec!["check", "remaining", "timeout", "write", "check"]
                    }
                );
                assert_eq!(writer.bytes.is_empty(), fail_at == 1);
            }
        }
    }

    #[test]
    fn framed_origin_authentication_is_not_a_deadline_and_nested_cause_wins() {
        for observed in [false, true] {
            let collector = CurrentCollectorV2::default();
            let framed: Result<()> = observe_current_result_v2(
                observed.then_some(&collector),
                CurrentSiteV2::RecipientFrame,
                Err(wholepact_signer_origin::Error::Authentication),
                current_origin_outcome_v2,
            )
            .map_err(|_| BridgeError::Ipc);
            assert_eq!(bridge_label(&framed), Some(CurrentOutcomeV2::BridgeIpc));
            assert_eq!(
                labels(&collector),
                observed.then_some(("RecipientFrame", "OriginAuthentication"))
            );

            let collector = CurrentCollectorV2::default();
            let lower = check_stream_expressions_v2(
                || false,
                || Err(BridgeError::Binding),
                observed.then_some(&collector),
            )
            .map_err(|_| wholepact_signer_origin::Error::Permission);
            let framed = observe_current_result_v2(
                observed.then_some(&collector),
                CurrentSiteV2::RecipientFrame,
                lower,
                current_origin_outcome_v2,
            )
            .map_err(|_| BridgeError::Ipc);
            assert_eq!(bridge_label(&framed), Some(CurrentOutcomeV2::BridgeIpc));
            assert_eq!(
                labels(&collector),
                observed.then_some(("RecipientOrigin", "BridgeBinding"))
            );
        }
    }

    #[test]
    fn response_kernel_preserves_decode_guard_digest_and_shape_order() {
        for observed in [false, true] {
            for (frame, digest_error, expected_site, expected_error, digest_calls) in [
                (
                    &b"not-json"[..],
                    false,
                    Some("RecipientResponseDecode"),
                    Some(CurrentOutcomeV2::BridgeBinding),
                    0,
                ),
                (
                    &br#"{"status":"denied"}"#[..],
                    false,
                    Some("RecipientResponse"),
                    Some(CurrentOutcomeV2::BridgePermission),
                    0,
                ),
                (
                    &br#"{"status":"current","request_digest":"same","extra":0}"#[..],
                    false,
                    Some("RecipientResponseDecode"),
                    Some(CurrentOutcomeV2::BridgeBinding),
                    0,
                ),
                (
                    &br#"{"status":"current","request_digest":"same"}"#[..],
                    true,
                    Some("RecipientResponseDigest"),
                    Some(CurrentOutcomeV2::BridgeBinding),
                    1,
                ),
                (
                    &br#"{"status":"current","request_digest":"different"}"#[..],
                    false,
                    Some("RecipientResponse"),
                    Some(CurrentOutcomeV2::BridgePermission),
                    1,
                ),
                (
                    &br#"{"status":"current","request_digest":"same"}"#[..],
                    false,
                    None,
                    None,
                    1,
                ),
            ] {
                let collector = CurrentCollectorV2::default();
                let calls = Cell::new(0);
                let result = check_current_response_v2(
                    frame,
                    || {
                        calls.set(calls.get() + 1);
                        if digest_error {
                            Err(BridgeError::Binding)
                        } else {
                            Ok("same".to_owned())
                        }
                    },
                    observed.then_some(&collector),
                );
                assert_eq!(calls.get(), digest_calls);
                assert_eq!(bridge_label(&result), expected_error);
                let expected = expected_site
                    .zip(expected_error)
                    .map(|(site, error)| (site, error.label()));
                assert_eq!(labels(&collector), if observed { expected } else { None });
            }
        }
    }

    #[test]
    fn io_classification_is_finite_and_preserves_owned_error() {
        for (kind, expected) in [
            (ErrorKind::TimedOut, "OriginIoTimedOut"),
            (ErrorKind::WouldBlock, "OriginIoWouldBlock"),
            (ErrorKind::UnexpectedEof, "OriginIoUnexpectedEof"),
            (ErrorKind::BrokenPipe, "OriginIoBrokenPipe"),
            (ErrorKind::ConnectionReset, "OriginIoConnectionReset"),
            (ErrorKind::ConnectionAborted, "OriginIoConnectionAborted"),
            (ErrorKind::NotConnected, "OriginIoNotConnected"),
            (ErrorKind::Interrupted, "OriginIoInterrupted"),
            (ErrorKind::PermissionDenied, "OriginIoPermissionDenied"),
            (ErrorKind::ConnectionRefused, "OriginIoOther"),
        ] {
            for site in [
                CurrentSiteV2::RecipientObserverClone,
                CurrentSiteV2::RecipientWriteTimeout,
                CurrentSiteV2::RecipientWriteIo,
            ] {
                let collector = CurrentCollectorV2::default();
                let error = std::io::Error::new(kind, "private error is never copied to evidence");
                let pointer = error.get_ref().unwrap() as *const _ as *const ();
                let result: std::io::Result<()> = observe_current_result_v2(
                    Some(&collector),
                    site,
                    Err(error),
                    current_io_outcome_v2,
                );
                let error = result.unwrap_err();
                assert_eq!(error.get_ref().unwrap() as *const _ as *const (), pointer);
                assert_eq!(error.kind(), kind);
                assert_eq!(labels(&collector), Some((site.label(), expected)));
            }
        }
    }

    #[test]
    fn collectors_are_invocation_local_and_first_failure_is_sticky() {
        let first = CurrentCollectorV2::default();
        let second = CurrentCollectorV2::default();
        let _: Result<()> = observe_current_result_v2(
            Some(&first),
            CurrentSiteV2::RecipientOrigin,
            Err(BridgeError::Verification),
            current_bridge_outcome_v2,
        );
        let _: Result<()> = observe_current_result_v2(
            Some(&first),
            CurrentSiteV2::RecipientMutex,
            Err(BridgeError::Ipc),
            current_bridge_outcome_v2,
        );
        assert_eq!(
            labels(&first),
            Some(("RecipientOrigin", "BridgeVerification"))
        );
        assert!(labels(&second).is_none());
        let _: Result<()> = observe_current_result_v2(
            Some(&second),
            CurrentSiteV2::RecipientResponse,
            Err(BridgeError::Permission),
            current_bridge_outcome_v2,
        );
        assert_eq!(
            labels(&second),
            Some(("RecipientResponse", "BridgePermission"))
        );
        assert_eq!(
            labels(&first),
            Some(("RecipientOrigin", "BridgeVerification"))
        );
    }
}
