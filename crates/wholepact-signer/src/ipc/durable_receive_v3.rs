//! Request-only closed ingress. Kernel peer observation is not source authority;
//! the native runtime must match its actual prepared source and authorized Host.
use super::*;
use crate::authority_bridge::{durable_review_ipc_v1 as v1, durable_review_ipc_v3::*, BridgeError, Result as BridgeResult};
use serde::Serialize;

pub(crate) struct AuthenticatedDurableReceiveRequestV3 {
    stream: UnixStream,
    peer: PeerProcess,
    command: ClosedRecipientCommandV3,
}
impl AuthenticatedDurableReceiveRequestV3 {
    pub(super) fn admitted(stream: UnixStream, peer: PeerProcess, command: ClosedRecipientCommandV3) -> Result<Self> {
        command.validate().map_err(|_| Error::InvalidData)?;
        peer.check_alive()?;
        let actual = PeerProcess::observe(&stream)?;
        peer.same_live_process(&actual)?;
        Ok(Self {stream,peer,command})
    }
    pub(crate) fn command(&self) -> &ClosedRecipientCommandV3 { &self.command }
    pub(crate) fn peer(&self) -> &PeerProcess { &self.peer }
    pub(crate) fn into_parts(self) -> (UnixStream, PeerProcess, ClosedRecipientCommandV3) { (self.stream,self.peer,self.command) }
}
pub(crate) fn send_response_v3(stream: &mut UnixStream, response: &ClosedRecipientResponseV3) -> BridgeResult<()> {
    if !matches!(response,ClosedRecipientResponseV3::Staged {..} | ClosedRecipientResponseV3::Preparing {..} | ClosedRecipientResponseV3::Admitting {..} | ClosedRecipientResponseV3::Denied) { return Err(BridgeError::Permission); }
    let peer = PeerProcess::observe(stream).map_err(|_| BridgeError::Permission)?;
    v1::bounded_write(stream, response, Instant::now() + Duration::from_secs(2), || peer.check_alive().map_err(|_| BridgeError::Permission))
}
pub(crate) fn send_staged_v3(stream: &mut UnixStream, request_digest: &str) -> BridgeResult<()> {
    send_response_v3(stream, &ClosedRecipientResponseV3::Staged {request_digest:request_digest.into()})
}
pub(crate) fn send_response_checked_v3(stream: &mut UnixStream, response: &ClosedRecipientResponseV3, deadline: Instant, check: impl Fn() -> BridgeResult<()>) -> BridgeResult<()> {
    let peer = PeerProcess::observe(stream).map_err(|_| BridgeError::Permission)?;
    v1::bounded_write(stream,response,deadline,|| { check()?; peer.check_alive().map_err(|_| BridgeError::Permission) })
}
pub(crate) fn send_prepared_v3(stream: &mut UnixStream, nonce: &str, intent: &RecipientIntentV3, remaining_read_ms: u64, deadline: Instant, check: impl Fn() -> BridgeResult<()>) -> BridgeResult<()> {
    intent.validate()?;
    send_response_checked_v3(stream, &ClosedRecipientResponseV3::Prepared {nonce:nonce.into(),intent:intent.clone(),remaining_read_ms},deadline,check)
}
pub(crate) fn send_ready_v3(stream: &mut UnixStream, intent_digest: &str, nonce: &str, remaining_read_ms: u64, deadline: Instant, check: impl Fn() -> BridgeResult<()>) -> BridgeResult<()> {
    send_response_checked_v3(stream, &ClosedRecipientResponseV3::Ready {intent_digest:intent_digest.into(),nonce:nonce.into(),remaining_read_ms},deadline,check)
}
pub(crate) fn send_verification_v3(stream: &mut UnixStream, nonce: &str, receipt: Option<&VerifiedDurableReviewReceiptV3>, deadline: Instant, check: impl Fn() -> BridgeResult<()>) -> BridgeResult<()> {
    match receipt {
        Some(receipt) => send_response_checked_v3(stream, &ClosedRecipientResponseV3::Verified {nonce:nonce.into(),receipt:receipt.clone()},deadline,check),
        None => send_response_checked_v3(stream, &ClosedRecipientResponseV3::Verifying {nonce:nonce.into()},deadline,check),
    }
}
pub(crate) fn send_denied_v3(stream: &mut UnixStream) -> BridgeResult<()> { send_response_v3(stream, &ClosedRecipientResponseV3::Denied) }

/// Receives once under the actual native source's narrowing check. Returns the
/// original received allocation and a BYTES-ONLY receipt; no proof is asserted.
/// The owned stream is dropped before native independent verification begins.
pub(crate) fn receive_payload_v3(
    mut stream: UnixStream,
    peer: PeerProcess,
    intent: &RecipientIntentV3,
    deadline: Instant,
    check: impl Fn() -> BridgeResult<()>,
    observe_frame: impl Fn(&wholepact_signer_origin::framing::ObservedFrameError),
    observe_terminal: impl FnOnce(&BridgeError),
) -> BridgeResult<(Zeroizing<Vec<u8>>, DurableReviewDeliveryReceiptV3)> {
    let result = receive_payload_borrowed_v3(&mut stream,peer,intent,deadline,check,observe_frame);
    // Observe this exact result, without another currentness check, while the
    // original owned stream is still held. Diagnostics cannot replace it.
    if let Err(error)=&result {observe_terminal(error);}
    drop(stream);
    result
}
fn receive_payload_borrowed_v3(
    stream: &mut UnixStream,
    peer: PeerProcess,
    intent: &RecipientIntentV3,
    deadline: Instant,
    check: impl Fn() -> BridgeResult<()>,
    observe_frame: impl Fn(&wholepact_signer_origin::framing::ObservedFrameError),
) -> BridgeResult<(Zeroizing<Vec<u8>>, DurableReviewDeliveryReceiptV3)> {
    intent.validate()?;
    let observer = stream.try_clone().map_err(|_| BridgeError::Ipc)?;
    let current = || { check()?; super::super::authority_bridge::durable_review_ipc_v3::require_before(deadline)?; peer.check_alive().map_err(|_| BridgeError::Permission)?; let actual = PeerProcess::observe(&observer).map_err(|_| BridgeError::Permission)?; peer.same_live_process(&actual).map_err(|_| BridgeError::Permission) };
    let mut raw = Zeroizing::new(Vec::new());
    let mut begun = false;
    loop {
        current()?;
        let bytes = wholepact_signer_origin::framing::read_frame_capped_checked_observed_until(&stream, &peer, 128 * 1024, deadline, || current().map_err(|_| wholepact_signer_origin::Error::Permission)).map_err(|observed| {observe_frame(&observed);BridgeError::Ipc})?;
        let command: v1::DeliveryCommandV1 = wholepact_core::strict_json::parse_typed_json_with_byte_limit(&bytes,128 * 1024).map_err(|_| BridgeError::Binding)?;
        current()?;
        match &command {
            v1::DeliveryCommandV1::CheckCurrent => write_checked(stream,&ClosedRecipientResponseV3::Current {intent_digest:intent.digest()?},deadline,&current)?,
            v1::DeliveryCommandV1::Begin {payload_digest,payload_bytes} => {
                if begun || payload_digest != &intent.payload_digest || *payload_bytes != intent.payload_bytes { return Err(BridgeError::Binding); }
                raw.try_reserve_exact(*payload_bytes as usize).map_err(|_| BridgeError::Limit)?;
                begun = true;
                write_checked(stream,&ClosedRecipientResponseV3::Receiving {received_bytes:0},deadline,&current)?;
            }
            v1::DeliveryCommandV1::Chunk {offset,data_hex} => {
                if !begun || *offset != raw.len() as u64 || data_hex.is_empty() || data_hex.len() > v1::CHUNK_BYTES * 2 || data_hex.len() % 2 != 0 || data_hex.bytes().any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b)) { return Err(BridgeError::Binding); }
                let chunk = Zeroizing::new(hex::decode(data_hex).map_err(|_| BridgeError::Binding)?);
                if raw.len() + chunk.len() > intent.payload_bytes as usize { return Err(BridgeError::Limit); }
                raw.extend_from_slice(&chunk);
                write_checked(stream,&ClosedRecipientResponseV3::Receiving {received_bytes:raw.len() as u64},deadline,&current)?;
            }
            v1::DeliveryCommandV1::Finish => {
                if !begun || raw.len() as u64 != intent.payload_bytes || hex::encode(Sha256::digest(raw.as_slice())) != intent.payload_digest { return Err(BridgeError::Binding); }
                current()?;
                let receipt = DurableReviewDeliveryReceiptV3 {version:3,intent_digest:intent.digest()?,payload_digest:intent.payload_digest.clone(),payload_bytes:intent.payload_bytes,state:"bytes_received_unverified".into()};
                write_checked(stream,&ClosedRecipientResponseV3::BytesReceived {receipt:receipt.clone()},deadline,&current)?;
                return Ok((raw,receipt));
            }
        }
    }
}
fn write_checked<T: Serialize>(stream: &mut UnixStream, value:&T,deadline:Instant,check:&dyn Fn()->BridgeResult<()>) -> BridgeResult<()> { v1::bounded_write(stream,value,deadline,check) }
