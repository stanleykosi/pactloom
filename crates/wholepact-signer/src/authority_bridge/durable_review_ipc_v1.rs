//! Bounded memory-only delivery to one actual installed signer on one held
//! authenticated stream. Public descriptors/payloads are inert data. Only the
//! metadata handshake below creates a recipient; it creates no spend authority.
use super::durable_construction_v1::{
    DurableConstructionHistoryRequestV1, DurableConstructionOutboxV1,
};
use super::{BridgeError, Result, ipc::OriginalHistoryClient};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
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
        if Instant::now() >= self.deadline {
            return Err(BridgeError::Permission);
        }
        self.client
            .check_durable_review_stream_v1(stream, &self.recipient)
    }
    pub fn check_current(&self) -> Result<()> {
        let mut stream = self.stream.lock().map_err(|_| BridgeError::Ipc)?;
        self.check_stream(&stream)?;
        let observer = stream.try_clone().map_err(|_| BridgeError::Ipc)?;
        bounded_write(
            &mut stream,
            &DeliveryCommandV1::CheckCurrent,
            self.deadline,
            || self.check_stream(&observer),
        )?;
        let frame = wholepact_signer_origin::framing::read_frame_capped_checked_until(
            &stream,
            self.client.peer(),
            128 * 1024,
            self.deadline,
            || {
                self.check_stream(&observer)
                    .map_err(|_| wholepact_signer_origin::Error::Permission)
            },
        )
        .map_err(|_| BridgeError::Ipc)?;
        self.check_stream(&stream)?;
        match serde_json::from_slice(&frame).map_err(|_| BridgeError::Binding)? {
            DeliveryResponseV1::Current { request_digest }
                if request_digest == self.recipient.request.digest()? =>
            {
                Ok(())
            }
            _ => Err(BridgeError::Permission),
        }
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
    let mut raw = Zeroizing::new(serde_json::to_vec(value).map_err(|_| BridgeError::Binding)?);
    if raw.len() >= 128 * 1024 {
        return Err(BridgeError::Limit);
    }
    raw.push(b'\n');
    let mut offset = 0;
    while offset < raw.len() {
        check()?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(BridgeError::Permission)?;
        stream
            .set_write_timeout(Some(remaining.min(Duration::from_secs(2))))
            .map_err(|_| BridgeError::Ipc)?;
        let written = stream.write(&raw[offset..]).map_err(|_| BridgeError::Ipc)?;
        if written == 0 {
            return Err(BridgeError::Ipc);
        }
        offset += written;
        check()?;
    }
    Ok(())
}
