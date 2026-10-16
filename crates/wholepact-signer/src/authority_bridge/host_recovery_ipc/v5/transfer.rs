//! Pure, bounded V5 disclosure framing. These states carry inert bytes only.
//! Kernel peer identity, native ownership, snapshot checks and the single
//! absolute deadline remain obligations of the authenticated owner. No DTO or
//! completed byte transfer grants continuity or publication authority.
use super::{BridgeError, Result};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::io::{self, Write};
use zeroize::{Zeroize, Zeroizing};

pub(crate) const TRANSFER_DIALECT_V1: &str = "v5_bounded_transfer_v1";
pub(crate) const MAX_TRANSFER_EVIDENCE_BYTES: usize = 1_048_576;
/// Includes the single transport newline; legacy framing is unchanged.
pub(crate) const MAX_TRANSFER_FRAME_BYTES: usize = 131_072;
pub(crate) const RAW_CHUNK_BYTES: usize = 32_768;
pub(crate) const MAX_TRANSFER_CHUNKS: u32 = 32;
const BYTE_DOMAIN: &[u8] = b"wholepact:host-recovery-transfer-bytes:v5:bounded:v1\0";
const BEGIN_DOMAIN: &str = "wholepact:host-recovery-transfer-begin:v5:bounded:v1";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub enum V5TransferDialect {
    #[default]
    #[serde(rename = "single_frame")]
    SingleFrame,
    #[serde(rename = "v5_bounded_transfer_v1")]
    BoundedV1,
}
impl<'de> Deserialize<'de> for V5TransferDialect {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct ExactDialect;
        impl serde::de::Visitor<'_> for ExactDialect {
            type Value = V5TransferDialect;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an exact V5 transfer dialect string")
            }
            fn visit_str<E: serde::de::Error>(
                self,
                value: &str,
            ) -> std::result::Result<Self::Value, E> {
                match value {
                    "single_frame" => Ok(V5TransferDialect::SingleFrame),
                    TRANSFER_DIALECT_V1 => Ok(V5TransferDialect::BoundedV1),
                    _ => Err(E::custom("unsupported V5 transfer dialect")),
                }
            }
        }
        deserializer.deserialize_str(ExactDialect)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TransferPurpose {
    Continuity,
    Publication,
}
impl<'de> Deserialize<'de> for TransferPurpose {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct ExactPurpose;
        impl serde::de::Visitor<'_> for ExactPurpose {
            type Value = TransferPurpose;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an exact V5 transfer purpose string")
            }
            fn visit_str<E: serde::de::Error>(
                self,
                value: &str,
            ) -> std::result::Result<Self::Value, E> {
                match value {
                    "continuity" => Ok(TransferPurpose::Continuity),
                    "publication" => Ok(TransferPurpose::Publication),
                    _ => Err(E::custom("unsupported V5 transfer purpose")),
                }
            }
        }
        deserializer.deserialize_str(ExactPurpose)
    }
}

/// Inputs retained by the actual approved owner, never proof of that owner.
pub(crate) struct TransferMetadata {
    pub(crate) purpose: TransferPurpose,
    pub(crate) transfer_id: String,
    pub(crate) lease_id: String,
    pub(crate) request_digest: String,
    pub(crate) native_review_digest: String,
    pub(crate) evidence_digest: String,
    pub(crate) head_digest: String,
    pub(crate) head_sequence: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransferHeader {
    pub(crate) dialect: String,
    pub(crate) purpose: TransferPurpose,
    pub(crate) transfer_id: String,
    pub(crate) lease_id: String,
    pub(crate) request_digest: String,
    pub(crate) native_review_digest: String,
    pub(crate) evidence_digest: String,
    pub(crate) byte_digest: String,
    pub(crate) total_bytes: u64,
    pub(crate) raw_chunk_bytes: u32,
    pub(crate) chunk_count: u32,
    pub(crate) head_digest: String,
    pub(crate) head_sequence: u64,
}

impl TransferHeader {
    pub(crate) fn validate(&self) -> Result<()> {
        for value in [
            &self.transfer_id,
            &self.lease_id,
            &self.request_digest,
            &self.native_review_digest,
            &self.evidence_digest,
            &self.byte_digest,
            &self.head_digest,
        ] {
            super::hash(value)?;
        }
        if self.dialect != TRANSFER_DIALECT_V1
            || self.raw_chunk_bytes != RAW_CHUNK_BYTES as u32
            || self.head_sequence > i64::MAX as u64
            || self.chunk_count != checked_chunk_count(self.total_bytes)?
        {
            return Err(BridgeError::Binding);
        }
        Ok(())
    }

    pub(crate) fn binding(&self) -> Result<TransferBinding> {
        self.validate()?;
        Ok(TransferBinding {
            transfer_id: self.transfer_id.clone(),
            begin_digest: wholepact_core::proposal::canonical_digest(BEGIN_DOMAIN, self)
                .map_err(|_| BridgeError::Binding)?,
        })
    }

    fn expected_chunk_bytes(&self, index: u32, offset: u64) -> Result<usize> {
        if index >= self.chunk_count
            || offset
                != u64::from(index)
                    .checked_mul(RAW_CHUNK_BYTES as u64)
                    .ok_or(BridgeError::Binding)?
        {
            return Err(BridgeError::Binding);
        }
        let remaining = self
            .total_bytes
            .checked_sub(offset)
            .ok_or(BridgeError::Binding)?;
        usize::try_from(remaining.min(RAW_CHUNK_BYTES as u64)).map_err(|_| BridgeError::Limit)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransferBinding {
    pub(crate) transfer_id: String,
    pub(crate) begin_digest: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransferChunk {
    pub(crate) binding: TransferBinding,
    pub(crate) index: u32,
    pub(crate) offset: u64,
    pub(crate) data_hex: String,
}
impl Drop for TransferChunk {
    fn drop(&mut self) {
        self.data_hex.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum TransferCommandV1 {
    Next {
        binding: TransferBinding,
        index: u32,
        offset: u64,
    },
    AcceptComplete {
        binding: TransferBinding,
        byte_digest: String,
        evidence_digest: String,
    },
    Finish {},
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum TransferResponseV1 {
    Begin { header: TransferHeader },
    Chunk { chunk: TransferChunk },
    HeldComplete { binding: TransferBinding },
    PreparedComplete { binding: TransferBinding },
    Denied {},
    Finished {},
}

fn checked_chunk_count(total: u64) -> Result<u32> {
    if total == 0 || total > MAX_TRANSFER_EVIDENCE_BYTES as u64 {
        return Err(BridgeError::Limit);
    }
    let count = total
        .checked_add(RAW_CHUNK_BYTES as u64 - 1)
        .ok_or(BridgeError::Limit)?
        / RAW_CHUNK_BYTES as u64;
    let count = u32::try_from(count).map_err(|_| BridgeError::Limit)?;
    if count == 0 || count > MAX_TRANSFER_CHUNKS {
        return Err(BridgeError::Limit);
    }
    Ok(count)
}

/// Domain-separated SHA-256 using the maintained library. Fixed-width framing:
/// domain-with-NUL, dialect length (u16 BE), dialect UTF-8, purpose byte (1/2),
/// lowercase request digest's 64 ASCII bytes, total length (u64 BE), exact bytes.
/// It detects byte substitution; it does not authenticate a sender.
fn byte_digest(purpose: TransferPurpose, request_digest: &str, bytes: &[u8]) -> Result<String> {
    super::hash(request_digest)?;
    checked_chunk_count(u64::try_from(bytes.len()).map_err(|_| BridgeError::Limit)?)?;
    let mut digest = Sha256::new();
    digest.update(BYTE_DOMAIN);
    digest.update((TRANSFER_DIALECT_V1.len() as u16).to_be_bytes());
    digest.update(TRANSFER_DIALECT_V1.as_bytes());
    digest.update([match purpose {
        TransferPurpose::Continuity => 1,
        TransferPurpose::Publication => 2,
    }]);
    digest.update(request_digest.as_bytes());
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    Ok(hex::encode(digest.finalize()))
}

/// Fallible, fixed-ceiling storage: serializer writes never trigger growth.
/// Reserving once also avoids leaving earlier evidence copies in old allocations.
struct BoundedWriter {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
}
impl BoundedWriter {
    fn new(limit: usize) -> Result<Self> {
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(limit)
            .map_err(|_| BridgeError::Limit)?;
        Ok(Self { bytes, limit })
    }
}
impl Write for BoundedWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if self
            .bytes
            .len()
            .checked_add(input.len())
            .is_none_or(|n| n > self.limit)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bounded V5 payload limit",
            ));
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode_bounded<T: Serialize>(value: &T, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut writer = BoundedWriter::new(limit)?;
    serde_json::to_writer(&mut writer, value).map_err(|_| BridgeError::Limit)?;
    Ok(writer.bytes)
}

/// JSON bytes, excluding the one newline supplied by the authenticated writer.
pub(crate) fn encode_frame<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>> {
    encode_bounded(value, MAX_TRANSFER_FRAME_BYTES - 1)
}

/// Receiver must enforce the same ceiling while accumulating. This check is an
/// additional pure parser boundary, not an unbounded-read substitute.
pub(crate) fn decode_frame<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.is_empty() || bytes.len() >= MAX_TRANSFER_FRAME_BYTES {
        return Err(BridgeError::Limit);
    }
    if bytes.first() != Some(&b'{')
        || bytes.last() != Some(&b'}')
        || bytes.contains(&b'\n')
        || bytes.contains(&b'\r')
    {
        return Err(BridgeError::Binding);
    }
    serde_json::from_slice(bytes).map_err(|_| BridgeError::Binding)
}

enum SenderState {
    Fresh,
    Sending { index: u32, offset: u64 },
    AwaitComplete,
    Accepted,
    Confirmed,
    Finished,
    Failed,
}

pub(crate) struct TransferSender {
    header: TransferHeader,
    binding: TransferBinding,
    bytes: Zeroizing<Vec<u8>>,
    state: SenderState,
}
impl TransferSender {
    pub(crate) fn new<T: Serialize>(metadata: TransferMetadata, evidence: &T) -> Result<Self> {
        // Reject metadata before the bounded allocation or serializer work.
        for value in [
            &metadata.transfer_id,
            &metadata.lease_id,
            &metadata.request_digest,
            &metadata.native_review_digest,
            &metadata.evidence_digest,
            &metadata.head_digest,
        ] {
            super::hash(value)?;
        }
        if metadata.head_sequence > i64::MAX as u64 {
            return Err(BridgeError::Binding);
        }
        let bytes = encode_bounded(evidence, MAX_TRANSFER_EVIDENCE_BYTES)?;
        let header = TransferHeader {
            dialect: TRANSFER_DIALECT_V1.into(),
            purpose: metadata.purpose,
            byte_digest: byte_digest(metadata.purpose, &metadata.request_digest, &bytes)?,
            transfer_id: metadata.transfer_id,
            lease_id: metadata.lease_id,
            request_digest: metadata.request_digest,
            native_review_digest: metadata.native_review_digest,
            evidence_digest: metadata.evidence_digest,
            total_bytes: bytes.len() as u64,
            raw_chunk_bytes: RAW_CHUNK_BYTES as u32,
            chunk_count: checked_chunk_count(bytes.len() as u64)?,
            head_digest: metadata.head_digest,
            head_sequence: metadata.head_sequence,
        };
        let binding = header.binding()?;
        encode_frame(&TransferResponseV1::Begin {
            header: header.clone(),
        })?;
        Ok(Self {
            header,
            binding,
            bytes,
            state: SenderState::Fresh,
        })
    }

    #[cfg(test)]
    pub(crate) fn header(&self) -> &TransferHeader {
        &self.header
    }

    fn fail<T>(&mut self) -> Result<T> {
        self.state = SenderState::Failed;
        self.bytes.zeroize();
        Err(BridgeError::Binding)
    }

    pub(crate) fn begin(&mut self) -> Result<TransferHeader> {
        if !matches!(self.state, SenderState::Fresh) {
            return self.fail();
        }
        self.state = SenderState::Sending {
            index: 0,
            offset: 0,
        };
        Ok(self.header.clone())
    }

    pub(crate) fn next(&mut self, command: &TransferCommandV1) -> Result<TransferChunk> {
        let (index, offset) = match self.state {
            SenderState::Sending { index, offset } => (index, offset),
            _ => return self.fail(),
        };
        let TransferCommandV1::Next {
            binding,
            index: supplied_index,
            offset: supplied_offset,
        } = command
        else {
            return self.fail();
        };
        if binding != &self.binding || *supplied_index != index || *supplied_offset != offset {
            return self.fail();
        }
        let result = (|| {
            let length = self.header.expected_chunk_bytes(index, offset)?;
            let start = usize::try_from(offset).map_err(|_| BridgeError::Limit)?;
            let end = start.checked_add(length).ok_or(BridgeError::Limit)?;
            let raw = self.bytes.get(start..end).ok_or(BridgeError::Binding)?;
            let hex_len = length.checked_mul(2).ok_or(BridgeError::Limit)?;
            let mut encoded = Zeroizing::new(Vec::new());
            encoded
                .try_reserve_exact(hex_len)
                .map_err(|_| BridgeError::Limit)?;
            encoded.resize(hex_len, 0);
            hex::encode_to_slice(raw, encoded.as_mut_slice()).map_err(|_| BridgeError::Binding)?;
            // Transfer the one encoded allocation without another chunk copy.
            // The error branch also zeroizes, even though hex emits only ASCII.
            let data_hex = match String::from_utf8(std::mem::take(&mut *encoded)) {
                Ok(value) => value,
                Err(error) => {
                    error.into_bytes().zeroize();
                    return Err(BridgeError::Binding);
                }
            };
            let chunk = TransferChunk {
                binding: self.binding.clone(),
                index,
                offset,
                data_hex,
            };
            #[derive(Serialize)]
            struct ChunkFrame<'a> {
                status: &'static str,
                chunk: &'a TransferChunk,
            }
            encode_frame(&ChunkFrame {
                status: "chunk",
                chunk: &chunk,
            })?;
            Ok((chunk, end as u64))
        })();
        match result {
            Ok((chunk, end)) => {
                let next_index = index.checked_add(1).ok_or(BridgeError::Limit)?;
                self.state = if next_index == self.header.chunk_count {
                    SenderState::AwaitComplete
                } else {
                    SenderState::Sending {
                        index: next_index,
                        offset: end,
                    }
                };
                Ok(chunk)
            }
            Err(_) => self.fail(),
        }
    }

    pub(crate) fn accept_complete(&mut self, command: &TransferCommandV1) -> Result<()> {
        let TransferCommandV1::AcceptComplete {
            binding,
            byte_digest,
            evidence_digest,
        } = command
        else {
            return self.fail();
        };
        if !matches!(self.state, SenderState::AwaitComplete)
            || binding != &self.binding
            || byte_digest != &self.header.byte_digest
            || evidence_digest != &self.header.evidence_digest
        {
            return self.fail();
        }
        self.state = SenderState::Accepted;
        Ok(())
    }

    /// Call only after the retained real owner and exact snapshot are rechecked.
    /// This is a transport response, not a native approval or sealed lease.
    pub(crate) fn confirmation(&mut self) -> Result<TransferResponseV1> {
        if !matches!(self.state, SenderState::Accepted) {
            return self.fail();
        }
        let response = match self.header.purpose {
            TransferPurpose::Continuity => TransferResponseV1::HeldComplete {
                binding: self.binding.clone(),
            },
            TransferPurpose::Publication => TransferResponseV1::PreparedComplete {
                binding: self.binding.clone(),
            },
        };
        if encode_frame(&response).is_err() {
            return self.fail();
        }
        self.bytes.zeroize();
        self.state = SenderState::Confirmed;
        Ok(response)
    }

    pub(crate) fn finish(&mut self) {
        self.bytes.zeroize();
        self.state = SenderState::Finished;
    }
}

enum CollectorState {
    AwaitBegin,
    Collecting {
        index: u32,
        offset: u64,
        awaiting_chunk: bool,
    },
    Complete,
    Failed,
}

pub(crate) struct TransferCollector {
    purpose: TransferPurpose,
    request_digest: String,
    header: Option<TransferHeader>,
    binding: Option<TransferBinding>,
    bytes: Zeroizing<Vec<u8>>,
    state: CollectorState,
}
impl TransferCollector {
    pub(crate) fn new(purpose: TransferPurpose, request_digest: String) -> Result<Self> {
        super::hash(&request_digest)?;
        Ok(Self {
            purpose,
            request_digest,
            header: None,
            binding: None,
            bytes: Zeroizing::new(Vec::new()),
            state: CollectorState::AwaitBegin,
        })
    }

    fn fail<T>(&mut self) -> Result<T> {
        self.state = CollectorState::Failed;
        self.bytes.zeroize();
        Err(BridgeError::Binding)
    }

    pub(crate) fn header(&self) -> Result<&TransferHeader> {
        if matches!(
            self.state,
            CollectorState::AwaitBegin | CollectorState::Failed
        ) {
            return Err(BridgeError::Binding);
        }
        self.header.as_ref().ok_or(BridgeError::Binding)
    }

    pub(crate) fn begin(&mut self, header: TransferHeader) -> Result<()> {
        if !matches!(self.state, CollectorState::AwaitBegin)
            || header.validate().is_err()
            || header.purpose != self.purpose
            || header.request_digest != self.request_digest
        {
            return self.fail();
        }
        let binding = match header.binding() {
            Ok(value) => value,
            Err(_) => return self.fail(),
        };
        let total = match usize::try_from(header.total_bytes) {
            Ok(value) => value,
            Err(_) => return self.fail(),
        };
        if self.bytes.try_reserve_exact(total).is_err() {
            return self.fail();
        }
        self.header = Some(header);
        self.binding = Some(binding);
        self.state = CollectorState::Collecting {
            index: 0,
            offset: 0,
            awaiting_chunk: false,
        };
        Ok(())
    }

    pub(crate) fn next_request(&mut self) -> Result<TransferCommandV1> {
        let (index, offset) = match self.state {
            CollectorState::Collecting {
                index,
                offset,
                awaiting_chunk: false,
            } => (index, offset),
            _ => return self.fail(),
        };
        let Some(binding) = self.binding.clone() else {
            return self.fail();
        };
        self.state = CollectorState::Collecting {
            index,
            offset,
            awaiting_chunk: true,
        };
        Ok(TransferCommandV1::Next {
            binding,
            index,
            offset,
        })
    }

    pub(crate) fn accept_chunk(&mut self, chunk: TransferChunk) -> Result<()> {
        let (index, offset) = match self.state {
            CollectorState::Collecting {
                index,
                offset,
                awaiting_chunk: true,
            } => (index, offset),
            _ => return self.fail(),
        };
        let result = (|| {
            let header = self.header.as_ref().ok_or(BridgeError::Binding)?;
            if self.binding.as_ref() != Some(&chunk.binding)
                || chunk.index != index
                || chunk.offset != offset
            {
                return Err(BridgeError::Binding);
            }
            let length = header.expected_chunk_bytes(index, offset)?;
            if chunk.data_hex.len() != length.checked_mul(2).ok_or(BridgeError::Limit)?
                || !chunk
                    .data_hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(BridgeError::Binding);
            }
            let start = usize::try_from(offset).map_err(|_| BridgeError::Limit)?;
            let end = start.checked_add(length).ok_or(BridgeError::Limit)?;
            if self.bytes.len() != start
                || end > header.total_bytes as usize
                || end > self.bytes.capacity()
            {
                return Err(BridgeError::Binding);
            }
            // Exact validated reservation above means resize cannot allocate.
            self.bytes.resize(end, 0);
            hex::decode_to_slice(&chunk.data_hex, &mut self.bytes[start..end])
                .map_err(|_| BridgeError::Binding)?;
            let next_index = index.checked_add(1).ok_or(BridgeError::Limit)?;
            Ok((next_index, end as u64, header.chunk_count))
        })();
        match result {
            Ok((index, offset, count)) => {
                self.state = if index == count {
                    CollectorState::Complete
                } else {
                    CollectorState::Collecting {
                        index,
                        offset,
                        awaiting_chunk: false,
                    }
                };
                Ok(())
            }
            Err(_) => self.fail(),
        }
    }

    /// The first access to any bytes is after exact reconstruction and digest.
    /// The returned object is inert; the consumer still must parse the complete
    /// V5 schema, validate it, compare the exact request and head, and provide
    /// its existing semantic digest before acknowledging completion.
    pub(crate) fn finish(mut self) -> Result<CompleteTransferBytes> {
        if !matches!(self.state, CollectorState::Complete) {
            return self.fail();
        }
        let header = self.header.take().ok_or(BridgeError::Binding)?;
        if self.bytes.len() as u64 != header.total_bytes
            || byte_digest(header.purpose, &header.request_digest, &self.bytes)?
                != header.byte_digest
        {
            return self.fail();
        }
        let binding = self.binding.take().ok_or(BridgeError::Binding)?;
        Ok(CompleteTransferBytes {
            header,
            binding,
            bytes: self.bytes,
            state: CompleteState::Reconstructed,
        })
    }
}

enum CompleteState {
    Reconstructed,
    AwaitConfirmation,
    Confirmed,
    Failed,
}

/// Complete, byte-validated serialized evidence, never a capability. No serde,
/// Clone, partial constructor, or conversion into a lease is provided.
pub(crate) struct CompleteTransferBytes {
    header: TransferHeader,
    binding: TransferBinding,
    bytes: Zeroizing<Vec<u8>>,
    state: CompleteState,
}
impl CompleteTransferBytes {
    pub(crate) fn header(&self) -> &TransferHeader {
        &self.header
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn fail<T>(&mut self) -> Result<T> {
        self.state = CompleteState::Failed;
        self.bytes.zeroize();
        Err(BridgeError::Binding)
    }

    /// Supply evidence.digest() only after actual schema/request/head validation.
    /// Matching the advertised digest alone cannot authenticate the sender.
    pub(crate) fn accept_complete(
        &mut self,
        actual_semantic_digest: &str,
    ) -> Result<TransferCommandV1> {
        if !matches!(self.state, CompleteState::Reconstructed)
            || actual_semantic_digest != self.header.evidence_digest
        {
            return self.fail();
        }
        self.state = CompleteState::AwaitConfirmation;
        Ok(TransferCommandV1::AcceptComplete {
            binding: self.binding.clone(),
            byte_digest: self.header.byte_digest.clone(),
            evidence_digest: actual_semantic_digest.into(),
        })
    }

    pub(crate) fn require_confirmation(&mut self, response: &TransferResponseV1) -> Result<()> {
        let binding = match (self.header.purpose, response) {
            (TransferPurpose::Continuity, TransferResponseV1::HeldComplete { binding })
            | (TransferPurpose::Publication, TransferResponseV1::PreparedComplete { binding }) => {
                binding
            }
            _ => return self.fail(),
        };
        if !matches!(self.state, CompleteState::AwaitConfirmation) || binding != &self.binding {
            return self.fail();
        }
        self.state = CompleteState::Confirmed;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn into_bytes(self) -> Result<Zeroizing<Vec<u8>>> {
        if !matches!(self.state, CompleteState::Confirmed) {
            return Err(BridgeError::Binding);
        }
        Ok(self.bytes)
    }
}

#[cfg(test)]
#[path = "transfer_tests.rs"]
mod tests;
