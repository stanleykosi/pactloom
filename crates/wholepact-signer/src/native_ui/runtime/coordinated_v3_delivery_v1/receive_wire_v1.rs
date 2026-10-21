//! One genuine coordinated Receive owner, one actual activated original channel.
//! Only inert framing/commands are shared with the maintained native profile.
use super::*;
use crate::authority_bridge::durable_review_ipc_v1::{self as wire, DeliveryCommandV1};
use crate::authority_bridge::durable_review_ipc_v3::coordinated_v1::{
    CoordinatedClosedResponseV1, CoordinatedDeliveryReceiptV1,
};
use crate::authority_bridge::{BridgeError, Result as BridgeResult};
use crate::native_peer::PeerProcess;
use std::os::unix::net::UnixStream;

pub(super) fn receive_exact(
    mut stream: UnixStream,
    peer: &crate::ipc::CoordinatedPairPeerV1,
    intent: &CoordinatedRecipientIntentV1,
    action: &SignerV3ReceiveFinalV1,
    original_material_deadline: Instant,
) -> BridgeResult<Zeroizing<Vec<u8>>> {
    intent.validate()?;
    let deadline = action
        .original_receive_deadline()
        .min(original_material_deadline)
        .min(peer.deadline());
    let observed = PeerProcess::observe(&stream).map_err(|_| BridgeError::Permission)?;
    peer.actual_peer()
        .same_live_process(&observed)
        .map_err(|_| BridgeError::Permission)?;
    let observer = stream.try_clone().map_err(|_| BridgeError::Ipc)?;
    let current = || {
        peer.check_current().map_err(|_| BridgeError::Permission)?;
        let actual = PeerProcess::observe(&observer).map_err(|_| BridgeError::Permission)?;
        peer.actual_peer()
            .same_live_process(&actual)
            .map_err(|_| BridgeError::Permission)?;
        if Instant::now() >= deadline {
            return Err(BridgeError::Permission);
        }
        action.check_current().map_err(|_| BridgeError::Permission)
    };
    let send = |stream: &mut UnixStream, value: &CoordinatedClosedResponseV1| {
        wire::bounded_write_restricted(stream, value, deadline, &current, &current)
    };
    let intent_digest = intent.digest()?;
    let mut raw = Zeroizing::new(Vec::new());
    let mut begun = false;
    loop {
        current()?;
        let frame = wholepact_signer_origin::framing::read_frame_capped_checked_observed_until(
            &stream,
            peer.actual_peer(),
            128 * 1024,
            deadline,
            || current().map_err(|_| wholepact_signer_origin::Error::Permission),
        )
        .map_err(|_| BridgeError::Ipc)?;
        let command: DeliveryCommandV1 =
            wholepact_core::strict_json::parse_typed_json_with_byte_limit(&frame, 128 * 1024)
                .map_err(|_| BridgeError::Binding)?;
        current()?;
        match &command {
            DeliveryCommandV1::CheckCurrent => send(
                &mut stream,
                &CoordinatedClosedResponseV1::Current {
                    intent_digest: intent_digest.clone(),
                },
            )?,
            DeliveryCommandV1::Begin {
                payload_digest,
                payload_bytes,
            } => {
                if begun
                    || payload_digest != &intent.payload_digest
                    || *payload_bytes != intent.payload_bytes
                {
                    return Err(BridgeError::Binding);
                }
                raw.try_reserve_exact(
                    usize::try_from(*payload_bytes).map_err(|_| BridgeError::Limit)?,
                )
                .map_err(|_| BridgeError::Limit)?;
                begun = true;
                send(
                    &mut stream,
                    &CoordinatedClosedResponseV1::Receiving { received_bytes: 0 },
                )?;
            }
            DeliveryCommandV1::Chunk { offset, data_hex } => {
                if !begun
                    || *offset != raw.len() as u64
                    || data_hex.is_empty()
                    || data_hex.len() > wire::CHUNK_BYTES * 2
                    || data_hex.len() % 2 != 0
                    || data_hex
                        .bytes()
                        .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
                {
                    return Err(BridgeError::Binding);
                }
                let chunk =
                    Zeroizing::new(hex::decode(data_hex).map_err(|_| BridgeError::Binding)?);
                if raw
                    .len()
                    .checked_add(chunk.len())
                    .ok_or(BridgeError::Limit)? as u64
                    > intent.payload_bytes
                {
                    return Err(BridgeError::Limit);
                }
                raw.extend_from_slice(&chunk);
                send(
                    &mut stream,
                    &CoordinatedClosedResponseV1::Receiving {
                        received_bytes: raw.len() as u64,
                    },
                )?;
            }
            DeliveryCommandV1::Finish => {
                if !begun
                    || raw.len() as u64 != intent.payload_bytes
                    || hex::encode(Sha256::digest(raw.as_slice())) != intent.payload_digest
                {
                    return Err(BridgeError::Binding);
                }
                current()?;
                send(
                    &mut stream,
                    &CoordinatedClosedResponseV1::BytesReceived {
                        receipt: CoordinatedDeliveryReceiptV1 {
                            version: 1,
                            intent_digest,
                            payload_digest: intent.payload_digest.clone(),
                            payload_bytes: intent.payload_bytes,
                            state: "bytes_received_unverified".into(),
                        },
                    },
                )?;
                // This is ONLY bytes custody. No VerifiedImport or completion
                // observation exists until independent proof/economics checks.
                return Ok(raw);
            }
        }
    }
}
