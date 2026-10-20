//! Resource preflight only, before maintained prost allocates decoded messages.
//! Uses prost's key/varint parser, preserves supported unknown fields, and never
//! substitutes for the maintained protobuf decoder, cryptography or scanner.
use crate::ChainError;
use http_body_util::{BodyExt, Full, Limited};
use prost::encoding::{WireType, decode_key, decode_varint};
use tonic::{body::Body, codegen::http::Response};

const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
const MAX_COMPACT_ITEMS: usize = 8192;

#[cfg(test)]
pub(crate) async fn guard_response(
    response: Response<Body>,
    maximum_bytes: usize,
    method: &str,
) -> Result<Response<Body>, ChainError> {
    guard_response_observed(response, maximum_bytes, method, &Default::default()).await
}

pub(crate) async fn guard_response_observed(
    response: Response<Body>,
    maximum_bytes: usize,
    method: &str,
    observer: &crate::transport_diagnostics::Observer,
) -> Result<Response<Body>, ChainError> {
    let (parts, body) = response.into_parts();
    // Collect only the bounded raw response. No protobuf messages have been allocated.
    // The caller's async timeout encloses this read and the upstream body drain.
    let mut body = Limited::new(body, maximum_bytes);
    let mut bytes = Vec::with_capacity(maximum_bytes.min(16 * 1024));
    let mut trailers = None;
    let mut body_frames = 0usize;
    while let Some(frame) = body.frame().await {
        body_frames += 1;
        if body_frames > 65_536 {
            return Err(ChainError::ResourceLimit);
        }
        let frame = frame.map_err(|error| {
            if error.is::<http_body_util::LengthLimitError>() {
                ChainError::ResourceLimit
            } else {
                observer.record(crate::transport_diagnostics::FailureSite::BodyDrain);
                ChainError::TransportUnavailable
            }
        })?;
        match frame.into_data() {
            Ok(chunk) => {
                if trailers.is_some() {
                    return Err(ChainError::MalformedEvidence);
                }
                // One contiguous bounded buffer, not a vector per network fragment.
                bytes
                    .len()
                    .checked_add(chunk.len())
                    .filter(|n| *n <= maximum_bytes)
                    .ok_or(ChainError::ResourceLimit)?;
                bytes.extend_from_slice(&chunk);
            }
            Err(frame) => {
                if let Ok(next) = frame.into_trailers()
                    && trailers.replace(next).is_some()
                {
                    return Err(ChainError::MalformedEvidence);
                }
            }
        }
    }
    preflight_frames(&bytes, method)?;
    let body = Full::new(tonic::codegen::Bytes::from(bytes))
        .with_trailers(async move { trailers.map(Ok::<_, std::convert::Infallible>) });
    Ok(Response::from_parts(parts, Body::new(body)))
}

fn preflight_frames(mut bytes: &[u8], method: &str) -> Result<(), ChainError> {
    let method = method.rsplit('/').next().unwrap_or(method);
    let max_frames = match method {
        "GetBlockRange" => 32,
        "GetSubtreeRoots" => MAX_COMPACT_ITEMS,
        _ => 1,
    };
    let block = matches!(method, "GetBlock" | "GetBlockRange");
    let mut frames = 0;
    let mut items = 0;
    while !bytes.is_empty() {
        if bytes.len() < 5 || bytes[0] != 0 {
            return Err(ChainError::MalformedEvidence);
        }
        let length = u32::from_be_bytes(
            bytes[1..5]
                .try_into()
                .map_err(|_| ChainError::MalformedEvidence)?,
        ) as usize;
        if length > MAX_FRAME_BYTES {
            return Err(ChainError::ResourceLimit);
        }
        bytes = &bytes[5..];
        if length > bytes.len() {
            return Err(ChainError::MalformedEvidence);
        }
        frames += 1;
        if frames > max_frames {
            return Err(ChainError::ResourceLimit);
        }
        walk_message(
            &bytes[..length],
            if block { Shape::Block } else { Shape::Scalar },
            &mut items,
        )?;
        bytes = &bytes[length..];
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Shape {
    Block,
    Transaction,
    Scalar,
}

/// No heap allocation and depth at most three (block -> transaction -> compact item).
/// Unknown non-group fields are skipped exactly as prost does, within the frame bound.
/// Protobuf groups are outside the pinned schema and are refused rather than recursed.
fn walk_message(mut bytes: &[u8], shape: Shape, items: &mut usize) -> Result<(), ChainError> {
    while !bytes.is_empty() {
        let (tag, wire) = decode_key(&mut bytes).map_err(|_| ChainError::MalformedEvidence)?;
        let repeated = matches!(shape, Shape::Block) && tag == 7
            || matches!(shape, Shape::Transaction) && matches!(tag, 4..=9);
        let nested = if matches!(shape, Shape::Block) && tag == 7 {
            Shape::Transaction
        } else {
            Shape::Scalar
        };
        if repeated {
            if wire != WireType::LengthDelimited {
                return Err(ChainError::MalformedEvidence);
            }
            *items += 1;
            if *items > MAX_COMPACT_ITEMS {
                return Err(ChainError::ResourceLimit);
            }
        }
        match wire {
            WireType::Varint => {
                decode_varint(&mut bytes).map_err(|_| ChainError::MalformedEvidence)?;
            }
            WireType::SixtyFourBit => advance(&mut bytes, 8)?,
            WireType::ThirtyTwoBit => advance(&mut bytes, 4)?,
            WireType::LengthDelimited => {
                let length =
                    decode_varint(&mut bytes).map_err(|_| ChainError::MalformedEvidence)?;
                let length = usize::try_from(length).map_err(|_| ChainError::ResourceLimit)?;
                if length > bytes.len() {
                    return Err(ChainError::MalformedEvidence);
                }
                if repeated || (matches!(shape, Shape::Block) && tag == 8) {
                    walk_message(&bytes[..length], nested, items)?;
                }
                advance(&mut bytes, length)?;
            }
            WireType::StartGroup | WireType::EndGroup => return Err(ChainError::MalformedEvidence),
        }
    }
    Ok(())
}
fn advance(bytes: &mut &[u8], count: usize) -> Result<(), ChainError> {
    if count > bytes.len() {
        return Err(ChainError::MalformedEvidence);
    }
    *bytes = &bytes[count..];
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn frame(bytes: &[u8]) -> Vec<u8> {
        let mut framed = vec![0];
        framed.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        framed.extend_from_slice(bytes);
        framed
    }
    #[test]
    fn rejects_repeated_allocation_amplification_before_prost_decode() {
        // Only 16,386 wire bytes; naive prost would allocate >3 MiB of empty
        // CompactTx capacity. The preflight rejects without decoding any of them.
        assert_eq!(
            preflight_frames(&frame(&[0x3a, 0].repeat(MAX_COMPACT_ITEMS + 1)), "GetBlock"),
            Err(ChainError::ResourceLimit)
        );
        assert!(preflight_frames(&frame(&[0x3a, 0].repeat(MAX_COMPACT_ITEMS)), "GetBlock").is_ok());
        // Nested empty output messages are counted before allocating their Vecs.
        let tx = [0x2a, 0].repeat(MAX_COMPACT_ITEMS);
        let mut block = vec![0x3a];
        prost::encoding::encode_varint(tx.len() as u64, &mut block);
        block.extend(tx);
        assert_eq!(
            preflight_frames(&frame(&block), "GetBlockRange"),
            Err(ChainError::ResourceLimit)
        );
        // The budget spans frames; splitting the same amplification is ineffective.
        let mut split = frame(&[0x3a, 0].repeat(4097));
        split.extend(frame(&[0x3a, 0].repeat(4096)));
        assert_eq!(
            preflight_frames(&split, "GetBlockRange"),
            Err(ChainError::ResourceLimit)
        );
    }
    #[test]
    fn bounds_frames_and_rejects_groups_but_preserves_unknown_scalar_fields() {
        let mut excess = Vec::new();
        for _ in 0..33 {
            excess.extend(frame(&[]));
        }
        assert_eq!(
            preflight_frames(&excess, "GetBlockRange"),
            Err(ChainError::ResourceLimit)
        );
        let mut compressed = frame(&[]);
        compressed[0] = 1;
        assert_eq!(
            preflight_frames(&compressed, "GetBlock"),
            Err(ChainError::MalformedEvidence)
        );
        assert_eq!(
            preflight_frames(&[0, 0, 0], "GetBlock"),
            Err(ChainError::MalformedEvidence)
        );
        assert_eq!(
            preflight_frames(&frame(&[0x53, 0x54]), "GetBlock"),
            Err(ChainError::MalformedEvidence)
        );
        // Unknown tag100 varint and tag101 bytes remain compatible with the pinned decoder.
        assert!(
            preflight_frames(
                &frame(&[0xa0, 0x06, 0x01, 0xaa, 0x06, 0x02, 0xff, 0xff]),
                "GetBlock"
            )
            .is_ok()
        );
        assert_eq!(
            preflight_frames(&[0, 0x7f, 0xff, 0xff, 0xff], "GetBlock"),
            Err(ChainError::ResourceLimit)
        );
    }
    #[cfg(feature = "synthetic-qualification")]
    #[tokio::test]
    async fn diagnostic_body_failure_is_site_grounded_not_resource_failure() {
        use crate::transport_diagnostics::{Observer, TransportDiagnostics};
        let diagnostics = TransportDiagnostics::default();
        let observer = Observer { diagnostics: Some(diagnostics.clone()) };
        let body = Full::new(tonic::codegen::Bytes::new())
            .map_err(|never| -> std::io::Error { match never {} })
            .with_trailers(async {
                Some(Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset)))
            });
        assert!(matches!(
            guard_response_observed(Response::new(Body::new(body)), 100, "GetBlock", &observer).await,
            Err(ChainError::TransportUnavailable)
        ));
        assert_eq!(diagnostics.snapshot().body_drain, 1);
        let oversized = Full::new(tonic::codegen::Bytes::from(vec![0; 101]));
        assert!(matches!(
            guard_response_observed(Response::new(Body::new(oversized)), 100, "GetBlock", &observer).await,
            Err(ChainError::ResourceLimit)
        ));
        assert_eq!(diagnostics.snapshot().body_drain, 1);
    }

    #[tokio::test]
    async fn fragmented_raw_body_has_one_buffer_and_a_fragment_budget() {
        use tonic::codegen::{
            Bytes,
            tokio_stream::{self, StreamExt},
        };
        let raw = frame(&[0xa0, 0x06, 0x01]);
        let mut chunks = Vec::new();
        for byte in &raw {
            let mut full = Full::new(Bytes::from(vec![*byte]));
            chunks.push(full.frame().await.unwrap());
        }
        let response = Response::new(Body::new(http_body_util::StreamBody::new(
            tokio_stream::iter(chunks),
        )));
        let result = guard_response(response, 1024, "GetBlock")
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(result.as_ref(), raw);
        // Lazy production of tiny fragments avoids a large test allocation too.
        let fragments = tokio_stream::iter(0..65_537).then(|_| async {
            let mut full = Full::new(Bytes::from_static(&[0]));
            full.frame().await.unwrap()
        });
        let response = Response::new(Body::new(http_body_util::StreamBody::new(fragments)));
        assert!(matches!(
            guard_response(response, 128 * 1024, "GetBlock").await,
            Err(ChainError::ResourceLimit)
        ));
    }

    #[tokio::test]
    async fn raw_body_guard_preserves_trailers_and_bounds_aggregate_bytes() {
        let mut trailers = tonic::codegen::http::HeaderMap::new();
        trailers.insert("grpc-status", "0".parse().unwrap());
        let raw = frame(&[]);
        let response = Response::new(Body::new(
            Full::new(tonic::codegen::Bytes::from(raw.clone()))
                .with_trailers(async { Some(Ok::<_, std::convert::Infallible>(trailers)) }),
        ));
        let guarded = guard_response(response, 100, "GetBlock")
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
        assert_eq!(guarded.trailers().unwrap()["grpc-status"], "0");
        assert_eq!(guarded.to_bytes().as_ref(), raw);
        let response = Response::new(Body::new(Full::new(tonic::codegen::Bytes::from(vec![
            0;
            101
        ]))));
        assert!(matches!(
            guard_response(response, 100, "GetBlockRange").await,
            Err(ChainError::ResourceLimit)
        ));
    }
}
