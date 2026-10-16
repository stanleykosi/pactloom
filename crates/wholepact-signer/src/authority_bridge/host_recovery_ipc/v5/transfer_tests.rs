//! No sockets, live native decisions, witness operations, signing, or proofs.
//! String fixtures test transport bounds only. The complete V5 fixture below
//! exercises the maintained evidence validators and both actual purpose binds.
use super::*;
use crate::authority_bridge::host_publication_ipc::v5::HostRecoveryPublicationRequestV5;
use crate::authority_bridge::host_recovery_ipc::v5::HostRecoveryContinuityEvidenceV5;

fn h(value: &str) -> String {
    value.repeat(32)
}

fn metadata(purpose: TransferPurpose) -> TransferMetadata {
    TransferMetadata {
        purpose,
        transfer_id: h("11"),
        lease_id: h("22"),
        request_digest: h("33"),
        native_review_digest: h("44"),
        evidence_digest: h("55"),
        head_digest: h("66"),
        head_sequence: 7,
    }
}

fn pair(size: usize, purpose: TransferPurpose) -> (TransferSender, TransferCollector) {
    assert!(size >= 2);
    let mut sender = TransferSender::new(metadata(purpose), &"a".repeat(size - 2)).unwrap();
    let mut collector = TransferCollector::new(purpose, h("33")).unwrap();
    collector.begin(sender.begin().unwrap()).unwrap();
    (sender, collector)
}

fn collect(sender: &mut TransferSender, mut collector: TransferCollector) -> CompleteTransferBytes {
    let count = collector.header().unwrap().chunk_count;
    for _ in 0..count {
        let command = collector.next_request().unwrap();
        assert!(encode_frame(&command).unwrap().len() < MAX_TRANSFER_FRAME_BYTES);
        let command = decode_frame(&encode_frame(&command).unwrap()).unwrap();
        let chunk = sender.next(&command).unwrap();
        let encoded = encode_frame(&TransferResponseV1::Chunk { chunk }).unwrap();
        assert!(encoded.len() < MAX_TRANSFER_FRAME_BYTES);
        let TransferResponseV1::Chunk { chunk } = decode_frame(&encoded).unwrap() else {
            panic!("expected chunk")
        };
        collector.accept_chunk(chunk).unwrap();
    }
    collector.finish().unwrap()
}

#[test]
fn exact_byte_and_begin_domains_and_wire_field_goldens() {
    for (purpose, bytes, begin) in [
        (
            TransferPurpose::Continuity,
            "10240a395b88f908f56314b5b233cc05e9387d355d03247f9ce662a2fd473d44",
            "260619c6d794f8255a566f57915472f803e897018274d56982ab5a9cd40fe513",
        ),
        (
            TransferPurpose::Publication,
            "ed951ffea07fb88d64188f09ba83a8baedb3aaaec8e2ff5b54a32806d2290805",
            "621424abf7794415ca9ed8efd7a68284bf447208aaab929be018c34fe03e9f79",
        ),
    ] {
        let mut sender = TransferSender::new(metadata(purpose), &"x").unwrap();
        let header = sender.begin().unwrap();
        assert_eq!(header.byte_digest, bytes);
        assert_eq!(header.binding().unwrap().begin_digest, begin);
        let mut collector = TransferCollector::new(purpose, h("33")).unwrap();
        collector.begin(header).unwrap();
        let command = collector.next_request().unwrap();
        let exact = format!(
            "{{\"operation\":\"next\",\"binding\":{{\"transfer_id\":\"{}\",\"begin_digest\":\"{}\"}},\"index\":0,\"offset\":0}}",
            h("11"),
            begin
        );
        assert_eq!(encode_frame(&command).unwrap().as_slice(), exact.as_bytes());
        let chunk = sender.next(&command).unwrap();
        assert_eq!(chunk.data_hex, "227822");
        let encoded = encode_frame(&TransferResponseV1::Chunk { chunk }).unwrap();
        let exact = format!(
            "{{\"status\":\"chunk\",\"chunk\":{{\"binding\":{{\"transfer_id\":\"{}\",\"begin_digest\":\"{}\"}},\"index\":0,\"offset\":0,\"data_hex\":\"227822\"}}}}",
            h("11"),
            begin
        );
        assert_eq!(encoded.as_slice(), exact.as_bytes());
    }
}

#[test]
fn complete_nonempty_v5_fixture_has_exact_21_chunk_roundtrip_for_both_purposes() {
    let evidence = crate::consent_journal::common_context_reentry_audit_fixture::fixture();
    evidence.validate().unwrap();
    let original_bytes = serde_json::to_vec(&evidence).unwrap();
    assert_eq!(original_bytes.len(), 683_170);
    assert!(
        !evidence
            .complete_history
            .construction
            .transport
            .grants
            .is_empty()
    );
    assert!(
        !evidence
            .complete_history
            .construction
            .transport
            .consumptions
            .is_empty()
    );
    let semantic = evidence.digest().unwrap();
    let publication = HostRecoveryPublicationRequestV5::new(
        &evidence,
        "/synthetic/recovered-profile".into(),
        h("97"),
    )
    .unwrap();
    for purpose in [TransferPurpose::Continuity, TransferPurpose::Publication] {
        let request_digest = match purpose {
            TransferPurpose::Continuity => evidence.request.digest().unwrap(),
            TransferPurpose::Publication => publication.digest().unwrap(),
        };
        let mut meta = metadata(purpose);
        meta.request_digest = request_digest.clone();
        meta.evidence_digest = semantic.clone();
        meta.head_digest = evidence.head.digest.clone();
        meta.head_sequence = evidence.head.sequence;
        let mut sender = TransferSender::new(meta, &evidence).unwrap();
        let header = sender.begin().unwrap();
        assert_eq!(header.chunk_count, 21);
        let begin = encode_frame(&TransferResponseV1::Begin { header }).unwrap();
        assert!(begin.len() < MAX_TRANSFER_FRAME_BYTES);
        let TransferResponseV1::Begin { header } = decode_frame(&begin).unwrap() else {
            panic!("begin")
        };
        let mut collector = TransferCollector::new(purpose, request_digest).unwrap();
        collector.begin(header).unwrap();
        let mut complete = collect(&mut sender, collector);
        assert_eq!(complete.bytes(), original_bytes.as_slice());
        let reconstructed: HostRecoveryContinuityEvidenceV5 =
            serde_json::from_slice(complete.bytes()).unwrap();
        reconstructed.validate().unwrap();
        assert!(reconstructed == evidence);
        assert_eq!(reconstructed.head.digest, complete.header().head_digest);
        assert_eq!(reconstructed.head.sequence, complete.header().head_sequence);
        match purpose {
            TransferPurpose::Continuity => assert!(reconstructed.request == evidence.request),
            TransferPurpose::Publication => publication.matches_evidence(&reconstructed).unwrap(),
        }
        let actual_semantic = reconstructed.digest().unwrap();
        assert_eq!(actual_semantic, semantic);
        let accept = complete.accept_complete(&actual_semantic).unwrap();
        sender.accept_complete(&accept).unwrap();
        let response = sender.confirmation().unwrap();
        complete.require_confirmation(&response).unwrap();
        assert_eq!(
            complete.into_bytes().unwrap().as_slice(),
            original_bytes.as_slice()
        );
        // No DTO in this test creates a live continuity/publication owner.
        assert!(
            reconstructed
                .complete_history
                .require_financial_activation_supported()
                .is_err()
        );
    }
}

#[test]
fn evidence_chunk_boundaries_and_maximum_32_chunks_are_exact() {
    for size in [
        2,
        RAW_CHUNK_BYTES - 1,
        RAW_CHUNK_BYTES,
        RAW_CHUNK_BYTES + 1,
        MAX_TRANSFER_EVIDENCE_BYTES - 1,
        MAX_TRANSFER_EVIDENCE_BYTES,
    ] {
        let (mut sender, collector) = pair(size, TransferPurpose::Continuity);
        assert_eq!(
            sender.header().chunk_count as usize,
            size.div_ceil(RAW_CHUNK_BYTES)
        );
        let mut complete = collect(&mut sender, collector);
        assert_eq!(complete.bytes().len(), size);
        let accept = complete.accept_complete(&h("55")).unwrap();
        sender.accept_complete(&accept).unwrap();
        complete
            .require_confirmation(&sender.confirmation().unwrap())
            .unwrap();
        assert_eq!(complete.into_bytes().unwrap().len(), size);
    }
    assert!(
        TransferSender::new(
            metadata(TransferPurpose::Continuity),
            &"a".repeat(MAX_TRANSFER_EVIDENCE_BYTES - 1)
        )
        .is_err()
    );
}

#[test]
fn rejects_announced_bounds_before_any_collection_allocation() {
    let sender = TransferSender::new(metadata(TransferPurpose::Continuity), &"x").unwrap();
    for field in 0..16 {
        let mut header = sender.header().clone();
        match field {
            0 => header.total_bytes = 0,
            1 => header.total_bytes = MAX_TRANSFER_EVIDENCE_BYTES as u64 + 1,
            2 => header.total_bytes = u64::MAX,
            3 => header.chunk_count = 0,
            4 => header.chunk_count = 33,
            5 => header.chunk_count = u32::MAX,
            6 => header.raw_chunk_bytes = 0,
            7 => header.raw_chunk_bytes = RAW_CHUNK_BYTES as u32 + 1,
            8 => header.head_sequence = u64::MAX,
            9 => header.dialect = "single_frame".into(),
            10 => header.transfer_id = h("AA"),
            11 => header.lease_id = "a".repeat(63),
            12 => header.native_review_digest = "a".repeat(65),
            13 => header.evidence_digest = h("gg"),
            14 => header.byte_digest.clear(),
            _ => header.head_digest.push('0'),
        }
        let mut collector = TransferCollector::new(TransferPurpose::Continuity, h("33")).unwrap();
        assert_eq!(collector.bytes.capacity(), 0);
        assert!(collector.begin(header).is_err(), "field {field}");
        assert_eq!(collector.bytes.capacity(), 0, "field {field}");
        assert!(collector.begin(sender.header().clone()).is_err());
        assert!(collector.header().is_err());
    }
}

#[test]
fn strict_dialect_and_purpose_are_strings_only() {
    assert_eq!(
        serde_json::from_str::<V5TransferDialect>("\"single_frame\"").unwrap(),
        V5TransferDialect::SingleFrame
    );
    assert_eq!(
        serde_json::from_str::<V5TransferDialect>("\"v5_bounded_transfer_v1\"").unwrap(),
        V5TransferDialect::BoundedV1
    );
    for value in [
        "null",
        "1",
        "true",
        "[]",
        "{}",
        "\"bounded_v1\"",
        "{\"v5_bounded_transfer_v1\":null}",
        "{\"single_frame\":null}",
    ] {
        assert!(serde_json::from_str::<V5TransferDialect>(value).is_err());
    }
    for value in [
        "null",
        "1",
        "{\"continuity\":null}",
        "{\"publication\":null}",
        "\"admit\"",
    ] {
        assert!(serde_json::from_str::<TransferPurpose>(value).is_err());
    }
}

#[test]
fn dedicated_wire_frame_exact_cap_and_strict_json_envelope() {
    assert_eq!(
        encode_frame(&TransferCommandV1::Finish {})
            .unwrap()
            .as_slice(),
        br#"{"operation":"finish"}"#
    );
    assert_eq!(
        encode_frame(&TransferResponseV1::Denied {})
            .unwrap()
            .as_slice(),
        br#"{"status":"denied"}"#
    );
    assert_eq!(
        encode_frame(&TransferResponseV1::Finished {})
            .unwrap()
            .as_slice(),
        br#"{"status":"finished"}"#
    );

    let exact = serde_json::json!({"pad":"a".repeat(MAX_TRANSFER_FRAME_BYTES - 1 - 10)});
    let encoded = encode_frame(&exact).unwrap();
    assert_eq!(encoded.len() + 1, MAX_TRANSFER_FRAME_BYTES);
    assert!(decode_frame::<serde_json::Value>(&encoded).is_ok());
    let over = serde_json::json!({"pad":"a".repeat(MAX_TRANSFER_FRAME_BYTES - 10)});
    assert!(encode_frame(&over).is_err());
    assert!(decode_frame::<serde_json::Value>(&serde_json::to_vec(&over).unwrap()).is_err());
    for bytes in [
        b"".as_slice(),
        b" {}",
        b"{} ",
        b"{}\n",
        b"{}\r",
        b"{}{}",
        b"null",
        b"[]",
    ] {
        assert!(decode_frame::<serde_json::Value>(bytes).is_err());
    }
    for bytes in [
        b"{\"operation\":\"finish\",\"extra\":true}".as_slice(),
        b"{\"operation\":\"admit\"}",
        b"{\"operation\":\"check_current\"}",
        b"{\"operation\":\"finish\",\"operation\":\"finish\"}",
    ] {
        assert!(
            decode_frame::<TransferCommandV1>(bytes).is_err(),
            "unexpected command accepted: {}",
            String::from_utf8_lossy(bytes)
        );
    }
    for bytes in [
        b"{\"status\":\"held\",\"lease_id\":\"x\",\"evidence\":{}}".as_slice(),
        b"{\"status\":\"prepared\",\"evidence\":{}}",
        b"{\"status\":\"denied\",\"extra\":1}",
        b"{\"status\":\"finished\",\"extra\":1}",
    ] {
        assert!(decode_frame::<TransferResponseV1>(bytes).is_err());
    }
}

#[test]
fn every_begin_binding_field_is_covered_against_substitution() {
    for field in 0..10 {
        let (mut sender, _) = pair(100, TransferPurpose::Continuity);
        let mut changed = sender.header().clone();
        match field {
            0 => changed.transfer_id = h("77"),
            1 => changed.lease_id = h("77"),
            2 => changed.request_digest = h("77"),
            3 => changed.native_review_digest = h("77"),
            4 => changed.evidence_digest = h("77"),
            5 => changed.byte_digest = h("77"),
            6 => changed.head_digest = h("77"),
            7 => changed.head_sequence += 1,
            8 => changed.total_bytes += 1,
            _ => changed.purpose = TransferPurpose::Publication,
        }
        let command = TransferCommandV1::Next {
            binding: changed.binding().unwrap(),
            index: 0,
            offset: 0,
        };
        assert!(sender.next(&command).is_err(), "field {field}");
        assert!(sender.bytes.is_empty());
        assert!(sender.begin().is_err());
    }
}

#[test]
fn exact_request_and_cross_purpose_begin_substitution_rejected_both_ways() {
    for (expected, supplied) in [
        (TransferPurpose::Continuity, TransferPurpose::Publication),
        (TransferPurpose::Publication, TransferPurpose::Continuity),
    ] {
        let header = TransferSender::new(metadata(supplied), &"x")
            .unwrap()
            .begin()
            .unwrap();
        let mut collector = TransferCollector::new(expected, h("33")).unwrap();
        assert!(collector.begin(header).is_err());
    }
    let header = TransferSender::new(metadata(TransferPurpose::Continuity), &"x")
        .unwrap()
        .begin()
        .unwrap();
    let mut collector = TransferCollector::new(TransferPurpose::Continuity, h("77")).unwrap();
    assert!(collector.begin(header).is_err());
}

#[test]
fn wrong_order_offsets_and_duplicate_requests_fail_terminally() {
    for field in 0..5 {
        let (mut sender, mut collector) = pair(RAW_CHUNK_BYTES + 1, TransferPurpose::Continuity);
        let mut command = collector.next_request().unwrap();
        if let TransferCommandV1::Next {
            binding,
            index,
            offset,
        } = &mut command
        {
            match field {
                0 => *index = 1,
                1 => *index = u32::MAX,
                2 => *offset = 1,
                3 => *offset = u64::MAX,
                _ => binding.transfer_id = h("77"),
            }
        }
        assert!(sender.next(&command).is_err());
        assert!(sender.bytes.is_empty());
        assert!(sender.next(&TransferCommandV1::Finish {}).is_err());
    }
    let (mut sender, mut collector) = pair(RAW_CHUNK_BYTES + 1, TransferPurpose::Continuity);
    let command = collector.next_request().unwrap();
    let first = sender.next(&command).unwrap();
    collector.accept_chunk(first).unwrap();
    assert!(sender.next(&command).is_err());
    assert!(collector.finish().is_err()); // omitted last chunk

    let (_, mut collector) = pair(100, TransferPurpose::Continuity);
    collector.next_request().unwrap();
    assert!(collector.next_request().is_err()); // pipelining is terminal
    assert!(collector.finish().is_err());
}

#[test]
fn malformed_noncanonical_short_long_and_unsolicited_chunks_are_terminal() {
    for field in 0..10 {
        let (mut sender, mut collector) = pair(RAW_CHUNK_BYTES + 1, TransferPurpose::Continuity);
        let command = collector.next_request().unwrap();
        let mut chunk = sender.next(&command).unwrap();
        match field {
            0 => {
                chunk.data_hex.pop();
            }
            1 => {
                chunk.data_hex.truncate(chunk.data_hex.len() - 2);
            }
            2 => chunk.data_hex.push_str("00"),
            3 => chunk.data_hex.replace_range(0..1, "A"),
            4 => chunk.data_hex.replace_range(0..1, "g"),
            5 => chunk.data_hex.replace_range(0..1, " "),
            6 => chunk.index = 1,
            7 => chunk.offset = u64::MAX,
            8 => chunk.binding.transfer_id = h("77"),
            _ => chunk.binding.begin_digest = h("77"),
        }
        assert!(collector.accept_chunk(chunk).is_err(), "field {field}");
        assert!(collector.bytes.is_empty());
        assert!(collector.next_request().is_err());
        assert!(collector.finish().is_err());
    }
    let (mut sender, mut collector) = pair(100, TransferPurpose::Continuity);
    let unsolicited = TransferCommandV1::Next {
        binding: sender.header().binding().unwrap(),
        index: 0,
        offset: 0,
    };
    assert!(
        collector
            .accept_chunk(sender.next(&unsolicited).unwrap())
            .is_err()
    );

    let (mut sender, mut collector) = pair(RAW_CHUNK_BYTES + 1, TransferPurpose::Continuity);
    let command = collector.next_request().unwrap();
    let chunk = sender.next(&command).unwrap();
    let replay: TransferChunk =
        serde_json::from_slice(&serde_json::to_vec(&chunk).unwrap()).unwrap();
    collector.accept_chunk(chunk).unwrap();
    collector.next_request().unwrap();
    assert!(collector.accept_chunk(replay).is_err());
}

#[test]
fn corruption_byte_digest_and_semantic_digest_are_independent_checks() {
    let (mut sender, mut collector) = pair(100, TransferPurpose::Continuity);
    let command = collector.next_request().unwrap();
    let mut chunk = sender.next(&command).unwrap();
    chunk.data_hex.replace_range(0..2, "00");
    collector.accept_chunk(chunk).unwrap(); // valid hex, wrong authenticated bytes
    assert!(collector.finish().is_err());

    let (mut sender, collector) = pair(100, TransferPurpose::Continuity);
    let mut complete = collect(&mut sender, collector);
    assert!(complete.accept_complete(&h("77")).is_err());
    assert!(complete.bytes().is_empty());
    assert!(complete.accept_complete(&h("55")).is_err());

    for field in 0..3 {
        let (mut sender, collector) = pair(100, TransferPurpose::Continuity);
        let mut complete = collect(&mut sender, collector);
        let mut command = complete.accept_complete(&h("55")).unwrap();
        if let TransferCommandV1::AcceptComplete {
            binding,
            byte_digest,
            evidence_digest,
        } = &mut command
        {
            match field {
                0 => binding.begin_digest = h("77"),
                1 => *byte_digest = h("77"),
                _ => *evidence_digest = h("77"),
            }
        }
        assert!(sender.accept_complete(&command).is_err());
        assert!(sender.confirmation().is_err());
    }
}

#[test]
fn early_accept_forged_held_and_cross_purpose_confirmation_are_terminal() {
    let (mut sender, collector) = pair(100, TransferPurpose::Continuity);
    let early = TransferCommandV1::AcceptComplete {
        binding: sender.header().binding().unwrap(),
        byte_digest: sender.header().byte_digest.clone(),
        evidence_digest: h("55"),
    };
    assert!(sender.accept_complete(&early).is_err());
    assert!(sender.confirmation().is_err());
    assert!(collector.finish().is_err());
    let (mut sender, _) = pair(100, TransferPurpose::Publication);
    assert!(sender.confirmation().is_err());

    for purpose in [TransferPurpose::Continuity, TransferPurpose::Publication] {
        for failure in 0..5 {
            let (mut sender, collector) = pair(100, purpose);
            let mut complete = collect(&mut sender, collector);
            if failure != 0 {
                complete.accept_complete(&h("55")).unwrap();
            }
            let mut binding = complete.header().binding().unwrap();
            if failure == 1 {
                binding.transfer_id = h("77");
            }
            if failure == 2 {
                binding.begin_digest = h("77");
            }
            let response = match (purpose, failure) {
                (_, 4) => TransferResponseV1::Denied {},
                (TransferPurpose::Continuity, 3) | (TransferPurpose::Publication, 0..=2) => {
                    TransferResponseV1::PreparedComplete { binding }
                }
                _ => TransferResponseV1::HeldComplete { binding },
            };
            assert!(complete.require_confirmation(&response).is_err());
            assert!(complete.bytes().is_empty());
            assert!(complete.into_bytes().is_err());
        }
    }
}

#[test]
fn duplicate_begin_accept_confirmation_and_finish_cannot_resume() {
    let (mut sender, mut collector) = pair(100, TransferPurpose::Continuity);
    assert!(collector.begin(sender.header().clone()).is_err());
    assert!(collector.bytes.is_empty());
    assert!(sender.begin().is_err());

    let (mut sender, collector) = pair(100, TransferPurpose::Continuity);
    let mut complete = collect(&mut sender, collector);
    let accept = complete.accept_complete(&h("55")).unwrap();
    sender.accept_complete(&accept).unwrap();
    assert!(sender.accept_complete(&accept).is_err());
    assert!(sender.confirmation().is_err());
    assert!(complete.accept_complete(&h("55")).is_err());

    let (mut sender, collector) = pair(100, TransferPurpose::Continuity);
    let mut complete = collect(&mut sender, collector);
    sender
        .accept_complete(&complete.accept_complete(&h("55")).unwrap())
        .unwrap();
    let response = sender.confirmation().unwrap();
    complete.require_confirmation(&response).unwrap();
    assert!(complete.require_confirmation(&response).is_err());
    assert!(complete.into_bytes().is_err());
    assert!(sender.confirmation().is_err());

    let (mut sender, _) = pair(100, TransferPurpose::Publication);
    sender.finish();
    assert!(sender.bytes.is_empty());
    assert!(sender.begin().is_err());
}
