//! Inert synthetic validation only: no socket, native approval factory, wallet,
//! witness service, credentials, proof or financial action is exercised here.
use super::*;
use crate::consent_journal::common_context_reentry_audit_fixture as fixture;

fn request(evidence: &HostRecoveryContinuityEvidenceV5) -> HostRecoveryPublicationRequestV5 {
    HostRecoveryPublicationRequestV5::new(
        evidence,
        PathBuf::from("/synthetic/recovered-profile"),
        "97".repeat(32),
    )
    .unwrap()
}

#[test]
fn publication_v5_binds_exact_complete_transport_evidence_without_projection() {
    let evidence = fixture::fixture();
    let request = request(&evidence);
    request.matches_evidence(&evidence).unwrap();
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
            .credentials
            .is_empty()
    );
    assert!(
        !evidence
            .complete_history
            .construction
            .transport
            .reservations
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
    let exact = request.digest().unwrap();
    for field in 0..6 {
        let mut changed = request.clone();
        match field {
            0 => changed.continuity.inventory_digest = "98".repeat(32),
            1 => changed.continuity.generation_id = "98".repeat(32),
            2 => changed.generation_manifest_digest = "98".repeat(32),
            3 => changed.continuity_evidence_digest = "98".repeat(32),
            4 => changed.target_profile = PathBuf::from("/synthetic/other-profile"),
            _ => {
                changed
                    .continuity
                    .expected_witness
                    .pinned_server_certificate_digest = "98".repeat(32)
            }
        }
        assert_ne!(exact, changed.digest().unwrap());
        if matches!(field, 0 | 1 | 3 | 5) {
            assert!(changed.matches_evidence(&evidence).is_err());
        }
    }
    for field in 0..5 {
        let mut changed = evidence.clone();
        match field {
            0 => changed
                .complete_history
                .construction
                .transport
                .grants
                .clear(),
            1 => changed
                .complete_history
                .construction
                .transport
                .credentials
                .clear(),
            2 => changed
                .complete_history
                .construction
                .transport
                .reservations
                .clear(),
            3 => changed
                .complete_history
                .construction
                .transport
                .consumptions
                .clear(),
            _ => changed
                .complete_history
                .signer_common_context_audit
                .reentry
                .rows
                .clear(),
        }
        assert!(request.matches_evidence(&changed).is_err());
        assert!(
            evidence
                .require_unchanged(&changed, Duration::ZERO)
                .is_err()
        );
    }
}

#[test]
fn publication_v5_audit_cannot_rebind_native_review_admission_or_target() {
    let evidence = fixture::fixture();
    let request = request(&evidence);
    let record = HostRecoveryPublicationRecordV5 {
        request: request.clone(),
        native_review_digest: "95".repeat(32),
        admission_id: "96".repeat(32),
    };
    require_exact_admission(
        &record,
        &request,
        &record.native_review_digest,
        &record.admission_id,
    )
    .unwrap();
    for field in 0..5 {
        let mut changed = record.clone();
        match field {
            0 => changed.native_review_digest = "98".repeat(32),
            1 => changed.admission_id = "98".repeat(32),
            2 => changed.request.continuity.inventory_digest = "98".repeat(32),
            3 => changed.request.target_profile = PathBuf::from("/synthetic/other-profile"),
            _ => changed.request.generation_manifest_digest = "98".repeat(32),
        }
        assert!(
            require_exact_admission(
                &changed,
                &request,
                &record.native_review_digest,
                &record.admission_id
            )
            .is_err()
        );
    }
    // Serde round trips preserve audit data only. No admission constructor is used.
    let bytes = serde_json::to_vec(&record).unwrap();
    let decoded: HostRecoveryPublicationRecordV5 = serde_json::from_slice(&bytes).unwrap();
    assert!(decoded == record);
}

#[test]
fn publication_v5_rejects_version_approval_flags_and_ambiguous_paths() {
    let request = request(&fixture::fixture());
    for key in [
        "approved",
        "activate_writer",
        "clear_exposure",
        "native_decision",
    ] {
        let mut value = serde_json::to_value(&request).unwrap();
        value[key] = true.into();
        assert!(serde_json::from_value::<HostRecoveryPublicationRequestV5>(value).is_err());
    }
    for version in [1, 2, 3, 4, 6] {
        let mut changed = request.clone();
        changed.schema_version = version;
        assert!(changed.validate().is_err());
        let mut changed = request.clone();
        changed.continuity.schema_version = version;
        assert!(changed.validate().is_err());
    }
    for target in [
        "relative",
        "/",
        "/synthetic/../target",
        "/synthetic//target",
        "/synthetic/target/",
        "/synthetic/\u{202e}target",
    ] {
        let mut changed = request.clone();
        changed.target_profile = target.into();
        assert!(changed.validate().is_err());
    }
}

#[test]
fn publication_v5_keeps_wire_budget_deadline_and_activation_denial() {
    use crate::authority_bridge::host_recovery_ipc::v5::{
        require_construction_transport_recovery_endpoint, require_wire_capacity,
    };
    let evidence = fixture::fixture();
    evidence
        .require_unchanged(&evidence, Duration::from_secs(29))
        .unwrap();
    assert!(
        evidence
            .require_unchanged(&evidence, Duration::from_secs(30))
            .is_err()
    );
    assert!(require_construction_transport_recovery_endpoint().is_err());
    assert!(
        evidence
            .complete_history
            .require_financial_activation_supported()
            .is_err()
    );
    let encoded = serde_json::to_vec(&evidence).unwrap().len();
    let publication_request_bytes = serde_json::to_vec(&request(&evidence)).unwrap().len();
    println!(
        "synthetic V5 complete evidence bytes={encoded}; publication request bytes={publication_request_bytes}; unchanged IPC cap={}",
        128 * 1024
    );
    // Full provenance is retained even when this synthetic envelope does not fit.
    if encoded > 128 * 1024 {
        assert!(require_wire_capacity(&evidence).is_err());
    }
    // The JSON quotes occupy two bytes; capacity is the unchanged IPC ceiling.
    require_wire_capacity(&"a".repeat(128 * 1024 - 2)).unwrap();
    assert!(require_wire_capacity(&"a".repeat(128 * 1024 - 1)).is_err());
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginalSessionShapeV5 {
    request: HostRecoveryContinuityRequestV5,
    writer_certificate_digest: String,
    writer_session_id: String,
    writer_session_expires_at_ms: u64,
    head: wholepact_authority::AuthorityHead,
    history_digest: String,
    complete_history: crate::authority_bridge::host_recovery_ipc::v5::HostRecoveryHistoryV5,
}

#[test]
fn publication_v5_some_historical_session_preserves_original_exact_wire_bytes() {
    let evidence = fixture::fixture();
    let original = OriginalSessionShapeV5 {
        request: evidence.request.clone(),
        writer_certificate_digest: evidence.writer_certificate_digest.clone(),
        writer_session_id: evidence.writer_session_id.clone().unwrap(),
        writer_session_expires_at_ms: evidence.writer_session_expires_at_ms.unwrap(),
        head: evidence.head.clone(),
        history_digest: evidence.history_digest.clone(),
        complete_history: evidence.complete_history.clone(),
    };
    assert_eq!(
        serde_json::to_vec(&evidence).unwrap(),
        serde_json::to_vec(&original).unwrap()
    );
    let decoded: HostRecoveryContinuityEvidenceV5 =
        serde_json::from_slice(&serde_json::to_vec(&original).unwrap()).unwrap();
    assert!(decoded == evidence);
}

#[test]
fn publication_v5_inactive_snapshot_is_informational_and_keeps_every_fence() {
    let original = fixture::fixture();
    let retained = serde_json::to_vec(&original.complete_history.construction.transport).unwrap();
    let debit = original
        .complete_history
        .conservative_debit_zatoshis()
        .unwrap();
    for status in ["paused", "revoked", "quarantined", "active"] {
        // Model an inert later historical snapshot only. This is not an
        // authenticated replay, owner factory, live pause or native approval.
        let mut value = serde_json::to_value(&original).unwrap();
        let snapshot =
            &mut value["complete_history"]["construction"]["original"]["observed_snapshot"];
        snapshot["writer_status"] = status.into();
        snapshot["active_writer_session"] = serde_json::Value::Null;
        snapshot["pending_writer_session"] = serde_json::Value::Null;
        snapshot["head"]["sequence"] = (original.head.sequence + 1).into();
        snapshot["head"]["digest"] = "bc".repeat(32).into();
        let head = snapshot["head"].clone();
        value["head"] = head;
        value["history_digest"] = "bd".repeat(32).into();
        value["complete_history"]["construction"]["original"]["complete_replay_digest"] =
            "bd".repeat(32).into();
        value["writer_session_id"] = serde_json::Value::Null;
        value["writer_session_expires_at_ms"] = serde_json::Value::Null;
        let evidence: HostRecoveryContinuityEvidenceV5 =
            serde_json::from_value(value.clone()).unwrap();
        evidence.validate().unwrap();
        request(&evidence).matches_evidence(&evidence).unwrap();
        assert!(evidence.writer_session_id.is_none());
        assert!(evidence.writer_session_expires_at_ms.is_none());
        assert_eq!(
            retained,
            serde_json::to_vec(&evidence.complete_history.construction.transport).unwrap()
        );
        assert_eq!(
            debit,
            evidence
                .complete_history
                .conservative_debit_zatoshis()
                .unwrap()
        );
        assert!(
            evidence
                .complete_history
                .require_financial_activation_supported()
                .is_err()
        );
        // A pre-extension strict V5 reader and every V4 reader refuse this
        // absence, rather than silently manufacturing an active session.
        assert!(serde_json::from_value::<OriginalSessionShapeV5>(value.clone()).is_err());
        assert!(
            serde_json::from_value::<
                crate::authority_bridge::host_recovery_ipc::v4::HostRecoveryContinuityEvidenceV4,
            >(value.clone())
            .is_err()
        );
        for field in ["writer_session_id", "writer_session_expires_at_ms"] {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<HostRecoveryContinuityEvidenceV5>(missing).is_err());
            let mut one_sided = value.clone();
            one_sided[field] = serde_json::to_value(&original).unwrap()[field].clone();
            assert!(
                serde_json::from_value::<HostRecoveryContinuityEvidenceV5>(one_sided)
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
    }
    let mut mismatch = original.clone();
    mismatch.writer_session_id = None;
    mismatch.writer_session_expires_at_ms = None;
    assert!(mismatch.validate().is_err());
}

#[test]
fn bounded_publication_reconstructs_full_transport_history_before_prepared_confirmation() {
    use crate::authority_bridge::host_recovery_ipc::v5::transfer::{
        TransferMetadata, TransferSender, encode_frame,
    };
    let evidence = fixture::fixture();
    let request = request(&evidence);
    let original = serde_json::to_vec(&evidence).unwrap();
    assert!(original.len() > 128 * 1024);
    let mut sender = TransferSender::new(
        TransferMetadata {
            purpose: TransferPurpose::Publication,
            transfer_id: "80".repeat(32),
            lease_id: "81".repeat(32),
            request_digest: request.digest().unwrap(),
            native_review_digest: "82".repeat(32),
            evidence_digest: evidence.digest().unwrap(),
            head_digest: evidence.head.digest.clone(),
            head_sequence: evidence.head.sequence,
        },
        &evidence,
    )
    .unwrap();
    let header = sender.begin().unwrap();
    let mut collector =
        TransferCollector::new(TransferPurpose::Publication, request.digest().unwrap()).unwrap();
    collector.begin(header.clone()).unwrap();
    for _ in 0..header.chunk_count {
        let next = collector.next_request().unwrap();
        let chunk = sender.next(&next).unwrap();
        let frame = TransferResponseV1::Chunk { chunk };
        let encoded = encode_frame(&frame).unwrap();
        assert!(encoded.len() < 128 * 1024);
        let TransferResponseV1::Chunk { chunk } = decode_frame(&encoded).unwrap() else {
            panic!("chunk required")
        };
        collector.accept_chunk(chunk).unwrap();
    }
    let mut complete = collector.finish().unwrap();
    assert_eq!(complete.bytes(), original);
    let restored: HostRecoveryContinuityEvidenceV5 =
        serde_json::from_slice(complete.bytes()).unwrap();
    require_transferred_publication_evidence(&request, &header, &restored).unwrap();
    assert!(restored == evidence);
    let accepted = complete
        .accept_complete(&restored.digest().unwrap())
        .unwrap();
    sender.accept_complete(&accepted).unwrap();
    complete
        .require_confirmation(&sender.confirmation().unwrap())
        .unwrap();
    // Completion is inert data. This fixture issues no native decision or admission.
    assert!(require_construction_transport_recovery_endpoint().is_err());
    eprintln!(
        "bounded publication evidence_bytes={} chunks={}",
        original.len(),
        header.chunk_count
    );
}

#[test]
fn bounded_publication_rejects_cross_purpose_request_and_snapshot_substitution() {
    use crate::authority_bridge::host_recovery_ipc::v5::transfer::{
        TransferMetadata, TransferSender,
    };
    let evidence = fixture::fixture();
    let request = request(&evidence);
    let sender = TransferSender::new(
        TransferMetadata {
            purpose: TransferPurpose::Publication,
            transfer_id: "80".repeat(32),
            lease_id: "81".repeat(32),
            request_digest: request.digest().unwrap(),
            native_review_digest: "82".repeat(32),
            evidence_digest: evidence.digest().unwrap(),
            head_digest: evidence.head.digest.clone(),
            head_sequence: evidence.head.sequence,
        },
        &evidence,
    )
    .unwrap();
    for changed_field in 0..5 {
        let mut header = sender.header().clone();
        match changed_field {
            0 => header.purpose = TransferPurpose::Continuity,
            1 => header.request_digest = "83".repeat(32),
            2 => header.evidence_digest = "83".repeat(32),
            3 => header.head_digest = "83".repeat(32),
            _ => header.head_sequence += 1,
        }
        assert!(require_transferred_publication_evidence(&request, &header, &evidence).is_err());
    }
}

#[test]
fn publication_v5_post_transfer_envelopes_refuse_unknown_fields_without_wire_change() {
    assert_eq!(
        serde_json::to_string(&HostPublicationResponseV5::Finished {}).unwrap(),
        r#"{"status":"finished"}"#
    );
    assert_eq!(
        serde_json::to_string(&HostPublicationResponseV5::Denied {}).unwrap(),
        r#"{"status":"denied"}"#
    );
    assert_eq!(
        serde_json::to_string(&HostPublicationCommandV5::Finish {}).unwrap(),
        r#"{"operation":"finish"}"#
    );
    for wire in [
        br#"{"status":"finished","approved":true}"#.as_slice(),
        br#"{"status":"denied","approved":true}"#.as_slice(),
    ] {
        assert!(decode_frame::<HostPublicationResponseV5>(wire).is_err());
    }
    assert!(
        decode_frame::<HostPublicationCommandV5>(br#"{"operation":"finish","approved":true}"#)
            .is_err()
    );
}
