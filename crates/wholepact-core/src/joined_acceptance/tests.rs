//! Synthetic strings only. No keys, receipts, cryptography, native authority,
//! proving, socket, provider, journal or financial action is constructed.
use super::*;

fn fixture(originals: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema_version": 1, "route": "ordinary_two_owner", "network": "testnet",
        "dispatch": "disabled", "originals": originals,
    }))
    .unwrap()
}
fn empty() -> Config {
    parse_config(&fixture(serde_json::json!({}))).unwrap()
}
fn synthetic_full() -> Config {
    let mut config = empty();
    for (index, reference) in REFERENCES.iter().enumerate() {
        let value = match reference.kind {
            Kind::Id => format!("synthetic-only-{}", reference.name),
            Kind::Digest => format!("{index:064x}"),
            Kind::MessageId => format!("{index:032x}"),
            Kind::Sequence => "1".into(),
            Kind::Time => {
                if reference.name.ends_with("transport_expires_at") {
                    "2026-10-16T01:00:00Z".into()
                } else {
                    "2026-10-16T00:00:00Z".into()
                }
            }
            Kind::Revision => "7".into(),
            Kind::Height => "123456".into(),
        };
        config.originals.insert(reference.name.into(), value);
    }
    parse_config(&serde_json::to_vec(&config).unwrap()).unwrap()
}

#[test]
fn empty_config_emits_pending_manual_native_steps() {
    let report = plan(&empty());
    assert_eq!(report.stages.len(), 13);
    assert_eq!(report.original_reference_count, 0);
    assert!(!report.execution_enabled && !report.dispatch_enabled);
    assert_eq!(report.runtime_qualification, "not_run");
    assert_eq!(report.product_acceptance, "not_established");
    assert!(report
        .stages
        .iter()
        .all(|s| s.status.starts_with("pending") || s.status.starts_with("disabled")));
}
#[test]
fn complete_synthetic_metadata_never_simulates_runtime_success() {
    let report = plan(&synthetic_full());
    assert!(report.stages.iter().all(|s| s.missing_originals.is_empty()));
    assert!(report
        .stages
        .iter()
        .all(|s| s.status == "pending_native_step"
            || s.status == "disabled_separate_authorization_required"));
    assert_eq!(report.product_acceptance, "not_established");
    assert_eq!(report.runtime_qualification, "not_run");
    assert!(!report.execution_enabled && !report.dispatch_enabled);
}
#[test]
fn duplicate_keys_unknown_fields_and_approval_flags_are_rejected() {
    for addition in [
        "\"schema_version\":1",
        "\"approved\":true",
        "\"peer_fvk_accepted\":true",
        "\"secret\":\"do-not-echo\"",
    ] {
        let original = String::from_utf8(fixture(serde_json::json!({}))).unwrap();
        let source = format!("{{{addition},{}", &original[1..]);
        assert!(matches!(
            parse_config(source.as_bytes()),
            Err(PlanError::InvalidConfig)
        ));
    }
    let source = br#"{"schema_version":1,"route":"ordinary_two_owner","network":"testnet","dispatch":"disabled","originals":{"job_id":"a","job_id":"b"}}"#;
    assert!(parse_config(source).is_err());
}
#[test]
fn dispatch_mainnet_recovered_and_wrong_schema_are_rejected() {
    for (key, value) in [
        ("dispatch", serde_json::json!("enabled")),
        ("dispatch", serde_json::json!(true)),
        ("network", serde_json::json!("mainnet")),
        ("route", serde_json::json!("recovered")),
        ("schema_version", serde_json::json!(2)),
    ] {
        let mut config: serde_json::Value =
            serde_json::from_slice(&fixture(serde_json::json!({}))).unwrap();
        config[key] = value;
        assert!(matches!(
            parse_config(&serde_json::to_vec(&config).unwrap()),
            Err(PlanError::InvalidConfig)
        ));
    }
}
#[test]
fn metadata_size_and_depth_are_bounded() {
    assert!(matches!(
        parse_config(&vec![b' '; MAX_CONFIG_BYTES + 1]),
        Err(PlanError::InvalidConfig)
    ));
    let deep = format!("{}0{}", "[".repeat(34), "]".repeat(34));
    assert!(parse_config(deep.as_bytes()).is_err());
}
#[test]
fn malformed_original_references_are_rejected_without_echoing_values() {
    for (key, value) in [
        ("unknown", "secret"),
        ("job_id", ""),
        ("job_id", "a\nb"),
        ("job_id", "/tmp/secret"),
        ("manifest_digest", "not-a-digest"),
        ("construction_revision", "1.0"),
        ("construction_revision", "01"),
        ("transaction_expiry_height", "0"),
        ("transaction_expiry_height", "4294967296"),
    ] {
        let error = parse_config(&fixture(serde_json::json!({key: value})))
            .err()
            .unwrap();
        assert_eq!(error, PlanError::InvalidReference);
        assert!(!error.to_string().contains(value) || value.is_empty());
    }
    let invalid = fixture(serde_json::json!({"job_id": "x".repeat(129)}));
    assert!(parse_config(&invalid).is_err());
    assert!(parse_config(&fixture(
        serde_json::json!({"construction_revision": u64::MAX.to_string()})
    ))
    .is_ok());
}
#[test]
fn duplicated_owner_slots_do_not_establish_two_owners() {
    for field in [
        "account_id",
        "participant_id",
        "authorization_id",
        "record_id",
    ] {
        let originals = serde_json::json!({format!("owner_a.{field}"): "synthetic-same", format!("owner_b.{field}"): "synthetic-same"});
        assert!(matches!(
            parse_config(&fixture(originals)),
            Err(PlanError::DuplicateOwner)
        ));
    }
}
#[test]
fn missing_inputs_remain_pending_and_all_stage_bindings_are_known() {
    let config = parse_config(&fixture(
        serde_json::json!({"job_id":"synthetic-original-job"}),
    ))
    .unwrap();
    let report = plan(&config);
    for stage in &report.stages {
        for name in stage.consumes.iter().chain(stage.capture) {
            assert!(REFERENCES.iter().any(|r| &r.name == name));
        }
    }
    let proof = report.stages.iter().find(|s| s.name == "proof").unwrap();
    assert!(!proof.missing_originals.contains(&"job_id"));
    assert!(proof.missing_originals.contains(&"candidate_id"));
}
#[test]
fn joined_stages_share_original_job_candidate_artifact_and_owner_inputs() {
    let report = plan(&empty());
    for name in [
        "proof",
        "proved_disclosure",
        "signature_intake",
        "transaction_checkpoint",
        "dispatch",
    ] {
        let stage = report.stages.iter().find(|s| s.name == name).unwrap();
        assert!(stage.consumes.contains(&"candidate_id"));
        assert!(stage.consumes.contains(&"job_id"));
    }
    for name in [
        "proved_disclosure",
        "owner_a_authorization",
        "owner_b_authorization",
        "signature_intake",
    ] {
        assert!(report
            .stages
            .iter()
            .find(|s| s.name == name)
            .unwrap()
            .consumes
            .contains(&"proved_artifact_digest"));
    }
    for name in [
        "authorization_transport",
        "signature_intake",
        "dispatch",
        "positive_resolution",
    ] {
        let stage = report.stages.iter().find(|s| s.name == name).unwrap();
        assert!(stage.consumes.contains(&"owner_a.authorization_id"));
        assert!(stage.consumes.contains(&"owner_b.authorization_id"));
    }
}
#[test]
fn prior_originals_allow_only_additive_capture() {
    let mut original = empty();
    original
        .originals
        .insert("job_id".into(), "synthetic-original-job".into());
    let mut added = original.clone();
    added
        .originals
        .insert("candidate_id".into(), "synthetic-original-candidate".into());
    assert!(preserve_originals(&original, &original).is_ok());
    assert!(preserve_originals(&original, &added).is_ok());
    assert_eq!(
        preserve_originals(&added, &original),
        Err(PlanError::ChangedOriginal)
    );
}
#[test]
fn prior_original_keys_owner_bindings_and_expiry_cannot_be_replaced() {
    let original = synthetic_full();
    for name in [
        "construction_key",
        "job_id",
        "owner_a.authorization_id",
        "owner_a.enrollment_ref",
        "transaction_expiry_height",
        "submission_operation_id",
        "owner_a.record_revision",
        "owner_b.record_revision",
        "owner_a.transport_expires_at",
        "owner_b.transport_message_id",
    ] {
        let mut modified = original.clone();
        modified.originals.insert(name.into(), "replacement".into());
        assert_eq!(
            preserve_originals(&original, &modified),
            Err(PlanError::ChangedOriginal)
        );
    }
}
#[test]
fn reports_contain_reference_names_but_never_private_transcribed_values() {
    let output = serde_json::to_string(&plan(&synthetic_full())).unwrap();
    assert!(!output.contains("synthetic-only-"));
    assert!(!output.contains("123456"));
    assert!(output.contains("untrusted_metadata_never_authority_or_completion"));
}

#[test]
fn every_history_dependent_stage_requires_both_complete_original_histories() {
    let mut config = synthetic_full();
    for name in [
        "owner_a.enrollment_ref",
        "owner_a.accepted_manifest_ref",
        "owner_b.enrollment_ref",
        "owner_b.accepted_manifest_ref",
    ] {
        config.originals.remove(name);
    }
    let report = plan(&config);
    for name in [
        "authorization_transport",
        "signature_intake",
        "transaction_checkpoint",
        "dispatch",
        "participant_records",
        "positive_resolution",
    ] {
        let stage = report.stages.iter().find(|s| s.name == name).unwrap();
        for missing in [
            "owner_a.enrollment_ref",
            "owner_a.accepted_manifest_ref",
            "owner_b.enrollment_ref",
            "owner_b.accepted_manifest_ref",
        ] {
            assert!(stage.missing_originals.contains(&missing));
        }
    }
}
#[test]
fn original_transport_order_and_deadline_shapes_fail_closed() {
    for (key, value) in [
        ("owner_a.transport_sequence", "0"),
        ("owner_a.transport_sequence", "9223372036854775808"),
        ("owner_a.transport_message_id", "a"),
        ("owner_a.transport_issued_at", "2026-02-30T00:00:00Z"),
        ("owner_a.transport_expires_at", "1969-12-31T23:59:59Z"),
    ] {
        assert!(parse_config(&fixture(serde_json::json!({key:value}))).is_err());
    }
    for end in ["2026-10-15T23:59:59Z", "2026-10-16T00:00:00Z"] {
        assert!(parse_config(&fixture(serde_json::json!({"owner_a.transport_issued_at":"2026-10-16T00:00:00Z", "owner_a.transport_expires_at":end}))).is_err());
    }
}
