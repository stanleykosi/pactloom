//! Pure synthetic data-codec tests. No Store, files, keys, native IPC or owners.
use super::*;
use serde_json::json;

fn marker() -> PrivateWorkspaceOriginV1 {
    PrivateWorkspaceOriginV1 {
        version: 1,
        purpose: PRIVATE_WORKSPACE_ORIGIN_PURPOSE_V1.into(),
        native_association_digest: "11".repeat(32),
        source_digest: "22".repeat(32),
        principal_id: "synthetic-constructor".into(),
        agreement_id: "synthetic-agreement".into(),
        obligation_id: "synthetic-obligation".into(),
        reviewer_account_ids: vec!["33".repeat(32), "44".repeat(32)],
        protected_destination: "/synthetic/private/workspace.sqlite".into(),
        retention_policy: "synthetic-exact-local-retention".into(),
        metadata_origin: "55".repeat(32),
    }
}

#[test]
fn marker_codec_has_exact_fields_and_fixed_canonical_domain() {
    let value = marker();
    value.validate().unwrap();
    let encoded = serde_json::to_string(&value).unwrap();
    assert!(PrivateWorkspaceOriginV1::from_json(&encoded).unwrap() == value);
    let object = serde_json::to_value(&value).unwrap();
    assert_eq!(object.as_object().unwrap().len(), 11);
    assert!(object.get("seed_digest").is_none());
    assert!(object.get("marker_digest").is_none());
    assert!(
        value.digest().unwrap()
            == wholepact_core::proposal::canonical_digest(
                PRIVATE_WORKSPACE_ORIGIN_DIGEST_DOMAIN_V1,
                &value,
            )
            .unwrap()
    );
    let reordered = serde_json::to_string_pretty(&object).unwrap();
    assert!(PrivateWorkspaceOriginV1::from_json(&reordered).unwrap() == value);
    assert!(
        PrivateWorkspaceOriginV1::from_json(&reordered)
            .unwrap()
            .digest()
            .unwrap()
            == value.digest().unwrap()
    );
}

#[test]
fn marker_codec_refuses_unknown_missing_wrong_typed_and_empty_fields() {
    let original = serde_json::to_value(marker()).unwrap();
    for field in original.as_object().unwrap().keys() {
        let mut missing = original.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(PrivateWorkspaceOriginV1::from_json(&missing.to_string()).is_err());
        let mut wrong = original.clone();
        wrong[field] = json!(null);
        assert!(PrivateWorkspaceOriginV1::from_json(&wrong.to_string()).is_err());
    }
    let mut unknown = original;
    unknown["permission"] = json!(true);
    assert!(PrivateWorkspaceOriginV1::from_json(&unknown.to_string()).is_err());
    for raw in ["null", "{}", "[]", "true", "1", "\"marker\""] {
        assert!(PrivateWorkspaceOriginV1::from_json(raw).is_err());
    }
}

#[test]
fn marker_codec_refuses_duplicate_escaped_trailing_and_unbounded_raw_json() {
    let original = serde_json::to_string(&marker()).unwrap();
    let prefix = original.strip_suffix('}').unwrap();
    for suffix in [r#", "version":1}"#, r#", "ver\u0073ion":1}"#] {
        assert!(PrivateWorkspaceOriginV1::from_json(&format!("{prefix}{suffix}")).is_err());
    }
    for raw in [
        format!("{original} {{}}"),
        original[..original.len() - 1].to_owned(),
        " ".repeat(MAX_PRIVATE_WORKSPACE_ORIGIN_JSON_BYTES + 1),
        format!("{}0{}", "[".repeat(33), "]".repeat(33)),
    ] {
        assert!(PrivateWorkspaceOriginV1::from_json(&raw).is_err());
    }
}

#[test]
fn marker_data_validation_rejects_noncanonical_roster_and_digests() {
    for field in [
        "native_association_digest",
        "source_digest",
        "metadata_origin",
    ] {
        for invalid in [
            "a".repeat(63),
            "A".repeat(64),
            "g".repeat(64),
            String::new(),
        ] {
            let mut value = serde_json::to_value(marker()).unwrap();
            value[field] = json!(invalid);
            assert!(PrivateWorkspaceOriginV1::from_json(&value.to_string()).is_err());
        }
    }
    for accounts in [
        vec![],
        vec!["33".repeat(32)],
        vec!["33".repeat(32), "44".repeat(32), "55".repeat(32)],
        vec!["33".repeat(32), "33".repeat(32)],
        vec!["44".repeat(32), "33".repeat(32)],
        vec!["synthetic-account-a".into(), "synthetic-account-b".into()],
        vec!["A".repeat(64), "b".repeat(64)],
    ] {
        let mut value = marker();
        value.reviewer_account_ids = accounts;
        assert!(value.validate().is_err());
    }
}

#[test]
fn marker_data_validation_bounds_labels_paths_retention_and_version() {
    for field in ["principal_id", "agreement_id", "obligation_id"] {
        for invalid in [
            String::new(),
            "x".repeat(257),
            "space label".into(),
            "x\n".into(),
        ] {
            let mut value = serde_json::to_value(marker()).unwrap();
            value[field] = json!(invalid);
            assert!(PrivateWorkspaceOriginV1::from_json(&value.to_string()).is_err());
        }
    }
    for invalid in [
        String::new(),
        "relative.sqlite".into(),
        format!("/{}", "x".repeat(4096)),
        "/x\n".into(),
    ] {
        let mut value = marker();
        value.protected_destination = invalid;
        assert!(value.validate().is_err());
    }
    for invalid in [String::new(), "x".repeat(1025), "x\n".into()] {
        let mut value = marker();
        value.retention_policy = invalid;
        assert!(value.validate().is_err());
    }
    for invalid in [0, 2, u16::MAX] {
        let mut value = marker();
        value.version = invalid;
        assert!(value.validate().is_err());
    }
    let mut value = marker();
    value.purpose = "ordinary-coordination".into();
    assert!(value.validate().is_err());
    let mut boundary = marker();
    boundary.principal_id = "p".repeat(256);
    boundary.agreement_id = "a".repeat(256);
    boundary.obligation_id = "o".repeat(256);
    boundary.protected_destination = format!("/{}", "p".repeat(4095));
    boundary.retention_policy = "r".repeat(1024);
    boundary.validate().unwrap();
    assert!(
        PrivateWorkspaceOriginV1::from_json(&serde_json::to_string(&boundary).unwrap()).is_ok()
    );
}

#[test]
fn marker_digest_covers_every_variable_field_without_asserting_provenance() {
    let original = marker();
    let digest = original.digest().unwrap();
    for index in 0..9 {
        let mut changed = original.clone();
        match index {
            0 => changed.native_association_digest = "66".repeat(32),
            1 => changed.source_digest = "66".repeat(32),
            2 => changed.principal_id.push_str("-other"),
            3 => changed.agreement_id.push_str("-other"),
            4 => changed.obligation_id.push_str("-other"),
            5 => changed.reviewer_account_ids[1] = "66".repeat(32),
            6 => changed.protected_destination.push_str("-other"),
            7 => changed.retention_policy.push_str("-other"),
            _ => changed.metadata_origin = "66".repeat(32),
        }
        assert!(changed.digest().unwrap() != digest);
    }
    // Validated synthetic claims still do not attest a file or native write.
    assert!(original.validate().is_ok());
}
