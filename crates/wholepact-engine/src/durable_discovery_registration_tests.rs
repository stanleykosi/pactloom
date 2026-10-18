//! Default/feature registration boundaries only. These tests neither admit a
//! native receipt nor qualify the private Host workspace's export contract.
use super::*;

fn original_record() -> StoredRecord {
    let engine = Engine::in_memory().unwrap();
    let access = Access {
        principal_id: "registration-owner".into(),
        include_owned_agreements: true,
        ..Access::default()
    };
    let mut draft: AgreementDraft = serde_json::from_str(include_str!(
        "../../wholepact-core/tests/fixtures/agreement.json"
    ))
    .unwrap();
    draft.agreement_id = "discovery-registration".into();
    draft.obligation_id = "discovery-registration-obligation".into();
    engine
        .create(&access, "discovery-registration-create", draft.clone())
        .unwrap();
    engine
        .store
        .get_agreement(&draft.agreement_id)
        .unwrap()
        .unwrap()
}

#[test]
fn empty_recognized_private_field_preserves_legacy_encoding() {
    let mut record = original_record();
    assert!(record.payload.get("durable_input_projections_v1").is_none());
    let original = encode(&decode(&record).unwrap()).unwrap();
    record.payload["durable_input_projections_v1"] = json!({});
    let decoded = decode(&record).unwrap();
    assert!(decoded.durable_input_projections_v1.is_empty());
    let encoded = encode(&decoded).unwrap();
    assert!(encoded.get("durable_input_projections_v1").is_none());
    assert_eq!(encoded, original);
}

#[test]
fn recognized_private_field_never_ignores_wrong_types_or_excess_rounds() {
    let original = original_record();
    for value in [json!(null), json!([]), json!(true), json!("private")] {
        let mut record = original.clone();
        record.payload["durable_input_projections_v1"] = value;
        assert_eq!(decode(&record).err().unwrap().code, "RECOVERY_REQUIRED");
    }
    let mut record = original;
    record.payload["durable_input_projections_v1"] =
        json!({"a": {}, "b": {}, "c": {}, "d": {}, "e": {}});
    assert_eq!(decode(&record).err().unwrap().code, "RECOVERY_REQUIRED");
}

#[test]
fn invalid_private_history_cannot_escape_through_historical_mutation() {
    let mut record = original_record();
    // Deliberately inert malformed history. A synthetic row is not an admitted
    // disclosure, and absence of current live state cannot authenticate it.
    record.payload["durable_input_projections_v1"] = json!({"private-round": {}});
    for replayed in [false, true] {
        let result = MutationResult {
            record: record.clone(),
            operation_id: "private-historical-operation".into(),
            event_sequence: 1,
            replayed,
        };
        assert_eq!(mutation(result).err().unwrap().code, "RECOVERY_REQUIRED");
    }
}

#[cfg(not(all(
    feature = "durable-proposal",
    feature = "manual-admission",
    target_os = "linux"
)))]
#[test]
fn unsupported_build_refuses_nonempty_recognized_history_before_projection() {
    let mut record = original_record();
    record.payload["durable_input_projections_v1"] = json!({"retained-round": {}});
    let error = decode(&record).err().unwrap();
    assert_eq!(error.code, "RECOVERY_REQUIRED");
    assert!(error.message.contains("compatible protected workspace"));
    assert!(!error.message.contains("retained-round"));
}

#[test]
fn compiler_registration_keeps_private_factories_and_native_activation_inaccessible() {
    // These structural assertions supplement actual Rust visibility. They are
    // not a runtime ownership/foreground-consent or native IPC qualification.
    let engine = include_str!("lib.rs");
    for module in [
        "durable_input_projections_v1",
        "durable_private_workspace_v1",
    ] {
        assert!(engine.contains(&format!("pub(crate) mod {module};")));
        assert!(!engine.contains(&format!("pub mod {module};")));
    }
    let facade = include_str!("durable_private_workspace_v1.rs");
    assert!(facade.contains("pub(crate) fn private_durable_workspace_source_v1"));
    assert!(!facade.contains("pub fn private_durable_workspace_source_v1"));
    let origin = include_str!("../../wholepact-signer-origin/src/lib.rs");
    let client = include_str!("../../wholepact-signer-origin/src/client.rs");
    assert!(origin.contains("pub use client::AuthenticatedDurableInputProjectionV1;"));
    assert!(client.contains("mod durable_input_projection_v1_client;"));
    for hidden in [
        "NativeInputProjectionClientV1",
        "NativeInputProjectionRedisclosureClientV1",
        "PendingInputProjectionPairV1",
        "PendingInputProjectionRedisclosurePairV1",
    ] {
        assert!(!origin.contains(hidden));
        assert!(!client.contains(hidden));
    }
}
