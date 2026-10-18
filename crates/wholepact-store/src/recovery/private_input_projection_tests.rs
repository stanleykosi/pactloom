//! Raw policy regression tests only. None of these synthetic cells creates
//! authenticated recovery provenance or native disclosure authority.
use super::*;

const SCOPE_ERROR: &str = "private input projection material is outside export or recovery scope";
const COLUMNS: [(&str, usize, usize); 4] = [
    ("records", 3, 6),
    ("operations", 5, 8),
    ("idempotency", 3, 4),
    ("events", 5, 8),
];

fn private_payloads() -> Vec<String> {
    vec![
        r#"{"durable_input_projections_v1":{"round":"SYNTHETIC-PRIVATE"}}"#.into(),
        r#"{"durable_input_projections_v\u0031":{"round":"SYNTHETIC-PRIVATE"}}"#.into(),
        r#"{"durable_input_projections_v1":{"round":"SYNTHETIC-PRIVATE"},"durable_input_projections_v\u0031":{}}"#.into(),
        r#"{"nested":{"durable_input_projections_v1":null}}"#.into(),
        r#"{"nested":{"key":1,"k\u0065y":2}}"#.into(),
        r#"{"durable_input_projections_v1":{}} trailing"#.into(),
    ]
}

fn refuse<T>(result: Result<T>) {
    assert!(matches!(result, Err(StoreError::InvalidInput(SCOPE_ERROR))));
}

#[test]
fn recovery_all_four_raw_cells_refuse_private_escaped_and_duplicate_keys() {
    for (table, column, width) in COLUMNS {
        for payload in private_payloads() {
            let mut cells = (0..width).map(|_| RecoveryCell::Null).collect::<Vec<_>>();
            cells[column] = RecoveryCell::Text(payload.clone());
            refuse(validate_no_private_input_projection_cells(table, &cells));
            let mut originals = vec![Value::Null; width];
            originals[column] = Value::String(payload);
            let encoded = serde_json::to_string(&originals).unwrap();
            // The outer SQL-cell array contains only strings and nulls. The
            // refusal must inspect the JSON string at the actual table offset.
            refuse(original_cells_without_private_input_projections(
                table, &encoded,
            ));
        }
    }
}

#[test]
fn recovery_raw_policy_preserves_construction_empty_and_opaque_strings() {
    for (table, column, width) in COLUMNS {
        for payload in [
            r#"{"durable_construction_v1":{"old":"retained"},"durable_input_projections_v1":{}}"#,
            r#"{"durable_input_projections_v\u0031":{}}"#,
            r#"{"opaque":"{\"durable_input_projections_v1\":{\"not-json-data\":true}}"}"#,
            r#"{"id":"minimal-event","revision":1}"#,
        ] {
            let mut cells = vec![Value::Null; width];
            cells[column] = Value::String(payload.into());
            // A different ordinary SQL string must never become JSON input.
            cells[0] = Value::String(private_payloads().remove(0));
            let encoded = serde_json::to_string(&cells).unwrap();
            let decoded =
                original_cells_without_private_input_projections(table, &encoded).unwrap();
            assert!(decoded == cells);
            assert!(serde_json::to_string(&decoded).unwrap() == encoded);
        }
    }
    let encoded =
        serde_json::to_string(&vec![Value::String(private_payloads().remove(0))]).unwrap();
    original_cells_without_private_input_projections("authority_events", &encoded).unwrap();
}

#[test]
fn recovery_inventory_scans_every_raw_row_before_first_record_projection() {
    let provenance = RecoveryProvenance {
        profile_id: "synthetic-profile".into(),
        checkpoint_id: "synthetic-checkpoint".into(),
        bundle_digest: "a".repeat(64),
        component_id: "coordination".into(),
        kind: JournalKind::CoordinationAuthority,
        component_digest: "b".repeat(64),
        application_id: 0,
        schema_version: SCHEMA_VERSION,
        rows: 2,
    };
    // This first row would fail aggregate decoding, not the privacy scanner.
    let earlier = vec![
        RecoveryCell::Text("unknown-aggregate".into()),
        RecoveryCell::Null,
        RecoveryCell::Null,
        RecoveryCell::Text("{}".into()),
    ];
    for (table, column, width) in COLUMNS {
        let mut later = (0..width).map(|_| RecoveryCell::Null).collect::<Vec<_>>();
        later[column] = RecoveryCell::Text(private_payloads().remove(0));
        refuse(StoreRecoveryInventory::inspect_rows(
            &provenance,
            [("records", earlier.as_slice()), (table, later.as_slice())],
            false,
        ));
    }
}

fn workspace_marker_payloads() -> [&'static str; 6] {
    [
        r#"{"private_workspace_origin_v1":{}}"#,
        r#"{"private_workspace_origin_v1":null}"#,
        r#"{"private_workspace_origin_v\u0031":{}}"#,
        r#"{"private_workspace_origin_v1":{},"private_workspace_origin_v\u0031":null}"#,
        r#"{"nested":[{"private_workspace_origin_v1":{}}]}"#,
        r#"{"record":{"payload":{}},"unknown":{"private_workspace_origin_v1":null}}"#,
    ]
}

#[test]
fn workspace_marker_scans_exact_current_and_original_cells_without_string_recursion() {
    for (table, column, width) in COLUMNS {
        for payload in workspace_marker_payloads() {
            let mut cells = (0..width).map(|_| RecoveryCell::Null).collect::<Vec<_>>();
            cells[column] = RecoveryCell::Text(payload.into());
            refuse(validate_no_private_input_projection_cells(table, &cells));
            let mut originals = vec![Value::Null; width];
            originals[column] = Value::String(payload.into());
            let encoded = serde_json::to_string(&originals).unwrap();
            refuse(original_cells_without_private_input_projections(
                table, &encoded,
            ));
        }
        let mut harmless = vec![Value::Null; width];
        harmless[0] = Value::String(workspace_marker_payloads()[0].into());
        harmless[column] = Value::String(
            r#"{"durable_input_projections_v1":{},"opaque":"{\"private_workspace_origin_v1\":null}"}"#.into(),
        );
        let encoded = serde_json::to_string(&harmless).unwrap();
        assert!(
            original_cells_without_private_input_projections(table, &encoded).unwrap() == harmless
        );
    }
}

#[test]
fn workspace_marker_inventory_prepass_precedes_any_earlier_record_projection() {
    let provenance = RecoveryProvenance {
        profile_id: "synthetic-profile".into(),
        checkpoint_id: "synthetic-checkpoint".into(),
        bundle_digest: "a".repeat(64),
        component_id: "coordination".into(),
        kind: JournalKind::CoordinationAuthority,
        component_digest: "b".repeat(64),
        application_id: 0,
        schema_version: SCHEMA_VERSION,
        rows: 2,
    };
    let earlier = vec![
        RecoveryCell::Text("unknown-aggregate".into()),
        RecoveryCell::Null,
        RecoveryCell::Null,
        RecoveryCell::Text("{}".into()),
    ];
    for (table, column, width) in COLUMNS {
        for payload in workspace_marker_payloads() {
            let mut later = (0..width).map(|_| RecoveryCell::Null).collect::<Vec<_>>();
            later[column] = RecoveryCell::Text(payload.into());
            refuse(StoreRecoveryInventory::inspect_rows(
                &provenance,
                [("records", earlier.as_slice()), (table, later.as_slice())],
                false,
            ));
        }
    }
}
