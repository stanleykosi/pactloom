//! Table-aware loader/capture policy tests. These raw in-memory rows are not
//! authenticated generations and cannot provide recovery or native authority.
use super::*;

const SCOPE_ERROR: &str = "private input projection material is outside export or recovery scope";
const PRIVATE: &str = r#"{"durable_input_projections_v\u0031":{"selected":"SYNTHETIC-PRIVATE"},"durable_input_projections_v1":{}}"#;

fn refuse<T>(result: Result<T>) {
    assert!(matches!(result, Err(StoreError::InvalidInput(SCOPE_ERROR))));
}

fn cells(table: &Table, payload: &str) -> Vec<Value> {
    let mut cells = vec![Value::Null; table.columns.split(',').count()];
    cells[private_input_projection_column(table.name).unwrap()] = Value::String(payload.into());
    cells
}

fn header(table: &str, payload: &str) -> Layer {
    let provenance = RecoveryProvenance {
        profile_id: "synthetic-profile".into(),
        checkpoint_id: "synthetic-checkpoint".into(),
        bundle_digest: "a".repeat(64),
        component_id: "coordination".into(),
        kind: JournalKind::CoordinationAuthority,
        component_digest: "b".repeat(64),
        application_id: 0,
        schema_version: SCHEMA_VERSION,
        rows: 1,
    };
    Layer {
        version: 2,
        ordinal: 1,
        parent_generation_id: "c".repeat(64),
        parent_inventory_digest: "d".repeat(64),
        parent_provenance: provenance.clone(),
        parent_schema_version: coordination_successor_template().schema_version,
        parent_destination_identity: "e".repeat(64),
        destination_identity: "f".repeat(64),
        generation_id: "1".repeat(64),
        inventory_digest: "2".repeat(64),
        source_provenance: provenance,
        previous_layer_digest: None,
        tables: snapshot_tables(false)
            .into_iter()
            .map(|descriptor| {
                (
                    descriptor.name.into(),
                    usize::from(descriptor.name == table),
                )
            })
            .collect(),
        rows: 1,
        bytes: payload.len(),
    }
}

#[test]
fn snapshot_rows_scan_four_base_cells_and_original_wrappers_only_one_level() {
    for table in BASE
        .iter()
        .filter(|table| private_input_projection_column(table.name).is_some())
    {
        let private = cells(table, PRIVATE);
        refuse(validate_snapshot_row_without_private_input_projections(
            table.name, &private,
        ));
        let wrapper = vec![
            Value::String(table.name.into()),
            serde_json::json!(0),
            Value::String(serde_json::to_string(&private).unwrap()),
        ];
        refuse(validate_snapshot_row_without_private_input_projections(
            ORIGINALS.name,
            &wrapper,
        ));
        for harmless in [
            r#"{"durable_input_projections_v1":{},"durable_construction_v1":{"retained":true}}"#,
            r#"{"opaque":"{\"durable_input_projections_v1\":{\"retained\":true}}"}"#,
        ] {
            let harmless = cells(table, harmless);
            validate_snapshot_row_without_private_input_projections(table.name, &harmless).unwrap();
            let wrapper = vec![
                Value::String(table.name.into()),
                serde_json::json!(0),
                Value::String(serde_json::to_string(&harmless).unwrap()),
            ];
            validate_snapshot_row_without_private_input_projections(ORIGINALS.name, &wrapper)
                .unwrap();
        }
    }
    let recursive = vec![
        Value::String(ORIGINALS.name.into()),
        serde_json::json!(0),
        Value::String("[]".into()),
    ];
    assert!(
        validate_snapshot_row_without_private_input_projections(ORIGINALS.name, &recursive)
            .is_err()
    );
    assert!(!snapshot_tables(true).iter().any(|table| matches!(
        table.name,
        "store_generation_layers" | "store_generation_layer_rows"
    )));
}

#[test]
fn layer_loader_refuses_private_base_and_nested_original_cells_before_digest_projection() {
    for table in BASE
        .iter()
        .filter(|table| private_input_projection_column(table.name).is_some())
    {
        for wrapped in [false, true] {
            let c = Connection::open_in_memory().unwrap();
            c.execute_batch(coordination_layered_successor_template().create_sql)
                .unwrap();
            let base = cells(table, PRIVATE);
            let (name, cells) = if wrapped {
                (
                    ORIGINALS.name,
                    vec![
                        Value::String(table.name.into()),
                        serde_json::json!(0),
                        Value::String(serde_json::to_string(&base).unwrap()),
                    ],
                )
            } else {
                (table.name, base)
            };
            let payload = serde_json::to_string(&HistoricalRow { rowid: 1, cells }).unwrap();
            let header = header(name, &payload);
            c.execute(
                "INSERT INTO store_generation_layers VALUES(1,?1,?2)",
                params![serde_json::to_string(&header).unwrap(), "0".repeat(64)],
            )
            .unwrap();
            c.execute(
                "INSERT INTO store_generation_layer_rows VALUES(1,?1,0,?2)",
                params![name, payload],
            )
            .unwrap();
            refuse(load_layer_rows(&c, &header));
        }
    }
}

#[test]
fn capture_refuses_private_originals_when_all_current_columns_are_harmless() {
    for table in BASE
        .iter()
        .filter(|table| private_input_projection_column(table.name).is_some())
    {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(coordination_successor_template().create_sql)
            .unwrap();
        crate::backup::validate_no_private_input_projections(&c).unwrap();
        capture(&c).unwrap();
        let encoded = serde_json::to_string(&cells(table, PRIVATE)).unwrap();
        c.execute(
            "INSERT INTO store_generation_original_rows VALUES(?1,0,?2)",
            params![table.name, encoded],
        )
        .unwrap();
        crate::backup::validate_no_private_input_projections(&c).unwrap();
        refuse(read_rows(&c, &ORIGINALS, ""));
        refuse(capture(&c));
        let unchanged: String = c
            .query_row(
                "SELECT payload FROM store_generation_original_rows",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(unchanged, encoded);
    }
}
