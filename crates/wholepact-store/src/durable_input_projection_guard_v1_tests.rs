//! Storage-only synthetic metadata, no native disclosure or authority claims.
use super::*;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use wholepact_storage_security::DatabaseKey;

fn directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}
fn payload(store: &Store, path: &Path) -> Value {
    let origin = hex::encode(store.verify_original_encrypted_destination(path).unwrap());
    let a = json!({"intent": {"account_id": "synthetic-a", "protected_destination": path}});
    let b = json!({"intent": {"account_id": "synthetic-b", "protected_destination": path}});
    json!({"durable_input_projections_v1": {"synthetic-round": {
        "metadata_origin": origin,
        "requests": {"synthetic-a": a.clone(), "synthetic-b": b},
        "intakes": {"synthetic-a": {"outbox": {"request": a}}}
    }}})
}
fn check(store: &Store, payload: &Value) -> Result<()> {
    store.check_durable_projection_destination_v1(&store.connection.lock().unwrap(), payload)
}

#[test]
fn projection_destination_requires_actual_original_encrypted_file() {
    let dir = directory();
    let path = dir.path().join("projection.sqlite");
    let store = Store::create_encrypted(&path, &DatabaseKey::from_bytes([72; 32])).unwrap();
    let valid = payload(&store, &path);
    check(&store, &valid).unwrap();
    for mutation in 0..7 {
        let mut changed = valid.clone();
        let round = &mut changed["durable_input_projections_v1"]["synthetic-round"];
        match mutation {
            0 => round["metadata_origin"] = json!("00".repeat(32)),
            1 => {
                round["requests"]["synthetic-a"]["intent"]["protected_destination"] =
                    json!("relative.sqlite")
            }
            2 => round["requests"]["synthetic-a"]["intent"]["account_id"] = json!("synthetic-b"),
            3 => {
                round["requests"]
                    .as_object_mut()
                    .unwrap()
                    .remove("synthetic-b");
            }
            4 => round["intakes"]["foreign-account"] = json!({}),
            5 => round["intakes"]["synthetic-a"]["outbox"]["request"] = json!({}),
            _ => round["intakes"] = json!([]),
        }
        assert!(check(&store, &changed).is_err(), "mutation {mutation}");
    }
    let memory = Store::in_memory().unwrap();
    assert!(check(&memory, &valid).is_err());
    check(&memory, &json!({"durable_input_projections_v1": {}})).unwrap();
    check(&memory, &json!({"ordinary": "legacy"})).unwrap();
    for value in [json!(null), json!([]), json!(true), json!("wrong")] {
        assert!(check(&store, &json!({"durable_input_projections_v1": value})).is_err());
    }
}

#[test]
fn projection_destination_rejects_same_path_replacement_and_other_original() {
    let dir = directory();
    let path = dir.path().join("projection.sqlite");
    let other_path = dir.path().join("other.sqlite");
    let store = Store::create_encrypted(&path, &DatabaseKey::from_bytes([73; 32])).unwrap();
    let other = Store::create_encrypted(&other_path, &DatabaseKey::from_bytes([74; 32])).unwrap();
    let valid = payload(&store, &path);
    assert!(check(&other, &valid).is_err());
    std::fs::rename(&path, dir.path().join("preserved-original.sqlite")).unwrap();
    // Contents do not matter: the retained open original file identity must
    // reject a different inode at the exact approved path before any admission.
    std::fs::copy(&other_path, &path).unwrap();
    assert!(check(&store, &valid).is_err());
}
