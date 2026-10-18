//! Bounded storage-only guards for retained private discovery metadata.
//! These checks establish destination correlation, never disclosure consent,
//! native provenance or spending authority. Seed-only workspace export privacy
//! still requires a separate first-write purpose boundary before activation.
use super::*;

const PROJECTION_KEY: &str = "durable_input_projections_v1";
// Record payloads retain their 1 MiB limit. IDs, timestamps, operation digest
// and fixed MutationResult fields require a separate bounded wrapper allowance.
const MAX_MUTATION_JSON_BYTES: usize = MAX_JSON_BYTES + 4096;
const MAX_CAPTURE_INTENTS: usize = 8;
const MAX_CAPTURE_INTENTS_PER_ACCOUNT: usize = 4;
const MAX_CAPTURE_INTENT_BYTES: usize = 128 * 1024;

pub(super) fn decode_record_payload(raw: &str) -> Result<Value> {
    wholepact_core::strict_json::parse_json_unique(raw.as_bytes())
        .map_err(|_| StoreError::RecoveryRequired)
}
pub(super) fn decode_mutation_value(raw: &str) -> Result<Value> {
    let value: Value = wholepact_core::strict_json::parse_typed_json_with_byte_limit(
        raw.as_bytes(),
        MAX_MUTATION_JSON_BYTES,
    )
    .map_err(|_| StoreError::RecoveryRequired)?;
    let payload = value
        .get("record")
        .and_then(|record| record.get("payload"))
        .ok_or(StoreError::RecoveryRequired)?;
    // Unknown wrapper fields cannot become an unguarded private-data route.
    // Raw duplicate rejection has already happened, and strings stay opaque.
    let mut wrapper = value.clone();
    wrapper["record"]["payload"] = Value::Null;
    crate::backup::validate_no_private_input_projections_json(&serde_json::to_string(&wrapper)?)?;
    // A wrapper allowance must not enlarge the embedded record limit.
    if serde_json::to_vec(payload)?.len() > MAX_JSON_BYTES {
        return Err(StoreError::RecoveryRequired);
    }
    Ok(value)
}

pub(super) fn decode_live_event(
    raw: &str,
    aggregate_type: &str,
    aggregate_id: &str,
    revision: i64,
) -> Result<Value> {
    // Every event kind rejects retained private metadata, including decoded
    // escaped names and nested keys, before any StoredEvent is constructed.
    crate::backup::validate_no_private_input_projections_json(raw)?;
    let payload = decode_record_payload(raw)?;
    if aggregate_type == "agreement" {
        let revision = u64::try_from(revision).map_err(|_| StoreError::RecoveryRequired)?;
        let object = payload.as_object().ok_or(StoreError::RecoveryRequired)?;
        if !object.is_empty()
            && (object.len() != 2
                || object.get("id").and_then(Value::as_str) != Some(aggregate_id)
                || object.get("revision").and_then(Value::as_u64) != Some(revision))
        {
            return Err(StoreError::RecoveryRequired);
        }
    }
    Ok(payload)
}

impl Store {
    // Both guards operate on the already-held connection. Never invoke a Store
    // getter, Engine, or consent callback here: those can relock or reenter.
    pub(super) fn check_private_record_destinations(
        &self,
        connection: &Connection,
        payload: &Value,
    ) -> Result<()> {
        self.check_durable_private_destination(connection, payload)?;
        self.check_durable_projection_destination_v1(connection, payload)
    }

    pub(crate) fn check_durable_projection_destination_v1(
        &self,
        connection: &Connection,
        payload: &Value,
    ) -> Result<()> {
        // Only the top-level reserved map has a destination-checked encoding.
        // Refuse hidden nonempty reserved maps elsewhere, without interpreting
        // arbitrary user string contents as JSON or changing legacy keys.
        let mut remainder = payload.clone();
        if let Some(object) = remainder.as_object_mut() {
            object.remove(PROJECTION_KEY);
        }
        crate::backup::validate_no_private_input_projections_json(&serde_json::to_string(
            &remainder,
        )?)?;
        let Some(value) = payload.get(PROJECTION_KEY) else {
            return Ok(());
        };
        let rounds = value.as_object().ok_or(StoreError::RecoveryRequired)?;
        if rounds.is_empty() {
            return Ok(());
        }
        // Independently bounded even when called with an already-built Value.
        let encoded = serde_json::to_vec(payload)?;
        let _: Value = wholepact_core::strict_json::parse_json_unique(&encoded)
            .map_err(|_| StoreError::RecoveryRequired)?;
        if rounds.len() > 4
            || self.protection != StorageProtection::Encrypted
            || self.recovered_generation
        {
            return Err(StoreError::RecoveryRequired);
        }
        let original = self
            .original_database
            .as_ref()
            .ok_or(StoreError::RecoveryRequired)?;
        original.check_current(connection)?;
        let actual = std::fs::canonicalize(connection.path().ok_or(StoreError::RecoveryRequired)?)?;
        let origin = hex::encode(original.origin_commitment());
        let mut all_operations = std::collections::BTreeSet::new();
        for round in rounds.values() {
            if round["metadata_origin"].as_str() != Some(origin.as_str()) {
                return Err(StoreError::RecoveryRequired);
            }
            let requests = round["requests"]
                .as_object()
                .ok_or(StoreError::RecoveryRequired)?;
            let intakes = round["intakes"]
                .as_object()
                .ok_or(StoreError::RecoveryRequired)?;
            if requests.len() != 2 || intakes.len() > 2 {
                return Err(StoreError::RecoveryRequired);
            }
            for (account, request) in requests {
                validate_id(account).map_err(|_| StoreError::RecoveryRequired)?;
                let operation = request["operation_id"]
                    .as_str()
                    .ok_or(StoreError::RecoveryRequired)?;
                require_operation(operation)?;
                if !all_operations.insert(operation) {
                    return Err(StoreError::RecoveryRequired);
                }
                let expected = request["intent"]["protected_destination"]
                    .as_str()
                    .ok_or(StoreError::RecoveryRequired)?;
                require_destination(expected, &actual)?;
                if request["intent"]["account_id"].as_str() != Some(account.as_str()) {
                    return Err(StoreError::RecoveryRequired);
                }
            }
            for (account, intake) in intakes {
                let expected = requests.get(account).ok_or(StoreError::RecoveryRequired)?;
                if intake["outbox"].get("request") != Some(expected) {
                    return Err(StoreError::RecoveryRequired);
                }
            }
            if let Some(captures) = round.get("capture_intents") {
                let captures = captures.as_object().ok_or(StoreError::RecoveryRequired)?;
                if captures.len() > MAX_CAPTURE_INTENTS {
                    return Err(StoreError::RecoveryRequired);
                }
                let mut counts = std::collections::BTreeMap::<&str, usize>::new();
                for (operation, intent) in captures {
                    require_operation(operation)?;
                    if !all_operations.insert(operation)
                        || serde_json::to_vec(intent)?.len() > MAX_CAPTURE_INTENT_BYTES
                    {
                        return Err(StoreError::RecoveryRequired);
                    }
                    let request = &intent["request"];
                    let scope = &request["scope"];
                    let account = scope["account_id"]
                        .as_str()
                        .ok_or(StoreError::RecoveryRequired)?;
                    let saved = requests.get(account).ok_or(StoreError::RecoveryRequired)?;
                    let destination = scope["protected_destination"]
                        .as_str()
                        .ok_or(StoreError::RecoveryRequired)?;
                    if request["operation_id"].as_str() != Some(operation.as_str())
                        || saved["intent"]["account_id"].as_str() != Some(account)
                        || saved["intent"]["protected_destination"].as_str() != Some(destination)
                        || !intakes.contains_key(account)
                    {
                        return Err(StoreError::RecoveryRequired);
                    }
                    require_destination(destination, &actual)?;
                    let count = counts.entry(account).or_default();
                    *count += 1;
                    if *count > MAX_CAPTURE_INTENTS_PER_ACCOUNT {
                        return Err(StoreError::RecoveryRequired);
                    }
                }
            }
        }
        original.check_current(connection)?;
        Ok(())
    }
}
fn require_operation(operation: &str) -> Result<()> {
    if operation.is_empty()
        || operation.len() > 128
        || !operation
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_:./@".contains(&byte))
    {
        return Err(StoreError::RecoveryRequired);
    }
    Ok(())
}
fn require_destination(expected: &str, actual: &Path) -> Result<()> {
    let expected = Path::new(expected);
    if !expected.is_absolute() || std::fs::canonicalize(expected)? != expected || actual != expected
    {
        return Err(StoreError::RecoveryRequired);
    }
    Ok(())
}

// Deterministic same-thread file substitution is test-only. Production has no
// injected callback, checkpoint, or relaxation of its original-file check.
#[cfg(test)]
thread_local! {
    static COMMIT_HOOK: std::cell::RefCell<Option<(bool, Box<dyn FnOnce()>)>> =
        const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
pub(super) fn run_commit_hook(after_commit: bool) {
    let hook = COMMIT_HOOK.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot
            .as_ref()
            .is_some_and(|(after, _)| *after == after_commit)
        {
            slot.take().map(|(_, hook)| hook)
        } else {
            None
        }
    });
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(test)]
#[path = "durable_input_projection_parser_v1_tests.rs"]
mod parser_tests;
#[cfg(all(test, target_os = "linux"))]
#[path = "durable_input_projection_guard_v1_tests.rs"]
mod tests;
