//! First-write purpose correlation on an already-held original Store.
//! No callback, lock reacquisition, native issuer or privacy permission lives here.
use super::*;
use crate::private_workspace_origin_v1::{
    PRIVATE_WORKSPACE_ORIGIN_KEY_V1 as KEY, PrivateWorkspaceOriginV1,
};

fn marker(payload: &Value) -> Result<Option<PrivateWorkspaceOriginV1>> {
    payload
        .get(KEY)
        .map(|value| PrivateWorkspaceOriginV1::from_json(&serde_json::to_string(value)?))
        .transpose()
}

pub(super) fn check_record(
    kind: &str,
    id: &str,
    payload: &Value,
    principal: Option<&str>,
) -> Result<()> {
    let Some(marker) = marker(payload)? else {
        return Ok(());
    };
    if kind != "agreement"
        || marker.agreement_id != id
        || payload["owner_client_id"].as_str() != Some(marker.principal_id.as_str())
        || payload["view"]["agreement"]["agreement_id"].as_str() != Some(id)
        || payload["view"]["agreement"]["obligation_id"].as_str()
            != Some(marker.obligation_id.as_str())
        || principal.is_some_and(|principal| principal != marker.principal_id)
    {
        return Err(StoreError::RecoveryRequired);
    }
    Ok(())
}

impl Store {
    pub(super) fn check_private_workspace_origin_v1(
        &self,
        connection: &Connection,
        payload: &Value,
    ) -> Result<()> {
        let Some(marker) = marker(payload)? else {
            return Ok(());
        };
        check_record("agreement", &marker.agreement_id, payload, None)?;
        if self.protection != StorageProtection::Encrypted
            || self.recovered_generation
            || self.recovered_binding.is_some()
        {
            return Err(StoreError::RecoveryRequired);
        }
        let original = self
            .original_database
            .as_ref()
            .ok_or(StoreError::RecoveryRequired)?;
        original.check_current(connection)?;
        let actual = std::fs::canonicalize(connection.path().ok_or(StoreError::RecoveryRequired)?)?;
        // Compare the canonical spelling as well as actual file identity. A
        // caller's syntactically absolute path is not destination provenance.
        if actual.to_str() != Some(marker.protected_destination.as_str())
            || std::fs::canonicalize(&marker.protected_destination)?.to_str()
                != Some(marker.protected_destination.as_str())
            || marker.metadata_origin != hex::encode(original.origin_commitment())
        {
            return Err(StoreError::RecoveryRequired);
        }
        original.check_current(connection)?;
        Ok(())
    }

    /// New-profile-only checks. Legacy construction history keeps its prior
    /// read semantics; the old construction original-file predicate is not run.
    pub(super) fn check_private_workspace_saved_v1(
        &self,
        connection: &Connection,
        saved: &MutationResult,
        principal: &str,
        resource_id: &str,
        operation: &str,
    ) -> Result<()> {
        let saved_marker = marker(&saved.record.payload)?;
        let current = read_record(connection, "agreement", &saved.record.id)?;
        if let Some(current) = &current {
            self.check_durable_projection_destination_v1(connection, &current.payload)?;
            check_record("agreement", &saved.record.id, &current.payload, None)?;
        }
        let current_marker = current
            .as_ref()
            .map(|record| marker(&record.payload))
            .transpose()?
            .flatten();
        if saved_marker.is_none() && current_marker.is_none() {
            return Ok(());
        }
        let current = current.as_ref().ok_or(StoreError::RecoveryRequired)?;
        if saved_marker.is_none()
            || saved_marker != current_marker
            || saved.record.id != resource_id
            || saved.operation_id != operation
            || saved.record.revision > current.revision
        {
            return Err(StoreError::RecoveryRequired);
        }
        check_record(
            "agreement",
            resource_id,
            &saved.record.payload,
            Some(principal),
        )?;
        check_record("agreement", resource_id, &current.payload, Some(principal))?;
        self.check_durable_projection_destination_v1(connection, &current.payload)?;
        self.check_durable_projection_destination_v1(connection, &saved.record.payload)
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn check_transition(
    connection: &Connection,
    kind: &str,
    id: &str,
    context: &CommandContext,
    current: Option<&StoredRecord>,
    incoming: &Value,
    saved: Option<&MutationResult>,
    expected_revision: Option<u64>,
    event_kind: &str,
) -> Result<()> {
    let next = marker(incoming)?;
    let old = current
        .map(|record| marker(&record.payload))
        .transpose()?
        .flatten();
    let replay = saved
        .map(|result| marker(&result.record.payload))
        .transpose()?
        .flatten();
    if next.is_none() && old.is_none() && replay.is_none() {
        return Ok(());
    }
    check_record(kind, id, incoming, Some(&context.principal_id))?;
    if let Some(current) = current {
        check_record(kind, id, &current.payload, Some(&context.principal_id))?;
    }
    if let Some(saved) = saved {
        check_record(kind, id, &saved.record.payload, Some(&context.principal_id))?;
        if next.is_none()
            || next != old
            || next != replay
            || saved.record.id != id
            || saved.operation_id != operation_id(context)
            || current.is_none_or(|current| saved.record.revision > current.revision)
        {
            return Err(StoreError::RecoveryRequired);
        }
        // Existing exact replay is not a second admission or a new first write.
        return Ok(());
    }
    if current.is_some() {
        if next.is_none() || next != old {
            return Err(StoreError::RecoveryRequired);
        }
    } else {
        if next.is_none()
            || kind != "agreement"
            || expected_revision.is_some()
            || event_kind != "agreement.created"
        {
            return Err(StoreError::RecoveryRequired);
        }
        require_pristine(connection)?;
    }
    Ok(())
}

fn require_pristine(connection: &Connection) -> Result<()> {
    if crate::backup::read_recovery_state(connection)?.recovery_required
        || connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name GLOB 'store_generation_*')",
            [],
            |row| row.get::<_, bool>(0),
        )?
        || connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_sequence)", [], |row| {
            row.get::<_, bool>(0)
        })?
    {
        return Err(StoreError::RecoveryRequired);
    }
    for table in [
        "records",
        "operations",
        "idempotency",
        "events",
        "authority_accounts",
        "authority_exposures",
        "authority_reservations",
        "authority_events",
        "effect_intents",
    ] {
        if connection.query_row(
            &format!("SELECT EXISTS(SELECT 1 FROM {table})"),
            [],
            |row| row.get::<_, bool>(0),
        )? {
            return Err(StoreError::RecoveryRequired);
        }
    }
    Ok(())
}
