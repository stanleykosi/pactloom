//! Commit-time original-file guard for private discovery metadata.
//! Inactive until the exclusive coordinator facade and all-history backup
//! refusal are registered together. This validates storage, never consent.
use super::*;

impl Store {
    /// Invoke inside the same pre-commit/post-commit boundaries as the existing
    /// durable construction guard, including exact idempotent replay. Caller
    /// checks alone cannot cover a destination replacement before SQLite commit.
    pub(crate) fn check_durable_projection_destination_v1(
        &self,
        connection: &Connection,
        payload: &Value,
    ) -> Result<()> {
        let Some(value) = payload.get("durable_input_projections_v1") else {
            return Ok(());
        };
        let rounds = value.as_object().ok_or(StoreError::RecoveryRequired)?;
        if rounds.is_empty() {
            return Ok(());
        }
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
                let expected = request["intent"]["protected_destination"]
                    .as_str()
                    .ok_or(StoreError::RecoveryRequired)?;
                let expected = Path::new(expected);
                if !expected.is_absolute()
                    || std::fs::canonicalize(expected)? != expected
                    || actual != expected
                    || request["intent"]["account_id"].as_str() != Some(account.as_str())
                {
                    return Err(StoreError::RecoveryRequired);
                }
            }
            for (account, intake) in intakes {
                let expected = requests.get(account).ok_or(StoreError::RecoveryRequired)?;
                if intake["outbox"].get("request") != Some(expected) {
                    return Err(StoreError::RecoveryRequired);
                }
            }
        }
        original.check_current(connection)?;
        Ok(())
    }
}

#[cfg(all(test, unix))]
#[path = "durable_input_projection_guard_v1_tests.rs"]
mod tests;
