//! Inert first-write purpose data, not native approval or storage ownership.
//!
//! Validation and the digest establish only a bounded canonical encoding.
//! The caller must separately join
//! every field to the actual selected source and original encrypted Store, and
//! authenticate the native PENDING/COMMIT association before any activation.

use crate::{Result, StoreError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const PRIVATE_WORKSPACE_ORIGIN_KEY_V1: &str = "private_workspace_origin_v1";
pub const PRIVATE_WORKSPACE_ORIGIN_PURPOSE_V1: &str = "durable-private-coordination-v1";
pub const PRIVATE_WORKSPACE_ORIGIN_DIGEST_DOMAIN_V1: &str =
    "wholepact:private-durable-workspace-origin:v1";
pub const MAX_PRIVATE_WORKSPACE_ORIGIN_JSON_BYTES: usize = 8 * 1024;
const MAX_DESTINATION_BYTES: usize = 4096;
const MAX_RETENTION_BYTES: usize = 1024;

/// Data only. Public fields and deserialization confer no provenance, authority,
/// privacy permission, or assertion that a native association was persisted.
/// Deliberately no Debug implementation: paths and retained scope are private.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateWorkspaceOriginV1 {
    pub version: u16,
    pub purpose: String,
    pub native_association_digest: String,
    /// Canonical digest of the complete exact source-selected seed, including
    /// original terms history. A second seed digest would be redundant.
    pub source_digest: String,
    pub principal_id: String,
    pub agreement_id: String,
    pub obligation_id: String,
    pub reviewer_account_ids: Vec<String>,
    pub protected_destination: String,
    pub retention_policy: String,
    pub metadata_origin: String,
}

impl PrivateWorkspaceOriginV1 {
    /// Bounded syntax only. This performs no filesystem access and authenticates
    /// no source, account, database, native association, or permission.
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 || self.purpose != PRIVATE_WORKSPACE_ORIGIN_PURPOSE_V1 {
            return Err(StoreError::RecoveryRequired);
        }
        for digest in [
            &self.native_association_digest,
            &self.source_digest,
            &self.metadata_origin,
        ] {
            require_digest(digest)?;
        }
        for id in [&self.principal_id, &self.agreement_id, &self.obligation_id] {
            crate::validate_id(id).map_err(|_| StoreError::RecoveryRequired)?;
        }
        if self.reviewer_account_ids.len() != 2
            || self.reviewer_account_ids[0] >= self.reviewer_account_ids[1]
        {
            return Err(StoreError::RecoveryRequired);
        }
        for account in &self.reviewer_account_ids {
            require_digest(account)?;
        }
        if self.protected_destination.len() > MAX_DESTINATION_BYTES
            || !Path::new(&self.protected_destination).is_absolute()
            || self.protected_destination.chars().any(char::is_control)
            || self.retention_policy.is_empty()
            || self.retention_policy.len() > MAX_RETENTION_BYTES
            || self.retention_policy.chars().any(char::is_control)
        {
            return Err(StoreError::RecoveryRequired);
        }
        // Field budgets are independent of the fixed whole-marker budget.
        if serde_json::to_vec(self)?.len() > MAX_PRIVATE_WORKSPACE_ORIGIN_JSON_BYTES {
            return Err(StoreError::RecoveryRequired);
        }
        Ok(())
    }

    /// Raw marker import. Never use Value collapse to hide duplicate decoded
    /// fields; both raw and canonical encodings retain the fixed marker budget.
    pub fn from_json(raw: &str) -> Result<Self> {
        let marker: Self = wholepact_core::strict_json::parse_typed_json_with_byte_limit(
            raw.as_bytes(),
            MAX_PRIVATE_WORKSPACE_ORIGIN_JSON_BYTES,
        )
        .map_err(|_| StoreError::RecoveryRequired)?;
        marker.validate()?;
        Ok(marker)
    }

    /// Fixed-domain canonical data commitment, never a receipt or capability.
    /// Native COMMIT may bind this value only after its own actual-owner checks.
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        wholepact_core::proposal::canonical_digest(PRIVATE_WORKSPACE_ORIGIN_DIGEST_DOMAIN_V1, self)
            .map_err(|_| StoreError::RecoveryRequired)
    }
}

fn require_digest(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(StoreError::RecoveryRequired);
    }
    Ok(())
}

#[cfg(test)]
#[path = "private_workspace_origin_v1_tests.rs"]
mod tests;
