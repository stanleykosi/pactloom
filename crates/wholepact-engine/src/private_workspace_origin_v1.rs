//! Inactive Stage A foundation. A first-write marker is immutable correlation,
//! never evidence of native approval, a persisted PENDING, or spending power.
//! Parent wiring and same-snapshot history/export guards remain required.
use crate::{ApiError, Result};
use serde_json::Value;
use wholepact_store::private_workspace_origin_v1::{
    PrivateWorkspaceOriginV1, PRIVATE_WORKSPACE_ORIGIN_KEY_V1,
};

fn damaged() -> ApiError {
    ApiError::new(
        "RECOVERY_REQUIRED",
        "Private workspace origin is incompatible; preserve its original dependency and journals",
    )
}

/// Generic projection boundary. Presence is enough to refuse, including a
/// malformed/null marker. Only purpose-specific internal owners may decode it.
pub(super) fn refuse_public_payload(payload: &Value) -> Result<()> {
    if payload.get(PRIVATE_WORKSPACE_ORIGIN_KEY_V1).is_some() {
        return Err(ApiError::new(
            "DISCLOSURE_DENIED",
            "Private workspace data requires its exact protected workspace and current scoped permission",
        ));
    }
    Ok(())
}

/// This is only a strict data decoder, not permission to read a private record.
/// Raw Store parsing must already have rejected duplicate decoded keys before
/// constructing this Value. A present null is never confused with absence.
pub(super) fn decode_marker(payload: &Value) -> Result<Option<PrivateWorkspaceOriginV1>> {
    let Some(value) = payload.get(PRIVATE_WORKSPACE_ORIGIN_KEY_V1) else {
        return Ok(None);
    };
    let raw = serde_json::to_string(value).map_err(|_| damaged())?;
    PrivateWorkspaceOriginV1::from_json(&raw)
        .map(Some)
        .map_err(|_| damaged())
}

#[cfg(all(
    feature = "durable-proposal",
    feature = "manual-admission",
    target_os = "linux"
))]
mod actual_source {
    use super::*;
    use crate::{
        durable_private_workspace_v1::{PrivateDurableWorkspaceSourceV1, PrivateWorkspaceScopeV1},
        Access,
    };

    /// The caller separately holds the genuine current privacy decision and
    /// actual Store/Directory owners. The association digest is consistency
    /// input only: this function cannot authenticate native persistence.
    pub(crate) fn from_source(
        source: &PrivateDurableWorkspaceSourceV1<'_>,
        access: &Access,
        scope: &PrivateWorkspaceScopeV1,
        native_association_digest: &str,
        actual_store_origin: [u8; 32],
    ) -> Result<PrivateWorkspaceOriginV1> {
        source.check_current(access)?;
        if scope.source_digest() != source.source_digest()
            || scope.principal_id() != source.principal_id()
            || scope.agreement_id() != source.agreement_id()
            || scope.obligation_id() != source.obligation_id()
            || scope.reviewer_account_ids() != source.reviewer_account_ids()
        {
            return Err(damaged());
        }
        let marker = PrivateWorkspaceOriginV1 {
            version: 1,
            purpose: "durable-private-coordination-v1".into(),
            native_association_digest: native_association_digest.into(),
            source_digest: source.source_digest().into(),
            principal_id: source.principal_id().into(),
            agreement_id: source.agreement_id().into(),
            obligation_id: source.obligation_id().into(),
            reviewer_account_ids: source.reviewer_account_ids(),
            protected_destination: scope
                .protected_destination()
                .to_str()
                .ok_or_else(damaged)?
                .into(),
            retention_policy: scope.retention_policy().into(),
            metadata_origin: hex::encode(actual_store_origin),
        };
        marker.validate().map_err(|_| damaged())?;
        source.check_current(access)?;
        Ok(marker)
    }
}

#[cfg(all(
    feature = "durable-proposal",
    feature = "manual-admission",
    target_os = "linux"
))]
pub(super) use actual_source::from_source;

#[cfg(test)]
#[path = "private_workspace_origin_v1_tests.rs"]
mod tests;
