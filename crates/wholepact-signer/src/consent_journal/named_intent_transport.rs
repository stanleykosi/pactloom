//! Signer-private nominal compilation of the canonical maintained transport.
//! Only genuine native original-intent/final-recipient owners call private sealers.
//! No type or raw qualified sealing entry is re-exported from the signer crate.
// Canonical codec is shared verbatim; this nominal owner uses only its needed API.
#![allow(dead_code)]
#[path = "../../../wholepact-transport/src/envelope_core.rs"]
mod envelope;
#[path = "../../../wholepact-transport/src/replay_schema.rs"]
mod replay_schema;
#[path = "../../../wholepact-transport/src/types_core.rs"]
mod types;
mod replay {
    const LEGACY_INBOX_SCHEMA: &str = super::replay_schema::INBOX_SCHEMAS[0].0;
    const INBOX_SCHEMA: &str = super::replay_schema::INBOX_SCHEMAS[1].0;
    const INBOX_SCHEMA_VERSION: i64 = super::replay_schema::INBOX_SCHEMAS[1].1;
    include!("../../../wholepact-transport/src/replay_core.rs");
}
pub(super) use envelope::*;
pub(super) use replay::*;
pub(super) use types::*;

// No public writer/boolean/trait accepts this nominal PreparedExport. The native
// original owner must hold its exact source/session lease and NativeDecision,
// recheck the original deadline, and atomically retain the resulting ciphertext
// before any output. Generic transport public guards are unchanged.
pub(super) fn seal_original_intent(
    prepared: PreparedExport,
    sender: &TransportSecret,
    approved_preview_digest: &str,
    now: &Timestamp,
) -> Result<EncryptedEnvelope> {
    if prepared.preview().context.artifact_kind != ArtifactKind::OfflineReservationIntent {
        return Err(TransportError::AuthorityUnavailable);
    }
    prepared.seal_qualified(sender, approved_preview_digest, now)
}

/// Called only after the private final recipient owner committed Started and
/// verified the exact maintained signature delta. No public raw sealer exists.
pub(super) fn seal_original_return(
    prepared: PreparedExport,
    sender: &TransportSecret,
    approved_preview_digest: &str,
    now: &Timestamp,
) -> Result<EncryptedEnvelope> {
    if prepared.preview().context.artifact_kind != ArtifactKind::OfflineAuthorizationReturn {
        return Err(TransportError::AuthorityUnavailable);
    }
    prepared.seal_qualified(sender, approved_preview_digest, now)
}
