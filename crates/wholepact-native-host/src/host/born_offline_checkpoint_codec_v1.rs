//! Host-private nominal compilation of the maintained canonical HPKE/outbox.
//! Only the actual native checkpoint owner can reach this purpose-specific
//! sealer. No new cryptography, public writer or raw qualified sealing API.
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
pub(in crate::host) use envelope::{
    EncryptedEnvelope, ReceivedArtifact, TransportPublicKey, TransportSecret,
};
pub(super) use envelope::{ExportRequest, PreparedExport, prepare_export};
pub(in crate::host) use replay::*;
pub(in crate::host) use types::*;

/// Historical immutable authentication only, including expired originals.
/// The actual native return owner must keep the original
/// checkpoint/outbox source, genuine consent and keys, validate the exact domain
/// and signature delta, and atomically retain replay plus its complete result.
/// It must compare the authenticated original window with actual born admission;
/// fresh post-return wallet/witness/native gates independently govern any use.
/// This never renews validity, commits replay, merges a transaction, or yields
/// spending authority. No ciphertext is resealed and no new origin is created.
pub(in crate::host) fn authenticate_born_return(
    envelope: &EncryptedEnvelope,
    recipient: &TransportSecret,
    expected_sender: &TransportPublicKey,
    expected: &MessageContext,
) -> Result<(ReceivedArtifact, AuthenticatedReceipt)> {
    if expected.artifact_kind != ArtifactKind::BornOfflineAuthorizationReturnV1 {
        return Err(TransportError::AuthorityUnavailable);
    }
    envelope::authenticate(envelope, recipient, expected_sender, expected, None)
}
mod outbox {
    use super::*;
    include!("../../../wholepact-transport/src/outbox_journal_core.rs");

    fn seal_for_journal(
        prepared: PreparedExport,
        sender: &TransportSecret,
        approved: &str,
        now: &Timestamp,
    ) -> Result<EncryptedEnvelope> {
        if prepared.preview().context.artifact_kind != ArtifactKind::BornOfflineCheckpointOriginV1 {
            return Err(TransportError::AuthorityUnavailable);
        }
        prepared.seal_qualified(sender, approved, now)
    }
}
pub(super) use outbox::{OutboxArtifact, SqliteOutbox};
