// Private inclusion: this module and its writer are never exported.
use wholepact_transport::{
    prepare_export, ArtifactKind, DisclosureField, EncryptedEnvelope, ExportRequest,
    MailboxProtection, MessageContext, MessageOrder, PreparedExport, ReceivedArtifact, Result,
    Timestamp, TransportError, TransportPublicKey, TransportSecret, MAX_ENCRYPTED_INBOX_BYTES,
    MAX_FILE_BYTES, MAX_MESSAGE_LIFETIME_SECONDS, MAX_REPLAY_RECORDS, MAX_REPLAY_STREAMS,
    SCHEMA_VERSION,
};
include!("../../wholepact-transport/src/outbox_journal.rs");

fn seal_for_journal(
    prepared: PreparedExport,
    sender: &TransportSecret,
    approved: &str,
    now: &Timestamp,
) -> Result<EncryptedEnvelope> {
    if prepared.preview().context.artifact_kind != ArtifactKind::Authorization {
        return Err(TransportError::AuthorityUnavailable);
    }
    // Public sealing cannot export qualified offline artifacts. The sole caller
    // is AuthorizationOutbox, after consuming a genuine OriginalHistoryLease.
    prepared.seal(sender, approved, now)
}
