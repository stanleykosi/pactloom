//! Generic and qualified offline outbox owner. The SQL journal implementation
//! is private source shared with the separate signer-release adapter.
use crate::{
    prepare_export, ArtifactKind, DisclosureField, EncryptedEnvelope, ExportRequest,
    MailboxProtection, MessageContext, MessageOrder, PreparedExport, ReceivedArtifact, Result,
    Timestamp, TransportError, TransportPublicKey, TransportSecret, MAX_ENCRYPTED_INBOX_BYTES,
    MAX_FILE_BYTES, MAX_MESSAGE_LIFETIME_SECONDS, MAX_REPLAY_RECORDS, MAX_REPLAY_STREAMS,
    SCHEMA_VERSION,
};
include!("outbox_journal.rs");

fn seal_for_journal(
    prepared: PreparedExport,
    sender: &TransportSecret,
    approved: &str,
    now: &Timestamp,
) -> Result<EncryptedEnvelope> {
    prepared.seal_qualified(sender, approved, now)
}

#[cfg(test)]
#[path = "outbox_split_tests.rs"]
mod split_tests;
