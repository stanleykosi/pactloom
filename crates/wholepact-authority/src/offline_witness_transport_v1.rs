//! Private compilation of the same maintained transport implementations.
//! None of these nominal types, raw journal methods or private sealers escape.
//! Generic public transport guards and wire/schema/domain bytes remain unchanged.
// The canonical leaves include generic helpers used by other owning adapters.
#![allow(dead_code)]

#[path = "../../wholepact-transport/src/envelope_core.rs"]
mod envelope;
#[path = "../../wholepact-transport/src/replay_schema.rs"]
mod replay_schema;
#[path = "../../wholepact-transport/src/types_core.rs"]
mod types;
mod replay {
    const LEGACY_INBOX_SCHEMA: &str = super::replay_schema::INBOX_SCHEMAS[0].0;
    const INBOX_SCHEMA: &str = super::replay_schema::INBOX_SCHEMAS[1].0;
    const INBOX_SCHEMA_VERSION: i64 = super::replay_schema::INBOX_SCHEMAS[1].1;
    include!("../../wholepact-transport/src/replay_core.rs");
}
mod outbox {
    use super::{
        ArtifactKind, DisclosureField, EncryptedEnvelope, ExportRequest, MAX_ENCRYPTED_INBOX_BYTES,
        MAX_FILE_BYTES, MAX_MESSAGE_LIFETIME_SECONDS, MAX_REPLAY_RECORDS, MAX_REPLAY_STREAMS,
        MailboxProtection, MessageContext, MessageOrder, PreparedExport, ReceivedArtifact, Result,
        SCHEMA_VERSION, Timestamp, TransportError, TransportPublicKey, TransportSecret,
        prepare_export,
    };
    include!("../../wholepact-transport/src/outbox_journal_core.rs");
    fn seal_for_journal(
        prepared: PreparedExport,
        sender: &TransportSecret,
        approved: &str,
        now: &Timestamp,
    ) -> Result<EncryptedEnvelope> {
        if prepared.preview().context.artifact_kind
            != ArtifactKind::OfflineMinimalAuthorityAdmission
        {
            return Err(TransportError::AuthorityUnavailable);
        }
        prepared.seal_qualified(sender, approved, now)
    }
}
#[path = "../../wholepact-transport/src/offline_minimal_admission_core.rs"]
mod offline_minimal_admission;

#[path = "../../wholepact-transport/src/named_review_binding_v1.rs"]
mod named_review_binding_v1;
pub(super) use named_review_binding_v1::*;

pub(super) use envelope::*;
pub(super) use offline_minimal_admission::*;
pub(super) use outbox::*;
pub(super) use replay::*;
pub(super) use types::*;
