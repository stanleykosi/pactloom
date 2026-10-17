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
    #[cfg(all(feature = "born-offline-witness-owner", target_os = "linux"))]
    impl SqliteReplayLedger {
        pub(crate) fn from_born_original_connection(
            connection: wholepact_storage_security::EncryptedConnection,
        ) -> Result<Self> {
            crate::journal::verify_born_artifact_schema_v1(connection.connection())
                .map_err(|_| TransportError::AuthorityUnavailable)?;
            let mode: String = connection
                .connection()
                .pragma_query_value(None, "journal_mode", |r| r.get(0))
                .map_err(|_| TransportError::Storage)?;
            let sync: i64 = connection
                .connection()
                .pragma_query_value(None, "synchronous", |r| r.get(0))
                .map_err(|_| TransportError::Storage)?;
            let foreign: i64 = connection
                .connection()
                .pragma_query_value(None, "foreign_keys", |r| r.get(0))
                .map_err(|_| TransportError::Storage)?;
            if mode != "wal" || sync != 2 || foreign != 1 {
                return Err(TransportError::Storage);
            }
            let identity = connection
                .database_identity()
                .map_err(|_| TransportError::Storage)?;
            let raw = connection.into_connection();
            raw.busy_timeout(std::time::Duration::from_secs(5))
                .map_err(|_| TransportError::Storage)?;
            Ok(Self {
                connection: raw,
                protection: MailboxProtection::Encrypted,
                identity: Some(identity),
            })
        }
    }
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
    #[cfg(all(feature = "born-offline-witness-owner", target_os = "linux"))]
    impl SqliteOutbox {
        pub(crate) fn from_born_original_connection(
            connection: wholepact_storage_security::EncryptedConnection,
        ) -> Result<Self> {
            crate::journal::verify_born_artifact_schema_v1(connection.connection())
                .map_err(|_| TransportError::AuthorityUnavailable)?;
            let mode: String = connection
                .connection()
                .pragma_query_value(None, "journal_mode", |r| r.get(0))
                .map_err(|_| TransportError::Storage)?;
            let sync: i64 = connection
                .connection()
                .pragma_query_value(None, "synchronous", |r| r.get(0))
                .map_err(|_| TransportError::Storage)?;
            let foreign: i64 = connection
                .connection()
                .pragma_query_value(None, "foreign_keys", |r| r.get(0))
                .map_err(|_| TransportError::Storage)?;
            if mode != "wal" || sync != 2 || foreign != 1 {
                return Err(TransportError::Storage);
            }
            let identity = connection
                .database_identity()
                .map_err(|_| TransportError::Storage)?;
            let raw = connection.into_connection();
            raw.busy_timeout(std::time::Duration::from_secs(5))
                .map_err(|_| TransportError::Storage)?;
            Ok(Self {
                connection: raw,
                protection: MailboxProtection::Encrypted,
                identity: Some(identity),
            })
        }
    }

    fn seal_for_journal(
        prepared: PreparedExport,
        sender: &TransportSecret,
        approved: &str,
        now: &Timestamp,
    ) -> Result<EncryptedEnvelope> {
        if !matches!(
            prepared.preview().context.artifact_kind,
            ArtifactKind::OfflineMinimalAuthorityAdmission
                | ArtifactKind::BornOfflineMinimalAdmissionV1
        ) {
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

#[path = "../../wholepact-transport/src/born_offline_minimal_admission_v1.rs"]
mod born_offline_minimal_admission_v1;
#[cfg(all(feature = "born-offline-witness-owner", target_os = "linux"))]
pub(super) use born_offline_minimal_admission_v1::*;

#[path = "../../wholepact-transport/src/born_offline_intent_v1.rs"]
mod born_offline_intent_v1;
#[cfg(all(feature = "born-offline-witness-owner", target_os = "linux"))]
pub(super) use born_offline_intent_v1::*;
