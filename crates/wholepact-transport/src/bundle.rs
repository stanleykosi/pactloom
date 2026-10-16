//! Typed backup adapters over exclusively borrowed, already-open encrypted
//! mailboxes. Source paths and imported archive schemas are never accepted here.
//! A whole-profile BundleAuthority must additionally quiesce independent writers.
use crate::{
    outbox::OUTBOX_SCHEMA, replay::{INBOX_SCHEMA, INBOX_SCHEMA_VERSION}, MailboxProtection, SqliteOutbox,
    SqliteReplayLedger, TransportError,
};
use rusqlite::Connection;
use wholepact_storage_security::bundle::{
    BackupReadPermit, BundleError, JournalAdapter, JournalKind, JournalTemplate,
};

pub static INBOX_BACKUP_TEMPLATE: JournalTemplate = JournalTemplate {
    kind: JournalKind::TransportInbox,
    application_id: 0x57504942,
    schema_version: INBOX_SCHEMA_VERSION,
    create_sql: INBOX_SCHEMA,
};
pub static OUTBOX_BACKUP_TEMPLATE: JournalTemplate = JournalTemplate {
    kind: JournalKind::TransportOutbox,
    application_id: 0x57504f42,
    schema_version: 1,
    create_sql: OUTBOX_SCHEMA,
};
pub struct TransportInboxBackup<'a> {
    journal: &'a mut SqliteReplayLedger,
}
pub struct TransportOutboxBackup<'a> {
    journal: &'a mut SqliteOutbox,
}
impl SqliteReplayLedger {
    /// Exclusive borrowing prevents this open inbox from accepting deliveries or
    /// domain results during the snapshot. It is not multi-connection fencing.
    pub fn backup_adapter(&mut self) -> Result<TransportInboxBackup<'_>, TransportError> {
        if self.protection() != MailboxProtection::Encrypted {
            return Err(TransportError::AuthorityUnavailable);
        }
        Ok(TransportInboxBackup { journal: self })
    }
}
impl SqliteOutbox {
    /// Exclusive borrowing prevents this open outbox from enqueueing/distributing
    /// new bytes during the snapshot. Already returned bytes cannot be revoked.
    pub fn backup_adapter(&mut self) -> Result<TransportOutboxBackup<'_>, TransportError> {
        if self.protection() != MailboxProtection::Encrypted {
            return Err(TransportError::AuthorityUnavailable);
        }
        Ok(TransportOutboxBackup { journal: self })
    }
}
impl JournalAdapter for TransportInboxBackup<'_> {
    fn template(&self) -> &'static JournalTemplate {
        &INBOX_BACKUP_TEMPLATE
    }
    fn read_locked(
        &self,
        permit: &BackupReadPermit<'_>,
        visitor: &mut dyn FnMut(&Connection) -> Result<(), BundleError>,
    ) -> Result<(), BundleError> {
        permit.check(self)?;
        if self.journal.protection() != MailboxProtection::Encrypted
            || !self.journal.connection.is_autocommit()
        {
            return Err(BundleError::Permission);
        }
        visitor(&self.journal.connection)
    }
}
impl JournalAdapter for TransportOutboxBackup<'_> {
    fn template(&self) -> &'static JournalTemplate {
        &OUTBOX_BACKUP_TEMPLATE
    }
    fn read_locked(
        &self,
        permit: &BackupReadPermit<'_>,
        visitor: &mut dyn FnMut(&Connection) -> Result<(), BundleError>,
    ) -> Result<(), BundleError> {
        permit.check(self)?;
        if self.journal.protection() != MailboxProtection::Encrypted
            || !self.journal.connection.is_autocommit()
        {
            return Err(BundleError::Permission);
        }
        visitor(&self.journal.connection)
    }
}

/// Retain complete authenticated original rows in an independently keyed,
/// generation-bound evidence file. This never activates a restored journal,
/// reruns work, renews consent, or establishes current settlement.
pub fn reconstruct_inbox_successor_evidence(
    source: &wholepact_storage_security::bundle::recovery::VerifiedRecoveryComponent,
    path: impl AsRef<std::path::Path>,
    key: &wholepact_storage_security::DatabaseKey,
    binding: &wholepact_storage_security::bundle::recovery::generation::GenerationBinding,
) -> Result<(), wholepact_storage_security::bundle::BundleError> {
    wholepact_storage_security::bundle::recovery::evidence::reconstruct_inbox_evidence(
        source,
        &INBOX_BACKUP_TEMPLATE,
        path,
        key,
        binding,
    )
}

/// Authenticate immutable evidence under this journal's compiled schema.
/// Private artifact access remains subject to the caller's native disclosure
/// boundary. Returned historical rows cannot be converted into a live journal.
pub fn open_inbox_successor_evidence(
    path: impl AsRef<std::path::Path>,
    key: &wholepact_storage_security::DatabaseKey,
    binding: &wholepact_storage_security::bundle::recovery::generation::GenerationBinding,
    expected: &wholepact_storage_security::bundle::recovery::RecoveryProvenance,
) -> Result<
    wholepact_storage_security::bundle::recovery::evidence::RecoveredEvidence,
    wholepact_storage_security::bundle::BundleError,
> {
    wholepact_storage_security::bundle::recovery::evidence::open_inbox_evidence(
        path,
        key,
        binding,
        expected,
        &INBOX_BACKUP_TEMPLATE,
    )
}

/// Retain complete authenticated original rows in an independently keyed,
/// generation-bound evidence file. This never activates a restored journal,
/// reruns work, renews consent, or establishes current settlement.
pub fn reconstruct_outbox_successor_evidence(
    source: &wholepact_storage_security::bundle::recovery::VerifiedRecoveryComponent,
    path: impl AsRef<std::path::Path>,
    key: &wholepact_storage_security::DatabaseKey,
    binding: &wholepact_storage_security::bundle::recovery::generation::GenerationBinding,
) -> Result<(), wholepact_storage_security::bundle::BundleError> {
    wholepact_storage_security::bundle::recovery::evidence::reconstruct_outbox_evidence(
        source,
        &OUTBOX_BACKUP_TEMPLATE,
        path,
        key,
        binding,
    )
}

/// Authenticate immutable evidence under this journal's compiled schema.
/// Private artifact access remains subject to the caller's native disclosure
/// boundary. Returned historical rows cannot be converted into a live journal.
pub fn open_outbox_successor_evidence(
    path: impl AsRef<std::path::Path>,
    key: &wholepact_storage_security::DatabaseKey,
    binding: &wholepact_storage_security::bundle::recovery::generation::GenerationBinding,
    expected: &wholepact_storage_security::bundle::recovery::RecoveryProvenance,
) -> Result<
    wholepact_storage_security::bundle::recovery::evidence::RecoveredEvidence,
    wholepact_storage_security::bundle::BundleError,
> {
    wholepact_storage_security::bundle::recovery::evidence::open_outbox_evidence(
        path,
        key,
        binding,
        expected,
        &OUTBOX_BACKUP_TEMPLATE,
    )
}
