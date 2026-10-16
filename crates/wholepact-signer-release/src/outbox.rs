//! Only this adapter can reach the privately included authorization writer.
use crate::{journal, AuthorizationOutboxArtifact, PreparedAuthorizationExport};
use wholepact_storage_security::{DatabaseFileIdentity, EncryptedConnection};
use wholepact_transport::{
    ArtifactKind, Result, SqliteOutbox, Timestamp, TransportError, TransportPublicKey,
    TransportSecret,
};

/// Original-signer-only writer on the SAME encrypted outbox used by transport.
/// A different database, including a valid same-schema empty mailbox, is refused.
/// No constructor takes an asserted identity, raw Connection, path or key bytes.
/// The native owner must retain its profile directory lock while both owners live.
/// Raw transport preparation cannot become signer authorization:
/// ```compile_fail
/// use wholepact_signer_release::AuthorizationOutbox;
/// use wholepact_transport::{PreparedExport, SqliteOutbox, TransportSecret, TransportPublicKey, Timestamp};
/// fn cannot_mint(raw: PreparedExport, adapter: &mut AuthorizationOutbox,
///     outbox: &SqliteOutbox, sender: &TransportSecret, recipient: &TransportPublicKey, now: &Timestamp) {
///     let _ = adapter.enqueue_authorization(outbox, raw, sender, recipient, "", now);
/// }
/// ```
/// The source-included raw journal is private to the adapter:
/// ```compile_fail
/// use wholepact_signer_release::journal::SqliteOutbox;
/// ```
pub struct AuthorizationOutbox {
    journal: journal::SqliteOutbox,
    bound_identity: DatabaseFileIdentity,
}
impl AuthorizationOutbox {
    pub fn from_encrypted_connection(
        original_outbox: &SqliteOutbox,
        connection: EncryptedConnection,
    ) -> Result<Self> {
        let bound_identity = original_outbox.database_identity()?;
        let actual = connection
            .database_identity()
            .map_err(|_| TransportError::Storage)?;
        if actual != bound_identity {
            return Err(TransportError::WrongContext);
        }
        // Compare BEFORE the shared journal can execute any schema statement.
        // Both factory-authenticated handles now identify the same live inode:
        // wrong keys cannot open it; no key digest, rekey or fallback is needed.
        let journal = journal::SqliteOutbox::from_encrypted_connection(connection)?;
        let result = Self {
            journal,
            bound_identity,
        };
        result.check_binding(original_outbox)?;
        Ok(result)
    }

    /// Read-only, fail-closed revalidation of BOTH current owning handles.
    /// Repeated on each use, after commit, and before returning a handoff guard.
    pub fn check_binding(&self, original_outbox: &SqliteOutbox) -> Result<()> {
        if original_outbox.database_identity()? != self.bound_identity
            || self.journal.database_identity()? != self.bound_identity
        {
            return Err(TransportError::WrongContext);
        }
        Ok(())
    }

    /// A genuine installed-signer release plus separate exact disclosure consent.
    /// The signer lease survives the transaction, exact recovery and handoff.
    pub fn enqueue_authorization<'a>(
        &mut self,
        original_outbox: &SqliteOutbox,
        released: PreparedAuthorizationExport<'a>,
        sender: &TransportSecret,
        recipient: &TransportPublicKey,
        approved_preview_digest: &str,
        now: &Timestamp,
    ) -> Result<AuthorizationOutboxArtifact<'a>> {
        self.check_binding(original_outbox)?;
        released.check_current()?;
        let preview = released.preview().clone();
        if preview.context.artifact_kind != ArtifactKind::Authorization {
            return Err(TransportError::AuthorityUnavailable);
        }
        if preview.recipient_key_fingerprint != recipient.fingerprint() {
            return Err(TransportError::DisclosureDenied);
        }
        let PreparedAuthorizationExport {
            prepared, original, ..
        } = released;
        let committed =
            self.journal
                .enqueue_validated(prepared, sender, approved_preview_digest, now)?;
        original
            .check_current()
            .map_err(|_| TransportError::AuthorityUnavailable)?;
        self.check_binding(original_outbox)?;
        // Read via the original public owner, preserving the existing public
        // OutboxArtifact type and proving both owners see the exact same bytes.
        // No resealing, new sequence, renewed validity or alternate lookup exists.
        let artifact = original_outbox.recover_for_recipient(
            &preview.context,
            recipient,
            preview.order.sequence,
        )?;
        let artifact = artifact.ok_or(TransportError::Storage)?;
        if artifact.preview_digest() != approved_preview_digest
            || artifact.envelope().as_bytes() != committed.envelope().as_bytes()
        {
            return Err(TransportError::Equivocation);
        }
        original
            .check_current()
            .map_err(|_| TransportError::AuthorityUnavailable)?;
        self.check_binding(original_outbox)?;
        Ok(AuthorizationOutboxArtifact { artifact, original })
    }

    /// Exact old ciphertext only. Retained issue/expiry, message, sequence,
    /// destination and signer payload never change, including after expiry.
    pub fn recover_authorization<'a>(
        &self,
        original_outbox: &SqliteOutbox,
        released: PreparedAuthorizationExport<'a>,
        recipient: &TransportPublicKey,
        approved_preview_digest: &str,
    ) -> Result<AuthorizationOutboxArtifact<'a>> {
        self.check_binding(original_outbox)?;
        released.check_current()?;
        let preview = released.preview();
        if preview.context.artifact_kind != ArtifactKind::Authorization {
            return Err(TransportError::AuthorityUnavailable);
        }
        if preview.digest()? != approved_preview_digest
            || preview.recipient_key_fingerprint != recipient.fingerprint()
        {
            return Err(TransportError::DisclosureDenied);
        }
        let artifact = original_outbox
            .recover_for_recipient(&preview.context, recipient, preview.order.sequence)?
            .ok_or(TransportError::WrongContext)?;
        if artifact.preview_digest() != approved_preview_digest {
            return Err(TransportError::Equivocation);
        }
        self.check_binding(original_outbox)?;
        released.check_current()?;
        Ok(AuthorizationOutboxArtifact {
            artifact,
            original: released.original,
        })
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
