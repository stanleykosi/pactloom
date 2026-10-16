//! Native-only independent transport setup. The original encrypted journal retains
//! keys before outbox initialization; failure never silently generates replacement keys.
use super::{
    NativeDecision, VerifierOwner,
    export_identity::{ExportIdentity, ExportSecrets, SetupIntent, SetupState},
};
use crate::{Error, Result, vault};
use sha2::{Digest, Sha256};
use wholepact_storage_security::{DatabaseKey, create_encrypted, open_encrypted_quiescent};
use wholepact_storage_security::{
    PlannedNamedVerifierOutboxInitialization as Planned,
    PlannedNamedVerifierOutboxInspection as Inspection,
};
use wholepact_transport::SqliteOutbox;
pub(super) const OUTBOX: &str = "named-verifier-outbox.sqlite";
pub(super) struct PreparedTransportSetup {
    digest: String,
    commitment: String,
    source: super::NativeAuthorityBinding,
    display: String,
}
impl VerifierOwner {
    pub(super) fn prepare_transport_setup(&mut self) -> Result<PreparedTransportSetup> {
        self.check_current()?;
        if self.journal.restored_informational {
            return Err(Error::RecoveryRequired);
        }
        if self
            .journal
            .export_identity
            .as_ref()
            .is_some_and(|s| s.state == SetupState::Ready)
        {
            return Err(Error::ReviewMismatch);
        }
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-named-verifier-transport-setup:v1",
            &(
                self.public_key(),
                self.directory.root().to_str().ok_or(Error::InvalidData)?,
                self.state_commitment()?,
                self.source.entry_digest(),
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        let display = format!(
            "CREATE OR RESUME SEPARATE ASSERTION TRANSPORT\nVerifier key: {}\nPrivate directory: {}\nIndependent X25519 transport and encrypted mailbox keys; no spending authority or data transmission. Recipient pins require a separate exact native decision. Partial setup retains its exact keys and never resets. Backups must include the mailbox; clones cannot be globally revoked.\nExact review: {}",
            hex::encode(self.public_key()),
            self.directory.root().display(),
            digest
        );
        Ok(PreparedTransportSetup {
            digest,
            commitment: self.state_commitment()?,
            source: self.source.clone(),
            display,
        })
    }
    pub(super) fn open_export_outbox(&self) -> Result<SqliteOutbox> {
        self.check_current()?;
        if self.journal.restored_informational {
            return Err(Error::RecoveryRequired);
        }
        let identity = self
            .journal
            .export_identity
            .as_ref()
            .ok_or(Error::Unavailable)?;
        identity.validate()?;
        if identity.state != SetupState::Ready {
            return Err(Error::Uncertain);
        }
        let path = std::fs::canonicalize(self.directory.root())?.join(OUTBOX);
        if identity.setup_intent.outbox_path != path {
            return Err(Error::ReviewMismatch);
        }
        let connection =
            open_encrypted_quiescent(path, &DatabaseKey::from_bytes(identity.secrets.database))
                .map_err(|_| Error::Verification)?;
        SqliteOutbox::from_encrypted_connection(connection).map_err(|_| Error::Verification)
    }
}
impl PreparedTransportSetup {
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn display(&self) -> &str {
        &self.display
    }
    pub(super) fn approve(self, owner: &mut VerifierOwner, decision: NativeDecision) -> Result<()> {
        owner.check_current()?;
        if owner.source != self.source || owner.state_commitment()? != self.commitment {
            return Err(Error::ReviewMismatch);
        }
        if decision.binding() != &owner.source || decision.reviewed_digest() != self.digest {
            return Err(Error::ReviewMismatch);
        }
        let source = owner.source.clone();
        let _publication = source.publication_lease()?;
        let result = (|| -> Result<()> {
            if owner.journal.export_identity.is_none() {
                if owner.directory.exists(OUTBOX)? {
                    return Err(Error::RecoveryRequired);
                }
                let transport = vault::random::<32>()?;
                let database = vault::random::<32>()?;
                if transport == database || transport == *owner.seed || database == *owner.seed {
                    return Err(Error::Crypto);
                }
                let path = std::fs::canonicalize(owner.directory.root())?.join(OUTBOX);
                let setup_intent = SetupIntent {
                    verifier_digest: hex::encode(Sha256::digest(owner.public_key())),
                    original_review_digest: self.digest.clone(),
                    outbox_path: path,
                    database_key_commitment: Planned::database_key_commitment(
                        &DatabaseKey::from_bytes(database),
                    ),
                };
                setup_intent.validate(&database)?;
                owner.journal.export_identity = Some(ExportIdentity {
                    version: 1,
                    setup_intent,
                    secrets: ExportSecrets {
                        transport,
                        database,
                    },
                    state: SetupState::Prepared,
                    pins: Default::default(),
                });
                owner.persist()?;
            }
            let identity = owner
                .journal
                .export_identity
                .as_ref()
                .ok_or(Error::InvalidData)?;
            identity.validate()?;
            if identity.state != SetupState::Prepared {
                return Err(Error::ReviewMismatch);
            }
            let path = std::fs::canonicalize(owner.directory.root())?.join(OUTBOX);
            let intent = &identity.setup_intent;
            if intent.outbox_path != path
                || intent.verifier_digest != hex::encode(Sha256::digest(owner.public_key()))
            {
                return Err(Error::ReviewMismatch);
            }
            let key = DatabaseKey::from_bytes(identity.secrets.database);
            let plan = Planned::new(
                &intent.verifier_digest,
                &intent.original_review_digest,
                &path,
                &key,
                &intent.database_key_commitment,
            )
            .map_err(|_| Error::RecoveryRequired)?;
            let outbox = if owner.directory.exists(OUTBOX)? {
                match plan
                    .inspect(
                        &path,
                        &key,
                        &intent.verifier_digest,
                        &intent.original_review_digest,
                        &intent.database_key_commitment,
                    )
                    .map_err(|_| Error::RecoveryRequired)?
                {
                    Inspection::AuthenticatedPristineEmpty => {
                        let initial = plan
                            .resume(
                                &path,
                                &key,
                                &intent.verifier_digest,
                                &intent.original_review_digest,
                                &intent.database_key_commitment,
                            )
                            .map_err(|_| Error::RecoveryRequired)?;
                        SqliteOutbox::from_named_verifier_initialization(initial)
                            .map_err(|_| Error::Verification)?
                    }
                    Inspection::Initialized(snapshot) => {
                        drop(snapshot);
                        // This second immutable inspection checks the complete compiled
                        // template before any source SQLite handle can modify sidecars.
                        let checked = SqliteOutbox::inspect_empty_named_verifier_setup(&path, &key)
                            .map_err(|_| Error::Verification)?;
                        drop(checked);
                        SqliteOutbox::from_encrypted_connection(
                            open_encrypted_quiescent(&path, &key)
                                .map_err(|_| Error::RecoveryRequired)?,
                        )
                        .map_err(|_| Error::Verification)?
                    }
                }
            } else {
                SqliteOutbox::from_encrypted_connection(
                    create_encrypted(&path, &key).map_err(|_| Error::RecoveryRequired)?,
                )
                .map_err(|_| Error::Verification)?
            };
            // A Prepared record cannot have exported any message. Even a known
            // schema with an envelope is refused, never adopted as empty setup.
            outbox
                .require_empty_for_initial_setup()
                .map_err(|_| Error::ReviewMismatch)?;
            drop(outbox);
            owner
                .journal
                .export_identity
                .as_mut()
                .ok_or(Error::InvalidData)?
                .state = SetupState::Ready;
            owner.persist()
        })();
        if result.is_err() {
            owner.poisoned = true;
            return Err(Error::Uncertain);
        }
        Ok(())
    }
}
