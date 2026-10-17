//! Exact retained return recovery and separately approved file handoff. Historical
//! expiry is not renewed; no retry can derive a key or seal new ciphertext.
use super::super::original_import::file_destination::ExactFileDestination;
use super::*;
use std::{io::Write, path::Path};
pub(crate) struct PreparedNamedRecipientReturnFile {
    operation: NamedRecipientOperation,
    profile: LiveNamedRecipientProfile,
    original: NamedRecipientOriginalRecordV1,
    started: NamedRecipientStartedRecordV1,
    result: NamedRecipientResultRecordV1,
    destination: ExactFileDestination,
    created: Instant,
    digest: String,
    display: String,
}
impl LiveNamedRecipientProfile {
    pub(crate) fn prepare_retained_return_file(
        &self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
        authorization: &str,
        path: &Path,
        operation: NamedRecipientOperation,
    ) -> ImportResult<PreparedNamedRecipientReturnFile> {
        self.prepare_return_file_for_origin(
            journal,
            session,
            vault,
            authorization,
            path,
            operation,
            false,
        )
    }
    pub(crate) fn prepare_born_retained_return_file(
        &self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
        authorization: &str,
        path: &Path,
        operation: NamedRecipientOperation,
    ) -> ImportResult<PreparedBornNamedRecipientReturnFile> {
        self.prepare_return_file_for_origin(
            journal,
            session,
            vault,
            authorization,
            path,
            operation,
            true,
        )
        .map(PreparedBornNamedRecipientReturnFile)
    }
    fn prepare_return_file_for_origin(
        &self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
        authorization: &str,
        path: &Path,
        operation: NamedRecipientOperation,
        born: bool,
    ) -> ImportResult<PreparedNamedRecipientReturnFile> {
        operation.check()?;
        require_profile_owner(self, journal)?;
        id(authorization).map_err(unavailable)?;
        let reference = original_reference(journal, self, authorization)?;
        let (profile, retained) = load_profile_and_original(journal, self, &reference)?;
        let original = retained.record;
        if original.born_origin.is_some() != born {
            return Err(TransportError::AuthorityUnavailable);
        }
        if !born {
            original.require_legacy_origin().map_err(unavailable)?;
        }
        let own = retained_own_policy(&original, vault)?;
        let envelope = assertion_receipt_digest(journal, self, &original)?;
        let assertion = self
            .recover_assertion_import(journal, session, vault, &reference, &own, &envelope)?
            .ok_or(TransportError::Authentication)?;
        let records = journal
            .acquire_preconstruction_records(
                &profile.enrollment_ref,
                &profile.manifest_ref,
                session,
            )
            .map_err(unavailable)?;
        require_own_context(self, &original, &own, vault, &records)?;
        if let Some(origin) = &original.born_origin {
            origin
                .require_retained_signer(
                    &*journal.connection.lock().map_err(unavailable)?,
                    &profile,
                    records.enrollment(),
                )
                .map_err(unavailable)?;
            origin
                .checkpoint_receipt
                .require_retained(&*journal.connection.lock().map_err(unavailable)?)
                .map_err(unavailable)?;
        }
        let (started, result) = read_result(journal, &original, &profile)?;
        let signed = Zeroizing::new(hex::decode(&result.result_hex).map_err(unavailable)?);
        inspect_named_verifier_return(
            assertion.artifact().fields()[0].bytes(),
            &signed,
            assertion.inspection(),
        )?;
        let returned = result
            .encrypted_return
            .as_ref()
            .ok_or(TransportError::AuthorityUnavailable)?;
        let final_review = started.return_metadata().map_err(unavailable)?;
        let destination = ExactFileDestination::prepare(path)?;
        let digest = digest(
            if born {
                "wholepact:native-born-named-recipient-return-file:v1"
            } else {
                "wholepact:native-named-recipient-return-file:v1"
            },
            &(
                &original.reference,
                &started.marker_digest().map_err(unavailable)?,
                &result.result_digest,
                &returned.envelope_digest,
                &final_review.consent_reference,
                &original.terms.return_recipient_key_digest,
                destination.review_binding(),
                self.source.entry_digest(),
            ),
        )
        .map_err(unavailable)?;
        let display = format!(
            "EXPORT ONLY THE ORIGINAL ENCRYPTED SIGNATURE RETURN\nAuthorization: {}\nOriginal consent: {}\nSigned artifact: {}\nExact ciphertext: {}\nPinned recipient key: {}\nDestination: {}\nThis writes the already retained encrypted return, unchanged. No signing, resealing, deadline extension, delivery acknowledgment or payment is performed. An expired original remains expired. The receiving online owner must recheck the exact original full artifact, signatures and current witness/source/chain validity before any submission. The selected private directory identity is part of this decision; an existing file will never be overwritten.\nExact native review: {}",
            authorization,
            final_review.consent_reference,
            result.result_digest,
            returned.envelope_digest,
            original.terms.return_recipient_key_digest,
            destination.display_path().display(),
            digest
        );
        records.check_current().map_err(unavailable)?;
        self.source.check_current().map_err(unavailable)?;
        operation.check()?;
        Ok(PreparedNamedRecipientReturnFile {
            operation,
            profile: LiveNamedRecipientProfile {
                record: profile,
                journal: self.journal.clone(),
                source: self.source.clone(),
            },
            original,
            started,
            result,
            destination,
            created: Instant::now(),
            digest,
            display,
        })
    }
}
impl PreparedNamedRecipientReturnFile {
    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn display(&self) -> &str {
        &self.display
    }
    pub(crate) fn write(
        self,
        decision: NativeDecision,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
    ) -> ImportResult<()> {
        require_profile_owner(&self.profile, journal)?;
        if decision.binding() != &self.profile.source || decision.reviewed_digest() != self.digest {
            return Err(TransportError::DisclosureDenied);
        }
        let deadline = self
            .created
            .checked_add(Duration::from_secs(120))
            .ok_or(TransportError::InvalidTime)?;
        let records = journal
            .acquire_preconstruction_records(
                &self.profile.record.enrollment_ref,
                &self.profile.record.manifest_ref,
                session,
            )
            .map_err(unavailable)?;
        let own = retained_own_policy(&self.original, vault)?;
        require_own_context(&self.profile, &self.original, &own, vault, &records)?;
        if let Some(origin) = &self.original.born_origin {
            origin
                .require_retained_signer(
                    &*journal.connection.lock().map_err(unavailable)?,
                    &self.profile.record,
                    records.enrollment(),
                )
                .map_err(unavailable)?;
            origin
                .checkpoint_receipt
                .require_retained(&*journal.connection.lock().map_err(unavailable)?)
                .map_err(unavailable)?;
        }
        let (started, result) = read_result(journal, &self.original, &self.profile.record)?;
        if started != self.started || result != self.result {
            return Err(TransportError::WrongContext);
        }
        let returned = result
            .encrypted_return
            .as_ref()
            .ok_or(TransportError::AuthorityUnavailable)?;
        let bytes = Zeroizing::new(hex::decode(&returned.envelope_hex).map_err(unavailable)?);
        let current = || {
            self.operation.check()?;
            records.check_current().map_err(unavailable)?;
            check_setup_current(&self.profile.source, deadline).map_err(unavailable)?;
            self.destination.check_directory()
        };
        current()?;
        let _publication = self
            .profile
            .source
            .publication_lease()
            .map_err(unavailable)?;
        current()?;
        let mut file = self.destination.allocate()?;
        (|| -> ImportResult<()> {
            current()?;
            file.write_all(&bytes).map_err(unavailable)?;
            file.sync_all().map_err(unavailable)?;
            self.destination.check_created(&file, bytes.len() as u64)?;
            self.destination.sync_parent()?;
            current()
        })()
        .map_err(|_| TransportError::ImportCommittedButUnavailable)
    }
}
fn read_result(
    journal: &SignerConsentJournal,
    original: &NamedRecipientOriginalRecordV1,
    profile: &NamedRecipientProfileRecordV1,
) -> ImportResult<(NamedRecipientStartedRecordV1, NamedRecipientResultRecordV1)> {
    let c = journal.connection.lock().map_err(unavailable)?;
    let started: String = c
        .query_row(
            "SELECT payload FROM signer_named_recipient_started WHERE authorization_id=?1",
            [&original.terms.authorization_id],
            |r| r.get(0),
        )
        .map_err(|_| TransportError::ImportCommittedButUnavailable)?;
    let started: NamedRecipientStartedRecordV1 = decode(started).map_err(unavailable)?;
    started.validate(original).map_err(unavailable)?;
    if started.return_metadata().is_err() {
        return Err(TransportError::AuthorityUnavailable);
    }
    let result: String = c
        .query_row(
            "SELECT payload FROM signer_named_recipient_results WHERE authorization_id=?1",
            [&original.terms.authorization_id],
            |r| r.get(0),
        )
        .map_err(|_| TransportError::ImportCommittedButUnavailable)?;
    let result: NamedRecipientResultRecordV1 = decode(result).map_err(unavailable)?;
    result.validate(&started, original).map_err(unavailable)?;
    if let Some(review) = &started.born_final_review {
        review
            .validate_profile(profile, original)
            .map_err(unavailable)?;
        review
            .admission_receipt
            .require_retained(&c)
            .map_err(unavailable)?;
    }
    Ok((started, result))
}

/// Separate nominal born export owner; no legacy constructor accepts a born original.
pub(crate) struct PreparedBornNamedRecipientReturnFile(PreparedNamedRecipientReturnFile);
impl PreparedBornNamedRecipientReturnFile {
    pub(crate) fn digest(&self) -> &str {
        self.0.digest()
    }
    pub(crate) fn display(&self) -> &str {
        self.0.display()
    }
    pub(crate) fn write(
        self,
        decision: NativeDecision,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
    ) -> ImportResult<()> {
        self.0.write(decision, journal, session, vault)
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
impl PreparedBornNamedRecipientReturnFile {
    /// Only the actual validated original/result export owner supplies these.
    /// The finite caller exposes them only after this same export succeeds.
    pub(crate) fn synthetic_original_references(
        &self,
    ) -> ImportResult<crate::consent_journal::OriginalNamedReturnReferencesV1> {
        let original = &self.0.original;
        let origin = original
            .born_origin
            .as_ref()
            .ok_or(TransportError::WrongContext)?;
        Ok(crate::consent_journal::OriginalNamedReturnReferencesV1 {
            authorization_id: original.terms.authorization_id.clone(),
            original_ref: original.reference.clone(),
            born_origin_digest: origin.digest().map_err(unavailable)?,
        })
    }
}
