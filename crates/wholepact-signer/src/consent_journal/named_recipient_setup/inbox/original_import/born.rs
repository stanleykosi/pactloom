//! Genuine native born-original intake. The shared private transactional kernel
//! still authenticates named evidence and independent own effects before rows.
//! Legacy entry points reject this origin; no authority or permit is projected.
use super::super::{NamedRecipientOperation, born_original_history};
use super::*;
use wholepact_authority::AuthorityClient;

pub(crate) struct BornNamedRecipientOriginalInputs {
    pub(crate) original: NamedRecipientOriginalInputs,
    pub(crate) checkpoint_envelope: EncryptedEnvelope,
}
pub(crate) struct PreparedBornNamedRecipientOriginalImport {
    inner: PreparedNamedRecipientOriginalImport,
    operation: NamedRecipientOperation,
}
pub(crate) struct RetainedBornNamedIntentExport {
    inner: RetainedNamedIntentExport,
}
pub(crate) struct PreparedBornNamedIntentFileExport {
    inner: PreparedNamedIntentFileExport,
}

fn check(
    profile: &LiveNamedRecipientProfile,
    operation: &NamedRecipientOperation,
) -> ImportResult<()> {
    operation.check()?;
    profile.source.check_current().map_err(unavailable)
}
fn authenticate_current_parents(
    profile: &LiveNamedRecipientProfile,
    original: &NamedRecipientOriginalRecordV1,
    client: &AuthorityClient,
    operation: &NamedRecipientOperation,
    deadline: Instant,
) -> ImportResult<()> {
    check(profile, operation)?;
    let expected = original
        .born_origin
        .as_ref()
        .ok_or(TransportError::WrongContext)?;
    let history = client
        .reconcile_history_checked_until(deadline, || {
            check(profile, operation).map_err(|_| wholepact_authority::AuthorityError::Permission)
        })
        .map_err(unavailable)?;
    let actual =
        born_original_history::authenticate_parent_draft(profile, original, &history, client)?;
    if &actual != expected {
        return Err(TransportError::WrongContext);
    }
    check(profile, operation)
}
impl LiveNamedRecipientProfile {
    pub(crate) fn prepare_born_original_import(
        &self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
        client: &AuthorityClient,
        inputs: BornNamedRecipientOriginalInputs,
        operation: NamedRecipientOperation,
    ) -> ImportResult<PreparedBornNamedRecipientOriginalImport> {
        check(self, &operation)?;
        if inputs.original.proposed.born_origin.is_none() {
            return Err(TransportError::WrongContext);
        }
        let checkpoint_envelope = inputs.checkpoint_envelope;
        let mut inner =
            self.prepare_original_import_inner(journal, session, vault, inputs.original)?;
        inner.operation = Some(operation.clone());
        inner.checkpoint_input = Some(
            super::super::born_checkpoint_input::prepare_checkpoint_input(
                self,
                &inner.original,
                checkpoint_envelope,
                inner.original_window_deadline.min(operation.deadline()),
                || {
                    operation.check()?;
                    super::born_courier::profile_current(self, journal, session)
                },
            )?,
        );
        authenticate_current_parents(
            self,
            &inner.original,
            client,
            &operation,
            inner
                .original_window_deadline
                .min(inner.created + Duration::from_secs(120)),
        )?;
        Ok(PreparedBornNamedRecipientOriginalImport { inner, operation })
    }
    pub(crate) fn recover_born_original_intent_export(
        &self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
        authorization_id: &str,
    ) -> ImportResult<Option<RetainedBornNamedIntentExport>> {
        let value =
            self.recover_original_intent_export_inner(journal, session, vault, authorization_id)?;
        match value {
            None => Ok(None),
            Some(inner) => {
                let origin = inner
                    .original
                    .born_origin
                    .as_ref()
                    .ok_or(TransportError::WrongContext)?;
                let records = journal
                    .acquire_preconstruction_records(
                        &self.record.enrollment_ref,
                        &self.record.manifest_ref,
                        session,
                    )
                    .map_err(unavailable)?;
                let c = journal
                    .connection
                    .lock()
                    .map_err(|_| TransportError::Storage)?;
                origin
                    .require_retained_signer(&c, &self.record, records.enrollment())
                    .map_err(|_| TransportError::WrongContext)?;
                records.check_current().map_err(unavailable)?;
                self.source.check_current().map_err(unavailable)?;
                Ok(Some(RetainedBornNamedIntentExport { inner }))
            }
        }
    }
}
impl PreparedBornNamedRecipientOriginalImport {
    pub(crate) fn digest(&self) -> &str {
        self.inner.digest()
    }
    pub(crate) fn display(&self) -> &str {
        self.inner.display()
    }
    pub(crate) fn authorization_id(&self) -> &str {
        self.inner.authorization_id()
    }
    pub(crate) fn approve(
        self,
        decision: NativeDecision,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
        client: &AuthorityClient,
        now: &Timestamp,
    ) -> ImportResult<RetainedBornNamedIntentExport> {
        if decision.binding() != &self.inner.profile.source
            || decision.reviewed_digest() != self.inner.digest
        {
            return Err(TransportError::WrongContext);
        }
        let deadline = review_deadline(self.inner.created, &decision)?
            .min(self.inner.original_window_deadline);
        // No DB lock or publication fence is held across authenticated network I/O.
        authenticate_current_parents(
            &self.inner.profile,
            &self.inner.original,
            client,
            &self.operation,
            deadline,
        )?;
        let inner = self
            .inner
            .approve_inner(decision, journal, session, vault, now)?;
        Ok(RetainedBornNamedIntentExport { inner })
    }
}
impl RetainedBornNamedIntentExport {
    pub(crate) fn display(&self) -> &str {
        self.inner.display()
    }
    pub(crate) fn authorization_id(&self) -> &str {
        self.inner.authorization_id()
    }
    pub(crate) fn original_ref(&self) -> &str {
        self.inner.original_ref()
    }
    pub(crate) fn prepare_file_export(
        self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
        destination: &Path,
        operation: NamedRecipientOperation,
    ) -> ImportResult<PreparedBornNamedIntentFileExport> {
        operation.check()?;
        if self.inner.original.born_origin.is_none() {
            return Err(TransportError::WrongContext);
        }
        let mut inner =
            self.inner
                .prepare_file_export_inner(journal, session, vault, destination)?;
        operation.check()?;
        inner.operation = Some(operation);
        Ok(PreparedBornNamedIntentFileExport { inner })
    }
}
impl PreparedBornNamedIntentFileExport {
    pub(crate) fn digest(&self) -> &str {
        self.inner.digest()
    }
    pub(crate) fn display(&self) -> &str {
        self.inner.display()
    }
    pub(crate) fn write_new_file(
        self,
        decision: NativeDecision,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
    ) -> ImportResult<()> {
        self.inner.write_new_file(decision, journal, session, vault)
    }
}
