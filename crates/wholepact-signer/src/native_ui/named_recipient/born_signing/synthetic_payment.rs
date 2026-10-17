//! Actual final native review/Started/protected-key/result plus separate export.
//! Synthetic exact event delivery is not attended-human qualification.
use super::*;
impl BornSigningWorkspace {
    fn synthetic_finish_step(
        &mut self,
        owner: &NamedRecipientOwnerContext<'_>,
        witness: &Arc<NativeWitnessWorkspace>,
        epoch: u64,
    ) -> Result<Option<crate::consent_journal::OriginalNamedReturnReferencesV1>> {
        loop {
            owner.authority.check_current()?;
            self.operation
                .as_ref()
                .ok_or(Error::Locked)?
                .check()
                .map_err(|_| Error::Locked)?;
            self.poll(owner, epoch)?;
            if self.pending.is_some() {
                break;
            }
            if self.job.is_none() {
                return Err(Error::ReviewMismatch);
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let p = self.pending.as_mut().ok_or(Error::Locked)?;
        if matches!(&p.operation, Operation::Evidence(_))
            || p.review.confirming()
            || p.review.display().is_empty()
            || p.review.continue_from_native_click(false, epoch).is_ok()
            || p.review.continue_from_native_click(true, epoch + 1).is_ok()
        {
            return Err(Error::ReviewMismatch);
        }
        self.frame = self.frame.saturating_add(1);
        if self.frame <= p.shown {
            return Err(Error::ReviewMismatch);
        }
        p.review.continue_from_native_click(true, epoch)?;
        p.continued = Some(self.frame);
        self.frame = self.frame.saturating_add(1);
        if !p.continued.is_some_and(|f| self.frame > f) {
            return Err(Error::ReviewMismatch);
        }
        self.phrase = Zeroizing::new(format!("AUTHORIZE {}", &p.review.digest()[..12]));
        let references = match &p.operation {
            Operation::Export(prepared) => Some(
                prepared
                    .synthetic_original_references()
                    .map_err(|_| Error::Verification)?,
            ),
            Operation::Sign(_) => None,
            Operation::Evidence(_) => return Err(Error::ReviewMismatch),
        };
        let step_operation = self.operation.as_ref().ok_or(Error::Locked)?.clone();
        step_operation.check().map_err(|_| Error::Locked)?;
        self.approve_pending(owner, Some(witness), true, epoch)?;
        while self.job.is_some() {
            step_operation.check().map_err(|_| Error::Locked)?;
            owner.authority.check_current()?;
            self.poll(owner, epoch)?;
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        // Reaped cancellation/late work cannot masquerade as success.
        step_operation.check().map_err(|_| Error::Locked)?;
        owner.authority.check_current()?;
        if self.pending.is_some() {
            return Err(Error::ReviewMismatch);
        }
        Ok(references)
    }
    pub(in crate::native_ui::named_recipient) fn synthetic_sign_and_export(
        &mut self,
        profile: &LiveNamedRecipientProfile,
        owner: &NamedRecipientOwnerContext<'_>,
        witness: &Arc<NativeWitnessWorkspace>,
        authorization: &str,
        destination: &std::path::Path,
        epoch: u64,
    ) -> Result<crate::consent_journal::OriginalNamedReturnReferencesV1> {
        if self.is_active() {
            return Err(Error::Locked);
        }
        witness.require_native_origin(&owner.authority.binding())?;
        self.authorization = authorization.into();
        let profile1 = profile.clone();
        let journal = owner.journal.clone();
        let session = owner.session.clone();
        let vault = owner.vault.clone();
        let id = authorization.to_owned();
        let w = witness.clone();
        let op = NamedRecipientOperation::new();
        self.operation = Some(op.clone());
        self.job = Some(Job::start(epoch, move || {
            Ok(Output::Review(Operation::Sign(Box::new(
                profile1
                    .prepare_born_final_signing(&journal, &session, &vault, w.client(), &id, op)
                    .map_err(|_| Error::Verification)?,
            ))))
        })?);
        if self.synthetic_finish_step(owner, witness, epoch)?.is_some() {
            return Err(Error::ReviewMismatch);
        }
        let profile = profile.clone();
        let journal = owner.journal.clone();
        let session = owner.session.clone();
        let vault = owner.vault.clone();
        let id = authorization.to_owned();
        let path = destination.to_path_buf();
        let op = NamedRecipientOperation::new();
        self.operation = Some(op.clone());
        self.job = Some(Job::start(epoch, move || {
            Ok(Output::Review(Operation::Export(Box::new(
                profile
                    .prepare_born_retained_return_file(&journal, &session, &vault, &id, &path, op)
                    .map_err(|_| Error::Verification)?,
            ))))
        })?);
        self.synthetic_finish_step(owner, witness, epoch)?
            .ok_or(Error::Uncertain)
    }
}
