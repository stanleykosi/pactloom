//! Finite synthetic controller event delivery over real first-original jobs.
//! No NativeDecision constructor, raw signer owner or authority is exposed.
use super::*;
impl BornInboxWorkspace {
    fn synthetic_finish_step(
        &mut self,
        owner: &NamedRecipientOwnerContext<'_>,
        witness: &Arc<NativeWitnessWorkspace>,
        epoch: u64,
    ) -> Result<()> {
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
        if p.review.confirming()
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
        Ok(())
    }
    pub(in crate::native_ui::named_recipient) fn synthetic_retain_and_export(
        &mut self,
        profile: &LiveNamedRecipientProfile,
        owner: &NamedRecipientOwnerContext<'_>,
        witness: &Arc<NativeWitnessWorkspace>,
        inputs: crate::consent_journal::BornNamedRecipientOriginalInputs,
        destination: &Path,
        epoch: u64,
    ) -> Result<String> {
        if self.is_active() || self.retained.is_some() {
            return Err(Error::Locked);
        }
        witness.require_native_origin(&owner.authority.binding())?;
        let profile = profile.clone();
        let journal = owner.journal.clone();
        let session = owner.session.clone();
        let vault = owner.vault.clone();
        let w = witness.clone();
        let op = NamedRecipientOperation::new();
        self.operation = Some(op.clone());
        self.job = Some(Job::start(epoch, move || {
            Ok(Output::Review(Operation::Original(Box::new(
                profile
                    .prepare_born_original_import(
                        &journal,
                        &session,
                        &vault,
                        w.client(),
                        inputs,
                        op,
                    )
                    .map_err(|_| Error::Verification)?,
            ))))
        })?);
        self.synthetic_finish_step(owner, witness, epoch)?;
        let retained = self.retained.take().ok_or(Error::Uncertain)?;
        let authorization = retained.authorization_id().to_owned();
        let journal = owner.journal.clone();
        let session = owner.session.clone();
        let vault = owner.vault.clone();
        let path = destination.to_path_buf();
        let op = NamedRecipientOperation::new();
        self.operation = Some(op.clone());
        self.job = Some(Job::start(epoch, move || {
            Ok(Output::Review(Operation::Export(Box::new(
                retained
                    .prepare_file_export(&journal, &session, &vault, &path, op)
                    .map_err(|_| Error::Verification)?,
            ))))
        })?);
        self.synthetic_finish_step(owner, witness, epoch)?;
        if self.authorization != authorization {
            return Err(Error::ReviewMismatch);
        }
        Ok(authorization)
    }
}
