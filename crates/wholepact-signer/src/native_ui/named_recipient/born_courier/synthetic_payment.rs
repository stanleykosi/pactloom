//! One explicit synthetic native courier decision for the exact retained file.
//! No automatic retry or delivery resealing; ambiguous outcomes are errors.
use super::*;
impl BornCourierWorkspace {
    pub(in crate::native_ui::named_recipient) fn synthetic_submit_original(
        &mut self,
        profile: &LiveNamedRecipientProfile,
        owner: &NamedRecipientOwnerContext<'_>,
        witness: &Arc<NativeWitnessWorkspace>,
        path: &Path,
        epoch: u64,
    ) -> Result<()> {
        if self.is_active() || self.delivery.is_some() {
            return Err(Error::Locked);
        }
        self.handoff_path = path.to_str().ok_or(Error::InvalidData)?.into();
        self.prepare_courier(
            profile,
            owner,
            witness,
            BornCourierActionV1::SubmitOriginal,
            epoch,
        )?;
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
        if !matches!(&p.operation, Operation::Courier(_))
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
        if self.pending.is_some() || self.delivery.is_none() {
            return Err(Error::Uncertain);
        }
        Ok(())
    }
}
