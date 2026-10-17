//! Concrete synthetic delivery of notices from the SAME actual assertion worker.
//! No caller may supply a review digest, source, decision, lease or signing key.
use super::*;
impl AssertionWorkspace {
    pub(in crate::native_ui::named_verifier_owner) fn poll_synthetic_original(
        &mut self,
        password: &str,
        epoch: u64,
    ) -> Result<Option<String>> {
        if self.cancelled {
            return Err(Error::Locked);
        }
        self.worker.reap();
        self.frame = self.frame.saturating_add(1);
        if self
            .native
            .as_ref()
            .is_some_and(|n| n.check_current().is_err())
        {
            self.cancel();
            return Err(Error::Locked);
        }
        while let Ok(notice) = self.worker.notices.try_recv() {
            match notice {
                Notice::NeedOwner => {
                    self.review = None;
                    self.native.take();
                    self.need_owner = true;
                }
                Notice::PeerWait => {
                    self.review = None;
                    self.native.take();
                    self.need_owner = false;
                }
                Notice::Review { digest, display } => {
                    if self.review.is_some() {
                        return Err(Error::ReviewMismatch);
                    }
                    self.review = Some(Review {
                        exact: ExactNativeReview::stage(
                            self.native.as_ref().ok_or(Error::Locked)?,
                            &digest,
                            display.to_string(),
                            epoch,
                        )?,
                        shown: self.frame,
                        continued: None,
                    });
                }
                Notice::Finished(result) => {
                    self.need_owner = false;
                    self.review = None;
                    self.native.take();
                    self.phrase.zeroize();
                    self.password.zeroize();
                    return result.map(Some);
                }
            }
        }
        if self.need_owner {
            let native =
                NativeAuthority::entered_named_verifier_window(self.worker.lifetime.deadline())?;
            let owner = VerifierOwner::open(&self.profile, password.as_bytes(), &native)?;
            self.worker.submit_owner(owner)?;
            self.native = Some(native);
            self.need_owner = false;
        }
        if let Some(review) = self.review.as_mut() {
            if review.exact.expired() || review.exact.display().is_empty() {
                return Err(Error::Locked);
            }
            if !review.exact.confirming() && self.frame > review.shown {
                if review
                    .exact
                    .continue_from_native_click(false, epoch)
                    .is_ok()
                    || review
                        .exact
                        .continue_from_native_click(true, epoch.wrapping_add(1))
                        .is_ok()
                {
                    return Err(Error::ReviewMismatch);
                }
                review.exact.continue_from_native_click(true, epoch)?;
                review.continued = Some(self.frame);
            } else if review.continued.is_some_and(|f| self.frame > f) {
                let review = self.review.take().ok_or(Error::Locked)?;
                let phrase = Zeroizing::new(format!("AUTHORIZE {}", &review.exact.digest()[..12]));
                self.worker
                    .decide(review.exact.consume_native_click(true, epoch, &phrase)?)?;
            }
        }
        Ok(None)
    }
    pub(in crate::native_ui::named_verifier_owner) fn drain_synthetic_original(&mut self) {
        self.cancel();
        while !self.worker.synthetic_finished() {
            self.worker.reap();
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        self.worker.reap();
    }
}
