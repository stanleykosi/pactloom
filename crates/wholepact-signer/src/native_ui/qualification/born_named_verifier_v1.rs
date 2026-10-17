//! Same-controller finite verifier lane. Disclosure serving remains asynchronous
//! so the actual verifier worker can release its held leases before GUI drain.
use super::*;
use crate::native_ui::born_manual_roster_v2::named_verifier_disclosure::Prepared;
use wholepact_signer_origin::named_verifier_policy::NamedVerifierPolicyScopeV1;

impl NamedContinuationFixtureV1 {
    pub(in crate::native_ui) fn arm_original_verifier_scope(
        &mut self,
        scope: NamedVerifierPolicyScopeV1,
    ) -> Result<PathBuf> {
        self.check_source()?;
        if !matches!(self.phase, Phase::Ready) {
            return Err(Error::ReviewMismatch);
        }
        let epoch = self.controller.epoch;
        self.controller
            .ui
            .synthetic_begin_verifier_lane(scope.clone(), epoch)?;
        drain(&mut self.controller.ui, epoch)?;
        if !matches!(self.controller.ui.review.as_ref().map(|r| &r.step),
            Some(Step::Named(step)) if matches!(step.as_ref(), NamedStep::Verifier(p) if matches!(p.as_ref(), Prepared::Select(_))))
        {
            return Err(Error::ReviewMismatch);
        }
        approve_current(&mut self.controller.ui, epoch)?;
        self.check_source()?;
        self.selected_verifier_scope = Some(scope);
        self.controller.ui.synthetic_verifier_endpoint()
    }
    pub(in crate::native_ui) fn require_verifier_lane(
        &self,
        scope: &NamedVerifierPolicyScopeV1,
        endpoint: &str,
    ) -> Result<()> {
        self.check_source()?;
        if self.selected_verifier_scope.as_ref() != Some(scope)
            || self.controller.ui.synthetic_verifier_endpoint()? != PathBuf::from(endpoint)
            || !self.controller.ui.synthetic_verifier_engaged()
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(in crate::native_ui) fn named_public_context(&self) -> Result<(String, String, [u8; 32])> {
        self.check_source()?;
        self.controller
            .ui
            .synthetic_named_public_context(self.controller.epoch)
    }
    pub(in crate::native_ui) fn poll_original_verifier_disclosure(&mut self) -> Result<bool> {
        let epoch = self.controller.epoch;
        self.controller.ui.poll_lifecycle(true, epoch);
        self.controller.ui.owner(epoch)?;
        if self.controller.ui.job.is_some() {
            return Ok(false);
        }
        if let Some(review) = self.controller.ui.review.as_mut() {
            if !matches!(&review.step, Step::Named(step) if matches!(step.as_ref(),
                NamedStep::Verifier(p) if matches!(p.as_ref(), Prepared::Pair {..} | Prepared::Disclose {..})))
                || review.exact.confirming()
                || review.exact.display().is_empty()
            {
                return Err(Error::ReviewMismatch);
            }
            review.displayed_to_end = true;
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
            self.controller.ui.confirmation =
                Zeroizing::new(format!("AUTHORIZE {}", &review.exact.digest()[..12]));
            // Same controller consume, but do not block its peers by draining a
            // real held-FVK server before the verifier has finished its work.
            self.controller.ui.approve(true, epoch)?;
            return Ok(false);
        }
        if self.controller.ui.synthetic_verifier_engaged() {
            return Ok(false);
        }
        self.check_source()?;
        if let Some(completed) = self.selected_verifier_scope.take() {
            if self.completed_verifier_scopes.len() >= 2
                || self.completed_verifier_scopes.contains(&completed)
            {
                return Err(Error::ReviewMismatch);
            }
            self.completed_verifier_scopes.push(completed);
        }
        Ok(true)
    }
}
