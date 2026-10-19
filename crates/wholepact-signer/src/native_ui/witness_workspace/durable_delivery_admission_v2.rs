//! Owner-mTLS adapter for prospective v2 admission only. The caller owns the
//! genuine original imported source, local retained intent and native decision.
use super::*;
use std::time::Instant;
use wholepact_authority::{AccountSnapshot, OwnerControlRequest};
impl NativeWitnessWorkspace {
    pub(in crate::native_ui) fn durable_delivery_admit_v2(
        &self,
        request: &OwnerControlRequest,
        deadline: Instant,
        mut check: impl FnMut() -> Result<()>,
        #[cfg(feature = "synthetic-born-joined-qualification")] failure: &mut Option<
            wholepact_authority::transport::history_diagnostics_v1::CheckedHistoryFailureV1,
        >,
    ) -> Result<AccountSnapshot> {
        self.check_current()?;
        check()?;
        let mut callback_error = None;
        let current = || {
            self.check_current().and_then(|_| check()).map_err(|error| {
                if callback_error.is_none() {
                    callback_error = Some(error);
                }
                wholepact_authority::AuthorityError::Permission
            })
        };
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let result = self
            .client
            .admit_durable_payment_with_delivery_v2_diagnosed_checked_until(
                request, deadline, current,
            )
            .map_err(|error| {
                *failure = Some(error);
                Error::Uncertain
            });
        #[cfg(not(feature = "synthetic-born-joined-qualification"))]
        let result = self
            .client
            .admit_durable_payment_with_delivery_v2_checked_until(request, deadline, current)
            .map_err(|_| Error::Uncertain);
        if let Some(error) = callback_error {
            return Err(error);
        }
        let snapshot = result?;
        self.check_current()?;
        check()?;
        Ok(snapshot)
    }
    pub(in crate::native_ui) fn durable_delivery_history_v2(
        &self,
        deadline: Instant,
        mut check: impl FnMut() -> Result<()>,
        #[cfg(feature = "synthetic-born-joined-qualification")] failure: &mut Option<
            wholepact_authority::transport::history_diagnostics_v1::CheckedHistoryFailureV1,
        >,
    ) -> Result<wholepact_authority::ReconciledAuthorityHistory> {
        self.check_current()?;
        check()?;
        let mut callback_error = None;
        let current = || {
            self.check_current().and_then(|_| check()).map_err(|error| {
                if callback_error.is_none() {
                    callback_error = Some(error);
                }
                wholepact_authority::AuthorityError::Permission
            })
        };
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let result = self
            .client
            .reconcile_history_diagnosed_checked_until(deadline, current)
            .map_err(|error| {
                *failure = Some(error);
                Error::Uncertain
            });
        #[cfg(not(feature = "synthetic-born-joined-qualification"))]
        let result = self
            .client
            .reconcile_history_checked_until(deadline, current)
            .map_err(|_| Error::Uncertain);
        if let Some(error) = callback_error {
            return Err(error);
        }
        let history = result?;
        self.check_current()?;
        check()?;
        Ok(history)
    }
}
