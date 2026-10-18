//! Actual selected mTLS credentials only. Imported-source and native decision
//! custody stays in runtime; these adapters cannot mint financial permission.
use super::*;
#[cfg(feature = "synthetic-born-joined-qualification")]
use crate::authority_bridge::durable_flow_diagnostics_v1 as flow_diag_v1;
macro_rules! workspace_flow_observe_v1 {
    ($observer:expr, $stage:expr, $original:expr) => {{
        let original = $original;
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let original = flow_diag_v1::observe_result($observer, $stage, original);
        original
    }};
}

use std::time::Instant;
#[cfg(feature = "synthetic-born-joined-qualification")]
use wholepact_authority::transport::history_diagnostics_v1::CheckedHistoryFailureV1;
use wholepact_authority::{
    AccountSnapshot, AuthenticatedWriterSession, OwnerControlRequest, ReconciledAuthorityHistory,
    WriterSessionReceipt,
};

impl NativeWitnessWorkspace {
    pub(in crate::native_ui) fn durable_instance_v1(&self) -> std::sync::Arc<()> {
        self.instance.clone()
    }
    pub(in crate::native_ui) fn require_durable_instance_v1(
        &self,
        instance: &std::sync::Arc<()>,
    ) -> Result<()> {
        if !same_actual_workspace(&self.instance, instance) {
            return Err(Error::RecoveryRequired);
        }
        self.check_current()
    }

    pub(in crate::native_ui) fn require_durable_credential_v1(
        &self,
        origin: &NativeAuthorityBinding,
        disclosure: &WitnessDisclosureDescriptor,
        expected_certificate: &str,
    ) -> Result<()> {
        self.require_native_origin(origin)?;
        if self.disclosure() != *disclosure
            || self.account_id != disclosure.account_id
            || self.writer_certificate_digest != expected_certificate
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }

    pub(in crate::native_ui) fn durable_history_v1(
        &self,
        deadline: Instant,
        check: impl FnMut() -> Result<()>,
    ) -> Result<ReconciledAuthorityHistory> {
        self.durable_history_inner_v1(
            deadline,
            check,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            None,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            None,
        )
    }

    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(in crate::native_ui) fn durable_history_diagnosed_v1(
        &self,
        deadline: Instant,
        check: impl FnMut() -> Result<()>,
        failure: &mut Option<(CheckedHistoryFailureV1, Option<Error>)>,
    ) -> Result<ReconciledAuthorityHistory> {
        self.durable_history_inner_v1(deadline, check, Some(failure), None)
    }

    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(in crate::native_ui) fn durable_history_flow_v1(
        &self,
        deadline: Instant,
        check: impl FnMut() -> Result<()>,
        observer: Option<&flow_diag_v1::DurableFlowObserverV1>,
        stage: flow_diag_v1::DurableFlowStageV1,
    ) -> Result<ReconciledAuthorityHistory> {
        self.durable_history_inner_v1(
            deadline,
            check,
            None,
            observer.map(|observer| (observer, stage)),
        )
    }
    fn durable_history_inner_v1(
        &self,
        deadline: Instant,
        mut check: impl FnMut() -> Result<()>,
        #[cfg(feature = "synthetic-born-joined-qualification")] failure: Option<
            &mut Option<(CheckedHistoryFailureV1, Option<Error>)>,
        >,
        #[cfg(feature = "synthetic-born-joined-qualification")] flow: Option<(
            &flow_diag_v1::DurableFlowObserverV1,
            flow_diag_v1::DurableFlowStageV1,
        )>,
    ) -> Result<ReconciledAuthorityHistory> {
        workspace_flow_observe_v1!(
            flow.map(|(observer, _)| observer),
            flow.map(|(_, stage)| stage)
                .unwrap_or(flow_diag_v1::DurableFlowStageV1::FixtureState),
            self.check_current()
        )?;
        workspace_flow_observe_v1!(
            flow.map(|(observer, _)| observer),
            flow.map(|(_, stage)| stage)
                .unwrap_or(flow_diag_v1::DurableFlowStageV1::FixtureState),
            check()
        )?;
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let mut callback_failure = None;
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let observed = failure.is_some();
        let current = || {
            self.check_current()
                .and_then(|_| check())
                .map_err(|_error| {
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    if let Some((observer, stage)) = flow {
                        observer.record_error(stage, &_error);
                    }
                    // The SAME callback Error is retained only for the exact
                    // synthetic observation; the authority result is unchanged.
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    {
                        observe_history_callback_error(observed, &mut callback_failure, _error)
                    }
                    #[cfg(not(feature = "synthetic-born-joined-qualification"))]
                    wholepact_authority::AuthorityError::Permission
                })
        };
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let history = if let Some(failure) = failure {
            self.client
                .reconcile_history_diagnosed_checked_until(deadline, current)
                .map_err(|authority_error| {
                    if failure.is_none() {
                        *failure = Some((authority_error, callback_failure));
                    }
                    Error::Uncertain
                })?
        } else {
            self.client
                .reconcile_history_checked_until(deadline, current)
                .map_err(|error| {
                    if let Some((observer, stage)) = flow {
                        observer.record_error(stage, &error);
                    }
                    Error::Uncertain
                })?
        };
        #[cfg(not(feature = "synthetic-born-joined-qualification"))]
        let history = self
            .client
            .reconcile_history_checked_until(deadline, current)
            .map_err(|_| Error::Uncertain)?;
        workspace_flow_observe_v1!(
            flow.map(|(observer, _)| observer),
            flow.map(|(_, stage)| stage)
                .unwrap_or(flow_diag_v1::DurableFlowStageV1::FixtureState),
            check()
        )?;
        if history.disclosure() != &self.disclosure()
            || history.snapshot().account_id != self.account_id
        {
            return Err(Error::Authentication);
        }
        Ok(history)
    }

    pub(in crate::native_ui) fn durable_admit_v1(
        &self,
        request: &OwnerControlRequest,
        deadline: Instant,
        check: impl FnMut() -> Result<()>,
    ) -> Result<AccountSnapshot> {
        self.durable_admit_inner_v1(
            request,
            deadline,
            check,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            None,
        )
    }

    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(in crate::native_ui) fn durable_admit_diagnosed_v1(
        &self,
        request: &OwnerControlRequest,
        deadline: Instant,
        check: impl FnMut() -> Result<()>,
        failure: &mut Option<(CheckedHistoryFailureV1, Option<Error>, bool)>,
    ) -> Result<AccountSnapshot> {
        self.durable_admit_inner_v1(request, deadline, check, Some(failure))
    }

    fn durable_admit_inner_v1(
        &self,
        request: &OwnerControlRequest,
        deadline: Instant,
        mut check: impl FnMut() -> Result<()>,
        #[cfg(feature = "synthetic-born-joined-qualification")] failure: Option<
            &mut Option<(CheckedHistoryFailureV1, Option<Error>, bool)>,
        >,
    ) -> Result<AccountSnapshot> {
        check()?;
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let observed = failure.is_some();
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let mut callback_failure = None;
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let mut first_workspace_current = false;
        let current = || {
            #[cfg(feature = "synthetic-born-joined-qualification")]
            let mut workspace_current = true;
            self.check_current()
                .and_then(|_| {
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    {
                        workspace_current = false;
                    }
                    check()
                })
                .map_err(|_error| {
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    {
                        if observed && callback_failure.is_none() {
                            first_workspace_current = workspace_current;
                        }
                        observe_history_callback_error(observed, &mut callback_failure, _error)
                    }
                    #[cfg(not(feature = "synthetic-born-joined-qualification"))]
                    wholepact_authority::AuthorityError::Permission
                })
        };
        #[cfg(feature = "synthetic-born-joined-qualification")]
        if let Some(failure) = failure {
            return self
                .client
                .admit_durable_payment_v1_diagnosed_checked_until(request, deadline, current)
                .map_err(|authority| {
                    if failure.is_none() {
                        *failure = Some((authority, callback_failure, first_workspace_current));
                    }
                    Error::Uncertain
                });
        }
        self.client
            .admit_durable_payment_v1_checked_until(request, deadline, current)
            .map_err(|_| Error::Uncertain)
    }

    pub(in crate::native_ui) fn durable_acquire_v1(
        &self,
        history: &ReconciledAuthorityHistory,
        admission: &str,
        deadline: Instant,
        check: impl FnMut() -> Result<()>,
    ) -> Result<WriterSessionReceipt> {
        self.durable_acquire_inner_v1(
            history,
            admission,
            deadline,
            check,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            None,
        )
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(in crate::native_ui) fn durable_acquire_observed_v1(
        &self,
        history: &ReconciledAuthorityHistory,
        admission: &str,
        deadline: Instant,
        check: impl FnMut() -> Result<()>,
        observer: Option<&flow_diag_v1::DurableFlowObserverV1>,
    ) -> Result<WriterSessionReceipt> {
        self.durable_acquire_inner_v1(history, admission, deadline, check, observer)
    }
    fn durable_acquire_inner_v1(
        &self,
        history: &ReconciledAuthorityHistory,
        admission: &str,
        deadline: Instant,
        mut check: impl FnMut() -> Result<()>,
        #[cfg(feature = "synthetic-born-joined-qualification")] observer: Option<
            &flow_diag_v1::DurableFlowObserverV1,
        >,
    ) -> Result<WriterSessionReceipt> {
        workspace_flow_observe_v1!(
            observer,
            flow_diag_v1::DurableFlowStageV1::AcquireCall,
            check()
        )?;
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let mut callback_stage = None;
        let current = || {
            let result = self.check_current();
            #[cfg(feature = "synthetic-born-joined-qualification")]
            if let (Some(observer), Err(error)) = (observer, &result) {
                observer.record_error(flow_diag_v1::DurableFlowStageV1::AcquireCall, error);
                if callback_stage.is_none() {
                    callback_stage =
                        Some(flow_diag_v1::DurableFlowCallbackStageV1::WorkspaceCurrent);
                }
            }
            result
                .and_then(|_| {
                    let result = check();
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    if let (Some(observer), Err(error)) = (observer, &result) {
                        observer.record_error(flow_diag_v1::DurableFlowStageV1::AcquireCall, error);
                        if callback_stage.is_none() {
                            callback_stage =
                                Some(flow_diag_v1::DurableFlowCallbackStageV1::CallerCurrent);
                        }
                    }
                    result
                })
                .map_err(|_| wholepact_authority::AuthorityError::Permission)
        };
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let result = if let Some(observer) = observer {
            observer.call_enter(flow_diag_v1::DurableFlowCallV1::WriterAcquire);
            let result = self
                .client
                .acquire_durable_payment_writer_v1_diagnosed_checked_until(
                    history, admission, deadline, current,
                );
            let result = observer.observe_transport(
                flow_diag_v1::DurableFlowTransportPurposeV1::Acquire,
                flow_diag_v1::DurableFlowStageV1::AcquireCall,
                callback_stage,
                result,
            );
            observer.call_return(flow_diag_v1::DurableFlowCallV1::WriterAcquire, &result);
            result
        } else {
            self.client.acquire_durable_payment_writer_v1_checked_until(
                history, admission, deadline, current,
            )
        };
        #[cfg(not(feature = "synthetic-born-joined-qualification"))]
        let result = self
            .client
            .acquire_durable_payment_writer_v1_checked_until(history, admission, deadline, current);
        result.map_err(|_| Error::Uncertain)
    }
    pub(in crate::native_ui) fn durable_activate_v1(
        &self,
        history: &ReconciledAuthorityHistory,
        admission: &str,
        request: &OwnerControlRequest,
        deadline: Instant,
        check: impl FnMut() -> Result<()>,
    ) -> Result<AccountSnapshot> {
        self.durable_activate_inner_v1(
            history,
            admission,
            request,
            deadline,
            check,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            None,
        )
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(in crate::native_ui) fn durable_activate_observed_v1(
        &self,
        history: &ReconciledAuthorityHistory,
        admission: &str,
        request: &OwnerControlRequest,
        deadline: Instant,
        check: impl FnMut() -> Result<()>,
        observer: Option<&flow_diag_v1::DurableFlowObserverV1>,
    ) -> Result<AccountSnapshot> {
        self.durable_activate_inner_v1(history, admission, request, deadline, check, observer)
    }
    fn durable_activate_inner_v1(
        &self,
        history: &ReconciledAuthorityHistory,
        admission: &str,
        request: &OwnerControlRequest,
        deadline: Instant,
        mut check: impl FnMut() -> Result<()>,
        #[cfg(feature = "synthetic-born-joined-qualification")] observer: Option<
            &flow_diag_v1::DurableFlowObserverV1,
        >,
    ) -> Result<AccountSnapshot> {
        workspace_flow_observe_v1!(
            observer,
            flow_diag_v1::DurableFlowStageV1::ActivationCall,
            check()
        )?;
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let mut callback_stage = None;
        let current = || {
            let result = self.check_current();
            #[cfg(feature = "synthetic-born-joined-qualification")]
            if let (Some(observer), Err(error)) = (observer, &result) {
                observer.record_error(flow_diag_v1::DurableFlowStageV1::ActivationCall, error);
                if callback_stage.is_none() {
                    callback_stage =
                        Some(flow_diag_v1::DurableFlowCallbackStageV1::WorkspaceCurrent);
                }
            }
            result
                .and_then(|_| {
                    let result = check();
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    if let (Some(observer), Err(error)) = (observer, &result) {
                        observer
                            .record_error(flow_diag_v1::DurableFlowStageV1::ActivationCall, error);
                        if callback_stage.is_none() {
                            callback_stage =
                                Some(flow_diag_v1::DurableFlowCallbackStageV1::CallerCurrent);
                        }
                    }
                    result
                })
                .map_err(|_| wholepact_authority::AuthorityError::Permission)
        };
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let result = if let Some(observer) = observer {
            observer.call_enter(flow_diag_v1::DurableFlowCallV1::WriterActivate);
            let result = self
                .client
                .activate_durable_payment_writer_v1_diagnosed_checked_until(
                    history, admission, request, deadline, current,
                );
            let result = observer.observe_transport(
                flow_diag_v1::DurableFlowTransportPurposeV1::Activate,
                flow_diag_v1::DurableFlowStageV1::ActivationCall,
                callback_stage,
                result,
            );
            observer.call_return(flow_diag_v1::DurableFlowCallV1::WriterActivate, &result);
            result
        } else {
            self.client
                .activate_durable_payment_writer_v1_checked_until(
                    history, admission, request, deadline, current,
                )
        };
        #[cfg(not(feature = "synthetic-born-joined-qualification"))]
        let result = self
            .client
            .activate_durable_payment_writer_v1_checked_until(
                history, admission, request, deadline, current,
            );
        result.map_err(|_| Error::Uncertain)
    }
    pub(in crate::native_ui) fn durable_active_v1(
        &self,
        history: &ReconciledAuthorityHistory,
        admission: &str,
        deadline: Instant,
        check: impl FnMut() -> Result<()>,
    ) -> Result<AuthenticatedWriterSession> {
        self.durable_active_inner_v1(
            history,
            admission,
            deadline,
            check,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            None,
        )
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(in crate::native_ui) fn durable_active_observed_v1(
        &self,
        history: &ReconciledAuthorityHistory,
        admission: &str,
        deadline: Instant,
        check: impl FnMut() -> Result<()>,
        observer: Option<&flow_diag_v1::DurableFlowObserverV1>,
    ) -> Result<AuthenticatedWriterSession> {
        self.durable_active_inner_v1(history, admission, deadline, check, observer)
    }
    fn durable_active_inner_v1(
        &self,
        history: &ReconciledAuthorityHistory,
        admission: &str,
        deadline: Instant,
        mut check: impl FnMut() -> Result<()>,
        #[cfg(feature = "synthetic-born-joined-qualification")] observer: Option<
            &flow_diag_v1::DurableFlowObserverV1,
        >,
    ) -> Result<AuthenticatedWriterSession> {
        workspace_flow_observe_v1!(
            observer,
            flow_diag_v1::DurableFlowStageV1::ActiveVerification,
            check()
        )?;
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let mut callback_stage = None;
        let current = || {
            let result = self.check_current();
            #[cfg(feature = "synthetic-born-joined-qualification")]
            if let (Some(observer), Err(error)) = (observer, &result) {
                observer.record_error(flow_diag_v1::DurableFlowStageV1::ActiveVerification, error);
                if callback_stage.is_none() {
                    callback_stage =
                        Some(flow_diag_v1::DurableFlowCallbackStageV1::WorkspaceCurrent);
                }
            }
            result
                .and_then(|_| {
                    let result = check();
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    if let (Some(observer), Err(error)) = (observer, &result) {
                        observer.record_error(
                            flow_diag_v1::DurableFlowStageV1::ActiveVerification,
                            error,
                        );
                        if callback_stage.is_none() {
                            callback_stage =
                                Some(flow_diag_v1::DurableFlowCallbackStageV1::CallerCurrent);
                        }
                    }
                    result
                })
                .map_err(|_| wholepact_authority::AuthorityError::Permission)
        };
        #[cfg(feature = "synthetic-born-joined-qualification")]
        let result = if let Some(observer) = observer {
            observer.call_enter(flow_diag_v1::DurableFlowCallV1::ActiveVerify);
            let result = self
                .client
                .verify_durable_payment_session_v1_diagnosed_checked_until(
                    history, admission, deadline, current,
                );
            let result = observer.observe_transport(
                flow_diag_v1::DurableFlowTransportPurposeV1::Verify,
                flow_diag_v1::DurableFlowStageV1::ActiveVerification,
                callback_stage,
                result,
            );
            observer.call_return(flow_diag_v1::DurableFlowCallV1::ActiveVerify, &result);
            result
        } else {
            self.client.verify_durable_payment_session_v1_checked_until(
                history, admission, deadline, current,
            )
        };
        #[cfg(not(feature = "synthetic-born-joined-qualification"))]
        let result = self
            .client
            .verify_durable_payment_session_v1_checked_until(history, admission, deadline, current);
        result.map_err(|_| Error::RecoveryRequired)
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
fn observe_history_callback_error(
    observed: bool,
    first: &mut Option<Error>,
    error: Error,
) -> wholepact_authority::AuthorityError {
    if observed && first.is_none() {
        *first = Some(error);
    }
    wholepact_authority::AuthorityError::Permission
}

fn same_actual_workspace(actual: &std::sync::Arc<()>, expected: &std::sync::Arc<()>) -> bool {
    std::sync::Arc::ptr_eq(actual, expected)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "synthetic-born-joined-qualification")]
    #[test]
    fn history_callback_observer_preserves_first_error_and_optional_none() {
        let mut first = None;
        assert!(matches!(
            observe_history_callback_error(false, &mut first, Error::Locked),
            wholepact_authority::AuthorityError::Permission
        ));
        assert!(first.is_none());
        assert!(matches!(
            observe_history_callback_error(
                true,
                &mut first,
                Error::ConsentJournal(crate::consent_journal::JournalError::Expired)
            ),
            wholepact_authority::AuthorityError::Permission
        ));
        assert!(matches!(
            observe_history_callback_error(true, &mut first, Error::ReviewMismatch),
            wholepact_authority::AuthorityError::Permission
        ));
        assert!(matches!(
            first.take(),
            Some(Error::ConsentJournal(
                crate::consent_journal::JournalError::Expired
            ))
        ));
    }
    #[test]
    fn equal_certificate_labels_cannot_substitute_another_client_instance() {
        let original = std::sync::Arc::new(());
        let retained = original.clone();
        let replacement = std::sync::Arc::new(());
        assert!(same_actual_workspace(&original, &retained));
        assert!(!same_actual_workspace(&original, &replacement));
        drop(original);
        assert!(!same_actual_workspace(&retained, &replacement));
    }
}
