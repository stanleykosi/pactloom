//! Actual selected mTLS credentials only. Imported-source and native decision
//! custody stays in runtime; these adapters cannot mint financial permission.
use super::*;
use std::time::Instant;
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
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<ReconciledAuthorityHistory> {
        self.check_current()?;
        check()?;
        let history = self
            .client
            .reconcile_history_checked_until(deadline, || {
                self.check_current()
                    .and_then(|_| check())
                    .map_err(|_| wholepact_authority::AuthorityError::Permission)
            })
            .map_err(|_| Error::Uncertain)?;
        check()?;
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
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<AccountSnapshot> {
        check()?;
        self.client
            .admit_durable_payment_v1_checked_until(request, deadline, || {
                self.check_current()
                    .and_then(|_| check())
                    .map_err(|_| wholepact_authority::AuthorityError::Permission)
            })
            .map_err(|_| Error::Uncertain)
    }

    pub(in crate::native_ui) fn durable_acquire_v1(
        &self,
        history: &ReconciledAuthorityHistory,
        admission: &str,
        deadline: Instant,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<WriterSessionReceipt> {
        check()?;
        self.client
            .acquire_durable_payment_writer_v1_checked_until(history, admission, deadline, || {
                self.check_current()
                    .and_then(|_| check())
                    .map_err(|_| wholepact_authority::AuthorityError::Permission)
            })
            .map_err(|_| Error::Uncertain)
    }

    pub(in crate::native_ui) fn durable_activate_v1(
        &self,
        history: &ReconciledAuthorityHistory,
        admission: &str,
        request: &OwnerControlRequest,
        deadline: Instant,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<AccountSnapshot> {
        check()?;
        self.client
            .activate_durable_payment_writer_v1_checked_until(
                history,
                admission,
                request,
                deadline,
                || {
                    self.check_current()
                        .and_then(|_| check())
                        .map_err(|_| wholepact_authority::AuthorityError::Permission)
                },
            )
            .map_err(|_| Error::Uncertain)
    }

    pub(in crate::native_ui) fn durable_active_v1(
        &self,
        history: &ReconciledAuthorityHistory,
        admission: &str,
        deadline: Instant,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<AuthenticatedWriterSession> {
        check()?;
        self.client
            .verify_durable_payment_session_v1_checked_until(history, admission, deadline, || {
                self.check_current()
                    .and_then(|_| check())
                    .map_err(|_| wholepact_authority::AuthorityError::Permission)
            })
            .map_err(|_| Error::RecoveryRequired)
    }
}

fn same_actual_workspace(actual: &std::sync::Arc<()>, expected: &std::sync::Arc<()>) -> bool {
    std::sync::Arc::ptr_eq(actual, expected)
}
#[cfg(test)]
mod tests {
    use super::*;
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
