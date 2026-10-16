//! Recheck the held source owners around every potentially interactive decision.
use wholepact_proof_jobs::{CheckpointScope, LocalAction, LocalProofConsent};
use wholepact_protocol::authorization::retention::{
    SignedRetentionConsent, SignedRetentionScope,
    transaction::{
        TransactionRecoveryConsent, TransactionRecoveryScope, TransactionRetentionConsent,
        TransactionRetentionScope,
    },
};

use wholepact_protocol::authorization::retention::transaction::submission_handoff::{
    SubmissionHandoffConsent, SubmissionHandoffScope,
};

pub(super) struct CheckedSettlementConsent<'a> {
    pub(super) proof: &'a dyn LocalProofConsent,
    pub(super) signed: &'a dyn SignedRetentionConsent,
    pub(super) transaction: &'a dyn TransactionRetentionConsent,
    pub(super) recovery: &'a dyn TransactionRecoveryConsent,
    pub(super) submission: &'a dyn SubmissionHandoffConsent,
    pub(super) current: &'a dyn Fn() -> bool,
}
fn checked(current: &dyn Fn() -> bool, decision: impl FnOnce() -> bool) -> bool {
    current() && decision() && current()
}
impl LocalProofConsent for CheckedSettlementConsent<'_> {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        checked(self.current, || self.proof.permits(scope, action))
    }
}
impl SignedRetentionConsent for CheckedSettlementConsent<'_> {
    fn permits(&self, scope: &SignedRetentionScope) -> bool {
        checked(self.current, || self.signed.permits(scope))
    }
}
impl TransactionRetentionConsent for CheckedSettlementConsent<'_> {
    fn permits(&self, scope: &TransactionRetentionScope) -> bool {
        checked(self.current, || self.transaction.permits(scope))
    }
}
impl TransactionRecoveryConsent for CheckedSettlementConsent<'_> {
    fn permits(&self, scope: &TransactionRecoveryScope<'_>) -> bool {
        checked(self.current, || self.recovery.permits(scope))
    }
}
impl SubmissionHandoffConsent for CheckedSettlementConsent<'_> {
    fn permits(&self, scope: &SubmissionHandoffScope<'_>) -> bool {
        checked(self.current, || self.submission.permits(scope))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    #[test]
    fn expired_source_cannot_prompt_or_survive_an_interactive_approval() {
        let called = Cell::new(false);
        assert!(!checked(&|| false, || {
            called.set(true);
            true
        }));
        assert!(!called.get());
        let current = Cell::new(true);
        assert!(!checked(&|| current.get(), || {
            current.set(false);
            true
        }));
        assert!(checked(&|| true, || true));
        assert!(!checked(&|| true, || false));
    }
}
