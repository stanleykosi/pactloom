//! Pure observer tests: no files, sockets, native events, credentials or clocks.
use super::*;

#[test]
fn exact_first_failure_survives_outer_error_erasure_and_scope_reset() {
    let scope = Scope::begin(FinancialNativeStageV1::Sign);
    bridge(&crate::authority_bridge::BridgeError::Journal(
        crate::consent_journal::JournalError::InvalidBinding,
    ));
    signer(&Error::Uncertain);
    assert_eq!(
        scope.failure(),
        Some(FinancialNativeDiagnosticV1 {
            stage: FinancialNativeStageV1::Sign,
            component: FinancialNativeComponentV1::Journal,
            error_class: FinancialNativeErrorClassV1::JournalInvalidBinding,
        })
    );
    drop(scope);
    let next = Scope::begin(FinancialNativeStageV1::ReturnPrepare);
    assert_eq!(next.failure(), None);
    at(FinancialNativeStageV1::HostPreparedWait);
    signer(&Error::Locked);
    assert_eq!(
        next.failure().unwrap().stage,
        FinancialNativeStageV1::HostPreparedWait
    );
    assert_eq!(
        next.failure().unwrap().error_class,
        FinancialNativeErrorClassV1::Locked
    );
}

#[test]
fn nested_scope_restores_parent_without_leaking_failure() {
    let outer = Scope::begin(FinancialNativeStageV1::Continue);
    signer(&Error::ReviewMismatch);
    let original = outer.failure();
    {
        let inner = Scope::begin(FinancialNativeStageV1::WalletObserve);
        assert!(inner.failure().is_none());
        signer(&Error::Verification);
        assert_eq!(
            inner.failure().unwrap().stage,
            FinancialNativeStageV1::WalletObserve
        );
    }
    assert_eq!(outer.failure(), original);
    drop(outer);
    signer(&Error::Uncertain);
    let clean = Scope::begin(FinancialNativeStageV1::SourceOpen);
    assert!(clean.failure().is_none());
}
