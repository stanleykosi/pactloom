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
            authority_call: None,
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

fn authority_call() -> FinancialAuthorityCallV1 {
    FinancialAuthorityCallV1 {
        stage: FinancialAuthorityStageV1::ExchangeDeadline,
        check_site: None,
        checkpoint: FinancialAuthorityCheckpointV1::AfterCallback,
        selected_limit: Some(FinancialAuthoritySelectedLimitV1::Exchange),
        selected_budget_us: Some(10_000_000),
        caller_remaining_at_failure_us: None,
        selected_remaining_at_failure_us: Some(0),
        exchange_elapsed_us: Some(10_000_001),
        exchange_cost: None,
        clamped: false,
        incomplete: false,
        pre_budget_callback_calls: 0,
        pre_budget_callback_us: 0,
    }
}

#[cfg(feature = "synthetic-qualification")]
#[test]
fn checked_metadata_preserves_same_call_callback_cause_only() {
    let scope = Scope::begin(FinancialNativeStageV1::AuthorityAdmit);
    let token = begin_checked_authority();
    signer(&Error::Locked);
    let prior = scope.failure().unwrap();
    let call = authority_call();
    attach_checked_authority(token, call);
    let enriched = scope.failure().unwrap();
    assert_eq!(enriched.stage, prior.stage);
    assert_eq!(enriched.component, prior.component);
    assert_eq!(enriched.error_class, prior.error_class);
    assert_eq!(enriched.authority_call, Some(call));
    let later = begin_checked_authority();
    let mut other = call;
    other.exchange_elapsed_us = Some(1);
    attach_checked_authority(later, other);
    assert_eq!(scope.failure(), Some(enriched));
}

#[cfg(feature = "synthetic-qualification")]
#[test]
fn checked_metadata_rejects_previous_nested_and_failed_scope_tokens() {
    let prior = Scope::begin(FinancialNativeStageV1::AuthorityAdmit);
    let old = begin_checked_authority();
    drop(prior);
    let current = Scope::begin(FinancialNativeStageV1::AuthorityAdmit);
    signer(&Error::Locked);
    attach_checked_authority(old, authority_call());
    assert!(current.failure().unwrap().authority_call.is_none());
    let too_late = begin_checked_authority();
    attach_checked_authority(too_late, authority_call());
    assert!(current.failure().unwrap().authority_call.is_none());
    drop(current);
    let outer = Scope::begin(FinancialNativeStageV1::AuthorityAdmit);
    let outer_token = begin_checked_authority();
    {
        let inner = Scope::begin(FinancialNativeStageV1::AuthorityAdmit);
        signer(&Error::Verification);
        attach_checked_authority(outer_token, authority_call());
        assert!(inner.failure().unwrap().authority_call.is_none());
    }
    assert!(outer.failure().is_none());
}

#[test]
fn authority_metadata_bounds_unknown_fields_and_nulls_are_closed() {
    let call = authority_call();
    assert!(call.is_valid_v1());
    let original = serde_json::to_value(call).unwrap();
    let mut maximum = call;
    maximum.pre_budget_callback_calls = 1;
    assert!(maximum.is_valid_v1());
    assert!(
        serde_json::from_value::<FinancialAuthorityCallV1>(serde_json::to_value(maximum).unwrap())
            .is_ok()
    );
    let mut excess = maximum;
    excess.pre_budget_callback_calls = 2;
    assert!(!excess.is_valid_v1());
    assert!(
        serde_json::from_value::<FinancialAuthorityCallV1>(serde_json::to_value(excess).unwrap())
            .is_err()
    );

    assert_eq!(
        serde_json::from_value::<FinancialAuthorityCallV1>(original.clone()).unwrap(),
        call
    );
    for field in [
        "selected_budget_us",
        "caller_remaining_at_failure_us",
        "selected_remaining_at_failure_us",
        "exchange_elapsed_us",
        "pre_budget_callback_us",
    ] {
        let mut value = original.clone();
        value[field] = serde_json::json!(600_000_001u32);
        assert!(serde_json::from_value::<FinancialAuthorityCallV1>(value).is_err());
    }
    let mut invalid = call;
    invalid.selected_budget_us = Some(600_000_001);
    assert!(!invalid.is_valid_v1());
    let mut value = original.clone();
    value["unexpected"] = serde_json::json!(false);
    assert!(serde_json::from_value::<FinancialAuthorityCallV1>(value).is_err());
    let cost = FinancialAuthorityCostV1 {
        callback_calls: 0,
        callback_us: 0,
        callback_max_us: 0,
        connect_calls: 0,
        connect_us: 0,
        handshake_calls: 0,
        handshake_us: 0,
        frame_write_calls: 0,
        frame_write_us: 0,
        frame_read_calls: 0,
        frame_read_us: 0,
    };
    let cost_json = serde_json::to_value(cost).unwrap();
    for field in [
        "callback_calls",
        "connect_calls",
        "handshake_calls",
        "frame_write_calls",
        "frame_read_calls",
    ] {
        let mut value = cost_json.clone();
        value[field] = serde_json::json!(1_000_001u32);
        assert!(serde_json::from_value::<FinancialAuthorityCostV1>(value).is_err());
    }
    for field in [
        "callback_us",
        "callback_max_us",
        "connect_us",
        "handshake_us",
        "frame_write_us",
        "frame_read_us",
    ] {
        let mut value = cost_json.clone();
        value[field] = serde_json::json!(600_000_001u32);
        assert!(serde_json::from_value::<FinancialAuthorityCostV1>(value).is_err());
    }
    let mut value = original.clone();
    value["exchange_cost"] = cost_json.clone();
    value["exchange_cost"]["unexpected"] = serde_json::json!(0);
    assert!(serde_json::from_value::<FinancialAuthorityCallV1>(value).is_err());
    let mut bad_cost = cost;
    bad_cost.callback_calls = 1_000_001;
    let mut invalid = call;
    invalid.exchange_cost = Some(bad_cost);
    assert!(!invalid.is_valid_v1());
    let diagnostic = FinancialNativeDiagnosticV1 {
        stage: FinancialNativeStageV1::Admit,
        component: FinancialNativeComponentV1::Authority,
        error_class: FinancialNativeErrorClassV1::AuthorityPermission,
        authority_call: None,
    };
    let encoded = serde_json::to_value(diagnostic).unwrap();
    assert!(encoded["authority_call"].is_null());
    assert_eq!(
        serde_json::from_value::<FinancialNativeDiagnosticV1>(encoded).unwrap(),
        diagnostic
    );
}
