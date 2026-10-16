use super::*;
fn fixture() -> HostRecoveryContinuityEvidenceV3 {
    serde_json::from_str(include_str!("fixtures/minimal_evidence.json")).unwrap()
}
#[test]
fn v3_preserves_minimal_offline_unknowns_and_keeps_endpoint_unavailable() {
    let e = fixture();
    e.validate().unwrap();
    assert_eq!(
        e.complete_history.conservative_debit_zatoshis().unwrap(),
        70
    );
    assert!(
        e.complete_history
            .require_financial_activation_supported()
            .is_err()
    );
    assert!(require_complete_origin_endpoint().is_err());
    let bytes = serde_json::to_vec(&e).unwrap();
    assert!(
        serde_json::from_slice::<super::super::v2::HostRecoveryContinuityEvidenceV2>(&bytes)
            .is_err()
    );
    let decoded: HostRecoveryContinuityEvidenceV3 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded.digest().unwrap(), e.digest().unwrap());
}
#[test]
fn v3_rejects_changed_replay_head_session_and_cross_version_without_fallback() {
    for n in 0..4 {
        let mut e = fixture();
        match n {
            0 => e.history_digest = "aa".repeat(32),
            1 => e.head.digest = "bb".repeat(32),
            2 => e.writer_session_id = "cc".repeat(32),
            _ => e.request.schema_version = 2,
        }
        assert!(e.validate().is_err());
    }
}
#[test]
fn v3_does_not_upgrade_missing_retained_offline_replay_or_legacy_birth() {
    let e = fixture();
    e.validate().unwrap();
    assert_eq!(
        e.complete_history
            .unresolved_offline_authorizations()
            .unwrap(),
        std::collections::BTreeSet::from(["synthetic-offline".into()])
    );
    assert!(
        e.complete_history
            .financial_origins_v2
            .account_use
            .genesis
            .is_none()
    );
    assert!(e.complete_history.construction.original_birth().is_none());
}

#[test]
fn ledger_derived_nonempty_v3_retains_charge_consumption_inputs_and_obligations() {
    let e: HostRecoveryContinuityEvidenceV3 =
        serde_json::from_str(include_str!("fixtures/nonempty_evidence.json")).unwrap();
    e.validate().unwrap();
    assert_eq!(
        e.complete_history.conservative_debit_zatoshis().unwrap(),
        400_012_000
    );
    assert_eq!(
        e.complete_history
            .construction
            .retained_input_value_zatoshis()
            .unwrap(),
        500_000_000
    );
    assert!(
        e.complete_history.construction.origins()[0]
            .consumed()
            .is_some()
    );
    assert!(
        !e.complete_history
            .conservative_obligations()
            .unwrap()
            .is_empty()
    );
    assert!(
        e.complete_history
            .require_financial_activation_supported()
            .is_err()
    );
    let mut changed = e.clone();
    changed.history_digest = "ee".repeat(32);
    assert!(changed.validate().is_err());
}

#[test]
fn v3_rejects_erased_construction_below_observed_lifetime_charge() {
    let mut value: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/nonempty_evidence.json")).unwrap();
    value["complete_history"]["construction"]["origins"] = serde_json::json!([]);
    let changed: HostRecoveryContinuityEvidenceV3 = serde_json::from_value(value).unwrap();
    assert!(changed.validate().is_err());
}

#[test]
fn v3_reinspection_never_extends_original_deadline_or_accepts_changed_evidence() {
    let e = fixture();
    e.require_unchanged(&e, Duration::from_secs(29)).unwrap();
    assert!(e.require_unchanged(&e, Duration::from_secs(30)).is_err());
    let mut changed = e.clone();
    changed.writer_session_expires_at_ms += 1;
    assert!(e.require_unchanged(&changed, Duration::ZERO).is_err());
}
