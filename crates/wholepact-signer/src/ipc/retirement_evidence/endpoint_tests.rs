//! Pure data/clock/state fixtures only. No listener, peer, native owner,
//! decision, provider, credentials, filesystem or production issuer is created.
use super::*;
use wholepact_signer_origin::retirement_evidence::{
    NETWORK_PROFILE_ID, PURPOSE, RetirementDestinationEvidenceRequestV1,
};

fn request() -> RetirementDestinationEvidenceRequestV1 {
    RetirementDestinationEvidenceRequestV1 {
        schema_version: 1,
        purpose: PURPOSE.into(),
        operation_id: "synthetic-retirement-observation".into(),
        request_nonce: "a".repeat(64),
        source_account_id: "synthetic-source-account".into(),
        network_profile_id: NETWORK_PROFILE_ID.into(),
        address: "utest1syntacticfixtureonly".into(),
    }
}

#[test]
fn retirement_endpoint_pair_schema_refuses_generic_unknown_and_empty_variants() {
    let original = serde_json::json!({
        "command": "request_pairing", "schema_version": 1,
        "application_label": "synthetic-client", "scope": request().pair_scope().unwrap(),
    });
    assert!(serde_json::from_value::<PairingEnvelope>(original.clone()).is_ok());
    for field in [
        "approved",
        "native",
        "deadline",
        "grant_id",
        "token_hex",
        "peer",
    ] {
        let mut changed = original.clone();
        changed[field] = serde_json::json!(true);
        assert!(serde_json::from_value::<PairingEnvelope>(changed).is_err());
    }
    for command in [
        "request",
        "status",
        "approve",
        "retirement_destination_observation",
    ] {
        let mut changed = original.clone();
        changed["command"] = serde_json::json!(command);
        assert!(serde_json::from_value::<PairingEnvelope>(changed).is_err());
    }
    for value in [
        serde_json::json!({}),
        serde_json::json!({"command":"request_pairing"}),
        serde_json::json!({"request_pairing":null}),
        serde_json::json!({"request_pairing":{"approved":true}}),
        serde_json::json!("request_pairing"),
    ] {
        assert!(serde_json::from_value::<PairingEnvelope>(value).is_err());
    }
}

#[test]
fn retirement_endpoint_requires_source_reserved_labels_and_zero_capabilities() {
    let scope = request().pair_scope().unwrap();
    require_reserved_scope(&scope, "synthetic-source-account").unwrap();
    assert!(require_reserved_scope(&scope, "different-source").is_err());
    for field in 0..7 {
        let mut changed = scope.clone();
        match field {
            0 => changed.account_id.push('x'),
            1 => changed.agreement_id.push('x'),
            2 => changed.participant_id.push('x'),
            3 => changed.manifest_digest = "invalid-digest".into(),
            4 => changed.history_read = true,
            5 => changed.authorization_export = true,
            _ => changed.preconstruction_export = true,
        }
        assert!(require_reserved_scope(&changed, "synthetic-source-account").is_err());
    }
    // Pairing commits to the later exact request, not just its reserved labels.
    let mut changed = request();
    changed.request_nonce = "b".repeat(64);
    assert!(changed.require_pair_scope(&scope).is_err());
}

#[test]
fn retirement_endpoint_admission_is_one_pair_then_one_request_without_reset() {
    let mut admission = Admission::Fresh;
    assert!(admission.accepts_connection());
    assert!(
        admission
            .advance(Admission::Paired, Admission::Sealed)
            .is_err()
    );
    admission
        .advance(Admission::Fresh, Admission::Pairing)
        .unwrap();
    assert!(!admission.accepts_connection());
    assert!(
        admission
            .advance(Admission::Fresh, Admission::Pairing)
            .is_err()
    );
    admission
        .advance(Admission::Pairing, Admission::Paired)
        .unwrap();
    assert!(admission.accepts_connection());
    admission
        .advance(Admission::Paired, Admission::Sealed)
        .unwrap();
    assert!(!admission.accepts_connection());
    assert!(
        admission
            .advance(Admission::Paired, Admission::Sealed)
            .is_err()
    );
    assert!(
        admission
            .advance(Admission::Fresh, Admission::Pairing)
            .is_err()
    );
}

#[test]
fn retirement_endpoint_deadlines_preserve_pre_read_admission_and_native_ceiling() {
    let admitted = Instant::now();
    let entry = admitted + Duration::from_secs(120);
    assert_eq!(
        phase_deadline(admitted, entry).unwrap(),
        admitted + READ_BUDGET
    );
    let near_end = entry - Duration::from_millis(1);
    assert_eq!(phase_deadline(near_end, entry).unwrap(), entry);
    assert!(phase_deadline(entry, entry).is_err());
    assert_eq!(
        require_native_ceiling(Some(entry), entry, admitted).unwrap(),
        entry
    );
    let shorter = entry - Duration::from_secs(1);
    assert_eq!(
        require_native_ceiling(Some(shorter), entry, admitted).unwrap(),
        shorter
    );
    assert!(require_native_ceiling(None, entry, admitted).is_err());
    assert!(
        require_native_ceiling(Some(entry + Duration::from_nanos(1)), entry, admitted).is_err()
    );
    assert!(require_native_ceiling(Some(admitted), entry, admitted).is_err());
    assert!(
        require_native_ceiling(Some(entry), entry + Duration::from_nanos(1), admitted).is_err()
    );
}

#[test]
fn retirement_endpoint_cancellation_is_monotone_and_nonblocking_with_held_locks() {
    let cancellation = RetirementEndpointCancellation {
        cancelled: Arc::new(AtomicBool::new(false)),
        active: Arc::new(Mutex::new(None)),
        grants: Arc::new(Mutex::new(BTreeMap::new())),
    };
    let original = cancellation.clone();
    let _active = cancellation.active.lock().unwrap();
    let _grants = cancellation.grants.lock().unwrap();
    // Both registries are empty fixtures. This exercises the actual restriction
    // flag and nonblocking locks without constructing a peer or authority.
    cancellation.cancel();
    original.cancel();
    assert!(cancellation.cancelled.load(Ordering::Acquire));
    assert!(original.cancelled.load(Ordering::Acquire));
}
