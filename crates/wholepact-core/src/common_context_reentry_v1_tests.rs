use super::*;
use crate::manual_roster_construction_v3::{
    CommonContextReadProfileV1, CommonContextReadPurposeV1,
};
fn h(n: u8) -> String {
    format!("{n:02x}").repeat(32)
}
fn fixture() -> RosterCommonContextReentryLineageV1 {
    let plan = crate::manual_roster_construction_v3::tests::plan();
    let read = RosterCommonContextReadRequestV1 {
        version: 1,
        operation_id: "synthetic-original-common-read".into(),
        profile: CommonContextReadProfileV1::for_plan(&plan).unwrap(),
        plan,
        original_durable_receipt_digest: h(70),
        witness_plan_approval_digest: h(71),
        purpose: CommonContextReadPurposeV1::RevalidateExactRetainedNotesAndCommonContext,
        current_caller_binding_digest: h(72),
        requested_at_ms: 40_000,
        admission_expires_at_ms: 70_000,
        completion_expires_at_ms: 100_000,
    };
    let sequence = read
        .plan
        .retained
        .selection
        .scope
        .selection
        .inventory
        .attempt
        .attempt_sequence
        + 1;
    RosterCommonContextReentryLineageV1 {
        version: 1,
        request: RosterCommonContextReentryRequestV1 {
            version: 1,
            operation_id: "synthetic-reentry".into(),
            original_read: read,
            original_read_admission_digest: h(73),
            pending_grant_digest: h(92),
            original_attempt_digest: h(74),
            original_attempt_sequence: sequence,
            current_caller_binding_digest: h(75),
            current_attempt_digest: h(74),
            current_attempt_sequence: sequence,
            purpose: CommonContextReentryPurposeV1::ResumeAlreadyAdmittedConstructionOnly,
            requested_at_ms: 80_000,
            admission_expires_at_ms: 90_000,
        },
        retained_signer_intent_digest: h(77),
        original_native_binding_digest: h(78),
        current_native_binding_digest: h(79),
        original_host_process_digest: h(80),
        original_record_digest: h(81),
        original_genesis_digest: h(82),
        original_birth_digest: h(83),
        current_witness_history_digest: h(84),
        current_witness_continuation_digest: h(74),
        current_writer_session_digest: h(85),
        construction_transport_credential_digest: h(87),
        construction_transport_credential_id: h(88),
        original_transport_fence_digest: h(89),
        current_writer_session_expires_at_ms: 110_000,
        native_review_digest: h(86),
        admitted_at_ms: 80_001,
        completion_expires_at_ms: 95_000,
    }
}
#[test]
fn inert_reentry_preserves_original_read_and_distinct_attempt_domain() {
    let value = fixture();
    value.validate().unwrap();
    let original = serde_json::to_vec(&value.request.original_read).unwrap();
    let round =
        RosterCommonContextReentryLineageV1::from_json(&serde_json::to_vec(&value).unwrap())
            .unwrap();
    assert!(value == round);
    assert_eq!(
        original,
        serde_json::to_vec(&round.request.original_read).unwrap()
    );
    assert_ne!(value.digest().unwrap(), value.request.digest().unwrap());
    assert_ne!(
        value.request.digest().unwrap(),
        value.request.original_read.digest().unwrap()
    );
}
#[test]
fn reentry_never_resets_old_window_or_accepts_old_caller_or_attempt() {
    let mutations: [fn(&mut RosterCommonContextReentryLineageV1); 9] = [
        |v| v.request.current_attempt_digest = h(91),
        |v| v.request.current_attempt_sequence = v.request.original_attempt_sequence + 1,
        |v| {
            v.request.current_caller_binding_digest = v
                .request
                .original_read
                .current_caller_binding_digest
                .clone()
        },
        |v| v.completion_expires_at_ms = v.request.original_read.completion_expires_at_ms + 1,
        |v| {
            v.request.admission_expires_at_ms = v.request.original_read.completion_expires_at_ms + 1
        },
        |v| v.current_native_binding_digest = v.original_native_binding_digest.clone(),
        |v| v.current_witness_continuation_digest = h(90),
        |v| v.admitted_at_ms = v.request.admission_expires_at_ms,
        |v| v.current_writer_session_expires_at_ms = v.completion_expires_at_ms - 1,
    ];
    for mutate in mutations {
        let mut v = fixture();
        mutate(&mut v);
        assert!(v.validate().is_err());
    }
}
#[test]
fn caller_approval_and_provider_restart_fields_fail_closed() {
    let value = fixture();
    for key in [
        "approved",
        "capability",
        "restart_read",
        "new_target_height",
    ] {
        let mut raw = serde_json::to_value(&value).unwrap();
        raw[key] = serde_json::json!(true);
        assert!(
            RosterCommonContextReentryLineageV1::from_json(&serde_json::to_vec(&raw).unwrap())
                .is_err()
        );
    }
}
