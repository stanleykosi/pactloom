//! Real signed-history replay against the actual purpose-specific birth audit.
//! Historical anchors are inert data. These tests do not construct a live owner,
//! an encrypted retained enrollment, a session or a construction capability.
use super::*;
use wholepact_authority::{
    manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2,
    pending_birth::PendingBirthCommitRecord,
};

fn fixture() -> serde_json::Value {
    let raw: serde_json::Value = serde_json::from_str(include_str!(
        "../../../consent_journal/fixtures/common-context-authority-audit.synthetic.json"
    ))
    .unwrap();
    assert_eq!(raw["native_actors_exercised"], false);
    raw
}

fn anchor(raw: &serde_json::Value) -> BirthAnchor {
    serde_json::from_value(
        raw["modeled_retention_evidence"][0]["request"]["selection"]["scope"]["selection"]
            ["original_policy_origin"]
            .clone(),
    )
    .unwrap()
}

fn extension(raw: &serde_json::Value) -> ManualRosterEnrollmentExtensionV2 {
    serde_json::from_value(raw["extension"].clone()).unwrap()
}

fn replay(raw: &serde_json::Value, count: usize) -> ReconciledAuthorityHistory {
    let birth: PendingBirthCommitRecord =
        serde_json::from_value(raw["original_birth"].clone()).unwrap();
    wholepact_authority::transport::synthetic::recorded_fixture_history(
        &birth,
        &serde_json::to_vec(&raw["authority_events"].as_array().unwrap()[..count]).unwrap(),
    )
    .unwrap()
}

#[test]
fn original_birth_link_accepts_approval_only_and_preserves_legacy_refusal() {
    let raw = fixture();
    let anchor = anchor(&raw);
    let extension = extension(&raw);
    let before = replay(&raw, 8);
    let legacy = anchor.audit_historical_witness_link(&before).unwrap();
    let scoped = anchor
        .audit_original_roster_preconstruction_witness_link(&before, &extension)
        .unwrap();
    // Exact old linkage result when both history gates support the archive.
    assert!(legacy.genesis() == scoped.genesis());
    assert!(legacy.original_disclosure() == scoped.original_disclosure());
    assert!(legacy.checkpoint() == scoped.checkpoint());
    assert!(legacy.permanent_exclusion() == scoped.permanent_exclusion());
    assert!(legacy.observed_head() == scoped.observed_head());

    // Actual signed V3 approval and its subsequently signed newer attempt.
    // The original birth remains historical and need not be the latest attempt.
    for count in [9, 13] {
        let history = replay(&raw, count);
        let audit = anchor
            .audit_original_roster_preconstruction_witness_link(&history, &extension)
            .unwrap();
        assert!(audit.genesis() == &anchor.expected_account_use_genesis().unwrap());
        assert!(audit.original_disclosure() == history.disclosure());
        assert!(Some(audit.checkpoint()) == history.snapshot().account_use_checkpoint.as_ref());
        assert!(audit.observed_head() == &history.snapshot().head);
        assert!(audit.permanent_exclusion().is_none());
        assert!(anchor.audit_historical_witness_link(&history).is_err());
    }
}

#[test]
fn original_birth_link_rejects_foreign_extension_and_other_original() {
    let raw = fixture();
    let anchor = anchor(&raw);
    let extension = extension(&raw);
    let history = replay(&raw, 13);
    let mut foreign = extension.clone();
    foreign.signer_roster_record_digest = "ab".repeat(32);
    foreign.validate().unwrap();
    assert!(anchor
        .audit_original_roster_preconstruction_witness_link(&history, &foreign)
        .is_err());

    // A different individually valid original from the same signed plan is
    // still not this history's birth/account/witness-policy provenance.
    let other: BirthAnchor = serde_json::from_value(
        raw["approval_only_history"]["approvals"][0]["record"]["approval"]["plan"]
            ["originals"][1]["request"]["selection"]["scope"]["selection"]
            ["original_policy_origin"]
            .clone(),
    )
    .unwrap();
    other.complete_policy_origin_v2().unwrap().validate().unwrap();
    assert_ne!(anchor.birth_digest(), other.birth_digest());
    assert!(other
        .audit_original_roster_preconstruction_witness_link(&history, &extension)
        .is_err());
}

#[test]
fn original_birth_link_rejects_reserved_consumed_and_tampered_history() {
    let raw = fixture();
    let anchor = anchor(&raw);
    let extension = extension(&raw);
    for count in [14, 15] {
        let history = replay(&raw, count);
        assert!(anchor
            .audit_original_roster_preconstruction_witness_link(&history, &extension)
            .is_err());
        assert!(anchor.audit_historical_witness_link(&history).is_err());
    }

    let birth: PendingBirthCommitRecord =
        serde_json::from_value(raw["original_birth"].clone()).unwrap();
    let mut events = raw["authority_events"].as_array().unwrap()[..9].to_vec();
    let signature = events[8]["mutation"]["body"]["control"]["record"]
        ["owner_signature"]["signature"]
        .as_array_mut()
        .unwrap();
    signature[0] = serde_json::json!(signature[0].as_u64().unwrap() ^ 1);
    assert!(wholepact_authority::transport::synthetic::recorded_fixture_history(
        &birth,
        &serde_json::to_vec(&events).unwrap(),
    )
    .is_err());
}
