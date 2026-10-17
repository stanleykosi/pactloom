//! Inert contract tests only. No native decision, wallet, retained source,
//! witness mutation, proof job or completed checkpoint is produced here.
use super::*;
use crate::manual_roster_construction_v2::ManualRosterConstructionPlanV2;
use crate::manual_roster_construction_v3::{
    CommonContextProposalV1, ManualRosterConstructionPlanV3, ManualRosterConstructionRequestV3,
};

fn legacy_plan() -> ManualRosterConstructionPlanV3 {
    crate::manual_roster_construction_v3::tests::plan()
}

fn original_retention_scope(scope: &mut ManualCandidateSelectionScope, end: u64) {
    scope.version = 2;
    scope.invocation.version = 2;
    scope.purpose = ORIGINAL_RETENTION_SELECTION_PURPOSE_V2.into();
    scope.invocation.construction_expires_at_ms = end;
}

fn rebuild(plan: &mut ManualRosterConstructionPlanV3) {
    plan.common_context = CommonContextProposalV1::from_originals(&plan.originals).unwrap();
    plan.common_context_digest = plan.common_context.digest().unwrap();
    plan.participants = plan
        .originals
        .iter()
        .map(|original| original.commitment().unwrap())
        .collect();
    plan.retained = plan.originals[0].request.clone();
    plan.retained_evidence_digest = plan.originals[0].evidence_digest.clone();
}

fn retention_plan() -> ManualRosterConstructionPlanV3 {
    let mut plan = legacy_plan();
    for original in &mut plan.originals {
        original_retention_scope(&mut original.request.selection.scope.selection, 190_000);
    }
    rebuild(&mut plan);
    plan.validate().unwrap();
    plan
}

#[test]
fn original_retention_preserves_legacy_bytes_domains_and_v3_history() {
    let plan = legacy_plan();
    let bytes = serde_json::to_vec(&plan).unwrap();
    let old_digest = plan.digest().unwrap();
    let scope = &plan.retained.selection.scope.selection;
    scope.require_legacy_selection().unwrap();
    assert!(scope.require_original_retention_scope().is_err());
    assert_eq!(
        scope.invocation.digest().unwrap(),
        canonical_digest(
            "wholepact:manual-candidate-invocation:v1",
            &scope.invocation
        )
        .unwrap()
    );
    assert_eq!(
        scope.pairing_digest().unwrap(),
        canonical_digest("wholepact:manual-candidate-selection-scope:v1", scope).unwrap()
    );
    let decoded = ManualRosterConstructionPlanV3::from_json(&bytes).unwrap();
    assert_eq!(serde_json::to_vec(&decoded).unwrap(), bytes);
    assert_eq!(decoded.digest().unwrap(), old_digest);
    assert_eq!(decoded.retained.selection.scope.selection.version, 1);
    assert_eq!(
        decoded
            .retained
            .selection
            .scope
            .selection
            .invocation
            .version,
        1
    );
    crate::manual_roster_construction_v2::tests::plan()
        .validate()
        .unwrap();
}

#[test]
fn original_retention_is_distinct_from_the_short_legacy_permit_bound() {
    let plan = retention_plan();
    let scope = &plan.retained.selection.scope.selection;
    scope.require_original_retention_scope().unwrap();
    assert!(scope.require_legacy_selection().is_err());
    assert!(
        scope.invocation.construction_expires_at_ms - scope.invocation.requested_at_ms
            > scope.inventory.enrollment.scope.maximum_permit_lifetime_ms
    );
    assert_eq!(
        scope.inventory.enrollment.scope.maximum_permit_lifetime_ms,
        120_000
    );
    assert_eq!(
        scope.invocation.digest().unwrap(),
        canonical_digest(
            "wholepact:manual-candidate-original-retention-invocation:v2",
            &scope.invocation,
        )
        .unwrap()
    );
    assert_eq!(
        scope.pairing_digest().unwrap(),
        canonical_digest(
            "wholepact:manual-candidate-original-retention-scope:v2",
            scope
        )
        .unwrap()
    );
    assert_ne!(
        scope.pairing_digest().unwrap(),
        canonical_digest("wholepact:manual-candidate-selection-scope:v1", scope).unwrap()
    );
    let mut legacy = scope.clone();
    legacy.version = 1;
    legacy.invocation.version = 1;
    legacy.purpose = "prepare_one_private_contribution".into();
    assert!(legacy.validate().is_err());
}

#[test]
fn original_retention_requires_exact_matching_versions_and_purpose() {
    let scope = retention_plan().retained.selection.scope.selection;
    let changes: [fn(&mut ManualCandidateSelectionScope); 6] = [
        |s| s.version = 1,
        |s| s.invocation.version = 1,
        |s| s.version = 3,
        |s| s.invocation.version = 3,
        |s| s.purpose = "prepare_one_private_contribution".into(),
        |s| s.purpose.push_str("_renewed"),
    ];
    for change in changes {
        let mut changed = scope.clone();
        change(&mut changed);
        assert!(changed.validate().is_err());
        assert!(changed.pairing_digest().is_err());
    }
    let legacy = legacy_plan().retained.selection.scope.selection;
    let mut imported_old_invocation = legacy.clone();
    imported_old_invocation.version = 2;
    imported_old_invocation.purpose = ORIGINAL_RETENTION_SELECTION_PURPOSE_V2.into();
    assert!(imported_old_invocation.validate().is_err());
    assert_eq!(legacy.invocation.version, 1);
}

#[test]
fn original_retention_is_fixed_by_original_scope_and_global_ceiling() {
    let mut scope = retention_plan().retained.selection.scope.selection;
    scope.invocation.construction_expires_at_ms = scope.inventory.enrollment.scope.expires_at_ms;
    scope.validate().unwrap();
    scope.invocation.construction_expires_at_ms += 1;
    assert!(scope.validate().is_err());

    let mut invocation = scope.invocation;
    invocation.construction_expires_at_ms =
        invocation.requested_at_ms + MAX_CONSTRUCTION_INVOCATION_MS;
    invocation.validate().unwrap();
    invocation.construction_expires_at_ms += 1;
    assert!(invocation.validate().is_err());
    invocation.construction_expires_at_ms = invocation.requested_at_ms;
    assert!(invocation.validate().is_err());

    let original = retention_plan();
    let mut later = original.clone();
    for owner in &mut later.originals {
        owner
            .request
            .selection
            .scope
            .selection
            .invocation
            .construction_expires_at_ms += 1;
    }
    // Changing a later copy is not a renewal of the original exact common context.
    assert!(later.validate().is_err());
    rebuild(&mut later);
    later.validate().unwrap();
    assert_ne!(original.digest().unwrap(), later.digest().unwrap());
    assert_ne!(
        original.invocation_digest().unwrap(),
        later.invocation_digest().unwrap()
    );
    assert_eq!(original.completion_deadline_ms(), 190_000);
}

#[test]
fn original_retention_cannot_enter_single_or_public_v2_construction() {
    let plan = retention_plan();
    let selection = &plan.retained.selection;
    selection.validate().unwrap();
    let single = ManualCandidateSelectionRequest {
        version: 1,
        operation_id: selection.operation_id.clone(),
        scope: selection.scope.selection.clone(),
        current_caller_binding_digest: selection.current_caller_binding_digest.clone(),
        requested_at_ms: selection.requested_at_ms,
        disclosure_expires_at_ms: selection.disclosure_expires_at_ms,
    };
    assert!(single.validate().is_err());
    assert!(single.digest().is_err());
    let v2 = ManualRosterConstructionPlanV2 {
        version: 2,
        retained: plan.retained.clone(),
        retained_evidence_digest: plan.retained_evidence_digest.clone(),
        proposal: plan.proposal.clone(),
        participants: plan.participants.clone(),
    };
    // The same original facts remain coherent. Only public V2 admission is denied.
    v2.validate_retained_economics().unwrap();
    assert!(v2.validate().is_err());
    assert!(v2.digest().is_err());
    plan.validate().unwrap();
}

#[test]
fn original_retention_v3_never_mixes_old_and_new_originals() {
    let legacy = legacy_plan();
    legacy.validate().unwrap();
    let mut mixed = legacy.clone();
    let old_end = mixed.originals[0]
        .request
        .selection
        .scope
        .selection
        .invocation
        .construction_expires_at_ms;
    original_retention_scope(
        &mut mixed.originals[0].request.selection.scope.selection,
        old_end,
    );
    mixed.originals[0].validate().unwrap();
    mixed.originals[1].validate().unwrap();
    assert!(CommonContextProposalV1::from_originals(&mixed.originals).is_err());
    assert!(mixed.validate().is_err());
    assert!(mixed.digest().is_err());
    retention_plan().validate().unwrap();
}

#[test]
fn original_retention_does_not_widen_disclosure_or_construction_admission() {
    let plan = retention_plan();
    let mut selection = plan.retained.selection.clone();
    selection.disclosure_expires_at_ms = selection.requested_at_ms + 30_000;
    selection.validate().unwrap();
    selection.disclosure_expires_at_ms += 1;
    assert!(selection.validate().is_err());
    let mut request = ManualRosterConstructionRequestV3 {
        version: 3,
        operation_id: "synthetic-original-retention-construction".into(),
        plan,
        current_caller_binding_digest: "ab".repeat(32),
        requested_at_ms: 130_000,
        admission_expires_at_ms: 160_000,
    };
    request.validate().unwrap();
    assert_eq!(request.remaining_admission_ms(159_999).unwrap(), 1);
    assert!(request.remaining_admission_ms(160_000).is_err());
    assert!(request.plan.completion_deadline_ms() > 160_000);
    request.admission_expires_at_ms += 1;
    assert!(request.validate().is_err());
}

#[test]
fn original_retention_keeps_exact_input_and_return_economics() {
    let plan = retention_plan();
    let mut changed = plan.clone();
    let original = &mut changed.originals[0].request;
    original.selected_inputs[0].value_zatoshis += 1;
    original.change_value_zatoshis += 1;
    original.validate().unwrap();
    rebuild(&mut changed);
    // Each retained record is arithmetically coherent, but it is not the exact
    // input value and same-account return approved by the complete proposal.
    assert!(changed.validate().is_err());
    let mut changed = plan;
    changed.originals[0]
        .request
        .change_address
        .push_str("substituted");
    changed.originals[0].request.validate().unwrap();
    rebuild(&mut changed);
    assert!(changed.validate().is_err());
}
