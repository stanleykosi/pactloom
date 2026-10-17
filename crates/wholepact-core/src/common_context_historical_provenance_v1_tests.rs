//! Pure inert facts, not scanner/native/witness owners or chain evidence.
use super::*;
use crate::manual_roster_construction_v3::CommonContextReadPurposeV1;
fn h(b: u8) -> String {
    format!("{b:02x}").repeat(32)
}
fn fixture(
    tied: bool,
) -> (
    CommonContextHistoricalProvenanceV1,
    Vec<ManualRosterConstructionPlanV3>,
    Vec<RosterCommonContextReadRequestV1>,
    Vec<String>,
) {
    let mut base = crate::manual_roster_construction_v3::tests::plan();
    if tied {
        let tip = base.originals[1].request.selection_context.clone();
        base.originals[0].request.selection_context.tip_height = tip.tip_height;
        base.originals[0]
            .request
            .selection_context
            .tip_hash_protocol = tip.tip_hash_protocol;
        base.common_context = CommonContextProposalV1::from_originals(&base.originals).unwrap();
        base.common_context_digest = base.common_context.digest().unwrap();
        base.participants = base
            .originals
            .iter()
            .map(|o| o.commitment().unwrap())
            .collect();
    }
    let plans = base
        .originals
        .iter()
        .map(|o| {
            let mut p = base.clone();
            p.retained = o.request.clone();
            p.retained_evidence_digest = o.evidence_digest.clone();
            p.validate().unwrap();
            p
        })
        .collect::<Vec<_>>();
    let reads = plans
        .iter()
        .enumerate()
        .map(|(i, p)| RosterCommonContextReadRequestV1 {
            version: 1,
            operation_id: format!("synthetic-historical-read-{i}"),
            plan: p.clone(),
            original_durable_receipt_digest: h(70),
            witness_plan_approval_digest: h(71),
            purpose: CommonContextReadPurposeV1::RevalidateExactRetainedNotesAndCommonContext,
            profile: p.common_context.read_profile.clone(),
            current_caller_binding_digest: h(72),
            requested_at_ms: 40_789,
            admission_expires_at_ms: 70_000,
            completion_expires_at_ms: 100_000,
        })
        .collect::<Vec<_>>();
    let admissions = vec![h(90), h(91)];
    let common = &base.common_context;
    let observations = plans
        .iter()
        .zip(&reads)
        .enumerate()
        .map(|(i, (p, r))| {
            let e = p.enrollment();
            let original = &p.retained.selection_context;
            CommonContextHistoricalParticipantV1 {
                participant_id: e.scope.participant_id.clone(),
                account_id: e.identity.account_id.clone(),
                full_viewing_key_digest: e.identity.full_viewing_key_digest.clone(),
                plan_digest: p.digest().unwrap(),
                retained_request_digest: p.retained.digest().unwrap(),
                read_request_digest: r.digest().unwrap(),
                read_admission_digest: admissions[i].clone(),
                selected_inputs_digest: selected_inputs_digest(p).unwrap(),
                original: HistoricalChainObservationV1 {
                    request_started_at_unix_seconds: 20,
                    observed_at_unix_seconds: 31 - i as u64,
                    valid_until_unix_seconds: 35,
                    tip_height: original.tip_height,
                    tip_hash_protocol: original.tip_hash_protocol.clone(),
                },
                revalidation: HistoricalChainObservationV1 {
                    request_started_at_unix_seconds: 40,
                    observed_at_unix_seconds: 41,
                    valid_until_unix_seconds: 60,
                    tip_height: common.reference_tip_height + 1,
                    tip_hash_protocol: h(95),
                },
                anchor_height: common.anchor_height,
                anchor_hash_protocol: common.anchor_hash_protocol.clone(),
                anchor_root: common.anchor_root.clone(),
                required_ancestry_digest: required_ancestry_digest(common).unwrap(),
            }
        })
        .collect();
    let provenance = CommonContextHistoricalProvenanceV1 {
        version: 1,
        common_context_digest: common.digest().unwrap(),
        reference_participant_id: common
            .participants
            .last()
            .unwrap()
            .commitment
            .participant_id
            .clone(),
        provider: common.provider.clone(),
        read_profile: common.read_profile.clone(),
        observations,
    };
    let refs = reads
        .iter()
        .zip(&admissions)
        .map(|(r, a)| (r, a.as_str()))
        .collect::<Vec<_>>();
    provenance.validate_for(&plans, &refs).unwrap();
    (provenance, plans, reads, admissions)
}
#[test]
fn historical_provenance_preserves_original_seconds_and_separate_later_observation() {
    let (p, plans, reads, a) = fixture(false);
    let refs = reads
        .iter()
        .zip(&a)
        .map(|(r, a)| (r, a.as_str()))
        .collect::<Vec<_>>();
    p.validate_for(&plans, &refs).unwrap();
    let s = p.reference_snapshot().unwrap();
    assert_eq!(s.observed_at_ms, 30_000);
    assert_eq!(s.tip_height, plans[0].common_context.reference_tip_height);
    assert_eq!(
        p.observations[1].revalidation.observed_at_ms().unwrap(),
        41_000
    );
    // Expired original provider TTL remains truthful history, not refreshed age.
    assert!(
        p.observations[1].original.valid_until_unix_seconds
            < p.observations[1].revalidation.observed_at_unix_seconds
    );
    let json = serde_json::to_vec(&p).unwrap();
    let restored: CommonContextHistoricalProvenanceV1 = crate::parse_typed_json(&json).unwrap();
    restored.validate_for(&plans, &refs).unwrap();
    assert_eq!(restored.digest().unwrap(), p.digest().unwrap());
}
#[test]
fn historical_provenance_tie_uses_last_canonical_owner_not_newest_clock() {
    let (p, _, _, _) = fixture(true);
    assert!(
        p.observations[0].original.observed_at_unix_seconds
            > p.observations[1].original.observed_at_unix_seconds
    );
    assert_eq!(p.reference_participant_id, p.observations[1].participant_id);
    let mut bad = p.clone();
    bad.reference_participant_id = bad.observations[0].participant_id.clone();
    assert!(bad.validate().is_err());
}
#[test]
fn historical_provenance_rejects_wrong_exact_relationships() {
    let (p, plans, reads, a) = fixture(false);
    let refs = reads
        .iter()
        .zip(&a)
        .map(|(r, a)| (r, a.as_str()))
        .collect::<Vec<_>>();
    for field in 0..17 {
        let mut bad = p.clone();
        let r = &mut bad.observations[0];
        match field {
            0 => r.account_id = h(1),
            1 => r.full_viewing_key_digest = h(2),
            2 => r.plan_digest = h(3),
            3 => r.retained_request_digest = h(4),
            4 => r.read_request_digest = h(5),
            5 => r.read_admission_digest = h(6),
            6 => r.selected_inputs_digest = h(7),
            7 => r.original.tip_hash_protocol = h(8),
            8 => r.original.tip_height += 1,
            9 => r.anchor_height -= 1,
            10 => r.anchor_hash_protocol = h(9),
            11 => r.anchor_root = h(10),
            12 => r.required_ancestry_digest = h(11),
            13 => bad.provider.endpoint = "https://different.invalid".into(),
            14 => bad.common_context_digest = h(12),
            15 => bad.read_profile.minimum_confirmations += 1,
            _ => r.revalidation.tip_height = plans[0].common_context.expiry_height,
        }
        assert!(bad.validate_for(&plans, &refs).is_err(), "field {field}");
    }
    let mut fork = p.clone();
    for row in &mut fork.observations {
        row.revalidation.tip_height = plans[0].common_context.reference_tip_height;
        row.revalidation.tip_hash_protocol = h(99);
    }
    assert!(fork.validate_for(&plans, &refs).is_err());
}
#[test]
fn historical_provenance_requires_all_reads_and_canonical_order() {
    let (p, plans, reads, a) = fixture(false);
    let refs = reads
        .iter()
        .zip(&a)
        .map(|(r, a)| (r, a.as_str()))
        .collect::<Vec<_>>();
    assert!(p.validate_for(&plans, &[]).is_err());
    assert!(p.validate_for(&plans, &refs[..1]).is_err());
    let mut bad = p.clone();
    bad.observations.reverse();
    assert!(bad.validate_for(&plans, &refs).is_err());
    let wrong = h(96);
    assert!(
        p.validate_for(
            &plans,
            &[(&reads[0], wrong.as_str()), (&reads[1], a[1].as_str())]
        )
        .is_err()
    );
}
#[test]
fn historical_provenance_clocks_are_bounded_quantized_labels() {
    let (p, plans, reads, a) = fixture(false);
    let refs = reads
        .iter()
        .zip(&a)
        .map(|(r, a)| (r, a.as_str()))
        .collect::<Vec<_>>();
    p.validate_for(&plans, &refs).unwrap(); // request40.789 sec and source second40 overlap
    for field in 0..4 {
        let mut bad = p.clone();
        match field {
            0 => bad.observations[0].original.valid_until_unix_seconds = u64::MAX,
            1 => bad.observations[0].original.request_started_at_unix_seconds = 32,
            2 => {
                bad.observations[0]
                    .revalidation
                    .request_started_at_unix_seconds = 39
            }
            _ => {
                bad.observations[0].revalidation.observed_at_unix_seconds = 101;
                bad.observations[0].revalidation.valid_until_unix_seconds = 102;
            }
        }
        assert!(bad.validate_for(&plans, &refs).is_err(), "clock {field}");
    }
}
#[test]
fn historical_provenance_snapshot_digest_commits_complete_history() {
    let (p, _, _, _) = fixture(false);
    let original = p.reference_snapshot().unwrap();
    let mut changed = p.clone();
    changed.observations[0].original.observed_at_unix_seconds -= 1;
    assert_ne!(
        original.snapshot_digest,
        changed.reference_snapshot().unwrap().snapshot_digest
    );
    assert_eq!(
        original.observed_at_ms,
        changed.reference_snapshot().unwrap().observed_at_ms
    );
    assert_eq!(
        original.source_identity_digest,
        changed.source_identity_digest().unwrap()
    );
    let mut unknown = serde_json::to_value(&p).unwrap();
    unknown["authority"] = serde_json::json!(true);
    assert!(serde_json::from_value::<CommonContextHistoricalProvenanceV1>(unknown).is_err());
}

#[test]
fn historical_provenance_participant_validation_never_invents_other_native_reads() {
    let (p, plans, reads, a) = fixture(false);
    p.validate_common_for(&plans[0].common_context).unwrap();
    p.validate_participant_for(&plans[0], &reads[0], &a[0])
        .unwrap();
    assert!(
        p.validate_participant_for(&plans[0], &reads[1], &a[1])
            .is_err()
    );
    let mut changed = p.clone();
    changed.observations[1].read_admission_digest = h(99);
    // The first signer cannot independently authenticate the second's native
    // read. Full Store validation still rejects this exact changed commitment.
    changed
        .validate_participant_for(&plans[0], &reads[0], &a[0])
        .unwrap();
    let refs = reads
        .iter()
        .zip(&a)
        .map(|(r, a)| (r, a.as_str()))
        .collect::<Vec<_>>();
    assert!(changed.validate_for(&plans, &refs).is_err());
}

#[test]
fn historical_provenance_rejects_scan_budget_overrun_inside_expiry() {
    let (mut p, plans, reads, admissions) = fixture(false);
    let refs = reads
        .iter()
        .zip(&admissions)
        .map(|(r, a)| (r, a.as_str()))
        .collect::<Vec<_>>();
    let limit = p
        .observations
        .iter()
        .zip(&reads)
        .map(|(row, read)| {
            row.original
                .tip_height
                .checked_add(read.maximum_additional_blocks().unwrap())
                .unwrap()
        })
        .min()
        .unwrap();
    assert!(limit > plans[0].common_context.reference_tip_height);
    for row in &mut p.observations {
        row.revalidation.tip_height = limit;
    }
    p.validate_for(&plans, &refs).unwrap();
    for row in &mut p.observations {
        row.revalidation.tip_height = limit + 1;
    }
    assert!(
        reads
            .iter()
            .all(|read| limit + 1 <= read.maximum_observed_tip().unwrap())
    );
    // Common expiry remains valid, but an actual participant's stricter read
    // scan budget cannot be replaced by that broader expiry bound.
    p.validate_common_for(&plans[0].common_context).unwrap();
    assert!(p.validate_for(&plans, &refs).is_err());
    assert!(
        p.validate_participant_for(&plans[0], &reads[0], &admissions[0])
            .is_err()
    );
}

#[test]
fn historical_provenance_preserves_source_ttl_without_renewing_it() {
    let (p, _, _, _) = fixture(false);
    let mut original = p.observations[0].original.clone();
    original.valid_until_unix_seconds =
        original.request_started_at_unix_seconds + EXACT_OBSERVATION_SOURCE_TTL_MS / 1000;
    original.validate().unwrap();
    original.valid_until_unix_seconds += 1;
    assert!(original.validate().is_err());
    // Expiry relative to a later observation remains truthful old history.
    assert!(
        p.observations[0].original.valid_until_unix_seconds
            < p.observations[0].revalidation.observed_at_unix_seconds
    );
    p.validate().unwrap();
}
