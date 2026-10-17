// Pure historical DTOs and encrypted Store histories, never runtime owners.
fn model_historical_provenance_v5(claim: &mut ManualRosterConstructionClaimV3) {
    use wholepact_core::common_context_historical_provenance_v1::*;
    assert_eq!(claim.version, 4);
    assert!(claim.historical_provenance.is_none());
    let common = &claim.consumed[0].request.plan.common_context;
    let rows = claim
        .consumed
        .iter()
        .zip(claim.reentry_lineages.as_ref().unwrap())
        .map(|(audit, lineage)| {
            let plan = &audit.request.plan;
            let retained = &plan.retained.selection_context;
            CommonContextHistoricalParticipantV1 {
                participant_id: plan.enrollment().scope.participant_id.clone(),
                account_id: plan.enrollment().identity.account_id.clone(),
                full_viewing_key_digest: plan.enrollment().identity.full_viewing_key_digest.clone(),
                plan_digest: plan.digest().unwrap(),
                retained_request_digest: plan.retained.digest().unwrap(),
                read_request_digest: lineage.request.original_read.digest().unwrap(),
                read_admission_digest: lineage.request.original_read_admission_digest.clone(),
                selected_inputs_digest: selected_inputs_digest(plan).unwrap(),
                original: HistoricalChainObservationV1 {
                    request_started_at_unix_seconds: 1,
                    observed_at_unix_seconds: 1,
                    valid_until_unix_seconds: 2,
                    tip_height: retained.tip_height,
                    tip_hash_protocol: retained.tip_hash_protocol.clone(),
                },
                revalidation: HistoricalChainObservationV1 {
                    request_started_at_unix_seconds: 2,
                    observed_at_unix_seconds: 2,
                    valid_until_unix_seconds: 3,
                    tip_height: common.reference_tip_height,
                    tip_hash_protocol: common.reference_tip_hash_protocol.clone(),
                },
                anchor_height: common.anchor_height,
                anchor_hash_protocol: common.anchor_hash_protocol.clone(),
                anchor_root: common.anchor_root.clone(),
                required_ancestry_digest: required_ancestry_digest(common).unwrap(),
            }
        })
        .collect::<Vec<_>>();
    let reference = rows
        .iter()
        .max_by_key(|r| r.original.tip_height)
        .unwrap()
        .participant_id
        .clone();
    let facts = CommonContextHistoricalProvenanceV1 {
        version: 1,
        common_context_digest: common.digest().unwrap(),
        reference_participant_id: reference,
        provider: common.provider.clone(),
        read_profile: common.read_profile.clone(),
        observations: rows,
    };
    claim.version = 5;
    claim.historical_provenance = Some(facts);
    claim.validate().unwrap();
}
fn seed_observed_claim_v5() -> ManualRosterConstructionClaimV3 {
    let mut claim = seed_reentered_claim_v4();
    model_historical_provenance_v5(&mut claim);
    claim
}
#[test]
fn historical_claim_v5_preserves_legacy_bytes_and_distinct_domains() {
    for old in [seed_claim(), seed_reentered_claim_v4()] {
        let value = serde_json::to_value(&old).unwrap();
        assert!(
            !value
                .as_object()
                .unwrap()
                .contains_key("historical_provenance")
        );
        let domain = if old.version == 3 {
            "wholepact:store-roster-construction-claim:v3"
        } else {
            "wholepact:store-roster-construction-claim:v4"
        };
        assert_eq!(old.digest().unwrap(), domain_digest(domain, &old).unwrap());
        assert!(old.require_historical_provenance_v5().is_err());
        let mut noncanonical = value;
        noncanonical["historical_provenance"] = serde_json::Value::Null;
        assert!(strict::<ManualRosterConstructionClaimV3>(&noncanonical).is_err());
    }
    let claim = seed_observed_claim_v5();
    assert_eq!(
        claim.digest().unwrap(),
        domain_digest("wholepact:store-roster-construction-claim:v5", &claim).unwrap()
    );
    assert_eq!(
        claim.request_digest().unwrap(),
        domain_digest(
            "wholepact:manual-roster-private-checkpoint-command:v5",
            &claim
        )
        .unwrap()
    );
    checkpoint(&claim).validate_for(&claim).unwrap();
    let decoded =
        strict::<ManualRosterConstructionClaimV3>(&serde_json::to_value(&claim).unwrap()).unwrap();
    assert!(decoded == claim);
}
#[test]
fn historical_claim_v5_requires_complete_original_reads_and_exact_all_rows() {
    let original = seed_observed_claim_v5();
    for mode in 0..12 {
        let mut bad = original.clone();
        match mode {
            0 => bad.historical_provenance = None,
            1 => bad.reentry_lineages = None,
            2 => bad.version = 4,
            3 => bad
                .historical_provenance
                .as_mut()
                .unwrap()
                .observations
                .pop()
                .map(|_| ())
                .unwrap(),
            4 => bad
                .historical_provenance
                .as_mut()
                .unwrap()
                .observations
                .swap(0, 1),
            5 => {
                bad.historical_provenance.as_mut().unwrap().observations[0].read_admission_digest =
                    h("other admission")
            }
            6 => {
                bad.historical_provenance.as_mut().unwrap().observations[0].read_request_digest =
                    h("other read")
            }
            7 => {
                bad.historical_provenance.as_mut().unwrap().observations[0].plan_digest =
                    h("other plan")
            }
            8 => {
                bad.historical_provenance.as_mut().unwrap().observations[0].selected_inputs_digest =
                    h("other inputs")
            }
            9 => {
                bad.historical_provenance
                    .as_mut()
                    .unwrap()
                    .provider
                    .source_id = "other-source".into()
            }
            10 => {
                bad.historical_provenance.as_mut().unwrap().observations[0]
                    .original
                    .observed_at_unix_seconds = u64::MAX
            }
            11 => {
                bad.historical_provenance.as_mut().unwrap().observations[0].account_id =
                    h("other account")
            }
            _ => unreachable!(),
        }
        assert!(bad.validate().is_err(), "case {mode}");
    }
}
#[test]
fn historical_claim_v5_old_marker_cannot_launder_authenticated_rows() {
    let store = Store::in_memory().unwrap();
    let root = append_modeled_construction_root(&store);
    let (claim, _) =
        append_modeled_common_context_rows_with_provenance(&store, &root, true, true, true);
    let c = store.connection.lock().unwrap();
    assert!(crate::backup::validate_construction_encoding(&c, true, true, true).is_ok());
    assert!(crate::backup::validate_construction_encoding(&c, true, true, false).is_err());
    for marker in [1, 2, 3, 4] {
        c.pragma_update(None, "user_version", marker).unwrap();
        assert!(crate::backup::require_construction_v5_encoding(&c).is_err());
    }
    c.pragma_update(None, "user_version", crate::SCHEMA_VERSION)
        .unwrap();
    crate::backup::require_construction_v5_encoding(&c).unwrap();
    assert_eq!(claim.version, 5);
}
#[test]
fn encrypted_historical_claim_v5_backup_reopen_preserves_complete_originals() {
    assert_encrypted_claim_encoding_backup_preserves_complete_history(5);
}
