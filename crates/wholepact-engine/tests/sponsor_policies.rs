//! Synthetic non-signing sponsor workflows. No real keys, account authority,
//! network execution, qualified identity assertions or monetary transfers.
use wholepact_core::{Amount, IntentStatus, MatchAssurance, ParticipationIntent, ProposalManifest};
use wholepact_engine::{
    Access, CandidateRequest, Engine, planning::RosterSelectionRequest, sponsor_policies::*,
};

fn actor(principal: &str, agreement_id: &str) -> Access {
    Access {
        include_owned_agreements: true,
        principal_id: principal.into(),
        agreement_ids: [agreement_id.into()].into(),
        ..Access::default()
    }
}
fn manifest() -> ProposalManifest {
    serde_json::from_str(include_str!(
        "../../wholepact-core/tests/fixtures/sponsor_manifest.json"
    ))
    .unwrap()
}
fn terms() -> SponsorPolicyTerms {
    serde_json::from_str(include_str!(
        "../../wholepact-core/tests/fixtures/sponsor_policy.json"
    ))
    .unwrap()
}
fn amount(value: u64) -> Amount {
    Amount::from_zatoshis(value).unwrap()
}
fn create_request() -> CreateSponsorPolicyRequest {
    CreateSponsorPolicyRequest {
        policy_id: "policy-one".into(),
        terms: terms(),
    }
}
fn preview_request(candidate_id: &str, version: u32) -> SponsorPolicyPreviewRequest {
    SponsorPolicyPreviewRequest {
        candidate_id: candidate_id.into(),
        expected_policy_version: version,
    }
}
fn state(state: SponsorPolicyState, version: u32) -> SponsorPolicyStateRequest {
    SponsorPolicyStateRequest {
        policy_id: "policy-one".into(),
        expected_policy_version: version,
        state,
    }
}
fn setup_candidate(engine: &Engine, manifest: ProposalManifest) -> (Access, Access, String) {
    let id = &manifest.agreement.agreement_id;
    let owner = actor("organizer", id);
    let sponsor = actor("sponsor-app", id);
    engine
        .create(
            &owner,
            &format!("create-agreement-{id}"),
            manifest.agreement.clone(),
        )
        .unwrap();
    for (index, participant) in manifest.participants.iter().enumerate() {
        engine
            .add_intent(
                &owner,
                &format!("create-intent-{id}-{index}"),
                id,
                index as u64 + 1,
                ParticipationIntent {
                    intent_id: format!("intent-{index}"),
                    agreement_id: id.clone(),
                    participant_id: participant.participant_id.clone(),
                    desired_contribution: participant.contribution,
                    maximum_net_debit: participant.maximum_net_debit,
                    fee_cap: participant.fee_cap,
                    conditions: vec![],
                    valid_until: None,
                    status: IntentStatus::Active,
                },
            )
            .unwrap();
    }
    engine
        .select_roster(
            &owner,
            &format!("select-roster-{id}"),
            id,
            3,
            RosterSelectionRequest {
                selected_intent_ids: vec!["intent-0".into(), "intent-1".into()],
            },
        )
        .unwrap();
    let result = engine
        .create_candidate(
            &owner,
            &format!("create-candidate-{id}"),
            id,
            4,
            CandidateRequest {
                manifest: manifest.clone(),
                previous_candidate_id: None,
            },
        )
        .unwrap();
    (
        owner,
        sponsor,
        result.agreement.candidates[0].candidate_id.clone(),
    )
}

#[test]
fn durable_immutable_versions_replay_and_compare_and_swap() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("synthetic-sponsor.sqlite");
    let engine = Engine::open(&path).unwrap();
    let (_, sponsor, _) = setup_candidate(&engine, manifest());
    let request = create_request();
    let created = engine
        .create_sponsor_policy(
            &sponsor,
            "sponsor-create-key-01",
            "sponsor-agreement",
            5,
            request.clone(),
        )
        .unwrap();
    assert_eq!(created.agreement_revision, 6);
    assert_eq!(created.policy.current_version, 1);
    assert!(!created.policy.authorization_allowed);
    let original_digest = created.policy.versions[0].terms_digest.clone();
    let mut revised_terms = terms();
    revised_terms.assurance = MatchAssurance::Attested {
        verifier_identity: "deliberately-selected-verifier".into(),
    };
    let update = UpdateSponsorPolicyRequest {
        policy_id: "policy-one".into(),
        expected_policy_version: 1,
        terms: revised_terms.clone(),
    };
    let revised = engine
        .update_sponsor_policy(
            &sponsor,
            "sponsor-update-key-01",
            "sponsor-agreement",
            6,
            update.clone(),
        )
        .unwrap();
    assert_eq!(revised.policy.current_version, 2);
    assert_eq!(revised.policy.versions[0].terms_digest, original_digest);
    assert_eq!(
        revised.policy.versions[0].terms.assurance,
        MatchAssurance::IndependentlyVerified
    );
    assert_eq!(
        revised.policy.versions[1].previous_terms_digest.as_ref(),
        Some(&original_digest)
    );
    let replay = engine
        .create_sponsor_policy(
            &sponsor,
            "sponsor-create-key-01",
            "sponsor-agreement",
            5,
            request.clone(),
        )
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.operation_id, created.operation_id);
    assert_eq!(replay.policy.current_version, 1);
    assert_eq!(replay.agreement_revision, 6);
    let replay = engine
        .update_sponsor_policy(
            &sponsor,
            "sponsor-update-key-01",
            "sponsor-agreement",
            6,
            update.clone(),
        )
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.operation_id, revised.operation_id);
    assert_eq!(
        engine
            .update_sponsor_policy(
                &sponsor,
                "sponsor-stale-cas-01",
                "sponsor-agreement",
                6,
                update.clone()
            )
            .unwrap_err()
            .code,
        "REVISION_CONFLICT"
    );
    assert_eq!(
        engine
            .update_sponsor_policy(
                &sponsor,
                "sponsor-stale-ver-01",
                "sponsor-agreement",
                7,
                update
            )
            .unwrap_err()
            .code,
        "REVISION_CONFLICT"
    );
    let mut conflict = request;
    conflict.terms.aggregate_budget = amount(100);
    assert_eq!(
        engine
            .create_sponsor_policy(
                &sponsor,
                "sponsor-create-key-01",
                "sponsor-agreement",
                5,
                conflict
            )
            .unwrap_err()
            .code,
        "IDEMPOTENCY_CONFLICT"
    );
    drop(engine);
    let reopened = Engine::open(&path).unwrap();
    let fetched = reopened
        .sponsor_policy(&sponsor, "sponsor-agreement", "policy-one")
        .unwrap();
    assert_eq!(fetched.versions.len(), 2);
    assert_eq!(fetched.versions[0].terms_digest, original_digest);
    assert_eq!(fetched.versions[1].terms, revised_terms);
}

#[test]
fn exact_preview_stays_unverifiable_and_unknown_budget_is_never_zero() {
    let engine = Engine::in_memory().unwrap();
    let (_, sponsor, candidate) = setup_candidate(&engine, manifest());
    engine
        .create_sponsor_policy(
            &sponsor,
            "sponsor-create-key-02",
            "sponsor-agreement",
            5,
            create_request(),
        )
        .unwrap();
    let events_before = engine.events(&sponsor, 0, 100).unwrap();
    let preview = engine
        .preview_sponsor_policy(
            &sponsor,
            "sponsor-agreement",
            "policy-one",
            preview_request(&candidate, 1),
        )
        .unwrap();
    assert_eq!(preview.formula.evaluation.calculated_match, amount(5));
    assert_eq!(preview.formula.evaluation.eligible_total, amount(8));
    assert_eq!(preview.formula.sponsor_net_debit, amount(6));
    assert_eq!(preview.status, "match_unverifiable");
    assert!(!preview.authorization_allowed);
    assert!(!preview.formula.evaluation.authorization_allowed);
    assert!(preview.budget.pending_authorization_exposure.is_none());
    assert!(preview.budget.settled_debit.is_none());
    assert!(preview.budget.remaining_budget.is_none());
    assert_eq!(engine.events(&sponsor, 0, 100).unwrap(), events_before);
    assert_eq!(
        engine
            .get(&sponsor, "sponsor-agreement")
            .unwrap()
            .authorization_exposure,
        "unknown"
    );
    let mut updated = terms();
    updated.assurance = MatchAssurance::Attested {
        verifier_identity: "named-verifier".into(),
    };
    engine
        .update_sponsor_policy(
            &sponsor,
            "sponsor-update-key-02",
            "sponsor-agreement",
            6,
            UpdateSponsorPolicyRequest {
                policy_id: "policy-one".into(),
                expected_policy_version: 1,
                terms: updated,
            },
        )
        .unwrap();
    assert_eq!(
        engine
            .preview_sponsor_policy(
                &sponsor,
                "sponsor-agreement",
                "policy-one",
                preview_request(&candidate, 1)
            )
            .unwrap_err()
            .code,
        "REVISION_CONFLICT"
    );
    let deliberate = engine
        .preview_sponsor_policy(
            &sponsor,
            "sponsor-agreement",
            "policy-one",
            preview_request(&candidate, 2),
        )
        .unwrap();
    assert!(matches!(
        deliberate.formula.evaluation.assurance,
        MatchAssurance::Attested { .. }
    ));
    assert!(!deliberate.authorization_allowed);
}

#[test]
fn owner_scope_is_stricter_than_agreement_or_admin_read_access() {
    let engine = Engine::in_memory().unwrap();
    let (organizer, sponsor, candidate) = setup_candidate(&engine, manifest());
    let mut request = create_request();
    request
        .terms
        .identity_requirements
        .push("private-sponsor-requirement".into());
    let created = engine
        .create_sponsor_policy(
            &sponsor,
            "sponsor-create-key-03",
            "sponsor-agreement",
            5,
            request,
        )
        .unwrap();
    let administrator = Access {
        include_owned_agreements: true,
        principal_id: "admin".into(),
        all_agreements: true,
        ..Access::default()
    };
    for outsider in [&organizer, &administrator] {
        assert!(
            engine
                .list_sponsor_policies(outsider, "sponsor-agreement")
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            engine
                .sponsor_policy(outsider, "sponsor-agreement", "policy-one")
                .unwrap_err()
                .code,
            "NOT_FOUND"
        );
        assert_eq!(
            engine
                .preview_sponsor_policy(
                    outsider,
                    "sponsor-agreement",
                    "policy-one",
                    preview_request(&candidate, 1)
                )
                .unwrap_err()
                .code,
            "NOT_FOUND"
        );
        assert_eq!(
            engine
                .set_sponsor_policy_state(
                    outsider,
                    "sponsor-illegal-pause",
                    "sponsor-agreement",
                    6,
                    state(SponsorPolicyState::Paused, 1)
                )
                .unwrap_err()
                .code,
            "NOT_FOUND"
        );
        let ordinary =
            serde_json::to_string(&engine.get(outsider, "sponsor-agreement").unwrap()).unwrap();
        assert!(!ordinary.contains("private-sponsor-requirement"));
        let operation = engine
            .operation(outsider, &created.operation_id)
            .unwrap()
            .to_string();
        assert!(!operation.contains("private-sponsor-requirement"));
        assert!(!operation.contains("owner_principal_id"));
        assert!(
            !engine
                .events(outsider, 0, 100)
                .unwrap()
                .to_string()
                .contains("private-sponsor-requirement")
        );
    }
    assert_eq!(
        engine
            .list_sponsor_policies(&sponsor, "sponsor-agreement")
            .unwrap()
            .len(),
        1
    );
    let unscoped = Access {
        include_owned_agreements: true,
        principal_id: "unscoped".into(),
        ..Access::default()
    };
    assert_eq!(
        engine
            .list_sponsor_policies(&unscoped, "sponsor-agreement")
            .unwrap_err()
            .code,
        "NOT_FOUND"
    );
}

#[test]
fn pause_edit_resume_and_retire_preserve_versions_and_exposure() {
    let engine = Engine::in_memory().unwrap();
    let (_, sponsor, candidate) = setup_candidate(&engine, manifest());
    engine
        .create_sponsor_policy(
            &sponsor,
            "sponsor-create-key-04",
            "sponsor-agreement",
            5,
            create_request(),
        )
        .unwrap();
    let paused = engine
        .set_sponsor_policy_state(
            &sponsor,
            "sponsor-pause-key-04",
            "sponsor-agreement",
            6,
            state(SponsorPolicyState::Paused, 1),
        )
        .unwrap();
    assert_eq!(paused.policy.state, SponsorPolicyState::Paused);
    assert_eq!(
        engine
            .preview_sponsor_policy(
                &sponsor,
                "sponsor-agreement",
                "policy-one",
                preview_request(&candidate, 1)
            )
            .unwrap_err()
            .code,
        "INVALID_TRANSITION"
    );
    let mut revised = terms();
    revised.aggregate_budget = amount(100);
    let updated = engine
        .update_sponsor_policy(
            &sponsor,
            "sponsor-update-key-04",
            "sponsor-agreement",
            7,
            UpdateSponsorPolicyRequest {
                policy_id: "policy-one".into(),
                expected_policy_version: 1,
                terms: revised.clone(),
            },
        )
        .unwrap();
    assert_eq!(updated.policy.state, SponsorPolicyState::Paused);
    assert_eq!(updated.policy.versions.len(), 2);
    let resumed = engine
        .set_sponsor_policy_state(
            &sponsor,
            "sponsor-resume-key-04",
            "sponsor-agreement",
            8,
            state(SponsorPolicyState::Draft, 2),
        )
        .unwrap();
    assert!(!resumed.policy.authorization_allowed);
    engine
        .preview_sponsor_policy(
            &sponsor,
            "sponsor-agreement",
            "policy-one",
            preview_request(&candidate, 2),
        )
        .unwrap();
    let retired = engine
        .set_sponsor_policy_state(
            &sponsor,
            "sponsor-retire-key-04",
            "sponsor-agreement",
            9,
            state(SponsorPolicyState::Retired, 2),
        )
        .unwrap();
    assert_eq!(retired.policy.versions.len(), 2);
    assert_eq!(
        engine
            .set_sponsor_policy_state(
                &sponsor,
                "sponsor-resume-again",
                "sponsor-agreement",
                10,
                state(SponsorPolicyState::Draft, 2)
            )
            .unwrap_err()
            .code,
        "INVALID_TRANSITION"
    );
    assert_eq!(
        engine
            .update_sponsor_policy(
                &sponsor,
                "sponsor-update-retired",
                "sponsor-agreement",
                10,
                UpdateSponsorPolicyRequest {
                    policy_id: "policy-one".into(),
                    expected_policy_version: 2,
                    terms: revised,
                }
            )
            .unwrap_err()
            .code,
        "INVALID_TRANSITION"
    );
    let replay = engine
        .set_sponsor_policy_state(
            &sponsor,
            "sponsor-retire-key-04",
            "sponsor-agreement",
            9,
            state(SponsorPolicyState::Retired, 2),
        )
        .unwrap();
    assert!(replay.replayed);
    let agreement = engine.get(&sponsor, "sponsor-agreement").unwrap();
    assert_eq!(agreement.authorization_exposure, "unknown");
    assert_eq!(agreement.chain_observation, "unknown");
}

#[test]
fn reusable_scope_does_not_grant_access_to_another_agreement() {
    let engine = Engine::in_memory().unwrap();
    let (_, mut sponsor, _) = setup_candidate(&engine, manifest());
    let mut other = manifest();
    other.agreement.agreement_id = "other-agreement".into();
    other.agreement.obligation_id = "other-obligation".into();
    let (_, _, other_candidate) = setup_candidate(&engine, other);
    let mut request = create_request();
    request.terms.agreement_scope.push("other-agreement".into());
    engine
        .create_sponsor_policy(
            &sponsor,
            "sponsor-create-key-05",
            "sponsor-agreement",
            5,
            request,
        )
        .unwrap();
    assert_eq!(
        engine
            .preview_sponsor_policy(
                &sponsor,
                "sponsor-agreement",
                "policy-one",
                preview_request(&other_candidate, 1)
            )
            .unwrap_err()
            .code,
        "NOT_FOUND"
    );
    sponsor.agreement_ids.insert("other-agreement".into());
    let result = engine
        .preview_sponsor_policy(
            &sponsor,
            "sponsor-agreement",
            "policy-one",
            preview_request(&other_candidate, 1),
        )
        .unwrap();
    assert_eq!(result.policy_agreement_id, "sponsor-agreement");
    assert_eq!(result.candidate_agreement_id, "other-agreement");
    assert!(!result.authorization_allowed);
}

#[test]
fn withdrawal_stale_candidate_and_invalid_terms_never_refresh_preview() {
    let engine = Engine::in_memory().unwrap();
    let (owner, sponsor, first_candidate) = setup_candidate(&engine, manifest());
    engine
        .create_sponsor_policy(
            &sponsor,
            "sponsor-create-key-06",
            "sponsor-agreement",
            5,
            create_request(),
        )
        .unwrap();
    let second = engine
        .create_candidate(
            &owner,
            "sponsor-second-candidate",
            "sponsor-agreement",
            6,
            CandidateRequest {
                manifest: manifest(),
                previous_candidate_id: Some(first_candidate.clone()),
            },
        )
        .unwrap()
        .agreement
        .candidates[1]
        .candidate_id
        .clone();
    assert_eq!(
        engine
            .preview_sponsor_policy(
                &sponsor,
                "sponsor-agreement",
                "policy-one",
                preview_request(&first_candidate, 1)
            )
            .unwrap_err()
            .code,
        "REVISION_CONFLICT"
    );
    engine
        .preview_sponsor_policy(
            &sponsor,
            "sponsor-agreement",
            "policy-one",
            preview_request(&second, 1),
        )
        .unwrap();
    engine
        .withdraw(
            &owner,
            "sponsor-withdraw-intent",
            "sponsor-agreement",
            "intent-0",
            7,
        )
        .unwrap();
    assert!(
        engine
            .preview_sponsor_policy(
                &sponsor,
                "sponsor-agreement",
                "policy-one",
                preview_request(&second, 1)
            )
            .is_err()
    );
    let mut invalid = create_request();
    invalid.policy_id = "expired-policy".into();
    invalid.terms.expires_at = Some("2020-01-01T00:00:00Z".into());
    assert_eq!(
        engine
            .create_sponsor_policy(
                &sponsor,
                "sponsor-create-expired",
                "sponsor-agreement",
                8,
                invalid
            )
            .unwrap_err()
            .code,
        "INVALID_TERMS"
    );
    let mut forged = serde_json::to_value(create_request()).unwrap();
    forged["terms"]["ownership_verified"] = serde_json::json!(true);
    assert!(serde_json::from_value::<CreateSponsorPolicyRequest>(forged).is_err());
    let mut request = serde_json::to_value(preview_request(&second, 1)).unwrap();
    request["eligible_total"] = serde_json::json!("1000000");
    assert!(serde_json::from_value::<SponsorPolicyPreviewRequest>(request).is_err());
}

#[test]
fn bounded_policy_count_version_history_and_failed_writes_are_atomic() {
    let engine = Engine::in_memory().unwrap();
    let (_, sponsor, _) = setup_candidate(&engine, manifest());
    let mut revision = 5;
    for index in 0..MAX_SPONSOR_POLICIES {
        let mut request = create_request();
        request.policy_id = format!("bounded-policy-{index}");
        revision = engine
            .create_sponsor_policy(
                &sponsor,
                &format!("bounded-create-key-{index}"),
                "sponsor-agreement",
                revision,
                request,
            )
            .unwrap()
            .agreement_revision;
    }
    assert_eq!(
        engine
            .create_sponsor_policy(
                &sponsor,
                "bounded-create-overflow",
                "sponsor-agreement",
                revision,
                create_request()
            )
            .unwrap_err()
            .code,
        "RESOURCE_EXHAUSTED"
    );
    assert_eq!(
        engine.get(&sponsor, "sponsor-agreement").unwrap().revision,
        revision
    );
    for version in 2..=MAX_SPONSOR_POLICY_VERSIONS {
        let mut changed = terms();
        changed.aggregate_budget = amount(50 + version as u64);
        revision = engine
            .update_sponsor_policy(
                &sponsor,
                &format!("bounded-version-key-{version}"),
                "sponsor-agreement",
                revision,
                UpdateSponsorPolicyRequest {
                    policy_id: "bounded-policy-0".into(),
                    expected_policy_version: version as u32 - 1,
                    terms: changed,
                },
            )
            .unwrap()
            .agreement_revision;
    }
    let mut changed = terms();
    changed.aggregate_budget = amount(100);
    assert_eq!(
        engine
            .update_sponsor_policy(
                &sponsor,
                "bounded-version-overflow",
                "sponsor-agreement",
                revision,
                UpdateSponsorPolicyRequest {
                    policy_id: "bounded-policy-0".into(),
                    expected_policy_version: MAX_SPONSOR_POLICY_VERSIONS as u32,
                    terms: changed,
                }
            )
            .unwrap_err()
            .code,
        "RESOURCE_EXHAUSTED"
    );
    assert_eq!(
        engine.get(&sponsor, "sponsor-agreement").unwrap().revision,
        revision
    );
    assert_eq!(
        engine
            .sponsor_policy(&sponsor, "sponsor-agreement", "bounded-policy-0")
            .unwrap()
            .versions
            .len(),
        MAX_SPONSOR_POLICY_VERSIONS
    );
}

#[test]
fn old_envelopes_default_empty_and_tampered_history_requires_recovery() {
    use wholepact_store::{CommandContext, Store};
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("synthetic-history.sqlite");
    let engine = Engine::open(&path).unwrap();
    let (_, sponsor, _) = setup_candidate(&engine, manifest());
    let store = Store::open(&path).unwrap();
    let mut old = store.get_agreement("sponsor-agreement").unwrap().unwrap();
    old.payload
        .as_object_mut()
        .unwrap()
        .remove("sponsor_policies");
    let command =
        CommandContext::for_request("synthetic-test", "simulate-old-envelope", &old.payload)
            .unwrap();
    store
        .update_agreement(
            &command,
            "sponsor-agreement",
            old.revision,
            old.payload,
            "synthetic_legacy_fixture",
        )
        .unwrap();
    assert!(
        engine
            .list_sponsor_policies(&sponsor, "sponsor-agreement")
            .unwrap()
            .is_empty()
    );
    engine
        .create_sponsor_policy(
            &sponsor,
            "sponsor-create-key-08",
            "sponsor-agreement",
            6,
            create_request(),
        )
        .unwrap();
    let mut corrupt = store.get_agreement("sponsor-agreement").unwrap().unwrap();
    corrupt.payload["sponsor_policies"]["policy-one"]["versions"][0]["terms"]["aggregate_budget"] =
        serde_json::json!("999");
    let command = CommandContext::for_request(
        "synthetic-test",
        "simulate-tampered-history",
        &corrupt.payload,
    )
    .unwrap();
    store
        .update_agreement(
            &command,
            "sponsor-agreement",
            corrupt.revision,
            corrupt.payload,
            "synthetic_corruption_fixture",
        )
        .unwrap();
    assert_eq!(
        engine
            .sponsor_policy(&sponsor, "sponsor-agreement", "policy-one")
            .unwrap_err()
            .code,
        "RECOVERY_REQUIRED"
    );
}
