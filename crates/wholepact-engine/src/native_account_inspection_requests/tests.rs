#![cfg(target_os = "linux")]
use super::*;
use crate::{Access, CandidateRequest, Engine};
use wholepact_core::*;
use wholepact_storage_security::DatabaseKey;
use wholepact_store::Store;

fn actor() -> Access {
    Access {
        include_owned_agreements: true,
        principal_id: "local-organizer".into(),
        ..Access::default()
    }
}
fn amount(n: u64) -> Amount {
    Amount::from_zatoshis(n).unwrap()
}
fn request() -> CandidateRequest {
    let mut agreement: AgreementDraft = serde_json::from_str(include_str!(
        "../../../wholepact-core/tests/fixtures/agreement.json"
    ))
    .unwrap();
    agreement.network_profile_id = "ironwood-testnet-nu7-candidate".into();
    agreement.recipients[0].amount = amount(300_000);
    agreement.funding_policy = FundingPolicy::Exact {
        target: amount(300_000),
    };
    let participants = vec![
        ParticipantAllocation {
            participant_id: "alice".into(),
            account_id: "account-a".into(),
            contribution: amount(100_000),
            fee_share: amount(5_000),
            fee_cap: amount(5_000),
            maximum_net_debit: amount(105_000),
            charges: vec![],
        },
        ParticipantAllocation {
            participant_id: "bob".into(),
            account_id: "account-b".into(),
            contribution: amount(200_000),
            fee_share: amount(10_000),
            fee_cap: amount(10_000),
            maximum_net_debit: amount(210_000),
            charges: vec![],
        },
    ];
    let inputs = participants
        .iter()
        .enumerate()
        .map(|(i, p)| ClaimedInput {
            input_id: format!("input-{i}"),
            participant_id: p.participant_id.clone(),
            account_id: p.account_id.clone(),
            amount: amount(if i == 0 { 200_000 } else { 300_000 }),
            ownership_evidence_ref: None,
        })
        .collect();
    let mut outputs = vec![ClaimedOutput {
        output_id: "recipient-output".into(),
        address: agreement.recipients[0].address.clone(),
        amount: amount(300_000),
        allocation: OutputAllocation::Recipient {
            recipient_id: agreement.recipients[0].recipient_id.clone(),
        },
    }];
    for (i, p) in participants.iter().enumerate() {
        outputs.push(ClaimedOutput {
            output_id: format!("change-{i}"),
            address: format!("utestsyntheticchange{i}"),
            amount: amount(if i == 0 { 95_000 } else { 90_000 }),
            allocation: OutputAllocation::Return {
                participant_id: p.participant_id.clone(),
                account_id: p.account_id.clone(),
                ownership_evidence_ref: None,
            },
        });
    }
    CandidateRequest {
        manifest: ProposalManifest {
            agreement,
            participants,
            inputs,
            outputs,
            transaction_fee: amount(15_000),
            expiry_height: 4_465_070,
        },
        previous_candidate_id: None,
    }
}
fn create_intents(engine: &Engine, request: &CandidateRequest) {
    let id = &request.manifest.agreement.agreement_id;
    engine
        .create(
            &actor(),
            "candidate-create-agreement",
            request.manifest.agreement.clone(),
        )
        .unwrap();
    for (i, p) in request.manifest.participants.iter().enumerate() {
        engine
            .add_intent(
                &actor(),
                &format!("candidate-intent-{i:04}"),
                id,
                i as u64 + 1,
                ParticipationIntent {
                    intent_id: format!("intent-{i}"),
                    agreement_id: id.clone(),
                    participant_id: p.participant_id.clone(),
                    desired_contribution: p.contribution,
                    maximum_net_debit: p.maximum_net_debit,
                    fee_cap: p.fee_cap,
                    conditions: vec![],
                    valid_until: None,
                    status: IntentStatus::Active,
                },
            )
            .unwrap();
    }
}

fn fixture() -> (tempfile::TempDir, Engine, String, String) {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let engine = Engine::from_store(
        Store::create_encrypted(
            dir.path().join("requests.sqlite"),
            &DatabaseKey::from_bytes([82; 32]),
        )
        .unwrap(),
    );
    let input = request();
    let id = input.manifest.agreement.agreement_id.clone();
    create_intents(&engine, &input);
    let result = engine
        .create_candidate(&actor(), "candidate-freeze-command", &id, 3, input)
        .unwrap();
    let candidate = result.agreement.candidates[0].candidate_id.clone();
    (dir, engine, id, candidate)
}

fn enqueue(
    engine: &Engine,
    agreement: &str,
    candidate: &str,
) -> NativeAccountInspectionRequestView {
    engine
        .queue_native_account_inspection(
            &actor(),
            "original-audit-key",
            agreement,
            4,
            NativeAccountInspectionRequest {
                candidate_id: candidate.into(),
                participant_id: "alice".into(),
            },
        )
        .unwrap()
}
fn snapshot(attempt: &NativeAccountInspectionAttempt) -> OwnerInspectionSnapshot {
    OwnerInspectionSnapshot {
        schema_version: 1,
        request: attempt.request().clone(),
        account_id: attempt.expected_account_id().into(),
        source_principal_id: "synthetic-native-owner".into(),
        writer_epoch: 1,
        recovery_required: false,
        inspected_at_ms: 1,
        provenance: "native_owner_approved_local_signer_journal".into(),
        freshness: "historical_local_snapshot_no_live_witness_or_chain_observation".into(),
        authorization_allowed: false,
        balance: None,
        account_pending_exposure: None,
        account_settled_debit: None,
        account_remaining_budget: None,
        authorizations: vec![],
        sponsor_policies: vec![],
        automation_grants: vec![],
    }
}
#[test]
fn started_interruption_preserves_original_key_and_unknown_without_second_execution() {
    let (dir, engine, agreement, candidate) = fixture();
    let queued = enqueue(&engine, &agreement, &candidate);
    let id = &queued.request.request_id;
    let _attempt = engine
        .mark_native_account_inspection_attempt(&actor(), &agreement, id)
        .unwrap();
    drop(engine);
    let engine = Engine::from_store(
        Store::open_encrypted(
            dir.path().join("requests.sqlite"),
            &DatabaseKey::from_bytes([82; 32]),
        )
        .unwrap(),
    );
    let replay = enqueue(&engine, &agreement, &candidate);
    assert_eq!(replay.request, queued.request);
    assert_eq!(replay.state, NativeRequestState::AttemptStarted);
    assert_eq!(replay.result_status, "unknown_no_committed_result");
    assert!(replay.result.is_none());
    assert!(
        engine
            .mark_native_account_inspection_attempt(&actor(), &agreement, id)
            .is_err()
    );
    assert!(
        engine
            .withdraw_native_account_inspection(
                &actor(),
                "cannot-withdraw-started",
                &agreement,
                6,
                id
            )
            .is_err()
    );
}
#[test]
fn committed_snapshot_is_exact_immutable_history_on_replay_and_cannot_be_overwritten() {
    let (dir, engine, agreement, candidate) = fixture();
    let queued = enqueue(&engine, &agreement, &candidate);
    let attempt = engine
        .mark_native_account_inspection_attempt(&actor(), &agreement, &queued.request.request_id)
        .unwrap();
    let original = snapshot(&attempt);
    let stale = NativeAccountInspectionAttempt {
        saved: attempt.saved.clone(),
    };
    engine
        .retain_owner_inspection(&actor(), attempt, original.clone())
        .unwrap();
    let replay = enqueue(&engine, &agreement, &candidate);
    assert_eq!(replay.result.as_ref(), Some(&original));
    let mut changed = original.clone();
    changed.inspected_at_ms += 1;
    assert!(
        engine
            .retain_owner_inspection(&actor(), stale, changed)
            .is_err()
    );
    assert_eq!(engine.get(&actor(), &agreement).unwrap().revision, 7);
    drop(engine);
    let reopened = Engine::from_store(
        Store::open_encrypted(
            dir.path().join("requests.sqlite"),
            &DatabaseKey::from_bytes([82; 32]),
        )
        .unwrap(),
    );
    assert_eq!(
        enqueue(&reopened, &agreement, &candidate).result,
        Some(original)
    );
}
#[test]
fn another_principal_cannot_read_or_supply_account_id_results_or_native_approval() {
    let (_dir, engine, agreement, candidate) = fixture();
    let queued = enqueue(&engine, &agreement, &candidate);
    let other = Access {
        principal_id: "other-owner".into(),
        all_agreements: true,
        ..Access::default()
    };
    assert!(
        engine
            .native_account_inspection_requests(&other, &agreement)
            .unwrap()
            .is_empty()
    );
    assert!(
        engine
            .native_account_inspection_request(&other, &agreement, &queued.request.request_id)
            .is_err()
    );
    assert!(
        engine
            .mark_native_account_inspection_attempt(&other, &agreement, &queued.request.request_id)
            .is_err()
    );
    for field in [
        "account_id",
        "approved",
        "result",
        "balance",
        "witness",
        "grant",
        "permission",
    ] {
        let mut request = json!({"candidate_id":candidate,"participant_id":"alice"});
        request[field] = json!(true);
        assert!(serde_json::from_value::<NativeAccountInspectionRequest>(request).is_err());
    }
}
#[test]
fn mismatched_account_or_scope_and_invented_zero_exposure_fail_closed() {
    for case in 0..5 {
        let (_dir, engine, agreement, candidate) = fixture();
        let queued = enqueue(&engine, &agreement, &candidate);
        let attempt = engine
            .mark_native_account_inspection_attempt(
                &actor(),
                &agreement,
                &queued.request.request_id,
            )
            .unwrap();
        let mut value = snapshot(&attempt);
        match case {
            0 => value.account_id = "account-b".into(),
            1 => value.request.principal_id = "other-owner".into(),
            2 => value.account_pending_exposure = Some(amount(0)),
            3 => value.authorization_allowed = true,
            _ => value.freshness = "live".into(),
        }
        assert!(
            engine
                .retain_owner_inspection(&actor(), attempt, value)
                .is_err()
        );
        assert!(
            engine
                .native_account_inspection_request(&actor(), &agreement, &queued.request.request_id)
                .unwrap()
                .result
                .is_none()
        );
    }
}
#[test]
fn withdraw_and_scope_restriction_preserve_attempt_boundary() {
    let (_dir, engine, agreement, candidate) = fixture();
    let queued = enqueue(&engine, &agreement, &candidate);
    engine
        .withdraw_native_account_inspection(
            &actor(),
            "withdraw-original",
            &agreement,
            5,
            &queued.request.request_id,
        )
        .unwrap();
    assert!(
        engine
            .mark_native_account_inspection_attempt(
                &actor(),
                &agreement,
                &queued.request.request_id
            )
            .is_err()
    );
    assert_eq!(
        enqueue(&engine, &agreement, &candidate).state,
        NativeRequestState::Withdrawn
    );
    let denied = Access {
        principal_id: actor().principal_id,
        ..Access::default()
    };
    assert!(
        engine
            .native_account_inspection_request(&denied, &agreement, &queued.request.request_id)
            .is_err()
    );
}

#[test]
fn repeated_queue_and_stale_queue_cannot_manufacture_an_attempt() {
    let (_dir, engine, agreement, candidate) = fixture();
    let queued = enqueue(&engine, &agreement, &candidate);
    let repeat = engine.queue_native_account_inspection(
        &actor(),
        "different-audit-key",
        &agreement,
        5,
        NativeAccountInspectionRequest {
            candidate_id: candidate,
            participant_id: "alice".into(),
        },
    );
    assert_eq!(repeat.unwrap_err().code, "INVALID_TRANSITION");
    let (revision, mut envelope) = {
        let e = engine.load(&actor(), &agreement).unwrap();
        (e.view.revision, e)
    };
    envelope.view.cancellation_requested = true;
    let command = context(
        &actor(),
        "unrelated-journal-change",
        "synthetic-read-only-test",
        &agreement,
        Some(revision),
        &json!({}),
    )
    .unwrap();
    engine
        .commit(
            &command,
            &agreement,
            revision,
            envelope,
            "synthetic-no-financial-effects",
        )
        .unwrap();
    assert!(
        engine
            .mark_native_account_inspection_attempt(
                &actor(),
                &agreement,
                &queued.request.request_id
            )
            .is_err()
    );
    assert_eq!(
        engine
            .native_account_inspection_request(&actor(), &agreement, &queued.request.request_id)
            .unwrap()
            .state,
        NativeRequestState::Queued
    );
}
