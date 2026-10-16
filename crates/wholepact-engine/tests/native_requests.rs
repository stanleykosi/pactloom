#![cfg(target_os = "linux")]
use wholepact_core::*;
use wholepact_engine::native_requests::*;
use wholepact_engine::{Access, CandidateRequest, Engine};
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
        "../../wholepact-core/tests/fixtures/agreement.json"
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
fn enqueue(engine: &Engine, id: &str, candidate: &str) -> NativeRequestView {
    engine
        .queue_native_construction(
            &actor(),
            "native-queue-original",
            id,
            4,
            NativeConstructionRequest {
                candidate_id: candidate.into(),
            },
        )
        .unwrap()
}
#[test]
fn exact_retry_keeps_original_identity_and_revision_after_start() {
    let (_dir, engine, id, candidate) = fixture();
    let queued = enqueue(&engine, &id, &candidate);
    assert_eq!(queued.queued_revision, 5);
    let attempted = engine
        .mark_native_construction_attempt(&actor(), &id, &queued.request_id)
        .unwrap();
    assert_eq!(attempted.revision(), 6);
    assert_eq!(attempted.candidate_id(), candidate);
    assert_eq!(
        attempted.construction_key(),
        format!("native-construction-{}", queued.request_id)
    );
    let replay = enqueue(&engine, &id, &candidate);
    assert_eq!(replay.request_id, queued.request_id);
    assert_eq!(replay.state, NativeRequestState::AttemptStarted);
    assert!(!replay.authorization_allowed);
    assert_eq!(replay.result_status, "unknown_not_financial_evidence");
    assert_eq!(engine.get(&actor(), &id).unwrap().revision, 6);
    assert!(
        engine
            .mark_native_construction_attempt(&actor(), &id, &queued.request_id)
            .is_err()
    );
}
#[test]
fn scope_and_request_owner_are_rechecked_even_for_replay() {
    let (_dir, engine, id, candidate) = fixture();
    let queued = enqueue(&engine, &id, &candidate);
    let hidden = Access {
        principal_id: actor().principal_id,
        ..Access::default()
    };
    assert!(
        engine
            .queue_native_construction(
                &hidden,
                "native-queue-original",
                &id,
                4,
                NativeConstructionRequest {
                    candidate_id: candidate
                }
            )
            .is_err()
    );
    let other = Access {
        principal_id: "other".into(),
        all_agreements: true,
        ..Access::default()
    };
    assert!(
        engine
            .native_request(&other, &id, &queued.request_id)
            .is_err()
    );
    assert!(engine.native_requests(&other, &id).unwrap().is_empty());
    assert!(
        engine
            .mark_native_construction_attempt(&other, &id, &queued.request_id)
            .is_err()
    );
}
#[test]
fn unrelated_revision_change_prevents_native_start() {
    let (_dir, engine, id, candidate) = fixture();
    let queued = enqueue(&engine, &id, &candidate);
    engine
        .review_candidate(&actor(), "review-after-queue-change", &candidate, 5)
        .unwrap();
    assert!(
        engine
            .mark_native_construction_attempt(&actor(), &id, &queued.request_id)
            .is_err()
    );
    assert_eq!(
        engine
            .native_request(&actor(), &id, &queued.request_id)
            .unwrap()
            .state,
        NativeRequestState::Queued
    );
}
#[test]
fn withdrawn_requests_cannot_start_and_started_requests_cannot_withdraw() {
    let (_dir, engine, id, candidate) = fixture();
    let queued = enqueue(&engine, &id, &candidate);
    let withdrawn = engine
        .withdraw_native_request(&actor(), "native-withdraw-key", &id, 5, &queued.request_id)
        .unwrap();
    assert_eq!(withdrawn.state, NativeRequestState::Withdrawn);
    assert!(
        engine
            .mark_native_construction_attempt(&actor(), &id, &queued.request_id)
            .is_err()
    );
    let next = engine
        .queue_native_construction(
            &actor(),
            "native-queue-second",
            &id,
            6,
            NativeConstructionRequest {
                candidate_id: candidate.clone(),
            },
        )
        .unwrap();
    engine
        .mark_native_construction_attempt(&actor(), &id, &next.request_id)
        .unwrap();
    assert!(
        engine
            .withdraw_native_request(&actor(), "withdraw-after-attempt", &id, 8, &next.request_id)
            .is_err()
    );
    assert!(
        engine
            .queue_native_construction(
                &actor(),
                "replacement-ambiguous",
                &id,
                8,
                NativeConstructionRequest {
                    candidate_id: candidate
                }
            )
            .is_err()
    );
}
#[test]
fn interrupted_attempt_survives_restart_as_unknown_without_rerun() {
    let (dir, engine, id, candidate) = fixture();
    let queued = enqueue(&engine, &id, &candidate);
    engine
        .mark_native_construction_attempt(&actor(), &id, &queued.request_id)
        .unwrap();
    drop(engine);
    let engine = Engine::from_store(
        Store::open_encrypted(
            dir.path().join("requests.sqlite"),
            &DatabaseKey::from_bytes([82; 32]),
        )
        .unwrap(),
    );
    let saved = engine
        .native_request(&actor(), &id, &queued.request_id)
        .unwrap();
    assert_eq!(saved.state, NativeRequestState::AttemptStarted);
    assert_eq!(saved.result_status, "unknown_not_financial_evidence");
    assert!(
        engine
            .mark_native_construction_attempt(&actor(), &id, &queued.request_id)
            .is_err()
    );
}
#[test]
fn unencrypted_engine_and_approval_shaped_input_are_rejected() {
    let engine = Engine::in_memory().unwrap();
    assert!(
        engine
            .queue_native_construction(
                &actor(),
                "native-queue-original",
                "id",
                1,
                NativeConstructionRequest {
                    candidate_id: "candidate".into()
                }
            )
            .is_err()
    );
    assert!(
        serde_json::from_value::<NativeConstructionRequest>(serde_json::json!({
            "candidate_id":"candidate", "approved":true
        }))
        .is_err()
    );
}
#[test]
fn lifetime_quota_preserves_withdrawn_history() {
    let (_dir, engine, id, candidate) = fixture();
    let mut revision = 4;
    for i in 0..MAX_NATIVE_REQUESTS {
        let queued = engine
            .queue_native_construction(
                &actor(),
                &format!("bounded-request-{i:04}"),
                &id,
                revision,
                NativeConstructionRequest {
                    candidate_id: candidate.clone(),
                },
            )
            .unwrap();
        revision += 1;
        engine
            .withdraw_native_request(
                &actor(),
                &format!("bounded-withdraw-{i:04}"),
                &id,
                revision,
                &queued.request_id,
            )
            .unwrap();
        revision += 1;
    }
    assert_eq!(
        engine.native_requests(&actor(), &id).unwrap().len(),
        MAX_NATIVE_REQUESTS
    );
    assert!(
        engine
            .queue_native_construction(
                &actor(),
                "native-over-quota-key",
                &id,
                revision,
                NativeConstructionRequest {
                    candidate_id: candidate
                }
            )
            .is_err()
    );
}

#[test]
fn legacy_empty_map_stays_omitted_and_request_survives_operation_history() {
    let (dir, engine, id, candidate) = fixture();
    drop(engine);
    let key = DatabaseKey::from_bytes([82; 32]);
    let store = Store::open_encrypted(dir.path().join("requests.sqlite"), &key).unwrap();
    let before = store.get_agreement(&id).unwrap().unwrap();
    assert!(before.payload.get("native_requests").is_none());
    let engine = Engine::from_store(store);
    let queued = enqueue(&engine, &id, &candidate);
    engine
        .mark_native_construction_attempt(&actor(), &id, &queued.request_id)
        .unwrap();
    drop(engine);
    let store = Store::open_encrypted(dir.path().join("requests.sqlite"), &key).unwrap();
    let latest = store.get_agreement(&id).unwrap().unwrap();
    assert_eq!(
        latest.payload["native_requests"][&queued.request_id]["state"],
        "attempt_started"
    );
    let events = store.events_after(0, 100).unwrap();
    let queued_event = events
        .iter()
        .find(|event| event.kind == "native_construction_requested")
        .unwrap();
    let operation = store
        .get_operation(&queued_event.operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        operation.result["record"]["payload"]["native_requests"][&queued.request_id]["state"],
        "queued"
    );
}

#[test]
fn concurrent_native_starts_return_at_most_one_attempt() {
    let (_dir, engine, id, candidate) = fixture();
    let queued = enqueue(&engine, &id, &candidate);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let engine = engine.clone();
            let id = id.clone();
            let request = queued.request_id.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                engine
                    .mark_native_construction_attempt(&actor(), &id, &request)
                    .is_ok()
            })
        })
        .collect();
    assert_eq!(
        threads
            .into_iter()
            .map(|thread| usize::from(thread.join().unwrap()))
            .sum::<usize>(),
        1
    );
    assert_eq!(engine.get(&actor(), &id).unwrap().revision, 6);
}

#[test]
fn native_attempt_backup_preserves_complete_history_and_restores_inert() {
    use std::collections::BTreeMap;
    use wholepact_storage_security::bundle::*;
    struct Gate;
    impl BundleLease for Gate {
        fn check_current(&self) -> std::result::Result<(), BundleError> {
            Ok(())
        }
        fn checkpoint_id(&self) -> &str {
            "synthetic-request-writers-stopped"
        }
    }
    impl BundleAuthority for Gate {
        fn acquire<'a>(
            &'a self,
            scope: &BundleScope<'_>,
        ) -> std::result::Result<Box<dyn BundleLease + 'a>, BundleError> {
            if scope.principal_id != "synthetic-admin" || scope.profile_id != "synthetic-profile" {
                return Err(BundleError::Permission);
            }
            Ok(Box::new(Gate))
        }
    }
    let (dir, engine, id, candidate) = fixture();
    let queued = enqueue(&engine, &id, &candidate);
    engine
        .mark_native_construction_attempt(&actor(), &id, &queued.request_id)
        .unwrap();
    drop(engine);
    let key = DatabaseKey::from_bytes([82; 32]);
    let store = Store::open_encrypted(dir.path().join("requests.sqlite"), &key).unwrap();
    let adapter = wholepact_store::bundle::CoordinationBundleAdapter::new(&store).unwrap();
    let sources = [RegisteredJournal::new("coordination", &adapter).unwrap()];
    let archive = dir.path().join("archive");
    snapshot(SnapshotRequest {
        principal_id: "synthetic-admin",
        profile_id: "synthetic-profile",
        sources: &sources,
        destination: &archive,
        key: &key,
        authority: &Gate,
        coverage: Coverage {
            present: BTreeMap::from([(
                JournalKind::CoordinationAuthority,
                vec!["coordination".into()],
            )]),
            absent: [
                JournalKind::SignerConsentAuthority,
                JournalKind::WalletScan,
                JournalKind::ProofWitness,
                JournalKind::SignedResults,
                JournalKind::ExactTransactions,
                JournalKind::Submission,
                JournalKind::TransportInbox,
                JournalKind::TransportOutbox,
            ]
            .into(),
        },
    })
    .unwrap();
    let restored = dir.path().join("restored");
    test_restore(RestoreRequest {
        principal_id: "synthetic-admin",
        profile_id: "synthetic-profile",
        archive: &archive,
        key: &key,
        targets: &[RestoreTarget {
            component_id: "coordination",
            template: wholepact_store::bundle::coordination_template(),
            destination: &restored,
            key: &key,
        }],
        authority: &Gate,
    })
    .unwrap();
    assert!(Store::open_encrypted(&restored, &key).is_err());
    let source = recovery::VerifiedRecoveryComponent::open(
        history::HistoryOpenRequest {
            archive: &archive,
            archive_key: &key,
            component_id: "coordination",
            restored_component: &restored,
            restored_key: &key,
        },
        wholepact_store::bundle::coordination_template(),
    )
    .unwrap();
    let inventory = wholepact_engine::recovery::inspect_coordination_recovery(&source).unwrap();
    let latest = inventory
        .store_inventory()
        .agreements()
        .iter()
        .find(|record| record.id == id)
        .unwrap();
    assert_eq!(
        latest.payload["native_requests"][&queued.request_id]["state"],
        "attempt_started"
    );
    assert!(
        inventory
            .store_inventory()
            .historical_agreements()
            .iter()
            .any(
                |record| record.payload["native_requests"][&queued.request_id]["state"] == "queued"
            )
    );
    assert!(Store::open_encrypted(&restored, &key).is_err());
}
