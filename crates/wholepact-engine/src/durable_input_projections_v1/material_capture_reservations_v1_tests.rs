//! Inert private-state and ordering tests only. Synthetic receipt DTOs here do
//! NOT authenticate a native peer, admit material, issue a ticket, run a scan,
//! prove SQLCipher crash recovery, or qualify an end-to-end capture operation.
use super::*;
use wholepact_signer_origin::durable_input_projection_v1::{
    projection_pairing_review_digest_v1, ProjectionChannelBindingV1,
};

fn receipt(projection: DurableInputProjectionV1) -> Intake {
    let request = DurableInputProjectionRequestV1 {
        version: 1,
        operation_id: format!("synthetic-discovery-{}", projection.intent.participant_id),
        intent: projection.intent.clone(),
    };
    let scope = request.pair_scope().unwrap();
    let process = "45".repeat(32);
    let channel_binding_digest = projection_pairing_review_digest_v1(&scope, &process, 1).unwrap();
    let mut outbox = DurableInputProjectionOutboxV1 {
        version: 1,
        request_digest: request.digest().unwrap(),
        projection_digest: projection.digest().unwrap(),
        request,
        projection,
        native_review_digest: "56".repeat(32),
        native_entry_digest: "67".repeat(32),
        recipient: ProjectionChannelBindingV1 {
            version: 1,
            scope,
            grant_id: "78".repeat(32),
            authenticated_local_grant_digest: "89".repeat(32),
            channel_binding_digest,
            uid: 1000,
            pid: 42,
            process_instance: process.clone(),
            signer_generation: 1,
        },
        reference: "00".repeat(32),
    };
    outbox.reference = outbox.compute_reference().unwrap();
    outbox.validate().unwrap();
    Intake {
        signer_enrollment_reference: "90".repeat(32),
        signer_process_instance: process,
        outbox,
        redelivery: None,
    }
}
fn fixture() -> (
    Round,
    DurableConstructionCaptureRequestV1,
    DurableExactConstructionAnchorV1,
) {
    let (first, request, anchor, _) = exact_material_v1::tests::fixture();
    let mut second = first.clone();
    second.intent.account_id = "22".repeat(32);
    second.intent.participant_id = "owner-1".into();
    second.intent.privacy_domain = "owner-1-privacy".into();
    second.inputs[0].input_id = format!("ironwood:{}:0", "bb".repeat(32));
    second.own_return_receiver = "usyntheticreturn1".into();
    let intakes: BTreeMap<_, _> = [first, second]
        .into_iter()
        .map(|projection| (projection.intent.account_id.clone(), receipt(projection)))
        .collect();
    let proposal = Proposal::validate(request.scope.proposal.clone()).unwrap();
    let round = Round {
        version: 1,
        principal_id: request.scope.constructor.principal_id.clone(),
        metadata_origin: "ab".repeat(32),
        created_at: request.scope.proposal.created_at.clone(),
        previous_candidate_id: None,
        requests: intakes
            .iter()
            .map(|(account, i)| (account.clone(), i.outbox.request.clone()))
            .collect(),
        intakes,
        frozen_manifest_digest: Some(proposal.manifest_digest().into()),
        capture_intents: BTreeMap::new(),
    };
    round.validate(&request.scope.proposal.proposal_id).unwrap();
    assert!(
        round
            .candidate(&request.scope.proposal.proposal_id)
            .unwrap()
            .input()
            == &request.scope.proposal
    );
    (round, request, anchor)
}
fn make_intent(
    round: &Round,
    request: DurableConstructionCaptureRequestV1,
    anchor: &DurableExactConstructionAnchorV1,
    sequence: u64,
) -> MaterialCaptureIntentV1 {
    let candidate_id = request.scope.proposal.proposal_id.clone();
    let source = source_binding(round, &round.candidate(&candidate_id).unwrap()).unwrap();
    let saved_anchor = SavedConstructionAnchorV1::from_anchor(anchor);
    let command = reservation_command(
        &Access {
            principal_id: round.principal_id.clone(),
            ..Access::default()
        },
        &format!("synthetic-capture-command-{sequence}"),
        &request.scope.proposal.manifest.agreement.agreement_id,
        &candidate_id,
        sequence,
        &request,
        &source,
        &saved_anchor,
    )
    .unwrap();
    MaterialCaptureIntentV1 {
        version: 1,
        request,
        source_set_binding: source,
        construction_anchor: saved_anchor,
        created_at_unix_seconds: 120,
        expected_revision: sequence,
        command,
    }
}
fn encode(round: &Round) -> Vec<u8> {
    serde_json::to_vec(round).unwrap()
}
fn second_request(
    round: &Round,
    template: &DurableConstructionCaptureRequestV1,
    operation: &str,
) -> DurableConstructionCaptureRequestV1 {
    let second = &round.intakes[&"22".repeat(32)].outbox.projection;
    let mut result = template.clone();
    result.operation_id = operation.into();
    result.scope.account_id = second.intent.account_id.clone();
    result.scope.participant_id = second.intent.participant_id.clone();
    result.scope.privacy_domain = second.intent.privacy_domain.clone();
    result
}

#[test]
fn inert_round_roundtrip_preserves_predispatch_intent_and_exact_lost_reply_locator() {
    let (mut round, request, anchor) = fixture();
    let id = request.scope.proposal.proposal_id.clone();
    let operation = request.operation_id.clone();
    let intent = make_intent(&round, request.clone(), &anchor, 7);
    append_intent(&mut round, &id, intent).unwrap();
    let encoded = encode(&round);
    let restored = decode_round_bytes(&encoded).unwrap();
    restored.validate(&id).unwrap();
    let saved = &restored.capture_intents[&operation];
    assert!(saved.request == request);
    assert_eq!(saved.original_locator().operation_id, operation);
    assert_eq!(saved.original_locator().expected_request_digest, None);
    assert_eq!(saved.construction_anchor.root, hex::encode(anchor.root));
    assert_eq!(saved.created_at_unix_seconds, 120);
    // The locator contains neither expired native refs nor a capture request.
    let locator = serde_json::to_value(saved.original_locator()).unwrap();
    assert_eq!(locator.as_object().unwrap().len(), 2);
    assert!(locator.get("enrollment_ref").is_none());
    assert!(locator.get("scope").is_none());
    // Current expiry is deliberately irrelevant to historical integrity.
    assert!(request.scope.check_valid_at(1000).is_err());
    restored.validate(&id).unwrap();
    assert_eq!(encoded, encode(&restored));
}

#[test]
fn old_round_without_history_stays_readable_and_non_authorizing() {
    let (round, request, _) = fixture();
    let value = serde_json::to_value(&round).unwrap();
    assert!(value.get("capture_intents").is_none());
    let restored = decode_round_value(&value).unwrap();
    restored
        .validate(&request.scope.proposal.proposal_id)
        .unwrap();
    assert!(restored.capture_intents.is_empty());
    assert!(!summary(&request.scope.proposal.proposal_id, &restored, false).authorization_allowed);
}

#[test]
fn changed_operation_request_source_anchor_account_or_command_is_damaged() {
    let (mut round, request, anchor) = fixture();
    let id = request.scope.proposal.proposal_id.clone();
    let operation = request.operation_id.clone();
    let intent = make_intent(&round, request, &anchor, 1);
    append_intent(&mut round, &id, intent).unwrap();
    for field in 0..12 {
        let mut changed = round.clone();
        let record = changed.capture_intents.get_mut(&operation).unwrap();
        match field {
            0 => record.request.operation_id.push_str("-wrong"),
            1 => record.request.enrollment_ref = "98".repeat(32),
            2 => record.request.accepted_manifest_ref = "87".repeat(32),
            3 => record.request.scope.retention_policy.push_str(" Changed."),
            4 => record.source_set_binding = "76".repeat(32),
            5 => record.construction_anchor.root = "65".repeat(32),
            6 => record.request.scope.account_id = "22".repeat(32),
            7 => record.command.idempotency_key.push_str("-other"),
            8 => record.expected_revision += 1,
            9 => changed.metadata_origin = "54".repeat(32),
            10 => changed.frozen_manifest_digest = Some("43".repeat(32)),
            _ => record.created_at_unix_seconds = 200,
        }
        assert!(changed.validate(&id).is_err(), "changed field {field}");
    }
}

#[test]
fn immutable_history_never_overwrites_and_is_bounded_per_owner_and_candidate() {
    let (mut round, request, anchor) = fixture();
    let id = request.scope.proposal.proposal_id.clone();
    for owner in 0..2 {
        for attempt in 0..MAX_CAPTURE_INTENTS_PER_OWNER {
            let operation = format!("owner-{owner}-capture-{attempt}");
            let mut next = if owner == 0 {
                request.clone()
            } else {
                second_request(&round, &request, &operation)
            };
            next.operation_id = operation;
            let intent = make_intent(&round, next, &anchor, (owner * 10 + attempt) as u64);
            append_intent(&mut round, &id, intent).unwrap();
        }
    }
    assert_eq!(round.capture_intents.len(), MAX_CAPTURE_INTENTS);
    let before = encode(&round);
    let first = round.capture_intents.values().next().unwrap().clone();
    assert_eq!(
        append_intent(&mut round, &id, first.clone())
            .unwrap_err()
            .code,
        "CONFLICT"
    );
    let mut changed = first;
    changed.request.enrollment_ref = "88".repeat(32);
    assert_eq!(
        append_intent(&mut round, &id, changed).unwrap_err().code,
        "CONFLICT"
    );
    let mut ninth = request;
    ninth.operation_id = "separate-fifth-attempt".into();
    let intent = make_intent(&round, ninth, &anchor, 99);
    assert_eq!(
        append_intent(&mut round, &id, intent).unwrap_err().code,
        "RESOURCE_EXHAUSTED"
    );
    assert_eq!(encode(&round), before);
    // A cancellation display cannot clear or relabel any old attempt.
    assert!(summary(&id, &round, true).cancellation_requested);
    assert_eq!(summary(&id, &round, true).material_capture_intent_count, 8);
    assert_eq!(encode(&round), before);
}

#[test]
fn other_owner_append_preserves_source_binding_but_reanchor_never_rewrites_first_intent() {
    let (mut round, request, anchor) = fixture();
    let id = request.scope.proposal.proposal_id.clone();
    let first = make_intent(&round, request.clone(), &anchor, 1);
    let binding = first.source_set_binding.clone();
    append_intent(&mut round, &id, first).unwrap();
    let second = second_request(&round, &request, "separate-owner-two-attempt");
    let first_bytes = serde_json::to_vec(&round.capture_intents[&request.operation_id]).unwrap();
    let mut changed_anchor = anchor.clone();
    changed_anchor.height += 1;
    changed_anchor.root = [0x12; 32];
    let changed = make_intent(&round, second.clone(), &changed_anchor, 2);
    assert_eq!(
        append_intent(&mut round, &id, changed).unwrap_err().code,
        "CONFLICT"
    );
    let next = make_intent(&round, second, &anchor, 3);
    append_intent(&mut round, &id, next).unwrap();
    assert_eq!(
        source_binding(&round, &round.candidate(&id).unwrap()).unwrap(),
        binding
    );
    assert_eq!(
        serde_json::to_vec(&round.capture_intents[&request.operation_id]).unwrap(),
        first_bytes
    );
}

#[test]
fn first_common_anchor_must_fit_both_independent_original_contexts() {
    let (mut round, request, anchor) = fixture();
    let second_account = "22".repeat(32);
    let mut second = round.intakes[&second_account].outbox.projection.clone();
    second.intent.anchor_height += 5;
    second.context.anchor_height += 5;
    second.context.tip_height += 5;
    second.context.anchor_hash = "ab".repeat(32);
    second.context.anchor_root = "bc".repeat(32);
    let replacement = receipt(second.clone());
    round
        .requests
        .insert(second_account.clone(), replacement.outbox.request.clone());
    round.intakes.insert(second_account, replacement);
    assert!(require_common_anchor(&round, &anchor).is_err());
    let common = DurableExactConstructionAnchorV1 {
        height: second.context.anchor_height,
        block_hash_protocol: [0xab; 32],
        root: [0xbc; 32],
    };
    require_common_anchor(&round, &common).unwrap();
    let incompatible = DurableExactConstructionAnchorV1 {
        root: [1; 32],
        ..common
    };
    assert!(require_common_anchor(&round, &incompatible).is_err());
    // No simultaneous tip requirement is invented by this planning predicate.
    assert!(second.context.tip_height > anchor.height);
    assert_eq!(request.scope.proposal.manifest.expiry_height, 4_465_100);
}

#[test]
fn saved_creation_must_fit_both_original_metadata_windows_without_current_clock() {
    let (mut round, request, anchor) = fixture();
    let second_account = "22".repeat(32);
    let mut projection = round.intakes[&second_account].outbox.projection.clone();
    projection.intent.valid_until_unix_seconds = 115;
    let replacement = receipt(projection);
    round
        .requests
        .insert(second_account.clone(), replacement.outbox.request.clone());
    round.intakes.insert(second_account, replacement);
    // Owner one's material window includes 120, but owner's two original
    // metadata window does not. Such a retained creation could not have passed.
    let id = request.scope.proposal.proposal_id.clone();
    let intent = make_intent(&round, request, &anchor, 1);
    assert!(append_intent(&mut round, &id, intent).is_err());
    assert!(round.capture_intents.is_empty());
}

#[test]
fn history_strictly_rejects_unknown_duplicate_depth_and_payload_overflow() {
    let (mut round, request, anchor) = fixture();
    let id = request.scope.proposal.proposal_id.clone();
    let intent = make_intent(&round, request, &anchor, 1);
    let intent_raw = serde_json::to_string(&intent).unwrap();
    append_intent(&mut round, &id, intent).unwrap();
    let raw = String::from_utf8(encode(&round)).unwrap();
    for field in [
        "native_approval",
        "material",
        "fvk_hex",
        "dispatch_ticket",
        "capture_granted",
    ] {
        let mut value = serde_json::to_value(&round).unwrap();
        let operation = round.capture_intents.keys().next().unwrap();
        value["capture_intents"][operation][field] = true.into();
        assert!(decode_round_value(&value).is_err(), "unknown {field}");
    }
    let duplicate_field = raw.replacen("\"version\":1", "\"version\":1,\"version\":1", 1);
    assert!(decode_round_bytes(duplicate_field.as_bytes()).is_err());
    let operation = round.capture_intents.keys().next().unwrap();
    let duplicate_map = format!("{{\"{operation}\":{intent_raw},\"{operation}\":{intent_raw}}}");
    let duplicate = raw.replace(
        &serde_json::to_string(&round.capture_intents).unwrap(),
        &duplicate_map,
    );
    assert!(decode_round_bytes(duplicate.as_bytes()).is_err());
    let deep = format!("{}0{}", "[".repeat(33), "]".repeat(33));
    assert!(decode_round_bytes(deep.as_bytes()).is_err());
    assert!(decode_round_bytes(&vec![b' '; MAX_ROUND_BYTES + 1]).is_err());
    assert!(require_bounded(
        &"x".repeat(MAX_CAPTURE_INTENT_BYTES),
        MAX_CAPTURE_INTENT_BYTES
    )
    .is_err());
}

#[test]
fn sanitized_summary_does_not_leak_private_history_or_native_references() {
    let (mut round, request, anchor) = fixture();
    let id = request.scope.proposal.proposal_id.clone();
    let intent = make_intent(&round, request.clone(), &anchor, 1);
    append_intent(&mut round, &id, intent).unwrap();
    let encoded = serde_json::to_string(&summary(&id, &round, false)).unwrap();
    for private in [
        request.operation_id.as_str(),
        request.enrollment_ref.as_str(),
        request.accepted_manifest_ref.as_str(),
        request.scope.account_id.as_str(),
        request.scope.protected_destination.as_str(),
        "capture_intents",
        "source_set_binding",
        "construction_anchor",
        "idempotency_key",
        "request_digest",
    ] {
        assert!(
            !encoded.contains(private),
            "private field leaked: {private}"
        );
    }
    assert!(encoded.contains("\"authorization_allowed\":false"));
}

#[test]
fn ordering_contract_commit_before_ticket_and_one_use_dispatch_no_recovery_reissue() {
    // This is deliberately a source-order contract, NOT a simulated database or
    // native crash test. Root integration must run the actual encrypted Store.
    let source = include_str!("material_capture_reservations_v1.rs");
    let reserve = source
        .split("pub(crate) fn reserve_material_capture_v1")
        .nth(1)
        .unwrap()
        .split("pub(crate) fn read_material_capture_locator_v1")
        .next()
        .unwrap();
    assert!(
        reserve.find("put(&mut envelope").unwrap()
            < reserve.find("let mutation = self.commit(").unwrap()
    );
    assert!(
        reserve.find("let mutation = self.commit(").unwrap()
            < reserve.find("Some(NewMaterialCaptureDispatchV1").unwrap()
    );
    assert!(reserve.contains("return Ok((replay, None))"));
    assert!(reserve.contains("if mutation.replayed"));
    let locator = source
        .split("pub(crate) fn read_material_capture_locator_v1")
        .nth(1)
        .unwrap();
    assert!(!locator.contains("NewMaterialCaptureDispatchV1 {"));
    assert!(!locator.contains("capture_and_request"));
    let exact = include_str!("exact_material_v1.rs");
    assert!(exact.contains("pub(crate) async fn capture(\n        self,"));
    assert!(exact.contains(
        "dispatch.require_exact(self, agreement_id, candidate_id, operation_id, &intent)?"
    ));
    assert!(exact.contains("intake_reserved_material_capture_v1"));
    assert!(exact.contains("join_saved_disclosure(&intent, &projection, outbox)?"));
    assert!(source.contains("std::ptr::eq(self.engine, engine)"));
    assert!(source.contains("MaterialCaptureActionV1::ReadOriginalLocator"));
    assert!(!source.contains("capture_intents.clear("));
    assert!(!source.contains("capture_intents.remove("));
}

// These tests exercise actual encrypted Engine/Store persistence and CAS, but
// seed inert synthetic receipt DATA directly. They still do NOT qualify native
// receipt admission, wallets, provider scans, signing, or native crash recovery.
struct CurrentPrivacy(std::sync::atomic::AtomicBool);
impl CurrentPrivacy {
    fn allowed() -> Self {
        Self(std::sync::atomic::AtomicBool::new(true))
    }
    fn revoke(&self) {
        self.0.store(false, std::sync::atomic::Ordering::SeqCst);
    }
    fn current(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}
impl LocalDurableDiscoveryConsentV1 for CurrentPrivacy {
    fn permits(
        &self,
        _: &DurableInputProjectionRequestV1,
        _: Option<&str>,
        _: DurableDiscoveryActionV1,
    ) -> bool {
        self.current()
    }
}
impl LocalDurableCaptureConsentV1 for CurrentPrivacy {
    fn permits(
        &self,
        _: &DurableConstructionCaptureRequestV1,
        origin: &str,
        _: MaterialCaptureActionV1,
    ) -> bool {
        self.current() && digest(origin)
    }
}
fn encrypted_fixture() -> (
    tempfile::TempDir,
    wholepact_storage_security::DatabaseKey,
    Engine,
    Access,
    DurableConstructionCaptureRequestV1,
    DurableExactConstructionAnchorV1,
) {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = directory.path().join("private-coordinator.sqlite");
    let key = wholepact_storage_security::DatabaseKey::from_bytes([0x48; 32]);
    let engine = Engine::from_store(wholepact_store::Store::create_encrypted(&path, &key).unwrap());
    let (mut round, mut request, anchor) = fixture();
    let access = Access {
        principal_id: round.principal_id.clone(),
        include_owned_agreements: true,
        ..Access::default()
    };
    let agreement = &request.scope.proposal.manifest.agreement.agreement_id;
    engine
        .create(
            &access,
            "capture-fixture-create-agreement",
            request.scope.proposal.manifest.agreement.clone(),
        )
        .unwrap();
    for (index, participant) in request
        .scope
        .proposal
        .manifest
        .participants
        .iter()
        .enumerate()
    {
        engine
            .add_intent(
                &access,
                &format!("capture-fixture-add-intent-{index}"),
                agreement,
                index as u64 + 1,
                wholepact_core::ParticipationIntent {
                    intent_id: format!("capture-fixture-intent-{index}"),
                    agreement_id: agreement.clone(),
                    participant_id: participant.participant_id.clone(),
                    desired_contribution: participant.contribution,
                    maximum_net_debit: participant.maximum_net_debit,
                    fee_cap: participant.fee_cap,
                    conditions: vec![],
                    valid_until: None,
                    status: wholepact_core::IntentStatus::Active,
                },
            )
            .unwrap();
    }
    engine
        .select_roster(
            &access,
            "capture-fixture-select-roster",
            agreement,
            3,
            crate::planning::RosterSelectionRequest {
                selected_intent_ids: vec![
                    "capture-fixture-intent-0".into(),
                    "capture-fixture-intent-1".into(),
                ],
            },
        )
        .unwrap();
    let now = now_seconds().unwrap();
    request.scope.protected_destination = path.to_str().unwrap().into();
    request.scope.valid_from_unix_seconds = now - 10;
    request.scope.valid_until_unix_seconds = now + 600;
    let mut intakes = BTreeMap::new();
    for (account, old) in &round.intakes {
        let mut projection = old.outbox.projection.clone();
        projection.intent.protected_destination = request.scope.protected_destination.clone();
        projection.intent.valid_from_unix_seconds = now - 20;
        projection.intent.valid_until_unix_seconds = now + 1200;
        projection.captured_at_unix_seconds = now - 15;
        intakes.insert(account.clone(), receipt(projection));
    }
    round.requests = intakes
        .iter()
        .map(|(account, intake)| (account.clone(), intake.outbox.request.clone()))
        .collect();
    round.intakes = intakes;
    round.metadata_origin = hex::encode(
        engine
            .store
            .verify_original_encrypted_destination(&path)
            .unwrap(),
    );
    let id = &request.scope.proposal.proposal_id;
    let proposal = round.candidate(id).unwrap();
    assert!(proposal.input() == &request.scope.proposal);
    let mut envelope = engine.load(&access, agreement).unwrap();
    envelope.view.candidates.push(CandidateView {
        candidate_id: id.clone(),
        proposal: proposal.input().clone(),
        manifest_digest: proposal.manifest_digest().into(),
        proposal_digest: proposal.proposal_digest().into(),
        accounting: serde_json::to_value(proposal.accounting()).unwrap(),
        reviews: vec![],
        proof_jobs: vec![],
    });
    put(&mut envelope, id, &round).unwrap();
    let command = crate::context(
        &access,
        "capture-fixture-inert-private-seed",
        "synthetic_capture_state_fixture",
        agreement,
        Some(4),
        &id,
    )
    .unwrap();
    engine
        .commit(
            &command,
            agreement,
            4,
            envelope,
            "synthetic_inert_capture_fixture",
        )
        .unwrap();
    (directory, key, engine, access, request, anchor)
}

#[test]
fn encrypted_commit_before_dispatch_reopen_exact_locator_and_replay_without_second_ticket() {
    let (_directory, key, engine, access, request, anchor) = encrypted_fixture();
    let privacy = CurrentPrivacy::allowed();
    let agreement = request
        .scope
        .proposal
        .manifest
        .agreement
        .agreement_id
        .clone();
    let id = request.scope.proposal.proposal_id.clone();
    let revision = engine.load(&access, &agreement).unwrap().view.revision;
    let (mutation, dispatch) = engine
        .reserve_material_capture_v1(
            &access,
            "capture-actual-commit-before-send",
            &agreement,
            &id,
            revision,
            request.clone(),
            anchor.clone(),
            &privacy,
            &privacy,
        )
        .unwrap();
    assert!(!mutation.replayed);
    assert!(dispatch.is_some());
    // Stop after the real SQLCipher commit and before any native dispatch. A
    // lost native reply has the same material-free Engine locator, not proof
    // that native execution occurred. No fake native owner is made here.
    drop(dispatch);
    let path = request.scope.protected_destination.clone();
    drop(engine);
    let reopened = Engine::from_store(wholepact_store::Store::open_encrypted(&path, &key).unwrap());
    let locator = reopened
        .read_material_capture_locator_v1(
            &access,
            &agreement,
            &id,
            &request.scope.account_id,
            &request.operation_id,
            &privacy,
            &privacy,
        )
        .unwrap();
    assert_eq!(locator.operation_id, request.operation_id);
    assert_eq!(locator.expected_request_digest, None);
    let (replay, second_dispatch) = reopened
        .reserve_material_capture_v1(
            &access,
            "capture-actual-commit-before-send",
            &agreement,
            &id,
            revision,
            request.clone(),
            anchor.clone(),
            &privacy,
            &privacy,
        )
        .unwrap();
    assert!(replay.replayed);
    assert!(second_dispatch.is_none());
    assert!(reopened
        .reserve_material_capture_v1(
            &access,
            "capture-different-replay-command",
            &agreement,
            &id,
            revision,
            request.clone(),
            anchor,
            &privacy,
            &privacy,
        )
        .is_err());
    assert!(reopened
        .read_material_capture_locator_v1(
            &access,
            &agreement,
            &id,
            &"22".repeat(32),
            &request.operation_id,
            &privacy,
            &privacy,
        )
        .is_err());
    assert!(reopened
        .read_material_capture_locator_v1(
            &access,
            &agreement,
            &id,
            &request.scope.account_id,
            "not-the-original-operation",
            &privacy,
            &privacy,
        )
        .is_err());
    privacy.revoke();
    assert!(reopened
        .read_material_capture_locator_v1(
            &access,
            &agreement,
            &id,
            &request.scope.account_id,
            &request.operation_id,
            &privacy,
            &privacy,
        )
        .is_err());
    assert_eq!(
        reopened
            .discovery_round(&reopened.load(&access, &agreement).unwrap(), &id)
            .unwrap()
            .capture_intents
            .len(),
        1
    );
}

#[test]
fn actual_engine_bound_ticket_cannot_move_to_an_engine_clone_even_with_same_store() {
    let (_directory, _key, engine, access, request, anchor) = encrypted_fixture();
    let privacy = CurrentPrivacy::allowed();
    let agreement = &request.scope.proposal.manifest.agreement.agreement_id;
    let id = &request.scope.proposal.proposal_id;
    let revision = engine.load(&access, agreement).unwrap().view.revision;
    let (_, dispatch) = engine
        .reserve_material_capture_v1(
            &access,
            "capture-engine-owner-ticket",
            agreement,
            id,
            revision,
            request.clone(),
            anchor,
            &privacy,
            &privacy,
        )
        .unwrap();
    let round = engine
        .discovery_round(&engine.load(&access, agreement).unwrap(), id)
        .unwrap();
    let same_store_different_engine = engine.clone();
    assert!(dispatch
        .unwrap()
        .require_exact(
            &same_store_different_engine,
            agreement,
            id,
            &request.operation_id,
            &round.capture_intents[&request.operation_id]
        )
        .is_err());
}

#[test]
fn privacy_revocation_or_cancellation_after_commit_denies_capture_without_clearing_intent() {
    for cancel in [false, true] {
        let (_directory, _key, engine, access, request, anchor) = encrypted_fixture();
        let privacy = CurrentPrivacy::allowed();
        let agreement = &request.scope.proposal.manifest.agreement.agreement_id;
        let id = &request.scope.proposal.proposal_id;
        let revision = engine.load(&access, agreement).unwrap().view.revision;
        let (mutation, dispatch) = engine
            .reserve_material_capture_v1(
                &access,
                "capture-commit-before-revocation",
                agreement,
                id,
                revision,
                request.clone(),
                anchor,
                &privacy,
                &privacy,
            )
            .unwrap();
        if cancel {
            engine
                .cancel(
                    &access,
                    "capture-cancel-after-commit",
                    agreement,
                    mutation.agreement.revision,
                )
                .unwrap();
        } else {
            privacy.revoke();
        }
        assert!(engine
            .retained_projection_capture_v1(
                &access,
                agreement,
                id,
                &request.operation_id,
                dispatch.unwrap(),
                &privacy,
                &privacy,
            )
            .is_err());
        assert_eq!(
            engine
                .discovery_round(&engine.load(&access, agreement).unwrap(), id)
                .unwrap()
                .capture_intents
                .len(),
            1
        );
    }
}

#[test]
fn independent_metadata_and_store_privacy_gates_and_stale_cas_cannot_mint_tickets() {
    let (_directory, _key, engine, access, request, anchor) = encrypted_fixture();
    let discovery = CurrentPrivacy::allowed();
    let capture = CurrentPrivacy::allowed();
    let denied = CurrentPrivacy::allowed();
    denied.revoke();
    let agreement = &request.scope.proposal.manifest.agreement.agreement_id;
    let id = &request.scope.proposal.proposal_id;
    let revision = engine.load(&access, agreement).unwrap().view.revision;
    for (metadata, destination) in [(&denied, &capture), (&discovery, &denied)] {
        assert!(engine
            .reserve_material_capture_v1(
                &access,
                "capture-independently-current-gates",
                agreement,
                id,
                revision,
                request.clone(),
                anchor.clone(),
                metadata,
                destination,
            )
            .is_err());
    }
    assert!(engine
        .discovery_round(&engine.load(&access, agreement).unwrap(), id)
        .unwrap()
        .capture_intents
        .is_empty());
    let (_, first_ticket) = engine
        .reserve_material_capture_v1(
            &access,
            "capture-independently-current-gates",
            agreement,
            id,
            revision,
            request.clone(),
            anchor.clone(),
            &discovery,
            &capture,
        )
        .unwrap();
    drop(first_ticket);
    let mut changed = request.clone();
    changed.operation_id = "separate-operation-stale-cas".into();
    assert!(engine
        .reserve_material_capture_v1(
            &access,
            "capture-separate-operation-stale-cas",
            agreement,
            id,
            revision,
            changed,
            anchor.clone(),
            &discovery,
            &capture,
        )
        .is_err());
    for (metadata, destination) in [(&denied, &capture), (&discovery, &denied)] {
        assert!(engine
            .reserve_material_capture_v1(
                &access,
                "capture-independently-current-gates",
                agreement,
                id,
                revision,
                request.clone(),
                anchor.clone(),
                metadata,
                destination,
            )
            .is_err());
    }
    assert_eq!(
        engine
            .discovery_round(&engine.load(&access, agreement).unwrap(), id)
            .unwrap()
            .capture_intents
            .len(),
        1
    );
}
