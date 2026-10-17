//! Never-funded, isolated synthetic cryptographic/replay fixtures. No native
//! consent, TLS session, wallet, network, proof or financial execution is claimed.
use super::*;
use crate::manual_roster_construction_v2::tests::construction_fixture_with_owner;
use crate::policy::{Event, Ledger};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair},
};
use std::{
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
};
use wholepact_core::manual_roster_construction_v3::{
    CommonContextProposalV1, ManualRosterOriginalRetentionV3,
};
use zeroize::Zeroizing;
fn h(c: char) -> String {
    c.to_string().repeat(64)
}

/// Test-only key exists in a fresh private temporary directory, never installed,
/// registered, exported or printed. OpenSSL builds the ordinary test certificate;
/// maintained ring performs the exact V3 plan signing operation below.
fn synthetic_owner() -> (tempfile::TempDir, Vec<u8>, EcdsaKeyPair) {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let run = |args: &[&str]| {
        assert!(
            Command::new("openssl")
                .current_dir(temp.path())
                .args(args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("test OpenSSL is required")
                .success()
        );
    };
    run(&[
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-sha256",
        "-days",
        "1",
        "-nodes",
        "-subj",
        "/CN=wholepact-never-funded-v3.invalid",
        "-keyout",
        "private.pem",
        "-out",
        "certificate.der",
        "-outform",
        "DER",
    ]);
    run(&[
        "pkcs8",
        "-topk8",
        "-nocrypt",
        "-in",
        "private.pem",
        "-outform",
        "DER",
        "-out",
        "private.pk8",
    ]);
    for name in ["private.pem", "private.pk8"] {
        std::fs::set_permissions(
            temp.path().join(name),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let encoded = Zeroizing::new(std::fs::read(temp.path().join("private.pk8")).unwrap());
    let key = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_ASN1_SIGNING,
        &encoded,
        &SystemRandom::new(),
    )
    .unwrap();
    let certificate = std::fs::read(temp.path().join("certificate.der")).unwrap();
    (temp, certificate, key)
}
/// Modeled historical native DATA for cross-crate schema tests only. This does
/// not invoke a native actor or mint its opaque retention/read/construction owner.
pub(crate) fn modeled_retention_evidence(
    request: &wholepact_core::manual_roster_construction_v2::ManualRosterContributionRetentionRequestV2,
) -> serde_json::Value {
    let enrollment = &request.selection.scope.selection.inventory.enrollment;
    serde_json::json!({
        "version": 2,
        "request": request,
        "retained_signer_intent_digest": h('9'),
        "native_review_digest": h('a'),
        "admitted_at_ms": request.requested_at_ms,
        "selection_observation": {
            "writer_certificate_digest": enrollment.signer.writer_certificate_digest,
            "writer_epoch": enrollment.signer.writer_epoch,
            "writer_session_digest": h('1'),
            "writer_session_expires_at_ms": request.selection.scope.selection.invocation.construction_expires_at_ms,
            "witness_head_sequence": 0,
            "witness_head_digest": h('2'),
            "complete_history_digest": h('3'),
            "exclusion_checkpoint_digest": h('4'),
            "native_review_digest": h('a'),
        },
    })
}
fn modeled_retention_evidence_digest(
    request: &wholepact_core::manual_roster_construction_v2::ManualRosterContributionRetentionRequestV2,
) -> String {
    wholepact_core::proposal::canonical_digest(
        "wholepact:roster-contribution-retention-evidence:v2",
        &modeled_retention_evidence(request),
    )
    .unwrap()
}
fn v3_plan(
    base: &wholepact_core::manual_roster_construction_v2::ManualRosterConstructionPlanV2,
) -> ManualRosterConstructionPlanV3 {
    let mut bob = base.retained.clone();
    bob.operation_id = "bob-original-retention".into();
    bob.selection.operation_id = "bob-original-selection".into();
    bob.selection_context.tip_height += 1;
    bob.selection_context.tip_hash_protocol = h('9');
    bob.selected_inputs = vec![ManualConstructionInput {
        input_id: "input-bob".into(),
        nullifier: h('5'),
        value_zatoshis: 700_000_000,
    }];
    bob.change_address = "usyntheticreturnbob".into();
    bob.change_value_zatoshis = 99_982_000;
    let scope = &mut bob.selection.scope.selection;
    let mut policy = scope.original_policy_origin.recipient_policy.clone();
    policy.account_id = h('b');
    policy.participant_id = "bob".into();
    policy.original_limits.per_operation_limit_zatoshis = 700_000_000;
    policy.original_limits.maximum_fee_share_zatoshis = 30_000;
    let inventory = &mut scope.inventory;
    inventory.original_recipient_policy = policy.clone();
    inventory.enrollment.identity.account_id = h('b');
    inventory.enrollment.identity.full_viewing_key_digest = h('d');
    inventory.enrollment.scope.participant_id = "bob".into();
    inventory.enrollment.scope.per_operation_limit_zatoshis = 700_000_000;
    inventory.enrollment.scope.maximum_fee_share_zatoshis = 30_000;
    inventory.enrollment.scope.recipient_scope_digests = vec![policy.digest().unwrap()];
    inventory.attachment.selected.account_id = h('b');
    inventory.attachment.selected.canonical_directory = "/synthetic/bob".into();
    inventory.attachment.selected.directory_identity_digest = h('9');
    inventory.wallet_destination = "/synthetic/bob/wallet.sqlite".into();
    let origin = &mut scope.original_policy_origin;
    origin.recipient_policy = policy.clone();
    origin.intent.identity.account_id = h('b');
    origin.intent.identity.full_viewing_key_digest = h('d');
    origin.intent.original_policy_terms.account_id = h('b');
    origin
        .intent
        .original_policy_terms
        .per_operation_limit_zatoshis = 700_000_000;
    origin
        .intent
        .original_policy_terms
        .maximum_fee_share_zatoshis = 30_000;
    origin.intent.original_policy_terms.recipient_scope_digests = vec![policy.digest().unwrap()];
    origin.intent.original_policy_terms_digest =
        origin.intent.original_policy_terms.digest().unwrap();
    origin.birth_digest = wholepact_core::proposal::canonical_digest(
        "wholepact:native-account-birth-intent:v2",
        &(&origin.intent, &policy),
    )
    .unwrap();
    inventory.enrollment.native_birth_digest = origin.birth_digest.clone();
    bob.validate().unwrap();
    let originals = vec![
        ManualRosterOriginalRetentionV3 {
            request: base.retained.clone(),
            evidence_digest: modeled_retention_evidence_digest(&base.retained),
        },
        ManualRosterOriginalRetentionV3 {
            evidence_digest: modeled_retention_evidence_digest(&bob),
            request: bob,
        },
    ];
    let common_context = CommonContextProposalV1::from_originals(&originals).unwrap();
    let result = ManualRosterConstructionPlanV3 {
        version: 3,
        retained: base.retained.clone(),
        retained_evidence_digest: originals[0].evidence_digest.clone(),
        proposal: base.proposal.clone(),
        participants: originals.iter().map(|o| o.commitment().unwrap()).collect(),
        originals,
        common_context_digest: common_context.digest().unwrap(),
        common_context,
    };
    result.validate().unwrap();
    result
}

pub(crate) fn construction_fixture_v3() -> (
    crate::pending_birth::PendingBirthCommitRecord,
    ManualRosterEnrollmentExtensionV2,
    Vec<Event>,
    Ledger,
) {
    let (birth, extension, events, ledger, _temp, _certificate, _key) =
        construction_fixture_v3_with_signing_owner();
    (birth, extension, events, ledger)
}
pub(crate) fn construction_fixture_v3_with_signing_owner() -> (
    crate::pending_birth::PendingBirthCommitRecord,
    ManualRosterEnrollmentExtensionV2,
    Vec<Event>,
    Ledger,
    tempfile::TempDir,
    Vec<u8>,
    EcdsaKeyPair,
) {
    construction_fixture_v3_mode(false)
}

fn construction_fixture_v3_with_original_retention() -> (
    crate::pending_birth::PendingBirthCommitRecord,
    ManualRosterEnrollmentExtensionV2,
    Vec<Event>,
    Ledger,
    tempfile::TempDir,
    Vec<u8>,
    EcdsaKeyPair,
) {
    construction_fixture_v3_mode(true)
}

fn construction_fixture_v3_mode(
    original_retention_v2: bool,
) -> (
    crate::pending_birth::PendingBirthCommitRecord,
    ManualRosterEnrollmentExtensionV2,
    Vec<Event>,
    Ledger,
    tempfile::TempDir,
    Vec<u8>,
    EcdsaKeyPair,
) {
    let (private_test_directory, certificate, key) = synthetic_owner();
    let pin = crate::transport::certificate_digest(&rustls::pki_types::CertificateDer::from(
        certificate.clone(),
    ));
    let (birth, extension, legacy_events, _) = construction_fixture_with_owner(Some(&pin));
    let mut events = legacy_events[..8].to_vec();
    let mut ledger = Ledger::new(birth.request.policy.clone()).unwrap();
    for event in &events {
        ledger.apply(event).unwrap();
    }
    let AuthorityMutation::ReserveManualRosterConstructionV2(old) = &legacy_events[9].mutation
    else {
        panic!("synthetic V2 seed")
    };
    // Retain during the actual second attempt, late enough that the immutable
    // original lifetime still covers its required fresh third continuation.
    let mut original = old.construction.plan.clone();
    original
        .retained
        .selection
        .scope
        .selection
        .invocation
        .requested_at_ms = 140_000;
    original
        .retained
        .selection
        .scope
        .selection
        .invocation
        .construction_expires_at_ms = 260_000;
    original.retained.selection.requested_at_ms = 140_000;
    original.retained.requested_at_ms = 141_000;
    if original_retention_v2 {
        let scope = &mut original.retained.selection.scope.selection;
        scope.version = 2;
        scope.purpose = "prepare_one_common_context_retained_contribution".into();
        scope.invocation.version = 2;
        // Fixed before the second publication, not rebased after its expiry.
        scope.invocation.requested_at_ms = 125_000;
        scope.invocation.construction_expires_at_ms = 350_000;
    }
    let plan = v3_plan(&original);
    let approval = ManualRosterConstructionApprovalV3 {
        version: 3,
        extension_digest: extension.digest().unwrap(),
        plan: plan.clone(),
        issued_at_ms: 142_000,
        initial_commit_deadline_ms: 160_000,
    };
    let signed = crate::manual_roster_construction_signature_v3::manual_roster_construction_owner_signing_bytes_v3(&extension, &approval).unwrap();
    let envelope = ManualRosterConstructionOwnerSignatureV3 {
        version: 3,
        extension: extension.clone(),
        approval: approval.clone(),
        scheme: "ecdsa-p256-sha256-asn1-v1".into(),
        owner_certificate_der: certificate.clone(),
        signature: key
            .sign(&SystemRandom::new(), &signed)
            .unwrap()
            .as_ref()
            .to_vec(),
    };
    let verified = crate::manual_roster_construction_signature_v3::verify_manual_roster_construction_owner_signature_v3(&envelope, &pin).unwrap();
    let record = ManualRosterConstructionApprovalRecordV3 {
        approval: approval.clone(),
        owner_signature_evidence_digest: verified.evidence_digest().to_owned(),
        owner_signature: Box::new(envelope),
        native_review_digest: h('e'),
    };
    let event = Event {
        mutation: AuthorityMutation::OwnerControl(OwnerControlRequest {
            operation_id: approval.owner_operation_id(&extension).unwrap(),
            account_id: ledger.policy.account_id.clone(),
            network_profile_id: ledger.policy.network_profile_id.clone(),
            writer_epoch: 1,
            expected_head: ledger.snapshot.head.clone(),
            control: OwnerControl::ApproveManualRosterConstructionV3 {
                record: Box::new(record),
            },
        }),
        authenticated_certificate_digest: pin,
        witness_time_ms: 142_000,
        writer_session_id: None,
        original_request_link: None,
    };
    ledger.apply(&event).unwrap();
    events.push(event);
    // A new actual replayed continuation is mandatory; do not relabel the
    // original retained attempt or shorten its publication drain interval.
    let continuation =
        crate::manual_roster_witness_v2::tests::continuation(&ledger, &extension, 251_000, '7');
    let event = crate::manual_roster_witness_v2::tests::continuation_event(
        &ledger,
        &extension,
        continuation.clone(),
        251_000,
    );
    ledger.apply(&event).unwrap();
    events.push(event);
    let session_id = crate::session::session_id(&[0x55; 32]);
    crate::manual_roster_witness_v2::tests::bootstrap(
        &birth,
        &extension,
        &mut ledger,
        &mut events,
        251_001,
        session_id.clone(),
    );
    let request = ManualRosterConstructionReservationRequestV3 {
        version: 3,
        construction: ManualRosterConstructionRequestV3 {
            version: 3,
            operation_id: "alice-reservation-v3".into(),
            plan,
            current_caller_binding_digest: old.construction.current_caller_binding_digest.clone(),
            requested_at_ms: 253_100,
            admission_expires_at_ms: 259_000,
        },
        attempt_digest: continuation.digest_for(&extension).unwrap(),
        attempt_sequence: continuation.sequence(),
        writer_epoch: 1,
        expected_head: ledger.snapshot.head.clone(),
        session_id: session_id.clone(),
        signer_intent_digest: h('9'),
        native_review_digest: h('a'),
        reviewed_at_ms: 253_200,
    };
    let event = Event {
        mutation: AuthorityMutation::ReserveManualRosterConstructionV3(Box::new(request)),
        authenticated_certificate_digest: ledger.policy.initial_writer_certificate_digest.clone(),
        witness_time_ms: 253_200,
        writer_session_id: Some(session_id.clone()),
        original_request_link: None,
    };
    let MutationResult::ManualRosterConstructionReservedV3(reservation) =
        ledger.apply(&event).unwrap()
    else {
        panic!("synthetic V3 reserve")
    };
    events.push(event);
    let continuation = ledger
        .latest_manual_roster_attempt_v2()
        .unwrap()
        .continuation
        .unwrap();
    let consume = ManualRosterConstructionConsumeRequestV3 {
        version: 3,
        operation_id: construction_consume_operation_id_v3(&reservation, &extension, &continuation)
            .unwrap(),
        reservation_operation_id: reservation.request.construction.operation_id.clone(),
        reservation_digest: reservation.digest_for(&extension, &continuation).unwrap(),
        account_id: ledger.policy.account_id.clone(),
        network_profile_id: ledger.policy.network_profile_id.clone(),
        writer_epoch: 1,
        expected_head: ledger.snapshot.head.clone(),
        session_id: session_id.clone(),
        common_invocation_digest: reservation.request.invocation_digest().unwrap(),
        current_caller_binding_digest: reservation
            .request
            .construction
            .current_caller_binding_digest
            .clone(),
    };
    let event = Event {
        mutation: AuthorityMutation::ConsumeManualRosterConstructionV3(consume),
        authenticated_certificate_digest: ledger.policy.initial_writer_certificate_digest.clone(),
        witness_time_ms: 253_300,
        writer_session_id: Some(session_id),
        original_request_link: None,
    };
    ledger.apply(&event).unwrap();
    events.push(event);
    (
        birth,
        extension,
        events,
        ledger,
        private_test_directory,
        certificate,
        key,
    )
}
#[test]
fn v3_reservation_requires_a_strictly_newer_actual_continuation_than_retention() {
    let (birth, extension, events, final_ledger) = construction_fixture_v3();
    let mut approved = Ledger::new(birth.request.policy.clone()).unwrap();
    for event in &events[..9] {
        approved.apply(event).unwrap();
    }
    let original = approved
        .latest_manual_roster_attempt_v2()
        .unwrap()
        .continuation
        .unwrap();
    let fresh = final_ledger
        .latest_manual_roster_attempt_v2()
        .unwrap()
        .continuation
        .unwrap();
    original.validate_for(&extension).unwrap();
    fresh.validate_for(&extension).unwrap();
    assert_eq!(original.sequence(), 2);
    assert_eq!(fresh.sequence(), 3);
    let AuthorityMutation::ReserveManualRosterConstructionV3(request) = &events[13].mutation else {
        panic!("actual synthetic replayed V3 reservation")
    };
    request.validate_for(&extension, &fresh).unwrap();
    let retained_attempt = &request
        .construction
        .plan
        .retained
        .selection
        .scope
        .selection
        .inventory
        .attempt;
    assert_eq!(retained_attempt.attempt_sequence, original.sequence());
    assert_eq!(
        retained_attempt.continuation_digest,
        original.digest_for(&extension).unwrap()
    );

    let mut reused = request.as_ref().clone();
    reused.attempt_sequence = original.sequence();
    reused.attempt_digest = original.digest_for(&extension).unwrap();
    reused.expected_head = approved.snapshot.head.clone();
    reused.session_id = approved
        .snapshot
        .active_writer_session
        .as_ref()
        .unwrap()
        .session_id
        .clone();
    assert!(matches!(
        reused.validate_for(&extension, &original),
        Err(AuthorityError::InvalidBinding)
    ));
    let mut event = events[13].clone();
    event.writer_session_id = Some(reused.session_id.clone());
    event.mutation = AuthorityMutation::ReserveManualRosterConstructionV3(Box::new(reused.clone()));
    let before = approved.snapshot.clone();
    assert!(approved.apply(&event).is_err());
    assert!(approved.snapshot == before);
    assert_eq!(approved.snapshot.outstanding_debit_zatoshis, 0);

    // A second internally valid retained plan under the genuinely replayed third
    // attempt still cannot be admitted using its older second continuation.
    let plan = &mut reused.construction.plan;
    for original_retention in &mut plan.originals {
        let retained = &mut original_retention.request;
        retained
            .selection
            .scope
            .selection
            .inventory
            .attempt
            .attempt_sequence = fresh.sequence();
        retained
            .selection
            .scope
            .selection
            .inventory
            .attempt
            .continuation_digest = fresh.digest_for(&extension).unwrap();
        retained
            .selection
            .scope
            .selection
            .invocation
            .requested_at_ms = 253_010;
        retained
            .selection
            .scope
            .selection
            .invocation
            .construction_expires_at_ms = 373_010;
        retained.selection.requested_at_ms = 253_010;
        retained.selection.disclosure_expires_at_ms = 280_000;
        retained.requested_at_ms = 253_020;
        retained.admission_expires_at_ms = 280_000;
    }
    plan.retained = plan.originals[0].request.clone();
    plan.participants = plan
        .originals
        .iter()
        .map(|o| o.commitment().unwrap())
        .collect();
    plan.common_context = CommonContextProposalV1::from_originals(&plan.originals).unwrap();
    plan.common_context_digest = plan.common_context.digest().unwrap();
    plan.validate().unwrap();
    reused.construction.validate().unwrap();
    assert!(matches!(
        reused.validate_for(&extension, &original),
        Err(AuthorityError::InvalidBinding)
    ));
}
#[test]
fn genuine_v3_owner_signature_replay_keeps_exposure_and_never_remints() {
    let (birth, extension, events, mut ledger) = construction_fixture_v3();
    assert_eq!(ledger.snapshot.outstanding_debit_zatoshis, 400_012_000);
    assert_eq!(ledger.snapshot.reserved_input_value_zatoshis, 500_000_000);
    let snapshot = ledger.snapshot.clone();
    ledger.recompute_exposure().unwrap();
    assert!(ledger.snapshot == snapshot);
    assert!(ledger.replay(&events[8]).unwrap().is_some());
    assert!(ledger.replay(&events[14]).unwrap().is_some());
    assert!(matches!(
        ledger.require_unconsumed_roster_construction_v3(&events[14].mutation),
        Err(AuthorityError::Uncertain)
    ));
    assert!(matches!(
        ledger.require_original_construction_slot(&h('1'), 2, true, None),
        Err(AuthorityError::Conflict)
    ));
    assert!(matches!(
        ledger.require_original_construction_slot(&h('1'), 2, false, None),
        Err(AuthorityError::Conflict)
    ));
    assert!(
        ledger
            .check_input_obligation_exclusions("other", [("input-alice", "unused")].into_iter())
            .is_err()
    );
    let mut approved = Ledger::new(birth.request.policy.clone()).unwrap();
    for event in &events[..9] {
        approved.apply(event).unwrap();
    }
    assert_eq!(approved.snapshot.outstanding_debit_zatoshis, 0);
    let approved_history =
        crate::manual_roster_witness_v2::tests::history(&birth, &approved, &events[..9]);
    approved_history
        .require_original_roster_preconstruction_history()
        .unwrap();
    assert!(approved_history.require_legacy_online_only().is_err());
    assert!(
        approved
            .require_original_construction_slot(&h('1'), 2, true, None)
            .is_err()
    );
    let history = crate::manual_roster_witness_v2::tests::history(&birth, &ledger, &events);
    assert!(matches!(
        history.construction_history_v1(),
        Err(AuthorityError::ConstructionHistoryUnsupported)
    ));
    let archive = history.construction_history_v2().unwrap();
    assert_eq!(archive.origins().len(), 1);
    assert_eq!(archive.approvals().len(), 1);
    assert_eq!(archive.retained_debit_zatoshis().unwrap(), 400_012_000);
    let bytes = serde_json::to_vec(&archive).unwrap();
    let restored: ConstructionHistoryV2 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(archive.digest().unwrap(), restored.digest().unwrap());
    if let Some(path) = std::env::var_os("WHOLEPACT_SYNTHETIC_V3_AUDIT_FIXTURE") {
        // Optional test interoperability artifact only. It contains public test
        // certificates/signatures, immutable audit data, and NO private key,
        // session key, live read owner or native construction capability.
        let mut read_ready = Ledger::new(birth.request.policy.clone()).unwrap();
        for event in &events[..13] {
            read_ready.apply(event).unwrap();
        }
        let read_ready_history =
            crate::manual_roster_witness_v2::tests::history(&birth, &read_ready, &events[..13]);
        let AuthorityMutation::ReserveManualRosterConstructionV3(reserve) = &events[13].mutation
        else {
            panic!("replayed synthetic reservation")
        };
        let modeled_retention_evidence: Vec<_> = reserve
            .construction
            .plan
            .originals
            .iter()
            .map(|original| {
                let evidence = modeled_retention_evidence(&original.request);
                assert_eq!(
                    wholepact_core::proposal::canonical_digest(
                        "wholepact:roster-contribution-retention-evidence:v2",
                        &evidence
                    )
                    .unwrap(),
                    original.evidence_digest,
                );
                evidence
            })
            .collect();
        let fixture = serde_json::json!({
            "fixture_version": 1,
            "fixture_kind": "never-funded-synthetic-signature-and-authority-replay-only",
            "native_actors_exercised": false,
            "modeled_retention_evidence": modeled_retention_evidence,
            "signer_read_or_construction_admission_exercised": false,
            "original_birth": birth,
            "extension": extension,
            "approval_only_history": approved_history.construction_history_v2().unwrap(),
            "pre_reserve_history": read_ready_history.construction_history_v2().unwrap(),
            "complete_history": archive,
            "authority_events": events,
        });
        use std::os::unix::fs::OpenOptionsExt;
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        std::io::Write::write_all(&mut output, &serde_json::to_vec(&fixture).unwrap()).unwrap();
        output.sync_all().unwrap();
    }
    let mut invalid = serde_json::to_value(&archive).unwrap();
    invalid["version"] = 3.into();
    assert!(
        serde_json::from_value::<ConstructionHistoryV2>(invalid)
            .unwrap()
            .validate()
            .is_err()
    );
    let mut invalid = serde_json::to_value(&archive).unwrap();
    invalid["origins"][0]["kind"] = "future_v4".into();
    assert!(serde_json::from_value::<ConstructionHistoryV2>(invalid).is_err());
    let mut invalid = serde_json::to_value(&archive).unwrap();
    invalid["approvals"] = serde_json::json!([]);
    assert!(
        serde_json::from_value::<ConstructionHistoryV2>(invalid)
            .unwrap()
            .validate()
            .is_err()
    );
    let OwnerControl::ApproveManualRosterConstructionV3 { record } = &(match &events[8].mutation {
        AuthorityMutation::OwnerControl(r) => r.control.clone(),
        _ => panic!(),
    }) else {
        panic!()
    };
    let mut bad = record.as_ref().clone();
    let approval_bytes = serde_json::to_vec(&record.approval).unwrap().len();
    assert!(approval_bytes <= MAX_FRAME_BYTES / 2 - 16 * 1024);
    assert!(serde_json::to_vec(record.as_ref()).unwrap().len() < MAX_FRAME_BYTES);
    // Oversized untrusted rosters stop at the explicit transport profile bound;
    // no truncation of originals or partial signed envelope is permitted.
    let mut oversized = record.approval.clone();
    while serde_json::to_vec(&oversized).unwrap().len() <= MAX_FRAME_BYTES / 2 - 16 * 1024 {
        oversized
            .plan
            .originals
            .push(oversized.plan.originals[0].clone());
    }
    assert!(matches!(
        oversized.validate_for(&extension),
        Err(AuthorityError::Limit)
    ));
    bad.owner_signature.signature[0] ^= 1;
    bad.owner_signature_evidence_digest = digest(
        "wholepact:manual-roster-construction-owner-signature:v3",
        &bad.owner_signature,
    )
    .unwrap();
    assert!(bad.validate_for(&extension).is_err());
}
#[test]
fn v2_approval_blocks_v3_before_any_new_charge_and_consumption_timeout_never_refunds() {
    let (legacy_birth, _, legacy_events, ledger) =
        crate::manual_roster_construction_v2::tests::construction_fixture();
    let mut approved = Ledger::new(legacy_birth.request.policy.clone()).unwrap();
    for event in &legacy_events[..9] {
        approved.apply(event).unwrap();
    }
    assert_eq!(approved.snapshot.outstanding_debit_zatoshis, 0);
    assert!(matches!(
        approved.require_original_construction_slot(&h('1'), 3, true, None),
        Err(AuthorityError::Conflict)
    ));
    assert!(matches!(
        ledger.require_original_construction_slot(&h('1'), 3, true, None),
        Err(AuthorityError::Conflict)
    ));
    let (birth, _, events, _) = construction_fixture_v3();
    let mut partial = Ledger::new(birth.request.policy.clone()).unwrap();
    for event in &events[..14] {
        partial.apply(event).unwrap();
    }
    let mut late = events[14].clone();
    late.witness_time_ms = 259_000;
    assert!(partial.apply(&late).is_err());
    assert_eq!(partial.snapshot.outstanding_debit_zatoshis, 400_012_000);
    assert_eq!(partial.snapshot.outstanding_reservations, 1);
    let history = crate::manual_roster_witness_v2::tests::history(&birth, &partial, &events[..14]);
    let archive = history.construction_history_v2().unwrap();
    assert!(
        matches!(&archive.origins()[0], ConstructionOriginHistoryV2::CommonContextV3 { origin } if origin.consumed().is_none())
    );
}

#[path = "manual_roster_construction_v3_tests/original_retention_v2.rs"]
mod original_retention_v2;
