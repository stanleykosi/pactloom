//! Never-funded source-staged fixtures. No native actor, socket, provider, proof,
//! real credential or financial execution is exercised by these tests.
use super::*;
use crate::policy::{Event, Ledger};
use ring::{rand::SystemRandom, signature::EcdsaKeyPair};
fn h(c: char) -> String {
    c.to_string().repeat(64)
}
fn signed_authorization(
    a: ConstructionTransportPreauthorizationV1,
    cert: &[u8],
    key: &EcdsaKeyPair,
) -> SignedConstructionTransportPreauthorizationV1 {
    SignedConstructionTransportPreauthorizationV1 {
        signature: key
            .sign(
                &SystemRandom::new(),
                &construction_transport_preauthorization_signing_bytes_v1(&a).unwrap(),
            )
            .unwrap()
            .as_ref()
            .to_vec(),
        authorization: a,
        scheme: "ecdsa-p256-sha256-asn1-v1".into(),
        owner_certificate_der: cert.to_vec(),
    }
}
fn signed_claim(
    c: ConstructionTransportClaimV1,
    cert: &[u8],
    key: &EcdsaKeyPair,
) -> SignedConstructionTransportClaimV1 {
    SignedConstructionTransportClaimV1 {
        signature: key
            .sign(
                &SystemRandom::new(),
                &construction_transport_claim_signing_bytes_v1(&c).unwrap(),
            )
            .unwrap()
            .as_ref()
            .to_vec(),
        claim: c,
        scheme: "ecdsa-p256-sha256-asn1-v1".into(),
        owner_certificate_der: cert.to_vec(),
    }
}
pub(crate) struct Fixture {
    pub(crate) birth: crate::pending_birth::PendingBirthCommitRecord,
    pub(crate) events: Vec<Event>,
    pub(crate) before: ConstructionHistoryWithTransportV1,
    pub(crate) granted: ConstructionHistoryWithTransportV1,
    pub(crate) claimed: ConstructionHistoryWithTransportV1,
    pub(crate) complete: ConstructionHistoryWithTransportV1,
    pub(crate) old_reservation: Event,
    pub(crate) modeled_read_evidence: serde_json::Value,
    pub(crate) modeled_retention_evidence: Vec<serde_json::Value>,
}
pub(crate) fn fixture() -> Fixture {
    fixture_with_signing_owner().0
}
fn fixture_with_signing_owner() -> (Fixture, tempfile::TempDir, Vec<u8>, EcdsaKeyPair) {
    let (birth, extension, old_events, _, private_directory, certificate, key) =
        crate::manual_roster_construction_v3::tests::construction_fixture_v3_with_signing_owner();
    let mut l = Ledger::new(birth.request.policy.clone()).unwrap();
    let mut events = old_events[..13].to_vec();
    for e in &events {
        l.apply(e).unwrap();
    }
    let history = |l: &Ledger, events: &[Event]| {
        crate::manual_roster_witness_v2::tests::history(&birth, l, events)
            .construction_history_with_transport_v1()
            .unwrap()
    };
    let before = history(&l, &events);
    let AuthorityMutation::ReserveManualRosterConstructionV3(original) = &old_events[13].mutation
    else {
        panic!("synthetic original reserve");
    };
    let approval = l.roster_construction_approval_v3(original).unwrap();
    let active = l.snapshot.active_writer_session.clone().unwrap();
    let read_request=wholepact_core::manual_roster_construction_v3::RosterCommonContextReadRequestV1 {
        version:1,operation_id:"modeled-only-handoff-common-context-read".into(),plan:original.construction.plan.clone(),original_durable_receipt_digest:"ab".repeat(32),witness_plan_approval_digest:approval.approval.digest_for(&extension).unwrap(),purpose:wholepact_core::manual_roster_construction_v3::CommonContextReadPurposeV1::RevalidateExactRetainedNotesAndCommonContext,profile:wholepact_core::manual_roster_construction_v3::CommonContextReadProfileV1::for_plan(&original.construction.plan).unwrap(),current_caller_binding_digest:original.construction.current_caller_binding_digest.clone(),requested_at_ms:original.construction.plan.completion_expires_at_ms()-20_000,admission_expires_at_ms:253_000,completion_expires_at_ms:original.construction.plan.completion_expires_at_ms()
    };
    read_request.validate().unwrap();
    let modeled_read_evidence = serde_json::json!({"version":1,"request":read_request,"retained_signer_intent_digest":original.signer_intent_digest,"current_attempt_digest":original.attempt_digest,"current_attempt_sequence":original.attempt_sequence,"native_review_digest":"de".repeat(32),"admitted_at_ms":252_900,"writer_session_expires_at_ms":active.expires_at_ms});
    let modeled_retention_evidence = original
        .construction
        .plan
        .originals
        .iter()
        .map(|o| {
            crate::manual_roster_construction_v3::tests::modeled_retention_evidence(&o.request)
        })
        .collect();
    let a = ConstructionTransportPreauthorizationV1 {
        version: 1,
        operation_id: "synthetic-handoff-preauthorize".into(),
        account_id: l.policy.account_id.clone(),
        network_profile_id: l.policy.network_profile_id.clone(),
        genesis_digest: l
            .policy
            .account_use_genesis
            .as_ref()
            .unwrap()
            .digest()
            .unwrap(),
        policy_digest: l.policy.policy_digest().unwrap(),
        original_session: active.clone(),
        attempt_digest: original.attempt_digest.clone(),
        attempt_sequence: original.attempt_sequence,
        read_request_digest: read_request.digest().unwrap(),
        read_evidence_digest: wholepact_core::proposal::canonical_digest(
            "wholepact:roster-common-context-read-evidence:v1",
            &modeled_read_evidence,
        )
        .unwrap(),
        plan_approval_digest: approval.approval.digest_for(&extension).unwrap(),
        invocation_digest: original.invocation_digest().unwrap(),
        original_caller_binding_digest: original.construction.current_caller_binding_digest.clone(),
        original_host_process_commitment: h('4'),
        original_native_binding_digest: h('5'),
        native_review_digest: h('6'),
        nonce: h('7'),
        authorized_at_ms: 253_000,
        expires_at_ms: 259_000,
    };
    let signed_authorization = signed_authorization(a, &certificate, &key);
    let grant = ConstructionTransportGrantV1 {
        version: 1,
        operation_id: format!(
            "construct-transport-grant-{}",
            signed_authorization.digest().unwrap()
        ),
        authorization: signed_authorization,
        expected_head: l.snapshot.head.clone(),
        native_review_digest: h('8'),
        granted_at_ms: 253_010,
    };
    assert!(
        serde_json::to_vec(&grant).unwrap().len() <= MAX_CONSTRUCTION_TRANSPORT_COMPONENT_BYTES
    );
    let e = Event {
        mutation: AuthorityMutation::OwnerControl(OwnerControlRequest {
            operation_id: grant.operation_id.clone(),
            account_id: l.policy.account_id.clone(),
            network_profile_id: l.policy.network_profile_id.clone(),
            writer_epoch: l.snapshot.writer_epoch,
            expected_head: l.snapshot.head.clone(),
            control: OwnerControl::GrantConstructionTransportV1 {
                grant: Box::new(grant),
            },
        }),
        authenticated_certificate_digest: l.policy.owner_certificate_digest.clone(),
        witness_time_ms: 253_010,
        writer_session_id: None,
        original_request_link: None,
    };
    l.apply(&e).unwrap();
    events.push(e);
    let granted = history(&l, &events);
    assert!(l.require_unfenced_transport(&active.session_id).is_ok());
    let pending = granted.transport.grants[0].clone();
    let claim = ConstructionTransportClaimV1 {
        version: 1,
        operation_id: format!("construct-transport-claim-{}", pending.digest().unwrap()),
        pending_grant_digest: pending.digest().unwrap(),
        expected_head: pending.committed_head.clone(),
        credential_id: credential_id(&[0x66; 32]),
        exporter_commitment: exporter_commitment(&[0x66; 32]),
        new_caller_binding_digest: h('b'),
        new_native_binding_digest: h('c'),
        original_host_process_commitment: h('4'),
        native_review_digest: h('d'),
        claimed_at_ms: 253_020,
    };
    let e = Event {
        mutation: AuthorityMutation::ClaimConstructionTransportV1(Box::new(signed_claim(
            claim,
            &certificate,
            &key,
        ))),
        authenticated_certificate_digest: active.writer_certificate_digest.clone(),
        witness_time_ms: 253_020,
        writer_session_id: None,
        original_request_link: None,
    };
    l.apply(&e).unwrap();
    events.push(e);
    let claimed = history(&l, &events);
    assert!(matches!(
        l.require_unfenced_transport(&active.session_id),
        Err(AuthorityError::SessionRequired)
    ));
    assert!(l.snapshot.active_writer_session.as_ref() == Some(&active));
    let mut request = (**original).clone();
    request.expected_head = l.snapshot.head.clone();
    request.construction.current_caller_binding_digest = h('b');
    let r = ConstructionTransportRequestV1 {
        version: 1,
        credential_id: credential_id(&[0x66; 32]),
        mutation: ConstructionTransportMutationV1::Reserve(Box::new(request)),
    };
    let e = Event {
        mutation: AuthorityMutation::UseConstructionTransportV1(Box::new(r)),
        authenticated_certificate_digest: active.writer_certificate_digest.clone(),
        witness_time_ms: 253_200,
        writer_session_id: None,
        original_request_link: None,
    };
    let MutationResult::ConstructionTransportReservedV1(reserved) = l.apply(&e).unwrap() else {
        panic!("purpose-distinct reserve");
    };
    events.push(e);
    let consume = ManualRosterConstructionConsumeRequestV3 {
        version: 3,
        operation_id: construction_consume_operation_id_v3(
            &reserved.original,
            &extension,
            &reserved.continuation,
        )
        .unwrap(),
        reservation_operation_id: reserved.original.request.construction.operation_id.clone(),
        reservation_digest: reserved
            .original
            .digest_for(&extension, &reserved.continuation)
            .unwrap(),
        account_id: l.policy.account_id.clone(),
        network_profile_id: l.policy.network_profile_id.clone(),
        writer_epoch: active.writer_epoch,
        expected_head: l.snapshot.head.clone(),
        session_id: active.session_id.clone(),
        common_invocation_digest: reserved.original.request.invocation_digest().unwrap(),
        current_caller_binding_digest: h('b'),
    };
    let e = Event {
        mutation: AuthorityMutation::UseConstructionTransportV1(Box::new(
            ConstructionTransportRequestV1 {
                version: 1,
                credential_id: credential_id(&[0x66; 32]),
                mutation: ConstructionTransportMutationV1::Consume(Box::new(consume)),
            },
        )),
        authenticated_certificate_digest: active.writer_certificate_digest.clone(),
        witness_time_ms: 253_300,
        writer_session_id: None,
        original_request_link: None,
    };
    l.apply(&e).unwrap();
    events.push(e);
    let complete = history(&l, &events);
    let fixture = Fixture {
        birth,
        events,
        before,
        granted,
        claimed,
        complete,
        old_reservation: old_events[13].clone(),
        modeled_read_evidence,
        modeled_retention_evidence,
    };
    (fixture, private_directory, certificate, key)
}
#[test]
fn complete_handoff_retains_claim_without_reserve_and_charges_original_ledger() {
    let f = fixture();
    assert_eq!(f.before.transport.grants.len(), 0);
    assert_eq!(f.granted.transport.grants.len(), 1);
    assert_eq!(f.claimed.transport.credentials.len(), 1);
    assert!(f.claimed.transport.reservations.is_empty());
    assert_eq!(f.claimed.retained_debit_zatoshis().unwrap(), 0);
    assert_eq!(f.complete.retained_debit_zatoshis().unwrap(), 400_012_000);
    assert_eq!(f.complete.transport.reservations.len(), 1);
    assert_eq!(f.complete.transport.consumptions.len(), 1);
    assert!(matches!(
        f.claimed.original.validate(),
        Err(AuthorityError::ConstructionHistoryUnsupported)
    ));
    for value in [&f.before, &f.granted, &f.claimed, &f.complete] {
        value.validate().unwrap();
        let b = serde_json::to_vec(value).unwrap();
        assert!(b.len() <= MAX_CONSTRUCTION_TRANSPORT_HISTORY_BYTES);
        let decoded: ConstructionHistoryWithTransportV1 = serde_json::from_slice(&b).unwrap();
        assert_eq!(value.digest().unwrap(), decoded.digest().unwrap());
    }
    let mut missing = f.claimed.clone();
    missing.transport.credentials.clear();
    assert!(missing.validate().is_err());
    if let Some(path) = std::env::var_os("WHOLEPACT_SYNTHETIC_HANDOFF_AUDIT_FIXTURE") {
        use std::os::unix::fs::OpenOptionsExt;
        let output = serde_json::json!({"fixture_version":1,"fixture_kind":"never-funded-source-protocol-and-synthetic-signature-only","native_actors_exercised":false,"sockets_or_provider_reads_exercised":false,"modeled_read_evidence":f.modeled_read_evidence,"modeled_retention_evidence":f.modeled_retention_evidence,"original_birth":f.birth,"before_grant_history":f.before,"granted_history":f.granted,"claimed_history":f.claimed,"complete_history":f.complete,"authority_events":f.events});
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        std::io::Write::write_all(&mut file, &serde_json::to_vec(&output).unwrap()).unwrap();
        file.sync_all().unwrap();
    }
}
#[test]
fn old_transport_fence_is_checked_before_new_effect_but_old_history_remains() {
    let f = fixture();
    let mut l = Ledger::new(f.birth.request.policy.clone()).unwrap();
    for e in &f.events[..15] {
        l.apply(e).unwrap();
    }
    assert!(matches!(
        l.apply(&f.old_reservation),
        Err(AuthorityError::SessionRequired)
    ));
    // Replay is deliberately informational inside the pure historical ledger.
    assert!(l.replay(&f.events[0]).unwrap().is_some());
    let old = l.snapshot.active_writer_session.as_ref().unwrap();
    assert!(
        l.snapshot
            .require_unfenced_transport(&old.session_id)
            .is_err()
    );
    let mut claim = f.events[14].clone();
    let AuthorityMutation::ClaimConstructionTransportV1(c) = &mut claim.mutation else {
        panic!("claim");
    };
    c.claim.credential_id = h('e');
    assert!(l.apply(&claim).is_err());
}

/// Keep all synthetic signatures and grant/claim digest links valid while
/// changing only the authorization being compared with retained history. This
/// cannot construct a runtime owner or append anything to a witness journal.
fn resign_historical_authorization(
    history: &mut ConstructionTransportHistoryV1,
    authorization: ConstructionTransportPreauthorizationV1,
    certificate: &[u8],
    key: &EcdsaKeyPair,
) {
    assert_eq!(history.grants.len(), 1);
    let pending = &mut history.grants[0];
    pending.grant.authorization = signed_authorization(authorization, certificate, key);
    pending.grant.operation_id = format!(
        "construct-transport-grant-{}",
        pending.grant.authorization.digest().unwrap()
    );
    pending.validate().unwrap();
    for credential in &mut history.credentials {
        credential.pending_grant = pending.clone();
        let mut claim = credential.signed_claim.claim.clone();
        claim.pending_grant_digest = pending.digest().unwrap();
        claim.operation_id = format!("construct-transport-claim-{}", claim.pending_grant_digest);
        credential.signed_claim = signed_claim(claim, certificate, key);
        credential.old_key_fence_digest = old_key_fence_digest(
            credential.authorization(),
            &credential.signed_claim,
            &credential.claimed_head,
        )
        .unwrap();
        credential.validate().unwrap();
    }
}

#[test]
fn portable_handoff_history_rejects_signed_genesis_attempt_caller_and_expiry_substitutions() {
    let (f, _private_directory, certificate, key) = fixture_with_signing_owner();
    let policy = &f.birth.request.policy;

    // Grant-only history must bind its signed genesis even before any claim or
    // Reserve exists. Re-signing prevents a signature error from masking it.
    let mut grant_only = f.granted.transport.clone();
    let mut authorization = grant_only.grants[0]
        .grant
        .authorization
        .authorization
        .clone();
    authorization.genesis_digest = h('e');
    resign_historical_authorization(&mut grant_only, authorization, &certificate, &key);
    grant_only.grants[0]
        .grant
        .authorization
        .verify(&policy.owner_certificate_digest)
        .unwrap();
    assert!(matches!(
        grant_only.validate_for(policy, f.granted.observed_snapshot()),
        Err(AuthorityError::InvalidBinding)
    ));

    for case in 0..4 {
        let mut changed = f.complete.transport.clone();
        // A Reserve-only historical phase is independently supported. Omitting
        // Consume here prevents its old request digest masking the comparison.
        changed.consumptions.clear();
        changed
            .validate_for(policy, f.complete.observed_snapshot())
            .unwrap();
        let mut authorization = changed.grants[0].grant.authorization.authorization.clone();
        match case {
            0 => authorization.attempt_digest = h('e'),
            1 => authorization.attempt_sequence += 1,
            2 => {
                changed.reservations[0]
                    .original
                    .request
                    .construction
                    .current_caller_binding_digest = h('e');
            }
            _ => {
                authorization.expires_at_ms = changed.reservations[0].original.admitted_at_ms + 1;
                assert!(
                    authorization.expires_at_ms
                        < changed.reservations[0]
                            .original
                            .request
                            .construction
                            .admission_expires_at_ms
                );
            }
        }
        resign_historical_authorization(&mut changed, authorization, &certificate, &key);
        changed.grants[0]
            .grant
            .authorization
            .verify(&policy.owner_certificate_digest)
            .unwrap();
        changed.credentials[0]
            .signed_claim
            .verify(&policy.owner_certificate_digest)
            .unwrap();
        let reservation = &changed.reservations[0];
        reservation
            .original
            .validate_for(&reservation.extension, &reservation.continuation)
            .unwrap();
        assert!(matches!(
            changed.validate_for(policy, f.complete.observed_snapshot()),
            Err(AuthorityError::InvalidBinding)
        ));
    }
}

#[test]
fn purpose_proofs_bind_exact_key_channel_and_allowlist() {
    let f = fixture();
    let AuthorityMutation::UseConstructionTransportV1(r) = &f.events[15].mutation else {
        panic!("reserve");
    };
    let key = [0x66; 32];
    let p = proof(&key, &key, r).unwrap();
    verify_proof(&key, &key, r, &p).unwrap();
    assert!(verify_proof(&key, &[0x67; 32], r, &p).is_err());
    assert!(verify_observe_proof(&key, &key, &r.credential_id, &p).is_err());
    let mut changed = (**r).clone();
    changed.version = 2;
    assert!(verify_proof(&key, &key, &changed, &p).is_err());
    assert_ne!(credential_id(&key), crate::session::session_id(&key));
    let old = serde_json::json!({"version":1,"credential_id":r.credential_id,"mutation":{"operation":"acquire_writer","request":{}}});
    assert!(serde_json::from_value::<ConstructionTransportRequestV1>(old).is_err());

    // Boxing is memory-layout only. Compare against the exact former unboxed
    // wire shape, including struct field order used by existing digest domains.
    #[derive(serde::Serialize)]
    #[serde(tag = "operation", content = "request", rename_all = "snake_case")]
    enum UnboxedMutationWire<'a> {
        Consume(&'a ManualRosterConstructionConsumeRequestV3),
    }
    #[derive(serde::Serialize)]
    struct UnboxedRequestWire<'a> {
        version: u16,
        credential_id: &'a str,
        mutation: UnboxedMutationWire<'a>,
    }
    let AuthorityMutation::UseConstructionTransportV1(wrapped) = &f.events[16].mutation else {
        panic!("synthetic consume");
    };
    let ConstructionTransportMutationV1::Consume(consume) = &wrapped.mutation else {
        panic!("synthetic consume");
    };
    let unboxed = UnboxedRequestWire {
        version: wrapped.version,
        credential_id: &wrapped.credential_id,
        mutation: UnboxedMutationWire::Consume(consume.as_ref()),
    };
    let legacy_bytes = serde_json::to_vec(&unboxed).unwrap();
    assert_eq!(serde_json::to_vec(wrapped).unwrap(), legacy_bytes);
    let decoded: ConstructionTransportRequestV1 = serde_json::from_slice(&legacy_bytes).unwrap();
    assert!(decoded == **wrapped);
}
