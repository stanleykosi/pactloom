//! Complete historical DATA validation, not a genuine Final, source, grant,
//! authenticated Authority history, or native constructor execution. The rows
//! use the maintained encrypted journal and real mathematical material codec.
//! The inert request hashes intentionally use Authority's raw serde encoder,
//! NOT Core's sorted canonical JSON. Nested validators run before our envelope.
use super::*;
use crate::authority_bridge::{
    durable_construction_v1::DurableConstructionHistoryRequestV1,
    durable_review_ipc_v1::DurableReviewDeliveryRequestV1,
};
use crate::consent_journal::storage::CoordinatedIntentMaterialFixture as MaterialFixture;
use sha2::{Digest, Sha256};
use wholepact_authority::{
    durable_delivery_admission_v2::canonical_durable_authorization_id_v2,
    durable_delivery_scope_v2::*,
    durable_payment_v1::{DurableFixedCandidateBindingV1, DurablePaymentAdmissionTermsV1},
    AuthorityHead, InputReservation,
};
use wholepact_core::manual_enrollment::ManualAccountIdentity;

fn h(byte: u8) -> String { format!("{byte:02x}").repeat(32) }
#[track_caller]
fn checked<T, E>(r: std::result::Result<T, E>) -> T {
    match r { Ok(v) => v, Err(_) => panic!("inert complete-intent fixture stage failed") }
}
fn authority_digest<T: serde::Serialize>(domain: &str, value: &T) -> String {
    let mut h = Sha256::new();
    h.update(domain.as_bytes()); h.update([0]);
    h.update(checked(serde_json::to_vec(value)));
    hex::encode(h.finalize())
}
fn fixed_binding(f: &DurableFixedCandidateBindingV1) -> String {
    let mut h = Sha256::new();
    h.update(b"wholepact:durable-fixed-proposal:pczt-0.10.0-pre.1:v1\0");
    h.update(f.schema_version.to_le_bytes()); h.update(f.revision.to_le_bytes());
    h.update(f.expiry_height.to_le_bytes());
    for value in [&f.network_profile_id, &f.agreement_id, &f.obligation_id,
        &f.proposal_id, &f.proposal_digest, &f.manifest_digest,
        &f.unsigned_artifact_digest, &f.proved_artifact_digest, &f.effects_commitment,
        &f.policy_digest, &f.review_binding, &f.action_mapping_digest, &f.anchor] {
        h.update((value.len() as u64).to_le_bytes()); h.update(value.as_bytes());
    }
    hex::encode(h.finalize())
}
fn rebind_request(intent: &mut CoordinatedAdmissionIntentV1) {
    let r = &mut intent.request;
    let scope = &checked(record(r)).scope;
    r.operation_id = format!("durable-delivery-admit-v2-{}", authority_digest(
        "wholepact:durable-delivery-owner-operation:v2",
        &(scope, &r.account_id, &r.network_profile_id, r.writer_epoch, &r.expected_head)));
    let review = authority_digest("wholepact:durable-delivery-witness-native-review:v2",
        &(&checked(record(r)).scope, &r.account_id, &r.network_profile_id,
          r.writer_epoch, &r.expected_head, &intent.disclosure));
    let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &mut r.control else { panic!() };
    record.witness_native_review_digest = review;
}
fn scope_mut(i: &mut CoordinatedAdmissionIntentV1) -> &mut DurableDeliveryScopeV2 {
    let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &mut i.request.control else { panic!() };
    &mut record.scope
}
fn rebind_recipient(i: &mut CoordinatedAdmissionIntentV1) {
    i.admit_read.recipient_intent_digest = checked(i.recipient_intent.digest());
}
fn retain(i: &mut CoordinatedAdmissionIntentV1) {
    i.admission = AdmissionProvenanceV1 {
        read_session_digest: i.read.read_session_digest.clone(),
        admit_read_presentation_digest: i.admit_read.presentation_digest.clone(),
        final_presentation_digest: h(0xc1), authenticated_ready_digest: h(0xc2),
        reviewed_digest: checked(i.review_digest()),
        reviewed_at_ms: i.admit_read.approved_at_ms + 10_000,
        retained_at_ms: i.admit_read.approved_at_ms + 20_000,
        expires_at_ms: i.admit_read.expires_at_ms - 10_000,
    };
}

fn complete(f: &MaterialFixture) -> CoordinatedAdmissionIntentV1 {
    let original = &f.rows()[0]; let current = &f.rows()[1];
    let enrollment = {
        let c = checked(f.journal().connection.lock());
        checked(storage::read_enrollment(&c, &current.request().enrollment_ref)).unwrap()
    };
    let proposal = checked(current.request().validate());
    let g = f.genesis(); let disclosure = f.disclosure().clone();
    let identity = ManualAccountIdentity {
        account_id: g.identity.account_id.clone(),
        full_viewing_key_digest: g.identity.full_viewing_key_digest.clone(),
        network_profile_id: g.identity.network_profile_id.clone(),
        derivation_domain: g.identity.derivation_domain.clone(),
    };
    let mut fixed = DurableFixedCandidateBindingV1 {
        schema_version: 1, network_profile_id: identity.network_profile_id.clone(),
        agreement_id: proposal.manifest().agreement.agreement_id.clone(),
        obligation_id: proposal.manifest().agreement.obligation_id.clone(),
        proposal_id: proposal.input().proposal_id.clone(),
        revision: proposal.manifest().agreement.revision,
        expiry_height: proposal.manifest().expiry_height,
        proposal_digest: proposal.proposal_digest().into(),
        manifest_digest: proposal.manifest_digest().into(),
        unsigned_artifact_digest: h(0x66), proved_artifact_digest: h(0x77),
        effects_commitment: h(0x88), policy_digest: h(0x99), review_binding: h(0xaa),
        action_mapping_digest: h(0xbb), anchor: h(0xcc), proposal_binding: String::new(),
    };
    fixed.proposal_binding = fixed_binding(&fixed);
    assert!(fixed.validate().is_ok(), "baseline fixed binding");
    let from = original.request().scope.valid_from_unix_seconds * 1000;
    let until = original.request().scope.valid_until_unix_seconds * 1000;
    let authorization = DurablePaymentAdmissionTermsV1 {
        version: 1, authorization_id: checked(canonical_durable_authorization_id_v2(&fixed, &identity)),
        identity: identity.clone(), original_policy_digest: disclosure.policy_digest.clone(),
        original_genesis_digest: checked(g.digest()), original_birth_commit_digest: h(0x10),
        original_roster_extension_digest: h(0x11), original_enrollment_ref: h(0x12),
        writer_certificate_digest: h(0x13), fixed: fixed.clone(),
        recipient_policy_scope_digest: h(0x14), concrete_recipient_scope_digest: h(0x15),
        inputs: vec![InputReservation { input_id: "inert-input".into(), nullifier: h(0x16),
            action_index: 0, value_zatoshis: 1_000 }],
        maximum_debit_zatoshis: 100, fee_share_zatoshis: 10, transaction_fee_zatoshis: 20,
        valid_from_ms: from, valid_until_ms: until,
    };
    assert!(authorization.validate().is_ok(), "baseline authorization terms");
    let mut owners = proposal.manifest().participants.iter().map(|p| {
        let mut owner = identity.clone(); owner.account_id = p.account_id.clone();
        DurableDeliveryOwnerLineageV2 { account_id: p.account_id.clone(),
            participant_id: p.participant_id.clone(),
            original_authorization_id: checked(canonical_durable_authorization_id_v2(&fixed, &owner)) }
    }).collect::<Vec<_>>();
    owners.sort_by(|a,b| a.account_id.cmp(&b.account_id));
    let material_scopes = owners.iter().map(|owner| DurableDeliveryMaterialScopeRefV2 {
        account_id: owner.account_id.clone(),
        original_scope_digest: if owner.account_id == identity.account_id {
            checked(original.request().scope.digest())
        } else { h(0x17) },
        valid_from_unix_seconds: from / 1000, valid_until_unix_seconds: until / 1000,
    }).collect::<Vec<_>>();
    let delivery = DurableDeliveryPlanV2 {
        dispatcher: DurableDeliveryDispatcherV2 { principal_id: "inert-dispatcher".into(),
            public_identity_commitment: h(0x18),
            authentication_profile: DurableDeliveryAuthenticationProfileV2::OriginalProtectedHostDispatcherV2,
            custody_policy_commitment: h(0x19) },
        original_host_generation_binding_digest: h(0x1a), original_host_profile_id: "inert-host".into(),
        submission_journal_identity: h(0x1b), submission_operation_id: "inert-submission-operation".into(),
        provider: wholepact_core::manual_construction::PreconstructionProvider {
            source_id: "inert-provider".into(), endpoint: "https://provider.invalid".into(),
            trust_profile: "single_tls_provider_report_not_consensus".into() },
        route: DurableDeliveryRouteV2::Direct {}, owners,
        valid_from_ms: from, valid_until_ms: until, minimum_expiry_margin_blocks: 10,
        maximum_fresh_admission_lifetime_ms: 30_000, maximum_explicitly_approved_attempts: 1,
        extraction_rule: DurableDeliveryExtractionRuleV2::FirstDurablyRetainedVerifiedExtraction,
        retry_rule: DurableDeliveryRetryRuleV2::SameRetainedBytesWithFreshAdmission,
        attempt_rule: DurableDeliveryAttemptRuleV2::ExplicitImmediateHostDecision,
    };
    let scope = DurableDeliveryScopeV2 {
        version: 2, authorization, accepted_manifest_ref: current.request().accepted_manifest_ref.clone(),
        original_writer_epoch: 7, delivery: delivery.clone(), witness: disclosure.clone(),
        original_ceilings: DurableDeliveryOriginalCeilingsV2 {
            payment_valid_from_ms: from, payment_valid_until_ms: until,
            enrollment_expires_at_ms: until, policy_expires_at_ms: until,
            material_scopes: material_scopes.clone() },
        disclosure_rule: DurableDeliveryDisclosureRuleV2::WholeTransactionAndConnectionMetadataToProviderCommitmentsAndLinkageToWitness,
    };
    assert!(scope.validate().is_ok(), "baseline full Authority scope");
    let request = OwnerControlRequest {
        operation_id: String::new(), account_id: identity.account_id.clone(),
        network_profile_id: identity.network_profile_id.clone(), writer_epoch: 7,
        expected_head: AuthorityHead { sequence: 4, digest: h(0x1c) },
        control: OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record: Box::new(
            DurableDeliveryAdmissionRecordV2 { scope, witness_native_review_digest: h(0) }) },
    };
    let TransportIdentityBinding::LocalProcess { process_instance, .. } = current.recipient_transport() else { panic!() };
    let recipient_intent = CoordinatedRecipientIntentV1 {
        version: 1,
        request: DurableReviewDeliveryRequestV1 {
            operation_id: "inert-review-operation".into(),
            enrollment_ref: current.request().enrollment_ref.clone(),
            accepted_manifest_ref: current.request().accepted_manifest_ref.clone(),
            own_disclosure: DurableConstructionHistoryRequestV1 {
                operation_id: original.request().operation_id.clone(),
                expected_request_digest: original.request_digest().into() },
            current_disclosure: Some(DurableConstructionHistoryRequestV1 {
                operation_id: current.request().operation_id.clone(),
                expected_request_digest: current.request_digest().into() }),
            proposal_binding: fixed.proposal_binding.clone(),
        },
        fixed: checked(serde_json::from_slice(&checked(serde_json::to_vec(&fixed)))),
        payload_digest: h(0x1d), payload_bytes: 1, delivery, material_scopes,
        account_id: identity.account_id, participant_id: current.request().scope.participant_id.clone(),
        agreement_id: fixed.agreement_id.clone(), manifest_digest: fixed.manifest_digest.clone(),
        coordinated_provider_reference: h(0x1e), signer_process_instance: h(0x1f),
        authorized_host_process_instance: process_instance.clone(),
        source_identity_digest: h(0x2a), source_generation: 1,
        read_session_digest: h(0x2b), receive_decision_digest: h(0x2c),
        original_enrollment_ref: current.request().enrollment_ref.clone(),
        original_manifest_ref: current.request().accepted_manifest_ref.clone(),
    };
    assert!(recipient_intent.validate().is_ok(), "baseline full recipient intent");
    let mut intent = CoordinatedAdmissionIntentV1 {
        version: 4, request, disclosure, owner_certificate_digest: g.owner_certificate_digest.clone(),
        enrollment_ref: current.request().enrollment_ref.clone(),
        manifest_ref: current.request().accepted_manifest_ref.clone(),
        read: ReadProvenanceV1 {
            principal_id: enrollment.principal_id().into(),
            // Serialized historical measurement only, not an authenticated peer.
            measurement: enrollment.receipt().trusted_launch_measurement().into(),
            source_identity_digest: recipient_intent.source_identity_digest.clone(),
            owner_selection_digest: h(0x2d), owner_service_digest: h(0x2e),
            read_session_digest: recipient_intent.read_session_digest.clone(),
            prepare_read_presentation_digest: recipient_intent.read_session_digest.clone(),
            receive_presentation_digest: recipient_intent.receive_decision_digest.clone(),
            approved_at_ms: from + 100_000, expires_at_ms: from + 220_000,
        },
        admit_read: AdmitReadProvenanceV1 {
            presentation_digest: h(0x2f), source_identity_digest: recipient_intent.source_identity_digest.clone(),
            recipient_intent_digest: checked(recipient_intent.digest()),
            owner_selection_digest: h(0x2d), owner_service_digest: h(0x2e),
            authenticated_history_digest: h(0x3a),
            approved_at_ms: from + 250_000, expires_at_ms: from + 370_000,
        },
        recipient_intent,
        ceilings: OwnerServiceCeilingsV1 {
            original_source_expires_at_ms: until, original_material_expires_at_ms: until,
            original_channel_expires_at_ms: until, original_owner_service_expires_at_ms: from + 600_000,
        },
        admission: AdmissionProvenanceV1 {
            read_session_digest: String::new(), admit_read_presentation_digest: String::new(),
            final_presentation_digest: String::new(), authenticated_ready_digest: String::new(),
            reviewed_digest: String::new(), reviewed_at_ms: 0, retained_at_ms: 0, expires_at_ms: 0,
        },
    };
    rebind_request(&mut intent);
    assert!(checked(record(&intent.request)).validate_request(&intent.request, &intent.disclosure).is_ok(), "baseline Authority request binding");
    assert!(intent.validate_review().is_ok(), "baseline full intent review");
    retain(&mut intent);
    assert!(intent.validate().is_ok(), "baseline full retained intent");
    intent
}

#[test]
fn complete_intent_accepts_fresh_admit_read_after_prepare_read_expiry() {
    let f = MaterialFixture::coordinated(); let i = complete(&f);
    assert!(i.admit_read.approved_at_ms > i.read.expires_at_ms);
    checked(i.disclosure.validate()); checked(i.recipient_intent.validate());
    checked(checked(record(&i.request)).validate_request(&i.request, &i.disclosure));
    checked(i.validate_review()); checked(i.validate());
    let c = checked(f.journal().connection.lock()); let before = c.total_changes();
    assert!(storage::verify_schema(&c).is_ok(), "baseline full encrypted schema audit");
    assert!(validate_original_rows(&c, &i).is_ok(), "baseline original encrypted row links");
    assert!(before == c.total_changes());
    // The historical native receipts remain expired; they are NOT renewed.
    let e = checked(storage::read_enrollment(&c, &i.enrollment_ref)).unwrap();
    assert!(e.receipt().expires_at_ms < i.read.approved_at_ms);
}

#[test]
fn complete_intent_rejects_individual_envelope_lineage_mismatches() {
    let f = MaterialFixture::coordinated(); let baseline = complete(&f);
    for mutation in 0..13 {
        let mut i = baseline.clone();
        match mutation {
            0 => i.version = 3, 1 => i.enrollment_ref = h(0xfe), 2 => i.manifest_ref = h(0xfe),
            3 => i.read.source_identity_digest = h(0xfe),
            4 => i.read.read_session_digest = h(0xfe),
            5 => i.read.prepare_read_presentation_digest = h(0xfe),
            6 => i.read.receive_presentation_digest = h(0xfe),
            7 => i.admit_read.source_identity_digest = h(0xfe),
            8 => i.admit_read.owner_selection_digest = h(0xfe),
            9 => i.admit_read.owner_service_digest = h(0xfe),
            10 => i.admit_read.recipient_intent_digest = h(0xfe),
            11 => i.recipient_intent.source_generation = 2,
            _ => i.recipient_intent.payload_bytes = 0,
        }
        assert!(i.validate_review().is_err(), "envelope mutation {mutation}");
    }
}

#[test]
fn complete_intent_rejects_original_ceiling_and_window_violations() {
    let f = MaterialFixture::coordinated(); let baseline = complete(&f);
    for mutation in 0..14 {
        let mut i = baseline.clone(); let from = i.read.approved_at_ms - 100_000;
        match mutation {
            0 => i.ceilings.original_owner_service_expires_at_ms = 0,
            1 => i.ceilings.original_source_expires_at_ms = i.ceilings.original_owner_service_expires_at_ms - 1,
            2 => i.ceilings.original_channel_expires_at_ms = i.ceilings.original_owner_service_expires_at_ms - 1,
            3 => i.ceilings.original_material_expires_at_ms = 0,
            4 => i.ceilings.original_material_expires_at_ms = i.ceilings.original_source_expires_at_ms + 1,
            5 => i.ceilings.original_material_expires_at_ms = i.admit_read.expires_at_ms - 1,
            6 => i.ceilings.original_owner_service_expires_at_ms = i.admit_read.expires_at_ms - 1,
            7 => i.read.approved_at_ms = 0,
            8 => i.read.expires_at_ms = i.read.approved_at_ms,
            9 => i.read.expires_at_ms = i.read.approved_at_ms + 120_001,
            10 => i.admit_read.approved_at_ms = i.read.approved_at_ms - 1,
            11 => i.admit_read.expires_at_ms = i.admit_read.approved_at_ms,
            12 => i.admit_read.expires_at_ms = i.admit_read.approved_at_ms + 120_001,
            _ => { i.read.approved_at_ms = from - 1; i.read.expires_at_ms = from + 1; }
        }
        assert!(i.validate_review().is_err(), "ceiling mutation {mutation}");
    }
}

#[test]
fn complete_intent_nested_requests_cannot_be_rebound_around_lineage() {
    let f = MaterialFixture::coordinated(); let baseline = complete(&f);
    for mutation in 0..7 {
        let mut i = baseline.clone();
        match mutation {
            0 => i.request.expected_head.sequence = 5,
            1 => i.request.writer_epoch += 1,
            2 => scope_mut(&mut i).accepted_manifest_ref = h(0xfe),
            3 => scope_mut(&mut i).delivery.submission_journal_identity = h(0xfe),
            4 => scope_mut(&mut i).original_ceilings.material_scopes[0].original_scope_digest = h(0xfe),
            5 => i.recipient_intent.request.proposal_binding = h(0xfe),
            _ => i.recipient_intent.request.current_disclosure = Some(i.recipient_intent.request.own_disclosure.clone()),
        }
        rebind_request(&mut i);
        assert!(i.validate_review().is_err(), "nested mutation {mutation}");
    }
}

#[test]
fn complete_intent_retention_commits_review_and_preserves_action_deadline() {
    let f = MaterialFixture::coordinated(); let baseline = complete(&f);
    for mutation in 0..9 {
        let mut i = baseline.clone();
        match mutation {
            0 => i.admission.read_session_digest = h(0xfe),
            1 => i.admission.admit_read_presentation_digest = h(0xfe),
            2 => i.admission.reviewed_digest = h(0xfe),
            3 => i.admission.reviewed_at_ms = i.admit_read.approved_at_ms - 1,
            4 => i.admission.retained_at_ms = i.admission.reviewed_at_ms - 1,
            5 => i.admission.expires_at_ms = i.admission.retained_at_ms,
            6 => i.admission.expires_at_ms = i.admit_read.expires_at_ms + 1,
            7 => i.admit_read.authenticated_history_digest = h(0xfe),
            _ => i.ceilings.original_owner_service_expires_at_ms += 1,
        }
        checked(i.validate_review());
        assert!(i.validate().is_err(), "retention mutation {mutation}");
    }
    let mut changed = baseline.clone(); changed.admission.authenticated_ready_digest = h(0xfe);
    assert!(checked(changed.review_digest()) == checked(baseline.review_digest()));
    assert!(checked(changed.request_digest()) == checked(baseline.request_digest()));
    changed.admit_read.authenticated_history_digest = h(0xfe);
    assert!(checked(changed.review_digest()) != checked(baseline.review_digest()));
    assert!(checked(changed.request_digest()) == checked(baseline.request_digest()));
}

#[test]
fn complete_intent_original_rows_reject_valid_envelope_wrong_source_lineage() {
    let f = MaterialFixture::coordinated(); let baseline = complete(&f);
    let c = checked(f.journal().connection.lock()); let before = c.total_changes();
    assert!(validate_original_rows(&c, &baseline).is_ok(), "baseline original encrypted row links");
    for mutation in 0..10 {
        let mut i = baseline.clone();
        match mutation {
            0 => i.read.principal_id = "different-owner".into(),
            1 => i.read.measurement = h(0xfe),
            2 => i.owner_certificate_digest = h(0xfe),
            3 => i.recipient_intent.authorized_host_process_instance = h(0xfe),
            4 => i.recipient_intent.request.current_disclosure = None,
            5 => i.recipient_intent.request.current_disclosure.as_mut().unwrap().expected_request_digest = h(0xfe),
            6 => scope_mut(&mut i).authorization.original_genesis_digest = h(0xfe),
            7 => {
                let own = i.recipient_intent.account_id.clone();
                i.recipient_intent.material_scopes.iter_mut().find(|m| m.account_id == own).unwrap().original_scope_digest = h(0xfe);
                scope_mut(&mut i).original_ceilings.material_scopes = i.recipient_intent.material_scopes.clone();
            }
            8 => i.recipient_intent.request.own_disclosure.expected_request_digest = h(0xfe),
            _ => {
                let other = &f.rows()[2];
                i.recipient_intent.request.current_disclosure = Some(DurableConstructionHistoryRequestV1 {
                    operation_id: other.request().operation_id.clone(),
                    expected_request_digest: other.request_digest().into(),
                });
            }
        }
        rebind_request(&mut i); rebind_recipient(&mut i); retain(&mut i);
        checked(i.validate()); // Reject the actual row join, not malformed DTO grammar.
        assert!(validate_original_rows(&c, &i).is_err(), "row mutation {mutation}");
    }
    assert!(before == c.total_changes());
}

#[test]
fn complete_intent_rejects_legacy_generation_rows_without_relabeling() {
    let f = MaterialFixture::legacy(); let i = complete(&f);
    checked(i.validate());
    let c = checked(f.journal().connection.lock()); let before = c.total_changes();
    let e = checked(storage::read_enrollment(&c, &i.enrollment_ref)).unwrap();
    assert!(e.receipt().permission_generation == 2);
    assert!(validate_original_rows(&c, &i).is_err());
    assert!(before == c.total_changes());
}

#[test]
fn complete_intent_encrypted_retained_reader_binds_canonical_row_columns() {
    let f = MaterialFixture::coordinated(); let i = complete(&f);
    let c = checked(f.journal().connection.lock());
    assert!(validate_original_rows(&c, &i).is_ok(), "baseline original encrypted row links");
    let authorization = &checked(record(&i.request)).scope.authorization.authorization_id;
    checked(c.execute_batch("SAVEPOINT inert_retained_fixture"));
    checked(c.execute("INSERT INTO signer_durable_payment_admission_intents VALUES(?1,?2,?3,?4,?5,?6)",
        params![i.request.operation_id, authorization, checked(i.request_digest()), i.enrollment_ref,
            i.manifest_ref, checked(encode(&i)).as_str()]));
    let before = c.total_changes();
    assert!(storage::verify_schema(&c).is_ok(), "retained full encrypted schema audit");
    let retained = checked(read(&c, authorization)).unwrap();
    assert!(retained.0 == i); checked(retained.history_digest());
    assert!(before == c.total_changes());
    assert!(c.execute("UPDATE signer_durable_payment_admission_intents SET request_digest=?1 WHERE authorization_id=?2", params![h(0xfe), authorization]).is_err());
    assert!(before == c.total_changes());
    // Rebuild inert setup after rollback, rather than disabling immutable-row
    // triggers or editing a committed record. This is not a publication path.
    checked(c.execute_batch("ROLLBACK TO inert_retained_fixture; RELEASE inert_retained_fixture"));
    checked(c.execute("INSERT INTO signer_durable_payment_admission_intents VALUES(?1,?2,?3,?4,?5,?6)",
        params![i.request.operation_id, authorization, h(0xfe), i.enrollment_ref,
            i.manifest_ref, checked(encode(&i)).as_str()]));
    let before = c.total_changes(); assert!(read(&c, authorization).is_err());
    assert!(before == c.total_changes());
}
