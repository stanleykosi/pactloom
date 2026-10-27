// Inert DTO/kernel checks, reusing the existing encrypted source-row fixture.
// No private-origin marker, authenticated history, native grant, result evidence,
// proof, signature, or writer permission is manufactured here. In particular,
// a canonical partial binding is NOT successful admission or completed signing.
use super::*;
use crate::durable_proposals_v1::private_financial_v2::{
    self as kernel, ContinuationReferenceV1, FinancialBindingV2,
};
use wholepact_signer::authority_bridge::financial_continuation_v1::{
    OwnerControl, OwnerControlRequest,
};

fn dto_digest(domain: &str, value: &impl serde::Serialize) -> String {
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update([0]);
    h.update(serde_json::to_vec(value).unwrap());
    hex::encode(h.finalize())
}

// Independent canonical encoding of inert identity data, not a proof verifier.
fn bind_fixed_dto(fixed: &mut FixedProposalIdentityV1) {
    let mut h = Sha256::new();
    h.update(b"wholepact:durable-fixed-proposal:pczt-0.10.0-pre.1:v1\0");
    h.update(fixed.schema_version.to_le_bytes());
    h.update(fixed.revision.to_le_bytes());
    h.update(fixed.expiry_height.to_le_bytes());
    for value in [
        &fixed.network_profile_id, &fixed.agreement_id, &fixed.obligation_id,
        &fixed.proposal_id, &fixed.proposal_digest, &fixed.manifest_digest,
        &fixed.unsigned_artifact_digest, &fixed.proved_artifact_digest,
        &fixed.effects_commitment, &fixed.policy_digest, &fixed.review_binding,
        &fixed.action_mapping_digest, &fixed.anchor,
    ] {
        h.update((value.len() as u64).to_le_bytes());
        h.update(value.as_bytes());
    }
    fixed.proposal_binding = hex::encode(h.finalize());
}

fn authorization_id(fixed: &FixedProposalIdentityV1, account: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"wholepact:durable-manual-proposal-authorization:v1\0");
    for value in [fixed.proposal_binding.as_str(), account] {
        h.update((value.len() as u64).to_le_bytes());
        h.update(value.as_bytes());
    }
    format!("durable-v1-{}", hex::encode(h.finalize()))
}

// Rebind only public historical DTO commitments. This does not construct the
// sealed AuthenticatedFinancialContinuationHistoryV1 or any action capability.
fn bind_continuation_dto(source: &mut ContinuationReferenceV1) {
    let r = &source.record;
    source.request.operation_id = format!("financial-continuation-admit-v1-{}",
        dto_digest("wholepact:financial-continuation-operation:v1", &(
            &r.terms, &r.signer_continuation_intent_digest, &source.request.account_id,
            &source.request.network_profile_id, source.request.writer_epoch,
            &source.request.expected_head,
        )));
    source.record.witness_native_review_digest = dto_digest(
        "wholepact:financial-continuation-native-review:v1", &(
            &r.terms, &r.signer_continuation_intent_digest, &source.request.account_id,
            &source.request.network_profile_id, source.request.writer_epoch,
            &source.request.expected_head, &r.terms.scope.witness,
        ));
    source.request.control = OwnerControl::AdmitFinancialContinuationV1 {
        record: Box::new(source.record.clone()),
    };
    source.record.validate_request(&source.request, &source.record.terms.scope.witness).unwrap();
}

fn inert_binding(envelope: &Envelope) -> (FixedProposalIdentityV1, FinancialBindingV2) {
    let candidate = &envelope.view.candidates[0];
    let fixed: FixedProposalIdentityV1 = serde_json::from_value(
        envelope.durable_proposals_v1[&candidate.candidate_id]["identity"].clone(),
    ).unwrap();
    let mut owners = candidate.proposal.manifest.participants.iter().collect::<Vec<_>>();
    owners.sort_by(|a, b| a.account_id.cmp(&b.account_id));
    let lineage = owners.iter().map(|p| json!({
        "account_id":p.account_id,"participant_id":p.participant_id,
        "original_authorization_id":authorization_id(&fixed, &p.account_id),
    })).collect::<Vec<_>>();
    let materials = owners.iter().map(|p| json!({
        "account_id":p.account_id,"original_scope_digest":hash(0xd1),
        "valid_from_unix_seconds":1,"valid_until_unix_seconds":120,
    })).collect::<Vec<_>>();
    let delivery = json!({
        "dispatcher":{"principal_id":"inert-dispatcher","public_identity_commitment":hash(0xd2),
            "authentication_profile":"original_protected_host_dispatcher_v2","custody_policy_commitment":hash(0xd3)},
        "original_host_generation_binding_digest":hash(0xd4),"original_host_profile_id":"inert-profile",
        "submission_journal_identity":hash(0xd5),"submission_operation_id":"inert-submission-operation",
        "provider":{"source_id":"inert-provider","endpoint":"https://provider.invalid",
            "trust_profile":"single_tls_provider_report_not_consensus"},"route":{"kind":"direct"},
        "owners":lineage,"valid_from_ms":1000,"valid_until_ms":120000,
        "minimum_expiry_margin_blocks":3,"maximum_fresh_admission_lifetime_ms":30000,
        "maximum_explicitly_approved_attempts":2,
        "extraction_rule":"first_durably_retained_verified_extraction",
        "retry_rule":"same_retained_bytes_with_fresh_admission","attempt_rule":"explicit_immediate_host_decision",
    });
    let continuations = owners.iter().enumerate().map(|(i, owner)| {
        let record = json!({
            "terms":{"scope":{"version":2,"authorization":{
                "version":1,"identity":{"account_id":owner.account_id,"full_viewing_key_digest":hash(0xd6),
                    "network_profile_id":fixed.network_profile_id,"derivation_domain":"inert-dto-not-key-evidence"},
                "original_policy_digest":hash(0xd7),"original_genesis_digest":hash(0xd8),
                "original_birth_commit_digest":hash(0xd9),"original_roster_extension_digest":hash(0xda),
                "original_enrollment_ref":hash(0xdb),"writer_certificate_digest":hash(0xdc),
                "fixed":fixed,"authorization_id":authorization_id(&fixed,&owner.account_id),
                "recipient_policy_scope_digest":hash(0xdd),"concrete_recipient_scope_digest":hash(0xde),
                "inputs":[{"input_id":format!("inert-input-{i}"),"nullifier":hash(0xdf),"action_index":i,"value_zatoshis":100}],
                "maximum_debit_zatoshis":50,"fee_share_zatoshis":1,"transaction_fee_zatoshis":2,
                "valid_from_ms":1000,"valid_until_ms":120000},
                "accepted_manifest_ref":hash(0xe0),"original_writer_epoch":1,"delivery":delivery,
                "witness":{"endpoint":format!("127.0.0.1:{}",1901+i),"server_name":"localhost",
                    "witness_id":format!("inert-witness-{i}"),"account_id":owner.account_id,
                    "network_profile_id":fixed.network_profile_id,"policy_digest":hash(0xd7),
                    "pinned_server_certificate_digest":hash(0xe1)},
                "original_ceilings":{"payment_valid_from_ms":1000,"payment_valid_until_ms":120000,
                    "enrollment_expires_at_ms":120000,"policy_expires_at_ms":120000,"material_scopes":materials},
                "disclosure_rule":"whole_transaction_and_connection_metadata_to_provider_commitments_and_linkage_to_witness"},
                "original_delivery_operation_id":format!("inert-original-delivery-{i}"),
                "original_delivery_request_digest":hash(0xe2),
                "original_delivery_committed_head":{"sequence":5,"digest":hash(0xe3)},
                "original_local_intent_digest":hash(0xe4),"original_recipient_intent_digest":hash(0xe5),
                "original_recipient_enrollment_ref":hash(0xe6),"original_recipient_manifest_ref":hash(0xe7),
                "valid_from_ms":1000,"valid_until_ms":120000},
            "signer_continuation_intent_digest":hash(0xe8),"witness_native_review_digest":hash(0xe9),
        });
        let request: OwnerControlRequest = serde_json::from_value(json!({
            "operation_id":"inert-unbound","account_id":owner.account_id,"network_profile_id":fixed.network_profile_id,
            "expected_head":{"sequence":5,"digest":hash(0xe3)},"writer_epoch":1,
            "control":{"action":"admit_financial_continuation_v1","record":record},
        })).unwrap();
        let mut source = ContinuationReferenceV1 {
            request, record: serde_json::from_value(record).unwrap(), authenticated_history_digest:hash(0xea),
        };
        bind_continuation_dto(&mut source);
        (owner.account_id.clone(), source)
    }).collect();
    (fixed, FinancialBindingV2 { schema_version:2, frozen_export_revision:envelope.view.revision,
        frozen_export_history_digest:hash(0xeb), continuations })
}

#[test]
fn financial_v2_partial_binding_is_strict_inert_data_not_completion() {
    let f = saved_history_with_fixed_identity(bind_fixed_dto);
    let (fixed, two) = inert_binding(f.envelopes.last().unwrap());
    two.validate(&fixed).unwrap();
    let first = two.continuations.keys().next().unwrap().clone();
    let mut one = two.clone();
    one.continuations.retain(|account, _| account == &first);
    one.validate(&fixed).unwrap();
    let original = serde_json::to_value(&one.continuations[&first]).unwrap();
    let roundtrip = kernel::decode_binding(&serde_json::to_value(&two).unwrap()).unwrap();
    assert_eq!(serde_json::to_value(&roundtrip.continuations[&first]).unwrap(), original);
    assert_eq!(roundtrip.continuations.len(), 2);
    // Zero owners is not an admitted partial binding. Nor can a caller extend
    // the fixed pair, substitute a map key, or smuggle a different shared plan.
    let mut bad = one.clone();
    bad.continuations.clear();
    assert!(bad.validate(&fixed).is_err());
    let mut bad = two.clone();
    bad.continuations.insert(hash(0xfa), one.continuations[&first].clone());
    assert!(bad.validate(&fixed).is_err());
    let mut bad = one.clone();
    let original_source = bad.continuations.remove(&first).unwrap();
    bad.continuations.insert(hash(0xfb), original_source);
    assert!(bad.validate(&fixed).is_err());
    let mut bad = two.clone();
    let last = bad.continuations.values_mut().last().unwrap();
    last.record.terms.scope.delivery.submission_operation_id = "inert-different-operation".into();
    bind_continuation_dto(last);
    assert!(bad.validate(&fixed).is_err());
    for field in ["proved_artifact_digest", "proposal_binding", "anchor"] {
        let mut changed = serde_json::to_value(&fixed).unwrap();
        changed[field] = json!(hash(0xfc));
        assert!(one.validate(&serde_json::from_value(changed).unwrap()).is_err());
    }
    let mut extra = serde_json::to_value(&one).unwrap();
    extra["completed"] = json!(true);
    assert!(kernel::decode_binding(&extra).is_err());
    extra.as_object_mut().unwrap().remove("completed");
    extra["frozen_export_history_digest"] = json!("a".repeat(64 * 1024));
    assert!(kernel::decode_binding(&extra).is_err());
}

#[test]
fn financial_v2_unmarked_history_cannot_be_promoted_by_partial_binding_after_reopen() {
    let f = saved_history_with_fixed_identity(bind_fixed_dto);
    let original = f.envelopes.last().unwrap();
    assert!(original.private_workspace_origin_v1.is_none());
    let original_bytes = crate::encode(original).unwrap();
    let (_, mut one) = inert_binding(original);
    let first = one.continuations.keys().next().unwrap().clone();
    one.continuations.retain(|account, _| account == &first);
    // Canonical data is valid but is not sufficient to cross the origin gate.
    assert!(kernel::bind(original, one.clone()).is_err());
    let mut injected = original.clone();
    let candidate = injected.view.candidates[0].candidate_id.clone();
    injected.durable_proposals_v1.get_mut(&candidate).unwrap()["financial_binding_v2"] =
        serde_json::to_value(&one).unwrap();
    assert!(kernel::binding(&injected).unwrap().is_some()); // passive DTO read only
    assert!(crate::durable_proposals_v1::validate_stored(&injected).is_err());
    assert!(kernel::progress_accounts(&injected).is_err());
    assert!(kernel::validate_export_shape(&injected).is_err());
    assert!(kernel::require_unfinished_export(&injected, &first).is_err());
    assert_eq!(crate::encode(original).unwrap(), original_bytes);
    let before = original_commands(&f.path, &f.key, f.origin).unwrap();
    assert_eq!(before.len(), 8);
    let record = f.store.get_agreement(&original.view.agreement.agreement_id).unwrap().unwrap();
    drop(f.store);
    let reopened = wholepact_store::Store::open_encrypted(&f.path, &f.key).unwrap();
    assert!(reopened.get_agreement(&original.view.agreement.agreement_id).unwrap().unwrap() == record);
    let after = original_commands(&f.path, &f.key, f.origin).unwrap();
    assert_eq!(serde_json::to_value(before).unwrap(), serde_json::to_value(after).unwrap());
    let replayed = crate::decode_unprojected(&record).unwrap();
    assert!(replayed.private_workspace_origin_v1.is_none());
    assert!(kernel::bind(&replayed, one).is_err());
    assert_eq!(crate::encode(&replayed).unwrap(), original_bytes);
}
