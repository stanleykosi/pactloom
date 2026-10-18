//! Pure original-V2 history and explicit-profile tests. Complete fabricated
//! birth preimages are not native owners, authenticated witnesses or spend
//! capabilities. Live cryptographic own-return discharge is tested separately.
use super::tests::{rehash_original, Fixture};
use super::*;
use wholepact_authority::{
    account_use_link::account_use_witness_origin_digest,
    manual_enrollment::original_birth_commit_digest,
    pending_birth::{PendingBirthCommitRecord, PendingBirthRequest},
    AccountPolicy, WitnessDisclosureDescriptor,
};
use wholepact_core::{
    born_policy_origin_v2::{
        BornPolicyIdentityV2, BornPolicyWitnessOriginV2, BornRecipientPolicyBirthIntentV2,
        BornRecipientPolicyOriginV2,
    },
    born_recipient_policy_v2::{
        BornConstructionRecipientPolicyV2, BornOriginalLimitsV2, BornOwnReturnRuleV2,
        BornRecipientLimitV2,
    },
};

fn h(c: char) -> String {
    c.to_string().repeat(64)
}

fn fixture_with(native_principal: &str, maximum_recipient: u64) -> Fixture {
    let mut f = Fixture::new();
    let m = f.manifest.proposal_input().manifest.clone();
    let s = &f.binding.original.terms.scope;
    let stable = BornConstructionRecipientPolicyV2 {
        version: 2,
        account_id: f.terms.account_id.clone(),
        network_profile_id: m.agreement.network_profile_id.clone(),
        agreement_id: m.agreement.agreement_id.clone(),
        obligation_id: m.agreement.obligation_id.clone(),
        participant_id: "alice".into(),
        recipients: m
            .agreement
            .recipients
            .iter()
            .map(|r| BornRecipientLimitV2 {
                recipient_id: r.recipient_id.clone(),
                address: r.address.clone(),
                memo: r.memo.clone(),
                instruction_provenance: r.instruction_provenance.clone(),
                maximum_amount_zatoshis: maximum_recipient,
            })
            .collect(),
        charges: vec![],
        original_limits: BornOriginalLimitsV2 {
            aggregate_budget_zatoshis: s.aggregate_budget_zatoshis,
            per_operation_limit_zatoshis: s.per_operation_limit_zatoshis,
            maximum_fee_share_zatoshis: s.maximum_fee_share_zatoshis,
            maximum_transaction_fee_zatoshis: s.maximum_transaction_fee_zatoshis,
            maximum_permit_lifetime_ms: s.maximum_permit_lifetime_ms,
            policy_expires_at_ms: s.expires_at_ms,
        },
        own_return_rule: BornOwnReturnRuleV2::AuthenticatedSameAccount,
    };
    stable.validate().unwrap();
    let scope_digest = stable.digest().unwrap();
    let g = &f.binding.original.genesis;
    let mut policy = AccountPolicy {
        account_use_genesis: None,
        witness_id: g.witness_id.clone(),
        account_id: g.identity.account_id.clone(),
        network_profile_id: g.identity.network_profile_id.clone(),
        owner_certificate_digest: g.owner_certificate_digest.clone(),
        initial_writer_certificate_digest: f
            .binding
            .original
            .terms
            .signer
            .writer_certificate_digest
            .clone(),
        initial_writer_epoch: 1,
        enrollment_refs: vec![h('9')],
        agreement_ids: vec![s.agreement_id.clone()],
        recipient_scope_digests: vec![scope_digest.clone()],
        aggregate_budget_zatoshis: s.aggregate_budget_zatoshis,
        per_operation_limit_zatoshis: s.per_operation_limit_zatoshis,
        maximum_fee_share_zatoshis: s.maximum_fee_share_zatoshis,
        maximum_transaction_fee_zatoshis: s.maximum_transaction_fee_zatoshis,
        maximum_permit_lifetime_ms: s.maximum_permit_lifetime_ms,
        policy_expires_at_ms: s.expires_at_ms,
    };
    let original_terms_digest =
        digest("wholepact:account-birth-original-policy-terms:v1", &policy).unwrap();
    let mut disclosure = WitnessDisclosureDescriptor {
        endpoint: "127.0.0.1:443".into(),
        server_name: "synthetic-original-witness.example".into(),
        witness_id: g.witness_id.clone(),
        account_id: g.identity.account_id.clone(),
        network_profile_id: g.identity.network_profile_id.clone(),
        policy_digest: h('0'),
        pinned_server_certificate_digest: h('3'),
    };
    let intent = BornRecipientPolicyBirthIntentV2 {
        version: 2,
        operation_id: format!("birth-{}", "a".repeat(32)),
        generation_instance_id: h('7'),
        identity: BornPolicyIdentityV2 {
            account_id: g.identity.account_id.clone(),
            full_viewing_key_digest: g.identity.full_viewing_key_digest.clone(),
            network_profile_id: g.identity.network_profile_id.clone(),
            derivation_domain: g.identity.derivation_domain.clone(),
            exact_derivation: "synthetic-original-derivation".into(),
        },
        witness_origin: BornPolicyWitnessOriginV2 {
            endpoint: disclosure.endpoint.clone(),
            server_name: disclosure.server_name.clone(),
            witness_id: disclosure.witness_id.clone(),
            pinned_server_certificate_digest: disclosure.pinned_server_certificate_digest.clone(),
        },
        original_policy_terms: serde_json::from_value(serde_json::to_value(&policy).unwrap())
            .unwrap(),
        original_policy_terms_digest: original_terms_digest.clone(),
        native_principal_id: native_principal.into(),
        native_measurement: h('6'),
        original_target: "/synthetic/original-account".into(),
    };
    let anchor = BornRecipientPolicyOriginV2 {
        version: 2,
        birth_digest: digest(
            "wholepact:native-account-birth-intent:v2",
            &(&intent, &stable),
        )
        .unwrap(),
        intent,
        recipient_policy: stable,
    };
    anchor.validate().unwrap();
    let mut genesis = g.clone();
    genesis.native_birth_digest = anchor.birth_digest.clone();
    genesis.witness_origin_digest = account_use_witness_origin_digest(&disclosure).unwrap();
    policy.account_use_genesis = Some(genesis.clone());
    disclosure.policy_digest = policy.policy_digest().unwrap();
    let request = PendingBirthRequest {
        version: 1,
        operation_id: anchor.intent.operation_id.clone(),
        generation_instance_id: anchor.intent.generation_instance_id.clone(),
        native_birth_digest: anchor.birth_digest.clone(),
        original_terms_digest,
        original_target_digest: h('8'),
        disclosure,
        policy,
        issued_at_ms: 1,
        initial_commit_deadline_ms: 100,
    };
    request.validate().unwrap();
    let commit = PendingBirthCommitRecord {
        version: 1,
        request_digest: request.digest().unwrap(),
        authenticated_owner_certificate_digest: request.policy.owner_certificate_digest.clone(),
        owner_approval_evidence_digest: h('a'),
        local_target_digest: h('b'),
        local_owner_review_digest: h('c'),
        committed_at_ms: 5,
        request,
    };
    commit.validate().unwrap();
    f.binding.original.genesis = genesis;
    let t = &mut f.binding.original.terms;
    t.native_birth_digest = anchor.birth_digest.clone();
    t.account_use_genesis_digest = f.binding.original.genesis.digest().unwrap();
    t.original_witness_origin_digest = f.binding.original.genesis.witness_origin_digest.clone();
    t.original_policy_digest = commit.request.policy.policy_digest().unwrap();
    t.birth_request_digest = commit.request_digest.clone();
    t.birth_commit_digest = original_birth_commit_digest(&commit).unwrap();
    t.scope.recipient_scope_digests = vec![scope_digest.clone()];
    rehash_original(&mut f.binding);
    f.binding.recipient_policy_profile = DurableBornRecipientPolicyProfileV1::StableOriginalV2 {
        original: OriginalRecipientPolicyExportProjectionV2 {
            version: 2,
            anchor,
            original_birth_commit: commit,
        },
        policy_scope_digest: scope_digest,
    };
    f.binding.validate().unwrap();
    f
}
fn fixture() -> Fixture {
    fixture_with("original-native-owner", 1_000_000_000)
}

fn stable(b: &DurableBornPolicyBindingV1) -> (&OriginalRecipientPolicyExportProjectionV2, &String) {
    match &b.recipient_policy_profile {
        DurableBornRecipientPolicyProfileV1::StableOriginalV2 {
            original,
            policy_scope_digest,
        } => (original, policy_scope_digest),
        _ => panic!("fixture must use the explicit stable V2 profile"),
    }
}

#[test]
fn explicit_stable_profile_maps_only_original_policy_and_keeps_exact_effects() {
    let f = fixture();
    f.binding
        .validate_consent(&f.terms, &f.enrollment, &f.manifest)
        .unwrap();
    assert!(f.binding.uses_stable_recipient_policy_v2());
    let (_, policy_digest) = stable(&f.binding);
    assert_ne!(policy_digest, &f.binding.recipient_scope_digest);
    assert!(!f
        .binding
        .original
        .terms
        .scope
        .recipient_scope_digests
        .contains(&f.binding.recipient_scope_digest));
    let original = f.evidence(true);
    let (enrollment, recipient) = witness_policy_scope(&original).unwrap();
    assert_eq!(enrollment, f.binding.original_enrollment_ref);
    assert_eq!(&recipient, policy_digest);
    assert_eq!(original.enrollment().reference(), f.terms.enrollment_ref);
    let returns = f
        .binding
        .stable_return_requirements_v2(&f.manifest)
        .unwrap();
    assert_eq!(returns.len(), 1);
    assert_eq!(returns[0].output_id, "alice-return");
    assert_eq!(returns[0].address, "usyntheticreturnalice");
    assert_eq!(returns[0].amount_zatoshis, 99_988_000);
    // These are explicit requirements for the native verifier, never a claim
    // that a fabricated address belongs to this account.
    assert!(f.binding.require_current_time(200_000).is_err());
    f.binding
        .validate_consent(&f.terms, &f.enrollment, &f.manifest)
        .unwrap();
}

#[test]
fn stable_profile_has_no_missing_tag_hash_or_legacy_upgrade_fallback() {
    let f = fixture();
    let mapped = f.evidence(true);
    let mut omitted = f.binding.clone();
    omitted.recipient_policy_profile = DurableBornRecipientPolicyProfileV1::FixedExactV1;
    assert!(omitted
        .validate_consent(&f.terms, &f.enrollment, &f.manifest)
        .is_err());
    let mut removed_after_approval = mapped.consent.clone();
    removed_after_approval
        .terms
        .durable_born_policy_v1
        .as_mut()
        .unwrap()
        .recipient_policy_profile = DurableBornRecipientPolicyProfileV1::FixedExactV1;
    assert!(removed_after_approval.validate().is_err());
    let mut wrong = f.binding.clone();
    if let DurableBornRecipientPolicyProfileV1::StableOriginalV2 {
        policy_scope_digest,
        ..
    } = &mut wrong.recipient_policy_profile
    {
        *policy_scope_digest = wrong.recipient_scope_digest.clone();
    }
    assert!(wrong.validate().is_err());
    let mut unknown = serde_json::to_value(&f.binding).unwrap();
    unknown["recipient_policy_profile"]["kind"] = "try_any_allowed_digest".into();
    assert!(serde_json::from_value::<DurableBornPolicyBindingV1>(unknown).is_err());
    let mut empty = serde_json::to_value(&f.binding).unwrap();
    empty["recipient_policy_profile"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<DurableBornPolicyBindingV1>(empty).is_err());

    // Existing exact profile omission still has exactly its old canonical bytes.
    let old = Fixture::new();
    let raw = serde_json::to_value(&old.binding).unwrap();
    assert!(raw.get("recipient_policy_profile").is_none());
    let mut explicit = raw.clone();
    explicit["recipient_policy_profile"] = serde_json::json!({"kind":"fixed_exact_v1"});
    let parsed: DurableBornPolicyBindingV1 = serde_json::from_value(explicit).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), raw);
    assert_eq!(
        digest(
            "wholepact:signer-original-spend-consent:v1",
            old.evidence(true).consent.terms()
        )
        .unwrap(),
        old.evidence(true).consent.reference()
    );
}

#[test]
fn stable_original_preimage_commit_genesis_and_extension_cannot_be_substituted() {
    let f = fixture();
    let mutations: Vec<Box<dyn Fn(&mut OriginalRecipientPolicyExportProjectionV2)>> = vec![
        Box::new(|p| p.version = 1),
        Box::new(|p| p.anchor.birth_digest = h('0')),
        Box::new(|p| p.anchor.intent.identity.full_viewing_key_digest = h('0')),
        Box::new(|p| p.anchor.intent.operation_id = format!("birth-{}", "b".repeat(32))),
        Box::new(|p| p.anchor.intent.generation_instance_id = h('0')),
        Box::new(|p| p.anchor.intent.original_policy_terms_digest = h('0')),
        Box::new(|p| p.anchor.recipient_policy.participant_id = "bob".into()),
        Box::new(|p| p.anchor.recipient_policy.obligation_id = "other-obligation".into()),
        Box::new(|p| p.original_birth_commit.request_digest = h('0')),
        Box::new(|p| p.original_birth_commit.request.native_birth_digest = h('0')),
        Box::new(|p| {
            p.original_birth_commit
                .request
                .policy
                .account_use_genesis
                .as_mut()
                .unwrap()
                .identity
                .account_id = h('0')
        }),
    ];
    for mutate in mutations {
        let mut b = f.binding.clone();
        if let DurableBornRecipientPolicyProfileV1::StableOriginalV2 { original, .. } =
            &mut b.recipient_policy_profile
        {
            mutate(original);
        }
        assert!(b.validate().is_err());
    }
    // Even a second internally valid preimage/commit is not the retained source.
    let other = fixture_with("different-original-owner", 1_000_000_000);
    other.binding.validate().unwrap();
    let mut b = f.binding.clone();
    b.recipient_policy_profile = other.binding.recipient_policy_profile;
    assert!(b.validate().is_err());
    let mut b = f.binding.clone();
    b.original_extension_digest = h('0');
    assert!(b.validate().is_err());
}

#[test]
fn stable_recipient_caps_and_exact_return_effects_are_independent_constraints() {
    let narrow = fixture_with("original-native-owner", 999_999_999);
    narrow.binding.validate().unwrap();
    assert!(narrow
        .binding
        .validate_consent(&narrow.terms, &narrow.enrollment, &narrow.manifest)
        .is_err());
    let f = fixture();
    let (origin, _) = stable(&f.binding);
    let mut changed = f.manifest.proposal_input().clone();
    changed.manifest.outputs[1].address = "usubstitutedownreturn".into();
    // Stable policy produces an ownership obligation, not a blanket permission.
    let (_, returns) = origin
        .anchor
        .recipient_policy
        .validate_candidate_for_enrollment(&f.binding.original.terms, &changed)
        .unwrap();
    assert_eq!(returns[0].address, "usubstitutedownreturn");
    let changed_proposal = wholepact_core::Proposal::validate(changed).unwrap();
    let changed_manifest = AcceptedManifestRecord::new(ManifestTerms {
        proposal: changed_proposal.input().clone(),
        proposal_digest: changed_proposal.proposal_digest().into(),
        manifest_digest: changed_proposal.manifest_digest().into(),
        ..f.manifest.terms.clone()
    })
    .unwrap();
    assert!(f
        .binding
        .stable_return_requirements_v2(&changed_manifest)
        .is_err());
    assert!(f
        .binding
        .validate_consent(&f.terms, &f.enrollment, &changed_manifest)
        .is_err());
}

#[test]
fn stable_request_reconstruction_retains_actual_local_delivery_and_exact_payment_commit() {
    use crate::authority_bridge::protocol::{
        AuthorizationDeliveryScope, RetainedAuthorizationRequest,
    };
    let f = fixture();
    let original = f.evidence(true);
    let request = RetainedAuthorizationRequest::from_original(
        &original,
        b"synthetic-fixed-artifact",
        wholepact_authority::AuthorityHead {
            sequence: 1,
            digest: h('a'),
        },
        AuthorizationDeliveryScope {
            candidate_id: "proposal-a".into(),
        },
    )
    .unwrap();
    request.validate_original(&original).unwrap();
    assert_eq!(
        request.reservation.recipient_scope_digest,
        *stable(&f.binding).1
    );
    assert_eq!(
        request.reservation.enrollment_ref,
        f.binding.original_enrollment_ref
    );
    assert!(original.original_consent().terms().transport == *f.enrollment.transport());
    let mut changed = request.clone();
    changed.reservation.recipient_scope_digest = f.binding.recipient_scope_digest.clone();
    assert!(changed.validate_original(&original).is_err());
    let mut changed = request;
    changed.reservation.enrollment_ref = f.enrollment.reference().into();
    assert!(changed.validate_original(&original).is_err());
}

#[cfg(all(
    feature = "durable-proposal",
    feature = "native-ui",
    target_os = "linux"
))]
#[test]
fn stable_actual_source_constructor_requires_complete_export_and_rejects_exact_validator() {
    use crate::account::birth::{
        enrollment::roster_v2::BornManualRosterEnrollmentRecordV2,
        recipient_policy_v2::OriginalRecipientPolicyExportV2,
    };
    let f = fixture();
    let native = digest(
        "wholepact:native-born-manual-roster-enrollment-review:v2",
        &(
            &f.binding.original,
            &f.binding.original_roster_extension.roster,
        ),
    )
    .unwrap();
    let source: BornManualRosterEnrollmentRecordV2 = serde_json::from_value(serde_json::json!({ "version":2, "account_record":f.binding.original, "roster":f.binding.original_roster_extension.roster, "signer_roster_native_review_digest":native })).unwrap();
    let export: OriginalRecipientPolicyExportV2 =
        serde_json::from_value(serde_json::to_value(stable(&f.binding).0).unwrap()).unwrap();
    let fixed = serde_json::from_value(serde_json::to_value(&f.binding.fixed).unwrap()).unwrap();
    assert!(DurableBornPolicyBindingV1::from_original_source(
        &source,
        &f.enrollment,
        &f.manifest,
        &fixed
    )
    .is_err());
    assert!(f
        .binding
        .validate_original_source(&source, &source.account_record.genesis)
        .is_err());
    f.binding
        .validate_stable_original_source_v2(&source, &source.account_record.genesis, &export)
        .unwrap();
    let rebuilt = DurableBornPolicyBindingV1::from_original_stable_source_v2(
        &source,
        &f.enrollment,
        &f.manifest,
        &fixed,
        &export,
    )
    .unwrap();
    assert!(rebuilt == f.binding);
    let other = fixture_with("different-original-owner", 1_000_000_000);
    let wrong_export: OriginalRecipientPolicyExportV2 =
        serde_json::from_value(serde_json::to_value(stable(&other.binding).0).unwrap()).unwrap();
    wrong_export.validate().unwrap();
    assert!(f
        .binding
        .validate_stable_original_source_v2(&source, &source.account_record.genesis, &wrong_export)
        .is_err());
}
