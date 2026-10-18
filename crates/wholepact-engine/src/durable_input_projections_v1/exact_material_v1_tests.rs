//! Pure restriction/join tests, not authenticated receipt, native authority,
//! current chain, encrypted intake, or actual capture qualification.
use super::*;
use wholepact_core::{
    durable_input_projection_v1::{DurableProjectedInputV1, DurableProjectionContextV1},
    FundingPolicy, PrivacyMode,
};
use wholepact_wallet::wallet::protected_sync::durable_construction_v1::{
    ConstructionRecipientV1, ConstructionReviewerV1, DurableConstructionScopeV1, PURPOSE,
};

fn amount(value: u64) -> Amount {
    Amount::from_zatoshis(value).unwrap()
}
pub(in super::super) fn fixture() -> (
    DurableInputProjectionV1,
    DurableConstructionCaptureRequestV1,
    DurableExactConstructionAnchorV1,
    BackendIdentity,
) {
    let mut agreement: wholepact_core::AgreementDraft = wholepact_core::parse_typed_json(
        include_bytes!("../../../wholepact-core/tests/fixtures/agreement.json"),
    )
    .unwrap();
    agreement.network_profile_id = "ironwood-testnet-nu7-candidate".into();
    agreement.recipients[0].amount = amount(300_000);
    agreement.funding_policy = FundingPolicy::Exact {
        target: amount(300_000),
    };
    agreement.privacy_profile.mode = PrivacyMode::DeclaredOperator;
    agreement.privacy_profile.proving_operator = Some("synthetic-constructor".into());
    let provider = BackendIdentity {
        source_id: "synthetic-provider".into(),
        endpoint: "https://invalid.invalid".into(),
        trust_profile: "single_tls_provider_report_not_consensus",
    };
    let accounts = vec!["11".repeat(32), "22".repeat(32)];
    let projections: Vec<_> = (0..2)
        .map(|owner| DurableInputProjectionV1 {
            version: 1,
            intent: DurableInputProjectionIntentV1 {
                version: 1,
                purpose: DurableInputProjectionPurposeV1::DurablePlainFixedInputProjectionV1,
                agreement: agreement.clone(),
                proposal_id: "synthetic-exact-candidate".into(),
                account_id: accounts[owner].clone(),
                participant_id: format!("owner-{owner}"),
                original_recipient_policy_digest: "33".repeat(32),
                privacy_domain: format!("owner-{owner}-privacy"),
                contribution: amount(150_000),
                maximum_fee_share: amount(30_000),
                maximum_transaction_fee: amount(60_000),
                transaction_expiry_height: 4_465_100,
                provider: PreconstructionProvider {
                    source_id: provider.source_id.clone(),
                    endpoint: provider.endpoint.clone(),
                    trust_profile: provider.trust_profile.into(),
                },
                anchor_height: 4_465_050,
                minimum_confirmations: 1,
                maximum_scan_blocks: 100,
                constructor_principal_id: "synthetic-constructor".into(),
                protected_destination: "/synthetic/private-coordinator.sqlite".into(),
                retention_policy: "Synthetic finite private retention.".into(),
                local_reviewer_account_ids: accounts.clone(),
                valid_from_unix_seconds: 100,
                valid_until_unix_seconds: 200,
            },
            inputs: vec![DurableProjectedInputV1 {
                input_id: format!(
                    "ironwood:{}:0",
                    if owner == 0 { "aa" } else { "bb" }.repeat(32)
                ),
                value: amount(250_000),
                commitment: "cc".repeat(32),
            }],
            selected_total: amount(250_000),
            own_return_receiver: format!("usyntheticreturn{owner}"),
            context: DurableProjectionContextV1 {
                tip_height: 4_465_051,
                tip_hash: "dd".repeat(32),
                anchor_height: 4_465_050,
                anchor_hash: "ee".repeat(32),
                anchor_root: "ff".repeat(32),
            },
            captured_at_unix_seconds: 101,
        })
        .collect();
    let candidate =
        candidate_from_retained_projections_v1(&projections, "2026-10-18T00:00:00Z").unwrap();
    let projection = projections[0].clone();
    let recipient = ConstructionRecipientV1 {
        principal_id: projection.intent.constructor_principal_id.clone(),
        authenticated_local_grant_digest: "12".repeat(32),
    };
    let request = DurableConstructionCaptureRequestV1 {
        operation_id: "new-native-material-operation".into(),
        enrollment_ref: "34".repeat(32),
        accepted_manifest_ref: "56".repeat(32),
        scope: DurableConstructionScopeV1 {
            version: 2,
            purpose: PURPOSE.into(),
            proposal: candidate.input().clone(),
            account_id: projection.intent.account_id.clone(),
            participant_id: projection.intent.participant_id.clone(),
            privacy_domain: projection.intent.privacy_domain.clone(),
            constructor: recipient.clone(),
            prover: recipient,
            reviewers: accounts
                .into_iter()
                .map(ConstructionReviewerV1::local_installed_signer)
                .collect(),
            protected_destination: projection.intent.protected_destination.clone(),
            retention_policy: projection.intent.retention_policy.clone(),
            valid_from_unix_seconds: 110,
            valid_until_unix_seconds: 190,
            minimum_confirmations: 1,
            maximum_scan_blocks: 100,
        },
    };
    let anchor = DurableExactConstructionAnchorV1 {
        height: projection.context.anchor_height,
        block_hash_protocol: [0xee; 32],
        root: [0xff; 32],
    };
    join_capture_request(&projection, candidate.input(), &request, &anchor).unwrap();
    (projection, request, anchor, provider)
}

#[test]
fn restrictions_preserve_original_context_every_commitment_and_return_receiver() {
    let (projection, mut request, mut anchor, provider) = fixture();
    request.scope.retention_policy =
        "A distinct fresh native material retention decision is still required.".into();
    anchor.height += 1;
    anchor.block_hash_protocol = [0xdd; 32];
    anchor.root = [0xab; 32];
    join_capture_request(&projection, &request.scope.proposal, &request, &anchor).unwrap();
    let exact = restrictions(&projection, &provider, &anchor).unwrap();
    assert_eq!(
        exact.expected.original_context.anchor_height,
        projection.context.anchor_height
    );
    assert_eq!(exact.expected.original_context.anchor_root, [0xff; 32]);
    assert_eq!(exact.expected.construction_anchor.height, anchor.height);
    assert_eq!(exact.expected.construction_anchor.root, anchor.root);
    assert_eq!(exact.expected.inputs[0].commitment, Some([0xcc; 32]));
    assert_eq!(
        exact.expected.inputs[0].input_id,
        projection.inputs[0].input_id
    );
    assert_eq!(
        exact.original_own_return_receiver,
        projection.own_return_receiver
    );
}

#[test]
fn original_anchor_cannot_be_relabelled_or_silently_moved_backwards() {
    let (projection, request, anchor, _) = fixture();
    for changed in [
        DurableExactConstructionAnchorV1 {
            root: [1; 32],
            ..anchor.clone()
        },
        DurableExactConstructionAnchorV1 {
            block_hash_protocol: [1; 32],
            ..anchor.clone()
        },
        DurableExactConstructionAnchorV1 {
            height: anchor.height - 1,
            ..anchor.clone()
        },
        DurableExactConstructionAnchorV1 {
            height: request.scope.proposal.manifest.expiry_height,
            ..anchor.clone()
        },
    ] {
        assert!(
            join_capture_request(&projection, &request.scope.proposal, &request, &changed).is_err()
        );
    }
}

#[test]
fn changed_source_destination_manifest_and_scope_are_not_recapture_permission() {
    let (projection, request, anchor, provider) = fixture();
    for field in 0..3 {
        let mut changed = provider.clone();
        match field {
            0 => changed.source_id.push_str("-changed"),
            1 => changed.endpoint.push_str("/changed"),
            _ => changed.trust_profile = "untrusted",
        }
        assert!(restrictions(&projection, &changed, &anchor).is_err());
    }
    for field in 0..6 {
        let mut changed = request.clone();
        match field {
            0 => changed.scope.protected_destination.push_str(".other"),
            1 => changed.scope.proposal.proposal_id.push_str("-other"),
            2 => changed.scope.privacy_domain.push_str("-other"),
            3 => changed.scope.valid_until_unix_seconds += 11,
            4 => changed.scope.maximum_scan_blocks += 1,
            _ => {
                changed.scope.proposal.manifest.inputs[0].input_id =
                    format!("ironwood:{}:0", "99".repeat(32))
            }
        }
        assert!(
            join_capture_request(&projection, &request.scope.proposal, &changed, &anchor).is_err()
        );
    }
}

#[test]
fn direct_capture_request_cannot_retarget_operation_refs_or_original_scope() {
    let (_, request, _, _) = fixture();
    let grant = request
        .scope
        .constructor
        .authenticated_local_grant_digest
        .clone();
    join_disclosed_capture_request(&request, &request, None, &grant).unwrap();
    for field in 0..7 {
        let mut changed = request.clone();
        match field {
            0 => changed.operation_id.push_str("-unrelated"),
            1 => changed.enrollment_ref = "ab".repeat(32),
            2 => changed.accepted_manifest_ref = "bc".repeat(32),
            3 => changed.scope.constructor.authenticated_local_grant_digest = "cd".repeat(32),
            4 => changed.scope.valid_until_unix_seconds += 1,
            5 => changed.scope.retention_policy.push_str(" Updated."),
            _ => changed.scope.account_id = "22".repeat(32),
        }
        assert!(join_disclosed_capture_request(&request, &changed, None, &grant).is_err());
    }
}

#[test]
fn redisclosure_scope_allows_only_exact_original_link_and_genuine_fresh_reference_deltas() {
    // Pure DATA correlation only: this does not create a sealed disclosure or
    // prove that a native signer approved any of these synthetic references.
    let (_, saved, _, _) = fixture();
    let grant = "ef".repeat(32);
    let mut current = saved.clone();
    current.operation_id = "distinct-native-redisclosure".into();
    current.enrollment_ref = "ab".repeat(32);
    current.accepted_manifest_ref = "bc".repeat(32);
    current.scope.constructor.authenticated_local_grant_digest = grant.clone();
    current.scope.prover.authenticated_local_grant_digest = grant.clone();
    let link = DurableConstructionRedisclosureLinkV1 {
        original_operation_id: saved.operation_id.clone(),
        original_request_digest: "cd".repeat(32),
        original_outbox_reference: "de".repeat(32),
    };
    join_disclosed_capture_request(&saved, &current, Some(&link), &grant).unwrap();
    for field in 0..10 {
        let mut changed = current.clone();
        let mut changed_link = link.clone();
        match field {
            0 => changed_link.original_operation_id.push_str("-other"),
            1 => changed_link.original_request_digest = "not-a-digest".into(),
            2 => changed_link.original_outbox_reference = "not-a-reference".into(),
            3 => changed.operation_id = saved.operation_id.clone(),
            4 => changed.scope.valid_from_unix_seconds += 1,
            5 => changed.scope.valid_until_unix_seconds += 1,
            6 => changed.scope.protected_destination.push_str(".other"),
            7 => changed.scope.prover.authenticated_local_grant_digest = "98".repeat(32),
            8 => changed.scope.reviewers.pop().map(|_| ()).unwrap(),
            _ => changed.scope.retention_policy.push_str(" Broadened."),
        }
        assert!(
            join_disclosed_capture_request(&saved, &changed, Some(&changed_link), &grant).is_err(),
            "changed field {field}"
        );
    }
    // A well-formed but wrong original digest must be rejected by the separate
    // full-material join, not falsely claimed checked by this scope predicate.
    let source = include_str!("exact_material_v1.rs");
    assert!(source.contains("let original_digest = original.digest()"));
    assert!(source.contains("if original_digest != expected"));
}

#[test]
fn plausible_equal_value_material_still_needs_exact_original_commitment_anchor_and_return() {
    let (projection, _, anchor, _) = fixture();
    let context = SelectionContext {
        tip_height: anchor.height + 1,
        tip_hash_protocol: [0xdd; 32],
        anchor_height: anchor.height,
        anchor_hash_protocol: anchor.block_hash_protocol,
        anchor_root: anchor.root,
    };
    let inputs = projection
        .inputs
        .iter()
        .map(|input| {
            (
                input.input_id.clone(),
                input.value.as_zatoshis(),
                bytes(&input.commitment).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    require_material_facts(
        &projection,
        &anchor,
        &projection.intent.account_id,
        &context,
        &projection.own_return_receiver,
        &inputs,
    )
    .unwrap();
    for field in 0..9 {
        let mut changed_context = context.clone();
        let mut changed_inputs = inputs.clone();
        let mut account = projection.intent.account_id.clone();
        let mut own_return = projection.own_return_receiver.clone();
        match field {
            0 => changed_inputs[0].0 = format!("ironwood:{}:0", "12".repeat(32)),
            1 => changed_inputs[0].1 += 1,
            2 => changed_inputs[0].2 = [0x34; 32],
            3 => changed_context.anchor_height += 1,
            4 => changed_context.anchor_hash_protocol = [0x56; 32],
            5 => changed_context.anchor_root = [0x78; 32],
            6 => account = "22".repeat(32),
            7 => own_return.push_str("unrelated"),
            _ => changed_inputs.clear(),
        }
        assert!(
            require_material_facts(
                &projection,
                &anchor,
                &account,
                &changed_context,
                &own_return,
                &changed_inputs
            )
            .is_err(),
            "changed field {field}"
        );
    }
}

#[test]
fn exact_admission_source_contract_checks_saved_digest_material_then_replay_safe_cas_gate() {
    // Structural supplement, not a native-response or actual-material fixture.
    let source = include_str!("exact_material_v1.rs");
    let wrapper = source
        .split("pub(crate) fn intake_reserved_material_capture_v1")
        .nth(1)
        .unwrap()
        .split("pub(super) fn join_capture_request")
        .next()
        .unwrap();
    assert!(
        wrapper
            .find("join_saved_disclosure(&intent, &projection, outbox)?")
            .unwrap()
            < wrapper
                .find("self.intake_durable_construction_v1(")
                .unwrap()
    );
    assert!(wrapper.contains("if existing != *outbox"));
    assert!(wrapper.contains("crate::candidates::check_revision(&envelope, revision)?"));
    let normalized = source.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(normalized.contains("impl crate::durable_construction_v1::LocalDurableMaterialConsentV1 for ExactCaptureAdmissionGate"));
    assert!(source.contains("self.material.permits(scope, material_digest, action)"));
    assert!(source.contains("canonical_durable_account_id(&evidence.fvk)"));
    assert!(source.contains("input.value_zatoshis"));
    assert!(source.contains("input.commitment"));
    assert!(source.contains("historical_source"));
}
