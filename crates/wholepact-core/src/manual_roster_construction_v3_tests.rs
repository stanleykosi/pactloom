//! Pure inert fixtures only: no wallet, sockets, scanner, proof or native owner.
use super::*;

fn h(value: u8) -> String {
    format!("{value:02x}").repeat(32)
}

pub(crate) fn plan() -> ManualRosterConstructionPlanV3 {
    let base = crate::manual_roster_construction_v2::tests::plan();
    let mut economics = base
        .retained
        .selection
        .scope
        .selection
        .economic_intent
        .clone();
    economics.agreement.network_profile_id = COMMON_CONTEXT_PROFILE_ID.into();
    economics.agreement.privacy_profile.mode = crate::PrivacyMode::DeclaredOperator;
    economics.agreement.privacy_profile.proving_operator = Some("synthetic-local-host".into());
    economics.expiry_height = COMMON_CONTEXT_NU7_ACTIVATION_HEIGHT + 100;
    let mut originals = Vec::new();
    for (index, participant) in economics.participants.iter().enumerate() {
        let mut r = base.retained.clone();
        r.operation_id = format!("synthetic-retain-{}", participant.participant_id);
        r.selection.operation_id = format!("synthetic-select-{}", participant.participant_id);
        let scope = &mut r.selection.scope.selection;
        scope.economic_intent = economics.clone();
        scope.invocation.economic_intent_digest = economics.digest().unwrap();
        let mut policy = scope.original_policy_origin.recipient_policy.clone();
        policy.account_id = participant.account_id.clone();
        policy.participant_id = participant.participant_id.clone();
        policy.network_profile_id = COMMON_CONTEXT_PROFILE_ID.into();
        policy.original_limits.per_operation_limit_zatoshis = 1_000_000_000;
        policy.original_limits.maximum_fee_share_zatoshis = 30_000;
        let inventory = &mut scope.inventory;
        inventory.original_recipient_policy = policy.clone();
        inventory.enrollment.identity.account_id = participant.account_id.clone();
        inventory.enrollment.identity.full_viewing_key_digest = h(20 + index as u8);
        inventory.enrollment.identity.network_profile_id = COMMON_CONTEXT_PROFILE_ID.into();
        inventory.enrollment.scope.participant_id = participant.participant_id.clone();
        inventory.enrollment.scope.per_operation_limit_zatoshis = 1_000_000_000;
        inventory.enrollment.scope.maximum_fee_share_zatoshis = 30_000;
        inventory.enrollment.scope.recipient_scope_digests = vec![policy.digest().unwrap()];
        inventory.attachment.selected.account_id = participant.account_id.clone();
        inventory.attachment.selected.canonical_directory =
            format!("/synthetic/{}", participant.participant_id);
        inventory.attachment.selected.directory_identity_digest = h(30 + index as u8);
        inventory.wallet_destination =
            format!("/synthetic/{}/wallet.sqlite", participant.participant_id);
        inventory.anchor_height = COMMON_CONTEXT_NU7_ACTIVATION_HEIGHT + 10;
        inventory.birthday.prior_height = COMMON_CONTEXT_NU7_ACTIVATION_HEIGHT;
        let origin = &mut scope.original_policy_origin;
        origin.recipient_policy = policy.clone();
        origin.intent.identity.account_id = participant.account_id.clone();
        origin.intent.identity.full_viewing_key_digest = inventory
            .enrollment
            .identity
            .full_viewing_key_digest
            .clone();
        origin.intent.identity.network_profile_id = COMMON_CONTEXT_PROFILE_ID.into();
        origin.intent.original_policy_terms.account_id = participant.account_id.clone();
        origin.intent.original_policy_terms.network_profile_id = COMMON_CONTEXT_PROFILE_ID.into();
        origin
            .intent
            .original_policy_terms
            .per_operation_limit_zatoshis = policy.original_limits.per_operation_limit_zatoshis;
        origin
            .intent
            .original_policy_terms
            .maximum_fee_share_zatoshis = policy.original_limits.maximum_fee_share_zatoshis;
        origin.intent.original_policy_terms.recipient_scope_digests =
            vec![policy.digest().unwrap()];
        origin.intent.original_policy_terms_digest =
            origin.intent.original_policy_terms.digest().unwrap();
        origin.birth_digest = canonical_digest(
            "wholepact:native-account-birth-intent:v2",
            &(&origin.intent, &policy),
        )
        .unwrap();
        inventory.enrollment.native_birth_digest = origin.birth_digest.clone();
        r.selection_context.anchor_height = inventory.anchor_height;
        r.selection_context.tip_height = inventory.anchor_height + 1 + index as u32;
        r.selection_context.tip_hash_protocol = h(40 + index as u8);
        r.selection.scope.provenance.original_host_audit =
            OriginalHostRosterAuditV3::AdditionalPublicationV3 {
                audit_digest: h(100 + index as u8),
            };
        r.selection.scope.provenance.roster.roster_sequence += index as u64;
        if index > 0 {
            r.selection.scope.provenance.roster.predecessor =
                crate::manual_roster_v2::HostRosterPredecessorV2::AdditionalPublicationV3 {
                    audit_digest: h(99 + index as u8),
                };
        }
        r.selected_inputs = vec![ManualConstructionInput {
            input_id: format!("synthetic-{}-input", participant.participant_id),
            nullifier: h(50 + index as u8),
            value_zatoshis: participant.maximum_net_debit.as_zatoshis()
                + if index == 0 { 100_000 } else { 0 },
        }];
        r.change_value_zatoshis = if index == 0 { 100_000 } else { 0 };
        r.validate().unwrap();
        originals.push(ManualRosterOriginalRetentionV3 {
            request: r,
            evidence_digest: h(60 + index as u8),
        });
    }
    let common_context = CommonContextProposalV1::from_originals(&originals).unwrap();
    let mut proposal = base.proposal;
    proposal.manifest.agreement = economics.agreement;
    proposal.manifest.expiry_height = economics.expiry_height;
    let result = ManualRosterConstructionPlanV3 {
        version: 3,
        retained: originals[0].request.clone(),
        retained_evidence_digest: originals[0].evidence_digest.clone(),
        proposal,
        participants: originals.iter().map(|o| o.commitment().unwrap()).collect(),
        originals,
        common_context_digest: common_context.digest().unwrap(),
        common_context,
    };
    result.validate().unwrap();
    result
}

fn read() -> RosterCommonContextReadRequestV1 {
    let plan = plan();
    RosterCommonContextReadRequestV1 {
        version: 1,
        operation_id: "synthetic-common-read".into(),
        profile: CommonContextReadProfileV1::for_plan(&plan).unwrap(),
        plan,
        original_durable_receipt_digest: h(70),
        witness_plan_approval_digest: h(71),
        purpose: CommonContextReadPurposeV1::RevalidateExactRetainedNotesAndCommonContext,
        current_caller_binding_digest: h(72),
        requested_at_ms: 40_000,
        admission_expires_at_ms: 70_000,
        completion_expires_at_ms: 100_000,
    }
}

#[test]
fn differing_original_tips_select_exact_maximum_and_keep_every_original() {
    let p = plan();
    // Explicit qualification-only export for downstream pure admission tests.
    // The fixture carries invented unfunded data and no process-local owner.
    if std::env::var_os("WHOLEPACT_EMIT_SYNTHETIC_COMMON_CONTEXT_FIXTURE").is_some() {
        println!(
            "SYNTHETIC_COMMON_CONTEXT_V3_JSON:{}",
            serde_json::to_string(&p).unwrap()
        );
    }
    assert_eq!(
        p.common_context.reference_tip_height,
        p.originals[1].request.selection_context.tip_height
    );
    assert_eq!(
        p.common_context.target_height,
        p.common_context.reference_tip_height + 1
    );
    assert_eq!(
        p.common_context.reference_tip_hash_protocol,
        p.originals[1].request.selection_context.tip_hash_protocol
    );
    let original_bytes: Vec<_> = p
        .originals
        .iter()
        .map(|o| serde_json::to_vec(&o.request).unwrap())
        .collect();
    let decoded =
        ManualRosterConstructionPlanV3::from_json(&serde_json::to_vec(&p).unwrap()).unwrap();
    assert!(decoded == p);
    assert_eq!(
        original_bytes,
        decoded
            .originals
            .iter()
            .map(|o| serde_json::to_vec(&o.request).unwrap())
            .collect::<Vec<_>>()
    );
    assert_eq!(p.completion_expires_at_ms(), 100_000);
    assert_eq!(p.maximum_net_debit_zatoshis().unwrap(), 400_012_000);
    assert_eq!(
        p.invocation_digest().unwrap(),
        p.common_context.original_invocation_digest
    );
}

#[test]
fn anchor_ancestry_and_ambiguous_original_hashes_are_never_relaxed() {
    let p = plan();
    for field in 0..3 {
        let mut originals = p.originals.clone();
        let r = &mut originals[1].request;
        match field {
            0 => {
                r.selection_context.anchor_height += 1;
                r.selection.scope.selection.inventory.anchor_height += 1;
            }
            1 => r.selection_context.anchor_hash_protocol = h(80),
            _ => r.selection_context.anchor_root = h(80),
        }
        assert!(CommonContextProposalV1::from_originals(&originals).is_err());
    }
    let mut originals = p.originals.clone();
    originals[1].request.selection_context.tip_height =
        originals[0].request.selection_context.tip_height;
    assert!(CommonContextProposalV1::from_originals(&originals).is_err());
    originals[1].request.selection_context.tip_hash_protocol = originals[0]
        .request
        .selection_context
        .tip_hash_protocol
        .clone();
    assert!(CommonContextProposalV1::from_originals(&originals).is_ok());
}

#[test]
fn every_original_and_common_scope_is_committed_and_cannot_be_substituted() {
    let p = plan();
    let changes: [fn(&mut ManualRosterConstructionPlanV3); 12] = [
        |p| {
            p.originals[1]
                .request
                .selection
                .scope
                .selection
                .inventory
                .provider
                .source_id
                .push_str("-other")
        },
        |p| {
            p.originals[1]
                .request
                .selection
                .scope
                .selection
                .inventory
                .enrollment
                .scope
                .principal_id
                .push_str("-other")
        },
        |p| {
            p.originals[1]
                .request
                .selection
                .scope
                .selection
                .inventory
                .enrollment
                .host
                .inventory_digest = h(81)
        },
        |p| p.originals[1].request.local_exclusion_digest = h(81),
        |p| p.originals[1].request.selected_inputs[0].nullifier = h(81),
        |p| {
            p.originals[1]
                .request
                .selection
                .scope
                .selection
                .inventory
                .retention_policy
                .push_str("-other")
        },
        |p| p.originals[1].evidence_digest = h(81),
        |p| p.retained.requested_at_ms += 1,
        |p| p.common_context.target_height += 1,
        |p| p.common_context.completion_expires_at_ms += 1,
        |p| p.common_context.expiry_height += 1,
        |p| p.common_context.participants[0].read_scope_digest = h(81),
    ];
    for change in changes {
        let mut changed = p.clone();
        change(&mut changed);
        assert!(changed.validate().is_err());
    }
    let mut changed = p.clone();
    changed.originals[1]
        .request
        .selection
        .scope
        .selection
        .inventory
        .wallet_destination = p.originals[0]
        .request
        .selection
        .scope
        .selection
        .inventory
        .wallet_destination
        .clone();
    assert!(CommonContextProposalV1::from_originals(&changed.originals).is_err());
    let mut changed = p;
    changed.originals[1].request.selected_inputs[0].nullifier =
        changed.originals[0].request.selected_inputs[0]
            .nullifier
            .clone();
    assert!(CommonContextProposalV1::from_originals(&changed.originals).is_err());
}

#[test]
fn exact_proposal_inputs_values_returns_recipients_fees_and_expiry_remain_fixed() {
    let p = plan();
    let changes: [fn(&mut ProposalInput); 7] = [
        |p| p.manifest.inputs[1].input_id = "substituted-bob-input".into(),
        |p| p.manifest.inputs[1].amount = crate::Amount::from_zatoshis(600_018_001).unwrap(),
        |p| {
            p.manifest
                .outputs
                .last_mut()
                .unwrap()
                .address
                .push_str("-other")
        },
        |p| p.manifest.outputs[0].address.push_str("-other"),
        |p| p.manifest.transaction_fee = crate::Amount::from_zatoshis(30_001).unwrap(),
        |p| p.manifest.expiry_height += 1,
        |p| p.artifact_digest = Some(h(82)),
    ];
    for change in changes {
        let mut changed = p.clone();
        change(&mut changed.proposal);
        assert!(changed.validate().is_err());
    }
    let mut changed = p;
    changed.originals.reverse();
    assert!(changed.validate().is_err());
}

#[test]
fn branch_expiry_overflow_and_all_original_scan_caps_are_fixed() {
    let p = plan();
    let changes: [fn(&mut CommonContextProposalV1); 8] = [
        |c| c.network_profile_id = "zcash-mainnet".into(),
        |c| c.consensus_branch_id = 0,
        |c| c.anchor_height = COMMON_CONTEXT_NU7_ACTIVATION_HEIGHT - 1,
        |c| c.reference_tip_height = u32::MAX,
        |c| c.expiry_height = 500_000_000,
        |c| c.expiry_height = c.reference_tip_height + 10,
        |c| c.maximum_owners = 9,
        |c| c.maximum_notes = 65,
    ];
    for change in changes {
        let mut changed = p.common_context.clone();
        change(&mut changed);
        assert!(changed.validate().is_err());
    }
    let mut originals = p.originals.clone();
    originals[1]
        .request
        .selection
        .scope
        .selection
        .inventory
        .maximum_blocks = 1;
    let context = CommonContextProposalV1::from_originals(&originals).unwrap();
    assert_eq!(context.read_profile.maximum_additional_blocks, 1);
    originals[1].request.selection_context.tip_height += 1;
    assert!(CommonContextProposalV1::from_originals(&originals).is_err());
    assert!(CommonContextProposalV1::from_originals(&p.originals[..1]).is_err());
    let oversized: Vec<_> = p.originals.iter().cycle().take(9).cloned().collect();
    assert!(CommonContextProposalV1::from_originals(&oversized).is_err());
}

#[test]
fn aggregate_note_limit_counts_all_complete_retained_owners() {
    let p = plan();
    let mut originals = p.originals;
    let r = &mut originals[1].request;
    let total = r.selected_inputs[0].value_zatoshis;
    r.selected_inputs = (0..64)
        .map(|index| ManualConstructionInput {
            input_id: format!("synthetic-split-bob-{index:02}"),
            nullifier: format!("{index:064x}"),
            value_zatoshis: if index == 63 { total - 63 } else { 1 },
        })
        .collect();
    r.validate().unwrap();
    assert!(CommonContextProposalV1::from_originals(&originals).is_err());
}

#[test]
fn v3_domains_are_distinct_and_old_or_extra_fields_cannot_be_coerced() {
    let old = crate::manual_roster_construction_v2::tests::plan();
    let old_bytes = serde_json::to_vec(&old).unwrap();
    let old_digest = old.digest().unwrap();
    old.validate().unwrap();
    assert!(ManualRosterConstructionPlanV3::from_json(&old_bytes).is_err());
    assert_eq!(
        old_digest,
        canonical_digest("wholepact:manual-roster-construction-plan:v2", &old).unwrap()
    );
    let p = plan();
    assert_ne!(
        p.digest().unwrap(),
        canonical_digest("wholepact:manual-roster-construction-plan:v2", &p).unwrap()
    );
    assert!(
        crate::parse_typed_json::<ManualRosterConstructionPlanV2>(&serde_json::to_vec(&p).unwrap())
            .is_err()
    );
    for field in ["approved", "native_owner", "can_construct", "signature_v2"] {
        let mut value = serde_json::to_value(&p).unwrap();
        value[field] = serde_json::json!(true);
        assert!(
            ManualRosterConstructionPlanV3::from_json(&serde_json::to_vec(&value).unwrap())
                .is_err()
        );
    }
    let bytes = serde_json::to_string(&p).unwrap();
    let duplicate = bytes.replacen("\"version\":3", "\"version\":3,\"version\":3", 1);
    assert!(ManualRosterConstructionPlanV3::from_json(duplicate.as_bytes()).is_err());
    let mut changed = p;
    changed.version = 2;
    assert!(changed.validate().is_err());
}

#[test]
fn read_has_new_plan_and_approval_domain_without_deadline_renewal() {
    let r = read();
    r.validate().unwrap();
    assert_eq!(r.maximum_additional_blocks().unwrap(), 10);
    assert_eq!(
        r.maximum_observed_tip().unwrap(),
        r.plan.common_context.expiry_height - 11
    );
    assert_eq!(r.remaining_admission_ms(69_999).unwrap(), 1);
    assert!(r.remaining_admission_ms(39_999).is_err());
    assert!(r.remaining_admission_ms(70_000).is_err());
    let d = r.digest().unwrap();
    let mut changed = r.clone();
    changed.witness_plan_approval_digest = h(90);
    assert_ne!(d, changed.digest().unwrap());
    let changes: [fn(&mut RosterCommonContextReadRequestV1); 7] = [
        |r| r.completion_expires_at_ms += 1,
        |r| r.admission_expires_at_ms += 1,
        |r| r.operation_id = r.plan.originals[1].request.operation_id.clone(),
        |r| r.profile.maximum_additional_blocks += 1,
        |r| r.profile.maximum_parallel_scans = 3,
        |r| r.profile.minimum_expiry_margin_blocks = 9,
        |r| {
            r.completion_expires_at_ms = r.requested_at_ms + 10_000;
            r.admission_expires_at_ms = r.completion_expires_at_ms;
        },
    ];
    for change in changes {
        let mut changed = r.clone();
        change(&mut changed);
        assert!(changed.validate().is_err());
    }
    for forbidden in [
        "preliminary_scan",
        "select_new_inputs",
        "sign",
        "dispatch",
        "renew",
    ] {
        assert!(
            serde_json::from_str::<CommonContextReadPurposeV1>(&format!("\"{forbidden}\""))
                .is_err()
        );
    }
}

#[test]
fn construction_request_remains_separate_from_additional_read() {
    let read = read();
    let request = ManualRosterConstructionRequestV3 {
        version: 3,
        operation_id: "synthetic-common-construct".into(),
        plan: read.plan,
        current_caller_binding_digest: h(91),
        requested_at_ms: 70_000,
        admission_expires_at_ms: 100_000,
    };
    request.validate().unwrap();
    assert_eq!(request.remaining_admission_ms(99_999).unwrap(), 1);
    assert!(request.remaining_admission_ms(100_000).is_err());
    assert!(
        RosterCommonContextReadRequestV1::from_json(&serde_json::to_vec(&request).unwrap())
            .is_err()
    );
    let mut changed = request;
    changed.admission_expires_at_ms += 1;
    assert!(changed.validate().is_err());
}
