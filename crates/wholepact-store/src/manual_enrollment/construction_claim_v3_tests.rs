//! Synthetic historical DTOs in actual encrypted Store files. No native owner,
//! wallet selection, signature, proof, socket, or live account is constructed.
use super::*;
use crate::manual_enrollment::construction_claim_v2::{
    append_modeled_construction_root, append_modeled_construction_rows, modeled_claim_v2,
    modeled_construction_roster_history,
};
use wholepact_core::manual_roster_construction_v3::{
    CommonContextProposalV1, ManualRosterConstructionPlanV3, ManualRosterOriginalRetentionV3,
};
use wholepact_storage_security::DatabaseKey;

fn h(tag: &str) -> String {
    request_digest(&serde_json::json!(["synthetic-v3-store-history", tag])).unwrap()
}

/// Construct separate, never-funded V3 historical originals before committing
/// any journal rows. Recompute all affected commitments; do not convert an
/// existing V2 claim, replace its original contexts, or issue a capability.
fn seed_claim() -> ManualRosterConstructionClaimV3 {
    let raw: serde_json::Value =
        serde_json::from_slice(include_bytes!("fixtures/synthetic_plan_v3.json")).unwrap();
    let mut originals: Vec<ManualRosterOriginalRetentionV3> =
        serde_json::from_value(raw["originals"].clone()).unwrap();
    let mut proposal: wholepact_core::ProposalInput =
        serde_json::from_value(raw["proposal"].clone()).unwrap();
    let accounts = ["51".repeat(32), "52".repeat(32)];
    let principal = "synthetic-v3-principal";
    let key = "synthetic-v3-construction-key";
    for (i, original) in originals.iter_mut().enumerate() {
        let r = &mut original.request;
        r.operation_id = format!("synthetic-v3-retain-{i}");
        r.selection.operation_id = format!("synthetic-v3-select-{i}");
        r.selected_inputs[0].input_id = format!("synthetic-v3-input-{i}");
        r.selected_inputs[0].nullifier = h(&format!("nullifier-{i}"));
        let s = &mut r.selection.scope.selection;
        s.economic_intent.candidate_id = "synthetic-v3-candidate".into();
        s.economic_intent.proposal_id = "synthetic-v3-proposal".into();
        s.economic_intent.agreement.agreement_id = "synthetic-v3-agreement".into();
        s.economic_intent.agreement.obligation_id = "synthetic-v3-obligation".into();
        for (p, account) in s.economic_intent.participants.iter_mut().zip(&accounts) {
            p.account_id = account.clone();
        }
        s.invocation.operation_id = "synthetic-v3-invocation".into();
        s.invocation.idempotency_key_digest =
            request_digest(&serde_json::json!([principal, key])).unwrap();
        s.invocation.invocation_nonce = h("invocation-nonce");
        s.invocation.economic_intent_digest = s.economic_intent.digest().unwrap();
        let inventory = &mut s.inventory;
        let policy = &mut inventory.original_recipient_policy;
        policy.account_id = accounts[i].clone();
        policy.agreement_id = s.economic_intent.agreement.agreement_id.clone();
        policy.obligation_id = s.economic_intent.agreement.obligation_id.clone();
        let terms = &mut inventory.enrollment;
        terms.operation_id = format!("synthetic-v3-enrollment-{i}");
        terms.identity.account_id = accounts[i].clone();
        terms.identity.derivation_domain = "dedicated-testnet-legacy-zip32-v1".into();
        terms.identity.full_viewing_key_digest = h(&format!("viewing-key-{i}"));
        terms.scope.principal_id = principal.into();
        terms.scope.agreement_id = policy.agreement_id.clone();
        terms.scope.obligation_id = policy.obligation_id.clone();
        terms.original_policy_digest = policy.digest().unwrap();
        terms.scope.recipient_scope_digests = vec![policy.digest().unwrap()];
        inventory.attachment.selected.account_id = accounts[i].clone();
        let origin = &mut s.original_policy_origin;
        origin.recipient_policy = policy.clone();
        origin.intent.native_principal_id = principal.into();
        origin.intent.identity.account_id = accounts[i].clone();
        origin.intent.identity.derivation_domain = terms.identity.derivation_domain.clone();
        origin.intent.identity.full_viewing_key_digest =
            terms.identity.full_viewing_key_digest.clone();
        origin.intent.original_policy_terms.account_id = accounts[i].clone();
        origin.intent.original_policy_terms.agreement_ids = vec![policy.agreement_id.clone()];
        origin.intent.original_policy_terms.recipient_scope_digests =
            vec![policy.digest().unwrap()];
        origin.intent.original_policy_terms_digest =
            origin.intent.original_policy_terms.digest().unwrap();
        origin.birth_digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-account-birth-intent:v2",
            &(&origin.intent, &origin.recipient_policy),
        )
        .unwrap();
        terms.native_birth_digest = origin.birth_digest.clone();
        original.evidence_digest = h(&format!("retained-evidence-{i}"));
        original.validate().unwrap();
    }
    let economic = &originals[0]
        .request
        .selection
        .scope
        .selection
        .economic_intent;
    proposal.proposal_id = economic.proposal_id.clone();
    proposal.manifest.agreement = economic.agreement.clone();
    proposal.manifest.participants = economic.participants.clone();
    for (i, input) in proposal.manifest.inputs.iter_mut().enumerate() {
        input.account_id = accounts[i].clone();
        input.input_id = originals[i].request.selected_inputs[0].input_id.clone();
    }
    for output in &mut proposal.manifest.outputs {
        if let wholepact_core::OutputAllocation::Return {
            participant_id,
            account_id,
            ..
        } = &mut output.allocation
        {
            let i = economic
                .participants
                .iter()
                .position(|p| &p.participant_id == participant_id)
                .unwrap();
            *account_id = accounts[i].clone();
        }
    }
    let context = CommonContextProposalV1::from_originals(&originals).unwrap();
    let participants = originals.iter().map(|o| o.commitment().unwrap()).collect();
    let plan = ManualRosterConstructionPlanV3 {
        version: 3,
        retained: originals[0].request.clone(),
        retained_evidence_digest: originals[0].evidence_digest.clone(),
        proposal,
        participants,
        originals,
        common_context_digest: context.digest().unwrap(),
        common_context: context,
    };
    let mut claim = ManualRosterConstructionClaimV3 {
        reentry_lineages: None,
        version: 3,
        principal_id: principal.into(),
        construction_key: key.into(),
        maximum_actions: 8,
        consumed: (0..2)
            .map(|i| ManualRosterConsumedConstructionAuditV3 {
                version: 3,
                request: ManualRosterConstructionRequestV3 {
                    version: 3,
                    operation_id: format!("synthetic-v3-construct-{i}"),
                    plan: plan.clone(),
                    current_caller_binding_digest: h(&format!("caller-{i}")),
                    requested_at_ms: 2002,
                    admission_expires_at_ms: 32_000,
                },
                retained_signer_intent_digest: h(&format!("retained-intent-{i}")),
                current_attempt_digest: h(&format!("construction-attempt-{i}")),
                current_attempt_sequence: 3,
                common_context_read_admission_digest: h(&format!("read-admission-{i}")),
                witness_plan_approval_digest: h(&format!("plan-approval-{i}")),
                native_review_digest: h(&format!("native-review-{i}")),
                witness_reservation_digest: h(&format!("reservation-{i}")),
                witness_consumed_digest: h(&format!("consumed-{i}")),
                reviewed_at_ms: 2003,
                reserved_at_ms: 2004,
                consumed_at_ms: 2005,
                reserved_debit_zatoshis: if i == 0 { 400_012_000 } else { 600_018_000 },
                reserved_input_value_zatoshis: if i == 0 { 400_112_000 } else { 600_018_000 },
                writer_session_expires_at_ms: 100_000,
            })
            .collect(),
    };
    rebuild(&mut claim);
    claim
}

/// Rebuild inert commitment closure after an explicit test-data mutation.
/// Callers mutate originals in the first plan only; no persisted row is changed.
fn rebuild(claim: &mut ManualRosterConstructionClaimV3) {
    let mut plan = claim.consumed[0].request.plan.clone();
    let identity = request_digest(&serde_json::json!([
        &claim.principal_id,
        &claim.construction_key
    ]))
    .unwrap();
    for original in &mut plan.originals {
        let selection = &mut original.request.selection.scope.selection;
        selection.invocation.idempotency_key_digest = identity.clone();
        selection.invocation.economic_intent_digest = selection.economic_intent.digest().unwrap();
    }
    plan.common_context = CommonContextProposalV1::from_originals(&plan.originals).unwrap();
    plan.common_context_digest = plan.common_context.digest().unwrap();
    plan.participants = plan
        .originals
        .iter()
        .map(|o| o.commitment().unwrap())
        .collect();
    for (i, audit) in claim.consumed.iter_mut().enumerate() {
        let mut owner_plan = plan.clone();
        owner_plan.retained = plan.originals[i].request.clone();
        owner_plan.retained_evidence_digest = plan.originals[i].evidence_digest.clone();
        audit.request.plan = owner_plan;
    }
    claim.validate().unwrap();
}

fn checkpoint(claim: &ManualRosterConstructionClaimV3) -> ManualRosterConstructionCheckpointV3 {
    let proposal = claim.validate().unwrap();
    let inventory = &claim.consumed[0]
        .request
        .plan
        .retained
        .selection
        .scope
        .selection
        .inventory;
    ManualRosterConstructionCheckpointV3 {
        version: 3,
        claim_digest: claim.digest().unwrap(),
        job_id: expected_job_id(&claim.principal_id, &claim.construction_key),
        scope: ManualRosterCheckpointScopeV3 {
            principal_id: claim.principal_id.clone(),
            candidate_id: claim.candidate_id().into(),
            manifest_digest: proposal.manifest_digest().into(),
            artifact_digest: h("artifact"),
            effects_commitment: h("effects"),
            coordination_request_digest: claim.request_digest().unwrap(),
            review_binding: h("review"),
            account_ids: proposal
                .manifest()
                .participants
                .iter()
                .map(|p| p.account_id.clone())
                .collect(),
            local_operator: inventory.operator_name.clone(),
            purpose: "construct_one_candidate".into(),
            retention_policy: inventory.retention_policy.clone(),
        },
    }
}

pub(crate) fn append_modeled_construction_rows_v3(
    store: &Store,
    root: &ManualEnrollmentInitialPublicationV2,
    with_checkpoint: bool,
) -> (
    ManualRosterConstructionClaimV3,
    Option<ManualRosterConstructionCheckpointV3>,
) {
    append_modeled_common_context_rows(store, root, with_checkpoint, false)
}

pub(crate) fn append_modeled_reentered_construction_rows_v4(
    store: &Store,
    root: &ManualEnrollmentInitialPublicationV2,
    with_checkpoint: bool,
) -> (
    ManualRosterConstructionClaimV3,
    Option<ManualRosterConstructionCheckpointV3>,
) {
    append_modeled_common_context_rows(store, root, with_checkpoint, true)
}

fn append_modeled_common_context_rows(
    store: &Store,
    root: &ManualEnrollmentInitialPublicationV2,
    with_checkpoint: bool,
    reentered: bool,
) -> (
    ManualRosterConstructionClaimV3,
    Option<ManualRosterConstructionCheckpointV3>,
) {
    let mut claim = seed_claim();
    let original_contexts: Vec<_> = claim.consumed[0]
        .request
        .plan
        .originals
        .iter()
        .map(|o| o.request.selection_context.clone())
        .collect();
    let previous = {
        let connection = store.connection.lock().unwrap();
        read_audits::<ManualEnrollmentAdditionalPublicationV3>(
            &connection,
            ADDITIONAL_PUBLICATION_V3,
        )
        .unwrap()
        .into_iter()
        .map(|(_, a)| a)
        .max_by_key(|a| a.store_sequence)
    };
    let mut retentions: Vec<_> = claim.consumed[0]
        .request
        .plan
        .originals
        .iter()
        .map(|o| o.request.clone())
        .collect();
    let (additions, continuations, attempts) =
        modeled_construction_roster_history(root, &mut retentions, previous.as_ref());
    for (original, retained) in claim.consumed[0]
        .request
        .plan
        .originals
        .iter_mut()
        .zip(retentions)
    {
        original.request = retained;
    }
    for (audit, attempt) in claim.consumed.iter_mut().zip(attempts) {
        audit.current_attempt_digest = attempt;
    }
    rebuild(&mut claim);
    assert!(
        claim.consumed[0]
            .request
            .plan
            .originals
            .iter()
            .map(|o| o.request.selection_context.clone())
            .eq(original_contexts)
    );
    assert_ne!(
        claim.consumed[0].request.plan.originals[0]
            .request
            .selection_context
            .tip_height,
        claim.consumed[0].request.plan.originals[1]
            .request
            .selection_context
            .tip_height
    );
    // Model the explicit new encoding before any immutable row is written.
    // Never retrofit reentry onto a persisted legacy claim.
    if reentered {
        model_reentry_lineages(&mut claim);
    }
    let receipt = with_checkpoint.then(|| checkpoint(&claim));
    let context = crate::CommandContext::for_request(
        &claim.principal_id,
        "synthetic-v3-agreement-create",
        &serde_json::json!(["synthetic-v3-agreement"]),
    )
    .unwrap();
    store.create_agreement(&context,&claim.proposal().manifest.agreement.agreement_id,
        serde_json::json!({"view":{"agreement":claim.proposal().manifest.agreement,"candidates":[]}})).unwrap();
    let connection = store.connection.lock().unwrap();
    for addition in additions {
        put(
            &connection,
            ADDITIONAL_PUBLICATION_V3,
            &addition.digest().unwrap(),
            &addition,
        );
    }
    for continuation in continuations {
        put(
            &connection,
            CONTINUATION_V4,
            &continuation.digest().unwrap(),
            &continuation,
        );
    }
    put(
        &connection,
        CONSTRUCTION_CLAIM_V3,
        &claim.digest().unwrap(),
        &claim,
    );
    if let Some(receipt) = &receipt {
        put(
            &connection,
            CONSTRUCTION_CHECKPOINT_V3,
            &receipt.claim_digest,
            receipt,
        );
    }
    read_construction_rows(&connection).unwrap();
    (claim, receipt)
}

fn put<T: Serialize>(connection: &rusqlite::Connection, kind: &str, id: &str, value: &T) {
    connection
        .execute(
            "INSERT INTO records VALUES(?1,?2,0,?3,1,1)",
            rusqlite::params![kind, id, serde_json::to_string(value).unwrap()],
        )
        .unwrap();
}

pub(crate) fn exact_manual_rows(store: &Store) -> Vec<(String, String, u64, String, i64, i64)> {
    store.connection.lock().unwrap().prepare("SELECT aggregate_type,id,revision,payload,created_at_ms,updated_at_ms FROM records WHERE aggregate_type LIKE 'generation_manual_%' ORDER BY aggregate_type,id").unwrap()
        .query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).unwrap().collect::<rusqlite::Result<_>>().unwrap()
}

#[test]
fn common_context_v3_claim_preserves_originals_and_canonical_domains() {
    let claim = seed_claim();
    let receipt = checkpoint(&claim);
    receipt.validate_for(&claim).unwrap();
    let originals = &claim.consumed[0].request.plan.originals;
    assert_eq!(originals.len(), 2);
    assert_eq!(
        originals[0].request.selection_context.anchor_root,
        originals[1].request.selection_context.anchor_root
    );
    assert_ne!(
        originals[0].request.selection_context.tip_height,
        originals[1].request.selection_context.tip_height
    );
    for audit in &claim.consumed {
        assert_eq!(
            audit.digest().unwrap(),
            wholepact_core::proposal::canonical_digest(
                "wholepact:roster-construction-consumed-native-evidence:v3",
                audit
            )
            .unwrap()
        );
    }
    let mut changed = serde_json::to_value(&claim).unwrap();
    changed["version"] = 2.into();
    assert!(
        strict::<ManualRosterConstructionClaimV3>(&changed)
            .unwrap()
            .validate()
            .is_err()
    );
    let mut changed = serde_json::to_value(&claim).unwrap();
    changed["consumed"][0]["request"]["plan"]["originals"][0]["authority"] = true.into();
    assert!(strict::<ManualRosterConstructionClaimV3>(&changed).is_err());
    assert!(validate_construction_set(&[], &[(receipt.claim_digest.clone(), receipt)]).is_err());
}

#[test]
fn encrypted_common_context_v3_mixed_backup_reopen_preserves_complete_history() {
    assert_encrypted_claim_backup_preserves_complete_history(false);
}

#[test]
fn encrypted_reentry_v4_mixed_backup_reopen_preserves_complete_history() {
    assert_encrypted_claim_backup_preserves_complete_history(true);
}

fn assert_encrypted_claim_backup_preserves_complete_history(reentered: bool) {
    for with_checkpoint in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let source_key = DatabaseKey::from_bytes([0x81; 32]);
        let archive_key = DatabaseKey::from_bytes([0x82; 32]);
        let restored_key = DatabaseKey::from_bytes([0x83; 32]);
        let source_path = directory.path().join("source.sqlite");
        let archive_path = directory.path().join("archive.sqlite");
        let restored_path = directory.path().join("restored.sqlite");
        let source = Store::create_encrypted(&source_path, &source_key).unwrap();
        let root = append_modeled_construction_root(&source);
        let (v2, v2_receipt) = append_modeled_construction_rows(&source, &root, !with_checkpoint);
        let original_v2 = exact_manual_rows(&source);
        let (v3, v3_receipt) =
            append_modeled_common_context_rows(&source, &root, with_checkpoint, reentered);
        assert_eq!(v3.version, if reentered { 4 } else { 3 });
        let exact = exact_manual_rows(&source);
        assert!(original_v2.iter().all(|row| exact.contains(row)));
        assert_eq!(
            source
                .list_records(ADDITIONAL_PUBLICATION_V3)
                .unwrap()
                .len(),
            4
        );
        assert_eq!(source.list_records(CONTINUATION_V4).unwrap().len(), 8);
        source
            .backup_agreement_journal(&archive_path, &archive_key)
            .unwrap();
        let archive_before = std::fs::read(&archive_path).unwrap();
        let (restored, report) = crate::backup::restore_agreement_journal(
            &archive_path,
            &archive_key,
            &restored_path,
            &restored_key,
        )
        .unwrap();
        assert!(report.recovery_required && !report.authorization_allowed);
        assert_eq!(exact_manual_rows(&restored), exact);
        drop(restored);
        let restored = Store::open_encrypted(&restored_path, &restored_key).unwrap();
        assert_eq!(exact_manual_rows(&restored), exact);
        assert!(
            restored
                .manual_roster_construction_evidence_v2(&v2.principal_id, &v2.construction_key)
                .unwrap()
                .unwrap()
                == (v2.clone(), v2_receipt)
        );
        assert!(
            restored
                .manual_roster_construction_evidence_v3(&v3.principal_id, &v3.construction_key)
                .unwrap()
                .unwrap()
                == (v3.clone(), v3_receipt)
        );
        assert!(
            restored
                .require_unused_common_context_invocation(
                    &v3.principal_id,
                    &v3.construction_key,
                    v3.invocation()
                )
                .is_err()
        );
        assert!(restored.manual_store_target().is_err());
        let rebackup_path = directory.path().join("rebackup.sqlite");
        restored
            .backup_agreement_journal(&rebackup_path, &archive_key)
            .unwrap();
        let (twice, _) = crate::backup::restore_agreement_journal(
            &rebackup_path,
            &archive_key,
            directory.path().join("twice.sqlite"),
            &source_key,
        )
        .unwrap();
        assert_eq!(exact_manual_rows(&twice), exact);
        assert_eq!(std::fs::read(&archive_path).unwrap(), archive_before);
        assert_eq!(exact_manual_rows(&source), exact);
    }
}

fn replace_string(value: &mut serde_json::Value, from: &str, to: &str) {
    match value {
        serde_json::Value::String(s) if s == from => *s = to.into(),
        serde_json::Value::Array(values) => {
            for v in values {
                replace_string(v, from, to);
            }
        }
        serde_json::Value::Object(values) => {
            for v in values.values_mut() {
                replace_string(v, from, to);
            }
        }
        _ => {}
    }
}

fn refresh_policy_commitments(original: &mut ManualRosterOriginalRetentionV3) {
    let selection = &mut original.request.selection.scope.selection;
    let policy = &selection.inventory.original_recipient_policy;
    let enrollment = &mut selection.inventory.enrollment;
    enrollment.original_policy_digest = policy.digest().unwrap();
    enrollment.scope.recipient_scope_digests = vec![policy.digest().unwrap()];
    let origin = &mut selection.original_policy_origin;
    origin.recipient_policy = policy.clone();
    origin.intent.original_policy_terms.recipient_scope_digests = vec![policy.digest().unwrap()];
    origin.intent.original_policy_terms_digest =
        origin.intent.original_policy_terms.digest().unwrap();
    origin.birth_digest = wholepact_core::proposal::canonical_digest(
        "wholepact:native-account-birth-intent:v2",
        &(&origin.intent, &origin.recipient_policy),
    )
    .unwrap();
    enrollment.native_birth_digest = origin.birth_digest.clone();
}

#[test]
fn common_context_v3_union_shares_keys_invocations_nonces_consumes_and_input_fences() {
    use crate::manual_enrollment::construction_claim_union::validate_union;
    let v2 = modeled_claim_v2();
    let baseline = seed_claim();
    let old = vec![(v2.digest().unwrap(), v2.clone())];
    let union = |v3: &ManualRosterConstructionClaimV3| {
        v3.validate().unwrap();
        validate_union(&old, &[(v3.digest().unwrap(), v3.clone())])
    };
    union(&baseline).unwrap();
    // A key string alone is not the identity; the canonical principal+key is.
    let mut different_principal = baseline.clone();
    different_principal.construction_key = v2.construction_key.clone();
    rebuild(&mut different_principal);
    union(&different_principal).unwrap();
    // Likewise input identifiers are scoped to their canonical account.
    let mut different_account = baseline.clone();
    let old_input = v2.consumed[0].request.plan.selected_inputs()[0]
        .input_id
        .clone();
    different_account.consumed[0].request.plan.originals[0]
        .request
        .selected_inputs[0]
        .input_id = old_input.clone();
    different_account.consumed[0]
        .request
        .plan
        .proposal
        .manifest
        .inputs[0]
        .input_id = old_input;
    rebuild(&mut different_account);
    union(&different_account).unwrap();
    for collision in [
        "principal-key",
        "invocation",
        "nonce",
        "consume",
        "nullifier",
        "account-input",
        "request-operation",
        "invocation-to-request",
        "request-to-invocation",
    ] {
        let mut v3 = baseline.clone();
        match collision {
            "principal-key" => {
                v3.principal_id = v2.principal_id.clone();
                v3.construction_key = v2.construction_key.clone();
                for original in &mut v3.consumed[0].request.plan.originals {
                    original
                        .request
                        .selection
                        .scope
                        .selection
                        .inventory
                        .enrollment
                        .scope
                        .principal_id = v2.principal_id.clone();
                    original
                        .request
                        .selection
                        .scope
                        .selection
                        .original_policy_origin
                        .intent
                        .native_principal_id = v2.principal_id.clone();
                    refresh_policy_commitments(original);
                }
            }
            "invocation" | "nonce" | "invocation-to-request" => {
                for original in &mut v3.consumed[0].request.plan.originals {
                    let invocation = &mut original.request.selection.scope.selection.invocation;
                    if collision == "nonce" {
                        invocation.invocation_nonce = v2.invocation().invocation_nonce.clone();
                    } else if collision == "invocation" {
                        invocation.operation_id = v2.invocation().operation_id.clone();
                    } else {
                        invocation.operation_id = v2.consumed[0].request.operation_id.clone();
                    }
                }
            }
            "consume" => {
                v3.consumed[0].witness_consumed_digest =
                    v2.consumed[0].witness_consumed_digest.clone()
            }
            "nullifier" => {
                v3.consumed[0].request.plan.originals[0]
                    .request
                    .selected_inputs[0]
                    .nullifier = v2.consumed[0].request.plan.selected_inputs()[0]
                    .nullifier
                    .clone()
            }
            "account-input" => {
                v3 = different_account.clone();
                let mut plan = serde_json::to_value(&v3.consumed[0].request.plan).unwrap();
                replace_string(
                    &mut plan,
                    &baseline.consumed[0]
                        .request
                        .plan
                        .enrollment()
                        .identity
                        .account_id,
                    &v2.consumed[0].request.plan.enrollment().identity.account_id,
                );
                v3.consumed[0].request.plan = serde_json::from_value(plan).unwrap();
                for original in &mut v3.consumed[0].request.plan.originals {
                    refresh_policy_commitments(original);
                }
            }
            "request-operation" => {
                v3.consumed[0].request.operation_id = v2.consumed[0].request.operation_id.clone()
            }
            "request-to-invocation" => {
                v3.consumed[0].request.operation_id = v2.invocation().operation_id.clone()
            }
            _ => unreachable!(),
        }
        rebuild(&mut v3);
        assert!(union(&v3).is_err(), "missing shared fence: {collision}");
        // Validate each version separately before combining. Both traversal
        // directions are restrictions over originals, not conversion/reissue.
        super::super::construction_claim_v2::validate_construction_set(&old, &[]).unwrap();
        validate_construction_set(&[(v3.digest().unwrap(), v3.clone())], &[]).unwrap();
        assert!(validate_union(&old, &[(v3.digest().unwrap(), v3)]).is_err());
    }
}

#[test]
fn encrypted_common_context_v3_shared_corruption_blocks_both_readers_and_backup() {
    for collision in [
        "invocation",
        "nonce",
        "request-operation",
        "consume",
        "nullifier",
    ] {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let key = DatabaseKey::from_bytes([0x84; 32]);
        let store = Store::create_encrypted(directory.path().join("source.sqlite"), &key).unwrap();
        let root = append_modeled_construction_root(&store);
        let (v2, _) = append_modeled_construction_rows(&store, &root, false);
        let (mut v3, _) = append_modeled_construction_rows_v3(&store, &root, false);
        let original_digest = v3.digest().unwrap();
        match collision {
            "invocation" | "nonce" => {
                for original in &mut v3.consumed[0].request.plan.originals {
                    let invocation = &mut original.request.selection.scope.selection.invocation;
                    if collision == "invocation" {
                        invocation.operation_id = v2.invocation().operation_id.clone();
                    } else {
                        invocation.invocation_nonce = v2.invocation().invocation_nonce.clone();
                    }
                }
            }
            "request-operation" => {
                v3.consumed[0].request.operation_id = v2.consumed[0].request.operation_id.clone()
            }
            "consume" => {
                v3.consumed[0].witness_consumed_digest =
                    v2.consumed[0].witness_consumed_digest.clone()
            }
            "nullifier" => {
                v3.consumed[0].request.plan.originals[0]
                    .request
                    .selected_inputs[0]
                    .nullifier = v2.consumed[0].request.plan.selected_inputs()[0]
                    .nullifier
                    .clone()
            }
            _ => unreachable!(),
        }
        rebuild(&mut v3);
        let connection = store.connection.lock().unwrap();
        // Deliberately corrupt an otherwise fully related historical record.
        // Each per-version reader still validates, proving the union catches it.
        connection
            .execute(
                "DELETE FROM records WHERE aggregate_type=?1 AND id=?2",
                rusqlite::params![CONSTRUCTION_CLAIM_V3, original_digest],
            )
            .unwrap();
        put(
            &connection,
            CONSTRUCTION_CLAIM_V3,
            &v3.digest().unwrap(),
            &v3,
        );
        super::super::construction_claim_v2::read_local_rows(&connection).unwrap();
        read_local_rows(&connection).unwrap();
        drop(connection);
        let before = exact_manual_rows(&store);
        assert!(
            store
                .manual_roster_construction_evidence_v2(&v2.principal_id, &v2.construction_key)
                .is_err(),
            "{collision}"
        );
        assert!(
            store
                .manual_roster_construction_evidence_v3(&v3.principal_id, &v3.construction_key)
                .is_err(),
            "{collision}"
        );
        assert!(
            store
                .backup_agreement_journal(directory.path().join("denied.sqlite"), &key)
                .is_err(),
            "{collision}"
        );
        assert_eq!(exact_manual_rows(&store), before);
    }
}

#[test]
fn common_context_v3_generic_commands_effects_and_preapproval_cannot_reuse_history() {
    let store = Store::in_memory().unwrap();
    let root = append_modeled_construction_root(&store);
    let (claim, _) = append_modeled_construction_rows_v3(&store, &root, false);
    let before = exact_manual_rows(&store);
    let context = crate::CommandContext::for_request(
        &claim.principal_id,
        &claim.construction_key,
        &serde_json::json!({}),
    )
    .unwrap();
    assert!(matches!(
        store.create_agreement(&context, "unrelated", serde_json::json!({})),
        Err(StoreError::IdempotencyConflict)
    ));
    for operation in std::iter::once(claim.invocation().operation_id.as_str()).chain(
        claim
            .consumed
            .iter()
            .map(|a| a.request.operation_id.as_str()),
    ) {
        assert!(matches!(
            store.record_effect_intent(
                operation,
                "send",
                "unrelated",
                &h("effect"),
                "retained:synthetic"
            ),
            Err(StoreError::IdempotencyConflict)
        ));
    }
    assert!(
        store
            .require_unused_common_context_invocation(
                &claim.principal_id,
                &claim.construction_key,
                claim.invocation()
            )
            .is_err()
    );
    assert_eq!(exact_manual_rows(&store), before);
    let receipt = checkpoint(&claim);
    for (kind, id, payload) in [
        (
            CONSTRUCTION_CLAIM_V3,
            claim.digest().unwrap(),
            serde_json::to_value(&claim).unwrap(),
        ),
        (
            CONSTRUCTION_CHECKPOINT_V3,
            receipt.claim_digest.clone(),
            serde_json::to_value(&receipt).unwrap(),
        ),
    ] {
        let other = crate::CommandContext::for_request(
            "synthetic-generic",
            "other-key",
            &serde_json::json!({}),
        )
        .unwrap();
        assert!(
            store
                .commit_record(&other, kind, &id, None, payload, "created")
                .is_err()
        );
    }
}

#[test]
fn common_context_v3_unused_preflight_rejects_unknown_history_generic_occupancy_and_contention() {
    let claim = seed_claim();
    for occupancy in [
        "unknown-version",
        "generic-key",
        "generic-operation",
        "mutex",
    ] {
        let store = Store::in_memory().unwrap();
        store
            .require_unused_common_context_invocation(
                &claim.principal_id,
                &claim.construction_key,
                claim.invocation(),
            )
            .unwrap();
        match occupancy {
            "unknown-version" => {
                put(
                    &store.connection.lock().unwrap(),
                    "generation_manual_construction_claim_v99",
                    "synthetic-unknown",
                    &serde_json::json!({}),
                );
            }
            "generic-key" => {
                let context = crate::CommandContext::for_request(
                    &claim.principal_id,
                    &claim.construction_key,
                    &serde_json::json!({}),
                )
                .unwrap();
                store
                    .create_agreement(&context, "synthetic-generic", serde_json::json!({}))
                    .unwrap();
            }
            "generic-operation" => {
                store
                    .record_effect_intent(
                        &claim.invocation().operation_id,
                        "send",
                        "synthetic-resource",
                        &h("effect"),
                        "retained:synthetic",
                    )
                    .unwrap();
            }
            "mutex" => {
                let _held = store.connection.lock().unwrap();
                assert!(matches!(
                    store.require_unused_common_context_invocation(
                        &claim.principal_id,
                        &claim.construction_key,
                        claim.invocation()
                    ),
                    Err(StoreError::ResourceExhausted)
                ));
                continue;
            }
            _ => unreachable!(),
        }
        assert!(
            store
                .require_unused_common_context_invocation(
                    &claim.principal_id,
                    &claim.construction_key,
                    claim.invocation()
                )
                .is_err(),
            "{occupancy}"
        );
    }
}

#[test]
fn common_context_v3_missing_original_root_selection_or_current_attempt_fails_closed() {
    for missing in [
        "root",
        "addition",
        "selection",
        "construction",
        "checkpoint-claim",
    ] {
        let store = Store::in_memory().unwrap();
        let root = append_modeled_construction_root(&store);
        let (claim, _) = append_modeled_construction_rows_v3(&store, &root, true);
        let connection = store.connection.lock().unwrap();
        match missing {
            "root" => {
                connection
                    .execute(
                        "DELETE FROM records WHERE aggregate_type=?1",
                        [INITIAL_PUBLICATION_V2],
                    )
                    .unwrap();
            }
            "addition" => {
                connection
                    .execute(
                        "DELETE FROM records WHERE aggregate_type=?1 AND id=?2",
                        rusqlite::params![
                            ADDITIONAL_PUBLICATION_V3,
                            claim.consumed[0]
                                .request
                                .plan
                                .retained
                                .selection
                                .scope
                                .provenance
                                .original_host_audit
                                .audit_digest()
                        ],
                    )
                    .unwrap();
            }
            "checkpoint-claim" => {
                connection
                    .execute(
                        "DELETE FROM records WHERE aggregate_type=?1",
                        [CONSTRUCTION_CLAIM_V3],
                    )
                    .unwrap();
            }
            "selection" | "construction" => {
                let sequence = if missing == "selection" { 2 } else { 3 };
                let rows = read_audits::<ManualEnrollmentContinuationAuditV4>(
                    &connection,
                    CONTINUATION_V4,
                )
                .unwrap();
                let (id, _) = rows
                    .iter()
                    .find(|(_, a)| a.evidence.admission.attempt_sequence == sequence)
                    .unwrap();
                connection
                    .execute(
                        "DELETE FROM records WHERE aggregate_type=?1 AND id=?2",
                        rusqlite::params![CONTINUATION_V4, id],
                    )
                    .unwrap();
            }
            _ => unreachable!(),
        }
        drop(connection);
        assert!(
            store
                .manual_roster_construction_evidence_v3(
                    &claim.principal_id,
                    &claim.construction_key
                )
                .is_err(),
            "{missing}"
        );
        assert!(
            store.list_records(CONSTRUCTION_CLAIM_V3).is_err(),
            "{missing}"
        );
    }
}

#[test]
fn common_context_v3_incomplete_consumed_roster_or_changed_checkpoint_never_confirms_result() {
    let claim = seed_claim();
    for mutation in [
        "missing-owner",
        "missing-original",
        "substituted-original",
        "reused-consume",
        "expired-session",
    ] {
        let mut changed = claim.clone();
        match mutation {
            "missing-owner" => {
                changed.consumed.pop();
            }
            "missing-original" => {
                changed.consumed[0].request.plan.originals.pop();
            }
            "substituted-original" => {
                changed.consumed[0].request.plan.originals[0]
                    .request
                    .selection_context
                    .tip_hash_protocol = h("substituted-tip");
            }
            "reused-consume" => {
                changed.consumed[1].witness_consumed_digest =
                    changed.consumed[0].witness_consumed_digest.clone();
            }
            "expired-session" => {
                changed.consumed[0].writer_session_expires_at_ms =
                    changed.consumed[0].consumed_at_ms;
            }
            _ => unreachable!(),
        }
        assert!(changed.validate().is_err(), "{mutation}");
    }
    let receipt = checkpoint(&claim);
    for field in 0..8 {
        let mut changed = receipt.clone();
        match field {
            0 => changed.claim_digest = h("other-claim"),
            1 => changed.job_id = "proof-unrelated".into(),
            2 => changed.scope.coordination_request_digest = h("other-command"),
            3 => changed.scope.candidate_id = "other-candidate".into(),
            4 => changed.scope.manifest_digest = h("other-manifest"),
            5 => {
                changed.scope.account_ids.pop();
            }
            6 => changed.scope.purpose = "prove_locally".into(),
            _ => changed.scope.retention_policy.push('x'),
        }
        assert!(
            changed.validate_for(&claim).is_err(),
            "checkpoint binding {field}"
        );
    }
}

#[test]
fn common_context_v3_preapproval_rejects_manual_key_and_operation_occupancy() {
    let claim = seed_claim();
    for occupied in ["manual-key", "manual-operation"] {
        let store = Store::in_memory().unwrap();
        let mut root = crate::manual_enrollment::tests::initial_publication::initial_fixture();
        let mut invocation = claim.invocation().clone();
        if occupied == "manual-key" {
            root.request_identity_digest = claim.request_identity().unwrap();
        } else {
            invocation.operation_id = root.operation_id.clone();
        }
        root.validate().unwrap();
        invocation.validate().unwrap();
        put(
            &store.connection.lock().unwrap(),
            INITIAL_PUBLICATION_V2,
            &root.digest().unwrap(),
            &root,
        );
        super::super::construction_claim_union::validate_current(&store.connection.lock().unwrap())
            .unwrap();
        let before = exact_manual_rows(&store);
        assert!(
            matches!(
                store.require_unused_common_context_invocation(
                    &claim.principal_id,
                    &claim.construction_key,
                    &invocation
                ),
                Err(StoreError::IdempotencyConflict)
            ),
            "{occupied}"
        );
        assert_eq!(exact_manual_rows(&store), before);
    }
}

#[test]
fn common_context_v3_preapproval_rejects_inherited_idempotency_and_effect_fences() {
    let claim = seed_claim();
    for kind in ["idempotency", "operation", "effect"] {
        // Private restriction-unit fixture, not a recovered-generation opener
        // or current native owner. Exercise the same retained fence query used
        // by final claim and prove preflight itself cannot modify any rows.
        let mut store = Store::in_memory().unwrap();
        store.recovered_generation = true;
        store
            .connection
            .lock()
            .unwrap()
            .execute_batch(include_str!("../recovery-schema.sql"))
            .unwrap();
        store
            .require_unused_common_context_invocation(
                &claim.principal_id,
                &claim.construction_key,
                claim.invocation(),
            )
            .unwrap();
        let identity = if kind == "idempotency" {
            claim.request_identity().unwrap()
        } else {
            claim.invocation().operation_id.clone()
        };
        store
            .connection
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO store_generation_fences VALUES(?1,?2,?3)",
                rusqlite::params![kind, identity, "synthetic-retained-fence"],
            )
            .unwrap();
        let before = exact_manual_rows(&store);
        assert!(
            matches!(
                store.require_unused_common_context_invocation(
                    &claim.principal_id,
                    &claim.construction_key,
                    claim.invocation()
                ),
                Err(StoreError::RecoveryRequired)
            ),
            "{kind}"
        );
        assert_eq!(exact_manual_rows(&store), before);
        let retained: (String, String, String) = store
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT kind,identity,detail FROM store_generation_fences",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            retained,
            (kind.into(), identity, "synthetic-retained-fence".into())
        );
    }
}

/// New independently modeled historical encoding, never a live owner and never
/// a rewrite of an existing version-3 row. No cryptography or network is used.
fn seed_reentered_claim_v4() -> ManualRosterConstructionClaimV3 {
    let mut claim = seed_claim();
    model_reentry_lineages(&mut claim);
    claim
}

fn model_reentry_lineages(claim: &mut ManualRosterConstructionClaimV3) {
    use wholepact_core::common_context_reentry_v1::{
        CommonContextReentryPurposeV1, RosterCommonContextReentryLineageV1,
        RosterCommonContextReentryRequestV1,
    };
    use wholepact_core::manual_roster_construction_v3::{
        CommonContextReadProfileV1, CommonContextReadPurposeV1, RosterCommonContextReadRequestV1,
    };
    assert_eq!(claim.version, 3);
    assert!(claim.reentry_lineages.is_none());
    claim.version = 4;
    let lineages = claim
        .consumed
        .iter()
        .enumerate()
        .map(|(i, consumed)| {
            let read = RosterCommonContextReadRequestV1 {
                version: 1,
                operation_id: format!("synthetic-original-read-{i}"),
                plan: consumed.request.plan.clone(),
                original_durable_receipt_digest: h(&format!("original-receipt-{i}")),
                witness_plan_approval_digest: consumed.witness_plan_approval_digest.clone(),
                purpose: CommonContextReadPurposeV1::RevalidateExactRetainedNotesAndCommonContext,
                profile: CommonContextReadProfileV1::for_plan(&consumed.request.plan).unwrap(),
                current_caller_binding_digest: h(&format!("original-caller-{i}")),
                requested_at_ms: 2001,
                admission_expires_at_ms: 2500,
                completion_expires_at_ms: 32_000,
            };
            let request = RosterCommonContextReentryRequestV1 {
                version: 1,
                operation_id: format!("synthetic-reentry-{i}"),
                original_read: read,
                original_read_admission_digest: consumed
                    .common_context_read_admission_digest
                    .clone(),
                pending_grant_digest: h(&format!("pending-grant-{i}")),
                original_attempt_digest: consumed.current_attempt_digest.clone(),
                original_attempt_sequence: consumed.current_attempt_sequence,
                current_caller_binding_digest: consumed
                    .request
                    .current_caller_binding_digest
                    .clone(),
                current_attempt_digest: consumed.current_attempt_digest.clone(),
                current_attempt_sequence: consumed.current_attempt_sequence,
                purpose: CommonContextReentryPurposeV1::ResumeAlreadyAdmittedConstructionOnly,
                requested_at_ms: 2001,
                admission_expires_at_ms: 32_000,
            };
            RosterCommonContextReentryLineageV1 {
                version: 1,
                request,
                retained_signer_intent_digest: consumed.retained_signer_intent_digest.clone(),
                original_native_binding_digest: h(&format!("old-native-{i}")),
                current_native_binding_digest: h(&format!("new-native-{i}")),
                original_host_process_digest: h("original-host-process"),
                original_record_digest: h(&format!("original-record-{i}")),
                original_genesis_digest: h(&format!("original-genesis-{i}")),
                original_birth_digest: h(&format!("original-birth-{i}")),
                current_witness_history_digest: h(&format!("current-history-{i}")),
                current_witness_continuation_digest: consumed.current_attempt_digest.clone(),
                current_writer_session_digest: h(&format!("original-session-{i}")),
                construction_transport_credential_digest: h(&format!("credential-digest-{i}")),
                construction_transport_credential_id: h(&format!("credential-id-{i}")),
                original_transport_fence_digest: h(&format!("old-key-fence-{i}")),
                current_writer_session_expires_at_ms: consumed.writer_session_expires_at_ms,
                native_review_digest: h(&format!("reentry-review-{i}")),
                admitted_at_ms: 2002,
                completion_expires_at_ms: 32_000,
            }
        })
        .collect();
    claim.reentry_lineages = Some(lineages);
    claim.validate().unwrap();
}
#[test]
fn reentry_v4_claim_requires_exact_full_lineage_without_changing_v3_bytes() {
    let old = seed_claim();
    let old_bytes = serde_json::to_vec(&old).unwrap();
    assert!(
        !serde_json::to_value(&old)
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("reentry_lineages")
    );
    let claim = seed_reentered_claim_v4();
    assert!(old.consumed == claim.consumed);
    assert_ne!(old.digest().unwrap(), claim.digest().unwrap());
    assert_ne!(
        old.request_digest().unwrap(),
        claim.request_digest().unwrap()
    );
    assert_eq!(serde_json::to_vec(&old).unwrap(), old_bytes);
    let mut noncanonical_old = serde_json::to_value(&old).unwrap();
    noncanonical_old["reentry_lineages"] = serde_json::Value::Null;
    assert!(strict::<ManualRosterConstructionClaimV3>(&noncanonical_old).is_err());
    assert!(serde_json::to_vec(&claim).unwrap().len() <= crate::MAX_JSON_BYTES);
    for mutation in 0..13 {
        let mut bad = claim.clone();
        match mutation {
            0 => bad.reentry_lineages = None,
            1 => bad.version = 3,
            2 => {
                bad.reentry_lineages.as_mut().unwrap().pop();
            }
            3 => {
                bad.reentry_lineages.as_mut().unwrap()[0]
                    .request
                    .current_caller_binding_digest = h("wrong-caller")
            }
            4 => bad.reentry_lineages.as_mut().unwrap()[0]
                .construction_transport_credential_digest
                .clear(),
            5 => bad.reentry_lineages.as_mut().unwrap().swap(0, 1),
            6 => {
                bad.reentry_lineages.as_mut().unwrap()[0].completion_expires_at_ms =
                    bad.consumed[0].consumed_at_ms
            }
            7 => bad.consumed[0].request.admission_expires_at_ms += 1,
            8 => bad.consumed[0].common_context_read_admission_digest = h("wrong-read"),
            9 => {
                bad.reentry_lineages.as_mut().unwrap()[0].current_writer_session_expires_at_ms += 1
            }
            10 => {
                bad.reentry_lineages.as_mut().unwrap()[0].native_review_digest =
                    bad.consumed[0].native_review_digest.clone()
            }
            11 => bad.reentry_lineages.as_mut().unwrap().clear(),
            _ => {
                bad.reentry_lineages.as_mut().unwrap()[0]
                    .request
                    .original_read
                    .witness_plan_approval_digest = h("wrong-plan-approval")
            }
        }
        assert!(bad.validate().is_err());
    }
}
#[test]
fn reentry_v4_claim_shares_original_invocation_and_input_fences() {
    let old = seed_claim();
    let new = seed_reentered_claim_v4();
    assert_eq!(
        old.request_identity().unwrap(),
        new.request_identity().unwrap()
    );
    assert!(
        validate_construction_set(
            &[(old.digest().unwrap(), old), (new.digest().unwrap(), new)],
            &[]
        )
        .is_err()
    );
}
#[test]
fn reentry_v4_rows_are_rejected_under_old_encoding_markers() {
    let store = Store::in_memory().unwrap();
    let claim = seed_reentered_claim_v4();
    let connection = store.connection.lock().unwrap();
    put(
        &connection,
        CONSTRUCTION_CLAIM_V3,
        &claim.digest().unwrap(),
        &claim,
    );
    assert!(crate::backup::validate_construction_encoding(&connection, true, false).is_err());
    for version in [2, 3, 4, 5] {
        connection.pragma_update(None, "application_id", wholepact_storage_security::bundle::recovery::generation::RECOVERED_GENERATION_APPLICATION_ID).unwrap();
        connection
            .pragma_update(None, "user_version", version)
            .unwrap();
        assert!(crate::backup::require_construction_v4_encoding(&connection).is_err());
    }
}

#[test]
fn encrypted_reentry_v4_migration_preserves_v3_bytes_and_rejects_marker_laundering() {
    for reentered in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let key = DatabaseKey::from_bytes([0x84; 32]);
        let path = directory.path().join("synthetic-migration.sqlite");
        let source = Store::create_encrypted(&path, &key).unwrap();
        let root = append_modeled_construction_root(&source);
        let (claim, receipt) = append_modeled_common_context_rows(&source, &root, true, reentered);
        let original = exact_manual_rows(&source);
        {
            let c = source.connection.lock().unwrap();
            // Explicit malformed-source test when reentered=true. A supported
            // opener must inspect the ORIGINAL marker before promoting it.
            c.pragma_update(None, "user_version", 3).unwrap();
        }
        drop(source);
        let opened = Store::open_encrypted(&path, &key);
        if reentered {
            assert!(opened.is_err());
            let snapshot =
                wholepact_storage_security::open_encrypted_read_snapshot(&path, &key).unwrap();
            let c = snapshot.connection();
            assert_eq!(
                c.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                    .unwrap(),
                3
            );
            let saved: String = c
                .query_row(
                    "SELECT payload FROM records WHERE aggregate_type=?1 AND id=?2",
                    rusqlite::params![CONSTRUCTION_CLAIM_V3, claim.digest().unwrap()],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(saved, serde_json::to_string(&claim).unwrap());
        } else {
            let opened = opened.unwrap();
            assert_eq!(exact_manual_rows(&opened), original);
            assert_eq!(
                opened
                    .connection
                    .lock()
                    .unwrap()
                    .pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                    .unwrap(),
                4
            );
            assert!(
                opened
                    .manual_roster_construction_evidence_v3(
                        &claim.principal_id,
                        &claim.construction_key,
                    )
                    .unwrap()
                    .unwrap()
                    == (claim, receipt)
            );
        }
    }
}
