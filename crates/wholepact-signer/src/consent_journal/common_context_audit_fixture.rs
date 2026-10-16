// Shared test-only inert audit model built around genuine signed authority replay.
// Never calls a native issuer, provider, socket, wallet, proof or financial client.
use super::signer;
use signer::authority_bridge::host_recovery_ipc::{
    v2::{AccountUseHistoryV2, HostRecoveryHistoryV2},
    v4::{
        HostRecoveryContinuityEvidenceV4, HostRecoveryContinuityRequestV4, HostRecoveryHistoryV4,
    },
};
use signer::consent_journal::{
    CommonContextSignerAuditInventoryV1 as Inventory, CommonContextSignerAuditV1 as Row,
};
use wholepact_authority::{
    ConstructionApprovalHistoryV2, ConstructionHistoryV2, ConstructionOriginHistoryV2,
};
use wholepact_core::manual_roster_construction_v3::{
    CommonContextReadProfileV1, CommonContextReadPurposeV1, RosterCommonContextReadRequestV1,
};
use wholepact_signer_origin::{
    manual_roster_construction_v2::ManualRosterContributionRetentionEvidenceV2,
    manual_roster_construction_v3::ManualRosterConstructionContributionEvidenceV3,
    roster_common_context_read_v1::RosterCommonContextReadEvidenceV1,
};

pub fn fixture() -> (Inventory, HostRecoveryContinuityEvidenceV4) {
    let raw: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/common-context-authority-audit.synthetic.json"
    ))
    .unwrap();
    assert_eq!(raw["native_actors_exercised"], false);
    assert_eq!(
        raw["signer_read_or_construction_admission_exercised"],
        false
    );
    let history: ConstructionHistoryV2 =
        serde_json::from_value(raw["complete_history"].clone()).unwrap();
    let pre: ConstructionHistoryV2 =
        serde_json::from_value(raw["pre_reserve_history"].clone()).unwrap();
    history.validate().unwrap();
    pre.validate().unwrap();
    let ConstructionOriginHistoryV2::CommonContextV3 { origin } = &history.origins()[0] else {
        panic!("exact V3 origin required")
    };
    let r = origin.reservation();
    let c = origin.consumed().unwrap();
    let plan = &r.request.construction.plan;
    let original: ManualRosterContributionRetentionEvidenceV2 =
        serde_json::from_value(raw["modeled_retention_evidence"][0].clone()).unwrap();
    original.validate().unwrap();
    assert_eq!(original.digest().unwrap(), plan.retained_evidence_digest);
    let ConstructionApprovalHistoryV2::CommonContextV3 { extension, record } = &pre.approvals()[0]
    else {
        panic!("exact signed V3 approval required")
    };
    let approval_digest = record.approval.digest_for(extension).unwrap();
    let read = RosterCommonContextReadEvidenceV1 {
        version: 1,
        request: RosterCommonContextReadRequestV1 {
            version: 1,
            operation_id: "modeled-only-common-context-read".into(),
            plan: plan.clone(),
            original_durable_receipt_digest: "ab".repeat(32),
            witness_plan_approval_digest: approval_digest.clone(),
            purpose: CommonContextReadPurposeV1::RevalidateExactRetainedNotesAndCommonContext,
            profile: CommonContextReadProfileV1::for_plan(plan).unwrap(),
            current_caller_binding_digest: r
                .request
                .construction
                .current_caller_binding_digest
                .clone(),
            requested_at_ms: plan.completion_expires_at_ms() - 20_000,
            admission_expires_at_ms: r.admitted_at_ms,
            completion_expires_at_ms: plan.completion_expires_at_ms(),
        },
        retained_signer_intent_digest: r.request.signer_intent_digest.clone(),
        current_attempt_digest: r.request.attempt_digest.clone(),
        current_attempt_sequence: r.request.attempt_sequence,
        native_review_digest: "de".repeat(32),
        admitted_at_ms: r.admitted_at_ms - 1,
        writer_session_expires_at_ms: r.session.expires_at_ms,
    };
    read.validate().unwrap();
    let evidence = ManualRosterConstructionContributionEvidenceV3 {
        version: 3,
        request: r.request.construction.clone(),
        retained_signer_intent_digest: r.request.signer_intent_digest.clone(),
        current_attempt_digest: r.request.attempt_digest.clone(),
        current_attempt_sequence: r.request.attempt_sequence,
        native_review_digest: r.request.native_review_digest.clone(),
        common_context_read_admission_digest: read.digest().unwrap(),
        witness_plan_approval_digest: approval_digest,
        witness_reservation_digest: r
            .digest_for(origin.extension(), origin.continuation())
            .unwrap(),
        witness_consumed_digest: c
            .digest_for(r, origin.extension(), origin.continuation())
            .unwrap(),
        reviewed_at_ms: r.request.reviewed_at_ms,
        reserved_at_ms: r.admitted_at_ms,
        consumed_at_ms: c.consumed_at_ms,
        reserved_debit_zatoshis: r.reserved_debit_zatoshis,
        reserved_input_value_zatoshis: r.reserved_input_value_zatoshis,
        writer_session_expires_at_ms: r.session.expires_at_ms,
    };
    evidence.validate().unwrap();
    let mut rows = vec![
        Row::ReadAdmitted {
            version: 1,
            original: Box::new(original),
            evidence: Box::new(read.clone()),
            witness_history: Box::new(pre),
        },
        Row::Reserved {
            version: 1,
            read_admission_digest: read.digest().unwrap(),
            extension: Box::new(origin.extension().clone()),
            continuation: Box::new(origin.continuation().clone()),
            record: Box::new(r.clone()),
        },
        Row::Consumed {
            version: 1,
            extension: Box::new(origin.extension().clone()),
            continuation: Box::new(origin.continuation().clone()),
            reservation: Box::new(r.clone()),
            consumed: Box::new(c.clone()),
            evidence: Box::new(evidence),
        },
    ];
    rows.sort_by_key(|r| (r.invocation_digest().unwrap(), r.phase()));
    let inventory = Inventory { version: 1, rows };
    inventory.validate_against(&history).unwrap();
    let birth = history.original_birth().unwrap().clone();
    let snapshot = history.observed_snapshot();
    let active = snapshot.active_writer_session.as_ref().unwrap();
    let complete_history = HostRecoveryHistoryV4 {
        schema_version: 4,
        financial_origins_v2: HostRecoveryHistoryV2 {
            schema_version: 2,
            complete_journal_digest: "ef".repeat(32),
            pending_birth_commit: Some(birth.clone()),
            origins: vec![],
            retained_enrollments: vec![],
            retained_reservation_intents: vec![],
            review_receipts: vec![],
            account_use: AccountUseHistoryV2 {
                genesis: birth.request.policy.account_use_genesis.clone(),
                exclusion: None,
                witness_ack: None,
            },
        },
        construction: history.clone(),
        signer_common_context_audit: inventory.clone(),
    };
    let evidence = HostRecoveryContinuityEvidenceV4 {
        request: HostRecoveryContinuityRequestV4 {
            schema_version: 4,
            inventory_digest: "a1".repeat(32),
            generation_id: "a2".repeat(32),
            account_id: snapshot.account_id.clone(),
            network_profile_id: snapshot.network_profile_id.clone(),
            expected_writer_epoch: snapshot.writer_epoch,
            expected_witness: history.witness().clone(),
        },
        writer_certificate_digest: snapshot.writer_certificate_digest.clone(),
        writer_session_id: active.session_id.clone(),
        writer_session_expires_at_ms: active.expires_at_ms,
        head: snapshot.head.clone(),
        history_digest: history.complete_replay_digest().into(),
        complete_history,
    };
    evidence.validate().unwrap();
    (inventory, evidence)
}
