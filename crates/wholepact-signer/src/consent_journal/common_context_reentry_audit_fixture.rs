//! Test-only inert local phases joined to genuine never-funded synthetic
//! authority signatures. No native decision, socket, wallet read or key use.
use super::*;
use crate::authority_bridge::host_recovery_ipc::{
    v2::{AccountUseHistoryV2, HostRecoveryHistoryV2},
    v5::*,
};
use wholepact_authority::construction_transport_handoff_v1::*;
use wholepact_core::common_context_reentry_v1::{
    CommonContextReentryPurposeV1, RosterCommonContextReentryLineageV1,
    RosterCommonContextReentryRequestV1,
};
use wholepact_signer_origin::{
    common_context_reentry_v1::RosterReenteredConstructionEvidenceV1,
    manual_roster_construction_v2::ManualRosterContributionRetentionEvidenceV2,
    manual_roster_construction_v3::ManualRosterConstructionContributionEvidenceV3,
    roster_common_context_read_v1::RosterCommonContextReadEvidenceV1,
};

pub fn fixture() -> HostRecoveryContinuityEvidenceV5 {
    let raw: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/common-context-handoff-audit.synthetic.json"
    ))
    .unwrap();
    assert_eq!(raw["fixture_version"], 1);
    assert_eq!(raw["native_actors_exercised"], false);
    assert_eq!(raw["sockets_or_provider_reads_exercised"], false);
    let before: ConstructionHistoryWithTransportV1 =
        serde_json::from_value(raw["before_grant_history"].clone()).unwrap();
    let claimed: ConstructionHistoryWithTransportV1 =
        serde_json::from_value(raw["claimed_history"].clone()).unwrap();
    let history: ConstructionHistoryWithTransportV1 =
        serde_json::from_value(raw["complete_history"].clone()).unwrap();
    before.validate().unwrap();
    claimed.validate().unwrap();
    history.validate().unwrap();
    let read: RosterCommonContextReadEvidenceV1 =
        serde_json::from_value(raw["modeled_read_evidence"].clone()).unwrap();
    let original: ManualRosterContributionRetentionEvidenceV2 =
        serde_json::from_value(raw["modeled_retention_evidence"][0].clone()).unwrap();
    let credential = history.transport.credentials[0].clone();
    let a = credential.authorization();
    let claim = &credential.signed_claim.claim;
    let grant = &credential.pending_grant;
    let birth = history.original.original_birth().unwrap().clone();
    let reservation = &history.transport.reservations[0];
    let consumed = &history.transport.consumptions[0];
    let r = &reservation.original;
    let c = &consumed.original;
    let lineage = RosterCommonContextReentryLineageV1 {
        version: 1,
        request: RosterCommonContextReentryRequestV1 {
            version: 1,
            operation_id: "modeled-only-signed-handoff-reentry".into(),
            original_read: read.request.clone(),
            original_read_admission_digest: read.digest().unwrap(),
            pending_grant_digest: grant.digest().unwrap(),
            original_attempt_digest: read.current_attempt_digest.clone(),
            original_attempt_sequence: read.current_attempt_sequence,
            current_caller_binding_digest: claim.new_caller_binding_digest.clone(),
            current_attempt_digest: read.current_attempt_digest.clone(),
            current_attempt_sequence: read.current_attempt_sequence,
            purpose: CommonContextReentryPurposeV1::ResumeAlreadyAdmittedConstructionOnly,
            requested_at_ms: grant.grant.granted_at_ms,
            admission_expires_at_ms: a.expires_at_ms,
        },
        retained_signer_intent_digest: read.retained_signer_intent_digest.clone(),
        original_native_binding_digest: a.original_native_binding_digest.clone(),
        current_native_binding_digest: claim.new_native_binding_digest.clone(),
        original_host_process_digest: a.original_host_process_commitment.clone(),
        original_record_digest: read
            .request
            .plan
            .retained
            .selection
            .scope
            .provenance
            .signer_roster_record_digest
            .clone(),
        original_genesis_digest: a.genesis_digest.clone(),
        original_birth_digest: birth.request.native_birth_digest.clone(),
        current_witness_history_digest: claimed.original.complete_replay_digest().into(),
        current_witness_continuation_digest: a.attempt_digest.clone(),
        current_writer_session_digest: wholepact_core::proposal::canonical_digest(
            "wholepact:common-context-reentry-writer-session:v1",
            &a.original_session,
        )
        .unwrap(),
        construction_transport_credential_digest: credential.digest().unwrap(),
        construction_transport_credential_id: credential.credential_id().into(),
        original_transport_fence_digest: credential.old_key_fence_digest.clone(),
        current_writer_session_expires_at_ms: a.original_session.expires_at_ms,
        native_review_digest: claim.native_review_digest.clone(),
        admitted_at_ms: claim.claimed_at_ms,
        completion_expires_at_ms: a.expires_at_ms,
    };
    let evidence = RosterReenteredConstructionEvidenceV1 {
        version: 1,
        reentry_lineage: lineage.clone(),
        construction: ManualRosterConstructionContributionEvidenceV3 {
            version: 3,
            request: r.request.construction.clone(),
            retained_signer_intent_digest: r.request.signer_intent_digest.clone(),
            current_attempt_digest: r.request.attempt_digest.clone(),
            current_attempt_sequence: r.request.attempt_sequence,
            native_review_digest: r.request.native_review_digest.clone(),
            common_context_read_admission_digest: read.digest().unwrap(),
            witness_plan_approval_digest: read.request.witness_plan_approval_digest.clone(),
            witness_reservation_digest: r
                .digest_for(&reservation.extension, &reservation.continuation)
                .unwrap(),
            witness_consumed_digest: c
                .digest_for(r, &reservation.extension, &reservation.continuation)
                .unwrap(),
            reviewed_at_ms: r.request.reviewed_at_ms,
            reserved_at_ms: r.admitted_at_ms,
            consumed_at_ms: c.consumed_at_ms,
            reserved_debit_zatoshis: r.reserved_debit_zatoshis,
            reserved_input_value_zatoshis: r.reserved_input_value_zatoshis,
            writer_session_expires_at_ms: r.session.expires_at_ms,
        },
    };
    let phases = vec![
        CommonContextReentryAuditPhaseV1::Authorized {
            authorization: Box::new(grant.grant.authorization.clone()),
        },
        CommonContextReentryAuditPhaseV1::Granted {
            grant: Box::new(grant.clone()),
        },
        CommonContextReentryAuditPhaseV1::Claimed {
            credential: Box::new(credential.clone()),
        },
        CommonContextReentryAuditPhaseV1::Reentered {
            lineage: Box::new(lineage.clone()),
            witness_history: Box::new(claimed),
        },
        CommonContextReentryAuditPhaseV1::Reserved {
            reentry_lineage_digest: lineage.digest().unwrap(),
            extension: Box::new(reservation.extension.clone()),
            continuation: Box::new(reservation.continuation.clone()),
            record: Box::new(reservation.clone()),
        },
        CommonContextReentryAuditPhaseV1::Consumed {
            reentry_lineage_digest: lineage.digest().unwrap(),
            record: Box::new(consumed.clone()),
            evidence: Box::new(evidence),
        },
    ];
    let mut rows: Vec<_> = phases
        .into_iter()
        .map(|record| CommonContextReentrySignerAuditV1 {
            version: 1,
            account_id: a.account_id.clone(),
            invocation_digest: a.invocation_digest.clone(),
            original_read_admission_digest: a.read_evidence_digest.clone(),
            record,
        })
        .collect();
    rows.sort_by_key(|r| (r.invocation_digest.clone(), r.phase()));
    let audit = CommonContextSignerAuditInventoryV2 {
        version: 2,
        original: CommonContextSignerAuditInventoryV1 {
            version: 1,
            rows: vec![CommonContextSignerAuditV1::ReadAdmitted {
                version: 1,
                original: Box::new(original),
                evidence: Box::new(read),
                witness_history: Box::new(before.original),
            }],
        },
        reentry: CommonContextReentryAuditInventoryV1 { version: 1, rows },
    };
    let snapshot = history.observed_snapshot();
    let active = snapshot.active_writer_session.as_ref().unwrap();
    let result = HostRecoveryContinuityEvidenceV5 {
        request: HostRecoveryContinuityRequestV5 {
            schema_version: 5,
            inventory_digest: "a1".repeat(32),
            generation_id: "a2".repeat(32),
            account_id: snapshot.account_id.clone(),
            network_profile_id: snapshot.network_profile_id.clone(),
            expected_writer_epoch: snapshot.writer_epoch,
            expected_witness: history.original.witness().clone(),
        },
        writer_certificate_digest: snapshot.writer_certificate_digest.clone(),
        writer_session_id: Some(active.session_id.clone()),
        writer_session_expires_at_ms: Some(active.expires_at_ms),
        head: snapshot.head.clone(),
        history_digest: history.original.complete_replay_digest().into(),
        complete_history: HostRecoveryHistoryV5 {
            schema_version: 5,
            financial_origins_v2: HostRecoveryHistoryV2 {
                schema_version: 2,
                complete_journal_digest: "ef".repeat(32),
                pending_birth_commit: Some(birth.clone()),
                origins: vec![],
                retained_enrollments: vec![],
                retained_reservation_intents: vec![],
                review_receipts: vec![],
                account_use: AccountUseHistoryV2 {
                    genesis: birth.request.policy.account_use_genesis,
                    exclusion: None,
                    witness_ack: None,
                },
            },
            construction: history,
            signer_common_context_audit: audit,
        },
    };
    result.validate().unwrap();
    result
}
