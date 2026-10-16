//! Data-only predicates. No native decision, authenticated replay or opaque
//! disclosure admission is fabricated; these tests cannot claim issuer success.
use super::*;
use wholepact_authority::{
    AuthorityHead, WriterStatus,
    account_use::{AccountUseCheckpoint, AccountUseIdentity, ExclusionReason},
};

fn data_request() -> RetiredHistoryRequest {
    let original_witness = WitnessDisclosureDescriptor {
        endpoint: "127.0.0.1:443".into(),
        server_name: "witness.example".into(),
        witness_id: "witness-a".into(),
        account_id: "a".repeat(64),
        network_profile_id: "ironwood-testnet-nu7-candidate".into(),
        policy_digest: "b".repeat(64),
        pinned_server_certificate_digest: "c".repeat(64),
    };
    let expected_genesis = AccountUseGenesis {
        version: 1,
        identity: AccountUseIdentity {
            account_id: original_witness.account_id.clone(),
            full_viewing_key_digest: "d".repeat(64),
            network_profile_id: original_witness.network_profile_id.clone(),
            derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
        },
        witness_id: original_witness.witness_id.clone(),
        witness_origin_digest: account_use_witness_origin_digest(&original_witness).unwrap(),
        owner_certificate_digest: "e".repeat(64),
        native_birth_digest: "f".repeat(64),
    };
    RetiredHistoryRequest {
        schema_version: 1,
        inventory_digest: "1".repeat(64),
        semantic_inventory_digest: "2".repeat(64),
        generation_id: "3".repeat(64),
        plan_digest: "4".repeat(64),
        target_profile: "/private/successor".into(),
        expected_genesis,
        original_witness,
    }
}
fn data_local(
    g: &AccountUseGenesis,
) -> (
    RetiredLocalAudit,
    PermanentAccountExclusion,
    AccountExclusionReceipt,
) {
    let exclusion = PermanentAccountExclusion {
        version: 1,
        identity: g.identity.clone(),
        genesis_digest: g.digest().unwrap(),
        operation_id: "retire-original".into(),
        native_review_digest: "5".repeat(64),
        reason: ExclusionReason::RetirementRequested,
    };
    let receipt = AccountExclusionReceipt {
        genesis_digest: g.digest().unwrap(),
        exclusion_digest: exclusion.digest().unwrap(),
        witness_origin_digest: g.witness_origin_digest.clone(),
        committed_head: AuthorityHead {
            sequence: 1,
            digest: "6".repeat(64),
        },
        operation_id: exclusion.operation_id.clone(),
    };
    let local = RetiredLocalAudit {
        genesis: g.clone(),
        local_exclusion: Some(exclusion.clone()),
        local_witness_ack: None,
        recovery_required: true,
        historical_writer_epoch: 7,
    };
    (local, exclusion, receipt)
}
fn data_audit() -> RetiredHistoryAuditRecord {
    let mut request = data_request();
    let (local, exclusion, receipt) = data_local(&request.expected_genesis);
    let policy = AccountPolicy {
        account_use_genesis: Some(request.expected_genesis.clone()),
        witness_id: request.original_witness.witness_id.clone(),
        account_id: request.original_witness.account_id.clone(),
        network_profile_id: request.original_witness.network_profile_id.clone(),
        owner_certificate_digest: request.expected_genesis.owner_certificate_digest.clone(),
        initial_writer_certificate_digest: "8".repeat(64),
        initial_writer_epoch: 1,
        enrollment_refs: vec!["1".repeat(64)],
        agreement_ids: vec!["agreement-a".into()],
        recipient_scope_digests: vec!["2".repeat(64)],
        aggregate_budget_zatoshis: 100,
        per_operation_limit_zatoshis: 90,
        maximum_fee_share_zatoshis: 5,
        maximum_transaction_fee_zatoshis: 10,
        maximum_permit_lifetime_ms: 60_000,
        policy_expires_at_ms: 1_800_000_000_000,
    };
    request.original_witness.policy_digest = policy.policy_digest().unwrap();
    RetiredHistoryAuditRecord {
        purpose: RetiredHistoryPurpose::InformationalRetiredHistoryOnly,
        snapshot: AccountSnapshot {
                transport_fences: None,
            account_use_checkpoint: Some(AccountUseCheckpoint {
                genesis_digest: request.expected_genesis.digest().unwrap(),
                history_digest: "9".repeat(64),
                permanent_exclusion_digest: Some(exclusion.digest().unwrap()),
            }),
            witness_id: request.original_witness.witness_id.clone(),
            account_id: request.original_witness.account_id.clone(),
            network_profile_id: request.original_witness.network_profile_id.clone(),
            policy_digest: request.original_witness.policy_digest.clone(),
            head: receipt.committed_head.clone(),
            writer_epoch: 7,
            writer_certificate_digest: "8".repeat(64),
            writer_status: WriterStatus::Revoked,
            outstanding_reservations: 0,
            outstanding_debit_zatoshis: 0,
            settled_debit_zatoshis: 42,
            aggregate_budget_zatoshis: 100,
            reserved_input_value_zatoshis: 0,
            last_witness_time_ms: 10,
            pending_writer_session: None,
            active_writer_session: None,
        },
        request,
        local,
        recipient: RetiredHistoryRecipient {
            grant_id: "1".repeat(64),
            channel_digest: "2".repeat(64),
            process_instance: "3".repeat(64),
            uid: 1000,
            pid: 1234,
            application_label: "data-only-host".into(),
        },
        native_review_digest: "4".repeat(64),
        witness_policy: policy,
        witnessed_exclusion: exclusion,
        witnessed_ack: receipt,
        history_digest: "5".repeat(64),
        conservative_permits: vec![],
        automatic_key_use_history: vec![],
    }
}
#[test]
fn modeled_request_commits_every_successor_identity_and_origin_dimension() {
    let r = data_request();
    let original = r.digest().unwrap();
    let edits: [fn(&mut RetiredHistoryRequest); 12] = [
        |r| r.inventory_digest = "9".repeat(64),
        |r| r.semantic_inventory_digest = "9".repeat(64),
        |r| r.generation_id = "9".repeat(64),
        |r| r.plan_digest = "9".repeat(64),
        |r| r.target_profile = "/private/other".into(),
        |r| r.expected_genesis.identity.full_viewing_key_digest = "9".repeat(64),
        |r| r.expected_genesis.native_birth_digest = "9".repeat(64),
        |r| r.expected_genesis.owner_certificate_digest = "9".repeat(64),
        |r| {
            r.expected_genesis.identity.account_id = "9".repeat(64);
            r.original_witness.account_id = "9".repeat(64);
        },
        |r| {
            r.original_witness.endpoint = "127.0.0.1:444".into();
            r.expected_genesis.witness_origin_digest =
                account_use_witness_origin_digest(&r.original_witness).unwrap();
        },
        |r| {
            r.original_witness.pinned_server_certificate_digest = "9".repeat(64);
            r.expected_genesis.witness_origin_digest =
                account_use_witness_origin_digest(&r.original_witness).unwrap();
        },
        |r| r.original_witness.policy_digest = "9".repeat(64),
    ];
    for edit in edits {
        let mut changed = r.clone();
        edit(&mut changed);
        assert_ne!(changed.digest().unwrap(), original);
        assert!(require_exact_consumption(&changed, &r, Duration::ZERO).is_err());
    }
}
#[test]
fn modeled_request_rejects_inconsistent_origin_unknown_fields_and_unsafe_path() {
    let mut r = data_request();
    r.original_witness.pinned_server_certificate_digest = "9".repeat(64);
    assert!(r.validate().is_err());
    for path in [
        "relative",
        "/",
        "/private/../successor",
        "/private//successor",
        "/private/successor/",
        "/private/\u{202e}successor",
    ] {
        let mut r = data_request();
        r.target_profile = path.into();
        assert!(r.validate().is_err());
    }
    let mut value = serde_json::to_value(data_request()).unwrap();
    value["active_writer"] = true.into();
    assert!(serde_json::from_value::<RetiredHistoryRequest>(value).is_err());
}
#[test]
fn modeled_local_pending_and_recovery_state_are_preserved() {
    let r = data_request();
    let (local, exclusion, receipt) = data_local(&r.expected_genesis);
    let before = serde_json::to_vec(&local).unwrap();
    assert!(
        local
            .validate_against(&r.expected_genesis, &exclusion, &receipt)
            .is_ok()
    );
    assert_eq!(before, serde_json::to_vec(&local).unwrap());
    assert!(local.local_witness_ack.is_none());
    assert!(local.recovery_required);
    assert_eq!(local.historical_writer_epoch, 7);
}
#[test]
fn modeled_remote_only_retirement_does_not_install_local_ack() {
    let r = data_request();
    let (mut local, exclusion, receipt) = data_local(&r.expected_genesis);
    local.local_exclusion = None;
    assert!(
        local
            .validate_against(&r.expected_genesis, &exclusion, &receipt)
            .is_ok()
    );
    assert!(local.local_exclusion.is_none() && local.local_witness_ack.is_none());
    local.local_witness_ack = Some(receipt.clone());
    assert!(
        local
            .validate_against(&r.expected_genesis, &exclusion, &receipt)
            .is_err()
    );
}
#[test]
fn modeled_conflicting_local_retirement_and_ack_are_denied() {
    let r = data_request();
    let (local, exclusion, receipt) = data_local(&r.expected_genesis);
    let mut changed = local.clone();
    changed.local_exclusion.as_mut().unwrap().operation_id = "other-retirement".into();
    assert!(
        changed
            .validate_against(&r.expected_genesis, &exclusion, &receipt)
            .is_err()
    );
    let mut changed = local;
    changed.local_witness_ack = Some(receipt.clone());
    assert!(
        changed
            .validate_against(&r.expected_genesis, &exclusion, &receipt)
            .is_ok()
    );
    changed
        .local_witness_ack
        .as_mut()
        .unwrap()
        .committed_head
        .digest = "9".repeat(64);
    assert!(
        changed
            .validate_against(&r.expected_genesis, &exclusion, &receipt)
            .is_err()
    );
}
#[test]
fn modeled_disclosure_age_boundary_is_fail_closed() {
    let r = data_request();
    assert!(
        require_exact_consumption(&r, &r, DISCLOSURE_LIFETIME - Duration::from_nanos(1)).is_ok()
    );
    assert!(require_exact_consumption(&r, &r, DISCLOSURE_LIFETIME).is_err());
    assert!(
        require_exact_consumption(&r, &r, DISCLOSURE_LIFETIME + Duration::from_secs(1)).is_err()
    );
}
#[test]
fn modeled_audit_retains_lifetime_consumed_budget_and_pending_exclusion() {
    let r = data_audit();
    assert!(r.validate_audit().is_ok());
    let bytes = serde_json::to_vec(&r).unwrap();
    let decoded: RetiredHistoryAuditRecord = serde_json::from_slice(&bytes).unwrap();
    assert!(decoded.validate_audit().is_ok());
    assert!(decoded == r);
    assert_eq!(decoded.snapshot.settled_debit_zatoshis, 42);
    assert_eq!(decoded.snapshot.remaining_budget_zatoshis().unwrap(), 58);
    assert!(decoded.local.recovery_required && decoded.local.local_witness_ack.is_none());
    // This is only DTO round-trip coverage, never an admission/replay constructor.
}
#[test]
fn modeled_audit_rejects_missing_retirement_checkpoint_and_unrelated_receipt() {
    let mut r = data_audit();
    r.snapshot
        .account_use_checkpoint
        .as_mut()
        .unwrap()
        .permanent_exclusion_digest = None;
    assert!(r.validate_audit().is_err());
    let mut r = data_audit();
    r.witnessed_ack.witness_origin_digest = "9".repeat(64);
    assert!(r.validate_audit().is_err());
    let mut r = data_audit();
    r.witness_policy.account_use_genesis = None;
    assert!(r.validate_audit().is_err());
}
