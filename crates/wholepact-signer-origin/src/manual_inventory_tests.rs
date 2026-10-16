use super::*;
use wholepact_core::{born_recipient_policy_v2::*, manual_construction::*, manual_inventory::*};

fn h(c: char) -> String {
    c.to_string().repeat(64)
}
fn evidence() -> ManualPreliminaryInventoryEvidence {
    // Inert wire-only fixture. No native owner, process, session, pending stream,
    // wallet inventory or opaque lease is constructed by these tests.
    let mut terms = crate::manual_continuation_v2::tests::enrollment_request().terms;
    let s = &terms.scope;
    let policy = BornConstructionRecipientPolicyV2 {
        version: 2,
        account_id: terms.identity.account_id.clone(),
        network_profile_id: terms.identity.network_profile_id.clone(),
        agreement_id: s.agreement_id.clone(),
        obligation_id: s.obligation_id.clone(),
        participant_id: s.participant_id.clone(),
        recipients: vec![BornRecipientLimitV2 {
            recipient_id: "syntheticrecipient".into(),
            address: "syntheticshieldedreceiver".into(),
            memo: None,
            instruction_provenance: "synthetic fixture".into(),
            maximum_amount_zatoshis: 80,
        }],
        charges: vec![],
        own_return_rule: BornOwnReturnRuleV2::AuthenticatedSameAccount,
        original_limits: BornOriginalLimitsV2 {
            aggregate_budget_zatoshis: s.aggregate_budget_zatoshis,
            per_operation_limit_zatoshis: s.per_operation_limit_zatoshis,
            maximum_fee_share_zatoshis: s.maximum_fee_share_zatoshis,
            maximum_transaction_fee_zatoshis: s.maximum_transaction_fee_zatoshis,
            maximum_permit_lifetime_ms: s.maximum_permit_lifetime_ms,
            policy_expires_at_ms: s.expires_at_ms,
        },
    };
    let policy_digest = policy.digest().unwrap();
    terms.scope.recipient_scope_digests = vec![policy_digest.clone()];
    let current = ManualCurrentState {
        writer_certificate_digest: terms.signer.writer_certificate_digest.clone(),
        writer_epoch: terms.signer.writer_epoch,
        writer_session_digest: h('a'),
        writer_session_expires_at_ms: 50000,
        witness_head_sequence: 4,
        witness_head_digest: h('b'),
        complete_history_digest: h('c'),
        exclusion_checkpoint_digest: h('d'),
        native_review_digest: h('e'),
    };
    let scope = ManualPreliminaryInventoryScope {
        version: 1,
        enrollment_ref: h('1'),
        witness_extension_digest: h('2'),
        attempt: ManualConstructionAttempt {
            version: 2,
            continuation_digest: h('3'),
            attempt_sequence: 2,
        },
        attachment: ManualConstructionAttachmentBinding {
            version: 1,
            original_primary_journal_origin_digest: terms
                .host
                .financial_journal_origin_digest
                .clone(),
            predecessor_registry_digest: h('4'),
            current_registry_digest: h('5'),
            latest_extension_digest: h('6'),
            selected: ManualParticipantAttachment {
                account_id: terms.identity.account_id.clone(),
                canonical_directory: "/synthetic/wallet".into(),
                directory_identity_digest: h('7'),
                journal_origin_digest: h('8'),
            },
        },
        enrollment: terms,
        original_recipient_policy: policy,
        operator_name: "synthetic native Host".into(),
        operator_destination: "/synthetic/inventory".into(),
        wallet_destination: "/synthetic/wallet/wallet.sqlite".into(),
        purpose: "preliminary_inventory_only".into(),
        retention_policy: "private local exact inventory".into(),
        provider: PreconstructionProvider {
            source_id: "syntheticprovider".into(),
            endpoint: "https://synthetic.invalid".into(),
            trust_profile: "single_tls_provider_report_not_consensus".into(),
        },
        birthday: PreconstructionBirthday {
            prior_height: 1,
            prior_block_hash: h('9'),
            sapling_tree: String::new(),
            orchard_tree: String::new(),
            ironwood_tree: String::new(),
        },
        minimum_confirmations: 1,
        maximum_blocks: 10,
        anchor_height: 2,
    };
    ManualPreliminaryInventoryEvidence {
        version: 1,
        request: ManualPreliminaryInventoryRequest {
            version: 1,
            operation_id: "syntheticinventory".into(),
            scope,
            current_caller_binding_digest: h('f'),
            requested_at_ms: 100,
            disclosure_expires_at_ms: 30100,
        },
        retained_signer_intent_digest: h('a'),
        original_descriptor_digest: policy_digest,
        current,
    }
}
#[test]
fn preliminary_evidence_binds_original_descriptor_writer_and_finite_window() {
    let original = evidence();
    original.validate().unwrap();
    for field in 0..6 {
        let mut wrong = original.clone();
        match field {
            0 => wrong.original_descriptor_digest = h('0'),
            1 => wrong.current.writer_epoch += 1,
            2 => wrong.current.writer_certificate_digest = h('0'),
            3 => wrong.current.writer_session_expires_at_ms = 30099,
            4 => wrong.request.requested_at_ms = 1,
            _ => wrong.version = 2,
        }
        assert!(wrong != original);
        assert!(wrong.validate().is_err());
    }
}
#[test]
fn preliminary_response_has_distinct_strict_wire_and_no_serialized_approval() {
    let e = evidence();
    e.validate().unwrap();
    let response = ManualPreliminaryInventoryResponse::PreliminaryInventoryDisclosedV1 {
        lease_id: h('b'),
        evidence: Box::new(e),
        account_fvk_hex: "07".repeat(96),
    };
    let value = serde_json::to_value(&response).unwrap();
    assert!(serde_json::from_value::<ManualPreliminaryInventoryResponse>(value.clone()).is_ok());
    for field in ["approved", "verified", "can_sign", "native_current"] {
        let mut bad = value.clone();
        bad[field] = serde_json::json!(true);
        assert!(serde_json::from_value::<ManualPreliminaryInventoryResponse>(bad).is_err());
    }
    assert!(
        serde_json::from_str::<ManualPreliminaryInventoryResponse>(
            r#"{"status":"denied","approved":true}"#
        )
        .is_err()
    );
    assert!(
        serde_json::from_str::<ManualPreliminaryInventoryResponse>(
            r#"{"status":"current","lease_id":"x"}"#
        )
        .is_err()
    );
    assert!(
        serde_json::from_str::<ManualPreliminaryInventoryResponse>(
            r#"{"status":"contribution_admitted_v1","evidence":{}}"#
        )
        .is_err()
    );
}
#[test]
fn preliminary_pair_scope_excludes_only_current_grant_and_cannot_rebind_destination() {
    let original = evidence().request;
    let pairing = original.scope.pairing_digest().unwrap();
    let mut new_grant = original.clone();
    new_grant.current_caller_binding_digest = h('0');
    assert_eq!(pairing, new_grant.scope.pairing_digest().unwrap());
    assert_ne!(original.digest().unwrap(), new_grant.digest().unwrap());
    let mut destination = original.clone();
    destination.scope.operator_destination = "/synthetic/other".into();
    assert_ne!(pairing, destination.scope.pairing_digest().unwrap());
    for invalid in [
        "/synthetic/wallet",
        "/synthetic/wallet/./wallet.sqlite",
        "/synthetic/wallet//wallet.sqlite",
        "/synthetic/wallet/other.sqlite",
    ] {
        let mut wrong = original.clone();
        wrong.scope.wallet_destination = invalid.into();
        assert!(wrong.validate().is_err());
    }
}
