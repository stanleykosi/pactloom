//! Pure synthetic descriptor tests. No keys, sockets, signing, ledger issuance or
//! chain evidence; passing these cannot qualify an offline runtime profile.
use super::*;

fn h(n: u8) -> String {
    format!("{n:064x}")
}
pub(crate) fn fixture() -> (
    ReserveOfflineAuthorization,
    AccountPolicy,
    OfflineEnrollmentPolicy,
) {
    let account = AccountPolicy {
        account_use_genesis: None,
        witness_id: "synthetic-witness".into(),
        account_id: "synthetic-account".into(),
        network_profile_id: "synthetic-testnet".into(),
        owner_certificate_digest: h(1),
        initial_writer_certificate_digest: h(2),
        initial_writer_epoch: 1,
        enrollment_refs: vec![h(3)],
        agreement_ids: vec!["synthetic-agreement".into()],
        recipient_scope_digests: vec![h(4)],
        aggregate_budget_zatoshis: 100,
        per_operation_limit_zatoshis: 80,
        maximum_fee_share_zatoshis: 5,
        maximum_transaction_fee_zatoshis: 10,
        maximum_permit_lifetime_ms: 60_000,
        policy_expires_at_ms: 100_000,
    };
    let offline = OfflineEnrollmentPolicy {
        schema_version: 1,
        account_id: account.account_id.clone(),
        network_profile_id: account.network_profile_id.clone(),
        witness_id: account.witness_id.clone(),
        witness_transport_key_digest: h(5),
        witness_certificate_digest: h(6),
        enrollment_ref: h(3),
        offline_signer_key_digest: h(7),
        return_recipient_key_digest: h(8),
        source_identity_digest: h(9),
        source_policy_digest: h(10),
        maximum_admission_lifetime_ms: 50_000,
        valid_from_ms: 1,
        expires_at_ms: 90_000,
        semantics: OfflineAuthoritySemantics::ExactEffectsPreReservedMayDrainAfterRevocation,
    };
    let request = ReserveOfflineAuthorization {
        schema_version: 1,
        operation_id: "synthetic-offline-reservation".into(),
        writer_epoch: 1,
        expected_head: AuthorityHead {
            sequence: 1,
            digest: h(11),
        },
        intent: OfflineReservationIntent {
            schema_version: 1,
            intent_id: "synthetic-native-reservation-intent".into(),
            native_reservation_review_digest: h(12),
            terms: OfflineAuthorizationTerms {
                account_id: account.account_id.clone(),
                network_profile_id: account.network_profile_id.clone(),
                consensus_branch_id: 0x77190ad9,
                authorization_id: "synthetic-authorization".into(),
                enrollment_ref: h(3),
                accepted_manifest_ref: h(13),
                agreement_id: "synthetic-agreement".into(),
                obligation_id: "synthetic-obligation".into(),
                proposal_id: "synthetic-proposal".into(),
                proposal_revision: 1,
                proposal_digest: h(14),
                manifest_digest: h(15),
                effects_digest: h(16),
                artifact_digest: h(17),
                review_binding: h(18),
                review_package_digest: h(19),
                recipient_scope_digest: h(4),
                offline_signer_key_digest: h(7),
                return_recipient_key_digest: h(8),
                offline_policy_digest: offline.policy_digest().unwrap(),
                snapshot: OfflineSnapshotCommitment {
                    source_id: "synthetic-source".into(),
                    source_identity_digest: h(9),
                    source_policy_digest: h(10),
                    snapshot_digest: h(20),
                    observed_at_ms: 1000,
                    tip_height: 100,
                    tip_hash: h(21),
                    anchor_height: 95,
                    anchor_hash: h(22),
                    anchor_root: h(23),
                },
                inputs: vec![InputReservation {
                    input_id: "synthetic-input".into(),
                    nullifier: h(24),
                    action_index: 0,
                    value_zatoshis: 100,
                }],
                maximum_debit_zatoshis: 70,
                fee_share_zatoshis: 2,
                transaction_fee_zatoshis: 4,
                transaction_expiry_height: 200,
                unknown_facts: OfflineUnknownFact::ALL.to_vec(),
                semantics: offline.semantics,
            },
        },
        requested_at_ms: 2000,
        admission_expires_at_ms: 30_000,
    };
    (request, account, offline)
}
fn admission(request: &ReserveOfflineAuthorization) -> OfflineAuthorizationAdmission {
    OfflineAuthorizationAdmission {
        schema_version: 1,
        witness_id: "synthetic-witness".into(),
        witness_policy_digest: h(25),
        witness_transport_key_digest: h(5),
        request_digest: request.request_digest().unwrap(),
        request: request.clone(),
        committed_head: AuthorityHead {
            sequence: request.expected_head.sequence + 1,
            digest: h(26),
        },
        reserved_at_ms: 3000,
        account_outstanding_debit_zatoshis: 70,
        account_reserved_input_value_zatoshis: 100,
        writer_session_id: h(27),
    }
}

#[test]
fn exact_offline_contract_round_trip_is_evidence_only() {
    let (r, account, offline) = fixture();
    r.validate_policy_bounds(&account, &offline, 3000).unwrap();
    let bytes = encode(&r).unwrap();
    let decoded: ReserveOfflineAuthorization = crate::decode(&bytes).unwrap();
    assert!(decoded == r);
    assert_ne!(
        r.intent.intent_digest().unwrap(),
        r.request_digest().unwrap()
    );
    assert_ne!(
        r.intent.terms.terms_digest().unwrap(),
        r.intent.intent_digest().unwrap()
    );
    admission(&r).matches_request(&decoded).unwrap();
    // Ordinary online reservation decoding fails: there is no invented original
    // spending consent and no automatic conversion to a runtime mutation.
    assert!(crate::decode::<crate::ReserveAuthorization>(&bytes).is_err());
    assert!(crate::decode::<crate::AuthorityMutation>(&bytes).is_err());
}

#[test]
fn exact_admission_rejects_changed_package_recipient_effects_and_intent() {
    let (r, _, _) = fixture();
    let a = admission(&r);
    for field in 0..8 {
        let mut changed = r.clone();
        match field {
            0 => changed.intent.terms.review_package_digest = h(31),
            1 => changed.intent.terms.offline_signer_key_digest = h(31),
            2 => changed.intent.terms.return_recipient_key_digest = h(31),
            3 => changed.intent.terms.effects_digest = h(31),
            4 => changed.intent.native_reservation_review_digest = h(31),
            5 => changed.intent.terms.snapshot.snapshot_digest = h(31),
            6 => changed.intent.terms.transaction_expiry_height += 1,
            _ => changed.operation_id.push_str("-retry"),
        }
        changed.validate().unwrap();
        assert!(a.matches_request(&changed).is_err());
    }
    for field in 0..4 {
        let mut changed = a.clone();
        match field {
            0 => changed.account_outstanding_debit_zatoshis = 69,
            1 => changed.account_reserved_input_value_zatoshis = 99,
            2 => changed.committed_head.sequence += 1,
            _ => changed.reserved_at_ms = r.admission_expires_at_ms,
        }
        assert!(changed.matches_request(&r).is_err());
    }
}

#[test]
fn input_and_unknown_fact_shape_cannot_hide_risk() {
    let (r, _, _) = fixture();
    for field in 0..8 {
        let mut changed = r.clone();
        match field {
            0 => {
                changed.intent.terms.unknown_facts.pop();
            }
            1 => changed.intent.terms.unknown_facts.swap(0, 1),
            2 => changed
                .intent
                .terms
                .inputs
                .push(changed.intent.terms.inputs[0].clone()),
            3 => changed.intent.terms.inputs[0].value_zatoshis = 69,
            4 => changed.intent.terms.inputs[0].nullifier = "A".repeat(64),
            5 => changed.intent.terms.transaction_expiry_height = 100,
            6 => changed.intent.terms.snapshot.anchor_height = 101,
            _ => changed.intent.terms.inputs[0].action_index = 256,
        }
        assert!(changed.validate().is_err());
    }
    let mut overflow = r.clone();
    overflow.intent.terms.inputs[0].value_zatoshis = MAX_MONEY;
    overflow.intent.terms.inputs.push(InputReservation {
        input_id: "other".into(),
        nullifier: h(32),
        action_index: 1,
        value_zatoshis: 1,
    });
    assert!(overflow.validate().is_err());
}

#[test]
fn policy_preflight_does_not_relax_existing_account_bounds() {
    let (r, account, offline) = fixture();
    for field in 0..9 {
        let mut changed = r.clone();
        match field {
            0 => changed.intent.terms.maximum_debit_zatoshis = 81,
            1 => changed.intent.terms.fee_share_zatoshis = 5, // also change total below
            2 => changed.intent.terms.transaction_fee_zatoshis = 11,
            3 => changed.intent.terms.enrollment_ref = h(31),
            4 => changed.intent.terms.offline_signer_key_digest = h(31),
            5 => changed.intent.terms.snapshot.source_identity_digest = h(31),
            6 => changed.admission_expires_at_ms = 60_000,
            7 => changed.intent.terms.offline_policy_digest = h(31),
            _ => changed.intent.terms.agreement_id = "other-agreement".into(),
        }
        if field == 1 {
            changed.intent.terms.fee_share_zatoshis = 6;
            changed.intent.terms.transaction_fee_zatoshis = 6;
        }
        assert!(
            changed
                .validate_policy_bounds(&account, &offline, 3000)
                .is_err()
        );
    }
    assert!(matches!(
        r.validate_policy_bounds(&account, &offline, 1999),
        Err(AuthorityError::Expired)
    ));
    assert!(matches!(
        r.validate_policy_bounds(&account, &offline, 30_000),
        Err(AuthorityError::Expired)
    ));
}

#[test]
fn strict_decoding_rejects_unknown_duplicate_and_unsupported_fields() {
    let (r, _, _) = fixture();
    let text = serde_json::to_string(&r).unwrap();
    let unknown = text.replacen('{', "{\"verified\":true,", 1);
    assert!(crate::decode::<ReserveOfflineAuthorization>(unknown.as_bytes()).is_err());
    let duplicate = text.replacen('{', "{\"schema_version\":1,", 1);
    assert!(crate::decode::<ReserveOfflineAuthorization>(duplicate.as_bytes()).is_err());
    let mut changed = r.clone();
    changed.schema_version = 2;
    assert!(matches!(
        changed.validate(),
        Err(AuthorityError::UnsupportedVersion)
    ));
    let oversized = vec![b' '; crate::MAX_FRAME_BYTES + 1];
    assert!(matches!(
        crate::decode::<ReserveOfflineAuthorization>(&oversized),
        Err(AuthorityError::Limit)
    ));
    let unknown_semantics = text.replace(
        "exact_effects_pre_reserved_may_drain_after_revocation",
        "globally_single_use_immediately_revocable",
    );
    assert!(crate::decode::<ReserveOfflineAuthorization>(unknown_semantics.as_bytes()).is_err());
}

#[test]
fn admission_policy_identity_must_match_the_original_enrollment() {
    let (r, account, offline) = fixture();
    let mut a = admission(&r);
    a.witness_policy_digest = account.policy_digest().unwrap();
    a.validate_reserved_policy_bounds(&account, &offline)
        .unwrap();
    for field in 0..4 {
        let mut changed = a.clone();
        match field {
            0 => changed.witness_id = "other-witness".into(),
            1 => changed.witness_policy_digest = h(31),
            2 => changed.witness_transport_key_digest = h(31),
            _ => changed.account_outstanding_debit_zatoshis = 101,
        }
        assert!(
            changed
                .validate_reserved_policy_bounds(&account, &offline)
                .is_err()
        );
    }
}
