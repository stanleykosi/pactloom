//! Synthetic audit data and encryption only. No NativeAuthority, NativeDecision,
//! approved writer, reentry owner, session, credential or server is constructed.
use super::*;
use wholepact_authority::account_use::AccountUseIdentity;
fn h(c: char) -> String {
    c.to_string().repeat(64)
}
fn synthetic_record() -> BornManualEnrollmentRecord {
    let identity = ManualAccountIdentity {
        account_id: h('1'),
        full_viewing_key_digest: h('2'),
        network_profile_id: "synthetic-testnet".into(),
        derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
    };
    let genesis = AccountUseGenesis {
        version: 1,
        identity: AccountUseIdentity {
            account_id: identity.account_id.clone(),
            full_viewing_key_digest: identity.full_viewing_key_digest.clone(),
            network_profile_id: identity.network_profile_id.clone(),
            derivation_domain: identity.derivation_domain.clone(),
        },
        witness_id: "synthetic-witness".into(),
        witness_origin_digest: h('8'),
        owner_certificate_digest: h('4'),
        native_birth_digest: h('5'),
    };
    let process = TransportIdentityBinding::LocalProcess {
        transport_identity_id: "synthetic-first-grant".into(),
        channel_key_digest: h('a'),
        channel_binding_digest: h('b'),
        uid: 12345,
        pid: 42,
        process_instance: "synthetic-first-instance".into(),
        signer_generation: 1,
        account_id: h('1'),
        agreement_id: "synthetic-agreement".into(),
        participant_id: "synthetic-participant".into(),
        manifest_digest: h('c'),
    };
    let terms = BornManualEnrollmentTerms {
        version: 1,
        operation_id: "synthetic-first-enrollment".into(),
        identity,
        birth_request_digest: h('3'),
        birth_commit_digest: h('4'),
        native_birth_digest: h('5'),
        original_policy_digest: h('6'),
        account_use_genesis_digest: genesis.digest().unwrap(),
        original_witness_origin_digest: genesis.witness_origin_digest.clone(),
        host: ManualHostGenerationBinding {
            generation_id: h('9'),
            inventory_digest: h('a'),
            generation_plan_digest: h('b'),
            financial_journal_origin_digest: h('c'),
            store_destination_identity: "synthetic-store-identity".into(),
            profile_id: "synthetic-profile".into(),
            canonical_root: "/synthetic/profile".into(),
            destination_identity_digest: h('e'),
            inherited_identity_digest: h('f'),
            scope_predecessor_digest: None,
        },
        signer: BornManualSignerBinding {
            enrollment_generation_id: h('1'),
            signer_target_digest: h('2'),
            original_envelope_digest: h('3'),
            owner_certificate_digest: h('4'),
            writer_certificate_digest: h('5'),
            writer_epoch: 1,
            native_signer_measurement: h('6'),
        },
        scope: BornManualScope {
            agreement_id: "synthetic-agreement".into(),
            obligation_id: "synthetic-obligation".into(),
            participant_id: "synthetic-participant".into(),
            principal_id: "synthetic-host-principal".into(),
            privacy_domain: "synthetic-domain".into(),
            recipient_scope_digests: vec![h('7')],
            aggregate_budget_zatoshis: 100,
            per_operation_limit_zatoshis: 80,
            maximum_fee_share_zatoshis: 5,
            maximum_transaction_fee_zatoshis: 10,
            maximum_permit_lifetime_ms: 1000,
            expires_at_ms: 200000,
        },
        transport_binding_digest: canonical("wholepact:born-manual-transport:v1", &process)
            .unwrap(),
        issued_at_ms: 10,
    };
    let principal = "synthetic-first-native-principal".to_owned();
    let record = BornManualEnrollmentRecord {
        terms_digest: terms.terms_digest().unwrap(),
        signer_native_review_digest: review_digest(&terms, &genesis, &process, &principal).unwrap(),
        terms,
        genesis,
        first_process_binding: process,
        first_native_principal: principal,
    };
    record.validate().unwrap();
    record
}
fn synthetic_attempt(record: &BornManualEnrollmentRecord, intent: &str) -> AcquireAttempt {
    let e = record.extension().unwrap();
    let mut current = record.first_process_binding.clone();
    if let TransportIdentityBinding::LocalProcess {
        pid,
        process_instance,
        transport_identity_id,
        ..
    } = &mut current
    {
        *pid = 73;
        *process_instance = "synthetic-fresh-instance".into();
        *transport_identity_id = "synthetic-fresh-grant".into();
    }
    let principal = "synthetic-fresh-native-principal".to_owned();
    let measurement = h('d');
    AcquireAttempt {
        version: 1,
        enrollment_ref: record.reference().unwrap(),
        intent_digest: intent.into(),
        extension_digest: e.digest().unwrap(),
        acquire_operation_id: e.acquire_operation_id().unwrap(),
        reentry_review_digest: canonical(
            "wholepact:native-born-manual-preacquire-reentry:v1",
            &(record, intent, &current, &principal, &measurement),
        )
        .unwrap(),
        acquire_review_digest: h('e'),
        current_process: current,
        native_principal: principal,
        native_measurement: measurement,
    }
}
fn encrypt(record: &BornManualEnrollmentRecord, audit: &AcquireAttempt, key: &[u8; 32]) -> Vec<u8> {
    vault::encrypt(
        key,
        &domain(record).unwrap(),
        &serde_json::to_vec(audit).unwrap(),
    )
    .unwrap()
}
#[test]
fn authenticated_attempt_roundtrip_preserves_original_record_and_fresh_audit() {
    let record = synthetic_record();
    let before = serde_json::to_vec(&record).unwrap();
    let intent = h('f');
    let audit = synthetic_attempt(&record, &intent);
    let key = [0x51; 32];
    let bytes = encrypt(&record, &audit, &key);
    validate_acquire_attempt_bytes(&record, &intent, &key, &bytes).unwrap();
    let restored = parse_attempt(&record, &intent, &key, &bytes).unwrap();
    assert!(restored == audit);
    assert!(restored.current_process != record.first_process_binding);
    assert_eq!(serde_json::to_vec(&record).unwrap(), before);
}
#[test]
fn missing_tampered_wrong_key_or_rebound_attempt_never_authenticates() {
    let record = synthetic_record();
    let intent = h('f');
    let audit = synthetic_attempt(&record, &intent);
    let key = [0x51; 32];
    let bytes = encrypt(&record, &audit, &key);
    let original = bytes.clone();
    assert!(validate_acquire_attempt_bytes(&record, &intent, &key, &[]).is_err());
    assert!(validate_acquire_attempt_bytes(&record, &intent, &[0x52; 32], &bytes).is_err());
    let mut tampered = bytes.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(validate_acquire_attempt_bytes(&record, &intent, &key, &tampered).is_err());
    assert!(validate_acquire_attempt_bytes(&record, &h('a'), &key, &bytes).is_err());
    let mut changed = record.clone();
    changed.terms.host.generation_id = h('0');
    changed.terms_digest = changed.terms.terms_digest().unwrap();
    changed.signer_native_review_digest = review_digest(
        &changed.terms,
        &changed.genesis,
        &changed.first_process_binding,
        &changed.first_native_principal,
    )
    .unwrap();
    changed.validate().unwrap();
    assert!(validate_acquire_attempt_bytes(&changed, &intent, &key, &bytes).is_err());
    assert_eq!(bytes, original);
}
#[test]
fn authenticated_ciphertext_cannot_hide_changed_original_acquire_or_native_review() {
    let record = synthetic_record();
    let intent = h('f');
    let audit = synthetic_attempt(&record, &intent);
    let key = [0x51; 32];
    for kind in 0..4 {
        let mut changed = audit.clone();
        match kind {
            0 => changed.acquire_operation_id = "different-operation".into(),
            1 => changed.extension_digest = h('0'),
            2 => changed.reentry_review_digest = h('0'),
            _ => changed.native_principal = "different-principal".into(),
        };
        let encrypted = encrypt(&record, &changed, &key);
        assert!(validate_acquire_attempt_bytes(&record, &intent, &key, &encrypted).is_err());
    }
}
