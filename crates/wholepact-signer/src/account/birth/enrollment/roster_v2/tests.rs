//! Pure synthetic records, local file inventory, and maintained encryption.
//! No approval, native capability, session, key-release or socket is created.
use super::*;
use wholepact_authority::account_use::AccountUseIdentity;
fn h(c: char) -> String {
    c.to_string().repeat(64)
}
fn synthetic_account_record() -> BornManualEnrollmentRecord {
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

pub(super) fn synthetic_record() -> BornManualRosterEnrollmentRecordV2 {
    let account_record = synthetic_account_record();
    let roster = HostRosterAppendBindingV2 {
        version: 2,
        generation_id: account_record.terms.host.generation_id.clone(),
        store_destination_identity: account_record.terms.host.store_destination_identity.clone(),
        roster_sequence: 2,
        predecessor:
            wholepact_core::manual_roster_v2::HostRosterPredecessorV2::InitialPublicationV2 {
                audit_digest: h('7'),
            },
    };
    let record = BornManualRosterEnrollmentRecordV2 {
        version: 2,
        signer_roster_native_review_digest: roster_review_digest(&account_record, &roster).unwrap(),
        account_record,
        roster,
    };
    record.validate().unwrap();
    record
}
#[test]
fn roster_wrapper_preserves_exact_original_account_record_and_ancestry() {
    let record = synthetic_record();
    let original = serde_json::to_vec(&record.account_record).unwrap();
    let extension = record.extension().unwrap();
    assert!(extension.account_extension == record.account_record.extension().unwrap());
    assert_eq!(extension.account_extension.sequence, 1);
    assert!(extension.account_extension.predecessor_digest.is_none());
    assert_eq!(record.roster.roster_sequence, 2);
    assert_ne!(
        record.reference().unwrap(),
        record.account_record.reference().unwrap()
    );
    assert_eq!(
        serde_json::to_vec(&record.account_record).unwrap(),
        original
    );
    let mut changed = record.clone();
    changed.roster.predecessor =
        wholepact_core::manual_roster_v2::HostRosterPredecessorV2::InitialPublicationV2 {
            audit_digest: h('8'),
        };
    assert!(changed.validate().is_err());
    changed.signer_roster_native_review_digest =
        roster_review_digest(&changed.account_record, &changed.roster).unwrap();
    assert!(changed.reference().unwrap() != record.reference().unwrap());
    assert_eq!(
        serde_json::to_vec(&changed.account_record).unwrap(),
        original
    );
}
#[test]
fn v2_intent_domain_and_discriminator_cannot_authenticate_v1_or_changed_wrapper() {
    let record = synthetic_record();
    let mut plain = vec![2];
    plain.extend([0x31; 32]);
    plain.extend(serde_json::to_vec(&record).unwrap());
    let (decoded, key) = decode_roster_intent_plain(&plain).unwrap();
    assert!(decoded == record);
    assert_eq!(*key, [0x31; 32]);
    let domain = b"wholepact:born-manual-roster-enrollment-intent:v2\0synthetic-birth";
    let ciphertext = vault::encrypt(&[0x41; 32], domain, &plain).unwrap();
    let restored = vault::decrypt(&[0x41; 32], domain, &ciphertext).unwrap();
    assert!(decode_roster_intent_plain(&restored).is_ok());
    assert!(
        vault::decrypt(
            &[0x41; 32],
            b"wholepact:born-manual-enrollment-intent:v1\0synthetic-birth",
            &ciphertext
        )
        .is_err()
    );
    assert!(vault::decrypt(&[0x42; 32], domain, &ciphertext).is_err());
    plain[0] = 1;
    assert!(decode_roster_intent_plain(&plain).is_err());
    let mut old = vec![1];
    old.extend([0x31; 32]);
    old.extend(serde_json::to_vec(&record.account_record).unwrap());
    assert!(decode_roster_intent_plain(&old).is_err());
    assert!(decode_roster_intent_plain(&[]).is_err());
}
#[test]
fn roster_disk_inventory_rejects_mixed_old_unknown_and_partial_history_without_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let dir = PrivateDirectory::create(&temp.path().join("synthetic-source")).unwrap();
    for n in ["account.wp", "birth-owner-request.wp"] {
        dir.write(n, b"synthetic inert bytes").unwrap();
    }
    roster_inventory(&dir).unwrap();
    dir.write(ROSTER_ACQUIRE, b"synthetic marker, not authenticated")
        .unwrap();
    assert!(roster_inventory(&dir).is_err());
    dir.write(INTENT, b"synthetic intent, not authenticated")
        .unwrap();
    roster_inventory(&dir).unwrap();
    dir.write(COMMIT, b"old V1 commit must be preserved")
        .unwrap();
    assert!(roster_inventory(&dir).is_err());
    assert_eq!(
        dir.read(COMMIT, 128).unwrap(),
        b"old V1 commit must be preserved"
    );
    assert!(super::super::inventory(&dir).is_err());
}
