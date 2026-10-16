//! Synthetic inert records and maintained vault encryption only. No native,
//! pairing, session, current witness, or approval capability is constructed.
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

fn first_marker(record: &BornManualEnrollmentRecord, intent: &str, key: &[u8; 32]) -> Vec<u8> {
    let process = &record.first_process_binding;
    let principal = "synthetic-fresh-principal";
    let measurement = h('d');
    let audit = serde_json::json!({"version":1,"enrollment_ref":record.reference().unwrap(),"intent_digest":intent,"extension_digest":record.extension().unwrap().digest().unwrap(),"acquire_operation_id":record.extension().unwrap().acquire_operation_id().unwrap(),"reentry_review_digest":canonical("wholepact:native-born-manual-preacquire-reentry:v1",&(record,intent,process,principal,&measurement)).unwrap(),"acquire_review_digest":h('e'),"current_process":process,"native_principal":principal,"native_measurement":measurement});
    let mut domain = b"wholepact:born-manual-first-acquire-attempt:v1\0".to_vec();
    domain.extend(record.reference().unwrap().as_bytes());
    vault::encrypt(key, &domain, &serde_json::to_vec(&audit).unwrap()).unwrap()
}
fn proposal(
    record: &BornManualEnrollmentRecord,
    intent: &str,
    first: &[u8],
    index: u16,
    previous: Option<String>,
) -> ContinuationProposal {
    let t = &record.terms;
    let e = record.extension().unwrap();
    let mut p = ContinuationProposal {
        version: 1,
        local_index: index,
        previous_local_digest: previous,
        enrollment_ref: record.reference().unwrap(),
        intent_digest: intent.into(),
        first_marker_digest: hex::encode(Sha256::digest(first)),
        continuation: ManualEnrollmentSessionContinuation {
            version: 1,
            extension_digest: e.digest().unwrap(),
            sequence: 2,
            previous_attempt_digest:
                wholepact_authority::manual_session_continuation::initial_manual_attempt_digest(&e)
                    .unwrap(),
            expected_snapshot: wholepact_authority::AccountSnapshot {
                transport_fences: None,
                account_use_checkpoint: None,
                witness_id: record.genesis.witness_id.clone(),
                account_id: t.identity.account_id.clone(),
                network_profile_id: t.identity.network_profile_id.clone(),
                policy_digest: t.original_policy_digest.clone(),
                head: wholepact_authority::AuthorityHead {
                    sequence: 1,
                    digest: h('b'),
                },
                writer_epoch: t.signer.writer_epoch,
                writer_certificate_digest: t.signer.writer_certificate_digest.clone(),
                writer_status: WriterStatus::Active,
                outstanding_reservations: 0,
                outstanding_debit_zatoshis: 0,
                settled_debit_zatoshis: 0,
                aggregate_budget_zatoshis: t.scope.aggregate_budget_zatoshis,
                reserved_input_value_zatoshis: 0,
                last_witness_time_ms: 20,
                pending_writer_session: None,
                active_writer_session: None,
            },
            expected_previous_admission_digest: None,
            attempt_nonce: format!("{:064x}", index),
            fresh_process_binding_digest: process_digest(&record.first_process_binding).unwrap(),
            fresh_signer_review_digest: String::new(),
            issued_at_ms: 30,
            initial_commit_deadline_ms: 120030,
        },
        process: record.first_process_binding.clone(),
        native_principal: "synthetic-continuation-owner".into(),
        native_measurement: h('d'),
        complete_history_digest: h('f'),
    };
    p.continuation.fresh_signer_review_digest = p.review_digest().unwrap();
    p
}
fn add(
    files: &mut BTreeMap<String, Vec<u8>>,
    record: &BornManualEnrollmentRecord,
    p: &ContinuationProposal,
    key: &[u8; 32],
) {
    let name = p.filename(Kind::Proposal).unwrap();
    let bytes = vault::encrypt(
        key,
        &domain(record, &name).unwrap(),
        &serde_json::to_vec(p).unwrap(),
    )
    .unwrap();
    files.insert(name, bytes);
}
#[test]
fn continuation_history_roundtrips_original_marker_and_local_chain() {
    let record = synthetic_record();
    let original = serde_json::to_vec(&record).unwrap();
    let key = [0x27; 32];
    let intent = h('e');
    let first = first_marker(&record, &intent, &key);
    let unchanged = first.clone();
    let one = proposal(&record, &intent, &first, 1, None);
    let two = proposal(&record, &intent, &first, 2, Some(one.digest().unwrap()));
    let mut files = BTreeMap::new();
    add(&mut files, &record, &one, &key);
    add(&mut files, &record, &two, &key);
    let parsed = validate_files(&record, &intent, &key, &first, &files).unwrap();
    assert_eq!(parsed.len(), 2);
    assert!(parsed[0].proposal == one);
    assert!(parsed[1].proposal == two);
    assert_eq!(first, unchanged);
    assert_eq!(serde_json::to_vec(&record).unwrap(), original);
}
#[test]
fn continuation_ciphertext_tamper_missing_prefix_and_wrong_original_are_denied() {
    let record = synthetic_record();
    let key = [0x27; 32];
    let intent = h('e');
    let first = first_marker(&record, &intent, &key);
    let one = proposal(&record, &intent, &first, 1, None);
    let two = proposal(&record, &intent, &first, 2, Some(one.digest().unwrap()));
    let mut files = BTreeMap::new();
    add(&mut files, &record, &one, &key);
    add(&mut files, &record, &two, &key);
    let mut missing = files.clone();
    missing.remove(&one.filename(Kind::Proposal).unwrap());
    assert!(validate_files(&record, &intent, &key, &first, &missing).is_err());
    let mut tampered = files.clone();
    let bytes = tampered
        .get_mut(&two.filename(Kind::Proposal).unwrap())
        .unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert!(validate_files(&record, &intent, &key, &first, &tampered).is_err());
    assert!(validate_files(&record, &h('a'), &key, &first, &files).is_err());
    assert!(validate_files(&record, &intent, &[0x28; 32], &first, &files).is_err());
    let mut wrong = record.clone();
    wrong.terms.host.profile_id = "different-original".into();
    assert!(validate_files(&wrong, &intent, &key, &first, &files).is_err());
}
#[test]
fn continuation_reencrypted_changed_native_review_or_predecessor_is_denied() {
    let record = synthetic_record();
    let key = [0x27; 32];
    let intent = h('e');
    let first = first_marker(&record, &intent, &key);
    let mut changed = proposal(&record, &intent, &first, 1, None);
    changed.native_principal = "substituted".into();
    let mut files = BTreeMap::new();
    add(&mut files, &record, &changed, &key);
    assert!(validate_files(&record, &intent, &key, &first, &files).is_err());
    let one = proposal(&record, &intent, &first, 1, None);
    let two = proposal(&record, &intent, &first, 2, Some(h('b')));
    files.clear();
    add(&mut files, &record, &one, &key);
    add(&mut files, &record, &two, &key);
    assert!(validate_files(&record, &intent, &key, &first, &files).is_err());
}
#[test]
fn continuation_inventory_rejects_orphan_signature_acquire_conflicting_digest_and_gap() {
    let digest = h('a');
    let mut names: BTreeSet<String> = [INTENT.into(), ACQUIRE_ATTEMPT.into()]
        .into_iter()
        .collect();
    names.insert(format!("{PREFIX}0001-{digest}.signature.wp"));
    assert!(check_names(&names).is_err());
    names.clear();
    names.insert(INTENT.into());
    names.insert(ACQUIRE_ATTEMPT.into());
    names.insert(format!("{PREFIX}0001-{digest}.proposal.wp"));
    names.insert(format!("{PREFIX}0001-{digest}.acquire.wp"));
    assert!(check_names(&names).is_err());
    names.remove(&format!("{PREFIX}0001-{digest}.acquire.wp"));
    names.insert(format!("{PREFIX}0001-{}.signature.wp", h('b')));
    assert!(check_names(&names).is_err());
    names.retain(|n| !n.contains("signature"));
    names.insert(format!("{PREFIX}0003-{digest}.proposal.wp"));
    assert!(check_names(&names).is_err());
    assert!(parse_name(&format!("{PREFIX}0033-{digest}.proposal.wp")).is_none());
}

#[test]
fn attempted_partial_inventory_is_rejected_without_changing_any_source_byte() {
    let temp = tempfile::tempdir().unwrap();
    let dir = PrivateDirectory::create(&temp.path().join("source")).unwrap();
    for name in [
        "account.wp",
        "birth-owner-request.wp",
        INTENT,
        ACQUIRE_ATTEMPT,
    ] {
        dir.write(name, b"synthetic immutable ciphertext").unwrap();
    }
    let tree = |dir: &PrivateDirectory| {
        let mut files = BTreeMap::new();
        for entry in std::fs::read_dir(dir.root()).unwrap() {
            let entry = entry.unwrap();
            files.insert(entry.file_name(), std::fs::read(entry.path()).unwrap());
        }
        files
    };
    assert!(inventory(&dir).is_ok());
    dir.write(
        COMMIT,
        b"synthetic contradictory completion without journal",
    )
    .unwrap();
    let before = tree(&dir);
    assert!(inventory(&dir).is_err());
    assert_eq!(before, tree(&dir));
    dir.write("tmp-uncertain", b"synthetic interrupted append")
        .unwrap();
    let before = tree(&dir);
    assert!(inventory(&dir).is_err());
    assert_eq!(before, tree(&dir));
}
