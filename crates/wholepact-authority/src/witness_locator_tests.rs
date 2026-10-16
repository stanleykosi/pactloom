//! Synthetic model/SQL tests. No owner lease, native decision, signature,
//! encrypted production namespace, real key or actual witness is constructed.
use super::*;
use crate::account_use::{AccountUseGenesis, ExclusionReason};
use crate::{AccountPolicy, WitnessDisclosureDescriptor};
use rusqlite::TransactionBehavior;

fn h(c: char) -> String {
    c.to_string().repeat(64)
}
fn request() -> PendingBirthRequest {
    let mut policy = AccountPolicy {
        account_use_genesis: None,
        witness_id: "synthetic-witness".into(),
        account_id: h('1'),
        network_profile_id: "synthetic-network".into(),
        owner_certificate_digest: h('2'),
        initial_writer_certificate_digest: h('3'),
        initial_writer_epoch: 1,
        enrollment_refs: vec![h('c')],
        agreement_ids: vec!["manual-only".into()],
        recipient_scope_digests: vec![h('4')],
        aggregate_budget_zatoshis: 100,
        per_operation_limit_zatoshis: 100,
        maximum_fee_share_zatoshis: 5,
        maximum_transaction_fee_zatoshis: 5,
        maximum_permit_lifetime_ms: 1000,
        policy_expires_at_ms: 100_000,
    };
    let original_terms_digest = wholepact_core::proposal::canonical_digest(
        "wholepact:account-birth-original-policy-terms:v1",
        &policy,
    )
    .unwrap();
    let mut disclosure = WitnessDisclosureDescriptor {
        endpoint: "127.0.0.1:1911".into(),
        server_name: "localhost".into(),
        witness_id: policy.witness_id.clone(),
        account_id: policy.account_id.clone(),
        network_profile_id: policy.network_profile_id.clone(),
        policy_digest: h('0'),
        pinned_server_certificate_digest: h('5'),
    };
    policy.account_use_genesis = Some(AccountUseGenesis {
        version: 1,
        identity: AccountUseIdentity {
            account_id: policy.account_id.clone(),
            full_viewing_key_digest: h('6'),
            network_profile_id: policy.network_profile_id.clone(),
            derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
        },
        witness_id: policy.witness_id.clone(),
        witness_origin_digest: account_use_witness_origin_digest(&disclosure).unwrap(),
        owner_certificate_digest: policy.owner_certificate_digest.clone(),
        native_birth_digest: h('7'),
    });
    disclosure.policy_digest = policy.policy_digest().unwrap();
    PendingBirthRequest {
        version: 1,
        operation_id: "synthetic-birth".into(),
        generation_instance_id: h('8'),
        native_birth_digest: h('7'),
        original_terms_digest,
        original_target_digest: h('9'),
        disclosure,
        policy,
        issued_at_ms: 1000,
        initial_commit_deadline_ms: 2000,
    }
}
fn namespace(r: &PendingBirthRequest) -> WitnessNamespaceBinding {
    WitnessNamespaceBinding {
        version: 1,
        namespace_instance_id: h('a'),
        initial_inventory_digest: h('b'),
        witness_id: r.policy.witness_id.clone(),
        witness_origin_digest: account_use_witness_origin_digest(&r.disclosure).unwrap(),
        pinned_server_certificate_digest: r.disclosure.pinned_server_certificate_digest.clone(),
        owner_certificate_digest: r.policy.owner_certificate_digest.clone(),
        network_profile_id: r.policy.network_profile_id.clone(),
        canonical_private_root: "/synthetic/never-opened/witness".into(),
        root_identity: DirectoryIdentity {
            platform: "linux-unix-v1".into(),
            device: 1,
            inode: 2,
            owner_uid: 1000,
        },
        journals_identity: DirectoryIdentity {
            platform: "linux-unix-v1".into(),
            device: 1,
            inode: 3,
            owner_uid: 1000,
        },
    }
}
fn intent(n: &WitnessNamespaceBinding, r: PendingBirthRequest) -> CreationIntent {
    CreationIntent {
        version: 1,
        namespace_digest: n.digest().unwrap(),
        request_digest: r.digest().unwrap(),
        derived_child: derived_child(&r.policy.account_id).unwrap(),
        local_target_digest: target_digest(n, &r.policy.account_id).unwrap(),
        request: r,
        local_owner_review_digest: h('d'),
        owner_approval_evidence_digest: h('e'),
    }
}
fn fixture() -> (WitnessNamespaceBinding, CreationIntent) {
    let r = request();
    let n = namespace(&r);
    let i = intent(&n, r);
    (n, i)
}
fn rebind(
    mut r: PendingBirthRequest,
    account: char,
    fvk: char,
    operation: &str,
    generation: char,
) -> PendingBirthRequest {
    r.policy.account_id = h(account);
    r.disclosure.account_id = h(account);
    let g = r.policy.account_use_genesis.as_mut().unwrap();
    g.identity.account_id = h(account);
    g.identity.full_viewing_key_digest = h(fvk);
    r.operation_id = operation.into();
    r.generation_instance_id = h(generation);
    let mut original = r.policy.clone();
    original.account_use_genesis = None;
    r.original_terms_digest = wholepact_core::proposal::canonical_digest(
        "wholepact:account-birth-original-policy-terms:v1",
        &original,
    )
    .unwrap();
    r.disclosure.policy_digest = r.policy.policy_digest().unwrap();
    r.validate().unwrap();
    r
}
fn synthetic_db(n: Option<&WitnessNamespaceBinding>) -> Connection {
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch("PRAGMA foreign_keys=ON; PRAGMA recursive_triggers=OFF;")
        .unwrap();
    c.execute_batch(SCHEMA).unwrap();
    c.pragma_update(None, "application_id", LOCATOR_APPLICATION_ID)
        .unwrap();
    c.pragma_update(None, "user_version", LOCATOR_SCHEMA_VERSION)
        .unwrap();
    c.execute("INSERT INTO witness_locator_quarantine VALUES(1,0)", [])
        .unwrap();
    if let Some(n) = n {
        // Test-only data fixture, never a production namespace installer.
        c.execute(
            "INSERT INTO witness_locator_namespace VALUES(1,?1,?2)",
            params![n.digest().unwrap(), &*encode(n).unwrap()],
        )
        .unwrap();
    }
    c
}
fn prepare(
    c: &Connection,
    n: &WitnessNamespaceBinding,
    i: &CreationIntent,
    now: u64,
) -> Result<CandidateAudit> {
    let tx = Transaction::new_unchecked(c, TransactionBehavior::Immediate)?;
    let history = load_exact(&tx, n)?;
    let result = prepare_in_transaction(&tx, &history, i, now)?;
    tx.commit()?;
    Ok(result)
}
fn evidence(n: &WitnessNamespaceBinding, i: &CreationIntent) -> CompletionEvidence {
    let birth_commit = PendingBirthCommitRecord {
        version: 1,
        request: i.request.clone(),
        request_digest: i.request_digest.clone(),
        authenticated_owner_certificate_digest: n.owner_certificate_digest.clone(),
        owner_approval_evidence_digest: i.owner_approval_evidence_digest.clone(),
        local_target_digest: i.local_target_digest.clone(),
        local_owner_review_digest: i.local_owner_review_digest.clone(),
        committed_at_ms: 1500,
    };
    let journal_genesis_commitment = digest(
        "wholepact:witness-locator-journal-genesis:v1",
        &(&i.request.policy, &birth_commit),
    )
    .unwrap();
    CompletionEvidence {
        version: 1,
        intent_digest: i.digest(n).unwrap(),
        birth_commit,
        journal_identity: JournalIdentity {
            device: 1,
            inode: 4,
            owner_uid: 1000,
        },
        journal_genesis_commitment,
    }
}
fn complete(
    c: &Connection,
    n: &WitnessNamespaceBinding,
    i: &CreationIntent,
    e: &CompletionEvidence,
    now: u64,
) -> Result<CompletionRecord> {
    let tx = Transaction::new_unchecked(c, TransactionBehavior::Immediate)?;
    let history = load_exact(&tx, n)?;
    let result = complete_in_transaction(&tx, &history, i, e, now)?;
    tx.commit()?;
    Ok(result)
}
fn exclusion(n: &WitnessNamespaceBinding, i: &CreationIntent) -> RetainedExclusion {
    RetainedExclusion {
        version: 1,
        namespace_digest: n.digest().unwrap(),
        source_history_digest: h('f'),
        exclusion: PermanentAccountExclusion {
            version: 1,
            identity: i.identity().clone(),
            genesis_digest: i
                .request
                .policy
                .account_use_genesis
                .as_ref()
                .unwrap()
                .digest()
                .unwrap(),
            operation_id: "synthetic-retirement".into(),
            native_review_digest: h('c'),
            reason: ExclusionReason::RetirementRequested,
        },
    }
}
fn exclude(c: &Connection, n: &WitnessNamespaceBinding, e: &RetainedExclusion) -> Result<()> {
    let tx = Transaction::new_unchecked(c, TransactionBehavior::Immediate)?;
    let history = load_exact(&tx, n)?;
    exclude_in_transaction(&tx, &history, e)?;
    tx.commit()?;
    Ok(())
}

#[test]
fn namespace_binding_rejects_root_pin_identity_and_inventory_substitution() {
    let (n, i) = fixture();
    let c = synthetic_db(Some(&n));
    assert!(load_exact(&c, &n).unwrap().classify(&i).is_ok());
    let mut changed = n.clone();
    changed.canonical_private_root.push_str("-other");
    assert!(load_exact(&c, &changed).is_err());
    let mut changed = n.clone();
    changed.root_identity.inode += 1;
    assert!(load_exact(&c, &changed).is_err());
    let mut changed = n.clone();
    changed.pinned_server_certificate_digest = h('f');
    assert!(load_exact(&c, &changed).is_err());
    let mut changed = n.clone();
    changed.initial_inventory_digest = h('f');
    assert!(load_exact(&c, &changed).is_err());
    let mut changed = i;
    changed.derived_child = format!("journals/{}.wp", h('f'));
    assert!(changed.validate(&n).is_err());
}
#[test]
fn missing_legacy_migration_and_restored_state_are_never_empty_namespace() {
    let (n, _) = fixture();
    assert!(matches!(
        load_exact(&synthetic_db(None), &n),
        Err(AuthorityError::RecoveryRequired)
    ));
    let c = synthetic_db(Some(&n));
    c.pragma_update(None, "user_version", 0).unwrap();
    assert!(matches!(
        load_exact(&c, &n),
        Err(AuthorityError::UnsupportedVersion)
    ));
    let c = synthetic_db(Some(&n));
    c.execute_batch("CREATE TABLE unexpected_legacy(v INTEGER)")
        .unwrap();
    assert!(matches!(
        load_exact(&c, &n),
        Err(AuthorityError::CorruptHistory)
    ));
    let c = synthetic_db(Some(&n));
    c.execute("UPDATE witness_locator_quarantine SET quarantined=1", [])
        .unwrap();
    assert!(matches!(
        load_exact(&c, &n),
        Err(AuthorityError::RecoveryRequired)
    ));
    assert!(
        c.execute("UPDATE witness_locator_quarantine SET quarantined=0", [])
            .is_err()
    );
    assert!(
        c.execute(
            "INSERT OR REPLACE INTO witness_locator_quarantine VALUES(1,0)",
            []
        )
        .is_err()
    );
    assert!(
        c.execute("DELETE FROM witness_locator_quarantine", [])
            .is_err()
    );
}
#[test]
fn exact_retry_retains_original_preparation_and_rejects_changed_deadline() {
    let (n, i) = fixture();
    let c = synthetic_db(Some(&n));
    assert!(matches!(
        prepare(&c, &n, &i, 1100).unwrap(),
        CandidateAudit::ReservedExactIncomplete
    ));
    prepare(&c, &n, &i, 1400).unwrap();
    let p = &load_exact(&c, &n).unwrap().prepared[&i.digest(&n).unwrap()];
    assert_eq!(p.prepared_at_ms, 1100);
    let mut changed = i.request.clone();
    changed.initial_commit_deadline_ms += 1;
    assert!(matches!(
        prepare(&c, &n, &intent(&n, changed), 1400),
        Err(AuthorityError::Conflict)
    ));
    assert!(prepare(&c, &n, &i, 2000).is_err());
    assert_eq!(load_exact(&c, &n).unwrap().prepared.len(), 1);
}
#[test]
fn both_actual_account_and_raw_fvk_digest_aliases_are_permanent_collisions() {
    let (n, i) = fixture();
    let c = synthetic_db(Some(&n));
    prepare(&c, &n, &i, 1100).unwrap();
    for r in [
        rebind(i.request.clone(), '1', 'f', "other-operation", 'a'),
        rebind(i.request.clone(), 'f', '6', "other-operation", 'a'),
        rebind(i.request.clone(), 'f', 'e', "synthetic-birth", 'a'),
        rebind(i.request.clone(), 'f', 'e', "other-operation", '8'),
    ] {
        assert!(matches!(
            prepare(&c, &n, &intent(&n, r), 1200),
            Err(AuthorityError::Conflict)
        ));
    }
    assert_eq!(load_exact(&c, &n).unwrap().prepared.len(), 1);
}
#[test]
fn committed_intent_survives_later_failure_without_journal_or_refund() {
    let (n, i) = fixture();
    let c = synthetic_db(Some(&n));
    {
        // Model failure before locator commit: transaction rollback leaves no row.
        let tx = Transaction::new_unchecked(&c, TransactionBehavior::Immediate).unwrap();
        let history = load_exact(&tx, &n).unwrap();
        prepare_in_transaction(&tx, &history, &i, 1100).unwrap();
    }
    assert!(load_exact(&c, &n).unwrap().prepared.is_empty());
    prepare(&c, &n, &i, 1100).unwrap();
    // Model failure after locator commit: subsequent read retains reservation.
    let reloaded = load_exact(&c, &n).unwrap();
    assert!(matches!(
        reloaded.classify(&i).unwrap(),
        CandidateAudit::ReservedExactIncomplete
    ));
    assert!(reloaded.completed.is_empty());
    assert_eq!(
        reloaded.prepared[&i.digest(&n).unwrap()]
            .intent
            .request
            .policy
            .aggregate_budget_zatoshis,
        100
    );
    assert!(
        c.execute("DELETE FROM witness_locator_intents", [])
            .is_err()
    );
}
#[test]
fn completion_requires_original_intent_and_exact_genesis_before_deadline() {
    let (n, i) = fixture();
    let c = synthetic_db(Some(&n));
    let e = evidence(&n, &i);
    assert!(matches!(
        complete(&c, &n, &i, &e, 3000),
        Err(AuthorityError::RecoveryRequired)
    ));
    prepare(&c, &n, &i, 1100).unwrap();
    let mut wrong = e.clone();
    wrong.birth_commit.local_target_digest = h('0');
    assert!(complete(&c, &n, &i, &wrong, 3000).is_err());
    let mut expired = e.clone();
    expired.birth_commit.committed_at_ms = 2000;
    assert!(complete(&c, &n, &i, &expired, 3000).is_err());
    let completed = complete(&c, &n, &i, &e, 9000).unwrap();
    assert!(completed == complete(&c, &n, &i, &e, 10_000).unwrap());
    assert_eq!(completed.completed_at_ms, 9000);
    assert!(matches!(
        prepare(&c, &n, &i, 20_000).unwrap(),
        CandidateAudit::CompletedOriginalAudit {
            permanently_excluded: false
        }
    ));
    let mut changed = e;
    changed.journal_identity.inode += 1;
    assert!(matches!(
        complete(&c, &n, &i, &changed, 20_000),
        Err(AuthorityError::Conflict)
    ));
}
#[test]
fn exclusions_survive_missing_account_rows_aliases_completion_and_retry() {
    let (n, i) = fixture();
    let c = synthetic_db(Some(&n));
    let e = exclusion(&n, &i);
    exclude(&c, &n, &e).unwrap();
    exclude(&c, &n, &e).unwrap();
    assert!(matches!(
        prepare(&c, &n, &i, 1100),
        Err(AuthorityError::PolicyDenied)
    ));
    let alias = intent(&n, rebind(i.request.clone(), 'a', '6', "alias", 'b'));
    assert!(matches!(
        prepare(&c, &n, &alias, 1100),
        Err(AuthorityError::PolicyDenied)
    ));
    assert_eq!(load_exact(&c, &n).unwrap().exclusions.len(), 1);
    let c = synthetic_db(Some(&n));
    prepare(&c, &n, &i, 1100).unwrap();
    exclude(&c, &n, &e).unwrap();
    assert!(matches!(
        prepare(&c, &n, &i, 1200),
        Err(AuthorityError::PolicyDenied)
    ));
    // Audit completion may reconcile a prior genuine commit but cannot retire
    // the exclusion or return any fresh creation/execution capability.
    complete(&c, &n, &i, &evidence(&n, &i), 9000).unwrap();
    assert!(matches!(
        prepare(&c, &n, &i, 10_000).unwrap(),
        CandidateAudit::CompletedOriginalAudit {
            permanently_excluded: true
        }
    ));
    assert_eq!(load_exact(&c, &n).unwrap().exclusions.len(), 1);
}
#[test]
fn replace_update_and_delete_cannot_rewrite_namespace_intent_completion_or_exclusion() {
    let (n, i) = fixture();
    let c = synthetic_db(Some(&n));
    prepare(&c, &n, &i, 1100).unwrap();
    complete(&c, &n, &i, &evidence(&n, &i), 3000).unwrap();
    exclude(&c, &n, &exclusion(&n, &i)).unwrap();
    for table in [
        "witness_locator_namespace",
        "witness_locator_intents",
        "witness_locator_completions",
        "witness_locator_exclusions",
    ] {
        assert!(
            c.execute(
                &format!("INSERT OR REPLACE INTO {table} SELECT * FROM {table}"),
                []
            )
            .is_err()
        );
        assert!(
            c.execute(&format!("UPDATE {table} SET payload=payload"), [])
                .is_err()
        );
        assert!(c.execute(&format!("DELETE FROM {table}"), []).is_err());
    }
    assert_eq!(load_exact(&c, &n).unwrap().completed.len(), 1);
}
#[test]
fn indexes_and_schema_must_agree_with_authenticated_payloads() {
    let (n, i) = fixture();
    let c = synthetic_db(Some(&n));
    prepare(&c, &n, &i, 1100).unwrap();
    c.execute("DROP TRIGGER witness_locator_intents_no_update", [])
        .unwrap();
    assert!(matches!(
        load_exact(&c, &n),
        Err(AuthorityError::CorruptHistory)
    ));
    // Restore exact trigger but alter a duplicated index field in between.
    c.execute(
        "UPDATE witness_locator_intents SET network_profile_id='other-network'",
        [],
    )
    .unwrap();
    c.execute_batch("CREATE TRIGGER witness_locator_intents_no_update BEFORE UPDATE ON witness_locator_intents\nBEGIN SELECT RAISE(ABORT,'immutable witness creation intent'); END;").unwrap();
    assert!(matches!(
        load_exact(&c, &n),
        Err(AuthorityError::CorruptHistory)
    ));
}
#[test]
fn resource_limits_and_unknown_fields_fail_closed() {
    let (n, i) = fixture();
    let p = PreparedIntent {
        intent: i.clone(),
        prepared_at_ms: 1100,
    };
    assert!(matches!(
        LocatorHistory::from_records(n.clone(), vec![p; MAX_INTENTS + 1], vec![], vec![]),
        Err(AuthorityError::Limit)
    ));
    let mut value = serde_json::to_value(&i).unwrap();
    value["approved"] = serde_json::json!(true);
    assert!(serde_json::from_value::<CreationIntent>(value).is_err());
    let mut value = serde_json::to_value(&n).unwrap();
    value["reset_namespace"] = serde_json::json!(true);
    assert!(serde_json::from_value::<WitnessNamespaceBinding>(value).is_err());
    let c = synthetic_db(Some(&n));
    assert!(
        c.execute(
            "INSERT INTO witness_locator_exclusions VALUES(?1,?2,?3,?4)",
            params![h('d'), h('1'), h('6'), vec![0u8; MAX_PAYLOAD_BYTES + 1]]
        )
        .is_err()
    );
}

#[test]
fn canonical_child_width_matches_the_immutable_sql_constraint() {
    let (namespace, intent) = fixture();
    assert_eq!(
        intent.derived_child.len(),
        "journals/".len() + 64 + ".wp".len()
    );
    assert_eq!(intent.derived_child.len(), 76);
    let connection = synthetic_db(Some(&namespace));
    prepare(&connection, &namespace, &intent, 1100).unwrap();
    let stored_length: usize = connection
        .query_row(
            "SELECT length(derived_child) FROM witness_locator_intents",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored_length, 76);
}

#[test]
fn sqlite_prefix_user_objects_cannot_hide_from_locator_schema_validation() {
    let (n, _) = fixture();
    for sql in [
        "CREATE TABLE sqliteXextra(value TEXT)",
        "CREATE TRIGGER sqliteXextra AFTER INSERT ON witness_locator_quarantine BEGIN SELECT 1; END",
    ] {
        let c = synthetic_db(Some(&n));
        load_exact(&c, &n).unwrap();
        c.execute_batch(sql).unwrap();
        assert!(matches!(
            load_exact(&c, &n),
            Err(AuthorityError::CorruptHistory)
        ));
    }
}
#[test]
fn locator_accepts_legitimate_sqlite_statistics_and_autoindexes() {
    let (n, _) = fixture();
    let c = synthetic_db(Some(&n));
    c.execute_batch("ANALYZE;").unwrap();
    let stats: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='sqlite_stat1')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(stats);
    load_exact(&c, &n).unwrap();
}
