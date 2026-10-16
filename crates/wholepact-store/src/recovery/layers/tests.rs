use super::*;

// Raw synthetic owner fixtures only. These tests cannot create the sealed
// ArchivedGenerationSource and do not stand in for encrypted native publication.
fn binding(index: u8) -> GenerationBinding {
    GenerationBinding::new(
        &format!("{index:02x}").repeat(32),
        &format!("{:02x}", index + 32).repeat(32),
    )
    .unwrap()
}
fn provenance(rows: usize, index: u8) -> RecoveryProvenance {
    RecoveryProvenance {
        profile_id: format!("synthetic-profile-{index}"),
        checkpoint_id: format!("synthetic-checkpoint-{index}"),
        bundle_digest: format!("{:02x}", index + 64).repeat(32),
        component_id: "coordination".into(),
        kind: JournalKind::CoordinationAuthority,
        component_digest: format!("{:02x}", index + 96).repeat(32),
        application_id: 0,
        schema_version: SCHEMA_VERSION,
        rows,
    }
}
fn agreement(store: &Store, id: &str) -> CommandContext {
    let context = CommandContext::for_request(
        "synthetic-owner",
        format!("create-{id}"),
        &serde_json::json!(["create", id]),
    )
    .unwrap();
    store.create_agreement(&context,id,serde_json::json!({"view":{"agreement":{"agreement_id":id}},"account_id":"synthetic-account","obligation_id":format!("obligation-{id}")})).unwrap();
    context
}
fn release(id: &str, amount: &str) -> ReleaseIntent {
    ReleaseIntent {
        authorization_id: id.into(),
        account_id: "synthetic-account".into(),
        writer_epoch: 7,
        obligation_id: format!("obligation-{id}"),
        proposal_id: format!("proposal-{id}"),
        manifest_digest: "a".repeat(64),
        effects_digest: "b".repeat(64),
        artifact_digest: "c".repeat(64),
        maximum_debit: amount.into(),
        input_ids: vec![format!("input-{id}")],
        aggregate_budget_limit: "10000".into(),
    }
}
fn insert_exposure(c: &Connection, intent: &ReleaseIntent, state: &str) {
    let payload = serde_json::to_value(intent).unwrap();
    c.execute(
        "INSERT INTO authority_exposures VALUES(?1,?2,?3,?4,?5,?6,?7,1,?8,1,1)",
        params![
            intent.authorization_id,
            intent.account_id,
            intent.obligation_id,
            intent.proposal_id,
            request_digest(&payload).unwrap(),
            intent.maximum_debit,
            state,
            serde_json::to_string(&payload).unwrap()
        ],
    )
    .unwrap();
}
fn root() -> (Store, RecoveryProvenance, GenerationBinding) {
    let mut store = Store::in_memory().unwrap();
    agreement(&store, "original-agreement");
    store
        .record_effect_intent(
            "original-effect",
            "send",
            "original-agreement",
            &"d".repeat(64),
            "retained:original",
        )
        .unwrap();
    store
        .initialize_authority_account("synthetic-account", 7)
        .unwrap();
    let c = store.connection.lock().unwrap();
    insert_exposure(&c, &release("charged", "111"), "consumed");
    insert_exposure(&c, &release("expired", "222"), "expired_observed");
    let mut originals = Vec::new();
    for table in BASE {
        for (ordinal, row) in read_rows(&c, table, "").unwrap().into_iter().enumerate() {
            originals.push((table.name, ordinal, row));
        }
    }
    let provenance = provenance(originals.len(), 1);
    c.execute_batch(include_str!("../../recovery-schema.sql"))
        .unwrap();
    for (table, ordinal, row) in originals {
        c.execute(
            "INSERT INTO store_generation_original_rows VALUES(?1,?2,?3)",
            params![
                table,
                ordinal as i64,
                serde_json::to_string(&row.cells).unwrap()
            ],
        )
        .unwrap();
        add_row_restrictions(&c, table, &row.cells).unwrap();
    }
    c.execute("UPDATE authority_exposures SET state=CASE WHEN state='consumed' THEN 'consumed' ELSE 'outstanding_uncertain' END",[]).unwrap();
    c.execute("UPDATE authority_accounts SET recovery_required=1", [])
        .unwrap();
    c.execute(
        "UPDATE store_recovery SET recovery_required=1,restored_at_ms=1,source_snapshot_digest=?1",
        [&provenance.component_digest],
    )
    .unwrap();
    c.execute(
        "INSERT INTO records VALUES('settlement_generation_identity','local',0,?1,1,1)",
        [serde_json::to_string(&"e".repeat(64)).unwrap()],
    )
    .unwrap();
    c.pragma_update(None, "application_id", RECOVERED_GENERATION_APPLICATION_ID)
        .unwrap();
    c.pragma_update(
        None,
        "user_version",
        coordination_successor_template().schema_version,
    )
    .unwrap();
    drop(c);
    let binding = binding(1);
    store.recovered_generation = true;
    store.recovered_binding = Some(binding.clone());
    store
        .add_recovery_obligation_fences(
            &binding,
            &BTreeSet::from(["witness-generation-one".into()]),
        )
        .unwrap();
    validate_generation(&store.connection.lock().unwrap(), &provenance, &binding).unwrap();
    (store, provenance, binding)
}
fn advance(
    parent: &Store,
    parent_provenance: &RecoveryProvenance,
    new_binding: &GenerationBinding,
) -> (Store, RecoveryProvenance) {
    let c = parent.connection.lock().unwrap();
    let parent_binding = parent.recovered_binding.as_ref().unwrap();
    validate_generation(&c, parent_provenance, parent_binding).unwrap();
    let template = generation_template(&c).unwrap();
    let (digest, row_count) = coordination_owner_rows_commitment(&c, template).unwrap();
    let mut provenance = provenance(row_count, new_binding.generation_id().as_bytes()[0]);
    provenance.application_id = RECOVERED_GENERATION_APPLICATION_ID;
    provenance.schema_version = template.schema_version;
    provenance.component_digest = digest.clone();
    let inventory = inventory(&c, &provenance).unwrap();
    let (rows, tables, bytes) = capture(&c).unwrap();
    let ordinal = generation_depth(&c).unwrap();
    let header = Layer {
        version: 2,
        ordinal,
        parent_generation_id: parent_binding.generation_id().into(),
        parent_inventory_digest: parent_binding.inventory_digest().into(),
        parent_provenance: parent_provenance.clone(),
        parent_schema_version: template.schema_version,
        parent_destination_identity: current_identity(&c, parent_binding).unwrap(),
        destination_identity: c
            .query_row("SELECT lower(hex(randomblob(32)))", [], |row| row.get(0))
            .unwrap(),
        generation_id: new_binding.generation_id().into(),
        inventory_digest: new_binding.inventory_digest().into(),
        source_provenance: provenance.clone(),
        previous_layer_digest: if ordinal > 1 {
            Some(
                c.query_row(
                    "SELECT digest FROM store_generation_layers WHERE ordinal=?1",
                    [(ordinal - 1) as i64],
                    |r| r.get(0),
                )
                .unwrap(),
            )
        } else {
            None
        },
        tables,
        rows: rows.len(),
        bytes,
    };
    let mut copy = Connection::open_in_memory().unwrap();
    rusqlite::backup::Backup::new(&c, &mut copy)
        .unwrap()
        .run_to_completion(128, std::time::Duration::ZERO, None)
        .unwrap();
    initialize_layer(&copy, &header, &rows, &inventory).unwrap();
    copy.pragma_update(
        None,
        "user_version",
        coordination_layered_successor_template().schema_version,
    )
    .unwrap();
    // The parent itself is never the transition destination, even in fixtures.
    assert_eq!(
        coordination_owner_rows_commitment(&c, template).unwrap().0,
        digest
    );
    let store = Store {
        connection: Mutex::new(copy),
        protection: StorageProtection::PlaintextDevelopment,
        original_database: None,
        recovered_generation: true,
        recovered_binding: Some(new_binding.clone()),
    };
    (store, provenance)
}

#[test]
fn layered_store_recovery_keeps_old_and_new_uncertainty_across_two_successors() {
    let (one, original, one_binding) = root();
    let original_destination = one.settlement_destination().unwrap();
    let first_context = agreement(&one, "generation-one-new");
    one.record_effect_intent(
        "new-effect",
        "send",
        "generation-one-new",
        &"a".repeat(64),
        "retained:new",
    )
    .unwrap();
    let two_binding = binding(2);
    let (two, two_source) = advance(&one, &original, &two_binding);
    assert_ne!(original_destination, two.settlement_destination().unwrap());
    assert_eq!(two.settled_debit("synthetic-account").unwrap(), "111");
    assert_eq!(two.outstanding_debit("synthetic-account").unwrap(), "222");
    assert_eq!(
        two.authority_account("synthetic-account")
            .unwrap()
            .unwrap()
            .writer_epoch,
        7
    );
    assert!(
        two.authority_account("synthetic-account")
            .unwrap()
            .unwrap()
            .recovery_required
    );
    assert!(two.recovery_state().unwrap().recovery_required);
    assert!(
        two.recovery_record_is_historical("agreement", "generation-one-new")
            .unwrap()
    );
    assert!(
        two.create_agreement(&first_context, "generation-one-new", serde_json::json!({}))
            .is_err()
    );
    assert!(
        two.settlement_obligation_requires_recovery("witness-generation-one")
            .unwrap()
    );
    let second_context = agreement(&two, "generation-two-new");
    two.add_recovery_obligation_fences(
        &two_binding,
        &BTreeSet::from(["witness-generation-two".into()]),
    )
    .unwrap();
    let (three, three_source) = advance(&two, &two_source, &binding(3));
    assert_ne!(
        three.settlement_destination().unwrap(),
        two.settlement_destination().unwrap()
    );
    assert!(
        three
            .create_agreement(&second_context, "generation-two-new", serde_json::json!({}))
            .is_err()
    );
    assert_eq!(three.settled_debit("synthetic-account").unwrap(), "111");
    assert_eq!(three.outstanding_debit("synthetic-account").unwrap(), "222");
    assert!(
        three
            .settlement_obligation_requires_recovery("witness-generation-one")
            .unwrap()
    );
    assert!(
        three
            .settlement_obligation_requires_recovery("witness-generation-two")
            .unwrap()
    );
    let c = three.connection.lock().unwrap();
    assert_eq!(generation_depth(&c).unwrap(), 3);
    validate_generation(&c, &three_source, &binding(3)).unwrap();
    verify_obligation_fences(
        &c,
        &one_binding,
        &BTreeSet::from(["witness-generation-one".into()]),
    )
    .unwrap();
    assert!(
        verify_obligation_fences(
            &c,
            &binding(3),
            &BTreeSet::from(["witness-generation-one".into()])
        )
        .is_err()
    );
    require_fence(&c, "effect", "new-effect").unwrap();
    require_fence(
        &c,
        "input",
        &request_digest(&serde_json::json!(["synthetic-account", "input-expired"])).unwrap(),
    )
    .unwrap();
}

#[test]
fn layered_store_recovery_rejects_counter_identity_and_parent_row_corruption() {
    for mutation in [
        "UPDATE authority_accounts SET writer_epoch=6",
        "UPDATE authority_exposures SET maximum_debit='0' WHERE authorization_id='charged'",
        "UPDATE authority_exposures SET state='expired_observed' WHERE authorization_id='expired'",
        "DROP TRIGGER store_generation_identities_no_update; UPDATE store_generation_identities SET destination_identity=printf('%064d',0) WHERE generation_id='0202020202020202020202020202020202020202020202020202020202020202'",
        "DROP TRIGGER store_generation_layer_rows_no_delete; DELETE FROM store_generation_layer_rows WHERE rowid=(SELECT min(rowid) FROM store_generation_layer_rows)",
        "DROP TRIGGER store_generation_fences_no_delete; DELETE FROM store_generation_fences WHERE kind='continuity_batch'",
    ] {
        let (one, original, _) = root();
        let (two, source) = advance(&one, &original, &binding(2));
        let c = two.connection.lock().unwrap();
        c.execute_batch(mutation).unwrap();
        assert!(
            validate_generation(&c, &source, &binding(2)).is_err(),
            "mutation must fail: {mutation}"
        );
    }
}

#[test]
fn layered_store_recovery_rejects_rebinding_and_saved_fence_downgrade() {
    let (one, original, _) = root();
    let (two, source) = advance(&one, &original, &binding(2));
    let c = two.connection.lock().unwrap();
    assert!(validate_generation(&c, &source, &binding(3)).is_err());
    assert!(
        c.execute("DELETE FROM store_generation_layers", [])
            .is_err()
    );
    assert!(
        c.execute(
            "UPDATE store_generation_identities SET inventory_digest=?1",
            ["0".repeat(64)]
        )
        .is_err()
    );
    assert!(
        c.execute("UPDATE store_generation_layer_rows SET payload='[]'", [])
            .is_err()
    );
    assert!(c.execute("UPDATE records SET payload='null' WHERE aggregate_type='settlement_generation_identity'",[]).is_err());
    c.execute_batch("DROP TRIGGER store_generation_fences_no_update; UPDATE store_generation_fences SET detail='[]' WHERE kind='continuity_batch';").unwrap();
    assert!(validate_generation(&c, &source, &binding(2)).is_err());
}

#[path = "tests/manual_audit_layers.rs"]
mod manual_audit_layers;
