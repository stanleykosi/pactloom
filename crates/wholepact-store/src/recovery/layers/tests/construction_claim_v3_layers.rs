//! Nonempty mixed-version history through actual encrypted synthetic G1/G2/G3
//! layers. This exercises private capture/restore kernels, not native issuance.
use super::*;
use crate::manual_enrollment::{
    append_modeled_initial_layer_audits,
    construction_claim_v2::{CONSTRUCTION_CLAIM_V2, append_modeled_construction_rows},
    construction_claim_v3::{
        CONSTRUCTION_CLAIM_V3, append_modeled_construction_rows_v3,
        append_modeled_historical_construction_rows_v5,
        append_modeled_reentered_construction_rows_v4, exact_manual_rows,
    },
};

#[test]
fn encrypted_common_context_v3_mixed_g2_g3_and_rebackup_preserve_original_rows_and_fences() {
    assert_encrypted_claim_layers_preserve_original_rows_and_fences(3);
}

#[test]
fn encrypted_reentry_v4_mixed_g2_g3_and_rebackup_preserve_original_rows_and_fences() {
    assert_encrypted_claim_layers_preserve_original_rows_and_fences(4);
}

#[test]
fn encrypted_historical_v5_mixed_g2_g3_and_rebackup_preserve_original_rows_and_fences() {
    // The ordinary5 source is restored into single8 before modeled born claims
    // are appended to that actual generation. This does not claim that an
    // ordinary source can invent an enrollment's future destination identity.
    assert_encrypted_claim_layers_preserve_original_rows_and_fences(5);
}

fn assert_encrypted_claim_layers_preserve_original_rows_and_fences(encoding: u16) {
    for with_checkpoint in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let one = root_encrypted(&directory.path().join("g1"));
        let root = append_modeled_initial_layer_audits(&one.store, 2);
        let (v2, v2_receipt) =
            append_modeled_construction_rows(&one.store, &root.0, !with_checkpoint);
        let v2_rows = exact_manual_rows(&one.store);
        let (v3, v3_receipt) = match encoding {
            3 => append_modeled_construction_rows_v3(&one.store, &root.0, with_checkpoint),
            4 => append_modeled_reentered_construction_rows_v4(&one.store, &root.0, with_checkpoint),
            5 => append_modeled_historical_construction_rows_v5(&one.store, &root.0, with_checkpoint),
            _ => panic!("unsupported synthetic claim encoding"),
        };
        assert_eq!(v3.version, encoding);
        assert_eq!(v3.historical_provenance.is_some(), encoding == 5);
        if encoding == 5 {
            assert_eq!(one.source.application_id, 0);
            assert_eq!(one.source.schema_version, 5);
            assert_eq!(
                generation_template(&one.store.connection.lock().unwrap()).unwrap().schema_version,
                8
            );
            v3.require_historical_provenance_v5().unwrap();
        }
        let claim_bytes = serde_json::to_vec(&v3).unwrap();
        let claim_digest = v3.digest().unwrap();
        let request_digest = v3.request_digest().unwrap();
        let receipt_bytes = serde_json::to_vec(&v3_receipt).unwrap();
        let exact = exact_manual_rows(&one.store);
        assert!(v2_rows.iter().all(|row| exact.contains(row)));
        let one_before = tree(&one.directory);
        let two = advance_encrypted(&one, &directory.path().join("g2"), 2);
        assert_eq!(exact_manual_rows(&two.store), exact);
        let two_before = tree(&two.directory);
        let three = advance_encrypted(&two, &directory.path().join("g3"), 3);
        assert_eq!(exact_manual_rows(&three.store), exact);
        let three_before = tree(&three.directory);
        let four = advance_encrypted(&three, &directory.path().join("g4-rebackup"), 4);
        for restored in [&two, &three, &four] {
            assert_eq!(exact_manual_rows(&restored.store), exact);
            assert!(
                restored
                    .store
                    .manual_roster_construction_evidence_v2(&v2.principal_id, &v2.construction_key)
                    .unwrap()
                    .unwrap()
                    == (v2.clone(), v2_receipt.clone())
            );
            let retained = restored
                .store
                .manual_roster_construction_evidence_v3(&v3.principal_id, &v3.construction_key)
                .unwrap()
                .unwrap();
            assert!(retained == (v3.clone(), v3_receipt.clone()));
            assert_eq!(serde_json::to_vec(&retained.0).unwrap(), claim_bytes);
            assert_eq!(retained.0.digest().unwrap(), claim_digest);
            assert_eq!(retained.0.request_digest().unwrap(), request_digest);
            assert_eq!(serde_json::to_vec(&retained.1).unwrap(), receipt_bytes);
            if encoding == 5 {
                assert_eq!(
                    generation_template(&restored.store.connection.lock().unwrap()).unwrap().schema_version,
                    9
                );
                assert!(
                    retained.0.require_historical_provenance_v5().unwrap()
                        == v3.require_historical_provenance_v5().unwrap()
                );
            }
            assert!(
                restored
                    .store
                    .recovery_record_is_historical(CONSTRUCTION_CLAIM_V2, &v2.digest().unwrap())
                    .unwrap()
            );
            assert!(
                restored
                    .store
                    .recovery_record_is_historical(CONSTRUCTION_CLAIM_V3, &v3.digest().unwrap())
                    .unwrap()
            );
            assert!(
                restored
                    .store
                    .require_unused_common_context_invocation(
                        &v3.principal_id,
                        &v3.construction_key,
                        v3.invocation()
                    )
                    .is_err()
            );
            assert!(
                restored
                    .store
                    .require_ordinary_financial_lineage(
                        &v3.proposal().manifest.agreement.agreement_id,
                        &v3.proposal().manifest.agreement.obligation_id,
                        &v3.principal_id,
                        Some(&v3.construction_key),
                        &[]
                    )
                    .is_err()
            );
            let context = CommandContext::for_request(
                &v3.principal_id,
                &v3.construction_key,
                &serde_json::json!({}),
            )
            .unwrap();
            assert!(restored.store.find_replay(&context).is_err());
            for audit in &v3.consumed {
                // Recovered history cannot return an apparently empty input
                // exclusion set that would invite reuse of the retained inputs.
                assert!(
                    restored.store.retained_financial_input_exclusions(
                        &audit.request.plan.enrollment().identity.account_id
                    ).is_err()
                );
                assert!(
                    restored
                        .store
                        .settlement_obligation_requires_recovery(
                            &audit.request.plan.enrollment().scope.obligation_id
                        )
                        .unwrap()
                );
            }
            assert_eq!(
                restored.store.settled_debit("synthetic-account").unwrap(),
                "111"
            );
            assert_eq!(
                restored
                    .store
                    .outstanding_debit("synthetic-account")
                    .unwrap(),
                "222"
            );
        }
        let guard = four.store.connection.lock().unwrap();
        let snapshot = four.snapshot();
        let c = snapshot.snapshot.connection();
        validate_generation(c, &four.source, &binding(4)).unwrap();
        let retained = inventory(c, &four.source).unwrap();
        assert_eq!(retained.construction_claims().len(), 1);
        assert_eq!(retained.construction_claims_v3().len(), 1);
        assert_eq!(
            retained.construction_checkpoints().len(),
            usize::from(!with_checkpoint)
        );
        assert_eq!(
            retained.construction_checkpoints_v3().len(),
            usize::from(with_checkpoint)
        );
        assert!(retained.construction_claims_v3()[0].1 == v3);
        drop(snapshot);
        drop(guard);
        assert_eq!(tree(&one.directory), one_before);
        assert_eq!(tree(&two.directory), two_before);
        assert_eq!(tree(&three.directory), three_before);
    }
}

#[test]
fn common_context_v3_templates_keep_legacy_markers_exact_and_reject_wrong_forms() {
    for version in 0..=10 {
        let ordinary = crate::bundle::coordination_template_for_schema(version);
        let single = coordination_successor_template_for_schema(version);
        let layered = coordination_layered_successor_template_for_schema(version);
        assert_eq!(ordinary.is_ok(), matches!(version, 1 | 2 | 3 | 4 | 5));
        assert_eq!(single.is_ok(), matches!(version, 2 | 4 | 6 | 8));
        assert_eq!(layered.is_ok(), matches!(version, 3 | 5 | 7 | 9));
        if let Ok(template) = ordinary {
            assert_eq!(template.schema_version, version);
            assert_eq!(template.application_id, 0);
        }
        if let Ok(template) = single {
            assert_eq!(template.schema_version, version);
            assert_eq!(template.application_id, RECOVERED_GENERATION_APPLICATION_ID);
        }
        if let Ok(template) = layered {
            assert_eq!(template.schema_version, version);
            assert_eq!(template.application_id, RECOVERED_GENERATION_APPLICATION_ID);
        }
    }
    assert_eq!(
        coordination_successor_template_for_schema(2)
            .unwrap()
            .create_sql,
        coordination_successor_template_for_schema(4)
            .unwrap()
            .create_sql
    );
    assert_eq!(
        coordination_layered_successor_template_for_schema(3)
            .unwrap()
            .create_sql,
        coordination_layered_successor_template_for_schema(5)
            .unwrap()
            .create_sql
    );
}

#[test]
fn encrypted_common_context_v3_legacy_g2_g3_keep_versions_and_deny_new_encoding() {
    let directory = tempfile::tempdir().unwrap();
    let one = root_encrypted_for_schema(&directory.path().join("legacy-single"), 2, 2);
    let root = append_modeled_initial_layer_audits(&one.store, 2);
    let (v2, receipt) = append_modeled_construction_rows(&one.store, &root.0, true);
    // The same pre-V3 immutable SQL/row layout deliberately models historical
    // ordinary schema2 restored into single-generation schema2, not schema3.
    {
        let connection = one.store.connection.lock().unwrap();
        validate_generation(&connection, &one.source, &binding(1)).unwrap();
        assert!(crate::backup::require_construction_v3_encoding(&connection).is_err());
        assert_eq!(generation_template(&connection).unwrap().schema_version, 2);
    }
    let exact = exact_manual_rows(&one.store);
    let one_before = tree(&one.directory);
    let two = advance_encrypted_for_schema(&one, &directory.path().join("legacy-layered"), 2, 3);
    {
        let connection = two.store.connection.lock().unwrap();
        // Every parent is legacy2, so the unchanged historical layered3 shape
        // is valid. No V3 claim may ever be written beneath this marker.
        validate_generation(&connection, &two.source, &binding(2)).unwrap();
        assert!(crate::backup::require_construction_v3_encoding(&connection).is_err());
        assert_eq!(generation_template(&connection).unwrap().schema_version, 3);
    }
    let two_before = tree(&two.directory);
    let three = advance_encrypted(&two, &directory.path().join("new-layered"), 3);
    {
        let connection = three.store.connection.lock().unwrap();
        assert_eq!(generation_template(&connection).unwrap().schema_version, 9);
        crate::backup::require_construction_v3_encoding(&connection).unwrap();
        validate_generation(&connection, &three.source, &binding(3)).unwrap();
    }
    assert_eq!(exact_manual_rows(&three.store), exact);
    assert!(
        three
            .store
            .manual_roster_construction_evidence_v2(&v2.principal_id, &v2.construction_key)
            .unwrap()
            .unwrap()
            == (v2, receipt)
    );
    assert_eq!(tree(&one.directory), one_before);
    assert_eq!(tree(&two.directory), two_before);
}

// Inert compiled-schema fixtures exercise the exact private read projection,
// not a snapshot/opener factory. No file, key, native owner or write admission.
#[test]
fn common_context_v3_immutable_projection_rejects_legacy_encoding_before_absence() {
    for version in [2, 3, 4, 5, 6, 7, 8, 9] {
        let c = Connection::open_in_memory().unwrap();
        let template = match version {
            2 | 4 | 6 | 8 => coordination_successor_template_for_schema(version).unwrap(),
            _ => coordination_layered_successor_template_for_schema(version).unwrap(),
        };
        c.execute_batch(template.create_sql).unwrap();
        c.pragma_update(None, "application_id", template.application_id)
            .unwrap();
        c.pragma_update(None, "user_version", version).unwrap();
        c.execute_batch("PRAGMA query_only=ON; BEGIN DEFERRED;")
            .unwrap();
        let before = c.total_changes();
        let result = read_snapshot_construction_evidence_v3(
            &c,
            "synthetic-principal",
            "missing-construction-key",
        );
        if version <= 3 {
            assert!(
                matches!(result, Err(StoreError::RecoveryRequired)),
                "legacy version {version} must be unsupported, never absent"
            );
        } else {
            assert!(result.unwrap().is_none());
        }
        assert_eq!(c.total_changes(), before);
        assert_eq!(
            c.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                .unwrap(),
            version
        );
    }
}

#[test]
fn reentry_v4_original_rows_and_inventory_reject_every_legacy_source_marker() {
    // Restriction-unit fixture only. An inert row set cannot create a sealed
    // generation, native owner, successor writer, or construction admission.
    let store = Store::in_memory().unwrap();
    let root =
        crate::manual_enrollment::construction_claim_v2::append_modeled_construction_root(&store);
    let (claim, _) = append_modeled_reentered_construction_rows_v4(&store, &root, true);
    let c = store.connection.lock().unwrap();
    let current = provenance(1, 1);
    assert_eq!(current.schema_version, 5);
    assert!(inventory(&c, &current).unwrap().construction_claims_v3()[0].1 == claim);
    c.execute_batch(include_str!("../../../recovery-schema.sql"))
        .unwrap();
    let row = read_rows(
        &c,
        &BASE[0],
        &format!("WHERE aggregate_type='{CONSTRUCTION_CLAIM_V3}'"),
    )
    .unwrap()
    .pop()
    .unwrap();
    c.execute(
        "INSERT INTO store_generation_original_rows VALUES('records',0,?1)",
        [serde_json::to_string(&row.cells).unwrap()],
    )
    .unwrap();
    add_row_restrictions(&c, "records", &row.cells).unwrap();
    validate_originals(&c, &current).unwrap();
    let before = c.total_changes();
    for (application, version, supported) in [
        (0, 1, false),
        (0, 2, false),
        (0, 3, false),
        (0, 4, true),
        (0, 5, true),
        (RECOVERED_GENERATION_APPLICATION_ID, 2, false),
        (RECOVERED_GENERATION_APPLICATION_ID, 3, false),
        (RECOVERED_GENERATION_APPLICATION_ID, 4, false),
        (RECOVERED_GENERATION_APPLICATION_ID, 5, false),
        (RECOVERED_GENERATION_APPLICATION_ID, 6, true),
        (RECOVERED_GENERATION_APPLICATION_ID, 7, true),
        (RECOVERED_GENERATION_APPLICATION_ID, 8, true),
        (RECOVERED_GENERATION_APPLICATION_ID, 9, true),
    ] {
        let mut source = current.clone();
        source.application_id = application;
        source.schema_version = version;
        assert_eq!(inventory(&c, &source).is_ok(), supported);
        assert_eq!(validate_originals(&c, &source).is_ok(), supported);
    }
    assert_eq!(c.total_changes(), before);
}

#[test]
fn encrypted_reentry_v4_recursive_targets_reject_old_markers_without_changing_sources() {
    let directory = tempfile::tempdir().unwrap();
    let one = root_encrypted(&directory.path().join("g1"));
    let root = append_modeled_initial_layer_audits(&one.store, 2);
    let (claim, _) = append_modeled_reentered_construction_rows_v4(&one.store, &root.0, true);
    let one_before = tree(&one.directory);
    let two = advance_encrypted(&one, &directory.path().join("g2"), 2);
    let before = tree(&two.directory);
    let _guard = two.store.connection.lock().unwrap();
    let snapshot = two.snapshot();
    let c = snapshot.snapshot.connection();
    validate_generation(c, &two.source, &binding(2)).unwrap();
    let current = coordination_layered_successor_template_for_schema(9).unwrap();
    validate_layered_for_template(c, &two.source, &binding(2), current).unwrap();
    for version in [3, 5, 7] {
        let legacy = coordination_layered_successor_template_for_schema(version).unwrap();
        assert!(validate_layered_for_template(c, &two.source, &binding(2), legacy).is_err());
    }
    let (header, _) = load_headers(c).unwrap().remove(0);
    let rows = load_layer_rows(c, &header).unwrap();
    verify_parent_commitment(c, &header, &rows).unwrap();
    for version in [2, 4, 6] {
        let mut changed = header.clone();
        changed.parent_schema_version = version;
        changed.source_provenance.schema_version = version;
        assert!(verify_parent_commitment(c, &changed, &rows).is_err());
    }
    assert!(
        snapshot
            .manual_roster_construction_evidence_v3(&claim.principal_id, &claim.construction_key,)
            .unwrap()
            .unwrap()
            .0
            == claim
    );
    snapshot.check_source_unchanged().unwrap();
    assert_eq!(tree(&one.directory), one_before);
    assert_eq!(tree(&two.directory), before);
}

#[test]
fn encrypted_reentry_v4_old_nonempty_history_keeps_exact_legacy_layers_after_upgrade() {
    let directory = tempfile::tempdir().unwrap();
    let one = root_encrypted_for_schema(&directory.path().join("v3-single"), 3, 4);
    let root = append_modeled_initial_layer_audits(&one.store, 2);
    let (claim, receipt) = append_modeled_construction_rows_v3(&one.store, &root.0, true);
    let exact = exact_manual_rows(&one.store);
    let one_before = tree(&one.directory);
    let two = advance_encrypted_for_schema(&one, &directory.path().join("v3-layered"), 2, 5);
    let two_before = tree(&two.directory);
    let three = advance_encrypted(&two, &directory.path().join("v4-layered"), 3);
    assert_eq!(exact_manual_rows(&three.store), exact);
    assert!(
        three
            .store
            .manual_roster_construction_evidence_v3(&claim.principal_id, &claim.construction_key,)
            .unwrap()
            .unwrap()
            == (claim, receipt)
    );
    let _guard = three.store.connection.lock().unwrap();
    let snapshot = three.snapshot();
    let c = snapshot.snapshot.connection();
    validate_generation(c, &three.source, &binding(3)).unwrap();
    let headers = load_headers(c).unwrap();
    assert_eq!(headers[0].0.parent_schema_version, 4);
    assert_eq!(headers[0].0.parent_provenance.schema_version, 3);
    assert_eq!(headers[1].0.parent_schema_version, 5);
    assert_eq!(generation_template(c).unwrap().schema_version, 9);
    assert_eq!(tree(&one.directory), one_before);
    assert_eq!(tree(&two.directory), two_before);
}
