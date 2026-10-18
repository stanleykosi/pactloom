//! Actual encrypted Store and generic Engine refusal tests. Source/association
//! digests are inert synthetic data, NOT genuine native owners or permissions.
//! These do not qualify the source-owned facade or native first-write ceremony.
use crate::*;
use std::os::unix::fs::PermissionsExt;
use wholepact_storage_security::DatabaseKey;
use wholepact_store::private_workspace_origin_v1::PrivateWorkspaceOriginV1;

struct Fixture {
    engine: Engine,
    access: Access,
    draft: AgreementDraft,
    command: CommandContext,
    result: MutationResult,
    path: std::path::PathBuf,
    key: DatabaseKey,
    directory: tempfile::TempDir,
}
fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.path().join("synthetic-private.sqlite");
    let key = DatabaseKey::from_bytes([118; 32]);
    let access = Access {
        principal_id: "synthetic-private-owner".into(),
        include_owned_agreements: true,
        ..Access::default()
    };
    let mut draft: AgreementDraft = serde_json::from_str(include_str!(
        "../../wholepact-core/tests/fixtures/agreement.json"
    ))
    .unwrap();
    draft.agreement_id = "synthetic-private-first-seed".into();
    draft.obligation_id = "synthetic-private-obligation".into();
    let source = Engine::in_memory().unwrap();
    source
        .create(&access, "synthetic-inert-source", draft.clone())
        .unwrap();
    let mut payload = source
        .store
        .get_agreement(&draft.agreement_id)
        .unwrap()
        .unwrap()
        .payload;
    payload["terms_editing_origin"] = json!(false);
    payload["view"]["roster_selected"] = json!(true);
    let store = Store::create_encrypted(&path, &key).unwrap();
    let marker = PrivateWorkspaceOriginV1 {
        version: 1,
        purpose: "durable-private-coordination-v1".into(),
        native_association_digest: "a".repeat(64),
        source_digest: "b".repeat(64),
        principal_id: access.principal_id.clone(),
        agreement_id: draft.agreement_id.clone(),
        obligation_id: draft.obligation_id.clone(),
        reviewer_account_ids: vec!["1".repeat(64), "2".repeat(64)],
        protected_destination: path.to_str().unwrap().into(),
        retention_policy: "Synthetic local retention, no native authority".into(),
        metadata_origin: hex::encode(store.verify_original_encrypted_destination(&path).unwrap()),
    };
    payload["private_workspace_origin_v1"] = serde_json::to_value(marker).unwrap();
    // Deliberately match a generic create command to exercise its exact replay
    // refusal. The low-level fixture is data, never a native association issuer.
    let command = context(
        &access,
        "synthetic-private-create",
        "create_agreement",
        &draft.agreement_id,
        None,
        &draft,
    )
    .unwrap();
    let result = store
        .create_agreement(&command, &draft.agreement_id, payload)
        .unwrap();
    Fixture {
        engine: Engine::from_store(store),
        access,
        draft,
        command,
        result,
        path,
        key,
        directory,
    }
}

fn assert_private_denial<T>(result: Result<T>) {
    match result {
        Err(error) => assert!(error.code == "DISCLOSURE_DENIED"),
        Ok(_) => panic!("private generic projection unexpectedly succeeded"),
    }
}

#[test]
fn encrypted_marker_only_seed_refuses_every_generic_projection_and_replay() {
    let f = fixture();
    let other = Access {
        principal_id: "synthetic-second-reader".into(),
        agreement_ids: [f.draft.agreement_id.clone()].into(),
        all_agreements: true,
        include_owned_agreements: true,
    };
    for access in [&f.access, &other] {
        assert_private_denial(f.engine.get(access, &f.draft.agreement_id));
        assert_private_denial(f.engine.list(access));
        assert_private_denial(f.engine.candidate(access, "any-candidate"));
        assert_private_denial(f.engine.events(access, 0, 10));
        assert_private_denial(f.engine.operation(access, &f.result.operation_id));
        assert_private_denial(f.engine.recovery(access));
        assert_private_denial(f.engine.cancel(
            access,
            "refused-private-cancel-v1",
            &f.draft.agreement_id,
            1,
        ));
    }
    assert_private_denial(
        f.engine
            .create(&f.access, "synthetic-private-create", f.draft.clone()),
    );
    assert_private_denial(f.engine.replay(&f.access, &f.command));
    for replayed in [false, true] {
        let mut result = f.result.clone();
        result.replayed = replayed;
        assert_private_denial(mutation(result));
    }
    let after = f
        .engine
        .store
        .get_agreement(&f.draft.agreement_id)
        .unwrap()
        .unwrap();
    assert!(after.revision == 1);
    assert!(after.payload == f.result.record.payload);
}

#[test]
fn generic_internal_commit_refuses_before_writing_marked_state() {
    let f = fixture();
    let mut envelope: Envelope = serde_json::from_value(f.result.record.payload.clone()).unwrap();
    envelope.view.cancellation_requested = true;
    let command = context(
        &f.access,
        "denied-private-write",
        "cancellation_requested",
        &f.draft.agreement_id,
        Some(1),
        &json!({}),
    )
    .unwrap();
    assert!(f
        .engine
        .commit(
            &command,
            &f.draft.agreement_id,
            1,
            envelope,
            "cancellation_requested"
        )
        .is_err());
    assert!(f.engine.store.find_replay(&command).unwrap().is_none());
    let after = f
        .engine
        .store
        .get_agreement(&f.draft.agreement_id)
        .unwrap()
        .unwrap();
    assert!(after.revision == 1);
    assert!(after.payload == f.result.record.payload);
}

#[test]
fn exact_encrypted_original_reopen_retains_marker_and_blocks_seed_only_backup() {
    let f = fixture();
    let marker = f.result.record.payload["private_workspace_origin_v1"].clone();
    let backup = f.directory.path().join("must-not-export.sqlite");
    assert!(f
        .engine
        .store
        .backup_agreement_journal(&backup, &DatabaseKey::from_bytes([119; 32]))
        .is_err());
    assert!(!backup.exists());
    drop(f.engine);
    let reopened = Engine::from_store(Store::open_encrypted(&f.path, &f.key).unwrap());
    let actual = reopened
        .store
        .get_agreement(&f.draft.agreement_id)
        .unwrap()
        .unwrap();
    assert!(actual.payload["private_workspace_origin_v1"] == marker);
    assert_private_denial(reopened.get(&f.access, &f.draft.agreement_id));
    assert_private_denial(reopened.operation(&f.access, &f.result.operation_id));
}

#[test]
fn malformed_or_null_marker_cannot_become_absent_during_envelope_decode() {
    let f = fixture();
    for marker in [json!(null), json!({}), json!(true)] {
        let mut record = f.result.record.clone();
        record.payload["private_workspace_origin_v1"] = marker;
        assert!(serde_json::from_value::<Envelope>(record.payload.clone()).is_err());
        assert!(decode(&record).is_err());
        assert!(decode_unprojected(&record).is_err());
    }
    let mut stripped = f.result.record.payload.clone();
    stripped
        .as_object_mut()
        .unwrap()
        .remove("private_workspace_origin_v1");
    let command =
        CommandContext::for_request(&f.access.principal_id, "strip-private-marker", &json!({}))
            .unwrap();
    assert!(f
        .engine
        .store
        .update_agreement(
            &command,
            &f.draft.agreement_id,
            1,
            stripped,
            "synthetic_marker_strip"
        )
        .is_err());
}

#[cfg(not(all(
    feature = "durable-proposal",
    feature = "manual-admission",
    target_os = "linux"
)))]
#[test]
fn unsupported_build_refuses_valid_private_marker_even_in_internal_decoder() {
    let f = fixture();
    assert!(decode_unprojected(&f.result.record).is_err());
}

#[test]
fn legacy_unmarked_generic_engine_still_reads_writes_and_replays() {
    let engine = Engine::in_memory().unwrap();
    let access = Access {
        principal_id: "legacy-owner".into(),
        include_owned_agreements: true,
        ..Access::default()
    };
    let mut draft: AgreementDraft = serde_json::from_str(include_str!(
        "../../wholepact-core/tests/fixtures/agreement.json"
    ))
    .unwrap();
    draft.agreement_id = "legacy-marker-compatibility".into();
    draft.obligation_id = "legacy-marker-obligation".into();
    engine
        .create(&access, "legacy-create-command-v1", draft.clone())
        .unwrap();
    assert!(
        engine
            .create(&access, "legacy-create-command-v1", draft.clone())
            .unwrap()
            .replayed
    );
    assert!(engine.get(&access, &draft.agreement_id).is_ok());
    assert!(engine.list(&access).unwrap().len() == 1);
    assert!(engine
        .cancel(&access, "legacy-cancel-command-v1", &draft.agreement_id, 1)
        .is_ok());
}
