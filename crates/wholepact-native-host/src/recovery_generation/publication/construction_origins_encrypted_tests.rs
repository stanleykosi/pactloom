//! Real sealed-metadata roundtrips with ledger-derived nonempty construction.
//! Saved audit records only; no native admission, sockets or financial action.
use super::*;
use wholepact_storage_security::bundle::JournalKind;
fn evidence() -> HostRecoveryContinuityEvidenceV3 {
    serde_json::from_str(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../wholepact-signer/src/authority_bridge/host_recovery_ipc/v3/fixtures/nonempty_evidence.json"))).unwrap()
}
fn components(layered: bool) -> Vec<RecoveryProvenance> {
    [
        ("coordination", JournalKind::CoordinationAuthority),
        ("inbox", JournalKind::TransportInbox),
        ("outbox", JournalKind::TransportOutbox),
        ("submission", JournalKind::Submission),
    ]
    .into_iter()
    .map(|(id, kind)| {
        let t = if kind == JournalKind::CoordinationAuthority {
            wholepact_store::recovery::coordination_successor_template()
        } else {
            super::super::archive_history::template(kind).unwrap()
        };
        RecoveryProvenance {
            profile_id: "synthetic-source".into(),
            checkpoint_id: "33".repeat(32),
            bundle_digest: "22".repeat(32),
            component_id: if layered {
                format!("root-{id}")
            } else {
                id.into()
            },
            kind,
            component_digest: "77".repeat(32),
            application_id: t.application_id,
            schema_version: t.schema_version,
            rows: 0,
        }
    })
    .collect()
}
fn metadata(
    secrets: &Secrets,
    plan_digest: &str,
    generation: &str,
    inventory: &str,
    target: &std::path::Path,
) -> (Vec<u8>, Vec<u8>, HostRecoveryContinuityEvidenceV3) {
    let mut e = evidence();
    e.request.generation_id = generation.into();
    e.request.inventory_digest = inventory.into();
    e.validate().unwrap();
    let manifest = ManifestV3 {
        version: 3,
        plan_digest: plan_digest.into(),
        continuity: vec![e.clone()],
        unmatched_host_authorizations: BTreeSet::new(),
        unresolved_offline_authorizations: BTreeSet::new(),
        unknown_external_signatures: true,
        recovered_obligations_fenced: true,
        financial_freshness_established: false,
    };
    let sealed = seal(secrets, b"manifest", &encode(&manifest).unwrap()).unwrap();
    let record = HostRecoveryPublicationRecordV3 {
        request: HostRecoveryPublicationRequestV3 {
            schema_version: 3,
            continuity: e.request.clone(),
            target_profile: target.into(),
            generation_manifest_digest: hash(&sealed),
            continuity_evidence_digest: e.digest().unwrap(),
        },
        native_review_digest: "55".repeat(32),
        admission_id: "66".repeat(32),
    };
    let commit = CommitV3 {
        version: 3,
        plan_digest: plan_digest.into(),
        manifest_digest: hash(&sealed),
        admissions: vec![record],
    };
    (
        sealed,
        seal(secrets, b"commit", &encode(&commit).unwrap()).unwrap(),
        e,
    )
}
fn check_preserved(secrets: &Secrets, manifest: &[u8], e: &HostRecoveryContinuityEvidenceV3) {
    let plain = unseal(secrets, b"manifest", manifest).unwrap();
    let restored: ManifestV3 = serde_json::from_slice(&plain).unwrap();
    assert!(restored.continuity[0] == *e);
    assert_eq!(
        restored.continuity[0]
            .complete_history
            .conservative_debit_zatoshis()
            .unwrap(),
        400_012_000
    );
    assert_eq!(
        restored.continuity[0]
            .complete_history
            .construction
            .retained_input_value_zatoshis()
            .unwrap(),
        500_000_000
    );
    assert!(
        restored.continuity[0]
            .complete_history
            .construction
            .origins()[0]
            .consumed()
            .is_some()
    );
    assert!(
        restored.continuity[0]
            .complete_history
            .require_financial_activation_supported()
            .is_err()
    );
}
#[test]
fn ordinary_encrypted_v3_metadata_roundtrip_preserves_nonempty_ledger_archive_and_rejects_omission()
{
    let fresh = Secrets::fresh().unwrap();
    let e = evidence();
    let plan = Plan {
        version: 1,
        generation_id: "11".repeat(32),
        inventory_digest: "22".repeat(32),
        target: "/synthetic-absent/construction-v3-ordinary".into(),
        source_profile: "synthetic-source".into(),
        successor_profile: fresh.profile(),
        components: components(false),
        affected_accounts: BTreeSet::from([e.request.account_id.clone()]),
        semantic_inventory_digest: "44".repeat(32),
        unknown_external_signatures: true,
        recovered_obligations_fenced: true,
    };
    let plain = encode(&plan).unwrap();
    let digest = hash(&plain);
    let secrets = fresh
        .bind_successor_plan(Sha256::digest(&plain).into())
        .unwrap();
    let sealed_plan = seal(&secrets, b"plan", &plain).unwrap();
    let (manifest, commit, e) = metadata(
        &secrets,
        &digest,
        &plan.generation_id,
        &plan.inventory_digest,
        &plan.target,
    );
    let keys = seal(
        &secrets,
        &[b"keys:".as_slice(), digest.as_bytes()].concat(),
        &[23u8; 128],
    )
    .unwrap();
    let originals = (
        sealed_plan.clone(),
        manifest.clone(),
        commit.clone(),
        keys.clone(),
    );
    let commit_plain = unseal(&secrets, b"commit", &commit).unwrap();
    let checked = super::super::complete_origins::checked_metadata_bytes_dispatch(
        &plan.target,
        &secrets,
        &commit_plain,
        &sealed_plan,
        &manifest,
        &keys,
    )
    .unwrap();
    assert_eq!(
        checked.restrictions,
        e.complete_history.conservative_obligations().unwrap()
    );
    check_preserved(&secrets, &manifest, &e);
    let mut changed: serde_json::Value =
        serde_json::from_slice(&unseal(&secrets, b"manifest", &manifest).unwrap()).unwrap();
    changed["continuity"][0]["complete_history"]["construction"]["origins"] = serde_json::json!([]);
    let altered = seal(
        &secrets,
        b"manifest",
        &serde_json::to_vec(&changed).unwrap(),
    )
    .unwrap();
    assert!(
        super::super::complete_origins::checked_metadata_bytes_dispatch(
            &plan.target,
            &secrets,
            &commit_plain,
            &sealed_plan,
            &altered,
            &keys
        )
        .is_err()
    );
    assert_eq!(originals, (sealed_plan, manifest, commit, keys));
}
#[test]
fn layered_encrypted_v3_metadata_roundtrip_preserves_nonempty_ledger_archive_and_parent_binding() {
    let fresh = Secrets::fresh().unwrap();
    let e = evidence();
    let plan = super::super::layered_metadata::LayeredPlan {
        version: 2,
        generation_id: "11".repeat(32),
        inventory_digest: "22".repeat(32),
        target: "/synthetic-absent/construction-v3-layered".into(),
        source_profile: "synthetic-source".into(),
        successor_profile: fresh.profile(),
        parent_manifest_digest: "22".repeat(32),
        parent_capsule_id: "33".repeat(32),
        parent_node_generation: "44".repeat(32),
        parent_key_commitment: super::super::layered_metadata::parent_key_commitment(&[23; 32])
            .unwrap(),
        components: components(true),
        affected_accounts: BTreeSet::from([e.request.account_id.clone()]),
        semantic_inventory_digest: "55".repeat(32),
        unknown_external_signatures: true,
        recovered_obligations_fenced: true,
    };
    plan.validate().unwrap();
    let plain = encode(&plan).unwrap();
    let digest = hash(&plain);
    let secrets = fresh
        .bind_successor_plan(Sha256::digest(&plain).into())
        .unwrap();
    let sealed_plan = seal(&secrets, b"plan", &plain).unwrap();
    let (manifest, commit, e) = metadata(
        &secrets,
        &digest,
        &plan.generation_id,
        &plan.inventory_digest,
        &plan.target,
    );
    let purpose = [b"keys:".as_slice(), digest.as_bytes()].concat();
    let keys = seal(&secrets, &purpose, &[23; 32]).unwrap();
    let original = (
        sealed_plan.clone(),
        manifest.clone(),
        commit.clone(),
        keys.clone(),
    );
    let checked = super::super::layered_metadata::checked_layered_metadata_bytes(
        &plan.target,
        &secrets,
        &sealed_plan,
        &manifest,
        &commit,
        &keys,
    )
    .unwrap();
    assert_eq!(
        checked.restrictions,
        e.complete_history.conservative_obligations().unwrap()
    );
    assert_eq!(checked.parent_key.as_slice(), &[23; 32]);
    check_preserved(&secrets, &manifest, &e);
    let wrong = seal(&secrets, &purpose, &[24; 32]).unwrap();
    assert!(
        super::super::layered_metadata::checked_layered_metadata_bytes(
            &plan.target,
            &secrets,
            &sealed_plan,
            &manifest,
            &commit,
            &wrong
        )
        .is_err()
    );
    let mut corrupted = commit.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 1;
    assert!(
        super::super::layered_metadata::checked_layered_metadata_bytes(
            &plan.target,
            &secrets,
            &sealed_plan,
            &manifest,
            &corrupted,
            &keys
        )
        .is_err()
    );
    assert_eq!(original, (sealed_plan, manifest, commit, keys));
}

#[test]
fn committed_v3_financial_opener_refuses_before_reading_or_mutating_files() {
    let temp = tempfile::tempdir().unwrap();
    let directory = Directory::create(&temp.path().join("v3-disabled")).unwrap();
    let secrets = Secrets::fresh().unwrap();
    let commit = CommitV3 {
        version: 3,
        plan_digest: "11".repeat(32),
        manifest_digest: "22".repeat(32),
        admissions: vec![],
    };
    assert!(matches!(
        open_checked_v3(&directory, &secrets, &commit, false),
        Err(Error::RecoveryFinancialUnsupported)
    ));
    let entries: Vec<_> = std::fs::read_dir(temp.path().join("v3-disabled"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(entries, vec![std::ffi::OsString::from("profile.lock")]);
    assert!(
        std::fs::read(temp.path().join("v3-disabled/profile.lock"))
            .unwrap()
            .is_empty()
    );
}
