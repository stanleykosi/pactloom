//! Never-funded canonical synthetic transport history. Historical audit metadata
//! is inert: these tests create no NativeDecision, native admission, sockets,
//! provider reads, proofs, restored writer capability or financial operation.
use super::super::retained_continuity_fixture as fixture;
use super::*;
use wholepact_storage_security::bundle::JournalKind;

fn metadata(e: HostRecoveryContinuityEvidenceV5) -> (ManifestV5, CommitV5) {
    let manifest = ManifestV5 {
        version: 5,
        plan_digest: "11".repeat(32),
        unresolved_offline_authorizations: e
            .complete_history
            .unresolved_offline_authorizations()
            .unwrap(),
        continuity: vec![e],
        unmatched_host_authorizations: BTreeSet::new(),
        unknown_external_signatures: true,
        recovered_obligations_fenced: true,
        financial_freshness_established: false,
    };
    let commit = audit_commit(
        &manifest,
        &"22".repeat(32),
        std::path::Path::new("/synthetic/transport-v5"),
    );
    (manifest, commit)
}
fn audit_commit(manifest: &ManifestV5, digest: &str, target: &std::path::Path) -> CommitV5 {
    // Saved historical records only. No conversion to live admission exists.
    CommitV5 {
        version: 5,
        plan_digest: manifest.plan_digest.clone(),
        manifest_digest: digest.into(),
        admissions: requests(manifest, target, digest)
            .unwrap()
            .into_iter()
            .map(|request| HostRecoveryPublicationRecordV5 {
                request,
                native_review_digest: "33".repeat(32),
                admission_id: "44".repeat(32),
            })
            .collect(),
    }
}
fn check(manifest: &ManifestV5, commit: &CommitV5) -> Result<BTreeSet<String>> {
    let e = fixture::fixture();
    validate_metadata_v5(
        &encode(manifest)?,
        &encode(commit)?,
        &"22".repeat(32),
        &"11".repeat(32),
        &e.request.generation_id,
        &e.request.inventory_digest,
        std::path::Path::new("/synthetic/transport-v5"),
        &BTreeSet::from([e.request.account_id]),
    )
}
fn assert_preserved(
    actual: &HostRecoveryContinuityEvidenceV5,
    expected: &HostRecoveryContinuityEvidenceV5,
) {
    assert!(actual == expected);
    let history = &actual.complete_history;
    assert!(history.conservative_debit_zatoshis().unwrap() > 0);
    assert!(!history.conservative_obligations().unwrap().is_empty());
    assert!(!history.construction.transport.credentials.is_empty());
    assert!(!history.construction.transport.reservations.is_empty());
    assert!(!history.construction.transport.consumptions.is_empty());
    assert!(
        history
            .construction
            .observed_snapshot()
            .transport_fences
            .is_some()
    );
    assert!(history.require_financial_activation_supported().is_err());
}

#[test]
fn complete_v5_metadata_keeps_signed_transport_and_requires_live_admissions() {
    let e = fixture::fixture();
    let (manifest, commit) = metadata(e.clone());
    assert_eq!(
        check(&manifest, &commit).unwrap(),
        e.complete_history.conservative_obligations().unwrap()
    );
    let rows = checked_continuity_rows(&encode(&manifest).unwrap()).unwrap();
    assert_preserved(&rows[0], &e);
    assert!(
        consume_admissions(
            &manifest,
            std::path::Path::new("/synthetic/transport-v5"),
            &"22".repeat(32),
            vec![]
        )
        .is_err()
    );
    assert!(wholepact_signer::authority_bridge::host_recovery_ipc::v5::require_construction_transport_recovery_endpoint().is_err());
}

#[test]
fn all_plan_manifest_account_and_inventory_bindings_are_exact() {
    let e = fixture::fixture();
    let (manifest, commit) = metadata(e.clone());
    let m = encode(&manifest).unwrap();
    let c = encode(&commit).unwrap();
    let accounts = BTreeSet::from([e.request.account_id.clone()]);
    for which in 0..6 {
        assert!(
            validate_metadata_v5(
                &m,
                &c,
                &if which == 0 {
                    "ee".repeat(32)
                } else {
                    "22".repeat(32)
                },
                &if which == 1 {
                    "ee".repeat(32)
                } else {
                    "11".repeat(32)
                },
                &if which == 2 {
                    "ee".repeat(32)
                } else {
                    e.request.generation_id.clone()
                },
                &if which == 3 {
                    "ee".repeat(32)
                } else {
                    e.request.inventory_digest.clone()
                },
                std::path::Path::new(if which == 4 {
                    "/synthetic/other"
                } else {
                    "/synthetic/transport-v5"
                }),
                &if which == 5 {
                    BTreeSet::new()
                } else {
                    accounts.clone()
                },
            )
            .is_err(),
            "binding {which}"
        );
    }
    let (mut m, c) = metadata(e.clone());
    m.continuity.push(e.clone());
    assert!(check(&m, &c).is_err());
    let (m, mut c) = metadata(e.clone());
    c.admissions.clear();
    assert!(check(&m, &c).is_err());
    let (m, mut c) = metadata(e.clone());
    c.admissions
        .push(serde_json::from_value(serde_json::to_value(&c.admissions[0]).unwrap()).unwrap());
    assert!(check(&m, &c).is_err());
    let (m, mut c) = metadata(e);
    c.admissions[0].request.continuity_evidence_digest = "ee".repeat(32);
    assert!(check(&m, &c).is_err());
}

#[test]
fn absent_native_success_keeps_charge_and_fences_and_changes_the_review_digest() {
    let e = fixture::fixture();
    let debit = e.complete_history.conservative_debit_zatoshis().unwrap();
    let obligations = e.complete_history.conservative_obligations().unwrap();
    let fences = e
        .complete_history
        .construction
        .observed_snapshot()
        .transport_fences
        .clone();
    let (mut manifest, original_commit) = metadata(e);
    let history = &mut manifest.continuity[0].complete_history;
    history.signer_common_context_audit.original.rows.clear();
    history.signer_common_context_audit.reentry.rows.clear();
    assert_eq!(history.conservative_debit_zatoshis().unwrap(), debit);
    assert_eq!(history.conservative_obligations().unwrap(), obligations);
    assert!(history.construction.observed_snapshot().transport_fences == fences);
    assert!(
        history
            .missing_local_native_phases()
            .unwrap()
            .transport
            .iter()
            .any(|m| m.missing_consumed)
    );
    manifest.continuity[0].validate().unwrap();
    assert!(check(&manifest, &original_commit).is_err());
    let revised = audit_commit(
        &manifest,
        &"22".repeat(32),
        std::path::Path::new("/synthetic/transport-v5"),
    );
    assert_eq!(check(&manifest, &revised).unwrap(), obligations);
    assert!(
        manifest.continuity[0]
            .complete_history
            .require_financial_activation_supported()
            .is_err()
    );
}

#[test]
fn downgrade_markers_missing_origins_and_unknown_authority_fail_closed() {
    let (manifest, commit) = metadata(fixture::fixture());
    for version in [1, 2, 3, 4, 6] {
        let mut m: ManifestV5 = serde_json::from_slice(&encode(&manifest).unwrap()).unwrap();
        m.version = version;
        assert!(check(&m, &commit).is_err());
        let mut c: CommitV5 = serde_json::from_slice(&encode(&commit).unwrap()).unwrap();
        c.version = version;
        assert!(check(&manifest, &c).is_err());
    }
    for field in [
        "native_admission",
        "approved",
        "current_financial_capability",
    ] {
        let mut m = serde_json::to_value(&manifest).unwrap();
        m[field] = true.into();
        assert!(serde_json::from_value::<ManifestV5>(m).is_err());
    }
    for field in ["transport", "original"] {
        let mut m = serde_json::to_value(&manifest).unwrap();
        m["continuity"][0]["complete_history"]["construction"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(serde_json::from_value::<ManifestV5>(m).is_err());
    }
    let encoded = serde_json::to_string(&manifest).unwrap();
    let duplicate = format!("{{\"version\":5,{}", &encoded[1..]);
    assert!(serde_json::from_str::<ManifestV5>(&duplicate).is_err());
    assert!(
        serde_json::from_slice::<super::super::common_context_origins::ManifestV4>(
            &encode(&manifest).unwrap()
        )
        .is_err()
    );
    for field in [
        "unknown_external_signatures",
        "recovered_obligations_fenced",
        "financial_freshness_established",
    ] {
        let mut value = serde_json::to_value(&manifest).unwrap();
        value[field] = (field == "financial_freshness_established").into();
        let changed: ManifestV5 = serde_json::from_value(value).unwrap();
        assert!(check(&changed, &commit).is_err());
    }
}

#[test]
fn signed_transport_tamper_and_changed_local_evidence_cannot_reuse_saved_review() {
    let (manifest, commit) = metadata(fixture::fixture());
    for field in ["old_key_fence_digest", "credential_id"] {
        let mut m = serde_json::to_value(&manifest).unwrap();
        m["continuity"][0]["complete_history"]["construction"]["transport"]["credentials"][0]
            [field] = "ee".repeat(32).into();
        let result = serde_json::from_value::<ManifestV5>(m);
        assert!(result.is_err() || check(&result.unwrap(), &commit).is_err());
    }
    let mut changed = serde_json::to_value(&manifest).unwrap();
    changed["continuity"][0]["complete_history"]["construction"]["transport"]["credentials"][0]["signed_claim"]
        ["claim"]["new_caller_binding_digest"] = "ee".repeat(32).into();
    let changed: ManifestV5 = serde_json::from_value(changed).unwrap();
    assert!(changed.continuity[0].validate().is_err());
    assert!(check(&changed, &commit).is_err());
    let mut m: ManifestV5 = serde_json::from_slice(&encode(&manifest).unwrap()).unwrap();
    m.continuity[0]
        .complete_history
        .signer_common_context_audit
        .reentry
        .rows
        .clear();
    m.continuity[0].validate().unwrap();
    assert!(check(&m, &commit).is_err());
    assert!(
        validate_metadata_v5(
            &vec![b' '; MAX_DOCUMENT + 1],
            &encode(&commit).unwrap(),
            &"22".repeat(32),
            &"11".repeat(32),
            &m.continuity[0].request.generation_id,
            &m.continuity[0].request.inventory_digest,
            std::path::Path::new("/synthetic/transport-v5"),
            &BTreeSet::from([m.continuity[0].request.account_id.clone()]),
        )
        .is_err()
    );
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
        let template = if kind == JournalKind::CoordinationAuthority {
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
            application_id: template.application_id,
            schema_version: template.schema_version,
            rows: 0,
        }
    })
    .collect()
}
fn encrypted_metadata(
    secrets: &Secrets,
    plan_digest: &str,
    generation: &str,
    inventory: &str,
    target: &std::path::Path,
) -> (Vec<u8>, Vec<u8>, HostRecoveryContinuityEvidenceV5) {
    let mut e = fixture::fixture();
    e.request.generation_id = generation.into();
    e.request.inventory_digest = inventory.into();
    e.validate().unwrap();
    let (mut manifest, _) = metadata(e.clone());
    manifest.plan_digest = plan_digest.into();
    let sealed = seal(secrets, b"manifest", &encode(&manifest).unwrap()).unwrap();
    let commit = audit_commit(&manifest, &hash(&sealed), target);
    (
        sealed,
        seal(secrets, b"commit", &encode(&commit).unwrap()).unwrap(),
        e,
    )
}

#[test]
fn ordinary_encrypted_v5_metadata_keeps_full_nonempty_history_and_original_source_bytes() {
    let fresh = Secrets::fresh().unwrap();
    let e = fixture::fixture();
    let plan = Plan {
        version: 1,
        generation_id: "11".repeat(32),
        inventory_digest: "22".repeat(32),
        target: "/synthetic-absent/transport-v5-ordinary".into(),
        source_profile: "synthetic-source".into(),
        successor_profile: fresh.profile(),
        components: components(false),
        affected_accounts: BTreeSet::from([e.request.account_id]),
        semantic_inventory_digest: "55".repeat(32),
        unknown_external_signatures: true,
        recovered_obligations_fenced: true,
    };
    let plan_plain = encode(&plan).unwrap();
    let digest = hash(&plan_plain);
    let secrets = fresh
        .bind_successor_plan(Sha256::digest(&plan_plain).into())
        .unwrap();
    let sealed_plan = seal(&secrets, b"plan", &plan_plain).unwrap();
    let (manifest, commit, e) = encrypted_metadata(
        &secrets,
        &digest,
        &plan.generation_id,
        &plan.inventory_digest,
        &plan.target,
    );
    let purpose = [b"keys:".as_slice(), digest.as_bytes()].concat();
    let keys = seal(&secrets, &purpose, &[23u8; 128]).unwrap();
    let source = (
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
    assert!(checked.plan == plan);
    assert_eq!(
        checked.restrictions,
        e.complete_history.conservative_obligations().unwrap()
    );
    let retained =
        checked_continuity_rows(&unseal(&secrets, b"manifest", &manifest).unwrap()).unwrap();
    assert_preserved(&retained[0], &e);
    let wrong_keys = seal(&secrets, &purpose, &[23u8; 127]).unwrap();
    assert!(
        super::super::complete_origins::checked_metadata_bytes_dispatch(
            &plan.target,
            &secrets,
            &commit_plain,
            &sealed_plan,
            &manifest,
            &wrong_keys,
        )
        .is_err()
    );
    assert!(
        super::super::complete_origins::checked_metadata_bytes_dispatch(
            std::path::Path::new("/synthetic/other"),
            &secrets,
            &commit_plain,
            &sealed_plan,
            &manifest,
            &keys,
        )
        .is_err()
    );
    let mut altered = manifest.clone();
    let last = altered.len() - 1;
    altered[last] ^= 1;
    assert!(
        super::super::complete_origins::checked_metadata_bytes_dispatch(
            &plan.target,
            &secrets,
            &commit_plain,
            &sealed_plan,
            &altered,
            &keys,
        )
        .is_err()
    );
    assert_eq!(source, (sealed_plan, manifest, commit, keys));
}

#[test]
fn layered_encrypted_v5_metadata_keeps_parent_key_and_full_transport_origins() {
    let fresh = Secrets::fresh().unwrap();
    let e = fixture::fixture();
    let plan = super::super::layered_metadata::LayeredPlan {
        version: 2,
        generation_id: "11".repeat(32),
        inventory_digest: "22".repeat(32),
        target: "/synthetic-absent/transport-v5-layered".into(),
        source_profile: "synthetic-source".into(),
        successor_profile: fresh.profile(),
        parent_manifest_digest: "22".repeat(32),
        parent_capsule_id: "33".repeat(32),
        parent_node_generation: "44".repeat(32),
        parent_key_commitment: super::super::layered_metadata::parent_key_commitment(&[23; 32])
            .unwrap(),
        components: components(true),
        affected_accounts: BTreeSet::from([e.request.account_id]),
        semantic_inventory_digest: "55".repeat(32),
        unknown_external_signatures: true,
        recovered_obligations_fenced: true,
    };
    plan.validate().unwrap();
    let plan_plain = encode(&plan).unwrap();
    let digest = hash(&plan_plain);
    let secrets = fresh
        .bind_successor_plan(Sha256::digest(&plan_plain).into())
        .unwrap();
    let sealed_plan = seal(&secrets, b"plan", &plan_plain).unwrap();
    let (manifest, commit, e) = encrypted_metadata(
        &secrets,
        &digest,
        &plan.generation_id,
        &plan.inventory_digest,
        &plan.target,
    );
    let purpose = [b"keys:".as_slice(), digest.as_bytes()].concat();
    let keys = seal(&secrets, &purpose, &[23u8; 32]).unwrap();
    let source = (
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
    assert!(checked.plan == plan);
    assert_eq!(checked.parent_key.as_slice(), &[23; 32]);
    assert_eq!(
        checked.restrictions,
        e.complete_history.conservative_obligations().unwrap()
    );
    let retained =
        checked_continuity_rows(&unseal(&secrets, b"manifest", &manifest).unwrap()).unwrap();
    assert_preserved(&retained[0], &e);
    let wrong_keys = seal(&secrets, &purpose, &[24u8; 32]).unwrap();
    assert!(
        super::super::layered_metadata::checked_layered_metadata_bytes(
            &plan.target,
            &secrets,
            &sealed_plan,
            &manifest,
            &commit,
            &wrong_keys,
        )
        .is_err()
    );
    assert!(
        super::super::layered_metadata::checked_layered_metadata_bytes(
            std::path::Path::new("/synthetic/other"),
            &secrets,
            &sealed_plan,
            &manifest,
            &commit,
            &keys,
        )
        .is_err()
    );
    assert_eq!(source, (sealed_plan, manifest, commit, keys));
}

#[test]
fn committed_v5_financial_open_denies_before_reading_or_mutating_files() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("v5-disabled");
    let directory = Directory::create(&target).unwrap();
    let secrets = Secrets::fresh().unwrap();
    let (_, commit) = metadata(fixture::fixture());
    assert!(matches!(
        open_checked_v5(&directory, &secrets, &commit, false),
        Err(Error::RecoveryFinancialUnsupported)
    ));
    let entries: Vec<_> = std::fs::read_dir(&target)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(entries, vec![std::ffi::OsString::from("profile.lock")]);
    assert!(
        std::fs::read(target.join("profile.lock"))
            .unwrap()
            .is_empty()
    );
}
