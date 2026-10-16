use super::*;
fn evidence() -> HostRecoveryContinuityEvidenceV4 {
    // Inert legacy fixture is explicitly rebuilt as a NEW empty typed audit
    // envelope. No issuer accepts this data and no old signature is reused.
    let mut value: serde_json::Value = serde_json::from_str(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../wholepact-signer/src/authority_bridge/host_recovery_ipc/v3/fixtures/minimal_evidence.json"))).unwrap();
    value["request"]["schema_version"] = 4.into();
    value["complete_history"]["schema_version"] = 4.into();
    value["complete_history"]["construction"]["version"] = 2.into();
    value["complete_history"]["construction"]["approvals"] = serde_json::json!([]);
    value["complete_history"]["signer_common_context_audit"] =
        serde_json::json!({"version":1,"rows":[]});
    let result: HostRecoveryContinuityEvidenceV4 = serde_json::from_value(value).unwrap();
    result.validate().unwrap();
    result
}
fn metadata() -> (ManifestV4, CommitV4, HostRecoveryContinuityEvidenceV4) {
    let e = evidence();
    let manifest = ManifestV4 {
        version: 4,
        plan_digest: "11".repeat(32),
        continuity: vec![e.clone()],
        unmatched_host_authorizations: BTreeSet::new(),
        unresolved_offline_authorizations: e
            .complete_history
            .unresolved_offline_authorizations()
            .unwrap(),
        unknown_external_signatures: true,
        recovered_obligations_fenced: true,
        financial_freshness_established: false,
    };
    // Plain historical audit fixture, deliberately not a native admission.
    let record = HostRecoveryPublicationRecordV4 {
        request: HostRecoveryPublicationRequestV4 {
            schema_version: 4,
            continuity: e.request.clone(),
            target_profile: "/synthetic/successor".into(),
            generation_manifest_digest: "22".repeat(32),
            continuity_evidence_digest: e.digest().unwrap(),
        },
        native_review_digest: "33".repeat(32),
        admission_id: "44".repeat(32),
    };
    let commit = CommitV4 {
        version: 4,
        plan_digest: manifest.plan_digest.clone(),
        manifest_digest: "22".repeat(32),
        admissions: vec![record],
    };
    (manifest, commit, e)
}
fn check(
    m: &ManifestV4,
    c: &CommitV4,
    e: &HostRecoveryContinuityEvidenceV4,
) -> Result<BTreeSet<String>> {
    validate_metadata_v4(
        &encode(m)?,
        &encode(c)?,
        &"22".repeat(32),
        &"11".repeat(32),
        &e.request.generation_id,
        &e.request.inventory_digest,
        std::path::Path::new("/synthetic/successor"),
        &BTreeSet::from([e.request.account_id.clone()]),
    )
}
#[test]
fn both_generation_shapes_consume_all_origin_obligation_fences() {
    let (m, c, e) = metadata();
    assert_eq!(
        check(&m, &c, &e).unwrap(),
        BTreeSet::from(["synthetic-offline-obligation".into()])
    );
    assert!(
        consume_admissions(
            &m,
            std::path::Path::new("/synthetic/successor"),
            &"22".repeat(32),
            vec![]
        )
        .is_err()
    );
}
#[test]
fn unknown_coverage_cannot_be_erased_or_relabelled_financially_current() {
    let (mut m, c, e) = metadata();
    m.unresolved_offline_authorizations.clear();
    assert!(check(&m, &c, &e).is_err());
    let (mut m, c, e) = metadata();
    m.unknown_external_signatures = false;
    assert!(check(&m, &c, &e).is_err());
    let (mut m, c, e) = metadata();
    m.financial_freshness_established = true;
    assert!(check(&m, &c, &e).is_err());
    let (mut m, c, e) = metadata();
    m.continuity[0]
        .complete_history
        .financial_origins_v2
        .complete_journal_digest = "ee".repeat(32);
    assert!(check(&m, &c, &e).is_err());
}
#[test]
fn mixed_versions_do_not_fall_back_to_legacy_or_accept_saved_authority() {
    let (mut m, c, e) = metadata();
    m.version = 1;
    assert!(check(&m, &c, &e).is_err());
    let (m, mut c, e) = metadata();
    c.version = 1;
    assert!(check(&m, &c, &e).is_err());
    assert_eq!(metadata_version(br#"{"version":5}"#).unwrap(), 5);
    assert!(metadata_version(br#"{"version":6}"#).is_err());
    #[cfg(all(feature = "manual-admission", target_os = "linux"))]
    {
        let complete = crate::recovery_generation::transport_capsule_fixtures::evidence();
        let bytes = serde_json::to_vec(&complete).unwrap();
        assert!(serde_json::from_slice::<HostRecoveryContinuityEvidenceV4>(&bytes).is_err());
    }
    // A recognized discriminator is not a complete metadata document.
    assert!(serde_json::from_slice::<CommitV4>(br#"{"version":5}"#).is_err());
    let (m, mut c, e) = metadata();
    c.admissions[0].request.target_profile = "/synthetic/other".into();
    assert!(check(&m, &c, &e).is_err());
}
#[test]
fn legacy_host_release_never_invents_an_offline_writer_or_original() {
    let e = evidence();
    let HostRecoveryReservationOriginV2::Offline { origin } =
        &e.complete_history.financial_origins_v2.origins[0]
    else {
        panic!("wrong origin")
    };
    let t = origin.terms().unwrap();
    let release = wholepact_store::authority::ReleaseIntent {
        authorization_id: t.authorization_id.clone(),
        account_id: t.account_id.clone(),
        writer_epoch: 1,
        obligation_id: t.obligation_id.clone(),
        proposal_id: t.proposal_id.clone(),
        manifest_digest: t.manifest_digest.clone(),
        effects_digest: t.effects_digest.clone(),
        artifact_digest: t.artifact_digest.clone(),
        maximum_debit: t.maximum_debit_zatoshis.to_string(),
        input_ids: t.inputs.iter().map(|i| i.input_id.clone()).collect(),
        aggregate_budget_limit: "100".into(),
    };
    assert!(match_host_releases(&[release], &[e]).is_err());
}
#[test]
fn mandatory_typed_audit_survives_encryption_and_old_reader_denies() {
    let (manifest, commit, evidence) = metadata();
    // Generation sealing requires a successor-bound storage vault. Match
    // this test manifest's exact plan digest; fresh ordinary vaults deny it.
    let secrets = Secrets::fresh()
        .unwrap()
        .bind_successor_plan([0x11; 32])
        .unwrap();
    let plain = encode(&manifest).unwrap();
    let encrypted = seal(&secrets, b"manifest", &plain).unwrap();
    let reopened = unseal(&secrets, b"manifest", &encrypted).unwrap();
    assert_eq!(*plain, *reopened);
    let decoded: ManifestV4 = serde_json::from_slice(&reopened).unwrap();
    check(&decoded, &commit, &evidence).unwrap();
    assert!(
        serde_json::from_slice::<super::super::construction_origins::ManifestV3>(&reopened)
            .is_err()
    );
    let mut value = serde_json::to_value(&manifest).unwrap();
    value["continuity"][0]["complete_history"]
        .as_object_mut()
        .unwrap()
        .remove("signer_common_context_audit");
    assert!(serde_json::from_value::<ManifestV4>(value).is_err());
    assert!(wholepact_signer::authority_bridge::host_recovery_ipc::v4::require_common_context_recovery_endpoint().is_err());
}

#[cfg(feature = "manual-admission")]
mod signed_nonempty_audit {
    use super::*;
    use wholepact_signer as signer;
    mod fixture {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../wholepact-signer/src/consent_journal/common_context_audit_fixture.rs"
        ));
    }
    #[test]
    fn nonempty_signed_origin_and_modeled_native_lineage_survive_encrypted_v4_metadata() {
        let (_, e) = fixture::fixture();
        let manifest = ManifestV4 {
            version: 4,
            plan_digest: "11".repeat(32),
            continuity: vec![e.clone()],
            unmatched_host_authorizations: BTreeSet::new(),
            unresolved_offline_authorizations: BTreeSet::new(),
            unknown_external_signatures: true,
            recovered_obligations_fenced: true,
            financial_freshness_established: false,
        };
        let commit = CommitV4 {
            version: 4,
            plan_digest: manifest.plan_digest.clone(),
            manifest_digest: "22".repeat(32),
            admissions: vec![HostRecoveryPublicationRecordV4 {
                request: HostRecoveryPublicationRequestV4 {
                    schema_version: 4,
                    continuity: e.request.clone(),
                    target_profile: "/synthetic/successor".into(),
                    generation_manifest_digest: "22".repeat(32),
                    continuity_evidence_digest: e.digest().unwrap(),
                },
                native_review_digest: "33".repeat(32),
                admission_id: "44".repeat(32),
            }],
        };
        check(&manifest, &commit, &e).unwrap();
        let before = encode(&manifest).unwrap();
        // Generation sealing requires a successor-bound storage vault. Match
        // this test manifest's exact plan digest; fresh ordinary vaults deny it.
        let secrets = Secrets::fresh()
            .unwrap()
            .bind_successor_plan([0x11; 32])
            .unwrap();
        let sealed = seal(&secrets, b"manifest", &before).unwrap();
        let plain = unseal(&secrets, b"manifest", &sealed).unwrap();
        assert_eq!(*before, *plain);
        let decoded: ManifestV4 = serde_json::from_slice(&plain).unwrap();
        check(&decoded, &commit, &e).unwrap();
        assert_eq!(
            decoded.continuity[0]
                .complete_history
                .conservative_debit_zatoshis()
                .unwrap(),
            e.complete_history.conservative_debit_zatoshis().unwrap()
        );
        let mut missing = decoded;
        missing.continuity[0]
            .complete_history
            .signer_common_context_audit
            .rows
            .clear();
        assert!(check(&missing, &commit, &e).is_err());
        assert!(wholepact_signer::authority_bridge::host_recovery_ipc::v4::require_common_context_recovery_endpoint().is_err());
    }
    #[test]
    fn exact_store_consume_join_rejects_changes_and_preserves_missing_audit_uncertainty() {
        let (audit, e) = fixture::fixture();
        let signer::consent_journal::CommonContextSignerAuditV1::Consumed { evidence, .. } =
            &audit.rows[0]
        else {
            panic!("canonical consumed")
        };
        let native: wholepact_store::manual_enrollment::ManualRosterConsumedConstructionAuditV3 =
            serde_json::from_value(serde_json::to_value(evidence).unwrap()).unwrap();
        require_exact_common_context_consume(&e.complete_history, &native).unwrap();
        let mut changed = native.clone();
        changed.common_context_read_admission_digest = "77".repeat(32);
        assert!(require_exact_common_context_consume(&e.complete_history, &changed).is_err());
        let mut changed = native;
        changed.request.plan.common_context_digest = "88".repeat(32);
        assert!(require_exact_common_context_consume(&e.complete_history, &changed).is_err());
        let mut changed = e.complete_history;
        changed.signer_common_context_audit.rows.clear();
        require_exact_common_context_consume(
            &changed,
            &serde_json::from_value(serde_json::to_value(evidence).unwrap()).unwrap(),
        )
        .unwrap();
        let missing = changed.missing_local_native_phases().unwrap();
        assert_eq!(missing.len(), 1);
        assert!(
            missing[0].missing_read_admission
                && missing[0].missing_reserved
                && missing[0].missing_consumed
        );
    }
}

#[test]
fn manifest_v4_cannot_drop_explicit_reentry_claim_lineage() {
    // Format gate only; this creates no Store inventory or native admission.
    super::require_manifest_v4_claim_encoding(3, false).unwrap();
    for (version, lineage) in [(3, true), (4, true), (4, false), (2, false), (5, true)] {
        assert!(matches!(
            super::require_manifest_v4_claim_encoding(version, lineage),
            Err(crate::Error::RecoveryFinancialUnsupported)
        ));
    }
}
