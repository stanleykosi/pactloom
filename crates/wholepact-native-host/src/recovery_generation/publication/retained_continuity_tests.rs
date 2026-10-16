//! Read-only historical source qualification only. Native actors, sockets,
//! live keys, proofs, restored authority and publication are not exercised.
use super::super::retained_continuity_fixture as fixture;
use super::*;
use wholepact_signer as signer;
mod old_fixture {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../wholepact-signer/src/consent_journal/common_context_audit_fixture.rs"
    ));
}

fn read_v5(e: &HostRecoveryContinuityEvidenceV5) -> Result<RetainedContinuity> {
    RetainedContinuity::read(&RetainedContinuityInput {
        version: 5,
        evidence_digest: &e.digest().map_err(|_| Error::Authentication)?,
        bytes: &serde_json::to_vec(e)?,
    })
}
fn inspect_one(e: &HostRecoveryContinuityEvidenceV5) -> Result<RetainedHistoryInspection> {
    inspect_account_rows(
        &[RetainedContinuityInput {
            version: 5,
            evidence_digest: &e.digest().map_err(|_| Error::Authentication)?,
            bytes: &serde_json::to_vec(e)?,
        }],
        &e.request.generation_id,
        &e.request.inventory_digest,
        &BTreeSet::from([e.request.account_id.clone()]),
    )
}
fn consume(
    e: &HostRecoveryContinuityEvidenceV5,
) -> (
    ManualRosterConsumedConstructionAuditV3,
    RosterCommonContextReentryLineageV1,
) {
    let row = e
        .complete_history
        .signer_common_context_audit
        .reentry
        .rows
        .iter()
        .find_map(|row| {
            if let CommonContextReentryAuditPhaseV1::Consumed { evidence, .. } = &row.record {
                Some(evidence)
            } else {
                None
            }
        })
        .unwrap();
    // Exact inert wire mirror, never an admission/token or runtime constructor.
    (
        serde_json::from_value(serde_json::to_value(&row.construction).unwrap()).unwrap(),
        row.reentry_lineage.clone(),
    )
}

#[test]
fn dispatch_keeps_complete_v4_and_v5_bytes_in_their_exact_families() {
    let old = old_fixture::fixture().1;
    let old_bytes = serde_json::to_vec(&old).unwrap();
    let old_digest = old.digest().unwrap();
    let RetainedContinuity::V4(retained) = RetainedContinuity::read(&RetainedContinuityInput {
        version: 4,
        evidence_digest: &old_digest,
        bytes: &old_bytes,
    })
    .unwrap() else {
        panic!("wrong historical family");
    };
    assert_eq!(serde_json::to_vec(&retained).unwrap(), old_bytes);
    let new = fixture::fixture();
    let new_bytes = serde_json::to_vec(&new).unwrap();
    let RetainedContinuity::V5(retained) = read_v5(&new).unwrap() else {
        panic!("wrong historical family");
    };
    assert_eq!(serde_json::to_vec(&retained).unwrap(), new_bytes);
    assert!(
        RetainedContinuity::read(&RetainedContinuityInput {
            version: 5,
            evidence_digest: &old_digest,
            bytes: &old_bytes,
        })
        .is_err()
    );
    assert!(
        RetainedContinuity::read(&RetainedContinuityInput {
            version: 4,
            evidence_digest: &new.digest().unwrap(),
            bytes: &new_bytes,
        })
        .is_err()
    );
}

#[test]
fn version_five_marker_cannot_invent_transport_facts_or_publication() {
    let old = old_fixture::fixture().1;
    let mut marker_only = serde_json::to_value(&old).unwrap();
    marker_only["request"]["schema_version"] = 5.into();
    marker_only["complete_history"]["schema_version"] = 5.into();
    assert!(
        RetainedContinuity::read(&RetainedContinuityInput {
            version: 5,
            evidence_digest: &old.digest().unwrap(),
            bytes: &serde_json::to_vec(&marker_only).unwrap(),
        })
        .is_err()
    );
    let new = fixture::fixture();
    for field in [
        "approved",
        "admissions",
        "native_admission",
        "publication",
        "financial_freshness_established",
    ] {
        let mut forged = serde_json::to_value(&new).unwrap();
        forged[field] = serde_json::json!(true);
        assert!(
            RetainedContinuity::read(&RetainedContinuityInput {
                version: 5,
                evidence_digest: &new.digest().unwrap(),
                bytes: &serde_json::to_vec(&forged).unwrap(),
            })
            .is_err()
        );
    }
    let publication = signer::authority_bridge::host_publication_ipc::v4::HostRecoveryPublicationRecordV4 {
        request: signer::authority_bridge::host_publication_ipc::v4::HostRecoveryPublicationRequestV4 {
            schema_version: 4, continuity: old.request.clone(), target_profile: "/synthetic/retained-only".into(),
            generation_manifest_digest: "22".repeat(32), continuity_evidence_digest: old.digest().unwrap(),
        }, native_review_digest: "33".repeat(32), admission_id: "44".repeat(32),
    };
    assert!(
        RetainedContinuity::read(&RetainedContinuityInput {
            version: 5,
            evidence_digest: &new.digest().unwrap(),
            bytes: &serde_json::to_vec(&publication).unwrap(),
        })
        .is_err()
    );
    assert!(
        signer::authority_bridge::host_recovery_ipc::v4::require_common_context_recovery_endpoint()
            .is_err()
    );
    assert!(signer::authority_bridge::host_recovery_ipc::v5::require_construction_transport_recovery_endpoint().is_err());
    assert!(
        new.complete_history
            .require_financial_activation_supported()
            .is_err()
    );
}

#[test]
fn exact_inventory_binding_accounts_and_evidence_digest_are_mandatory() {
    let e = fixture::fixture();
    let bytes = serde_json::to_vec(&e).unwrap();
    let digest = e.digest().unwrap();
    let input = RetainedContinuityInput {
        version: 5,
        evidence_digest: &digest,
        bytes: &bytes,
    };
    let accounts = BTreeSet::from([e.request.account_id.clone()]);
    assert!(
        inspect_account_rows(
            &[input],
            &e.request.generation_id,
            &e.request.inventory_digest,
            &accounts
        )
        .is_ok()
    );
    for (generation, inventory) in [
        ("ee".repeat(32), e.request.inventory_digest.clone()),
        (e.request.generation_id.clone(), "ee".repeat(32)),
    ] {
        assert!(
            inspect_account_rows(
                &[RetainedContinuityInput {
                    version: 5,
                    evidence_digest: &digest,
                    bytes: &bytes
                }],
                &generation,
                &inventory,
                &accounts
            )
            .is_err()
        );
    }
    assert!(
        inspect_account_rows(
            &[],
            &e.request.generation_id,
            &e.request.inventory_digest,
            &accounts
        )
        .is_err()
    );
    assert!(
        inspect_account_rows(
            &[
                RetainedContinuityInput {
                    version: 5,
                    evidence_digest: &digest,
                    bytes: &bytes
                },
                RetainedContinuityInput {
                    version: 5,
                    evidence_digest: &digest,
                    bytes: &bytes
                },
            ],
            &e.request.generation_id,
            &e.request.inventory_digest,
            &accounts
        )
        .is_err()
    );
    assert!(
        RetainedContinuity::read(&RetainedContinuityInput {
            version: 5,
            evidence_digest: &"ee".repeat(32),
            bytes: &bytes
        })
        .is_err()
    );
    assert!(
        RetainedContinuity::read(&RetainedContinuityInput {
            version: 6,
            evidence_digest: &digest,
            bytes: &bytes
        })
        .is_err()
    );
}

#[test]
fn exact_claim4_consume_joins_signed_transport_and_retained_native_lineage() {
    let e = fixture::fixture();
    let (native, lineage) = consume(&e);
    require_reentered_consume(&e, &native, &lineage).unwrap();
    for field in [
        "construction_transport_credential_digest",
        "construction_transport_credential_id",
        "original_transport_fence_digest",
        "current_native_binding_digest",
        "original_host_process_digest",
        "original_record_digest",
        "original_genesis_digest",
        "original_birth_digest",
        "current_witness_history_digest",
        "native_review_digest",
    ] {
        let mut altered = serde_json::to_value(&lineage).unwrap();
        let replacement = if altered[field] == serde_json::Value::String("ee".repeat(32)) {
            "ff".repeat(32)
        } else {
            "ee".repeat(32)
        };
        altered[field] = replacement.into();
        let altered = serde_json::from_value(altered).unwrap();
        assert!(
            require_reentered_consume(&e, &native, &altered).is_err(),
            "{field}"
        );
    }
    for field in [
        "retained_signer_intent_digest",
        "current_attempt_digest",
        "native_review_digest",
        "witness_reservation_digest",
        "witness_consumed_digest",
        "common_context_read_admission_digest",
        "witness_plan_approval_digest",
    ] {
        let mut altered = serde_json::to_value(&native).unwrap();
        let replacement = if altered[field] == serde_json::Value::String("ee".repeat(32)) {
            "ff".repeat(32)
        } else {
            "ee".repeat(32)
        };
        altered[field] = replacement.into();
        let altered = serde_json::from_value(altered).unwrap();
        assert!(
            require_reentered_consume(&e, &altered, &lineage).is_err(),
            "{field}"
        );
    }
    // A transport Consume cannot be accepted through the same-caller branch.
    assert!(require_original_common_context_consume(&read_v5(&e).unwrap(), &native).is_err());
}

#[test]
fn missing_local_success_keeps_charge_fences_and_explicit_uncertainty() {
    let mut e = fixture::fixture();
    let (native, lineage) = consume(&e);
    let before = inspect_one(&e).unwrap();
    e.complete_history
        .signer_common_context_audit
        .reentry
        .rows
        .retain(|row| row.phase() != "consumed");
    e.validate().unwrap();
    require_reentered_consume(&e, &native, &lineage).unwrap();
    let after = inspect_one(&e).unwrap();
    assert_eq!(
        before.conservative_debit_by_account,
        after.conservative_debit_by_account
    );
    assert_eq!(before.obligation_fences, after.obligation_fences);
    assert!(before.transport_fences_by_account == after.transport_fences_by_account);
    assert!(after.conservative_debit_by_account[&e.request.account_id] > 0);
    let MissingLocalPhases::V5(missing) = &after.missing_local_phases[&e.request.account_id] else {
        panic!("lost V5 provenance");
    };
    assert!(missing.transport.iter().any(|row| row.missing_consumed));
    assert!(
        e.complete_history
            .construction
            .observed_snapshot()
            .transport_fences
            .is_some()
    );
    // Complete local loss still cannot erase authoritative debit or fences.
    e.complete_history
        .signer_common_context_audit
        .original
        .rows
        .clear();
    e.complete_history
        .signer_common_context_audit
        .reentry
        .rows
        .clear();
    e.validate().unwrap();
    let lost = inspect_one(&e).unwrap();
    assert_eq!(
        before.conservative_debit_by_account,
        lost.conservative_debit_by_account
    );
    assert_eq!(before.obligation_fences, lost.obligation_fences);
    assert!(before.transport_fences_by_account == lost.transport_fences_by_account);
    let MissingLocalPhases::V5(missing) = &lost.missing_local_phases[&e.request.account_id] else {
        panic!("lost V5 provenance");
    };
    assert!(
        missing
            .transport
            .iter()
            .any(|row| row.missing_read_admission && row.missing_reentered && row.missing_consumed)
    );
}

#[test]
fn retained_byte_cap_and_unknown_or_duplicate_fields_fail_closed() {
    let e = fixture::fixture();
    let digest = e.digest().unwrap();
    assert!(
        RetainedContinuity::read(&RetainedContinuityInput {
            version: 5,
            evidence_digest: &digest,
            bytes: &vec![b' '; MAX_COMPLETE_HISTORY_V4_BYTES + 4097]
        })
        .is_err()
    );
    let encoded = serde_json::to_string(&e).unwrap();
    let duplicate = format!(
        "{{\"request\":{},{}",
        serde_json::to_string(&e.request).unwrap(),
        &encoded[1..]
    );
    assert!(
        RetainedContinuity::read(&RetainedContinuityInput {
            version: 5,
            evidence_digest: &digest,
            bytes: duplicate.as_bytes()
        })
        .is_err()
    );
    let mut altered = serde_json::to_value(e).unwrap();
    altered["complete_history"]["construction"]["transport"]["credentials"] = serde_json::json!([]);
    assert!(
        RetainedContinuity::read(&RetainedContinuityInput {
            version: 5,
            evidence_digest: &digest,
            bytes: &serde_json::to_vec(&altered).unwrap()
        })
        .is_err()
    );
}
