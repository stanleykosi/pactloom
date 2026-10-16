// Pure restricted-dispatch tests. The enclosing module's inspected request()
// and scope() builders contain inert JSON only. No LocalIpc, socket, peer,
// credential, native decision, witness client or financial issuer is created.
use super::*;

fn restricted() -> IpcMode {
    IpcMode::QuarantinedV5 {
        account_id: scope().account_id,
    }
}

fn bounded_request(publication: bool) -> serde_json::Value {
    let mut value = request(publication);
    value["transfer_dialect"] = "v5_bounded_transfer_v1".into();
    value
}

fn continuity_mut(value: &mut serde_json::Value, publication: bool) -> &mut serde_json::Value {
    if publication {
        &mut value["request"]["continuity"]
    } else {
        &mut value["request"]
    }
}

#[test]
fn quarantined_pairing_scope_requires_exact_account_and_only_historical_export_flags() {
    let mode = restricted();
    scope().validate().unwrap();
    for history_read in [false, true] {
        for authorization_export in [false, true] {
            for preconstruction_export in [false, true] {
                let mut requested = scope();
                requested.history_read = history_read;
                requested.authorization_export = authorization_export;
                requested.preconstruction_export = preconstruction_export;
                assert_eq!(
                    mode.permits_scope(&requested),
                    history_read && authorization_export && !preconstruction_export
                );
                // The new mode must not change ordinary request-only routing.
                assert!(IpcMode::Ordinary.permits_scope(&requested));
            }
        }
    }
    for other in ["other-account", "SYNTHETIC-ACCOUNT", "synthetic-account "] {
        let mut requested = scope();
        requested.account_id = other.into();
        assert!(!mode.permits_scope(&requested));
    }
    // Missing permission fields retain their existing false serde defaults;
    // omitted flags cannot become a historical-export pairing grant.
    for field in ["history_read", "authorization_export"] {
        let mut value = serde_json::to_value(scope()).unwrap();
        value.as_object_mut().unwrap().remove(field);
        let requested: PairScope = serde_json::from_value(value).unwrap();
        assert!(!mode.permits_scope(&requested));
    }
}

#[test]
fn quarantined_classifier_accepts_only_exact_account_bounded_v5_request_families() {
    let mode = restricted();
    for publication in [false, true] {
        let parsed: AppRequest = serde_json::from_value(bounded_request(publication)).unwrap();
        match &parsed {
            AppRequest::RequestHostRecoveryContinuityV5 { request, .. } => {
                request.validate().unwrap();
            }
            AppRequest::RequestHostRecoveryPublicationV5 { request, .. } => {
                request.validate().unwrap();
            }
            _ => unreachable!("inert V5 fixture request"),
        }
        assert!(mode.permits_scope(&scope()));
        assert!(mode.permits_request(&parsed));
        assert!(IpcMode::Ordinary.permits_request(&parsed));
        // Classifier acceptance is not native permission or release activation.
        assert!(matches!(parsed.validate(&scope()), Err(Error::Unavailable)));

        let mut other_account = bounded_request(publication);
        let continuity = continuity_mut(&mut other_account, publication);
        continuity["account_id"] = "other-account".into();
        continuity["expected_witness"]["account_id"] = "other-account".into();
        let parsed: AppRequest = serde_json::from_value(other_account).unwrap();
        assert!(!mode.permits_request(&parsed));
        assert!(
            mode.validate_authenticated_request(&parsed, &scope())
                .is_err()
        );
    }
}

#[test]
fn quarantined_classifier_rejects_single_frame_and_legacy_host_routes() {
    let mode = restricted();
    for publication in [false, true] {
        // An omitted dialect still means the ordinary legacy single frame.
        let omitted: AppRequest = serde_json::from_value(request(publication)).unwrap();
        assert!(!mode.permits_request(&omitted));
        assert!(
            mode.validate_authenticated_request(&omitted, &scope())
                .is_err()
        );
        let mut single_frame = request(publication);
        single_frame["transfer_dialect"] = "single_frame".into();
        let explicit: AppRequest = serde_json::from_value(single_frame).unwrap();
        assert!(!mode.permits_request(&explicit));
        assert!(
            mode.validate_authenticated_request(&explicit, &scope())
                .is_err()
        );

        for version in [1, 2, 3] {
            let mut value = request(publication);
            let suffix = if version == 1 {
                String::new()
            } else {
                format!("_v{version}")
            };
            let purpose = if publication {
                "publication"
            } else {
                "continuity"
            };
            value["operation"] = format!("request_host_recovery_{purpose}{suffix}").into();
            value["request"]["schema_version"] = version.into();
            continuity_mut(&mut value, publication)["schema_version"] = version.into();
            let parsed: AppRequest = serde_json::from_value(value).unwrap();
            assert!(!mode.permits_request(&parsed));
            assert!(
                mode.validate_authenticated_request(&parsed, &scope())
                    .is_err()
            );
            assert!(IpcMode::Ordinary.permits_request(&parsed));
        }
    }
}

#[test]
fn quarantined_classifier_denies_status_review_financial_and_signature_export_operations() {
    let mode = restricted();
    // The exact inert history shape also used by the existing settlement scope
    // test. These hashes identify no authorization and create no proof or key.
    let history = serde_json::json!({
        "authorization_id": "synthetic-authorization",
        "expected_original_consent_ref": "12".repeat(32),
        "expected_enrollment_ref": "34".repeat(32),
        "expected_manifest_ref": "56".repeat(32)
    });
    let redelivery = serde_json::json!({
        "operation_id": "synthetic-redelivery",
        "reference": "78".repeat(32)
    });
    let redelivery_request = serde_json::json!({
        "operation_id": "synthetic-redelivery",
        "authorization_id": "synthetic-authorization",
        "expected_original_consent_ref": "12".repeat(32),
        "expected_enrollment_ref": "34".repeat(32),
        "expected_manifest_ref": "56".repeat(32)
    });
    for value in [
        serde_json::json!({"operation": "status"}),
        serde_json::json!({
            "operation": "request_review", "request_id": "synthetic-review",
            "accepted_manifest_digest": scope().manifest_digest, "pczt_hex": "00"
        }),
        serde_json::json!({
            "operation": "request_automatic_authorization", "request": {
                "grant_id": "synthetic-grant", "candidate_id": "synthetic-candidate",
                "artifact_digest": "12".repeat(32),
                "accepted_manifest_digest": scope().manifest_digest
            }
        }),
        serde_json::json!({
            "operation": "request_settlement", "request": {
                "history": history, "dispatch_operation_id": "synthetic-dispatch"
            }
        }),
        serde_json::json!({"operation": "retrieve_authorization", "history": history}),
        serde_json::json!({"operation": "acquire_original_authorization", "history": history}),
        serde_json::json!({
            "operation": "request_result_redelivery", "request": redelivery_request
        }),
        serde_json::json!({
            "operation": "retrieve_redelivered_authorization",
            "history": history, "redelivery": redelivery
        }),
        serde_json::json!({
            "operation": "acquire_redelivered_authorization",
            "history": history, "redelivery": redelivery
        }),
    ] {
        let parsed: AppRequest = serde_json::from_value(value).unwrap();
        assert!(!mode.permits_request(&parsed));
        assert!(
            mode.validate_authenticated_request(&parsed, &scope())
                .is_err()
        );
        assert!(IpcMode::Ordinary.permits_request(&parsed));
    }
}

#[test]
fn quarantined_classifier_denies_dispatch_and_disclosure_dtos_without_provider_or_proof_calls() {
    // Parse only an existing inert proposal. Do not call consent_fixture(),
    // which reaches a protocol review-fixture helper rather than a JSON reader.
    let plan: serde_json::Value = serde_json::from_str(include_str!(
        "../account/birth/enrollment/roster_v2/inventory/fixtures/common-context-plan-v3.synthetic.json"
    ))
    .unwrap();
    let proposal = &plan["proposal"];
    let participant = &proposal["manifest"]["participants"][0];
    let account = participant["account_id"].as_str().unwrap();
    let mode = IpcMode::QuarantinedV5 {
        account_id: account.into(),
    };
    let grant_scope = PairScope {
        account_id: account.into(),
        ..scope()
    };
    let history = serde_json::json!({
        "authorization_id": "synthetic-authorization",
        "expected_original_consent_ref": "12".repeat(32),
        "expected_enrollment_ref": "34".repeat(32),
        "expected_manifest_ref": "56".repeat(32)
    });
    for value in [
        serde_json::json!({
            "operation": "request_preconstruction", "request": {
                "enrollment_ref": "11".repeat(32),
                "accepted_manifest_ref": "22".repeat(32), "sponsor_policy": null,
                "scope": {
                    "schema_version": 1, "proposal": proposal,
                    "account_id": account, "participant_id": participant["participant_id"],
                    "profile_id": "synthetic-profile", "principal_id": "synthetic-owner",
                    "operator_name": "synthetic-prover",
                    "operator_destination": "/synthetic/proof.sqlite",
                    "wallet_destination": "/synthetic/wallet.sqlite",
                    "reviewer_account_ids": [account], "privacy_domain": "synthetic-dedicated",
                    "purpose": "construct_exact_accepted_candidate",
                    "retention_policy": "Synthetic historical request only",
                    "provider": {
                        "source_id": "synthetic-source", "endpoint": "https://example.invalid:443",
                        "trust_profile": "single_tls_provider_report_not_consensus"
                    },
                    "minimum_confirmations": 10, "maximum_blocks": 100,
                    "anchor_height": 1000, "maximum_net_debit_zatoshis": 400_012_000u64,
                    "birthday": {
                        "prior_height": 900, "prior_block_hash": "33".repeat(32),
                        "sapling_tree": "", "orchard_tree": "", "ironwood_tree": ""
                    }
                }
            }
        }),
        serde_json::json!({
            "operation": "request_proved_disclosure", "request": {
                "schema_version": 1, "proposal": proposal,
                "account_id": account, "participant_id": participant["participant_id"],
                "enrollment_ref": "11".repeat(32), "accepted_manifest_ref": "22".repeat(32),
                "proved_artifact_sha256": "33".repeat(32), "review_binding": "44".repeat(32),
                "recipients": [{"account_id": account,
                    "provider_enrollment_reference": "55".repeat(32),
                    "process_instance": "synthetic-process"}],
                "purpose": "private_proved_pczt_export_and_exact_review"
            }
        }),
        serde_json::json!({
            "operation": "request_dispatch", "request": {
                "history": history, "operation_id": "synthetic-dispatch",
                "backend": {
                    "schema_version": 1, "profile_id": "synthetic-profile",
                    "principal_id": "synthetic-owner", "agreement_id": "synthetic-agreement",
                    "submission_journal_identity": "synthetic-journal",
                    "descriptor": {
                        "operation_id": "synthetic-submission", "obligation_id": "synthetic-obligation",
                        "proposal_id": "synthetic-proposal", "transaction_id": "12".repeat(32),
                        "bytes_sha256": "34".repeat(32), "expiry_height": 4_100_000,
                        "network": "testnet", "consensus_branch_id": 0x77190ad9u32
                    },
                    "backend": {"source_id": "synthetic-provider",
                        "endpoint": "https://example.invalid:443",
                        "trust_profile": "single_tls_provider_report_not_consensus"},
                    "purpose": "submit_exact_retained_transaction",
                    "confidence": "single_tls_provider_report_not_consensus",
                    "minimum_expiry_margin_blocks": 10
                }
            }
        }),
    ] {
        let parsed: AppRequest = serde_json::from_value(value).unwrap();
        assert!(!mode.permits_request(&parsed));
        assert!(
            mode.validate_authenticated_request(&parsed, &grant_scope)
                .is_err()
        );
        assert!(IpcMode::Ordinary.permits_request(&parsed));
    }
}

#[test]
fn quarantined_mode_does_not_replace_exact_dto_and_inventory_validation() {
    let mode = restricted();
    for publication in [false, true] {
        let parsed: AppRequest = serde_json::from_value(bounded_request(publication)).unwrap();
        let mut other_inventory = scope();
        other_inventory.manifest_digest = "ff".repeat(32);
        assert!(mode.permits_scope(&other_inventory));
        assert!(mode.permits_request(&parsed));
        assert!(matches!(
            parsed.validate(&other_inventory),
            Err(Error::Authentication)
        ));

        for field in [
            "schema_version",
            "inventory_digest",
            "generation_id",
            "expected_writer_epoch",
            "network_profile_id",
        ] {
            let mut value = bounded_request(publication);
            continuity_mut(&mut value, publication)[field] = match field {
                "schema_version" => 4.into(),
                "inventory_digest" | "generation_id" => "not-a-digest".into(),
                "expected_writer_epoch" => 0.into(),
                _ => "other-network".into(),
            };
            let parsed: AppRequest = serde_json::from_value(value).unwrap();
            // This intentionally remains a classifier, not a DTO validator.
            // authenticate() must perform mode-aware validation before peer/event creation.
            assert!(mode.permits_request(&parsed));
            assert!(matches!(parsed.validate(&scope()), Err(Error::InvalidData)));
            assert!(matches!(
                mode.validate_authenticated_request(&parsed, &scope()),
                Err(Error::InvalidData)
            ));
        }
        let mut unknown_permission = bounded_request(publication);
        unknown_permission["approved"] = true.into();
        assert!(serde_json::from_value::<AppRequest>(unknown_permission).is_err());
    }

    for (field, invalid) in [
        ("schema_version", serde_json::json!(4)),
        ("target_profile", serde_json::json!("relative/profile")),
        (
            "generation_manifest_digest",
            serde_json::json!("not-a-digest"),
        ),
        (
            "continuity_evidence_digest",
            serde_json::json!("not-a-digest"),
        ),
    ] {
        let mut value = bounded_request(true);
        value["request"][field] = invalid;
        let parsed: AppRequest = serde_json::from_value(value).unwrap();
        assert!(mode.permits_request(&parsed));
        assert!(matches!(parsed.validate(&scope()), Err(Error::InvalidData)));
        assert!(matches!(
            mode.validate_authenticated_request(&parsed, &scope()),
            Err(Error::InvalidData)
        ));
    }
}

#[test]
fn quarantined_validation_seam_accepts_bounded_requests_and_preserves_generic_denial() {
    let mode = restricted();
    for publication in [false, true] {
        let parsed: AppRequest = serde_json::from_value(bounded_request(publication)).unwrap();
        mode.validate_authenticated_request(&parsed, &scope())
            .unwrap();
        assert!(matches!(
            IpcMode::Ordinary.validate_authenticated_request(&parsed, &scope()),
            Err(Error::Unavailable)
        ));
        assert!(matches!(parsed.validate(&scope()), Err(Error::Unavailable)));
        for field in 0..7 {
            let mut wrong = scope();
            match field {
                0 => wrong.history_read = false,
                1 => wrong.authorization_export = false,
                2 => wrong.preconstruction_export = true,
                3 => wrong.account_id = "other-account".into(),
                4 => wrong.manifest_digest = "ff".repeat(32),
                5 => wrong.agreement_id.clear(),
                6 => wrong.participant_id.clear(),
                _ => unreachable!(),
            }
            assert!(
                mode.validate_authenticated_request(&parsed, &wrong)
                    .is_err()
            );
        }
        let mut wrong_account = bounded_request(publication);
        let continuity = continuity_mut(&mut wrong_account, publication);
        continuity["account_id"] = "other-account".into();
        continuity["expected_witness"]["account_id"] = "other-account".into();
        let parsed: AppRequest = serde_json::from_value(wrong_account).unwrap();
        assert!(
            mode.validate_authenticated_request(&parsed, &scope())
                .is_err()
        );
    }
}
