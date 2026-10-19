//! Pure exact-delta and real encrypted-journal regressions. Inert fixture
//! source/receipt values are NOT authenticated native issuers or proof success.
use super::*;
use std::os::unix::fs::PermissionsExt;
use wholepact_core::*;
fn amount(n: u64) -> Amount {
    Amount::from_zatoshis(n).unwrap()
}
fn request() -> CandidateRequest {
    let mut agreement: AgreementDraft = serde_json::from_str(include_str!(
        "../../../wholepact-core/tests/fixtures/agreement.json"
    ))
    .unwrap();
    agreement.network_profile_id = "ironwood-testnet-nu7-candidate".into();
    agreement.recipients[0].amount = amount(300_000);
    agreement.funding_policy = FundingPolicy::Exact {
        target: amount(300_000),
    };
    let participants = vec![
        ParticipantAllocation {
            participant_id: "alice".into(),
            account_id: "account-a".into(),
            contribution: amount(100_000),
            fee_share: amount(5_000),
            fee_cap: amount(5_000),
            maximum_net_debit: amount(105_000),
            charges: vec![],
        },
        ParticipantAllocation {
            participant_id: "bob".into(),
            account_id: "account-b".into(),
            contribution: amount(200_000),
            fee_share: amount(10_000),
            fee_cap: amount(10_000),
            maximum_net_debit: amount(210_000),
            charges: vec![],
        },
    ];
    let inputs = participants
        .iter()
        .enumerate()
        .map(|(i, p)| ClaimedInput {
            input_id: format!("input-{i}"),
            participant_id: p.participant_id.clone(),
            account_id: p.account_id.clone(),
            amount: amount(if i == 0 { 200_000 } else { 300_000 }),
            ownership_evidence_ref: None,
        })
        .collect();
    let mut outputs = vec![ClaimedOutput {
        output_id: "recipient-output".into(),
        address: agreement.recipients[0].address.clone(),
        amount: amount(300_000),
        allocation: OutputAllocation::Recipient {
            recipient_id: agreement.recipients[0].recipient_id.clone(),
        },
    }];
    for (i, p) in participants.iter().enumerate() {
        outputs.push(ClaimedOutput {
            output_id: format!("change-{i}"),
            address: format!("utestsyntheticchange{i}"),
            amount: amount(if i == 0 { 95_000 } else { 90_000 }),
            allocation: OutputAllocation::Return {
                participant_id: p.participant_id.clone(),
                account_id: p.account_id.clone(),
                ownership_evidence_ref: None,
            },
        });
    }
    CandidateRequest {
        manifest: ProposalManifest {
            agreement,
            participants,
            inputs,
            outputs,
            transaction_fee: amount(15_000),
            expiry_height: 4_465_070,
        },
        previous_candidate_id: None,
    }
}

fn seed() -> Envelope {
    let input = request();
    let engine = Engine::in_memory().unwrap();
    let access = Access {
        principal_id: "private-pure-owner".into(),
        include_owned_agreements: true,
        ..Access::default()
    };
    engine
        .create(
            &access,
            "private-pure-seed-command",
            input.manifest.agreement.clone(),
        )
        .unwrap();
    let record = engine
        .store
        .get_agreement(&input.manifest.agreement.agreement_id)
        .unwrap()
        .unwrap();
    let mut envelope = crate::decode_unprojected(&record).unwrap();
    envelope.terms_editing_origin = false;
    envelope.view.roster_selected = true;
    envelope.view.progress = "preparing_proposal".into();
    envelope
}
fn advance(mut envelope: Envelope) -> Envelope {
    envelope.view.revision += 1;
    envelope.view.updated_at = "2026-10-19T00:00:00Z".into();
    envelope
}
fn candidate_pair() -> (Envelope, Envelope) {
    let before = seed();
    let mut after = advance(before.clone());
    after
        .view
        .candidates
        .push(crate::candidates::build_exact_candidate_v2(request()).unwrap());
    (before, after)
}
#[test]
fn exact_candidate_delta_accepts_only_one_candidate_and_two_metadata_fields() {
    let (before, after) = candidate_pair();
    operation_v1::validate_delta(&before, &after, EffectV2::PrepareExactCandidate).unwrap();
    let mut second = advance(after.clone());
    second
        .view
        .candidates
        .push(second.view.candidates[0].clone());
    assert!(
        operation_v1::validate_delta(&after, &second, EffectV2::PrepareExactCandidate).is_err()
    );
    for changed in [
        {
            let mut e = after.clone();
            e.owner_client_id.push('x');
            e
        },
        {
            let mut e = after.clone();
            e.intent_owners.insert("foreign".into(), "other".into());
            e
        },
        {
            let mut e = after.clone();
            e.terms_editing_origin = true;
            e
        },
        {
            let mut e = after.clone();
            e.view.agreement.purpose.push('x');
            e
        },
        {
            let mut e = after.clone();
            e.view.terms_history.push(e.view.agreement.clone());
            e
        },
        {
            let mut e = after.clone();
            e.view.roster_selected = false;
            e
        },
        {
            let mut e = after.clone();
            e.view.cancellation_requested = true;
            e
        },
        {
            let mut e = after.clone();
            e.view.authorization_exposure = "authorized".into();
            e
        },
        {
            let mut e = after.clone();
            e.view.chain_observation = "confirmed".into();
            e
        },
        {
            let mut e = after.clone();
            e.view.created_at = "2020-01-01T00:00:00Z".into();
            e
        },
        {
            let mut e = after.clone();
            e.view.revision += 1;
            e
        },
        {
            let mut e = after.clone();
            e.view.progress = "awaiting_authorization".into();
            e
        },
        {
            let mut e = after.clone();
            e.transport_peer_grants.insert("foreign".into(), json!({}));
            e
        },
        {
            let mut e = after.clone();
            e.durable_input_projections_v1
                .insert("foreign".into(), json!({}));
            e
        },
    ] {
        assert!(
            operation_v1::validate_delta(&before, &changed, EffectV2::PrepareExactCandidate)
                .is_err()
        );
    }
}
fn inert_receipt(candidate: &CandidateView) -> crate::candidates::CheckpointReceipt {
    // Only a delta/denial fixture. No native source, construction or job exists.
    crate::candidates::CheckpointReceipt {
        original_request_v2: None,
        action_mappings_v1: Some(json!({"inputs":[],"outputs":[]})),
        job_id: format!("proof-{}", "1".repeat(64)),
        scope_digest: "2".repeat(64),
        principal_id: "private-pure-owner".into(),
        candidate_id: candidate.candidate_id.clone(),
        manifest_digest: candidate.manifest_digest.clone(),
        coordination_request_digest: "3".repeat(64),
        artifact_digest: "4".repeat(64),
        review_binding: "5".repeat(64),
        effects_commitment: "6".repeat(64),
        prepared_revision: 3,
    }
}
fn queued_summary(candidate: &CandidateView) -> JobSummary {
    JobSummary {
        job_id: format!("proof-{}", "1".repeat(64)),
        scope_digest: "2".repeat(64),
        candidate_id: candidate.candidate_id.clone(),
        state: wholepact_proof_jobs::JobState::Queued,
        attempt: 0,
        input_digest: "4".repeat(64),
        manifest_digest: candidate.manifest_digest.clone(),
        effects_commitment: "6".repeat(64),
        coordination_request_digest: "3".repeat(64),
        result_digest: None,
        review_binding: "5".repeat(64),
        encrypted_checkpoint_created: true,
        proof_verified: false,
        chain_validated: false,
        authorization_allowed: false,
        distribution_allowed: false,
    }
}
#[test]
fn constructor_and_metadata_link_have_distinct_exact_deltas() {
    let (_, before) = candidate_pair();
    let mut receipt = advance(before.clone());
    receipt
        .checkpoint_receipts
        .insert("7".repeat(64), inert_receipt(&before.view.candidates[0]));
    operation_v1::validate_delta(&before, &receipt, EffectV2::ConstructorReceipt).unwrap();
    let mut linked = advance(receipt.clone());
    let summary = queued_summary(&linked.view.candidates[0]);
    upsert_link(&mut linked, &summary).unwrap();
    operation_v1::validate_delta(&receipt, &linked, EffectV2::MetadataLink).unwrap();
    assert!(
        operation_v1::validate_delta(&receipt, &linked, EffectV2::RecordOriginalProofOutcome)
            .is_err()
    );
    let unchanged = advance(linked.clone());
    assert!(operation_v1::validate_delta(&linked, &unchanged, EffectV2::MetadataLink).is_err());
    for changed in [
        {
            let mut e = linked.clone();
            e.checkpoint_receipts.clear();
            e
        },
        {
            let mut e = linked.clone();
            e.view.candidates[0].proposal.proposal_id.push('x');
            e
        },
        {
            let mut e = linked.clone();
            e.view.candidates[0].accounting = json!({});
            e
        },
    ] {
        assert!(operation_v1::validate_delta(&receipt, &changed, EffectV2::MetadataLink).is_err());
    }
    let mut outcome = advance(linked.clone());
    outcome.view.candidates[0].proof_jobs[0].state = "running".into();
    outcome.view.candidates[0].proof_jobs[0].attempt = 1;
    operation_v1::validate_delta(&linked, &outcome, EffectV2::RecordOriginalProofOutcome).unwrap();
    for field in [
        "job_id",
        "scope_digest",
        "candidate_id",
        "manifest_digest",
        "coordination_request_digest",
        "input_digest",
        "effects_commitment",
        "review_binding",
        "observation_source",
    ] {
        let mut value = crate::encode(&outcome).unwrap();
        value["view"]["candidates"][0]["proof_jobs"][0][field] = json!("changed");
        let e: Envelope = serde_json::from_value(value).unwrap();
        assert!(
            operation_v1::validate_delta(&linked, &e, EffectV2::RecordOriginalProofOutcome)
                .is_err(),
            "{field}"
        );
    }
    for field in [
        "chain_validated",
        "authorization_allowed",
        "distribution_allowed",
    ] {
        let mut value = crate::encode(&outcome).unwrap();
        value["view"]["candidates"][0]["proof_jobs"][0][field] = json!(true);
        let e: Envelope = serde_json::from_value(value).unwrap();
        assert!(
            operation_v1::validate_delta(&linked, &e, EffectV2::RecordOriginalProofOutcome)
                .is_err(),
            "{field}"
        );
    }
}
#[test]
fn private_decoder_refuses_normalized_revision_exposure_and_unknown_fields() {
    let before = seed();
    let payload = crate::encode(&before).unwrap();
    let record = crate::StoredRecord {
        id: before.view.agreement.agreement_id.clone(),
        revision: before.view.revision,
        payload,
        created_at_ms: 1,
        updated_at_ms: 1,
    };
    decode_private_record(&record).unwrap();
    for path in ["revision", "authorization_exposure", "chain_observation"] {
        let mut bad = record.clone();
        bad.payload["view"][path] = if path == "revision" {
            json!(42)
        } else {
            json!("changed")
        };
        assert!(decode_private_record(&bad).is_err());
    }
    let mut bad = record;
    bad.payload["future_private_purpose"] = json!({});
    assert!(decode_private_record(&bad).is_err());
}
#[test]
fn prepare_empty_original_schema_preflight_refuses_foreign_replaced_and_uninitialized_files() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.path().join("metadata.sqlite");
    let key = DatabaseKey::from_bytes([112; 32]);
    let store = wholepact_store::Store::create_encrypted(&path, &key).unwrap();
    let origin = store.verify_original_encrypted_destination(&path).unwrap();
    drop(store);
    preflight_original_metadata(&path, &key, origin).unwrap();
    assert!(preflight_original_metadata(&path, &key, [4; 32]).is_err());
    std::fs::rename(&path, directory.path().join("old.sqlite")).unwrap();
    let replacement = wholepact_store::Store::create_encrypted(&path, &key).unwrap();
    drop(replacement);
    assert!(preflight_original_metadata(&path, &key, origin).is_err());
    let empty = directory.path().join("uninitialized.sqlite");
    let conn = wholepact_storage_security::create_encrypted(&empty, &key).unwrap();
    let identity = conn.database_identity().unwrap().origin_commitment();
    drop(conn);
    assert!(preflight_original_metadata(&empty, &key, identity).is_err());
}
#[test]
fn original_attempt_and_result_ownership_are_consuming_not_cloneable() {
    trait AmbiguousIfClone<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfClone<()> for T {}
    impl<T: ?Sized + Clone> AmbiguousIfClone<u8> for T {}
    let _ = <OriginalProofAttemptV2<'static, 'static> as AmbiguousIfClone<_>>::marker;
    let _ = <OriginalCheckpointOutcomeV2<'static, 'static> as AmbiguousIfClone<_>>::marker;
    fn consume(
        result: crate::Result<OriginalCheckpointOutcomeV2<'static, 'static>>,
    ) -> Option<OriginalProofAttemptV2<'static, 'static>> {
        match result {
            Ok(result) => result.into_attempt(),
            Err(_) => None,
        }
    }
    assert!(consume(Err(damaged())).is_none());
}

#[cfg(feature = "synthetic-qualification")]
mod actual_cryptography {
    use super::*;
    use wholepact_protocol::construction::{ConstructionContext, OwnedContribution, PROFILE_ID};
    use wholepact_protocol::durable_proposal_v1::canonical_durable_account_id;
    use wholepact_protocol::review::encode_testnet_receiver;
    use wholepact_wallet::wallet::synthetic_scanned_contributions;
    struct Fixture {
        agreement: AgreementDraft,
        request: CandidateRequest,
        chain: ConstructionContext,
        packages: Vec<OwnedContribution>,
        account_ids: Vec<String>,
    }
    fn fixture() -> Fixture {
        let (wallets, selection) = synthetic_scanned_contributions().unwrap();
        let receiver = encode_testnet_receiver(&wallets[0].notes()[0].note.recipient());
        // The scanner fixture's owner-a/owner-b labels are not durable account
        // identities. Derive the same canonical IDs from the actual scanned FVKs
        // before constructing the candidate, policy, receipt, or proof.
        let account_ids: Vec<_> = wallets
            .iter()
            .map(|w| canonical_durable_account_id(w.fvk()))
            .collect();
        let agreement = AgreementDraft {
            schema_version: 1,
            agreement_id: "scanner-to-engine-synthetic".into(),
            obligation_id: "never-funded-obligation".into(),
            revision: 1,
            purpose: "Synthetic scanner to candidate qualification; no network or funds".into(),
            organizer_identity: "fixture-organizer".into(),
            network_profile_id: PROFILE_ID.into(),
            recipients: vec![Recipient {
                recipient_id: "fixture-recipient".into(),
                address: receiver.clone(),
                amount: amount(300_000),
                memo: None,
                instruction_provenance: "Synthetic owner receiver, not a live payment".into(),
            }],
            funding_policy: FundingPolicy::Exact {
                target: amount(300_000),
            },
            fee_policy: FeePolicy::ProRata,
            privacy_profile: PrivacyProfile {
                mode: PrivacyMode::DeclaredOperator,
                proving_operator: Some("synthetic-local-constructor".into()),
                dedicated_accounts_required: true,
            },
            coordination_deadline: None,
            confirmation_policy: ConfirmationPolicy::default(),
            extensions: vec![],
        };
        let participants: Vec<_> = wallets
            .iter()
            .enumerate()
            .map(|(i, w)| ParticipantAllocation {
                participant_id: format!("participant-{i}"),
                account_id: account_ids[i].clone(),
                contribution: amount(if i == 0 { 100_000 } else { 200_000 }),
                fee_share: amount(if i == 0 { 5_000 } else { 10_000 }),
                fee_cap: amount(if i == 0 { 5_000 } else { 10_000 }),
                maximum_net_debit: amount(w.requested_debit_zatoshis()),
                charges: vec![],
            })
            .collect();
        let mut inputs = vec![];
        let mut outputs = vec![ClaimedOutput {
            output_id: "recipient-output".into(),
            address: receiver,
            amount: amount(300_000),
            allocation: OutputAllocation::Recipient {
                recipient_id: "fixture-recipient".into(),
            },
        }];
        for (i, w) in wallets.iter().enumerate() {
            for n in w.notes() {
                inputs.push(ClaimedInput {
                    input_id: n.input_id.clone(),
                    participant_id: participants[i].participant_id.clone(),
                    account_id: account_ids[i].clone(),
                    amount: amount(n.note.value().inner()),
                    ownership_evidence_ref: None,
                });
            }
            outputs.push(ClaimedOutput {
                output_id: format!("change-{i}"),
                address: encode_testnet_receiver(&w.change_address()),
                amount: amount(w.selected_zatoshis() - w.requested_debit_zatoshis()),
                allocation: OutputAllocation::Return {
                    participant_id: participants[i].participant_id.clone(),
                    account_id: account_ids[i].clone(),
                    ownership_evidence_ref: None,
                },
            });
        }
        let request = CandidateRequest {
            manifest: ProposalManifest {
                agreement: agreement.clone(),
                participants: participants.clone(),
                inputs,
                outputs,
                transaction_fee: amount(15_000),
                expiry_height: selection.tip_height + 30,
            },
            previous_candidate_id: None,
        };
        let chain = ConstructionContext {
            anchor: selection.anchor_root,
            anchor_height: selection.anchor_height,
            anchor_block_hash: selection.anchor_hash_protocol,
            target_height: selection.tip_height + 1,
        };
        let packages: Vec<_> = wallets
            .into_iter()
            .map(|w| {
                let mut contribution = w.into_contribution();
                contribution.account_id = canonical_durable_account_id(&contribution.fvk);
                contribution
            })
            .collect();
        Fixture {
            agreement,
            request,
            chain,
            packages,
            account_ids,
        }
    }

    struct ExactProofPrivacy {
        principal: String,
        candidate: String,
        manifest: String,
        accounts: Vec<String>,
    }
    impl LocalProofConsent for ExactProofPrivacy {
        fn permits(&self, scope: &CheckpointScope, _: LocalAction) -> bool {
            scope.principal_id == self.principal
                && scope.candidate_id == self.candidate
                && scope.manifest_digest == self.manifest
                && scope.account_ids == self.accounts
                && scope.local_operator == "synthetic-local-constructor"
                && scope.purpose == "actual synthetic proof component"
                && scope.retention_policy == "temporary component ciphertext"
        }
    }
    /// Actual constructor and Halo2 proof, no fabricated completed proof row.
    /// Tests shared fixed verification only, not a genuine native-source facade.
    #[test]
    fn actual_succeeded_proof_with_stale_queued_metadata_freezes_without_second_attempt() {
        let Fixture {
            agreement,
            request,
            chain,
            packages,
            account_ids,
        } = fixture();
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let metadata_key = DatabaseKey::from_bytes([120; 32]);
        let proof_key = DatabaseKey::from_bytes([121; 32]);
        let engine = Engine::from_store(
            wholepact_store::Store::create_encrypted(
                directory.path().join("metadata.sqlite"),
                &metadata_key,
            )
            .unwrap(),
        );
        let jobs = wholepact_proof_jobs::ProofJobStore::from_original_encrypted_connection_v1(
            wholepact_storage_security::create_encrypted(
                directory.path().join("proof.sqlite"),
                &proof_key,
            )
            .unwrap(),
        )
        .unwrap();
        let access = Access {
            principal_id: "synthetic-component-owner".into(),
            include_owned_agreements: true,
            ..Access::default()
        };
        engine
            .create(&access, "synthetic-proof-seed-command", agreement.clone())
            .unwrap();
        for (i, p) in request.manifest.participants.iter().enumerate() {
            engine
                .add_intent(
                    &access,
                    &format!("synthetic-proof-intent-{i}"),
                    &agreement.agreement_id,
                    i as u64 + 1,
                    ParticipationIntent {
                        intent_id: format!("intent-{i}"),
                        agreement_id: agreement.agreement_id.clone(),
                        participant_id: p.participant_id.clone(),
                        desired_contribution: p.contribution,
                        maximum_net_debit: p.maximum_net_debit,
                        fee_cap: p.fee_cap,
                        conditions: vec![],
                        valid_until: None,
                        status: IntentStatus::Active,
                    },
                )
                .unwrap();
        }
        let frozen = engine
            .create_candidate(
                &access,
                "synthetic-proof-candidate-command",
                &agreement.agreement_id,
                3,
                request,
            )
            .unwrap();
        let c = frozen.agreement.candidates[0].clone();
        let privacy = ExactProofPrivacy {
            principal: access.principal_id.clone(),
            candidate: c.candidate_id.clone(),
            manifest: c.manifest_digest.clone(),
            accounts: account_ids.clone(),
        };
        let declarations: Vec<_> = account_ids
            .iter()
            .map(|account| DisclosureAcknowledgement {
                account_id: account.clone(),
                manifest_digest: hex::decode(&c.manifest_digest).unwrap().try_into().unwrap(),
                operator: "synthetic-local-constructor".into(),
                reviewer_account_ids: account_ids.clone(),
                purpose: "actual synthetic proof component".into(),
                retention_policy: "temporary component ciphertext".into(),
                scope: DisclosureScope::DedicatedAccountFvkAndSelectedNotesAndOutputs,
            })
            .collect();
        let queued = engine
            .checkpoint_candidate_locally(
                &access,
                "synthetic-proof-checkpoint-command",
                &c.candidate_id,
                4,
                crate::proof_jobs::LocalCheckpoint {
                    construction: crate::candidates::LocalConstruction {
                        context: chain,
                        contributions: packages,
                        declarations: &declarations,
                    },
                    jobs: &jobs,
                    limits: ProvingLimits { maximum_actions: 8 },
                    consent: &privacy,
                },
            )
            .unwrap();
        let job = queued.agreement.candidates[0].proof_jobs[0].clone();
        let mut stale = engine.load(&access, &agreement.agreement_id).unwrap();
        assert_eq!(stale.view.candidates[0].proof_jobs[0].state, "queued");
        let actual = jobs
            .run_original_queued(&access.principal_id, &job.job_id, &privacy)
            .unwrap();
        assert_eq!(actual.attempt, 1);
        assert!(actual.proof_verified);
        let checkpoint = jobs
            .original_source_v1()
            .unwrap()
            .load_verified(&access.principal_id, &job.job_id, &privacy)
            .unwrap();
        let receipt = validate_provenance(&stale, &access, checkpoint.summary())
            .unwrap()
            .clone();
        // Legacy generic serialization remains unchanged, not a live-source token.
        assert!(receipt.original_request_v2.is_none());
        assert!(
            serde_json::to_value(&receipt)
                .unwrap()
                .get("original_request_v2")
                .is_none()
        );
        let mut observed_envelope = stale.clone();
        let observation = Observation::new(Operation::Freeze);
        let observed_fixed = crate::durable_proposals_v1::freeze_private_fixed_observed_v2(
            &observation,
            &mut observed_envelope,
            &access,
            &checkpoint,
            &receipt,
        )
        .unwrap();
        let fixed = crate::durable_proposals_v1::freeze_private_fixed_v2(
            &mut stale,
            &access,
            &checkpoint,
            &receipt,
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(&observed_fixed).unwrap(),
            serde_json::to_value(&fixed).unwrap()
        );
        assert_eq!(
            crate::encode(&observed_envelope).unwrap(),
            crate::encode(&stale).unwrap()
        );
        assert_eq!(stale.view.candidates[0].proof_jobs[0].state, "queued");
        assert_eq!(
            crate::durable_proposals_v1::read_private_fixed_v2(
                &stale,
                &access,
                &checkpoint,
                &receipt
            )
            .unwrap(),
            fixed
        );
        assert_eq!(
            jobs.status(&access.principal_id, &job.job_id, &privacy)
                .unwrap(),
            actual
        );
        let mut missing = receipt.clone();
        missing.action_mappings_v1 = None;
        assert!(
            crate::durable_proposals_v1::read_private_fixed_v2(
                &stale,
                &access,
                &checkpoint,
                &missing
            )
            .is_err()
        );
        let mut wrong = receipt;
        wrong.action_mappings_v1 = Some(json!({"inputs":[],"outputs":[]}));
        let mut altered_metadata = stale.clone();
        altered_metadata
            .durable_proposals_v1
            .get_mut(&c.candidate_id)
            .unwrap()["mappings"] = wrong.action_mappings_v1.clone().unwrap();
        let legacy_error = crate::durable_proposals_v1::read_private_fixed_v2(
            &altered_metadata,
            &access,
            &checkpoint,
            &wrong,
        )
        .unwrap_err();
        let observation = Observation::new(Operation::ReadFixed);
        let actual_error = observation
            .finish(crate::durable_proposals_v1::read_private_fixed_observed_v2(
                &observation,
                &altered_metadata,
                &access,
                &checkpoint,
                &wrong,
            ))
            .unwrap_err();
        assert_eq!(actual_error.code, legacy_error.code);
        assert_eq!(actual_error.message, legacy_error.message);
        assert_eq!(
            actual_error.details["private_fixed_diagnostic_v1"]["family"],
            "Protocol"
        );

        assert!(
            crate::durable_proposals_v1::read_private_fixed_v2(
                &stale,
                &access,
                &checkpoint,
                &wrong
            )
            .is_err()
        );
        assert_eq!(
            jobs.status(&access.principal_id, &job.job_id, &privacy)
                .unwrap(),
            actual
        );
    }
}

#[test]
fn original_request_requires_exact_key_principal_digest_revision_and_budget() {
    let (_, e) = candidate_pair();
    let mut receipt = inert_receipt(&e.view.candidates[0]);
    let access = Access {
        principal_id: receipt.principal_id.clone(),
        ..Access::default()
    };
    let key = "private-pure-original-request";
    assert!(validate_original_request_v2(&receipt, &access, key).is_err());
    // Legacy serialization never emits a new claim or upgrades its provenance.
    assert!(
        serde_json::to_value(&receipt)
            .unwrap()
            .get("original_request_v2")
            .is_none()
    );
    let command = crate::context(
        &access,
        key,
        "private_checkpoint_exact_original_v2",
        &receipt.candidate_id,
        Some(2),
        &json!({"local_input_digest":"a".repeat(64),"maximum_actions":8}),
    )
    .unwrap();
    receipt.job_id = wholepact_proof_jobs::job_id_for_key(&access.principal_id, key).unwrap();
    receipt.coordination_request_digest = command.request_digest.clone();
    receipt.original_request_v2 = Some(crate::candidates::OriginalCheckpointRequestV2 {
        command,
        expected_revision: 2,
        local_input_digest: "a".repeat(64),
        maximum_actions: 8,
    });
    validate_original_request_v2(&receipt, &access, key).unwrap();
    assert!(validate_original_request_v2(&receipt, &access, "different-original-key").is_err());
    for changed in [
        {
            let mut r = receipt.clone();
            r.original_request_v2.as_mut().unwrap().command.principal_id = "other".into();
            r
        },
        {
            let mut r = receipt.clone();
            r.original_request_v2
                .as_mut()
                .unwrap()
                .command
                .request_digest = "b".repeat(64);
            r
        },
        {
            let mut r = receipt.clone();
            r.original_request_v2.as_mut().unwrap().expected_revision += 1;
            r
        },
        {
            let mut r = receipt.clone();
            r.original_request_v2.as_mut().unwrap().local_input_digest = "c".repeat(64);
            r
        },
        {
            let mut r = receipt.clone();
            r.original_request_v2.as_mut().unwrap().maximum_actions = 9;
            r
        },
        {
            let mut r = receipt.clone();
            r.job_id = format!("proof-{}", "d".repeat(64));
            r
        },
        {
            let mut r = receipt.clone();
            r.prepared_revision += 1;
            r
        },
        {
            let mut r = receipt.clone();
            r.candidate_id.push('x');
            r
        },
    ] {
        assert!(validate_original_request_v2(&changed, &access, key).is_err());
    }
    assert_ne!(
        receipt_key(&access, key).unwrap(),
        receipt_key(&access, "different-original-key").unwrap()
    );
}
#[test]
fn every_unreleased_map_and_unknown_field_is_denied_by_exact_delta() {
    let (before, after) = candidate_pair();
    for field in [
        "durable_input_projections_v1",
        "sponsor_policies",
        "participant_records",
        "transport_peer_grants",
        "native_requests",
        "native_proof_requests",
        "native_proof_execution_requests",
        "native_artifact_handoff_requests",
        "native_settlement_requests",
        "native_dispatch_requests",
        "native_reconciliation_requests",
        "native_account_inspection_requests",
        "future_private_effect_v3",
    ] {
        let mut value = crate::encode(&after).unwrap();
        value[field] = json!({"foreign":{}});
        if let Ok(changed) = serde_json::from_value::<Envelope>(value) {
            assert!(
                operation_v1::validate_delta(&before, &changed, EffectV2::PrepareExactCandidate)
                    .is_err(),
                "{field}"
            );
        }
    }
}
#[test]
fn original_material_absolute_ceiling_is_not_extended_by_later_use() {
    use wholepact_wallet::wallet::protected_sync::durable_construction_v1::{
        ConstructionRecipientV1, ConstructionReviewerV1, DurableConstructionScopeV1,
        ExactTransportConstructionReviewerV1,
    };
    let c = crate::candidates::build_exact_candidate_v2(request()).unwrap();
    let scope = DurableConstructionScopeV1 {
        version: 1,
        purpose: "durable_fixed_candidate_construction_v1".into(),
        proposal: c.proposal.clone(),
        account_id: "account-a".into(),
        participant_id: "alice".into(),
        privacy_domain: "component-only".into(),
        constructor: ConstructionRecipientV1 {
            principal_id: "owner".into(),
            authenticated_local_grant_digest: "1".repeat(64),
        },
        prover: ConstructionRecipientV1 {
            principal_id: "owner".into(),
            authenticated_local_grant_digest: "2".repeat(64),
        },
        reviewers: ["account-a", "account-b"]
            .into_iter()
            .map(|account| {
                ConstructionReviewerV1::ExactTransport(ExactTransportConstructionReviewerV1 {
                    account_id: account.into(),
                    transport_key_digest: "3".repeat(64),
                })
            })
            .collect(),
        protected_destination: "/component/private-metadata.sqlite".into(),
        retention_policy: "exact original only".into(),
        valid_from_unix_seconds: 100,
        valid_until_unix_seconds: 200,
        minimum_confirmations: 1,
        maximum_scan_blocks: 20,
    };
    assert!(scope.check_valid_at(99).is_err());
    scope.check_valid_at(100).unwrap();
    scope.check_valid_at(199).unwrap();
    assert!(scope.check_valid_at(200).is_err());
    assert!(scope.check_valid_at(201).is_err());
    let original = serde_json::to_value(&scope).unwrap();
    for at in [200, 201, 10000] {
        assert!(scope.check_valid_at(at).is_err());
        assert_eq!(serde_json::to_value(&scope).unwrap(), original);
    }
}

#[test]
fn original_job_diagnostics_keep_only_the_exact_finite_category() {
    for (job, category) in [
        (
            wholepact_proof_jobs::JobError::ConsentDenied,
            "consent_denied",
        ),
        (wholepact_proof_jobs::JobError::NotFound, "not_found"),
        (
            wholepact_proof_jobs::JobError::InvalidRequest,
            "invalid_request",
        ),
        (
            wholepact_proof_jobs::JobError::VerificationFailed,
            "verification_failed",
        ),
        (
            wholepact_proof_jobs::JobError::IdempotencyConflict,
            "idempotency_conflict",
        ),
        (
            wholepact_proof_jobs::JobError::RecoveryRequired,
            "recovery_required",
        ),
        (
            wholepact_proof_jobs::JobError::StateConflict,
            "state_conflict",
        ),
        (wholepact_proof_jobs::JobError::Storage, "storage"),
        (
            wholepact_proof_jobs::JobError::UnsupportedSchema,
            "unsupported_schema",
        ),
        (
            wholepact_proof_jobs::JobError::ResourceExhausted,
            "resource_exhausted",
        ),
    ] {
        let error = job_error(job);
        assert_eq!(
            error.details.as_ref(),
            &json!({"private_original_job_error_v1":category})
        );
    }
}

/// Faults run the production observation kernels, not a fabricated native issuer
/// or completed proof row. The crypto component above remains separately gated.
mod diagnostic_v1_tests {
    use super::*;
    use diagnostics::{Call, CallState, Observation, Operation, Site};
    use std::cell::{Cell, RefCell};
    const KEY: &str = "private_fixed_diagnostic_v1";

    fn failure(observation: &Observation) -> ApiError {
        observation
            .finish::<()>(Err(ApiError::new("DISCLOSURE_DENIED", "local sentinel")))
            .unwrap_err()
    }
    fn core(error: &ApiError) -> &serde_json::Value {
        &error.details[KEY]
    }

    #[test]
    fn observed_owned_results_and_error_fields_are_not_replaced() {
        struct Owned<'a>(&'a Cell<u32>);
        impl Drop for Owned<'_> {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }
        let drops = Cell::new(0);
        let observation = Observation::new(Operation::Checkpoint);
        let owned = observation
            .finish(observation.api(Site::Candidate, Ok(Owned(&drops))))
            .unwrap();
        assert_eq!(drops.get(), 0);
        drop(owned);
        assert_eq!(drops.get(), 1);
        let mut original = ApiError::new(
            "INVALID_REQUEST",
            "private message remains only in original error",
        );
        original.retryable = true;
        original.operation_id = Some("original-operation".into());
        original.safe_actions = vec!["original action".into()];
        original.details = Box::new(json!({"existing":"value"}));
        let error = observation.finish::<()>(Err(original)).unwrap_err();
        assert_eq!(error.code, "INVALID_REQUEST");
        assert!(error.retryable);
        assert_eq!(error.operation_id.as_deref(), Some("original-operation"));
        assert_eq!(error.safe_actions, vec!["original action"]);
        assert_eq!(error.details["existing"], "value");
        assert!(!core(&error).to_string().contains("private message"));
    }

    #[test]
    fn observed_gate_preserves_every_short_circuit_and_first_actual_error() {
        for (exact, denied_at, permission, expected) in [
            (false, 0, true, vec![]),
            (true, 1, true, vec!["check"]),
            (true, 0, false, vec!["check", "permission"]),
            (true, 2, true, vec!["check", "permission", "check"]),
            (true, 0, true, vec!["check", "permission", "check"]),
        ] {
            let mut outcomes = Vec::new();
            for observed in [false, true] {
                let observation = Observation::new(Operation::Checkpoint);
                let order = RefCell::new(Vec::new());
                let calls = Cell::new(0);
                let allowed = diagnostics::gate_chain(
                    observed.then_some(&observation),
                    exact,
                    || {
                        order.borrow_mut().push("check");
                        calls.set(calls.get() + 1);
                        if calls.get() == denied_at {
                            let error = ApiError::new("MISSING_EVIDENCE", "not exported");
                            if observed {
                                observation.record(Site::GateMaterial, diagnostics::engine(&error));
                            }
                            Err(error)
                        } else {
                            Ok(())
                        }
                    },
                    || {
                        order.borrow_mut().push("permission");
                        permission
                    },
                );
                assert_eq!(*order.borrow(), expected);
                outcomes.push(allowed);
                if observed && !allowed {
                    let error = failure(&observation);
                    if denied_at > 0 {
                        assert_eq!(core(&error)["site"], "GateMaterial");
                        assert_eq!(core(&error)["cause"], "MISSING_EVIDENCE");
                        assert_eq!(core(&error)["engine_code"], "DISCLOSURE_DENIED");
                    }
                }
            }
            assert_eq!(outcomes[0], outcomes[1]);
        }
    }

    #[test]
    fn actual_wallet_roster_failure_keeps_generic_e_lower_cause_and_legacy_error() {
        let callback = Cell::new(0);
        let legacy: crate::Result<()> =
            with_durable_construction_roster_v1(Vec::new(), |_, _, _| {
                callback.set(callback.get() + 1);
                Ok(())
            });
        let observed: std::result::Result<(), diagnostics::RosterError> =
            with_durable_construction_roster_v1(Vec::new(), |_, _, _| {
                callback.set(callback.get() + 1);
                Ok(())
            });
        let observation = Observation::new(Operation::Checkpoint);
        let mapped = observed.map_err(|e| e.into_api(&observation, Site::WalletRosterAcquire));
        let error = observation.finish(mapped).unwrap_err();
        let old = legacy.unwrap_err();
        assert_eq!(callback.get(), 0);
        assert_eq!(error.code, old.code);
        assert_eq!(error.message, old.message);
        assert_eq!(error.retryable, old.retryable);
        assert_eq!(error.safe_actions, old.safe_actions);
        assert_eq!(core(&error)["family"], "DurableConstruction");
        assert_eq!(core(&error)["cause"], "Binding");
        assert_eq!(core(&error)["calls"]["receipt"], "NotCalled");
    }

    #[test]
    fn finite_lower_families_do_not_export_payloads_or_guess_job_storage() {
        use wholepact_wallet::wallet::protected_sync::{
            SyncError, durable_construction_v1::DurableConstructionError,
        };
        let cases = [
            diagnostics::construction(&DurableConstructionError::Sync(
                SyncError::NoCurrentObservation,
            )),
            diagnostics::construction(&DurableConstructionError::Sync(SyncError::Wallet(
                wholepact_wallet::wallet::WalletError::AccountMismatch,
            ))),
            diagnostics::construction(&DurableConstructionError::Sync(SyncError::Chain(
                wholepact_chain::ChainError::BackendFailure { grpc_code: 123456 },
            ))),
            diagnostics::store(&wholepact_store::StoreError::InvalidInput(
                "private path sentinel",
            )),
            diagnostics::store(&wholepact_store::StoreError::StorageSecurity(
                wholepact_storage_security::StorageSecurityError::SourceChanged,
            )),
            diagnostics::job(&wholepact_proof_jobs::JobError::Storage),
            diagnostics::protocol("Accepted manifest accounting is invalid"),
            diagnostics::protocol("private arbitrary protocol sentinel"),
        ];
        let expected = [
            ("Sync", "NoCurrentObservation"),
            ("Wallet", "AccountMismatch"),
            ("Chain", "BackendFailure"),
            ("Store", "InvalidInput"),
            ("StorageSecurity", "SourceChanged"),
            ("Job", "Storage"),
            ("Protocol", "Manifest"),
            ("Protocol", "Unclassified"),
        ];
        for (cause, (family, label)) in cases.into_iter().zip(expected) {
            let observation = Observation::new(Operation::Checkpoint);
            observation.record(Site::ProtocolConstruct, cause);
            let error = failure(&observation);
            let value = core(&error);
            assert_eq!(value["family"], family);
            assert_eq!(value["cause"], label);
            assert!(!value.to_string().contains("sentinel"));
            assert!(!value.to_string().contains("123456"));
        }
        let observation = Observation::new(Operation::ReadFixed);
        observation.record(
            Site::FixedVerify,
            diagnostics::Cause {
                family: "private-family",
                cause: "private-cause",
            },
        );
        let error = failure(&observation);
        assert_eq!(core(&error)["family"], "Engine");
        assert_eq!(core(&error)["cause"], "Unclassified");
    }

    #[test]
    fn actual_protocol_parse_failure_is_classified_without_second_evaluation() {
        let actual = wholepact_protocol::inspect_candidate(b"not a PCZT");
        let observation = Observation::new(Operation::Checkpoint);
        let mapped = actual.map_err(|error| {
            observation.record(Site::ProtocolInspect, diagnostics::protocol(&error));
            damaged()
        });
        let error = observation.finish(mapped).err().unwrap();
        assert_eq!(core(&error)["site"], "ProtocolInspect");
        assert_eq!(core(&error)["family"], "Protocol");
        assert!(!core(&error).to_string().contains("not a PCZT"));
    }

    #[test]
    fn real_store_fresh_replay_and_error_returns_survive_later_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("observed.sqlite");
        let key = DatabaseKey::from_bytes([121; 32]);
        let store = wholepact_store::Store::create_encrypted(&path, &key).unwrap();
        let create = wholepact_store::CommandContext::for_request(
            "owner",
            "create-observed-command",
            &json!({"n":0}),
        )
        .unwrap();
        let initial = store
            .create_agreement(&create, "observed", json!({"n":0}))
            .unwrap();
        let update = wholepact_store::CommandContext::for_request(
            "owner",
            "update-observed-command",
            &json!({"n":1}),
        )
        .unwrap();
        for expected in ["ReturnedOkFresh", "ReturnedOkReplay"] {
            let observation = Observation::new(Operation::Checkpoint);
            let result = store.update_agreement(
                &update,
                "observed",
                initial.record.revision,
                json!({"n":1}),
                "observed.changed",
            );
            observation.store_call(Site::ReceiptCommit, Call::Receipt, &result);
            let returned = result.unwrap();
            assert_eq!(returned.replayed, expected == "ReturnedOkReplay");
            // Same observation after a later postcheck Err cannot downgrade a known returned commit.
            observation.call(Call::Receipt, CallState::ReturnedErrUnknown);
            let error = failure(&observation);
            assert_eq!(core(&error)["calls"]["receipt"], expected);
        }
        let wrong = wholepact_store::CommandContext::for_request(
            "owner",
            "wrong-revision-command",
            &json!({"n":2}),
        )
        .unwrap();
        let observation = Observation::new(Operation::Checkpoint);
        let result =
            store.update_agreement(&wrong, "observed", 999, json!({"n":2}), "observed.changed");
        observation.store_call(Site::ReceiptCommit, Call::Receipt, &result);
        assert!(matches!(
            result,
            Err(wholepact_store::StoreError::RevisionConflict)
        ));
        let error = failure(&observation);
        assert_eq!(core(&error)["calls"]["receipt"], "ReturnedErrUnknown");
        assert_eq!(core(&error)["family"], "Store");
        assert_eq!(core(&error)["cause"], "RevisionConflict");
    }

    #[test]
    fn complete_call_slots_are_operation_local_and_proof_requires_consumption() {
        for (operation, related) in [
            (Operation::Checkpoint, vec!["receipt", "enqueue", "link"]),
            (Operation::Proof, vec!["proof", "outcome"]),
            (Operation::Freeze, vec!["freeze"]),
            (Operation::ReadFixed, vec![]),
            (Operation::OpenOriginal, vec![]),
        ] {
            let observation = Observation::new(operation);
            if operation == Operation::Proof {
                observation.consumed();
            }
            let error = failure(&observation);
            let value = core(&error);
            assert_eq!(value["call_scope"], "CurrentInvocation");
            assert_eq!(value["attempt_consumed"], operation == Operation::Proof);
            assert_eq!(value.as_object().unwrap().len(), 9);
            assert_eq!(value["calls"].as_object().unwrap().len(), 6);
            for slot in ["receipt", "enqueue", "link", "proof", "outcome", "freeze"] {
                assert_eq!(
                    value["calls"][slot],
                    if related.contains(&slot) {
                        "NotCalled"
                    } else {
                        "NotApplicable"
                    }
                );
            }
            assert!(serde_json::to_vec(value).unwrap().len() <= 4096);
        }
        let omitted = Observation::new(Operation::Proof);
        assert!(failure(&omitted).details.get(KEY).is_none());
        let enqueue = Observation::new(Operation::Checkpoint);
        enqueue.call(Call::Enqueue, CallState::ReturnedOkNoContinuation);
        assert_eq!(
            core(&failure(&enqueue))["calls"]["enqueue"],
            "ReturnedOkNoContinuation"
        );
        let invalid = Observation::new(Operation::Checkpoint);
        invalid.call(Call::Receipt, CallState::ReturnedOk);
        assert!(failure(&invalid).details.get(KEY).is_none());
    }

    #[test]
    fn collision_nonobject_and_borrow_contention_omit_without_changing_errors() {
        for details in [
            json!({KEY:{"preexisting":"do not replace"}}),
            json!(["arbitrary private details"]),
            json!(null),
        ] {
            let observation = Observation::new(Operation::Checkpoint);
            let mut error = ApiError::new("INVALID_REQUEST", "original");
            error.details = Box::new(details.clone());
            let returned = observation.finish::<()>(Err(error)).unwrap_err();
            assert_eq!(*returned.details, details);
        }
        let observation = Observation::new(Operation::Checkpoint);
        let error = ApiError::new("INVALID_REQUEST", "original");
        observation.record_while_borrowed_for_test(&error);
        let returned = observation.finish::<()>(Err(error)).unwrap_err();
        assert_eq!(returned.code, "INVALID_REQUEST");
        assert!(returned.details.get(KEY).is_none());
    }

    #[test]
    fn commit_metadata_merge_preserves_first_cause_and_arbitrary_existing_details() {
        let mut error = ApiError::new("RECOVERY_REQUIRED", "original");
        error.details = Box::new(
            json!({"private_original_job_error_v1":"Storage",KEY:{"reserved":"first"},"metadata_commit_status":"earlier","other":[1,2]}),
        );
        let original = error.details.clone();
        super::super::super::operation_v1::merge_error_details_v2(
            &mut error,
            &json!({"metadata_commit_status":"committed","new_fact":true,KEY:{"reserved":"later"}}),
        );
        for (key, value) in original.as_object().unwrap() {
            assert_eq!(&error.details[key], value);
        }
        assert_eq!(error.details["new_fact"], true);
        error.details = Box::new(json!("not an object"));
        super::super::super::operation_v1::merge_error_details_v2(
            &mut error,
            &json!({"fact":true}),
        );
        assert_eq!(*error.details, json!("not an object"));
    }

    #[test]
    fn actual_read_only_preflight_faults_preserve_source_and_original_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let key = DatabaseKey::from_bytes([122; 32]);
        let path = dir.path().join("metadata.sqlite");
        let store = wholepact_store::Store::create_encrypted(&path, &key).unwrap();
        let origin = store.verify_original_encrypted_destination(&path).unwrap();
        drop(store);
        for (file, expected, site) in [(&path, [7; 32], "SnapshotOrigin")] {
            let bytes = std::fs::read(file).unwrap();
            let legacy = preflight_original_metadata(file, &key, expected).unwrap_err();
            let observed = PreparedPrivateDurableCoordinatorV1::check_initialized_original_v1(
                file, &key, expected,
            )
            .unwrap_err();
            assert_eq!(observed.code, legacy.code);
            assert_eq!(observed.message, legacy.message);
            assert_eq!(core(&observed)["site"], site);
            assert_eq!(std::fs::read(file).unwrap(), bytes);
        }
        let empty = dir.path().join("empty.sqlite");
        let connection = wholepact_storage_security::create_encrypted(&empty, &key).unwrap();
        let empty_origin = connection.database_identity().unwrap().origin_commitment();
        drop(connection);
        let bytes = std::fs::read(&empty).unwrap();
        let legacy = preflight_original_metadata(&empty, &key, empty_origin).unwrap_err();
        let error = PreparedPrivateDurableCoordinatorV1::check_initialized_original_v1(
            &empty,
            &key,
            empty_origin,
        )
        .unwrap_err();
        assert_eq!(error.code, legacy.code);
        assert_eq!(error.message, legacy.message);
        // The snapshot factory rejects an uninitialized file before the Engine
        // can inspect its schema. Preserve that actual first typed failure.
        assert_eq!(core(&error)["site"], "SnapshotOpen");
        assert_eq!(core(&error)["family"], "StorageSecurity");
        assert_eq!(core(&error)["cause"], "UninitializedDatabase");
        assert_eq!(std::fs::read(&empty).unwrap(), bytes);

        // A distinct initialized encrypted journal reaches the schema check.
        // Mutate only this local negative fixture; never open it through Store
        // again, which could exercise a migration rather than a read preflight.
        let wrong_schema = dir.path().join("wrong-schema.sqlite");
        let store = wholepact_store::Store::create_encrypted(&wrong_schema, &key).unwrap();
        let wrong_schema_origin = store
            .verify_original_encrypted_destination(&wrong_schema)
            .unwrap();
        drop(store);
        let connection = wholepact_storage_security::open_encrypted(&wrong_schema, &key).unwrap();
        connection
            .connection()
            .pragma_update(None, "user_version", 4)
            .unwrap();
        drop(connection);
        let bytes = std::fs::read(&wrong_schema).unwrap();
        let legacy =
            preflight_original_metadata(&wrong_schema, &key, wrong_schema_origin).unwrap_err();
        let error = PreparedPrivateDurableCoordinatorV1::check_initialized_original_v1(
            &wrong_schema,
            &key,
            wrong_schema_origin,
        )
        .unwrap_err();
        assert_eq!(error.code, legacy.code);
        assert_eq!(error.message, legacy.message);
        assert_eq!(core(&error)["site"], "SnapshotSchema");
        assert_eq!(core(&error)["family"], "Engine");
        assert_eq!(core(&error)["cause"], legacy.code);
        assert_eq!(std::fs::read(&wrong_schema).unwrap(), bytes);
        PreparedPrivateDurableCoordinatorV1::check_initialized_original_v1(&path, &key, origin)
            .unwrap();
    }

    #[test]
    fn typed_original_receipt_comparison_preserves_exact_real_value() {
        let (_, envelope) = candidate_pair();
        let original = inert_receipt(&envelope.view.candidates[0]);
        assert!(same_original_receipt_v2(&original, &original).unwrap());
        let mut different = original.clone();
        different.prepared_revision += 1;
        assert!(!same_original_receipt_v2(&different, &original).unwrap());
        let mut different = original.clone();
        different.coordination_request_digest = "f".repeat(64);
        assert!(!same_original_receipt_v2(&different, &original).unwrap());
        let mut different = original.clone();
        different.action_mappings_v1 = None;
        assert!(!same_original_receipt_v2(&different, &original).unwrap());
        // The production helper takes CheckpointReceipt references; a stage's ()
        // can no longer silently participate in this serialization comparison.
    }
}
