//! Pure exact-delta and real encrypted-journal regressions. Inert fixture
//! source/receipt values are NOT authenticated native issuers or proof success.
use super::*;
use std::os::unix::fs::PermissionsExt;
use wholepact_core::*;
std::thread_local! {
    static ORIGINAL_CONSTRUCTOR_CALLS_V2: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
pub(super) fn record_original_constructor_v2() {
    ORIGINAL_CONSTRUCTOR_CALLS_V2.with(|count| count.set(count.get() + 1));
}
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
    let _ = <PreparedOriginalCheckpointV2<'static, 'static> as AmbiguousIfClone<_>>::marker;
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
        selection: wholepact_wallet::wallet::SelectionContext,
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
            selection,
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
            ..
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
    /// Shared review and actual proof-journal components only. Inert metadata
    /// never fabricates an authenticated native source, grant or coordinator.
    mod stage_reviews_v3 {
        use super::*;
        use std::cell::Cell;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use wholepact_wallet::wallet::protected_sync::durable_construction_v1::{
            ConstructionRecipientV1, ConstructionReviewerV1, PURPOSE,
        };
        fn checked<T, E>(result: std::result::Result<T, E>) -> T {
            match result {
                Ok(v) => v,
                Err(_) => panic!("stage review component failed"),
            }
        }
        fn materials(c: &CandidateView) -> Vec<PrivateFixedMaterialReviewV3> {
            let now = checked(stage_now_v3());
            c.proposal
                .manifest
                .participants
                .iter()
                .enumerate()
                .map(|(i, p)| PrivateFixedMaterialReviewV3 {
                    material_digest: format!("{:02x}", i + 1).repeat(32),
                    scope: DurableConstructionScopeV1 {
                        version: 2,
                        purpose: PURPOSE.into(),
                        proposal: c.proposal.clone(),
                        account_id: p.account_id.clone(),
                        participant_id: p.participant_id.clone(),
                        privacy_domain: "inert-stage-component".into(),
                        constructor: ConstructionRecipientV1 {
                            principal_id: "synthetic-local-constructor".into(),
                            authenticated_local_grant_digest: "ab".repeat(32),
                        },
                        prover: ConstructionRecipientV1 {
                            principal_id: "synthetic-local-constructor".into(),
                            authenticated_local_grant_digest: "ab".repeat(32),
                        },
                        reviewers: c
                            .proposal
                            .manifest
                            .participants
                            .iter()
                            .map(|p| {
                                ConstructionReviewerV1::local_installed_signer(p.account_id.clone())
                            })
                            .collect(),
                        protected_destination: "/inert-stage-component/metadata.sqlite".into(),
                        retention_policy: "temporary stage component ciphertext".into(),
                        valid_from_unix_seconds: now - 1,
                        valid_until_unix_seconds: now + 300,
                        minimum_confirmations: 1,
                        maximum_scan_blocks: 100,
                    },
                })
                .collect()
        }
        fn constructed() -> (
            CandidateView,
            ConstructedCheckpointV2,
            crate::candidates::CheckpointReceipt,
            Vec<PrivateFixedMaterialReviewV3>,
        ) {
            let f = fixture();
            let c = checked(crate::candidates::build_exact_candidate_v2(f.request));
            let materials = materials(&c);
            checked(check_stage_material_ceilings_v3(&materials));
            let access = Access {
                principal_id: "synthetic-local-constructor".into(),
                include_owned_agreements: true,
                ..Access::default()
            };
            let declarations: Vec<_> = f
                .account_ids
                .iter()
                .map(|account| DisclosureAcknowledgement {
                    account_id: account.clone(),
                    manifest_digest: checked(hex::decode(&c.manifest_digest)).try_into().unwrap(),
                    operator: access.principal_id.clone(),
                    reviewer_account_ids: f.account_ids.clone(),
                    purpose: materials[0].scope.purpose.clone(),
                    retention_policy: materials[0].scope.retention_policy.clone(),
                    scope: DisclosureScope::DedicatedAccountFvkAndSelectedNotesAndOutputs,
                })
                .collect();
            let input = checked(crate::candidates::private_request_digest(
                f.chain,
                &f.packages,
                &declarations,
            ));
            let key = "stage-review-component-original-key";
            let limits = ProvingLimits { maximum_actions: 8 };
            let command = checked(crate::context(
                &access,
                key,
                "private_checkpoint_exact_original_v2",
                &c.candidate_id,
                Some(4),
                &json!({"local_input_digest":input,"maximum_actions":8}),
            ));
            let observation = Observation::new(Operation::Checkpoint);
            let built = checked(construct_exact_artifact_v2(
                &access,
                &c.candidate_id,
                &c,
                &command,
                crate::candidates::LocalConstruction {
                    context: f.chain,
                    contributions: f.packages,
                    declarations: &declarations,
                },
                limits,
                &observation,
            ));
            let receipt = checked(prepare_constructor_receipt_v2(
                &access,
                key,
                &c.candidate_id,
                4,
                input,
                &c,
                &command,
                &built.built,
                &built.scope,
                limits,
                &observation,
            ));
            (c, built, receipt, materials)
        }
        fn review(
            c: &CandidateView,
            materials: Vec<PrivateFixedMaterialReviewV3>,
            scope: Option<CheckpointScope>,
        ) -> PrivateFixedStageReviewV3 {
            PrivateFixedStageReviewV3 {
                version: 3,
                purpose: "original-private-fixed-stage-review-v3",
                stage: if scope.is_some() {
                    PrivateFixedStageV3::AdmitOriginal
                } else {
                    PrivateFixedStageV3::Prepare
                },
                workspace_scope: PrivateWorkspaceScopeV1 {
                    source_digest: "11".repeat(32),
                    principal_id: "synthetic-local-constructor".into(),
                    agreement_id: c.proposal.manifest.agreement.agreement_id.clone(),
                    obligation_id: c.proposal.manifest.agreement.obligation_id.clone(),
                    reviewer_account_ids: c
                        .proposal
                        .manifest
                        .participants
                        .iter()
                        .map(|p| p.account_id.clone())
                        .collect(),
                    protected_destination: "/inert-stage-component/metadata.sqlite".into(),
                    retention_policy: "temporary stage component ciphertext".into(),
                },
                marker_digest: "22".repeat(32),
                native_association_digest: "33".repeat(32),
                metadata_origin: "44".repeat(32),
                proof_origin: "55".repeat(32),
                revision: 4,
                materials,
                checkpoint_scope: scope,
            }
        }
        #[test]
        fn current_scope_descriptor_refuses_either_expired_material_and_overflow() {
            let c = checked(crate::candidates::build_exact_candidate_v2(
                fixture().request,
            ));
            let mut data = materials(&c);
            checked(check_stage_material_ceilings_v3(&data));
            for index in 0..2 {
                let old = data[index].scope.clone();
                let now = checked(stage_now_v3());
                data[index].scope.valid_from_unix_seconds = now - 300;
                data[index].scope.valid_until_unix_seconds = now;
                let error = check_stage_material_ceilings_v3(&data).unwrap_err();
                assert_eq!(
                    error.details["private_fixed_stage_cause_v3"],
                    json!({"family":"DurableConstruction","cause":"Stale"})
                );
                data[index].scope = old;
            }
            checked(check_stage_material_ceilings_v3(&data));
            let mut descriptor = review(&c, data, None);
            checked(bounded_stage_review_v3(&descriptor));
            let encoded = checked(serde_json::to_value(&descriptor));
            let keys = encoded
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>();
            assert_eq!(
                keys,
                [
                    "version",
                    "purpose",
                    "stage",
                    "workspace_scope",
                    "marker_digest",
                    "native_association_digest",
                    "metadata_origin",
                    "proof_origin",
                    "revision",
                    "materials",
                    "checkpoint_scope"
                ]
                .into_iter()
                .map(str::to_owned)
                .collect()
            );
            for entry in encoded["materials"].as_array().unwrap() {
                assert_eq!(
                    entry
                        .as_object()
                        .unwrap()
                        .keys()
                        .cloned()
                        .collect::<BTreeSet<_>>(),
                    ["scope".into(), "material_digest".into()]
                        .into_iter()
                        .collect()
                );
            }
            descriptor.stage = PrivateFixedStageV3::ProveOriginal;
            assert!(bounded_stage_review_v3(&descriptor).is_err());
            descriptor.stage = PrivateFixedStageV3::Prepare;
            descriptor.workspace_scope.retention_policy = "x".repeat(MAX_STAGE_REVIEW_BYTES_V3);
            assert!(bounded_stage_review_v3(&descriptor).is_err());
            assert!(matches!(
                PrepareModeV3::StagePreparation.action(),
                PrivateWorkspaceActionV1::PrepareFixedStageV3
            ));
            assert!(matches!(
                PrepareModeV3::LegacyCheckpoint.action(),
                PrivateWorkspaceActionV1::CheckpointExactOriginal
            ));
        }
        #[test]
        fn actual_constructor_scope_projection_rejects_changed_receipt_and_never_exposes_artifact()
        {
            ORIGINAL_CONSTRUCTOR_CALLS_V2.with(|n| n.set(0));
            let (c, built, receipt, materials) = constructed();
            let projected = checked(retained_review_scope_v3(&c, &receipt, &materials));
            assert!(projected == built.scope);
            for field in [
                "scope_digest",
                "principal_id",
                "candidate_id",
                "manifest_digest",
                "coordination_request_digest",
                "artifact_digest",
                "review_binding",
                "effects_commitment",
            ] {
                let mut value = checked(serde_json::to_value(&receipt));
                value[field] = json!("00".repeat(32));
                let changed: crate::candidates::CheckpointReceipt =
                    checked(serde_json::from_value(value));
                assert!(retained_review_scope_v3(&c, &changed, &materials).is_err());
            }
            let mut descriptor = review(&c, materials, Some(projected));
            checked(bounded_stage_review_v3(&descriptor));
            assert!(descriptor.checkpoint_scope() == Some(&built.scope));
            assert!(descriptor.materials().len() == 2);
            descriptor.stage = PrivateFixedStageV3::Prepare;
            assert!(bounded_stage_review_v3(&descriptor).is_err());
            ORIGINAL_CONSTRUCTOR_CALLS_V2.with(|n| assert_eq!(n.get(), 1));
        }
        #[test]
        fn metadata_review_gate_allows_only_exact_status_and_checks_current_twice() {
            let c = checked(crate::candidates::build_exact_candidate_v2(
                fixture().request,
            ));
            let scope = CheckpointScope {
                principal_id: "synthetic-local-constructor".into(),
                candidate_id: c.candidate_id,
                manifest_digest: c.manifest_digest,
                artifact_digest: "11".repeat(32),
                effects_commitment: "22".repeat(32),
                coordination_request_digest: "33".repeat(32),
                review_binding: "44".repeat(32),
                account_ids: vec![],
                local_operator: "synthetic-local-constructor".into(),
                purpose: "inert metadata gate".into(),
                retention_policy: "inert".into(),
            };
            let calls = Cell::new(0);
            for action in [
                LocalAction::RetainPrivateWitnesses,
                LocalAction::ProveLocally,
                LocalAction::ReadPrivateArtifact,
            ] {
                assert!(!metadata_review_permission_v3(
                    &scope,
                    &scope,
                    action,
                    || {
                        calls.set(calls.get() + 1);
                        Ok(())
                    }
                ));
            }
            assert_eq!(calls.get(), 0);
            let mut wrong = scope.clone();
            wrong.artifact_digest = "55".repeat(32);
            assert!(!metadata_review_permission_v3(
                &wrong,
                &scope,
                LocalAction::InspectStatus,
                || {
                    calls.set(calls.get() + 1);
                    Ok(())
                }
            ));
            assert_eq!(calls.get(), 0);
            assert!(metadata_review_permission_v3(
                &scope,
                &scope,
                LocalAction::InspectStatus,
                || {
                    calls.set(calls.get() + 1);
                    Ok(())
                }
            ));
            assert_eq!(calls.get(), 2);
            calls.set(0);
            assert!(!metadata_review_permission_v3(
                &scope,
                &scope,
                LocalAction::InspectStatus,
                || {
                    calls.set(calls.get() + 1);
                    Err(denied())
                }
            ));
            assert_eq!(calls.get(), 1);
            calls.set(0);
            assert!(!metadata_review_permission_v3(
                &scope,
                &scope,
                LocalAction::InspectStatus,
                || {
                    calls.set(calls.get() + 1);
                    if calls.get() == 1 {
                        Ok(())
                    } else {
                        Err(denied())
                    }
                }
            ));
            assert_eq!(calls.get(), 2);
        }
        #[test]
        fn stage_scope_error_keeps_owned_error_fields_and_omits_unknown_or_collision() {
            use wholepact_wallet::wallet::protected_sync::durable_construction_v1::DurableConstructionError;
            let original = ApiError::from(DurableConstructionError::Stale);
            let mut input = ApiError::from(DurableConstructionError::Stale);
            input.details = Box::new(json!({"existing":"kept"}));
            let actual = preserve_stage_scope_cause_v3(
                input,
                diagnostics::construction(&DurableConstructionError::Stale),
            );
            assert_eq!(actual.code, original.code);
            assert_eq!(actual.message, original.message);
            assert_eq!(actual.retryable, original.retryable);
            assert_eq!(actual.safe_actions, original.safe_actions);
            assert_eq!(actual.operation_id, original.operation_id);
            assert_eq!(actual.details["existing"], "kept");
            assert_eq!(
                actual.details["private_fixed_stage_cause_v3"],
                json!({"family":"DurableConstruction","cause":"Stale"})
            );
            assert!(actual.details.get("private_fixed_diagnostic_v1").is_none());
            let mut collision = denied();
            collision.details =
                Box::new(json!({"private_fixed_stage_cause_v3":{"existing":"opaque"}}));
            let saved = collision.details.clone();
            let collision = preserve_stage_scope_cause_v3(
                collision,
                diagnostics::construction(&DurableConstructionError::Stale),
            );
            assert_eq!(collision.details, saved);
            for cause in [
                diagnostics::Cause {
                    family: "DurableConstruction",
                    cause: "Unknown",
                },
                diagnostics::Cause {
                    family: "unknown",
                    cause: "Stale",
                },
            ] {
                let input = denied();
                let saved = input.details.clone();
                assert_eq!(preserve_stage_scope_cause_v3(input, cause).details, saved);
            }
            let mut nonobject = denied();
            nonobject.details = Box::new(json!("opaque"));
            assert_eq!(
                *preserve_stage_scope_cause_v3(
                    nonobject,
                    diagnostics::construction(&DurableConstructionError::Stale)
                )
                .details,
                json!("opaque")
            );
        }
        #[test]
        fn metadata_bool_failure_preserves_first_cause_only_on_same_terminal_error() {
            fn failure(cause: &'static str) -> ApiError {
                preserve_stage_scope_cause_v3(
                    denied(),
                    diagnostics::Cause {
                        family: "DurableConstruction",
                        cause,
                    },
                )
            }
            let collector = StageInspectionFailureV3::default();
            let original: crate::Result<()> = Err(failure("Stale"));
            collector.observe(&original);
            collector.observe(&Err::<(), _>(failure("Binding")));
            let terminal = job_error(wholepact_proof_jobs::JobError::ConsentDenied);
            let code = terminal.code.clone();
            let message = terminal.message.clone();
            let details = terminal.details.clone();
            let retryable = terminal.retryable;
            let operation_id = terminal.operation_id.clone();
            let actions = terminal.safe_actions.clone();
            let result: crate::Result<()> = collector.finish(Err(terminal));
            let actual = result.unwrap_err();
            assert_eq!(actual.code, code);
            assert_eq!(actual.message, message);
            assert_eq!(actual.retryable, retryable);
            assert_eq!(actual.operation_id, operation_id);
            assert_eq!(actual.safe_actions, actions);
            assert_eq!(
                actual.details["private_original_job_error_v1"],
                details["private_original_job_error_v1"]
            );
            assert_eq!(
                actual.details["private_fixed_stage_cause_v3"]["cause"],
                "Stale"
            );
            assert!(actual.details.get("private_fixed_diagnostic_v1").is_none());
            assert_eq!(collector.finish(Ok(Box::new(7))).unwrap(), Box::new(7));
            let clean = StageInspectionFailureV3::default();
            let untouched: crate::Result<()> = clean.finish(Err(denied()));
            assert!(
                untouched
                    .unwrap_err()
                    .details
                    .get("private_fixed_stage_cause_v3")
                    .is_none()
            );
            for detail in [
                json!({"family":"DurableConstruction","cause":"Stale","extra":true}),
                json!({"family":"unknown","cause":"Stale"}),
                json!("malformed"),
            ] {
                let first = StageInspectionFailureV3::default();
                let mut error = denied();
                error.details = Box::new(json!({"private_fixed_stage_cause_v3":detail}));
                first.observe(&Err::<(), _>(error));
                first.observe(&original);
                let result: crate::Result<()> = first.finish(Err(denied()));
                assert!(
                    result
                        .unwrap_err()
                        .details
                        .get("private_fixed_stage_cause_v3")
                        .is_none()
                );
            }
        }
        struct ExactScope(CheckpointScope);
        impl LocalProofConsent for ExactScope {
            fn permits(&self, scope: &CheckpointScope, _: LocalAction) -> bool {
                scope == &self.0
            }
        }
        struct DenyAfterComputation {
            scope: CheckpointScope,
            prove: AtomicUsize,
            retain: AtomicUsize,
        }
        impl LocalProofConsent for DenyAfterComputation {
            fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
                if scope != &self.scope {
                    return false;
                }
                match action {
                    LocalAction::ProveLocally => self.prove.fetch_add(1, Ordering::SeqCst) == 0,
                    LocalAction::RetainPrivateWitnesses => {
                        self.retain.fetch_add(1, Ordering::SeqCst);
                        true
                    }
                    _ => false,
                }
            }
        }
        /// ACTUAL Halo2 computation and real original-qualified encrypted journal.
        /// This is a proof-job component, not a fabricated native/source facade.
        #[test]
        fn actual_halo2_postcompute_denial_is_uncertain_and_cannot_restart_original_attempt() {
            let (_, built, _, _) = constructed();
            let dir = checked(tempfile::tempdir());
            checked(std::fs::set_permissions(
                dir.path(),
                std::fs::Permissions::from_mode(0o700),
            ));
            let jobs = checked(
                wholepact_proof_jobs::ProofJobStore::from_original_encrypted_connection_v1(
                    checked(wholepact_storage_security::create_encrypted(
                        dir.path().join("proof.sqlite"),
                        &DatabaseKey::from_bytes([137; 32]),
                    )),
                ),
            );
            let source = checked(jobs.original_source_v1());
            let allow = ExactScope(built.scope.clone());
            let key = "postcompute-denial-original-command";
            let limits = ProvingLimits { maximum_actions: 8 };
            let outcome = checked(source.enqueue_original_once_v1(
                &built.scope,
                key,
                &built.built.pczt_bytes,
                &built.built.review_policy,
                limits,
                &allow,
            ));
            let (queued, attempt) = outcome.into_parts();
            assert!(queued.state == wholepact_proof_jobs::JobState::Queued && queued.attempt == 0);
            let deny = DenyAfterComputation {
                scope: built.scope.clone(),
                prove: AtomicUsize::new(0),
                retain: AtomicUsize::new(0),
            };
            let result = attempt.unwrap().run_original_queued_v1(&deny);
            assert!(matches!(
                result,
                Err(wholepact_proof_jobs::JobError::ConsentDenied)
            ));
            // The second Prove callback is after the real prove_reviewed call.
            // Short-circuit denial suppresses the second Retain callback.
            assert_eq!(deny.prove.load(Ordering::SeqCst), 2);
            assert_eq!(deny.retain.load(Ordering::SeqCst), 1);
            let actual = checked(source.status(&built.scope.principal_id, &queued.job_id, &allow));
            assert!(
                actual.state == wholepact_proof_jobs::JobState::Uncertain && actual.attempt == 1
            );
            assert!(!actual.proof_verified && actual.result_digest.is_none());
            assert!(matches!(
                source.load_verified(&built.scope.principal_id, &queued.job_id, &allow),
                Err(wholepact_proof_jobs::JobError::StateConflict)
            ));
            let replay = checked(source.enqueue_original_once_v1(
                &built.scope,
                key,
                &built.built.pczt_bytes,
                &built.built.review_policy,
                limits,
                &allow,
            ));
            let (replayed, fresh) = replay.into_parts();
            assert_eq!(replayed, actual);
            assert!(fresh.is_none());
            assert!(matches!(
                jobs.run_original_queued(&built.scope.principal_id, &queued.job_id, &allow),
                Err(wholepact_proof_jobs::JobError::StateConflict)
            ));
            assert_eq!(
                checked(source.status(&built.scope.principal_id, &queued.job_id, &allow)),
                actual
            );
        }
    }

    /// Same-kernel lifecycle components, not a fabricated original source or
    /// native approval. One actual randomized unsigned artifact is reused.
    mod prepared_lifecycle {
        use super::*;
        use wholepact_protocol::construction::SpendableNote;
        fn checked<T, E>(value: std::result::Result<T, E>) -> T {
            match value {
                Ok(value) => value,
                Err(_) => panic!("prepared lifecycle component failed"),
            }
        }
        fn copies(values: &[OwnedContribution]) -> Vec<OwnedContribution> {
            values
                .iter()
                .map(|v| OwnedContribution {
                    account_id: v.account_id.clone(),
                    fvk: v.fvk.clone(),
                    change_address: v.change_address,
                    notes: v
                        .notes
                        .iter()
                        .map(|n| SpendableNote {
                            input_id: n.input_id.clone(),
                            note: n.note.clone(),
                            witness: n.witness.clone(),
                        })
                        .collect(),
                })
                .collect()
        }
        #[test]
        fn prepared_context_accepts_advance_but_not_rewind_anchor_or_expiry_change() {
            let original = ConstructionContext {
                anchor: [1; 32],
                anchor_height: 4_465_040,
                anchor_block_hash: [2; 32],
                target_height: 4_465_041,
            };
            checked(validate_prepared_context_v2(original, original, 4_465_070));
            let mut advanced = original;
            advanced.target_height += 2;
            checked(validate_prepared_context_v2(original, advanced, 4_465_070));
            for current in [
                ConstructionContext {
                    target_height: original.target_height - 1,
                    ..original
                },
                ConstructionContext {
                    target_height: 4_465_071,
                    ..original
                },
                ConstructionContext {
                    anchor: [3; 32],
                    ..original
                },
                ConstructionContext {
                    anchor_height: original.anchor_height + 1,
                    ..original
                },
                ConstructionContext {
                    anchor_block_hash: [4; 32],
                    ..original
                },
            ] {
                assert!(validate_prepared_context_v2(original, current, 4_465_070).is_err());
            }
            // NU7 and real current note/ancestry eligibility are established by
            // the unchanged Wallet held kernel, not by this inert context DTO.
        }
        #[test]
        fn original_artifact_moves_once_across_advancing_join_and_fresh_only_recheck() {
            ORIGINAL_CONSTRUCTOR_CALLS_V2.with(|count| count.set(0));
            let f = fixture();
            let dir = checked(tempfile::tempdir());
            checked(std::fs::set_permissions(
                dir.path(),
                std::fs::Permissions::from_mode(0o700),
            ));
            let metadata = dir.path().join("metadata.sqlite");
            let proof_path = dir.path().join("proof.sqlite");
            let engine = Engine::from_store(checked(wholepact_store::Store::create_encrypted(
                &metadata,
                &DatabaseKey::from_bytes([126; 32]),
            )));
            let proof_key = DatabaseKey::from_bytes([127; 32]);
            let jobs = checked(
                wholepact_proof_jobs::ProofJobStore::from_encrypted_connection(checked(
                    wholepact_storage_security::create_encrypted(&proof_path, &proof_key),
                )),
            );
            let access = Access {
                principal_id: "synthetic-component-owner".into(),
                include_owned_agreements: true,
                ..Access::default()
            };
            checked(engine.create(
                &access,
                "prepared-component-create-command",
                f.agreement.clone(),
            ));
            for (i, p) in f.request.manifest.participants.iter().enumerate() {
                checked(engine.add_intent(
                    &access,
                    &format!("prepared-component-intent-{i}"),
                    &f.agreement.agreement_id,
                    i as u64 + 1,
                    ParticipationIntent {
                        intent_id: format!("prepared-intent-{i}"),
                        agreement_id: f.agreement.agreement_id.clone(),
                        participant_id: p.participant_id.clone(),
                        desired_contribution: p.contribution,
                        maximum_net_debit: p.maximum_net_debit,
                        fee_cap: p.fee_cap,
                        conditions: vec![],
                        valid_until: None,
                        status: IntentStatus::Active,
                    },
                ));
            }
            let candidate = checked(engine.create_candidate(
                &access,
                "prepared-component-candidate-command",
                &f.agreement.agreement_id,
                3,
                f.request,
            ));
            let c = candidate.agreement.candidates[0].clone();
            let before = checked(engine.load(&access, &f.agreement.agreement_id));
            assert!(before.private_workspace_origin_v1.is_none());
            let revision = before.view.revision;
            let declarations: Vec<_> = f
                .account_ids
                .iter()
                .map(|account| DisclosureAcknowledgement {
                    account_id: account.clone(),
                    manifest_digest: checked(hex::decode(&c.manifest_digest)).try_into().unwrap(),
                    operator: "synthetic-local-constructor".into(),
                    reviewer_account_ids: f.account_ids.clone(),
                    purpose: "actual synthetic proof component".into(),
                    retention_policy: "temporary component ciphertext".into(),
                    scope: DisclosureScope::DedicatedAccountFvkAndSelectedNotesAndOutputs,
                })
                .collect();
            let key = "prepared-component-checkpoint-command";
            let limits = ProvingLimits { maximum_actions: 8 };
            let input_digest = checked(crate::candidates::private_request_digest(
                f.chain,
                &f.packages,
                &declarations,
            ));
            let command = checked(crate::context(
                &access,
                key,
                "private_checkpoint_exact_original_v2",
                &c.candidate_id,
                Some(revision),
                &json!({"local_input_digest":input_digest,"maximum_actions":limits.maximum_actions}),
            ));
            let privacy = ExactProofPrivacy {
                principal: access.principal_id.clone(),
                candidate: c.candidate_id.clone(),
                manifest: c.manifest_digest.clone(),
                accounts: f.account_ids.clone(),
            };
            let observation = Observation::new(Operation::Checkpoint);
            let records = checked(engine.store.list_records("agreement"));
            let events = checked(engine.store.events_after(0, 64));
            let metadata_bytes = checked(std::fs::read(&metadata));
            let proof_bytes = checked(std::fs::read(&proof_path));
            checked(require_fresh_original_checkpoint_v2(
                &before,
                &c.candidate_id,
                revision,
                jobs.status_for_key(&access.principal_id, key, &command.request_digest, &privacy),
                &observation,
            ));
            let constructed = checked(construct_exact_artifact_v2(
                &access,
                &c.candidate_id,
                &c,
                &command,
                crate::candidates::LocalConstruction {
                    context: f.chain,
                    contributions: copies(&f.packages),
                    declarations: &declarations,
                },
                limits,
                &observation,
            ));
            let ConstructedCheckpointV2 { built, scope } = constructed;
            let receipt = checked(prepare_constructor_receipt_v2(
                &access,
                key,
                &c.candidate_id,
                revision,
                input_digest,
                &c,
                &command,
                &built,
                &scope,
                limits,
                &observation,
            ));
            let mut ready = ReadyOriginalCheckpointV2 {
                before: before.clone(),
                original_key: key.into(),
                candidate_id: c.candidate_id.clone(),
                revision,
                command,
                receipt_key: checked(receipt_key(&access, key)),
                receipt,
                built,
                scope,
                limits,
            };
            let original_pointer = ready.built.pczt_bytes.as_ptr();
            let original_bytes = ready.built.pczt_bytes.clone();
            let original_scope = checked(serde_json::to_value(&ready.scope));
            let original_receipt = checked(serde_json::to_value(&ready.receipt));
            let original_request = checked(serde_json::to_value(&ready.command));
            let original_policy_allocations = (
                ready.built.review_policy.participants.as_ptr(),
                ready.built.review_policy.inputs.as_ptr(),
                ready.built.review_policy.outputs.as_ptr(),
            );
            let original_review = checked(serde_json::to_value(checked(
                wholepact_protocol::review::verify_review(
                    &ready.built.pczt_bytes,
                    &ready.built.review_policy,
                ),
            )));
            let mut advanced = f.chain;
            advanced.target_height += 1;
            checked(validate_prepared_join_v2(
                &ready,
                &before,
                advanced,
                &f.packages,
                &declarations,
            ));
            assert!(
                checked(crate::candidates::private_request_digest(
                    advanced,
                    &f.packages,
                    &declarations
                )) != ready
                    .receipt
                    .original_request_v2
                    .as_ref()
                    .unwrap()
                    .local_input_digest
            );
            let mut changed = before.clone();
            changed.view.revision += 1;
            assert!(
                validate_prepared_join_v2(&ready, &changed, advanced, &f.packages, &declarations)
                    .is_err()
            );
            let mut changed_inputs = copies(&f.packages);
            changed_inputs[0].notes[0].input_id.push('x');
            assert!(
                validate_prepared_join_v2(
                    &ready,
                    &before,
                    advanced,
                    &changed_inputs,
                    &declarations
                )
                .is_err()
            );
            let old_scope = ready.scope.clone();
            ready.scope.retention_policy.push('x');
            assert!(
                validate_prepared_join_v2(&ready, &before, advanced, &f.packages, &declarations)
                    .is_err()
            );
            ready.scope = old_scope;
            let old_digest = ready.command.request_digest.clone();
            ready.command.request_digest = "0".repeat(64);
            assert!(
                validate_prepared_join_v2(&ready, &before, advanced, &f.packages, &declarations)
                    .is_err()
            );
            ready.command.request_digest = old_digest;
            let ready = checked(consume_prepared_join_v2(
                ready,
                &before,
                advanced,
                &f.packages,
                &declarations,
            ));
            assert!(
                ready.built.pczt_bytes.as_ptr() == original_pointer
                    && ready.built.pczt_bytes == original_bytes
            );
            assert!(checked(serde_json::to_value(&ready.scope)) == original_scope);
            assert!(checked(serde_json::to_value(&ready.receipt)) == original_receipt);
            assert!(checked(serde_json::to_value(&ready.command)) == original_request);
            assert!(
                original_policy_allocations
                    == (
                        ready.built.review_policy.participants.as_ptr(),
                        ready.built.review_policy.inputs.as_ptr(),
                        ready.built.review_policy.outputs.as_ptr(),
                    )
            );
            assert!(
                checked(serde_json::to_value(checked(
                    wholepact_protocol::review::verify_review(
                        &ready.built.pczt_bytes,
                        &ready.built.review_policy
                    ),
                ))) == original_review
            );
            ORIGINAL_CONSTRUCTOR_CALLS_V2.with(|count| assert_eq!(count.get(), 1));
            assert!(
                records == checked(engine.store.list_records("agreement"))
                    && events == checked(engine.store.events_after(0, 64))
            );
            assert!(
                metadata_bytes == checked(std::fs::read(&metadata))
                    && proof_bytes == checked(std::fs::read(&proof_path))
            );
            // A REAL queued row is now created solely for the refusal control.
            // No completed proof, native source owner or continuation is fabricated.
            checked(jobs.enqueue(
                &ready.scope,
                key,
                &ready.built.pczt_bytes,
                &ready.built.review_policy,
                limits,
                &privacy,
            ));
            let actual = jobs.status_for_key(
                &access.principal_id,
                key,
                &ready.command.request_digest,
                &privacy,
            );
            assert!(actual.as_ref().is_ok_and(|s| s.is_some()));
            assert!(
                require_fresh_original_checkpoint_v2(
                    &before,
                    &c.candidate_id,
                    revision,
                    actual,
                    &observation
                )
                .is_err()
            );
            let actual_error =
                jobs.status_for_key(&access.principal_id, key, &"0".repeat(64), &privacy);
            assert!(matches!(
                actual_error,
                Err(wholepact_proof_jobs::JobError::IdempotencyConflict)
            ));
            let error = require_fresh_original_checkpoint_v2(
                &before,
                &c.candidate_id,
                revision,
                actual_error,
                &observation,
            )
            .err()
            .unwrap();
            assert_eq!(error.code, "IDEMPOTENCY_CONFLICT");
            let mut partial = before.clone();
            partial
                .checkpoint_receipts
                .insert(ready.receipt_key.clone(), ready.receipt.clone());
            assert!(
                require_fresh_original_checkpoint_v2(
                    &partial,
                    &c.candidate_id,
                    revision,
                    Ok(None),
                    &observation
                )
                .is_err()
            );
            assert!(
                require_fresh_original_checkpoint_v2(
                    &before,
                    &c.candidate_id,
                    revision + 1,
                    Ok(None),
                    &observation
                )
                .is_err()
            );
            // Failure also consumes this memory-only Ready value. It cannot be
            // reused or converted to OriginalProofAttemptV2 from either Result.
            let failed =
                consume_prepared_join_v2(ready, &changed, advanced, &f.packages, &declarations);
            assert!(failed.is_err());
            ORIGINAL_CONSTRUCTOR_CALLS_V2.with(|count| assert_eq!(count.get(), 1));
            assert!(
                records == checked(engine.store.list_records("agreement"))
                    && events == checked(engine.store.events_after(0, 64))
            );
        }
    }
    /// Data-only mathematical/history component. Serialized historical labels
    /// are not native approvals. No authenticated disclosure, source owner,
    /// fresh observation, proof job or continuation is created by this module.
    mod immutable_validation {
        use super::*;
        use crate::durable_construction_v1::{Intake, MaterialCheckErrorV2, Roster};
        use std::cell::Cell;
        use std::path::{Path, PathBuf};
        use std::time::{Instant, SystemTime, UNIX_EPOCH};
        use wholepact_signer::authority_bridge::durable_construction_v1::{
            DurableConstructionOutboxV1, DurableConstructionRequestV1,
            HistoricalConstructionMaterialV1,
        };
        use wholepact_signer::consent_journal::TransportIdentityBinding;
        use wholepact_wallet::wallet::protected_sync::durable_construction_v1::{
            ConstructionRecipientV1, ConstructionReviewerV1, DurableConstructionScopeV1, PURPOSE,
        };

        fn checked<T, E>(result: std::result::Result<T, E>) -> T {
            match result {
                Ok(value) => value,
                Err(_) => panic!("inert mathematical component failed"),
            }
        }
        fn hash(byte: u8) -> String {
            format!("{byte:02x}").repeat(32)
        }
        fn unix_now() -> u64 {
            checked(SystemTime::now().duration_since(UNIX_EPOCH)).as_secs()
        }
        fn material(f: &Fixture, index: usize) -> HistoricalConstructionMaterialV1 {
            let owner = &f.packages[index];
            let notes: Vec<_> = owner.notes.iter().map(|n| {
                let mut fields = n.input_id.split(':');
                assert!(fields.next() == Some("ironwood"));
                let mut txid = checked(hex::decode(fields.next().unwrap_or("")));
                txid.reverse();
                let output_index = checked(fields.next().unwrap_or("").parse::<u16>());
                assert!(fields.next().is_none());
                json!({"input_id":n.input_id,"txid_protocol":hex::encode(txid),"output_index":output_index,
                    "recipient":hex::encode(n.note.recipient().to_raw_address_bytes()),
                    "value_zatoshis":n.note.value().inner(),"rho":hex::encode(n.note.rho().to_bytes()),
                    "rseed":hex::encode(n.note.rseed().as_bytes()),
                    "nullifier":hex::encode(n.note.nullifier(&owner.fvk).to_bytes()),
                    "commitment":hex::encode(orchard::note::ExtractedNoteCommitment::from(n.note.commitment()).to_bytes()),
                    "position":n.witness.position(),
                    "authentication_path":n.witness.auth_path().iter().map(|p|hex::encode(p.to_bytes())).collect::<Vec<_>>()})
            }).collect();
            let c = &f.selection;
            checked(HistoricalConstructionMaterialV1::decode(&checked(
                serde_json::to_vec(&json!({
                    "version":1,"account_id":owner.account_id,"fvk_hex":hex::encode(owner.fvk.to_bytes()),
                    "fvk_digest":hex::encode(Sha256::digest(owner.fvk.to_bytes())),
                    "selected_zatoshis":owner.notes.iter().map(|n|n.note.value().inner()).sum::<u64>(),
                    "requested_debit_zatoshis":f.request.manifest.participants[index].maximum_net_debit.as_zatoshis(),
                    "change_address":hex::encode(owner.change_address.to_raw_address_bytes()),
                    "birthday_height":c.anchor_height,
                    "context":{"tip_height":c.tip_height,"tip_hash_protocol":hex::encode(c.tip_hash_protocol),
                        "anchor_height":c.anchor_height,"anchor_hash_protocol":hex::encode(c.anchor_hash_protocol),
                        "anchor_root":hex::encode(c.anchor_root)},
                    "source":{"source_id":"inert-engine-math-component","endpoint":"https://component.invalid",
                        "trust_profile":"single_tls_provider_report_not_consensus","network":"test",
                        "branch_id":"0x77190ad9","lightwalletd_version":"synthetic-component",
                        "backend_subversion":"synthetic-no-backend","protocol_version":"synthetic-component-v1",
                        "request_started":1800000000u64,"observed_at":1800000001u64,"valid_until":1800000060u64},
                    "notes":notes
                })),
            )))
        }
        fn outbox(
            proposal: &ProposalInput,
            material: HistoricalConstructionMaterialV1,
            index: usize,
            destination: &Path,
            valid_from: u64,
            valid_until: u64,
        ) -> DurableConstructionOutboxV1 {
            let grant = hash(0x20 + index as u8);
            let channel = hash(0x30 + index as u8);
            let grant_id = hash(0x40 + index as u8);
            let principal = "synthetic-local-constructor";
            let scope = DurableConstructionScopeV1 {
                version: 2,
                purpose: PURPOSE.into(),
                proposal: proposal.clone(),
                account_id: proposal.manifest.participants[index].account_id.clone(),
                participant_id: proposal.manifest.participants[index].participant_id.clone(),
                privacy_domain: "inert-private-component".into(),
                constructor: ConstructionRecipientV1 {
                    principal_id: principal.into(),
                    authenticated_local_grant_digest: grant.clone(),
                },
                prover: ConstructionRecipientV1 {
                    principal_id: principal.into(),
                    authenticated_local_grant_digest: grant.clone(),
                },
                reviewers: proposal
                    .manifest
                    .participants
                    .iter()
                    .map(|p| ConstructionReviewerV1::local_installed_signer(p.account_id.clone()))
                    .collect(),
                protected_destination: destination.to_str().unwrap().into(),
                retention_policy: "temporary inert encrypted component".into(),
                valid_from_unix_seconds: valid_from,
                valid_until_unix_seconds: valid_until,
                minimum_confirmations: 1,
                maximum_scan_blocks: 100,
            };
            let verified = checked(Proposal::validate(proposal.clone()));
            let transport = TransportIdentityBinding::LocalProcess {
                transport_identity_id: grant_id.clone(),
                channel_key_digest: grant.clone(),
                channel_binding_digest: channel.clone(),
                uid: 42,
                pid: 100 + index as u32,
                process_instance: hash(0x50 + index as u8),
                signer_generation: 1,
                account_id: scope.account_id.clone(),
                agreement_id: proposal.manifest.agreement.agreement_id.clone(),
                participant_id: scope.participant_id.clone(),
                manifest_digest: verified.manifest_digest().into(),
            };
            let request = DurableConstructionRequestV1 {
                operation_id: format!("inert-math-operation-{index}"),
                enrollment_ref: hash(0x60 + index as u8),
                accepted_manifest_ref: hash(0x70 + index as u8),
                scope,
                material,
            };
            let request_digest = checked(request.digest());
            let material_digest = checked(request.material.digest());
            let review = hash(0x80 + index as u8);
            let entry = hash(0x90 + index as u8);
            let reference = checked(wholepact_core::proposal::canonical_digest(
                "wholepact:durable-construction-consent-outbox:v1",
                &(
                    &request_digest,
                    &material_digest,
                    &review,
                    &entry,
                    &grant,
                    &channel,
                    &grant_id,
                    &transport,
                    Option::<serde_json::Value>::None,
                ),
            ));
            let value = checked(serde_json::from_value(
                json!({"request":request,"request_digest":request_digest,
                "material_digest":material_digest,"native_review_digest":review,"native_entry_digest":entry,
                "recipient_grant_digest":grant,"original_channel_digest":channel,"original_grant_id":grant_id,
                "recipient_transport":transport,"reference":reference}),
            ));
            let value: DurableConstructionOutboxV1 = value;
            checked(value.validate());
            value
        }
        struct HistoryFixture {
            _dir: tempfile::TempDir,
            path: PathBuf,
            engine: Engine,
            envelopes: Vec<Envelope>,
            intake: Intake,
        }
        fn history_fixture() -> HistoryFixture {
            let f = fixture();
            let dir = checked(tempfile::tempdir());
            checked(std::fs::set_permissions(
                dir.path(),
                std::fs::Permissions::from_mode(0o700),
            ));
            let path = dir.path().join("inert-history.sqlite");
            let engine = Engine::from_store(checked(wholepact_store::Store::create_encrypted(
                &path,
                &DatabaseKey::from_bytes([123; 32]),
            )));
            let origin = checked(engine.store.verify_original_encrypted_destination(&path));
            let access = Access {
                principal_id: "synthetic-local-constructor".into(),
                include_owned_agreements: true,
                ..Access::default()
            };
            let seed_engine = checked(Engine::in_memory());
            checked(seed_engine.create(
                &access,
                "inert-component-seed-command",
                f.agreement.clone(),
            ));
            let record =
                checked(seed_engine.store.get_agreement(&f.agreement.agreement_id)).unwrap();
            let mut seed = checked(crate::decode_unprojected(&record));
            seed.terms_editing_origin = false;
            seed.view.roster_selected = true;
            seed.view.progress = "preparing_proposal".into();
            assert!(seed.private_workspace_origin_v1.is_none());
            let mut candidate = advance(seed.clone());
            candidate
                .view
                .candidates
                .push(checked(crate::candidates::build_exact_candidate_v2(
                    f.request.clone(),
                )));
            let now = unix_now();
            let mut roster = Roster::default();
            let mut envelopes = vec![seed, candidate];
            for index in 0..2 {
                let proposal = &envelopes[1].view.candidates[0].proposal;
                let value = Intake {
                    schema_version: 1,
                    principal_id: access.principal_id.clone(),
                    metadata_origin: hex::encode(origin),
                    signer_enrollment_reference: hash(0xa0 + index as u8),
                    signer_process_instance: hash(0xb0 + index as u8),
                    outbox: outbox(
                        proposal,
                        material(&f, index),
                        index,
                        &path,
                        now - 1,
                        now + 3599,
                    ),
                };
                roster
                    .owners
                    .insert(value.outbox.request().scope.account_id.clone(), value);
                let mut next = advance(envelopes.last().unwrap().clone());
                next.durable_construction_v1.insert(
                    next.view.candidates[0].candidate_id.clone(),
                    checked(serde_json::to_value(&roster)),
                );
                envelopes.push(next);
            }
            let intake = roster.owners.values().next().unwrap().clone();
            let mut receipt = advance(envelopes.last().unwrap().clone());
            receipt
                .checkpoint_receipts
                .insert(hash(0xc0), inert_receipt(&receipt.view.candidates[0]));
            envelopes.push(receipt);
            for (i, e) in envelopes.iter().enumerate() {
                checked(operation_v1::validate_shape(e));
                let command = checked(wholepact_store::CommandContext::for_request(
                    &access.principal_id,
                    &format!("inert-history-command-{i}"),
                    &json!(i),
                ));
                if i == 0 {
                    checked(engine.store.create_agreement(
                        &command,
                        &e.view.agreement.agreement_id,
                        checked(crate::encode(e)),
                    ));
                } else {
                    checked(engine.store.update_agreement(
                        &command,
                        &e.view.agreement.agreement_id,
                        i as u64,
                        checked(crate::encode(e)),
                        event(i),
                    ));
                }
            }
            HistoryFixture {
                _dir: dir,
                path,
                engine,
                envelopes,
                intake,
            }
        }
        fn event(i: usize) -> &'static str {
            match i {
                1 => "private_exact_candidate_prepared_v2",
                2 | 3 => "private_exact_material_retained_v2",
                4 => "private_original_constructor_recorded_v2",
                _ => panic!("invalid component phase"),
            }
        }
        fn purpose(i: usize) -> EffectV2 {
            match i {
                1 => EffectV2::PrepareExactCandidate,
                2 | 3 => EffectV2::RetainExactMaterial,
                4 => EffectV2::ConstructorReceipt,
                _ => panic!("invalid component phase"),
            }
        }
        fn owner_count(e: &Envelope) -> usize {
            e.durable_construction_v1
                .values()
                .map(|v| {
                    checked(serde_json::from_value::<Roster>(v.clone()))
                        .owners
                        .len()
                })
                .sum()
        }
        // Same pure read composition as the production traversal, deliberately
        // without native-marker/source checks or claims of coordinator authority.
        fn walk(f: &HistoryFixture, reuse: bool) -> crate::Result<(serde_json::Value, usize)> {
            let current = f
                .engine
                .store
                .get_agreement(&f.envelopes[0].view.agreement.agreement_id)
                .map_err(crate::store_error)?
                .ok_or_else(damaged)?;
            let current = decode_private_record(&current)?;
            operation_v1::validate_shape(&current)?;
            let mut validations = 2 * owner_count(&current);
            let mut previous: Option<Envelope> = None;
            for (i, event) in f
                .engine
                .store
                .events_after(0, 9)
                .map_err(crate::store_error)?
                .iter()
                .enumerate()
            {
                let operation = f
                    .engine
                    .store
                    .get_operation(&event.operation_id)
                    .map_err(crate::store_error)?
                    .ok_or_else(damaged)?;
                let saved: wholepact_store::MutationResult =
                    serde_json::from_value(operation.result).map_err(|_| damaged())?;
                let envelope = decode_private_record(&saved.record)?;
                operation_v1::validate_shape(&envelope)?;
                validations += 2 * owner_count(&envelope);
                if let Some(before) = &previous {
                    if reuse {
                        operation_v1::validate_delta_after_checked_shapes_v2(
                            before,
                            &envelope,
                            purpose(i),
                        )?;
                    } else {
                        operation_v1::validate_delta(before, &envelope, purpose(i))?;
                        validations += owner_count(before) + owner_count(&envelope);
                    }
                }
                previous = Some(envelope);
            }
            let result = crate::encode(previous.as_ref().ok_or_else(damaged)?)?;
            if result != crate::encode(&current)? {
                return Err(damaged());
            }
            Ok((result, validations))
        }
        fn state(f: &HistoryFixture) -> serde_json::Value {
            let events = checked(f.engine.store.events_after(0, 9));
            let operations: Vec<_> = events
                .iter()
                .map(|e| checked(f.engine.store.get_operation(&e.operation_id)))
                .collect();
            json!({"records":checked(f.engine.store.list_records("agreement")),"events":events,"operations":operations})
        }
        #[test]
        fn encrypted_history_shape_reuse_matches_full_kernels_and_reports_cost() {
            let f = history_fixture();
            let before = state(&f);
            let bytes = checked(std::fs::read(&f.path));
            for sample in 0..3 {
                let started = Instant::now();
                let old = checked(walk(&f, false));
                let old_us = started.elapsed().as_micros();
                let started = Instant::now();
                let new = checked(walk(&f, true));
                let new_us = started.elapsed().as_micros();
                assert!(old.0 == new.0);
                // Source-derived call counts, not runtime material instrumentation.
                assert_eq!((old.1, new.1), (22, 14));
                eprintln!(
                    "IMMUTABLE_COMPONENT engine_history sample={sample} baseline_us={old_us} reused_us={new_us} source_baseline_material_calls=22 source_reused_material_calls=14 equal=true"
                );
            }
            assert!(before == state(&f));
            assert!(bytes == checked(std::fs::read(&f.path)));
        }
        fn checked_delta(
            before: &Envelope,
            after: &Envelope,
            effect: EffectV2,
        ) -> crate::Result<()> {
            operation_v1::validate_shape(before)?;
            operation_v1::validate_shape(after)?;
            operation_v1::validate_delta_after_checked_shapes_v2(before, after, effect)
        }
        fn same_result(a: crate::Result<()>, b: crate::Result<()>) {
            match (a, b) {
                (Ok(()), Ok(())) => {}
                (Err(a), Err(b)) => assert!(
                    a.code == b.code
                        && a.message == b.message
                        && a.details == b.details
                        && a.retryable == b.retryable
                        && a.operation_id == b.operation_id
                        && a.safe_actions == b.safe_actions
                ),
                _ => panic!("component result mismatch"),
            }
        }
        #[test]
        fn checked_shape_tail_preserves_mutation_refusal_and_first_error() {
            let (before, after) = candidate_pair();
            same_result(
                operation_v1::validate_delta(&before, &after, EffectV2::PrepareExactCandidate),
                checked_delta(&before, &after, EffectV2::PrepareExactCandidate),
            );
            let mut variants = Vec::new();
            let mut e = after.clone();
            e.view.revision += 1;
            variants.push(e);
            let mut e = after.clone();
            e.view.updated_at = "invalid".into();
            variants.push(e);
            let mut e = after.clone();
            e.owner_client_id = "changed".into();
            variants.push(e);
            let mut e = after.clone();
            e.view.cancellation_requested = true;
            variants.push(e);
            let mut e = after.clone();
            e.view.authorization_exposure = "changed".into();
            variants.push(e);
            let mut e = after.clone();
            e.view.candidates.push(e.view.candidates[0].clone());
            variants.push(e);
            for e in variants {
                let old =
                    operation_v1::validate_delta(&before, &e, EffectV2::PrepareExactCandidate);
                assert!(old.is_err());
                same_result(
                    old,
                    checked_delta(&before, &e, EffectV2::PrepareExactCandidate),
                );
            }
            let mut wrong_before = before.clone();
            wrong_before.view.chain_observation = "changed".into();
            same_result(
                operation_v1::validate_delta(
                    &wrong_before,
                    &after,
                    EffectV2::PrepareExactCandidate,
                ),
                checked_delta(&wrong_before, &after, EffectV2::PrepareExactCandidate),
            );
            assert!(checked_delta(&before, &after, EffectV2::ConstructorReceipt).is_err());
            let encoded = checked(crate::encode(&after));
            for key in ["unknown_field", "view"] {
                let mut value = encoded.clone();
                if key == "view" {
                    value.as_object_mut().unwrap().remove(key);
                } else {
                    value[key] = json!(true);
                }
                assert!(serde_json::from_value::<Envelope>(value).is_err());
            }
        }
        fn material_damaged() -> ApiError {
            ApiError::new(
                "RECOVERY_REQUIRED",
                "Original authenticated durable disclosure history is missing or inconsistent; preserve all original journals",
            )
        }
        fn material_denied() -> ApiError {
            ApiError::new(
                "DISCLOSURE_DENIED",
                "Current exact private-material permission, original destination or validity is unavailable",
            )
        }
        // Literal pre-change same-intake composition, retained only as the
        // comparator. All three original live expressions still run normally.
        fn baseline_material(
            engine: &Engine,
            access: &Access,
            intake: &Intake,
            consent: &dyn LocalDurableMaterialConsentV1,
        ) -> crate::Result<()> {
            let check = || -> std::result::Result<(), MaterialCheckErrorV2> {
                intake.outbox.validate().map_err(|_| material_damaged())?;
                let scope = &intake.outbox.request().scope;
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|v| v.as_secs())
                    .map_err(|_| material_denied())?;
                scope.check_valid_at(now)?;
                if intake.principal_id != access.principal_id
                    || hex::encode(engine.store.verify_original_encrypted_destination(
                        Path::new(&scope.protected_destination),
                    )?) != intake.metadata_origin
                {
                    return Err(material_denied().into());
                }
                Ok(())
            };
            let run = || -> std::result::Result<(), MaterialCheckErrorV2> {
                check()?;
                if !consent.permits(
                    &intake.outbox.request().scope,
                    intake.outbox.material_digest(),
                    DurableMaterialActionV1::ReadForExactConstruction,
                ) {
                    return Err(material_denied().into());
                }
                check()
            };
            run().map_err(MaterialCheckErrorV2::into_api)
        }
        struct Consent<'a> {
            calls: Cell<usize>,
            allow: bool,
            replace_path: Option<&'a Path>,
        }
        impl LocalDurableMaterialConsentV1 for Consent<'_> {
            fn permits(
                &self,
                _: &DurableConstructionScopeV1,
                _: &str,
                _: DurableMaterialActionV1,
            ) -> bool {
                self.calls.set(self.calls.get() + 1);
                if let Some(path) = self.replace_path {
                    checked(std::fs::rename(path, path.with_extension("held")));
                }
                self.allow
            }
        }
        fn current_material(
            engine: &Engine,
            access: &Access,
            intake: &Intake,
            consent: &dyn LocalDurableMaterialConsentV1,
        ) -> crate::Result<()> {
            engine
                .check_durable_material_typed_v2(
                    access,
                    intake,
                    consent,
                    DurableMaterialActionV1::ReadForExactConstruction,
                )
                .map_err(MaterialCheckErrorV2::into_api)
        }
        #[test]
        fn same_intake_live_checks_keep_denial_post_origin_and_first_error() {
            let f = history_fixture();
            let access = Access {
                principal_id: f.intake.principal_id.clone(),
                ..Access::default()
            };
            let before = state(&f);
            let bytes = checked(std::fs::read(&f.path));
            // No callback on malformed data, expired scope, wrong principal or
            // wrong retained origin. In all cases the old first error is kept.
            let mut variants = vec![f.intake.clone()];
            let mut wrong = f.intake.clone();
            wrong.principal_id = "other".into();
            variants.push(wrong);
            let mut wrong = f.intake.clone();
            wrong.metadata_origin = hash(0xee);
            variants.push(wrong);
            let mut wrong = f.intake.clone();
            let mut value = checked(serde_json::to_value(&wrong.outbox));
            value["reference"] = json!(hash(0xef));
            wrong.outbox = checked(serde_json::from_value(value));
            variants.push(wrong);
            let mut expired = f.intake.clone();
            let request = expired.outbox.request();
            let index = f.envelopes[1].view.candidates[0]
                .proposal
                .manifest
                .participants
                .iter()
                .position(|p| p.account_id == request.scope.account_id)
                .unwrap();
            expired.outbox = outbox(
                &request.scope.proposal,
                request.material.clone(),
                index,
                &f.path,
                1,
                2,
            );
            variants.push(expired);
            for (index, intake) in variants.iter().enumerate() {
                let old_gate = Consent {
                    calls: Cell::new(0),
                    allow: true,
                    replace_path: None,
                };
                let new_gate = Consent {
                    calls: Cell::new(0),
                    allow: true,
                    replace_path: None,
                };
                let old = baseline_material(&f.engine, &access, intake, &old_gate);
                let new = current_material(&f.engine, &access, intake, &new_gate);
                assert_eq!(
                    (old_gate.calls.get(), new_gate.calls.get()),
                    if index == 0 { (1, 1) } else { (0, 0) }
                );
                assert_eq!(old.is_ok(), index == 0);
                same_result(old, new);
            }
            for allow in [false, true] {
                let mut results = Vec::new();
                for baseline in [true, false] {
                    let gate = Consent {
                        calls: Cell::new(0),
                        allow,
                        replace_path: Some(&f.path),
                    };
                    let result = if baseline {
                        baseline_material(&f.engine, &access, &f.intake, &gate)
                    } else {
                        current_material(&f.engine, &access, &f.intake, &gate)
                    };
                    checked(std::fs::rename(f.path.with_extension("held"), &f.path));
                    assert_eq!(gate.calls.get(), 1);
                    assert!(result.is_err());
                    if !allow {
                        assert!(result.as_ref().err().unwrap().code == "DISCLOSURE_DENIED");
                    }
                    // True consent followed by the real moved original file must
                    // fail the post-origin check, not silently reuse permission.
                    if allow {
                        assert!(result.as_ref().err().unwrap().code != "DISCLOSURE_DENIED");
                    }
                    results.push(result);
                }
                let new = results.pop().unwrap();
                let old = results.pop().unwrap();
                same_result(old, new);
            }
            for sample in 0..3 {
                let old_gate = Consent {
                    calls: Cell::new(0),
                    allow: true,
                    replace_path: None,
                };
                let new_gate = Consent {
                    calls: Cell::new(0),
                    allow: true,
                    replace_path: None,
                };
                let started = Instant::now();
                let old = baseline_material(&f.engine, &access, &f.intake, &old_gate);
                let old_us = started.elapsed().as_micros();
                let started = Instant::now();
                let new = current_material(&f.engine, &access, &f.intake, &new_gate);
                let new_us = started.elapsed().as_micros();
                assert!(old.is_ok() && new.is_ok());
                same_result(old, new);
                assert_eq!((old_gate.calls.get(), new_gate.calls.get()), (1, 1));
                eprintln!(
                    "IMMUTABLE_COMPONENT engine_intake sample={sample} baseline_us={old_us} reused_us={new_us} source_baseline_material_calls=2 source_reused_material_calls=1 source_live_checks=2 observed_consent_calls=1 equal=true"
                );
            }
            assert!(before == state(&f));
            assert!(bytes == checked(std::fs::read(&f.path)));
        }
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
