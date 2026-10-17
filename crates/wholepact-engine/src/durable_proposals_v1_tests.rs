//! Integrated actual-cryptography test of the post-proof durable lifecycle.
//! Native disclosure, attended approval and current chain authority are explicit
//! test-only issuers here. This is NOT pre-proof/native or live settlement qualification.
use super::*;
use crate::signature_intake::LocalSignedRetention;

fn owner_return(
    owner: usize,
    checkpoint: &wholepact_proof_jobs::VerifiedCheckpoint,
    secrets: &FixtureSecrets,
    at: u64,
    ledger: &mut transport::SqliteReplayLedger,
) -> (transport::ReceivedArtifact, AuthenticatedAccountAssociation) {
    let mut signer =
        pczt::roles::signer::Signer::new(pczt::Pczt::parse(checkpoint.pczt_bytes()).unwrap())
            .unwrap();
    let inputs: Vec<_> = checkpoint
        .policy()
        .inputs
        .iter()
        .filter(|i| i.participant_index == owner)
        .collect();
    for input in &inputs {
        signer
            .sign_ironwood(
                UnwrapErr(SysRng),
                input.action_index,
                &SpendAuthorizingKey::from(secrets.owners.owner_spending_key(owner)),
            )
            .unwrap();
    }
    let signed = signer.finish();
    let participant = &checkpoint.policy().participants[owner];
    let payload = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1, "candidate_id": checkpoint.scope().candidate_id,
        "manifest_digest": checkpoint.scope().manifest_digest,
        "proved_artifact_digest": checkpoint.summary().result_digest,
        "review_binding": checkpoint.scope().review_binding, "account_id": participant.account_id,
        "signatures": inputs.iter().map(|input| serde_json::json!({"action_index":input.action_index,
            "signature_hex": hex::encode(signed.ironwood().actions()[input.action_index].spend().spend_auth_sig().unwrap())})).collect::<Vec<_>>()
    })).unwrap();
    let context = transport::MessageContext {
        network_profile_id: PROFILE_ID.into(),
        agreement_id: AGREEMENT.into(),
        proposal_id: checkpoint.scope().candidate_id.clone(),
        proposal_revision: 1,
        sender_id: format!("durable-synthetic-signer-{owner}"),
        recipient_id: PRINCIPAL.into(),
        artifact_kind: transport::ArtifactKind::Authorization,
    };
    let sender = &secrets.senders[owner];
    let recipient = &secrets.recipient;
    let now = timestamp(at);
    let prepared = transport::prepare_export(
        transport::ExportRequest {
            context: context.clone(),
            order: transport::MessageOrder {
                message_id: transport::random_message_id().unwrap(),
                sequence: 1,
                issued_at: now.clone(),
                expires_at: timestamp(at + 60),
            },
            purpose: PURPOSE.into(),
            persistence_warning: RETENTION.into(),
        },
        vec![transport::DisclosureField::new("external_spend_signatures_v1", payload).unwrap()],
        &sender.public_key().unwrap(),
        &recipient.public_key().unwrap(),
        &now,
    )
    .unwrap();
    let digest = prepared.preview().digest().unwrap();
    let sealed = prepared.seal(sender, &digest, &now).unwrap();
    let artifact = transport::open_envelope(
        &sealed,
        recipient,
        &sender.public_key().unwrap(),
        &context,
        &now,
        ledger,
    )
    .unwrap();
    // Deliberately test-only source, unavailable in product library builds.
    let association = AuthenticatedAccountAssociation {
        origin: AccountAssociationOrigin::RemoteKeys,
        sender_fingerprint: sender.public_key().unwrap().fingerprint(),
        recipient_fingerprint: recipient.public_key().unwrap().fingerprint(),
        sender_id: context.sender_id,
        recipient_id: context.recipient_id,
        account_id: participant.account_id.clone(),
        fvk_digest: hex::encode(Sha256::digest(participant.fvk.to_bytes())),
        manifest_digest: checkpoint.scope().manifest_digest.clone(),
        candidate_id: checkpoint.scope().candidate_id.clone(),
    };
    (artifact, association)
}

#[test]
fn durable_proposals_two_owners_restart_and_exact_submission_unknown_recovery() {
    let Fixture {
        secrets,
        request,
        context,
        packages,
    } = fixture();
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let metadata_path = directory.path().join("metadata.db");
    let proof_path = directory.path().join("proof.db");
    let signed_path = directory.path().join("signed.db");
    let transaction_path = directory.path().join("transaction.db");
    let submission_path = directory.path().join("submission.db");
    let access = Access {
        principal_id: PRINCIPAL.into(),
        include_owned_agreements: true,
        ..Access::default()
    };
    let engine =
        Engine::from_store(Store::create_encrypted(&metadata_path, secrets.key(81)).unwrap());
    engine
        .create(
            &access,
            "durable-create-agreement",
            request.manifest.agreement.clone(),
        )
        .unwrap();
    for (index, participant) in request.manifest.participants.iter().enumerate() {
        engine
            .add_intent(
                &access,
                &format!("durable-add-intent-{index}"),
                AGREEMENT,
                index as u64 + 1,
                ParticipationIntent {
                    intent_id: format!("durable-intent-{index}"),
                    agreement_id: AGREEMENT.into(),
                    participant_id: participant.participant_id.clone(),
                    desired_contribution: participant.contribution,
                    maximum_net_debit: participant.maximum_net_debit,
                    fee_cap: participant.fee_cap,
                    conditions: vec![],
                    valid_until: None,
                    status: IntentStatus::Active,
                },
            )
            .unwrap();
    }
    engine
        .select_roster(
            &access,
            "durable-select-roster",
            AGREEMENT,
            3,
            RosterSelectionRequest {
                selected_intent_ids: vec!["durable-intent-0".into(), "durable-intent-1".into()],
            },
        )
        .unwrap();
    let created = engine
        .create_candidate(
            &access,
            "durable-create-candidate",
            AGREEMENT,
            4,
            request.clone(),
        )
        .unwrap();
    let candidate = created.agreement.candidates[0].clone();
    let candidate_id = candidate.candidate_id.clone();
    let privacy = FixturePrivacy {
        candidate_id: candidate_id.clone(),
        manifest_digest: candidate.manifest_digest.clone(),
        account_ids: request
            .manifest
            .participants
            .iter()
            .map(|p| p.account_id.clone())
            .collect(),
        allowed: AtomicBool::new(true),
    };
    let declarations: Vec<_> = privacy
        .account_ids
        .iter()
        .map(|account_id| DisclosureAcknowledgement {
            account_id: account_id.clone(),
            manifest_digest: hex::decode(&candidate.manifest_digest)
                .unwrap()
                .try_into()
                .unwrap(),
            operator: OPERATOR.into(),
            reviewer_account_ids: privacy.account_ids.clone(),
            purpose: PURPOSE.into(),
            retention_policy: RETENTION.into(),
            scope: DisclosureScope::DedicatedAccountFvkAndSelectedNotesAndOutputs,
        })
        .collect();
    let jobs = ProofJobStore::from_encrypted_connection(
        create_encrypted(&proof_path, secrets.key(82)).unwrap(),
    )
    .unwrap();
    // This test starts at the existing trusted embedded construction boundary.
    // The new genuine durable-contribution/native path has separate qualification.
    let checkpointed = engine
        .checkpoint_candidate_locally(
            &access,
            "durable-construct-checkpoint",
            &candidate_id,
            5,
            LocalCheckpoint {
                construction: LocalConstruction {
                    context,
                    contributions: packages,
                    declarations: &declarations,
                },
                jobs: &jobs,
                limits: ProvingLimits { maximum_actions: 8 },
                consent: &privacy,
            },
        )
        .unwrap();
    let job_id = checkpointed.agreement.candidates[0].proof_jobs[0]
        .job_id
        .clone();
    let proved = engine
        .run_candidate_proof_locally(
            &access,
            "durable-prove-once",
            &candidate_id,
            checkpointed.agreement.revision,
            LocalProofJob {
                job_id: &job_id,
                jobs: &jobs,
                consent: &privacy,
            },
        )
        .unwrap();
    let frozen = engine
        .freeze_durable_proposal_v1(
            &access,
            "durable-freeze-proof",
            &candidate_id,
            proved.agreement.revision,
            LocalProofJob {
                job_id: &job_id,
                jobs: &jobs,
                consent: &privacy,
            },
        )
        .unwrap();
    let fixed = engine
        .load_durable_proposal_for_local_review_v1(
            &access,
            &candidate_id,
            LocalProofJob {
                job_id: &job_id,
                jobs: &jobs,
                consent: &privacy,
            },
        )
        .unwrap();
    let fixed_identity = fixed.identity().clone();
    drop(fixed);
    let signed = SignedResultJournal::from_encrypted_connection(
        create_encrypted(&signed_path, secrets.key(83)).unwrap(),
    )
    .unwrap();
    let mut ledger = transport::SqliteReplayLedger::from_encrypted_connection(
        create_encrypted(directory.path().join("inbox.db"), secrets.key(90)).unwrap(),
    )
    .unwrap();
    let checkpoint = engine
        .load_candidate_proof_for_local_review(
            &access,
            &candidate_id,
            LocalProofJob {
                job_id: &job_id,
                jobs: &jobs,
                consent: &privacy,
            },
        )
        .unwrap();
    let (artifact, mut association) = owner_return(0, &checkpoint, &secrets, NOW, &mut ledger);
    let original_account = association.account_id.clone();
    association.account_id = checkpoint.policy().participants[1].account_id.clone();
    assert!(
        engine
            .intake_durable_signature_v1(
                &access,
                "durable-wrong-owner-intake",
                &candidate_id,
                frozen.agreement.revision,
                LocalProofJob {
                    job_id: &job_id,
                    jobs: &jobs,
                    consent: &privacy
                },
                LocalSignedRetention {
                    journal: &signed,
                    consent: &privacy
                },
                AuthenticatedSignatureDelivery {
                    artifact: &artifact,
                    association: Some(&association)
                },
                &timestamp(NOW)
            )
            .is_err()
    );
    association.account_id = original_account;
    // Simulate the cross-journal crash boundary: signed retention completed, but
    // no engine intake receipt was committed. A low-level row is NOT admission.
    let (context, signatures) = crate::signature_intake::retention_inputs(
        &checkpoint,
        AGREEMENT,
        &candidate_id,
        1,
        &[AuthenticatedSignatureDelivery {
            artifact: &artifact,
            association: Some(&association),
        }],
        &timestamp(NOW),
        false,
    )
    .unwrap();
    let original = signed
        .retain(
            context,
            "durable-owner-0-intake",
            checkpoint.pczt_bytes(),
            checkpoint.policy(),
            &signatures,
            ProvingLimits { maximum_actions: 8 },
            &privacy,
        )
        .unwrap();
    let not_admitted = engine
        .durable_proposal_status_v1(
            &access,
            &candidate_id,
            LocalProofJob {
                job_id: &job_id,
                jobs: &jobs,
                consent: &privacy,
            },
            LocalSignedRetention {
                journal: &signed,
                consent: &privacy,
            },
        )
        .unwrap();
    assert_eq!(not_admitted.retained_owner_count, 0);
    assert_eq!(not_admitted.verified_real_inputs, 0);
    let first = engine
        .reconcile_durable_signature_v1(
            &access,
            "durable-owner-0-intake",
            &candidate_id,
            frozen.agreement.revision,
            LocalProofJob {
                job_id: &job_id,
                jobs: &jobs,
                consent: &privacy,
            },
            LocalSignedRetention {
                journal: &signed,
                consent: &privacy,
            },
            AuthenticatedSignatureDelivery {
                artifact: &artifact,
                association: Some(&association),
            },
            &timestamp(NOW + 120),
        )
        .unwrap();
    let original_after = signed
        .reconcile_existing(
            crate::signature_intake::retention_inputs(
                &checkpoint,
                AGREEMENT,
                &candidate_id,
                1,
                &[AuthenticatedSignatureDelivery {
                    artifact: &artifact,
                    association: Some(&association),
                }],
                &timestamp(NOW + 120),
                true,
            )
            .unwrap()
            .0,
            "durable-owner-0-intake",
            checkpoint.pczt_bytes(),
            checkpoint.policy(),
            &signatures,
            ProvingLimits { maximum_actions: 8 },
            &privacy,
        )
        .unwrap();
    assert_eq!(original_after.result_id, original.result_id);
    assert_eq!(
        original_after.signed_candidate_digest,
        original.signed_candidate_digest
    );
    drop(signatures);
    let partial = engine
        .durable_proposal_status_v1(
            &access,
            &candidate_id,
            LocalProofJob {
                job_id: &job_id,
                jobs: &jobs,
                consent: &privacy,
            },
            LocalSignedRetention {
                journal: &signed,
                consent: &privacy,
            },
        )
        .unwrap();
    assert_eq!(partial.retained_owner_count, 1);
    assert!(!partial.signatures_complete);
    assert!(
        engine
            .assemble_durable_proposal_v1(
                &access,
                "durable-early-union",
                &candidate_id,
                first.agreement.revision,
                LocalProofJob {
                    job_id: &job_id,
                    jobs: &jobs,
                    consent: &privacy
                },
                LocalSignedRetention {
                    journal: &signed,
                    consent: &privacy
                }
            )
            .is_err()
    );
    // All owner-A artifacts and associations are destroyed; nothing transient
    // from the first owner's IPC/UI lifetime is retained for later combination.
    drop(association);
    drop(artifact);
    drop(checkpoint);
    drop(signed);
    drop(jobs);
    drop(engine);
    let engine =
        Engine::from_store(Store::open_encrypted(&metadata_path, secrets.key(81)).unwrap());
    let jobs = ProofJobStore::from_encrypted_connection(
        open_encrypted(&proof_path, secrets.key(82)).unwrap(),
    )
    .unwrap();
    let signed = SignedResultJournal::from_encrypted_connection(
        open_encrypted(&signed_path, secrets.key(83)).unwrap(),
    )
    .unwrap();
    let local = || LocalProofJob {
        job_id: &job_id,
        jobs: &jobs,
        consent: &privacy,
    };
    let retention = || LocalSignedRetention {
        journal: &signed,
        consent: &privacy,
    };
    assert_eq!(
        engine
            .load_durable_proposal_for_local_review_v1(&access, &candidate_id, local())
            .unwrap()
            .identity(),
        &fixed_identity
    );
    privacy.allowed.store(false, Ordering::SeqCst);
    assert!(
        engine
            .durable_proposal_status_v1(&access, &candidate_id, local(), retention())
            .is_err()
    );
    privacy.allowed.store(true, Ordering::SeqCst);
    // Two hours later the first transport admission is expired. No expired
    // admission is reused: only its completed immutable intake evidence remains.
    let later = NOW + 7200;
    let checkpoint = engine
        .load_candidate_proof_for_local_review(&access, &candidate_id, local())
        .unwrap();
    let (artifact, association) = owner_return(1, &checkpoint, &secrets, later, &mut ledger);
    let before_second = engine.get(&access, AGREEMENT).unwrap().revision;
    assert!(
        engine
            .reconcile_durable_signature_v1(
                &access,
                "durable-missing-original",
                &candidate_id,
                before_second,
                local(),
                retention(),
                AuthenticatedSignatureDelivery {
                    artifact: &artifact,
                    association: Some(&association)
                },
                &timestamp(later)
            )
            .is_err()
    );
    let second = engine
        .intake_durable_signature_v1(
            &access,
            "durable-owner-1-intake",
            &candidate_id,
            before_second,
            local(),
            retention(),
            AuthenticatedSignatureDelivery {
                artifact: &artifact,
                association: Some(&association),
            },
            &timestamp(later),
        )
        .unwrap();
    let duplicate = engine
        .intake_durable_signature_v1(
            &access,
            "durable-owner-1-intake",
            &candidate_id,
            before_second,
            local(),
            retention(),
            AuthenticatedSignatureDelivery {
                artifact: &artifact,
                association: Some(&association),
            },
            &timestamp(later),
        )
        .unwrap();
    assert!(duplicate.replayed);
    drop(association);
    drop(artifact);
    drop(checkpoint);
    let complete = engine
        .durable_proposal_status_v1(&access, &candidate_id, local(), retention())
        .unwrap();
    assert!(complete.signatures_complete);
    assert_eq!(complete.retained_owner_count, 2);
    assert!(
        !complete.authorization_allowed
            && !complete.distribution_allowed
            && !complete.chain_validated
    );
    let assembled = engine
        .assemble_durable_proposal_v1(
            &access,
            "durable-exact-owner-union",
            &candidate_id,
            second.agreement.revision,
            local(),
            retention(),
        )
        .unwrap();
    assert_eq!(assembled.agreement.progress, "ready_for_submission");
    let transactions = TransactionCheckpointJournal::from_encrypted_connection(
        create_encrypted(&transaction_path, secrets.key(84)).unwrap(),
    )
    .unwrap();
    let transaction = || LocalTransactionCheckpoint {
        journal: &transactions,
        consent: &privacy,
    };
    let extracted = engine
        .checkpoint_durable_transaction_v1(
            &access,
            &candidate_id,
            local(),
            retention(),
            transaction(),
        )
        .unwrap();
    let repeated = engine
        .checkpoint_durable_transaction_v1(
            &access,
            &candidate_id,
            local(),
            retention(),
            transaction(),
        )
        .unwrap();
    assert!(repeated.exact_replay);
    assert_eq!(extracted.transaction_digest, repeated.transaction_digest);
    // Fresh synthetic chain context is separate from the two-hour human wait.
    // This fixture does not claim real expiry survival or live input spendability.
    let chain_context = chain::synthetic_wallet_chain_context_for_qualification(later).unwrap();
    let backend_identity = chain_context.source().clone();
    let expected = chain::SubmissionDescriptor {
        operation_id: SUBMISSION_OPERATION.into(),
        obligation_id: OBLIGATION.into(),
        proposal_id: candidate_id.clone(),
        transaction_id: extracted.txid.clone(),
        bytes_sha256: extracted.transaction_digest.clone(),
        expiry_height: request.manifest.expiry_height,
        network: "testnet".into(),
        consensus_branch_id: chain::NU7_BRANCH_ID,
    };
    let mut authority = FixtureAuthority {
        expected: expected.clone(),
        allowed: Arc::new(AtomicBool::new(true)),
    };
    let mut submissions = chain::EncryptedSubmissionJournal::from_encrypted_connection(
        create_encrypted(&submission_path, secrets.key(85)).unwrap(),
    )
    .unwrap();
    let retained = engine
        .retain_durable_submission_v1(
            &access,
            &candidate_id,
            SUBMISSION_OPERATION,
            local(),
            retention(),
            LocalSubmissionHandoff {
                transactions: transaction(),
                submission_journal: &mut submissions,
                authority: &mut authority,
                backend: &backend_identity,
                chain_context: &chain_context,
                clock: &FixtureClock(later),
                policy: chain::SubmissionPolicy::default(),
                consent: &privacy,
            },
        )
        .unwrap();
    assert_eq!(retained, expected);
    let mut backend = OfflineBackend {
        context: chain_context.clone(),
        calls: vec![],
        pending: false,
        outcomes: vec![
            Err(chain::ChainError::Timeout),
            Ok(chain::BackendSubmissionResult::Acknowledged),
        ]
        .into(),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let uncertain = runtime.block_on(engine.dispatch_durable_submission_v1(&access, &candidate_id, SUBMISSION_OPERATION, local(), retention(),
        wholepact_protocol::authorization::retention::transaction::submission_handoff::LocalSubmissionDispatch {
            transactions: transaction(), submission_journal: &mut submissions, authority: &mut authority, backend: &mut backend,
            clock: &FixtureClock(later), policy: chain::SubmissionPolicy::default(), consent: &privacy })).unwrap();
    assert_eq!(
        uncertain.historical_provider_state,
        chain::SubmissionState::SubmissionUnknown
    );
    assert!(!uncertain.clears_authorization_exposure && !uncertain.permits_replacement);
    drop(submissions);
    let mut submissions = chain::EncryptedSubmissionJournal::from_encrypted_connection(
        open_encrypted(&submission_path, secrets.key(85)).unwrap(),
    )
    .unwrap();
    let acknowledged = runtime.block_on(engine.dispatch_durable_submission_v1(&access, &candidate_id, SUBMISSION_OPERATION, local(), retention(),
        wholepact_protocol::authorization::retention::transaction::submission_handoff::LocalSubmissionDispatch {
            transactions: transaction(), submission_journal: &mut submissions, authority: &mut authority, backend: &mut backend,
            clock: &FixtureClock(later + 1), policy: chain::SubmissionPolicy::default(), consent: &privacy })).unwrap();
    assert_eq!(
        acknowledged.historical_provider_state,
        chain::SubmissionState::BackendAcknowledged
    );
    assert_eq!(backend.calls.len(), 2);
    assert_eq!(backend.calls[0], backend.calls[1]);
    assert!(!acknowledged.clears_authorization_exposure && !acknowledged.permits_replacement);
    assert_eq!(
        engine
            .load_durable_proposal_for_local_review_v1(&access, &candidate_id, local())
            .unwrap()
            .identity(),
        &fixed_identity
    );
    assert_eq!(
        jobs.status(PRINCIPAL, &job_id, &privacy).unwrap().attempt,
        1
    );
    let canceled = engine
        .cancel(
            &access,
            "durable-cancel-coordination",
            AGREEMENT,
            engine.get(&access, AGREEMENT).unwrap().revision,
        )
        .unwrap();
    assert!(canceled.agreement.cancellation_requested);
    let replay = engine
        .assemble_durable_proposal_v1(
            &access,
            "durable-exact-owner-union",
            &candidate_id,
            second.agreement.revision,
            local(),
            retention(),
        )
        .unwrap();
    assert!(replay.replayed && replay.agreement.cancellation_requested);
    assert_eq!(replay.agreement.progress, "cancellation_requested");
    assert!(runtime.block_on(engine.dispatch_durable_submission_v1(&access, &candidate_id, SUBMISSION_OPERATION, local(), retention(),
        wholepact_protocol::authorization::retention::transaction::submission_handoff::LocalSubmissionDispatch {
            transactions: transaction(), submission_journal: &mut submissions, authority: &mut authority, backend: &mut backend,
            clock: &FixtureClock(later + 2), policy: chain::SubmissionPolicy::default(), consent: &privacy })).is_err());
    assert_eq!(backend.calls.len(), 2);
    let canceled_status = engine
        .durable_proposal_status_v1(&access, &candidate_id, local(), retention())
        .unwrap();
    assert!(canceled_status.cancellation_requested && canceled_status.signatures_complete);
}
