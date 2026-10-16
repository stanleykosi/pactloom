//! Never-funded synthetic fixtures only. No real wallet, remote source, spending
//! authorization, network submission or settlement is involved in these tests.
use super::*;
use std::{
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};
use wholepact_protocol::synthetic::review_fixture;
use wholepact_storage_security::{DatabaseKey, create_encrypted, open_encrypted};

const PRINCIPAL: &str = "synthetic-local-controller";
const KEY: [u8; 32] = [0x56; 32];
struct TestConsent(AtomicBool);
impl LocalProofConsent for TestConsent {
    fn permits(&self, scope: &CheckpointScope, _: LocalAction) -> bool {
        self.0.load(Ordering::SeqCst)
            && scope.principal_id == PRINCIPAL
            && scope.local_operator == "synthetic-local-prover"
    }
}
struct RevokeDuringAction {
    action: LocalAction,
    calls: std::sync::atomic::AtomicUsize,
}
impl LocalProofConsent for RevokeDuringAction {
    fn permits(&self, _: &CheckpointScope, action: LocalAction) -> bool {
        action != self.action || self.calls.fetch_add(1, Ordering::SeqCst) == 0
    }
}
fn revoking(action: LocalAction) -> RevokeDuringAction {
    RevokeDuringAction {
        action,
        calls: std::sync::atomic::AtomicUsize::new(0),
    }
}
fn permit() -> TestConsent {
    TestConsent(AtomicBool::new(true))
}
fn scope(bytes: &[u8], policy: &ReviewPolicy) -> CheckpointScope {
    CheckpointScope {
        principal_id: PRINCIPAL.into(),
        candidate_id: "synthetic-checkpoint-candidate".into(),
        manifest_digest: hex::encode(policy.manifest_digest),
        artifact_digest: digest(bytes),
        effects_commitment: verify_review(bytes, policy)
            .unwrap()
            .shielded_sighash()
            .into(),
        coordination_request_digest: "12".repeat(32),
        review_binding: verify_review(bytes, policy)
            .unwrap()
            .review_binding()
            .into(),
        account_ids: policy
            .participants
            .iter()
            .map(|p| p.account_id.clone())
            .collect(),
        local_operator: "synthetic-local-prover".into(),
        purpose: "Never-funded local proof checkpoint qualification".into(),
        retention_policy: "Private temporary encrypted fixture; remove at test end".into(),
    }
}
fn private_dir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}
fn create(path: &Path) -> ProofJobStore {
    ProofJobStore::from_encrypted_connection(
        create_encrypted(path, &DatabaseKey::from_bytes(KEY)).unwrap(),
    )
    .unwrap()
}
fn reopen(path: &Path) -> ProofJobStore {
    ProofJobStore::from_encrypted_connection(
        open_encrypted(path, &DatabaseKey::from_bytes(KEY)).unwrap(),
    )
    .unwrap()
}
fn budget() -> ProvingLimits {
    ProvingLimits { maximum_actions: 8 }
}

#[test]
fn checkpoint_is_encrypted_scoped_exact_and_gated_across_restart() {
    let dir = private_dir();
    let path = dir.path().join("private-jobs.db");
    let f = review_fixture().unwrap();
    let s = scope(&f.pczt_bytes, &f.policy);
    let consent = permit();
    let jobs = create(&path);
    consent.0.store(false, Ordering::SeqCst);
    assert_eq!(
        jobs.enqueue(
            &s,
            "synthetic-checkpoint-key",
            &f.pczt_bytes,
            &f.policy,
            budget(),
            &consent
        ),
        Err(JobError::ConsentDenied)
    );
    consent.0.store(true, Ordering::SeqCst);
    let queued = jobs
        .enqueue(
            &s,
            "synthetic-checkpoint-key",
            &f.pczt_bytes,
            &f.policy,
            budget(),
            &consent,
        )
        .unwrap();
    assert_eq!(queued.state, JobState::Queued);
    assert_eq!(
        queued.job_id,
        job_id_for_key(PRINCIPAL, "synthetic-checkpoint-key").unwrap()
    );
    assert_eq!(
        queued.scope_digest,
        digest(&serde_json::to_vec(&s).unwrap())
    );
    assert_eq!(
        jobs.status_for_key(
            PRINCIPAL,
            "synthetic-checkpoint-key",
            &s.coordination_request_digest,
            &consent
        )
        .unwrap(),
        Some(queued.clone())
    );
    assert_eq!(
        jobs.status_for_key(
            PRINCIPAL,
            "synthetic-checkpoint-key",
            &"13".repeat(32),
            &consent
        ),
        Err(JobError::IdempotencyConflict)
    );
    assert_eq!(
        jobs.status_for_key(
            PRINCIPAL,
            "missing-checkpoint-key",
            &s.coordination_request_digest,
            &consent
        ),
        Ok(None)
    );
    assert!(!queued.proof_verified);
    assert!(
        !queued.authorization_allowed && !queued.distribution_allowed && !queued.chain_validated
    );
    assert_eq!(
        jobs.status("different-principal", &queued.job_id, &consent),
        Err(JobError::NotFound)
    );
    let mut changed = s.clone();
    changed.retention_policy = "Changed scope is not exact replay".into();
    assert_eq!(
        jobs.enqueue(
            &changed,
            "synthetic-checkpoint-key",
            &f.pczt_bytes,
            &f.policy,
            budget(),
            &consent
        ),
        Err(JobError::IdempotencyConflict)
    );
    assert_eq!(
        jobs.load_verified(PRINCIPAL, &queued.job_id, &consent)
            .err(),
        Some(JobError::StateConflict)
    );
    // Check actual disk and live WAL, not only an encrypted metadata label.
    let encoded = policy::encode(&f.policy).unwrap();
    for suffix in ["", "-wal", "-shm"] {
        let file = std::path::PathBuf::from(format!("{}{suffix}", path.display()));
        if let Ok(bytes) = std::fs::read(file) {
            assert!(!bytes.windows(16).any(|w| w == b"SQLite format 3\0"));
            assert!(!bytes.windows(64).any(|w| w == &f.pczt_bytes[..64]));
            assert!(!bytes.windows(64).any(|w| w == &encoded[..64]));
            assert!(
                !bytes
                    .windows(PRINCIPAL.len())
                    .any(|w| w == PRINCIPAL.as_bytes())
            );
            assert!(
                !bytes
                    .windows(96)
                    .any(|w| w == f.policy.participants[0].fvk.to_bytes())
            );
        }
    }
    let debug = format!("{queued:?}");
    let json = serde_json::to_string(&queued).unwrap();
    assert!(!debug.contains(&hex::encode(f.policy.participants[0].fvk.to_bytes())));
    assert!(!json.contains("fvk") && !json.contains("witness") && !json.contains("memo"));
    drop(jobs);
    assert!(open_encrypted(&path, &DatabaseKey::from_bytes([0x57; 32])).is_err());
    let jobs = reopen(&path);
    assert_eq!(
        jobs.enqueue(
            &s,
            "synthetic-checkpoint-key",
            &f.pczt_bytes,
            &f.policy,
            budget(),
            &consent
        )
        .unwrap(),
        queued
    );
    consent.0.store(false, Ordering::SeqCst);
    assert_eq!(
        jobs.enqueue(
            &s,
            "synthetic-checkpoint-key",
            &f.pczt_bytes,
            &f.policy,
            budget(),
            &consent
        ),
        Err(JobError::ConsentDenied)
    );
    assert_eq!(
        jobs.run(PRINCIPAL, &queued.job_id, &consent),
        Err(JobError::ConsentDenied)
    );
    assert_eq!(
        jobs.status(PRINCIPAL, &queued.job_id, &consent),
        Err(JobError::ConsentDenied)
    );
    consent.0.store(true, Ordering::SeqCst);
    jobs.connection
        .lock()
        .unwrap()
        .execute("UPDATE proof_jobs SET scope=zeroblob(8193)", [])
        .unwrap();
    assert_eq!(
        jobs.status_for_key(
            PRINCIPAL,
            "synthetic-checkpoint-key",
            &s.coordination_request_digest,
            &consent
        ),
        Err(JobError::Storage)
    );
}

#[test]
fn invalid_binding_resource_limit_and_failed_intent_never_start_proof() {
    let dir = private_dir();
    let path = dir.path().join("private-jobs.db");
    let f = review_fixture().unwrap();
    let s = scope(&f.pczt_bytes, &f.policy);
    let consent = permit();
    let jobs = create(&path);
    let mut wrong = s.clone();
    wrong.review_binding = "00".repeat(32);
    assert_eq!(
        jobs.enqueue(
            &wrong,
            "synthetic-wrong-binding",
            &f.pczt_bytes,
            &f.policy,
            budget(),
            &consent
        ),
        Err(JobError::VerificationFailed)
    );
    assert_eq!(
        jobs.enqueue(
            &s,
            "synthetic-wrong-budget",
            &f.pczt_bytes,
            &f.policy,
            ProvingLimits { maximum_actions: 9 },
            &consent
        ),
        Err(JobError::InvalidRequest)
    );
    // A coordinator may not turn this proof repository into a store of usable
    // participant authorizations. Structurally nonempty real-input signatures
    // and preexisting proofs are rejected even before cryptographic use.
    for preexisting_proof in [false, true] {
        let raw = pczt::v2::Pczt::try_from(pczt::Pczt::parse(&f.pczt_bytes).unwrap()).unwrap();
        let mut wire = serde_json::to_value(raw).unwrap();
        if preexisting_proof {
            wire["ironwood"]["zkproof"] = serde_json::json!([1, 2, 3]);
        } else {
            wire["ironwood"]["actions"][f.policy.inputs[0].action_index]["spend"]["spend_auth_sig"] =
                serde_json::json!(vec![1u8; 64]);
        }
        let mutated: pczt::v2::Pczt = serde_json::from_value(wire).unwrap();
        let bytes = mutated.serialize();
        wholepact_protocol::inspect_candidate(&bytes).unwrap();
        let mut altered_scope = s.clone();
        altered_scope.artifact_digest = digest(&bytes);
        assert_eq!(
            jobs.enqueue(
                &altered_scope,
                "synthetic-forbidden-role",
                &bytes,
                &f.policy,
                budget(),
                &consent
            ),
            Err(JobError::InvalidRequest)
        );
    }
    // Actual SQLite page-limit exhaustion (SQLITE_FULL), not a fabricated error.
    let full_path = dir.path().join("full-private-jobs.db");
    let full_jobs = create(&full_path);
    {
        let connection = full_jobs.connection.lock().unwrap();
        let pages: i64 = connection
            .query_row("PRAGMA page_count", [], |r| r.get(0))
            .unwrap();
        connection
            .pragma_update(None, "max_page_count", pages)
            .unwrap();
    }
    assert_eq!(
        full_jobs.enqueue(
            &s,
            "synthetic-disk-full-key",
            &f.pczt_bytes,
            &f.policy,
            budget(),
            &consent
        ),
        Err(JobError::Storage)
    );
    let count: i64 = full_jobs
        .connection
        .lock()
        .unwrap()
        .query_row("SELECT count(*) FROM proof_jobs", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
    drop(full_jobs);
    let recovered_full = reopen(&full_path);
    let count: i64 = recovered_full
        .connection
        .lock()
        .unwrap()
        .query_row("SELECT count(*) FROM proof_events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
    assert_eq!(
        jobs.enqueue(
            &s,
            "synthetic-revoked-during",
            &f.pczt_bytes,
            &f.policy,
            budget(),
            &revoking(LocalAction::RetainPrivateWitnesses)
        ),
        Err(JobError::ConsentDenied)
    );
    assert_eq!(
        jobs.status_for_key(
            PRINCIPAL,
            "synthetic-revoked-during",
            &s.coordination_request_digest,
            &consent
        )
        .unwrap(),
        None
    );
    let queued = jobs
        .enqueue(
            &s,
            "synthetic-checkpoint-key",
            &f.pczt_bytes,
            &f.policy,
            budget(),
            &consent,
        )
        .unwrap();
    jobs.connection.lock().unwrap().execute_batch("CREATE TRIGGER fail_running BEFORE INSERT ON proof_events WHEN NEW.state='running' BEGIN SELECT RAISE(ABORT,'injected write failure'); END;").unwrap();
    assert_eq!(
        jobs.run(PRINCIPAL, &queued.job_id, &consent),
        Err(JobError::Storage)
    );
    assert_eq!(
        jobs.status(PRINCIPAL, &queued.job_id, &consent).unwrap(),
        queued
    );
    drop(jobs);
    assert_eq!(
        reopen(&path)
            .status(PRINCIPAL, &queued.job_id, &consent)
            .unwrap(),
        queued
    );
}

#[test]
fn interrupted_worker_helper() {
    let Ok(path) = std::env::var("WHOLEPACT_SYNTHETIC_PROOF_JOB_DB") else {
        return;
    };
    let job = std::env::var("WHOLEPACT_SYNTHETIC_PROOF_JOB_ID").unwrap();
    let jobs = reopen(Path::new(&path));
    jobs.run(PRINCIPAL, &job, &permit()).unwrap();
}

#[test]
#[ignore = "Expensive real Halo2 proof, crash recovery and post-proof disk failure qualification"]
fn real_proof_crash_recovery_failed_commit_and_exact_encrypted_restart() {
    use std::{
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    let dir = private_dir();
    let path = dir.path().join("private-jobs.db");
    let f = generic_constructed_fixture();
    let s = scope(&f.pczt_bytes, &f.review_policy);
    let consent = permit();
    let jobs = create(&path);
    let queued = jobs
        .enqueue(
            &s,
            "synthetic-real-proof-key",
            &f.pczt_bytes,
            &f.review_policy,
            budget(),
            &consent,
        )
        .unwrap();
    drop(jobs);
    // Kill an actual process after its durable running transition, while its
    // prover is doing work. No fake succeeded row or substitute proof is used.
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "tests::interrupted_worker_helper", "--nocapture"])
        .env("WHOLEPACT_SYNTHETIC_PROOF_JOB_DB", &path)
        .env("WHOLEPACT_SYNTHETIC_PROOF_JOB_ID", &queued.job_id)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let jobs = reopen(&path);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let status = jobs.status(PRINCIPAL, &queued.job_id, &consent).unwrap();
        if status.state == JobState::Running {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Child did not commit its running intent"
        );
        assert!(
            child.try_wait().unwrap().is_none(),
            "Child exited before observed running state"
        );
        thread::sleep(Duration::from_millis(25));
    }
    child.kill().unwrap();
    child.wait().unwrap();
    drop(jobs);
    let jobs = reopen(&path);
    assert_eq!(
        jobs.run(PRINCIPAL, &queued.job_id, &consent),
        Err(JobError::RecoveryRequired)
    );
    let uncertain = jobs
        .recover_interrupted(PRINCIPAL, &queued.job_id, 1, &consent)
        .unwrap();
    assert_eq!(uncertain.state, JobState::Uncertain);
    assert_eq!(
        jobs.recover_interrupted(PRINCIPAL, &queued.job_id, 1, &consent),
        Err(JobError::StateConflict)
    );
    jobs.connection.lock().unwrap().execute_batch("CREATE TRIGGER fail_completion BEFORE INSERT ON proof_events WHEN NEW.state='succeeded' BEGIN SELECT RAISE(ABORT,'injected disk write failure'); END;").unwrap();
    assert_eq!(
        jobs.run(PRINCIPAL, &queued.job_id, &consent),
        Err(JobError::Storage)
    );
    assert_eq!(
        jobs.load_verified(PRINCIPAL, &queued.job_id, &consent)
            .err(),
        Some(JobError::StateConflict)
    );
    drop(jobs);
    let jobs = reopen(&path);
    let running = jobs.status(PRINCIPAL, &queued.job_id, &consent).unwrap();
    assert_eq!(running.state, JobState::Running);
    assert_eq!(running.attempt, 2);
    assert!(running.result_digest.is_none());
    jobs.connection
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_completion")
        .unwrap();
    jobs.recover_interrupted(PRINCIPAL, &queued.job_id, 2, &consent)
        .unwrap();
    let success = jobs.run(PRINCIPAL, &queued.job_id, &consent).unwrap();
    assert_eq!(success.state, JobState::Succeeded);
    assert_eq!(success.attempt, 3);
    assert!(success.proof_verified);
    assert!(
        !success.authorization_allowed && !success.distribution_allowed && !success.chain_validated
    );
    let bytes = jobs
        .load_verified(PRINCIPAL, &queued.job_id, &consent)
        .unwrap()
        .pczt_bytes()
        .to_vec();
    assert_ne!(digest(&bytes), queued.input_digest);
    drop(jobs);
    let jobs = reopen(&path);
    let recovered = jobs
        .load_verified(PRINCIPAL, &queued.job_id, &consent)
        .unwrap();
    assert_eq!(recovered.pczt_bytes(), bytes);
    assert_eq!(recovered.summary(), &success);
    assert_eq!(
        jobs.run(PRINCIPAL, &queued.job_id, &consent).unwrap(),
        success
    );
    assert_eq!(
        jobs.enqueue(
            &s,
            "synthetic-real-proof-key",
            &f.pczt_bytes,
            &f.review_policy,
            budget(),
            &consent
        )
        .unwrap(),
        success
    );
    assert_eq!(
        jobs.load_verified(
            PRINCIPAL,
            &queued.job_id,
            &revoking(LocalAction::ReadPrivateArtifact)
        )
        .err(),
        Some(JobError::ConsentDenied)
    );
    assert_eq!(
        jobs.run(
            PRINCIPAL,
            &queued.job_id,
            &revoking(LocalAction::ProveLocally)
        ),
        Err(JobError::ConsentDenied)
    );
    let conn = jobs.connection.lock().unwrap();
    let events: i64 = conn
        .query_row(
            "SELECT count(*) FROM proof_events WHERE state='succeeded'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(events, 1);
    let mut corrupt = bytes;
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    conn.execute(
        "UPDATE proof_jobs SET result=?1,result_digest=?2",
        params![corrupt, digest(&corrupt)],
    )
    .unwrap();
    drop(conn);
    assert_eq!(
        jobs.load_verified(PRINCIPAL, &queued.job_id, &consent)
            .err(),
        Some(JobError::VerificationFailed)
    );
}

fn generic_constructed_fixture() -> wholepact_protocol::construction::ConstructedProposal {
    use wholepact_core::*;
    use wholepact_protocol::{construction::*, review::encode_testnet_receiver};
    let (wallets, selection) = wholepact_wallet::wallet::synthetic_scanned_contributions().unwrap();
    let amount = |n| Amount::from_zatoshis(n).unwrap();
    let receiver = encode_testnet_receiver(&wallets[0].notes()[0].note.recipient());
    let agreement = AgreementDraft {
        schema_version: 1,
        agreement_id: "synthetic-proof-agreement".into(),
        obligation_id: "synthetic-proof-obligation".into(),
        revision: 1,
        purpose: "Never-funded scanner, constructor and encrypted prover qualification".into(),
        organizer_identity: "fixture-organizer".into(),
        network_profile_id: PROFILE_ID.into(),
        recipients: vec![Recipient {
            recipient_id: "recipient".into(),
            address: receiver.clone(),
            amount: amount(300_000),
            memo: None,
            instruction_provenance: "Synthetic receiver".into(),
        }],
        funding_policy: FundingPolicy::Exact {
            target: amount(300_000),
        },
        fee_policy: FeePolicy::ProRata,
        privacy_profile: PrivacyProfile {
            mode: PrivacyMode::DeclaredOperator,
            proving_operator: Some("synthetic-local-prover".into()),
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
            account_id: w.account_id().into(),
            contribution: amount(if i == 0 { 100_000 } else { 200_000 }),
            fee_share: amount(if i == 0 { 5000 } else { 10000 }),
            fee_cap: amount(if i == 0 { 5000 } else { 10000 }),
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
            recipient_id: "recipient".into(),
        },
    }];
    for (i, w) in wallets.iter().enumerate() {
        for n in w.notes() {
            inputs.push(ClaimedInput {
                input_id: n.input_id.clone(),
                participant_id: participants[i].participant_id.clone(),
                account_id: w.account_id().into(),
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
                account_id: w.account_id().into(),
                ownership_evidence_ref: None,
            },
        });
    }
    let proposal = Proposal::validate(ProposalInput {
        proposal_id: "synthetic-checkpoint-candidate".into(),
        previous_proposal_id: None,
        manifest: ProposalManifest {
            agreement,
            participants,
            inputs,
            outputs,
            transaction_fee: amount(15000),
            expiry_height: selection.tip_height + 30,
        },
        artifact_digest: None,
        effects_commitment: None,
        created_at: "2026-10-13T15:00:00Z".into(),
    })
    .unwrap();
    let roster: Vec<_> = wallets.iter().map(|w| w.account_id().to_owned()).collect();
    let declarations: Vec<_> = roster
        .iter()
        .map(|id| DisclosureAcknowledgement {
            account_id: id.clone(),
            manifest_digest: hex::decode(proposal.manifest_digest())
                .unwrap()
                .try_into()
                .unwrap(),
            operator: "synthetic-local-prover".into(),
            reviewer_account_ids: roster.clone(),
            purpose: "Synthetic local qualification".into(),
            retention_policy: "Encrypted temporary checkpoint during test".into(),
            scope: DisclosureScope::DedicatedAccountFvkAndSelectedNotesAndOutputs,
        })
        .collect();
    construct_proposal(
        &proposal,
        ConstructionContext {
            anchor: selection.anchor_root,
            anchor_height: selection.anchor_height,
            anchor_block_hash: selection.anchor_hash_protocol,
            target_height: selection.tip_height + 1,
        },
        wallets.into_iter().map(|w| w.into_contribution()).collect(),
        &declarations,
    )
    .unwrap()
}

// Dedicated exact-observation adapter tests. Never run a proof worker here.
fn busy_timeout_ms(jobs: &ProofJobStore) -> u32 {
    jobs.connection
        .lock()
        .unwrap()
        .pragma_query_value(None, "busy_timeout", |r| r.get(0))
        .unwrap()
}

#[test]
fn fail_fast_enqueue_preserves_exact_idempotency_consent_and_validation() {
    let dir = private_dir();
    let jobs = create(&dir.path().join("synthetic-fail-fast.sqlite"));
    let f = review_fixture().unwrap();
    let s = scope(&f.pczt_bytes, &f.policy);
    let consent = permit();
    jobs.connection
        .lock()
        .unwrap()
        .busy_timeout(Duration::from_millis(71))
        .unwrap();
    let queued = jobs
        .enqueue_fail_fast(
            &s,
            "synthetic-fail-fast-key",
            &f.pczt_bytes,
            &f.policy,
            budget(),
            &consent,
        )
        .unwrap();
    assert_eq!(queued.state, JobState::Queued);
    assert!(
        !queued.proof_verified && !queued.authorization_allowed && !queued.distribution_allowed
    );
    assert_eq!(busy_timeout_ms(&jobs), 71);
    assert_eq!(
        jobs.enqueue(
            &s,
            "synthetic-fail-fast-key",
            &f.pczt_bytes,
            &f.policy,
            budget(),
            &consent
        )
        .unwrap(),
        queued
    );
    assert_eq!(
        jobs.enqueue_fail_fast(
            &s,
            "synthetic-fail-fast-key",
            &f.pczt_bytes,
            &f.policy,
            budget(),
            &consent
        )
        .unwrap(),
        queued
    );
    let mut changed = s.clone();
    changed.retention_policy.push_str(" changed");
    assert_eq!(
        jobs.enqueue_fail_fast(
            &changed,
            "synthetic-fail-fast-key",
            &f.pczt_bytes,
            &f.policy,
            budget(),
            &consent
        ),
        Err(JobError::IdempotencyConflict)
    );
    assert_eq!(
        jobs.enqueue_fail_fast(&s, "short", &f.pczt_bytes, &f.policy, budget(), &consent),
        Err(JobError::InvalidRequest)
    );
    consent.0.store(false, Ordering::SeqCst);
    assert_eq!(
        jobs.enqueue_fail_fast(
            &s,
            "synthetic-fail-fast-key",
            &f.pczt_bytes,
            &f.policy,
            budget(),
            &consent
        ),
        Err(JobError::ConsentDenied)
    );
    assert_eq!(busy_timeout_ms(&jobs), 71);
}

#[test]
fn fail_fast_enqueue_mutex_contention_and_poison_never_queue() {
    let dir = private_dir();
    let jobs = create(&dir.path().join("synthetic-mutex.sqlite"));
    let f = review_fixture().unwrap();
    let s = scope(&f.pczt_bytes, &f.policy);
    let consent = permit();
    {
        let _held = jobs.connection.lock().unwrap();
        assert_eq!(
            jobs.enqueue_fail_fast(
                &s,
                "synthetic-mutex-key",
                &f.pczt_bytes,
                &f.policy,
                budget(),
                &consent
            ),
            Err(JobError::ResourceExhausted)
        );
    }
    assert!(
        jobs.status_for_key(
            PRINCIPAL,
            "synthetic-mutex-key",
            &s.coordination_request_digest,
            &consent
        )
        .unwrap()
        .is_none()
    );
    let caught = catch_unwind(AssertUnwindSafe(|| {
        let mut c = jobs.connection.lock().unwrap();
        c.busy_timeout(Duration::from_millis(83)).unwrap();
        let _: Result<()> = with_zero_busy_timeout(&mut c, |c| {
            let actual: u32 = c
                .pragma_query_value(None, "busy_timeout", |r| r.get(0))
                .unwrap();
            assert_eq!(actual, 0);
            panic!("synthetic unwind")
        });
    }));
    assert!(caught.is_err());
    let held = match jobs.connection.lock() {
        Err(error) => error.into_inner(),
        Ok(_) => panic!("proof mutex must stay poisoned"),
    };
    let actual: u32 = held
        .pragma_query_value(None, "busy_timeout", |r| r.get(0))
        .unwrap();
    assert_eq!(actual, 83);
    drop(held);
    assert_eq!(
        jobs.enqueue_fail_fast(
            &s,
            "synthetic-mutex-key",
            &f.pczt_bytes,
            &f.policy,
            budget(),
            &consent
        ),
        Err(JobError::Storage)
    );
}

#[test]
fn fail_fast_enqueue_sqlite_contention_and_denial_restore_timeout() {
    let dir = private_dir();
    let path = dir.path().join("synthetic-sqlite-busy.sqlite");
    let jobs = create(&path);
    let other = open_encrypted(&path, &DatabaseKey::from_bytes(KEY)).unwrap();
    let f = review_fixture().unwrap();
    let s = scope(&f.pczt_bytes, &f.policy);
    let consent = permit();
    other.connection().execute_batch("BEGIN IMMEDIATE").unwrap();
    let started = std::time::Instant::now();
    assert_eq!(
        jobs.enqueue_fail_fast(
            &s,
            "synthetic-busy-key",
            &f.pczt_bytes,
            &f.policy,
            budget(),
            &consent
        ),
        Err(JobError::Storage)
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "no configured 5-second busy wait"
    );
    assert_eq!(busy_timeout_ms(&jobs), 5000);
    other.connection().execute_batch("ROLLBACK").unwrap();
    let revoked = revoking(LocalAction::RetainPrivateWitnesses);
    assert_eq!(
        jobs.enqueue_fail_fast(
            &s,
            "synthetic-busy-key",
            &f.pczt_bytes,
            &f.policy,
            budget(),
            &revoked
        ),
        Err(JobError::ConsentDenied)
    );
    assert_eq!(busy_timeout_ms(&jobs), 5000);
    assert!(
        jobs.status_for_key(
            PRINCIPAL,
            "synthetic-busy-key",
            &s.coordination_request_digest,
            &consent
        )
        .unwrap()
        .is_none()
    );
    // Ambiguous custom callback policy is refused before changing it.
    jobs.connection
        .lock()
        .unwrap()
        .busy_handler(Some(|_| false))
        .unwrap();
    assert_eq!(
        jobs.enqueue_fail_fast(
            &s,
            "synthetic-busy-key",
            &f.pczt_bytes,
            &f.policy,
            budget(),
            &consent
        ),
        Err(JobError::Storage)
    );
    assert_eq!(busy_timeout_ms(&jobs), 0);
}

#[test]
fn fail_fast_enqueue_last_consent_denial_rolls_back_before_restoring_policy() {
    struct DenyThird(std::sync::atomic::AtomicUsize);
    impl LocalProofConsent for DenyThird {
        fn permits(&self, _: &CheckpointScope, _: LocalAction) -> bool {
            self.0.fetch_add(1, Ordering::SeqCst) != 2
        }
    }
    let dir = private_dir();
    let jobs = create(&dir.path().join("synthetic-last-consent.sqlite"));
    let f = review_fixture().unwrap();
    let s = scope(&f.pczt_bytes, &f.policy);
    let denial = DenyThird(std::sync::atomic::AtomicUsize::new(0));
    assert_eq!(
        jobs.enqueue_fail_fast(
            &s,
            "synthetic-last-consent-key",
            &f.pczt_bytes,
            &f.policy,
            budget(),
            &denial
        ),
        Err(JobError::ConsentDenied)
    );
    assert_eq!(denial.0.load(Ordering::SeqCst), 3);
    assert_eq!(busy_timeout_ms(&jobs), 5000);
    assert!(
        jobs.status_for_key(
            PRINCIPAL,
            "synthetic-last-consent-key",
            &s.coordination_request_digest,
            &permit()
        )
        .unwrap()
        .is_none()
    );
    let c = jobs.connection.lock().unwrap();
    let count: i64 = c
        .query_row("SELECT count(*) FROM proof_events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
}
