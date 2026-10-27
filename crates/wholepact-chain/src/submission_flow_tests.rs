use super::*;
use crate::{SubmissionJournal, TransactionObservation, TransactionStatus};
use std::{cell::Cell, collections::VecDeque, fs, os::unix::fs::PermissionsExt, rc::Rc};
use wholepact_storage_security::{DatabaseKey, create_encrypted, open_encrypted};
use zcash_primitives::transaction::{Authorized, TransactionData};
const NOW: u64 = 1_800_000_020;
fn bytes(expiry: u32) -> Vec<u8> {
    // Empty never-funded fixture: parseable wire data, not a valid payment.
    let tx = TransactionData::<Authorized>::from_parts_v6(
        BranchId::Nu7,
        0,
        expiry.into(),
        None,
        None,
        None,
        None,
    )
    .freeze()
    .unwrap();
    let mut bytes = vec![];
    tx.write(&mut bytes).unwrap();
    bytes
}
fn plan() -> SubmissionPlan {
    SubmissionPlan::new(
        "synthetic-obligation-1",
        "synthetic-proposal-1",
        "synthetic-operation-1",
        &bytes(4_498_200),
    )
    .unwrap()
}
fn setup() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    DatabaseKey,
    EncryptedSubmissionJournal,
) {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join("submission.sqlite");
    let key = DatabaseKey::from_bytes([57; 32]);
    let journal = EncryptedSubmissionJournal::from_encrypted_connection(
        create_encrypted(&path, &key).unwrap(),
    )
    .unwrap();
    (dir, path, key, journal)
}
fn context() -> ChainContext {
    let (id, p, i, t, b) = crate::tests::fixture();
    crate::validate_context(&id, &p, &i, &t, &b, &t, NOW - 10, NOW).unwrap()
}
struct Clock(u64);
impl SubmissionClock for Clock {
    fn now_unix_seconds(&self) -> Result<u64, ChainError> {
        Ok(self.0)
    }
}
#[derive(Default)]
struct Authority {
    checks: Rc<Cell<usize>>,
    deny_check: usize,
}
struct Permit {
    checks: Rc<Cell<usize>>,
    deny_check: usize,
}
impl SubmissionAuthority for Authority {
    type Permit = Permit;
    fn authorize(&mut self, review: &SubmissionReview<'_>) -> Result<Permit, ChainError> {
        assert_eq!(review.descriptor.network, "testnet");
        assert_eq!(review.descriptor.consensus_branch_id, crate::NU7_BRANCH_ID);
        Ok(Permit {
            checks: self.checks.clone(),
            deny_check: self.deny_check,
        })
    }
}
impl SubmissionPermit for Permit {
    fn check_current(&mut self, _: &SubmissionReview<'_>) -> Result<(), ChainError> {
        let count = self.checks.get() + 1;
        self.checks.set(count);
        if count == self.deny_check {
            Err(ChainError::SubmissionNotAuthorized)
        } else {
            Ok(())
        }
    }
}
struct Backend {
    context: ChainContext,
    results: VecDeque<Result<BackendSubmissionResult, ChainError>>,
    calls: Vec<Vec<u8>>,
    pending: bool,
}
impl Backend {
    fn new(results: Vec<Result<BackendSubmissionResult, ChainError>>) -> Self {
        Self {
            context: context(),
            results: results.into(),
            calls: vec![],
            pending: false,
        }
    }
}
impl SubmissionBackend for Backend {
    fn identity(&self) -> &BackendIdentity {
        self.context.source()
    }
    fn fresh_context(&mut self) -> SubmissionFuture<'_, Result<ChainContext, ChainError>> {
        Box::pin(async { Ok(self.context.clone()) })
    }
    fn submit_exact<'a>(
        &'a mut self,
        dispatch: PreparedDispatch<'a>,
    ) -> SubmissionFuture<'a, Result<BackendSubmissionResult, ChainError>> {
        Box::pin(async move {
            self.calls.push(dispatch.exact_bytes().to_vec());
            if self.pending {
                std::future::pending().await
            } else {
                self.results.pop_front().unwrap()
            }
        })
    }
}
#[tokio::test]
async fn exact_restart_retry_retains_ambiguous_and_sticky_provider_history() {
    let (_dir, path, key, mut journal) = setup();
    let plan = plan();
    let mut authority = Authority::default();
    let mut backend = Backend::new(vec![
        Err(ChainError::Timeout),
        Ok(BackendSubmissionResult::Acknowledged),
        Err(ChainError::TransportUnavailable),
    ]);
    let first = submit_plan(
        &mut journal,
        &plan,
        &mut backend,
        &mut authority,
        &Clock(NOW),
        SubmissionPolicy::default(),
    )
    .await
    .unwrap();
    assert!(matches!(
        first.attempt.outcome,
        SubmissionAttemptOutcome::Indeterminate {
            reason: SubmissionFailure::Timeout
        }
    ));
    assert_eq!(
        first.historical_provider_state,
        SubmissionState::SubmissionUnknown
    );
    drop(journal);
    let mut journal =
        EncryptedSubmissionJournal::from_encrypted_connection(open_encrypted(&path, &key).unwrap())
            .unwrap();
    let accepted = retry_retained_submission(
        &mut journal,
        &plan.descriptor.operation_id,
        &mut backend,
        &mut authority,
        &Clock(NOW + 1),
        SubmissionPolicy::default(),
    )
    .await
    .unwrap();
    assert_eq!(accepted.attempt.number, 2);
    let lost = retry_retained_submission(
        &mut journal,
        &plan.descriptor.operation_id,
        &mut backend,
        &mut authority,
        &Clock(NOW + 2),
        SubmissionPolicy::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        lost.historical_provider_state,
        SubmissionState::BackendAcknowledged
    );
    assert_eq!(backend.calls, vec![plan.intent.exact_bytes().to_vec(); 3]);
    assert_eq!(
        journal
            .submission_attempts(&plan.descriptor.operation_id)
            .unwrap()
            .len(),
        3
    );
    assert!(!lost.clears_authorization_exposure && !lost.permits_replacement);
    let new = SubmissionPlan::new(
        "synthetic-obligation-1",
        "synthetic-proposal-2",
        "synthetic-operation-2",
        &bytes(4_498_201),
    )
    .unwrap();
    assert!(matches!(
        submit_plan(
            &mut journal,
            &new,
            &mut backend,
            &mut authority,
            &Clock(NOW + 3),
            SubmissionPolicy::default()
        )
        .await,
        Err(ChainError::ObligationConflict)
    ));
    let changed = SubmissionPlan::new(
        "synthetic-obligation-1",
        "synthetic-proposal-1",
        "synthetic-operation-1",
        &bytes(4_498_201),
    )
    .unwrap();
    assert!(matches!(
        submit_plan(
            &mut journal,
            &changed,
            &mut backend,
            &mut authority,
            &Clock(NOW + 3),
            SubmissionPolicy::default()
        )
        .await,
        Err(ChainError::IdempotencyConflict)
    ));
    assert_eq!(backend.calls.len(), 3);
}
#[tokio::test]
async fn authority_revocation_stale_context_and_failed_intent_never_dispatch() {
    let (_dir, _path, _key, mut journal) = setup();
    let plan = plan();
    let mut backend = Backend::new(vec![]);
    assert!(matches!(
        submit_plan(
            &mut journal,
            &plan,
            &mut backend,
            &mut DenySubmissionAuthority,
            &Clock(NOW),
            SubmissionPolicy::default()
        )
        .await,
        Err(ChainError::SubmissionNotAuthorized)
    ));
    assert!(
        journal
            .recover_intent_summary(&plan.descriptor.operation_id)
            .unwrap()
            .is_none()
    );
    let mut authority = Authority {
        deny_check: 2,
        ..Default::default()
    };
    assert!(matches!(
        submit_plan(
            &mut journal,
            &plan,
            &mut backend,
            &mut authority,
            &Clock(NOW),
            SubmissionPolicy::default()
        )
        .await,
        Err(ChainError::SubmissionNotAuthorized)
    ));
    assert_eq!(
        journal
            .submission_attempts(&plan.descriptor.operation_id)
            .unwrap()[0]
            .outcome,
        SubmissionAttemptOutcome::BlockedBeforeDispatch
    );
    assert!(matches!(
        submit_plan(
            &mut journal,
            &plan,
            &mut backend,
            &mut Authority::default(),
            &Clock(NOW + 51),
            SubmissionPolicy::default()
        )
        .await,
        Err(ChainError::StaleChain)
    ));
    journal
        .connection
        .pragma_update(None, "query_only", true)
        .unwrap();
    assert!(matches!(
        submit_plan(
            &mut journal,
            &plan,
            &mut backend,
            &mut Authority::default(),
            &Clock(NOW),
            SubmissionPolicy::default()
        )
        .await,
        Err(ChainError::JournalFailure)
    ));
    assert!(backend.calls.is_empty());
}
#[tokio::test]
async fn cancelled_dispatch_and_failed_result_commit_remain_unknown_on_restart() {
    let (_dir, path, key, mut journal) = setup();
    let plan = plan();
    let mut backend = Backend::new(vec![]);
    backend.pending = true;
    assert!(
        tokio::time::timeout(
            Duration::from_millis(5),
            submit_plan(
                &mut journal,
                &plan,
                &mut backend,
                &mut Authority::default(),
                &Clock(NOW),
                SubmissionPolicy::default()
            )
        )
        .await
        .is_err()
    );
    assert_eq!(backend.calls.len(), 1);
    drop(journal);
    let mut journal =
        EncryptedSubmissionJournal::from_encrypted_connection(open_encrypted(&path, &key).unwrap())
            .unwrap();
    assert_eq!(
        journal
            .submission_attempts(&plan.descriptor.operation_id)
            .unwrap()[0]
            .outcome,
        SubmissionAttemptOutcome::Unknown
    );
    // Fault injection at outcome persistence, after fake provider acceptance.
    journal.connection.execute_batch("CREATE TEMP TRIGGER fail_result BEFORE UPDATE ON submission_attempts BEGIN SELECT RAISE(ABORT,'synthetic fault'); END;").unwrap();
    backend.pending = false;
    backend
        .results
        .push_back(Ok(BackendSubmissionResult::Acknowledged));
    assert!(matches!(
        retry_retained_submission(
            &mut journal,
            &plan.descriptor.operation_id,
            &mut backend,
            &mut Authority::default(),
            &Clock(NOW),
            SubmissionPolicy::default()
        )
        .await,
        Err(ChainError::SubmissionOutcomeUnrecorded)
    ));
    assert_eq!(
        journal
            .submission_attempts(&plan.descriptor.operation_id)
            .unwrap()[1]
            .outcome,
        SubmissionAttemptOutcome::Unknown
    );
    drop(journal);
    let journal =
        EncryptedSubmissionJournal::from_encrypted_connection(open_encrypted(&path, &key).unwrap())
            .unwrap();
    assert_eq!(
        journal
            .recover_intent_summary(&plan.descriptor.operation_id)
            .unwrap()
            .unwrap()
            .historical_provider_state,
        SubmissionState::SubmissionUnknown
    );
}
#[test]
fn retained_handoff_binds_scope_and_restart_observations_are_stale() {
    let (_dir, path, key, mut journal) = setup();
    let plan = plan();
    let context = context();
    retain_submission_plan(
        &mut journal,
        &plan,
        &mut Authority::default(),
        context.source(),
        &context,
        &Clock(NOW),
        SubmissionPolicy::default(),
    )
    .unwrap();
    assert!(
        journal
            .submission_attempts(&plan.descriptor.operation_id)
            .unwrap()
            .is_empty()
    );
    let policy =
        crate::ConfirmationPolicy::new(10, 10, vec![context.source().source_id.clone()]).unwrap();
    let mut reconciler = crate::SettlementReconciler::new(
        &plan.descriptor.transaction_id,
        plan.descriptor.expiry_height,
        policy,
    )
    .unwrap();
    let o = TransactionObservation {
        transaction_id: plan.descriptor.transaction_id.clone(),
        context: context.clone(),
        status: TransactionStatus::Included {
            block: crate::BlockIdentity {
                height: context.tip().height - 9,
                hash: hex::encode([2; 32]),
            },
            confirmations: 10,
        },
        confirms_raw_transaction_id: true,
        independently_consensus_verified: false,
        clears_authorization_exposure: false,
    };
    let report = reconciler
        .reconcile(
            &[crate::SourceObservation {
                source_id: context.source().source_id.clone(),
                observation: Ok(o),
            }],
            NOW,
        )
        .unwrap();
    journal
        .record_reconciliation(&plan.descriptor.operation_id, &report)
        .unwrap();
    drop(journal);
    let journal =
        EncryptedSubmissionJournal::from_encrypted_connection(open_encrypted(&path, &key).unwrap())
            .unwrap();
    assert_eq!(
        journal
            .recover_reconciler(&plan.descriptor.operation_id)
            .unwrap()
            .unwrap()
            .last_report()
            .unwrap()
            .state,
        crate::SettlementObservationState::Stale
    );
    assert_eq!(
        journal
            .retained_submission_descriptor(&plan.descriptor.operation_id)
            .unwrap()
            .unwrap(),
        plan.descriptor
    );
}
#[test]
fn profile_expiry_and_attempt_resource_bounds_fail_closed() {
    let (_dir, _path, _key, mut journal) = setup();
    let plan = plan();
    assert!(
        SubmissionPlan::new(
            "synthetic-obligation-1",
            "synthetic-proposal-1",
            "synthetic-operation-1",
            &bytes(0)
        )
        .is_err()
    );
    let mut trailing = bytes(4_498_200);
    trailing.push(0);
    assert!(
        SubmissionPlan::new(
            "synthetic-obligation-1",
            "synthetic-proposal-1",
            "synthetic-operation-1",
            &trailing
        )
        .is_err()
    );
    let near = SubmissionPlan::new(
        "synthetic-obligation-2",
        "synthetic-proposal-2",
        "synthetic-operation-2",
        &bytes(4_498_146),
    )
    .unwrap();
    assert!(matches!(
        retain_submission_plan(
            &mut journal,
            &near,
            &mut Authority::default(),
            context().source(),
            &context(),
            &Clock(NOW),
            SubmissionPolicy::default()
        ),
        Err(ChainError::SubmissionExpiryMargin)
    ));
    journal.bind_submission_plan(&plan).unwrap();
    for _ in 0..128 {
        journal
            .begin_submission_attempt(&plan, "local-fixture", NOW, None)
            .unwrap();
    }
    assert!(matches!(
        journal.begin_submission_attempt(&plan, "local-fixture", NOW, None),
        Err(ChainError::ResourceLimit)
    ));
    assert_eq!(
        journal
            .submission_attempts(&plan.descriptor.operation_id)
            .unwrap()
            .len(),
        128
    );
}

/// Actual encrypted recovery/dispatch kernels with the existing parseable empty
/// wire fixture and a modeled, validated provider context. This is not a real
/// payment, native grant, consensus observation or exposure-resolution proof.
#[tokio::test]
async fn expired_retained_unknown_submission_refuses_retry_after_reopen() {
    let (_dir, path, key, mut journal) = setup();
    let plan = plan();
    let mut backend = Backend::new(vec![Err(ChainError::Timeout)]);
    let first = submit_plan(
        &mut journal,
        &plan,
        &mut backend,
        &mut Authority::default(),
        &Clock(NOW),
        SubmissionPolicy::default(),
    )
    .await
    .unwrap();
    assert_eq!(first.historical_provider_state, SubmissionState::SubmissionUnknown);
    assert!(!first.clears_authorization_exposure && !first.permits_replacement);
    assert_eq!(backend.calls.len(), 1);
    let original_attempts = journal
        .submission_attempts(&plan.descriptor.operation_id)
        .unwrap();
    assert_eq!(original_attempts.len(), 1);
    drop(journal);

    let mut journal =
        EncryptedSubmissionJournal::from_encrypted_connection(open_encrypted(&path, &key).unwrap())
            .unwrap();
    let changes_after_reopen = journal.connection.total_changes();
    // Cross the original minimum send margin, then the actual expiry height.
    // Fresh provider data and an otherwise permissive fresh test authority do
    // not renew the saved transaction or turn UNKNOWN into a safe replacement.
    for height in [plan.descriptor.expiry_height - 2, plan.descriptor.expiry_height] {
        let (identity, policy, mut info, mut tip, mut block) = crate::tests::fixture();
        info.block_height = u64::from(height);
        info.estimated_height = u64::from(height);
        tip.height = u64::from(height);
        block.height = u64::from(height);
        backend.context = crate::validate_context(
            &identity, &policy, &info, &tip, &block, &tip, NOW, NOW + 1,
        )
        .unwrap();
        let mut fresh_authority = Authority::default();
        assert!(matches!(
            retry_retained_submission(
                &mut journal,
                &plan.descriptor.operation_id,
                &mut backend,
                &mut fresh_authority,
                &Clock(NOW + 1),
                SubmissionPolicy::default(),
            )
            .await,
            Err(ChainError::SubmissionExpiryMargin)
        ));
        assert_eq!(fresh_authority.checks.get(), 0);
        assert_eq!(backend.calls.len(), 1);
        assert_eq!(journal.connection.total_changes(), changes_after_reopen);
        assert!(journal
            .retained_submission_descriptor(&plan.descriptor.operation_id)
            .unwrap()
            .as_ref() == Some(&plan.descriptor));
        let (retained, state) = journal
            .recover_exact_intent(&plan.descriptor.operation_id)
            .unwrap()
            .unwrap();
        assert!(retained.exact_bytes() == plan.intent.exact_bytes());
        assert_eq!(retained.bytes_sha256(), plan.descriptor.bytes_sha256);
        assert_eq!(state, SubmissionState::SubmissionUnknown);
        assert!(journal
            .submission_attempts(&plan.descriptor.operation_id)
            .unwrap() == original_attempts);
        let counts: (u64, u64) = journal.connection.query_row(
            "SELECT (SELECT count(*) FROM submission_intents),(SELECT count(*) FROM submission_bindings)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert_eq!(counts, (1, 1));
    }
}

#[test]
fn version_one_migration_preserves_unknown_exact_intent_without_inventing_authority() {
    let (_dir, path, key, mut journal) = setup();
    let plan = plan();
    journal.record_exact_intent(&plan.intent).unwrap();
    journal.connection.execute_batch("DROP TABLE settlement_deliveries; DROP TABLE settlement_evidence; DROP TABLE submission_attempts; DROP TABLE submission_bindings; DROP TABLE submission_observations; DROP TABLE submission_journal_identity; PRAGMA user_version=1;").unwrap();
    drop(journal);
    let journal =
        EncryptedSubmissionJournal::from_encrypted_connection(open_encrypted(&path, &key).unwrap())
            .unwrap();
    assert!(
        journal
            .retained_submission_descriptor(&plan.descriptor.operation_id)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        journal
            .recover_intent_summary(&plan.descriptor.operation_id)
            .unwrap()
            .unwrap()
            .historical_provider_state,
        SubmissionState::SubmissionUnknown
    );
}

#[tokio::test]
async fn concrete_wire_sender_is_one_shot_bounded_sanitized_and_never_implies_settlement() {
    use axum::{Router, body::Bytes, http::Uri, routing::post};
    use prost::Message;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    };
    #[derive(Clone, PartialEq, Message)]
    struct Reply {
        #[prost(int32, tag = "1")]
        code: i32,
        #[prost(string, tag = "2")]
        message: String,
    }
    let mode = Arc::new(AtomicU8::new(0));
    let observed = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let server_mode = mode.clone();
    let server_observed = observed.clone();
    let app = Router::new().fallback(post(move |uri: Uri, request: Bytes| {
        let mode = server_mode.clone();
        let observed = server_observed.clone();
        async move {
            let (_, _, mut info, tip, mut block) = crate::tests::fixture();
            block.time = crate::now().unwrap() as u32;
            info.estimated_height = info.block_height;
            let mut cache = "miss";
            let response = match uri.path().rsplit('/').next().unwrap() {
                "GetLightdInfo" => info.encode_to_vec(),
                "GetLatestBlock" => tip.encode_to_vec(),
                "GetBlock" => block.encode_to_vec(),
                "SendTransaction" => {
                    let sent = crate::rpc::RawTransaction::decode(&request[5..]).unwrap();
                    assert_eq!(sent.height, 0);
                    observed.lock().unwrap().push(sent.data);
                    let current = mode.load(Ordering::SeqCst);
                    if current == 2 {
                        tokio::time::sleep(Duration::from_millis(150)).await;
                    }
                    if current == 3 {
                        cache = "hit";
                    }
                    Reply {
                        code: if current == 1 { -26 } else { 0 },
                        message: if current == 4 {
                            "x".repeat(8192)
                        } else {
                            "private-server-canary-never-retain".into()
                        },
                    }
                    .encode_to_vec()
                }
                _ => panic!("unexpected RPC"),
            };
            let mut frame = vec![0];
            frame.extend_from_slice(&(response.len() as u32).to_be_bytes());
            frame.extend_from_slice(&response);
            (
                [
                    ("content-type", "application/grpc"),
                    ("grpc-status", "0"),
                    ("x-cache", cache),
                ],
                frame,
            )
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let policy = crate::NetworkPolicy {
        request_timeout: Duration::from_millis(80),
        retries: 2,
        retry_delay: Duration::from_millis(1),
        ..Default::default()
    };
    let adapter = ChainAdapter {
        identity: BackendIdentity {
            source_id: "local-fixture".into(),
            endpoint: endpoint.clone(),
            trust_profile: "synthetic_never_chain_evidence",
        },
        policy,
        rpc: crate::rpc::Rpc::for_test(&endpoint, policy),
    };
    let mut backend = LightwalletSubmissionBackend::new(adapter);
    assert_eq!(
        backend
            .adapter
            .rpc
            .submit_once(&bytes(4_498_200), 0)
            .await
            .unwrap_err(),
        ChainError::StaleChain
    );
    assert!(observed.lock().unwrap().is_empty());
    let (_dir, _path, _key, mut journal) = setup();
    let plan = plan();
    let mut authority = Authority::default();
    for current in 0..=4 {
        mode.store(current, Ordering::SeqCst);
        let report = submit_plan(
            &mut journal,
            &plan,
            &mut backend,
            &mut authority,
            &SystemSubmissionClock,
            SubmissionPolicy::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            observed.lock().unwrap().len(),
            usize::from(current) + 1,
            "transport must not auto-retry"
        );
        assert!(
            !serde_json::to_string(&report)
                .unwrap()
                .contains("private-server-canary")
        );
        match current {
            0 => assert_eq!(
                report.attempt.outcome,
                SubmissionAttemptOutcome::Acknowledged
            ),
            1 => assert_eq!(
                report.attempt.outcome,
                SubmissionAttemptOutcome::Rejected { code: -26 }
            ),
            _ => assert!(matches!(
                report.attempt.outcome,
                SubmissionAttemptOutcome::Indeterminate { .. }
            )),
        }
        assert_eq!(
            report.historical_provider_state,
            SubmissionState::BackendAcknowledged
        );
        assert!(!report.clears_authorization_exposure);
    }
    assert!(
        observed
            .lock()
            .unwrap()
            .iter()
            .all(|sent| sent == plan.intent.exact_bytes())
    );
    server.abort();
}

#[test]
fn retention_lease_rechecks_and_journal_destination_are_explicit() {
    let (_dir, _path, _key, mut journal) = setup();
    let plan = plan();
    let context = context();
    let identity = journal.identity().to_owned();
    assert_eq!(identity.len(), 64);
    let (_other, _other_path, _other_key, other) = setup();
    assert_ne!(identity, other.identity());
    let mut authority = Authority {
        deny_check: 2,
        ..Default::default()
    };
    assert!(matches!(
        retain_submission_plan(
            &mut journal,
            &plan,
            &mut authority,
            context.source(),
            &context,
            &Clock(NOW),
            SubmissionPolicy::default()
        ),
        Err(ChainError::SubmissionRetentionUncertain)
    ));
    assert!(
        journal
            .retained_submission_descriptor(&plan.descriptor.operation_id)
            .unwrap()
            .is_some()
    );
    assert!(
        journal
            .submission_attempts(&plan.descriptor.operation_id)
            .unwrap()
            .is_empty()
    );
    struct AdvancingClock(Cell<u64>);
    impl SubmissionClock for AdvancingClock {
        fn now_unix_seconds(&self) -> Result<u64, ChainError> {
            let now = self.0.get();
            self.0.set(now + 51);
            Ok(now)
        }
    }
    let (_third, _third_path, _third_key, mut third) = setup();
    assert!(matches!(
        retain_submission_plan(
            &mut third,
            &plan,
            &mut Authority::default(),
            context.source(),
            &context,
            &AdvancingClock(Cell::new(NOW)),
            SubmissionPolicy::default()
        ),
        Err(ChainError::StaleChain)
    ));
    assert!(
        third
            .recover_intent_summary(&plan.descriptor.operation_id)
            .unwrap()
            .is_none()
    );
}

/// Real encrypted submission journal plus the production orchestrator. The
/// adapter pauses at its readiness boundary and applies the SAME immutable
/// token ceiling required of the production RPC adapter before reading bytes.
/// This does not claim a real network connection or valid funded payment.
#[tokio::test]
async fn retained_submission_caps_send_after_delayed_readiness() {
    struct CappedAuthority {
        until: u64,
    }
    struct CappedPermit {
        until: u64,
    }
    impl SubmissionAuthority for CappedAuthority {
        type Permit = CappedPermit;
        fn authorize(&mut self, _: &SubmissionReview<'_>) -> Result<CappedPermit, ChainError> {
            Ok(CappedPermit { until: self.until })
        }
    }
    impl SubmissionPermit for CappedPermit {
        fn valid_until_unix_seconds(&self) -> Option<u64> {
            Some(self.until)
        }
        fn check_current(&mut self, review: &SubmissionReview<'_>) -> Result<(), ChainError> {
            if review.now_unix_seconds > self.until {
                Err(ChainError::SubmissionNotAuthorized)
            } else {
                Ok(())
            }
        }
    }
    struct DelayedReady {
        context: ChainContext,
        ready_at: u64,
        observed_ceiling: Option<u64>,
        sent: usize,
    }
    impl SubmissionBackend for DelayedReady {
        fn identity(&self) -> &BackendIdentity {
            self.context.source()
        }
        fn fresh_context(&mut self) -> SubmissionFuture<'_, Result<ChainContext, ChainError>> {
            Box::pin(async { Ok(self.context.clone()) })
        }
        fn submit_exact<'a>(
            &'a mut self,
            dispatch: PreparedDispatch<'a>,
        ) -> SubmissionFuture<'a, Result<BackendSubmissionResult, ChainError>> {
            Box::pin(async move {
                tokio::task::yield_now().await;
                self.observed_ceiling = Some(dispatch.valid_until_unix_seconds());
                if self.ready_at > dispatch.valid_until_unix_seconds() {
                    return Err(ChainError::StaleChain);
                }
                assert!(!dispatch.exact_bytes().is_empty());
                self.sent += 1;
                Ok(BackendSubmissionResult::Acknowledged)
            })
        }
    }
    let (_dir, _path, _key, mut journal) = setup();
    let plan = plan();
    let mut authority = CappedAuthority { until: NOW + 1 };
    let mut backend = DelayedReady {
        context: context(),
        ready_at: NOW + 2,
        observed_ceiling: None,
        sent: 0,
    };
    let report = submit_plan(
        &mut journal,
        &plan,
        &mut backend,
        &mut authority,
        &Clock(NOW),
        SubmissionPolicy::default(),
    )
    .await
    .unwrap();
    assert_eq!(backend.observed_ceiling, Some(NOW + 1));
    assert_eq!(backend.sent, 0);
    assert!(matches!(
        report.attempt.outcome,
        SubmissionAttemptOutcome::Indeterminate { .. }
    ));
    // Exact original bytes remain retained, and an expired authority cannot
    // enter the backend at all or reset/erase the first uncertain attempt.
    authority.until = NOW - 1;
    assert!(matches!(
        submit_plan(
            &mut journal,
            &plan,
            &mut backend,
            &mut authority,
            &Clock(NOW),
            SubmissionPolicy::default()
        )
        .await,
        Err(ChainError::SubmissionNotAuthorized)
    ));
    assert_eq!(backend.sent, 0);
}

/// Two real encrypted connections; the competing append happens after the
/// authority selects its exact attempt but before the maintained write boundary.
#[tokio::test]
async fn original_delegation_attempt_is_checked_inside_journal_transaction() {
    struct ExactAttempt {
        path: std::path::PathBuf,
        key: DatabaseKey,
        plan: SubmissionPlan,
    }
    struct ExactPermit;
    impl SubmissionAuthority for ExactAttempt {
        type Permit = ExactPermit;
        fn authorize(&mut self, _: &SubmissionReview<'_>) -> Result<ExactPermit, ChainError> {
            let mut competitor = EncryptedSubmissionJournal::from_encrypted_connection(
                open_encrypted(&self.path, &self.key).unwrap(),
            )
            .unwrap();
            competitor.begin_submission_attempt(&self.plan, "local-fixture", NOW, Some(1))?;
            Ok(ExactPermit)
        }
    }
    impl SubmissionPermit for ExactPermit {
        fn expected_attempt_number(&self) -> Option<u32> {
            Some(1)
        }
        fn check_current(&mut self, _: &SubmissionReview<'_>) -> Result<(), ChainError> {
            Ok(())
        }
    }
    let (_dir, path, key, mut journal) = setup();
    let plan = plan();
    journal.bind_submission_plan(&plan).unwrap();
    let mut authority = ExactAttempt {
        path,
        key,
        plan: self::plan(),
    };
    let mut backend = Backend::new(vec![Ok(BackendSubmissionResult::Acknowledged)]);
    assert!(matches!(
        submit_plan(
            &mut journal,
            &plan,
            &mut backend,
            &mut authority,
            &Clock(NOW),
            SubmissionPolicy::default()
        )
        .await,
        Err(ChainError::SubmissionNotAuthorized)
    ));
    assert!(backend.calls.is_empty());
    let attempts = journal
        .submission_attempts(&plan.descriptor.operation_id)
        .unwrap();
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].number, 1);
    assert!(matches!(
        attempts[0].outcome,
        SubmissionAttemptOutcome::Unknown
    ));
}

/// Actual encrypted attempt journal and production token propagation, with a
/// controlled readiness boundary. No sockets or claim of actual RPC coverage.
#[tokio::test]
async fn final_effect_restriction_survives_readiness_and_preserves_uncertainty() {
    use std::sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}};
    struct Restriction { revoked: Arc<AtomicBool>, samples: Arc<AtomicUsize> }
    impl SubmissionEffectRestriction for Restriction {
        fn check_before_effect(&self) -> Result<(), ChainError> {
            self.samples.fetch_add(1, Ordering::SeqCst);
            if self.revoked.load(Ordering::SeqCst) { Err(ChainError::SubmissionNotAuthorized) }
            else { Ok(()) }
        }
    }
    struct RestrictedAuthority { revoked: Arc<AtomicBool>, samples: Arc<AtomicUsize> }
    impl SubmissionAuthority for RestrictedAuthority {
        type Permit = Restriction;
        fn authorize(&mut self, _: &SubmissionReview<'_>) -> Result<Restriction, ChainError> {
            Ok(Restriction { revoked:self.revoked.clone(), samples:self.samples.clone() })
        }
    }
    impl SubmissionPermit for Restriction {
        fn effect_restriction(&self) -> Option<&dyn SubmissionEffectRestriction> { Some(self) }
        fn check_current(&mut self, _: &SubmissionReview<'_>) -> Result<(), ChainError> { Ok(()) }
    }
    struct ReadyBackend { context: ChainContext, revoked: Arc<AtomicBool>, sent: usize }
    impl SubmissionBackend for ReadyBackend {
        fn identity(&self) -> &BackendIdentity { self.context.source() }
        fn fresh_context(&mut self) -> SubmissionFuture<'_, Result<ChainContext,ChainError>> {
            Box::pin(async { Ok(self.context.clone()) })
        }
        fn submit_exact<'a>(&'a mut self, dispatch: PreparedDispatch<'a>) -> SubmissionFuture<'a,Result<BackendSubmissionResult,ChainError>> {
            Box::pin(async move {
                tokio::task::yield_now().await;
                self.revoked.store(true, Ordering::SeqCst);
                dispatch.check_effect_restriction()?;
                self.sent += 1;
                Ok(BackendSubmissionResult::Acknowledged)
            })
        }
    }
    let (_dir, _path, _key, mut journal) = setup();
    let plan = plan();
    let revoked = Arc::new(AtomicBool::new(false));
    let samples = Arc::new(AtomicUsize::new(0));
    let mut authority = RestrictedAuthority { revoked:revoked.clone(), samples:samples.clone() };
    let mut backend = ReadyBackend { context:context(), revoked, sent:0 };
    let report = submit_plan(&mut journal, &plan, &mut backend, &mut authority,
        &Clock(NOW), SubmissionPolicy::default()).await.unwrap();
    // Binding commit, attempt commit, then final-send readiness sample.
    assert_eq!(samples.load(Ordering::SeqCst), 3);
    assert_eq!(backend.sent, 0);
    assert!(matches!(report.attempt.outcome, SubmissionAttemptOutcome::Indeterminate { .. }));
    assert_eq!(report.attempt.number, 1);
}

#[test]
fn initial_submission_restrictions_rollback_but_outcome_settlement_survives_revocation() {
    struct Denied;
    impl SubmissionEffectRestriction for Denied {
        fn check_before_effect(&self) -> Result<(), ChainError> {
            Err(ChainError::SubmissionNotAuthorized)
        }
    }
    let (_dir, _path, _key, mut journal) = setup();
    let plan = plan();
    let operation = &plan.descriptor.operation_id;
    assert!(matches!(journal.bind_submission_plan_restricted(&plan, Some(&Denied)),
        Err(ChainError::SubmissionNotAuthorized)));
    assert!(journal.retained_submission_descriptor(operation).unwrap().is_none());
    assert!(journal.recover_intent_summary(operation).unwrap().is_none());
    // Independently authorized setup, followed by refusal of the first attempt.
    journal.bind_submission_plan(&plan).unwrap();
    let source = context().source().source_id.clone();
    assert!(matches!(journal.begin_submission_attempt_restricted(
        &plan, &source, NOW, Some(1), Some(&Denied)), Err(ChainError::SubmissionNotAuthorized)));
    assert!(journal.submission_attempts(operation).unwrap().is_empty());
    let mut attempt = journal.begin_submission_attempt(&plan, &source, NOW, Some(1)).unwrap();
    attempt.outcome = SubmissionAttemptOutcome::BlockedBeforeDispatch;
    // Outcome settlement is not a new attempt and cannot be suppressed by R.
    journal.finish_submission_attempt(operation, &attempt).unwrap();
    let saved = journal.submission_attempts(operation).unwrap();
    assert_eq!(saved.len(), 1);
    assert!(matches!(saved[0].outcome, SubmissionAttemptOutcome::BlockedBeforeDispatch));
}
