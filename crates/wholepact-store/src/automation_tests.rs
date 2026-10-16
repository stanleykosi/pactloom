use super::*;
use crate::authority::ExposureState;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use wholepact_core::{
    Amount,
    automation::{
        AUTOMATION_PROFILE, AutomationEvidence, AutomationEvidenceKind as Kind,
        AutomationEvidenceRequirement,
    },
};
use wholepact_storage_security::DatabaseKey;

fn money(value: u64) -> Amount {
    Amount::from_zatoshis(value).unwrap()
}
fn policy() -> AutomationAccountPolicy {
    AutomationAccountPolicy {
        policy_id: "owner-policy-1".into(),
        account_id: "account".into(),
        writer_epoch: 7,
        maximum_outstanding_debit: money(100),
        valid_from_ms: 1_000,
        expires_at_ms: 10_000,
    }
}
fn terms(id: &str, app: &str) -> AutomationGrantTerms {
    AutomationGrantTerms {
        grant_id: id.into(),
        application_id: app.into(),
        account_id: "account".into(),
        account_policy_id: "owner-policy-1".into(),
        writer_epoch: 7,
        network_profile: AUTOMATION_PROFILE.into(),
        signer_id: "synthetic-signer".into(),
        verifier_id: "synthetic-verifier".into(),
        agreement_ids: vec!["agreement".into()],
        recipient_fingerprints: vec!["a".repeat(64)],
        maximum_payment_debit: money(80),
        maximum_payment_fee: money(5),
        maximum_outstanding_debit: money(100),
        evidence: [
            Kind::AccountControl,
            Kind::RecipientInstructions,
            Kind::ExactEffects,
            Kind::CurrentChain,
            Kind::ExposureContinuity,
        ]
        .into_iter()
        .map(|kind| AutomationEvidenceRequirement {
            kind,
            verifier_id: "synthetic-verifier".into(),
            maximum_age_ms: 500,
        })
        .collect(),
        maximum_authorization_lifetime_ms: 500,
        maximum_expiry_height_delta: 20,
        valid_from_ms: 1_000,
        expires_at_ms: 9_000,
    }
}
fn request(id: &str, app: &str, debit: u64) -> AutomationRequest {
    AutomationRequest {
        authorization_id: id.into(),
        application_id: app.into(),
        account_id: "account".into(),
        writer_epoch: 7,
        agreement_id: "agreement".into(),
        obligation_id: format!("obligation-{id}"),
        proposal_id: format!("proposal-{id}"),
        network_profile: AUTOMATION_PROFILE.into(),
        manifest_digest: "b".repeat(64),
        effects_digest: "c".repeat(64),
        artifact_digest: "d".repeat(64),
        input_ids: vec![format!("input-{id}")],
        recipient_fingerprints: vec!["a".repeat(64)],
        maximum_debit: money(debit),
        fee: money(2),
        current_height: 4_465_040,
        transaction_expiry_height: 4_465_050,
        authorization_expires_at_ms: 2_400,
        evidence: terms("grant", app)
            .evidence
            .into_iter()
            .map(|r| AutomationEvidence {
                kind: r.kind,
                verifier_id: r.verifier_id,
                evidence_digest: "e".repeat(64),
                manifest_digest: "b".repeat(64),
                effects_digest: "c".repeat(64),
                observed_at_ms: 1_900,
                expires_at_ms: 2_500,
            })
            .collect(),
    }
}
#[derive(Clone)]
struct SyntheticTrust {
    held: Arc<AtomicBool>,
    now: Arc<AtomicU64>,
    checks: Arc<AtomicUsize>,
    acquisitions: Arc<AtomicUsize>,
    deny_at: Arc<AtomicUsize>,
}
struct SyntheticLease {
    trust: SyntheticTrust,
    scope: AutomationReview,
}
impl Default for SyntheticTrust {
    fn default() -> Self {
        Self {
            held: Arc::new(AtomicBool::new(false)),
            now: Arc::new(AtomicU64::new(2_000)),
            checks: Arc::new(AtomicUsize::new(0)),
            acquisitions: Arc::new(AtomicUsize::new(0)),
            deny_at: Arc::new(AtomicUsize::new(usize::MAX)),
        }
    }
}
impl Drop for SyntheticLease {
    fn drop(&mut self) {
        self.trust.held.store(false, Ordering::Release);
    }
}
impl AutomationLease for SyntheticLease {
    fn check_current(&self, review: &AutomationReview, _: u64) -> Result<()> {
        let check = self.trust.checks.fetch_add(1, Ordering::SeqCst);
        if review != &self.scope || check >= self.trust.deny_at.load(Ordering::SeqCst) {
            return Err(AutomationError::Denied);
        }
        Ok(())
    }
    fn consent_reference(&self) -> &str {
        "synthetic-original-owner-consent"
    }
}
impl AutomationTrustSource for SyntheticTrust {
    type Lease = SyntheticLease;
    fn verifier_id(&self) -> &str {
        "synthetic-verifier"
    }
    fn acquire(&self, review: &AutomationReview) -> Result<Self::Lease> {
        self.acquisitions.fetch_add(1, Ordering::SeqCst);
        while self
            .held
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            std::thread::yield_now();
        }
        Ok(SyntheticLease {
            trust: self.clone(),
            scope: review.clone(),
        })
    }
    fn now_ms(&self) -> Result<u64> {
        Ok(self.now.load(Ordering::SeqCst))
    }
}
struct SyntheticAuthorizer {
    calls: usize,
    fail: bool,
}
impl AutomaticAuthorizer for SyntheticAuthorizer {
    fn signer_id(&self) -> &str {
        "synthetic-signer"
    }
    fn authorize_exact(
        &mut self,
        prepared: PreparedAutomaticAuthorization<'_>,
    ) -> Result<AutomaticAuthorizationOutcome> {
        prepared.check_current()?;
        self.calls += 1;
        assert_eq!(
            prepared.record().original_activation_consent_reference,
            "synthetic-original-owner-consent"
        );
        if self.fail {
            Err(AutomationError::Unavailable)
        } else {
            Ok(AutomaticAuthorizationOutcome::RetainedLocally)
        }
    }
}
struct Fixture {
    store: Store,
    path: std::path::PathBuf,
    trust: SyntheticTrust,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "wholepact-automation-{}-{}.sqlite",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        use std::os::unix::fs::DirBuilderExt;
        let directory = path.with_extension("private");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let path = directory.join("automation.sqlite");
        let store = Store::create_encrypted(&path, &DatabaseKey::from_bytes([117; 32])).unwrap();
        store.initialize_authority_account("account", 7).unwrap();
        let fixture = Self {
            store,
            path,
            trust: SyntheticTrust::default(),
        };
        fixture
            .store
            .configure_automation_account(policy(), None, &fixture.trust)
            .unwrap();
        fixture
    }
    fn active(&self, id: &str, app: &str) {
        self.store
            .create_automation_grant(terms(id, app), &self.trust)
            .unwrap();
        self.store
            .change_automation_grant(id, 1, AutomationGrantAction::Activate, &self.trust)
            .unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.path.display()));
        }
        let _ = std::fs::remove_dir(self.path.parent().unwrap());
    }
}

#[test]
fn pure_review_examples_cover_every_scope_and_evidence_bound() {
    let p = policy();
    let g = terms("g", "app");
    let good = request("a", "app", 70);
    evaluate_automation_request(&p, &g, &good, 2_000).unwrap();
    let mut bad = Vec::new();
    let mut r = good.clone();
    r.application_id = "other".into();
    bad.push(r);
    let mut r = good.clone();
    r.account_id = "other".into();
    bad.push(r);
    let mut r = good.clone();
    r.writer_epoch += 1;
    bad.push(r);
    let mut r = good.clone();
    r.agreement_id = "other".into();
    bad.push(r);
    let mut r = good.clone();
    r.recipient_fingerprints = vec!["f".repeat(64)];
    bad.push(r);
    let mut r = good.clone();
    r.network_profile = "mainnet".into();
    bad.push(r);
    let mut r = good.clone();
    r.maximum_debit = money(81);
    bad.push(r);
    let mut r = good.clone();
    r.fee = money(6);
    bad.push(r);
    let mut r = good.clone();
    r.authorization_expires_at_ms = 2_501;
    bad.push(r);
    let mut r = good.clone();
    r.transaction_expiry_height = r.current_height;
    bad.push(r);
    let mut r = good.clone();
    r.transaction_expiry_height += 11;
    bad.push(r);
    let mut r = good.clone();
    r.evidence[0].verifier_id = "impostor".into();
    bad.push(r);
    let mut r = good.clone();
    r.evidence[0].effects_digest = "f".repeat(64);
    bad.push(r);
    let mut r = good.clone();
    r.evidence[0].observed_at_ms = 1_000;
    bad.push(r);
    let mut r = good.clone();
    r.evidence[0].expires_at_ms = 2_399;
    bad.push(r);
    let mut r = good.clone();
    r.evidence[0] = r.evidence[1].clone();
    bad.push(r);
    for r in bad {
        assert!(evaluate_automation_request(&p, &g, &r, 2_000).is_err());
    }
    let mut value = serde_json::to_value(good).unwrap();
    value["aggregate_budget_limit"] = serde_json::json!("999999");
    assert!(serde_json::from_value::<AutomationRequest>(value).is_err());
    let mut invalid = g.clone();
    invalid.evidence.pop();
    assert!(invalid.validate(&p).is_err());
    let mut invalid = g.clone();
    invalid.maximum_outstanding_debit = money(101);
    assert!(invalid.validate(&p).is_err());
}
#[test]
fn default_deny_plaintext_and_draft_never_call_authorizer() {
    let f = Fixture::new();
    let mut signer = SyntheticAuthorizer {
        calls: 0,
        fail: false,
    };
    assert!(matches!(
        f.store
            .create_automation_grant(terms("g", "app"), &DenyAutomationTrustSource),
        Err(AutomationError::Denied)
    ));
    assert!(matches!(
        Store::in_memory()
            .unwrap()
            .configure_automation_account(policy(), None, &f.trust),
        Err(AutomationError::Unavailable)
    ));
    f.store
        .create_automation_grant(terms("g", "app"), &f.trust)
        .unwrap();
    assert!(matches!(
        f.store
            .authorize_automatically("g", request("a", "app", 70), &f.trust, &mut signer),
        Err(AutomationError::NotActive)
    ));
    assert_eq!(signer.calls, 0);
    assert_eq!(f.store.outstanding_debit("account").unwrap(), "0");
}
#[test]
fn release_then_revoke_preserves_exact_consent_exposure_and_historical_replay() {
    let f = Fixture::new();
    f.active("g", "app");
    let mut signer = SyntheticAuthorizer {
        calls: 0,
        fail: false,
    };
    let r = request("a", "app", 70);
    let first = f
        .store
        .authorize_automatically("g", r.clone(), &f.trust, &mut signer)
        .unwrap();
    assert!(!first.replayed);
    assert_eq!(first.exposure.state, ExposureState::OutstandingUncertain);
    f.store.mark_authorization_released("a").unwrap();
    f.store
        .change_automation_grant("g", 2, AutomationGrantAction::Revoke, &f.trust)
        .unwrap();
    assert!(matches!(
        f.store
            .authorize_automatically("g", request("b", "app", 10), &f.trust, &mut signer),
        Err(AutomationError::NotActive)
    ));
    let replay = f
        .store
        .authorize_automatically("g", r.clone(), &DenyAutomationTrustSource, &mut signer)
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(signer.calls, 1);
    assert_eq!(replay.exposure.state, ExposureState::Released);
    assert_eq!(f.store.outstanding_debit("account").unwrap(), "70");
    let mut changed = r;
    changed.fee = money(3);
    assert!(matches!(
        f.store
            .authorize_automatically("g", changed, &f.trust, &mut signer),
        Err(AutomationError::Store(StoreError::IdempotencyConflict))
    ));
    assert!(
        f.store
            .change_automation_grant("g", 3, AutomationGrantAction::Activate, &f.trust)
            .is_err()
    );
    let events = f.store.events_after(0, 100).unwrap();
    assert!(events.iter().any(|e| e.kind == "automation.grant_revoked"));
    assert!(
        events
            .iter()
            .any(|e| e.kind == "automation.authorization_intent_recorded")
    );
}
#[test]
fn pause_resume_expiry_and_deliberate_renewal_never_extend_old_terms() {
    let f = Fixture::new();
    f.active("g", "app");
    f.store
        .change_automation_grant("g", 2, AutomationGrantAction::Pause, &f.trust)
        .unwrap();
    f.store
        .change_automation_grant("g", 3, AutomationGrantAction::Activate, &f.trust)
        .unwrap();
    f.trust.now.store(9_000, Ordering::SeqCst);
    let mut signer = SyntheticAuthorizer {
        calls: 0,
        fail: false,
    };
    assert!(
        f.store
            .authorize_automatically("g", request("a", "app", 10), &f.trust, &mut signer)
            .is_err()
    );
    f.store
        .change_automation_grant("g", 4, AutomationGrantAction::ObserveExpiry, &f.trust)
        .unwrap();
    assert!(
        f.store
            .change_automation_grant("g", 5, AutomationGrantAction::Activate, &f.trust)
            .is_err()
    );
    assert_eq!(
        f.store
            .automation_grant("g")
            .unwrap()
            .unwrap()
            .terms
            .expires_at_ms,
        9_000
    );
    let mut renewal = terms("renewal", "app");
    renewal.valid_from_ms = 9_000;
    renewal.expires_at_ms = 10_000;
    f.store.create_automation_grant(renewal, &f.trust).unwrap();
    assert_eq!(
        f.store.automation_grant("renewal").unwrap().unwrap().status,
        AutomationGrantStatus::Draft
    );
    assert_eq!(signer.calls, 0);
}
#[test]
fn racing_applications_and_legacy_path_share_one_durable_account_budget() {
    let f = Fixture::new();
    f.active("g1", "app1");
    f.active("g2", "app2");
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let results = std::thread::scope(|scope| {
        let mut workers = Vec::new();
        for (grant, app, id) in [("g1", "app1", "a"), ("g2", "app2", "b")] {
            let barrier = barrier.clone();
            let path = f.path.clone();
            let trust = SyntheticTrust::default();
            workers.push(scope.spawn(move || {
                let store =
                    Store::open_encrypted(path, &DatabaseKey::from_bytes([117; 32])).unwrap();
                barrier.wait();
                let mut signer = SyntheticAuthorizer {
                    calls: 0,
                    fail: false,
                };
                store.authorize_automatically(grant, request(id, app, 70), &trust, &mut signer)
            }));
        }
        workers
            .into_iter()
            .map(|w| w.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(AutomationError::Store(StoreError::BudgetExceeded))))
            .count(),
        1
    );
    assert_eq!(f.store.outstanding_debit("account").unwrap(), "70");
    let r = request("manual", "app", 40);
    let intent = ReleaseIntent {
        authorization_id: r.authorization_id,
        account_id: r.account_id,
        writer_epoch: r.writer_epoch,
        obligation_id: r.obligation_id,
        proposal_id: r.proposal_id,
        manifest_digest: r.manifest_digest,
        effects_digest: r.effects_digest,
        artifact_digest: r.artifact_digest,
        maximum_debit: "40".into(),
        input_ids: r.input_ids,
        aggregate_budget_limit: "999999".into(),
    };
    assert!(matches!(
        f.store.record_authorization_release_intent(&intent),
        Err(StoreError::BudgetExceeded)
    ));
}
#[test]
fn grant_budget_atomic_audit_fault_and_callback_failure_remain_conservative() {
    let f = Fixture::new();
    let mut g = terms("g", "app");
    g.maximum_outstanding_debit = money(80);
    f.store.create_automation_grant(g, &f.trust).unwrap();
    f.store
        .change_automation_grant("g", 1, AutomationGrantAction::Activate, &f.trust)
        .unwrap();
    let mut signer = SyntheticAuthorizer {
        calls: 0,
        fail: true,
    };
    f.store.connection.lock().unwrap().execute_batch("CREATE TRIGGER automation_fault BEFORE INSERT ON events WHEN NEW.kind='automation.authorization_intent_recorded' BEGIN SELECT RAISE(ABORT,'synthetic fault'); END;").unwrap();
    assert!(
        f.store
            .authorize_automatically("g", request("a", "app", 70), &f.trust, &mut signer)
            .is_err()
    );
    assert_eq!(signer.calls, 0);
    assert!(f.store.exposure("a").unwrap().is_none());
    f.store
        .connection
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER automation_fault;")
        .unwrap();
    let receipt = f
        .store
        .authorize_automatically("g", request("a", "app", 70), &f.trust, &mut signer)
        .unwrap();
    assert_eq!(
        receipt.record.outcome,
        AutomaticAuthorizationOutcome::Unknown
    );
    assert!(matches!(
        f.store
            .authorize_automatically("g", request("b", "app", 20), &f.trust, &mut signer),
        Err(AutomationError::Store(StoreError::BudgetExceeded))
    ));
    assert_eq!(f.store.outstanding_debit("account").unwrap(), "70");
}
#[test]
fn postcommit_gate_failure_never_invokes_signer_or_retries_the_durable_intent() {
    let f = Fixture::new();
    f.active("g", "app");
    let mut signer = SyntheticAuthorizer {
        calls: 0,
        fail: false,
    };
    let next = f.trust.checks.load(Ordering::SeqCst);
    f.trust.deny_at.store(next + 2, Ordering::SeqCst);
    assert!(matches!(
        f.store
            .authorize_automatically("g", request("a", "app", 70), &f.trust, &mut signer),
        Err(AutomationError::AuthorizationUncertain)
    ));
    assert_eq!(signer.calls, 0);
    assert_eq!(f.store.outstanding_debit("account").unwrap(), "70");
    let replay = f
        .store
        .authorize_automatically(
            "g",
            request("a", "app", 70),
            &DenyAutomationTrustSource,
            &mut signer,
        )
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(
        replay.record.outcome,
        AutomaticAuthorizationOutcome::Unknown
    );
    assert_eq!(signer.calls, 0);
}
#[test]
fn quarantine_writer_epoch_and_reorg_block_new_automatic_authority() {
    let f = Fixture::new();
    f.active("g", "app");
    let mut signer = SyntheticAuthorizer {
        calls: 0,
        fail: false,
    };
    f.store
        .authorize_automatically("g", request("a", "app", 70), &f.trust, &mut signer)
        .unwrap();
    f.store
        .record_observed_resolution("a", ExposureState::Consumed, "synthetic-confirmation")
        .unwrap();
    assert_eq!(f.store.outstanding_debit("account").unwrap(), "0");
    f.store
        .reopen_exposure_after_reorg("a", "synthetic-reorg")
        .unwrap();
    assert_eq!(f.store.outstanding_debit("account").unwrap(), "70");
    assert!(matches!(
        f.store
            .authorize_automatically("g", request("b", "app", 10), &f.trust, &mut signer),
        Err(AutomationError::Store(StoreError::RecoveryRequired))
    ));
    assert_eq!(signer.calls, 1);
}
#[test]
fn generic_record_writer_cannot_forge_automation_grant_or_replay_its_namespace() {
    let f = Fixture::new();
    let context = crate::CommandContext::for_request(
        "app",
        "forged-automation-001",
        &serde_json::json!({"forge":true}),
    )
    .unwrap();
    assert!(matches!(
        f.store.commit_record(
            &context,
            "automation_grant",
            "g",
            None,
            serde_json::json!({"status":"active"}),
            "forged"
        ),
        Err(StoreError::InvalidInput(_))
    ));
}

#[test]
fn held_account_lease_orders_revocation_after_an_inflight_authorization() {
    let f = Fixture::new();
    f.active("g", "app");
    let entered = Arc::new(std::sync::Barrier::new(2));
    let finish = Arc::new(std::sync::Barrier::new(2));
    struct BlockingAuthorizer {
        entered: Arc<std::sync::Barrier>,
        finish: Arc<std::sync::Barrier>,
    }
    impl AutomaticAuthorizer for BlockingAuthorizer {
        fn signer_id(&self) -> &str {
            "synthetic-signer"
        }
        fn authorize_exact(
            &mut self,
            _: PreparedAutomaticAuthorization<'_>,
        ) -> Result<AutomaticAuthorizationOutcome> {
            self.entered.wait();
            self.finish.wait();
            Ok(AutomaticAuthorizationOutcome::RetainedLocally)
        }
    }
    std::thread::scope(|scope| {
        let store = &f.store;
        let trust = &f.trust;
        let entered_worker = entered.clone();
        let finish_worker = finish.clone();
        let authorizing = scope.spawn(move || {
            let mut signer = BlockingAuthorizer {
                entered: entered_worker,
                finish: finish_worker,
            };
            store.authorize_automatically("g", request("a", "app", 70), trust, &mut signer)
        });
        entered.wait();
        assert_eq!(store.outstanding_debit("account").unwrap(), "70");
        let target = trust.acquisitions.load(Ordering::SeqCst) + 1;
        let revoking = scope.spawn(move || {
            store.change_automation_grant("g", 2, AutomationGrantAction::Revoke, trust)
        });
        while trust.acquisitions.load(Ordering::SeqCst) < target {
            std::thread::yield_now();
        }
        assert_eq!(
            store.automation_grant("g").unwrap().unwrap().status,
            AutomationGrantStatus::Active
        );
        finish.wait();
        authorizing.join().unwrap().unwrap();
        assert_eq!(
            revoking.join().unwrap().unwrap().status,
            AutomationGrantStatus::Revoked
        );
    });
    let mut signer = SyntheticAuthorizer {
        calls: 0,
        fail: false,
    };
    assert!(matches!(
        f.store
            .authorize_automatically("g", request("b", "app", 10), &f.trust, &mut signer),
        Err(AutomationError::NotActive)
    ));
    assert_eq!(signer.calls, 0);
    assert_eq!(f.store.outstanding_debit("account").unwrap(), "70");
}

#[test]
fn wrong_injected_signer_or_verifier_identity_cannot_acquire_new_authority() {
    let f = Fixture::new();
    f.active("g", "app");
    struct WrongSigner;
    impl AutomaticAuthorizer for WrongSigner {
        fn signer_id(&self) -> &str {
            "wrong-signer"
        }
        fn authorize_exact(
            &mut self,
            _: PreparedAutomaticAuthorization<'_>,
        ) -> Result<AutomaticAuthorizationOutcome> {
            panic!("wrong signer called")
        }
    }
    struct WrongVerifier(SyntheticTrust);
    impl AutomationTrustSource for WrongVerifier {
        type Lease = SyntheticLease;
        fn verifier_id(&self) -> &str {
            "wrong-verifier"
        }
        fn acquire(&self, _: &AutomationReview) -> Result<Self::Lease> {
            panic!("wrong verifier acquired")
        }
        fn now_ms(&self) -> Result<u64> {
            self.0.now_ms()
        }
    }
    assert!(matches!(
        f.store
            .authorize_automatically("g", request("a", "app", 70), &f.trust, &mut WrongSigner),
        Err(AutomationError::Denied)
    ));
    let mut signer = SyntheticAuthorizer {
        calls: 0,
        fail: false,
    };
    assert!(matches!(
        f.store.authorize_automatically(
            "g",
            request("a", "app", 70),
            &WrongVerifier(f.trust.clone()),
            &mut signer
        ),
        Err(AutomationError::Denied)
    ));
    assert_eq!(signer.calls, 0);
    assert_eq!(f.store.outstanding_debit("account").unwrap(), "0");
}

#[test]
fn expiry_restart_and_clock_regression_preserve_pending_budget() {
    let f = Fixture::new();
    f.active("g", "app");
    let mut signer = SyntheticAuthorizer {
        calls: 0,
        fail: false,
    };
    let first_request = request("a", "app", 70);
    f.store
        .authorize_automatically("g", first_request.clone(), &f.trust, &mut signer)
        .unwrap();
    f.trust.now.store(2_100, Ordering::SeqCst);
    f.store
        .authorize_automatically("g", request("b", "app", 10), &f.trust, &mut signer)
        .unwrap();
    // Regression is later than the grant/account timestamps but older than the
    // last authorization, exercising the separate account-wide high-water mark.
    f.trust.now.store(2_050, Ordering::SeqCst);
    assert!(matches!(
        f.store
            .authorize_automatically("g", request("c", "app", 10), &f.trust, &mut signer),
        Err(AutomationError::ClockInvalid)
    ));
    assert!(f.store.exposure("c").unwrap().is_none());
    let reopened = Store::open_encrypted(&f.path, &DatabaseKey::from_bytes([117; 32])).unwrap();
    let replay = reopened
        .authorize_automatically("g", first_request, &DenyAutomationTrustSource, &mut signer)
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(
        replay.record.original_activation_consent_reference,
        "synthetic-original-owner-consent"
    );
    f.trust.now.store(9_000, Ordering::SeqCst);
    reopened
        .change_automation_grant("g", 2, AutomationGrantAction::ObserveExpiry, &f.trust)
        .unwrap();
    let mut renewal = terms("renewal", "app");
    renewal.valid_from_ms = 9_000;
    renewal.expires_at_ms = 10_000;
    reopened.create_automation_grant(renewal, &f.trust).unwrap();
    reopened
        .change_automation_grant("renewal", 1, AutomationGrantAction::Activate, &f.trust)
        .unwrap();
    let mut next = request("renewed-request", "app", 30);
    next.authorization_expires_at_ms = 9_400;
    for evidence in &mut next.evidence {
        evidence.observed_at_ms = 9_000;
        evidence.expires_at_ms = 9_500;
    }
    assert!(matches!(
        reopened.authorize_automatically("renewal", next, &f.trust, &mut signer),
        Err(AutomationError::Store(StoreError::BudgetExceeded))
    ));
    assert_eq!(reopened.outstanding_debit("account").unwrap(), "80");
    assert_eq!(signer.calls, 2);
}

#[test]
fn delayed_key_use_rechecks_exact_policy_without_a_second_callback() {
    let f = Fixture::new();
    f.active("g", "app");
    struct DelayedAuthorizer {
        trust: SyntheticTrust,
        calls: usize,
        key_uses: usize,
    }
    impl AutomaticAuthorizer for DelayedAuthorizer {
        fn signer_id(&self) -> &str {
            "synthetic-signer"
        }
        fn authorize_exact(
            &mut self,
            prepared: PreparedAutomaticAuthorization<'_>,
        ) -> Result<AutomaticAuthorizationOutcome> {
            self.calls += 1;
            self.trust.now.store(2_401, Ordering::SeqCst);
            prepared.check_current()?;
            self.key_uses += 1;
            Ok(AutomaticAuthorizationOutcome::RetainedLocally)
        }
    }
    let mut signer = DelayedAuthorizer {
        trust: f.trust.clone(),
        calls: 0,
        key_uses: 0,
    };
    let receipt = f
        .store
        .authorize_automatically("g", request("a", "app", 70), &f.trust, &mut signer)
        .unwrap();
    assert_eq!(
        receipt.record.outcome,
        AutomaticAuthorizationOutcome::Unknown
    );
    assert_eq!(signer.calls, 1);
    assert_eq!(signer.key_uses, 0);
    assert_eq!(f.store.outstanding_debit("account").unwrap(), "70");
    f.store
        .authorize_automatically(
            "g",
            request("a", "app", 70),
            &DenyAutomationTrustSource,
            &mut signer,
        )
        .unwrap();
    assert_eq!(signer.calls, 1);
}

#[test]
fn observed_conflict_and_expiry_keep_grant_charge_and_never_reinvoke_authorizer() {
    for observed in [
        ExposureState::ConflictedObserved,
        ExposureState::ExpiredObserved,
    ] {
        let f = Fixture::new();
        let mut g = terms("g", "app");
        g.maximum_outstanding_debit = money(80);
        f.store.create_automation_grant(g, &f.trust).unwrap();
        f.store
            .change_automation_grant("g", 1, AutomationGrantAction::Activate, &f.trust)
            .unwrap();
        let mut signer = SyntheticAuthorizer {
            calls: 0,
            fail: false,
        };
        f.store
            .authorize_automatically("g", request("a", "app", 70), &f.trust, &mut signer)
            .unwrap();
        f.store
            .record_observed_resolution("a", observed, "synthetic-observation")
            .unwrap();
        assert_eq!(f.store.outstanding_debit("account").unwrap(), "70");
        // 20 fits the account's remaining 30, but not this grant's remaining 10.
        assert!(matches!(
            f.store
                .authorize_automatically("g", request("b", "app", 20), &f.trust, &mut signer),
            Err(AutomationError::Store(StoreError::BudgetExceeded))
        ));
        assert_eq!(signer.calls, 1);
        assert!(f.store.exposure("b").unwrap().is_none());
        let replay = f
            .store
            .authorize_automatically(
                "g",
                request("a", "app", 70),
                &DenyAutomationTrustSource,
                &mut signer,
            )
            .unwrap();
        assert!(replay.replayed);
        assert_eq!(signer.calls, 1);
        assert_eq!(f.store.exposure("a").unwrap().unwrap().state, observed);
        f.store
            .authorize_automatically("g", request("c", "app", 10), &f.trust, &mut signer)
            .unwrap();
        assert_eq!(signer.calls, 2);
        assert_eq!(f.store.outstanding_debit("account").unwrap(), "80");
    }
}

#[test]
fn consumed_settlement_reopens_pending_grant_capacity_but_never_lifetime_allowance() {
    let f = Fixture::new();
    let mut g = terms("g", "app");
    g.maximum_outstanding_debit = money(80);
    f.store.create_automation_grant(g, &f.trust).unwrap();
    f.store
        .change_automation_grant("g", 1, AutomationGrantAction::Activate, &f.trust)
        .unwrap();
    let mut signer = SyntheticAuthorizer {
        calls: 0,
        fail: false,
    };
    f.store
        .authorize_automatically("g", request("a", "app", 70), &f.trust, &mut signer)
        .unwrap();
    f.store
        .record_observed_resolution("a", ExposureState::Consumed, "synthetic-confirmed-original")
        .unwrap();
    assert_eq!(f.store.outstanding_debit("account").unwrap(), "0");
    assert_eq!(f.store.settled_debit("account").unwrap(), "70");
    // The pending grant has room again, but the account has only 30 remaining.
    f.store
        .authorize_automatically("g", request("b", "app", 20), &f.trust, &mut signer)
        .unwrap();
    assert!(matches!(
        f.store
            .authorize_automatically("g", request("c", "app", 11), &f.trust, &mut signer),
        Err(AutomationError::Store(StoreError::BudgetExceeded))
    ));
    assert_eq!(signer.calls, 2);
    assert_eq!(f.store.outstanding_debit("account").unwrap(), "20");
    assert_eq!(f.store.settled_debit("account").unwrap(), "70");
    assert!(f.store.exposure("c").unwrap().is_none());
}
