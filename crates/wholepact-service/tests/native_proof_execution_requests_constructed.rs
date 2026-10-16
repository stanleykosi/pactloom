#![cfg(target_os = "linux")]
//! In-process service qualification using the actual Engine constructor receipt.
//! All notes, blocks, principals, and database keys are synthetic and never funded.
//! No listener, proof generation, signing, native approval, or real keys are used.
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering};
use tower::ServiceExt;
use wholepact_core::*;
use wholepact_engine::{
    Access, CandidateRequest, Engine, candidates::LocalConstruction, proof_jobs::LocalCheckpoint,
};
use wholepact_proof_jobs::{
    CheckpointScope, JobState, JobSummary, LocalAction, LocalProofConsent, ProofJobStore,
};
use wholepact_protocol::{
    construction::*, proving::ProvingLimits, review::encode_testnet_receiver,
};
use wholepact_service::{
    NativeRuntime, application_with_native_runtime,
    security::{ClientConfig, Permission, SecurityConfig},
};
use wholepact_storage_security::{DatabaseKey, create_encrypted};
use wholepact_store::Store;
use wholepact_wallet::wallet::synthetic_scanned_contributions;

const PRINCIPAL: &str = "synthetic-http-controller";
const BOOTSTRAP: &str = "wholepact-synthetic-http-proof-only-not-a-secret";
const CONSTRUCTION_KEY: &str = "synthetic-http-original-construction";
const PURPOSE: &str = "Synthetic HTTP receipt qualification";
const RETENTION: &str = "Encrypted temporary directory only";

fn amount(n: u64) -> Amount {
    Amount::from_zatoshis(n).unwrap()
}

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
    let account_ids: Vec<_> = wallets.iter().map(|w| w.account_id().to_owned()).collect();
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
            account_id: w.account_id().into(),
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
    let packages: Vec<_> = wallets.into_iter().map(|w| w.into_contribution()).collect();
    Fixture {
        agreement,
        request,
        chain,
        packages,
        account_ids,
    }
}

// Private fixture gate for never-funded data, not a production authority helper.
// Every action that could prove, recover, or expose private bytes is refused.
struct SyntheticRetentionGate {
    candidate: String,
    manifest: String,
    accounts: Vec<String>,
    forbidden_action_checks: AtomicUsize,
}
impl LocalProofConsent for SyntheticRetentionGate {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        if !matches!(
            action,
            LocalAction::RetainPrivateWitnesses | LocalAction::InspectStatus
        ) {
            self.forbidden_action_checks.fetch_add(1, Ordering::SeqCst);
            return false;
        }
        scope.principal_id == PRINCIPAL
            && scope.candidate_id == self.candidate
            && scope.manifest_digest == self.manifest
            && scope.account_ids == self.accounts
            && scope.local_operator == "synthetic-local-constructor"
            && scope.purpose == PURPOSE
            && scope.retention_policy == RETENTION
    }
}

fn request(
    method: &str,
    path: &str,
    token: &str,
    csrf: Option<&str>,
    mutation: Option<(&str, u64)>,
    body: &str,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("Host", "127.0.0.1:4318")
        .header("Authorization", format!("Bearer {token}"));
    if let Some(csrf) = csrf {
        builder = builder.header("X-Wholepact-CSRF", csrf);
    }
    if let Some((key, revision)) = mutation {
        builder = builder
            .header("Content-Type", "application/json")
            .header("Idempotency-Key", key)
            .header("If-Match", format!("\"{revision}\""));
    }
    builder.body(Body::from(body.to_owned())).unwrap()
}
async fn response(app: &axum::Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}

struct HttpFixture {
    engine: Engine,
    jobs: ProofJobStore,
    access: Access,
    gate: SyntheticRetentionGate,
    original: JobSummary,
    app: axum::Router,
    token: String,
    csrf: String,
    agreement: String,
    _directory: tempfile::TempDir,
}
impl HttpFixture {
    fn revision(&self) -> u64 {
        self.engine
            .get(&self.access, &self.agreement)
            .unwrap()
            .revision
    }
    fn path(&self) -> String {
        format!(
            "/v1/agreements/{}/native-proof-execution-requests",
            self.agreement
        )
    }
    fn body(&self) -> String {
        json!({"candidate_id":self.original.candidate_id,"job_id":self.original.job_id}).to_string()
    }
    async fn get(&self, path: &str) -> Value {
        let (status, value) =
            response(&self.app, request("GET", path, &self.token, None, None, "")).await;
        assert_eq!(status, StatusCode::OK, "{value}");
        value
    }
    async fn post(
        &self,
        path: &str,
        key: &str,
        revision: u64,
        body: &str,
        expected: StatusCode,
    ) -> Value {
        let (status, value) = response(
            &self.app,
            request(
                "POST",
                path,
                &self.token,
                Some(&self.csrf),
                Some((key, revision)),
                body,
            ),
        )
        .await;
        assert_eq!(status, expected, "{value}");
        value
    }
    fn assert_inert(&self) {
        // Comparing the actual independent job journal detects accidental work,
        // rather than trusting only the coordination cache or the HTTP DTO.
        let actual = self
            .jobs
            .status(PRINCIPAL, &self.original.job_id, &self.gate)
            .unwrap();
        assert_eq!(actual, self.original);
        assert_eq!(actual.state, JobState::Queued);
        assert_eq!(actual.attempt, 0);
        assert!(actual.encrypted_checkpoint_created);
        assert!(!actual.proof_verified);
        assert!(!actual.chain_validated);
        assert!(!actual.authorization_allowed);
        assert!(!actual.distribution_allowed);
        assert_eq!(self.gate.forbidden_action_checks.load(Ordering::SeqCst), 0);
        assert_eq!(
            self.engine
                .get(&self.access, &self.agreement)
                .unwrap()
                .authorization_exposure,
            "unknown"
        );
    }
    fn assert_bound_request(&self, value: &Value, revision: u64) {
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["operation"], "proof_execute");
        assert_eq!(value["agreement_id"], self.agreement);
        assert_eq!(value["candidate_id"], self.original.candidate_id);
        assert_eq!(value["job_id"], self.original.job_id);
        assert_eq!(value["manifest_digest"], self.original.manifest_digest);
        assert_eq!(value["scope_digest"], self.original.scope_digest);
        assert_eq!(
            value["coordination_request_digest"],
            self.original.coordination_request_digest
        );
        assert_eq!(value["original_revision"], revision);
        assert_eq!(value["queued_revision"], revision + 1);
        assert_eq!(value["authorization_allowed"], false);
        assert_eq!(value["result_status"], "unknown_not_financial_evidence");
        // This is only an independent expected hash assertion. The persisted
        // receipt itself was created by checkpoint_candidate_locally above.
        let mut hash = Sha256::new();
        hash.update(b"wholepact:checkpoint-receipt:v1\0");
        hash.update(
            serde_json::to_vec(&json!({"principal":PRINCIPAL,"key":CONSTRUCTION_KEY})).unwrap(),
        );
        assert_eq!(value["receipt_storage_key"], hex::encode(hash.finalize()));
        assert_ne!(value["receipt_storage_key"], value["job_id"]);
        assert_eq!(
            hex::decode(value["receipt_digest"].as_str().unwrap())
                .unwrap()
                .len(),
            32
        );
        for private_field in [
            "pczt",
            "pczt_bytes",
            "fvk",
            "witnesses",
            "private_artifact",
            "policy",
        ] {
            assert!(value.get(private_field).is_none());
        }
    }
}

async fn constructed_service() -> HttpFixture {
    use std::os::unix::fs::PermissionsExt;
    let Fixture {
        agreement,
        request: input,
        chain,
        packages,
        account_ids,
    } = fixture();
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let engine = Engine::from_store(
        Store::create_encrypted(
            directory.path().join("metadata.sqlite"),
            &DatabaseKey::from_bytes([91; 32]),
        )
        .unwrap(),
    );
    let jobs = ProofJobStore::from_encrypted_connection(
        create_encrypted(
            directory.path().join("proof.sqlite"),
            &DatabaseKey::from_bytes([92; 32]),
        )
        .unwrap(),
    )
    .unwrap();
    let access = Access {
        principal_id: PRINCIPAL.into(),
        agreement_ids: [agreement.agreement_id.clone()].into(),
        ..Access::default()
    };
    engine
        .create(
            &access,
            "synthetic-http-create-agreement",
            agreement.clone(),
        )
        .unwrap();
    for (index, participant) in input.manifest.participants.iter().enumerate() {
        engine
            .add_intent(
                &access,
                &format!("synthetic-http-intent-{index}"),
                &agreement.agreement_id,
                index as u64 + 1,
                ParticipationIntent {
                    intent_id: format!("intent-{index}"),
                    agreement_id: agreement.agreement_id.clone(),
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
    let frozen = engine
        .create_candidate(
            &access,
            "synthetic-http-create-candidate",
            &agreement.agreement_id,
            input.manifest.participants.len() as u64 + 1,
            input,
        )
        .unwrap();
    let candidate = &frozen.agreement.candidates[0];
    let declarations: Vec<_> = account_ids
        .iter()
        .map(|account| DisclosureAcknowledgement {
            account_id: account.clone(),
            manifest_digest: hex::decode(&candidate.manifest_digest)
                .unwrap()
                .try_into()
                .unwrap(),
            operator: "synthetic-local-constructor".into(),
            reviewer_account_ids: account_ids.clone(),
            purpose: PURPOSE.into(),
            retention_policy: RETENTION.into(),
            scope: DisclosureScope::DedicatedAccountFvkAndSelectedNotesAndOutputs,
        })
        .collect();
    let gate = SyntheticRetentionGate {
        candidate: candidate.candidate_id.clone(),
        manifest: candidate.manifest_digest.clone(),
        accounts: account_ids,
        forbidden_action_checks: AtomicUsize::new(0),
    };
    let checkpoint = engine
        .checkpoint_candidate_locally(
            &access,
            CONSTRUCTION_KEY,
            &candidate.candidate_id,
            frozen.agreement.revision,
            LocalCheckpoint {
                construction: LocalConstruction {
                    context: chain,
                    contributions: packages,
                    declarations: &declarations,
                },
                jobs: &jobs,
                limits: ProvingLimits { maximum_actions: 8 },
                consent: &gate,
            },
        )
        .unwrap();
    assert_eq!(checkpoint.agreement.candidates[0].proof_jobs.len(), 1);
    let cached = &checkpoint.agreement.candidates[0].proof_jobs[0];
    let original = jobs.status(PRINCIPAL, &cached.job_id, &gate).unwrap();
    assert_eq!(
        original.job_id,
        wholepact_proof_jobs::job_id_for_key(PRINCIPAL, CONSTRUCTION_KEY).unwrap()
    );
    assert_eq!(original.scope_digest, cached.scope_digest);
    assert_eq!(
        original.coordination_request_digest,
        cached.coordination_request_digest
    );
    let config = SecurityConfig {
        clients: vec![ClientConfig {
            client_id: PRINCIPAL.into(),
            bootstrap_token: BOOTSTRAP.into(),
            permissions: [
                Permission::Read,
                Permission::Coordinate,
                Permission::Disclose,
            ]
            .into(),
            agreement_ids: [agreement.agreement_id.clone()].into(),
            all_agreements: false,
            include_owned_agreements: false,
        }],
        allowed_origins: Default::default(),
    };
    let runtime = NativeRuntime::new(engine.clone())
        .with_native_request_queue()
        .unwrap();
    let app = application_with_native_runtime(runtime, config, 4318, false).unwrap();
    let (status, session) = response(
        &app,
        request("GET", "/v1/session", BOOTSTRAP, None, None, ""),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(session["client_id"], PRINCIPAL);
    assert_eq!(session["agreement_scope"], "selected");
    assert_eq!(session["agreement_ids"], json!([agreement.agreement_id]));
    assert_eq!(session["all_agreements"], false);
    assert_eq!(session["include_owned_agreements"], false);
    let fixture = HttpFixture {
        engine,
        jobs,
        access,
        gate,
        original,
        app,
        token: session["session_token"].as_str().unwrap().into(),
        csrf: session["csrf_token"].as_str().unwrap().into(),
        agreement: agreement.agreement_id,
        _directory: directory,
    };
    fixture.assert_inert();
    fixture
}

#[tokio::test]
async fn actual_constructor_receipt_supports_http_enqueue_retry_read_and_withdraw() {
    let f = constructed_service().await;
    let path = f.path();
    let original_revision = f.revision();
    let key = "synthetic-http-enqueue-proof-request";
    assert_eq!(f.get(&path).await, json!([]));
    let queued = f
        .post(&path, key, original_revision, &f.body(), StatusCode::OK)
        .await;
    f.assert_bound_request(&queued, original_revision);
    assert_eq!(queued["state"], "queued");
    assert_eq!(queued["execution_status"], "not_attempted");
    assert!(queued["attempt_revision"].is_null());
    assert!(queued["execution_operation_id"].is_null());
    assert_eq!(f.revision(), original_revision + 1);
    let selected = format!("{path}/{}", queued["request_id"].as_str().unwrap());
    assert_eq!(f.get(&selected).await, queued);
    assert_eq!(f.get(&path).await, json!([queued]));
    // The original If-Match and request key are retried, not recomposed.
    assert_eq!(
        f.post(&path, key, original_revision, &f.body(), StatusCode::OK)
            .await,
        queued
    );
    assert_eq!(f.revision(), original_revision + 1);
    let conflict = f
        .post(&path, key, f.revision(), &f.body(), StatusCode::CONFLICT)
        .await;
    assert_eq!(conflict["code"], "IDEMPOTENCY_CONFLICT");
    let withdrawal_revision = f.revision();
    let withdraw = format!("{selected}/withdraw");
    let withdrawn = f
        .post(
            &withdraw,
            "synthetic-http-withdraw-proof-request",
            withdrawal_revision,
            "{}",
            StatusCode::OK,
        )
        .await;
    assert_eq!(withdrawn["state"], "withdrawn");
    assert_eq!(withdrawn["execution_status"], "not_attempted");
    assert_eq!(withdrawn["request_id"], queued["request_id"]);
    f.assert_bound_request(&withdrawn, original_revision);
    assert_eq!(f.revision(), withdrawal_revision + 1);
    assert_eq!(
        f.post(
            &withdraw,
            "synthetic-http-withdraw-proof-request",
            withdrawal_revision,
            "{}",
            StatusCode::OK
        )
        .await,
        withdrawn
    );
    // An enqueue retry after withdrawal returns the same historical request.
    assert_eq!(
        f.post(&path, key, original_revision, &f.body(), StatusCode::OK)
            .await,
        withdrawn
    );
    assert_eq!(f.get(&selected).await, withdrawn);
    assert_eq!(f.get(&path).await, json!([withdrawn]));
    assert_eq!(f.revision(), withdrawal_revision + 1);
    f.assert_inert();
}

#[tokio::test]
async fn actual_constructor_attempt_remains_unknown_and_http_cannot_replace_or_execute_it() {
    let f = constructed_service().await;
    let path = f.path();
    let original_revision = f.revision();
    let key = "synthetic-http-unknown-proof-request";
    let queued = f
        .post(&path, key, original_revision, &f.body(), StatusCode::OK)
        .await;
    let request_id = queued["request_id"].as_str().unwrap();
    let selected = format!("{path}/{request_id}");
    // The trusted embedding API records only the inert metadata fence. HTTP has
    // no route to this call and this test never obtains native runtime consent.
    let attempt = f
        .engine
        .mark_native_proof_execution_attempt(&f.access, &f.agreement, request_id)
        .unwrap();
    assert_eq!(attempt.candidate_id(), f.original.candidate_id);
    assert_eq!(attempt.job_id(), f.original.job_id);
    let unknown_revision = f.revision();
    assert_eq!(attempt.revision(), unknown_revision);
    let unknown = f.get(&selected).await;
    f.assert_bound_request(&unknown, original_revision);
    assert_eq!(unknown["state"], "attempt_started");
    assert_eq!(unknown["execution_status"], "unknown");
    assert_eq!(unknown["attempt_revision"], unknown_revision);
    assert!(unknown["execution_operation_id"].is_null());
    assert_eq!(
        f.post(&path, key, original_revision, &f.body(), StatusCode::OK)
            .await,
        unknown
    );
    // Reading the actual job journal is not an exact reconciliation commit.
    f.assert_inert();
    assert_eq!(f.get(&selected).await, unknown);
    let denied = f
        .post(
            &format!("{selected}/withdraw"),
            "synthetic-http-denied-withdraw",
            unknown_revision,
            "{}",
            StatusCode::CONFLICT,
        )
        .await;
    assert_eq!(denied["code"], "INVALID_TRANSITION");
    let denied = f
        .post(
            &path,
            "synthetic-http-denied-replacement",
            unknown_revision,
            &f.body(),
            StatusCode::CONFLICT,
        )
        .await;
    assert_eq!(denied["code"], "INVALID_TRANSITION");
    for action in [
        "start", "approve", "run", "prove", "recover", "complete", "sign", "submit",
    ] {
        let denied = f
            .post(
                &format!("{selected}/{action}"),
                &format!("synthetic-http-forbidden-{action}"),
                unknown_revision,
                "{}",
                StatusCode::NOT_IMPLEMENTED,
            )
            .await;
        assert_eq!(denied["code"], "UNSUPPORTED_CAPABILITY");
    }
    assert_eq!(f.get(&selected).await, unknown);
    assert_eq!(f.get(&path).await, json!([unknown]));
    assert_eq!(f.revision(), unknown_revision);
    f.assert_inert();
}
