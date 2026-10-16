//! Synthetic record provenance and local authority. No signer/chain qualification.
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::Value;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tower::ServiceExt;
use wholepact_core::{
    AuthorizationExposure, IntentStatus, ParticipationIntent, Proposal, records::*,
};
use wholepact_engine::{Access, ApiError, CandidateRequest, Engine, participant_records::*};
use wholepact_service::{
    application_with_records,
    protected_records::ProtectedRecordsRuntime,
    security::{Permission, SecurityConfig},
};
use wholepact_storage_security::DatabaseKey;
use wholepact_store::Store;
const PRINCIPAL: &str = "development-workspace";
const PROFILE: &str = "synthetic-record-profile";
const BOOT: &str = "wholepact-development-only-not-a-secret";
fn access() -> Access {
    Access {
        include_owned_agreements: true,
        principal_id: PRINCIPAL.into(),
        all_agreements: true,
        ..Access::default()
    }
}
fn window() -> ObservationWindow {
    let now = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
    ObservationWindow {
        now: now.format(&Rfc3339).unwrap(),
        oldest_acceptable: (now - time::Duration::seconds(300))
            .format(&Rfc3339)
            .unwrap(),
    }
}
struct Authority {
    binding: RecordStoreBinding,
    revoked: AtomicBool,
}
struct Lease<'a> {
    scope: ParticipantRecordScope,
    expires: String,
    authority: &'a Authority,
}
impl ParticipantRecordLease for Lease<'_> {
    fn scope(&self) -> &ParticipantRecordScope {
        &self.scope
    }
    fn expires_at(&self) -> &str {
        &self.expires
    }
    fn check_current(&self) -> wholepact_engine::Result<()> {
        if self.authority.revoked.load(Ordering::SeqCst) {
            Err(ApiError::new(
                "PERMISSION_DENIED",
                "Synthetic record lease revoked",
            ))
        } else {
            Ok(())
        }
    }
}
impl ParticipantRecordAuthority for Authority {
    fn acquire<'a>(
        &'a self,
        scope: &ParticipantRecordScope,
        window: &ObservationWindow,
    ) -> wholepact_engine::Result<Box<dyn ParticipantRecordLease + 'a>> {
        if scope.store != self.binding
            || scope.profile_id != PROFILE
            || scope.principal_id != PRINCIPAL
            || scope.participant_id != "alice"
            || scope.account_id != "account-alice"
        {
            return Err(ApiError::new(
                "PERMISSION_DENIED",
                "Synthetic exact record authority scope mismatch",
            ));
        }
        let now = OffsetDateTime::parse(&window.now, &Rfc3339).unwrap();
        let oldest = OffsetDateTime::parse(&window.oldest_acceptable, &Rfc3339).unwrap();
        assert_eq!((now - oldest).whole_seconds(), 300);
        assert_eq!(now.nanosecond(), 0);
        Ok(Box::new(Lease {
            scope: scope.clone(),
            expires: (now + time::Duration::minutes(1)).format(&Rfc3339).unwrap(),
            authority: self,
        }))
    }
}
struct SyntheticRetainedSource;
impl RetainedParticipantRecordSource for SyntheticRetainedSource {
    fn source_id(&self) -> &str {
        "synthetic-record-source"
    }
    fn load_retained_record(
        &mut self,
        request: &RetainParticipantRecordRequest,
        candidate: &Proposal,
    ) -> wholepact_engine::Result<SettlementRecord> {
        let hash = |byte: u8| format!("{byte:02x}").repeat(32);
        let mut approved = candidate.input().clone();
        approved.artifact_digest = Some(hash(1));
        approved.effects_commitment = Some(hash(2));
        let approved = Proposal::validate(approved)?;
        let own = OwnAuthorizationRecord {
            participant_id: request.participant_id.clone(),
            account_id: request.account_id.clone(),
            proposal_digest: approved.proposal_digest().into(),
            manifest_digest: approved.manifest_digest().into(),
            effects_commitment: hash(2),
            consent_record_ref: "PRIVATE-CONSENT-CANARY".into(),
            authorization_record_ref: "PRIVATE-AUTH-CANARY".into(),
            release_operation_id: Some("private-release-canary".into()),
            exposure: AuthorizationExposure::Released,
        };
        let transaction = ExactTransactionReference {
            network_profile_id: approved.manifest().agreement.network_profile_id.clone(),
            transaction_id: hash(3),
            transaction_bytes_digest: hash(4),
            effects_commitment: hash(2),
        };
        Ok(SettlementRecord::new(
            request.record_id.clone(),
            approved,
            own,
            transaction,
        )?)
    }
}
struct Fixture {
    dir: tempfile::TempDir,
    engine: Engine,
    authority: Arc<Authority>,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let engine = Engine::from_store(
            Store::create_encrypted(
                dir.path().join("records.sqlite"),
                &DatabaseKey::from_bytes([71; 32]),
            )
            .unwrap(),
        );
        let request: CandidateRequest = serde_json::from_str(include_str!(
            "../../wholepact-engine/tests/fixtures/candidate-request.json"
        ))
        .unwrap();
        let id = request.manifest.agreement.agreement_id.clone();
        engine
            .create(
                &access(),
                "record-http-create-agreement",
                request.manifest.agreement.clone(),
            )
            .unwrap();
        for (index, p) in request.manifest.participants.iter().enumerate() {
            engine
                .add_intent(
                    &access(),
                    &format!("record-http-intent-{index:04}"),
                    &id,
                    index as u64 + 1,
                    ParticipationIntent {
                        intent_id: format!("intent-{index}"),
                        agreement_id: id.clone(),
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
        let candidate = engine
            .create_candidate(&access(), "record-http-candidate-create", &id, 3, request)
            .unwrap();
        let authority = Arc::new(Authority {
            binding: engine.protected_record_store_binding().unwrap(),
            revoked: AtomicBool::new(false),
        });
        engine
            .retain_participant_record(
                &access(),
                "record-http-retain-original",
                &id,
                4,
                RetainParticipantRecordRequest {
                    record_id: "record-alice".into(),
                    candidate_id: candidate.agreement.candidates[0].candidate_id.clone(),
                    participant_id: "alice".into(),
                    account_id: "account-alice".into(),
                },
                ParticipantRecordRuntime {
                    profile_id: PROFILE,
                    authority: authority.as_ref(),
                    window: &window(),
                },
                &mut SyntheticRetainedSource,
            )
            .unwrap();
        Self {
            dir,
            engine,
            authority,
        }
    }
    fn runtime(&self) -> ProtectedRecordsRuntime {
        ProtectedRecordsRuntime::new(
            self.engine.clone(),
            PROFILE.into(),
            self.authority.clone(),
            300,
        )
        .unwrap()
    }
}
fn request(path: &str, token: Option<&str>) -> Request<Body> {
    let mut request = Request::builder()
        .uri(path)
        .header("Host", "127.0.0.1:4318")
        .header("Origin", "http://127.0.0.1:4319");
    if let Some(token) = token {
        request = request.header("Authorization", format!("Bearer {token}"));
    }
    request.body(Body::empty()).unwrap()
}
async fn json(response: axum::response::Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}
async fn session(app: &Router) -> String {
    json(
        app.clone()
            .oneshot(request("/v1/session", Some(BOOT)))
            .await
            .unwrap(),
    )
    .await["session_token"]
        .as_str()
        .unwrap()
        .into()
}
#[tokio::test]
async fn safe_record_status_requires_current_exact_authority_and_http_read_scope() {
    let fixture = Fixture::new();
    let app = application_with_records(
        fixture.runtime(),
        SecurityConfig::development_fixture(),
        4318,
        true,
    )
    .unwrap();
    assert_eq!(
        app.clone()
            .oneshot(request("/v1/records", None))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let token = session(&app).await;
    let response = app
        .clone()
        .oneshot(request("/v1/records", Some(&token)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let result = json(response).await;
    assert_eq!(result["status"], "available");
    assert_eq!(
        result["account_exposure"],
        "unknown_not_established_by_records"
    );
    assert_eq!(result["records"].as_array().unwrap().len(), 1);
    assert_eq!(result["records"][0]["confidence"], "no_observation");
    for private in [
        "PRIVATE-CONSENT-CANARY",
        "PRIVATE-AUTH-CANARY",
        "private-release-canary",
        "account-alice",
        "transaction_id",
        "maximum_net_debit",
        "disclosure_previews",
        "retirement_plans",
    ] {
        assert!(
            !result.to_string().contains(private),
            "private field: {private}"
        );
    }
    fixture.authority.revoked.store(true, Ordering::SeqCst);
    assert_eq!(
        app.clone()
            .oneshot(request("/v1/records", Some(&token)))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let mut config = SecurityConfig::development_fixture();
    config.clients[0].permissions.remove(&Permission::Read);
    let denied = application_with_records(fixture.runtime(), config, 4318, true).unwrap();
    let denied_token = session(&denied).await;
    assert_eq!(
        denied
            .oneshot(request("/v1/records", Some(&denied_token)))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let mut config = SecurityConfig::development_fixture();
    config.clients[0].client_id = "other-client".into();
    let other = application_with_records(fixture.runtime(), config, 4318, true).unwrap();
    let other_token = session(&other).await;
    let invisible = json(
        other
            .oneshot(request("/v1/records", Some(&other_token)))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(invisible["records"], serde_json::json!([]));
    assert_eq!(
        invisible["account_exposure"],
        "unknown_not_established_by_records"
    );
}
#[test]
fn record_runtime_rejects_plaintext_and_unbounded_clock_policy() {
    let fixture = Fixture::new();
    for age in [0, 301, u16::MAX] {
        assert!(
            ProtectedRecordsRuntime::new(
                fixture.engine.clone(),
                PROFILE.into(),
                fixture.authority.clone(),
                age
            )
            .is_err()
        );
    }
    assert!(
        ProtectedRecordsRuntime::new(
            Engine::in_memory().unwrap(),
            PROFILE.into(),
            fixture.authority.clone(),
            300
        )
        .is_err()
    );
    assert!(
        ProtectedRecordsRuntime::new(
            fixture.engine.clone(),
            "invalid/profile".into(),
            fixture.authority.clone(),
            300
        )
        .is_err()
    );
    let reopened = Engine::from_store(
        Store::open_encrypted(
            fixture.dir.path().join("records.sqlite"),
            &DatabaseKey::from_bytes([71; 32]),
        )
        .unwrap(),
    );
    let rebound =
        ProtectedRecordsRuntime::new(reopened, PROFILE.into(), fixture.authority.clone(), 300)
            .unwrap();
    assert_eq!(
        rebound.status(&access()).unwrap_err().code,
        "PERMISSION_DENIED"
    );
}
