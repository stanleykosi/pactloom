//! In-process routing only. No listener, installed signer or native approval.
use axum::{body::Body, http::Request};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;
use wholepact_engine::Engine;
use wholepact_service::{
    NativeRuntime, application_with_native_runtime,
    security::{Permission, SecurityConfig},
};
fn request(method: &str, path: &str, token: &str, csrf: Option<&str>, body: &str) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(path)
        .header("Host", "127.0.0.1:4318")
        .header("Authorization", format!("Bearer {token}"));
    if method == "POST" {
        b = b
            .header("Content-Type", "application/json")
            .header("Idempotency-Key", "synthetic-native-request-key")
            .header("If-Match", "\"1\"");
    }
    if let Some(csrf) = csrf {
        b = b.header("X-Wholepact-CSRF", csrf);
    }
    b.body(Body::from(body.to_owned())).unwrap()
}
async fn json(response: axum::response::Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}
async fn setup(
    enabled: bool,
    development: bool,
    read_only: bool,
) -> (tempfile::TempDir, axum::Router, Value) {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let engine = Engine::from_store(
        wholepact_store::Store::create_encrypted(
            directory.path().join("requests.sqlite"),
            &wholepact_storage_security::DatabaseKey::from_bytes([77; 32]),
        )
        .unwrap(),
    );
    let mut runtime = NativeRuntime::new(engine);
    if enabled {
        runtime = runtime.with_native_request_queue().unwrap();
    }
    let mut config = SecurityConfig::development_fixture();
    if read_only {
        config.clients[0].permissions = [Permission::Read].into();
    }
    let app = application_with_native_runtime(runtime, config, 4318, development).unwrap();
    let session = json(
        app.clone()
            .oneshot(request(
                "GET",
                "/v1/session",
                "wholepact-development-only-not-a-secret",
                None,
                "",
            ))
            .await
            .unwrap(),
    )
    .await;
    (directory, app, session)
}
#[tokio::test]
async fn generic_and_development_routes_do_not_advertise_native_queue() {
    for (enabled, development) in [(false, false), (true, true)] {
        let (_directory, app, session) = setup(enabled, development, false).await;
        let value = json(
            app.clone()
                .oneshot(request(
                    "GET",
                    "/v1/capabilities",
                    session["session_token"].as_str().unwrap(),
                    None,
                    "",
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            value["features"]["native_proof_reconciliation_requests"]["status"],
            "unavailable"
        );
    }
}
#[tokio::test]
async fn request_composition_never_advertises_financial_execution() {
    let (_directory, app, session) = setup(true, false, false).await;
    let value = json(
        app.clone()
            .oneshot(request(
                "GET",
                "/v1/capabilities",
                session["session_token"].as_str().unwrap(),
                None,
                "",
            ))
            .await
            .unwrap(),
    )
    .await;
    let feature = &value["features"]["native_proof_reconciliation_requests"];
    assert_eq!(feature["api_access"], "local_http_request_only");
    assert_eq!(feature["authorization_allowed"], false);
    assert_eq!(feature["proof_execution_allowed"], false);
}
#[tokio::test]
async fn read_only_principal_is_denied_before_request_parsing() {
    let (_directory, app, session) = setup(true, false, true).await;
    let value = json(
        app.oneshot(request(
            "POST",
            "/v1/agreements/example/native-proof-requests",
            session["session_token"].as_str().unwrap(),
            session["csrf_token"].as_str(),
            "{",
        ))
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(value["code"], "PERMISSION_DENIED");
}
#[tokio::test]
async fn no_http_start_or_approve_route_exists() {
    let (_directory, app, session) = setup(true, false, false).await;
    for action in [
        "start", "approve", "sign", "submit", "run", "recover", "complete",
    ] {
        let value = json(
            app.clone()
                .oneshot(request(
                    "POST",
                    &format!("/v1/agreements/example/native-proof-requests/request/{action}"),
                    session["session_token"].as_str().unwrap(),
                    session["csrf_token"].as_str(),
                    "{}",
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(value["code"], "UNSUPPORTED_CAPABILITY");
    }
}

#[tokio::test]
async fn proof_request_without_csrf_is_rejected_before_body_parsing() {
    let (_directory, app, session) = setup(true, false, false).await;
    let response = app
        .oneshot(request(
            "POST",
            "/v1/agreements/example/native-proof-requests",
            session["session_token"].as_str().unwrap(),
            None,
            "{",
        ))
        .await
        .unwrap();
    assert!(!response.status().is_success());
    let value = json(response).await;
    assert_eq!(value["code"], "CSRF_DENIED");
}
#[tokio::test]
async fn proof_request_selected_read_and_missing_receipt_fail_closed() {
    use std::os::unix::fs::PermissionsExt;
    use wholepact_core::{IntentStatus, ParticipationIntent};
    use wholepact_engine::{Access, CandidateRequest};
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let engine = Engine::from_store(
        wholepact_store::Store::create_encrypted(
            directory.path().join("selected.sqlite"),
            &wholepact_storage_security::DatabaseKey::from_bytes([78; 32]),
        )
        .unwrap(),
    );
    let input: CandidateRequest = serde_json::from_str(include_str!(
        "../../wholepact-engine/tests/fixtures/candidate-request.json"
    ))
    .unwrap();
    let id = input.manifest.agreement.agreement_id.clone();
    let access = Access {
        principal_id: "development-workspace".into(),
        agreement_ids: [id.clone()].into(),
        ..Access::default()
    };
    engine
        .create(
            &access,
            "http-fixture-create-key",
            input.manifest.agreement.clone(),
        )
        .unwrap();
    for (index, participant) in input.manifest.participants.iter().enumerate() {
        engine
            .add_intent(
                &access,
                &format!("http-fixture-intent-{index}"),
                &id,
                index as u64 + 1,
                ParticipationIntent {
                    intent_id: format!("intent-{index}"),
                    agreement_id: id.clone(),
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
    let revision = input.manifest.participants.len() as u64 + 1;
    let frozen = engine
        .create_candidate(&access, "http-fixture-candidate-key", &id, revision, input)
        .unwrap();
    let revision = frozen.agreement.revision;
    let candidate = frozen.agreement.candidates[0].candidate_id.clone();
    let runtime = NativeRuntime::new(engine)
        .with_native_request_queue()
        .unwrap();
    let mut config = SecurityConfig::development_fixture();
    config.clients[0].all_agreements = false;
    config.clients[0].include_owned_agreements = false;
    config.clients[0].agreement_ids = [id.clone()].into();
    config.clients[0].permissions.insert(Permission::Disclose);
    let app = application_with_native_runtime(runtime, config, 4318, false).unwrap();
    let session = json(
        app.clone()
            .oneshot(request(
                "GET",
                "/v1/session",
                "wholepact-development-only-not-a-secret",
                None,
                "",
            ))
            .await
            .unwrap(),
    )
    .await;
    let token = session["session_token"].as_str().unwrap();
    let csrf = session["csrf_token"].as_str();
    let post = |path: &str, key: &str, revision: u64, body: &str| {
        let mut request = request("POST", path, token, csrf, body);
        request
            .headers_mut()
            .insert("Idempotency-Key", key.parse().unwrap());
        request
            .headers_mut()
            .insert("If-Match", format!("\"{revision}\"").parse().unwrap());
        request
    };
    let path = format!("/v1/agreements/{id}/native-proof-requests");
    let inventory = json(
        app.clone()
            .oneshot(request("GET", &path, token, None, ""))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(inventory, serde_json::json!([]));
    let job = format!("proof-{}", "a".repeat(64));
    let body = serde_json::json!({"candidate_id":candidate,"job_id":job}).to_string();
    let missing = json(
        app.clone()
            .oneshot(post(&path, "missing-receipt-request", revision, &body))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(missing["code"], "MISSING_EVIDENCE");
    let bad =
        serde_json::json!({"candidate_id":candidate,"job_id":job,"approved":true}).to_string();
    let denied = json(
        app.clone()
            .oneshot(post(&path, "approval-flag-request", revision, &bad))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(denied["code"], "INVALID_TERMS");
    let outside = json(
        app.clone()
            .oneshot(request(
                "GET",
                "/v1/agreements/outside/native-proof-requests",
                token,
                None,
                "",
            ))
            .await
            .unwrap(),
    )
    .await;
    assert!(outside.get("code").is_some());
    let inventory = json(
        app.oneshot(request("GET", &path, token, None, ""))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(inventory, serde_json::json!([]));
}
