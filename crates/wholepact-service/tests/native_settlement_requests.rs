//! Synthetic direct Router checks only. No listener, signer, extraction or network.
use axum::{body::Body, http::Request};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use wholepact_engine::{Access, CandidateRequest, Engine};
use wholepact_service::{
    NativeRuntime, application_with_native_runtime,
    security::{Permission, SecurityConfig},
};

fn request(method: &str, path: &str, session: &Value, body: &str) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("Host", "127.0.0.1:4318")
        .header(
            "Authorization",
            format!("Bearer {}", session["session_token"].as_str().unwrap()),
        );
    if method == "POST" {
        builder = builder
            .header("Content-Type", "application/json")
            .header("Idempotency-Key", "synthetic-settlement-request-key")
            .header("If-Match", "\"1\"")
            .header("X-Wholepact-CSRF", session["csrf_token"].as_str().unwrap());
    }
    builder.body(Body::from(body.to_owned())).unwrap()
}
async fn body(response: axum::response::Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}
async fn setup(
    enabled: bool,
    development: bool,
    permissions: &[Permission],
) -> (tempfile::TempDir, axum::Router, Value, String) {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let engine = Engine::from_store(
        wholepact_store::Store::create_encrypted(
            directory.path().join("synthetic-settlement.sqlite"),
            &wholepact_storage_security::DatabaseKey::from_bytes([79; 32]),
        )
        .unwrap(),
    );
    let input: CandidateRequest = serde_json::from_str(include_str!(
        "../../wholepact-engine/tests/fixtures/candidate-request.json"
    ))
    .unwrap();
    let agreement = input.manifest.agreement.agreement_id.clone();
    let access = Access {
        principal_id: "development-workspace".into(),
        agreement_ids: [agreement.clone(), "outside".into()].into(),
        ..Access::default()
    };
    let mut outside = input.manifest.agreement.clone();
    outside.agreement_id = "outside".into();
    outside.obligation_id = "outside-obligation".into();
    engine
        .create(&access, "synthetic-outside-agreement-key", outside)
        .unwrap();
    engine
        .create(
            &access,
            "synthetic-settlement-agreement-key",
            input.manifest.agreement,
        )
        .unwrap();
    let mut runtime = NativeRuntime::new(engine);
    if enabled {
        runtime = runtime.with_native_request_queue().unwrap();
    }
    let mut config = SecurityConfig::development_fixture();
    config.clients[0].all_agreements = false;
    config.clients[0].include_owned_agreements = false;
    config.clients[0].agreement_ids = [agreement.clone()].into();
    config.clients[0].permissions = permissions.iter().copied().collect();
    let app = application_with_native_runtime(runtime, config, 4318, development).unwrap();
    let session = body(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/session")
                    .header("Host", "127.0.0.1:4318")
                    .header(
                        "Authorization",
                        "Bearer wholepact-development-only-not-a-secret",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    (directory, app, session, agreement)
}
const PERMISSIONS: &[Permission] = &[
    Permission::Read,
    Permission::Coordinate,
    Permission::Disclose,
];

#[tokio::test]
async fn queue_feature_is_inert_and_disabled_for_generic_or_development_service() {
    for (enabled, development) in [(false, false), (true, true), (true, false)] {
        let (_directory, app, session, agreement) = setup(enabled, development, PERMISSIONS).await;
        let capabilities = body(
            app.clone()
                .oneshot(request("GET", "/v1/capabilities", &session, ""))
                .await
                .unwrap(),
        )
        .await;
        let feature = &capabilities["features"]["native_settlement_requests"];
        assert_eq!(feature["authorization_allowed"], false);
        assert_eq!(feature["financial_execution_allowed"], false);
        assert_eq!(feature["result_status"], "historical_metadata_only");
        let available = enabled && !development;
        assert_eq!(
            feature["api_access"],
            if available {
                "local_http_request_only"
            } else {
                "unavailable"
            }
        );
        let path = format!("/v1/agreements/{agreement}/native-settlement-requests");
        let inventory = body(
            app.clone()
                .oneshot(request("GET", &path, &session, ""))
                .await
                .unwrap(),
        )
        .await;
        if available {
            assert_eq!(inventory, json!([]));
        } else {
            assert_eq!(inventory["code"], "UNSUPPORTED_CAPABILITY");
            let command = body(
                app.clone()
                    .oneshot(request("POST", &path, &session, "{}"))
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(command["code"], "UNSUPPORTED_CAPABILITY");
        }
    }
}
#[tokio::test]
async fn both_coordination_and_disclosure_are_required_before_body_parsing() {
    for permissions in [
        &[Permission::Read][..],
        &[Permission::Read, Permission::Coordinate][..],
        &[Permission::Read, Permission::Disclose][..],
    ] {
        let (_directory, app, session, agreement) = setup(true, false, permissions).await;
        for suffix in ["".to_owned(), format!("/{}/withdraw", "b".repeat(64))] {
            let path = format!("/v1/agreements/{agreement}/native-settlement-requests{suffix}");
            let denied = body(
                app.clone()
                    .oneshot(request("POST", &path, &session, "{"))
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(denied["code"], "PERMISSION_DENIED");
        }
    }
}
#[tokio::test]
async fn csrf_precedes_metadata_parsing_and_get_cannot_mutate() {
    let (_directory, app, session, agreement) = setup(true, false, PERMISSIONS).await;
    let path = format!("/v1/agreements/{agreement}/native-settlement-requests");
    let mut command = request("POST", &path, &session, "{");
    command.headers_mut().remove("X-Wholepact-CSRF");
    assert_eq!(
        body(app.clone().oneshot(command).await.unwrap()).await["code"],
        "CSRF_DENIED"
    );
    let withdrawal = format!("{path}/{}/withdraw", "b".repeat(64));
    assert_eq!(
        body(
            app.clone()
                .oneshot(request("GET", &withdrawal, &session, ""))
                .await
                .unwrap()
        )
        .await["code"],
        "UNSUPPORTED_CAPABILITY"
    );
    assert_eq!(
        body(
            app.oneshot(request("GET", &path, &session, ""))
                .await
                .unwrap()
        )
        .await,
        json!([])
    );
}
#[tokio::test]
async fn metadata_request_rejects_override_fields_and_unknown_original_intake() {
    let (_directory, app, session, agreement) = setup(true, false, PERMISSIONS).await;
    let path = format!("/v1/agreements/{agreement}/native-settlement-requests");
    let original = json!({"intake_request_id":"a".repeat(64),"kind":"signature_reconcile"});
    for field in [
        "candidate_id",
        "job_id",
        "signature_retention_key",
        "result_id",
        "request_digest",
        "signed_candidate_digest",
        "checkpoint_id",
        "transaction_digest",
        "txid",
        "approved",
        "observation",
    ] {
        let mut supplied = original.clone();
        supplied[field] = json!("caller-supplied-override");
        let denied = body(
            app.clone()
                .oneshot(request("POST", &path, &session, &supplied.to_string()))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(denied["code"], "INVALID_TERMS", "field {field}");
    }
    let mut unknown_kind = original.clone();
    unknown_kind["kind"] = json!("transaction_dispatch");
    assert_eq!(
        body(
            app.clone()
                .oneshot(request("POST", &path, &session, &unknown_kind.to_string()))
                .await
                .unwrap()
        )
        .await["code"],
        "INVALID_TERMS"
    );
    for kind in ["signature_reconcile", "transaction_checkpoint"] {
        let mut missing = original.clone();
        missing["kind"] = json!(kind);
        assert_eq!(
            body(
                app.clone()
                    .oneshot(request("POST", &path, &session, &missing.to_string()))
                    .await
                    .unwrap()
            )
            .await["code"],
            "NOT_FOUND"
        );
    }
    assert_eq!(
        body(
            app.oneshot(request("GET", &path, &session, ""))
                .await
                .unwrap()
        )
        .await,
        json!([])
    );
}
#[tokio::test]
async fn selected_scope_gates_inventory_item_queue_and_withdraw() {
    let (_directory, app, session, _agreement) = setup(true, false, PERMISSIONS).await;
    let outside = "/v1/agreements/outside/native-settlement-requests";
    for (method, suffix, input) in [
        ("GET", "", ""),
        ("GET", "/request", ""),
        ("POST", "", "{"),
        ("POST", "/request/withdraw", "{"),
    ] {
        let denied = body(
            app.clone()
                .oneshot(request(
                    method,
                    &format!("{outside}{suffix}"),
                    &session,
                    input,
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(denied["code"], "NOT_FOUND");
    }
}
#[tokio::test]
async fn no_execution_inspection_or_result_publication_endpoint_exists() {
    let (_directory, app, session, agreement) = setup(true, false, PERMISSIONS).await;
    for action in [
        "start",
        "approve",
        "sign",
        "submit",
        "run",
        "recover",
        "complete",
        "inspect",
        "reconcile",
        "extract",
        "broadcast",
        "dispatch",
        "record-result",
        "reset",
        "retry",
    ] {
        let path =
            format!("/v1/agreements/{agreement}/native-settlement-requests/request/{action}");
        assert_eq!(
            body(
                app.clone()
                    .oneshot(request("POST", &path, &session, "{}"))
                    .await
                    .unwrap()
            )
            .await["code"],
            "UNSUPPORTED_CAPABILITY",
            "action {action}"
        );
    }
}
