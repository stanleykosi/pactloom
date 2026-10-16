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
async fn native_inspection_is_request_only_and_disabled_without_protected_runtime() {
    for (enabled, development, expected) in [
        (false, false, "unavailable"),
        (true, true, "unavailable"),
        (true, false, "experimental"),
    ] {
        let (_dir, app, session) = setup(enabled, development, false).await;
        let value = json(
            app.oneshot(request(
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
        let f = &value["features"]["native_account_inspection_requests"];
        assert_eq!(f["status"], expected);
        assert_eq!(f["authorization_allowed"], false);
        assert_eq!(f["financial_execution_allowed"], false);
    }
}
#[tokio::test]
async fn native_inspection_requires_disclosure_scope_and_has_no_result_writer() {
    let (_dir, app, session) = setup(true, false, true).await;
    let value = json(
        app.oneshot(request(
            "POST",
            "/v1/agreements/example/native-account-inspection-requests",
            session["session_token"].as_str().unwrap(),
            session["csrf_token"].as_str(),
            "{",
        ))
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(value["code"], "PERMISSION_DENIED");
    let (_dir, app, session) = setup(true, false, false).await;
    for action in [
        "start", "approve", "result", "complete", "activate", "reset",
    ] {
        let path =
            format!("/v1/agreements/example/native-account-inspection-requests/original/{action}");
        let value = json(
            app.clone()
                .oneshot(request(
                    "POST",
                    &path,
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
