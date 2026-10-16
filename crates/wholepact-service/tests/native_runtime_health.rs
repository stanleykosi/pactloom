//! Synthetic in-process supervision only; no permission, observation or network effect.
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::Value;
use std::{sync::Arc, time::Duration};
use tokio::sync::watch;
use tower::ServiceExt;
use wholepact_engine::Engine;
use wholepact_service::{
    application, application_with_native_runtime,
    operator::{Operator, OperatorTask, TaskFuture, TaskKind},
    security::SecurityConfig,
    NativeRuntime,
};
struct PendingObservation;
impl OperatorTask for PendingObservation {
    fn kind(&self) -> TaskKind {
        TaskKind::ChainObservation
    }
    fn tick(&self) -> TaskFuture<'_> {
        Box::pin(std::future::pending())
    }
}
fn request(path: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .header("Host", "127.0.0.1:4318")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}
async fn value(response: axum::response::Response) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}
async fn session(app: &axum::Router) -> String {
    value(
        app.clone()
            .oneshot(request(
                "/v1/session",
                "wholepact-development-only-not-a-secret",
            ))
            .await
            .unwrap(),
    )
    .await["session_token"]
        .as_str()
        .unwrap()
        .into()
}
#[tokio::test]
async fn health_reflects_explicit_operator_lifetime_without_claiming_settlement() {
    let operator = Operator::new(
        vec![Arc::new(PendingObservation)],
        Duration::from_millis(100),
        Duration::from_secs(10),
    )
    .unwrap();
    let health = operator.health();
    let app = application_with_native_runtime(
        NativeRuntime::new(Engine::in_memory().unwrap()).with_operator_health(health.clone()),
        SecurityConfig::development_fixture(),
        4318,
        true,
    )
    .unwrap();
    let token = session(&app).await;
    let stopped = value(
        app.clone()
            .oneshot(request("/v1/health", &token))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(stopped["background_observation"], false);
    assert_eq!(stopped["operator_tasks"][0]["state"], "stopped");
    let (shutdown, receiver) = watch::channel(false);
    let running = tokio::spawn(operator.run(receiver));
    for _ in 0..100 {
        if health.snapshot().unwrap()[0].heartbeat_sequence > 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    let active = value(
        app.clone()
            .oneshot(request("/v1/health", &token))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(active["background_observation"], true);
    assert_eq!(active["operator_tasks"][0]["state"], "running");
    assert_eq!(active["settlement_verified"], false);
    assert_eq!(active["operator_tasks"][0].as_object().unwrap().len(), 5);
    let caps = value(
        app.clone()
            .oneshot(request("/v1/capabilities", &token))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(caps["runtime"]["background_observation"], true);
    let recovery = value(
        app.clone()
            .oneshot(request("/v1/recovery", &token))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(recovery["background_observation"], true);
    assert_eq!(recovery["observation_stale"], true);
    assert_eq!(recovery["new_authorization_allowed"], false);
    shutdown.send(true).unwrap();
    running.await.unwrap();
    let ended = value(app.oneshot(request("/v1/health", &token)).await.unwrap()).await;
    assert_eq!(ended["background_observation"], false);
}
#[tokio::test]
async fn ordinary_startup_has_no_operator_and_cannot_claim_background_observation() {
    let app = application(
        Engine::in_memory().unwrap(),
        SecurityConfig::development_fixture(),
        4318,
        true,
    )
    .unwrap();
    let token = session(&app).await;
    let health = value(app.oneshot(request("/v1/health", &token)).await.unwrap()).await;
    assert_eq!(health["background_observation"], false);
    assert_eq!(health["operator_status"], "not_configured");
    assert!(health["operator_tasks"].is_null());
}
