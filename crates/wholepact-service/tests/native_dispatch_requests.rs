//! Synthetic direct Router checks only. No listener, signer, extraction or network.
//! Positive dispatch source/replay semantics belong to the engine's modeled
//! observation fixture; these tests do not manufacture transaction authority.
use axum::{body::Body, http::Request};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use wholepact_core::{IntentStatus, ParticipationIntent};
use wholepact_engine::native_requests::{MAX_NATIVE_REQUESTS, NativeConstructionRequest};
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
            .header("Idempotency-Key", "synthetic-dispatch-request-key")
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
    let (directory, app, session, agreement, _) =
        setup_with_history(enabled, development, permissions, false).await;
    (directory, app, session, agreement)
}
async fn setup_with_history(
    enabled: bool,
    development: bool,
    permissions: &[Permission],
    fill_history: bool,
) -> (tempfile::TempDir, axum::Router, Value, String, u64) {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let engine = Engine::from_store(
        wholepact_store::Store::create_encrypted(
            directory.path().join("synthetic-dispatch.sqlite"),
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
            "synthetic-dispatch-agreement-key",
            input.manifest.agreement.clone(),
        )
        .unwrap();
    let mut revision = 1;
    if fill_history {
        // Public, inert construction metadata fills the current shared quota.
        // No constructor, proof, signer or transaction adapter is installed.
        for (index, participant) in input.manifest.participants.iter().enumerate() {
            let intent = engine
                .add_intent(
                    &access,
                    &format!("synthetic-dispatch-intent-{index}"),
                    &agreement,
                    revision,
                    ParticipationIntent {
                        intent_id: format!("intent-{index}"),
                        agreement_id: agreement.clone(),
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
            revision = intent.agreement.revision;
        }
        let frozen = engine
            .create_candidate(
                &access,
                "synthetic-dispatch-candidate-key",
                &agreement,
                revision,
                input,
            )
            .unwrap();
        revision = frozen.agreement.revision;
        let candidate_id = frozen.agreement.candidates[0].candidate_id.clone();
        for index in 0..MAX_NATIVE_REQUESTS {
            let queued = engine
                .queue_native_construction(
                    &access,
                    &format!("synthetic-shared-history-queue-{index}"),
                    &agreement,
                    revision,
                    NativeConstructionRequest {
                        candidate_id: candidate_id.clone(),
                    },
                )
                .unwrap();
            revision = queued.queued_revision;
            engine
                .withdraw_native_request(
                    &access,
                    &format!("synthetic-shared-history-withdraw-{index}"),
                    &agreement,
                    revision,
                    &queued.request_id,
                )
                .unwrap();
            revision += 1;
        }
    }
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
    (directory, app, session, agreement, revision)
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
        let feature = &capabilities["features"]["native_dispatch_requests"];
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
        let path = format!("/v1/agreements/{agreement}/native-dispatch-requests");
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
            for (method, suffix) in [("GET", "/request"), ("POST", "/request/withdraw")] {
                assert_eq!(
                    body(
                        app.clone()
                            .oneshot(request(method, &format!("{path}{suffix}"), &session, "{}"))
                            .await
                            .unwrap()
                    )
                    .await["code"],
                    "UNSUPPORTED_CAPABILITY"
                );
            }
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
            let path = format!("/v1/agreements/{agreement}/native-dispatch-requests{suffix}");
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
    let path = format!("/v1/agreements/{agreement}/native-dispatch-requests");
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
async fn metadata_request_rejects_override_fields_and_unknown_original_transaction() {
    let (_directory, app, session, agreement) = setup(true, false, PERMISSIONS).await;
    let path = format!("/v1/agreements/{agreement}/native-dispatch-requests");
    let original = json!({"transaction_request_id":"a".repeat(64)});
    for field in [
        "kind",
        "intake_request_id",
        "candidate_id",
        "manifest_digest",
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
        "observations",
        "source",
        "signed",
        "signatures_complete",
        "transaction_bytes",
        "raw_transaction",
        "backend_id",
        "operation_id",
        "submission_journal_identity",
        "endpoint",
        "network",
        "lease",
        "permission",
        "consent",
        "authorization_allowed",
        "financial_execution_allowed",
        "state",
        "attempt_revision",
        "outcome_status",
        "result_status",
        "principal_id",
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
    assert_eq!(
        body(
            app.clone()
                .oneshot(request("POST", &path, &session, &original.to_string()))
                .await
                .unwrap()
        )
        .await["code"],
        "NOT_FOUND"
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
async fn selected_scope_gates_inventory_item_queue_and_withdraw() {
    let (_directory, app, session, _agreement) = setup(true, false, PERMISSIONS).await;
    let outside = "/v1/agreements/outside/native-dispatch-requests";
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
        "execute",
        "status-refresh",
        "network",
        "network-refresh",
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
        let collection_action =
            format!("/v1/agreements/{agreement}/native-dispatch-requests/{action}");
        assert_eq!(
            body(
                app.clone()
                    .oneshot(request("POST", &collection_action, &session, "{}"))
                    .await
                    .unwrap()
            )
            .await["code"],
            "UNSUPPORTED_CAPABILITY",
            "collection action {action}"
        );
        for method in ["GET", "POST"] {
            let path =
                format!("/v1/agreements/{agreement}/native-dispatch-requests/request/{action}");
            assert_eq!(
                body(
                    app.clone()
                        .oneshot(request(method, &path, &session, "{}"))
                        .await
                        .unwrap()
                )
                .await["code"],
                "UNSUPPORTED_CAPABILITY",
                "{method} action {action}"
            );
        }
    }
}

#[tokio::test]
async fn inventory_and_item_require_read_permission() {
    let (_directory, app, session, agreement) =
        setup(true, false, &[Permission::Coordinate, Permission::Disclose]).await;
    for suffix in ["", "/request"] {
        let path = format!("/v1/agreements/{agreement}/native-dispatch-requests{suffix}");
        assert_eq!(
            body(
                app.clone()
                    .oneshot(request("GET", &path, &session, ""))
                    .await
                    .unwrap()
            )
            .await["code"],
            "PERMISSION_DENIED"
        );
    }
}

#[tokio::test]
async fn metadata_shape_and_withdrawal_body_are_strict() {
    let (_directory, app, session, agreement) = setup(true, false, PERMISSIONS).await;
    let path = format!("/v1/agreements/{agreement}/native-dispatch-requests");
    for supplied in [
        "{}",
        "[]",
        "null",
        "{\"transaction_request_id\":null}",
        "{\"transaction_request_id\":42}",
        "{\"transaction_request_id\":\"first\",\"transaction_request_id\":\"second\"}",
    ] {
        assert_eq!(
            body(
                app.clone()
                    .oneshot(request("POST", &path, &session, supplied))
                    .await
                    .unwrap()
            )
            .await["code"],
            "INVALID_TERMS"
        );
    }
    let withdrawal = format!("{path}/{}/withdraw", "b".repeat(64));
    for supplied in [
        "{\"approved\":true}",
        "{\"transaction_request_id\":\"replacement\"}",
        "[]",
    ] {
        assert_eq!(
            body(
                app.clone()
                    .oneshot(request("POST", &withdrawal, &session, supplied))
                    .await
                    .unwrap()
            )
            .await["code"],
            "INVALID_REQUEST"
        );
    }
    let mut missing_csrf = request("POST", &withdrawal, &session, "{");
    missing_csrf.headers_mut().remove("X-Wholepact-CSRF");
    assert_eq!(
        body(app.clone().oneshot(missing_csrf).await.unwrap()).await["code"],
        "CSRF_DENIED"
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
async fn queue_and_withdraw_require_unique_idempotency_and_revision_headers() {
    let (_directory, app, session, agreement) = setup(true, false, PERMISSIONS).await;
    let path = format!("/v1/agreements/{agreement}/native-dispatch-requests");
    let original = json!({"transaction_request_id":"a".repeat(64)}).to_string();
    for (path, input) in [
        (path.clone(), original),
        (format!("{path}/{}/withdraw", "b".repeat(64)), "{}".into()),
    ] {
        for header in ["Idempotency-Key", "If-Match"] {
            let mut missing = request("POST", &path, &session, &input);
            missing.headers_mut().remove(header);
            assert_eq!(
                body(app.clone().oneshot(missing).await.unwrap()).await["code"],
                "INVALID_REQUEST",
                "missing {header}"
            );
            let mut duplicate = request("POST", &path, &session, &input);
            let value = duplicate.headers().get(header).unwrap().clone();
            duplicate.headers_mut().append(header, value);
            assert_eq!(
                body(app.clone().oneshot(duplicate).await.unwrap()).await["code"],
                "INVALID_REQUEST",
                "duplicate {header}"
            );
        }
        for (header, value) in [
            ("Idempotency-Key", "short"),
            ("Idempotency-Key", "idempotency key with spaces"),
            ("If-Match", "1"),
            ("If-Match", "\"01\""),
            ("If-Match", "W/\"1\""),
            ("If-Match", "\"18446744073709551616\""),
        ] {
            let mut malformed = request("POST", &path, &session, &input);
            malformed
                .headers_mut()
                .insert(header, value.parse().unwrap());
            assert_eq!(
                body(app.clone().oneshot(malformed).await.unwrap()).await["code"],
                "INVALID_REQUEST",
                "malformed {header}"
            );
        }
        let mut stale = request("POST", &path, &session, &input);
        stale
            .headers_mut()
            .insert("If-Match", "\"0\"".parse().unwrap());
        assert_eq!(
            body(app.clone().oneshot(stale).await.unwrap()).await["code"],
            "REVISION_CONFLICT"
        );
    }
}

#[tokio::test]
async fn withdrawn_construction_history_uses_the_same_dispatch_request_quota() {
    let (_directory, app, session, agreement, revision) =
        setup_with_history(true, false, PERMISSIONS, true).await;
    let path = format!("/v1/agreements/{agreement}/native-dispatch-requests");
    let mut command = request(
        "POST",
        &path,
        &session,
        &json!({"transaction_request_id":"a".repeat(64)}).to_string(),
    );
    command
        .headers_mut()
        .insert("If-Match", format!("\"{revision}\"").parse().unwrap());
    assert_eq!(
        body(app.clone().oneshot(command).await.unwrap()).await["code"],
        "RESOURCE_EXHAUSTED"
    );
    assert_eq!(
        body(
            app.clone()
                .oneshot(request("GET", &path, &session, ""))
                .await
                .unwrap()
        )
        .await,
        json!([])
    );
    let preserved = body(
        app.oneshot(request(
            "GET",
            &format!("/v1/agreements/{agreement}/native-requests"),
            &session,
            "",
        ))
        .await
        .unwrap(),
    )
    .await;
    let history = preserved.as_array().unwrap();
    assert_eq!(history.len(), MAX_NATIVE_REQUESTS);
    assert!(history.iter().all(|entry| entry["state"] == "withdrawn"));
}
