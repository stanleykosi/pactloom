use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;
use wholepact_engine::Engine;
use wholepact_service::{application, security::SecurityConfig};
const BOOT: &str = "wholepact-development-only-not-a-secret";
fn app() -> Router {
    application(
        Engine::in_memory().unwrap(),
        SecurityConfig::development_fixture(),
        4318,
        true,
    )
    .unwrap()
}
fn request(
    method: &str,
    path: &str,
    token: Option<&str>,
    csrf: Option<&str>,
    body: Body,
) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(path)
        .header("Host", "127.0.0.1:4318")
        .header("Origin", "http://127.0.0.1:4319");
    if let Some(t) = token {
        b = b.header("Authorization", format!("Bearer {t}"));
    }
    if let Some(c) = csrf {
        b = b.header("X-Wholepact-CSRF", c);
    }
    if method == "POST" {
        b = b.header("Content-Type", "application/json");
    }
    b.body(body).unwrap()
}
async fn json_body(response: axum::response::Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}
async fn session(app: &Router) -> Value {
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            "/v1/session",
            Some(BOOT),
            None,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    json_body(response).await
}

async fn command(
    app: &Router,
    session: &Value,
    path: &str,
    payload: &Value,
    revision: Option<u64>,
    key: &str,
) -> axum::response::Response {
    let mut command = request(
        "POST",
        path,
        session["session_token"].as_str(),
        session["csrf_token"].as_str(),
        Body::from(payload.to_string()),
    );
    command
        .headers_mut()
        .insert("Idempotency-Key", key.parse().unwrap());
    if let Some(revision) = revision {
        command
            .headers_mut()
            .insert("If-Match", format!("\"{revision}\"").parse().unwrap());
    }
    app.clone().oneshot(command).await.unwrap()
}

#[tokio::test]
async fn candidate_api_restarts_replays_and_rejects_privileged_claims() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic-candidates.sqlite");
    let app = application(
        Engine::open(&path).unwrap(),
        SecurityConfig::development_fixture(),
        4318,
        true,
    )
    .unwrap();
    let session = session(&app).await;
    let candidate: Value = serde_json::from_str(include_str!(
        "../../wholepact-engine/tests/fixtures/candidate-request.json"
    ))
    .unwrap();
    let draft = &candidate["manifest"]["agreement"];
    let agreement_id = draft["agreement_id"].as_str().unwrap();
    assert_eq!(
        command(
            &app,
            &session,
            "/v1/agreements",
            draft,
            None,
            "http-candidate-create-agreement"
        )
        .await
        .status(),
        StatusCode::OK
    );
    for (i, participant) in candidate["manifest"]["participants"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let intent = json!({"intent_id":format!("intent-{i}"),"agreement_id":agreement_id,"participant_id":participant["participant_id"],"desired_contribution":participant["contribution"],"maximum_net_debit":participant["maximum_net_debit"],"fee_cap":participant["fee_cap"],"conditions":[],"valid_until":null,"status":"active"});
        assert_eq!(
            command(
                &app,
                &session,
                &format!("/v1/agreements/{agreement_id}/intents"),
                &intent,
                Some(i as u64 + 1),
                &format!("http-candidate-intent-{i:04}")
            )
            .await
            .status(),
            StatusCode::OK
        );
    }
    let route = format!("/v1/agreements/{agreement_id}/candidates");
    let mut untrusted = candidate.clone();
    untrusted["economic_terms_verified"] = json!(true);
    assert_eq!(
        command(
            &app,
            &session,
            &route,
            &untrusted,
            Some(3),
            "http-candidate-untrusted-flag"
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    let response = command(
        &app,
        &session,
        &route,
        &candidate,
        Some(3),
        "http-candidate-freeze-command",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let operation = response.headers()["x-operation-id"]
        .to_str()
        .unwrap()
        .to_owned();
    let frozen = json_body(response).await;
    let id = frozen["candidates"][0]["candidate_id"].as_str().unwrap();
    let review_route = format!("/v1/candidates/{id}/verify");
    let response = command(
        &app,
        &session,
        &review_route,
        &json!({}),
        Some(4),
        "http-candidate-review-command",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let reviewed = json_body(response).await;
    assert_eq!(
        reviewed["candidates"][0]["reviews"][0]["economic_terms_verified"],
        false
    );
    assert_eq!(
        reviewed["candidates"][0]["reviews"][0]["authorization_allowed"],
        false
    );
    for action in [
        "construct",
        "proof-jobs",
        "export",
        "authorization-requests",
        "submit",
    ] {
        let response = command(
            &app,
            &session,
            &format!("/v1/candidates/{id}/{action}"),
            &json!({}),
            Some(5),
            &format!("http-blocked-{action}-0001"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }
    drop(app);
    let app = application(
        Engine::open(&path).unwrap(),
        SecurityConfig::development_fixture(),
        4318,
        true,
    )
    .unwrap();
    let fresh = self::session(&app).await;
    let replay = command(
        &app,
        &fresh,
        &route,
        &candidate,
        Some(3),
        "http-candidate-freeze-command",
    )
    .await;
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(replay.headers()["x-operation-id"], operation);
    assert_eq!(replay.headers()["x-idempotent-replay"], "true");
    assert_eq!(json_body(replay).await["revision"], 4);
    let replay = command(
        &app,
        &fresh,
        &review_route,
        &json!({}),
        Some(4),
        "http-candidate-review-command",
    )
    .await;
    assert_eq!(replay.headers()["x-idempotent-replay"], "true");
    let state = json_body(replay).await;
    assert_eq!(state["revision"], 5);
    assert_eq!(
        state["candidates"][0]["reviews"].as_array().unwrap().len(),
        1
    );
}

#[tokio::test]
async fn rejects_localhost_attacks_and_shares_safe_cross_origin_errors() {
    let app = app();
    let response = app
        .clone()
        .oneshot(request("GET", "/v1/agreements", None, None, Body::empty()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers()["access-control-allow-origin"],
        "http://127.0.0.1:4319"
    );
    let mut evil = request("GET", "/v1/session", Some(BOOT), None, Body::empty());
    evil.headers_mut()
        .insert("Origin", "https://evil.example".parse().unwrap());
    assert_eq!(
        app.clone().oneshot(evil).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let mut dns = request("GET", "/v1/session", Some(BOOT), None, Body::empty());
    dns.headers_mut()
        .insert("Host", "evil.example:4318".parse().unwrap());
    assert_eq!(
        app.clone().oneshot(dns).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.clone()
            .oneshot(request(
                "GET",
                "/v1/agreements",
                Some(BOOT),
                None,
                Body::empty()
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let s = session(&app).await;
    let token = s["session_token"].as_str().unwrap();
    assert_eq!(
        app.clone()
            .oneshot(request(
                "GET",
                "/v1/session",
                Some(token),
                None,
                Body::empty()
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let rejected = app
        .clone()
        .oneshot(request(
            "POST",
            "/v1/agreements",
            Some(token),
            None,
            Body::from("{}"),
        ))
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(rejected).await["code"], "CSRF_DENIED");
}

#[tokio::test]
async fn real_api_mutation_replay_preconditions_limits_and_logout() {
    let app = app();
    let s = session(&app).await;
    let token = s["session_token"].as_str().unwrap();
    let csrf = s["csrf_token"].as_str().unwrap();
    let draft = include_str!("../../wholepact-core/tests/fixtures/agreement.json");
    let create = || {
        let mut r = request(
            "POST",
            "/v1/agreements",
            Some(token),
            Some(csrf),
            Body::from(draft),
        );
        r.headers_mut()
            .insert("Idempotency-Key", "create-request-00001".parse().unwrap());
        r
    };
    let first = app.clone().oneshot(create()).await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let operation = first.headers()["x-operation-id"].clone();
    let agreement = json_body(first).await;
    assert_eq!(agreement["revision"], 1);
    let replay = app.clone().oneshot(create()).await.unwrap();
    assert_eq!(replay.headers()["x-operation-id"], operation);
    assert_eq!(replay.headers()["x-idempotent-replay"], "true");
    let mut propose = request(
        "POST",
        "/v1/agreements/agreement-example-01/proposals",
        Some(token),
        Some(csrf),
        Body::from("{}"),
    );
    propose
        .headers_mut()
        .insert("Idempotency-Key", "proposal-request-001".parse().unwrap());
    propose
        .headers_mut()
        .insert("If-Match", "\"1\"".parse().unwrap());
    let result = app.clone().oneshot(propose).await.unwrap();
    assert_eq!(result.status(), StatusCode::OK);
    let result = json_body(result).await;
    assert_eq!(result["revision"], 2);
    assert_eq!(result["proposals"][0]["status"], "terms_only_not_signable");
    let duplicate = app
        .clone()
        .oneshot(request(
            "POST",
            "/v1/agreements/validate",
            Some(token),
            Some(csrf),
            Body::from("{\"schema_version\":1,\"schema_version\":1}"),
        ))
        .await
        .unwrap();
    assert_eq!(duplicate.status(), StatusCode::BAD_REQUEST);
    let large = app
        .clone()
        .oneshot(request(
            "POST",
            "/v1/agreements/validate",
            Some(token),
            Some(csrf),
            Body::from(" ".repeat(262145)),
        ))
        .await
        .unwrap();
    assert_eq!(large.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let ended = app
        .clone()
        .oneshot(request(
            "POST",
            "/v1/session/end",
            Some(token),
            Some(csrf),
            Body::from("{}"),
        ))
        .await
        .unwrap();
    assert_eq!(ended.status(), StatusCode::OK);
    let expired = app
        .clone()
        .oneshot(request(
            "GET",
            "/v1/agreements",
            Some(token),
            None,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(expired.status(), StatusCode::UNAUTHORIZED);
    assert!(expired
        .headers()
        .contains_key("access-control-allow-origin"));
}

#[tokio::test]
async fn sequential_short_lived_clients_do_not_exhaust_sessions() {
    let app = app();
    for _ in 0..12 {
        let s = session(&app).await;
        let r = request(
            "POST",
            "/v1/session/end",
            s["session_token"].as_str(),
            s["csrf_token"].as_str(),
            Body::from("{}"),
        );
        assert_eq!(
            app.clone().oneshot(r).await.unwrap().status(),
            StatusCode::OK
        );
    }
}

#[tokio::test]
async fn approved_preflight_is_narrow_and_untrusted_required_fields_fail() {
    let app = app();
    let mut r = request("OPTIONS", "/v1/agreements", None, None, Body::empty());
    r.headers_mut()
        .insert("Access-Control-Request-Method", "POST".parse().unwrap());
    r.headers_mut().insert(
        "Access-Control-Request-Headers",
        "Authorization, Content-Type, X-Wholepact-CSRF"
            .parse()
            .unwrap(),
    );
    assert_eq!(
        app.clone().oneshot(r).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    let s = session(&app).await;
    let mut draft: Value = serde_json::from_str(include_str!(
        "../../wholepact-core/tests/fixtures/agreement.json"
    ))
    .unwrap();
    draft["unknown_required_behavior"] = json!(true);
    let r = request(
        "POST",
        "/v1/agreements/validate",
        s["session_token"].as_str(),
        s["csrf_token"].as_str(),
        Body::from(draft.to_string()),
    );
    assert_eq!(
        app.clone().oneshot(r).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn json_and_sse_events_expose_identical_rfc3339_timestamps() {
    let engine = Engine::in_memory().unwrap();
    let app = application(engine, SecurityConfig::development_fixture(), 4318, true).unwrap();
    let s = session(&app).await;
    let token = s["session_token"].as_str().unwrap();
    let csrf = s["csrf_token"].as_str().unwrap();
    let mut create = request(
        "POST",
        "/v1/agreements",
        Some(token),
        Some(csrf),
        Body::from(include_str!(
            "../../wholepact-core/tests/fixtures/agreement.json"
        )),
    );
    create
        .headers_mut()
        .insert("Idempotency-Key", "timestamp-create-0001".parse().unwrap());
    assert_eq!(
        app.clone().oneshot(create).await.unwrap().status(),
        StatusCode::OK
    );
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            "/v1/events?after=0&format=json",
            Some(token),
            None,
            Body::empty(),
        ))
        .await
        .unwrap();
    let events = json_body(response).await;
    let expected = &events[0];
    let timestamp = expected["occurred_at"]
        .as_str()
        .expect("public RFC3339 event timestamp");
    assert!(
        time::OffsetDateTime::parse(timestamp, &time::format_description::well_known::Rfc3339)
            .is_ok()
    );
    assert!(expected.get("occurred_at_ms").is_none());
    let operation_response = app
        .clone()
        .oneshot(request(
            "GET",
            &format!(
                "/v1/operations/{}",
                expected["operation_id"].as_str().unwrap()
            ),
            Some(token),
            None,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(operation_response.status(), StatusCode::OK);
    let operation = json_body(operation_response).await;
    // Store commits the operation and event at exactly the same millisecond.
    assert_eq!(operation["created_at"], expected["occurred_at"]);
    assert_eq!(operation["updated_at"], expected["occurred_at"]);
    assert!(operation.get("created_at_ms").is_none());
    assert!(operation.get("principal_id").is_none());
    assert_eq!(
        operation["result"]["agreement"]["agreement"]["agreement_id"],
        expected["aggregate_id"]
    );
    assert!(operation["result"].get("record").is_none());

    let response = app
        .oneshot(request(
            "GET",
            "/v1/events?after=0",
            Some(token),
            None,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    let frame = tokio::time::timeout(std::time::Duration::from_secs(2), body.frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let bytes = frame.into_data().unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    let data = text
        .lines()
        .find_map(|line| line.strip_prefix("data: "))
        .unwrap();
    let streamed: Value = serde_json::from_str(data).unwrap();
    assert_eq!(streamed, *expected);
    assert!(text.contains(&format!("id: {}", expected["sequence"].as_u64().unwrap())));
}

#[tokio::test]
async fn unavailable_financial_views_never_report_known_empty_exposure() {
    let app = app();
    let s = session(&app).await;
    for resource in ["accounts", "authorizations", "records"] {
        let response = app
            .clone()
            .oneshot(request(
                "GET",
                &format!("/v1/{resource}"),
                s["session_token"].as_str(),
                None,
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        let body = json_body(response).await;
        assert_eq!(body["code"], "UNSUPPORTED_CAPABILITY");
        assert!(!body.is_array());
    }
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            "/v1/capabilities",
            s["session_token"].as_str(),
            None,
            Body::empty(),
        ))
        .await
        .unwrap();
    let body = json_body(response).await;
    assert_eq!(
        body["features"]["local_agreements"]["api_access"],
        "local_http"
    );
    assert_eq!(
        body["features"]["local_proof_checkpoints"]["api_access"],
        "embedded_only"
    );
    let recovery = app
        .oneshot(request(
            "GET",
            "/v1/recovery",
            s["session_token"].as_str(),
            None,
            Body::empty(),
        ))
        .await
        .unwrap();
    let recovery = json_body(recovery).await;
    assert_eq!(recovery["new_authorization_allowed"], false);
    assert_eq!(recovery["background_observation"], false);
}

#[tokio::test]
async fn roster_and_comparison_routes_preserve_revision_idempotency_and_scope() {
    let engine = Engine::in_memory().unwrap();
    let app = application(
        engine.clone(),
        SecurityConfig::development_fixture(),
        4318,
        true,
    )
    .unwrap();
    let s = session(&app).await;
    let draft: Value = serde_json::from_str(include_str!(
        "../../wholepact-core/tests/fixtures/agreement.json"
    ))
    .unwrap();
    let id = draft["agreement_id"].as_str().unwrap();
    let created = command(
        &app,
        &s,
        "/v1/agreements",
        &draft,
        None,
        "planning-http-create-0001",
    )
    .await;
    assert_eq!(created.status(), StatusCode::OK);
    for (index, participant) in ["alice", "bob"].iter().enumerate() {
        let intent = json!({"intent_id":format!("intent-{participant}"),"agreement_id":id,"participant_id":participant,"desired_contribution":draft["funding_policy"]["target"],"maximum_net_debit":draft["funding_policy"]["target"],"fee_cap":"0","conditions":[],"valid_until":null,"status":"active"});
        assert_eq!(
            command(
                &app,
                &s,
                &format!("/v1/agreements/{id}/intents"),
                &intent,
                Some(index as u64 + 1),
                &format!("planning-http-intent-{index}")
            )
            .await
            .status(),
            StatusCode::OK
        );
    }
    let route = format!("/v1/agreements/{id}/roster-selection");
    let roster = json!({"selected_intent_ids":["intent-alice"]});
    let result = command(
        &app,
        &s,
        &route,
        &roster,
        Some(3),
        "planning-http-select-0001",
    )
    .await;
    assert_eq!(result.status(), StatusCode::OK);
    let operation = result.headers()["x-operation-id"].clone();
    let state = json_body(result).await;
    assert_eq!(state["roster_selected"], true);
    assert_eq!(state["intents"][0]["status"], "selected");
    assert_eq!(state["intents"][1]["status"], "waitlisted");
    assert_eq!(state["authorization_exposure"], "unknown");
    let replay = command(
        &app,
        &s,
        &route,
        &roster,
        Some(3),
        "planning-http-select-0001",
    )
    .await;
    assert_eq!(replay.headers()["x-operation-id"], operation);
    assert_eq!(replay.headers()["x-idempotent-replay"], "true");
    assert_eq!(
        command(
            &app,
            &s,
            &route,
            &roster,
            Some(3),
            "planning-http-stale-0001"
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    let mut privileged = roster.clone();
    privileged["authorization_allowed"] = json!(true);
    assert_eq!(
        command(
            &app,
            &s,
            &route,
            &privileged,
            Some(4),
            "planning-http-forged-0001"
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    let proposals = format!("/v1/agreements/{id}/proposals");
    let older = json_body(
        command(
            &app,
            &s,
            &proposals,
            &json!({}),
            Some(4),
            "planning-http-preview-01",
        )
        .await,
    )
    .await;
    let older_id = older["proposals"][0]["proposal_id"].as_str().unwrap();
    assert_eq!(
        command(
            &app,
            &s,
            &route,
            &json!({"selected_intent_ids":["intent-bob"]}),
            Some(5),
            "planning-http-select-0002"
        )
        .await
        .status(),
        StatusCode::OK
    );
    let newer = json_body(
        command(
            &app,
            &s,
            &proposals,
            &json!({}),
            Some(6),
            "planning-http-preview-02",
        )
        .await,
    )
    .await;
    let newer_id = newer["proposals"][1]["proposal_id"].as_str().unwrap();
    let comparison_route = format!("/v1/proposals/{newer_id}/compare/{older_id}");
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            &comparison_route,
            s["session_token"].as_str(),
            None,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let comparison = json_body(response).await;
    assert_eq!(comparison["material_change"], true);
    assert_eq!(comparison["renewed_review_required"], true);
    assert_eq!(comparison["signable"], false);
    assert_eq!(comparison["scope"], "nonbinding_terms_only");

    let mut config = SecurityConfig::development_fixture();
    config.clients[0].permissions = [wholepact_service::security::Permission::Read].into();
    config.clients[0].all_agreements = false;
    config.clients[0].client_id = "other-read-only-client".into();
    let narrow = application(engine, config, 4318, true).unwrap();
    let ns = session(&narrow).await;
    assert_eq!(
        command(
            &narrow,
            &ns,
            &route,
            &roster,
            Some(7),
            "planning-http-denied-0001"
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    let hidden = narrow
        .oneshot(request(
            "GET",
            &comparison_route,
            ns["session_token"].as_str(),
            None,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(hidden.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn sponsor_policy_routes_preserve_owner_versions_and_unverifiable_budget() {
    let engine = Engine::in_memory().unwrap();
    let app = application(
        engine.clone(),
        SecurityConfig::development_fixture(),
        4318,
        true,
    )
    .unwrap();
    let s = session(&app).await;
    let candidate: Value = serde_json::from_str(include_str!(
        "../../wholepact-engine/tests/fixtures/candidate-request.json"
    ))
    .unwrap();
    let draft = &candidate["manifest"]["agreement"];
    let id = draft["agreement_id"].as_str().unwrap();
    assert_eq!(
        command(
            &app,
            &s,
            "/v1/agreements",
            draft,
            None,
            "sponsor-http-create-agreement"
        )
        .await
        .status(),
        StatusCode::OK
    );
    for (index, participant) in candidate["manifest"]["participants"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let intent = json!({"intent_id":format!("intent-{index}"),"agreement_id":id,"participant_id":participant["participant_id"],"desired_contribution":participant["contribution"],"maximum_net_debit":participant["maximum_net_debit"],"fee_cap":participant["fee_cap"],"conditions":[],"valid_until":null,"status":"active"});
        assert_eq!(
            command(
                &app,
                &s,
                &format!("/v1/agreements/{id}/intents"),
                &intent,
                Some(index as u64 + 1),
                &format!("sponsor-http-intent-{index:04}")
            )
            .await
            .status(),
            StatusCode::OK
        );
    }
    assert_eq!(
        command(
            &app,
            &s,
            &format!("/v1/agreements/{id}/roster-selection"),
            &json!({"selected_intent_ids":["intent-0","intent-1"]}),
            Some(3),
            "sponsor-http-roster-01"
        )
        .await
        .status(),
        StatusCode::OK
    );
    let state = json_body(
        command(
            &app,
            &s,
            &format!("/v1/agreements/{id}/candidates"),
            &candidate,
            Some(4),
            "sponsor-http-candidate-01",
        )
        .await,
    )
    .await;
    let candidate_id = state["candidates"][0]["candidate_id"].as_str().unwrap();
    let participants = candidate["manifest"]["participants"].as_array().unwrap();
    let terms = json!({"schema_version":1,"network_profile_id":draft["network_profile_id"],"agreement_scope":[id],"sponsor":{"participant_id":participants[1]["participant_id"],"account_id":participants[1]["account_id"]},"eligible_contributors":[{"participant_id":participants[0]["participant_id"],"account_id":participants[0]["account_id"]}],"beneficiaries":[{"recipient_id":draft["recipients"][0]["recipient_id"],"address":draft["recipients"][0]["address"],"maximum_amount":draft["recipients"][0]["amount"]}],"rate_numerator":2,"rate_denominator":1,"maximum_match":"200000","minimum_qualifying_total":"0","fee_cap":"10000","maximum_net_debit":"210000","aggregate_budget":"500000","assurance":{"kind":"independently_verified"},"identity_requirements":[],"privacy_profile":draft["privacy_profile"],"expires_at":null});
    let route = format!("/v1/agreements/{id}/sponsor-policies");
    let create = json!({"policy_id":"sponsor-policy","terms":terms});
    let response = command(
        &app,
        &s,
        &route,
        &create,
        Some(5),
        "sponsor-http-policy-create",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let operation = response.headers()["x-operation-id"].clone();
    let saved = json_body(response).await;
    assert_eq!(saved["agreement_revision"], 6);
    assert_eq!(saved["policy"]["state"], "draft");
    assert_eq!(saved["policy"]["authorization_allowed"], false);
    let replay = command(
        &app,
        &s,
        &route,
        &create,
        Some(5),
        "sponsor-http-policy-create",
    )
    .await;
    assert_eq!(replay.headers()["x-operation-id"], operation);
    assert_eq!(replay.headers()["x-idempotent-replay"], "true");
    let preview_route = format!("{route}/sponsor-policy/preview");
    let preview = json_body(
        command(
            &app,
            &s,
            &preview_route,
            &json!({"candidate_id":candidate_id,"expected_policy_version":1}),
            None,
            "unused-readonly-preview-key",
        )
        .await,
    )
    .await;
    assert_eq!(preview["status"], "match_unverifiable");
    assert_eq!(preview["authorization_allowed"], false);
    assert_eq!(
        preview["formula"]["evaluation"]["calculated_match"],
        "200000"
    );
    for field in [
        "pending_authorization_exposure",
        "settled_debit",
        "remaining_budget",
    ] {
        assert!(preview["budget"][field].is_null());
    }
    let mut revised = create.clone();
    revised["expected_policy_version"] = json!(1);
    revised["terms"]["aggregate_budget"] = json!("600000");
    assert_eq!(
        command(
            &app,
            &s,
            &format!("{route}/sponsor-policy/versions"),
            &revised,
            Some(6),
            "sponsor-http-policy-update"
        )
        .await
        .status(),
        StatusCode::OK
    );
    let mismatch = command(
        &app,
        &s,
        &format!("{route}/different-policy/state"),
        &json!({"policy_id":"sponsor-policy","expected_policy_version":2,"state":"paused"}),
        Some(7),
        "sponsor-http-policy-mismatch",
    )
    .await;
    assert_eq!(mismatch.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        command(
            &app,
            &s,
            &format!("{route}/sponsor-policy/state"),
            &json!({"policy_id":"sponsor-policy","expected_policy_version":2,"state":"paused"}),
            Some(7),
            "sponsor-http-policy-pause"
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        command(
            &app,
            &s,
            &preview_route,
            &json!({"candidate_id":candidate_id,"expected_policy_version":2}),
            None,
            "unused-readonly-preview-02"
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    let mut config = SecurityConfig::development_fixture();
    config.clients[0].client_id = "other-policy-reader".into();
    let other = application(engine, config, 4318, true).unwrap();
    let other_session = session(&other).await;
    let invisible = other
        .oneshot(request(
            "GET",
            &format!("{route}/sponsor-policy"),
            other_session["session_token"].as_str(),
            None,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(invisible.status(), StatusCode::NOT_FOUND);
}
