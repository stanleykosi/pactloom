//! Synthetic, in-process HTTP boundaries only. No listener, wallet, provider,
//! signing credential, proof, or financial execution is involved.
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    response::Response,
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use wholepact_engine::Engine;
use wholepact_service::{
    application,
    security::{Permission, SecurityConfig},
};

const BOOT: &str = "wholepact-development-only-not-a-secret";
const ID: &str = "agreement-example-01";
const ROUTE: &str = "/v1/agreements/agreement-example-01/terms-revisions";
const CREATE_KEY: &str = "synthetic-terms-create-0001";

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../wholepact-core/tests/fixtures/agreement.json"
    ))
    .unwrap()
}

fn revised() -> Value {
    let mut draft = fixture();
    draft["revision"] = json!(2);
    draft["purpose"] = json!("Revised synthetic procurement. No real funds.");
    draft["recipients"][0]["address"] = json!("uregtestsyntheticrevisedaddressnotforfunds");
    draft["recipients"][0]["amount"] = json!("1100000000");
    draft["recipients"][0]["memo"] = json!("Synthetic revised instructions");
    draft["recipients"][0]["instruction_provenance"] =
        json!("Revised synthetic fixture. Not address- or ownership-verified.");
    draft["funding_policy"]["target"] = json!("1100000000");
    draft["fee_policy"] =
        json!({"kind":"sponsor","participant_id":"synthetic-sponsor","amount":"1000"});
    draft["coordination_deadline"] = json!("2027-01-01T00:00:00Z");
    draft["confirmation_policy"]["required_confirmations"] = json!(12);
    draft["extensions"] = json!([{
        "name":"synthetic-note","required":false,"schema_version":1,
        "value":{"note":"Nonbinding synthetic revision"}
    }]);
    draft
}

fn app(engine: Engine) -> Router {
    application(engine, SecurityConfig::development_fixture(), 4318, true).unwrap()
}

fn request(method: &str, path: &str, session: Option<&Value>, body: Body) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("Host", "127.0.0.1:4318")
        .header("Origin", "http://127.0.0.1:4319");
    if let Some(session) = session {
        builder = builder.header(
            "Authorization",
            format!("Bearer {}", session["session_token"].as_str().unwrap()),
        );
        if method == "POST" {
            builder = builder.header("X-Wholepact-CSRF", session["csrf_token"].as_str().unwrap());
        }
    }
    if method == "POST" {
        builder = builder.header("Content-Type", "application/json");
    }
    builder.body(body).unwrap()
}

async fn body(response: Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

async fn ok(response: Response) -> Value {
    let status = response.status();
    let value = body(response).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    value
}

async fn error(response: Response, status: StatusCode, code: &str) -> Value {
    let actual = response.status();
    assert!(response.headers().get("x-operation-id").is_none());
    let value = body(response).await;
    assert_eq!(actual, status, "{value}");
    assert_eq!(value["code"], code, "{value}");
    value
}

async fn session(app: &Router) -> Value {
    let mut req = request("GET", "/v1/session", None, Body::empty());
    req.headers_mut()
        .insert("Authorization", format!("Bearer {BOOT}").parse().unwrap());
    ok(app.clone().oneshot(req).await.unwrap()).await
}

fn raw_command(
    session: &Value,
    path: &str,
    payload: String,
    revision: Option<u64>,
    key: Option<&str>,
) -> Request<Body> {
    let mut req = request("POST", path, Some(session), Body::from(payload));
    if let Some(key) = key {
        req.headers_mut()
            .insert("Idempotency-Key", key.parse().unwrap());
    }
    if let Some(revision) = revision {
        req.headers_mut()
            .insert("If-Match", format!("\"{revision}\"").parse().unwrap());
    }
    req
}

async fn command(
    app: &Router,
    session: &Value,
    path: &str,
    payload: &Value,
    revision: Option<u64>,
    key: &str,
) -> Response {
    app.clone()
        .oneshot(raw_command(
            session,
            path,
            payload.to_string(),
            revision,
            Some(key),
        ))
        .await
        .unwrap()
}

async fn get(app: &Router, session: &Value, path: &str) -> Value {
    ok(app
        .clone()
        .oneshot(request("GET", path, Some(session), Body::empty()))
        .await
        .unwrap())
    .await
}

async fn create(app: &Router, session: &Value) -> Value {
    ok(command(app, session, "/v1/agreements", &fixture(), None, CREATE_KEY).await).await
}

fn assert_unknown_exposure(value: &Value) {
    assert_eq!(value["authorization_exposure"], "unknown");
    assert_eq!(value["chain_observation"], "unknown");
    assert_eq!(value["candidates"], json!([]));
}

fn assert_editability(value: &Value, allowed: bool) {
    assert_eq!(value["terms_editability"]["allowed"], allowed);
    assert!(
        !value["terms_editability"]["reason"]
            .as_str()
            .unwrap()
            .trim()
            .is_empty()
    );
}

#[tokio::test]
async fn terms_revision_reopens_and_replays_original_result_without_rewriting_history() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic-terms-revisions.sqlite");
    let service = app(Engine::open(&path).unwrap());
    let s = session(&service).await;
    let original = fixture();
    let created = create(&service, &s).await;
    assert_eq!(created["agreement"], original);
    assert!(created.get("terms_history").is_none());
    assert_editability(&created, true);
    assert_unknown_exposure(&created);

    let preview = ok(command(
        &service,
        &s,
        &format!("/v1/agreements/{ID}/proposals"),
        &json!({}),
        Some(1),
        "synthetic-terms-preview-0001",
    )
    .await)
    .await;
    let proposal_id = preview["proposals"][0]["proposal_id"].as_str().unwrap();
    let reviewed = ok(command(
        &service,
        &s,
        &format!("/v1/proposals/{proposal_id}/verify"),
        &json!({}),
        Some(2),
        "synthetic-terms-review-0001",
    )
    .await)
    .await;
    assert_eq!(reviewed["revision"], 3);
    assert_eq!(reviewed["agreement"]["revision"], 1);
    assert_editability(&reviewed, true);

    let second = revised();
    let first_revision = command(
        &service,
        &s,
        ROUTE,
        &second,
        Some(3),
        "synthetic-terms-revise-0001",
    )
    .await;
    assert_eq!(first_revision.status(), StatusCode::OK);
    assert_eq!(first_revision.headers()["x-idempotent-replay"], "false");
    let operation = first_revision.headers()["x-operation-id"].clone();
    let saved = body(first_revision).await;
    assert_eq!(saved["revision"], 4);
    assert_eq!(saved["agreement"], second);
    assert_eq!(saved["terms_history"], json!([original]));
    assert_eq!(saved["proposals"], reviewed["proposals"]);
    assert_eq!(
        saved["verification_reports"],
        reviewed["verification_reports"]
    );
    assert_eq!(saved["proposals"][0]["manifest"]["agreement"], fixture());
    assert_eq!(
        saved["verification_reports"][0]["review_summary"]["signable"],
        false
    );
    assert_eq!(saved["progress"], "gathering_intent");
    assert_editability(&saved, true);
    assert_unknown_exposure(&saved);

    let next_preview = ok(command(
        &service,
        &s,
        &format!("/v1/agreements/{ID}/proposals"),
        &json!({}),
        Some(4),
        "synthetic-terms-preview-0002",
    )
    .await)
    .await;
    assert_eq!(
        next_preview["proposals"][1]["manifest"]["agreement"],
        second
    );
    assert_eq!(next_preview["proposals"][0], saved["proposals"][0]);
    let mut third = second.clone();
    third["revision"] = json!(3);
    third["purpose"] = json!("Third synthetic terms; requires fresh review.");
    let latest = ok(command(
        &service,
        &s,
        ROUTE,
        &third,
        Some(5),
        "synthetic-terms-revise-0002",
    )
    .await)
    .await;
    assert_eq!(latest["revision"], 6);
    assert_eq!(latest["terms_history"], json!([fixture(), second]));
    assert_unknown_exposure(&latest);
    drop(service);

    let service = app(Engine::open(&path).unwrap());
    let fresh = session(&service).await;
    let current = get(&service, &fresh, &format!("/v1/agreements/{ID}")).await;
    assert_eq!(current, latest);
    assert_editability(&current, true);
    let replay = command(
        &service,
        &fresh,
        ROUTE,
        &revised(),
        Some(3),
        "synthetic-terms-revise-0001",
    )
    .await;
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(replay.headers()["x-idempotent-replay"], "true");
    assert_eq!(replay.headers()["x-operation-id"], operation);
    let replay = body(replay).await;
    assert_eq!(replay["revision"], 4);
    for field in [
        "agreement",
        "terms_history",
        "proposals",
        "verification_reports",
        "created_at",
        "updated_at",
    ] {
        assert_eq!(replay[field], saved[field], "replay changed {field}");
    }
    assert_unknown_exposure(&replay);
    let create_replay = command(
        &service,
        &fresh,
        "/v1/agreements",
        &fixture(),
        None,
        CREATE_KEY,
    )
    .await;
    assert_eq!(create_replay.headers()["x-idempotent-replay"], "true");
    let create_replay = ok(create_replay).await;
    assert_eq!(create_replay["revision"], 1);
    assert_eq!(create_replay["agreement"], fixture());
    assert!(create_replay.get("terms_history").is_none());
    assert_eq!(
        get(&service, &fresh, &format!("/v1/agreements/{ID}")).await,
        current
    );
    let events = get(&service, &fresh, "/v1/events?after=0&format=json").await;
    assert_eq!(events.as_array().unwrap().len(), 6);
    assert_eq!(
        events
            .as_array()
            .unwrap()
            .iter()
            .filter(|event| event["kind"] == "agreement_terms_revised")
            .count(),
        2
    );
}

#[tokio::test]
async fn terms_revision_requires_exact_cas_and_distinct_payload_idempotency() {
    let service = app(Engine::in_memory().unwrap());
    let s = session(&service).await;
    create(&service, &s).await;
    let next = revised();
    for (revision, key) in [(None, Some("synthetic-terms-missing-cas")), (Some(1), None)] {
        error(
            service
                .clone()
                .oneshot(raw_command(&s, ROUTE, next.to_string(), revision, key))
                .await
                .unwrap(),
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
        )
        .await;
    }
    for header in ["1", "\"01\"", "*", "\"18446744073709551616\""] {
        let mut req = raw_command(
            &s,
            ROUTE,
            next.to_string(),
            None,
            Some("synthetic-terms-invalid-cas"),
        );
        req.headers_mut()
            .insert("If-Match", header.parse().unwrap());
        error(
            service.clone().oneshot(req).await.unwrap(),
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
        )
        .await;
    }
    for terms_revision in [1, 3] {
        let mut invalid = next.clone();
        invalid["revision"] = json!(terms_revision);
        error(
            command(
                &service,
                &s,
                ROUTE,
                &invalid,
                Some(1),
                &format!("synthetic-terms-order-{terms_revision:04}"),
            )
            .await,
            StatusCode::CONFLICT,
            "REVISION_CONFLICT",
        )
        .await;
    }
    let mut unchanged = fixture();
    unchanged["revision"] = json!(2);
    error(
        command(
            &service,
            &s,
            ROUTE,
            &unchanged,
            Some(1),
            "synthetic-terms-no-change-01",
        )
        .await,
        StatusCode::BAD_REQUEST,
        "INVALID_TERMS",
    )
    .await;

    let accepted = ok(command(
        &service,
        &s,
        ROUTE,
        &next,
        Some(1),
        "synthetic-terms-idempotent-01",
    )
    .await)
    .await;
    for (payload, cas) in [
        (fixture(), 1),
        (next.clone(), 2),
        (
            {
                let mut other = next.clone();
                other["purpose"] = json!("Different synthetic body");
                other
            },
            1,
        ),
    ] {
        error(
            command(
                &service,
                &s,
                ROUTE,
                &payload,
                Some(cas),
                "synthetic-terms-idempotent-01",
            )
            .await,
            StatusCode::CONFLICT,
            "IDEMPOTENCY_CONFLICT",
        )
        .await;
    }
    let mut third = next.clone();
    third["revision"] = json!(3);
    third["purpose"] = json!("Stale synthetic client");
    error(
        command(
            &service,
            &s,
            ROUTE,
            &third,
            Some(1),
            "synthetic-terms-stale-cas-01",
        )
        .await,
        StatusCode::CONFLICT,
        "REVISION_CONFLICT",
    )
    .await;
    error(
        command(
            &service,
            &s,
            ROUTE,
            &next,
            Some(2),
            "synthetic-terms-stale-body-01",
        )
        .await,
        StatusCode::CONFLICT,
        "REVISION_CONFLICT",
    )
    .await;
    error(
        command(&service, &s, ROUTE, &next, Some(1), CREATE_KEY).await,
        StatusCode::CONFLICT,
        "IDEMPOTENCY_CONFLICT",
    )
    .await;
    assert_eq!(
        get(&service, &s, &format!("/v1/agreements/{ID}")).await,
        accepted
    );
    assert_eq!(
        get(&service, &s, "/v1/events?after=0&format=json")
            .await
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn terms_revision_requires_propose_creator_exact_scope_and_csrf() {
    let engine = Engine::in_memory().unwrap();
    let service = app(engine.clone());
    let s = session(&service).await;
    let created = create(&service, &s).await;
    for csrf in [None, Some("invalid-synthetic-csrf")] {
        let mut req = raw_command(
            &s,
            ROUTE,
            revised().to_string(),
            Some(1),
            Some("synthetic-terms-csrf-0001"),
        );
        req.headers_mut().remove("X-Wholepact-CSRF");
        if let Some(csrf) = csrf {
            req.headers_mut()
                .insert("X-Wholepact-CSRF", csrf.parse().unwrap());
        }
        error(
            service.clone().oneshot(req).await.unwrap(),
            StatusCode::FORBIDDEN,
            "CSRF_DENIED",
        )
        .await;
    }
    let mut anonymous = raw_command(
        &s,
        ROUTE,
        revised().to_string(),
        Some(1),
        Some("synthetic-terms-anonymous-01"),
    );
    anonymous.headers_mut().remove("Authorization");
    error(
        service.clone().oneshot(anonymous).await.unwrap(),
        StatusCode::UNAUTHORIZED,
        "AUTHENTICATION_REQUIRED",
    )
    .await;

    let mut config = SecurityConfig::development_fixture();
    config.clients[0].permissions = [Permission::Read].into();
    let readonly = application(engine.clone(), config, 4318, true).unwrap();
    let read_session = session(&readonly).await;
    error(
        command(
            &readonly,
            &read_session,
            ROUTE,
            &revised(),
            Some(1),
            "synthetic-terms-permission-01",
        )
        .await,
        StatusCode::FORBIDDEN,
        "PERMISSION_DENIED",
    )
    .await;

    let mut config = SecurityConfig::development_fixture();
    config.clients[0].client_id = "synthetic-other-proposer".into();
    config.clients[0].permissions = [Permission::Read, Permission::Propose].into();
    config.clients[0].all_agreements = false;
    config.clients[0].include_owned_agreements = false;
    config.clients[0].agreement_ids = [ID.into()].into();
    let other = application(engine.clone(), config, 4318, true).unwrap();
    let other_session = session(&other).await;
    error(
        command(
            &other,
            &other_session,
            ROUTE,
            &revised(),
            Some(1),
            "synthetic-terms-nonowner-01",
        )
        .await,
        StatusCode::FORBIDDEN,
        "PERMISSION_DENIED",
    )
    .await;

    let mut config = SecurityConfig::development_fixture();
    config.clients[0].all_agreements = false;
    config.clients[0].include_owned_agreements = false;
    config.clients[0].agreement_ids = ["different-synthetic-agreement".into()].into();
    let hidden = application(engine.clone(), config, 4318, true).unwrap();
    let hidden_session = session(&hidden).await;
    let denied = error(
        command(
            &hidden,
            &hidden_session,
            ROUTE,
            &revised(),
            Some(1),
            "synthetic-terms-hidden-0001",
        )
        .await,
        StatusCode::NOT_FOUND,
        "NOT_FOUND",
    )
    .await;
    assert!(
        !denied
            .to_string()
            .contains(fixture()["purpose"].as_str().unwrap())
    );
    assert_eq!(
        get(&service, &s, &format!("/v1/agreements/{ID}")).await,
        created
    );

    let mut config = SecurityConfig::development_fixture();
    config.clients[0].permissions = [Permission::Read, Permission::Propose].into();
    config.clients[0].all_agreements = false;
    config.clients[0].include_owned_agreements = false;
    config.clients[0].agreement_ids = [ID.into()].into();
    let exact = application(engine, config, 4318, true).unwrap();
    let exact_session = session(&exact).await;
    let accepted = ok(command(
        &exact,
        &exact_session,
        ROUTE,
        &revised(),
        Some(1),
        "synthetic-terms-exact-scope-01",
    )
    .await)
    .await;
    assert_eq!(accepted["agreement"], revised());
    error(
        command(
            &hidden,
            &hidden_session,
            ROUTE,
            &revised(),
            Some(1),
            "synthetic-terms-exact-scope-01",
        )
        .await,
        StatusCode::NOT_FOUND,
        "NOT_FOUND",
    )
    .await;
    assert_eq!(
        get(&exact, &exact_session, &format!("/v1/agreements/{ID}")).await,
        accepted
    );
}

#[tokio::test]
async fn terms_revision_rejects_unknown_duplicate_and_inexact_monetary_fields_atomically() {
    let service = app(Engine::in_memory().unwrap());
    let s = session(&service).await;
    let original = create(&service, &s).await;
    let next = revised();
    let mut invalids = Vec::new();
    for field in [
        "authorization_allowed",
        "terms_history",
        "terms_editability",
        "unknown_required_behavior",
    ] {
        let mut payload = next.clone();
        payload[field] = json!(true);
        invalids.push((field.to_owned(), payload.to_string(), "INVALID_TERMS"));
    }
    let mut nested = next.clone();
    nested["recipients"][0]["ownership_verified"] = json!(true);
    invalids.push((
        "unknown-recipient-field".into(),
        nested.to_string(),
        "INVALID_TERMS",
    ));
    invalids.push((
        "duplicate-revision".into(),
        format!("{{\"revision\":2,{}", &next.to_string()[1..]),
        "INVALID_TERMS",
    ));
    invalids.push((
        "duplicate-amount".into(),
        next.to_string().replacen(
            "\"amount\":\"1100000000\"",
            "\"amount\":\"1100000000\",\"amount\":\"1100000000\"",
            1,
        ),
        "INVALID_TERMS",
    ));
    for (label, amount) in [
        ("numeric", json!(1100000000_u64)),
        ("fractional-number", json!(1.5)),
        ("decimal-string", json!("1.5")),
        ("negative-string", json!("-1")),
        ("negative-number", json!(-1)),
        ("zero", json!("0")),
        ("leading-zero", json!("01100000000")),
        ("above-range", json!("2100000000000001")),
    ] {
        let mut payload = next.clone();
        payload["recipients"][0]["amount"] = amount.clone();
        payload["funding_policy"]["target"] = amount;
        invalids.push((label.into(), payload.to_string(), "INVALID_TERMS"));
    }
    let mut target_mismatch = next.clone();
    target_mismatch["funding_policy"]["target"] = json!("1100000001");
    invalids.push((
        "conservation-target".into(),
        target_mismatch.to_string(),
        "CONSERVATION_FAILURE",
    ));
    let mut recipient_mismatch = next.clone();
    recipient_mismatch["recipients"][0]["amount"] = json!("1099999999");
    invalids.push((
        "conservation-recipient".into(),
        recipient_mismatch.to_string(),
        "CONSERVATION_FAILURE",
    ));
    let mut incomplete = next.clone();
    incomplete.as_object_mut().unwrap().remove("funding_policy");
    invalids.push((
        "incomplete-draft".into(),
        incomplete.to_string(),
        "INVALID_TERMS",
    ));
    for (label, payload, code) in invalids {
        let req = raw_command(
            &s,
            ROUTE,
            payload,
            Some(1),
            Some(&format!("synthetic-invalid-{label}")),
        );
        error(
            service.clone().oneshot(req).await.unwrap(),
            StatusCode::BAD_REQUEST,
            code,
        )
        .await;
        assert_eq!(
            get(&service, &s, &format!("/v1/agreements/{ID}")).await,
            original,
            "invalid {label} mutated the agreement"
        );
    }
    assert_eq!(
        get(&service, &s, "/v1/events?after=0&format=json")
            .await
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let valid = ok(command(
        &service,
        &s,
        ROUTE,
        &next,
        Some(1),
        "synthetic-valid-after-invalid",
    )
    .await)
    .await;
    assert_eq!(valid["agreement"], next);
    assert_unknown_exposure(&valid);
}

#[tokio::test]
async fn terms_revision_preserves_agreement_obligation_organizer_network_privacy_and_schema() {
    let service = app(Engine::in_memory().unwrap());
    let s = session(&service).await;
    let original = create(&service, &s).await;
    for (field, replacement, code) in [
        (
            "agreement_id",
            json!("different-synthetic-agreement"),
            "INVALID_TERMS",
        ),
        (
            "obligation_id",
            json!("different-synthetic-obligation"),
            "INVALID_TERMS",
        ),
        (
            "organizer_identity",
            json!("different-synthetic-organizer"),
            "INVALID_TERMS",
        ),
        (
            "network_profile_id",
            json!("ironwood-testnet-nu7-candidate"),
            "INVALID_TERMS",
        ),
        (
            "privacy_profile",
            json!({"mode":"declared_operator","proving_operator":"synthetic-prover","dedicated_accounts_required":true}),
            "INVALID_TERMS",
        ),
        ("schema_version", json!(2), "UNSUPPORTED_VERSION"),
    ] {
        let mut payload = revised();
        payload[field] = replacement;
        error(
            command(
                &service,
                &s,
                ROUTE,
                &payload,
                Some(1),
                &format!("synthetic-immutable-{field}"),
            )
            .await,
            StatusCode::BAD_REQUEST,
            code,
        )
        .await;
        assert_eq!(
            get(&service, &s, &format!("/v1/agreements/{ID}")).await,
            original
        );
    }
    assert_eq!(
        get(&service, &s, "/v1/events?after=0&format=json")
            .await
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn terms_revision_stays_closed_after_intent_withdrawal_or_cancellation() {
    for cancelled in [false, true] {
        let service = app(Engine::in_memory().unwrap());
        let s = session(&service).await;
        create(&service, &s).await;
        let mut closed = if cancelled {
            ok(command(
                &service,
                &s,
                &format!("/v1/agreements/{ID}/cancellation-requests"),
                &json!({}),
                Some(1),
                "synthetic-terms-cancel-0001",
            )
            .await)
            .await
        } else {
            let intent = json!({
                "intent_id":"synthetic-intent","agreement_id":ID,
                "participant_id":"synthetic-participant","desired_contribution":"1000000000",
                "maximum_net_debit":"1000000000","fee_cap":"0","conditions":[],
                "valid_until":null,"status":"active"
            });
            ok(command(
                &service,
                &s,
                &format!("/v1/agreements/{ID}/intents"),
                &intent,
                Some(1),
                "synthetic-terms-intent-0001",
            )
            .await)
            .await
        };
        assert_editability(&closed, false);
        assert_unknown_exposure(&closed);
        error(
            command(
                &service,
                &s,
                ROUTE,
                &revised(),
                Some(2),
                "synthetic-terms-closed-0001",
            )
            .await,
            StatusCode::CONFLICT,
            "INVALID_TRANSITION",
        )
        .await;
        if !cancelled {
            closed = ok(command(
                &service,
                &s,
                &format!("/v1/agreements/{ID}/intents/synthetic-intent/withdraw"),
                &json!({}),
                Some(2),
                "synthetic-terms-withdraw-01",
            )
            .await)
            .await;
            assert_eq!(closed["intents"][0]["status"], "withdrawn");
            assert_editability(&closed, false);
            error(
                command(
                    &service,
                    &s,
                    ROUTE,
                    &revised(),
                    Some(3),
                    "synthetic-terms-closed-0002",
                )
                .await,
                StatusCode::CONFLICT,
                "INVALID_TRANSITION",
            )
            .await;
        }
        let current = get(&service, &s, &format!("/v1/agreements/{ID}")).await;
        assert_eq!(current, closed);
        assert_eq!(current["agreement"], fixture());
        assert!(current.get("terms_history").is_none());
        assert_eq!(current["cancellation_requested"], cancelled);
        assert_unknown_exposure(&current);
        assert_editability(&current, false);
        let events = get(&service, &s, "/v1/events?after=0&format=json").await;
        assert_eq!(
            events.as_array().unwrap().len(),
            if cancelled { 2 } else { 3 }
        );
        assert!(
            events
                .as_array()
                .unwrap()
                .iter()
                .all(|event| event["kind"] != "agreement_terms_revised")
        );
    }
}
