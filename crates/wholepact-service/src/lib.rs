//! Versioned, authenticated loopback API. This binary never exposes a signer.
#![forbid(unsafe_code)]
pub mod operator;
#[cfg(feature = "operator-chain")]
pub mod operator_chain;
pub mod protected_records;
#[cfg(feature = "protected-transport")]
pub mod protected_transport;
pub mod security;

use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    middleware,
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::any,
};
use security::{Permission, Principal, Security, SecurityConfig};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::sync::Semaphore;
use wholepact_engine::sponsor_policies::{
    SponsorPolicyMutation, SponsorPolicyStateRequest, UpdateSponsorPolicyRequest,
};
use wholepact_engine::{Access, ApiError, Engine, Mutation};

pub const MAX_BODY_BYTES: usize = 262_144;
#[derive(Clone)]
pub struct App {
    engine: Engine,
    security: Arc<Security>,
    workers: Arc<Semaphore>,
    streams: Arc<Semaphore>,
    development_fixture: bool,
    native_request_queue: bool,
    records: Option<Arc<protected_records::ProtectedRecordsRuntime>>,
    operator_health: Option<operator::Health>,
    #[cfg(feature = "protected-transport")]
    transport: Option<Arc<std::sync::Mutex<protected_transport::ProtectedTransportRuntime>>>,
}

/// Native-only composition. Installing an existing controller does not create
/// its permissions or start any worker. Protected components must share one open store.
pub struct NativeRuntime {
    engine: Engine,
    native_request_queue: bool,
    records: Option<Arc<protected_records::ProtectedRecordsRuntime>>,
    operator_health: Option<operator::Health>,
    #[cfg(feature = "protected-transport")]
    transport: Option<Arc<std::sync::Mutex<protected_transport::ProtectedTransportRuntime>>>,
}
impl NativeRuntime {
    pub fn new(engine: Engine) -> Self {
        Self {
            engine,
            native_request_queue: false,
            records: None,
            operator_health: None,
            #[cfg(feature = "protected-transport")]
            transport: None,
        }
    }
    /// Installs inert request/status metadata only. The native host must offer
    /// its real foreground consumer separately; this never enables construction.
    pub fn with_native_request_queue(mut self) -> Result<Self, String> {
        self.engine
            .protected_record_store_binding()
            .map_err(|error| error.message)?;
        self.native_request_queue = true;
        Ok(self)
    }
    fn require_same_store(&self, other: &Engine) -> Result<(), String> {
        if self
            .engine
            .protected_record_store_binding()
            .map_err(|e| e.message)?
            != other
                .protected_record_store_binding()
                .map_err(|e| e.message)?
        {
            return Err("Protected runtime controllers refer to different open stores".into());
        }
        Ok(())
    }
    pub fn with_records(
        mut self,
        runtime: protected_records::ProtectedRecordsRuntime,
    ) -> Result<Self, String> {
        self.require_same_store(runtime.engine())?;
        self.records = Some(Arc::new(runtime));
        Ok(self)
    }
    #[cfg(feature = "protected-transport")]
    pub fn with_transport(
        mut self,
        runtime: protected_transport::ProtectedTransportRuntime,
    ) -> Result<Self, String> {
        self.require_same_store(runtime.engine())?;
        self.transport = Some(Arc::new(std::sync::Mutex::new(runtime)));
        Ok(self)
    }
    #[cfg(feature = "protected-transport")]
    pub fn with_shared_transport(
        mut self,
        runtime: Arc<std::sync::Mutex<protected_transport::ProtectedTransportRuntime>>,
    ) -> Result<Self, String> {
        {
            let guard = runtime
                .lock()
                .map_err(|_| "Protected transport runtime is poisoned".to_owned())?;
            self.require_same_store(guard.engine())?;
        }
        self.transport = Some(runtime);
        Ok(self)
    }
    pub fn with_operator_health(mut self, health: operator::Health) -> Self {
        self.operator_health = Some(health);
        self
    }
}
pub fn application_with_native_runtime(
    runtime: NativeRuntime,
    config: SecurityConfig,
    port: u16,
    development_fixture: bool,
) -> Result<Router, String> {
    let security = Security::new(config, port)?;
    let state = App {
        engine: runtime.engine,
        security: security.clone(),
        workers: Arc::new(Semaphore::new(16)),
        streams: Arc::new(Semaphore::new(8)),
        development_fixture,
        native_request_queue: runtime.native_request_queue && !development_fixture,
        records: runtime.records,
        operator_health: runtime.operator_health,
        #[cfg(feature = "protected-transport")]
        transport: runtime.transport,
    };
    Ok(Router::new()
        .fallback(any(dispatch))
        .with_state(state)
        .layer(middleware::from_fn_with_state(security, security::boundary)))
}
pub fn application(
    engine: Engine,
    config: SecurityConfig,
    port: u16,
    development_fixture: bool,
) -> Result<Router, String> {
    application_with_native_runtime(
        NativeRuntime::new(engine),
        config,
        port,
        development_fixture,
    )
}
/// Compatibility wrapper: the ordinary executable never constructs this runtime.
#[cfg(feature = "protected-transport")]
pub fn application_with_transport(
    runtime: protected_transport::ProtectedTransportRuntime,
    config: SecurityConfig,
    port: u16,
    development_fixture: bool,
) -> Result<Router, String> {
    let native = NativeRuntime::new(runtime.engine().clone()).with_transport(runtime)?;
    application_with_native_runtime(native, config, port, development_fixture)
}
pub fn application_with_records(
    runtime: protected_records::ProtectedRecordsRuntime,
    config: SecurityConfig,
    port: u16,
    development_fixture: bool,
) -> Result<Router, String> {
    let native = NativeRuntime::new(runtime.engine().clone()).with_records(runtime)?;
    application_with_native_runtime(native, config, port, development_fixture)
}
#[cfg(feature = "protected-transport")]
pub fn application_with_transport_and_records(
    transport: protected_transport::ProtectedTransportRuntime,
    records: protected_records::ProtectedRecordsRuntime,
    config: SecurityConfig,
    port: u16,
    development_fixture: bool,
) -> Result<Router, String> {
    let native = NativeRuntime::new(transport.engine().clone())
        .with_transport(transport)?
        .with_records(records)?;
    application_with_native_runtime(native, config, port, development_fixture)
}
fn operator_snapshot(app: &App) -> Result<Option<Vec<operator::TaskHealth>>, ApiError> {
    app.operator_health
        .as_ref()
        .map(|health| {
            health
                .snapshot()
                .map_err(|message| ApiError::new("STORAGE_UNAVAILABLE", message))
        })
        .transpose()
}
fn observation_active(tasks: Option<&[operator::TaskHealth]>) -> bool {
    tasks.is_some_and(|tasks| {
        tasks.iter().any(|task| {
            task.kind == operator::TaskKind::ChainObservation
                && matches!(
                    task.state,
                    operator::State::Waiting | operator::State::Running
                )
        })
    })
}
#[cfg(feature = "protected-transport")]
fn protected_runtime(
    app: &App,
) -> Result<std::sync::MutexGuard<'_, protected_transport::ProtectedTransportRuntime>, ApiError> {
    app.transport.as_ref().ok_or_else(|| ApiError::new("UNSUPPORTED_CAPABILITY", "No protected local transport runtime is configured; native staging, pinned peers and current consent are required"))?
        .lock().map_err(|_| ApiError::new("RECOVERY_REQUIRED", "Protected transport controller was interrupted; reconcile its original journals"))
}
fn transport_configured(app: &App) -> bool {
    #[cfg(feature = "protected-transport")]
    {
        app.transport.is_some()
    }
    #[cfg(not(feature = "protected-transport"))]
    {
        let _ = app;
        false
    }
}

fn access(p: &Principal) -> Access {
    Access {
        include_owned_agreements: p.include_owned_agreements,
        principal_id: p.client_id.clone(),
        agreement_ids: p.agreement_ids.clone(),
        all_agreements: p.all_agreements,
    }
}
fn error_response(error: ApiError) -> Response {
    let status = match error.code.as_str() {
        "AUTHENTICATION_REQUIRED" => StatusCode::UNAUTHORIZED,
        "PERMISSION_DENIED" | "CSRF_DENIED" => StatusCode::FORBIDDEN,
        "NOT_FOUND" => StatusCode::NOT_FOUND,
        "REVISION_CONFLICT"
        | "IDEMPOTENCY_CONFLICT"
        | "INVALID_TRANSITION"
        | "NATIVE_ATTEMPT_ALREADY_CLOSED" => StatusCode::CONFLICT,
        "UNSUPPORTED_CAPABILITY" => StatusCode::NOT_IMPLEMENTED,
        "RESOURCE_EXHAUSTED" => StatusCode::TOO_MANY_REQUESTS,
        "STORAGE_UNAVAILABLE" => StatusCode::SERVICE_UNAVAILABLE,
        "INTERNAL_ERROR" => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    };
    (status, Json(error)).into_response()
}
fn permission(p: &Principal, needed: Permission) -> Result<(), ApiError> {
    if p.permits(needed) {
        Ok(())
    } else {
        Err(ApiError::new(
            "PERMISSION_DENIED",
            "This application has not been granted the required capability",
        ))
    }
}
fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    wholepact_core::parse_typed_json(body).map_err(ApiError::from)
}
fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, ApiError> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| ApiError::new("INVALID_REQUEST", &format!("{name} is required")))?;
    if values.next().is_some() {
        return Err(ApiError::new("INVALID_REQUEST", "Duplicate command header"));
    }
    Ok(value)
}
fn key(headers: &HeaderMap) -> Result<&str, ApiError> {
    let k = header_value(headers, "idempotency-key")?;
    if k.len() < 16 || k.len() > 128 || !k.bytes().all(|b| (33..=126).contains(&b)) {
        return Err(ApiError::new(
            "INVALID_REQUEST",
            "Idempotency-Key must contain 16 to 128 visible ASCII bytes",
        ));
    }
    Ok(k)
}
fn revision(headers: &HeaderMap) -> Result<u64, ApiError> {
    let value = header_value(headers, "if-match")?;
    let number = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .ok_or_else(|| {
            ApiError::new(
                "INVALID_REQUEST",
                "If-Match must be a quoted aggregate revision",
            )
        })?;
    if number.is_empty()
        || !number.bytes().all(|b| b.is_ascii_digit())
        || number.len() > 1 && number.starts_with('0')
    {
        return Err(ApiError::new(
            "INVALID_REQUEST",
            "Invalid revision precondition",
        ));
    }
    number
        .parse()
        .map_err(|_| ApiError::new("INVALID_REQUEST", "Revision overflow"))
}
fn empty(body: &[u8]) -> Result<(), ApiError> {
    let value: Value = parse(body)?;
    if value != json!({}) {
        return Err(ApiError::new(
            "INVALID_REQUEST",
            "This command accepts an empty JSON object only",
        ));
    }
    Ok(())
}
fn mutated(m: Mutation) -> Response {
    let mut response = Json(m.agreement).into_response();
    if let Ok(value) = HeaderValue::from_str(&m.operation_id) {
        response.headers_mut().insert("x-operation-id", value);
    }
    if let Ok(value) = HeaderValue::from_str(&m.event_sequence.to_string()) {
        response.headers_mut().insert("x-event-sequence", value);
    }
    response.headers_mut().insert(
        "x-idempotent-replay",
        HeaderValue::from_static(if m.replayed { "true" } else { "false" }),
    );
    response
}

fn sponsor_mutated(m: SponsorPolicyMutation) -> Response {
    let operation = m.operation_id.clone();
    let sequence = m.event_sequence;
    let replayed = m.replayed;
    let mut response = Json(m).into_response();
    if let Ok(value) = HeaderValue::from_str(&operation) {
        response.headers_mut().insert("x-operation-id", value);
    }
    if let Ok(value) = HeaderValue::from_str(&sequence.to_string()) {
        response.headers_mut().insert("x-event-sequence", value);
    }
    response.headers_mut().insert(
        "x-idempotent-replay",
        HeaderValue::from_static(if replayed { "true" } else { "false" }),
    );
    response
}

async fn dispatch(State(app): State<App>, request: Request) -> Response {
    let Some(principal) = request.extensions().get::<Principal>().cloned() else {
        return error_response(ApiError::new(
            "AUTHENTICATION_REQUIRED",
            "Authentication is required",
        ));
    };
    if request.method() == Method::GET && request.uri().path() == "/v1/session" {
        return match app.security.issue_session(&principal) {
            Ok(session) => Json(session).into_response(),
            Err(message) => error_response(ApiError::new("RESOURCE_EXHAUSTED", message)),
        };
    }
    if request.uri().path().len() > 512 {
        return error_response(ApiError::new(
            "INVALID_REQUEST",
            "Path exceeds the supported limit",
        ));
    }
    let (parts, body) = request.into_parts();
    let query = parts.uri.query().unwrap_or("");
    if parts.method == Method::GET
        && parts.uri.path() == "/v1/events"
        && !query.split('&').any(|p| p == "format=json")
    {
        if let Err(error) = permission(&principal, Permission::Read) {
            return error_response(error);
        }
        let cursor = match event_cursor(query, &parts.headers) {
            Ok(n) => n,
            Err(e) => return error_response(e),
        };
        return stream_events(app, principal, cursor).await;
    }
    let Some(client_permit) = app.security.request_permit(&principal.client_id) else {
        return error_response(ApiError::new(
            "RESOURCE_EXHAUSTED",
            "This client has too many concurrent requests",
        ));
    };
    let Ok(permit) = app.workers.clone().try_acquire_owned() else {
        return error_response(ApiError::new(
            "RESOURCE_EXHAUSTED",
            "Local request queue is full",
        ));
    };
    let body =
        match tokio::time::timeout(Duration::from_secs(10), to_bytes(body, MAX_BODY_BYTES)).await {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(_)) => {
                return security::rejection(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "RESOURCE_EXHAUSTED",
                    "Request body exceeds 256 KiB",
                );
            }
            Err(_) => {
                return security::rejection(
                    StatusCode::REQUEST_TIMEOUT,
                    "RESOURCE_EXHAUSTED",
                    "Request body timed out",
                );
            }
        };
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let _client_permit = client_permit;
        let mut response = match dispatch_sync(
            &app,
            &principal,
            parts.method,
            parts.uri.path(),
            parts.uri.query().unwrap_or(""),
            &parts.headers,
            &body,
        ) {
            Ok(response) => response,
            Err(error) => error_response(error),
        };
        let request_id = parts
            .headers
            .get("x-request-id")
            .filter(|v| v.as_bytes().len() <= 128)
            .cloned();
        if let Some(id) = request_id {
            response.headers_mut().insert("x-request-id", id);
        }
        response
    })
    .await;
    result.unwrap_or_else(|_| {
        error_response(ApiError::new(
            "INTERNAL_ERROR",
            "Local request interrupted; inspect its idempotency key before retrying",
        ))
    })
}

fn dispatch_sync(
    app: &App,
    principal: &Principal,
    method: Method,
    path: &str,
    query: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, ApiError> {
    let caller = access(principal);
    let segments: Vec<_> = path.trim_matches('/').split('/').collect();
    if !segments.iter().all(|s| {
        s.len() <= 128
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
    }) {
        return Err(ApiError::new("INVALID_REQUEST", "Invalid resource path"));
    }
    if method == Method::GET {
        permission(principal, Permission::Read)?;
        let value = match segments.as_slice() {
            ["v1", "health"] => {
                let tasks = operator_snapshot(app)?;
                json!({"schema_version":1,"status":"ok","storage":"available","storage_protection":app.engine.storage_protection(),"signer":"not_connected","chain":"unknown_not_established_by_operator_health","background_observation":observation_active(tasks.as_deref()),"operator_status":if tasks.is_some() {"injected"} else {"not_configured"},"operator_tasks":tasks,"settlement_verified":false,"development_fixture":app.development_fixture})
            }
            ["v1", "capabilities"] => {
                let mut report = app.engine.capabilities();
                let tasks = operator_snapshot(app)?;
                report["runtime"]["background_observation"] =
                    json!(observation_active(tasks.as_deref()));
                report["runtime"]["operator_configured"] = json!(tasks.is_some());
                if let Some(features) = report["features"].as_object_mut() {
                    for (name, feature) in features {
                        feature["api_access"] = json!(match name.as_str() {
                            "local_agreements" | "candidate_terms" | "sponsor_policies" =>
                                "local_http",
                            "local_candidate_construction"
                            | "local_proof_checkpoints"
                            | "protected_wallet_checkpoint" => "embedded_only",
                            _ => "unavailable",
                        });
                    }
                }
                report["features"]["protected_transport_runtime"] = json!({"status":if transport_configured(app) {"experimental"} else {"unavailable"},"reason_code":if transport_configured(app) {"INJECTED_LOCAL_GATE_AND_NATIVE_STAGING_REQUIRED"} else {"PROTECTED_LOCAL_RUNTIME_NOT_CONFIGURED"},"api_access":if transport_configured(app) {"local_http"} else {"unavailable"},"operations":if transport_configured(app) {vec!["list_staged_summaries","read_staged_preview","import_enrolled_nonbinding_message","list_received_invitations","review_received_invitation"]} else {vec![]},"authorization_allowed":false});
                report["features"]["native_construction_requests"] = json!({"status":if app.native_request_queue {"experimental"} else {"unavailable"},"api_access":if app.native_request_queue {"local_http_request_only"} else {"unavailable"},"authorization_allowed":false,"financial_execution_allowed":false,"native_review":"stop_and_drain_service_then_native_construction_request","result_status":"unknown_until_separate_exact_artifact_inspection"});
                report["features"]["native_proof_reconciliation_requests"] = json!({"status":if app.native_request_queue {"experimental"} else {"unavailable"},"api_access":if app.native_request_queue {"local_http_request_only"} else {"unavailable"},"authorization_allowed":false,"proof_execution_allowed":false,"native_review":"stop_and_drain_service_then_native_proof_reconcile_request","result_status":"cached_metadata_only"});
                report["features"]["native_proof_execution_requests"] = json!({"status":if app.native_request_queue {"experimental"} else {"unavailable"},"api_access":if app.native_request_queue {"local_http_request_only"} else {"unavailable"},"authorization_allowed":false,"proof_execution_allowed":false,"native_review":"stop_and_drain_service_then_native_proof_execute_request","result_status":"durable_execution_metadata_only"});
                report["features"]["native_artifact_handoff_requests"] = json!({"status":if app.native_request_queue {"experimental"} else {"unavailable"},"api_access":if app.native_request_queue {"local_http_request_only"} else {"unavailable"},"authorization_allowed":false,"signature_execution_allowed":false,"native_review":"stop_and_drain_service_then_native_artifact_handoff_request","result_status":"attempt_metadata_only"});
                report["features"]["native_settlement_requests"] = json!({"status":if app.native_request_queue {"experimental"} else {"unavailable"},"api_access":if app.native_request_queue {"local_http_request_only"} else {"unavailable"},"authorization_allowed":false,"financial_execution_allowed":false,"native_review":"stop_and_drain_service_then_native_settlement_request","native_inspection":"stop_and_drain_service_then_native_settlement_inspect","result_status":"historical_metadata_only"});
                report["features"]["native_dispatch_requests"] = json!({"status":if app.native_request_queue {"experimental"} else {"unavailable"},"api_access":if app.native_request_queue {"local_http_request_only"} else {"unavailable"},"authorization_allowed":false,"financial_execution_allowed":false,"native_review":"stop_and_drain_service_then_native_dispatch_request","native_inspection":"stop_and_drain_service_then_native_dispatch_status","result_status":"historical_metadata_only"});
                report["features"]["native_account_inspection_requests"] = json!({"status":if app.native_request_queue {"experimental"} else {"unavailable"},"api_access":if app.native_request_queue {"local_http_request_only"} else {"unavailable"},"authorization_allowed":false,"financial_execution_allowed":false,"native_review":"stop_and_drain_service_then_native_account_inspection_request","native_inspection":"native_account_inspection_status","result_status":"historical_local_journal_metadata_account_totals_unknown"});
                report["features"]["native_reconciliation_requests"] = json!({"status":if app.native_request_queue {"experimental"} else {"unavailable"},"api_access":if app.native_request_queue {"local_http_request_only"} else {"unavailable"},"authorization_allowed":false,"financial_execution_allowed":false,"chain_observation_allowed":false,"independent_resolution_allowed":false,"native_review":"stop_and_drain_service_then_native_reconciliation_request","native_inspection":"stop_and_drain_service_then_native_reconciliation_status","result_status":"historical_metadata_only"});
                report["features"]["participant_record_status"] = json!({"status":if app.records.is_some() {"experimental"} else {"unavailable"},"reason_code":if app.records.is_some() {"INJECTED_PARTICIPANT_RECORD_AUTHORITY"} else {"PARTICIPANT_RECORD_RUNTIME_NOT_CONNECTED"},"api_access":if app.records.is_some() {"local_http"} else {"unavailable"},"authorization_allowed":false,"account_exposure":"unknown_not_established_by_records"});
                report
            }
            #[cfg(feature = "protected-transport")]
            ["v1", "invitations"] => {
                serde_json::to_value(protected_runtime(app)?.list_received_invitations(&caller)?)
                    .map_err(|_| ApiError::new("INTERNAL_ERROR", "Serialization failed"))?
            }
            #[cfg(feature = "protected-transport")]
            ["v1", "invitations", handle] => {
                serde_json::to_value(protected_runtime(app)?.received_invitation(&caller, handle)?)
                    .map_err(|_| ApiError::new("INTERNAL_ERROR", "Serialization failed"))?
            }
            ["v1", "agreements", id, "native-account-inspection-requests"] if app.native_request_queue => {
                serde_json::to_value(app.engine.native_account_inspection_requests(&caller, id)?).map_err(|_| ApiError::new("INTERNAL_ERROR", "Serialization failed"))?
            }
            ["v1", "agreements", id, "native-account-inspection-requests", request] if app.native_request_queue => {
                serde_json::to_value(app.engine.native_account_inspection_request(&caller, id, request)?).map_err(|_| ApiError::new("INTERNAL_ERROR", "Serialization failed"))?
            }
            ["v1", "agreements", id, "native-reconciliation-requests"]
                if app.native_request_queue =>
            {
                serde_json::to_value(app.engine.native_reconciliation_requests(&caller, id)?)
                    .map_err(|_| ApiError::new("INTERNAL_ERROR", "Serialization failed"))?
            }
            [
                "v1",
                "agreements",
                id,
                "native-reconciliation-requests",
                request,
            ] if app.native_request_queue => serde_json::to_value(
                app.engine
                    .native_reconciliation_request(&caller, id, request)?,
            )
            .map_err(|_| ApiError::new("INTERNAL_ERROR", "Serialization failed"))?,
            ["v1", "agreements", id, "native-dispatch-requests"] if app.native_request_queue => {
                serde_json::to_value(app.engine.native_dispatch_requests(&caller, id)?)
                    .map_err(|_| ApiError::new("INTERNAL_ERROR", "Serialization failed"))?
            }
            ["v1", "agreements", id, "native-dispatch-requests", request]
                if app.native_request_queue =>
            {
                serde_json::to_value(app.engine.native_dispatch_request(&caller, id, request)?)
                    .map_err(|_| ApiError::new("INTERNAL_ERROR", "Serialization failed"))?
            }
            ["v1", "agreements", id, "native-settlement-requests"] if app.native_request_queue => {
                serde_json::to_value(app.engine.native_settlement_requests(&caller, id)?)
                    .map_err(|_| ApiError::new("INTERNAL_ERROR", "Serialization failed"))?
            }
            [
                "v1",
                "agreements",
                id,
                "native-settlement-requests",
                request,
            ] if app.native_request_queue => {
                serde_json::to_value(app.engine.native_settlement_request(&caller, id, request)?)
                    .map_err(|_| ApiError::new("INTERNAL_ERROR", "Serialization failed"))?
            }
            ["v1", "agreements", id, "native-artifact-handoff-requests"]
                if app.native_request_queue =>
            {
                serde_json::to_value(app.engine.native_artifact_handoff_requests(&caller, id)?)
                    .map_err(|_| ApiError::new("INTERNAL_ERROR", "Serialization failed"))?
            }
            [
                "v1",
                "agreements",
                id,
                "native-artifact-handoff-requests",
                request,
            ] if app.native_request_queue => serde_json::to_value(
                app.engine
                    .native_artifact_handoff_request(&caller, id, request)?,
            )
            .map_err(|_| ApiError::new("INTERNAL_ERROR", "Serialization failed"))?,
            ["v1", "agreements", id, "native-proof-execution-requests"]
                if app.native_request_queue =>
            {
                serde_json::to_value(app.engine.native_proof_execution_requests(&caller, id)?)
                    .map_err(|_| ApiError::new("INTERNAL_ERROR", "Serialization failed"))?
            }
            [
                "v1",
                "agreements",
                id,
                "native-proof-execution-requests",
                request,
            ] if app.native_request_queue => serde_json::to_value(
                app.engine
                    .native_proof_execution_request(&caller, id, request)?,
            )
            .map_err(|_| ApiError::new("INTERNAL_ERROR", "Serialization failed"))?,
            ["v1", "agreements", id, "native-proof-requests"] if app.native_request_queue => {
                serde_json::to_value(app.engine.native_proof_requests(&caller, id)?)
                    .map_err(|_| ApiError::new("INTERNAL_ERROR", "Serialization failed"))?
            }
            ["v1", "agreements", id, "native-proof-requests", request]
                if app.native_request_queue =>
            {
                serde_json::to_value(app.engine.native_proof_request(&caller, id, request)?)
                    .map_err(|_| ApiError::new("INTERNAL_ERROR", "Serialization failed"))?
            }
            ["v1", "agreements", id, "native-requests"] if app.native_request_queue => {
                serde_json::to_value(app.engine.native_requests(&caller, id)?)
                    .map_err(|_| ApiError::new("INTERNAL_ERROR", "Serialization failed"))?
            }
            ["v1", "agreements", id, "native-requests", request] if app.native_request_queue => {
                serde_json::to_value(app.engine.native_request(&caller, id, request)?)
                    .map_err(|_| ApiError::new("INTERNAL_ERROR", "Serialization failed"))?
            }
            ["v1", "agreements"] => serde_json::to_value(app.engine.list(&caller)?)
                .map_err(|_| ApiError::new("INTERNAL_ERROR", "Serialization failed"))?,
            #[cfg(feature = "protected-transport")]
            ["v1", "agreements", id, "transport"] => {
                serde_json::to_value(protected_runtime(app)?.list(&caller, id)?)
                    .map_err(|_| ApiError::new("INTERNAL_ERROR", "Serialization failed"))?
            }
            #[cfg(feature = "protected-transport")]
            ["v1", "agreements", id, "transport", handle] => {
                serde_json::to_value(protected_runtime(app)?.preview(&caller, id, handle)?)
                    .map_err(|_| ApiError::new("INTERNAL_ERROR", "Serialization failed"))?
            }
            ["v1", "agreements", id, "sponsor-policies"] => {
                serde_json::to_value(app.engine.list_sponsor_policies(&caller, id)?)
                    .map_err(|_| ApiError::new("INTERNAL_ERROR", "Serialization failed"))?
            }
            ["v1", "agreements", id, "sponsor-policies", policy] => {
                serde_json::to_value(app.engine.sponsor_policy(&caller, id, policy)?)
                    .map_err(|_| ApiError::new("INTERNAL_ERROR", "Serialization failed"))?
            }
            ["v1", "agreements", id] => serde_json::to_value(app.engine.get(&caller, id)?)
                .map_err(|_| ApiError::new("INTERNAL_ERROR", "Serialization failed"))?,
            ["v1", "proposals", newer, "compare", older] => {
                serde_json::to_value(app.engine.compare_proposals(&caller, older, newer)?)
                    .map_err(|_| ApiError::new("INTERNAL_ERROR", "Serialization failed"))?
            }
            ["v1", "proposals", id] => serde_json::to_value(app.engine.proposal(&caller, id)?.1)
                .map_err(|_| ApiError::new("INTERNAL_ERROR", "Serialization failed"))?,
            ["v1", "candidates", newer, "compare", older] => {
                serde_json::to_value(app.engine.compare_candidates(&caller, older, newer)?)
                    .map_err(|_| ApiError::new("INTERNAL_ERROR", "Serialization failed"))?
            }
            ["v1", "candidates", id] => serde_json::to_value(app.engine.candidate(&caller, id)?.1)
                .map_err(|_| ApiError::new("INTERNAL_ERROR", "Serialization failed"))?,
            ["v1", "candidates", id, "proof-jobs"] => {
                let (_, candidate) = app.engine.candidate(&caller, id)?;
                json!({"schema_version":1,"candidate_id":candidate.candidate_id,"observation_source":"cached_coordination_journal","current_worker_liveness_known":false,"authorization_allowed":false,"distribution_allowed":false,"jobs":candidate.proof_jobs})
            }
            ["v1", "recovery"] => {
                let mut report = app.engine.recovery(&caller)?;
                report["background_observation"] =
                    json!(observation_active(operator_snapshot(app)?.as_deref()));
                report
            }
            ["v1", "events"] => app
                .engine
                .events(&caller, event_cursor(query, headers)?, 100)?,
            ["v1", "operations", id] => app.engine.operation(&caller, id)?,
            ["v1", "records"] if app.records.is_some() => serde_json::to_value(
                app.records
                    .as_ref()
                    .expect("checked runtime")
                    .status(&caller)?,
            )
            .map_err(|_| ApiError::new("INTERNAL_ERROR", "Serialization failed"))?,
            ["v1", resource @ ("accounts" | "authorizations" | "records")] => {
                return Err(ApiError::new(
                    "UNSUPPORTED_CAPABILITY",
                    match *resource {
                        "accounts" => {
                            "No qualified wallet account adapter is connected. Account availability and balances are unknown."
                        }
                        "authorizations" => {
                            "No authoritative signer exposure journal is connected. Absence of local metadata does not establish zero outstanding authorization."
                        }
                        _ => {
                            "No qualified settlement observation adapter is connected. Settlement evidence is unavailable."
                        }
                    },
                ));
            }
            _ => {
                return Err(ApiError::new(
                    "UNSUPPORTED_CAPABILITY",
                    "This endpoint is not implemented in the local development service",
                ));
            }
        };
        return Ok(Json(value).into_response());
    }
    if method != Method::POST {
        return Err(ApiError::new(
            "UNSUPPORTED_CAPABILITY",
            "Only explicit POST commands are supported",
        ));
    }
    match segments.as_slice() {
        ["v1", "agreements", id, "native-account-inspection-requests"] if app.native_request_queue => {
            permission(principal, Permission::Coordinate)?; permission(principal, Permission::Disclose)?;
            app.engine.get(&caller, id)?;
            Ok(Json(app.engine.queue_native_account_inspection(&caller, key(headers)?, id, revision(headers)?, parse(body)?)?).into_response())
        }
        ["v1", "agreements", id, "native-account-inspection-requests", request, "withdraw"] if app.native_request_queue => {
            permission(principal, Permission::Coordinate)?; permission(principal, Permission::Disclose)?;
            app.engine.get(&caller, id)?; empty(body)?;
            Ok(Json(app.engine.withdraw_native_account_inspection(&caller, key(headers)?, id, revision(headers)?, request)?).into_response())
        }
        ["v1", "agreements", id, "native-reconciliation-requests"] if app.native_request_queue => {
            permission(principal, Permission::Coordinate)?;
            permission(principal, Permission::Disclose)?;
            app.engine.get(&caller, id)?;
            Ok(Json(app.engine.queue_native_reconciliation(
                &caller,
                key(headers)?,
                id,
                revision(headers)?,
                parse(body)?,
            )?)
            .into_response())
        }
        [
            "v1",
            "agreements",
            id,
            "native-reconciliation-requests",
            request,
            "withdraw",
        ] if app.native_request_queue => {
            permission(principal, Permission::Coordinate)?;
            permission(principal, Permission::Disclose)?;
            app.engine.get(&caller, id)?;
            empty(body)?;
            Ok(Json(app.engine.withdraw_native_reconciliation_request(
                &caller,
                key(headers)?,
                id,
                revision(headers)?,
                request,
            )?)
            .into_response())
        }
        ["v1", "agreements", id, "native-dispatch-requests"] if app.native_request_queue => {
            permission(principal, Permission::Coordinate)?;
            permission(principal, Permission::Disclose)?;
            app.engine.get(&caller, id)?;
            Ok(Json(app.engine.queue_native_dispatch(
                &caller,
                key(headers)?,
                id,
                revision(headers)?,
                parse(body)?,
            )?)
            .into_response())
        }
        [
            "v1",
            "agreements",
            id,
            "native-dispatch-requests",
            request,
            "withdraw",
        ] if app.native_request_queue => {
            permission(principal, Permission::Coordinate)?;
            permission(principal, Permission::Disclose)?;
            app.engine.get(&caller, id)?;
            empty(body)?;
            Ok(Json(app.engine.withdraw_native_dispatch_request(
                &caller,
                key(headers)?,
                id,
                revision(headers)?,
                request,
            )?)
            .into_response())
        }
        ["v1", "agreements", id, "native-settlement-requests"] if app.native_request_queue => {
            permission(principal, Permission::Coordinate)?;
            permission(principal, Permission::Disclose)?;
            app.engine.get(&caller, id)?;
            Ok(Json(app.engine.queue_native_settlement(
                &caller,
                key(headers)?,
                id,
                revision(headers)?,
                parse(body)?,
            )?)
            .into_response())
        }
        [
            "v1",
            "agreements",
            id,
            "native-settlement-requests",
            request,
            "withdraw",
        ] if app.native_request_queue => {
            permission(principal, Permission::Coordinate)?;
            permission(principal, Permission::Disclose)?;
            app.engine.get(&caller, id)?;
            empty(body)?;
            Ok(Json(app.engine.withdraw_native_settlement_request(
                &caller,
                key(headers)?,
                id,
                revision(headers)?,
                request,
            )?)
            .into_response())
        }
        ["v1", "agreements", id, "native-artifact-handoff-requests"]
            if app.native_request_queue =>
        {
            permission(principal, Permission::Coordinate)?;
            permission(principal, Permission::Disclose)?;
            app.engine.get(&caller, id)?;
            Ok(Json(app.engine.queue_native_artifact_handoff(
                &caller,
                key(headers)?,
                id,
                revision(headers)?,
                parse(body)?,
            )?)
            .into_response())
        }
        [
            "v1",
            "agreements",
            id,
            "native-artifact-handoff-requests",
            request,
            "withdraw",
        ] if app.native_request_queue => {
            permission(principal, Permission::Coordinate)?;
            permission(principal, Permission::Disclose)?;
            app.engine.get(&caller, id)?;
            empty(body)?;
            Ok(Json(app.engine.withdraw_native_artifact_handoff_request(
                &caller,
                key(headers)?,
                id,
                revision(headers)?,
                request,
            )?)
            .into_response())
        }
        ["v1", "agreements", id, "native-proof-execution-requests"] if app.native_request_queue => {
            permission(principal, Permission::Coordinate)?;
            permission(principal, Permission::Disclose)?;
            app.engine.get(&caller, id)?;
            Ok(Json(app.engine.queue_native_proof_execution(
                &caller,
                key(headers)?,
                id,
                revision(headers)?,
                parse(body)?,
            )?)
            .into_response())
        }
        [
            "v1",
            "agreements",
            id,
            "native-proof-execution-requests",
            request,
            "withdraw",
        ] if app.native_request_queue => {
            permission(principal, Permission::Coordinate)?;
            permission(principal, Permission::Disclose)?;
            app.engine.get(&caller, id)?;
            empty(body)?;
            Ok(Json(app.engine.withdraw_native_proof_execution_request(
                &caller,
                key(headers)?,
                id,
                revision(headers)?,
                request,
            )?)
            .into_response())
        }
        ["v1", "agreements", id, "native-proof-requests"] if app.native_request_queue => {
            permission(principal, Permission::Coordinate)?;
            permission(principal, Permission::Disclose)?;
            app.engine.get(&caller, id)?;
            Ok(Json(app.engine.queue_native_proof_reconciliation(
                &caller,
                key(headers)?,
                id,
                revision(headers)?,
                parse(body)?,
            )?)
            .into_response())
        }
        [
            "v1",
            "agreements",
            id,
            "native-proof-requests",
            request,
            "withdraw",
        ] if app.native_request_queue => {
            permission(principal, Permission::Coordinate)?;
            permission(principal, Permission::Disclose)?;
            app.engine.get(&caller, id)?;
            empty(body)?;
            Ok(Json(app.engine.withdraw_native_proof_request(
                &caller,
                key(headers)?,
                id,
                revision(headers)?,
                request,
            )?)
            .into_response())
        }
        ["v1", "agreements", id, "native-requests"] if app.native_request_queue => {
            permission(principal, Permission::Coordinate)?;
            permission(principal, Permission::Disclose)?;
            app.engine.get(&caller, id)?;
            Ok(Json(app.engine.queue_native_construction(
                &caller,
                key(headers)?,
                id,
                revision(headers)?,
                parse(body)?,
            )?)
            .into_response())
        }
        [
            "v1",
            "agreements",
            id,
            "native-requests",
            request,
            "withdraw",
        ] if app.native_request_queue => {
            permission(principal, Permission::Coordinate)?;
            permission(principal, Permission::Disclose)?;
            app.engine.get(&caller, id)?;
            empty(body)?;
            Ok(Json(app.engine.withdraw_native_request(
                &caller,
                key(headers)?,
                id,
                revision(headers)?,
                request,
            )?)
            .into_response())
        }

        #[cfg(feature = "protected-transport")]
        ["v1", "agreements", id, "transport", handle, "import"] => {
            permission(principal, Permission::Coordinate)?;
            empty(body)?;
            Ok(mutated(protected_runtime(app)?.import(
                &caller,
                id,
                handle,
                key(headers)?,
                revision(headers)?,
            )?))
        }
        ["v1", "session", "end"] => {
            empty(body)?;
            app.security.end_session(principal);
            Ok(Json(json!({"ended":true})).into_response())
        }
        ["v1", "agreements", "validate"] => {
            permission(principal, Permission::Propose)?;
            Ok(Json(app.engine.validate(&parse(body)?)?).into_response())
        }
        ["v1", "agreements"] => {
            permission(principal, Permission::Propose)?;
            Ok(mutated(app.engine.create(
                &caller,
                key(headers)?,
                parse(body)?,
            )?))
        }
        ["v1", "agreements", id, "terms-revisions"] => {
            permission(principal, Permission::Propose)?;
            Ok(mutated(app.engine.revise_agreement(
                &caller,
                key(headers)?,
                id,
                revision(headers)?,
                parse(body)?,
            )?))
        }
        ["v1", "agreements", id, "sponsor-policies"] => {
            permission(principal, Permission::Propose)?;
            Ok(sponsor_mutated(app.engine.create_sponsor_policy(
                &caller,
                key(headers)?,
                id,
                revision(headers)?,
                parse(body)?,
            )?))
        }
        [
            "v1",
            "agreements",
            id,
            "sponsor-policies",
            policy,
            "versions",
        ] => {
            permission(principal, Permission::Propose)?;
            let request: UpdateSponsorPolicyRequest = parse(body)?;
            if request.policy_id != *policy {
                return Err(ApiError::new(
                    "INVALID_REQUEST",
                    "Policy body and path must identify the same policy",
                ));
            }
            Ok(sponsor_mutated(app.engine.update_sponsor_policy(
                &caller,
                key(headers)?,
                id,
                revision(headers)?,
                request,
            )?))
        }
        ["v1", "agreements", id, "sponsor-policies", policy, "state"] => {
            permission(principal, Permission::Propose)?;
            let request: SponsorPolicyStateRequest = parse(body)?;
            if request.policy_id != *policy {
                return Err(ApiError::new(
                    "INVALID_REQUEST",
                    "Policy body and path must identify the same policy",
                ));
            }
            Ok(sponsor_mutated(app.engine.set_sponsor_policy_state(
                &caller,
                key(headers)?,
                id,
                revision(headers)?,
                request,
            )?))
        }
        [
            "v1",
            "agreements",
            id,
            "sponsor-policies",
            policy,
            "preview",
        ] => {
            permission(principal, Permission::Read)?;
            Ok(Json(
                app.engine
                    .preview_sponsor_policy(&caller, id, policy, parse(body)?)?,
            )
            .into_response())
        }
        ["v1", "agreements", id, "roster-selection"] => {
            permission(principal, Permission::Coordinate)?;
            Ok(mutated(app.engine.select_roster(
                &caller,
                key(headers)?,
                id,
                revision(headers)?,
                parse(body)?,
            )?))
        }
        ["v1", "agreements", id, "intents"] => {
            permission(principal, Permission::Intent)?;
            Ok(mutated(app.engine.add_intent(
                &caller,
                key(headers)?,
                id,
                revision(headers)?,
                parse(body)?,
            )?))
        }
        ["v1", "agreements", id, "intents", intent, "withdraw"] => {
            permission(principal, Permission::Intent)?;
            empty(body)?;
            Ok(mutated(app.engine.withdraw(
                &caller,
                key(headers)?,
                id,
                intent,
                revision(headers)?,
            )?))
        }
        ["v1", "agreements", id, "proposals"] => {
            permission(principal, Permission::Coordinate)?;
            empty(body)?;
            Ok(mutated(app.engine.propose(
                &caller,
                key(headers)?,
                id,
                revision(headers)?,
            )?))
        }
        ["v1", "agreements", id, "candidates"] => {
            permission(principal, Permission::Coordinate)?;
            Ok(mutated(app.engine.create_candidate(
                &caller,
                key(headers)?,
                id,
                revision(headers)?,
                parse(body)?,
            )?))
        }
        ["v1", "candidates", id, "verify"] => {
            permission(principal, Permission::Read)?;
            empty(body)?;
            Ok(mutated(app.engine.review_candidate(
                &caller,
                key(headers)?,
                id,
                revision(headers)?,
            )?))
        }
        [
            "v1",
            "candidates",
            id,
            "construct" | "proof-jobs" | "export" | "authorization-requests" | "submit",
        ] => {
            permission(principal, Permission::Coordinate)?;
            key(headers)?;
            revision(headers)?;
            app.engine.candidate(&caller, id)?;
            Err(ApiError::new(
                "UNSUPPORTED_CAPABILITY",
                "The service has no authenticated private-artifact intake, durable witness checkpoint, disclosure, signing or submission capability",
            ))
        }
        ["v1", "proposals", id, "verify"] => {
            permission(principal, Permission::Read)?;
            empty(body)?;
            Ok(mutated(app.engine.review(
                &caller,
                key(headers)?,
                id,
                revision(headers)?,
            )?))
        }
        ["v1", "agreements", id, "cancellation-requests"] => {
            permission(principal, Permission::Intent)?;
            empty(body)?;
            Ok(mutated(app.engine.cancel(
                &caller,
                key(headers)?,
                id,
                revision(headers)?,
            )?))
        }
        ["v1", "agreements", id, "reconcile"] => {
            permission(principal, Permission::Read)?;
            empty(body)?;
            key(headers)?;
            revision(headers)?;
            app.engine.get(&caller, id)?;
            Err(ApiError::unsupported())
        }
        [
            "v1",
            "proposals",
            id,
            action @ ("authorization-requests"
            | "authorizations"
            | "proof-jobs"
            | "extract"
            | "submit"),
        ] => {
            permission(
                principal,
                match *action {
                    "authorization-requests" => Permission::AuthorizeRequest,
                    "submit" => Permission::Submit,
                    _ => Permission::Coordinate,
                },
            )?;
            key(headers)?;
            revision(headers)?;
            app.engine.proposal(&caller, id)?;
            Err(ApiError::unsupported())
        }
        _ => Err(ApiError::new(
            "UNSUPPORTED_CAPABILITY",
            "This operation is not implemented. No authorization, disclosure, or payment was created.",
        )),
    }
}

fn event_cursor(query: &str, headers: &HeaderMap) -> Result<u64, ApiError> {
    let mut cursor = None;
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| ApiError::new("INVALID_REQUEST", "Invalid event query"))?;
        if key == "after" && cursor.is_none() {
            cursor = Some(value.parse::<u64>().map_err(|_| {
                ApiError::new(
                    "INVALID_REQUEST",
                    "Event cursor must be an unsigned integer",
                )
            })?);
        } else if key != "format" || value != "json" {
            return Err(ApiError::new(
                "INVALID_REQUEST",
                "Unknown or repeated event query field",
            ));
        }
    }
    if let Some(header) = headers.get("last-event-id") {
        if cursor.is_none() {
            cursor = Some(
                header
                    .to_str()
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
                    .ok_or_else(|| {
                        ApiError::new(
                            "INVALID_REQUEST",
                            "Last-Event-ID must be an unsigned integer",
                        )
                    })?,
            );
        }
    }
    Ok(cursor.unwrap_or(0))
}
async fn stream_events(app: App, principal: Principal, mut cursor: u64) -> Response {
    let Some(client_permit) = app.security.stream_permit(&principal.client_id) else {
        return error_response(ApiError::new(
            "RESOURCE_EXHAUSTED",
            "This client has too many event streams",
        ));
    };
    let Ok(permit) = app.streams.clone().try_acquire_owned() else {
        return error_response(ApiError::new(
            "RESOURCE_EXHAUSTED",
            "Local event stream limit reached",
        ));
    };
    let stream = async_stream::stream! {
        let _permit = permit;
        let _client_permit = client_permit;
        loop {
            if !app.security.session_active(&principal) { yield Ok::<Event, Infallible>(Event::default().event("session_expired").data("{\"code\":\"AUTHENTICATION_REQUIRED\"}")); break; }
            let engine = app.engine.clone(); let caller = access(&principal);
            let batch = tokio::task::spawn_blocking(move || engine.event_batch(&caller,cursor,100)).await;
            match batch {
                Ok(Ok((Value::Array(events), scanned_cursor))) => {
                    for event in events {
                        if !app.security.session_active(&principal) { break; }
                        let next = event.get("sequence").and_then(Value::as_u64).unwrap_or(cursor);
                        cursor = cursor.max(next);
                        if let Ok(data) = serde_json::to_string(&event) { yield Ok(Event::default().event("wholepact").id(next.to_string()).data(data)); }
                    }
                    cursor = cursor.max(scanned_cursor);
                }
                _ => { yield Ok(Event::default().event("service_unavailable").data("{\"code\":\"STORAGE_UNAVAILABLE\"}")); break; }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    };
    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(1))
                .text("heartbeat"),
        )
        .into_response()
}
