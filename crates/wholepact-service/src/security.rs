//! Local transport security. Credentials are never put in URLs or log fields.
use axum::{
    Json,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

const SESSION_TTL: Duration = Duration::from_secs(30 * 60);
const MAX_SESSIONS_PER_CLIENT: usize = 8;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    Read,
    Propose,
    Intent,
    Coordinate,
    Disclose,
    AuthorizeRequest,
    Submit,
    Administer,
}

/// Supplied locally by the user. Loading this file does not create new grants.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub client_id: String,
    pub bootstrap_token: String,
    pub permissions: BTreeSet<Permission>,
    #[serde(default)]
    pub agreement_ids: BTreeSet<String>,
    #[serde(default)]
    pub all_agreements: bool,
    /// Explicit OWNED consent. Omission grants only the selected IDs, never future ownership.
    #[serde(default)]
    pub include_owned_agreements: bool,
}

impl Drop for ClientConfig {
    fn drop(&mut self) {
        self.bootstrap_token.zeroize();
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    pub clients: Vec<ClientConfig>,
    pub allowed_origins: BTreeSet<String>,
}

impl SecurityConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.clients.is_empty() || self.clients.len() > 32 {
            return Err("Configure 1 to 32 local clients".into());
        }
        let mut ids = BTreeSet::new();
        let mut credentials = BTreeSet::new();
        for client in &self.clients {
            if client.client_id.is_empty()
                || client.client_id.len() > 128
                || !client
                    .client_id
                    .bytes()
                    .all(|x| x.is_ascii_alphanumeric() || b"-_.".contains(&x))
            {
                return Err("Invalid client ID".into());
            }
            if !ids.insert(client.client_id.clone())
                || !credentials.insert(client.bootstrap_token.as_str())
            {
                return Err("Client IDs and credentials must be distinct".into());
            }
            if client.bootstrap_token.len() < 32
                || client.bootstrap_token.len() > 256
                || !client
                    .bootstrap_token
                    .bytes()
                    .all(|b| (33..=126).contains(&b))
            {
                return Err(
                    "Each bootstrap token must contain 32 to 256 visible ASCII bytes".into(),
                );
            }
            if client.agreement_ids.len() > 1024 {
                return Err("Too many agreement scopes".into());
            }
            if client.agreement_ids.iter().any(|id| {
                id.is_empty()
                    || id.len() > 128
                    || !id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
            }) {
                return Err("Invalid selected agreement ID".into());
            }
        }
        if self.allowed_origins.len() > 16 {
            return Err("Too many browser origins".into());
        }
        for origin in &self.allowed_origins {
            let uri: axum::http::Uri = origin.parse().map_err(|_| "Invalid browser origin")?;
            if uri.scheme_str() != Some("http")
                || !matches!(uri.host(), Some("127.0.0.1" | "localhost" | "[::1]"))
                || uri.port_u16().is_none()
                || uri.path() != "/"
                || uri.query().is_some()
                || origin.ends_with('/')
            {
                return Err(
                    "Browser origins must be exact HTTP loopback origins with a port and no path"
                        .into(),
                );
            }
        }
        Ok(())
    }

    /// Public, deterministic fixture. Never use with real or private records.
    pub fn development_fixture() -> Self {
        Self {
            clients: vec![ClientConfig {
                include_owned_agreements: true,
                client_id: "development-workspace".into(),
                bootstrap_token: "wholepact-development-only-not-a-secret".into(),
                permissions: [
                    Permission::Read,
                    Permission::Propose,
                    Permission::Intent,
                    Permission::Coordinate,
                ]
                .into(),
                agreement_ids: BTreeSet::new(),
                all_agreements: true,
            }],
            allowed_origins: [
                "http://127.0.0.1:4319".into(),
                "http://localhost:4319".into(),
            ]
            .into(),
        }
    }
}

#[derive(Clone)]
pub struct Principal {
    pub client_id: String,
    pub permissions: BTreeSet<Permission>,
    pub agreement_ids: BTreeSet<String>,
    pub all_agreements: bool,
    pub include_owned_agreements: bool,
    pub csrf_token: String,
    pub session_digest: Option<[u8; 32]>,
}

impl Drop for Principal {
    fn drop(&mut self) {
        self.csrf_token.zeroize();
        if let Some(digest) = &mut self.session_digest {
            digest.zeroize();
        }
    }
}

impl Principal {
    pub fn permits(&self, p: Permission) -> bool {
        self.permissions.contains(&p)
    }
    pub fn sees(&self, agreement_id: &str, owner: &str) -> bool {
        self.all_agreements
            || (self.include_owned_agreements && self.client_id == owner)
            || self.agreement_ids.contains(agreement_id)
    }
}

#[derive(Clone)]
struct Session {
    principal: Principal,
    expires: Instant,
}
struct Rate {
    window: Instant,
    requests: usize,
}

pub struct Security {
    config: SecurityConfig,
    allowed_hosts: BTreeSet<String>,
    sessions: Mutex<HashMap<[u8; 32], Session>>,
    rates: Mutex<HashMap<String, Rate>>,
    client_requests: BTreeMap<String, Arc<tokio::sync::Semaphore>>,
    client_streams: BTreeMap<String, Arc<tokio::sync::Semaphore>>,
}

fn digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}
fn random_token() -> Result<String, &'static str> {
    let mut bytes = [0; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| "Secure randomness unavailable")?;
    let token = hex::encode(bytes);
    bytes.zeroize();
    Ok(token)
}

impl Security {
    pub fn new(config: SecurityConfig, port: u16) -> Result<Arc<Self>, String> {
        config.validate()?;
        let client_requests = config
            .clients
            .iter()
            .map(|c| {
                (
                    c.client_id.clone(),
                    Arc::new(tokio::sync::Semaphore::new(4)),
                )
            })
            .collect();
        let client_streams = config
            .clients
            .iter()
            .map(|c| {
                (
                    c.client_id.clone(),
                    Arc::new(tokio::sync::Semaphore::new(2)),
                )
            })
            .collect();
        Ok(Arc::new(Self {
            client_requests,
            client_streams,
            config,
            allowed_hosts: [
                format!("127.0.0.1:{port}"),
                format!("localhost:{port}"),
                format!("[::1]:{port}"),
            ]
            .into(),
            sessions: Mutex::new(HashMap::new()),
            rates: Mutex::new(HashMap::new()),
        }))
    }

    fn authenticate(&self, token: &str, session_endpoint: bool) -> Option<Principal> {
        if token.len() > 256 {
            return None;
        }
        let hash = digest(token);
        let mut sessions = self.sessions.lock().ok()?;
        sessions.retain(|_, s| s.expires > Instant::now());
        if let Some(s) = sessions.get(&hash) {
            if !session_endpoint {
                return Some(s.principal.clone());
            }
            return None;
        }
        drop(sessions);
        if !session_endpoint {
            return None;
        }
        for c in &self.config.clients {
            if bool::from(hash.ct_eq(&digest(&c.bootstrap_token))) {
                return Some(Principal {
                    client_id: c.client_id.clone(),
                    permissions: c.permissions.clone(),
                    agreement_ids: c.agreement_ids.clone(),
                    all_agreements: c.all_agreements,
                    include_owned_agreements: c.include_owned_agreements,
                    csrf_token: String::new(),
                    session_digest: None,
                });
            }
        }
        None
    }

    pub fn issue_session(&self, source: &Principal) -> Result<serde_json::Value, &'static str> {
        if source.session_digest.is_some() {
            return Err("Bootstrap credential required; sessions cannot renew themselves");
        }
        let token = zeroize::Zeroizing::new(random_token()?);
        let mut p = source.clone();
        p.csrf_token = random_token()?;
        p.session_digest = Some(digest(&token));
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| "Session storage unavailable")?;
        sessions.retain(|_, s| s.expires > Instant::now());
        let count = sessions
            .values()
            .filter(|s| s.principal.client_id == p.client_id)
            .count();
        if count >= MAX_SESSIONS_PER_CLIENT {
            return Err("Client session limit reached; wait for expiry or restart service");
        }
        sessions.insert(
            digest(&token),
            Session {
                principal: p.clone(),
                expires: Instant::now() + SESSION_TTL,
            },
        );
        Ok(
            json!({"schema_version": 1, "client_id": p.client_id, "permissions": p.permissions, "agreement_ids": p.agreement_ids, "all_agreements": p.all_agreements, "include_owned_agreements": p.include_owned_agreements, "agreement_scope": if p.all_agreements { "all" } else if p.include_owned_agreements { "owned_and_selected" } else { "selected" }, "owned_agreements_included": p.all_agreements || p.include_owned_agreements, "owned_agreements_includes_future": p.all_agreements || p.include_owned_agreements, "agreement_ids_semantics": if p.all_agreements { "not_limiting_all_agreements" } else if p.include_owned_agreements { "additional_shared_agreements" } else { "exact_selected_agreements" }, "session_token": token.as_str(), "csrf_token": p.csrf_token, "expires_in_seconds": SESSION_TTL.as_secs()}),
        )
    }

    pub fn request_permit(&self, client: &str) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.client_requests
            .get(client)?
            .clone()
            .try_acquire_owned()
            .ok()
    }
    pub fn stream_permit(&self, client: &str) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.client_streams
            .get(client)?
            .clone()
            .try_acquire_owned()
            .ok()
    }
    pub fn end_session(&self, principal: &Principal) -> bool {
        match (principal.session_digest, self.sessions.lock()) {
            (Some(digest), Ok(mut sessions)) => sessions.remove(&digest).is_some(),
            _ => false,
        }
    }

    pub fn session_active(&self, principal: &Principal) -> bool {
        principal
            .session_digest
            .and_then(|d| {
                self.sessions
                    .lock()
                    .ok()?
                    .get(&d)
                    .map(|s| s.expires > Instant::now())
            })
            .unwrap_or(false)
    }

    fn rate_allows(&self, client_id: &str) -> bool {
        let Ok(mut rates) = self.rates.lock() else {
            return false;
        };
        let entry = rates.entry(client_id.to_owned()).or_insert(Rate {
            window: Instant::now(),
            requests: 0,
        });
        if entry.window.elapsed() > Duration::from_secs(60) {
            entry.window = Instant::now();
            entry.requests = 0;
        }
        entry.requests += 1;
        entry.requests <= 240
    }
}

fn single<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        None
    } else {
        Some(first)
    }
}

pub fn rejection(status: StatusCode, code: &str, message: &str) -> Response {
    (status, Json(json!({"code": code, "message": message, "retryable": false, "operation_id": null, "details": {}, "safe_actions": []}))).into_response()
}

/// Host validation occurs before even OPTIONS handling. Preflight exposes no data.
pub async fn boundary(
    State(security): State<Arc<Security>>,
    mut request: Request,
    next: Next,
) -> Response {
    let request_id = single(request.headers(), "x-request-id")
        .filter(|v| !v.is_empty() && v.len() <= 128 && v.bytes().all(|b| (33..=126).contains(&b)))
        .map(str::to_owned)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let headers = request.headers();
    if !single(headers, "host").is_some_and(|h| security.allowed_hosts.contains(h)) {
        return rejection(
            StatusCode::FORBIDDEN,
            "HOST_DENIED",
            "Exact loopback Host required",
        );
    }
    let origin = match single(headers, "origin") {
        Some(o) if security.config.allowed_origins.contains(o) => Some(o.to_string()),
        Some(_) => {
            return rejection(
                StatusCode::FORBIDDEN,
                "ORIGIN_DENIED",
                "This browser origin is not approved",
            );
        }
        None if headers.contains_key("origin") => {
            return rejection(
                StatusCode::FORBIDDEN,
                "ORIGIN_DENIED",
                "Invalid Origin header",
            );
        }
        None => None,
    };
    let reject = |status, code, message| {
        let mut response = rejection(status, code, message);
        cors(&mut response, origin.as_deref());
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    };
    if request
        .uri()
        .query()
        .is_some_and(|q| q.len() > 512 || q.to_ascii_lowercase().contains("token"))
    {
        return reject(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "Credentials are forbidden in URLs; query is bounded",
        );
    }
    if request.method() == Method::OPTIONS {
        if origin.is_none() {
            return reject(
                StatusCode::FORBIDDEN,
                "ORIGIN_DENIED",
                "Preflight requires an approved Origin",
            );
        }
        if !single(headers, "access-control-request-method")
            .is_some_and(|m| matches!(m, "GET" | "POST"))
        {
            return reject(
                StatusCode::FORBIDDEN,
                "METHOD_DENIED",
                "Unsupported preflight method",
            );
        }
        if let Some(value) = single(headers, "access-control-request-headers") {
            if !value.split(',').all(|h| {
                matches!(
                    h.trim().to_ascii_lowercase().as_str(),
                    "authorization"
                        | "content-type"
                        | "x-wholepact-csrf"
                        | "idempotency-key"
                        | "if-match"
                        | "x-request-id"
                        | "last-event-id"
                )
            }) {
                return reject(
                    StatusCode::FORBIDDEN,
                    "HEADER_DENIED",
                    "Unsupported preflight header",
                );
            }
        }
        let mut response = StatusCode::NO_CONTENT.into_response();
        cors(&mut response, origin.as_deref());
        response.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST"),
        );
        response.headers_mut().insert(header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("Authorization, Content-Type, X-Wholepact-CSRF, Idempotency-Key, If-Match, X-Request-Id, Last-Event-ID"));
        return response;
    }
    let Some(token) = single(headers, "authorization").and_then(|v| v.strip_prefix("Bearer "))
    else {
        return reject(
            StatusCode::UNAUTHORIZED,
            "AUTHENTICATION_REQUIRED",
            "A local client session is required",
        );
    };
    let Some(principal) = security.authenticate(
        token,
        request.uri().path() == "/v1/session" && request.method() == Method::GET,
    ) else {
        return reject(
            StatusCode::UNAUTHORIZED,
            "AUTHENTICATION_REQUIRED",
            "Invalid or expired session; exchange a local bootstrap credential at /v1/session",
        );
    };
    if !security.rate_allows(&principal.client_id) {
        return reject(
            StatusCode::TOO_MANY_REQUESTS,
            "RESOURCE_EXHAUSTED",
            "Client request rate exceeded",
        );
    }
    if request.method() != Method::GET && request.method() != Method::HEAD {
        let csrf = single(headers, "x-wholepact-csrf").unwrap_or("");
        if principal.csrf_token.is_empty()
            || !bool::from(csrf.as_bytes().ct_eq(principal.csrf_token.as_bytes()))
        {
            return reject(
                StatusCode::FORBIDDEN,
                "CSRF_DENIED",
                "Session-bound CSRF token required",
            );
        }
        if single(headers, "content-type").map(|x| x.split(';').next().unwrap_or("").trim())
            != Some("application/json")
        {
            return reject(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "INVALID_REQUEST",
                "Content-Type application/json required",
            );
        }
    }
    request.extensions_mut().insert(principal);
    let mut response = next.run(request).await;
    cors(&mut response, origin.as_deref());
    if let Ok(id) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", id);
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
        .headers_mut()
        .insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    response
}

fn cors(response: &mut Response<Body>, origin: Option<&str>) {
    if let Some(o) = origin.and_then(|o| HeaderValue::from_str(o).ok()) {
        response
            .headers_mut()
            .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, o);
    }
    response.headers_mut().insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static(
            "X-Request-Id, X-Operation-Id, X-Event-Sequence, X-Idempotent-Replay",
        ),
    );
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Origin"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_session_expiry_and_nonrenewal() {
        let security = Security::new(SecurityConfig::development_fixture(), 4318).unwrap();
        let bootstrap = security
            .authenticate("wholepact-development-only-not-a-secret", true)
            .unwrap();
        let issued = security.issue_session(&bootstrap).unwrap();
        let token = issued["session_token"].as_str().unwrap();
        let session = security.authenticate(token, false).unwrap();
        assert!(security.session_active(&session));
        assert!(security.authenticate(token, true).is_none());
        assert!(security.issue_session(&session).is_err());
        security
            .sessions
            .lock()
            .unwrap()
            .get_mut(&digest(token))
            .unwrap()
            .expires = Instant::now() - Duration::from_secs(1);
        assert!(!security.session_active(&session));
        assert!(security.authenticate(token, false).is_none());
    }

    #[test]
    fn client_limits_are_separate_and_bounded() {
        let security = Security::new(SecurityConfig::development_fixture(), 4318).unwrap();
        let a = security.stream_permit("development-workspace").unwrap();
        let b = security.stream_permit("development-workspace").unwrap();
        assert!(security.stream_permit("development-workspace").is_none());
        assert!(security.stream_permit("unknown-client").is_none());
        drop(a);
        drop(b);
        assert!(security.stream_permit("development-workspace").is_some());
    }
}

#[cfg(test)]
mod selected_agreement_tests {
    use super::*;
    fn config(owned: Option<bool>, all: bool) -> SecurityConfig {
        let mut client = json!({"client_id":"synthetic-owner","bootstrap_token":"synthetic-not-a-production-token-00000001","permissions":["read","propose"],"agreement_ids":["selected"],"all_agreements":all});
        if let Some(owned) = owned {
            client["include_owned_agreements"] = owned.into();
        }
        serde_json::from_value(json!({"clients":[client],"allowed_origins":[]})).unwrap()
    }
    #[test]
    fn omitted_scope_never_infers_owned_access() {
        let c = config(None, false);
        assert!(!c.clients[0].include_owned_agreements);
        let security = Security::new(c, 4318).unwrap();
        let p = security
            .authenticate("synthetic-not-a-production-token-00000001", true)
            .unwrap();
        assert!(p.sees("selected", "another-owner"));
        assert!(!p.sees("existing-owned", "synthetic-owner"));
        assert!(!p.sees("future-owned", "synthetic-owner"));
        assert!(!p.sees("foreign", "another-owner"));
        let engine_access = crate::access(&p);
        for (id, owner) in [
            ("selected", "another-owner"),
            ("future-owned", "synthetic-owner"),
            ("foreign", "another-owner"),
        ] {
            assert_eq!(
                p.sees(id, owner),
                engine_access.permits_agreement(id, owner)
            );
        }
    }
    #[test]
    fn explicit_owned_and_all_keep_only_their_chosen_semantics() {
        for (owned, all) in [(true, false), (false, true)] {
            let security = Security::new(config(Some(owned), all), 4318).unwrap();
            let p = security
                .authenticate("synthetic-not-a-production-token-00000001", true)
                .unwrap();
            assert!(p.sees("future-owned", "synthetic-owner"));
            assert_eq!(p.sees("foreign", "other"), all);
        }
    }
    #[test]
    fn exact_session_scope_survives_bootstrap_and_session_authentication() {
        let security = Security::new(config(Some(false), false), 4318).unwrap();
        let p = security
            .authenticate("synthetic-not-a-production-token-00000001", true)
            .unwrap();
        let response = security.issue_session(&p).unwrap();
        assert_eq!(response["agreement_scope"], "selected");
        assert_eq!(response["owned_agreements_includes_future"], false);
        assert_eq!(
            response["agreement_ids_semantics"],
            "exact_selected_agreements"
        );
        let session = security
            .authenticate(response["session_token"].as_str().unwrap(), false)
            .unwrap();
        assert!(session.sees("selected", "other"));
        assert!(!session.sees("new-owned", "synthetic-owner"));
        assert!(security.issue_session(&session).is_err());
    }
    #[test]
    fn malformed_selected_ids_and_oversized_scope_are_rejected() {
        for invalid in ["", "has space", "../outside", "line\nfeed"] {
            let mut c = config(Some(false), false);
            c.clients[0].agreement_ids = [invalid.into()].into();
            assert!(c.validate().is_err());
        }
        let mut c = config(Some(false), false);
        c.clients[0].agreement_ids = (0..1025).map(|n| format!("a-{n}")).collect();
        assert!(c.validate().is_err());
    }
}
