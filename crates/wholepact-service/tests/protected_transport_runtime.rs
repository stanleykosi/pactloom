#![cfg(feature = "protected-transport")]
//! Synthetic controllers and deterministic test keys only. These implementations
//! are not exported by the production runtime and never provision live identity.
use serde_json::json;
use std::{
    collections::BTreeSet,
    sync::{
        Arc, Mutex, RwLock, RwLockReadGuard,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
};
use wholepact_core::{AgreementDraft, ParticipationIntent};
use wholepact_engine::{Access, ApiError, Engine, transport_workflows::*};
use wholepact_service::protected_transport::*;
use wholepact_storage_security::{DatabaseKey, create_encrypted, open_encrypted};
use wholepact_store::Store;
use wholepact_transport::*;

struct SyntheticKeys {
    local_byte: AtomicU8,
    peer_byte: AtomicU8,
}
impl SyntheticKeys {
    fn new() -> Self {
        Self {
            local_byte: AtomicU8::new(22),
            peer_byte: AtomicU8::new(11),
        }
    }
}
impl LocalTransportKeyController for SyntheticKeys {
    fn keys(
        &self,
        scope: &TransportKeyScope,
    ) -> std::result::Result<ProtectedTransportKeys, ApiError> {
        if scope.principal_id != "owner" || !synthetic_agreement(&scope.context.agreement_id) {
            return Err(ApiError::new(
                "PERMISSION_DENIED",
                "Synthetic controller scope denied",
            ));
        }
        Ok(ProtectedTransportKeys {
            local_secret: secret(self.local_byte.load(Ordering::SeqCst)),
            pinned_peer: secret(self.peer_byte.load(Ordering::SeqCst))
                .public_key()
                .unwrap(),
        })
    }
}
struct SyntheticConsent {
    access: Arc<AtomicBool>,
    disclosure: AtomicBool,
    approved: Mutex<BTreeSet<String>>,
    fence: Arc<RwLock<()>>,
    substitute_scope: AtomicBool,
    revoke_on_retrieve: AtomicBool,
    revocation: Mutex<Option<std::thread::JoinHandle<()>>>,
}
impl SyntheticConsent {
    fn new() -> Self {
        Self {
            access: Arc::new(AtomicBool::new(true)),
            disclosure: AtomicBool::new(false),
            approved: Mutex::new(BTreeSet::new()),
            fence: Arc::new(RwLock::new(())),
            substitute_scope: AtomicBool::new(false),
            revoke_on_retrieve: AtomicBool::new(false),
            revocation: Mutex::new(None),
        }
    }
}
struct SyntheticLease<'a> {
    scope: LocalTransportScope,
    action: LocalTransportAction,
    expires: Timestamp,
    _guard: RwLockReadGuard<'a, ()>,
    access: &'a AtomicBool,
}
impl LocalTransportLease for SyntheticLease<'_> {
    fn scope(&self) -> &LocalTransportScope {
        &self.scope
    }
    fn action(&self) -> LocalTransportAction {
        self.action
    }
    fn expires_at(&self) -> &Timestamp {
        &self.expires
    }
    fn check_current(&self) -> std::result::Result<(), ApiError> {
        if self.access.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(ApiError::new(
                "PERMISSION_DENIED",
                "Synthetic authority revoked",
            ))
        }
    }
}
impl LocalTransportConsent for SyntheticConsent {
    fn acquire<'a>(
        &'a self,
        scope: &LocalTransportScope,
        action: LocalTransportAction,
        preview: &DisclosurePreview,
        fields: &[DisclosureField],
    ) -> std::result::Result<Box<dyn LocalTransportLease + 'a>, ApiError> {
        let guard = self.fence.read().unwrap();
        let denied = || ApiError::new("PERMISSION_DENIED", "Synthetic authority denied");
        if !self.access.load(Ordering::SeqCst)
            || scope.principal_id != "owner"
            || !synthetic_agreement(&scope.agreement_id)
            || preview.digest().unwrap() != scope.artifact_fingerprint
        {
            return Err(denied());
        }
        if action == LocalTransportAction::SealExport {
            if !self.disclosure.load(Ordering::SeqCst) {
                return Err(denied());
            }
            let mut approved = self.approved.lock().unwrap();
            if !fields.is_empty() {
                approved.insert(scope.artifact_fingerprint.clone());
            }
            if !approved.contains(&scope.artifact_fingerprint) {
                return Err(denied());
            }
        }
        if action == LocalTransportAction::RetrieveEncryptedExport {
            if !self.disclosure.load(Ordering::SeqCst)
                || !self
                    .approved
                    .lock()
                    .unwrap()
                    .contains(&scope.artifact_fingerprint)
            {
                return Err(denied());
            }
            if self.revoke_on_retrieve.swap(false, Ordering::SeqCst) {
                let fence = self.fence.clone();
                let access = self.access.clone();
                let (started, receiver) = std::sync::mpsc::channel();
                *self.revocation.lock().unwrap() = Some(std::thread::spawn(move || {
                    started.send(()).unwrap();
                    let _exclusive = fence.write().unwrap();
                    access.store(false, Ordering::SeqCst);
                }));
                receiver.recv().unwrap();
                assert!(
                    self.fence.try_write().is_err(),
                    "revocation must wait for handoff lease"
                );
            }
        }
        let mut scope = scope.clone();
        if self.substitute_scope.load(Ordering::SeqCst) {
            scope.artifact_fingerprint = "wrong-artifact".into();
        }
        Ok(Box::new(SyntheticLease {
            scope,
            action,
            expires: at(&now(), 60),
            _guard: guard,
            access: &self.access,
        }))
    }
}

fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    dir
}
fn now() -> Timestamp {
    Timestamp::from_unix_seconds(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
    )
    .unwrap()
}
fn at(now: &Timestamp, delta: i64) -> Timestamp {
    Timestamp::from_unix_seconds(now.unix_seconds() + delta).unwrap()
}
fn owner() -> Access {
    Access {
        include_owned_agreements: true,
        principal_id: "owner".into(),
        ..Access::default()
    }
}
fn secret(byte: u8) -> TransportSecret {
    TransportSecret::from_bytes([byte; 32]).unwrap()
}
fn synthetic_agreement(id: &str) -> bool {
    id == draft().agreement_id || id == "fresh-private-agreement"
}
fn draft() -> AgreementDraft {
    let mut draft: AgreementDraft = serde_json::from_str(include_str!(
        "../../wholepact-core/tests/fixtures/agreement.json"
    ))
    .unwrap();
    draft.purpose = "PRIVATE-INVITATION-SYNTHETIC-CANARY".into();
    draft
}
fn grant() -> TransportPeerGrantRequest {
    TransportPeerGrantRequest {
        grant_id: "peer-grant".into(),
        participant_id: "participant-one".into(),
        sender_key_fingerprint: secret(11).public_key().unwrap().fingerprint(),
        recipient_id: draft().organizer_identity,
        recipient_key_fingerprint: secret(22).public_key().unwrap().fingerprint(),
        allow_intent: true,
        allow_withdrawal: true,
        expires_at: at(&now(), 3600),
    }
}
fn context(revision: u64) -> MessageContext {
    MessageContext {
        network_profile_id: draft().network_profile_id,
        agreement_id: draft().agreement_id,
        proposal_id: NONBINDING_INTENT_CONTEXT.into(),
        proposal_revision: revision,
        sender_id: "participant-one".into(),
        recipient_id: draft().organizer_identity,
        artifact_kind: ArtifactKind::ParticipationIntent,
    }
}
fn file(revision: u64, sequence: u64, when: &Timestamp) -> EncryptedEnvelope {
    let intent: ParticipationIntent = serde_json::from_value(json!({"intent_id":"intent-one","agreement_id":draft().agreement_id,"participant_id":"participant-one",
        "desired_contribution":"1000000000","maximum_net_debit":"1000010000","fee_cap":"10000","conditions":["PRIVATE-INTENT-SYNTHETIC-CANARY"],"valid_until":null,"status":"active"})).unwrap();
    let prepared = prepare_intent_message(
        ExportRequest {
            context: context(revision),
            order: MessageOrder {
                message_id: format!("{sequence:032x}"),
                sequence,
                issued_at: when.clone(),
                expires_at: at(when, 600),
            },
            purpose: "Private synthetic intent".into(),
            persistence_warning: "Recipient can retain this explicitly chosen data.".into(),
        },
        TransportIntent {
            schema_version: 1,
            expected_agreement_revision: revision,
            intent,
        },
        &secret(11).public_key().unwrap(),
        &secret(22).public_key().unwrap(),
        when,
    )
    .unwrap();
    let digest = prepared.preview().digest().unwrap();
    prepared.seal(&secret(11), &digest, when).unwrap()
}
struct Fixture {
    dir: tempfile::TempDir,
    engine: Engine,
    runtime: ProtectedTransportRuntime,
    keys: Arc<SyntheticKeys>,
    consent: Arc<SyntheticConsent>,
}
impl Fixture {
    fn new() -> Self {
        let dir = private_dir();
        let engine = Engine::from_store(
            Store::create_encrypted(
                dir.path().join("engine.db"),
                &DatabaseKey::from_bytes([71; 32]),
            )
            .unwrap(),
        );
        engine
            .create(&owner(), "create-synthetic-agreement", draft())
            .unwrap();
        engine
            .grant_transport_peer(
                &owner(),
                "explicit-synthetic-peer-grant",
                &draft().agreement_id,
                1,
                grant(),
            )
            .unwrap();
        let inbox = SqliteReplayLedger::from_encrypted_connection(
            create_encrypted(
                dir.path().join("inbox.db"),
                &DatabaseKey::from_bytes([72; 32]),
            )
            .unwrap(),
        )
        .unwrap();
        let outbox = SqliteOutbox::from_encrypted_connection(
            create_encrypted(
                dir.path().join("outbox.db"),
                &DatabaseKey::from_bytes([73; 32]),
            )
            .unwrap(),
        )
        .unwrap();
        let keys = Arc::new(SyntheticKeys::new());
        let consent = Arc::new(SyntheticConsent::new());
        let runtime = ProtectedTransportRuntime::new(
            engine.clone(),
            inbox,
            outbox,
            keys.clone(),
            consent.clone(),
        )
        .unwrap();
        Self {
            dir,
            engine,
            runtime,
            keys,
            consent,
        }
    }
    fn stage(&mut self) -> ProtectedTransportSummary {
        self.runtime
            .stage_incoming(&owner(), context(2), &file(2, 1, &now()))
            .unwrap()
    }
}

#[test]
fn native_staging_exposes_only_scoped_metadata_and_exact_idempotent_import() {
    let mut f = Fixture::new();
    let staged = f.stage();
    let body = serde_json::to_string(&staged).unwrap();
    for private in [
        "PRIVATE-INTENT-SYNTHETIC-CANARY",
        "1000000000",
        "local_secret",
        "ciphertext",
        "fields",
        "sender_key_fingerprint",
    ] {
        assert!(!body.contains(private));
    }
    assert_eq!(staged.mailbox_storage, "encrypted");
    assert!(!staged.authorization_allowed);
    assert_eq!(staged.domain_status, "pending");
    let other = Access {
        include_owned_agreements: true,
        principal_id: "other".into(),
        agreement_ids: [draft().agreement_id].into(),
        all_agreements: false,
    };
    assert!(
        f.runtime
            .preview(&other, &draft().agreement_id, &staged.handle)
            .is_err()
    );
    assert!(
        f.runtime
            .preview(&owner(), "wrong-agreement", &staged.handle)
            .is_err()
    );
    assert_eq!(
        f.runtime
            .import(
                &owner(),
                &draft().agreement_id,
                &staged.handle,
                "wrong-command-key-0001",
                2
            )
            .err()
            .unwrap()
            .code,
        "IDEMPOTENCY_CONFLICT"
    );
    assert_eq!(
        f.engine
            .get(&owner(), &draft().agreement_id)
            .unwrap()
            .revision,
        2
    );
    let imported = f
        .runtime
        .import(
            &owner(),
            &draft().agreement_id,
            &staged.handle,
            staged.idempotency_key.as_deref().unwrap(),
            staged.expected_revision.unwrap(),
        )
        .unwrap();
    let replay = f
        .runtime
        .import(
            &owner(),
            &draft().agreement_id,
            &staged.handle,
            staged.idempotency_key.as_deref().unwrap(),
            2,
        )
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.operation_id, imported.operation_id);
    assert_eq!(
        f.engine
            .get(&owner(), &draft().agreement_id)
            .unwrap()
            .revision,
        3
    );
    assert_eq!(
        f.runtime
            .preview(&owner(), &draft().agreement_id, &staged.handle)
            .unwrap()
            .domain_status,
        "applied"
    );
    for entry in std::fs::read_dir(f.dir.path()).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        assert!(
            !bytes
                .windows(b"PRIVATE-INTENT-SYNTHETIC-CANARY".len())
                .any(|b| b == b"PRIVATE-INTENT-SYNTHETIC-CANARY")
        );
    }
}

#[test]
fn consent_key_rotation_and_peer_revocation_are_checked_even_on_completed_replay() {
    let mut f = Fixture::new();
    let staged = f.stage();
    let key = staged.idempotency_key.as_deref().unwrap();
    f.runtime
        .import(&owner(), &draft().agreement_id, &staged.handle, key, 2)
        .unwrap();
    f.consent.access.store(false, Ordering::SeqCst);
    assert_eq!(
        f.runtime
            .import(&owner(), &draft().agreement_id, &staged.handle, key, 2)
            .err()
            .unwrap()
            .code,
        "PERMISSION_DENIED"
    );
    assert!(
        f.runtime
            .list(&owner(), &draft().agreement_id)
            .unwrap()
            .is_empty()
    );
    f.consent.access.store(true, Ordering::SeqCst);
    f.keys.local_byte.store(33, Ordering::SeqCst);
    assert_eq!(
        f.runtime
            .preview(&owner(), &draft().agreement_id, &staged.handle)
            .err()
            .unwrap()
            .code,
        "PERMISSION_DENIED"
    );
    f.keys.local_byte.store(22, Ordering::SeqCst);
    f.engine
        .revoke_transport_peer(
            &owner(),
            "revoke-synthetic-peer-now",
            &draft().agreement_id,
            3,
            "peer-grant",
        )
        .unwrap();
    assert_eq!(
        f.runtime
            .import(&owner(), &draft().agreement_id, &staged.handle, key, 2)
            .err()
            .unwrap()
            .code,
        "PERMISSION_DENIED"
    );
    assert!(
        f.runtime
            .list(&owner(), &draft().agreement_id)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn invitation_export_requires_native_exact_disclosure_consent_and_recovers_same_bytes() {
    let mut f = Fixture::new();
    let now = now();
    let invitation = PrivateInvitation {
        schema_version: 1,
        invitation_id: "12".repeat(16),
        organizer_key_fingerprint: secret(22).public_key().unwrap().fingerprint(),
        invited_participant_id: "participant-one".into(),
        agreement_manifest_digest: f
            .engine
            .invitation_agreement_digest(&owner(), &draft().agreement_id)
            .unwrap(),
        offered_roles: vec![InvitationRole::Contributor],
        purpose: draft().purpose,
        recipient_summary: "Synthetic receiving instructions remain unverified.".into(),
        fee_summary: "Fees need a later exact approval.".into(),
        visibility_summary: "Read-only invitation only.".into(),
        coordination_deadline: at(&now, 1200),
    };
    let request = InvitationExportRequest {
        expected_agreement_revision: 2,
        transport: ExportRequest {
            context: MessageContext {
                network_profile_id: draft().network_profile_id,
                agreement_id: draft().agreement_id,
                proposal_id: "invitation-review".into(),
                proposal_revision: 1,
                sender_id: draft().organizer_identity,
                recipient_id: "participant-one".into(),
                artifact_kind: ArtifactKind::Invitation,
            },
            order: MessageOrder {
                message_id: "34".repeat(16),
                sequence: 1,
                issued_at: now.clone(),
                expires_at: at(&now, 600),
            },
            purpose: "Private invitation review".into(),
            persistence_warning: "The invited recipient can retain this preview.".into(),
        },
        invitation,
    };
    let staged = f.runtime.stage_invitation(&owner(), request).unwrap();
    assert_eq!(staged.delivery_status, "awaiting_native_disclosure_consent");
    assert_eq!(
        f.runtime
            .seal_invitation_export(&owner(), &draft().agreement_id, &staged.handle)
            .err()
            .unwrap()
            .code,
        "PERMISSION_DENIED"
    );
    assert!(
        f.runtime
            .retrieve_encrypted_export(&owner(), &draft().agreement_id, &staged.handle)
            .is_err()
    );
    f.consent.disclosure.store(true, Ordering::SeqCst);
    assert_eq!(
        f.runtime
            .seal_invitation_export(&owner(), &draft().agreement_id, &staged.handle)
            .unwrap()
            .delivery_status,
        "encrypted_export_ready"
    );
    let bytes = f
        .runtime
        .retrieve_encrypted_export(&owner(), &draft().agreement_id, &staged.handle)
        .unwrap()
        .as_bytes()
        .to_vec();
    f.runtime
        .seal_invitation_export(&owner(), &draft().agreement_id, &staged.handle)
        .unwrap();
    assert_eq!(
        f.runtime
            .retrieve_encrypted_export(&owner(), &draft().agreement_id, &staged.handle)
            .unwrap()
            .as_bytes(),
        bytes
    );
    f.consent.disclosure.store(false, Ordering::SeqCst);
    assert_eq!(
        f.runtime
            .retrieve_encrypted_export(&owner(), &draft().agreement_id, &staged.handle)
            .err()
            .unwrap()
            .code,
        "PERMISSION_DENIED"
    );
    // The revoker starts after lease acquisition and must wait for the exact
    // ciphertext handoff to finish. Every later read observes revocation.
    f.consent.disclosure.store(true, Ordering::SeqCst);
    f.consent.revoke_on_retrieve.store(true, Ordering::SeqCst);
    assert_eq!(
        f.runtime
            .retrieve_encrypted_export(&owner(), &draft().agreement_id, &staged.handle)
            .unwrap()
            .as_bytes(),
        bytes
    );
    f.consent
        .revocation
        .lock()
        .unwrap()
        .take()
        .unwrap()
        .join()
        .unwrap();
    assert!(
        f.runtime
            .retrieve_encrypted_export(&owner(), &draft().agreement_id, &staged.handle)
            .is_err()
    );
    assert_eq!(
        f.engine
            .get(&owner(), &draft().agreement_id)
            .unwrap()
            .revision,
        3
    );
}

#[test]
fn lease_scope_substitution_cannot_authorize_read_or_import() {
    let mut f = Fixture::new();
    let staged = f.stage();
    f.consent.substitute_scope.store(true, Ordering::SeqCst);
    assert!(
        f.runtime
            .preview(&owner(), &draft().agreement_id, &staged.handle)
            .is_err()
    );
    assert!(
        f.runtime
            .import(
                &owner(),
                &draft().agreement_id,
                &staged.handle,
                staged.idempotency_key.as_deref().unwrap(),
                2
            )
            .is_err()
    );
    assert_eq!(
        f.engine
            .get(&owner(), &draft().agreement_id)
            .unwrap()
            .revision,
        2
    );
}

#[test]
fn restart_loses_handles_but_explicit_native_recovery_reconciles_the_same_operation() {
    let mut f = Fixture::new();
    let staged = f.stage();
    let original = f
        .runtime
        .import(
            &owner(),
            &draft().agreement_id,
            &staged.handle,
            staged.idempotency_key.as_deref().unwrap(),
            2,
        )
        .unwrap();
    let Fixture {
        dir,
        engine,
        runtime,
        keys,
        consent,
    } = f;
    drop(runtime);
    let inbox = SqliteReplayLedger::from_encrypted_connection(
        open_encrypted(
            dir.path().join("inbox.db"),
            &DatabaseKey::from_bytes([72; 32]),
        )
        .unwrap(),
    )
    .unwrap();
    let outbox = SqliteOutbox::from_encrypted_connection(
        open_encrypted(
            dir.path().join("outbox.db"),
            &DatabaseKey::from_bytes([73; 32]),
        )
        .unwrap(),
    )
    .unwrap();
    let mut runtime = ProtectedTransportRuntime::new(engine, inbox, outbox, keys, consent).unwrap();
    assert!(
        runtime
            .list(&owner(), &draft().agreement_id)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        runtime
            .preview(&owner(), &draft().agreement_id, &staged.handle)
            .err()
            .unwrap()
            .code,
        "NOT_FOUND"
    );
    let recovered = runtime.stage_recovered(&owner(), context(2), 1).unwrap();
    assert!(recovered.historical);
    assert_eq!(recovered.domain_status, "applied");
    assert_eq!(recovered.idempotency_key, staged.idempotency_key);
    let replay = runtime
        .import(
            &owner(),
            &draft().agreement_id,
            &recovered.handle,
            recovered.idempotency_key.as_deref().unwrap(),
            2,
        )
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.operation_id, original.operation_id);
}

#[test]
fn legacy_ciphertext_only_mailboxes_cannot_be_labeled_protected() {
    let f = Fixture::new();
    let inbox = SqliteReplayLedger::open(f.dir.path().join("metadata-plaintext-inbox.db")).unwrap();
    let outbox = SqliteOutbox::open(f.dir.path().join("metadata-plaintext-outbox.db")).unwrap();
    assert_eq!(
        ProtectedTransportRuntime::new(
            f.engine.clone(),
            inbox,
            outbox,
            f.keys.clone(),
            f.consent.clone()
        )
        .err()
        .unwrap()
        .code,
        "ENCRYPTED_STORAGE_REQUIRED"
    );
    let inbox = SqliteReplayLedger::from_encrypted_connection(
        create_encrypted(
            f.dir.path().join("other-inbox.db"),
            &DatabaseKey::from_bytes([75; 32]),
        )
        .unwrap(),
    )
    .unwrap();
    let outbox = SqliteOutbox::from_encrypted_connection(
        create_encrypted(
            f.dir.path().join("other-outbox.db"),
            &DatabaseKey::from_bytes([76; 32]),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        ProtectedTransportRuntime::new(
            Engine::in_memory().unwrap(),
            inbox,
            outbox,
            f.keys,
            f.consent
        )
        .err()
        .unwrap()
        .code,
        "ENCRYPTED_STORAGE_REQUIRED"
    );
}

fn http_request(
    method: &str,
    path: &str,
    token: &str,
    csrf: Option<&str>,
    key: Option<&str>,
    revision: Option<u64>,
    body: &str,
) -> axum::http::Request<axum::body::Body> {
    let mut request = axum::http::Request::builder()
        .method(method)
        .uri(path)
        .header("Host", "127.0.0.1:4318")
        .header("Origin", "http://127.0.0.1:4319")
        .header("Authorization", format!("Bearer {token}"));
    if method == "POST" {
        request = request.header("Content-Type", "application/json");
    }
    if let Some(csrf) = csrf {
        request = request.header("X-Wholepact-CSRF", csrf);
    }
    if let Some(key) = key {
        request = request.header("Idempotency-Key", key);
    }
    if let Some(revision) = revision {
        request = request.header("If-Match", format!("\"{revision}\""));
    }
    request
        .body(axum::body::Body::from(body.to_owned()))
        .unwrap()
}
async fn response_json(response: axum::response::Response) -> serde_json::Value {
    use http_body_util::BodyExt;
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

#[tokio::test]
async fn protected_router_exposes_metadata_and_exact_import_under_authenticated_csrf_scopes() {
    use axum::http::StatusCode;
    use tower::ServiceExt;
    use wholepact_service::{
        application_with_transport,
        security::{ClientConfig, Permission, SecurityConfig},
    };
    let mut fixture = Fixture::new();
    let staged = fixture.stage();
    let (invitation_context, invitation_file) = incoming_invitation();
    let invitation = fixture
        .runtime
        .stage_incoming(&owner(), invitation_context, &invitation_file)
        .unwrap();
    let Fixture {
        dir: _dir,
        engine,
        runtime,
        keys: _keys,
        consent,
    } = fixture;
    const OWNER_TOKEN: &str = "synthetic-owner-bootstrap-not-a-real-secret";
    const READER_TOKEN: &str = "synthetic-reader-bootstrap-not-a-real-secret";
    let config = SecurityConfig {
        clients: vec![
            ClientConfig {
                include_owned_agreements: true,
                client_id: "owner".into(),
                bootstrap_token: OWNER_TOKEN.into(),
                permissions: [Permission::Read, Permission::Coordinate].into(),
                agreement_ids: [draft().agreement_id].into(),
                all_agreements: false,
            },
            ClientConfig {
                include_owned_agreements: true,
                client_id: "reader".into(),
                bootstrap_token: READER_TOKEN.into(),
                permissions: [Permission::Read].into(),
                agreement_ids: [draft().agreement_id].into(),
                all_agreements: false,
            },
        ],
        allowed_origins: ["http://127.0.0.1:4319".into()].into(),
    };
    let app = application_with_transport(runtime, config, 4318, true).unwrap();
    let session = response_json(
        app.clone()
            .oneshot(http_request(
                "GET",
                "/v1/session",
                OWNER_TOKEN,
                None,
                None,
                None,
                "",
            ))
            .await
            .unwrap(),
    )
    .await;
    let reader = response_json(
        app.clone()
            .oneshot(http_request(
                "GET",
                "/v1/session",
                READER_TOKEN,
                None,
                None,
                None,
                "",
            ))
            .await
            .unwrap(),
    )
    .await;
    let token = session["session_token"].as_str().unwrap();
    let csrf = session["csrf_token"].as_str().unwrap();
    let invitation_path = format!("/v1/invitations/{}", invitation.handle);
    for path in ["/v1/invitations", invitation_path.as_str()] {
        let response = app
            .clone()
            .oneshot(http_request("GET", path, token, None, None, None, ""))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await.to_string();
        assert!(!body.contains("ciphertext") && !body.contains("local_secret"));
        if path == invitation_path {
            assert!(body.contains("Fresh private invitation canary"));
        }
    }
    let cross_invitation = app
        .clone()
        .oneshot(http_request(
            "GET",
            &invitation_path,
            reader["session_token"].as_str().unwrap(),
            None,
            None,
            None,
            "",
        ))
        .await
        .unwrap();
    assert_eq!(cross_invitation.status(), StatusCode::NOT_FOUND);
    let list_path = format!("/v1/agreements/{}/transport", draft().agreement_id);
    let preview_path = format!("{list_path}/{}", staged.handle);
    let import_path = format!("{preview_path}/import");
    for path in [&list_path, &preview_path] {
        let response = app
            .clone()
            .oneshot(http_request("GET", path, token, None, None, None, ""))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await.to_string();
        assert!(!body.contains("PRIVATE-INTENT-SYNTHETIC-CANARY"));
        assert!(!body.contains("1000000000"));
        assert!(!body.contains("ciphertext"));
        assert!(!body.contains("local_secret"));
    }
    let cross = app
        .clone()
        .oneshot(http_request(
            "GET",
            &preview_path,
            reader["session_token"].as_str().unwrap(),
            None,
            None,
            None,
            "",
        ))
        .await
        .unwrap();
    assert_eq!(cross.status(), StatusCode::NOT_FOUND);
    let key = staged.idempotency_key.as_deref().unwrap();
    let csrf_denied = app
        .clone()
        .oneshot(http_request(
            "POST",
            &import_path,
            token,
            None,
            Some(key),
            Some(2),
            "{}",
        ))
        .await
        .unwrap();
    assert_eq!(csrf_denied.status(), StatusCode::FORBIDDEN);
    let permission_denied = app
        .clone()
        .oneshot(http_request(
            "POST",
            &import_path,
            reader["session_token"].as_str().unwrap(),
            reader["csrf_token"].as_str(),
            Some(key),
            Some(2),
            "{}",
        ))
        .await
        .unwrap();
    assert_eq!(permission_denied.status(), StatusCode::FORBIDDEN);
    for (wrong_key, revision) in [("wrong-staged-key-command-0001", 2), (key, 3)] {
        let wrong = app
            .clone()
            .oneshot(http_request(
                "POST",
                &import_path,
                token,
                Some(csrf),
                Some(wrong_key),
                Some(revision),
                "{}",
            ))
            .await
            .unwrap();
        assert_eq!(wrong.status(), StatusCode::CONFLICT);
    }
    assert_eq!(
        engine
            .get(&owner(), &draft().agreement_id)
            .unwrap()
            .revision,
        2
    );
    let injected = app
        .clone()
        .oneshot(http_request(
            "POST",
            &import_path,
            token,
            Some(csrf),
            Some(key),
            Some(2),
            "{\"ciphertext\":\"not-accepted\"}",
        ))
        .await
        .unwrap();
    assert_eq!(injected.status(), StatusCode::BAD_REQUEST);
    let imported = app
        .clone()
        .oneshot(http_request(
            "POST",
            &import_path,
            token,
            Some(csrf),
            Some(key),
            Some(2),
            "{}",
        ))
        .await
        .unwrap();
    assert_eq!(imported.status(), StatusCode::OK);
    let original_operation = imported.headers()["x-operation-id"]
        .to_str()
        .unwrap()
        .to_owned();
    let original = response_json(imported).await;
    assert_eq!(original["revision"], 3);
    let repeated = app
        .clone()
        .oneshot(http_request(
            "POST",
            &import_path,
            token,
            Some(csrf),
            Some(key),
            Some(2),
            "{}",
        ))
        .await
        .unwrap();
    assert_eq!(repeated.status(), StatusCode::OK);
    assert_eq!(repeated.headers()["x-idempotent-replay"], "true");
    assert_eq!(repeated.headers()["x-operation-id"], original_operation);
    let repeated = response_json(repeated).await;
    assert_eq!(original, repeated);
    assert!(!repeated.to_string().contains("ciphertext"));
    assert!(!repeated.to_string().contains("local_secret"));
    consent.access.store(false, Ordering::SeqCst);
    let revoked_gate = app
        .clone()
        .oneshot(http_request(
            "POST",
            &import_path,
            token,
            Some(csrf),
            Some(key),
            Some(2),
            "{}",
        ))
        .await
        .unwrap();
    assert_eq!(revoked_gate.status(), StatusCode::FORBIDDEN);
    consent.access.store(true, Ordering::SeqCst);
    engine
        .revoke_transport_peer(
            &owner(),
            "revoke-peer-after-http-import",
            &draft().agreement_id,
            3,
            "peer-grant",
        )
        .unwrap();
    let revoked_peer = app
        .clone()
        .oneshot(http_request(
            "POST",
            &import_path,
            token,
            Some(csrf),
            Some(key),
            Some(2),
            "{}",
        ))
        .await
        .unwrap();
    assert_eq!(revoked_peer.status(), StatusCode::FORBIDDEN);
}

fn incoming_invitation() -> (MessageContext, EncryptedEnvelope) {
    let now = now();
    let context = MessageContext {
        network_profile_id: draft().network_profile_id,
        agreement_id: "fresh-private-agreement".into(),
        proposal_id: "invitation-review".into(),
        proposal_revision: 1,
        sender_id: "remote-organizer".into(),
        recipient_id: "local-invitee".into(),
        artifact_kind: ArtifactKind::Invitation,
    };
    let prepared = prepare_invitation(
        ExportRequest {
            context: context.clone(),
            order: MessageOrder {
                message_id: "45".repeat(16),
                sequence: 1,
                issued_at: now.clone(),
                expires_at: at(&now, 600),
            },
            purpose: "Selected invitation review".into(),
            persistence_warning: "Selected private text is retained locally.".into(),
        },
        PrivateInvitation {
            schema_version: 1,
            invitation_id: "67".repeat(16),
            organizer_key_fingerprint: secret(11).public_key().unwrap().fingerprint(),
            invited_participant_id: "local-invitee".into(),
            agreement_manifest_digest: "89".repeat(32),
            offered_roles: vec![InvitationRole::Reviewer],
            purpose: "Fresh private invitation canary".into(),
            recipient_summary: "Selected recipient summary".into(),
            fee_summary: "Fees need independent review".into(),
            visibility_summary: "Only selected invitation text".into(),
            coordination_deadline: at(&now, 1200),
        },
        &secret(11).public_key().unwrap(),
        &secret(22).public_key().unwrap(),
        &now,
    )
    .unwrap();
    let digest = prepared.preview().digest().unwrap();
    (context, prepared.seal(&secret(11), &digest, &now).unwrap())
}
#[test]
fn fresh_invitation_is_durable_read_only_without_agreement_or_participant_grants() {
    let mut f = Fixture::new();
    let (context, file) = incoming_invitation();
    assert!(f.engine.get(&owner(), &context.agreement_id).is_err());
    let staged = f
        .runtime
        .stage_incoming(&owner(), context.clone(), &file)
        .unwrap();
    assert_eq!(staged.domain_status, "read_only_invitation_imported");
    assert!(staged.expected_revision.is_none() && staged.idempotency_key.is_none());
    let view = f
        .runtime
        .received_invitation(&owner(), &staged.handle)
        .unwrap();
    assert_eq!(view.invitation.purpose, "Fresh private invitation canary");
    assert_eq!(
        view.sender_key_fingerprint,
        secret(11).public_key().unwrap().fingerprint()
    );
    assert!(
        !view.participant_enrolled
            && !view.wallet_control_verified
            && !view.human_identity_verified
            && !view.recipient_ownership_verified
            && !view.summary.authorization_allowed
    );
    assert!(f.engine.get(&owner(), &context.agreement_id).is_err());
    assert!(
        f.runtime
            .import(
                &owner(),
                &context.agreement_id,
                &staged.handle,
                "not-an-enrollment",
                0
            )
            .is_err()
    );
    assert!(
        f.runtime
            .received_invitation(
                &Access {
                    include_owned_agreements: true,
                    principal_id: "another-client".into(),
                    ..Access::default()
                },
                &staged.handle
            )
            .is_err()
    );
    let recovered = f.runtime.stage_recovered(&owner(), context, 1).unwrap();
    let replay = f
        .runtime
        .received_invitation(&owner(), &recovered.handle)
        .unwrap();
    assert!(replay.summary.historical);
    assert_eq!(replay.local_retention_id, view.local_retention_id);
    assert_eq!(replay.original_message_id, view.original_message_id);
    f.consent.access.store(false, Ordering::SeqCst);
    assert!(
        f.runtime
            .received_invitation(&owner(), &staged.handle)
            .is_err()
    );
    assert!(
        f.runtime
            .list_received_invitations(&owner())
            .unwrap()
            .is_empty()
    );
}

struct DeniedRecords;
impl wholepact_engine::participant_records::ParticipantRecordAuthority for DeniedRecords {
    fn acquire<'a>(
        &'a self,
        _: &wholepact_engine::participant_records::ParticipantRecordScope,
        _: &wholepact_core::records::ObservationWindow,
    ) -> std::result::Result<
        Box<dyn wholepact_engine::participant_records::ParticipantRecordLease + 'a>,
        ApiError,
    > {
        Err(ApiError::new(
            "PERMISSION_DENIED",
            "No synthetic record access requested",
        ))
    }
}
fn synthetic_config() -> wholepact_service::security::SecurityConfig {
    use wholepact_service::security::*;
    SecurityConfig {
        clients: vec![ClientConfig {
            include_owned_agreements: true,
            client_id: "owner".into(),
            bootstrap_token: "synthetic-bootstrap-not-a-real-secret".into(),
            permissions: [Permission::Read].into(),
            agreement_ids: [].into(),
            all_agreements: false,
        }],
        allowed_origins: ["http://127.0.0.1:4319".into()].into(),
    }
}
#[test]
fn combined_runtime_requires_the_exact_same_open_encrypted_store() {
    use wholepact_service::{
        application_with_transport_and_records, protected_records::ProtectedRecordsRuntime,
    };
    let f = Fixture::new();
    let records = ProtectedRecordsRuntime::new(
        f.engine.clone(),
        draft().network_profile_id,
        Arc::new(DeniedRecords),
        60,
    )
    .unwrap();
    assert!(
        application_with_transport_and_records(f.runtime, records, synthetic_config(), 4318, true)
            .is_ok()
    );
    let f = Fixture::new();
    let other = Engine::from_store(
        Store::open_encrypted(
            f.dir.path().join("engine.db"),
            &DatabaseKey::from_bytes([71; 32]),
        )
        .unwrap(),
    );
    let records = ProtectedRecordsRuntime::new(
        other,
        draft().network_profile_id,
        Arc::new(DeniedRecords),
        60,
    )
    .unwrap();
    assert!(
        application_with_transport_and_records(f.runtime, records, synthetic_config(), 4318, true)
            .is_err()
    );
}

// Production portable runtime composed with explicitly synthetic consent/key and
// domain-validation fixtures. These bytes are not a cryptographic transaction.
fn portable_request(context: MessageContext, issued: &Timestamp) -> ExportRequest {
    ExportRequest {
        context,
        order: MessageOrder {
            message_id: "ab".repeat(16),
            sequence: 1,
            issued_at: issued.clone(),
            expires_at: at(issued, 300),
        },
        purpose: "synthetic selected participant delivery".into(),
        persistence_warning: "Copies cannot be recalled".into(),
    }
}
fn portable_field() -> DisclosureField {
    DisclosureField::new(
        "finalized_transaction_v1",
        b"SYNTHETIC-TRANSACTION-NOT-PAYMENT".to_vec(),
    )
    .unwrap()
}
fn reopen_portable(f: &mut Fixture) {
    f.runtime = ProtectedTransportRuntime::new(
        f.engine.clone(),
        SqliteReplayLedger::from_encrypted_connection(
            open_encrypted(
                f.dir.path().join("inbox.db"),
                &DatabaseKey::from_bytes([72; 32]),
            )
            .unwrap(),
        )
        .unwrap(),
        SqliteOutbox::from_encrypted_connection(
            open_encrypted(
                f.dir.path().join("outbox.db"),
                &DatabaseKey::from_bytes([73; 32]),
            )
            .unwrap(),
        )
        .unwrap(),
        f.keys.clone(),
        f.consent.clone(),
    )
    .unwrap();
}
#[test]
fn portable_delivery_is_exact_across_restart_denial_and_changed_payload() {
    let mut f = Fixture::new();
    let mut context = context(2);
    context.artifact_kind = ArtifactKind::FinalTransaction;
    let time = now();
    assert!(
        f.runtime
            .deliver_portable(
                &owner(),
                portable_request(context.clone(), &time),
                portable_field(),
                false,
                &|| Ok(()),
                |_, _| -> std::result::Result<(), ApiError> { panic!("denied callback") }
            )
            .is_err()
    );
    f.consent.disclosure.store(true, Ordering::SeqCst);
    let first = f
        .runtime
        .deliver_portable(
            &owner(),
            portable_request(context.clone(), &time),
            portable_field(),
            false,
            &|| Ok(()),
            |envelope, _| Ok(envelope.as_bytes().to_vec()),
        )
        .unwrap();
    reopen_portable(&mut f);
    let retry = f
        .runtime
        .deliver_portable(
            &owner(),
            portable_request(context.clone(), &time),
            portable_field(),
            true,
            &|| Ok(()),
            |envelope, _| Ok(envelope.as_bytes().to_vec()),
        )
        .unwrap();
    assert_eq!(first, retry);
    assert!(
        f.runtime
            .deliver_portable(
                &owner(),
                portable_request(context.clone(), &time),
                DisclosureField::new("finalized_transaction_v1", b"changed".to_vec()).unwrap(),
                false,
                &|| Ok(()),
                |_, _| -> std::result::Result<(), ApiError> { panic!("changed bytes callback") }
            )
            .is_err()
    );
    f.keys.peer_byte.store(33, Ordering::SeqCst);
    assert!(
        f.runtime
            .deliver_portable(
                &owner(),
                portable_request(context, &time),
                portable_field(),
                true,
                &|| Ok(()),
                |_, _| -> std::result::Result<(), ApiError> {
                    panic!("changed recipient key callback")
                }
            )
            .is_err()
    );
}
#[test]
fn portable_import_checks_before_retention_and_recovers_exact_denied_read() {
    use wholepact_service::protected_transport::portable::PortableSource;
    let mut f = Fixture::new();
    let mut context = context(2);
    context.artifact_kind = ArtifactKind::FinalTransaction;
    let time = now();
    let prepared = prepare_export(
        portable_request(context.clone(), &time),
        vec![portable_field()],
        &secret(11).public_key().unwrap(),
        &secret(22).public_key().unwrap(),
        &time,
    )
    .unwrap();
    let digest = prepared.preview().digest().unwrap();
    let envelope = prepared.seal(&secret(11), &digest, &time).unwrap();
    let reject = |_: &[u8]| {
        Err(ApiError::new(
            "SYNTHETIC_SCHEMA_REJECTED",
            "fixture validation denial",
        ))
    };
    assert!(
        f.runtime
            .import_portable(
                &owner(),
                context.clone(),
                PortableSource::Incoming(&envelope),
                reject,
                |_, _, _| -> std::result::Result<(), ApiError> { panic!("malformed callback") }
            )
            .is_err()
    );
    assert!(
        f.runtime
            .import_portable(
                &owner(),
                context.clone(),
                PortableSource::Retained(1),
                |_| Ok(()),
                |_, _, _| -> std::result::Result<(), ApiError> { panic!("invalid data retained") }
            )
            .is_err()
    );
    // Validation success is deliberately fixture-only, never payment evidence.
    assert!(
        f.runtime
            .import_portable(
                &owner(),
                context.clone(),
                PortableSource::Incoming(&envelope),
                |_| Ok(()),
                |_, _, _| Err::<(), _>(ApiError::new("USER_DENIED", "no plaintext file written"))
            )
            .is_err()
    );
    reopen_portable(&mut f);
    let (bytes, key) = f
        .runtime
        .import_portable(
            &owner(),
            context.clone(),
            PortableSource::Retained(1),
            |_| Ok(()),
            |bytes, key, _| Ok((bytes.to_vec(), key.to_string())),
        )
        .unwrap();
    assert_eq!(bytes, portable_field().bytes());
    let replay_key = f
        .runtime
        .import_portable(
            &owner(),
            context.clone(),
            PortableSource::Retained(1),
            |_| Ok(()),
            |_, key, _| Ok(key.to_string()),
        )
        .unwrap();
    assert_eq!(key, replay_key);
    assert!(
        f.runtime
            .import_portable(
                &owner(),
                context.clone(),
                PortableSource::Incoming(&envelope),
                |_| Ok(()),
                |_, _, _| -> std::result::Result<(), ApiError> { panic!("new duplicate delivery") }
            )
            .is_err()
    );
    context.recipient_id = "wrong-recipient".into();
    assert!(
        f.runtime
            .import_portable(
                &owner(),
                context,
                PortableSource::Incoming(&envelope),
                |_| Ok(()),
                |_, _, _| -> std::result::Result<(), ApiError> { panic!("wrong recipient") }
            )
            .is_err()
    );
}

#[test]
fn portable_effect_guard_rejects_authority_lost_during_final_prompt() {
    use wholepact_service::protected_transport::portable::PortableSource;
    let mut f = Fixture::new();
    f.consent.disclosure.store(true, Ordering::SeqCst);
    let consent = f.consent.clone();
    let mut context = context(2);
    context.artifact_kind = ArtifactKind::FinalTransaction;
    let time = now();
    let wrote = AtomicBool::new(false);
    assert!(
        f.runtime
            .deliver_portable(
                &owner(),
                portable_request(context.clone(), &time),
                portable_field(),
                false,
                &|| Ok(()),
                |_, current| {
                    // Simulate expiry/cancellation while native confirmation was pending.
                    consent.access.store(false, Ordering::SeqCst);
                    current()?;
                    wrote.store(true, Ordering::SeqCst);
                    Ok(())
                }
            )
            .is_err()
    );
    assert!(!wrote.load(Ordering::SeqCst));
    consent.access.store(true, Ordering::SeqCst);
    let prepared = prepare_export(
        portable_request(context.clone(), &time),
        vec![portable_field()],
        &secret(11).public_key().unwrap(),
        &secret(22).public_key().unwrap(),
        &time,
    )
    .unwrap();
    let digest = prepared.preview().digest().unwrap();
    let envelope = prepared.seal(&secret(11), &digest, &time).unwrap();
    assert!(
        f.runtime
            .import_portable(
                &owner(),
                context,
                PortableSource::Incoming(&envelope),
                |_| Ok(()),
                |_, _, current| {
                    consent.access.store(false, Ordering::SeqCst);
                    current()?;
                    wrote.store(true, Ordering::SeqCst);
                    Ok(())
                }
            )
            .is_err()
    );
    assert!(!wrote.load(Ordering::SeqCst));
}
