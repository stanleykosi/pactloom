//! Optional protected native composition. HTTP receives only scoped metadata and
//! opaque handles. No key, ciphertext, filename, arbitrary path, clock value or
//! caller-supplied approval crosses the browser request boundary.
#[cfg(all(feature = "signer-release", target_os = "linux"))]
pub mod signature_intake;
#[cfg(all(feature = "signer-release", target_os = "linux"))]
mod authorization;
#[cfg(feature = "proposal-review")]
mod proposal_review;
pub mod portable;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use wholepact_engine::{
    transport_workflows::{InvitationExportRequest, TransportImportRequirements},
    Access, ApiError, Engine, Mutation,
};
use wholepact_transport::{
    open_envelope, random_message_id, recover_received, ArtifactKind, DeliveryStatus,
    DisclosureField, DisclosurePreview, DomainImportResult, DomainOutcome, EncryptedEnvelope,
    MailboxProtection, MessageContext, PreparedExport, RecoveredArtifact, SqliteOutbox,
    SqliteReplayLedger, Timestamp, TransportError, TransportPublicKey, TransportSecret,
};

type Result<T> = std::result::Result<T, ApiError>;
pub const MAX_PROTECTED_TRANSPORT_HANDLES: usize = 64;
pub const PROTECTED_HANDLE_LIFETIME_SECONDS: i64 = 15 * 60;

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportDirection {
    Incoming,
    Outgoing,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LocalTransportAction {
    RetainIncoming,
    /// Read/restage original retained history without renewing protocol expiry.
    ReadRetained,
    /// Native-only held exact signature intake; does not grant account attribution.
    ReadAuthorization,
    PrepareInvitation,
    ReadSummary,
    ReadInvitation,
    ImportNonbinding,
    SealExport,
    RetrieveEncryptedExport,
}

/// Native-only key lookup. The controller must independently bind these labels to
/// its protected local identity and pinned peer; transport labels are not proof of
/// human identity or wallet ownership. No default implementation exists.
pub struct TransportKeyScope {
    pub principal_id: String,
    pub context: MessageContext,
    pub direction: TransportDirection,
}
pub struct ProtectedTransportKeys {
    pub local_secret: TransportSecret,
    pub pinned_peer: TransportPublicKey,
}
pub trait LocalTransportKeyController: Send + Sync {
    fn keys(&self, scope: &TransportKeyScope) -> Result<ProtectedTransportKeys>;
}

/// Exact-scope native consent and current local access. For disclosure, the gate
/// must present/check the actual immutable fields and destination and authenticate
/// consent to preview.digest(). A browser request or digest is never approval.
/// The provider must serialize revocation and pinned-key rotation with the held
/// exact-scope lease through commit or native handoff. A bool snapshot cannot do
/// this. No default authority or consent implementation exists.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalTransportScope {
    pub principal_id: String,
    pub agreement_id: String,
    pub context: MessageContext,
    pub artifact_fingerprint: String,
}
/// Native authority guard. Implementations hold their controller's revocation
/// fence until drop. check_current also rejects expiry or external cancellation;
/// it does not replace that fence. The scope covers the exact preview (including
/// keys, context and disclosure fields), principal and requested action.
pub trait LocalTransportLease {
    fn scope(&self) -> &LocalTransportScope;
    fn action(&self) -> LocalTransportAction;
    fn expires_at(&self) -> &Timestamp;
    fn check_current(&self) -> Result<()>;
}
pub trait LocalTransportConsent: Send + Sync {
    fn acquire<'a>(
        &'a self,
        scope: &LocalTransportScope,
        action: LocalTransportAction,
        preview: &DisclosurePreview,
        fields: &[DisclosureField],
    ) -> Result<Box<dyn LocalTransportLease + 'a>>;
}

#[derive(Clone, Serialize)]
pub struct ProtectedTransportSummary {
    pub handle: String,
    pub agreement_id: String,
    pub artifact_kind: ArtifactKind,
    pub direction: TransportDirection,
    pub artifact_fingerprint: String,
    pub expected_revision: Option<u64>,
    pub idempotency_key: Option<String>,
    pub currently_valid: bool,
    pub historical: bool,
    pub handle_expires_at: String,
    pub delivery_status: String,
    pub domain_status: String,
    pub authorization_allowed: bool,
    pub mailbox_storage: &'static str,
}

/// Explicitly selected read-only invitation content. Sender provenance is a
/// pinned transport key, never a verified human, wallet or recipient ownership.
#[derive(Clone, Serialize)]
pub struct ProtectedInvitationView {
    pub summary: ProtectedTransportSummary,
    pub invitation: wholepact_transport::PrivateInvitation,
    pub sender_id: String,
    pub recipient_id: String,
    pub sender_key_fingerprint: String,
    pub recipient_key_fingerprint: String,
    pub original_message_id: String,
    pub issued_at: String,
    pub expires_at: String,
    pub local_retention_id: String,
    pub participant_enrolled: bool,
    pub human_identity_verified: bool,
    pub wallet_control_verified: bool,
    pub recipient_ownership_verified: bool,
}

#[derive(Clone)]
struct Binding {
    handle: String,
    principal_id: String,
    context: MessageContext,
    direction: TransportDirection,
    preview: DisclosurePreview,
    artifact_fingerprint: String,
    handle_expires_at: Timestamp,
    historical: bool,
}
struct StagedEntry {
    binding: Binding,
    prepared: Option<PreparedExport>,
}

/// Created only by an embedding with verified encrypted journals and explicit
/// native controllers. The ordinary service factory never constructs this runtime.
/// The App owns its synchronization; methods perform no networking or filesystem
/// path selection. In-memory handles disappear on restart; exact ciphertext remains
/// durable and can be explicitly restaged by the protected native controller.
pub struct ProtectedTransportRuntime {
    engine: Engine,
    inbox: SqliteReplayLedger,
    outbox: SqliteOutbox,
    #[cfg(all(feature = "signer-release", target_os = "linux"))]
    authorization_outbox: Option<wholepact_signer_release::AuthorizationOutbox>,
    keys: Arc<dyn LocalTransportKeyController>,
    consent: Arc<dyn LocalTransportConsent>,
    staged: BTreeMap<String, StagedEntry>,
}
impl ProtectedTransportRuntime {
    pub fn new(
        engine: Engine,
        inbox: SqliteReplayLedger,
        outbox: SqliteOutbox,
        keys: Arc<dyn LocalTransportKeyController>,
        consent: Arc<dyn LocalTransportConsent>,
    ) -> Result<Self> {
        if engine.storage_protection() != "encrypted_local_metadata"
            || inbox.protection() != MailboxProtection::Encrypted
            || outbox.protection() != MailboxProtection::Encrypted
        {
            return Err(ApiError::new(
                "ENCRYPTED_STORAGE_REQUIRED",
                "Protected transport requires verified encrypted engine, inbox and outbox storage",
            ));
        }
        if engine.transport_recovery_required()? {
            return Err(quarantined());
        }
        Ok(Self {
            engine,
            inbox,
            outbox,
            #[cfg(all(feature = "signer-release", target_os = "linux"))]
            authorization_outbox: None,
            keys,
            consent,
            staged: BTreeMap::new(),
        })
    }
    /// Signer-release runtime construction is all-or-nothing. The adapter must
    /// authenticate the exact same database as the ordinary transport owner.
    #[cfg(all(feature = "signer-release", target_os = "linux"))]
    pub fn new_with_signer_release(
        engine: Engine, inbox: SqliteReplayLedger, outbox: SqliteOutbox,
        authorization_outbox: wholepact_signer_release::AuthorizationOutbox,
        keys: Arc<dyn LocalTransportKeyController>, consent: Arc<dyn LocalTransportConsent>,
    ) -> Result<Self> {
        authorization_outbox.check_binding(&outbox).map_err(transport_error)?;
        let mut runtime = Self::new(engine, inbox, outbox, keys, consent)?;
        runtime.authorization_outbox = Some(authorization_outbox);
        Ok(runtime)
    }
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    pub fn list(
        &self,
        access: &Access,
        agreement_id: &str,
    ) -> Result<Vec<ProtectedTransportSummary>> {
        self.current_owner(access, agreement_id)?;
        let now = trusted_now()?;
        let mut summaries = Vec::new();
        for entry in self.staged.values() {
            if entry.binding.principal_id != access.principal_id
                || entry.binding.context.agreement_id != agreement_id
                || now.unix_seconds() >= entry.binding.handle_expires_at.unix_seconds()
            {
                continue;
            }
            match self.preview_at(access, &entry.binding, &now) {
                Ok(summary) => summaries.push(summary),
                // Revoked/rotated scopes reveal neither payload nor handle presence.
                Err(error)
                    if error.code == "PERMISSION_DENIED"
                        || error.code == "AUTHENTICATION_REQUIRED" => {}
                Err(error) => return Err(error),
            }
        }
        Ok(summaries)
    }
    pub fn preview(
        &self,
        access: &Access,
        agreement_id: &str,
        handle: &str,
    ) -> Result<ProtectedTransportSummary> {
        let binding = self.binding(access, agreement_id, handle, &trusted_now()?)?;
        self.preview_at(access, &binding, &trusted_now()?)
    }
    /// Read-only invitation inbox, including agreements not present in Engine.
    /// Independent native key/consent authority, rather than an agreement ID or
    /// organizer assertion, controls every access. No agreement grant is created.
    pub fn list_received_invitations(
        &self,
        access: &Access,
    ) -> Result<Vec<ProtectedTransportSummary>> {
        if self.engine.transport_recovery_required()? {
            return Err(quarantined());
        }
        let now = trusted_now()?;
        let mut summaries = Vec::new();
        for entry in self.staged.values() {
            let b = &entry.binding;
            if !received_invitation(b)
                || b.principal_id != access.principal_id
                || now.unix_seconds() >= b.handle_expires_at.unix_seconds()
            {
                continue;
            }
            match self.preview_at(access, b, &now) {
                Ok(summary) => summaries.push(summary),
                Err(e) if e.code == "PERMISSION_DENIED" || e.code == "AUTHENTICATION_REQUIRED" => {}
                Err(e) => return Err(e),
            }
        }
        Ok(summaries)
    }
    pub fn received_invitation(
        &self,
        access: &Access,
        handle: &str,
    ) -> Result<ProtectedInvitationView> {
        let entry = self.staged.get(handle).ok_or_else(not_found)?;
        let binding = self.binding(
            access,
            &entry.binding.context.agreement_id,
            handle,
            &trusted_now()?,
        )?;
        if !received_invitation(&binding) {
            return Err(not_found());
        }
        let summary = self.preview_at(access, &binding, &trusted_now()?)?;
        let keys = self.current_keys(access, &binding)?;
        let recovered = self.recover(&binding, &keys)?;
        let authority = self.consent.clone();
        let lease = self.acquire_consent(
            authority.as_ref(),
            access,
            &binding,
            LocalTransportAction::ReadInvitation,
            recovered.artifact().fields(),
        )?;
        let review = wholepact_transport::review_invitation(recovered.artifact())
            .map_err(transport_error)?;
        let ticket = self
            .inbox
            .domain_import_ticket(recovered.artifact(), &invitation_processor(access))
            .map_err(transport_error)?;
        if ticket.completed() != Some(&invitation_result(&binding)) {
            return Err(denied());
        }
        check_lease(lease.as_ref())?;
        Ok(ProtectedInvitationView {
            summary,
            invitation: review.invitation().clone(),
            sender_id: binding.context.sender_id.clone(),
            recipient_id: binding.context.recipient_id.clone(),
            sender_key_fingerprint: binding.preview.sender_key_fingerprint.clone(),
            recipient_key_fingerprint: binding.preview.recipient_key_fingerprint.clone(),
            original_message_id: binding.preview.order.message_id.clone(),
            issued_at: binding.preview.order.issued_at.as_str().into(),
            expires_at: binding.preview.order.expires_at.as_str().into(),
            local_retention_id: ticket.idempotency_key().into(),
            participant_enrolled: false,
            human_identity_verified: false,
            wallet_control_verified: false,
            recipient_ownership_verified: false,
        })
    }

    pub fn import(
        &mut self,
        access: &Access,
        agreement_id: &str,
        handle: &str,
        key: &str,
        revision: u64,
    ) -> Result<Mutation> {
        let now = trusted_now()?;
        let binding = self.binding(access, agreement_id, handle, &now)?;
        if binding.direction != TransportDirection::Incoming
            || !nonbinding(binding.context.artifact_kind)
        {
            return Err(ApiError::new("UNSUPPORTED_CAPABILITY", "Only staged nonbinding intents or withdrawals can be imported through this endpoint"));
        }
        let keys = self.current_keys(access, &binding)?;
        let recovered = self.recover(&binding, &keys)?;
        let authority = self.consent.clone();
        let lease = self.acquire_consent(
            authority.as_ref(),
            access,
            &binding,
            LocalTransportAction::ImportNonbinding,
            recovered.artifact().fields(),
        )?;
        let requirements = self.engine.nonbinding_transport_requirements(
            access,
            &self.inbox,
            recovered.artifact(),
            &now,
        )?;
        if requirements.idempotency_key != key
            || requirements.expected_agreement_revision != revision
        {
            return Err(ApiError::new(
                "IDEMPOTENCY_CONFLICT",
                "Use the staged artifact's original exact idempotency key and expected revision",
            ));
        }
        // A gate/controller callback may have changed grants. The engine checks
        // current ownership/enrollment again and its write uses aggregate CAS.
        let result = self.engine.import_nonbinding_transport(
            access,
            &mut self.inbox,
            recovered.artifact(),
            &trusted_now()?,
        )?;
        check_lease(lease.as_ref())?;
        Ok(result)
    }

    /// Native-only intake. The native file picker/controller supplies the encrypted
    /// file and independently expected context; HTTP must never expose this method.
    /// Accepted ciphertext remains safely retained even if later consent is denied.
    pub fn stage_incoming(
        &mut self,
        access: &Access,
        expected: MessageContext,
        envelope: &EncryptedEnvelope,
    ) -> Result<ProtectedTransportSummary> {
        if expected.artifact_kind == ArtifactKind::Invitation {
            if self.engine.transport_recovery_required()? {
                return Err(quarantined());
            }
        } else {
            self.current_owner(access, &expected.agreement_id)?;
        }
        self.reserve_handle()?;
        if !nonbinding(expected.artifact_kind) && expected.artifact_kind != ArtifactKind::Invitation
        {
            return Err(ApiError::new("UNSUPPORTED_CAPABILITY", "This protected runtime only stages invitations and nonbinding participation messages"));
        }
        let keys = self.keys.keys(&TransportKeyScope {
            principal_id: access.principal_id.clone(),
            context: expected.clone(),
            direction: TransportDirection::Incoming,
        })?;
        let now = trusted_now()?;
        let received = open_envelope(
            envelope,
            &keys.local_secret,
            &keys.pinned_peer,
            &expected,
            &now,
            &mut self.inbox,
        )
        .map_err(transport_error)?;
        let binding = binding(
            access,
            received.preview(),
            TransportDirection::Incoming,
            false,
            &now,
        )?;
        let authority = self.consent.clone();
        let lease = self.acquire_consent(
            authority.as_ref(),
            access,
            &binding,
            LocalTransportAction::RetainIncoming,
            received.fields(),
        )?;
        if nonbinding(expected.artifact_kind) {
            self.engine
                .nonbinding_transport_requirements(access, &self.inbox, &received, &now)?;
        } else {
            wholepact_transport::review_invitation(&received).map_err(transport_error)?;
            let ticket = self
                .inbox
                .domain_import_ticket(&received, &invitation_processor(access))
                .map_err(transport_error)?;
            check_lease(lease.as_ref())?;
            self.inbox
                .complete_domain_import(&ticket, invitation_result(&binding))
                .map_err(transport_error)?;
        }
        self.staged.insert(
            binding.handle.clone(),
            StagedEntry {
                binding: binding.clone(),
                prepared: None,
            },
        );
        check_lease(lease.as_ref())?;
        drop(lease);
        self.preview_at(access, &binding, &trusted_now()?)
    }

    /// Native-only read-only recovery. Retained ciphertext is authenticated again;
    /// it never becomes a new transport delivery or refreshes its original expiry.
    pub fn stage_recovered(
        &mut self,
        access: &Access,
        expected: MessageContext,
        sequence: u64,
    ) -> Result<ProtectedTransportSummary> {
        if expected.artifact_kind == ArtifactKind::Invitation {
            if self.engine.transport_recovery_required()? {
                return Err(quarantined());
            }
        } else {
            self.current_owner(access, &expected.agreement_id)?;
        }
        self.reserve_handle()?;
        if !nonbinding(expected.artifact_kind) && expected.artifact_kind != ArtifactKind::Invitation
        {
            return Err(ApiError::new(
                "UNSUPPORTED_CAPABILITY",
                "This protected runtime cannot import this recovered artifact kind",
            ));
        }
        let keys = self.keys.keys(&TransportKeyScope {
            principal_id: access.principal_id.clone(),
            context: expected.clone(),
            direction: TransportDirection::Incoming,
        })?;
        let retained = self
            .inbox
            .retained_for_context(&expected, sequence)
            .map_err(transport_error)?
            .ok_or_else(not_found)?;
        let recovered =
            recover_received(&retained, &keys.local_secret, &keys.pinned_peer, &expected)
                .map_err(transport_error)?;
        let now = trusted_now()?;
        let binding = binding(
            access,
            recovered.artifact().preview(),
            TransportDirection::Incoming,
            true,
            &now,
        )?;
        let authority = self.consent.clone();
        let lease = self.acquire_consent(
            authority.as_ref(),
            access,
            &binding,
            LocalTransportAction::ReadRetained,
            recovered.artifact().fields(),
        )?;
        if nonbinding(expected.artifact_kind) {
            self.engine.nonbinding_transport_requirements(
                access,
                &self.inbox,
                recovered.artifact(),
                &now,
            )?;
        } else {
            wholepact_transport::review_invitation(recovered.artifact())
                .map_err(transport_error)?;
            let ticket = self
                .inbox
                .domain_import_ticket(recovered.artifact(), &invitation_processor(access))
                .map_err(transport_error)?;
            check_lease(lease.as_ref())?;
            self.inbox
                .complete_domain_import(&ticket, invitation_result(&binding))
                .map_err(transport_error)?;
        }
        self.staged.insert(
            binding.handle.clone(),
            StagedEntry {
                binding: binding.clone(),
                prepared: None,
            },
        );
        check_lease(lease.as_ref())?;
        drop(lease);
        self.preview_at(access, &binding, &trusted_now()?)
    }

    /// Native-only exact invitation preparation. It never enrolls a participant,
    /// infers user consent or seals a file by itself.
    pub fn stage_invitation(
        &mut self,
        access: &Access,
        request: InvitationExportRequest,
    ) -> Result<ProtectedTransportSummary> {
        self.current_owner(access, &request.transport.context.agreement_id)?;
        self.reserve_handle()?;
        let keys = self.keys.keys(&TransportKeyScope {
            principal_id: access.principal_id.clone(),
            context: request.transport.context.clone(),
            direction: TransportDirection::Outgoing,
        })?;
        let now = trusted_now()?;
        let prepared = self.engine.prepare_private_invitation(
            access,
            request,
            &keys.local_secret.public_key().map_err(transport_error)?,
            &keys.pinned_peer,
            &now,
        )?;
        let binding = binding(
            access,
            prepared.preview(),
            TransportDirection::Outgoing,
            false,
            &now,
        )?;
        let authority = self.consent.clone();
        let lease = self.acquire_consent(
            authority.as_ref(),
            access,
            &binding,
            LocalTransportAction::PrepareInvitation,
            prepared.fields(),
        )?;
        self.staged.insert(
            binding.handle.clone(),
            StagedEntry {
                binding: binding.clone(),
                prepared: Some(prepared),
            },
        );
        check_lease(lease.as_ref())?;
        drop(lease);
        self.preview_at(access, &binding, &trusted_now()?)
    }

    /// Restage an already committed outgoing invitation after restart, including
    /// expired history. The original selected source reconstructs its ORIGINAL
    /// preview at its issued timestamp solely to authenticate equality with the
    /// durable outbox digest. It is never treated as currently valid, enqueued,
    /// re-sealed, or given a new message identity/sequence/expiry.
    /// Missing or changed original source fails closed; HPKE ciphertext cannot be
    /// decrypted by its sender to invent a replacement preview.
    pub fn stage_committed_invitation(
        &mut self,
        access: &Access,
        original: InvitationExportRequest,
    ) -> Result<ProtectedTransportSummary> {
        self.current_owner(access, &original.transport.context.agreement_id)?;
        if original.transport.context.artifact_kind != ArtifactKind::Invitation {
            return Err(ApiError::new(
                "UNSUPPORTED_CAPABILITY",
                "Only exact already-committed invitation history can be restaged",
            ));
        }
        self.reserve_handle()?;
        let keys = self.keys.keys(&TransportKeyScope {
            principal_id: access.principal_id.clone(),
            context: original.transport.context.clone(),
            direction: TransportDirection::Outgoing,
        })?;
        let original_issued = original.transport.order.issued_at.clone();
        let prepared = wholepact_transport::prepare_invitation(
            original.transport,
            original.invitation,
            &keys.local_secret.public_key().map_err(transport_error)?,
            &keys.pinned_peer,
            &original_issued,
        )
        .map_err(transport_error)?;
        let committed = self
            .outbox
            .recover_for_recipient(
                &prepared.preview().context,
                &keys.pinned_peer,
                prepared.preview().order.sequence,
            )
            .map_err(transport_error)?
            .ok_or_else(not_found)?;
        if committed.preview_digest() != prepared.preview().digest().map_err(transport_error)? {
            return Err(ApiError::new(
                "PERMISSION_DENIED",
                "The supplied original preview does not match the exact committed encrypted export",
            ));
        }
        let now = trusted_now()?;
        let binding = binding(
            access,
            prepared.preview(),
            TransportDirection::Outgoing,
            true,
            &now,
        )?;
        let authority = self.consent.clone();
        let lease = self.acquire_consent(
            authority.as_ref(),
            access,
            &binding,
            LocalTransportAction::ReadRetained,
            prepared.fields(),
        )?;
        check_lease(lease.as_ref())?;
        self.staged.insert(
            binding.handle.clone(),
            StagedEntry {
                binding: binding.clone(),
                prepared: None,
            },
        );
        check_lease(lease.as_ref())?;
        drop(lease);
        self.preview_at(access, &binding, &trusted_now()?)
    }

    /// Native-only exact export. The injected native consent gate must authenticate
    /// a current decision on the actual selected fields, destination and preview.
    /// No HTTP route calls this method. Returned metadata contains no ciphertext.
    pub fn seal_invitation_export(
        &mut self,
        access: &Access,
        agreement_id: &str,
        handle: &str,
    ) -> Result<ProtectedTransportSummary> {
        let now = trusted_now()?;
        let binding = self.binding(access, agreement_id, handle, &now)?;
        if binding.direction != TransportDirection::Outgoing
            || binding.context.artifact_kind != ArtifactKind::Invitation
            || binding.historical
        {
            return Err(ApiError::new(
                "UNSUPPORTED_CAPABILITY",
                "Only native prepared invitations can be exported by this runtime",
            ));
        }
        let fields = self
            .staged
            .get(handle)
            .and_then(|entry| entry.prepared.as_ref())
            .map(|prepared| prepared.fields())
            .unwrap_or(&[]);
        let authority = self.consent.clone();
        let lease = self.acquire_consent(
            authority.as_ref(),
            access,
            &binding,
            LocalTransportAction::SealExport,
            fields,
        )?;
        let keys = self.current_keys(access, &binding)?;
        // If the previous call committed before an interrupted response, recover
        // that exact ciphertext; never create another envelope or new sequence.
        if self
            .outbox
            .recover_for_recipient(
                &binding.context,
                &keys.pinned_peer,
                binding.preview.order.sequence,
            )
            .map_err(transport_error)?
            .is_none()
        {
            let prepared = self.staged.get_mut(handle).and_then(|entry| entry.prepared.take()).ok_or_else(|| ApiError::new("RECOVERY_REQUIRED", "No committed ciphertext or retained preparation exists; explicitly restage the original local source"))?;
            self.outbox
                .enqueue(
                    prepared,
                    &keys.local_secret,
                    &binding.artifact_fingerprint,
                    &now,
                )
                .map_err(transport_error)?;
        }
        check_lease(lease.as_ref())?;
        drop(lease);
        self.preview_at(access, &binding, &trusted_now()?)
    }

    /// Native-only handoff of already committed ciphertext to a user-selected
    /// local file delivery adapter. This does not send, upload or choose a path.
    /// Do not expose these bytes through a browser-facing endpoint.
    pub fn retrieve_encrypted_export(
        &self,
        access: &Access,
        agreement_id: &str,
        handle: &str,
    ) -> Result<EncryptedEnvelope> {
        let binding = self.binding(access, agreement_id, handle, &trusted_now()?)?;
        if binding.direction != TransportDirection::Outgoing {
            return Err(not_found());
        }
        let keys = self.current_keys(access, &binding)?;
        let authority = self.consent.clone();
        let lease = self.acquire_consent(
            authority.as_ref(),
            access,
            &binding,
            LocalTransportAction::RetrieveEncryptedExport,
            &[],
        )?;
        let record = self
            .outbox
            .recover_for_recipient(
                &binding.context,
                &keys.pinned_peer,
                binding.preview.order.sequence,
            )
            .map_err(transport_error)?
            .ok_or_else(not_found)?;
        if record.preview_digest() != binding.artifact_fingerprint {
            return Err(denied());
        }
        let envelope = EncryptedEnvelope::from_bytes(record.envelope().as_bytes().to_vec())
            .map_err(transport_error)?;
        check_lease(lease.as_ref())?;
        Ok(envelope)
    }

    fn current_owner(&self, access: &Access, agreement_id: &str) -> Result<()> {
        if self.engine.transport_recovery_required()? {
            return Err(quarantined());
        }
        self.engine.transport_peer_grants(access, agreement_id)?;
        Ok(())
    }
    fn reserve_handle(&mut self) -> Result<()> {
        let now = trusted_now()?;
        self.staged
            .retain(|_, entry| entry.binding.handle_expires_at.unix_seconds() > now.unix_seconds());
        if self.staged.len() >= MAX_PROTECTED_TRANSPORT_HANDLES {
            return Err(ApiError::new(
                "RESOURCE_EXHAUSTED",
                "Protected native staging handles are full",
            ));
        }
        Ok(())
    }
    fn binding(
        &self,
        access: &Access,
        agreement_id: &str,
        handle: &str,
        now: &Timestamp,
    ) -> Result<Binding> {
        let entry = self.staged.get(handle).ok_or_else(not_found)?;
        if entry.binding.principal_id != access.principal_id
            || entry.binding.context.agreement_id != agreement_id
            || now.unix_seconds() >= entry.binding.handle_expires_at.unix_seconds()
        {
            return Err(not_found());
        }
        self.current_scope(access, &entry.binding)?;
        Ok(entry.binding.clone())
    }
    fn current_scope(&self, access: &Access, binding: &Binding) -> Result<()> {
        if binding.principal_id != access.principal_id {
            return Err(not_found());
        }
        if received_invitation(binding) {
            if self.engine.transport_recovery_required()? {
                return Err(quarantined());
            }
            Ok(())
        } else {
            self.current_owner(access, &binding.context.agreement_id)
        }
    }
    fn current_keys(&self, access: &Access, binding: &Binding) -> Result<ProtectedTransportKeys> {
        self.current_scope(access, binding)?;
        if binding.principal_id != access.principal_id {
            return Err(not_found());
        }
        let keys = self.keys.keys(&TransportKeyScope {
            principal_id: access.principal_id.clone(),
            context: binding.context.clone(),
            direction: binding.direction,
        })?;
        let local = keys
            .local_secret
            .public_key()
            .map_err(transport_error)?
            .fingerprint();
        let peer = keys.pinned_peer.fingerprint();
        let valid = match binding.direction {
            TransportDirection::Incoming => {
                local == binding.preview.recipient_key_fingerprint
                    && peer == binding.preview.sender_key_fingerprint
            }
            TransportDirection::Outgoing => {
                local == binding.preview.sender_key_fingerprint
                    && peer == binding.preview.recipient_key_fingerprint
            }
        };
        if !valid {
            return Err(denied());
        }
        Ok(keys)
    }
    fn acquire_consent<'a>(
        &self,
        authority: &'a dyn LocalTransportConsent,
        access: &Access,
        binding: &Binding,
        action: LocalTransportAction,
        fields: &[DisclosureField],
    ) -> Result<Box<dyn LocalTransportLease + 'a>> {
        self.current_scope(access, binding)?;
        let scope = LocalTransportScope {
            principal_id: access.principal_id.clone(),
            agreement_id: binding.context.agreement_id.clone(),
            context: binding.context.clone(),
            artifact_fingerprint: binding.artifact_fingerprint.clone(),
        };
        let lease = authority.acquire(&scope, action, &binding.preview, fields)?;
        if lease.scope() != &scope || lease.action() != action {
            return Err(denied());
        }
        check_lease(lease.as_ref())?;
        // Recheck under the held controller fence, including key rotation that
        // happened while native consent was being authenticated.
        self.current_scope(access, binding)?;
        self.current_keys(access, binding)?;
        Ok(lease)
    }
    fn recover(
        &self,
        binding: &Binding,
        keys: &ProtectedTransportKeys,
    ) -> Result<RecoveredArtifact> {
        let retained = self
            .inbox
            .retained_for_context(&binding.context, binding.preview.order.sequence)
            .map_err(transport_error)?
            .ok_or_else(not_found)?;
        let recovered = recover_received(
            &retained,
            &keys.local_secret,
            &keys.pinned_peer,
            &binding.context,
        )
        .map_err(transport_error)?;
        if recovered
            .artifact()
            .preview()
            .digest()
            .map_err(transport_error)?
            != binding.artifact_fingerprint
        {
            return Err(denied());
        }
        Ok(recovered)
    }
    fn preview_at(
        &self,
        access: &Access,
        binding: &Binding,
        now: &Timestamp,
    ) -> Result<ProtectedTransportSummary> {
        let keys = self.current_keys(access, binding)?;
        let authority = self.consent.clone();
        let lease = self.acquire_consent(
            authority.as_ref(),
            access,
            binding,
            LocalTransportAction::ReadSummary,
            &[],
        )?;
        let (requirements, delivery_status, domain_status) = match binding.direction {
            TransportDirection::Incoming => {
                let recovered = self.recover(binding, &keys)?;
                if nonbinding(binding.context.artifact_kind) {
                    let required = self.engine.nonbinding_transport_requirements(
                        access,
                        &self.inbox,
                        recovered.artifact(),
                        now,
                    )?;
                    let status = if required.domain_completed {
                        "applied"
                    } else {
                        "pending"
                    };
                    (Some(required), "authenticated_inbox".into(), status.into())
                } else {
                    wholepact_transport::review_invitation(recovered.artifact())
                        .map_err(transport_error)?;
                    let ticket = self
                        .inbox
                        .domain_import_ticket(recovered.artifact(), &invitation_processor(access))
                        .map_err(transport_error)?;
                    if ticket.completed() != Some(&invitation_result(binding)) {
                        return Err(denied());
                    }
                    (
                        None,
                        "authenticated_inbox".into(),
                        "read_only_invitation_imported".into(),
                    )
                }
            }
            TransportDirection::Outgoing => {
                let status = match self
                    .outbox
                    .recover_for_recipient(
                        &binding.context,
                        &keys.pinned_peer,
                        binding.preview.order.sequence,
                    )
                    .map_err(transport_error)?
                {
                    Some(record) => {
                        if record.preview_digest() != binding.artifact_fingerprint {
                            return Err(denied());
                        }
                        match record.delivery_status() {
                            DeliveryStatus::AwaitingRecipientReceipt => "encrypted_export_ready",
                            DeliveryStatus::RecipientReceiptRecorded => {
                                "recipient_receipt_recorded"
                            }
                        }
                    }
                    None => {
                        if self
                            .staged
                            .get(&binding.handle)
                            .is_some_and(|entry| entry.prepared.is_some())
                        {
                            "awaiting_native_disclosure_consent"
                        } else {
                            "restage_required"
                        }
                    }
                };
                (None, status.into(), "not_applicable".into())
            }
        };
        check_lease(lease.as_ref())?;
        Ok(summary(
            binding,
            now,
            requirements,
            delivery_status,
            domain_status,
        ))
    }
}
fn binding(
    access: &Access,
    preview: &DisclosurePreview,
    direction: TransportDirection,
    historical: bool,
    now: &Timestamp,
) -> Result<Binding> {
    Ok(Binding {
        handle: random_message_id().map_err(transport_error)?,
        principal_id: access.principal_id.clone(),
        context: preview.context.clone(),
        direction,
        preview: preview.clone(),
        artifact_fingerprint: preview.digest().map_err(transport_error)?,
        handle_expires_at: Timestamp::from_unix_seconds(
            now.unix_seconds()
                .checked_add(PROTECTED_HANDLE_LIFETIME_SECONDS)
                .ok_or_else(denied)?,
        )
        .map_err(transport_error)?,
        historical,
    })
}
fn summary(
    binding: &Binding,
    now: &Timestamp,
    requirements: Option<TransportImportRequirements>,
    delivery_status: String,
    domain_status: String,
) -> ProtectedTransportSummary {
    let currently_valid = now.unix_seconds() >= binding.preview.order.issued_at.unix_seconds()
        && now.unix_seconds() < binding.preview.order.expires_at.unix_seconds();
    ProtectedTransportSummary {
        handle: binding.handle.clone(),
        agreement_id: binding.context.agreement_id.clone(),
        artifact_kind: binding.context.artifact_kind,
        direction: binding.direction,
        artifact_fingerprint: binding.artifact_fingerprint.clone(),
        expected_revision: requirements.as_ref().map(|r| r.expected_agreement_revision),
        idempotency_key: requirements.map(|r| r.idempotency_key),
        currently_valid,
        historical: binding.historical || !currently_valid,
        handle_expires_at: binding.handle_expires_at.as_str().into(),
        delivery_status,
        domain_status,
        authorization_allowed: false,
        mailbox_storage: "encrypted",
    }
}
fn received_invitation(binding: &Binding) -> bool {
    binding.direction == TransportDirection::Incoming
        && binding.context.artifact_kind == ArtifactKind::Invitation
}
fn invitation_processor(access: &Access) -> String {
    // Receipt completion binds local retention to this authenticated principal.
    // It creates no agreement Access, membership or reusable transport authority.
    format!(
        "invitation-read-v1-{}",
        hex::encode(Sha256::digest(access.principal_id.as_bytes()))
    )
}
fn invitation_result(binding: &Binding) -> DomainImportResult {
    DomainImportResult {
        outcome: DomainOutcome::Applied,
        result_digest: binding.artifact_fingerprint.clone(),
    }
}
fn nonbinding(kind: ArtifactKind) -> bool {
    matches!(
        kind,
        ArtifactKind::ParticipationIntent | ArtifactKind::IntentWithdrawal
    )
}
fn trusted_now() -> Result<Timestamp> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ApiError::new("INVALID_TIME", "Trusted local clock is unavailable"))?
        .as_secs();
    Timestamp::from_unix_seconds(
        i64::try_from(seconds)
            .map_err(|_| ApiError::new("INVALID_TIME", "Trusted local clock is out of range"))?,
    )
    .map_err(transport_error)
}
fn check_lease(lease: &dyn LocalTransportLease) -> Result<()> {
    if lease.expires_at().unix_seconds() <= trusted_now()?.unix_seconds() {
        return Err(denied());
    }
    lease.check_current()
}
fn denied() -> ApiError {
    ApiError::new(
        "PERMISSION_DENIED",
        "Current native transport consent or exact pinned key binding is unavailable",
    )
}
fn not_found() -> ApiError {
    ApiError::new(
        "NOT_FOUND",
        "Protected artifact handle is absent, expired or outside this principal and agreement",
    )
}
fn quarantined() -> ApiError {
    ApiError::new(
        "RECOVERY_REQUIRED",
        "Restored transport grants and journals cannot establish current authority",
    )
}
fn transport_error(error: TransportError) -> ApiError {
    let code = match error {
        TransportError::Storage => "STORAGE_UNAVAILABLE",
        TransportError::ResourceLimit => "RESOURCE_EXHAUSTED",
        TransportError::Authentication => "AUTHENTICATION_REQUIRED",
        TransportError::Replay => "TRANSPORT_REPLAY",
        TransportError::DisclosureDenied => "DISCLOSURE_DENIED",
        TransportError::InvalidTime => "INVALID_TIME",
        _ => "INVALID_TRANSPORT_ARTIFACT",
    };
    ApiError::new(code, &error.to_string())
}
