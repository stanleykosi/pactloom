//! Nonbinding, explicitly enrolled transport peers. Transport authentication binds
//! a scoped peer key to a message; it never verifies wallet or real-world identity.
//! The organizer's current local grant is checked even when returning an old replay.
use super::*;
#[cfg(feature = "candidate-construction")]
pub mod proposal_review;
use wholepact_transport::{
    ArtifactKind, DisclosureField, DomainImportResult, DomainOutcome, ExportRequest,
    PreparedExport, PrivateInvitation, ReceivedArtifact, SqliteReplayLedger, Timestamp,
    TransportError, TransportPublicKey, prepare_export, prepare_invitation,
};

const PROCESSOR: &str = "engine-nonbinding-intents-v1";
const INTENT_FIELD: &str = "participation_intent_v1";
const WITHDRAWAL_FIELD: &str = "intent_withdrawal_v1";
pub const NONBINDING_INTENT_CONTEXT: &str = "nonbinding-intents-v1";
pub const MAX_TRANSPORT_PEER_GRANTS: usize = 128;
pub const MAX_PEER_GRANT_LIFETIME_SECONDS: i64 = 30 * 24 * 60 * 60;

/// Owner-approved enrollment of a specifically pinned transport peer, not an
/// assertion that this peer owns any wallet or represents a particular human.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportPeerGrantRequest {
    pub grant_id: String,
    pub participant_id: String,
    pub sender_key_fingerprint: String,
    pub recipient_id: String,
    pub recipient_key_fingerprint: String,
    pub allow_intent: bool,
    pub allow_withdrawal: bool,
    pub expires_at: Timestamp,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportPeerGrant {
    pub schema_version: u16,
    pub agreement_id: String,
    pub network_profile_id: String,
    pub enrolled_by_principal: String,
    pub request: TransportPeerGrantRequest,
    pub revoked: bool,
    #[serde(default)]
    pub recovery_required: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportIntent {
    pub schema_version: u16,
    pub expected_agreement_revision: u64,
    pub intent: ParticipationIntent,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportIntentWithdrawal {
    pub schema_version: u16,
    pub expected_agreement_revision: u64,
    pub participant_id: String,
    pub intent_id: String,
}

#[derive(Clone, Serialize)]
pub struct TransportImportRequirements {
    pub expected_agreement_revision: u64,
    pub idempotency_key: String,
    pub domain_completed: bool,
}

pub struct InvitationExportRequest {
    pub expected_agreement_revision: u64,
    pub transport: ExportRequest,
    pub invitation: PrivateInvitation,
}

impl Engine {
    fn require_protected_transport_store(&self) -> Result<()> {
        if self.store.protection() == wholepact_store::StorageProtection::PlaintextDevelopment {
            return Err(ApiError::new(
                "ENCRYPTED_STORAGE_REQUIRED",
                "Private transport peer grants and imported participation records require encrypted local storage",
            ));
        }
        if self.transport_recovery_required()? {
            return Err(ApiError::new(
                "RECOVERY_REQUIRED",
                "Restored transport peer grants remain quarantined until independent local authority reconciliation",
            ));
        }
        Ok(())
    }
    pub fn transport_recovery_required(&self) -> Result<bool> {
        self.store.runtime_recovery_required().map_err(store_error)
    }
    /// Explicit owner action. A peer cannot enroll itself merely by sending a file,
    /// knowing an agreement ID, or opening an invitation. Caller authentication and
    /// the service's administrative capability check remain outside the engine.
    pub fn grant_transport_peer(
        &self,
        access: &Access,
        key: &str,
        agreement_id: &str,
        revision: u64,
        request: TransportPeerGrantRequest,
    ) -> Result<Mutation> {
        self.require_protected_transport_store()?;
        if self
            .store
            .recovery_record_is_historical("agreement", agreement_id)
            .map_err(store_error)?
        {
            return Err(ApiError::new(
                "RECOVERY_REQUIRED",
                "Historical transport grants require separately reviewed reconciliation",
            ));
        }
        let command = context(
            access,
            key,
            "grant_transport_peer",
            agreement_id,
            Some(revision),
            &request,
        )?;
        let mut envelope = self.load(access, agreement_id)?;
        owner(&envelope, access)?;
        if let Some(replay) = self.replay(access, &command)? {
            return Ok(replay);
        }
        candidates::check_revision(&envelope, revision)?;
        validate_grant_request(
            &request,
            &envelope.view.agreement,
            OffsetDateTime::now_utc().unix_timestamp(),
        )?;
        if envelope.transport_peer_grants.len() >= MAX_TRANSPORT_PEER_GRANTS {
            return Err(ApiError::new(
                "RESOURCE_EXHAUSTED",
                "Transport peer grant history is full",
            ));
        }
        if envelope
            .transport_peer_grants
            .contains_key(&request.grant_id)
        {
            return Err(ApiError::new(
                "INVALID_TRANSITION",
                "Grant identity already exists; use a new explicit grant after revocation",
            ));
        }
        for value in envelope.transport_peer_grants.values() {
            let grant = decode_grant(value)?;
            if !grant.revoked
                && !grant.recovery_required
                && grant.request.expires_at.unix_seconds()
                    > OffsetDateTime::now_utc().unix_timestamp()
                && grant.request.participant_id == request.participant_id
            {
                return Err(ApiError::new(
                    "INVALID_TRANSITION",
                    "This participant already has an active transport peer grant",
                ));
            }
        }
        let grant = TransportPeerGrant {
            schema_version: 1,
            agreement_id: agreement_id.into(),
            network_profile_id: envelope.view.agreement.network_profile_id.clone(),
            enrolled_by_principal: access.principal_id.clone(),
            request,
            revoked: false,
            recovery_required: false,
        };
        envelope.transport_peer_grants.insert(
            grant.request.grant_id.clone(),
            serde_json::to_value(grant).map_err(|_| internal())?,
        );
        self.commit(
            &command,
            agreement_id,
            revision,
            envelope,
            "transport_peer_explicitly_enrolled",
        )
    }

    pub fn revoke_transport_peer(
        &self,
        access: &Access,
        key: &str,
        agreement_id: &str,
        revision: u64,
        grant_id: &str,
    ) -> Result<Mutation> {
        self.require_protected_transport_store()?;
        if self
            .store
            .recovery_record_is_historical("agreement", agreement_id)
            .map_err(store_error)?
        {
            return Err(ApiError::new(
                "RECOVERY_REQUIRED",
                "Historical transport grants require separately reviewed reconciliation",
            ));
        }
        valid_id(grant_id)?;
        let command = context(
            access,
            key,
            "revoke_transport_peer",
            agreement_id,
            Some(revision),
            &json!({"grant_id":grant_id}),
        )?;
        let mut envelope = self.load(access, agreement_id)?;
        owner(&envelope, access)?;
        if let Some(replay) = self.replay(access, &command)? {
            return Ok(replay);
        }
        candidates::check_revision(&envelope, revision)?;
        let mut grant = decode_grant(
            envelope
                .transport_peer_grants
                .get(grant_id)
                .ok_or_else(not_found)?,
        )?;
        grant.revoked = true;
        envelope.transport_peer_grants.insert(
            grant_id.into(),
            serde_json::to_value(grant).map_err(|_| internal())?,
        );
        self.commit(
            &command,
            agreement_id,
            revision,
            envelope,
            "transport_peer_revoked",
        )
    }

    pub fn transport_peer_grants(
        &self,
        access: &Access,
        agreement_id: &str,
    ) -> Result<Vec<TransportPeerGrant>> {
        let envelope = self.load(access, agreement_id)?;
        owner(&envelope, access)?;
        let recovery_required = self.transport_recovery_required()?
            || self
                .store
                .recovery_record_is_historical("agreement", agreement_id)
                .map_err(store_error)?;
        envelope
            .transport_peer_grants
            .values()
            .map(|value| {
                let mut grant = decode_grant(value)?;
                grant.recovery_required |= recovery_required;
                Ok(grant)
            })
            .collect()
    }

    pub fn invitation_agreement_digest(
        &self,
        access: &Access,
        agreement_id: &str,
    ) -> Result<String> {
        let envelope = self.load(access, agreement_id)?;
        owner(&envelope, access)?;
        agreement_digest(&envelope.view.agreement)
    }

    /// Prepare the exact invitation against current organizer-owned local terms.
    /// Durably closes local draft editing before any preparation escapes. This
    /// does not enroll the recipient or approve/export the disclosure.
    pub fn prepare_private_invitation(
        &self,
        access: &Access,
        request: InvitationExportRequest,
        sender: &TransportPublicKey,
        recipient: &TransportPublicKey,
        now: &Timestamp,
    ) -> Result<PreparedExport> {
        self.require_current_agreement(&request.transport.context.agreement_id)?;
        let mut envelope = self.load(access, &request.transport.context.agreement_id)?;
        owner(&envelope, access)?;
        let agreement = &envelope.view.agreement;
        if envelope.view.cancellation_requested
            || request.transport.context.network_profile_id != agreement.network_profile_id
            || request.transport.context.sender_id != agreement.organizer_identity
            || request.transport.context.proposal_revision != u64::from(agreement.revision)
            || request.invitation.agreement_manifest_digest != agreement_digest(agreement)?
            || request.invitation.purpose != agreement.purpose
        {
            return Err(ApiError::new(
                "INVALID_TERMS",
                "Invitation does not match the current organizer-owned agreement",
            ));
        }
        if let Some(deadline) = &agreement.coordination_deadline {
            let deadline = OffsetDateTime::parse(deadline, &Rfc3339).map_err(|_| internal())?;
            if request.invitation.coordination_deadline.unix_seconds() > deadline.unix_timestamp() {
                return Err(ApiError::new(
                    "INVALID_TERMS",
                    "Invitation cannot extend the agreement's coordination deadline",
                ));
            }
        }
        let prepared = prepare_invitation(
            request.transport,
            request.invitation,
            sender,
            recipient,
            now,
        )
        .map_err(transport_error)?;
        let id = envelope.view.agreement.agreement_id.clone();
        let fingerprint = prepared.preview().digest().map_err(transport_error)?;
        let command = context(
            access,
            &format!("invitation-close-{fingerprint}"),
            "close_terms_before_invitation",
            &id,
            Some(request.expected_agreement_revision),
            &json!({"preview_digest":fingerprint}),
        )?;
        if let Some(original) = self.replay(access, &command)? {
            // Retry the exact preparation after its closure committed. Never
            // substitute later terms or revive a cancelled/recovered agreement.
            if original.agreement.agreement != envelope.view.agreement {
                return Err(ApiError::new(
                    "REVISION_CONFLICT",
                    "Original invitation terms no longer match",
                ));
            }
            return Ok(prepared);
        }
        candidates::check_revision(&envelope, request.expected_agreement_revision)?;
        if envelope.terms_editing_origin {
            envelope.terms_editing_origin = false;
            self.commit(
                &command,
                &id,
                request.expected_agreement_revision,
                envelope,
                "terms_editing_closed_before_invitation",
            )?;
        }
        Ok(prepared)
    }

    /// Current read permission for a receipt-backed nonbinding import, including
    /// owner, peer enrollment, recipient and revocation. `now` is trusted runtime
    /// time, never a request field. Expired messages may still describe history.
    pub fn nonbinding_transport_requirements(
        &self,
        access: &Access,
        inbox: &SqliteReplayLedger,
        received: &ReceivedArtifact,
        now: &Timestamp,
    ) -> Result<TransportImportRequirements> {
        self.require_protected_transport_store()?;
        if self
            .store
            .recovery_record_is_historical("agreement", &received.preview().context.agreement_id)
            .map_err(store_error)?
        {
            return Err(ApiError::new(
                "RECOVERY_REQUIRED",
                "Historical transport grants require separately reviewed reconciliation",
            ));
        }
        let envelope = self.load(access, &received.preview().context.agreement_id)?;
        owner(&envelope, access)?;
        let command = decode_command(received)?;
        if received.preview().context.network_profile_id
            != envelope.view.agreement.network_profile_id
        {
            return Err(ApiError::new(
                "WRONG_NETWORK",
                "Transport profile does not match the local agreement",
            ));
        }
        require_current_grant(&envelope, received, now)?;
        command.check_binding(received)?;
        let ticket = inbox
            .domain_import_ticket(received, PROCESSOR)
            .map_err(transport_error)?;
        let expected_agreement_revision = match command {
            NonbindingCommand::Intent(message) => message.expected_agreement_revision,
            NonbindingCommand::Withdrawal(message) => message.expected_agreement_revision,
        };
        Ok(TransportImportRequirements {
            expected_agreement_revision,
            idempotency_key: ticket.idempotency_key().into(),
            domain_completed: ticket.completed().is_some(),
        })
    }

    /// Import only an enrolled peer's nonbinding intent or withdrawal. The actual
    /// engine operation and its event/idempotency result commit before inbox
    /// completion. Retrying after a crash uses the exact same engine request.
    /// Every path, including a completed replay, checks current owner access and
    /// current peer enrollment, recipient, fingerprint, scope and grant expiry.
    /// `now` must come from the trusted local runtime clock, never request JSON.
    pub fn import_nonbinding_transport(
        &self,
        access: &Access,
        inbox: &mut SqliteReplayLedger,
        received: &ReceivedArtifact,
        now: &Timestamp,
    ) -> Result<Mutation> {
        self.require_protected_transport_store()?;
        if self
            .store
            .recovery_record_is_historical("agreement", &received.preview().context.agreement_id)
            .map_err(store_error)?
        {
            return Err(ApiError::new(
                "RECOVERY_REQUIRED",
                "Historical transport grants require separately reviewed reconciliation",
            ));
        }
        let preview = received.preview();
        let id = &preview.context.agreement_id;
        let envelope = self.load(access, id)?;
        owner(&envelope, access)?;
        let command = decode_command(received)?;
        if preview.context.network_profile_id != envelope.view.agreement.network_profile_id {
            return Err(ApiError::new(
                "WRONG_NETWORK",
                "Transport profile does not match the local agreement",
            ));
        }
        require_current_grant(&envelope, received, now)?;
        command.check_binding(received)?;
        let peer = peer_access(received)?;
        let ticket = inbox
            .domain_import_ticket(received, PROCESSOR)
            .map_err(transport_error)?;
        let engine_command = command.engine_context(&peer, ticket.idempotency_key(), id)?;
        if let Some(replay) = self.replay(&peer, &engine_command)? {
            return finish_import(inbox, &ticket, replay);
        }
        if ticket.completed().is_some() {
            return Err(ApiError::new(
                "RECOVERY_REQUIRED",
                "Inbox completion has no matching engine operation; preserve both journals",
            ));
        }
        // Bind the eventual CAS to the SAME revision whose peer grant was
        // checked. A sender-selected future revision must never race a revoke.
        let expected_revision = match &command {
            NonbindingCommand::Intent(message) => message.expected_agreement_revision,
            NonbindingCommand::Withdrawal(message) => message.expected_agreement_revision,
        };
        if expected_revision != envelope.view.revision {
            return Err(ApiError::new(
                "REVISION_CONFLICT",
                "Transport import must match the current reviewed peer-grant revision",
            ));
        }
        if now.unix_seconds() < preview.order.issued_at.unix_seconds()
            || now.unix_seconds() >= preview.order.expires_at.unix_seconds()
        {
            return Err(ApiError::new(
                "INVALID_TIME",
                "Expired or future transport content cannot create a new engine operation",
            ));
        }
        match &command {
            NonbindingCommand::Intent(message) => {
                if let Some(valid_until) = &message.intent.valid_until {
                    if OffsetDateTime::parse(valid_until, &Rfc3339)
                        .map_err(|_| ApiError::new("INVALID_TERMS", "Intent timestamp is invalid"))?
                        .unix_timestamp()
                        <= now.unix_seconds()
                    {
                        return Err(ApiError::new(
                            "INVALID_TIME",
                            "Participation intent has expired",
                        ));
                    }
                }
                if let Some(deadline) = &envelope.view.agreement.coordination_deadline {
                    if OffsetDateTime::parse(deadline, &Rfc3339)
                        .map_err(|_| internal())?
                        .unix_timestamp()
                        <= now.unix_seconds()
                    {
                        return Err(ApiError::new(
                            "INVALID_TIME",
                            "Agreement coordination deadline has passed",
                        ));
                    }
                }
            }
            NonbindingCommand::Withdrawal(message) => {
                if !envelope.view.intents.iter().any(|intent| {
                    intent.intent_id == message.intent_id
                        && intent.participant_id == message.participant_id
                }) {
                    return Err(ApiError::new(
                        "PERMISSION_DENIED",
                        "Withdrawal must identify this enrolled participant's own intent",
                    ));
                }
            }
        }
        let mutation = match command {
            NonbindingCommand::Intent(message) => self.add_intent(
                &peer,
                ticket.idempotency_key(),
                id,
                message.expected_agreement_revision,
                message.intent,
            )?,
            NonbindingCommand::Withdrawal(message) => self.withdraw(
                &peer,
                ticket.idempotency_key(),
                id,
                &message.intent_id,
                message.expected_agreement_revision,
            )?,
        };
        finish_import(inbox, &ticket, mutation)
    }
}

/// Pure typed preparation. Exact disclosure approval, encryption, durable outbox
/// commit, and actual delivery remain separate explicit calls.
pub fn prepare_intent_message(
    request: ExportRequest,
    message: TransportIntent,
    sender: &TransportPublicKey,
    recipient: &TransportPublicKey,
    now: &Timestamp,
) -> Result<PreparedExport> {
    message.intent.validate()?;
    check_command_scope(
        &request.context,
        message.schema_version,
        message.expected_agreement_revision,
        &message.intent.participant_id,
        ArtifactKind::ParticipationIntent,
    )?;
    if message.intent.agreement_id != request.context.agreement_id
        || message.intent.status != IntentStatus::Active
    {
        return Err(ApiError::new(
            "INVALID_TERMS",
            "Only an active nonbinding intent for this agreement may be prepared",
        ));
    }
    prepare_export(
        request,
        vec![
            DisclosureField::new(
                INTENT_FIELD,
                serde_json::to_vec(&message).map_err(|_| internal())?,
            )
            .map_err(transport_error)?,
        ],
        sender,
        recipient,
        now,
    )
    .map_err(transport_error)
}
pub fn prepare_withdrawal_message(
    request: ExportRequest,
    message: TransportIntentWithdrawal,
    sender: &TransportPublicKey,
    recipient: &TransportPublicKey,
    now: &Timestamp,
) -> Result<PreparedExport> {
    valid_id(&message.intent_id)?;
    check_command_scope(
        &request.context,
        message.schema_version,
        message.expected_agreement_revision,
        &message.participant_id,
        ArtifactKind::IntentWithdrawal,
    )?;
    prepare_export(
        request,
        vec![
            DisclosureField::new(
                WITHDRAWAL_FIELD,
                serde_json::to_vec(&message).map_err(|_| internal())?,
            )
            .map_err(transport_error)?,
        ],
        sender,
        recipient,
        now,
    )
    .map_err(transport_error)
}

enum NonbindingCommand {
    Intent(TransportIntent),
    Withdrawal(TransportIntentWithdrawal),
}
impl NonbindingCommand {
    fn check_binding(&self, received: &ReceivedArtifact) -> Result<()> {
        let c = &received.preview().context;
        match self {
            Self::Intent(message) => {
                message.intent.validate()?;
                if message.intent.agreement_id != c.agreement_id
                    || message.intent.status != IntentStatus::Active
                {
                    return Err(ApiError::new(
                        "INVALID_TERMS",
                        "Intent must remain nonbinding, active and agreement-scoped",
                    ));
                }
                check_command_scope(
                    c,
                    message.schema_version,
                    message.expected_agreement_revision,
                    &message.intent.participant_id,
                    ArtifactKind::ParticipationIntent,
                )
            }
            Self::Withdrawal(message) => {
                valid_id(&message.intent_id)?;
                check_command_scope(
                    c,
                    message.schema_version,
                    message.expected_agreement_revision,
                    &message.participant_id,
                    ArtifactKind::IntentWithdrawal,
                )
            }
        }
    }
    fn engine_context(&self, peer: &Access, key: &str, id: &str) -> Result<CommandContext> {
        match self {
            Self::Intent(message) => context(
                peer,
                key,
                "record_intent",
                id,
                Some(message.expected_agreement_revision),
                &message.intent,
            ),
            Self::Withdrawal(message) => context(
                peer,
                key,
                "withdraw_intent",
                id,
                Some(message.expected_agreement_revision),
                &json!({"intent_id":message.intent_id}),
            ),
        }
    }
}
fn decode_command(received: &ReceivedArtifact) -> Result<NonbindingCommand> {
    if received.fields().len() != 1 {
        return Err(ApiError::new(
            "INVALID_REQUEST",
            "Exactly one supported nonbinding payload is required",
        ));
    }
    let field = &received.fields()[0];
    match (received.preview().context.artifact_kind, field.name()) {
        (ArtifactKind::ParticipationIntent, INTENT_FIELD) => Ok(NonbindingCommand::Intent(
            wholepact_core::parse_typed_json(field.bytes())?,
        )),
        (ArtifactKind::IntentWithdrawal, WITHDRAWAL_FIELD) => Ok(NonbindingCommand::Withdrawal(
            wholepact_core::parse_typed_json(field.bytes())?,
        )),
        _ => Err(ApiError::new(
            "UNSUPPORTED_CAPABILITY",
            "This domain importer only accepts enrolled nonbinding intents and withdrawals",
        )),
    }
}
fn check_command_scope(
    c: &wholepact_transport::MessageContext,
    version: u16,
    revision: u64,
    participant: &str,
    kind: ArtifactKind,
) -> Result<()> {
    valid_id(participant)?;
    if version != 1 {
        return Err(ApiError::new(
            "UNSUPPORTED_VERSION",
            "Unsupported nonbinding transport schema",
        ));
    }
    if revision == 0
        || revision > i64::MAX as u64
        || c.proposal_id != NONBINDING_INTENT_CONTEXT
        || c.proposal_revision != revision
        || c.artifact_kind != kind
        || c.sender_id != participant
    {
        return Err(ApiError::new(
            "INVALID_TERMS",
            "Nonbinding payload does not match its authenticated sender and revision context",
        ));
    }
    Ok(())
}
fn owner(envelope: &Envelope, access: &Access) -> Result<()> {
    if envelope.owner_client_id != access.principal_id {
        return Err(ApiError::new(
            "PERMISSION_DENIED",
            "Only the current local agreement owner may manage or import transport peers",
        ));
    }
    Ok(())
}
fn validate_grant_request(
    request: &TransportPeerGrantRequest,
    agreement: &AgreementDraft,
    now: i64,
) -> Result<()> {
    for id in [
        &request.grant_id,
        &request.participant_id,
        &request.recipient_id,
    ] {
        valid_id(id)?;
    }
    for fingerprint in [
        &request.sender_key_fingerprint,
        &request.recipient_key_fingerprint,
    ] {
        if fingerprint.len() != 64
            || !fingerprint
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ApiError::new(
                "INVALID_REQUEST",
                "A canonical pinned transport-key fingerprint is required",
            ));
        }
    }
    if request.recipient_id != agreement.organizer_identity
        || (!request.allow_intent && !request.allow_withdrawal)
        || request.expires_at.unix_seconds() <= now
        || request.expires_at.unix_seconds() - now > MAX_PEER_GRANT_LIFETIME_SECONDS
    {
        return Err(ApiError::new(
            "INVALID_REQUEST",
            "Peer enrollment needs the local organizer, an explicit scope and a future expiry within 30 days",
        ));
    }
    Ok(())
}
fn decode_grant(value: &Value) -> Result<TransportPeerGrant> {
    let grant: TransportPeerGrant = serde_json::from_value(value.clone()).map_err(|_| {
        ApiError::new(
            "RECOVERY_REQUIRED",
            "Stored transport peer grant is incompatible or damaged",
        )
    })?;
    if grant.schema_version != 1 {
        return Err(ApiError::new(
            "RECOVERY_REQUIRED",
            "Stored transport peer grant schema is unsupported",
        ));
    }
    Ok(grant)
}
fn require_current_grant(
    envelope: &Envelope,
    received: &ReceivedArtifact,
    now: &Timestamp,
) -> Result<()> {
    let p = received.preview();
    let mut matching = 0;
    for value in envelope.transport_peer_grants.values() {
        let grant = decode_grant(value)?;
        if !grant.revoked
            && !grant.recovery_required
            && grant.request.expires_at.unix_seconds() > now.unix_seconds()
            && grant.agreement_id == p.context.agreement_id
            && grant.network_profile_id == p.context.network_profile_id
            && grant.enrolled_by_principal == envelope.owner_client_id
            && grant.request.participant_id == p.context.sender_id
            && grant.request.sender_key_fingerprint == p.sender_key_fingerprint
            && grant.request.recipient_id == p.context.recipient_id
            && grant.request.recipient_key_fingerprint == p.recipient_key_fingerprint
            && match p.context.artifact_kind {
                ArtifactKind::ParticipationIntent => grant.request.allow_intent,
                ArtifactKind::IntentWithdrawal => grant.request.allow_withdrawal,
                _ => false,
            }
        {
            matching += 1;
        }
    }
    if matching != 1 {
        return Err(ApiError::new(
            "PERMISSION_DENIED",
            "No unique current owner-approved peer grant matches this sender, recipient and operation",
        ));
    }
    Ok(())
}
fn peer_access(received: &ReceivedArtifact) -> Result<Access> {
    let p = received.preview();
    let digest = hash_domain(
        b"wholepact:transport-peer-principal:v1\0",
        &json!({
            "network":p.context.network_profile_id,"agreement":p.context.agreement_id,"participant":p.context.sender_id,
            "sender_key":p.sender_key_fingerprint,"recipient":p.context.recipient_id,"recipient_key":p.recipient_key_fingerprint,
        }),
    )?;
    Ok(Access {
        include_owned_agreements: false,
        principal_id: format!("transport-peer:{digest}"),
        agreement_ids: [p.context.agreement_id.clone()].into(),
        all_agreements: false,
    })
}
fn finish_import(
    inbox: &mut SqliteReplayLedger,
    ticket: &wholepact_transport::DomainImportTicket,
    mutation: Mutation,
) -> Result<Mutation> {
    let result_digest = hash_domain(
        b"wholepact:transport-domain-result:v1\0",
        &json!({
            "operation_id":mutation.operation_id,"event_sequence":mutation.event_sequence,"agreement_revision":mutation.agreement.revision,
        }),
    )?;
    let result = DomainImportResult {
        outcome: DomainOutcome::Applied,
        result_digest,
    };
    if ticket
        .completed()
        .is_some_and(|completed| completed != &result)
    {
        return Err(ApiError::new(
            "RECOVERY_REQUIRED",
            "Inbox result conflicts with the engine's durable operation",
        ));
    }
    inbox
        .complete_domain_import(ticket, result)
        .map_err(transport_error)?;
    Ok(mutation)
}
fn agreement_digest(agreement: &AgreementDraft) -> Result<String> {
    hash_domain(
        b"wholepact:invitation-agreement:v1\0",
        &serde_json::to_value(agreement).map_err(|_| internal())?,
    )
}
fn valid_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
    {
        return Err(ApiError::new(
            "INVALID_REQUEST",
            "A bounded canonical identifier is required",
        ));
    }
    Ok(())
}
fn transport_error(error: TransportError) -> ApiError {
    let code = match error {
        TransportError::Storage => "STORAGE_UNAVAILABLE",
        TransportError::ResourceLimit => "RESOURCE_EXHAUSTED",
        TransportError::Authentication | TransportError::WrongRecipient => {
            "AUTHENTICATION_REQUIRED"
        }
        TransportError::AuthorityUnavailable => "UNSUPPORTED_CAPABILITY",
        TransportError::DomainConflict => "RECOVERY_REQUIRED",
        TransportError::DisclosureDenied => "DISCLOSURE_DENIED",
        TransportError::InvalidTime => "INVALID_TIME",
        _ => "INVALID_TRANSPORT_ARTIFACT",
    };
    ApiError::new(code, &error.to_string())
}
