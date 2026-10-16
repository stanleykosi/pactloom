//! Concrete configured legacy witness owner. Only AuthorityServer's actual mTLS
//! path invokes it. Privileged issuers never leave this private owning module.
use super::OfflineIntentAuthenticationIssuer;
use crate::offline::{OfflineEnrollmentPolicy, OfflineReservationIntent};
use crate::offline_witness_transport_v1 as transport;
use crate::offline_witness_v1::*;
use crate::*;
use std::{path::PathBuf, sync::Arc, time::Instant};
use wholepact_storage_security::{DatabaseFileIdentity, EncryptedConnection};

/// Local operator configuration, not enrollment evidence or an authority token.
/// The actual retained owner-mTLS policy must independently pin both HPKE keys.
/// No key generation, wallet creation, restored adoption or credential enrollment
/// occurs here. The caller retains responsibility for the independent witness's
/// original protected file ownership and coherent backup/restore procedures.
pub struct OfflineWitnessConfigurationV1 {
    pub expected_offline_policy_digest: String,
    pub witness_transport_key_file: PathBuf,
    pub offline_signer_public_key: [u8; 32],
    pub intent_profile: OfflineWitnessIntentProfileV1,
    pub encrypted_inbox: EncryptedConnection,
    pub encrypted_outbox: EncryptedConnection,
}

/// Explicit local profile selection. Named assurance is never inferred from an
/// incoming label, and its commitment never replaces the enrolled policy digest.
pub enum OfflineWitnessIntentProfileV1 {
    Independent,
    NamedVerifier { owner_setup_digest: String },
}

pub(crate) struct ConfiguredOfflineWitnessV1 {
    journal: Arc<AuthorityJournal>,
    policy: OfflineEnrollmentPolicy,
    secret: transport::TransportSecret,
    signer: transport::TransportPublicKey,
    profile: OfflineWitnessIntentProfileV1,
    inbox: transport::SqliteReplayLedger,
    outbox: transport::SqliteOutbox,
    journal_identity: DatabaseFileIdentity,
    inbox_identity: DatabaseFileIdentity,
    outbox_identity: DatabaseFileIdentity,
}
impl ConfiguredOfflineWitnessV1 {
    pub(crate) fn configure(
        journal: Arc<AuthorityJournal>,
        server_certificate: &str,
        input: OfflineWitnessConfigurationV1,
    ) -> Result<Self> {
        let policy = journal.offline_witness_policy_v1(&input.expected_offline_policy_digest)?;
        if policy.witness_certificate_digest != server_certificate {
            return Err(AuthorityError::Authentication);
        }
        let key = wholepact_storage_security::witness_namespace_fs::read_existing_storage_key(
            &input.witness_transport_key_file,
        )?;
        let secret = transport::TransportSecret::from_bytes(*key).map_err(map_transport)?;
        let signer = transport::TransportPublicKey::from_bytes(input.offline_signer_public_key)
            .map_err(map_transport)?;
        if secret.public_key().map_err(map_transport)?.fingerprint()
            != policy.witness_transport_key_digest
            || signer.fingerprint() != policy.offline_signer_key_digest
        {
            return Err(AuthorityError::Authentication);
        }
        if let OfflineWitnessIntentProfileV1::NamedVerifier { owner_setup_digest } =
            &input.intent_profile
        {
            hash(owner_setup_digest)?;
        }
        let journal_identity = journal
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?
            .database_identity()?;
        let inbox_identity = input.encrypted_inbox.database_identity()?;
        let outbox_identity = input.encrypted_outbox.database_identity()?;
        if journal_identity == inbox_identity
            || journal_identity == outbox_identity
            || inbox_identity == outbox_identity
        {
            return Err(AuthorityError::InvalidBinding);
        }
        let owner = Self {
            journal,
            policy,
            secret,
            signer,
            profile: input.intent_profile,
            inbox: transport::SqliteReplayLedger::from_encrypted_connection(input.encrypted_inbox)
                .map_err(map_transport)?,
            outbox: transport::SqliteOutbox::from_encrypted_connection(input.encrypted_outbox)
                .map_err(map_transport)?,
            journal_identity,
            inbox_identity,
            outbox_identity,
        };
        owner.check_files()?;
        Ok(owner)
    }

    fn check_files(&self) -> Result<()> {
        if self
            .journal
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?
            .database_identity()?
            != self.journal_identity
            || self.inbox.database_identity().map_err(map_transport)? != self.inbox_identity
            || self.outbox.database_identity().map_err(map_transport)? != self.outbox_identity
            || self
                .journal
                .offline_witness_policy_v1(&self.policy.policy_digest()?)?
                != self.policy
        {
            return Err(AuthorityError::Conflict);
        }
        Ok(())
    }

    pub(crate) fn submit(
        &mut self,
        peer: &str,
        exporter: &[u8; 32],
        server_certificate: &str,
        wire: &OfflineWitnessRequestV1,
        deadline: Instant,
    ) -> Result<OfflineWitnessDeliveryBodyV1> {
        before(deadline)?;
        let transport_end = u64::try_from(wire.export_template.expires_at_unix_seconds)
            .ok()
            .and_then(|v| v.checked_mul(1000))
            .ok_or(AuthorityError::InvalidBinding)?;
        let current = CurrentOfflineWitnessWindowV1::capture(
            wire.request.requested_at_ms,
            wire.request.admission_expires_at_ms.min(transport_end),
            deadline,
        )?;
        self.check_files()?;
        let record = wire.record()?;
        self.journal.authenticate_offline_witness_channel_v1(
            peer,
            &record,
            &wire.proof,
            exporter,
            server_certificate,
            &self.policy,
            now_ms()?,
        )?;
        before(deadline)?;
        let envelope_bytes = wire.envelope()?;
        let _parsed = transport::EncryptedEnvelope::from_bytes(envelope_bytes.clone())
            .map_err(map_transport)?;
        let journal = Arc::clone(&self.journal);
        let bridge = OfflineOriginalBridge {
            journal: &journal,
            peer,
        };
        // This comparison runs for exact retries too, before returning old bytes.
        let original = bridge.prepare(
            &wire.request,
            &envelope_bytes,
            wire.export_template.clone(),
            now_ms()?,
        )?;
        before(deadline)?;
        if bridge
            .recover_admission_export_history(&wire.request.operation_id)?
            .is_some()
        {
            return self.recover(
                peer,
                &OfflineAdmissionDeliveryLookupV1::from_request(&wire.request)?,
                deadline,
            );
        }
        let context = intent_context(&original.request().intent)?;
        let prepared_digest = original.prepared_record_digest()?;
        let envelope =
            transport::EncryptedEnvelope::from_bytes(original.original_envelope_bytes().to_vec())
                .map_err(map_transport)?;
        let received = if let Some(receipt) = original.authenticated_receipt() {
            if let Some(retained) = self
                .inbox
                .retained_for_context(&context, receipt.sequence)
                .map_err(map_transport)?
            {
                let historical =
                    transport::recover_received(&retained, &self.secret, &self.signer, &context)
                        .map_err(map_transport)?;
                if !historical.is_currently_valid(&timestamp(now_ms()?)?) {
                    return Err(AuthorityError::Expired);
                }
                let received = historical.into_artifact();
                validate_payload(&received, &original.request().intent, &self.profile)?;
                if transport_receipt(&received)? != *receipt {
                    return Err(AuthorityError::Authentication);
                }
                received
            } else {
                open_original(
                    &bridge,
                    &original,
                    &envelope,
                    &self.secret,
                    &self.signer,
                    &self.profile,
                    &mut self.inbox,
                    deadline,
                )?
            }
        } else {
            open_original(
                &bridge,
                &original,
                &envelope,
                &self.secret,
                &self.signer,
                &self.profile,
                &mut self.inbox,
                deadline,
            )?
        };
        before(deadline)?;
        bridge.record_inbox_accepted(
            &prepared_digest,
            &wire.request.operation_id,
            transport_receipt(&received)?,
            now_ms()?,
        )?;
        self.check_files()?;
        self.journal.authenticate_offline_witness_channel_v1(
            peer,
            &record,
            &wire.proof,
            exporter,
            server_certificate,
            &self.policy,
            now_ms()?,
        )?;
        before(deadline)?;
        // Private field construction is permitted only in this child of the
        // issuer's defining module, after actual pinned HPKE + durable inbox.
        let issuer = OfflineIntentAuthenticationIssuer {
            policy: self.policy.clone(),
        };
        let authentication = issuer.bind_verified_intent(
            &wire.request,
            &wire.request.intent,
            &self.signer.fingerprint(),
            &self
                .secret
                .public_key()
                .map_err(map_transport)?
                .fingerprint(),
            received.envelope_digest(),
        )?;
        if authentication.evidence() != &record.authentication {
            return Err(AuthorityError::Authentication);
        }
        // From this boundary onward any failure may leave durable exposure or an
        // emission fence. Always reconcile the identical original, never replace.
        let committed = self
            .journal
            .commit_offline_prepared_current_v1(
                peer,
                wire.request.clone(),
                authentication,
                wire.proof.clone(),
                exporter,
                server_certificate,
                &current,
            )
            .map_err(|_| AuthorityError::Uncertain)?;
        let _committed = committed;
        let mut finish = || -> Result<OfflineWitnessDeliveryBodyV1> {
            before(deadline)?;
            self.check_files()?;
            let selected =
                bridge.select_admission_export_current_v1(&wire.request.operation_id, &current)?;
            before(deadline)?;
            let sender = self.secret.public_key().map_err(map_transport)?;
            let now = timestamp(now_ms()?)?;
            let prepared = transport::prepare_offline_minimal_admission(
                &selected,
                &sender,
                &self.signer,
                &now,
            )
            .map_err(map_transport)?;
            let approved = prepared.preview().digest().map_err(map_transport)?;
            let artifact = self
                .outbox
                .enqueue_offline_minimal_admission_before(
                    prepared,
                    &self.secret,
                    &approved,
                    &now,
                    current.ceiling(),
                    current.first_wall_ms(),
                )
                .map_err(map_transport)?;
            before(deadline)?;
            self.check_files()?;
            current.check()?;
            delivery(
                selected.descriptor(),
                selected.export_plan(),
                artifact.envelope().as_bytes(),
                false,
            )
        };
        finish().map_err(|_| AuthorityError::Uncertain)
    }

    pub(crate) fn recover(
        &self,
        peer: &str,
        lookup: &OfflineAdmissionDeliveryLookupV1,
        deadline: Instant,
    ) -> Result<OfflineWitnessDeliveryBodyV1> {
        before(deadline)?;
        lookup.validate()?;
        self.check_files()?;
        // Authenticate exact account read access before looking up an operation.
        self.journal
            .snapshot(peer, &lookup.account_id, &lookup.network_profile_id)?;
        if lookup.offline_policy_digest != self.policy.policy_digest()? {
            return Err(AuthorityError::PolicyDenied);
        }
        let bridge = OfflineOriginalBridge {
            journal: &self.journal,
            peer,
        };
        let original = bridge
            .recover_admission_export_history(&lookup.operation_id)?
            .ok_or(AuthorityError::Uncertain)?;
        if OfflineAdmissionDeliveryLookupV1::from_request(&original.descriptor().request)?
            != *lookup
        {
            return Err(AuthorityError::Conflict);
        }
        let artifact = self
            .outbox
            .recover_original_offline_minimal_admission(
                &original,
                &self.secret.public_key().map_err(map_transport)?,
                &self.signer,
            )
            .map_err(map_transport)?
            .ok_or(AuthorityError::Uncertain)?;
        before(deadline)?;
        self.check_files()?;
        delivery(
            original.descriptor(),
            original.export_plan(),
            artifact.envelope().as_bytes(),
            true,
        )
    }
}

fn before(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        return Err(AuthorityError::Uncertain);
    }
    Ok(())
}
fn timestamp(ms: u64) -> Result<transport::Timestamp> {
    let seconds = i64::try_from(ms / 1000).map_err(|_| AuthorityError::Expired)?;
    transport::Timestamp::from_unix_seconds(seconds).map_err(map_transport)
}
fn map_transport(error: transport::TransportError) -> AuthorityError {
    use transport::TransportError as E;
    match error {
        E::Storage | E::ImportCommittedButUnavailable => AuthorityError::Storage,
        E::ResourceLimit => AuthorityError::Limit,
        E::InvalidTime => AuthorityError::Expired,
        E::Replay | E::Equivocation | E::OutOfOrder | E::DomainConflict => AuthorityError::Conflict,
        E::UnsupportedVersion => AuthorityError::UnsupportedVersion,
        _ => AuthorityError::Authentication,
    }
}
fn intent_context(intent: &OfflineReservationIntent) -> Result<transport::MessageContext> {
    intent.validate()?;
    let t = &intent.terms;
    Ok(transport::MessageContext {
        network_profile_id: t.network_profile_id.clone(),
        agreement_id: t.agreement_id.clone(),
        proposal_id: t.proposal_id.clone(),
        proposal_revision: t.proposal_revision,
        sender_id: format!("offline-intent:{}", t.offline_signer_key_digest),
        recipient_id: format!("offline-intent:{}", t.offline_policy_digest),
        artifact_kind: transport::ArtifactKind::OfflineReservationIntent,
    })
}
fn validate_payload(
    received: &transport::ReceivedArtifact,
    intent: &OfflineReservationIntent,
    profile: &OfflineWitnessIntentProfileV1,
) -> Result<()> {
    let fields = received.fields();
    let expected_names = match profile {
        OfflineWitnessIntentProfileV1::Independent => vec!["offline-reservation-intent-v1"],
        OfflineWitnessIntentProfileV1::NamedVerifier { .. } => vec![
            transport::NAMED_REVIEW_BINDING_FIELD_V1,
            "offline-reservation-intent-v1",
        ],
    };
    if fields.iter().map(|f| f.name()).collect::<Vec<_>>() != expected_names {
        return Err(AuthorityError::InvalidBinding);
    }
    let field = fields.last().ok_or(AuthorityError::InvalidBinding)?;
    let exact: OfflineReservationIntent = decode(field.bytes())?;
    if exact != *intent || encode(&exact)?.as_slice() != field.bytes() {
        return Err(AuthorityError::Authentication);
    }
    if let OfflineWitnessIntentProfileV1::NamedVerifier { owner_setup_digest } = profile {
        let header =
            transport::NamedReviewBindingV1::parse(fields[0].bytes()).map_err(map_transport)?;
        let mut terms =
            serde_json::to_value(&intent.terms).map_err(|_| AuthorityError::InvalidBinding)?;
        terms
            .as_object_mut()
            .ok_or(AuthorityError::InvalidBinding)?
            .remove("review_package_digest")
            .ok_or(AuthorityError::InvalidBinding)?;
        let context = digest("wholepact:named-verifier-original-context:v1", &terms)?;
        if header.owner_setup_digest != *owner_setup_digest
            || header.original_context_digest != context
            || header.review_package_digest().map_err(map_transport)?
                != intent.terms.review_package_digest
        {
            return Err(AuthorityError::Authentication);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn open_original(
    bridge: &OfflineOriginalBridge<'_>,
    original: &RetainedOfflineOriginal,
    envelope: &transport::EncryptedEnvelope,
    secret: &transport::TransportSecret,
    signer: &transport::TransportPublicKey,
    profile: &OfflineWitnessIntentProfileV1,
    inbox: &mut transport::SqliteReplayLedger,
    deadline: Instant,
) -> Result<transport::ReceivedArtifact> {
    before(deadline)?;
    let context = intent_context(&original.request().intent)?;
    let prepared = original.prepared_record_digest()?;
    transport::open_envelope_checked(
        envelope,
        secret,
        signer,
        &context,
        &timestamp(now_ms()?)?,
        inbox,
        |received| {
            before(deadline).map_err(|_| transport::TransportError::AuthorityUnavailable)?;
            validate_payload(received, &original.request().intent, profile)
                .map_err(|_| transport::TransportError::Authentication)?;
            let receipt = transport_receipt(received)
                .map_err(|_| transport::TransportError::Authentication)?;
            bridge
                .record_authenticated_receipt(
                    &prepared,
                    &original.request().operation_id,
                    receipt,
                    now_ms().map_err(|_| transport::TransportError::InvalidTime)?,
                )
                .map_err(|_| transport::TransportError::AuthorityUnavailable)
        },
    )
    .map_err(map_transport)
}
fn transport_receipt(received: &transport::ReceivedArtifact) -> Result<OriginalTransportReceipt> {
    let p = received.preview();
    let c = &p.context;
    let o = &p.order;
    if c.artifact_kind != transport::ArtifactKind::OfflineReservationIntent {
        return Err(AuthorityError::InvalidBinding);
    }
    Ok(OriginalTransportReceipt {
        network_profile_id: c.network_profile_id.clone(),
        agreement_id: c.agreement_id.clone(),
        proposal_id: c.proposal_id.clone(),
        proposal_revision: c.proposal_revision,
        sender_id: c.sender_id.clone(),
        recipient_id: c.recipient_id.clone(),
        artifact_kind: "offline_reservation_intent".into(),
        message_id: o.message_id.clone(),
        sequence: o.sequence,
        issued_at_unix_seconds: o.issued_at.unix_seconds(),
        expires_at_unix_seconds: o.expires_at.unix_seconds(),
        sender_key_fingerprint: p.sender_key_fingerprint.clone(),
        recipient_key_fingerprint: p.recipient_key_fingerprint.clone(),
        stream_digest: received.stream_digest().into(),
        preview_digest: p.digest().map_err(map_transport)?,
        content_digest: received.content_digest().into(),
        payload_digest: p.payload_digest.clone(),
        envelope_digest: received.envelope_digest().into(),
    })
}
fn delivery(
    admission: &crate::offline::OfflineAuthorizationAdmission,
    plan: &OfflineAdmissionExportPlan,
    ciphertext: &[u8],
    recovered: bool,
) -> Result<OfflineWitnessDeliveryBodyV1> {
    let body = OfflineWitnessDeliveryBodyV1 {
        schema_version: 1,
        original: OfflineAdmissionDeliveryLookupV1::from_request(&admission.request)?,
        authorization_id: admission.request.intent.terms.authorization_id.clone(),
        witness_id: admission.witness_id.clone(),
        witness_account_policy_digest: admission.witness_policy_digest.clone(),
        original_admission_digest: digest(
            "wholepact.offline-original-admission-assertion.v1",
            admission,
        )?,
        export_plan: plan.clone(),
        committed_head: admission.committed_head.clone(),
        reserved_at_ms: admission.reserved_at_ms,
        admission_expires_at_ms: admission.request.admission_expires_at_ms,
        ciphertext_hex: hex::encode(ciphertext),
        recovered_original: recovered,
    };
    body.validate()?;
    Ok(body)
}
