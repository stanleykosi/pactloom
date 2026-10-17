//! Actual native-origin namespace composition. No arbitrary database handles,
//! restored archives, parsed approval flags or legacy policy projection enter it.
use super::{AuthenticatedBornInputV1, RetainedBornOfflineOriginalV1};
use crate::{
    born_offline_admission_v1::*,
    born_offline_artifacts_v1::*,
    born_offline_enrollment_v1::*,
    born_offline_witness_v1::*,
    offline_admission::configured_witness::{before, map_transport, timestamp, transport_receipt},
    offline_witness_transport_v1 as transport,
    offline_witness_v1::{CurrentOfflineWitnessWindowV1, OfflineWitnessDeliveryBodyV1},
    witness_locator::{NamespaceOpenInput, open_born_history},
    *,
};
use std::{path::PathBuf, sync::Arc, time::Instant};
use wholepact_storage_security::DatabaseFileIdentity;

/// Operator selection of the original fixed OS-user namespace only. It creates
/// no keys, database, native decision or writer session. Existing native schema7
/// installation and exact enrolled HPKE possession are independently required.
pub struct BornOfflineWitnessConfigurationV1 {
    pub endpoint: String,
    pub server_name: String,
    pub witness_id: String,
    pub pinned_server_certificate_digest: String,
    pub owner_certificate_digest: String,
    pub network_profile_id: String,
    pub storage_key_file: PathBuf,
    pub expected_account_id: String,
    pub expected_enrollment_digest: String,
    pub expected_artifact_binding_digest: String,
}
pub(crate) struct ConfiguredBornOfflineWitnessV1 {
    pub(crate) journal: Arc<AuthorityJournal>,
    artifacts: BornOfflineArtifactRecordV1,
    enrollment: BornOfflineEnrollmentV1,
    secret: transport::TransportSecret,
    signer: transport::TransportPublicKey,
    profile: OfflineWitnessIntentProfileV1,
    inbox: transport::SqliteReplayLedger,
    outbox: transport::SqliteOutbox,
    identity: DatabaseFileIdentity,
}
impl ConfiguredBornOfflineWitnessV1 {
    pub(crate) fn configure(
        input: BornOfflineWitnessConfigurationV1,
        server: &str,
    ) -> Result<Self> {
        hash(&input.expected_enrollment_digest)?;
        hash(&input.expected_artifact_binding_digest)?;
        if input.pinned_server_certificate_digest != server {
            return Err(AuthorityError::Authentication);
        }
        let namespace = NamespaceOpenInput {
            #[cfg(feature = "synthetic-qualification")]
            synthetic_installation: None,
            endpoint: input.endpoint,
            server_name: input.server_name,
            witness_id: input.witness_id,
            pinned_server_certificate_digest: input.pinned_server_certificate_digest,
            owner_certificate_digest: input.owner_certificate_digest,
            network_profile_id: input.network_profile_id,
            storage_key_file: input
                .storage_key_file
                .to_str()
                .ok_or(AuthorityError::InvalidBinding)?
                .into(),
            expected_account_id: input.expected_account_id,
        };
        Self::configure_from_original_namespace(
            namespace,
            input.expected_enrollment_digest,
            input.expected_artifact_binding_digest,
            server,
        )
    }

    /// Actual namespace factory shared with the concrete synthetic installation.
    /// Production always constructs the fixed OS-user input with no selector.
    pub(crate) fn configure_from_original_namespace(
        input: NamespaceOpenInput,
        expected_enrollment_digest: String,
        expected_artifact_binding_digest: String,
        server: &str,
    ) -> Result<Self> {
        hash(&expected_enrollment_digest)?;
        hash(&expected_artifact_binding_digest)?;
        if input.pinned_server_certificate_digest != server {
            return Err(AuthorityError::Authentication);
        }
        let journal = Arc::new(open_born_history(input)?);
        let (artifacts, key) = journal.born_offline_artifacts_v1()?;
        let enrollment = {
            let c = journal
                .connection
                .lock()
                .map_err(|_| AuthorityError::Storage)?;
            let l = crate::journal::load(c.connection())?;
            l.born_offline_enrollment_v1()?
                .ok_or(AuthorityError::Permission)?
                .enrollment
                .clone()
        };
        if artifacts.binding.digest() != Ok(expected_artifact_binding_digest)
            || enrollment.digest() != Ok(expected_enrollment_digest)
            || enrollment.policy.witness_certificate_digest != server
        {
            return Err(AuthorityError::Authentication);
        }
        let secret = transport::TransportSecret::from_bytes(*key).map_err(map_transport)?;
        let signer_bytes: [u8; 32] = hex::decode(&artifacts.binding.offline_signer_public_key_hex)
            .map_err(|_| AuthorityError::InvalidBinding)?
            .try_into()
            .map_err(|_| AuthorityError::InvalidBinding)?;
        let signer =
            transport::TransportPublicKey::from_bytes(signer_bytes).map_err(map_transport)?;
        if secret.public_key().map_err(map_transport)?.fingerprint()
            != enrollment.policy.witness_transport_key_digest
            || signer.fingerprint() != enrollment.policy.offline_signer_key_digest
        {
            return Err(AuthorityError::Authentication);
        }
        let (inbox, outbox) = journal.open_born_artifact_handles_v1()?;
        let identity = journal
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?
            .database_identity()?;
        if inbox.database_identity()? != identity || outbox.database_identity()? != identity {
            return Err(AuthorityError::InvalidBinding);
        }
        let profile = match &enrollment.assurance {
            BornOfflineAssuranceV1::Independent => OfflineWitnessIntentProfileV1::Independent,
            BornOfflineAssuranceV1::NamedVerifierOwnEffectsV1 { owner_setup_digest } => {
                OfflineWitnessIntentProfileV1::NamedVerifier {
                    owner_setup_digest: owner_setup_digest.clone(),
                }
            }
        };
        let owner = Self {
            journal,
            artifacts,
            enrollment,
            secret,
            signer,
            profile,
            inbox: transport::SqliteReplayLedger::from_born_original_connection(inbox)
                .map_err(map_transport)?,
            outbox: transport::SqliteOutbox::from_born_original_connection(outbox)
                .map_err(map_transport)?,
            identity,
        };
        owner.check_files()?;
        Ok(owner)
    }
    pub(crate) fn require_server_certificate(&self, server: &str) -> Result<()> {
        if self.enrollment.policy.witness_certificate_digest != server {
            return Err(AuthorityError::Authentication);
        }
        self.check_files()
    }
    fn check_files(&self) -> Result<()> {
        let (record, _key) = self.journal.born_offline_artifacts_v1()?;
        if record != self.artifacts
            || self
                .journal
                .connection
                .lock()
                .map_err(|_| AuthorityError::Storage)?
                .database_identity()?
                != self.identity
            || self.inbox.database_identity().map_err(map_transport)? != self.identity
            || self.outbox.database_identity().map_err(map_transport)? != self.identity
        {
            return Err(AuthorityError::Conflict);
        }
        Ok(())
    }
    pub(crate) fn submit(
        &mut self,
        peer: &str,
        exporter: &[u8; 32],
        server: &str,
        wire: &BornOfflineWitnessRequestV1,
        deadline: Instant,
    ) -> Result<BornOfflineDeliveryBodyV1> {
        before(deadline)?;
        let end = u64::try_from(wire.export_template.expires_at_unix_seconds)
            .ok()
            .and_then(|v| v.checked_mul(1000))
            .ok_or(AuthorityError::InvalidBinding)?;
        let current = CurrentOfflineWitnessWindowV1::capture(
            wire.request.reservation.requested_at_ms,
            wire.request.reservation.admission_expires_at_ms.min(end),
            deadline,
        )?;
        self.check_files()?;
        if wire.request.enrollment_digest != self.enrollment.digest()?
            || wire.request.artifact_binding_digest != self.artifacts.binding.digest()?
        {
            return Err(AuthorityError::InvalidBinding);
        }
        let original = self
            .journal
            .prepare_born_offline_original_v1(peer, wire, exporter, server, &current)?;
        let lookup = BornOfflineDeliveryLookupV1::from_request(&wire.request)?;
        // Existing bytes are recovered unchanged; an absent outbox after a
        // committed admission may be finished only inside the original window.
        match self.journal.recover_born_offline_original_v1(peer, &lookup) {
            Ok((retained, admission)) => {
                if let Some(body) = self.recover_bytes(&retained, &admission, true)? {
                    return Ok(body);
                }
            }
            Err(AuthorityError::Uncertain) => {}
            Err(error) => return Err(error),
        }
        let context =
            transport::born_offline_intent_context_v1(&wire.request).map_err(map_transport)?;
        let envelope = transport::EncryptedEnvelope::from_bytes(original.envelope.clone())
            .map_err(map_transport)?;
        let recovered = if let Some(receipt) = &original.receipt {
            self.inbox
                .retained_for_context(&context, receipt.sequence)
                .map_err(map_transport)?
        } else {
            None
        };
        let (received, authenticated_receipt) = transport::authenticate(
            &envelope,
            &self.secret,
            &self.signer,
            &context,
            Some(&timestamp(current.check()?)?),
        )
        .map_err(map_transport)?;
        validate_born_payload(&received, &wire.request, &self.profile)?;
        if let Some(retained) = recovered {
            if !retained.matches(&authenticated_receipt)
                || Some(transport_receipt(&received)?) != original.receipt
            {
                return Err(AuthorityError::Authentication);
            }
        } else {
            // Actual HPKE precedes the domain callback, which precedes the
            // maintained replay transaction. Never hold an authority write lock
            // while opening the same-file inbox transaction on another handle.
            let receipt = transport_receipt(&received)?;
            self.journal
                .record_born_offline_receipt_v1(peer, wire, exporter, server, &receipt, &current)?;
            transport::ReplayLedger::accept_authenticated(
                &mut self.inbox,
                &authenticated_receipt,
                envelope.as_bytes(),
            )
            .map_err(map_transport)?;
        }
        self.check_files()?;
        current.check()?;
        let input = AuthenticatedBornInputV1 {
            receipt: transport_receipt(&received)?,
        };
        let admission = self
            .journal
            .commit_born_offline_v1(peer, wire, exporter, server, input, &current)
            .map_err(|_| AuthorityError::Uncertain)?;
        let mut finish = || -> Result<BornOfflineDeliveryBodyV1> {
            self.check_files()?;
            current.check()?;
            let (retained, stored) = self
                .journal
                .recover_born_offline_original_v1(peer, &lookup)?;
            if stored != admission {
                return Err(AuthorityError::Conflict);
            }
            let prepared = self.prepare_export(
                &stored,
                &retained.original.export_plan,
                &timestamp(current.check()?)?,
            )?;
            let approved = prepared.preview().digest().map_err(map_transport)?;
            let artifact = self
                .outbox
                .enqueue_validated_before(
                    prepared,
                    &self.secret,
                    &approved,
                    &timestamp(current.check()?)?,
                    current.ceiling(),
                    current.first_wall_ms(),
                )
                .map_err(map_transport)?;
            current.check()?;
            self.check_files()?;
            delivery(
                &stored,
                &retained.original.export_plan,
                artifact.envelope().as_bytes(),
                false,
            )
        };
        finish().map_err(|_| AuthorityError::Uncertain)
    }
    pub(crate) fn recover(
        &self,
        peer: &str,
        lookup: &BornOfflineDeliveryLookupV1,
        deadline: Instant,
    ) -> Result<BornOfflineDeliveryBodyV1> {
        before(deadline)?;
        self.check_files()?;
        if lookup.enrollment_digest != self.enrollment.digest()?
            || lookup.artifact_binding_digest != self.artifacts.binding.digest()?
        {
            return Err(AuthorityError::InvalidBinding);
        }
        let (old, admission) = self
            .journal
            .recover_born_offline_original_v1(peer, lookup)?;
        let body = self
            .recover_bytes(&old, &admission, true)?
            .ok_or(AuthorityError::Uncertain)?;
        before(deadline)?;
        self.check_files()?;
        Ok(body)
    }
    fn prepare_export(
        &self,
        admission: &BornOfflineAuthorizationAdmissionV1,
        plan: &OfflineAdmissionExportPlan,
        now: &transport::Timestamp,
    ) -> Result<transport::PreparedExport> {
        prepare_original_export(admission, plan, &self.artifacts, now)
    }

    fn recover_bytes(
        &self,
        original: &RetainedBornOfflineOriginalV1,
        admission: &BornOfflineAuthorizationAdmissionV1,
        recovered: bool,
    ) -> Result<Option<BornOfflineDeliveryBodyV1>> {
        let plan = &original.original.export_plan;
        let prepared = self.prepare_export(
            admission,
            plan,
            &transport::Timestamp::from_unix_seconds(plan.issued_at_unix_seconds)
                .map_err(map_transport)?,
        )?;
        let artifact = self
            .outbox
            .recover_for_recipient(
                &minimal_context(&admission.request),
                &self.signer,
                plan.sequence,
            )
            .map_err(map_transport)?;
        artifact
            .map(|artifact| {
                if artifact.preview_digest()
                    != prepared.preview().digest().map_err(map_transport)?
                {
                    return Err(AuthorityError::Authentication);
                }
                delivery(admission, plan, artifact.envelope().as_bytes(), recovered)
            })
            .transpose()
    }
}
/// Pure maintained transport projection, also used by historical schema checks.
/// This never seals, mutates a mailbox, reads a secret or grants authority.
pub(crate) fn prepare_original_export(
    admission: &BornOfflineAuthorizationAdmissionV1,
    plan: &OfflineAdmissionExportPlan,
    artifacts: &BornOfflineArtifactRecordV1,
    now: &transport::Timestamp,
) -> Result<transport::PreparedExport> {
    fn key(value: &str) -> Result<transport::TransportPublicKey> {
        let bytes: [u8; 32] = hex::decode(value)
            .map_err(|_| AuthorityError::InvalidBinding)?
            .try_into()
            .map_err(|_| AuthorityError::InvalidBinding)?;
        transport::TransportPublicKey::from_bytes(bytes).map_err(map_transport)
    }
    let witness = key(&artifacts.binding.witness_public_key_hex)?;
    let signer = key(&artifacts.binding.offline_signer_public_key_hex)?;
    let statement = transport::BornOfflineMinimalAdmissionV1::from_descriptor(admission, plan)
        .map_err(map_transport)?;
    transport::prepare_export(
        transport::ExportRequest {
            context: minimal_context(&admission.request),
            order: transport::MessageOrder {
                message_id: plan.message_id.clone(),
                sequence: plan.sequence,
                issued_at: transport::Timestamp::from_unix_seconds(plan.issued_at_unix_seconds)
                    .map_err(map_transport)?,
                expires_at: transport::Timestamp::from_unix_seconds(plan.expires_at_unix_seconds)
                    .map_err(map_transport)?,
            },
            purpose: plan.purpose.clone(),
            persistence_warning: plan.persistence_warning.clone(),
        },
        vec![
            transport::DisclosureField::new(
                transport::BORN_OFFLINE_MINIMAL_ADMISSION_FIELD_V1,
                encode(&statement)?.to_vec(),
            )
            .map_err(map_transport)?,
        ],
        &witness,
        &signer,
        now,
    )
    .map_err(map_transport)
}

fn minimal_context(r: &BornOfflineReservationRequestV1) -> transport::MessageContext {
    let t = &r.reservation.intent.terms;
    transport::MessageContext {
        network_profile_id: t.network_profile_id.clone(),
        agreement_id: t.agreement_id.clone(),
        proposal_id: t.proposal_id.clone(),
        proposal_revision: t.proposal_revision,
        sender_id: format!("offline-admission:{}", t.offline_policy_digest),
        recipient_id: format!("offline-admission:{}", t.offline_signer_key_digest),
        artifact_kind: transport::ArtifactKind::BornOfflineMinimalAdmissionV1,
    }
}
fn delivery(
    a: &BornOfflineAuthorizationAdmissionV1,
    plan: &OfflineAdmissionExportPlan,
    bytes: &[u8],
    recovered: bool,
) -> Result<BornOfflineDeliveryBodyV1> {
    let origin = BornOfflineDeliveryLookupV1::from_request(&a.request)?;
    let old = &a.reserved;
    let body = BornOfflineDeliveryBodyV1 {
        origin: origin.clone(),
        delivery: OfflineWitnessDeliveryBodyV1 {
            schema_version: 1,
            original: origin.original,
            authorization_id: old.request.intent.terms.authorization_id.clone(),
            witness_id: old.witness_id.clone(),
            witness_account_policy_digest: old.witness_policy_digest.clone(),
            original_admission_digest: a.admission_digest()?,
            export_plan: plan.clone(),
            committed_head: old.committed_head.clone(),
            reserved_at_ms: old.reserved_at_ms,
            admission_expires_at_ms: old.request.admission_expires_at_ms,
            ciphertext_hex: hex::encode(bytes),
            recovered_original: recovered,
        },
    };
    body.validate()?;
    Ok(body)
}

fn validate_born_payload(
    received: &transport::ReceivedArtifact,
    request: &BornOfflineReservationRequestV1,
    profile: &OfflineWitnessIntentProfileV1,
) -> Result<()> {
    let fields = received.fields();
    if fields.iter().map(|f| f.name()).collect::<Vec<_>>()
        != [
            transport::BORN_OFFLINE_INTENT_FIELD_V1,
            transport::NAMED_REVIEW_BINDING_FIELD_V1,
        ]
    {
        return Err(AuthorityError::InvalidBinding);
    }
    let exact: BornOfflineReservationRequestV1 = decode(fields[0].bytes())?;
    if exact != *request || encode(&exact)?.as_slice() != fields[0].bytes() {
        return Err(AuthorityError::Authentication);
    }
    let OfflineWitnessIntentProfileV1::NamedVerifier { owner_setup_digest } = profile else {
        return Err(AuthorityError::PolicyDenied);
    };
    let header =
        transport::NamedReviewBindingV1::parse(fields[1].bytes()).map_err(map_transport)?;
    let mut terms = serde_json::to_value(&request.reservation.intent.terms)
        .map_err(|_| AuthorityError::InvalidBinding)?;
    terms
        .as_object_mut()
        .ok_or(AuthorityError::InvalidBinding)?
        .remove("review_package_digest")
        .ok_or(AuthorityError::InvalidBinding)?;
    if header.owner_setup_digest != *owner_setup_digest
        || header.original_context_digest
            != digest("wholepact:named-verifier-original-context:v1", &terms)?
        || header.review_package_digest().map_err(map_transport)?
            != request.reservation.intent.terms.review_package_digest
    {
        return Err(AuthorityError::Authentication);
    }
    Ok(())
}
