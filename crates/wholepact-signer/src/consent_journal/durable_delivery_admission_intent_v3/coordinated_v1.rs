//! Explicit coordinated V3 historical profile (payload version 4). These are
//! inert original records, never constructors for a live receipt or grant.
//! Legacy version 3 retains its own provider namespace and validation rules.
use super::*;
use crate::authority_bridge::durable_review_ipc_v3::coordinated_recipient_v1::CoordinatedRecipientIntentV1;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadProvenanceV1 {
    principal_id: String,
    measurement: String,
    source_identity_digest: String,
    owner_selection_digest: String,
    owner_service_digest: String,
    read_session_digest: String,
    prepare_read_presentation_digest: String,
    receive_presentation_digest: String,
    approved_at_ms: u64,
    expires_at_ms: u64,
}

/// Separately frozen before initial owner selection is displayed. These are
/// original ceilings, not newly sampled allowances at AdmitRead or Audit.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerServiceCeilingsV1 {
    original_source_expires_at_ms: u64,
    original_material_expires_at_ms: u64,
    original_channel_expires_at_ms: u64,
    original_owner_service_expires_at_ms: u64,
}

/// New native post-Receive Read and its exact authenticated history result.
/// This does not change the earlier PrepareRead digest or action window.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmitReadProvenanceV1 {
    presentation_digest: String,
    source_identity_digest: String,
    recipient_intent_digest: String,
    owner_selection_digest: String,
    owner_service_digest: String,
    authenticated_history_digest: String,
    approved_at_ms: u64,
    expires_at_ms: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionProvenanceV1 {
    read_session_digest: String,
    admit_read_presentation_digest: String,
    final_presentation_digest: String,
    authenticated_ready_digest: String,
    reviewed_digest: String,
    reviewed_at_ms: u64,
    retained_at_ms: u64,
    expires_at_ms: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CoordinatedAdmissionIntentV1 {
    version: u16,
    request: OwnerControlRequest,
    disclosure: WitnessDisclosureDescriptor,
    owner_certificate_digest: String,
    enrollment_ref: String,
    manifest_ref: String,
    recipient_intent: CoordinatedRecipientIntentV1,
    read: ReadProvenanceV1,
    admit_read: AdmitReadProvenanceV1,
    ceilings: OwnerServiceCeilingsV1,
    admission: AdmissionProvenanceV1,
}

/// Strict canonical historical data. There is deliberately no Deserialize or
/// constructor on the retained wrapper and no live owner reconstructed here.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct RetainedCoordinatedAdmissionIntentV1(CoordinatedAdmissionIntentV1);
impl RetainedCoordinatedAdmissionIntentV1 {
    pub(crate) fn request(&self) -> &OwnerControlRequest {
        &self.0.request
    }
    pub(crate) fn disclosure(&self) -> &WitnessDisclosureDescriptor {
        &self.0.disclosure
    }
    pub(crate) fn owner_certificate_digest(&self) -> &str {
        &self.0.owner_certificate_digest
    }
    pub(crate) fn enrollment_ref(&self) -> &str {
        &self.0.enrollment_ref
    }
    pub(crate) fn manifest_ref(&self) -> &str {
        &self.0.manifest_ref
    }
    pub(crate) fn recipient_intent(&self) -> &CoordinatedRecipientIntentV1 {
        &self.0.recipient_intent
    }
    pub(crate) fn recipient_intent_digest(&self) -> Result<String> {
        self.0.recipient_intent.digest().map_err(invalid)
    }
    pub(crate) fn history_digest(&self) -> Result<String> {
        self.0.validate()?;
        digest(
            "wholepact:coordinated-durable-delivery-admission-history:v1",
            &self.0,
        )
    }
}

impl CoordinatedAdmissionIntentV1 {
    fn review_digest(&self) -> Result<String> {
        digest(
            "wholepact:coordinated-durable-delivery-admission-review:v1",
            &(
                self.version,
                &self.request,
                &self.disclosure,
                &self.owner_certificate_digest,
                &self.enrollment_ref,
                &self.manifest_ref,
                &self.recipient_intent,
                &self.read,
                &self.admit_read,
                &self.ceilings,
            ),
        )
    }
    fn request_digest(&self) -> Result<String> {
        digest(
            "wholepact:coordinated-durable-delivery-admission-request:v1",
            &self.request,
        )
    }
    fn validate_review(&self) -> Result<()> {
        actor_admit_read_detail_result!(AdmitReadIntentReviewNested, self.disclosure.validate().map_err(invalid))?;
        let scope = &actor_admit_read_detail_result!(AdmitReadIntentReviewNested, record(&self.request))?.scope;
        actor_admit_read_detail_result!(AdmitReadIntentReviewNested, actor_admit_read_detail_result!(AdmitReadIntentReviewNested, record(&self.request))?
            .validate_request(&self.request, &self.disclosure)
            .map_err(invalid))?;
        let r = &self.recipient_intent;
        actor_admit_read_detail_result!(AdmitReadIntentReviewNested, r.validate().map_err(invalid))?;
        let fixed: wholepact_authority::durable_payment_v1::DurableFixedCandidateBindingV1 =
            actor_admit_read_detail_result!(AdmitReadIntentReviewNested, serde_json::from_slice(&actor_admit_read_detail_result!(AdmitReadIntentReviewNested, serde_json::to_vec(&r.fixed).map_err(invalid))?)
                .map_err(invalid))?;
        for value in [
            &self.owner_certificate_digest,
            &self.enrollment_ref,
            &self.manifest_ref,
            &self.read.measurement,
            &self.read.source_identity_digest,
            &self.read.owner_selection_digest,
            &self.read.owner_service_digest,
            &self.read.read_session_digest,
            &self.read.prepare_read_presentation_digest,
            &self.read.receive_presentation_digest,
        ] {
            actor_admit_read_detail_result!(AdmitReadIntentReviewShape, hash(value))?;
        }
        actor_admit_read_detail_result!(AdmitReadIntentReviewShape, id(&self.read.principal_id))?;
        for value in [
            &self.admit_read.presentation_digest,
            &self.admit_read.source_identity_digest,
            &self.admit_read.recipient_intent_digest,
            &self.admit_read.owner_selection_digest,
            &self.admit_read.owner_service_digest,
            &self.admit_read.authenticated_history_digest,
        ] {
            actor_admit_read_detail_result!(AdmitReadIntentReviewShape, hash(value))?;
        }
        let service = self.ceilings.original_owner_service_expires_at_ms;
        if service == 0
            || service > self.ceilings.original_source_expires_at_ms
            || service > self.ceilings.original_channel_expires_at_ms
            || self.ceilings.original_material_expires_at_ms == 0
            || self.ceilings.original_material_expires_at_ms
                > self.ceilings.original_source_expires_at_ms
            || self.ceilings.original_material_expires_at_ms
                > self.ceilings.original_channel_expires_at_ms
            || self.read.expires_at_ms > self.ceilings.original_material_expires_at_ms
            || self.admit_read.expires_at_ms > self.ceilings.original_material_expires_at_ms
            || self.read.expires_at_ms > service
            || self.admit_read.source_identity_digest != self.read.source_identity_digest
            || self.admit_read.owner_selection_digest != self.read.owner_selection_digest
            || self.admit_read.owner_service_digest != self.read.owner_service_digest
            || self.admit_read.recipient_intent_digest != actor_admit_read_detail_result!(AdmitReadIntentReviewCeilings, r.digest().map_err(invalid))?
            || self.admit_read.approved_at_ms < self.read.approved_at_ms
            || self.admit_read.expires_at_ms <= self.admit_read.approved_at_ms
            || self.admit_read.expires_at_ms - self.admit_read.approved_at_ms > 120_000
            || self.admit_read.expires_at_ms > service
        {
            return actor_admit_read_detail_result!(AdmitReadIntentReviewCeilings, Err(JournalError::InvalidBinding));
        }

        if self.version != 4
            || r.original_enrollment_ref != self.enrollment_ref
            || r.original_manifest_ref != self.manifest_ref
            || r.request.enrollment_ref != self.enrollment_ref
            || r.request.accepted_manifest_ref != self.manifest_ref
            || r.account_id != self.request.account_id
            || scope.authorization.fixed != fixed
            || scope.accepted_manifest_ref != self.manifest_ref
            || scope.delivery != r.delivery
            || scope.original_ceilings.material_scopes != r.material_scopes
            || self.read.source_identity_digest != r.source_identity_digest
            || self.read.read_session_digest != r.read_session_digest
            || self.read.prepare_read_presentation_digest != self.read.read_session_digest
            || self.read.receive_presentation_digest != r.receive_decision_digest
            || self.read.approved_at_ms == 0
            || self.read.expires_at_ms <= self.read.approved_at_ms
            || self.read.expires_at_ms - self.read.approved_at_ms > 120_000
        {
            return actor_admit_read_detail_result!(AdmitReadIntentReviewBinding, Err(JournalError::InvalidBinding));
        }
        for material in &r.material_scopes {
            let from = actor_admit_read_detail_result!(AdmitReadIntentReviewMaterial, material
                .valid_from_unix_seconds
                .checked_mul(1000)
                .ok_or(JournalError::InvalidBinding))?;
            let until = actor_admit_read_detail_result!(AdmitReadIntentReviewMaterial, material
                .valid_until_unix_seconds
                .checked_mul(1000)
                .ok_or(JournalError::InvalidBinding))?;
            if self.read.approved_at_ms < from
                || self.read.expires_at_ms > until
                || self.admit_read.approved_at_ms < from
                || self.admit_read.expires_at_ms > until
            {
                return actor_admit_read_detail_result!(AdmitReadIntentReviewMaterial, Err(JournalError::InvalidBinding));
            }
        }
        Ok(())
    }
    fn validate(&self) -> Result<()> {
        self.validate_review()?;
        hash(&self.admission.read_session_digest)?;
        hash(&self.admission.reviewed_digest)?;
        hash(&self.admission.admit_read_presentation_digest)?;
        hash(&self.admission.final_presentation_digest)?;
        hash(&self.admission.authenticated_ready_digest)?;
        if self.admission.read_session_digest != self.read.read_session_digest
            || self.admission.reviewed_digest != self.review_digest()?
            || self.admission.admit_read_presentation_digest != self.admit_read.presentation_digest
            || self.admission.reviewed_at_ms < self.admit_read.approved_at_ms
            || self.admission.retained_at_ms < self.admission.reviewed_at_ms
            || self.admission.expires_at_ms <= self.admission.retained_at_ms
            || self.admission.expires_at_ms > self.admit_read.expires_at_ms
            || self.admission.expires_at_ms - self.admission.retained_at_ms > 120_000
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
}

fn validate_original_rows(c: &Connection, intent: &CoordinatedAdmissionIntentV1) -> Result<()> {
    actor_admit_read_detail_result!(AdmitReadIntentReview, intent.validate_review())?;
    actor_admit_read_detail_result!(AdmitReadIntentRowsOriginalLinks, super::validate_original_row_links(
        c,
        &intent.request,
        &intent.disclosure,
        &intent.owner_certificate_digest,
        &intent.enrollment_ref,
        &intent.manifest_ref,
        &intent.recipient_intent.participant_id,
        &intent.read.principal_id,
    ))?;
    let recipient = &intent.recipient_intent;
    let original = actor_admit_read_detail_result!(AdmitReadIntentRowsOriginalDisclosure, disclosure_row(c, &recipient.request.own_disclosure))?;
    if original.redisclosure().is_some() {
        return actor_admit_read_detail_result!(AdmitReadIntentRowsOriginalDisclosure, Err(JournalError::InvalidBinding));
    }
    // Coordinated entry requires a new current-session redisclosure. It cannot
    // inherit the historical row's transport or use legacy generation + 1.
    let current = actor_admit_read_detail_result!(AdmitReadIntentRowsCurrentDisclosure, disclosure_row(
        c,
        actor_admit_read_detail_result!(AdmitReadIntentRowsCurrentDisclosure, recipient
            .request
            .current_disclosure
            .as_ref()
            .ok_or(JournalError::InvalidBinding))?,
    ))?;
    actor_admit_read_detail_result!(AdmitReadIntentRowsCurrentDisclosure, current
        .validate_redisclosure_of(&original)
        .map_err(invalid))?;
    let enrollment =
        actor_admit_read_detail_result!(AdmitReadIntentRowsSession, storage::read_enrollment(c, &intent.enrollment_ref))?.ok_or(JournalError::NotFound)?;
    // These comparisons validate only retained provenance. Live preparation
    // and publication additionally need the actual same-session nonce map.
    if current.recipient_transport() != enrollment.transport()
        || enrollment.receipt().trusted_launch_measurement() != intent.read.measurement
        || enrollment.receipt().permission_generation != 1
    {
        return actor_admit_read_detail_result!(AdmitReadIntentRowsSession, Err(JournalError::InvalidBinding));
    }
    let TransportIdentityBinding::LocalProcess {
        process_instance,
        signer_generation,
        account_id,
        agreement_id,
        participant_id,
        manifest_digest,
        ..
    } = current.recipient_transport()
    else {
        return actor_admit_read_detail_result!(AdmitReadIntentRowsTransport, Err(JournalError::InvalidBinding));
    };
    if process_instance != &recipient.authorized_host_process_instance
        || *signer_generation != recipient.source_generation
        || account_id != &recipient.account_id
        || agreement_id != &recipient.agreement_id
        || participant_id != &recipient.participant_id
        || manifest_digest != &recipient.manifest_digest
    {
        return actor_admit_read_detail_result!(AdmitReadIntentRowsTransport, Err(JournalError::InvalidBinding));
    }
    let scope = &original.request().scope;
    let material = actor_admit_read_detail_result!(AdmitReadIntentRowsMaterial, recipient
        .material_scopes
        .iter()
        .find(|m| m.account_id == recipient.account_id)
        .ok_or(JournalError::InvalidBinding))?;
    if current.request().enrollment_ref != intent.enrollment_ref
        || current.request().accepted_manifest_ref != intent.manifest_ref
        || scope.account_id != recipient.account_id
        || scope.participant_id != recipient.participant_id
        || original.request().material.fvk_digest()
            != actor_admit_read_detail_result!(AdmitReadIntentRowsMaterial, record(&intent.request))?
                .scope
                .authorization
                .identity
                .full_viewing_key_digest
        || actor_admit_read_detail_result!(AdmitReadIntentRowsMaterial, scope.digest().map_err(invalid))? != material.original_scope_digest
        || scope.valid_from_unix_seconds != material.valid_from_unix_seconds
        || scope.valid_until_unix_seconds != material.valid_until_unix_seconds
    {
        return actor_admit_read_detail_result!(AdmitReadIntentRowsMaterial, Err(JournalError::InvalidBinding));
    }
    Ok(())
}

pub(crate) fn read(
    c: &Connection,
    authorization_id: &str,
) -> Result<Option<RetainedCoordinatedAdmissionIntentV1>> {
    id(authorization_id)?;
    let row: Option<(String,String,String,String,String)> = c.query_row(
        "SELECT operation_id,request_digest,enrollment_ref,manifest_ref,payload FROM signer_durable_payment_admission_intents WHERE authorization_id=?1",
        [authorization_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
    ).optional()?;
    row.map(
        |(operation, request_digest, enrollment, manifest, payload)| {
            let intent: CoordinatedAdmissionIntentV1 = decode(payload.clone())?;
            intent.validate()?;
            if intent.request.operation_id != operation
                || record(&intent.request)?
                    .scope
                    .authorization
                    .authorization_id
                    != authorization_id
                || intent.request_digest()? != request_digest
                || intent.enrollment_ref != enrollment
                || intent.manifest_ref != manifest
                || encode(&intent)?.as_str() != payload
            {
                return Err(JournalError::InvalidBinding);
            }
            validate_original_rows(c, &intent)?;
            Ok(RetainedCoordinatedAdmissionIntentV1(intent))
        },
    )
    .transpose()
}

/// Immutable local candidate, never permission to publish. No Deserialize or
/// caller-data constructor. Publication will require a different genuine Final.
pub(crate) struct PreparedCoordinatedAdmissionIntentV1 {
    journal: SignerJournalBinding,
    account: SignerAccountState,
    source_identity: String,
    intent: CoordinatedAdmissionIntentV1,
    review_digest: String,
}
// Pure exact-chain restrictions only. The fixed-cardinality entries below
// are assembled exclusively from the original prepared intent, retained source
// and genuine Final. Tests exercise the same predicate without minting any of
// those authorities. Digests/JSON are computed by the real methods at the call.
struct AdmissionPurposeChainV1<'a> {
    actors: (&'a wholepact_financial_coordinator_origin::FinancialActorContextV1,
             &'a wholepact_financial_coordinator_origin::FinancialActorContextV1),
    identities: [(&'a str, &'a str); 21],
    wall_ceilings: [(u64, u64); 3],
    original_deadlines: [(std::time::Instant, std::time::Instant); 4],
}
fn require_admission_purpose_chain(chain: &AdmissionPurposeChainV1<'_>) -> Result<()> {
    if chain.actors.0 != chain.actors.1
        || chain.identities.iter().any(|(a,b)| a != b)
        || chain.wall_ceilings.iter().any(|(a,b)| a != b)
        || chain.original_deadlines.iter().any(|(a,b)| a != b)
    {
        return Err(JournalError::Permission);
    }
    Ok(())
}

/// Inert exact-chain evidence, not a Final, permission or lease. Only the
/// original prepared intent joined to its retained source can construct it.
/// Owning these immutable presentations avoids a borrow of the intent that
/// must later move into the sole publication attempt.
pub(crate) struct CoordinatedAdmissionPurposeBindingV1 {
    prepare_read: wholepact_financial_coordinator_origin::SignerV3PrepareReadPresentationV1,
    admission: wholepact_financial_coordinator_origin::SignerV3AdmitPresentationV1,
}
impl CoordinatedAdmissionPurposeBindingV1 {
    pub(in crate::consent_journal) fn prepare_read(&self) -> &wholepact_financial_coordinator_origin::SignerV3PrepareReadPresentationV1 {
        &self.prepare_read
    }
    pub(in crate::consent_journal) fn require_admit(&self, action: &wholepact_financial_coordinator_origin::SignerV3AdmitFinalV1) -> Result<()> {
        action.check_current().map_err(invalid)?;
        if action.presentation() != &self.admission {
            return Err(JournalError::Permission);
        }
        Ok(())
    }
}
impl PreparedCoordinatedAdmissionIntentV1 {
    pub(crate) fn purpose_binding(
        &self,
        source: &crate::account::birth::enrollment::roster_v2::durable_entry_v1::CoordinatedPreparedDeliverySourceV1,
        action: &wholepact_financial_coordinator_origin::SignerV3AdmitFinalV1,
    ) -> Result<CoordinatedAdmissionPurposeBindingV1> {
        action.check_current().map_err(invalid)?;
        self.intent.validate_review()?;
        let read = source.cached_prepare_read().map_err(invalid)?;
        read.validate().map_err(invalid)?;
        action.presentation().validate().map_err(invalid)?;
        let facts = action.facts();
        let request_digest = self.intent.request_digest()?;
        let recipient_digest = self.intent.recipient_intent.digest().map_err(invalid)?;
        let request_json = serde_json::to_string(&self.intent.request).map_err(invalid)?;
        require_admission_purpose_chain(&AdmissionPurposeChainV1 {
            actors: (&action.presentation().actor, &read.actor),
            identities: [
                (&self.source_identity, source.source_identity()),
                (&self.source_identity, &read.facts.source_identity_digest),
                (&self.source_identity, &facts.read.source_identity_digest),
                (&self.intent.enrollment_ref, source.enrollment().reference()),
                (&self.intent.manifest_ref, source.manifest().reference()),
                (&self.intent.enrollment_ref, &read.facts.current_enrollment_ref),
                (&self.intent.manifest_ref, &read.facts.current_manifest_ref),
                (source.enrollment().receipt().native_session_id(), &read.facts.coordinated_session_id),
                (&self.intent.read.principal_id, source.enrollment().principal_id()),
                (&self.intent.read.measurement, source.peer().common_image_measurement()),
                (&self.intent.read.prepare_read_presentation_digest, &read.presentation_digest),
                (&self.intent.read.read_session_digest, &read.presentation_digest),
                (&self.intent.read.owner_selection_digest, &read.facts.owner_selection_digest),
                (&self.intent.owner_certificate_digest, &read.facts.owner_certificate_digest),
                (&self.review_digest, &facts.read.admission_review_digest),
                (&request_digest, &facts.read.admission_request_digest),
                (&self.intent.admit_read.presentation_digest, &facts.read.admit_read_presentation_digest),
                (&self.intent.admit_read.authenticated_history_digest, &facts.read.authenticated_history_digest),
                (&self.intent.read.owner_service_digest, &facts.read.owner_service_digest),
                (&recipient_digest, &facts.read.recipient_intent_digest),
                (&request_json, &facts.request_json),
            ],
            wall_ceilings: [
                (self.intent.ceilings.original_source_expires_at_ms, read.facts.source_expires_at_ms),
                (self.intent.ceilings.original_material_expires_at_ms, read.facts.material_expires_at_ms),
                (self.intent.ceilings.original_owner_service_expires_at_ms, read.facts.service_expires_at_ms),
            ],
            original_deadlines: [
                (action.original_source_deadline(), source.original_source_deadline()),
                (action.original_channel_deadline(), source.original_channel_deadline()),
                (action.original_material_deadline(), source.original_material_deadline()),
                (action.original_service_deadline(), source.original_service_deadline()),
            ],
        })?;
        action.check_current().map_err(invalid)?;
        Ok(CoordinatedAdmissionPurposeBindingV1 {
            prepare_read: read.clone(),
            admission: action.presentation().clone(),
        })
    }
}

impl PreparedCoordinatedAdmissionIntentV1 {
    pub(crate) fn request(&self) -> &OwnerControlRequest {
        &self.intent.request
    }
    pub(crate) fn review_digest(&self) -> &str {
        &self.review_digest
    }
    pub(crate) fn request_digest(&self) -> Result<String> {
        self.intent.request_digest()
    }
    pub(crate) fn display(&self) -> Result<String> {
        serde_json::to_string_pretty(&(
            &self.intent.request,
            &self.intent.disclosure,
            &self.intent.owner_certificate_digest,
            &self.intent.enrollment_ref,
            &self.intent.manifest_ref,
            &self.intent.recipient_intent,
            &self.intent.read,
            &self.intent.admit_read,
            &self.intent.ceilings,
        ))
        .map_err(invalid)
    }
}

impl SignerConsentJournal {
    pub(crate) fn prepare_coordinated_admission_intent_v1(
        &self,
        source: &crate::account::birth::enrollment::roster_v2::durable_entry_v1::CoordinatedPreparedDeliverySourceV1,
        action: &wholepact_financial_coordinator_origin::SignerV3AdmitReadFinalV1,
        economics: &crate::native_ui::durable_proposal_v1::VerifiedDurableEconomicsV1,
        recipient: &CoordinatedRecipientIntentV1,
        history: &wholepact_authority::ReconciledAuthorityHistory,
    ) -> Result<PreparedCoordinatedAdmissionIntentV1> {
        actor_admit_read_detail_result!(AdmitReadIntentSourceJournal, source
            .require_admission_journal(self, action))
            .map_err(invalid)?;
        let scope = actor_admit_read_detail_result!(AdmitReadIntentScope, source
            .admission_scope(action, economics, recipient, history))
            .map_err(invalid)?;
        let request = actor_admit_read_detail_result!(AdmitReadIntentAuthorityRequest, wholepact_authority::durable_delivery_admission_v2::prepare_durable_delivery_admission_request_v2(scope, history)).map_err(invalid)?;
        let read = actor_admit_read_detail_result!(AdmitReadIntentReadPresentation, source
            .admission_read_presentation(action))
            .map_err(invalid)?;
        let facts = action.facts();
        let intent = CoordinatedAdmissionIntentV1 {
            version: 4,
            request,
            disclosure: history.disclosure().clone(),
            owner_certificate_digest: facts.owner_certificate_digest.clone(),
            enrollment_ref: source.enrollment().reference().into(),
            manifest_ref: source.manifest().reference().into(),
            recipient_intent: recipient.clone(),
            read: ReadProvenanceV1 {
                principal_id: source.enrollment().principal_id().into(),
                measurement: source.peer().common_image_measurement().into(),
                source_identity_digest: read.facts.source_identity_digest.clone(),
                owner_selection_digest: read.facts.owner_selection_digest.clone(),
                owner_service_digest: facts.received.owner_service_digest.clone(),
                read_session_digest: read.presentation_digest.clone(),
                prepare_read_presentation_digest: read.presentation_digest.clone(),
                receive_presentation_digest: facts.received.receive_presentation_digest.clone(),
                approved_at_ms: read.facts.reviewed_at_ms,
                expires_at_ms: read.facts.expires_at_ms,
            },
            admit_read: AdmitReadProvenanceV1 {
                presentation_digest: action.presentation().presentation_digest.clone(),
                source_identity_digest: facts.received.source_identity_digest.clone(),
                recipient_intent_digest: facts.received.recipient_intent_digest.clone(),
                owner_selection_digest: facts.owner_selection_digest.clone(),
                owner_service_digest: facts.received.owner_service_digest.clone(),
                authenticated_history_digest: actor_admit_read_detail_result!(AdmitReadIntentHistoryDigest, history.history_digest()).map_err(invalid)?,
                approved_at_ms: facts.reviewed_at_ms,
                expires_at_ms: facts.expires_at_ms,
            },
            ceilings: OwnerServiceCeilingsV1 {
                original_source_expires_at_ms: read.facts.source_expires_at_ms,
                original_material_expires_at_ms: read.facts.material_expires_at_ms,
                original_owner_service_expires_at_ms: read.facts.service_expires_at_ms,
                original_channel_expires_at_ms: action.original_channel_expires_at_ms(),
            },
            admission: AdmissionProvenanceV1 {
                read_session_digest: String::new(),
                admit_read_presentation_digest: String::new(),
                final_presentation_digest: String::new(),
                authenticated_ready_digest: String::new(),
                reviewed_digest: String::new(),
                reviewed_at_ms: 0,
                retained_at_ms: 0,
                expires_at_ms: 0,
            },
        };
        actor_admit_read_detail_result!(AdmitReadIntentReview, intent.validate_review())?;
        let account = {
            let _fence = self
                .authority_fence
                .read()
                .map_err(|_| JournalError::Permission)?;
            actor_admit_read_detail_result!(AdmitReadIntentAction, action.check_current()).map_err(invalid)?;
            let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
            actor_admit_read_detail_result!(AdmitReadIntentAction, action.check_current()).map_err(invalid)?;
            actor_admit_read_detail_result!(AdmitReadIntentJournalIdentity, self.database_identity.check_current(&c))?;
            let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
            actor_admit_read_detail_result!(AdmitReadIntentAction, action.check_current()).map_err(invalid)?;
            actor_admit_read_detail_result!(AdmitReadIntentJournalSchema, storage::verify_schema(&tx))?;
            let account = actor_admit_read_detail_result!(AdmitReadIntentJournalAccount, storage::read_account(&tx))?;
            actor_admit_read_detail_result!(AdmitReadIntentCurrentRows, coordinated_current_rows(&tx, &intent))?;
            if !actor_admit_read_detail_result!(AdmitReadIntentFinancialRows, financial_admission_intents::read_all(&tx))?.is_empty() {
                return Err(JournalError::Conflict);
            }
            actor_admit_read_detail_result!(AdmitReadIntentJournalIdentity, self.database_identity.check_current(&tx))?;
            actor_admit_read_detail_result!(AdmitReadIntentAction, action.check_current()).map_err(invalid)?;
            tx.commit()?;
            account
        };
        actor_admit_read_detail_result!(AdmitReadIntentSourceJournal, source
            .require_admission_journal(self, action))
            .map_err(invalid)?;
        let review_digest = actor_admit_read_detail_result!(AdmitReadIntentReviewDigest, intent.review_digest())?;
        Ok(PreparedCoordinatedAdmissionIntentV1 {
            journal: self.binding(),
            account,
            source_identity: facts.received.source_identity_digest.clone(),
            intent,
            review_digest,
        })
    }
}

fn coordinated_current_rows(c: &Connection, intent: &CoordinatedAdmissionIntentV1) -> Result<()> {
    actor_admit_read_detail_result!(AdmitReadIntentOriginalRows, validate_original_rows(c, intent))?;
    let account = actor_admit_read_detail_result!(AdmitReadIntentRowsAccountUse, storage::read_account(c))?;
    let original = actor_admit_read_detail_result!(AdmitReadIntentRowsAccountUse, account_use_storage::inspect(c, &account.account_id))?;
    if account.recovery_required {
        return Err(JournalError::RecoveryRequired);
    }
    if account.writer_epoch != intent.request.writer_epoch
        || original.exclusion().is_some()
        || original.witness_ack().is_some()
    {
        return Err(JournalError::Permission);
    }
    let scope = &actor_admit_read_detail_result!(AdmitReadIntentRowsAccountUse, record(&intent.request))?.scope;
    let now = actor_admit_read_detail_result!(AdmitReadIntentRowsAccountUse, now_ms())?;
    if now < scope.authorization.valid_from_ms
        || now >= scope.authorization.valid_until_ms
        || now < scope.delivery.valid_from_ms
        || now >= scope.delivery.valid_until_ms
        || now < intent.admit_read.approved_at_ms
        || now >= intent.admit_read.expires_at_ms
    {
        return Err(JournalError::Expired);
    }
    Ok(())
}

/// Actual one-attempt local publication observation. An uncertain entered
/// transaction is never a retry grant, and committed records survive late R.
pub(crate) enum CoordinatedAdmissionRetentionV1 {
    EnteredFailed(JournalError),
    Retained {
        record: RetainedCoordinatedAdmissionIntentV1,
        pin: Option<PreparedDeliveryJournalRevisionV3>,
    },
}
impl SignerConsentJournal {
    pub(crate) fn retain_coordinated_admission_intent_v1(
        &self,
        prepared: PreparedCoordinatedAdmissionIntentV1,
        pin: PreparedDeliveryJournalRevisionV3,
        lease: &CoordinatedPurposeRecordLease<'_>,
        action: &wholepact_financial_coordinator_origin::SignerV3AdmitFinalV1,
        channel: &wholepact_authority::transport::durable_delivery_admission_v3::AuthenticatedDurableAdmissionChannelV3<'_>,
    ) -> Result<CoordinatedAdmissionRetentionV1> {
        action.check_current().map_err(invalid)?;
        channel.check_current().map_err(invalid)?;
        let facts = action.facts();
        let ready = action.ready();
        if prepared.journal != self.binding()
            || prepared.source_identity != facts.read.source_identity_digest
            || prepared.review_digest != facts.read.admission_review_digest
            || prepared.intent.request_digest()? != facts.read.admission_request_digest
            || prepared.intent.admit_read.presentation_digest
                != facts.read.admit_read_presentation_digest
            || prepared.intent.admit_read.authenticated_history_digest
                != facts.read.authenticated_history_digest
            || prepared.intent.read.owner_service_digest != facts.read.owner_service_digest
            || prepared.intent.recipient_intent.digest().map_err(invalid)?
                != facts.read.recipient_intent_digest
            || serde_json::to_string(&prepared.intent.request).map_err(invalid)?
                != facts.request_json
            || channel.request() != &prepared.intent.request
            || channel.authenticated_ready_digest_v1().map_err(invalid)?
                != ready.authenticated_ready_digest
            || lease.enrollment().reference() != prepared.intent.enrollment_ref
            || lease.manifest().reference() != prepared.intent.manifest_ref
        {
            return Err(JournalError::Permission);
        }
        lease.require_admit(action)?;
        let mut intent = prepared.intent;
        intent.admission = AdmissionProvenanceV1 {
            read_session_digest: intent.read.read_session_digest.clone(),
            admit_read_presentation_digest: intent.admit_read.presentation_digest.clone(),
            final_presentation_digest: action.presentation().presentation_digest.clone(),
            authenticated_ready_digest: ready.authenticated_ready_digest.clone(),
            reviewed_digest: prepared.review_digest,
            reviewed_at_ms: facts.reviewed_at_ms,
            retained_at_ms: now_ms()?,
            expires_at_ms: facts.expires_at_ms,
        };
        intent.validate()?;
        let result = self.with_coordinated_admission_effect_v1(pin, lease, action, |tx| {
            storage::check_account(tx, &prepared.account)?;
            coordinated_current_rows(tx, &intent)?;
            if !financial_admission_intents::read_all(tx)?.is_empty() { return Err(JournalError::Conflict); }
            let auth = &record(&intent.request)?.scope.authorization.authorization_id;
            let raw = encode(&intent)?;
            tx.execute("INSERT INTO signer_durable_payment_admission_intents(operation_id,authorization_id,request_digest,enrollment_ref,manifest_ref,payload) VALUES(?1,?2,?3,?4,?5,?6)", params![intent.request.operation_id,auth,intent.request_digest()?,intent.enrollment_ref,intent.manifest_ref,raw.as_str()])?;
            storage::bounded(tx, self.capacity_limits())?;
            coordinated_current_rows(tx, &intent)?;
            Ok(RetainedCoordinatedAdmissionIntentV1(intent.clone()))
        })?;
        match result {
            storage::CoordinatedAdmissionPublicationV1::EnteredFailed(error) => Ok(CoordinatedAdmissionRetentionV1::EnteredFailed(error)),
            storage::CoordinatedAdmissionPublicationV1::Retained { record, pin } => Ok(CoordinatedAdmissionRetentionV1::Retained { record, pin }),
        }
    }
}

#[cfg(test)]
#[path = "coordinated_v1/handoff_chain_tests.rs"]
mod handoff_chain_tests;

#[cfg(all(test, feature = "synthetic-qualification"))]
#[path = "coordinated_v1/full_intent_validation_tests.rs"]
mod full_intent_validation_tests;
