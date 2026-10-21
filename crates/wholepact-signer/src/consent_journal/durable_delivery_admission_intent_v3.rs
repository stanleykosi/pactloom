//! Closed-source prospective admission. Historical provenance is data, never a
//! reconstructed native receipt, read owner, action, or financial capability.
use super::*;
#[cfg(feature = "coordinated-financial-workflow-v1")]
#[path = "durable_delivery_admission_intent_v3/coordinated_v1.rs"]
pub(crate) mod coordinated_v1;
use crate::authority_bridge::durable_review_ipc_v3::RecipientIntentV3;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use wholepact_authority::{
    account_use_link::account_use_witness_origin_digest,
    durable_delivery_admission_v2::DurableDeliveryAdmissionRecordV2,
    OwnerControl, OwnerControlRequest, WitnessDisclosureDescriptor,
};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedReadProvenanceV3 {
    principal_id: String,
    measurement: String,
    read_session_digest: String,
    receive_decision_digest: String,
    approved_at_ms: u64,
    expires_at_ms: u64,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionProvenanceV3 {
    read_session_digest: String,
    reviewed_digest: String,
    reviewed_at_ms: u64,
    retained_at_ms: u64,
    expires_at_ms: u64,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableDeliveryAdmissionIntentV3 {
    version: u16,
    request: OwnerControlRequest,
    disclosure: WitnessDisclosureDescriptor,
    owner_certificate_digest: String,
    enrollment_ref: String,
    manifest_ref: String,
    recipient_intent: RecipientIntentV3,
    read: PreparedReadProvenanceV3,
    admission: AdmissionProvenanceV3,
}
/// Strictly validated, immutable historical DATA. Cloning this does not create
/// any prepared/read/action owner; none of those implements Deserialize.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct RetainedDurableDeliveryAdmissionIntentV3(DurableDeliveryAdmissionIntentV3);
impl RetainedDurableDeliveryAdmissionIntentV3 {
    pub(crate) fn request(&self) -> &OwnerControlRequest { &self.0.request }
    pub(crate) fn disclosure(&self) -> &WitnessDisclosureDescriptor { &self.0.disclosure }
    pub(crate) fn owner_certificate_digest(&self) -> &str { &self.0.owner_certificate_digest }
    pub(crate) fn enrollment_ref(&self) -> &str { &self.0.enrollment_ref }
    pub(crate) fn manifest_ref(&self) -> &str { &self.0.manifest_ref }
    pub(crate) fn recipient_intent(&self) -> &RecipientIntentV3 { &self.0.recipient_intent }
    pub(crate) fn recipient_intent_digest(&self) -> Result<String> { self.0.recipient_intent.digest().map_err(invalid) }
    pub(crate) fn native_review_digest(&self) -> &str { &self.0.admission.reviewed_digest }
    pub(crate) fn history_digest(&self) -> Result<String> {
        self.0.validate()?;
        digest("wholepact:signer-durable-delivery-admission-intent-history:v3", &self.0)
    }
}
fn invalid(_: impl std::fmt::Display) -> JournalError { JournalError::InvalidBinding }
fn record(request: &OwnerControlRequest) -> Result<&DurableDeliveryAdmissionRecordV2> {
    match &request.control {
        OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } => Ok(record),
        _ => Err(JournalError::InvalidBinding),
    }
}
impl DurableDeliveryAdmissionIntentV3 {
    fn review_digest(&self) -> Result<String> {
        digest("wholepact:signer-durable-delivery-admission-review:v3", &(
            self.version, &self.request, &self.disclosure, &self.owner_certificate_digest,
            &self.enrollment_ref, &self.manifest_ref, &self.recipient_intent, &self.read,
        ))
    }
    fn request_digest(&self) -> Result<String> {
        digest("wholepact:signer-durable-delivery-admission-request:v3", &self.request)
    }
    fn validate_review(&self) -> Result<()> {
        self.disclosure.validate().map_err(invalid)?;
        let scope = &record(&self.request)?.scope;
        record(&self.request)?.validate_request(&self.request, &self.disclosure).map_err(invalid)?;
        self.recipient_intent.validate().map_err(invalid)?;
        let r = &self.recipient_intent;
        let fixed: wholepact_authority::durable_payment_v1::DurableFixedCandidateBindingV1 =
            serde_json::from_slice(&serde_json::to_vec(&r.fixed).map_err(invalid)?).map_err(invalid)?;
        for h in [&self.owner_certificate_digest, &self.enrollment_ref, &self.manifest_ref,
            &self.read.measurement, &self.read.read_session_digest, &self.read.receive_decision_digest] { hash(h)?; }
        id(&self.read.principal_id)?;
        if self.version != 3
            || r.original_enrollment_ref != self.enrollment_ref
            || r.original_manifest_ref != self.manifest_ref
            || r.request.enrollment_ref != self.enrollment_ref
            || r.request.accepted_manifest_ref != self.manifest_ref
            || r.account_id != self.request.account_id
            || scope.authorization.fixed != fixed
            || scope.accepted_manifest_ref != self.manifest_ref
            || scope.delivery != r.delivery
            || scope.original_ceilings.material_scopes != r.material_scopes
            || self.read.read_session_digest != r.read_session_digest
            || self.read.receive_decision_digest != r.receive_decision_digest
            || self.read.receive_decision_digest != crate::native_ui::receive_review_digest_v3(r).map_err(invalid)?
            || self.read.approved_at_ms == 0
            || self.read.expires_at_ms <= self.read.approved_at_ms
            || self.read.expires_at_ms - self.read.approved_at_ms > 120_000
        { return Err(JournalError::InvalidBinding); }
        for material in &r.material_scopes {
            let from = material.valid_from_unix_seconds.checked_mul(1000).ok_or(JournalError::InvalidBinding)?;
            let until = material.valid_until_unix_seconds.checked_mul(1000).ok_or(JournalError::InvalidBinding)?;
            if self.read.approved_at_ms < from || self.read.expires_at_ms > until {
                return Err(JournalError::InvalidBinding);
            }
        }
        Ok(())
    }
    fn validate(&self) -> Result<()> {
        self.validate_review()?;
        hash(&self.admission.read_session_digest)?;
        hash(&self.admission.reviewed_digest)?;
        if self.admission.read_session_digest != self.read.read_session_digest
            || self.admission.reviewed_digest != self.review_digest()?
            || self.admission.reviewed_at_ms < self.read.approved_at_ms
            || self.admission.retained_at_ms < self.admission.reviewed_at_ms
            || self.admission.expires_at_ms <= self.admission.retained_at_ms
            || self.admission.expires_at_ms > self.read.expires_at_ms
            || self.admission.expires_at_ms - self.admission.retained_at_ms > 120_000
        { return Err(JournalError::InvalidBinding); }
        Ok(())
    }
}

/// The old enrollment/manifest receipts remain their ORIGINAL native lineage.
/// Fresh V3 read/admit provenance is explicitly separate, never spliced into it.
fn validate_original_rows(c: &Connection, intent: &DurableDeliveryAdmissionIntentV3) -> Result<()> {
    intent.validate_review()?;
    validate_original_row_links(
        c, &intent.request, &intent.disclosure, &intent.owner_certificate_digest,
        &intent.enrollment_ref, &intent.manifest_ref,
        &intent.recipient_intent.participant_id, &intent.read.principal_id,
    )?;
    validate_disclosure_lineage(c, intent)?;
    Ok(())
}

/// Data-only original19 equality kernel shared by explicitly tagged admission
/// profiles. Each caller validates its own closed recipient/review envelope and
/// disclosure lineage separately. This never reads or manufactures permission.
fn validate_original_row_links(
    c: &Connection,
    request: &OwnerControlRequest,
    disclosure: &WitnessDisclosureDescriptor,
    owner_certificate_digest: &str,
    enrollment_ref: &str,
    manifest_ref: &str,
    participant_id: &str,
    principal_id: &str,
) -> Result<()> {
    let terms = &record(request)?.scope.authorization;
    let account = storage::read_account(c)?;
    let stored = account_use_storage::inspect(c, &account.account_id)?;
    let genesis = stored.genesis().ok_or(JournalError::InvalidBinding)?;
    let enrollment = storage::read_enrollment(c, enrollment_ref)?.ok_or(JournalError::NotFound)?;
    let manifest = storage::read_manifest(c, manifest_ref)?.ok_or(JournalError::NotFound)?;
    let proposal = manifest.proposal()?;
    if record(request)?.scope.accepted_manifest_ref != manifest_ref
        || record(request)?.scope.original_writer_epoch != request.writer_epoch
        || &record(request)?.scope.witness != disclosure
        || account.account_id != request.account_id
        || request.writer_epoch > account.writer_epoch
        || genesis.identity.account_id != terms.identity.account_id
        || genesis.identity.full_viewing_key_digest != terms.identity.full_viewing_key_digest
        || genesis.identity.network_profile_id != terms.identity.network_profile_id
        || genesis.identity.derivation_domain != terms.identity.derivation_domain
        || genesis.digest().map_err(invalid)? != terms.original_genesis_digest
        || genesis.owner_certificate_digest != owner_certificate_digest
        || genesis.witness_id != disclosure.witness_id
        || genesis.witness_origin_digest != account_use_witness_origin_digest(disclosure).map_err(invalid)?
        || enrollment.account_id() != request.account_id
        || enrollment.account_fvk_digest() != terms.identity.full_viewing_key_digest
        || enrollment.terms.network_profile_id != request.network_profile_id
        || enrollment.agreement_id() != terms.fixed.agreement_id
        || enrollment.participant_id() != participant_id
        || manifest.enrollment_ref() != enrollment_ref
        || manifest.terms.account_id != request.account_id
        || manifest.terms.principal_id != enrollment.principal_id()
        || enrollment.principal_id() != principal_id
        || proposal.input().proposal_id != terms.fixed.proposal_id
        || proposal.manifest().agreement.revision != terms.fixed.revision
        || proposal.proposal_digest() != terms.fixed.proposal_digest
        || proposal.manifest_digest() != terms.fixed.manifest_digest
        || !storage::same_native_origin(enrollment.receipt(), manifest.receipt())
    { return Err(JournalError::InvalidBinding); }
    enrollment.transport().validate_scope(enrollment.account_id(), enrollment.agreement_id(), enrollment.participant_id(), Some(proposal.manifest_digest()))?;
    Ok(())
}

fn disclosure_row(
    c: &Connection,
    history: &crate::authority_bridge::durable_construction_v1::DurableConstructionHistoryRequestV1,
) -> Result<crate::authority_bridge::durable_construction_v1::DurableConstructionOutboxV1> {
    history.validate().map_err(invalid)?;
    let row: (String, String, String, String) = c.query_row(
        "SELECT request_digest,enrollment_ref,manifest_ref,payload FROM signer_durable_construction_outbox WHERE operation_id=?1",
        [&history.operation_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
    ).optional()?.ok_or(JournalError::NotFound)?;
    let value: crate::authority_bridge::durable_construction_v1::DurableConstructionOutboxV1 = decode(row.3.clone())?;
    let proposal = value.validate_with_proposal().map_err(invalid)?;
    let enrollment = storage::read_enrollment(c, &value.request().enrollment_ref)?.ok_or(JournalError::NotFound)?;
    let manifest = storage::read_manifest(c, &value.request().accepted_manifest_ref)?.ok_or(JournalError::NotFound)?;
    if enrollment.account_id() != value.request().scope.account_id
        || enrollment.account_fvk_digest() != value.request().material.fvk_digest()
        || enrollment.participant_id() != value.request().scope.participant_id
        || enrollment.agreement_id() != proposal.manifest().agreement.agreement_id
        || manifest.enrollment_ref() != value.request().enrollment_ref
        || manifest.proposal_input() != &value.request().scope.proposal
        || storage::read_account(c)?.account_id != value.request().scope.account_id
    { return Err(JournalError::InvalidBinding); }
    if value.request().operation_id != history.operation_id
        || value.request_digest() != history.expected_request_digest
        || value.request_digest() != row.0
        || value.request().enrollment_ref != row.1
        || value.request().accepted_manifest_ref != row.2
        || encode(&value)?.as_str() != row.3
    { return Err(JournalError::InvalidBinding); }
    Ok(value)
}
fn validate_disclosure_lineage(c: &Connection, intent: &DurableDeliveryAdmissionIntentV3) -> Result<()> {
    // Historical rows stay under their own original native provenance. The
    // source's initial full audit covers the complete outbox inventory; this
    // bounded selected-row join retains exact original/current FKs without
    // replaying the whole encrypted history at the final pinned effect.
    let recipient = &intent.recipient_intent;
    let original = disclosure_row(c, &recipient.request.own_disclosure)?;
    if original.redisclosure().is_some() { return Err(JournalError::InvalidBinding); }
    let current = match &recipient.request.current_disclosure {
        Some(history) => {
            let current = disclosure_row(c, history)?;
            current.validate_redisclosure_of(&original).map_err(invalid)?;
            current
        }
        None => original.clone(),
    };
    let TransportIdentityBinding::LocalProcess { process_instance, signer_generation, account_id, agreement_id, participant_id, manifest_digest, .. } = current.recipient_transport() else {
        return Err(JournalError::InvalidBinding);
    };
    // Grant-only revocation consumes exactly one actual IPC generation at
    // the closed transition. The original outbox generation is historical and
    // is never rewritten or rebound to the newly reviewed prepared source.
    if process_instance != &recipient.authorized_host_process_instance
        || signer_generation.checked_add(1) != Some(recipient.source_generation)
        || account_id != &recipient.account_id || agreement_id != &recipient.agreement_id
        || participant_id != &recipient.participant_id || manifest_digest != &recipient.manifest_digest
    { return Err(JournalError::InvalidBinding); }
    let scope = &original.request().scope;
    let material = recipient.material_scopes.iter().find(|m| m.account_id == recipient.account_id).ok_or(JournalError::InvalidBinding)?;
    if current.request().enrollment_ref != intent.enrollment_ref
        || current.request().accepted_manifest_ref != intent.manifest_ref
        || scope.account_id != recipient.account_id
        || scope.participant_id != recipient.participant_id
        || original.request().material.fvk_digest() != record(&intent.request)?.scope.authorization.identity.full_viewing_key_digest
        || scope.digest().map_err(invalid)? != material.original_scope_digest
        || scope.valid_from_unix_seconds != material.valid_from_unix_seconds
        || scope.valid_until_unix_seconds != material.valid_until_unix_seconds
    { return Err(JournalError::InvalidBinding); }
    Ok(())
}
pub(crate) fn read(c: &Connection, authorization_id: &str) -> Result<Option<RetainedDurableDeliveryAdmissionIntentV3>> {
    id(authorization_id)?;
    let row: Option<(String,String,String,String,String)> = c.query_row(
        "SELECT operation_id,request_digest,enrollment_ref,manifest_ref,payload FROM signer_durable_payment_admission_intents WHERE authorization_id=?1",
        [authorization_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
    ).optional()?;
    row.map(|(operation, request_digest, enrollment, manifest, payload)| {
        let intent: DurableDeliveryAdmissionIntentV3 = decode(payload.clone())?;
        intent.validate()?;
        if intent.request.operation_id != operation
            || record(&intent.request)?.scope.authorization.authorization_id != authorization_id
            || intent.request_digest()? != request_digest
            || intent.enrollment_ref != enrollment || intent.manifest_ref != manifest
            || encode(&intent)?.as_str() != payload
        { return Err(JournalError::InvalidBinding); }
        validate_original_rows(c, &intent)?;
        Ok(RetainedDurableDeliveryAdmissionIntentV3(intent))
    }).transpose()
}

use crate::account::birth::enrollment::roster_v2::durable_entry_v1::ActivePreparedDeliverySourceV3;
use crate::native_ui::{ExactDurableActionV3, PreparedReceiveAndViewAuthorityV3};

/// No Clone/Serde and no data constructor. Its actual read owner and original
/// journal binding must survive unchanged until the same-stream READY effect.
pub(crate) struct PreparedDurableDeliveryAdmissionIntentV3 {
    journal: SignerJournalBinding,
    account: SignerAccountState,
    source_identity: String,
    read_owner: Arc<PreparedReceiveAndViewAuthorityV3>,
    intent: DurableDeliveryAdmissionIntentV3,
    review_digest: String,
}
impl PreparedDurableDeliveryAdmissionIntentV3 {
    pub(crate) fn digest(&self) -> &str { &self.review_digest }
    pub(crate) fn review_digest(&self) -> &str { &self.review_digest }
    pub(crate) fn request(&self) -> &OwnerControlRequest { &self.intent.request }
    pub(crate) fn display(&self) -> Result<String> {
        self.read_owner.check_recipient(&self.intent.recipient_intent).map_err(invalid)?;
        // Pending admission provenance is deliberately absent from native review.
        serde_json::to_string_pretty(&(&self.intent.request, &self.intent.disclosure,
            &self.intent.owner_certificate_digest, &self.intent.enrollment_ref,
            &self.intent.manifest_ref, &self.intent.recipient_intent, &self.intent.read)).map_err(invalid)
    }
}
fn milliseconds(value: std::time::Duration) -> Result<u64> { u64::try_from(value.as_millis()).map_err(invalid) }
fn current_rows(c: &Connection, intent: &DurableDeliveryAdmissionIntentV3) -> Result<()> {
    validate_original_rows(c, intent)?;
    let account = storage::read_account(c)?;
    let original = account_use_storage::inspect(c, &account.account_id)?;
    if account.recovery_required { return Err(JournalError::RecoveryRequired); }
    if account.writer_epoch != intent.request.writer_epoch || original.exclusion().is_some() || original.witness_ack().is_some() { return Err(JournalError::Permission); }
    let scope = &record(&intent.request)?.scope;
    let now = now_ms()?;
    if now < scope.authorization.valid_from_ms || now >= scope.authorization.valid_until_ms
        || now < scope.delivery.valid_from_ms || now >= scope.delivery.valid_until_ms
        || now < intent.read.approved_at_ms || now >= intent.read.expires_at_ms
    { return Err(JournalError::Expired); }
    Ok(())
}
fn require_source(journal: &SignerConsentJournal, source: &ActivePreparedDeliverySourceV3, read: &Arc<PreparedReceiveAndViewAuthorityV3>, recipient: &RecipientIntentV3) -> Result<()> {
    source.check_current().map_err(invalid)?;
    read.check_recipient(recipient).map_err(invalid)?;
    if !Arc::ptr_eq(source.read(), read)
        || source.identity() != recipient.source_identity_digest
        || !std::ptr::eq(Arc::as_ptr(source.journal().map_err(invalid)?), journal)
    { return Err(JournalError::Permission); }
    Ok(())
}
impl SignerConsentJournal {
    pub(crate) fn prepare_durable_delivery_admission_intent_v3(
        &self,
        verified: &crate::native_ui::VerifiedImportV3,
        source: &ActivePreparedDeliverySourceV3,
        read: &Arc<PreparedReceiveAndViewAuthorityV3>,
        recipient: &RecipientIntentV3,
        request: OwnerControlRequest,
        disclosure: WitnessDisclosureDescriptor,
        owner_certificate_digest: &str,
    ) -> Result<PreparedDurableDeliveryAdmissionIntentV3> {
        verified.require_journal_binding_v3(source, read, recipient).map_err(invalid)?;
        require_source(self, source, read, recipient)?;
        let account = self.account_state()?;
        let now = now_ms()?;
        let monotonic = Instant::now();
        let approved_at_ms = now.checked_sub(milliseconds(monotonic.checked_duration_since(read.approved_at()).ok_or(JournalError::Expired)?)?).ok_or(JournalError::Expired)?;
        let expires_at_ms = now.checked_add(milliseconds(read.deadline().map_err(invalid)?.checked_duration_since(monotonic).ok_or(JournalError::Expired)?)?).ok_or(JournalError::Expired)?
            .min(recipient.material_scopes.iter().map(|m| m.valid_until_unix_seconds.checked_mul(1000).ok_or(JournalError::InvalidBinding)).collect::<Result<Vec<_>>>()?.into_iter().min().ok_or(JournalError::InvalidBinding)?);
        let intent = DurableDeliveryAdmissionIntentV3 {
            version: 3, request, disclosure, owner_certificate_digest: owner_certificate_digest.into(),
            enrollment_ref: recipient.original_enrollment_ref.clone(), manifest_ref: recipient.original_manifest_ref.clone(),
            recipient_intent: recipient.clone(),
            read: PreparedReadProvenanceV3 { principal_id: read.principal_id().into(), measurement: read.measurement().into(), read_session_digest: read.binding().entry_digest().into(), receive_decision_digest: read.receive_decision_digest().into(), approved_at_ms, expires_at_ms },
            admission: AdmissionProvenanceV3 { read_session_digest: String::new(), reviewed_digest: String::new(), reviewed_at_ms: 0, retained_at_ms: 0, expires_at_ms: 0 },
        };
        {
            let _fence = self.authority_fence.read().map_err(|_| JournalError::Permission)?;
            let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
            self.database_identity.check_current(&c)?;
            let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
            storage::check_account(&tx, &account)?;
            storage::verify_schema(&tx)?;
            current_rows(&tx, &intent)?;
            // One prospective local admission, never replay/rebase/re-sign.
            if !financial_admission_intents::read_all(&tx)?.is_empty() { return Err(JournalError::Conflict); }
            self.database_identity.check_current(&tx)?;
            read.check_recipient(recipient).map_err(invalid)?;
            tx.commit()?;
        }
        require_source(self, source, read, recipient)?;
        let review_digest = intent.review_digest()?;
        Ok(PreparedDurableDeliveryAdmissionIntentV3 { journal: self.binding(), account, source_identity: source.identity().into(), read_owner: Arc::clone(read), intent, review_digest })
    }

    /// The action can only follow authenticated READY. Acquire its real native
    /// publication lease, consume the actual source pin, and retain under that
    /// exact journal's Immediate transaction. No callback claims held authority.
    pub(crate) fn retain_durable_delivery_admission_intent_v3(
        &self,
        prepared: PreparedDurableDeliveryAdmissionIntentV3,
        source: &ActivePreparedDeliverySourceV3,
        action: ExactDurableActionV3,
    ) -> Result<(RetainedDurableDeliveryAdmissionIntentV3, PreparedDeliveryJournalRevisionV3, ExactDurableActionV3)> {
        require_source(self, source, &prepared.read_owner, &prepared.intent.recipient_intent)?;
        action.check_current().map_err(invalid)?;
        if prepared.journal != self.binding() || prepared.source_identity != source.identity()
            || action.binding() != &prepared.read_owner.binding()
            || action.admission_request().map_err(invalid)? != &prepared.intent.request
            || action.reviewed_digest().map_err(invalid)? != prepared.review_digest
        { return Err(JournalError::Permission); }
        let binding = action.binding().clone();
        let publication = binding.publication_lease().map_err(invalid)?;
        let now = now_ms()?;
        let monotonic = Instant::now();
        let reviewed_at_ms = now.checked_sub(milliseconds(monotonic.checked_duration_since(action.reviewed_at().map_err(invalid)?).ok_or(JournalError::Expired)?)?).ok_or(JournalError::Expired)?;
        let expires_at_ms = now.checked_add(milliseconds(action.deadline().checked_duration_since(monotonic).ok_or(JournalError::Expired)?)?).ok_or(JournalError::Expired)?.min(prepared.intent.read.expires_at_ms);
        let mut intent = prepared.intent;
        intent.admission = AdmissionProvenanceV3 { read_session_digest: binding.entry_digest().into(), reviewed_digest: prepared.review_digest, reviewed_at_ms, retained_at_ms: now, expires_at_ms };
        intent.validate()?;
        let pin = source.take_revision().map_err(invalid)?;
        let (retained, pin) = self.with_delivery_journal_effect_v3(pin, |tx| {
            storage::check_account(tx, &prepared.account)?;
            current_rows(tx, &intent)?;
            source.check_data_current().map_err(invalid)?;
            action.check_current().map_err(invalid)?;
            if !financial_admission_intents::read_all(tx)?.is_empty() { return Err(JournalError::Conflict); }
            let auth = &record(&intent.request)?.scope.authorization.authorization_id;
            let raw = encode(&intent)?;
            tx.execute("INSERT INTO signer_durable_payment_admission_intents(operation_id,authorization_id,request_digest,enrollment_ref,manifest_ref,payload) VALUES(?1,?2,?3,?4,?5,?6)", params![intent.request.operation_id, auth, intent.request_digest()?, intent.enrollment_ref, intent.manifest_ref, raw.as_str()])?;
            storage::bounded(tx, self.capacity_limits())?;
            current_rows(tx, &intent)?;
            source.check_data_current().map_err(invalid)?;
            action.check_current().map_err(invalid)?;
            Ok(RetainedDurableDeliveryAdmissionIntentV3(intent.clone()))
        })?;
        drop(publication);
        Ok((retained, pin, action))
    }

    /// A newly opened, fully audited actual source and new read owner may read
    /// old intent DATA, even after its historical read/admit times have expired.
    /// This never changes or resends the stored operation.
    pub(crate) fn durable_delivery_admission_intent_v3(
        &self,
        authorization_id: &str,
        source: &ActivePreparedDeliverySourceV3,
    ) -> Result<Option<RetainedDurableDeliveryAdmissionIntentV3>> {
        source.check_current().map_err(invalid)?;
        if !std::ptr::eq(Arc::as_ptr(source.journal().map_err(invalid)?), self) { return Err(JournalError::Permission); }
        let result = {
            let _fence = self.authority_fence.read().map_err(|_| JournalError::Permission)?;
            let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
            self.database_identity.check_current(&c)?;
            let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
            let value = read(&tx, authorization_id)?;
            if value.as_ref().is_some_and(|v| v.0.read.principal_id != source.read().principal_id()) { return Err(JournalError::Permission); }
            self.database_identity.check_current(&tx)?;
            source.read().binding().check_current().map_err(invalid)?;
            tx.commit()?;
            value
        };
        source.check_current().map_err(invalid)?;
        Ok(result)
    }
}
