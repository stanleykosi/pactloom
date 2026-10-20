//! Immutable new financial intent preimage. Historical rows are data, never an
//! issued native action, active writer, reservation or dispatcher admission.
use super::*;
use serde::{Deserialize, Serialize};
use wholepact_authority::{OwnerControl, OwnerControlRequest, durable_financial_continuation_v1::{FinancialContinuationRecordV1, original_delivery_request_digest_v1, prepare_financial_continuation_request_v1}};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewProvenanceV1 {
    source_identity_digest: String,
    principal_id: String,
    measurement: String,
    session_digest: String,
    permission_generation: u64,
    nonce: String,
    reviewed_at_ms: u64,
    expires_at_ms: u64,
    terms_digest: String,
    native_review_digest: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinancialContinuationIntentV1 {
    version: u16,
    request: OwnerControlRequest,
    owner_certificate_digest: String,
    review: ReviewProvenanceV1,
}
#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct RetainedFinancialContinuationIntentV1(FinancialContinuationIntentV1);
impl RetainedFinancialContinuationIntentV1 {
    pub(crate) fn request(&self) -> &OwnerControlRequest { &self.0.request }
    pub(crate) fn terms(&self) -> Result<&FinancialContinuationTermsV1> { Ok(&record(&self.0.request)?.terms) }
    pub(crate) fn history_digest(&self) -> Result<String> { self.0.validate()?; digest("wholepact:signer-financial-continuation-history:v1", &self.0) }
    pub(super) fn require_original(&self, genesis: &AccountUseGenesis) -> Result<()> {
        let t = self.terms()?;
        if t.scope.authorization.identity.account_id != genesis.identity.account_id
            || t.scope.authorization.identity.full_viewing_key_digest != genesis.identity.full_viewing_key_digest
            || t.scope.authorization.identity.network_profile_id != genesis.identity.network_profile_id
            || t.scope.authorization.identity.derivation_domain != genesis.identity.derivation_domain
            || self.0.owner_certificate_digest != genesis.owner_certificate_digest
            || wholepact_authority::account_use_link::account_use_witness_origin_digest(&t.scope.witness).map_err(invalid)? != genesis.witness_origin_digest
            || t.scope.witness.witness_id != genesis.witness_id { return Err(JournalError::InvalidBinding); }
        Ok(())
    }
}
fn invalid(_: impl std::fmt::Display) -> JournalError { JournalError::InvalidBinding }
fn record(request: &OwnerControlRequest) -> Result<&FinancialContinuationRecordV1> {
    match &request.control { OwnerControl::AdmitFinancialContinuationV1 { record } => Ok(record), _ => Err(JournalError::InvalidBinding) }
}
fn intent_digest(terms: &FinancialContinuationTermsV1, owner: &str, review: &ReviewProvenanceV1) -> Result<String> {
    digest("wholepact:signer-financial-continuation-intent-preimage:v1", &(1_u16, terms, owner, review))
}
impl FinancialContinuationIntentV1 {
    fn validate(&self) -> Result<()> {
        let record = record(&self.request)?;
        record.validate_request(&self.request, &record.terms.scope.witness).map_err(invalid)?;
        let r = &self.review;
        for h in [&r.source_identity_digest, &r.measurement, &r.session_digest, &r.nonce, &r.terms_digest, &r.native_review_digest] { hash(h)?; }
        id(&r.principal_id)?;
        hash(&self.owner_certificate_digest)?;
        if self.version != 1 || r.permission_generation != 1 || r.terms_digest != record.terms.intent_terms_digest().map_err(invalid)?
            || r.reviewed_at_ms == 0 || r.expires_at_ms <= r.reviewed_at_ms || r.expires_at_ms - r.reviewed_at_ms > 120_000
            || r.reviewed_at_ms < record.terms.valid_from_ms || r.expires_at_ms > record.terms.valid_until_ms
            || record.signer_continuation_intent_digest != intent_digest(&record.terms, &self.owner_certificate_digest, r)? { return Err(JournalError::InvalidBinding); }
        encode(self)?;
        Ok(())
    }
}
fn validate_original(c: &Connection, intent: &FinancialContinuationIntentV1) -> Result<()> {
    intent.validate()?;
    let terms = &record(&intent.request)?.terms;
    let original = authority::durable_delivery_admission_intent_v3::read(c, &terms.scope.authorization.authorization_id)?.ok_or(JournalError::NotFound)?;
    let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record: original_record } = &original.request().control else { return Err(JournalError::InvalidBinding); };
    if original_record.scope != terms.scope
        || original.request().operation_id != terms.original_delivery_operation_id
        || original_delivery_request_digest_v1(original.request()).map_err(invalid)? != terms.original_delivery_request_digest
        || original.history_digest()? != terms.original_local_intent_digest
        || original.recipient_intent_digest()? != terms.original_recipient_intent_digest
        || original.enrollment_ref() != terms.original_recipient_enrollment_ref
        || original.manifest_ref() != terms.original_recipient_manifest_ref
        || original.disclosure() != &terms.scope.witness
        || original.owner_certificate_digest() != intent.owner_certificate_digest
    { return Err(JournalError::InvalidBinding); }
    let enrollment = read_enrollment(c, original.enrollment_ref())?.ok_or(JournalError::NotFound)?;
    if enrollment.principal_id() != intent.review.principal_id { return Err(JournalError::Permission); }
    Ok(())
}

pub(crate) struct PreparedFinancialContinuationIntentV1 {
    journal: SignerJournalBinding,
    source_identity: String,
    intent: FinancialContinuationIntentV1,
    review: FinancialContinuationReviewV1,
}
impl PreparedFinancialContinuationIntentV1 {
    pub(crate) fn request(&self) -> &OwnerControlRequest { &self.intent.request }
    pub(super) fn check(&self, journal: &SignerConsentJournal, source: &FinancialSourceBindingV1, c: &Connection) -> Result<()> {
        if self.journal != journal.binding() || self.source_identity != source.source_digest { return Err(JournalError::Permission); }
        source.require(journal, c)?;
        self.review.check_source(&source.source_digest).map_err(|_| JournalError::Permission)?;
        if original_rows_digest(c)? != source.original_rows_digest { return Err(JournalError::Conflict); }
        record(&self.intent.request)?.terms.require_live(now_ms()?).map_err(invalid)?;
        validate_original(c, &self.intent)?;
        self.review.check_current().map_err(|_| JournalError::Permission)
    }
    pub(super) fn invalidate(&self) { self.review.invalidate(); }
}
pub(super) fn prepare(c: &Connection, journal: SignerJournalBinding, source: &FinancialSourceBindingV1,
    terms: FinancialContinuationTermsV1, review: FinancialContinuationReviewV1, history: &ReconciledAuthorityHistory,
) -> Result<PreparedFinancialContinuationIntentV1> {
    review.check_source(source.identity_digest()).map_err(|_| JournalError::Permission)?;
    terms.require_live(now_ms()?).map_err(invalid)?;
    if review.terms_digest() != terms.intent_terms_digest().map_err(invalid)? { return Err(JournalError::InvalidBinding); }
    let provenance = ReviewProvenanceV1 { source_identity_digest: review.source_identity_digest().into(), principal_id: review.principal_id().into(),
        measurement: review.measurement().into(), session_digest: review.session_digest().into(), permission_generation: review.permission_generation(), nonce: review.nonce().into(),
        reviewed_at_ms: review.reviewed_at_unix_ms(), expires_at_ms: review.expires_at_unix_ms(), terms_digest: review.terms_digest().into(), native_review_digest: review.native_review_digest().into() };
    let original = authority::durable_delivery_admission_intent_v3::read(c, &terms.scope.authorization.authorization_id)?.ok_or(JournalError::NotFound)?;
    let owner_certificate_digest = original.owner_certificate_digest().to_owned();
    let seed = intent_digest(&terms, &owner_certificate_digest, &provenance)?;
    let request = prepare_financial_continuation_request_v1(terms, seed, history).map_err(invalid)?;
    let intent = FinancialContinuationIntentV1 { version: 1, request, owner_certificate_digest, review: provenance };
    validate_original(c, &intent)?;
    review.check_current().map_err(|_| JournalError::Permission)?;
    Ok(PreparedFinancialContinuationIntentV1 { journal, source_identity: source.source_digest.clone(), intent, review })
}
pub(super) fn insert(c: &Connection, prepared: &PreparedFinancialContinuationIntentV1) -> Result<()> {
    let i = &prepared.intent;
    validate_original(c, i)?;
    let r = record(&i.request)?;
    let payload = encode(i)?;
    c.execute("INSERT INTO signer_financial_continuation_intents(operation_id,authorization_id,original_admission_operation_id,request_digest,enrollment_ref,manifest_ref,payload) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![i.request.operation_id, r.terms.scope.authorization.authorization_id, r.terms.original_delivery_operation_id, r.request_digest(&i.request).map_err(invalid)?, r.terms.original_recipient_enrollment_ref, r.terms.original_recipient_manifest_ref, payload.as_str()])?;
    Ok(())
}
pub(super) fn read(c: &Connection) -> Result<RetainedFinancialContinuationIntentV1> {
    let mut q = c.prepare("SELECT operation_id,authorization_id,original_admission_operation_id,request_digest,enrollment_ref,manifest_ref,payload FROM signer_financial_continuation_intents LIMIT 2")?;
    let rows = q.query_map([], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,String>(5)?,r.get::<_,String>(6)?)))?.collect::<std::result::Result<Vec<_>, _>>()?;
    if rows.len() != 1 { return Err(JournalError::RecoveryRequired); }
    let (operation, authorization, original, request_digest, enrollment, manifest, payload) = &rows[0];
    let value: FinancialContinuationIntentV1 = decode(payload.clone())?;
    validate_original(c, &value)?;
    let r = record(&value.request)?;
    if operation != &value.request.operation_id || authorization != &r.terms.scope.authorization.authorization_id || original != &r.terms.original_delivery_operation_id
        || request_digest != &r.request_digest(&value.request).map_err(invalid)? || enrollment != &r.terms.original_recipient_enrollment_ref
        || manifest != &r.terms.original_recipient_manifest_ref || encode(&value)?.as_str() != payload { return Err(JournalError::InvalidBinding); }
    Ok(RetainedFinancialContinuationIntentV1(value))
}
