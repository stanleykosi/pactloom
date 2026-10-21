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
pub(crate) struct RetainedFinancialContinuationIntentV1(RetainedContinuationPayload);
/// Serialization preserves each version's exact payload. Never derive
/// Deserialize here: explicit strict version dispatch is mandatory below.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
enum RetainedContinuationPayload {
    NativeV1(FinancialContinuationIntentV1),
    CoordinatedV2(super::coordinated_continue::CoordinatedFinancialContinuationIntentV2),
}
impl RetainedContinuationPayload {
    fn request(&self) -> &OwnerControlRequest {
        match self { Self::NativeV1(value) => &value.request, Self::CoordinatedV2(value) => value.request() }
    }
    fn owner_certificate_digest(&self) -> &str {
        match self { Self::NativeV1(value) => &value.owner_certificate_digest,
            Self::CoordinatedV2(value) => value.owner_certificate_digest() }
    }
    fn validate_original(&self, c: &Connection) -> Result<()> {
        match self { Self::NativeV1(value) => validate_original(c, value),
            Self::CoordinatedV2(value) => value.validate_original(c) }
    }
}
fn decode_payload(payload: &str) -> Result<RetainedContinuationPayload> {
    // This bounded selector is not the reader. Decode the original bytes again
    // into exactly one strict payload so duplicate fields cannot be normalized.
    let selector: serde_json::Value = decode(payload.to_owned())?;
    let value = match selector.get("version").and_then(serde_json::Value::as_u64) {
        Some(1) => RetainedContinuationPayload::NativeV1(decode(payload.to_owned())?),
        Some(2) => RetainedContinuationPayload::CoordinatedV2(decode(payload.to_owned())?),
        _ => return Err(JournalError::InvalidBinding),
    };
    if encode(&value)?.as_str() != payload { return Err(JournalError::InvalidBinding); }
    Ok(value)
}
impl RetainedFinancialContinuationIntentV1 {
    pub(crate) fn request(&self) -> &OwnerControlRequest { self.0.request() }
    pub(crate) fn terms(&self) -> Result<&FinancialContinuationTermsV1> { Ok(&record(self.0.request())?.terms) }
    pub(crate) fn history_digest(&self) -> Result<String> {
        match &self.0 {
            RetainedContinuationPayload::NativeV1(value) => {
                value.validate()?;
                digest("wholepact:signer-financial-continuation-history:v1", value)
            }
            RetainedContinuationPayload::CoordinatedV2(value) => value.history_digest(),
        }
    }
    pub(super) fn require_original(&self, genesis: &AccountUseGenesis) -> Result<()> {
        let t = self.terms()?;
        if t.scope.authorization.identity.account_id != genesis.identity.account_id
            || t.scope.authorization.identity.full_viewing_key_digest != genesis.identity.full_viewing_key_digest
            || t.scope.authorization.identity.network_profile_id != genesis.identity.network_profile_id
            || t.scope.authorization.identity.derivation_domain != genesis.identity.derivation_domain
            || self.0.owner_certificate_digest() != genesis.owner_certificate_digest
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
    let value = decode_payload(payload)?;
    value.validate_original(c)?;
    let r = record(value.request())?;
    if operation != &value.request().operation_id || authorization != &r.terms.scope.authorization.authorization_id || original != &r.terms.original_delivery_operation_id
        || request_digest != &r.request_digest(value.request()).map_err(invalid)? || enrollment != &r.terms.original_recipient_enrollment_ref
        || manifest != &r.terms.original_recipient_manifest_ref || encode(&value)?.as_str() != payload { return Err(JournalError::InvalidBinding); }
    Ok(RetainedFinancialContinuationIntentV1(value))
}

#[cfg(test)]
mod history_payload_tests {
    use super::*;

    // Shape-only values deliberately use Pause, not a continuation, so none
    // passes semantic validation or represents a historical authorization.
    fn native_shape() -> FinancialContinuationIntentV1 {
        FinancialContinuationIntentV1 {
            version: 1,
            request: OwnerControlRequest {
                operation_id: "shape-only".into(), account_id: "account".into(),
                network_profile_id: "network".into(), writer_epoch: 1,
                expected_head: wholepact_authority::AuthorityHead { sequence: 5, digest: "01".repeat(32) },
                control: OwnerControl::Pause,
            },
            owner_certificate_digest: "02".repeat(32),
            review: ReviewProvenanceV1 {
                source_identity_digest: "03".repeat(32), principal_id: "principal".into(),
                measurement: "04".repeat(32), session_digest: "05".repeat(32),
                permission_generation: 1, nonce: "06".repeat(32), reviewed_at_ms: 1_000,
                expires_at_ms: 121_000, terms_digest: "07".repeat(32), native_review_digest: "08".repeat(32),
            },
        }
    }
    fn coordinated_shape() -> super::super::coordinated_continue::CoordinatedFinancialContinuationIntentV2 {
        let native = native_shape();
        serde_json::from_value(serde_json::json!({
            "version": 2, "request": native.request,
            "owner_certificate_digest": native.owner_certificate_digest,
            "coordinated_provenance": {
                "origin": "original_coordinator_host_signer_v1", "preparation_nonce": "09".repeat(32),
                "review": {
                    "coordinator_process_instance": "10".repeat(32), "coordinator_focus_epoch": 7,
                    "signer_role": "signer1", "signer_process_instance": "11".repeat(32),
                    "original_host_process_instance": "12".repeat(32), "signer_principal_id": "principal",
                    "signer_image_measurement": "13".repeat(32), "source_identity_digest": "14".repeat(32),
                    "terms_digest": "15".repeat(32), "session_digest": "16".repeat(32),
                    "review_challenge": "17".repeat(32), "review_digest": "18".repeat(32),
                    "reviewed_at_ms": 1_000, "expires_at_ms": 121_000, "session_expires_at_ms": 300_000,
                },
            },
        })).unwrap()
    }
    #[test]
    fn native_wrapper_preserves_exact_bytes_and_hash_preimage() {
        let native = native_shape();
        let old = encode(&native).unwrap();
        let expected = digest("wholepact:signer-financial-continuation-history:v1", &native).unwrap();
        let retained = RetainedFinancialContinuationIntentV1(RetainedContinuationPayload::NativeV1(native));
        assert_eq!(encode(&retained).unwrap().as_str(), old.as_str());
        assert_eq!(digest("wholepact:signer-financial-continuation-history:v1", &retained).unwrap(), expected);
        assert!(matches!(decode_payload(&old).unwrap(), RetainedContinuationPayload::NativeV1(_)));
        assert!(retained.history_digest().is_err()); // Decoding is not semantic validity or permission.
    }
    #[test]
    fn explicit_reader_rejects_version_origin_duplicates_and_unknown_fields() {
        let native = encode(&native_shape()).unwrap();
        let coordinated = encode(&coordinated_shape()).unwrap();
        assert!(matches!(decode_payload(&coordinated).unwrap(), RetainedContinuationPayload::CoordinatedV2(_)));
        for bad in [
            native.replacen("\"version\":1", "\"version\":2", 1),
            coordinated.replacen("\"version\":2", "\"version\":1", 1),
            coordinated.replacen("\"version\":2", "\"version\":3", 1),
            coordinated.replacen("\"version\":2", "\"version\":2,\"version\":2", 1),
            coordinated.replacen("\"version\":2", "\"version\":2,\"extra\":true", 1),
            coordinated.replace("original_coordinator_host_signer_v1", "signer_native_v1"),
            coordinated.replacen("\"coordinated_provenance\":{", "\"coordinated_provenance\":{\"extra\":true,", 1),
            coordinated.replacen("\"review\":{", "\"review\":{\"permission_generation\":1,", 1),
            coordinated.replacen("\"coordinator_focus_epoch\":7", "\"coordinator_focus_epoch\":7,\"coordinator_focus_epoch\":7", 1),
            format!(" {}", coordinated.as_str()),
        ] { assert!(decode_payload(&bad).is_err()); }
    }
    #[test]
    fn coordinated_history_domain_is_distinct_and_shape_is_not_a_grant() {
        let coordinated = coordinated_shape();
        assert_ne!(
            digest("wholepact:signer-financial-continuation-history:v1", &coordinated).unwrap(),
            digest("wholepact:signer-coordinated-financial-continuation-history:v2", &coordinated).unwrap(),
        );
        assert!(coordinated.history_digest().is_err());
    }
}
