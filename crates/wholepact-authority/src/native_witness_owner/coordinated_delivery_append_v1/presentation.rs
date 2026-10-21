//! Closed ordinary data validation and mode-bound display. Digests here never
//! authenticate caller origin, possession, consent or permission to append.
use super::*;
use crate::{OwnerControl, witness_locator::NamespaceOpenInput};
use std::{net::SocketAddr, path::Path};
use zeroize::Zeroizing;
use super::super::delivery_preparation_v2::{self, InputsV2, PreparedNativeV2};

const VERSION: u16 = 1;
const PURPOSE: &str = "coordinated-witness-durable-delivery-review";
const MODE: &str = "one-exact-delivery-append";
const MAX_CERTIFICATE_BYTES: usize = 16 * 1024;
const MAX_REVIEW_BYTES: usize = 60 * 1024;
const MAX_REVIEW_LIFETIME_MS: u64 = 120_000;
pub(crate) const ADMISSION_NOTICE: &str = "The final primary click arms only this exact conditional append. The coordinator admits it automatically only after the authenticated original owner request and full preflight are ready. Cancel, close, Escape or focus loss processed before that admission prevents commitment. After admission this one exact effect may finish or remain uncertain even if the window loses focus. No new attempt or implicit retry is authorized.";
const TRUST_NOTICE: &str = "This review relies on the pinned coordinator and Witness image, OS and compositor. Certificate possession does not prove fresh keys, fresh account provenance or independent administration. No setup, reset, wallet signing or dispatch is authorized here.";

struct InputShape<'a>(&'a DeliveryReviewInputsV1);
impl std::ops::Deref for InputShape<'_> {
    type Target = DeliveryReviewInputsV1;
    fn deref(&self) -> &Self::Target { self.0 }
}
impl InputShape<'_> {
    fn validate(&self) -> Result<()> {
        self.validate_lengths()?;
        let address: SocketAddr = self.endpoint.parse().map_err(|_| AuthorityError::InvalidBinding)?;
        if address.to_string() != self.endpoint || address.port() == 0
            || address.ip().is_unspecified() || address.ip().is_multicast()
        { return Err(AuthorityError::InvalidBinding); }
        rustls::pki_types::ServerName::try_from(self.server_name.clone())
            .map_err(|_| AuthorityError::InvalidBinding)?;
        crate::id(&self.witness_id)?;
        crate::id(&self.network_profile_id)?;
        crate::hash(&self.pinned_server_certificate_digest)?;
        crate::hash(&self.expected_account_id)?;
        for path in [&self.storage_key_file, &self.server_certificate_der,
            &self.server_private_key_pkcs8_der, &self.trusted_client_root_der]
        { validate_path(path)?; }
        self.owner_pin()?;
        let request: OwnerControlRequest = wholepact_core::parse_typed_json(self.request_json.as_bytes())
            .map_err(|_| AuthorityError::InvalidBinding)?;
        let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &request.control
        else { return Err(AuthorityError::Permission); };
        if request.account_id != self.expected_account_id || request.network_profile_id != self.network_profile_id {
            return Err(AuthorityError::InvalidBinding);
        }
        record.validate_request_shape(&request)
    }
    fn validate_lengths(&self) -> Result<()> {
        for (value, max) in [
            (&self.endpoint, 256), (&self.server_name, 253), (&self.witness_id, 128),
            (&self.pinned_server_certificate_digest, 64), (&self.network_profile_id, 128),
            (&self.expected_account_id, 64), (&self.owner_certificate_der_hex, 2 * MAX_CERTIFICATE_BYTES),
            (&self.storage_key_file, 4096), (&self.server_certificate_der, 4096),
            (&self.server_private_key_pkcs8_der, 4096), (&self.trusted_client_root_der, 4096),
            (&self.request_json, crate::MAX_FRAME_BYTES),
        ] {
            if value.is_empty() || value.len() > max { return Err(AuthorityError::Limit); }
        }
        Ok(())
    }
    fn owner_pin(&self) -> Result<String> {
        if self.owner_certificate_der_hex.is_empty()
            || self.owner_certificate_der_hex.len() > 2 * MAX_CERTIFICATE_BYTES
        { return Err(AuthorityError::Limit); }
        let der = Zeroizing::new(hex::decode(&self.owner_certificate_der_hex)
            .map_err(|_| AuthorityError::InvalidBinding)?);
        if der.is_empty() || der.len() > MAX_CERTIFICATE_BYTES { return Err(AuthorityError::InvalidBinding); }
        let certificate = rustls::pki_types::CertificateDer::from(der.as_slice());
        // Same public DER shape check as the original independently chosen form;
        // actual namespace policy and TLS authentication are separate checks.
        webpki::EndEntityCert::try_from(&certificate).map_err(|_| AuthorityError::InvalidBinding)?;
        Ok(crate::transport::certificate_digest(&certificate))
    }
}
fn validate_path(value: &str) -> Result<()> {
    if !Path::new(value).is_absolute() || value.len() > 4096 || value.ends_with('/')
        || value.bytes().any(|c| c.is_ascii_control())
        || value[1..].split('/').any(|part| part.is_empty() || part == "." || part == "..")
    { return Err(AuthorityError::InvalidBinding); }
    Ok(())
}

/// Pure bounded shape checks only. Never opens a file, socket or source.
pub fn validate_delivery_review_inputs(data: &DeliveryReviewInputsV1) -> Result<()> {
    if serde_json::to_vec(data).map_err(|_| AuthorityError::InvalidBinding)?.len() > 60 * 1024 {
        return Err(AuthorityError::Limit);
    }
    InputShape(data).validate()
}
/// Pure mode/purpose/digest checks. Authentication is supplied ONLY by the
/// retained original role channel, not by these ordinary bytes.
pub fn validate_delivery_review_presentation(data: &DeliveryReviewPresentationV1) -> Result<()> {
    if data.version != VERSION || data.purpose != PURPOSE || data.mode != MODE
        || data.display.is_empty() || data.display.len() > MAX_REVIEW_BYTES
        || !data.display.contains(ADMISSION_NOTICE) || !data.display.contains(TRUST_NOTICE)
        || data.display.chars().any(|c| c != '\n' && c != ' ' && !c.is_ascii_graphic())
        || data.expires_at_ms.checked_sub(data.prepared_at_ms)
            .is_none_or(|n| n == 0 || n > MAX_REVIEW_LIFETIME_MS)
    { return Err(AuthorityError::InvalidBinding); }
    for hash in [&data.backend_review_digest, &data.presentation_digest, &data.account_id,
        &data.request_commitment, &data.source_commitment, &data.owner_certificate_digest,
        &data.expected_head_digest]
    { crate::hash(hash)?; }
    crate::id(&data.operation_id)?;
    if data.presentation_digest != presentation_digest(data)? {
        return Err(AuthorityError::InvalidBinding);
    }
    // Full complete DTO must fit one origin packet. Never truncate the review.
    if serde_json::to_vec(data).map_err(|_| AuthorityError::InvalidBinding)?.len() > 60 * 1024 {
        return Err(AuthorityError::Limit);
    }
    Ok(())
}
fn presentation_digest(data: &DeliveryReviewPresentationV1) -> Result<String> {
    crate::digest("wholepact:coordinated-witness-delivery-presentation:v1", &(
        data.version, &data.purpose, &data.mode, &data.display, &data.backend_review_digest,
        data.prepared_at_ms, data.expires_at_ms, &data.account_id, &data.operation_id,
        &data.request_commitment, &data.source_commitment, &data.owner_certificate_digest,
        data.expected_head_sequence, &data.expected_head_digest,
    ))
}
fn inert_text(value: &str) -> String {
    let mut safe = String::with_capacity(value.len());
    for c in value.chars() {
        if c == '\n' || c == ' ' || c.is_ascii_graphic() { safe.push(c); }
        else { safe.extend(c.escape_default()); }
    }
    safe
}

pub(super) struct PreparedReviewV1 {
    pub(super) prepared: PreparedNativeV2,
    pub(super) presentation: DeliveryReviewPresentationV1,
    pub(super) clock: ReviewClock,
}
/// Private actual-source opener. Only the genuine-origin role worker calls it.
/// It reads existing protected files, may perform opener sidecar work and binds
/// the exact inert listener. It is not globally read-only or a consent issuer.
pub(super) fn prepare(input: DeliveryReviewInputsV1, first: &mut observation::FirstFailureV1) -> Result<PreparedReviewV1> {
    let mut stage = observation::Stage::InputValidation;
    let result = prepare_inner(input, first, &mut stage);
    if let Err(error) = result.as_ref() { first.note(stage, *error); }
    result
}
fn prepare_inner(input: DeliveryReviewInputsV1, first: &mut observation::FirstFailureV1, stage: &mut observation::Stage) -> Result<PreparedReviewV1> {
    validate_delivery_review_inputs(&input)?;
    let owner_certificate_digest = InputShape(&input).owner_pin()?;
    let namespace = NamespaceOpenInput {
        #[cfg(feature = "synthetic-qualification")]
        synthetic_installation: None,
        endpoint: input.endpoint, server_name: input.server_name, witness_id: input.witness_id,
        pinned_server_certificate_digest: input.pinned_server_certificate_digest,
        owner_certificate_digest, network_profile_id: input.network_profile_id,
        storage_key_file: input.storage_key_file, expected_account_id: input.expected_account_id,
    };
    let fields = InputsV2 {
        request_json: Zeroizing::new(input.request_json),
        server_certificate_der: input.server_certificate_der,
        server_private_key_pkcs8_der: input.server_private_key_pkcs8_der,
        trusted_client_root_der: input.trusted_client_root_der,
    };
    let prepared = delivery_preparation_v2::prepare_observed(namespace, fields)
        .map_err(|failure| first.preparation(failure))?;
    *stage = observation::Stage::ReviewClock;
    let clock = ReviewClock::start(prepared.proposal.first_commit_deadline_ms())?;
    let (prepared_at_ms, expires_at_ms) = clock.display_bounds()?;
    *stage = observation::Stage::ReviewFacts;
    let backend_review_digest = prepared.proposal.review_digest()?;
    let display = inert_text(&format!("{}\n\nOriginal backend review digest: {}\n\n{}",
        prepared.proposal.coordinated_display_v1()?, backend_review_digest, TRUST_NOTICE));
    let request = prepared.proposal.coordinated_expected_v1();
    let journal = prepared.proposal.coordinated_journal_v1();
    let owner = journal.born_owner.as_ref().ok_or(AuthorityError::Permission)?;
    owner.check_mutation_current_without_mutex_wait()?;
    let (source_commitment, owner_certificate_digest) = {
        let c = journal.connection.try_lock().map_err(|_| AuthorityError::Permission)?;
        let file = c.database_identity()?;
        file.check_current(c.connection())?;
        let ledger = crate::journal::load(c.connection())?;
        prepared.proposal.validate_locked(&ledger, crate::now_ms()?)?;
        let (stamp, birth) = crate::journal::namespace_account_stamp(c.connection(), &ledger.policy)?;
        owner.require_original_account_connection(&c, &birth)?;
        file.check_current(c.connection())?;
        (source_commitment(&file, &stamp, &ledger.policy)?, ledger.policy.owner_certificate_digest)
    };
    clock.check()?;
    let mut presentation = DeliveryReviewPresentationV1 {
        version: VERSION, purpose: PURPOSE.into(), mode: MODE.into(), display,
        backend_review_digest, presentation_digest: String::new(), prepared_at_ms, expires_at_ms,
        account_id: request.account_id.clone(), operation_id: request.operation_id.clone(),
        request_commitment: crate::transport::durable_delivery_admission_v3::request_commitment_v3(request)?,
        source_commitment, owner_certificate_digest,
        expected_head_sequence: request.expected_head.sequence,
        expected_head_digest: request.expected_head.digest.clone(),
    };
    presentation.presentation_digest = presentation_digest(&presentation)?;
    validate_delivery_review_presentation(&presentation)?;
    *stage = observation::Stage::PreparedSourceCurrentness;
    prepared.proposal.check_current()?;
    *stage = observation::Stage::ReviewClock;
    clock.check()?;
    Ok(PreparedReviewV1 { prepared, presentation, clock })
}
pub(crate) fn source_commitment(
    file: &wholepact_storage_security::DatabaseFileIdentity,
    stamp: &crate::journal::NamespaceJournalStamp, policy: &crate::AccountPolicy,
) -> Result<String> {
    crate::digest("wholepact:coordinated-delivery-original-source:v1", &(file.origin_commitment(), stamp, policy))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn inert_data() -> DeliveryReviewPresentationV1 {
        let mut data = DeliveryReviewPresentationV1 {
            version: VERSION, purpose: PURPOSE.into(), mode: MODE.into(),
            display: format!("INERT DATA TEST ONLY\n{ADMISSION_NOTICE}\n{TRUST_NOTICE}"),
            backend_review_digest: "a".repeat(64), presentation_digest: String::new(),
            prepared_at_ms: 1_000, expires_at_ms: 121_000,
            account_id: "b".repeat(64), operation_id: "inert-operation".into(),
            request_commitment: "c".repeat(64), source_commitment: "d".repeat(64),
            owner_certificate_digest: "e".repeat(64), expected_head_sequence: 4,
            expected_head_digest: "f".repeat(64),
        };
        data.presentation_digest = presentation_digest(&data).unwrap();
        data
    }
    #[test]
    fn positive_presentation_binds_every_original_fact_and_mode() {
        let original = inert_data();
        assert!(validate_delivery_review_presentation(&original).is_ok());
        let value = serde_json::to_value(&original).unwrap();
        for field in ["purpose", "mode", "display", "backend_review_digest", "presentation_digest",
            "account_id", "operation_id", "request_commitment", "source_commitment", "owner_certificate_digest", "expected_head_digest"] {
            let mut altered = value.clone();
            altered[field] = serde_json::json!("altered");
            let data: DeliveryReviewPresentationV1 = serde_json::from_value(altered).unwrap();
            assert!(validate_delivery_review_presentation(&data).is_err(), "{field}");
        }
        for field in ["version", "prepared_at_ms", "expires_at_ms", "expected_head_sequence"] {
            let mut altered = value.clone();
            altered[field] = serde_json::json!(altered[field].as_u64().unwrap() + 1);
            let data: DeliveryReviewPresentationV1 = serde_json::from_value(altered).unwrap();
            assert!(validate_delivery_review_presentation(&data).is_err(), "{field}");
        }
    }
    #[test]
    fn positive_presentation_rejects_legacy_notice_controls_and_overflow() {
        let original = inert_data();
        for display in ["Cancel before publication always prevents commitment".into(),
            format!("{}\u{202e}", original.display), "x".repeat(60 * 1024 + 1)] {
            let mut data = original.clone();
            data.display = display;
            data.presentation_digest = presentation_digest(&data).unwrap();
            assert!(validate_delivery_review_presentation(&data).is_err());
        }
        let mut data = original;
        data.expires_at_ms += 1;
        data.presentation_digest = presentation_digest(&data).unwrap();
        assert!(validate_delivery_review_presentation(&data).is_err());
    }
    #[test]
    fn positive_ordinary_inputs_cannot_supply_origin_or_approval() {
        let empty = DeliveryReviewInputsV1::default();
        assert!(validate_delivery_review_inputs(&empty).is_err());
        let value = serde_json::to_value(empty).unwrap();
        for field in ["synthetic_installation", "namespace_root", "role", "fd", "approved", "password"] {
            let mut altered = value.clone();
            altered.as_object_mut().unwrap().insert(field.into(), serde_json::json!(true));
            assert!(serde_json::from_value::<DeliveryReviewInputsV1>(altered).is_err());
        }
        for path in ["relative", "/", "/a/../key", "/a//key", "/a/key/", "/a/ke\ny"] {
            assert!(validate_path(path).is_err());
        }
    }
}
