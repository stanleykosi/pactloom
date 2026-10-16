//! Private inert encrypted records. Parsing, hashing or retaining these records
//! never creates native approval, authenticated delivery or spending authority.
//! No Debug implementation: profiles contain a transport secret; originals can
//! contain private own-output expectations. No peer viewing key is represented.
use super::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use wholepact_authority::{
    OfflineAdmissionExportPlan,
    offline::{OfflineAuthorizationTerms, ReserveOfflineAuthorization},
};
use zeroize::Zeroize;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NamedRecipientProfileRecordV1 {
    pub(crate) schema_version: u16,
    pub(crate) reference: String,
    pub(crate) account_id: String,
    pub(crate) full_viewing_key_digest: String,
    pub(crate) enrollment_ref: String,
    pub(crate) manifest_ref: String,
    pub(crate) native_review_digest: String,
    pub(crate) native_origin_digest: String,
    pub(crate) original_setup_digest: String,
    pub(crate) verifier_signing_public_key: [u8; 32],
    pub(crate) verifier_transport_public_key: [u8; 32],
    pub(crate) witness_transport_public_key: [u8; 32],
    pub(crate) witness_certificate_digest: String,
    pub(crate) return_transport_public_key: [u8; 32],
    pub(crate) transport_public_key: [u8; 32],
    pub(crate) transport_secret: [u8; 32],
}
impl Drop for NamedRecipientProfileRecordV1 {
    fn drop(&mut self) {
        self.transport_secret.zeroize();
    }
}
impl NamedRecipientProfileRecordV1 {
    /// Stable pre-key-generation setup commitment. Process-local native origin,
    /// native review and generated key are excluded so exact retry after
    /// restart finds the original key; provenance remains in reference_digest.
    pub(crate) fn setup_digest(&self) -> Result<String> {
        digest(
            "wholepact:named-recipient-setup:v1",
            &(
                self.schema_version,
                &self.account_id,
                &self.full_viewing_key_digest,
                &self.enrollment_ref,
                &self.manifest_ref,
                &self.verifier_signing_public_key,
                &self.verifier_transport_public_key,
                &self.witness_transport_public_key,
                &self.witness_certificate_digest,
                &self.return_transport_public_key,
            ),
        )
    }
    /// Public commitment excludes private transport bytes. Full validation
    /// separately proves that the retained secret derives exactly this key.
    pub(crate) fn reference_digest(&self) -> Result<String> {
        digest(
            "wholepact:named-recipient-profile:v1",
            &(
                &self.original_setup_digest,
                &self.native_review_digest,
                &self.native_origin_digest,
                &self.transport_public_key,
            ),
        )
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.validate_structure()?;
        #[cfg(feature = "offline-review-foundation")]
        {
            let secret = wholepact_transport::TransportSecret::from_bytes(self.transport_secret)
                .map_err(|_| JournalError::InvalidBinding)?;
            let public = secret
                .public_key()
                .map_err(|_| JournalError::InvalidBinding)?;
            if public.as_bytes() != &self.transport_public_key {
                return Err(JournalError::InvalidBinding);
            }
            for key in [
                self.verifier_transport_public_key,
                self.witness_transport_public_key,
                self.return_transport_public_key,
            ] {
                wholepact_transport::TransportPublicKey::from_bytes(key)
                    .map_err(|_| JournalError::InvalidBinding)?;
            }
            Ok(())
        }
        #[cfg(not(feature = "offline-review-foundation"))]
        {
            Err(JournalError::NamedRecipientHistoryUnsupported)
        }
    }
    /// Structural retention check only. Not an authenticated or usable profile.
    pub(super) fn validate_structure(&self) -> Result<()> {
        id(&self.account_id)?;
        for h in [
            &self.reference,
            &self.full_viewing_key_digest,
            &self.enrollment_ref,
            &self.manifest_ref,
            &self.native_review_digest,
            &self.native_origin_digest,
            &self.original_setup_digest,
            &self.witness_certificate_digest,
        ] {
            hash(h)?;
        }
        if self.schema_version != 1
            || [
                self.verifier_signing_public_key,
                self.verifier_transport_public_key,
                self.witness_transport_public_key,
                self.return_transport_public_key,
                self.transport_public_key,
                self.transport_secret,
            ]
            .contains(&[0; 32])
            || self.original_setup_digest != self.setup_digest()?
            || self.reference != self.reference_digest()?
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NamedRecipientOwnInputV1 {
    pub(crate) action_index: u32,
    pub(crate) nullifier: String,
    pub(crate) value_zatoshis: u64,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NamedRecipientOutputPurposeV1 {
    OwnReturn,
    Recipient,
    PeerReturnUnverified,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NamedRecipientOwnOutputV1 {
    pub(crate) action_index: u32,
    pub(crate) receiver_hex: String,
    pub(crate) value_zatoshis: u64,
    pub(crate) memo_hex: String,
    pub(crate) purpose: NamedRecipientOutputPurposeV1,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NamedRecipientOwnExpectationsV1 {
    pub(crate) schema_version: u16,
    pub(crate) full_viewing_key_digest: String,
    pub(crate) manifest_digest: String,
    pub(crate) anchor: String,
    pub(crate) expiry_height: u32,
    pub(crate) maximum_selected_net_debit_zatoshis: u64,
    pub(crate) exact_selected_net_debit_zatoshis: u64,
    pub(crate) declared_fee_share_zatoshis: u64,
    pub(crate) exact_transaction_fee_zatoshis: u64,
    pub(crate) own_inputs: Vec<NamedRecipientOwnInputV1>,
    pub(crate) outputs: Vec<NamedRecipientOwnOutputV1>,
}
impl NamedRecipientOwnExpectationsV1 {
    fn validate(&self, terms: &OfflineAuthorizationTerms) -> Result<()> {
        for h in [
            &self.full_viewing_key_digest,
            &self.manifest_digest,
            &self.anchor,
        ] {
            hash(h)?;
        }
        if self.schema_version != 1
            || self.own_inputs.is_empty()
            || self.own_inputs.len() > 64
            || self.outputs.is_empty()
            || self.outputs.len() > 64
            || self.maximum_selected_net_debit_zatoshis > MAX_MONEY
            || self.exact_selected_net_debit_zatoshis > self.maximum_selected_net_debit_zatoshis
            || self.exact_selected_net_debit_zatoshis != terms.maximum_debit_zatoshis
            || self.declared_fee_share_zatoshis != terms.fee_share_zatoshis
            || self.exact_transaction_fee_zatoshis != terms.transaction_fee_zatoshis
            || self.manifest_digest != terms.manifest_digest
            || self.anchor != terms.snapshot.anchor_root
            || self.expiry_height != terms.transaction_expiry_height
            || self.expiry_height >= 500_000_000
            || self.own_inputs.len() != terms.inputs.len()
        {
            return Err(JournalError::InvalidBinding);
        }
        // The own-policy vector preserves manifest order for its exact
        // commitment; wire terms have canonical action-index order. Compare a
        // bijection without reordering either independently committed vector.
        let mut expected_inputs: BTreeMap<_, _> = terms
            .inputs
            .iter()
            .map(|input| (input.action_index, input))
            .collect();
        if expected_inputs.len() != terms.inputs.len() {
            return Err(JournalError::InvalidBinding);
        }
        let mut input_total = 0_u64;
        for input in &self.own_inputs {
            hash(&input.nullifier)?;
            let expected = expected_inputs
                .remove(&u64::from(input.action_index))
                .ok_or(JournalError::InvalidBinding)?;
            if input.nullifier != expected.nullifier
                || input.value_zatoshis != expected.value_zatoshis
            {
                return Err(JournalError::InvalidBinding);
            }
            input_total = money_add(input_total, input.value_zatoshis)?;
        }
        if !expected_inputs.is_empty() {
            return Err(JournalError::InvalidBinding);
        }
        let mut indices = BTreeSet::new();
        let mut own_return = 0_u64;
        for output in &self.outputs {
            if output.action_index > 255
                || !indices.insert(output.action_index)
                || output.value_zatoshis > MAX_MONEY
            {
                return Err(JournalError::InvalidBinding);
            }
            exact_hex(&output.receiver_hex, 43)?;
            exact_hex(&output.memo_hex, 512)?;
            if output.purpose == NamedRecipientOutputPurposeV1::OwnReturn {
                own_return = money_add(own_return, output.value_zatoshis)?;
            }
        }
        if input_total.checked_sub(own_return) != Some(self.exact_selected_net_debit_zatoshis) {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
}
fn money_add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b)
        .filter(|sum| *sum <= MAX_MONEY)
        .ok_or(JournalError::InvalidBinding)
}
fn exact_hex(s: &str, bytes: usize) -> Result<()> {
    if s.len() != bytes * 2
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(JournalError::InvalidBinding);
    }
    Ok(())
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NamedRecipientOriginalRecordV1 {
    pub(crate) schema_version: u16,
    pub(crate) reference: String,
    pub(crate) profile_ref: String,
    pub(crate) terms: OfflineAuthorizationTerms,
    pub(crate) original_artifact_digest: String,
    pub(crate) canonical_artifact_digest: String,
    pub(crate) transformation_digest: String,
    pub(crate) named_assertion_digest: String,
    /// Exact canonical package bytes, separate from the signed statement digest.
    pub(crate) assertion_package_digest: String,
    /// Immutable original issuer-request window; never reset by receipt retry.
    pub(crate) validity_not_before_ms: u64,
    pub(crate) validity_expires_ms: u64,
    /// Pre-package identity signed by the named verifier; never the reserve hash.
    pub(crate) original_request_digest: String,
    /// Complete original witness request, including expected head and time.
    pub(crate) reservation_request: ReserveOfflineAuthorization,
    pub(crate) reservation_request_digest: String,
    /// Unallocated original witness response template. Sequence remains zero.
    pub(crate) admission_export_template: OfflineAdmissionExportPlan,
    pub(crate) own_policy_digest: String,
    pub(crate) own_expectations: NamedRecipientOwnExpectationsV1,
}
impl NamedRecipientOriginalRecordV1 {
    pub(crate) fn reference_digest(&self) -> Result<String> {
        digest(
            "wholepact:named-recipient-original:v1",
            &(
                self.schema_version,
                &self.profile_ref,
                &self.terms,
                &self.original_artifact_digest,
                &self.canonical_artifact_digest,
                &self.transformation_digest,
                &self.named_assertion_digest,
                &self.assertion_package_digest,
                self.validity_not_before_ms,
                self.validity_expires_ms,
                &self.original_request_digest,
                &self.reservation_request,
                &self.reservation_request_digest,
                &self.admission_export_template,
                &self.own_policy_digest,
                &self.own_expectations,
            ),
        )
    }
    pub(crate) fn validate(&self, profile: &NamedRecipientProfileRecordV1) -> Result<()> {
        self.validate_structure(profile)?;
        #[cfg(feature = "offline-review-foundation")]
        {
            self.named_header(profile)?;
            Ok(())
        }
        #[cfg(not(feature = "offline-review-foundation"))]
        {
            Err(JournalError::NamedRecipientHistoryUnsupported)
        }
    }
    /// Structural archive retention only. Without transport support this does
    /// not claim that the canonical named header or a live profile was verified.
    pub(super) fn validate_structure(&self, profile: &NamedRecipientProfileRecordV1) -> Result<()> {
        self.terms
            .validate()
            .map_err(|_| JournalError::InvalidBinding)?;
        for h in [
            &self.reference,
            &self.profile_ref,
            &self.original_artifact_digest,
            &self.canonical_artifact_digest,
            &self.transformation_digest,
            &self.named_assertion_digest,
            &self.assertion_package_digest,
            &self.original_request_digest,
            &self.reservation_request_digest,
            &self.own_policy_digest,
        ] {
            hash(h)?;
        }
        self.reservation_request
            .validate()
            .map_err(|_| JournalError::InvalidBinding)?;
        validate_admission_template(
            &self.admission_export_template,
            &self.reservation_request,
            profile,
        )?;
        if self.reservation_request.intent.terms != self.terms
            || self
                .reservation_request
                .request_digest()
                .map_err(|_| JournalError::InvalidBinding)?
                != self.reservation_request_digest
            || self.reservation_request.requested_at_ms < self.validity_not_before_ms
            || self.reservation_request.admission_expires_at_ms > self.validity_expires_ms
        {
            return Err(JournalError::InvalidBinding);
        }
        self.own_expectations.validate(&self.terms)?;
        validate_original_assertion_window(self.validity_not_before_ms, self.validity_expires_ms)?;
        if self.schema_version != 1
            || self.profile_ref != profile.reference
            || self.terms.account_id != profile.account_id
            || self.terms.enrollment_ref != profile.enrollment_ref
            || self.terms.accepted_manifest_ref != profile.manifest_ref
            || self.terms.artifact_digest != self.original_artifact_digest
            || self.terms.offline_signer_key_digest
                != transport_fingerprint(&profile.transport_public_key)
            || self.terms.return_recipient_key_digest
                != transport_fingerprint(&profile.return_transport_public_key)
            || self.own_expectations.full_viewing_key_digest != profile.full_viewing_key_digest
            || self.reference != self.reference_digest()?
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }

    #[cfg(feature = "offline-review-foundation")]
    pub(crate) fn named_header(
        &self,
        profile: &NamedRecipientProfileRecordV1,
    ) -> Result<wholepact_transport::NamedReviewBindingV1> {
        let header = wholepact_transport::NamedReviewBindingV1 {
            schema_version: 1,
            disclosure_profile: wholepact_transport::NAMED_REVIEW_DISCLOSURE_PROFILE_V1.into(),
            owner_setup_digest: profile.original_setup_digest.clone(),
            assertion_package_digest: self.assertion_package_digest.clone(),
            original_context_digest:
                wholepact_offline_bridge::named_verifier_original_context_digest(&self.terms)
                    .map_err(|_| JournalError::InvalidBinding)?,
        };
        if header
            .review_package_digest()
            .map_err(|_| JournalError::InvalidBinding)?
            != self.terms.review_package_digest
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(header)
    }
}

fn validate_admission_template(
    template: &OfflineAdmissionExportPlan,
    request: &ReserveOfflineAuthorization,
    profile: &NamedRecipientProfileRecordV1,
) -> Result<()> {
    if template.sequence != 0 {
        return Err(JournalError::InvalidBinding);
    }
    // Existing maintained validator requires allocated sequence. This temporary
    // structural stand-in is never retained, exported or used as authority.
    let mut checked = template.clone();
    checked.sequence = 1;
    checked
        .validate()
        .map_err(|_| JournalError::InvalidBinding)?;
    let ms = |n: i64| {
        u64::try_from(n)
            .ok()
            .and_then(|n| n.checked_mul(1000))
            .ok_or(JournalError::InvalidBinding)
    };
    if ms(template.issued_at_unix_seconds)? < request.requested_at_ms
        || ms(template.expires_at_unix_seconds)? > request.admission_expires_at_ms
        || template.sender_id
            != format!(
                "offline-admission:{}",
                request.intent.terms.offline_policy_digest
            )
        || template.recipient_id
            != format!(
                "offline-admission:{}",
                request.intent.terms.offline_signer_key_digest
            )
        || template.sender_key_fingerprint
            != transport_fingerprint(&profile.witness_transport_public_key)
        || template.recipient_key_fingerprint
            != transport_fingerprint(&profile.transport_public_key)
    {
        return Err(JournalError::InvalidBinding);
    }
    Ok(())
}

fn validate_original_assertion_window(start_ms: u64, end_ms: u64) -> Result<()> {
    let first_second = start_ms.div_ceil(1000);
    let last_second = end_ms / 1000;
    if start_ms >= end_ms
        || end_ms > i64::MAX as u64
        || first_second >= last_second
        || last_second - first_second > 7 * 24 * 60 * 60
    {
        return Err(JournalError::InvalidBinding);
    }
    Ok(())
}

#[cfg(test)]
mod original_assertion_window_tests {
    use super::*;
    #[test]
    fn original_window_preserves_transport_seconds_and_never_wraps_or_refreshes() {
        assert!(validate_original_assertion_window(1_000, 30_000).is_ok());
        assert!(validate_original_assertion_window(1_999, 2_000).is_err());
        assert!(validate_original_assertion_window(3_000, 2_000).is_err());
        assert!(validate_original_assertion_window(0, 604_800_000).is_ok());
        assert!(validate_original_assertion_window(0, 604_801_000).is_err());
        assert!(validate_original_assertion_window(0, u64::MAX).is_err());
        assert!(validate_original_assertion_window(u64::MAX, u64::MAX).is_err());
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NamedRecipientStartedRecordV1 {
    /// Absent only in pre-issuer historical fixtures. Absence is never signing authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) final_review: Option<NamedRecipientFinalReviewV1>,
    pub(crate) schema_version: u16,
    pub(crate) authorization_id: String,
    pub(crate) original_ref: String,
    pub(crate) native_review_digest: String,
    pub(crate) native_origin_digest: String,
    pub(crate) admission_request_digest: String,
    pub(crate) authenticated_package_digest: String,
    pub(crate) original_deadline_ms: u64,
}
impl NamedRecipientStartedRecordV1 {
    pub(crate) fn marker_digest(&self) -> Result<String> {
        digest("wholepact:named-recipient-started:v1", self)
    }
    pub(crate) fn validate(&self, original: &NamedRecipientOriginalRecordV1) -> Result<()> {
        for h in [
            &self.original_ref,
            &self.native_review_digest,
            &self.native_origin_digest,
            &self.admission_request_digest,
            &self.authenticated_package_digest,
        ] {
            hash(h)?;
        }
        id(&self.authorization_id)?;
        if let Some(final_review) = &self.final_review {
            final_review.validate(original, self)?;
        }
        if self.schema_version != 1
            || self.authorization_id != original.terms.authorization_id
            || self.original_ref != original.reference
            || self.admission_request_digest != original.reservation_request_digest
            || self.original_deadline_ms > original.reservation_request.admission_expires_at_ms
            || self.authenticated_package_digest != original.terms.review_package_digest
            || self.original_deadline_ms == 0
            || self.original_deadline_ms > i64::MAX as u64
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NamedRecipientResultRecordV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) encrypted_return: Option<NamedRecipientEncryptedReturnV1>,
    pub(crate) schema_version: u16,
    pub(crate) authorization_id: String,
    pub(crate) original_ref: String,
    pub(crate) started_digest: String,
    pub(crate) result_digest: String,
    pub(crate) result_hex: String,
}
impl NamedRecipientResultRecordV1 {
    pub(crate) fn validate(
        &self,
        started: &NamedRecipientStartedRecordV1,
        original: &NamedRecipientOriginalRecordV1,
    ) -> Result<()> {
        started.validate(original)?;
        hash(&self.result_digest)?;
        match (&started.final_review, &self.encrypted_return) {
            (Some(review), Some(returned)) => {
                returned.validate(review, self)?;
                let bytes =
                    Zeroizing::new(hex::decode(&self.result_hex).map_err(invalid_named_record)?);
                let projection = signature_return_projection(original, started, &bytes)?;
                if hex::encode(Sha256::digest(&*projection)) != returned.projection_digest {
                    return Err(JournalError::InvalidBinding);
                }
            }
            (None, None) => (),
            _ => return Err(JournalError::InvalidBinding),
        }
        if self.schema_version != 1
            || self.authorization_id != started.authorization_id
            || self.original_ref != started.original_ref
            || self.started_digest != started.marker_digest()?
            || self.result_hex.is_empty()
            || self.result_hex.len() > MAX_RECORD_BYTES / 2
        {
            return Err(JournalError::InvalidBinding);
        }
        let bytes = Zeroizing::new(
            hex::decode(&self.result_hex).map_err(|_| JournalError::InvalidBinding)?,
        );
        if hex::encode(bytes.as_slice()) != self.result_hex
            || hex::encode(Sha256::digest(bytes.as_slice())) != self.result_digest
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
}
pub(super) fn transport_fingerprint(key: &[u8; 32]) -> String {
    domain_digest(b"wholepact.transport-key.v1\0", key)
}
pub(super) fn domain_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Immutable ciphertext and exact canonical preparation metadata. Parsing or
/// validating this record never creates authenticated delivery or live authority.
/// No Debug: preview metadata and ciphertext remain inside the encrypted journal.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NamedIntentOutboxRecordV1 {
    pub(crate) authorization_id: String,
    pub(crate) original_ref: String,
    pub(crate) profile_ref: String,
    pub(crate) stream: String,
    pub(crate) sequence: u64,
    /// Domain-hashed index of the raw message ID retained in preview_json.
    pub(crate) message_id: String,
    pub(crate) content_hash: String,
    pub(crate) payload_digest: String,
    pub(crate) envelope_digest: String,
    pub(crate) preview_json: String,
    pub(crate) envelope_hex: String,
}
impl NamedIntentOutboxRecordV1 {
    pub(crate) fn validate(
        &self,
        original: &NamedRecipientOriginalRecordV1,
        profile: &NamedRecipientProfileRecordV1,
    ) -> Result<()> {
        self.validate_structure(original, profile)?;
        original.validate(profile)?;
        #[cfg(feature = "offline-review-foundation")]
        {
            self.validate_preview(original, profile)
        }
        #[cfg(not(feature = "offline-review-foundation"))]
        {
            Err(JournalError::NamedRecipientHistoryUnsupported)
        }
    }
    pub(super) fn validate_structure(
        &self,
        original: &NamedRecipientOriginalRecordV1,
        profile: &NamedRecipientProfileRecordV1,
    ) -> Result<()> {
        original.validate_structure(profile)?;
        id(&self.authorization_id)?;
        for value in [
            &self.original_ref,
            &self.profile_ref,
            &self.stream,
            &self.message_id,
            &self.content_hash,
            &self.payload_digest,
            &self.envelope_digest,
        ] {
            hash(value)?;
        }
        if self.authorization_id != original.terms.authorization_id
            || self.original_ref != original.reference
            || self.profile_ref != original.profile_ref
            || self.profile_ref != profile.reference
            || self.sequence == 0
            || self.sequence > i64::MAX as u64
            || self.preview_json.is_empty()
            || self.preview_json.len() > MAX_RECORD_BYTES
            || self.envelope_hex.is_empty()
            || self.envelope_hex.len() > 2 * 1_048_576
        {
            return Err(JournalError::InvalidBinding);
        }
        // Featureless backup preserves exact metadata bytes but does not claim
        // transport/header verification; its typed reader remains unavailable.
        let _: serde_json::Value = wholepact_core::parse_typed_json(self.preview_json.as_bytes())
            .map_err(|_| JournalError::InvalidBinding)?;
        let envelope = Zeroizing::new(
            hex::decode(&self.envelope_hex).map_err(|_| JournalError::InvalidBinding)?,
        );
        if hex::encode(envelope.as_slice()) != self.envelope_hex
            || domain_digest(b"wholepact.encrypted-envelope.v1\0", envelope.as_slice())
                != self.envelope_digest
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
    #[cfg(feature = "offline-review-foundation")]
    fn validate_preview(
        &self,
        original: &NamedRecipientOriginalRecordV1,
        profile: &NamedRecipientProfileRecordV1,
    ) -> Result<()> {
        use wholepact_transport::{
            ArtifactKind, DisclosureField, DisclosurePreview, ExportRequest, MessageContext,
            NAMED_REVIEW_BINDING_FIELD_V1, TransportPublicKey, prepare_export,
        };
        let preview: DisclosurePreview =
            wholepact_core::parse_typed_json(self.preview_json.as_bytes())
                .map_err(invalid_named_record)?;
        if serde_json::to_string(&preview).map_err(invalid_named_record)? != self.preview_json
            || preview.order.sequence != self.sequence
        {
            return Err(JournalError::InvalidBinding);
        }
        let terms = &original.reservation_request.intent.terms;
        let context = MessageContext {
            network_profile_id: terms.network_profile_id.clone(),
            agreement_id: terms.agreement_id.clone(),
            proposal_id: terms.proposal_id.clone(),
            proposal_revision: terms.proposal_revision,
            sender_id: format!("offline-intent:{}", terms.offline_signer_key_digest),
            recipient_id: format!("offline-intent:{}", terms.offline_policy_digest),
            artifact_kind: ArtifactKind::OfflineReservationIntent,
        };
        if preview.context != context {
            return Err(JournalError::InvalidBinding);
        }
        let ms = |n: i64| {
            u64::try_from(n)
                .ok()
                .and_then(|n| n.checked_mul(1000))
                .ok_or(JournalError::InvalidBinding)
        };
        if ms(preview.order.issued_at.unix_seconds())?
            < original.reservation_request.requested_at_ms
            || ms(preview.order.expires_at.unix_seconds())?
                > original.reservation_request.admission_expires_at_ms
        {
            return Err(JournalError::InvalidBinding);
        }
        let prepared = prepare_export(
            ExportRequest {
                context,
                order: preview.order.clone(),
                purpose: preview.purpose.clone(),
                persistence_warning: preview.persistence_warning.clone(),
            },
            vec![
                DisclosureField::new(
                    "offline-reservation-intent-v1",
                    serde_json::to_vec(&original.reservation_request.intent)
                        .map_err(invalid_named_record)?,
                )
                .map_err(invalid_named_record)?,
                DisclosureField::new(
                    NAMED_REVIEW_BINDING_FIELD_V1,
                    original
                        .named_header(profile)?
                        .canonical_bytes()
                        .map_err(invalid_named_record)?,
                )
                .map_err(invalid_named_record)?,
            ],
            &TransportPublicKey::from_bytes(profile.transport_public_key)
                .map_err(invalid_named_record)?,
            &TransportPublicKey::from_bytes(profile.witness_transport_public_key)
                .map_err(invalid_named_record)?,
            &preview.order.issued_at,
        )
        .map_err(invalid_named_record)?;
        if prepared.preview() != &preview || self.payload_digest != preview.payload_digest {
            return Err(JournalError::InvalidBinding);
        }
        // Pure maintained-wire commitments, not an AuthenticatedReceipt. This
        // helper never seals, decrypts, grants permission or consults a clock.
        let commitments = prepared.retained_metadata().map_err(invalid_named_record)?;
        if commitments.stream_digest != self.stream
            || commitments.message_id_digest != self.message_id
            || commitments.content_digest != self.content_hash
            || commitments.payload_digest != self.payload_digest
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
}

fn invalid_named_record<E>(_: E) -> JournalError {
    JournalError::InvalidBinding
}

/// Complete historical final decision and original authenticated witness facts.
/// These serialized records are evidence only; only the private live native
/// continuation below may cause a first key invocation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NamedRecipientFinalReviewV1 {
    pub(crate) schema_version: u16,
    pub(crate) admission: wholepact_authority::offline::OfflineAuthorizationAdmission,
    pub(crate) enrollment: wholepact_authority::offline::OfflineEnrollmentPolicy,
    pub(crate) account_policy: wholepact_authority::AccountPolicy,
    pub(crate) witness: wholepact_authority::WitnessDisclosureDescriptor,
    pub(crate) history_digest: String,
    pub(crate) assertion_envelope_digest: String,
    pub(crate) native_review_digest: String,
    pub(crate) consent_reference: String,
    pub(crate) reviewed_at_ms: u64,
    pub(crate) return_message_id: String,
    pub(crate) return_sequence: u64,
    pub(crate) return_issued_at: i64,
    pub(crate) return_expires_at: i64,
}
impl NamedRecipientFinalReviewV1 {
    pub(crate) fn reference_digest(&self) -> Result<String> {
        digest(
            "wholepact:named-recipient-final-consent:v1",
            &(
                &self.admission,
                &self.enrollment,
                &self.account_policy,
                &self.witness,
                &self.history_digest,
                &self.assertion_envelope_digest,
                &self.native_review_digest,
                self.reviewed_at_ms,
                &self.return_message_id,
                self.return_sequence,
                self.return_issued_at,
                self.return_expires_at,
            ),
        )
    }
    pub(crate) fn validate(
        &self,
        original: &NamedRecipientOriginalRecordV1,
        started: &NamedRecipientStartedRecordV1,
    ) -> Result<()> {
        self.admission
            .validate_reserved_policy_bounds(&self.account_policy, &self.enrollment)
            .map_err(|_| JournalError::InvalidBinding)?;
        self.witness
            .validate()
            .map_err(|_| JournalError::InvalidBinding)?;
        for h in [
            &self.history_digest,
            &self.assertion_envelope_digest,
            &self.native_review_digest,
            &self.consent_reference,
        ] {
            hash(h)?;
        }
        exact_hex(&self.return_message_id, 16)?;
        let start = u64::try_from(self.return_issued_at)
            .ok()
            .and_then(|n| n.checked_mul(1000))
            .ok_or(JournalError::InvalidBinding)?;
        let end = u64::try_from(self.return_expires_at)
            .ok()
            .and_then(|n| n.checked_mul(1000))
            .ok_or(JournalError::InvalidBinding)?;
        if self.schema_version != 1
            || self.return_sequence == 0
            || self.return_sequence > i64::MAX as u64
            || self.admission.request != original.reservation_request
            || self.admission.request_digest != original.reservation_request_digest
            || self.witness.account_id != original.terms.account_id
            || self.witness.network_profile_id != original.terms.network_profile_id
            || self.witness.witness_id != self.admission.witness_id
            || self.witness.policy_digest != self.admission.witness_policy_digest
            || self.witness.pinned_server_certificate_digest
                != self.enrollment.witness_certificate_digest
            || self.native_review_digest != started.native_review_digest
            || self.consent_reference != self.reference_digest()?
            || self.consent_reference
                == self
                    .admission
                    .request
                    .intent
                    .intent_digest()
                    .map_err(|_| JournalError::InvalidBinding)?
            || self.reviewed_at_ms < self.admission.reserved_at_ms
            || self.reviewed_at_ms >= started.original_deadline_ms
            || start > self.reviewed_at_ms
            || end <= self.reviewed_at_ms
            || end > started.original_deadline_ms
            || end > original.validity_expires_ms
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NamedRecipientEncryptedReturnV1 {
    pub(crate) schema_version: u16,
    pub(crate) signed_artifact_digest: String,
    pub(crate) projection_digest: String,
    pub(crate) envelope_digest: String,
    pub(crate) envelope_hex: String,
}
impl NamedRecipientEncryptedReturnV1 {
    fn validate(
        &self,
        review: &NamedRecipientFinalReviewV1,
        result: &NamedRecipientResultRecordV1,
    ) -> Result<()> {
        for h in [
            &self.signed_artifact_digest,
            &self.projection_digest,
            &self.envelope_digest,
        ] {
            hash(h)?;
        }
        exact_hex(&review.return_message_id, 16)?;
        if self.schema_version != 1
            || self.signed_artifact_digest != result.result_digest
            || self.envelope_hex.is_empty()
            || self.envelope_hex.len() > 2 * 1_048_576
        {
            return Err(JournalError::InvalidBinding);
        }
        let bytes = Zeroizing::new(
            hex::decode(&self.envelope_hex).map_err(|_| JournalError::InvalidBinding)?,
        );
        #[cfg(feature = "offline-review-foundation")]
        wholepact_transport::EncryptedEnvelope::from_bytes(bytes.to_vec())
            .map_err(invalid_named_record)?;
        if hex::encode(bytes.as_slice()) != self.envelope_hex
            || domain_digest(b"wholepact.encrypted-envelope.v1\0", &bytes) != self.envelope_digest
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureReturn {
    schema_version: u16,
    account_id: String,
    authorization_id: String,
    original_consent_ref: String,
    native_review_digest: String,
    admission_request_digest: String,
    intent_digest: String,
    terms_digest: String,
    review_package_digest: String,
    reviewed_artifact_digest: String,
    online_proved_artifact_digest: String,
    manifest_digest: String,
    effects_digest: String,
    review_binding: String,
    signed_artifact_digest: String,
    signatures: Vec<Signature>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Signature {
    action_index: u64,
    signature_hex: String,
}
impl Drop for Signature {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.signature_hex.zeroize();
    }
}

/// Rebuild exact signature-only bytes from immutable original, final consent and
/// maintained parsed signed artifact. This cannot create a key-use capability.
pub(crate) fn signature_return_projection(
    original: &NamedRecipientOriginalRecordV1,
    started: &NamedRecipientStartedRecordV1,
    bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let review = started
        .final_review
        .as_ref()
        .ok_or(JournalError::InvalidBinding)?;
    let signed = pczt::Pczt::parse(bytes).map_err(invalid_named_record)?;
    let t = &original.terms;
    let signatures = t
        .inputs
        .iter()
        .map(|i| {
            Ok(Signature {
                action_index: i.action_index,
                signature_hex: hex::encode(
                    signed
                        .ironwood()
                        .actions()
                        .get(i.action_index as usize)
                        .and_then(|a| a.spend().spend_auth_sig().as_ref())
                        .ok_or(JournalError::InvalidBinding)?,
                ),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let payload = SignatureReturn {
        schema_version: 1,
        account_id: t.account_id.clone(),
        authorization_id: t.authorization_id.clone(),
        original_consent_ref: review.consent_reference.clone(),
        native_review_digest: started.native_review_digest.clone(),
        admission_request_digest: original.reservation_request_digest.clone(),
        intent_digest: original
            .reservation_request
            .intent
            .intent_digest()
            .map_err(invalid_named_record)?,
        terms_digest: t.terms_digest().map_err(invalid_named_record)?,
        review_package_digest: t.review_package_digest.clone(),
        reviewed_artifact_digest: original.canonical_artifact_digest.clone(),
        online_proved_artifact_digest: original.original_artifact_digest.clone(),
        manifest_digest: t.manifest_digest.clone(),
        effects_digest: t.effects_digest.clone(),
        review_binding: t.review_binding.clone(),
        signed_artifact_digest: hex::encode(Sha256::digest(bytes)),
        signatures,
    };
    let raw = Zeroizing::new(serde_json::to_vec(&payload).map_err(invalid_named_record)?);
    if raw.len() > 16_384 {
        return Err(JournalError::InvalidBinding);
    }
    Ok(raw)
}

#[cfg(test)]
mod own_input_order_tests {
    use super::*;

    #[test]
    fn named_own_expectations_preserve_policy_order_but_match_exact_input_bijection() {
        let mut terms = crate::consent_journal::offline_history::tests::full_admission()
            .0
            .request
            .intent
            .terms;
        let mut first = terms.inputs[0].clone();
        first.action_index = 2;
        first.input_id = "first-selected-input".into();
        first.nullifier = "12".repeat(32);
        first.value_zatoshis = terms.maximum_debit_zatoshis;
        let mut second = first.clone();
        second.action_index = 7;
        second.input_id = "second-selected-input".into();
        second.nullifier = "34".repeat(32);
        second.value_zatoshis = 10;
        terms.inputs = vec![first, second];
        terms.validate().unwrap();
        let own = NamedRecipientOwnExpectationsV1 {
            schema_version: 1,
            full_viewing_key_digest: "56".repeat(32),
            manifest_digest: terms.manifest_digest.clone(),
            anchor: terms.snapshot.anchor_root.clone(),
            expiry_height: terms.transaction_expiry_height,
            maximum_selected_net_debit_zatoshis: terms.maximum_debit_zatoshis,
            exact_selected_net_debit_zatoshis: terms.maximum_debit_zatoshis,
            declared_fee_share_zatoshis: terms.fee_share_zatoshis,
            exact_transaction_fee_zatoshis: terms.transaction_fee_zatoshis,
            own_inputs: terms
                .inputs
                .iter()
                .rev()
                .map(|input| NamedRecipientOwnInputV1 {
                    action_index: input.action_index as u32,
                    nullifier: input.nullifier.clone(),
                    value_zatoshis: input.value_zatoshis,
                })
                .collect(),
            outputs: vec![NamedRecipientOwnOutputV1 {
                action_index: 0,
                receiver_hex: "78".repeat(43),
                value_zatoshis: 10,
                memo_hex: "00".repeat(512),
                purpose: NamedRecipientOutputPurposeV1::OwnReturn,
            }],
        };
        let original_order = serde_json::to_vec(&own).unwrap();
        own.validate(&terms).unwrap();
        assert_eq!(original_order, serde_json::to_vec(&own).unwrap());
        assert_eq!(own.own_inputs[0].action_index, 7);
        assert_eq!(own.own_inputs[1].action_index, 2);
        for change in 0..4 {
            let mut altered = own.clone();
            match change {
                0 => altered.own_inputs[1] = altered.own_inputs[0].clone(),
                1 => altered.own_inputs[0].nullifier = "90".repeat(32),
                2 => altered.own_inputs[0].value_zatoshis += 1,
                _ => altered.own_inputs[0].action_index = 9,
            }
            assert!(altered.validate(&terms).is_err());
        }
        let mut duplicate_terms = terms.clone();
        duplicate_terms.inputs[1] = duplicate_terms.inputs[0].clone();
        assert!(own.validate(&duplicate_terms).is_err());
    }
}
