//! Source foundation: signature-verification adapter. A verified signature authenticates
//! possession of the selected existing owner certificate key only. It does not
//! prove native focus, signer key generation, account freshness, or local consent.
//! No signature issuer or witness creation capability is exposed here.
use crate::manual_enrollment::ManualEnrollmentExtension;
use crate::manual_session_continuation::ManualEnrollmentSessionContinuation;
use crate::{AuthorityError, Result, digest, hash};
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualEnrollmentSessionContinuationOwnerSignature {
    pub version: u16,
    pub extension: ManualEnrollmentExtension,
    pub continuation: ManualEnrollmentSessionContinuation,
    /// Only maintained P-256 SHA-256 ASN.1 is supported by this initial adapter.
    /// Unknown schemes fail closed; this is independent of existing TLS choices.
    pub scheme: String,
    pub owner_certificate_der: Vec<u8>,
    pub signature: Vec<u8>,
}
/// Opaque authentication evidence only. Its type deliberately has no method
/// producing native approval, journal enrollment, writer sessions or key use.
pub struct VerifiedManualEnrollmentSessionContinuationOwnerSignature {
    extension: ManualEnrollmentExtension,
    continuation: ManualEnrollmentSessionContinuation,
    certificate_digest: String,
    evidence_digest: String,
}
impl VerifiedManualEnrollmentSessionContinuationOwnerSignature {
    pub fn extension(&self) -> &ManualEnrollmentExtension {
        &self.extension
    }
    pub fn continuation(&self) -> &ManualEnrollmentSessionContinuation {
        &self.continuation
    }
    pub fn certificate_digest(&self) -> &str {
        &self.certificate_digest
    }
    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }
}
/// Independent setup must supply the expected owner pin. A pin taken only from
/// the untrusted envelope is not an authorized witness-owner selection. Final
/// local native consent remains a separate private issuer prerequisite.
pub fn verify_manual_enrollment_session_continuation_owner_signature(
    envelope: &ManualEnrollmentSessionContinuationOwnerSignature,
    independently_selected_owner_certificate_digest: &str,
) -> Result<VerifiedManualEnrollmentSessionContinuationOwnerSignature> {
    envelope.continuation.validate_for(&envelope.extension)?;
    hash(independently_selected_owner_certificate_digest)?;
    if envelope.version != 1
        || envelope.scheme != "ecdsa-p256-sha256-asn1-v1"
        || envelope.owner_certificate_der.is_empty()
        || envelope.owner_certificate_der.len() > 16 * 1024
        || envelope.signature.is_empty()
        || envelope.signature.len() > 80
    {
        return Err(AuthorityError::InvalidBinding);
    }
    let certificate = CertificateDer::from(envelope.owner_certificate_der.as_slice());
    let certificate_digest = crate::transport::certificate_digest(&certificate);
    if certificate_digest != independently_selected_owner_certificate_digest
        || certificate_digest != envelope.extension.terms.signer.owner_certificate_digest
    {
        return Err(AuthorityError::Permission);
    }
    let signed = manual_enrollment_session_continuation_owner_signing_bytes(
        &envelope.extension,
        &envelope.continuation,
    )?;
    let parsed = webpki::EndEntityCert::try_from(&certificate)
        .map_err(|_| AuthorityError::InvalidBinding)?;
    parsed
        .verify_signature(
            webpki::ring::ECDSA_P256_SHA256,
            &signed,
            &envelope.signature,
        )
        .map_err(|_| AuthorityError::Permission)?;
    // Exact pinned key verification, NOT PKI path, certificate validity or
    // revocation verification. The existing immutable local owner setup enforces its
    // own certificate policy before this adapter can enter an enrollment issuer.
    Ok(VerifiedManualEnrollmentSessionContinuationOwnerSignature {
        extension: envelope.extension.clone(),
        continuation: envelope.continuation.clone(),
        certificate_digest,
        evidence_digest: digest(
            "wholepact:manual-enrollment-session-continuation-owner-signature:v1",
            envelope,
        )?,
    })
}
/// Bytes for the dedicated private native-approved signer adapter. Merely
/// obtaining these public bytes never grants key access or native authority.
pub fn manual_enrollment_session_continuation_owner_signing_bytes(
    extension: &ManualEnrollmentExtension,
    continuation: &ManualEnrollmentSessionContinuation,
) -> Result<Vec<u8>> {
    let commitment = continuation.digest_for(extension)?;
    let mut bytes =
        b"wholepact:manual-enrollment-session-continuation-owner-approval:v1\0".to_vec();
    bytes.extend_from_slice(commitment.as_bytes());
    Ok(bytes)
}
