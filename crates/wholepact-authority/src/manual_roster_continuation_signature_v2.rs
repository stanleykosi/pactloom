//! Source foundation: signature-verification adapter. A verified signature authenticates
//! possession of the selected existing owner certificate key only. It does not
//! prove native focus, signer key generation, account freshness, or local consent.
//! No signature issuer or witness creation capability is exposed here.
use crate::manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2;
use crate::manual_roster_witness_v2::ManualRosterSessionContinuationV2;
use crate::{AuthorityError, Result, digest, hash};
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterContinuationOwnerSignatureV2 {
    pub version: u16,
    pub extension: ManualRosterEnrollmentExtensionV2,
    pub continuation: ManualRosterSessionContinuationV2,
    /// Only maintained P-256 SHA-256 ASN.1 is supported by this initial adapter.
    /// Unknown schemes fail closed; this is independent of existing TLS choices.
    pub scheme: String,
    pub owner_certificate_der: Vec<u8>,
    pub signature: Vec<u8>,
}
/// Opaque authentication evidence only. Its type deliberately has no method
/// producing native approval, journal enrollment, writer sessions or key use.
pub struct VerifiedManualRosterContinuationOwnerSignatureV2 {
    extension: ManualRosterEnrollmentExtensionV2,
    continuation: ManualRosterSessionContinuationV2,
    certificate_digest: String,
    evidence_digest: String,
}
impl VerifiedManualRosterContinuationOwnerSignatureV2 {
    pub fn extension(&self) -> &ManualRosterEnrollmentExtensionV2 {
        &self.extension
    }
    pub fn continuation(&self) -> &ManualRosterSessionContinuationV2 {
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
pub fn verify_manual_roster_continuation_owner_signature_v2(
    envelope: &ManualRosterContinuationOwnerSignatureV2,
    independently_selected_owner_certificate_digest: &str,
) -> Result<VerifiedManualRosterContinuationOwnerSignatureV2> {
    envelope.continuation.validate_for(&envelope.extension)?;
    hash(independently_selected_owner_certificate_digest)?;
    if envelope.version != 2
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
        || certificate_digest
            != envelope
                .extension
                .account_extension
                .terms
                .signer
                .owner_certificate_digest
    {
        return Err(AuthorityError::Permission);
    }
    let signed = manual_roster_continuation_owner_signing_bytes_v2(
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
    Ok(VerifiedManualRosterContinuationOwnerSignatureV2 {
        extension: envelope.extension.clone(),
        continuation: envelope.continuation.clone(),
        certificate_digest,
        evidence_digest: digest(
            "wholepact:manual-roster-session-continuation-owner-signature:v2",
            envelope,
        )?,
    })
}
/// Bytes for the dedicated private native-approved signer adapter. Merely
/// obtaining these public bytes never grants key access or native authority.
pub fn manual_roster_continuation_owner_signing_bytes_v2(
    extension: &ManualRosterEnrollmentExtensionV2,
    continuation: &ManualRosterSessionContinuationV2,
) -> Result<Vec<u8>> {
    let commitment = continuation.digest_for(extension)?;
    let mut bytes = b"wholepact:manual-roster-session-continuation-owner-approval:v2\0".to_vec();
    bytes.extend_from_slice(commitment.as_bytes());
    Ok(bytes)
}
