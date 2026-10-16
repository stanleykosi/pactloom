//! STAGED, UNCOMPILED. Signature authentication is not native approval.
//! Only maintained P-256/SHA-256 verification, with independently chosen pin.
use crate::manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2;
use crate::{AuthorityError, Result, digest, hash};
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterEnrollmentOwnerSignatureV2 {
    pub version: u16,
    pub extension: ManualRosterEnrollmentExtensionV2,
    pub scheme: String,
    pub owner_certificate_der: Vec<u8>,
    pub signature: Vec<u8>,
}
/// Authentication evidence only. There is deliberately no Deserialize, Clone,
/// public field, constructor, native-approval conversion or admission factory.
pub struct VerifiedManualRosterEnrollmentOwnerSignatureV2 {
    extension: ManualRosterEnrollmentExtensionV2,
    certificate_digest: String,
    evidence_digest: String,
}
impl VerifiedManualRosterEnrollmentOwnerSignatureV2 {
    pub fn extension(&self) -> &ManualRosterEnrollmentExtensionV2 {
        &self.extension
    }
    pub fn certificate_digest(&self) -> &str {
        &self.certificate_digest
    }
    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }
}
pub fn verify_manual_roster_enrollment_owner_signature_v2(
    envelope: &ManualRosterEnrollmentOwnerSignatureV2,
    independently_selected_owner_certificate_digest: &str,
) -> Result<VerifiedManualRosterEnrollmentOwnerSignatureV2> {
    envelope.extension.validate()?;
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
    let bytes = manual_roster_enrollment_owner_signing_bytes_v2(&envelope.extension)?;
    let parsed = webpki::EndEntityCert::try_from(&certificate)
        .map_err(|_| AuthorityError::InvalidBinding)?;
    parsed
        .verify_signature(webpki::ring::ECDSA_P256_SHA256, &bytes, &envelope.signature)
        .map_err(|_| AuthorityError::Permission)?;
    Ok(VerifiedManualRosterEnrollmentOwnerSignatureV2 {
        extension: envelope.extension.clone(),
        certificate_digest,
        evidence_digest: digest(
            "wholepact:manual-roster-enrollment-owner-signature:v2",
            envelope,
        )?,
    })
}
pub fn manual_roster_enrollment_owner_signing_bytes_v2(
    extension: &ManualRosterEnrollmentExtensionV2,
) -> Result<Vec<u8>> {
    let commitment = extension.digest()?;
    let mut bytes = b"wholepact:manual-roster-enrollment-owner-approval:v2\0".to_vec();
    bytes.extend_from_slice(commitment.as_bytes());
    Ok(bytes)
}
