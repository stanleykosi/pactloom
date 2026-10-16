//! Source foundation: signature-verification adapter. A verified signature authenticates
//! possession of the selected existing owner certificate key only. It does not
//! prove native focus, signer key generation, account freshness, or local consent.
//! No signature issuer or witness creation capability is exposed here.
use crate::manual_roster_construction_v3::ManualRosterConstructionApprovalV3;
use crate::manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2;
use crate::{AuthorityError, Result, digest, hash};
use rustls::pki_types::CertificateDer;

pub use crate::manual_roster_construction_v3::ManualRosterConstructionOwnerSignatureV3;
/// Opaque authentication evidence only. Its type deliberately has no method
/// producing native approval, journal enrollment, writer sessions or key use.
pub struct VerifiedManualRosterConstructionOwnerSignatureV3 {
    extension: ManualRosterEnrollmentExtensionV2,
    approval: ManualRosterConstructionApprovalV3,
    certificate_digest: String,
    evidence_digest: String,
    envelope: ManualRosterConstructionOwnerSignatureV3,
}
impl VerifiedManualRosterConstructionOwnerSignatureV3 {
    pub(crate) fn envelope(&self) -> &ManualRosterConstructionOwnerSignatureV3 {
        &self.envelope
    }
    pub fn extension(&self) -> &ManualRosterEnrollmentExtensionV2 {
        &self.extension
    }
    pub fn approval(&self) -> &ManualRosterConstructionApprovalV3 {
        &self.approval
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
pub fn verify_manual_roster_construction_owner_signature_v3(
    envelope: &ManualRosterConstructionOwnerSignatureV3,
    independently_selected_owner_certificate_digest: &str,
) -> Result<VerifiedManualRosterConstructionOwnerSignatureV3> {
    envelope.approval.validate_for(&envelope.extension)?;
    hash(independently_selected_owner_certificate_digest)?;
    if envelope.version != 3
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
    let signed =
        manual_roster_construction_owner_signing_bytes_v3(&envelope.extension, &envelope.approval)?;
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
    Ok(VerifiedManualRosterConstructionOwnerSignatureV3 {
        envelope: envelope.clone(),
        extension: envelope.extension.clone(),
        approval: envelope.approval.clone(),
        certificate_digest,
        evidence_digest: digest(
            "wholepact:manual-roster-construction-owner-signature:v3",
            envelope,
        )?,
    })
}
/// Bytes for the dedicated private native-approved signer adapter. Merely
/// obtaining these public bytes never grants key access or native authority.
pub fn manual_roster_construction_owner_signing_bytes_v3(
    extension: &ManualRosterEnrollmentExtensionV2,
    approval: &ManualRosterConstructionApprovalV3,
) -> Result<Vec<u8>> {
    let commitment = approval.digest_for(extension)?;
    let mut bytes = b"wholepact:manual-roster-construction-owner-approval:v3\0".to_vec();
    bytes.extend_from_slice(commitment.as_bytes());
    Ok(bytes)
}
