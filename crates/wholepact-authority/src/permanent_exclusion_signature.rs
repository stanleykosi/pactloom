//! Exact existing-owner-key authentication for a restrictive account tombstone.
//! A signature is not native consent, local persistence, or financial authority.
use crate::{
    account_use::{AccountUseGenesis, PermanentAccountExclusion},
    digest, hash, AuthorityError, Result,
};
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermanentExclusionOwnerSignatureV1 {
    pub version: u16,
    pub genesis: AccountUseGenesis,
    pub exclusion: PermanentAccountExclusion,
    pub scheme: String,
    pub owner_certificate_der: Vec<u8>,
    pub signature: Vec<u8>,
}
pub struct VerifiedPermanentExclusionOwnerSignatureV1 {
    genesis: AccountUseGenesis,
    exclusion: PermanentAccountExclusion,
    certificate_digest: String,
    evidence_digest: String,
}
impl VerifiedPermanentExclusionOwnerSignatureV1 {
    pub fn genesis(&self) -> &AccountUseGenesis {
        &self.genesis
    }
    pub fn exclusion(&self) -> &PermanentAccountExclusion {
        &self.exclusion
    }
    pub fn certificate_digest(&self) -> &str {
        &self.certificate_digest
    }
    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }
}
pub fn permanent_exclusion_owner_signing_bytes_v1(
    genesis: &AccountUseGenesis,
    exclusion: &PermanentAccountExclusion,
) -> Result<Vec<u8>> {
    genesis.validate()?;
    exclusion.validate()?;
    if exclusion.identity != genesis.identity || exclusion.genesis_digest != genesis.digest()? {
        return Err(AuthorityError::InvalidBinding);
    }
    let commitment = digest(
        "wholepact:permanent-exclusion-owner-content:v1",
        &(genesis, exclusion),
    )?;
    let mut bytes = b"wholepact:permanent-exclusion-owner-approval:v1\0".to_vec();
    bytes.extend_from_slice(commitment.as_bytes());
    Ok(bytes)
}
pub fn verify_permanent_exclusion_owner_signature_v1(
    envelope: &PermanentExclusionOwnerSignatureV1,
    independently_selected_owner_certificate_digest: &str,
) -> Result<VerifiedPermanentExclusionOwnerSignatureV1> {
    hash(independently_selected_owner_certificate_digest)?;
    let signed =
        permanent_exclusion_owner_signing_bytes_v1(&envelope.genesis, &envelope.exclusion)?;
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
        || certificate_digest != envelope.genesis.owner_certificate_digest
    {
        return Err(AuthorityError::Permission);
    }
    webpki::EndEntityCert::try_from(&certificate)
        .map_err(|_| AuthorityError::InvalidBinding)?
        .verify_signature(
            webpki::ring::ECDSA_P256_SHA256,
            &signed,
            &envelope.signature,
        )
        .map_err(|_| AuthorityError::Permission)?;
    Ok(VerifiedPermanentExclusionOwnerSignatureV1 {
        genesis: envelope.genesis.clone(),
        exclusion: envelope.exclusion.clone(),
        certificate_digest,
        evidence_digest: digest("wholepact:permanent-exclusion-owner-signature:v1", envelope)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signing_preimage_binds_exact_genesis_source_and_immutable_exclusion() {
        let (birth, _) = crate::manual_enrollment::tests::fixture();
        let genesis = birth.request.policy.account_use_genesis.unwrap();
        let mut exclusion = PermanentAccountExclusion {
            version: 1,
            identity: genesis.identity.clone(),
            genesis_digest: genesis.digest().unwrap(),
            operation_id: "synthetic-stop".into(),
            native_review_digest: "aa".repeat(32),
            reason: crate::account_use::ExclusionReason::RetirementRequested,
        };
        let original = permanent_exclusion_owner_signing_bytes_v1(&genesis, &exclusion).unwrap();
        exclusion.native_review_digest = "bb".repeat(32);
        assert_ne!(
            original,
            permanent_exclusion_owner_signing_bytes_v1(&genesis, &exclusion).unwrap()
        );
        exclusion.identity.full_viewing_key_digest = "cc".repeat(32);
        assert!(permanent_exclusion_owner_signing_bytes_v1(&genesis, &exclusion).is_err());
    }
}
