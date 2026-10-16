//! Immutable encrypted original owner signature. It is audit data only, never
//! a native decision, witness acknowledgment or permission to use account keys.
use super::*;
use wholepact_authority::permanent_exclusion_signature::{
    verify_permanent_exclusion_owner_signature_v1, PermanentExclusionOwnerSignatureV1,
};
pub(crate) const SIGNATURE: &str = "permanent-stop-owner-signature-v1.wp";
fn domain(genesis: &AccountUseGenesis) -> Result<Vec<u8>> {
    let mut value = b"wholepact:born-permanent-stop-signature:v1\0".to_vec();
    value.extend_from_slice(genesis.digest().map_err(|_| Error::InvalidData)?.as_bytes());
    Ok(value)
}
pub(crate) fn decode_signature(
    key: &[u8; 32],
    genesis: &AccountUseGenesis,
    bytes: &[u8],
) -> Result<PermanentExclusionOwnerSignatureV1> {
    let plain = vault::decrypt(key, &domain(genesis)?, bytes)?;
    if plain.len() > 128 * 1024 {
        return Err(Error::InvalidData);
    }
    let envelope: PermanentExclusionOwnerSignatureV1 =
        serde_json::from_slice(&plain).map_err(|_| Error::InvalidData)?;
    if &envelope.genesis != genesis {
        return Err(Error::ReviewMismatch);
    }
    verify_permanent_exclusion_owner_signature_v1(&envelope, &genesis.owner_certificate_digest)
        .map_err(|_| Error::Authentication)?;
    Ok(envelope)
}
impl BornPermanentStopSourceV1 {
    pub(crate) fn retained_signature(&self) -> Result<Option<PermanentExclusionOwnerSignatureV1>> {
        if !self.retained.account.directory.exists(SIGNATURE)? {
            return Ok(None);
        }
        let envelope = decode_signature(
            &self.retained.account.encryption_key,
            self.genesis(),
            &self
                .retained
                .account
                .directory
                .read(SIGNATURE, 256 * 1024)?,
        )?;
        if envelope.exclusion != self.exclusion()? {
            return Err(Error::ReviewMismatch);
        }
        Ok(Some(envelope))
    }
    pub(crate) fn retain_signature(
        &self,
        envelope: &PermanentExclusionOwnerSignatureV1,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<()> {
        self.check(owner)?;
        if envelope.genesis != *self.genesis() || envelope.exclusion != self.exclusion()? {
            return Err(Error::ReviewMismatch);
        }
        verify_permanent_exclusion_owner_signature_v1(
            envelope,
            &self.genesis().owner_certificate_digest,
        )
        .map_err(|_| Error::Authentication)?;
        if let Some(original) = self.retained_signature()? {
            if serde_json::to_vec(&original).map_err(|_| Error::InvalidData)?
                != serde_json::to_vec(envelope).map_err(|_| Error::InvalidData)?
            {
                return Err(Error::ReviewMismatch);
            }
            return Ok(());
        }
        let _native = self.source.publication_lease()?;
        self.check(owner)?;
        let plain = Zeroizing::new(serde_json::to_vec(envelope).map_err(|_| Error::InvalidData)?);
        let encrypted = vault::encrypt(
            &self.retained.account.encryption_key,
            &domain(self.genesis())?,
            &plain,
        )?;
        self.retained
            .account
            .directory
            .write(SIGNATURE, &encrypted)?;
        self.retained.account.directory.sync_all_files()?;
        self.retained_signature()?.ok_or(Error::RecoveryRequired)?;
        Ok(())
    }
}

pub(crate) const HOST_ACK: &str = "permanent-stop-host-ack-v1.wp";
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetainedPermanentStopHostAckV1 {
    pub(crate) evidence: wholepact_signer_origin::permanent_stop_v1::PermanentStopEvidenceV1,
    pub(crate) acknowledgment:
        wholepact_signer_origin::permanent_stop_v1::HostPermanentStopAcknowledgmentV1,
}
fn ack_domain(genesis: &AccountUseGenesis) -> Result<Vec<u8>> {
    let mut value = b"wholepact:born-permanent-stop-host-ack:v1\0".to_vec();
    value.extend_from_slice(genesis.digest().map_err(|_| Error::InvalidData)?.as_bytes());
    Ok(value)
}
pub(crate) fn decode_host_ack(
    key: &[u8; 32],
    genesis: &AccountUseGenesis,
    bytes: &[u8],
) -> Result<RetainedPermanentStopHostAckV1> {
    let plain = vault::decrypt(key, &ack_domain(genesis)?, bytes)?;
    if plain.len() > 256 * 1024 {
        return Err(Error::InvalidData);
    }
    let value: RetainedPermanentStopHostAckV1 =
        serde_json::from_slice(&plain).map_err(|_| Error::InvalidData)?;
    value
        .acknowledgment
        .require_evidence(&value.evidence)
        .map_err(|_| Error::Authentication)?;
    if value
        .evidence
        .request
        .original
        .enrollment
        .terms
        .identity
        .account_id
        != genesis.identity.account_id
    {
        return Err(Error::ReviewMismatch);
    }
    Ok(value)
}
impl BornPermanentStopSourceV1 {
    pub(crate) fn retained_host_ack(&self) -> Result<Option<RetainedPermanentStopHostAckV1>> {
        if !self.retained.account.directory.exists(HOST_ACK)? {
            return Ok(None);
        }
        let original = decode_host_ack(
            &self.retained.account.encryption_key,
            self.genesis(),
            &self.retained.account.directory.read(HOST_ACK, 512 * 1024)?,
        )?;
        if original.evidence.request.original != self.record().request()?
            || original.evidence.exclusion_digest
                != self.exclusion()?.digest().map_err(|_| Error::InvalidData)?
        {
            return Err(Error::ReviewMismatch);
        }
        let receipt = self
            .snapshot()?
            .witness_ack
            .ok_or(Error::RecoveryRequired)?;
        if original.evidence.original_witness_receipt_digest
            != receipt.digest().map_err(|_| Error::InvalidData)?
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(Some(original))
    }
    pub(crate) fn retain_host_ack(
        &self,
        receipt: &crate::native_ui::AuthenticatedPermanentStopHostReceiptV1<'_>,
    ) -> Result<()> {
        receipt.check_current()?;
        if !std::ptr::eq(self, receipt.source()) {
            return Err(Error::ReviewMismatch);
        }
        receipt
            .acknowledgment()
            .require_evidence(receipt.evidence())
            .map_err(|_| Error::Authentication)?;
        if let Some(original) = self.retained_host_ack()? {
            if original.acknowledgment != *receipt.acknowledgment() {
                return Err(Error::ReviewMismatch);
            }
            return Ok(());
        }
        let _native = self.source.publication_lease()?;
        receipt.check_current()?;
        let value = RetainedPermanentStopHostAckV1 {
            evidence: receipt.evidence().clone(),
            acknowledgment: receipt.acknowledgment().clone(),
        };
        let plain = Zeroizing::new(serde_json::to_vec(&value).map_err(|_| Error::InvalidData)?);
        let encrypted = vault::encrypt(
            &self.retained.account.encryption_key,
            &ack_domain(self.genesis())?,
            &plain,
        )?;
        self.retained
            .account
            .directory
            .write(HOST_ACK, &encrypted)?;
        self.retained.account.directory.sync_all_files()?;
        self.retained_host_ack()?.ok_or(Error::RecoveryRequired)?;
        Ok(())
    }
}
