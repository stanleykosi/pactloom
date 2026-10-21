//! Same-source Return pin. Only a genuine coordinated Read issues this wrapper;
//! it is change detection, not permission to send signatures.
use super::*;
use crate::native_peer::PeerProcess;
use wholepact_financial_coordinator_origin::SignerReturnReadFinalV1;

pub(crate) struct CoordinatedFinancialReturnSourcePinV1 {
    inner: FinancialReturnSourcePinV1,
    read_presentation_digest: String,
}
impl CoordinatedFinancialReturnSourcePinV1 {
    pub(crate) fn read_presentation_digest(&self) -> &str {
        &self.read_presentation_digest
    }
}
impl PreparedOriginalFinancialSourceV1 {
    pub(crate) fn check_coordinated_return_read_v1(
        &self,
        peer: &PeerProcess,
        read: &SignerReturnReadFinalV1,
    ) -> Result<()> {
        read.check_current()?;
        let facts = &read.presentation().facts;
        let original = &facts.original.activation.facts.original;
        if read.original_source_deadline() != self.original_deadline
            || original.source_identity_digest != self.identity
            || original.source_expires_at_ms != self.original_ceiling_ms
            || facts.original_host_process_instance != peer.instance()
            || original.original_host_process_instance != peer.instance()
        {
            return Err(Error::ReviewMismatch);
        }
        self.check_coordinated_public_custody_v2(peer)?;
        read.check_current()?;
        Ok(())
    }
    pub(crate) fn prepare_coordinated_return_source_pin_v1(
        &self,
        journal: FinancialReturnJournalPinV1,
        peer: &PeerProcess,
        read: &SignerReturnReadFinalV1,
    ) -> Result<CoordinatedFinancialReturnSourcePinV1> {
        self.check_coordinated_return_read_v1(peer, read)?;
        let inner = FinancialReturnSourcePinV1 {
            source_identity: self.identity.clone(),
            journal,
        };
        self.check_financial_return_source_pin_v1(&inner, peer)?;
        self.check_coordinated_return_read_v1(peer, read)?;
        Ok(CoordinatedFinancialReturnSourcePinV1 {
            inner,
            read_presentation_digest: read.presentation().presentation_digest.clone(),
        })
    }
    pub(crate) fn check_coordinated_return_source_pin_v1(
        &self,
        pin: &CoordinatedFinancialReturnSourcePinV1,
        peer: &PeerProcess,
    ) -> Result<()> {
        // No expired Read action is reused. This checks only the sealed original
        // custody, actual H pidfd and unchanged audited result revision.
        self.check_coordinated_public_custody_v2(peer)?;
        self.check_financial_return_source_pin_v1(&pin.inner, peer)?;
        self.check_coordinated_public_custody_v2(peer)
    }
}
