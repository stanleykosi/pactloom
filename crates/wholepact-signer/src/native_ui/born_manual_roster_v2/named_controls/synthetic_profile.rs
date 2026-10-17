//! Finite actual source plus actual nominal pin-owner composition. No raw native
//! decision, source or mutable profile record is exported to the caller.
use super::*;
use crate::native_ui::named_verifier_owner::EphemeralNamedVerifierV1;
use wholepact_authority::native_witness_owner::EphemeralBornTransportPublicPinV1;

impl BornManualRosterUiV2 {
    pub(in crate::native_ui) fn retain_synthetic_original_born_profile(
        &mut self,
        verifier: &EphemeralNamedVerifierV1,
        witness_pin: &EphemeralBornTransportPublicPinV1,
        actual_host_public_key: &wholepact_transport::TransportPublicKey,
        epoch: u64,
    ) -> Result<(String, String, [u8; 32])> {
        if self.job.is_some()
            || self.review.is_some()
            || self.named_controls.active()
            || self.named_controls.bridge.held()
            || self.named_controls.verifier.engaged()
            || self.named_controls.workspace.live_profile().is_some()
        {
            return Err(Error::Locked);
        }
        let owner = self.owner(epoch)?;
        let actual = self.named_continuation.as_ref().ok_or(Error::Locked)?;
        actual.check(&owner)?;
        let (signing_key, transport_key) = verifier.public_keys()?;
        // This nominal snapshot proves original public provenance only. It
        // carries no current key/native authority; the actual main-thread
        // witness must still revalidate its key before enrollment/install.
        let witness_public = witness_pin
            .original_public_key_for_account(&actual.source().genesis().identity.account_id)
            .map_err(|_| Error::ReviewMismatch)?;
        let disclosure = actual.source().original_witness_disclosure(&owner)?;
        if witness_pin.original_server_certificate_digest()
            != disclosure.pinned_server_certificate_digest
        {
            return Err(Error::ReviewMismatch);
        }
        let context = actual.context(&owner)?;
        self.named_controls
            .workspace
            .retain_synthetic_original_born_profile(
                &context,
                crate::consent_journal::NamedRecipientPins {
                    verifier_signing: signing_key,
                    verifier_transport: transport_key,
                    witness_transport: witness_public,
                    witness_certificate_digest: disclosure.pinned_server_certificate_digest,
                    return_transport: *actual_host_public_key.as_bytes(),
                },
                epoch,
            )?;
        let live = self
            .named_controls
            .workspace
            .live_profile()
            .ok_or(Error::Locked)?;
        live.check_current(actual.source().journal(), actual.session()?)?;
        actual.check(&owner)?;
        let projection = (
            live.reference().into(),
            live.original_setup_commitment().into(),
            *live.transport_public_key(),
        );
        if verifier.public_keys()? != (signing_key, transport_key)
            || witness_pin
                .original_public_key_for_account(&actual.source().genesis().identity.account_id)
                .map_err(|_| Error::ReviewMismatch)?
                != witness_public
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(projection)
    }
}
