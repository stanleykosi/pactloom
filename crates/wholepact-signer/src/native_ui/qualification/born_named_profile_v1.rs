//! Exact profile setup remains on the SAME original consumed native controller.
//! These arguments are actual nominal verifier/witness producers plus the
//! actual protected Host's public return key, never assertion/checkpoint data.
use super::*;
use crate::native_ui::named_verifier_owner::EphemeralNamedVerifierV1;
use wholepact_authority::native_witness_owner::EphemeralBornTransportPublicPinV1;

impl NamedContinuationFixtureV1 {
    pub(in crate::native_ui) fn retain_original_profile(
        &mut self,
        verifier: &EphemeralNamedVerifierV1,
        witness_pin: &EphemeralBornTransportPublicPinV1,
        actual_host_public_key: &wholepact_transport::TransportPublicKey,
    ) -> Result<(String, String, [u8; 32])> {
        self.check_source()?;
        if !matches!(self.phase, Phase::Ready) || !self.poll_exact_pairing_and_local_records()? {
            return Err(Error::ReviewMismatch);
        }
        let result = self.controller.ui.retain_synthetic_original_born_profile(
            verifier,
            witness_pin,
            actual_host_public_key,
            self.controller.epoch,
        )?;
        self.check_source()?;
        Ok(result)
    }
}
