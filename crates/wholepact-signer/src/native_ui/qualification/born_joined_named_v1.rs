//! Narrow cross-crate facade over the SAME consumed/parked native controller.
//! Available only in the opt-in never-funded synthetic qualification graph.
use super::*;
use super::construction_fixture::EphemeralConsumedNamedV3;
use crate::native_ui::born_manual_roster_v2::born_manual_roster::continuation_fixture::construction_fixture::named_fixture::NamedContinuationFixtureV1;

impl EphemeralConsumedNamedV3 {
    pub fn reopen_original_named_payment(self) -> Result<EphemeralNamedPaymentV1> {
        Ok(EphemeralNamedPaymentV1 {
            inner: NamedContinuationFixtureV1::open(self.inner)?,
        })
    }
}
/// Retains actual native and temporary owners. No public constructor, raw
/// source/decision getter, alternate process adoption or general callback issuer.
pub struct EphemeralNamedPaymentV1 {
    inner: NamedContinuationFixtureV1,
}
impl EphemeralNamedPaymentV1 {
    pub fn endpoint(&self) -> Result<PathBuf> {
        self.inner.endpoint()
    }
    pub fn provider(&self) -> Result<InstalledSignerProvider> {
        current_provider()
    }
    pub fn pairing_scope(&self) -> Result<wholepact_signer_origin::PairScope> {
        self.inner.pairing_scope()
    }
    pub fn deadline(&self) -> Result<Instant> {
        self.inner.deadline()
    }
    pub fn poll_exact_pairing_and_local_records(&mut self) -> Result<bool> {
        self.inner.poll_exact_pairing_and_local_records()
    }
}

impl EphemeralNamedPaymentV1 {
    /// Returns (original profile reference, original setup commitment, actual
    /// signer HPKE public key). The return pin must come from the same genuine
    /// retained Host's protected transport public projection. No checkpoint or
    /// verifier assertion is manufactured by retaining this exact profile.
    pub fn retain_original_profile(
        &mut self,
        verifier: &crate::native_ui::named_verifier_owner::EphemeralNamedVerifierV1,
        witness_pin: &wholepact_authority::native_witness_owner::EphemeralBornTransportPublicPinV1,
        actual_host_public_key: &wholepact_transport::TransportPublicKey,
    ) -> Result<(String, String, [u8; 32])> {
        self.inner
            .retain_original_profile(verifier, witness_pin, actual_host_public_key)
    }
}

impl EphemeralNamedPaymentV1 {
    pub fn arm_original_verifier_scope(
        &mut self,
        scope: wholepact_signer_origin::named_verifier_policy::NamedVerifierPolicyScopeV1,
    ) -> Result<PathBuf> {
        self.inner.arm_original_verifier_scope(scope)
    }
    pub fn poll_original_verifier_disclosure(&mut self) -> Result<bool> {
        self.inner.poll_original_verifier_disclosure()
    }
    /// Inert local enrollment/manifest references and actual signer public key.
    pub fn original_local_public_context(&self) -> Result<(String, String, [u8; 32])> {
        self.inner.named_public_context()
    }
    pub(in crate::native_ui) fn require_original_verifier_lane(
        &self,
        scope: &wholepact_signer_origin::named_verifier_policy::NamedVerifierPolicyScopeV1,
        endpoint: &str,
    ) -> Result<()> {
        self.inner.require_verifier_lane(scope, endpoint)
    }
}

impl EphemeralNamedPaymentV1 {
    pub fn export_original_owner_enrollment(
        &mut self,
        source_identity_digest: &str,
        source_policy_digest: &str,
    ) -> Result<(
        PathBuf,
        wholepact_authority::born_offline_enrollment_v1::BornOfflineEnrollmentV1,
    )> {
        self.inner
            .export_original_owner_enrollment(source_identity_digest, source_policy_digest)
    }
    pub fn installed_original_setup_metadata(
        &self,
    ) -> Result<crate::consent_journal::OriginalNamedSetupMetadataV1> {
        self.inner.installed_original_setup_metadata()
    }
}

impl EphemeralNamedPaymentV1 {
    pub fn retain_original_payment(
        &mut self,
        artifacts: crate::consent_journal::OriginalNamedPaymentArtifactsV1,
    ) -> Result<(String, PathBuf)> {
        self.inner.retain_original_payment(artifacts)
    }
    pub fn submit_original_payment(&mut self) -> Result<()> {
        self.inner.submit_original_payment()
    }
    pub fn sign_and_export_original_return(&mut self) -> Result<PathBuf> {
        self.inner.sign_and_export_original_return()
    }
    pub fn poll_original_host_history_or_dispatch(&mut self) -> Result<()> {
        self.inner.poll_original_host_history_or_dispatch()
    }
}

impl EphemeralNamedPaymentV1 {
    /// Exact historical references from the actual successful return-file owner.
    /// Host must independently acquire its genuine live history/dispatch leases.
    pub fn original_return_references(
        &self,
    ) -> Result<crate::consent_journal::OriginalNamedReturnReferencesV1> {
        self.inner.original_return_references()
    }
}
