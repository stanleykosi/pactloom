//! Immutable data-only linkage between the actual born V3 origin and separately
//! reviewed local signer enrollment. Neither parsing nor hashing issues a lease.
use super::*;
use wholepact_authority::{
    account_use::AccountUseGenesis, born_offline_construction_v1::BornOfflineConstructionOriginV1,
};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BornNamedRecipientProfileBindingV1 {
    pub(crate) version: u16,
    pub(crate) genesis: AccountUseGenesis,
    pub(crate) construction: BornOfflineConstructionOriginV1,
}
impl BornNamedRecipientProfileBindingV1 {
    pub(crate) fn validate(&self) -> Result<()> {
        self.genesis.validate().map_err(invalid_named_record)?;
        self.construction.validate().map_err(invalid_named_record)?;
        let terms = &self.construction.extension.account_extension.terms;
        if self.version != 1
            || self.construction.transport_credential_id.is_none()
            || terms.identity.account_id != self.genesis.identity.account_id
            || terms.identity.full_viewing_key_digest
                != self.genesis.identity.full_viewing_key_digest
            || terms.identity.network_profile_id != self.genesis.identity.network_profile_id
            || terms.identity.derivation_domain != self.genesis.identity.derivation_domain
            || terms.account_use_genesis_digest
                != self.genesis.digest().map_err(invalid_named_record)?
            || terms.original_witness_origin_digest != self.genesis.witness_origin_digest
            || terms.native_birth_digest != self.genesis.native_birth_digest
            || terms.signer.owner_certificate_digest != self.genesis.owner_certificate_digest
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
    pub(crate) fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:born-named-recipient-profile-binding:v1", self)
    }
    pub(crate) fn witness_enrollment_ref(&self) -> &str {
        &self.construction.extension.account_extension.enrollment_ref
    }
    pub(crate) fn validate_local_enrollment(
        &self,
        profile: &NamedRecipientProfileRecordV1,
        enrollment: &AccountEnrollmentRecord,
    ) -> Result<()> {
        self.validate()?;
        enrollment.validate()?;
        let terms = &self.construction.extension.account_extension.terms;
        let scope = &terms.scope;
        // The local principal belongs to a separate native signer session, not
        // the original Host principal. Its exact value is committed by this
        // retained local row/reference and checked by the actual native lease.
        if enrollment.reference() != profile.enrollment_ref
            || enrollment.account_id() != profile.account_id
            || enrollment.account_fvk_digest() != profile.full_viewing_key_digest
            || enrollment.account_id() != terms.identity.account_id
            || enrollment.account_fvk_digest() != terms.identity.full_viewing_key_digest
            || enrollment.agreement_id() != scope.agreement_id
            || enrollment.participant_id() != scope.participant_id
            || enrollment.terms.network_profile_id != terms.identity.network_profile_id
            || enrollment.terms.privacy_domain != scope.privacy_domain
            || enrollment.budget_limit_zatoshis() != scope.aggregate_budget_zatoshis
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
    pub(crate) fn validate_local_manifest(
        &self,
        profile: &NamedRecipientProfileRecordV1,
        enrollment: &AccountEnrollmentRecord,
        manifest: &AcceptedManifestRecord,
    ) -> Result<()> {
        self.validate_local_enrollment(profile, enrollment)?;
        let actual_proposal = manifest.proposal()?;
        let proposal = self
            .construction
            .reservation
            .request
            .construction
            .plan
            .validate()
            .map_err(invalid_named_record)?;
        if manifest.reference() != profile.manifest_ref
            || manifest.enrollment_ref() != enrollment.reference()
            || manifest.terms.account_id != profile.account_id
            || manifest.terms.principal_id != enrollment.principal_id()
            || actual_proposal.input() != proposal.input()
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
}
