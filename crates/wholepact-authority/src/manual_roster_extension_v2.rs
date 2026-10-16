//! STAGED, UNCOMPILED. New exact signed wrapper; V1 inner bytes/domain unchanged.
//! Decoding or validating is audit-only and never grants a namespace lease.
use crate::manual_enrollment::ManualEnrollmentExtension;
use crate::pending_birth::PendingBirthCommitRecord;
use crate::{AccountPolicy, AuthorityError, Result, digest, hash};
use serde::{Deserialize, Serialize};
use wholepact_core::manual_roster_v2::HostRosterAppendBindingV2;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRosterEnrollmentExtensionV2 {
    pub version: u16,
    pub account_extension: ManualEnrollmentExtension,
    pub roster: HostRosterAppendBindingV2,
    pub signer_roster_record_digest: String,
}
impl ManualRosterEnrollmentExtensionV2 {
    pub fn validate(&self) -> Result<()> {
        self.account_extension.validate()?;
        self.roster
            .validate_for_host(&self.account_extension.terms.host)
            .map_err(|_| AuthorityError::InvalidBinding)?;
        hash(&self.signer_roster_record_digest)?;
        if self.version != 2 {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:manual-roster-enrollment-extension:v2", self)
    }
    pub fn validate_original_birth(&self, birth: &PendingBirthCommitRecord) -> Result<()> {
        self.validate()?;
        self.account_extension.validate_original_birth(birth)
    }
    pub(crate) fn validate_original_policy(&self, policy: &AccountPolicy) -> Result<()> {
        self.validate()?;
        self.account_extension.validate_original_policy(policy)
    }
    pub(crate) fn owner_operation_id(&self) -> Result<String> {
        Ok(format!("manual-roster-extend-v2-{}", self.digest()?))
    }
    pub fn acquire_operation_id(&self) -> Result<String> {
        Ok(format!("manual-roster-acquire-v2-{}", self.digest()?))
    }
    pub fn admission_operation_id(&self) -> Result<String> {
        Ok(format!("manual-roster-admit-v2-{}", self.digest()?))
    }
}
