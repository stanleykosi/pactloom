//! Inert named-profile commitment. Hash equality does not establish setup,
//! assertion truth, native approval, an admission or permission to use a key.
use super::{Result, TransportError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const NAMED_REVIEW_BINDING_FIELD_V1: &str = "named-review-binding-v1";
pub const NAMED_REVIEW_DISCLOSURE_PROFILE_V1: &str = "wholepact.named-verifier-own-effects.v1";
pub const MAX_NAMED_REVIEW_BINDING_BYTES_V1: usize = 2048;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedReviewBindingV1 {
    pub schema_version: u16,
    pub disclosure_profile: String,
    pub owner_setup_digest: String,
    pub assertion_package_digest: String,
    pub original_context_digest: String,
}
impl NamedReviewBindingV1 {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 || self.disclosure_profile != NAMED_REVIEW_DISCLOSURE_PROFILE_V1
        {
            return Err(TransportError::WrongContext);
        }
        for value in [
            &self.owner_setup_digest,
            &self.assertion_package_digest,
            &self.original_context_digest,
        ] {
            super::types::validate_hex(value, 32)?;
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| TransportError::Malformed)?;
        if bytes.len() > MAX_NAMED_REVIEW_BINDING_BYTES_V1 {
            return Err(TransportError::ResourceLimit);
        }
        Ok(bytes)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_NAMED_REVIEW_BINDING_BYTES_V1 {
            return Err(TransportError::ResourceLimit);
        }
        let parsed: Self =
            wholepact_core::parse_typed_json(bytes).map_err(|_| TransportError::Malformed)?;
        if parsed.canonical_bytes()? != bytes {
            return Err(TransportError::Malformed);
        }
        Ok(parsed)
    }
    pub fn review_package_digest(&self) -> Result<String> {
        let mut digest = Sha256::new();
        digest.update(b"wholepact:named-recipient-review-package:v1\0");
        digest.update(self.canonical_bytes()?);
        Ok(hex::encode(digest.finalize()))
    }
    /// Inputs are independent locally retained expectations, not facts learned
    /// from this same header. This checks equality only, never their provenance.
    pub fn matches_expected(
        &self,
        owner_setup: &str,
        assertion_package: &str,
        original_context: &str,
    ) -> Result<()> {
        self.validate()?;
        if self.owner_setup_digest != owner_setup
            || self.assertion_package_digest != assertion_package
            || self.original_context_digest != original_context
        {
            return Err(TransportError::WrongContext);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "named_review_binding_v1_tests.rs"]
mod tests;
