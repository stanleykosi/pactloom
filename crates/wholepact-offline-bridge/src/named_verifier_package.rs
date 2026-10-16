//! Exact informational assertion package and own-effects/return consumer. The
//! package is untrusted input; its evidence is neither native consent nor a permit.
use crate::{
    NamedVerifierExpectedContext, NamedVerifierSignatureEvidence, NamedVerifierStatementV1, Result,
    SelectedOfflineEffectsReport, inspect_selected_offline_effects,
    verify_named_verifier_signature_evidence,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wholepact_protocol::own_effects::OwnEffectsPolicy;
use wholepact_transport::TransportError;
const MAX: usize = 2 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedVerifierPackageV1 {
    pub schema_version: u16,
    pub statement: NamedVerifierStatementV1,
    pub signature: Vec<u8>,
    pub recipient_artifact: Vec<u8>,
}
impl NamedVerifierPackageV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.statement.validate()?;
        if self.schema_version != 1
            || self.signature.len() != 64
            || self.recipient_artifact.len() > 1_048_576
            || hex::encode(Sha256::digest(&self.recipient_artifact))
                != self.statement.recipient_artifact_digest
        {
            return Err(TransportError::WrongContext);
        }
        let bytes = serde_json::to_vec(self).map_err(|_| TransportError::Malformed)?;
        if bytes.len() > MAX {
            return Err(TransportError::ResourceLimit);
        }
        Ok(bytes)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX {
            return Err(TransportError::ResourceLimit);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| TransportError::Malformed)?;
        if value.canonical_bytes()? != bytes {
            return Err(TransportError::Malformed);
        }
        Ok(value)
    }
}
pub struct NamedVerifierPackageInspection {
    package_digest: String,
    own: SelectedOfflineEffectsReport,
    assertion: NamedVerifierSignatureEvidence,
}
impl NamedVerifierPackageInspection {
    pub fn into_evidence(self) -> (SelectedOfflineEffectsReport, NamedVerifierSignatureEvidence) {
        (self.own, self.assertion)
    }
    pub fn package_digest(&self) -> &str {
        &self.package_digest
    }
    pub fn own(&self) -> &SelectedOfflineEffectsReport {
        &self.own
    }
    pub fn assertion(&self) -> &NamedVerifierSignatureEvidence {
        &self.assertion
    }
}
/// Caller supplies its actual retained own policy and explicitly locally selected
/// verifier identity/context. This verifies both evidence domains independently;
/// it cannot select the assurance mode or construct protected setup/authority.
pub fn inspect_named_verifier_package(
    bytes: &[u8],
    own_policy: &OwnEffectsPolicy,
    selected_key: &[u8; 32],
    expected: &NamedVerifierExpectedContext<'_>,
) -> Result<NamedVerifierPackageInspection> {
    let package = NamedVerifierPackageV1::parse(bytes)?;
    let own = inspect_selected_offline_effects(&package.recipient_artifact, own_policy)?;
    let assertion = verify_named_verifier_signature_evidence(
        &package.statement.canonical_bytes()?,
        &package.signature,
        selected_key,
        expected,
        own.inspection(),
    )?;
    Ok(NamedVerifierPackageInspection {
        package_digest: hex::encode(Sha256::digest(bytes)),
        own,
        assertion,
    })
}
/// Exact signature-only normalization of this retained package. It does not
/// reissue an assertion, refresh deadlines, verify chain state or authorize use.
pub fn inspect_named_verifier_return(
    original_package: &[u8],
    returned_artifact: &[u8],
    inspected: &NamedVerifierPackageInspection,
) -> Result<wholepact_protocol::offline_return::OpaqueVerifiedReturn> {
    if hex::encode(Sha256::digest(original_package)) != inspected.package_digest {
        return Err(TransportError::WrongContext);
    }
    let package = NamedVerifierPackageV1::parse(original_package)?;
    wholepact_protocol::offline_return::inspect_exact_own_signature_return(
        &package.recipient_artifact,
        returned_artifact,
        inspected.own.inspection(),
    )
    .map_err(|_| TransportError::Authentication)
}
