//! Purpose-distinct minimal assertion for a native born witness. Public DTOs and
//! pure projections never grant sealing, signer approval or spending authority.
use super::*;
use serde::{Deserialize, Serialize};
use wholepact_authority::{
    OfflineAdmissionExportPlan, born_offline_admission_v1::BornOfflineAuthorizationAdmissionV1,
};

pub const BORN_OFFLINE_MINIMAL_ADMISSION_FIELD_V1: &str = "born-offline-minimal-admission-v1";
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornOfflineMinimalAdmissionV1 {
    pub version: u16,
    pub enrollment_digest: String,
    pub artifact_binding_digest: String,
    pub original_born_request_digest: String,
    pub statement: OfflineMinimalAdmission,
}
impl BornOfflineMinimalAdmissionV1 {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(TransportError::UnsupportedVersion);
        }
        for h in [
            &self.enrollment_digest,
            &self.artifact_binding_digest,
            &self.original_born_request_digest,
        ] {
            super::types::validate_hex(h, 32)?;
        }
        self.statement.validate()
    }
    pub fn statement_digest(&self) -> Result<String> {
        self.validate()?;
        Ok(super::types::digest(
            b"wholepact.born-offline-minimal-admission.v1\0",
            &super::types::encode(self)?,
        ))
    }
    /// Inert exact projection only. The actual protected owner independently
    /// requires durable born admission and original outbox allocation before seal.
    pub fn from_descriptor(
        admission: &BornOfflineAuthorizationAdmissionV1,
        plan: &OfflineAdmissionExportPlan,
    ) -> Result<Self> {
        admission
            .matches_request(&admission.request)
            .map_err(|_| TransportError::Malformed)?;
        plan.matches_commit(&admission.reserved)
            .map_err(|_| TransportError::WrongContext)?;
        let a = &admission.reserved;
        let i = &a.request.intent;
        let value = Self {
            version: 1,
            enrollment_digest: admission.request.enrollment_digest.clone(),
            artifact_binding_digest: admission.request.artifact_binding_digest.clone(),
            original_born_request_digest: admission
                .request
                .request_digest()
                .map_err(|_| TransportError::Malformed)?,
            statement: OfflineMinimalAdmission {
                schema_version: 1,
                witness_id: a.witness_id.clone(),
                witness_transport_key_digest: a.witness_transport_key_digest.clone(),
                witness_policy_digest: a.witness_policy_digest.clone(),
                operation_id: a.request.operation_id.clone(),
                authorization_id: i.terms.authorization_id.clone(),
                request_digest: a.request_digest.clone(),
                intent_digest: i.intent_digest().map_err(|_| TransportError::Malformed)?,
                terms_digest: i
                    .terms
                    .terms_digest()
                    .map_err(|_| TransportError::Malformed)?,
                review_package_digest: i.terms.review_package_digest.clone(),
                original_admission_digest: admission
                    .admission_digest()
                    .map_err(|_| TransportError::Malformed)?,
                original_export_plan_digest: plan
                    .plan_digest()
                    .map_err(|_| TransportError::Malformed)?,
                committed_head: a.committed_head.clone(),
                reserved_at_ms: a.reserved_at_ms,
                admission_expires_at_ms: a.request.admission_expires_at_ms,
            },
        };
        value.validate()?;
        Ok(value)
    }
}
