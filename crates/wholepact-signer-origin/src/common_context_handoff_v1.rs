//! Inert bounded handoff wire. These values cannot issue native authority.
use crate::{Error, Result, hash, label};
use serde::{Deserialize, Serialize};
pub const MAX_HANDOFF_AUTHORIZATION_JSON: usize = 16 * 1024;
pub const MAX_HANDOFF_AUTHORIZATION_FRAME: usize = 32 * 1024;
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RosterCommonContextHandoffAuthorizationRequestV1 {
    pub version: u16,
    pub operation_id: String,
    pub original_read_admission_digest: String,
    pub current_caller_binding_digest: String,
}
impl RosterCommonContextHandoffAuthorizationRequestV1 {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(Error::Binding);
        }
        label(&self.operation_id)?;
        hash(&self.original_read_admission_digest)?;
        hash(&self.current_caller_binding_digest)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum RosterCommonContextHandoffAuthorizationResponseV1 {
    CommonContextHandoffAuthorizedV1 {
        signed_authorization_json: String,
        signed_authorization_digest: String,
    },
    Denied {},
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn approval_flags_and_legacy_responses_are_rejected() {
        for wire in [
            r#"{"status":"denied","approved":true}"#,
            r#"{"status":"common_context_read_admitted_v1","evidence":{}}"#,
        ] {
            assert!(
                serde_json::from_str::<RosterCommonContextHandoffAuthorizationResponseV1>(wire)
                    .is_err()
            );
        }
        let mut request = RosterCommonContextHandoffAuthorizationRequestV1 {
            version: 1,
            operation_id: "handoff".into(),
            original_read_admission_digest: "a".repeat(64),
            current_caller_binding_digest: "b".repeat(64),
        };
        assert!(request.validate().is_ok());
        request.version = 2;
        assert!(request.validate().is_err());
    }
}
