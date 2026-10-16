//! Inert evidence for explicit old-read/new-caller lineage. Parsing any of these
//! values creates no dormant, reentered, read, construction or signing owner.
use crate::manual_roster_construction_v3::ManualRosterConstructionContributionEvidenceV3;
use crate::{Error, Result, digest};
use serde::{Deserialize, Serialize};
use wholepact_core::common_context_reentry_v1::RosterCommonContextReentryLineageV1;

// Reentry repeats exact original facts but never widens the established frame
// cap. Oversized complete evidence fails closed; no compacted authority fallback.
pub const MAX_COMMON_CONTEXT_REENTRY_FRAME: usize = 768 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum RosterCommonContextReentryResponseV1 {
    CommonContextReenteredV1 {
        lineage: Box<RosterCommonContextReentryLineageV1>,
    },
    Denied {},
}

/// A new wire domain, leaving old V3 consumed evidence and its strict original
/// attempt interpretation unchanged. The explicit lineage must be archived and
/// joined; extracting `construction` alone discards its reentry provenance.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RosterReenteredConstructionEvidenceV1 {
    pub version: u16,
    pub reentry_lineage: RosterCommonContextReentryLineageV1,
    pub construction: ManualRosterConstructionContributionEvidenceV3,
}
impl RosterReenteredConstructionEvidenceV1 {
    pub fn validate(&self) -> Result<()> {
        self.reentry_lineage
            .validate()
            .map_err(|_| Error::Binding)?;
        self.construction.validate()?;
        let lineage = &self.reentry_lineage;
        let new = &lineage.request;
        let original = &new.original_read;
        let construction = &self.construction;
        if self.version != 1
            || construction.request.plan != original.plan
            || construction.request.current_caller_binding_digest
                != new.current_caller_binding_digest
            || construction.request.operation_id == new.operation_id
            || construction.request.operation_id == original.operation_id
            || construction.request.requested_at_ms < lineage.admitted_at_ms
            || construction.request.admission_expires_at_ms > lineage.completion_expires_at_ms
            || construction.retained_signer_intent_digest != lineage.retained_signer_intent_digest
            || construction.current_attempt_digest != new.current_attempt_digest
            || construction.current_attempt_sequence != new.current_attempt_sequence
            || construction.common_context_read_admission_digest
                != new.original_read_admission_digest
            || construction.witness_plan_approval_digest != original.witness_plan_approval_digest
            || construction.native_review_digest == lineage.native_review_digest
            || construction.writer_session_expires_at_ms
                != lineage.current_writer_session_expires_at_ms
            || construction.consumed_at_ms >= lineage.completion_expires_at_ms
        {
            return Err(Error::Binding);
        }
        if serde_json::to_vec(self).map_err(|_| Error::Binding)?.len()
            > MAX_COMMON_CONTEXT_REENTRY_FRAME
        {
            return Err(Error::Limit);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:roster-reentered-construction-evidence:v1", self)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum RosterReenteredConstructionResponseV1 {
    ReenteredConstructionConsumedV1 {
        evidence: Box<RosterReenteredConstructionEvidenceV1>,
    },
    Denied {},
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn old_and_caller_supplied_authority_flags_do_not_parse_as_reentry() {
        for json in [
            r#"{"status":"common_context_read_admitted_v1","evidence":{}}"#,
            r#"{"status":"denied","approved":true}"#,
            r#"{"status":"common_context_reentered_v1","lineage":{},"restore":true}"#,
        ] {
            assert!(serde_json::from_str::<RosterCommonContextReentryResponseV1>(json).is_err());
        }
        assert!(
            serde_json::from_str::<RosterCommonContextReentryResponseV1>(r#"{"status":"denied"}"#)
                .is_ok()
        );
        assert!(
            serde_json::from_str::<RosterReenteredConstructionResponseV1>(
                r#"{"status":"exact_construction_consumed_v3","evidence":{}}"#
            )
            .is_err()
        );
    }
}
