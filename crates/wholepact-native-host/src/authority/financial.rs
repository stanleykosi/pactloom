//! Foreground, exact saved-checkpoint privacy consent. This is not a spending,
//! account attribution, remote disclosure or submission authority.
use super::*;
use wholepact_proof_jobs::{CheckpointScope, LocalAction, LocalProofConsent};

pub(crate) struct NativeProofConsent {
    principal: String,
    candidate: String,
    manifest: String,
    terminal: Terminal,
    held: Held,
    allowed: Vec<LocalAction>,
    approved: Mutex<Vec<(CheckpointScope, LocalAction)>>,
}
impl Authority {
    pub(crate) fn proof_consent(
        &self,
        principal: &str,
        candidate: &str,
        manifest: &str,
        allowed: Vec<LocalAction>,
    ) -> Result<NativeProofConsent> {
        self.principal(principal)?;
        id(candidate)?;
        Ok(NativeProofConsent {
            principal: principal.into(),
            candidate: candidate.into(),
            manifest: manifest.into(),
            terminal: self.terminal.clone(),
            held: self
                .fence
                .acquire(now()?.checked_add(3600).ok_or(Error::Invalid)?)?,
            allowed,
            approved: Mutex::new(Vec::new()),
        })
    }
}
fn scope_matches(
    principal: &str,
    candidate: &str,
    manifest: &str,
    allowed: &[LocalAction],
    scope: &CheckpointScope,
    action: LocalAction,
) -> bool {
    scope.principal_id == principal
        && scope.candidate_id == candidate
        && scope.manifest_digest == manifest
        && allowed.contains(&action)
}
fn previously_inspected(
    approved: &[(CheckpointScope, LocalAction)],
    scope: &CheckpointScope,
) -> bool {
    approved
        .iter()
        .any(|(s, a)| s == scope && *a == LocalAction::InspectStatus)
}
impl LocalProofConsent for NativeProofConsent {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        if !scope_matches(
            &self.principal,
            &self.candidate,
            &self.manifest,
            &self.allowed,
            scope,
            action,
        ) || self.held.check().is_err()
        {
            return false;
        }
        let Ok(mut approved) = self.approved.lock() else {
            return false;
        };
        // Re-retention during proving is allowed only for the exact checkpoint
        // already inspected in this command. This issuer cannot approve new
        // constructed witnesses or a changed scope discovered while proving.
        if action == LocalAction::RetainPrivateWitnesses && !previously_inspected(&approved, scope)
        {
            return false;
        }
        if !approved.iter().any(|(s, a)| s == scope && *a == action) {
            let Ok(detail) = serde_json::to_string_pretty(scope) else {
                return false;
            };
            if self.terminal.confirm(&format!(
                "Allow {action:?} for this EXACT saved private checkpoint in this native process?\n{detail}\nViewing material and witnesses can reveal account activity. No bytes will be exported, and this approval grants no signing, account ownership or broadcast authority. Proving consumes local CPU and preserves the exact saved candidate. Recovery marks interrupted work uncertain; it does not assert completion. Approval ends on command completion, lock, revoke or one hour."
            )).is_err() || self.held.check().is_err() { return false; }
            approved.push((scope.clone(), action));
        }
        self.held.check().is_ok()
    }
}

impl Authority {
    pub(crate) fn check_financial_principal(&self, principal: &str) -> Result<()> {
        self.principal(principal)?;
        let held = self
            .fence
            .acquire(now()?.checked_add(1).ok_or(Error::Invalid)?)?;
        held.check()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Scope matching is tested independently of a controlling TTY: no fake
    // terminal or permissive production consent is introduced for testing.
    #[test]
    fn exact_scope_action_and_prior_retention_boundaries() {
        let scope = CheckpointScope {
            principal_id: "principal".into(),
            candidate_id: "candidate".into(),
            manifest_digest: "manifest".into(),
            artifact_digest: "artifact".into(),
            effects_commitment: "effects".into(),
            coordination_request_digest: "request".into(),
            review_binding: "review".into(),
            account_ids: vec!["account".into()],
            local_operator: "local".into(),
            purpose: "review".into(),
            retention_policy: "local".into(),
        };
        let allowed = [LocalAction::InspectStatus];
        assert!(scope_matches(
            "principal",
            "candidate",
            "manifest",
            &allowed,
            &scope,
            LocalAction::InspectStatus
        ));
        for (principal, candidate, manifest) in [
            ("other", "candidate", "manifest"),
            ("principal", "other", "manifest"),
            ("principal", "candidate", "other"),
        ] {
            assert!(!scope_matches(
                principal,
                candidate,
                manifest,
                &allowed,
                &scope,
                LocalAction::InspectStatus
            ));
        }
        assert!(!scope_matches(
            "principal",
            "candidate",
            "manifest",
            &allowed,
            &scope,
            LocalAction::ProveLocally
        ));
        assert!(!previously_inspected(&[], &scope));
        assert!(!previously_inspected(
            &[(scope.clone(), LocalAction::ProveLocally)],
            &scope
        ));
        let approved = [(scope.clone(), LocalAction::InspectStatus)];
        assert!(previously_inspected(&approved, &scope));
        let mut altered = scope.clone();
        altered.account_ids.push("other".into());
        assert!(!previously_inspected(&approved, &altered));
        altered = scope.clone();
        altered.artifact_digest = "substituted".into();
        assert!(!previously_inspected(&approved, &altered));
        altered = scope.clone();
        altered.retention_policy = "indefinite".into();
        assert!(!previously_inspected(&approved, &altered));
    }
}
