//! Separate native permissions for usable signed artifacts, extraction and exact
//! local submission handoff. None of these privacy gates grants spending authority.
use super::*;
use wholepact_protocol::authorization::retention::{
    SignedRetentionConsent, SignedRetentionScope,
    transaction::{
        RecoveryAction, TransactionRecoveryConsent, TransactionRecoveryScope,
        TransactionRetentionConsent, TransactionRetentionScope,
        submission_handoff::{SubmissionHandoffConsent, SubmissionHandoffScope},
    },
};

pub(crate) struct NativeRetentionConsent {
    principal: String,
    candidate: String,
    manifest: String,
    job: String,
    accounts: std::collections::BTreeSet<String>,
    terminal: Terminal,
    held: Held,
    approved: Mutex<BTreeMap<&'static str, String>>,
}
impl Authority {
    pub(crate) fn retention_consent(
        &self,
        principal: &str,
        candidate: &str,
        manifest: &str,
        job: &str,
        accounts: std::collections::BTreeSet<String>,
    ) -> Result<NativeRetentionConsent> {
        self.principal(principal)?;
        if accounts.is_empty() || accounts.len() > 32 {
            return Err(Error::Invalid);
        }
        Ok(NativeRetentionConsent {
            principal: principal.into(),
            candidate: candidate.into(),
            manifest: manifest.into(),
            job: job.into(),
            accounts,
            terminal: self.terminal.clone(),
            held: self
                .fence
                .acquire(now()?.checked_add(900).ok_or(Error::Invalid)?)?,
            approved: Mutex::new(BTreeMap::new()),
        })
    }
}
impl NativeRetentionConsent {
    fn matches(&self, scope: &SignedRetentionScope) -> bool {
        let c = &scope.context;
        c.principal_id == self.principal
            && c.candidate_id == self.candidate
            && c.manifest_digest == self.manifest
            && c.proof_job_id == self.job
            && c.account_ids.len() == self.accounts.len()
            && c.account_ids
                .iter()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>()
                == self.accounts
    }
    fn approve(&self, action: &'static str, detail: impl serde::Serialize) -> bool {
        if self.held.check().is_err() {
            return false;
        }
        let Ok(encoded) = serde_json::to_string_pretty(&detail) else {
            return false;
        };
        let Ok(mut approved) = self.approved.lock() else {
            return false;
        };
        if let Some(prior) = approved.get(action) {
            return prior == &encoded && self.held.check().is_ok();
        }
        if self.terminal.confirm(&format!("Approve {action} for this EXACT scope?\n{encoded}\nUsable spend signatures or transaction bytes remain in encrypted local journals. This is separate from original signer approval and does not itself authorize network submission. A failed or interrupted operation can leave durable intent; preserve the exact original keys and journals. Scope changes require a new command and approval. Permission ends with this command, lock/revoke or 15 minutes.")).is_err() || self.held.check().is_err() { return false; }
        approved.insert(action, encoded);
        true
    }
}
impl SignedRetentionConsent for NativeRetentionConsent {
    fn permits(&self, scope: &SignedRetentionScope) -> bool {
        self.matches(scope) && self.approve("retain exact usable signatures", scope)
    }
}
impl TransactionRetentionConsent for NativeRetentionConsent {
    fn permits(&self, scope: &TransactionRetentionScope) -> bool {
        SignedRetentionConsent::permits(self, &scope.signed_scope)
            && self.approve("extract/read and retain exact complete transaction", scope)
    }
}
impl SubmissionHandoffConsent for NativeRetentionConsent {
    fn permits(&self, scope: &SubmissionHandoffScope<'_>) -> bool {
        TransactionRetentionConsent::permits(self, scope.retained) && self.approve("copy exact retained transaction to the named local submission journal", serde_json::json!({
            "retained": scope.retained, "descriptor": scope.descriptor, "backend": scope.backend, "destination_journal_identity": scope.destination_journal_identity,
        }))
    }
}

/// Private record reconstruction can inspect only the already retained exact
/// checkpoint. It cannot restore copies or create a new extraction intent.
impl TransactionRecoveryConsent for NativeRetentionConsent {
    fn permits(&self, scope: &TransactionRecoveryScope<'_>) -> bool {
        let Some(action) = recovery_approval_action(scope) else {
            return false;
        };
        self.matches(&scope.retention.signed_scope) && self.approve(action, scope)
    }
}

fn recovery_approval_action(scope: &TransactionRecoveryScope<'_>) -> Option<&'static str> {
    if scope.action != RecoveryAction::InspectExistingIntent {
        return None;
    }
    // The journal first requests permission to inspect the original intent,
    // then separately presents its verified exact result. Each stage retains
    // its whole scope; neither approval can silently widen or change the other.
    match (scope.transaction_digest, scope.txid) {
        (None, None) => Some("inspect existing exact transaction intent"),
        (Some(digest), Some(txid)) if recovery_digest(digest) && recovery_digest(txid) => {
            Some("inspect existing exact retained transaction result")
        }
        _ => None,
    }
}

fn recovery_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wholepact_protocol::authorization::retention::SignedCandidateContext;

    // Synthetic scope/cache models only. No journal, signed artifact, proof,
    // signer socket or functioning native terminal is constructed or exercised.
    fn fixture() -> (NativeRetentionConsent, TransactionRetentionScope) {
        let scope = TransactionRetentionScope {
            signed_scope: SignedRetentionScope {
                context: SignedCandidateContext {
                    principal_id: "synthetic-principal".into(),
                    candidate_id: "synthetic-candidate".into(),
                    proof_job_id: "synthetic-job".into(),
                    checkpoint_scope_digest: "01".repeat(32),
                    proved_artifact_digest: "02".repeat(32),
                    manifest_digest: "03".repeat(32),
                    review_binding: "04".repeat(32),
                    delivery_provenance_digest: "05".repeat(32),
                    account_ids: vec!["synthetic-account".into()],
                    local_operator: "synthetic-operator".into(),
                    purpose: "No-artifact consent cache test".into(),
                    retention_policy: "No artifact is retained".into(),
                },
                signature_set_digest: "06".repeat(32),
            },
            signed_result_id: format!("signed-{}", "07".repeat(32)),
            signed_request_digest: "08".repeat(32),
            signed_candidate_digest: "09".repeat(32),
        };
        let context = &scope.signed_scope.context;
        let consent = NativeRetentionConsent {
            principal: context.principal_id.clone(),
            candidate: context.candidate_id.clone(),
            manifest: context.manifest_digest.clone(),
            job: context.proof_job_id.clone(),
            accounts: context.account_ids.iter().cloned().collect(),
            terminal: Terminal::disconnected_for_test(),
            held: Arc::new(Fence::default())
                .acquire(now().unwrap() + 900)
                .unwrap(),
            approved: Mutex::new(BTreeMap::new()),
        };
        (consent, scope)
    }

    fn model_cached_scope(consent: &NativeRetentionConsent, scope: &TransactionRecoveryScope<'_>) {
        consent.approved.lock().unwrap().insert(
            recovery_approval_action(scope).unwrap(),
            serde_json::to_string_pretty(scope).unwrap(),
        );
    }

    #[test]
    fn recovery_intent_and_exact_result_require_distinct_unchanged_approvals() {
        let (consent, scope) = fixture();
        let digest = "10".repeat(32);
        let txid = "11".repeat(32);
        let mut request = TransactionRecoveryScope {
            retention: &scope,
            action: RecoveryAction::InspectExistingIntent,
            transaction_digest: None,
            txid: None,
        };
        // A disconnected terminal cannot supply either fresh decision.
        assert!(!TransactionRecoveryConsent::permits(&consent, &request));
        model_cached_scope(&consent, &request);
        assert!(TransactionRecoveryConsent::permits(&consent, &request));

        request.transaction_digest = Some(&digest);
        request.txid = Some(&txid);
        assert!(!TransactionRecoveryConsent::permits(&consent, &request));
        model_cached_scope(&consent, &request);
        assert!(TransactionRecoveryConsent::permits(&consent, &request));
        let changed = "12".repeat(32);
        request.transaction_digest = Some(&changed);
        assert!(!TransactionRecoveryConsent::permits(&consent, &request));
        request.transaction_digest = Some(&digest);
        request.txid = Some(&changed);
        assert!(!TransactionRecoveryConsent::permits(&consent, &request));
        request.txid = Some(&txid);
        let (_, mut other_scope) = fixture();
        other_scope.signed_request_digest = changed.clone();
        request.retention = &other_scope;
        assert!(!TransactionRecoveryConsent::permits(&consent, &request));
        request.retention = &scope;
        request.transaction_digest = None;
        request.txid = None;
        assert!(TransactionRecoveryConsent::permits(&consent, &request));
    }

    #[test]
    fn recovery_rejects_partial_malformed_or_broader_result_scopes() {
        let (_, scope) = fixture();
        let digest = "10".repeat(32);
        let mut request = TransactionRecoveryScope {
            retention: &scope,
            action: RecoveryAction::InspectExistingIntent,
            transaction_digest: None,
            txid: None,
        };
        for (transaction_digest, txid) in [
            (Some(digest.as_str()), None),
            (None, Some(digest.as_str())),
            (Some("bad"), Some(digest.as_str())),
            (Some(digest.as_str()), Some("BAD")),
        ] {
            request.transaction_digest = transaction_digest;
            request.txid = txid;
            assert!(recovery_approval_action(&request).is_none());
        }
        request.transaction_digest = Some(&digest);
        request.txid = Some(&digest);
        for action in [
            RecoveryAction::ReadRetainedCopy,
            RecoveryAction::RestoreExactRetainedCopy,
        ] {
            request.action = action;
            assert!(recovery_approval_action(&request).is_none());
        }
    }

    #[test]
    fn cached_recovery_scopes_do_not_bypass_expiry_or_revocation() {
        for revoke in [false, true] {
            let (mut consent, scope) = fixture();
            let request = TransactionRecoveryScope {
                retention: &scope,
                action: RecoveryAction::InspectExistingIntent,
                transaction_digest: None,
                txid: None,
            };
            model_cached_scope(&consent, &request);
            assert!(TransactionRecoveryConsent::permits(&consent, &request));
            if revoke {
                consent.held.fence.state.lock().unwrap().blocked = true;
            } else {
                consent.held.expires = 0;
            }
            assert!(!TransactionRecoveryConsent::permits(&consent, &request));
        }
    }
}

/// Closed exact review cache for the prompt-free interval after the final Host
/// dispatch decision. No terminal, approval method or mutable cache is retained.
/// This remains only local artifact/handoff permission, never spending authority.
pub(crate) struct FrozenNativeRetentionConsentV1 {
    principal: String,
    candidate: String,
    manifest: String,
    job: String,
    accounts: std::collections::BTreeSet<String>,
    held: Held,
    approved: BTreeMap<&'static str, String>,
}
impl NativeRetentionConsent {
    pub(crate) fn freeze_for_dispatch(self) -> Result<FrozenNativeRetentionConsentV1> {
        self.held.check()?;
        let approved = self.approved.into_inner().map_err(|_| Error::Permission)?;
        for action in [
            "retain exact usable signatures",
            "extract/read and retain exact complete transaction",
            "copy exact retained transaction to the named local submission journal",
        ] {
            if !approved.contains_key(action) {
                return Err(Error::Permission);
            }
        }
        Ok(FrozenNativeRetentionConsentV1 {
            principal: self.principal,
            candidate: self.candidate,
            manifest: self.manifest,
            job: self.job,
            accounts: self.accounts,
            held: self.held,
            approved,
        })
    }
}
impl FrozenNativeRetentionConsentV1 {
    fn matches(&self, scope: &SignedRetentionScope) -> bool {
        let c = &scope.context;
        c.principal_id == self.principal
            && c.candidate_id == self.candidate
            && c.manifest_digest == self.manifest
            && c.proof_job_id == self.job
            && c.account_ids.len() == self.accounts.len()
            && c.account_ids
                .iter()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>()
                == self.accounts
    }
    fn approved(&self, action: &'static str, detail: impl serde::Serialize) -> bool {
        self.held.check().is_ok()
            && serde_json::to_string_pretty(&detail)
                .ok()
                .is_some_and(|detail| self.approved.get(action) == Some(&detail))
            && self.held.check().is_ok()
    }
    pub(crate) fn valid_until_unix_seconds(&self) -> u64 {
        self.held.expires
    }
}
impl SignedRetentionConsent for FrozenNativeRetentionConsentV1 {
    fn permits(&self, scope: &SignedRetentionScope) -> bool {
        self.matches(scope) && self.approved("retain exact usable signatures", scope)
    }
}
impl TransactionRetentionConsent for FrozenNativeRetentionConsentV1 {
    fn permits(&self, scope: &TransactionRetentionScope) -> bool {
        SignedRetentionConsent::permits(self, &scope.signed_scope)
            && self.approved("extract/read and retain exact complete transaction", scope)
    }
}
impl SubmissionHandoffConsent for FrozenNativeRetentionConsentV1 {
    fn permits(&self, scope: &SubmissionHandoffScope<'_>) -> bool {
        TransactionRetentionConsent::permits(self, scope.retained)
            && self.approved("copy exact retained transaction to the named local submission journal", serde_json::json!({
                "retained": scope.retained, "descriptor": scope.descriptor, "backend": scope.backend,
                "destination_journal_identity": scope.destination_journal_identity,
            }))
    }
}

/// One exact prepared signature-intake scope, with no terminal and no
/// transaction/extraction/handoff trait. Prepared before the short Return lease.
pub(crate) struct FrozenNativeSignedIntakeConsentV1 {
    held: Held,
    scope: String,
}
impl NativeRetentionConsent {
    pub(crate) fn freeze_for_signed_intake(self) -> Result<FrozenNativeSignedIntakeConsentV1> {
        self.held.check()?;
        let mut approved = self.approved.into_inner().map_err(|_| Error::Permission)?;
        if approved.len() != 1 {
            return Err(Error::Permission);
        }
        let scope = approved
            .remove("retain exact usable signatures")
            .ok_or(Error::Permission)?;
        Ok(FrozenNativeSignedIntakeConsentV1 {
            held: self.held,
            scope,
        })
    }
}
impl SignedRetentionConsent for FrozenNativeSignedIntakeConsentV1 {
    fn permits(&self, scope: &SignedRetentionScope) -> bool {
        self.held.check().is_ok()
            && serde_json::to_string_pretty(scope).ok().as_ref() == Some(&self.scope)
            && self.held.check().is_ok()
    }
}
