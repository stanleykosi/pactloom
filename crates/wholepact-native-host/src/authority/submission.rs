//! Exact native backend disclosure and production dispatch authority.
//! Native consent never substitutes for verified original transaction evidence or
//! a fresh independently authenticated witness admission for each account.
use super::*;
use wholepact_chain::{
    BackendIdentity, ChainError, SubmissionAuthority, SubmissionDescriptor, SubmissionPermit,
    SubmissionReview,
};
use wholepact_engine::signature_intake::VerifiedCandidateSubmission;
use wholepact_signer::authority_bridge::{
    dispatch_ipc::{BackendDisclosure as SignerBackendDisclosure, SignerDispatchAdmission},
    ipc::OriginalHistoryLease,
};

#[derive(serde::Serialize)]
struct BackendDisclosure<'a> {
    schema_version: u16,
    profile_id: &'a str,
    principal_id: &'a str,
    agreement_id: &'a str,
    submission_journal_identity: &'a str,
    descriptor: &'a SubmissionDescriptor,
    backend: &'a BackendIdentity,
    purpose: &'static str,
    confidence: &'static str,
    minimum_expiry_margin_blocks: u32,
}
/// Session-only consent issued by the actual controlling native terminal. No
/// public constructor or deserialization permits an HTTP approval boolean.
pub(crate) struct NativeSubmissionConsent {
    disclosure: SignerBackendDisclosure,
    descriptor: SubmissionDescriptor,
    journal: String,
    backend: BackendIdentity,
    digest: String,
    minimum_expiry_margin_blocks: u32,
    held: Held,
}
impl Authority {
    pub(crate) fn approve_exact_submission(
        &self,
        verified: &VerifiedCandidateSubmission,
        journal: &str,
        backend: &BackendIdentity,
        minimum_expiry_margin_blocks: u32,
    ) -> Result<NativeSubmissionConsent> {
        let context = verified.context();
        self.principal(&context.principal_id)?;
        if !(1..=100).contains(&minimum_expiry_margin_blocks)
            || backend.trust_profile != "single_tls_provider_report_not_consensus"
            || journal.is_empty()
        {
            return Err(Error::Permission);
        }
        let disclosure = BackendDisclosure {
            schema_version: 1,
            profile_id: &self.profile,
            principal_id: &context.principal_id,
            agreement_id: verified.agreement_id(),
            submission_journal_identity: journal,
            descriptor: verified.descriptor(),
            backend,
            purpose: "submit_exact_retained_transaction",
            confidence: "single_tls_provider_report_not_consensus",
            minimum_expiry_margin_blocks,
        };
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:submission-backend-disclosure:v1",
            &disclosure,
        )
        .map_err(|_| Error::Invalid)?;
        self.terminal.confirm(&format!(
            "Authorize ONE explicit submission attempt of the exact retained transaction.\n{}\nEffects commitment: {}\nDisclosure binding: {}\nThe named provider receives complete signed transaction bytes and connection metadata. It may retain/link them. This trusted single-provider observation is not independent consensus or a global unspentness guarantee. A timeout or rejection cannot recall signatures or clear exposure; only the same retained bytes may be retried after fresh approval. This approval expires in two minutes and ends on lock/revoke. Each original account also requires current independent witness admission.",
            serde_json::to_string_pretty(&disclosure)?, verified.effects_digest(), digest,
        ))?;
        let signer_disclosure: SignerBackendDisclosure =
            serde_json::from_value(serde_json::to_value(&disclosure)?)?;
        if signer_disclosure.digest().map_err(|_| Error::Invalid)? != digest {
            return Err(Error::Invalid);
        }
        let held = self
            .fence
            .acquire(now()?.checked_add(120).ok_or(Error::Invalid)?)?;
        Ok(NativeSubmissionConsent {
            disclosure: signer_disclosure,
            descriptor: verified.descriptor().clone(),
            journal: journal.into(),
            backend: backend.clone(),
            digest,
            minimum_expiry_margin_blocks,
            held,
        })
    }
}
impl NativeSubmissionConsent {
    /// Non-secret exact terms for independently approved signer dispatch. The
    /// descriptor itself grants no authority; only the live IPC receipt does.
    pub(crate) fn signer_disclosure(&self) -> Result<SignerBackendDisclosure> {
        self.held.check()?;
        Ok(self.disclosure.clone())
    }
    pub(crate) fn disclosure_digest(&self) -> &str {
        &self.digest
    }
    fn check(&self, review: &SubmissionReview<'_>) -> std::result::Result<(), ChainError> {
        self.held
            .check()
            .map_err(|_| ChainError::SubmissionNotAuthorized)?;
        if review.descriptor != &self.descriptor
            || review.journal_identity != self.journal
            || review.backend != &self.backend
            || review.context.source() != &self.backend
            || review.descriptor.network != "testnet"
            || review.descriptor.consensus_branch_id != wholepact_chain::NU7_BRANCH_ID
        {
            return Err(ChainError::SubmissionNotAuthorized);
        }
        review.context.check_fresh_at(review.now_unix_seconds)?;
        if review.context.tip().height < wholepact_chain::NU7_ACTIVATION_HEIGHT
            || review
                .context
                .tip()
                .height
                .checked_add(u64::from(self.minimum_expiry_margin_blocks))
                .is_none_or(|height| height > u64::from(review.descriptor.expiry_height))
        {
            return Err(ChainError::SubmissionExpiryMargin);
        }
        Ok(())
    }
}

/// Owns a genuine native fence and borrows the sealed engine predecessor and all
/// independently authenticated signer/witness evidence. Its one permit is held
/// until the orchestrator has persisted the attempt outcome.
pub(crate) struct ProductionSubmissionAuthority<'a> {
    verified: &'a VerifiedCandidateSubmission,
    originals: &'a [OriginalHistoryLease<'a>],
    admissions: &'a [SignerDispatchAdmission<'a>],
    consent: &'a NativeSubmissionConsent,
    used: bool,
}
pub(crate) struct ProductionSubmissionPermit<'a> {
    verified: &'a VerifiedCandidateSubmission,
    originals: &'a [OriginalHistoryLease<'a>],
    admissions: &'a [SignerDispatchAdmission<'a>],
    consent: &'a NativeSubmissionConsent,
}
impl<'a> ProductionSubmissionAuthority<'a> {
    pub(crate) fn new(
        verified: &'a VerifiedCandidateSubmission,
        originals: &'a [OriginalHistoryLease<'a>],
        admissions: &'a [SignerDispatchAdmission<'a>],
        consent: &'a NativeSubmissionConsent,
    ) -> Self {
        Self {
            verified,
            originals,
            admissions,
            consent,
            used: false,
        }
    }
}
impl<'a> SubmissionAuthority for ProductionSubmissionAuthority<'a> {
    type Permit = ProductionSubmissionPermit<'a>;
    fn authorize(
        &mut self,
        review: &SubmissionReview<'_>,
    ) -> std::result::Result<Self::Permit, ChainError> {
        if self.used {
            return Err(ChainError::SubmissionNotAuthorized);
        }
        let mut permit = ProductionSubmissionPermit {
            verified: self.verified,
            originals: self.originals,
            admissions: self.admissions,
            consent: self.consent,
        };
        permit.check_current(review)?;
        self.used = true;
        Ok(permit)
    }
}
impl SubmissionPermit for ProductionSubmissionPermit<'_> {
    fn check_current(
        &mut self,
        review: &SubmissionReview<'_>,
    ) -> std::result::Result<(), ChainError> {
        let denied = || ChainError::SubmissionNotAuthorized;
        self.consent.check(review)?;
        let expected = self.verified.descriptor();
        let context = self.verified.context();
        if review.descriptor != expected
            || self.originals.is_empty()
            || self.originals.len() != context.account_ids.len()
            || self.admissions.len() != self.originals.len()
        {
            return Err(denied());
        }
        let mut seen = std::collections::BTreeSet::new();
        let now_ms = review
            .now_unix_seconds
            .checked_mul(1000)
            .ok_or_else(denied)?;
        for original in self.originals {
            original.check_current().map_err(|_| denied())?;
            let e = original.evidence();
            let t = e.consent.terms();
            if !seen.insert(t.account_id.as_str())
                || !context.account_ids.contains(&t.account_id)
                || t.agreement_id != self.verified.agreement_id()
                || t.obligation_id != expected.obligation_id
                || t.proposal_id != context.candidate_id
                || t.manifest_digest != context.manifest_digest
                || t.artifact_digest != context.proved_artifact_digest
                || t.review_binding != context.review_binding
                || t.effects_digest != self.verified.effects_digest()
                || t.transaction_expiry_height != expected.expiry_height
                || t.account_id != e.enrollment.account_id()
                || t.enrollment_ref != e.enrollment.reference()
                || t.accepted_manifest_ref != e.accepted_manifest.reference()
                || e.release_intent.original_consent_ref() != e.consent.reference()
                || e.retained_result.as_ref().is_none_or(|result| {
                    result.authorization_id != t.authorization_id
                        || result.original_consent_ref != e.consent.reference()
                })
            {
                return Err(denied());
            }
            let admission = self
                .admissions
                .iter()
                .find(|a| a.descriptor().request.account_id == t.account_id)
                .ok_or_else(denied)?;
            let d = admission.descriptor();
            let request = &d.request;
            let reserved = &d.reservation;
            let r = &reserved.request;
            if request.final_transaction_digest != expected.bytes_sha256
                || request.final_transaction_id != expected.transaction_id
                || request.backend_disclosure_digest != self.consent.digest
                || request.transaction_expiry_height != expected.expiry_height
                || now_ms < request.reviewed_at_ms
                || now_ms >= request.admission_expires_at_ms
                || request.reservation_operation_id != r.operation_id
                || request.reservation_request_digest != reserved.request_digest
                || r.authorization_id != t.authorization_id
                || r.original_consent_ref != e.consent.reference()
                || r.obligation_id != t.obligation_id
                || r.manifest_digest != t.manifest_digest
                || r.effects_digest != t.effects_digest
                || r.artifact_digest != t.artifact_digest
                || r.review_binding != t.review_binding
                || r.maximum_debit_zatoshis != t.maximum_debit_zatoshis
                || r.transaction_expiry_height != t.transaction_expiry_height
            {
                return Err(denied());
            }
            // A witness admission is a linearized durable intent. This check
            // does not claim remote revocation can recall an admitted packet.
            admission.matches_request(request).map_err(|_| denied())?;
            original.check_current().map_err(|_| denied())?;
        }
        self.consent.check(review)
    }
}

impl Authority {
    /// Exact journal metadata disclosure only. This private native owner cannot
    /// issue a dispatch admission, query a provider or restore missing bytes.
    pub(crate) fn with_submission_status_read<R>(
        &self,
        principal: &str,
        request: &wholepact_engine::native_dispatch_requests::NativeDispatchRequestView,
        journal: &str,
        read: impl FnOnce() -> Result<R>,
    ) -> Result<R> {
        self.principal(principal)?;
        if !submission_status_binding(
            request.state,
            request.submission_journal_identity.as_deref(),
            journal,
        ) {
            return Err(Error::Permission);
        }
        self.terminal.confirm(&format!("Read the ORIGINAL encrypted submission journal for this exact retained request and disclose only its historical intent/attempt metadata to this authenticated client?\n{}\nThis may internally read retained transaction bytes to validate journal identity; those bytes are not returned. No provider query or broadcast occurs. Missing rows and stale provider acknowledgements cannot prove non-delivery, settlement or permit a retry. Permission ends with this command or lock/revoke.", serde_json::to_string_pretty(request)?))?;
        let held = self
            .fence
            .acquire(now()?.checked_add(120).ok_or(Error::Invalid)?)?;
        held.check()?;
        let result = read()?;
        held.check()?;
        Ok(result)
    }
}

fn submission_status_binding(
    state: wholepact_engine::native_requests::NativeRequestState,
    selected: Option<&str>,
    journal: &str,
) -> bool {
    state == wholepact_engine::native_requests::NativeRequestState::AttemptStarted
        && !journal.is_empty()
        && selected == Some(journal)
}
impl Authority {
    pub(crate) fn with_reconciliation_status_read<R>(
        &self,
        principal: &str,
        request: &wholepact_engine::native_reconciliation_requests::NativeReconciliationRequestView,
        journal: &str,
        read: impl FnOnce() -> Result<R>,
    ) -> Result<R> {
        self.principal(principal)?;
        if !submission_status_binding(
            request.state,
            Some(&request.submission_journal_identity),
            journal,
        ) {
            return Err(Error::Permission);
        }
        self.terminal.confirm(&format!("Read the original encrypted journal's historical reconciliation metadata for this EXACT request and disclose it to its authenticated client?\n{}\nNo provider query or positive resolution occurs. Reports are restored as stale. Historical successful resolution means only the named original local commit happened; it never proves current canonicality, complete exposure or safe replacement. Missing metadata stays unknown. Private bytes may be read internally to validate the journal, but are not returned.", serde_json::to_string_pretty(request)?))?;
        let held = self
            .fence
            .acquire(now()?.checked_add(120).ok_or(Error::Invalid)?)?;
        held.check()?;
        let result = read()?;
        held.check()?;
        Ok(result)
    }
}

#[cfg(test)]
mod dispatch_status_tests {
    use super::*;
    use wholepact_engine::native_requests::NativeRequestState;
    #[test]
    fn local_status_requires_started_original_and_same_selected_journal() {
        for state in [NativeRequestState::Queued, NativeRequestState::Withdrawn] {
            assert!(!submission_status_binding(
                state,
                Some("original"),
                "original"
            ));
        }
        assert!(!submission_status_binding(
            NativeRequestState::AttemptStarted,
            None,
            "original"
        ));
        assert!(!submission_status_binding(
            NativeRequestState::AttemptStarted,
            Some("other"),
            "original"
        ));
        assert!(!submission_status_binding(
            NativeRequestState::AttemptStarted,
            Some(""),
            ""
        ));
        assert!(submission_status_binding(
            NativeRequestState::AttemptStarted,
            Some("original"),
            "original"
        ));
    }
}
