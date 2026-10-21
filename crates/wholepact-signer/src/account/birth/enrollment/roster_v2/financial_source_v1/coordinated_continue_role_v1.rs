//! Read-only actual original19 facts for the same retained coordinated role.
//! No native session, action, source owner or journal handle is manufactured.
use super::*;
use wholepact_financial_coordinator_origin::SignerFinancialReadFinalV1;

impl PreparedOriginalFinancialSourceV1 {
    pub(crate) fn coordinated_continue_principal_v1(
        &self,
        terms: &FinancialContinuationTermsV1,
        original_host: &crate::native_peer::PeerProcess,
        read: &SignerFinancialReadFinalV1,
    ) -> Result<String> {
        let check_bounds = || -> Result<()> {
            self.check_continue_preparation_read_v2(terms, original_host, read)?;
            self.lifetime.check_connected()?;
            original_host.check_alive()?;
            if !matches!(
                &self.lifetime,
                OriginalFinancialCustodyLifetimeV1::Coordinated(_)
            ) || terms.valid_until_ms != self.original_ceiling_ms
                || Instant::now() >= self.original_deadline
            {
                return Err(Error::ReviewMismatch);
            }
            let now = u64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| Error::Locked)?
                    .as_millis(),
            )
            .map_err(|_| Error::Locked)?;
            terms.require_live(now).map_err(|_| Error::Locked)
        };
        check_bounds()?;
        self.check_coordinated_public_custody_v2(original_host)?;
        check_bounds()?;
        let principal =
            {
                let binding = self.binding.lock().map_err(|_| Error::Locked)?;
                check_bounds()?;
                match &self.journal {
                    OriginalJournalV1::Before(journal) => journal
                        .coordinated_continue_principal_v1(&binding, terms, original_host, read)?,
                    OriginalJournalV1::Financial(_) => return Err(Error::RecoveryRequired),
                }
            };
        check_bounds()?;
        self.check_coordinated_public_custody_v2(original_host)?;
        check_bounds()?;
        Ok(principal)
    }

    /// Zero-wait token/data checks only, safe while the actual binding is held.
    fn check_continue_preparation_read_v2(
        &self,
        terms: &FinancialContinuationTermsV1,
        original_host: &crate::native_peer::PeerProcess,
        read: &SignerFinancialReadFinalV1,
    ) -> Result<()> {
        read.check_current()?;
        let facts = &read.presentation().facts;
        if read.original_source_deadline() != self.original_deadline
            || facts.source_identity_digest != self.identity
            || facts.source_expires_at_ms != self.original_ceiling_ms
            || facts.terms_digest
                != terms
                    .intent_terms_digest()
                    .map_err(|_| Error::InvalidData)?
            || facts.original_host_process_instance != original_host.instance()
        {
            return Err(Error::ReviewMismatch);
        }
        read.check_current()?;
        Ok(())
    }

    /// The new workflow's read-only preparation requires the actual unconsumed
    /// v2 Read Final throughout. Legacy inert preparation/commit stay unchanged.
    pub(crate) fn prepare_coordinated_continuation_from_read_v2(
        &self,
        terms: FinancialContinuationTermsV1,
        history: wholepact_authority::ReconciledAuthorityHistory,
        original_host: crate::native_peer::PeerProcess,
        review: crate::consent_journal::CoordinatedContinueReviewDataV1,
        original_review_deadline: Instant,
        read: &SignerFinancialReadFinalV1,
    ) -> Result<crate::consent_journal::PreparedCoordinatedFinancialContinuationV1> {
        self.check_continue_preparation_read_v2(&terms, &original_host, read)?;
        self.check_coordinated_public_custody_v2(&original_host)?;
        self.check_continue_preparation_read_v2(&terms, &original_host, read)?;
        let original_host_check = original_host.clone();
        let prepared = {
            let binding = self.binding.lock().map_err(|_| Error::Locked)?;
            self.check_continue_preparation_read_v2(&terms, &original_host, read)?;
            match &self.journal {
                OriginalJournalV1::Before(journal) => journal
                    .prepare_coordinated_financial_continuation_from_read_v2(
                        &binding,
                        terms,
                        history,
                        original_host,
                        review,
                        self.original_ceiling_ms,
                        self.original_deadline,
                        original_review_deadline,
                        read,
                    )?,
                OriginalJournalV1::Financial(_) => return Err(Error::RecoveryRequired),
            }
        };
        read.check_current()?;
        self.check_coordinated_public_custody_v2(&original_host_check)?;
        read.check_current()?;
        prepared.check_retained_preparation()?;
        read.check_current()?;
        Ok(prepared)
    }
}

impl PreparedOriginalFinancialSourceV1 {
    /// Workflow Ready audits only under this concrete Arm. The surrounding
    /// identity/peer checks do not borrow generic custody as read permission.
    pub(crate) fn check_coordinated_continuation_ready_workflow_v2(
        &self,
        host: &crate::native_peer::PeerProcess,
        presented: &crate::consent_journal::PresentedCoordinatedFinancialContinuationV1,
        arm: &wholepact_financial_coordinator_origin::SignerContinueArmV1,
    ) -> Result<()> {
        presented.check_arm(arm)?;
        self.check_coordinated_public_custody_v2(host)?;
        presented.check_source(
            &self.identity,
            self.original_deadline,
            self.original_ceiling_ms,
        )?;
        presented.check_arm(arm)?;
        // File content checks are also covered by this exact live Arm.
        self.retained.check()?;
        presented.check_arm(arm)?;
        if publication::read_commit(&self.retained)? != self.original_commit {
            return Err(Error::ReviewMismatch);
        }
        presented.check_arm(arm)?;
        {
            let binding = self.binding.lock().map_err(|_| Error::Locked)?;
            presented.check_arm(arm)?;
            match &self.journal {
                OriginalJournalV1::Before(journal) => journal
                    .check_coordinated_financial_preparation_workflow_v2(
                        &binding, presented, arm,
                    )?,
                OriginalJournalV1::Financial(_) => return Err(Error::RecoveryRequired),
            }
        }
        presented.check_arm(arm)?;
        self.check_coordinated_public_custody_v2(host)?;
        presented.check_arm(arm)?;
        Ok(())
    }

    /// Same actual source, actual recipient and one Final. The successful actual
    /// transaction's sealed evidence supplies the post-commit binding; no new
    /// semantic reread is smuggled through custody after the grant is consumed.
    pub(crate) fn commit_coordinated_continuation_workflow_v2(
        self,
        host: &crate::native_peer::PeerProcess,
        presented: crate::consent_journal::PresentedCoordinatedFinancialContinuationV1,
        final_admission: wholepact_financial_coordinator_origin::SignerContinueFinalV1,
    ) -> std::result::Result<
        (Self, PendingFinancialContinuationAdmissionV1),
        crate::consent_journal::CoordinatedContinuationCommitFailureV1,
    > {
        use crate::consent_journal::CoordinatedContinuationCommitFailureV1 as Failure;
        let check = || -> Result<()> {
            presented.check_final(&final_admission)?;
            self.lifetime.check_connected()?;
            Ok(())
        };
        check().map_err(Failure::before_effect)?;
        self.check_coordinated_public_custody_v2(host)
            .map_err(Failure::before_effect)?;
        check().map_err(Failure::before_effect)?;
        presented
            .check_source(
                &self.identity,
                self.original_deadline,
                self.original_ceiling_ms,
            )
            .map_err(|e| Failure::before_effect(e.into()))?;
        self.retained.check().map_err(Failure::before_effect)?;
        check().map_err(Failure::before_effect)?;
        if publication::read_commit(&self.retained).map_err(Failure::before_effect)?
            != self.original_commit
        {
            return Err(Failure::before_effect(Error::ReviewMismatch));
        }
        check().map_err(Failure::before_effect)?;
        let Self {
            retained,
            original_commit,
            original_disclosure,
            journal,
            binding,
            identity,
            recipient,
            immutable,
            lifetime,
            original_ceiling_ms,
            original_deadline,
        } = self;
        let OriginalJournalV1::Before(journal) = journal else {
            return Err(Failure::before_effect(Error::RecoveryRequired));
        };
        let (journal, pending) =
            FinancialConsentJournalV1::transition_coordinated_original_workflow_v2(
                journal,
                binding
                    .into_inner()
                    .map_err(|_| Failure::before_effect(Error::Locked))?,
                presented,
                final_admission,
            )?;
        lifetime
            .check_connected()
            .map_err(Failure::after_commit_attempt)?;
        let binding = journal
            .binding_from_coordinated_commit_v2(&pending, &identity)
            .map_err(|e| Failure::after_commit_attempt(e.into()))?;
        lifetime
            .check_connected()
            .map_err(Failure::after_commit_attempt)?;
        let result = Self {
            retained,
            original_commit,
            original_disclosure,
            journal: OriginalJournalV1::Financial(journal),
            identity: binding.identity_digest().into(),
            binding: std::sync::Mutex::new(binding),
            recipient,
            immutable,
            lifetime,
            original_ceiling_ms,
            original_deadline,
        };
        result
            .check_coordinated_public_custody_v2(host)
            .map_err(Failure::after_commit_attempt)?;
        Ok((result, pending))
    }
}
