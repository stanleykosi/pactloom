//! Native ONE-record authority plus original-namespace durable serving selection.
//! Requests/configuration are data. Only the focused native Window decision and
//! the independently authenticated original owner-mTLS peer can commit a record.
use crate::{
    native_witness_owner::{NativeFinancialContinuationDecisionV1, NativeWorkerLease},
    witness_locator::{NamespaceOpenInput, open_born_history},
    *,
};
use std::sync::Arc;

pub(crate) struct FinancialContinuationProposalV1 {
    journal: Arc<AuthorityJournal>,
    expected: OwnerControlRequest,
    disclosure: WitnessDisclosureDescriptor,
}
pub(crate) struct NativeFinancialContinuationSourceV1 {
    proposal: FinancialContinuationProposalV1,
    lease: Option<NativeWorkerLease>,
    committed: Option<AccountSnapshot>,
    #[cfg(feature = "synthetic-qualification")]
    admission_observer:
        Option<crate::transport::admission_diagnostics_v1::AdmissionWitnessObserverV1>,
}
impl FinancialContinuationProposalV1 {
    // Crate-private retained facts for the separate nominal coordinated adapter.
    // No consent, native lease, or effect can be constructed from these values.
    #[cfg(feature = "coordinated-witness-financial-continuation")]
    pub(crate) fn coordinated_journal_v1(&self) -> Arc<AuthorityJournal> {
        self.journal.clone()
    }
    #[cfg(feature = "coordinated-witness-financial-continuation")]
    pub(crate) fn coordinated_expected_v1(&self) -> &OwnerControlRequest {
        &self.expected
    }
    #[cfg(feature = "coordinated-witness-financial-continuation")]
    pub(crate) fn coordinated_display_v1(&self, setup: &wholepact_financial_coordinator_origin::WitnessFinancialContinuationSetupV1) -> Result<String> {
        self.coordinated_setup_current_v1(setup)?;
        serde_json::to_string_pretty(&serde_json::json!({
            "operation": "Arm ONE exact original financial continuation append",
            "request": self.expected,
            "actual_original_witness": self.disclosure,
            "notice": crate::native_witness_owner::coordinated_financial_continuation_v1::ADMISSION_NOTICE,
            "limits": "Independent original owner mTLS must submit this identical request. Every later key-use requires its own fresh approval. Original payment, dispatcher, route, expiry and attempt bounds remain fixed. No signature, extraction or transaction dispatch occurs here.",
        })).map_err(|_| AuthorityError::InvalidBinding)
    }
    #[cfg(feature = "coordinated-witness-financial-continuation")]
    pub(crate) fn coordinated_setup_review_digest_v1(&self, setup: &wholepact_financial_coordinator_origin::WitnessFinancialContinuationSetupV1) -> Result<String> {
        self.coordinated_setup_current_v1(setup)?;
        crate::durable_financial_continuation_v1::request_native_review_digest_v1(&self.expected, &self.disclosure)
    }
    /// Borrow retained request data for synthetic correlation only. This does
    /// not check freshness or provide native approval, a source or a grant.
    #[cfg(feature = "synthetic-qualification")]
    pub(crate) fn retained_request_for_synthetic_qualification(&self) -> &OwnerControlRequest {
        &self.expected
    }
    pub(crate) fn review_digest(&self) -> Result<String> {
        self.check_current()?;
        crate::durable_financial_continuation_v1::request_native_review_digest_v1(
            &self.expected,
            &self.disclosure,
        )
    }
    pub(crate) fn first_commit_deadline_ms(&self) -> Option<u64> {
        match &self.expected.control {
            OwnerControl::AdmitFinancialContinuationV1 { record } => {
                Some(record.terms.valid_until_ms)
            }
            _ => None,
        }
    }
    pub(crate) fn display(&self) -> Result<String> {
        self.check_current()?;
        serde_json::to_string_pretty(&serde_json::json!({
            "operation": "Approve ONE exact original payment and its bounded future dispatch after original owner mTLS",
            "request": self.expected,
            "actual_original_witness": self.disclosure,
            "notice": "This explicitly approves the exact financial continuation and bounded future dispatch in the displayed original delivery plan. Each key-use operation still requires its own fresh native action. After both signatures, a fresh Host decision may dispatch only the first retained verified transaction, even after signing process death. Original expiry, inputs, recipient, budget, exposure, dispatcher, route and attempt bounds cannot change. An uncertain operation must be reconciled with its exact original request. This is not approval of another transaction or replacement signing session.",
        })).map_err(|_| AuthorityError::InvalidBinding)
    }
    #[cfg(feature = "coordinated-witness-financial-continuation")]
    pub(crate) fn coordinated_setup_current_v1(&self, setup: &wholepact_financial_coordinator_origin::WitnessFinancialContinuationSetupV1) -> Result<()> {
        let guard = crate::native_witness_owner::financial_setup_guard_v1::FinancialSetupGuardV1::Coordinated(setup);
        self.coordinated_audit_current_v1(guard)
    }
    #[cfg(feature = "coordinated-witness-financial-continuation")]
    pub(crate) fn coordinated_arm_current_v1(&self, arm: &wholepact_financial_coordinator_origin::WitnessFinancialContinuationArmV1) -> Result<()> {
        self.coordinated_audit_current_v1(crate::native_witness_owner::financial_setup_guard_v1::FinancialSetupGuardV1::Arm(arm))
    }
    #[cfg(feature = "coordinated-witness-financial-continuation")]
    fn coordinated_audit_current_v1(&self, guard: crate::native_witness_owner::financial_setup_guard_v1::FinancialSetupGuardV1<'_>) -> Result<()> {
        guard.check()?;
        self.journal.born_owner.as_ref().ok_or(AuthorityError::Permission)?.check_setup_current(guard, true)?;
        let c = self.journal.connection.lock().map_err(|_| AuthorityError::Storage)?;
        guard.check()?;
        let ledger = crate::journal::load(c.connection())?;
        guard.check()?;
        self.validate_locked(&ledger, now_ms()?)?;
        guard.check()
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        self.journal
            .born_owner
            .as_ref()
            .ok_or(AuthorityError::Permission)?
            .check_mutation_current()?;
        let c = self
            .journal
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let ledger = crate::journal::load(c.connection())?;
        self.validate_locked(&ledger, now_ms()?)
    }
    pub(crate) fn validate_locked(&self, ledger: &crate::policy::Ledger, now: u64) -> Result<()> {
        let OwnerControl::AdmitFinancialContinuationV1 { record } = &self.expected.control else {
            return Err(AuthorityError::Permission);
        };
        record.validate_request(&self.expected, &self.disclosure)?;
        if ledger.policy.owner_certificate_digest.is_empty()
            || ledger.policy.account_id != self.expected.account_id
            || ledger.policy.network_profile_id != self.expected.network_profile_id
            || ledger.snapshot.head != self.expected.expected_head
        {
            return Err(AuthorityError::StaleHead);
        }
        if ledger.snapshot.writer_status == WriterStatus::Quarantined {
            return Err(AuthorityError::RecoveryRequired);
        }
        ledger.validate_new_financial_continuation_v1(&self.expected, now)
    }
    pub(crate) fn require_endpoint(&self, server: &str, listen: &str) -> Result<()> {
        if self.disclosure.pinned_server_certificate_digest != server
            || self.disclosure.endpoint != listen
        {
            return Err(AuthorityError::Authentication);
        }
        Ok(())
    }
}
pub(crate) fn prepare_financial_continuation_v1(
    input: NamespaceOpenInput,
    expected: OwnerControlRequest,
) -> Result<FinancialContinuationProposalV1> {
    if !matches!(
        expected.control,
        OwnerControl::AdmitFinancialContinuationV1 { .. }
    ) {
        return Err(AuthorityError::Permission);
    }
    let input_owner = input.owner_certificate_digest.clone();
    let journal = Arc::new(open_born_history(input)?);
    let disclosure = {
        let c = journal
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let ledger = crate::journal::load(c.connection())?;
        if input_owner != ledger.policy.owner_certificate_digest {
            return Err(AuthorityError::Authentication);
        }
        let birth = crate::pending_birth_storage::read(c.connection(), &ledger.policy)?
            .ok_or(AuthorityError::CorruptHistory)?;
        birth.request.disclosure
    };
    let proposal = FinancialContinuationProposalV1 {
        journal,
        expected,
        disclosure,
    };
    proposal.check_current()?;
    Ok(proposal)
}
#[cfg(feature = "coordinated-witness-financial-continuation")]
pub(crate) fn prepare_coordinated_financial_continuation_v1(input: NamespaceOpenInput, expected: OwnerControlRequest, setup: &wholepact_financial_coordinator_origin::WitnessFinancialContinuationSetupV1) -> Result<FinancialContinuationProposalV1> {
    if !matches!(
        expected.control,
        OwnerControl::AdmitFinancialContinuationV1 { .. }
    ) {
        return Err(AuthorityError::Permission);
    }
    let input_owner = input.owner_certificate_digest.clone();
    let guard = crate::native_witness_owner::financial_setup_guard_v1::FinancialSetupGuardV1::Coordinated(setup);
    guard.check()?;
    let journal = Arc::new(crate::witness_locator::open_born_history_guarded(input, guard)?);
    let disclosure = {
        let c = journal
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        guard.check()?;
        let ledger = crate::journal::load(c.connection())?;
        if input_owner != ledger.policy.owner_certificate_digest {
            return Err(AuthorityError::Authentication);
        }
        guard.check()?;
        let birth = crate::pending_birth_storage::read(c.connection(), &ledger.policy)?
            .ok_or(AuthorityError::CorruptHistory)?;
        birth.request.disclosure
    };
    let proposal = FinancialContinuationProposalV1 {
        journal,
        expected,
        disclosure,
    };
    proposal.coordinated_setup_current_v1(setup)?;
    Ok(proposal)
}

pub(crate) fn arm_financial_continuation_v1(
    decision: NativeFinancialContinuationDecisionV1,
) -> Result<NativeFinancialContinuationSourceV1> {
    let (proposal, lease) = decision.into_parts();
    proposal.check_current()?;
    lease.check_current()?;
    if lease.reviewed_digest() != proposal.review_digest()? {
        return Err(AuthorityError::Permission);
    }
    Ok(NativeFinancialContinuationSourceV1 {
        proposal,
        lease: Some(lease),
        committed: None,
        #[cfg(feature = "synthetic-qualification")]
        admission_observer: None,
    })
}
impl NativeFinancialContinuationSourceV1 {
    #[cfg(feature = "synthetic-qualification")]
    pub(crate) fn set_admission_observer(
        &mut self,
        observer: Option<crate::transport::admission_diagnostics_v1::AdmissionWitnessObserverV1>,
    ) {
        self.admission_observer = observer;
    }
    #[cfg(feature = "synthetic-qualification")]
    pub(crate) fn admission_observer(
        &self,
    ) -> Option<&crate::transport::admission_diagnostics_v1::AdmissionWitnessObserverV1> {
        self.admission_observer.as_ref()
    }

    pub(crate) fn journal(&self) -> Arc<AuthorityJournal> {
        Arc::clone(&self.proposal.journal)
    }
    pub(crate) fn require_endpoint(&self, server: &str, listen: &str) -> Result<()> {
        self.proposal.require_endpoint(server, listen)
    }
    /// No journal lock here: transport checks keep OPEN across bounded I/O.
    pub(crate) fn check_open(&self) -> Result<()> {
        self.lease
            .as_ref()
            .ok_or(AuthorityError::Permission)?
            .check_current()?;
        self.proposal
            .journal
            .born_owner
            .as_ref()
            .ok_or(AuthorityError::Permission)?
            .check_mutation_current()
    }
    pub(crate) fn require_exact_locked(
        &self,
        journal: &AuthorityJournal,
        ledger: &crate::policy::Ledger,
        peer: &str,
        request: &OwnerControlRequest,
        now: u64,
    ) -> Result<()> {
        self.check_open()?;
        if !std::ptr::eq(Arc::as_ptr(&self.proposal.journal), journal)
            || peer != ledger.policy.owner_certificate_digest
            || request != &self.proposal.expected
        {
            return Err(AuthorityError::Authentication);
        }
        // Observe ONLY the success of the equality already evaluated above.
        // This data cannot replace that equality or any currentness validation.
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = &self.admission_observer {
            observer.exact_request_matched();
        }
        self.proposal.validate_locked(ledger, now)
    }
    /// Only the exact append kernel calls this after journal/transaction preflight.
    pub(crate) fn take_publication_after_lock(
        &mut self,
    ) -> Result<crate::native_witness_owner::NativePublicationLease> {
        let lease = self.lease.take().ok_or(AuthorityError::Permission)?;
        if lease.reviewed_digest()
            != crate::durable_financial_continuation_v1::request_native_review_digest_v1(
                &self.proposal.expected,
                &self.proposal.disclosure,
            )?
        {
            return Err(AuthorityError::Authentication);
        }
        lease.publication_lease()
    }
    pub(crate) fn record_committed(&mut self, snapshot: AccountSnapshot) {
        self.committed = Some(snapshot);
        #[cfg(feature = "synthetic-qualification")]
        if let Some(observer) = &self.admission_observer {
            observer.snapshot_recorded();
        }
    }
    pub(crate) fn committed(&self) -> Option<&AccountSnapshot> {
        self.committed.as_ref()
    }
}

pub(crate) struct ConfiguredFinancialWitnessV1 {
    journal: Arc<AuthorityJournal>,
    admission: OwnerControlRequest,
    disclosure: WitnessDisclosureDescriptor,
}
impl ConfiguredFinancialWitnessV1 {
    pub(crate) fn from_original(journal: AuthorityJournal, operation_id: &str) -> Result<Self> {
        id(operation_id)?;
        journal.require_born_read_current()?;
        if journal.born_owner.is_none() {
            return Err(AuthorityError::Permission);
        }
        let (admission, disclosure) = {
            let c = journal
                .connection
                .lock()
                .map_err(|_| AuthorityError::Storage)?;
            let ledger = crate::journal::load_financial_continuation_v1(c.connection())?;
            ledger.require_financial_continuation_history_v1()?;
            let admission = ledger
                .financial_continuation_v1(operation_id)?
                .ok_or(AuthorityError::Permission)?
                .clone();
            let birth = crate::pending_birth_storage::read(c.connection(), &ledger.policy)?
                .ok_or(AuthorityError::CorruptHistory)?;
            (admission, birth.request.disclosure)
        };
        Ok(Self {
            journal: Arc::new(journal),
            admission,
            disclosure,
        })
    }
    /// Private original-service selection. The exact retained S request is
    /// compared with the authenticated original journal; ordinary selectors
    /// cannot admit, renew or replace its persisted delegation.
    #[cfg(feature = "coordinated-witness-financial-signing")]
    pub(crate) fn from_original_coordinated_v1(
        journal: AuthorityJournal,
        expected: &OwnerControlRequest,
        setup: &wholepact_financial_coordinator_origin::WitnessFinancialSigningSetupV1,
    ) -> Result<Self> {
        let guard = crate::native_witness_owner::financial_setup_guard_v1::FinancialSetupGuardV1::SigningSetup(setup);
        guard.check()?;
        id(&expected.operation_id)?;
        let owner = journal.born_owner.as_ref().ok_or(AuthorityError::Permission)?;
        owner.check_setup_current(guard, false)?;
        let (admission, disclosure) = {
            let c = journal.connection.lock().map_err(|_| AuthorityError::Storage)?;
            guard.check()?;
            let read_guard = crate::journal::ReadGuardV1::coordinated(guard);
            let ledger = crate::journal::load_financial_continuation_guarded_v1(c.connection(), read_guard)?;
            guard.check()?;
            ledger.require_financial_continuation_history_v1()?;
            let admission = ledger.financial_continuation_v1(&expected.operation_id)?
                .ok_or(AuthorityError::Permission)?.clone();
            if admission != *expected { return Err(AuthorityError::InvalidBinding); }
            let OwnerControl::AdmitFinancialContinuationV1 { record } = &admission.control else {
                return Err(AuthorityError::Permission);
            };
            record.terms.require_live(now_ms()?)?;
            guard.check()?;
            let birth = crate::pending_birth_storage::read_guarded(c.connection(), &ledger.policy, read_guard)?
                .ok_or(AuthorityError::CorruptHistory)?;
            guard.check()?;
            (admission, birth.request.disclosure)
        };
        owner.check_setup_current(guard, false)?;
        guard.check()?;
        Ok(Self { journal: Arc::new(journal), admission, disclosure })
    }
    #[cfg(feature = "coordinated-witness-financial-signing")]
    pub(crate) fn coordinated_original_admission_v1(&self) -> &OwnerControlRequest {
        &self.admission
    }
    #[cfg(feature = "coordinated-witness-financial-signing")]
    pub(crate) fn coordinated_original_disclosure_v1(&self) -> &WitnessDisclosureDescriptor {
        &self.disclosure
    }
    pub(crate) fn journal(&self) -> Arc<AuthorityJournal> {
        Arc::clone(&self.journal)
    }
    pub(crate) fn require_endpoint(&self, server: &str, listen: &str) -> Result<()> {
        if self.disclosure.pinned_server_certificate_digest != server
            || self.disclosure.endpoint != listen
        {
            return Err(AuthorityError::Authentication);
        }
        Ok(())
    }
    pub(crate) fn require_locked(
        &self,
        journal: &AuthorityJournal,
        ledger: &crate::policy::Ledger,
    ) -> Result<&str> {
        if !std::ptr::eq(Arc::as_ptr(&self.journal), journal)
            || ledger.financial_continuation_v1(&self.admission.operation_id)?
                != Some(&self.admission)
        {
            return Err(AuthorityError::Permission);
        }
        ledger.require_financial_continuation_history_v1()?;
        Ok(&self.admission.operation_id)
    }
    pub(crate) fn check_mutation_current(&self) -> Result<()> {
        self.journal
            .born_owner
            .as_ref()
            .ok_or(AuthorityError::Permission)?
            .check_mutation_current()
    }
}
impl ConfiguredFinancialWitnessV1 {
    pub(crate) fn require_dispatcher_locked(
        &self,
        journal: &AuthorityJournal,
        ledger: &crate::policy::Ledger,
        peer: &str,
    ) -> Result<()> {
        self.require_locked(journal, ledger)?;
        let OwnerControl::AdmitFinancialContinuationV1 { record } = &self.admission.control else {
            return Err(AuthorityError::Permission);
        };
        if peer
            != record
                .terms
                .scope
                .delivery
                .dispatcher
                .public_identity_commitment
            || peer == ledger.policy.owner_certificate_digest
            || peer == ledger.policy.initial_writer_certificate_digest
        {
            return Err(AuthorityError::Authentication);
        }
        Ok(())
    }
}
