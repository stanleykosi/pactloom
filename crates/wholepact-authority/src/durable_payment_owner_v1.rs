//! Native ONE-record authority plus original-namespace durable serving selection.
//! Requests/configuration are data. Only the focused native Window decision and
//! the independently authenticated original owner-mTLS peer can commit a record.
use crate::{
    native_witness_owner::{NativeDurablePaymentAdmissionDecisionV1, NativeWorkerLease},
    witness_locator::{open_born_history, NamespaceOpenInput},
    *,
};
use std::sync::Arc;

pub(crate) struct DurablePaymentAdmissionProposalV1 {
    journal: Arc<AuthorityJournal>,
    expected: OwnerControlRequest,
    disclosure: WitnessDisclosureDescriptor,
}
pub(crate) struct NativeDurablePaymentAdmissionSourceV1 {
    proposal: DurablePaymentAdmissionProposalV1,
    lease: Option<NativeWorkerLease>,
    committed: Option<AccountSnapshot>,
}
pub(crate) struct ConfiguredDurablePaymentWitnessV1 {
    journal: Arc<AuthorityJournal>,
    admission: OwnerControlRequest,
    disclosure: WitnessDisclosureDescriptor,
}
impl DurablePaymentAdmissionProposalV1 {
    /// Borrow retained request data for synthetic correlation only. This does
    /// not check freshness or provide native approval, a source or a grant.
    #[cfg(feature = "synthetic-qualification")]
    pub(crate) fn retained_request_for_synthetic_qualification(&self) -> &OwnerControlRequest {
        &self.expected
    }
    pub(crate) fn review_digest(&self) -> Result<String> {
        self.check_current()?;
        crate::durable_payment_v1::request_native_review_digest_v1(&self.expected, &self.disclosure)
    }
    pub(crate) fn first_commit_deadline_ms(&self) -> Option<u64> {
        match &self.expected.control {
            OwnerControl::AdmitDurablePaymentV1 { record } => Some(record.terms.valid_until_ms),
            _ => None,
        }
    }
    pub(crate) fn display(&self) -> Result<String> {
        self.check_current()?;
        serde_json::to_string_pretty(&serde_json::json!({
            "operation": "Admit ONE exact durable payment after original owner mTLS",
            "request": self.expected,
            "actual_original_witness": self.disclosure,
            "notice": "This authorizes this exact financial candidate for the explicit interval. Original policy, intent expiry, budget, exclusions and exposure remain unchanged. The original owner certificate must separately submit this exact request over authenticated TLS. Cancel or loss of focus before commit prevents admission. After commit, closing this window or stopping a server does not revoke the record. It remains valid until its approved end or existing account exclusion/quarantine. Later serving requires an independent opening of this original namespace. There is no session replacement after original session-key loss or expiry.",
        })).map_err(|_| AuthorityError::InvalidBinding)
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
        let OwnerControl::AdmitDurablePaymentV1 { record } = &self.expected.control else {
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
        ledger.validate_new_durable_payment_admission_v1(&self.expected, now)
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
pub(crate) fn prepare_durable_payment_admission_v1(
    input: NamespaceOpenInput,
    expected: OwnerControlRequest,
) -> Result<DurablePaymentAdmissionProposalV1> {
    if !matches!(expected.control, OwnerControl::AdmitDurablePaymentV1 { .. }) {
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
    let proposal = DurablePaymentAdmissionProposalV1 {
        journal,
        expected,
        disclosure,
    };
    proposal.check_current()?;
    Ok(proposal)
}
pub(crate) fn arm_durable_payment_admission_v1(
    decision: NativeDurablePaymentAdmissionDecisionV1,
) -> Result<NativeDurablePaymentAdmissionSourceV1> {
    let (proposal, lease) = decision.into_parts();
    proposal.check_current()?;
    lease.check_current()?;
    if lease.reviewed_digest() != proposal.review_digest()? {
        return Err(AuthorityError::Permission);
    }
    Ok(NativeDurablePaymentAdmissionSourceV1 {
        proposal,
        lease: Some(lease),
        committed: None,
    })
}
impl NativeDurablePaymentAdmissionSourceV1 {
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
        self.proposal.validate_locked(ledger, now)
    }
    /// Only the exact append kernel calls this after journal/transaction preflight.
    pub(crate) fn take_publication_after_lock(
        &mut self,
    ) -> Result<crate::native_witness_owner::NativePublicationLease> {
        let lease = self.lease.take().ok_or(AuthorityError::Permission)?;
        if lease.reviewed_digest()
            != crate::durable_payment_v1::request_native_review_digest_v1(
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
    }
    pub(crate) fn committed(&self) -> Option<&AccountSnapshot> {
        self.committed.as_ref()
    }
}
impl ConfiguredDurablePaymentWitnessV1 {
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
            let ledger = crate::journal::load(c.connection())?;
            ledger.require_supported_durable_payment_history_v1()?;
            let admission = ledger
                .durable_payment_admission_v1(operation_id)?
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
            || ledger.durable_payment_admission_v1(&self.admission.operation_id)?
                != Some(&self.admission)
        {
            return Err(AuthorityError::Permission);
        }
        ledger.require_supported_durable_payment_history_v1()?;
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
