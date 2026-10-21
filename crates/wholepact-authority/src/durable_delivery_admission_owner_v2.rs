//! Native ONE-record authority plus original-namespace durable serving selection.
//! Requests/configuration are data. Only the focused native Window decision and
//! the independently authenticated original owner-mTLS peer can commit a record.
use crate::{
    native_witness_owner::{NativeDurableDeliveryAdmissionDecisionV2, NativeWorkerLease},
    witness_locator::{open_born_history, NamespaceOpenInput},
    *,
};
use std::sync::Arc;

pub(crate) struct DurableDeliveryAdmissionProposalV2 {
    journal: Arc<AuthorityJournal>,
    expected: OwnerControlRequest,
    disclosure: WitnessDisclosureDescriptor,
}
pub(crate) struct NativeDurableDeliveryAdmissionSourceV2 {
    proposal: DurableDeliveryAdmissionProposalV2,
    lease: Option<NativeWorkerLease>,
    committed: Option<AccountSnapshot>,
    #[cfg(feature = "synthetic-qualification")]
    admission_observer:
        Option<crate::transport::admission_diagnostics_v1::AdmissionWitnessObserverV1>,
}
impl DurableDeliveryAdmissionProposalV2 {
    /// Borrow retained request data for synthetic correlation only. This does
    /// not check freshness or provide native approval, a source or a grant.
    #[cfg(feature = "synthetic-qualification")]
    pub(crate) fn retained_request_for_synthetic_qualification(&self) -> &OwnerControlRequest {
        &self.expected
    }
    pub(crate) fn review_digest(&self) -> Result<String> {
        self.check_current()?;
        crate::durable_delivery_admission_v2::request_native_review_digest_v2(
            &self.expected,
            &self.disclosure,
        )
    }
    pub(crate) fn first_commit_deadline_ms(&self) -> Option<u64> {
        match &self.expected.control {
            OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } => {
                Some(record.scope.delivery.valid_until_ms)
            }
            _ => None,
        }
    }
    pub(crate) fn display(&self) -> Result<String> {
        self.check_current()?;
        serde_json::to_string_pretty(&serde_json::json!({
            "operation": "Retain ONE exact prospective delivery scope after original owner mTLS",
            "request": self.expected,
            "actual_original_witness": self.disclosure,
            "notice": "This records the whole exact prospective delivery scope against the original account and bootstrap. The independent signer must derive the original fixed PCZT/material and Host lineage. This witness does not attest the remote Host filesystem or possess those materials. Original owner mTLS must submit this identical request. Cancel or focus loss before publication prevents commitment; an uncertain result must be audited with the exact same operation. No Acquire, Activate, Reserve, signature, extraction, release, final-byte delivery, dispatcher authentication or dispatch is supported. Historical reading does not establish current material availability.",
        })).map_err(|_| AuthorityError::InvalidBinding)
    }
    /// Separate cancel-only presentation. Legacy display/digest remain unchanged.
    /// This returns inert facts only and never a source, approval or decision.
    #[cfg(feature = "coordinated-witness-cancel-review")]
    pub(crate) fn cancel_only_display_v1(&self) -> Result<String> {
        self.check_current()?;
        serde_json::to_string_pretty(&serde_json::json!({
            "operation": "Review ONE exact prospective delivery scope; approval unavailable",
            "request": self.expected,
            "actual_original_witness": self.disclosure,
            "notice": "Approval is unavailable in this review-only slice. No append can be admitted. Cancel, close, Escape, or focus loss requests disposal of this review. The independent signer must derive the original fixed PCZT/material and Host lineage. This witness does not attest the remote Host filesystem or possess those materials. No Acquire, Activate, Reserve, signature, extraction, release, final-byte delivery, dispatcher authentication or dispatch is supported. Historical reading does not establish current material availability.",
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
        let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &self.expected.control
        else {
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
        ledger.validate_new_durable_delivery_admission_v2(&self.expected, now)
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
pub(crate) fn prepare_durable_delivery_admission_v2(
    input: NamespaceOpenInput,
    expected: OwnerControlRequest,
) -> Result<DurableDeliveryAdmissionProposalV2> {
    if !matches!(
        expected.control,
        OwnerControl::AdmitDurablePaymentWithDeliveryV2 { .. }
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
    let proposal = DurableDeliveryAdmissionProposalV2 {
        journal,
        expected,
        disclosure,
    };
    proposal.check_current()?;
    Ok(proposal)
}
pub(crate) fn arm_durable_delivery_admission_v2(
    decision: NativeDurableDeliveryAdmissionDecisionV2,
) -> Result<NativeDurableDeliveryAdmissionSourceV2> {
    let (proposal, lease) = decision.into_parts();
    proposal.check_current()?;
    lease.check_current()?;
    if lease.reviewed_digest() != proposal.review_digest()? {
        return Err(AuthorityError::Permission);
    }
    Ok(NativeDurableDeliveryAdmissionSourceV2 {
        proposal,
        lease: Some(lease),
        committed: None,
        #[cfg(feature = "synthetic-qualification")]
        admission_observer: None,
    })
}
impl NativeDurableDeliveryAdmissionSourceV2 {
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
    /// Read-only preamble check on the actual already armed source. The metadata
    /// is compared with its privately held complete request and current head;
    /// it does not consume native publication or mutate the ledger.
    pub(crate) fn require_preparation_v3(
        &self,
        peer: &str,
        preparation: &crate::transport::durable_delivery_admission_v3::DurableAdmissionPrepareV3,
    ) -> Result<()> {
        self.check_open()?;
        preparation.matches(&self.proposal.expected)?;
        let connection = self.proposal.journal.connection.lock().map_err(|_| AuthorityError::Storage)?;
        let ledger = crate::journal::load(connection.connection())?;
        if peer != ledger.policy.owner_certificate_digest { return Err(AuthorityError::Authentication); }
        self.proposal.validate_locked(&ledger, now_ms()?)?;
        self.check_open()
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
            != crate::durable_delivery_admission_v2::request_native_review_digest_v2(
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
