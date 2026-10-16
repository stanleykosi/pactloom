//! Concrete original-namespace publication. Only the focused witness-native
//! decision consumes this proposal; signatures and parsed records are insufficient.
use crate::{
    born_offline_enrollment_signature_v1::VerifiedBornOfflineEnrollmentOwnerSignatureV1,
    born_offline_enrollment_v1::*,
    native_witness_owner::NativeBornOfflineEnrollmentDecisionV1,
    policy::Event,
    witness_locator::{NamespaceOpenInput, open_born_history},
    *,
};
use rusqlite::{Transaction, TransactionBehavior, params};

pub(crate) struct BornOfflineEnrollmentProposalV1 {
    journal: AuthorityJournal,
    enrollment: BornOfflineEnrollmentV1,
    signature_evidence: String,
    reviewed_head: AuthorityHead,
    review_digest: String,
    existing: Option<BornOfflineEnrollmentAuditV1>,
}
#[derive(Clone)]
pub(crate) struct BornOfflineEnrollmentAuditV1 {
    pub(crate) enrollment_digest: String,
    pub(crate) offline_policy_digest: String,
    pub(crate) enrollment_ref: String,
    pub(crate) original_record: BornOfflineEnrollmentRecordV1,
    pub(crate) committed_head: AuthorityHead,
}
impl BornOfflineEnrollmentProposalV1 {
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
        let birth = crate::pending_birth_storage::read(c.connection(), &ledger.policy)?
            .ok_or(AuthorityError::CorruptHistory)?;
        self.enrollment.validate_original_birth(&birth)?;
        if ledger.snapshot.head != self.reviewed_head {
            return Err(AuthorityError::StaleHead);
        }
        match (&self.existing, ledger.born_offline_enrollment_v1()?) {
            (None, None) => {
                ledger.validate_new_born_offline_enrollment_v1(&self.record(), now_ms()?)
            }
            (Some(audit), Some(record))
                if record == &audit.original_record && record.enrollment == self.enrollment =>
            {
                Ok(())
            }
            _ => Err(AuthorityError::Conflict),
        }
    }
    fn record(&self) -> BornOfflineEnrollmentRecordV1 {
        BornOfflineEnrollmentRecordV1 {
            enrollment: self.enrollment.clone(),
            owner_signature_evidence_digest: self.signature_evidence.clone(),
            native_review_digest: self.review_digest.clone(),
        }
    }
    pub(crate) fn review_digest(&self) -> Result<String> {
        self.check_current()?;
        Ok(self.review_digest.clone())
    }
    pub(crate) fn first_commit_deadline_ms(&self) -> Option<u64> {
        self.existing
            .is_none()
            .then_some(self.enrollment.first_commit_deadline_ms)
    }
    pub(crate) fn display(&self) -> Result<String> {
        self.check_current()?;
        serde_json::to_string_pretty(&serde_json::json!({
            "operation": "Approve one exact born offline enrollment for the original active writer session",
            "notice": "SOURCE-STAGED. This records a bounded offline policy under the original account, birth and already-active writer session. No new key, writer session, lifetime budget, genesis, credential or mailbox is created. It does not authorize a signature or payment. Born offline execution remains unavailable until the dedicated protected transport owner is complete and qualified. Existing manual-only routes reject offline-bearing history, so committing this record prevents further use through those older routes. Account charges, original sessions, exclusions and all prior history remain retained. This first enrollment cannot be renewed, replaced or undone here. Exact historical retries return the original record, without extending any deadline.",
            "enrollment": self.enrollment,
            "new_verified_owner_signature_evidence_digest": self.signature_evidence,
            "reviewed_current_head": self.reviewed_head,
            "native_review_digest": self.review_digest,
            "original_retained_record_on_exact_retry": self.existing.as_ref().map(|a| &a.original_record),
            "financial_execution_available": false,
        })).map_err(|_| AuthorityError::InvalidBinding)
    }
}

pub(crate) fn prepare_born_offline_enrollment_v1(
    input: NamespaceOpenInput,
    signature: VerifiedBornOfflineEnrollmentOwnerSignatureV1,
) -> Result<BornOfflineEnrollmentProposalV1> {
    if input.owner_certificate_digest != signature.certificate_digest()
        || input.expected_account_id != signature.enrollment().policy.account_id
    {
        return Err(AuthorityError::Permission);
    }
    let journal = open_born_history(input)?;
    journal
        .born_owner
        .as_ref()
        .ok_or(AuthorityError::Permission)?
        .check_mutation_current()?;
    let enrollment = signature.enrollment().clone();
    let (reviewed_head, existing) = {
        let c = journal
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let ledger = crate::journal::load(c.connection())?;
        let birth = crate::pending_birth_storage::read(c.connection(), &ledger.policy)?
            .ok_or(AuthorityError::CorruptHistory)?;
        enrollment.validate_original_birth(&birth)?;
        let existing = if let Some(record) = ledger.born_offline_enrollment_v1()? {
            if record.enrollment != enrollment {
                return Err(AuthorityError::Conflict);
            }
            let (_, _, MutationResult::Controlled(snapshot)) = ledger
                .operations
                .get(&enrollment.owner_operation_id()?)
                .ok_or(AuthorityError::CorruptHistory)?
            else {
                return Err(AuthorityError::CorruptHistory);
            };
            Some(BornOfflineEnrollmentAuditV1 {
                enrollment_digest: enrollment.digest()?,
                offline_policy_digest: enrollment.policy.policy_digest()?,
                enrollment_ref: enrollment.policy.enrollment_ref.clone(),
                original_record: record.clone(),
                committed_head: snapshot.head.clone(),
            })
        } else {
            None
        };
        (ledger.snapshot.head, existing)
    };
    let signature_evidence = signature.evidence_digest().to_owned();
    let review_digest = digest(
        "wholepact:native-born-offline-enrollment-review:v1",
        &(
            &enrollment,
            &signature_evidence,
            &reviewed_head,
            existing.as_ref().map(|a| &a.original_record),
        ),
    )?;
    let proposal = BornOfflineEnrollmentProposalV1 {
        journal,
        enrollment,
        signature_evidence,
        reviewed_head,
        review_digest,
        existing,
    };
    proposal.check_current()?;
    Ok(proposal)
}

pub(crate) fn commit_born_offline_enrollment_v1(
    decision: NativeBornOfflineEnrollmentDecisionV1,
) -> Result<BornOfflineEnrollmentAuditV1> {
    let (proposal, lease) = decision.into_parts();
    lease.check_current()?;
    if lease.reviewed_digest() != proposal.review_digest {
        return Err(AuthorityError::Permission);
    }
    proposal.check_current()?;
    lease.check_current()?;
    if let Some(audit) = &proposal.existing {
        // Exact historical disclosure never enters PUBLISHING. Cancellation or
        // blur remains effective through the final read/copy of the audit.
        let retained = audit.clone();
        lease.check_current()?;
        return Ok(retained);
    }
    let owner = proposal
        .journal
        .born_owner
        .as_ref()
        .ok_or(AuthorityError::Permission)?;
    owner.check_mutation_current()?;
    let c = proposal
        .journal
        .connection
        .lock()
        .map_err(|_| AuthorityError::Storage)?;
    let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate)?;
    lease.check_current()?;
    let mut ledger = crate::journal::load(&tx)?;
    if ledger.snapshot.head != proposal.reviewed_head {
        return Err(AuthorityError::StaleHead);
    }
    let birth = crate::pending_birth_storage::read(&tx, &ledger.policy)?
        .ok_or(AuthorityError::CorruptHistory)?;
    proposal.enrollment.validate_original_birth(&birth)?;
    let now = now_ms()?;
    let record = proposal.record();
    ledger.validate_new_born_offline_enrollment_v1(&record, now)?;
    let event = Event {
        mutation: AuthorityMutation::OwnerControl(OwnerControlRequest {
            operation_id: record.enrollment.owner_operation_id()?,
            account_id: ledger.policy.account_id.clone(),
            network_profile_id: ledger.policy.network_profile_id.clone(),
            writer_epoch: ledger.snapshot.writer_epoch,
            expected_head: ledger.snapshot.head.clone(),
            control: OwnerControl::EnrollBornOfflineV1 {
                record: Box::new(record.clone()),
            },
        }),
        authenticated_certificate_digest: ledger.policy.owner_certificate_digest.clone(),
        witness_time_ms: now,
        writer_session_id: None,
        original_request_link: None,
    };
    let previous = ledger.snapshot.head.digest.clone();
    ledger.apply(&event)?;
    let payload = encode(&event)?;
    let retained: u64 = tx.query_row(
        "SELECT coalesce(sum(length(payload)),0) FROM authority_events",
        [],
        |r| r.get(0),
    )?;
    if retained
        .checked_add(payload.len() as u64)
        .filter(|n| *n <= MAX_JOURNAL_BYTES)
        .is_none()
    {
        return Err(AuthorityError::Limit);
    }
    // All replay, journal/registry locks, size checks and fallible audit
    // construction precede the one-shot publication race. In particular, a
    // cancel while any preflight read or lock waits must still prevent append.
    owner.check_mutation_current()?;
    lease.check_current()?;
    let precommit_now = now_ms()?;
    if precommit_now < now {
        return Err(AuthorityError::Expired);
    }
    record.enrollment.require_first_commit_time(precommit_now)?;
    let audit = BornOfflineEnrollmentAuditV1 {
        enrollment_digest: record.enrollment.digest()?,
        offline_policy_digest: record.enrollment.policy.policy_digest()?,
        enrollment_ref: record.enrollment.policy.enrollment_ref.clone(),
        original_record: record.clone(),
        committed_head: ledger.snapshot.head.clone(),
    };
    // The only non-revocable portion is this exact already-preflighted append.
    let publication = lease.publication_lease()?;
    publication.check_current()?;
    if publication.reviewed_digest() != proposal.review_digest
        || publication.admitted_at_ms() < precommit_now
    {
        return Err(AuthorityError::Permission);
    }
    record
        .enrollment
        .require_first_commit_time(publication.admitted_at_ms())?;
    tx.execute(
        "INSERT INTO authority_events VALUES(?1,?2,?3,?4,?5)",
        params![
            ledger.snapshot.head.sequence,
            event.mutation.operation_id(),
            previous,
            ledger.snapshot.head.digest,
            payload.as_slice()
        ],
    )?;
    publication.check_current()?;
    let final_now = now_ms()?;
    if final_now < publication.admitted_at_ms() {
        return Err(AuthorityError::Expired);
    }
    record.enrollment.require_first_commit_time(final_now)?;
    // Once commit starts, a storage or final-current failure cannot safely claim
    // no publication. Recovery must inspect the exact immutable original event.
    tx.commit().map_err(|_| AuthorityError::Uncertain)?;
    owner
        .check_mutation_current()
        .map_err(|_| AuthorityError::Uncertain)?;
    publication
        .check_current()
        .map_err(|_| AuthorityError::Uncertain)?;
    Ok(audit)
}
