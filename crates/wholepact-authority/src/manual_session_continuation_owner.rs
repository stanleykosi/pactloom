//! Sole local native continuation publisher. A signature authenticates the
//! original owner key; only the private focused decision admits this transaction.
use crate::manual_enrollment::ManualEnrollmentExtension;
use crate::manual_session_continuation::*;
use crate::manual_session_continuation_signature::VerifiedManualEnrollmentSessionContinuationOwnerSignature;
use crate::native_witness_owner::NativeManualSessionContinuationDecision;
use crate::witness_locator::{NamespaceOpenInput, open_born_history};
use crate::{policy::Event, *};
use rusqlite::{Transaction, TransactionBehavior, params};

pub(crate) struct ManualSessionContinuationProposal {
    journal: AuthorityJournal,
    extension: ManualEnrollmentExtension,
    continuation: ManualEnrollmentSessionContinuation,
    signature_evidence: String,
    expected_head: AuthorityHead,
    reviewed_digest: String,
    existing: Option<ManualSessionContinuationAudit>,
}
#[derive(Clone)]
pub(crate) struct ManualSessionContinuationAudit {
    pub(crate) attempt_digest: String,
    pub(crate) committed_head: AuthorityHead,
}
impl ManualSessionContinuationProposal {
    pub(crate) fn review_digest(&self) -> Result<String> {
        self.check_current()?;
        Ok(self.reviewed_digest.clone())
    }
    pub(crate) fn display(&self) -> Result<String> {
        self.check_current()?;
        serde_json::to_string_pretty(&serde_json::json!({
            "operation":"Append one exact manual enrollment session continuation",
            "notice":"This fences the exact prior bootstrap session and approves only one successor attempt. All prior records, keys and receipts remain. Original writer epoch, policy, budget, exclusions and enrollment stay unchanged. This does not authorize construction, spending, signing, release, offline use, replacement, restore or new genesis.",
            "extension":self.extension,"continuation":self.continuation,
            "owner_signature_evidence_digest":self.signature_evidence,"review_digest":self.reviewed_digest,
            "current_head":self.expected_head,"already_committed_exact_audit_retry":self.existing.is_some()
        })).map_err(|_|AuthorityError::InvalidBinding)
    }
    pub(crate) fn first_commit_deadline_ms(&self) -> Option<u64> {
        self.existing
            .is_none()
            .then_some(self.continuation.initial_commit_deadline_ms)
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
        ledger.require_supported_manual_history()?;
        if ledger.manual_roster_extension()?.is_some() {
            return Err(AuthorityError::Permission);
        }
        let birth = crate::pending_birth_storage::read(c.connection(), &ledger.policy)?
            .ok_or(AuthorityError::CorruptHistory)?;
        self.extension.validate_original_birth(&birth)?;
        if ledger.manual_extension()?.map(|r| &r.extension) != Some(&self.extension) {
            return Err(AuthorityError::Conflict);
        }
        if ledger.snapshot.head != self.expected_head {
            return Err(AuthorityError::StaleHead);
        }
        let operation = self.continuation.owner_operation_id(&self.extension)?;
        match (&self.existing, ledger.operations.get(&operation)) {
            (None, None) => ledger.validate_new_manual_continuation(
                &ManualEnrollmentSessionContinuationRecord {
                    continuation: self.continuation.clone(),
                    owner_signature_evidence_digest: self.signature_evidence.clone(),
                    native_review_digest: self.reviewed_digest.clone(),
                },
                now_ms()?,
            )?,
            (
                Some(_),
                Some((
                    AuthorityMutation::OwnerControl(OwnerControlRequest {
                        control: OwnerControl::ContinueManualEnrollmentSession { record },
                        ..
                    }),
                    _,
                    MutationResult::Controlled(_),
                )),
            ) if record.continuation == self.continuation => {}
            _ => return Err(AuthorityError::Conflict),
        }
        Ok(())
    }
}
pub(crate) fn prepare_manual_session_continuation(
    input: NamespaceOpenInput,
    signature: VerifiedManualEnrollmentSessionContinuationOwnerSignature,
) -> Result<ManualSessionContinuationProposal> {
    if input.owner_certificate_digest != signature.certificate_digest()
        || input.expected_account_id != signature.extension().terms.identity.account_id
    {
        return Err(AuthorityError::Permission);
    }
    let journal = open_born_history(input)?;
    journal
        .born_owner
        .as_ref()
        .ok_or(AuthorityError::Permission)?
        .check_mutation_current()?;
    let extension = signature.extension().clone();
    let continuation = signature.continuation().clone();
    let (expected_head, existing) = {
        let c = journal
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let ledger = crate::journal::load(c.connection())?;
        ledger.require_supported_manual_history()?;
        if ledger.manual_roster_extension()?.is_some() {
            return Err(AuthorityError::Permission);
        }
        let birth = crate::pending_birth_storage::read(c.connection(), &ledger.policy)?
            .ok_or(AuthorityError::CorruptHistory)?;
        extension.validate_original_birth(&birth)?;
        if ledger.manual_extension()?.map(|r| &r.extension) != Some(&extension) {
            return Err(AuthorityError::Conflict);
        }
        let existing = match ledger
            .operations
            .get(&continuation.owner_operation_id(&extension)?)
        {
            None => None,
            Some((
                AuthorityMutation::OwnerControl(OwnerControlRequest {
                    control: OwnerControl::ContinueManualEnrollmentSession { record },
                    ..
                }),
                _,
                MutationResult::Controlled(snapshot),
            )) if record.continuation == continuation => Some(ManualSessionContinuationAudit {
                attempt_digest: continuation.digest_for(&extension)?,
                committed_head: snapshot.head.clone(),
            }),
            Some(_) => return Err(AuthorityError::Conflict),
        };
        (ledger.snapshot.head, existing)
    };
    let signature_evidence = signature.evidence_digest().to_owned();
    let reviewed_digest = digest(
        "wholepact:native-manual-session-continuation-review:v1",
        &(
            &extension,
            &continuation,
            &signature_evidence,
            &expected_head,
            existing.is_some(),
        ),
    )?;
    let proposal = ManualSessionContinuationProposal {
        journal,
        extension,
        continuation,
        signature_evidence,
        expected_head,
        reviewed_digest,
        existing,
    };
    proposal.check_current()?;
    Ok(proposal)
}
pub(crate) fn commit_manual_session_continuation(
    decision: NativeManualSessionContinuationDecision,
) -> Result<ManualSessionContinuationAudit> {
    let (proposal, lease) = decision.into_parts();
    proposal.check_current()?;
    lease.check_current()?;
    if lease.reviewed_digest() != proposal.reviewed_digest {
        return Err(AuthorityError::Permission);
    }
    let publication = lease.publication_lease()?;
    publication.check_current()?;
    if publication.reviewed_digest() != proposal.reviewed_digest
        || publication.admitted_at_ms() > now_ms()?
    {
        return Err(AuthorityError::Permission);
    }
    proposal.check_current()?;
    if let Some(audit) = proposal.existing {
        publication.check_current()?;
        return Ok(audit);
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
    let mut ledger = crate::journal::load(&tx)?;
    if ledger.snapshot.head != proposal.expected_head {
        return Err(AuthorityError::StaleHead);
    }
    let birth = crate::pending_birth_storage::read(&tx, &ledger.policy)?
        .ok_or(AuthorityError::CorruptHistory)?;
    proposal.extension.validate_original_birth(&birth)?;
    let now = now_ms()?;
    let record = ManualEnrollmentSessionContinuationRecord {
        continuation: proposal.continuation.clone(),
        owner_signature_evidence_digest: proposal.signature_evidence,
        native_review_digest: proposal.reviewed_digest,
    };
    ledger.validate_new_manual_continuation(&record, now)?;
    let event = Event {
        mutation: AuthorityMutation::OwnerControl(OwnerControlRequest {
            operation_id: proposal
                .continuation
                .owner_operation_id(&proposal.extension)?,
            account_id: ledger.policy.account_id.clone(),
            network_profile_id: ledger.policy.network_profile_id.clone(),
            writer_epoch: ledger.snapshot.writer_epoch,
            expected_head: ledger.snapshot.head.clone(),
            control: OwnerControl::ContinueManualEnrollmentSession {
                record: Box::new(record),
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
    owner.check_mutation_current()?;
    publication.check_current()?;
    let final_now = now_ms()?;
    if final_now < now || final_now >= proposal.continuation.initial_commit_deadline_ms {
        return Err(AuthorityError::Expired);
    }
    tx.commit()?;
    Ok(ManualSessionContinuationAudit {
        attempt_digest: proposal.continuation.digest_for(&proposal.extension)?,
        committed_head: ledger.snapshot.head,
    })
}
