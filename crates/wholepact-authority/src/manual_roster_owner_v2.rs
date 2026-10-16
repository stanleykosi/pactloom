//! Concrete local native publication through the original immutable namespace.
//! No constructor from serialized IDs creates owner authority. The independent
//! owner signature and focused local decision are both required before append.
use crate::manual_enrollment::ManualEnrollmentExtensionRecord;
use crate::manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2;
use crate::manual_roster_signature_v2::VerifiedManualRosterEnrollmentOwnerSignatureV2;
use crate::manual_roster_witness_v2::ManualRosterEnrollmentExtensionRecordV2;
use crate::native_witness_owner::NativeManualRosterExtensionDecisionV2;
use crate::witness_locator::{NamespaceOpenInput, open_born_history};
use crate::{policy::Event, *};
use rusqlite::{Transaction, TransactionBehavior, params};

pub(crate) struct ManualRosterExtensionProposalV2 {
    journal: AuthorityJournal,
    extension: ManualRosterEnrollmentExtensionV2,
    signature_evidence: String,
    expected_head: AuthorityHead,
    reviewed_digest: String,
    existing: Option<ManualRosterExtensionAuditV2>,
}
#[derive(Clone)]
pub(crate) struct ManualRosterExtensionAuditV2 {
    pub(crate) extension_digest: String,
    pub(crate) enrollment_ref: String,
    pub(crate) committed_head: AuthorityHead,
}
impl ManualRosterExtensionProposalV2 {
    pub(crate) fn review_digest(&self) -> Result<String> {
        self.check_current()?;
        Ok(self.reviewed_digest.clone())
    }
    pub(crate) fn display(&self) -> Result<String> {
        self.check_current()?;
        serde_json::to_string_pretty(&serde_json::json!({
            "operation": "Append the exact Host-roster-bound first account extension",
            "notice": "Original account policy and lifetime budget remain unchanged. This grants only scoped writer bootstrap and one finite enrollment publication. It does not authorize spending, offline use, automation, restore, replacement or new genesis.",
            "extension": self.extension,
            "original_owner_signature_evidence_digest": self.signature_evidence,
            "expected_head": self.expected_head,
            "review_digest": self.reviewed_digest,
            "already_committed_exact_audit_retry": self.existing.is_some(),
        })).map_err(|_| AuthorityError::InvalidBinding)
    }
    pub(crate) fn first_commit_deadline_ms(&self) -> Option<u64> {
        self.existing
            .is_none()
            .then_some(self.extension.account_extension.terms.scope.expires_at_ms)
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        let owner = self
            .journal
            .born_owner
            .as_ref()
            .ok_or(AuthorityError::Permission)?;
        owner.check_mutation_current()?;
        let c = self
            .journal
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let ledger = crate::journal::load(c.connection())?;
        ledger.require_supported_manual_history()?;
        let birth = crate::pending_birth_storage::read(c.connection(), &ledger.policy)?
            .ok_or(AuthorityError::CorruptHistory)?;
        self.extension.validate_original_birth(&birth)?;
        if ledger.snapshot.head != self.expected_head {
            return Err(AuthorityError::StaleHead);
        }
        match (&self.existing, ledger.manual_roster_extension()?) {
            (None, None) => {
                let record = ManualRosterEnrollmentExtensionRecordV2 {
                    extension: self.extension.clone(),
                    account_record: ManualEnrollmentExtensionRecord {
                        extension: self.extension.account_extension.clone(),
                        owner_signature_evidence_digest: self.signature_evidence.clone(),
                        native_review_digest: self.reviewed_digest.clone(),
                    },
                };
                ledger.validate_new_manual_roster_extension(&record, now_ms()?)?;
            }
            (Some(_), Some(record)) if record.extension == self.extension => {}
            _ => return Err(AuthorityError::Conflict),
        }
        Ok(())
    }
}
pub(crate) fn prepare_manual_roster_extension_v2(
    input: NamespaceOpenInput,
    signature: VerifiedManualRosterEnrollmentOwnerSignatureV2,
) -> Result<ManualRosterExtensionProposalV2> {
    if input.owner_certificate_digest != signature.certificate_digest()
        || input.expected_account_id
            != signature
                .extension()
                .account_extension
                .terms
                .identity
                .account_id
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
    let (expected_head, existing) = {
        let c = journal
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let ledger = crate::journal::load(c.connection())?;
        ledger.require_supported_manual_history()?;
        let birth = crate::pending_birth_storage::read(c.connection(), &ledger.policy)?
            .ok_or(AuthorityError::CorruptHistory)?;
        extension.validate_original_birth(&birth)?;
        let existing = if let Some(record) = ledger.manual_roster_extension()? {
            if record.extension != extension {
                return Err(AuthorityError::Conflict);
            }
            let (_, _, result) = ledger
                .operations
                .get(&extension.owner_operation_id()?)
                .ok_or(AuthorityError::CorruptHistory)?;
            let MutationResult::Controlled(snapshot) = result else {
                return Err(AuthorityError::CorruptHistory);
            };
            Some(ManualRosterExtensionAuditV2 {
                extension_digest: extension.digest()?,
                enrollment_ref: extension.account_extension.enrollment_ref.clone(),
                committed_head: snapshot.head.clone(),
            })
        } else {
            None
        };
        (ledger.snapshot.head, existing)
    };
    let signature_evidence = signature.evidence_digest().to_owned();
    let reviewed_digest = digest(
        "wholepact:native-manual-roster-extension-review:v2",
        &(
            &extension,
            &signature_evidence,
            &expected_head,
            existing.is_some(),
        ),
    )?;
    let proposal = ManualRosterExtensionProposalV2 {
        journal,
        extension,
        signature_evidence,
        expected_head,
        reviewed_digest,
        existing,
    };
    proposal.check_current()?;
    Ok(proposal)
}
pub(crate) fn commit_manual_roster_extension_v2(
    decision: NativeManualRosterExtensionDecisionV2,
) -> Result<ManualRosterExtensionAuditV2> {
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
        // Re-review authenticates continuing the exact immutable result; never
        // replaces its first signature evidence, native review, time or scope.
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
    let record = ManualRosterEnrollmentExtensionRecordV2 {
        extension: proposal.extension.clone(),
        account_record: ManualEnrollmentExtensionRecord {
            extension: proposal.extension.account_extension.clone(),
            owner_signature_evidence_digest: proposal.signature_evidence,
            native_review_digest: proposal.reviewed_digest,
        },
    };
    ledger.validate_new_manual_roster_extension(&record, now)?;
    let event = Event {
        mutation: AuthorityMutation::OwnerControl(OwnerControlRequest {
            operation_id: proposal.extension.owner_operation_id()?,
            account_id: ledger.policy.account_id.clone(),
            network_profile_id: ledger.policy.network_profile_id.clone(),
            writer_epoch: ledger.snapshot.writer_epoch,
            expected_head: ledger.snapshot.head.clone(),
            control: OwnerControl::ExtendManualRosterEnrollmentV2 {
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
    if final_now < now
        || final_now
            >= proposal
                .extension
                .account_extension
                .terms
                .scope
                .expires_at_ms
    {
        return Err(AuthorityError::Expired);
    }
    tx.commit()?;
    Ok(ManualRosterExtensionAuditV2 {
        extension_digest: proposal.extension.digest()?,
        enrollment_ref: proposal.extension.account_extension.enrollment_ref,
        committed_head: ledger.snapshot.head,
    })
}
