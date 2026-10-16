//! Sole local native approval publisher. A signature authenticates the
//! original owner key; only the private focused decision admits this transaction.
use crate::manual_roster_construction_signature_v2::VerifiedManualRosterConstructionOwnerSignatureV2;
use crate::manual_roster_construction_v2::*;
use crate::manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2;
use crate::native_witness_owner::NativeManualRosterConstructionDecisionV2;
use crate::witness_locator::{NamespaceOpenInput, open_born_history};
use crate::{policy::Event, *};
use rusqlite::{Transaction, TransactionBehavior, params};

pub(crate) struct ManualRosterConstructionProposalV2 {
    journal: AuthorityJournal,
    extension: ManualRosterEnrollmentExtensionV2,
    approval: ManualRosterConstructionApprovalV2,
    signature_evidence: String,
    expected_head: AuthorityHead,
    reviewed_digest: String,
    existing: Option<ManualRosterConstructionAuditV2>,
}
#[derive(Clone)]
pub(crate) struct ManualRosterConstructionAuditV2 {
    pub(crate) approval_digest: String,
    pub(crate) committed_head: AuthorityHead,
}
impl ManualRosterConstructionProposalV2 {
    pub(crate) fn review_digest(&self) -> Result<String> {
        self.check_current()?;
        Ok(self.reviewed_digest.clone())
    }
    pub(crate) fn display(&self) -> Result<String> {
        self.check_current()?;
        serde_json::to_string_pretty(&serde_json::json!({
            "operation":"Approve one exact non-signing construction invocation",
            "notice":"This approves only the complete displayed final proposal, exact original selected inputs and return, complete sorted participant retention commitments, original V2 roster and policy, and immutable common invocation. Retention permission remains separate. A fresh continued V2 writer attempt, actual caller binding and separate current signer-native full-proposal review are still required for Reserve and one-use Consume. Each reservation charges the original account ledger and all selected inputs conservatively. Already-consumed non-signing work may complete after owner focus handoff, only within the original deadline. Cancellation stops new admission; consumption, expiry and cancellation never refund or erase retained exposure. The original lifetime budget is unchanged. No proving, signing, release, dispatch, replacement, restore or new genesis is authorized.",
            "extension":self.extension,"approval":self.approval,
            "owner_signature_evidence_digest":self.signature_evidence,"review_digest":self.reviewed_digest,
            "current_head":self.expected_head,"already_committed_exact_audit_retry":self.existing.is_some()
        })).map_err(|_|AuthorityError::InvalidBinding)
    }
    pub(crate) fn first_commit_deadline_ms(&self) -> Option<u64> {
        self.existing
            .is_none()
            .then_some(self.approval.initial_commit_deadline_ms)
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
        let birth = crate::pending_birth_storage::read(c.connection(), &ledger.policy)?
            .ok_or(AuthorityError::CorruptHistory)?;
        self.extension.validate_original_birth(&birth)?;
        if ledger.manual_roster_extension()?.map(|r| &r.extension) != Some(&self.extension) {
            return Err(AuthorityError::Conflict);
        }
        if ledger.snapshot.head != self.expected_head {
            return Err(AuthorityError::StaleHead);
        }
        let operation = self.approval.owner_operation_id(&self.extension)?;
        match (&self.existing, ledger.operations.get(&operation)) {
            (None, None) => ledger.validate_new_roster_construction_approval_v2(
                &ManualRosterConstructionApprovalRecordV2 {
                    approval: self.approval.clone(),
                    owner_signature_evidence_digest: self.signature_evidence.clone(),
                    native_review_digest: self.reviewed_digest.clone(),
                },
                now_ms()?,
            )?,
            (
                Some(_),
                Some((
                    AuthorityMutation::OwnerControl(OwnerControlRequest {
                        control: OwnerControl::ApproveManualRosterConstructionV2 { record },
                        ..
                    }),
                    _,
                    MutationResult::Controlled(_),
                )),
            ) if record.approval == self.approval => {}
            _ => return Err(AuthorityError::Conflict),
        }
        Ok(())
    }
}
pub(crate) fn prepare_manual_roster_construction_v2(
    input: NamespaceOpenInput,
    signature: VerifiedManualRosterConstructionOwnerSignatureV2,
) -> Result<ManualRosterConstructionProposalV2> {
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
    let approval = signature.approval().clone();
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
        if ledger.manual_roster_extension()?.map(|r| &r.extension) != Some(&extension) {
            return Err(AuthorityError::Conflict);
        }
        let existing = match ledger
            .operations
            .get(&approval.owner_operation_id(&extension)?)
        {
            None => None,
            Some((
                AuthorityMutation::OwnerControl(OwnerControlRequest {
                    control: OwnerControl::ApproveManualRosterConstructionV2 { record },
                    ..
                }),
                _,
                MutationResult::Controlled(snapshot),
            )) if record.approval == approval => Some(ManualRosterConstructionAuditV2 {
                approval_digest: approval.digest_for(&extension)?,
                committed_head: snapshot.head.clone(),
            }),
            Some(_) => return Err(AuthorityError::Conflict),
        };
        (ledger.snapshot.head, existing)
    };
    let signature_evidence = signature.evidence_digest().to_owned();
    let reviewed_digest = digest(
        "wholepact:native-manual-roster-construction-review:v2",
        &(
            &extension,
            &approval,
            &signature_evidence,
            &expected_head,
            existing.is_some(),
        ),
    )?;
    let proposal = ManualRosterConstructionProposalV2 {
        journal,
        extension,
        approval,
        signature_evidence,
        expected_head,
        reviewed_digest,
        existing,
    };
    proposal.check_current()?;
    Ok(proposal)
}
pub(crate) fn commit_manual_roster_construction_v2(
    decision: NativeManualRosterConstructionDecisionV2,
) -> Result<ManualRosterConstructionAuditV2> {
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
    let record = ManualRosterConstructionApprovalRecordV2 {
        approval: proposal.approval.clone(),
        owner_signature_evidence_digest: proposal.signature_evidence,
        native_review_digest: proposal.reviewed_digest,
    };
    ledger.validate_new_roster_construction_approval_v2(&record, now)?;
    let event = Event {
        mutation: AuthorityMutation::OwnerControl(OwnerControlRequest {
            operation_id: proposal.approval.owner_operation_id(&proposal.extension)?,
            account_id: ledger.policy.account_id.clone(),
            network_profile_id: ledger.policy.network_profile_id.clone(),
            writer_epoch: ledger.snapshot.writer_epoch,
            expected_head: ledger.snapshot.head.clone(),
            control: OwnerControl::ApproveManualRosterConstructionV2 {
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
    if final_now < now || final_now >= proposal.approval.initial_commit_deadline_ms {
        return Err(AuthorityError::Expired);
    }
    tx.commit()?;
    Ok(ManualRosterConstructionAuditV2 {
        approval_digest: proposal.approval.digest_for(&proposal.extension)?,
        committed_head: ledger.snapshot.head,
    })
}
