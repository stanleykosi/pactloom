//! Independent native witness decision for one inert pending transport grant.
//! The owner-controlled GUI alone can construct the commit decision. The signed
//! source preauthorization proves admission only; it is never a writer grant.
use crate::construction_transport_handoff_v1::*;
use crate::native_witness_owner::NativeConstructionTransportGrantDecisionV1;
use crate::witness_locator::{NamespaceOpenInput, open_born_history};
use crate::*;

pub(crate) struct ConstructionTransportGrantProposalV1 {
    journal: AuthorityJournal,
    grant: ConstructionTransportGrantV1,
    owner_certificate_digest: String,
    review_digest: String,
    complete_history_display: String,
}
impl ConstructionTransportGrantProposalV1 {
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
        if ledger.policy.owner_certificate_digest != self.owner_certificate_digest {
            return Err(AuthorityError::Permission);
        }
        ledger.validate_construction_transport_grant(&self.grant, now_ms()?)
    }
    pub(crate) fn review_digest(&self) -> Result<String> {
        self.check_current()?;
        Ok(self.review_digest.clone())
    }
    pub(crate) fn first_commit_deadline_ms(&self) -> Option<u64> {
        Some(self.grant.authorization.authorization.expires_at_ms)
    }
    pub(crate) fn display(&self) -> Result<String> {
        self.check_current()?;
        serde_json::to_string_pretty(&serde_json::json!({
            "operation": "Grant one inert construction transport handoff",
            "notice": "SOURCE-STAGED, NOT ACTIVATED. The original Host must already hold ALL real additional-read observations before it releases this signed admission for review. A copied completion flag cannot establish that fact. This decision records one pending grant, with no active credential, budget charge, signing or dispatch authority. Before claim, an explicitly selected one-grant server may disclose bounded Snapshot/ReadHistory pages of this exact pending head to the SAME authenticated original writer certificate for fresh native reconciliation, only while its original session and grant remain active. Each such read closes its connection; it grants no claim, key, mutation or renewed deadline. Only a new genuine native original-owner decision may bind the exact post-grant head to one fresh TLS exporter. Its atomic claim permanently fences the original general transport key. Original account, genesis, writer session and attempt, exact read and proposal, fixed nonce, expiry, input fences and lifetime accounting remain unchanged. Any intervening event, timeout, lost native state or uncertain claim is terminal. No rekey retry, session renewal, financial/offline authority, proof, replacement or recovery is authorized.",
            "grant": self.grant,
            "exact_native_review_digest": self.review_digest,
            "complete_authenticated_history": self.complete_history_display,
        })).map_err(|_| AuthorityError::InvalidBinding)
    }
}

pub(crate) fn prepare_construction_transport_grant_v1(
    input: NamespaceOpenInput,
    authorization: SignedConstructionTransportPreauthorizationV1,
) -> Result<ConstructionTransportGrantProposalV1> {
    authorization.verify(&input.owner_certificate_digest)?;
    if input.expected_account_id != authorization.authorization.account_id {
        return Err(AuthorityError::Permission);
    }
    let owner_certificate_digest = input.owner_certificate_digest.clone();
    let journal = open_born_history(input)?;
    journal
        .born_owner
        .as_ref()
        .ok_or(AuthorityError::Permission)?
        .check_mutation_current()?;
    let (expected_head, complete_history_display) = {
        let c = journal
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let ledger = crate::journal::load(c.connection())?;
        ledger.require_supported_manual_history()?;
        ledger.validate_construction_transport_authorization(
            &authorization.authorization,
            now_ms()?,
        )?;
        if ledger.policy.owner_certificate_digest != owner_certificate_digest {
            return Err(AuthorityError::Permission);
        }
        let entries = ledger.operations.values().collect::<Vec<_>>();
        let history = serde_json::json!({
            "policy": ledger.policy,
            "snapshot": ledger.snapshot,
            "account_use_history": {
                "genesis": ledger.account_use_history.genesis(),
                "permanent_exclusion": ledger.account_use_history.exclusion(),
                "checkpoint": ledger.account_use_history.checkpoint()?,
            },
            "complete_operations": entries,
        });
        bounded(&history, MAX_CONSTRUCTION_TRANSPORT_HISTORY_BYTES)?;
        (
            ledger.snapshot.head.clone(),
            serde_json::to_string_pretty(&history).map_err(|_| AuthorityError::InvalidBinding)?,
        )
    };
    let granted_at_ms = now_ms()?;
    let review_digest = digest(
        "wholepact:native-construction-transport-grant-review:v1",
        &(
            &authorization,
            &owner_certificate_digest,
            &expected_head,
            granted_at_ms,
        ),
    )?;
    let grant = ConstructionTransportGrantV1 {
        version: 1,
        operation_id: format!("construct-transport-grant-{}", authorization.digest()?),
        authorization,
        expected_head,
        native_review_digest: review_digest.clone(),
        granted_at_ms,
    };
    grant.validate()?;
    let proposal = ConstructionTransportGrantProposalV1 {
        journal,
        grant,
        owner_certificate_digest,
        review_digest,
        complete_history_display,
    };
    proposal.check_current()?;
    Ok(proposal)
}

pub(crate) fn commit_construction_transport_grant_v1(
    decision: NativeConstructionTransportGrantDecisionV1,
) -> Result<PendingConstructionTransportGrantV1> {
    let (proposal, lease) = decision.into_parts();
    proposal.check_current()?;
    lease.check_current()?;
    if lease.reviewed_digest() != proposal.review_digest {
        return Err(AuthorityError::Permission);
    }
    let publication = lease.publication_lease()?;
    publication.check_current()?;
    if publication.reviewed_digest() != proposal.review_digest {
        return Err(AuthorityError::Permission);
    }
    proposal.journal.commit_construction_transport_grant(
        proposal.grant.clone(),
        &proposal.owner_certificate_digest,
        &|| {
            publication.check_current()?;
            proposal
                .journal
                .born_owner
                .as_ref()
                .ok_or(AuthorityError::Permission)?
                .check_mutation_current()
        },
    )
}
