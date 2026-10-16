//! Dedicated restrictive native-owner publication. Generic born bootstrap stays
//! closed. The original namespace, exact owner signature and final native click
//! are all retained through one current-head compare-and-swap transaction.
use crate::account_use::{AccountUseGenesis, PermanentAccountExclusion};
use crate::account_use_link::AccountExclusionReceipt;
use crate::native_witness_owner::NativePermanentExclusionDecisionV1;
use crate::permanent_exclusion_signature::VerifiedPermanentExclusionOwnerSignatureV1;
use crate::witness_locator::{open_born_history, NamespaceOpenInput};
use crate::{policy::Event, *};
use rusqlite::{params, Transaction, TransactionBehavior};

pub(crate) const ACTIVATION_QUALIFIED_V1: bool = false;
pub(crate) struct PermanentExclusionProposalV1 {
    journal: AuthorityJournal,
    genesis: AccountUseGenesis,
    exclusion: PermanentAccountExclusion,
    expected_head: AuthorityHead,
    signature_evidence: String,
    reviewed_digest: String,
    existing: Option<AccountExclusionReceipt>,
}
fn require_original(
    ledger: &crate::policy::Ledger,
    genesis: &AccountUseGenesis,
    exclusion: &PermanentAccountExclusion,
) -> Result<()> {
    genesis.validate()?;
    exclusion.validate()?;
    // journal::load replayed every supported event. A retirement restriction
    // must not use the empty/preconstruction enrollment admission gate.
    if ledger.policy.account_use_genesis.as_ref() != Some(genesis)
        || ledger.manual_roster_extension()?.is_none()
        || exclusion.identity != genesis.identity
        || exclusion.genesis_digest != genesis.digest()?
    {
        return Err(AuthorityError::InvalidBinding);
    }
    if let Some(old) = ledger.account_use_history.exclusion() {
        if old != exclusion {
            return Err(AuthorityError::Conflict);
        }
    }
    Ok(())
}
fn original_receipt(
    ledger: &crate::policy::Ledger,
    genesis: &AccountUseGenesis,
    exclusion: &PermanentAccountExclusion,
) -> Result<Option<AccountExclusionReceipt>> {
    if ledger.account_use_history.exclusion().is_none() {
        return Ok(None);
    }
    let (mutation, _, result) = ledger
        .operations
        .get(&exclusion.operation_id)
        .ok_or(AuthorityError::CorruptHistory)?;
    match mutation {
        AuthorityMutation::OwnerControl(request)
            if request.operation_id == exclusion.operation_id
                && request.account_id == genesis.identity.account_id
                && matches!(&request.control, OwnerControl::PermanentlyExcludeAccount { exclusion: original } if original == exclusion) =>
            {}
        _ => return Err(AuthorityError::CorruptHistory),
    }
    let MutationResult::Controlled(snapshot) = result else {
        return Err(AuthorityError::CorruptHistory);
    };
    Ok(Some(AccountExclusionReceipt {
        genesis_digest: genesis.digest()?,
        exclusion_digest: exclusion.digest()?,
        witness_origin_digest: genesis.witness_origin_digest.clone(),
        committed_head: snapshot.head.clone(),
        operation_id: exclusion.operation_id.clone(),
    }))
}
impl PermanentExclusionProposalV1 {
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
        require_original(&ledger, &self.genesis, &self.exclusion)?;
        if ledger.snapshot.head != self.expected_head
            || original_receipt(&ledger, &self.genesis, &self.exclusion)? != self.existing
        {
            return Err(AuthorityError::StaleHead);
        }
        Ok(())
    }
    pub(crate) fn review_digest(&self) -> Result<String> {
        self.check_current()?;
        Ok(self.reviewed_digest.clone())
    }
    pub(crate) fn display(&self) -> Result<String> {
        self.check_current()?;
        let c = self
            .journal
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let ledger = crate::journal::load(c.connection())?;
        serde_json::to_string_pretty(&serde_json::json!({
            "operation": "Permanently stop routine reuse of this exact born account",
            "notice": "Irreversible local restriction. All released authorization, reservations, consumed lifetime capacity and observation records remain. This neither recovers funds, proves an empty account, revokes a disclosed viewing key nor synchronizes arbitrary external applications. Active writer pointers are closed; previously released effects may still execute.",
            "genesis": self.genesis, "exclusion": self.exclusion,
            "original_owner_signature_evidence_digest": self.signature_evidence,
            "expected_head": self.expected_head, "pending_and_retained_exposure": ledger.snapshot,
            "all_retained_original_operations": ledger.operations.values().map(|(mutation, _, result)| (mutation,result)).collect::<Vec<_>>(),
            "review_digest": self.reviewed_digest, "exact_committed_retry": self.existing.is_some(),
        })).map_err(|_| AuthorityError::InvalidBinding)
    }
}
pub(crate) fn prepare_permanent_exclusion_v1(
    input: NamespaceOpenInput,
    signature: VerifiedPermanentExclusionOwnerSignatureV1,
) -> Result<PermanentExclusionProposalV1> {
    if !ACTIVATION_QUALIFIED_V1 {
        return Err(AuthorityError::PermanentStopUnavailable);
    }
    if input.owner_certificate_digest != signature.certificate_digest()
        || input.expected_account_id != signature.genesis().identity.account_id
    {
        return Err(AuthorityError::Permission);
    }
    let journal = open_born_history(input)?;
    journal
        .born_owner
        .as_ref()
        .ok_or(AuthorityError::Permission)?
        .check_mutation_current()?;
    let genesis = signature.genesis().clone();
    let exclusion = signature.exclusion().clone();
    let (expected_head, existing) = {
        let c = journal
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let ledger = crate::journal::load(c.connection())?;
        require_original(&ledger, &genesis, &exclusion)?;
        let birth = crate::pending_birth_storage::read(c.connection(), &ledger.policy)?
            .ok_or(AuthorityError::CorruptHistory)?;
        if birth.request.policy.account_use_genesis.as_ref() != Some(&genesis) {
            return Err(AuthorityError::InvalidBinding);
        }
        (
            ledger.snapshot.head.clone(),
            original_receipt(&ledger, &genesis, &exclusion)?,
        )
    };
    let signature_evidence = signature.evidence_digest().to_owned();
    let reviewed_digest = digest(
        "wholepact:native-permanent-exclusion-review:v1",
        &(
            &genesis,
            &exclusion,
            &signature_evidence,
            &expected_head,
            existing.is_some(),
        ),
    )?;
    let p = PermanentExclusionProposalV1 {
        journal,
        genesis,
        exclusion,
        expected_head,
        signature_evidence,
        reviewed_digest,
        existing,
    };
    p.check_current()?;
    Ok(p)
}
pub(crate) fn commit_permanent_exclusion_v1(
    decision: NativePermanentExclusionDecisionV1,
) -> Result<AccountExclusionReceipt> {
    if !ACTIVATION_QUALIFIED_V1 {
        return Err(AuthorityError::PermanentStopUnavailable);
    }
    let (p, lease) = decision.into_parts();
    p.check_current()?;
    lease.check_current()?;
    if lease.reviewed_digest() != p.reviewed_digest {
        return Err(AuthorityError::Permission);
    }
    let publication = lease.publication_lease()?;
    publication.check_current()?;
    p.check_current()?;
    if let Some(receipt) = p.existing {
        publication.check_current()?;
        return Ok(receipt);
    }
    let owner = p
        .journal
        .born_owner
        .as_ref()
        .ok_or(AuthorityError::Permission)?;
    owner.check_mutation_current()?;
    let c = p
        .journal
        .connection
        .lock()
        .map_err(|_| AuthorityError::Storage)?;
    let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate)?;
    let mut ledger = crate::journal::load(&tx)?;
    require_original(&ledger, &p.genesis, &p.exclusion)?;
    if ledger.snapshot.head != p.expected_head {
        return Err(AuthorityError::StaleHead);
    }
    let event = Event {
        mutation: AuthorityMutation::OwnerControl(OwnerControlRequest {
            operation_id: p.exclusion.operation_id.clone(),
            account_id: p.genesis.identity.account_id.clone(),
            network_profile_id: p.genesis.identity.network_profile_id.clone(),
            writer_epoch: ledger.snapshot.writer_epoch,
            expected_head: ledger.snapshot.head.clone(),
            control: OwnerControl::PermanentlyExcludeAccount {
                exclusion: p.exclusion.clone(),
            },
        }),
        authenticated_certificate_digest: p.genesis.owner_certificate_digest.clone(),
        witness_time_ms: now_ms()?,
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
    if publication.reviewed_digest() != p.reviewed_digest
        || publication.admitted_at_ms() > now_ms()?
    {
        return Err(AuthorityError::Permission);
    }
    tx.commit()?;
    original_receipt(&ledger, &p.genesis, &p.exclusion)?.ok_or(AuthorityError::CorruptHistory)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dedicated_restriction_retains_nonempty_construction_and_original_retry_head() {
        // Pure recorded ledger replay. No native decision, namespace owner,
        // socket, signing key, proof or live financial capability is created.
        let (_, _, _, mut ledger) =
            crate::manual_roster_construction_v2::tests::construction_fixture();
        let genesis = ledger.policy.account_use_genesis.clone().unwrap();
        let exclusion = PermanentAccountExclusion {
            version: 1,
            identity: genesis.identity.clone(),
            genesis_digest: genesis.digest().unwrap(),
            operation_id: "synthetic-stop-reuse".into(),
            native_review_digest: "91".repeat(32),
            reason: crate::account_use::ExclusionReason::RetirementRequested,
        };
        assert!(ledger.snapshot.outstanding_debit_zatoshis > 0);
        require_original(&ledger, &genesis, &exclusion).unwrap();
        let before = (
            ledger.snapshot.outstanding_debit_zatoshis,
            ledger.snapshot.settled_debit_zatoshis,
            ledger.snapshot.reserved_input_value_zatoshis,
        );
        let event = Event {
            mutation: AuthorityMutation::OwnerControl(OwnerControlRequest {
                operation_id: exclusion.operation_id.clone(),
                account_id: genesis.identity.account_id.clone(),
                network_profile_id: genesis.identity.network_profile_id.clone(),
                writer_epoch: ledger.snapshot.writer_epoch,
                expected_head: ledger.snapshot.head.clone(),
                control: OwnerControl::PermanentlyExcludeAccount {
                    exclusion: exclusion.clone(),
                },
            }),
            authenticated_certificate_digest: genesis.owner_certificate_digest.clone(),
            witness_time_ms: 200_000,
            writer_session_id: None,
            original_request_link: None,
        };
        ledger.apply(&event).unwrap();
        require_original(&ledger, &genesis, &exclusion).unwrap();
        assert_eq!(
            before,
            (
                ledger.snapshot.outstanding_debit_zatoshis,
                ledger.snapshot.settled_debit_zatoshis,
                ledger.snapshot.reserved_input_value_zatoshis
            )
        );
        let first = original_receipt(&ledger, &genesis, &exclusion)
            .unwrap()
            .unwrap();
        ledger.apply(&event).unwrap();
        assert!(
            original_receipt(&ledger, &genesis, &exclusion)
                .unwrap()
                .as_ref()
                == Some(&first)
        );
        let mut changed = exclusion.clone();
        changed.native_review_digest = "92".repeat(32);
        assert!(require_original(&ledger, &genesis, &changed).is_err());
    }
}
