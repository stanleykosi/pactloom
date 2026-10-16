//! Witness-owned observation. Client JSON can request a check, never supply a result.
use crate::reservation_view::ReservationView;
use crate::{
    policy::{Event, Ledger},
    *,
};
use rusqlite::{Transaction, TransactionBehavior, params};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use wholepact_chain::{
    SubmissionDescriptor,
    local_node::{LocalNodeSourceDescriptor, LocalValidatingNode},
};

pub fn resolution_source_digest(source: &LocalNodeSourceDescriptor) -> Result<String> {
    source
        .validate()
        .map_err(|_| AuthorityError::InvalidBinding)?;
    digest("wholepact:authority-resolution-source:v1", source)
}
/// Minted only after the enrolled witness answers over authenticated TLS. This is
/// live evidence of independent witness commit, never a new spending permission.
pub struct AuthenticatedResolutionReceipt {
    pub(crate) receipt: ResolutionReceipt,
    pub(crate) certificate: String,
    pub(crate) deadline: Instant,
}
impl AuthenticatedResolutionReceipt {
    pub fn receipt(&self) -> &ResolutionReceipt {
        &self.receipt
    }
    pub fn authenticated_witness_certificate_digest(&self) -> &str {
        &self.certificate
    }
    pub fn check_current(&self) -> Result<()> {
        if Instant::now() >= self.deadline {
            Err(AuthorityError::ResolutionUnavailable)
        } else {
            Ok(())
        }
    }
}
impl AuthorityJournal {
    /// Runtime attachment only; it cannot enroll a source or change trust. The
    /// exact descriptor must already be owner-authenticated in protected history.
    pub fn attach_resolution_node(&self, node: Arc<LocalValidatingNode>) -> Result<()> {
        self.require_born_mutation_current()?;
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let ledger = crate::journal::load(c.connection())?;
        if ledger.resolution_source.as_ref()
            != Some(&resolution_source_digest(&node.source_descriptor())?)
        {
            return Err(AuthorityError::Permission);
        }
        *self
            .resolution_node
            .lock()
            .map_err(|_| AuthorityError::Storage)? = Some(node);
        Ok(())
    }
    fn qualify_original(
        &self,
        ledger: &Ledger,
        operation: &str,
        conflict: Option<&wholepact_chain::local_node::CanonicalConflictCandidate>,
    ) -> Result<(ResolutionRecord, String)> {
        self.require_born_mutation_current()?;
        let (_, _, result) = ledger
            .operations
            .get(operation)
            .ok_or(AuthorityError::InvalidBinding)?;
        let request = ReservationView::from_result(result).ok_or(AuthorityError::InvalidBinding)?;
        let (bytes, txid) = ledger
            .final_transactions
            .get(operation)
            .ok_or(AuthorityError::ResolutionUnavailable)?;
        let node = self
            .resolution_node
            .lock()
            .map_err(|_| AuthorityError::Storage)?
            .clone()
            .ok_or(AuthorityError::ResolutionUnavailable)?;
        let source = node.source_descriptor();
        let source_digest = resolution_source_digest(&source)?;
        if ledger.resolution_source.as_ref() != Some(&source_digest) {
            return Err(AuthorityError::Permission);
        }
        if request.network_profile_id != "ironwood-testnet-nu7-candidate"
            || source.network != "testnet"
            || source.consensus_branch_id != wholepact_chain::NU7_BRANCH_ID
        {
            return Err(AuthorityError::ResolutionUnavailable);
        }
        let descriptor = SubmissionDescriptor {
            operation_id: request.operation_id.to_owned(),
            obligation_id: request.obligation_id.to_owned(),
            proposal_id: request.proposal_id.to_owned(),
            transaction_id: txid.clone(),
            bytes_sha256: bytes.clone(),
            expiry_height: request.transaction_expiry_height,
            network: source.network.clone(),
            consensus_branch_id: source.consensus_branch_id,
        };
        let inputs: Vec<_> = request
            .inputs
            .iter()
            .map(|i| (i.action_index, i.nullifier.clone()))
            .collect();
        let qualified = match conflict {
            Some(candidate) => node.qualify_admission_conflict(
                &descriptor,
                candidate,
                request.effects_digest,
                &inputs,
            ),
            None => node.qualify_admission(&descriptor),
        }
        .map_err(|_| AuthorityError::ResolutionUnavailable)?;
        qualified
            .check_source(&source)
            .map_err(|_| AuthorityError::ResolutionUnavailable)?;
        if qualified.descriptor() != &descriptor
            || qualified.target_shielded_sighash() != request.effects_digest
            || !request.inputs.iter().all(|i| {
                qualified
                    .target_inputs()
                    .contains(&(i.action_index, i.nullifier.clone()))
            })
        {
            return Err(AuthorityError::InvalidBinding);
        }
        let archive = qualified
            .evidence_json()
            .map_err(|_| AuthorityError::ResolutionUnavailable)?;
        let canonical: serde_json::Value =
            serde_json::from_str(&archive).map_err(|_| AuthorityError::InvalidBinding)?;
        let inclusion_block_hash = canonical
            .pointer("/inclusion/hash")
            .and_then(|v| v.as_str())
            .ok_or(AuthorityError::InvalidBinding)?
            .to_owned();
        let inclusion_block_height = canonical
            .pointer("/inclusion/height")
            .and_then(|v| v.as_u64())
            .ok_or(AuthorityError::InvalidBinding)?;
        let record = ResolutionRecord {
            operation_id: format!("resolution-{}", ledger.snapshot.head.sequence + 1),
            account_id: request.account_id.to_owned(),
            network_profile_id: request.network_profile_id.to_owned(),
            expected_head: ledger.snapshot.head.clone(),
            reservation_operation_id: operation.into(),
            reservation_request_digest: request.request_digest.to_owned(),
            final_transaction_id: txid.clone(),
            final_transaction_digest: bytes.clone(),
            source_descriptor_digest: source_digest,
            evidence_digest: qualified
                .evidence_id()
                .map_err(|_| AuthorityError::ResolutionUnavailable)?,
            consumed_nullifiers: match conflict {
                Some(c) => vec![c.nullifier.clone()],
                None => request.inputs.iter().map(|i| i.nullifier.clone()).collect(),
            },
            conflict: conflict.cloned(),
            inclusion_block_hash,
            inclusion_block_height,
        };
        qualified
            .check_source(&source)
            .map_err(|_| AuthorityError::ResolutionUnavailable)?;
        Ok((record, archive))
    }
    pub(crate) fn revalidate_resolutions(&self, ledger: &Ledger) -> Result<()> {
        self.require_born_mutation_current()?;
        // All are checked under the same SQLite write transaction that admits a
        // new reservation. Any missing, stale, changed or unavailable evidence
        // reopens every released budget before another authorization is issued.
        let started = Instant::now();
        for operation in ledger.resolutions.keys() {
            let original = &ledger.resolutions[operation].record;
            let (fresh, _) =
                self.qualify_original(ledger, operation, original.conflict.as_ref())?;
            if !same_canonical_resolution(&fresh, original) {
                return Err(AuthorityError::ResolutionUnavailable);
            }
        }
        if started.elapsed() >= Duration::from_secs(30) {
            return Err(AuthorityError::ResolutionUnavailable);
        }
        Ok(())
    }
    pub(crate) fn append_reopen(
        &self,
        tx: &Transaction<'_>,
        ledger: &mut Ledger,
        now: u64,
    ) -> Result<()> {
        self.require_born_mutation_current()?;
        let mutation = AuthorityMutation::ReopenResolutions(ReopenResolutions {
            operation_id: format!("reopen-{}", ledger.snapshot.head.sequence + 1),
            account_id: ledger.policy.account_id.clone(),
            network_profile_id: ledger.policy.network_profile_id.clone(),
            expected_head: ledger.snapshot.head.clone(),
        });
        append(tx, ledger, mutation, now)?;
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn resolve_reservation(
        &self,
        peer: &str,
        account: &str,
        network: &str,
        operation: &str,
    ) -> Result<ResolutionReceipt> {
        self.resolve_reservation_selected(peer, account, network, operation, None)
    }
    pub(crate) fn resolve_reservation_selected(
        &self,
        peer: &str,
        account: &str,
        network: &str,
        operation: &str,
        conflict: Option<&wholepact_chain::local_node::CanonicalConflictCandidate>,
    ) -> Result<ResolutionReceipt> {
        self.require_born_mutation_current()?;
        id(operation)?;
        let c = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate)?;
        crate::journal::authenticate_admission(&tx, peer)?;
        let mut ledger = crate::journal::load(&tx)?;
        ledger.authenticate_read(peer, account, network)?;
        if ledger.snapshot.writer_status == WriterStatus::Quarantined {
            return Err(AuthorityError::RecoveryRequired);
        }
        let now = now_ms()?.max(ledger.snapshot.last_witness_time_ms);
        let (record, archive) = match self.qualify_original(&ledger, operation, conflict) {
            Ok(value) => value,
            Err(error) => {
                if !ledger.resolutions.is_empty() {
                    self.append_reopen(&tx, &mut ledger, now)?;
                    tx.commit()?;
                }
                return Err(error);
            }
        };
        if let Some(existing) = ledger.resolutions.get(operation) {
            if same_canonical_resolution(&existing.record, &record) {
                return Ok(existing.clone());
            }
            self.append_reopen(&tx, &mut ledger, now)?;
            tx.commit()?;
            return Err(AuthorityError::ResolutionUnavailable);
        }
        // Full private canonical evidence and immutable resolution commit together.
        let evidence_bytes: u64 = tx.query_row(
            "SELECT coalesce(sum(length(payload)),0) FROM authority_resolution_evidence",
            [],
            |r| r.get(0),
        )?;
        if evidence_bytes
            .checked_add(archive.len() as u64)
            .is_none_or(|n| n > MAX_JOURNAL_BYTES)
        {
            return Err(AuthorityError::Limit);
        }
        tx.execute(
            "INSERT OR IGNORE INTO authority_resolution_evidence VALUES(?1,?2)",
            params![record.evidence_digest, archive.as_bytes()],
        )?;
        let MutationResult::ResolutionRecorded(receipt) = append(
            &tx,
            &mut ledger,
            AuthorityMutation::QualifiedResolution(record),
            now,
        )?
        else {
            return Err(AuthorityError::CorruptHistory);
        };
        tx.commit()?;
        Ok(*receipt)
    }
}
fn append(
    tx: &Transaction<'_>,
    ledger: &mut Ledger,
    mutation: AuthorityMutation,
    now: u64,
) -> Result<MutationResult> {
    let event = Event {
        original_request_link: None,
        mutation,
        authenticated_certificate_digest: ledger.policy.owner_certificate_digest.clone(),
        witness_time_ms: now,
        writer_session_id: None,
    };
    let previous = ledger.snapshot.head.digest.clone();
    let result = ledger.apply(&event)?;
    let payload = encode(&event)?;
    let bytes: u64 = tx.query_row(
        "SELECT coalesce(sum(length(payload)),0) FROM authority_events",
        [],
        |r| r.get(0),
    )?;
    if bytes
        .checked_add(payload.len() as u64)
        .is_none_or(|n| n > MAX_JOURNAL_BYTES)
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
            &*payload
        ],
    )?;
    Ok(result)
}

// Fresh evidence may have a new timestamp/digest/head, but cannot silently swap
// either original or alternative or move its canonical inclusion after a reorg.
fn same_canonical_resolution(a: &ResolutionRecord, b: &ResolutionRecord) -> bool {
    a.account_id == b.account_id
        && a.network_profile_id == b.network_profile_id
        && a.reservation_operation_id == b.reservation_operation_id
        && a.reservation_request_digest == b.reservation_request_digest
        && a.final_transaction_id == b.final_transaction_id
        && a.final_transaction_digest == b.final_transaction_digest
        && a.source_descriptor_digest == b.source_descriptor_digest
        && a.conflict == b.conflict
        && a.consumed_nullifiers == b.consumed_nullifiers
        && a.inclusion_block_hash == b.inclusion_block_hash
        && a.inclusion_block_height == b.inclusion_block_height
}

#[cfg(test)]
mod conflict_revalidation_tests {
    use super::*;
    #[test]
    fn canonical_conflict_revalidation_requires_same_original_alternative_and_block() {
        let record = ResolutionRecord {
            operation_id: "synthetic-resolution".into(),
            account_id: "synthetic-account".into(),
            network_profile_id: "ironwood-testnet-nu7-candidate".into(),
            expected_head: AuthorityHead {
                sequence: 1,
                digest: "11".repeat(32),
            },
            reservation_operation_id: "synthetic-original".into(),
            reservation_request_digest: "22".repeat(32),
            final_transaction_id: "33".repeat(32),
            final_transaction_digest: "44".repeat(32),
            source_descriptor_digest: "55".repeat(32),
            evidence_digest: "66".repeat(32),
            consumed_nullifiers: vec!["77".repeat(32)],
            conflict: Some(wholepact_chain::local_node::CanonicalConflictCandidate {
                included_transaction_id: "88".repeat(32),
                original_transaction_hex: "00".into(),
                nullifier: "77".repeat(32),
            }),
            inclusion_block_hash: "99".repeat(32),
            inclusion_block_height: 4_500_000,
        };
        let mut refreshed = record.clone();
        refreshed.evidence_digest = "aa".repeat(32);
        refreshed.expected_head.sequence += 1;
        assert!(same_canonical_resolution(&record, &refreshed));
        for mode in 0..8 {
            let mut changed = record.clone();
            match mode {
                0 => changed.inclusion_block_hash = "ab".repeat(32),
                1 => changed.inclusion_block_height += 1,
                2 => changed.conflict.as_mut().unwrap().included_transaction_id = "ac".repeat(32),
                3 => changed.conflict.as_mut().unwrap().nullifier = "ad".repeat(32),
                4 => changed.final_transaction_digest = "ae".repeat(32),
                5 => changed.reservation_operation_id.push('2'),
                6 => changed.source_descriptor_digest = "af".repeat(32),
                _ => changed.conflict = None,
            }
            assert!(
                !same_canonical_resolution(&record, &changed),
                "changed {mode}"
            );
        }
    }
}
