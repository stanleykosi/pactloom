//! Independent signer settlement provenance. No serialized report can release
//! signer exposure. Original consent, release and signed result stay immutable.
use super::*;
use pczt::{Pczt, roles::signer::Signer};
use sha2::Digest;
use std::collections::BTreeSet;
use wholepact_chain::settlement_evidence::RetainedSettlementObservation;
use wholepact_chain::{BackendIdentity, ConfirmationPolicy};

/// Created only by re-reading the protected signer journal and parsing the
/// exact originally verified PCZT. It is neither portable nor deserializable.
pub struct SignerSettlementBinding {
    journal: SignerJournalBinding,
    authorization_id: String,
    original_consent_ref: String,
    account_id: String,
    obligation_id: String,
    effects_digest: String,
    expiry_height: u32,
    inputs: Vec<(u64, String)>,
    witness_certificate_digest: String,
}
impl SignerSettlementBinding {
    pub fn authorization_id(&self) -> &str {
        &self.authorization_id
    }
    pub fn original_consent_ref(&self) -> &str {
        &self.original_consent_ref
    }
    pub fn account_id(&self) -> &str {
        &self.account_id
    }
    pub fn obligation_id(&self) -> &str {
        &self.obligation_id
    }
    pub fn effects_digest(&self) -> &str {
        &self.effects_digest
    }
    pub fn expiry_height(&self) -> u32 {
        self.expiry_height
    }
    pub fn inputs(&self) -> &[(u64, String)] {
        &self.inputs
    }
    pub fn witness_certificate_digest(&self) -> &str {
        &self.witness_certificate_digest
    }
}
impl SignerConsentJournal {
    /// This reads actual retained originals and bridge bytes under native read
    /// authority, rather than accepting a proposal, imported evidence or summary.
    pub fn settlement_binding(
        &self,
        authorization_id: &str,
        session: &SignerConsentSession,
    ) -> Result<SignerSettlementBinding> {
        let lease = self.acquire_original_authorization(authorization_id, session)?;
        let request = self
            .bridge_request(&lease)
            .map_err(|_| JournalError::InvalidBinding)?;
        let bytes = request
            .artifact()
            .map_err(|_| JournalError::InvalidBinding)?;
        let original = lease.evidence();
        let t = original.original_consent().terms();
        let parsed = Pczt::parse(&bytes).map_err(|_| JournalError::InvalidBinding)?;
        let inputs = exact_inputs(&parsed, &t.input_bindings)?;
        let effects = Signer::new(parsed)
            .map_err(|_| JournalError::InvalidBinding)?
            .shielded_sighash();
        if hex::encode(effects) != t.effects_digest {
            return Err(JournalError::InvalidBinding);
        }
        let c = self.connection.lock().map_err(|_| JournalError::Database)?;
        // Requires both authenticated witness reservation retained at signing and
        // durable key-use/result history. A consent-only record is insufficient.
        bridge_storage::read_validated_result(&c, authorization_id, original)
            .map_err(|_| JournalError::InvalidBinding)?;
        let permit = bridge_storage::read_permit(&c, authorization_id)
            .map_err(|_| JournalError::InvalidBinding)?
            .ok_or(JournalError::NotFound)?;
        permit
            .descriptor()
            .matches_request(request.reservation())
            .map_err(|_| JournalError::InvalidBinding)?;
        lease.check_current()?;
        Ok(SignerSettlementBinding {
            journal: self.binding(),
            authorization_id: t.authorization_id.clone(),
            original_consent_ref: original.original_consent().reference().into(),
            account_id: t.account_id.clone(),
            obligation_id: t.obligation_id.clone(),
            effects_digest: t.effects_digest.clone(),
            expiry_height: t.transaction_expiry_height,
            inputs,
            witness_certificate_digest: permit.witness_certificate_digest().into(),
        })
    }

    /// Conservative account-wide durable quarantine. Existing release exposure
    /// already remains outstanding; quarantining additionally fences every future
    /// authorization. Replaying this mutation is idempotent, including after a
    /// crash before source delivery acknowledgement. There is no clear operation.
    ///
    /// `sources` and `policy` must be the independently enrolled signer source
    /// configuration, never values copied from an IPC observation or report.
    pub fn quarantine_settlement_observation(
        &self,
        binding: &SignerSettlementBinding,
        evidence: &RetainedSettlementObservation,
        sources: &[BackendIdentity],
        policy: &ConfirmationPolicy,
        session: &SignerConsentSession,
    ) -> Result<()> {
        if binding.journal != self.binding()
            || !evidence.requires_conservative_reopen()
            || !evidence.matches_sources(sources, policy)
            || evidence.descriptor().obligation_id != binding.obligation_id
        {
            return Err(JournalError::InvalidBinding);
        }
        let account = self.account_state()?;
        let permission = session.read_lease(&self.binding(), &account)?;
        let _fence = self
            .authority_fence
            .write()
            .map_err(|_| JournalError::Permission)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        storage::check_account(&tx, &account)?;
        let original = storage::read_original(&tx, &binding.authorization_id)?
            .ok_or(JournalError::NotFound)?;
        if original.original_consent().reference() != binding.original_consent_ref
            || original.original_consent().terms().principal_id != permission.principal
            || account.account_id != binding.account_id
        {
            return Err(JournalError::InvalidBinding);
        }
        permission.check_current()?;
        if tx.execute(
            "UPDATE signer_account SET recovery_required=1 WHERE singleton=1",
            [],
        )? != 1
        {
            return Err(JournalError::InvalidBinding);
        }
        tx.commit()?;
        Ok(())
    }
}

fn exact_inputs(parsed: &Pczt, inputs: &[ConsentInputBinding]) -> Result<Vec<(u64, String)>> {
    if inputs.is_empty() || inputs.len() > 256 {
        return Err(JournalError::InvalidBinding);
    }
    let mut indices = BTreeSet::new();
    let mut nullifiers = BTreeSet::new();
    let mut result = Vec::with_capacity(inputs.len());
    for input in inputs {
        let index =
            usize::try_from(input.action_index).map_err(|_| JournalError::InvalidBinding)?;
        let action = parsed
            .ironwood()
            .actions()
            .get(index)
            .ok_or(JournalError::InvalidBinding)?;
        let actual = hex::encode(action.spend().nullifier());
        if actual != input.nullifier || !indices.insert(index) || !nullifiers.insert(actual.clone())
        {
            return Err(JournalError::InvalidBinding);
        }
        result.push((input.action_index, actual));
    }
    result.sort();
    Ok(result)
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SignerResolutionRecord {
    original_consent_ref: String,
    request_digest: String,
    source: SignerSettlementSource,
    transaction: wholepact_chain::SubmissionDescriptor,
    report: Option<wholepact_chain::ReconciliationReport>,
    archive: Option<String>,
    witness: wholepact_authority::ResolutionReceipt,
    consumed_nullifiers: Vec<String>,
}
impl SignerConsentJournal {
    /// Both authorities independently qualify canonical consumption. The witness
    /// receipt is issued only on its authenticated live channel; the signer node
    /// permit is non-deserializable and bound to its separately native-enrolled
    /// source. Originals stay immutable; only the append ledger affects budget.
    #[allow(clippy::too_many_arguments)]
    pub fn resolve_settlement(
        &self,
        binding: &SignerSettlementBinding,
        source_reference: &str,
        evidence: &RetainedSettlementObservation,
        permit: &wholepact_chain::local_node::LocalResolutionPermit,
        witness: &wholepact_authority::AuthenticatedResolutionReceipt,
        session: &SignerConsentSession,
    ) -> Result<()> {
        if !matches!(
            permit.kind(),
            wholepact_chain::local_node::LocalResolutionKind::ExactTransactionConsumed
        ) || evidence.requires_conservative_reopen()
        {
            return Err(JournalError::InvalidBinding);
        }
        let source = self.settlement_source(source_reference, session)?;
        self.commit_resolution(
            binding,
            source_reference,
            &source,
            evidence.evidence_id(),
            evidence.descriptor(),
            permit.target_inputs(),
            permit.target_shielded_sighash(),
            permit.kind(),
            None,
            Some(evidence.report().clone()),
            None,
            witness,
            session,
            &|| {
                permit
                    .check_source(evidence, source.source())
                    .map_err(|_| JournalError::Permission)
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_resolution(
        &self,
        binding: &SignerSettlementBinding,
        source_reference: &str,
        enrolled: &SignerSettlementSource,
        evidence_id: &str,
        descriptor: &wholepact_chain::SubmissionDescriptor,
        inputs: &[(u64, String)],
        effects: &str,
        kind: &wholepact_chain::local_node::LocalResolutionKind,
        conflict: Option<&wholepact_chain::local_node::CanonicalConflictCandidate>,
        report: Option<wholepact_chain::ReconciliationReport>,
        archive: Option<String>,
        witness: &wholepact_authority::AuthenticatedResolutionReceipt,
        session: &SignerConsentSession,
        check_live: &dyn Fn() -> Result<()>,
    ) -> Result<()> {
        let source = self.settlement_source(source_reference, session)?;
        check_live()?;
        witness
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        if source != *enrolled
            || binding.journal != self.binding()
            || binding.effects_digest != effects
            || binding.expiry_height != descriptor.expiry_height
            || binding.inputs.iter().any(|i| !inputs.contains(i))
            || source.account_id() != binding.account_id
            || witness.authenticated_witness_certificate_digest()
                != binding.witness_certificate_digest
        {
            return Err(JournalError::InvalidBinding);
        }
        let wr = &witness.receipt().record;
        let consumed: Vec<String> = match (kind, conflict) {
            (wholepact_chain::local_node::LocalResolutionKind::ExactTransactionConsumed, None) => {
                binding.inputs.iter().map(|(_, n)| n.clone()).collect()
            }
            (
                wholepact_chain::local_node::LocalResolutionKind::IronwoodInputConflict {
                    nullifier,
                },
                Some(candidate),
            ) if nullifier == &candidate.nullifier
                && binding.inputs.iter().any(|(_, n)| n == nullifier) =>
            {
                candidate
                    .validate_original(descriptor, &binding.effects_digest, &binding.inputs)
                    .map_err(|_| JournalError::InvalidBinding)?;
                vec![nullifier.clone()]
            }
            _ => return Err(JournalError::InvalidBinding),
        };
        if wr.account_id != binding.account_id
            || wr.reservation_operation_id != binding.authorization_id
            || wr.final_transaction_id != descriptor.transaction_id
            || wr.final_transaction_digest != descriptor.bytes_sha256
            || wr.source_descriptor_digest != source.witness_source_digest()
            || wr.conflict.as_ref() != conflict
            || consumed.iter().any(|n| !wr.consumed_nullifiers.contains(n))
        {
            return Err(JournalError::InvalidBinding);
        }
        let account = self.account_state()?;
        if account.recovery_required {
            return Err(JournalError::RecoveryRequired);
        }
        let permission = session.read_lease(&self.binding(), &account)?;
        let _fence = self
            .authority_fence
            .write()
            .map_err(|_| JournalError::Permission)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        storage::check_account(&tx, &account)?;
        let original = storage::read_original(&tx, &binding.authorization_id)?
            .ok_or(JournalError::NotFound)?;
        if original.original_consent().reference() != binding.original_consent_ref
            || original.original_consent().terms().principal_id != permission.principal
            || account.account_id != binding.account_id
        {
            return Err(JournalError::InvalidBinding);
        }
        let request = bridge_storage::read_request(&tx, &binding.authorization_id)
            .map_err(|_| JournalError::InvalidBinding)?
            .ok_or(JournalError::NotFound)?;
        request
            .validate_original(&original)
            .map_err(|_| JournalError::InvalidBinding)?;
        let request_digest = request
            .reservation()
            .request_digest()
            .map_err(|_| JournalError::InvalidBinding)?;
        if request_digest != wr.reservation_request_digest {
            return Err(JournalError::InvalidBinding);
        }
        let record = SignerResolutionRecord {
            original_consent_ref: binding.original_consent_ref.clone(),
            request_digest,
            source,
            transaction: descriptor.clone(),
            report,
            archive,
            witness: witness.receipt().clone(),
            consumed_nullifiers: consumed,
        };
        append_event(
            &tx,
            evidence_id,
            &binding.authorization_id,
            source_reference,
            if conflict.is_some() {
                "canonical_conflict"
            } else {
                "canonical_consumed"
            },
            &encode(&record)?,
        )?;
        storage::bounded(&tx, self.capacity_limits())?;
        permission.check_current()?;
        check_live()?;
        witness
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        tx.commit()?;
        Ok(())
    }

    /// Independently enrolled local-node negative replay. The source journal's
    /// durable provenance permits only reopening; saved evidence never resolves.
    pub fn reopen_local_settlement(
        &self,
        binding: &SignerSettlementBinding,
        source_reference: &str,
        evidence: &RetainedSettlementObservation,
        session: &SignerConsentSession,
    ) -> Result<()> {
        let source = self.settlement_source(source_reference, session)?;
        if binding.journal != self.binding()
            || !evidence.requires_conservative_reopen()
            || !evidence.matches_source_descriptor(source.source())
            || evidence.descriptor().obligation_id != binding.obligation_id
        {
            return Err(JournalError::InvalidBinding);
        }
        let account = self.account_state()?;
        let permission = session.read_lease(&self.binding(), &account)?;
        let _fence = self
            .authority_fence
            .write()
            .map_err(|_| JournalError::Permission)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        storage::check_account(&tx, &account)?;
        if account.account_id != binding.account_id {
            return Err(JournalError::InvalidBinding);
        }
        let mut q = tx.prepare("SELECT authorization_id FROM signer_release_intents WHERE account_id=?1 AND obligation_id=?2")?;
        let ids = q
            .query_map(
                rusqlite::params![binding.account_id, binding.obligation_id],
                |r| r.get::<_, String>(0),
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(q);
        if ids.is_empty() {
            return Err(JournalError::NotFound);
        }
        for authorization in ids {
            let original =
                storage::read_original(&tx, &authorization)?.ok_or(JournalError::NotFound)?;
            if original.original_consent().terms().principal_id != permission.principal {
                return Err(JournalError::Permission);
            }
            let payload = encode(&(
                evidence.journal_identity(),
                evidence.descriptor(),
                evidence.report(),
                &source,
            ))?;
            append_event(
                &tx,
                evidence.evidence_id(),
                &authorization,
                source_reference,
                "reopened",
                &payload,
            )?;
        }
        tx.execute(
            "UPDATE signer_account SET recovery_required=1 WHERE singleton=1",
            [],
        )?;
        storage::bounded(&tx, self.capacity_limits())?;
        permission.check_current()?;
        tx.commit()?;
        Ok(())
    }
}
fn append_event(
    c: &rusqlite::Connection,
    evidence: &str,
    authorization: &str,
    source: &str,
    kind: &str,
    payload: &str,
) -> Result<()> {
    use rusqlite::OptionalExtension;
    let old: Option<(String,String)> = c.query_row("SELECT source_ref,payload FROM signer_settlement_events WHERE evidence_id=?1 AND authorization_id=?2 AND kind=?3",rusqlite::params![evidence,authorization,kind],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
    if let Some((old_source, old_payload)) = old {
        if old_source != source || old_payload != payload {
            return Err(JournalError::Conflict);
        }
        return Ok(());
    }
    c.execute("INSERT INTO signer_settlement_events(evidence_id,authorization_id,source_ref,kind,payload) VALUES(?1,?2,?3,?4,?5)",rusqlite::params![evidence,authorization,source,kind,payload])?;
    Ok(())
}

impl SignerConsentJournal {
    /// Revalidate immediately before dispatch and each live dispatch lease check.
    /// A held original lease cannot mask a recovery fence committed after issue.
    pub(crate) fn revalidate_settlement_authority(
        &self,
        lease: &OriginalAuthorizationLease<'_>,
    ) -> crate::authority_bridge::Result<()> {
        use crate::authority_bridge::BridgeError;
        lease.check_current()?;
        if lease.binding() != &self.binding() {
            return Err(BridgeError::Binding);
        }
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = c
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        let account = storage::read_account(&tx)?;
        if account.recovery_required {
            return Err(BridgeError::RecoveryRequired);
        }
        if account.account_id != lease.evidence().enrollment().account_id() {
            return Err(BridgeError::Binding);
        }
        if !self.revalidate_settlements_in_transaction(&tx)? {
            tx.commit().map_err(JournalError::from)?;
            return Err(BridgeError::RecoveryRequired);
        }
        lease.check_current()?;
        tx.commit().map_err(JournalError::from)?;
        Ok(())
    }

    /// Runtime attachment never enrolls trust. The exact descriptor must already
    /// have the independent signer's native approval in this protected journal.
    pub fn attach_settlement_node(
        &self,
        source_reference: &str,
        node: Arc<wholepact_chain::local_node::LocalValidatingNode>,
        session: &SignerConsentSession,
    ) -> Result<()> {
        let source = self.settlement_source(source_reference, session)?;
        if source.source() != &node.source_descriptor() {
            return Err(JournalError::Permission);
        }
        self.settlement_nodes
            .lock()
            .map_err(|_| JournalError::Database)?
            .insert(source_reference.into(), node);
        Ok(())
    }

    fn settlement_descriptor(
        &self,
        authorization_id: &str,
        dispatch_operation: &str,
        session: &SignerConsentSession,
    ) -> Result<wholepact_chain::SubmissionDescriptor> {
        let lease = self.acquire_original_authorization(authorization_id, session)?;
        let retained = self
            .retained_dispatch(&lease, dispatch_operation)
            .map_err(|_| JournalError::InvalidBinding)?
            .ok_or(JournalError::NotFound)?;
        let d = retained.request.backend.descriptor;
        lease.check_current()?;
        Ok(wholepact_chain::SubmissionDescriptor {
            operation_id: d.operation_id,
            obligation_id: d.obligation_id,
            proposal_id: d.proposal_id,
            transaction_id: d.transaction_id,
            bytes_sha256: d.bytes_sha256,
            expiry_height: d.expiry_height,
            network: d.network,
            consensus_branch_id: d.consensus_branch_id,
        })
    }
    /// Pure protected-history comparison before native approval or node access.
    pub(crate) fn validate_settlement_candidate(
        &self,
        authorization_id: &str,
        dispatch_operation: &str,
        candidate: &wholepact_chain::local_node::CanonicalConflictCandidate,
        session: &SignerConsentSession,
    ) -> Result<()> {
        let binding = self.settlement_binding(authorization_id, session)?;
        let descriptor =
            self.settlement_descriptor(authorization_id, dispatch_operation, session)?;
        candidate
            .validate_original(&descriptor, binding.effects_digest(), binding.inputs())
            .map_err(|_| JournalError::InvalidBinding)
    }

    /// Exact target comes from retained native dispatch, not IPC transaction
    /// fields. Both signer and witness read their own enrolled validating node.
    #[cfg(all(feature = "native-ui", target_os = "linux"))]
    pub fn observe_and_resolve_settlement(
        &self,
        authorization_id: &str,
        dispatch_operation: &str,
        source_reference: &str,
        witness: &wholepact_authority::AuthorityClient,
        session: &SignerConsentSession,
    ) -> Result<()> {
        self.observe_and_resolve_settlement_selected(
            authorization_id,
            dispatch_operation,
            source_reference,
            None,
            witness,
            session,
        )
    }
    #[cfg(all(feature = "native-ui", target_os = "linux"))]
    pub(crate) fn observe_and_resolve_settlement_selected(
        &self,
        authorization_id: &str,
        dispatch_operation: &str,
        source_reference: &str,
        conflict: Option<&wholepact_chain::local_node::CanonicalConflictCandidate>,
        witness: &wholepact_authority::AuthorityClient,
        session: &SignerConsentSession,
    ) -> Result<()> {
        if let Some(candidate) = conflict {
            self.validate_settlement_candidate(
                authorization_id,
                dispatch_operation,
                candidate,
                session,
            )?;
        }
        {
            let lease = self.acquire_original_authorization(authorization_id, session)?;
            self.revalidate_settlement_authority(&lease)
                .map_err(|_| JournalError::RecoveryRequired)?;
        }
        let binding = self.settlement_binding(authorization_id, session)?;
        let source = self.settlement_source(source_reference, session)?;
        let descriptor =
            self.settlement_descriptor(authorization_id, dispatch_operation, session)?;
        let node = self
            .settlement_nodes
            .lock()
            .map_err(|_| JournalError::Database)?
            .get(source_reference)
            .cloned()
            .ok_or(JournalError::Permission)?;
        if node.source_descriptor() != *source.source() {
            return Err(JournalError::Permission);
        }
        let observed = match conflict {
            Some(candidate) => node.qualify_admission_conflict(
                &descriptor,
                candidate,
                binding.effects_digest(),
                binding.inputs(),
            ),
            None => node.qualify_admission(&descriptor),
        };
        let qualified = match observed {
            Ok(value) => value,
            Err(_) => {
                self.reopen_resolved_after_failed_observation(session)?;
                return Err(JournalError::Permission);
            }
        };
        let witnessed = match conflict {
            Some(candidate) => witness.resolve_reservation_conflict(authorization_id, candidate),
            None => witness.resolve_reservation(authorization_id),
        };
        let witness = match witnessed {
            Ok(value) => value,
            Err(_) => {
                self.reopen_resolved_after_failed_observation(session)?;
                return Err(JournalError::Permission);
            }
        };
        if witness.receipt().record.inclusion_block_hash != qualified.inclusion().hash
            || witness.receipt().record.inclusion_block_height != qualified.inclusion().height
        {
            self.reopen_resolved_after_failed_observation(session)?;
            return Err(JournalError::InvalidBinding);
        }
        let evidence = qualified
            .evidence_id()
            .map_err(|_| JournalError::InvalidBinding)?;
        self.commit_resolution(
            &binding,
            source_reference,
            &source,
            &evidence,
            &descriptor,
            qualified.target_inputs(),
            qualified.target_shielded_sighash(),
            qualified.kind(),
            conflict,
            None,
            Some(
                qualified
                    .evidence_json()
                    .map_err(|_| JournalError::InvalidBinding)?,
            ),
            &witness,
            session,
            &|| {
                qualified
                    .check_source(source.source())
                    .map_err(|_| JournalError::Permission)
            },
        )
    }

    #[cfg(all(feature = "native-ui", target_os = "linux"))]
    fn reopen_resolved_after_failed_observation(
        &self,
        session: &SignerConsentSession,
    ) -> Result<()> {
        let account = self.account_state()?;
        let permission = session.read_lease(&self.binding(), &account)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        storage::check_account(&tx, &account)?;
        let mut q = tx.prepare("SELECT e.evidence_id,e.authorization_id,e.source_ref FROM signer_settlement_events e WHERE e.sequence=(SELECT max(x.sequence) FROM signer_settlement_events x WHERE x.authorization_id=e.authorization_id) AND e.kind IN ('canonical_consumed','canonical_conflict')")?;
        let rows = q
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(q);
        if !rows.is_empty() {
            for (prior, authorization, source) in rows {
                let evidence = digest(
                    "wholepact:signer-observation-failed:v1",
                    &(&prior, &authorization, &source),
                )?;
                append_event(
                    &tx,
                    &evidence,
                    &authorization,
                    &source,
                    "reopened",
                    "{\"reason\":\"independent_observation_failed\"}",
                )?;
            }
            tx.execute(
                "UPDATE signer_account SET recovery_required=1 WHERE singleton=1",
                [],
            )?;
        }
        storage::bounded(&tx, self.capacity_limits())?;
        permission.check_current()?;
        tx.commit()?;
        Ok(())
    }

    /// Called while holding the same authority transaction as new permission.
    /// On failure this writes conservative reopening+quarantine; the caller MUST
    /// commit that fence before returning RecoveryRequired, never roll it back.
    pub(super) fn revalidate_settlements_in_transaction(
        &self,
        c: &rusqlite::Connection,
    ) -> Result<bool> {
        let mut q=c.prepare("SELECT e.evidence_id,e.authorization_id,e.source_ref,e.payload FROM signer_settlement_events e WHERE e.sequence=(SELECT max(x.sequence) FROM signer_settlement_events x WHERE x.authorization_id=e.authorization_id) AND e.kind IN ('canonical_consumed','canonical_conflict')")?;
        let rows = q
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(q);
        let started = std::time::Instant::now();
        let mut qualified = Vec::new();
        let mut failed = false;
        for (_, authorization, source_ref, payload) in &rows {
            let record: SignerResolutionRecord = decode(payload.clone())?;
            let original =
                storage::read_original(c, authorization)?.ok_or(JournalError::NotFound)?;
            if record.original_consent_ref != original.original_consent().reference() {
                return Err(JournalError::InvalidBinding);
            }
            let node = self
                .settlement_nodes
                .lock()
                .map_err(|_| JournalError::Database)?
                .get(source_ref)
                .cloned();
            let result = node.ok_or(JournalError::Permission).and_then(|node| {
                if node.source_descriptor() != *record.source.source() {
                    return Err(JournalError::Permission);
                }
                let t = original.original_consent().terms();
                let inputs: Vec<_> = t
                    .input_bindings
                    .iter()
                    .map(|i| (i.action_index, i.nullifier.clone()))
                    .collect();
                let p = match &record.witness.record.conflict {
                    Some(candidate) => node.qualify_admission_conflict(
                        &record.transaction,
                        candidate,
                        &t.effects_digest,
                        &inputs,
                    ),
                    None => node.qualify_admission(&record.transaction),
                }
                .map_err(|_| JournalError::Permission)?;
                p.check_source(record.source.source())
                    .map_err(|_| JournalError::Permission)?;
                let t = original.original_consent().terms();
                if p.target_shielded_sighash() != t.effects_digest
                    || t.input_bindings.iter().any(|i| {
                        !p.target_inputs()
                            .contains(&(i.action_index, i.nullifier.clone()))
                    })
                    || p.inclusion().hash != record.witness.record.inclusion_block_hash
                    || p.inclusion().height != record.witness.record.inclusion_block_height
                {
                    return Err(JournalError::InvalidBinding);
                }
                Ok(p)
            });
            match result {
                Ok(p) => qualified.push(p),
                Err(_) => {
                    failed = true;
                    break;
                }
            }
        }
        failed |= started.elapsed() >= std::time::Duration::from_secs(30)
            || qualified.iter().any(|p| p.check_current().is_err());
        if !failed {
            return Ok(true);
        }
        // Conservatively reopen ALL locally resolved authorizations. No provider
        // error, missing runtime attachment or restore can leave freed budget.
        for (old_evidence, authorization, source_ref, _) in rows {
            let evidence = digest(
                "wholepact:signer-source-freshness-lost:v1",
                &(&old_evidence, &authorization, &source_ref),
            )?;
            append_event(
                c,
                &evidence,
                &authorization,
                &source_ref,
                "reopened",
                "{\"reason\":\"independent_canonical_revalidation_unavailable\"}",
            )?;
        }
        c.execute(
            "UPDATE signer_account SET recovery_required=1 WHERE singleton=1",
            [],
        )?;
        storage::bounded(c, self.capacity_limits())?;
        Ok(false)
    }
}

/// Read-only protected-history inspection for a permanent-stop disclosure. This
/// never consults runtime nodes, checks a wall clock, appends events, computes a
/// freed budget, or reconstructs a live settlement/authorization capability.
/// The caller holds one bounded SQLite read snapshot for all local tables.
#[cfg(all(feature = "native-ui", target_os = "linux"))]
pub(super) fn read_permanent_stop_history(
    c: &rusqlite::Connection,
    account: &SignerAccountState,
) -> Result<serde_json::Value> {
    use rusqlite::OptionalExtension;
    use std::collections::BTreeMap;
    let count: u64 = c.query_row("SELECT count(*) FROM signer_settlement_events", [], |r| {
        r.get(0)
    })?;
    if count > 4096 {
        return Err(JournalError::Limit);
    }
    let mut q = c.prepare("SELECT sequence,evidence_id,authorization_id,source_ref,kind,payload FROM signer_settlement_events ORDER BY sequence")?;
    let mut rows = q.query([])?;
    let mut prior: BTreeMap<String, (String, String, String)> = BTreeMap::new();
    let mut display = Vec::new();
    let mut display_bytes = 0usize;
    let mut last_sequence = 0u64;
    while let Some(row) = rows.next()? {
        let sequence: u64 = row.get(0)?;
        let evidence: String = row.get(1)?;
        let authorization: String = row.get(2)?;
        let source_ref: String = row.get(3)?;
        let kind: String = row.get(4)?;
        let payload: String = row.get(5)?;
        if sequence <= last_sequence || payload.len() > MAX_RECORD_BYTES {
            return Err(JournalError::InvalidBinding);
        }
        last_sequence = sequence;
        hash(&evidence)?;
        hash(&source_ref)?;
        id(&authorization)?;
        let original = storage::read_original(c, &authorization)?.ok_or(JournalError::NotFound)?;
        let terms = original.original_consent().terms();
        if terms.account_id != account.account_id {
            return Err(JournalError::InvalidBinding);
        }
        let (source_account, raw): (String, String) = c
            .query_row(
                "SELECT account_id,payload FROM signer_settlement_sources WHERE reference=?1",
                [&source_ref],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or(JournalError::NotFound)?;
        let source: SignerSettlementSource = decode(raw)?;
        source.validate()?;
        if source.reference() != source_ref
            || source_account != account.account_id
            || source.account_id() != account.account_id
            || source.principal_id() != terms.principal_id
        {
            return Err(JournalError::InvalidBinding);
        }
        let mut historical_dispatch_retained = None;
        let witness_digest = match kind.as_str() {
            "canonical_consumed" | "canonical_conflict" => {
                let record: SignerResolutionRecord = decode(payload.clone())?;
                let request = bridge_storage::read_request(c, &authorization)
                    .map_err(|_| JournalError::InvalidBinding)?
                    .ok_or(JournalError::NotFound)?;
                request
                    .validate_original(&original)
                    .map_err(|_| JournalError::InvalidBinding)?;
                bridge_storage::read_validated_result(c, &authorization, &original)
                    .map_err(|_| JournalError::InvalidBinding)?;
                let request_digest = request
                    .reservation()
                    .request_digest()
                    .map_err(|_| JournalError::InvalidBinding)?;
                let wr = &record.witness.record;
                if record.original_consent_ref != original.original_consent().reference()
                    || record.source != source
                    || record.request_digest != request_digest
                    || wr.reservation_request_digest != request_digest
                    || wr.reservation_operation_id != authorization
                    || wr.account_id != account.account_id
                    || wr.network_profile_id != request.reservation().network_profile_id
                    || record.transaction.obligation_id != terms.obligation_id
                    || record.transaction.proposal_id != terms.proposal_id
                    || record.transaction.expiry_height != terms.transaction_expiry_height
                {
                    return Err(JournalError::InvalidBinding);
                }
                let dispatch: Option<(String, String)> = c.query_row(
                    "SELECT authorization_id,payload FROM signer_dispatch_requests WHERE operation_id=?1",
                    [&record.transaction.operation_id], |r| Ok((r.get(0)?, r.get(1)?)),
                ).optional()?;
                historical_dispatch_retained = Some(dispatch.is_some());
                // A co-party can broadcast after signing without any local
                // dispatch. Such history remains valid, historical and uncertain.
                if let Some((dispatch_authorization, raw)) = dispatch {
                    let permit = bridge_storage::read_permit(c, &authorization)
                        .map_err(|_| JournalError::InvalidBinding)?
                        .ok_or(JournalError::NotFound)?;
                    let dispatch: dispatch_storage::RetainedDispatch = decode(raw)?;
                    dispatch
                        .request
                        .validate()
                        .map_err(|_| JournalError::InvalidBinding)?;
                    dispatch
                        .exact
                        .validate()
                        .map_err(|_| JournalError::InvalidBinding)?;
                    dispatch
                        .witness
                        .validate()
                        .map_err(|_| JournalError::InvalidBinding)?;
                    dispatch.request.history.matches(
                    &crate::authority_bridge::protocol::OriginalAuthorizationView::from_original(&original),
                ).map_err(|_| JournalError::InvalidBinding)?;
                    let backend = &dispatch.request.backend;
                    if dispatch_authorization != authorization
                        || dispatch.request.operation_id != dispatch.exact.operation_id
                        || dispatch.exact.operation_id != record.transaction.operation_id
                        || dispatch.exact.account_id != account.account_id
                        || dispatch.exact.reservation_operation_id != authorization
                        || dispatch.exact.reservation_request_digest != request_digest
                        || dispatch.exact.backend_disclosure_digest
                            != backend.digest().map_err(|_| JournalError::InvalidBinding)?
                        || dispatch.exact.final_transaction_id != record.transaction.transaction_id
                        || dispatch.exact.final_transaction_digest
                            != record.transaction.bytes_sha256
                        || dispatch.exact.transaction_expiry_height
                            != record.transaction.expiry_height
                        || dispatch.witness.pinned_server_certificate_digest
                            != permit.witness_certificate_digest()
                        || dispatch.witness.account_id != account.account_id
                        || dispatch.exact.network_profile_id != dispatch.witness.network_profile_id
                        || request
                            .disclosure
                            .as_ref()
                            .is_some_and(|d| d.descriptor != dispatch.witness)
                        || backend.agreement_id != terms.agreement_id
                        || serde_json::to_value(&backend.descriptor)
                            .map_err(|_| JournalError::InvalidBinding)?
                            != serde_json::to_value(&record.transaction)
                                .map_err(|_| JournalError::InvalidBinding)?
                    {
                        return Err(JournalError::InvalidBinding);
                    }
                }
                let inputs: Vec<_> = terms
                    .input_bindings
                    .iter()
                    .map(|i| (i.action_index, i.nullifier.clone()))
                    .collect();
                validate_historical_positive(
                    &record,
                    &kind,
                    &evidence,
                    &inputs,
                    &terms.effects_digest,
                )?;
                Some(digest(
                    "wholepact:historical-settlement-witness-display:v1",
                    &record.witness,
                )?)
            }
            "reopened" => {
                validate_historical_reopen(
                    c,
                    &payload,
                    &evidence,
                    &authorization,
                    &source,
                    &terms.obligation_id,
                    prior.get(&authorization),
                    &account.account_id,
                )?;
                None
            }
            _ => return Err(JournalError::InvalidBinding),
        };
        let item = serde_json::json!({
            "sequence": sequence, "authorization_id": authorization,
            "original_consent_ref": original.original_consent().reference(),
            "obligation_id": terms.obligation_id, "proposal_id": terms.proposal_id,
            "historical_maximum_debit_zatoshis": terms.maximum_debit_zatoshis.to_string(),
            "historical_fee_share_zatoshis": terms.fee_share_zatoshis.to_string(),
            "historical_kind": kind, "evidence_digest": evidence,
            "source_reference": source_ref, "witness_receipt_display_digest": witness_digest,
            "payload_digest": hex::encode(sha2::Sha256::digest(payload.as_bytes())),
            "retained_dispatch_present": historical_dispatch_retained,
            "current_canonical_status": "unknown", "spendable_budget": "unknown",
            "permits_replacement": false
        });
        display_bytes = display_bytes
            .checked_add(
                serde_json::to_vec(&item)
                    .map_err(|_| JournalError::InvalidBinding)?
                    .len(),
            )
            .ok_or(JournalError::Limit)?;
        if display_bytes > 1024 * 1024 {
            return Err(JournalError::Limit);
        }
        display.push(item);
        prior.insert(authorization, (evidence, source_ref, kind));
    }
    let value = serde_json::json!({"historical_only":true,"current_authentication":false,
        "release_authority":false,"settlement_events":display});
    if serde_json::to_vec(&value)
        .map_err(|_| JournalError::InvalidBinding)?
        .len()
        > 1024 * 1024
    {
        return Err(JournalError::Limit);
    }
    Ok(value)
}

fn validate_historical_positive(
    record: &SignerResolutionRecord,
    kind: &str,
    evidence: &str,
    inputs: &[(u64, String)],
    effects: &str,
) -> Result<()> {
    let wr = &record.witness.record;
    record.source.validate()?;
    for v in [
        &record.original_consent_ref,
        &record.request_digest,
        evidence,
        &wr.reservation_request_digest,
        &wr.final_transaction_id,
        &wr.final_transaction_digest,
        &wr.source_descriptor_digest,
        &wr.evidence_digest,
        &wr.inclusion_block_hash,
        &wr.expected_head.digest,
        &record.witness.committed_head.digest,
    ] {
        hash(v)?;
    }
    id(&wr.operation_id)?;
    if wr.expected_head.sequence.checked_add(1) != Some(record.witness.committed_head.sequence)
        || wr.inclusion_block_height == 0
        || record.request_digest != wr.reservation_request_digest
        || wr.account_id != record.source.account_id()
        || wr.source_descriptor_digest != record.source.witness_source_digest()
        || wr.final_transaction_id != record.transaction.transaction_id
        || wr.final_transaction_digest != record.transaction.bytes_sha256
        || record.transaction.network != record.source.source().network
        || record.transaction.consensus_branch_id != record.source.source().consensus_branch_id
        || inputs.is_empty()
        || inputs.len() > 256
    {
        return Err(JournalError::InvalidBinding);
    }
    let expected: BTreeSet<_> = inputs.iter().map(|(_, n)| n).collect();
    if expected.len() != inputs.len() {
        return Err(JournalError::InvalidBinding);
    }
    match (kind, &wr.conflict) {
        ("canonical_consumed", None) => {
            if record.consumed_nullifiers.iter().collect::<BTreeSet<_>>() != expected
                || record.consumed_nullifiers.len() != expected.len()
                || wr.consumed_nullifiers.iter().collect::<BTreeSet<_>>() != expected
                || wr.consumed_nullifiers.len() != expected.len()
            {
                return Err(JournalError::InvalidBinding);
            }
        }
        ("canonical_conflict", Some(candidate)) => {
            candidate
                .validate_original(&record.transaction, effects, inputs)
                .map_err(|_| JournalError::InvalidBinding)?;
            if record.consumed_nullifiers != [candidate.nullifier.clone()]
                || wr.consumed_nullifiers != record.consumed_nullifiers
            {
                return Err(JournalError::InvalidBinding);
            }
        }
        _ => return Err(JournalError::InvalidBinding),
    }
    match (&record.report, &record.archive) {
        (Some(report), None) if wr.conflict.is_none() => {
            validate_historical_report(report, &record.transaction, record.source.source())?;
            if !report.state.confirmation_policy_met()
                || report.confidence_lost
                || report.reorganization_observed
                || report.last_inclusion.as_ref().is_none_or(|b| {
                    b.hash != wr.inclusion_block_hash || b.height != wr.inclusion_block_height
                })
            {
                return Err(JournalError::InvalidBinding);
            }
        }
        (None, Some(archive)) => {
            validate_historical_archive(record, evidence, inputs, effects, archive)?
        }
        _ => return Err(JournalError::InvalidBinding),
    }
    Ok(())
}

fn validate_historical_report(
    report: &wholepact_chain::ReconciliationReport,
    descriptor: &wholepact_chain::SubmissionDescriptor,
    source: &wholepact_chain::local_node::LocalNodeSourceDescriptor,
) -> Result<()> {
    // Maintained pure structural validation on a clone; no journal mutation or
    // attempt to refresh saved observations into current authority.
    wholepact_chain::SettlementReconciler::restore(report.clone())
        .map_err(|_| JournalError::InvalidBinding)?;
    if report.transaction_id != descriptor.transaction_id
        || report.expiry_height != descriptor.expiry_height
        || report.policy != source.confirmation_policy
    {
        return Err(JournalError::InvalidBinding);
    }
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalCanonicalArchive {
    source: wholepact_chain::local_node::LocalNodeSourceDescriptor,
    target_inputs: Vec<(u64, String)>,
    target_shielded_sighash: String,
    source_id: String,
    source_release: String,
    source_commit: String,
    certificate_sha256: String,
    session_binding_sha256: String,
    target: wholepact_chain::SubmissionDescriptor,
    included_transaction_id: String,
    included_transaction_hex: String,
    inclusion: wholepact_chain::BlockIdentity,
    tip: wholepact_chain::BlockIdentity,
    tip_mined_at: u64,
    observed_at: u64,
    required_confirmations: u32,
    kind: wholepact_chain::local_node::LocalResolutionKind,
}
fn validate_historical_archive(
    record: &SignerResolutionRecord,
    evidence: &str,
    inputs: &[(u64, String)],
    effects: &str,
    archive: &str,
) -> Result<()> {
    if archive.len() > 262144 || hex::encode(sha2::Sha256::digest(archive.as_bytes())) != evidence {
        return Err(JournalError::InvalidBinding);
    }
    let a: HistoricalCanonicalArchive = decode(archive.to_owned())?;
    let source = record.source.source();
    for v in [
        &a.certificate_sha256,
        &a.session_binding_sha256,
        &a.inclusion.hash,
        &a.tip.hash,
        &a.included_transaction_id,
    ] {
        hash(v)?;
    }
    if a.source != *source
        || a.source_id != source.source_id
        || a.source_release != source.node_release
        || a.source_commit != source.node_source_commit
        || a.certificate_sha256 != source.pinned_certificate_sha256
        || a.target != record.transaction
        || a.target_shielded_sighash != effects
        || a.target_inputs.len() > 256
        || inputs.iter().any(|i| !a.target_inputs.contains(i))
        || a.target_inputs.iter().collect::<BTreeSet<_>>().len() != a.target_inputs.len()
        || a.inclusion.height == 0
        || a.tip.height < a.inclusion.height
        || a.inclusion.hash != record.witness.record.inclusion_block_hash
        || a.inclusion.height != record.witness.record.inclusion_block_height
        || a.required_confirmations != source.confirmation_policy.required_confirmations()
        || a.tip
            .height
            .checked_sub(a.inclusion.height)
            .and_then(|n| n.checked_add(1))
            .is_none_or(|n| n < u64::from(a.required_confirmations))
        || a.observed_at == 0
        || a.tip_mined_at > a.observed_at.saturating_add(30)
        || a.observed_at.saturating_sub(a.tip_mined_at) > 1200
        || a.included_transaction_hex.is_empty()
        || a.included_transaction_hex.len() > 128 * 1024
        || !a.included_transaction_hex.len().is_multiple_of(2)
    {
        return Err(JournalError::InvalidBinding);
    }
    let bytes = Zeroizing::new(
        hex::decode(&a.included_transaction_hex).map_err(|_| JournalError::InvalidBinding)?,
    );
    if hex::encode(bytes.as_slice()) != a.included_transaction_hex {
        return Err(JournalError::InvalidBinding);
    }
    let parsed = wholepact_chain::SubmissionPlan::new(
        &a.target.obligation_id,
        &a.target.proposal_id,
        &a.target.operation_id,
        bytes.as_slice(),
    )
    .map_err(|_| JournalError::InvalidBinding)?;
    if parsed.descriptor().transaction_id != a.included_transaction_id {
        return Err(JournalError::InvalidBinding);
    }
    match (&record.witness.record.conflict, &a.kind) {
        (None, wholepact_chain::local_node::LocalResolutionKind::ExactTransactionConsumed)
            if a.included_transaction_id == record.transaction.transaction_id
                && parsed.descriptor().bytes_sha256 == record.transaction.bytes_sha256 => {}
        (
            Some(candidate),
            wholepact_chain::local_node::LocalResolutionKind::IronwoodInputConflict { nullifier },
        ) if candidate.nullifier == *nullifier
            && candidate.included_transaction_id == a.included_transaction_id => {}
        _ => return Err(JournalError::InvalidBinding),
    }
    Ok(())
}

#[cfg(all(feature = "native-ui", target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
fn validate_historical_reopen(
    c: &rusqlite::Connection,
    payload: &str,
    evidence: &str,
    authorization: &str,
    source: &SignerSettlementSource,
    obligation: &str,
    prior: Option<&(String, String, String)>,
    account: &str,
) -> Result<()> {
    let value: serde_json::Value = decode(payload.to_owned())?;
    if value.is_array() {
        let (journal, descriptor, report, carried_source): (
            String,
            wholepact_chain::SubmissionDescriptor,
            wholepact_chain::ReconciliationReport,
            SignerSettlementSource,
        ) = decode(payload.to_owned())?;
        hash(&journal)?;
        if carried_source != *source
            || descriptor.obligation_id != obligation
            || descriptor.network != source.source().network
            || descriptor.consensus_branch_id != source.source().consensus_branch_id
            || !(report.confidence_lost || report.reorganization_observed)
        {
            return Err(JournalError::InvalidBinding);
        }
        id(&descriptor.operation_id)?;
        id(&descriptor.proposal_id)?;
        hash(&descriptor.bytes_sha256)?;
        validate_historical_report(&report, &descriptor, source.source())?;
        return Ok(());
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reason {
        reason: String,
    }
    let reason: Reason = decode(payload.to_owned())?;
    let (old, old_source, old_kind) = prior.ok_or(JournalError::InvalidBinding)?;
    if old_source != source.reference()
        || !matches!(
            old_kind.as_str(),
            "canonical_consumed" | "canonical_conflict"
        )
    {
        return Err(JournalError::InvalidBinding);
    }
    let domain = match reason.reason.as_str() {
        "independent_observation_failed" => Some("wholepact:signer-observation-failed:v1"),
        "independent_canonical_revalidation_unavailable" => {
            Some("wholepact:signer-source-freshness-lost:v1")
        }
        "restored_positive_evidence_requires_fresh_requalification" => None,
        _ => return Err(JournalError::InvalidBinding),
    };
    if let Some(domain) = domain {
        if digest(domain, &(old, authorization, source.reference()))? != evidence {
            return Err(JournalError::InvalidBinding);
        }
    } else {
        let count: u64 = c.query_row(
            "SELECT count(*) FROM signer_recovery_generations WHERE phase='committed'",
            [],
            |r| r.get(0),
        )?;
        if count > 4096 {
            return Err(JournalError::Limit);
        }
        let mut q = c.prepare(
            "SELECT generation_id,payload FROM signer_recovery_generations WHERE phase='committed'",
        )?;
        let mut rows = q.query([])?;
        let mut found = false;
        while let Some(row) = rows.next()? {
            let generation: String = row.get(0)?;
            let record: recovery_activation::RecoveryActivationRecord = decode(row.get(1)?)?;
            hash(&generation)?;
            if record.generation_id != generation || record.account_id != account {
                return Err(JournalError::InvalidBinding);
            }
            if digest(
                "wholepact:recovery-conservative-reopen:v1",
                &(&generation, old, authorization, source.reference()),
            )? == evidence
            {
                found = true;
            }
        }
        if !found {
            return Err(JournalError::InvalidBinding);
        }
    }
    Ok(())
}

#[cfg(all(test, feature = "synthetic-qualification"))]
mod tests {
    use super::*;

    #[test]
    fn settlement_event_replay_is_idempotent_and_changed_payload_is_rejected() {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE signer_settlement_events(sequence INTEGER PRIMARY KEY,evidence_id TEXT,authorization_id TEXT,source_ref TEXT,kind TEXT,payload TEXT,UNIQUE(evidence_id,authorization_id,kind));").unwrap();
        append_event(
            &c,
            "synthetic-evidence",
            "synthetic-original",
            "synthetic-source",
            "reopened",
            "same",
        )
        .unwrap();
        append_event(
            &c,
            "synthetic-evidence",
            "synthetic-original",
            "synthetic-source",
            "reopened",
            "same",
        )
        .unwrap();
        assert!(matches!(
            append_event(
                &c,
                "synthetic-evidence",
                "synthetic-original",
                "synthetic-source",
                "reopened",
                "changed"
            ),
            Err(JournalError::Conflict)
        ));
        assert!(matches!(
            append_event(
                &c,
                "synthetic-evidence",
                "synthetic-original",
                "other-source",
                "reopened",
                "same"
            ),
            Err(JournalError::Conflict)
        ));
        assert_eq!(
            c.query_row("SELECT count(*) FROM signer_settlement_events", [], |r| r
                .get::<_, u64>(
                0
            ))
            .unwrap(),
            1
        );
    }

    #[test]
    fn settlement_original_pczt_mapping_rejects_nullifier_index_and_duplicate_substitution() {
        // Maintained-library, never-funded PCZT fixture; no proof generation.
        let (_, _, bytes) = crate::manifest::tests::consent_fixture();
        let pczt = Pczt::parse(&bytes).unwrap();
        let original = ConsentInputBinding {
            input_id: "synthetic-original-input".into(),
            action_index: 0,
            nullifier: hex::encode(pczt.ironwood().actions()[0].spend().nullifier()),
            value_zatoshis: 1,
        };
        assert_eq!(
            exact_inputs(&pczt, std::slice::from_ref(&original)).unwrap(),
            vec![(0, original.nullifier.clone())]
        );
        let mut wrong = original.clone();
        wrong.nullifier = "00".repeat(32);
        assert!(exact_inputs(&pczt, &[wrong]).is_err());
        let mut wrong = original.clone();
        wrong.action_index = u64::MAX;
        assert!(exact_inputs(&pczt, &[wrong]).is_err());
        assert!(exact_inputs(&pczt, &[original.clone(), original]).is_err());
        assert!(exact_inputs(&pczt, &[]).is_err());
    }
}

#[cfg(all(
    test,
    feature = "synthetic-qualification",
    feature = "native-ui",
    target_os = "linux"
))]
mod historical_stop_tests {
    use super::*;
    use serde_json::json;
    use wholepact_chain::{
        BlockIdentity, ReconciliationReport, SettlementObservationState, SourceTip,
        SubmissionDescriptor,
    };

    // Fabricated historical shapes only. No live issuer, credentials, socket,
    // node, proof, signature generation, or current canonical assertion.
    fn fixture() -> (SignerResolutionRecord, Vec<(u64, String)>, String) {
        let descriptor = wholepact_chain::local_node::LocalNodeSourceDescriptor {
            source_id: "synthetic-node".into(),
            endpoint: "127.0.0.1:12345".into(),
            server_name: "localhost".into(),
            pinned_certificate_sha256: "11".repeat(32),
            client_certificate_sha256: "22".repeat(32),
            trusted_root_sha256: vec!["33".repeat(32)],
            node_release: wholepact_chain::local_node::ZEBRA_RELEASE.into(),
            node_source_commit: wholepact_chain::local_node::ZEBRA_SOURCE_COMMIT.into(),
            network: "testnet".into(),
            consensus_branch_id: wholepact_chain::NU7_BRANCH_ID,
            activation_height: wholepact_chain::NU7_ACTIVATION_HEIGHT,
            confirmation_policy: ConfirmationPolicy::new(10, 10, vec!["synthetic-node".into()])
                .unwrap(),
        };
        let receipt = NativeConsentReceipt {
            native_session_id: "44".repeat(32),
            trusted_launch_measurement: "55".repeat(32),
            permission_generation: 1,
            writer_epoch: 1,
            nonce: "66".repeat(32),
            reviewed_at_ms: 1000,
            expires_at_ms: 2000,
        };
        let account = "synthetic-account";
        let principal = "synthetic-owner";
        let witness = "77".repeat(32);
        let reference = digest(
            "wholepact:signer-settlement-source:v1",
            &(account, principal, &descriptor, &witness, &receipt),
        )
        .unwrap();
        let source: SignerSettlementSource = serde_json::from_value(json!({"reference":reference,
            "account_id":account,"principal_id":principal,"source":descriptor,
            "witness_source_digest":witness,"receipt":receipt}))
        .unwrap();
        let target = SubmissionDescriptor {
            operation_id: "synthetic-dispatch".into(),
            obligation_id: "synthetic-obligation".into(),
            proposal_id: "synthetic-proposal".into(),
            transaction_id: "88".repeat(32),
            bytes_sha256: "99".repeat(32),
            expiry_height: 4_600_000,
            network: "testnet".into(),
            consensus_branch_id: wholepact_chain::NU7_BRANCH_ID,
        };
        let block = BlockIdentity {
            height: 4_500_000,
            hash: "aa".repeat(32),
        };
        let report = ReconciliationReport {
            transaction_id: target.transaction_id.clone(),
            expiry_height: target.expiry_height,
            policy: source.source().confirmation_policy.clone(),
            observed_at_unix_seconds: 100,
            valid_until_unix_seconds: 130,
            state: SettlementObservationState::ConfirmationPolicyMet {
                block: block.clone(),
                confirmations: 21,
            },
            last_inclusion: Some(block.clone()),
            confidence_lost: false,
            reorganization_observed: false,
            source_ids: vec!["synthetic-node".into()],
            source_tips: vec![SourceTip {
                source_id: "synthetic-node".into(),
                tip: BlockIdentity {
                    height: 4_500_020,
                    hash: "bb".repeat(32),
                },
            }],
            independently_consensus_verified: false,
            clears_authorization_exposure: false,
            permits_replacement: false,
        };
        let inputs = vec![(0, "cc".repeat(32))];
        let record: SignerResolutionRecord = serde_json::from_value(json!({
            "original_consent_ref":"dd".repeat(32),"request_digest":"ee".repeat(32),"source":source,
            "transaction":target,"report":report,"archive":null,
            "witness":{"record":{"operation_id":"synthetic-resolution","account_id":account,
                "network_profile_id":"ironwood-testnet-nu7-candidate","expected_head":{"sequence":1,"digest":"12".repeat(32)},
                "reservation_operation_id":"synthetic-authorization","reservation_request_digest":"ee".repeat(32),
                "final_transaction_id":"88".repeat(32),"final_transaction_digest":"99".repeat(32),
                "source_descriptor_digest":witness,"evidence_digest":"13".repeat(32),
                "consumed_nullifiers":[inputs[0].1],"inclusion_block_hash":block.hash,"inclusion_block_height":block.height},
                "committed_head":{"sequence":2,"digest":"14".repeat(32)}},
            "consumed_nullifiers":[inputs[0].1]
        })).unwrap();
        (record, inputs, "15".repeat(32))
    }
    fn copy(record: &SignerResolutionRecord) -> SignerResolutionRecord {
        serde_json::from_value(serde_json::to_value(record).unwrap()).unwrap()
    }
    #[test]
    fn historical_consumed_shape_keeps_old_time_and_rejects_cross_link_tamper() {
        let (record, inputs, effects) = fixture();
        validate_historical_positive(
            &record,
            "canonical_consumed",
            &"16".repeat(32),
            &inputs,
            &effects,
        )
        .unwrap();
        for mode in 0..7 {
            let mut wrong = copy(&record);
            match mode {
                0 => wrong.witness.record.source_descriptor_digest = "17".repeat(32),
                1 => wrong.witness.committed_head.sequence += 1,
                2 => wrong.consumed_nullifiers.push(inputs[0].1.clone()),
                3 => wrong.witness.record.final_transaction_digest = "18".repeat(32),
                4 => wrong.witness.record.reservation_request_digest = "19".repeat(32),
                5 => wrong.report.as_mut().unwrap().permits_replacement = true,
                _ => wrong.report.as_mut().unwrap().confidence_lost = true,
            }
            assert!(
                validate_historical_positive(
                    &wrong,
                    "canonical_consumed",
                    &"16".repeat(32),
                    &inputs,
                    &effects
                )
                .is_err(),
                "tamper {mode}"
            );
        }
        assert!(
            validate_historical_positive(
                &record,
                "canonical_conflict",
                &"16".repeat(32),
                &inputs,
                &effects
            )
            .is_err()
        );
        let mut wrong = copy(&record);
        wrong.witness.record.conflict =
            Some(wholepact_chain::local_node::CanonicalConflictCandidate {
                included_transaction_id: "20".repeat(32),
                original_transaction_hex: "00".into(),
                nullifier: inputs[0].1.clone(),
            });
        assert!(
            validate_historical_positive(
                &wrong,
                "canonical_conflict",
                &"16".repeat(32),
                &inputs,
                &effects
            )
            .is_err()
        );
    }
    #[test]
    fn historical_archive_checks_exact_bytes_source_inclusion_and_digest() {
        let (mut record, inputs, effects) = fixture();
        let raw =
            include_str!("../../../wholepact-chain/src/fixtures/synthetic-conflict-original.hex")
                .trim();
        let bytes = hex::decode(raw).unwrap();
        let plan = wholepact_chain::SubmissionPlan::new(
            "synthetic-obligation",
            "synthetic-proposal",
            "synthetic-dispatch",
            &bytes,
        )
        .unwrap();
        record.transaction = plan.descriptor().clone();
        record.witness.record.final_transaction_id = record.transaction.transaction_id.clone();
        record.witness.record.final_transaction_digest = record.transaction.bytes_sha256.clone();
        record.report = None;
        let source = record.source.source();
        let archive = json!({"source":source,"target_inputs":inputs,"target_shielded_sighash":effects,
            "source_id":source.source_id,"source_release":source.node_release,"source_commit":source.node_source_commit,
            "certificate_sha256":source.pinned_certificate_sha256,"session_binding_sha256":"21".repeat(32),
            "target":record.transaction,"included_transaction_id":record.transaction.transaction_id,"included_transaction_hex":raw,
            "inclusion":{"height":record.witness.record.inclusion_block_height,"hash":record.witness.record.inclusion_block_hash},
            "tip":{"height":4_500_020,"hash":"22".repeat(32)},"tip_mined_at":110,"observed_at":100,
            "required_confirmations":10,"kind":{"kind":"exact_transaction_consumed"}});
        record.archive = Some(archive.to_string());
        let evidence = hex::encode(sha2::Sha256::digest(
            record.archive.as_ref().unwrap().as_bytes(),
        ));
        validate_historical_positive(&record, "canonical_consumed", &evidence, &inputs, &effects)
            .unwrap();
        assert!(
            validate_historical_positive(
                &record,
                "canonical_consumed",
                &"23".repeat(32),
                &inputs,
                &effects
            )
            .is_err()
        );
        for pointer in [
            "/source_id",
            "/inclusion/hash",
            "/included_transaction_id",
            "/target_shielded_sighash",
        ] {
            let mut wrong = archive.clone();
            *wrong.pointer_mut(pointer).unwrap() = json!("24".repeat(32));
            record.archive = Some(wrong.to_string());
            let bad = hex::encode(sha2::Sha256::digest(
                record.archive.as_ref().unwrap().as_bytes(),
            ));
            assert!(
                validate_historical_positive(
                    &record,
                    "canonical_consumed",
                    &bad,
                    &inputs,
                    &effects
                )
                .is_err()
            );
        }
    }
    #[test]
    fn historical_reason_reopens_bind_prior_event_without_any_mutation() {
        let (record, _, _) = fixture();
        let c = rusqlite::Connection::open_in_memory().unwrap();
        let prior = (
            "25".repeat(32),
            record.source.reference().into(),
            "canonical_conflict".into(),
        );
        for (reason, domain) in [
            (
                "independent_observation_failed",
                "wholepact:signer-observation-failed:v1",
            ),
            (
                "independent_canonical_revalidation_unavailable",
                "wholepact:signer-source-freshness-lost:v1",
            ),
        ] {
            let evidence = digest(
                domain,
                &(
                    &prior.0,
                    "synthetic-authorization",
                    record.source.reference(),
                ),
            )
            .unwrap();
            let raw = json!({"reason":reason}).to_string();
            validate_historical_reopen(
                &c,
                &raw,
                &evidence,
                "synthetic-authorization",
                &record.source,
                "synthetic-obligation",
                Some(&prior),
                "synthetic-account",
            )
            .unwrap();
            assert!(
                validate_historical_reopen(
                    &c,
                    &raw,
                    &evidence,
                    "substituted-authorization",
                    &record.source,
                    "synthetic-obligation",
                    Some(&prior),
                    "synthetic-account"
                )
                .is_err()
            );
            assert!(
                validate_historical_reopen(
                    &c,
                    &raw,
                    &evidence,
                    "synthetic-authorization",
                    &record.source,
                    "synthetic-obligation",
                    None,
                    "synthetic-account"
                )
                .is_err()
            );
        }
        assert_eq!(c.total_changes(), 0);
    }
    #[test]
    fn historical_recovery_reopen_requires_exact_retained_generation() {
        let (record, _, _) = fixture();
        let c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE signer_recovery_generations(generation_id TEXT,phase TEXT,payload TEXT);",
        )
        .unwrap();
        let generation = "26".repeat(32);
        let prior = (
            "27".repeat(32),
            record.source.reference().into(),
            "canonical_consumed".into(),
        );
        let raw = json!({"reason":"restored_positive_evidence_requires_fresh_requalification"})
            .to_string();
        let evidence = digest(
            "wholepact:recovery-conservative-reopen:v1",
            &(
                &generation,
                &prior.0,
                "synthetic-authorization",
                record.source.reference(),
            ),
        )
        .unwrap();
        assert!(
            validate_historical_reopen(
                &c,
                &raw,
                &evidence,
                "synthetic-authorization",
                &record.source,
                "synthetic-obligation",
                Some(&prior),
                "synthetic-account"
            )
            .is_err()
        );
        let activation = json!({"operation_id":"synthetic-recovery","generation_id":generation,"inventory_digest":"28".repeat(32),
            "fence_digest":"29".repeat(32),"history_digest":"30".repeat(32),"account_id":"synthetic-account","writer_epoch":2,
            "source_bundle_digest":"31".repeat(32),"source_component_digest":"32".repeat(32),"target_profile":"synthetic-private-profile","review_digest":"33".repeat(32)});
        c.execute(
            "INSERT INTO signer_recovery_generations VALUES(?1,'committed',?2)",
            rusqlite::params![generation, activation.to_string()],
        )
        .unwrap();
        let before = c.total_changes();
        validate_historical_reopen(
            &c,
            &raw,
            &evidence,
            "synthetic-authorization",
            &record.source,
            "synthetic-obligation",
            Some(&prior),
            "synthetic-account",
        )
        .unwrap();
        assert_eq!(before, c.total_changes());
    }
    #[test]
    fn historical_negative_tuple_preserves_direct_reopen_without_positive() {
        let (record, _, _) = fixture();
        let c = rusqlite::Connection::open_in_memory().unwrap();
        let mut report = record.report.unwrap();
        report.confidence_lost = true;
        report.state = SettlementObservationState::InclusionUncertain;
        let raw = serde_json::to_string(&(
            "34".repeat(32),
            &record.transaction,
            &report,
            &record.source,
        ))
        .unwrap();
        validate_historical_reopen(
            &c,
            &raw,
            &"35".repeat(32),
            "synthetic-authorization",
            &record.source,
            "synthetic-obligation",
            None,
            "synthetic-account",
        )
        .unwrap();
        assert!(
            validate_historical_reopen(
                &c,
                &raw,
                &"35".repeat(32),
                "synthetic-authorization",
                &record.source,
                "wrong-obligation",
                None,
                "synthetic-account"
            )
            .is_err()
        );
        report.confidence_lost = false;
        let raw = serde_json::to_string(&(
            "34".repeat(32),
            &record.transaction,
            &report,
            &record.source,
        ))
        .unwrap();
        assert!(
            validate_historical_reopen(
                &c,
                &raw,
                &"35".repeat(32),
                "synthetic-authorization",
                &record.source,
                "synthetic-obligation",
                None,
                "synthetic-account"
            )
            .is_err()
        );
        assert_eq!(c.total_changes(), 0);
    }
    #[test]
    fn historical_reader_empty_is_inert_and_over_capacity_is_denied() {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE signer_settlement_events(sequence INTEGER PRIMARY KEY,evidence_id TEXT,authorization_id TEXT,source_ref TEXT,kind TEXT,payload TEXT);").unwrap();
        let account = SignerAccountState {
            account_id: "synthetic-account".into(),
            writer_epoch: 7,
            recovery_required: true,
        };
        let result = read_permanent_stop_history(&c, &account).unwrap();
        assert_eq!(result["current_authentication"], false);
        assert_eq!(result["release_authority"], false);
        assert_eq!(result["settlement_events"], json!([]));
        assert_eq!(c.total_changes(), 0);
        c.execute_batch("WITH RECURSIVE x(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM x WHERE n<4097) INSERT INTO signer_settlement_events(sequence) SELECT n FROM x;").unwrap();
        let before = c.total_changes();
        assert!(matches!(
            read_permanent_stop_history(&c, &account),
            Err(JournalError::Limit)
        ));
        assert_eq!(before, c.total_changes());
    }
}
