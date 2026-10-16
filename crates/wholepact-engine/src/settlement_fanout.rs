//! Native-only replay of source-bound observation invalidation into one protected
//! engine store. Positive resolution additionally requires live exact node and
//! authenticated original signer provenance; neither path accepts a JSON permit.
use super::*;
use crate::participant_records::RecordStoreBinding;
use wholepact_chain::SubmissionDescriptor;
use wholepact_chain::settlement_evidence::RetainedSettlementObservation;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementSinkScope {
    pub store: RecordStoreBinding,
    pub destination: String,
    pub journal_identity: String,
    pub transaction: SubmissionDescriptor,
    pub affected_agreement_ids: Vec<String>,
    pub affected_account_ids: Vec<String>,
}
/// A trusted runtime must hold account/record mutation permission for every
/// affected local alternative until commit. An arbitrary caller's bool is not
/// authority, and an agreement read grant does not implement this lease.
pub trait SettlementSinkLease {
    fn scope(&self) -> &SettlementSinkScope;
    fn check_current(&self) -> Result<()>;
}
pub trait SettlementSinkAuthority: Send + Sync {
    /// Separate positive-mutation grant. Implementations must independently enroll
    /// this exact node descriptor and hold its approval through the commit. An
    /// invalidation-only grant can never be reused to free reservations.
    fn acquire_resolution<'a>(
        &'a self,
        _scope: &SettlementSinkScope,
        _source: &wholepact_chain::local_node::LocalNodeSourceDescriptor,
    ) -> Result<Box<dyn SettlementSinkLease + 'a>> {
        Err(ApiError::new(
            "SETTLEMENT_RESOLUTION_PERMISSION_REQUIRED",
            "A separate native resolution grant is required",
        ))
    }

    /// Exact alternative/nullifier disclosure needs its own native grant.
    fn acquire_conflict_resolution<'a>(
        &'a self,
        _scope: &SettlementSinkScope,
        _source: &wholepact_chain::local_node::LocalNodeSourceDescriptor,
        _candidate: &wholepact_chain::local_node::CanonicalConflictCandidate,
    ) -> Result<Box<dyn SettlementSinkLease + 'a>> {
        Err(ApiError::new(
            "SETTLEMENT_RESOLUTION_PERMISSION_REQUIRED",
            "An exact native conflict grant is required",
        ))
    }

    fn acquire<'a>(
        &'a self,
        scope: &SettlementSinkScope,
    ) -> Result<Box<dyn SettlementSinkLease + 'a>>;
}
impl Engine {
    pub fn settlement_sink_scope(
        &self,
        journal_identity: &str,
        transaction: &SubmissionDescriptor,
    ) -> Result<SettlementSinkScope> {
        if self.store.protection() != wholepact_store::StorageProtection::Encrypted {
            return Err(ApiError::new(
                "STORAGE_PROTECTION_REQUIRED",
                "Settlement fanout requires protected local storage",
            ));
        }
        if journal_identity.is_empty()
            || journal_identity.len() > 128
            || !journal_identity
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_:.".contains(&b))
        {
            return Err(ApiError::new(
                "SETTLEMENT_SCOPE_MISMATCH",
                "Invalid journal identity",
            ));
        }
        use sha2::{Digest, Sha256};
        let store_id = self.store.settlement_destination().map_err(store_error)?;
        let binding = serde_json::to_vec(&(store_id, journal_identity, transaction))
            .map_err(|_| ApiError::new("SETTLEMENT_SCOPE_MISMATCH", "Invalid source descriptor"))?;
        let destination = format!("store-{}", hex::encode(Sha256::digest(binding)));
        let mut affected_agreement_ids = Vec::new();
        let mut record_accounts = Vec::new();
        for record in self.store.list_agreements().map_err(store_error)? {
            let envelope: Envelope = decode(&record)?;
            if envelope.view.agreement.obligation_id == transaction.obligation_id {
                affected_agreement_ids.push(record.id);
                record_accounts.extend(
                    envelope
                        .participant_records
                        .values()
                        .map(|r| r.settlement_account_id().to_owned()),
                );
            }
        }
        affected_agreement_ids.sort();
        let mut affected_account_ids = self
            .store
            .settlement_affected_accounts(&transaction.obligation_id)
            .map_err(store_error)?;
        affected_account_ids.extend(record_accounts);
        affected_account_ids.sort();
        affected_account_ids.dedup();
        Ok(SettlementSinkScope {
            store: self.protected_record_store_binding()?,
            destination,
            journal_identity: journal_identity.into(),
            transaction: transaction.clone(),
            affected_agreement_ids,
            affected_account_ids,
        })
    }
    /// On failure the source delivery must remain pending. On success the caller
    /// may acknowledge exactly this destination/evidence pair. Replaying after a
    /// crash between commit and acknowledgment is harmless.
    pub fn apply_settlement_observation(
        &self,
        scope: &SettlementSinkScope,
        evidence: &RetainedSettlementObservation,
        authority: &dyn SettlementSinkAuthority,
    ) -> Result<()> {
        let expected =
            self.settlement_sink_scope(evidence.journal_identity(), evidence.descriptor())?;
        if *scope != expected {
            return Err(ApiError::new(
                "SETTLEMENT_SCOPE_MISMATCH",
                "Settlement source or local store changed",
            ));
        }
        let lease = authority.acquire(scope)?;
        if lease.scope() != scope {
            return Err(ApiError::new(
                "SETTLEMENT_SCOPE_MISMATCH",
                "Settlement lease does not bind this destination",
            ));
        }
        lease.check_current()?;
        // Never infer resolution from inclusion, absence, expiry or stale replay.
        if !evidence.requires_conservative_reopen() {
            return Ok(());
        }
        let snapshot = self.store.list_agreements().map_err(store_error)?;
        let mut current_ids = Vec::new();
        let mut record_accounts = Vec::new();
        for record in &snapshot {
            let envelope: Envelope = decode(record)?;
            if envelope.view.agreement.obligation_id == scope.transaction.obligation_id {
                current_ids.push(record.id.clone());
                record_accounts.extend(
                    envelope
                        .participant_records
                        .values()
                        .map(|r| r.settlement_account_id().to_owned()),
                );
            }
        }
        current_ids.sort();
        if current_ids != scope.affected_agreement_ids
            || record_accounts
                .iter()
                .any(|a| !scope.affected_account_ids.contains(a))
        {
            return Err(ApiError::new(
                "SETTLEMENT_SCOPE_MISMATCH",
                "Affected agreements changed; renew native permission",
            ));
        }
        let mut updates = Vec::new();
        for stored in &snapshot {
            let mut envelope: Envelope = decode(stored)?;
            if envelope.view.agreement.obligation_id != scope.transaction.obligation_id {
                continue;
            }
            let mut changed = false;
            for record in envelope.participant_records.values_mut() {
                changed |= record.invalidate_settlement()?;
            }
            if changed {
                envelope.view.revision = stored.revision.checked_add(1).ok_or_else(|| {
                    ApiError::new("RESOURCE_EXHAUSTED", "Agreement revision exhausted")
                })?;
                envelope.view.updated_at = now();
                updates.push((stored.id.clone(), encode(&envelope)?));
            }
        }
        lease.check_current()?;
        self.store
            .reopen_settlement_obligation(
                evidence.evidence_id(),
                &scope.transaction.obligation_id,
                &snapshot,
                &scope.affected_account_ids,
                &updates,
            )
            .map_err(store_error)?;
        lease.check_current()?;
        Ok(())
    }
}

#[cfg(all(feature = "signer-authority-bridge", target_os = "linux"))]
impl Engine {
    /// Apply only the exact authenticated original, never all authorizations
    /// sharing a proposal label. The receipt proves historical signer/witness
    /// commit; the independent live node permit supplies current canonicality.
    /// No account recovery fence or alternative authorization is cleared.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_settlement_resolution(
        &self,
        scope: &SettlementSinkScope,
        evidence: &RetainedSettlementObservation,
        permit: &wholepact_chain::local_node::LocalResolutionPermit,
        enrolled_source: &wholepact_chain::local_node::LocalNodeSourceDescriptor,
        history: &wholepact_signer::authority_bridge::ipc::OriginalHistoryLease<'_>,
        receipt: &wholepact_signer::authority_bridge::settlement_ipc::SignerSettlementReceipt<'_>,
        request: &wholepact_signer::authority_bridge::settlement_ipc::SettlementRequest,
        authority: &dyn SettlementSinkAuthority,
    ) -> Result<()> {
        self.apply_settlement_resolution_checked(
            scope,
            evidence,
            permit,
            enrolled_source,
            history,
            receipt,
            request,
            authority,
            &|| Ok(()),
        )
    }

    // Additional exact local-record permission only. This callback must not load
    // Store data: the final invocation runs while the Store transaction is held.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn apply_settlement_resolution_checked(
        &self,
        scope: &SettlementSinkScope,
        evidence: &RetainedSettlementObservation,
        permit: &wholepact_chain::local_node::LocalResolutionPermit,
        enrolled_source: &wholepact_chain::local_node::LocalNodeSourceDescriptor,
        history: &wholepact_signer::authority_bridge::ipc::OriginalHistoryLease<'_>,
        receipt: &wholepact_signer::authority_bridge::settlement_ipc::SignerSettlementReceipt<'_>,
        request: &wholepact_signer::authority_bridge::settlement_ipc::SettlementRequest,
        authority: &dyn SettlementSinkAuthority,
        check_record_permission: &dyn Fn() -> Result<()>,
    ) -> Result<()> {
        let denied = || {
            ApiError::new(
                "SETTLEMENT_RESOLUTION_UNAVAILABLE",
                "Exact current settlement provenance could not be verified",
            )
        };
        if *scope
            != self.settlement_sink_scope(evidence.journal_identity(), evidence.descriptor())?
            || evidence.requires_conservative_reopen()
            || !resolution_selection_matches(
                permit.kind(),
                permit.included_transaction_id(),
                &scope.transaction.transaction_id,
                request.conflict.as_ref(),
            )
            || !receipt.matches_history(history)
            || receipt.request_digest() != request.digest().map_err(|_| denied())?
            || request.dispatch_operation_id
                != native_account_dispatch_operation(
                    &scope.transaction.operation_id,
                    &request.history.authorization_id,
                )?
        {
            return Err(denied());
        }
        let original = history.evidence();
        let terms = original.consent.terms();
        let release = original.release_intent.intent();
        let result = original.retained_result.as_ref().ok_or_else(denied)?;
        if request.history.authorization_id != terms.authorization_id
            || request.history.expected_original_consent_ref != original.consent.reference()
            || request.history.expected_enrollment_ref != original.enrollment.reference()
            || request.history.expected_manifest_ref != original.accepted_manifest.reference()
            || original.release_intent.original_consent_ref() != original.consent.reference()
            || result.authorization_id != terms.authorization_id
            || result.original_consent_ref != original.consent.reference()
            || !history.result_is_for_current_recipient()
            || release.authorization_id != terms.authorization_id
            || release.account_id != terms.account_id
            || release.obligation_id != scope.transaction.obligation_id
            || terms.obligation_id != scope.transaction.obligation_id
            || terms.effects_digest != permit.target_shielded_sighash()
            || release.effects_digest != terms.effects_digest
            || terms.transaction_expiry_height != scope.transaction.expiry_height
            || terms.input_bindings.is_empty()
            || terms.input_bindings.iter().any(|i| {
                !permit
                    .target_inputs()
                    .contains(&(i.action_index, i.nullifier.clone()))
            })
            || !scope.affected_account_ids.contains(&terms.account_id)
            || !scope.affected_agreement_ids.contains(&terms.agreement_id)
        {
            return Err(denied());
        }
        let lease = match &request.conflict {
            Some(candidate) => {
                let inputs: Vec<_> = terms
                    .input_bindings
                    .iter()
                    .map(|i| (i.action_index, i.nullifier.clone()))
                    .collect();
                candidate
                    .validate_original(&scope.transaction, &terms.effects_digest, &inputs)
                    .map_err(|_| denied())?;
                authority.acquire_conflict_resolution(scope, enrolled_source, candidate)?
            }
            None => authority.acquire_resolution(scope, enrolled_source)?,
        };
        if lease.scope() != scope {
            return Err(denied());
        }
        // The held native lease fences revocation through commit. Its current
        // scope check may read this same store, so never call it while the store
        // transaction mutex is held. Independent source/history checks are safe
        // inside the transaction and run immediately before commit.
        let check = || -> Result<()> {
            history.check_current().map_err(|_| denied())?;
            permit
                .check_source(evidence, enrolled_source)
                .map_err(|_| denied())?;
            // Last: history liveness may block on IPC. Do not let that interval
            // consume the selected record permission before the final commit.
            check_record_permission()
        };
        lease.check_current()?;
        check()?;
        let snapshot = self.store.list_agreements().map_err(store_error)?;
        let mut updates = Vec::new();
        let mut matched = false;
        for stored in &snapshot {
            let mut envelope: Envelope = decode(stored)?;
            if envelope.view.agreement.obligation_id != scope.transaction.obligation_id {
                continue;
            }
            let mut changed = false;
            for record in envelope.participant_records.values_mut() {
                if let Some(updated) =
                    record.resolve_exact_settlement(original, evidence, permit, enrolled_source)?
                {
                    matched = true;
                    changed |= updated;
                }
            }
            if changed {
                envelope.view.revision = stored.revision.checked_add(1).ok_or_else(denied)?;
                envelope.view.updated_at = now();
                updates.push((stored.id.clone(), encode(&envelope)?));
            }
        }
        if !matched {
            return Err(denied());
        }
        let provenance = serde_json::json!({
            "source": enrolled_source,
            "journal": evidence.journal_identity(),
            "transaction": evidence.descriptor(),
            "original_consent": original.consent.reference(),
            "signer_settlement_request": receipt.request_digest(),
            "result_digest": result.result_digest,
            "outbox_digest": result.outbox_digest,
            "provider_enrollment": history.provider_enrollment_reference(),
            "canonical_alternative": request.conflict.as_ref().map(|c| serde_json::json!({
                "included_transaction_id": c.included_transaction_id, "nullifier": c.nullifier,
                "original_transaction_id": scope.transaction.transaction_id,
                "original_bytes_sha256": scope.transaction.bytes_sha256,
                "inclusion": permit.inclusion(),
            })),
        });
        let live = || check().map_err(|_| wholepact_store::StoreError::RecoveryRequired);
        if request.conflict.is_some() {
            self.store.retain_exact_conflict_release(
                release,
                evidence.evidence_id(),
                &provenance,
                &snapshot,
                &updates,
                &live,
            )
        } else {
            self.store.consume_exact_settlement_release(
                release,
                evidence.evidence_id(),
                &provenance,
                &snapshot,
                &updates,
                &live,
            )
        }
        .map_err(store_error)?;
        lease.check_current()?;
        check()?;
        Ok(())
    }
}

/// Exact native dispatch key already used by the authenticated signer handoff.
/// A per-account dispatch is distinct from the coordinator submission operation.
pub fn native_account_dispatch_operation(
    submission_operation: &str,
    authorization: &str,
) -> Result<String> {
    wholepact_core::proposal::canonical_digest(
        "wholepact:native-account-dispatch:v1",
        &(submission_operation, authorization),
    )
    .map_err(|_| {
        ApiError::new(
            "SETTLEMENT_SCOPE_MISMATCH",
            "Invalid original dispatch binding",
        )
    })
}

#[cfg(all(feature = "signer-authority-bridge", target_os = "linux"))]
fn resolution_selection_matches(
    kind: &wholepact_chain::local_node::LocalResolutionKind,
    included: &str,
    original: &str,
    candidate: Option<&wholepact_chain::local_node::CanonicalConflictCandidate>,
) -> bool {
    use wholepact_chain::local_node::LocalResolutionKind;
    match (kind, candidate) {
        (LocalResolutionKind::ExactTransactionConsumed, None) => included == original,
        (LocalResolutionKind::IronwoodInputConflict { nullifier }, Some(c)) => {
            included == c.included_transaction_id
                && included != original
                && nullifier == &c.nullifier
        }
        _ => false,
    }
}

#[cfg(all(test, feature = "signer-authority-bridge", target_os = "linux"))]
mod conflict_selection_tests {
    use super::*;
    use wholepact_chain::local_node::{CanonicalConflictCandidate, LocalResolutionKind};
    #[test]
    fn canonical_conflict_selection_binds_alternative_nullifier_and_original_kind() {
        let candidate = CanonicalConflictCandidate {
            included_transaction_id: "11".repeat(32),
            original_transaction_hex: "00".into(),
            nullifier: "22".repeat(32),
        };
        let original = "33".repeat(32);
        let kind = LocalResolutionKind::IronwoodInputConflict {
            nullifier: candidate.nullifier.clone(),
        };
        assert!(resolution_selection_matches(
            &kind,
            &candidate.included_transaction_id,
            &original,
            Some(&candidate)
        ));
        assert!(!resolution_selection_matches(
            &kind,
            &candidate.included_transaction_id,
            &original,
            None
        ));
        assert!(!resolution_selection_matches(
            &kind,
            &original,
            &original,
            Some(&candidate)
        ));
        assert!(!resolution_selection_matches(
            &kind,
            &"44".repeat(32),
            &original,
            Some(&candidate)
        ));
        let wrong = LocalResolutionKind::IronwoodInputConflict {
            nullifier: "55".repeat(32),
        };
        assert!(!resolution_selection_matches(
            &wrong,
            &candidate.included_transaction_id,
            &original,
            Some(&candidate)
        ));
        assert!(!resolution_selection_matches(
            &LocalResolutionKind::ExactTransactionConsumed,
            &original,
            &original,
            Some(&candidate)
        ));
        assert!(resolution_selection_matches(
            &LocalResolutionKind::ExactTransactionConsumed,
            &original,
            &original,
            None
        ));
    }
}
