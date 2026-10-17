//! Concrete current installed-peer owners, one atomic immutable invocation claim.
use super::super::construction_claim_v3::*;
use super::*;
use wholepact_signer_origin::AdmittedManualRosterConstructionContributionV3;

pub enum ManualRosterConstructionClaimOutcomeV3<'store> {
    Started(ManualRosterConstructionClaimTokenV3<'store>),
    ExistingOnly(ManualRosterConstructionClaimV3),
}
/// No Clone/Deserialize/constructor. Lost response permanently loses builder
/// permission: retained rows are read-only evidence, never a token factory.
pub struct ManualRosterConstructionClaimTokenV3<'store> {
    store: &'store Store,
    claim: ManualRosterConstructionClaimV3,
}
impl ManualRosterConstructionClaimTokenV3<'_> {
    pub fn row(&self) -> &ManualRosterConstructionClaimV3 {
        &self.claim
    }
    /// Persist the exact constructed artifact receipt BEFORE private enqueue.
    /// This consumes the only in-process builder claim even if commit fails.
    pub fn record_checkpoint(
        self,
        checkpoint: ManualRosterConstructionCheckpointV3,
    ) -> Result<ManualRosterConstructionCheckpointV3> {
        self.record_checkpoint_with_mode(checkpoint, ManualPersistenceMode::Existing)
    }
    /// Exact same consuming receipt write, with fail-fast lock contention.
    /// Error can follow a durable commit; it never permits reconstruction.
    pub fn record_checkpoint_fail_fast(
        self,
        checkpoint: ManualRosterConstructionCheckpointV3,
    ) -> Result<ManualRosterConstructionCheckpointV3> {
        self.record_checkpoint_with_mode(checkpoint, ManualPersistenceMode::FailFast)
    }
    fn record_checkpoint_with_mode(
        self,
        checkpoint: ManualRosterConstructionCheckpointV3,
        mode: ManualPersistenceMode,
    ) -> Result<ManualRosterConstructionCheckpointV3> {
        checkpoint.validate_for(&self.claim)?;
        let mut c = match mode {
            ManualPersistenceMode::Existing => self
                .store
                .connection
                .lock()
                .map_err(|_| StoreError::Poisoned)?,
            ManualPersistenceMode::FailFast => {
                self.store
                    .connection
                    .try_lock()
                    .map_err(|error| match error {
                        std::sync::TryLockError::WouldBlock => StoreError::ResourceExhausted,
                        std::sync::TryLockError::Poisoned(_) => StoreError::Poisoned,
                    })?
            }
        };
        mode.with_connection(&mut c, |c| {
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            crate::backup::require_construction_v3_encoding(&tx)?;
            if matches!(self.claim.version, 4 | 5) {
                crate::backup::require_construction_v4_encoding(&tx)?;
            }
            if self.claim.version == 5 {
                crate::backup::require_construction_v5_encoding(&tx)?;
            }
            let (claims, checkpoints) = read_construction_rows(&tx)?;
            let id = self.claim.digest()?;
            let original = claims
                .iter()
                .find(|(key, _)| key == &id)
                .ok_or(StoreError::RecoveryRequired)?;
            if original.1 != self.claim
                || checkpoints.iter().any(|(key, _)| key == &id)
                || self.store.generation_fenced(
                    &tx,
                    "record",
                    &format!("{CONSTRUCTION_CLAIM_V3}:{id}"),
                )?
            {
                return Err(StoreError::RecoveryRequired);
            }
            let first = &self.claim.consumed[0].request.plan;
            kernel::require_continuation_original_v3(
                self.store,
                &tx,
                first.enrollment(),
                &first
                    .retained
                    .selection
                    .scope
                    .selection
                    .inventory
                    .enrollment_ref,
                &first
                    .retained
                    .selection
                    .scope
                    .selection
                    .inventory
                    .witness_extension_digest,
                &store_known_inherited(&tx)?,
            )?;
            insert_row(&tx, CONSTRUCTION_CHECKPOINT_V3, &id, &checkpoint)?;
            read_construction_rows(&tx)?;
            tx.commit()?;
            Ok(checkpoint)
        })
    }
}
struct ConstructionInvocation<'a> {
    principal: &'a str,
    key: &'a str,
    maximum_actions: usize,
}
impl Store {
    /// An exact fresh full-roster conjunction, never an ordinary financial gate
    /// exception. Existing rows return historical evidence with no builder owner.
    pub fn claim_manual_roster_construction_v3<'store>(
        &'store self,
        target: &ManualStoreTarget<'_>,
        expected: &StoredRecord,
        principal: &str,
        key: &str,
        maximum_actions: usize,
        admitted: &[&AdmittedManualRosterConstructionContributionV3],
    ) -> Result<ManualRosterConstructionClaimOutcomeV3<'store>> {
        self.claim_manual_roster_construction_v3_with_mode(
            target,
            expected,
            ConstructionInvocation {
                principal,
                key,
                maximum_actions,
            },
            admitted,
            ManualPersistenceMode::Existing,
            None,
        )
    }
    /// Same one-use native owners and immutable claim; only contention policy
    /// changes. Filesystem, SQLite and commit duration are not hard-bounded.
    pub fn claim_manual_roster_construction_v3_fail_fast<'store>(
        &'store self,
        target: &ManualStoreTarget<'_>,
        expected: &StoredRecord,
        principal: &str,
        key: &str,
        maximum_actions: usize,
        admitted: &[&AdmittedManualRosterConstructionContributionV3],
    ) -> Result<ManualRosterConstructionClaimOutcomeV3<'store>> {
        self.claim_manual_roster_construction_v3_with_mode(
            target,
            expected,
            ConstructionInvocation {
                principal,
                key,
                maximum_actions,
            },
            admitted,
            ManualPersistenceMode::FailFast,
            None,
        )
    }
    /// The only observed construction issuer accepts the actual held wallet
    /// conjunction, not a deserialized record, timestamp, trait, or callback.
    #[cfg(feature = "observed-construction")]
    pub fn claim_manual_roster_construction_v5_fail_fast<'store>(
        &'store self,
        target: &ManualStoreTarget<'_>,
        expected: &StoredRecord,
        principal: &str,
        key: &str,
        maximum_actions: usize,
        admitted: &[&AdmittedManualRosterConstructionContributionV3],
        held: &wholepact_wallet::wallet::protected_sync::exact_input_observation::HeldCommonContextRosterObservation<'_>,
    ) -> Result<ManualRosterConstructionClaimOutcomeV3<'store>> {
        let observe = || {
            held.require_original_admissions(admitted)
                .map_err(|_| StoreError::RecoveryRequired)?;
            let facts = held
                .historical_provenance_v1()
                .map_err(|_| StoreError::RecoveryRequired)?;
            held.require_original_admissions(admitted)
                .map_err(|_| StoreError::RecoveryRequired)?;
            Ok(facts)
        };
        self.claim_manual_roster_construction_v3_with_mode(
            target,
            expected,
            ConstructionInvocation {
                principal,
                key,
                maximum_actions,
            },
            admitted,
            ManualPersistenceMode::FailFast,
            Some(&observe),
        )
    }
    fn claim_manual_roster_construction_v3_with_mode<'store>(
        &'store self,
        target: &ManualStoreTarget<'_>,
        expected: &StoredRecord,
        invocation: ConstructionInvocation<'_>,
        admitted: &[&AdmittedManualRosterConstructionContributionV3],
        mode: ManualPersistenceMode,
        // Private code sharing only. The sole Some caller above closes over
        // the nominal held owner; no external DTO/closure issuer exists.
        observe: Option<&dyn Fn() -> Result<wholepact_core::common_context_historical_provenance_v1::CommonContextHistoricalProvenanceV1>>,
    ) -> Result<ManualRosterConstructionClaimOutcomeV3<'store>> {
        let ConstructionInvocation {
            principal,
            key,
            maximum_actions,
        } = invocation;
        let mut consumed = Vec::with_capacity(admitted.len());
        let mut reentry_lineages = Vec::new();
        for owner in admitted {
            owner.check_completion().map_err(denied)?;
            let request = owner.request().map_err(denied)?;
            require_target_with_mode(self, target, request.plan.enrollment(), mode)?;
            let audit: ManualRosterConsumedConstructionAuditV3 =
                strict(&serde_json::to_value(owner.evidence())?)?;
            if audit.digest()? != owner.evidence().digest().map_err(denied)? {
                return Err(StoreError::RecoveryRequired);
            }
            if let Some(lineage) = owner.reentry_lineage() {
                validate_reentry_lineage(lineage, &audit)?;
                reentry_lineages.push(lineage.clone());
            }
            consumed.push(audit);
        }
        let historical_provenance = observe.map(|f| f()).transpose()?;
        let claim = ManualRosterConstructionClaimV3 {
            version: if historical_provenance.is_some() {
                5
            } else if reentry_lineages.is_empty() {
                3
            } else {
                4
            },
            historical_provenance,
            reentry_lineages: (!reentry_lineages.is_empty()).then_some(reentry_lineages),
            principal_id: principal.into(),
            construction_key: key.into(),
            maximum_actions,
            consumed,
        };
        claim.validate()?;
        let id = claim.digest()?;
        let existing = with_historical_observation_boundary(
            &claim.historical_provenance,
            observe,
            || {
                let mut c = self.connection.try_lock().map_err(|error| match error {
                    std::sync::TryLockError::WouldBlock => StoreError::ResourceExhausted,
                    std::sync::TryLockError::Poisoned(_) => StoreError::Poisoned,
                })?;
                let existing = mode.with_connection(&mut c, |c| {
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            crate::backup::require_construction_v3_encoding(&tx)?;
            if matches!(claim.version, 4 | 5) { crate::backup::require_construction_v4_encoding(&tx)?; }
            if claim.version == 5 { crate::backup::require_construction_v5_encoding(&tx)?; }
        let (existing, _) = read_construction_rows(&tx)?;
        for (saved_id, saved) in &existing {
            if saved.request_identity()? == claim.request_identity()?
                || saved.invocation().operation_id == claim.invocation().operation_id
                || saved.invocation().invocation_nonce == claim.invocation().invocation_nonce
                || (saved.proposal().manifest.agreement.agreement_id
                    == claim.proposal().manifest.agreement.agreement_id
                    && saved.candidate_id() == claim.candidate_id())
            {
                if saved_id != &id || saved != &claim {
                    return Err(StoreError::IdempotencyConflict);
                }
                return Ok(Some(saved.clone()));
            }
        }
        let mut combined = existing.clone();
        combined.push((id.clone(), claim.clone()));
        // No old ambiguous claim may silently make the same actual inputs
        // available under a different invocation, key, candidate or deadline.
        validate_construction_set(&combined, &[]).map_err(|_| StoreError::InputReserved)?;
        let other = super::super::construction_claim_v2::read_local_rows(&tx)?.0;
        super::super::construction_claim_union::validate_union(&other, &combined).map_err(|_| StoreError::InputReserved)?;
        if existing.len() >= 256 {
            return Err(StoreError::ResourceExhausted);
        }
        let context = crate::CommandContext {
            principal_id: principal.into(),
            idempotency_key: key.into(),
            request_digest: claim.request_digest()?,
        };
        require_unused_generic_context(&tx, &context)?;
        super::super::require_generic_request_not_manual(&tx, &context)?;
        self.require_current_replay(&tx, &context)?;
        for operation in std::iter::once(claim.invocation().operation_id.as_str()).chain(
            claim
                .consumed
                .iter()
                .map(|a| a.request.operation_id.as_str()),
        ) {
            super::super::require_generic_operation_not_manual(&tx, operation)?;
            if self.generation_fenced(&tx,"operation",operation)? || self.generation_fenced(&tx,"effect",operation)?
                || tx.query_row("SELECT EXISTS(SELECT 1 FROM operations WHERE operation_id=?1 UNION ALL SELECT 1 FROM effect_intents WHERE operation_id=?1)",[operation],|r|r.get::<_,bool>(0))? {
                return Err(StoreError::RecoveryRequired);
            }
        }

        self.require_current_record_write(
            &tx,
            CONSTRUCTION_CLAIM_V3,
            &id,
            &serde_json::to_value(&claim)?,
        )?;
        let known = store_known_inherited(&tx)?;
        let additions =
            read_audits::<ManualEnrollmentAdditionalPublicationV3>(&tx, ADDITIONAL_PUBLICATION_V3)?;
        let continuations =
            read_audits::<ManualEnrollmentContinuationAuditV4>(&tx, CONTINUATION_V4)?;
        super::super::additional_publication::validate_chains(&additions, &continuations)?;
        for audit in &claim.consumed {
            let plan = &audit.request.plan;
            let selection = &plan.retained.selection.scope.selection;
            let inventory = &selection.inventory;
            let terms = plan.enrollment();
            kernel::require_agreement_snapshot(&tx, expected, terms)?;
            if expected.revision != claim.agreement_revision()
                || expected.payload.pointer("/view/agreement")
                    != Some(&serde_json::to_value(&claim.proposal().manifest.agreement)?)
                || expected
                    .payload
                    .pointer("/view/candidates")
                    .and_then(serde_json::Value::as_array)
                    .ok_or(StoreError::RecoveryRequired)?
                    .iter()
                    .any(|candidate| {
                        candidate
                            .get("candidate_id")
                            .and_then(serde_json::Value::as_str)
                            == Some(claim.candidate_id())
                    })
            {
                return Err(StoreError::RevisionConflict);
            }
            let original = kernel::require_continuation_original_v3(
                self,
                &tx,
                terms,
                &inventory.enrollment_ref,
                &inventory.witness_extension_digest,
                &known,
            )?;
            let provenance = &plan.retained.selection.scope.provenance;
            if provenance.original_host_audit.audit_digest() != original.digest()?
                || provenance.roster != original.evidence.request.roster
                || provenance.signer_roster_record_digest
                    != original.evidence.signer_roster_record_digest
                || provenance.witness_roster_extension_digest
                    != original.evidence.witness_roster_extension_digest
            {
                return Err(StoreError::RecoveryRequired);
            }
            let latest = continuations
                .iter()
                .filter(|(_, a)| {
                    a.original_audit.audit_digest() == provenance.original_host_audit.audit_digest()
                })
                .max_by_key(|(_, a)| a.store_sequence)
                .ok_or(StoreError::RecoveryRequired)?;
            if latest.1.evidence.admission.attempt_sequence != audit.current_attempt_sequence
                || latest.1.evidence.admission.attempt_digest != audit.current_attempt_digest
                || audit.current_attempt_sequence <= inventory.attempt.attempt_sequence
            {
                return Err(StoreError::RecoveryRequired);
            }
            let exclusions = crate::financial_preflight::read_retained_input_exclusions(
                &tx,
                &terms.identity.account_id,
                &original.aliases,
            )?;
            if exclusions.snapshot_digest()? != plan.retained.local_exclusion_digest
                || plan
                    .selected_inputs()
                    .iter()
                    .any(|i| exclusions.excludes(&i.input_id, &i.nullifier))
            {
                return Err(StoreError::InputReserved);
            }
        }
        for owner in admitted {
            owner.check_completion().map_err(denied)?;
        }
        insert_row(&tx, CONSTRUCTION_CLAIM_V3, &id, &claim)?;
        read_construction_rows(&tx)?;
        tx.commit()?;
        Ok(None)
        })?;
                drop(c);
                Ok(existing)
            },
        )?;
        if let Some(saved) = existing {
            return Ok(ManualRosterConstructionClaimOutcomeV3::ExistingOnly(saved));
        }
        // Failure here means ambiguous retained claim, never rollback/reissue.
        target.check_current_with_mode(mode)?;
        for owner in admitted {
            owner.check_completion().map_err(denied)?;
        }
        Ok(ManualRosterConstructionClaimOutcomeV3::Started(
            ManualRosterConstructionClaimTokenV3 { store: self, claim },
        ))
    }
}
fn insert_row<T: Serialize>(
    tx: &rusqlite::Transaction<'_>,
    kind: &str,
    id: &str,
    value: &T,
) -> Result<()> {
    let payload = crate::encode(&serde_json::to_value(value)?)?;
    tx.execute(
        "INSERT INTO records VALUES(?1,?2,0,?3,?4,?4)",
        params![kind, id, payload, crate::now_ms()],
    )?;
    Ok(())
}

/// Private ordering boundary. Full wallet restrictions may query this same
/// Store, so they run only before the persistence closure and after its locks
/// have been released. Persistence itself retains direct Store/native checks.
/// A failed postcheck leaves any durable claim intact and returns no token.
fn with_historical_observation_boundary<T>(
    expected: &Option<wholepact_core::common_context_historical_provenance_v1::CommonContextHistoricalProvenanceV1>,
    observe: Option<&dyn Fn() -> Result<wholepact_core::common_context_historical_provenance_v1::CommonContextHistoricalProvenanceV1>>,
    persist: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let check = || -> Result<()> {
        if observe.map(|f| f()).transpose()? != *expected {
            return Err(StoreError::RecoveryRequired);
        }
        Ok(())
    };
    with_claim_pre_post_checks(check, persist)
}
fn with_claim_pre_post_checks<T>(
    check: impl Fn() -> Result<()>,
    persist: impl FnOnce() -> Result<T>,
) -> Result<T> {
    check()?;
    let output = persist()?;
    check()?;
    Ok(output)
}

#[cfg(test)]
mod historical_claim_boundary_tests {
    use super::*;
    use std::cell::Cell;
    #[test]
    fn historical_claim_v5_boundary_keeps_full_checks_outside_persistence_lock() {
        let lock = std::sync::Mutex::new(());
        let checks = Cell::new(0);
        let durable = Cell::new(false);
        // Same private ordering primitive, with inert callbacks only. This
        // does not issue a native/held/Store construction owner.
        let output = with_claim_pre_post_checks(
            || {
                let _available = lock.try_lock().map_err(|_| StoreError::ResourceExhausted)?;
                checks.set(checks.get() + 1);
                Ok(())
            },
            || {
                let _guard = lock.try_lock().unwrap();
                assert_eq!(checks.get(), 1);
                durable.set(true);
                Ok(7)
            },
        )
        .unwrap();
        assert_eq!(output, 7);
        assert_eq!(checks.get(), 2);
        assert!(durable.get());
    }
    #[test]
    fn historical_claim_v5_failed_postcheck_keeps_durable_effect_without_output() {
        let checks = Cell::new(0);
        let durable = Cell::new(false);
        let output = with_claim_pre_post_checks(
            || {
                checks.set(checks.get() + 1);
                if checks.get() == 2 {
                    Err(StoreError::RecoveryRequired)
                } else {
                    Ok(())
                }
            },
            || {
                durable.set(true);
                Ok(7)
            },
        );
        assert!(matches!(output, Err(StoreError::RecoveryRequired)));
        assert!(durable.get());
        assert_eq!(checks.get(), 2);
    }
    #[test]
    fn historical_claim_v5_failed_precheck_does_not_start_persistence() {
        let started = Cell::new(false);
        let output = with_claim_pre_post_checks(
            || Err(StoreError::RecoveryRequired),
            || {
                started.set(true);
                Ok(7)
            },
        );
        assert!(output.is_err());
        assert!(!started.get());
    }
}
