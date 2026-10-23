//! Audit-only concrete installed-signer consumers. These do not reserve inputs,
//! initialize accounts, change lifetime accounting or authorize any effect.
//! The Host owner must separately hold its real native decision and authenticate
//! plan/profile/root/financial registry and complete inherited capsule coverage.
//! No externally implemented trait, callback or verified boolean is accepted.
use super::*;
use crate::CommandContext;
use rusqlite::{Connection, TransactionBehavior, params};
use wholepact_signer_origin::manual::{
    DurableManualActionAdmission, DurableManualEnrollmentAdmission, ManualCurrentState,
};
use wholepact_signer_origin::{ManualActionLease, ManualEnrollmentLease};

/// Confirmation of retained audit bytes only. It cannot be consumed as a signer,
/// financial, witness-budget, key-use or external-effect permission.
pub struct ManualAuditAppendReceipt {
    audit_digest: String,
    operation_id: String,
    enrollment_ref: String,
    replayed: bool,
}
impl ManualAuditAppendReceipt {
    pub fn audit_digest(&self) -> &str {
        &self.audit_digest
    }
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
    pub fn enrollment_ref(&self) -> &str {
        &self.enrollment_ref
    }
    pub fn replayed(&self) -> bool {
        self.replayed
    }
}
fn denied(_: wholepact_signer_origin::Error) -> StoreError {
    StoreError::RecoveryRequired
}
fn require_target(
    store: &Store,
    target: &ManualStoreTarget<'_>,
    terms: &BornManualEnrollmentTerms,
) -> Result<()> {
    require_target_with_mode(store, target, terms, ManualPersistenceMode::Existing)
}
fn require_target_with_mode(
    store: &Store,
    target: &ManualStoreTarget<'_>,
    terms: &BornManualEnrollmentTerms,
    mode: ManualPersistenceMode,
) -> Result<()> {
    if !std::ptr::eq(store, target.store)
        || target.generation_id != terms.host.generation_id
        || target.inventory_digest != terms.host.inventory_digest
        || target.store_destination_identity != terms.host.store_destination_identity
    {
        return Err(StoreError::RecoveryRequired);
    }
    target.check_current_with_mode(mode)
}
fn require_writer(current: &ManualCurrentState, terms: &BornManualEnrollmentTerms) -> Result<()> {
    current.validate().map_err(denied)?;
    if current.writer_epoch != terms.signer.writer_epoch
        || current.writer_certificate_digest != terms.signer.writer_certificate_digest
    {
        return Err(StoreError::RecoveryRequired);
    }
    Ok(())
}
fn request_identity(
    context: &CommandContext,
    principal: &str,
    request: &serde_json::Value,
) -> Result<String> {
    crate::validate_context(context)?;
    if context.principal_id != principal || context.request_digest != request_digest(request)? {
        return Err(StoreError::IdempotencyConflict);
    }
    request_digest(&serde_json::json!([
        &context.principal_id,
        &context.idempotency_key
    ]))
}
fn require_unused_generic_context(c: &Connection, context: &CommandContext) -> Result<()> {
    let exists: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM idempotency WHERE principal_id=?1 AND idempotency_key=?2)",
        params![context.principal_id, context.idempotency_key],
        |r| r.get(0),
    )?;
    if exists {
        return Err(StoreError::IdempotencyConflict);
    }
    Ok(())
}
fn store_known_inherited(c: &Connection) -> Result<Vec<(ManualAccountIdentity, BTreeSet<String>)>> {
    let required = {
        let mut q =
            c.prepare("SELECT identity FROM store_generation_fences WHERE kind='account'")?;
        let rows = q
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<BTreeSet<_>>>()?;
        rows
    };
    let mut known: BTreeMap<String, (ManualAccountIdentity, BTreeSet<String>)> = BTreeMap::new();
    let sources = read_audits::<ManualEnrollmentAudit>(c, ENROLLMENT)?
        .into_iter()
        .map(|(_, a)| (a.terms.identity, a.aliases))
        .chain(
            read_audits::<ManualEnrollmentInitialPublicationV2>(c, INITIAL_PUBLICATION_V2)?
                .into_iter()
                .map(|(_, a)| (a.terms().identity.clone(), a.aliases)),
        )
        .chain(
            read_audits::<ManualEnrollmentAdditionalPublicationV3>(c, ADDITIONAL_PUBLICATION_V3)?
                .into_iter()
                .map(|(_, a)| (a.terms().identity.clone(), a.aliases)),
        )
        .chain(
            read_audits::<ManualExclusionAudit>(c, EXCLUSION)?
                .into_iter()
                .map(|(_, a)| (a.identity, a.aliases)),
        );
    for (identity, aliases) in sources {
        if aliases.is_disjoint(&required) {
            continue;
        }
        if let Some((old, old_aliases)) = known.get_mut(&identity.account_id) {
            if old != &identity {
                return Err(StoreError::RecoveryRequired);
            }
            old_aliases.extend(aliases);
        } else {
            known.insert(identity.account_id.clone(), (identity, aliases));
        }
    }
    // The kernel checks exact coverage of every Store-known inherited fence.
    // Legacy/v1 identities without these protected rows remain Unknown and deny.
    Ok(known.into_values().collect())
}
fn retained_enrollment_admission(
    value: &DurableManualEnrollmentAdmission,
) -> ManualDurableEnrollmentAudit {
    ManualDurableEnrollmentAudit {
        exact_request_digest: value.exact_request_digest.clone(),
        signer_intent_digest: value.signer_intent_digest.clone(),
        witness_admission_digest: value.witness_admission_digest.clone(),
        admitted_at_ms: value.admitted_at_ms,
        admission_deadline_ms: value.admission_deadline_ms,
    }
}
fn retained_admission(value: &DurableManualActionAdmission) -> ManualDurableActionAudit {
    ManualDurableActionAudit {
        exact_request_digest: value.exact_request_digest.clone(),
        signer_intent_digest: value.signer_intent_digest.clone(),
        witness_admission_digest: value.witness_admission_digest.clone(),
        admitted_at_ms: value.admitted_at_ms,
        admission_deadline_ms: value.admission_deadline_ms,
    }
}
impl Store {
    /// Retain exact genuine enrollment evidence. This consumes the concrete live
    /// lease and stores audit only. The actual Host owner must conjoin its native
    /// decision and full plan/profile/registry/inherited-identity coverage before
    /// this call. Success MUST NOT be used as a financial admission.
    pub fn append_manual_enrollment_audit(
        &self,
        target: &ManualStoreTarget<'_>,
        context: &CommandContext,
        expected_agreement: &StoredRecord,
        lease: ManualEnrollmentLease<'_>,
    ) -> Result<ManualAuditAppendReceipt> {
        lease.check_current().map_err(denied)?;
        let evidence = lease.evidence();
        evidence.validate().map_err(denied)?;
        let terms = &lease.binding().terms;
        let admission = retained_enrollment_admission(&evidence.admission);
        require_target(self, target, terms)?;
        require_writer(&evidence.current, terms)?;
        let identity = request_identity(
            context,
            &terms.scope.principal_id,
            &serde_json::to_value(lease.binding())?,
        )?;
        let provider = lease.provider_enrollment_reference();
        hash(provider)?;
        let mut c = self.connection.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => StoreError::ResourceExhausted,
            std::sync::TryLockError::Poisoned(_) => StoreError::Poisoned,
        })?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_unused_generic_context(&tx, context)?;
        kernel::require_agreement_snapshot(&tx, expected_agreement, terms)?;
        let old = read_audits::<ManualEnrollmentAudit>(&tx, ENROLLMENT)?;
        let audit = if let Some((_, old)) = old
            .iter()
            .find(|(_, a)| a.terms.operation_id == terms.operation_id)
        {
            // Fresh current checks never replace the original durable audit.
            if old.terms != *terms
                || old.admission != admission
                || old.enrollment_ref != evidence.enrollment_ref
                || old.witness_extension_digest != evidence.witness_extension_digest
                || old.witness_extension_sequence != evidence.witness_extension_sequence
                || old.witness_extension_predecessor_digest
                    != evidence.witness_extension_predecessor_digest
                || old.request_identity_digest != identity
                || old.original_provider_enrollment_ref != provider
                || old.aliases != BTreeSet::from([terms.identity.account_id.clone()])
            {
                return Err(StoreError::IdempotencyConflict);
            }
            old.clone()
        } else {
            let sequence = old
                .iter()
                .filter(|(_, a)| a.terms.host.generation_id == terms.host.generation_id)
                .count() as u64
                + 1;
            ManualEnrollmentAudit {
                version: 1,
                terms: terms.clone(),
                admission,
                enrollment_ref: evidence.enrollment_ref.clone(),
                witness_extension_digest: evidence.witness_extension_digest.clone(),
                witness_extension_sequence: evidence.witness_extension_sequence,
                witness_extension_predecessor_digest: evidence
                    .witness_extension_predecessor_digest
                    .clone(),
                aliases: BTreeSet::from([terms.identity.account_id.clone()]),
                store_sequence: sequence,
                request_identity_digest: identity,
                original_provider_enrollment_ref: provider.into(),
                original_complete_history_digest: evidence.current.complete_history_digest.clone(),
                original_exclusion_checkpoint_digest: evidence
                    .current
                    .exclusion_checkpoint_digest
                    .clone(),
                original_native_review_digest: evidence.current.native_review_digest.clone(),
            }
        };
        let known = store_known_inherited(&tx)?;
        let inserted = kernel::append_enrollment(self, &tx, &audit, &known)?;
        // Fixed concrete same-channel current check, bounded by the bridge's
        // two-second maximum; no arbitrary callback or indefinitely held peer.
        lease.check_current().map_err(denied)?;
        tx.commit()?;
        let receipt = ManualAuditAppendReceipt {
            audit_digest: audit.digest()?,
            operation_id: terms.operation_id.clone(),
            enrollment_ref: audit.enrollment_ref,
            replayed: !inserted,
        };
        drop(c);
        // The original audit is already durable. Keep this exact authenticated
        // stream open through Finished, outside the Store lock. A failed or
        // late check/ack is recovery-required, never rollback or a new attempt.
        lease.check_current().map_err(denied)?;
        lease.finish().map_err(denied)?;
        Ok(receipt)
    }

    /// Retain original exact durable action admission. This does not execute the
    /// action, reserve or release inputs, discount exposure, or grant financial
    /// permission. The signer+witness durable admission is its serialization
    /// point. Timeout/disconnect preserves their uncertain original outcome; a
    /// retry cannot renew the admitted time, deadline or either commitment.
    pub fn append_manual_action_audit(
        &self,
        target: &ManualStoreTarget<'_>,
        context: &CommandContext,
        expected_agreement: &StoredRecord,
        lease: ManualActionLease<'_>,
    ) -> Result<ManualAuditAppendReceipt> {
        lease.check_current().map_err(denied)?;
        let evidence = lease.evidence();
        evidence.validate().map_err(denied)?;
        let request = lease.binding();
        require_target(self, target, &request.enrollment)?;
        require_writer(&evidence.current, &request.enrollment)?;
        let identity = request_identity(
            context,
            &request.enrollment.scope.principal_id,
            &serde_json::to_value(request)?,
        )?;
        if identity != request.intent.idempotency_key_digest {
            return Err(StoreError::IdempotencyConflict);
        }
        let provider = lease.provider_enrollment_reference();
        hash(provider)?;
        let admission = retained_admission(&evidence.admission);
        let mut c = self.connection.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => StoreError::ResourceExhausted,
            std::sync::TryLockError::Poisoned(_) => StoreError::Poisoned,
        })?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_unused_generic_context(&tx, context)?;
        kernel::require_agreement_snapshot(&tx, expected_agreement, &request.enrollment)?;
        let enrollments = read_audits::<ManualEnrollmentAudit>(&tx, ENROLLMENT)?;
        let (enrollment_digest, enrollment) = enrollments
            .iter()
            .find(|(_, a)| a.enrollment_ref == request.enrollment_ref)
            .ok_or(StoreError::RecoveryRequired)?;
        if enrollment.terms != request.enrollment
            || enrollment.witness_extension_digest != request.witness_extension_digest
            || enrollment.original_provider_enrollment_ref != provider
        {
            return Err(StoreError::RecoveryRequired);
        }
        let old = read_audits::<ManualActionAudit>(&tx, SCOPE)?;
        let audit = if let Some((_, old)) = old
            .iter()
            .find(|(_, a)| a.intent.operation_id == request.intent.operation_id)
        {
            if old.enrollment_audit_digest != *enrollment_digest
                || old.witness_extension_digest != request.witness_extension_digest
                || old.intent != request.intent
                || old.admission != admission
                || old.provider_enrollment_ref != provider
            {
                return Err(StoreError::IdempotencyConflict);
            }
            old.clone()
        } else {
            ManualActionAudit {
                version: 1,
                enrollment_audit_digest: enrollment_digest.clone(),
                witness_extension_digest: request.witness_extension_digest.clone(),
                intent: request.intent.clone(),
                admission,
                provider_enrollment_ref: provider.into(),
                complete_history_digest: evidence.current.complete_history_digest.clone(),
                exclusion_checkpoint_digest: evidence.current.exclusion_checkpoint_digest.clone(),
                native_review_digest: evidence.current.native_review_digest.clone(),
            }
        };
        // Exact original expiration is checked by the concrete lease; this audit
        // write cannot reacquire, extend or replace the durable remote admission.
        crate::recovery::project_manual_snapshot(
            &tx,
            self.recovered_binding
                .as_ref()
                .ok_or(StoreError::RecoveryRequired)?,
        )?;
        let inserted = kernel::append_action(self, &tx, &audit)?;
        lease.check_current().map_err(denied)?;
        tx.commit()?;
        Ok(ManualAuditAppendReceipt {
            audit_digest: audit.digest()?,
            operation_id: request.intent.operation_id.clone(),
            enrollment_ref: request.enrollment_ref.clone(),
            replayed: !inserted,
        })
    }
}

impl Store {
    /// Privacy-preserving early rejection before the Host pairs or sends a
    /// private continuation request. This read grants no enrollment authority.
    pub fn require_manual_enrollment_continuation_original(
        &self,
        target: &ManualStoreTarget<'_>,
        expected_agreement: &StoredRecord,
        terms: &BornManualEnrollmentTerms,
        enrollment_ref: &str,
        witness_extension_digest: &str,
    ) -> Result<()> {
        require_target(self, target, terms)?;
        let mut c = self.connection.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => StoreError::ResourceExhausted,
            std::sync::TryLockError::Poisoned(_) => StoreError::Poisoned,
        })?;
        // One coherent read snapshot. No rows are created or changed.
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        kernel::require_agreement_snapshot(&tx, expected_agreement, terms)?;
        kernel::require_continuation_original(
            self,
            &tx,
            terms,
            enrollment_ref,
            witness_extension_digest,
        )?;
        tx.commit()?;
        drop(c);
        target.check_current()
    }

    /// Consume the actual same-peer V2 lease and retain one exact continuation
    /// audit. Missing first enrollment is explicitly unsupported. The real Host
    /// owner must also hold its fresh native/profile/registry conjunction.
    pub fn append_manual_enrollment_continuation_audit(
        &self,
        target: &ManualStoreTarget<'_>,
        context: &CommandContext,
        expected_agreement: &StoredRecord,
        lease: wholepact_signer_origin::ManualEnrollmentContinuationLeaseV2<'_>,
    ) -> Result<ManualAuditAppendReceipt> {
        lease.check_current().map_err(denied)?;
        lease.evidence().validate().map_err(denied)?;
        let terms = &lease.binding().enrollment.terms;
        require_target(self, target, terms)?;
        require_writer(&lease.evidence().current, terms)?;
        let identity = request_identity(
            context,
            &terms.scope.principal_id,
            &serde_json::to_value(lease.binding())?,
        )?;
        let operation = crate::operation_id(context);
        let provider = lease.provider_enrollment_reference();
        hash(provider)?;
        // Strict data-only mirror: this conversion cannot manufacture a lease.
        let evidence: ManualContinuationEvidenceV2 =
            strict(&serde_json::to_value(lease.evidence())?)?;
        evidence.validate()?;
        let mut c = self.connection.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => StoreError::ResourceExhausted,
            std::sync::TryLockError::Poisoned(_) => StoreError::Poisoned,
        })?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_unused_generic_context(&tx, context)?;
        kernel::require_agreement_snapshot(&tx, expected_agreement, terms)?;
        let original = kernel::require_continuation_original(
            self,
            &tx,
            terms,
            &evidence.enrollment_ref,
            &evidence.witness_extension_digest,
        )?;
        if original.original_provider_enrollment_ref != provider {
            return Err(StoreError::RecoveryRequired);
        }
        let retained = read_audits::<ManualEnrollmentContinuationAudit>(&tx, CONTINUATION)?;
        let original_digest = original.digest()?;
        let audit = if let Some((_, old)) = retained.iter().find(|(_, a)| {
            a.operation_id == operation
                || a.evidence.admission.attempt_digest == evidence.admission.attempt_digest
        }) {
            evidence.require_exact_retry(&old.evidence)?;
            if old.operation_id != operation
                || old.request_identity_digest != identity
                || old.enrollment_audit_digest != original_digest
                || old.provider_enrollment_ref != provider
                || old.aliases != original.aliases
            {
                return Err(StoreError::IdempotencyConflict);
            }
            old.clone()
        } else {
            let previous = retained
                .iter()
                .filter(|(_, a)| a.enrollment_audit_digest == original_digest)
                .max_by_key(|(_, a)| a.store_sequence);
            ManualEnrollmentContinuationAudit {
                version: 2,
                enrollment_audit_digest: original_digest,
                operation_id: operation.clone(),
                request_identity_digest: identity,
                provider_enrollment_ref: provider.into(),
                store_sequence: previous.map_or(1, |(_, a)| a.store_sequence + 1),
                predecessor_digest: previous.map(|(id, _)| id.clone()),
                aliases: original.aliases.clone(),
                evidence,
            }
        };
        let inserted = kernel::append_continuation(self, &tx, &audit)?;
        lease.check_current().map_err(denied)?;
        tx.commit()?;
        drop(c);
        // A failure here is conservative uncertainty after durable audit only;
        // exact retry recovers the original bytes, never another admission.
        lease.check_current().map_err(denied)?;
        Ok(ManualAuditAppendReceipt {
            audit_digest: audit.digest()?,
            operation_id: operation,
            enrollment_ref: audit.evidence.enrollment_ref,
            replayed: !inserted,
        })
    }
}

impl Store {
    /// Explicit early route selection. A V1 original cannot enter this route.
    /// Missing original Host publication is valid only under the unchanged empty
    /// original scope and complete known inherited restrictions.
    pub fn require_manual_enrollment_initial_publication_v2(
        &self,
        target: &ManualStoreTarget<'_>,
        expected_agreement: &StoredRecord,
        terms: &BornManualEnrollmentTerms,
        enrollment_ref: &str,
        witness_extension_digest: &str,
    ) -> Result<()> {
        require_target(self, target, terms)?;
        let mut c = self.connection.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => StoreError::ResourceExhausted,
            std::sync::TryLockError::Poisoned(_) => StoreError::Poisoned,
        })?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        kernel::require_agreement_snapshot(&tx, expected_agreement, terms)?;
        kernel::require_initial_publication_target(
            self,
            &tx,
            terms,
            enrollment_ref,
            witness_extension_digest,
            &store_known_inherited(&tx)?,
        )?;
        tx.commit()?;
        drop(c);
        target.check_current()
    }

    /// Actual lower V2 lease consumer. The native Host operation owner remains
    /// required at the Host seam; this Store receipt grants no financial action.
    pub fn append_manual_enrollment_initial_publication_v2(
        &self,
        target: &ManualStoreTarget<'_>,
        context: &CommandContext,
        expected_agreement: &StoredRecord,
        lease: wholepact_signer_origin::ManualEnrollmentContinuationLeaseV2<'_>,
    ) -> Result<ManualAuditAppendReceipt> {
        lease.check_current().map_err(denied)?;
        lease.evidence().validate().map_err(denied)?;
        let terms = &lease.binding().enrollment.terms;
        require_target(self, target, terms)?;
        require_writer(&lease.evidence().current, terms)?;
        let identity = request_identity(
            context,
            &terms.scope.principal_id,
            &serde_json::to_value(lease.binding())?,
        )?;
        let operation = crate::operation_id(context);
        let provider = lease.provider_enrollment_reference();
        hash(provider)?;
        let evidence: ManualContinuationEvidenceV2 =
            strict(&serde_json::to_value(lease.evidence())?)?;
        let mut audit = ManualEnrollmentInitialPublicationV2 {
            version: 2,
            operation_id: operation.clone(),
            request_identity_digest: identity,
            provider_enrollment_ref: provider.into(),
            store_sequence: 1,
            aliases: BTreeSet::from([terms.identity.account_id.clone()]),
            evidence,
        };
        audit.validate()?;
        let mut c = self.connection.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => StoreError::ResourceExhausted,
            std::sync::TryLockError::Poisoned(_) => StoreError::Poisoned,
        })?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_unused_generic_context(&tx, context)?;
        kernel::require_agreement_snapshot(&tx, expected_agreement, terms)?;
        let known = store_known_inherited(&tx)?;
        if let Some(original) = kernel::require_initial_publication_target(
            self,
            &tx,
            terms,
            &audit.evidence.enrollment_ref,
            &audit.evidence.witness_extension_digest,
            &known,
        )? {
            audit.require_exact_retry(&original)?;
            // Never replace the first retained current observations on retry.
            audit = original;
        }
        let inserted = kernel::append_initial_publication_v2(self, &tx, &audit, &known)?;
        lease.check_current().map_err(denied)?;
        tx.commit()?;
        drop(c);
        lease.check_current().map_err(denied)?;
        Ok(ManualAuditAppendReceipt {
            audit_digest: audit.digest()?,
            operation_id: operation,
            enrollment_ref: audit.evidence.enrollment_ref,
            replayed: !inserted,
        })
    }

    pub fn require_manual_enrollment_continuation_original_v2(
        &self,
        target: &ManualStoreTarget<'_>,
        expected_agreement: &StoredRecord,
        terms: &BornManualEnrollmentTerms,
        enrollment_ref: &str,
        witness_extension_digest: &str,
    ) -> Result<()> {
        require_target(self, target, terms)?;
        let mut c = self.connection.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => StoreError::ResourceExhausted,
            std::sync::TryLockError::Poisoned(_) => StoreError::Poisoned,
        })?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        kernel::require_agreement_snapshot(&tx, expected_agreement, terms)?;
        kernel::require_continuation_original_v2(
            self,
            &tx,
            terms,
            enrollment_ref,
            witness_extension_digest,
            &store_known_inherited(&tx)?,
        )?;
        tx.commit()?;
        drop(c);
        target.check_current()
    }

    /// A separate tagged V3 historical audit linked to a real V2 first Host
    /// publication, consuming the same genuine successor-attempt lease format.
    pub fn append_manual_enrollment_continuation_audit_v3(
        &self,
        target: &ManualStoreTarget<'_>,
        context: &CommandContext,
        expected_agreement: &StoredRecord,
        lease: wholepact_signer_origin::ManualEnrollmentContinuationLeaseV2<'_>,
    ) -> Result<ManualAuditAppendReceipt> {
        lease.check_current().map_err(denied)?;
        lease.evidence().validate().map_err(denied)?;
        let terms = &lease.binding().enrollment.terms;
        require_target(self, target, terms)?;
        require_writer(&lease.evidence().current, terms)?;
        let identity = request_identity(
            context,
            &terms.scope.principal_id,
            &serde_json::to_value(lease.binding())?,
        )?;
        let operation = crate::operation_id(context);
        let provider = lease.provider_enrollment_reference();
        hash(provider)?;
        let evidence: ManualContinuationEvidenceV2 =
            strict(&serde_json::to_value(lease.evidence())?)?;
        evidence.validate()?;
        let mut c = self.connection.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => StoreError::ResourceExhausted,
            std::sync::TryLockError::Poisoned(_) => StoreError::Poisoned,
        })?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_unused_generic_context(&tx, context)?;
        kernel::require_agreement_snapshot(&tx, expected_agreement, terms)?;
        let known = store_known_inherited(&tx)?;
        let original = kernel::require_continuation_original_v2(
            self,
            &tx,
            terms,
            &evidence.enrollment_ref,
            &evidence.witness_extension_digest,
            &known,
        )?;
        if original.provider_enrollment_ref != provider {
            return Err(StoreError::RecoveryRequired);
        }
        let link = OriginalManualEnrollmentAuditLink::InitialPublicationV2 {
            audit_digest: original.digest()?,
        };
        let retained = read_audits::<ManualEnrollmentContinuationAuditV3>(&tx, CONTINUATION_V3)?;
        let audit = if let Some((_, old)) = retained.iter().find(|(_, a)| {
            a.operation_id == operation
                || a.evidence.admission.attempt_digest == evidence.admission.attempt_digest
        }) {
            evidence.require_exact_retry(&old.evidence)?;
            if old.operation_id != operation
                || old.request_identity_digest != identity
                || old.original_audit != link
                || old.provider_enrollment_ref != provider
                || old.aliases != original.aliases
            {
                return Err(StoreError::IdempotencyConflict);
            }
            old.clone()
        } else {
            let previous = retained
                .iter()
                .filter(|(_, a)| a.original_audit == link)
                .max_by_key(|(_, a)| a.store_sequence);
            ManualEnrollmentContinuationAuditV3 {
                version: 3,
                original_audit: link,
                operation_id: operation.clone(),
                request_identity_digest: identity,
                provider_enrollment_ref: provider.into(),
                store_sequence: previous.map_or(1, |(_, a)| a.store_sequence + 1),
                predecessor_digest: previous.map(|(id, _)| id.clone()),
                aliases: original.aliases.clone(),
                evidence,
            }
        };
        let inserted = kernel::append_continuation_v3(self, &tx, &audit, &known)?;
        lease.check_current().map_err(denied)?;
        tx.commit()?;
        drop(c);
        lease.check_current().map_err(denied)?;
        Ok(ManualAuditAppendReceipt {
            audit_digest: audit.digest()?,
            operation_id: operation,
            enrollment_ref: audit.evidence.enrollment_ref,
            replayed: !inserted,
        })
    }
}

impl Store {
    /// Read-only route selection from actual immutable rows. This tagged result
    /// is correlation only; every concrete appender rechecks the original under
    /// its own IMMEDIATE transaction and consumes the genuine current lease.
    /// None is an eligible still-empty original scope, never permission to turn
    /// an existing-audit continuation command into initial publication.
    pub fn manual_enrollment_original_audit_link(
        &self,
        target: &ManualStoreTarget<'_>,
        expected_agreement: &StoredRecord,
        terms: &BornManualEnrollmentTerms,
        enrollment_ref: &str,
        witness_extension_digest: &str,
    ) -> Result<Option<OriginalManualEnrollmentAuditLink>> {
        require_target(self, target, terms)?;
        let mut c = self.connection.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => StoreError::ResourceExhausted,
            std::sync::TryLockError::Poisoned(_) => StoreError::Poisoned,
        })?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        kernel::require_agreement_snapshot(&tx, expected_agreement, terms)?;
        let projection = crate::recovery::project_manual_snapshot(
            &tx,
            self.recovered_binding
                .as_ref()
                .ok_or(StoreError::RecoveryRequired)?,
        )?;
        let all = projection.enrollments();
        let original = all.iter().find(|a| a.enrollment_ref() == enrollment_ref);
        let link = match original {
            Some(ManualEnrollmentProjection::EnrollmentV1(_)) => {
                let original = kernel::require_continuation_original(
                    self,
                    &tx,
                    terms,
                    enrollment_ref,
                    witness_extension_digest,
                )?;
                Some(OriginalManualEnrollmentAuditLink::EnrollmentV1 {
                    audit_digest: original.digest()?,
                })
            }
            Some(ManualEnrollmentProjection::InitialPublicationV2(_)) => {
                let original = kernel::require_continuation_original_v2(
                    self,
                    &tx,
                    terms,
                    enrollment_ref,
                    witness_extension_digest,
                    &store_known_inherited(&tx)?,
                )?;
                Some(OriginalManualEnrollmentAuditLink::InitialPublicationV2 {
                    audit_digest: original.digest()?,
                })
            }
            Some(ManualEnrollmentProjection::AdditionalPublicationV3(_)) => {
                let original = kernel::require_continuation_original_v3(
                    self,
                    &tx,
                    terms,
                    enrollment_ref,
                    witness_extension_digest,
                    &store_known_inherited(&tx)?,
                )?;
                Some(OriginalManualEnrollmentAuditLink::AdditionalPublicationV3 {
                    audit_digest: original.digest()?,
                })
            }
            None => {
                if kernel::require_initial_publication_target(
                    self,
                    &tx,
                    terms,
                    enrollment_ref,
                    witness_extension_digest,
                    &store_known_inherited(&tx)?,
                )?
                .is_some()
                {
                    return Err(StoreError::RecoveryRequired);
                }
                None
            }
        };
        tx.commit()?;
        drop(c);
        target.check_current()?;
        Ok(link)
    }
}

#[path = "selection_read.rs"]
mod selection_read;

pub use selection_read::ManualCandidateLocalExclusions;

#[path = "selection_read_roster_v2.rs"]
mod selection_read_roster_v2;
pub use selection_read_roster_v2::ManualRosterCandidateLocalExclusionsV2;

#[path = "roster_head.rs"]
mod roster_head;
pub use roster_head::{ManualEnrollmentRosterHead, ManualEnrollmentRosterMember, OriginalManualRosterReadV3};

#[path = "roster_admission.rs"]
mod roster_admission;

#[path = "construction_claim_v2_runtime.rs"]
mod construction_claim_v2_runtime;
pub use construction_claim_v2_runtime::{
    ManualRosterConstructionClaimOutcomeV2, ManualRosterConstructionClaimTokenV2,
};

#[path = "construction_claim_v3_runtime.rs"]
mod construction_claim_v3_runtime;
pub use construction_claim_v3_runtime::{
    ManualRosterConstructionClaimOutcomeV3, ManualRosterConstructionClaimTokenV3,
};

#[path = "permanent_stop.rs"]
mod permanent_stop;
pub use permanent_stop::ManualPermanentStopReceiptV1;
