//! Concrete same-peer roster admission consumers. The native Host owner is
//! separately required. Audit receipts cannot authorize selection or finance.
use super::*;

impl Store {
    pub fn append_manual_enrollment_additional_publication_v3(
        &self,
        target: &ManualStoreTarget<'_>,
        context: &CommandContext,
        expected_agreement: &StoredRecord,
        lease: wholepact_signer_origin::ManualRosterEnrollmentLeaseV2<'_>,
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
        let evidence: ManualRosterEnrollmentEvidenceV2 =
            strict(&serde_json::to_value(lease.evidence())?)?;
        let mut audit = ManualEnrollmentAdditionalPublicationV3 {
            version: 3,
            operation_id: operation.clone(),
            request_identity_digest: identity,
            provider_enrollment_ref: provider.into(),
            store_sequence: lease.binding().roster.roster_sequence,
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
        if let Some(original) = kernel::require_additional_publication_target(
            self,
            &tx,
            terms,
            &lease.binding().roster,
            &audit.evidence.enrollment_ref,
            &audit.evidence.witness_extension_digest,
            &known,
        )? {
            audit.require_exact_retry(&original)?;
            // Never replace the first retained current observations on retry.
            audit = original;
        }
        let inserted = kernel::append_additional_publication_v3(self, &tx, &audit, &known)?;
        lease.check_current().map_err(denied)?;
        tx.commit()?;
        drop(c);
        // The audit is already durable. A failed current check or Finished ack
        // is recovery-required, never rollback and never permission to re-pair.
        lease
            .check_current()
            .map_err(|_| StoreError::RecoveryRequired)?;
        lease.finish().map_err(|_| StoreError::RecoveryRequired)?;
        Ok(ManualAuditAppendReceipt {
            audit_digest: audit.digest()?,
            operation_id: operation,
            enrollment_ref: audit.evidence.enrollment_ref,
            replayed: !inserted,
        })
    }

    pub fn require_manual_enrollment_continuation_original_v3(
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
        kernel::require_continuation_original_v3(
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

    pub fn append_manual_enrollment_continuation_audit_v4(
        &self,
        target: &ManualStoreTarget<'_>,
        context: &CommandContext,
        expected_agreement: &StoredRecord,
        lease: wholepact_signer_origin::ManualRosterEnrollmentLeaseV2<'_>,
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
        let evidence: ManualRosterEnrollmentEvidenceV2 =
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
        let original = kernel::require_continuation_original_v3(
            self,
            &tx,
            terms,
            &evidence.enrollment_ref,
            &evidence.witness_extension_digest,
            &known,
        )?;
        original.require_immutable_publication_identity(
            &evidence.request,
            &evidence.enrollment_ref,
            &evidence.witness_extension_digest,
            &evidence.witness_roster_extension_digest,
            &evidence.signer_roster_record_digest,
        )?;
        if original.provider_enrollment_ref != provider {
            return Err(StoreError::RecoveryRequired);
        }
        let link = OriginalManualEnrollmentAuditLink::AdditionalPublicationV3 {
            audit_digest: original.digest()?,
        };
        let retained = read_audits::<ManualEnrollmentContinuationAuditV4>(&tx, CONTINUATION_V4)?;
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
            ManualEnrollmentContinuationAuditV4 {
                version: 4,
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
        let inserted = kernel::append_continuation_v4(self, &tx, &audit, &known)?;
        lease.check_current().map_err(denied)?;
        tx.commit()?;
        drop(c);
        // The audit is already durable. A failed current check or Finished ack
        // is recovery-required, never rollback and never permission to re-pair.
        lease
            .check_current()
            .map_err(|_| StoreError::RecoveryRequired)?;
        lease.finish().map_err(|_| StoreError::RecoveryRequired)?;
        Ok(ManualAuditAppendReceipt {
            audit_digest: audit.digest()?,
            operation_id: operation,
            enrollment_ref: audit.evidence.enrollment_ref,
            replayed: !inserted,
        })
    }
}
impl Store {
    /// Read-only exact route/CAS evidence. None means this new V3 original has
    /// not been appended; it does not grant authority or bypass native approval.
    pub fn manual_enrollment_roster_original_audit_link(
        &self,
        target: &ManualStoreTarget<'_>,
        expected_agreement: &StoredRecord,
        terms: &BornManualEnrollmentTerms,
        roster: &wholepact_core::manual_roster_v2::HostRosterAppendBindingV2,
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
        let original = kernel::require_additional_publication_target(
            self,
            &tx,
            terms,
            roster,
            enrollment_ref,
            witness_extension_digest,
            &store_known_inherited(&tx)?,
        )?;
        let link = original
            .map(|a| {
                a.digest().map(|audit_digest| {
                    OriginalManualEnrollmentAuditLink::AdditionalPublicationV3 { audit_digest }
                })
            })
            .transpose()?;
        tx.commit()?;
        drop(c);
        target.check_current()?;
        Ok(link)
    }
}

impl Store {
    /// Early read-only comparison of ALL immutable exported wrapper identities.
    /// A retained audit is historical metadata, not native or witness authority.
    /// The current attempt may differ for a continuation. The initial-publication
    /// retry route must additionally call require_exact_publication_request.
    #[allow(clippy::too_many_arguments)]
    pub fn manual_enrollment_roster_request_original(
        &self,
        target: &ManualStoreTarget<'_>,
        expected_agreement: &StoredRecord,
        request: &wholepact_signer_origin::manual_roster_v2::HostManualRosterPublicationRequestV2,
        enrollment_ref: &str,
        witness_extension_digest: &str,
        witness_roster_extension_digest: &str,
        signer_roster_record_digest: &str,
    ) -> Result<Option<ManualEnrollmentAdditionalPublicationV3>> {
        request.validate().map_err(denied)?;
        hash(witness_roster_extension_digest)?;
        hash(signer_roster_record_digest)?;
        let projected_request: ManualRosterPublicationRequestV2 =
            strict(&serde_json::to_value(request)?)?;
        let terms = &request.enrollment.terms;
        require_target(self, target, terms)?;
        let mut c = self.connection.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => StoreError::ResourceExhausted,
            std::sync::TryLockError::Poisoned(_) => StoreError::Poisoned,
        })?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        kernel::require_agreement_snapshot(&tx, expected_agreement, terms)?;
        let original = kernel::require_additional_publication_target(
            self,
            &tx,
            terms,
            &request.roster,
            enrollment_ref,
            witness_extension_digest,
            &store_known_inherited(&tx)?,
        )?;
        if let Some(old) = &original {
            old.require_immutable_publication_identity(
                &projected_request,
                enrollment_ref,
                witness_extension_digest,
                witness_roster_extension_digest,
                signer_roster_record_digest,
            )?;
        }
        tx.commit()?;
        drop(c);
        target.check_current()?;
        Ok(original)
    }
}
