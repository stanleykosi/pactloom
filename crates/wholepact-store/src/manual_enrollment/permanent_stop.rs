//! Dedicated concrete restriction consumer. Only a live installed-origin stop
//! lease reaches mutation; public historical records cannot recreate that lease.
use super::*;
use wholepact_signer_origin::manual_roster_v2::HostManualRosterEnrollmentRequestV2;
use wholepact_signer_origin::{
    PermanentStopLeaseV1,
    permanent_stop_v1::{HostPermanentStopAcknowledgmentV1, HostPermanentStopRequestV1},
};

/// Confirmation of durable restriction bytes and the exact peer acknowledgment.
/// This is not account emptiness, reclaimed funds, settlement, or authority.
pub struct ManualPermanentStopReceiptV1 {
    publication: ManualPermanentStopPublicationV1,
    replayed: bool,
}
impl ManualPermanentStopReceiptV1 {
    pub fn publication(&self) -> &ManualPermanentStopPublicationV1 {
        &self.publication
    }
    pub fn replayed(&self) -> bool {
        self.replayed
    }
}
fn lock_error(error: std::sync::TryLockError<std::sync::MutexGuard<'_, Connection>>) -> StoreError {
    match error {
        std::sync::TryLockError::WouldBlock => StoreError::ResourceExhausted,
        std::sync::TryLockError::Poisoned(_) => StoreError::Poisoned,
    }
}
fn request(
    original: &ManualEnrollmentAdditionalPublicationV3,
) -> Result<HostPermanentStopRequestV1> {
    original.validate()?;
    let value = HostPermanentStopRequestV1 {
        version: 1,
        original: HostManualRosterEnrollmentRequestV2 {
            version: 2,
            enrollment: serde_json::from_value(serde_json::to_value(
                &original.evidence.request.enrollment,
            )?)?,
            roster: original.evidence.request.roster.clone(),
        },
        original_host_audit_digest: original.digest()?,
        provider_enrollment_ref: original.provider_enrollment_ref.clone(),
    };
    value.validate().map_err(denied)?;
    if value.digest().map_err(denied)?
        != permanent_stop_record::request_digest_for_original(original)?
    {
        return Err(StoreError::RecoveryRequired);
    }
    Ok(value)
}
fn original_from_store(
    store: &Store,
    c: &Connection,
    target: &ManualStoreTarget<'_>,
    agreement: &StoredRecord,
    account_id: &str,
) -> Result<ManualEnrollmentAdditionalPublicationV3> {
    hash(account_id)?;
    if !std::ptr::eq(store, target.store) {
        return Err(StoreError::RecoveryRequired);
    }
    let binding = store
        .recovered_binding
        .as_ref()
        .ok_or(StoreError::RecoveryRequired)?;
    if !store.recovered_generation
        || store.protection != StorageProtection::Encrypted
        || !crate::backup::read_recovery_state(c)?.recovery_required
        || binding.generation_id() != target.generation_id
        || binding.inventory_digest() != target.inventory_digest
        || store.current_recovered_settlement_identity(c)? != target.store_destination_identity
    {
        return Err(StoreError::RecoveryRequired);
    }
    let projection = crate::recovery::project_manual_snapshot(c, binding)?;
    let mut rows = projection
        .additional_publications_v3()
        .iter()
        .filter(|row| {
            row.terms().identity.account_id == account_id
                && row.terms().host.generation_id == target.generation_id
                && row.terms().scope.agreement_id == agreement.id
        });
    let original = rows.next().ok_or(StoreError::NotFound)?.clone();
    if rows.next().is_some()
        || original.terms().host.inventory_digest != target.inventory_digest
        || original.terms().host.store_destination_identity != target.store_destination_identity
    {
        return Err(StoreError::RecoveryRequired);
    }
    kernel::require_agreement_snapshot(c, agreement, original.terms())?;
    // Current-generation restriction only; no ancestor or generic alias import.
    for (kind, value) in [
        (
            "record",
            format!("{ADDITIONAL_PUBLICATION_V3}:{}", original.digest()?),
        ),
        ("record", format!("agreement:{}", agreement.id)),
        ("agreement", agreement.id.clone()),
        ("idempotency", original.request_identity_digest.clone()),
    ] {
        if store.generation_fenced(c, kind, &value)? {
            return Err(StoreError::RecoveryRequired);
        }
    }
    Ok(original)
}
impl Store {
    /// Read an exact retained V3 original, including all aliases. The identifiers
    /// select a row; the opened Store and current agreement own every returned field.
    pub fn manual_permanent_stop_original_v1(
        &self,
        target: &ManualStoreTarget<'_>,
        expected_agreement: &StoredRecord,
        account_id: &str,
    ) -> Result<ManualEnrollmentAdditionalPublicationV3> {
        target.check_current_fail_fast()?;
        let mut c = self.connection.try_lock().map_err(lock_error)?;
        let result = ManualPersistenceMode::FailFast.with_connection(&mut c, |c| {
            let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
            let original = original_from_store(self, &tx, target, expected_agreement, account_id)?;
            tx.commit()?;
            Ok(original)
        })?;
        drop(c);
        target.check_current_fail_fast()?;
        Ok(result)
    }
    /// One atomic append of the existing exclusion and exact original publication.
    /// Durable bytes precede the acknowledgment. Post-commit failure remains an
    /// uncertain acknowledgment and never removes or rewrites the restriction.
    pub fn append_manual_permanent_stop_v1(
        &self,
        target: &ManualStoreTarget<'_>,
        expected_agreement: &StoredRecord,
        lease: PermanentStopLeaseV1<'_>,
    ) -> Result<ManualPermanentStopReceiptV1> {
        lease.check_current().map_err(denied)?;
        let evidence = lease.evidence();
        evidence.validate().map_err(denied)?;
        let terms = &evidence.request.original.enrollment.terms;
        require_target_with_mode(self, target, terms, ManualPersistenceMode::FailFast)?;
        if lease.provider_enrollment_reference() != evidence.request.provider_enrollment_ref {
            return Err(StoreError::RecoveryRequired);
        }
        let mut c = self.connection.try_lock().map_err(lock_error)?;
        let (publication, replayed) =
            ManualPersistenceMode::FailFast.with_connection(&mut c, |c| {
                let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let original = original_from_store(
                    self,
                    &tx,
                    target,
                    expected_agreement,
                    &terms.identity.account_id,
                )?;
                if evidence.request != request(&original)? {
                    return Err(StoreError::RecoveryRequired);
                }
                let proposed = ManualPermanentStopPublicationV1 {
                    version: 1,
                    original_host_audit_digest: original.digest()?,
                    provider_enrollment_ref: original.provider_enrollment_ref.clone(),
                    request_digest: evidence.request.digest().map_err(denied)?,
                    exclusion: ManualExclusionAudit {
                        version: 1,
                        operation_id: evidence.exclusion_operation_id.clone(),
                        identity: original.terms().identity.clone(),
                        aliases: original.aliases.clone(),
                        account_use_genesis_digest: original
                            .terms()
                            .account_use_genesis_digest
                            .clone(),
                        exclusion_digest: evidence.exclusion_digest.clone(),
                        witness_history_digest: evidence.complete_witness_history_digest.clone(),
                    },
                    original_witness_receipt_digest: evidence
                        .original_witness_receipt_digest
                        .clone(),
                    original_witness_head_sequence: evidence.original_witness_head_sequence,
                    original_witness_head_digest: evidence.original_witness_head_digest.clone(),
                    original_native_review_digest: evidence.native_review_digest.clone(),
                };
                proposed.require_original(&original)?;
                let rows = read_audits::<ManualPermanentStopPublicationV1>(&tx, PERMANENT_STOP_V1)?;
                let prior = rows.iter().find(|(_, row)| {
                    row.original_host_audit_digest == proposed.original_host_audit_digest
                });
                let (publication, replayed) = if let Some((_, first)) = prior {
                    first.require_same_publication(&proposed)?;
                    (first.clone(), true)
                } else {
                    // An unrelated pre-existing exclusion cannot be promoted into
                    // this dedicated publication or acquire invented receipt provenance.
                    if read_audits::<ManualExclusionAudit>(&tx, EXCLUSION)?
                        .iter()
                        .any(|(_, old)| {
                            overlaps(
                                &old.identity,
                                &old.aliases,
                                &proposed.exclusion.identity,
                                &proposed.exclusion.aliases,
                            )
                        })
                    {
                        return Err(StoreError::RecoveryRequired);
                    }
                    (proposed, false)
                };
                if self.generation_fenced(&tx, "operation", &publication.exclusion.operation_id)? {
                    return Err(StoreError::RecoveryRequired);
                }
                kernel::append_exclusion(&tx, &publication.exclusion)?;
                if !replayed {
                    insert_publication(&tx, &publication)?;
                }
                // Validate the complete resulting set before admission, not merely
                // one record or a client-supplied "complete" flag.
                crate::recovery::project_manual_snapshot(
                    &tx,
                    self.recovered_binding
                        .as_ref()
                        .ok_or(StoreError::RecoveryRequired)?,
                )?;
                lease.check_current().map_err(denied)?;
                tx.commit()?;
                Ok((publication, replayed))
            })?;
        drop(c);
        target.check_current_fail_fast()?;
        lease.check_current().map_err(denied)?;
        let acknowledgment = HostPermanentStopAcknowledgmentV1 {
            version: 1,
            request_digest: publication.request_digest.clone(),
            exclusion_operation_id: publication.exclusion.operation_id.clone(),
            exclusion_digest: publication.exclusion.exclusion_digest.clone(),
            original_witness_receipt_digest: publication.original_witness_receipt_digest.clone(),
            original_host_audit_digest: publication.original_host_audit_digest.clone(),
            restriction_audit_digest: publication.exclusion.digest()?,
            original_host_witness_history_digest: publication
                .exclusion
                .witness_history_digest
                .clone(),
            provider_enrollment_ref: publication.provider_enrollment_ref.clone(),
        };
        acknowledgment
            .require_evidence(lease.evidence())
            .map_err(denied)?;
        lease.acknowledge(acknowledgment).map_err(denied)?;
        Ok(ManualPermanentStopReceiptV1 {
            publication,
            replayed,
        })
    }
}
fn insert_publication(
    tx: &rusqlite::Transaction<'_>,
    publication: &ManualPermanentStopPublicationV1,
) -> Result<()> {
    let payload = crate::encode(&serde_json::to_value(publication)?)?;
    let (count, bytes): (u64, u64) = tx.query_row(
        "SELECT count(*),coalesce(sum(length(CAST(payload AS BLOB))),0) FROM records WHERE aggregate_type GLOB 'generation_manual_*'", [], |row| Ok((row.get(0)?, row.get(1)?)))?;
    if count >= MAX_AUDITS as u64
        || bytes
            .checked_add(payload.len() as u64)
            .is_none_or(|n| n > MAX_AUDIT_BYTES)
    {
        return Err(StoreError::ResourceExhausted);
    }
    tx.execute(
        "INSERT INTO records VALUES(?1,?2,0,?3,?4,?4)",
        params![
            PERMANENT_STOP_V1,
            publication.digest()?,
            payload,
            crate::now_ms()
        ],
    )?;
    Ok(())
}
