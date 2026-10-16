//! Actual V2 Store/request-bound local exclusions. Only a live roster-native
//! lower lease creates this owner; no V1 owner/request adaptation is permitted.
use super::*;
use crate::financial_preflight::RetainedInputExclusions;
use wholepact_core::{
    manual_roster_candidate_selection_v2::ManualRosterCandidateSelectionRequestV2,
    manual_roster_inventory_v2::ManualRosterPreparationProvenanceV2,
};
use wholepact_signer_origin::ManualRosterCandidateSelectionLeaseV2;

pub struct ManualRosterCandidateLocalExclusionsV2<'store> {
    store: &'store Store,
    target: ManualStoreTarget<'store>,
    expected_agreement: StoredRecord,
    request: ManualRosterCandidateSelectionRequestV2,
    provider_enrollment_ref: String,
    exclusions: RetainedInputExclusions,
}
impl ManualRosterCandidateLocalExclusionsV2<'_> {
    pub fn current_for(
        &self,
        store: &Store,
        request: &ManualRosterCandidateSelectionRequestV2,
    ) -> Result<&RetainedInputExclusions> {
        if !std::ptr::eq(store, self.store) || request != &self.request {
            return Err(StoreError::RecoveryRequired);
        }
        let actual = read_local(
            store,
            &self.target,
            &self.expected_agreement,
            request,
            &self.provider_enrollment_ref,
            ContinuationRead::LatestSelection,
            ManualPersistenceMode::Existing,
        )?;
        if actual != self.exclusions {
            return Err(StoreError::RevisionConflict);
        }
        Ok(&self.exclusions)
    }
}
impl ManualRosterCandidateLocalExclusionsV2<'_> {
    /// Current restrictions for an ALREADY retained contribution only. The
    /// concrete snapshot remains Store-bound and the original selection request
    /// must be exact. This neither returns a native gate nor renews selection.
    pub fn current_retained_for(
        &self,
        store: &Store,
        retained: &wholepact_core::manual_roster_construction_v2::ManualRosterContributionRetentionRequestV2,
    ) -> Result<&RetainedInputExclusions> {
        self.current_retained_for_with_mode(store, retained, ManualPersistenceMode::Existing)
    }
    pub fn current_retained_for_fail_fast(
        &self,
        store: &Store,
        retained: &wholepact_core::manual_roster_construction_v2::ManualRosterContributionRetentionRequestV2,
    ) -> Result<&RetainedInputExclusions> {
        self.current_retained_for_with_mode(store, retained, ManualPersistenceMode::FailFast)
    }
    fn current_retained_for_with_mode(
        &self,
        store: &Store,
        retained: &wholepact_core::manual_roster_construction_v2::ManualRosterContributionRetentionRequestV2,
        persistence: ManualPersistenceMode,
    ) -> Result<&RetainedInputExclusions> {
        retained
            .validate()
            .map_err(|_| StoreError::RecoveryRequired)?;
        if !std::ptr::eq(store, self.store)
            || retained.selection != self.request
            || retained.local_exclusion_digest != self.exclusions.snapshot_digest()?
        {
            return Err(StoreError::RecoveryRequired);
        }
        let actual = read_local(
            store,
            &self.target,
            &self.expected_agreement,
            &self.request,
            &self.provider_enrollment_ref,
            ContinuationRead::RetainedHistorical,
            persistence,
        )?;
        // Never subtract newly observed exclusions, including an apparent own
        // reservation. Only a separate exact admitted ledger effect could do
        // that; this first consumer deliberately denies any snapshot change.
        if actual != self.exclusions {
            return Err(StoreError::RevisionConflict);
        }
        Ok(&self.exclusions)
    }
}
impl Store {
    pub fn manual_roster_candidate_local_exclusions_v2<'store>(
        &'store self,
        target: &ManualStoreTarget<'_>,
        expected_agreement: &StoredRecord,
        lease: &ManualRosterCandidateSelectionLeaseV2<'_>,
    ) -> Result<ManualRosterCandidateLocalExclusionsV2<'store>> {
        lease.check_current().map_err(denied)?;
        let request = lease.binding();
        let provider_enrollment_ref = lease.provider_enrollment_reference();
        let exclusions = read_local(
            self,
            target,
            expected_agreement,
            request,
            provider_enrollment_ref,
            ContinuationRead::LatestSelection,
            ManualPersistenceMode::Existing,
        )?;
        let target = self.manual_store_target()?;
        lease.check_current().map_err(denied)?;
        Ok(ManualRosterCandidateLocalExclusionsV2 {
            store: self,
            target,
            expected_agreement: expected_agreement.clone(),
            request: request.clone(),
            provider_enrollment_ref: provider_enrollment_ref.into(),
            exclusions,
        })
    }
}
enum ContinuationRead {
    LatestSelection,
    RetainedHistorical,
}
fn read_local(
    store: &Store,
    target: &ManualStoreTarget<'_>,
    expected_agreement: &StoredRecord,
    request: &ManualRosterCandidateSelectionRequestV2,
    provider_enrollment_ref: &str,
    mode: ContinuationRead,
    persistence: ManualPersistenceMode,
) -> Result<RetainedInputExclusions> {
    request
        .validate()
        .map_err(|_| StoreError::RecoveryRequired)?;
    let inventory = &request.scope.selection.inventory;
    let terms = &inventory.enrollment;
    require_target_with_mode(store, target, terms, persistence)?;
    let mut connection = store.connection.try_lock().map_err(|error| match error {
        std::sync::TryLockError::WouldBlock => StoreError::ResourceExhausted,
        std::sync::TryLockError::Poisoned(_) => StoreError::Poisoned,
    })?;
    let result = persistence.with_connection(&mut connection, |connection| {
    let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    kernel::require_agreement_snapshot(&tx, expected_agreement, terms)?;
    // Resolve the exact original from the actual authenticated Store, even when
    // another roster member has since become the roster tip. Initial V1/V2 rows
    // and unretained additions have no fallback into this continued-only route.
    let original = kernel::require_continuation_original_v3(
        store,
        &tx,
        terms,
        &inventory.enrollment_ref,
        &inventory.witness_extension_digest,
        &store_known_inherited(&tx)?,
    )?;
    let original_digest = original.digest()?;
    require_provenance(
        &request.scope.provenance,
        &ManualRosterPreparationProvenanceV2 {
            version: 2,
            original_host_audit: wholepact_core::manual_roster_inventory_v2::OriginalHostRosterAuditV3::AdditionalPublicationV3 { audit_digest: original_digest.clone() },
            roster: original.evidence.request.roster.clone(),
            signer_roster_record_digest: original.evidence.signer_roster_record_digest.clone(),
            witness_roster_extension_digest: original.evidence.witness_roster_extension_digest.clone(),
        },
        provider_enrollment_ref, &original.provider_enrollment_ref,
    )?;
    let additions =
        read_audits::<ManualEnrollmentAdditionalPublicationV3>(&tx, ADDITIONAL_PUBLICATION_V3)?;
    let continuations = read_audits::<ManualEnrollmentContinuationAuditV4>(&tx, CONTINUATION_V4)?;
    crate::manual_enrollment::additional_publication::validate_chains(&additions, &continuations)?;
    let latest = continuations
        .iter()
        .filter(|(_, a)| a.original_audit.audit_digest() == original_digest)
        .max_by_key(|(_, a)| a.store_sequence)
        .map(|(_, a)| &a.evidence.admission);
    match mode {
        ContinuationRead::LatestSelection => require_current_continuation(
            original.evidence.admission.attempt_sequence,
            latest.map(|a| (a.attempt_sequence, a.attempt_digest.as_str())),
            inventory.attempt.attempt_sequence,
            &inventory.attempt.continuation_digest,
        )?,
        ContinuationRead::RetainedHistorical => {
            // The real snapshot was minted while this was the latest exact V4.
            // A subsequent separately admitted V4 must not erase that fact, but
            // neither can this historical read authorize a new selection or
            // establish that a phase-two attempt is currently admitted.
            let present = continuations.iter().any(|(_, a)| {
                a.original_audit.audit_digest() == original_digest
                    && a.evidence.admission.attempt_sequence == inventory.attempt.attempt_sequence
                    && a.evidence.admission.attempt_digest == inventory.attempt.continuation_digest
            });
            require_retained_continuation(
                original.evidence.admission.attempt_sequence,
                inventory.attempt.attempt_sequence,
                present,
            )?;
        }
    }
    let result = crate::financial_preflight::read_retained_input_exclusions(
        &tx,
        &terms.identity.account_id,
        &original.aliases,
    )?;
    tx.commit()?;
    Ok(result)
    })?;
    drop(connection);
    target.check_current_with_mode(persistence)?;
    Ok(result)
}
/// Pure comparisons only; actual facts above come from the locked Store and
/// genuine installed-peer lease. This helper can issue no snapshot or authority.
fn require_provenance(
    claimed: &ManualRosterPreparationProvenanceV2,
    actual: &ManualRosterPreparationProvenanceV2,
    provider: &str,
    actual_provider: &str,
) -> Result<()> {
    if claimed != actual || provider != actual_provider {
        return Err(StoreError::RecoveryRequired);
    }
    Ok(())
}
fn require_current_continuation(
    original_sequence: u64,
    latest: Option<(u64, &str)>,
    requested_sequence: u64,
    requested_digest: &str,
) -> Result<()> {
    let (sequence, digest) = latest.ok_or(StoreError::RecoveryRequired)?;
    if sequence <= original_sequence || sequence != requested_sequence || digest != requested_digest
    {
        return Err(StoreError::RecoveryRequired);
    }
    Ok(())
}
fn require_retained_continuation(original: u64, selected: u64, present: bool) -> Result<()> {
    if selected <= original || !present {
        return Err(StoreError::RecoveryRequired);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use wholepact_core::{
        manual_roster_inventory_v2::OriginalHostRosterAuditV3,
        manual_roster_v2::{HostRosterAppendBindingV2, HostRosterPredecessorV2},
    };
    #[test]
    fn retained_history_requires_exact_existing_advancing_attempt() {
        assert!(require_retained_continuation(1, 2, true).is_ok());
        assert!(require_retained_continuation(1, 2, false).is_err());
        assert!(require_retained_continuation(1, 1, true).is_err());
        assert!(require_retained_continuation(2, 1, true).is_err());
        // This does not relax the original latest-selection checker.
        assert!(require_current_continuation(1, Some((3, "later")), 2, "selected").is_err());
    }
    fn provenance() -> ManualRosterPreparationProvenanceV2 {
        ManualRosterPreparationProvenanceV2 {
            version: 2,
            original_host_audit: OriginalHostRosterAuditV3::AdditionalPublicationV3 {
                audit_digest: "a".repeat(64),
            },
            roster: HostRosterAppendBindingV2 {
                version: 2,
                generation_id: "b".repeat(64),
                store_destination_identity: "synthetic-store".into(),
                roster_sequence: 2,
                predecessor: HostRosterPredecessorV2::InitialPublicationV2 {
                    audit_digest: "c".repeat(64),
                },
            },
            signer_roster_record_digest: "d".repeat(64),
            witness_roster_extension_digest: "e".repeat(64),
        }
    }
    #[test]
    fn every_v2_provenance_field_and_actual_provider_are_required() {
        let actual = provenance();
        assert!(require_provenance(&actual, &actual, "provider", "provider").is_ok());
        for n in 0..8 {
            let mut changed = actual.clone();
            match n {
                0 => changed.version = 1,
                1 => {
                    changed.original_host_audit =
                        OriginalHostRosterAuditV3::AdditionalPublicationV3 {
                            audit_digest: "f".repeat(64),
                        }
                }
                2 => changed.roster.generation_id = "1".repeat(64),
                3 => changed.roster.store_destination_identity.push_str("-other"),
                4 => changed.roster.roster_sequence += 1,
                5 => {
                    changed.roster.predecessor = HostRosterPredecessorV2::EnrollmentV1 {
                        audit_digest: "c".repeat(64),
                    }
                }
                6 => changed.signer_roster_record_digest = "2".repeat(64),
                _ => changed.witness_roster_extension_digest = "3".repeat(64),
            }
            assert!(require_provenance(&changed, &actual, "provider", "provider").is_err());
        }
        assert!(require_provenance(&actual, &actual, "other-provider", "provider").is_err());
    }
    #[test]
    fn initial_only_stale_changed_or_nonadvancing_attempt_cannot_select() {
        assert!(require_current_continuation(1, Some((2, "current")), 2, "current").is_ok());
        for (latest, sequence, digest) in [
            (None, 2, "current"),
            (Some((1, "initial")), 1, "initial"),
            (Some((3, "newer")), 2, "current"),
            (Some((2, "current")), 2, "changed"),
        ] {
            assert!(require_current_continuation(1, latest, sequence, digest).is_err());
        }
    }
}
