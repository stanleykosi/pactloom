//! Read-only join of complete witness reservations and retained offline history.
//!
//! This is deliberately not complete signer continuity: local online originals,
//! bridge rows, account-use provenance and the live recovery/native fences must
//! still be checked by their owners. No legacy support gate is removed here.
//! A successful join cannot authorize import, recovery, key use or dispatch.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use wholepact_authority::{
    ReconciledAuthorityHistory, ReservationEvidenceRef, ReservationPermit,
    manual_roster_construction_v2::ManualRosterConstructionHistoryRecordV2,
    offline::{
        OfflineAuthorizationAdmission, OfflineAuthorizationTerms, OfflineEnrollmentPolicy,
        OfflineReservationIntent,
    },
};

/// Which copies are present in this inspection, not whether a signature exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OfflineReconciliationPresence {
    ReplayedWitnessOnly,
    RetainedSignerOnly,
    ReplayedAndRetained,
}

/// History coverage only. Even complete coverage is not current permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OfflineReplayCoverage {
    AllRetainedAdmissionsPresent,
    RetainedAdmissionsMissing,
}

/// Borrowed audit evidence. It cannot be deserialized into a live capability.
/// A retained signer copy can itself be full-remote-only, minimal-local-only,
/// or both; its original distinctions and uncertainty are preserved unchanged.
pub struct ReconciledOfflineOrigin<'a> {
    terms: &'a OfflineAuthorizationTerms,
    replayed: Option<&'a OfflineAuthorizationAdmission>,
    retained: Option<&'a OfflineOriginHistory>,
}
impl ReconciledOfflineOrigin<'_> {
    pub fn terms(&self) -> &OfflineAuthorizationTerms {
        self.terms
    }
    pub fn replayed_admission(&self) -> Option<&OfflineAuthorizationAdmission> {
        self.replayed
    }
    pub fn retained_history(&self) -> Option<&OfflineOriginHistory> {
        self.retained
    }
    pub fn presence(&self) -> OfflineReconciliationPresence {
        match (self.replayed.is_some(), self.retained.is_some()) {
            (true, false) => OfflineReconciliationPresence::ReplayedWitnessOnly,
            (true, true) => OfflineReconciliationPresence::ReplayedAndRetained,
            // Private constructors always populate at least one source.
            _ => OfflineReconciliationPresence::RetainedSignerOnly,
        }
    }
    pub fn signature_knowledge(&self) -> OfflineSignatureKnowledge {
        self.retained.map_or(
            OfflineSignatureKnowledge::HistoricalAdmissionSignatureUnknown,
            OfflineOriginHistory::signature_knowledge,
        )
    }
    /// Only an epoch actually present in replayed witness evidence. Minimal
    /// local evidence never acquires the current account/native writer epoch.
    pub fn replayed_writer_epoch(&self) -> Option<u64> {
        self.replayed.map(|a| a.request.writer_epoch)
    }
}

/// Complete witness financial and construction history plus retained *offline* admissions.
/// Online originals without a witness reservation are outside this API's scope;
/// callers must still run complete local-online continuity, not drop those rows.
/// Nonbinding retained offline policies and intents are preserved separately.
pub struct OfflineReconciliationInventory<'a> {
    witness_online: Vec<&'a ReservationPermit>,
    offline: Vec<ReconciledOfflineOrigin<'a>>,
    retained: &'a OfflineHistoryInventory,
    // Exact independent non-signing records, including consumed exposure.
    construction: Vec<(&'a str, &'a ManualRosterConstructionHistoryRecordV2)>,
    common_context_history: Option<wholepact_authority::ConstructionHistoryV2>,
}
impl<'a> OfflineReconciliationInventory<'a> {
    /// Complete inert non-signing records. Every original input ID, nullifier,
    /// obligation, charge and consume link remains visible; none is a permit.
    pub fn construction_records(
        &self,
    ) -> &[(&'a str, &'a ManualRosterConstructionHistoryRecordV2)] {
        &self.construction
    }
    /// Explicit financial-use boundary, independent of historical enumeration.
    /// A successful historical join never imports or activates construction.
    pub fn require_financial_activation_supported(&self) -> Result<()> {
        if !self.construction.is_empty() || self.common_context_history.is_some() {
            return Err(JournalError::ConstructionHistoryUnsupported);
        }
        Ok(())
    }
    pub(super) fn with_construction_records(
        mut self,
        records: impl IntoIterator<Item = (&'a str, &'a ManualRosterConstructionHistoryRecordV2)>,
    ) -> Result<Self> {
        let mut exact = BTreeMap::new();
        for (operation, record) in records {
            let recorded_operation = match record {
                ManualRosterConstructionHistoryRecordV2::Reservation { record } => {
                    if record.reserved_debit_zatoshis
                        != record
                            .request
                            .maximum_net_debit_zatoshis()
                            .map_err(|_| JournalError::InvalidBinding)?
                        || record.reserved_input_value_zatoshis
                            != record
                                .request
                                .input_value_zatoshis()
                                .map_err(|_| JournalError::InvalidBinding)?
                    {
                        return Err(JournalError::InvalidBinding);
                    }
                    &record.request.construction.operation_id
                }
                ManualRosterConstructionHistoryRecordV2::Consumed { record } => {
                    &record.request.operation_id
                }
            };
            if operation != recorded_operation || exact.insert(operation, record).is_some() {
                return Err(JournalError::Conflict);
            }
        }
        let mut consumed_reservations = BTreeSet::new();
        for record in exact.values() {
            if let ManualRosterConstructionHistoryRecordV2::Consumed { record } = record {
                let Some(ManualRosterConstructionHistoryRecordV2::Reservation { record: original }) =
                    exact.get(record.request.reservation_operation_id.as_str())
                else {
                    // An omitted reserve cannot turn consumed exposure into an
                    // empty or apparently refundable historical inventory.
                    return Err(JournalError::InvalidBinding);
                };
                if !consumed_reservations.insert(record.request.reservation_operation_id.as_str())
                    || record.request.expected_head != original.snapshot.head
                    || record.request.account_id != original.snapshot.account_id
                    || record.request.writer_epoch != original.request.writer_epoch
                    || record.request.session_id != original.session.session_id
                    || record.construction_expires_at_ms != original.construction_expires_at_ms
                {
                    return Err(JournalError::Conflict);
                }
            }
        }
        self.construction = exact.into_iter().collect();
        Ok(self)
    }
    pub fn construction_history_v2(&self) -> Option<&wholepact_authority::ConstructionHistoryV2> {
        self.common_context_history.as_ref()
    }
    pub(super) fn with_common_context_history(
        mut self,
        history: Option<wholepact_authority::ConstructionHistoryV2>,
    ) -> Result<Self> {
        if let Some(h) = &history {
            h.validate().map_err(|_| JournalError::InvalidBinding)?;
            // The typed archive includes every V2 origin too. It must match the
            // legacy branch exactly, rather than shadow or silently replace it.
            for origin in h.origins() {
                if let wholepact_authority::ConstructionOriginHistoryV2::RosterV2 { origin } =
                    origin
                {
                    let r = origin.reservation();
                    let matched = self.construction.iter().any(|(id, record)| {
                        *id == r.request.construction.operation_id && matches!(record,
                            ManualRosterConstructionHistoryRecordV2::Reservation { record } if record.as_ref() == r)
                    });
                    if !matched {
                        return Err(JournalError::Conflict);
                    }
                }
            }
        }
        self.common_context_history = history;
        Ok(self)
    }
    pub fn witness_online_reservations(&self) -> &[&ReservationPermit] {
        &self.witness_online
    }
    /// Deterministic authorization-ID order, with each exact origin counted once.
    pub fn offline_origins(&self) -> &[ReconciledOfflineOrigin<'_>] {
        &self.offline
    }
    pub fn retained_enrollments(&self) -> &[OfflineEnrollmentPolicy] {
        self.retained.enrollments()
    }
    pub fn retained_reservation_intents(&self) -> &[OfflineReservationIntent] {
        self.retained.reservation_intents()
    }
    pub fn replay_coverage(&self) -> OfflineReplayCoverage {
        if self.offline.iter().any(|o| o.replayed.is_none()) {
            OfflineReplayCoverage::RetainedAdmissionsMissing
        } else {
            OfflineReplayCoverage::AllRetainedAdmissionsPresent
        }
    }
    /// One necessary history predicate, never a sufficient recovery permission.
    pub fn require_retained_offline_coverage(&self) -> Result<()> {
        if self.replay_coverage() == OfflineReplayCoverage::RetainedAdmissionsMissing {
            return Err(JournalError::RecoveryRequired);
        }
        Ok(())
    }
    /// Display-only worst-case debit of this union. It includes historical
    /// resolved/expired financial entries, every original construction reserve
    /// exactly once even after Consume, plus unmatched local
    /// offline admissions. It is NOT available balance or accountwide budget:
    /// local online originals and financial resolution remain separate inputs.
    pub fn conservative_union_debit_zatoshis(&self) -> Result<u64> {
        self.witness_online
            .iter()
            .map(|p| p.request.maximum_debit_zatoshis)
            .chain(self.offline.iter().map(|o| o.terms.maximum_debit_zatoshis))
            .chain(
                self.construction
                    .iter()
                    .filter_map(|(_, record)| match record {
                        ManualRosterConstructionHistoryRecordV2::Reservation { record } => {
                            Some(record.reserved_debit_zatoshis)
                        }
                        // Consumption never adds a second debit or refunds the first.
                        ManualRosterConstructionHistoryRecordV2::Consumed { .. } => None,
                    }),
            )
            .chain(
                self.common_context_history
                    .iter()
                    .flat_map(|h| h.origins())
                    .filter_map(|origin| match origin {
                        wholepact_authority::ConstructionOriginHistoryV2::CommonContextV3 {
                            origin,
                        } => Some(origin.reservation().reserved_debit_zatoshis),
                        wholepact_authority::ConstructionOriginHistoryV2::RosterV2 { .. } => None,
                    }),
            )
            .try_fold(0_u64, |sum, value| {
                sum.checked_add(value).ok_or(JournalError::Limit)
            })
    }
}

impl OfflineHistoryInventory {
    /// Join with an opaque, complete authenticated replay. Both arguments remain
    /// historical read data; this neither checks nor refreshes a live lease.
    /// Missing retained admissions are visible as gaps, never silently filtered.
    pub fn reconcile_reservations<'a>(
        &'a self,
        history: &'a ReconciledAuthorityHistory,
    ) -> Result<OfflineReconciliationInventory<'a>> {
        self.reconcile_financial_branch(history)?
            .with_construction_records(history.manual_roster_construction_records_v2())?
            .with_common_context_history(common_context_history(history)?)
    }

    /// Private financial branch for a complete V5 wrapper. The authenticated
    /// transport history is checked here and must remain in the containing
    /// complete result; this branch is never an old-format complete history.
    pub(super) fn reconcile_transport_financial_branch<'a>(
        &'a self,
        history: &'a ReconciledAuthorityHistory,
        complete: &wholepact_authority::construction_transport_handoff_v1::ConstructionHistoryWithTransportV1,
    ) -> Result<OfflineReconciliationInventory<'a>> {
        if history
            .construction_history_with_transport_v1()
            .map_err(|_| JournalError::InvalidBinding)?
            != *complete
        {
            return Err(JournalError::InvalidBinding);
        }
        self.reconcile_financial_branch(history)
    }

    fn reconcile_financial_branch<'a>(
        &'a self,
        history: &'a ReconciledAuthorityHistory,
    ) -> Result<OfflineReconciliationInventory<'a>> {
        let account = &history.snapshot().account_id;
        let witness = history.disclosure();
        for policy in self.enrollments() {
            if policy.account_id != *account
                || policy.network_profile_id != witness.network_profile_id
                || policy.witness_id != witness.witness_id
                || policy.witness_certificate_digest != witness.pinned_server_certificate_digest
            {
                return Err(JournalError::InvalidBinding);
            }
        }
        for intent in self.reservation_intents() {
            if intent.terms.account_id != *account
                || intent.terms.network_profile_id != witness.network_profile_id
            {
                return Err(JournalError::InvalidBinding);
            }
        }
        for retained in self.admitted_origins() {
            let terms = retained_terms(retained)?;
            if terms.account_id != *account
                || terms.network_profile_id != witness.network_profile_id
            {
                return Err(JournalError::InvalidBinding);
            }
            if let Some(local) = retained.local_admission() {
                if local.statement.witness_id != witness.witness_id
                    || local.statement.witness_policy_digest != witness.policy_digest
                    || local.pinned_witness_certificate_digest
                        != witness.pinned_server_certificate_digest
                {
                    return Err(JournalError::Conflict);
                }
            }
            if let Some(provenance) = retained.provenance() {
                if provenance.account_policy != *history.account_policy()
                    || provenance.witness != *witness
                {
                    return Err(JournalError::Conflict);
                }
            }
        }
        // Authenticated replay establishes the original policy/source context;
        // matching DTOs alone cannot substitute for that replay.
        let inventory = join_replayed(self, history.reservation_evidence())?;
        for origin in inventory.offline_origins() {
            if let Some(admission) = origin.replayed_admission() {
                if admission.request.intent.terms.account_id != *account
                    || admission.request.intent.terms.network_profile_id
                        != witness.network_profile_id
                    || admission.witness_id != witness.witness_id
                    || admission.witness_policy_digest != witness.policy_digest
                    || !history.contains_head(&admission.request.expected_head)
                    || !history.contains_head(&admission.committed_head)
                {
                    return Err(JournalError::Conflict);
                }
                if let Some(provenance) = origin
                    .retained_history()
                    .and_then(OfflineOriginHistory::provenance)
                {
                    if !history.contains_head(&provenance.history_head)
                        || history
                            .owner_control_request(&provenance.enrollment_operation.operation_id)
                            != Some(&provenance.enrollment_operation)
                    {
                        return Err(JournalError::Conflict);
                    }
                }
            }
        }
        for permit in inventory.witness_online_reservations() {
            if permit.request.account_id != *account
                || permit.request.network_profile_id != witness.network_profile_id
                || permit.witness_id != witness.witness_id
                || permit.policy_digest != witness.policy_digest
                || !history.contains_head(&permit.request.expected_head)
                || !history.contains_head(&permit.committed_head)
            {
                return Err(JournalError::Conflict);
            }
        }
        Ok(inventory)
    }
}

fn retained_terms(retained: &OfflineOriginHistory) -> Result<&OfflineAuthorizationTerms> {
    if let Some(local) = retained.local_admission() {
        return Ok(&local.terms);
    }
    retained
        .admission()
        .map(|a| &a.request.intent.terms)
        .ok_or(JournalError::InvalidBinding)
}

// Pure union kernel, private outside this journal. Unit fixtures exercise this
// separately; they do not manufacture an authenticated ReconciledAuthorityHistory.
pub(super) fn join_replayed<'a>(
    retained: &'a OfflineHistoryInventory,
    replayed: impl IntoIterator<Item = ReservationEvidenceRef<'a>>,
) -> Result<OfflineReconciliationInventory<'a>> {
    let mut ids = BTreeSet::new();
    let mut online = BTreeMap::new();
    let mut offline = BTreeMap::new();
    for evidence in replayed {
        match evidence {
            ReservationEvidenceRef::OnlineV2(permit) => {
                permit
                    .matches_request(&permit.request)
                    .map_err(|_| JournalError::InvalidBinding)?;
                permit
                    .request
                    .validate()
                    .map_err(|_| JournalError::InvalidBinding)?;
                let id = &permit.request.authorization_id;
                if !ids.insert(id.as_str()) {
                    return Err(JournalError::Conflict);
                }
                online.insert(id.as_str(), permit);
            }
            ReservationEvidenceRef::OfflineV1(admission) => {
                admission
                    .matches_request(&admission.request)
                    .map_err(|_| JournalError::InvalidBinding)?;
                let terms = &admission.request.intent.terms;
                if !ids.insert(terms.authorization_id.as_str()) {
                    return Err(JournalError::Conflict);
                }
                offline.insert(
                    terms.authorization_id.as_str(),
                    ReconciledOfflineOrigin {
                        terms,
                        replayed: Some(admission),
                        retained: None,
                    },
                );
            }
        }
    }
    let mut retained_ids = BTreeSet::new();
    for origin in retained.admitted_origins() {
        let terms = retained_terms(origin)?;
        let id = terms.authorization_id.as_str();
        if !retained_ids.insert(id) || online.contains_key(id) {
            return Err(JournalError::Conflict);
        }
        if let Some(entry) = offline.get_mut(id) {
            let replayed = entry.replayed.ok_or(JournalError::InvalidBinding)?;
            if let Some(full) = origin.admission() {
                if full != replayed {
                    return Err(JournalError::Conflict);
                }
            }
            if let Some(local) = origin.local_admission() {
                local.validate_remote(replayed)?;
            }
            entry.retained = Some(origin);
        } else {
            offline.insert(
                id,
                ReconciledOfflineOrigin {
                    terms,
                    replayed: None,
                    retained: Some(origin),
                },
            );
        }
    }
    Ok(OfflineReconciliationInventory {
        witness_online: online.into_values().collect(),
        offline: offline.into_values().collect(),
        retained,
        construction: Vec::new(),
        common_context_history: None,
    })
}

/// Complete authenticated archive, including approval-only V3. This returns no
/// current owner and is never projected into an old-reader financial permit.
pub(super) fn common_context_history(
    history: &ReconciledAuthorityHistory,
) -> Result<Option<wholepact_authority::ConstructionHistoryV2>> {
    let complete = history
        .construction_history_v2()
        .map_err(|_| JournalError::ConstructionHistoryUnsupported)?;
    let has_v3 = complete.origins().iter().any(|o| {
        matches!(
            o,
            wholepact_authority::ConstructionOriginHistoryV2::CommonContextV3 { .. }
        )
    }) || complete.approvals().iter().any(|a| {
        matches!(
            a,
            wholepact_authority::ConstructionApprovalHistoryV2::CommonContextV3 { .. }
        )
    });
    Ok(has_v3.then_some(complete))
}
