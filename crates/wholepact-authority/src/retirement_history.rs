//! Read-only projection of the opaque complete authenticated witness replay.
//! No Deserialize/public constructor, current lease, or retirement readiness.
use crate::{ReconciledAuthorityHistory, ReservationEvidenceRef, Result};
use serde::Serialize;

#[derive(Serialize)]
pub struct RetirementWitnessHistoryFacts {
    evidence_kind: &'static str,
    witness_id: String,
    account_id: String,
    network_profile_id: String,
    policy_digest: String,
    head_sequence: u64,
    head_digest: String,
    witness_last_event_time_ms: u64,
    online_reservation_descriptors: usize,
    offline_reservation_descriptors: usize,
    construction_reservation_records: usize,
    construction_consumption_records: usize,
    construction_retained_debit_zatoshis: u64,
    construction_retained_input_value_zatoshis: u64,
    construction_accounting_semantics: &'static str,
    outstanding_reservations: u64,
    outstanding_debit_zatoshis: u64,
    settled_debit_zatoshis: u64,
    reserved_input_value_zatoshis: u64,
    automatic_key_use_admissions: usize,
    recovery_fences: usize,
    account_use_genesis_digest: Option<String>,
    permanent_exclusion_digest: Option<String>,
    account_birth_semantics: &'static str,
    earliest_chain_activity: &'static str,
    complete_external_pending_transactions: &'static str,
    canonical_unspentness: &'static str,
    external_clone_absence: &'static str,
    retirement_completion: &'static str,
}
impl ReconciledAuthorityHistory {
    pub fn retirement_history_facts(&self) -> Result<RetirementWitnessHistoryFacts> {
        let (mut online, mut offline) = (0, 0);
        for evidence in self.reservation_evidence() {
            match evidence {
                ReservationEvidenceRef::OnlineV2(_) => online += 1,
                ReservationEvidenceRef::OfflineV1(_) => offline += 1,
            }
        }
        // Purpose-distinct construction holds are not financial reservation
        // descriptors. Enumerate them explicitly; never infer absence by using
        // the online/offline iterator alone. Consume/expiry never refund them.
        let (mut construction_reservations, mut construction_consumptions) = (0, 0);
        let (mut construction_debit, mut construction_inputs) = (0u64, 0u64);
        for (_, record) in self.manual_roster_construction_records_v2() {
            match record {
                crate::manual_roster_construction_v2::ManualRosterConstructionHistoryRecordV2::Reservation { record } => {
                    construction_reservations += 1;
                    construction_debit = construction_debit.checked_add(record.reserved_debit_zatoshis).ok_or(crate::AuthorityError::InvalidBinding)?;
                    construction_inputs = construction_inputs.checked_add(record.reserved_input_value_zatoshis).ok_or(crate::AuthorityError::InvalidBinding)?;
                },
                crate::manual_roster_construction_v2::ManualRosterConstructionHistoryRecordV2::Consumed { .. } => construction_consumptions += 1,
            }
        }
        for (_, record) in self.manual_roster_construction_records_v3() {
            match record {
                crate::manual_roster_construction_v3::ManualRosterConstructionHistoryRecordV3::Reservation { record } => {
                    construction_reservations += 1;
                    construction_debit = construction_debit.checked_add(record.reserved_debit_zatoshis).ok_or(crate::AuthorityError::InvalidBinding)?;
                    construction_inputs = construction_inputs.checked_add(record.reserved_input_value_zatoshis).ok_or(crate::AuthorityError::InvalidBinding)?;
                },
                crate::manual_roster_construction_v3::ManualRosterConstructionHistoryRecordV3::Consumed { .. } => construction_consumptions += 1,
            }
        }
        let s = self.snapshot();
        let use_history = self.account_use_history();
        Ok(RetirementWitnessHistoryFacts {
            evidence_kind: "complete_authenticated_witness_namespace_observation",
            witness_id: s.witness_id.clone(),
            account_id: s.account_id.clone(),
            network_profile_id: s.network_profile_id.clone(),
            policy_digest: s.policy_digest.clone(),
            head_sequence: s.head.sequence,
            head_digest: s.head.digest.clone(),
            witness_last_event_time_ms: s.last_witness_time_ms,
            online_reservation_descriptors: online,
            offline_reservation_descriptors: offline,
            construction_reservation_records: construction_reservations,
            construction_consumption_records: construction_consumptions,
            construction_retained_debit_zatoshis: construction_debit,
            construction_retained_input_value_zatoshis: construction_inputs,
            construction_accounting_semantics: "purpose_distinct_permanently_retained_not_signed_released_or_refunded",
            outstanding_reservations: s.outstanding_reservations,
            outstanding_debit_zatoshis: s.outstanding_debit_zatoshis,
            settled_debit_zatoshis: s.settled_debit_zatoshis,
            reserved_input_value_zatoshis: s.reserved_input_value_zatoshis,
            automatic_key_use_admissions: self.automatic_key_use_admissions().len(),
            recovery_fences: self.recovery_fences().len(),
            account_use_genesis_digest: use_history.genesis().map(|g| g.digest()).transpose()?,
            permanent_exclusion_digest: use_history.exclusion().map(|e| e.digest()).transpose()?,
            account_birth_semantics: if use_history.genesis().is_some() {
                "witness_namespace_birth_only_not_earliest_chain_activity"
            } else {
                "legacy_unknown"
            },
            earliest_chain_activity: "unknown",
            complete_external_pending_transactions: "unknown",
            canonical_unspentness: "unknown",
            external_clone_absence: "unknown",
            retirement_completion: "unavailable",
        })
    }
}
