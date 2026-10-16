//! Versioned historical construction archive. Decoding validates structure only;
//! authenticity comes from the containing authenticated/native-approved archive.
//! No current session, financial permission, refund or recovery issuer exists here.
use crate::{
    AccountSnapshot, AuthorityError, ReconciledAuthorityHistory, Result,
    WitnessDisclosureDescriptor,
    manual_roster_construction_v2::{
        ManualRosterConstructionConsumedRecordV2, ManualRosterConstructionHistoryRecordV2,
        ManualRosterConstructionReservationRecordV2,
    },
    manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2,
    manual_roster_witness_v2::ManualRosterSessionContinuationV2,
    pending_birth::PendingBirthCommitRecord,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
const MAX_BYTES: usize = 120 * 1024;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstructionOriginHistoryV1 {
    extension: ManualRosterEnrollmentExtensionV2,
    continuation: ManualRosterSessionContinuationV2,
    reservation: ManualRosterConstructionReservationRecordV2,
    consumed: Option<ManualRosterConstructionConsumedRecordV2>,
}
impl ConstructionOriginHistoryV1 {
    pub fn reservation(&self) -> &ManualRosterConstructionReservationRecordV2 {
        &self.reservation
    }
    pub fn consumed(&self) -> Option<&ManualRosterConstructionConsumedRecordV2> {
        self.consumed.as_ref()
    }
    pub fn extension(&self) -> &ManualRosterEnrollmentExtensionV2 {
        &self.extension
    }
    pub fn continuation(&self) -> &ManualRosterSessionContinuationV2 {
        &self.continuation
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstructionHistoryV1 {
    version: u16,
    witness: WitnessDisclosureDescriptor,
    observed_snapshot: AccountSnapshot,
    complete_replay_digest: String,
    original_birth: Option<PendingBirthCommitRecord>,
    origins: Vec<ConstructionOriginHistoryV1>,
}
impl ConstructionHistoryV1 {
    pub fn origins(&self) -> &[ConstructionOriginHistoryV1] {
        &self.origins
    }
    pub fn witness(&self) -> &WitnessDisclosureDescriptor {
        &self.witness
    }
    pub fn observed_snapshot(&self) -> &AccountSnapshot {
        &self.observed_snapshot
    }
    pub fn complete_replay_digest(&self) -> &str {
        &self.complete_replay_digest
    }
    pub fn original_birth(&self) -> Option<&PendingBirthCommitRecord> {
        self.original_birth.as_ref()
    }
    pub fn retained_debit_zatoshis(&self) -> Result<u64> {
        self.origins.iter().try_fold(0u64, |n, r| {
            n.checked_add(r.reservation.reserved_debit_zatoshis)
                .ok_or(AuthorityError::Limit)
        })
    }
    pub fn retained_input_value_zatoshis(&self) -> Result<u64> {
        self.origins.iter().try_fold(0u64, |n, r| {
            n.checked_add(r.reservation.reserved_input_value_zatoshis)
                .ok_or(AuthorityError::Limit)
        })
    }
    pub fn conservative_obligations(&self) -> BTreeSet<String> {
        self.origins
            .iter()
            .map(|r| {
                r.reservation
                    .request
                    .enrollment()
                    .scope
                    .obligation_id
                    .clone()
            })
            .collect()
    }
    pub fn validate(&self) -> Result<()> {
        if self.observed_snapshot.transport_fences.is_some() {
            return Err(AuthorityError::ConstructionHistoryUnsupported);
        }
        self.validate_projection()
    }
    pub(crate) fn validate_projection(&self) -> Result<()> {
        self.witness.validate()?;
        wholepact_core::proposal::validate_sha256(&self.complete_replay_digest)
            .map_err(|_| AuthorityError::InvalidBinding)?;
        wholepact_core::proposal::validate_sha256(&self.observed_snapshot.head.digest)
            .map_err(|_| AuthorityError::InvalidBinding)?;
        if self.version != 1
            || self.origins.len() > 4096
            || self.observed_snapshot.account_id != self.witness.account_id
            || self.observed_snapshot.witness_id != self.witness.witness_id
            || self.observed_snapshot.network_profile_id != self.witness.network_profile_id
            || self.observed_snapshot.policy_digest != self.witness.policy_digest
            || serde_json::to_vec(self)
                .map_err(|_| AuthorityError::InvalidBinding)?
                .len()
                > MAX_BYTES
        {
            return Err(AuthorityError::InvalidBinding);
        }
        if self
            .observed_snapshot
            .outstanding_debit_zatoshis
            .checked_add(self.observed_snapshot.settled_debit_zatoshis)
            .ok_or(AuthorityError::Limit)?
            > self.observed_snapshot.aggregate_budget_zatoshis
        {
            return Err(AuthorityError::InvalidBinding);
        }
        let mut previous: Option<&str> = None;
        let mut operations = BTreeSet::new();
        for origin in &self.origins {
            let birth = self
                .original_birth
                .as_ref()
                .ok_or(AuthorityError::InvalidBinding)?;
            origin.extension.validate_original_birth(birth)?;
            origin.continuation.validate_for(&origin.extension)?;
            origin
                .reservation
                .validate_for(&origin.extension, &origin.continuation)?;
            let r = &origin.reservation;
            let operation = r.request.construction.operation_id.as_str();
            if previous.is_some_and(|p| p >= operation)
                || !operations.insert(operation)
                || r.snapshot.account_id != self.witness.account_id
                || r.snapshot.witness_id != self.witness.witness_id
                || r.snapshot.network_profile_id != self.witness.network_profile_id
                || r.snapshot.policy_digest != self.witness.policy_digest
            {
                return Err(AuthorityError::InvalidBinding);
            }
            previous = Some(operation);
            self.require_historical_snapshot(&r.snapshot)?;
            if let Some(c) = &origin.consumed {
                c.validate_for(r, &origin.extension, &origin.continuation)?;
                if !operations.insert(c.request.operation_id.as_str()) {
                    return Err(AuthorityError::InvalidBinding);
                }
                self.require_historical_snapshot(&c.snapshot)?;
            }
        }
        if self.retained_debit_zatoshis()? > self.observed_snapshot.outstanding_debit_zatoshis
            || self.retained_input_value_zatoshis()?
                > self.observed_snapshot.reserved_input_value_zatoshis
            || self.origins.len() as u64 > self.observed_snapshot.outstanding_reservations
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    fn require_historical_snapshot(&self, s: &AccountSnapshot) -> Result<()> {
        if s.head.sequence > self.observed_snapshot.head.sequence
            || (s.head.sequence == self.observed_snapshot.head.sequence
                && s != &self.observed_snapshot)
            || s.last_witness_time_ms > self.observed_snapshot.last_witness_time_ms
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        wholepact_core::proposal::canonical_digest("wholepact:construction-history:v1", self)
            .map_err(|_| AuthorityError::InvalidBinding)
    }
}
impl ReconciledAuthorityHistory {
    /// Produced from every retained record of the already complete replay.
    /// The serializable result is historical data; saved copies grant no authority.
    pub fn construction_history_v1(&self) -> Result<ConstructionHistoryV1> {
        self.require_construction_v2_only()?;
        self.construction_history_v1_projection()
    }
    pub(crate) fn construction_history_v1_projection(&self) -> Result<ConstructionHistoryV1> {
        let mut reserves = BTreeMap::new();
        let mut consumed = BTreeMap::new();
        for (operation, record) in self.manual_roster_construction_records_v2() {
            match record {
                ManualRosterConstructionHistoryRecordV2::Reservation { record } => {
                    if operation != record.request.construction.operation_id
                        || reserves.insert(operation, record.as_ref()).is_some()
                    {
                        return Err(AuthorityError::CorruptHistory);
                    }
                }
                ManualRosterConstructionHistoryRecordV2::Consumed { record } => {
                    if operation != record.request.operation_id
                        || consumed
                            .insert(
                                record.request.reservation_operation_id.as_str(),
                                record.as_ref(),
                            )
                            .is_some()
                    {
                        return Err(AuthorityError::CorruptHistory);
                    }
                }
            }
        }
        let mut origins = Vec::new();
        for (_, r) in reserves {
            let enrollment_ref = &r
                .request
                .construction
                .plan
                .retained
                .selection
                .scope
                .selection
                .inventory
                .enrollment_ref;
            let extension = self
                .manual_roster_enrollment_extension(enrollment_ref)?
                .ok_or(AuthorityError::CorruptHistory)?
                .clone();
            let continuation = self
                .manual_roster_session_continuation_v2(&r.request.attempt_digest)?
                .ok_or(AuthorityError::CorruptHistory)?
                .clone();
            origins.push(ConstructionOriginHistoryV1 {
                extension,
                continuation,
                reservation: r.clone(),
                consumed: consumed
                    .remove(r.request.construction.operation_id.as_str())
                    .cloned(),
            });
        }
        if !consumed.is_empty() {
            return Err(AuthorityError::CorruptHistory);
        }
        let result = ConstructionHistoryV1 {
            version: 1,
            witness: self.disclosure().clone(),
            observed_snapshot: self.snapshot().clone(),
            complete_replay_digest: self.history_digest()?,
            original_birth: self.pending_birth_commit().cloned(),
            origins,
        };
        result.validate_projection()?;
        Ok(result)
    }
}
