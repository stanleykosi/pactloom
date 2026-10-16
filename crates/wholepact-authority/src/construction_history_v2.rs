//! Exhaustive V2/V3 archive. Values are immutable audit evidence, never an issuer.
//! The original V1 wire layout and digest domain remain unchanged.
use crate::{
    construction_history::ConstructionOriginHistoryV1,
    manual_roster_construction_v2::ManualRosterConstructionApprovalRecordV2,
    manual_roster_construction_v3::*,
    manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2,
    manual_roster_witness_v2::ManualRosterSessionContinuationV2,
    pending_birth::PendingBirthCommitRecord, *,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstructionOriginHistoryV3 {
    extension: ManualRosterEnrollmentExtensionV2,
    continuation: ManualRosterSessionContinuationV2,
    reservation: ManualRosterConstructionReservationRecordV3,
    consumed: Option<ManualRosterConstructionConsumedRecordV3>,
}
impl ConstructionOriginHistoryV3 {
    pub fn extension(&self) -> &ManualRosterEnrollmentExtensionV2 {
        &self.extension
    }
    pub fn continuation(&self) -> &ManualRosterSessionContinuationV2 {
        &self.continuation
    }
    pub fn reservation(&self) -> &ManualRosterConstructionReservationRecordV3 {
        &self.reservation
    }
    pub fn consumed(&self) -> Option<&ManualRosterConstructionConsumedRecordV3> {
        self.consumed.as_ref()
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConstructionOriginHistoryV2 {
    RosterV2 {
        origin: Box<ConstructionOriginHistoryV1>,
    },
    CommonContextV3 {
        origin: Box<ConstructionOriginHistoryV3>,
    },
}
impl ConstructionOriginHistoryV2 {
    pub fn operation_id(&self) -> &str {
        match self {
            Self::RosterV2 { origin } => &origin.reservation().request.construction.operation_id,
            Self::CommonContextV3 { origin } => {
                &origin.reservation().request.construction.operation_id
            }
        }
    }
    pub fn original_key_digest(&self) -> &str {
        match self {
            Self::RosterV2 { origin } => {
                &origin
                    .reservation()
                    .request
                    .construction
                    .plan
                    .retained
                    .selection
                    .scope
                    .selection
                    .invocation
                    .idempotency_key_digest
            }
            Self::CommonContextV3 { origin } => {
                &origin
                    .reservation()
                    .request
                    .construction
                    .plan
                    .retained
                    .selection
                    .scope
                    .selection
                    .invocation
                    .idempotency_key_digest
            }
        }
    }
    pub fn reserved_debit_zatoshis(&self) -> u64 {
        match self {
            Self::RosterV2 { origin } => origin.reservation().reserved_debit_zatoshis,
            Self::CommonContextV3 { origin } => origin.reservation().reserved_debit_zatoshis,
        }
    }
    pub fn reserved_input_value_zatoshis(&self) -> u64 {
        match self {
            Self::RosterV2 { origin } => origin.reservation().reserved_input_value_zatoshis,
            Self::CommonContextV3 { origin } => origin.reservation().reserved_input_value_zatoshis,
        }
    }
    pub fn obligation_id(&self) -> &str {
        match self {
            Self::RosterV2 { origin } => {
                &origin
                    .reservation()
                    .request
                    .enrollment()
                    .scope
                    .obligation_id
            }
            Self::CommonContextV3 { origin } => {
                &origin
                    .reservation()
                    .request
                    .enrollment()
                    .scope
                    .obligation_id
            }
        }
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConstructionApprovalHistoryV2 {
    RosterV2 {
        extension: Box<ManualRosterEnrollmentExtensionV2>,
        record: Box<ManualRosterConstructionApprovalRecordV2>,
    },
    CommonContextV3 {
        extension: Box<ManualRosterEnrollmentExtensionV2>,
        record: Box<ManualRosterConstructionApprovalRecordV3>,
    },
}
impl ConstructionApprovalHistoryV2 {
    fn original_key(&self) -> &str {
        match self {
            Self::RosterV2 { record, .. } => {
                &record
                    .approval
                    .plan
                    .retained
                    .selection
                    .scope
                    .selection
                    .invocation
                    .idempotency_key_digest
            }
            Self::CommonContextV3 { record, .. } => {
                &record
                    .approval
                    .plan
                    .retained
                    .selection
                    .scope
                    .selection
                    .invocation
                    .idempotency_key_digest
            }
        }
    }
    fn validate(&self, birth: &PendingBirthCommitRecord) -> Result<()> {
        match self {
            Self::RosterV2 { extension, record } => {
                extension.validate_original_birth(birth)?;
                record.validate_for(extension)
            }
            Self::CommonContextV3 { extension, record } => {
                extension.validate_original_birth(birth)?;
                record.validate_for(extension)
            }
        }
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstructionHistoryV2 {
    version: u16,
    witness: WitnessDisclosureDescriptor,
    observed_snapshot: AccountSnapshot,
    complete_replay_digest: String,
    original_birth: Option<PendingBirthCommitRecord>,
    approvals: Vec<ConstructionApprovalHistoryV2>,
    origins: Vec<ConstructionOriginHistoryV2>,
}
impl ConstructionHistoryV2 {
    pub fn origins(&self) -> &[ConstructionOriginHistoryV2] {
        &self.origins
    }
    pub fn approvals(&self) -> &[ConstructionApprovalHistoryV2] {
        &self.approvals
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
            n.checked_add(r.reserved_debit_zatoshis())
                .ok_or(AuthorityError::Limit)
        })
    }
    pub fn retained_input_value_zatoshis(&self) -> Result<u64> {
        self.origins.iter().try_fold(0u64, |n, r| {
            n.checked_add(r.reserved_input_value_zatoshis())
                .ok_or(AuthorityError::Limit)
        })
    }
    pub fn conservative_obligations(&self) -> BTreeSet<String> {
        self.origins
            .iter()
            .map(|r| r.obligation_id().to_owned())
            .collect()
    }
    fn require_historical_snapshot(&self, s: &AccountSnapshot) -> Result<()> {
        if s.account_id != self.witness.account_id
            || s.witness_id != self.witness.witness_id
            || s.network_profile_id != self.witness.network_profile_id
            || s.policy_digest != self.witness.policy_digest
            || s.head.sequence > self.observed_snapshot.head.sequence
            || (s.head.sequence == self.observed_snapshot.head.sequence
                && s != &self.observed_snapshot)
            || s.last_witness_time_ms > self.observed_snapshot.last_witness_time_ms
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub fn validate(&self) -> Result<()> {
        if self.observed_snapshot.transport_fences.is_some() {
            return Err(AuthorityError::ConstructionHistoryUnsupported);
        }
        self.validate_projection()
    }
    pub(crate) fn validate_projection(&self) -> Result<()> {
        self.witness.validate()?;
        hash(&self.complete_replay_digest)?;
        hash(&self.observed_snapshot.head.digest)?;
        self.require_historical_snapshot(&self.observed_snapshot)?;
        if self.version != 2
            || self.origins.len() > 4096
            || self.approvals.len() > 4096
            || serde_json::to_vec(self)
                .map_err(|_| AuthorityError::InvalidBinding)?
                .len()
                > MAX_JOURNAL_BYTES as usize
            || self
                .observed_snapshot
                .outstanding_debit_zatoshis
                .checked_add(self.observed_snapshot.settled_debit_zatoshis)
                .is_none_or(|v| v > self.observed_snapshot.aggregate_budget_zatoshis)
        {
            return Err(AuthorityError::InvalidBinding);
        }
        let mut approvals = BTreeMap::new();
        let mut previous_key: Option<&str> = None;
        for approval in &self.approvals {
            approval.validate(
                self.original_birth
                    .as_ref()
                    .ok_or(AuthorityError::InvalidBinding)?,
            )?;
            let key = approval.original_key();
            if previous_key.is_some_and(|p| p >= key) || approvals.insert(key, approval).is_some() {
                return Err(AuthorityError::InvalidBinding);
            }
            previous_key = Some(key);
        }
        let mut previous: Option<&str> = None;
        let mut keys = BTreeSet::new();
        let mut operations = BTreeSet::new();
        for origin in &self.origins {
            let birth = self
                .original_birth
                .as_ref()
                .ok_or(AuthorityError::InvalidBinding)?;
            let operation = origin.operation_id();
            if previous.is_some_and(|p| p >= operation)
                || !operations.insert(operation)
                || !keys.insert(origin.original_key_digest())
            {
                return Err(AuthorityError::InvalidBinding);
            }
            previous = Some(operation);
            let approval = approvals
                .get(origin.original_key_digest())
                .ok_or(AuthorityError::InvalidBinding)?;
            match (origin, *approval) {
                (
                    ConstructionOriginHistoryV2::RosterV2 { origin },
                    ConstructionApprovalHistoryV2::RosterV2 { extension, record },
                ) => {
                    let r = origin.reservation();
                    if origin.extension() != extension.as_ref() {
                        return Err(AuthorityError::InvalidBinding);
                    }
                    origin.extension().validate_original_birth(birth)?;
                    r.validate_for(origin.extension(), origin.continuation())?;
                    record
                        .approval
                        .matches_request(&r.request.construction, extension)?;
                    self.require_historical_snapshot(&r.snapshot)?;
                    if let Some(c) = origin.consumed() {
                        c.validate_for(r, origin.extension(), origin.continuation())?;
                        self.require_historical_snapshot(&c.snapshot)?;
                        if !operations.insert(c.request.operation_id.as_str()) {
                            return Err(AuthorityError::InvalidBinding);
                        }
                    }
                }
                (
                    ConstructionOriginHistoryV2::CommonContextV3 { origin },
                    ConstructionApprovalHistoryV2::CommonContextV3 { extension, record },
                ) => {
                    let r = origin.reservation();
                    if origin.extension() != extension.as_ref() {
                        return Err(AuthorityError::InvalidBinding);
                    }
                    origin.extension().validate_original_birth(birth)?;
                    r.validate_for(origin.extension(), origin.continuation())?;
                    record
                        .approval
                        .matches_request(&r.request.construction, extension)?;
                    self.require_historical_snapshot(&r.snapshot)?;
                    if let Some(c) = origin.consumed() {
                        c.validate_for(r, origin.extension(), origin.continuation())?;
                        self.require_historical_snapshot(&c.snapshot)?;
                        if !operations.insert(c.request.operation_id.as_str()) {
                            return Err(AuthorityError::InvalidBinding);
                        }
                    }
                }
                _ => return Err(AuthorityError::InvalidBinding),
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
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:construction-history:v2", self)
    }
}
impl ReconciledAuthorityHistory {
    pub fn construction_history_v2(&self) -> Result<ConstructionHistoryV2> {
        if !self.construction_transport_history.is_empty() {
            return Err(AuthorityError::ConstructionHistoryUnsupported);
        }
        self.construction_history_v2_projection()
    }
    pub(crate) fn construction_history_v2_projection(&self) -> Result<ConstructionHistoryV2> {
        let legacy = self.construction_history_v1_projection()?;
        let mut origins: Vec<_> = legacy
            .origins()
            .iter()
            .cloned()
            .map(|origin| ConstructionOriginHistoryV2::RosterV2 {
                origin: Box::new(origin),
            })
            .collect();
        let mut reserves = BTreeMap::new();
        let mut consumed = BTreeMap::new();
        for (operation, record) in self.manual_roster_construction_records_v3() {
            match record {
                ManualRosterConstructionHistoryRecordV3::Reservation { record } => {
                    if operation != record.request.construction.operation_id
                        || reserves.insert(operation, record.as_ref()).is_some()
                    {
                        return Err(AuthorityError::CorruptHistory);
                    }
                }
                ManualRosterConstructionHistoryRecordV3::Consumed { record } => {
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
        for (_, reservation) in reserves {
            let enrollment_ref = &reservation
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
                .manual_roster_session_continuation_v2(&reservation.request.attempt_digest)?
                .ok_or(AuthorityError::CorruptHistory)?
                .clone();
            origins.push(ConstructionOriginHistoryV2::CommonContextV3 {
                origin: Box::new(ConstructionOriginHistoryV3 {
                    extension,
                    continuation,
                    reservation: reservation.clone(),
                    consumed: consumed
                        .remove(reservation.request.construction.operation_id.as_str())
                        .cloned(),
                }),
            });
        }
        if !consumed.is_empty() {
            return Err(AuthorityError::CorruptHistory);
        }
        origins.sort_by(|a, b| a.operation_id().cmp(b.operation_id()));
        let mut approvals = Vec::new();
        for request in self.owner_controls.values() {
            match &request.control {
                OwnerControl::ApproveManualRosterConstructionV2 { record } => {
                    let e = &record
                        .approval
                        .plan
                        .retained
                        .selection
                        .scope
                        .selection
                        .inventory
                        .enrollment_ref;
                    approvals.push(ConstructionApprovalHistoryV2::RosterV2 {
                        extension: Box::new(
                            self.manual_roster_enrollment_extension(e)?
                                .ok_or(AuthorityError::CorruptHistory)?
                                .clone(),
                        ),
                        record: record.clone(),
                    });
                }
                OwnerControl::ApproveManualRosterConstructionV3 { record } => {
                    let e = &record
                        .approval
                        .plan
                        .retained
                        .selection
                        .scope
                        .selection
                        .inventory
                        .enrollment_ref;
                    approvals.push(ConstructionApprovalHistoryV2::CommonContextV3 {
                        extension: Box::new(
                            self.manual_roster_enrollment_extension(e)?
                                .ok_or(AuthorityError::CorruptHistory)?
                                .clone(),
                        ),
                        record: record.clone(),
                    });
                }
                _ => {}
            }
        }
        approvals.sort_by(|a, b| a.original_key().cmp(b.original_key()));
        let result = ConstructionHistoryV2 {
            version: 2,
            witness: self.disclosure().clone(),
            observed_snapshot: self.snapshot().clone(),
            complete_replay_digest: self.history_digest()?,
            original_birth: self.pending_birth_commit().cloned(),
            approvals,
            origins,
        };
        result.validate_projection()?;
        Ok(result)
    }
}
