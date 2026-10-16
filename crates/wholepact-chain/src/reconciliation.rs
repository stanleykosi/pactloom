//! Conservative, deterministic reconciliation of provider observations.
//! Reports never clear an authorization, approve a replacement, or prove consensus.
use crate::{
    BlockIdentity, ChainError, TransactionObservation, TransactionStatus, compare_contexts,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use zcash_protocol::TxId;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConfirmationPolicy {
    required_confirmations: u32,
    expiry_observation_depth: u32,
    sources: Vec<String>,
}
impl ConfirmationPolicy {
    /// Sources are explicitly selected dependencies, not a count of independent votes.
    pub fn new(
        required_confirmations: u32,
        expiry_observation_depth: u32,
        sources: Vec<String>,
    ) -> Result<Self, ChainError> {
        let policy = Self {
            required_confirmations,
            expiry_observation_depth,
            sources,
        };
        policy.validate()?;
        Ok(policy)
    }
    fn validate(&self) -> Result<(), ChainError> {
        if !(1..=100).contains(&self.required_confirmations)
            || !(1..=100).contains(&self.expiry_observation_depth)
            || self.sources.is_empty()
            || self.sources.len() > 8
            || self.sources.iter().any(|s| !valid_source_id(s))
            || self.sources.iter().collect::<BTreeSet<_>>().len() != self.sources.len()
        {
            return Err(ChainError::InvalidConfiguration);
        }
        Ok(())
    }
    pub fn required_confirmations(&self) -> u32 {
        self.required_confirmations
    }
    pub fn sources(&self) -> &[String] {
        &self.sources
    }
}
pub(crate) fn valid_source_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

pub struct SourceObservation {
    pub source_id: String,
    pub observation: Result<TransactionObservation, ChainError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum SettlementObservationState {
    NotObserved,
    PendingObserved,
    Included {
        block: BlockIdentity,
        confirmations: u64,
    },
    ConfirmationPolicyMet {
        block: BlockIdentity,
        confirmations: u64,
    },
    Reorganized,
    /// Only observed height passed expiry with the configured depth. Not absence proof.
    PastExpiryObserved,
    /// Prior inclusion can no longer be corroborated. This does not prove a reorg.
    InclusionUncertain,
    Stale,
    Contradictory,
    MissingAncestry,
    BackendUnavailable,
}
impl SettlementObservationState {
    pub fn confirmation_policy_met(&self) -> bool {
        matches!(self, Self::ConfirmationPolicyMet { .. })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceTip {
    pub source_id: String,
    pub tip: BlockIdentity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationReport {
    pub transaction_id: String,
    pub expiry_height: u32,
    pub policy: ConfirmationPolicy,
    pub observed_at_unix_seconds: u64,
    pub valid_until_unix_seconds: u64,
    pub state: SettlementObservationState,
    /// Last corroborated inclusion is retained when confidence is reduced.
    pub last_inclusion: Option<BlockIdentity>,
    /// Loss lineage persists across degraded observations and journal restores.
    /// It clears only after fresh corroborated confirmation without a newly
    /// observed change of inclusion; it never clears authorization exposure.
    pub confidence_lost: bool,
    pub reorganization_observed: bool,
    pub source_ids: Vec<String>,
    pub source_tips: Vec<SourceTip>,
    pub independently_consensus_verified: bool,
    pub clears_authorization_exposure: bool,
    pub permits_replacement: bool,
}
impl ReconciliationReport {
    /// Always use this accessor at display/action time; serialized status is historical.
    pub fn state_at(&self, now: u64) -> SettlementObservationState {
        if now < self.observed_at_unix_seconds || now > self.valid_until_unix_seconds {
            SettlementObservationState::Stale
        } else {
            self.state.clone()
        }
    }
    pub(crate) fn validate(&self) -> Result<(), ChainError> {
        self.policy.validate()?;
        if TxId::from_hex(&self.transaction_id).is_none()
            || self.expiry_height == 0
            || self.source_ids.len() > 8
            || self.source_tips.len() > 8
            || self
                .source_ids
                .iter()
                .any(|id| !self.policy.sources.contains(id))
            || self.source_ids.iter().collect::<BTreeSet<_>>().len() != self.source_ids.len()
            || self.valid_until_unix_seconds < self.observed_at_unix_seconds
            || self.independently_consensus_verified
            || self.clears_authorization_exposure
            || self.permits_replacement
        {
            return Err(ChainError::MalformedEvidence);
        }
        for source in &self.source_tips {
            if !self.source_ids.contains(&source.source_id) {
                return Err(ChainError::MalformedEvidence);
            }
            validate_block(&source.tip)?;
        }
        if self
            .source_tips
            .iter()
            .map(|s| &s.source_id)
            .collect::<BTreeSet<_>>()
            .len()
            != self.source_tips.len()
        {
            return Err(ChainError::MalformedEvidence);
        }
        if let Some(block) = &self.last_inclusion {
            validate_block(block)?;
        }
        match &self.state {
            SettlementObservationState::Included {
                block,
                confirmations,
            }
            | SettlementObservationState::ConfirmationPolicyMet {
                block,
                confirmations,
            } => {
                validate_block(block)?;
                if *confirmations == 0
                    || self.last_inclusion.as_ref() != Some(block)
                    || self.state.confirmation_policy_met()
                        != (*confirmations >= u64::from(self.policy.required_confirmations))
                {
                    return Err(ChainError::MalformedEvidence);
                }
            }
            _ => {}
        }
        Ok(())
    }
}
fn validate_block(block: &BlockIdentity) -> Result<(), ChainError> {
    if block.height == 0
        || block.hash.len() != 64
        || hex::decode(&block.hash).map_or(true, |b| b.iter().all(|v| *v == 0))
    {
        return Err(ChainError::MalformedEvidence);
    }
    Ok(())
}

pub struct SettlementReconciler {
    transaction_id: String,
    expiry_height: u32,
    policy: ConfirmationPolicy,
    previous: Option<ReconciliationReport>,
}
impl SettlementReconciler {
    pub fn new(
        transaction_id: &str,
        expiry_height: u32,
        policy: ConfirmationPolicy,
    ) -> Result<Self, ChainError> {
        let id = TxId::from_hex(transaction_id).ok_or(ChainError::MalformedEvidence)?;
        policy.validate()?;
        if expiry_height == 0 {
            return Err(ChainError::InvalidConfiguration);
        }
        Ok(Self {
            transaction_id: id.to_string(),
            expiry_height,
            policy,
            previous: None,
        })
    }
    /// Reopened state is explicitly stale even if its saved wall-clock TTL remains.
    pub fn restore(mut historical: ReconciliationReport) -> Result<Self, ChainError> {
        historical.validate()?;
        historical.confidence_lost |= historical.state.confirmation_policy_met();
        historical.state = SettlementObservationState::Stale;
        Ok(Self {
            transaction_id: historical.transaction_id.clone(),
            expiry_height: historical.expiry_height,
            policy: historical.policy.clone(),
            previous: Some(historical),
        })
    }
    pub fn last_report(&self) -> Option<&ReconciliationReport> {
        self.previous.as_ref()
    }

    pub fn reconcile(
        &mut self,
        evidence: &[SourceObservation],
        now: u64,
    ) -> Result<ReconciliationReport, ChainError> {
        // Reject amplification before inspecting provider evidence. No evidence is better
        // than retaining a stale positive state; callers must use state_at at point of use.
        if evidence.len() > 8 {
            return Err(ChainError::ResourceLimit);
        }
        let mut report = ReconciliationReport {
            transaction_id: self.transaction_id.clone(),
            expiry_height: self.expiry_height,
            policy: self.policy.clone(),
            observed_at_unix_seconds: now,
            valid_until_unix_seconds: now,
            state: SettlementObservationState::BackendUnavailable,
            last_inclusion: self
                .previous
                .as_ref()
                .and_then(|p| p.last_inclusion.clone()),
            confidence_lost: false,
            reorganization_observed: false,
            source_ids: vec![],
            source_tips: vec![],
            independently_consensus_verified: false,
            clears_authorization_exposure: false,
            permits_replacement: false,
        };
        let mut accepted = Vec::new();
        let mut failure: Option<SettlementObservationState> = None;
        for item in evidence {
            if !self.policy.sources.contains(&item.source_id)
                || report.source_ids.contains(&item.source_id)
            {
                failure = Some(SettlementObservationState::Contradictory);
                continue;
            }
            report.source_ids.push(item.source_id.clone());
            let o = match &item.observation {
                Ok(o) => o,
                Err(e) => {
                    let state = match e {
                        ChainError::StaleChain => SettlementObservationState::Stale,
                        ChainError::ContradictoryChain
                        | ChainError::WrongBranch
                        | ChainError::WrongNetwork
                        | ChainError::MalformedEvidence => {
                            SettlementObservationState::Contradictory
                        }
                        ChainError::MissingAncestryEvidence => {
                            SettlementObservationState::MissingAncestry
                        }
                        _ => SettlementObservationState::BackendUnavailable,
                    };
                    choose_failure(&mut failure, state);
                    continue;
                }
            };
            let malformed = o.transaction_id != self.transaction_id
                || o.context.source().source_id != item.source_id
                || o.clears_authorization_exposure
                || o.independently_consensus_verified
                || (!matches!(o.status, TransactionStatus::NotObserved)
                    && !o.confirms_raw_transaction_id);
            if malformed {
                choose_failure(&mut failure, SettlementObservationState::Contradictory);
                continue;
            }
            if o.context.check_fresh_at(now).is_err() {
                choose_failure(&mut failure, SettlementObservationState::Stale);
                continue;
            }
            if let TransactionStatus::Included {
                block,
                confirmations,
            } = &o.status
                && (validate_block(block).is_err()
                    || block.height > o.context.tip().height
                    || block.height > u64::from(self.expiry_height)
                    || (block.height == o.context.tip().height
                        && block.hash != o.context.tip().hash)
                    || *confirmations != o.context.tip().height - block.height + 1)
            {
                choose_failure(&mut failure, SettlementObservationState::Contradictory);
                continue;
            }
            report.source_tips.push(SourceTip {
                source_id: item.source_id.clone(),
                tip: o.context.tip().clone(),
            });
            accepted.push(o);
        }
        if report.source_ids.len() != self.policy.sources.len() {
            choose_failure(&mut failure, SettlementObservationState::BackendUnavailable);
        }
        if let Some(first) = accepted.first() {
            for other in accepted.iter().skip(1) {
                match compare_contexts(&first.context, &other.context, now) {
                    Err(ChainError::MissingAncestryEvidence) => {
                        choose_failure(&mut failure, SettlementObservationState::MissingAncestry)
                    }
                    Err(_) => {
                        choose_failure(&mut failure, SettlementObservationState::Contradictory)
                    }
                    Ok(()) => {
                        if first.status != other.status {
                            choose_failure(&mut failure, SettlementObservationState::Contradictory);
                        }
                    }
                }
            }
        }
        if let Some(failure) = failure {
            report.state = failure;
        } else if let Some(o) = accepted.first() {
            report.valid_until_unix_seconds = accepted
                .iter()
                .map(|o| o.context.valid_until_unix_seconds())
                .min()
                .unwrap_or(now);
            report.state = match &o.status {
                TransactionStatus::NotObserved if report.last_inclusion.is_some() => {
                    SettlementObservationState::InclusionUncertain
                }
                TransactionStatus::NotObserved
                    if o.context.tip().height
                        >= u64::from(self.expiry_height)
                            + u64::from(self.policy.expiry_observation_depth) =>
                {
                    SettlementObservationState::PastExpiryObserved
                }
                TransactionStatus::NotObserved => SettlementObservationState::NotObserved,
                TransactionStatus::PendingObserved
                    if o.context.tip().height > u64::from(self.expiry_height) =>
                {
                    SettlementObservationState::Contradictory
                }
                TransactionStatus::PendingObserved if report.last_inclusion.is_some() => {
                    report.reorganization_observed = true;
                    SettlementObservationState::Reorganized
                }
                TransactionStatus::PendingObserved => SettlementObservationState::PendingObserved,
                TransactionStatus::Reorganized => {
                    report.reorganization_observed = true;
                    SettlementObservationState::Reorganized
                }
                TransactionStatus::Included {
                    block,
                    confirmations,
                } => {
                    report.reorganization_observed = report
                        .last_inclusion
                        .as_ref()
                        .is_some_and(|old| old != block);
                    report.last_inclusion = Some(block.clone());
                    if *confirmations >= u64::from(self.policy.required_confirmations) {
                        SettlementObservationState::ConfirmationPolicyMet {
                            block: block.clone(),
                            confirmations: *confirmations,
                        }
                    } else {
                        SettlementObservationState::Included {
                            block: block.clone(),
                            confirmations: *confirmations,
                        }
                    }
                }
            };
        }
        report.confidence_lost = self
            .previous
            .as_ref()
            .is_some_and(|p| p.state.confirmation_policy_met() || p.confidence_lost)
            && (!report.state.confirmation_policy_met() || report.reorganization_observed);
        report.validate()?;
        self.previous = Some(report.clone());
        Ok(report)
    }
}
fn choose_failure(
    slot: &mut Option<SettlementObservationState>,
    candidate: SettlementObservationState,
) {
    fn rank(state: &SettlementObservationState) -> u8 {
        match state {
            SettlementObservationState::Contradictory => 4,
            SettlementObservationState::Stale => 3,
            SettlementObservationState::MissingAncestry => 2,
            _ => 1,
        }
    }
    if slot.as_ref().is_none_or(|old| rank(&candidate) > rank(old)) {
        *slot = Some(candidate);
    }
}

#[cfg(test)]
#[path = "reconciliation_tests.rs"]
mod tests;
