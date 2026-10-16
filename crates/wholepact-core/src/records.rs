//! Private participant records and conservative, source-qualified confidence.
//!
//! These are protected-storage objects, not ordinary API/log summaries. A source
//! is trusted adapter code which authenticates and validates its observations;
//! deserializing a provider's JSON is not an implementation of that boundary.
//! No record, digest, or confidence value authorizes a spend or resolves a ledger.
use crate::agreement::{bounded_text, validate_timestamp};
use crate::error::validate_id;
use crate::proposal::{canonical_digest, validate_sha256};
use crate::{
    AuthorizationExposure, ChainObservation, ChainStatus, CoreError, ErrorCode, Proposal,
    ProposalInput, Result,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

pub const MAX_RECORD_OBSERVATIONS: usize = 4096;

/// Identity and byte hash are deliberately separate. A hash is not verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactTransactionReference {
    pub network_profile_id: String,
    pub transaction_id: String,
    pub transaction_bytes_digest: String,
    pub effects_commitment: String,
}
impl ExactTransactionReference {
    pub fn validate(&self) -> Result<()> {
        validate_id(&self.network_profile_id, "network profile")?;
        validate_sha256(&self.transaction_id)?;
        validate_sha256(&self.transaction_bytes_digest)?;
        bounded_text(&self.effects_commitment, 512, "effects commitment")
    }
}

/// References to the participant's protected consent and signer journal. They
/// are retained evidence references, never a substitute for signature checking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnAuthorizationRecord {
    pub participant_id: String,
    pub account_id: String,
    pub proposal_digest: String,
    pub manifest_digest: String,
    pub effects_commitment: String,
    pub consent_record_ref: String,
    pub authorization_record_ref: String,
    pub release_operation_id: Option<String>,
    pub exposure: AuthorizationExposure,
}
impl OwnAuthorizationRecord {
    fn validate(&self, proposal: &Proposal) -> Result<()> {
        for id in [
            &self.participant_id,
            &self.account_id,
            &self.consent_record_ref,
            &self.authorization_record_ref,
        ] {
            validate_id(id, "own authorization reference")?;
        }
        let owner = proposal
            .manifest()
            .participants
            .iter()
            .find(|p| p.participant_id == self.participant_id)
            .ok_or_else(|| {
                CoreError::new(
                    ErrorCode::UnknownParticipant,
                    "record owner is absent from the approved proposal",
                )
            })?;
        if owner.account_id != self.account_id
            || self.proposal_digest != proposal.proposal_digest()
            || self.manifest_digest != proposal.manifest_digest()
            || Some(&self.effects_commitment) != proposal.input().effects_commitment.as_ref()
        {
            return Err(CoreError::new(ErrorCode::RevisionConflict, "own authorization must bind the exact account, manifest, proposal and transaction effects"));
        }
        if let Some(id) = &self.release_operation_id {
            validate_id(id, "release operation")?;
        }
        if self.exposure == AuthorizationExposure::NotAuthorized
            || self.exposure.was_released() != self.release_operation_id.is_some()
        {
            return Err(CoreError::new(ErrorCode::MissingEvidence, "an authorization record needs local authorization and consistent durable release provenance"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationWindow {
    /// Canonical UTC supplied by the host's clock policy.
    pub now: String,
    /// Chosen freshness policy, not a claim that an old observation is current.
    pub oldest_acceptable: String,
}
impl ObservationWindow {
    pub fn validate(&self) -> Result<()> {
        validate_timestamp(&self.now)?;
        validate_timestamp(&self.oldest_acceptable)?;
        if self.oldest_acceptable > self.now {
            return Err(CoreError::new(
                ErrorCode::InvalidTerms,
                "observation window starts after the current time",
            ));
        }
        Ok(())
    }
    pub fn contains(&self, timestamp: &str) -> bool {
        timestamp >= self.oldest_acceptable.as_str() && timestamp <= self.now.as_str()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationPolicy {
    pub source_id: String,
    pub trust_profile_id: String,
    pub adapter_id: String,
}
impl ObservationPolicy {
    pub fn validate(&self) -> Result<()> {
        validate_id(&self.source_id, "observation source")?;
        validate_id(&self.trust_profile_id, "observation trust profile")?;
        validate_id(&self.adapter_id, "observation adapter")
    }
}

/// Adapter output remains subject to all core consistency checks. The adapter
/// must check transaction identity, network, canonical ancestry and freshness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourcedChainObservation {
    pub transaction: ExactTransactionReference,
    pub adapter_id: String,
    pub observation: ChainObservation,
}
impl SourcedChainObservation {
    pub fn validate_for(
        &self,
        expected: &ExactTransactionReference,
        policy: &ObservationPolicy,
    ) -> Result<()> {
        expected.validate()?;
        self.transaction.validate()?;
        policy.validate()?;
        self.observation.validate()?;
        if &self.transaction != expected
            || self.adapter_id != policy.adapter_id
            || self.observation.source_id != policy.source_id
            || self.observation.trust_profile_id != policy.trust_profile_id
        {
            return Err(CoreError::new(
                ErrorCode::MissingEvidence,
                "observation does not match the exact transaction and configured evidence source",
            ));
        }
        Ok(())
    }
}

/// Trusted host adapter, never an externally implementable JSON `verified`
/// flag. Implementations must use qualified chain-validation code. Core does
/// not claim that an implementation is qualified merely because it compiles.
pub trait SettlementObservationSource {
    fn observe_exact_transaction(
        &mut self,
        transaction: &ExactTransactionReference,
    ) -> Result<SourcedChainObservation>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordConfidence {
    NoObservation,
    OutcomeUncertain,
    Pending,
    Included,
    ConfirmationPolicyMet,
    Stale,
    Contradictory,
    Reorganized,
    ExpiredObserved,
    ConflictedObserved,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecordAssessment {
    pub confidence: RecordConfidence,
    pub confirmations: u32,
    pub required_confirmations: u32,
    pub observation_ids: Vec<String>,
    pub sources: Vec<ObservationPolicy>,
    /// Reorg/contradiction history cannot be erased by a later success response.
    /// This record does not itself implement authoritative exposure resolution.
    pub exposure_reconciliation_required: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordEvent {
    ObservationRecorded,
    ExactReplay,
    ReconcileOutstandingExposure,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct SettlementRecord {
    record_id: String,
    proposal: Proposal,
    own_authorization: OwnAuthorizationRecord,
    transaction: ExactTransactionReference,
    observations: Vec<SourcedChainObservation>,
    exposure_reconciliation_required: bool,
}
impl fmt::Debug for SettlementRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SettlementRecord { private_contents: [REDACTED] }")
    }
}
impl SettlementRecord {
    pub fn new(
        record_id: String,
        proposal: Proposal,
        own_authorization: OwnAuthorizationRecord,
        transaction: ExactTransactionReference,
    ) -> Result<Self> {
        validate_id(&record_id, "record ID")?;
        own_authorization.validate(&proposal)?;
        transaction.validate()?;
        if transaction.network_profile_id != proposal.manifest().agreement.network_profile_id
            || Some(&transaction.effects_commitment) != proposal.input().effects_commitment.as_ref()
        {
            return Err(CoreError::new(
                ErrorCode::RevisionConflict,
                "record transaction differs from the approved network or effects",
            ));
        }
        Ok(Self {
            record_id,
            proposal,
            own_authorization,
            transaction,
            observations: vec![],
            exposure_reconciliation_required: false,
        })
    }
    pub fn record_id(&self) -> &str {
        &self.record_id
    }
    pub fn proposal(&self) -> &Proposal {
        &self.proposal
    }
    pub fn own_authorization(&self) -> &OwnAuthorizationRecord {
        &self.own_authorization
    }
    pub fn transaction(&self) -> &ExactTransactionReference {
        &self.transaction
    }
    pub fn observations(&self) -> &[SourcedChainObservation] {
        &self.observations
    }

    /// Pure transition after one trusted-adapter read. Commit returned record
    /// and event together in protected storage. No ledger exposure is cleared.
    pub fn observe(
        &self,
        source: &mut impl SettlementObservationSource,
        policy: &ObservationPolicy,
        window: &ObservationWindow,
    ) -> Result<(Self, RecordEvent)> {
        policy.validate()?;
        window.validate()?;
        let observation = source.observe_exact_transaction(&self.transaction)?;
        observation.validate_for(&self.transaction, policy)?;
        if !window.contains(&observation.observation.observed_at) {
            return Err(CoreError::new(
                ErrorCode::StaleChain,
                "new observation is stale or from the future",
            ));
        }
        self.append_checked(observation)
    }
    fn append_checked(&self, observation: SourcedChainObservation) -> Result<(Self, RecordEvent)> {
        let incoming = &observation.observation;
        if let Some(old) = self
            .observations
            .iter()
            .find(|old| old.observation.observation_id == incoming.observation_id)
        {
            return if old == &observation {
                Ok((self.clone(), RecordEvent::ExactReplay))
            } else {
                Err(CoreError::new(
                    ErrorCode::RevisionConflict,
                    "observation ID was reused with different evidence",
                ))
            };
        }
        if self.observations.len() >= MAX_RECORD_OBSERVATIONS {
            return Err(CoreError::new(
                ErrorCode::ResourceLimit,
                "record observation limit reached; archive protected history before continuing",
            ));
        }
        if self
            .observations
            .iter()
            .rev()
            .find(|old| old.observation.source_id == incoming.source_id)
            .is_some_and(|old| incoming.observed_at <= old.observation.observed_at)
        {
            return Err(CoreError::new(ErrorCode::StaleChain, "source observations must progress strictly in time; exact replays keep their original ID"));
        }
        if matches!(
            incoming.status,
            ChainStatus::Included | ChainStatus::ConfirmationPolicyMet
        ) && incoming
            .inclusion_height
            .is_some_and(|height| height > self.proposal.manifest().expiry_height)
        {
            return Err(CoreError::new(
                ErrorCode::StaleChain,
                "approved transaction cannot be included beyond its inclusive expiry height",
            ));
        }
        if incoming.status == ChainStatus::ConfirmationPolicyMet
            && incoming.confirmations
                < self
                    .proposal
                    .manifest()
                    .agreement
                    .confirmation_policy
                    .required_confirmations
        {
            return Err(CoreError::new(
                ErrorCode::MissingEvidence,
                "observation overstates the approved confirmation policy",
            ));
        }
        let required = self
            .proposal
            .manifest()
            .agreement
            .confirmation_policy
            .required_confirmations;
        if incoming.status == ChainStatus::ExpiredObserved
            && incoming.tip_height
                < self
                    .proposal
                    .manifest()
                    .expiry_height
                    .checked_add(required)
                    .ok_or_else(|| {
                        CoreError::new(
                            ErrorCode::InvalidTerms,
                            "expiry confidence boundary overflow",
                        )
                    })?
        {
            return Err(CoreError::new(
                ErrorCode::StaleChain,
                "expiry observation has not passed the inclusive expiry and confidence margin",
            ));
        }
        if incoming.status == ChainStatus::ConflictedObserved && incoming.confirmations < required {
            return Err(CoreError::new(
                ErrorCode::MissingEvidence,
                "conflict has not met the record confirmation policy",
            ));
        }
        if !self
            .observations
            .iter()
            .any(|o| o.observation.source_id == incoming.source_id)
            && self
                .observations
                .iter()
                .map(|o| &o.observation.source_id)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                >= 256
        {
            return Err(CoreError::new(
                ErrorCode::ResourceLimit,
                "record supports at most 256 distinct observation sources",
            ));
        }
        let mut latest_by_source = BTreeMap::new();
        for prior in &self.observations {
            latest_by_source.insert(&prior.observation.source_id, &prior.observation);
        }
        let provider_contradiction = latest_by_source.values().any(|prior| {
            prior.source_id != incoming.source_id && !compatible_observations(prior, incoming)
        });
        let reduced = provider_contradiction
            || incoming.status == ChainStatus::Reorganized
            || self.observations.last().is_some_and(|old| {
                matches!(
                    old.observation.status,
                    ChainStatus::Included | ChainStatus::ConfirmationPolicyMet
                ) && (incoming.inclusion_hash != old.observation.inclusion_hash
                    || incoming.inclusion_height != old.observation.inclusion_height
                    || incoming.confirmations < old.observation.confirmations)
            });
        let mut next = self.clone();
        next.exposure_reconciliation_required |= reduced;
        next.observations.push(observation);
        Ok((
            next,
            if reduced {
                RecordEvent::ReconcileOutstandingExposure
            } else {
                RecordEvent::ObservationRecorded
            },
        ))
    }
    pub fn assess(&self, window: &ObservationWindow) -> Result<RecordAssessment> {
        window.validate()?;
        let required_confirmations = self
            .proposal
            .manifest()
            .agreement
            .confirmation_policy
            .required_confirmations;
        let mut latest = BTreeMap::new();
        for observation in &self.observations {
            latest.insert(&observation.observation.source_id, observation);
        }
        let current: Vec<_> = latest
            .values()
            .copied()
            .filter(|o| window.contains(&o.observation.observed_at))
            .collect();
        let mut result = RecordAssessment {
            confidence: if latest.is_empty() {
                RecordConfidence::NoObservation
            } else {
                RecordConfidence::Stale
            },
            confirmations: 0,
            required_confirmations,
            observation_ids: current
                .iter()
                .map(|o| o.observation.observation_id.clone())
                .collect(),
            sources: current
                .iter()
                .map(|o| ObservationPolicy {
                    source_id: o.observation.source_id.clone(),
                    trust_profile_id: o.observation.trust_profile_id.clone(),
                    adapter_id: o.adapter_id.clone(),
                })
                .collect(),
            exposure_reconciliation_required: self.exposure_reconciliation_required,
        };
        let Some(first) = current.first() else {
            return Ok(result);
        };
        let compatible = current
            .iter()
            .all(|o| compatible_observations(&o.observation, &first.observation));
        if !compatible {
            result.confidence = RecordConfidence::Contradictory;
            result.exposure_reconciliation_required = true;
            return Ok(result);
        }
        result.confirmations = current
            .iter()
            .map(|o| o.observation.confirmations)
            .min()
            .unwrap_or(0);
        result.confidence = match first.observation.status {
            ChainStatus::NotSubmitted
            | ChainStatus::SubmissionUnknown
            | ChainStatus::BackendRejected => RecordConfidence::OutcomeUncertain,
            ChainStatus::PendingObserved => RecordConfidence::Pending,
            ChainStatus::Included | ChainStatus::ConfirmationPolicyMet
                if result.confirmations >= required_confirmations =>
            {
                RecordConfidence::ConfirmationPolicyMet
            }
            ChainStatus::Included | ChainStatus::ConfirmationPolicyMet => {
                RecordConfidence::Included
            }
            ChainStatus::Reorganized => RecordConfidence::Reorganized,
            ChainStatus::ExpiredObserved => RecordConfidence::ExpiredObserved,
            ChainStatus::ConflictedObserved => RecordConfidence::ConflictedObserved,
        };
        Ok(result)
    }
    pub fn archive(&self) -> SettlementRecordArchive {
        SettlementRecordArchive {
            schema_version: 1,
            record_id: self.record_id.clone(),
            proposal: self.proposal.input().clone(),
            own_authorization: self.own_authorization.clone(),
            transaction: self.transaction.clone(),
            observations: self.observations.clone(),
            exposure_reconciliation_required: self.exposure_reconciliation_required,
        }
    }
    /// Restored data is validated, but an integrity-valid archive establishes
    /// neither current writer authority nor complete released-authorization history.
    pub fn restore(archive: SettlementRecordArchive) -> Result<Self> {
        let mut record = Self::load_retained_archive(archive)?;
        record.exposure_reconciliation_required = true;
        Ok(record)
    }
    /// Rehydrate an integrity-protected current journal entry, preserving all
    /// conservative warnings. This performs no authority/freshness verification
    /// and must never be used instead of `restore` for backups/imported history.
    pub fn load_retained_archive(archive: SettlementRecordArchive) -> Result<Self> {
        if archive.schema_version != 1 {
            return Err(CoreError::new(
                ErrorCode::UnsupportedVersion,
                "unsupported private record version",
            ));
        }
        if archive.observations.len() > MAX_RECORD_OBSERVATIONS {
            return Err(CoreError::new(
                ErrorCode::ResourceLimit,
                "record observation limit exceeded",
            ));
        }
        let mut record = Self::new(
            archive.record_id,
            Proposal::validate(archive.proposal)?,
            archive.own_authorization,
            archive.transaction,
        )?;
        for observation in archive.observations {
            observation.validate_for(
                &record.transaction,
                &ObservationPolicy {
                    source_id: observation.observation.source_id.clone(),
                    trust_profile_id: observation.observation.trust_profile_id.clone(),
                    adapter_id: observation.adapter_id.clone(),
                },
            )?;
            record = record.append_checked(observation)?.0;
        }
        record.exposure_reconciliation_required |= archive.exposure_reconciliation_required;
        Ok(record)
    }
    /// Integrity binding for protected persistence and preview invalidation, not
    /// a signature or independently verifiable proof of payment.
    pub fn content_digest(&self) -> Result<String> {
        canonical_digest("wholepact:private-record:v1", &self.archive())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettlementRecordArchive {
    pub schema_version: u32,
    pub record_id: String,
    pub proposal: ProposalInput,
    pub own_authorization: OwnAuthorizationRecord,
    pub transaction: ExactTransactionReference,
    pub observations: Vec<SourcedChainObservation>,
    /// Conservative warning only; false never establishes authority or freshness.
    #[serde(default)]
    pub exposure_reconciliation_required: bool,
}
impl fmt::Debug for SettlementRecordArchive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SettlementRecordArchive { private_contents: [REDACTED] }")
    }
}

fn compatible_observations(left: &ChainObservation, right: &ChainObservation) -> bool {
    let inclusion_status = |status| {
        matches!(
            status,
            ChainStatus::Included | ChainStatus::ConfirmationPolicyMet
        )
    };
    (left.status == right.status
        || (inclusion_status(left.status) && inclusion_status(right.status)))
        && left.inclusion_hash == right.inclusion_hash
        && left.inclusion_height == right.inclusion_height
}
