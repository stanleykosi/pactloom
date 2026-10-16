//! Three independent state axes. These are deterministic bookkeeping rules,
//! not cryptographic evidence or permission to sign. Host adapters authenticate
//! observations; the store atomically commits events/intents before side effects.
use crate::agreement::validate_timestamp;
use crate::error::validate_id;
use crate::proposal::validate_sha256;
use crate::{Amount, CoreError, ErrorCode, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgressState {
    Draft,
    GatheringIntent,
    PreparingProposal,
    AwaitingAuthorization,
    ReadyForSubmission,
    SubmissionAttempted,
    ObservingSettlement,
    Declined,
    RevisionRequired,
    ValidationFailed,
    Obsolete,
    CancellationRequested,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationExposure {
    NotAuthorized,
    AuthorizedLocally,
    Released,
    OutstandingUncertain,
    ExpiredObserved,
    ConflictedObserved,
    Consumed,
}

impl AuthorizationExposure {
    /// Execution assessment at the last observed branch only. This is not a
    /// budget release, replacement permit or account-retirement decision.
    pub fn may_still_execute(self) -> bool {
        matches!(
            self,
            Self::AuthorizedLocally | Self::Released | Self::OutstandingUncertain
        )
    }
    /// Keep reversible conflict and expiry observations charged until a distinct
    /// qualified resolution/admission protocol establishes more than this label.
    /// Consumed value is settled debit, not reusable allowance.
    pub fn retains_unresolved_exposure(self) -> bool {
        !matches!(self, Self::NotAuthorized | Self::Consumed)
    }
    pub fn was_released(self) -> bool {
        !matches!(self, Self::NotAuthorized | Self::AuthorizedLocally)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainStatus {
    NotSubmitted,
    SubmissionUnknown,
    BackendRejected,
    PendingObserved,
    Included,
    ConfirmationPolicyMet,
    Reorganized,
    ExpiredObserved,
    ConflictedObserved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainObservation {
    pub observation_id: String,
    pub source_id: String,
    pub trust_profile_id: String,
    pub observed_at: String,
    pub tip_height: u32,
    pub tip_hash: String,
    pub synchronized: bool,
    pub status: ChainStatus,
    pub inclusion_height: Option<u32>,
    pub inclusion_hash: Option<String>,
    pub confirmations: u32,
    pub evidence_ref: String,
}

impl ChainObservation {
    pub fn validate(&self) -> Result<()> {
        validate_id(&self.observation_id, "observation ID")?;
        validate_id(&self.source_id, "chain source ID")?;
        validate_id(&self.trust_profile_id, "trust profile ID")?;
        validate_id(&self.evidence_ref, "chain evidence reference")?;
        validate_timestamp(&self.observed_at)?;
        validate_sha256(&self.tip_hash)?;
        if !self.synchronized {
            return Err(CoreError::new(
                ErrorCode::StaleChain,
                "unsynchronized chain observations cannot resolve authorization exposure",
            ));
        }
        match (self.inclusion_height, &self.inclusion_hash) {
            (Some(height), Some(hash)) => {
                validate_sha256(hash)?;
                let expected = self
                    .tip_height
                    .checked_sub(height)
                    .and_then(|n| n.checked_add(1))
                    .ok_or_else(|| {
                        CoreError::new(
                            ErrorCode::StaleChain,
                            "inclusion height contradicts the observed chain tip",
                        )
                    })?;
                if self.confirmations != expected {
                    return Err(CoreError::new(
                        ErrorCode::StaleChain,
                        "confirmation count contradicts inclusion and tip heights",
                    ));
                }
            }
            (None, None) if self.confirmations == 0 => {}
            _ => {
                return Err(CoreError::new(
                    ErrorCode::StaleChain,
                    "incomplete or inconsistent inclusion evidence",
                ));
            }
        }
        let requires_inclusion = matches!(
            self.status,
            ChainStatus::Included
                | ChainStatus::ConfirmationPolicyMet
                | ChainStatus::ConflictedObserved
        );
        if requires_inclusion != self.inclusion_height.is_some() {
            return Err(CoreError::new(
                ErrorCode::StaleChain,
                "chain status contradicts the presence of inclusion evidence",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Lifecycle {
    progress: ProgressState,
    authorization_exposure: AuthorizationExposure,
    chain_status: ChainStatus,
    expiry_height: u32,
    required_confirmations: u32,
    release_operation_id: Option<String>,
    transaction_bytes_digest: Option<String>,
    latest_observation: Option<ChainObservation>,
    recovery_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleEvent {
    BeginGatheringIntent,
    PrepareProposal,
    AwaitAuthorization,
    RecordLocalAuthorization,
    DiscardUnreleasedAuthorization,
    /// Applying this event is not persistence. Commit it and the outbox before
    /// any signature crosses the signer boundary, even when delivery may fail.
    RecordReleaseIntent {
        operation_id: String,
    },
    RecordReadyForSubmission,
    /// Retries must retain this exact transaction-bytes digest.
    RecordSubmissionIntent {
        transaction_bytes_digest: String,
    },
    RecordBackendRejection,
    RequestCancellation,
    Decline,
    RequireRevision,
    FailValidation,
    MarkObsolete,
    MarkRecoveryRequired,
    MarkReorganization,
}

impl Lifecycle {
    pub fn new(expiry_height: u32, required_confirmations: u32) -> Result<Self> {
        if expiry_height == 0 || required_confirmations == 0 || required_confirmations > 10_000 {
            return Err(CoreError::new(
                ErrorCode::InvalidTerms,
                "expiry and confirmation policy must be nonzero",
            ));
        }
        expiry_height
            .checked_add(required_confirmations)
            .ok_or_else(|| {
                CoreError::new(
                    ErrorCode::InvalidTerms,
                    "expiry confidence height overflows",
                )
            })?;
        Ok(Self {
            progress: ProgressState::Draft,
            authorization_exposure: AuthorizationExposure::NotAuthorized,
            chain_status: ChainStatus::NotSubmitted,
            expiry_height,
            required_confirmations,
            release_operation_id: None,
            transaction_bytes_digest: None,
            latest_observation: None,
            recovery_required: false,
        })
    }
    pub fn progress(&self) -> ProgressState {
        self.progress
    }
    pub fn authorization_exposure(&self) -> AuthorizationExposure {
        self.authorization_exposure
    }
    pub fn chain_status(&self) -> ChainStatus {
        self.chain_status
    }
    pub fn recovery_required(&self) -> bool {
        self.recovery_required
    }
    pub fn latest_observation(&self) -> Option<&ChainObservation> {
        self.latest_observation.as_ref()
    }

    /// Returns a new state; errors leave the original state untouched.
    pub fn apply(&self, event: LifecycleEvent) -> Result<Self> {
        use AuthorizationExposure as A;
        use LifecycleEvent as E;
        use ProgressState as P;
        let mut next = self.clone();
        let invalid = || {
            CoreError::new(
                ErrorCode::InvalidTransition,
                "event is not permitted in the current lifecycle state",
            )
        };
        match event {
            E::BeginGatheringIntent if self.progress == P::Draft => {
                next.progress = P::GatheringIntent
            }
            E::PrepareProposal
                if matches!(
                    self.progress,
                    P::Draft | P::GatheringIntent | P::RevisionRequired
                ) && self.authorization_exposure == A::NotAuthorized =>
            {
                next.progress = P::PreparingProposal
            }
            E::AwaitAuthorization if self.progress == P::PreparingProposal => {
                next.progress = P::AwaitingAuthorization
            }
            E::RecordLocalAuthorization
                if self.progress == P::AwaitingAuthorization
                    && self.authorization_exposure == A::NotAuthorized
                    && !self.recovery_required =>
            {
                next.authorization_exposure = A::AuthorizedLocally
            }
            E::DiscardUnreleasedAuthorization
                if self.authorization_exposure == A::AuthorizedLocally
                    && self.release_operation_id.is_none() =>
            {
                next.authorization_exposure = A::NotAuthorized
            }
            E::RecordReleaseIntent { operation_id } => {
                validate_id(&operation_id, "release operation ID")?;
                if self.release_operation_id.as_ref() == Some(&operation_id) {
                    return Ok(next);
                }
                if self.authorization_exposure != A::AuthorizedLocally
                    || self.progress != P::AwaitingAuthorization
                    || self.recovery_required
                    || self.release_operation_id.is_some()
                {
                    return Err(invalid());
                }
                next.release_operation_id = Some(operation_id);
                next.authorization_exposure = A::Released;
            }
            E::RecordReadyForSubmission
                if self.authorization_exposure == A::Released
                    && self.progress == P::AwaitingAuthorization
                    && !self.recovery_required =>
            {
                next.progress = P::ReadyForSubmission
            }
            E::RecordSubmissionIntent {
                transaction_bytes_digest,
            } => {
                validate_sha256(&transaction_bytes_digest)?;
                if !matches!(
                    self.progress,
                    P::ReadyForSubmission | P::SubmissionAttempted | P::ObservingSettlement
                ) || !matches!(
                    self.authorization_exposure,
                    A::Released | A::OutstandingUncertain
                ) || self.recovery_required
                {
                    return Err(invalid());
                }
                if self
                    .transaction_bytes_digest
                    .as_ref()
                    .is_some_and(|digest| digest != &transaction_bytes_digest)
                {
                    return Err(CoreError::new(
                        ErrorCode::OutstandingExposure,
                        "submission retry cannot change the exact transaction bytes",
                    ));
                }
                next.transaction_bytes_digest = Some(transaction_bytes_digest);
                next.progress = P::SubmissionAttempted;
                next.chain_status = ChainStatus::SubmissionUnknown;
                next.authorization_exposure = A::OutstandingUncertain;
            }
            E::RecordBackendRejection
                if self.transaction_bytes_digest.is_some()
                    && self.authorization_exposure.may_still_execute() =>
            {
                next.chain_status = ChainStatus::BackendRejected;
                next.authorization_exposure = A::OutstandingUncertain;
            }
            E::RequestCancellation => {
                next.progress = P::CancellationRequested;
                if self.authorization_exposure.was_released()
                    && self.authorization_exposure.may_still_execute()
                {
                    next.authorization_exposure = A::OutstandingUncertain;
                }
                // Even local authorization is retained until protected deletion
                // has been acknowledged by DiscardUnreleasedAuthorization.
            }
            E::Decline => next.progress = P::Declined,
            E::RequireRevision => next.progress = P::RevisionRequired,
            E::FailValidation => next.progress = P::ValidationFailed,
            E::MarkObsolete => next.progress = P::Obsolete,
            E::MarkRecoveryRequired => {
                next.recovery_required = true;
                if self.authorization_exposure.was_released() {
                    next.authorization_exposure = A::OutstandingUncertain;
                }
            }
            E::MarkReorganization => {
                next.chain_status = ChainStatus::Reorganized;
                if self.authorization_exposure.was_released() {
                    next.authorization_exposure = A::OutstandingUncertain;
                    next.progress = P::ObservingSettlement;
                }
                // Previously resolved alternatives may be live again. A new
                // fresh observation alone must not automatically clear this.
                next.recovery_required = true;
            }
            _ => return Err(invalid()),
        }
        Ok(next)
    }

    /// Bookkeep a host-authenticated chain observation. The caller must verify
    /// transaction identity, canonical-chain inclusion/conflict, and freshness
    /// against a qualified profile before calling. This method cannot do so.
    /// It never grants authorization or clears recovery-required status.
    pub fn observe(&self, observation: ChainObservation) -> Result<Self> {
        use AuthorizationExposure as A;
        observation.validate()?;
        if self
            .latest_observation
            .as_ref()
            .is_some_and(|previous| observation.observed_at < previous.observed_at)
        {
            return Err(CoreError::new(
                ErrorCode::StaleChain,
                "an older observation cannot replace the current chain assessment",
            ));
        }
        if !self.authorization_exposure.was_released() {
            return Err(CoreError::new(
                ErrorCode::InvalidTransition,
                "cannot resolve an authorization that was not released",
            ));
        }
        let mut next = self.clone();
        match observation.status {
            ChainStatus::Included | ChainStatus::ConfirmationPolicyMet => {
                let inclusion = observation.inclusion_height.ok_or_else(|| {
                    CoreError::new(
                        ErrorCode::MissingEvidence,
                        "inclusion requires a block reference",
                    )
                })?;
                if inclusion > self.expiry_height {
                    return Err(CoreError::new(
                        ErrorCode::StaleChain,
                        "inclusion after the transaction expiry contradicts the profile",
                    ));
                }
                if observation.status == ChainStatus::ConfirmationPolicyMet {
                    if observation.confirmations < self.required_confirmations {
                        return Err(CoreError::new(
                            ErrorCode::StaleChain,
                            "confirmation policy has not been met",
                        ));
                    }
                    next.authorization_exposure = A::Consumed;
                } else {
                    next.authorization_exposure = A::OutstandingUncertain;
                }
                next.progress = ProgressState::ObservingSettlement;
            }
            ChainStatus::ExpiredObserved => {
                let boundary = self
                    .expiry_height
                    .checked_add(self.required_confirmations)
                    .ok_or_else(|| {
                        CoreError::new(
                            ErrorCode::InvalidTerms,
                            "expiry confidence boundary overflow",
                        )
                    })?;
                if observation.tip_height < boundary || observation.inclusion_height.is_some() {
                    return Err(CoreError::new(
                        ErrorCode::StaleChain,
                        "expiry requires a canonical observed tip beyond the inclusive expiry height and confidence margin",
                    ));
                }
                next.authorization_exposure = A::ExpiredObserved;
            }
            ChainStatus::ConflictedObserved => {
                if observation.inclusion_height.is_none()
                    || observation.confirmations < self.required_confirmations
                {
                    return Err(CoreError::new(
                        ErrorCode::MissingEvidence,
                        "conflict requires confirmed canonical-chain evidence",
                    ));
                }
                next.authorization_exposure = A::ConflictedObserved;
            }
            ChainStatus::Reorganized => {
                next.authorization_exposure = A::OutstandingUncertain;
                next.recovery_required = true;
            }
            ChainStatus::PendingObserved
            | ChainStatus::SubmissionUnknown
            | ChainStatus::BackendRejected => {
                next.authorization_exposure = A::OutstandingUncertain;
                if matches!(
                    self.authorization_exposure,
                    A::Consumed | A::ExpiredObserved | A::ConflictedObserved
                ) {
                    next.recovery_required = true;
                }
                next.progress = ProgressState::ObservingSettlement;
            }
            ChainStatus::NotSubmitted => {
                return Err(CoreError::new(
                    ErrorCode::InvalidTransition,
                    "not-submitted status cannot clear released exposure",
                ));
            }
        }
        if matches!(
            self.authorization_exposure,
            A::Consumed | A::ExpiredObserved | A::ConflictedObserved
        ) && self.authorization_exposure != next.authorization_exposure
        {
            next.authorization_exposure = A::OutstandingUncertain;
            next.recovery_required = true;
        }
        next.chain_status = observation.status;
        next.latest_observation = Some(observation);
        Ok(next)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionExposure {
    pub proposal_id: String,
    pub obligation_id: String,
    pub maximum_net_debit: Amount,
    pub exposure: AuthorizationExposure,
    pub input_ids: Vec<String>,
}

/// A local record is not proof of resolution. This result is only a conservative
/// bookkeeping gate; a qualified signer must establish current authoritative
/// history and chain evidence independently before any replacement is approved.
pub fn check_replacement(
    obligation_id: &str,
    history: &[RevisionExposure],
    recovery_required: bool,
) -> Result<()> {
    validate_id(obligation_id, "obligation ID")?;
    if recovery_required {
        return Err(CoreError::new(
            ErrorCode::RecoveryRequired,
            "reconcile writer authority and complete authorization history before replacement",
        ));
    }
    let mut proposals = BTreeSet::new();
    for revision in history {
        validate_id(&revision.proposal_id, "historical proposal ID")?;
        if revision.obligation_id != obligation_id || !proposals.insert(&revision.proposal_id) {
            return Err(CoreError::new(
                ErrorCode::RevisionConflict,
                "historical proposal must be unique and belong to the same obligation",
            ));
        }
        if revision.exposure == AuthorizationExposure::Consumed {
            return Err(CoreError::new(
                ErrorCode::OutstandingExposure,
                "the obligation already has a consumed settlement; a replacement could duplicate payment",
            ));
        }
        if revision.exposure.retains_unresolved_exposure() {
            return Err(CoreError::new(
                ErrorCode::OutstandingExposure,
                "a historical revision retains exposure; conflict or expiry observations do not permit replacement",
            ));
        }
    }
    Ok(())
}

/// Counts every unresolved local/released authorization, including reversible
/// conflict and expiry observations. Shared inputs never net their debit.
/// Consumed debits belong to a separate settled/lifetime ledger, not free budget.
pub fn outstanding_exposure(history: &[RevisionExposure]) -> Result<Amount> {
    let mut ids = BTreeSet::new();
    for revision in history {
        validate_id(&revision.proposal_id, "proposal ID")?;
        if !ids.insert(&revision.proposal_id) {
            return Err(CoreError::new(
                ErrorCode::DuplicateIdentifier,
                "duplicate proposal in exposure ledger",
            ));
        }
    }
    Ok(Amount::checked_sum(
        history
            .iter()
            .filter(|r| r.exposure.retains_unresolved_exposure())
            .map(|r| r.maximum_net_debit),
    )?)
}
