//! An INERT reference model of financial-review observations, NOT an authority.
//!
//! Every public value is caller-supplied descriptive data or an observation. None
//! authenticates a peer, proves focus, issues a permission, or executes an effect.
//! In particular, `FinalAdmissionObserved` is a trace fact, NOT a usable permit.
//! There are no live-crate dependencies, permission traits, authority conversions,
//! effect callbacks, IPC, GUI, credentials, clocks, random sources, or persistence.
//!
//! One trace fixes one original session/review scope and its original absolute
//! bounds. Events represent a single coordinator's processed total order, not the
//! physical time a GUI blurred. Human review only arms the finite action plan.
//! Preparation only describes one exact next effect. Final admission consumes its
//! exact challenge once. Admission before observed revocation may leave THAT
//! effect in flight; revocation blocks every subsequent admission. Historical
//! start/outcome observations can finish that record without granting more work.
//!
//! A production adapter must independently authenticate actual process/channel/
//! source bindings, derive prepared payloads from reviewed originals, serialize
//! the focus/revocation/admission boundary, apply the original deadlines, and
//! preserve durable crash fences. This model implements none of those adapters.
//! Reconstructing a new trace cannot establish freshness or reconcile a journal.
//! See README.md for source mapping and deliberately excluded production claims.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

macro_rules! descriptor_id {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $name(pub [u8; 32]);
    };
}

descriptor_id!(PrincipalId, "An inert principal label, never an authenticated principal.");
descriptor_id!(AccountId, "An inert account label, distinct from a principal.");
descriptor_id!(InstanceId, "An inert process, worker, channel, or coordinator instance label.");
descriptor_id!(ReviewId, "An inert review label, not a review capability.");
descriptor_id!(ActionId, "An inert exact action-instance label.");
descriptor_id!(SourceId, "An inert exact original source label.");
descriptor_id!(EffectId, "An inert exact subeffect label, not executable authority.");
descriptor_id!(ChallengeId, "A one-use challenge label in this trace; no randomness is generated.");
descriptor_id!(BindingDescriptor, "An opaque asserted binding, not a verified hash or proof.");

/// A caller-described original session epoch. The model cannot prove freshness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionEpoch(pub u64);

/// A caller-described review epoch. A trace never renews or replaces it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReviewEpoch(pub u64);

/// The original pair has two distinct owner positions, never a wildcard owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerSlot {
    /// First original owner.
    First,
    /// Second original owner.
    Second,
}

/// A descriptive independently reviewed role, not a role credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Original Host.
    Host,
    /// Exact original signer owner.
    Signer(OwnerSlot),
    /// Exact independent Witness owner.
    Witness(OwnerSlot),
}

/// Actual-bound identity fields a future adapter would have to establish itself.
/// Equality here checks only supplied labels and never authenticates them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerBindingDescriptor {
    /// Exact role, including owner position.
    pub role: Role,
    /// Exact principal, separate from the reviewed account.
    pub principal: PrincipalId,
    /// Original process-instance label, not a claimed PID used as authentication.
    pub process_instance: InstanceId,
    /// Original worker-instance label.
    pub worker_instance: InstanceId,
    /// Original authenticated-channel-instance label, asserted but not verified.
    pub channel_instance: InstanceId,
    /// Binding asserted to have come from an actual channel/peer observation.
    pub actual_binding: BindingDescriptor,
}

/// Original source families stay distinct; neither is read by this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceKind {
    /// A pinned path-backed original.
    PathBacked,
    /// A pinned canonical original.
    Canonical,
}

/// Original source labels are fixed throughout this trace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceDescriptor {
    /// Source family, never interchangeable by admission.
    pub kind: SourceKind,
    /// Exact source identity.
    pub identity: SourceId,
    /// Asserted original-source pin; the model performs no file or journal read.
    pub original_pin: BindingDescriptor,
}

/// Finite original action categories, not broad workflow permissions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionKind {
    /// Retain one original signer continuation intent.
    ContinueExact,
    /// Send one already retained continuation request to its Witness.
    AdmitExact,
    /// One checked original acquisition RPC/mutation; never renew its source.
    AcquireExact,
    /// One checked original activation RPC/mutation; never renew its session.
    ActivateExact,
    /// Seven separately admitted signer subeffect obligations.
    SignExact,
    /// One independently reviewed Witness append obligation.
    WitnessAppendExact,
    /// One exact payload disclosure; never Host intake authority.
    ReturnExact,
    /// One separately reviewed original Host intake obligation.
    HostIntakeExact,
    /// Five separately admitted original Host completion obligations.
    HostCompleteExact,
    /// Eight separately admitted original dispatch obligations, with one send.
    HostDispatchExact,
}

/// A finite source-grounded subeffect obligation. These abstractions do NOT claim
/// current live functions are atomic, fully decomposed, or already gated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectKind {
    /// Original continuation-intent retention.
    RetainContinuationIntent,
    /// Original retained continuation-request send.
    SendRetainedContinuationRequest,
    /// Original checked acquisition.
    AcquireOriginal,
    /// Original checked activation.
    ActivateOriginal,
    /// Exact consent-release retention.
    RecordConsentRelease,
    /// Exact signer request retention.
    RetainExactRequest,
    /// Exact Reserve request send.
    ReserveRequestSend,
    /// Matching authenticated-permit retention.
    RetainAuthenticatedPermit,
    /// Exact Started fence retention; NOT key-use authority.
    CommitStarted,
    /// Exact participant-action key-use batch, bounded to eight in this model.
    KeyUseExactBatch,
    /// Exact signer result retention; NOT cancel-exempt cleanup.
    RetainExactResult,
    /// Exact Witness append commit.
    AppendExactCommit,
    /// Exact bounded return-payload disclosure on the retained original stream.
    DiscloseExactReturnPayload,
    /// Separately reviewed original signer-result Host intake.
    CommitOriginalResultIntake,
    /// Exact original union payload retention.
    RetainExactUnionPayload,
    /// Separate exact original union lineage retention.
    RetainExactUnionLineage,
    /// Recovery-significant original extraction-intent fence.
    CommitExtractionIntent,
    /// Exact original extraction.
    ExtractExactTransaction,
    /// Exact completed-transaction retention.
    RetainCompletedTransaction,
    /// Exact dispatch pair-intent retention.
    RetainPairIntent,
    /// Actual first Witness admission request.
    Owner0AdmissionRequest,
    /// Matching first Witness receipt retention.
    Owner0ReceiptRetention,
    /// Actual second Witness admission request.
    Owner1AdmissionRequest,
    /// Matching second Witness receipt retention.
    Owner1ReceiptRetention,
    /// Exact saved-transaction-byte handoff.
    SavedTransactionHandoff,
    /// Exact original attempt fence retention.
    AttemptRetention,
    /// One exact final transaction request send, never an implicit retry.
    FinalTransactionSend,
}

/// Maximum subeffect obligations in any supported finite plan.
pub const MAX_PLAN_EFFECTS: usize = 8;
/// Maximum participant actions in a single exact key-use batch.
pub const MAX_KEY_USE_BATCH: u8 = 8;

impl ActionKind {
    /// The fixed finite obligation order; not a returned executable plan.
    pub fn effect_order(self) -> &'static [EffectKind] {
        use EffectKind::*;
        match self {
            Self::ContinueExact => &[RetainContinuationIntent],
            Self::AdmitExact => &[SendRetainedContinuationRequest],
            Self::AcquireExact => &[AcquireOriginal],
            Self::ActivateExact => &[ActivateOriginal],
            Self::SignExact => &[
                RecordConsentRelease, RetainExactRequest, ReserveRequestSend,
                RetainAuthenticatedPermit, CommitStarted, KeyUseExactBatch,
                RetainExactResult,
            ],
            Self::WitnessAppendExact => &[AppendExactCommit],
            Self::ReturnExact => &[DiscloseExactReturnPayload],
            Self::HostIntakeExact => &[CommitOriginalResultIntake],
            Self::HostCompleteExact => &[
                RetainExactUnionPayload, RetainExactUnionLineage,
                CommitExtractionIntent, ExtractExactTransaction,
                RetainCompletedTransaction,
            ],
            Self::HostDispatchExact => &[
                RetainPairIntent, Owner0AdmissionRequest, Owner0ReceiptRetention,
                Owner1AdmissionRequest, Owner1ReceiptRetention,
                SavedTransactionHandoff, AttemptRetention, FinalTransactionSend,
            ],
        }
    }

    fn matches_role(self, role: Role) -> bool {
        match self {
            Self::ContinueExact | Self::AdmitExact | Self::AcquireExact
            | Self::ActivateExact | Self::SignExact | Self::ReturnExact => {
                matches!(role, Role::Signer(_))
            }
            Self::WitnessAppendExact => matches!(role, Role::Witness(_)),
            Self::HostIntakeExact | Self::HostCompleteExact | Self::HostDispatchExact => {
                role == Role::Host
            }
        }
    }
}

/// Immutable initial reviewed scope. Future payload/result bindings do not have
/// to exist at human-review time: they are separate preparation observations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewScopeDescriptor {
    /// Original coordinator instance, never restored by this model.
    pub coordinator_instance: InstanceId,
    /// Original session epoch.
    pub session_epoch: SessionEpoch,
    /// Original review epoch.
    pub review_epoch: ReviewEpoch,
    /// Exact review identifier.
    pub review_id: ReviewId,
    /// Exact reviewed action identifier.
    pub action_id: ActionId,
    /// Fixed finite action category.
    pub action: ActionKind,
    /// Original reviewed account, independent of the acting principal.
    pub account: AccountId,
    /// Original shared physical coordinator-window label, NOT a role panel.
    /// All members of a SessionTrace must use this same label. It proves no GUI/focus.
    pub review_surface_instance: InstanceId,
    /// Original actual-bound peer descriptor, never authenticated here.
    pub peer: PeerBindingDescriptor,
    /// Original pinned source descriptor.
    pub source: SourceDescriptor,
    /// Exact original review/request anchor, not a future result digest.
    pub reviewed_binding: BindingDescriptor,
    /// Exact reviewed key-use batch width for SignExact; zero for other actions.
    pub reviewed_key_use_batch: u8,
}

/// Externally supplied absolute time readings. This crate never reads a clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeObservation {
    /// Original wall-clock domain, in milliseconds.
    pub wall_ms: u64,
    /// Original monotonic-clock domain, in milliseconds.
    pub monotonic_ms: u64,
}

/// Original absolute bounds, supplied once and never extended or recalculated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OriginalBounds {
    issued: TimeObservation,
    expires: TimeObservation,
}

impl OriginalBounds {
    /// Record existing absolute bounds. No duration arithmetic, clock I/O, or
    /// policy for choosing a new expiry is introduced.
    pub fn from_absolute(
        issued: TimeObservation,
        expires: TimeObservation,
    ) -> Result<Self, Rejection> {
        if expires.wall_ms <= issued.wall_ms
            || expires.monotonic_ms <= issued.monotonic_ms
        {
            return Err(Rejection::InvalidOriginalBounds);
        }
        Ok(Self { issued, expires })
    }

    /// Original issuance readings, unchanged.
    pub fn issued(self) -> TimeObservation { self.issued }

    /// Original exclusive expiry readings, unchanged.
    pub fn expires(self) -> TimeObservation { self.expires }
}

/// Later exact prepared-effect data, not a cryptographic proof or a permit.
/// The backend's derivation from the review and predecessor is only represented
/// by equality of asserted anchors here; actual verification is deferred.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedEffectDescriptor {
    /// Exact expected next obligation, never a broad action category.
    pub kind: EffectKind,
    /// Unique effect identifier within this trace.
    pub effect_id: EffectId,
    /// Unique, single-admission challenge within this trace.
    pub challenge: ChallengeId,
    /// Exact dynamic payload/request/result binding asserted at preparation.
    pub payload_binding: BindingDescriptor,
    /// Must equal the immutable initial reviewed binding.
    pub reviewed_binding: BindingDescriptor,
    /// Must name the immediately preceding completed effect, or None initially.
    pub predecessor: Option<EffectId>,
    /// One for non-key-use effects; exact reviewed width for key use.
    pub batch_width: u8,
}

/// Full original scope and coordinator processing order for one observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventHeader {
    /// Exact original scope; equality is NOT authentication.
    pub scope: ReviewScopeDescriptor,
    /// Strict contiguous coordinator sequence, beginning at one.
    pub sequence: u64,
    /// Supplied absolute readings, checked without renewing original bounds.
    pub observed_at: TimeObservation,
}

/// Explicit outcomes never imply another attempt, reissue, or fresh authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectOutcome {
    /// Exact effect was observed to complete; does not prove current focus.
    Completed,
    /// Exact admitted effect is known not to have happened. Still no replay.
    KnownNoEffect,
    /// It may have happened. No implicit retry or in-model reconciliation.
    Unknown,
}

/// Narrow source-grounded drain observations, NOT new mutation permissions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrainKind {
    /// Exact matching committed Witness response after a known append commit.
    WitnessCommittedReceiptCompletion,
    /// Conservative outcome bookkeeping of the exact already admitted send.
    DispatchOutcomeRecord,
}

/// Input observations. No variant executes, signs, sends, writes, or authorizes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Observation {
    /// One entire focus batch. Any loss in it wins over ending focused. The
    /// complete batch must be processed before its queued admission observations;
    /// this model cannot detect omitted or misordered native-event delivery.
    FocusBatch {
        /// Focus at the end of the batch.
        focused_at_end: bool,
        /// Includes any blur/close in the same batch, even before a refocus.
        loss_observed_in_batch: bool,
    },
    /// Exact initial human review only arms; never final effect admission.
    InitialHumanReviewed,
    /// Prepare one exact next effect; does not admit or start it.
    PrepareEffect(PreparedEffectDescriptor),
    /// Coordinator processed final admission of exactly the prepared descriptor.
    FinalAdmit(PreparedEffectDescriptor),
    /// Historical report that the one already admitted effect started. This is
    /// NOT a worker command, permission, or promise that revocation recalled it.
    WorkerStartedObservation(PreparedEffectDescriptor),
    /// Historical result for the one exact admitted effect, including after blur.
    OutcomeObserved {
        /// Must match the entire admitted prepared descriptor.
        effect: PreparedEffectDescriptor,
        /// Terminal outcome of that subeffect.
        outcome: EffectOutcome,
    },
    /// Exact non-authorizing completion bookkeeping, not another effect grant.
    DrainObserved {
        /// Must match the entire originally admitted descriptor.
        effect: PreparedEffectDescriptor,
        /// Only one of the narrowly mapped source-grounded drain categories.
        kind: DrainKind,
        /// Asserted exact outcome/receipt binding; not authenticated here.
        evidence_binding: BindingDescriptor,
    },
    /// Explicit user cancellation.
    Cancel,
    /// Review window closed.
    Close,
    /// Original peer/channel disconnected or died; admitted effects become unknown.
    PeerLost,
    /// A restart never revives this original scope, even with identical labels.
    PeerRestarted,
    /// Observe supplied time without inventing a timer or extending a lease.
    CheckOriginalBounds,
}

/// One serial coordinator observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    /// Original scope, total order, and supplied time.
    pub header: EventHeader,
    /// Inert observation.
    pub observation: Observation,
}

/// First irreversible invalidation observed in a trace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Invalidation {
    /// Processed blur, including blur and refocus in one batch.
    FocusLost,
    /// Processed explicit cancellation.
    Cancelled,
    /// Processed review-window close.
    Closed,
    /// Original peer/channel died or disconnected.
    PeerLost,
    /// Original peer restarted; no reconnect/rearm route exists.
    PeerRestarted,
    /// Either original absolute bound reached, including equality.
    Expired,
    /// Either supplied clock moved backwards, including before original issuance.
    ClockRollback,
    /// Event order was replayed, skipped, reordered, or exhausted.
    EventOrder,
    /// Caller-provided scope/effect data failed an exact identity check.
    BindingMismatch,
    /// One member reported an unknown outcome; the fixed session is quarantined.
    UnknownOutcome,
    /// One member reported known no effect; no dependent session step may follow.
    KnownNoEffect,
    /// The fixed session observed a wrong-phase or otherwise invalid message.
    UnexpectedObservation,
}

/// Observable progress for one exact effect, not executable capability state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectProgress {
    /// Prepared only; no final admission has been observed.
    Prepared,
    /// Final admission observed once; execution remains unproven.
    Admitted,
    /// Historical start observed once; completion remains unproven.
    InFlight,
    /// Exact outcome observed. No replay/reissue even for KnownNoEffect.
    Outcome(EffectOutcome),
}

/// Immutable externally visible copy of a bounded effect record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectRecordObservation {
    /// Exact prepared descriptor, never an executable ticket.
    pub descriptor: PreparedEffectDescriptor,
    /// Observed progress, never an actual permission trait.
    pub progress: EffectProgress,
    /// Optional exact non-authorizing completion bookkeeping observation.
    pub drain: Option<(DrainKind, BindingDescriptor)>,
}

/// Review status is descriptive only; even Armed and Admitted confer no power.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReviewStatus {
    /// No original focus observation yet.
    AwaitingFocus,
    /// Focus observed, awaiting the exact initial human review.
    AwaitingHumanReview,
    /// Initial human review observed; a next exact effect still needs admission.
    Armed,
    /// One next effect prepared but not admitted.
    Prepared,
    /// One exact effect admitted or started, with no known outcome yet.
    AwaitingOutcome,
    /// All finite plan effects completed; no extension or next action exists.
    Completed,
    /// A known-no-effect result ended this trace; not retry permission.
    KnownNoEffect,
    /// An unknown outcome ended this trace; no implicit reconciliation/retry.
    Unknown,
    /// Original review is permanently invalidated; an admitted record may drain.
    Invalidated(Invalidation),
}

/// Observable acceptance result, explicitly NOT a capability or dispatch token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationReceipt {
    /// Focus batch recorded.
    FocusObserved,
    /// Initial review recorded, with no admitted effect.
    HumanReviewObserved,
    /// Exact next effect prepared, with no admitted effect.
    PreparationObserved,
    /// One exact final admission recorded; no execution is performed.
    FinalAdmissionObserved,
    /// Historical start recorded for an already admitted effect.
    StartObserved,
    /// Historical exact outcome recorded.
    OutcomeObserved,
    /// Narrow non-authorizing completion bookkeeping recorded.
    DrainObserved,
    /// Invalidation recorded; no rearm or renewal follows.
    InvalidationObserved,
    /// Original bounds remain current at the supplied observation.
    BoundsObserved,
}

/// Fail-closed rejection of an observation, never a fallback authority route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejection {
    /// Original absolute expiry is not strictly after issuance.
    InvalidOriginalBounds,
    /// Action category does not match the independently reviewed role.
    WrongRole,
    /// Reviewed key batch is absent, too large, or supplied for a non-sign action.
    InvalidBatchWidth,
    /// Any original scope component differs.
    ScopeMismatch,
    /// Contiguous event sequence was replayed, reordered, skipped, or exhausted.
    EventOrder,
    /// Original trace was irreversibly invalidated.
    Invalidated(Invalidation),
    /// Effect/order/challenge/payload/anchor/predecessor differs from the exact next one.
    EffectMismatch,
    /// Effect identifier or challenge was already used in this trace.
    ReusedEffectOrChallenge,
    /// Correct data at an invalid phase, including duplicate review/admit/outcome.
    WrongPhase,
    /// Unsupported/generalized cleanup, or a duplicate exact drain observation.
    InvalidDrain,
}

/// A bounded, single-session inert trace. It has no reset, reconnect, renewal,
/// effect-execution, serialization, authority conversion, or persistence API.
#[derive(Debug)]
pub struct ReviewTrace {
    scope: ReviewScopeDescriptor,
    bounds: OriginalBounds,
    last_time: TimeObservation,
    last_sequence: u64,
    focused: bool,
    human_reviewed: bool,
    invalidation: Option<Invalidation>,
    records: Vec<EffectRecordObservation>,
}

impl ReviewTrace {
    /// Create one inert trace of a caller-described original scope. This does
    /// not establish a real session or authenticate any descriptor.
    pub fn new(scope: ReviewScopeDescriptor, bounds: OriginalBounds) -> Result<Self, Rejection> {
        if !scope.action.matches_role(scope.peer.role) {
            return Err(Rejection::WrongRole);
        }
        if (scope.action == ActionKind::SignExact
            && !(1..=MAX_KEY_USE_BATCH).contains(&scope.reviewed_key_use_batch))
            || (scope.action != ActionKind::SignExact && scope.reviewed_key_use_batch != 0)
        {
            return Err(Rejection::InvalidBatchWidth);
        }
        Ok(Self {
            scope, bounds, last_time: bounds.issued(), last_sequence: 0,
            focused: false, human_reviewed: false, invalidation: None,
            records: Vec::with_capacity(MAX_PLAN_EFFECTS),
        })
    }

    /// Original scope, immutable for this trace.
    pub fn scope(&self) -> &ReviewScopeDescriptor { &self.scope }

    /// Original absolute bounds, immutable for this trace.
    pub fn original_bounds(&self) -> OriginalBounds { self.bounds }

    /// Last accepted coordinator sequence, for inspection only.
    pub fn last_sequence(&self) -> u64 { self.last_sequence }

    /// Bounded observation records, never executable tickets.
    pub fn records(&self) -> &[EffectRecordObservation] { &self.records }

    /// Current descriptive status. Invalidation never disappears on refocus.
    pub fn status(&self) -> ReviewStatus {
        if let Some(reason) = self.invalidation {
            return ReviewStatus::Invalidated(reason);
        }
        match self.records.last().map(|record| record.progress) {
            Some(EffectProgress::Prepared) => return ReviewStatus::Prepared,
            Some(EffectProgress::Admitted | EffectProgress::InFlight) => {
                return ReviewStatus::AwaitingOutcome;
            }
            Some(EffectProgress::Outcome(EffectOutcome::KnownNoEffect)) => {
                return ReviewStatus::KnownNoEffect;
            }
            Some(EffectProgress::Outcome(EffectOutcome::Unknown)) => return ReviewStatus::Unknown,
            Some(EffectProgress::Outcome(EffectOutcome::Completed))
                if self.records.len() == self.scope.action.effect_order().len() => {
                    return ReviewStatus::Completed;
                }
            _ => {}
        }
        if self.human_reviewed { ReviewStatus::Armed }
        else if self.focused { ReviewStatus::AwaitingHumanReview }
        else { ReviewStatus::AwaitingFocus }
    }

    /// Process one observation in exact coordinator order. A successful return
    /// records data only and must never be used as real effect authorization.
    pub fn observe(&mut self, event: Event) -> Result<ObservationReceipt, Rejection> {
        if event.header.scope != self.scope {
            self.invalidate(Invalidation::BindingMismatch);
            return Err(Rejection::ScopeMismatch);
        }
        if self.last_sequence.checked_add(1) != Some(event.header.sequence) {
            self.invalidate(Invalidation::EventOrder);
            return Err(Rejection::EventOrder);
        }
        self.last_sequence = event.header.sequence;
        self.observe_time(event.header.observed_at);

        match event.observation {
            Observation::Cancel => self.record_invalidation(Invalidation::Cancelled),
            Observation::Close => self.record_invalidation(Invalidation::Closed),
            Observation::PeerLost => self.record_peer_loss(Invalidation::PeerLost),
            Observation::PeerRestarted => self.record_peer_loss(Invalidation::PeerRestarted),
            Observation::FocusBatch { focused_at_end, loss_observed_in_batch } => {
                if !focused_at_end || loss_observed_in_batch {
                    self.focused = false;
                    return self.record_invalidation(Invalidation::FocusLost);
                }
                self.require_current()?;
                self.focused = true;
                Ok(ObservationReceipt::FocusObserved)
            }
            Observation::CheckOriginalBounds => {
                self.require_current()?;
                Ok(ObservationReceipt::BoundsObserved)
            }
            Observation::InitialHumanReviewed => {
                self.require_current()?;
                if self.status() != ReviewStatus::AwaitingHumanReview {
                    return Err(Rejection::WrongPhase);
                }
                self.human_reviewed = true;
                Ok(ObservationReceipt::HumanReviewObserved)
            }
            Observation::PrepareEffect(effect) => self.prepare(effect),
            Observation::FinalAdmit(effect) => {
                self.require_current()?;
                self.require_matching_effect(&effect)?;
                let record = self.records.last_mut().ok_or(Rejection::WrongPhase)?;
                if record.progress != EffectProgress::Prepared {
                    return Err(Rejection::WrongPhase);
                }
                record.progress = EffectProgress::Admitted;
                Ok(ObservationReceipt::FinalAdmissionObserved)
            }
            Observation::WorkerStartedObservation(effect) => {
                // Historical report only: admission-before-blur is not recalled.
                self.require_matching_effect(&effect)?;
                let record = self.records.last_mut().ok_or(Rejection::WrongPhase)?;
                if record.progress != EffectProgress::Admitted {
                    return Err(Rejection::WrongPhase);
                }
                record.progress = EffectProgress::InFlight;
                Ok(ObservationReceipt::StartObserved)
            }
            Observation::OutcomeObserved { effect, outcome } => {
                // No admission/currentness is granted by recording an outcome.
                self.require_matching_effect(&effect)?;
                let record = self.records.last_mut().ok_or(Rejection::WrongPhase)?;
                if !matches!(record.progress, EffectProgress::Admitted | EffectProgress::InFlight) {
                    return Err(Rejection::WrongPhase);
                }
                record.progress = EffectProgress::Outcome(outcome);
                Ok(ObservationReceipt::OutcomeObserved)
            }
            Observation::DrainObserved { effect, kind, evidence_binding } => {
                self.require_matching_effect(&effect)?;
                let record = self.records.last_mut().ok_or(Rejection::InvalidDrain)?;
                let allowed = match (kind, effect.kind, record.progress) {
                    (DrainKind::WitnessCommittedReceiptCompletion, EffectKind::AppendExactCommit,
                        EffectProgress::Outcome(EffectOutcome::Completed)) => true,
                    (DrainKind::DispatchOutcomeRecord, EffectKind::FinalTransactionSend,
                        EffectProgress::Outcome(_)) => true,
                    _ => false,
                };
                if !allowed || record.drain.is_some() {
                    return Err(Rejection::InvalidDrain);
                }
                record.drain = Some((kind, evidence_binding));
                Ok(ObservationReceipt::DrainObserved)
            }
        }
    }

    fn prepare(&mut self, effect: PreparedEffectDescriptor) -> Result<ObservationReceipt, Rejection> {
        self.require_current()?;
        if self.status() != ReviewStatus::Armed {
            return Err(Rejection::WrongPhase);
        }
        let expected = self.scope.action.effect_order().get(self.records.len()).copied();
        let predecessor = self.records.last().map(|record| record.descriptor.effect_id);
        let batch_width = if effect.kind == EffectKind::KeyUseExactBatch {
            self.scope.reviewed_key_use_batch
        } else { 1 };
        if expected != Some(effect.kind) || effect.reviewed_binding != self.scope.reviewed_binding
            || effect.predecessor != predecessor || effect.batch_width != batch_width
        {
            self.invalidate(Invalidation::BindingMismatch);
            return Err(Rejection::EffectMismatch);
        }
        if self.records.iter().any(|record| record.descriptor.effect_id == effect.effect_id
            || record.descriptor.challenge == effect.challenge)
        {
            self.invalidate(Invalidation::BindingMismatch);
            return Err(Rejection::ReusedEffectOrChallenge);
        }
        self.records.push(EffectRecordObservation {
            descriptor: effect, progress: EffectProgress::Prepared, drain: None,
        });
        Ok(ObservationReceipt::PreparationObserved)
    }

    fn require_matching_effect(&mut self, effect: &PreparedEffectDescriptor) -> Result<(), Rejection> {
        match self.records.last() {
            Some(record) if &record.descriptor == effect => Ok(()),
            Some(_) => {
                self.invalidate(Invalidation::BindingMismatch);
                Err(Rejection::EffectMismatch)
            }
            None => Err(Rejection::WrongPhase),
        }
    }

    fn observe_time(&mut self, time: TimeObservation) {
        if time.wall_ms < self.last_time.wall_ms || time.monotonic_ms < self.last_time.monotonic_ms {
            self.invalidate(Invalidation::ClockRollback);
        }
        if time.wall_ms >= self.bounds.expires.wall_ms
            || time.monotonic_ms >= self.bounds.expires.monotonic_ms
        {
            self.invalidate(Invalidation::Expired);
        }
        // Retain high-water marks even after a rollback; never move a clock back.
        self.last_time.wall_ms = self.last_time.wall_ms.max(time.wall_ms);
        self.last_time.monotonic_ms = self.last_time.monotonic_ms.max(time.monotonic_ms);
    }

    fn require_current(&self) -> Result<(), Rejection> {
        match self.invalidation {
            Some(reason) => Err(Rejection::Invalidated(reason)),
            None => Ok(()),
        }
    }

    fn invalidate(&mut self, reason: Invalidation) {
        if self.invalidation.is_none() { self.invalidation = Some(reason); }
    }

    fn record_invalidation(&mut self, reason: Invalidation) -> Result<ObservationReceipt, Rejection> {
        self.invalidate(reason);
        Ok(ObservationReceipt::InvalidationObserved)
    }

    fn record_peer_loss(&mut self, reason: Invalidation) -> Result<ObservationReceipt, Rejection> {
        self.invalidate(reason);
        if let Some(record) = self.records.last_mut() {
            if matches!(record.progress, EffectProgress::Admitted | EffectProgress::InFlight) {
                // A lost original peer cannot establish completion/no effect.
                record.progress = EffectProgress::Outcome(EffectOutcome::Unknown);
            }
        }
        Ok(ObservationReceipt::InvalidationObserved)
    }
}

#[cfg(test)]
mod tests;

mod session;
pub use session::{SessionTrace, MAX_SESSION_REVIEWS};
