//! Inert composition solely to express session-wide observed revocation order.
use super::*;

/// The original Host, two signers, and two independent Witness roles. A model
/// session has at most one fixed action/review per role, not an extensible workflow.
pub const MAX_SESSION_REVIEWS: usize = 5;

/// A fixed group of independent role reviews sharing one observed session order.
/// This is NOT a scheduler, IPC server, focus observer, or executable coordinator.
/// No member can be added/replaced after construction. A new process/session may
/// not revive a member. A fresh object alone cannot prove durable freshness.
/// This is one fixed review/action per role, NOT a model of the entire multi-action
/// lifecycle or cross-action financial causality. Account/source relationships
/// between members require a separate production proof; their labels stay fixed.
/// Different owner-slot labels do NOT prove different real people/accounts, nor
/// do matching signer/Witness slot labels prove a matching real account.
#[derive(Debug)]
pub struct SessionTrace {
    reviews: Vec<ReviewTrace>,
    last_sequence: u64,
    invalidation: Option<Invalidation>,
}

impl SessionTrace {
    /// Group fresh inert traces of distinct original roles in the same session.
    /// Every review still needs its own exact human review and final admissions.
    pub fn new(reviews: Vec<ReviewTrace>) -> Result<Self, Rejection> {
        if reviews.is_empty() || reviews.len() > MAX_SESSION_REVIEWS {
            return Err(Rejection::WrongPhase);
        }
        let original = reviews[0].scope();
        for (index, review) in reviews.iter().enumerate() {
            if review.last_sequence != 0 || !review.records.is_empty()
                || review.invalidation.is_some() || review.human_reviewed
                || review.scope.coordinator_instance != original.coordinator_instance
                || review.scope.session_epoch != original.session_epoch
                || review.scope.review_surface_instance != original.review_surface_instance
                || reviews[..index].iter().any(|prior| {
                    prior.scope.peer.role == review.scope.peer.role
                        || prior.scope.review_id == review.scope.review_id
                        || prior.scope.action_id == review.scope.action_id
                })
            {
                return Err(Rejection::ScopeMismatch);
            }
        }
        Ok(Self { reviews, last_sequence: 0, invalidation: None })
    }

    /// Fixed member observations only; cannot register a new role or action.
    pub fn reviews(&self) -> &[ReviewTrace] { &self.reviews }

    /// Last accepted session-wide sequence. Member counters are internal local
    /// observation counters, not a second source of session ordering authority.
    pub fn last_sequence(&self) -> u64 { self.last_sequence }

    /// First session-wide invalidation, never cleared by refocus or another role.
    pub fn invalidation(&self) -> Option<Invalidation> { self.invalidation }

    /// Record one globally ordered role observation. All members see processed
    /// blur/cancel/close/peer loss/restart BEFORE any new admission. Any original
    /// deadline expiry or clock rollback also closes the entire group. This is
    /// a conservative MODEL composition policy, not a new production expiry rule.
    /// Each original absolute bound remains unchanged. This
    /// sequential model does not prove a concurrent implementation is linearizable.
    /// The caller must deliver each complete FocusBatch before same-batch queued
    /// admissions. This API cannot detect omitted/misordered native event batches.
    pub fn observe(&mut self, mut event: Event) -> Result<ObservationReceipt, Rejection> {
        if self.last_sequence.checked_add(1) != Some(event.header.sequence) {
            self.invalidate_all(Invalidation::EventOrder, false);
            return Err(Rejection::EventOrder);
        }
        let index = match self.reviews.iter().position(|review| review.scope == event.header.scope) {
            Some(index) => index,
            None => {
                self.invalidate_all(Invalidation::BindingMismatch, false);
                return Err(Rejection::ScopeMismatch);
            }
        };
        self.last_sequence = event.header.sequence;

        // Every member observes the same supplied time; there are no actual clocks.
        for review in &mut self.reviews { review.observe_time(event.header.observed_at); }
        if let Some(reason) = self.reviews.iter().find_map(|review| review.invalidation) {
            self.invalidate_all(reason, false);
        }
        let revoke = match &event.observation {
            Observation::FocusBatch { focused_at_end, loss_observed_in_batch }
                if !*focused_at_end || *loss_observed_in_batch => Some((Invalidation::FocusLost, false)),
            Observation::Cancel => Some((Invalidation::Cancelled, false)),
            Observation::Close => Some((Invalidation::Closed, false)),
            Observation::PeerLost => Some((Invalidation::PeerLost, true)),
            Observation::PeerRestarted => Some((Invalidation::PeerRestarted, true)),
            _ => None,
        };
        if let Some((reason, uncertain)) = revoke { self.invalidate_all(reason, uncertain); }

        if let Observation::PrepareEffect(effect) = &event.observation {
            if self.reviews.iter().any(|review| review.records.iter().any(|record| {
                record.descriptor.effect_id == effect.effect_id
                    || record.descriptor.challenge == effect.challenge
            })) {
                self.invalidate_all(Invalidation::BindingMismatch, false);
                return Err(Rejection::ReusedEffectOrChallenge);
            }
        }

        // The session owns the global sequence; members only count routed events.
        // No member is publicly mutable, so callers cannot bypass session ordering.
        event.header.sequence = match self.reviews[index].last_sequence.checked_add(1) {
            Some(sequence) => sequence,
            None => {
                self.invalidate_all(Invalidation::EventOrder, false);
                return Err(Rejection::EventOrder);
            }
        };
        let result = self.reviews[index].observe(event);
        if let Some(reason) = self.reviews[index].invalidation {
            self.invalidate_all(reason, false);
        }
        // A failed exact member must not leave another role free to proceed with
        // an incomplete original pair. This conservative fixed-group quarantine
        // is not a proof of full cross-action financial workflow causality.
        match self.reviews[index].records.last().map(|record| record.progress) {
            Some(EffectProgress::Outcome(EffectOutcome::Unknown)) => {
                self.invalidate_all(Invalidation::UnknownOutcome, false);
            }
            Some(EffectProgress::Outcome(EffectOutcome::KnownNoEffect)) => {
                self.invalidate_all(Invalidation::KnownNoEffect, false);
            }
            _ => {}
        }
        if result.is_err() { self.invalidate_all(Invalidation::UnexpectedObservation, false); }
        result
    }

    fn invalidate_all(&mut self, reason: Invalidation, uncertain: bool) {
        if self.invalidation.is_none() { self.invalidation = Some(reason); }
        for review in &mut self.reviews {
            if uncertain {
                // Conservative session quarantine: disconnected originals cannot
                // establish a known execution outcome for any in-flight member.
                let _ = review.record_peer_loss(reason);
            } else {
                review.invalidate(reason);
            }
        }
    }
}
