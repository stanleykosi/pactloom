//! One financial-continuation actual-source adapter. The sole positive entry consumes
//! genuine fixed-fork role custody; data validation does not create consent.
//! Cancel-only handles, legacy decisions, booleans and imported FDs never convert.
pub(crate) mod observation;
mod presentation;
mod worker;
use super::lifecycle::ReviewClock;
use crate::{
    durable_financial_continuation_owner_v1::FinancialContinuationProposalV1, policy::Ledger,
    protocol::WireResponse, AccountSnapshot, AuthorityError, AuthorityJournal, OwnerControlRequest,
    Result,
};
pub(crate) use presentation::{source_commitment, ADMISSION_NOTICE};
pub use presentation::{
    validate_financial_witness_inputs, validate_financial_witness_presentation,
};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Instant,
};
pub use wholepact_financial_coordinator_origin::{
    FinancialWitnessInputsV1, FinancialWitnessPresentationV1,
};
use wholepact_financial_coordinator_origin::{
    FinancialWitnessOutcomeV1, FinancialWitnessReadyV1, WitnessFinancialContinuationArmV1,
};
pub use worker::run_witness_financial_continuation_once_v1;

// Concrete token, never inert data or a local fake. The origin crate constructs
// it ONLY on exact authenticated original-channel receive.
pub(crate) use crate::transport::coordinated_financial_continuation_v1::AuthenticatedOriginalOwnerPeerV1;
pub(crate) use wholepact_financial_coordinator_origin::WitnessFinancialContinuationFinalV1 as FinancialContinuationFinalV1;

#[derive(Clone, Copy, PartialEq, Eq)]
enum PhaseV1 {
    Armed,
    Preflight,
    AwaitingGrant,
    AdmittedRevalidating,
    Publishing,
    CommitAttempted,
    Terminal,
}

/// Local single-effect result, not a receipt supplied by C. No terminal state
/// can return to Pending or turn an Uncertain/commit attempt into KnownNoEffect.
enum OutcomeV1 {
    Pending,
    Completed(AccountSnapshot),
    KnownNoEffect(AuthorityError),
    Uncertain,
}
impl OutcomeV1 {
    fn no_effect(&mut self, error: AuthorityError, commit_attempted: bool) {
        if commit_attempted || error == AuthorityError::Uncertain {
            self.uncertain();
            return;
        }
        if matches!(self, Self::Pending) {
            *self = Self::KnownNoEffect(error);
        }
    }
    fn uncertain(&mut self) {
        if matches!(self, Self::Pending) {
            *self = Self::Uncertain;
        }
    }
    fn committed(&mut self, snapshot: AccountSnapshot) -> Result<()> {
        if !matches!(self, Self::Pending) {
            return Err(AuthorityError::Uncertain);
        }
        *self = Self::Completed(snapshot);
        Ok(())
    }
}

/// Both flags are monotone restriction-only observations. The actual original
/// channel monitor owns their writers; no external setter or caller bool exists.
struct RestrictionsV1 {
    revoke_requested: AtomicBool,
    original_coordinator_lost: AtomicBool,
}
impl RestrictionsV1 {
    fn require_connected(&self) -> Result<()> {
        if self.original_coordinator_lost.load(Ordering::Acquire) {
            return Err(AuthorityError::Permission);
        }
        Ok(())
    }
    fn require_unrevoked(&self) -> Result<()> {
        self.require_connected()?;
        if self.revoke_requested.load(Ordering::Acquire) {
            return Err(AuthorityError::Permission);
        }
        Ok(())
    }
}

/// Fields private; only the actual role worker constructs this after consuming
/// its genuine origin arm against the complete original prepared presentation.
/// The proposal remains actual original preparation and is never extracted from
/// CancelOnlyDeliveryReviewV1 or reconstructed from its serialized presentation.
pub(crate) struct CoordinatedFinancialContinuationSourceV1 {
    proposal: FinancialContinuationProposalV1,
    arm: WitnessFinancialContinuationArmV1,
    clock: ReviewClock,
    review_bounds: (u64, u64),
    session_deadline: Instant,
    presentation: FinancialWitnessPresentationV1,
    retained_effect: Option<String>,
    restrictions: Arc<RestrictionsV1>,
    phase: PhaseV1,
    pending_effect: Option<String>,
    outcome: OutcomeV1,
    first_failure: observation::FirstFailureV1,
}
impl CoordinatedFinancialContinuationSourceV1 {
    pub(crate) fn check_original_owner_preflight(
        &self,
        owner: &crate::witness_locator::BornJournalOwner,
    ) -> Result<()> {
        self.check_before_publication()?;
        owner.check_setup_current(
            super::financial_setup_guard_v1::FinancialSetupGuardV1::Arm(&self.arm),
            true,
        )?;
        self.check_before_publication()
    }
    pub(crate) fn physical_io_deadline(&self, accepted: Instant) -> Instant {
        accepted
            .min(self.clock.original_deadline())
            .min(self.session_deadline)
            .min(self.arm.effective_io_deadline())
    }
    pub(crate) fn check_terminal_io(&self) -> Result<()> {
        if matches!(self.outcome, OutcomeV1::Pending) {
            return Err(AuthorityError::Permission);
        }
        self.check_clocks()?;
        self.restrictions.require_connected()?;
        self.arm
            .check_original_coordinator_alive()
            .map_err(|_| AuthorityError::Permission)
    }
    pub(crate) fn journal(&self) -> Arc<AuthorityJournal> {
        self.proposal.coordinated_journal_v1()
    }
    pub(crate) fn original_presentation_digest(&self) -> &str {
        &self.presentation.presentation_digest
    }
    pub(crate) fn original_review_bounds(&self) -> (u64, u64) {
        self.review_bounds
    }
    pub(crate) fn retained_wait_bounds(&self) -> FinancialContinuationWaitBoundsV1 {
        FinancialContinuationWaitBoundsV1 {
            clock: self.clock.clone(),
            session_deadline: self.session_deadline,
            restrictions: self.restrictions.clone(),
        }
    }
    fn check_clocks(&self) -> Result<()> {
        self.clock.check()?;
        if Instant::now() >= self.session_deadline {
            return Err(AuthorityError::Expired);
        }
        Ok(())
    }
    /// Cheap checks only: no journal/registry/filesystem lock and no IPC. It is
    /// valid while the journal mutex is held; never call proposal.check_current.
    pub(crate) fn check_before_publication(&self) -> Result<()> {
        if !matches!(
            self.phase,
            PhaseV1::Armed
                | PhaseV1::Preflight
                | PhaseV1::AwaitingGrant
                | PhaseV1::AdmittedRevalidating
        ) || !matches!(self.outcome, OutcomeV1::Pending)
        {
            return Err(AuthorityError::Permission);
        }
        self.check_clocks()?;
        if self.phase == PhaseV1::AdmittedRevalidating {
            self.restrictions.require_connected()
        } else {
            self.arm
                .check_current()
                .map_err(|_| AuthorityError::Permission)?;
            self.restrictions.require_unrevoked()
        }
    }
    pub(crate) fn begin_exact_preflight(&mut self) -> Result<()> {
        self.check_before_publication()?;
        if self.phase != PhaseV1::Armed || self.pending_effect.is_some() {
            return Err(AuthorityError::Permission);
        }
        self.phase = PhaseV1::Preflight;
        Ok(())
    }
    pub(crate) fn retain_preflight_commitment(&mut self, commitment: &str) -> Result<()> {
        self.check_before_publication()?;
        crate::hash(commitment)?;
        if self.phase != PhaseV1::Preflight || self.pending_effect.is_some() {
            return Err(AuthorityError::Permission);
        }
        self.pending_effect = Some(commitment.into());
        self.retained_effect = Some(commitment.into());
        self.phase = PhaseV1::AwaitingGrant;
        Ok(())
    }
    pub(crate) fn begin_exact_commit(
        &mut self,
        commitment: &str,
        grant: &FinancialContinuationFinalV1,
    ) -> Result<()> {
        // A valid exact grant already won C's A/R ordering. Do not treat a
        // later ordinary blur as recalling that admission before local P.
        self.check_clocks()?;
        self.restrictions.require_connected()?;
        grant
            .check_current()
            .map_err(|_| AuthorityError::Permission)?;
        if self.phase != PhaseV1::AwaitingGrant
            || !matches!(self.outcome, OutcomeV1::Pending)
            || self.pending_effect.as_deref() != Some(commitment)
            || grant.effect_commitment() != commitment
            || grant.presentation_digest() != self.presentation.presentation_digest
            || grant.original_review_deadline() != self.clock.original_deadline()
        {
            return Err(AuthorityError::Authentication);
        }
        self.phase = PhaseV1::AdmittedRevalidating;
        Ok(())
    }
    pub(crate) fn require_source_commitment(&self, actual: &str) -> Result<()> {
        if actual != self.presentation.source_commitment {
            return Err(AuthorityError::Conflict);
        }
        Ok(())
    }
    pub(crate) fn ready_for_exact_effect(
        &self,
        effect: &str,
        peer: &AuthenticatedOriginalOwnerPeerV1,
    ) -> Result<FinancialWitnessReadyV1> {
        let (accepted_at_ms, accepted_tls_expires_at_ms) = peer.original_accept_bounds();
        Ok(FinancialWitnessReadyV1 {
            presentation_digest: self.presentation.presentation_digest.clone(),
            effect_commitment: effect.into(),
            request_commitment: self.presentation.request_commitment.clone(),
            source_commitment: self.presentation.source_commitment.clone(),
            owner_certificate_digest: peer.certificate_digest().into(),
            expected_head_sequence: self.presentation.expected_head_sequence,
            expected_head_digest: self.presentation.expected_head_digest.clone(),
            accepted_at_ms,
            accepted_tls_expires_at_ms,
        })
    }
    pub(crate) fn require_endpoint(&self, server: &str, endpoint: &str) -> Result<()> {
        self.proposal.require_endpoint(server, endpoint)
    }
    pub(crate) fn check_exact_terminal_response(&self, response: &WireResponse) -> Result<()> {
        let exact = match (&self.outcome, response) {
            (
                OutcomeV1::Completed(wanted),
                WireResponse::Mutation(crate::MutationResult::Controlled(actual)),
            ) => wanted == actual,
            (OutcomeV1::KnownNoEffect(wanted), WireResponse::Rejected(actual)) => wanted == actual,
            (OutcomeV1::Uncertain, WireResponse::Rejected(AuthorityError::Uncertain)) => true,
            _ => false,
        };
        if !exact {
            return Err(AuthorityError::Uncertain);
        }
        // The retained TLS stream still enforces its own ORIGINAL deadline.
        // Late ordinary blur cannot suppress this exact committed outcome.
        Ok(())
    }
    pub(crate) fn require_exact_locked(
        &self,
        journal: &AuthorityJournal,
        ledger: &Ledger,
        peer: &AuthenticatedOriginalOwnerPeerV1,
        request: &OwnerControlRequest,
        now: u64,
    ) -> Result<()> {
        self.check_before_publication()?;
        peer.check_original_bounds()?;
        let original = self.proposal.coordinated_journal_v1();
        if !std::ptr::eq(Arc::as_ptr(&original), journal)
            || peer.certificate_digest() != ledger.policy.owner_certificate_digest
            || request != self.proposal.coordinated_expected_v1()
        {
            return Err(AuthorityError::Authentication);
        }
        self.proposal.validate_locked(ledger, now)
    }
    /// Private sole P issuer. An opaque original-channel grant is necessary but
    /// never sufficient: this runs only after the second full locked preflight.
    pub(crate) fn consume_final_admit_after_lock<'a>(
        &mut self,
        effect: &str,
        peer: &'a AuthenticatedOriginalOwnerPeerV1,
        grant: FinancialContinuationFinalV1,
    ) -> Result<CoordinatedFinancialContinuationPublicationV1<'a>> {
        self.check_before_publication()?;
        peer.check_original_bounds()?;
        grant
            .check_current()
            .map_err(|_| AuthorityError::Permission)?;
        if self.phase != PhaseV1::AdmittedRevalidating
            || self.pending_effect.as_deref() != Some(effect)
            || grant.effect_commitment() != effect
        {
            return Err(AuthorityError::Authentication);
        }
        self.pending_effect.take();
        self.phase = PhaseV1::Publishing;
        Ok(CoordinatedFinancialContinuationPublicationV1 {
            clock: self.clock.clone(),
            session_deadline: self.session_deadline,
            restrictions: self.restrictions.clone(),
            peer,
            grant,
        })
    }
    pub(crate) fn observe_failure(&mut self, stage: observation::Stage, error: AuthorityError) {
        // Exact operation result, not a guessed cause or backend-malfunction
        // claim. A concurrent Cancel cannot erase an earlier real Permission.
        // Outcome/disposal, not this observation, determines the terminal claim.
        self.first_failure.note(stage, error);
    }
    pub(crate) fn record_commit_attempt(&mut self) -> Result<()> {
        if self.phase != PhaseV1::Publishing || !matches!(self.outcome, OutcomeV1::Pending) {
            self.record_uncertain();
            return Err(AuthorityError::Uncertain);
        }
        self.phase = PhaseV1::CommitAttempted;
        Ok(())
    }
    pub(crate) fn record_no_effect(&mut self, error: AuthorityError) {
        self.outcome
            .no_effect(error, self.phase == PhaseV1::CommitAttempted);
        self.pending_effect.take();
        self.phase = PhaseV1::Terminal;
    }
    pub(crate) fn record_uncertain(&mut self) {
        self.outcome.uncertain();
        self.pending_effect.take();
        self.phase = PhaseV1::Terminal;
    }
    pub(crate) fn record_committed(&mut self, snapshot: AccountSnapshot) -> Result<()> {
        if self.phase != PhaseV1::CommitAttempted {
            self.record_uncertain();
            return Err(AuthorityError::Uncertain);
        }
        self.outcome.committed(snapshot)?;
        self.phase = PhaseV1::Terminal;
        Ok(())
    }
}

/// Concrete private worker/control handoff. The receiver can carry ONLY the
/// origin crate's sealed token. No external sender, generic verifier callback or
/// approval-data constructor is exposed. Actual role entry will own both ends.
pub(crate) struct FinancialContinuationCoordinatorBridgeV1 {
    events: std::sync::mpsc::SyncSender<worker::WorkerEventV1>,
    grant: std::sync::mpsc::Receiver<FinancialContinuationFinalV1>,
}
impl FinancialContinuationCoordinatorBridgeV1 {
    pub(crate) fn await_final_admit(
        &self,
        ticket: &crate::journal::PreparedFinancialContinuationAppendV1,
    ) -> Result<FinancialContinuationFinalV1> {
        ticket.check_while_waiting()?;
        self.events
            .try_send(worker::WorkerEventV1::Ready(
                ticket.ready_data(),
                ticket.original_tls_deadline(),
            ))
            .map_err(|_| AuthorityError::Permission)?;
        loop {
            // Final is enqueued before the monitor publishes a later Cancel.
            // Check the queue again after a refusal to close that ordering race.
            let grant = match poll_ordered_grant(&self.grant, || ticket.check_while_waiting())? {
                Some(grant) => grant,
                None => match self.grant.recv_timeout(std::time::Duration::from_millis(5)) {
                    Ok(grant) => grant,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        return Err(AuthorityError::Permission);
                    }
                },
            };
            // An actual admitted token is not recalled by later ordinary R.
            // Its exact identity and original actor/clock checks remain required.
            if grant.effect_commitment() != ticket.effect_commitment()
                || grant.original_accepted_deadline() != ticket.original_tls_deadline()
            {
                return Err(AuthorityError::Authentication);
            }
            grant
                .check_current()
                .map_err(|_| AuthorityError::Permission)?;
            return Ok(grant);
        }
    }
}

// Scheduling only: this helper cannot construct or validate an admission token.
fn poll_ordered_grant<T>(
    queue: &std::sync::mpsc::Receiver<T>,
    check_wait: impl FnOnce() -> Result<()>,
) -> Result<Option<T>> {
    use std::sync::mpsc::TryRecvError;
    match queue.try_recv() {
        Ok(value) => return Ok(Some(value)),
        Err(TryRecvError::Disconnected) => return Err(AuthorityError::Permission),
        Err(TryRecvError::Empty) => (),
    }
    if let Err(error) = check_wait() {
        // No new wait or renewed deadline is permitted after terminal refusal.
        return match queue.try_recv() {
            Ok(value) => Ok(Some(value)),
            Err(_) => Err(error),
        };
    }
    Ok(None)
}

/// Copying these restriction-only observations preserves the original clock;
/// it does not copy a source, grant, preparation or permission.
#[derive(Clone)]
pub(crate) struct FinancialContinuationWaitBoundsV1 {
    clock: ReviewClock,
    session_deadline: Instant,
    restrictions: Arc<RestrictionsV1>,
}
impl FinancialContinuationWaitBoundsV1 {
    pub(crate) fn check_unadmitted(&self) -> Result<()> {
        self.clock.check()?;
        if Instant::now() >= self.session_deadline {
            return Err(AuthorityError::Expired);
        }
        self.restrictions.require_unrevoked()
    }
}

/// Carries only the exact admitted effect across the A/P race. Later ordinary
/// blur cannot recall P. Original clock/source/peer/death restrictions still
/// prevent starting E when detected; no claim of interruptible fsync exists.
pub(crate) struct CoordinatedFinancialContinuationPublicationV1<'a> {
    clock: ReviewClock,
    session_deadline: Instant,
    restrictions: Arc<RestrictionsV1>,
    peer: &'a AuthenticatedOriginalOwnerPeerV1,
    grant: FinancialContinuationFinalV1,
}
impl CoordinatedFinancialContinuationPublicationV1<'_> {
    pub(crate) fn check_original_owner(
        &self,
        owner: &crate::witness_locator::BornJournalOwner,
    ) -> Result<()> {
        self.check_original_bounds()?;
        owner.check_setup_current(
            super::financial_setup_guard_v1::FinancialSetupGuardV1::Final(&self.grant),
            true,
        )?;
        self.check_original_bounds()
    }
    pub(crate) fn check_original_bounds(&self) -> Result<()> {
        self.clock.check()?;
        if Instant::now() >= self.session_deadline {
            return Err(AuthorityError::Expired);
        }
        self.restrictions.require_connected()?;
        self.peer.check_original_bounds()?;
        self.grant
            .check_current()
            .map_err(|_| AuthorityError::Permission)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordered_queue_preserves_prior_final_without_manufacturing_authority() {
        let (send, recv) = std::sync::mpsc::sync_channel(1);
        // Inert integers test only the actual queue ordering kernel.
        send.send(7u8).unwrap();
        assert_eq!(
            poll_ordered_grant(&recv, || panic!("queued item must win")).unwrap(),
            Some(7)
        );
        assert_eq!(
            poll_ordered_grant(&recv, || {
                send.send(9u8).unwrap();
                Err(AuthorityError::Permission)
            })
            .unwrap(),
            Some(9)
        );
        assert!(matches!(
            poll_ordered_grant(&recv, || Err(AuthorityError::Expired)),
            Err(AuthorityError::Expired)
        ));
        assert_eq!(poll_ordered_grant(&recv, || Ok(())).unwrap(), None);
    }
    #[test]
    fn uncertainty_cannot_be_downgraded_by_outer_no_effect_cleanup() {
        let mut outcome = OutcomeV1::Pending;
        outcome.uncertain();
        outcome.no_effect(AuthorityError::Expired, false);
        assert!(matches!(outcome, OutcomeV1::Uncertain));
    }
    #[test]
    fn rollback_failure_and_commit_attempt_never_become_known_no_effect() {
        let mut rollback = OutcomeV1::Pending;
        rollback.no_effect(AuthorityError::Uncertain, false);
        assert!(matches!(rollback, OutcomeV1::Uncertain));
        let mut commit = OutcomeV1::Pending;
        commit.no_effect(AuthorityError::Storage, true);
        assert!(matches!(commit, OutcomeV1::Uncertain));
    }
    #[test]
    fn no_effect_is_terminal_and_cannot_be_reissued() {
        let mut outcome = OutcomeV1::Pending;
        outcome.no_effect(AuthorityError::Expired, false);
        outcome.no_effect(AuthorityError::Permission, false);
        outcome.uncertain(); // a later response/channel failure cannot erase proof
        assert!(matches!(
            outcome,
            OutcomeV1::KnownNoEffect(AuthorityError::Expired)
        ));
    }
}
